//! screen keeps a screened `*` grant from carrying a DNS tunnel. A tunnel
//! needs many new names to carry data out, answers that change to carry
//! data in, and records with room for that data. Screening takes away
//! each, per service: names shaped like data are refused, new names and
//! sites are budgeted by the hour, and an answer keeps a few public
//! addresses or short records, owned by the question's name, with no
//! aliases. cache.zig holds a screened answer at least hold_s, whatever
//! its TTL, and charges the budget again for a name whose answer it lets
//! go early. Exact and `*.NAME` grants are never screened. No system
//! calls: the caller gives the time and the hash key, and fuzz.zig drives
//! it. See docs/design/unwound-plan.md.
const std = @import("std");
const network = @import("network");
const wire = @import("wire.zig");
const mem = std.mem;

/// A screened name has at most max_name characters, in at most max_labels
/// labels of at most max_label characters each.
pub const max_name = 100;
pub const max_labels = 6;
pub const max_label = 40;
/// A label, or the labels left of the site taken together, that has
/// entropy_len characters or more is refused at max_entropy bits per
/// character or more.
const entropy_len = 24;
const max_entropy = 3.5;

/// Within window_ms, a service may ask about new_sites sites, and
/// new_names names under each site, that it has not asked about already.
pub const new_sites = 32;
pub const new_names = 32;
pub const window_ms = 60 * 60 * 1000;
/// hold_s is the least time, in seconds, a screened answer stands.
pub const hold_s = 5 * 60;
/// An answer keeps at most max_kept records, with max_data bytes of data
/// in all.
pub const max_kept = 4;
pub const max_data = 512;

pub const key_len = 16;
const Hash = std.crypto.auth.siphash.SipHash64(2, 4);

/// Sign is what made screening refuse a question. The first five are a
/// name shaped like data: a tunnel's sign. The last two are a budget spent.
pub const Sign = enum {
    long_name,
    many_labels,
    long_label,
    random_label,
    random_name,
    new_sites,
    new_names,

    pub fn tunnel(s: Sign) bool {
        return @backingInt(s) < @backingInt(Sign.new_sites);
    }
};

/// Refusal says why screening refused a question; for a random label or
/// name, bits is what it scored, in bits per character.
pub const Refusal = struct { sign: Sign, bits: f32 = 0 };

/// Dropped counts the records of the asked type an answer did not keep:
/// addresses that are not public, names of the wrong shape, and records
/// past the answer's room.
pub const Dropped = struct { nonpublic: u8 = 0, shape: u8 = 0, room: u8 = 0 };

/// trim cuts a, an answer to name of type t, to what a screened answer
/// keeps: up to room(t) records of type t, each with a public address,
/// which also stops DNS rebinding, or a screened name, in max_data bytes,
/// all given as name's own. The alias chain is left out, so an answer has
/// no aliases to fill. It returns what of type t it dropped.
pub fn trim(a: *wire.Answer, name: *const wire.Name, t: wire.Type) Dropped {
    var dropped: Dropped = .{};
    var n: usize = 0;
    var used: usize = 0;
    for (a.slice()) |r| {
        if (r.type != t) continue;
        var drop: ?*u8 = switch (r.type) {
            .a, .aaaa => if (network.public(r.rdata)) null else &dropped.nonpublic,
            .cname, .ns, .ptr, .mx, .srv => if (shape(wire.target(&r).text()) == null)
                null
            else
                &dropped.shape,
            .txt, .caa => null,
        };
        if (drop == null and (n == room(t) or r.rdata.len > max_data - used))
            drop = &dropped.room;
        if (drop) |d| {
            d.* +|= 1;
            continue;
        }
        a.records[n] = r;
        a.records[n].name = name.*;
        n += 1;
        used += r.rdata.len;
    }
    a.n = n;
    return dropped;
}

/// room is how many records of type t an answer keeps.
fn room(t: wire.Type) u8 {
    return switch (t) {
        .cname => 1,
        .txt, .caa => 2,
        .a, .aaaa, .mx, .srv, .ns, .ptr => max_kept,
    };
}

/// Seen is a name a service asked about, last at last. An evicted name's
/// answer was let go early: asking again costs a new place.
const Seen = struct { key: u64 = 0, last: i64 = 0, evicted: bool = false };

const Site = struct {
    key: u64 = 0,
    last: i64 = 0,
    names: [new_names]Seen = @splat(.{}),
};

/// live reports whether what was keyed key and last asked about at last
/// is still remembered.
fn live(key: u64, last: i64, now: i64) bool {
    return key != 0 and now - last < window_ms;
}

/// Service is the budget of one service. Its zero value is a service that
/// has asked nothing.
pub const Service = struct {
    sites: [new_sites]Site = @splat(.{}),

    /// ask decides a question a screened grant allowed: a refusal, or null
    /// when the name may be asked.
    pub fn ask(s: *Service, key: *const [key_len]u8, name: []const u8, now: i64) ?Refusal {
        if (shape(name)) |r| return r;
        if (s.spend(key, name, now)) |sign| return .{ .sign = sign };
        return null;
    }

    /// evicted records that the cache let name's answer go before it
    /// expired. Asking again costs the budget a new name, so letting
    /// answers go cannot refresh them faster than the budget allows new
    /// names.
    pub fn evicted(s: *Service, key: *const [key_len]u8, name: []const u8, now: i64) void {
        const site_key = hash(key, site(name));
        const name_key = hash(key, name);
        for (&s.sites) |*x| if (x.key == site_key and live(x.key, x.last, now)) {
            for (&x.names) |*n| if (n.key == name_key and live(n.key, n.last, now)) {
                n.evicted = true;
            };
        };
    }

    /// spend records that the service asked about name, or says which
    /// budget it has spent.
    fn spend(s: *Service, key: *const [key_len]u8, name: []const u8, now: i64) ?Sign {
        const site_key = hash(key, site(name));
        const name_key = hash(key, name);
        const st = for (&s.sites) |*x| {
            if (x.key == site_key and live(x.key, x.last, now)) break x;
        } else for (&s.sites) |*x| {
            if (live(x.key, x.last, now)) continue;
            x.* = .{ .key = site_key, .last = now };
            break x;
        } else return .new_sites;
        const seen = for (&st.names) |*n| {
            if (n.key == name_key and !n.evicted and live(n.key, n.last, now)) break n;
        } else for (&st.names) |*n| {
            if (!live(n.key, n.last, now)) break n;
        } else return .new_names;
        seen.* = .{ .key = name_key, .last = now };
        st.last = now;
        return null;
    }
};

/// hash is name's keyed hash, never 0, which marks a free place. The key
/// is secret, so no one can choose a new name that passes for an old one.
fn hash(key: *const [key_len]u8, name: []const u8) u64 {
    return Hash.toInt(name, key) | 1;
}

/// shape says why name may not be asked under a screened grant, or given
/// in a screened answer, or returns null when it may.
pub fn shape(name: []const u8) ?Refusal {
    if (name.len > max_name) return .{ .sign = .long_name };
    var labels = mem.splitScalar(u8, name, '.');
    var n: usize = 0;
    while (labels.next()) |l| {
        n += 1;
        if (n > max_labels) return .{ .sign = .many_labels };
        if (l.len > max_label) return .{ .sign = .long_label };
        const bits = entropy(l);
        if (bits >= max_entropy) return .{ .sign = .random_label, .bits = bits };
    }
    const left = entropy(name[0 .. name.len - site(name).len]);
    if (left >= max_entropy) return .{ .sign = .random_name, .bits = left };
    return null;
}

/// entropy is text's Shannon entropy in bits per character, its dots and
/// hyphens aside, or 0 when it is too short to be data rather than a name.
/// Separators are left out so that they can neither dilute data nor make
/// words look like data.
fn entropy(text: []const u8) f32 {
    var counts: [256]u8 = @splat(0);
    var n: usize = 0;
    for (text) |c| if (c != '.' and c != '-') {
        counts[c] += 1;
        n += 1;
    };
    if (n < entropy_len) return 0;
    const total: f32 = @floatFromInt(n);
    var bits: f32 = 0;
    for (counts) |k| if (k > 0) {
        const p = @as(f32, @floatFromInt(k)) / total;
        bits -= p * std.math.log2(p);
    };
    return bits;
}

/// site is the part of name its registrant chose: the last two labels, or
/// three under a country's co, com, net, org, gov, edu or ac. Budgets are
/// per site, so a shared suffix that is not listed here, such as a dynamic
/// DNS provider's, only shares one site's budget among its tenants.
pub fn site(name: []const u8) []const u8 {
    const last = mem.findScalarLast(u8, name, '.') orelse return name;
    const second = mem.findScalarLast(u8, name[0..last], '.') orelse return name;
    if (name.len - last - 1 == 2) for ([_][]const u8{
        "co",
        "com",
        "net",
        "org",
        "gov",
        "edu",
        "ac",
    }) |sld| {
        if (!mem.eql(u8, name[second + 1 .. last], sld)) continue;
        const third = mem.findScalarLast(u8, name[0..second], '.') orelse return name;
        return name[third + 1 ..];
    };
    return name[second + 1 ..];
}

const testing = std.testing;

fn rep(comptime c: u8, comptime n: usize) *const [n]u8 {
    const r: [n]u8 = @splat(c);
    return &r;
}

test "sites are the registrant's part of a name" {
    for ([_][2][]const u8{
        .{ "www.example.com", "example.com" },
        .{ "a.b.c.example.com", "example.com" },
        .{ "example.com", "example.com" },
        .{ "com", "com" },
        .{ "", "" },
        .{ "www.bbc.co.uk", "bbc.co.uk" },
        .{ "co.uk", "co.uk" },
        .{ "x.example.uk", "example.uk" },
        .{ "a.b.example.com.au", "example.com.au" },
        .{ "a.b.example.ac.jp", "example.ac.jp" },
        // A three-letter country code, or another second level, is two.
        .{ "a.b.example.com.xyz", "com.xyz" },
        .{ "a.b.example.ne.jp", "ne.jp" },
    }) |c| try testing.expectEqualStrings(c[1], site(c[0]));
}

test "names that carry data are refused; names people use are not" {
    // Names of real services, as a screened grant should resolve them.
    for ([_][]const u8{
        "",
        "localhost",
        "example.com",
        "www.google.com",
        "fonts.googleapis.com",
        "objects.githubusercontent.com",
        "d2lsmt1kzk1yhz.cloudfront.net",
        "e13678.dscb.akamaiedge.net",
        "www.microsoft.com-c-3.edgekey.net",
        "s3.dualstack.us-east-1.amazonaws.com",
        "ec2-54-123-45-67.compute-1.amazonaws.com",
        "login.microsoftonline.com",
        "_acme-challenge.www.example.com",
        "xn--bcher-kva.example",
        "15.2.0.192.in-addr.arpa",
        "1e100.net",
    }) |name| {
        if (shape(name)) |r| std.debug.print("refused {s}: {t}\n", .{ name, r.sign });
        try testing.expectEqual(null, shape(name));
    }
    // Names of real tunnels' queries, and names past the limits, with the
    // sign each shows.
    for ([_]struct { []const u8, Sign }{
        // dnscat2: hex labels, and the same data diluted with hyphens.
        .{ "dnscat.9b7e01c7da2a5d06c3a1f4e2b8d90c13.t.example.com", .random_label },
        .{ "9-b-7-e-0-1-c-7-d-a-2-a-5.d-0-6-c-3-a-1-f-4-e-2-b-8.example.com", .random_name },
        .{ "4e3a01c7da2a5d06c3a1f4e2b8d90c13ab.t.example.com", .random_label },
        // iodine: base32 data in long labels.
        .{ "paaqbcdkfiqyab4z3yq0hb4ixbbrnma.t.example.com", .random_label },
        // dns2tcp and Cobalt Strike's DNS beacon: data split over labels.
        .{ "a1b2c3d4e5f6.g7h8i9j0k1l2.m3n4o5p6q7r8.t.example.com", .random_name },
        .{ "api.1a2b3c4d.5e6f7a8b9c.0d1e2f3a4b.example.com", .random_name },
        // Sliver: base32 data.
        .{ "8kj3mq7np2xr5vt9wz4by6ch1df.example.com", .random_label },
        // Too long, too deep, a label too long.
        .{
            rep('a', 40) ++ "." ++ rep('b', 40) ++ "." ++ rep('c', 10) ++ ".example.com",
            .long_name,
        },
        .{ "a.b.c.d.e.example.com", .many_labels },
        .{ rep('a', 41) ++ ".example.com", .long_label },
    }) |c| {
        const r = shape(c[0]) orelse {
            std.debug.print("allowed {s}\n", .{c[0]});
            return error.TestUnexpectedResult;
        };
        try testing.expectEqual(c[1], r.sign);
        try testing.expect(r.sign.tunnel());
        if (r.sign == .random_label or r.sign == .random_name)
            try testing.expect(r.bits >= max_entropy);
    }
    // Known false refusals: AWS's generated names, an address and a long
    // region, or a load balancer's, look like data. An exact grant, or one
    // of *.compute.amazonaws.com or *.elb.amazonaws.com, resolves them.
    for ([_][]const u8{
        "ec2-203-0-113-255.ap-southeast-2.compute.amazonaws.com",
        "my-load-balancer-1234567890.us-west-2.elb.amazonaws.com",
    }) |name| try testing.expect(shape(name) != null);
}

const test_key: [key_len]u8 = @splat(7);

fn wn(s: []const u8) wire.Name {
    return wire.Name.fromText(s) catch unreachable;
}

fn answerOf(records: []const wire.Record) wire.Answer {
    var a: wire.Answer = .{};
    for (records) |r| {
        @memcpy(a.data[a.used..][0..r.rdata.len], r.rdata);
        a.records[a.n] = r;
        a.records[a.n].rdata = a.data[a.used..][0..r.rdata.len];
        a.used += r.rdata.len;
        a.n += 1;
    }
    return a;
}

test "a service gets a site's names, and sites, within its budget by the hour" {
    const s = try testing.allocator.create(Service);
    defer testing.allocator.destroy(s);
    s.* = .{};
    var buf: [64]u8 = undefined;
    const t0: i64 = 1000;
    for (0..new_names) |i| {
        const name = try std.mem.print(&buf, "n{d}.example.com", .{i});
        try testing.expectEqual(null, s.ask(&test_key, name, t0));
    }
    // The site's budget is spent; names it has are still asked, and
    // other sites are not affected.
    try testing.expectEqual(
        Refusal{ .sign = .new_names },
        s.ask(&test_key, "more.example.com", t0).?,
    );
    try testing.expectEqual(null, s.ask(&test_key, "n0.example.com", t0));
    try testing.expectEqual(null, s.ask(&test_key, "n0.example.net", t0));
    // An hour after a name was last asked about, its place is free.
    try testing.expectEqual(
        Refusal{ .sign = .new_names },
        s.ask(&test_key, "more.example.com", t0 + window_ms - 1).?,
    );
    try testing.expectEqual(null, s.ask(&test_key, "more.example.com", t0 + window_ms));

    s.* = .{};
    for (0..new_sites) |i| {
        const name = try std.mem.print(&buf, "www.site{d}.example", .{i});
        try testing.expectEqual(null, s.ask(&test_key, name, t0));
    }
    try testing.expectEqual(
        Refusal{ .sign = .new_sites },
        s.ask(&test_key, "www.another.example", t0).?,
    );
    try testing.expectEqual(null, s.ask(&test_key, "mail.site0.example", t0));
    try testing.expectEqual(null, s.ask(&test_key, "www.another.example", t0 + window_ms));
    // Refusals for shape spend nothing.
    try testing.expectEqual(
        Refusal{ .sign = .many_labels },
        s.ask(&test_key, "a.b.c.d.e.f.example", t0).?,
    );
}

test "a name whose answer was let go early costs the budget again" {
    const s = try testing.allocator.create(Service);
    defer testing.allocator.destroy(s);
    s.* = .{};
    var buf: [64]u8 = undefined;
    for (0..new_names - 1) |i| {
        const name = try std.mem.print(&buf, "n{d}.example.com", .{i});
        try testing.expectEqual(null, s.ask(&test_key, name, 0));
    }
    // Asked again, a name costs nothing; let go and asked again, it takes
    // the site's last place, and then there is none for it.
    try testing.expectEqual(null, s.ask(&test_key, "n0.example.com", 1));
    s.evicted(&test_key, "n0.example.com", 2);
    try testing.expectEqual(null, s.ask(&test_key, "n0.example.com", 3));
    try testing.expectEqual(null, s.ask(&test_key, "n0.example.com", 4));
    s.evicted(&test_key, "n0.example.com", 5);
    try testing.expectEqual(Refusal{ .sign = .new_names }, s.ask(&test_key, "n0.example.com", 6).?);
}

test "a screened answer keeps its room, public addresses and well-shaped names" {
    const q = wn("www.example.com");
    var a = answerOf(&.{
        .{ .name = q, .type = .cname, .ttl = 60, .rdata = "\x03cdn\x07example\x03net\x00" },
        .{ .name = wn("cdn.example.net"), .type = .a, .ttl = 60, .rdata = "\x5d\xb8\xd8\x22" },
        .{ .name = wn("cdn.example.net"), .type = .a, .ttl = 60, .rdata = "\x0a\x00\x00\x01" },
        .{ .name = wn("cdn.example.net"), .type = .a, .ttl = 60, .rdata = "\x7f\x00\x00\x01" },
        .{ .name = wn("cdn.example.net"), .type = .a, .ttl = 60, .rdata = "\x01\x01\x01\x01" },
        .{ .name = wn("cdn.example.net"), .type = .a, .ttl = 60, .rdata = "\x01\x01\x01\x02" },
        .{ .name = wn("cdn.example.net"), .type = .a, .ttl = 60, .rdata = "\x01\x01\x01\x03" },
        .{ .name = wn("cdn.example.net"), .type = .a, .ttl = 60, .rdata = "\x01\x01\x01\x04" },
    });
    // No alias, no private or loopback address, four records at most, all
    // the question's own.
    try testing.expectEqual(Dropped{ .nonpublic = 2, .room = 1 }, trim(&a, &q, .a));
    try testing.expectEqual(4, a.n);
    try testing.expectEqualSlices(u8, "\x5d\xb8\xd8\x22", a.records[0].rdata);
    try testing.expectEqualSlices(u8, "\x01\x01\x01\x03", a.records[3].rdata);
    for (a.slice()) |r| {
        try testing.expectEqualStrings("www.example.com", r.name.text());
        try testing.expectEqual(.a, r.type);
    }

    const apex = wn("example.com");
    const txt = "\xff" ++ rep('x', 255);
    var texts = answerOf(&.{
        .{ .name = apex, .type = .txt, .ttl = 60, .rdata = txt },
        .{ .name = apex, .type = .txt, .ttl = 60, .rdata = "\x05hello" },
        .{ .name = apex, .type = .txt, .ttl = 60, .rdata = txt },
        .{ .name = apex, .type = .txt, .ttl = 60, .rdata = "\x05hello" },
    });
    // Two TXT records, of max_data bytes in all: the second long one does not fit.
    try testing.expectEqual(Dropped{ .room = 2 }, trim(&texts, &apex, .txt));
    try testing.expectEqual(2, texts.n);
    try testing.expectEqualSlices(u8, txt, texts.records[0].rdata);
    try testing.expectEqualSlices(u8, "\x05hello", texts.records[1].rdata);

    var mx = answerOf(&.{
        .{
            .name = apex,
            .type = .mx,
            .ttl = 60,
            .rdata = "\x00\x0a\x24" ++ "0123456789abcdefghijklmnopqrstuvwxyz" ++
                "\x07example\x03com\x00",
        },
        .{
            .name = apex,
            .type = .mx,
            .ttl = 60,
            .rdata = "\x00\x0a\x04mail\x07example\x03com\x00",
        },
    });
    try testing.expectEqual(Dropped{ .shape = 1 }, trim(&mx, &apex, .mx));
    try testing.expectEqual(1, mx.n);
    try testing.expectEqualStrings("mail.example.com", wire.target(&mx.records[0]).text());

    var v6 = answerOf(&.{
        .{ .name = apex, .type = .aaaa, .ttl = 60, .rdata = &network.v6(&.{ 0xfd, 0x00 }, 1) },
        .{
            .name = apex,
            .type = .aaaa,
            .ttl = 60,
            .rdata = &network.v6(&.{ 0x26, 0x06, 0x47, 0x00 }, 1),
        },
    });
    try testing.expectEqual(Dropped{ .nonpublic = 1 }, trim(&v6, &apex, .aaaa));
    try testing.expectEqual(1, v6.n);
}
