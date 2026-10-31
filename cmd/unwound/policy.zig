//! policy reads unwound's grants from the image's compiled network policy,
//! `lookup UID PATTERN TYPE... [unfiltered]` lines, and decides questions.
//! Grants only add: no order, no denials, no modes. A pattern is an exact
//! name, `*.NAME` for every name below it (not NAME itself), or `*` for
//! any name, which is screened (screen.zig) unless the line says
//! `unfiltered`. Both broad wildcards exclude endpoints.zig's destinations;
//! only named grants override those defaults.
const std = @import("std");
const dns = @import("dns");
const wire = @import("wire.zig");
const endpoints = @import("endpoints.zig");
const mem = std.mem;

pub const max_grants = 1024;

pub const Kind = enum { exact, below, any };

pub const Grant = struct {
    /// service indexes users, which also gives its label.
    service: u8,
    kind: Kind,
    name: wire.Name,
    types: std.EnumSet(wire.Type),
    unfiltered: bool,
    /// line is where the grant is in the policy file, from 1: its rule.
    line: u16,

    fn covers(g: *const Grant, n: *const wire.Name) bool {
        const want = g.name.text();
        const have = n.text();
        return switch (g.kind) {
            .any => true,
            .exact => mem.eql(u8, have, want),
            .below => have.len > want.len + 1 and mem.endsWith(u8, have, want) and
                have[have.len - want.len - 1] == '.',
        };
    }
};

pub const Why = enum {
    granted,
    /// screened matched only a screened `*`: screen.zig decides the rest.
    screened,
    /// system_domain is a boot-config suffix on a screened `*` grant.
    /// It still passes tunnel screening and endpoint defaults, skipping age.
    system_domain,
    /// unsupported is a type no grant can name: ANY, AXFR, UPDATE's.
    unsupported,
    no_grant,
    /// endpoint is a shared callback service or IP-prefixed hostname.
    endpoint,
};

/// Only an arbitrary screened wildcard needs domain-age evidence. Explicit
/// grants and the assigned system domain bypass age, not tunnel screening.
pub fn needsAge(why: Why) bool {
    return why == .screened;
}

pub const Decision = struct {
    allow: bool,
    why: Why,
    /// line is the grant that decided, or 0.
    line: u16 = 0,
};

pub const Policy = struct {
    users: dns.Users = .{},
    system_domain: ?wire.Name = null,
    grants: [max_grants]Grant = undefined,
    n: usize = 0,
    /// generation identifies the policy text in audit records.
    generation: u32 = 0,

    /// parse reads every lookup line of text and ignores the rest, which is
    /// fence's. Any malformed lookup line fails the whole policy.
    pub fn parse(p: *Policy, text: []const u8) !void {
        p.* = .{ .users = try dns.lookupUsers(text), .generation = std.hash.Crc32.hash(text) };
        var lines = mem.splitScalar(u8, text, '\n');
        var number: usize = 0;
        while (lines.next()) |line| {
            number += 1;
            var words = mem.tokenizeScalar(u8, line, ' ');
            if (!mem.eql(u8, words.next() orelse "", "lookup")) continue;
            if (p.n == max_grants or number > std.math.maxInt(u16)) return error.BadPolicy;
            const id: dns.Uids = try .parse(words.next() orelse "");
            const pattern = words.next() orelse return error.BadPolicy;
            var g: Grant = .{
                .service = for (p.users.ids[0..p.users.len], 0..) |u, i| {
                    if (u.first == id.first and u.last == id.last) break @intCast(i);
                } else unreachable,
                .kind = .exact,
                .name = .{},
                .types = .empty,
                .unfiltered = false,
                .line = @intCast(number),
            };
            if (mem.eql(u8, pattern, "*")) {
                g.kind = .any;
            } else {
                const below = mem.startsWith(u8, pattern, "*.");
                if (below) g.kind = .below;
                const text_name = if (below) pattern[2..] else pattern;
                if (text_name.len == 0) return error.BadPolicy;
                g.name = wire.Name.fromText(text_name) catch return error.BadPolicy;
            }
            while (words.next()) |w| {
                if (mem.eql(u8, w, "unfiltered")) {
                    if (g.kind != .any or words.peek() != null) return error.BadPolicy;
                    g.unfiltered = true;
                    break;
                }
                g.types.insert(wire.Type.parse(w) orelse return error.BadPolicy);
            }
            if (g.types.count() == 0) return error.BadPolicy;
            p.grants[p.n] = g;
            p.n += 1;
        }
    }

    /// service returns the service whose label ip is.
    pub fn service(p: *const Policy, ip: [4]u8) ?u8 {
        return if (dns.labelIndex(p.users, ip)) |i| @intCast(i) else null;
    }

    /// uid is the user s's label stands for: one uid, or a range, as `:people`.
    pub fn uid(p: *const Policy, s: u8) dns.Uids {
        return p.users.ids[s];
    }

    /// setSystemDomain accepts a DHCP or boot-config domain, not a field from
    /// a DNS client. An empty value clears a prior assignment on renewal.
    pub fn setSystemDomain(p: *Policy, raw: []const u8) bool {
        p.system_domain = null;
        if (raw.len == 0) return true;
        var canonical: [253]u8 = undefined;
        const normalized = dns.normalizeSystemDomain(raw, &canonical) orelse return false;
        p.system_domain = wire.Name.fromText(normalized) catch return false;
        return true;
    }

    fn inSystemDomain(p: *const Policy, n: *const wire.Name) bool {
        const base = if (p.system_domain) |*d| d.text() else return false;
        const query = n.text();
        return mem.eql(u8, query, base) or
            (query.len > base.len and mem.endsWith(u8, query, base) and
                query[query.len - base.len - 1] == '.');
    }

    /// decide answers whether service s may ask for name and type t. A
    /// named grant wins over a broad wildcard, whatever the order. Without
    /// one, endpoint defaults apply to both screened and unfiltered `*`.
    pub fn decide(p: *const Policy, s: u8, n: *const wire.Name, t: u16) Decision {
        const qtype = wire.Type.from(t) orelse return .{ .allow = false, .why = .unsupported };
        var screened: u16 = 0;
        var unfiltered: u16 = 0;
        for (p.grants[0..p.n]) |*g| {
            if (g.service != s or !g.types.contains(qtype) or !g.covers(n)) continue;
            if (g.kind == .any) {
                if (g.unfiltered) {
                    if (unfiltered == 0) unfiltered = g.line;
                } else if (screened == 0) screened = g.line;
                continue;
            }
            return .{ .allow = true, .why = .granted, .line = g.line };
        }
        const system_domain = p.inSystemDomain(n);
        if ((screened != 0 or unfiltered != 0) and
            endpoints.reason(n.text()) != null)
            return .{
                .allow = false,
                .why = .endpoint,
                .line = if (unfiltered != 0) unfiltered else screened,
            };
        if (unfiltered != 0) return .{ .allow = true, .why = .granted, .line = unfiltered };
        if (screened != 0 and system_domain)
            return .{ .allow = true, .why = .system_domain, .line = screened };
        if (screened != 0) return .{ .allow = true, .why = .screened, .line = screened };
        return .{ .allow = false, .why = .no_grant };
    }
};

const testing = std.testing;

fn name(s: []const u8) wire.Name {
    return wire.Name.fromText(s) catch unreachable;
}

const example =
    \\connect 1001 tcp 443
    \\lookup 1001 api.example.com A AAAA
    \\lookup 1001 _acme-challenge.example.com TXT
    \\lookup 1001 *.example.net A
    \\dns 69
    \\lookup 1002 * A AAAA
    \\lookup 1003 * A AAAA TXT unfiltered
    \\lookup 1002 pinned.example.org A
    \\
;

test "grants: exact names, subtrees, wildcards and their types" {
    var p: Policy = .{};
    try p.parse(example);
    try testing.expectEqual(3, p.users.len);
    const svc = p.service(.{ 127, 53, 0, 1 }).?;
    try testing.expectEqual(dns.Uids.one(1001), p.uid(svc));
    const cases = [_]struct { s: u8, n: []const u8, t: u16, d: Decision }{
        .{
            .s = 0,
            .n = "api.example.com",
            .t = 1,
            .d = .{ .allow = true, .why = .granted, .line = 2 },
        },
        .{
            .s = 0,
            .n = "api.example.com",
            .t = 28,
            .d = .{ .allow = true, .why = .granted, .line = 2 },
        },
        .{ .s = 0, .n = "api.example.com", .t = 16, .d = .{ .allow = false, .why = .no_grant } },
        .{ .s = 0, .n = "x.api.example.com", .t = 1, .d = .{ .allow = false, .why = .no_grant } },
        .{
            .s = 0,
            .n = "_acme-challenge.example.com",
            .t = 16,
            .d = .{ .allow = true, .why = .granted, .line = 3 },
        },
        // *.example.net is below it, never example.net, and on label boundaries.
        .{
            .s = 0,
            .n = "a.b.example.net",
            .t = 1,
            .d = .{ .allow = true, .why = .granted, .line = 4 },
        },
        .{ .s = 0, .n = "example.net", .t = 1, .d = .{ .allow = false, .why = .no_grant } },
        .{ .s = 0, .n = "evilexample.net", .t = 1, .d = .{ .allow = false, .why = .no_grant } },
        .{ .s = 0, .n = "example.net.evil", .t = 1, .d = .{ .allow = false, .why = .no_grant } },
        // Another service's grants are not this one's.
        .{
            .s = 1,
            .n = "api.example.com",
            .t = 1,
            .d = .{ .allow = true, .why = .screened, .line = 6 },
        },
        .{ .s = 1, .n = "api.example.com", .t = 16, .d = .{ .allow = false, .why = .no_grant } },
        // A screened * yields to an exact grant, whatever the order.
        .{
            .s = 1,
            .n = "pinned.example.org",
            .t = 1,
            .d = .{ .allow = true, .why = .granted, .line = 8 },
        },
        .{ .s = 1, .n = "pinned.example.org", .t = 16, .d = .{ .allow = false, .why = .no_grant } },
        .{
            .s = 2,
            .n = "anything.at.all",
            .t = 16,
            .d = .{ .allow = true, .why = .granted, .line = 7 },
        },
        .{ .s = 2, .n = "", .t = 1, .d = .{ .allow = true, .why = .granted, .line = 7 } },
        // ANY, AXFR and unknown types are never granted, even unfiltered.
        .{
            .s = 2,
            .n = "anything.at.all",
            .t = 255,
            .d = .{ .allow = false, .why = .unsupported },
        },
        .{
            .s = 2,
            .n = "anything.at.all",
            .t = 252,
            .d = .{ .allow = false, .why = .unsupported },
        },
        .{ .s = 2, .n = "anything.at.all", .t = 65, .d = .{ .allow = false, .why = .unsupported } },
    };
    for (cases) |c| try testing.expectEqual(c.d, p.decide(c.s, &name(c.n), c.t));
    try testing.expectEqual(null, p.service(.{ 127, 53, 0, 4 }));
    try testing.expectEqual(null, p.service(.{ 127, 0, 0, 1 }));
}

test "assigned system domain applies only to screened wildcard grants" {
    var p: Policy = .{};
    try p.parse(example);
    try testing.expect(p.setSystemDomain("Corp.Example.COM."));
    try testing.expectEqualStrings("corp.example.com", p.system_domain.?.text());
    const cases = [_]struct { s: u8, n: []const u8, t: u16, allow: bool, why: Why, line: u16 }{
        // Pinned-only service 0 is never widened by system_domain.
        .{ .s = 0, .n = "corp.example.com", .t = 1, .allow = false, .why = .no_grant, .line = 0 },
        .{
            .s = 0,
            .n = "host.corp.example.com",
            .t = 16,
            .allow = false,
            .why = .no_grant,
            .line = 0,
        },
        // Screened `*` service 1 gets system_domain only for its granted RR types.
        .{
            .s = 1,
            .n = "corp.example.com",
            .t = 1,
            .allow = true,
            .why = .system_domain,
            .line = 6,
        },
        .{
            .s = 1,
            .n = "host.corp.example.com",
            .t = 28,
            .allow = true,
            .why = .system_domain,
            .line = 6,
        },
        .{
            .s = 1,
            .n = "host.corp.example.com",
            .t = 16,
            .allow = false,
            .why = .no_grant,
            .line = 0,
        },
        .{
            .s = 1,
            .n = "evilcorp.example.com",
            .t = 1,
            .allow = true,
            .why = .screened,
            .line = 6,
        },
        .{
            .s = 1,
            .n = "corp.example.com.evil",
            .t = 1,
            .allow = true,
            .why = .screened,
            .line = 6,
        },
        .{
            .s = 1,
            .n = "corp.example.com",
            .t = 255,
            .allow = false,
            .why = .unsupported,
            .line = 0,
        },
    };
    for (cases) |c| {
        const got = p.decide(c.s, &name(c.n), c.t);
        try testing.expectEqual(c.allow, got.allow);
        try testing.expectEqual(c.why, got.why);
        try testing.expectEqual(c.line, got.line);
    }
    for ([_][]const u8{
        "a",
        ".example.com",
        "example..com",
        "example.com..",
        "*.example.com",
        "a_b.example.com",
    }) |bad|
        try testing.expect(!p.setSystemDomain(bad));
    try testing.expect(p.system_domain == null);
    try testing.expect(p.setSystemDomain(""));
    try testing.expect(needsAge(.screened));
    try testing.expect(!needsAge(.system_domain));
    try testing.expect(!needsAge(.granted));
}

test "malformed lookup lines fail the whole policy" {
    for ([_][]const u8{
        "lookup",
        "lookup 1001",
        "lookup 1001 a.example",
        "lookup x a.example A",
        "lookup 4294967295 a.example A",
        "lookup 1001 A.example A",
        "lookup 1001 a.example. A",
        "lookup 1001 a.example a",
        "lookup 1001 a.example ANY",
        "lookup 1001 a.example all",
        "lookup 1001 a.example AXFR",
        "lookup 1001 a.example A unfiltered",
        "lookup 1001 *.a.example A unfiltered",
        "lookup 1001 * unfiltered",
        "lookup 1001 * A unfiltered A",
        "lookup 1001 *. A",
        "lookup 1001 *a.example A",
        "lookup 1001 a.*.example A",
        "lookup 1001 ** A",
    }) |bad| {
        var p: Policy = .{};
        try testing.expectError(error.BadPolicy, p.parse(bad));
    }
}

test "the policy names each grant's rule and generation" {
    var p: Policy = .{};
    try p.parse(example);
    var q: Policy = .{};
    try q.parse(example ++ "lookup 1004 b.example A\n");
    try testing.expect(p.generation != q.generation);
    try testing.expectEqual(4, q.users.len);
}

test "default endpoint exclusions yield only to explicit grants" {
    const p = try testing.allocator.create(Policy);
    defer testing.allocator.destroy(p);
    try p.parse(
        "lookup 1 * A AAAA CNAME TXT\n" ++
            "lookup 2 * A AAAA unfiltered\n" ++
            "lookup 3 httpbin.org A\n" ++
            "lookup 3 *.webhook.site A\n" ++
            "lookup 3 192-0-2-1.example.com A\n" ++
            "lookup 3 * A\n" ++
            "lookup 4 * A AAAA unfiltered\n" ++
            "lookup 4 httpbin.org A\n" ++
            "lookup 4 *.ngrok.app A\n",
    );
    for ([_][]const u8{
        "httpbin.org",
        "token.oastify.com",
        "127.0.0.1.203-0-113-1.sslip.io",
        "192-0-2-1.example.com",
        "2001-db8--1.example.com",
    }) |text| {
        const n = name(text);
        for ([_]u16{ 1, 28, 5, 16 }) |t| {
            const d = p.decide(0, &n, t);
            try testing.expect(!d.allow);
            try testing.expectEqual(Why.endpoint, d.why);
        }
        try testing.expectEqual(Why.endpoint, p.decide(1, &n, 1).why);
    }
    for ([_][]const u8{ "httpbin.org", "token.webhook.site", "192-0-2-1.example.com" }) |text| {
        const n = name(text);
        try testing.expectEqual(Why.granted, p.decide(2, &n, 1).why);
    }
    for ([_][]const u8{ "httpbin.org", "app.ngrok.app" }) |text| {
        const n = name(text);
        try testing.expectEqual(Why.granted, p.decide(3, &n, 1).why);
        try testing.expectEqual(Why.endpoint, p.decide(3, &n, 28).why);
    }
    // A DHCP suffix cannot turn a blocked service into an automatic grant.
    try testing.expect(p.setSystemDomain("oastify.com"));
    const assigned = name("token.oastify.com");
    try testing.expectEqual(Why.endpoint, p.decide(2, &assigned, 1).why);
    const normal = name("api.example.com");
    try testing.expectEqual(Why.screened, p.decide(0, &normal, 1).why);
}
