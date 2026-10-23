//! cache keeps each service's answers as long as they say, so a question
//! asked again is answered at once and the resolvers are asked once. Each
//! service has its own: no service learns from its timing what another
//! asked, and none can push out another's answers. A positive answer is
//! kept for its records' least TTL and a negative one for its SOA's (RFC
//! 2308); failures, and negative answers with no SOA, are not kept. A
//! screened answer stands at least screen.hold_s whatever it says, failures
//! included, so its answers cannot change to carry data. When the cache is
//! full the answer least recently given goes; a screened one that goes
//! early charges its name to the budget again. No system calls: the caller
//! gives the time, and fuzz.zig drives it.
const std = @import("std");
const wire = @import("wire.zig");
const screen = @import("screen.zig");
const mem = std.mem;

/// max_entries bounds one service's answers; max_data, one answer's
/// records, each kept as its type, its length and its data.
pub const max_entries = 256;
pub const max_data = 768;

/// Entry is one answer to a name and type. Its zero value is free.
pub const Entry = struct {
    /// until is when the answer expires; used, when it was last given.
    until: i64 = 0,
    used: i64 = 0,
    type: u16 = 0,
    rcode: wire.Rcode = .noerror,
    screened: bool = false,
    n: u8 = 0,
    len: u8 = 0,
    dropped: screen.Dropped = .{},
    name: [253]u8 = @splat(0),
    data: [max_data]u8 = @splat(0),

    pub fn live(e: *const Entry, now: i64) bool {
        return e.until > now;
    }

    /// records returns the answer's records, with the time it has left as
    /// their TTL. Owners follow the alias chain from name, the question:
    /// each alias's target owns what comes after it.
    pub fn records(
        e: *const Entry,
        name: *const wire.Name,
        now: i64,
        out: *[wire.max_records]wire.Record,
    ) []const wire.Record {
        const ttl: u32 = @intCast(@max(1, @divFloor(e.until - now, std.time.ms_per_s)));
        var owner = name.*;
        var at: usize = 0;
        for (out[0..e.n]) |*r| {
            const t: wire.Type = @fromBackingInt(mem.readInt(u16, e.data[at..][0..2], .little));
            const len = mem.readInt(u16, e.data[at + 2 ..][0..2], .little);
            r.* = .{ .name = owner, .type = t, .ttl = ttl, .rdata = e.data[at + 4 ..][0..len] };
            at += 4 + len;
            if (t == .cname and e.type != @backingInt(wire.Type.cname)) owner = wire.target(r);
        }
        return out[0..e.n];
    }
};

pub const Cache = struct {
    entries: [max_entries]Entry = @splat(.{}),

    /// find returns the answer kept for name and type, if one is.
    pub fn find(c: *Cache, name: []const u8, t: wire.Type, now: i64) ?*const Entry {
        for (&c.entries) |*e| {
            if (!e.live(now) or e.type != @backingInt(t) or !mem.eql(u8, e.name[0..e.len], name))
                continue;
            e.used = now;
            return e;
        }
        return null;
    }

    /// put keeps a, upstream's answer to name and type, for ttl seconds,
    /// and returns the answer that stands: one already kept for the
    /// question stands until it expires. An answer too large to keep is
    /// not kept: null. A screened answer let go before it expires is
    /// charged to budget again.
    pub fn put(
        c: *Cache,
        budget: *screen.Service,
        key: *const [screen.key_len]u8,
        name: *const wire.Name,
        t: wire.Type,
        a: *const wire.Answer,
        ttl: u32,
        screened: bool,
        dropped: screen.Dropped,
        now: i64,
    ) ?*const Entry {
        if (c.find(name.text(), t, now)) |e| return e;
        var size: usize = 0;
        for (a.slice()) |r| size += 4 + r.rdata.len;
        if (size > max_data) return null;
        // An expired answer's place, or else the least recently given's.
        var e = &c.entries[0];
        for (&c.entries) |*x| {
            if (!x.live(now)) {
                e = x;
                break;
            }
            if (x.used < e.used) e = x;
        }
        if (e.live(now) and e.screened) budget.evicted(key, e.name[0..e.len], now);
        e.* = .{
            .until = now + @as(i64, ttl) * std.time.ms_per_s,
            .used = now,
            .type = @backingInt(t),
            .rcode = a.rcode,
            .screened = screened,
            .n = @intCast(a.n),
            .len = name.len,
            .dropped = dropped,
        };
        @memcpy(e.name[0..name.len], name.text());
        var at: usize = 0;
        for (a.slice()) |r| {
            mem.writeInt(u16, e.data[at..][0..2], @backingInt(r.type), .little);
            mem.writeInt(u16, e.data[at + 2 ..][0..2], @intCast(r.rdata.len), .little);
            @memcpy(e.data[at + 4 ..][0..r.rdata.len], r.rdata);
            at += 4 + r.rdata.len;
        }
        return e;
    }
};

/// lifetime is how long, in seconds, a, an answer to a question of type t,
/// may be kept, or null when it may not be. A whole answer is kept for its
/// records' least TTL; one without records of type t, NXDOMAIN or NODATA,
/// for the least of that and its SOA's, and not at all without one. A
/// failure is not kept, nor is an answer with a TTL of 0. A screened
/// answer is kept at least screen.hold_s, whatever it is.
pub fn lifetime(a: *const wire.Answer, t: wire.Type, screened: bool) ?u32 {
    var ttl: ?u32 = null;
    if (a.rcode == .noerror or a.rcode == .nxdomain) {
        var least: u32 = wire.max_ttl;
        var whole = false;
        for (a.slice()) |r| {
            least = @min(least, r.ttl);
            whole = whole or r.type == t;
        }
        ttl = if (whole and a.rcode == .noerror)
            least
        else if (a.negative) |n| @min(least, n) else null;
    }
    if (screened) return @max(ttl orelse 0, screen.hold_s);
    const kept = ttl orelse return null;
    return if (kept == 0) null else kept;
}

const testing = std.testing;
const test_key: [screen.key_len]u8 = @splat(3);

fn wn(s: []const u8) wire.Name {
    return wire.Name.fromText(s) catch unreachable;
}

fn answerOf(rcode: wire.Rcode, negative: ?u32, records: []const wire.Record) wire.Answer {
    var a: wire.Answer = .{ .rcode = rcode, .negative = negative };
    for (records) |r| {
        @memcpy(a.data[a.used..][0..r.rdata.len], r.rdata);
        a.records[a.n] = r;
        a.records[a.n].rdata = a.data[a.used..][0..r.rdata.len];
        a.used += r.rdata.len;
        a.n += 1;
    }
    return a;
}

test "answers are kept as long as they say, and failures not at all" {
    const q = wn("www.example.com");
    const edge = wn("edge.example.net");
    const chain = answerOf(.noerror, null, &.{
        .{ .name = q, .type = .cname, .ttl = 600, .rdata = "\x04edge\x07example\x03net\x00" },
        .{ .name = edge, .type = .a, .ttl = 60, .rdata = "\x01\x02\x03\x04" },
        .{ .name = edge, .type = .a, .ttl = 90, .rdata = "\x01\x02\x03\x05" },
    });
    try testing.expectEqual(60, lifetime(&chain, .a, false));
    try testing.expectEqual(screen.hold_s, lifetime(&chain, .a, true));
    const long = answerOf(
        .noerror,
        null,
        &.{.{ .name = q, .type = .a, .ttl = 3600, .rdata = "\x01\x02\x03\x04" }},
    );
    try testing.expectEqual(3600, lifetime(&long, .a, true));
    const zero = answerOf(
        .noerror,
        null,
        &.{.{ .name = q, .type = .a, .ttl = 0, .rdata = "\x01\x02\x03\x04" }},
    );
    try testing.expectEqual(null, lifetime(&zero, .a, false));
    try testing.expectEqual(screen.hold_s, lifetime(&zero, .a, true));

    // NXDOMAIN and NODATA, by their SOA; an alias to nothing, by the least
    // of the alias and the SOA.
    try testing.expectEqual(120, lifetime(&answerOf(.nxdomain, 120, &.{}), .a, false));
    try testing.expectEqual(null, lifetime(&answerOf(.nxdomain, null, &.{}), .a, false));
    try testing.expectEqual(screen.hold_s, lifetime(&answerOf(.nxdomain, null, &.{}), .a, true));
    try testing.expectEqual(45, lifetime(&answerOf(.noerror, 45, &.{}), .aaaa, false));
    const alias: wire.Record = .{
        .name = q,
        .type = .cname,
        .ttl = 300,
        .rdata = "\x04edge\x07example\x03net\x00",
    };
    const dangling = answerOf(.noerror, 900, &.{alias});
    try testing.expectEqual(300, lifetime(&dangling, .aaaa, false));
    try testing.expectEqual(null, lifetime(&answerOf(.noerror, null, &.{alias}), .aaaa, false));
    // A CNAME question's alias is a whole answer.
    try testing.expectEqual(300, lifetime(&dangling, .cname, false));

    // A resolver's failure is kept only when screened.
    try testing.expectEqual(null, lifetime(&answerOf(.servfail, 60, &.{}), .a, false));
    try testing.expectEqual(screen.hold_s, lifetime(&answerOf(.servfail, null, &.{}), .a, true));
}

test "a kept answer is given back with its chain and the time it has left" {
    const c = try testing.allocator.create(Cache);
    defer testing.allocator.destroy(c);
    c.* = .{};
    var budget: screen.Service = .{};
    const q = wn("www.example.com");
    const edge = wn("edge.example.net");
    const a = answerOf(.noerror, null, &.{
        .{ .name = q, .type = .cname, .ttl = 600, .rdata = "\x04edge\x07example\x03net\x00" },
        .{ .name = edge, .type = .a, .ttl = 60, .rdata = "\x01\x02\x03\x04" },
    });
    const e = c.put(&budget, &test_key, &q, .a, &a, 60, false, .{}, 1000).?;
    try testing.expectEqual(e, c.find("www.example.com", .a, 1000 + 59_999).?);
    try testing.expectEqual(null, c.find("www.example.com", .aaaa, 1000));
    try testing.expectEqual(null, c.find("www.example.com", .a, 1000 + 60_000));

    var out: [wire.max_records]wire.Record = undefined;
    const got = e.records(&q, 1000 + 30_000, &out);
    try testing.expectEqual(2, got.len);
    try testing.expectEqualStrings("www.example.com", got[0].name.text());
    try testing.expectEqual(.cname, got[0].type);
    try testing.expectEqualStrings("edge.example.net", got[1].name.text());
    try testing.expectEqualSlices(u8, "\x01\x02\x03\x04", got[1].rdata);
    for (got) |r| try testing.expectEqual(30, r.ttl);
    try testing.expectEqual(1, e.records(&q, 1000 + 59_999, &out)[0].ttl);

    // While it stands, a later answer to the same question changes nothing.
    const later = answerOf(
        .noerror,
        null,
        &.{.{ .name = q, .type = .a, .ttl = 60, .rdata = "\x09\x09\x09\x09" }},
    );
    try testing.expectEqual(e, c.put(&budget, &test_key, &q, .a, &later, 60, false, .{}, 2000).?);
    try testing.expectEqual(2, e.n);

    // An answer too large to keep is not kept.
    var big: wire.Answer = .{};
    const txt = "\xff" ++ @as([255]u8, @splat('x'));
    for (0..3) |_| {
        big.records[big.n] = .{ .name = q, .type = .txt, .ttl = 60, .rdata = txt };
        big.n += 1;
    }
    try testing.expectEqual(null, c.put(&budget, &test_key, &q, .txt, &big, 60, false, .{}, 1000));
}

test "a full cache lets the answer least recently given go" {
    const c = try testing.allocator.create(Cache);
    defer testing.allocator.destroy(c);
    c.* = .{};
    var budget: screen.Service = .{};
    var buf: [64]u8 = undefined;
    const a = answerOf(.noerror, null, &.{});
    for (0..max_entries) |i| {
        const q = try wire.Name.fromText(try std.mem.print(&buf, "n{d}.example.com", .{i}));
        _ = c.put(&budget, &test_key, &q, .a, &a, 600, false, .{}, @intCast(i)).?;
    }
    // The first, given again, stays; the second goes for a new answer.
    _ = c.find("n0.example.com", .a, 1000).?;
    const q = wn("new.example.com");
    _ = c.put(&budget, &test_key, &q, .a, &a, 600, false, .{}, 1001).?;
    try testing.expect(c.find("n0.example.com", .a, 1002) != null);
    try testing.expectEqual(null, c.find("n1.example.com", .a, 1002));
    try testing.expect(c.find("new.example.com", .a, 1002) != null);
}

test "a screened answer let go early charges its name to the budget again" {
    const c = try testing.allocator.create(Cache);
    defer testing.allocator.destroy(c);
    c.* = .{};
    const budget = try testing.allocator.create(screen.Service);
    defer testing.allocator.destroy(budget);
    budget.* = .{};
    var buf: [64]u8 = undefined;
    const a = answerOf(.noerror, null, &.{});
    // A poller fills the cache with screened answers over 32 sites, which
    // lets the first, 0.s0.example, go.
    for (0..max_entries + 1) |i| {
        const text = try std.mem.print(&buf, "{d}.s{d}.example", .{ i, i % screen.new_sites });
        const q = try wire.Name.fromText(text);
        try testing.expectEqual(null, budget.ask(&test_key, q.text(), @intCast(i)));
        _ = c.put(budget, &test_key, &q, .a, &a, screen.hold_s, true, .{}, @intCast(i)).?;
    }
    try testing.expectEqual(null, c.find("0.s0.example", .a, 1000));
    // s0.example has 9 names. Asked again, the one let go takes a new
    // place, so 22 more fit, not 23.
    try testing.expectEqual(null, budget.ask(&test_key, "0.s0.example", 1000));
    for (0..22) |i| {
        const text = try std.mem.print(&buf, "more{d}.s0.example", .{i});
        try testing.expectEqual(null, budget.ask(&test_key, text, 1000));
    }
    try testing.expectEqual(
        screen.Sign.new_names,
        budget.ask(&test_key, "last.s0.example", 1000).?.sign,
    );
}
