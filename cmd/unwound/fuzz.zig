//! Properties shared by the seed tests and coverage-guided fuzzer: no input
//! crashes a parser or grows past its bounds, and whatever unwound accepts
//! it rebuilds into the same thing.
const std = @import("std");
const wire = @import("wire.zig");
const policy = @import("policy.zig");
const screen = @import("screen.zig");
const cache = @import("cache.zig");
const network = @import("network");
const t = std.testing;
const mem = std.mem;

test "fuzz queries: anything accepted rebuilds into the same question" {
    try t.fuzz({}, query, .{
        .corpus = &.{
            "",
            "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
                "\x03www\x07example\x03com\x00\x00\x01\x00\x01",
            // An OPT record with the DO bit, which is dropped.
            "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x01a\x00\x00\x1c\x00\x01" ++
                "\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00",
            "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01",
        },
    });
}

fn query(_: void, smith: *t.Smith) !void {
    var input: [wire.query_max + 64]u8 = undefined;
    const msg = input[0..smith.slice(&input)];
    const q = wire.parseQuery(msg) catch |err| {
        if (err == error.Short) try t.expect(msg.len < wire.header_len);
        return;
    };
    try t.expect(msg.len <= wire.query_max);
    // The name is canonical, and rebuilt in any case it reads back the same.
    _ = try wire.Name.fromText(q.name.text());
    const qtype = wire.Type.from(q.type) orelse return;
    var mix: [32]u8 = undefined;
    smith.bytes(&mix);
    var buf: [wire.query_max]u8 = undefined;
    const again = try wire.parseQuery(wire.writeQuery(&buf, q.id, &q.name, qtype, &mix));
    try t.expectEqual(q.id, again.id);
    try t.expectEqual(q.type, again.type);
    try t.expectEqualStrings(q.name.text(), again.name.text());
    var out: [wire.response_max]u8 = undefined;
    const refused = wire.writeResponse(
        &out,
        q.id,
        q.rd,
        .refused,
        .{ .name = &q.name, .type = q.type },
        &.{},
        null,
        wire.udp_max,
    );
    try t.expect(refused.len <= wire.udp_max);
}

test "fuzz responses: accepted answers are chains that rebuild unchanged" {
    try t.fuzz({}, response, .{
        .corpus = &.{
            "",
            // An alias, then an address at its target.
            "\x00\x01\x00\x00\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x06\x03cdn\xc0\x10" ++
                "\x03cdn\xc0\x10\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04",
            "\x00\x01\x00\x00\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04",
            "\x00\x00\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00",
        },
    });
}

fn response(_: void, smith: *t.Smith) !void {
    const types = [_]wire.Type{ .a, .aaaa, .cname, .mx, .txt, .srv, .ns, .ptr, .caa, .tlsa };
    const qtype = types[smith.index(types.len)];
    var mix: [32]u8 = undefined;
    smith.bytes(&mix);
    const qname = try wire.Name.fromText("www.example.com");
    var qbuf: [wire.query_max]u8 = undefined;
    const sent = wire.writeQuery(&qbuf, 0x4242, &qname, qtype, &mix);

    // Mostly a response that repeats the question with fuzzed flags and
    // records built field by field; sometimes anything at all.
    var msg: [8192]u8 = undefined;
    var len: usize = 0;
    if (smith.boolWeighted(1, 15)) {
        @memcpy(msg[0..sent.len], sent);
        msg[2] = 0x80 |
            (smith.valueWeighted(u8, &.{ .value(u8, 0, 3), .rangeAtMost(u8, 0, 255, 1) }) & 0x07);
        msg[3] = smith.valueWeighted(
            u8,
            &.{ .value(u8, 0x80, 4), .value(u8, 0x83, 1), .rangeAtMost(u8, 0, 255, 1) },
        );
        len = sent.len;
        len += records(smith, msg[0..], len);
    }
    len += smith.slice(msg[len..@min(msg.len, len + 64)]);
    var a: wire.Answer = .{};
    wire.parseResponse(msg[0..len], sent, &a) catch return;
    try t.expect(a.n <= wire.max_records and a.used <= wire.max_rdata);
    if (a.truncated or a.rcode == .servfail) return try t.expectEqual(0, a.n);

    // The chain: aliases from the question, then records of its type at its end.
    var at = qname;
    for (a.slice(), 0..) |*r, i| {
        try t.expect(r.ttl <= wire.max_ttl);
        try t.expectEqualStrings(at.text(), r.name.text());
        if (r.type == .cname and qtype != .cname) {
            at = wire.target(r);
        } else {
            try t.expectEqual(qtype, r.type);
            if (qtype == .cname) try t.expectEqual(0, i);
        }
    }

    // Rebuilt for a client, it parses back to the same records.
    var lower: [wire.query_max]u8 = undefined;
    const plain = wire.writeQuery(&lower, 0x4242, &qname, qtype, null);
    var out: [wire.response_max]u8 = undefined;
    const rebuilt = wire.writeResponse(
        &out,
        0x4242,
        true,
        a.rcode,
        .{ .name = &qname, .type = @backingInt(qtype) },
        a.slice(),
        a.negative,
        wire.response_max,
    );
    var b: wire.Answer = .{};
    try wire.parseResponse(rebuilt, plain, &b);
    try t.expectEqual(a.rcode, b.rcode);
    try t.expectEqual(a.negative, b.negative);
    if (a.negative) |n| try t.expect(n <= wire.max_ttl);
    try t.expectEqual(a.n, b.n);
    for (a.slice(), b.slice()) |x, y| {
        try t.expectEqualStrings(x.name.text(), y.name.text());
        try t.expectEqual(x.type, y.type);
        try t.expectEqual(x.ttl, y.ttl);
        try t.expectEqualSlices(u8, x.rdata, y.rdata);
    }
    // And over UDP it fits, truncated if it must be.
    const udp = wire.writeResponse(
        &out,
        0x4242,
        true,
        a.rcode,
        .{ .name = &qname, .type = @backingInt(qtype) },
        a.slice(),
        a.negative,
        wire.udp_max,
    );
    try t.expect(udp.len <= wire.udp_max);
}

/// records appends fuzzed records to msg at len, counting them in its
/// header's sections, and returns how many bytes it wrote. Owners and
/// alias targets are mostly the question's name, a few others, or pointers
/// to them, so chains form; data mostly fits its type.
fn records(smith: *t.Smith, msg: []u8, start: usize) usize {
    const owners = [_][]const u8{
        "\xc0\x0c",
        "\x03cdn\xc0\x10",
        "\x03cdn\x03net\x00",
        "\x03www\x07example\x03com\x00",
        "\x01x\xc0\x0c",
    };
    const types = [_]u16{ 1, 28, 5, 15, 16, 33, 2, 12, 257, 6, 41, 46, 39, 255 };
    var len = start;
    const n = smith.valueRangeAtMost(u8, 0, 12);
    for (0..n) |_| {
        if (msg.len - len < 600) break;
        const section = smith.valueWeighted(
            u8,
            &.{ .value(u8, 6, 3), .value(u8, 8, 1), .value(u8, 10, 1) },
        );
        const at = msg[section..][0..2];
        mem.writeInt(u16, at, mem.readInt(u16, at, .big) +% 1, .big);
        const owner = owners[smith.index(owners.len)];
        @memcpy(msg[len..][0..owner.len], owner);
        len += owner.len;
        const ty = types[smith.index(types.len)];
        mem.writeInt(u16, msg[len..][0..2], ty, .big);
        mem.writeInt(
            u16,
            msg[len + 2 ..][0..2],
            smith.valueWeighted(u16, &.{ .value(u16, 1, 15), .rangeAtMost(u16, 0, 0xffff, 1) }),
            .big,
        );
        mem.writeInt(u32, msg[len + 4 ..][0..4], smith.value(u32), .big);
        len += 10;
        const data_at = len;
        if (smith.boolWeighted(1, 3)) {
            // Data shaped for its type.
            switch (ty) {
                1 => len += copy(msg[len..], "\x01\x02\x03\x04"),
                28 => len += copy(
                    msg[len..],
                    "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                ),
                5, 2, 12 => len += copy(msg[len..], owners[smith.index(owners.len)]),
                15 => {
                    len += copy(msg[len..], "\x00\x0a");
                    len += copy(msg[len..], owners[smith.index(owners.len)]);
                },
                33 => {
                    len += copy(msg[len..], "\x00\x01\x00\x01\x01\xbb");
                    len += copy(msg[len..], owners[smith.index(owners.len)]);
                },
                16 => {
                    const k = smith.valueRangeAtMost(u8, 0, 255);
                    msg[len] = k;
                    smith.bytes(msg[len + 1 ..][0..k]);
                    len += 1 + @as(usize, k);
                },
                257 => len += copy(msg[len..], "\x00\x05issueca.example"),
                6 => {
                    len += copy(msg[len..], owners[smith.index(owners.len)]);
                    len += copy(msg[len..], owners[smith.index(owners.len)]);
                    smith.bytes(msg[len..][0..20]);
                    len += 20;
                },
                else => len += smith.slice(msg[len..][0..32]),
            }
        } else len += smith.slice(msg[len..][0..64]);
        mem.writeInt(u16, msg[data_at - 2 ..][0..2], @intCast(len - data_at), .big);
    }
    return len - start;
}

fn copy(to: []u8, from: []const u8) usize {
    @memcpy(to[0..from.len], from);
    return from.len;
}

test "fuzz policy: grants allow only what they name" {
    try t.fuzz({}, grants, .{ .corpus = &.{
        "",
        "lookup 1 a.example A\nlookup 2 *.b.example AAAA TXT\n" ++
            "lookup 3 * A unfiltered\nlookup 1 * A\n",
        "connect 1 tcp 443\nlookup 1 _x._tcp.example SRV\n",
    } });
}

fn grants(_: void, smith: *t.Smith) !void {
    var text: [512]u8 = undefined;
    const policy_text = text[0..smith.slice(&text)];
    const p = try t.allocator.create(policy.Policy);
    defer t.allocator.destroy(p);
    p.parse(policy_text) catch return;
    if (p.users.len == 0) return;
    if (smith.boolWeighted(1, 3)) _ = p.setSystemDomain("corp.example");
    // Ask about a name some grant names, or a relative of one.
    var name: wire.Name = .{};
    if (p.n > 0) {
        const g = &p.grants[smith.index(p.n)];
        name = g.name;
        if (smith.boolWeighted(1, 1) and name.len + 2 <= name.buf.len) {
            // One label more: x.NAME.
            @memmove(name.buf[2 .. name.len + 2], name.buf[0..name.len]);
            name.buf[0] = 'x';
            name.buf[1] = '.';
            name.len += 2;
            if (g.name.len == 0) name.len -= 1;
        }
    }
    const s: u8 = @intCast(smith.index(p.users.len));
    const qtype = smith.value(u16);
    const d = p.decide(s, &name, qtype);
    if (!d.allow) return;
    // An allowed question names its grant, which covers it.
    const g = for (p.grants[0..p.n]) |*g| {
        if (g.line == d.line) break g;
    } else return error.NoSuchGrant;
    try t.expectEqual(s, g.service);
    try t.expect(g.types.contains(wire.Type.from(qtype).?));
    try t.expectEqual(
        d.why == .screened or d.why == .system_domain,
        g.kind == .any and !g.unfiltered,
    );
    switch (g.kind) {
        .any => {},
        .exact => try t.expectEqualStrings(g.name.text(), name.text()),
        .below => try t.expect(mem.endsWith(u8, name.text(), g.name.text()) and
            name.len > g.name.len),
    }
}

test "fuzz cache: answers are kept as they say, and screened ones fit and stand" {
    try t.fuzz({}, caching, .{ .corpus = &.{""} });
}

/// caching asks names, some screened and some shaped like data, at fuzzed
/// times, answers them with fuzzed responses, and checks what the cache
/// keeps and gives back.
fn caching(_: void, smith: *t.Smith) !void {
    const c = try t.allocator.create(cache.Cache);
    defer t.allocator.destroy(c);
    c.* = .{};
    const s = try t.allocator.create(screen.Service);
    defer t.allocator.destroy(s);
    s.* = .{};
    const key: [screen.key_len]u8 = @splat(1);
    const names = [_][]const u8{
        "www.example.com",
        "a.example.com",
        "www.bbc.co.uk",
        "example.net",
        "dnscat.9b7e01c7da2a5d06c3a1f4e2b8d90c13.example.com",
    };
    const types = [_]wire.Type{ .a, .aaaa, .cname, .mx, .txt, .srv, .ns, .ptr, .caa, .tlsa };
    // standing is the screened answer last kept for each name and type.
    // There are fewer questions than places, so none is let go early.
    var standing: [names.len][types.len]?cache.Entry = @splat(@splat(null));
    var now: i64 = 1;
    for (0..smith.valueRangeAtMost(u8, 1, 32)) |_| {
        now += smith.valueWeighted(u32, &.{
            .value(u32, 0, 4),
            .rangeAtMost(u32, 1, 1000, 2),
            .rangeAtMost(u32, 1, 2 * screen.window_ms, 1),
        });
        const ni = smith.index(names.len);
        const ti = smith.index(types.len);
        const screened = ni % 2 == 0;
        const qname = try wire.Name.fromText(names[ni]);
        const qtype = types[ti];
        const was = &standing[ni][ti];
        if (was.*) |w| if (!w.live(now)) {
            was.* = null;
        };
        // A refusal is a tunnel's sign exactly when the name is shaped
        // like data; otherwise a budget is spent.
        if (screened) if (s.ask(&key, qname.text(), now)) |r| {
            try t.expectEqual(r.sign.tunnel(), screen.shape(qname.text()) != null);
            continue;
        };
        if (c.find(qname.text(), qtype, now)) |e| {
            try given(e, &qname, qtype, now);
            if (screened) try t.expect(same(e, &was.*.?, &qname, now));
            continue;
        }
        var qbuf: [wire.query_max]u8 = undefined;
        const sent = wire.writeQuery(&qbuf, 0x4242, &qname, qtype, null);
        var msg: [8192]u8 = undefined;
        @memcpy(msg[0..sent.len], sent);
        msg[2] = 0x81;
        msg[3] = smith.valueWeighted(
            u8,
            &.{ .value(u8, 0x80, 4), .value(u8, 0x83, 1), .value(u8, 0x82, 1) },
        );
        const len = sent.len + records(smith, &msg, sent.len);
        var a: wire.Answer = .{};
        wire.parseResponse(msg[0..len], sent, &a) catch continue;
        const ttl = cache.lifetime(&a, qtype, screened) orelse {
            // Only an unscreened failure, an answer with a TTL of 0, or a
            // negative one without an SOA is not kept.
            try t.expect(!screened);
            continue;
        };
        try t.expect(ttl <= wire.max_ttl and (!screened or ttl >= screen.hold_s));
        var dropped: screen.Dropped = .{};
        var asked: usize = 0;
        if (screened) {
            for (a.slice()) |r| asked += @intFromBool(r.type == qtype);
            dropped = screen.trim(&a, &qname, qtype);
        }
        const e = c.put(s, &key, &qname, qtype, &a, ttl, screened, dropped, now) orelse {
            try t.expect(!screened);
            continue;
        };
        try given(e, &qname, qtype, now);
        if (!screened) continue;
        // A screened answer keeps or counts each record of the asked type,
        // and what it keeps stands until it expires.
        try kept(e, &qname, qtype, now);
        const d = e.dropped;
        try t.expectEqual(asked, @as(usize, e.n) + d.nonpublic + d.shape + d.room);
        was.* = e.*;
    }
}

/// given checks an answer as the cache gives it back: the question's
/// chain, with the time it has left.
fn given(e: *const cache.Entry, q: *const wire.Name, qtype: wire.Type, now: i64) !void {
    var out: [wire.max_records]wire.Record = undefined;
    var at = q.*;
    for (e.records(q, now, &out)) |*r| {
        try t.expect(r.ttl >= 1 and r.ttl <= wire.max_ttl);
        try t.expectEqualStrings(at.text(), r.name.text());
        if (r.type == .cname and qtype != .cname)
            at = wire.target(r)
        else
            try t.expectEqual(qtype, r.type);
    }
}

/// kept checks a screened answer: few records, all of the question's
/// name and type, with public addresses and screened names.
fn kept(e: *const cache.Entry, q: *const wire.Name, qtype: wire.Type, now: i64) !void {
    var out: [wire.max_records]wire.Record = undefined;
    var data: usize = 0;
    const got = e.records(q, now, &out);
    try t.expect(got.len <= screen.max_kept);
    for (got) |*r| {
        try t.expectEqual(qtype, r.type);
        try t.expectEqualStrings(q.text(), r.name.text());
        data += r.rdata.len;
        switch (r.type) {
            .a, .aaaa => try t.expect(network.public(r.rdata)),
            .txt, .caa, .tlsa => {},
            .cname,
            .ns,
            .ptr,
            .mx,
            .srv,
            => try t.expectEqual(null, screen.shape(wire.target(r).text())),
        }
    }
    try t.expect(data <= screen.max_data);
}

fn same(a: *const cache.Entry, b: *const cache.Entry, q: *const wire.Name, now: i64) bool {
    var x: [wire.max_records]wire.Record = undefined;
    var y: [wire.max_records]wire.Record = undefined;
    const ra = a.records(q, now, &x);
    const rb = b.records(q, now, &y);
    if (a.until != b.until or a.rcode != b.rcode or ra.len != rb.len) return false;
    for (ra, rb) |p, r| if (p.type != r.type or !mem.eql(u8, p.rdata, r.rdata)) return false;
    return true;
}
