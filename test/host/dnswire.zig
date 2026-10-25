//! dnswire writes and reads the DNS messages that checks ask and fixtures
//! answer: one question, names written whole, compressed names read. It
//! allocates nothing, so forked children may use it.

const std = @import("std");
const mem = std.mem;

pub const max_message = 65535;
pub const max_records = 64;

pub const Error = error{ Truncated, BadName, NoRoom, TooManyRecords };

/// Message is a DNS message written into buf.
pub const Message = struct {
    buf: []u8,
    len: usize = 0,

    pub fn bytes(m: *const Message) []const u8 {
        return m.buf[0..m.len];
    }

    pub fn put(m: *Message, data: []const u8) Error!void {
        if (m.buf.len - m.len < data.len) return error.NoRoom;
        @memcpy(m.buf[m.len..][0..data.len], data);
        m.len += data.len;
    }

    pub fn int(m: *Message, comptime T: type, value: T) Error!void {
        var b: [@sizeOf(T)]u8 = undefined;
        mem.writeInt(T, &b, value, .big);
        try m.put(&b);
    }

    /// name writes text as labels; empty labels, as from a final dot, vanish.
    pub fn name(m: *Message, text: []const u8) Error!void {
        var labels = mem.tokenizeScalar(u8, text, '.');
        while (labels.next()) |l| {
            if (l.len > 63) return error.BadName;
            try m.int(u8, @intCast(l.len));
            try m.put(l);
        }
        try m.int(u8, 0);
    }

    pub fn header(m: *Message, h: Header) Error!void {
        for ([_]u16{ h.id, h.flags, h.qd, h.an, h.ns, h.ar }) |v| try m.int(u16, v);
    }

    /// record writes a resource record of class IN.
    pub fn record(
        m: *Message,
        owner: []const u8,
        kind: u16,
        ttl: u32,
        data: []const u8,
    ) Error!void {
        try m.name(owner);
        try m.int(u16, kind);
        try m.int(u16, 1);
        try m.int(u32, ttl);
        try m.int(u16, @intCast(data.len));
        try m.put(data);
    }
};

pub const Header = struct {
    id: u16,
    flags: u16 = 0x0100,
    qd: u16 = 1,
    an: u16 = 0,
    ns: u16 = 0,
    ar: u16 = 0,
};

/// query writes a recursive question for name and kind, class IN.
pub fn query(buf: []u8, id: u16, name: []const u8, kind: u16) Error![]const u8 {
    var m: Message = .{ .buf = buf };
    try m.header(.{ .id = id });
    try m.name(name);
    try m.int(u16, kind);
    try m.int(u16, 1);
    return m.bytes();
}

/// readName reads the name at msg[at..] into out, dotted, following
/// compression, and returns it and where the name ended.
pub fn readName(msg: []const u8, at: usize, out: *[255]u8) Error!struct { []const u8, usize } {
    var pos = at;
    var end: ?usize = null;
    var len: usize = 0;
    var jumps: usize = 0;
    while (true) {
        if (pos >= msg.len) return error.Truncated;
        const n = msg[pos];
        if (n == 0) break;
        if (n & 0xc0 == 0xc0) {
            if (pos + 1 >= msg.len) return error.Truncated;
            jumps += 1;
            if (jumps > 64) return error.BadName;
            end = end orelse pos + 2;
            pos = (@as(usize, n & 0x3f) << 8) | msg[pos + 1];
            continue;
        }
        if (n > 63) return error.BadName;
        if (pos + 1 + n > msg.len) return error.Truncated;
        if (len + n + @intFromBool(len > 0) > out.len) return error.BadName;
        if (len > 0) {
            out[len] = '.';
            len += 1;
        }
        @memcpy(out[len..][0..n], msg[pos + 1 ..][0..n]);
        len += n;
        pos += 1 + n;
    }
    return .{ out[0..len], end orelse pos + 1 };
}

pub const Record = struct { kind: u16, ttl: u32, data: []const u8 };

/// Reply is a parsed response: its header and the answer section.
pub const Reply = struct {
    id: u16,
    flags: u16,
    qd: u16,
    answers: []const Record,

    pub fn rcode(r: Reply) u4 {
        return @truncate(r.flags);
    }
    pub fn truncated(r: Reply) bool {
        return r.flags & 0x0200 != 0;
    }
    pub fn authentic(r: Reply) bool {
        return r.flags & 0x0020 != 0;
    }
};

/// parse reads msg's header, skips its questions and keeps up to
/// records.len answers.
pub fn parse(msg: []const u8, records: []Record) Error!Reply {
    if (msg.len < 12) return error.Truncated;
    const qd = mem.readInt(u16, msg[4..6], .big);
    const an = mem.readInt(u16, msg[6..8], .big);
    if (an > records.len) return error.TooManyRecords;
    var at: usize = 12;
    var scratch: [255]u8 = undefined;
    for (0..qd) |_| {
        at = (try readName(msg, at, &scratch))[1] + 4;
    }
    for (records[0..an]) |*r| {
        at = (try readName(msg, at, &scratch))[1];
        if (at + 10 > msg.len) return error.Truncated;
        const size = mem.readInt(u16, msg[at + 8 ..][0..2], .big);
        if (at + 10 + size > msg.len) return error.Truncated;
        r.* = .{
            .kind = mem.readInt(u16, msg[at..][0..2], .big),
            .ttl = mem.readInt(u32, msg[at + 4 ..][0..4], .big),
            .data = msg[at + 10 ..][0..size],
        };
        at += 10 + size;
    }
    return .{
        .id = mem.readInt(u16, msg[0..2], .big),
        .flags = mem.readInt(u16, msg[2..4], .big),
        .qd = qd,
        .answers = records[0..an],
    };
}

/// Question is a query's first question, as a fixture reads it.
pub const Question = struct {
    name: []const u8,
    kind: u16,
    /// raw is the question as sent: name, type and class.
    raw: []const u8,
};

pub fn question(msg: []const u8, out: *[255]u8) Error!Question {
    if (msg.len < 12) return error.Truncated;
    const name, const end = try readName(msg, 12, out);
    if (end + 4 > msg.len) return error.Truncated;
    return .{
        .name = name,
        .kind = mem.readInt(u16, msg[end..][0..2], .big),
        .raw = msg[12 .. end + 4],
    };
}

const types = [_]struct { u16, []const u8 }{
    .{ 1, "A" },     .{ 2, "NS" },    .{ 5, "CNAME" }, .{ 6, "SOA" },
    .{ 12, "PTR" },  .{ 15, "MX" },   .{ 16, "TXT" },  .{ 28, "AAAA" },
    .{ 33, "SRV" },  .{ 52, "TLSA" }, .{ 257, "CAA" }, .{ 252, "AXFR" },
    .{ 255, "ANY" },
};

/// typeNamed reads a type's mnemonic or number.
pub fn typeNamed(text: []const u8) ?u16 {
    for (types) |t| if (std.ascii.eqlIgnoreCase(t[1], text)) return t[0];
    return std.fmt.parseInt(u16, text, 10) catch null;
}

/// typeName is kind's mnemonic, or null for one this table lacks.
pub fn typeName(kind: u16) ?[]const u8 {
    for (types) |t| if (t[0] == kind) return t[1];
    return null;
}

const rcodes = [_][]const u8{ "noerror", "formerr", "servfail", "nxdomain", "notimp", "refused" };

/// rcodeNamed reads an rcode's name (noerror, refused, ...) or number.
pub fn rcodeNamed(text: []const u8) ?u4 {
    for (rcodes, 0..) |r, i| if (std.ascii.eqlIgnoreCase(r, text)) return @intCast(i);
    return std.fmt.parseInt(u4, text, 10) catch null;
}

test "a query reads back as its question" {
    var buf: [512]u8 = undefined;
    const q = try query(&buf, 0x4242, "API.example.test.", 28);
    var name: [255]u8 = undefined;
    const got = try question(q, &name);
    try std.testing.expectEqualStrings("API.example.test", got.name);
    try std.testing.expectEqual(28, got.kind);
    try std.testing.expectEqual(0x4242, mem.readInt(u16, q[0..2], .big));
    try std.testing.expectEqual(0x0100, mem.readInt(u16, q[2..4], .big));
}

test "compressed answers parse, and loops and overruns are refused" {
    var buf: [512]u8 = undefined;
    var m: Message = .{ .buf = &buf };
    try m.header(.{ .id = 7, .flags = 0x81a0, .an = 2 });
    try m.name("x.test");
    try m.int(u16, 1);
    try m.int(u16, 1);
    // A pointer to the question's name, then a whole name.
    try m.put(&.{ 0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x0c });
    try m.record("y.test", 1, 30, &.{ 192, 0, 2, 1 });
    var records: [4]Record = undefined;
    const r = try parse(m.bytes(), &records);
    try std.testing.expectEqual(0, r.rcode());
    try std.testing.expect(r.authentic() and !r.truncated());
    try std.testing.expectEqual(2, r.answers.len);
    try std.testing.expectEqual(5, r.answers[0].kind);
    try std.testing.expectEqual(30, r.answers[1].ttl);
    var name: [255]u8 = undefined;
    const first, const end = try readName(m.bytes(), 24, &name);
    try std.testing.expectEqualStrings("x.test", first);
    try std.testing.expectEqual(26, end);
    const loop = @as([12]u8, @splat(0)) ++ [_]u8{ 0xc0, 12 };
    try std.testing.expectError(error.BadName, readName(&loop, 12, &name));
    try std.testing.expectError(error.Truncated, parse(m.bytes()[0 .. m.len - 1], &records));
    try std.testing.expectEqual(16, typeNamed("txt").?);
    try std.testing.expectEqualStrings("TLSA", typeName(52).?);
    try std.testing.expectEqual(5, rcodeNamed("refused").?);
}
