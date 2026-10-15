//! Bounded D-Bus framing for the UniFi read-only service-state adapter.
const std = @import("std");
const mem = std.mem;
pub const limit = 32 << 10;
pub const Error = error{ BadMessage, TooLarge };

pub const Cursor = struct {
    data: []const u8,
    pos: usize = 0,
    endian: std.builtin.Endian = .little,

    pub fn take(c: *Cursor, n: usize) Error![]const u8 {
        if (n > c.data.len - c.pos) return error.BadMessage;
        const result = c.data[c.pos..][0..n];
        c.pos += n;
        return result;
    }

    pub fn alignTo(c: *Cursor, n: usize) Error!void {
        const pad = (n - c.pos % n) % n;
        for (try c.take(pad)) |b| if (b != 0) return error.BadMessage;
    }

    pub fn byte(c: *Cursor) Error!u8 {
        return (try c.take(1))[0];
    }

    pub fn uint(c: *Cursor) Error!u32 {
        try c.alignTo(4);
        return mem.readInt(u32, (try c.take(4))[0..4], c.endian);
    }

    pub fn string(c: *Cursor, short: bool) Error![]const u8 {
        const n: usize = if (short) try c.byte() else try c.uint();
        const s = try c.take(n);
        if (try c.byte() != 0 or mem.indexOfScalar(u8, s, 0) != null or
            !std.unicode.utf8ValidateSlice(s)) return error.BadMessage;
        return s;
    }

    pub fn done(c: Cursor) Error!void {
        if (c.pos != c.data.len) return error.BadMessage;
    }
};

pub const Buffer = struct {
    bytes: [limit]u8 = undefined,
    len: usize = 0,

    pub fn slice(b: *const Buffer) []const u8 {
        return b.bytes[0..b.len];
    }

    pub fn append(b: *Buffer, s: []const u8) Error!void {
        if (s.len > b.bytes.len - b.len) return error.TooLarge;
        @memcpy(b.bytes[b.len..][0..s.len], s);
        b.len += s.len;
    }

    pub fn byte(b: *Buffer, n: u8) Error!void {
        try b.append(&.{n});
    }

    pub fn alignTo(b: *Buffer, n: usize) Error!void {
        const pad = (n - b.len % n) % n;
        const zeros: [8]u8 = @splat(0);
        try b.append(zeros[0..pad]);
    }

    pub fn uint(b: *Buffer, n: u32) Error!void {
        try b.alignTo(4);
        var bytes: [4]u8 = undefined;
        mem.writeInt(u32, &bytes, n, .little);
        try b.append(&bytes);
    }

    pub fn string(b: *Buffer, s: []const u8, short: bool) Error!void {
        if (s.len > limit or (short and s.len > 255)) return error.TooLarge;
        if (short) try b.byte(@intCast(s.len)) else try b.uint(@intCast(s.len));
        try b.append(s);
        try b.byte(0);
    }

    pub fn field(b: *Buffer, code: u8, kind: u8, value: []const u8) Error!void {
        try b.alignTo(8);
        try b.byte(code);
        try b.string(&.{kind}, true);
        try b.string(value, kind == 'g');
    }

    pub fn uintField(b: *Buffer, code: u8, n: u32) Error!void {
        try b.alignTo(8);
        try b.byte(code);
        try b.string("u", true);
        try b.uint(n);
    }
};

pub const Message = struct {
    kind: u8,
    flags: u8,
    serial: u32,
    path: []const u8 = "",
    interface: []const u8 = "",
    member: []const u8 = "",
    destination: []const u8 = "",
    signature: []const u8 = "",
    body: Cursor,
};

pub fn length(data: []const u8) Error!?usize {
    if (data.len < 16) return null;
    const endian: std.builtin.Endian = switch (data[0]) {
        'l' => .little,
        'B' => .big,
        else => return error.BadMessage,
    };
    if (data[3] != 1 or data[1] < 1 or data[1] > 4 or data[2] & ~@as(u8, 7) != 0 or
        mem.readInt(u32, data[8..12], endian) == 0) return error.BadMessage;
    const fields = mem.readInt(u32, data[12..16], endian);
    const body = mem.readInt(u32, data[4..8], endian);
    if (fields > limit - 16 or body > limit) return error.TooLarge;
    const total = 16 + mem.alignForward(usize, fields, 8) + body;
    if (total > limit) return error.TooLarge;
    return total;
}

pub fn parse(data: []const u8) Error!Message {
    const n = (try length(data)) orelse return error.BadMessage;
    if (data.len != n) return error.BadMessage;
    const endian: std.builtin.Endian = if (data[0] == 'l') .little else .big;
    const end = 16 + mem.readInt(u32, data[12..16], endian);
    const body_start = mem.alignForward(usize, end, 8);
    var m: Message = .{
        .kind = data[1],
        .flags = data[2],
        .serial = mem.readInt(u32, data[8..12], endian),
        .body = .{ .data = data[body_start..], .endian = endian },
    };
    var c: Cursor = .{ .data = data[0..end], .pos = 16, .endian = endian };
    var seen: u256 = 0;
    while (c.pos < c.data.len) {
        try c.alignTo(8);
        const code = try c.byte();
        const bit = @as(u256, 1) << @intCast(code);
        if (code == 0 or seen & bit != 0) return error.BadMessage;
        seen |= bit;
        const sig = try c.string(true);
        if (sig.len != 1) return error.BadMessage;
        const expected: u8 = switch (code) {
            1 => 'o',
            2, 3, 4, 6, 7 => 's',
            5, 9 => 'u',
            8 => 'g',
            else => sig[0],
        };
        if (sig[0] != expected) return error.BadMessage;
        if (sig[0] == 'u') {
            const value = try c.uint();
            if (code == 9 and value != 0) return error.BadMessage;
            continue;
        }
        if (sig[0] != 's' and sig[0] != 'o' and sig[0] != 'g') return error.BadMessage;
        const value = try c.string(sig[0] == 'g');
        switch (code) {
            1 => m.path = value,
            2 => m.interface = value,
            3 => m.member = value,
            6 => m.destination = value,
            8 => m.signature = value,
            else => {},
        }
    }
    var pad: Cursor = .{ .data = data[end..body_start] };
    for (try pad.take(pad.data.len)) |b| if (b != 0) return error.BadMessage;
    if (m.kind == 1 and (m.path.len == 0 or m.member.len == 0)) return error.BadMessage;
    return m;
}

pub fn encode(
    out: *Buffer,
    kind: u8,
    serial: u32,
    fields: *const Buffer,
    body: *const Buffer,
) Error!void {
    var frame: Buffer = .{};
    try frame.append(&.{ 'l', kind, 0, 1 });
    try frame.uint(@intCast(body.len));
    try frame.uint(serial);
    try frame.uint(@intCast(fields.len));
    try frame.append(fields.slice());
    try frame.alignTo(8);
    try frame.append(body.slice());
    try out.append(frame.slice());
}

test "framing refuses oversized, truncated, duplicate and mistyped headers" {
    var fields: Buffer = .{};
    try fields.field(1, 'o', "/org/freedesktop/systemd1");
    try fields.field(3, 's', "LoadUnit");
    try fields.field(8, 'g', "s");
    var body: Buffer = .{};
    try body.string("unifi.service", false);
    var packet: Buffer = .{};
    try encode(&packet, 1, 1, &fields, &body);
    const m = try parse(packet.slice());
    try std.testing.expectEqualStrings("LoadUnit", m.member);
    try std.testing.expectEqual(@as(?usize, null), try length(packet.slice()[0..15]));
    for (16..packet.len) |n| try std.testing.expectError(
        error.BadMessage,
        parse(packet.slice()[0..n]),
    );
    mem.writeInt(u32, packet.bytes[4..8], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.TooLarge, length(packet.slice()));
    packet.len = 0;
    try fields.field(3, 's', "Again");
    try encode(&packet, 1, 1, &fields, &body);
    try std.testing.expectError(error.BadMessage, parse(packet.slice()));
    fields.len = 0;
    packet.len = 0;
    try fields.field(1, 's', "/wrong-type");
    try encode(&packet, 1, 1, &fields, &body);
    try std.testing.expectError(error.BadMessage, parse(packet.slice()));
}

test "strings require valid UTF-8, a terminator, and exact consumption" {
    var c: Cursor = .{ .data = &.{ 1, 0xff, 0 } };
    try std.testing.expectError(error.BadMessage, c.string(true));
    c = .{ .data = &.{ 2, 'a', 0, 0 } };
    try std.testing.expectError(error.BadMessage, c.string(true));
    c = .{ .data = &.{ 1, 'a', 1 } };
    try std.testing.expectError(error.BadMessage, c.string(true));
    c = .{ .data = &.{0} };
    try std.testing.expectError(error.BadMessage, c.done());
    var b: Buffer = .{ .len = limit };
    try std.testing.expectError(error.TooLarge, b.byte(0));
}

test "big endian calls and consecutive unaligned frames retain their boundaries" {
    var fields: Buffer = .{};
    try fields.field(1, 'o', "/x");
    try fields.field(3, 's', "Ping");
    var body: Buffer = .{};
    var packet: Buffer = .{};
    try encode(&packet, 1, 1, &fields, &body);
    packet.bytes[0] = 'B';
    for ([_]usize{ 4, 8, 12, 20, 36 }) |pos| {
        const n = mem.readInt(u32, packet.bytes[pos..][0..4], .little);
        mem.writeInt(u32, packet.bytes[pos..][0..4], n, .big);
    }
    const big = try parse(packet.slice());
    try std.testing.expectEqualStrings("/x", big.path);
    try std.testing.expectEqualStrings("Ping", big.member);
    packet.len = 0;
    try body.byte(0);
    try encode(&packet, 1, 1, &fields, &body);
    const first = packet.len;
    try encode(&packet, 1, 2, &fields, &body);
    try std.testing.expectEqual(@as(u32, 1), (try parse(packet.slice()[0..first])).serial);
    try std.testing.expectEqual(@as(u32, 2), (try parse(packet.slice()[first..])).serial);
}

test "mutating every header byte cannot escape frame bounds" {
    var fields: Buffer = .{};
    try fields.field(1, 'o', "/x");
    try fields.field(3, 's', "Ping");
    const body: Buffer = .{};
    var packet: Buffer = .{};
    try encode(&packet, 1, 1, &fields, &body);
    for (0..packet.len) |i| {
        const original = packet.bytes[i];
        for (0..256) |b| {
            packet.bytes[i] = @intCast(b);
            _ = parse(packet.slice()) catch continue;
        }
        packet.bytes[i] = original;
    }
}
