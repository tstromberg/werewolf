//! Exercise the real server-list, ping and unauthenticated login protocols.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const Event = union(enum) { checked: anyerror!void, timeout: Io.Cancelable!void };
    var buffer: [2]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.checked, check, .{ io, a, ctx, args[1], args[2] });
    try events.concurrent(.timeout, timeout, .{io});
    switch (try events.await()) {
        .checked => |result| try result,
        .timeout => |result| {
            try result;
            return error.MinecraftTimeout;
        },
    }
}

fn timeout(io: Io) Io.Cancelable!void {
    try io.sleep(.fromSeconds(180), .awake);
}

fn check(io: Io, a: Allocator, ctx: driver.Run, suite: []const u8, mode: []const u8) !void {
    const ready = std.mem.eql(u8, mode, "ready");
    if (!ready and !std.mem.eql(u8, mode, "game")) return error.Usage;
    // The lifecycle probe restarts Java after the first readiness pass.
    while (true) {
        var attempt: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer attempt.deinit();
        status(io, attempt.allocator(), !ready) catch |err| switch (err) {
            error.ConnectionRefused, error.EndOfStream => {
                try io.sleep(.fromMilliseconds(100), .awake);
                continue;
            },
            else => return err,
        };
        break;
    }
    if (ready) return ctx.result(io, suite, "mc-up", true);
    try ctx.result(io, suite, "mc-ping", true);
    try stranger(io, a);
    try ctx.result(io, suite, "mc-stranger", true);
    const management: Io.net.IpAddress = .{ .ip4 = .loopback(25575) };
    if (management.connect(io, .{ .mode = .stream })) |unexpected| {
        unexpected.close(io);
        return error.RconListening;
    } else |err| if (err != error.ConnectionRefused and err != error.AccessDenied) return err;
    try ctx.result(io, suite, "mc-no-rcon", true);
}

fn status(io: Io, a: Allocator, pinging: bool) !void {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(25565) };
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var input: [4096]u8 = undefined;
    var output: [4096]u8 = undefined;
    var reader = stream.reader(io, &input);
    var writer = stream.writer(io, &output);
    try writer.interface.writeAll("\x10\x00\x89\x06\x09localhost\x63\xdd\x01\x01\x00");
    try writer.interface.flush();
    const body = try packet(a, &reader.interface);
    var cursor: Cursor = .{ .bytes = body };
    if (try cursor.number() != 0) return error.StatusPacket;
    const json = try cursor.take(try cursor.number());
    if (cursor.offset != body.len) return error.TrailingStatus;
    const value = try std.json.parseFromSliceLeaky(std.json.Value, a, json, .{});
    if (value != .object) return error.BadStatus;
    const description = value.object.get("description") orelse return error.MissingDescription;
    const text = if (description == .string) description else if (description == .object)
        description.object.get("text") orelse return error.MissingDescription
    else
        return error.BadDescription;
    if (text != .string or !std.mem.eql(u8, text.string, "werewolf")) return error.WrongServer;
    if (!pinging) return;
    var ping: [10]u8 = undefined;
    ping[0] = 9;
    ping[1] = 1;
    io.random(ping[2..]);
    try writer.interface.writeAll(&ping);
    try writer.interface.flush();
    if (!std.mem.eql(u8, try packet(a, &reader.interface), ping[1..]))
        return error.PingMismatch;
}

fn stranger(io: Io, a: Allocator) !void {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(25565) };
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var input: [4096]u8 = undefined;
    var output: [4096]u8 = undefined;
    var reader = stream.reader(io, &input);
    var writer = stream.writer(io, &output);
    try writer.interface.writeAll(
        "\x10\x00\x89\x06\x09localhost\x63\xdd\x02" ++
            "\x1a\x00\x08stranger" ++
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    );
    try writer.interface.flush();
    try challenge(try packet(a, &reader.interface));
}

fn packet(a: Allocator, reader: *Io.Reader) ![]const u8 {
    var prefix: [5]u8 = undefined;
    for (&prefix, 0..) |*byte, i| {
        byte.* = try reader.takeByte();
        if (byte.* < 128) {
            var cursor: Cursor = .{ .bytes = prefix[0 .. i + 1] };
            const length = try cursor.number();
            if (length == 0 or length > 65536) return error.PacketLength;
            const payload = try a.alloc(u8, length);
            try reader.readSliceAll(payload);
            return payload;
        }
    }
    return error.BadVarint;
}

const Cursor = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn take(c: *Cursor, size: usize) ![]const u8 {
        if (size > c.bytes.len - c.offset) return error.TruncatedPacket;
        const value = c.bytes[c.offset..][0..size];
        c.offset += size;
        return value;
    }

    fn number(c: *Cursor) !u32 {
        var value: u32 = 0;
        for (0..5) |i| {
            const byte = (try c.take(1))[0];
            if (i == 4 and byte > 7) return error.BadVarint;
            value |= @as(u32, byte & 127) << @intCast(i * 7);
            if (byte < 128) return value;
        }
        return error.BadVarint;
    }
};

fn challenge(bytes: []const u8) !void {
    var cursor: Cursor = .{ .bytes = bytes };
    if (try cursor.number() != 1) return error.NoEncryptionChallenge;
    const server = try cursor.take(try cursor.number());
    const key = try cursor.take(try cursor.number());
    const token = try cursor.take(try cursor.number());
    const authenticate = try cursor.take(1);
    if (server.len > 20 or key.len == 0 or token.len == 0 or
        authenticate[0] != 1 or cursor.offset != bytes.len) return error.BadEncryptionChallenge;
}

test "packet fields reject truncation and overlong or negative lengths" {
    var good: Cursor = .{ .bytes = "\x89\x06abc" };
    try std.testing.expectEqual(@as(u32, 777), try good.number());
    try std.testing.expectEqualStrings("abc", try good.take(3));
    try std.testing.expectError(error.TruncatedPacket, good.take(1));
    for ([_][]const u8{ "\x80", "\xff\xff\xff\xff\xff", "\xff\xff\xff\xff\x0f" }) |bad| {
        var cursor: Cursor = .{ .bytes = bad };
        if (cursor.number()) |_| return error.AcceptedBadLength else |_| {}
    }
}

test "a stranger must be challenged for authentication before login" {
    try challenge("\x01\x00\x03key\x03tok\x01");
    for ([_][]const u8{
        "\x02\x00\x03key\x03tok\x01",
        "\x01\x00\x00\x03tok\x01",
        "\x01\x00\x03key\x03tok\x00",
        "\x01\x00\x03key\x03tok",
        "\x01\x00\x03key\x03tok\x01extra",
    }) |bad| if (challenge(bad)) |_| return error.AcceptedBadChallenge else |_| {};
}
