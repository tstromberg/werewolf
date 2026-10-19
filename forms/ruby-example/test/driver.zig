//! Exercise raw HTTP/1.0 framing and a genuinely fragmented request.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "wire")) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    for ([_]bool{ false, true }) |fragmented| {
        const response = try exchange(a, init.io, fragmented);
        const body_at = std.mem.find(u8, response, "\r\n\r\n") orelse return error.Headers;
        const body = response[body_at + 4 ..];
        try ctx.result(
            init.io,
            args[1],
            if (fragmented) "ruby-fragmented" else "ruby-framing",
            framed(response) and std.mem.startsWith(u8, body, "werewolf: Ruby ") and
                std.mem.endsWith(u8, body, " is answering\n"),
        );
    }
}

fn exchange(a: Allocator, io: Io, fragmented: bool) ![]const u8 {
    const Event = union(enum) { response: anyerror![]const u8, timeout: Io.Cancelable!void };
    var buffer: [2]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.response, request, .{ a, io, fragmented });
    try events.concurrent(.timeout, sleep, .{io});
    return switch (try events.await()) {
        .response => |result| try result,
        .timeout => |result| {
            try result;
            return error.Timeout;
        },
    };
}
fn sleep(io: Io) Io.Cancelable!void {
    try io.sleep(.fromSeconds(5), .awake);
}
fn request(a: Allocator, io: Io, fragmented: bool) ![]const u8 {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(8080) };
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    if (fragmented) {
        try writer.interface.writeAll("GET / HTTP/1.1\r\nHost: localhost\r\n");
        try writer.interface.flush();
        try io.sleep(.fromSeconds(1), .awake);
        try writer.interface.writeAll("\r\n");
    } else try writer.interface.writeAll("GET / HTTP/1.0\r\n\r\n");
    try writer.interface.flush();
    var reader = stream.reader(io, &buffer);
    return reader.interface.allocRemaining(a, .limited(8192));
}

fn framed(response: []const u8) bool {
    const end = std.mem.find(u8, response, "\r\n\r\n") orelse return false;
    var lines = std.mem.splitSequence(u8, response[0..end], "\r\n");
    if (!std.mem.eql(u8, lines.next() orelse return false, "HTTP/1.1 200 OK")) return false;
    var length: ?usize = null;
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse return false;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "content-length")) continue;
        if (length != null) return false;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (value.len == 0) return false;
        for (value) |ch| if (!std.ascii.isDigit(ch)) return false;
        length = std.fmt.parseInt(usize, value, 10) catch return false;
    }
    return length != null and length.? == response.len - end - 4;
}

test "wire framing rejects truncated, extra, duplicate and malformed lengths" {
    const prefix = "HTTP/1.1 200 OK\r\nContent-Length: ";
    try std.testing.expect(framed(prefix ++ "1\r\n\r\nx"));
    try std.testing.expect(!framed(prefix ++ "2\r\n\r\nx"));
    try std.testing.expect(!framed(prefix ++ "1\r\n\r\nxx"));
    try std.testing.expect(!framed(prefix ++ "1\r\nContent-Length: 1\r\n\r\nx"));
    try std.testing.expect(!framed(prefix ++ "broken\r\n\r\nx"));
    try std.testing.expect(!framed(prefix ++ "+1\r\n\r\nx"));
}
