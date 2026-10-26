//! Supply a real backend, inspect forwarded headers and send an incomplete request.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const path = "/werewolf-check";
const response = "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n" ++
    "werewolf-backend";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "wire")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(443) };
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    const Event = union(enum) {
        backend: anyerror!Headers,
        client: anyerror!void,
        timeout: Io.Cancelable!void,
    };
    var buffer: [3]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.backend, serve, .{ io, &server });
    try events.concurrent(.client, fetch, .{io});
    try events.concurrent(.timeout, sleep, .{ io, 65 });
    var forwarded: ?Headers = null;
    var delivered = false;
    while (forwarded == null or !delivered) switch (try events.await()) {
        .backend => |result| forwarded = try result,
        .client => |result| {
            try result;
            delivered = true;
        },
        .timeout => |result| {
            try result;
            return error.BackendTimeout;
        },
    };
    events.cancelDiscard();
    try ctx.result(io, args[1], "haproxy-proxies", delivered);
    const headers = forwarded.?;
    try ctx.result(io, args[1], "haproxy-httpoxy", safeHeaders(headers.bytes[0..headers.len]));
    try slow(io);
    try ctx.result(io, args[1], "haproxy-slow", true);
}

const Headers = struct { bytes: [8192]u8 = undefined, len: usize = 0 };

fn readHeaders(io: Io, stream: Io.net.Stream) !Headers {
    var bytes: [1024]u8 = undefined;
    var reader = stream.reader(io, &bytes);
    var headers: Headers = .{};
    while (headers.len < headers.bytes.len) {
        headers.bytes[headers.len] = try reader.interface.takeByte();
        headers.len += 1;
        if (std.mem.endsWith(u8, headers.bytes[0..headers.len], "\r\n\r\n")) return headers;
    }
    return error.HeadersTooLong;
}

fn serve(io: Io, server: *Io.net.Server) !Headers {
    // Health checks open and close TCP without sending a request.
    while (true) {
        const stream = try server.accept(io);
        defer stream.close(io);
        const headers = readHeaders(io, stream) catch |err| switch (err) {
            error.EndOfStream => continue,
            else => return err,
        };
        var bytes: [1024]u8 = undefined;
        var writer = stream.writer(io, &bytes);
        try writer.interface.writeAll(response);
        try writer.interface.flush();
        return headers;
    }
}

fn fetch(io: Io) !void {
    const stop = Io.Clock.awake.now(io).addDuration(.fromSeconds(60));
    while (true) {
        const address: Io.net.IpAddress = .{ .ip4 = .loopback(80) };
        const stream = try address.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var bytes: [1024]u8 = undefined;
        var writer = stream.writer(io, &bytes);
        try writer.interface.writeAll("GET " ++ path ++ " HTTP/1.0\r\nHost: localhost\r\n" ++
            "Proxy: http://evil.example/\r\nConnection: close\r\n\r\n");
        try writer.interface.flush();
        var reader = stream.reader(io, &bytes);
        var result: [8192]u8 = undefined;
        const n = try reader.interface.readSliceShort(&result);
        const reply = result[0..n];
        if (std.mem.startsWith(u8, reply, "HTTP/1.1 200 ")) {
            const at = std.mem.find(u8, reply, "\r\n\r\n") orelse return error.ResponseHeaders;
            if (!std.mem.eql(u8, reply[at + 4 ..], "werewolf-backend")) return error.ResponseBody;
            return;
        }
        if (!std.mem.startsWith(u8, reply, "HTTP/1.1 503 ")) return error.ResponseStatus;
        if (Io.Clock.awake.now(io).compare(.gte, stop)) return error.BackendUnavailable;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
}

fn slow(io: Io) !void {
    const Event = union(enum) { response: anyerror!void, timeout: Io.Cancelable!void };
    var buffer: [2]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.response, incomplete, .{io});
    try events.concurrent(.timeout, sleep, .{ io, 20 });
    switch (try events.await()) {
        .response => |result| try result,
        .timeout => |result| {
            try result;
            return error.SlowRequestNotRejected;
        },
    }
}
fn incomplete(io: Io) !void {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(80) };
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var bytes: [1024]u8 = undefined;
    var writer = stream.writer(io, &bytes);
    try writer.interface.writeAll("GET / HTTP/1.1\r\nHost: localhost\r\n");
    try writer.interface.flush();
    const headers = try readHeaders(io, stream);
    if (!std.mem.startsWith(u8, headers.bytes[0..headers.len], "HTTP/1.1 408 "))
        return error.SlowRequestStatus;
}
fn sleep(io: Io, seconds: i64) Io.Cancelable!void {
    try io.sleep(.fromSeconds(seconds), .awake);
}

fn safeHeaders(headers: []const u8) bool {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    const first = lines.next() orelse return false;
    if (!std.mem.eql(u8, first, "GET " ++ path ++ " HTTP/1.0") and
        !std.mem.eql(u8, first, "GET " ++ path ++ " HTTP/1.1")) return false;
    var forwarded = false;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.findScalar(u8, line, ':') orelse return false;
        if (std.ascii.eqlIgnoreCase(line[0..colon], "proxy")) return false;
        if (std.ascii.eqlIgnoreCase(line[0..colon], "x-forwarded-for")) {
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (forwarded or !std.mem.eql(u8, value, "127.0.0.1")) return false;
            forwarded = true;
        }
    }
    return forwarded;
}

test "httpoxy inspects complete header names and the actual forwarded address" {
    const request = "GET /werewolf-check HTTP/1.0\r\n";
    const address = "X-Forwarded-For: 127.0.0.1\r\n\r\n";
    try std.testing.expect(safeHeaders(request ++ address));
    try std.testing.expect(!safeHeaders(request ++ "pRoXy: evil\r\n" ++ address));
    try std.testing.expect(!safeHeaders(request ++ "X-Forwarded-For: 127.0.0.2\r\n\r\n"));
    try std.testing.expect(!safeHeaders(request ++ "X-Forwarded-For: 127.0.0.1\r\n" ++ address));
    try std.testing.expect(!safeHeaders("GET /other HTTP/1.0\r\n" ++ address));
    try std.testing.expect(!safeHeaders(request ++ "Host: localhost\r\n\r\n"));
}
