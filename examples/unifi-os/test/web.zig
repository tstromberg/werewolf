//! HTTP/1.0 GET from a loopback port for the console checks. TLS is left
//! unverified, like curl -k: Core issues its console certificate itself.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const tls = std.crypto.tls;

pub const Response = struct { status: u16, body: []const u8 };

pub fn get(io: Io, a: Allocator, port: u16, path: []const u8, secure: bool) !Response {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var reader = stream.reader(io, try a.alloc(u8, tls.Client.min_buffer_len));
    var writer = stream.writer(io, try a.alloc(u8, tls.Client.min_buffer_len));
    const request = try a.print("GET {s} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", .{path});
    if (!secure) {
        try writer.interface.writeAll(request);
        try writer.interface.flush();
        return parse(try reader.interface.allocRemaining(a, .limited(1 << 20)));
    }
    var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    var client = try tls.Client.init(&reader.interface, &writer.interface, .{
        .host = .no_verification,
        .ca = .no_verification,
        .read_buffer = try a.alloc(u8, tls.Client.min_buffer_len + 8192),
        .write_buffer = try a.alloc(u8, 1024),
        .entropy = &entropy,
        .realtime_now = Io.Clock.real.now(io),
        // HTTP/1.0 ends the body with the connection; a short body fails its check.
        .allow_truncation_attacks = true,
    });
    try client.writer.writeAll(request);
    try client.writer.flush();
    try writer.interface.flush();
    return parse(try client.reader.allocRemaining(a, .limited(1 << 20)));
}

/// The status and body of a response whose body runs to the end.
pub fn parse(raw: []const u8) !Response {
    const end = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.HttpHeader;
    const line = raw[0 .. std.mem.find(u8, raw, "\r\n") orelse unreachable];
    if (line.len < 12 or !std.mem.startsWith(u8, line, "HTTP/1.") or line[8] != ' ' or
        (line.len > 12 and line[12] != ' ')) return error.HttpStatus;
    for (line[9..12]) |c| if (!std.ascii.isDigit(c)) return error.HttpStatus;
    return .{
        .status = std.fmt.parseInt(u16, line[9..12], 10) catch unreachable,
        .body = raw[end + 4 ..],
    };
}

/// A line of the page carries the console manifest naming UOSSERVER.
pub fn manifest(body: []const u8) bool {
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |line| {
        const at = std.mem.find(u8, line, "window.UNIFI_OS_MANIFEST") orelse continue;
        if (std.mem.find(u8, line[at..], "UOSSERVER") != null) return true;
    }
    return false;
}

test "responses split into a status and the rest of the stream" {
    const t = std.testing;
    const ok = try parse("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html>\r\n\r\nrest");
    try t.expectEqual(@as(u16, 200), ok.status);
    try t.expectEqualStrings("<html>\r\n\r\nrest", ok.body);
    try t.expectEqual(@as(u16, 404), (try parse("HTTP/1.0 404\r\n\r\n")).status);
    try t.expectError(error.HttpHeader, parse("HTTP/1.1 200 OK\r\n"));
    try t.expectError(error.HttpStatus, parse("HTTP/1.1 2000 OK\r\n\r\n"));
    try t.expectError(error.HttpStatus, parse("SSH-2.0-OpenSSH\r\n\r\n"));
    try t.expectError(error.HttpStatus, parse("HTTP/1.1 +20 OK\r\n\r\n"));
}

test "the manifest and its product name share a line" {
    try std.testing.expect(
        manifest("<script>\nwindow.UNIFI_OS_MANIFEST = {\"x\":\"UOSSERVER\"}\n"),
    );
    try std.testing.expect(!manifest("window.UNIFI_OS_MANIFEST = {}\nUOSSERVER\n"));
    try std.testing.expect(!manifest("UOSSERVER window.UNIFI_OS_MANIFEST\n"));
}
