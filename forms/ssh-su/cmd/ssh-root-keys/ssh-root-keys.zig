//! Root's AuthorizedKeysCommand: local clients must currently be in wheel.
const std = @import("std");
const people = @import("people");
const linux = std.os.linux;
const mem = std.mem;
const Address = std.Io.net.IpAddress;

pub fn main(init: std.process.Init) !void {
    if (linux.getuid() != 0 or linux.geteuid() != 0) return error.Unauthorized;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 3) return error.InvalidArguments;
    const endpoints = try connection(args[2], try std.fmt.parseInt(u16, args[1], 10));
    const client = endpoints.client;
    const server = endpoints.server;
    const ipv4 = try sockets(init.io, gpa, "/proc/net/tcp");
    const ipv6 = sockets(init.io, gpa, "/proc/net/tcp6") catch |err| switch (err) {
        error.FileNotFound => "",
        else => return err,
    };
    const table = try mem.concat(gpa, u8, &.{ ipv4, "\n", ipv6 });
    if (try owner(table, client, server)) |uid| {
        const passwd = try std.Io.Dir.cwd().readFileAlloc(
            init.io,
            "/etc/passwd",
            gpa,
            .limited(1 << 20),
        );
        const group = try std.Io.Dir.cwd().readFileAlloc(
            init.io,
            "/etc/group",
            gpa,
            .limited(1 << 20),
        );
        if (!people.administrator(passwd, group, uid)) return error.NotAdministrator;
    } else {
        // A loopback connection must have a client socket in our namespace.
        const loopback = switch (client) {
            .ip4 => |a| a.bytes[0] == 127,
            .ip6 => client.eql(&try Address.parse("::1", client.getPort())),
        };
        if (loopback) return error.UnknownLocalClient;
    }
    const keys = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        "/run/werewolf/keys/root",
        gpa,
        .limited(1 << 20),
    );
    try std.Io.File.stdout().writeStreamingAll(init.io, keys);
}

fn sockets(io: std.Io, gpa: mem.Allocator, path: []const u8) ![]const u8 {
    // procfs reports a zero size; read until EOF rather than trust stat.
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var buffer: [4096]u8 = undefined;
    var reader = file.readerStreaming(io, &buffer);
    return reader.interface.allocRemaining(gpa, .limited(8 << 20));
}

fn connection(text: []const u8, listener: u16) !struct { client: Address, server: Address } {
    var words = mem.tokenizeScalar(u8, text, ' ');
    const first = try endpoint(&words);
    const second = try endpoint(&words);
    const ambiguous = (first.getPort() == listener) == (second.getPort() == listener);
    if (listener == 0 or words.next() != null or ambiguous) return error.InvalidArguments;
    // Identify the listener explicitly rather than depend on pair ordering.
    return if (first.getPort() == listener)
        .{ .client = second, .server = first }
    else
        .{ .client = first, .server = second };
}

test "connection endpoints are identified by the configured listener port" {
    const a = try connection("127.0.0.1 22 127.0.0.1 40000", 22);
    const b = try connection("127.0.0.1 40000 127.0.0.1 22", 22);
    try std.testing.expect(a.client.eql(&b.client));
    try std.testing.expect(a.server.eql(&b.server));
    try std.testing.expectEqual(@as(u16, 40000), a.client.getPort());
    try std.testing.expectError(
        error.InvalidArguments,
        connection("127.0.0.1 22 127.0.0.1 22", 22),
    );
}

fn endpoint(words: *mem.TokenIterator(u8, .scalar)) !Address {
    const address = words.next() orelse return error.InvalidEndpoint;
    const port = try std.fmt.parseInt(u16, words.next() orelse return error.InvalidEndpoint, 10);
    if (port == 0) return error.InvalidEndpoint;
    return Address.parse(address, port);
}

fn procEndpoint(text: []const u8) !Address {
    const colon = mem.findScalar(u8, text, ':') orelse return error.InvalidSocket;
    const size: usize = switch (colon) {
        8 => 4,
        32 => 16,
        else => return error.InvalidSocket,
    };
    var bytes: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(bytes[0..size], text[0..colon]);
    // proc prints each native-endian 32-bit address word as hexadecimal.
    if (@import("builtin").cpu.arch.endian() == .little) {
        var i: usize = 0;
        while (i < size) : (i += 4) mem.reverse(u8, bytes[i..][0..4]);
    }
    const port = try std.fmt.parseInt(u16, text[colon + 1 ..], 16);
    return if (size == 4)
        .{ .ip4 = .{ .bytes = bytes[0..4].*, .port = port } }
    else
        Address.fromIp6(.{ .bytes = bytes, .port = port });
}

fn owner(table: []const u8, client: Address, server: Address) !?u32 {
    var lines = mem.tokenizeScalar(u8, table, '\n');
    while (lines.next()) |line| {
        var fields = mem.tokenizeAny(u8, line, " \t");
        _ = fields.next() orelse continue;
        const local = procEndpoint(fields.next() orelse continue) catch continue;
        const remote = procEndpoint(fields.next() orelse continue) catch continue;
        if (!local.eql(&client) or !remote.eql(&server)) continue;
        if (!mem.eql(u8, fields.next() orelse return error.InvalidSocket, "01")) continue;
        for (0..3) |_| _ = fields.next() orelse return error.InvalidSocket;
        return try std.fmt.parseInt(u32, fields.next() orelse return error.InvalidSocket, 10);
    }
    return null;
}

test "local reauthentication checks the exact live client tuple" {
    const c = try Address.parse("127.0.0.1", 40000);
    const s = try Address.parse("127.0.0.1", 22);
    const table = "0: 0100007F:9C40 0100007F:0016 01 00000000:00000000 00:00000000 00000000 " ++
        "1001 0 12\n";
    try std.testing.expectEqual(@as(?u32, 1001), try owner(table, c, s));
    try std.testing.expectEqual(@as(?u32, null), try owner(table, s, c));
    try std.testing.expectEqual(
        @as(?u32, null),
        try owner(table, try Address.parse("127.0.0.1", 40001), s),
    );
    const mapped = "0: 0000000000000000FFFF00000100007F:9C40 " ++
        "0000000000000000FFFF00000100007F:0016 01 " ++
        "00000000:00000000 00:00000000 00000000 1001 0 12\n";
    try std.testing.expectEqual(@as(?u32, 1001), try owner(mapped, c, s));
}
