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
        error.FileNotFound => if (client == .ip6 or server == .ip6) return err else "",
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
        // Any connection originating from a local address must have a live
        // client socket in our namespace; fail closed if enumeration fails.
        const fib_trie = try sockets(init.io, gpa, "/proc/net/fib_trie");
        const if_inet6: ?[]const u8 = if (client == .ip6)
            try sockets(init.io, gpa, "/proc/net/if_inet6")
        else
            null;
        if (try isLocalAddress(client, server, fib_trie, if_inet6)) {
            return error.UnknownLocalClient;
        }
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

fn normalizeAddress(addr: Address) Address {
    return switch (addr) {
        .ip4 => addr,
        .ip6 => |a| if (mem.allEqual(u8, a.bytes[0..10], 0) and
            a.bytes[10] == 0xff and a.bytes[11] == 0xff)
            .{ .ip4 = .{ .bytes = a.bytes[12..16].*, .port = a.port } }
        else
            .{ .ip6 = .{ .bytes = a.bytes, .port = a.port } },
    };
}

fn sameHost(a: Address, b: Address) bool {
    const na = normalizeAddress(a);
    const nb = normalizeAddress(b);
    return switch (na) {
        .ip4 => |va| nb == .ip4 and mem.eql(u8, &va.bytes, &nb.ip4.bytes),
        .ip6 => |va| nb == .ip6 and mem.eql(u8, &va.bytes, &nb.ip6.bytes),
    };
}

fn isLocalAddress(
    client: Address,
    server: Address,
    fib_trie: []const u8,
    if_inet6: ?[]const u8,
) !bool {
    const c = normalizeAddress(client);
    const s = normalizeAddress(server);
    if (sameHost(c, s)) return true;
    switch (c) {
        .ip4 => |a| {
            if (a.bytes[0] == 127 or mem.eql(u8, &a.bytes, &.{ 0, 0, 0, 0 })) return true;
            var saw_local = false;
            var candidate: ?[4]u8 = null;
            var lines = mem.splitScalar(u8, fib_trie, '\n');
            while (lines.next()) |raw| {
                const line = mem.trim(u8, raw, " \t\r");
                if (mem.startsWith(u8, line, "|-- ")) {
                    const parsed = Address.parse(line["|-- ".len..], 1) catch {
                        candidate = null;
                        continue;
                    };
                    candidate = if (parsed == .ip4) parsed.ip4.bytes else null;
                    continue;
                }
                if (mem.eql(u8, line, "/32 host LOCAL")) {
                    if (candidate) |ip| {
                        saw_local = true;
                        if (mem.eql(u8, &ip, &a.bytes)) return true;
                    }
                }
                candidate = null;
            }
            if (!saw_local) return error.MissingLocalAddresses;
            return false;
        },
        .ip6 => |a| {
            if (mem.allEqual(u8, a.bytes[0..15], 0) and a.bytes[15] <= 1) {
                return true;
            }
            const text = if_inet6 orelse return error.MissingLocalAddresses;
            var saw_any = false;
            var lines = mem.splitScalar(u8, text, '\n');
            while (lines.next()) |raw| {
                const line = mem.trim(u8, raw, " \t\r");
                if (line.len == 0) continue;
                var fields = mem.tokenizeAny(u8, line, " \t");
                const hex = fields.next() orelse return error.InvalidIfInet6;
                if (hex.len != 32) return error.InvalidIfInet6;
                var bytes: [16]u8 = undefined;
                _ = std.fmt.hexToBytes(&bytes, hex) catch return error.InvalidIfInet6;
                saw_any = true;
                if (mem.eql(u8, &bytes, &a.bytes)) return true;
            }
            if (!saw_any) return error.MissingLocalAddresses;
            return false;
        },
    }
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
    const raw = words.next() orelse return error.InvalidEndpoint;
    const address = if (mem.findScalar(u8, raw, '%')) |zone| raw[0..zone] else raw;
    const port = try std.fmt.parseInt(u16, words.next() orelse return error.InvalidEndpoint, 10);
    if (port == 0) return error.InvalidEndpoint;
    return normalizeAddress(try Address.parse(address, port));
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
    return normalizeAddress(if (size == 4)
        .{ .ip4 = .{ .bytes = bytes[0..4].*, .port = port } }
    else
        Address.fromIp6(.{ .bytes = bytes, .port = port }));
}

fn owner(table: []const u8, client: Address, server: Address) !?u32 {
    const norm_client = normalizeAddress(client);
    const norm_server = normalizeAddress(server);
    var lines = mem.tokenizeScalar(u8, table, '\n');
    while (lines.next()) |line| {
        var fields = mem.tokenizeAny(u8, line, " \t");
        _ = fields.next() orelse continue;
        const local = procEndpoint(fields.next() orelse continue) catch continue;
        const remote = procEndpoint(fields.next() orelse continue) catch continue;
        if (!local.eql(&norm_client) or !remote.eql(&norm_server)) continue;
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

test "IPv4-mapped IPv6 endpoints normalize to IPv4 and local NIC addresses fail closed" {
    const mapped = try connection("::ffff:10.0.2.15 40000 ::ffff:10.0.2.15 22", 22);
    try std.testing.expect(mapped.client == .ip4);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 2, 15 }, &mapped.client.ip4.bytes);
    const table = "0: 0F02000A:9C40 0F02000A:0016 01 00000000:00000000 00:00000000 00000000 " ++
        "60000 0 12\n";
    try std.testing.expectEqual(@as(?u32, 60000), try owner(table, mapped.client, mapped.server));

    const fib =
        \\Local:
        \\  |-- 10.0.2.15
        \\     /32 host LOCAL
        \\  |-- 192.168.50.9
        \\     /32 host LOCAL
        \\  |-- 127.0.0.1
        \\     /32 host LOCAL
    ;
    const secondary = try Address.parse("192.168.50.9", 41234);
    const remote = try Address.parse("198.51.100.7", 41234);
    try std.testing.expect(try isLocalAddress(mapped.client, mapped.server, fib, null));
    try std.testing.expect(try isLocalAddress(secondary, mapped.server, fib, null));
    try std.testing.expect(try isLocalAddress(
        normalizeAddress(try Address.parse("::ffff:127.0.0.1", 41234)),
        mapped.server,
        fib,
        null,
    ));
    try std.testing.expect(!(try isLocalAddress(remote, mapped.server, fib, null)));

    // Empty or unreadable interface address tables fail closed.
    try std.testing.expectError(
        error.MissingLocalAddresses,
        isLocalAddress(remote, mapped.server, "", null),
    );
    const v6_server = try Address.parse("2001:db8::1", 22);
    const v6_remote = try Address.parse("2001:db8::99", 50000);
    const v6_local = try Address.parse("fe80::1234", 50000);
    const inet6 = "fe800000000000000000000000001234 02 40 20 80 eth0\n";
    try std.testing.expect(try isLocalAddress(v6_local, v6_server, fib, inet6));
    try std.testing.expect(!(try isLocalAddress(v6_remote, v6_server, fib, inet6)));
    try std.testing.expectError(
        error.MissingLocalAddresses,
        isLocalAddress(v6_remote, v6_server, fib, null),
    );
}
