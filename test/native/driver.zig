//! Shared console protocol for boot-time integration clients. No shell or commands from config.
const std = @import("std");
const Io = std.Io;
pub const fetch = @import("fetch.zig");
pub const system = @import("system.zig");
pub const udp = @import("udp.zig");

pub const Run = struct {
    run: []const u8,
    phase: []const u8,

    pub fn load(io: Io, gpa: std.mem.Allocator, path: []const u8) !Run {
        const raw = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4096));
        const c = try std.json.parseFromSliceLeaky(Run, gpa, raw, .{});
        if (c.run.len != 32) return error.InvalidRun;
        for (c.run) |ch| if (!std.ascii.isHex(ch)) return error.InvalidRun;
        if (!std.mem.eql(u8, c.phase, "seed") and !std.mem.eql(u8, c.phase, "verify"))
            return error.InvalidPhase;
        return c;
    }

    pub fn result(c: Run, io: Io, suite: []const u8, name: []const u8, passed: bool) !void {
        try emit(
            io,
            .{
                .event = "case",
                .run = c.run,
                .phase = c.phase,
                .suite = suite,
                .case = name,
                .status = if (passed) "pass" else "fail",
            },
        );
        if (!passed) return error.AssertionFailed;
    }
};

pub fn emit(io: Io, value: anytype) !void {
    var buf: [4096]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try out.writeAll("werewolf-test: ");
    try std.json.Stringify.value(value, .{}, &out);
    try out.writeByte('\n');
    try Io.File.stdout().writeStreamingAll(io, out.buffered());
}

pub fn deadline(io: Io, seconds: i64) Io.Timeout {
    return (Io.Timeout{ .duration = .{
        .raw = .fromSeconds(seconds),
        .clock = .awake,
    } }).toDeadline(io);
}

/// procfs reports size zero. Stream it rather than trusting stat's size.
pub fn readKernel(io: Io, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var reader = file.readerStreaming(io, &buf);
    const text = try reader.interface.allocRemaining(gpa, .limited(4 << 20));
    if (text.len == 0) {
        gpa.free(text);
        return error.EmptyKernelFile;
    }
    return text;
}

test "kernel files with stat size zero are read as streams" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const text = try readKernel(std.testing.io, std.testing.allocator, "/proc/self/status");
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.startsWith(u8, text, "Name:"));
}

/// Read both tables: an unreadable table must fail, never prove no listener.
pub fn tcpPrivate(io: Io, gpa: std.mem.Allocator, port: u16, allow_loopback: bool) !bool {
    for ([_][]const u8{ "/proc/net/tcp", "/proc/net/tcp6" }) |path| {
        const table = readKernel(io, gpa, path) catch |err| {
            if (err != error.FileNotFound or !std.mem.endsWith(u8, path, "tcp6")) return err;
            // ipv6.disable=1 can leave TCPv6 in the protocol registry despite
            // rejecting IPv6 sockets. Require that specific kernel refusal;
            // a permission failure must not masquerade as an absent stack.
            const linux = std.os.linux;
            const fd = linux.socket(linux.AF.INET6, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
            const why = linux.errno(fd);
            if (why == .SUCCESS) _ = linux.close(@intCast(fd));
            if (why != .AFNOSUPPORT) return error.UnobservableTcp6;
            continue;
        };
        defer gpa.free(table);
        if (!privateTable(table, port, allow_loopback)) return false;
    }
    return true;
}

fn privateTable(table: []const u8, port: u16, allow_loopback: bool) bool {
    var lines = std.mem.tokenizeScalar(u8, table, '\n');
    var header = std.mem.tokenizeAny(u8, lines.next() orelse return false, " \t");
    for ([_][]const u8{ "sl", "local_address" }) |word|
        if (!std.mem.eql(u8, header.next() orelse return false, word)) return false;
    const remote = header.next() orelse return false;
    if (!std.mem.eql(u8, remote, "rem_address") and
        !std.mem.eql(u8, remote, "remote_address")) return false;
    if (!std.mem.eql(u8, header.next() orelse return false, "st")) return false;
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        _ = fields.next() orelse return false;
        const local = fields.next() orelse return false;
        _ = fields.next() orelse return false;
        const state = fields.next() orelse return false;
        const split = std.mem.findScalarLast(u8, local, ':') orelse return false;
        const got = std.fmt.parseInt(u16, local[split + 1 ..], 16) catch return false;
        if (got != port or !std.mem.eql(u8, state, "0A")) continue;
        if (!allow_loopback) return false;
        const address = local[0..split];
        if (!std.mem.eql(u8, address, "0100007F") and
            !std.mem.eql(u8, address, "00000000000000000000000001000000")) return false;
    }
    return true;
}

test "private listeners cover IPv4, IPv6, wildcard and non-listening sockets" {
    try std.testing.expect(!privateTable("", 5432, true));
    try std.testing.expect(!privateTable("unobserved\n", 5432, true));
    try std.testing.expect(!privateTable(
        "sl local_address rem_address st\n0: 00000000:1538 00000000:0000 0A\n",
        5432,
        true,
    ));
    try std.testing.expect(privateTable(
        "sl local_address rem_address st\n0: 0100007F:1538 00000000:0000 0A\n",
        5432,
        true,
    ));
    try std.testing.expect(!privateTable(
        "sl local_address rem_address st\n0: 0100007F:1538 00000000:0000 0A\n",
        5432,
        false,
    ));
    try std.testing.expect(!privateTable(
        "sl local_address rem_address st\n0: 00000000000000000000000000000000:1538 x 0A\n",
        5432,
        true,
    ));
    try std.testing.expect(privateTable(
        "sl local_address rem_address st\n0: 00000000000000000000000001000000:1538 x 0A\n",
        5432,
        true,
    ));
    try std.testing.expect(privateTable(
        "sl local_address rem_address st\n0: 00000000:1538 00000000:0000 01\n",
        5432,
        false,
    ));
}
