//! Shared console protocol for boot-time integration clients. No shell or commands from config.
const std = @import("std");
const Io = std.Io;

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

/// Read both tables: an unreadable table must fail, never prove no listener.
pub fn tcpPrivate(io: Io, gpa: std.mem.Allocator, port: u16, allow_loopback: bool) !bool {
    for ([_][]const u8{ "/proc/net/tcp", "/proc/net/tcp6" }) |path| {
        const table = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err| {
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
    _ = lines.next();
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
    try std.testing.expect(!privateTable(
        "header\n0: 00000000:1538 00000000:0000 0A\n",
        5432,
        true,
    ));
    try std.testing.expect(privateTable("header\n0: 0100007F:1538 00000000:0000 0A\n", 5432, true));
    try std.testing.expect(!privateTable(
        "header\n0: 0100007F:1538 00000000:0000 0A\n",
        5432,
        false,
    ));
    try std.testing.expect(!privateTable(
        "header\n0: 00000000000000000000000000000000:1538 x 0A\n",
        5432,
        true,
    ));
    try std.testing.expect(privateTable(
        "header\n0: 00000000000000000000000001000000:1538 x 0A\n",
        5432,
        true,
    ));
    try std.testing.expect(privateTable(
        "header\n0: 00000000:1538 00000000:0000 01\n",
        5432,
        false,
    ));
}
