//! Test-only stage 2 wrapper. The production stage and service set are unchanged.
const std = @import("std");
const test_driver = @import("test-driver");
const Io = std.Io;
const linux = std.os.linux;
const Plan = struct { drivers: []const struct {
    name: []const u8,
    mode: []const u8 = "probes",
    root: bool = false,
    wait: []const []const u8,
} };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len == 1) {
        // Like production stage 2, give output a blocking console. Keep the
        // updater/keeper descriptors for the original stage, never for tests.
        const fd = linux.open("/dev/console", .{ .ACCMODE = .WRONLY, .NOCTTY = true }, 0);
        if (linux.errno(fd) != .SUCCESS) return error.Console;
        _ = linux.dup2(@intCast(fd), 1);
        _ = linux.dup2(@intCast(fd), 2);
        if (fd > 2) _ = linux.close(@intCast(fd));
        _ = try std.process.spawn(io, .{
            .argv = &.{ "/usr/lib/werewolf/test-stage", "run" },
            .stdin = .ignore,
        });
        return std.process.replace(io, .{
            .exe = .{ .explicit = .{ .dir = .cwd(), .path = "/usr/lib/werewolf/runit-stage" } },
            .argv = &.{"/etc/runit/2"},
        });
    }
    if (args.len != 2 or !std.mem.eql(u8, args[1], "run")) return error.Usage;
    _ = linux.close_range(3, std.math.maxInt(linux.fd_t), .{ .UNSHARE = false, .CLOEXEC = false });
    const ctx = try test_driver.Run.load(io, gpa, "/run/config/tests/context");
    const plan = try std.json.parseFromSliceLeaky(Plan, gpa, @embedFile("plan.json"), .{});
    var passed = true;
    for (plan.drivers) |d| {
        const name = d.name;
        if (!try ready(io, d.wait)) {
            try test_driver.emit(io, .{
                .event = "driver",
                .run = ctx.run,
                .phase = ctx.phase,
                .suite = name,
                .status = "fail",
                .reason = "service paths unavailable",
            });
            passed = false;
            continue;
        }
        const result = std.process.run(gpa, io, .{
            .argv = if (d.root) &.{
                try gpa.print(
                    "/usr/lib/werewolf/{s}",
                    .{name},
                ),
                name,
                d.mode,
                "/run/config/tests/context",
            } else &.{"/usr/lib/werewolf/leash"},
            .cwd = .{ .path = try gpa.print(
                "/usr/share/werewolf/tests/{s}",
                .{name},
            ) },
            .stdout_limit = .limited(64 << 10),
            .stderr_limit = .limited(16 << 10),
            .timeout = test_driver.deadline(
                io,
                if (std.mem.eql(u8, name, "test-platform")) 360 else 180,
            ),
        }) catch |err| {
            try test_driver.emit(
                io,
                .{
                    .event = "driver",
                    .run = ctx.run,
                    .phase = ctx.phase,
                    .suite = name,
                    .status = "fail",
                    .reason = @errorName(err),
                },
            );
            passed = false;
            continue;
        };
        try Io.File.stdout().writeStreamingAll(io, result.stdout);
        try Io.File.stderr().writeStreamingAll(io, result.stderr);
        const ok = result.term == .exited and result.term.exited == 0;
        try test_driver.emit(
            io,
            .{
                .event = "driver",
                .run = ctx.run,
                .phase = ctx.phase,
                .suite = name,
                .status = if (ok) "pass" else "fail",
            },
        );
        passed = passed and ok;
    }
    try test_driver.emit(
        io,
        .{
            .event = "complete",
            .run = ctx.run,
            .phase = ctx.phase,
            .status = if (passed) "pass" else "fail",
        },
    );
}

// Wait for leash's logger gate and the Landlock socket/path inodes before
// starting the client; its own checks handle application protocol readiness.
fn ready(io: Io, paths: []const []const u8) !bool {
    const syslog = blk: {
        Io.Dir.cwd().access(io, "/usr/lib/werewolf/syslogd", .{}) catch break :blk false;
        break :blk true;
    };
    for (0..1200) |_| {
        var present = true;
        if (syslog) {
            var flag: [2]u8 = undefined;
            const value = Io.Dir.cwd().readFile(io, "/run/syslog/ready", &flag) catch "";
            present = std.mem.eql(u8, value, "1");
        }
        for (paths) |path| Io.Dir.cwd().access(io, path, .{}) catch {
            present = false;
        };
        if (present) return true;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    return false;
}
