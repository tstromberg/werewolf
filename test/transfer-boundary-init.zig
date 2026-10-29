//! PID 1 for the isolated transfer boundary tests; contains no application code.
const std = @import("std");
const linux = std.os.linux;
pub fn main(init: std.process.Init) noreturn {
    _ = linux.mkdir("/dev", 0o755);
    _ = linux.mkdir("/proc", 0o755);
    _ = linux.mount("devtmpfs", "/dev", "devtmpfs", 0, 0);
    _ = linux.mount("proc", "/proc", "proc", 0, 0);
    _ = linux.mkdir("/tmp", 0o700);
    if (linux.errno(linux.mount("tmpfs", "/tmp", "tmpfs", 0, 0)) != .SUCCESS or
        linux.errno(linux.chdir("/tmp")) != .SUCCESS) poweroff();
    const fd = linux.open("/dev/console", .{ .ACCMODE = .RDWR }, 0);
    if (linux.errno(fd) == .SUCCESS) for (0..3) |n| {
        _ = linux.dup2(@intCast(fd), @intCast(n));
    };
    cgroupCheck(init.io, init.arena.allocator()) catch |err| {
        std.debug.print("transfer-cgroup-failed: {s}\n", .{@errorName(err)});
        poweroff();
    };
    check(init.io) catch {
        std.Io.File.stdout().writeStreamingAll(init.io, "transfer-boundaries-failed\n") catch {};
        poweroff();
    };
    std.Io.File.stdout().writeStreamingAll(init.io, "transfer-boundaries-passed\n") catch {};
    poweroff();
}

fn cgroupCheck(io: std.Io, a: std.mem.Allocator) !void {
    const Dir = std.Io.Dir;
    const data = @import("data-transfer");
    try Dir.cwd().createDirPath(io, "/transfer-cgroups");
    if (linux.errno(linux.mount("none", "/transfer-cgroups", "cgroup2", 0, 0)) != .SUCCESS)
        return error.CgroupMount;
    try Dir.cwd().createDirPath(io, "/transfer-cgroups/app");
    try Dir.cwd().createDirPath(io, "/transfer-supervise/supervise.app");
    var status: [20]u8 = @splat(0);
    status[17] = 'd';
    try Dir.cwd().writeFile(io, .{ .sub_path = "/transfer-supervise/supervise.app/status", .data = &status, .flags = .{ .permissions = .fromMode(0o600) } });
    var supervision = try Dir.cwd().openDir(io, "/transfer-supervise", .{});
    defer supervision.close(io);
    var cgroups = try Dir.cwd().openDir(io, "/transfer-cgroups", .{});
    defer cgroups.close(io);
    const membership = try cgroups.openFile(io, "app/cgroup.procs", .{ .mode = .read_write });
    defer membership.close(io);
    try membership.writeStreamingAll(io, "0\n");
    if (try membership.length(io) != 0) return error.CgroupSize;
    if (data.supervision.capture(io, a, supervision, cgroups, &.{"app"})) |_|
        return error.CgroupWriterAccepted
    else |err| if (err != error.TransferWritersRunning) return err;
    const home = try cgroups.openFile(io, "cgroup.procs", .{ .mode = .read_write });
    defer home.close(io);
    try home.writeStreamingAll(io, "0\n");
    _ = try data.supervision.capture(io, a, supervision, cgroups, &.{"app"});
    try std.Io.File.stdout().writeStreamingAll(io, "transfer-cgroup-stream-passed\n");
}
fn check(io: std.Io) !void {
    var child = try std.process.spawn(io, .{ .argv = &.{"/checks"}, .stdin = .ignore, .stdout = .inherit, .stderr = .inherit });
    defer child.kill(io);
    if (!(try child.wait(io)).success()) return error.Failed;
}
fn poweroff() noreturn {
    _ = linux.sync();
    _ = linux.reboot(.MAGIC1, .MAGIC2, .POWER_OFF, null);
    while (true) _ = linux.pause();
}
