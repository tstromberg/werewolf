//! PID 1 for the isolated transfer boundary tests; contains no application code.
const std = @import("std");
const linux = std.os.linux;
pub fn main(init: std.process.Init) noreturn {
    _ = linux.mkdir("/dev", 0o755);
    _ = linux.mkdir("/proc", 0o755);
    _ = linux.mount("devtmpfs", "/dev", "devtmpfs", 0, 0);
    _ = linux.mount("proc", "/proc", "proc", 0, 0);
    const fd = linux.open("/dev/console", .{ .ACCMODE = .RDWR }, 0);
    if (linux.errno(fd) == .SUCCESS) for (0..3) |n| {
        _ = linux.dup2(@intCast(fd), @intCast(n));
    };
    check(init.io) catch {
        std.Io.File.stdout().writeStreamingAll(init.io, "transfer-boundaries-failed\n") catch {};
        poweroff();
    };
    std.Io.File.stdout().writeStreamingAll(init.io, "transfer-boundaries-passed\n") catch {};
    poweroff();
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
