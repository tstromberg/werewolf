//! Open the kernel log before dropping root, then copy it to bounded RAM.
const std = @import("std");
const sandbox = @import("sandbox");
const linux = std.os.linux;

const log_path = "/run/werewolf/vuln-kmsg";
const log_uid = 75;
const max_bytes = 2 << 20;

pub fn main() !void {
    const source: i32 = @intCast(try sandbox.sys(linux.open(
        "/dev/kmsg",
        .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        0,
    ), "open kmsg"));
    const target: i32 = @intCast(try sandbox.sys(linux.open(
        log_path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true, .NOFOLLOW = true },
        0o644,
    ), "open log"));
    // The parent returns to init; the reader has no network or path access.
    const pid = try sandbox.sys(linux.fork(), "fork reader");
    if (pid != 0) return;
    try sandbox.closeAllBut(&.{ source, target });
    try sandbox.dropTo(log_uid, null);
    var filter: sandbox.Filter = .{};
    filter.allowArg("read", 0, @intCast(source));
    filter.allowArg("write", 0, @intCast(target));
    filter.allowArg("ftruncate", 0, @intCast(target));
    filter.allowArg("lseek", 0, @intCast(target));
    filter.allow("exit");
    filter.allow("exit_group");
    filter.allow("rt_sigreturn");
    try filter.install();
    var buffer: [64 << 10]u8 = undefined;
    var offset: usize = 0;
    while (true) {
        const n = linux.read(source, &buffer, buffer.len);
        switch (linux.errno(n)) {
            .SUCCESS => if (n == 0) linux.exit_group(1),
            .INTR => continue,
            // The kernel overwrote records before the reader caught up.
            .PIPE => {
                const lost = "0,0,0,-;vuln-kmsg: kernel log overrun; records lost\n";
                if (!append(target, lost, &offset)) linux.exit_group(1);
                continue;
            },
            else => linux.exit_group(1),
        }
        if (!append(target, buffer[0..n], &offset)) linux.exit_group(1);
    }
}

fn append(fd: i32, bytes: []const u8, offset: *usize) bool {
    if (offset.* + bytes.len > max_bytes) {
        if (linux.errno(linux.ftruncate(fd, 0)) != .SUCCESS or
            linux.errno(linux.lseek(fd, 0, linux.SEEK.SET)) != .SUCCESS) return false;
        offset.* = 0;
    }
    var done: usize = 0;
    while (done < bytes.len) {
        const n = linux.write(fd, bytes[done..].ptr, bytes.len - done);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return false;
        done += n;
    }
    offset.* += done;
    return true;
}
