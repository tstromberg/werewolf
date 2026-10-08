//! reboot, poweroff: stop the machine cleanly, then restart it or turn it
//! off. One program under two names, as OpenBSD's reboot and halt are.
//!
//! It sets runit's reboot flag, /etc/runit/reboot, as runit-init does
//! (executable to restart, not to turn off), and ends stage 2, runsvdir, PID
//! 1's child, with SIGTERM: runsvdir exits at once, and runit runs stage 3
//! (/etc/runit/3), which stops the services and puts /data down, then
//! restarts or powers off as the flag says. runit-init asks runit instead,
//! and runit then signals stage 2 and, unless it has already exited, waits
//! a whole second to look again: a second of most reboots, as an update's.
//! Where stage 2 cannot be found or signalled, it asks through runit-init
//! (6 to restart, 0 to turn off), as before.

const std = @import("std");
const linux = std.os.linux;

const reboot_flag = "/etc/runit/reboot";

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const level = (if (args.len == 1) levelFor(std.fs.path.basename(args[0])) else null) orelse {
        std.debug.print("usage: reboot | poweroff\n", .{});
        std.process.exit(2);
    };
    if (setFlag(std.mem.eql(u8, level, "6"))) if (stageTwo()) |pid| {
        if (linux.errno(linux.kill(pid, linux.SIG.TERM)) == .SUCCESS) std.process.exit(0);
    };
    const err = std.process.replace(init.io, .{ .argv = &.{ "/usr/bin/runit-init", level } });
    std.debug.print("{s}: runit-init: {s}\n", .{ args[0], @errorName(err) });
    std.process.exit(1);
}

/// runit-init's level for the name this was run as: 6 to restart, 0 to
/// turn off, and none for any other name, so a stray link (halt, say)
/// does nothing.
fn levelFor(name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "reboot")) return "6";
    if (std.mem.eql(u8, name, "poweroff")) return "0";
    return null;
}

/// runit's reboot flag, made if it is not there: its owner's execute bit
/// says restart, and none says turn off, which runit reads after stage 3.
fn setFlag(restart: bool) bool {
    const fd = linux.open(reboot_flag, .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    return linux.errno(linux.fchmod(@intCast(fd), if (restart) 0o100 else 0)) == .SUCCESS;
}

/// runit's stage 2: PID 1's child named runsvdir, read from /proc.
fn stageTwo() ?linux.pid_t {
    const dir = linux.open("/proc", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(dir) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(dir));
    var ents: [4096]u8 align(8) = undefined;
    while (true) {
        const n = linux.getdents64(@intCast(dir), &ents, ents.len);
        if (linux.errno(n) != .SUCCESS or n == 0) return null;
        var off: usize = 0;
        while (off < n) {
            const ent: *align(1) const linux.dirent64 = @ptrCast(&ents[off]);
            off += ent.reclen;
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.name)), 0);
            const pid = std.fmt.parseInt(linux.pid_t, name, 10) catch continue;
            var path: [32]u8 = undefined;
            const len = (std.mem.print(
                path[0 .. path.len - 1],
                "/proc/{d}/stat",
                .{pid},
            ) catch continue).len;
            path[len] = 0;
            const p = path[0..len :0];
            var buf: [512]u8 = undefined;
            if (isStageTwo(readSmall(p, &buf) orelse continue)) return pid;
        }
    }
}

/// Whether a /proc/PID/stat line is runsvdir's, child of PID 1: "PID
/// (COMM) STATE PPID ...", the name in parentheses, which may itself hold
/// spaces or parentheses, so read up to the last ")".
fn isStageTwo(stat: []const u8) bool {
    const open = std.mem.findScalar(u8, stat, '(') orelse return false;
    const close = std.mem.findScalarLast(u8, stat, ')') orelse return false;
    if (close < open or !std.mem.eql(u8, stat[open + 1 .. close], "runsvdir")) return false;
    var rest = std.mem.tokenizeScalar(u8, stat[close + 1 ..], ' ');
    _ = rest.next() orelse return false; // state
    return std.mem.eql(u8, rest.next() orelse return false, "1");
}

fn readSmall(path: [:0]const u8, buf: []u8) ?[]const u8 {
    const fd = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(fd));
    const n = linux.read(@intCast(fd), buf.ptr, buf.len);
    if (linux.errno(n) != .SUCCESS) return null;
    return buf[0..n];
}

test levelFor {
    try std.testing.expectEqualStrings("0", levelFor("poweroff").?);
    try std.testing.expectEqualStrings("6", levelFor("reboot").?);
    try std.testing.expectEqual(null, levelFor("halt"));
    try std.testing.expectEqual(null, levelFor("reboot2"));
}

test isStageTwo {
    try std.testing.expect(isStageTwo("543 (runsvdir) S 1 543 543 0 -1 4194560 160\n"));
    try std.testing.expect(!isStageTwo("544 (runsvdir) S 543 543 543 0 -1\n"));
    try std.testing.expect(!isStageTwo("545 (runsv) S 543 543 543 0 -1\n"));
    try std.testing.expect(!isStageTwo("546 (x) runsvdir) S 1 1 1\n"));
    try std.testing.expect(!isStageTwo("547 (runsvdir) S\n"));
    try std.testing.expect(!isStageTwo("garbage"));
}
