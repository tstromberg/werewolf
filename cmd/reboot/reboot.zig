//! reboot and poweroff stop the machine cleanly through runit's stage 3, then
//! restart it or turn it off. One program serves both names. See README.md.

const std = @import("std");
const linux = std.os.linux;

const reboot_flag = "/etc/runit/reboot";

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const level = (if (args.len == 1) levelFor(std.fs.path.basename(args[0])) else null) orelse {
        std.debug.print("usage: reboot | poweroff\n", .{});
        std.process.exit(2);
    };
    // Ending stage 2 ourselves skips the second runit-init would wait for it.
    // If that fails, runit-init does the whole job.
    if (setFlag(std.mem.eql(u8, level, "6"))) if (stageTwo()) |pid| {
        if (linux.errno(linux.kill(pid, linux.SIG.TERM)) == .SUCCESS) std.process.exit(0);
    };
    const err = std.process.replace(init.io, .{ .argv = &.{ "/usr/bin/runit-init", level } });
    std.debug.print("{s}: runit-init: {s}\n", .{ args[0], @errorName(err) });
    std.process.exit(1);
}

/// levelFor returns runit-init's level for the program name: 6 for reboot, 0
/// for poweroff. Any other name returns null, so a stray link such as halt
/// does nothing.
fn levelFor(name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "reboot")) return "6";
    if (std.mem.eql(u8, name, "poweroff")) return "0";
    return null;
}

/// setFlag creates runit's reboot flag if needed and sets its mode. runit reads
/// it after stage 3: owner execute means restart, mode 0 means power off.
fn setFlag(restart: bool) bool {
    const fd = linux.open(reboot_flag, .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    return linux.errno(linux.fchmod(@intCast(fd), if (restart) 0o100 else 0)) == .SUCCESS;
}

/// stageTwo returns the pid of runit's stage 2, the runsvdir that is PID 1's
/// child, or null if /proc has none.
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
            const p = std.mem.printSentinel(&path, "/proc/{d}/stat", .{pid}, 0) catch continue;
            var buf: [512]u8 = undefined;
            if (isStageTwo(readSmall(p, &buf) orelse continue)) return pid;
        }
    }
}

/// isStageTwo reports whether a /proc/PID/stat line ("PID (COMM) STATE PPID
/// ...") is runsvdir with parent 1. COMM may hold spaces or parentheses, so
/// the name ends at the last ")".
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
