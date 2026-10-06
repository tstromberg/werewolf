//! debug-shell: a root shell on the serial console, for debugging, when the
//! kernel command line has werewolf.debug=1 and the form has a shell to
//! give (busybox's getty and ash: the sshd, lima and prod-ssh forms, or any
//! form built with DEV=1). Otherwise it parks itself.
//!
//! runsv runs it as /etc/sv/debug-shell/run, and as /etc/sv/debug-shell/control/t
//! in place of sending TERM. The shell is an interactive ash, which ignores
//! TERM, so stage 3 would wait out its whole timeout; as t it sends the
//! shell HUP, which it honours, and exits 0, which tells runsv the signal
//! has been sent.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (std.mem.eql(u8, std.fs.path.basename(args[0]), "t")) {
        const text = Io.Dir.cwd().readFileAlloc(
            io,
            "supervise/pid",
            gpa,
            .limited(32),
        ) catch std.process.exit(1);
        const pid = std.fmt.parseInt(
            linux.pid_t,
            std.mem.trim(u8, text, " \n"),
            10,
        ) catch std.process.exit(1);
        if (pid <= 1 or
            linux.errno(linux.kill(pid, linux.SIG.HUP)) != .SUCCESS) std.process.exit(1);
        return;
    }

    var cmdline: [4096]u8 = undefined;
    const fd = linux.open("/proc/cmdline", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    const n = if (linux.errno(fd) == .SUCCESS)
        linux.read(@intCast(fd), &cmdline, cmdline.len)
    else
        0;
    const line = if (linux.errno(n) == .SUCCESS) cmdline[0..n] else "";
    var words = std.mem.tokenizeAny(u8, line, " \n");
    var debug = false;
    while (words.next()) |w| debug = debug or std.mem.eql(u8, w, "werewolf.debug=1");
    if (!debug) park(io, null);
    if (!executable("/usr/bin/getty") or
        !executable("/bin/ash")) park(io, "werewolf.debug=1, but this form has no shell to give");

    const err = std.process.replace(
        io,
        .{ .argv = &.{
            "/usr/bin/getty",
            "-n",
            "-l",
            "/bin/ash",
            "-L",
            "115200",
            consoleName(line),
            "vt100",
        } },
    );
    say(io, "getty: {s}", .{@errorName(err)});
    std.process.exit(1);
}

/// The kernel's console, as the last console= names it, without its
/// options ("ttyS0,115200" is ttyS0); "console" if there is none.
fn consoleName(cmdline: []const u8) []const u8 {
    var name: []const u8 = "console";
    var words = std.mem.tokenizeAny(u8, cmdline, " \n");
    while (words.next()) |w| {
        if (!std.mem.startsWith(u8, w, "console=")) continue;
        const v = w["console=".len..];
        var end: usize = 0;
        while (end < v.len and std.ascii.isAlphanumeric(v[end])) end += 1;
        if (end > 0) name = v[0..end];
    }
    return name;
}

fn executable(path: [:0]const u8) bool {
    return linux.errno(linux.access(path, linux.X_OK)) == .SUCCESS;
}

/// Down, as a service with nothing to do: runsv will not restart it.
fn park(io: Io, why: ?[]const u8) noreturn {
    if (why) |w| say(io, "{s}", .{w});
    const err = std.process.replace(io, .{ .argv = &.{ "/usr/bin/sv", "down", "." } });
    say(io, "sv down: {s}", .{@errorName(err)});
    std.process.exit(1);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const line = std.mem.print(&buf, "debug-shell: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

test consoleName {
    try std.testing.expectEqualStrings(
        "ttyAMA0",
        consoleName("console=ttyAMA0 panic=1 werewolf.debug=1\n"),
    );
    try std.testing.expectEqualStrings("ttyS0", consoleName("console=tty0 console=ttyS0,115200n8"));
    try std.testing.expectEqualStrings("hvc0", consoleName("console=hvc0"));
    try std.testing.expectEqualStrings("console", consoleName("quiet"));
    try std.testing.expectEqualStrings("console", consoleName("console=/dev/x"));
}
