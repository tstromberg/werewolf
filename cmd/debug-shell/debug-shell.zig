//! debug-shell gives a passwordless root shell on the serial console, but
//! only on a DEV=1 build booted with werewolf.debug=1; otherwise it parks.
//! runsv also runs it as control/t to stop the shell. See README.md.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;
const cmdline = @import("cmdline");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    // As control/t: an interactive ash ignores TERM, so send it HUP. Exit 0
    // tells runsv the signal was sent.
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

    var buf: [4096]u8 = undefined;
    const fd = linux.open("/proc/cmdline", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    const n = if (linux.errno(fd) == .SUCCESS)
        linux.read(@intCast(fd), &buf, buf.len)
    else
        0;
    const line = if (linux.errno(n) == .SUCCESS) buf[0..n] else "";
    // Parse the line as stage0 did (lib/cmdline.zig); a refused line gives
    // no shell. The command line alone is no gate, since root or anyone at
    // a bitten machine's GRUB menu can set it, so the image must be DEV=1.
    var refused: cmdline.Failure = .{};
    const cmd = cmdline.parse(line, &refused) orelse park(io, null);
    if (!cmd.debug) park(io, null);
    if (linux.errno(linux.access("/usr/share/werewolf/dev", linux.F_OK)) != .SUCCESS)
        park(io, "werewolf.debug=1 ignored: only a DEV=1 build gives a console shell");
    if (!executable("/usr/bin/getty") or
        !executable("/bin/ash")) park(io, "werewolf.debug=1, but this form has no shell to give");

    const tty = consoleName(line);
    say(io, "werewolf.debug=1: a root shell, without a password, on {s}", .{tty});

    const err = std.process.replace(
        io,
        .{ .argv = &.{
            "/usr/bin/getty",
            "-n",
            "-l",
            "/bin/ash",
            "-L",
            "115200",
            tty,
            "vt100",
        } },
    );
    say(io, "getty: {s}", .{@errorName(err)});
    std.process.exit(1);
}

/// consoleName returns the device the last console= names, cut to its
/// leading letters and digits ("ttyS0,115200" is ttyS0), or "console".
fn consoleName(line: []const u8) []const u8 {
    var name: []const u8 = "console";
    var words = std.mem.tokenizeAny(u8, line, " \n");
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

/// park logs why, if given, and runs `sv down .` so runsv does not restart
/// the service.
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
