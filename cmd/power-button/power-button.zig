//! power-button turns the hypervisor's power-button press into a clean
//! poweroff. It watches the input devices. See README.md.

const std = @import("std");
const sandbox = @import("sandbox");
const Io = std.Io;
const linux = std.os.linux;

const event_size = 24;
const max_devices = 32;
const key_power = 116;
const power_id = 71;

pub fn main(init: std.process.Init) !void {
    _ = linux.close_range(3, std.math.maxInt(linux.fd_t), .{ .UNSHARE = false, .CLOEXEC = false });
    const io = init.io;
    var fds: [max_devices]linux.pollfd = undefined;
    var names: [max_devices][]const u8 = undefined;
    var n: usize = 0;

    if (Io.Dir.cwd().openDir(io, "/dev/input", .{ .iterate = true })) |opened| {
        var d = opened;
        defer d.close(io);
        var it = d.iterate();
        while (try it.next(io)) |e| {
            if (!std.mem.startsWith(u8, e.name, "event") or n == max_devices) continue;
            const path = try init.arena.allocator().printSentinel(
                "/dev/input/{s}",
                .{e.name},
                0,
            );
            const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
            if (linux.errno(rc) != .SUCCESS) continue;
            fds[n] = .{ .fd = @intCast(rc), .events = linux.POLL.IN, .revents = 0 };
            names[n] = path;
            n += 1;
        }
    } else |_| {}
    if (n == 0) park(io, "no input devices, staying down");
    say(io, "watching {d} input device{s}", .{ n, if (n == 1) "" else "s" });
    const control: i32 = @intCast(try sandbox.sys(linux.open(
        "supervise/control",
        .{ .ACCMODE = .WRONLY, .NONBLOCK = true, .CLOEXEC = true },
        0,
    ), "open service control"));
    const reboot = try flag("/run/runit/reboot");
    const stopit = try flag("/run/runit/stopit");
    var pipe: [2]i32 = undefined;
    _ = try sandbox.sys(linux.pipe2(&pipe, .{ .CLOEXEC = true }), "pipe");
    const parent = linux.getpid();
    const pid = try sandbox.sys(linux.fork(), "fork");
    if (pid == 0) {
        _ = linux.close(pipe[0]);
        _ = linux.close(control);
        _ = linux.close(reboot);
        _ = linux.close(stopit);
        sandbox.tieTo(parent);
        try sandbox.dropTo(power_id, "/var/empty");
        var f: sandbox.Filter = .{};
        // Only input descriptors remain readable; the worker cannot open more.
        f.allow("read");
        for ([_]i32{ 1, 2, pipe[1] }) |fd| f.allowArg("write", 0, @intCast(fd));
        for ([_]i32{ 1, 2 }) |fd| f.allowArg("writev", 0, @intCast(fd));
        inline for (.{ "poll", "ppoll", "close", "restart_syscall", "exit", "exit_group" }) |call|
            f.allow(call);
        try f.install();
        watch(io, fds[0..n], names[0..n], pipe[1]) catch linux.exit_group(1);
        linux.exit_group(0);
    }
    _ = linux.close(pipe[1]);
    for (fds[0..n]) |fd| _ = linux.close(fd.fd);
    try sandbox.keepOnly(0);
    var f: sandbox.Filter = .{};
    f.allowArg("read", 0, @intCast(pipe[0]));
    for ([_]i32{ 1, 2, control }) |fd| f.allowArg("write", 0, @intCast(fd));
    for ([_]i32{ 1, 2 }) |fd| f.allowArg("writev", 0, @intCast(fd));
    f.allowTwo("fchmod", 0, @intCast(reboot), 1, 0);
    f.allowTwo("fchmod", 0, @intCast(stopit), 1, 0o100);
    f.allowTwo("kill", 0, 1, 1, @backingInt(linux.SIG.CONT));
    inline for (.{ "restart_syscall", "exit", "exit_group" }) |call| f.allow(call);
    try f.install();
    var request: [2]u8 = undefined;
    while (true) {
        const got = linux.read(pipe[0], &request, request.len);
        if (linux.errno(got) == .INTR) continue;
        if (linux.errno(got) != .SUCCESS or got != 1) linux.exit_group(1);
        switch (request[0]) {
            'P' => {
                // runit-init's protocol: select poweroff, request stage 3,
                // then wake PID 1. No executable or arbitrary signal is allowed.
                _ = sandbox.sys(linux.fchmod(reboot, 0), "poweroff flag") catch linux.exit_group(1);
                _ = sandbox.sys(linux.fchmod(stopit, 0o100), "stop flag") catch linux.exit_group(1);
                _ = sandbox.sys(
                    linux.kill(1, linux.SIG.CONT),
                    "wake runit",
                ) catch linux.exit_group(1);
            },
            'D' => {
                if (linux.write(control, "d", 1) != 1) linux.exit_group(1);
            },
            else => linux.exit_group(1),
        }
        linux.exit_group(0);
    }
}

fn flag(path: [:0]const u8) !i32 {
    const fd: i32 = @intCast(try sandbox.sys(linux.open(
        path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    ), "open runit flag"));
    var st: linux.Statx = undefined;
    _ = try sandbox.sys(
        linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true }, &st),
        "stat runit flag",
    );
    if (st.uid != 0 or st.mode & linux.S.IFMT != linux.S.IFREG or st.mode & 0o022 != 0)
        return error.UnsafeFlag;
    return fd;
}

fn watch(io: Io, fds: []linux.pollfd, names: []const []const u8, out: i32) !void {
    var watched: [max_devices + 1]linux.pollfd = undefined;
    @memcpy(watched[0..fds.len], fds);
    // POLLERR on the write end means the monitor's read end has closed.
    watched[fds.len] = .{ .fd = out, .events = 0, .revents = 0 };
    var ev: [event_size]u8 = undefined;
    var open = fds.len;
    while (true) {
        const ready = linux.poll(&watched, @intCast(fds.len + 1), -1);
        if (linux.errno(ready) == .INTR) continue;
        if (linux.errno(ready) != .SUCCESS) return error.PollFailed;
        if (watched[fds.len].revents != 0) return error.ParentGone;
        for (watched[0..fds.len], names) |*p, name| {
            const gone = p.revents & (linux.POLL.HUP | linux.POLL.ERR | linux.POLL.NVAL) != 0;
            const readable = p.revents & linux.POLL.IN != 0;
            p.revents = 0;
            // Close a vanished device once it is drained, or poll returns
            // at once for it forever. poll skips a negative descriptor.
            if (gone and !readable) {
                say(io, "{s} is gone", .{name});
                _ = linux.close(p.fd);
                p.fd = -1;
                open -= 1;
                if (open == 0) {
                    if (linux.write(out, "D", 1) != 1) return error.WriteFailed;
                    return;
                }
                continue;
            }
            if (!readable) continue;
            const got = linux.read(p.fd, &ev, ev.len);
            if (linux.errno(got) != .SUCCESS or got != ev.len) continue;
            if (!isPowerPress(ev)) continue;
            say(io, "power button on {s}, powering off", .{name});
            if (linux.write(out, "P", 1) != 1) return error.WriteFailed;
            return;
        }
    }
}

/// isPowerPress reports whether a 64-bit struct input_event is the power key
/// going down: after a 16-byte time, type EV_KEY (1), code KEY_POWER, value 1.
fn isPowerPress(ev: [event_size]u8) bool {
    const kind = std.mem.readInt(u16, ev[16..18], .little);
    const code = std.mem.readInt(u16, ev[18..20], .little);
    const value = std.mem.readInt(i32, ev[20..24], .little);
    return kind == 1 and code == key_power and value == 1;
}

/// park logs why and marks the service down, so runsv does not restart a
/// service with nothing to watch.
fn park(io: Io, why: []const u8) noreturn {
    sandbox.keepOnly(0) catch {};
    say(io, "{s}", .{why});
    const err = std.process.replace(io, .{ .argv = &.{ "/usr/bin/sv", "down", "." } });
    say(io, "sv down: {s}", .{@errorName(err)});
    std.process.exit(1);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const line = std.mem.print(&buf, "power-button: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

test isPowerPress {
    var ev: [event_size]u8 = @splat(0);
    @memcpy(ev[16..24], &[_]u8{ 0x01, 0x00, 0x74, 0x00, 0x01, 0x00, 0x00, 0x00 });
    try std.testing.expect(isPowerPress(ev));
    ev[20] = 0; // released
    try std.testing.expect(!isPowerPress(ev));
    ev[20] = 1;
    ev[18] = 0x73; // another key
    try std.testing.expect(!isPowerPress(ev));
}
