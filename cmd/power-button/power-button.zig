//! power-button turns the hypervisor's power-button press into a clean
//! poweroff. It watches the input devices. See README.md.

const std = @import("std");
const sandbox = @import("sandbox");
const Io = std.Io;
const linux = std.os.linux;

const event_size = 24;
const max_devices = 32;
const key_power = 116;

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
    // Every descriptor is open. poweroff needs only root's uid, so keep no
    // capability while waiting.
    try sandbox.keepOnly(0);

    var ev: [event_size]u8 = undefined;
    var open = n;
    while (true) {
        const ready = linux.poll(&fds, @intCast(n), -1);
        if (linux.errno(ready) == .INTR) continue;
        if (linux.errno(ready) != .SUCCESS) return error.PollFailed;
        for (fds[0..n], names[0..n]) |*p, name| {
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
                if (open == 0) park(io, "every device is gone, staying down");
                continue;
            }
            if (!readable) continue;
            const got = linux.read(p.fd, &ev, ev.len);
            if (linux.errno(got) != .SUCCESS or got != ev.len) continue;
            if (!isPowerPress(ev)) continue;
            say(io, "power button on {s}, powering off", .{name});
            const err = std.process.replace(io, .{ .argv = &.{"/usr/bin/poweroff"} });
            say(io, "poweroff: {s}", .{@errorName(err)});
            std.process.exit(1);
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
