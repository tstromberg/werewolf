//! powerbtn: turn the hypervisor's power-button press into a clean poweroff.
//!
//! The press reaches the machine as an input event on /dev/input/event*:
//! struct input_event, 24 bytes on a 64-bit kernel, a time then type, code
//! and value. EV_KEY (1), KEY_POWER (116), pressed (1) asks runit, PID 1,
//! to stop the machine and power it off, as poweroff does. Every device is
//! watched at once with poll(2), each through one open descriptor, so the
//! kernel's queue holds events between reads.
//!
//! The ACPI button (x86, and arm64 servers that boot with ACPI) arrives this
//! way. arm64 machines described by a device tree (QEMU's virt, Apple's VZ)
//! wire it to gpio-keys, which Alpine's linux-virt does not build: there
//! nothing ever arrives, and with no devices the service parks itself.
//!
//! runsv runs it as /etc/sv/powerbtn/run, with no arguments and no shell.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;

const event_size = 24;
const max_devices = 32;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var fds: [max_devices]linux.pollfd = undefined;
    var names: [max_devices][]const u8 = undefined;
    var n: usize = 0;

    var d = Io.Dir.cwd().openDir(
        io,
        "/dev/input",
        .{ .iterate = true },
    ) catch park(io, "no input devices, staying down");
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
    if (n == 0) park(io, "no input devices, staying down");

    var ev: [event_size]u8 = undefined;
    while (true) {
        const ready = linux.poll(&fds, @intCast(n), -1);
        if (linux.errno(ready) == .INTR) continue;
        if (linux.errno(ready) != .SUCCESS) return error.PollFailed;
        for (fds[0..n], names[0..n]) |*p, name| {
            if (p.revents & linux.POLL.IN == 0) continue;
            p.revents = 0;
            const got = linux.read(p.fd, &ev, ev.len);
            if (linux.errno(got) != .SUCCESS or got != ev.len) continue;
            if (!isPowerPress(ev)) continue;
            say(io, "power button on {s}, powering off", .{name});
            const err = std.process.replace(io, .{ .argv = &.{ "/usr/bin/runit-init", "0" } });
            say(io, "runit-init: {s}", .{@errorName(err)});
            std.process.exit(1);
        }
    }
}

/// Whether an input_event is the power key going down: type EV_KEY (1),
/// code KEY_POWER (116), value 1, after the 16 bytes of its time.
fn isPowerPress(ev: [event_size]u8) bool {
    const kind = std.mem.readInt(u16, ev[16..18], .little);
    const code = std.mem.readInt(u16, ev[18..20], .little);
    const value = std.mem.readInt(i32, ev[20..24], .little);
    return kind == 1 and code == 116 and value == 1;
}

/// Down, as a service with nothing to do: runsv will not restart it.
fn park(io: Io, why: []const u8) noreturn {
    say(io, "{s}", .{why});
    const err = std.process.replace(io, .{ .argv = &.{ "/usr/bin/sv", "down", "." } });
    say(io, "sv down: {s}", .{@errorName(err)});
    std.process.exit(1);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const line = std.mem.print(&buf, "powerbtn: " ++ fmt ++ "\n", args) catch return;
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
