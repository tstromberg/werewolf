//! power-button turns the hypervisor's power-button press into a clean
//! poweroff. It watches input devices and, on device-tree arm64, the GPIO
//! power line. See README.md.

const std = @import("std");
const sandbox = @import("sandbox");
const Io = std.Io;
const linux = std.os.linux;

const event_size = 24;
const max_devices = 32;
const key_power = 116;
const tree = "/sys/firmware/devicetree/base";

// linux/gpio.h, version 2 of the character device's interface.
const line_flag_active_low = 1 << 1;
const line_flag_input = 1 << 2;
const line_flag_edge_rising = 1 << 4;
const line_event_rising = 1;

const LineAttribute = extern struct { id: u32, padding: u32, value: u64 };
const LineConfigAttribute = extern struct { attr: LineAttribute, mask: u64 };
const LineConfig = extern struct {
    flags: u64,
    num_attrs: u32,
    padding: [5]u32,
    attrs: [10]LineConfigAttribute,
};
const LineRequest = extern struct {
    offsets: [64]u32,
    consumer: [32]u8,
    config: LineConfig,
    num_lines: u32,
    event_buffer_size: u32,
    padding: [5]u32,
    fd: i32,
};
const LineEvent = extern struct {
    timestamp_ns: u64,
    id: u32,
    offset: u32,
    seqno: u32,
    line_seqno: u32,
    padding: [6]u32,
};
comptime {
    std.debug.assert(@sizeOf(LineRequest) == 592);
    std.debug.assert(@sizeOf(LineEvent) == 48);
}
const get_line_ioctl = linux.IOCTL.IOWR(0xB4, 0x07, LineRequest);

pub fn main(init: std.process.Init) !void {
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
    // On device-tree arm64 the key is a GPIO line. It goes last, at index gpio.
    var gpio: ?usize = null;
    if (n < max_devices) if (gpioPowerLine(io, init.arena.allocator())) |fd| {
        fds[n] = .{ .fd = fd, .events = linux.POLL.IN, .revents = 0 };
        names[n] = "the device tree's GPIO power key";
        gpio = n;
        n += 1;
    };
    if (n == 0) park(io, "no input devices or GPIO power key, staying down");
    const inputs = n - @intFromBool(gpio != null);
    say(io, "watching {d} input device{s}{s}", .{
        inputs,
        if (inputs == 1) "" else "s",
        if (gpio != null) " and the GPIO power key" else "",
    });
    // Every descriptor is open. poweroff needs only root's uid, so keep no
    // capability while waiting.
    try sandbox.keepOnly(0);

    var ev: [event_size]u8 = undefined;
    var open = n;
    while (true) {
        const ready = linux.poll(&fds, @intCast(n), -1);
        if (linux.errno(ready) == .INTR) continue;
        if (linux.errno(ready) != .SUCCESS) return error.PollFailed;
        for (fds[0..n], names[0..n], 0..) |*p, name, i| {
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
            if (gpio == i) {
                var le: LineEvent = undefined;
                const got = linux.read(p.fd, std.mem.asBytes(&le), @sizeOf(LineEvent));
                if (linux.errno(got) != .SUCCESS or got != @sizeOf(LineEvent)) continue;
                if (le.id != line_event_rising) continue;
            } else {
                const got = linux.read(p.fd, &ev, ev.len);
                if (linux.errno(got) != .SUCCESS or got != ev.len) continue;
                if (!isPowerPress(ev)) continue;
            }
            say(io, "power button on {s}, powering off", .{name});
            const err = std.process.replace(io, .{ .argv = &.{"/usr/bin/poweroff"} });
            say(io, "poweroff: {s}", .{@errorName(err)});
            std.process.exit(1);
        }
    }
}

/// gpioPowerLine requests the GPIO line that the device tree's gpio-keys wires
/// to KEY_POWER, for rising edges (a press; active-low lines are inverted).
/// It returns the line's event descriptor, or null after logging why.
fn gpioPowerLine(io: Io, gpa: std.mem.Allocator) ?i32 {
    const key = powerKey(io, gpa) orelse return null;
    const chip = chipFor(io, gpa, key.phandle) orelse {
        say(
            io,
            "the GPIO power key's controller (phandle {d}) is not a gpiochip; is gpio-pl061 " ++
                "loaded?",
            .{key.phandle},
        );
        return null;
    };
    const path = gpa.printSentinel("/dev/{s}", .{chip}, 0) catch return null;
    const crc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(crc) != .SUCCESS) {
        say(io, "{s}: {t}", .{ path, linux.errno(crc) });
        return null;
    }
    defer _ = linux.close(@intCast(crc));
    var req = std.mem.zeroes(LineRequest);
    req.offsets[0] = key.line;
    @memcpy(req.consumer[0.."power-button".len], "power-button");
    req.config.flags = line_flag_input | line_flag_edge_rising |
        @as(u64, if (key.active_low) line_flag_active_low else 0);
    req.num_lines = 1;
    const rc = linux.ioctl(@intCast(crc), get_line_ioctl, @intFromPtr(&req));
    if (linux.errno(rc) != .SUCCESS) {
        say(io, "{s} line {d}: {t}", .{ path, key.line, linux.errno(rc) });
        return null;
    }
    say(io, "the power key is {s} line {d}", .{ path, key.line });
    return req.fd;
}

const PowerKey = struct { phandle: u32, line: u32, active_low: bool };

/// powerKey finds the gpio-keys entry for KEY_POWER and parses its gpios
/// property: three big-endian u32 cells, the controller's phandle, the line,
/// and flags whose bit 0 is GPIO_ACTIVE_LOW.
fn powerKey(io: Io, gpa: std.mem.Allocator) ?PowerKey {
    var keys = Io.Dir.cwd().openDir(
        io,
        tree ++ "/gpio-keys",
        .{ .iterate = true },
    ) catch return null;
    defer keys.close(io);
    var it = keys.iterate();
    while (it.next(io) catch return null) |e| {
        if (e.kind != .directory) continue;
        var buf: [16]u8 = undefined;
        const code = readIn(io, keys, gpa, e.name, "linux,code", &buf) orelse continue;
        if (code.len != 4 or std.mem.readInt(u32, code[0..4], .big) != key_power) continue;
        const gpios = readIn(io, keys, gpa, e.name, "gpios", &buf) orelse continue;
        return parseGpios(gpios);
    }
    return null;
}

fn parseGpios(cells: []const u8) ?PowerKey {
    if (cells.len != 12) return null;
    return .{
        .phandle = std.mem.readInt(u32, cells[0..4], .big),
        .line = std.mem.readInt(u32, cells[4..8], .big),
        .active_low = std.mem.readInt(u32, cells[8..12], .big) & 1 != 0,
    };
}

/// chipFor returns the name of the gpiochip in /sys/bus/gpio/devices whose
/// of_node/phandle is phandle.
fn chipFor(io: Io, gpa: std.mem.Allocator, phandle: u32) ?[]const u8 {
    var chips = Io.Dir.cwd().openDir(
        io,
        "/sys/bus/gpio/devices",
        .{ .iterate = true },
    ) catch return null;
    defer chips.close(io);
    var it = chips.iterate();
    while (it.next(io) catch return null) |e| {
        if (!std.mem.startsWith(u8, e.name, "gpiochip")) continue;
        var buf: [16]u8 = undefined;
        const ph = readIn(io, chips, gpa, e.name, "of_node/phandle", &buf) orelse continue;
        if (ph.len == 4 and std.mem.readInt(u32, ph[0..4], .big) == phandle)
            return gpa.dupe(u8, e.name) catch null;
    }
    return null;
}

/// readIn reads dir/name/file into buf.
fn readIn(
    io: Io,
    dir: Io.Dir,
    gpa: std.mem.Allocator,
    name: []const u8,
    file: []const u8,
    buf: []u8,
) ?[]const u8 {
    const path = gpa.print("{s}/{s}", .{ name, file }) catch return null;
    var f = dir.openFile(io, path, .{}) catch return null;
    defer f.close(io);
    const n = f.readStreaming(io, &.{buf}) catch return null;
    return buf[0..n];
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

test parseGpios {
    // Apple's VZ: the PL061 (phandle 3), line 6, active high.
    const vz = [_]u8{ 0, 0, 0, 3, 0, 0, 0, 6, 0, 0, 0, 0 };
    try std.testing.expectEqual(
        PowerKey{ .phandle = 3, .line = 6, .active_low = false },
        parseGpios(&vz).?,
    );
    const low = [_]u8{ 0, 0, 0x80, 1, 0, 0, 0, 3, 0, 0, 0, 1 };
    try std.testing.expect(parseGpios(&low).?.active_low);
    try std.testing.expectEqual(null, parseGpios(vz[0..8]));
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
