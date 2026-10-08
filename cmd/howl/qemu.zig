//! QEMU: a werewolf machine kept here, in the background (make run with
//! RUN_DIR), where no likelier engine is (Lima, bhyve, Firecracker), or
//! as --on qemu asks. Its directory, build/machines/NAME, holds its
//! data disk, its config tar, its console on console.sock and in
//! console.log, QEMU's monitor on monitor.sock, its pid in qemu.pid, and
//! the ports this host reaches it by in machine. It has user-mode
//! networking, so it needs no root: ssh and the form's last port are
//! forwarded from this host's loopback.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const net = Io.net;
const posix = std.posix;
const howl = @import("howl.zig");

/// QEMU's pid, while the machine runs.
pub fn running(io: Io, gpa: Allocator, d: []const u8) ?posix.pid_t {
    const path = gpa.print("{s}/qemu.pid", .{d}) catch return null;
    const text = Dir.cwd().readFileAlloc(io, path, gpa, .limited(64)) catch return null;
    const pid = std.fmt.parseInt(posix.pid_t, std.mem.trim(u8, text, " \n"), 10) catch return null;
    posix.kill(pid, @fromBackingInt(@intCast(0))) catch return null;
    return pid;
}

/// Stop it, as Ctrl-a x does: QEMU's monitor told to quit, or, if that
/// does not answer, a signal. Whether one was running. A monitor that
/// is not there, or that nothing listens on, means no QEMU of this
/// machine's: its pid is a stale one, maybe another process's by now,
/// and is sent nothing.
pub fn stop(io: Io, gpa: Allocator, d: []const u8) !bool {
    const pid = running(io, gpa, d) orelse return false;
    const ua = try net.UnixAddress.init(try gpa.print("{s}/monitor.sock", .{d}));
    if (ua.connect(io)) |s| {
        defer s.close(io);
        const f: Io.File = .{ .handle = s.socket.handle, .flags = .{ .nonblocking = false } };
        f.writeStreamingAll(io, "quit\n") catch {};
    } else |err| switch (err) {
        error.ConnectionRefused, error.FileNotFound => {
            howl.say(io, "{s}: no QEMU at its monitor; pid {d} is stale, left alone", .{ d, pid });
            Dir.cwd().deleteFile(io, try gpa.print("{s}/qemu.pid", .{d})) catch {};
            return false;
        },
        else => howl.say(io, "{s}: its monitor: {s}", .{ d, @errorName(err) }),
    }
    for (0..50) |_| {
        posix.kill(pid, @fromBackingInt(@intCast(0))) catch return true;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    howl.say(io, "{s}: QEMU did not quit when told; pid {d} sent TERM, then KILL", .{ d, pid });
    posix.kill(pid, .TERM) catch return true;
    try io.sleep(.fromSeconds(1), .awake);
    posix.kill(pid, .KILL) catch {};
    return true;
}

/// A port on this host's loopback that nothing listens on: want, or, if
/// something does, one the kernel picks.
pub fn freePort(io: Io, want: u16) !u16 {
    var a: net.IpAddress = .{ .ip4 = .loopback(want) };
    if (a.listen(io, .{})) |srv| {
        var s = srv;
        s.deinit(io);
        return want;
    } else |_| {}
    a = .{ .ip4 = .loopback(0) };
    var s = try a.listen(io, .{});
    defer s.deinit(io);
    return s.socket.address.getPort();
}

/// The value of key in the machine's record, its KEY VALUE lines.
pub fn record(io: Io, gpa: Allocator, d: []const u8, key: []const u8) ?[]const u8 {
    const path = gpa.print("{s}/machine", .{d}) catch return null;
    const text = Dir.cwd().readFileAlloc(io, path, gpa, .limited(1024)) catch return null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| {
        var words = std.mem.tokenizeScalar(u8, l, ' ');
        if (std.mem.eql(u8, words.next() orelse continue, key)) return words.next();
    }
    return null;
}

/// path, a sparse disk of size bytes, unless it is there already: a
/// machine's /data, which outlives its restarts.
pub fn disk(io: Io, path: []const u8, size: u64) !void {
    // Root's alone on the host: it is the machine's /data, its secrets
    // and its database, in the clear unless a data key was given.
    const f = Dir.cwd().createFile(io, path, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    }) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        else => return err,
    };
    defer f.close(io);
    try f.setLength(io, size);
}

/// The machine's console, here: what it has said, then, on a terminal,
/// the console itself, keys and all, until Ctrl-] leaves it running, or it
/// stops.
pub fn attach(io: Io, gpa: Allocator, d: []const u8) !void {
    const out = Io.File.stdout();
    const log = try gpa.print("{s}/console.log", .{d});
    const text = Dir.cwd().readFileAlloc(io, log, gpa, .limited(64 << 20)) catch "";
    // The last 64 KiB: the boot, and what followed.
    try out.writeStreamingAll(io, text[text.len -| (64 << 10)..]);
    const in = Io.File.stdin();
    if (!(in.isTty(io) catch false)) return;

    const ua = try net.UnixAddress.init(try gpa.print("{s}/console.sock", .{d}));
    const s = try ua.connect(io);
    defer s.close(io);
    try Io.File.stderr().writeStreamingAll(
        io,
        "\r\n[the console; Ctrl-] leaves it, the machine running]\r\n",
    );

    const was = try posix.tcgetattr(in.handle);
    var raw = was;
    raw.lflag.ECHO = false;
    raw.lflag.ICANON = false;
    raw.lflag.ISIG = false;
    raw.lflag.IEXTEN = false;
    raw.iflag.IXON = false;
    raw.iflag.ICRNL = false;
    raw.iflag.BRKINT = false;
    raw.iflag.ISTRIP = false;
    raw.oflag.OPOST = false;
    raw.cc[@backingInt(posix.V.MIN)] = 1;
    raw.cc[@backingInt(posix.V.TIME)] = 0;
    try posix.tcsetattr(in.handle, .FLUSH, raw);
    defer posix.tcsetattr(in.handle, .FLUSH, was) catch {};

    var fds = [2]posix.pollfd{
        .{ .fd = in.handle, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = s.socket.handle, .events = posix.POLL.IN, .revents = 0 },
    };
    const sock: Io.File = .{ .handle = s.socket.handle, .flags = .{ .nonblocking = false } };
    var buf: [4096]u8 = undefined;
    while (true) {
        _ = try posix.poll(&fds, -1);
        if (fds[0].revents != 0) {
            const n = try posix.read(in.handle, &buf);
            if (n == 0) break;
            if (std.mem.findScalar(u8, buf[0..n], 0x1d)) |at| {
                if (at > 0) try sock.writeStreamingAll(io, buf[0..at]);
                break;
            }
            try sock.writeStreamingAll(io, buf[0..n]);
        }
        if (fds[1].revents != 0) {
            const n = posix.read(s.socket.handle, &buf) catch 0;
            if (n == 0) {
                try Io.File.stderr().writeStreamingAll(io, "\r\n[the machine stopped]\r\n");
                return;
            }
            try out.writeStreamingAll(io, buf[0..n]);
        }
    }
    try Io.File.stderr().writeStreamingAll(
        io,
        "\r\n[left the console; the machine runs on]\r\n",
    );
}

test freePort {
    const io = std.testing.io;
    var a: net.IpAddress = .{ .ip4 = .loopback(0) };
    var held = try a.listen(io, .{});
    defer held.deinit(io);
    const taken = held.socket.address.getPort();
    const got = try freePort(io, taken);
    try std.testing.expect(got != taken and got != 0);
}
