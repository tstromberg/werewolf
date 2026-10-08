//! A machine here coming up, as create and run watch it: its console,
//! until init says it is up, with its own times for the kernel and
//! userland; its address, from Lima's leases, where it has one to wait
//! for; and, for a form that serves ssh, its sshd's banner, so "up" means
//! reachable.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const net = Io.net;
const posix = std.posix;
const lima = @import("lima.zig");
const progress = @import("progress.zig");

/// init's line that says a boot finished: "werewolf: up in 0.120s (the
/// kernel 0.051s, userland 0.069s)".
pub const up_line = "werewolf: up in ";

/// How a boot ended, as its console says: init's up line, a kernel panic,
/// or, when the time to wait ran out, neither.
pub const Outcome = enum { up, panic, late };

/// What console text says of a boot so far: up, a panic, or null for
/// neither yet.
pub fn outcome(text: []const u8) ?Outcome {
    if (std.mem.find(u8, text, up_line) != null) return .up;
    if (std.mem.find(u8, text, "Kernel panic") != null) return .panic;
    return null;
}

/// How long a machine may take to come up.
const wait_seconds = 180;
/// How long its sshd may take to answer, once it is up.
const ssh_seconds = 30;

/// How a machine started, as create tells it: when its console first
/// spoke, its own account of its boot (init's "up in" line), and when its
/// address came.
pub const Boot = struct {
    up: bool = false,
    address: ?[]const u8 = null,
    /// From the start to the console's first word: the VM powering on.
    power_ns: ?i96 = null,
    /// init's own times, as it says them: "0.051s".
    kernel: []const u8 = "",
    userland: []const u8 = "",
    /// From up to the lease.
    address_ns: ?i96 = null,
    /// The engine ended before the machine was up, as Firecracker's
    /// supervisor says on the console: no use waiting on.
    ended: bool = false,
};

/// Wait for a machine started now to boot, and, given its MAC, for its
/// address too: its console from seen, and the leases, as spin shows it.
pub fn watch(
    io: Io,
    gpa: Allocator,
    console_log: []const u8,
    seen: u64,
    m: ?[]const u8,
    before: u64,
    spin: *progress.Spinner,
) !Boot {
    var b: Boot = .{};
    const start = Io.Clock.awake.now(io);
    var up_at: ?Io.Timestamp = null;
    const buf = try gpa.alloc(u8, 1 << 20);
    const lbuf = try gpa.alloc(u8, if (m != null) 4 << 20 else 1);
    var said: []const u8 = "";
    for (0..wait_seconds * 20) |_| {
        if (!b.up) if (Dir.cwd().openFile(io, console_log, .{})) |f| {
            defer f.close(io);
            // A log shorter than before was started again.
            const len = f.length(io) catch 0;
            const from = if (seen <= len) seen else 0;
            if (len > from and
                b.power_ns == null) b.power_ns = start.untilNow(io, .awake).toNanoseconds();
            const n = f.readPositionalAll(io, buf, from) catch 0;
            said = try lastLine(gpa, buf[0..n]);
            if (upLine(buf[0..n])) |u| {
                b.up = true;
                b.kernel = try gpa.dupe(u8, u.kernel);
                b.userland = try gpa.dupe(u8, u.userland);
                up_at = Io.Clock.awake.now(io);
                if (m == null) return b;
            } else if (std.mem.find(u8, buf[0..n], "werewolf: firecracker exited ")) |at| {
                // Exit 0 is a reboot, which the supervisor runs again.
                const rest = buf[at + "werewolf: firecracker exited ".len .. n];
                if (!std.mem.startsWith(u8, rest, "0:")) {
                    b.ended = true;
                    return b;
                }
            }
        } else |_| {};
        if (m) |hw| if (Dir.cwd().readFile(io, lima.leases, lbuf)) |text| {
            if (lima.lease(text, hw)) |l| if (l.expiry > before) {
                b.address = try gpa.dupe(u8, l.ip);
                if (up_at) |u| b.address_ns = u.untilNow(io, .awake).toNanoseconds();
                return b;
            };
        } else |_| {};
        spin.tick(
            if (b.power_ns == null)
                "Starting the VM"
            else if (!b.up)
                "Booting"
            else
                "Waiting for its address",
            said,
        );
        try io.sleep(.fromMilliseconds(50), .awake);
    }
    return b;
}

/// init's times in its "werewolf: up in 0.120s (the kernel 0.051s,
/// userland 0.069s)" line, if text holds one.
fn upLine(text: []const u8) ?struct { kernel: []const u8, userland: []const u8 } {
    const at = std.mem.find(u8, text, up_line) orelse return null;
    const line = text[at..(std.mem.findScalarPos(u8, text, at, '\n') orelse text.len)];
    const k = "(the kernel ";
    const u = ", userland ";
    const ki = (std.mem.find(u8, line, k) orelse return null) + k.len;
    const ui = (std.mem.find(u8, line, u) orelse return null) + u.len;
    const ke = std.mem.findScalarPos(u8, line, ki, ',') orelse return null;
    const ue = std.mem.findScalarPos(u8, line, ui, ')') orelse return null;
    return .{ .kernel = line[ki..ke], .userland = line[ui..ue] };
}

/// The last line text holds with anything in it, as the spinner shows one.
fn lastLine(gpa: Allocator, text: []const u8) ![]const u8 {
    var it = std.mem.splitBackwardsScalar(u8, text, '\n');
    while (it.next()) |l| {
        const c = try progress.clean(gpa, l);
        if (c.len > 0) return c;
    }
    return "";
}

/// Wait for an sshd at host:port to say who it is, "SSH-", as spin shows
/// it: a TCP connection alone proves nothing through QEMU's forwarding,
/// which accepts before the machine listens. Whether it did.
pub fn awaitSsh(io: Io, host: []const u8, port: u16, spin: *progress.Spinner) bool {
    const addr = net.IpAddress.parse(host, port) catch return false;
    const started = Io.Clock.awake.now(io);
    while (started.untilNow(io, .awake).toSeconds() < ssh_seconds) {
        spin.tick("Starting its services", "");
        if (banner(io, addr)) return true;
        io.sleep(.fromMilliseconds(200), .awake) catch {};
    }
    return false;
}

fn banner(io: Io, addr: net.IpAddress) bool {
    // No timeout: Zig's std cannot yet connect with one, and a machine
    // here answers a closed port at once, with a reset.
    const s = addr.connect(io, .{ .mode = .stream }) catch return false;
    defer s.close(io);
    var fds = [1]posix.pollfd{.{ .fd = s.socket.handle, .events = posix.POLL.IN, .revents = 0 }};
    if ((posix.poll(&fds, 1000) catch 0) == 0) return false;
    var buf: [4]u8 = undefined;
    const n = posix.read(s.socket.handle, &buf) catch return false;
    return n == 4 and std.mem.eql(u8, &buf, "SSH-");
}

const testing = std.testing;

test upLine {
    const u = upLine(
        "x\nwerewolf: up in 0.120s (the kernel 0.051s, userland 0.069s), handing over to runit\n",
    ).?;
    try testing.expectEqualStrings("0.051s", u.kernel);
    try testing.expectEqualStrings("0.069s", u.userland);
    try testing.expectEqual(null, upLine("werewolf: booting\n"));
}

test outcome {
    try testing.expectEqual(null, outcome("stage0: ...\n"));
    try testing.expectEqual(.up, outcome("...\nwerewolf: up in 0.6s (the kernel 0.2s)\n"));
    try testing.expectEqual(.panic, outcome("Kernel panic - not syncing\n"));
}
