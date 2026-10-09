//! qemu manages a machine that QEMU runs in the background, the engine of
//! last resort. User-mode networking needs no root. See README.md.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const net = Io.net;
const posix = std.posix;
const howl = @import("howl.zig");

/// Machine is what a machine under QEMU boots, and where its state is.
pub const Machine = struct {
    arch: howl.Arch,
    /// dir holds the console, monitor, pid, data disk and config tar. It
    /// and the files below are absolute: QEMU daemonized runs in /.
    dir: []const u8,
    kernel: []const u8,
    initrd: []const u8,
    /// cmdline is the kernel arguments the image asks for.
    cmdline: []const u8,
    ssh_port: u16,
    /// web_port is this host's port that reaches the machine's guest_web.
    web_port: u16,
    guest_web: u16,
};

/// Accel is how QEMU runs a guest of this machine's arch.
pub const Accel = enum { hvf, kvm, nvmm, tcg };

/// accel returns QEMU's accelerator here: Hypervisor.framework on macOS,
/// KVM or NetBSD's NVMM where their device is, else emulation. FreeBSD
/// emulates, since QEMU has no bhyve (create --on bhyve has).
pub fn accel(io: Io) Accel {
    if (builtin.os.tag == .macos) return .hvf;
    Dir.cwd().access(io, "/dev/kvm", .{}) catch {
        Dir.cwd().access(io, "/dev/nvmm", .{}) catch return .tcg;
        return .nvmm;
    };
    return .kvm;
}

/// hasEl2 reports whether QEMU can give an aarch64 guest EL2 here: TCG
/// always, HVF on Apple M3 and later, KVM where the host nests. Given EL2,
/// the guest's kernel would start its built-in KVM, so werewolf boots with
/// kvm-arm.mode=none and posture proves it holds. QEMU, started paused and
/// told to quit, says in milliseconds.
pub fn hasEl2(io: Io, a: Accel) bool {
    var child = std.process.spawn(io, .{
        .argv = &.{
            "qemu-system-aarch64", "-M",   "virt,virtualization=on", "-accel",
            @tagName(a),           "-cpu", cpu(a),                   "-nodefaults",
            "-display",            "none", "-monitor",               "stdio",
            "-S",
        },
        .stdin = .pipe,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return false;
    child.stdin.?.writeStreamingAll(io, "quit\n") catch {};
    child.stdin.?.close(io);
    child.stdin = null;
    const term = child.wait(io) catch return false;
    return term == .exited and term.exited == 0;
}

fn cpu(a: Accel) []const u8 {
    return if (a == .tcg) "max" else "host";
}

/// argv returns the QEMU command that starts m in the background, booted
/// directly: the console on dir/console.sock and in console.log, the
/// monitor on monitor.sock, the pid in qemu.pid; user networking, with
/// ssh and the web port forwarded from loopback; data.img as vda, /data,
/// and the config tar read-only after it.
pub fn argv(gpa: Allocator, m: Machine, a: Accel, el2: bool) ![]const []const u8 {
    // QEMU reads a doubled comma as one in an option's value, so a path
    // cannot add options of its own.
    const d = try std.mem.replaceOwned(u8, gpa, m.dir, ",", ",,");
    const machine, const console = switch (m.arch) {
        .aarch64 => .{ "virt", "ttyAMA0" },
        .x86_64 => .{ "q35", "ttyS0" },
    };
    return gpa.dupe([]const u8, &.{
        try gpa.print("qemu-system-{t}", .{m.arch}),
        "-M",
        try gpa.print("{s}{s}", .{ machine, if (el2) ",virtualization=on" else "" }),
        "-accel",
        @tagName(a),
        "-cpu",
        cpu(a),
        "-display",
        "none",
        "-daemonize",
        "-pidfile",
        try gpa.print("{s}/qemu.pid", .{m.dir}),
        "-chardev",
        try gpa.print(
            "socket,id=con,path={s}/console.sock,server=on,wait=off,logfile={s}/console.log",
            .{ d, d },
        ),
        "-serial",
        "chardev:con",
        "-monitor",
        try gpa.print("unix:{s}/monitor.sock,server,nowait", .{d}),
        "-smp",
        "4",
        "-m",
        "2048",
        "-kernel",
        m.kernel,
        "-initrd",
        m.initrd,
        "-append",
        try gpa.print(
            "console={s} {s} werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 " ++
                "werewolf.dns=10.0.2.3 werewolf.data=vda werewolf.debug=1",
            .{ console, m.cmdline },
        ),
        "-netdev",
        try gpa.print(
            "user,id=n0,hostfwd=tcp:127.0.0.1:{d}-:22,hostfwd=tcp:127.0.0.1:{d}-:{d}",
            .{ m.ssh_port, m.web_port, m.guest_web },
        ),
        "-device",
        "virtio-net-pci,netdev=n0",
        "-device",
        "virtio-rng-pci",
        "-drive",
        try gpa.print("file={s}/data.img,format=raw,if=virtio", .{d}),
        "-drive",
        try gpa.print("file={s}/config.tar,format=raw,if=virtio,readonly=on", .{d}),
    });
}

/// running returns QEMU's pid from d/qemu.pid, or null if it is not running.
pub fn running(io: Io, gpa: Allocator, d: []const u8) ?posix.pid_t {
    const path = gpa.print("{s}/qemu.pid", .{d}) catch return null;
    const text = Dir.cwd().readFileAlloc(io, path, gpa, .limited(64)) catch return null;
    const pid = std.fmt.parseInt(posix.pid_t, std.mem.trim(u8, text, " \n"), 10) catch return null;
    posix.kill(pid, @fromBackingInt(@intCast(0))) catch return null;
    return pid;
}

/// stop tells QEMU's monitor to quit, then sends TERM and KILL if it does
/// not, and reports whether a QEMU was running. If the monitor socket is
/// gone or refuses, the pid is stale and may belong to another process now,
/// so it is sent nothing.
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

/// freePort returns want if nothing listens on it on loopback, else a free
/// port the kernel picks.
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

/// record returns the value of key in d/machine, a file of KEY VALUE lines.
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

/// disk creates path as a sparse file of size bytes for the machine's /data.
/// An existing disk is kept, so /data survives restarts.
pub fn disk(io: Io, path: []const u8, size: u64) !void {
    // Mode 0600: /data holds secrets, in the clear unless a data key was given.
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

/// attach prints the console log's tail, then, on a terminal, connects to
/// the live console until Ctrl-] detaches or the machine stops.
pub fn attach(io: Io, gpa: Allocator, d: []const u8) !void {
    const out = Io.File.stdout();
    const log = try gpa.print("{s}/console.log", .{d});
    const text = Dir.cwd().readFileAlloc(io, log, gpa, .limited(64 << 20)) catch "";
    // The last 64 KiB holds the boot and what followed.
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

test argv {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const m: Machine = .{
        .arch = .aarch64,
        .dir = "/w,x/m",
        .kernel = "/w/vmlinuz",
        .initrd = "/w/initramfs.zst",
        .cmdline = "debugfs=off",
        .ssh_port = 2222,
        .web_port = 8080,
        .guest_web = 80,
    };
    const a = try argv(arena.allocator(), m, .hvf, true);
    const line = try std.mem.join(arena.allocator(), " ", a);
    try std.testing.expectEqualStrings("qemu-system-aarch64", a[0]);
    for ([_][]const u8{
        "-M virt,virtualization=on -accel hvf -cpu host",
        "-pidfile /w,x/m/qemu.pid",
        "path=/w,,x/m/console.sock",
        "-append console=ttyAMA0 debugfs=off werewolf.ip=10.0.2.15/24",
        "hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8080-:80",
        "file=/w,,x/m/config.tar,format=raw,if=virtio,readonly=on",
    }) |want| try std.testing.expect(std.mem.find(u8, line, want) != null);
    const x = try argv(arena.allocator(), .{
        .arch = .x86_64,
        .dir = "/m",
        .kernel = "k",
        .initrd = "i",
        .cmdline = "",
        .ssh_port = 1,
        .web_port = 2,
        .guest_web = 3,
    }, .tcg, false);
    const xl = try std.mem.join(arena.allocator(), " ", x);
    try std.testing.expect(std.mem.find(u8, xl, "-M q35 -accel tcg -cpu max") != null);
    try std.testing.expect(std.mem.find(u8, xl, "console=ttyS0") != null);
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
