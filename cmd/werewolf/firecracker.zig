//! Firecracker: a werewolf machine as a microVM on Linux with KVM,
//! experimental, booted directly: the kernel and the slot's initramfs,
//! with no bootloader and no slots; a data disk of its own; the config tar
//! as a second virtio drive, read-only, where init finds it; and the
//! slot's root.erofs as a third, read-only, which stage0 opens through
//! dm-verity (werewolf.root=vdc). Not appended to the initramfs, as
//! `make run`'s is: the kernel would unpack it into RAM, 20 MB held for
//! the machine's life, as nothing frees an initramfs, and 26 ms of every
//! boot. Read from the disk as it is used, it cost userland 10 ms, so a
//! boot came up 10 to 15 ms sooner. A rebuild cannot change it under a
//! running machine: the build makes a new root.erofs, not writing over
//! the old one, which Firecracker holds open until the next boot.
//!
//! Firecracker is a process that exits when the guest stops, for a reboot
//! as for a halt, so create starts it detached, under setsid, through
//! werewolf's own supervisor (`werewolf _firecracker`), which runs it
//! again after a reboot, which the console tells from a halt, and keeps
//! its console on the machine's console.log. Firecracker runs as this
//! user; only the machine's network needs root, through sudo or doas: a
//! tap device of the name's, on a /30 of 172.16.0.0/16 the name's sha256
//! picks, with the host at .1, the guest at .2 and NAT out through
//! iptables, since Firecracker has no user-mode network and no DHCP. So
//! the address goes on the kernel command line, as init takes it
//! (werewolf.ip), with this host's resolver, the first not on loopback.
//! The supervisor's pidfile is the state: the machine runs while the
//! Firecracker it names does.

const std = @import("std");
const builtin = @import("builtin");
const ww = @import("werewolf.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// Whether this machine runs Firecracker: Linux with /dev/kvm, and
/// firecracker on the PATH (tools/install-deps installs it).
pub fn installed(io: Io, gpa: Allocator) bool {
    if (builtin.os.tag != .linux) return false;
    Dir.cwd().access(io, "/dev/kvm", .{}) catch return false;
    const r = std.process.run(gpa, io, .{ .argv = &.{ "firecracker", "--version" } }) catch
        return false;
    return r.term == .exited and r.term.exited == 0;
}

/// Whether the network can be set up now, with no one asked a password:
/// root, or a sudo or doas that asks none, as create and run need to
/// choose Firecracker without stopping to ask.
pub fn rootReady(io: Io, gpa: Allocator) bool {
    if (isRoot()) return true;
    return asked(io, gpa, (asRoot(io, gpa) catch return false)[0]);
}

/// What sets the network up, which needs root: nothing as root; else the
/// first of sudo and doas that asks no password, or, if both would, the
/// first there is.
pub fn asRoot(io: Io, gpa: Allocator) error{NoRoot}![]const []const u8 {
    if (isRoot()) return &.{};
    const tools = .{ "/usr/bin/sudo", "/usr/bin/doas", "/usr/local/bin/doas" };
    var first: ?[]const []const u8 = null;
    inline for (tools) |path| {
        // Comptime, so what is returned is static, not a temporary's address.
        const tool: []const []const u8 = comptime &.{std.fs.path.basename(path)};
        if (Dir.cwd().access(io, path, .{})) |_| {
            if (asked(io, gpa, tool[0])) return tool;
            first = first orelse tool;
        } else |_| {}
    }
    return first orelse error.NoRoot;
}

/// Whether tool runs a command as root without asking a password: -n,
/// fail rather than ask, which sudo and doas both take.
fn asked(io: Io, gpa: Allocator, tool: []const u8) bool {
    const r = std.process.run(gpa, io, .{ .argv = &.{ tool, "-n", "true" } }) catch return false;
    return r.term == .exited and r.term.exited == 0;
}

fn isRoot() bool {
    return switch (builtin.os.tag) {
        .linux => std.os.linux.geteuid() == 0,
        else => std.c.geteuid() == 0,
    };
}

/// A machine's network: its tap device and MAC, and its /30, all from the
/// name's sha256, so nothing records them.
pub const Net = struct {
    tap: []const u8,
    mac: []const u8,
    /// This host's address on the tap, the machine's gateway.
    host: []const u8,
    /// The machine's address, and the /30 both are in.
    guest: []const u8,
    subnet: []const u8,
};

pub fn net(gpa: Allocator, name: []const u8) !Net {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(name, &h, .{});
    const a = h[0];
    const b: u8 = (h[1] & 0x3f) << 2;
    return .{
        .tap = try gpa.print("fc{x:0>8}", .{std.mem.readInt(u32, h[2..6], .big)}),
        .mac = try gpa.print("06:00:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{ h[6], h[7], h[8], h[9] }),
        .host = try gpa.print("172.16.{d}.{d}", .{ a, b + 1 }),
        .guest = try gpa.print("172.16.{d}.{d}", .{ a, b + 2 }),
        .subnet = try gpa.print("172.16.{d}.{d}/30", .{ a, b }),
    };
}

/// The kernel's arguments: the serial console, a reboot by the keyboard
/// controller, which Firecracker takes as the guest's exit, no PCI, which
/// Firecracker has none of, then the image's own arguments, and the
/// address, with the data disk, as make run gives them, and the root's.
pub fn bootArgs(gpa: Allocator, image_args: []const u8, n: Net, dns: []const u8) ![]const u8 {
    return gpa.print(
        "console=ttyS0 reboot=k panic=10 pci=off {s} werewolf.ip={s}/30 werewolf.gw={s} " ++
            "werewolf.dns={s} werewolf.data=vda werewolf.root=vdc",
        .{ image_args, n.guest, n.host, dns },
    );
}

/// The kernel Firecracker boots, relative to the checkout: on x86_64 the
/// ELF vmlinux the build unpacks from the bzImage (Makefile,
/// $(BUILD)/vmlinux), which Firecracker loads as it is, where given the
/// bzImage it waits while the bzImage's stub gunzips 39 MB, 0.1 s of every
/// boot; on aarch64 the raw Image, $(BUILD)/vmlinuz already.
pub fn kernelPath(gpa: Allocator, arch: []const u8) ![]const u8 {
    const file = if (std.mem.eql(u8, arch, "x86_64")) "vmlinux" else "vmlinuz";
    return gpa.print("build/{s}/{s}", .{ arch, file });
}

const Drive = struct {
    drive_id: []const u8,
    path_on_host: []const u8,
    is_root_device: bool,
    is_read_only: bool,
};

/// Firecracker's configuration file: two CPUs and 2 GiB, as Lima's
/// machines have; the data disk first, so it is vda, then the tar, vdb,
/// then the root, vdc, in the order the kernel finds them.
pub fn config(
    gpa: Allocator,
    kernel: []const u8,
    initrd: []const u8,
    args: []const u8,
    data: []const u8,
    tar: []const u8,
    root: []const u8,
    log: []const u8,
    n: Net,
) ![]u8 {
    return std.json.Stringify.valueAlloc(gpa, .{
        .@"boot-source" = .{
            .kernel_image_path = kernel,
            .initrd_path = initrd,
            .boot_args = args,
        },
        // Firecracker's own log on a file of its own, so the console is
        // the machine's alone.
        .logger = .{ .log_path = log, .level = "Warning" },
        .drives = [_]Drive{
            .{
                .drive_id = "data",
                .path_on_host = data,
                .is_root_device = false,
                .is_read_only = false,
            },
            .{
                .drive_id = "config",
                .path_on_host = tar,
                .is_root_device = false,
                .is_read_only = true,
            },
            .{
                .drive_id = "root",
                .path_on_host = root,
                .is_root_device = false,
                .is_read_only = true,
            },
        },
        .@"network-interfaces" = [_]struct {
            iface_id: []const u8,
            guest_mac: []const u8,
            host_dev_name: []const u8,
        }{.{ .iface_id = "eth0", .guest_mac = n.mac, .host_dev_name = n.tap }},
        .@"machine-config" = .{ .vcpu_count = 2, .mem_size_mib = 2048 },
    }, .{ .whitespace = .indent_2 });
}

/// This host's resolver, for the machine: the first nameserver not on
/// loopback, in systemd-resolved's own file, where the real ones are
/// when /etc/resolv.conf names its stub, else in /etc/resolv.conf.
pub fn hostDns(io: Io, gpa: Allocator) ?[]const u8 {
    for ([_][]const u8{ "/run/systemd/resolve/resolv.conf", "/etc/resolv.conf" }) |path| {
        const text = Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 << 10)) catch continue;
        if (nameserver(text)) |ns| return ns;
    }
    return null;
}

/// The first nameserver line's address that is not loopback.
pub fn nameserver(text: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        if (!std.mem.eql(u8, words.next() orelse continue, "nameserver")) continue;
        const ns = words.next() orelse continue;
        if (std.mem.startsWith(u8, ns, "127.") or std.mem.eql(u8, ns, "::1")) continue;
        return ns;
    }
    return null;
}

/// The machine's network, up: its tap, this user's, so Firecracker opens
/// it unprivileged; this host's address on it; forwarding; and NAT out,
/// with the forward rules the host may need. Each step is skipped where
/// it is done already, so a second create changes nothing.
pub fn networkUp(
    io: Io,
    gpa: Allocator,
    root: []const []const u8,
    n: Net,
    user: []const u8,
    why: *ww.Why,
) !void {
    if (!done(io, gpa, root, &.{ "ip", "link", "show", n.tap })) {
        try run(
            io,
            gpa,
            root,
            &.{ "ip", "tuntap", "add", "dev", n.tap, "mode", "tap", "user", user },
            why,
        );
        try run(
            io,
            gpa,
            root,
            &.{ "ip", "addr", "add", try gpa.print("{s}/30", .{n.host}), "dev", n.tap },
            why,
        );
    }
    try run(io, gpa, root, &.{ "ip", "link", "set", n.tap, "up" }, why);
    try run(io, gpa, root, &.{ "sysctl", "-q", "-w", "net.ipv4.ip_forward=1" }, why);
    for (try rules(gpa, n)) |r| {
        if (done(io, gpa, root, try iptables(gpa, "-C", r))) continue;
        try run(io, gpa, root, try iptables(gpa, "-A", r), why);
    }
}

/// The machine's network, down: its rules and its tap. Nothing is said of
/// what was gone already.
pub fn networkDown(io: Io, gpa: Allocator, root: []const []const u8, n: Net) void {
    for (rules(
        gpa,
        n,
    ) catch return) |r| _ = done(io, gpa, root, iptables(gpa, "-D", r) catch return);
    _ = done(io, gpa, root, &.{ "ip", "link", "del", n.tap });
}

/// An iptables rule: its table, if not the filter table, its chain and
/// its specification.
const Rule = struct {
    table: []const []const u8 = &.{},
    chain: []const u8,
    spec: []const []const u8,
};

/// The rules the machine's network takes: NAT out for its /30, and its
/// tap's traffic forwarded both ways.
fn rules(gpa: Allocator, n: Net) ![3]Rule {
    return .{
        .{
            .table = &.{ "-t", "nat" },
            .chain = "POSTROUTING",
            .spec = try gpa.dupe([]const u8, &.{ "-s", n.subnet, "-j", "MASQUERADE" }),
        },
        .{
            .chain = "FORWARD",
            .spec = try gpa.dupe([]const u8, &.{ "-i", n.tap, "-j", "ACCEPT" }),
        },
        .{
            .chain = "FORWARD",
            .spec = try gpa.dupe([]const u8, &.{ "-o", n.tap, "-j", "ACCEPT" }),
        },
    };
}

/// iptables VERB on the rule: -C asks whether it is there, -A adds it, -D
/// removes it.
pub fn iptables(gpa: Allocator, verb: []const u8, r: Rule) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(gpa, "iptables");
    try argv.appendSlice(gpa, r.table);
    try argv.appendSlice(gpa, &.{ verb, r.chain });
    try argv.appendSlice(gpa, r.spec);
    return argv.items;
}

/// Whether a command on the node, as root, succeeds; quietly.
fn done(io: Io, gpa: Allocator, root: []const []const u8, args: []const []const u8) bool {
    const argv = std.mem.concat(gpa, []const u8, &.{ root, args }) catch return false;
    const r = std.process.run(gpa, io, .{ .argv = argv }) catch return false;
    return r.term == .exited and r.term.exited == 0;
}

fn run(
    io: Io,
    gpa: Allocator,
    root: []const []const u8,
    args: []const []const u8,
    why: *ww.Why,
) !void {
    try ww.run(io, why, try std.mem.concat(gpa, []const u8, &.{ root, args }));
}

/// The Firecracker the supervisor runs for the machine in dir, by its
/// pidfile, if it is alive.
pub fn running(io: Io, gpa: Allocator, dir: []const u8) ?std.posix.pid_t {
    const text = Dir.cwd().readFileAlloc(
        io,
        gpa.print("{s}/firecracker.pid", .{dir}) catch return null,
        gpa,
        .limited(32),
    ) catch return null;
    const pid = std.fmt.parseInt(
        std.posix.pid_t,
        std.mem.trim(u8, text, " \n"),
        10,
    ) catch return null;
    if (builtin.os.tag != .linux) return null;
    std.posix.kill(pid, .CONT) catch return null;
    return pid;
}

/// A hard stop: Firecracker killed, which ends the machine as cutting its
/// power would, and its supervisor, which removes the pidfile, waited for.
pub fn stop(io: Io, gpa: Allocator, dir: []const u8, pid: std.posix.pid_t, why: *ww.Why) !void {
    if (builtin.os.tag != .linux) return;
    std.posix.kill(pid, .KILL) catch {};
    var waited: u32 = 0;
    while (waited < 10) : (waited += 1) {
        if (running(io, gpa, dir) == null) return;
        try io.sleep(.fromSeconds(1), .awake);
    }
    return why.refuse("{s}: its Firecracker, pid {d}, did not stop", .{ dir, pid });
}

/// The supervisor, `werewolf _firecracker DIR`, detached: runs Firecracker
/// on DIR's vm.json, its console on this process's standard output, with
/// its standard input a pipe held open and never written, so the console
/// reads nothing, and its pid in DIR's pidfile. Firecracker exits 0 when
/// the guest stops, for a reboot as for a halt: the console tells them
/// apart, so a reboot runs it again, so long as the machine's config tar
/// is still there (delete removes it), and a halt ends the machine. Any
/// other exit, an error or a kill by delete or create, ends it too.
pub fn keep(io: Io, gpa: Allocator, dir: []const u8) !void {
    const vm = try gpa.print("{s}/vm.json", .{dir});
    const log = try gpa.print("{s}/console.log", .{dir});
    const fc_log = try gpa.print("{s}/firecracker.log", .{dir});
    const pidfile = try gpa.print("{s}/firecracker.pid", .{dir});
    const config_tar = try gpa.print("{s}/config.tar", .{dir});
    // The console, opened to append: every boot's output follows the last,
    // and what create saw before it started is still there to skip.
    const out: Io.File = .{
        .handle = try std.posix.openat(
            std.posix.AT.FDCWD,
            log,
            .{ .ACCMODE = .WRONLY, .APPEND = true, .CREAT = true },
            0o600,
        ),
        .flags = .{ .nonblocking = false },
    };
    defer out.close(io);
    while (true) {
        const seen = if (Dir.cwd().statFile(io, log, .{})) |st| st.size else |_| 0;
        // Firecracker's log must exist before it opens it.
        (Dir.cwd().createFile(io, fc_log, .{ .truncate = false }) catch |err|
            return err).close(io);
        var child = try std.process.spawn(io, .{
            .argv = &.{ "firecracker", "--no-api", "--config-file", vm },
            .stdin = .pipe,
            .stdout = .{ .file = out },
            .stderr = .{ .file = out },
        });
        try Dir.cwd().writeFile(io, .{
            .sub_path = pidfile,
            .data = try gpa.print("{d}\n", .{child.id orelse 0}),
        });
        const term = try child.wait(io);
        Dir.cwd().deleteFile(io, pidfile) catch {};
        const code: u32 = if (term == .exited) term.exited else 1;
        const text = Dir.cwd().readFileAlloc(io, log, gpa, .limited(64 << 20)) catch "";
        const since = text[@min(seen, text.len)..];
        const halted = std.mem.find(u8, since, "reboot: Power down") != null;
        var buf: [256]u8 = undefined;
        out.writeStreamingAll(io, std.mem.print(
            &buf,
            "werewolf: firecracker exited {d}: {s}\n",
            .{ code, if (code != 0)
                "an error, or it was killed"
            else if (halted)
                "the guest halted"
            else
                "the guest asked to reboot" },
        ) catch unreachable) catch {};
        if (code != 0 or halted) return;
        Dir.cwd().access(io, config_tar, .{}) catch return;
    }
}

const testing = std.testing;

test net {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const n = try net(arena.allocator(), "edge");
    try testing.expect(n.tap.len == 10 and std.mem.startsWith(u8, n.tap, "fc"));
    try testing.expect(std.mem.startsWith(u8, n.mac, "06:00:") and n.mac.len == 17);
    try testing.expect(std.mem.startsWith(u8, n.host, "172.16."));
    try testing.expect(std.mem.endsWith(u8, n.subnet, "/30"));
    const again = try net(arena.allocator(), "edge");
    try testing.expectEqualStrings(n.guest, again.guest);
    try testing.expect(!std.mem.eql(u8, n.tap, (try net(arena.allocator(), "router")).tap));
}

test iptables {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const n = try net(arena.allocator(), "edge");
    const r = try rules(arena.allocator(), n);
    const nat = try iptables(arena.allocator(), "-C", r[0]);
    try testing.expectEqualStrings("-t", nat[1]);
    try testing.expectEqualStrings("POSTROUTING", nat[4]);
    try testing.expectEqualStrings(n.subnet, nat[6]);
    const fwd = try iptables(arena.allocator(), "-A", r[1]);
    try testing.expectEqualStrings("FORWARD", fwd[2]);
    try testing.expectEqualStrings(n.tap, fwd[4]);
}

test nameserver {
    try testing.expectEqualStrings(
        "192.168.5.2",
        nameserver("# resolved\nnameserver 127.0.0.53\nnameserver 192.168.5.2\nsearch x\n").?,
    );
    try testing.expectEqual(null, nameserver("nameserver 127.0.0.1\n"));
}

test config {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const n = try net(gpa, "edge");
    const args = try bootArgs(gpa, "loglevel=5", n, "9.9.9.9");
    try testing.expect(std.mem.startsWith(
        u8,
        args,
        "console=ttyS0 reboot=k panic=10 pci=off loglevel=5 werewolf.ip=172.16.",
    ));
    try testing.expect(std.mem.endsWith(
        u8,
        args,
        "werewolf.dns=9.9.9.9 werewolf.data=vda werewolf.root=vdc",
    ));
    const c = try config(
        gpa,
        "/b/vmlinuz",
        "/b/slot/initramfs.zst",
        args,
        "/m/data.img",
        "/m/config.tar",
        "/b/slot/root.erofs",
        "/m/firecracker.log",
        n,
    );
    try testing.expect(std.mem.find(u8, c, "\"kernel_image_path\": \"/b/vmlinuz\"") != null);
    try testing.expect(std.mem.find(u8, c, "\"log_path\": \"/m/firecracker.log\"") != null);
    try testing.expect(std.mem.find(u8, c, "\"is_read_only\": true") != null);
    const data = std.mem.find(u8, c, "\"/m/data.img\"").?;
    const tar = std.mem.find(u8, c, "\"/m/config.tar\"").?;
    const root = std.mem.find(u8, c, "\"/b/slot/root.erofs\"").?;
    try testing.expect(data < tar and tar < root);
    try testing.expect(std.mem.find(u8, c, n.tap) != null);
    try testing.expect(std.mem.find(u8, c, "\"mem_size_mib\": 2048") != null);
}

test kernelPath {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings(
        "build/x86_64/vmlinux",
        try kernelPath(arena.allocator(), "x86_64"),
    );
    try testing.expectEqualStrings(
        "build/aarch64/vmlinuz",
        try kernelPath(arena.allocator(), "aarch64"),
    );
}
