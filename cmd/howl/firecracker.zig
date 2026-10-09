//! firecracker runs a machine as a Firecracker microVM on Linux with KVM
//! (experimental). It boots the kernel and stage0 directly, with no
//! bootloader or slots, under a supervisor. See README.md.

const std = @import("std");
const builtin = @import("builtin");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// installed reports whether this is Linux with /dev/kvm and firecracker
/// on the PATH (tools/install-deps installs it).
pub fn installed(io: Io, gpa: Allocator) bool {
    if (builtin.os.tag != .linux) return false;
    Dir.cwd().access(io, "/dev/kvm", .{}) catch return false;
    const r = std.process.run(gpa, io, .{ .argv = &.{ "firecracker", "--version" } }) catch
        return false;
    return r.term == .exited and r.term.exited == 0;
}

/// rootReady reports whether the network can be set up without a password
/// prompt. create and run only pick Firecracker by default when it can.
pub fn rootReady(io: Io, gpa: Allocator) bool {
    const root = asRoot(io, gpa) catch return false;
    return root.len == 0 or asked(io, gpa, root[0]);
}

/// asRoot returns the command prefix for root: none when already root,
/// else the first of sudo and doas that needs no password, else the first
/// installed. It fails with error.NoRoot if neither is installed.
pub fn asRoot(io: Io, gpa: Allocator) error{NoRoot}![]const []const u8 {
    if (howl.isRoot()) return &.{};
    const tools = .{ "/usr/bin/sudo", "/usr/bin/doas", "/usr/local/bin/doas" };
    var first: ?[]const []const u8 = null;
    inline for (tools) |path| {
        // Comptime, so the returned slice is static, not a temporary's address.
        const tool: []const []const u8 = comptime &.{std.fs.path.basename(path)};
        if (Dir.cwd().access(io, path, .{})) |_| {
            if (asked(io, gpa, tool[0])) return tool;
            first = first orelse tool;
        } else |_| {}
    }
    return first orelse error.NoRoot;
}

/// asked reports whether tool runs a command without a password. Both sudo
/// and doas take -n to fail instead of prompting.
fn asked(io: Io, gpa: Allocator, tool: []const u8) bool {
    const r = std.process.run(gpa, io, .{ .argv = &.{ tool, "-n", "true" } }) catch return false;
    return r.term == .exited and r.term.exited == 0;
}

/// Net is a machine's tap device, MAC and /30, all derived from the name's
/// sha256 so nothing needs to record them.
pub const Net = struct {
    tap: []const u8,
    mac: []const u8,
    /// host is this host's address on the tap and the machine's gateway.
    host: []const u8,
    /// guest is the machine's address; subnet is the /30 holding both.
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

/// bootArgs returns the kernel command line. Firecracker has no DHCP, so
/// the address goes here. reboot=k reboots through the keyboard
/// controller, which Firecracker treats as the guest exiting; pci=off
/// because Firecracker has no PCI.
pub fn bootArgs(gpa: Allocator, image_args: []const u8, n: Net, dns: []const u8) ![]const u8 {
    return gpa.print(
        "console=ttyS0 reboot=k panic=10 pci=off {s} werewolf.ip={s}/30 werewolf.gw={s} " ++
            "werewolf.dns={s} werewolf.data=vda werewolf.root=vdc",
        .{ image_args, n.guest, n.host, dns },
    );
}

/// kernelPath returns the kernel to boot, relative to the checkout. On
/// x86_64 it is the ELF vmlinux the build unpacks from the bzImage:
/// booting the bzImage costs 0.1 s per boot while its stub gunzips 39 MB.
/// On aarch64 vmlinuz is already a raw Image.
pub fn kernelPath(gpa: Allocator, arch: howl.Arch) ![]const u8 {
    const file = switch (arch) {
        .x86_64 => "vmlinux",
        .aarch64 => "vmlinuz",
    };
    return gpa.print("build/{t}/{s}", .{ arch, file });
}

const Drive = struct {
    drive_id: []const u8,
    path_on_host: []const u8,
    is_root_device: bool,
    is_read_only: bool,
};

/// config returns Firecracker's JSON configuration. The kernel names
/// drives in order, so data is vda, the config tar vdb and the root vdc,
/// as bootArgs expects.
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
        // Send Firecracker's log to a separate file to keep the console clean.
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
        .@"machine-config" = .{ .vcpu_count = howl.local_cpus, .mem_size_mib = howl.local_mib },
    }, .{ .whitespace = .indent_2 });
}

/// hostDns returns this host's first non-loopback nameserver. It reads
/// systemd-resolved's file first, since /etc/resolv.conf may name only the
/// 127.0.0.53 stub, which the guest cannot reach.
pub fn hostDns(io: Io, gpa: Allocator) ?[]const u8 {
    for ([_][]const u8{ "/run/systemd/resolve/resolv.conf", "/etc/resolv.conf" }) |path| {
        const text = Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 << 10)) catch continue;
        if (nameserver(text)) |ns| return ns;
    }
    return null;
}

/// nameserver returns the first non-loopback nameserver in resolv.conf text.
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

/// networkUp creates the tap, owned by user so Firecracker opens it
/// unprivileged, gives the host its address, enables forwarding and adds
/// NAT and FORWARD rules. Each step is skipped if already done.
pub fn networkUp(
    io: Io,
    gpa: Allocator,
    root: []const []const u8,
    n: Net,
    user: []const u8,
    why: *howl.Why,
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
    // Enable forwarding only if it was off, and leave a marker so the last
    // machine's networkDown turns it off again. A host that already
    // forwarded keeps forwarding.
    const forward = Dir.cwd().readFileAlloc(io, ip_forward, gpa, .limited(8)) catch "";
    if (std.mem.eql(u8, std.mem.trim(u8, forward, "\n"), "0")) {
        if (Dir.cwd().createFile(io, forward_marker, .{ .exclusive = true })) |f| {
            f.close(io);
        } else |err| if (err != error.PathAlreadyExists) return err;
        try run(io, gpa, root, &.{ "sysctl", "-q", "-w", "net.ipv4.ip_forward=1" }, why);
    }
    for (try rules(gpa, n)) |r| {
        if (done(io, gpa, root, try iptables(gpa, "-C", r))) continue;
        try run(io, gpa, root, try iptables(gpa, "-A", r), why);
    }
}

/// networkDown removes the rules and the tap, and turns forwarding off if
/// networkUp turned it on and no machine's tap is left. It ignores
/// anything already gone.
pub fn networkDown(io: Io, gpa: Allocator, root: []const []const u8, n: Net) void {
    for (rules(
        gpa,
        n,
    ) catch return) |r| _ = done(io, gpa, root, iptables(gpa, "-D", r) catch return);
    _ = done(io, gpa, root, &.{ "ip", "link", "del", n.tap });
    Dir.cwd().access(io, forward_marker, .{}) catch return;
    if (tapsLeft(io)) return;
    if (done(io, gpa, root, &.{ "sysctl", "-q", "-w", "net.ipv4.ip_forward=0" }))
        Dir.cwd().deleteFile(io, forward_marker) catch {};
}

const ip_forward = "/proc/sys/net/ipv4/ip_forward";
/// forward_marker records that networkUp turned on the host's forwarding.
const forward_marker = "build/host/ip_forward-was-off";

/// tapsLeft reports whether any tap named like net's remains. It answers
/// true when unsure, so forwarding stays on.
fn tapsLeft(io: Io) bool {
    var d = Dir.cwd().openDir(io, "/sys/class/net", .{ .iterate = true }) catch return true;
    defer d.close(io);
    var it = d.iterate();
    while (it.next(io) catch return true) |e| {
        if (e.name.len != 10 or !std.mem.startsWith(u8, e.name, "fc")) continue;
        const hex = for (e.name[2..]) |c| {
            if (!std.ascii.isHex(c)) break false;
        } else true;
        if (hex) return true;
    }
    return false;
}

/// Rule is an iptables rule. An empty table means the filter table.
const Rule = struct {
    table: []const []const u8 = &.{},
    chain: []const u8,
    spec: []const []const u8,
};

/// rules returns NAT for the machine's /30 and FORWARD accepts both ways on
/// its tap.
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

/// iptables returns the argv for verb on r: -C checks, -A adds, -D removes.
pub fn iptables(gpa: Allocator, verb: []const u8, r: Rule) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(gpa, "iptables");
    try argv.appendSlice(gpa, r.table);
    try argv.appendSlice(gpa, &.{ verb, r.chain });
    try argv.appendSlice(gpa, r.spec);
    return argv.items;
}

/// done runs args under root quietly and reports whether it succeeded.
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
    why: *howl.Why,
) !void {
    try howl.run(io, why, try std.mem.concat(gpa, []const u8, &.{ root, args }));
}

/// running returns the pid in dir's pidfile if that Firecracker is alive.
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

/// stop kills Firecracker, like cutting power, and waits up to 10 s for
/// the supervisor to remove the pidfile.
pub fn stop(io: Io, gpa: Allocator, dir: []const u8, pid: std.posix.pid_t, why: *howl.Why) !void {
    if (builtin.os.tag != .linux) return;
    std.posix.kill(pid, .KILL) catch {};
    var waited: u32 = 0;
    while (waited < 10) : (waited += 1) {
        if (running(io, gpa, dir) == null) return;
        try io.sleep(.fromSeconds(1), .awake);
    }
    return why.refuse("{s}: its Firecracker, pid {d}, did not stop", .{ dir, pid });
}

/// keep is the supervisor, `howl _firecracker DIR`. It runs Firecracker on
/// DIR/vm.json with the console appended to DIR/console.log and stdin a
/// pipe never written. Firecracker exits 0 on both reboot and halt, so
/// keep reads the console to tell them apart, and restarts on reboot while
/// config.tar exists; delete removes it. Any other exit ends the machine.
pub fn keep(io: Io, gpa: Allocator, dir: []const u8) !void {
    const vm = try gpa.print("{s}/vm.json", .{dir});
    const log = try gpa.print("{s}/console.log", .{dir});
    const fc_log = try gpa.print("{s}/firecracker.log", .{dir});
    const pidfile = try gpa.print("{s}/firecracker.pid", .{dir});
    const config_tar = try gpa.print("{s}/config.tar", .{dir});
    // Append, so each boot follows the last and watch can skip what it saw.
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
    // Read only the log's tail, where a halt shows; the log grows forever.
    const tail = try gpa.alloc(u8, 1 << 20);
    while (true) {
        const seen = if (Dir.cwd().statFile(io, log, .{})) |st| st.size else |_| 0;
        // Firecracker's log must exist before it opens it.
        (try Dir.cwd().createFile(io, fc_log, .{ .truncate = false })).close(io);
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
        const since: []const u8 = if (Dir.cwd().openFile(io, log, .{})) |f| read: {
            defer f.close(io);
            const len = f.length(io) catch break :read "";
            const from = @max(seen, len -| tail.len);
            break :read tail[0 .. f.readPositionalAll(io, tail, from) catch 0];
        } else |_| "";
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
        "/b/slot/stage0.zst",
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
        try kernelPath(arena.allocator(), .x86_64),
    );
    try testing.expectEqualStrings(
        "build/aarch64/vmlinuz",
        try kernelPath(arena.allocator(), .aarch64),
    );
}
