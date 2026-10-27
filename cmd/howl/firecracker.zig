//! firecracker runs a machine as a Firecracker microVM on Linux with KVM
//! (experimental). The machine is the boot disk QEMU boots, slots and all.
//! Firecracker has no firmware or TPM. The default pins the initial boot
//! files on the trusted host and keeps IPE. Explicitly unprotected machines
//! use the supervisor's systemd-boot-like A/B selection. See README.md.

const std = @import("std");
const builtin = @import("builtin");
const gpt = @import("gpt");
const image = @import("image");
const howl = @import("howl.zig");
const booting = @import("boot.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;

pub const unavailable: @import("cmdline").Protections = .initMany(&.{ .secureboot, .tpm });
pub const warning = "Firecracker does not support UEFI Secure Boot or a TPM. " ++
    "Firmware cannot authenticate boot code, and there is no TPM release floor to prevent " ++
    "rollback to an older vulnerable image. By default howl pins boot files and arguments " ++
    "on the trusted host and retains IPE and dm-verity. Restoring older host state can still " ++
    "roll the machine back. Automatic image updates are unavailable: security fixes require " ++
    "rebuilding on the host. Use QEMU for " ++
    "firmware verification and TPM rollback protection.";
pub const trust_file = "firecracker-boot.json";

const BootTrust = struct {
    version: u8 = 1,
    entry: []const u8,
    kernel: [64]u8,
    initrd: [64]u8,

    fn hash(bytes: []const u8) [64]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        return std.fmt.bytesToHex(digest, .lower);
    }

    fn verify(trust: BootTrust, entry: []const u8, kernel: []const u8, initrd: []const u8) !void {
        if (trust.version != 1 or !mem.eql(u8, trust.entry, entry) or
            !mem.eql(u8, &trust.kernel, &hash(kernel)) or
            !mem.eql(u8, &trust.initrd, &hash(initrd))) return error.BootFilesChanged;
    }
};

/// Pin only a newly built image. Never enroll an existing guest-writable disk.
pub fn pin(io: Io, gpa: Allocator, dir: []const u8, why: *howl.Why) !void {
    const esp = try openEsp(io, gpa, dir, why);
    const text = try esp.run("mtype", &.{"::/loader/entries/werewolf-a.conf"});
    const e = Entry.parse("werewolf-a.conf", text);
    try e.direct();
    const trust: BootTrust = .{
        .entry = text,
        .kernel = BootTrust.hash(try esp.run("mtype", &.{try gpa.print("::{s}", .{e.linux})})),
        .initrd = BootTrust.hash(try esp.run("mtype", &.{try gpa.print("::{s}", .{e.initrd})})),
    };
    try howl.writePrivate(
        io,
        gpa,
        try gpa.print("{s}/{s}", .{ dir, trust_file }),
        try std.json.Stringify.valueAlloc(gpa, trust, .{ .whitespace = .indent_2 }),
        why,
    );
}

/// installed checks KVM, the supported static Firecracker binary and a working
/// namespace sandbox before auto-selection or an expensive image build.
pub fn installed(io: Io, gpa: Allocator) bool {
    if (builtin.os.tag != .linux) return false;
    Dir.cwd().access(io, "/dev/kvm", .{}) catch return false;
    const r = std.process.run(gpa, io, .{ .argv = &.{ "firecracker", "--version" } }) catch
        return false;
    if (r.term != .exited or r.term.exited != 0 or !supportedVersion(r.stdout) or
        executable(io, gpa, "prlimit") == null or
        executable(io, gpa, "timeout") == null) return false;
    // Check namespaces and the static release binary before building an image.
    const probe = std.process.run(gpa, io, .{ .argv = &.{
        "bwrap",        "--unshare-user", "--unshare-pid", "--disable-userns", "--new-session",
        "--cap-drop",   "ALL",            "--clearenv",    "--ro-bind",
        executable(
            io,
            gpa,
            "firecracker",
        ) orelse return false,
        "/firecracker", "--remount-ro",   "/",             "--",               "/firecracker",
        "--version",
    } }) catch return false;
    return probe.term == .exited and probe.term.exited == 0;
}

fn executable(io: Io, gpa: Allocator, name: []const u8) ?[]const u8 {
    var paths = mem.tokenizeScalar(u8, howl.environ.get("PATH") orelse "", ':');
    while (paths.next()) |path| {
        const file = std.fs.path.resolveAlloc(gpa, &.{ path, name }) catch return null;
        Dir.cwd().access(io, file, .{ .execute = true }) catch continue;
        return Dir.cwd().realPathFileAlloc(io, file, gpa) catch null;
    }
    return null;
}

/// A minimal mount namespace, with no host home, trust records, agent sockets,
/// signing keys or sibling VMs. Keep the host network namespace only to open
/// our tap; Firecracker's default seccomp remains enabled. No fallback to an
/// unsandboxed launch when namespace setup fails.
fn sandboxArgs(io: Io, gpa: Allocator, dir: []const u8) ![]const []const u8 {
    const fc = executable(io, gpa, "firecracker") orelse return error.FirecrackerMissing;
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(gpa, &.{
        "prlimit",           try gpa.print("--as={d}", .{(@as(u64, howl.local_mib) + 1024) << 20}),
        "--nofile=256",      "--core=0",
        "--",                "bwrap",
        "--unshare-user",    "--unshare-pid",
        "--unshare-ipc",     "--unshare-uts",
        "--unshare-cgroup",  "--disable-userns",
        "--die-with-parent", "--new-session",
        "--cap-drop",        "ALL",
        "--clearenv",        "--ro-bind",
        fc,                  "/firecracker",
        "--proc",            "/proc",
        "--dev",             "/dev",
        "--dev-bind",        "/dev/kvm",
        "/dev/kvm",          "--dev-bind",
        "/dev/net/tun",      "/dev/net/tun",
    });
    for ([_][]const u8{ "vm.json", "kernel", "stage0.zst", "config.tar" }) |file|
        try args.appendSlice(
            gpa,
            &.{
                "--ro-bind",
                try gpa.print("{s}/{s}", .{ dir, file }),
                try gpa.print("/vm/{s}", .{file}),
            },
        );
    try args.appendSlice(
        gpa,
        &.{ "--bind", try gpa.print("{s}/disk.img", .{dir}), "/vm/disk.img" },
    );
    const import_disk = try gpa.print("{s}/import.img", .{dir});
    if (Dir.cwd().access(io, import_disk, .{})) |_|
        try args.appendSlice(gpa, &.{ "--ro-bind", import_disk, "/vm/import.img" })
    else |err| if (err != error.FileNotFound) return err;
    try args.appendSlice(
        gpa,
        &.{
            "--chdir",
            "/",
            "--remount-ro",
            "/dev",
            "--remount-ro",
            "/proc",
            "--remount-ro",
            "/",
            "--",
            "/firecracker",
            "--no-api",
            "--config-file",
            "/vm/vm.json",
        },
    );
    return args.items;
}

fn supportedVersion(output: []const u8) bool {
    const text = mem.cutPrefix(u8, output, "Firecracker v") orelse return false;
    const end = mem.findAny(u8, text, " \r\n") orelse text.len;
    const v = std.SemanticVersion.parse(text[0..end]) catch return false;
    return v.order(.{ .major = 1, .minor = 17, .patch = 0 }) != .lt;
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
        .tap = try gpa.print("fc{x:0>8}", .{mem.readInt(u32, h[2..6], .big)}),
        .mac = try gpa.print("06:00:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{ h[6], h[7], h[8], h[9] }),
        .host = try gpa.print("172.16.{d}.{d}", .{ a, b + 1 }),
        .guest = try gpa.print("172.16.{d}.{d}", .{ a, b + 2 }),
        .subnet = try gpa.print("172.16.{d}.{d}/30", .{ a, b }),
    };
}

/// bootArgs returns the machine's arguments, which the disk's entry adds
/// to the image's and updates carry over. Firecracker has no DHCP, so the
/// address goes here. reboot=k reboots through the keyboard controller,
/// which Firecracker treats as the guest exiting.
pub fn bootArgs(gpa: Allocator, n: Net, dns: []const u8) ![]const []const u8 {
    return gpa.dupe([]const u8, &.{
        "reboot=k",
        try gpa.print("werewolf.ip={s}/30", .{n.guest}),
        try gpa.print("werewolf.gw={s}", .{n.host}),
        try gpa.print("werewolf.dns={s}", .{dns}),
    });
}

const Drive = struct {
    drive_id: []const u8,
    path_on_host: []const u8,
    is_root_device: bool,
    is_read_only: bool,
    rate_limiter: ?struct { bandwidth: Bucket, ops: Bucket } = null,
};

const Bucket = struct { size: u64, refill_time: u64 = 100 };

/// config returns Firecracker's JSON configuration: the boot disk, the
/// config tar, and the import disk when import_disk is set.
fn config(
    gpa: Allocator,
    kernel: []const u8,
    initrd: []const u8,
    args: []const u8,
    disk: []const u8,
    tar: []const u8,
    import_disk: ?[]const u8,
    log: []const u8,
    n: Net,
) ![]u8 {
    const extra: []const Drive = if (import_disk) |p| &.{.{
        .drive_id = "import",
        .path_on_host = p,
        .is_root_device = false,
        .is_read_only = true,
    }} else &.{};
    const drives = try mem.concat(gpa, Drive, &.{
        &.{
            .{
                .drive_id = "disk",
                .path_on_host = disk,
                .is_root_device = false,
                .is_read_only = false,
                .rate_limiter = .{ .bandwidth = .{ .size = 16 << 20 }, .ops = .{ .size = 1000 } },
            },
            .{
                .drive_id = "config",
                .path_on_host = tar,
                .is_root_device = false,
                .is_read_only = true,
            },
        },
        extra,
    });
    return std.json.Stringify.valueAlloc(gpa, .{
        .@"boot-source" = .{
            .kernel_image_path = kernel,
            .initrd_path = initrd,
            .boot_args = args,
        },
        // Send Firecracker's log to a separate file to keep the console clean.
        .logger = .{ .log_path = log, .level = "Warning" },
        .drives = drives,
        .@"network-interfaces" = [_]struct {
            iface_id: []const u8,
            guest_mac: []const u8,
            host_dev_name: []const u8,
            rx_rate_limiter: struct { bandwidth: Bucket } = .{ .bandwidth = .{ .size = 16 << 20 } },
            tx_rate_limiter: struct { bandwidth: Bucket } = .{ .bandwidth = .{ .size = 16 << 20 } },
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
    var lines = mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = mem.tokenizeAny(u8, line, " \t\r");
        if (!mem.eql(u8, words.next() orelse continue, "nameserver")) continue;
        const ns = words.next() orelse continue;
        if (mem.startsWith(u8, ns, "127.") or mem.eql(u8, ns, "::1")) continue;
        return ns;
    }
    return null;
}

/// networkUp creates the tap, owned by user so Firecracker opens it
/// unprivileged, gives the host its address, enables forwarding and adds
/// NAT and tap filtering. Replace only this tap's rules on each start.
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
    // readFile, not readFileAlloc, which takes /proc's size of 0 as empty.
    var fwd: [8]u8 = undefined;
    const forward = Dir.cwd().readFile(io, ip_forward, &fwd) catch "";
    if (mem.eql(u8, mem.trim(u8, forward, "\n"), "0")) {
        if (Dir.cwd().createFile(io, forward_marker, .{ .exclusive = true })) |f| {
            f.close(io);
        } else |err| if (err != error.PathAlreadyExists) return err;
        try run(io, gpa, root, &.{ "sysctl", "-q", "-w", "net.ipv4.ip_forward=1" }, why);
    }
    // Retire the broad rules installed by older howl versions.
    for (try legacyRules(gpa, n)) |r| while (done(io, gpa, root, try iptables(gpa, "-D", r))) {};
    const policy = try rules(gpa, n);
    for (policy) |r| while (done(io, gpa, root, try iptables(gpa, "-D", r))) {};
    // Prepend in reverse order: unrelated host ACCEPT rules cannot bypass the
    // tap's source, host-access, metadata and inter-VM restrictions.
    var i = policy.len;
    while (i > 0) {
        i -= 1;
        const r = policy[i];
        try run(io, gpa, root, try iptables(gpa, "-I", r), why);
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
    for (legacyRules(
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
        if (e.name.len != 10 or !mem.startsWith(u8, e.name, "fc")) continue;
        const hex = for (e.name[2..]) |c| {
            if (!std.ascii.isHex(c)) break false;
        } else true;
        if (hex) return true;
    }
    return false;
}

/// Rule is an iptables rule. An empty table means the filter table.
const Rule = struct {
    ipv6: bool = false,
    table: []const []const u8 = &.{},
    chain: []const u8,
    spec: []const []const u8,
};

/// rules returns NAT for the machine's /30 and FORWARD accepts both ways on
/// its tap.
fn legacyRules(gpa: Allocator, n: Net) ![3]Rule {
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

fn rules(gpa: Allocator, n: Net) ![]const Rule {
    const r = try gpa.alloc(Rule, 15);
    r[0] = .{
        .table = &.{ "-t", "nat" },
        .chain = "POSTROUTING",
        .spec = try gpa.dupe([]const u8, &.{ "-s", n.guest, "-j", "MASQUERADE" }),
    };
    r[1] = .{
        .chain = "INPUT",
        .spec = try gpa.dupe([]const u8, &.{ "-i", n.tap, "!", "-s", n.guest, "-j", "DROP" }),
    };
    r[2] = .{
        .chain = "INPUT",
        .spec = try gpa.dupe(
            []const u8,
            &.{
                "-i",
                n.tap,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            },
        ),
    };
    // Preserve a host DNS resolver, including systemd-resolved forwarding.
    r[3] = .{
        .chain = "INPUT",
        .spec = try gpa.dupe(
            []const u8,
            &.{ "-i", n.tap, "-p", "udp", "--dport", "53", "-j", "ACCEPT" },
        ),
    };
    r[4] = .{
        .chain = "INPUT",
        .spec = try gpa.dupe(
            []const u8,
            &.{ "-i", n.tap, "-p", "tcp", "--dport", "53", "-j", "ACCEPT" },
        ),
    };
    r[5] = .{ .chain = "INPUT", .spec = try gpa.dupe([]const u8, &.{ "-i", n.tap, "-j", "DROP" }) };
    r[6] = .{
        .chain = "FORWARD",
        .spec = try gpa.dupe([]const u8, &.{ "-i", n.tap, "!", "-s", n.guest, "-j", "DROP" }),
    };
    r[7] = .{
        .chain = "FORWARD",
        .spec = try gpa.dupe([]const u8, &.{ "-i", n.tap, "-d", "169.254.0.0/16", "-j", "DROP" }),
    };
    r[8] = .{
        .chain = "FORWARD",
        .spec = try gpa.dupe([]const u8, &.{ "-i", n.tap, "-o", "fc+", "-j", "DROP" }),
    };
    r[9] = .{
        .chain = "FORWARD",
        .spec = try gpa.dupe([]const u8, &.{ "-i", n.tap, "-j", "ACCEPT" }),
    };
    r[10] = .{
        .chain = "FORWARD",
        .spec = try gpa.dupe(
            []const u8,
            &.{
                "-o",
                n.tap,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            },
        ),
    };
    r[11] = .{
        .chain = "FORWARD",
        .spec = try gpa.dupe([]const u8, &.{ "-o", n.tap, "-j", "DROP" }),
    };
    // howl configures IPv4 only. Do not leave an IPv6 path around the policy.
    r[12] = .{
        .ipv6 = true,
        .chain = "INPUT",
        .spec = try gpa.dupe([]const u8, &.{ "-i", n.tap, "-j", "DROP" }),
    };
    r[13] = .{
        .ipv6 = true,
        .chain = "FORWARD",
        .spec = try gpa.dupe([]const u8, &.{ "-i", n.tap, "-j", "DROP" }),
    };
    r[14] = .{
        .ipv6 = true,
        .chain = "FORWARD",
        .spec = try gpa.dupe([]const u8, &.{ "-o", n.tap, "-j", "DROP" }),
    };
    return r;
}

/// iptables returns the argv for verb on r: -C checks, -A adds, -D removes.
pub fn iptables(gpa: Allocator, verb: []const u8, r: Rule) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(gpa, if (r.ipv6) "ip6tables" else "iptables");
    try argv.appendSlice(gpa, r.table);
    try argv.appendSlice(gpa, &.{ verb, r.chain });
    try argv.appendSlice(gpa, r.spec);
    return argv.items;
}

/// done runs args under root quietly and reports whether it succeeded.
fn done(io: Io, gpa: Allocator, root: []const []const u8, args: []const []const u8) bool {
    const argv = mem.concat(gpa, []const u8, &.{ root, args }) catch return false;
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
    try howl.run(io, why, try mem.concat(gpa, []const u8, &.{ root, args }));
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
        mem.trim(u8, text, " \n"),
        10,
    ) catch return null;
    if (builtin.os.tag != .linux) return null;
    std.posix.kill(pid, @fromBackingInt(@intCast(0))) catch return null;
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

/// Entry is a Boot Loader Specification entry on the disk's EFI partition.
/// werewolf's have one line of each key.
const Entry = struct {
    /// name is the file's: werewolf-a.conf, or werewolf-b+1.conf while it
    /// counts tries.
    name: []const u8,
    version: []const u8 = "",
    linux: []const u8 = "",
    initrd: []const u8 = "",
    efi: bool = false,
    options: []const u8 = "",

    fn parse(name: []const u8, text: []const u8) Entry {
        var e: Entry = .{ .name = name };
        var lines = mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = mem.trim(u8, raw, " \t\r");
            if (mem.eql(u8, line, "efi") or mem.eql(u8, line, "uki") or
                mem.eql(u8, line, "uki-url")) e.efi = true;
            const sp = mem.findAny(u8, line, " \t") orelse continue;
            const key = line[0..sp];
            const value = mem.trim(u8, line[sp..], " \t");
            if (mem.eql(u8, key, "version")) e.version = value;
            if (mem.eql(u8, key, "linux")) e.linux = value;
            if (mem.eql(u8, key, "initrd")) e.initrd = value;
            if (mem.eql(u8, key, "efi") or mem.eql(u8, key, "uki") or
                mem.eql(u8, key, "uki-url")) e.efi = true;
            if (mem.eql(u8, key, "options")) e.options = value;
        }
        return e;
    }

    fn direct(e: Entry) error{ FirmwareRequired, IncompleteEntry }!void {
        if (e.efi) return error.FirmwareRequired;
        if (e.linux.len == 0 or e.initrd.len == 0) return error.IncompleteEntry;
    }

    /// Tries is the count in an entry's name: werewolf-b+1.conf has one try
    /// left, werewolf-b+0-1.conf none, after one.
    const Tries = struct { left: u32, done: u32 };

    fn tries(e: Entry) ?Tries {
        const stem = mem.cutSuffix(u8, e.name, ".conf") orelse return null;
        const count = stem[(mem.findScalarLast(u8, stem, '+') orelse return null) + 1 ..];
        const dash = mem.findScalar(u8, count, '-');
        return .{
            .left = std.fmt.parseUnsigned(u32, count[0 .. dash orelse count.len], 10) catch
                return null,
            .done = if (dash) |d|
                std.fmt.parseUnsigned(u32, count[d + 1 ..], 10) catch return null
            else
                0,
        };
    }

    /// spent returns the name after one more try, or null if e counts none
    /// or has none left.
    fn spent(e: Entry, gpa: Allocator) !?[]const u8 {
        const t = e.tries() orelse return null;
        if (t.left == 0) return null;
        const stem = e.name[0..mem.findScalarLast(u8, e.name, '+').?];
        return try gpa.print("{s}+{d}-{d}.conf", .{ stem, t.left - 1, t.done + 1 });
    }

    /// before reports whether systemd-boot puts a ahead of b, for entries
    /// that share a sort-key, as werewolf's do: one with no tries left goes
    /// last, then the newest version first (serials, which sort as text),
    /// then the name, so the order is total.
    fn before(a: Entry, b: Entry) bool {
        const a_out = if (a.tries()) |t| t.left == 0 else false;
        const b_out = if (b.tries()) |t| t.left == 0 else false;
        if (a_out != b_out) return b_out;
        return switch (mem.order(u8, a.version, b.version)) {
            .gt => true,
            .lt => false,
            .eq => mem.order(u8, a.name, b.name) == .gt,
        };
    }
};

/// Esp reads and renames files on the EFI partition of a stopped
/// machine's disk with mtools.
const Esp = struct {
    io: Io,
    gpa: Allocator,
    disk: []const u8,
    why: *howl.Why,

    /// run runs an mtools command on the partition and returns its output.
    fn run(esp: Esp, tool: []const u8, args: []const []const u8) ![]const u8 {
        // The FAT metadata is guest-writable too. A parser bug must not expose
        // the supervisor's trust records or signing keys to the guest.
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(esp.gpa, &.{
            "timeout",          "30",                "prlimit",
            "--as=53687091" ++
                "2",
            "--cpu=15",         "--nofile=64",       "--core=0",
            "--",               "bwrap",
            "--unshare-al" ++
                "l",
            "--unshare-use" ++
                "r",
            "--disable-userns", "--die-with-parent", "--new-session",
            "--cap-drop",       "ALL",
            "--clearen" ++
                "v",
            "--setenv",
            "MTOOLS_SKIP_CHEC" ++
                "K",
            "1",                "--proc",            "/proc",
            "--dev",            "/dev",              "--ro-bind",
            executable(
                esp.io,
                esp.gpa,
                tool,
            ) orelse return error.MtoolsMissing,
            try esp.gpa.print(
                "/{s}",
                .{tool},
            ),
            if (mem.eql(u8, tool, "mren"))
                "--bind"
            else
                "--ro-bind",
            esp.disk,           "/disk.img",
        });
        for ([_][]const u8{ "/lib", "/lib64", "/usr/lib", "/usr/lib64" }) |path|
            try argv.appendSlice(esp.gpa, &.{ "--ro-bind-try", path, path });
        try argv.appendSlice(
            esp.gpa,
            &.{
                "--chdir",
                "/",
                "--remount-ro",
                "/dev",
                "--remount-ro",
                "/proc",
                "--remount-ro",
                "/",
                "--",
                try esp.gpa.print("/{s}", .{tool}),
                "-i",
                try esp.gpa.print("/disk.img@@{d}", .{gpt.margin * gpt.sector}),
            },
        );
        try argv.appendSlice(esp.gpa, args);
        const r = std.process.run(esp.gpa, esp.io, .{
            .argv = argv.items,
            .stdout_limit = .limited(image.max_gunzip),
            .stderr_limit = .limited(4096),
        }) catch |err| return esp.why.refuse("{s}: {t}", .{ tool, err });
        if (r.term != .exited or r.term.exited != 0) return esp.why.refuse(
            "{s} {s}: {s}",
            .{ tool, args[args.len - 1], mem.trim(u8, r.stderr, " \n") },
        );
        return r.stdout;
    }
};

/// boot does systemd-boot's part for the machine in dir: it picks the
/// entry on disk.img's EFI partition, renames it to spend a try if it
/// counts them, takes its kernel and stage0, and writes vm.json. It
/// returns what it chose, for the console log. x86_64 keeps the bzImage:
/// its decompressor supplies KASLR, bypassed by extracting the ELF. This
/// requires Firecracker 1.17+. aarch64 unwraps the EFI zboot Image.
fn openEsp(io: Io, gpa: Allocator, dir: []const u8, why: *howl.Why) !Esp {
    const disk = try gpa.print("{s}/disk.img", .{dir});
    return .{
        .io = io,
        .gpa = gpa,
        .disk = disk,
        .why = why,
    };
}

fn boot(io: Io, gpa: Allocator, dir: []const u8, why: *howl.Why, pinned: bool) ![]const u8 {
    const esp = try openEsp(io, gpa, dir, why);
    const disk = try gpa.print("{s}/disk.img", .{dir});
    const trust: ?BootTrust = if (pinned) try std.json.parseFromSliceLeaky(
        BootTrust,
        gpa,
        try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/{s}", .{ dir, trust_file }),
            gpa,
            .limited(64 << 10),
        ),
        .{},
    ) else null;
    var chosen: ?Entry = null;
    if (trust) |t| {
        // The trusted host selects the initial image. Guest-written entries cannot
        // select a different kernel, root hash, command line or trial slot.
        const text = try esp.run("mtype", &.{"::/loader/entries/werewolf-a.conf"});
        if (!mem.eql(
            u8,
            text,
            t.entry,
        )) return why.refuse("pinned Firecracker boot entry changed", .{});
        chosen = .parse("werewolf-a.conf", text);
    } else {
        var listed = mem.tokenizeScalar(
            u8,
            try esp.run("mdir", &.{ "-b", "::/loader/entries" }),
            '\n',
        );
        while (listed.next()) |path| {
            if (!mem.endsWith(u8, path, ".conf")) continue;
            const e: Entry = .parse(
                path["::/loader/entries/".len..],
                try esp.run("mtype", &.{path}),
            );
            if (chosen == null or e.before(chosen.?)) chosen = e;
        }
    }
    const e = chosen orelse return why.refuse("{s}: no boot entries", .{disk});
    e.direct() catch |err| return switch (err) {
        error.FirmwareRequired => why.refuse(
            "Firecracker has no UEFI Secure Boot; refusing EFI entry {s}; use --on qemu",
            .{e.name},
        ),
        error.IncompleteEntry => why.refuse("{s}: no linux or initrd line", .{e.name}),
    };
    var said = try gpa.print("booting {s}", .{e.name});
    if (try e.spent(gpa)) |name| {
        _ = try esp.run("mren", &.{ try gpa.print("::/loader/entries/{s}", .{e.name}), name });
        said = try gpa.print("{s}, a try spent: {s}", .{ said, name });
    }
    const shipped = try esp.run("mtype", &.{try gpa.print("::{s}", .{e.linux})});
    const stage0 = try esp.run("mtype", &.{try gpa.print("::{s}", .{e.initrd})});
    if (trust) |t| {
        t.verify(t.entry, shipped, stage0) catch
            return why.refuse("pinned Firecracker kernel or initrd changed; refusing to boot", .{});
        said = try gpa.print("{s}; host-pinned kernel, initrd and command line verified", .{said});
    }
    const kernel = if (builtin.cpu.arch == .x86_64)
        shipped
    else
        image.unwrapZboot(
            gpa,
            shipped,
        ) catch |err| return why.refuse("{s}: {t}", .{ e.linux, err });
    const kernel_path = try gpa.print("{s}/kernel", .{dir});
    const stage0_path = try gpa.print("{s}/stage0.zst", .{dir});
    try Dir.cwd().writeFile(io, .{ .sub_path = kernel_path, .data = kernel });
    try Dir.cwd().writeFile(io, .{ .sub_path = stage0_path, .data = stage0 });
    var args: std.ArrayList(u8) = .empty;
    var words = mem.tokenizeScalar(u8, e.options, ' ');
    while (words.next()) |w| {
        if (added(w)) continue;
        try args.print(gpa, "{s}{s}", .{ if (args.items.len > 0) " " else "", w });
    }
    const import_path = try gpa.print("{s}/import.img", .{dir});
    const import_disk: ?[]const u8 = if (Dir.cwd().access(io, import_path, .{})) |_|
        import_path
    else |_|
        null;
    try Dir.cwd().writeFile(io, .{
        .sub_path = try gpa.print("{s}/vm.json", .{dir}),
        .data = try config(
            gpa,
            "/vm/kernel",
            "/vm/stage0.zst",
            args.items,
            "/vm/disk.img",
            "/vm/config.tar",
            if (import_disk != null) "/vm/import.img" else null,
            "/dev/stderr",
            try net(gpa, std.fs.path.basename(dir)),
        ),
    });
    return said;
}

/// added reports whether Firecracker adds arg to every command line:
/// pci=off, earlycon= for its serial port, virtio_mmio.device= for each
/// device on x86_64. An update carries the running command line into its
/// entry, so boot drops them, lest each update add them once more.
fn added(arg: []const u8) bool {
    return mem.eql(u8, arg, "pci=off") or mem.startsWith(u8, arg, "earlycon=") or
        mem.startsWith(u8, arg, "virtio_mmio.device=");
}

pub const log_limit = 8 << 20;

fn boundedWrite(io: Io, file: Io.File, bytes: []const u8) !void {
    if (bytes.len > log_limit) return error.LogChunkTooLarge;
    if (try file.length(io) > log_limit - bytes.len) try file.setLength(io, 0);
    try file.writePositionalAll(io, bytes, try file.length(io));
}

/// Drain continuously, even after a log fills. Blocking the guest's serial
/// device is neither a storage limit nor a reliable way to observe shutdown.
fn drain(io: Io, from: Io.File, to: Io.File) !bool {
    defer from.close(io);
    const halt = "reboot: Power down";
    var buffer: [64 << 10]u8 = undefined;
    var held: usize = 0;
    var halted = false;
    while (true) {
        const n = from.readStreaming(io, &.{buffer[held..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        halted = halted or mem.find(u8, buffer[0 .. held + n], halt) != null;
        try boundedWrite(io, to, buffer[held .. held + n]);
        const retained = @min(held + n, halt.len - 1);
        @memmove(buffer[0..retained], buffer[held + n - retained .. held + n]);
        held = retained;
    }
    return halted;
}

/// keep is the supervisor, `howl _firecracker DIR`. Before each start it
/// boots as systemd-boot would (boot). It runs Firecracker on DIR/vm.json
/// with bounded console/diagnostic logs and stdin a pipe never written.
/// Firecracker exits 0 on both reboot and halt, so keep observes the console
/// stream to tell them apart, and restarts on reboot while config.tar
/// exists; delete removes it. Any other exit ends the machine.
pub fn keep(io: Io, gpa: Allocator, dir: []const u8, pinned: bool) !void {
    // Preserve admission when an operator invokes the internal supervisor directly.
    // Once selected, losing the record during a guest reboot never downgrades it.
    const require_pin = pinned or
        if (Dir.cwd().access(io, try gpa.print("{s}/{s}", .{ dir, trust_file }), .{})) |_|
            true
        else |err| switch (err) {
            error.FileNotFound => false,
            else => return err,
        };
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
    const errors: Io.File = .{
        .handle = try std.posix.openat(
            std.posix.AT.FDCWD,
            fc_log,
            .{ .ACCMODE = .WRONLY, .APPEND = true, .CREAT = true },
            0o600,
        ),
        .flags = .{ .nonblocking = false },
    };
    defer errors.close(io);
    var buf: [4352]u8 = undefined;
    while (true) {
        // Each boot holds a kernel in memory; free it before the next.
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        var why: howl.Why = .{};
        const said = boot(io, arena.allocator(), dir, &why, require_pin) catch |err| {
            boundedWrite(io, out, mem.print(
                &buf,
                booting.no_slot ++ "{s}\n",
                .{if (why.text.len > 0) why.text else @errorName(err)},
            ) catch unreachable) catch {};
            return;
        };
        boundedWrite(io, out, mem.print(&buf, "werewolf: {s}\n", .{said}) catch
            "werewolf: booting\n") catch {};
        var child = try std.process.spawn(io, .{
            .argv = try sandboxArgs(io, arena.allocator(), dir),
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .pipe,
        });
        defer child.kill(io);
        var console = try io.concurrent(drain, .{ io, child.stdout.?, out });
        child.stdout = null;
        defer _ = console.cancel(io) catch {};
        var diagnostics = try io.concurrent(drain, .{ io, child.stderr.?, errors });
        child.stderr = null;
        defer _ = diagnostics.cancel(io) catch {};
        try Dir.cwd().writeFile(io, .{
            .sub_path = pidfile,
            .data = try arena.allocator().print("{d}\n", .{child.id orelse 0}),
        });
        const term = try child.wait(io);
        const halted = try console.await(io);
        _ = try diagnostics.await(io);
        Dir.cwd().deleteFile(io, pidfile) catch {};
        const code: u32 = if (term == .exited) term.exited else 1;
        boundedWrite(io, out, mem.print(
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

test "bzImage boot requires Firecracker 1.17 or newer" {
    try testing.expect(supportedVersion("Firecracker v1.17.0\n"));
    try testing.expect(supportedVersion("Firecracker v1.18.0\n"));
    try testing.expect(!supportedVersion("Firecracker v1.16.0\n"));
    try testing.expect(!supportedVersion("Firecracker v1.17.0-rc.1\n"));
    try testing.expect(!supportedVersion("unknown"));
}

test "host boot pins reject changed kernel, initrd, arguments and unknown versions" {
    const trust: BootTrust = .{
        .entry = "linux /kernel\ninitrd /initrd\noptions werewolf.disable=secureboot,tpm\n",
        .kernel = BootTrust.hash("trusted kernel"),
        .initrd = BootTrust.hash("trusted stage0 and IPE policy"),
    };
    try trust.verify(trust.entry, "trusted kernel", "trusted stage0 and IPE policy");
    try testing.expectError(
        error.BootFilesChanged,
        trust.verify(trust.entry, "other kernel", "trusted stage0 and IPE policy"),
    );
    try testing.expectError(
        error.BootFilesChanged,
        trust.verify(trust.entry, "trusted kernel", "other stage0 or IPE policy"),
    );
    try testing.expectError(
        error.BootFilesChanged,
        trust.verify(
            "linux /kernel\ninitrd /initrd\noptions ipe.enforce=0\n",
            "trusted kernel",
            "trusted stage0 and IPE policy",
        ),
    );
    var future = trust;
    future.version = 2;
    try testing.expectError(
        error.BootFilesChanged,
        future.verify(trust.entry, "trusted kernel", "trusted stage0 and IPE policy"),
    );
}

test net {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const n = try net(arena.allocator(), "edge");
    try testing.expect(n.tap.len == 10 and mem.startsWith(u8, n.tap, "fc"));
    try testing.expect(mem.startsWith(u8, n.mac, "06:00:") and n.mac.len == 17);
    try testing.expect(mem.startsWith(u8, n.host, "172.16."));
    try testing.expect(mem.endsWith(u8, n.subnet, "/30"));
    const again = try net(arena.allocator(), "edge");
    try testing.expectEqualStrings(n.guest, again.guest);
    try testing.expect(!mem.eql(u8, n.tap, (try net(arena.allocator(), "router")).tap));
}

test iptables {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const n = try net(arena.allocator(), "edge");
    const r = try rules(arena.allocator(), n);
    const nat = try iptables(arena.allocator(), "-C", r[0]);
    try testing.expectEqualStrings("-t", nat[1]);
    try testing.expectEqualStrings("POSTROUTING", nat[4]);
    try testing.expectEqualStrings(n.guest, nat[6]);
    const fwd = try iptables(arena.allocator(), "-A", r[1]);
    try testing.expectEqualStrings("INPUT", fwd[2]);
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
    const args = try mem.join(gpa, " ", try bootArgs(gpa, n, "9.9.9.9"));
    try testing.expect(mem.startsWith(u8, args, "reboot=k werewolf.ip=172.16."));
    try testing.expect(mem.find(u8, args, "/30 werewolf.gw=172.16.") != null);
    try testing.expect(mem.endsWith(u8, args, " werewolf.dns=9.9.9.9"));
    const c = try config(
        gpa,
        "/m/kernel",
        "/m/stage0.zst",
        args,
        "/m/disk.img",
        "/m/config.tar",
        null,
        "/m/firecracker.log",
        n,
    );
    try testing.expect(mem.find(u8, c, "\"kernel_image_path\": \"/m/kernel\"") != null);
    try testing.expect(mem.find(u8, c, "\"log_path\": \"/m/firecracker.log\"") != null);
    const disk = mem.find(u8, c, "\"/m/disk.img\"").?;
    const tar = mem.find(u8, c, "\"/m/config.tar\"").?;
    try testing.expect(disk < tar);
    const brought = try config(
        gpa,
        "/m/kernel",
        "/m/stage0.zst",
        args,
        "/m/disk.img",
        "/m/config.tar",
        "/m/import.img",
        "/m/firecracker.log",
        n,
    );
    const imported = mem.find(u8, brought, "\"/m/import.img\"").?;
    try testing.expect(mem.find(u8, brought, "\"/m/config.tar\"").? < imported);
    try testing.expect(mem.find(u8, c, "\"is_read_only\": false") != null);
    try testing.expect(mem.find(u8, c, n.tap) != null);
    const mib = std.fmt.comptimePrint("\"mem_size_mib\": {d}", .{howl.local_mib});
    try testing.expect(mem.find(u8, c, mib) != null);
}

test added {
    try testing.expect(added("pci=off"));
    try testing.expect(added("earlycon=uart,mmio,0x40002000"));
    try testing.expect(added("virtio_mmio.device=4K@0xd0000000:5"));
    try testing.expect(!added("reboot=k"));
    try testing.expect(!added("werewolf.slot=a"));
}

test "Entry.parse" {
    const e: Entry = .parse("werewolf-b+1.conf",
        \\title werewolf b
        \\sort-key werewolf
        \\version 20261010T120000Z
        \\linux /werewolf/b/vmlinuz
        \\initrd  /werewolf/b/stage0.zst
        \\options console=ttyS0,115200 werewolf.slot=b
        \\
    );
    try testing.expectEqualStrings("20261010T120000Z", e.version);
    try testing.expectEqualStrings("/werewolf/b/vmlinuz", e.linux);
    try testing.expectEqualStrings("/werewolf/b/stage0.zst", e.initrd);
    try testing.expectEqualStrings("console=ttyS0,115200 werewolf.slot=b", e.options);
    // An EFI entry must not silently fall back to unsigned direct boot,
    // even when an attacker appends linux and initrd lines.
    const signed: Entry = .parse("werewolf-a.conf",
        \\efi /werewolf/a/uki.efi
        \\linux /untrusted/kernel
        \\initrd /untrusted/initrd
        \\
    );
    try testing.expect(signed.efi);
    try testing.expectError(error.FirmwareRequired, signed.direct());
    const blank: Entry = .parse("werewolf-a.conf",
        \\efi /werewolf/a/uki.efi
        \\linux /untrusted/kernel
        \\initrd /untrusted/initrd
        \\efi
        \\
    );
    try testing.expectError(error.FirmwareRequired, blank.direct());
    try testing.expectError(error.FirmwareRequired, Entry.parse("bare.conf",
        \\efi
        \\linux /untrusted/kernel
        \\initrd /untrusted/initrd
        \\
    ).direct());
    inline for (.{ "uki", "uki-url" }) |directive| {
        try testing.expectError(error.FirmwareRequired, Entry.parse(
            "untrusted.conf",
            directive ++
                " /werewolf/a/uki.efi\nlinux /untrusted/kernel\ninitrd /untrusted/initrd\n",
        ).direct());
        try testing.expectError(error.FirmwareRequired, Entry.parse(
            "bare.conf",
            directive ++ "\nlinux /untrusted/kernel\ninitrd /untrusted/initrd\n",
        ).direct());
    }
    try e.direct();
    try testing.expectError(error.IncompleteEntry, (Entry{ .name = "empty.conf" }).direct());
}

test "Entry.tries" {
    const gpa = testing.allocator;
    try testing.expectEqual(null, (Entry{ .name = "werewolf-a.conf" }).tries());
    try testing.expectEqual(null, try (Entry{ .name = "werewolf-a.conf" }).spent(gpa));
    const fresh: Entry = .{ .name = "werewolf-b+1.conf" };
    try testing.expectEqual(Entry.Tries{ .left = 1, .done = 0 }, fresh.tries().?);
    const name = (try fresh.spent(gpa)).?;
    defer gpa.free(name);
    try testing.expectEqualStrings("werewolf-b+0-1.conf", name);
    const out: Entry = .{ .name = name };
    try testing.expectEqual(Entry.Tries{ .left = 0, .done = 1 }, out.tries().?);
    try testing.expectEqual(null, try out.spent(gpa));
    try testing.expectEqual(null, (Entry{ .name = "werewolf-b+x.conf" }).tries());
    try testing.expectEqual(null, (Entry{ .name = "werewolf-b+1-.conf" }).tries());
}

test "Entry.before" {
    const a: Entry = .{ .name = "werewolf-a.conf", .version = "19800101T000000Z" };
    const b: Entry = .{ .name = "werewolf-b+1.conf", .version = "20261010T120000Z" };
    const b_out: Entry = .{ .name = "werewolf-b+0-1.conf", .version = "20261010T120000Z" };
    const b_good: Entry = .{ .name = "werewolf-b.conf", .version = "20261010T120000Z" };
    // The update boots first, once; out of tries, the old slot does.
    try testing.expect(b.before(a) and !a.before(b));
    try testing.expect(a.before(b_out) and !b_out.before(a));
    try testing.expect(b_good.before(a));
    try testing.expect(!a.before(a));
}
