//! bhyve runs a machine as a bhyve VM on FreeBSD x86_64 or arm64 (experimental),
//! under a supervisor that restarts bhyve on reboot. See README.md.

const std = @import("std");
const builtin = @import("builtin");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub const firmware = firmwareFor(builtin.cpu.arch);
pub const firmware_package = if (builtin.cpu.arch == .aarch64)
    "u-boot-bhyve-arm64"
else
    "bhyve-firmware";

fn firmwareFor(arch: std.Target.Cpu.Arch) []const u8 {
    return if (arch == .aarch64)
        "/usr/local/share/u-boot/u-boot-bhyve-arm64/u-boot.bin"
    else
        "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd";
}

/// Resolve overrides before privilege elevation; the supervisor retains the
/// resolved arguments across guest reboots. Never fall back after an override fails.
pub const Runtime = struct {
    binary: []const u8 = "bhyve",
    arm64_firmware: ?[]const u8 = null,

    pub fn fromEnvironment(env: *const std.process.Environ.Map) !Runtime {
        const runtime: Runtime = .{
            .binary = env.get("BHYVE_BINARY") orelse "bhyve",
            .arm64_firmware = env.get("BHYVE_ARM64_FIRMWARE"),
        };
        if (env.get("BHYVE_BINARY")) |path| try validatePath(path);
        if (runtime.arm64_firmware) |path| try validatePath(path);
        return runtime;
    }

    fn validatePath(path: []const u8) !void {
        if (!std.mem.startsWith(u8, path, "/") or
            std.mem.findAny(u8, path, ",\r\n\x00") != null) return error.BadBhyvePath;
    }

    pub fn firmwarePath(runtime: Runtime, arch: std.Target.Cpu.Arch) []const u8 {
        return if (arch == .aarch64)
            runtime.arm64_firmware orelse firmwareFor(arch)
        else
            firmwareFor(arch);
    }
};
/// user_ip, user_gw and user_dns are slirp's fixed guest network, written
/// into the config tar for a form with no DHCP client.
pub const user_ip = "10.0.2.15/24";
pub const user_gw = "10.0.2.2";
pub const user_dns = "10.0.2.3";

pub const Mode = enum { tap, slirp };
pub const Backend = union(Mode) { tap: []const u8, slirp: []const Forward };
pub const Network = struct {
    mode: Mode = .tap,
    tap: ?[]const u8 = null,
    bridge: ?[]const u8 = null,
    owner: ?[]const u8 = null,

    pub fn backend(n: Network, fwds: []const Forward) Backend {
        return if (n.mode == .slirp) .{ .slirp = fwds } else .{ .tap = n.tap.? };
    }
};

/// TAP is the default; never silently fall back to SLIRP after setup fails.
pub fn prepareNetwork(
    io: Io,
    gpa: Allocator,
    at: []const u8,
    mode: Mode,
    bridge: ?[]const u8,
    why: *howl.Why,
) !Network {
    if (mode == .slirp) {
        howl.say(io, "warning: bhyve's outbound SLIRP helper runs as nobody outside Capsicum; " ++
            "a helper exploit could access host files and network services available to that " ++
            "account. " ++
            "The bhyve VMM remains sandboxed; TAP avoids this helper", .{});
        try downNetwork(io, gpa, at, null);
        return .{ .mode = .slirp };
    }
    var host = io;
    var said: howl.Why = .{};
    const r = up: {
        var taps = Taps.open(io, gpa, hostIfconfig(&host), at, &said) catch |err| break :up err;
        defer taps.close();
        break :up taps.up(bridge);
    } catch |err| return why.refuse(
        "TAP setup failed: {s}",
        .{if (err == error.Refused) said.text else @errorName(err)},
    );
    return .{ .mode = .tap, .tap = r.tap, .bridge = r.bridge, .owner = r.owner };
}

/// An old supervisor may remove only the TAP it started, not its successor's.
pub fn downNetwork(io: Io, gpa: Allocator, at: []const u8, owner: ?[]const u8) !void {
    Dir.cwd().access(
        io,
        try gpa.print("{s}/bhyve-network.json", .{at}),
        .{},
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    var host = io;
    var said: howl.Why = .{};
    const done = down: {
        var taps = Taps.open(io, gpa, hostIfconfig(&host), at, &said) catch |err| break :down err;
        defer taps.close();
        break :down taps.down(owner);
    };
    done catch |err| {
        howl.say(io, "TAP cleanup failed: {s}", .{
            if (err == error.Refused) said.text else @errorName(err),
        });
        return error.BhyveNetworkCleanupFailed;
    };
}

/// Ifconfig runs ifconfig with args. A change alters the host's network;
/// with missing, an interface that does not exist is null, not a refusal.
const Ifconfig = struct {
    context: *anyopaque,
    run: *const fn (
        context: *anyopaque,
        gpa: Allocator,
        args: []const []const u8,
        change: bool,
        missing: bool,
        why: *howl.Why,
    ) anyerror!?[]const u8,
};

fn hostIfconfig(io: *Io) Ifconfig {
    return .{ .context = io, .run = runIfconfig };
}

/// runIfconfig runs /sbin/ifconfig, a change as root through doas or sudo.
fn runIfconfig(
    context: *anyopaque,
    gpa: Allocator,
    args: []const []const u8,
    change: bool,
    missing: bool,
    why: *howl.Why,
) !?[]const u8 {
    const io: *const Io = @ptrCast(@alignCast(context));
    const root: []const []const u8 = if (change)
        asRoot(io.*) catch return why.refuse("TAP setup needs root, doas or sudo", .{})
    else
        &.{};
    const result = try std.process.run(gpa, io.*, .{
        .argv = try std.mem.concat(gpa, []const u8, &.{ root, &.{"/sbin/ifconfig"}, args }),
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(8192),
    });
    if (result.term == .exited and result.term.exited == 0) return result.stdout;
    if (missing and std.mem.find(u8, result.stderr, "does not exist") != null) return null;
    const said = std.mem.trim(u8, result.stderr, &std.ascii.whitespace);
    return why.refuse("{s}", .{if (said.len == 0) "ifconfig failed" else said});
}

/// Record is bhyve-network.json: the TAP howl made for one machine, the
/// bridge it joined, and the owner token in the TAP's description.
const Record = struct {
    mode: []const u8,
    tap: []const u8,
    bridge: []const u8,
    owner: []const u8,
};

/// Taps owns one machine directory's TAP on an existing bridge, holding
/// its lock; it never creates a bridge or reconfigures the host network.
const Taps = struct {
    io: Io,
    gpa: Allocator,
    ifconfig: Ifconfig,
    why: *howl.Why,
    dir: []const u8,
    /// prefix begins every owner token for dir: another directory's TAPs
    /// are never this one's.
    prefix: []const u8,
    guard: Io.File,

    fn open(io: Io, gpa: Allocator, ifconfig: Ifconfig, at: []const u8, why: *howl.Why) !Taps {
        const dir = try Dir.cwd().realPathFileAlloc(io, at, gpa);
        const guard = try Dir.cwd().createFile(io, try gpa.print(
            "{s}/bhyve-network.lock",
            .{dir},
        ), .{
            .truncate = false,
            .permissions = .fromMode(0o600),
        });
        errdefer guard.close(io);
        try guard.lock(io, .exclusive);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(dir, &digest, .{});
        return .{
            .io = io,
            .gpa = gpa,
            .ifconfig = ifconfig,
            .why = why,
            .dir = dir,
            .prefix = try gpa.print("howl:{s}:", .{std.fmt.bytesToHex(digest, .lower)[0..20]}),
            .guard = guard,
        };
    }

    fn close(t: *Taps) void {
        t.guard.unlock(t.io);
        t.guard.close(t.io);
    }

    fn ask(t: *const Taps, change: bool, args: []const []const u8) ![]const u8 {
        return (try t.ifconfig.run(t.ifconfig.context, t.gpa, args, change, false, t.why)).?;
    }

    /// probe is the interface's ifconfig output, or null if it does not exist.
    fn probe(t: *const Taps, name: []const u8) !?[]const u8 {
        return t.ifconfig.run(t.ifconfig.context, t.gpa, &.{name}, false, true, t.why);
    }

    fn path(t: *const Taps) ![]const u8 {
        return t.gpa.print("{s}/bhyve-network.json", .{t.dir});
    }

    fn load(t: *const Taps) !?Record {
        const text = Dir.cwd().readFileAlloc(t.io, try t.path(), t.gpa, .limited(8192)) catch |err|
            switch (err) {
                error.FileNotFound => return null,
                else => return err,
            };
        const r = std.json.parseFromSliceLeaky(Record, t.gpa, text, .{}) catch return t.invalid();
        const token = std.mem.cutPrefix(u8, r.owner, t.prefix) orelse return t.invalid();
        if (!std.mem.eql(u8, r.mode, "tap") or !isTap(r.tap) or !interface(r.bridge) or
            token.len != 32) return t.invalid();
        for (token) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return t.invalid();
        return r;
    }

    fn invalid(t: *const Taps) error{Refused} {
        return t.why.refuse(
            "invalid bhyve TAP ownership record; inspect it before changing networking",
            .{},
        );
    }

    /// bridge is wanted if it is an existing bridge, else the one bridge.
    fn bridge(t: *const Taps, wanted: ?[]const u8) ![]const u8 {
        var names = std.mem.tokenizeAny(
            u8,
            try t.ask(false, &.{ "-g", "bridge" }),
            &std.ascii.whitespace,
        );
        if (wanted) |w| {
            while (names.next()) |name| if (interface(w) and std.mem.eql(u8, name, w)) return w;
            return t.why.refuse("not an existing bridge: {s}", .{w});
        }
        const only = names.next();
        if (only == null or names.next() != null) return t.why.refuse(
            "TAP needs one existing bridge; choose --bridge NAME, or use --network slirp " ++
                "(no bridge is created automatically)",
            .{},
        );
        return only.?;
    }

    /// down destroys the recorded TAP and forgets it, unless expected names
    /// another owner. It refuses a TAP that is not this machine's.
    fn down(t: *const Taps, expected: ?[]const u8) !void {
        const r = try t.load() orelse return;
        if (expected) |owner| if (!std.mem.eql(u8, owner, r.owner)) return;
        if (try t.probe(r.tap)) |current| {
            if (!std.mem.eql(u8, description(current) orelse "", r.owner))
                return t.why.refuse("{s}: not this VM's TAP; leaving it untouched", .{r.tap});
            _ = try t.ask(true, &.{ r.tap, "destroy" });
        }
        Dir.cwd().deleteFile(t.io, try t.path()) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }

    /// up joins this machine's TAP to the bridge: the recorded one again if
    /// it is still there, else a new one whose description is a new owner.
    fn up(t: *const Taps, wanted: ?[]const u8) !Record {
        const selected = try t.bridge(wanted);
        if (try t.load()) |previous| {
            const current = try t.probe(previous.tap);
            if (current) |text| if (!std.mem.eql(u8, description(text) orelse "", previous.owner))
                return t.why.refuse(
                    "{s}: not this VM's TAP; leaving it untouched",
                    .{previous.tap},
                );
            if (current != null and std.mem.eql(u8, selected, previous.bridge)) {
                // An operator may have detached it, or taken it down.
                if (!member(try t.ask(false, &.{selected}), previous.tap))
                    _ = try t.ask(true, &.{ selected, "addm", previous.tap });
                _ = try t.ask(true, &.{ previous.tap, "up" });
                return previous;
            }
            try t.down(null);
        }
        const tap = std.mem.trim(u8, try t.ask(true, &.{ "tap", "create" }), &std.ascii.whitespace);
        if (!isTap(tap)) return t.why.refuse(
            "ifconfig returned an unexpected new TAP name: {s}",
            .{tap},
        );
        // This call made the TAP, so a failure destroys it; no other is touched.
        errdefer {
            var ignored: howl.Why = .{};
            _ = t.ifconfig.run(
                t.ifconfig.context,
                t.gpa,
                &.{ tap, "destroy" },
                true,
                false,
                &ignored,
            ) catch null;
        }
        var token: [16]u8 = undefined;
        try t.io.randomSecure(&token);
        const r: Record = .{
            .mode = "tap",
            .tap = tap,
            .bridge = selected,
            .owner = try t.gpa.print("{s}{s}", .{ t.prefix, &std.fmt.bytesToHex(token, .lower) }),
        };
        _ = try t.ask(true, &.{ tap, "description", r.owner, "up" });
        _ = try t.ask(true, &.{ selected, "addm", tap });
        try t.save(r);
        return r;
    }

    /// save writes the record durably, mode 0600, replacing any before it.
    fn save(t: *const Taps, r: Record) !void {
        var nonce: [8]u8 = undefined;
        try t.io.randomSecure(&nonce);
        const temporary = try t.gpa.print("{s}/.bhyve-network-{x}", .{ t.dir, &nonce });
        defer Dir.cwd().deleteFile(t.io, temporary) catch {};
        {
            const out = try Dir.cwd().createFile(t.io, temporary, .{
                .exclusive = true,
                .permissions = .fromMode(0o600),
            });
            defer out.close(t.io);
            try out.writeStreamingAll(t.io, try std.json.Stringify.valueAlloc(t.gpa, r, .{}));
            try out.sync(t.io);
        }
        try Dir.rename(Dir.cwd(), temporary, Dir.cwd(), try t.path(), t.io);
    }
};

/// interface is a name ifconfig takes as one interface and no option.
fn interface(name: []const u8) bool {
    if (name.len == 0 or name.len > 15 or !std.ascii.isAlphabetic(name[0])) return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, "_.-", c) == null)
        return false;
    return true;
}

fn isTap(name: []const u8) bool {
    const number = std.mem.cutPrefix(u8, name, "tap") orelse return false;
    if (number.len == 0) return false;
    for (number) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

fn description(text: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line|
        if (std.mem.cutPrefix(
            u8,
            std.mem.trim(u8, line, &std.ascii.whitespace),
            "description: ",
        )) |d|
            return d;
    return null;
}

/// member reports whether a bridge's ifconfig output lists name.
fn member(text: []const u8, name: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, &std.ascii.whitespace);
        if (!std.mem.eql(u8, words.next() orelse continue, "member:")) continue;
        if (std.mem.eql(u8, words.next() orelse continue, name)) return true;
    }
    return false;
}

fn networkOwner(io: Io, gpa: Allocator, at: []const u8) !?[]const u8 {
    const text = Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/bhyve-network.json", .{at}),
        gpa,
        .limited(8192),
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    return (try std.json.parseFromSliceLeaky(Network, gpa, text, .{})).owner;
}

pub fn staticAddress(gpa: Allocator, tar: []const u8) !?[]const u8 {
    var reader: Io.Reader = .fixed(tar);
    var names: [Dir.max_path_bytes]u8 = undefined;
    var links: [Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(
        &reader,
        .{ .file_name_buffer = &names, .link_name_buffer = &links },
    );
    while (try it.next()) |entry| if (std.mem.eql(u8, entry.name, "network")) {
        if (entry.kind != .file or reader.seek > tar.len or entry.size > tar.len - reader.seek)
            return error.BadNetwork;
        var reason: []const u8 = "";
        const n = @import("network").parse(
            tar[reader.seek..][0..@intCast(entry.size)],
            &reason,
        ) orelse return error.BadNetwork;
        return try gpa.dupe(u8, n.ip[0..std.mem.findScalar(u8, n.ip, '/').?]);
    };
    return null;
}

/// Read only this boot's DHCP announcements, never a previous lease.
pub fn awaitAddress(io: Io, gpa: Allocator, log: []const u8, seen: u64) !?[]const u8 {
    const buf = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(buf);
    for (0..600) |_| {
        if (Dir.cwd().openFile(io, log, .{})) |file| {
            defer file.close(io);
            const n = try file.readPositionalAll(io, buf, seen);
            if (@import("proxmox.zig").address(buf[0..n])) |ip| return try gpa.dupe(u8, ip);
        } else |_| {}
        try io.sleep(.fromMilliseconds(50), .awake);
    }
    return null;
}

/// installed reports whether this is a supported FreeBSD host with vmm loaded.
pub fn installed(io: Io) bool {
    if (builtin.os.tag != .freebsd or
        (builtin.cpu.arch != .x86_64 and builtin.cpu.arch != .aarch64)) return false;
    Dir.cwd().access(io, "/dev/vmmctl", .{}) catch return false;
    return true;
}

/// exists reports whether bhyve has a VM named name. A VM exists from its
/// first run until bhyvectl --destroy.
pub fn exists(io: Io, gpa: Allocator, name: []const u8) !bool {
    Dir.cwd().access(io, try gpa.print("/dev/vmm/{s}", .{name}), .{}) catch return false;
    return true;
}

/// asRoot returns the command prefix that runs bhyve as root: none when
/// already root, else doas or sudo from /usr/local/bin. It fails with
/// error.NoRoot if neither is installed.
pub fn asRoot(io: Io) error{NoRoot}![]const []const u8 {
    if (howl.isRoot()) return &.{};
    inline for (.{ "doas", "sudo" }) |tool| {
        if (Dir.cwd().access(io, "/usr/local/bin/" ++ tool, .{})) |_| return &.{tool} else |_| {}
    }
    return error.NoRoot;
}

/// Forward is a port slirp forwards from 127.0.0.1:host to guest.
pub const Forward = struct { host: u16, guest: u16 };

/// forwards maps up to 100 guest ports to consecutive host ports from a
/// base that name's sha256 picks (20000 to 59900, by hundreds). A name
/// always gets the same ports, and two names rarely collide.
pub fn forwards(gpa: Allocator, name: []const u8, ports: []const u16) ![]const Forward {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(name, &h, .{});
    const base: u16 = 20000 + (std.mem.readInt(u16, h[0..2], .big) % 400) * 100;
    const out = try gpa.alloc(Forward, @min(ports.len, 100));
    for (out, ports[0..out.len], 0..) |*f, p, i| f.* = .{
        .host = base + @as(u16, @intCast(i)),
        .guest = p,
    };
    return out;
}

/// argv returns bhyve's command line: the disk and a read-only config tar
/// on virtio, TAP or explicitly selected SLIRP, an RNG, the serial console
/// on stdout, and UEFI firmware. slirp is "open" so updates can reach out, and so that
/// FreeBSD 15.1's slirp helper skips capability mode, where, as root,
/// getpwnam(nobody) fails and the helper dies, killing bhyve with SIGPIPE.
/// -w: Linux reads MSRs bhyve lacks. -H: yield the CPU when idle. -u: UTC
/// clock. No -A: FreeBSD 15 always builds ACPI tables and dropped the flag.
pub fn argv(
    gpa: Allocator,
    name: []const u8,
    disk: []const u8,
    config: []const u8,
    net: Backend,
    import_disk: ?[]const u8,
) ![]const []const u8 {
    return command(gpa, name, disk, config, net, import_disk, null);
}

pub const Protection = struct {
    code: []const u8,
    vars: []const u8,
    tpm_socket: []const u8,
};

pub fn command(
    gpa: Allocator,
    name: []const u8,
    disk: []const u8,
    config: []const u8,
    backend: Backend,
    import_disk: ?[]const u8,
    protection: ?Protection,
) ![]const []const u8 {
    return commandFor(builtin.cpu.arch, gpa, name, disk, config, backend, import_disk, protection);
}

pub fn commandWith(
    gpa: Allocator,
    name: []const u8,
    disk: []const u8,
    config: []const u8,
    backend: Backend,
    import_disk: ?[]const u8,
    protection: ?Protection,
    runtime: Runtime,
) ![]const []const u8 {
    return commandForWith(
        builtin.cpu.arch,
        gpa,
        name,
        disk,
        config,
        backend,
        import_disk,
        protection,
        runtime,
    );
}

fn commandFor(
    arch: std.Target.Cpu.Arch,
    gpa: Allocator,
    name: []const u8,
    disk: []const u8,
    config: []const u8,
    backend: Backend,
    import_disk: ?[]const u8,
    protection: ?Protection,
) ![]const []const u8 {
    return commandForWith(arch, gpa, name, disk, config, backend, import_disk, protection, .{});
}

fn commandForWith(
    arch: std.Target.Cpu.Arch,
    gpa: Allocator,
    name: []const u8,
    disk: []const u8,
    config: []const u8,
    backend: Backend,
    import_disk: ?[]const u8,
    protection: ?Protection,
    runtime: Runtime,
) ![]const []const u8 {
    if (arch != .x86_64 and arch != .aarch64) return error.UnsupportedArchitecture;
    if (arch == .aarch64 and protection != null) return error.UnsupportedProtection;
    var net: std.ArrayList(u8) = .empty;
    switch (backend) {
        .tap => |tap| {
            if (tap.len < 4 or !std.mem.startsWith(u8, tap, "tap")) return error.BadTapName;
            for (tap[3..]) |c| if (!std.ascii.isDigit(c)) return error.BadTapName;
            try net.print(gpa, "virtio-net,{s}", .{tap});
        },
        .slirp => |fwds| {
            try net.appendSlice(gpa, "virtio-net,slirp,open");
            for (fwds, 0..) |f, i| try net.print(gpa, "{s}tcp:127.0.0.1:{d}-:{d}", .{
                if (i == 0) ",hostfwd=" else ";", f.host, f.guest,
            });
        },
    }
    var out: std.ArrayList([]const u8) = .empty;
    try out.append(gpa, runtime.binary);
    if (arch == .x86_64) try out.appendSlice(gpa, &.{ "-H", "-w", "-u" });
    try out.appendSlice(gpa, &.{
        "-c",
        std.fmt.comptimePrint("{d}", .{howl.local_cpus}),
        "-m",
        std.fmt.comptimePrint("{d}M", .{howl.local_mib}),
        "-s",
        "0,hostbridge",
    });
    if (arch == .x86_64) try out.appendSlice(gpa, &.{ "-s", "1,lpc" });
    try out.appendSlice(gpa, &.{
        "-s",
        try gpa.print("2,{s}", .{net.items}),
        "-s",
        try gpa.print("3,virtio-blk,{s}", .{disk}),
        "-s",
        try gpa.print("4,virtio-blk,{s},ro", .{config}),
        "-s",
        "5,virtio-rnd",
    });
    if (import_disk) |p| try out.appendSlice(gpa, &.{
        "-s",
        try gpa.print("6,virtio-blk,{s},ro", .{p}),
    });
    if (arch == .aarch64) {
        try out.appendSlice(gpa, &.{
            "-o", "console=stdio", "-o",
            try gpa.print(
                "bootrom={s}",
                .{runtime.firmwarePath(arch)},
            ),
        });
    } else if (protection) |p| {
        try out.appendSlice(gpa, &.{ "-l", "com1,stdio", "-l" });
        try out.append(gpa, try gpa.print("bootrom,{s},{s}", .{ p.code, p.vars }));
        // The TPM's ACPI table and event log are delivered through fw_cfg.
        try out.appendSlice(gpa, &.{
            "-o", "lpc.fwcfg=qemu",
            "-l", try gpa.print("tpm,swtpm,{s}", .{p.tpm_socket}),
        });
    } else try out.appendSlice(gpa, &.{
        "-l", "com1,stdio", "-l", try gpa.print("bootrom,{s}", .{firmwareFor(arch)}),
    });
    try out.append(gpa, name);
    return out.items;
}

/// destroy returns the bhyvectl command that destroys the VM name, which
/// also ends its bhyve and supervisor.
pub fn destroy(gpa: Allocator, name: []const u8) ![]const []const u8 {
    return try gpa.dupe(
        []const u8,
        &.{ "bhyvectl", try gpa.print("--vm={s}", .{name}), "--destroy" },
    );
}

/// keep is the supervisor, `howl _bhyve NAME CONFIG BHYVE...`, run as root
/// under daemon(8). bhyve's stdin is a pipe never written, so the console
/// reads nothing. On exit 0 (reboot) keep destroys the VM and runs bhyve
/// again while config exists; delete removes config to stop the loop. On
/// any other exit it destroys the VM and returns, except on 4: bhyve also
/// exits 4 when delete or another create destroyed the VM, and the VM of
/// that name may already be a new one.
pub fn keep(
    io: Io,
    gpa: Allocator,
    name: []const u8,
    config: []const u8,
    bhyve: []const []const u8,
) !void {
    return keepWith(io, gpa, name, config, bhyve, null);
}

/// Keep the TPM under the invoking user's custody, elevating only bhyve.
/// A new emulator on every boot resets PCRs while retaining enrolled NV.
pub fn keepProtected(
    io: Io,
    gpa: Allocator,
    name: []const u8,
    at: []const u8,
    bhyve: []const []const u8,
) !void {
    return keepWith(io, gpa, name, try gpa.print("{s}/config.tar", .{at}), bhyve, at);
}

/// prepareSupervisor creates the lifetime lock as the invoking user before
/// daemon elevates the supervisor. The root supervisor then opens the same
/// 0600 file, while later create and stop calls by that user can inspect it.
pub fn prepareSupervisor(io: Io, gpa: Allocator, at: []const u8) !void {
    const guard = try Dir.cwd().createFile(io, try gpa.print("{s}/bhyve.lock", .{at}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    guard.close(io);
}

fn keepWith(
    io: Io,
    gpa: Allocator,
    name: []const u8,
    config: []const u8,
    bhyve: []const []const u8,
    protected_at: ?[]const u8,
) !void {
    const at = std.fs.path.dirname(config) orelse return error.BadConfigPath;
    const guard = try Dir.cwd().createFile(io, try gpa.print("{s}/bhyve.lock", .{at}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer guard.close(io);
    if (!try guard.tryLock(io, .exclusive)) return error.BhyveAlreadyRunning;
    defer guard.unlock(io);
    defer if (protected_at) |secured| @import("local-secure.zig").stopTpmAt(
        io,
        gpa,
        secured,
    ) catch {};
    const owner = try networkOwner(io, gpa, at);
    defer if (owner) |token| downNetwork(io, gpa, at, token) catch {};
    // Host TPM/ACPI diagnostics can interrupt a serial line byte by byte.
    // Keep them separate so readiness and DHCP records remain readable.
    const diagnostics = try Dir.cwd().createFile(io, try gpa.print("{s}/bhyve.log", .{at}), .{
        .permissions = .fromMode(0o600),
    });
    defer diagnostics.close(io);
    while (true) {
        if (Dir.cwd().access(io, try gpa.print("{s}/bhyve.stop", .{at}), .{})) |_|
            return
        else |err| {
            if (err != error.FileNotFound) return err;
        }
        if (protected_at) |secured| try @import("local-secure.zig").restartTpmAt(io, gpa, secured);
        var child = try std.process.spawn(io, .{
            .argv = bhyve,
            .stdin = .pipe,
            .stdout = .inherit,
            .stderr = .{ .file = diagnostics },
        });
        const term = try child.wait(io);
        const code: u32 = if (term == .exited) term.exited else 4;
        howl.say(io, "{s}: bhyve exited {d}: {s}", .{ name, code, switch (code) {
            0 => "the guest asked to reboot",
            1 => "the guest powered off",
            2 => "the guest halted",
            3 => "triple fault",
            else => "an error, or the VM was destroyed",
        } });
        if (code == 4) return;
        const root = if (protected_at != null) try asRoot(io) else &.{};
        _ = std.process.run(gpa, io, .{
            .argv = try std.mem.concat(gpa, []const u8, &.{ root, try destroy(gpa, name) }),
        }) catch {};
        if (code != 0) return;
        Dir.cwd().access(io, config, .{}) catch return;
    }
}

test "protected bhyve keeps enrolled firmware and uses the TPM command socket" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const line = try std.mem.join(gpa, " ", try commandFor(.x86_64, gpa, "edge", "/m/disk.im" ++
        "g", "/m/config.tar", .{
        .tap = "tap7",
    }, null, .{
        .code = "/m/code.fd",
        .vars = "/m/vars.fd",
        .tpm_socket = "/private-tpm/data.sock",
    }));
    try testing.expect(std.mem.find(u8, line, "bootrom,/m/code.fd,/m/vars.fd") != null);
    try testing.expect(std.mem.find(u8, line, "-o lpc.fwcfg=qemu") != null);
    try testing.expect(std.mem.find(u8, line, "tpm,swtpm,/private-tpm/data.sock") != null);
    try testing.expect(std.mem.find(u8, line, firmwareFor(.x86_64)) == null);
}

pub fn supervised(io: Io, gpa: Allocator, at: []const u8) !bool {
    const guard = Dir.cwd().openFile(
        io,
        try gpa.print("{s}/bhyve.lock", .{at}),
        .{ .mode = .read_write },
    ) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer guard.close(io);
    if (try guard.tryLock(io, .exclusive)) {
        guard.unlock(io);
        return false;
    }
    return true;
}

/// Wait for the supervisor and its child before stopping TPM custody.
pub fn stop(io: Io, gpa: Allocator, name: []const u8, at: []const u8) !void {
    const owner = try networkOwner(io, gpa, at);
    const marker = try Dir.cwd().createFile(io, try gpa.print("{s}/bhyve.stop", .{at}), .{
        .permissions = .fromMode(0o600),
    });
    marker.close(io);
    const root = try asRoot(io);
    for (0..100) |_| {
        if (try exists(io, gpa, name)) {
            const result = try std.process.run(gpa, io, .{
                .argv = try std.mem.concat(gpa, []const u8, &.{ root, try destroy(gpa, name) }),
            });
            if (result.term != .exited or result.term.exited != 0) return error.BhyveStopFailed;
        }
        if (!try supervised(io, gpa, at)) {
            if (owner) |token| try downNetwork(io, gpa, at, token);
            return;
        }
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    return error.BhyveStopTimeout;
}

pub fn stopProtected(io: Io, gpa: Allocator, name: []const u8, at: []const u8) !void {
    try stop(io, gpa, name, at);
    try @import("local-secure.zig").stopTpmAt(io, gpa, at);
}

const testing = std.testing;

test "runtime overrides are explicit paths and preserve protection gates" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var env: std.process.Environ.Map = .init(gpa);
    try testing.expectEqualStrings("bhyve", (try Runtime.fromEnvironment(&env)).binary);
    for ([_][]const u8{ "relative", "", "/bad,option", "/bad\npath", "/bad\rpath" }) |bad| {
        try env.put("BHYVE_BINARY", bad);
        try testing.expectError(error.BadBhyvePath, Runtime.fromEnvironment(&env));
    }
    try env.put("BHYVE_BINARY", "/private build/bhyve");
    try env.put("BHYVE_ARM64_FIRMWARE", "relative");
    try testing.expectError(error.BadBhyvePath, Runtime.fromEnvironment(&env));
    try env.put("BHYVE_ARM64_FIRMWARE", "/private build/u-boot.bin");
    const runtime = try Runtime.fromEnvironment(&env);
    const args = try commandForWith(
        .aarch64,
        gpa,
        "test",
        "/disk",
        "/config",
        .{ .tap = "tap0" },
        null,
        null,
        runtime,
    );
    try testing.expectEqualStrings(runtime.binary, args[0]);
    const line = try std.mem.join(gpa, " ", args);
    try testing.expect(std.mem.find(u8, line, "bootrom=/private build/u-boot.bin") != null);
    try testing.expectEqualStrings(firmwareFor(.x86_64), runtime.firmwarePath(.x86_64));
    try testing.expectError(
        error.UnsupportedProtection,
        commandForWith(.aarch64, gpa, "test", "/disk", "/config", .{
            .tap = "tap0",
        }, null, .{
            .code = "/code",
            .vars = "/vars",
            .tpm_socket = "/tpm",
        }, runtime),
    );
}

test forwards {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const f = try forwards(gpa, "edge", &.{ 22, 443 });
    try testing.expectEqual(@as(usize, 2), f.len);
    try testing.expect(f[0].host >= 20000 and f[0].host <= 59900 and f[0].host % 100 == 0);
    try testing.expectEqual(f[0].host + 1, f[1].host);
    try testing.expectEqual(@as(u16, 443), f[1].guest);
    try testing.expectEqual(f[0].host, (try forwards(gpa, "edge", &.{22}))[0].host);
    try testing.expectEqual(@as(usize, 0), (try forwards(gpa, "edge", &.{})).len);
}

test argv {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const a = try commandFor(.x86_64, gpa, "edge", "/m/disk.img", "/m/config.tar", .{ .slirp = &.{
        .{ .host = 23400, .guest = 22 },
        .{ .host = 23401, .guest = 443 },
    } }, null, null);
    try testing.expectEqualStrings("bhyve", a[0]);
    try testing.expectEqualStrings("edge", a[a.len - 1]);
    try testing.expectEqualStrings(
        "2,virtio-net,slirp,open,hostfwd=tcp:127.0.0.1:23400-:22;tcp:127.0.0.1:23401-:443",
        a[13],
    );
    try testing.expectEqualStrings("4,virtio-blk,/m/config.tar,ro", a[17]);
    const brought = try commandFor(
        .x86_64,
        gpa,
        "edge",
        "/m/disk.img",
        "/m/config.tar",
        .{ .tap = "tap7" },
        "/m/import.img",
        null,
    );
    try testing.expectEqualStrings("2,virtio-net,tap7", brought[13]);
    try testing.expectEqualStrings("6,virtio-blk,/m/import.img,ro", brought[21]);
    const none = try commandFor(.x86_64, gpa, "m", "/d", "/c", .{ .slirp = &.{} }, null, null);
    try testing.expectEqualStrings("2,virtio-net,slirp,open", none[13]);
    const d = try destroy(gpa, "edge");
    try testing.expectEqualStrings("--vm=edge", d[1]);
}

test "arm64 bhyve uses U-Boot and no x86-only devices or options" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    for ([_]Backend{
        .{ .tap = "tap7" },
        .{ .slirp = &.{.{ .host = 23400, .guest = 22 }} },
    }) |net| {
        const args = try commandFor(.aarch64, gpa, "arm", "/d", "/c", net, "/i", null);
        const line = try std.mem.join(gpa, " ", args);
        for ([_][]const u8{ "-H", "-w", "-u", "-l", "1,lpc" }) |flag|
            for (args) |arg| try testing.expect(!std.mem.eql(u8, flag, arg));
        try testing.expect(std.mem.find(u8, line, "-o console=stdio -o bootrom=" ++
            "/usr/local/share/u-boot/u-boot-bhyve-arm64/u-boot.bin") != null);
        try testing.expect(std.mem.find(u8, line, "3,virtio-blk,/d") != null);
        try testing.expect(std.mem.find(u8, line, "4,virtio-blk,/c,ro") != null);
        try testing.expect(std.mem.find(u8, line, "6,virtio-blk,/i,ro") != null);
        try testing.expectEqualStrings("arm", args[args.len - 1]);
    }
    try testing.expectError(error.UnsupportedProtection, commandFor(
        .aarch64,
        gpa,
        "arm",
        "/d",
        "/c",
        .{ .tap = "tap7" },
        null,
        .{ .code = "/code", .vars = "/vars", .tpm_socket = "/tpm" },
    ));
}

test "bhyve TAP names cannot inject backend options" {
    for ([_][]const u8{ "", "tap", "tap1,slirp", "tap1;bad", "re0" }) |tap|
        try testing.expectError(
            error.BadTapName,
            argv(testing.allocator, "m", "/d", "/c", .{ .tap = tap }, null),
        );
    try testing.expectEqual(Mode.tap, (Network{}).mode);
}

test "bhyve TAP reads explicit static addresses, not SLIRP defaults" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const empty = try howl.writeTar(gpa, &.{});
    try testing.expectEqual(null, try staticAddress(gpa, empty));
    const tar = try howl.writeTar(gpa, &.{.{
        .path = "network",
        .data = "werewolf.ip=10.9.8.50/24 werewolf.gw=10.9.8.1\n",
        .from = "test",
    }});
    try testing.expectEqualStrings("10.9.8.50", (try staticAddress(gpa, tar)).?);
    const invalid = try howl.writeTar(
        gpa,
        &.{.{ .path = "network", .data = "werewolf.ip=not-an-ip", .from = "test" }},
    );
    try testing.expectError(error.BadNetwork, staticAddress(gpa, invalid));
}

/// FakeHost is a host's interfaces, bridges and members, which ifconfig
/// reads and changes; it records every call and whether it was a change.
const FakeHost = struct {
    gpa: Allocator,
    /// interfaces maps each interface to its description.
    interfaces: std.StringArrayHashMapUnmanaged(?[]const u8) = .empty,
    /// bridges maps each bridge to its members.
    bridges: std.StringArrayHashMapUnmanaged(std.StringArrayHashMapUnmanaged(void)) = .empty,
    calls: std.ArrayList(struct { args: []const u8, change: bool }) = .empty,
    fail_attach: bool = false,

    fn init(gpa: Allocator) !FakeHost {
        var f: FakeHost = .{ .gpa = gpa };
        try f.interfaces.put(gpa, "re0bridge", null);
        try f.bridges.put(gpa, "re0bridge", .empty);
        try f.bridges.getPtr("re0bridge").?.put(gpa, "re0", {});
        return f;
    }

    fn ifconfig(f: *FakeHost) Ifconfig {
        return .{ .context = f, .run = run };
    }

    fn members(f: *FakeHost, name: []const u8) []const []const u8 {
        return f.bridges.getPtr(name).?.keys();
    }

    fn changes(f: *const FakeHost) usize {
        var n: usize = 0;
        for (f.calls.items) |c| n += @intFromBool(c.change);
        return n;
    }

    fn count(f: *const FakeHost, line: []const u8) usize {
        var n: usize = 0;
        for (f.calls.items) |c| n += @intFromBool(std.mem.eql(u8, c.args, line));
        return n;
    }

    fn run(
        context: *anyopaque,
        gpa: Allocator,
        args: []const []const u8,
        change: bool,
        missing: bool,
        why: *howl.Why,
    ) !?[]const u8 {
        const f: *FakeHost = @ptrCast(@alignCast(context));
        const line = try std.mem.join(f.gpa, " ", args);
        try f.calls.append(f.gpa, .{ .args = line, .change = change });
        if (std.mem.eql(
            u8,
            line,
            "-g bridge",
        )) return try std.mem.join(gpa, "\n", f.bridges.keys());
        if (std.mem.eql(u8, line, "tap create")) {
            try testing.expect(!f.interfaces.contains("tap0"));
            try f.interfaces.put(f.gpa, "tap0", null);
            return "tap0\n";
        }
        const name = args[0];
        if (args.len == 1) {
            const known = f.interfaces.get(name) orelse
                return if (missing) null else why.refuse("missing interface", .{});
            var text: std.ArrayList(u8) = .empty;
            try text.print(gpa, "{s}: flags=UP\n", .{name});
            if (known) |d| try text.print(gpa, "\tdescription: {s}\n", .{d});
            if (f.bridges.getPtr(name)) |set| for (set.keys()) |m|
                try text.print(gpa, "\tmember: {s} flags=UP\n", .{m});
            return text.items;
        }
        if (std.mem.eql(u8, args[1], "description")) {
            try f.interfaces.put(f.gpa, name, try f.gpa.dupe(u8, args[2]));
        } else if (std.mem.eql(u8, args[1], "addm")) {
            if (f.fail_attach) return why.refuse("bridge attach failed", .{});
            const set = f.bridges.getPtr(name).?;
            try testing.expect(!set.contains(args[2]));
            try set.put(f.gpa, try f.gpa.dupe(u8, args[2]), {});
        } else if (std.mem.eql(u8, args[1], "destroy")) {
            try testing.expect(f.interfaces.orderedRemove(name));
            for (f.bridges.values()) |*set| _ = set.orderedRemove(name);
        } else if (!std.mem.eql(u8, args[1], "up")) {
            std.debug.print("unexpected network mutation: {s}\n", .{line});
            return error.UnexpectedMutation;
        }
        try testing.expect(change);
        return "";
    }
};

/// TapTest is one test's fake host and machine directory, whose TAP it owns.
const TapTest = struct {
    arena: std.heap.ArenaAllocator,
    tmp: testing.TmpDir,
    host: FakeHost,
    why: howl.Why = .{},
    taps: Taps,

    fn init(t: *TapTest) !void {
        t.arena = .init(testing.allocator);
        t.tmp = testing.tmpDir(.{});
        const gpa = t.arena.allocator();
        t.host = try .init(gpa);
        t.why = .{};
        const dir = try t.tmp.dir.realPathFileAlloc(testing.io, ".", gpa);
        t.taps = try .open(testing.io, gpa, t.host.ifconfig(), dir, &t.why);
    }

    fn deinit(t: *TapTest) void {
        t.taps.close();
        t.tmp.cleanup();
        t.arena.deinit();
    }

    fn refused(t: *TapTest, result: anytype, reason: []const u8) !void {
        try testing.expectError(error.Refused, result);
        try testing.expect(std.mem.find(u8, t.why.text, reason) != null);
    }

    fn write(t: *TapTest, text: []const u8) !void {
        try t.tmp.dir.writeFile(testing.io, .{ .sub_path = "bhyve-network.json", .data = text });
    }
};

fn expectRecord(want: Record, got: ?Record) !void {
    const g = got orelse return error.MissingRecord;
    inline for (.{ "mode", "tap", "bridge", "owner" }) |field|
        try testing.expectEqualStrings(@field(want, field), @field(g, field));
}

test "bhyve TAP: one existing bridge is selected and the owned TAP removed" {
    var t: TapTest = undefined;
    try t.init();
    defer t.deinit();
    const r = try t.taps.up(null);
    try testing.expectEqualStrings("re0bridge", r.bridge);
    try testing.expectEqualStrings("re0 tap0", try std.mem.join(
        t.arena.allocator(),
        " ",
        t.host.members("re0bridge"),
    ));
    try expectRecord(r, try t.taps.load());
    const st = try t.tmp.dir.statFile(testing.io, "bhyve-network.json", .{});
    try testing.expectEqual(0o600, st.permissions.toMode() & 0o777);
    try t.taps.down(r.owner);
    try testing.expectEqual(1, t.host.interfaces.count());
    try testing.expectEqual(null, t.host.interfaces.get("re0bridge").?);
    try testing.expectEqual(1, t.host.members("re0bridge").len);
    try testing.expectEqualStrings("re0", t.host.members("re0bridge")[0]);
    try testing.expectEqual(null, try t.taps.load());
}

test "bhyve TAP: reuse neither recreates the TAP nor adds an existing member" {
    var t: TapTest = undefined;
    try t.init();
    defer t.deinit();
    const r = try t.taps.up(null);
    try expectRecord(r, try t.taps.up(null));
    try testing.expectEqual(1, t.host.count("tap create"));
}

test "bhyve TAP: reuse restores a detached membership" {
    var t: TapTest = undefined;
    try t.init();
    defer t.deinit();
    const r = try t.taps.up(null);
    try testing.expect(t.host.bridges.getPtr("re0bridge").?.orderedRemove(r.tap));
    try expectRecord(r, try t.taps.up(null));
    try testing.expect(t.host.bridges.getPtr("re0bridge").?.contains(r.tap));
}

test "bhyve TAP: an ambiguous or absent bridge refuses before any change" {
    var t: TapTest = undefined;
    try t.init();
    defer t.deinit();
    const gpa = t.arena.allocator();
    for ([_][]const []const u8{ &.{}, &.{ "bridge0", "bridge1" } }) |names| {
        t.host.bridges = .empty;
        for (names) |name| try t.host.bridges.put(gpa, name, .empty);
        t.host.calls.clearRetainingCapacity();
        try t.refused(t.taps.up(null), "--bridge");
        try testing.expectEqual(0, t.host.changes());
    }
}

test "bhyve TAP: an explicit bridge resolves ambiguity; invalid names refuse" {
    var t: TapTest = undefined;
    try t.init();
    defer t.deinit();
    const gpa = t.arena.allocator();
    try t.host.interfaces.put(gpa, "bridge1", null);
    try t.host.bridges.put(gpa, "bridge1", .empty);
    try testing.expectEqualStrings("bridge1", (try t.taps.up("bridge1")).bridge);
    try t.taps.down(null);
    for ([_][]const u8{
        "missing",
        "-a",
        "re0bridge,slirp",
        "re0bridge;bad",
        &@as([16]u8, @splat('a')),
    }) |bad| {
        t.host.calls.clearRetainingCapacity();
        try t.refused(t.taps.up(bad), "not an existing bridge");
        try testing.expectEqual(0, t.host.changes());
    }
}

test "bhyve TAP: a failed attach rolls back only the new TAP" {
    var t: TapTest = undefined;
    try t.init();
    defer t.deinit();
    t.host.fail_attach = true;
    try t.refused(t.taps.up(null), "attach failed");
    try testing.expectEqual(1, t.host.interfaces.count());
    try testing.expect(t.host.interfaces.contains("re0bridge"));
    try testing.expectEqual(null, try t.taps.load());
}

test "bhyve TAP: a foreign interface is neither adopted nor destroyed" {
    var t: TapTest = undefined;
    try t.init();
    defer t.deinit();
    const r = try t.taps.up(null);
    try t.host.interfaces.put(t.arena.allocator(), r.tap, "another owner");
    try t.refused(t.taps.up(null), "not this VM");
    try t.refused(t.taps.down(null), "not this VM");
    try testing.expectEqualStrings("another owner", t.host.interfaces.get(r.tap).?.?);
    try testing.expect(try t.taps.load() != null);
}

test "bhyve TAP: an old supervisor cannot remove its successor's" {
    var t: TapTest = undefined;
    try t.init();
    defer t.deinit();
    const old = try t.taps.up(null);
    try t.taps.down(old.owner);
    const new = try t.taps.up(null);
    try testing.expect(!std.mem.eql(u8, old.owner, new.owner));
    try t.taps.down(old.owner);
    try expectRecord(new, try t.taps.load());
    try testing.expect(t.host.interfaces.contains(new.tap));
}

test "bhyve TAP: an interface missing after a reboot is safe" {
    var t: TapTest = undefined;
    try t.init();
    defer t.deinit();
    const r = try t.taps.up(null);
    _ = t.host.interfaces.orderedRemove(r.tap);
    _ = t.host.bridges.getPtr("re0bridge").?.orderedRemove(r.tap);
    const new = try t.taps.up(null);
    try testing.expect(!std.mem.eql(u8, r.owner, new.owner));
    _ = t.host.interfaces.orderedRemove(new.tap);
    try t.taps.down(null);
    try testing.expectEqual(null, try t.taps.load());
}

test "bhyve TAP: a malformed record or another directory's refuses" {
    var t: TapTest = undefined;
    try t.init();
    defer t.deinit();
    const gpa = t.arena.allocator();
    const r = try t.taps.up(null);
    for ([_][]const u8{
        "[]",
        try std.json.Stringify.valueAlloc(gpa, Record{
            .mode = r.mode,
            .tap = "re0",
            .bridge = r.bridge,
            .owner = r.owner,
        }, .{}),
        try std.json.Stringify.valueAlloc(gpa, Record{
            .mode = r.mode,
            .tap = r.tap,
            .bridge = r.bridge,
            .owner = "howl:other:00",
        }, .{}),
        try gpa.print(
            "{{\"mode\":\"tap\",\"tap\":\"{s}\",\"bridge\":null,\"owner\":\"{s}\"}}",
            .{ r.tap, r.owner },
        ),
    }) |bad| {
        try t.write(bad);
        try t.refused(t.taps.down(null), "invalid bhyve TAP ownership record");
    }
    try testing.expect(t.host.interfaces.contains("tap0"));
}
