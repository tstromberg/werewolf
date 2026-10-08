//! init: PID 1 from stage0 handing over until runit takes it.
//!
//! stage0 has mounted the form's root.erofs read-only at / and handed over:
//! nothing here or after can write the root, so what changes lives in /run,
//! /tmp, /var/tmp and /data. init only has to make the machine reachable:
//! filesystems, the kernel's settings, one address, the operator's keys,
//! /data. Then it hands over to fence, which sets the network policy and
//! becomes runit; /etc/runit/2 runs the services and /etc/runit/3 shuts down.
//!
//! Every form includes minimal, so this program is in every image. It must
//! not know which form it is in: it prepares the machine and starts runit,
//! and the services a form adds take care of themselves. It decides from
//! what the image carries (a DHCP client, mke2fs, cryptsetup) and what it
//! is told, instead.
//!
//! Everything it reads comes from two places, in this order:
//!
//!     kernel command line   werewolf.ip=CIDR werewolf.gw=ADDR werewolf.dns=ADDR
//!                             (without werewolf.ip, the address is DHCP's)
//!                           werewolf.mac=ADDR (which NIC, when there are several)
//!                           werewolf.data=DEV (/data on a disk: DEV, formatted once)
//!                           (werewolf.debug=1, a root shell on the console where
//!                             the form has one, is the debug-shell service's)
//!                           and, on a machine with slots:
//!                           werewolf.victim=UUID:DIR (the filesystem holding the
//!                             slots, config.tar and data/)
//!                           werewolf.grubenv=UUID:PATH (GRUB's environment block,
//!                             which the slot-keep service writes)
//!     config                one tar: config.tar in the victim's directory, or
//!                           else the first block device written with one;
//!                           never two, merged. It is extracted to /run/config,
//!                           by a confined child, for the services to read
//!                           (hostname and authorized_keys are applied here).
//!                           Beside it, a NoCloud volume labelled `cidata`, from
//!                           which the first user, its ssh keys and Lima's data
//!                           files beneath /run/config are taken, never in
//!                           place of the tar's, and without running
//!                           provisioning scripts. Failing both, the cloud's
//!                           metadata server.
//!
//! It runs no shell. What it cannot do itself it asks of werewolf's programs
//! (mount, modules, net, dhcp, cloud, fence) and of the filesystem tools the
//! form carries (blkid, mke2fs, e2fsck, cryptsetup), each by its full path.
//! A step that fails is said on the console and the boot goes on, as far as
//! it can; only failing to start fence ends it, which panics the kernel and
//! sends the machine back to its last good slot.

const std = @import("std");

const Io = std.Io;

const Dir = Io.Dir;

const Allocator = std.mem.Allocator;

const linux = std.os.linux;
const phase_kernel = @import("kernel.zig");
const phase_network = @import("network.zig");
const phase_config = @import("config.zig");
const phase_data = @import("data.zig");
const phase_seal = @import("seal.zig");
const instanceId = phase_config.instanceId;
const lockdownLevel = phase_kernel.lockdownLevel;
const sysctls = phase_kernel.sysctls;
const seal = phase_seal.seal;

pub const mount_bin = "/usr/lib/werewolf/mount";

const path_env = "/usr/sbin:/usr/bin:/sbin:/bin";

pub fn main(init: std.process.Init) !void {
    var m: Machine = .{
        .io = init.io,
        .gpa = init.arena.allocator(),
        .env = try init.environ_map.clone(init.arena.allocator()),
    };
    try m.env.put("PATH", path_env);
    // Where the boot's time goes: stage0's phases, then init's, each marked
    // as it ends. Taken out of the environment before anything is started;
    // the names point into a copy, since removing the variable frees it.
    var phases = Phases.parse(try m.gpa.dupe(u8, m.env.get("WEREWOLF_BOOT") orelse ""));
    _ = m.env.swapRemove("WEREWOLF_BOOT");

    // Nothing here may wait on a person. A tool that prompts (mke2fs does,
    // over an old signature) reads end of file instead of stalling the boot.
    const null_fd = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(null_fd) == .SUCCESS) _ = linux.dup2(@intCast(null_fd), 0);

    m.filesystems();
    m.seed();
    m.cmd = parseCmdline(m.read("/proc/cmdline"));
    phases.add("mounts", bootMs());
    m.kernel() catch {
        say("the kernel's protections are not all set; not handing over", .{});
        std.process.exit(1);
    };
    phases.add("sysctls", bootMs());
    // The config on the machine's disks first, since it may hold the
    // network; the cloud's, which comes over the network, after it.
    m.victim();
    phases.add("victim", bootMs());
    m.config();
    phases.add("config", bootMs());
    m.network();
    phases.add("network", bootMs());
    m.metadata();
    phases.add("metadata", bootMs());
    m.data();
    phases.add("data", bootMs());

    if (m.cmd.grubenv.len > 0) m.write(
        "/run/werewolf/grubenv",
        m.fmt("{s}\n", .{m.cmd.grubenv}),
        0o644,
    );

    // fence sets the network policy the build compiled from the forms,
    // binding only declared TCP ports and the metadata server only for those
    // named, then becomes runit, so every process inherits it. If it cannot,
    // PID 1 ends, and the machine falls back to the slot that last worked.
    // No core dumps, by anyone it starts: a crash leaves no copy of a
    // program's memory, and its secrets, behind. A hard limit, so no
    // process can raise its own.
    const no_core: linux.rlimit = .{ .cur = 0, .max = 0 };
    if (linux.errno(linux.setrlimit(
        .CORE,
        &no_core,
    )) != .SUCCESS) say("core dumps not limited", .{});
    // The seal fails closed, as fence does: PID 1 ends, the kernel panics,
    // and the machine comes back on the slot that last worked.
    seal(&m) catch |err| {
        say("not sealed: {s}; not handing over", .{@errorName(err)});
        std.process.exit(1);
    };
    // The mount broker (cmd/mount-broker), which mounts for the few that
    // must once fence's Landlock domain forbids mounting to everyone in
    // it: started here, so it is outside that domain, and after the seal,
    // so it is under it like every other process. It never exits; without
    // it nothing can keep this slot, so a machine whose broker would not
    // start falls back to the slot that last worked.
    if (std.process.spawn(m.io, .{
        .argv = &.{"/usr/lib/werewolf/mount-broker"},
        .environ_map = &m.env,
        .stdin = .ignore,
    })) |_| {} else |broker_err| say("no mount broker: {s}", .{@errorName(broker_err)});
    // The DHCP lease's renewal (cmd/dhcp-client), started here too, so it
    // keeps CAP_NET_ADMIN to apply a lease, and its packet socket, which
    // fence then takes from every process after it, root's included: no
    // form need keep either for DHCP. runit does not restart it; should it
    // end, the address it applied stays.
    if (m.dhcp) if (std.process.spawn(m.io, .{
        .argv = &.{ "/usr/lib/werewolf/dhcp-client", "keep" },
        .environ_map = &m.env,
        .stdin = .ignore,
    })) |_| {} else |dhcp_err| say("no DHCP renewal: {s}", .{@errorName(dhcp_err)});
    // The seal, and starting the broker and the renewal.
    phases.add("seal", bootMs());
    // How long the boot took, for the console and the demo's page: the
    // kernel's part, which stage0 measured, and userland's, stage0 and init,
    // phase by phase.
    const kernel_ms = phases.endOf("kernel");
    const up_ms = bootMs();
    const took = phases.durations(m.gpa);
    m.write(
        "/run/werewolf/boot",
        m.fmt("{s}\n", .{std.json.Stringify.valueAlloc(m.gpa, .{
            .kernel_ms = kernel_ms,
            .userland_ms = up_ms -| kernel_ms,
            .phases = took,
        }, .{}) catch ""}),
        0o644,
    );
    var line: Io.Writer.Allocating = .init(m.gpa);
    for (took, 0..) |p, i| line.writer.print("{s}{s} {d}.{d:0>3}s", .{
        if (i == 0) "" else ", ", p.name, p.ms / 1000, p.ms % 1000,
    }) catch {};
    say("phases: {s}", .{line.written()});
    // The boot is over, so the console takes the kernel's notices from
    // here on: what the kernel refuses (an exec, lockdown, Yama, Landlock)
    // it says at that level, which loglevel=5 kept off the console while
    // the boot's own notices would have cost a millisecond a line on a
    // cloud's serial port (Makefile, KERNEL_ARGS). dmesg has every one.
    if (!writeFile(
        "/proc/sys/kernel/printk",
        "6",
    )) say("console loglevel not raised: the kernel's refusals stay in dmesg", .{});
    say("up in {s}s (the kernel {s}s, userland {s}s), handing over to runit", .{
        m.fmt("{d}.{d:0>3}", .{ up_ms / 1000, up_ms % 1000 }),
        m.fmt("{d}.{d:0>3}", .{ kernel_ms / 1000, kernel_ms % 1000 }),
        m.fmt("{d}.{d:0>3}", .{ (up_ms -| kernel_ms) / 1000, (up_ms -| kernel_ms) % 1000 }),
    });
    const err = std.process.replace(
        m.io,
        .{ .argv = &.{ "/usr/lib/werewolf/fence", "/usr/bin/runit" }, .environ_map = &m.env },
    );
    say("cannot start fence: {s}", .{@errorName(err)});
    std.process.exit(1);
}

pub const Machine = struct {
    io: Io,
    gpa: Allocator,
    env: std.process.Environ.Map,
    cmd: Cmdline = .{},
    victim_dir: []const u8 = "",
    nocloud_user: []const u8 = "",
    /// Whether a config tar or a NoCloud seed was found on a disk, so the
    /// cloud's metadata server is not asked.
    configured: bool = false,
    /// Whether the address is DHCP's, for its renewal to be started.
    dhcp: bool = false,

    // Each phase is in a file of its own, and still m.phase() here.
    pub const filesystems = phase_kernel.filesystems;
    pub const cgroups = phase_kernel.cgroups;
    pub const seed = phase_kernel.seed;
    pub const kernel = phase_kernel.kernel;
    pub const network = phase_network.network;
    pub const staticNetwork = phase_network.staticNetwork;
    pub const routerAdvertisements = phase_network.routerAdvertisements;
    pub const pickNic = phase_network.pickNic;
    pub const victim = phase_config.victim;
    pub const config = phase_config.config;
    pub const metadata = phase_config.metadata;
    pub const nocloud = phase_config.nocloud;
    pub const limaConfig = phase_config.limaConfig;
    pub const keys = phase_config.keys;
    pub const extract = phase_config.extract;
    pub const extractChild = phase_config.extractChild;
    pub const sizeUp = phase_config.sizeUp;
    pub const writeOut = phase_config.writeOut;
    pub const data = phase_data.data;
    pub const dataHome = phase_data.dataHome;
    pub const nodata = phase_data.nodata;

    /// werewolf's mount, which says what went wrong itself; the boot goes on.
    pub fn mount(m: *Machine, args: []const []const u8) void {
        const argv = std.mem.concat(m.gpa, []const u8, &.{ &.{mount_bin}, args }) catch return;
        _ = m.run(argv);
    }

    pub fn run(m: *Machine, argv: []const []const u8) bool {
        return m.spawn(argv, false) == 0;
    }

    /// As run, with the program's own complaints silenced: for probes, whose
    /// failure is an answer.
    pub fn runQuiet(m: *Machine, argv: []const []const u8) bool {
        return m.spawn(argv, true) == 0;
    }

    pub fn exitCode(m: *Machine, argv: []const []const u8) u32 {
        return m.spawn(argv, true);
    }

    /// name's path in PATH, as the shell's command -v finds it. Programs
    /// run by their full path: spawn would resolve a bare name against
    /// init's own environment, and the kernel gives it no PATH.
    pub fn which(m: *Machine, name: []const u8) ?[:0]const u8 {
        var dirs = std.mem.tokenizeScalar(u8, path_env, ':');
        while (dirs.next()) |dir| {
            const path = m.fmtZ("{s}/{s}", .{ dir, name });
            if (executable(path)) return path;
        }
        return null;
    }

    /// argv's exit code, or 255 if it did not run or was killed.
    pub fn spawn(m: *Machine, argv: []const []const u8, quiet: bool) u32 {
        var child = std.process.spawn(m.io, .{
            .argv = argv,
            .environ_map = &m.env,
            .stdin = .ignore,
            .stdout = if (quiet) .ignore else .inherit,
            .stderr = if (quiet) .ignore else .inherit,
        }) catch return 255;
        const term = child.wait(m.io) catch return 255;
        return switch (term) {
            .exited => |code| code,
            else => 255,
        };
    }

    pub fn isMounted(m: *Machine, point: []const u8) bool {
        return m.mountSource(point) != null;
    }

    /// What is mounted on point, as the kernel's mount table names it, or
    /// null if nothing is.
    pub fn mountSource(m: *Machine, point: []const u8) ?[]const u8 {
        var it = std.mem.tokenizeScalar(u8, m.read("/proc/self/mounts"), '\n');
        while (it.next()) |line| {
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            const source = f.next() orelse continue;
            if (std.mem.eql(u8, f.next() orelse continue, point)) return source;
        }
        return null;
    }

    /// path, read to its end, or "" (procfs and sysfs report a size of 0).
    pub fn read(m: *Machine, path: []const u8) []const u8 {
        var f = Dir.cwd().openFile(m.io, path, .{}) catch return "";
        defer f.close(m.io);
        var buf: [4096]u8 = undefined;
        var r = f.readerStreaming(m.io, &buf);
        return r.interface.allocRemaining(m.gpa, .limited(1 << 20)) catch "";
    }

    /// text to path, with mode; a failure is said.
    pub fn write(m: *Machine, path: []const u8, text: []const u8, mode: u32) void {
        Dir.cwd().writeFile(
            m.io,
            .{ .sub_path = path, .data = text, .flags = .{ .permissions = .fromMode(mode) } },
        ) catch |err|
            return say("{s}: {s}", .{ path, @errorName(err) });
        _ = linux.fchmodat(linux.AT.FDCWD, m.z(path), mode);
    }

    pub fn append(m: *Machine, path: []const u8, text: []const u8) void {
        var f = Dir.cwd().openFile(
            m.io,
            path,
            .{ .mode = .write_only },
        ) catch |err| return say("{s}: {s}", .{ path, @errorName(err) });
        defer f.close(m.io);
        const end = f.length(m.io) catch return;
        f.writePositionalAll(
            m.io,
            text,
            end,
        ) catch |err| say("{s}: {s}", .{ path, @errorName(err) });
    }

    /// The names in dir, sorted, as the shell's glob gives them.
    pub fn list(m: *Machine, dir: []const u8) []const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        var d = Dir.cwd().openDir(m.io, dir, .{ .iterate = true }) catch return out.items;
        defer d.close(m.io);
        var it = d.iterate();
        while (it.next(m.io) catch null) |e| {
            if (e.name[0] == '.') continue;
            out.append(m.gpa, m.gpa.dupe(u8, e.name) catch continue) catch continue;
        }
        std.mem.sort([]const u8, out.items, {}, lessString);
        return out.items;
    }

    pub fn mkdirAll(m: *Machine, path: [:0]const u8) void {
        Dir.cwd().createDirPath(m.io, path) catch {};
        _ = linux.fchmodat(linux.AT.FDCWD, path, 0o700);
    }

    pub fn fmt(m: *Machine, comptime f: []const u8, args: anytype) []const u8 {
        return m.gpa.print(f, args) catch "";
    }

    pub fn fmtZ(m: *Machine, comptime f: []const u8, args: anytype) [:0]const u8 {
        return m.gpa.printSentinel(f, args, 0) catch "";
    }

    pub fn z(m: *Machine, s: []const u8) [:0]const u8 {
        return m.gpa.dupeSentinel(u8, s, 0) catch "";
    }
};

const Cmdline = struct {
    ip: []const u8 = "",
    gw: []const u8 = "",
    dns: []const u8 = "",
    mac: []const u8 = "",
    data: []const u8 = "",
    victim: []const u8 = "",
    grubenv: []const u8 = "",
    seal: []const u8 = "",
};

fn parseCmdline(text: []const u8) Cmdline {
    var c: Cmdline = .{};
    var it = std.mem.tokenizeAny(u8, text, " \t\n");
    while (it.next()) |arg| {
        inline for (@typeInfo(Cmdline).@"struct".field_names) |name| {
            const prefix = "werewolf." ++ name ++ "=";
            if (std.mem.startsWith(u8, arg, prefix)) @field(c, name) = arg[prefix.len..];
        }
    }
    return c;
}

pub fn lastField(s: []const u8) []const u8 {
    const t = std.mem.trimEnd(u8, s, " \t\r");
    const i = std.mem.lastIndexOfAny(u8, t, " \t") orelse return t;
    return t[i + 1 ..];
}

pub fn firstLine(s: []const u8) []const u8 {
    return s[0 .. std.mem.findScalar(u8, s, '\n') orelse s.len];
}

fn firstWord(s: []const u8) []const u8 {
    var it = std.mem.tokenizeAny(u8, s, " \n");
    return it.next() orelse "";
}

pub fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n");
}

pub fn orNone(s: []const u8) []const u8 {
    return if (s.len > 0) s else "none";
}

fn lessString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

pub fn mkdir(path: [:0]const u8, mode: u32) void {
    _ = linux.mkdir(path, mode);
}

pub fn exists(path: [:0]const u8) bool {
    return linux.errno(linux.access(path, linux.F_OK)) == .SUCCESS;
}

pub fn executable(path: [:0]const u8) bool {
    return linux.errno(linux.access(path, linux.X_OK)) == .SUCCESS;
}

pub fn isBlockDevice(path: [:0]const u8) bool {
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(
        linux.AT.FDCWD,
        path,
        0,
        .{ .TYPE = true },
        &st,
    )) != .SUCCESS) return false;
    return st.mode & linux.S.IFMT == linux.S.IFBLK;
}

pub fn writeFile(path: [:0]const u8, data: []const u8) bool {
    return writeErrno(path, data) == .SUCCESS;
}

/// writeFile, but returning why it failed, so a caller can tell a read-only
/// /proc/sys (a container) from a refusal that matters on real hardware.
pub fn writeErrno(path: [:0]const u8, data: []const u8) linux.E {
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return linux.errno(fd);
    defer _ = linux.close(@intCast(fd));
    const n = linux.write(@intCast(fd), data.ptr, data.len);
    if (linux.errno(n) != .SUCCESS) return linux.errno(n);
    return if (n == data.len) .SUCCESS else .IO;
}

pub fn say(comptime f: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "werewolf: " ++ f ++ "\n", args) catch return;
    _ = linux.write(1, line.ptr, line.len);
}

/// Where the boot's time went: each phase's name and when it ended, in
/// milliseconds of the boot clock. stage0 hands its own over as
/// WEREWOLF_BOOT, `kernel=225 modules=611 slot=838 root=851`; init adds
/// its own after them.
const Phases = struct {
    names: [max][]const u8 = undefined,
    ends: [max]u64 = undefined,
    len: usize = 0,

    const max = 16;
    const Took = struct { name: []const u8, ms: u64 };

    /// stage0's phases: each a name of lowercase letters and when it ended,
    /// none before the last. The first that is not stops the list.
    fn parse(text: []const u8) Phases {
        var p: Phases = .{};
        var it = std.mem.tokenizeScalar(u8, text, ' ');
        while (it.next()) |word| {
            const eq = std.mem.findScalar(u8, word, '=') orelse break;
            const name = word[0..eq];
            const end = std.fmt.parseInt(u64, word[eq + 1 ..], 10) catch break;
            if (name.len == 0 or name.len > 16) break;
            for (name) |c| if (c < 'a' or c > 'z') return p;
            if (p.len > 0 and end < p.ends[p.len - 1]) break;
            p.add(name, end);
        }
        return p;
    }

    /// A phase that ended at end; past max, nothing.
    fn add(p: *Phases, name: []const u8, end: u64) void {
        if (p.len == max) return;
        p.names[p.len] = name;
        p.ends[p.len] = end;
        p.len += 1;
    }

    /// When the phase name ended, or 0 if there was none.
    fn endOf(p: *const Phases, name: []const u8) u64 {
        for (p.names[0..p.len], p.ends[0..p.len]) |n, e| if (std.mem.eql(u8, n, name)) return e;
        return 0;
    }

    /// How long each phase took: from the end of the one before, or, for the
    /// first, from the boot clock's start.
    fn durations(p: *const Phases, gpa: Allocator) []const Took {
        const out = gpa.alloc(Took, p.len) catch return &.{};
        for (out, 0..) |*t, i| t.* = .{
            .name = p.names[i],
            .ms = p.ends[i] -| if (i == 0) 0 else p.ends[i - 1],
        };
        return out;
    }
};

const testing = std.testing;

test parseCmdline {
    const c = parseCmdline(
        "console=hvc0 werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.data=vda " ++
            "werewolf.victim=ab:/w werewolf.debug=1\n",
    );
    try testing.expectEqualStrings("10.0.2.15/24", c.ip);
    try testing.expectEqualStrings("10.0.2.2", c.gw);
    try testing.expectEqualStrings("vda", c.data);
    try testing.expectEqualStrings("ab:/w", c.victim);
    try testing.expectEqualStrings("", c.mac);
}

test Phases {
    var p = Phases.parse("kernel=225 modules=611 slot=838 root=851");
    p.add("mounts", 900);
    try testing.expectEqual(225, p.endOf("kernel"));
    try testing.expectEqual(0, p.endOf("absent"));
    const took = p.durations(testing.allocator);
    defer testing.allocator.free(took);
    try testing.expectEqual(5, took.len);
    try testing.expectEqualStrings("kernel", took[0].name);
    try testing.expectEqual(225, took[0].ms);
    try testing.expectEqual(386, took[1].ms);
    try testing.expectEqualStrings("mounts", took[4].name);
    try testing.expectEqual(49, took[4].ms);

    // A bad word ends the list; what came before it stays.
    try testing.expectEqual(1, Phases.parse("kernel=225 modules=100").len);
    try testing.expectEqual(1, Phases.parse("kernel=225 Bad=900 root=950").len);
    try testing.expectEqual(1, Phases.parse("kernel=225 root=x").len);
    try testing.expectEqual(1, Phases.parse("kernel=225 \"x\"=900").len);
    try testing.expectEqual(0, Phases.parse("").len);
    try testing.expectEqual(0, Phases.parse("=5").len);

    // Past max, nothing more is kept.
    var full: Phases = .{};
    for (0..Phases.max + 3) |i| full.add("x", i);
    try testing.expectEqual(Phases.max, full.len);
}

test "small parsers" {
    try testing.expectEqualStrings(
        "i-0123",
        instanceId("local-hostname: x\ninstance-id: i-0123\n"),
    );
    try testing.expectEqualStrings(
        "integrity",
        lockdownLevel("none [integrity] confidentiality\n"),
    );
    try testing.expectEqualStrings("12.34", firstWord("12.34 56.78\n"));
}

/// Milliseconds since the kernel started its clock.
fn bootMs() u64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}

// Each phase's tests, with these.
test {
    _ = phase_kernel;
    _ = phase_network;
    _ = phase_config;
    _ = phase_data;
    _ = phase_seal;
}
