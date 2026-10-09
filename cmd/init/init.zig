//! init is PID 1 between stage0 and runit. It mounts filesystems, sets the
//! kernel's protections, reads the config, brings up the network and /data,
//! seals the machine, and execs fence, which becomes runit. See README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const phase_kernel = @import("kernel.zig");
const phase_network = @import("network.zig");
const phase_config = @import("config.zig");
const phase_data = @import("data.zig");
const phase_oci = @import("oci.zig");
const phase_seal = @import("seal.zig");
const cmdline = @import("cmdline");

pub const mount_bin = "/usr/lib/werewolf/mount";

const path_env = "/usr/sbin:/usr/bin:/sbin:/bin";

pub fn main(init: std.process.Init) !void {
    var m: Machine = .{
        .io = init.io,
        .gpa = init.arena.allocator(),
        .env = .init(init.arena.allocator()),
    };
    // Build from nothing the environment every program inherits through
    // fence and runit. init's own holds each NAME=value the kernel did not
    // take from its command line, which blkid, e2fsprogs and the loader
    // would read as settings.
    try m.env.put("PATH", path_env);
    try m.env.put("HOME", "/");
    try m.env.put("TERM", "linux");
    // Each phase is marked as it ends, stage0's first, to show where the
    // boot's time goes.
    var phases = Phases.parse(init.environ_map.get("WEREWOLF_BOOT") orelse "");

    // No tool may wait on a person. One that prompts (mke2fs does, over an
    // old signature) reads end of file instead of stalling the boot.
    const null_fd = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(null_fd) == .SUCCESS) _ = linux.dup2(@intCast(null_fd), 0);

    m.filesystems();
    m.seed();
    // stage0 checked the line by the same rules, so a refusal here means
    // the line changed under it.
    var refused: cmdline.Failure = .{};
    m.cmd = cmdline.parse(m.read("/proc/cmdline"), &refused) orelse {
        say("the command line's {s}: {s}; not handing over", .{ refused.word, refused.why });
        std.process.exit(1);
    };
    phases.add("mounts", bootMs());
    m.kernel() catch {
        say("the kernel's protections are not all set; not handing over", .{});
        std.process.exit(1);
    };
    phases.add("sysctls", bootMs());
    // The config on disk comes first, since it may set the network; the
    // cloud's metadata needs the network.
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
    if (m.oci()) phases.add("oci", bootMs());

    // No process may dump core, so a crash leaves no copy of its memory and
    // secrets behind. The hard limit is 0, so no process can raise it.
    const no_core: linux.rlimit = .{ .cur = 0, .max = 0 };
    if (linux.errno(linux.setrlimit(.CORE, &no_core)) != .SUCCESS)
        say("core dumps not limited", .{});
    // The seal fails closed: PID 1 exits, the kernel panics, and the machine
    // comes back on the slot that last worked.
    phase_seal.seal(&m) catch |err| {
        say("not sealed: {s}; not handing over", .{@errorName(err)});
        std.process.exit(1);
    };
    // The mount broker mounts for the few programs that must, once fence's
    // Landlock domain forbids mounting. Starting it here puts it outside that
    // domain but under the seal. Without it nothing can keep this slot, so
    // the machine falls back to the slot that last worked.
    if (std.process.spawn(m.io, .{
        .argv = &.{"/usr/lib/werewolf/mount-broker"},
        .environ_map = &m.env,
        .stdin = .ignore,
    })) |_| {} else |broker_err| say("no mount broker: {s}", .{@errorName(broker_err)});
    // DHCP renewal starts before fence, which takes CAP_NET_ADMIN and packet
    // sockets from every later process, root included. runit does not
    // restart it; if it exits, the address it applied stays.
    if (m.dhcp) if (std.process.spawn(m.io, .{
        .argv = &.{ "/usr/lib/werewolf/dhcp-client", "keep" },
        .environ_map = &m.env,
        .stdin = .ignore,
    })) |_| {} else |dhcp_err| say("no DHCP renewal: {s}", .{@errorName(dhcp_err)});
    phases.add("seal", bootMs());
    // The boot's timing goes to the console and /run/werewolf/boot (read by
    // the demo's page). stage0 measured the kernel's part.
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
    // Raise the console loglevel now the boot is over, so the kernel's
    // refusals (exec, lockdown, Yama, Landlock) reach it. loglevel=5 kept
    // them off during boot, where each line costs a millisecond on a
    // cloud's serial port (Makefile, KERNEL_ARGS).
    if (!writeFile("/proc/sys/kernel/printk", "6"))
        say("console loglevel not raised: the kernel's refusals stay in dmesg", .{});
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
    cmd: cmdline.Cmdline = .{},
    victim_dir: []const u8 = "",
    nocloud_user: []const u8 = "",
    /// configured is set when a disk held a config tar or a NoCloud seed;
    /// the cloud's metadata server is then not asked.
    configured: bool = false,
    /// dhcp is set when DHCP gave the address, so its renewal is started.
    dhcp: bool = false,

    // Each phase lives in its own file but is still called as m.phase().
    pub const filesystems = phase_kernel.filesystems;
    pub const seed = phase_kernel.seed;
    pub const kernel = phase_kernel.kernel;
    pub const network = phase_network.network;
    pub const victim = phase_config.victim;
    pub const config = phase_config.config;
    pub const metadata = phase_config.metadata;
    pub const data = phase_data.data;
    pub const oci = phase_oci.oci;

    /// mount runs werewolf's mount with args. mount reports its own errors,
    /// and the boot goes on.
    pub fn mount(m: *Machine, args: []const []const u8) void {
        const argv = std.mem.concat(m.gpa, []const u8, &.{ &.{mount_bin}, args }) catch return;
        _ = m.run(argv);
    }

    pub fn run(m: *Machine, argv: []const []const u8) bool {
        return m.spawn(argv, false) == 0;
    }

    /// runQuiet is run with the program's output discarded, for probes whose
    /// failure is an answer.
    pub fn runQuiet(m: *Machine, argv: []const []const u8) bool {
        return m.spawn(argv, true) == 0;
    }

    /// which returns name's path in path_env, or null. Programs run by full
    /// path because spawn resolves a bare name against init's environment,
    /// and the kernel gives init no PATH.
    pub fn which(m: *Machine, name: []const u8) ?[:0]const u8 {
        var dirs = std.mem.tokenizeScalar(u8, path_env, ':');
        while (dirs.next()) |dir| {
            const path = m.fmtZ("{s}/{s}", .{ dir, name });
            if (executable(path)) return path;
        }
        return null;
    }

    /// spawn runs argv and returns its exit code, or 255 if it did not run
    /// or was killed.
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

    /// mountSource returns the source mounted on point, as
    /// /proc/self/mounts names it, or null.
    pub fn mountSource(m: *Machine, point: []const u8) ?[]const u8 {
        var it = std.mem.tokenizeScalar(u8, m.read("/proc/self/mounts"), '\n');
        while (it.next()) |line| {
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            const source = f.next() orelse continue;
            if (std.mem.eql(u8, f.next() orelse continue, point)) return source;
        }
        return null;
    }

    /// read returns path's contents, up to 1 MiB, or "". It reads to the end
    /// because procfs and sysfs report a size of 0.
    pub fn read(m: *Machine, path: []const u8) []const u8 {
        var f = Dir.cwd().openFile(m.io, path, .{}) catch return "";
        defer f.close(m.io);
        var buf: [4096]u8 = undefined;
        var r = f.readerStreaming(m.io, &buf);
        return r.interface.allocRemaining(m.gpa, .limited(1 << 20)) catch "";
    }

    /// readRegular is read for a file from outside the image: it must be a
    /// regular file, not a link (see openRegular). It returns "" otherwise.
    pub fn readRegular(m: *Machine, path: []const u8) []const u8 {
        const fd = openRegular(m.z(path)) orelse return "";
        var f: Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
        defer f.close(m.io);
        var buf: [4096]u8 = undefined;
        var r = f.readerStreaming(m.io, &buf);
        return r.interface.allocRemaining(m.gpa, .limited(1 << 20)) catch "";
    }

    /// write writes text to path with mode, and logs a failure.
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

    /// list returns the names in dir, sorted, without dot files.
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

pub fn lastField(s: []const u8) []const u8 {
    const t = std.mem.trimEnd(u8, s, " \t\r");
    const i = std.mem.lastIndexOfAny(u8, t, " \t") orelse return t;
    return t[i + 1 ..];
}

pub fn firstLine(s: []const u8) []const u8 {
    return s[0 .. std.mem.findScalar(u8, s, '\n') orelse s.len];
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

/// fileType returns the type bits of fd's mode (S.IFREG, S.IFBLK, ...), or 0.
pub fn fileType(fd: i32) u32 {
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(fd, "", AT_EMPTY_PATH, .{ .TYPE = true }, &st)) != .SUCCESS)
        return 0;
    return st.mode & linux.S.IFMT;
}

const AT_EMPTY_PATH = 0x1000;

/// openRegular opens path for reading if it is a regular file and not a
/// link, or returns null. It is for files from outside the image (a cidata
/// ISO, a victim): a FIFO or device could block PID 1 forever, and a link
/// could point anywhere.
pub fn openRegular(path: [:0]const u8) ?i32 {
    const fd = linux.open(path, .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .NOCTTY = true,
    }, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    if (fileType(@intCast(fd)) != linux.S.IFREG) {
        _ = linux.close(@intCast(fd));
        return null;
    }
    return @intCast(fd);
}

pub fn writeFile(path: [:0]const u8, data: []const u8) bool {
    return writeErrno(path, data) == .SUCCESS;
}

/// writeErrno is writeFile returning the errno, so a caller can tell a
/// read-only /proc/sys (a container) from a refusal that matters.
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

/// Phases records when each boot phase ended, in milliseconds of the boot
/// clock. stage0 passes its phases in WEREWOLF_BOOT as
/// `kernel=225 modules=611 slot=838 root=851`; init appends its own.
const Phases = struct {
    names: [max][]const u8 = undefined,
    ends: [max]u64 = undefined,
    len: usize = 0,

    const max = 16;
    const Took = struct { name: []const u8, ms: u64 };

    /// parse reads stage0's phases. Each name is lowercase letters, and no
    /// phase may end before the one before it; parsing stops at the first
    /// bad word.
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

    /// add records a phase that ended at end. Past max it does nothing.
    fn add(p: *Phases, name: []const u8, end: u64) void {
        if (p.len == max) return;
        p.names[p.len] = name;
        p.ends[p.len] = end;
        p.len += 1;
    }

    /// endOf returns when phase name ended, or 0 if there was none.
    fn endOf(p: *const Phases, name: []const u8) u64 {
        for (p.names[0..p.len], p.ends[0..p.len]) |n, e| if (std.mem.eql(u8, n, name)) return e;
        return 0;
    }

    /// durations returns how long each phase took, from the end of the one
    /// before, or from boot for the first.
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

test lastField {
    try testing.expectEqualStrings("bob", lastField("name: bob"));
    try testing.expectEqualStrings("bob", lastField("name:\tbob \r"));
    try testing.expectEqualStrings("\"1000\"", lastField("uid: \"1000\""));
    try testing.expectEqualStrings("only", lastField("only"));
    try testing.expectEqualStrings("", lastField(""));
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

/// bootMs returns milliseconds since boot (CLOCK_BOOTTIME), or 0.
fn bootMs() u64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}

// Run each phase's tests too.
test {
    _ = phase_kernel;
    _ = phase_network;
    _ = phase_config;
    _ = phase_data;
    _ = phase_oci;
    _ = phase_seal;
}
