//! mount: mount a filesystem werewolf uses, and only ever tighten a mount.
//!
//!     mount -t TYPE [-o OPTIONS] SOURCE TARGET   mount SOURCE on TARGET
//!     mount --bind SOURCE TARGET                 bind SOURCE onto TARGET
//!     mount -o remount[,OPTIONS] TARGET          tighten the mount on TARGET
//!
//! One-way by construction, and the kernel holds it to that:
//!
//! - A new mount is built detached (fsopen, fsmount) with nosuid and noexec,
//!   nodev unless it is a filesystem of device nodes, and nosymfollow unless
//!   it holds links the system follows (/proc, /sys, /dev) or is told
//!   symfollow, and
//!   only then attached: there is no moment it lacks them.
//! - A bind is cloned detached (open_tree), given the same restrictions,
//!   then attached. symfollow there only withholds nosymfollow: a clone
//!   keeps every restriction its source has.
//! - A remount is mount_setattr(2) with nothing to clear: the call cannot
//!   lift ro, nosuid, nodev, noexec or nosymfollow, whatever it is given.
//!   The one filesystem option a remount takes is hidepid=invisible, which
//!   only narrows what /proc shows.
//! - suid, dev, exec, and rw or symfollow on a remount, are refused
//!   outright.
//!
//! And as paranoid as OpenBSD would have it:
//!
//! - Allowlists, failing closed: the filesystem types werewolf mounts, the
//!   options each takes with their values checked, and the places it mounts
//!   (/proc, /sys, /dev, /run, /tmp, /var/tmp, /data, /victim, /mnt), so nothing can
//!   be mounted over /etc, /usr or the root itself.
//! - Paths are absolute, without . or .., and resolved by openat2(2) with
//!   symlinks refused: a link planted in a writable directory cannot steer
//!   a mount elsewhere.
//! - After the arguments are read and before anything is asked of the
//!   kernel, it pledges (lib/sandbox.zig): every capability but
//!   CAP_SYS_ADMIN gone, from the bounding set too, never to come back, and
//!   a seccomp filter allowing only the system calls below; any other, or
//!   another architecture's call, kills it.
//! - It reads no environment and no file, prints nothing on success, and on
//!   failure one line with the kernel's own reason.
//!
//! It is a tool that cannot loosen a mount, not a lock: root can still run a
//! program of its own that calls mount(2). What binds root is the seal
//! (docs/design/lockdown.md) and IPE (docs/design/verified-boot.md).

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    const p = parse(gpa, args[1..]) catch |err| fail("", err, "");
    pledge() catch |err| fail(p.target, err, "");
    var log: [512]u8 = @splat(0);
    apply(p, &log) catch |err|
        fail(p.target, err, std.mem.trim(u8, std.mem.sliceTo(&log, 0), " \n"));
    // Straight out: returning would free memory, which the pledge forbids.
    linux.exit_group(0);
}

// --- what may be mounted -------------------------------------------------------

/// The places mounts may go, and binds may come from.
const places = [_][]const u8{
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp",
    "/var/tmp",
    "/data",
    "/victim",
    "/mnt",
};

const Fs = struct {
    name: [:0]const u8,
    /// Its source is a block device, under /dev.
    block: bool = false,
    /// It holds device nodes, so it is mounted without nodev.
    devices: bool = false,
    /// It holds links the system needs followed, the kernel's own
    /// (/proc/self, /sys/class/*) or device-mapper's (/dev/mapper/data,
    /// which cryptsetup makes), so it is mounted without nosymfollow.
    links: bool = false,
    /// The filesystem options it may be given.
    options: []const []const u8 = &.{},
};

const filesystems = [_]Fs{
    .{ .name = "proc", .links = true, .options = &.{"hidepid"} },
    .{ .name = "sysfs", .links = true },
    .{ .name = "securityfs" },
    // The leashed services' cgroup2 hierarchy, under /run (cmd/init); no
    // options, since init mounts it once and the kernel names its files.
    .{ .name = "cgroup2" },
    .{ .name = "devtmpfs", .devices = true, .links = true },
    .{ .name = "devpts", .devices = true },
    .{ .name = "tmpfs", .options = &.{ "mode", "size" } },
    // /data on a disk, plain or inside LUKS2 (cmd/init).
    .{ .name = "ext4", .block = true },
    // A NoCloud seed, read-only.
    .{ .name = "iso9660", .block = true },
};

/// Filesystem options a remount may pass, whatever the filesystem: each only
/// narrows what it shows.
const remount_options = [_][]const u8{"hidepid"};

// mount_setattr(2) and fsmount(2) attributes (linux/mount.h).
const ATTR = struct { // ziglint-ignore: Z032
    const RDONLY: u64 = 0x1;
    const NOSUID: u64 = 0x2;
    const NODEV: u64 = 0x4;
    const NOEXEC: u64 = 0x8;
    const ATIME: u64 = 0x70; // a field, not a flag
    const NOATIME: u64 = 0x10;
    const NODIRATIME: u64 = 0x80;
    const NOSYMFOLLOW: u64 = 0x200000;
};

const attr_options = [_]struct { []const u8, u64 }{
    .{ "ro", ATTR.RDONLY },
    .{ "nosuid", ATTR.NOSUID },
    .{ "nodev", ATTR.NODEV },
    .{ "noexec", ATTR.NOEXEC },
    .{ "noatime", ATTR.NOATIME },
    .{ "nodiratime", ATTR.NODIRATIME },
    .{ "nosymfollow", ATTR.NOSYMFOLLOW },
};

/// Options that would lift a restriction. rw and symfollow are ones only on
/// a remount: on a new mount or a bind, symfollow withholds nosymfollow.
const loosening = [_][]const u8{ "suid", "dev", "exec", "strictatime" };

// --- reading the arguments -----------------------------------------------------

const Action = enum { mount, bind, tighten };

/// A filesystem option: key, or key=value.
const Option = struct { key: [:0]const u8, value: ?[:0]const u8 = null };

/// Everything an invocation asks, checked before the kernel hears of it.
const Plan = struct {
    action: Action = .mount,
    /// For a mount; a bind or remount has none.
    fs: ?*const Fs = null,
    source: [:0]const u8 = "",
    target: [:0]const u8 = "",
    attrs: u64 = 0,
    options: []const Option = &.{},
};

fn parse(gpa: Allocator, args: []const [:0]const u8) !Plan {
    var p: Plan = .{};
    var bind = false;
    var fstype: ?[]const u8 = null;
    var opts: []const u8 = "";
    var pos: [2][:0]const u8 = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-t") or std.mem.eql(u8, a, "-o")) {
            i += 1;
            if (i == args.len) return error.Usage;
            if (a[1] == 't') fstype = args[i] else opts = args[i];
        } else if (std.mem.eql(u8, a, "--bind")) {
            bind = true;
        } else if (a.len == 0 or a[0] == '-' or n == 2) {
            return error.Usage;
        } else {
            pos[n] = a;
            n += 1;
        }
    }

    var rw = false;
    var follow = false;
    var remount = false;
    var options: std.ArrayList(Option) = .empty;
    var it = std.mem.tokenizeScalar(u8, opts, ',');
    next: while (it.next()) |o| {
        if (std.mem.eql(u8, o, "remount")) {
            remount = true;
            continue;
        }
        if (std.mem.eql(u8, o, "bind")) {
            bind = true;
            continue;
        }
        if (std.mem.eql(u8, o, "rw")) {
            rw = true;
            continue;
        }
        if (std.mem.eql(u8, o, "symfollow")) {
            follow = true;
            continue;
        }
        if (std.mem.eql(u8, o, "defaults") or std.mem.eql(u8, o, "relatime")) continue;
        for (loosening) |l| if (std.mem.eql(u8, o, l)) return error.Loosens;
        for (attr_options) |a| if (std.mem.eql(u8, o, a[0])) {
            p.attrs |= a[1];
            continue :next;
        };
        const eq = std.mem.findScalar(u8, o, '=');
        try options.append(gpa, .{
            .key = try gpa.dupeSentinel(u8, o[0 .. eq orelse o.len], 0),
            .value = if (eq) |e| try gpa.dupeSentinel(u8, o[e + 1 ..], 0) else null,
        });
    }
    p.options = options.items;
    // remount,bind is how a bind is tightened; it is a remount like any other.
    p.action = if (remount) .tighten else if (bind) .bind else .mount;

    switch (p.action) {
        .tighten => {
            if (n != 1 or fstype != null) return error.Usage;
            if (rw or follow) return error.Loosens;
            for (p.options) |o| if (!allowed(&remount_options, o)) return error.Option;
            p.target = try place(pos[0]);
        },
        .bind => {
            if (n != 2 or fstype != null or p.options.len > 0) return error.Usage;
            if (rw and p.attrs & ATTR.RDONLY != 0) return error.Usage;
            p.source = try place(pos[0]);
            p.target = try place(pos[1]);
            p.attrs |= ATTR.NOSUID | ATTR.NODEV | ATTR.NOEXEC;
            if (!follow) p.attrs |= ATTR.NOSYMFOLLOW;
        },
        .mount => {
            if (n != 2) return error.Usage;
            if (rw and p.attrs & ATTR.RDONLY != 0) return error.Usage;
            // A mount names its filesystem: the kernel is never asked to
            // read a device as one kind after another.
            const t = fstype orelse return error.Usage;
            const fs = for (&filesystems) |*f| {
                if (std.mem.eql(u8, f.name, t)) break f;
            } else return error.Filesystem;
            p.fs = fs;
            p.source = if (fs.block) try device(pos[0]) else try name(pos[0]);
            p.target = try place(pos[1]);
            for (p.options) |o| if (!allowed(fs.options, o)) return error.Option;
            p.attrs |= ATTR.NOSUID | ATTR.NOEXEC;
            if (!fs.devices) p.attrs |= ATTR.NODEV;
            if (!fs.links and !follow) p.attrs |= ATTR.NOSYMFOLLOW;
        },
    }
    return p;
}

/// A path is absolute, has no empty, . or .. component, and lies in one of
/// the places.
fn place(path: [:0]const u8) ![:0]const u8 {
    if (path.len == 0 or path.len > 1024 or path[0] != '/') return error.Path;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |c| {
        if (c.len == 0 or std.mem.eql(u8, c, ".") or std.mem.eql(u8, c, "..")) return error.Path;
    }
    for (places) |pl| {
        if (std.mem.eql(u8, path, pl)) return path;
        if (std.mem.startsWith(u8, path, pl) and path[pl.len] == '/') return path;
    }
    return error.Place;
}

/// A block device: a clean path under /dev.
fn device(path: [:0]const u8) ![:0]const u8 {
    _ = try place(path);
    if (!std.mem.startsWith(u8, path, "/dev/")) return error.Device;
    return path;
}

/// The source of a filesystem without a device is only a label: tmpfs, proc.
fn name(s: [:0]const u8) ![:0]const u8 {
    if (s.len == 0 or s.len > 32) return error.Source;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return error.Source;
    return s;
}

/// Whether o is one of keys, with a valid value.
fn allowed(keys: []const []const u8, o: Option) bool {
    for (keys) |k| if (std.mem.eql(u8, o.key, k)) return validValue(o);
    return false;
}

/// Each option's value, in the one form werewolf uses it.
fn validValue(o: Option) bool {
    const v = o.value orelse return false;
    if (std.mem.eql(u8, o.key, "hidepid")) return std.mem.eql(u8, v, "invisible");
    if (std.mem.eql(u8, o.key, "mode")) {
        if (v.len < 3 or v.len > 4) return false;
        for (v) |c| if (c < '0' or c > '7') return false;
        return true;
    }
    if (std.mem.eql(u8, o.key, "size")) {
        if (v.len == 0 or v.len > 12) return false;
        const last = v[v.len - 1];
        const digits = if (std.mem.findScalar(u8, "kmg%", last) != null)
            v[0 .. v.len - 1]
        else
            v;
        if (digits.len == 0) return false;
        for (digits) |c| if (!std.ascii.isDigit(c)) return false;
        return true;
    }
    return false;
}

// --- pledge --------------------------------------------------------------------

const CAP_SYS_ADMIN = 21;

/// CAP_SYS_ADMIN alone, never to gain more, and a filter of the calls apply
/// makes, and the few exiting and writing need.
fn pledge() !void {
    try sandbox.keepOnly(1 << CAP_SYS_ADMIN);
    var f: sandbox.Filter = .{};
    inline for (.{
        "openat2",    "open_tree",     "fsopen", "fsconfig", "fsmount", "move_mount",
        "fspick",     "mount_setattr", "read",   "write",    "close",   "exit",
        "exit_group",
    }) |call| f.allow(call);
    try f.install();
}

// --- asking the kernel ---------------------------------------------------------

const O_PATH = 0o10000000;
const O_CLOEXEC = 0o2000000;
const RESOLVE_NO_MAGICLINKS = 0x02;
const RESOLVE_NO_SYMLINKS = 0x04;
const AT_EMPTY_PATH = 0x1000;
const OPEN_TREE_CLONE = 1;
const MOVE_MOUNT_F_EMPTY_PATH = 0x04;
const MOVE_MOUNT_T_EMPTY_PATH = 0x40;
const FSCONFIG_SET_FLAG = 0;
const FSCONFIG_SET_STRING = 1;
const FSCONFIG_CMD_CREATE = 6;
const FSCONFIG_CMD_RECONFIGURE = 7;
const FSPICK_EMPTY_PATH = 0x08;
const CLOEXEC = 1; // FSOPEN_, FSMOUNT_, FSPICK_CLOEXEC

const OpenHow = extern struct { flags: u64, mode: u64, resolve: u64 };
const MountAttr = extern struct { set: u64, clr: u64, propagation: u64, userns_fd: u64 };

fn apply(p: Plan, log: []u8) !void {
    const target = try resolve(p.target);
    defer _ = linux.close(target);
    switch (p.action) {
        .tighten => {
            // Only a set: what the mount has, it keeps.
            try setattr(target, p.attrs);
            if (p.options.len > 0) {
                const fc = try fd(linux.syscall3(
                    .fspick,
                    @bitCast(@as(isize, target)),
                    @intFromPtr(""),
                    FSPICK_EMPTY_PATH | CLOEXEC,
                ));
                defer _ = linux.close(fc);
                try configure(fc, p.options, log);
                try fsconfigCmd(fc, FSCONFIG_CMD_RECONFIGURE, log);
            }
        },
        .bind => {
            const source = try resolve(p.source);
            defer _ = linux.close(source);
            const tree = try fd(linux.syscall3(
                .open_tree,
                @bitCast(@as(isize, source)),
                @intFromPtr(""),
                OPEN_TREE_CLONE | O_CLOEXEC | AT_EMPTY_PATH,
            ));
            defer _ = linux.close(tree);
            try setattr(tree, p.attrs);
            try attach(tree, target);
        },
        .mount => try create(p.fs.?, p, target, log),
    }
}

/// Open a place for mounting on, refusing symlinks anywhere in its path.
fn resolve(path: [:0]const u8) !i32 {
    var how: OpenHow = .{
        .flags = O_PATH | O_CLOEXEC,
        .mode = 0,
        .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    return fd(linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(path.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    ));
}

fn create(fs: *const Fs, p: Plan, target: i32, log: []u8) !void {
    const fc = try fd(linux.syscall2(.fsopen, @intFromPtr(fs.name.ptr), CLOEXEC));
    defer _ = linux.close(fc);
    try fsconfig(fc, FSCONFIG_SET_STRING, "source", p.source, log);
    if (p.attrs & ATTR.RDONLY != 0) try fsconfig(fc, FSCONFIG_SET_FLAG, "ro", null, log);
    try configure(fc, p.options, log);
    try fsconfigCmd(fc, FSCONFIG_CMD_CREATE, log);
    const m = try fd(linux.syscall3(.fsmount, @bitCast(@as(isize, fc)), CLOEXEC, p.attrs));
    defer _ = linux.close(m);
    try attach(m, target);
}

fn configure(fc: i32, options: []const Option, log: []u8) !void {
    for (options) |o| {
        if (o.value) |v|
            try fsconfig(fc, FSCONFIG_SET_STRING, o.key, v, log)
        else
            try fsconfig(fc, FSCONFIG_SET_FLAG, o.key, null, log);
    }
}

fn fsconfig(fc: i32, cmd: u32, key: [:0]const u8, value: ?[:0]const u8, log: []u8) !void {
    const v: usize = if (value) |x| @intFromPtr(x.ptr) else 0;
    sys(linux.syscall5(
        .fsconfig,
        @bitCast(@as(isize, fc)),
        cmd,
        @intFromPtr(key.ptr),
        v,
        0,
    )) catch |err| {
        drain(fc, log);
        return err;
    };
}

fn fsconfigCmd(fc: i32, cmd: u32, log: []u8) !void {
    sys(linux.syscall5(.fsconfig, @bitCast(@as(isize, fc)), cmd, 0, 0, 0)) catch |err| {
        drain(fc, log);
        return err;
    };
}

/// The kernel's own account of a failed fsconfig, read from the context.
fn drain(fc: i32, log: []u8) void {
    const n = linux.read(fc, log.ptr, log.len - 1);
    log[if (linux.errno(n) == .SUCCESS) n else 0] = 0;
}

/// set added to the mount at dirfd, and nothing cleared but the atime field
/// that noatime moves, which is not a restriction.
fn setattr(dirfd: i32, set: u64) !void {
    const clr: u64 = if (set & ATTR.NOATIME != 0) ATTR.ATIME else 0;
    var attr: MountAttr = .{ .set = set, .clr = clr, .propagation = 0, .userns_fd = 0 };
    try sys(linux.syscall5(
        .mount_setattr,
        @bitCast(@as(isize, dirfd)),
        @intFromPtr(""),
        AT_EMPTY_PATH,
        @intFromPtr(&attr),
        @sizeOf(MountAttr),
    ));
}

fn attach(mnt: i32, target: i32) !void {
    try sys(linux.syscall5(
        .move_mount,
        @bitCast(@as(isize, mnt)),
        @intFromPtr(""),
        @bitCast(@as(isize, target)),
        @intFromPtr(""),
        MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
    ));
}

fn fd(rc: usize) !i32 {
    try sys(rc);
    return @intCast(rc);
}

fn sys(rc: usize) !void {
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM => error.PermissionDenied,
        .ACCES => error.AccessDenied,
        .NOENT => error.NoSuchFileOrDirectory,
        .LOOP => error.SymlinkInPath,
        .BUSY => error.Busy,
        .INVAL => error.InvalidArgument,
        .NODEV => error.NoSuchFilesystem,
        .NOTBLK => error.NotABlockDevice,
        .NOTDIR => error.NotADirectory,
        .NOSYS => error.TooOldAKernel,
        else => error.Failed,
    };
}

// --- saying so -----------------------------------------------------------------

fn fail(target: []const u8, err: anyerror, kernel: []const u8) noreturn {
    var buf: [1024]u8 = undefined;
    const line = switch (err) {
        error.Usage =>
        \\usage: mount -t TYPE [-o OPTIONS] SOURCE TARGET
        \\       mount [-o OPTIONS] DEVICE TARGET
        \\       mount --bind SOURCE TARGET
        \\       mount -o remount[,OPTIONS] TARGET
        \\
        ,
        else => std.mem.print(&buf, "mount: {s}{s}{s}{s}{s}\n", .{
            target,
            if (target.len > 0) ": " else "",
            describe(err),
            if (kernel.len > 0) ": " else "",
            kernel,
        }) catch "mount: failed\n",
    };
    _ = linux.write(2, line.ptr, line.len);
    linux.exit_group(if (err == error.Usage) 2 else 1);
}

fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.Loosens => "refused: that option would lift a restriction, and this mount only " ++
            "adds them",
        error.Option => "refused: an option this filesystem is not given, or not in the form " ++
            "werewolf uses",
        error.Filesystem => "refused: not a filesystem werewolf mounts",
        error.Path => "refused: paths are absolute, without empty, . or .. parts",
        error.Place => "refused: not under /proc, /sys, /dev, /run, /tmp, /var/tmp, /data, " ++
            "/victim or /mnt",
        error.Device => "refused: a block device is a path under /dev",
        error.Source => "refused: the source of this filesystem is a plain name",
        error.SymlinkInPath => "refused: a symlink in the path",
        else => @errorName(err),
    };
}

// --- tests ---------------------------------------------------------------------

const testing = std.testing;

fn tryParse(args: []const [:0]const u8) !Plan {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    // Plans in tests are compared at once; the arena outlives them by design.
    errdefer arena.deinit();
    const p = try parse(arena.allocator(), args);
    arena.deinit();
    return .{ .action = p.action, .fs = p.fs, .attrs = p.attrs };
}

test "a new mount is nosuid, noexec, nodev and nosymfollow, but where it cannot be" {
    const shut = ATTR.NOSUID | ATTR.NODEV | ATTR.NOEXEC | ATTR.NOSYMFOLLOW;
    const t = try tryParse(&.{ "-t", "tmpfs", "-o", "mode=1777,size=25%", "tmpfs", "/tmp" });
    try testing.expectEqual(shut, t.attrs);
    const d = try tryParse(&.{ "-t", "devpts", "devpts", "/dev/pts" });
    try testing.expectEqual(ATTR.NOSUID | ATTR.NOEXEC | ATTR.NOSYMFOLLOW, d.attrs);
    const i = try tryParse(&.{ "-t", "iso9660", "-o", "ro", "/dev/vdb", "/mnt" });
    try testing.expectEqual(ATTR.RDONLY | shut, i.attrs);
    // Links the system follows: /proc/self, /sys/class/net/eth0, and
    // /dev/mapper/data, which cryptsetup makes.
    const dev = try tryParse(&.{ "-t", "devtmpfs", "dev", "/dev" });
    try testing.expectEqual(ATTR.NOSUID | ATTR.NOEXEC, dev.attrs);
    const proc = try tryParse(&.{ "-t", "proc", "proc", "/proc" });
    try testing.expectEqual(ATTR.NOSUID | ATTR.NODEV | ATTR.NOEXEC, proc.attrs);
    const sysfs = try tryParse(&.{ "-t", "sysfs", "sys", "/sys" });
    try testing.expectEqual(ATTR.NOSUID | ATTR.NODEV | ATTR.NOEXEC, sysfs.attrs);
}

test "symfollow withholds nosymfollow from a new mount or a bind, and lifts nothing" {
    const t = try tryParse(&.{ "-t", "ext4", "-o", "symfollow", "/dev/vdb", "/data" });
    try testing.expectEqual(ATTR.NOSUID | ATTR.NODEV | ATTR.NOEXEC, t.attrs);
    const b = try tryParse(&.{ "--bind", "-o", "symfollow", "/data/svc/x", "/data/svc/x" });
    try testing.expectEqual(ATTR.NOSUID | ATTR.NODEV | ATTR.NOEXEC, b.attrs);
    try testing.expectError(error.Loosens, tryParse(&.{ "-o", "remount,symfollow", "/data" }));
    try testing.expectError(error.Loosens, tryParse(&.{ "-o", "remount,bind,symfollow", "/data" }));
}

test "nothing that would lift a restriction is taken" {
    for ([_][:0]const u8{ "exec", "suid", "dev", "nosuid,exec" }) |o| {
        try testing.expectError(
            error.Loosens,
            tryParse(&.{ "-t", "tmpfs", "-o", o, "tmpfs", "/tmp" }),
        );
        try testing.expectError(error.Loosens, tryParse(&.{ "-o", o, "/tmp" }));
    }
    try testing.expectError(error.Loosens, tryParse(&.{ "-o", "remount,rw", "/victim" }));
}

test "a remount narrows, and takes only options that narrow" {
    const v = try tryParse(&.{ "-o", "remount,bind,ro,nosuid,nodev,noexec", "/victim" });
    try testing.expectEqual(Action.tighten, v.action);
    try testing.expectEqual(ATTR.RDONLY | ATTR.NOSUID | ATTR.NODEV | ATTR.NOEXEC, v.attrs);
    _ = try tryParse(&.{ "-o", "remount,nosuid,nodev,noexec,hidepid=invisible", "/proc" });
    try testing.expectError(error.Option, tryParse(&.{ "-o", "remount,discard", "/data" }));
    try testing.expectError(error.Option, tryParse(&.{ "-o", "remount,hidepid=off", "/proc" }));
    try testing.expectError(error.Option, tryParse(&.{ "-o", "remount,size=90%", "/tmp" }));
}

test "only werewolf's filesystems, options and values" {
    try testing.expectError(error.Filesystem, tryParse(&.{ "-t", "ntfs", "/dev/vdb", "/mnt" }));
    // Filesystems no caller of mount uses: the broker mounts the ESP and the
    // victim's itself.
    for ([_][:0]const u8{ "vfat", "xfs", "btrfs" }) |t|
        try testing.expectError(error.Filesystem, tryParse(&.{ "-t", t, "/dev/vda1", "/mnt" }));
    try testing.expectError(error.Filesystem, tryParse(&.{ "-t", "overlay", "overlay", "/mnt" }));
    try testing.expectError(
        error.Option,
        tryParse(&.{ "-t", "tmpfs", "-o", "uid=0", "tmpfs", "/tmp" }),
    );
    try testing.expectError(
        error.Option,
        tryParse(&.{ "-t", "tmpfs", "-o", "mode=8777", "tmpfs", "/tmp" }),
    );
    try testing.expectError(
        error.Option,
        tryParse(&.{ "-t", "tmpfs", "-o", "size=lots", "tmpfs", "/tmp" }),
    );
    try testing.expectError(
        error.Option,
        tryParse(&.{ "-t", "proc", "-o", "hidepid=0", "proc", "/proc" }),
    );
    try testing.expectError(
        error.Option,
        tryParse(&.{ "-t", "ext4", "-o", "errors=continue", "/dev/vda", "/data" }),
    );
    try testing.expectError(
        error.Option,
        tryParse(&.{ "-t", "ext4", "-o", "discard", "/dev/vda", "/data" }),
    );
}

test "only werewolf's places, as clean absolute paths" {
    for ([_][:0]const u8{
        "/etc",
        "/usr/bin",
        "/root",
        "/var",
        "/var/lib",
        "/datax",
        "/tmpfoo",
    }) |t| {
        try testing.expectError(error.Place, tryParse(&.{ "-t", "tmpfs", "tmpfs", t }));
    }
    for ([_][:0]const u8{ "/", "tmp", "/tmp/../etc", "/tmp/./x", "//tmp", "/tmp/" }) |t| {
        try testing.expectError(error.Path, tryParse(&.{ "-t", "tmpfs", "tmpfs", t }));
    }
    try testing.expectError(error.Device, tryParse(&.{ "-t", "ext4", "/data/disk.img", "/mnt" }));
    try testing.expectError(error.Source, tryParse(&.{ "-t", "tmpfs", "/dev/vda", "/tmp" }));
    try testing.expectError(error.Place, tryParse(&.{ "--bind", "/etc", "/data" }));
}

test "binds, and what is not an invocation" {
    const b = try tryParse(&.{ "--bind", "/victim/var/lib/werewolf/data", "/data" });
    try testing.expectEqual(Action.bind, b.action);
    try testing.expectEqual(ATTR.NOSUID | ATTR.NODEV | ATTR.NOEXEC | ATTR.NOSYMFOLLOW, b.attrs);
    // A mount names its filesystem: nothing is probed.
    try testing.expectError(
        error.Usage,
        tryParse(&.{ "-o", "nosuid,nodev,noexec", "/dev/vda1", "/victim" }),
    );
    try testing.expectError(error.Usage, tryParse(&.{"/tmp"}));
    try testing.expectError(error.Usage, tryParse(&.{ "-t", "tmpfs" }));
    try testing.expectError(error.Usage, tryParse(&.{ "-o", "remount", "/tmp", "/run" }));
    try testing.expectError(error.Usage, tryParse(&.{ "-f", "tmpfs", "/tmp" }));
    try testing.expectError(
        error.Usage,
        tryParse(&.{ "-o", "ro,rw", "-t", "tmpfs", "tmpfs", "/tmp" }),
    );
    try testing.expectError(error.Usage, tryParse(&.{ "-t", "tmpfs", "-o", "remount", "/tmp" }));
}
