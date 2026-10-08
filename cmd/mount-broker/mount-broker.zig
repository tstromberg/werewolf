//! mount-broker: the few mounts werewolf makes once it has booted, made for
//! root's own programs, which fence's Landlock domain keeps from mounting
//! at all (docs/design/pledge.md).
//!
//!     mount-broker      serve, until the machine stops
//!
//! init starts it just before it becomes fence, so it alone stays outside
//! fence's domain. It listens on /run/werewolf/mount-broker.sock, root's
//! alone, answers only uid 0, and takes one word a connection:
//!
//!     grub       the filesystem holding GRUB's environment (what init wrote
//!                in /run/werewolf/grubenv), read-write at /run/werewolf/mnt/grub
//!     esp        the EFI system partition (werewolf.esp), read-write at
//!                /run/werewolf/mnt/esp
//!     victim     the victim's filesystem (werewolf.victim), read-write at
//!                /run/werewolf/mnt/victim
//!     shutdown   /data unmounted, or read-only if busy; its LUKS mapping
//!                closed; the victim's filesystem read-only, which writes
//!                its journal in place for GRUB, and /victim unmounted if it
//!                can be
//!
//! It answers one line: `ok PATH`, `ok`, or `no WHY`. A mount lasts as long
//! as the connection that asked for it: when the asker closes it, or dies,
//! the broker unmounts. Nothing an asker says but the word is used: which
//! filesystem comes from the kernel command line and what init wrote in
//! /run, found by the UUID in its superblock, and how it is mounted is
//! fixed here, as the one-way mount helper mounts: built detached (fsopen,
//! fsmount) with nosuid, nodev, noexec and nosymfollow, then attached. bite
//! names GRUB's environment and the victim's directory by where their links
//! lead (readlink -f), so nothing here needs one followed.
//!
//! One process, with CAP_SYS_ADMIN alone and locked, under a seccomp filter
//! of the calls above and its socket's, the classic mount(2) only to remount
//! read-only and umount2 only plainly; it runs nothing. Two
//! devices answering to the same UUID or serial are refused, not guessed
//! between. Every event is one JSON line on the console.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const dm = @import("dm");
const broker = @import("broker");

const socket_path = broker.socket_path;
const mnt_dir = broker.mnt_dir;
const cap_sys_admin = 21;
const max_conns = 8;

/// The words and their places are the library's (lib/broker.zig), so an
/// asker checks the answer against the same places.
const Word = broker.Word;

/// A connection: what it has said so far, and the mount it holds. An
/// asker that is gone while something else still holds its mount open
/// keeps the slot (fd closed, holds set) until a plain unmount succeeds.
const Conn = struct {
    fd: i32 = -1,
    buf: [16]u8 = undefined,
    len: usize = 0,
    holds: ?Word = null,

    fn open(c: Conn) bool {
        return c.fd >= 0;
    }

    fn orphan(c: Conn) bool {
        return c.fd < 0 and c.holds != null;
    }
};

pub fn main() !void {
    var log: Log = .{};
    const listener = setUp() catch |err| {
        log.event(
            "error",
            .{
                .step = "start",
                .@"error" = @errorName(err),
                .call = sandbox.failed,
                .errno = sandbox.errnoName(sandbox.failed_errno),
            },
        );
        linux.exit_group(1);
    };
    log.event("listening", .{ .socket = socket_path });
    serve(&log, listener);
}

/// The socket, the mount points, and the sandbox, before anyone can ask.
fn setUp() !i32 {
    _ = linux.mkdirat(linux.AT.FDCWD, mnt_dir, 0o700);
    inline for (.{
        Word.grub,
        Word.esp,
        Word.victim,
    }) |w| _ = linux.mkdirat(linux.AT.FDCWD, w.place(), 0o700);
    _ = linux.unlinkat(linux.AT.FDCWD, socket_path, 0);
    const fd: i32 = @intCast(try sandbox.sys(
        linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0),
        "socket",
    ));
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..socket_path.len], socket_path);
    // Root's alone from the moment it exists.
    const old = linux.syscall1(.umask, 0o077);
    _ = try sandbox.sys(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un)), "bind");
    _ = linux.syscall1(.umask, old);
    _ = try sandbox.sys(linux.listen(fd, max_conns), "listen");

    try sandbox.keepOnly(1 << cap_sys_admin);
    var f: sandbox.Filter = .{};
    inline for (.{
        "accept4", "getsockopt",    "sendto",    "read",       "close",           "poll",
        "ppoll",   "openat",        "pread64",   "getdents64", "fsopen",          "fsconfig",
        "fsmount", "move_mount",    "sync",      "write",      "mmap",            "munmap",
        "mremap",  "clock_gettime", "nanosleep", "exit_group", "restart_syscall",
    }) |name| f.allow(name);
    f.allowArg("ioctl", 1, dm.dev_remove);
    // The classic mount(2) only to remount read-only, at shutdown; umount2
    // only plainly, never lazily: nothing it could mount or move with them.
    f.allowArg("mount", 3, linux.MS.REMOUNT | linux.MS.RDONLY);
    f.allowArg("umount2", 1, 0);
    try f.install();
    return fd;
}

fn serve(log: *Log, listener: i32) noreturn {
    var conns: [max_conns]Conn = @splat(.{});
    while (true) {
        var fds: [max_conns + 1]linux.pollfd = undefined;
        fds[0] = .{ .fd = listener, .events = linux.POLL.IN, .revents = 0 };
        for (conns, 1..) |c, i| fds[i] = .{ .fd = c.fd, .events = linux.POLL.IN, .revents = 0 };
        // A second at a time while an orphaned mount waits to be unmounted.
        var waiting = false;
        for (conns) |c| if (c.orphan()) {
            waiting = true;
        };
        const n = linux.poll(&fds, fds.len, if (waiting) 1000 else -1);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            // Not an asker's doing, and not a reason to stop: the machine
            // needs the broker to keep its slots. A moment, then again,
            // rather than a loop that spins.
            else => {
                _ = linux.nanosleep(&.{ .sec = 0, .nsec = 100 * std.time.ns_per_ms }, null);
                continue;
            },
        }
        for (&conns, fds[1..]) |*c, p| {
            if (c.open() and p.revents != 0) heard(log, c, &conns);
        }
        for (&conns) |*c| if (c.orphan()) release(log, c, false);
        if (fds[0].revents & linux.POLL.IN != 0) accept(log, listener, &conns);
    }
}

/// A new asker: root, or turned away; and room for it, or turned away.
fn accept(log: *Log, listener: i32, conns: *[max_conns]Conn) void {
    const rc = linux.accept4(listener, null, null, linux.SOCK.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return;
    const fd: i32 = @intCast(rc);
    var cred: Ucred = .{ .pid = 0, .uid = std.math.maxInt(u32), .gid = 0 };
    var len: linux.socklen_t = @sizeOf(Ucred);
    if (linux.errno(linux.getsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.PEERCRED,
        @ptrCast(&cred),
        &len,
    )) != .SUCCESS or cred.uid != 0) {
        log.event("refused", .{ .pid = cred.pid, .uid = cred.uid, .reason = "not root" });
        _ = linux.close(fd);
        return;
    }
    for (conns) |*c| if (!c.open() and !c.orphan()) {
        c.* = .{ .fd = fd };
        return;
    };
    reply(fd, "no busy: too many askers\n");
    _ = linux.close(fd);
}

/// Bytes from an asker, or its end.
fn heard(log: *Log, c: *Conn, conns: *[max_conns]Conn) void {
    const rc = if (c.len < c.buf.len)
        linux.read(c.fd, c.buf[c.len..].ptr, c.buf.len - c.len)
    else
        0;
    if (linux.errno(rc) != .SUCCESS or rc == 0 or c.holds != null) return hangUp(log, c);
    c.len += rc;
    const eol = std.mem.findScalar(u8, c.buf[0..c.len], '\n') orelse {
        if (c.len == c.buf.len) {
            reply(c.fd, "no: a word, then a newline\n");
            hangUp(log, c);
        }
        return;
    };
    const word = std.meta.stringToEnum(Word, c.buf[0..eol]) orelse {
        reply(c.fd, "no: grub, esp, victim or shutdown\n");
        return hangUp(log, c);
    };
    if (word == .shutdown) {
        for (conns) |*other| if (other.holds != null) hangUp(log, other);
        shutdown(log);
        reply(c.fd, "ok\n");
        return hangUp(log, c);
    }
    for (conns) |other| if (other.holds == word) {
        reply(c.fd, "no busy: another asker holds it\n");
        return hangUp(log, c);
    };
    mountWord(log, word) catch |err| {
        var buf: [96]u8 = undefined;
        reply(c.fd, std.mem.print(&buf, "no {s}\n", .{@errorName(err)}) catch "no\n");
        return hangUp(log, c);
    };
    c.holds = word;
    var buf: [64]u8 = undefined;
    reply(c.fd, std.mem.print(&buf, "ok {s}\n", .{word.place()}) catch unreachable);
}

/// An asker gone: its connection closed, and what it held unmounted.
fn hangUp(log: *Log, c: *Conn) void {
    if (c.open()) _ = linux.close(c.fd);
    c.fd = -1;
    c.len = 0;
    if (c.holds != null) release(log, c, true);
}

/// The mount c holds, unmounted plainly, never detached: a lazy unmount
/// would hide a mount a process in the domain still has open, and the
/// broker would say it was gone while that process kept writing through
/// it, and would mount the same filesystem again for the next asker. If
/// it is busy, the word stays c's, refused to other askers, and serve
/// tries again each second until the kernel lets it go; the first refusal
/// is said, and so is the unmount when it comes.
fn release(log: *Log, c: *Conn, first: bool) void {
    const w = c.holds.?;
    const err = linux.errno(linux.umount2(w.place(), 0));
    if (err == .BUSY) {
        if (first) log.event("busy", .{ .what = @tagName(w), .held = "by a process still" });
        return;
    }
    // Unmounted, or no longer a mount at all (EINVAL): either way gone.
    if (err == .SUCCESS) {
        log.event("unmounted", .{ .what = @tagName(w), .late = !first });
    } else {
        log.event(
            "unmounted",
            .{ .what = @tagName(w), .late = !first, .errno = sandbox.errnoName(err) },
        );
    }
    c.* = .{};
}

/// The kernel's struct ucred, what SO_PEERCRED gives.
const Ucred = extern struct { pid: i32, uid: u32, gid: u32 };

fn reply(fd: i32, text: []const u8) void {
    _ = linux.sendto(fd, text.ptr, text.len, linux.MSG.NOSIGNAL, null, 0);
}

// --- mounting ------------------------------------------------------------------

/// The filesystem a word names, found and mounted at its place.
fn mountWord(log: *Log, word: Word) !void {
    // Each from the kernel command line itself, never from init's record
    // of it under /run, which root in fence's domain can rewrite: the
    // asker may name a word, not a device.
    var cmdline_buf: [4096]u8 = undefined;
    const cmdline = readFile("/proc/cmdline", &cmdline_buf);
    const want: Want = switch (word) {
        .victim => parseUuid(before(
            ':',
            arg(cmdline, "werewolf.victim=") orelse return error.NoVictim,
        )) orelse
            return error.BadVictim,
        .grub => parseUuid(before(
            ':',
            arg(cmdline, "werewolf.grubenv=") orelse return error.NoGrubEnvironment,
        )) orelse
            return error.BadGrubEnvironment,
        .esp => parseSerial(arg(
            cmdline,
            "werewolf.esp=",
        ) orelse return error.NoEsp) orelse return error.BadEsp,
        .shutdown => unreachable,
    };
    var dev_buf: [64]u8 = undefined;
    const found = try find(want, &dev_buf);
    try attach(found.kind, found.dev, word.place());
    log.event(
        "mounted",
        .{
            .what = @tagName(word),
            .device = found.dev,
            .fs = @tagName(found.kind),
            .at = word.place(),
        },
    );
}

const Kind = enum { ext4, xfs, btrfs, vfat };
/// A device, and the kind of filesystem on it.
const Found = struct { dev: [:0]const u8, kind: Kind };
const Want = union(enum) { uuid: [16]u8, serial: u32 };

/// The one block device whose filesystem is want. Two that answer to it, as
/// a clone or snapshot of a disk attached beside it would, or two FAT
/// volumes sharing a 32-bit serial, are refused: which one GRUB reads is not
/// the broker's to guess, and an attached disk must not be mounted, and
/// written, in the real one's place.
fn find(want: Want, dev_buf: *[64]u8) !Found {
    const dir = linux.openat(
        linux.AT.FDCWD,
        "/sys/class/block",
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(dir) != .SUCCESS) return error.NoSuchFilesystem;
    defer _ = linux.close(@intCast(dir));
    var found: ?Found = null;
    var other_buf: [64]u8 = undefined;
    var buf: [4096]u8 align(8) = undefined;
    while (true) {
        const n = linux.getdents64(@intCast(dir), &buf, buf.len);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const ent: *align(1) const linux.dirent64 = @ptrCast(&buf[off]);
            off += ent.reclen;
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.name)), 0);
            if (name[0] == '.' or name.len > 32) continue;
            const into = if (found == null) dev_buf else &other_buf;
            const dev = std.mem.printSentinel(into, "/dev/{s}", .{name}, 0) catch continue;
            const kind = identifyDevice(dev, want) orelse continue;
            if (found != null) return error.TwoFilesystemsMatch;
            found = .{ .dev = dev, .kind = kind };
        }
    }
    return found orelse error.NoSuchFilesystem;
}

const btrfs_at = 0x10000;

fn identifyDevice(dev: [:0]const u8, want: Want) ?Kind {
    const fd = linux.openat(linux.AT.FDCWD, dev, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(fd));
    var buf: [btrfs_at + 0x1000]u8 = undefined;
    const n = linux.pread(@intCast(fd), &buf, buf.len, 0);
    if (linux.errno(n) != .SUCCESS) return null;
    const id = identify(buf[0..n]) orelse return null;
    return if (std.meta.eql(id.want, want)) id.kind else null;
}

/// The filesystem a device's first bytes describe, and what names it, as
/// each stores it: ext2/3/4 at 1 KiB in (magic 0xEF53), xfs at 0 ("XFSB"),
/// btrfs at 64 KiB in ("_BHRfS_M"), each by UUID; FAT by its volume serial,
/// beside "FAT32   " in a FAT32 boot sector, "FAT16   " or "FAT12   " in an
/// older one.
fn identify(b: []const u8) ?struct { kind: Kind, want: Want } {
    if (b.len >= 1024 + 0x78 and std.mem.readInt(u16, b[1024 + 0x38 ..][0..2], .little) == 0xEF53)
        return .{ .kind = .ext4, .want = .{ .uuid = b[1024 + 0x68 ..][0..16].* } };
    if (b.len >= 48 and std.mem.eql(u8, b[0..4], "XFSB"))
        return .{ .kind = .xfs, .want = .{ .uuid = b[32..48].* } };
    if (b.len >= btrfs_at + 0x48 and std.mem.eql(u8, b[btrfs_at + 0x40 ..][0..8], "_BHRfS_M"))
        return .{ .kind = .btrfs, .want = .{ .uuid = b[btrfs_at + 0x20 ..][0..16].* } };
    if (b.len >= 512 and b[510] == 0x55 and b[511] == 0xAA) {
        if (std.mem.eql(u8, b[0x52..0x5a], "FAT32   "))
            return .{
                .kind = .vfat,
                .want = .{ .serial = std.mem.readInt(u32, b[0x43..0x47], .little) },
            };
        if (std.mem.eql(u8, b[0x36..0x3e], "FAT16   ") or
            std.mem.eql(u8, b[0x36..0x3e], "FAT12   "))
            return .{
                .kind = .vfat,
                .want = .{ .serial = std.mem.readInt(u32, b[0x27..0x2b], .little) },
            };
    }
    return null;
}

// mount_setattr(2) and fsmount(2) attributes, and fsconfig(2) commands.
const attr_nosuid = 0x2;
const attr_nodev = 0x4;
const attr_noexec = 0x8;
const attr_nosymfollow = 0x200000;
/// FSOPEN_CLOEXEC and FSMOUNT_CLOEXEC, both.
const fs_cloexec = 1;
const fsconfig_set_string = 1;
const fsconfig_cmd_create = 6;
const move_mount_f_empty_path = 0x4;
const move_mount_t_empty_path = 0x40;

/// dev, a kind of filesystem, read-write at place: built detached with
/// nosuid, nodev, noexec and nosymfollow, then attached, so there is no
/// moment it lacks them.
fn attach(kind: Kind, dev: [:0]const u8, place: [:0]const u8) !void {
    const name: [:0]const u8 = @tagName(kind);
    const fc = try fdOf(
        linux.syscall2(.fsopen, @intFromPtr(name.ptr), fs_cloexec),
        "fsopen",
    );
    defer _ = linux.close(fc);
    _ = try sandbox.sys(
        linux.syscall5(
            .fsconfig,
            @bitCast(@as(isize, fc)),
            fsconfig_set_string,
            @intFromPtr("source"),
            @intFromPtr(dev.ptr),
            0,
        ),
        "fsconfig",
    );
    _ = try sandbox.sys(
        linux.syscall5(.fsconfig, @bitCast(@as(isize, fc)), fsconfig_cmd_create, 0, 0, 0),
        "fsconfig create",
    );
    const m = try fdOf(
        linux.syscall3(
            .fsmount,
            @bitCast(@as(isize, fc)),
            fs_cloexec,
            attr_nosuid | attr_nodev | attr_noexec | attr_nosymfollow,
        ),
        "fsmount",
    );
    defer _ = linux.close(m);
    const target = try fdOf(
        linux.openat(
            linux.AT.FDCWD,
            place,
            .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
            0,
        ),
        "open the mount point",
    );
    defer _ = linux.close(target);
    _ = try sandbox.sys(linux.syscall5(
        .move_mount,
        @bitCast(@as(isize, m)),
        @intFromPtr(""),
        @bitCast(@as(isize, target)),
        @intFromPtr(""),
        move_mount_f_empty_path | move_mount_t_empty_path,
    ), "move_mount");
}

fn fdOf(rc: usize, comptime what: []const u8) !i32 {
    return @intCast(try sandbox.sys(rc, what));
}

// --- shutdown ------------------------------------------------------------------

/// What stage 3 asks for last, as it did itself before fence: /data
/// unmounted, or read-only if something holds it; the LUKS mapping under
/// it closed; the victim's filesystem read-only, which writes what its
/// journal holds into place so the next boot's GRUB reads it, and /victim
/// unmounted if it can be. Each step done whatever the last one did.
fn shutdown(log: *Log) void {
    linux.sync();
    var mounts_buf: [16 << 10]u8 = undefined;
    const mounts = readFile("/proc/self/mounts", &mounts_buf);
    if (isMounted(mounts, "/data")) {
        if (linux.errno(linux.umount2("/data", 0)) == .SUCCESS) {
            log.event("shutdown", .{ .data = "unmounted" });
        } else if (remountReadOnly("/data")) {
            log.event("shutdown", .{ .data = "busy; read-only" });
        } else {
            log.event("shutdown", .{ .data = "busy; still writable" });
        }
    }
    if (dm.remove("data")) {
        log.event("shutdown", .{ .luks = "closed" });
    } else if (exists("/dev/mapper/data")) {
        log.event("shutdown", .{ .luks = "not closed" });
    }
    if (isMounted(mounts, "/victim")) {
        const journal = remountReadOnly("/victim");
        const unmounted = linux.errno(linux.umount2("/victim", 0)) == .SUCCESS;
        log.event("shutdown", .{ .victim_read_only = journal, .victim_unmounted = unmounted });
    }
}

/// The filesystem under dir read-only: mount(2)'s remount, which changes the
/// filesystem itself, and so writes its journal into place.
fn remountReadOnly(dir: [*:0]const u8) bool {
    return linux.errno(linux.mount(
        null,
        dir,
        null,
        linux.MS.REMOUNT | linux.MS.RDONLY,
        0,
    )) == .SUCCESS;
}

fn isMounted(mounts: []const u8, dir: []const u8) bool {
    var lines = std.mem.splitScalar(u8, mounts, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        _ = fields.next();
        if (std.mem.eql(u8, fields.next() orelse continue, dir)) return true;
    }
    return false;
}

// --- the machine's own record --------------------------------------------------

/// A file's bytes, as many as fit; none if it cannot be read.
fn exists(path: [*:0]const u8) bool {
    const fd = linux.open(path, .{ .PATH = true, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    _ = linux.close(@intCast(fd));
    return true;
}

fn readFile(path: [*:0]const u8, buf: []u8) []const u8 {
    const fd = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return "";
    defer _ = linux.close(@intCast(fd));
    var got: usize = 0;
    while (got < buf.len) {
        const n = linux.read(@intCast(fd), buf[got..].ptr, buf.len - got);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        got += n;
    }
    return buf[0..got];
}

/// The value of name=value among the kernel's arguments.
fn arg(cmdline: []const u8, comptime name: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeAny(u8, cmdline, " \n");
    while (it.next()) |a| if (std.mem.startsWith(u8, a, name)) return a[name.len..];
    return null;
}

fn before(c: u8, s: []const u8) []const u8 {
    return s[0 .. std.mem.findScalar(u8, s, c) orelse s.len];
}

/// 57e1f000-77e2-4b0f-8a3c-0000000000a0 as its 16 bytes, in order.
fn parseUuid(s: []const u8) ?Want {
    if (s.len != 36) return null;
    var out: [16]u8 = undefined;
    var j: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (s[i] != '-') return null;
            i += 1;
            continue;
        }
        out[j] = std.fmt.parseInt(u8, s[i .. i + 2], 16) catch return null;
        j += 1;
        i += 2;
    }
    return .{ .uuid = out };
}

/// A FAT volume's serial as blkid writes it, 57E1-F000.
fn parseSerial(s: []const u8) ?Want {
    if (s.len != 9 or s[4] != '-') return null;
    const hi = std.fmt.parseInt(u16, s[0..4], 16) catch return null;
    const lo = std.fmt.parseInt(u16, s[5..9], 16) catch return null;
    return .{ .serial = @as(u32, hi) << 16 | lo };
}

// --- the console ---------------------------------------------------------------

/// JSON lines on stdout: `mount-broker: {"time":...,"event":...,...}`.
const Log = struct {
    buf: [1024]u8 = undefined,

    fn event(l: *Log, name: []const u8, fields: anytype) void {
        var w: std.Io.Writer = .fixed(&l.buf);
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.REALTIME, &ts);
        const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(ts.sec) };
        const yd = es.getEpochDay().calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();
        w.print("mount-broker: {{\"time\":\"{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z\"," ++
            "\"event\":\"{s}\",", .{
            yd.year,              md.month.numeric(),      md.day_index + 1,
            ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
            name,
        }) catch return;
        const mark = w.end;
        std.json.Stringify.value(fields, .{}, &w) catch return;
        @memmove(l.buf[mark .. w.end - 1], l.buf[mark + 1 .. w.end]);
        w.end -= 1;
        w.writeByte('\n') catch return;
        _ = linux.write(1, w.buffered().ptr, w.buffered().len);
    }
};

const testing = std.testing;

test identify {
    var b: [btrfs_at + 0x1000]u8 = @splat(0);
    // ext4: magic at 1024 + 0x38, UUID at 1024 + 0x68.
    std.mem.writeInt(u16, b[1024 + 0x38 ..][0..2], 0xEF53, .little);
    @memcpy(b[1024 + 0x68 ..][0..16], &(parseUuid("57e1f000-77e2-4b0f-8a3c-0000000000a0").?.uuid));
    const ext4 = identify(&b).?;
    try testing.expectEqual(Kind.ext4, ext4.kind);
    try testing.expect(std.meta.eql(
        ext4.want,
        parseUuid("57e1f000-77e2-4b0f-8a3c-0000000000a0").?,
    ));

    // FAT32: the serial 57E1-F000, little-endian at 0x43.
    var fat: [512]u8 = @splat(0);
    fat[510] = 0x55;
    fat[511] = 0xAA;
    @memcpy(fat[0x52..0x5a], "FAT32   ");
    std.mem.writeInt(u32, fat[0x43..0x47], 0x57E1F000, .little);
    const esp = identify(&fat).?;
    try testing.expectEqual(Kind.vfat, esp.kind);
    try testing.expect(std.meta.eql(esp.want, parseSerial("57E1-F000").?));
    try testing.expect(!std.meta.eql(esp.want, parseSerial("57E1-F001").?));

    var nothing: [512]u8 = @splat(0);
    try testing.expectEqual(null, identify(&nothing));
}

test "the machine's own record" {
    const cmdline = "console=hvc0 werewolf.victim=57e1f000-77e2-4b0f-8a3c-0000000000a0:/var/lib/" ++
        "werewolf werewolf.esp=57E1-F000\n";
    try testing.expectEqualStrings(
        "57e1f000-77e2-4b0f-8a3c-0000000000a0",
        before(':', arg(cmdline, "werewolf.victim=").?),
    );
    try testing.expectEqualStrings("57E1-F000", arg(cmdline, "werewolf.esp=").?);
    try testing.expectEqual(null, arg(cmdline, "werewolf.grubenv="));
    for ([_][]const u8{
        "57E1F000",
        "57E1-F00",
        "57E1-G000",
        "",
    }) |bad| try testing.expectEqual(null, parseSerial(bad));
    for ([_][]const u8{
        "57e1f000-77e2-4b0f-8a3c-0000000000a",
        "57e1f000_77e2-4b0f-8a3c-0000000000a0",
        "",
    }) |bad|
        try testing.expectEqual(null, parseUuid(bad));
    try testing.expect(isMounted(
        "/dev/vda /victim ext4 ro 0 0\ntmpfs /run tmpfs rw 0 0\n",
        "/victim",
    ));
    try testing.expect(!isMounted("/dev/vda /victim2 ext4 ro 0 0\n", "/victim"));
}
