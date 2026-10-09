//! mount-broker mounts the few filesystems root's programs need after boot,
//! when fence's Landlock domain forbids them to mount. Each connection sends
//! one word and holds its mount until it closes. See README.md.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const cmdline = @import("cmdline");
const dm = @import("dm");
const broker = @import("broker");

const socket_path = broker.socket_path;
const mnt_dir = broker.mnt_dir;
const cap_sys_admin = 21;
const max_conns = 8;

/// Word comes from lib/broker.zig, so an asker checks the answer against
/// the same places.
const Word = broker.Word;

/// Conn is a connection: what it has sent so far and the mount it holds.
/// If the asker is gone but its mount is busy, the Conn stays an orphan
/// (fd closed, holds set) until a plain unmount succeeds.
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

/// setUp makes the mount points and the listening socket, then confines
/// the process, all before anyone can ask.
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
    // umask 077 makes the socket root's alone from the moment it exists.
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
    // Classic mount(2) may only remount read-only (at shutdown), and
    // umount2 may not detach lazily, so neither can mount or move anything.
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
        // Wake each second while an orphaned mount waits to be unmounted.
        var waiting = false;
        for (conns) |c| if (c.orphan()) {
            waiting = true;
        };
        const n = linux.poll(&fds, fds.len, if (waiting) 1000 else -1);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            // Not a reason to stop: the machine needs the broker to keep
            // its slots. Pause rather than spin.
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

/// accept takes a new asker, turning it away unless it is root and there
/// is a free Conn.
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

/// heard reads from an asker and acts on its word, or hangs up.
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

/// hangUp closes c's connection and releases what it held.
fn hangUp(log: *Log, c: *Conn) void {
    if (c.open()) _ = linux.close(c.fd);
    c.fd = -1;
    c.len = 0;
    if (c.holds != null) release(log, c, true);
}

/// release unmounts c's mount plainly, never lazily: a lazy unmount would
/// hide a mount some process still has open, and the broker would report
/// it gone and mount it again for the next asker. If it is busy, c keeps
/// the word and serve retries each second. first is true on the first try,
/// which alone logs the busy refusal.
fn release(log: *Log, c: *Conn, first: bool) void {
    const w = c.holds.?;
    const err = linux.errno(linux.umount2(w.place(), 0));
    if (err == .BUSY) {
        if (first) log.event("busy", .{ .what = @tagName(w), .held = "by a process still" });
        return;
    }
    // EINVAL means it is no longer a mount; either way it is gone.
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

/// Ucred is the kernel's struct ucred, as SO_PEERCRED returns it.
const Ucred = extern struct { pid: i32, uid: u32, gid: u32 };

fn reply(fd: i32, text: []const u8) void {
    _ = linux.sendto(fd, text.ptr, text.len, linux.MSG.NOSIGNAL, null, 0);
}

// --- mounting ------------------------------------------------------------------

/// mountWord finds the filesystem word names and mounts it at its place.
fn mountWord(log: *Log, word: Word) !void {
    // Read the kernel command line itself, never a copy under /run, which
    // root in fence's domain could rewrite: the asker names a word, not a
    // device.
    var cmdline_buf: [4096]u8 = undefined;
    var refused: cmdline.Failure = .{};
    const cmd = cmdline.parse(readFile("/proc/cmdline", &cmdline_buf), &refused) orelse
        return error.BadCommandLine;
    // parse checked each place's UUID, so .? holds.
    const want: Want = switch (word) {
        .victim => .{ .uuid = cmdline.uuid((cmd.victim orelse return error.NoVictim).uuid).? },
        .grub => .{
            .uuid = cmdline.uuid((cmd.grubenv orelse return error.NoGrubEnvironment).uuid).?,
        },
        .esp => .{ .serial = cmd.esp orelse return error.NoEsp },
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
/// Found is a device and the kind of filesystem on it.
const Found = struct { dev: [:0]const u8, kind: Kind };
const Want = union(enum) { uuid: [16]u8, serial: u32 };

/// find returns the one block device whose filesystem is want. It fails if
/// two match (a clone or snapshot attached beside the disk, or two FAT
/// volumes sharing a serial): an attached disk must not be mounted and
/// written in the real one's place.
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

/// identify returns the filesystem in a device's first bytes and its UUID
/// or serial: ext2/3/4 at 1 KiB (magic 0xEF53), xfs at 0 ("XFSB"), btrfs at
/// 64 KiB ("_BHRfS_M"), and FAT by the volume serial in its boot sector.
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
/// fs_cloexec is both FSOPEN_CLOEXEC and FSMOUNT_CLOEXEC.
const fs_cloexec = 1;
const fsconfig_set_string = 1;
const fsconfig_cmd_create = 6;
const move_mount_f_empty_path = 0x4;
const move_mount_t_empty_path = 0x40;

/// attach mounts dev read-write at place. The mount is built detached with
/// nosuid, nodev, noexec and nosymfollow, then attached, so it never
/// exists without them.
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

/// shutdown, asked for last by stage 3, unmounts /data (or remounts it
/// read-only if busy), closes its LUKS mapping, and remounts /victim
/// read-only, which writes its journal in place for GRUB, then tries to
/// unmount it. Each step runs whatever the last one did.
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

/// remountReadOnly makes the filesystem under dir read-only. A classic
/// remount changes the filesystem itself, so it writes its journal in place.
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

// --- files ---------------------------------------------------------------------

/// exists reports whether path can be opened.
fn exists(path: [*:0]const u8) bool {
    const fd = linux.open(path, .{ .PATH = true, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    _ = linux.close(@intCast(fd));
    return true;
}

/// readFile reads as much of path as fits in buf, or nothing if it cannot.
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

// --- the console ---------------------------------------------------------------

/// Log writes events as JSON lines on stdout:
/// `mount-broker: {"time":...,"event":...,...}`.
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
    const id = cmdline.uuid("57e1f000-77e2-4b0f-8a3c-0000000000a0").?;
    @memcpy(b[1024 + 0x68 ..][0..16], &id);
    const ext4 = identify(&b).?;
    try testing.expectEqual(Kind.ext4, ext4.kind);
    try testing.expect(std.meta.eql(ext4.want, Want{ .uuid = id }));

    // FAT32: the serial 57E1-F000, little-endian at 0x43.
    var fat: [512]u8 = @splat(0);
    fat[510] = 0x55;
    fat[511] = 0xAA;
    @memcpy(fat[0x52..0x5a], "FAT32   ");
    std.mem.writeInt(u32, fat[0x43..0x47], 0x57E1F000, .little);
    const esp = identify(&fat).?;
    try testing.expectEqual(Kind.vfat, esp.kind);
    try testing.expect(std.meta.eql(esp.want, Want{ .serial = cmdline.serial("57E1-F000").? }));
    try testing.expect(!std.meta.eql(esp.want, Want{ .serial = cmdline.serial("57E1-F001").? }));

    var nothing: [512]u8 = @splat(0);
    try testing.expectEqual(null, identify(&nothing));
}

test isMounted {
    try testing.expect(isMounted(
        "/dev/vda /victim ext4 ro 0 0\ntmpfs /run tmpfs rw 0 0\n",
        "/victim",
    ));
    try testing.expect(!isMounted("/dev/vda /victim2 ext4 ro 0 0\n", "/victim"));
}
