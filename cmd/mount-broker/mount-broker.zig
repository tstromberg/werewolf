//! mount-broker mounts the few filesystems root's programs need after boot,
//! when fence's Landlock domain forbids them to mount. Each connection sends
//! one word and holds its mount until it closes. See README.md.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const cmdline = @import("cmdline");
const dm = @import("dm");
const policy = @import("update-policy");
const signed = @import("prebuilt");
const broker = @import("broker");
const Sha256 = std.crypto.hash.sha2.Sha256;

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
    pid: i32 = 0,
    buf: [1024]u8 = undefined,
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
        "accept4",    "getsockopt",    "sendto",    "read",       "close",           "poll",
        "ppoll",      "openat",        "pread64",   "getdents64", "fsopen",          "fsconfig",
        "fsmount",    "move_mount",    "sync",      "write",      "mmap",            "munmap",
        "mremap",     "clock_gettime", "nanosleep", "exit_group", "restart_syscall", "pidfd_open",
        "readlinkat", "mkdirat",       "unlinkat",  "renameat",   "fsync",
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
        c.* = .{ .fd = fd, .pid = cred.pid };
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
    const request = c.buf[0..eol];
    if (std.mem.startsWith(u8, request, "esp-") or std.mem.startsWith(u8, request, "slot-")) {
        var buf: [1024]u8 = undefined;
        const text = handleEsp(log, c, request, &buf) catch |err|
            std.mem.print(&buf, "no {s}\n", .{@errorName(err)}) catch "no\n";
        reply(c.fd, text);
        return hangUp(log, c);
    }
    const word = std.meta.stringToEnum(Word, request) orelse {
        reply(c.fd, "no: grub, victim or shutdown\n");
        return hangUp(log, c);
    };
    if (word == .shutdown) {
        if (!authorizeService(log, c.pid, .stage)) {
            log.event("word refused", .{ .pid = c.pid, .word = "shutdown" });
            reply(c.fd, "no NotStageThree\n");
            return hangUp(log, c);
        }
        for (conns) |*other| if (other.holds != null) hangUp(log, other);
        shutdown(log);
        reply(c.fd, "ok\n");
        return hangUp(log, c);
    }
    // Mount words are lent only where they have a use: grub and the
    // victim only on a bitten machine (slot-keep's commit, the updater,
    // bite-cleanup), and the victim on a native machine only to the
    // updater's TPM retirement, which still writes its boot state there.
    // Everywhere else the slot files move through the operations above.
    {
        const ctx = bootContext();
        const services: []const Service = if (word == .victim and !ctx.bitten and ctx.release)
            &.{.updater}
        else
            &.{ .updater, .keeper, .bite };
        const situational = switch (word) {
            .grub => ctx.bitten,
            .victim => ctx.bitten or (ctx.release and authorizeService(log, c.pid, .updater)),
            .shutdown => unreachable,
        };
        var allowed = situational;
        if (allowed) {
            allowed = false;
            for (services) |s| if (authorizeService(log, c.pid, s)) {
                allowed = true;
                break;
            };
        }
        if (!allowed) {
            log.event("word refused", .{ .pid = c.pid, .word = @tagName(word) });
            reply(c.fd, "no NotHereOrNotService\n");
            return hangUp(log, c);
        }
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

/// makeMount returns a detached read-write mount of dev. The caller owns
/// the mount descriptor; closing it ends a mount that was never attached.
fn makeMount(kind: Kind, dev: [:0]const u8) !i32 {
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
    return fdOf(
        linux.syscall3(
            .fsmount,
            @bitCast(@as(isize, fc)),
            fs_cloexec,
            attr_nosuid | attr_nodev | attr_noexec | attr_nosymfollow,
        ),
        "fsmount",
    );
}

/// attach mounts dev read-write at place. The mount is built detached with
/// nosuid, nodev, noexec and nosymfollow, then attached, so it never
/// exists without them.
fn attach(kind: Kind, dev: [:0]const u8, place: [:0]const u8) !void {
    const m = try makeMount(kind, dev);
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

// --- the EFI partition ---------------------------------------------------------
//
// The ESP has no mount word. For these fixed operations the broker makes
// a detached mount, works through its descriptor, and closes it: the ESP
// is never attached where another process could reach it. Only the
// supervised slot-keep and slot-update services may ask; authorizeEsp
// checks the asking process, its parent supervisor, and its working
// directory, so an interactive root shell or a manually run binary is
// refused.

const stage_dir = "/data/svc/autoupdate/work/slot";
const max_staged: u64 = 192 << 20;

const Service = enum { updater, keeper, bite, stage };

fn handleEsp(log: *Log, c: *Conn, request: []const u8, out: []u8) ![]const u8 {
    const op = request[0 .. std.mem.findScalar(u8, request, ' ') orelse request.len];
    const service: Service = if (std.mem.eql(u8, op, "esp-status") or
        std.mem.eql(u8, op, "esp-commit"))
        .keeper
    else if (std.mem.eql(u8, op, "esp-disarm") or std.mem.eql(u8, op, "esp-arm") or
        std.mem.eql(u8, op, "esp-inspect") or std.mem.eql(u8, op, "esp-install") or
        std.mem.eql(u8, op, "slot-root") or std.mem.eql(u8, op, "slot-decl") or
        std.mem.eql(u8, op, "slot-meta"))
        .updater
    else
        return error.UnknownEspOperation;
    if (!authorizeService(log, c.pid, service)) {
        log.event("esp refused", .{ .pid = c.pid, .op = op, .service = @tagName(service) });
        return error.NotSlotService;
    }
    log.event("esp operation", .{ .pid = c.pid, .op = op });
    if (std.mem.eql(u8, op, "slot-root")) {
        try slotRootNow(try broker.parseSlotRoot(request));
        return "ok\n";
    }
    if (std.mem.eql(u8, op, "slot-decl")) {
        try slotDeclNow(try broker.parseSlotDecl(request));
        return "ok\n";
    }
    if (std.mem.eql(u8, op, "slot-meta")) {
        try slotMetaNow(try broker.parseSlotMeta(request));
        return "ok\n";
    }
    if (std.mem.eql(u8, op, "esp-status")) {
        return switch ((try espScan()).status) {
            .already => "ok already\n",
            .tried => "ok tried\n",
            .none => "ok none\n",
        };
    }
    if (std.mem.eql(u8, op, "esp-commit")) {
        try espCommitNow();
        return "ok\n";
    }
    if (std.mem.eql(u8, op, "esp-disarm")) {
        try espDeleteEntries((try bootSlots()).other);
        return "ok\n";
    }
    if (std.mem.eql(u8, op, "esp-arm")) {
        try espArmNow();
        return "ok\n";
    }
    if (std.mem.eql(u8, op, "esp-inspect")) return espInspectNow(out);
    const req = try broker.parseEspInstall(request);
    try espInstallNow(req);
    return "ok\n";
}

/// authorizeService reports whether pid is the service: for slot-keep,
/// slot-update and bite-cleanup the right binary in the right context,
/// checked while a pidfd pins the process. A refusal logs its stage, and
/// an identity mismatch logs what was observed, so a service that cannot
/// commit is diagnosable from the console alone.
fn authorizeService(log: *Log, pid: i32, service: Service) bool {
    if (pid <= 0) {
        log.event(
            "identity refused",
            .{ .pid = pid, .service = @tagName(service), .stage = "pid" },
        );
        return false;
    }
    const pidfd = linux.pidfd_open(@intCast(pid), 0);
    if (linux.errno(pidfd) != .SUCCESS) {
        log.event(
            "identity refused",
            .{
                .pid = pid,
                .service = @tagName(service),
                .stage = "pidfd",
                .errno = sandbox.errnoName(linux.errno(pidfd)),
            },
        );
        return false;
    }
    defer _ = linux.close(@intCast(pidfd));
    const start = procStart(pid) orelse {
        log.event(
            "identity refused",
            .{ .pid = pid, .service = @tagName(service), .stage = "start" },
        );
        return false;
    };
    if (!serviceIdentity(pid, service)) {
        log.event(
            "identity refused",
            .{ .pid = pid, .service = @tagName(service), .stage = "identity" },
        );
        logIdentity(log, pid);
        return false;
    }
    if (procStart(pid) != start) {
        log.event(
            "identity refused",
            .{ .pid = pid, .service = @tagName(service), .stage = "changed" },
        );
        return false;
    }
    return true;
}

/// logIdentity logs the identity fields authorizeService checks, as seen
/// in /proc at refusal time.
fn logIdentity(log: *Log, pid: i32) void {
    var exe_buf: [256]u8 = undefined;
    var cmd_buf: [512]u8 = undefined;
    var cwd_buf: [256]u8 = undefined;
    var pe_buf: [256]u8 = undefined;
    var pc_buf: [512]u8 = undefined;
    const ppid = procParent(pid) orelse 0;
    log.event("identity seen", .{
        .pid = pid,
        .exe = procLink(pid, "exe", &exe_buf) orelse "",
        .exe_errno = @tagName(linkErrno(pid, "exe")),
        .arg0 = procArg(procText(pid, "cmdline", &cmd_buf) orelse "", 0),
        .args = procArgs(procText2(pid, "cmdline", &cmd_buf) orelse ""),
        .cwd = procLink(pid, "cwd", &cwd_buf) orelse "",
        .cwd_errno = @tagName(linkErrno(pid, "cwd")),
        .ppid = ppid,
        .parent_exe = procLink(ppid, "exe", &pe_buf) orelse "",
        .parent_arg0 = procArg(procText(ppid, "cmdline", &pc_buf) orelse "", 0),
        .parent_arg1 = procArg(procText2(ppid, "cmdline", &pc_buf) orelse "", 1),
        .parent_args = procArgs(procText3(ppid, "cmdline", &pc_buf) orelse ""),
    });
}

fn serviceIdentity(pid: i32, service: Service) bool {
    var exe_buf: [256]u8 = undefined;
    var cmd_buf: [512]u8 = undefined;
    var cwd_buf: [256]u8 = undefined;
    var pe_buf: [256]u8 = undefined;
    var pc_buf: [512]u8 = undefined;
    const ppid = procParent(pid) orelse return false;
    return identityMatches(
        service,
        procLink(pid, "exe", &exe_buf) orelse return false,
        procArg(procText(pid, "cmdline", &cmd_buf) orelse return false, 0),
        procArgs(procText2(pid, "cmdline", &cmd_buf) orelse return false),
        procLink(pid, "cwd", &cwd_buf) orelse return false,
        procLink(ppid, "exe", &pe_buf) orelse return false,
        procArg(procText(ppid, "cmdline", &pc_buf) orelse return false, 0),
        procArg(procText2(ppid, "cmdline", &pc_buf) orelse return false, 1),
        procArgs(procText3(ppid, "cmdline", &pc_buf) orelse return false),
    );
}

// procText, procText2 and procText3 read the same file into the same
// buffer; they exist so a caller can take several slices of one read in
// one expression without the buffer being refilled between them. Each
// returns the same bytes.
fn procText(pid: i32, name: []const u8, buf: []u8) ?[]const u8 {
    return procRead(pid, name, buf);
}
fn procText2(pid: i32, name: []const u8, buf: []u8) ?[]const u8 {
    return procRead(pid, name, buf);
}
fn procText3(pid: i32, name: []const u8, buf: []u8) ?[]const u8 {
    return procRead(pid, name, buf);
}

fn procRead(pid: i32, name: []const u8, buf: []u8) ?[]const u8 {
    var path_buf: [64]u8 = undefined;
    const path = std.mem.printSentinel(
        &path_buf,
        "/proc/{d}/{s}",
        .{ pid, name },
        0,
    ) catch return null;
    const fd = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(fd));
    var got: usize = 0;
    while (got < buf.len) {
        const n = linux.read(@intCast(fd), buf[got..].ptr, buf.len - got);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS) return null;
        if (n == 0) break;
        got += n;
    }
    return buf[0..got];
}

/// linkErrno reports why reading pid's link name failed, or SUCCESS.
fn linkErrno(pid: i32, name: []const u8) linux.E {
    var path_buf: [64]u8 = undefined;
    var buf: [256]u8 = undefined;
    const path = std.mem.printSentinel(
        &path_buf,
        "/proc/{d}/{s}",
        .{ pid, name },
        0,
    ) catch return .INVAL;
    return linux.errno(linux.readlinkat(linux.AT.FDCWD, path, &buf, buf.len));
}

fn procLink(pid: i32, name: []const u8, buf: []u8) ?[]const u8 {
    if (pid <= 0) return null;
    const kind = std.meta.stringToEnum(broker.LinkKind, name) orelse return null;
    var request = broker.linkRequest(@intCast(pid), kind) catch return null;
    if (!linkTransfer(true, &request)) return null;
    var length: [2]u8 = undefined;
    if (!linkTransfer(false, &length)) return null;
    const n = std.mem.readInt(u16, &length, .little);
    if (n == 0 or n >= broker.link_limit or n > buf.len) return null;
    if (!linkTransfer(false, buf[0..n])) return null;
    return buf[0..n];
}

fn linkTransfer(write: bool, data: []u8) bool {
    var at: usize = 0;
    while (at < data.len) {
        const n = if (write)
            linux.write(0, data[at..].ptr, data.len - at)
        else
            linux.read(0, data[at..].ptr, data.len - at);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return false;
        at += n;
    }
    return true;
}

fn procParent(pid: i32) ?i32 {
    var buf: [1024]u8 = undefined;
    const text = procRead(pid, "status", &buf) orelse return null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "PPid:")) continue;
        return std.fmt.parseInt(i32, std.mem.trim(u8, line["PPid:".len..], " \t"), 10) catch null;
    }
    return null;
}

fn procStart(pid: i32) ?u64 {
    var buf: [2048]u8 = undefined;
    const text = procRead(pid, "stat", &buf) orelse return null;
    const close = std.mem.findScalarLast(u8, text, ')') orelse return null;
    var it = std.mem.tokenizeScalar(u8, text[close + 1 ..], ' ');
    var i: usize = 0;
    while (it.next()) |field| : (i += 1) {
        // Tokens after the comm are fields 3, 4, ...; starttime is 22.
        if (i == 19) return std.fmt.parseInt(u64, field, 10) catch null;
    }
    return null;
}

fn procArg(text: []const u8, n: usize) []const u8 {
    var it = std.mem.tokenizeScalar(u8, text, 0);
    var i: usize = 0;
    while (it.next()) |arg| : (i += 1) if (i == n) return arg;
    return "";
}

fn procArgs(text: []const u8) usize {
    var it = std.mem.tokenizeScalar(u8, text, 0);
    var n: usize = 0;
    while (it.next()) |_| n += 1;
    return n;
}

/// identityMatches is the service test authorizeService applies.
fn identityMatches(
    service: Service,
    exe: []const u8,
    arg0: []const u8,
    args: usize,
    cwd: []const u8,
    parent_exe: []const u8,
    parent_arg0: []const u8,
    parent_arg1: []const u8,
    parent_args: usize,
) bool {
    if (service == .bite)
        return std.mem.eql(u8, exe, "/usr/lib/werewolf/bite-cleanup") and args >= 1 and args <= 2;
    if (service == .stage)
        return std.mem.eql(u8, exe, "/usr/lib/werewolf/runit-stage") and
            (std.mem.eql(u8, arg0, "3") or std.mem.eql(u8, arg0, "/etc/runit/3")) and
            (std.mem.eql(u8, parent_exe, "/usr/bin/runit") or std.mem.eql(u8, parent_exe, "runit"));
    const want_exe, const name = switch (service) {
        .updater => .{ "/usr/lib/werewolf/slot-update", "autoupdate" },
        .keeper => .{ "/usr/lib/werewolf/slot-keep", "slot-keep" },
        .bite, .stage => unreachable,
    };
    var dir_buf: [64]u8 = undefined;
    var run_buf: [64]u8 = undefined;
    const dir = std.mem.print(&dir_buf, "/etc/sv/{s}", .{name}) catch return false;
    const run = std.mem.print(&run_buf, "/etc/sv/{s}/run", .{name}) catch return false;
    return std.mem.eql(u8, exe, want_exe) and args == 1 and
        (std.mem.eql(u8, arg0, "./run") or std.mem.eql(u8, arg0, run)) and
        std.mem.eql(u8, cwd, dir) and
        std.mem.eql(u8, parent_exe, "/usr/bin/runsv") and
        std.mem.eql(u8, parent_arg0, "runsv") and
        std.mem.eql(u8, parent_arg1, name) and parent_args == 2;
}

/// bootContext is the boot's shape: bitten (a GRUB environment is named)
/// and tpm (a release identity is sealed in the TPM).
fn bootContext() struct { bitten: bool, release: bool } {
    var cmdline_buf: [4096]u8 = undefined;
    var refused: cmdline.Failure = .{};
    const parsed = cmdline.parse(readFile("/proc/cmdline", &cmdline_buf), &refused) orelse
        return .{ .bitten = false, .release = false };
    return .{ .bitten = parsed.grubenv != null, .release = parsed.release != null };
}

fn bootSlots() !struct { current: []const u8, other: []const u8 } {
    var cmdline_buf: [4096]u8 = undefined;
    var refused: cmdline.Failure = .{};
    const parsed = cmdline.parse(readFile("/proc/cmdline", &cmdline_buf), &refused) orelse
        return error.BadCommandLine;
    const slot = parsed.slot orelse return error.NoSlot;
    return .{
        .current = @tagName(slot),
        .other = if (slot == .a) "b" else "a",
    };
}

fn espMount() !i32 {
    var cmdline_buf: [4096]u8 = undefined;
    var refused: cmdline.Failure = .{};
    const parsed = cmdline.parse(readFile("/proc/cmdline", &cmdline_buf), &refused) orelse
        return error.BadCommandLine;
    const serial = parsed.esp orelse return error.NoEsp;
    var dev_buf: [64]u8 = undefined;
    const found = try find(.{ .serial = serial }, &dev_buf);
    if (found.kind != .vfat) return error.NotEsp;
    return makeMount(found.kind, found.dev);
}

fn zBuf(buf: []u8, text: []const u8) ![:0]const u8 {
    return std.mem.printSentinel(buf, "{s}", .{text}, 0);
}

fn openAt(dirfd: i32, path: []const u8, flags: linux.O, mode: linux.mode_t) !i32 {
    var buf: [512]u8 = undefined;
    return fdOf(linux.openat(dirfd, try zBuf(&buf, path), flags, mode), "openat");
}

fn openDirAt(dirfd: i32, name: []const u8, create: bool) !i32 {
    if (create) {
        var buf: [128]u8 = undefined;
        const rc = linux.mkdirat(dirfd, try zBuf(&buf, name), 0o700);
        if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .EXIST) return error.MkdirFailed;
    }
    return openAt(
        dirfd,
        name,
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    );
}

fn readAt(dirfd: i32, path: []const u8, buf: []u8) ![]const u8 {
    const fd = try openAt(
        dirfd,
        path,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    );
    defer _ = linux.close(fd);
    var got: usize = 0;
    while (true) {
        if (got == buf.len) return error.TooLarge;
        const n = linux.read(fd, buf[got..].ptr, buf.len - got);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS) return error.ReadFailed;
        if (n == 0) return buf[0..got];
        got += n;
    }
}

fn writeAll(fd: i32, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        const n = linux.write(fd, data[off..].ptr, data.len - off);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return error.WriteFailed;
        off += n;
    }
}

/// writeFileAt writes data as name in dirfd through a temporary name, so a
/// crash leaves either the old file or the new one.
fn writeFileAt(dirfd: i32, name: []const u8, data: []const u8) !void {
    var tmp_buf: [160]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, "{s}.tmp", .{name});
    const fd = try openAt(
        dirfd,
        tmp,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true, .CLOEXEC = true },
        0o700,
    );
    defer _ = linux.close(fd);
    try writeAll(fd, data);
    if (linux.errno(linux.fsync(fd)) != .SUCCESS) return error.SyncFailed;
    var from_buf: [160]u8 = undefined;
    var to_buf: [160]u8 = undefined;
    const rc = linux.renameat(dirfd, try zBuf(&from_buf, tmp), dirfd, try zBuf(&to_buf, name));
    if (linux.errno(rc) != .SUCCESS) return error.RenameFailed;
}

fn unlinkAt(dirfd: i32, name: []const u8) !void {
    var buf: [160]u8 = undefined;
    const rc = linux.unlinkat(dirfd, try zBuf(&buf, name), 0);
    if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .NOENT) return error.UnlinkFailed;
}

const Names = struct {
    buf: [32][128]u8 = undefined,
    lens: [32]usize = undefined,
    count: usize = 0,

    fn get(n: *const Names, i: usize) []const u8 {
        return n.buf[i][0..n.lens[i]];
    }
    fn sort(n: *Names) void {
        var i: usize = 1;
        while (i < n.count) : (i += 1) {
            var j = i;
            while (j > 0 and std.mem.order(u8, n.get(j), n.get(j - 1)) == .lt) : (j -= 1) {
                std.mem.swap([128]u8, &n.buf[j], &n.buf[j - 1]);
                std.mem.swap(usize, &n.lens[j], &n.lens[j - 1]);
            }
        }
    }
};

fn listNames(dirfd: i32) !Names {
    var names: Names = .{};
    var buf: [4096]u8 align(8) = undefined;
    while (true) {
        const n = linux.getdents64(dirfd, &buf, buf.len);
        if (linux.errno(n) != .SUCCESS) return error.ListFailed;
        if (n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const ent: *align(1) const linux.dirent64 = @ptrCast(&buf[off]);
            off += ent.reclen;
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.name)), 0);
            if (name[0] == '.' or name.len >= 128) continue;
            if (names.count == names.buf.len) return error.TooManyEntries;
            @memcpy(names.buf[names.count][0..name.len], name);
            names.lens[names.count] = name.len;
            names.count += 1;
        }
    }
    names.sort();
    return names;
}

const EspScan = struct {
    status: broker.EspStatus,
    tried: [128]u8 = undefined,
    tried_len: usize = 0,
};

fn espScan() !EspScan {
    const m = try espMount();
    defer _ = linux.close(m);
    return espScanMount(m);
}

fn espScanMount(m: i32) !EspScan {
    const slots = try bootSlots();
    var base_buf: [32]u8 = undefined;
    const base = try std.mem.print(&base_buf, "werewolf-{s}", .{slots.current});
    var good_buf: [40]u8 = undefined;
    const good = try std.mem.print(&good_buf, "{s}.conf", .{base});
    const loader = openDirAt(m, "loader", false) catch return .{ .status = .none };
    defer _ = linux.close(loader);
    const entries = openDirAt(loader, "entries", false) catch return .{ .status = .none };
    defer _ = linux.close(entries);
    var scan: EspScan = .{ .status = .none };
    const names = try listNames(entries);
    for (0..names.count) |i| {
        const name = names.get(i);
        if (std.mem.eql(u8, name, good)) return .{ .status = .already };
        if (signed.isCountingEntry(name, base) and scan.status == .none) {
            scan.status = .tried;
            @memcpy(scan.tried[0..name.len], name);
            scan.tried_len = name.len;
        }
    }
    return scan;
}

fn espCommitNow() !void {
    const m = try espMount();
    defer _ = linux.close(m);
    const scan = try espScanMount(m);
    if (scan.status == .already) return;
    if (scan.status == .none) return error.NoEntry;
    const slots = try bootSlots();
    const loader = try openDirAt(m, "loader", false);
    defer _ = linux.close(loader);
    const entries = try openDirAt(loader, "entries", false);
    defer _ = linux.close(entries);
    var good_buf: [40]u8 = undefined;
    const good = try std.mem.print(&good_buf, "werewolf-{s}.conf", .{slots.current});
    var from_buf: [160]u8 = undefined;
    var to_buf: [160]u8 = undefined;
    const rc = linux.renameat(
        entries,
        try zBuf(&from_buf, scan.tried[0..scan.tried_len]),
        entries,
        try zBuf(&to_buf, good),
    );
    if (linux.errno(rc) != .SUCCESS) return error.RenameFailed;
    if (linux.errno(linux.fsync(entries)) != .SUCCESS) return error.SyncFailed;
    linux.sync();
}

fn espSlotDir(m: i32, slot: []const u8, create: bool) !i32 {
    const werewolf = try openDirAt(m, "werewolf", create);
    defer _ = linux.close(werewolf);
    return openDirAt(werewolf, slot, create);
}

fn espEntriesDir(m: i32, create: bool) !i32 {
    const loader = try openDirAt(m, "loader", create);
    defer _ = linux.close(loader);
    return openDirAt(loader, "entries", create);
}

fn espDeleteEntries(slot: []const u8) !void {
    const m = try espMount();
    defer _ = linux.close(m);
    const entries = espEntriesDir(m, false) catch return;
    defer _ = linux.close(entries);
    const names = try listNames(entries);
    for (0..names.count) |i| {
        if (signed.isEntryOf(names.get(i), slot)) try unlinkAt(entries, names.get(i));
    }
    if (linux.errno(linux.fsync(entries)) != .SUCCESS) return error.SyncFailed;
    linux.sync();
}

fn espNewest(entries: i32) !i64 {
    var newest: i64 = 0;
    const names = try listNames(entries);
    for (0..names.count) |i| {
        if (!std.mem.startsWith(u8, names.get(i), "werewolf-")) continue;
        var buf: [4096]u8 = undefined;
        const text = readAt(entries, names.get(i), &buf) catch continue;
        if (signed.entrySecs(text)) |secs| newest = @max(newest, secs);
    }
    return newest;
}

fn espVersion(newest: i64) ![20]u8 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    var buf: [20]u8 = undefined;
    _ = try std.mem.print(&buf, "{f}", .{policy.Serial{ .secs = @max(ts.sec, newest + 1) }});
    return buf;
}

fn espArmNow() !void {
    const m = try espMount();
    defer _ = linux.close(m);
    const slots = try bootSlots();
    const slot_dir = try espSlotDir(m, slots.other, false);
    defer _ = linux.close(slot_dir);
    const uki = blk: {
        const fd = openAt(
            slot_dir,
            "uki.efi",
            .{ .ACCMODE = .RDONLY, .PATH = true, .NOFOLLOW = true, .CLOEXEC = true },
            0,
        ) catch break :blk false;
        _ = linux.close(fd);
        break :blk true;
    };
    const entries = try espEntriesDir(m, false);
    defer _ = linux.close(entries);
    var backing: [64 << 10]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const gpa = fba.allocator();
    var options: []const u8 = "";
    var found = false;
    const names = try listNames(entries);
    for (0..names.count) |i| {
        const name = names.get(i);
        if (!signed.isEntryOf(name, slots.other)) continue;
        var buf: [4096]u8 = undefined;
        options = try signed.rollbackOptions(
            gpa,
            try readAt(entries, name, &buf),
            slots.other,
            uki,
        );
        found = true;
    }
    if (!found) return error.NoOtherSlotEntry;
    const newest = try espNewest(entries);
    for (0..names.count) |i| {
        if (signed.isEntryOf(names.get(i), slots.other)) try unlinkAt(entries, names.get(i));
    }
    const version = try espVersion(newest);
    const entry = try signed.loaderEntry(gpa, slots.other, &version, options, uki);
    var name_buf: [64]u8 = undefined;
    const name = try std.mem.print(&name_buf, "werewolf-{s}+1.conf", .{slots.other});
    try writeFileAt(entries, name, entry);
    if (linux.errno(linux.fsync(entries)) != .SUCCESS) return error.SyncFailed;
    linux.sync();
}

const Digest = struct { size: u64, hex: [64]u8 };

fn digestFd(fd: i32) !Digest {
    var hash: Sha256 = .init(.{});
    var total: u64 = 0;
    var buf: [64 << 10]u8 = undefined;
    while (true) {
        const n = linux.read(fd, &buf, buf.len);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS) return error.ReadFailed;
        if (n == 0) break;
        hash.update(buf[0..n]);
        total += n;
        if (total > max_staged) return error.TooLarge;
    }
    var out: [Sha256.digest_length]u8 = undefined;
    hash.final(&out);
    return .{ .size = total, .hex = std.fmt.bytesToHex(out, .lower) };
}

fn digestAt(dirfd: i32, name: []const u8) !?Digest {
    const fd = openAt(
        dirfd,
        name,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    ) catch |err| {
        if (err == error.SystemCall and sandbox.failed_errno == .NOENT) return null;
        return err;
    };
    defer _ = linux.close(fd);
    return try digestFd(fd);
}

/// copyChecked copies the file at src into dirfd as dest, through a
/// temporary name, only if its bytes match want's size and SHA-256.
fn copyChecked(
    dirfd: i32,
    src: []const u8,
    dest: []const u8,
    want: broker.EspArtifact,
    limit: u64,
) !void {
    if (want.size > limit) return error.TooLarge;
    const sfd = try openAt(
        linux.AT.FDCWD,
        src,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    );
    defer _ = linux.close(sfd);
    var tmp_buf: [160]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, "{s}.tmp", .{dest});
    const dst = try openAt(
        dirfd,
        tmp,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true, .CLOEXEC = true },
        0o700,
    );
    defer _ = linux.close(dst);
    var hash: Sha256 = .init(.{});
    var total: u64 = 0;
    var buf: [64 << 10]u8 = undefined;
    while (true) {
        const n = linux.read(sfd, &buf, buf.len);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS) return error.ReadFailed;
        if (n == 0) break;
        hash.update(buf[0..n]);
        try writeAll(dst, buf[0..n]);
        total += n;
        if (total > want.size) return error.DigestMismatch;
    }
    if (total != want.size) return error.DigestMismatch;
    var out: [Sha256.digest_length]u8 = undefined;
    hash.final(&out);
    if (!std.mem.eql(
        u8,
        &std.fmt.bytesToHex(out, .lower),
        want.sha256,
    )) return error.DigestMismatch;
    if (linux.errno(linux.fsync(dst)) != .SUCCESS) return error.SyncFailed;
    var from_buf: [160]u8 = undefined;
    var to_buf: [160]u8 = undefined;
    const rc = linux.renameat(dirfd, try zBuf(&from_buf, tmp), dirfd, try zBuf(&to_buf, dest));
    if (linux.errno(rc) != .SUCCESS) return error.RenameFailed;
    if (linux.errno(linux.fsync(dirfd)) != .SUCCESS) return error.SyncFailed;
}

fn espInstallNow(req: broker.EspInstall) !void {
    const m = try espMount();
    defer _ = linux.close(m);
    const slots = try bootSlots();
    // The staged command line is verified before anything on the ESP
    // changes: confined root can write the staging directory, so its
    // bytes are trusted only as the updater's named digest describes.
    var line_buf: [8192]u8 = undefined;
    const staged_cmdline = try readAt(linux.AT.FDCWD, stage_dir ++ "/cmdline", &line_buf);
    const slot_cmdline = try signed.cmdline(staged_cmdline);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(staged_cmdline, &digest, .{});
    if (staged_cmdline.len != req.cmdline.size or
        !std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), req.cmdline.sha256))
        return error.DigestMismatch;
    const entries = try espEntriesDir(m, true);
    defer _ = linux.close(entries);
    const names = try listNames(entries);
    for (0..names.count) |i| {
        if (signed.isEntryOf(names.get(i), slots.other)) try unlinkAt(entries, names.get(i));
    }
    const slot_dir = try espSlotDir(m, slots.other, true);
    defer _ = linux.close(slot_dir);
    try copyChecked(slot_dir, stage_dir ++ "/vmlinuz", "vmlinuz", req.vmlinuz, max_staged);
    try copyChecked(slot_dir, stage_dir ++ "/stage0.zst", "stage0.zst", req.stage0, max_staged);
    if (req.uki) |uki| {
        try copyChecked(slot_dir, stage_dir ++ "/uki.efi", "uki.efi", uki, max_staged);
    } else {
        try unlinkAt(slot_dir, "uki.efi");
    }
    var backing: [64 << 10]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const gpa = fba.allocator();
    var cmd_buf: [8192]u8 = undefined;
    const boot_cmdline = readFile("/proc/cmdline", cmd_buf[0..4096]);
    const options = try signed.withSlot(gpa, boot_cmdline, slot_cmdline, slots.other);
    const newest = try espNewest(entries);
    const version = try espVersion(newest);
    const entry = try signed.loaderEntry(gpa, slots.other, &version, options, req.uki != null);
    var name_buf: [64]u8 = undefined;
    const name = try std.mem.print(&name_buf, "werewolf-{s}+1.conf", .{slots.other});
    try writeFileAt(entries, name, entry);
    if (linux.errno(linux.fsync(entries)) != .SUCCESS) return error.SyncFailed;
    linux.sync();
}

fn victimMount() !i32 {
    var cmdline_buf: [4096]u8 = undefined;
    var refused: cmdline.Failure = .{};
    const parsed = cmdline.parse(readFile("/proc/cmdline", &cmdline_buf), &refused) orelse
        return error.BadCommandLine;
    const v = parsed.victim orelse return error.NoVictim;
    var dev_buf: [64]u8 = undefined;
    const found = try find(.{ .uuid = cmdline.uuid(v.uuid).? }, &dev_buf);
    return makeMount(found.kind, found.dev);
}

/// victimSlotDir opens (creating if asked) the slot's directory on the
/// victim filesystem: the victim path's components, then the slot.
fn victimSlotDir(m: i32, slot: []const u8, create: bool) !i32 {
    var cmdline_buf: [4096]u8 = undefined;
    var refused: cmdline.Failure = .{};
    const parsed = cmdline.parse(readFile("/proc/cmdline", &cmdline_buf), &refused) orelse
        return error.BadCommandLine;
    var fd = m;
    var owned = false;
    errdefer {
        if (owned) _ = linux.close(fd);
    }
    var parts = std.mem.splitScalar(u8, parsed.victim.?.path, '/');
    while (parts.next()) |part| {
        if (part.len == 0) continue;
        const next = try openDirAt(fd, part, create);
        if (owned) _ = linux.close(fd);
        fd = next;
        owned = true;
    }
    const slot_fd = try openDirAt(fd, slot, create);
    if (owned) _ = linux.close(fd);
    return slot_fd;
}

fn slotRootNow(want: broker.EspArtifact) !void {
    const m = try victimMount();
    defer _ = linux.close(m);
    const slots = try bootSlots();
    const dir = try victimSlotDir(m, slots.other, true);
    defer _ = linux.close(dir);
    try copyChecked(dir, stage_dir ++ "/root.erofs", "root.erofs", want, 16 << 30);
    linux.sync();
}

fn slotDeclNow(decl: broker.SlotDecl) !void {
    const m = try victimMount();
    defer _ = linux.close(m);
    const slots = try bootSlots();
    if (decl.current) |text| {
        const dir = try victimSlotDir(m, slots.current, true);
        defer _ = linux.close(dir);
        try writeFileAt(dir, "declaration", text);
    }
    if (decl.next) |text| {
        const dir = try victimSlotDir(m, slots.other, true);
        defer _ = linux.close(dir);
        try writeFileAt(dir, "declaration", text);
    }
    linux.sync();
}

fn slotMetaNow(meta: broker.SlotMeta) !void {
    const m = try victimMount();
    defer _ = linux.close(m);
    const slots = try bootSlots();
    const dir = try victimSlotDir(m, slots.other, true);
    defer _ = linux.close(dir);
    try copyChecked(
        dir,
        "/data/svc/autoupdate/work/image.json",
        "image.json",
        meta.manifest,
        max_staged,
    );
    try copyChecked(
        dir,
        "/data/svc/autoupdate/work/image.json.sig",
        "image.json.sig",
        meta.signature,
        max_staged,
    );
    try copyChecked(dir, stage_dir ++ "/cmdline", "cmdline", meta.cmdline_file, max_staged);
    linux.sync();
}

fn espInspectNow(out: []u8) ![]const u8 {
    const m = try espMount();
    defer _ = linux.close(m);
    const slots = try bootSlots();
    const slot_dir = espSlotDir(m, slots.other, false) catch {
        return std.mem.print(out, "ok k=- s=- u=-\n", .{});
    };
    defer _ = linux.close(slot_dir);
    const k = try digestAt(slot_dir, "vmlinuz");
    const s = try digestAt(slot_dir, "stage0.zst");
    const u = try digestAt(slot_dir, "uki.efi");
    var w: std.Io.Writer = .fixed(out);
    try w.writeAll("ok ");
    inline for (.{ "k", "s", "u" }, .{ k, s, u }, 0..) |key, file, i| {
        if (i > 0) try w.writeAll(" ");
        try w.print("{s}=", .{key});
        if (file) |f| try w.print("{d}:{s}", .{ f.size, &f.hex }) else try w.writeAll("-");
    }
    try w.writeAll("\n");
    return w.buffered();
}

test "esp service identity accepts only the supervised services" {
    try std.testing.expect(identityMatches(
        .updater,
        "/usr/lib/werewolf/slot-update",
        "./run",
        1,
        "/etc/sv/autoupdate",
        "/usr/bin/runsv",
        "runsv",
        "autoupdate",
        2,
    ));
    try std.testing.expect(identityMatches(
        .keeper,
        "/usr/lib/werewolf/slot-keep",
        "/etc/sv/slot-keep/run",
        1,
        "/etc/sv/slot-keep",
        "/usr/bin/runsv",
        "runsv",
        "slot-keep",
        2,
    ));
    // An interactive root shell running the same binary is not the service.
    try std.testing.expect(!identityMatches(
        .updater,
        "/usr/lib/werewolf/slot-update",
        "./run",
        1,
        "/root",
        "/usr/bin/sshd",
        "sshd",
        "autoupdate",
        2,
    ));
    try std.testing.expect(!identityMatches(
        .updater,
        "/usr/lib/werewolf/slot-update",
        "check",
        2,
        "/etc/sv/autoupdate",
        "/usr/bin/runsv",
        "runsv",
        "autoupdate",
        2,
    ));
    // bite-cleanup and stage 3 are recognized by program alone; their own
    // situational checks (a bitten, committed machine; shutdown) gate them.
    try std.testing.expect(identityMatches(
        .bite,
        "/usr/lib/werewolf/bite-cleanup",
        "bite-cleanup",
        1,
        "/root",
        "/usr/bin/ash",
        "ash",
        "",
        1,
    ));
    try std.testing.expect(!identityMatches(
        .bite,
        "/usr/lib/werewolf/bite-cleanup",
        "bite-cleanup",
        3,
        "/root",
        "/usr/bin/ash",
        "ash",
        "",
        1,
    ));
    try std.testing.expect(identityMatches(
        .stage,
        "/usr/lib/werewolf/runit-stage",
        "/etc/runit/3",
        1,
        "/",
        "/usr/bin/runit",
        "runit",
        "",
        1,
    ));
    try std.testing.expect(!identityMatches(
        .stage,
        "/usr/lib/werewolf/runit-stage",
        "/etc/runit/3",
        1,
        "/root",
        "/usr/bin/sshd",
        "sshd",
        "",
        1,
    ));
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
