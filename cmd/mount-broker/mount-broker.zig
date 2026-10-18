//! mount-broker mounts the few filesystems root's programs need after boot,
//! when fence's Landlock domain forbids them to mount. Callers ask over three
//! inherited socketpairs (updater, keeper, stage). See README.md.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const cmdline = @import("cmdline");
const dm = @import("dm");
const policy = @import("update-policy");
const signed = @import("prebuilt");
const broker = @import("broker");
const Sha256 = std.crypto.hash.sha2.Sha256;

const cap_sys_admin = 21;
const roles = [_]broker.Role{ .updater, .keeper, .stage };
var reboot_flag: i32 = -1;
var stop_flag: i32 = -1;
var owner_device: ?i32 = null;

pub fn main() !void {
    var log: Log = .{};
    setUp() catch |err| {
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
    log.event("listening", .{ .channels = roles.len });
    serve(&log);
}

/// setUp verifies the inherited role descriptors, closes everything above
/// them, and confines the process before serving.
fn setUp() !void {
    for (roles) |role| {
        const fd = broker.serverFd(role);
        _ = try sandbox.sys(linux.fcntl(fd, linux.F.SETFD, linux.FD_CLOEXEC), "fcntl");
    }
    _ = try sandbox.sys(
        linux.close_range(6, std.math.maxInt(linux.fd_t), .{ .UNSHARE = false, .CLOEXEC = false }),
        "close_range",
    );
    reboot_flag = try runitFlag("/run/runit/reboot");
    stop_flag = try runitFlag("/run/runit/stopit");
    {
        var threaded: std.Io.Threaded = .init_single_threaded;
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        owner_device = try broker.openOwnerPort(threaded.io(), arena.allocator());
    }
    var updater_group: linux.gid_t = 77;
    _ = try sandbox.sys(
        linux.setgroups(1, @ptrCast(&updater_group)),
        "broker read-publication group",
    );
    try sandbox.keepOnly(1 << cap_sys_admin);
    var f: sandbox.Filter = .{};
    inline for (.{
        "recvfrom",        "sendto",   "sendmsg",  "read",     "write",         "close",     "poll",
        "ppoll",           "openat",   "openat2",  "fstat",    "statx",         "pread64",   "getdents64",
        "fsopen",          "fsconfig", "fsmount",  "sync",     "mmap",          "munmap",    "mremap",
        "fsync",           "mkdirat",  "unlinkat", "renameat", "clock_gettime", "nanosleep", "exit_group",
        "restart_syscall",
    }) |name| f.allow(name);
    f.allowArg("fchmod", 1, 0o640);
    f.allowArg("fchmod", 1, 0o750);
    f.allowTwo("fchown", 1, std.math.maxInt(u32), 2, 77);
    f.allowTwo("fchmod", 0, @intCast(reboot_flag), 1, 0o100);
    f.allowTwo("fchmod", 0, @intCast(stop_flag), 1, 0o100);
    f.allowTwo("kill", 0, 1, 1, @backingInt(linux.SIG.CONT));
    f.allowArg("open_tree", 2, open_tree_flags);
    f.allowArg("move_mount", 4, move_mount_f_empty_path | move_mount_t_empty_path);
    f.allowTwo("mount_setattr", 2, linux.AT.EMPTY_PATH, 4, @sizeOf(MountAttr));
    f.allowArg("ioctl", 1, dm.dev_remove);
    // Classic mount(2) may only remount read-only (at shutdown), and
    // umount2 may not detach lazily, so neither can mount or move anything.
    f.allowArg("mount", 3, linux.MS.REMOUNT | linux.MS.RDONLY);
    f.allowArg("umount2", 1, 0);
    try f.install();
}

fn runitFlag(path: [:0]const u8) !i32 {
    const fd = try fdOf(linux.open(path, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0), "open broker runit flag");
    errdefer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    _ = try sandbox.sys(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{
        .TYPE = true,
        .MODE = true,
        .UID = true,
        .NLINK = true,
    }, &st), "stat broker runit flag");
    if (st.uid != 0 or st.mode & linux.S.IFMT != linux.S.IFREG or st.nlink != 1 or
        st.mode & 0o022 != 0)
        return error.UnsafeRunitFlag;
    return fd;
}

fn serve(log: *Log) noreturn {
    var fds: [roles.len]linux.pollfd = undefined;
    for (roles, 0..) |role, i| fds[i] = .{
        .fd = broker.serverFd(role),
        .events = linux.POLL.IN,
        .revents = 0,
    };
    while (true) {
        for (&fds) |*p| p.revents = 0;
        const n = linux.poll(&fds, fds.len, -1);
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
        for (&fds, roles) |*p, role| {
            if (p.fd < 0 or p.revents == 0) continue;
            if (p.revents & linux.POLL.IN != 0) {
                heard(log, p.fd, role);
            } else if (p.revents & (linux.POLL.HUP | linux.POLL.ERR | linux.POLL.NVAL) != 0) {
                _ = linux.close(p.fd);
                p.fd = -1;
            }
        }
    }
}

/// heard reads one packet from role's socketpair and replies.
fn heard(log: *Log, fd: i32, role: broker.Role) void {
    var in_buf: [1024]u8 = undefined;
    const rc = linux.recvfrom(fd, &in_buf, in_buf.len, linux.MSG.TRUNC, null, null);
    if (linux.errno(rc) == .INTR) return;
    if (linux.errno(rc) != .SUCCESS or rc == 0) return;
    if (rc > in_buf.len) {
        reply(fd, "no BadRequest\n");
        return;
    }
    const request = std.mem.trimEnd(u8, in_buf[0..rc], "\n");
    var out_buf: [1024]u8 = undefined;
    const text = handleRequest(log, role, request, &out_buf) catch |err| failed: {
        log.event("refused", .{
            .role = @tagName(role),
            .@"error" = @errorName(err),
            .call = if (err == error.SystemCall) sandbox.failed else null,
            .errno = if (err == error.SystemCall) sandbox.errnoName(sandbox.failed_errno) else null,
        });
        break :failed std.mem.print(&out_buf, "no {s}\n", .{@errorName(err)}) catch "no\n";
    };
    if (role == .updater and std.mem.eql(u8, request, "owner-channel") and
        std.mem.eql(u8, text, "ok\n"))
    {
        broker.sendOwnerChannel(fd, owner_device) catch reply(fd, "no OwnerChannelSend\n");
    } else reply(fd, text);
}

fn reply(fd: i32, text: []const u8) void {
    _ = linux.sendto(fd, text.ptr, text.len, linux.MSG.NOSIGNAL, null, 0);
}

// --- mounting ------------------------------------------------------------------

const Kind = enum { ext4, vfat };
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

fn identifyDevice(dev: [:0]const u8, want: Want) ?Kind {
    const fd = linux.openat(linux.AT.FDCWD, dev, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(fd));
    var buf: [4096]u8 = undefined;
    const n = linux.pread(@intCast(fd), &buf, buf.len, 0);
    if (linux.errno(n) != .SUCCESS) return null;
    const id = identify(buf[0..n]) orelse return null;
    return if (std.meta.eql(id.want, want)) id.kind else null;
}

/// identify returns the filesystem in a device's first bytes and its UUID
/// or serial: ext2/3/4 at 1 KiB (magic 0xEF53), and FAT by the volume
/// serial in its boot sector.
fn identify(b: []const u8) ?struct { kind: Kind, want: Want } {
    if (b.len >= 1024 + 0x78 and std.mem.readInt(u16, b[1024 + 0x38 ..][0..2], .little) == 0xEF53)
        return .{ .kind = .ext4, .want = .{ .uuid = b[1024 + 0x68 ..][0..16].* } };
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
const open_tree_flags: u32 = 1 | @as(u32, @bitCast(linux.O{ .CLOEXEC = true }));
const MountAttr = extern struct {
    set: u64,
    clear: u64 = 0,
    propagation: u64 = 0,
    userns: u64 = 0,
};

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

fn fdOf(rc: usize, comptime what: []const u8) !i32 {
    return @intCast(try sandbox.sys(rc, what));
}

// --- the EFI and boot partitions -----------------------------------------------
//
// Neither the ESP nor the boot partition has a mount word. For these fixed
// operations the broker makes a detached mount, works through its descriptor,
// and closes it: neither partition is attached where another process could
// reach it. Each operation is accepted only on the socketpair descriptor of
// the role that owns it (keeper, updater, or stage).

const work_dir = "/data/svc/autoupdate/work";
const max_staged: u64 = 192 << 20;

const OpenHow = extern struct {
    flags: u64,
    mode: u64 = 0,
    resolve: u64 = 0,
};
const resolve_no_symlinks: u64 = 0x04;
const resolve_beneath: u64 = 0x08;

fn roleForOp(op: []const u8) !broker.Role {
    if (std.mem.eql(u8, op, "shutdown")) return .stage;
    if (std.mem.eql(u8, op, "esp-status") or std.mem.eql(u8, op, "esp-commit"))
        return .keeper;
    if (std.mem.eql(u8, op, "esp-disarm") or std.mem.eql(u8, op, "esp-arm") or
        std.mem.eql(u8, op, "esp-inspect") or std.mem.eql(u8, op, "esp-install") or
        std.mem.eql(u8, op, "slot-root") or std.mem.eql(u8, op, "slot-decl") or
        std.mem.eql(u8, op, "slot-meta") or std.mem.eql(u8, op, "slot-state") or
        std.mem.eql(u8, op, "installer-runtime") or std.mem.eql(u8, op, "reboot") or
        std.mem.eql(u8, op, "updater-ready") or std.mem.eql(u8, op, "owner-channel"))
        return .updater;
    return error.UnknownEspOperation;
}

fn handleRequest(log: *Log, role: broker.Role, request: []const u8, out: []u8) ![]const u8 {
    const op = request[0 .. std.mem.findScalar(u8, request, ' ') orelse request.len];
    const want_role = try roleForOp(op);
    if (role != want_role) {
        log.event("esp refused", .{
            .role = @tagName(role),
            .op = op,
            .service = @tagName(want_role),
        });
        return if (want_role == .stage) error.NotStageThree else error.NotSlotService;
    }
    if (std.mem.eql(u8, op, "owner-channel")) {
        if (!std.mem.eql(u8, request, "owner-channel")) return error.BadRequest;
        return "ok\n";
    }
    if (std.mem.eql(u8, op, "shutdown")) {
        if (!std.mem.eql(u8, request, "shutdown")) return error.BadRequest;
        shutdown(log);
        return "ok\n";
    }
    if (std.mem.eql(u8, op, "updater-ready")) {
        if (!std.mem.eql(u8, request, "updater-ready")) return error.BadRequest;
        try publishMarker("/run/werewolf/updater-ready");
        return "ok\n";
    }
    if (std.mem.eql(u8, op, "reboot")) {
        if (!std.mem.eql(u8, request, "reboot")) return error.BadRequest;
        _ = try sandbox.sys(linux.fchmod(reboot_flag, 0o100), "update reboot flag");
        _ = try sandbox.sys(linux.fchmod(stop_flag, 0o100), "update stop flag");
        _ = try sandbox.sys(linux.kill(1, linux.SIG.CONT), "wake runit for update");
        return "ok\n";
    }
    if (std.mem.eql(u8, op, "installer-runtime")) {
        if (!std.mem.eql(u8, request, "installer-runtime")) return error.BadRequest;
        try installerRuntime();
        return "ok\n";
    }
    log.event("esp operation", .{ .role = @tagName(role), .op = op });
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
    if (std.mem.eql(u8, op, "slot-state")) {
        try slotStateNow(try broker.parseSlotState(request));
        return "ok\n";
    }
    if (std.mem.eql(u8, op, "esp-status")) {
        if (!std.mem.eql(u8, request, "esp-status")) return error.BadRequest;
        return switch ((try espScan()).status) {
            .already => "ok already\n",
            .tried => "ok tried\n",
            .none => "ok none\n",
        };
    }
    if (std.mem.eql(u8, op, "esp-commit")) {
        if (!std.mem.eql(u8, request, "esp-commit")) return error.BadRequest;
        try espCommitNow();
        try publishMarker("/run/werewolf/committed");
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

fn publishMarker(path: [:0]const u8) !void {
    const marker = try openAt(linux.AT.FDCWD, path, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    }, 0o644);
    defer _ = linux.close(marker);
    var st: linux.Statx = undefined;
    _ = try sandbox.sys(linux.statx(marker, "", linux.AT.EMPTY_PATH, .{
        .TYPE = true,
        .MODE = true,
        .UID = true,
        .NLINK = true,
    }, &st), "stat committed marker");
    if (st.uid != 0 or st.nlink != 1 or st.mode & linux.S.IFMT != linux.S.IFREG or
        st.mode & 0o022 != 0)
        return error.UnsafeCommittedMarker;
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
    errdefer unlinkAt(dirfd, tmp) catch {};
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

fn espVersion(newest: i64) ![16]u8 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    var buf: [16]u8 = undefined;
    _ = try std.mem.print(&buf, "{f}", .{policy.Serial{ .secs = @max(ts.sec, newest + 1) }});
    return buf;
}

test "EFI versions are canonical serials and advance past the newest entry" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const first = try espVersion(0);
    const secs = try policy.parseSerial(&first);
    const next = try espVersion(secs);
    try std.testing.expect(try policy.parseSerial(&next) > secs);
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

fn validStagedDir(st: linux.Statx) bool {
    return (st.mode & linux.S.IFMT) == linux.S.IFDIR and
        (st.uid == 0 or st.uid == 77) and st.gid == st.uid and (st.mode & 0o022) == 0;
}

const installer_usr = "/data/svc/autoupdate/usr";
const installer_host = "/data/svc/autoupdate/host";

/// Attach immutable construction sources read-only at checked directories.
fn installerRuntime() !void {
    try readonlyRuntime("/usr", installer_usr);
    try readonlyRuntime("/", installer_host);
    try updaterReadAccess();
}

fn readonlyRuntime(source: [:0]const u8, destination: [:0]const u8) !void {
    const flags: linux.O = .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true };
    const how: OpenHow = .{
        .flags = @as(u32, @bitCast(flags)),
        .resolve = resolve_no_symlinks,
    };
    const target = try fdOf(
        linux.syscall4(
            .openat2,
            @bitCast(@as(isize, linux.AT.FDCWD)),
            @intFromPtr(destination.ptr),
            @intFromPtr(&how),
            @sizeOf(OpenHow),
        ),
        "open installer target",
    );
    defer _ = linux.close(target);
    var dst: linux.Statx = undefined;
    _ = try sandbox.sys(
        linux.statx(
            target,
            "",
            linux.AT.EMPTY_PATH,
            .{ .TYPE = true, .MODE = true, .UID = true, .GID = true, .INO = true },
            &dst,
        ),
        "stat installer target",
    );
    if (!validStagedDir(dst) or dst.uid != 0) return error.UnsafeInstallerTarget;
    var src: linux.Statx = undefined;
    _ = try sandbox.sys(
        linux.statx(linux.AT.FDCWD, source, 0, .{ .INO = true }, &src),
        "stat immutable usr",
    );
    if (dst.ino == src.ino and dst.dev_major == src.dev_major and dst.dev_minor == src.dev_minor)
        return;
    const tree = try fdOf(
        linux.syscall3(
            .open_tree,
            @bitCast(@as(isize, linux.AT.FDCWD)),
            @intFromPtr(source.ptr),
            open_tree_flags,
        ),
        "clone immutable usr",
    );
    defer _ = linux.close(tree);
    const attr: MountAttr = .{ .set = 1 | attr_nosuid | attr_nodev };
    const made_readonly = linux.syscall5(
        .mount_setattr,
        @intCast(tree),
        @intFromPtr(""),
        linux.AT.EMPTY_PATH,
        @intFromPtr(&attr),
        @sizeOf(MountAttr),
    );
    _ = try sandbox.sys(made_readonly, "make installer runtime read-only");
    const attached = linux.syscall5(
        .move_mount,
        @intCast(tree),
        @intFromPtr(""),
        @intCast(target),
        @intFromPtr(""),
        move_mount_f_empty_path | move_mount_t_empty_path,
    );
    _ = try sandbox.sys(attached, "attach installer runtime");
}

fn validStagedFile(st: linux.Statx) bool {
    return (st.mode & linux.S.IFMT) == linux.S.IFREG and
        st.nlink == 1 and (st.uid == 0 or st.uid == 77) and st.gid == st.uid and
        (st.mode & 0o022) == 0;
}

fn openStagedFile(rel: [:0]const u8) !i32 {
    const dir_flags: linux.O = .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    const how_dir: OpenHow = .{
        .flags = @as(u32, @bitCast(dir_flags)),
        .resolve = resolve_no_symlinks,
    };
    const wfd = try fdOf(
        linux.syscall4(
            .openat2,
            @bitCast(@as(isize, linux.AT.FDCWD)),
            @intFromPtr(work_dir.ptr),
            @intFromPtr(&how_dir),
            @sizeOf(OpenHow),
        ),
        "openat2 work_dir",
    );
    defer _ = linux.close(wfd);
    var dst_st: linux.Statx = undefined;
    if (linux.errno(linux.statx(
        wfd,
        "",
        linux.AT.EMPTY_PATH,
        .{ .TYPE = true, .MODE = true, .UID = true, .GID = true },
        &dst_st,
    )) != .SUCCESS or !validStagedDir(dst_st)) return error.UnsafeStagedDir;
    const file_flags: linux.O = .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    };
    const how_file: OpenHow = .{
        .flags = @as(u32, @bitCast(file_flags)),
        .resolve = resolve_beneath | resolve_no_symlinks,
    };
    const fd = try fdOf(
        linux.syscall4(
            .openat2,
            @bitCast(@as(isize, wfd)),
            @intFromPtr(rel.ptr),
            @intFromPtr(&how_file),
            @sizeOf(OpenHow),
        ),
        "openat2 staged",
    );
    errdefer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(
        fd,
        "",
        linux.AT.EMPTY_PATH,
        .{ .TYPE = true, .MODE = true, .UID = true, .GID = true, .NLINK = true },
        &st,
    )) != .SUCCESS or !validStagedFile(st)) return error.NotRegularFile;
    return fd;
}

fn readStaged(rel: [:0]const u8, buf: []u8) ![]const u8 {
    const fd = try openStagedFile(rel);
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

/// stageChecked copies the file at src (relative to work_dir) into dirfd as
/// dest.tmp, fsyncing it only if its bytes match want's size and SHA-256.
fn stageChecked(
    dirfd: i32,
    src: [:0]const u8,
    dest: []const u8,
    want: broker.EspArtifact,
    limit: u64,
) !void {
    if (want.size > limit) return error.TooLarge;
    const sfd = try openStagedFile(src);
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
    errdefer unlinkAt(dirfd, tmp) catch {};
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
}

/// commitStaged renames dest.tmp over dest in dirfd and fsyncs the directory.
fn commitStaged(dirfd: i32, dest: []const u8) !void {
    var tmp_buf: [160]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, "{s}.tmp", .{dest});
    errdefer unlinkAt(dirfd, tmp) catch {};
    var from_buf: [160]u8 = undefined;
    var to_buf: [160]u8 = undefined;
    const rc = linux.renameat(dirfd, try zBuf(&from_buf, tmp), dirfd, try zBuf(&to_buf, dest));
    if (linux.errno(rc) != .SUCCESS) return error.RenameFailed;
    if (linux.errno(linux.fsync(dirfd)) != .SUCCESS) return error.SyncFailed;
}

/// copyChecked stages src as dest.tmp, verifies its SHA-256, and renames it over dest.
fn copyChecked(
    dirfd: i32,
    src: [:0]const u8,
    dest: []const u8,
    want: broker.EspArtifact,
    limit: u64,
) !void {
    try stageChecked(dirfd, src, dest, want, limit);
    try commitStaged(dirfd, dest);
}

fn espInstallNow(req: broker.EspInstall) !void {
    const m = try espMount();
    defer _ = linux.close(m);
    const slots = try bootSlots();
    // The staged command line and artifacts are verified before any live file
    // or entry on the ESP changes: confined root can write the staging
    // directory, so its bytes are trusted only as the updater's named digests
    // describe.
    var line_buf: [8192]u8 = undefined;
    const staged_cmdline = try readStaged("slot/cmdline", &line_buf);
    const slot_cmdline = try signed.cmdline(staged_cmdline);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(staged_cmdline, &digest, .{});
    if (staged_cmdline.len != req.cmdline.size or
        !std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), req.cmdline.sha256))
        return error.DigestMismatch;
    const entries = try espEntriesDir(m, true);
    defer _ = linux.close(entries);
    const slot_dir = try espSlotDir(m, slots.other, true);
    defer _ = linux.close(slot_dir);
    try stageChecked(slot_dir, "slot/vmlinuz", "vmlinuz", req.vmlinuz, max_staged);
    errdefer unlinkAt(slot_dir, "vmlinuz.tmp") catch {};
    try stageChecked(slot_dir, "slot/stage0.zst", "stage0.zst", req.stage0, max_staged);
    errdefer unlinkAt(slot_dir, "stage0.zst.tmp") catch {};
    if (req.uki) |uki| {
        try stageChecked(slot_dir, "slot/uki.efi", "uki.efi", uki, max_staged);
    }
    errdefer if (req.uki != null) unlinkAt(slot_dir, "uki.efi.tmp") catch {};
    const names = try listNames(entries);
    for (0..names.count) |i| {
        if (signed.isEntryOf(names.get(i), slots.other)) try unlinkAt(entries, names.get(i));
    }
    try commitStaged(slot_dir, "vmlinuz");
    try commitStaged(slot_dir, "stage0.zst");
    if (req.uki != null) {
        try commitStaged(slot_dir, "uki.efi");
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

fn bootMount() !i32 {
    var cmdline_buf: [4096]u8 = undefined;
    var refused: cmdline.Failure = .{};
    const parsed = cmdline.parse(readFile("/proc/cmdline", &cmdline_buf), &refused) orelse
        return error.BadCommandLine;
    const s = parsed.slots orelse return error.NoSlots;
    var dev_buf: [64]u8 = undefined;
    const found = try find(.{ .uuid = cmdline.uuid(s).? }, &dev_buf);
    return makeMount(found.kind, found.dev);
}

/// bootSlotDir opens (creating if asked) /slot/{slot} on the boot filesystem.
fn bootSlotDir(m: i32, slot: []const u8, create: bool) !i32 {
    const slot_root = try openDirAt(m, "slot", create);
    defer _ = linux.close(slot_root);
    try updaterReadable(slot_root, true);
    const leaf = try openDirAt(slot_root, slot, create);
    errdefer _ = linux.close(leaf);
    try updaterReadable(leaf, true);
    return leaf;
}

// The updater may inspect boot artifacts, never change them through /boot.
// Root owns every inode; group 77 gets read/traverse without write permission.
fn updaterReadable(fd: i32, directory: bool) !void {
    var st: linux.Statx = undefined;
    _ = try sandbox.sys(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{
        .TYPE = true,
        .UID = true,
        .NLINK = true,
    }, &st), "stat updater inspection inode");
    const kind: u16 = if (directory) linux.S.IFDIR else linux.S.IFREG;
    if (st.uid != 0 or st.mode & linux.S.IFMT != kind or
        (!directory and st.nlink != 1)) return error.UnsafeBootInspection;
    _ = try sandbox.sys(linux.fchown(fd, std.math.maxInt(u32), 77), "boot inspection group");
    _ = try sandbox.sys(linux.fchmod(fd, if (directory) 0o750 else 0o640), "boot inspection mode");
}

fn updaterReadableFile(dir: i32, name: []const u8) !void {
    const fd = openAt(dir, name, .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    }, 0) catch |err| {
        if (err == error.SystemCall and sandbox.failed_errno == .NOENT) return;
        return err;
    };
    defer _ = linux.close(fd);
    try updaterReadable(fd, false);
}

fn updaterReadAccess() !void {
    const mount = bootMount() catch |err| {
        if (err == error.NoSlots) return;
        return err;
    };
    defer _ = linux.close(mount);
    for ([_][]const u8{ "a", "b" }) |name| {
        const dir = bootSlotDir(mount, name, false) catch |err| {
            if (err == error.SystemCall and sandbox.failed_errno == .NOENT) continue;
            return err;
        };
        defer _ = linux.close(dir);
        for ([_][]const u8{
            "root.erofs", "image.json", "image.json.sig", "cmdline", "declaration",
        }) |file|
            try updaterReadableFile(dir, file);
    }
    const state = openDirAt(mount, "state", false) catch |err| {
        if (err == error.SystemCall and sandbox.failed_errno == .NOENT) return;
        return err;
    };
    defer _ = linux.close(state);
    try updaterReadable(state, true);
    for ([_][]const u8{ "0", "1" }) |name| try updaterReadableFile(state, name);
    linux.sync();
}

fn slotRootNow(want: broker.EspArtifact) !void {
    const m = try bootMount();
    defer _ = linux.close(m);
    const slots = try bootSlots();
    const dir = try bootSlotDir(m, slots.other, true);
    defer _ = linux.close(dir);
    try copyChecked(dir, "slot/root.erofs", "root.erofs", want, 16 << 30);
    try updaterReadableFile(dir, "root.erofs");
    linux.sync();
}

fn slotDeclNow(decl: broker.SlotDecl) !void {
    const m = try bootMount();
    defer _ = linux.close(m);
    const slots = try bootSlots();
    if (decl.current) |text| {
        const dir = try bootSlotDir(m, slots.current, true);
        defer _ = linux.close(dir);
        try writeFileAt(dir, "declaration", text);
        try updaterReadableFile(dir, "declaration");
    }
    if (decl.next) |text| {
        const dir = try bootSlotDir(m, slots.other, true);
        defer _ = linux.close(dir);
        try writeFileAt(dir, "declaration", text);
        try updaterReadableFile(dir, "declaration");
    }
    linux.sync();
}

fn slotMetaNow(meta: broker.SlotMeta) !void {
    const m = try bootMount();
    defer _ = linux.close(m);
    const slots = try bootSlots();
    const dir = try bootSlotDir(m, slots.other, true);
    defer _ = linux.close(dir);
    try copyChecked(
        dir,
        "image.json",
        "image.json",
        meta.manifest,
        max_staged,
    );
    try copyChecked(
        dir,
        "image.sig",
        "image.json.sig",
        meta.signature,
        max_staged,
    );
    try copyChecked(dir, "slot/cmdline", "cmdline", meta.cmdline_file, max_staged);
    for ([_][]const u8{ "image.json", "image.json.sig", "cmdline" }) |name| {
        try updaterReadableFile(dir, name);
    }
    linux.sync();
}

fn slotStateNow(req: broker.SlotJournal) !void {
    const m = try bootMount();
    defer _ = linux.close(m);
    const dir = try openDirAt(m, "state", true);
    defer _ = linux.close(dir);
    const name: []const u8 = if (req.position == 0) "0" else "1";
    try updaterReadable(dir, true);
    try copyChecked(dir, "boot.permit", name, req.permit, max_staged);
    try updaterReadableFile(dir, name);
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

test "installer runtime accepts no paths and belongs only to the updater" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var log: Log = .{};
    var output: [256]u8 = undefined;
    try std.testing.expectError(error.BadRequest, handleRequest(
        &log,
        .updater,
        "installer-runtime /tmp/other",
        &output,
    ));
    try std.testing.expectError(error.NotSlotService, handleRequest(
        &log,
        .keeper,
        "installer-runtime",
        &output,
    ));
}

test "each broker operation belongs to one socketpair role" {
    try std.testing.expectEqual(broker.Role.updater, try roleForOp("owner-channel"));
    try std.testing.expectEqual(broker.Role.updater, try roleForOp("installer-runtime"));
    try std.testing.expectEqual(broker.Role.updater, try roleForOp("reboot"));
    try std.testing.expectEqual(broker.Role.keeper, try roleForOp("esp-status"));
    try std.testing.expectEqual(broker.Role.keeper, try roleForOp("esp-commit"));
    try std.testing.expectEqual(broker.Role.updater, try roleForOp("esp-disarm"));
    try std.testing.expectEqual(broker.Role.updater, try roleForOp("esp-arm"));
    try std.testing.expectEqual(broker.Role.updater, try roleForOp("esp-inspect"));
    try std.testing.expectEqual(broker.Role.updater, try roleForOp("esp-install"));
    try std.testing.expectEqual(broker.Role.updater, try roleForOp("slot-root"));
    try std.testing.expectEqual(broker.Role.updater, try roleForOp("slot-decl"));
    try std.testing.expectEqual(broker.Role.updater, try roleForOp("slot-meta"));
    try std.testing.expectEqual(broker.Role.updater, try roleForOp("slot-state"));
    try std.testing.expectEqual(broker.Role.stage, try roleForOp("shutdown"));
    try std.testing.expectError(error.UnknownEspOperation, roleForOp("victim"));
    try std.testing.expectError(error.UnknownEspOperation, roleForOp("boot"));
}

// --- shutdown ------------------------------------------------------------------

/// shutdown, asked for last by stage 3, unmounts /data (or remounts it
/// read-only if busy), closes its LUKS mapping, and remounts /boot
/// read-only, which writes its journal in place, then tries to unmount it.
/// Each step runs whatever the last one did.
fn shutdown(log: *Log) void {
    linux.sync();
    _ = linux.umount2(installer_host, 0);
    _ = linux.umount2(installer_usr, 0);
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
    if (isMounted(mounts, "/boot")) {
        const journal = remountReadOnly("/boot");
        const unmounted = linux.errno(linux.umount2("/boot", 0)) == .SUCCESS;
        log.event("shutdown", .{ .boot_read_only = journal, .boot_unmounted = unmounted });
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
    const fd = linux.openat(linux.AT.FDCWD, path, .{ .PATH = true, .CLOEXEC = true }, 0);
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
        if (linux.errno(n) == .INTR) continue;
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
        const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(0, ts.sec)) };
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
        if (w.end <= mark) return;
        @memmove(l.buf[mark .. w.end - 1], l.buf[mark + 1 .. w.end]);
        w.end -= 1;
        w.writeByte('\n') catch return;
        _ = linux.write(1, w.buffered().ptr, w.buffered().len);
    }
};

const testing = std.testing;

test identify {
    var b: [4096]u8 = @splat(0);
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
        "/dev/vda /boot ext4 ro 0 0\ntmpfs /run tmpfs rw 0 0\n",
        "/boot",
    ));
    try testing.expect(!isMounted("/dev/vda /boot2 ext4 ro 0 0\n", "/boot"));
}

test "staged inputs require trusted ownership, safe modes and one link" {
    var dir = std.mem.zeroes(linux.Statx);
    dir.mode = linux.S.IFDIR | 0o755;
    try testing.expect(validStagedDir(dir));
    dir.uid = 77;
    dir.gid = 77;
    try testing.expect(validStagedDir(dir));
    dir.gid = 0;
    try testing.expect(!validStagedDir(dir));
    dir.uid = 0;
    dir.mode = linux.S.IFDIR | 0o775;
    try testing.expect(!validStagedDir(dir));
    dir.mode = linux.S.IFDIR | 0o755;
    dir.uid = 69;
    try testing.expect(!validStagedDir(dir));

    var file = std.mem.zeroes(linux.Statx);
    file.mode = linux.S.IFREG | 0o600;
    file.nlink = 1;
    try testing.expect(validStagedFile(file));
    file.nlink = 2;
    try testing.expect(!validStagedFile(file));
    file.nlink = 1;
    file.uid = 69;
    try testing.expect(!validStagedFile(file));
    file.uid = 0;
    file.mode = linux.S.IFREG | 0o664;
    try testing.expect(!validStagedFile(file));
    file.mode = linux.S.IFIFO | 0o600;
    try testing.expect(!validStagedFile(file));
}

test "reboot requires the updater role and an exact request" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var log: Log = .{};
    var out: [1024]u8 = undefined;
    try testing.expectError(error.NotSlotService, handleRequest(&log, .keeper, "reboot", &out));
    try testing.expectError(error.NotSlotService, handleRequest(&log, .stage, "reboot", &out));
    try testing.expectError(error.BadRequest, handleRequest(&log, .updater, "reboot extra", &out));
}

test "EFI versions contain only the canonical serial and advance" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const first = try espVersion(0);
    const secs = try policy.parseSerial(&first);
    const next = try espVersion(secs);
    try testing.expect(try policy.parseSerial(&next) > secs);
}
