//! stage0: PID 1 on every werewolf machine, from the kernel to the root's
//! /init. It raises lockdown, loads the modules, mounts the form's
//! root.erofs read-only directly as the root, and hands over to its /init.
//! Nothing can write the root: what the running system writes goes to /run,
//! /tmp, /var/tmp or /data, and the root is the image, byte for byte, on
//! every boot.
//!
//! The image is a slot's on a machine with slots, found on a filesystem the
//! kernel command line names:
//!
//!     werewolf.victim=UUID:DIR   the filesystem, and the directory holding a/ and b/
//!     werewolf.slot=a|b          which slot this boot is
//!
//! (both, or neither); or, booted directly (QEMU, Lima), /root.erofs in this
//! initramfs, which the build appends.
//!
//! Getting back to a slot that works is the loader's job (GRUB or
//! systemd-boot). A new slot boots once; if anything here fails, stage0
//! exits, the kernel panics, panic=10 reboots it, and the loader boots the
//! slot that last committed. A slot that boots but never commits is caught
//! by the deadman.
//!
//! It is the kernel's first process, so it uses the kernel directly: no
//! shell, no blkid, no mount program. It finds the filesystem by reading
//! each block device's superblock for the UUID.

const std = @import("std");
const linux = std.os.linux;
const MS = linux.MS; // ziglint-ignore: Z032

const deadman_after = 600;
const find_for = 10; // seconds to wait for the victim's disk to appear

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    // How long the kernel took: the boot clock as the first program starts.
    // init shows it with its own, and the demo's page with the services'.
    const kernel_ms = bootMs();

    mountFs("proc", "/proc", "proc", MS.NOSUID | MS.NODEV | MS.NOEXEC);
    mountFs("sys", "/sys", "sysfs", MS.NOSUID | MS.NODEV | MS.NOEXEC);
    mountFs("dev", "/dev", "devtmpfs", MS.NOSUID | MS.NOEXEC);

    const boot = parseCmdline(readAll(gpa, "/proc/cmdline")) catch |err| switch (err) {
        error.Unpaired => fail("werewolf.victim and werewolf.slot come together", .{}),
        error.Twice => fail("werewolf.victim or werewolf.slot given twice", .{}),
        error.BadVictim => fail("werewolf.victim must be UUID:/DIR", .{}),
        error.BadSlot => fail("werewolf.slot must be a or b", .{}),
    };

    // Lockdown at integrity before any module: the kernel then loads only
    // those signed by its key, and refuses the rest. It only rises (writing
    // the level it has is refused too, so it is read first); the root's init
    // finds it raised.
    mountFs("securityfs", "/sys/kernel/security", "securityfs", MS.NOSUID | MS.NODEV | MS.NOEXEC);
    const lockdown = "/sys/kernel/security/lockdown";
    if (!isLocked(readAll(gpa, lockdown)) and
        !writeFile(lockdown, "integrity")) fail("cannot raise lockdown", .{});

    // Every module the form needs, then the loader closes for good: the
    // root that follows finds it closed and loads nothing.
    if (!run(io, &.{"/usr/lib/werewolf/modload"})) say("not every module loaded; see above", .{});

    var img: [:0]const u8 = "/root.erofs";
    if (boot.slot.len > 0) {
        const found = findFilesystem(gpa, boot.uuid) orelse fail("no filesystem {s}", .{boot.uuid});
        mkdir("/victim");
        const rc = linux.mount(
            found.dev,
            "/victim",
            @tagName(found.kind),
            MS.NOSUID | MS.NODEV | MS.NOEXEC,
            0,
        );
        if (linux.errno(rc) != .SUCCESS) fail(
            "cannot mount {s}: {s}",
            .{ found.dev, @tagName(linux.errno(rc)) },
        );
        img = try gpa.printSentinel(
            "/victim{s}/{s}/root.erofs",
            .{ boot.dir, boot.slot },
            0,
        );
    }
    // Read-only, and nothing over it: no overlay to write into. erofs
    // mounts the image file itself where the file's filesystem lets it (a
    // slot's ext4, xfs or btrfs); the initramfs, in tmpfs, does not, and
    // says so with ENOTBLK, so a direct boot's image goes through a
    // read-only loop device.
    mkdir("/root");
    const flags = MS.RDONLY | MS.NOSUID | MS.NODEV;
    var rc = linux.mount(img, "/root", "erofs", flags, 0);
    if (linux.errno(rc) == .NOTBLK) {
        const loop = loopDevice(
            gpa,
            img,
        ) catch |err| fail("cannot attach {s} to a loop device: {s}", .{ img, @errorName(err) });
        rc = linux.mount(loop.path, "/root", "erofs", flags, 0);
        // Only now: autoclear detaches the image when the last holder of
        // the device lets go, and until the mount holds it, that is us.
        _ = linux.close(loop.fd);
    }
    if (linux.errno(rc) != .SUCCESS) fail(
        "cannot mount {s}: {s}",
        .{ img, @tagName(linux.errno(rc)) },
    );
    if (boot.slot.len > 0)
        say("slot {s}: {s}, read-only, is the root", .{ boot.slot, img })
    else
        say("{s}, read-only, is the root", .{img});

    if (boot.slot.len > 0) deadman(boot.slot);

    // The root is read-only, so its mount points are in the image already.
    for ([_][:0]const u8{ "dev", "proc", "sys", "victim" }) |m| {
        if (std.mem.eql(u8, m, "victim") and boot.slot.len == 0) continue;
        const from = try gpa.printSentinel("/{s}", .{m}, 0);
        const to = try gpa.printSentinel("/root/{s}", .{m}, 0);
        if (linux.errno(linux.mount(
            from,
            to,
            null,
            MS.MOVE,
            0,
        )) != .SUCCESS) fail("cannot move /{s} into the root", .{m});
    }
    // What switch_root does: put the new root over / and start its init
    // inside it.
    if (linux.errno(linux.chdir("/root")) != .SUCCESS) fail("cannot enter /root", .{});
    if (linux.errno(linux.mount(
        ".",
        "/",
        null,
        MS.MOVE,
        0,
    )) != .SUCCESS) fail("cannot move the root over /", .{});
    if (linux.errno(linux.chroot(".")) != .SUCCESS) fail("cannot enter the root", .{});
    _ = linux.chdir("/");
    say("the kernel took {d}.{d:0>3}s", .{ kernel_ms / 1000, kernel_ms % 1000 });
    var env = try init.environ_map.clone(gpa);
    try env.put("WEREWOLF_KERNEL_MS", try gpa.print("{d}", .{kernel_ms}));
    const err = std.process.replace(io, .{ .argv = &.{"/init"}, .environ_map = &env });
    fail("cannot start /init: {s}", .{@errorName(err)});
}

/// The deadman: a child that outlives this initramfs, sleeping, then looking
/// through PID 1's root for the mark slot-keep leaves; without it, it reboots
/// at once. The loader has spent this slot's one boot, so the machine comes
/// back on the slot that last committed. It touches no file of the
/// initramfs once it sleeps, and reaches PID 1 through a /proc of its own.
fn deadman(slot: []const u8) void {
    mkdir("/deadman");
    mountFs("proc", "/deadman", "proc", MS.NOSUID | MS.NODEV | MS.NOEXEC);
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) fail("cannot start the deadman", .{});
    if (pid != 0) return;

    var ts: linux.timespec = .{ .sec = deadman_after, .nsec = 0 };
    while (linux.errno(linux.nanosleep(&ts, &ts)) == .INTR) {}
    if (linux.errno(linux.access(
        "/deadman/1/root/run/werewolf/committed",
        linux.F_OK,
    )) != .SUCCESS) {
        var buf: [128]u8 = undefined;
        const msg = std.mem.print(
            &buf,
            "stage0: slot {s} did not commit in 10 minutes; rebooting into the last good slot\n",
            .{slot},
        ) catch "";
        _ = writeFile("/dev/console", msg);
        _ = writeFile("/deadman/sysrq-trigger", "b");
    }
    linux.exit(0);
}

// --- a loop device -------------------------------------------------------------

/// <linux/loop.h>, which Zig's std does not carry.
const LOOP_CTL_GET_FREE = 0x4C82;
const LOOP_CONFIGURE = 0x4C0A;
const LO_FLAGS_READ_ONLY = 1;
const LO_FLAGS_AUTOCLEAR = 4;

const LoopInfo64 = extern struct {
    device: u64 = 0,
    inode: u64 = 0,
    rdevice: u64 = 0,
    offset: u64 = 0,
    sizelimit: u64 = 0,
    number: u32 = 0,
    encrypt_type: u32 = 0,
    encrypt_key_size: u32 = 0,
    flags: u32 = 0,
    file_name: [64]u8 = @splat(0),
    crypt_name: [64]u8 = @splat(0),
    encrypt_key: [32]u8 = @splat(0),
    init: [2]u64 = .{ 0, 0 },
};

const LoopConfig = extern struct {
    fd: u32,
    block_size: u32 = 0,
    info: LoopInfo64,
    reserved: [8]u64 = @splat(0),
};

/// A free loop device, read-only, holding file, and gone once its mount
/// is (autoclear). The caller closes fd once the device is mounted: closed
/// before, autoclear would detach the image at once.
fn loopDevice(gpa: std.mem.Allocator, file: [:0]const u8) !struct { path: [:0]const u8, fd: i32 } {
    const ctl = linux.open("/dev/loop-control", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    if (linux.errno(ctl) != .SUCCESS) return error.NoLoopControl;
    defer _ = linux.close(@intCast(ctl));
    const n = linux.ioctl(@intCast(ctl), LOOP_CTL_GET_FREE, 0);
    if (linux.errno(n) != .SUCCESS) return error.NoFreeLoop;
    const dev = try gpa.printSentinel("/dev/loop{d}", .{n}, 0);

    // devtmpfs makes the node a moment after the device exists.
    var fd: usize = 0;
    for (0..50) |_| {
        fd = linux.open(dev, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd) != .NOENT) break;
        var ts: linux.timespec = .{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
    }
    if (linux.errno(fd) != .SUCCESS) return error.NoLoopDevice;
    errdefer _ = linux.close(@intCast(fd));
    const backing = linux.open(file, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(backing) != .SUCCESS) return error.NoImage;
    defer _ = linux.close(@intCast(backing));

    var cfg: LoopConfig = .{
        .fd = @intCast(backing),
        .info = .{ .flags = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR },
    };
    if (linux.errno(linux.ioctl(
        @intCast(fd),
        LOOP_CONFIGURE,
        @intFromPtr(&cfg),
    )) != .SUCCESS) return error.LoopConfigure;
    return .{ .path = dev, .fd = @intCast(fd) };
}

// --- the victim's filesystem ---------------------------------------------------

const Kind = enum { ext4, xfs, btrfs };
const Found = struct { dev: [:0]const u8, kind: Kind };

/// The block device whose filesystem has uuid, waiting for it to appear:
/// a disk's driver may still be probing when the modules are loaded.
fn findFilesystem(gpa: std.mem.Allocator, uuid: []const u8) ?Found {
    const want = parseUuid(uuid) orelse return null;
    var waited: usize = 0;
    while (waited < find_for * 5) : (waited += 1) {
        if (scan(gpa, want)) |f| return f;
        var ts: linux.timespec = .{ .sec = 0, .nsec = 200 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
    }
    return null;
}

/// Each block device, its superblock read for want.
fn scan(gpa: std.mem.Allocator, want: [16]u8) ?Found {
    const dir = linux.open(
        "/sys/class/block",
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(dir) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(dir));
    var buf: [4096]u8 align(8) = undefined;
    while (true) {
        const n = linux.getdents64(@intCast(dir), &buf, buf.len);
        if (linux.errno(n) != .SUCCESS or n == 0) return null;
        var off: usize = 0;
        while (off < n) {
            const ent: *align(1) const linux.dirent64 = @ptrCast(&buf[off]);
            off += ent.reclen;
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.name)), 0);
            if (name[0] == '.') continue;
            const dev = gpa.printSentinel("/dev/{s}", .{name}, 0) catch continue;
            const kind = superblock(dev, want) orelse continue;
            return .{ .dev = dev, .kind = kind };
        }
    }
}

/// The filesystem on dev, if its UUID is want.
fn superblock(dev: [:0]const u8, want: [16]u8) ?Kind {
    const fd = linux.open(dev, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(fd));
    var buf: [btrfs_at + 0x1000]u8 = undefined;
    const n = linux.pread(@intCast(fd), &buf, buf.len, 0);
    if (linux.errno(n) != .SUCCESS) return null;
    const id = identify(buf[0..n]) orelse return null;
    return if (std.mem.eql(u8, &id.uuid, &want)) id.kind else null;
}

const btrfs_at = 0x10000;

/// The filesystem a device's first bytes describe, and its UUID, as each
/// stores it: ext2/3/4 at 1 KiB in (magic 0xEF53), xfs at 0 ("XFSB"),
/// btrfs at 64 KiB in ("_BHRfS_M").
fn identify(b: []const u8) ?struct { kind: Kind, uuid: [16]u8 } {
    if (b.len >= 1024 + 0x78 and std.mem.readInt(u16, b[1024 + 0x38 ..][0..2], .little) == 0xEF53)
        return .{ .kind = .ext4, .uuid = b[1024 + 0x68 ..][0..16].* };
    if (b.len >= 48 and std.mem.eql(u8, b[0..4], "XFSB"))
        return .{ .kind = .xfs, .uuid = b[32..48].* };
    if (b.len >= btrfs_at + 0x48 and std.mem.eql(u8, b[btrfs_at + 0x40 ..][0..8], "_BHRfS_M"))
        return .{ .kind = .btrfs, .uuid = b[btrfs_at + 0x20 ..][0..16].* };
    return null;
}

/// 57e1f000-77e2-4b0f-8a3c-0000000000a0 as its 16 bytes, in order.
fn parseUuid(s: []const u8) ?[16]u8 {
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
    return out;
}

// --- the command line ----------------------------------------------------------

const Boot = struct { uuid: []const u8 = "", dir: []const u8 = "", slot: []const u8 = "" };

/// werewolf.victim=UUID:/DIR and werewolf.slot=a|b, both or neither, each
/// once, and well formed.
fn parseCmdline(text: []const u8) !Boot {
    var b: Boot = .{};
    var victim: ?[]const u8 = null;
    var it = std.mem.tokenizeAny(u8, text, " \t\n");
    while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "werewolf.victim=")) {
            if (victim != null) return error.Twice;
            victim = arg["werewolf.victim=".len..];
        } else if (std.mem.startsWith(u8, arg, "werewolf.slot=")) {
            if (b.slot.len > 0) return error.Twice;
            b.slot = arg["werewolf.slot=".len..];
            if (!std.mem.eql(u8, b.slot, "a") and
                !std.mem.eql(u8, b.slot, "b")) return error.BadSlot;
        }
    }
    if ((victim == null) != (b.slot.len == 0)) return error.Unpaired;
    const v = victim orelse return b;
    const colon = std.mem.findScalar(u8, v, ':') orelse return error.BadVictim;
    b.uuid = v[0..colon];
    b.dir = v[colon + 1 ..];
    if (parseUuid(b.uuid) == null or !isSafeDir(b.dir)) return error.BadVictim;
    return b;
}

/// An absolute path of plain names: no ., no .., no empty parts, and only
/// the characters paths here use.
fn isSafeDir(dir: []const u8) bool {
    if (dir.len < 2 or dir[0] != '/' or dir[dir.len - 1] == '/') return false;
    var parts = std.mem.splitScalar(u8, dir[1..], '/');
    while (parts.next()) |p| {
        if (p.len == 0 or std.mem.eql(u8, p, ".") or std.mem.eql(u8, p, "..")) return false;
        for (p) |c| if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '_' and
            c != '-') return false;
    }
    return true;
}

fn isLocked(text: []const u8) bool {
    return std.mem.indexOf(u8, text, "[integrity]") != null or
        std.mem.indexOf(u8, text, "[confidentiality]") != null;
}

// --- the kernel, directly ------------------------------------------------------

fn mountFs(source: [:0]const u8, target: [:0]const u8, kind: [:0]const u8, flags: u32) void {
    mkdir(target);
    const rc = linux.mount(source, target, kind, flags, 0);
    if (linux.errno(rc) != .SUCCESS and
        linux.errno(rc) != .BUSY) fail("cannot mount {s} on {s}", .{ kind, target });
}

fn mkdir(path: [:0]const u8) void {
    _ = linux.mkdir(path, 0o755);
}

fn writeFile(path: [:0]const u8, data: []const u8) bool {
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    const n = linux.write(@intCast(fd), data.ptr, data.len);
    return linux.errno(n) == .SUCCESS and n == data.len;
}

/// path, read to its end (procfs and sysfs report a size of 0).
fn readAll(gpa: std.mem.Allocator, path: [:0]const u8) []const u8 {
    const fd = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return "";
    defer _ = linux.close(@intCast(fd));
    var out: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = linux.read(@intCast(fd), &buf, buf.len);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        out.appendSlice(gpa, buf[0..n]) catch break;
    }
    return out.items;
}

/// Whether argv runs and exits 0, its output on the console with ours.
fn run(io: std.Io, argv: []const []const u8) bool {
    var child = std.process.spawn(io, .{ .argv = argv, .stdin = .ignore }) catch return false;
    const term = child.wait(io) catch return false;
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn say(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "stage0: " ++ fmt ++ "\n", args) catch return;
    _ = linux.write(1, line.ptr, line.len);
}

/// Exiting PID 1 panics the kernel; panic=10 reboots it, and the loader
/// boots the slot that last committed.
fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    say(fmt ++ "; panicking, so the machine reboots into the last good slot", args);
    linux.exit(1);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test parseCmdline {
    const b = try parseCmdline(
        "console=hvc0 werewolf.victim=57e1f000-77e2-4b0f-8a3c-0000000000a0:/var/lib/werewolf " ++
            "werewolf.slot=b\n",
    );
    try testing.expectEqualStrings("57e1f000-77e2-4b0f-8a3c-0000000000a0", b.uuid);
    try testing.expectEqualStrings("/var/lib/werewolf", b.dir);
    try testing.expectEqualStrings("b", b.slot);
    const direct = try parseCmdline("console=ttyAMA0 werewolf.ip=10.0.2.15/24\n");
    try testing.expectEqualStrings("", direct.slot);

    const uuid = "57e1f000-77e2-4b0f-8a3c-0000000000a0";
    try testing.expectError(error.Unpaired, parseCmdline("werewolf.slot=a"));
    try testing.expectError(error.Unpaired, parseCmdline("werewolf.victim=" ++ uuid ++ ":/w"));
    try testing.expectError(
        error.BadSlot,
        parseCmdline("werewolf.victim=" ++ uuid ++ ":/w werewolf.slot=c"),
    );
    try testing.expectError(
        error.Twice,
        parseCmdline("werewolf.victim=" ++ uuid ++ ":/w werewolf.slot=a werewolf.slot=b"),
    );
    try testing.expectError(
        error.BadVictim,
        parseCmdline("werewolf.victim=" ++ uuid ++ ":/w/../etc werewolf.slot=a"),
    );
    try testing.expectError(
        error.BadVictim,
        parseCmdline("werewolf.victim=" ++ uuid ++ ":w werewolf.slot=a"),
    );
    try testing.expectError(
        error.BadVictim,
        parseCmdline("werewolf.victim=nope:/w werewolf.slot=a"),
    );
}

test parseUuid {
    const u = parseUuid("57e1f000-77e2-4b0f-8a3c-0000000000a0").?;
    try testing.expectEqualSlices(
        u8,
        &.{ 0x57, 0xe1, 0xf0, 0x00, 0x77, 0xe2, 0x4b, 0x0f, 0x8a, 0x3c, 0, 0, 0, 0, 0, 0xa0 },
        &u,
    );
    try testing.expectEqual(null, parseUuid("57e1f000x77e2-4b0f-8a3c-0000000000a0"));
    try testing.expectEqual(null, parseUuid("57e1f000-77e2-4b0f-8a3c-0000000000a"));
}

test identify {
    var b: [btrfs_at + 0x1000]u8 = @splat(0);
    try testing.expectEqual(null, identify(&b));

    std.mem.writeInt(u16, b[1024 + 0x38 ..][0..2], 0xEF53, .little);
    b[1024 + 0x68] = 0x57;
    var id = identify(&b).?;
    try testing.expectEqual(Kind.ext4, id.kind);
    try testing.expectEqual(0x57, id.uuid[0]);

    @memset(&b, 0);
    @memcpy(b[0..4], "XFSB");
    b[32] = 0xab;
    id = identify(&b).?;
    try testing.expectEqual(Kind.xfs, id.kind);
    try testing.expectEqual(0xab, id.uuid[0]);

    @memset(&b, 0);
    @memcpy(b[btrfs_at + 0x40 ..][0..8], "_BHRfS_M");
    b[btrfs_at + 0x20] = 0xcd;
    id = identify(&b).?;
    try testing.expectEqual(Kind.btrfs, id.kind);
    try testing.expectEqual(0xcd, id.uuid[0]);
}

test LoopConfig {
    // The kernel's struct loop_config is 304 bytes; LOOP_CONFIGURE reads
    // exactly that.
    try testing.expectEqual(232, @sizeOf(LoopInfo64));
    try testing.expectEqual(304, @sizeOf(LoopConfig));
}

test isLocked {
    try testing.expect(isLocked("none [integrity] confidentiality\n"));
    try testing.expect(!isLocked("[none] integrity confidentiality\n"));
}

/// Milliseconds since the kernel started its clock.
fn bootMs() u64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}
