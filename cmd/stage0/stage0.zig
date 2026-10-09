//! stage0 is the initramfs's PID 1. It raises lockdown, loads modules,
//! opens the root image through dm-verity, mounts it read-only as /, and
//! execs its /init. See README.md.

const std = @import("std");
const linux = std.os.linux;
const dm = @import("dm");
const verity = @import("verity");
const cmdline = @import("cmdline");
const MS = linux.MS; // ziglint-ignore: Z032

/// deadman_after is how many seconds a slot has to commit before the
/// deadman reboots it.
const deadman_after = 600;
const find_for = 10; // seconds to wait for the victim's disk to appear

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    // The boot clock now is how long the kernel took.
    const kernel_ms = bootMs();

    mountFs("proc", "/proc", "proc", MS.NOSUID | MS.NODEV | MS.NOEXEC);
    mountFs("sys", "/sys", "sysfs", MS.NOSUID | MS.NODEV | MS.NOEXEC);
    mountFs("dev", "/dev", "devtmpfs", MS.NOSUID | MS.NOEXEC);

    // Check the whole line once, for every later program: a line that is
    // ambiguous or malformed ends the boot here.
    var refused: cmdline.Failure = .{};
    const boot = cmdline.parse(readAll(gpa, "/proc/cmdline"), &refused) orelse
        fail("the command line's {s}: {s}", .{ refused.word, refused.why });

    // Raise lockdown to integrity before any module loads, so the kernel
    // refuses unsigned ones. Writing the current level is refused too, so
    // read it first.
    mountFs("securityfs", "/sys/kernel/security", "securityfs", MS.NOSUID | MS.NODEV | MS.NOEXEC);
    const lockdown = "/sys/kernel/security/lockdown";
    if (!isLocked(readAll(gpa, lockdown)) and
        !writeFile(lockdown, "integrity")) fail("cannot raise lockdown", .{});

    // modload loads the form's modules and closes the loader for good. It
    // reads tags on stdin, one per line. "hyperv" goes first, since the
    // slot's disk may sit behind VMBus, which exists only on Hyper-V (Azure).
    // "esp" adds FAT for werewolf's own EFI partition. The disk search runs
    // while drivers load; then modload is told the filesystem kind (xfs and
    // btrfs need modules; ext4 does not).
    var loader: ?std.process.Child = std.process.spawn(io, .{
        .argv = &.{"/usr/lib/werewolf/modload"},
        .stdin = .pipe,
    }) catch |err| blk: {
        say("cannot run modload: {s}", .{@errorName(err)});
        break :blk null;
    };
    if (loader) |l| {
        if (linux.errno(linux.access("/sys/bus/vmbus", linux.F_OK)) == .SUCCESS)
            l.stdin.?.writeStreamingAll(io, "hyperv\n") catch {};
        if (boot.esp != null) l.stdin.?.writeStreamingAll(io, "esp\n") catch {};
    }
    const found = if (boot.victim) |v| findFilesystem(gpa, v.uuid) else null;
    if (loader) |*l| {
        const name = if (found) |f| @tagName(f.kind) else "none";
        l.stdin.?.writeStreamingAll(io, name) catch {};
        l.stdin.?.writeStreamingAll(io, "\n") catch {};
        l.stdin.?.close(io);
        l.stdin = null;
        const ok = if (l.wait(io)) |term| switch (term) {
            .exited => |code| code == 0,
            else => false,
        } else |_| false;
        if (!ok) say("not every module loaded; see above", .{});
    }
    // Nothing frees the initramfs after the switch, so delete its 14 MB of
    // modules now that they are loaded or refused.
    std.Io.Dir.cwd().deleteTree(io, "/usr/lib/modules") catch |err|
        say("modules not freed: {s}", .{@errorName(err)});
    const modules_ms = bootMs();

    var img: [:0]const u8 = "/root.erofs";
    if (boot.root.len > 0) {
        // The driver has loaded, but devtmpfs may not have made the node yet.
        img = try gpa.printSentinel("/dev/{s}", .{boot.root}, 0);
        var waited: usize = 0;
        while (linux.errno(linux.access(img, linux.F_OK)) != .SUCCESS) : (waited += 1) {
            if (waited == find_for * 100) fail("no disk {s}", .{img});
            var ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
            _ = linux.nanosleep(&ts, null);
        }
    }
    var slot_ms: u64 = 0;
    if (boot.victim) |v| {
        const f = found orelse fail("no filesystem {s}", .{v.uuid});
        mkdir("/victim");
        const rc = linux.mount(
            f.dev,
            "/victim",
            @tagName(f.kind),
            MS.NOSUID | MS.NODEV | MS.NOEXEC,
            0,
        );
        if (linux.errno(rc) != .SUCCESS) fail(
            "cannot mount {s}: {s}",
            .{ f.dev, @tagName(linux.errno(rc)) },
        );
        img = try gpa.printSentinel(
            "/victim{s}/{s}/root.erofs",
            .{ v.path, @tagName(boot.slot.?) },
            0,
        );
        slot_ms = bootMs();
    }
    // dm-verity checks each block of the image as it is read. A disk is
    // mapped directly; a file goes through a read-only loop device. The
    // node is made from dm's device number rather than waiting on devtmpfs.
    const params = verity.Params.parse(readAll(gpa, "/verity")) catch
        fail("no root hash in /verity", .{});
    const loop = if (boot.root.len > 0) null else loopDevice(gpa, img) catch |err|
        fail("cannot attach {s} to a loop device: {s}", .{ img, @errorName(err) });
    var table_buf: [512]u8 = undefined;
    const table = verity.table(&table_buf, if (loop) |l| l.path else img, params) catch
        unreachable;
    const sectors = params.data_blocks * (verity.block_size / 512);
    const dev = dm.create("root", "verity", sectors, table) catch |err|
        fail("cannot open {s} through dm-verity: {s}", .{ img, @errorName(err) });
    // dm-verity holds the loop device now; autoclear detaches it when
    // dm-verity lets go.
    if (loop) |l| _ = linux.close(l.fd);
    const root_dev = "/dev/mapper/root";
    const made = linux.mknodat(linux.AT.FDCWD, root_dev, linux.S.IFBLK | 0o600, dev);
    if (linux.errno(made) != .SUCCESS) fail("cannot make {s}", .{root_dev});
    mkdir("/root");
    const rc = linux.mount(root_dev, "/root", "erofs", MS.RDONLY | MS.NOSUID | MS.NODEV, 0);
    if (linux.errno(rc) != .SUCCESS) fail(
        "cannot mount {s}: {s}",
        .{ img, @tagName(linux.errno(rc)) },
    );
    const root_ms = bootMs();
    if (boot.slot) |slot|
        say(
            "slot {s}: {s}, read-only, verified (root hash {x}…), is the root",
            .{ @tagName(slot), img, params.root[0..8] },
        )
    else
        say(
            "{s}, read-only, verified (root hash {x}…), is the root",
            .{ img, params.root[0..8] },
        );

    if (boot.slot) |slot| {
        // A shorter wait is for make check-deadman, so only a DEV build's
        // root, now verified, may ask for one. A release always waits ten
        // minutes.
        var after: u32 = deadman_after;
        if (boot.deadman > 0) {
            if (linux.errno(linux.access("/root/usr/share/werewolf/dev", linux.F_OK)) == .SUCCESS) {
                after = boot.deadman;
                say("the deadman waits {d}s (werewolf.deadman, a DEV build)", .{after});
            } else say("werewolf.deadman ignored: not a DEV build", .{});
        }
        deadman(@tagName(slot), after);
    }

    // The root is read-only, so the image already has these mount points.
    for ([_][:0]const u8{ "dev", "proc", "sys", "victim" }) |m| {
        if (std.mem.eql(u8, m, "victim") and boot.slot == null) continue;
        const from = try gpa.printSentinel("/{s}", .{m}, 0);
        const to = try gpa.printSentinel("/root/{s}", .{m}, 0);
        if (linux.errno(linux.mount(from, to, null, MS.MOVE, 0)) != .SUCCESS)
            fail("cannot move /{s} into the root", .{m});
    }
    // Do what switch_root does: move the new root over / and chroot into it.
    if (linux.errno(linux.chdir("/root")) != .SUCCESS) fail("cannot enter /root", .{});
    if (linux.errno(linux.mount(".", "/", null, MS.MOVE, 0)) != .SUCCESS)
        fail("cannot move the root over /", .{});
    if (linux.errno(linux.chroot(".")) != .SUCCESS) fail("cannot enter the root", .{});
    _ = linux.chdir("/");
    say("the kernel took {d}.{d:0>3}s", .{ kernel_ms / 1000, kernel_ms % 1000 });
    // Pass init only WEREWOLF_BOOT, each phase's end in boot-clock ms. The
    // kernel puts every NAME=value it does not take into stage0's
    // environment, and it must not reach every process on the machine.
    var env: std.process.Environ.Map = .init(gpa);
    try env.put("WEREWOLF_BOOT", if (slot_ms > 0)
        try gpa.print(
            "kernel={d} modules={d} slot={d} root={d}",
            .{ kernel_ms, modules_ms, slot_ms, root_ms },
        )
    else
        try gpa.print("kernel={d} modules={d} root={d}", .{ kernel_ms, modules_ms, root_ms }));
    const err = std.process.replace(io, .{ .argv = &.{"/init"}, .environ_map = &env });
    fail("cannot start /init: {s}", .{@errorName(err)});
}

/// deadman forks a child that sleeps for after seconds, then reboots unless
/// slot-keep has left its mark in PID 1's root. The loader has spent this
/// slot's one boot, so the machine returns on the slot that last committed.
/// The child reaches PID 1 through its own /proc and the kernel log through
/// a descriptor opened now, since /dev moves into the new root.
fn deadman(slot: []const u8, after: u32) void {
    mkdir("/deadman");
    mountFs("proc", "/deadman", "proc", MS.NOSUID | MS.NODEV | MS.NOEXEC);
    const kmsg = linux.open("/dev/kmsg", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) fail("cannot start the deadman", .{});
    if (pid != 0) {
        if (linux.errno(kmsg) == .SUCCESS) _ = linux.close(@intCast(kmsg));
        return;
    }

    var ts: linux.timespec = .{ .sec = after, .nsec = 0 };
    while (linux.errno(linux.nanosleep(&ts, &ts)) == .INTR) {}
    if (linux.errno(linux.access(
        "/deadman/1/root/run/werewolf/committed",
        linux.F_OK,
    )) != .SUCCESS) {
        var buf: [128]u8 = undefined;
        const msg = std.mem.print(
            &buf,
            "<2>stage0: slot {s} did not commit in {d}s; rebooting into the last good slot\n",
            .{ slot, after },
        ) catch "";
        // The kernel prints its log to the console from another thread,
        // and sysrq's reset, unlike a panic, waits for nothing. Give the
        // console a second to say why.
        if (linux.errno(kmsg) == .SUCCESS) {
            _ = linux.write(@intCast(kmsg), msg.ptr, msg.len);
            var pause: linux.timespec = .{ .sec = 1, .nsec = 0 };
            _ = linux.nanosleep(&pause, null);
        }
        // If sysrq-trigger fails, call reboot: this process forked before
        // the seal and keeps every capability. Exiting quietly would leave
        // the bad slot running.
        if (!writeFile("/deadman/sysrq-trigger", "b"))
            _ = linux.reboot(.MAGIC1, .MAGIC2, .RESTART, null);
    }
    linux.exit(0);
}

// --- a loop device -------------------------------------------------------------

// Constants from <linux/loop.h> and <fcntl.h>, which Zig's std lacks.
const AT_EMPTY_PATH = 0x1000;
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

/// loopDevice attaches file to a free read-only, autoclearing loop device.
/// The caller must close fd only after something else holds the device;
/// closing it sooner would detach the image at once.
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
    // Only a regular file, no link: the slot's filesystem comes from the
    // disk, and a FIFO there would block PID 1 forever with no panic to
    // fall back on. A wrong file only fails verification.
    const backing = linux.open(file, .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .NOCTTY = true,
    }, 0);
    if (linux.errno(backing) != .SUCCESS) return error.NoImage;
    defer _ = linux.close(@intCast(backing));
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(@intCast(backing), "", AT_EMPTY_PATH, .{ .TYPE = true }, &st)) !=
        .SUCCESS or st.mode & linux.S.IFMT != linux.S.IFREG) return error.NotAnImageFile;
    // Read the whole image ahead in the background: the boot reads most of
    // it, and a cloud's network disk serves a few large reads far faster
    // than many small ones. Reading the hash tree first was no faster on GCP.
    _ = linux.fadvise(@intCast(backing), 0, 0, linux.POSIX_FADV.WILLNEED);

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

/// findFilesystem returns the block device whose filesystem has uuid,
/// polling every 10 ms for up to find_for seconds while drivers load. If
/// two devices have it, stage0 fails rather than guess, as the mount
/// broker does.
fn findFilesystem(gpa: std.mem.Allocator, uuid: []const u8) ?Found {
    const want = cmdline.uuid(uuid) orelse return null;
    var waited: usize = 0;
    while (waited < find_for * 100) : (waited += 1) {
        switch (scan(gpa, want)) {
            .none => {},
            .one => |f| return f,
            .two => |d| fail(
                "{s} and {s} both hold filesystem {s}, as a clone or snapshot attached " ++
                    "beside the disk would; refusing to guess",
                .{ d[0], d[1], uuid },
            ),
        }
        var ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
    }
    return null;
}

const Scan = union(enum) { none, one: Found, two: [2][:0]const u8 };

/// scan reads every block device's superblock for want. It reads them all,
/// so it sees a second device with the same UUID.
fn scan(gpa: std.mem.Allocator, want: [16]u8) Scan {
    const dir = linux.open(
        "/sys/class/block",
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(dir) != .SUCCESS) return .none;
    defer _ = linux.close(@intCast(dir));
    var found: ?Found = null;
    var buf: [4096]u8 align(8) = undefined;
    while (true) {
        const n = linux.getdents64(@intCast(dir), &buf, buf.len);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const ent: *align(1) const linux.dirent64 = @ptrCast(&buf[off]);
            off += ent.reclen;
            const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.name)), 0);
            if (name[0] == '.') continue;
            const dev = gpa.printSentinel("/dev/{s}", .{name}, 0) catch continue;
            const kind = superblock(dev, want) orelse continue;
            if (found) |f| return .{ .two = .{ f.dev, dev } };
            found = .{ .dev = dev, .kind = kind };
        }
    }
    return if (found) |f| .{ .one = f } else .none;
}

/// superblock returns the filesystem kind on dev if its UUID is want.
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

/// identify returns the filesystem kind and UUID in a device's first bytes:
/// ext2/3/4 at 1 KiB (magic 0xEF53), xfs at 0 ("XFSB"), btrfs at 64 KiB
/// ("_BHRfS_M").
fn identify(b: []const u8) ?struct { kind: Kind, uuid: [16]u8 } {
    if (b.len >= 1024 + 0x78 and std.mem.readInt(u16, b[1024 + 0x38 ..][0..2], .little) == 0xEF53)
        return .{ .kind = .ext4, .uuid = b[1024 + 0x68 ..][0..16].* };
    if (b.len >= 48 and std.mem.eql(u8, b[0..4], "XFSB"))
        return .{ .kind = .xfs, .uuid = b[32..48].* };
    if (b.len >= btrfs_at + 0x48 and std.mem.eql(u8, b[btrfs_at + 0x40 ..][0..8], "_BHRfS_M"))
        return .{ .kind = .btrfs, .uuid = b[btrfs_at + 0x20 ..][0..16].* };
    return null;
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

/// readAll returns path's contents, or "". It reads to the end because
/// procfs and sysfs report a size of 0.
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

/// say writes one line to the console.
fn say(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "stage0: " ++ fmt ++ "\n", args) catch return;
    _ = linux.write(1, line.ptr, line.len);
}

/// fail logs why and exits, which panics the kernel; panic= reboots, and
/// the loader boots the slot that last committed. The reason goes to
/// /dev/kmsg at KERN_CRIT, which prints at any console loglevel and which
/// the kernel flushes on panic. A write to the console tty may still be
/// draining the UART at reboot and be lost, so it is only the fallback.
fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(
        &buf,
        "<2>stage0: " ++ fmt ++ "; panicking, so the machine reboots into the last good slot\n",
        args,
    ) catch linux.exit(1);
    if (!writeFile("/dev/kmsg", line)) _ = linux.write(1, line.ptr + 3, line.len - 3);
    linux.exit(1);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

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

/// bootMs returns milliseconds since boot (CLOCK_BOOTTIME), or 0.
fn bootMs() u64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}
