//! stage0: PID 1 on every werewolf machine, from the kernel to the root's
//! /init. It raises lockdown, loads the modules, mounts the form's
//! root.erofs read-only directly as the root, and hands over to its /init.
//! Nothing can write the root: what the running system writes goes to /run,
//! /tmp, /var/tmp or /data, and the root is the image, byte for byte, on
//! every boot.
//!
//! The image carries a dm-verity hash tree after its data, and this
//! initramfs the parameters to open it with, /verity, both from the same
//! build (lib/verity.zig). The root is mounted through dm-verity, so every
//! block read from it is checked against the tree, and the tree against its
//! root hash: a block that does not match fails to read
//! (docs/design/verified-boot.md).
//!
//! The image is a slot's on a machine with slots, found on a filesystem the
//! kernel command line names:
//!
//!     werewolf.victim=UUID:DIR   the filesystem, and the directory holding a/ and b/
//!     werewolf.slot=a|b          which slot this boot is
//!     werewolf.deadman=SECONDS   the deadman's wait, 1 to 600, taken only
//!                                from a DEV build's root (make check-deadman)
//!
//! (both, or neither); or, booted directly, /root.erofs in this initramfs,
//! which the build appends (make run), or a disk of its own:
//!
//!     werewolf.root=DEV          the disk holding the image, by its name in
//!                                /dev (Firecracker's vdc), with no slot
//!
//! Every werewolf.* word on the line is checked first, by lib/cmdline.zig,
//! which every later program reads it with: a line it refuses ends the
//! boot here, so none of them meets one.
//!
//! A disk is read as the root is used, where the kernel unpacks an
//! appended image into RAM before stage0 starts, and nothing frees it: on
//! Firecracker 20 MB for the machine's life, and 26 ms of every boot,
//! against 10 ms more of userland reading from the disk.
//!
//! Getting back to a slot that works is the loader's job (GRUB or
//! systemd-boot). A new slot boots once; if anything here fails, stage0
//! exits, the kernel panics, panic=10 reboots it, and the loader boots the
//! slot that last committed. A slot that boots but never commits is caught
//! by the deadman.
//!
//! It is the kernel's first process, so it uses the kernel directly: no
//! shell, no blkid, no mount program. It finds the filesystem by reading
//! each block device's superblock for the UUID, and refuses two: the root
//! image is verified, but /data and the config tar come from that
//! filesystem too, and a clone attached beside it must not stand in.

const std = @import("std");
const linux = std.os.linux;
const dm = @import("dm");
const verity = @import("verity");
const cmdline = @import("cmdline");
const MS = linux.MS; // ziglint-ignore: Z032

/// How long a slot has to commit before the deadman reboots it.
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

    // The whole line, checked here for every program after: one that
    // reads two ways, or not at all, ends the boot before anything does.
    var refused: cmdline.Failure = .{};
    const boot = cmdline.parse(readAll(gpa, "/proc/cmdline"), &refused) orelse
        fail("the command line's {s}: {s}", .{ refused.word, refused.why });

    // Lockdown at integrity before any module: the kernel then loads only
    // those signed by its key, and refuses the rest. It only rises (writing
    // the level it has is refused too, so it is read first); the root's init
    // finds it raised.
    mountFs("securityfs", "/sys/kernel/security", "securityfs", MS.NOSUID | MS.NODEV | MS.NOEXEC);
    const lockdown = "/sys/kernel/security/lockdown";
    if (!isLocked(readAll(gpa, lockdown)) and
        !writeFile(lockdown, "integrity")) fail("cannot raise lockdown", .{});

    // Every module the form needs, then the loader closes for good: the
    // root that follows finds it closed and loads nothing. modload is told
    // the tags this machine needs, a line each. Hyper-V's first: the kernel
    // registers VMBus, built in, only on Hyper-V (Azure), and the slot's
    // disk may sit behind it, so its drivers load before the search; and
    // FAT's on werewolf's own disk (werewolf.esp), for its EFI partition. The
    // disk is looked for while the drivers load, its superblock needing
    // none, and modload then told its filesystem, for the modules that
    // alone needs (xfs's, btrfs's): none for werewolf's own ext4, or with
    // no slot.
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
    // The initramfs stays in RAM after the switch, as nothing frees it:
    // its modules, loaded or refused now, would hold 14 MB for good.
    std.Io.Dir.cwd().deleteTree(io, "/usr/lib/modules") catch |err|
        say("modules not freed: {s}", .{@errorName(err)});
    const modules_ms = bootMs();

    var img: [:0]const u8 = "/root.erofs";
    if (boot.root.len > 0) {
        // Its driver loaded with the rest; its node may still be coming.
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
    // Read-only, and nothing over it: no overlay to write into. dm-verity
    // maps the image, checking each block as it is read: a disk as it is,
    // and a file, in a slot's filesystem or in this initramfs, through a
    // read-only loop device. The device node is made from the number dm
    // gives, not waited for from devtmpfs.
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
    // dm-verity holds the loop device now: autoclear detaches the image
    // when it lets go.
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
        // A shorter wait is for testing the deadman (make check-deadman),
        // so only a DEV build's root, verified now, may ask for one: a
        // released machine waits its ten minutes whatever its command line.
        var after: u32 = deadman_after;
        if (boot.deadman > 0) {
            if (linux.errno(linux.access("/root/usr/share/werewolf/dev", linux.F_OK)) == .SUCCESS) {
                after = boot.deadman;
                say("the deadman waits {d}s (werewolf.deadman, a DEV build)", .{after});
            } else say("werewolf.deadman ignored: not a DEV build", .{});
        }
        deadman(@tagName(slot), after);
    }

    // The root is read-only, so its mount points are in the image already.
    for ([_][:0]const u8{ "dev", "proc", "sys", "victim" }) |m| {
        if (std.mem.eql(u8, m, "victim") and boot.slot == null) continue;
        const from = try gpa.printSentinel("/{s}", .{m}, 0);
        const to = try gpa.printSentinel("/root/{s}", .{m}, 0);
        if (linux.errno(linux.mount(from, to, null, MS.MOVE, 0)) != .SUCCESS)
            fail("cannot move /{s} into the root", .{m});
    }
    // What switch_root does: put the new root over / and start its init
    // inside it.
    if (linux.errno(linux.chdir("/root")) != .SUCCESS) fail("cannot enter /root", .{});
    if (linux.errno(linux.mount(".", "/", null, MS.MOVE, 0)) != .SUCCESS)
        fail("cannot move the root over /", .{});
    if (linux.errno(linux.chroot(".")) != .SUCCESS) fail("cannot enter the root", .{});
    _ = linux.chdir("/");
    say("the kernel took {d}.{d:0>3}s", .{ kernel_ms / 1000, kernel_ms % 1000 });
    // init's environment holds one thing, and nothing the kernel handed
    // stage0: every NAME=value on the command line it did not take itself
    // comes here as environment, and would otherwise go on to every
    // process on the machine. Where the time went, each phase and when it
    // ended, for init to add its own to: the kernel, the modules, the
    // slot's filesystem found and mounted, and the root opened through
    // dm-verity.
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

/// The deadman: a child that outlives this initramfs, sleeping, then looking
/// through PID 1's root for the mark slot-keep leaves; without it, it reboots
/// at once. The loader has spent this slot's one boot, so the machine comes
/// back on the slot that last committed. It touches no file of the
/// initramfs once it sleeps, and reaches PID 1 through a /proc of its own,
/// and the kernel's log through a descriptor opened now: /dev moves into
/// the new root, leaving this one's empty.
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
        // The kernel prints its log to the console from a thread of its
        // own, and sysrq's reset waits for nothing, unlike a panic: a
        // second for the console to say why, or the reboot goes unexplained.
        if (linux.errno(kmsg) == .SUCCESS) {
            _ = linux.write(@intCast(kmsg), msg.ptr, msg.len);
            var pause: linux.timespec = .{ .sec = 1, .nsec = 0 };
            _ = linux.nanosleep(&pause, null);
        }
        // sysrq's reset waits for nothing; should its file be gone, the
        // kernel's own restart, which still holds every capability from
        // before the seal. Never a silent end: the slot would stay.
        if (!writeFile("/deadman/sysrq-trigger", "b"))
            _ = linux.reboot(.MAGIC1, .MAGIC2, .RESTART, null);
    }
    linux.exit(0);
}

// --- a loop device -------------------------------------------------------------

/// <linux/loop.h>, which Zig's std does not carry.
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

/// A free loop device, read-only, holding file, and gone once its last
/// holder is (autoclear). The caller closes fd once something else holds
/// the device: closed before, autoclear would detach the image at once.
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
    // A regular file, no link followed: the slot's filesystem is the
    // disk's, and a FIFO at the image's name would hold PID 1 in open
    // for good, with no panic to fall back on, where a wrong file fails.
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
    // The whole image, data and hash tree, read into the page cache in the
    // background from now: the boot reads most of it, and a cloud's network
    // disk answers a few large reads far sooner than hundreds of small ones.
    // (Asking for the tree first was measured on GCP too: no faster.)
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

/// The block device whose filesystem has uuid, waiting for it to appear:
/// its driver is still loading, or probing, as the search begins. Looked
/// for every 10 ms, so the boot goes on the moment it is there. Two that
/// answer to it, and stage0 fails rather than guess, as the mount broker
/// does: the loader falls back, and so will the other slot, until the
/// second is gone.
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

/// Each block device, its superblock read for want: every one, so that a
/// second with the same UUID is seen.
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

/// One line on the console.
fn say(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "stage0: " ++ fmt ++ "\n", args) catch return;
    _ = linux.write(1, line.ptr, line.len);
}

/// Exiting PID 1 panics the kernel; panic= reboots it, and the loader
/// boots the slot that last committed. The reason goes through /dev/kmsg,
/// which a serial console writes synchronously ("<2>", KERN_CRIT, so it
/// prints whatever the console log level): a plain write to the console tty
/// can still be draining the UART when the panic reboots the machine, and
/// on a fast KVM host it is lost -- exactly when the reason matters most --
/// whereas the kernel flushes its log on panic. The console itself is the
/// fallback for a machine with no /dev/kmsg.
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

/// Milliseconds since the kernel started its clock.
fn bootMs() u64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}
