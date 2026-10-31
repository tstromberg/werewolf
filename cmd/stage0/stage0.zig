//! stage0 is the initramfs's PID 1. It raises lockdown, loads modules,
//! opens the root image through dm-verity, mounts it read-only as /, and
//! execs its /init. See stage0.8.

const std = @import("std");
const linux = std.os.linux;
const dm = @import("dm");
const verity = @import("verity");
const ipe = @import("ipe");
const cmdline = @import("cmdline");
const sandbox = @import("sandbox");
const tpm = @import("tpm");
const uefi_sig = @import("uefi-sig");
const MS = linux.MS; // ziglint-ignore: Z032
const nosymfollow = 256; // Linux MS_NOSYMFOLLOW, absent from std.os.linux.MS.

/// deadman_after is how many seconds a slot has to commit before the
/// deadman reboots it.
const deadman_after = 600;
const find_for = 10; // seconds to wait for the slots disk to appear

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
    const boot_line = readAll(gpa, "/proc/cmdline");
    if (boot_line.len == 0) fail("cannot read /proc/cmdline", .{});
    var boot = cmdline.parse(boot_line, &refused) orelse
        fail("the command line's {s}: {s}", .{ refused.word, refused.why });

    // The kernel forces lockdown to confidentiality from its config, so no
    // one, root included, reads its memory (kcore, perf reads); raise it here
    // too, so a kernel that only allows it is held the same. Writing the
    // current level is refused, so read it first.
    mountFs("securityfs", "/sys/kernel/security", "securityfs", MS.NOSUID | MS.NODEV | MS.NOEXEC);
    const lockdown = "/sys/kernel/security/lockdown";
    if (!isLocked(readAll(gpa, lockdown)) and
        !writeFile(lockdown, "confidentiality")) fail("cannot raise lockdown", .{});

    // The kernel has every driver built in and no module loader: find the
    // slot's disk now.
    const found = if (boot.slots) |u| findFilesystem(gpa, u) else null;
    const disk_ms = bootMs();
    if (boot.native) {
        if (boot.slot != null) fail("native UKI supplied an explicit slot; not handing over", .{});
        const vars = "/sys/firmware/efi/efivars";
        mountFs(
            "efivarfs",
            vars,
            "efivarfs",
            MS.NOSUID | MS.NODEV | MS.NOEXEC | MS.RDONLY | nosymfollow,
        );
        if (boot.secure) {
            const on = readAll(gpa, vars ++ "/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
            const setup = readAll(gpa, vars ++ "/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c");
            if (on.len != 5 or on[4] != 1 or setup.len != 5 or setup[4] != 0)
                fail("Secure Boot required outside setup mode; not handing over " ++
                    "(SecureBoot bytes={d} value={d}, SetupMode bytes={d} value={d})", .{
                    on.len,    if (on.len == 5) on[4] else @as(u8, 255),
                    setup.len, if (setup.len == 5) setup[4] else @as(u8, 255),
                });
            say("Secure Boot enforced outside setup mode", .{});
        }
        boot.slot = cmdline.firmwareSlot(readAll(
            gpa,
            vars ++ "/StubImageIdentifier-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f",
        )) orelse fail("native UKI has no canonical firmware slot path; not handing over", .{});
        const resolved = try gpa.print("{s} werewolf.slot={s}\n", .{
            std.mem.trimEnd(u8, boot_line, "\n"), @tagName(boot.slot.?),
        });
        const record = try std.Io.Dir.cwd().createFile(io, "/boot-cmdline", .{
            .exclusive = true,
            .permissions = .fromMode(0o400),
        });
        defer record.close(io);
        try record.writeStreamingAll(io, resolved);
        if (linux.errno(linux.mount(
            "/boot-cmdline",
            "/proc/cmdline",
            null,
            MS.BIND,
            0,
        )) != .SUCCESS or
            linux.errno(linux.mount(
                null,
                "/proc/cmdline",
                null,
                MS.BIND | MS.REMOUNT | MS.RDONLY | MS.NOSUID | MS.NODEV | MS.NOEXEC | nosymfollow,
                0,
            )) != .SUCCESS)
            fail("cannot protect native boot identity", .{});
        say(
            "native UKI selected slot {s}; unsigned loader options excluded",
            .{@tagName(boot.slot.?)},
        );
    }

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
    if (boot.slots) |u| {
        const f = found orelse fail("no filesystem {s}", .{u});
        mkdir("/boot");
        const rc = linux.mount(
            f.dev,
            "/boot",
            @tagName(f.kind),
            MS.NOSUID | MS.NODEV | MS.NOEXEC,
            0,
        );
        if (linux.errno(rc) != .SUCCESS) fail(
            "cannot mount {s}: {s}",
            .{ f.dev, @tagName(linux.errno(rc)) },
        );
        img = try gpa.printSentinel(
            "/boot/slot/{s}/root.erofs",
            .{@tagName(boot.slot.?)},
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
    // Firmware that admits a second signer would boot that signer's loader
    // beside werewolf, outside every check below.
    if (boot.native and boot.secure) {
        firmwareTrust(gpa) catch |err| fail(
            "Secure Boot: {s}; not handing over",
            .{@errorName(err)},
        );
        say("Secure Boot admits only this image's signer", .{});
    }
    // A release boots only at or above its channel's floor, which this
    // first boot sets and nothing later lowers (lib/tpm.zig).
    const floor = releaseFloor(io, boot) catch |err|
        fail("TPM floor: {s}; not handing over", .{@errorName(err)});
    if (floor) |f| {
        if (f.index < f.floor) fail(
            "TPM floor: release {d} is below its channel's floor, {d}; not handing over",
            .{ f.index, f.floor },
        );
        say("TPM floor {d}: release {d} admitted; reset authority sealed", .{ f.floor, f.index });
    }
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

    // Switch away from initramfs trust before any descendant is forked.
    // The deadman uses only raw calls, so it needs no executable mappings
    // from the initramfs after this policy becomes active.
    enforceIpe(io, gpa, params.root) catch |err|
        fail("IPE: {s}; not handing over", .{@errorName(err)});

    if (boot.slot) |slot| {
        // A shorter wait is for make check-deadman, so only a native test
        // image's root, now verified, may ask for one; howl never exports
        // one as a release. A release always waits ten minutes.
        var after: u32 = deadman_after;
        if (boot.deadman > 0) {
            const marker = "/root/usr/share/werewolf/test-image";
            if (linux.errno(linux.access(marker, linux.F_OK)) == .SUCCESS) {
                after = boot.deadman;
                say("the deadman waits {d}s (werewolf.deadman, a test image)", .{after});
            } else say("werewolf.deadman ignored: not a test image", .{});
        }
        deadman(@tagName(slot), after);
    }

    // The root is read-only, so the image already has these mount points.
    for ([_][:0]const u8{ "dev", "proc", "sys", "boot" }) |m| {
        if (std.mem.eql(u8, m, "boot") and boot.slot == null) continue;
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
    // Pass init only the verified root identity, phase times and TPM floor.
    // The kernel puts every
    // NAME=value it does not take into stage0's environment, and it must not
    // reach every process on the machine.
    var env: std.process.Environ.Map = .init(gpa);
    try env.put("WEREWOLF_ROOT", &std.fmt.bytesToHex(params.root, .lower));
    var marker: [tpm.Marker.max]u8 = undefined;
    if (floor) |f| try env.put("WEREWOLF_ROLLBACK", try f.format(&marker));
    try env.put("WEREWOLF_BOOT", if (slot_ms > 0)
        try gpa.print(
            "kernel={d} disk={d} slot={d} root={d}",
            .{ kernel_ms, disk_ms, slot_ms, root_ms },
        )
    else
        try gpa.print("kernel={d} disk={d} root={d}", .{ kernel_ms, disk_ms, root_ms }));
    const err = std.process.replace(io, .{ .argv = &.{"/init"}, .environ_map = &env });
    fail("cannot start /init: {s}", .{@errorName(err)});
}

/// releaseFloor enrolls or checks the TPM for a release that names its
/// channel, and returns what it found; null for an image without the floor.
/// A root that requires the floor never boots without a release identity.
fn releaseFloor(io: std.Io, boot: cmdline.Cmdline) !?tpm.Marker {
    const required = linux.errno(linux.access(
        "/root" ++ tpm.metadata ++ "/protocol",
        linux.F_OK,
    )) ==
        .SUCCESS;
    const channel = boot.channel orelse {
        if (required) return error.MissingSealedBootIdentity;
        return null;
    };
    if (!required) return error.UnexpectedReleaseIdentity;
    var device = try tpm.Device.open();
    defer device.close();
    return .{
        .handle = tpm.handle(channel),
        .floor = try device.boot(io, channel, boot.index.?),
        .index = boot.index.?,
    };
}

fn enforceIpe(io: std.Io, gpa: std.mem.Allocator, root: [32]u8) !void {
    // Every werewolf kernel has IPE and no policy of its own: an image that
    // does not require IPE runs unenforced; one that does must load its policy.
    if (linux.errno(linux.access("/root" ++ ipe.marker, linux.F_OK)) != .SUCCESS) return;
    if (linux.errno(linux.access(ipe.base, linux.F_OK)) != .SUCCESS) return error.IpeMissing;
    const signed = std.Io.Dir.cwd().readFileAlloc(
        io,
        "/ipe.p7b",
        gpa,
        .limited(ipe.max_policy),
    ) catch
        return error.IpePolicyMissing;
    if (!writeFile(ipe.base ++ "/new_policy", signed)) return error.IpePolicyRejected;
    var expected: std.Io.Writer.Allocating = .init(gpa);
    defer expected.deinit();
    try ipe.policy(&expected.writer, root);
    if (!std.mem.eql(u8, readAll(gpa, ipe.policy_path), expected.written()))
        return error.IpeWrongRoot;
    if (!writeFile(ipe.active, "1") or !writeFile(ipe.base ++ "/enforce", "1") or
        !ipe.enforced(
            readAll(gpa, ipe.policy_path),
            readAll(gpa, ipe.active),
            readAll(gpa, ipe.base ++ "/enforce"),
        ))
        return error.IpeNotEnforced;
    try ipe.lockAdmin();
    say("IPE: only this root image may execute; policy administration removed", .{});
}

/// deadman forks a child that sleeps for after seconds, then reboots unless
/// slot-keep has left its mark in PID 1's root. The loader has spent this
/// slot's one boot, so the machine returns on the slot that last committed.
/// The child reaches PID 1 through a detached /proc descriptor and the kernel
/// log through a descriptor opened now, since /dev moves into the new root.
fn deadman(slot: []const u8, after: u32) void {
    mkdir("/deadman");
    mountFs("proc", "/deadman", "proc", MS.NOSUID | MS.NODEV | MS.NOEXEC);
    const proc_rc = linux.open(
        "/deadman",
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(proc_rc) != .SUCCESS) fail("cannot open /deadman", .{});
    const proc_fd: i32 = @intCast(proc_rc);
    _ = linux.umount2("/deadman", linux.MNT.DETACH);
    _ = linux.rmdir("/deadman");
    const kmsg = linux.open("/dev/kmsg", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) fail("cannot start the deadman", .{});
    if (pid != 0) {
        _ = linux.close(proc_fd);
        if (linux.errno(kmsg) == .SUCCESS) _ = linux.close(@intCast(kmsg));
        return;
    }
    _ = linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0);
    const keep_kmsg = linux.errno(kmsg) == .SUCCESS;
    const kmsg_fd: i32 = if (keep_kmsg) @intCast(kmsg) else -1;
    const kept_fds: []const i32 = if (keep_kmsg) &.{ proc_fd, kmsg_fd } else &.{proc_fd};
    sandbox.closeAllBut(kept_fds) catch fail("cannot close deadman descriptors", .{});
    sandbox.keepOnly(
        (1 << linux.CAP.SYS_BOOT) | (1 << linux.CAP.SYS_PTRACE),
    ) catch fail("cannot drop deadman capabilities", .{});
    var f: sandbox.Filter = .{};
    inline for (.{
        "nanosleep", "clock_nanosleep", "restart_syscall",
        "faccessat", "faccessat2",      "openat",
        "write",     "close",           "reboot",
        "exit",      "exit_group",
    }) |name| f.allow(name);
    f.install() catch fail("cannot confine the deadman", .{});

    var ts: linux.timespec = .{ .sec = after, .nsec = 0 };
    while (linux.errno(linux.nanosleep(&ts, &ts)) == .INTR) {}
    if (linux.errno(linux.faccessat(
        proc_fd,
        "1/root/run/werewolf/committed",
        linux.F_OK,
        0,
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
        if (keep_kmsg) {
            _ = linux.write(kmsg_fd, msg.ptr, msg.len);
            var pause: linux.timespec = .{ .sec = 1, .nsec = 0 };
            _ = linux.nanosleep(&pause, null);
        }
        // If sysrq-trigger fails, call reboot: this process keeps
        // CAP_SYS_BOOT. Exiting quietly would leave the bad slot running.
        const trig = linux.openat(
            proc_fd,
            "sysrq-trigger",
            .{ .ACCMODE = .WRONLY, .CLOEXEC = true },
            0,
        );
        if (linux.errno(trig) == .SUCCESS) {
            _ = linux.write(@intCast(trig), "b", 1);
            _ = linux.close(@intCast(trig));
        }
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

// --- the slots filesystem ----------------------------------------------------

const Kind = enum { ext4 };
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
    var buf: [4096]u8 = undefined;
    const n = linux.pread(@intCast(fd), &buf, buf.len, 0);
    if (linux.errno(n) != .SUCCESS) return null;
    const id = identify(buf[0..n]) orelse return null;
    return if (std.mem.eql(u8, &id.uuid, &want)) id.kind else null;
}

/// identify returns the filesystem kind and UUID in a device's first bytes:
/// ext2/3/4 at 1 KiB (magic 0xEF53).
fn identify(b: []const u8) ?struct { kind: Kind, uuid: [16]u8 } {
    if (b.len >= 1024 + 0x78 and std.mem.readInt(u16, b[1024 + 0x38 ..][0..2], .little) == 0xEF53)
        return .{ .kind = .ext4, .uuid = b[1024 + 0x68 ..][0..16].* };
    return null;
}

fn isLocked(text: []const u8) bool {
    return std.mem.indexOf(u8, text, "[confidentiality]") != null;
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
/// firmwareTrust requires that the signers firmware admits, db's
/// certificates less dbx's, are exactly the image's boot certificate, which
/// howl puts in the verified root. An extra one is named by its hash: a
/// cloud template's CA, or one an enrollment left behind.
fn firmwareTrust(gpa: std.mem.Allocator) !void {
    const vars = "/sys/firmware/efi/efivars";
    const own = readAll(gpa, "/root/usr/share/werewolf/boot.der");
    if (own.len == 0) return error.NoBootCertificate;
    const pk_text = readAll(gpa, vars ++ "/" ++ uefi_sig.pk_name);
    const kek_text = readAll(gpa, vars ++ "/" ++ uefi_sig.kek_name);
    const db_text = readAll(gpa, vars ++ "/" ++ uefi_sig.db_name);
    const dbx_text = readAll(gpa, vars ++ "/" ++ uefi_sig.dbx_name);
    try checkFirmwareTrust(gpa, pk_text, kek_text, db_text, dbx_text, own, true);
}

fn checkFirmwareTrust(
    gpa: std.mem.Allocator,
    pk_text: []const u8,
    kek_text: []const u8,
    db_text: []const u8,
    dbx_text: []const u8,
    own: []const u8,
    log_foreign: bool,
) !void {
    const eval = try uefi_sig.evaluate(gpa, pk_text, kek_text, db_text, dbx_text, own);
    var found = false;
    var extra: usize = 0;
    for (eval.active_db) |certificate| {
        if (std.mem.eql(u8, certificate, own)) {
            found = true;
            continue;
        }
        extra += 1;
        if (log_foreign) {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(certificate, &digest, .{});
            const encoded = try gpa.alloc(
                u8,
                std.base64.standard.Encoder.calcSize(certificate.len),
            );
            say("Secure Boot admits another signer, sha256 {x} der {s}", .{
                &digest,
                std.base64.standard.Encoder.encode(encoded, certificate),
            });
        }
    }
    if (extra > 0) return error.ForeignSignerInDb;
    if (!found) return error.SignerNotInDb;
}

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

test checkFirmwareTrust {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const cas = @import("files").microsoft_uefi_cas;
    const own = cas[0];
    const ms_pk = cas[1];

    var pk: std.ArrayList(u8) = .empty;
    try uefi_sig.encodeList(gpa, &pk, uefi_sig.x509_guid, &.{ms_pk});
    var kek: std.ArrayList(u8) = .empty;
    try uefi_sig.encodeList(gpa, &kek, uefi_sig.x509_guid, &.{ms_pk});

    // Azure template: all 4 CAs + own in db.
    var db: std.ArrayList(u8) = .empty;
    try uefi_sig.encodeList(gpa, &db, uefi_sig.x509_guid, &cas);
    var own_db: std.ArrayList(u8) = .empty;
    try uefi_sig.encodeList(gpa, &own_db, uefi_sig.x509_guid, &.{ cas[1], cas[2], cas[3], own });

    // Bare SHA-256 digests in dbx do NOT revoke X.509 signers in UEFI firmware.
    var sha_dbx: std.ArrayList(u8) = .empty;
    for (cas[1..]) |ca| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(ca, &digest, .{});
        try uefi_sig.encodeList(gpa, &sha_dbx, uefi_sig.sha256_guid, &.{&digest});
    }
    try testing.expectError(
        error.ForeignSignerInDb,
        checkFirmwareTrust(gpa, pk.items, kek.items, own_db.items, sha_dbx.items, own, false),
    );

    // X.509 certificate entries in dbx DO revoke the foreign CAs, leaving own alone.
    var x509_dbx: std.ArrayList(u8) = .empty;
    try uefi_sig.encodeList(gpa, &x509_dbx, uefi_sig.x509_guid, cas[1..]);
    try checkFirmwareTrust(gpa, pk.items, kek.items, own_db.items, x509_dbx.items, own, false);

    // Custom PK (PK == own) rejects an extra KEK or binary hash allowlist in db.
    var own_pk: std.ArrayList(u8) = .empty;
    try uefi_sig.encodeList(gpa, &own_pk, uefi_sig.x509_guid, &.{own});
    var extra_kek: std.ArrayList(u8) = .empty;
    try uefi_sig.encodeList(gpa, &extra_kek, uefi_sig.x509_guid, &.{ own, ms_pk });
    try testing.expectError(
        error.ForeignKek,
        checkFirmwareTrust(gpa, own_pk.items, extra_kek.items, own_pk.items, "", own, false),
    );
}

test identify {
    var b: [4096]u8 = @splat(0);
    try testing.expectEqual(null, identify(&b));

    std.mem.writeInt(u16, b[1024 + 0x38 ..][0..2], 0xEF53, .little);
    b[1024 + 0x68] = 0x57;
    const id = identify(&b).?;
    try testing.expectEqual(Kind.ext4, id.kind);
    try testing.expectEqual(0x57, id.uuid[0]);
}

test LoopConfig {
    // The kernel's struct loop_config is 304 bytes; LOOP_CONFIGURE reads
    // exactly that.
    try testing.expectEqual(232, @sizeOf(LoopInfo64));
    try testing.expectEqual(304, @sizeOf(LoopConfig));
}

test isLocked {
    try testing.expect(isLocked("none integrity [confidentiality]\n"));
    try testing.expect(!isLocked("none [integrity] confidentiality\n"));
    try testing.expect(!isLocked("[none] integrity confidentiality\n"));
}

/// bootMs returns milliseconds since boot (CLOCK_BOOTTIME), or 0.
fn bootMs() u64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}
