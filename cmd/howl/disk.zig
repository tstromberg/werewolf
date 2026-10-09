//! disk writes werewolf's UEFI boot disk from a slot: a GPT (boot/gpt.zig),
//! an EFI system partition filled with mtools, and an ext4 partition made
//! with mke2fs -d. See docs/design/native-boot.md.
//!
//! Every GUID, UUID, serial number and time is fixed, so the same slot gives
//! the same disk, byte for byte.

const std = @import("std");
const gpt = @import("gpt");
const build = @import("build.zig");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const mem = std.mem;
const B = build.B;

/// default_mib is a boot disk's size in MiB when no one says: a release's,
/// and every machine's.
pub const default_mib = 8192;

/// Options are the disk's size and the kernel arguments it adds.
pub const Options = struct {
    /// size_mib is the disk's size, as DISK_MIB.
    size_mib: u32 = default_mib,
    /// args go on the kernel command line, as DISK_ARGS; updates carry them
    /// over. Lima's DHCP, for one, needs werewolf.mac=.
    args: []const []const u8 = &.{},
};

const esp_mib = 256;
/// esp_serial is the FAT serial number, which blkid reports as the EFI
/// partition's UUID, esp_uuid.
const esp_serial = "57E1F000";
const esp_uuid = "57E1-F000";
const root_uuid = "57e1f000-77e2-4b0f-8a3c-0000000000a0";
/// epoch is FAT's first day, 1980-01-01, where mtools' and mke2fs's clocks
/// stop.
const epoch_seconds = 315532800;
const epoch = std.fmt.comptimePrint("{d}", .{epoch_seconds});

/// keg_dirs hold e2fsprogs where Homebrew keeps it off the PATH. They come
/// before the PATH: another mke2fs on it, such as Android's, is older.
const keg_dirs = [_][]const u8{
    "/usr/local/opt/e2fsprogs/sbin",
    "/opt/homebrew/opt/e2fsprogs/sbin",
};

/// esp_dirs are the EFI partition's directories, sorted, as mmd makes them.
/// The order of mmd's and mcopy's calls decides where each entry lands.
const esp_dirs = [_][]const u8{
    "EFI",
    "EFI/BOOT",
    "loader",
    "loader/entries",
    "werewolf",
    "werewolf/a",
};

/// Boot is what differs by arch: systemd-boot's file, its name at the
/// removable-media path, and the consoles.
const Boot = struct { efi: []const u8, name: []const u8, console: []const u8 };

/// bootOf returns arch's Boot. The kernel prints to every console named;
/// userland prints to the last one that exists, /dev/console. x86_64's
/// serial port is ttyS0 everywhere. On aarch64 the kernel finds ttyAMA0
/// itself (ACPI SPCR) but not Graviton's 16550, so it names ttyS0, which
/// exists only there, then hvc0 for Lima's vz, which has no serial port.
/// aarch64 names no tty0: it would take /dev/console where the ports are
/// missing. An arg of console=hvc0 makes hvc0 /dev/console on x86_64 too.
fn bootOf(arch: howl.Arch) Boot {
    return switch (arch) {
        .aarch64 => .{
            .efi = "systemd-bootaa64.efi",
            .name = "BOOTAA64.EFI",
            .console = "console=ttyS0,115200 console=hvc0",
        },
        .x86_64 => .{
            .efi = "systemd-bootx64.efi",
            .name = "BOOTX64.EFI",
            .console = "console=tty0 console=hvc0 console=ttyS0,115200",
        },
    };
}

/// write writes out, a sparse disk of the slot in slot_dir (vmlinuz,
/// stage0.zst, root.erofs and cmdline) that boots with systemd-boot from
/// boot_rootfs, boot/boot.yaml's rootfs. It needs mtools and e2fsprogs.
pub fn write(
    b: *B,
    out: []const u8,
    boot_rootfs: []const u8,
    slot_dir: []const u8,
    o: Options,
) !void {
    const io = b.io;
    const arch = b.spec.arch;
    const boot = bootOf(arch);
    const l = gpt.layout(o.size_mib, esp_mib) catch
        return b.fail("a disk of {d} MiB is too small", .{o.size_mib});

    const cmdline_path = try b.path("{s}/cmdline", .{slot_dir});
    const cmdline = Dir.cwd().readFileAlloc(io, cmdline_path, b.gpa, .limited(64 << 10)) catch
        return b.fail("{s} has no cmdline, the image's kernel arguments (make slot)", .{slot_dir});
    const image_args = mem.trimEnd(u8, cmdline, "\n");
    // The image's arguments go on the entry's options line. Allow only
    // plain characters, so no newline starts another line, as bite does.
    for (image_args) |c| if (!std.ascii.isAlphanumeric(c) and
        mem.findScalar(u8, "_.,= -", c) == null)
        return b.fail("{s} holds more than kernel arguments", .{cmdline_path});
    const extra = try mem.join(b.gpa, " ", o.args);
    for (extra) |c| if (std.ascii.isControl(c))
        return b.fail("disk arguments hold a control character: {s}", .{extra});

    var tools: [5][]const u8 = undefined;
    for (&tools, [_][]const u8{ "mformat", "mmd", "mcopy", "mke2fs", "debugfs" }) |*t, name|
        t.* = try tool(b, name);
    const mformat, const mmd, const mcopy, const mke2fs, const debugfs = tools;
    const env = try b.gpa.create(std.process.Environ.Map);
    env.* = try b.env.clone(b.gpa);
    try env.put("SOURCE_DATE_EPOCH", epoch);
    try env.put("E2FSPROGS_FAKE_TIME", epoch);
    try env.put("MTOOLS_SKIP_CHECK", "1");
    try env.put("TZ", "UTC");

    const w = try b.path("{s}.d", .{out});
    try Dir.cwd().deleteTree(io, w);
    Dir.cwd().deleteFile(io, out) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    };
    const esp = try b.path("{s}/esp", .{w});
    const root = try b.path("{s}/root", .{w});
    try Dir.cwd().createDirPath(io, try b.path("{s}/werewolf/a", .{root}));
    for (esp_dirs) |d| try Dir.cwd().createDirPath(io, try b.path("{s}/{s}", .{ esp, d }));
    gpt.create(io, out, l) catch |err| return b.fail("{s}: {t}", .{ out, err });

    // The EFI partition's files, dated FAT's first day, which mcopy -m keeps.
    const efi = try b.path("EFI/BOOT/{s}", .{boot.name});
    {
        const f = try Dir.cwd().createFile(io, try b.path("{s}/{s}", .{ esp, efi }), .{});
        defer f.close(io);
        try b.run(&.{
            "bsdtar", "-xOf", boot_rootfs, try b.path("usr/lib/systemd/boot/efi/{s}", .{boot.efi}),
        }, .{ .stdout = f });
    }
    // No menu, and no editing the command line from the console.
    try b.put(esp, "loader/loader.conf",
        \\timeout 0
        \\editor no
        \\auto-entries no
        \\auto-firmware no
        \\
    );
    // Slot a is good from the start, so it has no try count. Its version is
    // older than any update's, so the first update's slot sorts ahead of it.
    const options = try b.path(
        "{s} init=/init panic=10 softlockup_panic=1 {s} werewolf.victim={s}:/werewolf " ++
            "werewolf.esp={s}{s}{s} werewolf.slot=a",
        .{ boot.console, image_args, root_uuid, esp_uuid, if (extra.len > 0) " " else "", extra },
    );
    try b.put(esp, "loader/entries/werewolf-a.conf", try b.path(
        \\title werewolf a
        \\sort-key werewolf
        \\version 19800101T000000Z
        \\linux /werewolf/a/vmlinuz
        \\initrd /werewolf/a/stage0.zst
        \\options {s}
        \\
    , .{options}));
    for ([_][]const u8{ "vmlinuz", "stage0.zst" }) |name| try b.copy(
        try b.path("{s}/{s}", .{ slot_dir, name }),
        try b.path("{s}/werewolf/a/{s}", .{ esp, name }),
    );
    // Sorted, as the directories are.
    const esp_files = [_][]const u8{
        efi,                     "loader/entries/werewolf-a.conf", "loader/loader.conf",
        "werewolf/a/stage0.zst", "werewolf/a/vmlinuz",
    };
    const then: Io.Timestamp = .fromNanoseconds(epoch_seconds * std.time.ns_per_s);
    for (esp_files) |f| try Dir.cwd().setTimestamps(io, try b.path("{s}/{s}", .{ esp, f }), .{
        .access_timestamp = .{ .new = then },
        .modify_timestamp = .{ .new = then },
    });

    const image = try b.path("{s}@@{d}", .{ out, l.esp_first * gpt.sector });
    try b.run(&.{
        mformat, "-i",  image, "-F", "-T", try b.path("{d}", .{l.root_first - l.esp_first}),
        "-h",    "64",  "-s",  "32", "-N", esp_serial,
        "-v",    "ESP", "::",
    }, .{ .env = env });
    for (esp_dirs) |d| try b.run(
        &.{ mmd, "-i", image, try b.path("::/{s}", .{d}) },
        .{ .env = env },
    );
    for (esp_files) |f| try b.run(&.{
        mcopy, "-m", "-i", image, try b.path("{s}/{s}", .{ esp, f }), try b.path("::/{s}", .{f}),
    }, .{ .env = env });

    // The root partition holds root.erofs under werewolf/. mke2fs -d copies
    // the staged modes: u=rwX,go=rX, but 0700 on werewolf/, so that only
    // root reaches a slot.
    const erofs = try b.path("{s}/werewolf/a/root.erofs", .{root});
    try b.copy(try b.path("{s}/root.erofs", .{slot_dir}), erofs);
    const st = try Dir.cwd().statFile(io, erofs, .{});
    const file_mode: std.posix.mode_t = if (st.permissions.toMode() & 0o111 != 0) 0o755 else 0o644;
    for ([_]struct { []const u8, std.posix.mode_t }{
        .{ root, 0o755 },
        .{ try b.path("{s}/werewolf", .{root}), 0o700 },
        .{ try b.path("{s}/werewolf/a", .{root}), 0o755 },
        .{ erofs, file_mode },
    }) |e| try Dir.cwd().setFilePermissions(io, e[0], .fromMode(e[1]), .{});
    const offset = l.root_first * gpt.sector;
    // No orphan_file (e2fsprogs 1.47's default): ext4 reads all 512 of its
    // blocks at every mount, and stage0 mounts this disk on every boot. On
    // a cloud's network disk that cost 543 reads and 0.21 s, against 48.
    const extended = try b.path("offset={d},hash_seed={s},root_owner=0:0", .{ offset, root_uuid });
    const blocks = try b.path("{d}", .{(l.root_last + 1 - l.root_first) / 8});
    try b.run(&.{
        mke2fs, "-q",      "-F", "-t",           "ext4", "-b",     "4096", "-L", "werewolf",
        "-U",   root_uuid, "-O", "^orphan_file", "-E",   extended, "-d",   root, out,
        blocks,
    }, .{ .env = env });
    // mke2fs -d keeps the builder's owners and times. A file left with the
    // builder's uid would belong to whoever has that uid on the machine.
    var cmds: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "/werewolf", "/werewolf/a", "/werewolf/a/root.erofs" }) |p| {
        for ([_][]const u8{ "uid", "gid" }) |f| try cmds.print(b.gpa, "sif {s} {s} 0\n", .{ p, f });
        for ([_][]const u8{ "atime", "ctime", "mtime", "crtime" }) |f|
            try cmds.print(b.gpa, "sif {s} {s} {s}\n", .{ p, f, epoch });
    }
    const cmds_path = try b.path("{s}/debugfs.cmds", .{w});
    try b.put(w, "debugfs.cmds", cmds.items);
    try b.run(&.{
        debugfs, "-w", "-f", cmds_path, try b.path("{s}?offset={d}", .{ out, offset }),
    }, .{ .env = env });
    try Dir.cwd().deleteTree(io, w);
    try b.steps.note("disk {s} ({t}, {d} MiB, EFI {s}, root {s})", .{
        out, arch, o.size_mib, esp_uuid, root_uuid,
    });
}

/// tool returns where name is: in a keg_dirs directory, or on the PATH.
fn tool(b: *B, name: []const u8) ![]const u8 {
    var dirs: std.ArrayList([]const u8) = .empty;
    try dirs.appendSlice(b.gpa, &keg_dirs);
    var path = mem.tokenizeScalar(u8, howl.environ.get("PATH") orelse "", ':');
    while (path.next()) |d| try dirs.append(b.gpa, d);
    for (dirs.items) |d| {
        const p = try b.path("{s}/{s}", .{ d, name });
        Dir.cwd().access(b.io, p, .{ .execute = true }) catch continue;
        return p;
    }
    return b.fail("no {s}; on macOS, brew install mtools e2fsprogs", .{name});
}
