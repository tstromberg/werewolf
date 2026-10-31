//! Disposable storage-appliance integration checks. Arguments are trusted
//! kernel, helper initramfs, PostgreSQL image and its verity parameters.
//! Public fixtures only; no existing VM or host directory is attached.
const std = @import("std");
const data = @import("data-transfer");
const helper = @import("data-helper.zig");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const Captured = struct { policy: data.Policy, archive: []const u8 };

pub fn main(init: std.process.Init) !void {
    howl.environ = init.environ_map;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len < 5 or args.len > 8) return error.TransferTestArguments;
    const io = init.io;
    const cwd = try std.process.currentPathAlloc(io, a);
    const arch = howl.hostArch() orelse return error.UnsupportedHostArch;
    const verity = try @import("verity").Params.parse(try Dir.cwd().readFileAlloc(
        io,
        args[4],
        a,
        .limited(4096),
    ));
    const image = std.fmt.bytesToHex(verity.root, .lower);
    const guest: helper.Guest = .{
        .arch = arch,
        .kernel = try std.fs.path.resolveAlloc(a, &.{ cwd, args[1] }),
        .initramfs = try std.fs.path.resolveAlloc(a, &.{ cwd, args[2] }),
        .image = try std.fs.path.resolveAlloc(a, &.{ cwd, args[3] }),
        .verity = verity,
    };
    var nonce: [12]u8 = undefined;
    try io.randomSecure(&nonce);
    const work = try a.print(
        "/tmp/werewolf-transfer-check-{s}",
        .{std.fmt.bytesToHex(nonce, .lower)},
    );
    try Dir.cwd().createDir(io, work, .fromMode(0o700));
    var check: Check = .{ .io = io, .a = a, .work = work, .guest = guest, .image = &image };
    errdefer howl.say(
        io,
        "transfer-check failed in {s}; public fixture kept at {s}",
        .{ check.phase, work },
    );
    if (args.len >= 6) try check.boundaries(try std.fs.path.resolveAlloc(a, &.{ cwd, args[5] }));
    try check.run();
    if (args.len >= 7) try check.cli(try std.fs.path.resolveAlloc(a, &.{ cwd, args[6] }));
    if (args.len == 8) {
        try check.encrypted(try std.fs.path.resolveAlloc(a, &.{ cwd, args[7] }));
        try File.stdout().writeStreamingAll(
            io,
            "data-transfer: encrypted source/destination, wrong-key rejection and plaintext " ++
                "restore passed\n",
        );
    }
    try Dir.cwd().deleteTree(io, work);
    try File.stdout().writeStreamingAll(
        io,
        "data-transfer: offline full/service round trips, source immutability, exclusions, " ++
            "corruption, conflict and dirty-source checks passed\n",
    );
}

const Check = struct {
    io: Io,
    a: Allocator,
    work: []const u8,
    guest: helper.Guest,
    image: []const u8,
    why: howl.Why = .{},
    phase: []const u8 = "fixture creation",
    replay_copy: bool = false,

    fn path(c: *Check, name: []const u8) ![]const u8 {
        return c.a.print("{s}/{s}", .{ c.work, name });
    }
    fn boundaries(c: *Check, initramfs: []const u8) !void {
        try c.guard();
        c.phase = "Linux privilege boundaries";
        const console = try c.path("boundaries.log");
        const output = try c.path("boundaries.out");
        var guest = c.guest;
        guest.initramfs = initramfs;
        try helper.execute(
            c.io,
            try helper.argv(
                c.io,
                c.a,
                guest,
                .{ .data = guest.image, .control = guest.image },
                console,
                output,
            ),
            .fromSeconds(120),
        );
        const log = try Dir.cwd().readFileAlloc(c.io, console, c.a, .limited(1 << 20));
        if (mem.find(u8, log, "transfer-boundaries-passed") == null or
            mem.find(u8, log, "SKIP") != null)
            return error.TransferTestBoundary;
    }

    fn guard(c: *Check) !void {
        c.phase = "helper retains lifecycle lock after its parent closes it";
        const guard_path = try c.path("guard.lock");
        const held = try Dir.cwd().createFile(
            c.io,
            guard_path,
            .{ .permissions = .fromMode(0o600) },
        );
        var held_open = true;
        defer if (held_open) held.close(c.io);
        try held.lock(c.io, .exclusive);
        var args: std.ArrayList([]const u8) = .empty;
        try args.appendSlice(c.a, try helper.argv(c.io, c.a, c.guest, .{
            .data = c.guest.image,
            .control = c.guest.image,
            .guard = held,
        }, try c.path("guard.log"), try c.path("guard.out")));
        try args.append(c.a, "-S");
        var child = try std.process.spawn(c.io, .{
            .argv = args.items,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
            .inherit_files = &.{held},
        });
        defer child.kill(c.io);
        const probe = try Dir.cwd().openFile(c.io, guard_path, .{ .mode = .read_write });
        defer probe.close(c.io);
        held.close(c.io);
        held_open = false;
        for (0..10) |_| {
            try c.io.sleep(.fromMilliseconds(100), .awake);
            if (try probe.tryLock(c.io, .exclusive)) return error.TransferTestLockLost;
        }
        child.kill(c.io);
        if (!try probe.tryLock(c.io, .exclusive)) return error.TransferTestLockLeaked;
        probe.unlock(c.io);
    }
    fn command(c: *Check, args: []const []const u8) ![]const u8 {
        const r = try std.process.run(
            c.a,
            c.io,
            .{
                .argv = args,
                .stdout_limit = .limited(4 << 20),
                .stderr_limit = .limited(16 << 10),
            },
        );
        if (!r.term.success()) return error.TransferTestTool;
        return r.stdout;
    }
    fn debug(c: *Check, disk: []const u8, command_text: []const u8, write: bool) ![]const u8 {
        const mk = @import("ext4.zig").findMke2fs(c.io, c.a) orelse return error.TransferTestTool;
        const bin = try c.a.print("{s}/debugfs", .{std.fs.path.dirname(mk).?});
        return c.command(if (write)
            &.{ bin, "-w", "-R", command_text, disk }
        else
            &.{ bin, "-R", command_text, disk });
    }
    fn volume(
        c: *Check,
        name: []const u8,
        files: []const []const u8,
        contents: []const []const u8,
    ) ![]const u8 {
        const tree = try c.path(try c.a.print("{s}-tree", .{name}));
        try Dir.cwd().createDir(c.io, tree, .fromMode(0o755));
        for (files, contents) |path_name, bytes| {
            const dest = try c.a.print("{s}/{s}", .{ tree, path_name });
            try Dir.cwd().createDirPath(c.io, std.fs.path.dirname(dest).?);
            try Dir.cwd().writeFile(c.io, .{ .sub_path = dest, .data = bytes });
        }
        try Dir.cwd().createDirPath(c.io, try c.a.print("{s}/.werewolf", .{tree}));
        try Dir.cwd().writeFile(
            c.io,
            .{
                .sub_path = try c.a.print("{s}/.werewolf/data-image", .{tree}),
                .data = try c.a.print("{s}\n", .{c.image}),
                .flags = .{ .permissions = .fromMode(0o600) },
            },
        );
        Dir.cwd().setFilePermissions(
            c.io,
            try c.a.print("{s}/.werewolf", .{tree}),
            .fromMode(0o700),
            .{ .follow_symlinks = false },
        ) catch |err|
            if (err != error.FileNotFound) return err;
        const disk = try c.path(try c.a.print("{s}.img", .{name}));
        const f = try Dir.cwd().createFile(
            c.io,
            disk,
            .{ .exclusive = true, .permissions = .fromMode(0o600) },
        );
        defer f.close(c.io);
        try f.setLength(c.io, 96 << 20);
        const mk = @import("ext4.zig").findMke2fs(c.io, c.a) orelse return error.TransferTestTool;
        _ = try c.command(&.{
            mk,
            "-q",
            "-F",
            "-t",
            "ext4",
            "-o",
            "Linux",
            "-m",
            "0",
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,no_copy_xattrs",
            "-d",
            tree,
            disk,
        });
        // Host SELinux labels are not guest fixture metadata. mke2fs omits
        // those xattrs above, but preserves ownership. Normalize this fixture
        // to the image's approved root identity, never change source VMs.
        var dir = try Dir.cwd().openDir(c.io, tree, .{ .iterate = true });
        defer dir.close(c.io);
        var walker = try dir.walk(c.a);
        defer walker.deinit();
        while (try walker.next(c.io)) |entry| {
            for ([_][]const u8{ "uid", "gid" }) |field|
                _ = try c.debug(
                    disk,
                    try c.a.print("set_inode_field /{s} {s} 0", .{ entry.path, field }),
                    true,
                );
        }
        return disk;
    }
    fn invoke(
        c: *Check,
        label: []const u8,
        disk: []const u8,
        archive: ?[]const u8,
        scope: ?[]const u8,
    ) !Captured {
        return c.withKey(label, disk, archive, scope, null);
    }
    fn withKey(
        c: *Check,
        label: []const u8,
        disk: []const u8,
        archive: ?[]const u8,
        scope: ?[]const u8,
        key: ?[]const u8,
    ) !Captured {
        c.phase = label;
        const work = try c.path(label);
        try Dir.cwd().createDir(c.io, work, .fromMode(0o700));
        const control = try helper.controlDisk(c.io, c.a, work, .{
            .operation = if (archive != null) "import" else "export",
            .layout = "volume",
            .image = c.image,
            .verity = c.guest.verity,
            .arch = @tagName(c.guest.arch),
            .target = "public-fixture",
            .service = scope,
            .initialize = archive != null,
            .replay_journal_on_copy = c.replay_copy,
        }, archive, key, &c.why);
        const policy = try helper.run(
            c.io,
            c.a,
            c.guest,
            .{ .data = disk, .control = control, .writable = archive != null or c.replay_copy },
            work,
        );
        return .{ .policy = policy, .archive = try c.a.print("{s}/archive.tar.zst", .{work}) };
    }

    fn encryptedVolume(
        c: *Check,
        initramfs: []const u8,
        label: []const u8,
        key: []const u8,
        empty: bool,
    ) ![]const u8 {
        c.phase = label;
        const work = try c.path(label);
        try Dir.cwd().createDir(c.io, work, .fromMode(0o700));
        const disk = try c.a.print("{s}/volume.raw", .{work});
        const file = try Dir.cwd().createFile(c.io, disk, .{ .permissions = .fromMode(0o600) });
        try file.setLength(c.io, 128 << 20);
        file.close(c.io);
        const control = try helper.controlDisk(c.io, c.a, work, .{
            .operation = "inspect",
            .layout = "volume",
            .image = c.image,
            .verity = c.guest.verity,
            .arch = @tagName(c.guest.arch),
            .target = "public-encrypted-fixture",
            .initialize = empty,
        }, null, key, &c.why);
        var guest = c.guest;
        guest.initramfs = initramfs;
        const console = try c.a.print("{s}/prepare.log", .{work});
        try helper.execute(
            c.io,
            try helper.argv(
                c.io,
                c.a,
                guest,
                .{ .data = disk, .control = control, .writable = true },
                console,
                try c.a.print("{s}/prepare.out", .{work}),
            ),
            .fromSeconds(120),
        );
        const text = try Dir.cwd().readFileAlloc(c.io, console, c.a, .limited(1 << 20));
        if (mem.find(
            u8,
            text,
            "encrypted-fixture-ready",
        ) == null) return error.TransferTestEncryption;
        return disk;
    }

    fn encrypted(c: *Check, initramfs: []const u8) !void {
        const key = try c.path("fixture.key");
        const wrong = try c.path("wrong.key");
        try Dir.cwd().writeFile(
            c.io,
            .{
                .sub_path = key,
                .data = "public fixture key 0123456789abcdef",
                .flags = .{ .permissions = .fromMode(0o600) },
            },
        );
        try Dir.cwd().writeFile(
            c.io,
            .{
                .sub_path = wrong,
                .data = "wrong fixture key 0123456789abcdef!",
                .flags = .{ .permissions = .fromMode(0o600) },
            },
        );
        const source = try c.encryptedVolume(initramfs, "encrypted-source", key, false);
        const before = (try @import("prebuilt").hashFile(c.io, c.a, source)).sha256;
        for ([_]?[]const u8{ null, wrong }, 0..) |bad_key, n| {
            if (c.withKey(
                try c.a.print("encrypted-refused-{d}", .{n}),
                source,
                null,
                null,
                bad_key,
            )) |_|
                return error.TransferTestKeyAccepted
            else |err| if (err != error.TransferKey) return err;
        }
        const archive = try c.withKey("encrypted-export", source, null, null, key);
        _ = try c.validate(archive.archive, archive.policy, null);
        try c.equal(before, (try @import("prebuilt").hashFile(c.io, c.a, source)).sha256);
        const target = try c.encryptedVolume(initramfs, "encrypted-target", key, true);
        const empty = (try @import("prebuilt").hashFile(c.io, c.a, target)).sha256;
        if (c.withKey("encrypted-import-wrong-key", target, archive.archive, null, wrong)) |_|
            return error.TransferTestKeyAccepted
        else |err| if (err != error.TransferKey) return err;
        try c.equal(empty, (try @import("prebuilt").hashFile(c.io, c.a, target)).sha256);
        _ = try c.withKey("encrypted-import", target, archive.archive, null, key);
        const restored = try c.withKey("encrypted-restored-export", target, null, null, key);
        const result = try c.validate(restored.archive, restored.policy, null);
        if (result.manifest.entries.len != 3) return error.TransferTestEncryption;
        const plain = try c.volume("encrypted-plain-target", &.{}, &.{});
        _ = try c.invoke("encrypted-to-plain", plain, restored.archive, null);
        try c.equal(
            "encrypted public fixture\n",
            try c.debug(plain, "cat /svc/postgres/payload", false),
        );
    }
    fn validate(
        c: *Check,
        filename: []const u8,
        policy: data.Policy,
        scope: ?[]const u8,
    ) !data.Result {
        c.phase = "host archive validation";
        const f = try Dir.cwd().openFile(c.io, filename, .{});
        defer f.close(c.io);
        var buf: [64 << 10]u8 = undefined;
        var input = f.readerStreaming(c.io, &buf);
        return data.zstd.validate(c.a, &input.interface, policy, scope, null);
    }
    fn equal(_: *Check, want: []const u8, got: []const u8) !void {
        if (!mem.eql(u8, want, got)) return error.TransferTestBytes;
    }
    fn hash(c: *Check, filename: []const u8) ![]const u8 {
        return (try @import("prebuilt").hashFile(c.io, c.a, filename)).sha256;
    }

    // A real CLI check using disposable GPT disks. These images are never
    // booted as applications; Secure Boot remains a separate lifecycle gate.
    fn bootVolume(c: *Check, at: []const u8, occupied: bool) !void {
        const tree = try c.a.print("{s}/tree", .{at});
        try Dir.cwd().createDirPath(c.io, try c.a.print("{s}/slot/a", .{tree}));
        try Dir.cwd().copyFile(
            c.guest.image,
            .cwd(),
            try c.a.print("{s}/slot/a/root.erofs", .{tree}),
            c.io,
            .{},
        );
        try Dir.cwd().createDirPath(c.io, try c.a.print("{s}/data/.werewolf", .{tree}));
        try Dir.cwd().writeFile(
            c.io,
            .{
                .sub_path = try c.a.print("{s}/data/.werewolf/data-image", .{tree}),
                .data = try c.a.print("{s}\n", .{c.image}),
                .flags = .{ .permissions = .fromMode(0o600) },
            },
        );
        try Dir.cwd().setFilePermissions(
            c.io,
            try c.a.print("{s}/data/.werewolf", .{tree}),
            .fromMode(0o700),
            .{},
        );
        if (occupied) {
            try Dir.cwd().createDirPath(c.io, try c.a.print("{s}/data/svc/postgres", .{tree}));
            try Dir.cwd().writeFile(
                c.io,
                .{
                    .sub_path = try c.a.print("{s}/data/svc/postgres/payload", .{tree}),
                    .data = "CLI archive bytes\n",
                },
            );
            try Dir.cwd().writeFile(
                c.io,
                .{
                    .sub_path = try c.a.print("{s}/data/.hidden", .{tree}),
                    .data = "hidden CLI bytes\n",
                },
            );
        }
        const disk = try c.a.print("{s}/disk.img", .{at});
        const layout = try @import("gpt").layout(512, 16);
        try @import("gpt").create(c.io, disk, layout);
        const mk = @import("ext4.zig").findMke2fs(c.io, c.a) orelse return error.TransferTestTool;
        _ = try c.command(&.{
            mk,
            "-q",
            "-F",
            "-t",
            "ext4",
            "-o",
            "Linux",
            "-b",
            "4096",
            "-m",
            "0",
            "-E",
            try c.a.print(
                "offset={d},lazy_itable_init=0,lazy_journal_init=0," ++
                    "root_owner=0:0,no_copy_xattrs",
                .{layout.root_first * 512},
            ),
            "-d",
            tree,
            disk,
            try c.a.print("{d}", .{(layout.root_last + 1 - layout.root_first) / 8}),
        });
        const view = try c.a.print("{s}?offset={d}", .{ disk, layout.root_first * 512 });
        var dir = try Dir.cwd().openDir(c.io, tree, .{ .iterate = true });
        defer dir.close(c.io);
        var walker = try dir.walk(c.a);
        defer walker.deinit();
        while (try walker.next(c.io)) |entry| for ([_][]const u8{ "uid", "gid" }) |field| {
            _ = try c.debug(view, try c.a.print("sif /{s} {s} 0", .{ entry.path, field }), true);
        };
        try Dir.cwd().deleteTree(c.io, tree);
        try Dir.cwd().createDirPath(c.io, try c.a.print("{s}/authority", .{at}));
        const image_out = std.fs.path.dirname(std.fs.path.dirname(c.guest.image).?).?;
        const profile: @import("local-secure.zig").Profile = .{
            .spec = .{
                .form = std.fs.path.basename(image_out),
                .arch = c.guest.arch,
                .build = std.fs.path.dirname(image_out),
                .disk_path = disk,
                .boot_cert = try c.path("fixture-public.crt"),
            },
            .provider = .qemu,
            .managed = false,
        };
        try Dir.cwd().writeFile(
            c.io,
            .{
                .sub_path = try c.a.print("{s}/authority/profile.json", .{at}),
                .data = try std.json.Stringify.valueAlloc(c.a, profile, .{}),
            },
        );
    }

    fn cliCommand(c: *Check, binary: []const u8, args: []const []const u8, success: bool) !void {
        var env = try howl.environ.clone(c.a);
        try env.put("HOME", c.work);
        try env.put("XDG_DATA_HOME", c.work);
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.append(c.a, binary);
        try argv.appendSlice(c.a, args);
        const result = try std.process.run(
            c.a,
            c.io,
            .{
                .argv = argv.items,
                .environ_map = &env,
                .stdout_limit = .limited(1 << 20),
                .stderr_limit = .limited(1 << 20),
            },
        );
        if (result.term.success() != success) {
            howl.say(c.io, "CLI {s}: {s}{s}", .{ args[0], result.stdout, result.stderr });
            return error.TransferTestCli;
        }
    }

    fn cli(c: *Check, binary: []const u8) !void {
        c.phase = "CLI full and selected round trips";
        const suffix = std.fs.path.basename(c.work)["werewolf-transfer-check-".len..][0..8];
        const names = [_][]const u8{
            try c.a.print("transfer-source-{s}", .{suffix}),
            try c.a.print("transfer-target-{s}", .{suffix}),
            try c.a.print("transfer-service-{s}", .{suffix}),
        };
        try Dir.cwd().writeFile(
            c.io,
            .{
                .sub_path = try c.path("fixture-public.crt"),
                .data = "public storage fixture; never enrolled or booted\n",
            },
        );
        for (names, 0..) |name, i| {
            const at = try howl.machineDir(c.a, name);
            try Dir.cwd().createDirPath(c.io, at);
            try c.bootVolume(at, i == 0);
        }
        defer for (names) |name| Dir.cwd().deleteTree(
            c.io,
            howl.machineDir(c.a, name) catch continue,
        ) catch {};
        const archive = try c.path("cli.tar.zst");
        const source_disk = try c.a.print("{s}/disk.img", .{try howl.machineDir(c.a, names[0])});
        const before = try c.hash(source_disk);
        // A missing PID file must not bypass the hypervisor's storage lock.
        // This paused process never executes a guest instruction or writes data.
        var holder = try std.process.spawn(c.io, .{
            .argv = &.{
                if (c.guest.arch == .aarch64) "qemu-system-aarch64" else "qemu-system-x86_64",
                "-M",
                if (c.guest.arch == .aarch64) "virt" else "q35",
                "-S",
                "-nodefaults",
                "-display",
                "none",
                "-monitor",
                "none",
                "-nic",
                "none",
                "-drive",
                try c.a.print("if=none,id=data,format=raw,file={s}", .{source_disk}),
                "-device",
                "virtio-blk-pci,drive=data",
            },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        defer holder.kill(c.io);
        // Observe the storage lock rather than assuming the child has started.
        var locked = false;
        for (0..100) |_| {
            const probe = try std.process.run(
                c.a,
                c.io,
                .{ .argv = &.{ "lsof", "-Fpcfn", "--", source_disk } },
            );
            if (probe.term.success() and probe.stdout.len > 0) {
                locked = true;
                break;
            }
            try c.io.sleep(.fromMilliseconds(20), .awake);
        }
        if (!locked) return error.TransferTestStorageLock;
        try c.cliCommand(binary, &.{ "export", names[0], "--output", archive }, false);
        try c.cliCommand(binary, &.{ "import", names[0], "not-an-archive" }, false);
        holder.kill(c.io);
        try c.equal(before, try c.hash(source_disk));
        try c.cliCommand(binary, &.{ "export", names[0], "--output", archive }, true);
        try c.equal(before, try c.hash(source_disk));
        if ((try Dir.cwd().statFile(c.io, archive, .{})).permissions.toMode() & 0o777 != 0o600)
            return error.TransferTestPermissions;
        try c.cliCommand(binary, &.{ "export", names[0], "--output", archive }, false);
        try c.cliCommand(binary, &.{ "import", names[1], archive }, true);
        try c.cliCommand(binary, &.{ "import", names[1], archive }, false);
        try c.cliCommand(binary, &.{ "import", names[2], archive, "--service", "postgres" }, true);
        try c.cliCommand(binary, &.{ "sync", names[2], c.work }, false);
        try c.cliCommand(binary, &.{ "import", names[2], "--retry", "old-snapshot" }, false);
        try c.cliCommand(binary, &.{ "import", names[2], c.work }, false);
        try c.cliCommand(binary, &.{ "create", names[2], "--import", c.work }, false);
        // Verify target bytes through another complete CLI export.
        const restored = try c.path("cli-restored.tar.zst");
        try c.cliCommand(binary, &.{ "export", names[1], "--output", restored }, true);
        try c.equal(try c.hash(archive), try c.hash(restored));
    }
    fn run(c: *Check) !void {
        const payload = try c.a.alloc(u8, 33 << 20);
        Io.random(c.io, payload);
        const source = try c.volume(
            "source",
            &.{
                "extra",
                ".hidden",
                "svc/postgres/payload",
                ".werewolf/source-identity",
                "svc/sshd/host-key",
                "log/current",
            },
            &.{
                "outside services\n",
                "",
                payload,
                "source authority",
                "source SSH key",
                "source audit trail",
            },
        );
        const before = try c.hash(source);
        const full = try c.invoke("full-export", source, null, null);
        const inventory = try c.validate(full.archive, full.policy, null);
        var has_log = false;
        for (inventory.manifest.entries) |e|
            if (mem.eql(u8, e.path, "log/current") and e.kind == .file) {
                has_log = true;
            };
        if (!has_log) return error.TransferTestMissingLogs;
        try c.equal(before, try c.hash(source));
        {
            const replay = try c.path("journal-copy.raw");
            try Dir.cwd().copyFile(source, .cwd(), replay, c.io, .{});
            _ = try c.debug(replay, "feature needs_recovery", true);
            c.replay_copy = true;
            defer c.replay_copy = false;
            const recovered = try c.invoke("journal-copy-export", replay, null, null);
            _ = try c.validate(recovered.archive, recovered.policy, null);
            try c.equal(before, try c.hash(source));
        }
        for (inventory.manifest.entries) |e| if (data.excluded(
            e.path,
        )) return error.TransferTestExclusion;
        const selected = try c.invoke("service-export", source, null, "postgres");
        const selected_inventory = try c.validate(selected.archive, selected.policy, "postgres");
        for (selected_inventory.manifest.entries) |e|
            if (!data.selected(e.path, "postgres")) return error.TransferTestScope;
        try c.equal(before, try c.hash(source));
        const destination = try c.volume(
            "destination",
            &.{ ".werewolf/destination-identity", "log/current" },
            &.{ "destination authority", "destination audit trail" },
        );
        _ = try c.invoke("full-import", destination, full.archive, null);
        try c.equal("outside services\n", try c.debug(destination, "cat /extra", false));
        try c.equal(
            "destination authority",
            try c.debug(destination, "cat /.werewolf/destination-identity", false),
        );
        try c.equal("destination audit trail", try c.debug(destination, "cat /log/current", false));
        const restored = try c.path("restored");
        _ = try c.debug(
            destination,
            try c.a.print("dump /svc/postgres/payload {s}", .{restored}),
            false,
        );
        try c.equal(
            payload,
            try Dir.cwd().readFileAlloc(c.io, restored, c.a, .limited(payload.len + 1)),
        );
        const fresh = try c.volume("fresh", &.{}, &.{});
        _ = try c.debug(fresh, "rm /.werewolf/data-image", true);
        _ = try c.invoke("fresh-import", fresh, selected.archive, null);
        try c.equal(
            try c.a.print("{s}\n", .{c.image}),
            try c.debug(fresh, "cat /.werewolf/data-image", false),
        );
        if (c.invoke("fresh-import-repeat", fresh, selected.archive, null)) |_|
            return error.TransferTestConflict
        else |err| if (err != error.TransferInstall)
            return err;
        for ([_]?[]const u8{ "postgres", null }, 0..) |scope, i| {
            const dest = try c.volume(
                try c.a.print("selected-{d}", .{i}),
                &.{ "svc/plex/sentinel", ".werewolf/destination-identity" },
                &.{ "keep Plex", "destination authority" },
            );
            _ = try c.invoke(
                try c.a.print("selected-import-{d}", .{i}),
                dest,
                if (scope == null) selected.archive else full.archive,
                scope,
            );
            try c.equal("keep Plex", try c.debug(dest, "cat /svc/plex/sentinel", false));
            const output = try c.path(try c.a.print("restored-{d}", .{i}));
            _ = try c.debug(
                dest,
                try c.a.print("dump /svc/postgres/payload {s}", .{output}),
                false,
            );
            try c.equal(
                payload,
                try Dir.cwd().readFileAlloc(c.io, output, c.a, .limited(payload.len + 1)),
            );
        }
        if (c.invoke("occupied-import", destination, full.archive, null)) |_|
            return error.TransferTestConflict
        else |err| if (err != error.TransferInstall)
            return err;
        try c.equal("outside services\n", try c.debug(destination, "cat /extra", false));
        const corrupt = try c.path("corrupt.tar.zst");
        try Dir.cwd().copyFile(full.archive, Dir.cwd(), corrupt, c.io, .{});
        const damaged = try Dir.cwd().openFile(c.io, corrupt, .{ .mode = .read_write });
        try damaged.writePositionalAll(c.io, "\x00\x00\x00\x00", 0);
        damaged.close(c.io);
        const empty = try c.volume("empty", &.{}, &.{});
        if (c.invoke("corrupt-import", empty, corrupt, null)) |_|
            return error.TransferTestCorruption
        else |err| if (err != error.TransferInstall)
            return err;
        _ = try c.debug(source, "set_super_value state 0", true);
        const dirty_hash = try c.hash(source);
        if (c.invoke("dirty-export", source, null, null)) |_|
            return error.TransferTestDirty
        else |err| if (err != error.TransferFilesystem)
            return err;
        c.replay_copy = true;
        if (c.invoke("damaged-copy-refused", source, null, null)) |_|
            return error.TransferTestDirty
        else |err| if (err != error.TransferFilesystem)
            return err;
        c.replay_copy = false;
        try c.equal(dirty_hash, try c.hash(source));
        // An ext4 error flag is filesystem damage, distinct from an unclean
        // but otherwise valid journal. Both must be refused without writes.
        _ = try c.debug(source, "set_super_value state 2", true);
        const error_hash = try c.hash(source);
        if (c.invoke("error-export", source, null, null)) |_|
            return error.TransferTestDirty
        else |err| if (err != error.TransferFilesystem)
            return err;
        try c.equal(error_hash, try c.hash(source));
    }
};
