//! slot holds build's steps from the packages on: meta, the overlay, the
//! slot (the root sealed with dm-verity, the stage0s and their modules, the
//! kernel), a direct boot's initramfs and the disks made of the slot.
//! See build.zig.

const std = @import("std");
const forms = @import("form");
const compose = @import("compose");
const verity = @import("verity");
const image = @import("image");
const build = @import("build.zig");
const packages = @import("packages.zig");
const embedded = @import("files");
const disk = @import("disk.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const mem = std.mem;
const B = build.B;

const tiers_url = "https://raw.githubusercontent.com/werewolf-linux/cve-feed/main/";

/// meta writes OUT/meta, what the image needs to rebuild itself, and
/// OUT/ro, what compose lays over the packages: compose's records, then
/// the kernel, Alpine's repositories, the overlay's files, apk's world,
/// the tiers feed and its key, and werewolf's advisories where no package
/// brings them. Nothing says when or where it
/// was built, so a rebuild matches.
pub fn meta(b: *B, rootfs: []const u8) !void {
    const out = b.p.out;
    const stamp = try b.path("{s}/meta.stamp", .{out});
    const kernel_rootfs = try b.path("{s}/kernel/rootfs.tar", .{b.p.build});
    // howl itself holds the release keys, advisories and known posture
    // failures (files.zig), so b.self covers them.
    const fixed = [_][]const u8{ rootfs, kernel_rootfs, b.self };
    const inputs = try mem.concat(
        b.gpa,
        []const u8,
        &.{ &fixed, b.form_files, b.rootfs, b.bins, b.made, b.app },
    );
    const began = try b.begin(stamp, inputs) orelse return;
    // A step that fails part way leaves no stamp to call it made.
    Dir.cwd().deleteFile(b.io, stamp) catch {};
    const meta_dir = try b.path("{s}/meta", .{out});
    const ro_dir = try b.path("{s}/ro", .{out});
    for ([_][]const u8{ meta_dir, ro_dir }) |d| try Dir.cwd().deleteTree(b.io, d);

    // The accounts as the packages leave them, which compose adds to.
    var text: [3][]const u8 = undefined;
    for (&text, [_][]const u8{ "passwd", "group", "shadow" }) |*t, name|
        t.* = try b.capture(stamp, &.{ "bsdtar", "-xOf", rootfs, try b.path("etc/{s}", .{name}) });
    {
        var ro = try Dir.cwd().createDirPathOpen(b.io, ro_dir, .{});
        defer ro.close(b.io);
        var md = try Dir.cwd().createDirPathOpen(b.io, meta_dir, .{});
        defer md.close(b.io);
        const accounts: compose.Accounts = .{
            .passwd = text[0],
            .group = text[1],
            .shadow = text[2],
        };
        const kind: compose.Build = .{
            .arch = b.arch,
            .dev = b.spec.dev,
            .posture_known = embedded.posture_known,
        };
        var f: forms.Failure = .{};
        compose.compose(
            b.io,
            b.gpa,
            Dir.cwd(),
            b.chain,
            accounts,
            ro,
            md,
            kind,
            &f,
        ) catch |err| switch (err) {
            error.Form => return b.steps.fail(f.text),
            else => |e| return b.fail("compose: {t}", .{e}),
        };
    }

    const d = try b.path("{s}/usr/share/werewolf", .{meta_dir});
    const kernel_pkg = try packages.lockedKernel(
        b.gpa,
        try b.read("build/lock/kernel.lock.json", 64 << 20),
        @tagName(b.spec.arch),
    );
    try b.put(d, "kernel", try b.path("{s}\n", .{kernel_pkg}));
    try b.put(d, "alpine", try b.capture(stamp, &.{
        "bsdtar", "-xOf", kernel_rootfs, "etc/apk/repositories",
    }));
    try b.put(d, "overlay", try overlayList(b));
    // apk's world as the packages leave it, without the pins FREEZE adds.
    // Published, it names the format's package, so the updater takes only
    // programs that read the files compose writes (lib/compose.zig).
    try Dir.cwd().createDirPath(b.io, try b.path("{s}/etc/apk", .{meta_dir}));
    const world = try b.capture(stamp, &.{ "bsdtar", "-xOf", rootfs, "etc/apk/world" });
    const unpinned = try withoutPins(b.gpa, world);
    if (unpinned.len == 0) return b.fail(
        "{s}: every package in etc/apk/world is pinned",
        .{rootfs},
    );
    try b.put(meta_dir, "etc/apk/world", unpinned);
    try b.put(d, "release", try b.path("{s} {s} built-by-make\n", .{ b.name, kernel_pkg }));
    try b.put(d, "tiers.pub", embedded.tiers_pub);
    try b.put(d, "tiers", tiers_url ++ "\n");
    // The repository's minimal-form brings werewolf-advisories, and the
    // list updates with it; any other image carries howl's.
    const advised = for (b.from_repo) |n| {
        if (mem.eql(u8, n, b.chain[0].name)) break true;
    } else false;
    if (!advised) try b.put(d, "advisories", embedded.advisories);
    try Dir.cwd().writeFile(b.io, .{ .sub_path = stamp, .data = "" });
    try b.done(stamp, began);
}

/// withoutPins returns world's lines that hold no =, each ended by a
/// newline, as grep -v = prints them.
fn withoutPins(gpa: Allocator, world: []const u8) ![]const u8 {
    if (world.len == 0) return "";
    const body = if (mem.endsWith(u8, world, "\n")) world[0 .. world.len - 1] else world;
    var out: std.ArrayList(u8) = .empty;
    var lines = mem.splitScalar(u8, body, '\n');
    while (lines.next()) |l| {
        if (mem.findScalar(u8, l, '=') == null) try out.print(gpa, "{s}\n", .{l});
    }
    return out.items;
}

/// overlayList returns the files and links in the overlay's directories
/// but OUT/ro, sorted, each once: what the updater carries forward.
fn overlayList(b: *B) ![]const u8 {
    var seen: std.array_hash_map.String(void) = .empty;
    for (b.overlay[1..]) |dir| {
        var d = Dir.cwd().openDir(b.io, dir, .{ .iterate = true }) catch continue;
        defer d.close(b.io);
        var w = try d.walk(b.gpa);
        defer w.deinit();
        while (try w.next(b.io)) |e| {
            if (e.kind != .file and e.kind != .sym_link) continue;
            if (mem.eql(u8, e.basename, ".DS_Store")) continue;
            try seen.put(b.gpa, try b.gpa.dupe(u8, e.path), {});
        }
    }
    const all = seen.keys();
    mem.sortUnstable([]const u8, all, {}, build.lessThan);
    var out: std.ArrayList(u8) = .empty;
    for (all) |l| try out.print(b.gpa, "{s}\n", .{l});
    return out.items;
}

/// make makes the overlay, the slot, and what else goals ask, from
/// rootfs, the packages.
pub fn make(b: *B, rootfs: []const u8, goals: build.Goals) !void {
    const out = b.p.out;
    const overlay = try b.path("{s}/overlay.tar", .{out});
    const stamp = try b.path("{s}/meta.stamp", .{out});
    try layerStep(
        b,
        overlay,
        try mem.concat(b.gpa, []const u8, &.{ &.{stamp}, b.rootfs, b.bins, b.made, b.app }),
        try mem.concat(b.gpa, []const u8, &.{ b.overlay, &.{try b.path("{s}/meta", .{out})} }),
    );
    const root = try b.path("{s}/slot/root.erofs", .{out});
    try rootErofs(b, root, rootfs, overlay);
    try layerStep(
        b,
        try b.path("{s}/verity.tar", .{out}),
        &.{root},
        &.{try b.path("{s}/verity", .{out})},
    );
    try stage0Init(b, rootfs);
    try stage0(b, "stage0", "modules", b.modules.native);
    if (goals.slot) try stage0(b, "stage0-bitten", "modules-bitten", b.modules.all);
    if (goals.image) try initramfs(b, root);
    // The slot's kernel as Alpine ships it, not BUILD/vmlinuz: on aarch64
    // an EFI zboot image, 10 MB to the raw Image's 36, which a UEFI
    // machine's firmware reads on every boot.
    try copyStep(
        b,
        try b.path("{s}/slot/vmlinuz", .{out}),
        try b.path("{s}/vmlinuz", .{b.p.build}),
        try b.path("{s}/kernel/x/boot/vmlinuz-virt", .{b.p.build}),
    );
    // The kernel arguments the image asks for, beside it, for bite and
    // the disk to boot it with.
    try copyStep(
        b,
        try b.path("{s}/slot/cmdline", .{out}),
        stamp,
        try b.path("{s}/meta/usr/share/werewolf/cmdline", .{out}),
    );
    if (goals.disk) try diskStep(
        b,
        b.spec.disk_path orelse try b.path("{s}/disk.img", .{out}),
        false,
    );
    if (goals.qcow2) try diskStep(b, try b.path("{s}/disk.qcow2", .{out}), true);
}

fn layerStep(
    b: *B,
    target: []const u8,
    inputs: []const []const u8,
    dirs: []const []const u8,
) !void {
    const began = try b.begin(target, inputs) orelse return;
    try layer(b, target, dirs);
    try b.done(target, began);
}

/// layer writes target, a tar of dirs laid over one another in order, in
/// restricted pax: ustar's bytes, but for a pax header where a path or a
/// link is too long for ustar, which would otherwise drop it with a mere
/// warning (an image's node_modules has both). Its bytes depend only on
/// the files' contents and whether each is executable: sorted, owned by
/// root, modes 644 or 755, dated 1970 as apko dates its own files, and
/// carrying nothing of the builder's (owners, extended attributes,
/// .DS_Store). Images are made from tars alone, so no
/// inode number or time of the build host reaches one.
fn layer(b: *B, target: []const u8, dirs: []const []const u8) !void {
    const io = b.io;
    const stage = try b.path("{s}.d", .{target});
    try Dir.cwd().deleteTree(io, stage);
    var into = try Dir.cwd().createDirPathOpen(
        io,
        stage,
        .{ .open_options = .{ .iterate = true } },
    );
    defer into.close(io);
    for (dirs) |dir| try lay(b, dir, into);

    // Every name below stage, as find lists them, dated 1970 and sorted.
    var names: std.ArrayList([]const u8) = .empty;
    {
        var w = try into.walk(b.gpa);
        defer w.deinit();
        while (try w.next(io)) |e| try names.append(b.gpa, try b.gpa.dupe(u8, e.path));
    }
    for (names.items) |n| try into.setTimestamps(io, n, .{
        .follow_symlinks = false,
        .access_timestamp = .{ .new = .zero },
        .modify_timestamp = .{ .new = .zero },
    });
    mem.sortUnstable([]const u8, names.items, {}, build.lessThan);
    var list: std.ArrayList(u8) = .empty;
    for (names.items) |n| try list.print(b.gpa, "{s}\n", .{n});
    const list_path = try b.path("{s}.list", .{target});
    try Dir.cwd().writeFile(io, .{ .sub_path = list_path, .data = list.items });
    const t = try b.tmp(target);
    {
        const names_in = try Dir.cwd().openFile(io, list_path, .{});
        defer names_in.close(io);
        try b.run(&.{
            "bsdtar",      "-cf",             try b.absolute(t), "--format",
            "paxr",        "--uid",           "0",               "--gid",
            "0",           "--numeric-owner", "--no-xattrs",     "--no-acls",
            "--no-fflags", "-n",              "-T",              "-",
        }, .{ .cwd = stage, .stdin = names_in });
    }
    try b.rename(t, target);
    try Dir.cwd().deleteFile(io, list_path);
    try Dir.cwd().deleteTree(io, stage);
}

/// lay copies dir's tree into into as cp -R does, then normalises it as
/// chmod u=rwX,go=rX does: directories 755, files 755 if executable, else
/// 644. A file laid over another keeps the first's mode, as cp leaves it;
/// a link replaces a file or link. What cp would refuse, or do through a
/// link, fails.
fn lay(b: *B, dir: []const u8, into: Dir) !void {
    const io = b.io;
    var from = Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch |err|
        return b.fail("{s}: {t}", .{ dir, err });
    defer from.close(io);
    var w = try from.walk(b.gpa);
    defer w.deinit();
    var buf: [Dir.max_path_bytes]u8 = undefined;
    while (try w.next(io)) |e| {
        if (mem.eql(u8, e.basename, ".DS_Store")) continue;
        const there = into.statFile(io, e.path, .{ .follow_symlinks = false }) catch null;
        const was: ?Io.File.Kind = if (there) |st| st.kind else null;
        const misfit = switch (e.kind) {
            .directory => was != null and was != .directory,
            .file => was != null and was != .file,
            .sym_link => was == .directory,
            else => true,
        };
        if (misfit) return b.fail("{s}/{s}: cannot lay a {t} over {s}", .{
            dir, e.path, e.kind, if (was) |k| @tagName(k) else "nothing",
        });
        switch (e.kind) {
            .directory => {
                try into.createDirPath(io, e.path);
                try into.setFilePermissions(io, e.path, .fromMode(0o755), .{});
            },
            .file => {
                const st = try (if (was != null) into else from).statFile(io, e.path, .{});
                try from.copyFile(e.path, into, e.path, io, .{});
                const exec = st.permissions.toMode() & 0o111 != 0;
                try into.setFilePermissions(io, e.path, .fromMode(if (exec) 0o755 else 0o644), .{});
            },
            .sym_link => {
                const link = buf[0..try from.readLink(io, e.path, &buf)];
                if (was != null) try into.deleteFile(io, e.path);
                try into.symLink(io, link, e.path, .{});
            },
            else => unreachable,
        }
    }
}

/// rootErofs makes target, the slot's root, from the packages and the
/// overlay without what the form prunes, then appends its dm-verity hash
/// tree and writes the root hash and salt stage0 opens it with to
/// OUT/verity/verity (lib/verity.zig, the tree veritysetup makes).
fn rootErofs(b: *B, target: []const u8, rootfs: []const u8, overlay: []const u8) !void {
    const out = b.p.out;
    const inputs = try mem.concat(
        b.gpa,
        []const u8,
        &.{ &.{ rootfs, overlay, b.self }, b.form_files },
    );
    const began = try b.begin(target, inputs) orelse return;
    try Dir.cwd().createDirPath(b.io, try b.path("{s}/slot", .{out}));
    // The root directory itself, first: without an entry for it,
    // mkfs.erofs gives / the builder's uid and mode 0777, which sshd's
    // StrictModes rightly refuses keys under. Then, if the image takes the
    // sh shim, /bin/sh as a link to it, which a package's sh, busybox's,
    // or a form's replaces (cmd/sh-shim/README.md).
    const mtree = try b.path("{s}/root.mtree", .{out});
    const head = "#mtree\n./ type=dir uid=0 gid=0 uname=root gname=root mode=0755 time=0.0\n";
    const sh =
        \\./usr type=dir uid=0 gid=0 mode=0755 time=0.0
        \\./usr/bin type=dir uid=0 gid=0 mode=0755 time=0.0
        \\./usr/bin/sh type=link uid=0 gid=0 mode=0777 time=0.0 link=/usr/lib/werewolf/sh-shim
        \\
    ;
    try Dir.cwd().writeFile(b.io, .{
        .sub_path = mtree,
        .data = if (try takes(b, "sh-shim")) head ++ sh else head,
    });
    const root_tar = try b.path("{s}/root.tar", .{out});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(
        b.gpa,
        &.{ "bsdtar", "-cf", root_tar, "--uid", "0", "--gid", "0", "--numeric-owner" },
    );
    var f: forms.Failure = .{};
    const pruned = compose.prune(b.gpa, b.chain, &f) catch |err| switch (err) {
        error.Form => return b.steps.fail(f.text),
        else => |e| return e,
    };
    for (pruned) |p| try argv.appendSlice(b.gpa, &.{ "--exclude", p });
    try argv.appendSlice(b.gpa, &.{
        try b.path("@{s}", .{mtree}),
        try b.path("@{s}", .{rootfs}),
        try b.path("@{s}", .{overlay}),
    });
    try b.run(argv.items, .{});
    // An image service runs in its own tree, which lacks werewolf's
    // programs: a form's `before` helpers, and service-config for its
    // settings. Each tree gets the root's /usr/lib/werewolf, in the root's
    // order and bytes (erofs keeps one copy of the data); Landlock lets a
    // service run only what its service file names.
    var roots: std.ArrayList([]const u8) = .empty;
    for (b.chain) |c| {
        const svcs = c.spec.get("services") orelse continue;
        for (svcs.map) |svc|
            if (svc.value.get("image") != null) try roots.append(b.gpa, svc.key);
    }
    if (roots.items.len > 0) {
        const programs = try b.path("{s}/programs.tar", .{out});
        const from_root = try b.path("@{s}", .{root_tar});
        const ours = "usr/lib/werewolf/*";
        try b.run(&.{ "bsdtar", "-cf", programs, "--include", ours, from_root }, .{});
        const from_programs = try b.path("@{s}", .{programs});
        for (roots.items) |name| {
            const into = try b.path(",^usr/,oci/{s}/usr/,", .{name});
            try b.run(&.{ "bsdtar", "-rf", root_tar, "-s", into, from_programs }, .{});
        }
        try Dir.cwd().deleteFile(b.io, programs);
    }
    Dir.cwd().deleteFile(b.io, target) catch {};
    try checkErofs(b);
    // -T0 dates every file and the image 1970, and the UUID is fixed
    // (stage0 finds the image by path), so a rebuild matches.
    const t = try b.tmp(target);
    try b.run(try mem.concat(b.gpa, []const u8, &.{
        &.{"mkfs.erofs"},
        &image.erofs_options,
        &.{ "-T0", "-U", "00000000-0000-0000-0000-000000000000", "--tar=f", t, root_tar },
    }), .{});
    try Dir.cwd().deleteFile(b.io, root_tar);
    try Dir.cwd().deleteFile(b.io, mtree);

    const file = try Dir.cwd().openFile(b.io, t, .{ .mode = .read_write });
    defer file.close(b.io);
    const built = verity.build(b.gpa, b.io, file) catch |err|
        return b.fail("{s}: verity: {t}", .{ t, err });
    try file.writePositionalAll(b.io, built.tree, try file.length(b.io));
    var line: Io.Writer.Allocating = .init(b.gpa);
    try built.params.format(&line.writer);
    try Dir.cwd().createDirPath(b.io, try b.path("{s}/verity", .{out}));
    try b.write(try b.path("{s}/verity/verity", .{out}), line.written());
    try b.rename(t, target);
    try b.done(target, began);
}

/// takes reports whether a form of the chain takes program.
fn takes(b: *B, program: []const u8) !bool {
    for (b.chain) |c| for (try c.items(b.gpa, "programs")) |item| {
        var it = mem.tokenizeAny(u8, item, " \t");
        while (it.next()) |p| if (mem.eql(u8, p, program)) return true;
    };
    return false;
}

/// checkErofs refuses a mkfs.erofs that would write a bad root.
fn checkErofs(b: *B) !void {
    const version = try b.steps.exec(&.{.{ .argv = &.{ "mkfs.erofs", "--version" } }}, .{});
    const help = try b.steps.exec(&.{.{ .argv = &.{ "mkfs.erofs", "--help" } }}, .{});
    const both = try mem.concat(b.gpa, u8, &.{ version.output, help.output });
    var v: []const u8 = "";
    image.checkErofs(version.output, both, &v) catch |err| return switch (err) {
        error.ErofsTooOld => b.fail(
            "mkfs.erofs {s}: 1.9 or later is needed; older ones write an image of empty files",
            .{if (v.len > 0) v else "before 1.9"},
        ),
        error.ErofsNoZstd => b.fail(
            "mkfs.erofs has no zstd: make install-deps builds an erofs-utils with it",
            .{},
        ),
    };
}

/// stage0Init writes OUT/stage0/init.tar: stage0's /init and the module
/// loader, the image's own, as the updater takes them from the root it
/// builds. Published, they come from rootfs, werewolf's packages.
fn stage0Init(b: *B, rootfs: []const u8) !void {
    const target = try b.path("{s}/stage0/init.tar", .{b.p.out});
    const inputs: []const []const u8 = if (b.spec.published)
        &.{rootfs}
    else
        &.{ b.stage0_bin, b.loader_bin };
    const began = try b.begin(target, inputs) orelse return;
    const files = try b.path("{s}/stage0/files", .{b.p.out});
    try Dir.cwd().deleteTree(b.io, files);
    try Dir.cwd().createDirPath(b.io, try b.path("{s}/usr/lib/werewolf", .{files}));
    const init = try b.path("{s}/init", .{files});
    if (b.spec.published) {
        try b.run(&.{
            "bsdtar",                  "-xf",                      rootfs, "-C", files,
            "usr/lib/werewolf/stage0", "usr/lib/werewolf/modload",
        }, .{});
        try b.rename(try b.path("{s}/usr/lib/werewolf/stage0", .{files}), init);
    } else {
        try b.copy(b.stage0_bin, init);
        try b.copy(b.loader_bin, try b.path("{s}/usr/lib/werewolf/modload", .{files}));
    }
    try layer(b, target, &.{files});
    try b.done(target, began);
}

/// stage0 writes OUT/slot/NAME.zst, a stage0: /dev's nodes, /init and the
/// loader, the modules words name (OUT/MODULES.tar), and /verity. It has
/// no packages.
fn stage0(b: *B, name: []const u8, modules_name: []const u8, words: []const []const u8) !void {
    const out = b.p.out;
    const modules = try b.path("{s}/{s}.tar", .{ out, modules_name });
    try moduleTar(b, modules, words);
    const target = try b.path("{s}/slot/{s}.zst", .{ out, name });
    const init_tar = try b.path("{s}/stage0/init.tar", .{out});
    const verity_tar = try b.path("{s}/verity.tar", .{out});
    const mtree = try b.path("{s}/stage0.mtree", .{b.p.build});
    try packages.keep(b, mtree, embedded.stage0_mtree);
    const began = try b.begin(target, &.{ modules, mtree, init_tar, verity_tar }) orelse return;
    try Dir.cwd().createDirPath(b.io, try b.path("{s}/slot", .{out}));
    const cpio = try b.path("{s}/slot/{s}.cpio", .{ out, name });
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(b.gpa, &.{
        "bsdtar", "-cf", cpio, "--format", "newc", "--uid", "0", "--gid", "0", "--numeric-owner",
    });
    for ([_][]const u8{ mtree, init_tar, modules, verity_tar }) |from|
        try argv.append(b.gpa, try b.path("@{s}", .{from}));
    try b.run(argv.items, .{});
    const t = try b.tmp(target);
    try b.run(&.{ "zstd", "-19", "-T0", "-q", "-f", "-o", t, cpio }, .{});
    // zstd dates its output to the cpio's whole second, older than an input
    // written in that second: the next build would make it again.
    try Dir.cwd().setTimestampsNow(b.io, t, .{});
    try b.rename(t, target);
    try Dir.cwd().deleteFile(b.io, cpio);
    try b.done(target, began);
}

/// moduleTar writes target, the modules a stage0 loads and their order
/// (image.modules), decompressed: Alpine's kernel cannot (MODULE_DECOMPRESS
/// is off), and the loader hands the kernel each file as it is.
fn moduleTar(b: *B, target: []const u8, words: []const []const u8) !void {
    const vmlinuz = try b.path("{s}/vmlinuz", .{b.p.build});
    const inputs = try mem.concat(b.gpa, []const u8, &.{ &.{ vmlinuz, b.self }, b.form_files });
    const began = try b.begin(target, inputs) orelse return;
    const dir = target[0 .. target.len - ".tar".len];
    try Dir.cwd().deleteTree(b.io, dir);
    const mods = try b.path("{s}/kernel/x/lib/modules", .{b.p.build});
    var kvers = try Dir.cwd().openDir(b.io, mods, .{ .iterate = true });
    defer kvers.close(b.io);
    var it = kvers.iterate();
    const first = (try it.next(b.io)) orelse return b.fail("{s}: no kernel", .{mods});
    const kver = try b.gpa.dupe(u8, first.name);
    if (try it.next(b.io) != null) return b.fail("{s}: more than one kernel", .{mods});
    const src = try b.path("{s}/{s}", .{ mods, kver });
    var bad: []const u8 = "";
    const m = image.modules(
        b.gpa,
        try b.read(try b.path("{s}/modules.dep", .{src}), 16 << 20),
        words,
        b.modules.native,
        b.params,
        &bad,
    ) catch |err| return switch (err) {
        error.NoModules => b.fail(
            "{s}: no modules to load: the build lost its module list",
            .{target},
        ),
        error.NativeModuleMissing => b.fail(
            "{s}: native module {s} missing from its list",
            .{ target, bad },
        ),
        error.ModuleNotFound => b.fail("module {s} not in {s}/modules.dep", .{ bad, src }),
        error.ParamsForMissingModule => b.fail(
            "module parameters for {s}, which the form does not carry",
            .{bad},
        ),
        error.OutOfMemory => error.OutOfMemory,
    };
    const dst = try b.path("{s}/usr/lib/modules/{s}", .{ dir, kver });
    try Dir.cwd().createDirPath(b.io, dst);
    try b.put(dst, "werewolf.modules", m.list);
    for (m.files) |file| {
        const in = try b.path("{s}/{s}", .{ src, file });
        const raw = image.gunzip(b.gpa, try b.read(in, image.max_gunzip)) catch |err|
            return b.fail("{s}: {t}", .{ in, err });
        const to = try b.path("{s}/{s}", .{ dst, file[0 .. file.len - ".gz".len] });
        try Dir.cwd().createDirPath(b.io, std.fs.path.dirname(to).?);
        try Dir.cwd().writeFile(b.io, .{ .sub_path = to, .data = raw });
    }
    try layer(b, target, &.{dir});
    try b.done(target, began);
}

/// initramfs writes OUT/initramfs.zst, for a direct boot: the slot's
/// stage0, then a cpio holding root.erofs, which the kernel unpacks after
/// it and stage0 mounts. The cpio is made from a tar, so it carries no
/// inode or device number of this host.
fn initramfs(b: *B, root: []const u8) !void {
    const out = b.p.out;
    const target = try b.path("{s}/initramfs.zst", .{out});
    const stage0_zst = try b.path("{s}/slot/stage0.zst", .{out});
    const began = try b.begin(target, &.{ stage0_zst, root }) orelse return;
    if (!mem.eql(u8, b.chain[0].name, "minimal"))
        return b.fail("form {s} does not include minimal, which carries /init", .{b.name});
    const direct = try b.path("{s}/direct", .{out});
    try Dir.cwd().deleteTree(b.io, direct);
    try Dir.cwd().createDirPath(b.io, direct);
    try b.copy(root, try b.path("{s}/root.erofs", .{direct}));
    try Dir.cwd().setTimestamps(b.io, try b.path("{s}/root.erofs", .{direct}), .{
        .access_timestamp = .{ .new = .zero },
        .modify_timestamp = .{ .new = .zero },
    });
    const cpio = try b.path("{s}/direct.cpio.zst", .{out});
    {
        const f = try Dir.cwd().createFile(b.io, cpio, .{});
        defer f.close(b.io);
        // Through pipes, as the Makefile's: zstd then writes no content
        // size, which it does for a file.
        const ran = try b.steps.exec(&.{
            .{ .argv = &.{
                "bsdtar",      "-cf",             "-",           "--format",
                "ustar",       "--uid",           "0",           "--gid",
                "0",           "--numeric-owner", "--no-xattrs", "--no-acls",
                "--no-fflags", "root.erofs",
            }, .cwd = direct, .env = b.env },
            .{ .argv = &.{ "bsdtar", "-cf", "-", "--format", "newc", "@-" } },
            .{ .argv = &.{ "zstd", "-1", "-q", "-c" } },
        }, .{ .stdout = f });
        if (!ran.ok) return b.fail("packing {s} for a direct boot failed", .{root});
    }
    try cat(b, target, &.{ stage0_zst, cpio });
    try Dir.cwd().deleteTree(b.io, direct);
    try Dir.cwd().deleteFile(b.io, cpio);
    var chain: std.ArrayList(u8) = .empty;
    for (b.chain) |c| try chain.print(b.gpa, " {s}", .{c.name});
    try b.steps.note("form {s}:{s}", .{ b.name, chain.items });
    try b.done(target, began);
}

/// cat writes target, the files one after another.
fn cat(b: *B, target: []const u8, files: []const []const u8) !void {
    const t = try b.tmp(target);
    {
        const out = try Dir.cwd().createFile(b.io, t, .{});
        defer out.close(b.io);
        var buf: [64 << 10]u8 = undefined;
        var w = out.writer(b.io, &buf);
        for (files) |name| {
            const in = try Dir.cwd().openFile(b.io, name, .{});
            defer in.close(b.io);
            var r: Io.File.Reader = .init(in, b.io, &.{});
            _ = w.interface.sendFileAll(&r, .unlimited) catch |err| switch (err) {
                error.ReadFailed => return r.err.?,
                error.WriteFailed => return w.err.?,
            };
        }
        try w.interface.flush();
    }
    try b.rename(t, target);
}

/// copyStep copies from to target, with its mode, when target is older
/// than input.
fn copyStep(b: *B, target: []const u8, input: []const u8, from: []const u8) !void {
    const began = try b.begin(target, &.{input}) orelse return;
    try Dir.cwd().createDirPath(b.io, std.fs.path.dirname(target).?);
    const t = try b.tmp(target);
    try b.copy(from, t);
    try b.rename(t, target);
    try b.done(target, began);
}

/// diskStep writes target, werewolf's own boot disk of the slot
/// (disk.zig), of Spec.disk's size: raw, with Spec.disk's kernel
/// arguments, or as a release publishes it, qcow2 compressed with zlib and
/// without them. zlib is named, not left to qemu-img's default, which a
/// later qemu-img may change.
fn diskStep(b: *B, target: []const u8, qcow2: bool) !void {
    const out = b.p.out;
    // systemd-boot, from Wolfi, pinned by a lock as the kernel is.
    const yaml = try packages.bootConfig(b, "boot.yaml");
    const lock = "build/lock/boot.lock.json";
    const boot = try b.path("{s}/boot/rootfs.tar", .{b.p.build});
    try packages.relock(b, lock, yaml);
    try packages.apkoBuild(b, boot, yaml, lock, &.{lock});
    const slot = try b.path("{s}/slot", .{out});
    if (std.fs.path.dirname(target)) |parent| try Dir.cwd().createDirPath(b.io, parent);
    // The disk's size and kernel arguments, beside it and rewritten only when
    // they change, are an input: steps rebuild by file times, so new options
    // must make a newer file, or a disk built with the old ones would stay.
    const options = try b.path("{s}.options", .{target});
    var want: Io.Writer.Allocating = .init(b.gpa);
    try want.writer.print("size-mib {d}\n", .{b.spec.disk.size_mib});
    if (!qcow2) for (b.spec.disk.args) |arg| try want.writer.print("arg {s}\n", .{arg});
    const was = Dir.cwd().readFileAlloc(b.io, options, b.gpa, .limited(64 << 10)) catch "";
    if (!mem.eql(u8, was, want.written())) try b.write(options, want.written());
    const began = try b.begin(target, &.{
        try b.path("{s}/vmlinuz", .{slot}),    try b.path("{s}/stage0.zst", .{slot}),
        try b.path("{s}/root.erofs", .{slot}), try b.path("{s}/cmdline", .{slot}),
        boot,                                  b.self,
        options,
    }) orelse return;
    const t = try b.tmp(target);
    if (qcow2) {
        const raw = try b.path("{s}/disk.raw", .{out});
        try disk.write(b, raw, boot, slot, .{ .size_mib = b.spec.disk.size_mib });
        try b.run(&.{
            "qemu-img", "convert", "-f",
            "raw",      "-O",      "qcow2",
            "-c",       "-o",      "compression_type=zlib",
            raw,        t,
        }, .{});
        try Dir.cwd().deleteFile(b.io, raw);
    } else {
        try disk.write(b, t, boot, slot, b.spec.disk);
    }
    try b.rename(t, target);
    try b.done(target, began);
}

const testing = std.testing;

test withoutPins {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings(
        "busybox\nruntime\n",
        try withoutPins(a, "busybox\nlinux=1-r0\nruntime\n"),
    );
    try testing.expectEqualStrings("a\n\nb\n", try withoutPins(a, "a\n\nb"));
    try testing.expectEqualStrings("", try withoutPins(a, "x=1\n"));
}
