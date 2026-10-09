//! slot builds the other slot from packages and installs it, arming one try.
//! Update in slot-update.zig re-exports these as its methods. See README.md.

const std = @import("std");
const apk = @import("apk.zig");
const compose = @import("compose");
const form = @import("form");
const stage0Modules = @import("image").modules;
const ModuleParam = @import("image").Param;
const m = @import("slot-update.zig");
const Io = m.Io;
const Dir = m.Dir;
const Allocator = m.Allocator;
const linux = m.linux;
const sandbox = m.sandbox;
const policy = m.policy;
const releases = m.releases;
const verity = m.verity;

const apk_seconds = m.apk_seconds;
const attempt_path = m.attempt_path;
const cache_dir = m.cache_dir;
const max_apk_file = m.max_apk_file;
const max_read = m.max_read;
const meta_dir = m.meta_dir;
const update_id = m.update_id;
const work_dir = m.work_dir;

const argvZ = m.argvZ;
const nowSecs = m.nowSecs;
const Package = m.Package;
const parentDir = m.parentDir;
const parseInstalled = m.parseInstalled;
const testing = std.testing;
const Update = m.Update;

// --- build ------------------------------------------------------------------

/// buildSlot builds the other slot into work_dir/slot as `make slot` would:
/// root.erofs with its dm-verity tree, vmlinuz, and stage0.zst. It expects
/// packagesPlan to have installed work_dir/root and work_dir/kernel.
pub fn buildSlot(u: *Update, new_kernel: []const u8) !void {
    const io = u.io;
    const root = work_dir ++ "/root";
    try Dir.cwd().createDirPath(io, work_dir ++ "/slot");
    const r: Root = try .open(u, root);
    defer r.close(u);

    // Do what apko does and apk does not: busybox links, no setuid or setgid.
    u.step = "root";
    try busyboxLinks(u, r);
    // Compose first, while the account files are still the packages' own.
    u.step = "compose";
    try composeInto(u, r);
    u.step = "root";
    // Copy werewolf's programs and the operator's --app as built, the apk
    // setup, and the build records except those compose just wrote.
    for (try u.lines(try u.read(meta_dir ++ "/overlay"))) |p| try copyInto(u, r, "", p);
    for (&[_][]const u8{ "etc/apk/repositories", "etc/apk/arch" }) |p| try copyInto(u, r, "", p);
    for (try u.listDir("/etc/apk/keys")) |name| try copyInto(
        u,
        r,
        "",
        try u.gpa.print("etc/apk/keys/{s}", .{name}),
    );
    try copyTree(u, r, "", "usr/share/werewolf", &compose.records);
    // Remove what the form prunes (form.yaml's prune), as the build does. A
    // path the packages no longer bring is logged, not an error, so an
    // upstream change cannot stop updates.
    for (try u.lines(try u.read(meta_dir ++ "/prune"))) |p| {
        if (try r.remove(u, p)) continue;
        try u.record(.{ .event = "prune", .path = p, .why = "not in the packages now" });
    }
    const form_name = std.mem.trim(u8, try u.read(meta_dir ++ "/form"), "\n");
    try r.write(u, meta_dir ++ "/kernel", try u.gpa.print("{s}\n", .{new_kernel}));
    try r.write(
        u,
        meta_dir ++ "/release",
        try u.gpa.print(
            "{s} {s} {s} updated-on-{s}\n",
            .{ form_name, try u.nowText(), new_kernel, u.host },
        ),
    );
    try stripSetid(u, root);
    // The slot's / takes this directory's owner and mode. It must be root
    // and 0755, or sshd's StrictModes refuses every key.
    _ = try u.sys(
        linux.fchownat(linux.AT.FDCWD, root, 0, 0, linux.AT.SYMLINK_NOFOLLOW),
        "chown the new root",
    );
    _ = try u.sys(linux.fchmodat(linux.AT.FDCWD, root, 0o755), "chmod the new root");
    // Match the build (Makefile, EROFS_OPTS). zstd level 9 in 64 KiB
    // clusters boots faster than larger clusters or higher levels, and
    // builds in seconds.
    try u.run(&.{
        "/usr/bin/mkfs.erofs",
        "-b",
        "4096",
        "-zzstd,level=9",
        "-C65536",
        "-Eall-fragments,dedupe",
        // No xattrs, as in the build: a package's security.capability
        // would otherwise reach the image, inert only while / is nosuid.
        "-x-1",
        work_dir ++ "/slot/root.erofs",
        root,
    });
    // Append the dm-verity tree, as the build does (tools/verity.zig); its
    // parameters go into stage0's /verity below.
    u.step = "verity";
    const erofs = try Dir.cwd().openFile(
        io,
        work_dir ++ "/slot/root.erofs",
        .{ .mode = .read_write },
    );
    defer erofs.close(io);
    const tree = try verity.build(u.gpa, io, erofs);
    try erofs.writePositionalAll(io, tree.tree, try erofs.length(io));

    // Keep the kernel as Alpine ships it. On arm64 that is an EFI zboot
    // image, which systemd-boot runs as is and install unwraps for GRUB.
    u.step = "vmlinuz";
    const k: Root = try .open(u, work_dir ++ "/kernel");
    defer k.close(u);
    try u.write(work_dir ++ "/slot/vmlinuz", try k.read(u, "boot/vmlinuz-virt"));

    u.step = "stage0";
    // Like the build's stage0, this one has no packages
    // (cmd/stage0/stage0.mtree).
    const s = work_dir ++ "/stage0";
    Dir.cwd().deleteTree(u.io, s) catch {};
    try Dir.cwd().createDirPath(u.io, s);
    const s0: Root = try .open(u, s);
    defer s0.close(u);
    // writeCpio adds the device nodes here. init and the loader come from
    // the new root, as the build takes them from its image, so a fix to
    // either arrives with its package.
    (try s0.makeDir(u, "dev")).close(io);
    try s0.writeMode(u, "init", try r.read(u, "usr/lib/werewolf/stage0"), .fromMode(0o755));
    try s0.writeMode(
        u,
        "usr/lib/werewolf/modload",
        try r.read(u, "usr/lib/werewolf/modload"),
        .fromMode(0o755),
    );
    const kvers = try k.list(u, "lib/modules");
    if (kvers.len != 1) return error.NotOneKernel;
    const src = try u.gpa.print("lib/modules/{s}", .{kvers[0]});
    const dst = try u.gpa.print("usr/lib/modules/{s}", .{kvers[0]});
    const dep = try k.read(u, try u.gpa.print("{s}/modules.dep", .{src}));
    // The build's stage0s, from the same lists in the same order
    // (lib/image.zig): under a distro's GRUB (bite), modules-bitten, which
    // adds the distro filesystem's modules to werewolf's own.
    const native = try u.lines(try u.read(meta_dir ++ "/modules"));
    const words = if (u.cmd.grubenv != null)
        try u.lines(try u.read(meta_dir ++ "/modules-bitten"))
    else
        native;
    var params: std.ArrayList(ModuleParam) = .empty;
    for (try u.lines(try u.read(meta_dir ++ "/module-params"))) |line| {
        const space = std.mem.findScalar(u8, line, ' ') orelse return error.BadModuleParams;
        try params.append(u.gpa, .{ .module = line[0..space], .value = line[space + 1 ..] });
    }
    var bad: []const u8 = "";
    const mods = stage0Modules(u.gpa, dep, words, native, params.items, &bad) catch |err| {
        u.detail = bad;
        return err;
    };
    // Decompress, as the build does: Alpine's kernel cannot, and modload
    // passes each file as is.
    for (mods.files) |path| {
        const ko = try gunzip(u.gpa, try k.read(u, try u.gpa.print("{s}/{s}", .{ src, path })));
        try s0.write(u, try u.gpa.print("{s}/{s}", .{ dst, withoutGz(path) }), ko);
    }
    try s0.write(u, try u.gpa.print("{s}/werewolf.modules", .{dst}), mods.list);
    var line: Io.Writer.Allocating = .init(u.gpa);
    try tree.params.format(&line.writer);
    try s0.write(u, "verity", line.written());
    try writeCpio(u, s, work_dir ++ "/stage0.cpio");
    try u.run(&.{
        "/usr/bin/zstd",
        "-19",
        "-q",
        "-f",
        "-o",
        work_dir ++ "/slot/stage0.zst",
        work_dir ++ "/stage0.cpio",
    });
}

// --- install ----------------------------------------------------------------

/// install writes the built slot and arms one try of it, under GRUB (bite)
/// or, without werewolf.grubenv, systemd-boot (installEsp). root.erofs goes
/// beside this slot's on the victim's filesystem; the kernel and stage0 go
/// in werewolf/ beside GRUB's directory. /victim is read-only, so the mount
/// broker lends writable mounts.
pub fn install(u: *Update, build: []const u8) !void {
    if (u.cmd.grubenv == null) return installEsp(u, build);
    const io = u.io;
    u.step = "install";
    const victim = try u.held(.victim);
    defer victim.release();
    const grub = try u.held(.grub);
    defer grub.release();
    const v = victim.path();
    const g = grub.path();

    const gpath = u.cmd.grubenv.?.path;
    const kdir = try u.gpa.print(
        "{s}{s}/werewolf/{s}",
        .{ g, parentDir(parentDir(gpath)), u.other },
    );
    const rdir = try u.gpa.print(
        "{s}{s}/{s}",
        .{ v, u.cmd.victim.?.path, u.other },
    );
    try Dir.cwd().createDirPath(io, kdir);
    try Dir.cwd().createDirPath(io, rdir);
    // Disarm first, so nothing boots the slot or names it in attempt until
    // it is whole.
    const env = try u.gpa.print("{s}{s}", .{ g, gpath });
    Dir.cwd().deleteFile(io, attempt_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    try u.run(&.{ "/usr/lib/werewolf/grub-setenv", env, "next_entry", "" });
    // Each file goes through a temporary name, so it is whole or absent.
    // GRUB cannot run arm64's EFI zboot image, so unwrap the Image inside.
    try Dir.cwd().copyFile(
        work_dir ++ "/slot/root.erofs",
        Dir.cwd(),
        try u.gpa.print("{s}/root.erofs", .{rdir}),
        io,
        .{},
    );
    try u.writeReplacing(
        try u.gpa.print("{s}/vmlinuz", .{kdir}),
        try unwrapZboot(u.gpa, try u.read(work_dir ++ "/slot/vmlinuz")),
    );
    try Dir.cwd().copyFile(
        work_dir ++ "/slot/stage0.zst",
        Dir.cwd(),
        try u.gpa.print("{s}/stage0.zst", .{kdir}),
        io,
        .{},
    );
    linux.sync();
    // bite's GRUB entries read each slot's kernel arguments from the
    // environment, so an update's new arguments reach older machines.
    const args = try std.mem.join(u.gpa, " ", try u.words(try u.slotCmdline()));
    try u.run(&.{
        "/usr/lib/werewolf/grub-setenv",
        env,
        try u.gpa.print("werewolf_args_{s}", .{u.other}),
        args,
    });
    // Arm, then write attempt. In the other order, a power cut between
    // them would record a try that never happened as a rollback and mark
    // an unjudged build bad. In this order it costs at most one extra
    // boot. See README.md, Arming order.
    const entry = try u.gpa.print("werewolf-{s}", .{u.other});
    try u.run(&.{ "/usr/lib/werewolf/grub-setenv", env, "next_entry", entry });
    try writeAttempt(u, build);
}

fn writeAttempt(u: *Update, build: []const u8) !void {
    try u.writeReplacing(
        attempt_path,
        try u.gpa.print("{s} {s} {s}\n", .{ u.other, build, try u.bootId() }),
    );
}

/// installEsp installs the other slot on werewolf's own disk
/// (docs/design/native-boot.md): root.erofs to the ext4 partition, the
/// kernel and stage0 to the EFI partition, and a loader entry with one try,
/// which systemd-boot boots next because it is newest. slot-keep removes
/// the try count once the slot is healthy; otherwise the try is spent and
/// systemd-boot falls back.
fn installEsp(u: *Update, build: []const u8) !void {
    const io = u.io;
    u.step = "install";
    const victim = try u.held(.victim);
    defer victim.release();
    const esp = try u.held(.esp);
    defer esp.release();
    const v = victim.path();
    const e = esp.path();

    const rdir = try u.gpa.print(
        "{s}{s}/{s}",
        .{ v, u.cmd.victim.?.path, u.other },
    );
    const kdir = try u.gpa.print("{s}/werewolf/{s}", .{ e, u.other });
    const entries = try u.gpa.print("{s}/loader/entries", .{e});
    try Dir.cwd().createDirPath(io, rdir);
    try Dir.cwd().createDirPath(io, kdir);
    try Dir.cwd().createDirPath(io, entries);

    // Remove the other slot's entries and attempt first, so nothing boots
    // it while its files change. vfat has no journal, so sync the deletes
    // before changing any file.
    Dir.cwd().deleteFile(io, attempt_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    for (try u.listDir(entries)) |name| {
        if (!isEntryOf(name, u.other)) continue;
        try Dir.cwd().deleteFile(io, try u.gpa.print("{s}/{s}", .{ entries, name }));
    }
    linux.sync();
    // copyFile goes through a temporary name, so each file is whole or absent.
    try Dir.cwd().copyFile(
        work_dir ++ "/slot/root.erofs",
        Dir.cwd(),
        try u.gpa.print("{s}/root.erofs", .{rdir}),
        io,
        .{},
    );
    for (&[_][]const u8{ "vmlinuz", "stage0.zst" }) |f| {
        try Dir.cwd().copyFile(
            try u.gpa.print("{s}/slot/{s}", .{ work_dir, f }),
            Dir.cwd(),
            try u.gpa.print("{s}/{s}", .{ kdir, f }),
            io,
            .{},
        );
    }
    linux.sync();

    // systemd-boot boots the newest version, so the new entry must be newer
    // than the running slot's even if the clock is behind.
    var newest: i64 = 0;
    for (try u.listDir(entries)) |name| {
        if (!std.mem.startsWith(u8, name, "werewolf-") or
            !std.mem.endsWith(u8, name, ".conf")) continue;
        const text = try u.read(try u.gpa.print("{s}/{s}", .{ entries, name }));
        newest = @max(newest, entrySecs(text) orelse continue);
    }
    // A serial sorts by time in systemd-boot's version order.
    const version = try u.gpa.print(
        "{f}",
        .{policy.Serial{ .secs = @max(nowSecs(io), newest + 1) }},
    );
    const options = try withSlot(
        u.gpa,
        try u.read("/proc/cmdline"),
        try u.slotCmdline(),
        u.other,
    );
    const entry = try loaderEntry(u.gpa, u.other, version, options);
    const tmp = try u.gpa.print("{s}/werewolf-{s}.tmp", .{ entries, u.other });
    try u.write(tmp, entry);
    // Arm, then write attempt, as install does and for the same reason.
    try Dir.cwd().rename(
        tmp,
        Dir.cwd(),
        try u.gpa.print("{s}/werewolf-{s}+1.conf", .{ entries, u.other }),
        io,
    );
    linux.sync();
    try writeAttempt(u, build);
}

// --- helpers ----------------------------------------------------------------
/// apkAdd installs packages into a new root without root touching the
/// network. apkFetcher, as _update, fetches fresh indexes (apk would trust
/// a cached one for hours) and the packages into a per-root cache on
/// /data, so a check that finds nothing new downloads only indexes. Root
/// then checks the cache against the keys directory (checkCache), installs
/// with --no-network from repos, and prunes the cache to what was installed.
pub fn apkAdd(
    u: *Update,
    root: []const u8,
    arch: []const u8,
    keys: []const u8,
    repos: []const []const u8,
    packages: []const []const u8,
) !void {
    const source = try std.mem.concat(u.gpa, []const u8, &.{ &.{ "--keys-dir", keys }, repos });
    const name = std.fs.path.basename(root);
    const cache = try u.gpa.printSentinel("{s}/{s}", .{ cache_dir, name }, 0);
    const scratch = try u.gpa.printSentinel(
        "{s}/apk-{s}",
        .{ work_dir, name },
        0,
    );
    try Dir.cwd().createDirPath(u.io, cache);
    Dir.cwd().deleteTree(u.io, scratch) catch {};
    try Dir.cwd().createDirPath(u.io, scratch);
    _ = try u.sys(
        linux.fchownat(
            linux.AT.FDCWD,
            scratch,
            update_id,
            update_id,
            linux.AT.SYMLINK_NOFOLLOW,
        ),
        "chown scratch",
    );

    // Fetch indexes, then packages: `cache download` fetches no index.
    const world = try std.mem.join(u.gpa, "\n", packages);
    for ([_][]const []const u8{ &.{"update"}, &.{ "cache", "download" } }) |applet| {
        var b: Update.Backoff = .{};
        while (true) {
            if (apkFetch(u, applet, arch, source, world, cache, scratch)) break else |err| {
                // Retry an apk that failed; the cache keeps what arrived,
                // so a retry fetches only the rest. One killed at
                // apk_seconds is not retried.
                if (err != error.CommandFailed or !u.again(&b, "apk")) return err;
            }
        }
    }
    try Dir.cwd().deleteTree(u.io, scratch);
    const idx = try checkCache(u, cache, keys);
    if (heldFormat(packages, idx)) |h| try u.record(.{
        .event = "held",
        .format = h.pinned,
        .offered = h.offered,
        .why = "the repository has moved to a newer werewolf-format; reinstall to follow",
    });

    try u.run(try std.mem.concat(u.gpa, []const u8, &.{
        &.{ "/usr/bin/apk", "--root", root, "--arch", arch, "--cache-dir", cache, "--no-network" },
        source,
        &.{ "--no-scripts", "--quiet", "--no-progress", "add", "--initdb" },
        packages,
    }));
    try prune(u, cache, root);
}

/// apkFetch runs one apk applet in apkFetcher, as _update, then takes the
/// cache back for root (reclaim).
fn apkFetch(
    u: *Update,
    applet: []const []const u8,
    arch: []const u8,
    source: []const []const u8,
    world: []const u8,
    cache: [:0]const u8,
    scratch: [:0]const u8,
) !void {
    const argv_z = try argvZ(u.gpa, try std.mem.concat(u.gpa, []const u8, &.{
        &.{ "/usr/bin/apk", "--root", scratch, "--arch", arch, "--cache-dir", cache },
        source,
        &.{ "--quiet", "--no-progress" },
        applet,
    }));
    _ = try u.sys(
        linux.fchownat(
            linux.AT.FDCWD,
            cache,
            update_id,
            update_id,
            linux.AT.SYMLINK_NOFOLLOW,
        ),
        "chown cache",
    );
    const fetched = u.child(
        apkFetcher,
        .{ argv_z, world, cache, scratch },
        64 << 10,
        apk_seconds,
    );
    try reclaim(u, cache);
    const e = fetched catch |err| {
        u.detail = "apk, as _update";
        return err;
    };
    if (e.code != 0) {
        u.detail = try u.gpa.print(
            "apk, as _update: {s}",
            .{std.mem.trim(u8, e.out[0..@min(e.out.len, 400)], " \n")},
        );
        return error.CommandFailed;
    }
}

/// checkCache verifies the cache before root's apk reads it (apk.zig): each
/// index signed by a key in keys, each package as an index lists it. A
/// package no index lists is removed. A bad index or package is removed, so
/// the next pass fetches it again, and fails this pass. It returns the
/// packages the indexes list.
fn checkCache(u: *Update, cache: []const u8, keys: []const u8) !apk.Index {
    var trusted: std.ArrayList(apk.Key) = .empty;
    for (try u.listDir(keys)) |name| {
        const path = try u.gpa.print("{s}/{s}", .{ keys, name });
        try trusted.append(u.gpa, .{
            .name = name,
            .key = releases.parseKey(u.gpa, try u.read(path)) catch |err| {
                u.detail = path;
                return err;
            },
        });
    }
    var d = try Dir.cwd().openDir(u.io, cache, .{ .follow_symlinks = false });
    defer d.close(u.io);
    var idx: apk.Index = .empty;
    const names = try u.listDir(cache);
    for (names) |name| {
        if (!std.mem.startsWith(u8, name, "APKINDEX.")) continue;
        const kept = apk.readIndex(
            u.gpa,
            trusted.items,
            &idx,
            try d.readFileAlloc(u.io, name, u.gpa, .limited(max_read)),
        ) catch |err| {
            // Delete it, or a bad index left by the fetcher would fail every
            // later pass.
            d.deleteFile(u.io, name) catch {};
            u.detail = try u.gpa.print("{s}/{s}", .{ cache, name });
            return err;
        };
        try d.writeFile(u.io, .{ .sub_path = name, .data = kept });
    }
    for (names) |name| {
        if (std.mem.startsWith(u8, name, "APKINDEX.")) continue;
        apk.checkPackage(u.gpa, u.io, d, name, &idx) catch |err| {
            try d.deleteFile(u.io, name);
            if (err == error.NotInIndex) continue;
            u.detail = try u.gpa.print("{s}/{s}", .{ cache, name });
            return err;
        };
    }
    return idx;
}

/// Held is the werewolf-format a world pins and the newest an index offers.
const Held = struct { pinned: u32, offered: u32 };

/// heldFormat returns the pin and the newest werewolf-format idx lists, if
/// packages pin one and idx lists a newer: the machine then takes only what
/// its format allows (lib/compose.zig).
fn heldFormat(packages: []const []const u8, idx: apk.Index) ?Held {
    const pin = "werewolf-format=";
    const pinned = for (packages) |p| {
        if (std.mem.startsWith(u8, p, pin))
            break std.fmt.parseInt(u32, p[pin.len..], 10) catch return null;
    } else return null;
    var newest = pinned;
    var it = idx.keyIterator();
    while (it.next()) |name| {
        // NAME-VERSION.HASH, VERSION being N-rR.
        const rest = std.mem.cutPrefix(u8, name.*, "werewolf-format-") orelse continue;
        const n = rest[0 .. std.mem.findScalar(u8, rest, '-') orelse continue];
        newest = @max(newest, std.fmt.parseInt(u32, n, 10) catch continue);
    }
    return if (newest > pinned) .{ .pinned = pinned, .offered = newest } else null;
}

/// prune deletes cached packages that root did not install, keeping the
/// indexes. apk's `cache clean` keeps every version an index lists (all of
/// them, for Wolfi), and with --purge on a disk root deletes every package.
fn prune(u: *Update, cache: []const u8, root: []const u8) !void {
    const installed = try parseInstalled(u.gpa, try readIn(u, root, "lib/apk/db/installed"));
    var d = try Dir.cwd().openDir(u.io, cache, .{ .iterate = true, .follow_symlinks = false });
    defer d.close(u.io);
    var old: std.ArrayList([]const u8) = .empty;
    var it = d.iterate();
    while (try it.next(u.io)) |e| {
        if (std.mem.endsWith(u8, e.name, ".apk") and
            !isCachedOf(e.name, installed)) try old.append(u.gpa, try u.gpa.dupe(u8, e.name));
    }
    for (old.items) |name| try d.deleteFile(u.io, name);
}

/// reclaim gives the cache back to root after the fetcher exits: each
/// regular file with a name apk uses is chowned to root and set to 0644.
/// Anything else the fetcher left is removed unread.
fn reclaim(u: *Update, cache: [:0]const u8) !void {
    _ = try u.sys(
        linux.fchownat(linux.AT.FDCWD, cache, 0, 0, linux.AT.SYMLINK_NOFOLLOW),
        "chown cache",
    );
    var d = try Dir.cwd().openDir(u.io, cache, .{ .iterate = true, .follow_symlinks = false });
    defer d.close(u.io);
    var strays: std.ArrayList([]const u8) = .empty;
    var it = d.iterate();
    while (try it.next(u.io)) |e| {
        if (e.kind != .file or !cacheName(e.name)) {
            try strays.append(u.gpa, try u.gpa.dupe(u8, e.name));
            continue;
        }
        const file = try u.gpa.dupeSentinel(u8, e.name, 0);
        _ = try u.sys(
            linux.fchownat(d.handle, file, 0, 0, linux.AT.SYMLINK_NOFOLLOW),
            "chown cached file",
        );
        // The fetcher chose the old mode, so reset it.
        _ = try u.sys(linux.fchmodat(d.handle, file, 0o644), "chmod cached file");
    }
    for (strays.items) |stray| try d.deleteTree(u.io, stray);
}

fn busyboxLinks(u: *Update, r: Root) !void {
    const d = "etc/busybox-paths.d";
    for (r.list(u, d) catch return) |name| {
        for (try u.lines(try r.read(u, try u.gpa.print("{s}/{s}", .{ d, name })))) |p| {
            if (!try r.exists(u, p)) try r.symLink(u, "/usr/bin/busybox", p);
        }
    }
}

fn stripSetid(u: *Update, root: []const u8) !void {
    var d = try Dir.cwd().openDir(u.io, root, .{ .iterate = true });
    defer d.close(u.io);
    var w = try d.walk(u.gpa);
    while (try w.next(u.io)) |e| {
        if (e.kind != .file) continue;
        const st = try e.dir.statFile(u.io, e.basename, .{ .follow_symlinks = false });
        const mode = st.permissions.toMode();
        if (mode & 0o6000 != 0) {
            try e.dir.setFilePermissions(
                u.io,
                e.basename,
                .fromMode(mode & ~@as(std.posix.mode_t, 0o6000)),
                .{ .follow_symlinks = false },
            );
        }
    }
}

/// composeInto lays into r what the forms derive (lib/compose.zig), as the
/// build does. The form chain comes from this image's
/// /usr/share/werewolf/forms, under dm-verity; the accounts come from r.
/// compose writes only to a scratch directory, which is copied in through
/// Root, so no link a package laid can lead a write out of the new root.
fn composeInto(u: *Update, r: Root) !void {
    const io = u.io;
    const scratch = work_dir ++ "/compose";
    Dir.cwd().deleteTree(io, scratch) catch {};
    var staged = Dir.cwd().openDir(io, meta_dir, .{}) catch |err| {
        u.detail = meta_dir;
        return err;
    };
    defer staged.close(io);
    staged.access(io, "forms", .{}) catch {
        u.detail = "this image stages no forms (/usr/share/werewolf/forms): it predates " ++
            "compose; install a newer one";
        return error.NoStagedForms;
    };
    var f: form.Failure = .{};
    errdefer if (f.text.len > 0) {
        u.detail = f.text;
    };
    const leaf = std.mem.trim(u8, try u.read(meta_dir ++ "/form"), "\n");
    const forms = try form.chain(io, u.gpa, staged, leaf, &f);
    const b: compose.Build = .{
        .arch = switch (@import("builtin").cpu.arch) {
            .aarch64 => .aarch64,
            .x86_64 => .x86_64,
            else => @compileError("werewolf runs on aarch64 and x86_64"),
        },
        .dev = if (staged.access(io, "dev", .{})) true else |_| false,
        .posture_known = try u.read(meta_dir ++ "/posture-known"),
    };
    const accounts: compose.Accounts = .{
        .passwd = try r.read(u, "etc/passwd"),
        .group = try r.read(u, "etc/group"),
        .shadow = try r.read(u, "etc/shadow"),
    };
    var ro = try Dir.cwd().createDirPathOpen(io, scratch ++ "/ro", .{});
    defer ro.close(io);
    var meta = try Dir.cwd().createDirPathOpen(io, scratch ++ "/meta", .{});
    defer meta.close(io);
    try compose.compose(io, u.gpa, staged, forms, accounts, ro, meta, b, &f);
    try copyTree(u, r, scratch ++ "/ro", "", &.{});
    try copyTree(u, r, scratch ++ "/meta", "", &.{});
    try Dir.cwd().deleteTree(io, scratch);
}

/// copyTree copies directory path from the tree at from ("" for /) into r,
/// except top-level names in skip. It copies empty directories too.
fn copyTree(
    u: *Update,
    r: Root,
    from: []const u8,
    path: []const u8,
    skip: []const []const u8,
) !void {
    var d = Dir.cwd().openDir(
        u.io,
        try u.gpa.print("{s}/{s}", .{ from, path }),
        .{ .iterate = true },
    ) catch |err| {
        u.detail = path;
        return err;
    };
    defer d.close(u.io);
    var w = try d.walk(u.gpa);
    defer w.deinit();
    next: while (try w.next(u.io)) |e| {
        const top = e.path[0 .. std.mem.findScalar(u8, e.path, '/') orelse e.path.len];
        for (skip) |s| if (std.mem.eql(u8, s, top)) continue :next;
        const p = if (path.len == 0) e.path else try u.gpa.print("{s}/{s}", .{ path, e.path });
        if (e.kind == .directory) {
            (try r.makeDir(u, p)).close(u.io);
            continue;
        }
        try copyInto(u, r, from, p);
    }
}

/// copyInto copies path from the tree at from ("" for /) into r with its
/// permissions. A symlink stays a symlink, so a form's `run` link does not
/// become a copy of the old binary. A .mountpoint (the empty file that keeps
/// a mount point in the image) is hidden by the mount here, so it is created.
fn copyInto(u: *Update, r: Root, from: []const u8, path: []const u8) !void {
    errdefer u.detail = path;
    if (std.mem.eql(u8, std.fs.path.basename(path), ".mountpoint")) return r.write(u, path, "");
    const src = try u.gpa.print("{s}/{s}", .{ from, path });
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const n = Dir.cwd().readLink(u.io, src, &buf) catch |err| switch (err) {
        error.NotLink => return r.copy(u, src, path, null),
        else => return err,
    };
    try r.symLink(u, buf[0..n], path);
}

/// writeCpio writes a newc cpio of everything under root for use as an
/// initramfs: owned by root, children after their directory, then the
/// device nodes in devices.
fn writeCpio(u: *Update, root: []const u8, out_path: []const u8) !void {
    var out: Io.Writer.Allocating = .init(u.gpa);
    var d = try Dir.cwd().openDir(u.io, root, .{ .iterate = true });
    defer d.close(u.io);
    var w = try d.walk(u.gpa);
    var ino: u32 = 1;
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    while (try w.next(u.io)) |e| : (ino += 1) {
        const path = try u.gpa.printSentinel("{s}/{s}", .{ root, e.path }, 0);
        var st: linux.Statx = undefined;
        const rc = linux.statx(
            linux.AT.FDCWD,
            path,
            linux.AT.SYMLINK_NOFOLLOW,
            .{ .TYPE = true, .MODE = true },
            &st,
        );
        if (linux.errno(rc) != .SUCCESS) return error.StatFailed;
        const node: Node = .{
            .name = e.path,
            .mode = st.mode,
            .ino = ino,
            .rdev_major = st.rdev_major,
            .rdev_minor = st.rdev_minor,
        };
        const data: []const u8 = switch (st.mode & linux.S.IFMT) {
            linux.S.IFREG => try e.dir.readFileAlloc(
                u.io,
                e.basename,
                u.gpa,
                .limited(max_read),
            ),
            linux.S.IFLNK => link_buf[0..try e.dir.readLink(u.io, e.basename, &link_buf)],
            linux.S.IFDIR, linux.S.IFCHR, linux.S.IFBLK => "",
            else => return error.UnexpectedFileKind,
        };
        try cpioEntry(&out.writer, node, data);
    }
    for (devices) |dev| {
        var n = dev;
        n.ino = ino;
        ino += 1;
        try cpioEntry(&out.writer, n, "");
    }
    try cpioEntry(&out.writer, .{ .name = "TRAILER!!!", .mode = 0, .ino = 0 }, "");
    try u.write(out_path, out.written());
}

// --- the new roots ------------------------------------------------------------

/// Root is a root being built. Every path resolves as the slot will
/// resolve it (openat2 RESOLVE_IN_ROOT), so a symlink a package laid stays
/// within the root and never reaches the running system. Writes always
/// create a new file, never write through a link.
const Root = struct {
    dir: Dir,

    fn open(u: *Update, path: []const u8) !Root {
        return .{ .dir = try Dir.cwd().openDir(u.io, path, .{ .follow_symlinks = false }) };
    }

    fn close(r: Root, u: *Update) void {
        r.dir.close(u.io);
    }

    /// read returns the whole file at path.
    fn read(r: Root, u: *Update, path: []const u8) ![]const u8 {
        const f: Io.File = .{
            .handle = try r.openIn(u, path, .{ .ACCMODE = .RDONLY }),
            .flags = .{ .nonblocking = false },
        };
        defer f.close(u.io);
        var buf: [64 << 10]u8 = undefined;
        var reader = f.reader(u.io, &buf);
        return reader.interface.allocRemaining(u.gpa, .limited(max_read)) catch |err| switch (err) {
            error.ReadFailed => return reader.err orelse error.ReadFailed,
            else => return err,
        };
    }

    /// list returns the names in directory path.
    fn list(r: Root, u: *Update, path: []const u8) ![]const []const u8 {
        const d: Dir = .{ .handle = try r.openIn(u, path, dir_flags) };
        defer d.close(u.io);
        var names: std.ArrayList([]const u8) = .empty;
        var it = d.iterate();
        while (try it.next(u.io)) |e| try names.append(u.gpa, try u.gpa.dupe(u8, e.name));
        return names.items;
    }

    /// exists reports whether path exists, without following a final link.
    fn exists(r: Root, u: *Update, path: []const u8) !bool {
        const d: Dir = .{ .handle = r.openIn(
            u,
            parentDir(path),
            dir_flags,
        ) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        } };
        defer d.close(u.io);
        _ = d.statFile(
            u.io,
            std.fs.path.basename(path),
            .{ .follow_symlinks = false },
        ) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        return true;
    }

    /// remove deletes the file or link at path, and reports whether there
    /// was one.
    fn remove(r: Root, u: *Update, path: []const u8) !bool {
        errdefer u.detail = path;
        const d: Dir = .{ .handle = r.openIn(
            u,
            parentDir(path),
            dir_flags,
        ) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        } };
        defer d.close(u.io);
        d.deleteFile(u.io, std.fs.path.basename(path)) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        return true;
    }

    fn write(r: Root, u: *Update, path: []const u8, data: []const u8) !void {
        try r.writeMode(u, path, data, .default_file);
    }

    fn writeMode(
        r: Root,
        u: *Update,
        path: []const u8,
        data: []const u8,
        mode: Io.File.Permissions,
    ) !void {
        const d, const name = try r.fresh(u, path);
        defer d.close(u.io);
        try d.writeFile(u.io, .{
            .sub_path = name,
            .data = data,
            .flags = .{ .exclusive = true, .permissions = mode },
        });
    }

    /// copy copies src, from the running system, to path, with mode, or
    /// src's mode if null.
    fn copy(
        r: Root,
        u: *Update,
        src: []const u8,
        path: []const u8,
        mode: ?Io.File.Permissions,
    ) !void {
        const d, const name = try r.fresh(u, path);
        defer d.close(u.io);
        try Dir.cwd().copyFile(src, d, name, u.io, .{ .permissions = mode, .replace = false });
    }

    fn symLink(r: Root, u: *Update, target: []const u8, path: []const u8) !void {
        const d, const name = try r.fresh(u, path);
        defer d.close(u.io);
        try d.symLink(u.io, target, name, .{});
    }

    /// fresh returns path's directory, created if missing, and its base
    /// name, after removing any existing entry so writes create a new file.
    fn fresh(r: Root, u: *Update, path: []const u8) !struct { Dir, []const u8 } {
        const d = try r.makeDir(u, parentDir(path));
        errdefer d.close(u.io);
        const name = std.fs.path.basename(path);
        d.deleteFile(u.io, name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        return .{ d, name };
    }

    /// makeDir opens directory path, creating it and its parents if missing.
    fn makeDir(r: Root, u: *Update, path: []const u8) !Dir {
        if (r.openIn(u, path, dir_flags)) |fd| return .{ .handle = fd } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }
        if (path.len == 0) return error.FileNotFound;
        const parent = try r.makeDir(u, parentDir(path));
        defer parent.close(u.io);
        const name = try u.gpa.dupeSentinel(u8, std.fs.path.basename(path), 0);
        const rc = linux.mkdirat(parent.handle, name, 0o755);
        if (linux.errno(rc) != .EXIST) _ = try u.sys(rc, "mkdir in a new root");
        return .{ .handle = try r.openIn(u, path, dir_flags) };
    }

    /// openIn opens path with the root as /, refusing magic links such as
    /// /proc/self/fd/N.
    fn openIn(r: Root, u: *Update, path: []const u8, flags: linux.O) !i32 {
        const OpenHow = extern struct { flags: u64, mode: u64, resolve: u64 };
        const RESOLVE_NO_MAGICLINKS = 0x02;
        const RESOLVE_IN_ROOT = 0x10;
        var o = flags;
        o.CLOEXEC = true;
        var how: OpenHow = .{
            .flags = @as(u32, @bitCast(o)),
            .mode = 0,
            .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
        };
        const rc = linux.syscall4(
            .openat2,
            @bitCast(@as(isize, r.dir.handle)),
            @intFromPtr((try u.gpa.dupeSentinel(u8, if (path.len == 0) "." else path, 0)).ptr),
            @intFromPtr(&how),
            @sizeOf(OpenHow),
        );
        if (linux.errno(rc) == .NOENT) return error.FileNotFound;
        return @intCast(try u.sys(rc, "open in a new root"));
    }

    const dir_flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true };
};

/// readIn returns the whole file at path within root, resolved by Root.
pub fn readIn(u: *Update, root: []const u8, path: []const u8) ![]const u8 {
    const r: Root = try .open(u, root);
    defer r.close(u);
    return r.read(u, path);
}

// --- apk's network half, as _update -----------------------------------------

/// apkFetcher is apk's network half. It runs argv as _update, with no
/// environment, against scratch, a root holding only world and an empty
/// database. It may read /usr, /etc and the resolver's file, execute only
/// apk, write only beneath cache and scratch, and connect only to TCP ports
/// 443 and 53. Its output goes to out.
fn apkFetcher(
    argv: [:null]const ?[*:0]const u8,
    world: []const u8,
    cache: [:0]const u8,
    scratch: [:0]const u8,
    out: i32,
    parent: linux.pid_t,
) noreturn {
    sandbox.tieTo(parent);
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    apkExec(
        argv,
        world,
        cache,
        scratch,
        out,
    ) catch |err| sandbox.say(out, 1, sandbox.whyNot(arena.allocator(), err), "");
}

fn apkExec(
    argv: [:null]const ?[*:0]const u8,
    world: []const u8,
    cache: [:0]const u8,
    scratch: [:0]const u8,
    out: i32,
) !noreturn {
    try sandbox.closeAllBut(&.{out});
    for ([_]i32{ 1, 2 }) |fd| _ = try sandbox.sys(linux.dup3(out, fd, 0), "dup3");
    // Open what it may reach while still root. With DHCP, resolv.conf is a
    // link into /run, so it gets its own rule.
    const dir: linux.O = .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true };
    const file: linux.O = .{ .PATH = true, .CLOEXEC = true };
    var rules: [9]sandbox.Rule = undefined;
    var n: usize = 0;
    for ([_]struct { [:0]const u8, linux.O, u64 }{
        .{ "/usr", dir, sandbox.read_file | sandbox.read_dir },
        .{ "/etc", dir, sandbox.read_file | sandbox.read_dir },
        .{ "/usr/bin/apk", file, sandbox.execute },
        .{ interpreter, file, sandbox.execute },
        .{ "/dev/null", file, sandbox.read_file | sandbox.write_file },
        .{ cache, dir, sandbox.own_dir },
        .{ "/etc/resolv.conf", file, sandbox.read_file },
    }) |r| {
        const fd = linux.openat(linux.AT.FDCWD, r[0], r[1], 0);
        if (linux.errno(fd) == .NOENT and std.mem.eql(u8, r[0], "/etc/resolv.conf")) continue;
        rules[n] = .{
            .fd = @intCast(try sandbox.sys(fd, "open what apk may reach")),
            .access = r[2],
        };
        n += 1;
    }
    const root: i32 = @intCast(try sandbox.sys(
        linux.openat(linux.AT.FDCWD, scratch, dir, 0),
        "open scratch",
    ));
    rules[n] = .{ .fd = root, .access = sandbox.own_dir };
    n += 1;
    // Cap file size, so a compromised child cannot fill /data with one file.
    try sandbox.limit(.FSIZE, max_apk_file);
    try sandbox.dropTo(update_id, null);
    for ([_][:0]const u8{ "etc", "etc/apk", "lib", "lib/apk", "lib/apk/db" }) |d| {
        const rc = linux.mkdirat(root, d, 0o755);
        if (linux.errno(rc) != .EXIST) _ = try sandbox.sys(rc, "mkdir in scratch");
    }
    try writeAt(root, "etc/apk/world", world);
    try writeAt(root, "lib/apk/db/installed", "");
    try sandbox.landlock(rules[0..n], &.{ 443, 53 });

    // The calls apk 2.14 makes to fetch, as traced under glibc on both
    // architectures (x86_64's arch_prctl sets up TLS); names an
    // architecture lacks are skipped. apk tries to mount /proc in its root,
    // is refused, and carries on.
    var f: sandbox.Filter = .{};
    inline for (.{
        "read",            "readv",           "pread64",         "write",
        "writev",          "pwrite64",        "openat",          "open",
        "close",           "fstat",           "newfstatat",      "stat",
        "lstat",           "statx",           "fstatfs",         "statfs",
        "lseek",           "getdents64",      "faccessat",       "faccessat2",
        "access",          "readlinkat",      "readlink",        "mkdirat",
        "mkdir",           "renameat",        "renameat2",       "rename",
        "unlinkat",        "unlink",          "utimensat",       "ftruncate",
        "fsync",           "fdatasync",       "fcntl",           "flock",
        "dup",             "dup2",            "dup3",            "umask",
        "mmap",            "munmap",          "mprotect",        "mremap",
        "madvise",         "brk",             "futex",           "getpid",
        "gettid",          "getuid",          "geteuid",         "getgid",
        "getegid",         "connect",         "getsockopt",      "setsockopt",
        "getsockname",     "getpeername",     "sendto",          "recvfrom",
        "sendmsg",         "recvmsg",         "sendmmsg",        "recvmmsg",
        "shutdown",        "poll",            "ppoll",           "pselect6",
        "select",          "rt_sigaction",    "rt_sigprocmask",  "rt_sigreturn",
        "getrandom",       "clock_gettime",   "gettimeofday",    "nanosleep",
        "clock_nanosleep", "set_tid_address", "set_robust_list", "rseq",
        "prlimit64",       "uname",           "execve",          "exit_group",
        "exit",            "restart_syscall", "arch_prctl",
    }) |name| f.allow(name);
    // IP only. glibc also tries nscd's Unix socket and netlink, and copes
    // without them.
    f.allowArg("socket", 0, linux.AF.INET);
    f.allowArg("socket", 0, linux.AF.INET6);
    f.refuse("socket");
    // FIONREAD, and isatty's TCGETS and TCGETS2.
    for ([_]u32{ 0x541b, 0x5401, 0x802c542a }) |req| f.allowArg("ioctl", 1, req);
    f.refuse("mount");
    f.refuse("umount2");
    try f.install();

    const envp = [_:null]?[*:0]const u8{};
    _ = try sandbox.sys(linux.execve(argv[0].?, argv.ptr, &envp), "execve apk");
    unreachable;
}

/// interpreter is glibc's dynamic loader, which the kernel runs apk with.
/// Anything it runs is as confined as apk.
const interpreter = switch (@import("builtin").cpu.arch) {
    .x86_64 => "/lib64/ld-linux-x86-64.so.2",
    .aarch64 => "/lib/ld-linux-aarch64.so.1",
    else => @compileError("werewolf builds for x86_64 and aarch64"),
};

/// writeAt creates name beneath dir, without following links, and writes
/// data.
fn writeAt(dir: i32, name: [*:0]const u8, data: []const u8) !void {
    const fd: i32 = @intCast(try sandbox.sys(
        linux.openat(
            dir,
            name,
            .{
                .ACCMODE = .WRONLY,
                .CREAT = true,
                .TRUNC = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            },
            0o644,
        ),
        "create in scratch",
    ));
    defer _ = linux.close(fd);
    var off: usize = 0;
    while (off < data.len) off += try sandbox.sys(
        linux.write(fd, data[off..].ptr, data.len - off),
        "write in scratch",
    );
}

/// isCachedOf reports whether file, a cache name NAME-VERSION.HASH.apk, is
/// one of pkgs.
fn isCachedOf(file: []const u8, pkgs: []const Package) bool {
    const stem = file[0 .. std.mem.findScalarLast(
        u8,
        file[0 .. file.len - ".apk".len],
        '.',
    ) orelse return false];
    for (pkgs) |p| {
        if (stem.len == p.name.len + 1 + p.version.len and std.mem.startsWith(u8, stem, p.name) and
            stem[p.name.len] == '-' and std.mem.endsWith(u8, stem, p.version)) return true;
    }
    return false;
}

/// cacheName reports whether apk would give a cache file this name.
fn cacheName(name: []const u8) bool {
    return std.mem.eql(u8, name, "installed") or std.mem.endsWith(u8, name, ".apk") or
        (std.mem.startsWith(u8, name, "APKINDEX.") and std.mem.endsWith(u8, name, ".tar.gz"));
}

// --- pure functions, tested below -------------------------------------------

/// withSlot returns the other slot's command line. Machine arguments from
/// this boot (console, werewolf.mac) carry over, but the image's arguments
/// replace any of the same name, so a loosened entry does not outlive an
/// update and new arguments reach older machines. werewolf.slot is set to
/// slot; the loader's initrd= and BOOT_IMAGE= are dropped.
fn withSlot(
    gpa: Allocator,
    cmdline: []const u8,
    image: []const u8,
    slot: []const u8,
) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeAny(u8, cmdline, " \n");
    next: while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "werewolf.slot=") or
            std.mem.startsWith(u8, arg, "initrd=") or
            std.mem.startsWith(u8, arg, "BOOT_IMAGE=")) continue;
        var own = std.mem.tokenizeAny(u8, image, " \n");
        while (own.next()) |o| if (std.mem.eql(u8, argName(arg), argName(o))) continue :next;
        try out.print(gpa, "{s} ", .{arg});
    }
    var own = std.mem.tokenizeAny(u8, image, " \n");
    while (own.next()) |o| try out.print(gpa, "{s} ", .{o});
    try out.print(gpa, "werewolf.slot={s}", .{slot});
    return out.items;
}

/// argName returns a kernel argument's name: the part before =, or all of it.
fn argName(arg: []const u8) []const u8 {
    return arg[0 .. std.mem.findScalar(u8, arg, '=') orelse arg.len];
}

/// loaderEntry returns a Boot Loader Specification type 1 entry for slot.
/// version orders the slots, newest first; sort-key groups them.
fn loaderEntry(
    gpa: Allocator,
    slot: []const u8,
    version: []const u8,
    options: []const u8,
) ![]const u8 {
    return gpa.print(
        \\title werewolf {s}
        \\sort-key werewolf
        \\version {s}
        \\linux /werewolf/{s}/vmlinuz
        \\initrd /werewolf/{s}/stage0.zst
        \\options {s}
        \\
    , .{ slot, version, slot, slot, options });
}

/// isEntryOf reports whether name is an entry of slot: werewolf-b.conf,
/// werewolf-b+1.conf with tries left, or werewolf-b+0-1.conf with none.
fn isEntryOf(name: []const u8, slot: []const u8) bool {
    const prefix = "werewolf-";
    if (!std.mem.startsWith(u8, name, prefix) or !std.mem.endsWith(u8, name, ".conf")) return false;
    const rest = name[prefix.len .. name.len - ".conf".len];
    if (!std.mem.startsWith(u8, rest, slot)) return false;
    return rest.len == slot.len or rest[slot.len] == '+';
}

/// entrySecs returns an entry's version, a policy.Serial, in Unix seconds,
/// or null if it has none or another format.
fn entrySecs(entry: []const u8) ?i64 {
    var it = std.mem.tokenizeScalar(u8, entry, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "version "))
            return policy.parseSerial(line["version ".len..]) catch null;
    }
    return null;
}

/// gunzip inflates a gzip stream of up to max_read bytes.
fn gunzip(gpa: Allocator, data: []const u8) ![]const u8 {
    var in: Io.Reader = .fixed(data);
    var gz: std.compress.flate.Decompress = .init(&in, .gzip, &.{});
    return gz.reader.allocRemaining(gpa, .limited(max_read)) catch |err| switch (err) {
        error.ReadFailed => return gz.err orelse error.ReadFailed,
        else => return err,
    };
}

/// withoutGz strips .gz: kernel/fs/ext4/ext4.ko.gz -> kernel/fs/ext4/ext4.ko.
fn withoutGz(path: []const u8) []const u8 {
    return if (std.mem.endsWith(u8, path, ".gz")) path[0 .. path.len - 3] else path;
}

/// unwrapZboot returns the Image inside an arm64 EFI zboot image ("MZ",
/// "zimg", then the gzipped Image's offset and size as little-endian u32).
/// Any other image is returned unchanged.
fn unwrapZboot(gpa: Allocator, image: []const u8) ![]const u8 {
    if (image.len < 16 or !std.mem.eql(u8, image[4..8], "zimg")) return image;
    const off = std.mem.readInt(u32, image[8..12], .little);
    const size = std.mem.readInt(u32, image[12..16], .little);
    if (@as(u64, off) + size > image.len) return error.BadZboot;
    return gunzip(gpa, image[off .. off + size]);
}

const Node = struct {
    name: []const u8,
    mode: u32,
    ino: u32,
    rdev_major: u32 = 0,
    rdev_minor: u32 = 0,
};

/// devices are the build stage0's device nodes (cmd/stage0/stage0.mtree).
/// The kernel opens /dev/console as PID 1's stdio before /dev is mounted;
/// without it, stage0's output is lost or lands in the first file opened.
/// fence forbids mknod, so the nodes go straight into the cpio.
const devices = [_]Node{
    .{
        .name = "dev/console",
        .mode = linux.S.IFCHR | 0o620,
        .ino = 0,
        .rdev_major = 5,
        .rdev_minor = 1,
    },
    .{
        .name = "dev/null",
        .mode = linux.S.IFCHR | 0o666,
        .ino = 0,
        .rdev_major = 1,
        .rdev_minor = 3,
    },
    .{
        .name = "dev/random",
        .mode = linux.S.IFCHR | 0o666,
        .ino = 0,
        .rdev_major = 1,
        .rdev_minor = 8,
    },
    .{
        .name = "dev/urandom",
        .mode = linux.S.IFCHR | 0o666,
        .ino = 0,
        .rdev_major = 1,
        .rdev_minor = 9,
    },
    .{
        .name = "dev/zero",
        .mode = linux.S.IFCHR | 0o666,
        .ino = 0,
        .rdev_major = 1,
        .rdev_minor = 5,
    },
};

/// cpioEntry writes one newc cpio entry: header, name and data, each padded
/// to 4 bytes.
fn cpioEntry(w: *Io.Writer, n: Node, data: []const u8) !void {
    const fields = [_]u32{
        n.ino,
        n.mode,
        0,
        0,
        1,
        0,
        @intCast(data.len),
        0,
        0,
        n.rdev_major,
        n.rdev_minor,
        @intCast(n.name.len + 1),
        0,
    };
    try w.writeAll("070701");
    for (fields) |f| try w.print("{x:0>8}", .{f});
    try w.writeAll(n.name);
    try w.writeByte(0);
    try w.splatByteAll(0, pad4(110 + n.name.len + 1));
    try w.writeAll(data);
    try w.splatByteAll(0, pad4(data.len));
}

fn pad4(n: usize) usize {
    return (4 - n % 4) % 4;
}

// --- tests ------------------------------------------------------------------

test "a new root's links lead within it" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var u: Update = .{ .io = io, .gpa = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // No link in root/ may reach outside/: not by an absolute path, by
    // climbing out, or by writing through a link. As with /.. on the slot,
    // climbing out stays at the root, so etc/up is root/outside/.
    try tmp.dir.createDirPath(io, "root/etc");
    try tmp.dir.createDirPath(io, "root/outside");
    try tmp.dir.createDirPath(io, "outside");
    try tmp.dir.writeFile(io, .{ .sub_path = "outside/file", .data = "kept" });
    const outside = try tmp.dir.realPathFileAlloc(io, "outside", a);
    try tmp.dir.symLink(io, outside, "root/usr", .{});
    try tmp.dir.symLink(io, "../../outside", "root/etc/up", .{});
    try tmp.dir.symLink(io, try a.print("{s}/file", .{outside}), "root/etc/passwd", .{});

    const r: Root = try .open(&u, try tmp.dir.realPathFileAlloc(io, "root", a));
    defer r.close(&u);
    try testing.expectError(error.FileNotFound, r.write(&u, "usr/share/x", "out"));
    try testing.expectError(error.FileNotFound, r.read(&u, "usr/file"));
    try r.write(&u, "etc/up/y", "in");
    try r.write(&u, "etc/passwd", "new");
    try r.symLink(&u, "/usr/bin/busybox", "etc/up/sh");
    try testing.expectEqualStrings(
        "in",
        try tmp.dir.readFileAlloc(io, "root/outside/y", a, .unlimited),
    );
    try testing.expectEqualStrings("new", try r.read(&u, "etc/passwd"));
    try testing.expect(try r.exists(&u, "etc/up/sh"));
    try testing.expect(!try r.exists(&u, "etc/up/missing"));

    var d = try tmp.dir.openDir(io, "outside", .{ .iterate = true });
    defer d.close(io);
    var it = d.iterate();
    try testing.expectEqualStrings("file", (try it.next(io)).?.name);
    try testing.expectEqual(null, try it.next(io));
    try testing.expectEqualStrings("kept", try d.readFileAlloc(io, "file", a, .unlimited));
}

test "systemd-boot entries" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings(
        "console=hvc0 werewolf.victim=ab:/werewolf werewolf.esp=57E1-F000 werewolf.mac=52:55 " ++
            "werewolf.slot=b",
        try withSlot(
            a,
            "initrd=\\werewolf\\a\\stage0.zst console=hvc0 werewolf.slot=a " ++
                "werewolf.victim=ab:/werewolf werewolf.esp=57E1-F000  werewolf.mac=52:55\n",
            "",
            "b",
        ),
    );
    // The image's arguments replace any of the same name, or are added.
    try testing.expectEqualStrings(
        "console=hvc0 werewolf.victim=ab:/werewolf debugfs=off proc_mem.force_override=never " ++
            "werewolf.slot=b",
        try withSlot(
            a,
            "console=hvc0 proc_mem.force_override=always werewolf.slot=a " ++
                "werewolf.victim=ab:/werewolf\n",
            "debugfs=off proc_mem.force_override=never\n",
            "b",
        ),
    );
    try testing.expectEqualStrings(
        \\title werewolf b
        \\sort-key werewolf
        \\version 20261006T120000Z
        \\linux /werewolf/b/vmlinuz
        \\initrd /werewolf/b/stage0.zst
        \\options x werewolf.slot=b
        \\
    , try loaderEntry(a, "b", "20261006T120000Z", "x werewolf.slot=b"));
    // entrySecs reads back versions a new entry must beat (howl's first
    // disk's, a leap day); versions in other formats count as none.
    for ([_]i64{ 0, 315532800, 1835481599, 1835481600, 1791288000 }) |secs| {
        const entry = try a.print(
            "title werewolf a\nversion {f}\n",
            .{policy.Serial{ .secs = secs }},
        );
        try testing.expectEqual(secs, entrySecs(entry).?);
    }
    for ([_][]const u8{
        "title werewolf a\n",
        "version 0-werewolf-a\n",
        "version 20261306T120000Z\n",
        "version 2026100GT120000Z\n",
        "version +0261006T120000Z\n",
        "version 19691231T235959Z\n",
        "version 20260231T120000Z\n",
    }) |entry| try testing.expectEqual(null, entrySecs(entry));
    for ([_][]const u8{
        "werewolf-b.conf",
        "werewolf-b+1.conf",
        "werewolf-b+0-1.conf",
    }) |n| try testing.expect(isEntryOf(n, "b"));
    for ([_][]const u8{
        "werewolf-a.conf",
        "werewolf-b.tmp",
        "werewolf-bb.conf",
        "other-b.conf",
    }) |n| try testing.expect(!isEntryOf(n, "b"));
}

test cacheName {
    for ([_][]const u8{
        "installed",
        "APKINDEX.f8759e6a.tar.gz",
        "zstd-1.5.7-r10.cc2743ad.apk",
    }) |n| try testing.expect(cacheName(n));
    for ([_][]const u8{
        "APKINDEX.f8759e6a.tar",
        ".apk.27182ee91faf",
        "installed.new",
        "lib",
        "zstd-1.5.7-r10.apk.tmp",
    }) |n| try testing.expect(!cacheName(n));
}

test isCachedOf {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const pkgs = try parseInstalled(
        arena.allocator(),
        "P:zstd\nV:1.5.7-r10\n\nP:glibc-2.44\nV:2.44-r8\n",
    );
    try testing.expect(isCachedOf("zstd-1.5.7-r10.cc2743ad.apk", pkgs));
    try testing.expect(isCachedOf("glibc-2.44-2.44-r8.b91ee306.apk", pkgs));
    try testing.expect(!isCachedOf("glibc-2.44-2.44-r7.53c9e93b.apk", pkgs));
    try testing.expect(!isCachedOf("zstd-1.5.7-r1.cc2743ad.apk", pkgs));
    try testing.expect(!isCachedOf("libzstd1-1.5.7-r10.933e1e74.apk", pkgs));
    try testing.expect(!isCachedOf("zstd-1.5.7-r10.apk", pkgs));
    try testing.expect(!isCachedOf(".apk", pkgs));
}

test heldFormat {
    const gpa = testing.allocator;
    var idx: apk.Index = .empty;
    defer idx.deinit(gpa);
    const sha1: [20]u8 = @splat(0);
    try idx.put(gpa, "werewolf-format-1-r0.00000000", sha1);
    try idx.put(gpa, "werewolf-fence-20261009.161730-r0.00000000", sha1);
    const world = [_][]const u8{ "werewolf-fence", "werewolf-format=1" };
    try testing.expectEqual(null, heldFormat(&world, idx));
    try testing.expectEqual(null, heldFormat(&.{"werewolf-fence"}, idx));
    try idx.put(gpa, "werewolf-format-2-r0.00000000", sha1);
    try idx.put(gpa, "werewolf-format-x-r0.00000000", sha1);
    try testing.expectEqual(Held{ .pinned = 1, .offered = 2 }, heldFormat(&world, idx).?);
    try testing.expectEqual(null, heldFormat(&.{"werewolf-format=2"}, idx));
}

test withoutGz {
    try testing.expectEqualStrings(
        "kernel/fs/ext4/ext4.ko",
        withoutGz("kernel/fs/ext4/ext4.ko.gz"),
    );
    try testing.expectEqualStrings("kernel/fs/ext4/ext4.ko", withoutGz("kernel/fs/ext4/ext4.ko"));
}

test cpioEntry {
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try cpioEntry(&out.writer, .{ .name = "init", .mode = 0o100755, .ino = 1 }, "ab");
    const b = out.written();
    try testing.expectEqualStrings("070701", b[0..6]);
    try testing.expectEqualStrings("000081ed", b[14..22]);
    try testing.expectEqualStrings("init\x00", b[110..115]);
    try testing.expectEqual(0, (110 + 5 + pad4(115)) % 4);
    try testing.expectEqual(b.len, 110 + 5 + pad4(115) + 2 + pad4(2));

    out.clearRetainingCapacity();
    try cpioEntry(
        &out.writer,
        .{ .name = "dev/console", .mode = 0o020620, .ino = 2, .rdev_major = 5, .rdev_minor = 1 },
        "",
    );
    const c = out.written();
    try testing.expectEqualStrings("00002190", c[14..22]);
    try testing.expectEqualStrings("00000005", c[78..86]);
    try testing.expectEqualStrings("00000001", c[86..94]);
}

test unwrapZboot {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const plain = "not a zboot image, at all";
    try testing.expectEqualStrings(plain, try unwrapZboot(arena.allocator(), plain));
    var bad: [16]u8 = @splat(0);
    @memcpy(bad[4..8], "zimg");
    std.mem.writeInt(u32, bad[8..12], 8, .little);
    std.mem.writeInt(u32, bad[12..16], 100, .little);
    try testing.expectError(error.BadZboot, unwrapZboot(arena.allocator(), &bad));
}
