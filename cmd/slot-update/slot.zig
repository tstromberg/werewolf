//! slot: building and installing the other slot. From packages: apk's
//! fetcher as _update, then root's offline install into a new root, the
//! root image, its dm-verity tree, and stage0. Then install: the slot
//! written whole, `attempt` kept, and its one try armed, last. Each takes
//! the Update of slot-update.zig, whose methods call these as their own.

const std = @import("std");
const apk = @import("apk.zig");
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
pub fn buildSlot(u: *Update, new_kernel: []const u8) !void {
    const io = u.io;
    const root = work_dir ++ "/root";
    try Dir.cwd().createDirPath(io, work_dir ++ "/slot");
    const r: Root = try .open(u, root);
    defer r.close(u);

    // What apko does that apk does not: busybox's links, no setuid or setgid.
    u.step = "root";
    try busyboxLinks(u, r);
    // werewolf's own files as the build laid them, and the apk setup and
    // build record the next update will need.
    for (try u.lines(try u.read(meta_dir ++ "/overlay"))) |p| try copyInto(u, r, p);
    for (&[_][]const u8{ "etc/apk/repositories", "etc/apk/arch" }) |p| try copyInto(u, r, p);
    for (try u.listDir("/etc/apk/keys")) |name| try copyInto(
        u,
        r,
        try u.gpa.print("etc/apk/keys/{s}", .{name}),
    );
    try copyTree(u, r, "usr/share/werewolf");
    // What the form leaves out of its packages (Makefile, form.yaml's prune):
    // removed here as the build left them out, so this slot holds what the
    // build's did. One the packages no longer bring is noted, not an error:
    // an upstream fix must not stop the machine updating.
    for (try u.lines(try u.read(meta_dir ++ "/prune"))) |p| {
        if (try r.remove(u, p)) continue;
        try u.record(.{ .event = "prune", .path = p, .why = "not in the packages now" });
    }
    const form = std.mem.trim(u8, try u.read(meta_dir ++ "/form"), "\n");
    try r.write(u, meta_dir ++ "/kernel", try u.gpa.print("{s}\n", .{new_kernel}));
    try r.write(
        u,
        meta_dir ++ "/release",
        try u.gpa.print(
            "{s} {s} {s} updated-on-{s}\n",
            .{ form, try u.nowText(), new_kernel, u.host },
        ),
    );
    try stripSetid(u, root);
    // The slot's / is this directory's owner and mode: root's, 0755,
    // whoever made it, or sshd's StrictModes refuses every key.
    _ = try u.sys(
        linux.fchownat(linux.AT.FDCWD, root, 0, 0, linux.AT.SYMLINK_NOFOLLOW),
        "chown the new root",
    );
    _ = try u.sys(linux.fchmodat(linux.AT.FDCWD, root, 0o755), "chmod the new root");
    // As the build makes it (Makefile, EROFS_OPTS), so a slot built here
    // boots as a published one does: zstd at level 9 in 64 KiB clusters
    // boots faster than larger clusters or higher levels, and builds in
    // seconds, not minutes.
    try u.run(&.{
        "/usr/bin/mkfs.erofs",
        "-b",
        "4096",
        "-zzstd,level=9",
        "-C65536",
        "-Eall-fragments,dedupe",
        // No extended attributes, as the build's tar strips them: a
        // package's file capabilities (security.capability) would
        // otherwise ride into the image, inert only while the root stays
        // nosuid.
        "-x-1",
        work_dir ++ "/slot/root.erofs",
        root,
    });
    // Its dm-verity hash tree after it, and the line stage0 opens it with,
    // for stage0's /verity below: as the build makes them (tools/verity.zig).
    u.step = "verity";
    const image = try Dir.cwd().openFile(
        io,
        work_dir ++ "/slot/root.erofs",
        .{ .mode = .read_write },
    );
    defer image.close(io);
    const tree = try verity.build(u.gpa, io, image);
    try image.writePositionalAll(io, tree.tree, try image.length(io));

    // The kernel as Alpine ships it, as the build lays it in a slot
    // (Makefile): on arm64 an EFI zboot image, which systemd-boot runs as
    // it is, and install unwraps for GRUB, which cannot.
    u.step = "vmlinuz";
    const k: Root = try .open(u, work_dir ++ "/kernel");
    defer k.close(u);
    try u.write(work_dir ++ "/slot/vmlinuz", try k.read(u, "boot/vmlinuz-virt"));

    u.step = "stage0";
    // No packages, as the build's has none (cmd/stage0/stage0.mtree).
    const s = work_dir ++ "/stage0";
    Dir.cwd().deleteTree(u.io, s) catch {};
    try Dir.cwd().createDirPath(u.io, s);
    const s0: Root = try .open(u, s);
    defer s0.close(u);
    // Where writeCpio puts the device nodes.
    (try s0.makeDir(u, "dev")).close(io);
    try s0.copy(u, meta_dir ++ "/stage0.init", "init", .fromMode(0o755));
    // werewolf's module loader, as the build lays it in stage0.
    try s0.copy(u, "/usr/lib/werewolf/modload", "usr/lib/werewolf/modload", .fromMode(0o755));
    const kvers = try k.list(u, "lib/modules");
    if (kvers.len != 1) return error.NotOneKernel;
    const src = try u.gpa.print("lib/modules/{s}", .{kvers[0]});
    const dst = try u.gpa.print("usr/lib/modules/{s}", .{kvers[0]});
    const dep = try k.read(u, try u.gpa.print("{s}/modules.dep", .{src}));
    // The form's modules, and on a distro's disk (bite's, under GRUB) its
    // filesystem's too, which werewolf's own disk leaves out, as the
    // build's two stage0s do (Makefile, BITTEN_TAGS).
    var leaves: std.ArrayList([]const u8) = .empty;
    try leaves.appendSlice(u.gpa, try u.lines(try u.read(meta_dir ++ "/modules")));
    if (u.cmd.grubenv != null)
        try leaves.appendSlice(u.gpa, try u.lines(try u.read(meta_dir ++ "/modules-bitten")));
    const order = try moduleOrder(u.gpa, dep, leaves.items);
    // Decompressed, as the build does: Alpine's kernel cannot, and the
    // loader hands it each file as it is.
    for (order) |mod| {
        const ko = try gunzip(u.gpa, try k.read(u, try u.gpa.print("{s}/{s}", .{ src, mod.path })));
        try s0.write(u, try u.gpa.print("{s}/{s}", .{ dst, withoutGz(mod.path) }), ko);
    }
    const list = try moduleList(u.gpa, order, try u.read(meta_dir ++ "/module-params"));
    try s0.write(u, try u.gpa.print("{s}/werewolf.modules", .{dst}), list);
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
// root.erofs beside this slot's on the victim's filesystem; the kernel and
// stage0 in /boot/werewolf, beside GRUB's directory. Both mounted apart
// and writable, since /victim is read-only.
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
    // Disarm first: a staged slot's try is set, and until the new slot
    // is whole, nothing boots it; nor does `attempt` name it.
    const env = try u.gpa.print("{s}{s}", .{ g, gpath });
    Dir.cwd().deleteFile(io, attempt_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    try u.run(&.{ "/usr/lib/werewolf/grub-setenv", env, "next_entry", "" });
    // Each through a temporary name, so whole or absent. The kernel
    // unwrapped: GRUB cannot run arm64's EFI zboot image, only the Image
    // inside it.
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
    // The image's kernel arguments, which bite's entries read from
    // GRUB's environment for each slot, so an update's new arguments
    // reach a machine bitten before them.
    const args = try std.mem.join(u.gpa, " ", try u.words(try u.slotCmdline()));
    try u.run(&.{
        "/usr/lib/werewolf/grub-setenv",
        env,
        try u.gpa.print("werewolf_args_{s}", .{u.other}),
        args,
    });
    // Then the one try, and last `attempt`, kept: an attempt is on
    // record only for a slot that is armed. The other order would, after
    // a power cut between the two, record a try that never happened as a
    // rollback, and so blacklist a build no boot has judged. This way a
    // cut between them leaves a slot armed with no record: it boots once,
    // slot-keep commits it if it is healthy, and if it is not, nothing
    // marks the build bad and the next pass tries it again, one boot's
    // cost and no loss.
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

/// The other slot onto werewolf's own disk (docs/design/native-boot.md): its
/// root.erofs to the ext4 partition, as install does; its kernel and
/// stage0 to the EFI partition; and a loader entry with one try, which
/// systemd-boot boots next because it is the newest. slot-keep removes the
/// count once the slot is healthy; if it is not, systemd-boot has spent
/// the try and boots the slot this one replaced.
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

    // The other slot's entry goes first, and `attempt` with it: from
    // here until the new one is written, nothing boots the other slot
    // while its files change. vfat keeps no journal, so the deletes are
    // made to stick before any file changes.
    Dir.cwd().deleteFile(io, attempt_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    for (try u.listDir(entries)) |name| {
        if (!isEntryOf(name, u.other)) continue;
        try Dir.cwd().deleteFile(io, try u.gpa.print("{s}/{s}", .{ entries, name }));
    }
    linux.sync();
    // Each through a temporary name (copyFile), so whole or absent.
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

    // Now, or a second past the newest werewolf entry left, the running
    // slot's, if the clock is behind the one that wrote it: systemd-boot
    // boots the newest version, so an older one would never be tried.
    var newest: i64 = 0;
    for (try u.listDir(entries)) |name| {
        if (!std.mem.startsWith(u8, name, "werewolf-") or
            !std.mem.endsWith(u8, name, ".conf")) continue;
        const text = try u.read(try u.gpa.print("{s}/{s}", .{ entries, name }));
        newest = @max(newest, entrySecs(text) orelse continue);
    }
    // A serial, which systemd-boot orders by time.
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
    // The one try first, then `attempt`, as install does and for the
    // same reason.
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
/// Install packages into a new root, through a cache on /data named for
/// the root (root, kernel, stage0), so a check that finds nothing new
/// downloads indexes and nothing else. Each root has a cache of its own,
/// so cleaning one keeps nothing another needs.
///
/// Root does not touch the network. apk's network half runs first, as
/// _update (apkFetcher): the indexes, fresh every time, since apk would
/// otherwise trust a cached one for hours, and every package the new
/// root takes, into the cache. Root takes the cache back, checks it
/// against keys, the directory of keys its indexes must be signed with
/// (checkCache), and installs from it with --no-network from repos, the
/// repositories apk is told of. Then it prunes the cache to the packages
/// the new root took, so it holds one copy of the image, no more.
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

    // The indexes, then the packages: `cache download` fetches no index.
    const world = try std.mem.join(u.gpa, "\n", packages);
    for ([_][]const []const u8{ &.{"update"}, &.{ "cache", "download" } }) |applet| {
        var b: Update.Backoff = .{};
        while (true) {
            if (apkFetch(u, applet, arch, source, world, cache, scratch)) break else |err| {
                // An apk that exited failing is tried again, from where it
                // stopped: the cache keeps what came, so a retry fetches
                // only what did not. One killed at apk_seconds is not.
                if (err != error.CommandFailed or !u.again(&b, "apk")) return err;
            }
        }
    }
    try Dir.cwd().deleteTree(u.io, scratch);
    try checkCache(u, cache, keys);

    try u.run(try std.mem.concat(u.gpa, []const u8, &.{
        &.{ "/usr/bin/apk", "--root", root, "--arch", arch, "--cache-dir", cache, "--no-network" },
        source,
        &.{ "--no-scripts", "--quiet", "--no-progress", "add", "--initdb" },
        packages,
    }));
    try prune(u, cache, root);
}

/// One apk applet, in a child as _update (apkFetcher): the network half
/// of apkAdd.
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

/// The cache as root's apk may read it (apk.zig): each index signed by a
/// key in keys, each package as an index lists it, and nothing else. A
/// package no index lists any more is removed. One that is not as its
/// index has it is removed too, for the next pass to fetch again, and
/// fails this one.
fn checkCache(u: *Update, cache: []const u8, keys: []const u8) !void {
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
            // Gone before the pass ends, as a bad package is: the fetcher
            // could otherwise leave one and end every pass after, for good.
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
}

/// The cache, down to the packages root has installed, and the indexes.
/// Not apk's `cache clean`: without --purge it keeps any version an
/// index still lists, which for Wolfi is all of them, and with it,
/// where the root is on a disk, it deletes every package.
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

/// The cache, root's again once the fetcher is gone: each entry a regular
/// file of a name apk gives one, owned by root, mode 0644. Anything else
/// it left is removed unread.
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
        // And root's mode: the fetcher, dead by now, chose the last.
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

/// path, a directory, and everything under it, from this root into r:
/// the build record, whose etc/ holds the image's accounts.
fn copyTree(u: *Update, r: Root, path: []const u8) !void {
    var d = Dir.cwd().openDir(
        u.io,
        try u.gpa.print("/{s}", .{path}),
        .{ .iterate = true },
    ) catch |err| {
        u.detail = path;
        return err;
    };
    defer d.close(u.io);
    var w = try d.walk(u.gpa);
    defer w.deinit();
    while (try w.next(u.io)) |e| {
        if (e.kind == .directory) continue;
        try copyInto(u, r, try u.gpa.print("{s}/{s}", .{ path, e.path }));
    }
}

/// path, from this root into r, with its permissions. A symlink stays a
/// symlink: a form's `run` that links to a binary must not become a copy
/// of the old one. A .mountpoint is the empty file that keeps a mount
/// point's directory in the image; here what is mounted there hides it,
/// so it is made.
fn copyInto(u: *Update, r: Root, path: []const u8) !void {
    errdefer u.detail = path;
    if (std.mem.eql(u8, std.fs.path.basename(path), ".mountpoint")) return r.write(u, path, "");
    const src = try u.gpa.print("/{s}", .{path});
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const n = Dir.cwd().readLink(u.io, src, &buf) catch |err| switch (err) {
        error.NotLink => return r.copy(u, src, path, null),
        else => return err,
    };
    try r.symLink(u, buf[0..n], path);
}

/// A newc cpio of everything under root, as the kernel unpacks an
/// initramfs: owned by root, children after their directory, and last the
/// device nodes the build's stage0 has (devices). The type and device
/// numbers come from statx.
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

/// A root being built, every path in it resolved as the slot will resolve
/// it (openat2, RESOLVE_IN_ROOT): a symlink a package laid leads within
/// the root, whatever it names, and never out into the running system.
/// Each file written is made anew, never written through a link.
const Root = struct {
    dir: Dir,

    fn open(u: *Update, path: []const u8) !Root {
        return .{ .dir = try Dir.cwd().openDir(u.io, path, .{ .follow_symlinks = false }) };
    }

    fn close(r: Root, u: *Update) void {
        r.dir.close(u.io);
    }

    /// path, a file in the root, whole.
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

    /// The names in path, a directory in the root.
    fn list(r: Root, u: *Update, path: []const u8) ![]const []const u8 {
        const d: Dir = .{ .handle = try r.openIn(u, path, dir_flags) };
        defer d.close(u.io);
        var names: std.ArrayList([]const u8) = .empty;
        var it = d.iterate();
        while (try it.next(u.io)) |e| try names.append(u.gpa, try u.gpa.dupe(u8, e.name));
        return names.items;
    }

    /// Whether path is in the root, as a link or anything else.
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

    /// path, a file or link in the root, removed: true, or false if there
    /// was none to remove.
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
        const d, const name = try r.fresh(u, path);
        defer d.close(u.io);
        try d.writeFile(u.io, .{ .sub_path = name, .data = data, .flags = .{ .exclusive = true } });
    }

    /// src, from the running system, to path in the root, with mode, or
    /// src's if null.
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

    /// path's directory, made if missing, and its name there, removed if
    /// it was there: what is written there is made anew.
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

    /// path, a directory in the root, made if missing, each directory
    /// above it too.
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

    /// path, opened beneath the root as if the root were /, through no
    /// magic link (/proc/self/fd/N and the like).
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

/// path in the root at root, whole (Root.read).
pub fn readIn(u: *Update, root: []const u8, path: []const u8) ![]const u8 {
    const r: Root = try .open(u, root);
    defer r.close(u);
    return r.read(u, path);
}

// --- apk's network half, as _update -----------------------------------------

/// As _update, apk's network half: argv, run with no environment, in
/// scratch, a root of its own holding only world and an empty database. It
/// reads the image (/usr, /etc and the resolver's file), runs nothing but
/// apk, writes only beneath cache and scratch, connects over TCP only to
/// ports 443 and 53, and starts no process. What it says goes to out.
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
    // What it may reach, opened while root can. resolv.conf leads, on a
    // machine with DHCP, to the client's in /run.
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
    // No file bigger than any package or index, so a child that turns on
    // root cannot fill /data with one.
    try sandbox.limit(.FSIZE, max_apk_file);
    try sandbox.dropTo(update_id, null);
    for ([_][:0]const u8{ "etc", "etc/apk", "lib", "lib/apk", "lib/apk/db" }) |d| {
        const rc = linux.mkdirat(root, d, 0o755);
        if (linux.errno(rc) != .EXIST) _ = try sandbox.sys(rc, "mkdir in scratch");
    }
    try writeAt(root, "etc/apk/world", world);
    try writeAt(root, "lib/apk/db/installed", "");
    try sandbox.landlock(rules[0..n], &.{ 443, 53 });

    // What apk 2.14 calls to fetch, as traced, under glibc on either
    // architecture (x86_64's arch_prctl sets up thread-local storage); the
    // names one lacks are skipped. It tries to mount /proc
    // in its root, which is refused as for any unprivileged process, and
    // carries on.
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
    // IP, and nothing else: glibc's lookups also try nscd's Unix socket,
    // and netlink for the addresses configured, and do without.
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

/// glibc's dynamic loader, which the kernel runs apk with; what it runs in
/// turn would be as confined as apk is.
const interpreter = switch (@import("builtin").cpu.arch) {
    .x86_64 => "/lib64/ld-linux-x86-64.so.2",
    .aarch64 => "/lib/ld-linux-aarch64.so.1",
    else => @compileError("werewolf builds for x86_64 and aarch64"),
};

/// A file beneath dir, written whole.
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

/// Whether file, a package in apk's cache (NAME-VERSION.HASH.apk), is one
/// of pkgs.
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

/// A name apk gives a file in its cache.
fn cacheName(name: []const u8) bool {
    return std.mem.eql(u8, name, "installed") or std.mem.endsWith(u8, name, ".apk") or
        (std.mem.startsWith(u8, name, "APKINDEX.") and std.mem.endsWith(u8, name, ".tar.gz"));
}

// --- pure functions, tested below -------------------------------------------

/// This boot's command line, for the other slot: what the machine was
/// booted with (its console, werewolf.mac) carries over, but the image's
/// own arguments (/usr/share/werewolf/cmdline, which the build writes from
/// the form's allowances) replace any of the same name, so an entry edited
/// to loosen one does not outlive the next update, and one an update adds
/// reaches machines installed before it. werewolf.slot is the other slot's;
/// initrd= and BOOT_IMAGE= belong to the loader that wrote them, and are
/// dropped.
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

/// A kernel argument's name: what comes before its =, or all of it.
fn argName(arg: []const u8) []const u8 {
    return arg[0 .. std.mem.findScalar(u8, arg, '=') orelse arg.len];
}

/// A systemd-boot entry (the Boot Loader Specification's type 1) for slot.
/// version orders the slots, newest first; sort-key keeps them together.
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

/// Whether name is one of slot's entries: werewolf-b.conf, werewolf-b+1.conf
/// with tries left, werewolf-b+0-1.conf with none.
fn isEntryOf(name: []const u8, slot: []const u8) bool {
    const prefix = "werewolf-";
    if (!std.mem.startsWith(u8, name, prefix) or !std.mem.endsWith(u8, name, ".conf")) return false;
    const rest = name[prefix.len .. name.len - ".conf".len];
    if (!std.mem.startsWith(u8, rest, slot)) return false;
    return rest.len == slot.len or rest[slot.len] == '+';
}

/// An entry's version, a serial as a new one is written (policy.Serial),
/// in seconds since the epoch; null if it has none, or one of another form.
fn entrySecs(entry: []const u8) ?i64 {
    var it = std.mem.tokenizeScalar(u8, entry, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "version "))
            return policy.parseSerial(line["version ".len..]) catch null;
    }
    return null;
}

/// A module in load order: its path in modules.dep, and the tag a machine
/// must name for it to load (modload), or "" for every machine.
const Mod = struct { path: []const u8, tag: []const u8 = "" };

/// The order to load modules in: each leaf's dependencies from modules.dep,
/// read back to front, then the leaf. A leaf `@TAG:NAME`, a tagged line of
/// the form's list, is for the machines stage0 names TAG on, and its
/// modules carry the tag: those for every machine come first, and one an
/// untagged leaf needs loads for every machine, as the build lists them
/// (Makefile, modules.tar). One two tags need is listed under each.
fn moduleOrder(gpa: Allocator, dep: []const u8, leaves: []const []const u8) ![]const Mod {
    var out: std.ArrayList(Mod) = .empty;
    for (0..2) |pass| for (leaves) |word| {
        var tag: []const u8 = "";
        var leaf = word;
        if (std.mem.startsWith(u8, word, "@")) {
            const colon = std.mem.findScalar(u8, word, ':') orelse return error.BadModuleTag;
            tag = word[1..colon];
            leaf = word[colon + 1 ..];
            if (tag.len == 0 or leaf.len == 0) return error.BadModuleTag;
        }
        if ((tag.len > 0) != (pass == 1)) continue;
        const suffix = try gpa.print("/{s}.ko.gz", .{leaf});
        var lines_it = std.mem.splitScalar(u8, dep, '\n');
        const line = while (lines_it.next()) |l| {
            const colon = std.mem.findScalar(u8, l, ':') orelse continue;
            if (std.mem.endsWith(u8, l[0..colon], suffix)) break l;
        } else return error.ModuleNotFound;
        var fields: std.ArrayList([]const u8) = .empty;
        var f = std.mem.tokenizeAny(u8, line, ": ");
        while (f.next()) |x| try fields.append(gpa, x);
        var i = fields.items.len;
        while (i > 0) {
            i -= 1;
            const path = fields.items[i];
            const listed = for (out.items) |x| {
                if (std.mem.eql(u8, x.path, path) and
                    (x.tag.len == 0 or std.mem.eql(u8, x.tag, tag))) break true;
            } else false;
            if (!listed) try out.append(gpa, .{ .path = path, .tag = tag });
        }
    };
    return out.items;
}

/// werewolf.modules for a load order: each path without .gz, after `@` and
/// its tag and a space where it has one, and after it the parameters
/// /usr/share/werewolf/module-params gives its module, a line `MODULE
/// KEY=VALUE`, as the build writes them (Makefile, MODULE_PARAMS).
/// Parameters for a module not in the order are an error, not a module
/// loaded without them.
fn moduleList(gpa: Allocator, order: []const Mod, params: []const u8) ![]const u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    for (order) |mod| {
        const path = withoutGz(mod.path);
        if (mod.tag.len > 0) try out.writer.print("@{s} ", .{mod.tag});
        try out.writer.writeAll(path);
        const stem = std.fs.path.basename(path);
        var lines_it = std.mem.tokenizeScalar(u8, params, '\n');
        while (lines_it.next()) |line| {
            const space = std.mem.findScalar(u8, line, ' ') orelse return error.BadModuleParams;
            if (std.mem.eql(
                u8,
                line[0..space],
                stem[0 .. stem.len - ".ko".len],
            )) try out.writer.print(" {s}", .{line[space + 1 ..]});
        }
        try out.writer.writeByte('\n');
    }
    var lines_it = std.mem.tokenizeScalar(u8, params, '\n');
    next: while (lines_it.next()) |line| {
        const name = line[0 .. std.mem.findScalar(u8, line, ' ') orelse line.len];
        for (order) |mod| {
            const stem = std.fs.path.basename(withoutGz(mod.path));
            if (std.mem.eql(u8, name, stem[0 .. stem.len - ".ko".len])) continue :next;
        }
        return error.ParamsForMissingModule;
    }
    return out.written();
}

/// A gzip stream, inflated: at most max_read bytes of it.
fn gunzip(gpa: Allocator, data: []const u8) ![]const u8 {
    var in: Io.Reader = .fixed(data);
    var gz: std.compress.flate.Decompress = .init(&in, .gzip, &.{});
    return gz.reader.allocRemaining(gpa, .limited(max_read)) catch |err| switch (err) {
        error.ReadFailed => return gz.err orelse error.ReadFailed,
        else => return err,
    };
}

/// kernel/fs/ext4/ext4.ko.gz -> kernel/fs/ext4/ext4.ko
fn withoutGz(path: []const u8) []const u8 {
    return if (std.mem.endsWith(u8, path, ".gz")) path[0 .. path.len - 3] else path;
}

/// The Image inside arm64's EFI zboot image: "MZ", "zimg", then the
/// gzipped Image's offset and size as little-endian u32. Anything else is
/// returned as it is.
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

/// The device nodes in the build's stage0, with its modes, as
/// cmd/stage0/stage0.mtree lists them. The kernel opens /dev/console as
/// PID 1's stdin, stdout and stderr before anything mounts /dev; without
/// it stage0 and modload start with none, and what they say is lost or
/// lands in the first file they open. Root here may not make device files
/// (fence), and needs none: they go into the cpio as they are.
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

/// One newc cpio entry: header, name and data, each padded to 4 bytes.
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
    // outside/, which no link in root/ may reach: by an absolute path, up
    // out of the root, or as the file a name in the root links to. Up out
    // of the root is the root, as for /.. on the slot, so etc/up is the
    // root's own outside/.
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
    // The image's arguments replace any of the same name, and are added
    // where missing.
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
    // The versions a new entry must be newer than: mkdisk's first, a leap
    // day, and versions of other forms, which count as none.
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

test withoutGz {
    try testing.expectEqualStrings(
        "kernel/fs/ext4/ext4.ko",
        withoutGz("kernel/fs/ext4/ext4.ko.gz"),
    );
    try testing.expectEqualStrings("kernel/fs/ext4/ext4.ko", withoutGz("kernel/fs/ext4/ext4.ko"));
}

test moduleOrder {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const dep =
        \\kernel/fs/ext4/ext4.ko.gz: kernel/lib/crc/crc16.ko.gz kernel/fs/mbcache.ko.gz kernel/fs/jbd2/jbd2.ko.gz
        \\kernel/fs/xfs/xfs.ko.gz:
        \\kernel/fs/jbd2/jbd2.ko.gz:
        \\kernel/fs/btrfs/btrfs.ko.gz: kernel/lib/raid6/raid6_pq.ko.gz kernel/lib/crc/crc16.ko.gz
        \\kernel/lib/raid6/raid6_pq.ko.gz:
        \\kernel/fs/zfs/zfs.ko.gz: kernel/lib/raid6/raid6_pq.ko.gz
    ;
    const order = try moduleOrder(a, dep, &.{ "ext4", "xfs", "jbd2" });
    try testing.expectEqual(5, order.len);
    try testing.expectEqualStrings("kernel/fs/jbd2/jbd2.ko.gz", order[0].path);
    try testing.expectEqualStrings("kernel/fs/ext4/ext4.ko.gz", order[3].path);
    try testing.expectEqualStrings("kernel/fs/xfs/xfs.ko.gz", order[4].path);
    for (order) |mod| try testing.expectEqualStrings("", mod.tag);
    try testing.expectError(error.ModuleNotFound, moduleOrder(a, dep, &.{"f2fs"}));

    // Tagged leaves after the rest, whatever their place in the list; a
    // module the untagged need too (crc16) stays theirs, and one two tags
    // need (raid6_pq) is listed under each.
    const tagged = try moduleOrder(a, dep, &.{ "@btrfs:btrfs", "ext4", "@zfs:zfs" });
    try testing.expectEqual(4 + 2 + 2, tagged.len);
    try testing.expectEqualStrings("kernel/fs/ext4/ext4.ko.gz", tagged[3].path);
    try testing.expectEqualStrings("", tagged[3].tag);
    try testing.expectEqualStrings("kernel/lib/raid6/raid6_pq.ko.gz", tagged[4].path);
    try testing.expectEqualStrings("btrfs", tagged[4].tag);
    try testing.expectEqualStrings("kernel/fs/btrfs/btrfs.ko.gz", tagged[5].path);
    try testing.expectEqualStrings("kernel/lib/raid6/raid6_pq.ko.gz", tagged[6].path);
    try testing.expectEqualStrings("zfs", tagged[6].tag);
    try testing.expectEqualStrings("zfs", tagged[7].tag);
    for ([_][]const u8{ "@btrfs", "@:btrfs", "@btrfs:" }) |bad|
        try testing.expectError(error.BadModuleTag, moduleOrder(a, dep, &.{bad}));
}

test moduleList {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const order = [_]Mod{
        .{ .path = "kernel/arch/x86/kvm/kvm.ko.gz" },
        .{ .path = "kernel/arch/x86/kvm/kvm-intel.ko.gz" },
    };
    try testing.expectEqualStrings(
        "kernel/arch/x86/kvm/kvm.ko\nkernel/arch/x86/kvm/kvm-intel.ko\n",
        try moduleList(a, &order, ""),
    );
    try testing.expectEqualStrings(
        "kernel/arch/x86/kvm/kvm.ko\nkernel/arch/x86/kvm/kvm-intel.ko nested=0 ept=1\n",
        try moduleList(a, &order, "kvm-intel nested=0\nkvm-intel ept=1\n"),
    );
    try testing.expectEqualStrings(
        "@xfs kernel/fs/xfs/xfs.ko\n",
        try moduleList(a, &.{.{ .path = "kernel/fs/xfs/xfs.ko.gz", .tag = "xfs" }}, ""),
    );
    try testing.expectError(
        error.ParamsForMissingModule,
        moduleList(a, &order, "kvm-amd nested=0\n"),
    );
    try testing.expectError(error.BadModuleParams, moduleList(a, &order, "kvm-intel\n"));
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
