//! update: keep a machine booted from a slot current, from Wolfi and Alpine.
//!
//!     update check     if Wolfi or Alpine has anything newer than this image,
//!                      build the other slot, boot it once, and reboot
//!     update outcome   after a reboot, log whether the last update held
//!
//! The other slot is built as `make slot` builds one, with apk where the build
//! has apko: the userland from this image's /etc/apk (world, repositories,
//! Wolfi's key), the kernel from Alpine's linux-virt checked against the keys
//! in /etc/werewolf/alpine-keys, and the rest from the build record in
//! /usr/share/werewolf. apk fetches and verifies every package, and compares
//! every apk version; nothing here decides what to trust.
//!
//! Each update writes a report to /data/svc/autoupdate/reports: what changed,
//! the CVEs that fixes (Wolfi's security.json for packages, the Linux kernel
//! CNA's records for the kernel), and the sha256 of every source consulted, so
//! an auditor can fetch the same files and derive the same list. Every event
//! is also one JSON line in /data/svc/autoupdate/log and on the console.
//!
//! All memory comes from the process arena and is never freed before exit, so
//! nothing is used after it is freed. The one exception is the kernel's CVE
//! records, 17,000 of them, each parsed in a scratch arena reset between them,
//! with only what matches copied out.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const meta_dir = "/usr/share/werewolf";
const state_dir = "/data/svc/autoupdate";
const work_dir = state_dir ++ "/work";
const log_path = state_dir ++ "/log";
const kernel_cves_url = "https://git.kernel.org/pub/scm/linux/security/vulns.git/snapshot/vulns-master.tar.gz";
const max_read = 256 << 20;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    const mode = if (args.len == 2) args[1] else "";

    var u: Update = .{ .io = init.io, .gpa = gpa };
    u.setup() catch |err| fatal(&u, err);
    if (std.mem.eql(u8, mode, "check")) {
        u.check() catch |err| fatal(&u, err);
    } else if (std.mem.eql(u8, mode, "outcome")) {
        u.outcome() catch |err| fatal(&u, err);
    } else {
        std.debug.print("usage: update check|outcome\n", .{});
        std.process.exit(2);
    }
}

fn fatal(u: *Update, err: anyerror) noreturn {
    u.record(.{ .event = "error", .step = u.step, .@"error" = @errorName(err), .detail = u.detail }) catch {};
    Dir.cwd().deleteTree(u.io, work_dir) catch {};
    std.process.exit(1);
}

const Update = struct {
    io: Io,
    gpa: Allocator,
    host: []const u8 = "",
    cmd: Cmdline = .{},
    other: []const u8 = "b",
    step: []const u8 = "start",
    /// What the last command that failed said, for the error event.
    detail: []const u8 = "",

    fn setup(u: *Update) !void {
        try Dir.cwd().createDirPath(u.io, state_dir ++ "/reports");
        u.host = std.mem.trim(u8, try u.read("/etc/hostname"), " \n");
        u.cmd = parseCmdline(try u.read("/proc/cmdline"));
        if (u.cmd.slot.len == 0 or u.cmd.victim.len == 0 or u.cmd.grubenv.len == 0)
            return error.NotBootedFromASlot;
        u.other = if (std.mem.eql(u8, u.cmd.slot, "b")) "a" else "b";
    }

    // --- outcome -----------------------------------------------------------
    // The last update left `attempt`: the slot it built and the build's hash.
    // Booted into that slot, and committed, it held; booted into the other,
    // it did not, and the same build is not tried again.
    fn outcome(u: *Update) !void {
        const attempt = u.read(state_dir ++ "/attempt") catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        var it = std.mem.tokenizeAny(u8, attempt, " \n");
        const tried = it.next() orelse return error.BadAttemptFile;
        const build = it.next() orelse return error.BadAttemptFile;
        const release = std.mem.trim(u8, try u.read(meta_dir ++ "/release"), "\n");
        if (std.mem.eql(u8, tried, u.cmd.slot)) {
            try u.record(.{ .event = "commit", .slot = u.cmd.slot, .build = build, .release = release });
        } else {
            try u.append(state_dir ++ "/bad", try std.fmt.allocPrint(u.gpa, "{s}\n", .{build}));
            try u.record(.{ .event = "rollback", .failed = tried, .running = u.cmd.slot, .build = build, .release = release });
        }
        try Dir.cwd().deleteFile(u.io, state_dir ++ "/attempt");
    }

    // --- check -------------------------------------------------------------
    fn check(u: *Update) !void {
        const io = u.io;
        Dir.cwd().deleteTree(io, work_dir) catch {};
        try Dir.cwd().createDirPath(io, work_dir);
        defer Dir.cwd().deleteTree(io, work_dir) catch {};
        const arch = std.mem.trim(u8, try u.read("/etc/apk/arch"), "\n");
        const release = std.mem.trim(u8, try u.read(meta_dir ++ "/release"), "\n");

        u.step = "userland";
        try u.apkAdd(work_dir ++ "/root", arch, &.{ "--keys-dir", "/etc/apk/keys", "--repositories-file", "/etc/apk/repositories" }, try u.words(try u.read("/etc/apk/world")));
        u.step = "kernel";
        const alpine = std.mem.trim(u8, try u.read(meta_dir ++ "/alpine"), "\n");
        try u.apkAdd(work_dir ++ "/kernel", arch, &.{ "--keys-dir", "/etc/werewolf/alpine-keys", "--repository", alpine }, &.{"linux-virt"});

        u.step = "compare";
        const old_pkgs = try parseInstalled(u.gpa, try u.read("/lib/apk/db/installed"));
        const new_pkgs = try parseInstalled(u.gpa, try u.read(work_dir ++ "/root/lib/apk/db/installed"));
        const kernel_pkgs = try parseInstalled(u.gpa, try u.read(work_dir ++ "/kernel/lib/apk/db/installed"));
        const old_kernel = std.mem.trim(u8, try u.read(meta_dir ++ "/kernel"), "\n");
        const new_kernel = try std.fmt.allocPrint(u.gpa, "linux-virt-{s}", .{versionOf(kernel_pkgs, "linux-virt") orelse return error.NoKernel});
        const changes = try diffPackages(u.gpa, old_pkgs, new_pkgs);
        const kernel_changed = !std.mem.eql(u8, old_kernel, new_kernel);
        if (changes.len == 0 and !kernel_changed) {
            return u.record(.{ .event = "check", .slot = u.cmd.slot, .release = release, .result = "current" });
        }

        const build = try buildHash(u.gpa, new_pkgs, new_kernel);
        if (u.isBad(build)) {
            return u.record(.{ .event = "skip", .build = build, .reason = "this build rolled back before" });
        }

        u.step = "cves";
        var client: std.http.Client = .{ .allocator = u.gpa, .io = io };
        defer client.deinit();
        var sources: std.ArrayList(Source) = .empty;
        const repo = (try u.words(try u.read("/etc/apk/repositories")))[0];
        const package_cves = try u.packageCves(&client, &sources, repo, old_pkgs, new_pkgs);
        const kernel_cves = if (kernel_changed) try u.kernelCves(&client, &sources, old_kernel, new_kernel) else KernelFixes{};

        try u.buildSlot(arch, new_kernel, release);
        try u.install(build);

        u.step = "report";
        const stamp = try u.now();
        const report: Report = .{
            .time = stamp,
            .host = u.host,
            .build = build,
            .from = .{ .slot = u.cmd.slot, .release = release, .kernel = old_kernel },
            .to = .{ .slot = u.other, .kernel = new_kernel },
            .packages = changes,
            .package_cves = package_cves,
            .kernel_cves = kernel_cves,
            .sources = sources.items,
        };
        const report_path = try std.fmt.allocPrint(u.gpa, "{s}/reports/{s}-{s}.json", .{ state_dir, stamp, build });
        var out: Io.Writer.Allocating = .init(u.gpa);
        try std.json.Stringify.value(report, .{ .whitespace = .indent_2 }, &out.writer);
        try out.writer.writeByte('\n');
        try Dir.cwd().writeFile(io, .{ .sub_path = report_path, .data = out.written() });

        var cve_count: usize = kernel_cves.cves.len;
        for (package_cves) |p| cve_count += p.cves.len;
        try u.record(.{
            .event = "update",
            .from = u.cmd.slot,
            .to = u.other,
            .build = build,
            .kernel = try std.fmt.allocPrint(u.gpa, "{s} -> {s}", .{ old_kernel, new_kernel }),
            .packages = changes.len,
            .cves = cve_count,
            .report = report_path,
        });
        u.step = "reboot";
        Dir.cwd().deleteTree(io, work_dir) catch {};
        try u.run(&.{"/usr/bin/reboot"});
    }

    // --- CVEs --------------------------------------------------------------
    // Wolfi's security.json: for each source package, the version that fixed
    // each CVE. A CVE counts when that version is newer than the old one and no
    // newer than the new one, as apk compares them. "0" lists CVEs that never
    // applied. A versioned stream (openssl-4.0) is also looked up under its
    // base name (openssl); the window keeps other streams' fixes out. The file
    // is not signed, so it informs the report and nothing else.
    fn packageCves(u: *Update, client: *std.http.Client, sources: *std.ArrayList(Source), repo: []const u8, old: []const Package, new: []const Package) ![]const PackageFix {
        const url = try std.fmt.allocPrint(u.gpa, "{s}/security.json", .{repo});
        const body = u.fetch(client, sources, url) catch return &.{};
        const db = std.json.parseFromSliceLeaky(SecDb, u.gpa, body, .{ .ignore_unknown_fields = true }) catch |err| {
            sources.items[sources.items.len - 1].@"error" = @errorName(err);
            return &.{};
        };
        var fixes: std.ArrayList(PackageFix) = .empty;
        for (try diffOrigins(u.gpa, old, new)) |o| {
            var cves: std.ArrayList([]const u8) = .empty;
            const base = streamBase(o.origin);
            for (db.packages) |p| {
                if (!std.mem.eql(u8, p.pkg.name, o.origin) and !std.mem.eql(u8, p.pkg.name, base)) continue;
                const secfixes = p.pkg.secfixes orelse continue;
                var it = secfixes.map.iterator();
                while (it.next()) |e| {
                    const fixed = e.key_ptr.*;
                    if (std.mem.eql(u8, fixed, "0")) continue;
                    if (!try u.apkNewer(fixed, o.from) or try u.apkNewer(fixed, o.to)) continue;
                    for (e.value_ptr.*) |id| {
                        if (std.mem.startsWith(u8, id, "CVE-")) try appendUnique(u.gpa, &cves, id);
                    }
                }
            }
            if (cves.items.len == 0) continue;
            std.mem.sort([]const u8, cves.items, {}, lessString);
            try fixes.append(u.gpa, .{ .origin = o.origin, .from = o.from, .to = o.to, .cves = cves.items });
        }
        return fixes.items;
    }

    // The Linux kernel CNA's records, from git.kernel.org as one tarball: for
    // each CVE, the stable releases that fixed it. A CVE counts when its fix
    // for this kernel's branch (6.18.*) is in (old, new]. Records are often
    // published weeks after a fix ships, so this is what was known at update
    // time.
    fn kernelCves(u: *Update, client: *std.http.Client, sources: *std.ArrayList(Source), old_kernel: []const u8, new_kernel: []const u8) !KernelFixes {
        const old = kernelVersion(old_kernel) orelse return error.BadKernelVersion;
        const new = kernelVersion(new_kernel) orelse return error.BadKernelVersion;
        const branch = try std.fmt.allocPrint(u.gpa, "{d}.{d}", .{ new[0], new[1] });
        var fixes: KernelFixes = .{ .branch = branch, .from = old_kernel, .to = new_kernel };
        const body = u.fetch(client, sources, kernel_cves_url) catch return fixes;
        fixes.cves = scanKernelCves(u.gpa, body, branch, old, new) catch |err| {
            sources.items[sources.items.len - 1].@"error" = @errorName(err);
            return fixes;
        };
        return fixes;
    }

    /// GET url over TLS checked against the system's CA bundle, recording it
    /// as a source: its sha256 and when it was fetched, or why it was not.
    fn fetch(u: *Update, client: *std.http.Client, sources: *std.ArrayList(Source), url: []const u8) ![]const u8 {
        try sources.append(u.gpa, .{ .url = url, .fetched = try u.now() });
        const source = &sources.items[sources.items.len - 1];
        var body: Io.Writer.Allocating = .init(u.gpa);
        const res = client.fetch(.{ .location = .{ .url = url }, .response_writer = &body.writer }) catch |err| {
            source.@"error" = @errorName(err);
            return err;
        };
        if (res.status != .ok) {
            source.@"error" = @tagName(res.status);
            return error.HttpStatus;
        }
        source.sha256 = try sha256Hex(u.gpa, body.written());
        return body.written();
    }

    // --- build -------------------------------------------------------------
    fn buildSlot(u: *Update, arch: []const u8, new_kernel: []const u8, release: []const u8) !void {
        const io = u.io;
        const root = work_dir ++ "/root";
        try Dir.cwd().createDirPath(io, work_dir ++ "/slot");

        // What apko does that apk does not: busybox's links, no setuid or setgid.
        u.step = "root";
        try u.busyboxLinks(root);
        // werewolf's own files as the build laid them, and the apk setup and
        // build record the next update will need.
        for (try u.lines(try u.read(meta_dir ++ "/overlay"))) |p| try u.copyInto(root, p);
        for (&[_][]const u8{ "etc/apk/repositories", "etc/apk/arch" }) |p| try u.copyInto(root, p);
        for (try u.listDir("/etc/apk/keys")) |name| try u.copyInto(root, try std.fmt.allocPrint(u.gpa, "etc/apk/keys/{s}", .{name}));
        for (try u.listDir(meta_dir)) |name| try u.copyInto(root, try std.fmt.allocPrint(u.gpa, "usr/share/werewolf/{s}", .{name}));
        const form = std.mem.trim(u8, try u.read(meta_dir ++ "/form"), "\n");
        try u.write(root ++ meta_dir ++ "/kernel", try std.fmt.allocPrint(u.gpa, "{s}\n", .{new_kernel}));
        try u.write(root ++ meta_dir ++ "/release", try std.fmt.allocPrint(u.gpa, "{s} {s} {s} updated-on-{s} from {s}\n", .{ form, try u.now(), new_kernel, u.host, release }));
        try u.stripSetid(root);
        try u.run(&.{ "mkfs.erofs", "-b", "4096", "-zlz4hc", work_dir ++ "/slot/root.erofs", root });

        // Alpine's arm64 kernel is an EFI zboot image; the slot carries the raw
        // Image inside it, as the build does (see Makefile).
        u.step = "vmlinuz";
        const vmlinuz = try u.read(work_dir ++ "/kernel/boot/vmlinuz-virt");
        try u.write(work_dir ++ "/slot/vmlinuz", try unwrapZboot(u.gpa, vmlinuz));

        u.step = "stage0";
        const s = work_dir ++ "/stage0";
        try u.apkAdd(s, arch, &.{ "--keys-dir", "/etc/apk/keys", "--repositories-file", "/etc/apk/repositories" }, try u.words(try u.read(meta_dir ++ "/stage0.world")));
        try u.busyboxLinks(s);
        try u.stripSetid(s);
        try Dir.cwd().copyFile(meta_dir ++ "/stage0.init", Dir.cwd(), s ++ "/init", io, .{ .permissions = .fromMode(0o755) });
        const kvers = try u.listDir(work_dir ++ "/kernel/lib/modules");
        if (kvers.len != 1) return error.NotOneKernel;
        const src = try std.fmt.allocPrint(u.gpa, "{s}/kernel/lib/modules/{s}", .{ work_dir, kvers[0] });
        const dst = try std.fmt.allocPrint(u.gpa, "{s}/usr/lib/modules/{s}", .{ s, kvers[0] });
        const dep = try u.read(try std.fmt.allocPrint(u.gpa, "{s}/modules.dep", .{src}));
        const order = try moduleOrder(u.gpa, dep, try u.lines(try u.read(meta_dir ++ "/modules")));
        for (order) |p| {
            try Dir.cwd().copyFile(try std.fmt.allocPrint(u.gpa, "{s}/{s}", .{ src, p }), Dir.cwd(), try std.fmt.allocPrint(u.gpa, "{s}/{s}", .{ dst, p }), io, .{ .make_path = true });
        }
        var list: Io.Writer.Allocating = .init(u.gpa);
        for (order) |p| try list.writer.print("{s}\n", .{p});
        try u.write(try std.fmt.allocPrint(u.gpa, "{s}/werewolf.modules", .{dst}), list.written());
        try u.writeCpio(s, work_dir ++ "/stage0.cpio");
        try u.run(&.{ "zstd", "-19", "-q", "-f", "-o", work_dir ++ "/slot/initramfs.zst", work_dir ++ "/stage0.cpio" });
    }

    // --- install -----------------------------------------------------------
    // root.erofs beside this slot's on the victim's filesystem; the kernel and
    // stage0 in /boot/werewolf, beside GRUB's directory. Both mounted apart
    // and writable, since /victim is read-only.
    fn install(u: *Update, build: []const u8) !void {
        const io = u.io;
        u.step = "install";
        const v = work_dir ++ "/mnt/v";
        const g = work_dir ++ "/mnt/g";
        try Dir.cwd().createDirPath(io, v);
        try Dir.cwd().createDirPath(io, g);
        try u.mountUuid(uuidOf(u.cmd.victim), v);
        defer u.run(&.{ "umount", v }) catch {};
        try u.mountUuid(uuidOf(u.cmd.grubenv), g);
        defer u.run(&.{ "umount", g }) catch {};

        const gpath = pathOf(u.cmd.grubenv);
        const kdir = try std.fmt.allocPrint(u.gpa, "{s}{s}/werewolf/{s}", .{ g, parentDir(parentDir(gpath)), u.other });
        const rdir = try std.fmt.allocPrint(u.gpa, "{s}{s}/{s}", .{ v, pathOf(u.cmd.victim), u.other });
        try Dir.cwd().createDirPath(io, kdir);
        try Dir.cwd().createDirPath(io, rdir);
        const erofs_new = try std.fmt.allocPrint(u.gpa, "{s}/root.erofs.new", .{rdir});
        try Dir.cwd().copyFile(work_dir ++ "/slot/root.erofs", Dir.cwd(), erofs_new, io, .{});
        try Dir.cwd().rename(erofs_new, Dir.cwd(), try std.fmt.allocPrint(u.gpa, "{s}/root.erofs", .{rdir}), io);
        for (&[_][]const u8{ "vmlinuz", "initramfs.zst" }) |f| {
            try Dir.cwd().copyFile(try std.fmt.allocPrint(u.gpa, "{s}/slot/{s}", .{ work_dir, f }), Dir.cwd(), try std.fmt.allocPrint(u.gpa, "{s}/{s}", .{ kdir, f }), io, .{});
        }
        try u.run(&.{"sync"});
        try u.write(state_dir ++ "/attempt", try std.fmt.allocPrint(u.gpa, "{s} {s}\n", .{ u.other, build }));
        const entry = try std.fmt.allocPrint(u.gpa, "werewolf-{s}", .{u.other});
        try u.run(&.{ "/usr/lib/werewolf/grubenv", try std.fmt.allocPrint(u.gpa, "{s}{s}", .{ g, gpath }), "next_entry", entry });
    }

    // --- helpers -----------------------------------------------------------
    fn apkAdd(u: *Update, root: []const u8, arch: []const u8, source: []const []const u8, packages: []const []const u8) !void {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(u.gpa, &.{ "apk", "--root", root, "--arch", arch });
        try argv.appendSlice(u.gpa, source);
        try argv.appendSlice(u.gpa, &.{ "--no-scripts", "--quiet", "--no-progress", "add", "--initdb" });
        try argv.appendSlice(u.gpa, packages);
        try u.run(argv.items);
    }

    /// Whether apk version a is newer than b.
    fn apkNewer(u: *Update, a: []const u8, b: []const u8) !bool {
        const out = try u.output(&.{ "apk", "version", "-t", a, b });
        return std.mem.eql(u8, std.mem.trim(u8, out, " \n"), ">");
    }

    fn mountUuid(u: *Update, uuid: []const u8, dir: []const u8) !void {
        const dev = std.mem.trim(u8, try u.output(&.{ "blkid", "-c", "/dev/null", "-l", "-o", "device", "-t", try std.fmt.allocPrint(u.gpa, "UUID={s}", .{uuid}) }), "\n");
        try u.run(&.{ "mount", "-o", "nosuid,nodev,noexec", dev, dir });
    }

    fn busyboxLinks(u: *Update, root: []const u8) !void {
        const d = try std.fmt.allocPrint(u.gpa, "{s}/etc/busybox-paths.d", .{root});
        for (u.listDir(d) catch return) |name| {
            for (try u.lines(try u.read(try std.fmt.allocPrint(u.gpa, "{s}/{s}", .{ d, name })))) |p| {
                const link = try std.fmt.allocPrint(u.gpa, "{s}/{s}", .{ root, std.mem.trimStart(u8, p, "/") });
                _ = Dir.cwd().statFile(u.io, link, .{ .follow_symlinks = false }) catch {
                    try Dir.cwd().symLink(u.io, "/usr/bin/busybox", link, .{});
                };
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
                try e.dir.setFilePermissions(u.io, e.basename, .fromMode(mode & ~@as(std.posix.mode_t, 0o6000)), .{ .follow_symlinks = false });
            }
        }
    }

    /// Copy /path to root/path, with its permissions.
    fn copyInto(u: *Update, root: []const u8, path: []const u8) !void {
        const dst = try std.fmt.allocPrint(u.gpa, "{s}/{s}", .{ root, path });
        try Dir.cwd().copyFile(try std.fmt.allocPrint(u.gpa, "/{s}", .{path}), Dir.cwd(), dst, u.io, .{ .make_path = true });
    }

    /// A newc cpio of everything under root, as the kernel unpacks an
    /// initramfs: owned by root, children after their directory.
    fn writeCpio(u: *Update, root: []const u8, out_path: []const u8) !void {
        var out: Io.Writer.Allocating = .init(u.gpa);
        var d = try Dir.cwd().openDir(u.io, root, .{ .iterate = true });
        defer d.close(u.io);
        var w = try d.walk(u.gpa);
        var ino: u32 = 1;
        var link_buf: [Dir.max_path_bytes]u8 = undefined;
        while (try w.next(u.io)) |e| : (ino += 1) {
            const st = try e.dir.statFile(u.io, e.basename, .{ .follow_symlinks = false });
            const perm: u32 = @intCast(st.permissions.toMode() & 0o7777);
            switch (e.kind) {
                .directory => try cpioEntry(&out.writer, e.path, 0o040000 | perm, ino, ""),
                .sym_link => {
                    const n = try e.dir.readLink(u.io, e.basename, &link_buf);
                    try cpioEntry(&out.writer, e.path, 0o120000 | 0o777, ino, link_buf[0..n]);
                },
                .file => try cpioEntry(&out.writer, e.path, 0o100000 | perm, ino, try e.dir.readFileAlloc(u.io, e.basename, u.gpa, .limited(max_read))),
                else => return error.UnexpectedFileKind,
            }
        }
        try cpioEntry(&out.writer, "TRAILER!!!", 0, 0, "");
        try u.write(out_path, out.written());
    }

    fn isBad(u: *Update, build: []const u8) bool {
        const bad = u.read(state_dir ++ "/bad") catch return false;
        for (u.lines(bad) catch return false) |l| if (std.mem.eql(u8, l, build)) return true;
        return false;
    }

    /// One JSON line, in the log and on the console.
    fn record(u: *Update, fields: anytype) !void {
        var line: Io.Writer.Allocating = .init(u.gpa);
        try line.writer.print("{{\"time\":\"{s}\",\"host\":", .{try u.now()});
        try std.json.Stringify.value(u.host, .{}, &line.writer);
        var rest: Io.Writer.Allocating = .init(u.gpa);
        try std.json.Stringify.value(fields, .{}, &rest.writer);
        try line.writer.print(",{s}\n", .{rest.written()[1..]});
        try u.append(log_path, line.written());
        try Io.File.stdout().writeStreamingAll(u.io, try std.fmt.allocPrint(u.gpa, "autoupdate: {s}", .{line.written()}));
    }

    fn run(u: *Update, argv: []const []const u8) !void {
        _ = try u.output(argv);
    }

    fn output(u: *Update, argv: []const []const u8) ![]const u8 {
        const res = try std.process.run(u.gpa, u.io, .{ .argv = argv });
        switch (res.term) {
            .exited => |code| if (code == 0) return res.stdout,
            else => {},
        }
        u.detail = try std.fmt.allocPrint(u.gpa, "{s}: {s}", .{ argv[0], std.mem.trim(u8, res.stderr[0..@min(res.stderr.len, 400)], " \n") });
        return error.CommandFailed;
    }

    fn read(u: *Update, path: []const u8) ![]const u8 {
        return Dir.cwd().readFileAlloc(u.io, path, u.gpa, .limited(max_read));
    }

    fn write(u: *Update, path: []const u8, data: []const u8) !void {
        try Dir.cwd().writeFile(u.io, .{ .sub_path = path, .data = data });
    }

    fn append(u: *Update, path: []const u8, data: []const u8) !void {
        var f = try Dir.cwd().createFile(u.io, path, .{ .truncate = false });
        defer f.close(u.io);
        try f.writePositionalAll(u.io, data, try f.length(u.io));
    }

    fn listDir(u: *Update, path: []const u8) ![]const []const u8 {
        var d = try Dir.cwd().openDir(u.io, path, .{ .iterate = true });
        defer d.close(u.io);
        var names: std.ArrayList([]const u8) = .empty;
        var it = d.iterate();
        while (try it.next(u.io)) |e| try names.append(u.gpa, try u.gpa.dupe(u8, e.name));
        std.mem.sort([]const u8, names.items, {}, lessString);
        return names.items;
    }

    fn lines(u: *Update, text: []const u8) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        var it = std.mem.tokenizeScalar(u8, text, '\n');
        while (it.next()) |l| {
            const t = std.mem.trim(u8, l, " \r");
            if (t.len > 0) try out.append(u.gpa, t);
        }
        return out.items;
    }

    fn words(u: *Update, text: []const u8) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        var it = std.mem.tokenizeAny(u8, text, " \n");
        while (it.next()) |w| try out.append(u.gpa, w);
        if (out.items.len == 0) return error.Empty;
        return out.items;
    }

    /// Now, as RFC 3339 in UTC.
    fn now(u: *Update) ![]const u8 {
        const ns = Io.Timestamp.now(u.io, .real).nanoseconds;
        return rfc3339(u.gpa, @intCast(@divFloor(ns, std.time.ns_per_s)));
    }
};

// --- report ------------------------------------------------------------------

const Report = struct {
    time: []const u8,
    host: []const u8,
    build: []const u8,
    from: struct { slot: []const u8, release: []const u8, kernel: []const u8 },
    to: struct { slot: []const u8, kernel: []const u8 },
    packages: []const Change,
    package_cves: []const PackageFix,
    kernel_cves: KernelFixes,
    sources: []const Source,
};

const Change = struct { name: []const u8, from: ?[]const u8, to: ?[]const u8 };
const PackageFix = struct { origin: []const u8, from: []const u8, to: []const u8, cves: []const []const u8 };
const KernelFix = struct { id: []const u8, fixed_in: []const u8, title: []const u8 };
const KernelFixes = struct { branch: []const u8 = "", from: []const u8 = "", to: []const u8 = "", cves: []const KernelFix = &.{} };
const Source = struct { url: []const u8, fetched: []const u8, sha256: ?[]const u8 = null, @"error": ?[]const u8 = null };

// --- pure functions, tested below ----------------------------------------------

const Cmdline = struct { victim: []const u8 = "", slot: []const u8 = "", grubenv: []const u8 = "" };

fn parseCmdline(text: []const u8) Cmdline {
    var c: Cmdline = .{};
    var it = std.mem.tokenizeAny(u8, text, " \n");
    while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "werewolf.victim=")) c.victim = arg["werewolf.victim=".len..];
        if (std.mem.startsWith(u8, arg, "werewolf.slot=")) c.slot = arg["werewolf.slot=".len..];
        if (std.mem.startsWith(u8, arg, "werewolf.grubenv=")) c.grubenv = arg["werewolf.grubenv=".len..];
    }
    return c;
}

fn uuidOf(spec: []const u8) []const u8 {
    return spec[0 .. std.mem.indexOfScalar(u8, spec, ':') orelse spec.len];
}

fn pathOf(spec: []const u8) []const u8 {
    const i = std.mem.indexOfScalar(u8, spec, ':') orelse return "";
    return spec[i + 1 ..];
}

fn parentDir(path: []const u8) []const u8 {
    return path[0 .. std.mem.lastIndexOfScalar(u8, path, '/') orelse 0];
}

const Package = struct { name: []const u8, version: []const u8, origin: []const u8 };

/// The packages in an apk installed database: P (name), V (version) and o
/// (origin, the source package) of each record; records end at a blank line.
fn parseInstalled(gpa: Allocator, text: []const u8) ![]const Package {
    var out: std.ArrayList(Package) = .empty;
    var p: Package = .{ .name = "", .version = "", .origin = "" };
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) {
            if (p.name.len > 0) try out.append(gpa, finish(p));
            p = .{ .name = "", .version = "", .origin = "" };
        } else if (std.mem.startsWith(u8, line, "P:")) {
            p.name = line[2..];
        } else if (std.mem.startsWith(u8, line, "V:")) {
            p.version = line[2..];
        } else if (std.mem.startsWith(u8, line, "o:")) {
            p.origin = line[2..];
        }
    }
    if (p.name.len > 0) try out.append(gpa, finish(p));
    std.mem.sort(Package, out.items, {}, struct {
        fn lt(_: void, a: Package, b: Package) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.lt);
    return out.items;
}

fn finish(p: Package) Package {
    return .{ .name = p.name, .version = p.version, .origin = if (p.origin.len > 0) p.origin else p.name };
}

fn versionOf(pkgs: []const Package, name: []const u8) ?[]const u8 {
    for (pkgs) |p| if (std.mem.eql(u8, p.name, name)) return p.version;
    return null;
}

/// Each package whose version differs: from null is added, to null removed.
fn diffPackages(gpa: Allocator, old: []const Package, new: []const Package) ![]const Change {
    var out: std.ArrayList(Change) = .empty;
    for (new) |n| {
        const o = versionOf(old, n.name);
        if (o == null or !std.mem.eql(u8, o.?, n.version)) try out.append(gpa, .{ .name = n.name, .from = o, .to = n.version });
    }
    for (old) |o| {
        if (versionOf(new, o.name) == null) try out.append(gpa, .{ .name = o.name, .from = o.version, .to = null });
    }
    return out.items;
}

const OriginChange = struct { origin: []const u8, from: []const u8, to: []const u8 };

/// Source packages present before and after, at different versions.
fn diffOrigins(gpa: Allocator, old: []const Package, new: []const Package) ![]const OriginChange {
    var out: std.ArrayList(OriginChange) = .empty;
    for (new) |n| {
        const o = for (old) |p| {
            if (std.mem.eql(u8, p.origin, n.origin)) break p.version;
        } else continue;
        if (std.mem.eql(u8, o, n.version)) continue;
        for (out.items) |c| {
            if (std.mem.eql(u8, c.origin, n.origin)) break;
        } else try out.append(gpa, .{ .origin = n.origin, .from = o, .to = n.version });
    }
    return out.items;
}

/// openssl-4.0 -> openssl; a name without a version suffix is its own base.
fn streamBase(origin: []const u8) []const u8 {
    const i = std.mem.lastIndexOfScalar(u8, origin, '-') orelse return origin;
    const tail = origin[i + 1 ..];
    if (tail.len == 0) return origin;
    for (tail) |c| if (!std.ascii.isDigit(c) and c != '.') return origin;
    return origin[0..i];
}

/// The first 16 hex digits of the sha256 of what goes into a build.
fn buildHash(gpa: Allocator, pkgs: []const Package, kernel: []const u8) ![]const u8 {
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    for (pkgs) |p| {
        h.update(p.name);
        h.update("-");
        h.update(p.version);
        h.update("\n");
    }
    h.update(kernel);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    const hex = std.fmt.bytesToHex(digest, .lower);
    return gpa.dupe(u8, hex[0..16]);
}

fn sha256Hex(gpa: Allocator, data: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    return gpa.dupe(u8, &hex);
}

/// linux-virt-6.18.55-r0, or 6.18.55, as {6, 18, 55}.
fn kernelVersion(s: []const u8) ?[3]u32 {
    var v = s;
    if (std.mem.startsWith(u8, v, "linux-virt-")) v = v["linux-virt-".len..];
    if (std.mem.indexOfScalar(u8, v, '-')) |i| v = v[0..i];
    var out: [3]u32 = .{ 0, 0, 0 };
    var it = std.mem.splitScalar(u8, v, '.');
    for (&out) |*part| {
        const field = it.next() orelse return null;
        part.* = std.fmt.parseInt(u32, field, 10) catch return null;
    }
    if (it.next() != null) return null;
    return out;
}

fn kernelLess(a: [3]u32, b: [3]u32) bool {
    return std.mem.order(u32, &a, &b) == .lt;
}

/// The parts of a kernel CNA record (CVE JSON 5) that say which stable
/// release fixed it on which branch.
const KernelRecord = struct {
    cveMetadata: struct { cveId: []const u8 },
    containers: struct {
        cna: struct {
            title: []const u8 = "",
            affected: []const struct {
                versions: []const struct {
                    version: []const u8,
                    status: []const u8,
                    lessThanOrEqual: ?[]const u8 = null,
                    versionType: ?[]const u8 = null,
                } = &.{},
            } = &.{},
        },
    },
};

/// The version that fixed this CVE on branch, if it is in (old, new].
fn kernelFixedIn(rec: KernelRecord, branch: []const u8, old: [3]u32, new: [3]u32) ?[]const u8 {
    for (rec.containers.cna.affected) |a| {
        for (a.versions) |v| {
            if (!std.mem.eql(u8, v.status, "unaffected")) continue;
            if (!std.mem.eql(u8, v.versionType orelse "", "semver")) continue;
            const le = v.lessThanOrEqual orelse continue;
            if (!std.mem.endsWith(u8, le, ".*") or !std.mem.eql(u8, le[0 .. le.len - 2], branch)) continue;
            const fixed = kernelVersion(v.version) orelse continue;
            if (kernelLess(old, fixed) and !kernelLess(new, fixed)) return v.version;
        }
    }
    return null;
}

/// Every CVE in the kernel CNA's tarball fixed on branch in (old, new].
fn scanKernelCves(gpa: Allocator, tarball_gz: []const u8, branch: []const u8, old: [3]u32, new: [3]u32) ![]const KernelFix {
    var in: Io.Reader = .fixed(tarball_gz);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var gz: std.compress.flate.Decompress = .init(&in, .gzip, &window);
    var name_buf: [Dir.max_path_bytes]u8 = undefined;
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&gz.reader, .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf });
    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();
    var out: std.ArrayList(KernelFix) = .empty;
    while (try it.next()) |file| {
        if (file.kind != .file or !isKernelRecord(file.name)) continue;
        _ = scratch.reset(.retain_capacity);
        const s = scratch.allocator();
        var body: Io.Writer.Allocating = .init(s);
        try it.streamRemaining(file, &body.writer);
        const rec = std.json.parseFromSliceLeaky(KernelRecord, s, body.written(), .{ .ignore_unknown_fields = true }) catch continue;
        const fixed = kernelFixedIn(rec, branch, old, new) orelse continue;
        try out.append(gpa, .{
            .id = try gpa.dupe(u8, rec.cveMetadata.cveId),
            .fixed_in = try gpa.dupe(u8, fixed),
            .title = try gpa.dupe(u8, rec.containers.cna.title),
        });
    }
    std.mem.sort(KernelFix, out.items, {}, struct {
        fn lt(_: void, a: KernelFix, b: KernelFix) bool {
            return std.mem.lessThan(u8, a.id, b.id);
        }
    }.lt);
    return out.items;
}

/// vulns-master/cve/published/2026/CVE-2026-52988.json
fn isKernelRecord(name: []const u8) bool {
    const base = name[(std.mem.lastIndexOfScalar(u8, name, '/') orelse return false) + 1 ..];
    return std.mem.indexOf(u8, name, "/cve/published/") != null and
        std.mem.startsWith(u8, base, "CVE-") and std.mem.endsWith(u8, base, ".json");
}

/// Wolfi's security.json, as much of it as is used.
const SecDb = struct {
    packages: []const struct {
        pkg: struct {
            name: []const u8,
            secfixes: ?std.json.ArrayHashMap([]const []const u8) = null,
        },
    },
};

/// The order to load modules in: each leaf's dependencies from modules.dep,
/// read back to front, then the leaf; each module once.
fn moduleOrder(gpa: Allocator, dep: []const u8, leaves: []const []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (leaves) |leaf| {
        const suffix = try std.fmt.allocPrint(gpa, "/{s}.ko.gz", .{leaf});
        var lines_it = std.mem.splitScalar(u8, dep, '\n');
        const line = while (lines_it.next()) |l| {
            const colon = std.mem.indexOfScalar(u8, l, ':') orelse continue;
            if (std.mem.endsWith(u8, l[0..colon], suffix)) break l;
        } else return error.ModuleNotFound;
        var fields: std.ArrayList([]const u8) = .empty;
        var f = std.mem.tokenizeAny(u8, line, ": ");
        while (f.next()) |x| try fields.append(gpa, x);
        var i = fields.items.len;
        while (i > 0) {
            i -= 1;
            try appendUnique(gpa, &out, fields.items[i]);
        }
    }
    return out.items;
}

/// Alpine's arm64 vmlinuz is an EFI zboot image: "MZ", "zimg", then the
/// gzipped Image's offset and size as little-endian u32. Anything else is
/// returned as it is.
fn unwrapZboot(gpa: Allocator, image: []const u8) ![]const u8 {
    if (image.len < 16 or !std.mem.eql(u8, image[4..8], "zimg")) return image;
    const off = std.mem.readInt(u32, image[8..12], .little);
    const size = std.mem.readInt(u32, image[12..16], .little);
    if (@as(u64, off) + size > image.len) return error.BadZboot;
    var in: Io.Reader = .fixed(image[off .. off + size]);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var gz: std.compress.flate.Decompress = .init(&in, .gzip, &window);
    var out: Io.Writer.Allocating = .init(gpa);
    _ = try gz.reader.streamRemaining(&out.writer);
    return out.written();
}

/// One newc cpio entry: header, name and data, each padded to 4 bytes.
fn cpioEntry(w: *Io.Writer, name: []const u8, mode: u32, ino: u32, data: []const u8) !void {
    const fields = [_]u32{ ino, mode, 0, 0, 1, 0, @intCast(data.len), 0, 0, 0, 0, @intCast(name.len + 1), 0 };
    try w.writeAll("070701");
    for (fields) |f| try w.print("{x:0>8}", .{f});
    try w.writeAll(name);
    try w.writeByte(0);
    try w.splatByteAll(0, pad4(110 + name.len + 1));
    try w.writeAll(data);
    try w.splatByteAll(0, pad4(data.len));
}

fn pad4(n: usize) usize {
    return (4 - n % 4) % 4;
}

fn rfc3339(gpa: Allocator, secs: u64) ![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.allocPrint(gpa, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
}

fn appendUnique(gpa: Allocator, list: *std.ArrayList([]const u8), s: []const u8) !void {
    for (list.items) |x| if (std.mem.eql(u8, x, s)) return;
    try list.append(gpa, s);
}

fn lessString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test parseCmdline {
    const c = parseCmdline("console=hvc0 werewolf.victim=abcd:/var/lib/werewolf werewolf.slot=b werewolf.grubenv=ef01:/boot/grub/grubenv\n");
    try testing.expectEqualStrings("abcd:/var/lib/werewolf", c.victim);
    try testing.expectEqualStrings("b", c.slot);
    try testing.expectEqualStrings("abcd", uuidOf(c.victim));
    try testing.expectEqualStrings("/var/lib/werewolf", pathOf(c.victim));
    try testing.expectEqualStrings("/boot", parentDir(parentDir(pathOf(c.grubenv))));
    try testing.expectEqualStrings("", parentDir(parentDir("/grub/grubenv")));
}

test "installed database, diffs and origins" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const old = try parseInstalled(a, "P:busybox-full\nV:1.37.0-r30\no:busybox\n\nP:openssl-4.0-libcrypto\nV:4.0.2-r0\no:openssl-4.0\n\nP:gone\nV:1-r0\n");
    const new = try parseInstalled(a, "P:openssl-4.0-libcrypto\nV:4.0.3-r3\no:openssl-4.0\n\nP:busybox-full\nV:1.38.0-r2\no:busybox\n\nP:fresh\nV:2-r0\n\n");
    try testing.expectEqual(3, old.len);
    try testing.expectEqualStrings("gone", old[1].origin);

    const changes = try diffPackages(a, old, new);
    try testing.expectEqual(4, changes.len);
    try testing.expectEqualStrings("busybox-full", changes[0].name);
    try testing.expectEqualStrings("1.37.0-r30", changes[0].from.?);
    try testing.expectEqualStrings("fresh", changes[1].name);
    try testing.expectEqual(null, changes[1].from);
    try testing.expectEqualStrings("gone", changes[3].name);
    try testing.expectEqual(null, changes[3].to);

    const origins = try diffOrigins(a, old, new);
    try testing.expectEqual(2, origins.len);
    try testing.expectEqualStrings("busybox", origins[0].origin);
    try testing.expectEqualStrings("openssl-4.0", origins[1].origin);

    try testing.expectEqualStrings((try buildHash(a, new, "k")), (try buildHash(a, new, "k")));
    try testing.expect(!std.mem.eql(u8, try buildHash(a, new, "k"), try buildHash(a, old, "k")));
}

test streamBase {
    try testing.expectEqualStrings("openssl", streamBase("openssl-4.0"));
    try testing.expectEqualStrings("glibc", streamBase("glibc-2.44"));
    try testing.expectEqualStrings("busybox", streamBase("busybox"));
    try testing.expectEqualStrings("ca-certificates", streamBase("ca-certificates"));
    try testing.expectEqualStrings("py3-", streamBase("py3-"));
}

test kernelVersion {
    try testing.expectEqual([3]u32{ 6, 18, 55 }, kernelVersion("linux-virt-6.18.55-r0").?);
    try testing.expectEqual([3]u32{ 6, 18, 42 }, kernelVersion("6.18.42").?);
    try testing.expectEqual(null, kernelVersion("6.18"));
    try testing.expectEqual(null, kernelVersion("6.18.x"));
}

test "kernel CVE window" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const json =
        \\{"cveMetadata":{"cveId":"CVE-2026-52988"},"containers":{"cna":{"title":"netfilter: x",
        \\ "affected":[{"versions":[{"version":"0","lessThan":"5.15","status":"unaffected","versionType":"semver"},
        \\   {"version":"6.12.101","lessThanOrEqual":"6.12.*","status":"unaffected","versionType":"semver"},
        \\   {"version":"6.18.55","lessThanOrEqual":"6.18.*","status":"unaffected","versionType":"semver"},
        \\   {"version":"abc","lessThan":"def","status":"affected","versionType":"git"}]}]}}}
    ;
    const rec = try std.json.parseFromSliceLeaky(KernelRecord, arena.allocator(), json, .{ .ignore_unknown_fields = true });
    try testing.expectEqualStrings("6.18.55", kernelFixedIn(rec, "6.18", .{ 6, 18, 54 }, .{ 6, 18, 55 }).?);
    try testing.expectEqualStrings("6.18.55", kernelFixedIn(rec, "6.18", .{ 6, 18, 1 }, .{ 6, 18, 60 }).?);
    try testing.expectEqual(null, kernelFixedIn(rec, "6.18", .{ 6, 18, 55 }, .{ 6, 18, 60 }));
    try testing.expectEqual(null, kernelFixedIn(rec, "6.18", .{ 6, 18, 50 }, .{ 6, 18, 54 }));
    try testing.expectEqual(null, kernelFixedIn(rec, "6.1", .{ 6, 1, 1 }, .{ 6, 1, 999 }));
    try testing.expect(isKernelRecord("vulns-master/cve/published/2026/CVE-2026-52988.json"));
    try testing.expect(!isKernelRecord("vulns-master/cve/published/2026/CVE-2026-52988.mbox"));
    try testing.expect(!isKernelRecord("vulns-master/cve/rejected/2026/CVE-2026-1.json"));
}

test "secdb parses with versions as keys" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const db = try std.json.parseFromSliceLeaky(SecDb, arena.allocator(),
        \\{"apkurl":"x","packages":[{"pkg":{"name":"zlib","secfixes":{"0":["CVE-2026-22184"],"1.3.2.1_rc20260601-r0":["CVE-2026-85091","GHSA-x"]}}},{"pkg":{"name":"none"}}]}
    , .{ .ignore_unknown_fields = true });
    try testing.expectEqual(2, db.packages.len);
    try testing.expectEqual(2, db.packages[0].pkg.secfixes.?.map.count());
    try testing.expectEqual(null, db.packages[1].pkg.secfixes);
}

test moduleOrder {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const dep =
        \\kernel/fs/ext4/ext4.ko.gz: kernel/lib/crc/crc16.ko.gz kernel/fs/mbcache.ko.gz kernel/fs/jbd2/jbd2.ko.gz
        \\kernel/fs/xfs/xfs.ko.gz:
        \\kernel/fs/jbd2/jbd2.ko.gz:
    ;
    const order = try moduleOrder(arena.allocator(), dep, &.{ "ext4", "xfs", "jbd2" });
    try testing.expectEqual(5, order.len);
    try testing.expectEqualStrings("kernel/fs/jbd2/jbd2.ko.gz", order[0]);
    try testing.expectEqualStrings("kernel/fs/ext4/ext4.ko.gz", order[3]);
    try testing.expectEqualStrings("kernel/fs/xfs/xfs.ko.gz", order[4]);
    try testing.expectError(error.ModuleNotFound, moduleOrder(arena.allocator(), dep, &.{"btrfs"}));
}

test cpioEntry {
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try cpioEntry(&out.writer, "init", 0o100755, 1, "ab");
    const b = out.written();
    try testing.expectEqualStrings("070701", b[0..6]);
    try testing.expectEqualStrings("000081ed", b[14..22]);
    try testing.expectEqualStrings("init\x00", b[110..115]);
    try testing.expectEqual(0, (110 + 5 + pad4(115)) % 4);
    try testing.expectEqual(b.len, 110 + 5 + pad4(115) + 2 + pad4(2));
}

test unwrapZboot {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const plain = "not a zboot image, at all";
    try testing.expectEqualStrings(plain, try unwrapZboot(arena.allocator(), plain));
    var bad = [_]u8{0} ** 16;
    @memcpy(bad[4..8], "zimg");
    std.mem.writeInt(u32, bad[8..12], 8, .little);
    std.mem.writeInt(u32, bad[12..16], 100, .little);
    try testing.expectError(error.BadZboot, unwrapZboot(arena.allocator(), &bad));
}

test rfc3339 {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("2026-10-06T12:42:29Z", try rfc3339(arena.allocator(), 1791290549));
}
