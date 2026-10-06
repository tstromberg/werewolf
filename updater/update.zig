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
const linux = std.os.linux;
const sandbox = @import("sandbox.zig");

const meta_dir = "/usr/share/werewolf";
const state_dir = "/data/svc/autoupdate";
const work_dir = state_dir ++ "/work";
const cache_dir = state_dir ++ "/cache";
const log_path = state_dir ++ "/log";
const kernel_cves_url = "https://git.kernel.org/pub/scm/linux/security/vulns.git/snapshot/vulns-master.tar.gz";
const max_read = 256 << 20;

/// _update, the account the CVE children run as (forms/autoupdate.yaml).
const update_id: u32 = 69;
/// The fetcher's root, and where the CVE sources are fetched to.
const net_root = work_dir ++ "/net";
const cves_dir = work_dir ++ "/cves";
/// How long a fetcher and a reader may take, in seconds; what a reader may
/// send back; the memory it may map, all told; a kernel CVE's title.
const fetch_seconds = 600;
const apk_seconds = 1800;
const read_seconds = 300;
const max_lines = 4 << 20;
const reader_memory = 1 << 30;
const max_title = 512;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    // runsv starts /etc/sv/autoupdate/run, a link to this program, with no
    // arguments: that is the daemon.
    const as_service = args.len == 1 and std.mem.eql(u8, std.fs.path.basename(args[0]), "run");
    const mode = if (args.len == 2) args[1] else if (as_service) "daemon" else "";
    if (std.mem.eql(u8, mode, "daemon")) daemon(init.io);

    var u: Update = .{ .io = init.io, .gpa = gpa };
    u.setup() catch |err| fatal(&u, err);
    if (std.mem.eql(u8, mode, "check")) {
        u.check() catch |err| fatal(&u, err);
    } else if (std.mem.eql(u8, mode, "outcome")) {
        u.outcome() catch |err| fatal(&u, err);
    } else {
        std.debug.print("usage: update check|outcome|daemon\n", .{});
        std.process.exit(2);
    }
}

fn fatal(u: *Update, err: anyerror) noreturn {
    failed(u, err);
    std.process.exit(1);
}

/// An error, logged, and the work directory cleared.
fn failed(u: *Update, err: anyerror) void {
    u.record(.{ .event = "error", .step = u.step, .@"error" = @errorName(err), .detail = u.detail }) catch {};
    Dir.cwd().deleteTree(u.io, work_dir) catch {};
}

/// The autoupdate service. Once this slot has committed: outcome, then a
/// check at once and every 20 hours after, or as often as the form's
/// /etc/werewolf/update-every says, in seconds (demo's says 3600). A check
/// that fails is logged and tried again next time. Each pass has an arena
/// of its own, freed when it ends, so months of checks use what one does.
/// Only a machine booted from a slot can do any of this; elsewhere the
/// service parks itself.
fn daemon(io: Io) noreturn {
    switch (pass(io, .setup)) {
        .ok => {},
        .not_a_slot => park(io, "not booted from a slot, staying down"),
        .failed => {},
    }
    while (true) {
        Dir.cwd().access(io, "/run/werewolf/committed", .{}) catch {
            io.sleep(.fromSeconds(10), .awake) catch {};
            continue;
        };
        break;
    }
    const every = updateEvery(io);
    _ = pass(io, .outcome);
    while (true) {
        _ = pass(io, .check);
        io.sleep(.fromSeconds(every), .awake) catch {};
    }
}

const Step = enum { setup, outcome, check };
const PassResult = enum { ok, not_a_slot, failed };

fn pass(io: Io, step: Step) PassResult {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    var u: Update = .{ .io = io, .gpa = arena.allocator() };
    u.setup() catch |err| {
        if (err == error.NotBootedFromASlot) return .not_a_slot;
        failed(&u, err);
        return .failed;
    };
    (switch (step) {
        .setup => {},
        .outcome => u.outcome(),
        .check => u.check(),
    }) catch |err| {
        failed(&u, err);
        return .failed;
    };
    return .ok;
}

/// Seconds between checks: the form's /etc/werewolf/update-every, or 20
/// hours.
fn updateEvery(io: Io) i64 {
    var buf: [32]u8 = undefined;
    const n = Dir.cwd().readFile(io, "/etc/werewolf/update-every", &buf) catch return 72000;
    return std.fmt.parseInt(i64, std.mem.trim(u8, n, " \n"), 10) catch 72000;
}

/// Down, as a service with nothing to do: runsv will not restart it.
fn park(io: Io, why: []const u8) noreturn {
    Io.File.stdout().writeStreamingAll(io, "autoupdate: ") catch {};
    Io.File.stdout().writeStreamingAll(io, why) catch {};
    Io.File.stdout().writeStreamingAll(io, "\n") catch {};
    const err = std.process.replace(io, .{ .argv = &.{ "/usr/bin/sv", "down", "." } });
    std.debug.print("autoupdate: sv down: {s}\n", .{@errorName(err)});
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
        // The kernel's, which init sets whether or not a config named one.
        const uts = std.posix.uname();
        u.host = try u.gpa.dupe(u8, std.mem.sliceTo(&uts.nodename, 0));
        u.cmd = parseCmdline(try u.read("/proc/cmdline"));
        // A slot boots from a distro's GRUB (bite: werewolf.grubenv) or from
        // werewolf's own disk under systemd-boot (werewolf.esp).
        if (u.cmd.slot.len == 0 or u.cmd.victim.len == 0 or (u.cmd.grubenv.len == 0 and u.cmd.esp.len == 0))
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
        try u.netRoot();
        var sources: std.ArrayList(Source) = .empty;
        const repo = (try u.words(try u.read("/etc/apk/repositories")))[0];
        const package_cves = try u.packageCves(&sources, repo, old_pkgs, new_pkgs);
        const kernel_cves = if (kernel_changed) try u.kernelCves(&sources, old_kernel, new_kernel) else KernelFixes{};

        try u.buildSlot(arch, new_kernel);
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
    // Root neither fetches a CVE source nor parses one. For each, a fetcher
    // (below) makes the request as _update and writes the body to a file
    // root opened for it; root hashes the file for the report; a reader, as
    // _update with no network and no files, parses it and sends back a line
    // per CVE, which root checks field by field, the version window again
    // included, before any goes in the report.

    // Wolfi's security.json: for each source package, the version that fixed
    // each CVE. A CVE counts when that version is newer than the old one and
    // no newer than the new one, in apk's order. "0" lists CVEs that never
    // applied. A versioned stream (openssl-4.0) is also looked up under its
    // base name (openssl); the window keeps other streams' fixes out. The
    // file is not signed, so it informs the report and nothing else.
    fn packageCves(u: *Update, sources: *std.ArrayList(Source), repo: []const u8, old: []const Package, new: []const Package) ![]const PackageFix {
        const origins = try diffOrigins(u.gpa, old, new);
        const url = try std.fmt.allocPrint(u.gpa, "{s}/security.json", .{repo});
        const body = try u.fetch(sources, url, "security.json") orelse return &.{};
        defer _ = linux.close(body.fd);
        const found = u.examine(sources, .{ .secdb = origins }, body) orelse return &.{};
        return packageFixes(u.gpa, found, origins) catch |err| {
            sources.items[sources.items.len - 1].@"error" = @errorName(err);
            return &.{};
        };
    }

    // The Linux kernel CNA's records, from git.kernel.org as one tarball: for
    // each CVE, the stable releases that fixed it. A CVE counts when its fix
    // for this kernel's branch (6.18.*) is in (old, new]. Records are often
    // published weeks after a fix ships, so this is what was known at update
    // time.
    fn kernelCves(u: *Update, sources: *std.ArrayList(Source), old_kernel: []const u8, new_kernel: []const u8) !KernelFixes {
        const old = kernelVersion(old_kernel) orelse return error.BadKernelVersion;
        const new = kernelVersion(new_kernel) orelse return error.BadKernelVersion;
        const branch = try std.fmt.allocPrint(u.gpa, "{d}.{d}", .{ new[0], new[1] });
        var fixes: KernelFixes = .{ .branch = branch, .from = old_kernel, .to = new_kernel };
        const body = try u.fetch(sources, kernel_cves_url, "vulns.tar.gz") orelse return fixes;
        defer _ = linux.close(body.fd);
        const found = u.examine(sources, .{ .kernel = .{ .branch = branch, .old = old, .new = new } }, body) orelse return fixes;
        fixes.cves = kernelFixes(u.gpa, found, old, new) catch |err| {
            sources.items[sources.items.len - 1].@"error" = @errorName(err);
            return fixes;
        };
        return fixes;
    }

    /// GET url, by a fetcher, into cves/name. The file, recorded as a source
    /// with its sha256; or null, the source recorded with why not.
    fn fetch(u: *Update, sources: *std.ArrayList(Source), url: []const u8, comptime name: []const u8) !?Body {
        try sources.append(u.gpa, .{ .url = url, .fetched = try u.now() });
        const source = &sources.items[sources.items.len - 1];
        const fd: i32 = @intCast(try u.sys(linux.openat(linux.AT.FDCWD, cves_dir ++ "/" ++ name, .{ .ACCMODE = .RDWR, .CREAT = true, .TRUNC = true, .CLOEXEC = true, .NOFOLLOW = true }, 0o600), "open " ++ name));
        errdefer _ = linux.close(fd);
        const said = u.ask(fetcher, .{ url, fd }, 256, fetch_seconds) catch |err| {
            source.@"error" = @errorName(err);
            _ = linux.close(fd);
            return null;
        };
        if (!std.mem.eql(u8, said.status, "ok")) {
            source.@"error" = said.status;
            _ = linux.close(fd);
            return null;
        }
        var h: std.crypto.hash.sha2.Sha256 = .init(.{});
        var buf: [64 << 10]u8 = undefined;
        var size: usize = 0;
        while (true) {
            const n = try u.sys(linux.pread(fd, &buf, buf.len, @intCast(size)), "read " ++ name);
            if (n == 0) break;
            h.update(buf[0..n]);
            size += n;
        }
        const hex = std.fmt.bytesToHex(h.finalResult(), .lower);
        source.sha256 = try u.gpa.dupe(u8, &hex);
        return .{ .fd = fd, .size = size };
    }

    /// What a reader found in body, for job: the lines after its "ok", or
    /// null, with why not recorded on the last source.
    fn examine(u: *Update, sources: *std.ArrayList(Source), job: Job, body: Body) ?[]const u8 {
        const source = &sources.items[sources.items.len - 1];
        const said = u.ask(reader, .{ job, body }, max_lines, read_seconds) catch |err| {
            source.@"error" = @errorName(err);
            return null;
        };
        if (!std.mem.eql(u8, said.status, "ok")) {
            source.@"error" = said.status;
            return null;
        }
        return said.rest;
    }

    /// Run f(args..., out, parent) in a process of its own, and take what it
    /// writes to out until it exits: at most max bytes, within seconds. A
    /// child that says more or takes longer is killed, and is an error, as
    /// is one a signal ended.
    fn child(u: *Update, comptime f: anytype, args: anytype, max: usize, seconds: i64) !Exit {
        var pipe: [2]i32 = undefined;
        _ = try u.sys(linux.pipe2(&pipe, .{ .CLOEXEC = true }), "pipe");
        defer _ = linux.close(pipe[0]);
        const parent = linux.getpid();
        const rc = linux.fork();
        if (linux.errno(rc) != .SUCCESS) _ = linux.close(pipe[1]);
        if (try u.sys(rc, "fork") == 0) {
            _ = linux.close(pipe[0]);
            @call(.auto, f, args ++ .{ pipe[1], parent });
        }
        _ = linux.close(pipe[1]);
        return collect(u.gpa, @intCast(rc), pipe[0], max, seconds);
    }

    /// A CVE child's answer: it exits 0, and the first line it writes is its
    /// status, "ok" or why not, in printable ASCII; the rest is what it
    /// found. Anything else is an error.
    fn ask(u: *Update, comptime f: anytype, args: anytype, max: usize, seconds: i64) !Said {
        const e = try u.child(f, args, max, seconds);
        if (e.code != 0) return error.ChildFailed;
        const eol = std.mem.indexOfScalar(u8, e.out, '\n') orelse return error.ChildSaidNothing;
        const status = e.out[0..eol];
        if (status.len == 0 or status.len > 128) return error.ChildSaidNonsense;
        for (status) |c| if (c < 0x20 or c > 0x7e) return error.ChildSaidNonsense;
        return .{ .status = status, .rest = e.out[eol + 1 ..] };
    }

    /// The fetcher's root: copies of the resolver's files, and nothing else.
    fn netRoot(u: *Update) !void {
        try Dir.cwd().createDirPath(u.io, net_root ++ "/etc");
        try Dir.cwd().createDirPath(u.io, cves_dir);
        inline for (.{ "resolv.conf", "hosts" }) |name| {
            Dir.cwd().copyFile("/etc/" ++ name, Dir.cwd(), net_root ++ "/etc/" ++ name, u.io, .{}) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
        }
    }

    /// A system call's result, or an error with what failed in detail.
    fn sys(u: *Update, rc: usize, comptime what: []const u8) !usize {
        return sandbox.sys(rc, what) catch |err| {
            u.detail = try std.fmt.allocPrint(u.gpa, "{s}: {s}", .{ what, errnoName(sandbox.failed_errno) });
            return err;
        };
    }

    // --- build -------------------------------------------------------------
    fn buildSlot(u: *Update, arch: []const u8, new_kernel: []const u8) !void {
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
        try u.copyTree(root, "usr/share/werewolf");
        const form = std.mem.trim(u8, try u.read(meta_dir ++ "/form"), "\n");
        try u.write(root ++ meta_dir ++ "/kernel", try std.fmt.allocPrint(u.gpa, "{s}\n", .{new_kernel}));
        try u.write(root ++ meta_dir ++ "/release", try std.fmt.allocPrint(u.gpa, "{s} {s} {s} updated-on-{s}\n", .{ form, try u.now(), new_kernel, u.host }));
        try u.stripSetid(root);
        // The slot's / is this directory's owner and mode: root's, 0755,
        // whoever made it, or sshd's StrictModes refuses every key.
        _ = try u.sys(linux.fchownat(linux.AT.FDCWD, root, 0, 0, linux.AT.SYMLINK_NOFOLLOW), "chown the new root");
        _ = try u.sys(linux.fchmodat(linux.AT.FDCWD, root, 0o755), "chmod the new root");
        // As the build makes it (Makefile, EROFS_OPTS), but zstd for lzma:
        // Wolfi's mkfs.erofs has no lzma, and the kernel reads both. A slot
        // is on disk, not in RAM, so its few more megabytes cost nothing,
        // and zstd reads faster.
        try u.run(&.{ "mkfs.erofs", "-b", "4096", "-zzstd,level=19", "-C1048576", "-Eall-fragments,dedupe", work_dir ++ "/slot/root.erofs", root });

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
        // werewolf's module loader, as the build lays it in stage0.
        try Dir.cwd().copyFile("/usr/lib/werewolf/modules", Dir.cwd(), s ++ "/usr/lib/werewolf/modules", io, .{ .make_path = true, .permissions = .fromMode(0o755) });
        const kvers = try u.listDir(work_dir ++ "/kernel/lib/modules");
        if (kvers.len != 1) return error.NotOneKernel;
        const src = try std.fmt.allocPrint(u.gpa, "{s}/kernel/lib/modules/{s}", .{ work_dir, kvers[0] });
        const dst = try std.fmt.allocPrint(u.gpa, "{s}/usr/lib/modules/{s}", .{ s, kvers[0] });
        const dep = try u.read(try std.fmt.allocPrint(u.gpa, "{s}/modules.dep", .{src}));
        const order = try moduleOrder(u.gpa, dep, try u.lines(try u.read(meta_dir ++ "/modules")));
        // Decompressed, as the build does: Alpine's kernel cannot, and the
        // loader hands it each file as it is.
        for (order) |p| {
            const ko = try gunzip(u.gpa, try u.read(try std.fmt.allocPrint(u.gpa, "{s}/{s}", .{ src, p })));
            const out = try std.fmt.allocPrint(u.gpa, "{s}/{s}", .{ dst, withoutGz(p) });
            try Dir.cwd().createDirPath(io, parentDir(out));
            try u.write(out, ko);
        }
        const list = try moduleList(u.gpa, order, try u.read(meta_dir ++ "/module-params"));
        try u.write(try std.fmt.allocPrint(u.gpa, "{s}/werewolf.modules", .{dst}), list);
        try u.writeCpio(s, work_dir ++ "/stage0.cpio");
        try u.run(&.{ "zstd", "-19", "-q", "-f", "-o", work_dir ++ "/slot/initramfs.zst", work_dir ++ "/stage0.cpio" });
    }

    // --- install -----------------------------------------------------------
    // root.erofs beside this slot's on the victim's filesystem; the kernel and
    // stage0 in /boot/werewolf, beside GRUB's directory. Both mounted apart
    // and writable, since /victim is read-only.
    fn install(u: *Update, build: []const u8) !void {
        if (u.cmd.grubenv.len == 0) return u.installEsp(build);
        const io = u.io;
        u.step = "install";
        const v = work_dir ++ "/mnt/v";
        const g = work_dir ++ "/mnt/g";
        try Dir.cwd().createDirPath(io, v);
        try Dir.cwd().createDirPath(io, g);
        try u.mountUuid(uuidOf(u.cmd.victim), v, null);
        defer _ = linux.umount2(v, 0);
        try u.mountUuid(uuidOf(u.cmd.grubenv), g, null);
        defer _ = linux.umount2(g, 0);

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
        linux.sync();
        try u.write(state_dir ++ "/attempt", try std.fmt.allocPrint(u.gpa, "{s} {s}\n", .{ u.other, build }));
        const entry = try std.fmt.allocPrint(u.gpa, "werewolf-{s}", .{u.other});
        try u.run(&.{ "/usr/lib/werewolf/grubenv", try std.fmt.allocPrint(u.gpa, "{s}{s}", .{ g, gpath }), "next_entry", entry });
    }

    /// The other slot onto werewolf's own disk (design/native-boot.md): its
    /// root.erofs to the ext4 partition, as install does; its kernel and
    /// stage0 to the EFI partition; and a loader entry with one try, which
    /// systemd-boot boots next because it is the newest. commit removes the
    /// count once the slot is healthy; if it is not, systemd-boot has spent
    /// the try and boots the slot this one replaced.
    fn installEsp(u: *Update, build: []const u8) !void {
        const io = u.io;
        u.step = "install";
        const v = work_dir ++ "/mnt/v";
        const e = work_dir ++ "/mnt/e";
        try Dir.cwd().createDirPath(io, v);
        try Dir.cwd().createDirPath(io, e);
        try u.mountUuid(uuidOf(u.cmd.victim), v, null);
        defer _ = linux.umount2(v, 0);
        try u.mountUuid(u.cmd.esp, e, "vfat");
        defer _ = linux.umount2(e, 0);

        const rdir = try std.fmt.allocPrint(u.gpa, "{s}{s}/{s}", .{ v, pathOf(u.cmd.victim), u.other });
        const kdir = try std.fmt.allocPrint(u.gpa, "{s}/werewolf/{s}", .{ e, u.other });
        const entries = e ++ "/loader/entries";
        try Dir.cwd().createDirPath(io, rdir);
        try Dir.cwd().createDirPath(io, kdir);
        try Dir.cwd().createDirPath(io, entries);

        // The other slot's entry goes first: from here until the new one is
        // written, nothing boots the other slot while its files change.
        for (try u.listDir(entries)) |name| {
            if (isEntryOf(name, u.other)) try Dir.cwd().deleteFile(io, try std.fmt.allocPrint(u.gpa, "{s}/{s}", .{ entries, name }));
        }
        try u.replace(work_dir ++ "/slot/root.erofs", try std.fmt.allocPrint(u.gpa, "{s}/root.erofs", .{rdir}));
        for (&[_][]const u8{ "vmlinuz", "initramfs.zst" }) |f| {
            try u.replace(try std.fmt.allocPrint(u.gpa, "{s}/slot/{s}", .{ work_dir, f }), try std.fmt.allocPrint(u.gpa, "{s}/{s}", .{ kdir, f }));
        }
        linux.sync();

        const version = try compactTime(u.gpa, @intCast(@divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s)));
        const options = try withSlot(u.gpa, try u.read("/proc/cmdline"), try u.read(meta_dir ++ "/cmdline"), u.other);
        const entry = try loaderEntry(u.gpa, u.other, version, options);
        const tmp = try std.fmt.allocPrint(u.gpa, "{s}/werewolf-{s}.tmp", .{ entries, u.other });
        try u.write(tmp, entry);
        try Dir.cwd().rename(tmp, Dir.cwd(), try std.fmt.allocPrint(u.gpa, "{s}/werewolf-{s}+1.conf", .{ entries, u.other }), io);
        linux.sync();
        try u.write(state_dir ++ "/attempt", try std.fmt.allocPrint(u.gpa, "{s} {s}\n", .{ u.other, build }));
    }

    /// src to dst, through a temporary name, so dst is whole or absent.
    fn replace(u: *Update, src: []const u8, dst: []const u8) !void {
        const tmp = try std.fmt.allocPrint(u.gpa, "{s}.new", .{dst});
        try Dir.cwd().copyFile(src, Dir.cwd(), tmp, u.io, .{});
        try Dir.cwd().rename(tmp, Dir.cwd(), dst, u.io);
    }

    // --- helpers -----------------------------------------------------------
    /// Install packages into a new root, through a cache on /data named for
    /// the root (root, kernel, stage0), so a check that finds nothing new
    /// downloads indexes and nothing else. Each root has a cache of its own,
    /// so cleaning one keeps nothing another needs.
    ///
    /// Root does not touch the network. apk's network half runs first, as
    /// _update (apkFetcher): the indexes, fresh every time, since apk would
    /// otherwise trust a cached one for hours, and every package the new
    /// root takes, into the cache. Root takes the cache back and installs
    /// from it with --no-network, checking every signature and hash against
    /// its own keys, as apk always does. Then it prunes the cache to the
    /// packages the new root took, so it holds one copy of the image, no
    /// more.
    fn apkAdd(u: *Update, root: []const u8, arch: []const u8, source: []const []const u8, packages: []const []const u8) !void {
        const name = std.fs.path.basename(root);
        const cache = try std.fmt.allocPrintSentinel(u.gpa, "{s}/{s}", .{ cache_dir, name }, 0);
        const scratch = try std.fmt.allocPrintSentinel(u.gpa, "{s}/apk-{s}", .{ work_dir, name }, 0);
        try Dir.cwd().createDirPath(u.io, cache);
        Dir.cwd().deleteTree(u.io, scratch) catch {};
        try Dir.cwd().createDirPath(u.io, scratch);
        _ = try u.sys(linux.fchownat(linux.AT.FDCWD, scratch, update_id, update_id, linux.AT.SYMLINK_NOFOLLOW), "chown scratch");

        // The indexes, then the packages: `cache download` fetches no index.
        const world = try std.mem.join(u.gpa, "\n", packages);
        for ([_][]const []const u8{ &.{"update"}, &.{ "cache", "download" } }) |applet| {
            var fetch_argv: std.ArrayList(?[*:0]const u8) = .empty;
            for ([_][]const u8{ "/usr/bin/apk", "--root", scratch, "--arch", arch, "--cache-dir", cache }) |arg| try fetch_argv.append(u.gpa, try u.gpa.dupeSentinel(u8, arg, 0));
            for (source) |arg| try fetch_argv.append(u.gpa, try u.gpa.dupeSentinel(u8, arg, 0));
            for ([_][]const u8{ "--quiet", "--no-progress" }) |arg| try fetch_argv.append(u.gpa, try u.gpa.dupeSentinel(u8, arg, 0));
            for (applet) |arg| try fetch_argv.append(u.gpa, try u.gpa.dupeSentinel(u8, arg, 0));
            const argv_z = try fetch_argv.toOwnedSliceSentinel(u.gpa, null);
            _ = try u.sys(linux.fchownat(linux.AT.FDCWD, cache, update_id, update_id, linux.AT.SYMLINK_NOFOLLOW), "chown cache");
            const fetched = u.child(apkFetcher, .{ argv_z, world, cache, scratch }, 64 << 10, apk_seconds);
            try u.reclaim(cache);
            const e = fetched catch |err| {
                u.detail = "apk, as _update";
                return err;
            };
            if (e.code != 0) {
                u.detail = try std.fmt.allocPrint(u.gpa, "apk, as _update: {s}", .{std.mem.trim(u8, e.out[0..@min(e.out.len, 400)], " \n")});
                return error.CommandFailed;
            }
        }
        try Dir.cwd().deleteTree(u.io, scratch);

        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(u.gpa, &.{ "apk", "--root", root, "--arch", arch, "--cache-dir", cache, "--no-network" });
        try argv.appendSlice(u.gpa, source);
        try argv.appendSlice(u.gpa, &.{ "--no-scripts", "--quiet", "--no-progress", "add", "--initdb" });
        try argv.appendSlice(u.gpa, packages);
        try u.run(argv.items);
        try u.prune(cache, root);
    }

    /// The cache, down to the packages root has installed, and the indexes.
    /// Not apk's `cache clean`: without --purge it keeps any version an
    /// index still lists, which for Wolfi is all of them, and with it,
    /// where the root is on a disk, it deletes every package.
    fn prune(u: *Update, cache: []const u8, root: []const u8) !void {
        const installed = try parseInstalled(u.gpa, try u.read(try std.fmt.allocPrint(u.gpa, "{s}/lib/apk/db/installed", .{root})));
        var d = try Dir.cwd().openDir(u.io, cache, .{ .iterate = true, .follow_symlinks = false });
        defer d.close(u.io);
        var old: std.ArrayList([]const u8) = .empty;
        var it = d.iterate();
        while (try it.next(u.io)) |e| {
            if (std.mem.endsWith(u8, e.name, ".apk") and !isCachedOf(e.name, installed)) try old.append(u.gpa, try u.gpa.dupe(u8, e.name));
        }
        for (old.items) |name| try d.deleteFile(u.io, name);
    }

    /// The cache, root's again once the fetcher is gone: each entry a regular
    /// file of a name apk gives one, owned by root. Anything else it left is
    /// removed unread.
    fn reclaim(u: *Update, cache: [:0]const u8) !void {
        _ = try u.sys(linux.fchownat(linux.AT.FDCWD, cache, 0, 0, linux.AT.SYMLINK_NOFOLLOW), "chown cache");
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
            _ = try u.sys(linux.fchownat(d.handle, file, 0, 0, linux.AT.SYMLINK_NOFOLLOW), "chown cached file");
        }
        for (strays.items) |stray| try d.deleteTree(u.io, stray);
    }

    /// The filesystem with uuid on dir. The mount helper probes only Linux
    /// filesystems, so FAT is named.
    fn mountUuid(u: *Update, uuid: []const u8, dir: []const u8, kind: ?[]const u8) !void {
        const dev = std.mem.trim(u8, try u.output(&.{ "blkid", "-c", "/dev/null", "-l", "-o", "device", "-t", try std.fmt.allocPrint(u.gpa, "UUID={s}", .{uuid}) }), "\n");
        if (kind) |k| {
            try u.run(&.{ "/usr/lib/werewolf/mount", "-t", k, "-o", "nosuid,nodev,noexec", dev, dir });
        } else {
            try u.run(&.{ "/usr/lib/werewolf/mount", "-o", "nosuid,nodev,noexec", dev, dir });
        }
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
    /// path, a directory, and everything under it, from this root into
    /// root: the build record, whose etc/ holds the image's accounts.
    fn copyTree(u: *Update, root: []const u8, path: []const u8) !void {
        var d = Dir.cwd().openDir(u.io, try std.fmt.allocPrint(u.gpa, "/{s}", .{path}), .{ .iterate = true }) catch |err| {
            u.detail = path;
            return err;
        };
        defer d.close(u.io);
        var w = try d.walk(u.gpa);
        defer w.deinit();
        while (try w.next(u.io)) |e| {
            if (e.kind == .directory) continue;
            try u.copyInto(root, try std.fmt.allocPrint(u.gpa, "{s}/{s}", .{ path, e.path }));
        }
    }

    /// path, from this root into root. A symlink stays a symlink: a form's
    /// `run` that links to a binary must not become a copy of the old one.
    /// A .mountpoint is the empty file that keeps a mount point's directory
    /// in the image; here what is mounted there hides it, so it is made.
    fn copyInto(u: *Update, root: []const u8, path: []const u8) !void {
        errdefer u.detail = path;
        const src = try std.fmt.allocPrint(u.gpa, "/{s}", .{path});
        const dst = try std.fmt.allocPrint(u.gpa, "{s}/{s}", .{ root, path });
        if (std.mem.eql(u8, std.fs.path.basename(path), ".mountpoint")) {
            try Dir.cwd().createDirPath(u.io, parentDir(dst));
            return Dir.cwd().writeFile(u.io, .{ .sub_path = dst, .data = "" });
        }
        var buf: [Dir.max_path_bytes]u8 = undefined;
        const n = Dir.cwd().readLink(u.io, src, &buf) catch |err| switch (err) {
            error.NotLink => return Dir.cwd().copyFile(src, Dir.cwd(), dst, u.io, .{ .make_path = true }),
            else => return err,
        };
        try Dir.cwd().createDirPath(u.io, parentDir(dst));
        Dir.cwd().deleteFile(u.io, dst) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        try Dir.cwd().symLink(u.io, buf[0..n], dst, .{});
    }

    /// A newc cpio of everything under root, as the kernel unpacks an
    /// initramfs: owned by root, children after their directory. The type
    /// and device numbers come from statx, since the stage0 root has device
    /// nodes (/dev/console, which the kernel opens before anything mounts
    /// /dev) as well as files, directories and links.
    fn writeCpio(u: *Update, root: []const u8, out_path: []const u8) !void {
        var out: Io.Writer.Allocating = .init(u.gpa);
        var d = try Dir.cwd().openDir(u.io, root, .{ .iterate = true });
        defer d.close(u.io);
        var w = try d.walk(u.gpa);
        var ino: u32 = 1;
        var link_buf: [Dir.max_path_bytes]u8 = undefined;
        while (try w.next(u.io)) |e| : (ino += 1) {
            const path = try std.fmt.allocPrintSentinel(u.gpa, "{s}/{s}", .{ root, e.path }, 0);
            var st: linux.Statx = undefined;
            const rc = linux.statx(linux.AT.FDCWD, path, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .MODE = true }, &st);
            if (linux.errno(rc) != .SUCCESS) return error.StatFailed;
            const node: Node = .{ .name = e.path, .mode = st.mode, .ino = ino, .rdev_major = st.rdev_major, .rdev_minor = st.rdev_minor };
            const data: []const u8 = switch (st.mode & linux.S.IFMT) {
                linux.S.IFREG => try e.dir.readFileAlloc(u.io, e.basename, u.gpa, .limited(max_read)),
                linux.S.IFLNK => link_buf[0..try e.dir.readLink(u.io, e.basename, &link_buf)],
                linux.S.IFDIR, linux.S.IFCHR, linux.S.IFBLK => "",
                else => return error.UnexpectedFileKind,
            };
            try cpioEntry(&out.writer, node, data);
        }
        try cpioEntry(&out.writer, .{ .name = "TRAILER!!!", .mode = 0, .ino = 0 }, "");
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

// --- the CVE children ----------------------------------------------------------

const Body = struct { fd: i32, size: usize };
const Exit = struct { code: u8, out: []const u8 };
const Said = struct { status: []const u8, rest: []const u8 };
const Job = union(enum) {
    secdb: []const OriginChange,
    kernel: struct { branch: []const u8, old: [3]u32, new: [3]u32 },
};

/// As _update, rooted in net_root with only the resolver's files to read,
/// TCP only to ports 443 and 53, and no file bigger than max_read: GET url
/// into body, then say "ok", or why not.
fn fetcher(url: []const u8, body: i32, out: i32, parent: linux.pid_t) noreturn {
    sandbox.tieTo(parent);
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const status = fetchInto(arena.allocator(), url, body, out) catch |err| whyNot(arena.allocator(), err);
    say(out, 0, status, "");
}

fn fetchInto(gpa: Allocator, url: []const u8, body: i32, out: i32) ![]const u8 {
    try sandbox.closeAllBut(&.{ body, out });
    var threaded: Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    // The CA bundle, read before the chroot hides it.
    const now = Io.Clock.real.now(io);
    try client.ca_bundle.rescan(gpa, io, now);
    client.now = now;
    try sandbox.limit(.FSIZE, max_read);
    try sandbox.dropTo(update_id, net_root);
    const etc: i32 = @intCast(try sandbox.sys(linux.openat(linux.AT.FDCWD, "/etc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0), "open /etc"));
    try sandbox.landlock(&.{.{ .fd = etc, .access = sandbox.read_file }}, &.{ 443, 53 });
    _ = linux.close(etc);
    // What the request takes, as traced: the resolver's files, DNS over
    // UDP (bound to port 0) or TCP, TLS over TCP, and the body to the file;
    // nothing else is written anywhere but the status pipe and /dev/null.
    var f: sandbox.Filter = .{};
    f.allowArg("socket", 0, linux.AF.INET);
    f.allowArg("socket", 0, linux.AF.INET6);
    f.allow("bind");
    f.allow("connect");
    f.allow("getsockname");
    f.allow("sendmsg");
    f.allow("sendmmsg");
    f.allow("recvmsg");
    f.allow("openat");
    f.allow("preadv");
    f.allowArg("writev", 0, @intCast(body));
    f.allowArg("write", 0, @intCast(out));
    f.allowArg("write", 0, 2);
    f.allow("close");
    f.allow("poll");
    f.allow("ppoll");
    f.allow("mmap");
    f.allow("munmap");
    f.allow("mremap");
    f.allow("getrandom");
    f.allow("clock_gettime");
    f.allow("exit_group");
    try f.install();

    var buf: [64 << 10]u8 = undefined;
    const file: Io.File = .{ .handle = body, .flags = .{ .nonblocking = false } };
    var w = file.writerStreaming(io, &buf);
    const res = try client.fetch(.{ .location = .{ .url = url }, .response_writer = &w.interface });
    try w.interface.flush();
    if (res.status != .ok) return std.enums.tagName(std.http.Status, res.status) orelse "HttpStatus";
    return "ok";
}

/// As _update in the empty /var/empty, with no network, no files, and at
/// most reader_memory of memory: parse body for job, and say "ok" and a
/// line per CVE, or why not.
fn reader(job: Job, body: Body, out: i32, parent: linux.pid_t) noreturn {
    sandbox.tieTo(parent);
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const gpa = arena.allocator();
    var lines: Io.Writer.Allocating = .init(gpa);
    readInto(gpa, job, body, out, &lines.writer) catch |err| say(out, 0, whyNot(gpa, err), "");
    say(out, 0, "ok", lines.written());
}

fn readInto(gpa: Allocator, job: Job, body: Body, out: i32, w: *Io.Writer) !void {
    try sandbox.closeAllBut(&.{ body.fd, out });
    try sandbox.limit(.AS, reader_memory);
    try sandbox.dropTo(update_id, "/var/empty");
    try sandbox.landlock(&.{}, &.{});
    var f: sandbox.Filter = .{};
    f.allowArg("pread64", 0, @intCast(body.fd));
    f.allowArg("write", 0, @intCast(out));
    f.allow("mmap");
    f.allow("munmap");
    f.allow("mremap");
    f.allow("exit_group");
    try f.install();

    const data = try gpa.alloc(u8, body.size);
    var got: usize = 0;
    while (got < data.len) {
        const n = try sandbox.sys(linux.pread(body.fd, data[got..].ptr, data.len - got, @intCast(got)), "pread");
        if (n == 0) return error.ShortRead;
        got += n;
    }
    switch (job) {
        .secdb => |origins| try secdbLines(gpa, data, origins, w),
        .kernel => |k| try kernelLines(gpa, data, k.branch, k.old, k.new, w),
    }
}

/// As _update, apk's network half: argv, run with no environment, in
/// scratch, a root of its own holding only world and an empty database. It
/// reads the image (/usr, /etc and the resolver's file), runs nothing but
/// apk, writes only beneath cache and scratch, connects over TCP only to
/// ports 443 and 53, and starts no process. What it says goes to out.
fn apkFetcher(argv: [:null]const ?[*:0]const u8, world: []const u8, cache: [:0]const u8, scratch: [:0]const u8, out: i32, parent: linux.pid_t) noreturn {
    sandbox.tieTo(parent);
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    apkExec(argv, world, cache, scratch, out) catch |err| say(out, 1, whyNot(arena.allocator(), err), "");
}

fn apkExec(argv: [:null]const ?[*:0]const u8, world: []const u8, cache: [:0]const u8, scratch: [:0]const u8, out: i32) !noreturn {
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
        rules[n] = .{ .fd = @intCast(try sandbox.sys(fd, "open what apk may reach")), .access = r[2] };
        n += 1;
    }
    const root: i32 = @intCast(try sandbox.sys(linux.openat(linux.AT.FDCWD, scratch, dir, 0), "open scratch"));
    rules[n] = .{ .fd = root, .access = sandbox.own_dir };
    n += 1;
    try sandbox.dropTo(update_id, null);
    for ([_][:0]const u8{ "etc", "etc/apk", "lib", "lib/apk", "lib/apk/db" }) |d| {
        const rc = linux.mkdirat(root, d, 0o755);
        if (linux.errno(rc) != .EXIST) _ = try sandbox.sys(rc, "mkdir in scratch");
    }
    try writeAt(root, "etc/apk/world", world);
    try writeAt(root, "lib/apk/db/installed", "");
    try sandbox.landlock(rules[0..n], &.{ 443, 53 });

    // What apk 2.14 calls to fetch, as traced, under glibc on either
    // architecture; the names one lacks are skipped. It tries to mount /proc
    // in its root, which is refused as for any unprivileged process, and
    // carries on.
    var f: sandbox.Filter = .{};
    inline for (.{
        "read",            "readv",           "pread64",      "write",        "writev",          "pwrite64",
        "openat",          "open",            "close",        "fstat",        "newfstatat",      "stat",
        "lstat",           "statx",           "fstatfs",      "statfs",       "lseek",           "getdents64",
        "faccessat",       "faccessat2",      "access",       "readlinkat",   "readlink",        "mkdirat",
        "mkdir",           "renameat",        "renameat2",    "rename",       "unlinkat",        "unlink",
        "utimensat",       "ftruncate",       "fsync",        "fdatasync",    "fcntl",           "flock",
        "dup",             "dup2",            "dup3",         "umask",        "mmap",            "munmap",
        "mprotect",        "mremap",          "madvise",      "brk",          "futex",           "getpid",
        "gettid",          "getuid",          "geteuid",      "getgid",       "getegid",         "connect",
        "getsockopt",      "setsockopt",      "getsockname",  "getpeername",  "sendto",          "recvfrom",
        "sendmsg",         "recvmsg",         "sendmmsg",     "recvmmsg",     "shutdown",        "poll",
        "ppoll",           "pselect6",        "select",       "rt_sigaction", "rt_sigprocmask",  "rt_sigreturn",
        "getrandom",       "clock_gettime",   "gettimeofday", "nanosleep",    "clock_nanosleep", "set_tid_address",
        "set_robust_list", "rseq",            "prlimit64",    "uname",        "execve",          "exit_group",
        "exit",            "restart_syscall",
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
    const fd: i32 = @intCast(try sandbox.sys(linux.openat(dir, name, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true, .NOFOLLOW = true }, 0o644), "create in scratch"));
    defer _ = linux.close(fd);
    var off: usize = 0;
    while (off < data.len) off += try sandbox.sys(linux.write(fd, data[off..].ptr, data.len - off), "write in scratch");
}

/// Whether file, a package in apk's cache (NAME-VERSION.HASH.apk), is one
/// of pkgs.
fn isCachedOf(file: []const u8, pkgs: []const Package) bool {
    const stem = file[0 .. std.mem.lastIndexOfScalar(u8, file[0 .. file.len - ".apk".len], '.') orelse return false];
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

/// A child's error, as its status line: the error, or for a system call,
/// which and the kernel's reason.
fn whyNot(gpa: Allocator, err: anyerror) []const u8 {
    if (err != error.SystemCall) return @errorName(err);
    return std.fmt.allocPrint(gpa, "{s}: {s}", .{ sandbox.failed, errnoName(sandbox.failed_errno) }) catch "SystemCall";
}

/// A child's last words, and its end.
fn say(out: i32, code: u8, status: []const u8, rest: []const u8) noreturn {
    for ([_][]const u8{ status, "\n", rest }) |data| {
        var off: usize = 0;
        while (off < data.len) {
            const n = linux.write(out, data[off..].ptr, data.len - off);
            if (linux.errno(n) != .SUCCESS) linux.exit_group(1);
            off += n;
        }
    }
    // Straight out: the runtime's cleanup would make calls the filter kills.
    linux.exit_group(code);
}

/// What child pid writes to in, and its exit code: at most max bytes,
/// within seconds. It is killed if it says more, or takes longer.
fn collect(gpa: Allocator, pid: linux.pid_t, in: i32, max: usize, seconds: i64) !Exit {
    var reaped = false;
    defer if (!reaped) {
        _ = linux.kill(pid, .KILL);
        var status: i32 = 0;
        while (linux.errno(linux.wait4(pid, &status, 0, null)) == .INTR) {}
    };
    const buf = try gpa.alloc(u8, max);
    const deadline = nowMs() + seconds * std.time.ms_per_s;
    var got: usize = 0;
    while (true) {
        const left = deadline - nowMs();
        if (left <= 0) return error.Timeout;
        var pfd = [1]linux.pollfd{.{ .fd = in, .events = linux.POLL.IN, .revents = 0 }};
        const ready = linux.poll(&pfd, 1, @intCast(@min(left, std.time.ms_per_s)));
        if (linux.errno(ready) == .INTR or ready == 0) continue;
        if (got == max) return error.ChildSaidTooMuch;
        const n = linux.read(in, buf[got..].ptr, max - got);
        switch (linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        if (n == 0) break;
        got += n;
    }
    // Its end of the pipe is closed: it has until the deadline to exit.
    while (nowMs() < deadline) {
        var status: i32 = 0;
        const rc = linux.wait4(pid, &status, linux.W.NOHANG, null);
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS) return error.WaitFailed;
        if (rc == 0) {
            const tick: linux.timespec = .{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
            _ = linux.nanosleep(&tick, null);
            continue;
        }
        reaped = true;
        const s: u32 = @bitCast(status);
        if (!linux.W.IFEXITED(s)) return error.ChildKilled;
        return .{ .code = linux.W.EXITSTATUS(s), .out = buf[0..got] };
    }
    return error.Timeout;
}

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.BOOTTIME, &ts);
    return ts.sec * std.time.ms_per_s + @divFloor(ts.nsec, std.time.ns_per_ms);
}

fn errnoName(e: linux.E) []const u8 {
    return std.enums.tagName(linux.E, e) orelse "unknown";
}

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

const Cmdline = struct { victim: []const u8 = "", slot: []const u8 = "", grubenv: []const u8 = "", esp: []const u8 = "" };

fn parseCmdline(text: []const u8) Cmdline {
    var c: Cmdline = .{};
    var it = std.mem.tokenizeAny(u8, text, " \n");
    while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "werewolf.victim=")) c.victim = arg["werewolf.victim=".len..];
        if (std.mem.startsWith(u8, arg, "werewolf.slot=")) c.slot = arg["werewolf.slot=".len..];
        if (std.mem.startsWith(u8, arg, "werewolf.grubenv=")) c.grubenv = arg["werewolf.grubenv=".len..];
        if (std.mem.startsWith(u8, arg, "werewolf.esp=")) c.esp = arg["werewolf.esp=".len..];
    }
    return c;
}

/// This boot's command line, for the other slot: what the machine was
/// booted with (its console, werewolf.mac) carries over, but the image's
/// own arguments (/usr/share/werewolf/cmdline, which the build writes from
/// the form's allowances) replace any of the same name, so an entry edited
/// to loosen one does not outlive the next update, and one an update adds
/// reaches machines installed before it. werewolf.slot is the other slot's;
/// initrd= and BOOT_IMAGE= belong to the loader that wrote them, and are
/// dropped.
fn withSlot(gpa: Allocator, cmdline: []const u8, image: []const u8, slot: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeAny(u8, cmdline, " \n");
    next: while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "werewolf.slot=") or std.mem.startsWith(u8, arg, "initrd=") or
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
    return arg[0 .. std.mem.indexOfScalar(u8, arg, '=') orelse arg.len];
}

/// A systemd-boot entry (the Boot Loader Specification's type 1) for slot.
/// version orders the slots, newest first; sort-key keeps them together.
fn loaderEntry(gpa: Allocator, slot: []const u8, version: []const u8, options: []const u8) ![]const u8 {
    return std.fmt.allocPrint(gpa,
        \\title werewolf {s}
        \\sort-key werewolf
        \\version {s}
        \\linux /werewolf/{s}/vmlinuz
        \\initrd /werewolf/{s}/initramfs.zst
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

/// secs as a version systemd-boot orders by time: 20261006T120000Z.
fn compactTime(gpa: Allocator, secs: u64) ![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.allocPrint(gpa, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
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

// apk's version order, as apk-tools 2.14's src/version.c defines it, so no
// apk need run to compare two: {digit}{.digit}...{letter}{_suffix{#}}...{-r#}.
// A version is read as tokens, each kind known from the character that ends
// the last, in an order that only rises but for a few steps back.
const Tok = enum(i8) { invalid = -1, digit_or_zero, digit, letter, suffix, suffix_no, revision_no, end };

const VersionReader = struct {
    s: []const u8,
    t: Tok = .digit,

    const pre_suffixes = [_][]const u8{ "alpha", "beta", "pre", "rc" };
    const post_suffixes = [_][]const u8{ "cvs", "svn", "git", "hg", "p" };

    /// The kind of the next token, from what separates it from the last.
    fn next(r: *VersionReader) void {
        const s = r.s;
        var n: Tok = .invalid;
        if (s.len == 0 or s[0] == 0) {
            n = .end;
        } else if ((r.t == .digit or r.t == .digit_or_zero) and std.ascii.isLower(s[0])) {
            n = .letter;
        } else if (r.t == .letter and std.ascii.isDigit(s[0])) {
            n = .digit;
        } else if (r.t == .suffix and std.ascii.isDigit(s[0])) {
            n = .suffix_no;
        } else {
            switch (s[0]) {
                '.' => n = .digit_or_zero,
                '_' => n = .suffix,
                '-' => if (s.len > 1 and s[1] == 'r') {
                    n = .revision_no;
                    r.s = r.s[1..];
                },
                else => {},
            }
            r.s = r.s[1..];
        }
        if (@backingInt(n) < @backingInt(r.t) and !((n == .digit_or_zero and r.t == .digit) or
            (n == .suffix and r.t == .suffix_no) or (n == .digit and r.t == .letter))) n = .invalid;
        r.t = n;
    }

    /// The value of the token of kind r.t, and past it.
    fn token(r: *VersionReader) i64 {
        const s = r.s;
        if (s.len == 0) {
            r.t = .end;
            return 0;
        }
        var i: usize = 0;
        var v: i64 = 0;
        var nt: Tok = .invalid;
        switch (r.t) {
            .digit_or_zero, .digit, .suffix_no, .revision_no => if (r.t == .digit_or_zero and s[0] == '0') {
                // Leading zeros: 1.01 is older than 1.1.
                while (i + 1 < s.len and s[i + 1] == '0') i += 1;
                nt = .digit;
                v = -@as(i64, @intCast(i));
            } else {
                while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) v = v * 10 + (s[i] - '0');
                if (i >= 18) return r.fail();
            },
            .letter => {
                v = s[0];
                i = 1;
            },
            .suffix => suffix: {
                // Before the release (alpha, -4, to rc, -1), or after it.
                for (pre_suffixes, 0..) |p, k| if (std.mem.startsWith(u8, s, p)) {
                    i = p.len;
                    v = @as(i64, @intCast(k)) - pre_suffixes.len;
                    break :suffix;
                };
                for (post_suffixes, 0..) |p, k| if (std.mem.startsWith(u8, s, p)) {
                    i = p.len;
                    v = @intCast(k);
                    break :suffix;
                };
                return r.fail();
            },
            else => return r.fail(),
        }
        r.s = s[i..];
        if (r.s.len == 0) {
            r.t = .end;
        } else if (nt != .invalid) {
            r.t = nt;
        } else {
            r.next();
        }
        return v;
    }

    fn fail(r: *VersionReader) i64 {
        r.t = .invalid;
        return -1;
    }
};

/// a against b, as `apk version -t a b` orders them.
fn apkOrder(a: []const u8, b: []const u8) std.math.Order {
    var x: VersionReader = .{ .s = a };
    var y: VersionReader = .{ .s = b };
    var xv: i64 = 0;
    var yv: i64 = 0;
    while (x.t == y.t and x.t != .end and x.t != .invalid and xv == yv) {
        xv = x.token();
        yv = y.token();
    }
    if (xv != yv) return std.math.order(xv, yv);
    if (x.t == y.t) return .eq;
    // Equal as far as one goes: the longer is newer, unless what it goes
    // on with is a pre-release suffix.
    var xs = x;
    var ys = y;
    if (x.t == .suffix and xs.token() < 0) return .lt;
    if (y.t == .suffix and ys.token() < 0) return .gt;
    return std.math.order(@backingInt(y.t), @backingInt(x.t));
}

/// Whether apk would take s as a version.
fn validVersion(s: []const u8) bool {
    var r: VersionReader = .{ .s = s };
    while (r.t != .end and r.t != .invalid) _ = r.token();
    return r.t == .end;
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

/// Wolfi's security.json, as the reader's lines, "INDEX FIXED CVE": a CVE
/// fixed at version FIXED, in the window of origins[INDEX].
fn secdbLines(gpa: Allocator, json: []const u8, origins: []const OriginChange, w: *Io.Writer) !void {
    const db = try std.json.parseFromSliceLeaky(SecDb, gpa, json, .{ .ignore_unknown_fields = true });
    for (origins, 0..) |o, i| {
        const base = streamBase(o.origin);
        for (db.packages) |p| {
            if (!std.mem.eql(u8, p.pkg.name, o.origin) and !std.mem.eql(u8, p.pkg.name, base)) continue;
            const secfixes = p.pkg.secfixes orelse continue;
            var it = secfixes.map.iterator();
            while (it.next()) |e| {
                if (!inWindow(e.key_ptr.*, o.from, o.to)) continue;
                for (e.value_ptr.*) |id| {
                    if (validCve(id)) try w.print("{d} {s} {s}\n", .{ i, e.key_ptr.*, id });
                }
            }
        }
    }
}

/// The reader's lines from secdbLines, checked: each names an origin asked
/// about, a version in its window, and a CVE id. A reader that sends any
/// other line is not believed at all.
fn packageFixes(gpa: Allocator, text: []const u8, origins: []const OriginChange) ![]const PackageFix {
    const cves = try gpa.alloc(std.ArrayList([]const u8), origins.len);
    @memset(cves, .empty);
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ' ');
        const i = std.fmt.parseUnsigned(usize, f.next().?, 10) catch return error.BadLine;
        const fixed = f.next() orelse return error.BadLine;
        const id = f.next() orelse return error.BadLine;
        if (f.next() != null or i >= origins.len or !validCve(id)) return error.BadLine;
        if (!inWindow(fixed, origins[i].from, origins[i].to)) return error.BadLine;
        try appendUnique(gpa, &cves[i], id);
    }
    var fixes: std.ArrayList(PackageFix) = .empty;
    for (origins, cves) |o, c| {
        if (c.items.len == 0) continue;
        std.mem.sort([]const u8, c.items, {}, lessString);
        try fixes.append(gpa, .{ .origin = o.origin, .from = o.from, .to = o.to, .cves = c.items });
    }
    return fixes.items;
}

/// Whether fixed is a version newer than from and no newer than to. "0",
/// never affected, is in no window.
fn inWindow(fixed: []const u8, from: []const u8, to: []const u8) bool {
    return validVersion(fixed) and !std.mem.eql(u8, fixed, "0") and
        apkOrder(fixed, from) == .gt and apkOrder(fixed, to) != .gt;
}

/// CVE-2026-52988: the year, and four digits or more.
fn validCve(id: []const u8) bool {
    if (id.len < 13 or id.len > 32 or !std.mem.startsWith(u8, id, "CVE-") or id[8] != '-') return false;
    for (id[4..8]) |c| if (!std.ascii.isDigit(c)) return false;
    for (id[9..]) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// The kernel CNA's tarball, as the reader's lines, "CVE FIXED TITLE": each
/// CVE fixed on branch in (old, new], with its title made one line.
fn kernelLines(gpa: Allocator, tarball_gz: []const u8, branch: []const u8, old: [3]u32, new: [3]u32, w: *Io.Writer) !void {
    var in: Io.Reader = .fixed(tarball_gz);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var gz: std.compress.flate.Decompress = .init(&in, .gzip, &window);
    var name_buf: [Dir.max_path_bytes]u8 = undefined;
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&gz.reader, .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf });
    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();
    while (try it.next()) |file| {
        if (file.kind != .file or !isKernelRecord(file.name)) continue;
        _ = scratch.reset(.retain_capacity);
        const s = scratch.allocator();
        var body: Io.Writer.Allocating = .init(s);
        try it.streamRemaining(file, &body.writer);
        const rec = std.json.parseFromSliceLeaky(KernelRecord, s, body.written(), .{ .ignore_unknown_fields = true }) catch continue;
        const fixed = kernelFixedIn(rec, branch, old, new) orelse continue;
        if (!validCve(rec.cveMetadata.cveId)) continue;
        try w.print("{s} {s} {s}\n", .{ rec.cveMetadata.cveId, fixed, try oneLine(s, rec.containers.cna.title) });
    }
}

/// s with control characters as spaces, and cut, on a character's
/// boundary, to max_title bytes.
fn oneLine(gpa: Allocator, s: []const u8) ![]const u8 {
    var end = @min(s.len, max_title);
    if (end < s.len) while (end > 0 and s[end] & 0xc0 == 0x80) : (end -= 1) {};
    const out = try gpa.dupe(u8, s[0..end]);
    for (out) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = ' ';
    };
    return out;
}

/// The reader's lines from kernelLines, checked: a CVE id, a version on
/// new's branch in (old, new], and a title of printable UTF-8. A reader
/// that sends any other line is not believed at all.
fn kernelFixes(gpa: Allocator, text: []const u8, old: [3]u32, new: [3]u32) ![]const KernelFix {
    var out: std.ArrayList(KernelFix) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ' ');
        const id = f.next().?;
        const fixed = f.next() orelse return error.BadLine;
        const title = f.rest();
        const v = kernelVersion(fixed) orelse return error.BadLine;
        if (!validCve(id) or v[0] != new[0] or v[1] != new[1] or !kernelLess(old, v) or kernelLess(new, v)) return error.BadLine;
        if (title.len > max_title or !std.unicode.utf8ValidateSlice(title)) return error.BadLine;
        for (title) |c| if (c < 0x20 or c == 0x7f) return error.BadLine;
        try out.append(gpa, .{ .id = id, .fixed_in = fixed, .title = title });
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

/// werewolf.modules for a load order: each path without .gz, and after it
/// the parameters /usr/share/werewolf/module-params gives its module, a
/// line `MODULE KEY=VALUE`, as the build writes them (Makefile,
/// MODULE_PARAMS). Parameters for a module not in the order are an error,
/// not a module loaded without them.
fn moduleList(gpa: Allocator, order: []const []const u8, params: []const u8) ![]const u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    for (order) |p| {
        const path = withoutGz(p);
        try out.writer.writeAll(path);
        const stem = std.fs.path.basename(path);
        var lines_it = std.mem.tokenizeScalar(u8, params, '\n');
        while (lines_it.next()) |line| {
            const space = std.mem.indexOfScalar(u8, line, ' ') orelse return error.BadModuleParams;
            if (std.mem.eql(u8, line[0..space], stem[0 .. stem.len - ".ko".len])) try out.writer.print(" {s}", .{line[space + 1 ..]});
        }
        try out.writer.writeByte('\n');
    }
    var lines_it = std.mem.tokenizeScalar(u8, params, '\n');
    next: while (lines_it.next()) |line| {
        const name = line[0 .. std.mem.indexOfScalar(u8, line, ' ') orelse line.len];
        for (order) |p| {
            const stem = std.fs.path.basename(withoutGz(p));
            if (std.mem.eql(u8, name, stem[0 .. stem.len - ".ko".len])) continue :next;
        }
        return error.ParamsForMissingModule;
    }
    return out.written();
}

/// Alpine's arm64 vmlinuz is an EFI zboot image: "MZ", "zimg", then the
/// gzipped Image's offset and size as little-endian u32. Anything else is
/// returned as it is.
/// A gzip stream, inflated.
fn gunzip(gpa: Allocator, data: []const u8) ![]const u8 {
    var in: Io.Reader = .fixed(data);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var gz: std.compress.flate.Decompress = .init(&in, .gzip, &window);
    var out: Io.Writer.Allocating = .init(gpa);
    _ = try gz.reader.streamRemaining(&out.writer);
    return out.written();
}

/// kernel/fs/ext4/ext4.ko.gz -> kernel/fs/ext4/ext4.ko
fn withoutGz(path: []const u8) []const u8 {
    return if (std.mem.endsWith(u8, path, ".gz")) path[0 .. path.len - 3] else path;
}

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

const Node = struct { name: []const u8, mode: u32, ino: u32, rdev_major: u32 = 0, rdev_minor: u32 = 0 };

/// One newc cpio entry: header, name and data, each padded to 4 bytes.
fn cpioEntry(w: *Io.Writer, n: Node, data: []const u8) !void {
    const fields = [_]u32{ n.ino, n.mode, 0, 0, 1, 0, @intCast(data.len), 0, 0, n.rdev_major, n.rdev_minor, @intCast(n.name.len + 1), 0 };
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

test "systemd-boot entries" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = parseCmdline("console=hvc0 werewolf.slot=a werewolf.victim=ab:/werewolf werewolf.esp=57E1-F000\n");
    try testing.expectEqualStrings("57E1-F000", c.esp);
    try testing.expectEqualStrings("", c.grubenv);
    try testing.expectEqualStrings(
        "console=hvc0 werewolf.victim=ab:/werewolf werewolf.esp=57E1-F000 werewolf.mac=52:55 werewolf.slot=b",
        try withSlot(a, "initrd=\\werewolf\\a\\initramfs.zst console=hvc0 werewolf.slot=a werewolf.victim=ab:/werewolf werewolf.esp=57E1-F000  werewolf.mac=52:55\n", "", "b"),
    );
    // The image's arguments replace any of the same name, and are added
    // where missing.
    try testing.expectEqualStrings(
        "console=hvc0 werewolf.victim=ab:/werewolf debugfs=off proc_mem.force_override=never werewolf.slot=b",
        try withSlot(a, "console=hvc0 proc_mem.force_override=always werewolf.slot=a werewolf.victim=ab:/werewolf\n", "debugfs=off proc_mem.force_override=never\n", "b"),
    );
    try testing.expectEqualStrings(
        \\title werewolf b
        \\sort-key werewolf
        \\version 20261006T120000Z
        \\linux /werewolf/b/vmlinuz
        \\initrd /werewolf/b/initramfs.zst
        \\options x werewolf.slot=b
        \\
    , try loaderEntry(a, "b", "20261006T120000Z", "x werewolf.slot=b"));
    try testing.expectEqualStrings("20261006T120000Z", try compactTime(a, 1791288000));
    for ([_][]const u8{ "werewolf-b.conf", "werewolf-b+1.conf", "werewolf-b+0-1.conf" }) |n| try testing.expect(isEntryOf(n, "b"));
    for ([_][]const u8{ "werewolf-a.conf", "werewolf-b.tmp", "werewolf-bb.conf", "other-b.conf" }) |n| try testing.expect(!isEntryOf(n, "b"));
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

test apkOrder {
    // Each as apk-tools 2.14.10's `apk version -t` answered.
    const cases = [_]struct { []const u8, []const u8, std.math.Order }{
        .{ "1.0", "1.0.1", .lt },
        .{ "1.0_alpha", "1.0", .lt },
        .{ "1.0_alpha1", "1.0_alpha2", .lt },
        .{ "1.0_beta", "1.0_alpha", .gt },
        .{ "1.0_rc1", "1.0", .lt },
        .{ "1.0_p1", "1.0", .gt },
        .{ "1.0-r1", "1.0-r0", .gt },
        .{ "1.0-r10", "1.0-r9", .gt },
        .{ "1.0a", "1.0", .gt },
        .{ "1.0a", "1.0b", .lt },
        .{ "1.01", "1.1", .lt },
        .{ "1.010", "1.9", .lt },
        .{ "1.001", "1.01", .lt },
        .{ "2.0", "1.99", .gt },
        .{ "1.3.2.1_rc20260601-r0", "1.3.2.1-r0", .lt },
        .{ "1.3.2.1_rc20260601-r0", "1.3.2-r5", .gt },
        .{ "4.0.3-r3", "4.0.2-r0", .gt },
        .{ "1.38.0-r2", "1.37.0-r30", .gt },
        .{ "1.0", "1.0", .eq },
        .{ "1.0-r0", "1.0", .gt },
        .{ "0", "1.0", .lt },
        .{ "1.0_git20260101", "1.0", .gt },
        .{ "1.0_cvs", "1.0_svn", .lt },
        .{ "6.18.55-r0", "6.18.9-r0", .gt },
        .{ "1.2.3_p4-r1", "1.2.3_p4-r0", .gt },
        .{ "1.2.3_pre1", "1.2.3_p1", .lt },
        .{ "2.39.4", "2.39.4_p0", .lt },
        .{ "1.0_bad", "1.0", .lt },
        .{ "abc", "1.0", .lt },
        .{ "1.0.", "1.0", .gt },
        .{ "1.0", "1.0-r", .lt },
        .{ "1.2.3a1", "1.2.3a", .gt },
        .{ "5.2.37_p20250701-r0", "5.2.37-r40", .gt },
        .{ "2026.04.13-r1", "2026.4.13-r1", .lt },
        .{ "1.0.0.0.0.0", "1.0", .gt },
        .{ "1.0_alpha_p1", "1.0_alpha", .gt },
    };
    for (cases) |c| {
        errdefer std.debug.print("{s} {s}\n", .{ c[0], c[1] });
        try testing.expectEqual(c[2], apkOrder(c[0], c[1]));
        try testing.expectEqual(c[2].invert(), apkOrder(c[1], c[0]));
    }
    // And as `apk version -c` judged them.
    for ([_][]const u8{ "1.0", "1.0.", "1.0-r", "0", "", "1.0_alpha_p1", "1.3.2.1_rc20260601-r0" }) |v| try testing.expect(validVersion(v));
    for ([_][]const u8{ "1.0_bad", "abc", "1.0-x", "1.0 ", "1.0-r1a", "1234567890123456789" }) |v| try testing.expect(!validVersion(v));
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

test "package CVEs, from a reader and checked" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const origins: []const OriginChange = &.{
        .{ .origin = "zlib", .from = "1.3.1-r0", .to = "1.3.2.1-r0" },
        .{ .origin = "openssl-4.0", .from = "4.0.2-r0", .to = "4.0.3-r3" },
    };
    var out: Io.Writer.Allocating = .init(a);
    try secdbLines(a,
        \\{"packages":[
        \\ {"pkg":{"name":"zlib","secfixes":{"0":["CVE-2026-22184"],"1.3.2.1_rc20260601-r0":["CVE-2026-85091","GHSA-x"],"1.3.2-r0":["CVE-2026-1111"],"1.4-r0":["CVE-2026-2222"]}}},
        \\ {"pkg":{"name":"openssl","secfixes":{"4.0.3-r0":["CVE-2026-3333"],"3.5.9-r0":["CVE-2026-4444"],"4.0.3 -r1":["CVE-2026-5555"]}}},
        \\ {"pkg":{"name":"other","secfixes":{"4.0.3-r0":["CVE-2026-6666"]}}}]}
    , origins, &out.writer);
    try testing.expectEqualStrings(
        \\0 1.3.2.1_rc20260601-r0 CVE-2026-85091
        \\0 1.3.2-r0 CVE-2026-1111
        \\1 4.0.3-r0 CVE-2026-3333
        \\
    , out.written());

    const fixes = try packageFixes(a, out.written(), origins);
    try testing.expectEqual(2, fixes.len);
    try testing.expectEqualStrings("zlib", fixes[0].origin);
    try testing.expectEqualStrings("CVE-2026-1111", fixes[0].cves[0]);
    try testing.expectEqualStrings("CVE-2026-85091", fixes[0].cves[1]);
    try testing.expectEqualStrings("4.0.2-r0", fixes[1].from);
    try testing.expectEqual(0, (try packageFixes(a, "", origins)).len);

    // A reader that lies in any one line is believed in none.
    for ([_][]const u8{
        "2 4.0.3-r0 CVE-2026-3333", // no such origin
        "1 4.0.4-r0 CVE-2026-3333", // after the window
        "1 4.0.2-r0 CVE-2026-3333", // the old version itself
        "1 0 CVE-2026-3333",
        "1 4.0.3-r0 GHSA-xxxx-xxxx-xxxx",
        "1 4.0.3-r0 CVE-2026-3333 more",
        "1 4.0.3-r0",
        "1 4.0.3-r0 CVE-26-3333",
        "-1 4.0.3-r0 CVE-2026-3333",
        "1 4.0.3-r0 CVE-2026-3333\x00",
    }) |bad| {
        const text = try std.fmt.allocPrint(a, "0 1.3.2-r0 CVE-2026-1111\n{s}\n", .{bad});
        try testing.expectError(error.BadLine, packageFixes(a, text, origins));
    }
}

test "kernel CVEs, from a reader and checked" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const old: [3]u32 = .{ 6, 18, 50 };
    const new: [3]u32 = .{ 6, 18, 55 };
    const fixes = try kernelFixes(a, "CVE-2026-9000 6.18.55 b: \xc3\xa9t\xc3\xa9\nCVE-2026-10001 6.18.51 a: x\n", old, new);
    try testing.expectEqual(2, fixes.len);
    try testing.expectEqualStrings("CVE-2026-10001", fixes[0].id);
    try testing.expectEqualStrings("a: x", fixes[0].title);
    try testing.expectEqualStrings("6.18.55", fixes[1].fixed_in);
    for ([_][]const u8{
        "CVE-2026-9999 6.18.50 x", // the old version itself
        "CVE-2026-9999 6.18.56 x",
        "CVE-2026-9999 6.12.52 x",
        "CVE-2026-9999 6.18 x",
        "CVE-2026-9999 6.18.52 \x1b[2Jx",
        "CVE-2026-9999 6.18.52 \xff",
        "CVE-2026-99x9 6.18.52 x",
    }) |bad| try testing.expectError(error.BadLine, kernelFixes(a, bad, old, new));

    try testing.expectEqualStrings("a b  c", try oneLine(a, "a\nb\t\x7fc"));
    var long: [max_title + 1]u8 = @splat('x');
    long[max_title - 1] = 0xc3;
    long[max_title] = 0xa9;
    try testing.expectEqual(max_title - 1, (try oneLine(a, &long)).len);
}

test cacheName {
    for ([_][]const u8{ "installed", "APKINDEX.f8759e6a.tar.gz", "zstd-1.5.7-r10.cc2743ad.apk" }) |n| try testing.expect(cacheName(n));
    for ([_][]const u8{ "APKINDEX.f8759e6a.tar", ".apk.27182ee91faf", "installed.new", "lib", "zstd-1.5.7-r10.apk.tmp" }) |n| try testing.expect(!cacheName(n));
}

test isCachedOf {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const pkgs = try parseInstalled(arena.allocator(), "P:zstd\nV:1.5.7-r10\n\nP:glibc-2.44\nV:2.44-r8\n");
    try testing.expect(isCachedOf("zstd-1.5.7-r10.cc2743ad.apk", pkgs));
    try testing.expect(isCachedOf("glibc-2.44-2.44-r8.b91ee306.apk", pkgs));
    try testing.expect(!isCachedOf("glibc-2.44-2.44-r7.53c9e93b.apk", pkgs));
    try testing.expect(!isCachedOf("zstd-1.5.7-r1.cc2743ad.apk", pkgs));
    try testing.expect(!isCachedOf("libzstd1-1.5.7-r10.933e1e74.apk", pkgs));
    try testing.expect(!isCachedOf("zstd-1.5.7-r10.apk", pkgs));
    try testing.expect(!isCachedOf(".apk", pkgs));
}

test validCve {
    for ([_][]const u8{ "CVE-2026-0001", "CVE-1999-1234567" }) |id| try testing.expect(validCve(id));
    for ([_][]const u8{ "CVE-2026-001", "cve-2026-0001", "CVE-2026-0001 ", "CVE-20260-0001", "GHSA-2026-0001", "CVE-2026-0001a" }) |id| try testing.expect(!validCve(id));
}

test {
    _ = sandbox;
}

test withoutGz {
    try testing.expectEqualStrings("kernel/fs/ext4/ext4.ko", withoutGz("kernel/fs/ext4/ext4.ko.gz"));
    try testing.expectEqualStrings("kernel/fs/ext4/ext4.ko", withoutGz("kernel/fs/ext4/ext4.ko"));
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

test moduleList {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const order = [_][]const u8{ "kernel/arch/x86/kvm/kvm.ko.gz", "kernel/arch/x86/kvm/kvm-intel.ko.gz" };
    try testing.expectEqualStrings("kernel/arch/x86/kvm/kvm.ko\nkernel/arch/x86/kvm/kvm-intel.ko\n", try moduleList(a, &order, ""));
    try testing.expectEqualStrings(
        "kernel/arch/x86/kvm/kvm.ko\nkernel/arch/x86/kvm/kvm-intel.ko nested=0 ept=1\n",
        try moduleList(a, &order, "kvm-intel nested=0\nkvm-intel ept=1\n"),
    );
    try testing.expectError(error.ParamsForMissingModule, moduleList(a, &order, "kvm-amd nested=0\n"));
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
    try cpioEntry(&out.writer, .{ .name = "dev/console", .mode = 0o020620, .ino = 2, .rdev_major = 5, .rdev_minor = 1 }, "");
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

test rfc3339 {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("2026-10-06T12:42:29Z", try rfc3339(arena.allocator(), 1791290549));
}
