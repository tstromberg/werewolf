//! slot-update: keep a machine booted from a slot current, from Wolfi and Alpine.
//!
//!     slot-update check     if Wolfi or Alpine has anything newer than this image,
//!                           build the other slot and stage it: armed to boot
//!                           once, and booted by the daemon when it is due
//!     slot-update outcome   after a reboot, log whether the last update held
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
pub const Io = std.Io;
pub const Dir = Io.Dir;
pub const Allocator = std.mem.Allocator;
pub const linux = std.os.linux;
pub const sandbox = @import("sandbox");
const broker = @import("broker");
pub const verity = @import("verity");
pub const policy = @import("update-policy");
pub const cve = @import("cve.zig");
pub const releases = @import("release.zig");
pub const tiers = @import("tiers.zig");
const stage = @import("stage.zig");
const slot = @import("slot.zig");
const Pending = stage.Pending;

pub const meta_dir = "/usr/share/werewolf";
const state_dir = "/data/svc/autoupdate";
pub const work_dir = state_dir ++ "/work";
pub const cache_dir = state_dir ++ "/cache";
const log_path = state_dir ++ "/log";
/// The staged slot, and when this machine first saw each tier of its fixes.
pub const pending_path = state_dir ++ "/pending";
/// "SLOT BUILD BOOT" of the slot armed to boot once, and the boot that armed
/// it (attemptOf).
pub const attempt_path = state_dir ++ "/attempt";
/// Held while a pass changes anything here, so a check run by hand and the
/// daemon's never interleave.
pub const lock_path = state_dir ++ "/lock";
/// When the last reboot for an update went, in seconds since the epoch.
pub const rebooted_path = state_dir ++ "/rebooted";
/// The last tiers feed this machine took, and its signature.
pub const feed_path = state_dir ++ "/cve-tiers.json";
pub const feed_sig_path = feed_path ++ ".sig";
/// The newest serial of a feed this machine took.
pub const feed_serial_path = feed_path ++ ".serial";
/// The most a feed or its signature may be.
pub const max_feed = 16 << 20;
/// Reports kept, newest first: years of updates at a few a week.
const max_reports = 500;
/// The form's update settings, then the operator's (lib/update-policy.zig).
pub const form_policy = "/etc/werewolf/update-policy.json";
pub const operator_policy = "/run/config/update-policy.json";
/// Where the daemon says it can update (daemon).
const ready_path = "/run/werewolf/updater-ready";
const kernel_cves_url = "https://git.kernel.org/pub/scm/linux/security/vulns.git/snapshot/vu" ++
    "lns-" ++
    "master.tar.gz";
pub const max_read = 256 << 20;

/// _update, the account the children that fetch run as
/// (forms/prod.yaml).
pub const update_id: u32 = 69;
/// The CVE fetcher's root, and where the CVE sources are fetched to.
const net_root = work_dir ++ "/net";
pub const cves_dir = work_dir ++ "/cves";
/// How long a CVE fetcher, apk's fetcher and a CVE reader may take, in
/// seconds; what a reader may send back.
const fetch_seconds = 600;
pub const apk_seconds = 1800;
const read_seconds = 300;
const max_lines = 4 << 20;
/// How long a tool root runs may take (mkfs.erofs, zstd, apk offline,
/// grub-setenv), in seconds, and the most it may say on each of stdout and
/// stderr: one that hangs is killed, and the pass fails, to try again.
const tool_seconds = 1800;
const max_tool_output = 1 << 20;
/// The most any one file apk's fetcher writes may be: an index or a
/// package, the largest of which (a JDK) is a few hundred megabytes.
pub const max_apk_file = 1 << 30;

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
        var settings: policy.Settings = .{};
        u.loadPolicy(&settings) catch |err| fatal(&u, err);
        u.check(&settings, false) catch |err| fatal(&u, err);
    } else if (std.mem.eql(u8, mode, "outcome")) {
        u.outcome() catch |err| fatal(&u, err);
    } else {
        std.debug.print("usage: slot-update check|outcome|daemon\n", .{});
        std.process.exit(2);
    }
}

fn fatal(u: *Update, err: anyerror) noreturn {
    failed(u, err);
    std.process.exit(1);
}

/// An error, logged, and the work directory cleared.
fn failed(u: *Update, err: anyerror) void {
    u.record(.{
        .event = "error",
        .step = u.step,
        .@"error" = @errorName(err),
        .detail = u.detail,
    }) catch {};
    Dir.cwd().deleteTree(u.io, work_dir) catch {};
}

/// The autoupdate service. Once this slot has committed: the settings
/// (loadPolicy), outcome, then a check at once and every hour after, or as
/// often as the form's /etc/werewolf/update-every says, in seconds. A check
/// stages what it finds; between checks the daemon sleeps until the staged
/// slot is due, and boots it then (bootIfDue). A check that fails is logged
/// and tried again next time. Each pass has an arena of its own, freed when
/// it ends, so months of checks use what one does. Only a machine booted
/// from a slot can do any of this; elsewhere the service parks itself.
///
/// Once setup succeeds, so that it could update if asked, it says so in
/// /run/werewolf/updater-ready, and slot-keep commits no slot until it
/// has: a slot whose updater cannot start could never be updated again,
/// so it must not be kept. /run starts empty each boot.
fn daemon(io: Io) noreturn {
    // Speculative Store Bypass off for the daemon and every child, apk and
    // mkfs.erofs included: they read what came from the network. Where the
    // CPU offers no control (EINVAL, ENXIO, EPERM), it runs as it would.
    _ = linux.prctl(
        @backingInt(linux.PR.SET_SPECULATION_CTRL),
        linux.PR.SPEC_STORE_BYPASS,
        linux.PR.SPEC_FORCE_DISABLE,
        0,
        0,
    );
    // Before anything is logged: a machine that has never logged has never
    // checked, and boots whatever its first check stages at once.
    var ctx: Ctx = .{ .first_boot = neverLogged(io) };
    switch (pass(io, .setup, &ctx)) {
        .ok => Dir.cwd().writeFile(io, .{ .sub_path = ready_path, .data = "" }) catch |err| {
            std.debug.print(
                "autoupdate: cannot write {s}: {s}\n",
                .{ ready_path, @errorName(err) },
            );
        },
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
    _ = pass(io, .policy, &ctx);
    _ = pass(io, .outcome, &ctx);
    var next_check = nowSecs(io);
    while (true) {
        if (nowSecs(io) >= next_check) {
            if (pass(io, .check, &ctx) == .ok) ctx.first_boot = false;
            next_check = nowSecs(io) + every;
        }
        if (!ctx.rebooting) _ = pass(io, .boot, &ctx);
        const wait = @min(next_check - nowSecs(io), ctx.due_in orelse every);
        io.sleep(.fromSeconds(@max(wait, 1)), .awake) catch {};
    }
}

/// What the daemon keeps between passes: the settings, read once; whether
/// this machine has yet to finish a check; how long until the staged slot
/// is due, if one is; and whether it has asked to reboot.
pub const Ctx = struct {
    settings: policy.Settings = .{},
    first_boot: bool = false,
    due_in: ?i64 = null,
    rebooting: bool = false,
};

const Step = enum { setup, policy, outcome, check, boot };
const PassResult = enum { ok, not_a_slot, failed };

fn pass(io: Io, step: Step, ctx: *Ctx) PassResult {
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
        .policy => u.loadPolicy(&ctx.settings),
        .outcome => u.outcome(),
        .check => u.check(&ctx.settings, ctx.first_boot),
        .boot => u.bootIfDue(ctx),
    }) catch |err| {
        failed(&u, err);
        return .failed;
    };
    return .ok;
}

/// Whether this machine's log is missing or empty: it has never checked.
fn neverLogged(io: Io) bool {
    const f = Dir.cwd().openFile(io, log_path, .{}) catch return true;
    defer f.close(io);
    return (f.length(io) catch return false) == 0;
}

pub fn nowSecs(io: Io) i64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

/// Seconds since the kernel started its clock.
pub fn bootSecs() i64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
    return ts.sec;
}

/// Seconds between checks: the form's /etc/werewolf/update-every, or an
/// hour; never less than five minutes, nor more than a week.
fn updateEvery(io: Io) i64 {
    var buf: [32]u8 = undefined;
    const n = Dir.cwd().readFile(io, "/etc/werewolf/update-every", &buf) catch return 3600;
    const every = std.fmt.parseInt(i64, std.mem.trim(u8, n, " \n"), 10) catch return 3600;
    return std.math.clamp(every, 5 * 60, 7 * 24 * 3600);
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

pub const Update = struct {
    io: Io,
    gpa: Allocator,
    host: []const u8 = "",
    cmd: Cmdline = .{},
    other: []const u8 = "b",
    step: []const u8 = "start",
    /// What the last command that failed said, for the error event.
    detail: []const u8 = "",

    pub fn setup(u: *Update) !void {
        try Dir.cwd().createDirPath(u.io, state_dir ++ "/reports");
        // The kernel's, which init sets whether or not a config named one.
        const uts = std.posix.uname();
        u.host = try u.gpa.dupe(u8, std.mem.sliceTo(&uts.nodename, 0));
        u.cmd = parseCmdline(try u.read("/proc/cmdline"));
        // A slot boots from a distro's GRUB (bite: werewolf.grubenv) or from
        // werewolf's own disk under systemd-boot (werewolf.esp).
        if (u.cmd.slot.len == 0 or u.cmd.victim.len == 0 or (u.cmd.grubenv.len == 0 and
            u.cmd.esp.len == 0))
            return error.NotBootedFromASlot;
        u.other = if (std.mem.eql(u8, u.cmd.slot, "b")) "a" else "b";
    }

    // --- outcome -----------------------------------------------------------
    // The last update left `attempt`: the slot it built and the build's hash.
    // Booted into that slot, and committed, it held; booted into the other,
    // it did not, and the same build is not tried again.
    pub fn outcome(u: *Update) !void {
        const held_lock = try u.lock();
        defer _ = linux.close(held_lock);
        const attempt = try u.attemptOf() orelse return;
        // Armed in this boot, so not tried yet: the daemon started again,
        // and there is nothing to judge until the machine reboots.
        if (std.mem.eql(u8, attempt.boot, try u.bootId())) return;
        const tried = attempt.slot;
        const build = attempt.build;
        const release = std.mem.trim(u8, try u.read(meta_dir ++ "/release"), "\n");
        const down = u.downtime();
        if (std.mem.eql(u8, tried, u.cmd.slot)) {
            Dir.cwd().rename(
                state_dir ++ "/attempt-serial",
                Dir.cwd(),
                state_dir ++ "/serial",
                u.io,
            ) catch |err|
                if (err != error.FileNotFound) return err;
            try u.record(.{
                .event = "commit",
                .slot = u.cmd.slot,
                .build = build,
                .release = release,
                .waited = try u.waited(),
                .down = down,
            });
        } else {
            try u.append(state_dir ++ "/bad", try u.gpa.print("{s}\n", .{build}));
            try u.record(.{
                .event = "rollback",
                .failed = tried,
                .running = u.cmd.slot,
                .build = build,
                .release = release,
                .down = down,
            });
        }
        Dir.cwd().deleteFile(u.io, state_dir ++ "/attempt-serial") catch {};
        Dir.cwd().deleteFile(u.io, pending_path) catch {};
        Dir.cwd().deleteFile(u.io, rebooted_path) catch {};
        try Dir.cwd().deleteFile(u.io, attempt_path);
    }

    pub const Attempt = stage.Attempt;
    pub const attemptOf = stage.attemptOf;
    pub const bootId = stage.bootId;
    pub const armed = stage.armed;
    pub const lock = stage.lock;
    pub const downtime = stage.downtime;
    pub const waited = stage.waited;
    pub const loadPolicy = stage.loadPolicy;
    pub const readPending = stage.readPending;
    pub const dueOf = stage.dueOf;
    pub const whyOf = stage.whyOf;
    pub const seed = stage.seed;
    pub const tiersFeed = stage.tiersFeed;
    pub const fetchFeed = stage.fetchFeed;
    pub const ownAdvisories = stage.ownAdvisories;
    pub const noFeed = stage.noFeed;
    pub const retier = stage.retier;
    pub const bootIfDue = stage.bootIfDue;

    // --- check -------------------------------------------------------------
    // What the other slot would be: the latest signed release of this form,
    // if CI publishes the form (the build record names where), or else what
    // Wolfi and Alpine have now. Then the same for both: the CVEs it fixes,
    // the slot, the report, and the slot staged, to boot once when it is due
    // (bootIfDue).
    pub fn check(u: *Update, s: *const policy.Settings, first_boot: bool) !void {
        const io = u.io;
        // Until this slot has committed, the other is the one to fall back
        // to, and must not be written.
        Dir.cwd().access(io, "/run/werewolf/committed", .{}) catch return error.NotCommitted;
        const held_lock = try u.lock();
        defer _ = linux.close(held_lock);
        Dir.cwd().deleteTree(io, work_dir) catch {};
        try Dir.cwd().createDirPath(io, work_dir);
        defer Dir.cwd().deleteTree(io, work_dir) catch {};
        const arch = std.mem.trim(u8, try u.read("/etc/apk/arch"), "\n");
        const release = std.mem.trim(u8, try u.read(meta_dir ++ "/release"), "\n");
        const published = if (Dir.cwd().access(io, meta_dir ++ "/releases", .{}))
            true
        else |_|
            false;
        const plan = (if (published)
            try u.releasePlan(arch, release)
        else
            try u.packagesPlan(arch, release)) orelse return;

        if (u.isBad(plan.build)) {
            return u.record(.{
                .event = "skip",
                .build = plan.build,
                .reason = "this build rolled back before",
            });
        }
        const staged = try u.readPending();
        if (staged) |p| if (std.mem.eql(u8, p.build, plan.build) and try u.armed(p)) {
            // Staged already: tier its fixes again, and say when it boots.
            const now_p = try u.retier(s, p, plan);
            const d = try u.dueOf(s, now_p);
            return u.record(.{
                .event = "check",
                .slot = u.cmd.slot,
                .release = release,
                .result = "staged",
                .build = now_p.build,
                .tier = @tagName(d.tier),
                .due = try u.time(d.at),
                .due_in = d.at - nowSecs(io),
            });
        };

        u.step = "cves";
        try u.netRoot();
        var sources: std.ArrayList(Source) = .empty;
        const repo = (try u.words(try u.read("/etc/apk/repositories")))[0];
        const package_cves = try u.packageCves(&sources, repo, plan.old_pkgs, plan.new_pkgs);
        const kernel_changed = !std.mem.eql(u8, plan.old_kernel, plan.new_kernel);
        const kernel_cves = if (kernel_changed)
            try u.kernelCves(&sources, plan.old_kernel, plan.new_kernel)
        else
            cve.KernelFixes{};

        // Tiered before anything is installed, so nothing after the install
        // can fail for want of the feed.
        u.step = "stage";
        const feed = try u.tiersFeed();
        const fixes = try tiers.tiersOf(u.gpa, feed, .{
            .changes = try diffOrigins(u.gpa, plan.old_pkgs, plan.new_pkgs),
            .package_cves = package_cves,
            .kernel_cves = kernel_cves,
            .old_kernel = plan.old_kernel,
            .new_kernel = plan.new_kernel,
            .advisories = stage.advisoriesOf(plan),
            .have = try u.ownAdvisories(),
        });
        const now = nowSecs(io);
        const stamp = try u.time(now);
        const report_path = try u.gpa.print(
            "{s}/reports/{s}-{s}.json",
            .{ state_dir, stamp, plan.build },
        );
        var next: Pending = staged orelse .{ .build = plan.build };
        next.build = plan.build;
        next.report = report_path;
        next.first_boot = next.first_boot or first_boot;
        for (std.enums.values(policy.Tier)) |t| if (fixes.first[@backingInt(t)]) |f| {
            const seen = next.tier(t);
            if (seen.* == null) seen.* = .{
                .seen = try u.time(now),
                .subject = f.subject,
                .evidence = f.evidence,
            };
        };

        switch (plan.from) {
            .packages => try u.buildSlot(arch, plan.new_kernel),
            .release => |r| try u.fetchRelease(r.base, r.name, r.manifest),
        }
        // pending stays as it was, with its first-seen times, until the new
        // build is armed: install takes `attempt` away first, so the old
        // build is no longer armed, and bootIfDue boots nothing meanwhile.
        try u.install(plan.build);
        try u.writeReplacing(pending_path, try std.json.Stringify.valueAlloc(u.gpa, next, .{}));
        // outcome keeps a release's serial once its slot commits, so no
        // older one is taken after it.
        if (plan.from == .release) try u.write(
            state_dir ++ "/attempt-serial",
            plan.from.release.manifest.serial,
        );
        const d = try u.dueOf(s, next);
        const why = try u.whyOf(s, next, d, now);

        u.step = "report";
        const changes = try diffPackages(u.gpa, plan.old_pkgs, plan.new_pkgs);
        const report: Report = .{
            .tier = @tagName(d.tier),
            .why = why,
            .time = stamp,
            .host = u.host,
            .build = plan.build,
            .from = .{ .slot = u.cmd.slot, .release = release, .kernel = plan.old_kernel },
            .to = .{ .slot = u.other, .kernel = plan.new_kernel },
            .packages = changes,
            .package_cves = package_cves,
            .kernel_cves = kernel_cves,
            .sources = sources.items,
        };
        var out: Io.Writer.Allocating = .init(u.gpa);
        try std.json.Stringify.value(report, .{ .whitespace = .indent_2 }, &out.writer);
        try out.writer.writeByte('\n');
        try u.writeReplacing(report_path, out.written());
        u.pruneReports() catch {};
        var cve_count: usize = kernel_cves.cves.len;
        for (package_cves) |p| cve_count += p.cves.len;
        try u.record(.{
            .event = "stage",
            .slot = u.other,
            .from = u.cmd.slot,
            .build = plan.build,
            .kernel = try u.gpa.print("{s} -> {s}", .{ plan.old_kernel, plan.new_kernel }),
            .packages = changes.len,
            .cves = cve_count,
            .tier = @tagName(d.tier),
            .seen = next.seenTimes(),
            .fixes = .{
                .urgent = fixes.count[@backingInt(policy.Tier.urgent)],
                .high = fixes.count[@backingInt(policy.Tier.high)],
                .medium = fixes.count[@backingInt(policy.Tier.medium)],
                .low = fixes.count[@backingInt(policy.Tier.low)],
            },
            .due = try u.time(d.at),
            .due_in = d.at - now,
            .why = why,
            .report = report_path,
        });
    }

    /// The other slot as Wolfi and Alpine would have it now, installed into
    /// work_dir/root and work_dir/kernel; or null, logged, if it would be
    /// this one.
    fn packagesPlan(u: *Update, arch: []const u8, release: []const u8) !?Plan {
        u.step = "userland";
        try u.apkAdd(
            work_dir ++ "/root",
            arch,
            "/etc/apk/keys",
            &.{ "--repositories-file", "/etc/apk/repositories" },
            try u.words(try u.read("/etc/apk/world")),
        );
        u.step = "kernel";
        const alpine = std.mem.trim(u8, try u.read(meta_dir ++ "/alpine"), "\n");
        try u.apkAdd(
            work_dir ++ "/kernel",
            arch,
            "/etc/werewolf/alpine-keys",
            &.{ "--repository", alpine },
            &.{"linux-virt"},
        );

        u.step = "compare";
        const old_pkgs = try parseInstalled(u.gpa, try u.read("/lib/apk/db/installed"));
        const new_pkgs = try parseInstalled(
            u.gpa,
            try slot.readIn(u, work_dir ++ "/root", "lib/apk/db/installed"),
        );
        const kernel_pkgs = try parseInstalled(
            u.gpa,
            try slot.readIn(u, work_dir ++ "/kernel", "lib/apk/db/installed"),
        );
        const old_kernel = std.mem.trim(u8, try u.read(meta_dir ++ "/kernel"), "\n");
        const new_kernel = try u.gpa.print(
            "linux-virt-{s}",
            .{versionOf(kernel_pkgs, "linux-virt") orelse return error.NoKernel},
        );
        // apk installs what the index names, and an index carries no date:
        // a signed index older than this image's would be installed as
        // happily as a newer one. Nothing goes backwards.
        const changes = try diffPackages(u.gpa, old_pkgs, new_pkgs);
        if (backwards(changes, old_kernel, new_kernel)) |what| {
            try u.record(.{
                .event = "skip",
                .release = release,
                .reason = try u.gpa.print("{s} would go backwards", .{what}),
            });
            return null;
        }
        if (changes.len == 0 and std.mem.eql(u8, old_kernel, new_kernel)) {
            try u.record(.{
                .event = "check",
                .slot = u.cmd.slot,
                .release = release,
                .result = "current",
            });
            return null;
        }
        return .{
            .build = try buildHash(u.gpa, new_pkgs, new_kernel),
            .old_pkgs = old_pkgs,
            .new_pkgs = new_pkgs,
            .old_kernel = old_kernel,
            .new_kernel = new_kernel,
            .from = .packages,
        };
    }

    /// The other slot as the latest release of this form has it, its
    /// manifest signed with the image key; or null, logged, if this slot
    /// is that release, or it is not one to take: expired, older than one
    /// already taken, or not published for this form yet.
    fn releasePlan(u: *Update, arch: []const u8, release: []const u8) !?Plan {
        u.step = "release";
        try u.netRoot();
        const base = std.mem.trim(u8, try u.read(meta_dir ++ "/releases"), " \n");
        const form = std.mem.trim(u8, try u.read(meta_dir ++ "/form"), "\n");
        const name = try u.gpa.print("{s}-{s}", .{ form, arch });
        const data = u.downloadSmall(
            try u.gpa.print("{s}{s}.json", .{ base, name }),
            cves_dir ++ "/manifest.json",
        ) catch |err| {
            if (err == error.FetchFailed and std.mem.eql(u8, u.detail, "not_found")) {
                try u.record(.{
                    .event = "skip",
                    .release = release,
                    .reason = "no release of this form yet",
                });
                return null;
            }
            return err;
        };
        const sig = try u.downloadSmall(
            try u.gpa.print("{s}{s}.json.sig", .{ base, name }),
            cves_dir ++ "/manifest.sig",
        );
        const key = try releases.parseKey(u.gpa, try u.read(meta_dir ++ "/image.pub"));
        const secs: i64 = @intCast(@divFloor(
            Io.Timestamp.now(u.io, .real).nanoseconds,
            std.time.ns_per_s,
        ));
        const m = releases.open(u.gpa, key, data, sig, form, arch, secs) catch |err| switch (err) {
            error.Stale => {
                try u.record(.{
                    .event = "skip",
                    .release = release,
                    .reason = "the latest release has expired",
                });
                return null;
            },
            else => return err,
        };

        u.step = "compare";
        const old_kernel = std.mem.trim(u8, try u.read(meta_dir ++ "/kernel"), "\n");
        const running = try u.gpa.print(
            "/victim{s}/{s}/root.erofs",
            .{ pathOf(u.cmd.victim), u.cmd.slot },
        );
        const root = m.files.map.get("root.erofs").?;
        if (std.mem.eql(u8, &try u.sha256Of(running), root.sha256) and
            std.mem.eql(u8, m.kernel, old_kernel))
        {
            try u.record(.{
                .event = "check",
                .slot = u.cmd.slot,
                .release = release,
                .result = "current",
            });
            return null;
        }
        if (u.read(state_dir ++ "/serial")) |taken| {
            if (std.mem.order(u8, m.serial, std.mem.trim(u8, taken, "\n")) != .gt) {
                try u.record(.{
                    .event = "skip",
                    .build = m.build,
                    .reason = "not newer than the release last taken",
                });
                return null;
            }
        } else |err| if (err != error.FileNotFound) return err;

        const new_pkgs = try u.gpa.alloc(Package, m.packages.len);
        for (m.packages, new_pkgs) |p, *n| n.* = .{
            .name = p.name,
            .version = p.version,
            .origin = p.origin,
        };
        return .{
            .build = m.build,
            .old_pkgs = try parseInstalled(u.gpa, try u.read("/lib/apk/db/installed")),
            .new_pkgs = new_pkgs,
            .old_kernel = old_kernel,
            .new_kernel = m.kernel,
            .from = .{ .release = .{ .base = base, .name = name, .manifest = m } },
        };
    }

    /// A release's slot files into work_dir/slot as a built slot has them,
    /// each checked against the manifest's size and sha256.
    fn fetchRelease(
        u: *Update,
        base: []const u8,
        name: []const u8,
        m: releases.Manifest,
    ) !void {
        u.step = "fetch";
        try Dir.cwd().createDirPath(u.io, work_dir ++ "/slot");
        const targets = [_][:0]const u8{
            work_dir ++ "/slot/vmlinuz",
            work_dir ++ "/slot/initramfs.zst",
            work_dir ++ "/slot/root.erofs",
        };
        for (releases.Manifest.slot_files, targets) |file, target| {
            try u.fetchReleaseFile(base, name, file, m.files.map.get(file).?, target);
        }
        // The release's own kernel arguments, where its manifest names them:
        // a slot boots with what its image asks for, not this one's.
        if (m.files.map.get("cmdline")) |want| {
            if (want.size > 4096) return error.BadManifest;
            try u.fetchReleaseFile(base, name, "cmdline", want, work_dir ++ "/slot/cmdline");
        }
    }

    fn fetchReleaseFile(
        u: *Update,
        base: []const u8,
        name: []const u8,
        file: []const u8,
        want: releases.Manifest.File,
        target: [:0]const u8,
    ) !void {
        const got = try u.download(try u.gpa.print("{s}{s}-{s}", .{ base, name, file }), target);
        _ = linux.close(got.fd);
        if (got.size != want.size or !std.mem.eql(u8, &got.sha256, want.sha256)) {
            u.detail = try u.gpa.print("{s}: not the file the manifest names", .{file});
            return error.ReleaseFileMismatch;
        }
    }

    /// The kernel arguments the new slot boots with: its release's, when
    /// the release carried them (fetchRelease), or else this image's, which
    /// a slot built from packages carries forward with the rest of
    /// werewolf's files. One line of printable ASCII, as a loader entry and
    /// GRUB's environment can hold.
    pub fn slotCmdline(u: *Update) ![]const u8 {
        const text = u.read(work_dir ++ "/slot/cmdline") catch |err| switch (err) {
            error.FileNotFound => try u.read(meta_dir ++ "/cmdline"),
            else => return err,
        };
        const line = std.mem.trimEnd(u8, text, "\n");
        for (line) |c| if (c < ' ' or c > '~' or c == '\\') return error.BadCmdline;
        return line;
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
    fn packageCves(
        u: *Update,
        sources: *std.ArrayList(Source),
        repo: []const u8,
        old: []const Package,
        new: []const Package,
    ) ![]const cve.PackageFix {
        const origins = try diffOrigins(u.gpa, old, new);
        const url = try u.gpa.print("{s}/security.json", .{repo});
        const body = try u.fetch(sources, url, "security.json") orelse return &.{};
        defer _ = linux.close(body.fd);
        const found = u.examine(sources, .{ .secdb = origins }, body) orelse return &.{};
        return cve.packageFixes(u.gpa, found, origins) catch |err| {
            sources.items[sources.items.len - 1].@"error" = @errorName(err);
            return &.{};
        };
    }

    // The Linux kernel CNA's records, from git.kernel.org as one tarball: for
    // each CVE, the stable releases that fixed it. A CVE counts when its fix
    // for this kernel's branch (6.18.*) is in (old, new]. Records are often
    // published weeks after a fix ships, so this is what was known at update
    // time.
    fn kernelCves(
        u: *Update,
        sources: *std.ArrayList(Source),
        old_kernel: []const u8,
        new_kernel: []const u8,
    ) !cve.KernelFixes {
        const old = cve.kernelVersion(old_kernel) orelse return error.BadKernelVersion;
        const new = cve.kernelVersion(new_kernel) orelse return error.BadKernelVersion;
        const branch = try u.gpa.print("{d}.{d}", .{ new[0], new[1] });
        var fixes: cve.KernelFixes = .{ .branch = branch, .from = old_kernel, .to = new_kernel };
        const body = try u.fetch(sources, kernel_cves_url, "vulns.tar.gz") orelse return fixes;
        defer _ = linux.close(body.fd);
        const found = u.examine(
            sources,
            .{ .kernel = .{ .branch = branch, .old = old, .new = new } },
            body,
        ) orelse return fixes;
        fixes.cves = cve.kernelFixes(u.gpa, found, old, new) catch |err| {
            sources.items[sources.items.len - 1].@"error" = @errorName(err);
            return fixes;
        };
        return fixes;
    }

    /// GET url, by a fetcher, into cves/name. The file, recorded as a source
    /// with its sha256; or null, the source recorded with why not.
    pub fn fetch(
        u: *Update,
        sources: *std.ArrayList(Source),
        url: []const u8,
        comptime name: []const u8,
    ) !?cve.Body {
        try sources.append(u.gpa, .{ .url = url, .fetched = try u.nowText() });
        const source = &sources.items[sources.items.len - 1];
        const got = u.download(url, cves_dir ++ "/" ++ name) catch |err| {
            source.@"error" = if (err == error.FetchFailed) u.detail else @errorName(err);
            return null;
        };
        source.sha256 = try u.gpa.dupe(u8, &got.sha256);
        return .{ .fd = got.fd, .size = got.size };
    }

    /// GET url, by a fetcher as _update (cve.fetcher), into path, a file
    /// root makes for it: the file, open, with its size and sha256. A
    /// fetcher that says why not fails with error.FetchFailed, its word in
    /// detail.
    pub fn download(u: *Update, url: []const u8, path: [:0]const u8) !Download {
        const flags: linux.O = .{
            .ACCMODE = .RDWR,
            .CREAT = true,
            .TRUNC = true,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        };
        const fd: i32 = @intCast(try u.sys(
            linux.openat(linux.AT.FDCWD, path, flags, 0o600),
            "open a download",
        ));
        errdefer _ = linux.close(fd);
        const said = try u.ask(cve.fetcher, .{ update_id, net_root, url, fd }, 256, fetch_seconds);
        if (!std.mem.eql(u8, said.status, "ok")) {
            u.detail = said.status;
            return error.FetchFailed;
        }
        var h: std.crypto.hash.sha2.Sha256 = .init(.{});
        var buf: [64 << 10]u8 = undefined;
        var size: usize = 0;
        while (true) {
            const n = try u.sys(linux.pread(fd, &buf, buf.len, @intCast(size)), "read a download");
            if (n == 0) break;
            h.update(buf[0..n]);
            size += n;
        }
        return .{ .fd = fd, .size = size, .sha256 = std.fmt.bytesToHex(h.finalResult(), .lower) };
    }

    /// A small file, a manifest or its signature, by download, as bytes.
    fn downloadSmall(u: *Update, url: []const u8, path: [:0]const u8) ![]const u8 {
        return u.downloadMax(url, path, 1 << 20);
    }

    /// A file of at most max bytes, by download, as bytes.
    pub fn downloadMax(u: *Update, url: []const u8, path: [:0]const u8, max: usize) ![]const u8 {
        const got = try u.download(url, path);
        _ = linux.close(got.fd);
        if (got.size > max) return error.TooBig;
        return u.read(path);
    }

    /// The sha256 of a file, as hex.
    fn sha256Of(u: *Update, path: []const u8) ![64]u8 {
        // Read through, not into memory: it is a root image, every hour.
        var f = try Dir.cwd().openFile(u.io, path, .{});
        defer f.close(u.io);
        var h: std.crypto.hash.sha2.Sha256 = .init(.{});
        var buf: [64 << 10]u8 = undefined;
        var at: u64 = 0;
        while (true) {
            const n = try f.readPositionalAll(u.io, &buf, at);
            if (n == 0) break;
            h.update(buf[0..n]);
            at += n;
        }
        return std.fmt.bytesToHex(h.finalResult(), .lower);
    }

    /// What a reader found in body, for job: the lines after its "ok", or
    /// null, with why not recorded on the last source.
    fn examine(
        u: *Update,
        sources: *std.ArrayList(Source),
        job: cve.Job,
        body: cve.Body,
    ) ?[]const u8 {
        const source = &sources.items[sources.items.len - 1];
        const said = u.ask(
            cve.reader,
            .{ update_id, job, body },
            max_lines,
            read_seconds,
        ) catch |err| {
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
    pub fn child(
        u: *Update,
        comptime f: anytype,
        args: anytype,
        max: usize,
        seconds: i64,
    ) !sandbox.Exit {
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
        return sandbox.collect(u.gpa, @intCast(rc), pipe[0], max, seconds);
    }

    /// A CVE child's answer: it exits 0, and the first line it writes is its
    /// status, "ok" or why not, in printable ASCII; the rest is what it
    /// found. Anything else is an error.
    fn ask(u: *Update, comptime f: anytype, args: anytype, max: usize, seconds: i64) !Said {
        const e = try u.child(f, args, max, seconds);
        if (e.code != 0) return error.ChildFailed;
        const eol = std.mem.findScalar(u8, e.out, '\n') orelse return error.ChildSaidNothing;
        const status = e.out[0..eol];
        if (status.len == 0 or status.len > 128) return error.ChildSaidNonsense;
        for (status) |c| if (c < 0x20 or c > 0x7e) return error.ChildSaidNonsense;
        return .{ .status = status, .rest = e.out[eol + 1 ..] };
    }

    /// The fetcher's root: copies of the resolver's files, and nothing else.
    pub fn netRoot(u: *Update) !void {
        try Dir.cwd().createDirPath(u.io, net_root ++ "/etc");
        try Dir.cwd().createDirPath(u.io, cves_dir);
        inline for (.{ "resolv.conf", "hosts" }) |name| {
            Dir.cwd().copyFile(
                "/etc/" ++ name,
                Dir.cwd(),
                net_root ++ "/etc/" ++ name,
                u.io,
                .{},
            ) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
        }
    }

    /// A system call's result, or an error with what failed in detail.
    pub fn sys(u: *Update, rc: usize, comptime what: []const u8) !usize {
        return sandbox.sys(rc, what) catch |err| {
            u.detail = try u.gpa.print(
                "{s}: {s}",
                .{ what, sandbox.errnoName(sandbox.failed_errno) },
            );
            return err;
        };
    }

    pub const buildSlot = slot.buildSlot;
    pub const install = slot.install;

    pub const apkAdd = slot.apkAdd;

    /// A filesystem the mount broker mounts read-write for as long as it
    /// is held: fence's Landlock domain refuses this process mount(2)
    /// itself (cmd/mount-broker).
    pub fn held(u: *Update, word: broker.Word) !broker.Held {
        return broker.ask(word) catch |err| {
            const why = if (err == error.Refused) broker.refusal else @errorName(err);
            u.detail = try u.gpa.print("mount-broker, {s}: {s}", .{ @tagName(word), why });
            return err;
        };
    }

    fn isBad(u: *Update, build: []const u8) bool {
        const bad = u.read(state_dir ++ "/bad") catch return false;
        for (u.lines(bad) catch return false) |l| if (std.mem.eql(u8, l, build)) return true;
        return false;
    }

    /// One JSON line, in the log and on the console. Each counts on from
    /// the last, seq, and names it, prev: the first 16 hex digits of its
    /// SHA-256 (docs/design/update-policy.md, The audit log).
    pub fn record(u: *Update, fields: anytype) !void {
        const tail = try u.logTail();
        const Seq = struct { seq: u64 = 0 };
        var seq = (std.json.parseFromSliceLeaky(Seq, u.gpa, tail.last, .{
            .ignore_unknown_fields = true,
        }) catch Seq{}).seq;
        // A line a crash cut short is ended, counted, and chained over as it
        // is, so the chain goes on through it and shows where it broke.
        var last = tail.last;
        if (tail.torn.len > 0) {
            try u.append(log_path, "\n");
            last = try std.mem.concat(u.gpa, u8, &.{ tail.torn, "\n" });
            seq += 1;
        }
        const prev = policy.chain(last);
        var line: Io.Writer.Allocating = .init(u.gpa);
        try line.writer.print("{{\"time\":\"{s}\",\"host\":", .{try u.nowText()});
        try std.json.Stringify.value(u.host, .{}, &line.writer);
        try line.writer.print(",\"seq\":{d},\"prev\":\"{s}\"", .{
            seq + 1, if (last.len == 0) "" else &prev,
        });
        var rest: Io.Writer.Allocating = .init(u.gpa);
        try std.json.Stringify.value(fields, .{}, &rest.writer);
        try line.writer.print(",{s}\n", .{rest.written()[1..]});
        try u.append(log_path, line.written());
        // On the disk before anything follows: a log a power cut can take
        // lines from is no record of what the machine did.
        try u.syncPath(log_path);
        try Io.File.stdout().writeStreamingAll(
            u.io,
            try u.gpa.print("autoupdate: {s}", .{line.written()}),
        );
    }

    pub fn run(u: *Update, argv: []const []const u8) !void {
        _ = try u.output(argv);
    }

    fn output(u: *Update, argv: []const []const u8) ![]const u8 {
        const res = std.process.run(u.gpa, u.io, .{
            .argv = argv,
            .stdout_limit = .limited(max_tool_output),
            .stderr_limit = .limited(max_tool_output),
            .timeout = .{ .deadline = .fromNow(u.io, .{
                .raw = .fromSeconds(tool_seconds),
                .clock = .boot,
            }) },
        }) catch |err| {
            u.detail = try u.gpa.print("{s}: {s}", .{ argv[0], @errorName(err) });
            return err;
        };
        switch (res.term) {
            .exited => |code| if (code == 0) return res.stdout,
            else => {},
        }
        u.detail = try u.gpa.print(
            "{s}: {s}",
            .{ argv[0], std.mem.trim(u8, res.stderr[0..@min(res.stderr.len, 400)], " \n") },
        );
        return error.CommandFailed;
    }

    /// The log's last whole line, with its newline, or "" if there is none;
    /// and what follows it without a newline, a line a crash cut short.
    fn logTail(u: *Update) !struct { last: []const u8, torn: []const u8 } {
        var f = Dir.cwd().openFile(u.io, log_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return .{ .last = "", .torn = "" },
            else => return err,
        };
        defer f.close(u.io);
        const size = try f.length(u.io);
        const buf = try u.gpa.alloc(u8, @intCast(@min(size, 64 << 10)));
        const tail = buf[0..try f.readPositionalAll(u.io, buf, size - buf.len)];
        const end = if (std.mem.findScalarLast(u8, tail, '\n')) |i| i + 1 else 0;
        const start = if (end > 0) if (std.mem.findScalarLast(u8, tail[0 .. end - 1], '\n')) |i|
            i + 1
        else
            0 else 0;
        return .{ .last = tail[start..end], .torn = tail[end..] };
    }

    pub fn read(u: *Update, path: []const u8) ![]const u8 {
        return Dir.cwd().readFileAlloc(u.io, path, u.gpa, .limited(max_read));
    }

    pub fn write(u: *Update, path: []const u8, data: []const u8) !void {
        try Dir.cwd().writeFile(u.io, .{ .sub_path = path, .data = data });
    }

    pub fn append(u: *Update, path: []const u8, data: []const u8) !void {
        var f = try Dir.cwd().createFile(u.io, path, .{ .truncate = false });
        defer f.close(u.io);
        try f.writePositionalAll(u.io, data, try f.length(u.io));
    }

    pub fn listDir(u: *Update, path: []const u8) ![]const []const u8 {
        var d = try Dir.cwd().openDir(u.io, path, .{ .iterate = true });
        defer d.close(u.io);
        var names: std.ArrayList([]const u8) = .empty;
        var it = d.iterate();
        while (try it.next(u.io)) |e| try names.append(u.gpa, try u.gpa.dupe(u8, e.name));
        std.mem.sort([]const u8, names.items, {}, lessString);
        return names.items;
    }

    pub fn lines(u: *Update, text: []const u8) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        var it = std.mem.tokenizeScalar(u8, text, '\n');
        while (it.next()) |l| {
            const t = std.mem.trim(u8, l, " \r");
            if (t.len > 0) try out.append(u.gpa, t);
        }
        return out.items;
    }

    pub fn words(u: *Update, text: []const u8) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        var it = std.mem.tokenizeAny(u8, text, " \n");
        while (it.next()) |w| try out.append(u.gpa, w);
        if (out.items.len == 0) return error.Empty;
        return out.items;
    }

    /// Now, as RFC 3339 in UTC.
    pub fn nowText(u: *Update) ![]const u8 {
        return u.time(nowSecs(u.io));
    }

    pub fn time(u: *Update, secs: i64) ![]const u8 {
        return rfc3339(u.gpa, @intCast(secs));
    }

    /// data to path through a temporary name, so path is whole or absent,
    /// and on the disk, the rename too, before it returns.
    pub fn writeReplacing(u: *Update, path: []const u8, data: []const u8) !void {
        const tmp = try u.gpa.print("{s}.new", .{path});
        try u.write(tmp, data);
        try u.syncPath(tmp);
        try Dir.cwd().rename(tmp, Dir.cwd(), path, u.io);
        try u.syncPath(std.fs.path.dirname(path) orelse ".");
    }

    fn syncPath(u: *Update, path: []const u8) !void {
        const fd: i32 = @intCast(try u.sys(linux.openat(
            linux.AT.FDCWD,
            try u.gpa.dupeSentinel(u8, path, 0),
            .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true },
            0,
        ), "open to sync"));
        defer _ = linux.close(fd);
        _ = try u.sys(linux.fsync(fd), "fsync");
    }

    /// The newest max_reports reports kept, the rest removed: a staged
    /// build that a newer one replaced leaves one each hour it lasted.
    fn pruneReports(u: *Update) !void {
        const names = try u.listDir(state_dir ++ "/reports");
        if (names.len <= max_reports) return;
        // Named TIME-BUILD.json, so sorted by name is sorted by time.
        for (names[0 .. names.len - max_reports]) |name| {
            try Dir.cwd().deleteFile(
                u.io,
                try u.gpa.print("{s}/reports/{s}", .{ state_dir, name }),
            );
        }
    }
};

// --- the CVE children -------------------------------------------------------

const Said = struct { status: []const u8, rest: []const u8 };

// --- report -----------------------------------------------------------------

const Report = struct {
    time: []const u8,
    host: []const u8,
    build: []const u8,
    /// The update's tier, and why it boots when it does
    /// (docs/design/update-policy.md).
    tier: []const u8,
    why: []const u8,
    from: struct { slot: []const u8, release: []const u8, kernel: []const u8 },
    to: struct { slot: []const u8, kernel: []const u8 },
    packages: []const Change,
    package_cves: []const cve.PackageFix,
    kernel_cves: cve.KernelFixes,
    sources: []const Source,
};

/// What the other slot would be, and where it comes from.
pub const Plan = struct {
    build: []const u8,
    old_pkgs: []const Package,
    new_pkgs: []const Package,
    old_kernel: []const u8,
    new_kernel: []const u8,
    from: union(enum) {
        packages,
        release: struct { base: []const u8, name: []const u8, manifest: releases.Manifest },
    },
};

pub const Download = struct { fd: i32, size: usize, sha256: [64]u8 };

const Change = struct { name: []const u8, from: ?[]const u8, to: ?[]const u8 };
const Source = struct {
    url: []const u8,
    fetched: []const u8,
    sha256: ?[]const u8 = null,
    @"error": ?[]const u8 = null,
};

// --- pure functions, tested below -------------------------------------------

pub const Cmdline = struct {
    victim: []const u8 = "",
    slot: []const u8 = "",
    grubenv: []const u8 = "",
    esp: []const u8 = "",
};

pub fn parseCmdline(text: []const u8) Cmdline {
    var c: Cmdline = .{};
    var it = std.mem.tokenizeAny(u8, text, " \n");
    while (it.next()) |arg| {
        if (std.mem.startsWith(
            u8,
            arg,
            "werewolf.victim=",
        )) c.victim = arg["werewolf.victim=".len..];
        if (std.mem.startsWith(u8, arg, "werewolf.slot=")) c.slot = arg["werewolf.slot=".len..];
        if (std.mem.startsWith(
            u8,
            arg,
            "werewolf.grubenv=",
        )) c.grubenv = arg["werewolf.grubenv=".len..];
        if (std.mem.startsWith(u8, arg, "werewolf.esp=")) c.esp = arg["werewolf.esp=".len..];
    }
    return c;
}

fn uuidOf(spec: []const u8) []const u8 {
    return spec[0 .. std.mem.findScalar(u8, spec, ':') orelse spec.len];
}

pub fn pathOf(spec: []const u8) []const u8 {
    const i = std.mem.findScalar(u8, spec, ':') orelse return "";
    return spec[i + 1 ..];
}

pub fn parentDir(path: []const u8) []const u8 {
    return path[0 .. std.mem.findScalarLast(u8, path, '/') orelse 0];
}

pub const Package = struct { name: []const u8, version: []const u8, origin: []const u8 };

/// The packages in an apk installed database: P (name), V (version) and o
/// (origin, the source package) of each record; records end at a blank line.
pub fn parseInstalled(gpa: Allocator, text: []const u8) ![]const Package {
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
    return .{
        .name = p.name,
        .version = p.version,
        .origin = if (p.origin.len > 0) p.origin else p.name,
    };
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
        if (o == null or
            !std.mem.eql(
                u8,
                o.?,
                n.version,
            )) try out.append(gpa, .{ .name = n.name, .from = o, .to = n.version });
    }
    for (old) |o| {
        if (versionOf(
            new,
            o.name,
        ) == null) try out.append(gpa, .{ .name = o.name, .from = o.version, .to = null });
    }
    return out.items;
}

/// The first package, or the kernel, that changes would take to an older
/// version, in apk's order; or null.
fn backwards(
    changes: []const Change,
    old_kernel: []const u8,
    new_kernel: []const u8,
) ?[]const u8 {
    for (changes) |c| {
        const from = c.from orelse continue;
        const to = c.to orelse continue;
        if (cve.apkOrder(to, from) == .lt) return c.name;
    }
    const prefix = "linux-virt-";
    if (std.mem.startsWith(u8, old_kernel, prefix) and
        std.mem.startsWith(u8, new_kernel, prefix) and
        cve.apkOrder(
            new_kernel[prefix.len..],
            old_kernel[prefix.len..],
        ) == .lt) return "linux-virt";
    return null;
}

test backwards {
    const up = [_]Change{.{ .name = "curl", .from = "8.17.0-r0", .to = "8.17.0-r1" }};
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        backwards(&up, "linux-virt-6.18.55-r0", "linux-virt-6.18.56-r0"),
    );
    const down = [_]Change{
        .{ .name = "zlib", .from = null, .to = "1.3.2-r0" },
        .{ .name = "openssl", .from = "3.5.4-r0", .to = "3.5.3-r0" },
    };
    try std.testing.expectEqualStrings(
        "openssl",
        backwards(&down, "linux-virt-6.18.55-r0", "linux-virt-6.18.55-r0").?,
    );
    try std.testing.expectEqualStrings(
        "linux-virt",
        backwards(&up, "linux-virt-6.18.55-r0", "linux-virt-6.18.9-r0").?,
    );
}

/// Source packages present before and after, at different versions.
pub fn diffOrigins(
    gpa: Allocator,
    old: []const Package,
    new: []const Package,
) ![]const cve.OriginChange {
    var out: std.ArrayList(cve.OriginChange) = .empty;
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

fn rfc3339(gpa: Allocator, secs: u64) ![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return gpa.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,              md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
}

pub fn appendUnique(gpa: Allocator, list: *std.ArrayList([]const u8), s: []const u8) !void {
    for (list.items) |x| if (std.mem.eql(u8, x, s)) return;
    try list.append(gpa, s);
}

fn lessString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

// --- tests ------------------------------------------------------------------

const testing = std.testing;

test parseCmdline {
    const c = parseCmdline(
        "console=hvc0 werewolf.victim=abcd:/var/lib/werewolf werewolf.slot=b " ++
            "werewolf.grubenv=ef01:/boot/grub/grubenv\n",
    );
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
    const old = try parseInstalled(
        a,
        "P:busybox-full\nV:1.37.0-r30\no:busybox\n\nP:openssl-4.0-libcrypto\nV:4.0.2-r0\no:opens" ++
            "sl-4.0\n\nP:gone\nV:1-r0\n",
    );
    const new = try parseInstalled(
        a,
        "P:openssl-4.0-libcrypto\nV:4.0.3-r3\no:openssl-4.0\n\nP:busybox-full\nV:1.38.0-r2\no:bu" ++
            "sybox\n\nP:fresh\nV:2-r0\n\n",
    );
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

test {
    _ = sandbox;
    _ = cve;
    _ = releases;
    _ = tiers;
    _ = stage;
    _ = slot;
    _ = @import("apk.zig");
}

test rfc3339 {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings(
        "2026-10-06T12:42:29Z",
        try rfc3339(arena.allocator(), 1791290549),
    );
}
