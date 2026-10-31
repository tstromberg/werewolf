//! slot-update is the autoupdater. It builds or fetches the other slot, stages
//! it to boot once when its fixes make it due, and logs whether it held.
//!
//!     slot-update [check]   stage the other slot if anything newer exists
//!     slot-update outcome   after a reboot, log whether the last update held
//!
//! See slot-update.8.md and docs/updater.md.

const std = @import("std");
const apk = @import("apk");
const ipe = @import("ipe");
const prebuilt = @import("prebuilt");
const images = @import("images.zig");
pub const Io = std.Io;
pub const Dir = Io.Dir;
pub const Allocator = std.mem.Allocator;
pub const linux = std.os.linux;
pub const sandbox = @import("sandbox");
const cmdline = @import("cmdline");
pub const verity = @import("verity");
pub const policy = @import("update-policy");
const werewolf_repository = @import("package").repository;
pub const cve = @import("cve.zig");
const kernelVersion = @import("cve").kernelVersion;
const kernelPackage = @import("cve").kernelPackage;
pub const tiers = @import("tiers.zig");
const stage = @import("stage.zig");
const slot = @import("slot.zig");
const installer = @import("installer.zig");
const workers = @import("workers.zig");
const control = @import("control.zig");
const owner = @import("owner.zig");
var owner_paused = false;
const broker = @import("broker");
const Pending = stage.Pending;

pub const meta_dir = "/usr/share/werewolf";
pub const state_dir = "/data/svc/autoupdate";
pub const coord_dir = state_dir ++ "/state";
pub const work_dir = state_dir ++ "/work";
pub const cache_dir = state_dir ++ "/cache";
pub const log_path = state_dir ++ "/log";
/// checked_path exists once a check has finished, ending the first boot.
const checked_path = coord_dir ++ "/checked";
/// pending_path holds the staged build and when each tier of its fixes was
/// first seen (stage.Pending).
pub const pending_path = coord_dir ++ "/pending";
/// attempt_path holds "SLOT BUILD BOOT": the slot armed to boot once, its
/// build, and the boot_id that armed it (attemptOf).
pub const attempt_path = coord_dir ++ "/attempt";
/// lock_path is flocked while a pass changes state, so a check run by hand
/// and the daemon's never interleave.
pub const lock_path = coord_dir ++ "/lock";
/// rebooted_path holds the RFC 3339 time of the last update reboot. outcome
/// leaves it, so the next update reboot waits an hour after it. A cold boot
/// is not an update reboot and does not move the time.
pub const rebooted_path = coord_dir ++ "/rebooted";
/// feed_path holds the last tiers feed taken; feed_sig_path its signature.
pub const feed_path = coord_dir ++ "/cve-tiers.json";
pub const feed_sig_path = feed_path ++ ".sig";
/// feed_serial_path holds the newest feed serial taken, so a feed never goes
/// backwards.
pub const feed_serial_path = feed_path ++ ".serial";
/// max_feed is the size limit for a feed or its signature.
pub const max_feed = 16 << 20;
/// max_reports is how many reports to keep: years of updates at a few a week.
const max_reports = 500;
/// form_policy and operator_policy are the update settings, the operator's
/// applied over the form's (lib/update-policy.zig).
pub const form_policy = "/etc/werewolf/update-policy.json";
pub const operator_policy = "/run/config/update-policy.json";
/// ready_path tells slot-keep that the updater works (see daemon).
const ready_path = "/run/werewolf/updater-ready";
const kernel_cves_url = "https://git.kernel.org/pub/scm/linux/security/vulns.git/snapshot/" ++
    "vulns-master.tar.gz";
pub const max_read = 256 << 20;

/// update_id is _update's uid, which the fetching and parsing children run as
/// (forms/prod/form.yaml).
pub const update_id: u32 = 69;
/// net_root is the fetcher's chroot; cves_dir receives fetched files.
const net_root = work_dir ++ "/net";
pub const cves_dir = work_dir ++ "/cves";
/// apk_seconds bounds each apk invocation.
/// max_retry_ms is the total time retries may wait (Update.again).
const max_retry_ms = 120_000;
pub const apk_seconds = 1800;
/// tool_seconds and max_tool_output bound a tool that root runs (mkfs.erofs,
/// zstd, apk offline). A tool that hangs is killed and the pass
/// fails, to be retried.
pub const tool_seconds = 1800;
const max_tool_output = 1 << 20;
/// max_apk_file bounds each index or package apk's fetcher writes. The
/// largest package (a JDK) is a few hundred megabytes.
pub const max_apk_file = 1 << 30;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    // runsv starts /etc/sv/autoupdate/run, a link to this program, with no
    // arguments. That means daemon.
    // A person running it with no arguments means check.
    const as_service = args.len == 1 and std.mem.eql(u8, std.fs.path.basename(args[0]), "run");
    const mode = if (args.len == 2 or (args.len == 3 and std.mem.eql(u8, args[1], "try")))
        args[1]
    else if (as_service)
        "daemon"
    else if (args.len == 1)
        "check"
    else
        "";
    if (std.mem.eql(u8, mode, "daemon")) {
        broker.keepOnlyClient(.updater);
        daemon();
    }
    broker.keepOnlyClient(null);
    if (!std.mem.eql(u8, mode, "check") and !std.mem.eql(u8, mode, "outcome") and
        !std.mem.eql(u8, mode, "try"))
    {
        std.debug.print("usage: slot-update [check|outcome|daemon|try [DECLARATION-HASH]]\n", .{});
        std.process.exit(2);
    }

    try control.submit(init.io, gpa, mode, if (args.len == 3) args[2] else null);
}

fn operator(io: Io, request: control.Request) !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    var u: Update = .{ .io = io, .gpa = arena.allocator() };
    u.setup() catch |err| {
        failed(&u, err);
        return err;
    };
    (switch (request.command) {
        .@"try" => slot.tryOther(&u, request.declaration),
        .check => blk: {
            var settings: policy.Settings = .{};
            try u.loadPolicy(&settings);
            break :blk u.check(&settings, false);
        },
        .outcome => u.outcome(),
    }) catch |err| {
        failed(&u, err);
        return err;
    };
}

fn requested(io: Io, listener: i32) bool {
    if (ownerRequested(io)) return true;
    var buf: [control.limit + 1]u8 = undefined;
    const next = control.accept(listener, &buf) orelse return false;
    operator(io, next.request) catch |err| {
        control.reply(next.fd, err);
        return true;
    };
    control.reply(next.fd, null);
    return true;
}

/// Host operators use the same supervised, unprivileged coordinator and broker
/// as root's local socket. This channel accepts no executable or filesystem path.
fn ownerRequested(io: Io) bool {
    const request = workers.owner_channel.receive() orelse return false;
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    if (request.command == .status) {
        ownerStatus(io, gpa, request.id) catch |err| ownerReply(gpa, request.id, err);
        return true;
    }
    switch (request.command) {
        .pause => owner_paused = true,
        .@"resume" => owner_paused = false,
        .check, .outcome, .@"try" => operator(io, .{
            .command = std.meta.stringToEnum(control.Command, @tagName(request.command)).?,
            .declaration = request.declaration,
        }) catch |err| {
            ownerReply(gpa, request.id, err);
            return true;
        },
        .status => unreachable,
    }
    ownerReply(gpa, request.id, null);
    return true;
}

fn ownerReply(gpa: Allocator, id: []const u8, err: ?anyerror) void {
    const response = std.json.Stringify.valueAlloc(gpa, .{
        .id = id,
        .ok = err == null,
        .@"error" = if (err) |e| @errorName(e) else null,
    }, .{}) catch return;
    workers.owner_channel.send(std.mem.concat(gpa, u8, &.{ response, "\n" }) catch return);
}

fn ownerStatus(io: Io, gpa: Allocator, id: []const u8) !void {
    const Check = struct { id: []const u8, result: enum { pass, fail, skip } };
    const OwnerPosture = struct { checks: []const Check };
    const raw = Dir.cwd().readFileAlloc(
        io,
        "/run/werewolf/posture.json",
        gpa,
        .limited(4 << 20),
    ) catch |err|
        if (err == error.FileNotFound) null else return err;
    const report = if (raw) |text|
        try std.json.parseFromSliceLeaky(
            OwnerPosture,
            gpa,
            text,
            .{ .ignore_unknown_fields = true },
        )
    else
        null;
    var u: Update = .{ .io = io, .gpa = gpa };
    const boot_id = try u.bootId();
    var refused: cmdline.Failure = .{};
    const cmd = cmdline.parse(workers.boot_line, &refused) orelse return error.BadCommandLine;
    const other_cmdline = if (cmd.slot) |boot_slot|
        Dir.cwd().readFileAlloc(
            io,
            try gpa.print("/boot/slot/{s}/cmdline", .{@tagName(boot_slot.other())}),
            gpa,
            .limited(4096),
        ) catch |err|
            if (err == error.FileNotFound) null else return err
    else
        null;
    const response = try std.json.Stringify.valueAlloc(gpa, .{
        .format = "werewolf-owner-status/1",
        .id = id,
        .ok = true,
        .boot_id = boot_id,
        .cmdline = workers.boot_line,
        .committed = fileExists(io, "/run/werewolf/committed"),
        .ready = fileExists(io, ready_path),
        .paused = owner_paused,
        .checks = if (report) |r| r.checks else &.{},
        .other_cmdline = other_cmdline,
    }, .{});
    workers.owner_channel.send(try std.mem.concat(gpa, u8, &.{ response, "\n" }));
}

fn fileExists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// failed logs err. It leaves the work directory alone: a pass that failed
/// with error.Busy must not delete the work of the pass holding the lock.
fn failed(u: *Update, err: anyerror) void {
    u.record(.{
        .event = "error",
        .step = u.step,
        .@"error" = @errorName(err),
        .detail = u.detail,
    }) catch |log_err| std.debug.print("slot-update: {s} {s}: {s}; the log: {s}\n", .{
        u.step,
        @errorName(err),
        u.detail,
        @errorName(log_err),
    });
}

/// daemon is the autoupdate service. After setup succeeds it writes
/// ready_path; slot-keep commits no slot before that, since a slot whose
/// updater cannot start could never be updated again. Once this slot has
/// committed, it loads the settings, runs outcome, then checks at once and
/// every update-every seconds, sleeping until the next notice or check
/// (bootIfDue). A check that fails before this boot has finished one, and
/// before the machine has been up ten minutes, is tried again in 30
/// seconds. Off a slot it parks.
fn daemon() noreturn {
    var threaded: Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    // Disable Speculative Store Bypass for the daemon and every child, since
    // apk and mkfs.erofs parse network data. Errors mean the CPU has no
    // control, so ignore them.
    _ = linux.prctl(
        @backingInt(linux.PR.SET_SPECULATION_CTRL),
        linux.PR.SPEC_STORE_BYPASS,
        linux.PR.SPEC_FORCE_DISABLE,
        0,
        0,
    );
    const listener = control.listen() catch park(io, "cannot start operator request listener");
    workers.start(io) catch |err| {
        std.debug.print(
            "autoupdate: worker setup: {s}: {s} ({s})\n",
            .{ @errorName(err), sandbox.failed, sandbox.errnoName(sandbox.failed_errno) },
        );
        park(io, "cannot confine update coordinator");
    };
    // A machine that has never finished a check boots its first update at
    // once. Test "never finished", not "never logged": a first check that
    // failed before the network was up still logs.
    var ctx: Ctx = .{ .first_boot = neverChecked(io) };
    switch (pass(io, .setup, &ctx)) {
        .ok => broker.updaterReady() catch |err| {
            std.debug.print(
                "autoupdate: cannot write {s}: {s}\n",
                .{ ready_path, @errorName(err) },
            );
        },
        .not_a_slot => park(io, "not booted from a slot, staying down"),
        .failed => {},
    }
    while (true) {
        if (!workers.alive()) linux.exit_group(1);
        Dir.cwd().access(io, "/run/werewolf/committed", .{}) catch {
            _ = requested(io, listener);
            io.sleep(.fromSeconds(1), .awake) catch {};
            continue;
        };
        break;
    }
    const every = updateEvery(io);
    _ = pass(io, .policy, &ctx);
    _ = pass(io, .outcome, &ctx);
    // Allow the fresh boot to finish becoming reachable before autonomous replacement.
    // Operator requests remain immediate and are processed before a scheduled pass.
    var next_check = nowSecs(io) + 10;
    var boot_checked = false;
    while (true) {
        if (!workers.alive()) linux.exit_group(1);
        if (requested(io, listener)) continue;
        if (owner_paused) {
            io.sleep(.fromSeconds(1), .awake) catch {};
            continue;
        }
        if (nowSecs(io) >= next_check) {
            if (pass(io, .check, &ctx) == .ok) {
                boot_checked = true;
                if (ctx.first_boot) {
                    ctx.first_boot = false;
                    Dir.cwd().writeFile(io, .{ .sub_path = checked_path, .data = "" }) catch |err|
                        std.debug.print(
                            "autoupdate: cannot write {s}: {s}\n",
                            .{ checked_path, @errorName(err) },
                        );
                }
                next_check = nowSecs(io) + every;
            } else if (!boot_checked and bootSecs() < boot_retry_for) {
                next_check = nowSecs(io) + boot_retry_every;
            } else next_check = nowSecs(io) + every;
        }
        if (!ctx.rebooting) _ = pass(io, .boot, &ctx);
        // Poll operator requests without changing the scheduled check or reboot deadline.
        io.sleep(.fromSeconds(1), .awake) catch {};
    }
}

/// boot_retry_every is how soon a boot's check is tried again when it
/// failed. boot_retry_for is how long after boot those retries last.
const boot_retry_every = 30;
const boot_retry_for = 10 * 60;

/// Ctx is the daemon's state between passes: the settings, read once;
/// whether no check has finished yet; seconds until the next notice or
/// check; whether a reboot was requested; and the countdown for the
/// staged build, which restarts when that build changes.
pub const Ctx = struct {
    settings: policy.Settings = .{},
    first_boot: bool = false,
    due_in: ?i64 = null,
    rebooting: bool = false,
    notice_build: [64]u8 = @splat(0),
    notice_len: u8 = 0,
    reboot_at: ?i64 = null,
    /// spoken is the lead, in seconds, of the notice already sent.
    spoken: ?i64 = null,

    pub fn clearNotice(ctx: *Ctx) void {
        ctx.notice_len = 0;
        ctx.reboot_at = null;
        ctx.spoken = null;
    }

    pub fn noticeIs(ctx: *const Ctx, build: []const u8) bool {
        return ctx.notice_len == build.len and
            std.mem.eql(u8, ctx.notice_build[0..ctx.notice_len], build);
    }

    pub fn remember(ctx: *Ctx, build: []const u8) void {
        const n = @min(build.len, ctx.notice_build.len);
        @memcpy(ctx.notice_build[0..n], build[0..n]);
        ctx.notice_len = @intCast(n);
    }
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

/// neverChecked reports whether checked_path is absent.
fn neverChecked(io: Io) bool {
    Dir.cwd().access(io, checked_path, .{}) catch |err| return err == error.FileNotFound;
    return false;
}

pub fn nowSecs(io: Io) i64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

/// bootSecs returns CLOCK_BOOTTIME in seconds, or 0 on error.
pub fn bootSecs() i64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
    return ts.sec;
}

/// updateEvery returns the seconds between checks: the form's
/// /etc/werewolf/update-every, or an hour, clamped to five minutes..a week.
fn updateEvery(io: Io) i64 {
    var buf: [32]u8 = undefined;
    const n = Dir.cwd().readFile(io, "/etc/werewolf/update-every", &buf) catch return 3600;
    const every = std.fmt.parseInt(i64, std.mem.trim(u8, n, " \n"), 10) catch return 3600;
    return std.math.clamp(every, 5 * 60, 7 * 24 * 3600);
}

/// park logs why and marks the service down so runsv does not restart it.
fn park(io: Io, why: []const u8) noreturn {
    if (linux.geteuid() == 0) sandbox.keepOnly(0) catch {};
    Io.File.stdout().writeStreamingAll(io, "autoupdate: ") catch {};
    Io.File.stdout().writeStreamingAll(io, why) catch {};
    Io.File.stdout().writeStreamingAll(io, "\n") catch {};
    workers.park();
}

pub const Update = struct {
    io: Io,
    gpa: Allocator,
    host: []const u8 = "",
    cmd: cmdline.Cmdline = .{},
    /// slot is the slot this boot runs; other is the one an update writes.
    slot: []const u8 = "a",
    other: []const u8 = "b",
    step: []const u8 = "start",
    /// detail is what the last failed command said, for the error event.
    detail: []const u8 = "",
    image: ?images.Verified = null,

    pub fn setup(u: *Update) !void {
        Dir.cwd().access(u.io, state_dir ++ "/reports", .{}) catch
            try Dir.cwd().createDirPath(u.io, state_dir ++ "/reports");
        // init always sets the kernel's hostname, configured or not.
        const uts = std.posix.uname();
        u.host = try u.gpa.dupe(u8, std.mem.sliceTo(&uts.nodename, 0));
        // Parse as stage0 does (lib/cmdline.zig). werewolf.slot,
        // werewolf.slots and werewolf.esp identify a disk slot.
        var refused: cmdline.Failure = .{};
        u.cmd = cmdline.parse(
            if (workers.boot_line.len > 0) workers.boot_line else try u.read("/proc/cmdline"),
            &refused,
        ) orelse
            return error.BadCommandLine;
        const s = u.cmd.slot orelse return error.NotBootedFromASlot;
        if (u.cmd.esp == null) return error.NotBootedFromASlot;
        u.slot = @tagName(s);
        u.other = @tagName(s.other());
    }

    // --- outcome -----------------------------------------------------------

    /// outcome judges the last update from attempt_path: if this boot runs
    /// the attempted slot, the update held; otherwise it rolled back and its
    /// build is added to the bad list so it is never tried again.
    pub fn outcome(u: *Update) !void {
        // Until this slot commits it may still roll back, so judging now
        // could log a bad build as good.
        Dir.cwd().access(u.io, "/run/werewolf/committed", .{}) catch return error.NotCommitted;
        const held_lock = try u.lock();
        defer _ = linux.close(held_lock);
        const attempt = try u.attemptOf() orelse return;
        // Armed during this boot, so not tried yet (the daemon restarted).
        if (std.mem.eql(u8, attempt.boot, try u.bootId())) return;
        const tried = attempt.slot;
        const build = attempt.build;
        const release = std.mem.trim(u8, try u.read(meta_dir ++ "/release"), "\n");
        const down = u.downtime();
        if (std.mem.eql(u8, tried, u.slot)) {
            try u.record(.{
                .event = "commit",
                .slot = u.slot,
                .build = build,
                .release = release,
                .waited = try u.waited(),
                .down = down,
            });
        } else {
            try u.append(coord_dir ++ "/bad", try u.gpa.print("{s}\n", .{build}));
            try u.record(.{
                .event = "rollback",
                .failed = tried,
                .running = u.slot,
                .build = build,
                .release = release,
                .down = down,
            });
        }
        // rebooted stays, so a second update reboot waits an hour after it.
        Dir.cwd().deleteFile(u.io, pending_path) catch {};
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

    /// check plans the other slot, from the form's latest signed release if
    /// CI publishes the form, else from what Wolfi and Alpine have now. It
    /// then finds the CVEs fixed, writes the slot and a report, and stages
    /// the slot to boot once when due (bootIfDue).
    pub fn check(u: *Update, s: *const policy.Settings, first_boot: bool) !void {
        const io = u.io;
        // Until this slot commits, the other slot is the fallback and must
        // not be written.
        Dir.cwd().access(io, "/run/werewolf/committed", .{}) catch return error.NotCommitted;
        const held_lock = try u.lock();
        defer _ = linux.close(held_lock);
        try workers.reset(u);
        defer workers.reset(u) catch {};
        try u.netRoot();
        const arch = std.mem.trim(u8, try u.read("/etc/apk/arch"), "\n");
        const release = std.mem.trim(u8, try u.read(meta_dir ++ "/release"), "\n");
        const image_update = try u.needsSignedImage();
        const plan = ((if (image_update)
            images.plan(u, arch)
        else
            u.packagesPlan(arch, release)) catch |err| {
            try u.writeReplacing(coord_dir ++ "/held", @errorName(err));
            return err;
        }) orelse {
            Dir.cwd().deleteFile(io, coord_dir ++ "/held") catch {};
            return;
        };
        Dir.cwd().deleteFile(io, coord_dir ++ "/held") catch {};

        if (u.isBad(plan.build)) {
            return u.record(.{
                .event = "skip",
                .build = plan.build,
                .reason = "this build rolled back before",
            });
        }
        const staged = try u.readPending();
        if (staged) |p| if (std.mem.eql(u8, p.build, plan.build) and try u.armed(p)) {
            // Already staged: re-tier its fixes and log when it boots.
            const now_p = try u.retier(s, p, plan);
            const d = try u.dueOf(s, now_p);
            return u.record(.{
                .event = "check",
                .slot = u.slot,
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
        // Werewolf's package feeds have no Wolfi security.json.
        const repo = securityRepository(try u.words(try u.read("/etc/apk/repositories"))) orelse
            return error.NoWolfiRepository;
        const applied = if (u.image != null)
            try images.applied(u)
        else
            localChanged(plan.old_pkgs, plan.new_pkgs);
        const package_cves: []const cve.PackageFix = if (applied)
            &.{}
        else
            try u.packageCves(&sources, repo, plan.old_pkgs, plan.new_pkgs);
        const kernel_changed = !std.mem.eql(u8, plan.old_kernel, plan.new_kernel);
        const kernel_cves = if (kernel_changed and !applied)
            try u.kernelCves(&sources, plan.old_kernel, plan.new_kernel)
        else
            cve.KernelFixes{};

        // Tier before installing, so nothing after the install can fail for
        // want of the feed.
        u.step = "stage";
        const feed = if (applied) null else try u.tiersFeed();
        const fixes = try tiers.tiersOf(u.gpa, feed, .{
            .changes = try diffOrigins(u.gpa, plan.old_pkgs, plan.new_pkgs),
            .package_cves = package_cves,
            .kernel_cves = kernel_cves,
            .old_kernel = plan.old_kernel,
            .new_kernel = plan.new_kernel,
            .advisories = plan.advisories,
            .have = try u.ownAdvisories(),
        });
        if (!image_update) {
            try u.requireLocalUpdate();
            try workers.build(u, plan.new_kernel);
        }
        // Write pending only after install arms the new build, so a failed
        // install keeps the first-seen times. install removes attempt first,
        // so bootIfDue boots nothing meanwhile. Seen is stamped here, not
        // before the install: a first check's minute of notice has to still
        // be ahead when the slot can actually boot.
        try u.install(plan.build);
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
        next.applied = if (applied) try u.time(now) else null;
        for (std.enums.values(policy.Tier)) |t| if (fixes.first.get(t)) |f| {
            const seen = next.tier(t);
            if (seen.* == null) seen.* = .{
                .seen = try u.time(now),
                .subject = f.subject,
                .evidence = f.evidence,
            };
        };
        try u.writeReplacing(pending_path, try std.json.Stringify.valueAlloc(u.gpa, next, .{}));
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
            .from = .{ .slot = u.slot, .release = release, .kernel = plan.old_kernel },
            .to = .{ .slot = u.other, .kernel = plan.new_kernel },
            .packages = changes,
            .package_cves = package_cves,
            .kernel_cves = kernel_cves,
            .advisories = try tiers.missing(u.gpa, plan.advisories, try u.ownAdvisories()),
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
            .from = u.slot,
            .build = plan.build,
            .kernel = try u.gpa.print("{s} -> {s}", .{ plan.old_kernel, plan.new_kernel }),
            .packages = changes.len,
            .cves = cve_count,
            .tier = @tagName(d.tier),
            .seen = next.seenTimes(),
            .fixes = .{
                .urgent = fixes.count.get(.urgent),
                .high = fixes.count.get(.high),
                .medium = fixes.count.get(.medium),
                .low = fixes.count.get(.low),
            },
            .due = try u.time(d.at),
            .due_in = d.at - now,
            .why = why,
            .report = report_path,
        });
    }

    /// packagesPlan installs what Wolfi and werewolf have now into
    /// work_dir/root and work_dir/kernel and returns the plan. It returns
    /// null, after logging, if nothing changed or a version would go back.
    fn packagesPlan(u: *Update, arch: []const u8, release: []const u8) !?Plan {
        u.step = "userland";
        try workers.packages(u, .{
            .kernel = false,
            .arch = arch,
            .packages = try u.words(try u.read("/etc/apk/world")),
        });
        const repositories = try u.read("/etc/apk/repositories");
        for (@import("package").pinned_repositories) |feed| {
            if (std.mem.find(u8, repositories, feed) == null) continue;
            u.step = "pinned-feed";
            try u.netRoot();
            const index_path = work_dir ++ "/feed-index.tar.gz";
            const url = try u.gpa.print("{s}/{s}/APKINDEX.tar.gz", .{ feed, arch });
            const got = try u.downloadLimit(url, index_path, 64 << 20);
            _ = linux.close(got.fd);
            const trust = [_]apk.Trusted{.{
                .name = @import("package").repository_key,
                .key = try apk.parseKey(u.gpa, @import("package").repository_pem),
            }};
            if (try apk.feedFallback(
                u.gpa,
                &trust,
                try u.read(index_path),
                try slot.readIn(u, work_dir ++ "/root", "lib/apk/db/installed"),
            )) |name| {
                u.detail = try u.gpa.print(
                    "{s}: resolved outside the signed feed {s}",
                    .{ name, feed },
                );
                return error.FeedPackageRequired;
            }
        }
        u.step = "kernel";
        // linux-werewolf, from the repository the image's kernel came from,
        // trusting werewolf's key alone: Wolfi's never vouches for a kernel.
        const repository = std.mem.trim(u8, try u.read(meta_dir ++ "/kernel-repository"), "\n");
        try workers.packages(u, .{
            .kernel = true,
            .arch = arch,
            .repository = repository,
            .packages = &.{"linux-werewolf"},
        });
        u.step = "kernel-config";
        try slot.checkKernelConfig(u, work_dir ++ "/kernel");

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
            "linux-werewolf-{s}",
            .{versionOf(kernel_pkgs, "linux-werewolf") orelse return error.NoKernel},
        );
        // An index carries no date, so apk would install an older signed
        // index as happily as a newer one. Refuse any downgrade.
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
                .slot = u.slot,
                .release = release,
                .result = "current",
            });
            return null;
        }
        // werewolf's own fixes, as werewolf-advisories lists them in the new
        // root; an image built from a tree has none.
        const listed = slot.readIn(
            u,
            work_dir ++ "/root",
            "usr/share/werewolf/advisories",
        ) catch |err|
            switch (err) {
                error.FileNotFound => "",
                else => return err,
            };
        var bad: policy.BadLine = .{};
        const advisories = policy.parseAdvisories(u.gpa, listed, &bad) catch |err| {
            u.detail = try u.gpa.print("advisories:{d}: {s}", .{ bad.n, bad.line });
            return err;
        };
        return .{
            .build = try buildHash(u.gpa, new_pkgs, new_kernel),
            .old_pkgs = old_pkgs,
            .new_pkgs = new_pkgs,
            .old_kernel = old_kernel,
            .new_kernel = new_kernel,
            .advisories = advisories,
        };
    }

    /// slotCmdline returns the new slot's kernel arguments, as compose wrote
    /// them into its root from its forms. It refuses anything but one line
    /// of printable ASCII without backslashes, so a loader entry and GRUB's
    /// environment hold it intact.
    pub fn slotCmdline(u: *Update) ![]const u8 {
        if (u.image != null) return prebuilt.cmdline(try u.read(work_dir ++ "/slot/cmdline"));
        const text = try slot.readIn(u, work_dir ++ "/root", "usr/share/werewolf/cmdline");
        const line = std.mem.trimEnd(u8, text, "\n");
        for (line) |c| if (c < ' ' or c > '~' or c == '\\') return error.BadCmdline;
        return line;
    }

    // --- CVEs --------------------------------------------------------------
    // Root never fetches or parses a CVE source. A fetcher, as _update, writes
    // the body to a file root opened; root hashes it for the report; a reader,
    // as _update with no network or files, parses it and sends a line per
    // CVE, which root checks field by field before using it.

    /// packageCves returns the CVEs that Wolfi's security.json says the
    /// package changes fix (see cve.zig). The file is unsigned, so it only
    /// informs the report. Fetch or parse failures are recorded in sources.
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

    /// kernelCves returns the CVEs whose fix for the new kernel's branch is
    /// in (old, new], from the kernel CNA's records on git.kernel.org. Records
    /// often lag a fix by weeks, so this is only what was known at update time.
    fn kernelCves(
        u: *Update,
        sources: *std.ArrayList(Source),
        old_kernel: []const u8,
        new_kernel: []const u8,
    ) !cve.KernelFixes {
        const old = kernelVersion(old_kernel) orelse return error.BadKernelVersion;
        const new = kernelVersion(new_kernel) orelse return error.BadKernelVersion;
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

    /// fetch downloads url into cves_dir/name and records it in sources with
    /// its sha256. On failure it records why and returns null.
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

    /// download has a fetcher (cve.fetcher), running as _update, GET url into
    /// path, a file root creates. It returns the open file, its size and
    /// sha256. Transient failures are retried while `again` allows, so a
    /// network blip costs a retry, not an hour. Otherwise it returns
    /// error.FetchFailed with the fetcher's reason in detail.
    pub fn download(u: *Update, url: []const u8, path: [:0]const u8) !Download {
        return u.downloadLimit(url, path, 256 << 20);
    }

    pub fn downloadLimit(
        u: *Update,
        url: []const u8,
        path: [:0]const u8,
        maximum: usize,
    ) !Download {
        var b: Backoff = .{};
        while (true) {
            if (u.downloadOnce(url, path, maximum)) |got| return got else |err| {
                if (err != error.FetchFailed or !transient(u.detail) or
                    !u.again(&b, url)) return err;
            }
        }
    }

    fn downloadOnce(u: *Update, url: []const u8, path: [:0]const u8, maximum: usize) !Download {
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
        const said = saidOf(try workers.fetch(u, url, fd, maximum)) catch |err| {
            u.detail = url;
            return err;
        };
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
            if (size > maximum) return error.TooBig;
        }
        return .{ .fd = fd, .size = size, .sha256 = std.fmt.bytesToHex(h.finalResult(), .lower) };
    }

    /// Backoff holds the next retry's base wait and the total waited so far.
    pub const Backoff = struct { wait_ms: u64 = 2000, waited_ms: u64 = 0 };

    /// again logs and sleeps before a retry, and returns false once the wait
    /// would pass max_retry_ms. The wait is random in [0.5, 1.5) of b's base,
    /// which doubles each time, so machines that failed together do not
    /// retry in step.
    pub fn again(u: *Update, b: *Backoff, what: []const u8) bool {
        var r: [8]u8 = undefined;
        u.io.random(&r);
        const ms = b.wait_ms / 2 + std.mem.readInt(u64, &r, .little) % b.wait_ms;
        if (b.waited_ms + ms > max_retry_ms) return false;
        std.debug.print("autoupdate: {s}: {s}; again in {d} ms\n", .{ what, u.detail, ms });
        u.io.sleep(.fromMilliseconds(@intCast(ms)), .awake) catch {};
        b.waited_ms += ms;
        b.wait_ms *= 2;
        return true;
    }

    /// downloadSmall downloads a file of at most 1 MiB, such as a manifest or
    /// signature, and returns its bytes.
    fn downloadSmall(u: *Update, url: []const u8, path: [:0]const u8) ![]const u8 {
        return u.downloadMax(url, path, 1 << 20);
    }

    /// downloadMax downloads url to path and returns its bytes, or
    /// error.TooBig if it exceeds max.
    pub fn downloadMax(u: *Update, url: []const u8, path: [:0]const u8, max: usize) ![]const u8 {
        const got = try u.downloadLimit(url, path, max);
        defer _ = linux.close(got.fd);
        if (got.size > max) return error.TooBig;
        const f: Io.File = .{ .handle = got.fd, .flags = .{ .nonblocking = false } };
        const buf = try u.gpa.alloc(u8, @intCast(got.size));
        if (try f.readPositionalAll(u.io, buf, 0) != buf.len) return error.UnexpectedEof;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(buf, &digest, .{});
        if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), &got.sha256))
            return error.ArtifactMismatch;
        return buf;
    }

    /// examine has a reader parse body for job and returns the lines after its
    /// "ok". On failure it records why on the last source and returns null.
    fn examine(
        u: *Update,
        sources: *std.ArrayList(Source),
        job: cve.Job,
        body: cve.Body,
    ) ?[]const u8 {
        const source = &sources.items[sources.items.len - 1];
        const said = saidOf(workers.read(u, job, body) catch |err| {
            source.@"error" = @errorName(err);
            return null;
        }) catch |err| {
            source.@"error" = @errorName(err);
            return null;
        };
        if (!std.mem.eql(u8, said.status, "ok")) {
            source.@"error" = said.status;
            return null;
        }
        return said.rest;
    }

    /// child runs f(args..., out, parent) in a forked process and returns what
    /// it writes to out and its exit. A child that writes more than max bytes
    /// or runs past seconds is killed; that, or death by signal, is an error.
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

    /// netRoot creates the fetcher's chroot, holding only copies of
    /// resolv.conf and hosts, and cves_dir.
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

    /// sys returns rc, or an error with what failed and the errno in detail.
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

    /// A locally rebuilt root has no CI-signed IPE policy. Refuse before
    /// modifying a slot; the policy signing key never belongs on a machine.
    pub fn requireLocalUpdate(u: *Update) !void {
        if (try u.needsSignedImage()) {
            u.step = "ipe";
            u.detail = "IPE requires a prebuilt image and its signed root policy; local package " ++
                "rebuilds are held";
            return error.IpeSignedImageRequired;
        }
    }

    pub fn needsSignedImage(u: *Update) !bool {
        if (workers.channel >= 0 and workers.ipe_policy != null) return true;
        if (Dir.cwd().access(u.io, meta_dir ++ "/secure-boot", .{})) |_|
            return true
        else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }
        // Every werewolf kernel has IPE; a loaded release policy is what enforces.
        return !try localUpdateAllowed(
            Dir.cwd().access(u.io, ipe.marker, .{}),
            Dir.cwd().access(u.io, ipe.active, .{}),
        );
    }

    pub const apkAdd = slot.apkAdd;

    pub fn isBad(u: *Update, build: []const u8) bool {
        const bad = u.read(coord_dir ++ "/bad") catch return false;
        for (u.lines(bad) catch return false) |l| if (std.mem.eql(u8, l, build)) return true;
        return false;
    }

    /// record appends one JSON line to the log, fsyncs it, and prints it on
    /// the console. Each line has seq, one more than the last, and prev, the
    /// first 16 hex digits of the last line's SHA-256
    /// (docs/design/implemented/update-policy.md, The audit log).
    pub fn record(u: *Update, fields: anytype) !void {
        // Lock from reading the tail to appending. A check run by hand logs
        // beside the daemon, and two writers reading the same tail would
        // share a seq and prev, and could overwrite each other.
        const log_fd: i32 = @intCast(try u.sys(linux.openat(
            linux.AT.FDCWD,
            log_path,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true, .NOFOLLOW = true },
            0o644,
        ), "open the log"));
        defer _ = linux.close(log_fd);
        while (true) switch (linux.errno(linux.flock(log_fd, std.posix.LOCK.EX))) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.LogLock,
        };
        const tail = try u.logTail();
        const Seq = struct { seq: u64 = 0 };
        var seq = (std.json.parseFromSliceLeaky(Seq, u.gpa, tail.last, .{
            .ignore_unknown_fields = true,
        }) catch Seq{}).seq;
        // Terminate and count a line a crash cut short, and chain over it, so
        // the chain continues and shows where it broke.
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
        // Sync before anything follows: a log that loses lines to a power
        // cut is no record of what the machine did.
        try u.syncPath(log_path);
        try Io.File.stdout().writeStreamingAll(
            u.io,
            try u.gpa.print("autoupdate: {s}", .{line.written()}),
        );
    }

    /// run executes argv[0], a full path, with no environment, collecting
    /// stdout and stderr up to max_tool_output bytes. A tool still running
    /// after tool_seconds is killed, even if it closed its output. Unless it
    /// exits 0, run fails with the end of its output in detail.
    pub fn run(u: *Update, argv: []const []const u8) !void {
        const e = u.child(
            tool,
            .{try argvZ(u.gpa, argv)},
            max_tool_output,
            tool_seconds,
        ) catch |err| {
            u.detail = try u.gpa.print("{s}: {s}", .{ argv[0], @errorName(err) });
            return err;
        };
        if (e.code == 0) return;
        const said = std.mem.trim(u8, e.out, " \n");
        u.detail = try u.gpa.print("{s}: {s}", .{ argv[0], said[said.len -| 400..] });
        return error.CommandFailed;
    }

    /// logTail returns the log's last whole line with its newline ("" if
    /// none), and any trailing bytes without a newline: a line a crash cut.
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
        const start = if (std.mem.findScalarLast(u8, tail[0..end -| 1], '\n')) |i| i + 1 else 0;
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

    /// nowText returns the current time as RFC 3339 in UTC.
    pub fn nowText(u: *Update) ![]const u8 {
        return u.time(nowSecs(u.io));
    }

    pub fn time(u: *Update, secs: i64) ![]const u8 {
        return u.gpa.print("{f}", .{policy.Time{ .secs = secs }});
    }

    /// writeReplacing writes data to path atomically through path.new, and
    /// syncs both the file and the rename before returning.
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

    /// pruneReports deletes all but the newest max_reports reports. Every
    /// newly staged build writes one, even if a newer build replaces it.
    fn pruneReports(u: *Update) !void {
        const names = try u.listDir(state_dir ++ "/reports");
        if (names.len <= max_reports) return;
        // Names are TIME-BUILD.json, so name order is time order.
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
fn saidOf(e: sandbox.Exit) !Said {
    if (e.code != 0) return error.ChildFailed;
    const eol = std.mem.findScalar(u8, e.out, '\n') orelse return error.ChildSaidNothing;
    const status = e.out[0..eol];
    if (status.len == 0 or status.len > 128) return error.ChildSaidNonsense;
    for (status) |c| if (c < 0x20 or c > 0x7e) return error.ChildSaidNonsense;
    return .{ .status = status, .rest = e.out[eol + 1 ..] };
}

/// tool is the child Update.run forks: it execs argv with stdout and stderr
/// on out, every other descriptor closed, and dies with its parent.
fn tool(argv: [:null]const ?[*:0]const u8, out: i32, parent: linux.pid_t) noreturn {
    sandbox.tieTo(parent);
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    execTool(
        argv,
        out,
    ) catch |err| sandbox.say(out, 127, sandbox.whyNot(arena.allocator(), err), "");
}

pub const apk_caps: u32 = (1 << linux.CAP.CHOWN) |
    (1 << linux.CAP.DAC_OVERRIDE) |
    (1 << linux.CAP.DAC_READ_SEARCH) |
    (1 << linux.CAP.FOWNER) |
    (1 << linux.CAP.FSETID);

pub fn keepDaemonCaps(keep: u32) !void {
    for (0..64) |cap| {
        if (cap < 32 and keep & (@as(u32, 1) << @intCast(cap)) != 0) continue;
        const rc = linux.prctl(@backingInt(linux.PR.CAPBSET_DROP), cap, 0, 0, 0);
        if (linux.errno(rc) != .INVAL) _ = try sandbox.sys(rc, "capbset drop");
    }
    const CapHeader = extern struct { version: u32 = 0x20080522, pid: i32 = 0 };
    const CapSets = extern struct { effective: u32 = 0, permitted: u32 = 0, inheritable: u32 = 0 };
    var hdr: CapHeader = .{};
    const caps = [2]CapSets{ .{ .effective = keep, .permitted = keep }, .{} };
    _ = try sandbox.sys(linux.syscall2(.capset, @intFromPtr(&hdr), @intFromPtr(&caps)), "capset");
    _ = try sandbox.sys(
        linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0),
        "no_new_privs",
    );
}

fn execTool(argv: [:null]const ?[*:0]const u8, out: i32) !noreturn {
    try sandbox.closeAllButAnonymous(&.{out});
    for ([_]i32{ 1, 2 }) |fd| _ = try sandbox.sys(linux.dup3(out, fd, 0), "dup3");
    if (std.mem.eql(u8, std.mem.span(argv[0].?), "/usr/bin/apk")) {
        try installer.confine(
            if (workers.jailed) null else state_dir,
            try installer.destination(argv),
        );
        try keepDaemonCaps(apk_caps);
        try installer.filter();
    } else if (linux.geteuid() == 0) try sandbox.keepOnly(0);
    const envp = [_:null]?[*:0]const u8{};
    _ = try sandbox.sys(linux.execve(argv[0].?, argv.ptr, &envp), "execve");
    unreachable;
}

// --- report -----------------------------------------------------------------

const Report = struct {
    time: []const u8,
    host: []const u8,
    build: []const u8,
    /// tier and why explain when the update boots
    /// (docs/design/implemented/update-policy.md).
    tier: []const u8,
    why: []const u8,
    from: struct { slot: []const u8, release: []const u8, kernel: []const u8 },
    to: struct { slot: []const u8, kernel: []const u8 },
    packages: []const Change,
    package_cves: []const cve.PackageFix,
    kernel_cves: cve.KernelFixes,
    advisories: []const policy.Advisory = &.{},
    sources: []const Source,
};

/// Plan describes the other slot: its packages and kernel, and its source.
pub const Plan = struct {
    build: []const u8,
    old_pkgs: []const Package,
    new_pkgs: []const Package,
    old_kernel: []const u8,
    new_kernel: []const u8,
    /// advisories are werewolf's own fixes the new root lists
    /// (werewolf-advisories), which tiers counts against this image's.
    advisories: []const policy.Advisory,
};

pub const Download = struct { fd: i32, size: usize, sha256: [64]u8 };

/// A signed operator declaration is due at once, independently of CVEs.
fn localChanged(old: []const Package, new: []const Package) bool {
    for (new) |n| {
        if (!std.mem.startsWith(u8, n.name, "local-")) continue;
        for (old) |o| {
            if (!std.mem.eql(u8, o.name, n.name)) continue;
            if (!std.mem.eql(u8, o.version, n.version)) return true;
            break;
        } else return true;
    }
    return false;
}

const Change = struct { name: []const u8, from: ?[]const u8, to: ?[]const u8 };
const Source = struct {
    url: []const u8,
    fetched: []const u8,
    sha256: ?[]const u8 = null,
    @"error": ?[]const u8 = null,
};

// --- pure functions, tested below -------------------------------------------

pub fn parentDir(path: []const u8) []const u8 {
    return path[0 .. std.mem.findScalarLast(u8, path, '/') orelse 0];
}

/// argvZ converts argv to execve's form: NUL-terminated strings ending in
/// null.
pub fn argvZ(gpa: Allocator, argv: []const []const u8) ![:null]const ?[*:0]const u8 {
    const z = try gpa.allocSentinel(?[*:0]const u8, argv.len, null);
    for (argv, z) |a, *p| p.* = try gpa.dupeSentinel(u8, a, 0);
    return z;
}

pub const Package = prebuilt.Package;

/// parseInstalled parses an apk installed database, sorted by name. Records
/// end at a blank line; P is the name, V the version, o the origin (source
/// package), which defaults to the name, and p what it provides, which may
/// name the Wolfi source it rebuilds instead (prebuilt.rebuiltFrom).
pub fn parseInstalled(gpa: Allocator, text: []const u8) ![]const Package {
    var out: std.ArrayList(Package) = .empty;
    var p: Package = .{ .name = "", .version = "", .origin = "" };
    var rebuilt: ?[]const u8 = null;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) {
            if (rebuilt) |r| p.origin = r;
            if (p.name.len > 0) try out.append(gpa, finish(p));
            p = .{ .name = "", .version = "", .origin = "" };
            rebuilt = null;
        } else if (std.mem.startsWith(u8, line, "P:")) {
            p.name = line[2..];
        } else if (std.mem.startsWith(u8, line, "V:")) {
            p.version = line[2..];
        } else if (std.mem.startsWith(u8, line, "o:")) {
            p.origin = line[2..];
        } else if (std.mem.startsWith(u8, line, "p:")) {
            rebuilt = prebuilt.rebuiltFrom(line[2..]);
        }
    }
    if (rebuilt) |r| p.origin = r;
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

/// diffPackages lists packages whose version differs. A null from means
/// added; a null to means removed.
fn diffPackages(gpa: Allocator, old: []const Package, new: []const Package) ![]const Change {
    var out: std.ArrayList(Change) = .empty;
    for (new) |n| {
        const o = versionOf(old, n.name);
        if (o != null and std.mem.eql(u8, o.?, n.version)) continue;
        try out.append(gpa, .{ .name = n.name, .from = o, .to = n.version });
    }
    for (old) |o| {
        if (versionOf(new, o.name) != null) continue;
        try out.append(gpa, .{ .name = o.name, .from = o.version, .to = null });
    }
    return out.items;
}

/// backwards returns the first package, or the kernel's, that would move to
/// an older version in apk's order, or null. Moving from Alpine's linux-virt
/// to linux-werewolf compares versions alone.
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
    const old = kernelPackage(old_kernel) orelse return null;
    const new = kernelPackage(new_kernel) orelse return null;
    if (cve.apkOrder(new.version, old.version) == .lt) return new.name;
    return null;
}

fn securityRepository(repositories: []const []const u8) ?[]const u8 {
    for (repositories) |repo| {
        if (std.mem.eql(u8, repo, werewolf_repository) or
            std.mem.startsWith(u8, repo, werewolf_repository ++ "/")) continue;
        return repo;
    }
    return null;
}

test "CVE source skips werewolf's hardened and package-specific feeds" {
    const wolfi = "https://packages.wolfi.dev/os";
    const ours = [_][]const u8{
        werewolf_repository, werewolf_repository ++ "/hardened", werewolf_repository ++ "/python",
    };
    try std.testing.expect(securityRepository(&ours) == null);
    try std.testing.expectEqualStrings(wolfi, securityRepository(&(ours ++ .{wolfi})).?);
    const other = werewolf_repository ++ "-mirror";
    try std.testing.expectEqualStrings(other, securityRepository(&.{other}).?);
}

test "a tool's output, exit and deadline" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var u: Update = .{ .io = testing.io, .gpa = arena.allocator() };
    try u.run(&.{ "/bin/sh", "-c", "exit 0" });
    try testing.expectError(error.CommandFailed, u.run(&.{ "/bin/sh", "-c", "echo said; exit 3" }));
    try testing.expectEqualStrings("/bin/sh: said", u.detail);
    try testing.expectError(error.CommandFailed, u.run(&.{"/nonexistent"}));
    try testing.expectEqualStrings("/nonexistent: execve: NOENT", u.detail);
    // A tool that closes its output and hangs is still killed at the deadline.
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "exec >&- 2>&-; sleep 30" };
    try testing.expectError(error.Timeout, u.child(tool, .{&argv}, 1024, 1));
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
    // Leaving Alpine's kernel for werewolf's is forward; returning is not.
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        backwards(&up, "linux-virt-6.18.56-r0", "linux-werewolf-7.2.11-r1"),
    );
    try std.testing.expectEqualStrings(
        "linux-werewolf",
        backwards(&up, "linux-werewolf-7.2.11-r1", "linux-werewolf-7.2.10-r1").?,
    );
}

/// diffOrigins lists source packages present in both old and new at
/// different versions, once each. A rebuild counts as the Wolfi source and
/// version it names (prebuilt.Package), so Wolfi's CVE fixes match it.
pub fn diffOrigins(
    gpa: Allocator,
    old: []const Package,
    new: []const Package,
) ![]const cve.OriginChange {
    var out: std.ArrayList(cve.OriginChange) = .empty;
    for (new) |n| {
        const to = sourceOf(n);
        const from = for (old) |p| {
            const s = sourceOf(p);
            if (std.mem.eql(u8, s.origin, to.origin)) break s.version;
        } else continue;
        if (std.mem.eql(u8, from, to.version)) continue;
        for (out.items) |c| {
            if (std.mem.eql(u8, c.origin, to.origin)) break;
        } else try out.append(gpa, .{ .origin = to.origin, .from = from, .to = to.version });
    }
    return out.items;
}

/// sourceOf returns the origin and version p's CVEs are counted under.
fn sourceOf(p: Package) struct { origin: []const u8, version: []const u8 } {
    const i = std.mem.findScalarLast(u8, p.origin, ':') orelse
        return .{ .origin = p.origin, .version = p.version };
    return .{ .origin = p.origin[0..i], .version = p.origin[i + 1 ..] };
}

/// buildHash identifies a build: the first 16 hex digits of the sha256 of
/// its package names, versions and kernel.
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

fn lessString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

// --- tests ------------------------------------------------------------------

const testing = std.testing;

test "reboot countdown retains both package and full image build IDs" {
    var ctx: Ctx = .{};
    for ([_][]const u8{
        "0123456789abcdef",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    }) |build| {
        ctx.remember(build);
        try testing.expect(ctx.noticeIs(build));
        try testing.expect(!ctx.noticeIs("another-build"));
        ctx.clearNotice();
        try testing.expect(!ctx.noticeIs(build));
    }
}

fn localUpdateAllowed(marker_access: anyerror!void, policy_access: anyerror!void) !bool {
    const required = if (marker_access) |_| true else |err| switch (err) {
        error.FileNotFound => false,
        else => return err,
    };
    const present = if (policy_access) |_| true else |err| switch (err) {
        error.FileNotFound => false,
        else => return err,
    };
    return !required and !present;
}

test "IPE update guard holds while a release policy is loaded, even without its marker" {
    try testing.expect(try localUpdateAllowed(error.FileNotFound, error.FileNotFound));
    try testing.expect(!try localUpdateAllowed({}, error.FileNotFound));
    try testing.expect(!try localUpdateAllowed(error.FileNotFound, {}));
    try testing.expect(!try localUpdateAllowed({}, {}));
    try testing.expectError(
        error.AccessDenied,
        localUpdateAllowed(error.AccessDenied, error.FileNotFound),
    );
    try testing.expectError(
        error.AccessDenied,
        localUpdateAllowed(error.FileNotFound, error.AccessDenied),
    );
}

test parentDir {
    try testing.expectEqualStrings("/boot", parentDir(parentDir("/boot/loader/entries")));
    try testing.expectEqualStrings("", parentDir(parentDir("/loader/entries")));
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

test "a rebuild of Wolfi's glibc counts as the Wolfi glibc it rebuilds" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const wolfi = try parseInstalled(a, "P:glibc-2.44\nV:2.44-r8\no:glibc-2.44\n");
    const rebuilt = "P:glibc-neutered-2.44\nV:2.44-r{d}\no:glibc-neutered-2.44\n" ++
        "p:glibc=2.44-r{d} wolfi-origin:glibc-2.44:2.44-r{d}\n";
    const r18 = try parseInstalled(a, try a.print(rebuilt, .{ 18, 18, 8 }));
    const r19 = try parseInstalled(a, try a.print(rebuilt, .{ 19, 19, 9 }));
    try testing.expectEqualStrings("glibc-2.44:2.44-r8", r18[0].origin);
    // Moving to the rebuild of the same Wolfi glibc fixes nothing.
    try testing.expectEqual(0, (try diffOrigins(a, wolfi, r18)).len);
    // The next rebuild carries Wolfi's r9: its fixes are Wolfi's (r8, r9].
    const changes = try diffOrigins(a, r18, r19);
    try testing.expectEqual(1, changes.len);
    try testing.expectEqualStrings("glibc-2.44", changes[0].origin);
    try testing.expectEqualStrings("2.44-r8", changes[0].from);
    try testing.expectEqualStrings("2.44-r9", changes[0].to);
}

test {
    _ = broker;
    _ = control;
    _ = owner;
    _ = sandbox;
    _ = cve;
    _ = tiers;
    _ = stage;
    _ = installer;
    _ = workers;
    _ = slot;
    _ = @import("notice.zig");
}

/// transient reports whether a fetch failure may pass on retry: no answer
/// (an error name rather than an HTTP status), a 5xx, 408 or 429. A refusal
/// like 404 will be the same next time.
fn transient(said: []const u8) bool {
    if (std.mem.eql(u8, said, "TooBig")) return false;
    const status = std.meta.stringToEnum(std.http.Status, said) orelse return true;
    return @backingInt(status) >= 500 or status == .request_timeout or
        status == .too_many_requests;
}

test transient {
    try testing.expect(!transient("TooBig"));
    try std.testing.expect(transient("ConnectionRefused"));
    try std.testing.expect(transient("service_unavailable"));
    try std.testing.expect(transient("too_many_requests"));
    try std.testing.expect(!transient("not_found"));
    try std.testing.expect(!transient("forbidden"));
}
