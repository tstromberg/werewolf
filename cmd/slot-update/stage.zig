//! stage: when a staged slot boots, and what says so
//! (docs/design/update-policy.md). The settings, the CVE tiers feed, the
//! slot armed for one try and the boot that armed it (`attempt`), the
//! deadlines kept in `pending`, the lock, and the reboot. Each takes the
//! Update of slot-update.zig, whose methods call these as their own.

const std = @import("std");
const m = @import("slot-update.zig");
const Io = m.Io;
const Dir = m.Dir;
const Allocator = m.Allocator;
const linux = m.linux;
const policy = m.policy;
const cve = m.cve;
const releases = m.releases;
const tiers = m.tiers;

const attempt_path = m.attempt_path;
const cves_dir = m.cves_dir;
const feed_path = m.feed_path;
const feed_serial_path = m.feed_serial_path;
const feed_sig_path = m.feed_sig_path;
const form_policy = m.form_policy;
const lock_path = m.lock_path;
const max_feed = m.max_feed;
const meta_dir = m.meta_dir;
const operator_policy = m.operator_policy;
const pending_path = m.pending_path;
const rebooted_path = m.rebooted_path;

const bootSecs = m.bootSecs;
const Ctx = m.Ctx;
const diffOrigins = m.diffOrigins;
const nowSecs = m.nowSecs;
const Plan = m.Plan;
const Update = m.Update;

// --- attempt ----------------------------------------------------------------

/// The slot armed to boot once: which, its build, and the boot that
/// armed it; empty for an attempt written before boots were named.
pub const Attempt = struct { slot: []const u8, build: []const u8, boot: []const u8 };

pub fn attemptOf(u: *Update) !?Attempt {
    const text = u.read(attempt_path) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    var it = std.mem.tokenizeAny(u8, text, " \n");
    return .{
        .slot = it.next() orelse return error.BadAttemptFile,
        .build = it.next() orelse return error.BadAttemptFile,
        .boot = it.next() orelse "",
    };
}

/// This boot, as the kernel names it. Read with pread, not u.read:
/// procfs gives its files a size of 0, which readFileAlloc believes. An
/// empty one is an error, never a match: every attempt would look armed
/// in this boot, and no outcome would ever be judged.
pub fn bootId(u: *Update) ![]const u8 {
    var f = try Dir.cwd().openFile(u.io, "/proc/sys/kernel/random/boot_id", .{});
    defer f.close(u.io);
    const buf = try u.gpa.alloc(u8, 64);
    const id = std.mem.trim(u8, buf[0..try f.readPositionalAll(u.io, buf, 0)], " \n");
    if (id.len == 0) return error.NoBootId;
    return id;
}

/// Whether p's slot is armed: this boot armed the other slot with p's
/// build. Only then does a reboot boot it, and only then is it staged.
pub fn armed(u: *Update, p: Pending) !bool {
    const a = try u.attemptOf() orelse return false;
    return std.mem.eql(u8, a.build, p.build) and std.mem.eql(u8, a.slot, u.other) and
        std.mem.eql(u8, a.boot, try u.bootId());
}

/// The lock on state_dir, or error.Busy if another pass holds it.
pub fn lock(u: *Update) !i32 {
    const fd: i32 = @intCast(try u.sys(linux.openat(
        linux.AT.FDCWD,
        lock_path,
        .{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true, .NOFOLLOW = true },
        0o600,
    ), "open the lock"));
    if (linux.errno(linux.flock(fd, std.posix.LOCK.EX | std.posix.LOCK.NB)) != .SUCCESS) {
        _ = linux.close(fd);
        u.detail = "another slot-update holds " ++ lock_path;
        return error.Busy;
    }
    return fd;
}

/// Seconds from the reboot bootIfDue logged to this kernel's start: the
/// old slot stopping, the firmware and the loader, and, after a
/// rollback, the failed slot's boot too. Null if that reboot left no
/// mark. Both ends are the wall clock, so it is as exact as the clock
/// the kernel read at boot, about a second.
pub fn downtime(u: *Update) ?i64 {
    const text = u.read(rebooted_path) catch return null;
    const at = std.fmt.parseInt(i64, std.mem.trim(u8, text, " \n"), 10) catch return null;
    return nowSecs(u.io) - bootSecs() - at;
}

/// For each tier the committed slot carried, when this machine first
/// saw it and the seconds from then to now.
pub fn waited(u: *Update) !Waits {
    const p = try u.readPending() orelse return .{};
    const now = nowSecs(u.io);
    const of = struct {
        fn f(x: ?Pending.Seen, t: i64) !?Waited {
            const y = x orelse return null;
            return .{ .seen = y.seen, .seconds = t - try releases.parseTime(y.seen) };
        }
    }.f;
    return .{
        .urgent = try of(p.urgent, now),
        .high = try of(p.high, now),
        .medium = try of(p.medium, now),
        .low = try of(p.low, now),
    };
}

// --- policy -----------------------------------------------------------------
// werewolf's settings, then the form's, then the operator's
// (docs/design/update-policy.md, Settings): each file all or nothing,
// and what is in force logged.
pub fn loadPolicy(u: *Update, s: *policy.Settings) !void {
    var refused: std.ArrayList(Refused) = .empty;
    const files = [_]struct { path: []const u8, source: policy.Source }{
        .{ .path = form_policy, .source = .form },
        .{ .path = operator_policy, .source = .operator },
    };
    for (files) |f| {
        // The form's file refused, its lowered limits are lost, and the
        // operator's could then reach werewolf's: so it is not read.
        if (f.source == .operator and refused.items.len > 0) {
            try refused.append(u.gpa, .{
                .file = f.path,
                .key = "",
                .why = "not read: the form's file was refused",
            });
            continue;
        }
        const input = Dir.cwd().readFileAlloc(
            u.io,
            f.path,
            u.gpa,
            .limited(policy.max_input + 1),
        ) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => {
                try refused.append(
                    u.gpa,
                    .{ .file = f.path, .key = "", .why = @errorName(err) },
                );
                continue;
            },
        };
        if (try policy.apply(u.gpa, s, f.source, input)) |r|
            try refused.append(u.gpa, .{ .file = f.path, .key = r.key, .why = r.why });
    }
    const text = struct {
        fn f(gpa: Allocator, secs: u32) ![]const u8 {
            return gpa.print("{f}", .{policy.Setting{ .secs = secs }});
        }
    }.f;
    try u.record(.{
        .event = "policy",
        .settings = .{
            .window = .{
                .value = try u.gpa.print("{f}", .{s.window}),
                .source = @tagName(s.source.window),
            },
            .high = Valued{
                .value = try text(u.gpa, s.time.high),
                .source = @tagName(s.source.high),
                .limit = try text(u.gpa, s.limit.high),
            },
            .medium = Valued{
                .value = try text(u.gpa, s.time.medium),
                .source = @tagName(s.source.medium),
                .limit = try text(u.gpa, s.limit.medium),
            },
            .low = Valued{
                .value = try text(u.gpa, s.time.low),
                .source = @tagName(s.source.low),
                .limit = try text(u.gpa, s.limit.low),
            },
        },
        .refused = refused.items,
    });
}

/// The staged slot, or null. One that cannot be read, cut short by a
/// crash, is logged and removed: it costs its first-seen times, never
/// the updater.
pub fn readPending(u: *Update) !?Pending {
    const data = u.read(pending_path) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    return std.json.parseFromSliceLeaky(Pending, u.gpa, data, .{
        .ignore_unknown_fields = true,
    }) catch |err| {
        try u.record(.{
            .event = "error",
            .step = "pending",
            .@"error" = @errorName(err),
            .detail = "unreadable; removed",
        });
        try Dir.cwd().deleteFile(u.io, pending_path);
        return null;
    };
}

/// When the staged slot p is due, and the tier that makes it then: the
/// policy's time, held until an hour after boot unless a first check
/// staged it.
pub fn dueOf(u: *Update, s: *const policy.Settings, p: Pending) !policy.Due {
    var seen: policy.Seen = @splat(null);
    for (std.enums.values(policy.Tier)) |t| if (p.get(t)) |x| {
        seen[@backingInt(t)] = try releases.parseTime(x.seen);
    };
    var d = policy.when(s, seen, u.seed(p.build), p.first_boot) orelse
        return error.NothingStaged;
    if (!p.first_boot) d.at = policy.spaced(d.at, nowSecs(u.io) - bootSecs());
    return d;
}

/// The log's why for the staged slot p, due as d.
pub fn whyOf(
    u: *Update,
    s: *const policy.Settings,
    p: Pending,
    d: policy.Due,
    now: i64,
) ![]const u8 {
    const x = p.get(d.tier).?;
    var out: Io.Writer.Allocating = .init(u.gpa);
    try policy.why(
        &out.writer,
        s,
        d.tier,
        .{ .subject = x.subject, .evidence = x.evidence },
        try releases.parseTime(x.seen),
        u.seed(p.build),
        p.first_boot,
        d.at,
        now,
    );
    return out.written();
}

/// This machine's seed for build: by its disk, which outlives every
/// slot, so its place is the same from boot to boot.
pub fn seed(u: *Update, build: []const u8) u64 {
    const colon = std.mem.findScalar(u8, u.cmd.victim, ':') orelse u.cmd.victim.len;
    return policy.seed(u.cmd.victim[0..colon], build);
}

// --- the tiers feed ---------------------------------------------------------
// Fetched as _update, as the CVE sources are; checked against the image's
// tiers.pub before it is read; and kept once taken, so that whenever a
// newer one cannot be had, does not check, or is older, the one kept
// serves until it expires (docs/design/update-policy.md). Null when
// there is none to trust: then every fix counts as High.
pub fn tiersFeed(u: *Update) !?tiers.Feed {
    const base_text = u.read(meta_dir ++ "/tiers") catch |err| switch (err) {
        error.FileNotFound => return u.noFeed(null, "this image names no tiers feed"),
        else => return err,
    };
    const base = std.mem.trim(u8, base_text, " \n");
    const key = try releases.parseKey(u.gpa, try u.read(meta_dir ++ "/tiers.pub"));
    const now = nowSecs(u.io);
    // The newest serial ever taken, kept apart from the feed, so no
    // older feed is taken even once the one kept has expired.
    const last: ?[]const u8 = if (u.read(feed_serial_path)) |t|
        std.mem.trim(u8, t, " \n")
    else |_|
        null;
    const kept_data = u.read(feed_path) catch "";
    const kept: ?tiers.Feed = if (kept_data.len > 0) b: {
        const sig = u.read(feed_sig_path) catch break :b null;
        break :b tiers.open(u.gpa, key, kept_data, sig, now, last) catch null;
    } else null;

    try u.netRoot();
    const fresh = u.fetchFeed(base, key, now, last);
    if (fresh) |got| {
        const same = std.mem.eql(u8, kept_data, got.data);
        if (!same) {
            try u.writeReplacing(feed_sig_path, got.sig);
            try u.writeReplacing(feed_path, got.data);
            try u.writeReplacing(
                feed_serial_path,
                try u.gpa.print("{s}\n", .{got.feed.serial}),
            );
        }
        try u.record(.{
            .event = "feed",
            .serial = got.feed.serial,
            .expires = got.feed.expires,
            .result = if (same) "unchanged" else "ok",
        });
        return got.feed;
    } else |err| {
        const reason = if (err == error.FetchFailed)
            try u.gpa.print("{s}: {s}", .{ @errorName(err), u.detail })
        else
            @errorName(err);
        const k = kept orelse return u.noFeed(reason, null);
        try u.record(.{
            .event = "feed",
            .serial = k.serial,
            .expires = k.expires,
            .result = "kept",
            .reason = reason,
        });
        return k;
    }
}

/// The feed at base and its signature, as _update fetches them, taken
/// only if they check.
pub fn fetchFeed(
    u: *Update,
    base: []const u8,
    key: releases.Key,
    now: i64,
    last: ?[]const u8,
) !struct { feed: tiers.Feed, data: []const u8, sig: []const u8 } {
    const data = try u.downloadMax(
        try u.gpa.print("{s}cve-tiers.json", .{base}),
        cves_dir ++ "/cve-tiers.json",
        max_feed,
    );
    const sig = try u.downloadMax(
        try u.gpa.print("{s}cve-tiers.json.sig", .{base}),
        cves_dir ++ "/cve-tiers.json.sig",
        max_feed,
    );
    return .{
        .feed = try tiers.open(u.gpa, key, data, sig, now, last),
        .data = data,
        .sig = sig,
    };
}

/// The advisories this image's own code has (release/advisories, in
/// the build record); none, for an image built before there were any.
pub fn ownAdvisories(u: *Update) ![]const u8 {
    return u.read(meta_dir ++ "/advisories") catch |err| switch (err) {
        error.FileNotFound => "",
        else => err,
    };
}

/// No feed to trust, logged with why, and what that means.
pub fn noFeed(u: *Update, reason: ?[]const u8, why: ?[]const u8) !?tiers.Feed {
    try u.record(.{
        .event = "feed",
        .result = "none",
        .reason = reason orelse why orelse "",
        .consequence = "every fix counts as High",
    });
    return null;
}

/// The staged slot's fixes, from its report, tiered again against the
/// latest feed: a tier seen for the first time joins pending, logged as
/// `tier`, and can only bring the boot sooner.
pub fn retier(u: *Update, s: *const policy.Settings, p: Pending, plan: Plan) !Pending {
    const text = u.read(p.report) catch return p;
    const r = std.json.parseFromSliceLeaky(struct {
        package_cves: []const cve.PackageFix = &.{},
        kernel_cves: cve.KernelFixes = .{},
    }, u.gpa, text, .{ .ignore_unknown_fields = true }) catch return p;
    const feed = try u.tiersFeed();
    const fixes = try tiers.tiersOf(u.gpa, feed, .{
        .changes = try diffOrigins(u.gpa, plan.old_pkgs, plan.new_pkgs),
        .package_cves = r.package_cves,
        .kernel_cves = r.kernel_cves,
        .old_kernel = plan.old_kernel,
        .new_kernel = plan.new_kernel,
        .advisories = advisoriesOf(plan),
        .have = try u.ownAdvisories(),
    });
    const now = nowSecs(u.io);
    var next = p;
    var rose: ?policy.Tier = null;
    for (std.enums.values(policy.Tier)) |t| if (fixes.first[@backingInt(t)]) |f| {
        const seen = next.tier(t);
        if (seen.* != null) continue;
        seen.* = .{ .seen = try u.time(now), .subject = f.subject, .evidence = f.evidence };
        if (rose == null or @backingInt(t) > @backingInt(rose.?)) rose = t;
    };
    const t = rose orelse return p;
    const was = try u.dueOf(s, p);
    const d = try u.dueOf(s, next);
    try u.writeReplacing(pending_path, try std.json.Stringify.valueAlloc(u.gpa, next, .{}));
    const f = next.get(t).?;
    try u.record(.{
        .event = "tier",
        .build = p.build,
        .fix = f.subject,
        .cause = f.evidence,
        .feed = if (feed) |x| x.serial else null,
        .from = @tagName(was.tier),
        .to = @tagName(t),
        .was_due = try u.time(was.at),
        .due = try u.time(d.at),
        .due_in = d.at - now,
        .why = try u.whyOf(s, next, d, now),
    });
    return next;
}

// --- boot -------------------------------------------------------------------
// The staged slot, booted once it is due; until then, how long that is.
pub fn bootIfDue(u: *Update, ctx: *Ctx) !void {
    ctx.due_in = null;
    const held_lock = try u.lock();
    defer _ = linux.close(held_lock);
    const p = try u.readPending() orelse return;
    // Not armed: its try is spent or was never set. Rebooting would boot
    // this slot again, so wait for the next check to stage it anew.
    if (!try u.armed(p)) return;
    const d = try u.dueOf(&ctx.settings, p);
    const now = nowSecs(u.io);
    if (now < d.at) {
        ctx.due_in = d.at - now;
        return;
    }
    u.step = "reboot";
    try u.record(.{
        .event = "reboot",
        .build = p.build,
        .tier = @tagName(d.tier),
        .cause = if (p.first_boot) "first-boot" else "due",
        .due = try u.time(d.at),
        .late = now - d.at,
        .why = try u.whyOf(&ctx.settings, p, d, now),
    });
    // For the next boot's outcome to say how long the machine was down;
    // without it, the reboot still goes.
    u.writeReplacing(rebooted_path, try u.gpa.print("{d}\n", .{now})) catch {};
    u.run(&.{"/usr/bin/reboot"}) catch |err| {
        Dir.cwd().deleteFile(u.io, rebooted_path) catch {};
        return err;
    };
    ctx.rebooting = true;
}

// --- state ------------------------------------------------------------------

/// The staged slot, in pending: its build, whether a machine's first check
/// staged it, and for each tier of the fixes it carries, when this machine
/// first saw one and the first such fix, for the log's why.
pub const Pending = struct {
    build: []const u8,
    /// Its report, whose CVEs each check tiers again.
    report: []const u8 = "",
    first_boot: bool = false,
    urgent: ?Seen = null,
    high: ?Seen = null,
    medium: ?Seen = null,
    low: ?Seen = null,

    pub const Seen = struct { seen: []const u8, subject: []const u8, evidence: []const u8 };

    pub fn tier(p: *Pending, t: policy.Tier) *?Seen {
        return switch (t) {
            .urgent => &p.urgent,
            .high => &p.high,
            .medium => &p.medium,
            .low => &p.low,
        };
    }

    pub fn get(p: Pending, t: policy.Tier) ?Seen {
        return switch (t) {
            .urgent => p.urgent,
            .high => p.high,
            .medium => p.medium,
            .low => p.low,
        };
    }

    pub fn seenTimes(p: Pending) struct {
        urgent: ?[]const u8,
        high: ?[]const u8,
        medium: ?[]const u8,
        low: ?[]const u8,
    } {
        const at = struct {
            fn f(x: ?Seen) ?[]const u8 {
                return if (x) |y| y.seen else null;
            }
        }.f;
        return .{
            .urgent = at(p.urgent),
            .high = at(p.high),
            .medium = at(p.medium),
            .low = at(p.low),
        };
    }
};

const Waited = struct { seen: []const u8, seconds: i64 };
pub const Waits = struct {
    urgent: ?Waited = null,
    high: ?Waited = null,
    medium: ?Waited = null,
    low: ?Waited = null,
};
const Valued = struct { value: []const u8, source: []const u8, limit: []const u8 };
const Refused = struct { file: []const u8, key: []const u8, why: []const u8 };

/// werewolf's own advisories a plan's release carries; a slot built from
/// packages carries werewolf's code forward unchanged, and so none.
pub fn advisoriesOf(plan: Plan) []const releases.Manifest.Advisory {
    return switch (plan.from) {
        .packages => &.{},
        .release => |r| r.manifest.advisories,
    };
}
