//! stage decides when a staged slot boots (docs/design/update-policy.md). It
//! holds the settings, the CVE tiers feed, `attempt`, `pending`, the lock and
//! the reboot. Update in slot-update.zig re-exports these as its methods.

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

/// Attempt is the slot armed to boot once, its build, and the boot_id that
/// armed it. boot is empty in attempts written before boot_ids were recorded.
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

/// bootId returns the kernel's boot_id. It uses pread because procfs reports
/// a size of 0, which readFileAlloc trusts. An empty id is an error: it would
/// match every old attempt, and no outcome would ever be judged.
pub fn bootId(u: *Update) ![]const u8 {
    var f = try Dir.cwd().openFile(u.io, "/proc/sys/kernel/random/boot_id", .{});
    defer f.close(u.io);
    const buf = try u.gpa.alloc(u8, 64);
    const id = std.mem.trim(u8, buf[0..try f.readPositionalAll(u.io, buf, 0)], " \n");
    if (id.len == 0) return error.NoBootId;
    return id;
}

/// armed reports whether this boot armed the other slot with p's build. Only
/// then is p staged, and only then does a reboot boot it.
pub fn armed(u: *Update, p: Pending) !bool {
    const a = try u.attemptOf() orelse return false;
    return std.mem.eql(u8, a.build, p.build) and std.mem.eql(u8, a.slot, u.other) and
        std.mem.eql(u8, a.boot, try u.bootId());
}

/// lock takes the state lock and returns its descriptor, or error.Busy if
/// another pass holds it.
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

/// downtime returns the seconds from the reboot bootIfDue logged to this
/// kernel's start: shutdown, firmware and loader, plus the failed slot's
/// boot after a rollback. It is null if no reboot was logged. Both ends use
/// the wall clock, so it is accurate to about a second.
pub fn downtime(u: *Update) ?i64 {
    const text = u.read(rebooted_path) catch return null;
    const at = policy.parseTime(std.mem.trim(u8, text, " \n")) catch return null;
    return nowSecs(u.io) - bootSecs() - at;
}

/// waited returns, for each tier the committed slot carried, when this
/// machine first saw it and the seconds since.
pub fn waited(u: *Update) !Waits {
    var w: Waits = .{};
    const p = try u.readPending() orelse return w;
    const now = nowSecs(u.io);
    inline for (comptime std.enums.values(policy.Tier)) |t| if (p.get(t)) |x| {
        @field(w, @tagName(t)) = .{ .seen = x.seen, .seconds = now - try policy.parseTime(x.seen) };
    };
    return w;
}

// --- policy -----------------------------------------------------------------

/// loadPolicy applies the form's settings, then the operator's, over
/// werewolf's defaults (docs/design/update-policy.md, Settings), and logs the
/// result. Each file is taken whole or refused whole.
pub fn loadPolicy(u: *Update, s: *policy.Settings) !void {
    var refused: std.ArrayList(Refused) = .empty;
    const files = [_]struct { path: []const u8, source: policy.Source }{
        .{ .path = form_policy, .source = .form },
        .{ .path = operator_policy, .source = .operator },
    };
    for (files) |f| {
        // If the form's file was refused, its lowered limits are lost, and the
        // operator's file could exceed them. Refuse it too.
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

/// readPending returns the staged slot, or null. An unreadable file (a
/// crash cut it short) is logged and removed: that loses its first-seen
/// times but never wedges the updater.
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

/// dueOf returns when p is due and the tier that sets it. Unless a first
/// check staged p, the time is held to at least an hour after boot.
pub fn dueOf(u: *Update, s: *const policy.Settings, p: Pending) !policy.Due {
    var seen: policy.Seen = .initFill(null);
    for (std.enums.values(policy.Tier)) |t| if (p.get(t)) |x| {
        seen.set(t, try policy.parseTime(x.seen));
    };
    var d = policy.when(s, seen, u.seed(p.build), p.first_boot) orelse
        return error.NothingStaged;
    if (!p.first_boot) d.at = policy.spaced(d.at, nowSecs(u.io) - bootSecs());
    return d;
}

/// whyOf returns the log's explanation of why p is due at d.
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
        try policy.parseTime(x.seen),
        u.seed(p.build),
        p.first_boot,
        d.at,
        now,
    );
    return out.written();
}

/// seed returns this machine's seed for build. It derives from the disk's
/// UUID, which outlives every slot, so it is stable across boots.
pub fn seed(u: *Update, build: []const u8) u64 {
    return policy.seed(u.cmd.victim.?.uuid, build);
}

// --- the tiers feed ---------------------------------------------------------

/// tiersFeed fetches the tiers feed as _update and checks it against the
/// image's tiers.pub. It keeps the last good feed, which serves until it
/// expires when a newer one cannot be fetched or verified. It returns null
/// when no feed can be trusted; then every fix counts as High.
pub fn tiersFeed(u: *Update) !?tiers.Feed {
    const base_text = u.read(meta_dir ++ "/tiers") catch |err| switch (err) {
        error.FileNotFound => return u.noFeed("this image names no tiers feed"),
        else => return err,
    };
    const base = std.mem.trim(u8, base_text, " \n");
    const key = try releases.parseKey(u.gpa, try u.read(meta_dir ++ "/tiers.pub"));
    const now = nowSecs(u.io);
    // The newest serial is kept apart from the feed, so no older feed is
    // taken even after the kept one expires.
    const last: ?[]const u8 = if (u.read(feed_serial_path)) |t|
        std.mem.trim(u8, t, " \n")
    else |_|
        null;
    const kept_data = u.read(feed_path) catch "";
    // Why the kept feed is unusable, logged if the fetch fails too.
    var kept_error: ?[]const u8 = null;
    const kept: ?tiers.Feed = if (kept_data.len > 0) b: {
        const sig = u.read(feed_sig_path) catch |err| {
            kept_error = @errorName(err);
            break :b null;
        };
        break :b tiers.open(u.gpa, key, kept_data, sig, now, last) catch |err| {
            kept_error = @errorName(err);
            break :b null;
        };
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
        const k = kept orelse return u.noFeed(if (kept_error) |ke|
            try u.gpa.print("{s}; the kept feed: {s}", .{ reason, ke })
        else
            reason);
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

/// fetchFeed downloads the feed at base and its signature and returns them
/// if they verify and are not older than last.
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

/// ownAdvisories returns the advisories already fixed in this image's code
/// (release/advisories in the build record), or "" for older images.
pub fn ownAdvisories(u: *Update) ![]const u8 {
    return u.read(meta_dir ++ "/advisories") catch |err| switch (err) {
        error.FileNotFound => "",
        else => err,
    };
}

/// noFeed logs that no feed can be trusted, why, and that every fix counts
/// as High. It returns null.
pub fn noFeed(u: *Update, reason: []const u8) !?tiers.Feed {
    try u.record(.{
        .event = "feed",
        .result = "none",
        .reason = reason,
        .consequence = "every fix counts as High",
    });
    return null;
}

/// retier tiers the staged slot's fixes from its report against the latest
/// feed. A tier seen for the first time is added to pending and logged as
/// `tier`; this can only bring the boot sooner.
pub fn retier(u: *Update, s: *const policy.Settings, p: Pending, plan: Plan) !Pending {
    // Without its report, keep the current tiers and log it: a fix that has
    // since risen to Urgent will not bring the boot sooner.
    const text = u.read(p.report) catch |err| {
        try u.record(.{
            .event = "error",
            .step = "retier",
            .@"error" = @errorName(err),
            .detail = p.report,
        });
        return p;
    };
    const r = std.json.parseFromSliceLeaky(struct {
        package_cves: []const cve.PackageFix = &.{},
        kernel_cves: cve.KernelFixes = .{},
    }, u.gpa, text, .{ .ignore_unknown_fields = true }) catch |err| {
        try u.record(.{
            .event = "error",
            .step = "retier",
            .@"error" = @errorName(err),
            .detail = p.report,
        });
        return p;
    };
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
    for (std.enums.values(policy.Tier)) |t| if (fixes.first.get(t)) |f| {
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

/// bootIfDue reboots into the staged slot once it is due. Until then it sets
/// ctx.due_in to the seconds left.
pub fn bootIfDue(u: *Update, ctx: *Ctx) !void {
    ctx.due_in = null;
    const held_lock = try u.lock();
    defer _ = linux.close(held_lock);
    const p = try u.readPending() orelse return;
    // Not armed: its try is spent or was never set. A reboot would boot this
    // slot again, so wait for the next check to stage it.
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
    // Lets the next boot's outcome log the downtime. Reboot even if it fails.
    u.writeReplacing(rebooted_path, try u.gpa.print("{s}\n", .{try u.time(now)})) catch {};
    u.run(&.{"/usr/bin/reboot"}) catch |err| {
        Dir.cwd().deleteFile(u.io, rebooted_path) catch {};
        return err;
    };
    ctx.rebooting = true;
}

// --- state ------------------------------------------------------------------

/// Pending is the staged slot: its build, whether a first check staged it,
/// and for each tier of its fixes, when this machine first saw one and which
/// fix it was, for the log's why.
pub const Pending = struct {
    build: []const u8,
    /// report is the path of the report whose CVEs each check re-tiers.
    report: []const u8 = "",
    first_boot: bool = false,
    urgent: ?Seen = null,
    high: ?Seen = null,
    medium: ?Seen = null,
    low: ?Seen = null,

    pub const Seen = struct { seen: []const u8, subject: []const u8, evidence: []const u8 };

    pub fn tier(p: *Pending, t: policy.Tier) *?Seen {
        return switch (t) {
            inline else => |x| &@field(p, @tagName(x)),
        };
    }

    pub fn get(p: Pending, t: policy.Tier) ?Seen {
        return switch (t) {
            inline else => |x| @field(p, @tagName(x)),
        };
    }

    /// seenTimes returns when each tier was first seen, for the log.
    pub fn seenTimes(p: Pending) std.enums.EnumFieldStruct(
        policy.Tier,
        ?[]const u8,
        @as(?[]const u8, null),
    ) {
        var out: std.enums.EnumFieldStruct(policy.Tier, ?[]const u8, @as(?[]const u8, null)) = .{};
        inline for (comptime std.enums.values(policy.Tier)) |t| {
            if (p.get(t)) |x| @field(out, @tagName(t)) = x.seen;
        }
        return out;
    }
};

const Waited = struct { seen: []const u8, seconds: i64 };
pub const Waits = std.enums.EnumFieldStruct(policy.Tier, ?Waited, @as(?Waited, null));
const Valued = struct { value: []const u8, source: []const u8, limit: []const u8 };
const Refused = struct { file: []const u8, key: []const u8, why: []const u8 };

/// advisoriesOf returns the werewolf advisories a plan's release carries. A
/// slot built from packages keeps werewolf's code unchanged, so it has none.
pub fn advisoriesOf(plan: Plan) []const releases.Manifest.Advisory {
    return switch (plan.from) {
        .packages => &.{},
        .release => |r| r.manifest.advisories,
    };
}
