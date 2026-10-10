//! notice is the wall(1)-style warning before an update reboot. It decides
//! when to speak and what to say. The text is the staged report joined to
//! the tiers feed: package names, versions, CVE or advisory ids, and the
//! four tier words. Nothing else, so a CVE title cannot write an escape
//! onto a session. See docs/design/current.md.

const std = @import("std");
const Allocator = std.mem.Allocator;
const policy = @import("update-policy");
const tiers = @import("tiers.zig");

/// floor_secs is how long a reboot that is already due still waits, so the
/// reason is on the console before the machine goes down.
pub const floor_secs = 15;
const minute = 60;
const max_lines = 12;

/// Mark is one step of the countdown. send is the lead, in seconds, to
/// announce now. wait is the seconds until the next step. A null wait means
/// reboot once send has gone out.
pub const Mark = struct {
    send: ?i64 = null,
    brief: bool = false,
    wait: ?i64 = null,
};

/// rebootAt is when the reboot happens. A due time still ahead is that
/// time, even when an older deadline was latched: a tier that rises is due
/// sooner, and the old time must not keep it. One already past waits
/// floor_secs, and that wait is not pushed back. Once a notice has been
/// sent, the time stays.
pub fn rebootAt(due: i64, now: i64, latched: ?i64, spoke: bool) i64 {
    if (spoke) return latched orelse if (now >= due) now + floor_secs else due;
    if (now < due) return due;
    // A floor already chosen is at most floor_secs ahead. Anything later
    // is an older deadline.
    if (latched) |t| if (t >= now and t - now <= floor_secs) return t;
    return now + floor_secs;
}

/// plan is the next notice. spoken is the lead already announced, or null.
/// The first notice inside the last minute says the real time left. The
/// fifteen-second and one-second marks follow when they are still ahead.
pub fn plan(remaining: i64, spoken: ?i64) Mark {
    if (remaining > minute) return .{ .wait = remaining - minute };
    const left: i64 = if (remaining < 0) 0 else remaining;
    var send: ?i64 = null;
    var brief = false;
    if (spoken == null) {
        send = left;
        brief = left <= 1;
    } else if (left <= 15 and spoken.? > 15) {
        send = left;
        brief = left <= 1;
    } else if (left <= 1 and spoken.? > 1) {
        send = left;
        brief = true;
    }
    if (left <= 1) return .{ .send = send, .brief = brief };
    const said = send orelse spoken.?;
    return .{ .send = send, .brief = brief, .wait = if (said > 15) left - 15 else left - 1 };
}

/// Body is the part of a staged report the notice is allowed to read.
pub const Body = struct {
    packages: []const Pkg = &.{},
    package_cves: []const Fix = &.{},
    kernel_cves: Kernel = .{},
    advisories: []const Adv = &.{},

    pub const Pkg = struct {
        name: []const u8,
        from: ?[]const u8 = null,
        to: ?[]const u8 = null,
    };
    pub const Fix = struct {
        origin: []const u8,
        from: []const u8 = "",
        to: []const u8 = "",
        cves: []const []const u8 = &.{},
    };
    pub const Kernel = struct {
        from: []const u8 = "",
        to: []const u8 = "",
        cves: []const struct { id: []const u8 } = &.{},
    };
    pub const Adv = struct { id: []const u8, tier: policy.Tier };
};

/// Notice is one warning: when, how long, which tier is causing the reboot,
/// and whether this is the one-second notice (the causing tier only).
pub const Notice = struct {
    host: []const u8,
    now: i64,
    lead: i64,
    tier: policy.Tier,
    brief: bool = false,
    report: []const u8 = "",
    body: Body = .{},
    feed: ?tiers.Feed = null,
};

/// text is the message written to the console and to every login.
pub fn text(gpa: Allocator, n: Notice) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    const w = &out.writer;
    try w.print("\nBroadcast message from werewolf@{s} (autoupdate) (", .{hostOf(n.host)});
    try wallClock(w, n.now);
    try w.writeAll("):\n\n");
    if (n.lead <= 0) {
        try w.writeAll("Rebooting now to install updates. ");
    } else if (n.lead == 1) {
        try w.writeAll("Rebooting in 1 second to install updates. ");
    } else if (n.lead == minute) {
        try w.writeAll("Rebooting in 1 minute to install updates. ");
    } else try w.print("Rebooting in {d} seconds to install updates. ", .{n.lead});
    const posture = n.tier == .urgent or n.tier == .high;
    try w.print("{s}: {s}.\n\n", .{
        if (posture) "Security posture" else "Maintenance window",
        n.tier.title(),
    });
    try writeItems(gpa, w, n);
    try w.writeAll("\nThe new slot is already installed. This reboot switches to it.\n");
    return out.written();
}

fn hostOf(host: []const u8) []const u8 {
    return if (plain(host)) host else "host";
}

const Item = struct {
    name: []const u8,
    from: []const u8,
    to: []const u8,
    lines: std.ArrayList(Line) = .empty,
};
const Line = struct { id: []const u8, tier: policy.Tier, bare: bool = false };

fn writeItems(gpa: Allocator, w: *std.Io.Writer, n: Notice) !void {
    var items: std.ArrayList(Item) = .empty;
    // fixes counts CVEs and advisories the report named, before the
    // one-second notice drops other tiers. Those are not "no CVE".
    var fixes: usize = 0;
    for (n.body.package_cves) |p| {
        const show = plain(p.origin) and plain(p.from) and plain(p.to);
        for (p.cves) |id| {
            if (!plain(id)) continue;
            fixes += 1;
            if (!show) continue;
            const tier = tiers.tierOf(n.feed, id);
            if (n.brief and tier != n.tier) continue;
            try addLine(gpa, &items, p.origin, p.from, p.to, .{ .id = id, .tier = tier });
        }
    }
    const k = n.body.kernel_cves;
    const show_k = plain(strip(k.from)) and plain(strip(k.to));
    for (k.cves) |c| {
        if (!plain(c.id)) continue;
        fixes += 1;
        if (!show_k) continue;
        const tier = tiers.tierOf(n.feed, c.id);
        if (n.brief and tier != n.tier) continue;
        try addLine(gpa, &items, "linux-virt", strip(k.from), strip(k.to), .{ .id = c.id, .tier = tier });
    }
    for (n.body.advisories) |a| {
        if (!plain(a.id)) continue;
        fixes += 1;
        if (n.brief and a.tier != n.tier) continue;
        try addLine(gpa, &items, "werewolf", "", "", .{ .id = a.id, .tier = a.tier });
    }
    // A package with no CVE is listed on a Low reboot, and whenever the
    // notice would otherwise not say what is being installed.
    if (n.tier == .low or (fixes == 0 and lineCount(items.items) == 0)) {
        for (n.body.packages) |p| {
            if (!plain(p.name)) continue;
            const from = p.from orelse "";
            const to = p.to orelse "";
            if (from.len > 0 and !plain(from)) continue;
            if (to.len > 0 and !plain(to)) continue;
            if (find(items.items, p.name) != null) continue;
            try addLine(gpa, &items, p.name, from, to, .{ .id = "", .tier = n.tier, .bare = true });
        }
        if (k.cves.len == 0 and !std.mem.eql(u8, k.from, k.to) and
            plain(strip(k.from)) and plain(strip(k.to)) and find(items.items, "linux-virt") == null)
            try addLine(gpa, &items, "linux-virt", strip(k.from), strip(k.to), .{
                .id = "",
                .tier = n.tier,
                .bare = true,
            });
    }
    std.mem.sort(Item, items.items, {}, struct {
        fn less(_: void, a: Item, b: Item) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.less);
    for (items.items) |*item| std.mem.sort(Line, item.lines.items, {}, struct {
        fn less(_: void, a: Line, b: Line) bool {
            if (a.tier != b.tier) return @backingInt(a.tier) > @backingInt(b.tier);
            return std.mem.lessThan(u8, a.id, b.id);
        }
    }.less);

    var width: usize = 0;
    for (items.items) |item| width = @max(width, item.name.len);
    var shown: usize = 0;
    var total: usize = 0;
    for (items.items) |item| total += item.lines.items.len;
    for (items.items) |item| {
        if (shown >= max_lines) break;
        var header = false;
        for (item.lines.items) |line| {
            if (shown >= max_lines) break;
            if (!header) {
                try writeHeader(w, item, width);
                header = true;
            }
            if (line.bare) {
                try w.print("    no CVE, {s}\n", .{line.tier.title()});
            } else try w.print("    {s}  {s}\n", .{ line.id, line.tier.title() });
            shown += 1;
        }
    }
    // The cap can land on a package boundary. The next package is unshown
    // too, so count it here rather than only inside a half-printed one.
    if (shown < total and readable(n.report)) try w.print("and {d} more in {s}\n", .{ total - shown, n.report });
}

fn writeHeader(w: *std.Io.Writer, item: Item, width: usize) !void {
    try w.print("  {s}", .{item.name});
    try w.splatByteAll(' ', width - item.name.len);
    if (item.from.len == 0 and item.to.len == 0) {
        try w.writeByte('\n');
    } else if (item.from.len == 0) {
        try w.print("  {s}\n", .{item.to});
    } else if (item.to.len == 0) {
        try w.print("  {s} -> (removed)\n", .{item.from});
    } else try w.print("  {s} -> {s}\n", .{ item.from, item.to });
}

fn addLine(
    gpa: Allocator,
    items: *std.ArrayList(Item),
    name: []const u8,
    from: []const u8,
    to: []const u8,
    line: Line,
) !void {
    if (find(items.items, name)) |i| {
        try items.items[i].lines.append(gpa, line);
        return;
    }
    try items.append(gpa, .{ .name = name, .from = from, .to = to });
    try items.items[items.items.len - 1].lines.append(gpa, line);
}

fn find(items: []const Item, name: []const u8) ?usize {
    for (items, 0..) |item, i| if (std.mem.eql(u8, item.name, name)) return i;
    return null;
}

fn lineCount(items: []const Item) usize {
    var n: usize = 0;
    for (items) |item| n += item.lines.items.len;
    return n;
}

fn strip(version: []const u8) []const u8 {
    const prefix = "linux-virt-";
    return if (std.mem.startsWith(u8, version, prefix)) version[prefix.len..] else version;
}

/// plain is a token safe to write to a terminal: no controls, no escapes.
fn plain(s: []const u8) bool {
    if (s.len == 0 or s.len > 128) return false;
    for (s) |c| {
        if (std.ascii.isAlphanumeric(c)) continue;
        if (c != '.' and c != '_' and c != '+' and c != '-') return false;
    }
    return true;
}

fn readable(s: []const u8) bool {
    if (s.len == 0 or s.len > 256) return false;
    for (s) |c| if (c < 0x20 or c == 0x7f) return false;
    return true;
}

const days = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const months = [_][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

fn wallClock(w: *std.Io.Writer, secs: i64) !void {
    const y, const mo, const d, const h, const mi, const s = policy.civil(secs);
    // 1970-01-01 was a Thursday. days[0] is Sunday.
    const wd: usize = @intCast(@mod(@divFloor(secs, policy.day) + 4, 7));
    try w.print("{s} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} {d}", .{
        days[wd], months[mo - 1], d, h, mi, s, y,
    });
}

test "rebootAt latches the floor and freezes once spoken" {
    try std.testing.expectEqual(@as(i64, 115), rebootAt(100, 100, null, false));
    try std.testing.expectEqual(@as(i64, 115), rebootAt(100, 101, 115, false));
    try std.testing.expectEqual(@as(i64, 200), rebootAt(200, 100, null, false));
    try std.testing.expectEqual(@as(i64, 150), rebootAt(150, 100, 200, false));
    try std.testing.expectEqual(@as(i64, 200), rebootAt(150, 100, 200, true));
    // A maintenance deadline already latched does not outrank a fix that
    // has since come due. A due time still ahead replaces it too.
    try std.testing.expectEqual(@as(i64, 115), rebootAt(100, 100, 100_000, false));
    try std.testing.expectEqual(@as(i64, 250), rebootAt(250, 100, 100_000, false));
}

test "the countdown announces a minute, fifteen seconds and one second" {
    const leads = try countdown(std.testing.allocator, 90, null);
    defer std.testing.allocator.free(leads);
    try std.testing.expectEqualSlices(i64, &.{ 60, 15, 1 }, leads);

    const late = try countdown(std.testing.allocator, 10, null);
    defer std.testing.allocator.free(late);
    try std.testing.expectEqualSlices(i64, &.{ 10, 1 }, late);

    const due = try countdown(std.testing.allocator, 0, null);
    defer std.testing.allocator.free(due);
    try std.testing.expectEqualSlices(i64, &.{ 15, 1 }, due);

    // The same build was going to wait out a window. It is due now.
    const risen = try countdown(std.testing.allocator, 0, 100_000);
    defer std.testing.allocator.free(risen);
    try std.testing.expectEqualSlices(i64, &.{ 15, 1 }, risen);
}

fn countdown(gpa: Allocator, due: i64, latched0: ?i64) ![]i64 {
    var now: i64 = 0;
    var latched = latched0;
    var spoken: ?i64 = null;
    var leads: std.ArrayList(i64) = .empty;
    errdefer leads.deinit(gpa);
    for (0..8) |_| {
        const at = rebootAt(due, now, latched, spoken != null);
        latched = at;
        const step = plan(at - now, spoken);
        if (step.send) |lead| {
            try leads.append(gpa, lead);
            spoken = lead;
        }
        if (step.wait) |w| {
            if (w < 1) return error.Wait;
            now += w;
            continue;
        }
        if (at > now + floor_secs) return error.Late;
        return leads.toOwnedSlice(gpa);
    }
    return error.Spin;
}

test "plan wakes at a minute, fifteen seconds and one second" {
    const early = plan(90, null);
    try std.testing.expectEqual(@as(?i64, null), early.send);
    try std.testing.expectEqual(@as(?i64, 30), early.wait);

    const open = plan(60, null);
    try std.testing.expectEqual(@as(?i64, 60), open.send);
    try std.testing.expectEqual(false, open.brief);
    try std.testing.expectEqual(@as(?i64, 45), open.wait);

    const mid = plan(45, 60);
    try std.testing.expectEqual(@as(?i64, null), mid.send);
    try std.testing.expectEqual(@as(?i64, 30), mid.wait);

    const fifteen = plan(15, 45);
    try std.testing.expectEqual(@as(?i64, 15), fifteen.send);
    try std.testing.expectEqual(false, fifteen.brief);
    try std.testing.expectEqual(@as(?i64, 14), fifteen.wait);

    const one = plan(1, 15);
    try std.testing.expectEqual(@as(?i64, 1), one.send);
    try std.testing.expectEqual(true, one.brief);
    try std.testing.expectEqual(@as(?i64, null), one.wait);

    // Under a minute, the first notice says the real time, then one second.
    const late = plan(10, null);
    try std.testing.expectEqual(@as(?i64, 10), late.send);
    try std.testing.expectEqual(@as(?i64, 9), late.wait);
    const last = plan(1, 10);
    try std.testing.expectEqual(@as(?i64, 1), last.send);
    try std.testing.expectEqual(true, last.brief);
}

test "the notice names the package, the CVE and the risk" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const now = try policy.parseTime("2026-10-10T12:34:00Z");
    const feed: tiers.Feed = .{
        .format = tiers.format,
        .serial = "20261010T000000Z",
        .expires = "2026-10-17T00:00:00Z",
        .kernel = "6.18",
        .urgent = &.{.{ .cve = "CVE-2026-1111", .origin = "openssl", .fixed = "3.4.1-r1" }},
        .high = &.{
            .{ .cve = "CVE-2026-2222", .origin = "openssl", .fixed = "3.4.1-r1" },
            .{ .cve = "CVE-2026-52988", .fixed = "6.18.55" },
        },
    };
    const body: Body = .{
        .package_cves = &.{.{
            .origin = "openssl",
            .from = "3.4.0-r0",
            .to = "3.4.1-r1",
            .cves = &.{ "CVE-2026-2222", "CVE-2026-1111" },
        }},
        .kernel_cves = .{
            .from = "linux-virt-6.18.54-r0",
            .to = "linux-virt-6.18.55-r0",
            .cves = &.{.{ .id = "CVE-2026-52988" }},
        },
        .packages = &.{.{ .name = "busybox", .from = "1.37.0-r30", .to = "1.37.0-r31" }},
    };
    const full = try text(gpa, .{
        .host = "example",
        .now = now,
        .lead = 60,
        .tier = .urgent,
        .report = "/data/svc/autoupdate/reports/x.json",
        .body = body,
        .feed = feed,
    });
    try std.testing.expectEqualStrings(
        "\nBroadcast message from werewolf@example (autoupdate) (Sat Oct 10 12:34:00 2026):\n" ++
            "\nRebooting in 1 minute to install updates. Security posture: Urgent.\n" ++
            "\n  linux-virt  6.18.54-r0 -> 6.18.55-r0\n" ++
            "    CVE-2026-52988  High\n" ++
            "  openssl     3.4.0-r0 -> 3.4.1-r1\n" ++
            "    CVE-2026-1111  Urgent\n" ++
            "    CVE-2026-2222  High\n" ++
            "\nThe new slot is already installed. This reboot switches to it.\n",
        full,
    );

    const brief = try text(gpa, .{
        .host = "example",
        .now = now,
        .lead = 1,
        .tier = .urgent,
        .brief = true,
        .body = body,
        .feed = feed,
    });
    try std.testing.expect(std.mem.indexOf(u8, brief, "CVE-2026-1111  Urgent") != null);
    try std.testing.expect(std.mem.indexOf(u8, brief, "CVE-2026-2222") == null);
    try std.testing.expect(std.mem.indexOf(u8, brief, "Rebooting in 1 second") != null);

    const low = try text(gpa, .{
        .host = "example",
        .now = now,
        .lead = 60,
        .tier = .low,
        .body = .{ .packages = body.packages },
    });
    try std.testing.expect(std.mem.indexOf(u8, low, "Maintenance window: Low") != null);
    try std.testing.expect(std.mem.indexOf(u8, low, "busybox  1.37.0-r30 -> 1.37.0-r31") != null);
    try std.testing.expect(std.mem.indexOf(u8, low, "no CVE, Low") != null);

    const adv = try text(gpa, .{
        .host = "example",
        .now = now,
        .lead = 60,
        .tier = .urgent,
        .body = .{ .advisories = &.{.{ .id = "WW-2026-001", .tier = .urgent }} },
    });
    try std.testing.expect(std.mem.indexOf(u8, adv, "WW-2026-001  Urgent") != null);
    try std.testing.expect(std.mem.indexOf(u8, adv, "  werewolf\n") != null);
}

test "a staged report parses, titles and all" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const raw =
        \\{"packages":[{"name":"openssl","from":"1","to":"2"}],
        \\"package_cves":[{"origin":"openssl","from":"1","to":"2","cves":["CVE-2026-1111"]}],
        \\"kernel_cves":{"branch":"6.18","from":"linux-virt-1","to":"linux-virt-2","cves":[{"id":"CVE-2026-1","fixed_in":"2","title":"net: x"}]},
        \\"advisories":[{"id":"WW-2026-001","date":"2026-10-01","tier":"urgent","title":"fence: old"}]}
    ;
    const body = try std.json.parseFromSliceLeaky(Body, arena.allocator(), raw, .{
        .ignore_unknown_fields = true,
    });
    try std.testing.expectEqualStrings("openssl", body.package_cves[0].origin);
    try std.testing.expectEqualStrings("CVE-2026-1", body.kernel_cves.cves[0].id);
    try std.testing.expectEqual(policy.Tier.urgent, body.advisories[0].tier);
}

test "a long notice names the report and drops an unsafe id" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var cves: [13][]const u8 = undefined;
    for (&cves, 0..) |*c, i| c.* = try std.fmt.allocPrint(gpa, "CVE-2026-{d:0>4}", .{i});
    var ids: [14][]const u8 = undefined;
    @memcpy(ids[0..13], &cves);
    ids[13] = "CVE-2026-9\n";
    const body: Body = .{
        .package_cves = &.{.{
            .origin = "openssl",
            .from = "1",
            .to = "2",
            .cves = &ids,
        }},
    };
    const msg = try text(gpa, .{
        .host = "bad host",
        .now = 0,
        .lead = 15,
        .tier = .high,
        .report = "/data/svc/autoupdate/reports/x.json",
        .body = body,
    });
    try std.testing.expect(std.mem.indexOf(u8, msg, "werewolf@host") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "and 1 more in /data/svc/autoupdate/reports/x.json") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "CVE-2026-9") == null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "Security posture: High") != null);

    // Twelve lines fill the cap on the first package. The next package
    // still has to be counted.
    var first: [12][]const u8 = undefined;
    for (&first, 0..) |*c, i| c.* = try std.fmt.allocPrint(gpa, "CVE-2026-{d:0>4}", .{i});
    const split = try text(gpa, .{
        .host = "example",
        .now = 0,
        .lead = 60,
        .tier = .high,
        .report = "/data/svc/autoupdate/reports/x.json",
        .body = .{ .package_cves = &.{
            .{ .origin = "openssl", .from = "1", .to = "2", .cves = &first },
            .{ .origin = "zlib", .from = "1", .to = "2", .cves = &.{"CVE-2026-0099"} },
        } },
    });
    try std.testing.expect(std.mem.indexOf(u8, split, "and 1 more in /data/svc/autoupdate/reports/x.json") != null);
    try std.testing.expect(std.mem.indexOf(u8, split, "CVE-2026-0099") == null);
    try std.testing.expect(std.mem.indexOf(u8, split, "zlib") == null);
}

test "a one-second notice does not call a filtered CVE no CVE" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const feed: tiers.Feed = .{
        .format = tiers.format,
        .serial = "20261010T000000Z",
        .expires = "2026-10-17T00:00:00Z",
        .kernel = "6.18",
        .high = &.{.{ .cve = "CVE-2026-2222", .origin = "openssl", .fixed = "2" }},
    };
    const msg = try text(gpa, .{
        .host = "example",
        .now = 0,
        .lead = 1,
        .tier = .urgent,
        .brief = true,
        .body = .{
            .package_cves = &.{.{
                .origin = "openssl",
                .from = "1",
                .to = "2",
                .cves = &.{"CVE-2026-2222"},
            }},
            .packages = &.{.{ .name = "busybox", .from = "1", .to = "2" }},
        },
        .feed = feed,
    });
    try std.testing.expect(std.mem.indexOf(u8, msg, "no CVE") == null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "busybox") == null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "CVE-2026-2222") == null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "Security posture: Urgent") != null);
}
