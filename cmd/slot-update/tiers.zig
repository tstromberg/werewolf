//! tiers reads the signed CVE tiers feed (docs/design/update-policy.md) and
//! tiers an update's fixes by it, including Urgent and High fixes that the
//! unsigned sources missed.

const std = @import("std");
const Allocator = std.mem.Allocator;
const policy = @import("update-policy");
const sources = @import("cve");
const cve = @import("cve.zig");
const releases = @import("release.zig");
const apk = @import("apk");

pub const format = "werewolf-cve-tiers/1";

/// Entry is one CVE in one tier, with the evidence for its tier. Urgent and
/// High entries must name the fixed version and the package (origin), or no
/// origin for a kernel fix on the feed's branch.
pub const Entry = struct {
    cve: []const u8,
    origin: ?[]const u8 = null,
    fixed: ?[]const u8 = null,
    score: ?f64 = null,
    vector: ?[]const u8 = null,
    source: ?[]const u8 = null,
    kev: ?[]const u8 = null,
};

pub const Feed = struct {
    format: []const u8,
    serial: []const u8,
    expires: []const u8,
    kernel: []const u8,
    urgent: []const Entry = &.{},
    high: []const Entry = &.{},
    medium: []const Entry = &.{},
    low: []const Entry = &.{},
};

/// open verifies sig over data with key before parsing it, then returns the
/// feed if check accepts it.
pub fn open(
    gpa: Allocator,
    key: apk.Key,
    data: []const u8,
    sig: []const u8,
    now: i64,
    last: ?[]const u8,
) !Feed {
    try apk.verify(key, data, sig);
    const f = try std.json.parseFromSliceLeaky(Feed, gpa, data, .{ .ignore_unknown_fields = true });
    try check(f, now, last);
    return f;
}

/// check returns an error unless f may be taken at now. The format must
/// match, the feed must not be expired, and its serial must not be older
/// than last, so a stale copy cannot take a machine backwards. The serial
/// may be at most a day ahead and expiry at most a week after it, so even a
/// leaked key cannot pin a machine to one feed. Urgent and High entries must
/// be well formed (see Entry), since they are matched from the feed alone.
pub fn check(f: Feed, now: i64, last: ?[]const u8) !void {
    if (!std.mem.eql(u8, f.format, format)) return error.BadFormat;
    const signed = policy.parseSerial(f.serial) catch return error.BadSerial;
    const expires = policy.parseTime(f.expires) catch return error.BadExpiry;
    if (signed > now + policy.day) return error.BadSerial;
    if (expires > signed + 7 * policy.day) return error.BadExpiry;
    if (expires <= now) return error.Expired;
    if (last) |l| if (std.mem.order(u8, f.serial, l) == .lt) return error.Older;
    for ([_][]const Entry{ f.urgent, f.high }) |entries| for (entries) |e| {
        const fixed = e.fixed orelse return error.BadEntry;
        if (e.origin == null and !sources.onBranch(fixed, f.kernel)) return error.BadEntry;
    };
}

/// Tiers holds, for an update, each tier's first fix and its fix count.
pub const Tiers = struct {
    first: std.enums.EnumArray(policy.Tier, ?policy.Fix) = .initFill(null),
    count: std.enums.EnumArray(policy.Tier, u32) = .initFill(0),

    pub fn add(t: *Tiers, tier: policy.Tier, fix: policy.Fix) void {
        if (t.first.get(tier) == null) t.first.set(tier, fix);
        t.count.getPtr(tier).* += 1;
    }
};

/// Update is what an update changes and the CVEs the unsigned sources say it
/// fixes.
pub const Update = struct {
    changes: []const cve.OriginChange,
    package_cves: []const cve.PackageFix,
    kernel_cves: cve.KernelFixes,
    old_kernel: []const u8,
    new_kernel: []const u8,
    /// advisories are the release's; have is the running image's list.
    advisories: []const releases.Manifest.Advisory = &.{},
    have: []const u8 = "",
};

/// tiersOf tiers every fix the update carries, werewolf's advisories
/// included. With a feed, each CVE the sources name takes the feed's tier,
/// or Medium if the feed does not list it yet; every Urgent or High fix the
/// feed places in this update's version range counts even if the sources
/// missed it; and an update with no fixes is Low. Without a feed, every CVE
/// is High, and so is the update itself if no fix is Urgent or High, since
/// nothing signed says what it fixes.
pub fn tiersOf(gpa: Allocator, feed: ?Feed, u: Update) !Tiers {
    var t: Tiers = .{};
    var counted: std.StringHashMapUnmanaged(void) = .empty;
    const f = feed orelse {
        for (u.package_cves) |p| for (p.cves) |id| {
            if ((try counted.getOrPut(gpa, id)).found_existing) continue;
            t.add(
                .high,
                .{ .subject = try subject(gpa, id, p.origin), .evidence = "no valid tiers feed" },
            );
        };
        for (u.kernel_cves.cves) |k| {
            if ((try counted.getOrPut(gpa, k.id)).found_existing) continue;
            t.add(
                .high,
                .{ .subject = try subject(gpa, k.id, null), .evidence = "no valid tiers feed" },
            );
        }
        try addAdvisories(gpa, &t, u.advisories, u.have);
        if (t.count.get(.high) == 0 and t.count.get(.urgent) == 0)
            t.add(
                .high,
                .{
                    .subject = "this update",
                    .evidence = "no valid tiers feed to say what it fixes",
                },
            );
        return t;
    };

    // Index each CVE under the most urgent tier that lists it.
    var named: std.StringHashMapUnmanaged(Named) = .empty;
    inline for (.{ .urgent, .high, .medium, .low }) |tier| for (@field(f, @tagName(tier))) |e| {
        const slot = try named.getOrPut(gpa, e.cve);
        if (!slot.found_existing) slot.value_ptr.* = .{ .tier = tier, .entry = e };
    };

    // Tier what the sources found by the feed.
    for (u.package_cves) |p| for (p.cves) |id| {
        if ((try counted.getOrPut(gpa, id)).found_existing) continue;
        try addNamed(gpa, &t, named.get(id), id, p.origin);
    };
    for (u.kernel_cves.cves) |k| {
        if ((try counted.getOrPut(gpa, k.id)).found_existing) continue;
        try addNamed(gpa, &t, named.get(k.id), k.id, null);
    }

    // Add Urgent and High fixes the feed alone places in this update.
    const old_kernel = sources.kernelVersion(u.old_kernel);
    const new_kernel = sources.kernelVersion(u.new_kernel);
    inline for (.{ .urgent, .high }) |tier| for (@field(f, @tagName(tier))) |e| {
        const fixed = e.fixed orelse continue;
        const carried = if (e.origin) |origin| for (u.changes) |c| {
            if (!std.mem.eql(u8, origin, c.origin) and
                !std.mem.eql(u8, origin, cve.streamBase(c.origin))) continue;
            if (cve.apkOrder(fixed, c.from) == .gt and cve.apkOrder(fixed, c.to) != .gt) break true;
        } else false else if (old_kernel != null and new_kernel != null) b: {
            // Only the new kernel's branch: 6.18.56 does not fix 6.12.
            const v = sources.kernelVersion(fixed) orelse break :b false;
            if (v[0] != new_kernel.?[0] or v[1] != new_kernel.?[1]) break :b false;
            break :b sources.kernelLess(old_kernel.?, v) and !sources.kernelLess(new_kernel.?, v);
        } else false;
        if (!carried or (try counted.getOrPut(gpa, e.cve)).found_existing) continue;
        t.add(
            tier,
            .{ .subject = try subject(gpa, e.cve, e.origin), .evidence = try evidence(gpa, e) },
        );
    };
    try addAdvisories(gpa, &t, u.advisories, u.have);
    for (t.count.values) |n| if (n > 0) return t;
    t.first.set(.low, .{ .subject = "this update", .evidence = "it fixes no known CVE" });
    return t;
}

/// Named is a feed entry and its tier.
const Named = struct { tier: policy.Tier, entry: Entry };

/// addAdvisories adds each werewolf advisory the release carries whose id is
/// not in have (/usr/share/werewolf/advisories), at its tier, with its title
/// as evidence. The image lists exactly what its code fixes, so no date or
/// serial is compared.
fn addAdvisories(
    gpa: Allocator,
    t: *Tiers,
    advisories: []const releases.Manifest.Advisory,
    have: []const u8,
) !void {
    var held: std.StringHashMapUnmanaged(void) = .empty;
    var lines = std.mem.splitScalar(u8, have, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t");
        const id = words.next() orelse continue;
        if (id[0] != '#') try held.put(gpa, id, {});
    }
    for (advisories) |a| {
        if (held.contains(a.id)) continue;
        t.add(
            a.tier,
            .{ .subject = try gpa.print("{s} in werewolf", .{a.id}), .evidence = a.title },
        );
    }
}

fn addNamed(
    gpa: Allocator,
    t: *Tiers,
    found: ?Named,
    id: []const u8,
    origin: ?[]const u8,
) !void {
    const s = try subject(gpa, id, origin);
    if (found) |x|
        t.add(x.tier, .{ .subject = s, .evidence = try evidence(gpa, x.entry) })
    else
        t.add(.medium, .{ .subject = s, .evidence = "not in the tiers feed yet" });
}

/// subject returns "CVE-2026-1111 in busybox", or "... in the kernel".
fn subject(gpa: Allocator, id: []const u8, origin: ?[]const u8) ![]const u8 {
    return if (origin) |o|
        gpa.print("{s} in {s}", .{ id, o })
    else
        gpa.print("{s} in the kernel", .{id});
}

/// evidence describes what an entry's tier rests on, for the log's why:
/// "CVSS 8.1 from NVD (CVSS:3.1/AV:N/...), in KEV since 2026-10-06", or
/// "no score yet".
pub fn evidence(gpa: Allocator, e: Entry) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    if (e.score) |s| {
        const by = if (e.source) |src| sourceName(src) else "an unnamed source";
        try out.writer.print("CVSS {d:.1} from {s}", .{ s, by });
        if (e.vector) |v| try out.writer.print(" ({s})", .{v});
    } else try out.writer.writeAll("no score yet");
    if (e.kev) |since| try out.writer.print(", in KEV since {s}", .{since});
    return out.written();
}

fn sourceName(src: []const u8) []const u8 {
    if (std.mem.eql(u8, src, "nvd")) return "NVD";
    if (std.mem.eql(u8, src, "cna")) return "its CNA";
    if (std.mem.eql(u8, src, "cisa-adp")) return "CISA";
    return src;
}

// --- tests ---------------------------------------------------------------------

const t0 = 1791381731; // 2026-10-07T14:02:11Z

fn feedOf(urgent: []const Entry, high: []const Entry, medium: []const Entry) Feed {
    return .{
        .format = format,
        .serial = "20261007T140000Z",
        .expires = "2026-10-10T14:00:00Z",
        .kernel = "6.18",
        .urgent = urgent,
        .high = high,
        .medium = medium,
    };
}

test "check: format, expiry, and never backwards" {
    const f = feedOf(&.{}, &.{}, &.{});
    try check(f, t0, null);
    try check(f, t0, "20261007T140000Z");
    try check(f, t0, "20261006T000000Z");
    try std.testing.expectError(error.Older, check(f, t0, "20261007T150000Z"));
    try std.testing.expectError(error.Expired, check(f, t0 + 3 * policy.day, null));
    var g = f;
    g.format = "werewolf-cve-tiers/2";
    try std.testing.expectError(error.BadFormat, check(g, t0, null));
}

test "check: serial and expiry bounded, signed entries whole" {
    var f = feedOf(&.{}, &.{}, &.{});
    f.serial = "20261009T140000Z"; // two days ahead
    try std.testing.expectError(error.BadSerial, check(f, t0, null));
    f = feedOf(&.{}, &.{}, &.{});
    f.serial = "~";
    try std.testing.expectError(error.BadSerial, check(f, t0, null));
    f = feedOf(&.{}, &.{}, &.{});
    f.expires = "2027-01-01T00:00:00Z"; // signed to outlast a week
    try std.testing.expectError(error.BadExpiry, check(f, t0, null));
    f = feedOf(&.{.{ .cve = "CVE-2026-1", .origin = "curl" }}, &.{}, &.{});
    try std.testing.expectError(error.BadEntry, check(f, t0, null));
    f = feedOf(&.{.{ .cve = "CVE-2026-1", .fixed = "1-r0" }}, &.{}, &.{});
    try std.testing.expectError(error.BadEntry, check(f, t0, null));
    // A kernel fix on another branch, or not a release version.
    f = feedOf(&.{}, &.{.{ .cve = "CVE-2026-1", .fixed = "6.12.1" }}, &.{});
    try std.testing.expectError(error.BadEntry, check(f, t0, null));
    f = feedOf(&.{}, &.{.{ .cve = "CVE-2026-1", .fixed = "6.18.x" }}, &.{});
    try std.testing.expectError(error.BadEntry, check(f, t0, null));
    f = feedOf(&.{}, &.{.{ .cve = "CVE-2026-1", .fixed = "6.18.56" }}, &.{});
    try check(f, t0, null);
}

test "tiers: the feed's tier, Medium when unnamed, Low with no CVE" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const f = feedOf(
        &.{.{
            .cve = "CVE-2026-1",
            .origin = "openssl",
            .fixed = "3.5.4-r0",
            .score = 9.8,
            .source = "nvd",
            .kev = "2026-10-06",
        }},
        &.{},
        &.{.{ .cve = "CVE-2026-2" }},
    );
    const t = try tiersOf(gpa, f, .{
        .changes = &.{.{ .origin = "openssl", .from = "3.5.3-r0", .to = "3.5.4-r0" }},
        .package_cves = &.{.{
            .origin = "openssl",
            .from = "3.5.3-r0",
            .to = "3.5.4-r0",
            .cves = &.{ "CVE-2026-1", "CVE-2026-2", "CVE-2026-3" },
        }},
        .kernel_cves = .{},
        .old_kernel = "linux-virt-6.18.55-r0",
        .new_kernel = "linux-virt-6.18.55-r0",
    });
    try std.testing.expectEqual([4]u32{ 0, 2, 0, 1 }, t.count.values);
    try std.testing.expectEqualStrings("CVE-2026-1 in openssl", t.first.get(.urgent).?.subject);
    try std.testing.expectEqualStrings(
        "CVSS 9.8 from NVD, in KEV since 2026-10-06",
        t.first.get(.urgent).?.evidence,
    );
    try std.testing.expectEqualStrings("no score yet", t.first.get(.medium).?.evidence);

    const none = try tiersOf(gpa, f, .{
        .changes = &.{.{ .origin = "zlib", .from = "1.3.1-r0", .to = "1.3.1-r1" }},
        .package_cves = &.{},
        .kernel_cves = .{},
        .old_kernel = "linux-virt-6.18.55-r0",
        .new_kernel = "linux-virt-6.18.55-r0",
    });
    try std.testing.expectEqual([4]u32{ 0, 0, 0, 0 }, none.count.values);
    try std.testing.expectEqualStrings("it fixes no known CVE", none.first.get(.low).?.evidence);
}

test "tiers: Urgent and High from the feed alone, in this update's versions" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const f = feedOf(
        &.{
            .{
                .cve = "CVE-2026-10",
                .fixed = "6.18.56",
                .score = 9.8,
                .source = "cna",
            },
            .{
                .cve = "CVE-2026-11",
                .fixed = "6.18.40",
                .score = 9.8,
                .source = "cna",
            },
        },
        &.{
            .{
                .cve = "CVE-2026-20",
                .origin = "curl",
                .fixed = "8.17.0-r1",
                .score = 7.5,
                .source = "nvd",
            },
            .{
                .cve = "CVE-2026-21",
                .origin = "curl",
                .fixed = "8.18.0-r0",
                .score = 7.5,
                .source = "nvd",
            },
            .{
                .cve = "CVE-2026-22",
                .origin = "openssl",
                .fixed = "3.6.0-r0",
                .score = 7.5,
                .source = "nvd",
            },
        },
        &.{},
    );
    // The sources named nothing, as if one hid them or failed.
    const t = try tiersOf(gpa, f, .{
        .changes = &.{
            .{ .origin = "curl", .from = "8.17.0-r0", .to = "8.17.0-r2" },
            .{ .origin = "openssl-3.5", .from = "3.5.3-r0", .to = "3.5.4-r0" },
        },
        .package_cves = &.{},
        .kernel_cves = .{},
        .old_kernel = "linux-virt-6.18.55-r0",
        .new_kernel = "linux-virt-6.18.56-r0",
    });
    // CVE-2026-10 (6.18.56, in range) and CVE-2026-20 (8.17.0-r1) count;
    // CVE-2026-11 (fixed long before), CVE-2026-21 (not yet) and
    // CVE-2026-22 (an openssl stream this update does not touch) do not.
    try std.testing.expectEqual([4]u32{ 0, 0, 1, 1 }, t.count.values);
    try std.testing.expectEqualStrings("CVE-2026-10 in the kernel", t.first.get(.urgent).?.subject);
    try std.testing.expectEqualStrings("CVE-2026-20 in curl", t.first.get(.high).?.subject);
}

test "tiers: without a feed, every CVE is High" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const t = try tiersOf(arena.allocator(), null, .{
        .changes = &.{},
        .package_cves = &.{.{
            .origin = "busybox",
            .from = "1",
            .to = "2",
            .cves = &.{"CVE-2026-1"},
        }},
        .kernel_cves = .{ .cves = &.{.{
            .id = "CVE-2026-9",
            .fixed_in = "6.18.56",
            .title = "x",
        }} },
        .old_kernel = "linux-virt-6.18.55-r0",
        .new_kernel = "linux-virt-6.18.56-r0",
    });
    try std.testing.expectEqual([4]u32{ 0, 0, 2, 0 }, t.count.values);
    try std.testing.expectEqualStrings("no valid tiers feed", t.first.get(.high).?.evidence);
    // Nothing named and nothing signed to say so: High, not Low.
    const quiet = try tiersOf(arena.allocator(), null, .{
        .changes = &.{},
        .package_cves = &.{},
        .kernel_cves = .{},
        .old_kernel = "linux-virt-6.18.55-r0",
        .new_kernel = "linux-virt-6.18.56-r0",
    });
    try std.testing.expectEqual([4]u32{ 0, 0, 1, 0 }, quiet.count.values);
}

test "advisories: only those this image lacks" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var t: Tiers = .{};
    try addAdvisories(gpa, &t, &.{
        .{ .id = "WW-2026-001", .tier = .high, .title = "fence: old" },
        .{ .id = "WW-2026-002", .tier = .urgent, .title = "init: new" },
    }, "# comment\nWW-2026-001  2026-10-01  high  fence: old\n");
    try std.testing.expectEqual([4]u32{ 0, 0, 0, 1 }, t.count.values);
    try std.testing.expectEqualStrings("WW-2026-002 in werewolf", t.first.get(.urgent).?.subject);
    try std.testing.expectEqualStrings("init: new", t.first.get(.urgent).?.evidence);
}

test "evidence" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    try std.testing.expectEqualStrings(
        "no score yet",
        try evidence(gpa, .{ .cve = "CVE-1999-0289" }),
    );
    try std.testing.expectEqualStrings(
        "CVSS 5.5 from CISA",
        try evidence(gpa, .{ .cve = "x", .score = 5.5, .source = "cisa-adp" }),
    );
    try std.testing.expectEqualStrings(
        "CVSS 8.1 from NVD (CVSS:3.1/AV:N), in KEV since 2026-10-01",
        try evidence(gpa, .{
            .cve = "x",
            .score = 8.1,
            .source = "nvd",
            .vector = "CVSS:3.1/AV:N",
            .kev = "2026-10-01",
        }),
    );
    try std.testing.expectEqualStrings(
        "no score yet, in KEV since 2026-10-01",
        try evidence(gpa, .{ .cve = "x", .kev = "2026-10-01" }),
    );
}
