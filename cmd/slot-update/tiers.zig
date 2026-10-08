//! tiers: the CVE tiers feed (docs/design/update-policy.md), as a machine
//! reads it. Root checks its signature against the image's tiers.pub
//! before it reads a byte, as it does a release manifest's, and refuses one
//! expired, or older than the feed this machine last took. Then it answers
//! two questions about an update: which tier each CVE the update fixes is
//! in, and which Urgent and High fixes the update carries that the
//! unsigned sources left out, found from the signed feed alone.

const std = @import("std");
const Allocator = std.mem.Allocator;
const policy = @import("update-policy");
const sources = @import("cve");
const cve = @import("cve.zig");
const releases = @import("release.zig");

pub const format = "werewolf-cve-tiers/1";

/// One CVE in one tier. Urgent and High entries name the package (origin),
/// or none for the kernel's, on the feed's branch, and the version that
/// fixed it; every entry carries what its tier rests on.
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

/// data, signed as sig by key, as a feed: only if the signature checks and
/// check says it may be taken.
pub fn open(
    gpa: Allocator,
    key: releases.Key,
    data: []const u8,
    sig: []const u8,
    now: i64,
    last: ?[]const u8,
) !Feed {
    try releases.verify(key, data, sig);
    const f = try std.json.parseFromSliceLeaky(Feed, gpa, data, .{ .ignore_unknown_fields = true });
    try check(f, now, last);
    return f;
}

/// Whether f may be taken at now: its format this one, not expired, and its
/// serial no older than last, the serial of the feed this machine last took,
/// so no cache or stale copy can take a machine backwards.
///
/// Its serial must be a serial, no more than a day ahead of now, and it may
/// expire no more than a week after it: a feed signed to last forever, or
/// to outrank every later one, is refused, so not even a leaked key pins a
/// machine to one feed. Every Urgent and High entry must name a version
/// that fixed it, and a package, or none for a kernel release on the
/// feed's branch, or the promise that they are found from signed data
/// alone would not hold.
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

/// Each tier's first fix, and how many fixes each tier has, among those an
/// update carries.
pub const Tiers = struct {
    first: std.enums.EnumArray(policy.Tier, ?policy.Fix) = .initFill(null),
    count: std.enums.EnumArray(policy.Tier, u32) = .initFill(0),

    pub fn add(t: *Tiers, tier: policy.Tier, fix: policy.Fix) void {
        if (t.first.get(tier) == null) t.first.set(tier, fix);
        t.count.getPtr(tier).* += 1;
    }
};

/// What an update changes, and the CVEs the unsigned sources say it fixes.
pub const Update = struct {
    changes: []const cve.OriginChange,
    package_cves: []const cve.PackageFix,
    kernel_cves: cve.KernelFixes,
    old_kernel: []const u8,
    new_kernel: []const u8,
    /// A release's advisories, and the running image's own list of them.
    advisories: []const releases.Manifest.Advisory = &.{},
    have: []const u8 = "",
};

/// The tier of every fix an update carries, werewolf's own advisories
/// included (addAdvisories). With a feed: each CVE the
/// sources name takes the feed's tier, or Medium if the feed does not name
/// it yet; and every Urgent or High fix the feed names, in a version this
/// update brings, counts whether or not the sources named it. Without one,
/// missing, expired or not to be trusted, every CVE counts as High, and so
/// does the update itself if the sources named none, since nothing signed
/// says what it fixes. With one, an update that fixes no CVE is Low.
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

    // Each CVE by the most urgent tier that names it.
    var named: std.StringHashMapUnmanaged(Named) = .empty;
    inline for (.{ .urgent, .high, .medium, .low }) |tier| for (@field(f, @tagName(tier))) |e| {
        const slot = try named.getOrPut(gpa, e.cve);
        if (!slot.found_existing) slot.value_ptr.* = .{ .tier = tier, .entry = e };
    };

    // What the sources found, each by the feed's tier.
    for (u.package_cves) |p| for (p.cves) |id| {
        if ((try counted.getOrPut(gpa, id)).found_existing) continue;
        try addNamed(gpa, &t, named.get(id), id, p.origin);
    };
    for (u.kernel_cves.cves) |k| {
        if ((try counted.getOrPut(gpa, k.id)).found_existing) continue;
        try addNamed(gpa, &t, named.get(k.id), k.id, null);
    }

    // What the feed alone says this update fixes, Urgent and High.
    const old_kernel = sources.kernelVersion(u.old_kernel);
    const new_kernel = sources.kernelVersion(u.new_kernel);
    inline for (.{ .urgent, .high }) |tier| for (@field(f, @tagName(tier))) |e| {
        const fixed = e.fixed orelse continue;
        const carried = if (e.origin) |origin| for (u.changes) |c| {
            if (!std.mem.eql(u8, origin, c.origin) and
                !std.mem.eql(u8, origin, cve.streamBase(c.origin))) continue;
            if (cve.apkOrder(fixed, c.from) == .gt and cve.apkOrder(fixed, c.to) != .gt) break true;
        } else false else if (old_kernel != null and new_kernel != null) b: {
            // The running kernel's branch only: 6.18.56 is no fix to 6.12.
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

/// A CVE the feed names, and in which tier.
const Named = struct { tier: policy.Tier, entry: Entry };

/// werewolf's own advisories a release carries that the running image
/// does not: their ids not among those in have, the image's
/// /usr/share/werewolf/advisories (release/advisories), each counted as a
/// fix at its tier, its title the evidence. A machine knows exactly which
/// fixes its own code has, so no date or serial is compared.
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

/// "CVE-2026-1111 in busybox", or "in the kernel".
fn subject(gpa: Allocator, id: []const u8, origin: ?[]const u8) ![]const u8 {
    return if (origin) |o|
        gpa.print("{s} in {s}", .{ id, o })
    else
        gpa.print("{s} in the kernel", .{id});
}

/// What a tier rests on, for the log's why: "CVSS 8.1 from NVD
/// (CVSS:3.1/AV:N/...), in KEV since 2026-10-06", or "no score yet".
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
    // The kernel's, on another branch than the feed's, or not a release.
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
    // The sources named nothing: a source that hid them, or failed.
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
    // CVE-2026-10 (6.18.56, in the window) and CVE-2026-20 (8.17.0-r1); not
    // CVE-2026-11 (fixed long before), CVE-2026-21 (not yet), or
    // CVE-2026-22 (openssl, a stream this update leaves alone).
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
    // Nothing named, and nothing signed to say so: High, not Low.
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
