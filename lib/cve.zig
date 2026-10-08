//! cve: the CVE sources, as the tiers feed's writer (tools/cve-tiers.zig)
//! and the updater's reader (cmd/slot-update/cve.zig) both read them:
//! Wolfi's security.json, and the kernel CNA's records with the stable
//! release that fixed each CVE on a branch. One reading on both sides, so
//! nothing the writer signs into the feed is something a machine refuses.

const std = @import("std");

/// CVE-2026-52988: the year, and four digits or more.
pub fn validCve(id: []const u8) bool {
    if (id.len < 13 or id.len > 32 or !std.mem.startsWith(u8, id, "CVE-") or
        id[8] != '-') return false;
    for (id[4..8]) |c| if (!std.ascii.isDigit(c)) return false;
    for (id[9..]) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// linux-virt-6.18.55-r0, or 6.18.55, as {6, 18, 55}.
pub fn kernelVersion(s: []const u8) ?[3]u32 {
    var v = s;
    if (std.mem.startsWith(u8, v, "linux-virt-")) v = v["linux-virt-".len..];
    if (std.mem.findScalar(u8, v, '-')) |i| v = v[0..i];
    var out: [3]u32 = .{ 0, 0, 0 };
    var it = std.mem.splitScalar(u8, v, '.');
    for (&out) |*part| {
        const field = it.next() orelse return null;
        // Digits alone: parseInt would also take "+" and "_".
        if (field.len == 0 or field.len > 9) return null;
        for (field) |c| if (!std.ascii.isDigit(c)) return null;
        part.* = std.fmt.parseInt(u32, field, 10) catch return null;
    }
    if (it.next() != null) return null;
    return out;
}

/// Whether kernel version a is older than b.
pub fn kernelLess(a: [3]u32, b: [3]u32) bool {
    return std.mem.order(u32, &a, &b) == .lt;
}

/// Whether version is a kernel release on branch: 6.18.55 on 6.18.
pub fn onBranch(version: []const u8, branch: []const u8) bool {
    return kernelVersion(version) != null and version.len > branch.len and
        std.mem.startsWith(u8, version, branch) and version[branch.len] == '.';
}

/// Wolfi's security.json, as much of it as is used.
pub const SecDb = struct {
    packages: []const struct {
        pkg: struct {
            name: []const u8,
            secfixes: ?std.json.ArrayHashMap([]const []const u8) = null,
        },
    },
};

/// The parts of a kernel CNA record (CVE JSON 5) that say which stable
/// release fixed it on which branch.
pub const KernelRecord = struct {
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

/// The release that fixed rec on branch (6.18): its "unaffected" semver
/// entry whose lessThanOrEqual is the branch's wildcard, and whose version
/// is a release on the branch itself (onBranch), 6.18.55 for 6.18.*.
pub fn kernelFixedOn(rec: KernelRecord, branch: []const u8) ?[]const u8 {
    for (rec.containers.cna.affected) |a| {
        for (a.versions) |v| {
            if (!std.mem.eql(u8, v.status, "unaffected")) continue;
            if (!std.mem.eql(u8, v.versionType orelse "", "semver")) continue;
            const le = v.lessThanOrEqual orelse continue;
            if (!std.mem.endsWith(u8, le, ".*") or
                !std.mem.eql(u8, le[0 .. le.len - 2], branch)) continue;
            if (onBranch(v.version, branch)) return v.version;
        }
    }
    return null;
}

/// vulns-master/cve/published/2026/CVE-2026-52988.json
pub fn isKernelRecord(name: []const u8) bool {
    const base = name[(std.mem.findScalarLast(u8, name, '/') orelse return false) + 1 ..];
    return std.mem.find(u8, name, "/cve/published/") != null and
        std.mem.startsWith(u8, base, "CVE-") and std.mem.endsWith(u8, base, ".json");
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test validCve {
    for ([_][]const u8{
        "CVE-2026-0001",
        "CVE-1999-1234567",
    }) |id| try testing.expect(validCve(id));
    for ([_][]const u8{
        "CVE-2026-001",
        "cve-2026-0001",
        "CVE-2026-0001 ",
        "CVE-20260-0001",
        "GHSA-2026-0001",
        "CVE-2026-0001a",
    }) |id| try testing.expect(!validCve(id));
}

test kernelVersion {
    try testing.expectEqual([3]u32{ 6, 18, 55 }, kernelVersion("linux-virt-6.18.55-r0").?);
    try testing.expectEqual([3]u32{ 6, 18, 42 }, kernelVersion("6.18.42").?);
    try testing.expectEqual(null, kernelVersion("6.18"));
    try testing.expectEqual(null, kernelVersion("6.18."));
    try testing.expectEqual(null, kernelVersion("6.18.x"));
    try testing.expectEqual(null, kernelVersion("6.18.+5"));
    try testing.expectEqual(null, kernelVersion("6.1_8.5"));
    try testing.expectEqual(null, kernelVersion("+6.1_8.5_5"));
    try testing.expect(kernelLess(.{ 6, 18, 9 }, .{ 6, 18, 10 }));
    try testing.expect(onBranch("6.18.55", "6.18"));
    try testing.expect(!onBranch("6.18.55", "6.1"));
    try testing.expect(!onBranch("6.18", "6.18"));
    try testing.expect(!onBranch("6.18.x", "6.18"));
    try testing.expect(!kernelLess(.{ 6, 18, 10 }, .{ 6, 18, 10 }));
}

test kernelFixedOn {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const rec = try std.json.parseFromSliceLeaky(KernelRecord, arena.allocator(),
        \\{"cveMetadata":{"cveId":"CVE-2026-52988"},"containers":{"cna":{"title":"netfilter: x",
        \\ "affected":[{"versions":[{"version":"0","lessThan":"5.15","status":"unaffected","versionType":"semver"},
        \\   {"version":"6.12.101","lessThanOrEqual":"6.12.*","status":"unaffected","versionType":"semver"},
        \\   {"version":"6.18.55","lessThanOrEqual":"6.18.*","status":"unaffected","versionType":"semver"},
        \\   {"version":"6.19","lessThanOrEqual":"6.19.*","status":"unaffected","versionType":"semver"},
        \\   {"version":"6.1.9","lessThanOrEqual":"6.1.*","status":"affected","versionType":"semver"},
        \\   {"version":"abc","lessThan":"def","status":"affected","versionType":"git"}]}]}}}
    , .{ .ignore_unknown_fields = true });
    try testing.expectEqualStrings("netfilter: x", rec.containers.cna.title);
    try testing.expectEqualStrings("6.18.55", kernelFixedOn(rec, "6.18").?);
    try testing.expectEqualStrings("6.12.101", kernelFixedOn(rec, "6.12").?);
    try testing.expectEqual(null, kernelFixedOn(rec, "6.1"));
    // Not a release on the branch: 6.19 is its first, not a stable fix.
    try testing.expectEqual(null, kernelFixedOn(rec, "6.19"));
    try testing.expectEqual(null, kernelFixedOn(rec, "6.20"));
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
