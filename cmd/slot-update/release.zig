//! release checks a werewolf release manifest: its signature by the image key,
//! then its form, architecture and fields (docs/releases.md). Signatures are
//! RSA PKCS#1 v1.5 over SHA-256, as `openssl dgst -sha256 -sign` makes them
//! (lib/apk.zig checks them).

const std = @import("std");
const Allocator = std.mem.Allocator;
const apk = @import("apk");
const policy = @import("update-policy");

/// Manifest is the part of a release manifest the updater uses. Manifests
/// do not expire: a release stands until the next one supersedes it.
pub const Manifest = struct {
    format: []const u8,
    form: []const u8,
    arch: []const u8,
    serial: []const u8,
    build: []const u8,
    kernel: []const u8,
    files: std.json.ArrayHashMap(File),
    packages: []const struct { name: []const u8, version: []const u8, origin: []const u8 },
    /// advisories lists fixes to werewolf's own code, which no CVE names
    /// (release/advisories).
    advisories: []const Advisory = &.{},

    pub const File = struct { sha256: []const u8, size: u64 };
    /// Advisory is one line of release/advisories. Its date is ignored
    /// because no machine compares it.
    pub const Advisory = struct {
        id: []const u8,
        tier: policy.Tier,
        title: []const u8,
    };

    /// slot_files are the files a slot needs from a release.
    pub const slot_files = [_][]const u8{ "vmlinuz", "stage0.zst", "root.erofs" };
    /// bitten_stage0 replaces stage0.zst on a machine bite took over. It adds
    /// the modules a distro's filesystem needs (Makefile, BITTEN_TAGS).
    pub const bitten_stage0 = "stage0-bitten.zst";
};

/// open verifies sig over data with key, then parses the manifest. It must
/// be for this form and arch, have a serial at most a day after now, and
/// name every slot file with a valid entry.
pub fn open(
    gpa: Allocator,
    key: apk.Key,
    data: []const u8,
    sig: []const u8,
    form: []const u8,
    arch: []const u8,
    now: i64,
) !Manifest {
    try apk.verify(key, data, sig);
    const m = std.json.parseFromSliceLeaky(
        Manifest,
        gpa,
        data,
        .{ .ignore_unknown_fields = true },
    ) catch
        return error.BadManifest;
    if (!std.mem.eql(u8, m.format, "werewolf-release/1")) return error.BadManifest;
    if (!std.mem.eql(u8, m.form, form) or
        !std.mem.eql(u8, m.arch, arch)) return error.NotThisMachine;
    // build goes into report file names and the space- and line-separated
    // attempt and bad files, so allow only 16 lower-case hex digits.
    if (m.build.len != 16) return error.BadManifest;
    for (m.build) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return error.BadManifest;
    const signed = policy.parseSerial(m.serial) catch return error.BadManifest;
    if (signed > now + 24 * 3600) return error.BadManifest;
    for (m.advisories) |a| if (!validAdvisory(a)) return error.BadManifest;
    for (Manifest.slot_files) |name|
        try checkFile(m.files.map.get(name) orelse return error.BadManifest);
    if (m.files.map.get(Manifest.bitten_stage0)) |f| try checkFile(f);
    return m;
}

/// checkFile requires a lower-case hex sha256 and a size of 1 byte to 256 MiB.
fn checkFile(f: Manifest.File) !void {
    if (f.sha256.len != 64 or f.size == 0 or f.size > 256 << 20) return error.BadManifest;
    for (f.sha256) |c| if (!std.ascii.isHex(c) or std.ascii.isUpper(c)) return error.BadManifest;
}

/// validAdvisory applies the rules howl's manifest.zig writes advisories
/// by: an id of WW-YEAR-NUMBER and a title of printable ASCII without
/// quotes or backslashes. JSON parsing already checks the tier.
pub fn validAdvisory(a: Manifest.Advisory) bool {
    const id = a.id;
    if (id.len < 11 or id.len > 32 or !std.mem.startsWith(u8, id, "WW-") or
        id[7] != '-') return false;
    for (id[3..7]) |c| if (!std.ascii.isDigit(c)) return false;
    for (id[8..]) |c| if (!std.ascii.isDigit(c)) return false;
    if (a.title.len == 0 or a.title.len > 200) return false;
    for (a.title) |c| if (c < ' ' or c > '~' or c == '"' or c == '\\') return false;
    return true;
}

test validAdvisory {
    const good: Manifest.Advisory = .{ .id = "WW-2026-001", .tier = .high, .title = "fence: x" };
    try std.testing.expect(validAdvisory(good));
    var a = good;
    a.id = "WW-26-1";
    try std.testing.expect(!validAdvisory(a));
    a = good;
    a.title = "a \"quote\"";
    try std.testing.expect(!validAdvisory(a));
    // An unknown tier fails to parse, so the whole manifest is refused.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try std.json.parseFromSliceLeaky(
        Manifest.Advisory,
        arena.allocator(),
        \\{"id": "WW-2026-001", "date": "2026-10-07", "tier": "high", "title": "fence: x"}
    ,
        .{ .ignore_unknown_fields = true },
    );
    try std.testing.expectEqual(policy.Tier.high, parsed.tier);
    try std.testing.expectError(error.InvalidEnumTag, std.json.parseFromSliceLeaky(
        Manifest.Advisory,
        arena.allocator(),
        \\{"id": "WW-2026-001", "tier": "severe", "title": "fence: x"}
    ,
        .{ .ignore_unknown_fields = true },
    ));
}

const testing = std.testing;
const test_key = @embedFile("testdata/image.pub");
const test_manifest = @embedFile("testdata/prod-ssh-aarch64.json");
const test_sig = @embedFile("testdata/prod-ssh-aarch64.json.sig");
/// signed_at is when the test manifest was signed.
const signed_at = 1791299416;

test "a release CI signed checks, and nothing else does" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = try apk.parseKey(a, test_key);
    try testing.expectEqual(512, key.modulus.len);

    const m = try open(a, key, test_manifest, test_sig, "prod-ssh", "aarch64", signed_at + 3600);
    try testing.expectEqualStrings("cd9d31b81c66fe3a", m.build);
    try testing.expectEqualStrings("linux-virt-6.18.55-r0", m.kernel);
    try testing.expectEqual(20717568, m.files.map.get("root.erofs").?.size);

    try testing.expectError(
        error.NotThisMachine,
        open(a, key, test_manifest, test_sig, "prod", "aarch64", signed_at),
    );
    try testing.expectError(
        error.NotThisMachine,
        open(a, key, test_manifest, test_sig, "prod-ssh", "x86_64", signed_at),
    );
    // A release is good until another supersedes it, however old.
    _ = try open(a, key, test_manifest, test_sig, "prod-ssh", "aarch64", signed_at + 365 * 86400);
    // A machine whose clock lags by a day still takes it; one further
    // behind does not.
    try testing.expectError(
        error.BadManifest,
        open(a, key, test_manifest, test_sig, "prod-ssh", "aarch64", signed_at - 2 * 86400),
    );

    // Changing any byte breaks the signature.
    const forged = try a.dupe(u8, test_manifest);
    const at = std.mem.find(u8, forged, "\"build\": \"").? + 10;
    forged[at] = if (forged[at] == '0') '1' else '0';
    try testing.expectError(
        error.BadSignature,
        open(a, key, forged, test_sig, "prod-ssh", "aarch64", signed_at),
    );
    const bad_sig = try a.dupe(u8, test_sig);
    bad_sig[100] ^= 1;
    try testing.expectError(
        error.BadSignature,
        open(a, key, test_manifest, bad_sig, "prod-ssh", "aarch64", signed_at),
    );
    try testing.expectError(
        error.BadSignature,
        open(a, key, test_manifest, test_sig[1..], "prod-ssh", "aarch64", signed_at),
    );
}
