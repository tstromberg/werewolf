//! release: what makes a werewolf release one to install. A release is
//! files and a manifest naming them, signed in CI with the image key
//! (docs/releases.md). The image carries the key's public half; nothing
//! about a release is believed until its manifest's signature checks
//! against it, and then only for the form and architecture this machine
//! runs, before the manifest expires.
//!
//! The signature is RSA PKCS#1 v1.5 over the manifest's SHA-256, as
//! `openssl dgst -sha256 -sign` makes it, so the standard library checks it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const rsa = Certificate.rsa;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// The image key's public half, as its PEM gives it.
pub const Key = struct {
    modulus: []const u8,
    exponent: []const u8,
};

/// rsaEncryption, 1.2.840.113549.1.1.1, as DER writes it.
const rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

/// The key in a PEM `PUBLIC KEY` (X.509 SubjectPublicKeyInfo) holding an
/// RSA key of 2048 to 4096 bits.
pub fn parseKey(gpa: Allocator, pem: []const u8) !Key {
    const begin = "-----BEGIN PUBLIC KEY-----";
    const end = "-----END PUBLIC KEY-----";
    const a = (std.mem.find(u8, pem, begin) orelse return error.BadKey) + begin.len;
    const b = std.mem.findPos(u8, pem, a, end) orelse return error.BadKey;
    var b64: std.ArrayList(u8) = .empty;
    for (pem[a..b]) |c| if (!std.ascii.isWhitespace(c)) try b64.append(gpa, c);
    const decoder = std.base64.standard.Decoder;
    const bytes = try gpa.alloc(u8, decoder.calcSizeForSlice(b64.items) catch return error.BadKey);
    decoder.decode(bytes, b64.items) catch return error.BadKey;

    // SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { 0, RSAPublicKey } }
    const spki = try element(bytes, 0, .sequence);
    const algorithm = try element(bytes, spki.slice.start, .sequence);
    const oid = try element(bytes, algorithm.slice.start, .object_identifier);
    if (!std.mem.eql(
        u8,
        bytes[oid.slice.start..oid.slice.end],
        &rsa_encryption,
    )) return error.BadKey;
    const bits = try element(bytes, algorithm.slice.end, .bitstring);
    if (bits.slice.end != spki.slice.end or bits.slice.end - bits.slice.start < 2 or
        bytes[bits.slice.start] != 0)
        return error.BadKey;
    const inner = bytes[bits.slice.start + 1 .. bits.slice.end];
    // parseDer reads within inner; its lengths are checked here first.
    const seq = try element(inner, 0, .sequence);
    const n = try element(inner, seq.slice.start, .integer);
    _ = try element(inner, n.slice.end, .integer);
    const parts = rsa.PublicKey.parseDer(inner) catch return error.BadKey;
    switch (parts.modulus.len) {
        256, 384, 512 => {},
        else => return error.BadKey,
    }
    _ = rsa.PublicKey.fromBytes(parts.exponent, parts.modulus) catch return error.BadKey;
    return .{ .modulus = parts.modulus, .exponent = parts.exponent };
}

/// The DER element at index, of tag, within bytes.
fn element(bytes: []const u8, index: u32, tag: der.Tag) !der.Element {
    if (index + 2 > bytes.len) return error.BadKey;
    const e = der.Element.parse(bytes, index) catch return error.BadKey;
    if (e.identifier.tag != tag or e.slice.end > bytes.len or
        e.slice.start > e.slice.end) return error.BadKey;
    return e;
}

/// Whether sig is key's signature of data's SHA-256.
pub fn verify(key: Key, data: []const u8, sig: []const u8) !void {
    return verifyHash(Sha256, key, data, sig);
}

/// Whether sig is key's signature of data's Hash: SHA-256, or for apk's
/// older indexes, SHA-1.
pub fn verifyHash(comptime Hash: type, key: Key, data: []const u8, sig: []const u8) !void {
    if (sig.len != key.modulus.len) return error.BadSignature;
    const public_key = rsa.PublicKey.fromBytes(key.exponent, key.modulus) catch return error.BadKey;
    switch (key.modulus.len) {
        inline 256,
        384,
        512,
        => |len| rsa.PKCS1v1_5Signature.verify(len, sig[0..len], data, public_key, Hash) catch
            return error.BadSignature,
        else => return error.BadKey,
    }
}

/// A release's manifest, as much of it as the updater uses.
pub const Manifest = struct {
    format: []const u8,
    form: []const u8,
    arch: []const u8,
    serial: []const u8,
    expires: []const u8,
    build: []const u8,
    kernel: []const u8,
    files: std.json.ArrayHashMap(File),
    packages: []const struct { name: []const u8, version: []const u8, origin: []const u8 },
    /// werewolf's own security advisories (release/advisories), signed with
    /// the rest: fixes to werewolf's code, which no CVE names.
    advisories: []const Advisory = &.{},

    pub const File = struct { sha256: []const u8, size: u64 };
    pub const Advisory = struct {
        id: []const u8,
        date: []const u8,
        tier: []const u8,
        title: []const u8,
    };

    /// What a slot needs from a release.
    pub const slot_files = [_][]const u8{ "vmlinuz", "stage0.zst", "root.erofs" };
    /// stage0 for a slot on a distro's disk, after bite, which a bitten
    /// machine fetches in place of stage0.zst: the same, with the modules
    /// only a distro's filesystem needs (Makefile, BITTEN_TAGS), which
    /// werewolf's own disk and a direct boot leave out.
    pub const bitten_stage0 = "stage0-bitten.zst";
};

/// The manifest in data, which must be signed by key with sig, and be one
/// for this form and architecture, unexpired at now (seconds since the
/// epoch), and naming a slot's files.
pub fn open(
    gpa: Allocator,
    key: Key,
    data: []const u8,
    sig: []const u8,
    form: []const u8,
    arch: []const u8,
    now: i64,
) !Manifest {
    try verify(key, data, sig);
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
    if (now >= try parseTime(m.expires)) return error.Stale;
    const signed = serialTime(m.serial) catch return error.BadManifest;
    if (signed > now + 24 * 3600) return error.BadManifest;
    for (m.advisories) |a| if (!validAdvisory(a)) return error.BadManifest;
    for (Manifest.slot_files) |name|
        try checkFile(m.files.map.get(name) orelse return error.BadManifest);
    if (m.files.map.get(Manifest.bitten_stage0)) |f| try checkFile(f);
    return m;
}

/// A slot file's entry: a lower-case sha256, and a size of at most 256 MiB.
fn checkFile(f: Manifest.File) !void {
    if (f.sha256.len != 64 or f.size == 0 or f.size > 256 << 20) return error.BadManifest;
    for (f.sha256) |c| if (!std.ascii.isHex(c) or std.ascii.isUpper(c)) return error.BadManifest;
}

/// An advisory as release/manifest checks one: WW-YEAR-NUMBER, a date, a
/// tier, and a title of printable ASCII without quotes or backslashes.
pub fn validAdvisory(a: Manifest.Advisory) bool {
    const id = a.id;
    if (id.len < 11 or id.len > 32 or !std.mem.startsWith(u8, id, "WW-") or
        id[7] != '-') return false;
    for (id[3..7]) |c| if (!std.ascii.isDigit(c)) return false;
    for (id[8..]) |c| if (!std.ascii.isDigit(c)) return false;
    if (a.date.len != 10 or a.date[4] != '-' or a.date[7] != '-') return false;
    for (a.date, 0..) |c, i| if (i != 4 and i != 7 and !std.ascii.isDigit(c)) return false;
    const tiers = [_][]const u8{ "urgent", "high", "medium", "low" };
    for (tiers) |t| {
        if (std.mem.eql(u8, a.tier, t)) break;
    } else return false;
    if (a.title.len == 0 or a.title.len > 200) return false;
    for (a.title) |c| if (c < ' ' or c > '~' or c == '"' or c == '\\') return false;
    return true;
}

test validAdvisory {
    const good: Manifest.Advisory = .{
        .id = "WW-2026-001",
        .date = "2026-10-07",
        .tier = "high",
        .title = "fence: x",
    };
    try std.testing.expect(validAdvisory(good));
    var a = good;
    a.id = "WW-26-1";
    try std.testing.expect(!validAdvisory(a));
    a = good;
    a.tier = "severe";
    try std.testing.expect(!validAdvisory(a));
    a = good;
    a.title = "a \"quote\"";
    try std.testing.expect(!validAdvisory(a));
    a = good;
    a.date = "2026-1-07";
    try std.testing.expect(!validAdvisory(a));
}

/// A serial, 20261006T151016Z, as seconds since the epoch.
pub fn serialTime(serial: []const u8) !i64 {
    if (serial.len != 16 or serial[8] != 'T' or serial[15] != 'Z') return error.BadTime;
    var buf: [20]u8 = undefined;
    const s = std.mem.print(&buf, "{s}-{s}-{s}T{s}:{s}:{s}Z", .{
        serial[0..4], serial[4..6], serial[6..8], serial[9..11], serial[11..13], serial[13..15],
    }) catch return error.BadTime;
    return parseTime(s);
}

/// RFC 3339 in UTC, 2026-10-13T15:10:16Z, as seconds since the epoch.
pub fn parseTime(s: []const u8) !i64 {
    if (s.len != 20 or s[4] != '-' or s[7] != '-' or s[10] != 'T' or s[13] != ':' or s[16] != ':' or
        s[19] != 'Z')
        return error.BadTime;
    const num = struct {
        fn f(t: []const u8) !u32 {
            for (t) |c| if (!std.ascii.isDigit(c)) return error.BadTime;
            return std.fmt.parseUnsigned(u32, t, 10) catch error.BadTime;
        }
    }.f;
    const year = try num(s[0..4]);
    const month = try num(s[5..7]);
    const day = try num(s[8..10]);
    const hour = try num(s[11..13]);
    const minute = try num(s[14..16]);
    const second = try num(s[17..19]);
    if (year < 1970 or month < 1 or month > 12 or day < 1 or hour > 23 or minute > 59 or
        second > 59) return error.BadTime;
    const leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
    const days_in = [12]u32{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (day > days_in[month - 1]) return error.BadTime;
    var days: i64 = 0;
    var y: u32 = 1970;
    while (y < year) : (y += 1) days += if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0))
        366
    else
        365;
    for (days_in[0 .. month - 1]) |d| days += d;
    days += day - 1;
    return days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

const testing = std.testing;
const test_key = @embedFile("testdata/image.pub");
const test_manifest = @embedFile("testdata/prod-ssh-aarch64.json");
const test_sig = @embedFile("testdata/prod-ssh-aarch64.json.sig");
/// When the test manifest was signed, and a week later, when it expires.
const signed_at = 1791299416;

test "a release CI signed checks, and nothing else does" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = try parseKey(a, test_key);
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
    try testing.expectError(
        error.Stale,
        open(a, key, test_manifest, test_sig, "prod-ssh", "aarch64", signed_at + 7 * 86400),
    );
    // Signed, but the clock says not yet: a machine whose clock lags a
    // day still takes it; one a day and more behind does not.
    try testing.expectError(
        error.BadManifest,
        open(a, key, test_manifest, test_sig, "prod-ssh", "aarch64", signed_at - 2 * 86400),
    );

    // One byte changed, anywhere, and it is not a release.
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

test "keys that are not the image key's kind" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.BadKey, parseKey(a, "no key here"));
    try testing.expectError(
        error.BadKey,
        parseKey(a, "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"),
    );
    // An Ed25519 key: right wrapper, wrong algorithm.
    try testing.expectError(error.BadKey, parseKey(a,
        \\-----BEGIN PUBLIC KEY-----
        \\MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
        \\-----END PUBLIC KEY-----
    ));
}

test parseTime {
    try testing.expectEqual(signed_at + 7 * 86400, try parseTime("2026-10-13T15:10:16Z"));
    try testing.expectEqual(0, try parseTime("1970-01-01T00:00:00Z"));
    try testing.expectEqual(951782400, try parseTime("2000-02-29T00:00:00Z"));
    for ([_][]const u8{
        "2026-02-29T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-10-13 15:10:16Z",
        "2026-10-13T15:10:16",
        "+026-10-13T15:10:16Z",
    }) |bad|
        try testing.expectError(error.BadTime, parseTime(bad));
}
