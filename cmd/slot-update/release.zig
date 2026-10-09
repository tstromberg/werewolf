//! release checks a werewolf release manifest: its signature by the image key,
//! then its form, architecture and fields (docs/releases.md). Signatures are
//! RSA PKCS#1 v1.5 over SHA-256, as `openssl dgst -sha256 -sign` makes them.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const rsa = Certificate.rsa;
const Sha256 = std.crypto.hash.sha2.Sha256;
const policy = @import("update-policy");

/// Key is an RSA public key, such as the image key.
pub const Key = struct {
    modulus: []const u8,
    exponent: []const u8,
};

/// rsa_encryption is the DER encoding of OID 1.2.840.113549.1.1.1.
const rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

/// parseKey parses a PEM `PUBLIC KEY` (X.509 SubjectPublicKeyInfo). It
/// accepts only RSA keys of 2048, 3072 or 4096 bits.
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
    // parseDer trusts the lengths in inner, so check them here first.
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

/// element parses the DER element at index and checks its tag and bounds.
fn element(bytes: []const u8, index: u32, tag: der.Tag) !der.Element {
    if (index + 2 > bytes.len) return error.BadKey;
    const e = der.Element.parse(bytes, index) catch return error.BadKey;
    if (e.identifier.tag != tag or e.slice.end > bytes.len or
        e.slice.start > e.slice.end) return error.BadKey;
    return e;
}

/// verify returns an error unless sig is key's signature of data's SHA-256.
pub fn verify(key: Key, data: []const u8, sig: []const u8) !void {
    return verifyHash(Sha256, key, data, sig);
}

/// verifyHash is verify with another hash: apk's older indexes use SHA-1.
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
