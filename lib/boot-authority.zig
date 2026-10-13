//! Portable TPM authority from authenticated firmware, with separately pinned code trust.
const std = @import("std");
const apk = @import("apk");
const mem = std.mem;
const Sha256 = std.crypto.hash.sha2.Sha256;
const vars = "/sys/firmware/efi/efivars/";
const global = "-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const database = "-d719b2cb-3d3a-4596-a3bc-dad00e67656f";
pub const max_variable = 16 << 10;
// EFI_CERT_X509_GUID, in the firmware's mixed-endian GUID representation.
const x509 = [_]u8{
    0xa1,
    0x59,
    0xc0,
    0xa5,
    0xe4,
    0x94,
    0xa7,
    0x4a,
    0x87,
    0xb5,
    0xab,
    0x15,
    0x5c,
    0x2b,
    0xf0,
    0x72,
};

pub const Variables = struct {
    secure: []const u8,
    setup: []const u8,
    pk: []const u8,
    kek: []const u8,
    db: []const u8,
};

/// No mutable config supplies the signer or code certificate pin.
pub fn load(io: std.Io, gpa: mem.Allocator, vendor: [32]u8) !apk.Key {
    const secure = read(io, gpa, vars ++ "SecureBoot" ++ global) catch |err| switch (err) {
        error.FileNotFound => return error.InsecureFirmware,
        else => return err,
    };
    const setup = read(io, gpa, vars ++ "SetupMode" ++ global) catch |err| switch (err) {
        error.FileNotFound => return error.InsecureFirmware,
        else => return err,
    };
    try mode(secure, 1);
    try mode(setup, 0);
    return key(.{
        .secure = secure,
        .setup = setup,
        .pk = try read(io, gpa, vars ++ "PK" ++ global),
        .kek = try read(io, gpa, vars ++ "KEK" ++ global),
        .db = try read(io, gpa, vars ++ "db" ++ database),
    }, vendor);
}

fn read(io: std.Io, gpa: mem.Allocator, path: []const u8) ![]const u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    // efivarfs may report zero size. Read the stream and reject an extra byte.
    const data = try gpa.alloc(u8, max_variable + 1);
    const n = try file.readPositionalAll(io, data, 0);
    if (n > max_variable) return error.BadFirmwareAuthority;
    return data[0..n];
}

pub fn key(v: Variables, vendor: [32]u8) !apk.Key {
    try mode(v.secure, 1);
    try mode(v.setup, 0);
    const owner = try certificate(v.pk);
    if (!mem.eql(u8, owner, try certificate(v.kek))) return error.ForeignFirmwareAuthority;
    const code = try certificate(v.db);
    var digest: [32]u8 = undefined;
    Sha256.hash(code, &digest, .{});
    if (!mem.eql(u8, &digest, &vendor)) return error.ForeignBootTrust;
    const authority = try certificateKey(owner);
    const publisher = try certificateKey(code);
    if (mem.eql(u8, authority.modulus, publisher.modulus)) return error.SharedBootAuthority;
    return authority;
}

fn mode(raw: []const u8, expected: u8) !void {
    if (raw.len != 5 or raw[4] != expected or
        mem.readInt(u32, raw[0..4], .little) != 6) return error.InsecureFirmware;
}

/// Exactly one authenticated X.509 list with one certificate; reject extra trust.
pub fn certificate(raw: []const u8) ![]const u8 {
    if (raw.len < 4 + 28 + 16 + 1 or raw.len > max_variable)
        return error.BadFirmwareAuthority;
    if (mem.readInt(u32, raw[0..4], .little) != 0x27 or
        !mem.eql(u8, raw[4..20], &x509)) return error.BadFirmwareAuthority;
    const list_size = mem.readInt(u32, raw[20..24], .little);
    const header_size = mem.readInt(u32, raw[24..28], .little);
    const signature_size = mem.readInt(u32, raw[28..32], .little);
    if (list_size != raw.len - 4 or header_size != 0 or
        signature_size != raw.len - 32) return error.BadFirmwareAuthority;
    return raw[48..];
}

const Element = struct { tag: u8, body: []const u8 };
const Der = struct {
    data: []const u8,
    at: usize = 0,

    fn next(d: *Der) !Element {
        if (d.data.len - d.at < 2) return error.BadAuthorityCertificate;
        const tag = d.data[d.at];
        if (tag & 0x1f == 0x1f) return error.BadAuthorityCertificate;
        d.at += 1;
        const first = d.data[d.at];
        d.at += 1;
        var size: usize = first;
        if (first & 0x80 != 0) {
            const count = first & 0x7f;
            if (count == 0 or count > 2 or count > d.data.len - d.at or
                d.data[d.at] == 0) return error.BadAuthorityCertificate;
            size = 0;
            for (d.data[d.at..][0..count]) |byte| size = (size << 8) | byte;
            if (size < 128) return error.BadAuthorityCertificate;
            d.at += count;
        }
        if (size > d.data.len - d.at) return error.BadAuthorityCertificate;
        defer d.at += size;
        return .{ .tag = tag, .body = d.data[d.at..][0..size] };
    }

    fn take(d: *Der, tag: u8) ![]const u8 {
        const element = try d.next();
        if (element.tag != tag) return error.BadAuthorityCertificate;
        return element.body;
    }

    fn end(d: Der) !void {
        if (d.at != d.data.len) return error.BadAuthorityCertificate;
    }
};

fn validateDer(data: []const u8, depth: u8) !void {
    if (depth > 16) return error.BadAuthorityCertificate;
    var d: Der = .{ .data = data };
    while (d.at < data.len) {
        const e = try d.next();
        if (e.tag & 0x20 != 0) try validateDer(e.body, depth + 1);
    }
}

/// Firmware authenticates this trust anchor; no clock or CA discovery chooses a key.
pub fn certificateKey(raw: []const u8) !apk.Key {
    if (raw.len == 0 or raw.len > max_variable - 48) return error.BadAuthorityCertificate;
    try validateDer(raw, 0);
    var top: Der = .{ .data = raw };
    var cert: Der = .{ .data = try top.take(0x30) };
    try top.end();
    var tbs: Der = .{ .data = try cert.take(0x30) };
    _ = try cert.take(0x30);
    const signature = try cert.take(0x03);
    if (signature.len < 2 or signature[0] != 0) return error.BadAuthorityCertificate;
    try cert.end();
    if (tbs.data.len == 0) return error.BadAuthorityCertificate;
    if (tbs.data[0] == 0xa0) {
        var version: Der = .{ .data = try tbs.take(0xa0) };
        const value = try version.take(0x02);
        if (value.len != 1 or value[0] > 2) return error.BadAuthorityCertificate;
        try version.end();
    }
    _ = try tbs.take(0x02); // serial
    _ = try tbs.take(0x30); // signature algorithm
    _ = try tbs.take(0x30); // issuer
    _ = try tbs.take(0x30); // validity
    _ = try tbs.take(0x30); // subject
    var spki: Der = .{ .data = try tbs.take(0x30) };
    var algorithm: Der = .{ .data = try spki.take(0x30) };
    const oid = try algorithm.take(0x06);
    if (!mem.eql(u8, oid, &.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1 }))
        return error.UnsupportedAuthorityKey;
    if (algorithm.at != algorithm.data.len) {
        if ((try algorithm.take(0x05)).len != 0) return error.BadAuthorityCertificate;
    }
    try algorithm.end();
    const bits = try spki.take(0x03);
    try spki.end();
    if (bits.len < 2 or bits[0] != 0) return error.BadAuthorityCertificate;
    var rsa: Der = .{ .data = bits[1..] };
    var parts: Der = .{ .data = try rsa.take(0x30) };
    try rsa.end();
    const encoded = try parts.take(0x02);
    const exponent = try parts.take(0x02);
    try parts.end();
    // Positive, minimally encoded, full-size RSA modulus and TPM-supported exponent.
    if (encoded.len < 2 or encoded[0] != 0 or encoded[1] & 0x80 == 0)
        return error.UnsupportedAuthorityKey;
    const modulus = encoded[1..];
    if ((modulus.len != 256 and modulus.len != 384 and modulus.len != 512) or
        !mem.eql(u8, exponent, &.{ 1, 0, 1 })) return error.UnsupportedAuthorityKey;
    _ = std.crypto.Certificate.rsa.PublicKey.fromBytes(exponent, modulus) catch
        return error.UnsupportedAuthorityKey;
    // Ignore only the optional unique identifiers/extensions after SubjectPublicKeyInfo.
    while (tbs.at < tbs.data.len) {
        const optional = try tbs.next();
        if (optional.tag != 0x81 and optional.tag != 0x82 and optional.tag != 0xa3)
            return error.BadAuthorityCertificate;
    }
    return .{ .modulus = modulus, .exponent = exponent };
}

fn fixture(gpa: mem.Allocator, der: []const u8) ![]u8 {
    const raw = try gpa.alloc(u8, 48 + der.len);
    @memset(raw, 0);
    mem.writeInt(u32, raw[0..4], 0x27, .little);
    @memcpy(raw[4..20], &x509);
    mem.writeInt(u32, raw[20..24], @intCast(raw.len - 4), .little);
    mem.writeInt(u32, raw[28..32], @intCast(raw.len - 32), .little);
    @memcpy(raw[48..], der);
    return raw;
}

const owner_der = @embedFile("testdata/boot-authority/owner.der");
const vendor_der = @embedFile("testdata/boot-authority/vendor.der");

test "firmware authority agrees with independent OpenSSL SPKI and pins separate boot trust" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const expected = try apk.parseKey(gpa, @embedFile("testdata/boot-authority/owner.pub"));
    const parsed = try certificateKey(owner_der);
    try std.testing.expectEqualSlices(u8, expected.modulus, parsed.modulus);
    try std.testing.expectEqualSlices(u8, expected.exponent, parsed.exponent);
    const pk = try fixture(gpa, owner_der);
    const db = try fixture(gpa, vendor_der);
    var digest: [32]u8 = undefined;
    Sha256.hash(vendor_der, &digest, .{});
    var v: Variables = .{
        .secure = &.{ 6, 0, 0, 0, 1 },
        .setup = &.{ 6, 0, 0, 0, 0 },
        .pk = pk,
        .kek = pk,
        .db = db,
    };
    try std.testing.expectEqualSlices(u8, expected.modulus, (try key(v, digest)).modulus);
    try std.testing.expectError(error.ForeignBootTrust, key(v, @splat(0)));
    v.kek = db;
    try std.testing.expectError(error.ForeignFirmwareAuthority, key(v, digest));
    v.kek = pk;
    v.db = pk;
    Sha256.hash(owner_der, &digest, .{});
    try std.testing.expectError(error.SharedBootAuthority, key(v, digest));
    v.secure = &.{ 6, 0, 0, 0, 0 };
    try std.testing.expectError(error.InsecureFirmware, key(v, digest));
    v.secure = &.{ 6, 0, 0, 0, 1 };
    v.setup = &.{ 6, 0, 0, 0, 1 };
    try std.testing.expectError(error.InsecureFirmware, key(v, digest));
}

test "single-certificate firmware variables reject every truncation, extra trust and attributes" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const pk = try fixture(gpa, owner_der);
    for (0..pk.len) |i| try std.testing.expectError(
        error.BadFirmwareAuthority,
        certificate(pk[0..i]),
    );
    const doubled = try mem.concat(gpa, u8, &.{ pk, pk[4..] });
    try std.testing.expectError(error.BadFirmwareAuthority, certificate(doubled));
    for ([_]usize{ 0, 4, 20, 24, 28 }) |at| {
        const bad = try gpa.dupe(u8, pk);
        bad[at] ^= 1;
        try std.testing.expectError(error.BadFirmwareAuthority, certificate(bad));
    }
    const two = try mem.concat(gpa, u8, &.{ pk, pk[32..] });
    mem.writeInt(u32, two[20..24], @intCast(two.len - 4), .little);
    try std.testing.expectError(error.BadFirmwareAuthority, certificate(two));
}

test "certificate parsing rejects every truncation, trailing bytes and malformed DER" {
    const t = std.testing;
    for (0..owner_der.len) |i| try t.expectError(
        error.BadAuthorityCertificate,
        certificateKey(owner_der[0..i]),
    );
    try t.expectError(error.BadAuthorityCertificate, certificateKey(owner_der ++ "\x00"));
    try t.expectError(error.BadAuthorityCertificate, certificateKey(&.{ 0x30, 0x80, 0, 0 }));
    try t.expectError(error.BadAuthorityCertificate, certificateKey(&.{ 0x30, 0x81, 1, 0 }));
    try t.expectError(error.BadAuthorityCertificate, certificateKey(&.{ 0x30, 0xff }));
    var mutated: [owner_der.len]u8 = undefined;
    // Untrusted firmware data must return a bounded error rather than trap on any one-byte
    // mutation.
    for (0..owner_der.len) |at| {
        @memcpy(&mutated, owner_der);
        mutated[at] ^= 0xff;
        _ = certificateKey(&mutated) catch continue;
    }
}
