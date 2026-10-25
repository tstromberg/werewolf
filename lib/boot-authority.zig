//! Boot certificate parsing: the RSA key of the X.509 certificate howl enrolls
//! in firmware, from bounded, strictly checked DER.
const std = @import("std");
const apk = @import("apk");
const mem = std.mem;
const max_certificate = 16 << 10;

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

/// certificateKey returns the RSA key of one DER X.509 certificate, refusing
/// any malformed, trailing or unsupported encoding. No clock or CA discovery
/// chooses a key.
pub fn certificateKey(raw: []const u8) !apk.Key {
    if (raw.len == 0 or raw.len > max_certificate) return error.BadAuthorityCertificate;
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

const owner_der = @embedFile("testdata/boot-authority/owner.der");

test "certificate keys agree with independent OpenSSL SPKI" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const expected = try apk.parseKey(gpa, @embedFile("testdata/boot-authority/owner.pub"));
    const parsed = try certificateKey(owner_der);
    try std.testing.expectEqualSlices(u8, expected.modulus, parsed.modulus);
    try std.testing.expectEqualSlices(u8, expected.exponent, parsed.exponent);
    _ = try certificateKey(@embedFile("testdata/boot-authority/vendor.der"));
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
