//! Signed per-machine HTTPS transport; it grants no code or TPM authorization.
const std = @import("std");
const apk = @import("apk");
const certificate = @import("boot-authority.zig");
const mem = std.mem;
pub const tag = "werewolf.transport/1\x00";
pub const header = tag.len + 32 + 4 + 2 + 2;
pub const max_certificate = 4096;
pub const max_bundle = header + max_certificate + 512;
pub const path = "/run/config/machine-transport";

pub const Declaration = struct {
    machine: [32]u8,
    host: [4]u8,
    port: u16,
    ca: []const u8,

    pub fn message(d: Declaration, gpa: mem.Allocator) ![]const u8 {
        if (mem.eql(u8, &d.machine, &@as([32]u8, @splat(0))) or d.port == 0 or
            d.ca.len == 0 or d.ca.len > max_certificate) return error.BadMachineTransport;
        _ = try certificate.certificateKey(d.ca);
        const raw = try gpa.alloc(u8, header + d.ca.len);
        @memcpy(raw[0..tag.len], tag);
        @memcpy(raw[tag.len..][0..32], &d.machine);
        @memcpy(raw[tag.len + 32 ..][0..4], &d.host);
        mem.writeInt(u16, raw[tag.len + 36 ..][0..2], d.port, .big);
        mem.writeInt(u16, raw[tag.len + 38 ..][0..2], @intCast(d.ca.len), .big);
        @memcpy(raw[header..], d.ca);
        return raw;
    }

    pub fn endpoint(d: Declaration, gpa: mem.Allocator) ![]const u8 {
        return gpa.print("https://{d}.{d}.{d}.{d}:{d}", .{
            d.host[0], d.host[1], d.host[2], d.host[3], d.port,
        });
    }
};

/// Signature, machine nonce and immutable network policy precede CA interpretation.
pub fn open(key: apk.Key, raw: []const u8, machine: [32]u8, host: [4]u8, port: u16) !Declaration {
    if (raw.len < header + key.modulus.len or raw.len > max_bundle)
        return error.BadMachineTransport;
    const body = raw[0 .. raw.len - key.modulus.len];
    try apk.verify(key, body, raw[body.len..]);
    if (!mem.eql(u8, body[0..tag.len], tag) or
        mem.eql(u8, &machine, &@as([32]u8, @splat(0))) or
        !mem.eql(u8, body[tag.len..][0..32], &machine)) return error.ForeignMachineTransport;
    const received: Declaration = .{
        .machine = body[tag.len..][0..32].*,
        .host = body[tag.len + 32 ..][0..4].*,
        .port = mem.readInt(u16, body[tag.len + 36 ..][0..2], .big),
        .ca = body[header..],
    };
    if (!mem.eql(u8, &received.host, &host) or port == 0 or received.port != port)
        return error.UndeclaredPermitEndpoint;
    if (received.ca.len == 0 or received.ca.len > max_certificate or
        mem.readInt(u16, body[tag.len + 38 ..][0..2], .big) != received.ca.len)
        return error.BadMachineTransport;
    _ = try certificate.certificateKey(received.ca);
    return received;
}

test "transport encodes only a bounded public certificate, machine and endpoint" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const d: Declaration = .{
        .machine = @splat(1),
        .host = .{ 192, 168, 5, 2 },
        .port = 8443,
        .ca = @embedFile("testdata/boot-authority/vendor.der"),
    };
    const bytes = try d.message(gpa);
    try std.testing.expectEqual(header + d.ca.len, bytes.len);
    try std.testing.expectEqualSlices(u8, tag, bytes[0..tag.len]);
    try std.testing.expectEqualStrings("https://192.168.5.2:8443", try d.endpoint(gpa));
    var invalid = d;
    invalid.machine = @splat(0);
    try std.testing.expectError(error.BadMachineTransport, invalid.message(gpa));
    invalid = d;
    invalid.port = 0;
    try std.testing.expectError(error.BadMachineTransport, invalid.message(gpa));
    invalid = d;
    invalid.ca = "not a certificate";
    try std.testing.expectError(error.BadAuthorityCertificate, invalid.message(gpa));
}

test "signed transport binds machine, endpoint and CA before interpreting untrusted bytes" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const signer = try apk.parseKey(gpa, @embedFile("testdata/machine-transport/signer.pub"));
    const raw = @embedFile("testdata/machine-transport/valid.bundle");
    const host = [4]u8{ 192, 168, 5, 2 };
    const d = try open(signer, raw, @splat(1), host, 8443);
    try t.expectEqualSlices(u8, @embedFile("testdata/boot-authority/vendor.der"), d.ca);
    try t.expectEqualSlices(u8, raw[0 .. raw.len - signer.modulus.len], try d.message(gpa));
    try t.expectError(error.ForeignMachineTransport, open(signer, raw, @splat(2), host, 8443));
    try t.expectError(error.ForeignMachineTransport, open(signer, raw, @splat(0), host, 8443));
    try t.expectError(error.UndeclaredPermitEndpoint, open(signer, raw, @splat(1), host, 443));
    try t.expectError(
        error.UndeclaredPermitEndpoint,
        open(signer, raw, @splat(1), .{ 10, 0, 2, 2 }, 8443),
    );
    try t.expectError(
        error.BadMachineTransport,
        open(
            signer,
            @embedFile("testdata/machine-transport/bad-length.bundle"),
            @splat(1),
            host,
            8443,
        ),
    );
    try t.expectError(
        error.ForeignMachineTransport,
        open(
            signer,
            @embedFile("testdata/machine-transport/bad-domain.bundle"),
            @splat(1),
            host,
            8443,
        ),
    );
    try t.expectError(
        error.BadAuthorityCertificate,
        open(signer, @embedFile("testdata/machine-transport/bad-ca.bundle"), @splat(1), host, 8443),
    );
    const foreign = try apk.parseKey(gpa, @embedFile("testdata/apk/test.rsa.pub"));
    try t.expectError(error.BadSignature, open(foreign, raw, @splat(1), host, 8443));
    for (0..raw.len) |i| {
        if (open(signer, raw[0..i], @splat(1), host, 8443)) |_|
            return error.TruncatedTransportAccepted
        else |_| {}
    }
    var corrupted: [raw.len]u8 = undefined;
    for (0..raw.len) |i| {
        @memcpy(&corrupted, raw);
        corrupted[i] ^= 1;
        try t.expectError(error.BadSignature, open(signer, &corrupted, @splat(1), host, 8443));
    }
}
