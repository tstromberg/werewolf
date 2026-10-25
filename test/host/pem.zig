//! pem writes and reads PEM: certificates a host.tls Authority minted, for
//! a server a check runs elsewhere (a guest's Caddy), its EC private key,
//! and the certificates in a trust bundle.

const std = @import("std");
const tls = @import("tls.zig");
const Allocator = std.mem.Allocator;
const mem = std.mem;

/// encode is der as one PEM block labelled label.
pub fn encode(gpa: Allocator, label: []const u8, der: []const u8) ![]u8 {
    const Base64 = std.base64.standard.Encoder;
    const text = try gpa.alloc(u8, Base64.calcSize(der.len));
    defer gpa.free(text);
    _ = Base64.encode(text, der);
    var out: std.ArrayList(u8) = .empty;
    try out.print(gpa, "-----BEGIN {s}-----\n", .{label});
    var i: usize = 0;
    while (i < text.len) : (i += 64) {
        try out.appendSlice(gpa, text[i..@min(i + 64, text.len)]);
        try out.append(gpa, '\n');
    }
    try out.print(gpa, "-----END {s}-----\n", .{label});
    return out.toOwnedSlice(gpa);
}

/// chain is an identity's certificates, leaf first, as a server's file.
pub fn chain(gpa: Allocator, identity: tls.Identity) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    for (identity.chain) |der| {
        const block = try encode(gpa, "CERTIFICATE", der);
        defer gpa.free(block);
        try out.appendSlice(gpa, block);
    }
    return out.toOwnedSlice(gpa);
}

/// key is an identity's private key as SEC 1 "EC PRIVATE KEY".
pub fn key(gpa: Allocator, identity: tls.Identity) ![]u8 {
    const prime256v1 = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
    var der: [121]u8 = undefined;
    const secret = identity.key.secret_key.toBytes();
    const point = identity.key.public_key.toUncompressedSec1();
    var w: std.Io.Writer = .fixed(&der);
    w.writeAll("\x30\x77\x02\x01\x01\x04\x20") catch unreachable;
    w.writeAll(&secret) catch unreachable;
    w.writeAll("\xa0\x0a" ++ prime256v1 ++ "\xa1\x44\x03\x42\x00") catch unreachable;
    w.writeAll(&point) catch unreachable;
    return encode(gpa, "EC PRIVATE KEY", w.buffered());
}

/// Block is one certificate of a bundle: its PEM text and its DER.
pub const Block = struct { text: []const u8, der: []const u8 };

/// certificates are the CERTIFICATE blocks in text that decode.
pub fn certificates(gpa: Allocator, text: []const u8) ![]const Block {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    const decoder: std.base64.Base64DecoderWithIgnore =
        .init(std.base64.standard_alphabet_chars, '=', " \t\r\n");
    var out: std.ArrayList(Block) = .empty;
    var from: usize = 0;
    while (mem.findPos(u8, text, from, begin)) |start| {
        const stop = mem.findPos(u8, text, start, end) orelse break;
        from = stop + end.len;
        if (from < text.len and text[from] == '\n') from += 1;
        const body = text[start + begin.len .. stop];
        const der = try gpa.alloc(u8, decoder.calcSizeUpperBound(body.len));
        const n = decoder.decode(der, body) catch continue;
        if (n == 0) continue;
        try out.append(gpa, .{ .text = text[start..from], .der = der[0..n] });
    }
    return out.items;
}

test "an issued identity's chain and key read back as PEM" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = std.testing.io;
    const ca = try tls.Authority.init(io, gpa, "werewolf test authority");
    const identity = try ca.issue(io, gpa, &.{"127.0.0.1"});
    const certs = try certificates(gpa, try chain(gpa, identity));
    try std.testing.expectEqual(2, certs.len);
    try std.testing.expectEqualSlices(u8, identity.chain[0], certs[0].der);
    try std.testing.expectEqualSlices(u8, ca.der, certs[1].der);
    try std.testing.expectEqualStrings(try ca.pem(gpa), certs[1].text);
    const pem = try key(gpa, identity);
    try std.testing.expect(mem.startsWith(u8, pem, "-----BEGIN EC PRIVATE KEY-----\n"));
}
