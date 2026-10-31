//! UEFI Signature Database (EFI_SIGNATURE_LIST) parsing and X.509 authority
//! verification for stage0, posture and howl.
//!
//! UEFI 2.10 §32.4.1 & §32.5.3.3:
//!   - PK, KEK and db must admit X.509 certificates alone (EFI_CERT_X509_GUID);
//!     any raw binary digest allowlist (EFI_CERT_SHA256_GUID) or unknown
//!     signature list type in PK, KEK or db is refused.
//!   - An X.509 signer in db is revoked in dbx only by a matching
//!     EFI_CERT_X509_GUID certificate or an unconditional
//!     EFI_CERT_X509_SHA256_GUID ToBeSignedHash entry (TimeOfRevocation == 0),
//!     never by EFI_CERT_SHA256_GUID (which revokes PE image digests, not CAs).

const std = @import("std");
const mem = std.mem;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const pk_name = "PK-8be4df61-93ca-11d2-aa0d-00e098032b8c";
pub const kek_name = "KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c";
pub const db_name = "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f";
pub const dbx_name = "dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f";

/// EFI_CERT_X509_GUID (a5c059a1-94e4-4aa7-87b5-ab155c2bf072).
pub const x509_guid = [16]u8{
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
};

/// EFI_CERT_SHA256_GUID (c1c41626-504c-4092-aca9-41f936934328).
pub const sha256_guid = [16]u8{
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,
    0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
};

/// EFI_CERT_X509_SHA256_GUID (3bd2a492-96c0-4079-b420-fcf98ef103ed).
pub const x509_sha256_guid = [16]u8{
    0x92, 0xa4, 0xd2, 0x3b, 0xc0, 0x96, 0x79, 0x40,
    0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed,
};

pub const Error = error{
    MalformedSignatureList,
    NonX509SignatureList,
    BadCertificateDer,
    EmptyPk,
    MultiplePk,
    EmptyKek,
    ForeignKek,
    OutOfMemory,
};

pub const List = struct {
    kind: [16]u8,
    header: []const u8,
    entries: []const u8,
    entry_size: usize,

    pub fn iterator(self: List) EntryIterator {
        return .{ .entries = self.entries, .entry_size = self.entry_size };
    }
};

pub const EntryIterator = struct {
    entries: []const u8,
    entry_size: usize,

    pub fn next(self: *EntryIterator) ?[]const u8 {
        if (self.entries.len == 0) return null;
        const data = self.entries[16..self.entry_size];
        self.entries = self.entries[self.entry_size..];
        return data;
    }
};

pub const ListIterator = struct {
    rest: []const u8,

    pub fn init(variable: []const u8) Error!ListIterator {
        if (variable.len == 0) return .{ .rest = "" };
        if (variable.len < 4) return error.MalformedSignatureList;
        return .{ .rest = variable[4..] };
    }

    pub fn next(self: *ListIterator) Error!?List {
        if (self.rest.len == 0) return null;
        if (self.rest.len < 28) return error.MalformedSignatureList;
        const list_size: usize = mem.readInt(u32, self.rest[16..20], .little);
        const header_size: usize = mem.readInt(u32, self.rest[20..24], .little);
        const entry_size: usize = mem.readInt(u32, self.rest[24..28], .little);
        if (list_size < 28 or list_size > self.rest.len or header_size > list_size - 28)
            return error.MalformedSignatureList;
        const entries = self.rest[28 + header_size .. list_size];
        if (entry_size <= 16 or entries.len < entry_size or entries.len % entry_size != 0)
            return error.MalformedSignatureList;
        const out: List = .{
            .kind = self.rest[0..16].*,
            .header = self.rest[28 .. 28 + header_size],
            .entries = entries,
            .entry_size = entry_size,
        };
        self.rest = self.rest[list_size..];
        return out;
    }
};

const DerTlv = struct {
    tag: u8,
    raw: []const u8,
    body: []const u8,
};

fn readDerTlv(data: []const u8, at: *usize) Error!DerTlv {
    if (data.len - at.* < 2) return error.BadCertificateDer;
    const start = at.*;
    const tag = data[at.*];
    if (tag & 0x1f == 0x1f) return error.BadCertificateDer;
    at.* += 1;
    const first = data[at.*];
    at.* += 1;
    var len: usize = first;
    if (first & 0x80 != 0) {
        const nbytes = first & 0x7f;
        if (nbytes == 0 or nbytes > 3 or nbytes > data.len - at.* or data[at.*] == 0)
            return error.BadCertificateDer;
        len = 0;
        for (data[at.*..][0..nbytes]) |b| len = (len << 8) | b;
        if (len < 128) return error.BadCertificateDer;
        at.* += nbytes;
    }
    if (len > data.len - at.*) return error.BadCertificateDer;
    const body = data[at.*..][0..len];
    at.* += len;
    return .{ .tag = tag, .raw = data[start..at.*], .body = body };
}

/// tbsBytes validates outer X.509 DER framing and returns the raw
/// tbsCertificate TLV bytes covered by EFI_CERT_X509_SHA256_GUID.
pub fn tbsBytes(cert_der: []const u8) Error![]const u8 {
    if (cert_der.len == 0 or cert_der.len > 32 << 10) return error.BadCertificateDer;
    var outer_at: usize = 0;
    const outer = try readDerTlv(cert_der, &outer_at);
    if (outer.tag != 0x30 or outer_at != cert_der.len) return error.BadCertificateDer;
    var inner_at: usize = 0;
    const tbs = try readDerTlv(outer.body, &inner_at);
    const alg = try readDerTlv(outer.body, &inner_at);
    const sig = try readDerTlv(outer.body, &inner_at);
    if (tbs.tag != 0x30 or alg.tag != 0x30 or sig.tag != 0x03 or
        sig.body.len < 2 or sig.body[0] != 0 or inner_at != outer.body.len)
        return error.BadCertificateDer;
    return tbs.raw;
}

/// x509Certificates extracts all X.509 DER entries from an efivarfs variable,
/// refusing any non-X.509 signature list (such as EFI_CERT_SHA256_GUID).
pub fn x509Certificates(gpa: mem.Allocator, variable: []const u8) Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var lists = try ListIterator.init(variable);
    while (try lists.next()) |list| {
        if (!mem.eql(u8, &list.kind, &x509_guid) or list.header.len != 0)
            return error.NonX509SignatureList;
        var entries = list.iterator();
        while (entries.next()) |cert| {
            _ = try tbsBytes(cert);
            try out.append(gpa, cert);
        }
    }
    return out.items;
}

/// validateDbx verifies the binary framing of every signature list in dbx.
pub fn validateDbx(dbx_variable: []const u8) Error!void {
    var lists = try ListIterator.init(dbx_variable);
    while (try lists.next()) |list| {
        if (mem.eql(u8, &list.kind, &x509_guid)) {
            if (list.header.len != 0) return error.MalformedSignatureList;
        } else if (mem.eql(u8, &list.kind, &sha256_guid)) {
            if (list.header.len != 0 or list.entry_size != 16 + 32)
                return error.MalformedSignatureList;
        } else if (mem.eql(u8, &list.kind, &x509_sha256_guid)) {
            if (list.header.len != 0 or list.entry_size != 16 + 48)
                return error.MalformedSignatureList;
        }
    }
}

/// isCertRevoked reports whether UEFI DxeImageVerificationLib revokes cert_der
/// under dbx_variable. EFI_CERT_SHA256_GUID entries never revoke X.509 signers.
pub fn isCertRevoked(cert_der: []const u8, dbx_variable: []const u8) Error!bool {
    const tbs = try tbsBytes(cert_der);
    var tbs_digest: [32]u8 = undefined;
    Sha256.hash(tbs, &tbs_digest, .{});
    const zero_time: [16]u8 = @splat(0);

    var lists = try ListIterator.init(dbx_variable);
    while (try lists.next()) |list| {
        if (mem.eql(u8, &list.kind, &x509_guid)) {
            if (list.header.len != 0) return error.MalformedSignatureList;
            var entries = list.iterator();
            while (entries.next()) |revoked_cert| {
                if (mem.eql(u8, revoked_cert, cert_der)) return true;
            }
        } else if (mem.eql(u8, &list.kind, &x509_sha256_guid)) {
            if (list.header.len != 0 or list.entry_size != 16 + 48)
                return error.MalformedSignatureList;
            var entries = list.iterator();
            while (entries.next()) |item| {
                if (mem.eql(u8, item[32..48], &zero_time) and
                    mem.eql(u8, item[0..32], &tbs_digest))
                    return true;
            }
        } else if (mem.eql(u8, &list.kind, &sha256_guid)) {
            if (list.header.len != 0 or list.entry_size != 16 + 32)
                return error.MalformedSignatureList;
        }
    }
    return false;
}

pub const Evaluation = struct {
    pk: []const u8,
    kek: []const []const u8,
    active_db: []const []const u8,
};

/// evaluate validates PK, KEK, db and dbx, returning the deduplicated set of
/// unrevoked X.509 signers in db. When own_cert is given and PK equals
/// own_cert, KEK must also equal own_cert alone.
pub fn evaluate(
    gpa: mem.Allocator,
    pk_variable: []const u8,
    kek_variable: []const u8,
    db_variable: []const u8,
    dbx_variable: []const u8,
    own_cert: ?[]const u8,
) Error!Evaluation {
    if (own_cert) |own| _ = try tbsBytes(own);
    const pk = try x509Certificates(gpa, pk_variable);
    if (pk.len == 0) return error.EmptyPk;
    if (pk.len > 1) return error.MultiplePk;
    const kek = try x509Certificates(gpa, kek_variable);
    if (kek.len == 0) return error.EmptyKek;
    if (own_cert) |own| {
        if (mem.eql(u8, pk[0], own) and (kek.len != 1 or !mem.eql(u8, kek[0], own)))
            return error.ForeignKek;
    }
    try validateDbx(dbx_variable);
    const db = try x509Certificates(gpa, db_variable);
    var active: std.ArrayList([]const u8) = .empty;
    for (db) |cert| {
        if (try isCertRevoked(cert, dbx_variable)) continue;
        var seen = false;
        for (active.items) |existing| {
            if (mem.eql(u8, existing, cert)) {
                seen = true;
                break;
            }
        }
        if (!seen) try active.append(gpa, cert);
    }
    return .{
        .pk = pk[0],
        .kek = kek,
        .active_db = active.items,
    };
}

/// encodeEfivar builds a synthetic efivarfs payload (4-byte attributes + lists)
/// for tests.
pub fn encodeList(
    gpa: mem.Allocator,
    out: *std.ArrayList(u8),
    kind: [16]u8,
    items: []const []const u8,
) !void {
    const owner: [16]u8 = @splat(0xee);
    if (out.items.len == 0) try out.appendSlice(gpa, &.{ 0x27, 0, 0, 0 });
    for (items) |item| {
        const entry_size: u32 = @intCast(16 + item.len);
        const list_size: u32 = 28 + entry_size;
        try out.appendSlice(gpa, &kind);
        var sizes: [12]u8 = undefined;
        mem.writeInt(u32, sizes[0..4], list_size, .little);
        mem.writeInt(u32, sizes[4..8], 0, .little);
        mem.writeInt(u32, sizes[8..12], entry_size, .little);
        try out.appendSlice(gpa, &sizes);
        try out.appendSlice(gpa, &owner);
        try out.appendSlice(gpa, item);
    }
}

const testing = std.testing;
const owner_der = @embedFile("testdata/boot-authority/owner.der");
const vendor_der = @embedFile("testdata/boot-authority/vendor.der");

test "EFI_CERT_SHA256_GUID in dbx never revokes an X.509 signer in db" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var pk: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &pk, x509_guid, &.{owner_der});
    var kek: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &kek, x509_guid, &.{owner_der});
    var db: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &db, x509_guid, &.{ owner_der, vendor_der });

    // Put SHA-256(vendor_der) AND SHA-256(tbs(vendor_der)) into dbx as
    // EFI_CERT_SHA256_GUID: real UEFI firmware still trusts vendor_der!
    var cert_hash: [32]u8 = undefined;
    Sha256.hash(vendor_der, &cert_hash, .{});
    var tbs_hash: [32]u8 = undefined;
    Sha256.hash(try tbsBytes(vendor_der), &tbs_hash, .{});
    var bad_dbx: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &bad_dbx, sha256_guid, &.{ &cert_hash, &tbs_hash });

    const unrevoked = try evaluate(gpa, pk.items, kek.items, db.items, bad_dbx.items, owner_der);
    try testing.expectEqual(@as(usize, 2), unrevoked.active_db.len);

    // Revoking vendor_der via EFI_CERT_X509_GUID leaves owner_der alone.
    var x509_dbx: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &x509_dbx, x509_guid, &.{vendor_der});
    try encodeList(gpa, &x509_dbx, sha256_guid, &.{&cert_hash});
    const clean = try evaluate(gpa, pk.items, kek.items, db.items, x509_dbx.items, owner_der);
    try testing.expectEqual(@as(usize, 1), clean.active_db.len);
    try testing.expectEqualSlices(u8, owner_der, clean.active_db[0]);

    // Unconditional EFI_CERT_X509_SHA256_GUID (TimeOfRevocation == 0) also revokes,
    // while a non-zero timestamp is not treated as an unconditional revocation.
    var tbs_entry: [48]u8 = @splat(0);
    @memcpy(tbs_entry[0..32], &tbs_hash);
    var tbs_dbx: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &tbs_dbx, x509_sha256_guid, &.{&tbs_entry});
    const clean_tbs = try evaluate(gpa, pk.items, kek.items, db.items, tbs_dbx.items, owner_der);
    try testing.expectEqual(@as(usize, 1), clean_tbs.active_db.len);

    tbs_entry[32] = 1; // non-zero TimeOfRevocation
    var timed_dbx: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &timed_dbx, x509_sha256_guid, &.{&tbs_entry});
    const timed = try evaluate(gpa, pk.items, kek.items, db.items, timed_dbx.items, owner_der);
    try testing.expectEqual(@as(usize, 2), timed.active_db.len);
}

test "PK, KEK and db reject binary hash allowlists, empty PK/KEK and rogue KEK" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var own_list: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &own_list, x509_guid, &.{owner_der});
    var vendor_list: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &vendor_list, x509_guid, &.{vendor_der});

    const dummy_hash: [32]u8 = @splat(0xaa);
    var hash_db: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &hash_db, x509_guid, &.{owner_der});
    try encodeList(gpa, &hash_db, sha256_guid, &.{&dummy_hash});
    try testing.expectError(
        error.NonX509SignatureList,
        evaluate(gpa, own_list.items, own_list.items, hash_db.items, "", owner_der),
    );
    try testing.expectError(
        error.EmptyPk,
        evaluate(gpa, "", own_list.items, own_list.items, "", owner_der),
    );
    try testing.expectError(
        error.EmptyKek,
        evaluate(gpa, own_list.items, "", own_list.items, "", owner_der),
    );
    // When PK == boot.der (custom PK), KEK must not admit a second authority.
    var two_kek: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &two_kek, x509_guid, &.{ owner_der, vendor_der });
    try testing.expectError(
        error.ForeignKek,
        evaluate(gpa, own_list.items, two_kek.items, own_list.items, "", owner_der),
    );
    // Published download / Azure template: PK != boot.der (e.g. owner.der PK/KEK,
    // vendor.der db) succeeds when db \ dbx == { vendor.der }.
    const delegated = try evaluate(
        gpa,
        own_list.items,
        own_list.items,
        vendor_list.items,
        "",
        vendor_der,
    );
    try testing.expectEqual(@as(usize, 1), delegated.active_db.len);
    try testing.expectEqualSlices(u8, vendor_der, delegated.active_db[0]);
}

test "malformed signature lists and truncated DER fail closed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    try testing.expectError(error.MalformedSignatureList, x509Certificates(gpa, &.{ 1, 2, 3 }));
    var list: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &list, x509_guid, &.{owner_der});
    try testing.expectError(
        error.MalformedSignatureList,
        x509Certificates(gpa, list.items[0 .. list.items.len - 1]),
    );
    var bad_cert: std.ArrayList(u8) = .empty;
    try encodeList(gpa, &bad_cert, x509_guid, &.{&.{ 1, 2, 3 }});
    try testing.expectError(error.BadCertificateDer, x509Certificates(gpa, bad_cert.items));
}
