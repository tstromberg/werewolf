//! Bounded cloud attestation and encrypted credential transport; deployment stays gated.
const std = @import("std");
const apk = @import("apk");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const rsa = std.crypto.Certificate.rsa;
// Fixed TPM/parent, sensitive origin, admin policy, restricted signing.
const attributes: u32 = 0x500b2;
const domain = "werewolf.enroll/1\x00";
const zero: [32]u8 = @splat(0);

pub const Challenge = struct {
    machine: [32]u8,
    factory: [32]u8,
    pcr: [32]u8,
    challenge: [32]u8,

    pub fn check(c: Challenge) !void {
        inline for (.{ "machine", "factory", "pcr", "challenge" }) |field|
            if (std.mem.eql(u8, &@field(c, field), &zero)) return error.BadEnrollmentContext;
    }

    pub fn nonce(c: Challenge) ![32]u8 {
        try c.check();
        var hash = Sha256.init(.{});
        hash.update(domain);
        inline for (.{ "machine", "factory", "pcr", "challenge" }) |field|
            hash.update(&@field(c, field));
        return hash.finalResult();
    }
};

pub const Policy = struct {
    quote: [32]u8,
    activate: [32]u8,
    digest: [32]u8,
};

pub fn policy(pcr: [32]u8) !Policy {
    if (std.mem.eql(u8, &pcr, &zero)) return error.UnmeasuredBoot;
    var selected: [32]u8 = undefined;
    Sha256.hash(&pcr, &selected, .{});
    // PolicyPCR hashes the selection before the concatenated-PCR digest.
    var hash = Sha256.init(.{});
    hash.update(&zero);
    hash.update(&.{ 0, 0, 1, 0x7f });
    hash.update(&.{ 0, 0, 0, 1, 0, 0xb, 3, 0, 8, 0 });
    hash.update(&selected);
    const base = hash.finalResult();
    var result: Policy = undefined;
    inline for (.{ "quote", "activate" }, .{ @as(u32, 0x158), @as(u32, 0x147) }) |field, code| {
        hash = Sha256.init(.{});
        hash.update(&base);
        hash.update(&.{ 0, 0, 1, 0x6c });
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded, code, .big);
        hash.update(&encoded);
        @field(result, field) = hash.finalResult();
    }
    hash = Sha256.init(.{});
    hash.update(&zero);
    hash.update(&.{ 0, 0, 1, 0x71 });
    hash.update(&result.quote);
    hash.update(&result.activate);
    result.digest = hash.finalResult();
    return result;
}

const Read = struct {
    raw: []const u8,
    at: usize = 0,

    fn bytes(r: *Read, count: usize) ![]const u8 {
        if (count > r.raw.len - r.at) return error.BadAttestation;
        defer r.at += count;
        return r.raw[r.at..][0..count];
    }

    fn int(r: *Read, comptime T: type) !T {
        return std.mem.readInt(T, (try r.bytes(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }

    fn sized(r: *Read) ![]const u8 {
        return r.bytes(try r.int(u16));
    }

    fn end(r: Read) !void {
        if (r.at != r.raw.len) return error.BadAttestation;
    }
};

pub const AttestationKey = struct { key: apk.Key, name: [34]u8 };

fn objectName(area: []const u8) [34]u8 {
    var name: [34]u8 = undefined;
    std.mem.writeInt(u16, name[0..2], 0xb, .big);
    Sha256.hash(area, name[2..34], .{});
    return name;
}

fn qualifiedName(parent: []const u8, name: [34]u8) [34]u8 {
    var result: [34]u8 = undefined;
    std.mem.writeInt(u16, result[0..2], 0xb, .big);
    var hash = Sha256.init(.{});
    hash.update(parent);
    hash.update(&name);
    @memcpy(result[2..34], &hash.finalResult());
    return result;
}

pub fn endorsementKey(raw: []const u8, pinned: apk.Key) ![34]u8 {
    try checkRsa(pinned);
    if (raw.len > 512) return error.BadAttestation;
    var outer: Read = .{ .raw = raw };
    const area = try outer.sized();
    try outer.end();
    var r: Read = .{ .raw = area };
    if (try r.int(u16) != 1 or try r.int(u16) != 0xb or
        try r.int(u32) != 0x300b2) return error.UnsupportedEndorsementKey;
    var hash = Sha256.init(.{});
    hash.update(&zero);
    hash.update(&.{ 0, 0, 1, 0x51, 0x40, 0, 0, 0xb });
    var expected = hash.finalResult();
    Sha256.hash(&expected, &expected, .{});
    if (!std.mem.eql(u8, try r.sized(), &expected) or
        try r.int(u16) != 6 or try r.int(u16) != 128 or
        try r.int(u16) != 0x43 or try r.int(u16) != 0x10 or
        try r.int(u16) != 2048) return error.UnsupportedEndorsementKey;
    const exponent = try r.int(u32);
    if (exponent != 0 and exponent != 65537) return error.UnsupportedEndorsementKey;
    if (!std.mem.eql(u8, try r.sized(), pinned.modulus)) return error.WrongEndorsementKey;
    try r.end();
    return qualifiedName(&.{ 0x40, 0, 0, 0xb }, objectName(area));
}

/// Input is a complete TPM2B_PUBLIC, never a PEM key stripped of its TPM attributes.
pub fn attestationKey(raw: []const u8, pcr: [32]u8) !AttestationKey {
    if (raw.len > 512) return error.BadAttestation;
    var outer: Read = .{ .raw = raw };
    const area = try outer.sized();
    try outer.end();
    var r: Read = .{ .raw = area };
    if (try r.int(u16) != 1 or try r.int(u16) != 0xb or
        try r.int(u32) != attributes) return error.BadAttestationKey;
    const expected = try policy(pcr);
    if (!std.mem.eql(u8, try r.sized(), &expected.digest) or
        try r.int(u16) != 0x10 or try r.int(u16) != 0x14 or
        try r.int(u16) != 0xb or try r.int(u16) != 2048) return error.BadAttestationKey;
    const exponent = try r.int(u32);
    if (exponent != 0 and exponent != 65537) return error.BadAttestationKey;
    const key: apk.Key = .{ .modulus = try r.sized(), .exponent = &.{ 1, 0, 1 } };
    try r.end();
    try checkRsa(key);
    return .{ .key = key, .name = objectName(area) };
}

/// Quote bytes are TPMS_ATTEST; signature bytes are TPMT_SIGNATURE.
pub fn verifyQuote(
    ak: AttestationKey,
    parent: [34]u8,
    context: Challenge,
    quote: []const u8,
    signature: []const u8,
) !void {
    const nonce = try context.nonce();
    if (quote.len > 1024 or signature.len > 262) return error.BadAttestation;
    var r: Read = .{ .raw = quote };
    if (try r.int(u32) != 0xff544347 or try r.int(u16) != 0x8018)
        return error.BadAttestation;
    const qualified = try r.sized();
    if (!std.mem.eql(u8, qualified, &qualifiedName(&parent, ak.name)))
        return error.BadAttestation;
    if (!std.mem.eql(u8, try r.sized(), &nonce)) return error.StaleAttestation;
    _ = try r.int(u64); // clock
    _ = try r.int(u32); // reset count
    _ = try r.int(u32); // restart count
    if (try r.int(u8) > 1) return error.BadAttestation;
    _ = try r.int(u64); // firmware version
    if (!std.mem.eql(u8, try r.bytes(10), &.{ 0, 0, 0, 1, 0, 0xb, 3, 0, 8, 0 }))
        return error.BadAttestation;
    var digest: [32]u8 = undefined;
    Sha256.hash(&context.pcr, &digest, .{});
    if (!std.mem.eql(u8, try r.sized(), &digest)) return error.WrongBootstrapMeasurement;
    try r.end();
    r = .{ .raw = signature };
    if (try r.int(u16) != 0x14 or try r.int(u16) != 0xb) return error.BadAttestation;
    const signed = try r.sized();
    try r.end();
    apk.verify(ak.key, quote, signed) catch return error.BadAttestationSignature;
}

fn checkRsa(key: apk.Key) !void {
    if (key.modulus.len != 256 or key.modulus[0] & 0x80 == 0 or
        !std.mem.eql(u8, key.exponent, &.{ 1, 0, 1 })) return error.UnsupportedEndorsementKey;
    _ = rsa.PublicKey.fromBytes(
        key.exponent,
        key.modulus,
    ) catch return error.UnsupportedEndorsementKey;
}

pub const Credential = struct {
    blob: [68]u8,
    seed: [256]u8,
};

/// Standard TPM MakeCredential for an RSA-2048/SHA-256/AES-128-CFB EK.
pub fn makeCredential(io: std.Io, ek: apk.Key, name: [34]u8, secret: *const [32]u8) !Credential {
    try checkRsa(ek);
    if (!std.mem.eql(u8, name[0..2], &.{ 0, 0xb })) return error.BadAttestationKey;
    var seed: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    try io.randomSecure(&seed);
    var storage = kdfa(&seed, "STORAGE", &name, 128);
    defer std.crypto.secureZero(u8, &storage);
    var integrity = kdfa(&seed, "INTEGRITY", "", 256);
    defer std.crypto.secureZero(u8, &integrity);
    var plain: [34]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain);
    std.mem.writeInt(u16, plain[0..2], 32, .big);
    @memcpy(plain[2..34], secret);
    var result: Credential = undefined;
    cfb(result.blob[34..68], &plain, storage[0..16].*);
    var mac = Hmac.init(&integrity);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&mac));
    mac.update(result.blob[34..68]);
    mac.update(&name);
    std.mem.writeInt(u16, result.blob[0..2], 32, .big);
    mac.final(result.blob[2..34]);
    result.seed = try oaep(io, ek, &seed);
    return result;
}

fn kdfa(key: *const [32]u8, label: []const u8, context: []const u8, bits: u32) [32]u8 {
    var mac = Hmac.init(key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&mac));
    mac.update(&.{ 0, 0, 0, 1 });
    mac.update(label);
    mac.update(&.{0});
    mac.update(context);
    var length: [4]u8 = undefined;
    std.mem.writeInt(u32, &length, bits, .big);
    mac.update(&length);
    return mac.finalResult();
}

fn cfb(out: []u8, input: []const u8, key: [16]u8) void {
    var aes = std.crypto.core.aes.Aes128.initEnc(key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&aes));
    var previous: [16]u8 = @splat(0);
    var mask: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &mask);
    var at: usize = 0;
    while (at < input.len) : (at += 16) {
        aes.encrypt(&mask, &previous);
        const count = @min(16, input.len - at);
        for (out[at..][0..count], input[at..][0..count], mask[0..count]) |*d, s, m| d.* = s ^ m;
        if (count == 16) @memcpy(&previous, out[at..][0..16]);
    }
}

fn mgf(out: []u8, seed: []const u8) void {
    var at: usize = 0;
    var counter: u32 = 0;
    while (at < out.len) : (counter += 1) {
        var hash = Sha256.init(.{});
        hash.update(seed);
        var count: [4]u8 = undefined;
        std.mem.writeInt(u32, &count, counter, .big);
        hash.update(&count);
        var digest = hash.finalResult();
        defer std.crypto.secureZero(u8, &digest);
        const length = @min(32, out.len - at);
        @memcpy(out[at..][0..length], digest[0..length]);
        at += length;
    }
}

fn oaep(io: std.Io, key: apk.Key, message: *const [32]u8) ![256]u8 {
    var encoded: [256]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &encoded);
    var random: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &random);
    try io.randomSecure(&random);
    var db: [223]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &db);
    Sha256.hash("IDENTITY\x00", db[0..32], .{});
    db[190] = 1;
    @memcpy(db[191..223], message);
    var mask: [223]u8 = undefined;
    defer std.crypto.secureZero(u8, &mask);
    mgf(&mask, &random);
    for (encoded[33..256], db, mask) |*d, a, b| d.* = a ^ b;
    var seed_mask: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed_mask);
    mgf(&seed_mask, encoded[33..256]);
    for (encoded[1..33], random, seed_mask) |*d, a, b| d.* = a ^ b;
    const public = try rsa.PublicKey.fromBytes(key.exponent, key.modulus);
    var number = try @TypeOf(public.e).fromBytes(public.n, &encoded, .big);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&number));
    const encrypted = try public.n.powPublic(number, public.e);
    var result: [256]u8 = undefined;
    try encrypted.toBytes(&result, .big);
    return result;
}

pub const Capsule = struct { nonce: [12]u8, encrypted: [64]u8, tag: [16]u8 };

pub const Bundle = struct {
    credential: Credential,
    capsule: Capsule,
    pub const size = domain.len + 4 + 68 + 256 + 12 + 64 + 16;

    pub fn encode(b: Bundle) [size]u8 {
        var raw: [size]u8 = undefined;
        @memcpy(raw[0..domain.len], domain);
        var at: usize = domain.len;
        inline for (.{ b.credential.blob, b.credential.seed }) |field| {
            std.mem.writeInt(u16, raw[at..][0..2], field.len, .big);
            at += 2;
            @memcpy(raw[at..][0..field.len], &field);
            at += field.len;
        }
        inline for (.{ b.capsule.nonce, b.capsule.encrypted, b.capsule.tag }) |field| {
            @memcpy(raw[at..][0..field.len], &field);
            at += field.len;
        }
        return raw;
    }

    pub fn decode(raw: []const u8) !Bundle {
        if (raw.len != size or !std.mem.eql(u8, raw[0..domain.len], domain))
            return error.BadEnrollmentCapsule;
        var r: Read = .{ .raw = raw, .at = domain.len };
        var result: Bundle = undefined;
        const blob = try r.sized();
        const seed = try r.sized();
        if (blob.len != 68 or seed.len != 256 or !std.mem.eql(u8, blob[0..2], &.{ 0, 32 }))
            return error.BadEnrollmentCapsule;
        @memcpy(&result.credential.blob, blob);
        @memcpy(&result.credential.seed, seed);
        @memcpy(&result.capsule.nonce, try r.bytes(12));
        @memcpy(&result.capsule.encrypted, try r.bytes(64));
        @memcpy(&result.capsule.tag, try r.bytes(16));
        try r.end();
        return result;
    }
};

pub const capsule_domain = "werewolf.enroll.capsule/1\x00";

pub fn capsuleMessage(
    challenge: Challenge,
    raw: []const u8,
) ![capsule_domain.len + 32 + Bundle.size]u8 {
    _ = try Bundle.decode(raw);
    var result: [capsule_domain.len + 32 + Bundle.size]u8 = undefined;
    @memcpy(result[0..capsule_domain.len], capsule_domain);
    @memcpy(result[capsule_domain.len..][0..32], &try challenge.nonce());
    @memcpy(result[capsule_domain.len + 32 ..], raw);
    return result;
}

pub fn verifyCapsule(signer: apk.Key, challenge: Challenge, raw: []const u8) !Bundle {
    const start = Bundle.size;
    if (raw.len != start + 2 + signer.modulus.len or
        std.mem.readInt(u16, raw[start..][0..2], .big) != signer.modulus.len)
        return error.BadEnrollmentCapsule;
    const message = try capsuleMessage(challenge, raw[0..start]);
    apk.verify(signer, &message, raw[start + 2 ..]) catch return error.BadEnrollmentSignature;
    return Bundle.decode(raw[0..start]);
}

fn aad(context: Challenge, name: [34]u8, ek: apk.Key) ![domain.len + 32 + 34 + 32]u8 {
    try checkRsa(ek);
    var result: [domain.len + 32 + 34 + 32]u8 = undefined;
    @memcpy(result[0..domain.len], domain);
    @memcpy(result[domain.len..][0..32], &try context.nonce());
    @memcpy(result[domain.len + 32 ..][0..34], &name);
    Sha256.hash(ek.modulus, result[domain.len + 66 ..][0..32], .{});
    return result;
}

pub fn seal(
    io: std.Io,
    context: Challenge,
    name: [34]u8,
    ek: apk.Key,
    key: *const [32]u8,
    credentials: *const [64]u8,
) !Capsule {
    const associated = try aad(context, name, ek);
    var result: Capsule = undefined;
    try io.randomSecure(&result.nonce);
    Gcm.encrypt(&result.encrypted, &result.tag, credentials, &associated, result.nonce, key.*);
    return result;
}

pub fn open(
    context: Challenge,
    name: [34]u8,
    ek: apk.Key,
    key: *const [32]u8,
    capsule: Capsule,
) ![64]u8 {
    const associated = try aad(context, name, ek);
    var result: [64]u8 = undefined;
    errdefer std.crypto.secureZero(u8, &result);
    try Gcm.decrypt(&result, &capsule.encrypted, capsule.tag, &associated, capsule.nonce, key.*);
    return result;
}

test "bootstrap requires a measured PCR and complete nonzero context" {
    const t = std.testing;
    try t.expectError(error.UnmeasuredBoot, policy(@splat(0)));
    var context: Challenge = .{
        .machine = @splat(1),
        .factory = @splat(2),
        .pcr = @splat(3),
        .challenge = @splat(4),
    };
    _ = try context.nonce();
    inline for (.{ "machine", "factory", "pcr", "challenge" }) |field| {
        const old = @field(context, field);
        @field(context, field) = zero;
        try t.expectError(error.BadEnrollmentContext, context.nonce());
        @field(context, field) = old;
    }
}

test "capsules authenticate machine, factory, PCR, challenge, keys and ciphertext" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const pem = try std.Io.Dir.cwd().readFileAlloc(
        t.io,
        "lib/testdata/tpm-ab/signer.pub",
        arena.allocator(),
        .limited(1024),
    );
    const ek = try apk.parseKey(arena.allocator(), pem);
    const context: Challenge = .{
        .machine = @splat(1),
        .factory = @splat(2),
        .pcr = @splat(3),
        .challenge = @splat(4),
    };
    const name: [34]u8 = .{ 0, 0xb } ++ @as([32]u8, @splat(5));
    const key: [32]u8 = @splat(6);
    const credentials: [64]u8 = @splat(7);
    const capsule = try seal(t.io, context, name, ek, &key, &credentials);
    try t.expectEqual(credentials, try open(context, name, ek, &key, capsule));
    inline for (.{ "machine", "factory", "pcr", "challenge" }) |field| {
        var wrong = context;
        @field(wrong, field)[0] ^= 1;
        try t.expectError(error.AuthenticationFailed, open(wrong, name, ek, &key, capsule));
    }
    var changed = capsule;
    changed.encrypted[0] ^= 1;
    try t.expectError(error.AuthenticationFailed, open(context, name, ek, &key, changed));
    changed = capsule;
    changed.tag[0] ^= 1;
    try t.expectError(error.AuthenticationFailed, open(context, name, ek, &key, changed));
    changed = capsule;
    changed.nonce[0] ^= 1;
    try t.expectError(error.AuthenticationFailed, open(context, name, ek, &key, changed));
    var wrong_name = name;
    wrong_name[3] ^= 1;
    try t.expectError(error.AuthenticationFailed, open(context, wrong_name, ek, &key, capsule));
    var wrong_key = key;
    wrong_key[0] ^= 1;
    try t.expectError(error.AuthenticationFailed, open(context, name, ek, &wrong_key, capsule));
    var wrong_modulus: [256]u8 = ek.modulus[0..256].*;
    wrong_modulus[100] ^= 1;
    var wrong_ek = ek;
    wrong_ek.modulus = &wrong_modulus;
    try t.expectError(error.AuthenticationFailed, open(context, name, wrong_ek, &key, capsule));
}

const Packet = struct {
    data: [4096]u8 = undefined,
    len: usize = 0,
    sessions: [2]u32 = @splat(0),
    session_count: usize = 0,

    fn bytes(b: *Packet, raw: []const u8) void {
        std.debug.assert(raw.len <= b.data.len - b.len);
        @memcpy(b.data[b.len..][0..raw.len], raw);
        b.len += raw.len;
    }

    fn int(b: *Packet, comptime T: type, n: T) void {
        var raw: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &raw, n, .big);
        b.bytes(&raw);
    }

    fn sized(b: *Packet, raw: []const u8) void {
        b.int(u16, @intCast(raw.len));
        b.bytes(raw);
    }
};

fn command(code: u32, handles: []const u32, sessions: []const u32) Packet {
    var b: Packet = .{};
    std.debug.assert(sessions.len <= b.sessions.len);
    @memcpy(b.sessions[0..sessions.len], sessions);
    b.session_count = sessions.len;
    b.int(u16, if (sessions.len > 0) 0x8002 else 0x8001);
    b.int(u32, 0);
    b.int(u32, code);
    for (handles) |handle| b.int(u32, handle);
    if (sessions.len > 0) {
        b.int(u32, @intCast(sessions.len * 9));
        for (sessions) |handle| {
            b.int(u32, handle);
            b.sized("");
            b.int(u8, 0); // consume sessions after this authorized command
            b.sized("");
        }
    }
    return b;
}

pub const Public = struct {
    raw: [512]u8 = undefined,
    len: usize = 0,

    pub fn slice(p: *const Public) []const u8 {
        return p.raw[0..p.len];
    }

    fn take(r: *Read) !Public {
        const start = r.at;
        _ = try r.sized();
        const raw = r.raw[start..r.at];
        if (raw.len > 512) return error.BadAttestation;
        var result: Public = .{ .len = raw.len };
        @memcpy(result.raw[0..raw.len], raw);
        return result;
    }
};

pub const Quote = struct {
    attest: [1024]u8 = undefined,
    len: usize,
    signature: [262]u8,
};

pub const Boot = struct {
    device: *Device,
    ek: u32,
    ak: u32,
    ek_public: Public,
    ak_public: Public,
    pcr: [32]u8,

    pub fn deinit(b: *Boot) void {
        b.device.flush(b.ak);
        b.device.flush(b.ek);
    }

    pub fn quote(b: *Boot, context: Challenge) !Quote {
        try context.check();
        if (!std.mem.eql(u8, &context.pcr, &b.pcr)) return error.WrongBootstrapMeasurement;
        const session = try b.device.pcrSession(b.pcr, 0x158);
        defer b.device.flush(session);
        var packet = command(0x158, &.{b.ak}, &.{session});
        packet.sized(&try context.nonce());
        packet.int(u16, 0x14);
        packet.int(u16, 0xb);
        packet.bytes(&.{ 0, 0, 0, 1, 0, 0xb, 3, 0, 8, 0 });
        var reply = try b.device.call(&packet, false, 1);
        const quoted = try reply.parameters.sized();
        if (quoted.len > 1024) return error.BadAttestation;
        var result: Quote = .{ .len = quoted.len, .signature = undefined };
        @memcpy(result.attest[0..quoted.len], quoted);
        @memcpy(&result.signature, try reply.parameters.bytes(262));
        try reply.parameters.end();
        return result;
    }

    pub fn receive(b: *Boot, signer: apk.Key, challenge: Challenge, raw: []const u8) ![64]u8 {
        if (!std.mem.eql(u8, &challenge.pcr, &b.pcr)) return error.WrongBootstrapMeasurement;
        const bundle = try verifyCapsule(signer, challenge, raw);
        var shared = try b.activate(bundle.credential);
        defer std.crypto.secureZero(u8, &shared);
        const ak = try attestationKey(b.ak_public.slice(), b.pcr);
        const ek: apk.Key = .{
            .modulus = b.ek_public.slice()[b.ek_public.len - 256 ..],
            .exponent = &.{ 1, 0, 1 },
        };
        _ = try endorsementKey(b.ek_public.slice(), ek);
        return open(challenge, ak.name, ek, &shared, bundle.capsule);
    }

    fn activate(b: *Boot, credential: Credential) ![32]u8 {
        // A replayed bootstrap must not release its capsule key after enrollment.
        try b.device.fresh();
        const ak_session = try b.device.pcrSession(b.pcr, 0x147);
        defer b.device.flush(ak_session);
        const ek_session = try b.device.endorsementSession();
        defer b.device.flush(ek_session);
        var packet = command(0x147, &.{ b.ak, b.ek }, &.{ ak_session, ek_session });
        packet.sized(&credential.blob);
        packet.sized(&credential.seed);
        defer std.crypto.secureZero(u8, &b.device.response);
        var reply = try b.device.call(&packet, false, 2);
        const key = try reply.parameters.sized();
        if (key.len != 32) return error.BadCredential;
        try reply.parameters.end();
        return key[0..32].*;
    }
};

pub const Device = struct {
    io: std.Io,
    file: std.Io.File,
    response: [4096]u8 = undefined,
    last_error: u32 = 0,

    pub fn close(d: *Device) void {
        std.crypto.secureZero(u8, &d.response);
        d.file.close(d.io);
    }

    const Reply = struct { handle: u32, parameters: Read };

    fn call(d: *Device, packet: *Packet, handle: bool, sessions: usize) !Reply {
        std.debug.assert(sessions == packet.session_count);
        defer std.crypto.secureZero(u8, &packet.data);
        std.mem.writeInt(u32, packet.data[2..6], @intCast(packet.len), .big);
        try d.file.writeStreamingAll(d.io, packet.data[0..packet.len]);
        var got = try d.file.readStreaming(d.io, &.{&d.response});
        while (got < 10) {
            const n = try d.file.readStreaming(d.io, &.{d.response[got..]});
            if (n == 0) return error.BadTpmResponse;
            got += n;
        }
        const size = std.mem.readInt(u32, d.response[2..6], .big);
        if (size < 10 or size > d.response.len or got > size) return error.BadTpmResponse;
        while (got < size) {
            const n = try d.file.readStreaming(d.io, &.{d.response[got..size]});
            if (n == 0) return error.BadTpmResponse;
            got += n;
        }
        d.last_error = std.mem.readInt(u32, d.response[6..10], .big);
        if (d.last_error != 0) return error.TpmRefused;
        const tag = std.mem.readInt(u16, d.response[0..2], .big);
        if (tag != (if (sessions > 0) @as(u16, 0x8002) else 0x8001)) return error.BadTpmResponse;
        var r: Read = .{ .raw = d.response[10..size] };
        const returned = if (handle) try r.int(u32) else 0;
        if (sessions == 0) return .{ .handle = returned, .parameters = r };
        const params = try r.bytes(try r.int(u32));
        for (packet.sessions[0..sessions]) |session_handle| {
            const nonce = try r.sized();
            // Password-session responses always set continueSession, unlike consumed policies.
            const password = session_handle == 0x40000009;
            if (nonce.len != (if (password) @as(usize, 0) else 32) or
                try r.int(u8) != (if (password) @as(u8, 1) else 0) or
                (try r.sized()).len != 0) return error.BadTpmResponse;
        }
        try r.end();
        return .{ .handle = returned, .parameters = .{ .raw = params } };
    }

    fn flush(d: *Device, handle: u32) void {
        var packet = command(0x165, &.{handle}, &.{});
        _ = d.call(&packet, false, 0) catch {};
    }

    pub fn pcr11(d: *Device) ![32]u8 {
        var packet = command(0x17e, &.{}, &.{});
        packet.bytes(&.{ 0, 0, 0, 1, 0, 0xb, 3, 0, 8, 0 });
        var reply = try d.call(&packet, false, 0);
        var r = &reply.parameters;
        _ = try r.int(u32);
        if (!std.mem.eql(u8, try r.bytes(10), &.{ 0, 0, 0, 1, 0, 0xb, 3, 0, 8, 0 }) or
            try r.int(u32) != 1) return error.BadTpmResponse;
        const digest = try r.sized();
        if (digest.len != 32) return error.BadTpmResponse;
        try r.end();
        return digest[0..32].*;
    }

    pub fn fresh(d: *Device) !void {
        var packet = command(0x17a, &.{}, &.{});
        packet.int(u32, 6); // TPM properties
        packet.int(u32, 0x200); // permanent
        packet.int(u32, 1);
        var reply = try d.call(&packet, false, 0);
        var r = &reply.parameters;
        if (try r.int(u8) > 1 or try r.int(u32) != 6 or try r.int(u32) != 1 or
            try r.int(u32) != 0x200) return error.BadTpmResponse;
        if (try r.int(u32) & 5 != 0) return error.TpmAlreadyProvisioned;
        try r.end();
        packet = command(0x17a, &.{}, &.{});
        packet.int(u32, 1); // handles; refuse either Werewolf NV protocol
        packet.int(u32, 0x01500020);
        packet.int(u32, 2);
        reply = try d.call(&packet, false, 0);
        r = &reply.parameters;
        if (try r.int(u8) > 1 or try r.int(u32) != 1) return error.BadTpmResponse;
        const count = try r.int(u32);
        if (count > 2) return error.BadTpmResponse;
        for (0..count) |_| {
            const value = try r.int(u32);
            if (value == 0x01500020 or value == 0x01500021) return error.TpmAlreadyProvisioned;
        }
        try r.end();
        packet = command(0x17a, &.{}, &.{});
        packet.int(u32, 9); // hierarchy authorization policies
        packet.int(u32, 0x40000001);
        packet.int(u32, 4);
        reply = try d.call(&packet, false, 0);
        r = &reply.parameters;
        if (try r.int(u8) != 0 or try r.int(u32) != 9 or try r.int(u32) != 4)
            return error.UnprotectedTpmHierarchy;
        for ([4]u32{ 0x40000001, 0x4000000a, 0x4000000b, 0x4000000c }) |hierarchy|
            if (try r.int(u32) != hierarchy or try r.int(u16) != 0x10)
                return error.UnprotectedTpmHierarchy;
        try r.end();
    }

    fn session(d: *Device) !u32 {
        var nonce: [32]u8 = undefined;
        try d.io.randomSecure(&nonce);
        var packet = command(0x176, &.{ 0x40000007, 0x40000007 }, &.{});
        packet.sized(&nonce);
        packet.sized("");
        packet.int(u8, 1);
        packet.int(u16, 0x10);
        packet.int(u16, 0xb);
        var reply = try d.call(&packet, true, 0);
        errdefer d.flush(reply.handle);
        if ((try reply.parameters.sized()).len != 32) return error.BadTpmResponse;
        try reply.parameters.end();
        return reply.handle;
    }

    fn endorsementSession(d: *Device) !u32 {
        const handle = try d.session();
        errdefer d.flush(handle);
        var packet = command(0x151, &.{ 0x4000000b, handle }, &.{0x40000009});
        packet.sized("");
        packet.sized("");
        packet.sized("");
        packet.int(i32, 0);
        var reply = try d.call(&packet, false, 1);
        _ = try reply.parameters.sized(); // timeout
        try ticket(&reply.parameters);
        try reply.parameters.end();
        return handle;
    }

    fn pcrSession(d: *Device, pcr: [32]u8, code: u32) !u32 {
        const p = try policy(pcr);
        const handle = try d.session();
        errdefer d.flush(handle);
        var packet = command(0x17f, &.{handle}, &.{});
        var digest: [32]u8 = undefined;
        Sha256.hash(&pcr, &digest, .{});
        packet.sized(&digest);
        packet.bytes(&.{ 0, 0, 0, 1, 0, 0xb, 3, 0, 8, 0 });
        _ = try d.call(&packet, false, 0);
        packet = command(0x16c, &.{handle}, &.{});
        packet.int(u32, code);
        _ = try d.call(&packet, false, 0);
        packet = command(0x171, &.{handle}, &.{});
        packet.int(u32, 2);
        packet.sized(&p.quote);
        packet.sized(&p.activate);
        _ = try d.call(&packet, false, 0);
        return handle;
    }

    pub fn begin(d: *Device, pcr: [32]u8) !Boot {
        _ = try policy(pcr);
        try d.fresh();
        if (!std.mem.eql(u8, &try d.pcr11(), &pcr)) return error.WrongBootstrapMeasurement;
        var packet = command(0x131, &.{0x4000000b}, &.{0x40000009}); // CreatePrimary
        packet.sized(&.{ 0, 0, 0, 0 });
        var area = template(true, pcr);
        packet.sized(area.data[0..area.len]);
        packet.sized("");
        packet.int(u32, 0);
        var reply = try d.call(&packet, true, 1);
        const ek = reply.handle;
        errdefer d.flush(ek);
        const ek_public = try Public.take(&reply.parameters);
        try creation(&reply.parameters);
        const ek_name = try reply.parameters.sized();
        if (!std.mem.eql(
            u8,
            ek_name,
            &objectName(ek_public.slice()[2..]),
        )) return error.BadTpmResponse;
        try reply.parameters.end();
        const parent = try d.endorsementSession();
        defer d.flush(parent);
        packet = command(0x153, &.{ek}, &.{parent}); // Create
        packet.sized(&.{ 0, 0, 0, 0 });
        area = template(false, pcr);
        packet.sized(area.data[0..area.len]);
        packet.sized("");
        packet.int(u32, 0);
        reply = try d.call(&packet, false, 1);
        const private = try reply.parameters.sized();
        if (private.len > 1024) return error.BadTpmResponse;
        var wrapped: [1024]u8 = undefined;
        defer std.crypto.secureZero(u8, &wrapped);
        @memcpy(wrapped[0..private.len], private);
        const private_len = private.len;
        const ak_public = try Public.take(&reply.parameters);
        try creation(&reply.parameters);
        try reply.parameters.end();
        const parsed = try attestationKey(ak_public.slice(), pcr);
        const load_session = try d.endorsementSession();
        defer d.flush(load_session);
        packet = command(0x157, &.{ek}, &.{load_session}); // Load
        packet.sized(wrapped[0..private_len]);
        packet.bytes(ak_public.slice());
        reply = try d.call(&packet, true, 1);
        errdefer d.flush(reply.handle);
        if (!std.mem.eql(
            u8,
            try reply.parameters.sized(),
            &parsed.name,
        )) return error.BadTpmResponse;
        try reply.parameters.end();
        return .{
            .device = d,
            .ek = ek,
            .ak = reply.handle,
            .ek_public = ek_public,
            .ak_public = ak_public,
            .pcr = pcr,
        };
    }
};

fn ticket(r: *Read) !void {
    _ = try r.int(u16);
    _ = try r.int(u32);
    _ = try r.sized();
}

fn creation(r: *Read) !void {
    _ = try r.sized();
    _ = try r.sized();
    try ticket(r);
}

fn template(ek: bool, pcr: [32]u8) Packet {
    var b: Packet = .{};
    b.int(u16, 1);
    b.int(u16, 0xb);
    b.int(u32, if (ek) 0x300b2 else attributes);
    if (ek) {
        var hash = Sha256.init(.{});
        hash.update(&zero);
        hash.update(&.{ 0, 0, 1, 0x51, 0x40, 0, 0, 0xb });
        var digest = hash.finalResult();
        Sha256.hash(&digest, &digest, .{});
        b.sized(&digest);
        b.int(u16, 6);
        b.int(u16, 128);
        b.int(u16, 0x43);
        b.int(u16, 0x10);
    } else {
        b.sized(&(policy(pcr) catch unreachable).digest);
        b.int(u16, 0x10);
        b.int(u16, 0x14);
        b.int(u16, 0xb);
    }
    b.int(u16, 2048);
    b.int(u32, 0);
    b.sized(if (ek) &@as([256]u8, @splat(0)) else "");
    return b;
}

test "independent TPM quotes bind full templates, qualified parent, PCR and challenge" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const base = "lib/testdata/tpm-bootstrap/";
    const raw = try std.Io.Dir.cwd().readFileAlloc(t.io, base ++ "context", gpa, .limited(129));
    try t.expectEqual(@as(usize, 128), raw.len);
    const challenge: Challenge = .{
        .machine = raw[0..32].*,
        .factory = raw[32..64].*,
        .pcr = raw[64..96].*,
        .challenge = raw[96..128].*,
    };
    const pem = try std.Io.Dir.cwd().readFileAlloc(t.io, base ++ "ek.pem", gpa, .limited(1024));
    const pinned = try apk.parseKey(gpa, pem);
    const ek = try std.Io.Dir.cwd().readFileAlloc(t.io, base ++ "ek.pub", gpa, .limited(512));
    const public = try std.Io.Dir.cwd().readFileAlloc(t.io, base ++ "ak.pub", gpa, .limited(512));
    const quote = try std.Io.Dir.cwd().readFileAlloc(
        t.io,
        base ++ "quote.msg",
        gpa,
        .limited(1024),
    );
    const signature = try std.Io.Dir.cwd().readFileAlloc(
        t.io,
        base ++ "quote.sig",
        gpa,
        .limited(263),
    );
    const parent = try endorsementKey(ek, pinned);
    const ak = try attestationKey(public, challenge.pcr);
    try verifyQuote(ak, parent, challenge, quote, signature);
    for (0..public.len) |n| {
        if (attestationKey(public[0..n], challenge.pcr)) |_|
            return error.AcceptedTruncatedKey
        else |_| {}
    }
    for (0..quote.len) |n| {
        if (verifyQuote(ak, parent, challenge, quote[0..n], signature)) |_|
            return error.AcceptedTruncatedQuote
        else |_| {}
    }
    for (0..signature.len) |n| {
        if (verifyQuote(ak, parent, challenge, quote, signature[0..n])) |_|
            return error.AcceptedTruncatedSignature
        else |_| {}
    }
    public[9] ^= 0x40;
    try t.expectError(error.BadAttestationKey, attestationKey(public, challenge.pcr));
    public[9] ^= 0x40;
    public[12] ^= 1; // authorization-policy substitution
    try t.expectError(error.BadAttestationKey, attestationKey(public, challenge.pcr));
    public[12] ^= 1;
    var changed = challenge;
    changed.challenge[0] ^= 1;
    try t.expectError(error.StaleAttestation, verifyQuote(ak, parent, changed, quote, signature));
    changed = challenge;
    changed.pcr[0] ^= 1;
    try t.expectError(error.StaleAttestation, verifyQuote(ak, parent, changed, quote, signature));
    var wrong_parent = parent;
    wrong_parent[5] ^= 1;
    try t.expectError(
        error.BadAttestation,
        verifyQuote(ak, wrong_parent, challenge, quote, signature),
    );
    signature[signature.len - 1] ^= 1;
    try t.expectError(
        error.BadAttestationSignature,
        verifyQuote(ak, parent, challenge, quote, signature),
    );
    signature[signature.len - 1] ^= 1;
    var wrong_modulus = try gpa.dupe(u8, pinned.modulus);
    wrong_modulus[20] ^= 1;
    var wrong_key = pinned;
    wrong_key.modulus = wrong_modulus;
    try t.expectError(error.WrongEndorsementKey, endorsementKey(ek, wrong_key));
}

test "capsule framing rejects every truncated packet, oversized body and invalid lengths" {
    const t = std.testing;
    var bundle: Bundle = .{
        .credential = .{ .blob = @splat(1), .seed = @splat(2) },
        .capsule = .{ .nonce = @splat(3), .encrypted = @splat(4), .tag = @splat(5) },
    };
    bundle.credential.blob[0..2].* = .{ 0, 32 };
    var raw = bundle.encode();
    const parsed = try Bundle.decode(&raw);
    try t.expectEqual(raw, parsed.encode());
    for (0..raw.len) |n|
        try t.expectError(error.BadEnrollmentCapsule, Bundle.decode(raw[0..n]));
    try t.expectError(error.BadEnrollmentCapsule, Bundle.decode(&(raw ++ [_]u8{0})));
    raw[domain.len + 1] -= 1;
    if (Bundle.decode(&raw)) |_| return error.AcceptedInvalidCapsule else |_| {}
}
