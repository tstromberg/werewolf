//! test-sk: a security key in software, for make check alone. It is an
//! OpenSSH security key provider (sk-api.h), the library ssh-keygen -w and
//! ssh's SecurityKeyProvider load, so a check can log in to a machine that
//! takes security keys alone (the sshd form's werewolf.conf, the bastion's
//! sshd_config) with no key to touch.
//!
//! It asserts its user's presence without one: whoever reads its key file
//! logs in, which is what a security key exists to prevent. So it is built
//! for this host, into build/host, and never into an image.
//!
//! Ed25519 alone; the key handle is the key's seed. A signature is as
//! OpenSSH's own regress/misc/sk-dummy makes it, an authenticator's:
//! Ed25519 over SHA-256(application), the flags, a big-endian counter and
//! SHA-256(data). Everything handed back is malloc's, for ssh to free.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// sk-api.h's SSH_SK_VERSION_MAJOR: ssh refuses a provider whose major
/// version is not its own.
const version_major = 0x000a0000;
const alg_ed25519 = 0x01;
const err_general = -1;
const err_unsupported = -2;
/// The counter every signature carries: no clone detection to satisfy.
const counter = 1;

const EnrollResponse = extern struct {
    flags: u8,
    public_key: ?[*]u8,
    public_key_len: usize,
    key_handle: ?[*]u8,
    key_handle_len: usize,
    signature: ?[*]u8,
    signature_len: usize,
    attestation_cert: ?[*]u8,
    attestation_cert_len: usize,
    authdata: ?[*]u8,
    authdata_len: usize,
};

const SignResponse = extern struct {
    flags: u8,
    counter: u32,
    sig_r: ?[*]u8,
    sig_r_len: usize,
    sig_s: ?[*]u8,
    sig_s_len: usize,
};

extern "c" fn getentropy(buf: [*]u8, len: usize) c_int;

export fn sk_api_version() u32 { // ziglint-ignore: Z001
    return version_major;
}

export fn sk_enroll( // ziglint-ignore: Z001
    alg: u32,
    challenge: ?[*]const u8,
    challenge_len: usize,
    application: ?[*:0]const u8,
    flags: u8,
    pin: ?[*:0]const u8,
    options: ?*const anyopaque,
    enroll_response: ?*?*EnrollResponse,
) c_int {
    _ = .{ challenge, challenge_len, application, pin, options };
    const out = enroll_response orelse return err_general;
    out.* = null;
    if (alg != alg_ed25519) return err_unsupported;
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    if (getentropy(&seed, seed.len) != 0) return err_general;
    const pair = Ed25519.KeyPair.generateDeterministic(seed) catch return err_general;
    const r: *EnrollResponse = @ptrCast(@alignCast(std.c.calloc(1, @sizeOf(EnrollResponse)) orelse
        return err_general));
    r.flags = flags;
    r.public_key = dup(&pair.public_key.toBytes());
    r.public_key_len = Ed25519.PublicKey.encoded_length;
    r.key_handle = dup(&seed);
    r.key_handle_len = seed.len;
    // ssh wants a signature to free, and checks none: there is no attestation.
    r.signature = @ptrCast(std.c.calloc(1, 1));
    if (r.public_key == null or r.key_handle == null or r.signature == null) {
        freeEnroll(r);
        return err_general;
    }
    out.* = r;
    return 0;
}

export fn sk_sign( // ziglint-ignore: Z001
    alg: u32,
    data: ?[*]const u8,
    data_len: usize,
    application: ?[*:0]const u8,
    key_handle: ?[*]const u8,
    key_handle_len: usize,
    flags: u8,
    pin: ?[*:0]const u8,
    options: ?*const anyopaque,
    sign_response: ?*?*SignResponse,
) c_int {
    _ = .{ pin, options };
    const out = sign_response orelse return err_general;
    out.* = null;
    if (alg != alg_ed25519) return err_unsupported;
    if (key_handle_len != Ed25519.KeyPair.seed_length) return err_general;
    const app = std.mem.span(application orelse return err_general);
    const seed = (key_handle orelse return err_general)[0..Ed25519.KeyPair.seed_length].*;
    const signed = toSign(app, flags, (data orelse return err_general)[0..data_len]);
    const pair = Ed25519.KeyPair.generateDeterministic(seed) catch return err_general;
    const sig = pair.sign(&signed, null) catch return err_general;
    const r: *SignResponse = @ptrCast(@alignCast(std.c.calloc(1, @sizeOf(SignResponse)) orelse
        return err_general));
    r.flags = flags;
    r.counter = counter;
    r.sig_r = dup(&sig.toBytes());
    r.sig_r_len = Ed25519.Signature.encoded_length;
    if (r.sig_r == null) {
        std.c.free(r);
        return err_general;
    }
    out.* = r;
    return 0;
}

export fn sk_load_resident_keys( // ziglint-ignore: Z001
    pin: ?[*:0]const u8,
    options: ?*const anyopaque,
    rks: ?*anyopaque,
    nrks: ?*usize,
) c_int {
    _ = .{ pin, options, rks, nrks };
    return err_unsupported;
}

/// What an authenticator signs: SHA-256(application), flags, the counter
/// big-endian, and SHA-256(data).
fn toSign(application: []const u8, flags: u8, data: []const u8) [32 + 1 + 4 + 32]u8 {
    var out: [32 + 1 + 4 + 32]u8 = undefined;
    Sha256.hash(application, out[0..32], .{});
    out[32] = flags;
    std.mem.writeInt(u32, out[33..37], counter, .big);
    Sha256.hash(data, out[37..69], .{});
    return out;
}

/// bytes, in memory malloc's, or null.
fn dup(bytes: []const u8) ?[*]u8 {
    const p: [*]u8 = @ptrCast(std.c.malloc(bytes.len) orelse return null);
    @memcpy(p[0..bytes.len], bytes);
    return p;
}

fn freeEnroll(r: *EnrollResponse) void {
    std.c.free(r.public_key);
    std.c.free(r.key_handle);
    std.c.free(r.signature);
    std.c.free(r);
}

test "a key enrolled signs as an authenticator does" {
    var enrolled: ?*EnrollResponse = null;
    try std.testing.expectEqual(
        0,
        sk_enroll(alg_ed25519, null, 0, "ssh:", 0x01, null, null, &enrolled),
    );
    const e = enrolled.?;
    defer freeEnroll(e);
    try std.testing.expectEqual(32, e.key_handle_len);
    const data = "session";
    var signed: ?*SignResponse = null;
    try std.testing.expectEqual(0, sk_sign(
        alg_ed25519,
        data,
        data.len,
        "ssh:",
        e.key_handle,
        e.key_handle_len,
        0x01,
        null,
        null,
        &signed,
    ));
    const s = signed.?;
    defer {
        std.c.free(s.sig_r);
        std.c.free(s);
    }
    try std.testing.expectEqual(0x01, s.flags);
    const public: Ed25519.PublicKey = try .fromBytes(e.public_key.?[0..32].*);
    const sig: Ed25519.Signature = .fromBytes(s.sig_r.?[0..64].*);
    const want = toSign("ssh:", 0x01, data);
    try sig.verify(&want, public);
    try std.testing.expectError(error.SignatureVerificationFailed, sig.verify("other", public));
    try std.testing.expectEqual(
        err_unsupported,
        sk_enroll(0x00, null, 0, "ssh:", 0, null, null, &enrolled),
    );
}
