//! TPM 2.0 signed retirement; serial-floor commands remain host-only test probes.
const std = @import("std");
const apk = @import("apk");
const Sha256 = std.crypto.hash.sha2.Sha256;
const retirement = @import("boot-state.zig");
pub const Record = retirement.Record;
pub const record_size = retirement.size;
pub const releaseId = retirement.releaseId;
pub const pair_index: u32 = 0x01500021;
// Written, no DA, auth read, NV extend, owner/policy write.
pub const pair_attributes: u32 = 0x2204004a;
pub const pair_qualifier = "werewolf.boot/2";
pub const index: u32 = 0x01500020;
pub const attributes: u32 = 0x2204100a; // written, no DA, auth read, write-all, owner/policy write
pub const qualifier = "werewolf.rollback/1";
pub const metadata = "/usr/share/werewolf/tpm";
const owner: u32 = 0x40000001;
const platform: u32 = 0x4000000c;
const password: u32 = 0x40000009;

const Bytes = struct {
    data: [4096]u8 = undefined,
    len: usize = 0,
    fn bytes(b: *Bytes, input: []const u8) void {
        @memcpy(b.data[b.len..][0..input.len], input);
        b.len += input.len;
    }
    fn int(b: *Bytes, comptime T: type, input: T) void {
        std.mem.writeInt(T, b.data[b.len..][0..@sizeOf(T)], input, .big);
        b.len += @sizeOf(T);
    }
    fn sized(b: *Bytes, input: []const u8) void {
        b.int(u16, @intCast(input.len));
        b.bytes(input);
    }
    fn slice(b: *const Bytes) []const u8 {
        return b.data[0..b.len];
    }
};

const Read = struct {
    data: []const u8,
    at: usize = 0,
    fn bytes(r: *Read, n: usize) ![]const u8 {
        if (n > r.data.len - r.at) return error.BadTpmResponse;
        defer r.at += n;
        return r.data[r.at..][0..n];
    }
    fn int(r: *Read, comptime T: type) !T {
        return std.mem.readInt(T, (try r.bytes(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
    fn sized(r: *Read) ![]const u8 {
        return r.bytes(try r.int(u16));
    }
};

fn command(code: u32, handles: []const u32, auth: ?u32) Bytes {
    var b: Bytes = .{};
    b.int(u16, if (auth != null) 0x8002 else 0x8001);
    b.int(u32, 0);
    b.int(u32, code);
    for (handles) |h| b.int(u32, h);
    if (auth) |session| {
        b.int(u32, 9);
        b.int(u32, session);
        b.int(u16, 0);
        b.int(u8, 0);
        b.int(u16, 0);
    }
    return b;
}

fn passwordCommand(code: u32, handles: []const u32, secret: []const u8) Bytes {
    var b = command(code, handles, null);
    std.mem.writeInt(u16, b.data[0..2], 0x8002, .big);
    b.int(u32, @intCast(9 + secret.len));
    b.int(u32, password);
    b.sized("");
    b.int(u8, 0);
    b.sized(secret);
    return b;
}

pub fn public(key: apk.Key) !Bytes {
    if (key.modulus.len != 256 and key.modulus.len != 384 and
        key.modulus.len != 512) return error.BadTpmKey;
    if (!std.mem.eql(u8, key.exponent, &.{ 1, 0, 1 })) return error.BadTpmKey;
    var b: Bytes = .{};
    b.int(u16, 1); // RSA
    b.int(u16, 0xb); // SHA-256 name
    b.int(u32, 0x40040); // signing, userWithAuth
    b.sized("");
    b.int(u16, 0x10); // no symmetric algorithm
    b.int(u16, 0x10); // unrestricted signature scheme
    b.int(u16, @intCast(key.modulus.len * 8));
    b.int(u32, 65537);
    b.sized(key.modulus);
    return b;
}

fn name(data: []const u8) [34]u8 {
    var out: [34]u8 = undefined;
    std.mem.writeInt(u16, out[0..2], 0xb, .big);
    Sha256.hash(data, out[2..34], .{});
    return out;
}

pub fn authorization(key: apk.Key) ![32]u8 {
    return authorize(key, qualifier);
}

fn authorize(key: apk.Key, reference: []const u8) ![32]u8 {
    const pubkey = try public(key);
    const key_name = name(pubkey.slice());
    var b: Bytes = .{};
    b.bytes(&@as([32]u8, @splat(0)));
    b.int(u32, 0x16a); // PolicyAuthorize
    b.bytes(&key_name);
    var first: [32]u8 = undefined;
    Sha256.hash(b.slice(), &first, .{});
    b = .{};
    b.bytes(&first);
    b.bytes(reference);
    var result: [32]u8 = undefined;
    Sha256.hash(b.slice(), &result, .{});
    return result;
}

pub fn pairAuthorization(key: apk.Key) ![32]u8 {
    return authorize(key, pair_qualifier);
}

fn pairPublic(key: apk.Key) !Bytes {
    var b: Bytes = .{};
    b.int(u32, pair_index);
    b.int(u16, 0xb);
    b.int(u32, pair_attributes);
    b.sized(&try pairAuthorization(key));
    b.int(u16, 32);
    return b;
}

pub fn pairCpHash(key: apk.Key, state: Record) ![32]u8 {
    const nv = try pairPublic(key);
    const nv_name = name(nv.slice());
    var b: Bytes = .{};
    b.int(u32, 0x136); // NV_Extend
    b.bytes(&nv_name);
    b.bytes(&nv_name);
    b.sized(&state.digest());
    var result: [32]u8 = undefined;
    Sha256.hash(b.slice(), &result, .{});
    return result;
}

fn pcrSelection(b: *Bytes) void {
    b.int(u32, 1);
    b.int(u16, 0xb); // SHA-256
    b.int(u8, 3);
    b.bytes(&.{ 0, 8, 0 }); // PCR 11
}

/// Exact old anchor, retained UKI measurement and one exact NV extension.
pub fn pairApproved(key: apk.Key, state: Record) ![32]u8 {
    _ = try Record.decode(&state.encode());
    const nv = try pairPublic(key);
    var b: Bytes = .{};
    b.bytes(&state.previous);
    b.int(u16, 0);
    b.int(u16, 0); // equality
    var args: [32]u8 = undefined;
    Sha256.hash(b.slice(), &args, .{});
    b = .{};
    b.bytes(&@as([32]u8, @splat(0)));
    b.int(u32, 0x149); // PolicyNV
    b.bytes(&args);
    b.bytes(&name(nv.slice()));
    var digest: [32]u8 = undefined;
    Sha256.hash(b.slice(), &digest, .{});
    b = .{};
    b.bytes(&digest);
    b.int(u32, 0x17f); // PolicyPCR
    pcrSelection(&b);
    var pcr_digest: [32]u8 = undefined;
    Sha256.hash(&state.pcr, &pcr_digest, .{});
    b.bytes(&pcr_digest);
    Sha256.hash(b.slice(), &digest, .{});
    b = .{};
    b.bytes(&digest);
    b.int(u32, 0x16e); // PolicyCpHash
    b.bytes(&try pairCpHash(key, state));
    Sha256.hash(b.slice(), &digest, .{});
    return digest;
}

pub fn pairMessage(key: apk.Key, state: Record) ![32 + pair_qualifier.len]u8 {
    return (try pairApproved(key, state)) ++ pair_qualifier.*;
}

pub fn verifyRecord(
    key: apk.Key,
    raw: []const u8,
    signature: []const u8,
    anchor: [32]u8,
    release: [32]u8,
) !Record {
    const state = try Record.decode(raw);
    const message = try pairMessage(key, state);
    try apk.verify(key, &message, signature);
    if (!std.mem.eql(u8, &state.anchor(), &anchor)) return error.StaleBootState;
    if (!state.allows(release)) return error.RollbackRefused;
    return state;
}

fn nvPublic(key: apk.Key) !Bytes {
    var b: Bytes = .{};
    b.int(u32, index);
    b.int(u16, 0xb);
    b.int(u32, attributes);
    b.sized(&try authorization(key));
    b.int(u16, 8);
    return b;
}

pub fn value(serial: u64) [8]u8 {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, serial, .big);
    return b;
}

pub fn cpHash(key: apk.Key, serial: u64) ![32]u8 {
    const nv = try nvPublic(key);
    const nv_name = name(nv.slice());
    var b: Bytes = .{};
    b.int(u32, 0x137); // NV_Write
    b.bytes(&nv_name);
    b.bytes(&nv_name);
    b.sized(&value(serial));
    b.int(u16, 0);
    var digest: [32]u8 = undefined;
    Sha256.hash(b.slice(), &digest, .{});
    return digest;
}

/// PolicyNV(floor <= serial) and PolicyCpHash(exact NV_Write), signed with qualifier.
pub fn approved(key: apk.Key, serial: u64) ![32]u8 {
    const nv = try nvPublic(key);
    const nv_name = name(nv.slice());
    var b: Bytes = .{};
    b.bytes(&value(serial));
    b.int(u16, 0);
    b.int(u16, 9); // unsigned <=
    var args: [32]u8 = undefined;
    Sha256.hash(b.slice(), &args, .{});
    b = .{};
    b.bytes(&@as([32]u8, @splat(0)));
    b.int(u32, 0x149); // PolicyNV
    b.bytes(&args);
    b.bytes(&nv_name);
    var digest: [32]u8 = undefined;
    Sha256.hash(b.slice(), &digest, .{});
    b = .{};
    b.bytes(&digest);
    b.int(u32, 0x16e); // PolicyCpHash
    b.bytes(&try cpHash(key, serial));
    Sha256.hash(b.slice(), &digest, .{});
    return digest;
}

pub const Device = struct {
    io: std.Io,
    file: std.Io.File,
    response: [4096]u8 = undefined,
    last_error: u32 = 0,

    pub fn open(io: std.Io) !Device {
        return .{
            .io = io,
            .file = try std.Io.Dir.cwd().openFile(io, "/dev/tpmrm0", .{ .mode = .read_write }),
        };
    }
    pub fn close(d: *Device) void {
        std.crypto.secureZero(u8, &d.response);
        d.file.close(d.io);
    }

    fn call(d: *Device, b: *Bytes) !Read {
        defer std.crypto.secureZero(u8, &b.data);
        std.mem.writeInt(u32, b.data[2..6], @intCast(b.len), .big);
        try d.file.writeStreamingAll(d.io, b.slice());
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
        var r: Read = .{ .data = d.response[10..size] };
        const tag = std.mem.readInt(u16, d.response[0..2], .big);
        if (tag == 0x8002) {
            const len = try r.int(u32);
            return .{ .data = try r.bytes(len) };
        }
        if (tag != 0x8001) return error.BadTpmResponse;
        return r;
    }

    fn property(d: *Device, id: u32) !u32 {
        var b = command(0x17a, &.{}, null);
        b.int(u32, 6);
        b.int(u32, id);
        b.int(u32, 1);
        var r = try d.call(&b);
        _ = try r.int(u8);
        if (try r.int(u32) != 6 or try r.int(u32) != 1 or
            try r.int(u32) != id) return error.BadTpmResponse;
        return r.int(u32);
    }

    /// Host-only enrollment of a fresh TPM; credentials never enter a guest image.
    pub fn provision(
        d: *Device,
        key: apk.Key,
        initial: Record,
        credentials: *const [2][32]u8,
    ) !void {
        const zero: [32]u8 = @splat(0);
        if (!std.mem.eql(u8, &initial.previous, &zero) or
            !std.mem.eql(
                u8,
                &initial.retained,
                &initial.candidate,
            )) return error.WrongFactoryBootState;
        for (credentials) |*secret|
            if (std.mem.eql(u8, secret, &zero)) return error.BadProvisioningCredential;
        if (try d.property(0x200) & 5 != 0) return error.TpmAlreadyProvisioned;
        try d.noHierarchyPolicies();
        var b = command(0x17a, &.{}, null);
        b.int(u32, 1); // HANDLES
        b.int(u32, pair_index);
        b.int(u32, 1);
        var r = try d.call(&b);
        _ = try r.int(u8);
        if (try r.int(u32) != 1) return error.BadTpmResponse;
        const count = try r.int(u32);
        if (count > 1) return error.BadTpmResponse;
        if (count == 1 and try r.int(u32) == pair_index) return error.TpmAlreadyProvisioned;
        if (r.at != r.data.len) return error.BadTpmResponse;
        for ([2]u32{ owner, 0x4000000a }, credentials) |hierarchy, *secret| {
            b = command(0x129, &.{hierarchy}, password); // HierarchyChangeAuth
            b.sized(secret);
            _ = try d.call(&b);
        }
        b = passwordCommand(0x127, &.{0x4000000a}, &credentials[1]); // ClearControl
        b.int(u8, 1);
        _ = try d.call(&b);
        var nv = try pairPublic(key);
        std.mem.writeInt(u32, nv.data[6..10], pair_attributes & ~@as(u32, 1 << 29), .big);
        b = passwordCommand(0x12a, &.{owner}, &credentials[0]); // NV_DefineSpace
        b.sized("");
        b.sized(nv.slice());
        _ = try d.call(&b);
        b = passwordCommand(0x136, &.{ owner, pair_index }, &credentials[0]);
        b.sized(&initial.digest());
        _ = try d.call(&b);
        try d.disablePlatform();
        if (!std.mem.eql(u8, &try d.anchor(key), &initial.anchor())) return error.WrongBootState;
    }

    pub fn disablePlatform(d: *Device) !void {
        if (try d.property(0x201) & 1 == 0) return;
        var b = command(0x121, &.{platform}, password);
        b.int(u32, platform);
        b.int(u8, 0);
        _ = d.call(&b) catch |err| {
            // UEFI can retain an enabled hierarchy with a firmware-held random auth.
            if (err == error.TpmRefused and d.authRefused()) {
                try d.noHierarchyPolicies();
                return;
            }
            return err;
        };
        if (try d.property(0x201) & 1 != 0) return error.TpmPlatformEnabled;
    }

    fn authRefused(d: *Device) bool {
        return d.last_error == 0x9a2 or d.last_error == 0x98e;
    }

    fn noHierarchyPolicies(d: *Device) !void {
        var b = command(0x17a, &.{}, null);
        b.int(u32, 9); // AUTH_POLICIES
        b.int(u32, owner);
        b.int(u32, 4);
        var r = try d.call(&b);
        if (try r.int(u8) != 0 or try r.int(u32) != 9 or try r.int(u32) != 4)
            return error.UnprotectedTpmHierarchy;
        for ([4]u32{ owner, 0x4000000a, 0x4000000b, platform }) |handle| {
            if (try r.int(u32) != handle or try r.int(u16) != 0x10)
                return error.UnprotectedTpmHierarchy;
        }
        if (r.at != r.data.len) return error.BadTpmResponse;
    }

    fn hierarchyProtected(d: *Device) !void {
        if (try d.property(0x200) & 0x105 != 0x105) return error.UnprotectedTpmHierarchy;
        try d.noHierarchyPolicies();
        if (try d.property(0x201) & 1 == 0) return;
        // An auth-only no-op must be refused. Boot's trusted firmware/ stage0
        // established the protection before any guest-controlled process ran.
        var b = command(0x121, &.{platform}, password);
        b.int(u32, platform);
        b.int(u8, 1);
        _ = d.call(&b) catch |err| {
            if (err == error.TpmRefused and d.authRefused()) return;
            return err;
        };
        return error.UnprotectedTpmHierarchy;
    }

    pub fn floor(d: *Device, key: apk.Key) !u64 {
        // Reset authority must remain outside the guest, including physical-presence commands.
        try d.hierarchyProtected();
        var b = command(0x169, &.{index}, null);
        var r = try d.call(&b);
        const actual = try r.sized();
        const expected = try nvPublic(key);
        if (!std.mem.eql(u8, actual, expected.slice()) or
            !std.mem.eql(u8, try r.sized(), &name(actual)))
            return error.WrongRollbackIndex;
        b = command(0x14e, &.{ index, index }, password);
        b.int(u16, 8);
        b.int(u16, 0);
        r = try d.call(&b);
        const data = try r.sized();
        if (data.len != 8) return error.BadTpmResponse;
        return std.mem.readInt(u64, data[0..8], .big);
    }

    pub fn anchor(d: *Device, key: apk.Key) ![32]u8 {
        try d.hierarchyProtected();
        var b = command(0x169, &.{pair_index}, null);
        var r = try d.call(&b);
        const actual = try r.sized();
        const expected = try pairPublic(key);
        if (!std.mem.eql(u8, actual, expected.slice()) or
            !std.mem.eql(u8, try r.sized(), &name(actual))) return error.WrongRollbackIndex;
        b = command(0x14e, &.{ pair_index, pair_index }, password);
        b.int(u16, 32);
        b.int(u16, 0);
        r = try d.call(&b);
        const data = try r.sized();
        if (data.len != 32) return error.BadTpmResponse;
        var result: [32]u8 = undefined;
        @memcpy(&result, data);
        return result;
    }

    pub fn pcr11(d: *Device) ![32]u8 {
        var b = command(0x17e, &.{}, null);
        pcrSelection(&b);
        var r = try d.call(&b);
        _ = try r.int(u32);
        var selection: Bytes = .{};
        pcrSelection(&selection);
        if (!std.mem.eql(u8, try r.bytes(selection.len), selection.slice()) or
            try r.int(u32) != 1) return error.BadTpmResponse;
        const data = try r.sized();
        if (data.len != 32) return error.BadTpmResponse;
        var result: [32]u8 = undefined;
        @memcpy(&result, data);
        return result;
    }

    pub fn check(d: *Device, key: apk.Key, serial: u64) !void {
        if (serial < try d.floor(key)) return error.RollbackRefused;
    }

    fn flush(d: *Device, handle: u32) void {
        var b = command(0x165, &.{handle}, null);
        _ = d.call(&b) catch {};
    }

    const Session = struct { handle: u32, key_name: [34]u8, ticket: Bytes };

    fn session(
        d: *Device,
        key: apk.Key,
        policy: [32]u8,
        reference: []const u8,
        signature: []const u8,
    ) !Session {
        if (signature.len != key.modulus.len) return error.BadRollbackSignature;
        const area = try public(key);
        var b = command(0x167, &.{}, null); // LoadExternal
        b.sized("");
        b.sized(area.slice());
        b.int(u32, owner);
        var r = try d.call(&b);
        const signer = try r.int(u32);
        defer d.flush(signer);
        const key_name = name(area.slice());
        if (!std.mem.eql(u8, try r.sized(), &key_name)) return error.BadTpmResponse;
        var signed_data: Bytes = .{};
        signed_data.bytes(&policy);
        signed_data.bytes(reference);
        var hash: [32]u8 = undefined;
        Sha256.hash(signed_data.slice(), &hash, .{});
        b = command(0x177, &.{signer}, null); // VerifySignature
        b.sized(&hash);
        b.int(u16, 0x14);
        b.int(u16, 0xb);
        b.sized(signature);
        r = try d.call(&b);
        var ticket: Bytes = .{};
        ticket.bytes(r.data);
        b = command(0x17b, &.{}, null); // GetRandom
        b.int(u16, 32);
        r = try d.call(&b);
        var nonce: [32]u8 = undefined;
        const random = try r.sized();
        if (random.len != 32) return error.BadTpmResponse;
        @memcpy(&nonce, random);
        b = command(0x176, &.{ 0x40000007, 0x40000007 }, null); // StartAuthSession
        b.sized(&nonce);
        b.sized("");
        b.int(u8, 1);
        b.int(u16, 0x10);
        b.int(u16, 0xb);
        r = try d.call(&b);
        return .{ .handle = try r.int(u32), .key_name = key_name, .ticket = ticket };
    }

    fn authorizeSession(d: *Device, s: Session, policy: [32]u8, reference: []const u8) !void {
        var b = command(0x16a, &.{s.handle}, null);
        b.sized(&policy);
        b.sized(reference);
        b.sized(&s.key_name);
        b.bytes(s.ticket.slice());
        _ = try d.call(&b);
    }

    pub fn advance(d: *Device, key: apk.Key, serial: u64, signature: []const u8) !void {
        try d.check(key, serial);
        const policy = try approved(key, serial);
        const s = try d.session(key, policy, qualifier, signature);
        defer d.flush(s.handle);
        var b = command(0x149, &.{ index, index, s.handle }, password);
        b.sized(&value(serial));
        b.int(u16, 0);
        b.int(u16, 9);
        _ = try d.call(&b);
        b = command(0x16e, &.{s.handle}, null);
        b.sized(&try cpHash(key, serial));
        _ = try d.call(&b);
        try d.authorizeSession(s, policy, qualifier);
        b = command(0x137, &.{ index, index }, s.handle);
        b.sized(&value(serial));
        b.int(u16, 0);
        _ = try d.call(&b);
    }

    pub fn retire(d: *Device, key: apk.Key, state: Record, signature: []const u8) !void {
        if (!std.mem.eql(u8, &try d.anchor(key), &state.previous))
            return error.StaleBootState;
        const policy = try pairApproved(key, state);
        const s = try d.session(key, policy, pair_qualifier, signature);
        defer d.flush(s.handle);
        var b = command(0x149, &.{ pair_index, pair_index, s.handle }, password);
        b.sized(&state.previous);
        b.int(u16, 0);
        b.int(u16, 0);
        _ = try d.call(&b);
        b = command(0x17f, &.{s.handle}, null);
        var digest: [32]u8 = undefined;
        Sha256.hash(&state.pcr, &digest, .{});
        b.sized(&digest);
        pcrSelection(&b);
        _ = try d.call(&b);
        b = command(0x16e, &.{s.handle}, null);
        b.sized(&try pairCpHash(key, state));
        _ = try d.call(&b);
        try d.authorizeSession(s, policy, pair_qualifier);
        b = command(0x136, &.{ pair_index, pair_index }, s.handle);
        b.sized(&state.digest());
        _ = try d.call(&b);
        if (!std.mem.eql(u8, &try d.anchor(key), &state.anchor())) return error.StaleBootState;
    }
};

pub fn keyAt(io: std.Io, gpa: std.mem.Allocator, root: []const u8) !apk.Key {
    const protocol = try readFile(
        io,
        gpa,
        try gpa.print("{s}{s}/protocol", .{ root, metadata }),
        16,
    );
    if (!std.mem.eql(u8, protocol, "2\n")) return error.BadBootProtocol;
    return apk.parseKey(
        gpa,
        try readFile(io, gpa, try gpa.print("{s}{s}/signer.pub", .{ root, metadata }), 8192),
    );
}

fn readFile(io: std.Io, gpa: std.mem.Allocator, file: []const u8, limit: usize) ![]const u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, file, gpa, .limited(limit + 1));
}

pub const Journal = struct { record: Record, position: u1 };

pub fn bundle(key: apk.Key, raw: []const u8) !Record {
    if (raw.len != record_size + key.modulus.len) return error.BadBootState;
    const record = try Record.decode(raw[0..record_size]);
    const message = try pairMessage(key, record);
    try apk.verify(key, &message, raw[record_size..]);
    return record;
}

/// Select by protected state, never by a disk-side completion flag.
pub fn current(
    io: std.Io,
    gpa: std.mem.Allocator,
    key: apk.Key,
    directory: []const u8,
    anchor_value: [32]u8,
    release: [32]u8,
) !Journal {
    for (0..2) |i| {
        const file = try gpa.print("{s}/state.{d}", .{ directory, i });
        const raw = readFile(io, gpa, file, record_size + 512) catch |err| switch (err) {
            error.FileNotFound, error.StreamTooLong => continue,
            else => return err,
        };
        const record = bundle(key, raw) catch continue;
        if (!std.mem.eql(u8, &record.anchor(), &anchor_value)) continue;
        if (!record.allows(release)) return error.RollbackRefused;
        return .{ .record = record, .position = @intCast(i) };
    }
    return error.MissingBootState;
}

pub fn boot(io: std.Io, gpa: std.mem.Allocator, release: ?[32]u8, directory: []const u8) !bool {
    if (release == null) {
        std.Io.Dir.cwd().access(io, "/root" ++ metadata, .{}) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        return error.MissingSealedBootIdentity;
    }
    const key = try keyAt(io, gpa, "/root");
    var device = try Device.open(io);
    defer device.close();
    try device.disablePlatform();
    try measured(try device.pcr11());
    _ = try current(io, gpa, key, directory, try device.anchor(key), release.?);
    return true;
}

pub fn protected(io: std.Io, gpa: std.mem.Allocator, release: ?[32]u8, directory: []const u8) bool {
    const id = release orelse return false;
    const key = keyAt(io, gpa, "") catch return false;
    var device = Device.open(io) catch return false;
    defer device.close();
    const anchor_value = device.anchor(key) catch return false;
    measured(device.pcr11() catch return false) catch return false;
    _ = current(io, gpa, key, directory, anchor_value, id) catch return false;
    return true;
}

fn measured(pcr: [32]u8) !void {
    if (std.mem.eql(u8, &pcr, &@as([32]u8, @splat(0)))) return error.UnmeasuredBoot;
}

test "mandatory TPM boot refuses an unmeasured PCR" {
    try std.testing.expectError(error.UnmeasuredBoot, measured(@splat(0)));
    try measured(@splat(1));
}

/// Persist a complete signed bundle before the caller removes an entry or retires NV.
pub fn publish(
    io: std.Io,
    gpa: std.mem.Allocator,
    directory: []const u8,
    position: u1,
    raw: []const u8,
) !void {
    try std.Io.Dir.cwd().createDirPath(io, directory);
    const target = try gpa.print("{s}/state.{d}", .{ directory, position });
    const temp = try gpa.print("{s}.tmp", .{target});
    const file = try std.Io.Dir.cwd().createFile(io, temp, .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, raw);
    try file.sync(io);
    try std.Io.Dir.cwd().rename(temp, std.Io.Dir.cwd(), target, io);
    // Also persist creation/rename of the directory and its parent on ext4.
    if (@import("builtin").os.tag == .linux) std.os.linux.sync();
}

test "TPM values and parsers keep complete bounded binary records" {
    const t = std.testing;
    try t.expectEqual(@as(u64, 20), std.mem.readInt(u64, &value(20), .big));
    var r: Read = .{ .data = &.{ 0, 8, 1, 2 } };
    try t.expectError(error.BadTpmResponse, r.sized());
    var b = command(0x137, &.{ index, index }, password);
    try t.expectEqual(@as(usize, 31), b.len);
    b.sized(&value(20));
    b.int(u16, 0);
    try t.expectEqual(@as(usize, 43), b.len);
}

test "journal ignores a torn new record but refuses stale authorization and retired releases" {
    const t = std.testing;
    const io = t.io;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena.allocator());
    const gpa = arena.allocator();
    const dir = try gpa.print("{s}/journal", .{root});
    const key = try apk.parseKey(gpa, @embedFile("testdata/tpm-ab/signer.pub"));
    const raw = @embedFile("testdata/tpm-ab/ab.state") ++ @embedFile("testdata/tpm-ab/ab.sig");
    const record = try bundle(key, raw);
    try t.expectError(
        error.MissingBootState,
        current(io, gpa, key, dir, record.anchor(), record.retained),
    );
    try publish(io, gpa, dir, 0, raw);
    try tmp.dir.writeFile(io, .{ .sub_path = "journal/state.1", .data = raw[0..100] });
    const selected = try current(io, gpa, key, dir, record.anchor(), record.candidate);
    try t.expectEqual(@as(u1, 0), selected.position);
    try t.expectError(
        error.MissingBootState,
        current(io, gpa, key, dir, @splat(9), record.retained),
    );
    try t.expectError(
        error.RollbackRefused,
        current(io, gpa, key, dir, record.anchor(), @splat(9)),
    );
    try publish(io, gpa, dir, 1, raw);
    try t.expectEqualDeep(
        record,
        (try current(io, gpa, key, dir, record.anchor(), record.retained)).record,
    );
}

test "canonical policy hashes match real TPM trial sessions and signature tickets" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const key = try apk.parseKey(arena.allocator(), @embedFile("testdata/tpm/signer.pub"));
    const area = try public(key);
    try t.expectEqualSlices(u8, @embedFile("testdata/tpm/signer.name"), &name(area.slice()));
    try t.expectEqualSlices(
        u8,
        @embedFile("testdata/tpm/authorize.policy"),
        &try authorization(key),
    );
    inline for (.{ 10, 20 }) |serial| {
        const prefix = "testdata/tpm/" ++ std.fmt.comptimePrint("{d}", .{serial});
        try t.expectEqualSlices(u8, @embedFile(prefix ++ ".cp")[2..], &try cpHash(key, serial));
        const policy = try approved(key, serial);
        try t.expectEqualSlices(u8, @embedFile(prefix ++ ".policy"), &policy);
        var message: Bytes = .{};
        message.bytes(&policy);
        message.bytes(qualifier);
        try apk.verify(key, message.slice(), @embedFile(prefix ++ ".sig"));
        message.data[0] ^= 1;
        try t.expectError(
            error.BadSignature,
            apk.verify(key, message.slice(), @embedFile(prefix ++ ".sig")),
        );
    }
}

test "A/B policy and exact-pair verification match independent TPM trial fixtures" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const key = try apk.parseKey(arena.allocator(), @embedFile("testdata/tpm-ab/signer.pub"));
    const raw = @embedFile("testdata/tpm-ab/ab.state");
    const signature = @embedFile("testdata/tpm-ab/ab.sig");
    const record = try Record.decode(raw);
    const area = try public(key);
    try t.expectEqualSlices(u8, @embedFile("testdata/tpm-ab/signer.name"), &name(area.slice()));
    try t.expectEqualSlices(
        u8,
        @embedFile("testdata/tpm-ab/authorize.policy"),
        &try pairAuthorization(key),
    );
    try t.expectEqualSlices(
        u8,
        @embedFile("testdata/tpm-ab/ab.cp")[2..],
        &try pairCpHash(key, record),
    );
    try t.expectEqualSlices(
        u8,
        @embedFile("testdata/tpm-ab/ab.policy"),
        &try pairApproved(key, record),
    );
    for ([2][32]u8{ record.retained, record.candidate }) |release|
        try t.expectEqualDeep(
            record,
            try verifyRecord(key, raw, signature, record.anchor(), release),
        );
    try t.expectError(
        error.RollbackRefused,
        verifyRecord(key, raw, signature, record.anchor(), @splat(0)),
    );
    try t.expectError(
        error.StaleBootState,
        verifyRecord(key, raw, signature, record.previous, record.retained),
    );
    try t.expectError(
        error.BadSignature,
        verifyRecord(key, raw, signature[0..255], record.anchor(), record.retained),
    );
    for (16..raw.len) |i| {
        var changed = record.encode();
        changed[i] ^= 1;
        try t.expectError(
            error.BadSignature,
            verifyRecord(key, &changed, signature, record.anchor(), record.retained),
        );
    }
}
