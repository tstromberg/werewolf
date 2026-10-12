//! TPM 2.0 rollback floor: public reads and signed, monotonic NV writes.
const std = @import("std");
const apk = @import("apk");
const Sha256 = std.crypto.hash.sha2.Sha256;
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
    b.bytes(qualifier);
    var result: [32]u8 = undefined;
    Sha256.hash(b.slice(), &result, .{});
    return result;
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
        d.file.close(d.io);
    }

    fn call(d: *Device, b: *Bytes) !Read {
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

    pub fn disablePlatform(d: *Device) !void {
        if (try d.property(0x201) & 1 == 0) return;
        var b = command(0x121, &.{platform}, password);
        b.int(u32, platform);
        b.int(u8, 0);
        _ = try d.call(&b);
        if (try d.property(0x201) & 1 != 0) return error.TpmPlatformEnabled;
    }

    pub fn floor(d: *Device, key: apk.Key) !u64 {
        // Reset authority must remain outside the guest, including physical-presence commands.
        if (try d.property(0x200) & 0x105 != 0x105 or try d.property(0x201) & 1 != 0)
            return error.UnprotectedTpmHierarchy;
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

    pub fn check(d: *Device, key: apk.Key, serial: u64) !void {
        if (serial < try d.floor(key)) return error.RollbackRefused;
    }

    fn flush(d: *Device, handle: u32) void {
        var b = command(0x165, &.{handle}, null);
        _ = d.call(&b) catch {};
    }

    pub fn advance(d: *Device, key: apk.Key, serial: u64, signature: []const u8) !void {
        try d.check(key, serial);
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
        const policy = try approved(key, serial);
        var signed_data: Bytes = .{};
        signed_data.bytes(&policy);
        signed_data.bytes(qualifier);
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
        const session = try r.int(u32);
        defer d.flush(session);
        b = command(0x149, &.{ index, index, session }, password);
        b.sized(&value(serial));
        b.int(u16, 0);
        b.int(u16, 9);
        _ = try d.call(&b);
        b = command(0x16e, &.{session}, null);
        b.sized(&try cpHash(key, serial));
        _ = try d.call(&b);
        b = command(0x16a, &.{session}, null);
        b.sized(&policy);
        b.sized(qualifier);
        b.sized(&key_name);
        b.bytes(ticket.slice());
        _ = try d.call(&b);
        b = command(0x137, &.{ index, index }, session);
        b.sized(&value(serial));
        b.int(u16, 0);
        _ = try d.call(&b);
    }
};

pub const Enrollment = struct { key: apk.Key, serial: u64, signature: []const u8 };

pub fn enrollment(io: std.Io, gpa: std.mem.Allocator, root: []const u8) !?Enrollment {
    const dir = try gpa.print("{s}{s}", .{ root, metadata });
    const serial = std.Io.Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/serial", .{dir}),
        gpa,
        .limited(32),
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    const e: Enrollment = .{
        .key = try apk.parseKey(
            gpa,
            try std.Io.Dir.cwd().readFileAlloc(
                io,
                try gpa.print("{s}/signer.pub", .{dir}),
                gpa,
                .limited(8192),
            ),
        ),
        .serial = try std.fmt.parseUnsigned(u64, std.mem.trimEnd(u8, serial, "\n"), 10),
        .signature = try std.Io.Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/permit.sig", .{dir}),
            gpa,
            .limited(8192),
        ),
    };
    if (e.serial == 0) return error.BadTpmSerial;
    const policy = try approved(e.key, e.serial);
    const message = try std.mem.concat(gpa, u8, &.{ &policy, qualifier });
    try apk.verify(e.key, message, e.signature);
    return e;
}

pub fn boot(io: std.Io, gpa: std.mem.Allocator) !bool {
    const e = try enrollment(io, gpa, "/root") orelse return false;
    var device = try Device.open(io);
    defer device.close();
    try device.disablePlatform();
    try device.check(e.key, e.serial);
    return true;
}

pub fn commit(io: std.Io, gpa: std.mem.Allocator) !void {
    const e = try enrollment(io, gpa, "") orelse return;
    var device = try Device.open(io);
    defer device.close();
    try device.advance(e.key, e.serial, e.signature);
}

pub fn protected(io: std.Io, gpa: std.mem.Allocator) bool {
    const e = (enrollment(io, gpa, "") catch return false) orelse return false;
    var device = Device.open(io) catch return false;
    defer device.close();
    device.check(e.key, e.serial) catch return false;
    return true;
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
