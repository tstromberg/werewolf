//! Rootless bootstrap boundary and bounded enrollment channel; no workload handover.
const std = @import("std");
const apk = @import("apk");
const tpm = @import("tpm");
const bootstrap = @import("bootstrap");

pub const challenge_tag = "WWCHAL01";
pub const ready_tag = "WWREADY1";
pub const capsule_tag = "WWCAPS01";
pub const done_tag = "WWDONE01";
pub const max_capsule = bootstrap.Bundle.size + 2 + 512;
pub const Mode = enum { fresh, recovery };

pub fn firmware(on: []const u8, setup: []const u8) !void {
    if (on.len != 5 or setup.len != 5 or on[4] != 1 or setup[4] != 0 or
        !validEfiAttrs(on[0..4]) or !validEfiAttrs(setup[0..4]))
        return error.UnenforcedSecureBoot;
}

fn validEfiAttrs(raw: *const [4]u8) bool {
    const attrs = std.mem.readInt(u32, raw, .little);
    return attrs == 6 or attrs == 7;
}

pub fn factory(key: apk.Key, raw: []const u8) !tpm.Record {
    const initial = try tpm.bundle(key, raw);
    try factoryRecord(initial);
    return initial;
}

fn factoryRecord(initial: tpm.Record) !void {
    if (!std.mem.eql(u8, &initial.previous, &@as([32]u8, @splat(0))) or
        !std.mem.eql(u8, &initial.retained, &initial.candidate)) return error.WrongFactoryBootState;
}

/// Mutable channel data cannot replace trust or context baked into the signed initramfs.
pub fn challenge(
    initial: tpm.Record,
    raw_factory: []const u8,
    pcr: [32]u8,
    raw: []const u8,
) !bootstrap.Challenge {
    if (raw.len != 128) return error.BadEnrollmentContext;
    const context: bootstrap.Challenge = .{
        .machine = raw[0..32].*,
        .factory = raw[32..64].*,
        .pcr = raw[64..96].*,
        .challenge = raw[96..128].*,
    };
    try context.check();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw_factory, &digest, .{});
    if (!std.mem.eql(u8, &context.machine, &initial.machine) or
        !std.mem.eql(u8, &context.factory, &digest)) return error.WrongFactoryBootState;
    if (!std.mem.eql(u8, &context.pcr, &pcr)) return error.WrongBootstrapMeasurement;
    return context;
}

pub fn readExact(io: std.Io, file: std.Io.File, bytes: []u8) !void {
    var at: usize = 0;
    while (at < bytes.len) {
        const n = try file.readStreaming(io, &.{bytes[at..]});
        if (n == 0) return error.EndOfStream;
        at += n;
    }
}

/// Returns only after secret buffers are wiped and the protected factory anchor is read back.
pub fn exchange(
    io: std.Io,
    file: std.Io.File,
    input: std.Io.File,
    output: std.Io.File,
    key: apk.Key,
    raw_factory: []const u8,
    mode: Mode,
) ![32]u8 {
    const initial = try factory(key, raw_factory);
    var device: bootstrap.Device = .{ .io = io, .file = file };
    defer std.crypto.secureZero(u8, &device.response);
    if (mode == .recovery) {
        var target: tpm.Device = .{ .io = io, .file = file };
        defer std.crypto.secureZero(u8, &target.response);
        _ = try target.incomplete(key);
    } else try device.fresh();
    _ = try bootstrap.policy(try device.pcr11());
    try output.writeStreamingAll(io, ready_tag);
    var tag: [8]u8 = undefined;
    try readExact(io, input, &tag);
    if (!std.mem.eql(u8, &tag, challenge_tag)) return error.BadEnrollmentFrame;
    var raw: [128]u8 = undefined;
    try readExact(io, input, &raw);
    const context = try challenge(initial, raw_factory, try device.pcr11(), &raw);
    var boot = if (mode == .recovery)
        try device.beginRecovery(context.pcr, key)
    else
        try device.begin(context.pcr);
    var active = true;
    defer if (active) boot.deinit();
    const quote = try boot.quote(context);
    try output.writeStreamingAll(io, "WWENROL1");
    for ([_][]const u8{
        boot.ek_public.slice(),     boot.ak_public.slice(),
        quote.attest[0..quote.len], &quote.signature,
    }) |field| {
        var length: [2]u8 = undefined;
        std.mem.writeInt(u16, &length, @intCast(field.len), .big);
        try output.writeStreamingAll(io, &length);
        try output.writeStreamingAll(io, field);
    }
    try readExact(io, input, &tag);
    if (!std.mem.eql(u8, &tag, capsule_tag)) return error.BadEnrollmentFrame;
    var length: [2]u8 = undefined;
    try readExact(io, input, &length);
    const size = std.mem.readInt(u16, &length, .big);
    if (size < bootstrap.Bundle.size + 2 + 256 or size > max_capsule)
        return error.BadEnrollmentCapsule;
    var capsule: [max_capsule]u8 = undefined;
    try readExact(io, input, capsule[0..size]);
    var credentials = try boot.receive(key, context, capsule[0..size]);
    defer std.crypto.secureZero(u8, &credentials);
    boot.deinit();
    active = false;
    var target: tpm.Device = .{ .io = io, .file = file };
    defer std.crypto.secureZero(u8, &target.response);
    if (mode == .recovery)
        try target.recover(key, initial, @ptrCast(&credentials))
    else
        try target.provision(key, initial, @ptrCast(&credentials));
    return target.anchor(key);
}

test "firmware enrollment requires exact enabled SecureBoot and disabled SetupMode" {
    const t = std.testing;
    const on = [_]u8{ 7, 0, 0, 0, 1 };
    const setup = [_]u8{ 7, 0, 0, 0, 0 };
    try firmware(&on, &setup);
    for (0..5) |n| {
        try t.expectError(error.UnenforcedSecureBoot, firmware(on[0..n], &setup));
        try t.expectError(error.UnenforcedSecureBoot, firmware(&on, setup[0..n]));
    }
    try t.expectError(error.UnenforcedSecureBoot, firmware(&setup, &setup));
    try t.expectError(error.UnenforcedSecureBoot, firmware(&on, &on));
    try t.expectError(error.UnenforcedSecureBoot, firmware(&on, &(setup ++ .{0})));
}

test "bootstrap context binds immutable factory, machine and actual measurement" {
    const t = std.testing;
    const initial: tpm.Record = .{
        .machine = @splat(1),
        .previous = @splat(0),
        .retained = @splat(2),
        .candidate = @splat(2),
        .pcr = @splat(3),
    };
    try factoryRecord(initial);
    var retired = initial;
    retired.previous[0] = 1;
    try t.expectError(error.WrongFactoryBootState, factoryRecord(retired));
    retired = initial;
    retired.candidate[0] = 3;
    try t.expectError(error.WrongFactoryBootState, factoryRecord(retired));
    const baked = "signed immutable factory fixture";
    var raw: [128]u8 = undefined;
    @memcpy(raw[0..32], &initial.machine);
    std.crypto.hash.sha2.Sha256.hash(baked, raw[32..64], .{});
    @memset(raw[64..96], 4);
    @memset(raw[96..128], 5);
    _ = try challenge(initial, baked, @splat(4), &raw);
    try t.expectError(error.WrongBootstrapMeasurement, challenge(initial, baked, @splat(3), &raw));
    try t.expectError(
        error.WrongFactoryBootState,
        challenge(initial, "other factory", @splat(4), &raw),
    );
    for (0..128) |n| try t.expectError(
        error.BadEnrollmentContext,
        challenge(initial, baked, @splat(4), raw[0..n]),
    );
    raw[0] ^= 1;
    try t.expectError(error.WrongFactoryBootState, challenge(initial, baked, @splat(4), &raw));
    raw[0] ^= 1;
    @memset(raw[96..128], 0);
    try t.expectError(error.BadEnrollmentContext, challenge(initial, baked, @splat(4), &raw));
}
