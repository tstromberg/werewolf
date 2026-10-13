//! Host attestation/capsule codec and independent integration probes.
const std = @import("std");
const bootstrap = @import("bootstrap");
const apk = @import("apk");
const tpm = @import("tpm");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len < 3) return error.BadArguments;
    if (std.mem.eql(u8, args[1], "policy") and args.len == 3) {
        const raw = try read(io, gpa, args[2], 32);
        if (raw.len != 32) return error.BadDigest;
        const p = try bootstrap.policy(raw[0..32].*);
        try std.Io.File.stdout().writeStreamingAll(io, &p.quote);
        try std.Io.File.stdout().writeStreamingAll(io, &p.activate);
        try std.Io.File.stdout().writeStreamingAll(io, &p.digest);
        return;
    }
    const raw = try read(io, gpa, args[2], 128);
    if (raw.len != 128) return error.BadEnrollmentContext;
    const context: bootstrap.Challenge = .{
        .machine = raw[0..32].*,
        .factory = raw[32..64].*,
        .pcr = raw[64..96].*,
        .challenge = raw[96..128].*,
    };
    if (std.mem.eql(u8, args[1], "guest-probe") and args.len == 6) {
        try guest(io, gpa, context, args[3], args[4], args[5]);
        return;
    }
    if (std.mem.eql(u8, args[1], "challenge") and args.len == 3) {
        try std.Io.File.stdout().writeStreamingAll(io, &try context.nonce());
        return;
    }
    if (std.mem.eql(u8, args[1], "check-capsule") and args.len == 9) {
        const ek = try apk.parseKey(gpa, try read(io, gpa, args[3], 1024));
        const ak = try bootstrap.attestationKey(try read(io, gpa, args[4], 512), context.pcr);
        const key = try read(io, gpa, args[5], 32);
        defer std.crypto.secureZero(u8, key);
        if (key.len != 32) return error.BadCredential;
        const signer = try apk.parseKey(gpa, try read(io, gpa, args[8], 1024));
        const bundle = try bootstrap.verifyCapsule(signer, context, try read(
            io,
            gpa,
            args[6],
            bootstrap.Bundle.size + 2 + 512,
        ));
        var credentials = try bootstrap.open(context, ak.name, ek, key[0..32], bundle.capsule);
        defer std.crypto.secureZero(u8, &credentials);
        const expected = try read(io, gpa, args[7], 64);
        defer std.crypto.secureZero(u8, expected);
        if (!std.crypto.timing_safe.eql(
            [64]u8,
            credentials,
            (if (expected.len == 64) expected[0..64].* else return error.BadCredential),
        ))
            return error.WrongCredential;
        return;
    }
    if ((!std.mem.eql(u8, args[1], "verify") or args.len != 8) and
        (!std.mem.eql(u8, args[1], "wrap") or args.len != 12)) return error.BadArguments;
    const ek = try apk.parseKey(gpa, try read(io, gpa, args[3], 1024));
    const parent = try bootstrap.endorsementKey(try read(io, gpa, args[4], 512), ek);
    const ak = try bootstrap.attestationKey(try read(io, gpa, args[5], 512), context.pcr);
    try bootstrap.verifyQuote(
        ak,
        parent,
        context,
        try read(io, gpa, args[6], 1024),
        try read(io, gpa, args[7], 262),
    );
    if (args.len == 8) return;
    const private = try read(io, gpa, args[8], 64);
    defer std.crypto.secureZero(u8, private);
    if (private.len != 64) return error.BadProvisioningCredential;
    const zero: [32]u8 = @splat(0);
    if (std.mem.eql(u8, private[0..32], &zero) or
        std.mem.eql(u8, private[32..64], &zero) or
        std.mem.eql(u8, private[0..32], private[32..64])) return error.BadProvisioningCredential;
    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    try io.randomSecure(&key);
    const bundle: bootstrap.Bundle = .{
        .credential = try bootstrap.makeCredential(io, ek, ak.name, &key),
        .capsule = try bootstrap.seal(io, context, ak.name, ek, &key, private[0..64]),
    };
    const signed = try sign(io, gpa, context, bundle, args[9], args[10], args[11]);
    const output = try std.Io.Dir.cwd().createFile(io, args[11], .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer output.close(io);
    try output.writeStreamingAll(io, signed);
    try output.sync(io);
}

fn read(io: std.Io, gpa: std.mem.Allocator, file: []const u8, limit: usize) ![]u8 {
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, file, gpa, .limited(limit + 1));
    if (raw.len > limit) return error.TooBig;
    return raw;
}

fn guest(
    io: std.Io,
    gpa: std.mem.Allocator,
    context: bootstrap.Challenge,
    endpoint: []const u8,
    signer: []const u8,
    permit: []const u8,
) !void {
    try context.check();
    const key = try apk.parseKey(gpa, try read(io, gpa, signer, 1024));
    const factory = try read(io, gpa, permit, 688);
    const initial = try tpm.bundle(key, factory);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(factory, &digest, .{});
    const zero: [32]u8 = @splat(0);
    if (!std.mem.eql(u8, &context.factory, &digest) or
        !std.mem.eql(u8, &context.machine, &initial.machine) or
        !std.mem.eql(u8, &initial.previous, &zero) or
        !std.mem.eql(u8, &initial.retained, &initial.candidate)) return error.WrongFactoryBootState;
    const file = if (std.mem.eql(u8, endpoint, "/dev/tpmrm0"))
        try std.Io.Dir.cwd().openFile(io, endpoint, .{ .mode = .read_write })
    else if (std.mem.startsWith(u8, endpoint, "unix:")) blk: {
        const address = try std.Io.net.UnixAddress.init(endpoint[5..]);
        const stream = try address.connect(io);
        break :blk std.Io.File{
            .handle = stream.socket.handle,
            .flags = .{ .nonblocking = false },
        };
    } else return error.BadTpmEndpoint;
    var device: bootstrap.Device = .{ .io = io, .file = file };
    defer device.close();
    var boot = try device.begin(context.pcr);
    var active = true;
    defer if (active) boot.deinit();
    const quote = try boot.quote(context);
    const out = std.Io.File.stdout();
    try out.writeStreamingAll(io, "WWENROL1");
    for ([_][]const u8{
        boot.ek_public.slice(),
        boot.ak_public.slice(),
        quote.attest[0..quote.len],
        &quote.signature,
    }) |field| {
        var length: [2]u8 = undefined;
        std.mem.writeInt(u16, &length, @intCast(field.len), .big);
        try out.writeStreamingAll(io, &length);
        try out.writeStreamingAll(io, field);
    }
    var capsule: [bootstrap.Bundle.size + 2 + 512 + 1]u8 = undefined;
    var got: usize = 0;
    while (got < capsule.len) {
        const n = std.Io.File.stdin().readStreaming(
            io,
            &.{capsule[got..]},
        ) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        got += n;
    }
    var credentials = try boot.receive(key, context, capsule[0..got]);
    defer std.crypto.secureZero(u8, &credentials);
    boot.deinit();
    active = false;
    var target: tpm.Device = .{ .io = io, .file = file };
    defer std.crypto.secureZero(u8, &target.response);
    try target.provision(key, initial, @ptrCast(&credentials));
    try out.writeStreamingAll(io, &try target.anchor(key));
}

fn sign(
    io: std.Io,
    gpa: std.mem.Allocator,
    challenge: bootstrap.Challenge,
    bundle: bootstrap.Bundle,
    private: []const u8,
    public: []const u8,
    target: []const u8,
) ![]const u8 {
    var nonce: [8]u8 = undefined;
    try io.randomSecure(&nonce);
    const message = try gpa.print(
        "{s}/.enroll-{x}.message",
        .{ std.fs.path.dirname(target) orelse ".", &nonce },
    );
    const signature = try gpa.print("{s}.sig", .{message});
    const file = try std.Io.Dir.cwd().createFile(
        io,
        message,
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    );
    defer std.Io.Dir.cwd().deleteFile(io, message) catch {};
    defer file.close(io);
    try file.writeStreamingAll(io, &try bootstrap.capsuleMessage(challenge, &bundle.encode()));
    const sig = try std.Io.Dir.cwd().createFile(
        io,
        signature,
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    );
    sig.close(io);
    defer std.Io.Dir.cwd().deleteFile(io, signature) catch {};
    const result = try std.process.run(gpa, io, .{
        .argv = &.{ "openssl", "dgst", "-sha256", "-sign", private, "-out", signature, message },
        .stdout_limit = .limited(8192),
        .stderr_limit = .limited(8192),
    });
    if (result.term != .exited or result.term.exited != 0) return error.SigningFailed;
    const key = try apk.parseKey(gpa, try read(io, gpa, public, 1024));
    const raw = try read(io, gpa, signature, 512);
    var length: [2]u8 = undefined;
    std.mem.writeInt(u16, &length, @intCast(raw.len), .big);
    const signed = try std.mem.concat(gpa, u8, &.{ &bundle.encode(), &length, raw });
    _ = try bootstrap.verifyCapsule(key, challenge, signed);
    return signed;
}
