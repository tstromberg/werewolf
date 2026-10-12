//! Host enrollment and canonical permit messages; private credentials stay here.
const std = @import("std");
const tpm = @import("tpm");
const apk = @import("apk");
const Steps = @import("progress.zig").Steps;
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub const Signer = struct { key: []const u8, public: []const u8 };

pub fn signer(io: Io, gpa: Allocator, steps: *Steps, dir: []const u8, kept: bool) !Signer {
    const key = try gpa.print("{s}/permit.key", .{dir});
    const public = try gpa.print("{s}/permit.pub", .{dir});
    if (kept) {
        for ([2][]const u8{ key, public }) |file| try Dir.cwd().access(io, file, .{});
    } else {
        const file = try Dir.cwd().createFile(io, key, .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        file.close(io);
        if (!(try steps.exec(&.{.{ .argv = &.{
            "openssl", "genrsa", "-out", key, "2048",
        } }}, .{})).ok) return steps.fail("creating the TPM permit signer failed");
        if (!(try steps.exec(&.{.{ .argv = &.{
            "openssl", "pkey", "-in", key, "-pubout", "-out", public,
        } }}, .{})).ok) return steps.fail("extracting the TPM permit public key failed");
    }
    _ = try apk.parseKey(gpa, try read(io, gpa, public, 8192));
    return .{ .key = key, .public = public };
}

pub fn factory(
    io: Io,
    gpa: Allocator,
    steps: *Steps,
    authority: Signer,
    dir: []const u8,
    slot: []const u8,
) ![]const u8 {
    const key = try apk.parseKey(gpa, try read(io, gpa, authority.public, 8192));
    var record: tpm.Record = .{
        .machine = undefined,
        .previous = @splat(0),
        .retained = try digestFile(io, gpa, try gpa.print("{s}/release.id", .{slot})),
        .candidate = undefined,
        .pcr = try digestFile(io, gpa, try gpa.print("{s}/pcr11", .{slot})),
    };
    try io.randomSecure(&record.machine);
    record.candidate = record.retained;
    const message = try gpa.print("{s}/factory.message", .{dir});
    const signature = try gpa.print("{s}/factory.sig", .{dir});
    try durable(io, message, &try tpm.pairMessage(key, record));
    if (!(try steps.exec(&.{.{ .argv = &.{
        "openssl", "dgst", "-sha256", "-sign", authority.key, "-out", signature, message,
    } }}, .{})).ok) return steps.fail("signing the factory boot pair failed");
    const bundle = try std.mem.concat(gpa, u8, &.{
        &record.encode(), try read(io, gpa, signature, 512),
    });
    _ = try tpm.bundle(key, bundle);
    const target = try gpa.print("{s}/factory.permit", .{dir});
    try durable(io, target, bundle);
    const registry = try gpa.print("{s}/records", .{dir});
    try Dir.cwd().createDirPath(io, registry);
    try durable(io, try gpa.print("{s}/{x}.permit", .{ registry, &record.anchor() }), bundle);
    try Dir.cwd().deleteFile(io, message);
    try Dir.cwd().deleteFile(io, signature);
    return target;
}

pub fn provision(
    io: Io,
    gpa: Allocator,
    authority: Signer,
    dir: []const u8,
    state: []const u8,
) !void {
    const key = try apk.parseKey(gpa, try read(io, gpa, authority.public, 8192));
    const initial = try tpm.bundle(
        key,
        try read(io, gpa, try gpa.print("{s}/factory.permit", .{dir}), 688),
    );
    const credentials = try gpa.print("{s}/credentials", .{dir});
    try Dir.cwd().createDir(io, credentials, .fromMode(0o700));
    var secrets: [2][32]u8 = undefined;
    for ([2][]const u8{ "owner.auth", "lockout.auth" }, &secrets) |name, *secret| {
        try io.randomSecure(secret);
        try durable(io, try gpa.print("{s}/{s}", .{ credentials, name }), secret);
    }
    try syncDir(io, credentials);
    try Dir.cwd().createDirPath(io, state);
    try Dir.cwd().setFilePermissions(io, state, .fromMode(0o700), .{});
    var nonce: [8]u8 = undefined;
    try io.randomSecure(&nonce);
    const socket = try gpa.print("/tmp/ww-enroll-{x}.sock", .{&nonce});
    const control = try gpa.print("{s}.ctrl", .{socket});
    var child = try std.process.spawn(io, .{
        .argv = &.{
            "swtpm",
            "socket",
            "--tpm2",
            "--tpmstate",
            try gpa.print("dir={s}", .{state}),
            "--ctrl",
            try gpa.print("type=unixio,path={s}", .{control}),
            "--server",
            try gpa.print("type=unixio,path={s}", .{socket}),
            "--flags",
            "not-need-init,startup-clear",
            "--terminate",
        },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer {
        if (child.id) |pid| std.posix.kill(pid, .KILL) catch {};
        child.kill(io);
        Dir.cwd().deleteFile(io, socket) catch {};
        Dir.cwd().deleteFile(io, control) catch {};
    }
    var connected: ?Io.net.Stream = null;
    const address = try Io.net.UnixAddress.init(socket);
    for (0..100) |_| {
        connected = address.connect(io) catch null;
        if (connected != null) break;
        try io.sleep(.fromMilliseconds(50), .awake);
    }
    const stream = connected orelse return error.TpmStartupFailed;
    {
        var device: tpm.Device = .{
            .io = io,
            .file = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = false } },
        };
        defer device.close();
        try device.provision(key, initial, secrets);
    }
    const ended = try child.wait(io);
    if (ended != .exited or ended.exited != 0) return error.TpmShutdownFailed;
    try durable(io, try gpa.print("{s}/enrolled", .{dir}), &initial.anchor());
}

/// The publisher supplies only registered hashes. Signature and transition checks run here.
pub fn permit(io: Io, gpa: Allocator, args: []const []const u8) !void {
    if (args.len != 7) return error.BadArguments;
    const key = try apk.parseKey(gpa, try read(io, gpa, args[0], 8192));
    const old = try tpm.bundle(key, try read(io, gpa, args[1], 688));
    const retained = try hex(args[2]);
    const candidate = try hex(args[3]);
    const pcr = try hex(args[4]);
    const next: tpm.Record = .{
        .machine = old.machine,
        .previous = old.anchor(),
        .retained = retained,
        .candidate = candidate,
        .pcr = pcr,
    };
    try old.transition(next, retained, pcr);
    try durable(io, args[5], &next.encode());
    try durable(io, args[6], &try tpm.pairMessage(key, next));
}

pub fn verify(io: Io, gpa: Allocator, args: []const []const u8) !void {
    if (args.len != 2) return error.BadArguments;
    const key = try apk.parseKey(gpa, try read(io, gpa, args[0], 8192));
    _ = try tpm.bundle(key, try read(io, gpa, args[1], 688));
}

pub fn hex(text: []const u8) ![32]u8 {
    if (text.len != 64) return error.BadDigest;
    var value: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&value, text);
    return value;
}

pub fn digestFile(io: Io, gpa: Allocator, file: []const u8) ![32]u8 {
    const raw = try read(io, gpa, file, 33);
    if (raw.len != 32) return error.BadDigest;
    return raw[0..32].*;
}

fn read(io: Io, gpa: Allocator, file: []const u8, max: usize) ![]const u8 {
    return Dir.cwd().readFileAlloc(io, file, gpa, .limited(max));
}

pub fn durable(io: Io, file: []const u8, data: []const u8) !void {
    const out = try Dir.cwd().createFile(io, file, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer out.close(io);
    try out.writeStreamingAll(io, data);
    try out.sync(io);
    try syncDir(io, std.fs.path.dirname(file) orelse ".");
}

fn syncDir(io: Io, path: []const u8) !void {
    const dir = try Dir.cwd().openDir(io, path, .{});
    defer dir.close(io);
    const file: Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    try file.sync(io);
}

test "publisher hashes must be complete SHA256 digests" {
    try std.testing.expectError(error.BadDigest, hex("ab"));
    try std.testing.expectEqual(@as([32]u8, @splat(0xab)), try hex(
        "abababababababababababababababababababababababababababababababab",
    ));
}
