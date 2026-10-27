//! Owner-approved image cache. Archives select a digest, never code or keys.
//! A pristine disk is recorded before a machine's first application boot.
const std = @import("std");
const howl = @import("howl.zig");
const native = @import("build.zig");
const secure = @import("local-secure.zig");
const bundle = @import("boot-image.zig");
const helper = @import("data-helper.zig");
const Io = std.Io;
const Dir = Io.Dir;
const A = std.mem.Allocator;

pub const Record = struct {
    version: u8 = 1,
    profile: secure.Profile,
    verity: @import("verity").Params,
    disk_sha256: ?[]const u8 = null,
};

pub fn directory(io: Io, a: A, image: []const u8) ![]const u8 {
    _ = try bundle.hex(image);
    return a.print("{s}/data-images/{s}", .{ try howl.dataDir(io, a), image });
}

pub fn read(io: Io, a: A, image: []const u8) !Record {
    const dir = try directory(io, a, image);
    const r = try std.json.parseFromSliceLeaky(Record, a, try Dir.cwd().readFileAlloc(
        io,
        try a.print("{s}/image.json", .{dir}),
        a,
        .limited(256 << 10),
    ), .{});
    if (r.version != 1 or !std.mem.eql(u8, image, &std.fmt.bytesToHex(r.verity.root, .lower)))
        return error.TransferImageCache;
    const root = try Dir.cwd().openFile(io, try a.print("{s}/root.erofs", .{dir}), .{});
    defer root.close(io);
    try @import("verity").verify(a, io, root, r.verity);
    return r;
}

/// Only called with a new, never booted disk, while holding secure.lock.
pub fn remember(io: Io, a: A, profile: secure.Profile, why: *howl.Why) !void {
    _ = try approve(io, a, profile, true, why);
}

pub fn approve(io: Io, a: A, profile: secure.Profile, pristine: bool, why: *howl.Why) !Record {
    const slot = if (profile.bundle) |request| blk: {
        _ = try bundle.verify(io, a, request, profile.spec.arch);
        break :blk try a.print("{s}/slot", .{request.directory});
    } else try a.print("{s}/slot", .{(try native.paths(a, profile.local orelse profile.spec)).out});
    // /verity is inside the authenticated stage0, never a guest-controlled path.
    const result = try std.process.run(a, io, .{
        .argv = &.{ "bsdtar", "-xOf", try a.print("{s}/stage0.zst", .{slot}), "verity" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    if (!result.term.success()) return error.TransferImageParameters;
    const verity = try @import("verity").Params.parse(result.stdout);
    const image = std.fmt.bytesToHex(verity.root, .lower);
    const dir = try directory(io, a, &image);
    try Dir.cwd().createDirPath(io, dir);
    try Dir.cwd().setFilePermissions(io, dir, .fromMode(0o700), .{});
    const lock = try Dir.cwd().createFile(io, try a.print("{s}/image.lock", .{dir}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer lock.close(io);
    try lock.lock(io, .exclusive);
    defer lock.unlock(io);
    if (read(io, a, &image)) |r| {
        if (!pristine or r.disk_sha256 != null) return r;
    } else |err| if (err != error.FileNotFound) return err;
    for ([_][]const u8{ "vmlinuz", "root.erofs" }) |name|
        try Dir.cwd().copyFile(try a.print("{s}/{s}", .{ slot, name }), Dir.cwd(), try a.print("{s}/{s}", .{ dir, name }), io, .{});
    try Dir.cwd().copyFile(profile.spec.boot_cert orelse return error.TransferImageCertificate, Dir.cwd(), try a.print("{s}/boot.crt", .{dir}), io, .{});
    var disk_hash: ?[]const u8 = null;
    if (pristine) {
        const disk = try a.print("{s}/disk.raw", .{dir});
        // No unsafe shared-image option: QEMU must acquire its storage lock.
        try howl.run(io, why, &.{ "qemu-img", "convert", "-O", "raw", profile.spec.disk_path.?, disk });
        try Dir.cwd().setFilePermissions(io, disk, .fromMode(0o600), .{});
        const f = try Dir.cwd().openFile(io, disk, .{});
        defer f.close(io);
        try f.sync(io);
        disk_hash = (try @import("prebuilt").hashFile(io, a, disk)).sha256;
    }
    var approved = profile;
    approved.spec.boot_cert = try a.print("{s}/boot.crt", .{dir});
    if (profile.spec.ipe_cert) |cert| {
        const path = try a.print("{s}/image.crt", .{dir});
        try Dir.cwd().copyFile(cert, .cwd(), path, io, .{});
        approved.spec.ipe_cert = path;
    }
    if (approved.bundle) |*request| {
        request.boot_certificate = approved.spec.boot_cert.?;
        request.image_certificate = approved.spec.ipe_cert orelse return error.TransferImageCertificate;
    }
    const r: Record = .{
        .profile = approved,
        .verity = verity,
        .disk_sha256 = disk_hash,
    };
    try bundle.durable(io, try a.print("{s}/image.json", .{dir}), try std.json.Stringify.valueAlloc(a, r, .{}));
    return r;
}

pub fn guest(io: Io, a: A, image: []const u8, r: Record, why: *howl.Why) !helper.Guest {
    const dir = try directory(io, a, image);
    const spec: native.Spec = .{ .form = "data-transfer-helper", .arch = r.profile.spec.arch };
    var steps = try @import("progress.zig").Steps.init(io, a, why, .{
        .command = "howl data transfer",
        .log = try a.print("{s}/helper-build.log", .{dir}),
        .first = .{ .name = "Preparing isolated storage helper", .short = "helper" },
    });
    const paths = try howl.buildHere(io, a, &steps, spec, .{ .transfer_helper = true });
    _ = try steps.finish();
    const cwd = try std.process.currentPathAlloc(io, a);
    return .{
        .arch = r.profile.spec.arch,
        .verity = r.verity,
        .kernel = try a.print("{s}/vmlinuz", .{dir}),
        .image = try a.print("{s}/root.erofs", .{dir}),
        .initramfs = try std.fs.path.resolveAlloc(a, &.{ cwd, paths.out, "helper.cpio.zst" }),
    };
}
