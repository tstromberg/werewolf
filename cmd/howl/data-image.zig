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
    var r = try std.json.parseFromSliceLeaky(Record, a, try Dir.cwd().readFileAlloc(
        io,
        try a.print("{s}/image.json", .{dir}),
        a,
        .limited(256 << 10),
    ), .{});
    if (r.version != 1 or !std.mem.eql(u8, image, &std.fmt.bytesToHex(r.verity.root, .lower)))
        return error.TransferImageCache;
    if (r.profile.configuration) |definition| r.profile.spec.form = definition.form;
    const root = try Dir.cwd().openFile(io, try a.print("{s}/root.erofs", .{dir}), .{});
    defer root.close(io);
    try @import("verity").verify(a, io, root, r.verity);
    return r;
}

/// Only called with a new, never booted disk, while holding secure.lock.
pub fn remember(io: Io, a: A, profile: secure.Profile, why: *howl.Why) !void {
    _ = try approve(io, a, profile, true, why);
}

/// The owner selects a published release through normal Howl trust, never a
/// URL or signer supplied by the archive. A different image is not a restore.
pub fn published(io: Io, a: A, form: []const u8, on: howl.Platform, arch: howl.Arch, version: ?[]const u8, expected: []const u8, why: *howl.Why) !Record {
    const request = try @import("download.zig").selected(io, a, form, on, arch, version, why);
    const m = (try bundle.verify(io, a, request, arch)).manifest;
    const verity = try parameters(io, a, try a.print("{s}/slot", .{request.directory}));
    if (!std.mem.eql(u8, expected, &std.fmt.bytesToHex(verity.root, .lower)))
        return error.TransferImage;
    return approve(io, a, .{
        .provider = on,
        .managed = if (m.configuration) |c| c.lima_managed else false,
        .imported = m.image.build,
        .bundle = request,
        .configuration = m.configuration,
        .spec = .{
            .form = m.form,
            .variants = m.variants,
            .arch = arch,
            .published = true,
            .boot_cert = request.boot_certificate,
            .ipe_cert = request.image_certificate,
            .boot_native = true,
            .tpm = true,
            .image_index = m.image.index,
            .ipe_updates = m.image.channel,
            .image_serial = m.image.serial,
            .update_port = (try std.Uri.parse(m.image.channel)).port,
        },
    }, false, why);
}

fn parameters(io: Io, a: A, slot: []const u8) !@import("verity").Params {
    // /verity is inside the authenticated stage0, never a guest-controlled path.
    const result = try std.process.run(a, io, .{
        .argv = &.{ "bsdtar", "-xOf", try a.print("{s}/stage0.zst", .{slot}), "verity" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    if (!result.term.success()) return error.TransferImageParameters;
    return @import("verity").Params.parse(result.stdout);
}

pub fn approve(io: Io, a: A, profile: secure.Profile, pristine: bool, why: *howl.Why) !Record {
    const slot = if (profile.bundle) |request| blk: {
        _ = try bundle.verify(io, a, request, profile.spec.arch);
        break :blk try a.print("{s}/slot", .{request.directory});
    } else try a.print("{s}/slot", .{(try native.paths(a, profile.local orelse profile.spec)).out});
    const verity = try parameters(io, a, slot);
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
    if (profile.spec.boot_cert) |cert| {
        try Dir.cwd().copyFile(cert, Dir.cwd(), try a.print("{s}/boot.crt", .{dir}), io, .{});
    } else if (profile.provider != .firecracker) return error.TransferImageCertificate;
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
    if (approved.configuration) |definition| approved.spec.form = definition.form;
    approved.data_image = try a.dupe(u8, &image);
    approved.spec.boot_cert = if (profile.spec.boot_cert != null) try a.print("{s}/boot.crt", .{dir}) else null;
    if (profile.spec.ipe_cert) |cert| {
        const path = try a.print("{s}/image.crt", .{dir});
        try Dir.cwd().copyFile(cert, .cwd(), path, io, .{});
        approved.spec.ipe_cert = path;
    }
    if (approved.bundle) |*request| {
        request.boot_certificate = approved.spec.boot_cert.?;
        request.image_certificate = approved.spec.ipe_cert orelse return error.TransferImageCertificate;
        const original = request.directory;
        const kept = try a.print("{s}/bundle", .{dir});
        for ([_][]const u8{ "boot.json", "boot.json.sig", "disk.img.zst" }) |name|
            try keepFile(io, a, original, kept, name);
        inline for (@import("prebuilt").names) |name|
            try keepFile(io, a, original, kept, try a.print("slot/{s}", .{name}));
        for ([_][]const u8{ "latest.json", "latest.json.sig" }) |name|
            try keepFile(io, a, original, kept, try a.print("prebuilt/{t}/{s}", .{ profile.spec.arch, name }));
        request.directory = kept;
    }
    const r: Record = .{
        .profile = approved,
        .verity = verity,
        .disk_sha256 = disk_hash,
    };
    try replaceRecord(io, a, try a.print("{s}/image.json", .{dir}), try std.json.Stringify.valueAlloc(a, r, .{}));
    return r;
}

/// Caller holds the image or machine lifecycle lock. Keep the old record
/// intact until its replacement and directory entry are durable.
pub fn replaceRecord(io: Io, a: A, path: []const u8, bytes: []const u8) !void {
    var random: [12]u8 = undefined;
    try io.randomSecure(&random);
    const temporary = try a.print("{s}.{s}.new", .{ path, std.fmt.bytesToHex(random, .lower) });
    defer Dir.cwd().deleteFile(io, temporary) catch {};
    try bundle.durable(io, temporary, bytes);
    try Dir.cwd().rename(temporary, .cwd(), path, io);
    var parent = try Dir.cwd().openDir(io, std.fs.path.dirname(path).?, .{});
    defer parent.close(io);
    try @import("data-transfer").install.syncDir(io, parent);
}

fn keepFile(io: Io, a: A, from: []const u8, to: []const u8, name: []const u8) !void {
    if (std.mem.eql(u8, from, to)) return;
    const path = try a.print("{s}/{s}", .{ to, name });
    try Dir.cwd().createDirPath(io, std.fs.path.dirname(path).?);
    try Dir.cwd().copyFile(try a.print("{s}/{s}", .{ from, name }), .cwd(), path, io, .{});
    const f = try Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    try f.sync(io);
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
