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
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Record = struct {
    version: u8 = 1,
    profile: secure.Profile,
    verity: @import("verity").Params,
    kernel_sha256: ?[]const u8 = null,
    disk_sha256: ?[]const u8 = null,
};

fn frame(h: *Sha256, bytes: []const u8) void {
    var size: [8]u8 = undefined;
    std.mem.writeInt(u64, &size, bytes.len, .little);
    h.update(&size);
    h.update(bytes);
}

fn frameU64(h: *Sha256, n: u64) void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, n, .little);
    h.update(&raw);
}

fn frameOptional(h: *Sha256, v: ?[]const u8) void {
    if (v) |bytes| {
        h.update(&.{1});
        frame(h, bytes);
    } else {
        h.update(&.{0});
    }
}

/// Bind the approved image cache key to the verified root, kernel, signer
/// certificates, disabled protections, disk options, and deployment metadata.
pub fn cacheKey(
    io: Io,
    a: A,
    profile: secure.Profile,
    verity: @import("verity").Params,
    kernel_sha256: []const u8,
) ![64]u8 {
    var h = Sha256.init(.{});
    frame(&h, "werewolf-data-image/1");
    frameU64(&h, verity.data_blocks);
    frameU64(&h, verity.hash_start);
    h.update(&verity.salt);
    h.update(&verity.root);
    frame(&h, kernel_sha256);
    const s = profile.spec;
    frame(&h, if (profile.configuration) |d| d.form else s.form);
    frameU64(&h, s.variants.len);
    for (s.variants) |v| frame(&h, v);
    frame(&h, @tagName(s.arch));
    h.update(&.{
        @intFromBool(s.dev),
        @intFromBool(s.published),
        @intFromBool(s.boot_native),
        @intFromBool(s.tpm),
        @intFromBool(profile.managed),
    });
    for (std.enums.values(@import("cmdline").Protection)) |p|
        h.update(&.{@intFromBool(s.disabled.contains(p))});
    frameU64(&h, s.disk.size_mib);
    frameU64(&h, s.disk.args.len);
    for (s.disk.args) |arg| frame(&h, arg);
    frameU64(&h, s.image_index);
    frameOptional(&h, s.ipe_updates);
    frameOptional(&h, s.image_serial);
    if (s.update_port) |p| {
        h.update(&.{1});
        frameU64(&h, p);
    } else {
        h.update(&.{0});
    }
    if (s.boot_cert) |cert| {
        h.update(&.{1});
        frame(&h, (try @import("prebuilt").hashFile(io, a, cert)).sha256);
    } else {
        h.update(&.{0});
    }
    if (s.ipe_cert) |cert| {
        h.update(&.{1});
        frame(&h, (try @import("prebuilt").hashFile(io, a, cert)).sha256);
    } else {
        h.update(&.{0});
    }
    frameOptional(&h, profile.imported);
    frameOptional(&h, if (profile.bundle) |req| req.channel else null);
    frameOptional(
        &h,
        if (profile.configuration) |def|
            try std.json.Stringify.valueAlloc(a, def, .{})
        else
            null,
    );
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

pub fn directory(io: Io, a: A, key: []const u8) ![]const u8 {
    _ = try bundle.hex(key);
    return a.print("{s}/data-images/{s}", .{ try howl.dataDir(io, a), key });
}

pub fn read(io: Io, a: A, key: []const u8) !Record {
    const dir = try directory(io, a, key);
    var r = try std.json.parseFromSliceLeaky(Record, a, try Dir.cwd().readFileAlloc(
        io,
        try a.print("{s}/image.json", .{dir}),
        a,
        .limited(256 << 10),
    ), .{});
    const kernel_hash = r.kernel_sha256 orelse return error.TransferImageCache;
    if (r.version != 1 or !std.mem.eql(u8, key, r.profile.data_image orelse ""))
        return error.TransferImageCache;
    if (r.profile.configuration) |definition| r.profile.spec.form = definition.form;
    const expected_key = try cacheKey(io, a, r.profile, r.verity, kernel_hash);
    if (!std.mem.eql(u8, key, &expected_key)) return error.TransferImageCache;
    if (!std.mem.eql(
        u8,
        kernel_hash,
        (try @import("prebuilt").hashFile(io, a, try a.print("{s}/vmlinuz", .{dir}))).sha256,
    )) return error.TransferImageCache;
    const root = try Dir.cwd().openFile(io, try a.print("{s}/root.erofs", .{dir}), .{});
    defer root.close(io);
    try @import("verity").verify(a, io, root, r.verity);
    return r;
}

/// Resolve a new-machine archive's verity root digest to a single unambiguous
/// approved image record. Multiple distinct approved profiles sharing one root
/// filesystem fail closed and require explicit selection.
pub fn findByVerity(io: Io, a: A, verity_hex: []const u8, why: *howl.Why) !Record {
    _ = try bundle.hex(verity_hex);
    const base = try a.print("{s}/data-images", .{try howl.dataDir(io, a)});
    var root_dir = Dir.cwd().openDir(io, base, .{
        .iterate = true,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return err,
    };
    defer root_dir.close(io);
    var matched_key: ?[]const u8 = null;
    var it = root_dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        _ = bundle.hex(entry.name) catch continue;
        const json_bytes = root_dir.readFileAlloc(
            io,
            try a.print("{s}/image.json", .{entry.name}),
            a,
            .limited(256 << 10),
        ) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        const candidate = try std.json.parseFromSliceLeaky(Record, a, json_bytes, .{});
        if (!std.mem.eql(u8, verity_hex, &std.fmt.bytesToHex(candidate.verity.root, .lower)))
            continue;
        if (matched_key != null) return why.refuse(
            "multiple approved images share root digest {s}; select one with --with FORM " ++
                "--version SERIAL or create an empty destination first",
            .{verity_hex},
        );
        matched_key = try a.dupe(u8, entry.name);
    }
    const key = matched_key orelse return error.FileNotFound;
    return read(io, a, key);
}

/// Only called with a new, never booted disk, while holding secure.lock.
pub fn remember(io: Io, a: A, profile: secure.Profile, why: *howl.Why) !void {
    _ = try approve(io, a, profile, true, why);
}

/// The owner selects a published release through normal Howl trust, never a
/// URL or signer supplied by the archive. A different image is not a restore.
pub fn published(
    io: Io,
    a: A,
    form: []const u8,
    on: howl.Platform,
    arch: howl.Arch,
    version: ?[]const u8,
    expected: []const u8,
    why: *howl.Why,
) !Record {
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
    if (profile.spec.boot_cert == null and profile.provider != .firecracker)
        return error.TransferImageCertificate;
    const slot = if (profile.bundle) |request| blk: {
        _ = try bundle.verify(io, a, request, profile.spec.arch);
        break :blk try a.print("{s}/slot", .{request.directory});
    } else try a.print("{s}/slot", .{(try native.paths(a, profile.local orelse profile.spec)).out});
    const verity = try parameters(io, a, slot);
    const kernel_hash = (try @import("prebuilt").hashFile(
        io,
        a,
        try a.print("{s}/vmlinuz", .{slot}),
    )).sha256;
    const key = try cacheKey(io, a, profile, verity, kernel_hash);
    const dir = try directory(io, a, &key);
    try Dir.cwd().createDirPath(io, dir);
    try Dir.cwd().setFilePermissions(io, dir, .fromMode(0o700), .{});
    const lock = try Dir.cwd().createFile(io, try a.print("{s}/image.lock", .{dir}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer lock.close(io);
    try lock.lock(io, .exclusive);
    defer lock.unlock(io);
    if (read(io, a, &key)) |r| {
        if (!pristine or r.disk_sha256 != null) return r;
    } else |err| if (err != error.FileNotFound) return err;
    for ([_][]const u8{ "vmlinuz", "root.erofs" }) |name|
        try Dir.cwd().copyFile(
            try a.print("{s}/{s}", .{ slot, name }),
            Dir.cwd(),
            try a.print("{s}/{s}", .{ dir, name }),
            io,
            .{},
        );
    if (profile.spec.boot_cert) |cert| {
        try Dir.cwd().copyFile(cert, Dir.cwd(), try a.print("{s}/boot.crt", .{dir}), io, .{});
    }
    var disk_hash: ?[]const u8 = null;
    if (pristine) {
        const disk = try a.print("{s}/disk.raw", .{dir});
        // No unsafe shared-image option: QEMU must acquire its storage lock.
        try howl.run(
            io,
            why,
            &.{ "qemu-img", "convert", "-O", "raw", profile.spec.disk_path.?, disk },
        );
        try Dir.cwd().setFilePermissions(io, disk, .fromMode(0o600), .{});
        const f = try Dir.cwd().openFile(io, disk, .{});
        defer f.close(io);
        try f.sync(io);
        disk_hash = (try @import("prebuilt").hashFile(io, a, disk)).sha256;
    }
    var approved = profile;
    approved.spec = secure.scrubLocalSpec(approved.spec);
    approved.spec.disk_path = null;
    approved.local = if (approved.local) |local| secure.scrubLocalSpec(local) else null;
    if (approved.configuration) |definition| approved.spec.form = definition.form;
    approved.data_image = try a.dupe(u8, &image);
    approved.spec.boot_cert = if (profile.spec.boot_cert != null)
        try a.print("{s}/boot.crt", .{dir})
    else
        null;
    if (profile.spec.ipe_cert) |cert| {
        const path = try a.print("{s}/image.crt", .{dir});
        try Dir.cwd().copyFile(cert, .cwd(), path, io, .{});
        approved.spec.ipe_cert = path;
    }
    if (approved.bundle) |*request| {
        request.boot_certificate = approved.spec.boot_cert.?;
        request.image_certificate = approved.spec.ipe_cert orelse
            return error.TransferImageCertificate;
        const original = request.directory;
        const kept = try a.print("{s}/bundle", .{dir});
        for ([_][]const u8{ "boot.json", "boot.json.sig", "disk.img.zst" }) |name|
            try keepFile(io, a, original, kept, name);
        inline for (@import("prebuilt").names) |name|
            try keepFile(io, a, original, kept, try a.print("slot/{s}", .{name}));
        for ([_][]const u8{ "latest.json", "latest.json.sig" }) |name|
            try keepFile(
                io,
                a,
                original,
                kept,
                try a.print("prebuilt/{t}/{s}", .{ profile.spec.arch, name }),
            );
        request.directory = kept;
    }
    const r: Record = .{
        .profile = approved,
        .verity = verity,
        .kernel_sha256 = kernel_hash,
        .disk_sha256 = disk_hash,
    };
    try replaceRecord(
        io,
        a,
        try a.print("{s}/image.json", .{dir}),
        try std.json.Stringify.valueAlloc(a, r, .{}),
    );
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

pub fn guest(io: Io, a: A, key: []const u8, r: Record, why: *howl.Why) !helper.Guest {
    const dir = try directory(io, a, key);
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

test "cacheKey binds full deployment profile and findByVerity refuses ambiguous matches" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(t.io, ".", a);
    var env: std.process.Environ.Map = .init(a);
    try env.put("HOME", root);
    try env.put("XDG_DATA_HOME", try a.print("{s}/xdg", .{root}));
    howl.environ = &env;
    defer howl.environ = undefined;

    var block: [4096]u8 = @splat(0x41);
    try tmp.dir.writeFile(t.io, .{ .sub_path = "root.erofs", .data = &block });
    const erofs_file = try tmp.dir.openFile(t.io, "root.erofs", .{});
    defer erofs_file.close(t.io);
    const tree = try @import("verity").build(a, t.io, erofs_file);

    try tmp.dir.writeFile(t.io, .{ .sub_path = "vmlinuz", .data = "kernel-v1" });
    const kernel_hash = (try @import("prebuilt").hashFile(
        t.io,
        a,
        try a.print("{s}/vmlinuz", .{root}),
    )).sha256;
    try tmp.dir.writeFile(t.io, .{ .sub_path = "boot-a.crt", .data = "boot-cert-a" });
    try tmp.dir.writeFile(t.io, .{ .sub_path = "boot-a-copy.crt", .data = "boot-cert-a" });
    try tmp.dir.writeFile(t.io, .{ .sub_path = "boot-b.crt", .data = "boot-cert-b" });
    try tmp.dir.writeFile(t.io, .{ .sub_path = "ipe-a.crt", .data = "ipe-cert-a" });
    try tmp.dir.writeFile(t.io, .{ .sub_path = "ipe-b.crt", .data = "ipe-cert-b" });

    const base: secure.Profile = .{
        .provider = .qemu,
        .managed = false,
        .configuration = .{
            .form = "postgresql",
            .interface = .{ .files = &.{}, .settings = &.{} },
            .ports = &.{ 22, 5432 },
            .dhcp = true,
            .ssh = .files,
            .lima_managed = false,
        },
        .spec = .{
            .form = "postgresql",
            .arch = .aarch64,
            .boot_cert = try a.print("{s}/boot-a.crt", .{root}),
            .ipe_cert = try a.print("{s}/ipe-a.crt", .{root}),
            .boot_native = true,
            .tpm = true,
        },
    };
    const k0 = try cacheKey(t.io, a, base, tree.params, kernel_hash);

    var same_cert_other_path = base;
    same_cert_other_path.spec.boot_cert = try a.print("{s}/boot-a-copy.crt", .{root});
    try t.expectEqualSlices(
        u8,
        &k0,
        &try cacheKey(t.io, a, same_cert_other_path, tree.params, kernel_hash),
    );

    var diff_boot = base;
    diff_boot.spec.boot_cert = try a.print("{s}/boot-b.crt", .{root});
    const k_boot = try cacheKey(t.io, a, diff_boot, tree.params, kernel_hash);
    try t.expect(!std.mem.eql(u8, &k0, &k_boot));

    var diff_ipe = base;
    diff_ipe.spec.ipe_cert = try a.print("{s}/ipe-b.crt", .{root});
    try t.expect(!std.mem.eql(
        u8,
        &k0,
        &try cacheKey(t.io, a, diff_ipe, tree.params, kernel_hash),
    ));

    var diff_cfg = base;
    diff_cfg.configuration.?.ports = &.{22};
    try t.expect(!std.mem.eql(
        u8,
        &k0,
        &try cacheKey(t.io, a, diff_cfg, tree.params, kernel_hash),
    ));

    var diff_disabled = base;
    diff_disabled.spec.disabled.insert(.tpm);
    try t.expect(!std.mem.eql(
        u8,
        &k0,
        &try cacheKey(t.io, a, diff_disabled, tree.params, kernel_hash),
    ));

    var diff_disk = base;
    diff_disk.spec.disk.size_mib = 16384;
    try t.expect(!std.mem.eql(
        u8,
        &k0,
        &try cacheKey(t.io, a, diff_disk, tree.params, kernel_hash),
    ));

    var why: howl.Why = .{};
    const verity_hex = std.fmt.bytesToHex(tree.params.root, .lower);
    try t.expectError(error.FileNotFound, findByVerity(t.io, a, &verity_hex, &why));

    const writeEntry = struct {
        fn put(
            io: Io,
            alloc: A,
            src_root: []const u8,
            key: []const u8,
            prof: secure.Profile,
            ver: @import("verity").Params,
            kern: []const u8,
        ) !void {
            const d = try directory(io, alloc, key);
            try Dir.cwd().createDirPath(io, d);
            try Dir.cwd().copyFile(
                try alloc.print("{s}/root.erofs", .{src_root}),
                .cwd(),
                try alloc.print("{s}/root.erofs", .{d}),
                io,
                .{},
            );
            try Dir.cwd().copyFile(
                try alloc.print("{s}/vmlinuz", .{src_root}),
                .cwd(),
                try alloc.print("{s}/vmlinuz", .{d}),
                io,
                .{},
            );
            try Dir.cwd().copyFile(
                prof.spec.boot_cert.?,
                .cwd(),
                try alloc.print("{s}/boot.crt", .{d}),
                io,
                .{},
            );
            try Dir.cwd().copyFile(
                prof.spec.ipe_cert.?,
                .cwd(),
                try alloc.print("{s}/image.crt", .{d}),
                io,
                .{},
            );
            var stored = prof;
            stored.data_image = try alloc.dupe(u8, key);
            stored.spec.boot_cert = try alloc.print("{s}/boot.crt", .{d});
            stored.spec.ipe_cert = try alloc.print("{s}/image.crt", .{d});
            try replaceRecord(
                io,
                alloc,
                try alloc.print("{s}/image.json", .{d}),
                try std.json.Stringify.valueAlloc(alloc, Record{
                    .profile = stored,
                    .verity = ver,
                    .kernel_sha256 = kern,
                }, .{}),
            );
        }
    }.put;

    try writeEntry(t.io, a, root, &k0, base, tree.params, kernel_hash);
    const loaded = try findByVerity(t.io, a, &verity_hex, &why);
    try t.expectEqualStrings(&k0, loaded.profile.data_image.?);

    try writeEntry(t.io, a, root, &k_boot, diff_boot, tree.params, kernel_hash);
    try t.expectError(error.Refused, findByVerity(t.io, a, &verity_hex, &why));
    try t.expect(std.mem.find(u8, why.text, "multiple approved images share root digest") != null);
}
