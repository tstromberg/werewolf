//! Authenticated, machine-independent boot disks and their exact signed slot.
const std = @import("std");
const howl = @import("howl.zig");
const image = @import("prebuilt");
const tpm = @import("tpm");
const uki = @import("uki");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub const Request = struct {
    directory: []const u8,
    boot_certificate: []const u8,
    image_certificate: []const u8,
    channel: []const u8,
};
pub const format = "werewolf-boot/2";
pub const Manifest = struct {
    format: []const u8 = format,
    form: []const u8,
    image: image.Manifest,
    disk: image.Artifact,
    raw_size: u64,
    boot_certificate: []const u8,
    configuration: ?@import("boot-config.zig").Definition = null,
};
pub const Verified = struct { manifest: Manifest };
pub const Producer = struct {
    form: []const u8,
    arch: []const u8,
    disk: []const u8,
    slot: []const u8,
    head: []const u8,
    output: []const u8,
    image_key: []const u8,
    image_certificate: []const u8,
    boot_certificate: []const u8,
    channel: []const u8,
    configuration_form: ?[]const u8 = null,
};

/// hex parses a SHA-256 digest written as 64 hex digits.
pub fn hex(text: []const u8) ![32]u8 {
    if (text.len != 64) return error.BadDigest;
    var value: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&value, text);
    return value;
}

/// durable writes a new file, mode 0600, and syncs it and its directory.
pub fn durable(io: Io, file: []const u8, data: []const u8) !void {
    const out = try Dir.cwd().createFile(io, file, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer out.close(io);
    try out.writeStreamingAll(io, data);
    try out.sync(io);
    // Zig otherwise opens Linux directories with O_PATH, which cannot be fsynced.
    const dir = try Dir.cwd().openDir(
        io,
        std.fs.path.dirname(file) orelse ".",
        .{ .iterate = true },
    );
    defer dir.close(io);
    const handle: Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    try handle.sync(io);
}

fn read(io: Io, gpa: Allocator, path: []const u8, limit: usize) ![]u8 {
    const bytes = try Dir.cwd().readFileAlloc(io, path, gpa, .limited(limit + 1));
    if (bytes.len > limit) return error.ImageTooBig;
    return bytes;
}

fn capture(io: Io, gpa: Allocator, argv: []const []const u8) ![]u8 {
    const result = try std.process.run(gpa, io, .{
        .argv = argv,
        .stdout_limit = .limited(8192),
        .stderr_limit = .limited(8192),
    });
    if (result.term != .exited or result.term.exited != 0) return error.BootImageToolFailed;
    return result.stdout;
}

fn certificate(io: Io, gpa: Allocator, file: []const u8) ![32]u8 {
    const der = try capture(io, gpa, &.{ "openssl", "x509", "-in", file, "-outform", "DER" });
    _ = try tpm.firmware.certificateKey(der);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(der, &digest, .{});
    return digest;
}

fn key(io: Io, gpa: Allocator, cert: []const u8) !@import("apk").Key {
    return @import("apk").parseKey(gpa, try capture(
        io,
        gpa,
        &.{ "openssl", "x509", "-in", cert, "-pubkey", "-noout" },
    ));
}

pub fn check(m: Manifest, expected: image.Identity) !void {
    if (!std.mem.eql(u8, m.format, format) or
        !@import("form").isName(m.form)) return error.BadBootImageProfile;
    try image.check(m.image, expected);
    if (m.configuration) |definition| try @import("boot-config.zig").check(definition, m.form);
    if (m.image.files.@"uki.efi" == null) return error.BadBootImageProfile;
    if (m.disk.size == 0 or m.disk.size > 2 << 30 or m.raw_size < 512 << 20 or
        m.raw_size > 16 << 30 or m.raw_size % (1 << 20) != 0)
        return error.BadBootImageSize;
    _ = try hex(m.disk.sha256);
    _ = try hex(m.boot_certificate);
}

pub fn open(
    gpa: Allocator,
    signer: @import("apk").Key,
    data: []const u8,
    signature: []const u8,
    expected: image.Identity,
) !Manifest {
    if (data.len > image.max_manifest or signature.len > 512) return error.ImageTooBig;
    try @import("apk").verify(signer, data, signature);
    const m = try std.json.parseFromSliceLeaky(Manifest, gpa, data, .{});
    try check(m, expected);
    return m;
}

/// Authenticate metadata before a downloader uses its paths, sizes or identities.
pub fn admitHead(io: Io, gpa: Allocator, request: Request, arch: howl.Arch) !Manifest {
    const m = try open(
        gpa,
        try key(io, gpa, request.image_certificate),
        try read(io, gpa, try gpa.print("{s}/boot.json", .{request.directory}), image.max_manifest),
        try read(io, gpa, try gpa.print("{s}/boot.json.sig", .{request.directory}), 512),
        .{ .channel = request.channel, .arch = @tagName(arch) },
    );
    if (!std.mem.eql(
        u8,
        &try certificate(io, gpa, request.boot_certificate),
        &try hex(m.boot_certificate),
    )) return error.WrongBootCertificate;
    return m;
}

/// admitDeployment admits a head a machine of form may be deployed from:
/// form's own, with the definition it is configured by.
pub fn admitDeployment(
    io: Io,
    gpa: Allocator,
    request: Request,
    arch: howl.Arch,
    form: []const u8,
) !Manifest {
    const m = try admitHead(io, gpa, request, arch);
    if (!std.mem.eql(u8, m.form, form)) return error.WrongBootForm;
    if (m.configuration == null) return error.MissingDeploymentDefinition;
    return m;
}

pub fn verify(io: Io, gpa: Allocator, request: Request, arch: howl.Arch) !Verified {
    const m = try admitHead(io, gpa, request, arch);
    const head = try image.open(gpa, try key(io, gpa, request.image_certificate), try read(
        io,
        gpa,
        try gpa.print("{s}/prebuilt/{t}/latest.json", .{ request.directory, arch }),
        image.max_manifest,
    ), try read(
        io,
        gpa,
        try gpa.print("{s}/prebuilt/{t}/latest.json.sig", .{ request.directory, arch }),
        512,
    ), .{ .channel = request.channel, .arch = @tagName(arch) });
    const a = try std.json.Stringify.valueAlloc(gpa, m.image, .{});
    const b = try std.json.Stringify.valueAlloc(gpa, head, .{});
    if (!std.mem.eql(u8, a, b)) return error.ConflictingBootImageManifest;
    const slot = try gpa.print("{s}/slot", .{request.directory});
    inline for (image.names) |name| {
        const got = try image.hashFile(io, gpa, try gpa.print("{s}/{s}", .{ slot, name }));
        try image.matches(m.image.artifact(name).?, got.size, got.sha256);
    }
    const compressed = try image.hashFile(
        io,
        gpa,
        try gpa.print("{s}/disk.img.zst", .{request.directory}),
    );
    try image.matches(m.disk, compressed.size, compressed.sha256);
    const raw = try read(io, gpa, try gpa.print("{s}/uki.efi", .{slot}), 512 << 20);
    // The signed UKI must name the release the signed manifest names: the
    // channel and index stage0 holds to the TPM floor.
    const line = try uki.section(raw, ".cmdline") orelse return error.MissingBootIdentity;
    var bad: @import("cmdline").Failure = .{};
    const parsed = @import("cmdline").parse(std.mem.trimEnd(u8, line, "\x00"), &bad) orelse
        return error.BadBootIdentity;
    const channel = parsed.channel orelse return error.WrongBootIdentity;
    if (!parsed.secure or !parsed.native or parsed.index.? != m.image.index or
        !std.mem.eql(u8, &std.fmt.bytesToHex(channel, .lower), m.image.channel_id))
        return error.WrongBootIdentity;
    for ([_]struct { []const u8, image.Artifact }{
        .{ ".linux", m.image.files.vmlinuz }, .{ ".initrd", m.image.files.@"stage0.zst" },
    }) |part| {
        const bytes = try uki.section(raw, part[0]) orelse return error.MissingBootSection;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        try image.matches(part[1], bytes.len, &std.fmt.bytesToHex(digest, .lower));
    }
    _ = try capture(
        io,
        gpa,
        &.{
            "osslsigncode",
            "verify",
            "-CAfile",
            request.boot_certificate,
            "-in",
            try gpa.print("{s}/uki.efi", .{slot}),
        },
    );
    return .{ .manifest = m };
}

pub fn materialize(
    io: Io,
    gpa: Allocator,
    steps: *@import("progress.zig").Steps,
    request: Request,
    verified: Verified,
    output: []const u8,
) !void {
    const raw_size = verified.manifest.raw_size;
    try steps.enter(.{ .name = "Unpacking the authenticated boot disk", .short = "disk" });
    try unpack(io, try gpa.print("{s}/disk.img.zst", .{request.directory}), output, raw_size);
    const layout = try @import("gpt").layout(@intCast(raw_size >> 20), 256);
    const file = try Dir.cwd().openFile(io, output, .{});
    defer file.close(io);
    if (try file.length(io) != raw_size) return error.BadBootImageSize;
    var primary: [(2 + 32) * 512]u8 = undefined;
    var backup: [(32 + 1) * 512]u8 = undefined;
    @import("gpt").encode(layout, &primary, &backup);
    const bytes = try gpa.alloc(u8, primary.len);
    if (try file.readPositionalAll(io, bytes, 0) != primary.len or
        !std.mem.eql(u8, bytes, &primary)) return error.BadBootImageLayout;
    const tail = try gpa.alloc(u8, backup.len);
    if (try file.readPositionalAll(io, tail, raw_size - backup.len) != backup.len or
        !std.mem.eql(u8, tail, &backup)) return error.BadBootImageLayout;
    const work = std.fs.path.dirname(output).?;
    const loader = try gpa.print("{s}/verify-loader.efi", .{work});
    const installed = try gpa.print("{s}/verify-uki.efi", .{work});
    defer Dir.cwd().deleteFile(io, loader) catch {};
    defer Dir.cwd().deleteFile(io, installed) catch {};
    _ = try capture(io, gpa, &.{ "mcopy", "-i", try gpa.print(
        "{s}@@1048576",
        .{output},
    ), if (std.mem.eql(u8, verified.manifest.image.arch, "aarch64"))
        "::/EFI/BOOT/BOOTAA64.EFI"
    else
        "::/EFI/BOOT/BOOTX64.EFI", loader });
    _ = try capture(
        io,
        gpa,
        &.{
            "mcopy",
            "-i",
            try gpa.print("{s}@@1048576", .{output}),
            "::/werewolf/a/uki.efi",
            installed,
        },
    );
    const got = try image.hashFile(io, gpa, installed);
    try image.matches(verified.manifest.image.files.@"uki.efi".?, got.size, got.sha256);
    try loaderEntry(try capture(io, gpa, &.{
        "mtype",                             "-i", try gpa.print("{s}@@1048576", .{output}),
        "::/loader/entries/werewolf-a.conf",
    }));
    const loader_config = try capture(io, gpa, &.{
        "mtype", "-i", try gpa.print("{s}@@1048576", .{output}), "::/loader/loader.conf",
    });
    if (!std.mem.eql(
        u8,
        std.mem.trim(u8, loader_config, "\r\n"),
        "timeout 0\neditor no\nauto-entries no\nauto-firmware no",
    ))
        return error.UnprotectedLoaderConfiguration;
    _ = try capture(
        io,
        gpa,
        &.{ "osslsigncode", "verify", "-CAfile", request.boot_certificate, "-in", loader },
    );
}

fn loaderEntry(text: []const u8) !void {
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    var found = false;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (std.mem.startsWith(u8, line, "uki ")) {
            if (found or !std.mem.eql(u8, line, "uki /werewolf/a/uki.efi"))
                return error.UnprotectedLoaderEntry;
            found = true;
        } else if (!std.mem.startsWith(u8, line, "title ") and
            !std.mem.startsWith(u8, line, "sort-key ") and
            !std.mem.startsWith(u8, line, "version ")) return error.UnprotectedLoaderEntry;
    }
    if (!found) return error.UnprotectedLoaderEntry;
}

fn unpack(io: Io, input: []const u8, output: []const u8, limit: u64) !void {
    const file = try Dir.cwd().createFile(io, output, .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    errdefer Dir.cwd().deleteFile(io, output) catch {};
    var child = try std.process.spawn(io, .{
        .argv = &.{ "zstd", "-q", "-d", "-c", "-M512MB", input },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    defer child.kill(io);
    const stream = child.stdout.?;
    child.stdout = null;
    defer stream.close(io);
    var bytes: [64 << 10]u8 = undefined;
    var at: u64 = 0;
    while (true) {
        const count = stream.readStreaming(io, &.{&bytes}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (count == 0) break;
        if (count > limit - at) return error.BadBootImageSize;
        if (!std.mem.allEqual(u8, bytes[0..count], 0))
            try file.writePositionalAll(io, bytes[0..count], at);
        at += count;
    }
    const ended = try child.wait(io);
    if (ended != .exited or ended.exited != 0) return error.BootImageToolFailed;
    if (at != limit) return error.BadBootImageSize;
    try file.setLength(io, limit);
    try file.sync(io);
}

pub fn command(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    if (args.len == 3 and std.mem.eql(u8, args[0], "download")) {
        const provider = std.meta.stringToEnum(howl.Platform, args[2]) orelse
            return error.BadSecuredProvider;
        const request = try @import("download.zig").latest(
            io,
            gpa,
            args[1],
            provider,
            howl.hostArch() orelse return error.UnsupportedHostArch,
            why,
        );
        try Io.File.stdout().writeStreamingAll(
            io,
            try std.json.Stringify.valueAlloc(gpa, request, .{}),
        );
        return;
    }
    if (args.len == 7 and std.mem.eql(u8, args[0], "head")) {
        const arch = howl.archName(args[5]) orelse return error.WrongImageArch;
        const m = try admitDeployment(io, gpa, .{
            .directory = args[1],
            .boot_certificate = args[2],
            .image_certificate = args[3],
            .channel = args[4],
        }, arch, args[6]);
        try Io.File.stdout().writeStreamingAll(io, try std.json.Stringify.valueAlloc(gpa, m, .{}));
        return;
    }
    if (args.len == 2 and std.mem.eql(u8, args[0], "seal")) return seal(
        io,
        gpa,
        try std.json.parseFromSliceLeaky(Producer, gpa, try read(io, gpa, args[1], 64 << 10), .{}),
        why,
    );
    if ((args.len != 5 and args.len != 6) or !std.mem.eql(u8, args[0], "verify"))
        return error.BadArguments;
    const v = try verify(
        io,
        gpa,
        .{
            .directory = args[1],
            .boot_certificate = args[2],
            .image_certificate = args[3],
            .channel = args[4],
        },
        if (args.len == 6)
            howl.archName(args[5]) orelse return error.WrongImageArch
        else
            howl.hostArch() orelse return error.UnsupportedHostArch,
    );
    try Io.File.stdout().writeStreamingAll(io, try std.json.Stringify.valueAlloc(gpa, v, .{}));
}

/// seal makes p's built image a boot bundle: the slot, its signed head and
/// the compressed disk beside a boot.json the image key signs, which binds
/// the form, the disk and the boot certificate. `release build-protected`
/// (tools/release) seals werewolf's images with it, and howl the images it
/// builds with the user's own keys.
pub fn seal(io: Io, gpa: Allocator, p: Producer, why: *howl.Why) !void {
    const arch = howl.archName(p.arch) orelse return error.WrongImageArch;
    const published = @import("published.zig");
    const previous_arch = published.arch;
    published.arch = null;
    defer published.arch = previous_arch;
    const data = try read(
        io,
        gpa,
        try gpa.print("{s}/latest.json", .{p.head}),
        image.max_manifest,
    );
    const signed = try image.open(
        gpa,
        try key(io, gpa, p.image_certificate),
        data,
        try read(io, gpa, try gpa.print("{s}/latest.json.sig", .{p.head}), 512),
        .{ .channel = p.channel, .arch = p.arch },
    );
    try Dir.cwd().createDir(io, p.output, .fromMode(0o700));
    try Dir.cwd().createDir(io, try gpa.print("{s}/slot", .{p.output}), .fromMode(0o700));
    inline for (image.names) |name| try Dir.cwd().copyFile(
        try gpa.print("{s}/{s}", .{ p.slot, name }),
        Dir.cwd(),
        try gpa.print("{s}/slot/{s}", .{ p.output, name }),
        io,
        .{},
    );
    try Dir.cwd().copyFile(
        try gpa.print("{s}/latest.json", .{p.head}),
        Dir.cwd(),
        try gpa.print("{s}/latest.json", .{p.output}),
        io,
        .{},
    );
    try Dir.cwd().copyFile(
        try gpa.print("{s}/latest.json.sig", .{p.head}),
        Dir.cwd(),
        try gpa.print("{s}/latest.json.sig", .{p.output}),
        io,
        .{},
    );
    const disk = try gpa.print("{s}/disk.img.zst", .{p.output});
    try howl.run(io, why, &.{ "zstd", "-q", "-T0", p.disk, "-o", disk });
    const m: Manifest = .{
        .form = p.form,
        .configuration = try @import("boot-config.zig").derive(
            io,
            gpa,
            p.configuration_form orelse p.form,
            p.form,
            why,
        ),
        .image = signed,
        .disk = try image.hashFile(io, gpa, disk),
        .raw_size = (try Dir.cwd().statFile(io, p.disk, .{})).size,
        .boot_certificate = try gpa.dupe(
            u8,
            &std.fmt.bytesToHex(try certificate(io, gpa, p.boot_certificate), .lower),
        ),
    };
    try check(m, .{ .channel = p.channel, .arch = p.arch });
    const head = try gpa.print("{s}/boot.json", .{p.output});
    try durable(io, head, try std.json.Stringify.valueAlloc(gpa, m, .{}));
    try howl.run(
        io,
        why,
        &.{
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            p.image_key,
            "-out",
            try gpa.print("{s}/boot.json.sig", .{p.output}),
            head,
        },
    );
    const public = try gpa.print("{s}/prebuilt/{s}", .{ p.output, p.arch });
    try Dir.cwd().createDirPath(io, try gpa.print("{s}/{s}", .{ public, signed.build }));
    for ([_][]const u8{ "latest.json", "latest.json.sig" }) |name|
        try Dir.cwd().copyFile(
            try gpa.print("{s}/{s}", .{ p.head, name }),
            Dir.cwd(),
            try gpa.print("{s}/{s}", .{ public, name }),
            io,
            .{},
        );
    inline for (image.names) |name| try Dir.cwd().copyFile(
        try gpa.print("{s}/{s}", .{ p.slot, name }),
        Dir.cwd(),
        try gpa.print("{s}/{s}/{s}", .{ public, signed.build, name }),
        io,
        .{},
    );
    _ = try verify(
        io,
        gpa,
        .{
            .directory = p.output,
            .boot_certificate = p.boot_certificate,
            .image_certificate = p.image_certificate,
            .channel = p.channel,
        },
        arch,
    );
}

test "boot entries cannot add unsigned options or select another executable" {
    const t = std.testing;
    try loaderEntry("title werewolf a\nuki /werewolf/a/uki.efi\n");
    for ([_][]const u8{
        "uki /werewolf/a/uki.efi\noptions werewolf.disable=tpm\n",
        "efi /werewolf/a/uki.efi\n",
        "uki /other.efi\n",
        "uki /werewolf/a/uki.efi\nuki /werewolf/a/uki.efi\n",
    }) |bad| try t.expectError(error.UnprotectedLoaderEntry, loaderEntry(bad));
}

test "disk decompression enforces exact size and removes invalid partial output" {
    const t = std.testing;
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(t.io, ".", t.allocator);
    defer t.allocator.free(root);
    try tmp.dir.writeFile(t.io, .{ .sub_path = "raw", .data = "bounded disk" });
    const raw = try std.fs.path.join(t.allocator, &.{ root, "raw" });
    defer t.allocator.free(raw);
    const compressed = try std.fs.path.join(t.allocator, &.{ root, "raw.zst" });
    defer t.allocator.free(compressed);
    const output = try std.fs.path.join(t.allocator, &.{ root, "disk" });
    defer t.allocator.free(output);
    const result = try std.process.run(t.allocator, t.io, .{
        .argv = &.{ "zstd", "-q", raw, "-o", compressed },
    });
    defer t.allocator.free(result.stdout);
    defer t.allocator.free(result.stderr);
    try t.expect(result.term == .exited and result.term.exited == 0);
    try unpack(t.io, compressed, output, 12);
    const bytes = try tmp.dir.readFileAlloc(t.io, "disk", t.allocator, .limited(13));
    defer t.allocator.free(bytes);
    try t.expectEqualStrings("bounded disk", bytes);
    try t.expectError(error.BadBootImageSize, unpack(t.io, compressed, output, 4));
    try t.expectError(error.FileNotFound, tmp.dir.access(t.io, "disk", .{}));
    try t.expectError(error.BadBootImageSize, unpack(t.io, compressed, output, 20));
    try t.expectError(error.FileNotFound, tmp.dir.access(t.io, "disk", .{}));
}

test "portable boot profiles require signed IPE, a UKI and bounded disks" {
    const t = std.testing;
    const zero = &@as([64]u8, @splat('0'));
    var files: image.Files = undefined;
    inline for (image.names) |name| @field(files, name) = .{ .size = 1, .sha256 = zero };
    const build = image.buildId(files);
    const identity: image.Identity = .{
        .channel = "https://example.test/playground",
        .arch = "aarch64",
    };
    const slot_image: image.Manifest = .{
        .format = image.format,
        .channel = identity.channel,
        .arch = identity.arch,
        .serial = "20261013T000000Z",
        .build = &build,
        .ipe = true,
        .root_hash = zero,
        .kernel = "6.18-test",
        .packages = &.{.{ .name = "init", .origin = "init", .version = "1" }},
        .channel_id = zero,
        .index = 1,
        .files = files,
    };
    const valid: Manifest = .{
        .form = "playground",
        .image = slot_image,
        .disk = .{ .size = 1, .sha256 = zero },
        .raw_size = 8 << 30,
        .boot_certificate = zero,
    };
    try check(valid, identity);
    var bad = valid;
    bad.image.ipe = false;
    try t.expectError(error.NotAnIpeImage, check(bad, identity));
    bad = valid;
    bad.image.files.@"uki.efi" = null;
    bad.image.build = &image.buildId(bad.image.files);
    try t.expectError(error.BadBootImageProfile, check(bad, identity));
    bad = valid;
    bad.raw_size = 32 << 30;
    try t.expectError(error.BadBootImageSize, check(bad, identity));
    bad = valid;
    bad.form = "../foreign";
    try t.expectError(error.BadBootImageProfile, check(bad, identity));
    try t.expectError(
        error.WrongImageChannel,
        check(valid, .{ .channel = "https://foreign.test", .arch = identity.arch }),
    );
}

test "durable files are exclusive and private" {
    const t = std.testing;
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(t.io, ".", t.allocator);
    defer t.allocator.free(root);
    const file = try std.fs.path.join(t.allocator, &.{ root, "record" });
    defer t.allocator.free(file);
    try durable(t.io, file, "kept");
    try t.expectError(error.PathAlreadyExists, durable(t.io, file, "again"));
    const st = try tmp.dir.statFile(t.io, "record", .{});
    try t.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);
}

/// Fixture signs boot profiles for verify's refusals. Its keys come from
/// openssl: Zig has no RSA signer.
const Fixture = struct {
    io: Io,
    gpa: Allocator,
    root: []const u8,
    arch: howl.Arch,
    channel: []const u8,
    manifest: std.json.Value,

    fn init(io: Io, gpa: Allocator, root: []const u8) !Fixture {
        var f: Fixture = .{
            .io = io,
            .gpa = gpa,
            .root = root,
            .arch = howl.hostArch() orelse return error.SkipZigTest,
            .channel = undefined,
            .manifest = undefined,
        };
        for ([_][]const u8{ "vendor", "foreign" }) |name| try f.keypair(name, 2048);
        const der = try capture(io, gpa, &.{
            "openssl", "x509", "-in", try f.path("vendor.crt"), "-outform", "DER",
        });
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(der, &digest, .{});
        const text = try Dir.cwd().readFileAlloc(
            io,
            "lib/testdata/prebuilt/image.json",
            gpa,
            .limited(64 << 10),
        );
        var signed = try std.json.parseFromSliceLeaky(std.json.Value, gpa, text, .{});
        try signed.object.put(gpa, "arch", .{ .string = @tagName(f.arch) });
        const files = &signed.object.getPtr("files").?.object;
        try files.put(
            gpa,
            "uki.efi",
            try artifactValue(gpa, .{ .size = 1, .sha256 = &@as([64]u8, @splat('1')) }),
        );
        try signed.object.put(gpa, "build", .{ .string = try buildOf(gpa, signed) });
        f.channel = signed.object.get("channel").?.string;
        var m: std.json.ObjectMap = .empty;
        try m.put(gpa, "format", .{ .string = format });
        try m.put(gpa, "form", .{ .string = "playground" });
        try m.put(gpa, "image", signed);
        try m.put(
            gpa,
            "disk",
            try artifactValue(gpa, .{ .size = 1, .sha256 = &@as([64]u8, @splat('0')) }),
        );
        try m.put(gpa, "raw_size", .{ .integer = 8 << 30 });
        try m.put(gpa, "boot_certificate", .{
            .string = try gpa.dupe(u8, &std.fmt.bytesToHex(digest, .lower)),
        });
        f.manifest = .{ .object = m };
        return f;
    }

    fn path(f: *const Fixture, name: []const u8) ![]const u8 {
        return f.gpa.print("{s}/{s}", .{ f.root, name });
    }

    fn openssl(f: *const Fixture, argv: []const []const u8) !void {
        const result = try std.process.run(f.gpa, f.io, .{
            .argv = argv,
            .stdout_limit = .limited(1 << 20),
            .stderr_limit = .limited(1 << 20),
        });
        if (result.term != .exited or result.term.exited != 0) return error.OpensslFailed;
    }

    fn keypair(f: *const Fixture, name: []const u8, bits: u16) !void {
        const private = try f.path(try f.gpa.print("{s}.key", .{name}));
        const cert = try f.path(try f.gpa.print("{s}.crt", .{name}));
        try f.openssl(&.{
            "openssl", "req",   "-x509", "-newkey", try f.gpa.print("rsa:{d}", .{bits}),
            "-nodes",  "-days", "1",     "-subj",   "/CN=boot-image-test",
            "-keyout", private, "-out",  cert,
        });
    }

    fn sign(f: *const Fixture, file: []const u8, signer: []const u8) !void {
        const private = try f.path(try f.gpa.print("{s}.key", .{signer}));
        const out = try f.gpa.print("{s}.sig", .{file});
        try f.openssl(&.{ "openssl", "dgst", "-sha256", "-sign", private, "-out", out, file });
    }

    /// invoke signs m as boot.json, then verifies it as a download would,
    /// trusting the image certificate trust.crt.
    fn invoke(f: *const Fixture, m: std.json.Value, o: struct {
        signer: []const u8 = "vendor",
        mutate: bool = false,
        trust: []const u8 = "vendor",
    }) !Verified {
        const head = try f.path("boot.json");
        const data = try std.json.Stringify.valueAlloc(f.gpa, m, .{});
        try Dir.cwd().writeFile(f.io, .{ .sub_path = head, .data = data });
        try f.sign(head, o.signer);
        if (o.mutate) try Dir.cwd().writeFile(f.io, .{
            .sub_path = head,
            .data = try f.gpa.print("{s} ", .{data}),
        });
        return verify(f.io, f.gpa, .{
            .directory = f.root,
            .boot_certificate = try f.path("vendor.crt"),
            .image_certificate = try f.path(try f.gpa.print("{s}.crt", .{o.trust})),
            .channel = f.channel,
        }, f.arch);
    }
};

fn artifactValue(gpa: Allocator, a: image.Artifact) !std.json.Value {
    var o: std.json.ObjectMap = .empty;
    try o.put(gpa, "size", .{ .integer = @intCast(a.size) });
    try o.put(gpa, "sha256", .{ .string = a.sha256 });
    return .{ .object = o };
}

fn buildOf(gpa: Allocator, signed: std.json.Value) ![]const u8 {
    const files = try std.json.parseFromValueLeaky(
        image.Files,
        gpa,
        signed.object.get("files").?,
        .{},
    );
    return gpa.dupe(u8, &image.buildId(files));
}

/// pe is a minimal PE32+ image holding sections, as tools/uki.zig reads one.
fn pe(gpa: Allocator, machine: u16, sections: []const [2][]const u8) ![]u8 {
    const coff = 0x40 + 4;
    const opt = coff + 20;
    const start = std.mem.alignForward(usize, opt + 112 + 40 * sections.len, 512);
    var size = start;
    for (sections) |s| size += s[1].len;
    const out = try gpa.alloc(u8, size);
    @memset(out, 0);
    @memcpy(out[0..2], "MZ");
    std.mem.writeInt(u32, out[0x3c..][0..4], 0x40, .little);
    @memcpy(out[coff - 4 ..][0..4], "PE\x00\x00");
    std.mem.writeInt(u16, out[coff..][0..2], machine, .little);
    std.mem.writeInt(u16, out[coff + 2 ..][0..2], @intCast(sections.len), .little);
    std.mem.writeInt(u16, out[coff + 16 ..][0..2], 112, .little);
    std.mem.writeInt(u16, out[coff + 18 ..][0..2], 0x22, .little);
    std.mem.writeInt(u16, out[opt..][0..2], 0x20b, .little);
    std.mem.writeInt(u32, out[opt + 32 ..][0..4], 512, .little);
    std.mem.writeInt(u32, out[opt + 36 ..][0..4], 512, .little);
    var at: u32 = @intCast(start);
    for (sections, 0..) |s, i| {
        const h = opt + 112 + 40 * i;
        const len: u32 = @intCast(s[1].len);
        @memcpy(out[h..][0..s[0].len], s[0]);
        for ([_]struct { usize, u32 }{
            .{ 8, len }, .{ 12, at }, .{ 16, len }, .{ 20, at }, .{ 36, 0x40000040 },
        }) |field| std.mem.writeInt(u32, out[h + field[0] ..][0..4], field[1], .little);
        @memcpy(out[at..][0..len], s[1]);
        at += len;
    }
    return out;
}

test "boot profiles reach the artifact gate only under the vendor's signature" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const f = try Fixture.init(t.io, gpa, try tmp.dir.realPathFileAlloc(t.io, ".", gpa));
    try t.expectError(error.FileNotFound, f.invoke(f.manifest, .{}));
    // An RSA-4096 signature is the largest a head may carry.
    try f.keypair("big", 4096);
    try t.expectError(error.FileNotFound, f.invoke(f.manifest, .{
        .signer = "big",
        .trust = "big",
    }));
    try t.expectEqual(512, (try tmp.dir.statFile(t.io, "boot.json.sig", .{})).size);
    try t.expectError(error.BadSignature, f.invoke(f.manifest, .{ .signer = "foreign" }));
    try t.expectError(error.BadSignature, f.invoke(f.manifest, .{ .mutate = true }));
}

test "signed weak profiles and unknown fields cannot pass admission" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const f = try Fixture.init(t.io, gpa, try tmp.dir.realPathFileAlloc(t.io, ".", gpa));
    const original = try std.json.Stringify.valueAlloc(gpa, f.manifest, .{});
    for ([_]struct { []const []const u8, std.json.Value, anyerror }{
        .{ &.{"format"}, .{ .string = "werewolf-boot/1" }, error.BadBootImageProfile },
        .{ &.{ "image", "format" }, .{ .string = "werewolf-image/1" }, error.NotAnIpeImage },
        .{ &.{ "image", "ipe" }, .{ .bool = false }, error.NotAnIpeImage },
        .{
            &.{ "image", "channel_id" },
            .{ .string = &@as([63]u8, @splat('0')) },
            error.BadImageRelease,
        },
        .{
            &.{ "image", "channel_id" },
            .{ .string = &@as([64]u8, @splat('A')) },
            error.BadImageRelease,
        },
        .{ &.{ "image", "index" }, .{ .integer = 0 }, error.BadImageRelease },
        .{ &.{"raw_size"}, .{ .integer = 32 << 30 }, error.BadBootImageSize },
        .{ &.{ "disk", "size" }, .{ .integer = 3 << 30 }, error.BadBootImageSize },
        .{ &.{"form"}, .{ .string = "../foreign" }, error.BadBootImageProfile },
        .{
            &.{"boot_certificate"},
            .{ .string = &@as([64]u8, @splat('0')) },
            error.WrongBootCertificate,
        },
        .{
            &.{ "image", "channel" },
            .{ .string = "https://foreign.test/shop" },
            error.WrongImageChannel,
        },
        .{ &.{"allow_insecure"}, .{ .bool = true }, error.UnknownField },
        // Protocol v2's permit endpoint, PCR 11 and boot context are no longer fields.
        .{ &.{"permit_host"}, .{ .string = "192.168.5.2" }, error.UnknownField },
        .{ &.{"permit_port"}, .{ .integer = 9443 }, error.UnknownField },
        .{ &.{"pcr11"}, .{ .string = &@as([64]u8, @splat('1')) }, error.UnknownField },
        .{
            &.{ "image", "boot_context" },
            .{ .string = &@as([64]u8, @splat('0')) },
            error.UnknownField,
        },
    }) |case| {
        const fields, const value, const reason = case;
        var changed = try std.json.parseFromSliceLeaky(std.json.Value, gpa, original, .{});
        var cursor = &changed;
        for (fields[0 .. fields.len - 1]) |name| cursor = cursor.object.getPtr(name).?;
        try cursor.object.put(gpa, fields[fields.len - 1], value);
        t.expectError(reason, f.invoke(changed, .{})) catch |err| {
            std.debug.print("{s}\n", .{fields[fields.len - 1]});
            return err;
        };
    }
}

test "the signed UKI must name the manifest's channel and index" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var f = try Fixture.init(t.io, gpa, try tmp.dir.realPathFileAlloc(t.io, ".", gpa));
    const signed = f.manifest.object.getPtr("image").?;
    const channel_id = signed.object.get("channel_id").?.string;
    const index: u64 = @intCast(signed.object.get("index").?.integer);
    const native = "werewolf.native=1 werewolf.secure=1 " ++
        "werewolf.slots=57e1f000-77e2-4b0f-8a3c-0000000000a0 werewolf.esp=57E1-F000";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("https://foreign.test/shop", &digest, .{});
    const foreign = std.fmt.bytesToHex(digest, .lower);
    const head = try gpa.print("prebuilt/{t}", .{f.arch});
    try tmp.dir.createDirPath(t.io, "slot");
    try tmp.dir.createDirPath(t.io, head);
    const disk = "compressed-disk-fixture";
    try tmp.dir.writeFile(t.io, .{ .sub_path = "disk.img.zst", .data = disk });
    try f.manifest.object.put(gpa, "disk", try artifactValue(gpa, try image.hashBytes(gpa, disk)));
    const release = " werewolf.channel={s} werewolf.index={d}";
    for ([_]struct { ?[]const u8, anyerror }{
        // The identity holds and the sections match; the unsigned PE then fails Authenticode.
        .{ try gpa.print(native ++ release, .{ channel_id, index }), error.BootImageToolFailed },
        .{ try gpa.print(native ++ release, .{ &foreign, index }), error.WrongBootIdentity },
        .{ try gpa.print(native ++ release, .{ channel_id, index + 1 }), error.WrongBootIdentity },
        .{ native, error.WrongBootIdentity },
        .{
            native ++ " werewolf.tpm=2 werewolf.release=" ++ &@as([64]u8, @splat('1')),
            error.BadBootIdentity,
        },
        .{ null, error.MissingBootIdentity },
    }) |case| {
        const line, const reason = case;
        var payloads: [image.names.len][]const u8 = undefined;
        for (image.names[0 .. payloads.len - 1], payloads[0 .. payloads.len - 1]) |name, *p|
            p.* = try gpa.print("fixture:{s}", .{name});
        var sections: std.ArrayList([2][]const u8) = .empty;
        try sections.appendSlice(
            gpa,
            &.{ .{ ".linux", payloads[0] }, .{ ".initrd", payloads[2] } },
        );
        if (line) |l| try sections.append(gpa, .{ ".cmdline", try gpa.print("{s}\x00", .{l}) });
        payloads[payloads.len - 1] =
            try pe(gpa, if (f.arch == .aarch64) 0xaa64 else 0x8664, sections.items);
        var files: std.json.ObjectMap = .empty;
        for (image.names, payloads) |name, p| {
            try tmp.dir.writeFile(t.io, .{
                .sub_path = try gpa.print("slot/{s}", .{name}),
                .data = p,
            });
            try files.put(gpa, name, try artifactValue(gpa, try image.hashBytes(gpa, p)));
        }
        try signed.object.put(gpa, "files", .{ .object = files });
        try signed.object.put(gpa, "build", .{ .string = try buildOf(gpa, signed.*) });
        const latest = try gpa.print("{s}/{s}/latest.json", .{ f.root, head });
        try Dir.cwd().writeFile(t.io, .{
            .sub_path = latest,
            .data = try std.json.Stringify.valueAlloc(gpa, signed.*, .{}),
        });
        try f.sign(latest, "vendor");
        try t.expectError(reason, f.invoke(f.manifest, .{}));
    }
}
