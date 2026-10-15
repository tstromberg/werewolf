//! Authenticated, machine-independent boot disks and their exact measured slot.
const std = @import("std");
const howl = @import("howl.zig");
const image = @import("prebuilt");
const tpm = @import("tpm");
const uki = @import("uki");
const enrollment = @import("enrollment.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub const Request = struct {
    directory: []const u8,
    boot_certificate: []const u8,
    image_certificate: []const u8,
    channel: []const u8,
};
pub const Manifest = struct {
    format: []const u8 = "werewolf-boot/1",
    form: []const u8,
    image: image.Manifest,
    disk: image.Artifact,
    raw_size: u64,
    boot_certificate: []const u8,
    permit_host: []const u8,
    permit_port: u16,
    pcr11: []const u8,
    configuration: ?@import("boot-config.zig").Definition = null,
};
pub const Verified = struct { manifest: Manifest, release: [32]u8, pcr: [32]u8 };
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
    permit_host: []const u8,
    permit_port: u16,
    configuration_form: ?[]const u8 = null,
};

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
    if (!std.mem.eql(u8, m.format, "werewolf-boot/1") or
        !@import("form").isName(m.form)) return error.BadBootImageProfile;
    try image.check(m.image, expected);
    if (m.configuration) |definition| try @import("boot-config.zig").check(definition, m.form);
    if (m.image.boot_context == null or m.image.files.@"uki.efi" == null or
        m.permit_port == 0 or
        (!std.mem.eql(u8, m.permit_host, "192.168.5.2") and
            !std.mem.eql(u8, m.permit_host, "10.0.2.2"))) return error.BadBootImageProfile;
    if (m.disk.size == 0 or m.disk.size > 2 << 30 or m.raw_size < 512 << 20 or
        m.raw_size > 16 << 30 or m.raw_size % (1 << 20) != 0)
        return error.BadBootImageSize;
    _ = try enrollment.hex(m.disk.sha256);
    _ = try enrollment.hex(m.boot_certificate);
    const pcr = try enrollment.hex(m.pcr11);
    if (std.mem.eql(u8, &pcr, &@as([32]u8, @splat(0)))) return error.UnmeasuredBootImage;
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
        &try enrollment.hex(m.boot_certificate),
    )) return error.WrongBootCertificate;
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
    const pcr = try uki.pcr11(raw);
    if (!std.mem.eql(u8, &pcr, &try enrollment.hex(m.pcr11))) return error.WrongBootMeasurement;
    const release = tpm.releaseId(
        @tagName(arch),
        try enrollment.hex(m.image.files.@"root.erofs".sha256),
        try enrollment.hex(m.image.files.vmlinuz.sha256),
        try enrollment.hex(m.image.files.@"stage0.zst".sha256),
        try enrollment.hex(m.image.boot_context.?),
    );
    const line = try uki.section(raw, ".cmdline") orelse return error.MissingBootIdentity;
    var bad: @import("cmdline").Failure = .{};
    const parsed = @import("cmdline").parse(std.mem.trimEnd(u8, line, "\x00"), &bad) orelse
        return error.BadBootIdentity;
    if (!parsed.tpm or !parsed.secure or !parsed.native or parsed.release == null or
        !std.mem.eql(u8, &parsed.release.?, &release)) return error.WrongBootIdentity;
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
    return .{ .manifest = m, .release = release, .pcr = pcr };
}

pub fn materialize(
    io: Io,
    gpa: Allocator,
    steps: *@import("progress.zig").Steps,
    request: Request,
    verified: Verified,
    output: []const u8,
    factory: []const u8,
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
    const commands = try gpa.print("{s}/enroll-disk.cmds", .{work});
    defer Dir.cwd().deleteFile(io, commands) catch {};
    const updates = "mkdir /state\nwrite {s} /state/0\n" ++
        "sif /state uid 0\nsif /state gid 0\n" ++
        "sif /state mode 040700\n" ++
        "sif /state/0 uid 0\nsif /state/0 gid 0\n" ++
        "sif /state/0 mode 0100600\n";
    try enrollment.durable(io, commands, try gpa.print(updates, .{try quote(gpa, factory)}));
    const debugfs = if (@import("builtin").os.tag == .macos)
        "/opt/homebrew/opt/e2fsprogs/sbin/debugfs"
    else
        "debugfs";
    _ = try capture(
        io,
        gpa,
        &.{
            debugfs,
            "-w",
            "-f",
            commands,
            try gpa.print("{s}?offset={d}", .{ output, layout.root_first * 512 }),
        },
    );
    // debugfs reports command failures on stderr while exiting successfully.
    const readback = try capture(
        io,
        gpa,
        &.{
            debugfs,
            "-R",
            "cat /state/0",
            try gpa.print("{s}?offset={d}", .{ output, layout.root_first * 512 }),
        },
    );
    if (!std.mem.eql(u8, readback, try read(io, gpa, factory, tpm.record_size + 512)))
        return error.FactoryJournalWriteFailed;
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

fn quote(gpa: Allocator, path: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.append(gpa, '"');
    for (path) |c| {
        if (std.ascii.isControl(c)) return error.BadDiskPath;
        if (c == '"' or c == '\\') try out.append(gpa, '\\');
        try out.append(gpa, c);
    }
    try out.append(gpa, '"');
    return out.toOwnedSlice(gpa);
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
    if (args.len == 8 and std.mem.eql(u8, args[0], "head")) {
        const arch = howl.archName(args[5]) orelse return error.WrongImageArch;
        const m = try admitHead(io, gpa, .{
            .directory = args[1],
            .boot_certificate = args[2],
            .image_certificate = args[3],
            .channel = args[4],
        }, arch);
        if (!std.mem.eql(u8, m.form, args[6])) return error.WrongBootForm;
        const host: []const u8 = if (std.mem.eql(u8, args[7], "lima"))
            "192.168.5.2"
        else if (std.mem.eql(u8, args[7], "qemu"))
            "10.0.2.2"
        else
            return error.BadSecuredProvider;
        if (!std.mem.eql(u8, m.permit_host, host)) return error.WrongBootProvider;
        if (m.configuration == null) return error.MissingDeploymentDefinition;
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
/// the form, the disk, the boot certificate, the permit endpoint and the
/// predicted PCR 11. release/build-protected seals werewolf's images with
/// it, and howl the images it builds with the user's own keys.
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
        .permit_host = p.permit_host,
        .permit_port = p.permit_port,
        .pcr11 = try gpa.dupe(
            u8,
            &std.fmt.bytesToHex(
                try uki.pcr11(try read(
                    io,
                    gpa,
                    try gpa.print("{s}/uki.efi", .{p.slot}),
                    512 << 20,
                )),
                .lower,
            ),
        ),
    };
    try check(m, .{ .channel = p.channel, .arch = p.arch });
    const head = try gpa.print("{s}/boot.json", .{p.output});
    try enrollment.durable(io, head, try std.json.Stringify.valueAlloc(gpa, m, .{}));
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
    const verified = try verify(
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
    try enrollment.durable(
        io,
        try gpa.print("{s}/slot/release.id", .{p.output}),
        &verified.release,
    );
    try enrollment.durable(io, try gpa.print("{s}/slot/pcr11", .{p.output}), &verified.pcr);
}

test "disk journal paths are quoted without command injection" {
    const t = std.testing;
    const value = try quote(t.allocator, "/a b/c\"d\\e");
    defer t.allocator.free(value);
    try t.expectEqualStrings("\"/a b/c\\\"d\\\\e\"", value);
    try t.expectError(error.BadDiskPath, quote(t.allocator, "key\nwrite bad"));
}

test "boot entries cannot add unsigned options or select another executable" {
    const t = std.testing;
    try loaderEntry("title werewolf a\nuki /werewolf/a/uki.efi\n");
    for ([_][]const u8{
        "uki /werewolf/a/uki.efi\noptions werewolf.tpm=0\n",
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

test "portable boot profiles require measured signed IPE and bounded declared transport" {
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
        .boot_context = zero,
        .files = files,
    };
    const valid: Manifest = .{
        .form = "playground",
        .image = slot_image,
        .disk = .{ .size = 1, .sha256 = zero },
        .raw_size = 8 << 30,
        .boot_certificate = zero,
        .permit_host = "192.168.5.2",
        .permit_port = 9443,
        .pcr11 = &@as([64]u8, @splat('1')),
    };
    try check(valid, identity);
    var bad = valid;
    bad.image.ipe = false;
    try t.expectError(error.NotAnIpeImage, check(bad, identity));
    bad = valid;
    bad.image.boot_context = null;
    try t.expectError(error.BadBootImageProfile, check(bad, identity));
    bad = valid;
    bad.permit_host = "127.0.0.1";
    try t.expectError(error.BadBootImageProfile, check(bad, identity));
    bad = valid;
    bad.permit_port = 0;
    try t.expectError(error.BadBootImageProfile, check(bad, identity));
    bad = valid;
    bad.raw_size = 32 << 30;
    try t.expectError(error.BadBootImageSize, check(bad, identity));
    bad = valid;
    bad.form = "../foreign";
    try t.expectError(error.BadBootImageProfile, check(bad, identity));
    bad = valid;
    bad.pcr11 = zero;
    try t.expectError(error.UnmeasuredBootImage, check(bad, identity));
    try t.expectError(
        error.WrongImageChannel,
        check(valid, .{ .channel = "https://foreign.test", .arch = identity.arch }),
    );
}
