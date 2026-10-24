//! Isolated provider bootstrap launch; no workload or reset authority in its disk.
const std = @import("std");
const howl = @import("howl.zig");
const gcp = @import("gcp.zig");
const gpt = @import("gpt");
const uki = @import("uki");
const cmdline = @import("cmdline");
const images = @import("boot-image.zig");
const Io = std.Io;

const Manifest = struct {
    kind: []const u8,
    protocol: u8,
    arch: []const u8,
    mode: []const u8,
    channel: []const u8,
    pcr11: []const u8,
    uki_sha256: []const u8,
    publisher_sha256: []const u8,
};

/// The ordinary cloud gate remains closed. This entry point launches only
/// an isolated signed enrollment image, whose PID 1 refuses workload handover.
pub fn command(io: Io, gpa: std.mem.Allocator, args: []const []const u8, why: *howl.Why) !void {
    if (args.len != 4 or !std.mem.eql(u8, args[0], "gcp"))
        return why.refuse("_cloud-bootstrap gcp NAME IMAGE-DIRECTORY OWNER-CERT", .{});
    const name = args[1];
    if (!howl.isMachineName(name)) return error.BadCloudResource;
    const source = args[2];
    const manifest = try std.json.parseFromSliceLeaky(Manifest, gpa, try read(
        io,
        gpa,
        try gpa.print("{s}/manifest.json", .{source}),
        8192,
    ), .{ .ignore_unknown_fields = true });
    const arch = howl.archName(manifest.arch) orelse return error.UnsupportedHostArch;
    if (!std.mem.eql(u8, manifest.kind, "tpm-bootstrap") or manifest.protocol != 1 or
        !std.mem.eql(u8, manifest.mode, "fresh") or !std.mem.eql(u8, manifest.channel, "serial"))
        return error.BadBootstrapImage;
    const binary = try gpa.print("{s}/bootstrap.efi", .{source});
    const bytes = try read(io, gpa, binary, 256 << 20);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &digest, &try @import("enrollment.zig").hex(manifest.uki_sha256)) or
        !std.mem.eql(u8, &try uki.pcr11(bytes), &try @import("enrollment.zig").hex(manifest.pcr11)))
        return error.WrongBootstrapMeasurement;
    var bad: cmdline.Failure = .{};
    const line = try uki.section(bytes, ".cmdline") orelse return error.BadBootstrapImage;
    const boot = cmdline.parse(std.mem.trimEnd(u8, line, "\x00"), &bad) orelse
        return error.BadBootstrapImage;
    if (!boot.bootstrap or !boot.secure or !boot.native or boot.recovery or
        boot.disable.count() != 0) return error.BadBootstrapImage;
    const public = try std.process.run(gpa, io, .{
        .argv = &.{ "openssl", "x509", "-in", args[3], "-pubkey", "-noout" },
        .stdout_limit = .limited(1024),
    });
    if (public.term != .exited or public.term.exited != 0) return error.BadBootstrapAuthority;
    std.crypto.hash.sha2.Sha256.hash(public.stdout, &digest, .{});
    if (!std.mem.eql(u8, &digest, &try @import("enrollment.zig").hex(manifest.publisher_sha256)))
        return error.BadBootstrapAuthority;
    const certificate = try gpa.print("{s}/boot.crt", .{source});
    try howl.run(io, why, &.{ "osslsigncode", "verify", "-CAfile", certificate, "-in", binary });

    const place = try gcp.place(io, gpa, why);
    if (try gcp.formOf(io, gpa, place, name, why) != null)
        return why.refuse("{s}: an existing instance cannot be re-enrolled", .{name});
    const directory = try howl.machineDir(gpa, name);
    // Never overwrite the evidence or credentials of a previous attempt.
    try Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(directory).?);
    try Io.Dir.cwd().createDir(io, directory, .fromMode(0o700));
    const disk = try gpa.print("{s}/disk.img", .{directory});
    const layout = try gpt.layout(1024, 128);
    try gpt.create(io, disk, layout);
    const esp = try gpa.print("{s}@@{d}", .{ disk, layout.esp_first * gpt.sector });
    try howl.run(io, why, &.{
        "mformat", "-i", esp, "-F", "-T",
        try gpa.print(
            "{d}",
            .{layout.root_first - layout.esp_first},
        ),
        "::",
    });
    try howl.run(io, why, &.{ "mmd", "-i", esp, "::/EFI", "::/EFI/BOOT" });
    const loader = if (arch == .aarch64) "::/EFI/BOOT/BOOTAA64.EFI" else "::/EFI/BOOT/BOOTX64.EFI";
    try howl.run(io, why, &.{ "mcopy", "-i", esp, binary, loader });
    try Io.Dir.cwd().copyFile(
        certificate,
        Io.Dir.cwd(),
        try gpa.print("{s}/boot.crt", .{directory}),
        io,
        .{},
    );
    const qcow = try gpa.print("{s}/disk.qcow2", .{directory});
    try howl.run(io, why, &.{ "qemu-img", "convert", "-f", "raw", "-O", "qcow2", disk, qcow });
    const image = try gcp.ensureImageWithAuthority(
        io,
        gpa,
        place,
        "tpm-bootstrap",
        arch,
        qcow,
        directory,
        args[3],
        .bootstrap,
        why,
    );
    try howl.writePrivate(io, gpa, try gpa.print("{s}/image", .{directory}), image, why);
    try howl.writePrivate(io, gpa, try gpa.print("{s}/engine", .{directory}), "gcp", why);
    const config = try gpa.print("{s}/config.b64", .{directory});
    try howl.writePrivate(io, gpa, config, "", why);
    try gcp.create(io, gpa, place, name, "tpm-bootstrap", arch, null, image, config, why);
    try howl.run(io, why, &.{
        "gcloud",
        "--quiet",
        "--project",
        place.project,
        "compute",
        "instances",
        "add-metadata",
        name,
        "--zone",
        place.zone,
        "--metadata",
        "serial-port-enable=TRUE,block-project-ssh-keys=TRUE",
    });
    try Io.File.stdout().writeStreamingAll(io, try gpa.print("{s}\t{s}\n", .{ name, image }));
}

fn read(io: Io, gpa: std.mem.Allocator, path: []const u8, limit: usize) ![]u8 {
    const data = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(limit + 1));
    if (data.len > limit) return error.BootstrapTooBig;
    return data;
}

/// Test the real factory handover while ordinary protected cloud deployment
/// remains gated. Preserve the instance and its TPM; replace only the stopped
/// bootstrap disk with the authenticated factory disk for its enrolled pair.
pub fn workload(io: Io, gpa: std.mem.Allocator, args: []const []const u8, why: *howl.Why) !void {
    if (args.len != 7 or !std.mem.eql(u8, args[0], "gcp") or !howl.isMachineName(args[1]))
        return why.refuse(
            "_cloud-workload gcp NAME REQUEST.json FACTORY OWNER-CERT IDENTITY-PIN CONFIG-DIR",
            .{},
        );
    const name = args[1];
    const request = try std.json.parseFromSliceLeaky(
        images.Request,
        gpa,
        try read(io, gpa, args[2], 8192),
        .{},
    );
    const verified = try images.verify(
        io,
        gpa,
        request,
        howl.hostArch() orelse return error.UnsupportedHostArch,
    );
    const arch = howl.archName(
        verified.manifest.image.arch,
    ) orelse return error.UnsupportedHostArch;
    const definition = verified.manifest.configuration orelse return error.MissingDeploymentDefinition;
    const owner = try std.process.run(gpa, io, .{
        .argv = &.{ "openssl", "x509", "-in", args[4], "-pubkey", "-noout" },
        .stdout_limit = .limited(1024),
    });
    if (owner.term != .exited or owner.term.exited != 0) return error.BadBootstrapAuthority;
    const factory = try @import("tpm").bundle(
        try @import("apk").parseKey(gpa, owner.stdout),
        try read(io, gpa, args[3], 688),
    );
    if (!std.mem.eql(u8, &factory.previous, &@as([32]u8, @splat(0))) or
        !std.mem.eql(u8, &factory.retained, &verified.release) or
        !std.mem.eql(u8, &factory.candidate, &verified.release) or
        !std.mem.eql(u8, &factory.pcr, &verified.pcr)) return error.WrongFactoryBootState;
    // A lost pin is never permission to enroll or trust another TPM.
    try Io.Dir.cwd().access(io, args[5], .{});
    try @import("cloud-enrollment.zig").retrieve(io, gpa, &.{ "gcp", name, args[5] }, why);
    const place = try gcp.place(io, gpa, why);
    const form = try gcp.formOf(io, gpa, place, name, why) orelse return error.BadCloudResource;
    if (!std.mem.eql(u8, form, "tpm-bootstrap")) return error.NotBootstrapInstance;
    const directory = try howl.machineDir(gpa, name);
    var steps = try @import("progress.zig").Steps.init(io, gpa, why, .{
        .verbose = false,
        .command = "howl _cloud-workload",
        .log = try gpa.print("{s}/handover.log", .{directory}),
        .first = .{ .name = "Preparing the authenticated factory disk", .short = "factory" },
    });
    const raw = try gpa.print("{s}/factory.img", .{directory});
    try images.materialize(io, gpa, &steps, request, verified, raw, args[3]);
    try Io.Dir.cwd().copyFile(
        request.boot_certificate,
        Io.Dir.cwd(),
        try gpa.print("{s}/boot.crt", .{directory}),
        io,
        .{},
    );
    const qcow = try gpa.print("{s}/factory.qcow2", .{directory});
    try howl.run(io, why, &.{ "qemu-img", "convert", "-f", "raw", "-O", "qcow2", raw, qcow });
    const image = try gcp.ensureImageWithAuthority(
        io,
        gpa,
        place,
        verified.manifest.form,
        arch,
        qcow,
        directory,
        args[4],
        .workload,
        why,
    );
    try howl.writePrivate(io, gpa, try gpa.print("{s}/workload-image", .{directory}), image, why);
    const entries = try howl.gather(
        io,
        gpa,
        definition.interface,
        .{ .form = verified.manifest.form, .config = args[6] },
        why,
    );
    const tar = try howl.writeTar(gpa, entries);
    if (howl.misfit(entries, tar.len, .gcp)) |reason| return why.refuse("gcp: {s}", .{reason});
    const bytes = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(tar.len));
    const config = try gpa.print("{s}/config.b64", .{directory});
    try howl.writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{directory}), tar, why);
    try howl.writePrivate(io, gpa, config, std.base64.standard.Encoder.encode(bytes, tar), why);
    const source = try @import("cloud.zig").allowSource(io, gpa, "me", why);
    const disk = try gpa.print("{s}-workload", .{name});
    try howl.writePrivate(io, gpa, try gpa.print("{s}/workload-disk", .{directory}), disk, why);
    _ = try query(
        io,
        gpa,
        place,
        &.{
            "compute",
            "disks",
            "create",
            disk,
            "--zone",
            place.zone,
            "--image",
            image,
            "--type",
            "pd-balanced",
        },
        why,
    );
    const before = try query(io, gpa, place, &.{
        "compute", "instances", "describe", name, "--zone", place.zone, "--format=json(disks)",
    }, why);
    const Disks = struct { disks: []const struct { boot: bool = false, source: []const u8 } };
    const disks = try std.json.parseFromSliceLeaky(
        Disks,
        gpa,
        before,
        .{ .ignore_unknown_fields = true },
    );
    const previous = for (disks.disks) |attached| {
        if (attached.boot) break std.fs.path.basename(attached.source);
    } else return error.MissingBootstrapDisk;
    try howl.writePrivate(
        io,
        gpa,
        try gpa.print("{s}/bootstrap-disk", .{directory}),
        previous,
        why,
    );
    _ = try query(
        io,
        gpa,
        place,
        &.{ "compute", "instances", "stop", name, "--zone", place.zone },
        why,
    );
    _ = try query(
        io,
        gpa,
        place,
        &.{ "compute", "instances", "detach-disk", name, "--zone", place.zone, "--disk", previous },
        why,
    );
    _ = try query(
        io,
        gpa,
        place,
        &.{
            "compute",
            "instances",
            "attach-disk",
            name,
            "--zone",
            place.zone,
            "--disk",
            disk,
            "--boot",
        },
        why,
    );
    _ = try query(
        io,
        gpa,
        place,
        &.{
            "compute",
            "instances",
            "set-disk-auto-delete",
            name,
            "--zone",
            place.zone,
            "--disk",
            disk,
            "--auto-delete",
        },
        why,
    );
    try gcp.publishConfig(io, gpa, place, name, config, why);
    for (try gcp.openArgs(gpa, place, name, definition.ports, source)) |command_args|
        try howl.run(io, why, command_args);
    _ = try query(
        io,
        gpa,
        place,
        &.{ "compute", "instances", "start", name, "--zone", place.zone },
        why,
    );
    switch (try gcp.awaitUp(io, gpa, place, name)) {
        .up => {},
        else => return why.refuse(
            "{s}: factory did not boot; howl console {s} --on gcp",
            .{ name, name },
        ),
    }
    _ = try steps.finish();
    try Io.File.stdout().writeStreamingAll(io, try gpa.print("{s}\t{s}\t{s}\n", .{
        name,
        gcp.address(
            io,
            gpa,
            place,
            name,
        ) orelse return error.MissingCloudAddress,
        verified.manifest.form,
    }));
}

fn query(
    io: Io,
    gpa: std.mem.Allocator,
    place: gcp.Place,
    args: []const []const u8,
    why: *howl.Why,
) ![]const u8 {
    const argv = try std.mem.concat(
        gpa,
        []const u8,
        &.{ &.{ "gcloud", "--quiet", "--project", place.project }, args },
    );
    const result = try std.process.run(
        gpa,
        io,
        .{ .argv = argv, .stdout_limit = .limited(64 << 10), .stderr_limit = .limited(16 << 10) },
    );
    if (result.term != .exited or result.term.exited != 0)
        return why.refuse("gcloud: {s}", .{std.mem.trim(u8, result.stderr, "\r\n")});
    return result.stdout;
}
