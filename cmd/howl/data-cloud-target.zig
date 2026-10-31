//! Offline cloud imports prepare a fresh disk without creating a VM. Explicit
//! start provisions new firmware/TPM authority; existing cloud disks never swap.
const std = @import("std");
const howl = @import("howl.zig");
const secure = @import("local-secure.zig");
const images = @import("data-image.zig");
const transport = @import("data-cloud-disk.zig");
const cloud = @import("data-cloud.zig");
const Io = std.Io;
const Dir = Io.Dir;
const A = std.mem.Allocator;

pub fn requireUnstaged(io: Io, a: A, at: []const u8) !void {
    const bytes = Dir.cwd().readFileAlloc(
        io,
        try a.print("{s}/authority/profile.json", .{at}),
        a,
        .limited(256 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if ((try secure.parseProfile(a, bytes)).cloud_staged) return error.TransferAwaitingStart;
}

pub fn prepare(
    io: Io,
    a: A,
    at: []const u8,
    on: howl.Platform,
    size: ?[]const u8,
    record: images.Record,
    config: []const u8,
    why: *howl.Why,
) !secure.Profile {
    if (!cloud.supported(on)) return error.TransferProvider;
    const expected = record.disk_sha256 orelse return error.TransferImageCache;
    const fallback = std.fmt.bytesToHex(record.verity.root, .lower);
    const cache = try images.directory(io, a, record.profile.data_image orelse &fallback);
    const source = try a.print("{s}/disk.raw", .{cache});
    if (!std.mem.eql(
        u8,
        expected,
        (try @import("prebuilt").hashFile(io, a, source)).sha256,
    )) return error.TransferImageCache;
    const authority = try a.print("{s}/authority", .{at});
    try Dir.cwd().createDir(io, authority, .fromMode(0o700));
    errdefer Dir.cwd().deleteTree(io, authority) catch {};
    const disk = try a.print("{s}/disk.img", .{at});
    const reservation = try Dir.cwd().createFile(
        io,
        disk,
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    );
    reservation.close(io);
    errdefer Dir.cwd().deleteFile(io, disk) catch {};
    try howl.run(io, why, &.{ "qemu-img", "convert", "-f", "raw", "-O", "raw", source, disk });
    try Dir.cwd().setFilePermissions(io, disk, .fromMode(0o600), .{});
    const cert = try a.print("{s}/boot.crt", .{at});
    try Dir.cwd().copyFile(
        record.profile.spec.boot_cert orelse return error.TransferImageCertificate,
        .cwd(),
        cert,
        io,
        .{},
    );
    try @import("boot-image.zig").durable(io, try a.print("{s}/config.tar", .{at}), config);
    try @import("boot-image.zig").durable(io, try a.print("{s}/engine", .{at}), @tagName(on));
    var profile = record.profile;
    profile.provider = on;
    profile.cloud = null;
    profile.cloud_staged = true;
    profile.cloud_size = size;
    profile.spec.disk_path = disk;
    profile.spec.boot_cert = cert;
    try images.replaceRecord(
        io,
        a,
        try a.print("{s}/profile.json", .{authority}),
        try std.json.Stringify.valueAlloc(a, profile, .{}),
    );
    return profile;
}

pub fn start(
    io: Io,
    a: A,
    name: []const u8,
    at: []const u8,
    staged: secure.Profile,
    why: *howl.Why,
) !void {
    if (!cloud.supported(staged.provider)) return error.TransferProvider;
    try requireImported(io, a, at, staged.data_image orelse return error.TransferImageCache);
    return activate(io, a, name, at, staged, why);
}

fn requireImported(io: Io, a: A, at: []const u8, image: []const u8) !void {
    const ready = Dir.cwd().readFileAlloc(
        io,
        try a.print("{s}/authority/import-ready", .{at}),
        a,
        .limited(128),
    ) catch |err| switch (err) {
        error.FileNotFound => return error.TransferImportIncomplete,
        else => return err,
    };
    if (!std.mem.eql(u8, ready, image)) return error.TransferImageCache;
}

fn activate(
    io: Io,
    a: A,
    name: []const u8,
    at: []const u8,
    staged: secure.Profile,
    why: *howl.Why,
) !void {
    const path = try a.print("{s}/authority/profile.json", .{at});
    if (staged.cloud) |context| {
        // Capture succeeded before an interrupted final local publication.
        if (!(try cloud.state(io, a, name, context)).running) switch (context) {
            .aws => |p| {
                _ = try transport.aws(
                    io,
                    a,
                    p.region,
                    &.{ "ec2", "start-instances", "--instance-ids", p.id },
                );
                _ = try transport.aws(
                    io,
                    a,
                    p.region,
                    &.{ "ec2", "wait", "instance-running", "--instance-ids", p.id },
                );
            },
            .gcp => |p| {
                _ = try transport.gcp(
                    io,
                    a,
                    p.project,
                    &.{ "compute", "instances", "start", name, "--zone", p.zone },
                );
            },
            .azure => |p| {
                _ = try transport.azure(
                    io,
                    a,
                    p.group,
                    &.{ "vm", "start", "-n", name, "-o", "none" },
                );
            },
        };
    } else {
        const work = try a.print("{s}/publish", .{at});
        try Dir.cwd().createDirPath(io, work);
        try Dir.cwd().setFilePermissions(io, work, .fromMode(0o700), .{});
        defer Dir.cwd().deleteTree(io, work) catch {};
        const disk = try a.print("{s}/disk.qcow2", .{work});
        try Dir.cwd().copyFile(
            staged.spec.boot_cert orelse return error.TransferImageCertificate,
            .cwd(),
            try a.print("{s}/boot.crt", .{work}),
            io,
            .{},
        );
        const raw = staged.spec.disk_path orelse return error.TransferStorageState;
        // The storage helper checked this disk at import. It contains no
        // imported boot code; only the approved image's /data was writable.
        try howl.run(io, why, &.{ "qemu-img", "convert", "-f", "raw", "-O", "qcow2", raw, disk });
        const form = (staged.local orelse staged.spec).form;
        const tar = try a.print("{s}/config.tar", .{at});
        switch (staged.provider) {
            .aws => {
                const api = @import("aws.zig");
                const p = try api.place(io, a, why);
                if (try api.find(io, a, p, name, why) != null) return error.TransferTargetExists;
                // A new AMI enrolls only the approved signer. EC2 initializes
                // fresh firmware variables and NitroTPM for the new instance.
                const image = try api.ensureImage(
                    io,
                    a,
                    p,
                    form,
                    staged.spec.arch,
                    disk,
                    work,
                    why,
                );
                defer cleanupAwsImage(io, a, p.region, image);
                const bytes = try Dir.cwd().readFileAlloc(io, tar, a, .limited(64 << 20));
                const encoded = try a.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len));
                const b64 = try a.print("{s}/config.b64", .{work});
                try @import("boot-image.zig").durable(
                    io,
                    b64,
                    std.base64.standard.Encoder.encode(encoded, bytes),
                );
                const id = try api.create(
                    io,
                    a,
                    p,
                    name,
                    form,
                    staged.spec.arch,
                    staged.cloud_size,
                    image,
                    b64,
                    why,
                );
                try cloud.capture(io, a, name, .{ .aws = .{ .region = p.region, .id = id } });
            },
            .gcp => {
                const api = @import("gcp.zig");
                const p = try api.place(io, a, why);
                if (try api.formOf(io, a, p, name, why) != null) return error.TransferTargetExists;
                var random: [12]u8 = undefined;
                try io.randomSecure(&random);
                const temporary = try a.print("ww-data-{s}", .{std.fmt.bytesToHex(random, .lower)});
                const bucket = try a.print("gs://{s}", .{temporary});
                const region = p.zone[0 .. std.mem.findScalarLast(
                    u8,
                    p.zone,
                    '-',
                ) orelse return error.TransferCloudPlace];
                _ = try transport.gcp(
                    io,
                    a,
                    p.project,
                    &.{
                        "storage",
                        "buckets",
                        "create",
                        bucket,
                        "--location",
                        region,
                        "--uniform-bucket-level-access",
                        "--public-access-prevention",
                        "--soft-delete-duration=0",
                    },
                );
                defer {
                    _ = transport.gcp(
                        io,
                        a,
                        p.project,
                        &.{ "storage", "rm", "--recursive", bucket },
                    ) catch {
                        howl.say(
                            io,
                            "temporary bucket {s} remains; remove its objects and delete it",
                            .{bucket},
                        );
                    };
                }
                const image = try api.privateImage(
                    io,
                    a,
                    p,
                    form,
                    staged.spec.arch,
                    disk,
                    work,
                    temporary,
                    bucket,
                    why,
                );
                defer {
                    _ = transport.gcp(
                        io,
                        a,
                        p.project,
                        &.{ "compute", "images", "delete", image },
                    ) catch {
                        howl.say(io, "temporary image {s} remains in {s}", .{ image, p.project });
                    };
                }
                const bytes = try Dir.cwd().readFileAlloc(io, tar, a, .limited(64 << 20));
                const encoded = try a.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len));
                const b64 = try a.print("{s}/config.b64", .{work});
                try @import("boot-image.zig").durable(
                    io,
                    b64,
                    std.base64.standard.Encoder.encode(encoded, bytes),
                );
                try api.create(
                    io,
                    a,
                    p,
                    name,
                    form,
                    staged.spec.arch,
                    staged.cloud_size,
                    image,
                    b64,
                    why,
                );
                try cloud.capture(
                    io,
                    a,
                    name,
                    .{ .gcp = .{ .project = p.project, .zone = p.zone, .id = "" } },
                );
            },
            .azure => {
                const api = @import("azure.zig");
                const p = try api.place(io, a, why);
                if (try api.find(io, a, p, name, why) != null) return error.TransferTargetExists;
                // Azure's gallery owns its Secure Boot signature policy and
                // creates fresh VMGS for this new VM, not the exported VM's.
                const image = try api.ensureImage(
                    io,
                    a,
                    p,
                    form,
                    staged.spec.arch,
                    disk,
                    work,
                    why,
                );
                defer cleanupAzureImage(io, a, p.group, image);
                try api.create(
                    io,
                    a,
                    p,
                    name,
                    form,
                    staged.spec.arch,
                    staged.cloud_size,
                    image,
                    tar,
                    why,
                );
                try cloud.capture(
                    io,
                    a,
                    name,
                    .{ .azure = .{ .group = p.group, .location = p.location, .id = "" } },
                );
            },
            else => unreachable,
        }
    }
    var profile = try secure.parseProfile(
        a,
        try Dir.cwd().readFileAlloc(io, path, a, .limited(256 << 10)),
    );
    profile.cloud_staged = false;
    try images.replaceRecord(io, a, path, try std.json.Stringify.valueAlloc(a, profile, .{}));
    howl.say(io, "{s}: restored VM started", .{name});
}

fn cleanupAwsImage(io: Io, a: A, region: []const u8, image: []const u8) void {
    const snapshot = transport.aws(
        io,
        a,
        region,
        &.{
            "ec2",
            "describe-images",
            "--image-ids",
            image,
            "--query",
            "Images[0].BlockDeviceMappings[].Ebs.SnapshotId",
        },
    ) catch return;
    const ids = std.json.parseFromSliceLeaky([]const []const u8, a, snapshot, .{}) catch return;
    if (ids.len != 1) return;
    _ = transport.aws(io, a, region, &.{ "ec2", "deregister-image", "--image-id", image }) catch {
        howl.say(io, "temporary AMI {s} remains in {s}", .{ image, region });
        return;
    };
    _ = transport.aws(
        io,
        a,
        region,
        &.{ "ec2", "delete-snapshot", "--snapshot-id", ids[0] },
    ) catch {
        howl.say(io, "temporary snapshot {s} remains in {s}", .{ ids[0], region });
    };
}

fn cleanupAzureImage(io: Io, a: A, group: []const u8, image: []const u8) void {
    const definition = std.fs.path.dirname(std.fs.path.dirname(image) orelse return) orelse return;
    const gallery = std.fs.path.dirname(
        std.fs.path.dirname(definition) orelse return,
    ) orelse return;
    const disk = std.mem.replaceOwned(u8, a, std.fs.path.basename(gallery), "_", "-") catch return;
    // Restored target identity makes this image unique to the newly staged VM.
    for ([_][]const []const u8{
        &.{ "sig", "image-version", "delete", "--ids", image },
        &.{ "sig", "image-definition", "delete", "--ids", definition },
        &.{ "sig", "delete", "--ids", gallery },
        &.{ "disk", "delete", "-n", disk, "--yes", "-o", "none" },
    }) |args| {
        // Azure may briefly reject deleting a parent after its child is gone.
        for (0..3) |attempt| {
            _ = transport.azure(io, a, group, args) catch {
                if (attempt < 2) {
                    io.sleep(.fromSeconds(2), .awake) catch {};
                    continue;
                }
                howl.say(
                    io,
                    "private restore image {s} remains; remove its gallery and source disk {s}",
                    .{ image, disk },
                );
                return;
            };
            break;
        }
    }
}

test "staged cloud data cannot be replaced by create" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const at = try tmp.dir.realPathFileAlloc(t.io, ".", a);
    try requireUnstaged(t.io, a, at);
    try tmp.dir.createDir(t.io, "authority", .fromMode(0o700));
    const image = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const profile: secure.Profile = .{
        .spec = .{ .form = "postgresql", .arch = .aarch64 },
        .managed = false,
        .provider = .gcp,
        .cloud_staged = true,
        .data_image = image,
    };
    try tmp.dir.writeFile(
        t.io,
        .{
            .sub_path = "authority/profile.json",
            .data = try std.json.Stringify.valueAlloc(a, profile, .{}),
        },
    );
    try t.expectError(error.TransferAwaitingStart, requireUnstaged(t.io, a, at));
    var why: howl.Why = .{};
    try t.expectError(error.TransferImportIncomplete, start(t.io, a, "fixture", at, profile, &why));
    try tmp.dir.writeFile(t.io, .{ .sub_path = "authority/import-ready", .data = image });
    try requireImported(t.io, a, at, image);
    try t.expectError(error.TransferImageCache, requireImported(t.io, a, at, "other"));
}
