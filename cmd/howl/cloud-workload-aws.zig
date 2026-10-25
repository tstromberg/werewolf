//! Internal AWS factory handover on the same enrolled instance and NitroTPM.
const std = @import("std");
const howl = @import("howl.zig");
const aws = @import("aws.zig");
const images = @import("boot-image.zig");
const Io = std.Io;

pub fn command(io: Io, gpa: std.mem.Allocator, args: []const []const u8, why: *howl.Why) !void {
    if (args.len != 7 or !std.mem.eql(u8, args[0], "aws") or !howl.isMachineName(args[1]))
        return error.BadArguments;
    const name = args[1];
    const request = try std.json.parseFromSliceLeaky(images.Request, gpa, try read(io, gpa, args[2], 8192), .{});
    const verified = try images.verify(io, gpa, request, howl.hostArch() orelse return error.UnsupportedHostArch);
    const arch = howl.archName(verified.manifest.image.arch) orelse return error.UnsupportedHostArch;
    const definition = verified.manifest.configuration orelse return error.MissingDeploymentDefinition;
    const owner = try std.process.run(gpa, io, .{
        .argv = &.{ "openssl", "x509", "-in", args[4], "-pubkey", "-noout" },
        .stdout_limit = .limited(1024),
    });
    if (owner.term != .exited or owner.term.exited != 0) return error.BadBootstrapAuthority;
    const factory = try @import("tpm").bundle(try @import("apk").parseKey(gpa, owner.stdout), try read(io, gpa, args[3], 688));
    if (!std.mem.eql(u8, &factory.previous, &@as([32]u8, @splat(0))) or
        !std.mem.eql(u8, &factory.retained, &verified.release) or
        !std.mem.eql(u8, &factory.candidate, &verified.release) or
        !std.mem.eql(u8, &factory.pcr, &verified.pcr)) return error.WrongFactoryBootState;
    const place = try aws.place(io, gpa, why);
    const instance = try aws.find(io, gpa, place, name, why) orelse return error.BadCloudResource;
    if (!std.mem.eql(u8, instance.form, "tpm-bootstrap")) return error.NotBootstrapInstance;
    try Io.Dir.cwd().access(io, args[5], .{});
    try @import("cloud-enrollment.zig").retrieve(io, gpa, &.{ "aws", instance.id, args[5] }, why);
    const directory = try howl.machineDir(gpa, name);
    var steps = try @import("progress.zig").Steps.init(io, gpa, why, .{
        .verbose = false,
        .command = "howl _cloud-workload aws",
        .log = try gpa.print("{s}/handover.log", .{directory}),
        .first = .{ .name = "Preparing the authenticated factory disk", .short = "factory" },
    });
    const raw = try gpa.print("{s}/factory.img", .{directory});
    try images.materialize(io, gpa, &steps, request, verified, raw, args[3]);
    try Io.Dir.cwd().copyFile(request.boot_certificate, Io.Dir.cwd(), try gpa.print("{s}/boot.crt", .{directory}), io, .{});
    const qcow = try gpa.print("{s}/factory.qcow2", .{directory});
    try howl.run(io, why, &.{ "qemu-img", "convert", "-f", "raw", "-O", "qcow2", raw, qcow });
    const ami = try aws.ensureImageWithAuthority(io, gpa, place, verified.manifest.form, arch, qcow, directory, args[4], .workload, why);
    try howl.writePrivate(io, gpa, try gpa.print("{s}/workload-image", .{directory}), ami, why);
    const entries = try howl.gather(io, gpa, definition.interface, .{ .form = verified.manifest.form, .config = args[6] }, why);
    const tar = try howl.writeTar(gpa, entries);
    if (howl.misfit(entries, tar.len, .aws)) |reason| return why.refuse("aws: {s}", .{reason});
    const bytes = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(tar.len));
    const encoded = std.base64.standard.Encoder.encode(bytes, tar);
    const again = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(encoded.len));
    const config = try gpa.print("{s}/config.b64.b64", .{directory});
    try howl.writePrivate(io, gpa, config, std.base64.standard.Encoder.encode(again, encoded), why);
    try howl.writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{directory}), tar, why);
    const description = try query(io, gpa, place, &.{
        "ec2",     "describe-instances",           "--instance-ids", instance.id,
        "--query", "Reservations[0].Instances[0]", "--output",       "json",
    }, why);
    const Instance = struct {
        RootDeviceName: []const u8,
        Placement: struct { AvailabilityZone: []const u8 },
        BlockDeviceMappings: []const struct { DeviceName: []const u8, Ebs: struct { VolumeId: []const u8 } },
    };
    const before = try std.json.parseFromSliceLeaky(Instance, gpa, description, .{ .ignore_unknown_fields = true });
    if (!std.mem.eql(u8, before.RootDeviceName, "/dev/xvda")) return error.WrongBootstrapDisk;
    const previous = for (before.BlockDeviceMappings) |disk| {
        if (std.mem.eql(u8, disk.DeviceName, before.RootDeviceName)) break disk.Ebs.VolumeId;
    } else return error.MissingBootstrapDisk;
    const snapshot = try query(io, gpa, place, &.{
        "ec2",     "describe-images",                                 "--image-ids", ami,
        "--query", "Images[0].BlockDeviceMappings[0].Ebs.SnapshotId",
    }, why);
    const volume = try query(io, gpa, place, &.{
        "ec2",           "create-volume", "--availability-zone",  before.Placement.AvailabilityZone,
        "--snapshot-id", snapshot,        "--volume-type",        "gp3",
        "--query",       "VolumeId",      "--tag-specifications", try gpa.print("ResourceType=volume,Tags=[{{Key=Name,Value={s}-workload}}]", .{name}),
    }, why);
    try howl.writePrivate(io, gpa, try gpa.print("{s}/bootstrap-disk", .{directory}), previous, why);
    try howl.writePrivate(io, gpa, try gpa.print("{s}/workload-disk", .{directory}), volume, why);
    _ = try query(io, gpa, place, &.{ "ec2", "wait", "volume-available", "--volume-ids", volume }, why);
    // Only the isolated, already-refused bootstrap runs here. It has no
    // writable workload filesystem or service to shut down before the swap.
    _ = try query(io, gpa, place, &.{ "ec2", "stop-instances", "--instance-ids", instance.id, "--skip-os-shutdown" }, why);
    _ = try query(io, gpa, place, &.{ "ec2", "wait", "instance-stopped", "--instance-ids", instance.id }, why);
    _ = try query(io, gpa, place, &.{ "ec2", "detach-volume", "--volume-id", previous }, why);
    _ = try query(io, gpa, place, &.{ "ec2", "wait", "volume-available", "--volume-ids", previous }, why);
    _ = try query(io, gpa, place, &.{ "ec2", "attach-volume", "--instance-id", instance.id, "--volume-id", volume, "--device", before.RootDeviceName }, why);
    _ = try query(io, gpa, place, &.{ "ec2", "wait", "volume-in-use", "--volume-ids", volume }, why);
    _ = try query(io, gpa, place, &.{
        "ec2",                                                                                                            "modify-instance-attribute", "--instance-id", instance.id, "--block-device-mappings",
        try gpa.print("[{{\"DeviceName\":\"{s}\",\"Ebs\":{{\"DeleteOnTermination\":true}}}}]", .{before.RootDeviceName}),
    }, why);
    _ = try query(io, gpa, place, &.{ "ec2", "modify-instance-attribute", "--instance-id", instance.id, "--attribute", "userData", "--value", try gpa.print("file://{s}", .{config}) }, why);
    const source = try @import("cloud.zig").allowSource(io, gpa, "me", why);
    for (try aws.openArgs(gpa, place, name, definition.ports, source)) |argv| try howl.run(io, why, argv);
    _ = try query(io, gpa, place, &.{ "ec2", "start-instances", "--instance-ids", instance.id }, why);
    switch (try aws.awaitUp(io, gpa, place, instance.id)) {
        .up => {},
        else => return why.refuse("{s}: factory did not boot; howl console {s} --on aws", .{ name, name }),
    }
    try @import("cloud-enrollment.zig").retrieve(io, gpa, &.{ "aws", instance.id, args[5] }, why);
    _ = try steps.finish();
    try Io.File.stdout().writeStreamingAll(io, try gpa.print("{s}\t{s}\t{s}\n", .{
        name, aws.address(io, gpa, place, instance.id) orelse return error.MissingCloudAddress, verified.manifest.form,
    }));
}

fn read(io: Io, gpa: std.mem.Allocator, path: []const u8, limit: usize) ![]u8 {
    const data = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(limit + 1));
    if (data.len > limit) return error.BootstrapTooBig;
    return data;
}

fn query(io: Io, gpa: std.mem.Allocator, place: aws.Place, args: []const []const u8, why: *howl.Why) ![]const u8 {
    const argv = try std.mem.concat(gpa, []const u8, &.{ &.{ "aws", "--region", place.region, "--output", "text" }, args });
    const result = try std.process.run(gpa, io, .{ .argv = argv, .stdout_limit = .limited(64 << 10), .stderr_limit = .limited(8192) });
    if (result.term != .exited or result.term.exited != 0)
        return why.refuse("aws: {s}", .{std.mem.trim(u8, result.stderr, "\r\n")});
    return std.mem.trim(u8, result.stdout, " \r\n");
}
