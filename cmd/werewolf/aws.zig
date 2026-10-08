//! AWS: a werewolf machine on EC2, from the same two files every target
//! takes. The boot disk becomes an AMI, named as GCP's image is
//! (image.zig): written straight into an EBS snapshot through EBS's direct
//! API, only the 512 KiB blocks that hold data (a hundred or so of an
//! 8 GiB disk's 16384), several at once, each with its sha256, which EBS
//! checks; then registered for UEFI, the ENA and IMDSv2 alone. No bucket,
//! no VM Import, no service role: minutes and a setup fewer. The config
//! tar, in base64, is the instance's user data, which cloud-metadata
//! fetches through IMDSv2 (docs/cloud.md). The instance has no instance
//! profile, and a security group of its own, werewolf-NAME, which lets
//! nothing in until its owner says what may.
//!
//! The region and credentials are the aws CLI's own (aws configure, or
//! AWS_REGION and AWS_PROFILE). AWS is the state: an instance's Name tag
//! is its name, and its werewolf-form tag the form it was made from.

const std = @import("std");
const ww = @import("werewolf.zig");
const images = @import("image.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// How long create waits for a machine to say it is up.
const wait_seconds = 300;
/// EBS's block, the unit a direct snapshot is written in.
const block_size = 512 << 10;
/// How many blocks go up at once: each is an aws process, which mostly
/// waits on the network.
const parallel = 8;
/// How long a snapshot may take to complete once its blocks are in.
const snapshot_seconds = 600;
const tag = "werewolf-form";
/// The states of an instance that has not gone, nor is going.
const alive = "Name=instance-state-name,Values=pending,running,stopping,stopped";

pub const Place = struct { region: []const u8 };

/// The region the aws CLI works in, or a refusal saying why not: the one
/// it resolves, from the environment or its config, as an EC2 call shows
/// it, which also says whether it has credentials.
pub fn place(io: Io, gpa: Allocator, why: *ww.Why) !Place {
    const region = call(io, gpa, &.{
        "aws",                             "ec2",
        "describe-availability-zones",     "--query",
        "AvailabilityZones[0].RegionName", "--output",
        "text",
    });
    // The CLI's own words say what to set: a region, or credentials.
    if (!region.ok) return why.refuse("--on aws: {s}", .{lastLine(region.err)});
    return .{ .region = region.out };
}

const Result = struct { ok: bool, out: []const u8 = "", err: []const u8 = "" };

/// A command's trimmed output and error, and whether it succeeded.
fn call(io: Io, gpa: Allocator, argv: []const []const u8) Result {
    const r = std.process.run(gpa, io, .{ .argv = argv }) catch |err|
        return .{ .ok = false, .err = if (err == error.FileNotFound)
            "no aws command here (brew install awscli)"
        else
            @errorName(err) };
    return .{
        .ok = r.term == .exited and r.term.exited == 0,
        .out = std.mem.trim(u8, r.stdout, " \r\n"),
        .err = std.mem.trim(u8, r.stderr, " \r\n"),
    };
}

/// aws, in p's region, its output as text, with args.
fn aws(gpa: Allocator, p: Place, args: []const []const u8) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{ "aws", "--region", p.region, "--output", "text" });
    try argv.appendSlice(gpa, args);
    return argv.items;
}

/// aws's output, or null if it failed or said nothing.
fn ask(io: Io, gpa: Allocator, p: Place, args: []const []const u8) ?[]const u8 {
    const r = call(io, gpa, aws(gpa, p, args) catch return null);
    if (!r.ok or r.out.len == 0 or std.mem.eql(u8, r.out, "None")) return null;
    return r.out;
}

/// aws's output, or a refusal with its error.
fn need(io: Io, gpa: Allocator, p: Place, args: []const []const u8, why: *ww.Why) ![]const u8 {
    const r = call(io, gpa, try aws(gpa, p, args));
    if (!r.ok) return why.refuse("aws {s} {s}: {s}", .{ args[0], args[1], lastLine(r.err) });
    return r.out;
}

/// The last line of the CLI's error, without its prefix: "(NoRegion):
/// You must specify a region...".
fn lastLine(text: []const u8) []const u8 {
    const t = std.mem.trimEnd(u8, text, " \r\n");
    var line = t[if (std.mem.findScalarLast(u8, t, '\n')) |nl| nl + 1 else 0..];
    for ([_][]const u8{ "aws: [ERROR]: ", "An error occurred " }) |prefix| {
        if (std.mem.startsWith(u8, line, prefix)) line = line[prefix.len..];
    }
    return line;
}

/// The machine a form runs on, for an arch: AWS's name for the arch, and
/// the smallest Nitro instance with 2 GiB, whose disks are NVMe and whose
/// NIC is the ENA, which prod's modules carry.
pub const Machine = struct { arch: []const u8, kind: []const u8 };

pub fn machine(arch: []const u8) Machine {
    return if (std.mem.eql(u8, arch, "aarch64"))
        .{ .arch = "arm64", .kind = "t4g.small" }
    else
        .{ .arch = "x86_64", .kind = "t3.small" };
}

/// The AMI of disk, a release's disk.qcow2: there already, or made from a
/// snapshot written straight from it.
pub fn ensureImage(
    io: Io,
    gpa: Allocator,
    p: Place,
    form: []const u8,
    arch: []const u8,
    disk: []const u8,
    work: []const u8,
    why: *ww.Why,
) ![]const u8 {
    const name = try images.name(gpa, form, arch, &try images.sha256(io, disk));
    if (ask(io, gpa, p, &.{
        "ec2",
        "describe-images",
        "--owners",
        "self",
        "--filters",
        try gpa.print("Name=name,Values={s}", .{name}),
        "--query",
        "Images[0].ImageId",
    })) |id| {
        ww.say(io, "image {s}: there already, {s}", .{ name, id });
        return id;
    }
    ww.say(io, "image {s}: making it from {s}", .{ name, disk });
    // Raw, so a block is at its offset; sparse where the disk is empty.
    const raw = try gpa.print("{s}/disk.raw", .{work});
    defer Dir.cwd().deleteFile(io, raw) catch {};
    try ww.run(io, why, &.{ "qemu-img", "convert", "-f", "qcow2", "-O", "raw", disk, raw });
    const snapshot = try writeSnapshot(io, gpa, p, name, form, raw, work, why);
    const m = machine(arch);
    return need(io, gpa, p, &.{
        "ec2",
        "register-image",
        "--name",
        name,
        "--architecture",
        m.arch,
        "--boot-mode",
        "uefi",
        "--ena-support",
        "--virtualization-type",
        "hvm",
        "--imds-support",
        "v2.0",
        "--root-device-name",
        "/dev/xvda",
        "--block-device-mappings",
        try gpa.print(
            "DeviceName=/dev/xvda,Ebs={{SnapshotId={s},VolumeType=gp3,DeleteOnTermination=true}}",
            .{snapshot},
        ),
        "--tag-specifications",
        try gpa.print("ResourceType=image,Tags=[{{Key={s},Value={s}}}]", .{ tag, form }),
        "--query",
        "ImageId",
    }, why);
}

/// One aws put-snapshot-block at a time per slot: its block's file, and
/// where it says what went wrong.
const Slot = struct {
    child: ?std.process.Child = null,
    index: u64 = 0,
    data: []const u8,
    err: []const u8,
};

/// A snapshot of raw, a disk image, written block by block through EBS's
/// direct API, the blocks that hold data alone: what is never written
/// reads as zeros. Its id, once EBS says it is complete.
fn writeSnapshot(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    form: []const u8,
    raw: []const u8,
    work: []const u8,
    why: *ww.Why,
) ![]const u8 {
    var f = try Dir.cwd().openFile(io, raw, .{});
    defer f.close(io);
    const size = try f.length(io);
    const id = try need(io, gpa, p, &.{
        "ebs",
        "start-snapshot",
        "--volume-size",
        try gpa.print("{d}", .{gib(size)}),
        "--description",
        name,
        "--tags",
        try gpa.print("Key={s},Value={s}", .{ tag, form }),
        try gpa.print("Key=Name,Value={s}", .{name}),
        "--query",
        "SnapshotId",
    }, why);

    var slots: [parallel]Slot = undefined;
    for (&slots, 0..) |*s, i| s.* = .{
        .data = try gpa.print("{s}/block-{d}", .{ work, i }),
        .err = try gpa.print("{s}/block-{d}.err", .{ work, i }),
    };
    defer for (&slots) |*s| {
        if (s.child) |*c| _ = c.wait(io) catch {};
        Dir.cwd().deleteFile(io, s.data) catch {};
        Dir.cwd().deleteFile(io, s.err) catch {};
    };
    const buf = try gpa.alloc(u8, block_size);
    var written: u64 = 0;
    var index: u64 = 0;
    while (index * block_size < size) : (index += 1) {
        const n = try f.readPositionalAll(io, buf, index * block_size);
        @memset(buf[n..], 0);
        if (std.mem.allEqual(u8, buf, 0)) continue;
        const s = &slots[written % parallel];
        try finish(io, gpa, s, why);
        try Dir.cwd().writeFile(io, .{ .sub_path = s.data, .data = buf });
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(buf, &digest, .{});
        var sum: [44]u8 = undefined;
        const err_file = try Dir.cwd().createFile(io, s.err, .{});
        defer err_file.close(io);
        s.index = index;
        s.child = std.process.spawn(io, .{
            .argv = try aws(gpa, p, &.{
                "ebs",
                "put-snapshot-block",
                "--snapshot-id",
                id,
                "--block-index",
                try gpa.print("{d}", .{index}),
                // A streaming blob: a path, not fileb://.
                "--block-data",
                s.data,
                "--data-length",
                std.fmt.comptimePrint("{d}", .{block_size}),
                "--checksum",
                std.base64.standard.Encoder.encode(&sum, &digest),
                "--checksum-algorithm",
                "SHA256",
            }),
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .{ .file = err_file },
        }) catch |err| return why.refuse("aws ebs put-snapshot-block: {s}", .{@errorName(err)});
        written += 1;
    }
    for (&slots) |*s| try finish(io, gpa, s, why);
    ww.say(io, "image {s}: {d} blocks, {d} MiB, in snapshot {s}", .{
        name,
        written,
        written * block_size >> 20,
        id,
    });
    _ = try need(io, gpa, p, &.{
        "ebs",
        "complete-snapshot",
        "--snapshot-id",
        id,
        "--changed-blocks-count",
        try gpa.print("{d}", .{written}),
    }, why);
    const start = Io.Clock.awake.now(io);
    while (start.untilNow(io, .awake).toSeconds() < snapshot_seconds) {
        const state = ask(io, gpa, p, &.{
            "ec2",
            "describe-snapshots",
            "--snapshot-ids",
            id,
            "--query",
            "Snapshots[0].State",
        }) orelse "";
        if (std.mem.eql(u8, state, "completed")) return id;
        if (std.mem.eql(u8, state, "error"))
            return why.refuse("snapshot {s} failed after its blocks were written", .{id});
        try io.sleep(.fromSeconds(2), .awake);
    }
    return why.refuse(
        "snapshot {s} not complete after 10 minutes: aws ec2 describe-snapshots --snapshot-ids {s}",
        .{ id, id },
    );
}

/// The block a slot sent, waited for: a refusal, with what aws said, if it
/// was not taken.
fn finish(io: Io, gpa: Allocator, s: *Slot, why: *ww.Why) !void {
    var child = s.child orelse return;
    s.child = null;
    const term = child.wait(io) catch |err|
        return why.refuse("aws ebs put-snapshot-block: {s}", .{@errorName(err)});
    if (term == .exited and term.exited == 0) return;
    const said = Dir.cwd().readFileAlloc(io, s.err, gpa, .limited(64 << 10)) catch "";
    return why.refuse(
        "aws ebs put-snapshot-block, block {d}: {s}",
        .{ s.index, lastLine(said) },
    );
}

/// A disk's size in GiB, as EBS takes a volume's: rounded up.
fn gib(bytes: u64) u64 {
    return (bytes + (1 << 30) - 1) >> 30;
}

pub const Instance = struct { id: []const u8, form: []const u8 };

/// The instance named name that has not gone, and the form its tag names,
/// "" if none does; null if there is none.
pub fn find(io: Io, gpa: Allocator, p: Place, name: []const u8) ?Instance {
    const text = ask(io, gpa, p, &.{
        "ec2",
        "describe-instances",
        "--filters",
        gpa.print("Name=tag:Name,Values={s}", .{name}) catch return null,
        alive,
        "--query",
        "Reservations[].Instances[].[InstanceId,Tags[?Key=='" ++ tag ++ "'].Value|[0]]",
    }) orelse return null;
    return instance(text);
}

fn instance(text: []const u8) ?Instance {
    var lines = std.mem.tokenizeAny(u8, text, "\r\n");
    var f = std.mem.splitScalar(u8, lines.next() orelse return null, '\t');
    const id = f.next() orelse return null;
    const form = f.next() orelse "";
    return .{ .id = id, .form = if (std.mem.eql(u8, form, "None")) "" else form };
}

/// The machine's security group, werewolf-NAME, in the default VPC: no
/// rule lets anything in, and its owner adds what should.
fn securityGroup(io: Io, gpa: Allocator, p: Place, name: []const u8, why: *ww.Why) ![]const u8 {
    const group = try gpa.print("werewolf-{s}", .{name});
    if (ask(io, gpa, p, &.{
        "ec2",
        "describe-security-groups",
        "--filters",
        try gpa.print("Name=group-name,Values={s}", .{group}),
        "--query",
        "SecurityGroups[0].GroupId",
    })) |id| return id;
    return need(io, gpa, p, &.{
        "ec2",
        "create-security-group",
        "--group-name",
        group,
        "--description",
        try gpa.print("werewolf machine {s}: nothing in until allowed", .{name}),
        "--tag-specifications",
        try gpa.print("ResourceType=security-group,Tags=[{{Key=Name,Value={s}}}]", .{group}),
        "--query",
        "GroupId",
    }, why);
}

/// A default subnet in a zone that offers kind: not every zone has every
/// instance type (us-east-1e has no t4g), and AWS, left to choose, may
/// choose one that does not.
fn defaultSubnet(io: Io, gpa: Allocator, p: Place, kind: []const u8, why: *ww.Why) ![]const u8 {
    const zones = ask(io, gpa, p, &.{
        "ec2",
        "describe-instance-type-offerings",
        "--location-type",
        "availability-zone",
        "--filters",
        try gpa.print("Name=instance-type,Values={s}", .{kind}),
        "--query",
        "InstanceTypeOfferings[].Location",
    }) orelse return why.refuse("{s} is not offered in {s}", .{ kind, p.region });
    const subnets = ask(io, gpa, p, &.{
        "ec2",
        "describe-subnets",
        "--filters",
        "Name=default-for-az,Values=true",
        "--query",
        "Subnets[].[AvailabilityZone,SubnetId]",
    }) orelse return why.refuse(
        "no default VPC in {s}, which create uses: aws ec2 create-default-vpc",
        .{p.region},
    );
    return pickSubnet(zones, subnets) orelse why.refuse(
        "no default subnet in {s} is in a zone offering {s} ({s})",
        .{ p.region, kind, zones },
    );
}

/// The subnet, of describe-subnets' ZONE<tab>SUBNET lines, in the first
/// zone, by name, that zones lists: the same choice every time.
fn pickSubnet(zones: []const u8, subnets: []const u8) ?[]const u8 {
    var best: ?[]const u8 = null;
    var best_zone: []const u8 = "";
    var lines = std.mem.tokenizeAny(u8, subnets, "\r\n");
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, '\t');
        const zone = f.next() orelse continue;
        const id = f.next() orelse continue;
        var offered = std.mem.tokenizeAny(u8, zones, "\t\r\n ");
        const in_zone = while (offered.next()) |z| {
            if (std.mem.eql(u8, z, zone)) break true;
        } else false;
        if (!in_zone) continue;
        if (best == null or std.mem.lessThan(u8, zone, best_zone)) {
            best = id;
            best_zone = zone;
        }
    }
    return best;
}

/// An instance of ami, its config in user data from b64, in the default
/// VPC and its own security group: no instance profile, IMDSv2 alone, one
/// hop, so only the machine itself reaches it. size is the instance type,
/// if not the arch's smallest. Its instance id.
pub fn create(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    form: []const u8,
    arch: []const u8,
    size: ?[]const u8,
    ami: []const u8,
    b64: []const u8,
    why: *ww.Why,
) ![]const u8 {
    const kind = size orelse machine(arch).kind;
    const subnet = try defaultSubnet(io, gpa, p, kind, why);
    const group = try securityGroup(io, gpa, p, name, why);
    return need(io, gpa, p, &.{
        "ec2",
        "run-instances",
        "--image-id",
        ami,
        "--instance-type",
        kind,
        "--subnet-id",
        subnet,
        "--security-group-ids",
        group,
        // The CLI encodes run-instances' user data in base64 itself, so the
        // machine reads the file's own text, the tar in base64.
        "--user-data",
        try gpa.print("file://{s}", .{b64}),
        "--metadata-options",
        "HttpTokens=required,HttpEndpoint=enabled,HttpPutResponseHopLimit=1",
        "--tag-specifications",
        try gpa.print(
            "ResourceType=instance,Tags=[{{Key=Name,Value={s}}},{{Key={s},Value={s}}}]",
            .{ name, tag, form },
        ),
        try gpa.print("ResourceType=volume,Tags=[{{Key=Name,Value={s}}}]", .{name}),
        "--query",
        "Instances[0].InstanceId",
    }, why);
}

/// A new config for an instance: stopped, which AWS asks of it with ACPI's
/// power button, its user data replaced, which AWS allows only then, and
/// started again.
pub fn reconfigure(
    io: Io,
    gpa: Allocator,
    p: Place,
    id: []const u8,
    b64: []const u8,
    why: *ww.Why,
) !void {
    // modify-instance-attribute takes user data already in base64, unlike
    // run-instances: the base64 of the file, so the machine reads the same
    // text as it would from create.
    const text = Dir.cwd().readFileAlloc(io, b64, gpa, .limited(1 << 20)) catch |err|
        return why.refuse("{s}: {s}", .{ b64, @errorName(err) });
    const again = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(text.len));
    const value = try gpa.print("{s}.b64", .{b64});
    try ww.writePrivate(io, gpa, value, std.base64.standard.Encoder.encode(again, text), why);
    defer Dir.cwd().deleteFile(io, value) catch {};

    try ww.run(io, why, try aws(gpa, p, &.{ "ec2", "stop-instances", "--instance-ids", id }));
    try ww.run(
        io,
        why,
        try aws(gpa, p, &.{ "ec2", "wait", "instance-stopped", "--instance-ids", id }),
    );
    try ww.run(io, why, try aws(gpa, p, &.{
        "ec2",
        "modify-instance-attribute",
        "--instance-id",
        id,
        "--attribute",
        "userData",
        "--value",
        try gpa.print("file://{s}", .{value}),
    }));
    try ww.run(io, why, try aws(gpa, p, &.{ "ec2", "start-instances", "--instance-ids", id }));
}

/// The instance's public address.
pub fn address(io: Io, gpa: Allocator, p: Place, id: []const u8) ?[]const u8 {
    return ask(io, gpa, p, &.{
        "ec2",
        "describe-instances",
        "--instance-ids",
        id,
        "--query",
        "Reservations[0].Instances[0].PublicIpAddress",
    });
}

/// The serial console as Nitro keeps it now, the latest 64 KiB: what the
/// CLI decodes from base64.
pub fn console(io: Io, gpa: Allocator, p: Place, id: []const u8) ?[]const u8 {
    return ask(
        io,
        gpa,
        p,
        &.{ "ec2", "get-console-output", "--instance-id", id, "--latest", "--query", "Output" },
    );
}

/// The console of the instance's current run, if AWS has any yet. AWS
/// begins a console afresh at each start, but may answer with the last
/// run's for a while after: a console is this run's only if AWS last wrote
/// it no earlier than the instance's LaunchTime, which each start resets.
/// Not by its text: a werewolf boot is the same every time, to the pids.
fn currentConsole(io: Io, gpa: Allocator, p: Place, id: []const u8) ?[]const u8 {
    const launched = ask(io, gpa, p, &.{
        "ec2",
        "describe-instances",
        "--instance-ids",
        id,
        "--query",
        "Reservations[0].Instances[0].LaunchTime",
    }) orelse return null;
    const out = ask(io, gpa, p, &.{
        "ec2",
        "get-console-output",
        "--instance-id",
        id,
        "--latest",
        "--query",
        "[Timestamp,Output]",
    }) orelse return null;
    return ofRun(out, launched);
}

/// get-console-output's TIMESTAMP<tab>OUTPUT, the output if it was written
/// at or after launched. AWS writes both times as UTC, alike, so their
/// order is their bytes'.
fn ofRun(out: []const u8, launched: []const u8) ?[]const u8 {
    const tab = std.mem.findScalar(u8, out, '\t') orelse return null;
    const text = out[tab + 1 ..];
    if (std.mem.eql(u8, text, "None")) return null;
    return if (std.mem.order(u8, out[0..tab], launched) == .lt) null else text;
}

/// Wait for this run's boot to finish, or panic.
pub fn awaitUp(io: Io, gpa: Allocator, p: Place, id: []const u8) !enum { up, panic, late } {
    const start = Io.Clock.awake.now(io);
    while (start.untilNow(io, .awake).toSeconds() < wait_seconds) {
        if (currentConsole(io, gpa, p, id)) |text| {
            if (std.mem.find(u8, text, "werewolf: up in ") != null) return .up;
            if (std.mem.find(u8, text, "Kernel panic") != null) return .panic;
        }
        try io.sleep(.fromSeconds(2), .awake);
    }
    return .late;
}

/// The instance, then its security group, which AWS frees only once the
/// instance has gone. Its volume goes with it; the AMI stays.
pub fn delete(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    inst: ?Instance,
    why: *ww.Why,
) !void {
    if (inst) |i| {
        try ww.run(
            io,
            why,
            try aws(gpa, p, &.{ "ec2", "terminate-instances", "--instance-ids", i.id }),
        );
        try ww.run(
            io,
            why,
            try aws(gpa, p, &.{ "ec2", "wait", "instance-terminated", "--instance-ids", i.id }),
        );
    }
    if (ask(io, gpa, p, &.{
        "ec2",
        "describe-security-groups",
        "--filters",
        try gpa.print("Name=group-name,Values=werewolf-{s}", .{name}),
        "--query",
        "SecurityGroups[0].GroupId",
    })) |group| try ww.run(
        io,
        why,
        try aws(gpa, p, &.{ "ec2", "delete-security-group", "--group-id", group }),
    );
}

const testing = std.testing;

test machine {
    try testing.expectEqualStrings("t4g.small", machine("aarch64").kind);
    try testing.expectEqualStrings("x86_64", machine("x86_64").arch);
}

test gib {
    try testing.expectEqual(@as(u64, 8), gib(8 << 30));
    try testing.expectEqual(@as(u64, 9), gib((8 << 30) + 1));
    try testing.expectEqual(@as(u64, 1), gib(1));
    // A disk is whole blocks, or its last is padded with zeros.
    try testing.expectEqual(@as(u64, 0), (8 << 30) % block_size);
}

test pickSubnet {
    const subnets = "us-east-1e\tsubnet-e\nus-east-1b\tsubnet-b\nus-east-1a\tsubnet-a\n";
    try testing.expectEqualStrings(
        "subnet-a",
        pickSubnet("us-east-1b\tus-east-1a\tus-east-1c", subnets).?,
    );
    try testing.expectEqualStrings("subnet-b", pickSubnet("us-east-1b", subnets).?);
    try testing.expectEqual(null, pickSubnet("us-east-1f", subnets));
}

test instance {
    const i = instance("i-0abc\tprod\ni-0def\tNone\n").?;
    try testing.expectEqualStrings("i-0abc", i.id);
    try testing.expectEqualStrings("prod", i.form);
    try testing.expectEqualStrings("", instance("i-0def\tNone").?.form);
    try testing.expectEqual(null, instance(""));
}

test ofRun {
    const launched = "2026-10-08T00:51:11+00:00";
    // This run's console.
    try testing.expectEqualStrings(
        "UEFI\r\nwerewolf: up in 1.3s\r\n",
        ofRun("2026-10-08T00:58:10+00:00\tUEFI\r\nwerewolf: up in 1.3s\r\n", launched).?,
    );
    // The run before's, written before this one began: not this run's.
    try testing.expectEqual(
        null,
        ofRun("2026-10-08T00:50:14+00:00\twerewolf: up in 1.5s\r\n", launched),
    );
    try testing.expectEqual(null, ofRun("2026-10-08T00:58:10+00:00\tNone", launched));
    try testing.expectEqual(null, ofRun("", launched));
}

test lastLine {
    try testing.expectEqualStrings("b", lastLine("a\nb\n"));
    try testing.expectEqualStrings("a", lastLine("a"));
    try testing.expectEqualStrings(
        "(NoRegion): You must specify a region.",
        lastLine("\naws: [ERROR]: An error occurred (NoRegion): You must specify a region.\n"),
    );
}
