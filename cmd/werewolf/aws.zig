//! AWS: a werewolf machine on EC2, from the same two files every target
//! takes. The boot disk becomes an AMI, named as GCP's image is
//! (image.zig): converted to a dynamic VHD, which holds only the blocks
//! written (tens of MiB of an 8 GiB disk), put in S3, imported as an EBS
//! snapshot by VM Import, and registered for UEFI, the ENA and IMDSv2
//! alone. The config tar, in base64, is the instance's user data, which
//! cloud-metadata fetches through IMDSv2 (docs/cloud.md). The instance has
//! no instance profile, and a security group of its own, werewolf-NAME,
//! which lets nothing in until its owner says what may.
//!
//! The region and credentials are the aws CLI's own (aws configure, or
//! AWS_REGION and AWS_PROFILE). Two things werewolf does not make, and
//! names when they are missing (docs/service-vms.md#aws-vm): the bucket VM
//! Import reads, werewolf-images-ACCOUNT-REGION, and VM Import's service
//! role, vmimport. A tool that makes IAM roles on a retry is not one an
//! SRE wants. AWS is the state: an instance's Name tag is its name, and
//! its werewolf-form tag the form it was made from.

const std = @import("std");
const ww = @import("werewolf.zig");
const images = @import("image.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// How long create waits for a machine to say it is up.
const wait_seconds = 300;
/// How long VM Import may take; a small disk takes minutes.
const import_seconds = 3600;
const tag = "werewolf-form";
/// The states of an instance that has not gone, nor is going.
const alive = "Name=instance-state-name,Values=pending,running,stopping,stopped";

pub const Place = struct { region: []const u8, account: []const u8 };

/// The region and account the aws CLI works in, or a refusal saying why
/// not. The region is the one the CLI resolves, from the environment or
/// its config, as an EC2 call shows it.
pub fn place(io: Io, gpa: Allocator, why: *ww.Why) !Place {
    const region = call(io, gpa, &.{
        "aws",                             "ec2",
        "describe-availability-zones",     "--query",
        "AvailabilityZones[0].RegionName", "--output",
        "text",
    });
    // The CLI's own words say what to set: a region, or credentials.
    if (!region.ok) return why.refuse("--on aws: {s}", .{lastLine(region.err)});
    const account = call(
        io,
        gpa,
        &.{ "aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text" },
    );
    if (!account.ok) return why.refuse("--on aws: {s}", .{lastLine(account.err)});
    return .{ .region = region.out, .account = account.out };
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

/// The bucket VM Import reads the disk from: S3's names are global, so the
/// account's and region's.
pub fn bucket(gpa: Allocator, p: Place) ![]const u8 {
    return gpa.print("werewolf-images-{s}-{s}", .{ p.account, p.region });
}

/// The AMI of disk, a release's disk.qcow2: there already, or imported
/// through the bucket, whose upload is then deleted.
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

    // What werewolf does not make, named before anything is uploaded.
    const b = try bucket(gpa, p);
    const head = call(io, gpa, try aws(gpa, p, &.{ "s3api", "head-bucket", "--bucket", b }));
    if (!head.ok) return why.refuse(
        "no bucket {s} for VM Import to read ({s}): make it once, aws s3api create-bucket " ++
            "--bucket {s}{s}{s} (docs/service-vms.md#aws-vm)",
        .{
            b,
            lastLine(head.err),
            b,
            if (std.mem.eql(u8, p.region, "us-east-1"))
                ""
            else
                " --create-bucket-configuration LocationConstraint=",
            if (std.mem.eql(u8, p.region, "us-east-1")) "" else p.region,
        },
    );
    // Asking needs iam:GetRole, which a deployer may not have: only an
    // answer that the role is missing stops here; the import says the rest.
    const role = call(io, gpa, try aws(gpa, p, &.{ "iam", "get-role", "--role-name", "vmimport" }));
    if (!role.ok and std.mem.find(u8, role.err, "NoSuchEntity") != null) return why.refuse(
        "no vmimport role, which VM Import takes to read {s} and make the snapshot: make it " ++
            "once, as docs/service-vms.md#aws-vm says",
        .{b},
    );

    ww.say(io, "image {s}: making it from {s}", .{ name, disk });
    const vhd = try gpa.print("{s}/disk.vhd", .{work});
    defer Dir.cwd().deleteFile(io, vhd) catch {};
    // force_size keeps the disk's own size, which VHD's geometry would
    // otherwise round, and with it the GPT's backup at the disk's end.
    try ww.run(io, why, &.{
        "qemu-img", "convert",                         "-f", "qcow2", "-O", "vpc",
        "-o",       "subformat=dynamic,force_size=on", disk, vhd,
    });
    const key = try gpa.print("{s}.vhd", .{name});
    const object = try gpa.print("s3://{s}/{s}", .{ b, key });
    try ww.run(io, why, try aws(gpa, p, &.{ "s3", "cp", "--only-show-errors", vhd, object }));
    defer _ = ask(io, gpa, p, &.{ "s3", "rm", "--only-show-errors", object });

    const task = try need(io, gpa, p, &.{
        "ec2",
        "import-snapshot",
        "--description",
        name,
        "--disk-container",
        try gpa.print("Format=VHD,UserBucket={{S3Bucket={s},S3Key={s}}}", .{ b, key }),
        "--query",
        "ImportTaskId",
    }, why);
    const snapshot = try awaitImport(io, gpa, p, name, task, why);
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

/// The snapshot VM Import made, once its task is done.
fn awaitImport(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    task: []const u8,
    why: *ww.Why,
) ![]const u8 {
    var last: []const u8 = "";
    var waited: u32 = 0;
    while (waited < import_seconds) : (waited += 15) {
        const text = ask(io, gpa, p, &.{
            "ec2",
            "describe-import-snapshot-tasks",
            "--import-task-ids",
            task,
            "--query",
            "ImportSnapshotTasks[0].SnapshotTaskDetail.[Status,SnapshotId,StatusMessage,Progress]",
        }) orelse "";
        const t = importTask(text);
        if (std.mem.eql(u8, t.status, "completed")) return t.snapshot;
        if (std.mem.eql(u8, t.status, "deleting") or std.mem.eql(u8, t.status, "deleted"))
            return why.refuse("VM Import {s} failed: {s}", .{ task, t.message });
        if (!std.mem.eql(u8, text, last)) {
            ww.say(io, "image {s}: importing, {s} {s}%", .{ name, t.message, t.progress });
            last = text;
        }
        try io.sleep(.fromSeconds(15), .awake);
    }
    return why.refuse(
        "VM Import {s} not done after an hour: aws ec2 describe-import-snapshot-tasks " ++
            "--import-task-ids {s}",
        .{ task, task },
    );
}

const ImportTask = struct {
    status: []const u8 = "",
    snapshot: []const u8 = "",
    message: []const u8 = "",
    progress: []const u8 = "",
};

/// describe-import-snapshot-tasks's line: status, snapshot, message and
/// progress, tab-separated, None for what is not there yet.
fn importTask(text: []const u8) ImportTask {
    var f = std.mem.splitScalar(u8, text, '\t');
    return .{
        .status = f.next() orelse "",
        .snapshot = f.next() orelse "",
        .message = f.next() orelse "",
        .progress = f.next() orelse "",
    };
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
    var waited: u32 = 0;
    while (waited < wait_seconds) : (waited += 5) {
        if (currentConsole(io, gpa, p, id)) |text| {
            if (std.mem.find(u8, text, "werewolf: up in ") != null) return .up;
            if (std.mem.find(u8, text, "Kernel panic") != null) return .panic;
        }
        try io.sleep(.fromSeconds(5), .awake);
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

test bucket {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const b = try bucket(
        arena.allocator(),
        .{ .region = "eu-central-1", .account = "123456789012" },
    );
    try testing.expectEqualStrings("werewolf-images-123456789012-eu-central-1", b);
    try testing.expect(b.len <= 63);
}

test importTask {
    const t = importTask("active\tNone\tpending\t3");
    try testing.expectEqualStrings("active", t.status);
    try testing.expectEqualStrings("3", t.progress);
    try testing.expectEqualStrings(
        "snap-0123",
        importTask("completed\tsnap-0123\tNone\tNone").snapshot,
    );
    try testing.expectEqualStrings("", importTask("").snapshot);
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
