//! aws runs werewolf machines on EC2 through the aws CLI. It writes images
//! straight into EBS snapshots, so it needs no S3 bucket, VM Import or
//! service role. See README.md.

const std = @import("std");
const howl = @import("howl.zig");
const images = @import("image.zig");
const booting = @import("boot.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// wait_seconds is how long create waits for the machine to boot.
const wait_seconds = 300;
/// block_size is the unit of the EBS direct snapshot API.
const block_size = 512 << 10;
/// parallel is how many blocks upload at once. Each is an aws process that
/// mostly waits on the network.
const parallel = 8;
/// snapshot_seconds is how long a snapshot may take to complete once all
/// its blocks are written.
const snapshot_seconds = 600;
const tag = howl.form_tag;
/// alive filters out instances that are terminated or shutting down.
const alive = "Name=instance-state-name,Values=pending,running,stopping,stopped";

pub const Place = struct { region: []const u8 };

/// place returns the region the aws CLI resolves from its config or the
/// environment. It asks EC2, which also checks the credentials, and refuses
/// with the CLI's error.
pub fn place(io: Io, gpa: Allocator, why: *howl.Why) !Place {
    const region = call(io, gpa, &.{
        "aws",                             "ec2",
        "describe-availability-zones",     "--query",
        "AvailabilityZones[0].RegionName", "--output",
        "text",
    });
    // The CLI's error says whether a region or credentials are missing.
    if (!region.ok) return why.refuse("--on aws: {s}", .{lastLine(region.err)});
    return .{ .region = region.out };
}

const Result = struct { ok: bool, out: []const u8 = "", err: []const u8 = "" };

/// call runs argv and returns its trimmed stdout and stderr and whether it
/// succeeded.
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

/// aws returns the argv that runs aws with args in p's region, with text
/// output.
fn aws(gpa: Allocator, p: Place, args: []const []const u8) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{ "aws", "--region", p.region, "--output", "text" });
    try argv.appendSlice(gpa, args);
    return argv.items;
}

/// ask runs aws and returns its output, or null if it failed or printed
/// nothing or "None".
fn ask(io: Io, gpa: Allocator, p: Place, args: []const []const u8) ?[]const u8 {
    const r = call(io, gpa, aws(gpa, p, args) catch return null);
    if (!r.ok or r.out.len == 0 or std.mem.eql(u8, r.out, "None")) return null;
    return r.out;
}

/// need runs aws and returns its output, or refuses with its error.
fn need(io: Io, gpa: Allocator, p: Place, args: []const []const u8, why: *howl.Why) ![]const u8 {
    const r = call(io, gpa, try aws(gpa, p, args));
    if (!r.ok) return why.refuse("aws {s} {s}: {s}", .{ args[0], args[1], lastLine(r.err) });
    return r.out;
}

/// lastLine returns the last line of the CLI's error without its prefix,
/// such as "(NoRegion): You must specify a region.".
fn lastLine(text: []const u8) []const u8 {
    const t = std.mem.trimEnd(u8, text, " \r\n");
    var line = t[if (std.mem.findScalarLast(u8, t, '\n')) |nl| nl + 1 else 0..];
    for ([_][]const u8{ "aws: [ERROR]: ", "An error occurred " }) |prefix| {
        if (std.mem.startsWith(u8, line, prefix)) line = line[prefix.len..];
    }
    return line;
}

/// Machine holds AWS's name for an arch and the smallest Nitro instance
/// type with 2 GiB. Nitro means NVMe disks and the ENA NIC, which prod's
/// modules include.
pub const Machine = struct { arch: []const u8, size: []const u8 };

pub fn machine(arch: howl.Arch) Machine {
    return switch (arch) {
        .aarch64 => .{ .arch = "arm64", .size = "t4g.small" },
        .x86_64 => .{ .arch = "x86_64", .size = "t3.small" },
    };
}

/// ensureImage returns the id of the AMI for disk (a disk.qcow2), creating
/// it from a snapshot if needed. The AMI boots UEFI, uses ENA, and allows
/// only IMDSv2.
pub fn ensureImage(
    io: Io,
    gpa: Allocator,
    p: Place,
    form: []const u8,
    arch: howl.Arch,
    disk: []const u8,
    work: []const u8,
    why: *howl.Why,
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
        howl.say(io, "image {s}: there already, {s}", .{ name, id });
        return id;
    }
    howl.say(io, "image {s}: making it from {s}", .{ name, disk });
    // Convert to raw so each block sits at its offset; empty space stays
    // sparse.
    const raw = try gpa.print("{s}/disk.raw", .{work});
    defer Dir.cwd().deleteFile(io, raw) catch {};
    try howl.run(io, why, &.{ "qemu-img", "convert", "-f", "qcow2", "-O", "raw", disk, raw });
    const snapshot = try writeSnapshot(io, gpa, p, name, form, raw, work, why);
    errdefer _ = ask(io, gpa, p, &.{ "ec2", "delete-snapshot", "--snapshot-id", snapshot });
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

/// Slot runs one aws put-snapshot-block at a time. data holds the block and
/// err receives the command's stderr.
const Slot = struct {
    child: ?std.process.Child = null,
    index: u64 = 0,
    data: []const u8,
    err: []const u8,
};

/// writeSnapshot writes raw into a new snapshot through the EBS direct API
/// and returns its id once complete. It skips all-zero blocks, which read
/// as zeros anyway; an 8 GiB disk has about a hundred blocks of data.
fn writeSnapshot(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    form: []const u8,
    raw: []const u8,
    work: []const u8,
    why: *howl.Why,
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
    // Delete a half-written snapshot if a later step fails, so it is not
    // billed.
    errdefer _ = ask(io, gpa, p, &.{ "ec2", "delete-snapshot", "--snapshot-id", id });

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
                // A streaming blob takes a path, not fileb://.
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
    howl.say(io, "image {s}: {d} blocks, {d} MiB, in snapshot {s}", .{
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

/// finish waits for the slot's upload, refusing with aws's error if it
/// failed.
fn finish(io: Io, gpa: Allocator, s: *Slot, why: *howl.Why) !void {
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

/// gib returns bytes in GiB, rounded up, as EBS sizes volumes.
fn gib(bytes: u64) u64 {
    return (bytes + (1 << 30) - 1) >> 30;
}

/// Instance is a live instance and its form tag, "" if it has none.
pub const Instance = struct { id: []const u8, form: []const u8 };

/// find returns the live instance whose Name tag is name, or null.
pub fn find(io: Io, gpa: Allocator, p: Place, name: []const u8, why: *howl.Why) !?Instance {
    // Use need, not ask: treating a failure such as an expired login as
    // "no instance" would make delete forget an instance that still runs.
    const text = try need(io, gpa, p, &.{
        "ec2",
        "describe-instances",
        "--filters",
        try gpa.print("Name=tag:Name,Values={s}", .{name}),
        alive,
        "--query",
        "Reservations[].Instances[].[InstanceId,Tags[?Key=='" ++ tag ++ "'].Value|[0]]",
    }, why);
    return if (std.mem.eql(u8, text, "None")) null else instance(text);
}

fn instance(text: []const u8) ?Instance {
    var lines = std.mem.tokenizeAny(u8, text, "\r\n");
    var f = std.mem.splitScalar(u8, lines.next() orelse return null, '\t');
    const id = f.next() orelse return null;
    const form = f.next() orelse "";
    return .{ .id = id, .form = if (std.mem.eql(u8, form, "None")) "" else form };
}

/// securityGroup returns the id of werewolf-NAME in the default VPC,
/// creating it if needed. It has no inbound rules; openArgs adds them.
fn securityGroup(io: Io, gpa: Allocator, p: Place, name: []const u8, why: *howl.Why) ![]const u8 {
    const group = try gpa.print("werewolf-{s}", .{name});
    if (try groupId(io, gpa, p, group)) |id| return id;
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

/// groupId returns the id of the security group named group, or null.
fn groupId(io: Io, gpa: Allocator, p: Place, group: []const u8) !?[]const u8 {
    return ask(io, gpa, p, &.{
        "ec2",
        "describe-security-groups",
        "--filters",
        try gpa.print("Name=group-name,Values={s}", .{group}),
        "--query",
        "SecurityGroups[0].GroupId",
    });
}

/// defaultSubnet returns a default subnet in a zone that offers size. Not
/// every zone has every type (us-east-1e has no t4g), and AWS may pick one
/// that lacks it.
fn defaultSubnet(io: Io, gpa: Allocator, p: Place, size: []const u8, why: *howl.Why) ![]const u8 {
    const zones = ask(io, gpa, p, &.{
        "ec2",
        "describe-instance-type-offerings",
        "--location-type",
        "availability-zone",
        "--filters",
        try gpa.print("Name=instance-type,Values={s}", .{size}),
        "--query",
        "InstanceTypeOfferings[].Location",
    }) orelse return why.refuse("{s} is not offered in {s}", .{ size, p.region });
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
        .{ p.region, size, zones },
    );
}

/// pickSubnet returns the subnet, from describe-subnets' ZONE<tab>SUBNET
/// lines, in the alphabetically first zone that zones lists, so the choice
/// is stable.
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

/// create launches an instance of ami with b64, the base64 config tar, as its
/// user data, and returns its id. It gets no instance profile, and IMDSv2
/// with a hop limit of 1, so only the machine itself reaches the metadata.
/// A null size picks machine(arch).size.
pub fn create(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    form: []const u8,
    arch: howl.Arch,
    size: ?[]const u8,
    ami: []const u8,
    b64: []const u8,
    why: *howl.Why,
) ![]const u8 {
    const instance_type = size orelse machine(arch).size;
    const subnet = try defaultSubnet(io, gpa, p, instance_type, why);
    const group = try securityGroup(io, gpa, p, name, why);
    // The CLI retries a launch whose reply it lost; the token makes AWS
    // treat the retry as the same launch, not a second instance. Make it
    // fresh: a token reused after a delete would return the terminated one.
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    return need(io, gpa, p, &.{
        "ec2",
        "run-instances",
        "--client-token",
        try gpa.print("{s}-{x}", .{ name, std.mem.readInt(u64, &nonce, .little) }),
        "--image-id",
        ami,
        "--instance-type",
        instance_type,
        "--subnet-id",
        subnet,
        "--security-group-ids",
        group,
        // The CLI base64-encodes run-instances' user data itself, so the
        // machine reads the file's text: the tar in base64.
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

/// reconfigure stops the instance (AWS presses the ACPI power button),
/// replaces its user data, which AWS allows only while stopped, and starts it.
pub fn reconfigure(
    io: Io,
    gpa: Allocator,
    p: Place,
    id: []const u8,
    b64: []const u8,
    why: *howl.Why,
) !void {
    // Unlike run-instances, modify-instance-attribute does not encode user
    // data, so encode the file again; the machine then reads the same text
    // as after create.
    const text = Dir.cwd().readFileAlloc(io, b64, gpa, .limited(1 << 20)) catch |err|
        return why.refuse("{s}: {s}", .{ b64, @errorName(err) });
    const again = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(text.len));
    const value = try gpa.print("{s}.b64", .{b64});
    try howl.writePrivate(io, gpa, value, std.base64.standard.Encoder.encode(again, text), why);
    defer Dir.cwd().deleteFile(io, value) catch {};

    try howl.run(io, why, try aws(gpa, p, &.{ "ec2", "stop-instances", "--instance-ids", id }));
    try howl.run(
        io,
        why,
        try aws(gpa, p, &.{ "ec2", "wait", "instance-stopped", "--instance-ids", id }),
    );
    try howl.run(io, why, try aws(gpa, p, &.{
        "ec2",
        "modify-instance-attribute",
        "--instance-id",
        id,
        "--attribute",
        "userData",
        "--value",
        try gpa.print("file://{s}", .{value}),
    }));
    try howl.run(io, why, try aws(gpa, p, &.{ "ec2", "start-instances", "--instance-ids", id }));
}

/// address returns the instance's public IP address.
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

/// console returns the latest 64 KiB of the serial console, decoded by the
/// CLI.
pub fn console(io: Io, gpa: Allocator, p: Place, id: []const u8) ?[]const u8 {
    return ask(
        io,
        gpa,
        p,
        &.{ "ec2", "get-console-output", "--instance-id", id, "--latest", "--query", "Output" },
    );
}

/// currentConsole returns the console of the instance's current run, or
/// null. After a start, AWS may return the previous run's console for a
/// while, so it compares the console's timestamp with LaunchTime, which each
/// start resets. The text cannot tell: every boot prints the same lines.
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

/// ofRun returns the OUTPUT of get-console-output's TIMESTAMP<tab>OUTPUT if
/// it was written at or after launched. AWS writes both times in the same
/// UTC format, so comparing bytes compares times.
fn ofRun(out: []const u8, launched: []const u8) ?[]const u8 {
    const tab = std.mem.findScalar(u8, out, '\t') orelse return null;
    const text = out[tab + 1 ..];
    if (std.mem.eql(u8, text, "None")) return null;
    return if (std.mem.order(u8, out[0..tab], launched) == .lt) null else text;
}

/// awaitUp waits for this run's boot to finish or panic.
pub fn awaitUp(io: Io, gpa: Allocator, p: Place, id: []const u8) !booting.Outcome {
    const start = Io.Clock.awake.now(io);
    while (start.untilNow(io, .awake).toSeconds() < wait_seconds) {
        if (currentConsole(io, gpa, p, id)) |text| if (booting.outcome(text)) |o| return o;
        try io.sleep(.fromSeconds(2), .awake);
    }
    return .late;
}

/// openArgs returns the commands that let source reach the instance on
/// ports: one rule per port in werewolf-NAME. delete removes the group.
pub fn openArgs(
    gpa: Allocator,
    p: Place,
    name: []const u8,
    ports: []const u16,
    source: []const u8,
) ![]const []const []const u8 {
    const all = try gpa.alloc([]const []const u8, ports.len);
    for (ports, all) |port, *argv| argv.* = try gpa.dupe([]const u8, &.{
        "aws",                                  "ec2",
        "authorize-security-group-ingress",     "--region",
        p.region,                               "--group-name",
        try gpa.print("werewolf-{s}", .{name}), "--protocol",
        "tcp",                                  "--port",
        try gpa.print("{d}", .{port}),          "--cidr",
        source,                                 "--output",
        "text",
    });
    return all;
}

/// delete terminates the instance and its volume, waits, then deletes its
/// security group, which AWS frees only after. The AMI stays.
pub fn delete(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    inst: ?Instance,
    why: *howl.Why,
) !void {
    if (inst) |i| {
        try howl.run(
            io,
            why,
            try aws(gpa, p, &.{ "ec2", "terminate-instances", "--instance-ids", i.id }),
        );
        try howl.run(
            io,
            why,
            try aws(gpa, p, &.{ "ec2", "wait", "instance-terminated", "--instance-ids", i.id }),
        );
    }
    if (try groupId(io, gpa, p, try gpa.print("werewolf-{s}", .{name}))) |group| try howl.run(
        io,
        why,
        try aws(gpa, p, &.{ "ec2", "delete-security-group", "--group-id", group }),
    );
}

const testing = std.testing;

test openArgs {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const c = try openArgs(
        arena.allocator(),
        .{ .region = "us-east-1" },
        "web",
        &.{ 22, 8080 },
        "10.0.0.0/8",
    );
    try testing.expectEqual(@as(usize, 2), c.len);
    try testing.expectEqualStrings("werewolf-web", c[0][6]);
    try testing.expectEqualStrings("8080", c[1][10]);
    try testing.expectEqualStrings("10.0.0.0/8", c[1][12]);
}

test machine {
    try testing.expectEqualStrings("t4g.small", machine(.aarch64).size);
    try testing.expectEqualStrings("x86_64", machine(.x86_64).arch);
}

test gib {
    try testing.expectEqual(@as(u64, 8), gib(8 << 30));
    try testing.expectEqual(@as(u64, 9), gib((8 << 30) + 1));
    try testing.expectEqual(@as(u64, 1), gib(1));
    // A disk is whole blocks; otherwise the last one is zero-padded.
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
    // The previous run's console, written before this launch.
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
