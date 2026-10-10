//! gcp runs werewolf machines on Google Compute Engine through the gcloud CLI.
//! See README.md.

const std = @import("std");
const howl = @import("howl.zig");
const images = @import("image.zig");
const booting = @import("boot.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// wait_seconds is how long create waits for the machine to boot.
const wait_seconds = 300;
const label = howl.form_tag;

pub const Place = struct { project: []const u8, zone: []const u8 };

/// place returns gcloud's configured project and zone. The zone defaults to
/// us-central1-a, which has Arm machines. It refuses if gcloud has no project.
pub fn place(io: Io, gpa: Allocator, why: *howl.Why) !Place {
    const project = configValue(io, gpa, "project") orelse
        return why.refuse(
            "--on gcp: no gcloud, or no project: gcloud auth login, gcloud config set project " ++
                "PROJECT",
            .{},
        );
    return .{
        .project = project,
        .zone = configValue(io, gpa, "compute/zone") orelse "us-central1-a",
    };
}

fn configValue(io: Io, gpa: Allocator, key: []const u8) ?[]const u8 {
    const r = std.process.run(
        gpa,
        io,
        .{ .argv = &.{ "gcloud", "config", "get-value", key } },
    ) catch return null;
    const v = std.mem.trim(u8, r.stdout, " \n");
    return if (r.term == .exited and r.term.exited == 0 and v.len > 0) v else null;
}

/// gcloud returns the argv that runs gcloud quietly in p's project with args.
fn gcloud(gpa: Allocator, p: Place, args: []const []const u8) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{ "gcloud", "--quiet", "--project", p.project });
    try argv.appendSlice(gpa, args);
    return argv.items;
}

/// ask runs gcloud and returns its trimmed output, or null if it failed.
fn ask(io: Io, gpa: Allocator, p: Place, args: []const []const u8) ?[]const u8 {
    const r = std.process.run(
        gpa,
        io,
        .{ .argv = gcloud(gpa, p, args) catch return null },
    ) catch return null;
    return if (r.term == .exited and r.term.exited == 0)
        std.mem.trim(u8, r.stdout, " \n")
    else
        null;
}

/// Machine holds GCP's name for an arch, the default machine type, and the
/// NIC type werewolf has a driver for.
pub const Machine = struct { arch: []const u8, size: []const u8, nic: []const u8 };

pub fn machine(arch: howl.Arch) Machine {
    return switch (arch) {
        .aarch64 => .{ .arch = "ARM64", .size = "t2a-standard-1", .nic = "GVNIC" },
        .x86_64 => .{ .arch = "X86_64", .size = "e2-medium", .nic = "VIRTIO_NET" },
    };
}

/// ensureImage returns the name of the image for disk (a disk.qcow2), creating
/// it if needed. The upload goes through bucket PROJECT-werewolf-images and is
/// deleted afterwards.
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
    if (ask(
        io,
        gpa,
        p,
        &.{ "compute", "images", "describe", name, "--format", "value(name)" },
    ) != null) {
        howl.say(io, "image {s}: there already", .{name});
        return name;
    }
    howl.say(io, "image {s}: making it from {s}", .{ name, disk });
    // GCP wants disk.raw in a gzipped GNU-format tar. GNU tar keeps the
    // disk sparse; bsdtar writes the holes as zeros, which gzip shrinks.
    const raw = try gpa.print("{s}/disk.raw", .{work});
    const tarball = try gpa.print("{s}/image.tar.gz", .{work});
    defer Dir.cwd().deleteFile(io, raw) catch {};
    defer Dir.cwd().deleteFile(io, tarball) catch {};
    try howl.run(io, why, &.{ "qemu-img", "convert", "-f", "qcow2", "-O", "raw", disk, raw });
    const v = std.process.run(gpa, io, .{ .argv = &.{ "tar", "--version" } }) catch null;
    const gnu = if (v) |r| std.mem.find(u8, r.stdout, "GNU tar") != null else false;
    try howl.run(io, why, &.{
        "tar",
        "-C",
        work,
        if (gnu) "--format=oldgnu" else "--format=gnutar",
        if (gnu) "-Sczf" else "-czf",
        tarball,
        "disk.raw",
    });
    const bucket = try gpa.print("gs://{s}-werewolf-images", .{p.project});
    const region = p.zone[0 .. std.mem.findScalarLast(u8, p.zone, '-') orelse p.zone.len];
    if (ask(
        io,
        gpa,
        p,
        &.{ "storage", "buckets", "describe", bucket, "--format", "value(name)" },
    ) == null) {
        try howl.run(io, why, try gcloud(gpa, p, &.{
            "storage",                       "buckets",
            "create",                        bucket,
            "--location",                    region,
            "--uniform-bucket-level-access",
        }));
    }
    const object = try gpa.print("{s}/{s}.tar.gz", .{ bucket, name });
    try howl.run(io, why, try gcloud(gpa, p, &.{ "storage", "cp", tarball, object }));
    defer _ = ask(io, gpa, p, &.{ "storage", "rm", object });
    try howl.run(io, why, try gcloud(gpa, p, &.{
        "compute",
        "images",
        "create",
        name,
        "--source-uri",
        object,
        "--architecture",
        machine(arch).arch,
        "--guest-os-features",
        "UEFI_COMPATIBLE,GVNIC",
        "--labels",
        try gpa.print("{s}={s}", .{ label, form }),
        // Store the image in the zone's region, not GCP's default
        // multi-region, so it is not copied across regions.
        "--storage-location",
        region,
    }));
    return name;
}

/// formOf returns the form label of instance name, "" if it has none, or null
/// if there is no such instance. Any other gcloud failure, such as an expired
/// login, is refused: treating it as "no instance" would make delete forget a
/// machine that is still running.
pub fn formOf(io: Io, gpa: Allocator, p: Place, name: []const u8, why: *howl.Why) !?[]const u8 {
    const r = std.process.run(gpa, io, .{ .argv = try gcloud(gpa, p, &.{
        "compute",  "instances",                     "describe", name, "--zone", p.zone,
        "--format", "value(labels." ++ label ++ ")",
    }) }) catch |err| return why.refuse("gcloud: {s}", .{@errorName(err)});
    if (r.term == .exited and r.term.exited == 0) return std.mem.trim(u8, r.stdout, " \n");
    if (std.mem.find(u8, r.stderr, "was not found") != null) return null;
    const e = std.mem.trimEnd(u8, r.stderr, " \r\n");
    return why.refuse("gcloud compute instances describe {s}: {s}", .{
        name,
        e[if (std.mem.findScalarLast(u8, e, '\n')) |nl| nl + 1 else 0..],
    });
}

/// create starts VM name from image, with the base64 config file b64 as its
/// user-data. It has no service account or scopes, and Secure Boot is off
/// because werewolf's loader does not support it yet. A null size picks
/// machine(arch).size.
pub fn create(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    form: []const u8,
    arch: howl.Arch,
    size: ?[]const u8,
    image: []const u8,
    b64: []const u8,
    why: *howl.Why,
) !void {
    const m = machine(arch);
    try howl.run(io, why, try gcloud(gpa, p, &.{
        "compute",
        "instances",
        "create",
        name,
        "--zone",
        p.zone,
        "--machine-type",
        size orelse m.size,
        "--image",
        image,
        // Use SSD, not GCP's HDD default (pd-standard), which read an 8 GB
        // disk at ~10 MB/s and ~6 ms a request. On a t2a-standard-1, reboot
        // to ssh took 3.8 s on pd-balanced against 5.3 s, for $0.10 a
        // GB-month against $0.04.
        "--boot-disk-type",
        "pd-balanced",
        "--network-interface",
        try gpa.print("nic-type={s}", .{m.nic}),
        "--tags",
        name,
        "--labels",
        try gpa.print("{s}={s}", .{ label, form }),
        "--no-service-account",
        "--no-scopes",
        "--no-shielded-secure-boot",
        "--metadata-from-file",
        try gpa.print("user-data={s}", .{b64}),
    }));
}

/// reconfigure replaces the instance's user-data with b64, then stops and
/// starts it. GCP stops the machine by pressing its power button.
pub fn reconfigure(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    b64: []const u8,
    why: *howl.Why,
) !void {
    try howl.run(io, why, try gcloud(gpa, p, &.{
        "compute",              "instances",
        "add-metadata",         name,
        "--zone",               p.zone,
        "--metadata-from-file", try gpa.print("user-data={s}", .{b64}),
    }));
    try howl.run(
        io,
        why,
        try gcloud(gpa, p, &.{ "compute", "instances", "stop", name, "--zone", p.zone }),
    );
    try howl.run(
        io,
        why,
        try gcloud(gpa, p, &.{ "compute", "instances", "start", name, "--zone", p.zone }),
    );
}

/// address returns the instance's external IP address.
pub fn address(io: Io, gpa: Allocator, p: Place, name: []const u8) ?[]const u8 {
    return ask(io, gpa, p, &.{
        "compute",
        "instances",
        "describe",
        name,
        "--zone",
        p.zone,
        "--format",
        "get(networkInterfaces[0].accessConfigs[0].natIP)",
    });
}

/// console returns the instance's serial console output.
pub fn console(io: Io, gpa: Allocator, p: Place, name: []const u8) ?[]const u8 {
    return ask(
        io,
        gpa,
        p,
        &.{ "compute", "instances", "get-serial-port-output", name, "--zone", p.zone },
    );
}

/// awaitUp waits for the boot to finish or panic. GCP keeps only the current
/// run's console, so after a stop and start the old boot is not mistaken for it.
pub fn awaitUp(io: Io, gpa: Allocator, p: Place, name: []const u8) !booting.Outcome {
    const start = Io.Clock.awake.now(io);
    while (start.untilNow(io, .awake).toSeconds() < wait_seconds) {
        if (console(io, gpa, p, name)) |text| if (booting.outcome(text)) |o| return o;
        try io.sleep(.fromSeconds(2), .awake);
    }
    return .late;
}

pub fn delete(io: Io, gpa: Allocator, p: Place, name: []const u8, why: *howl.Why) !void {
    try howl.run(
        io,
        why,
        try gcloud(gpa, p, &.{ "compute", "instances", "delete", name, "--zone", p.zone }),
    );
    // Delete the rule openArgs's command makes, if the user ran it.
    _ = ask(
        io,
        gpa,
        p,
        &.{ "compute", "firewall-rules", "delete", try gpa.print("{s}-allow", .{name}) },
    );
}

/// openArgs returns the command that lets source reach the machine on ports:
/// a firewall rule NAME-allow on the machine's tag. delete removes it.
pub fn openArgs(
    gpa: Allocator,
    p: Place,
    name: []const u8,
    ports: []const u16,
    source: []const u8,
) ![]const []const []const u8 {
    var allow: std.ArrayList(u8) = .empty;
    for (ports, 0..) |port, i| try allow.print(
        gpa,
        "{s}tcp:{d}",
        .{ if (i == 0) "" else ",", port },
    );
    const argv = try gpa.dupe([]const u8, &.{
        "gcloud",                            "compute",
        "firewall-rules",                    "create",
        try gpa.print("{s}-allow", .{name}), "--project",
        p.project,                           "--target-tags",
        name,                                "--source-ranges",
        source,                              "--allow",
        allow.items,
    });
    return gpa.dupe([]const []const u8, &.{argv});
}

const testing = std.testing;

test openArgs {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const c = try openArgs(
        arena.allocator(),
        .{ .project = "pr", .zone = "us-central1-a" },
        "web",
        &.{ 22, 8080 },
        "$ME/32",
    );
    try testing.expectEqual(@as(usize, 1), c.len);
    try testing.expectEqualStrings("web-allow", c[0][4]);
    try testing.expectEqualStrings("$ME/32", c[0][10]);
    try testing.expectEqualStrings("tcp:22,tcp:8080", c[0][12]);
}

test machine {
    try testing.expectEqualStrings("t2a-standard-1", machine(.aarch64).size);
    try testing.expectEqualStrings("VIRTIO_NET", machine(.x86_64).nic);
}
