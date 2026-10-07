//! GCP: a werewolf machine on Google Compute Engine, from the same two
//! files every target takes. The boot disk becomes a GCP image, named by
//! the sha256 of the release's disk.qcow2, so a build is uploaded once and
//! every machine of it shares the image. The config tar, in base64, is the
//! instance's user-data, which cloud-metadata fetches (docs/cloud.md). The
//! VM has no service account and no Secure Boot, which werewolf's loader
//! does not support yet.
//!
//! The project and zone are gcloud's own (gcloud config); the zone, if
//! gcloud has none, us-central1-a, which has Arm machines. GCP is the
//! state: an instance's label says the form it was made from.

const std = @import("std");
const ww = @import("werewolf.zig");
const images = @import("image.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// How long create waits for a machine to say it is up.
const wait_seconds = 300;
const label = "werewolf-form";

pub const Place = struct { project: []const u8, zone: []const u8 };

/// Where gcloud is set to work, or a refusal saying how to set it.
pub fn place(io: Io, gpa: Allocator, why: *ww.Why) !Place {
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

/// gcloud, quiet, in p's project, with args.
fn gcloud(gpa: Allocator, p: Place, args: []const []const u8) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{ "gcloud", "--quiet", "--project", p.project });
    try argv.appendSlice(gpa, args);
    return argv.items;
}

/// gcloud's output, or null if it failed.
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

/// The machine a form runs on, for an arch: GCP's name for the arch, the
/// machine type, and the NIC werewolf has a driver for.
pub const Machine = struct { arch: []const u8, kind: []const u8, nic: []const u8 };

pub fn machine(arch: []const u8) Machine {
    return if (std.mem.eql(u8, arch, "aarch64"))
        .{ .arch = "ARM64", .kind = "t2a-standard-1", .nic = "GVNIC" }
    else
        .{ .arch = "X86_64", .kind = "e2-small", .nic = "VIRTIO_NET" };
}

/// The image of disk, a release's disk.qcow2: there already, or made from
/// it through PROJECT-werewolf-images, whose upload is then deleted.
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
    if (ask(
        io,
        gpa,
        p,
        &.{ "compute", "images", "describe", name, "--format", "value(name)" },
    ) != null) {
        ww.say(io, "image {s}: there already", .{name});
        return name;
    }
    ww.say(io, "image {s}: making it from {s}", .{ name, disk });
    // GCP takes a raw disk named disk.raw, in a gzipped GNU tar, which
    // keeps the disk's holes where GNU tar is the tar; bsdtar writes them
    // out, and gzip makes them small again.
    const raw = try gpa.print("{s}/disk.raw", .{work});
    const tarball = try gpa.print("{s}/image.tar.gz", .{work});
    defer Dir.cwd().deleteFile(io, raw) catch {};
    defer Dir.cwd().deleteFile(io, tarball) catch {};
    try ww.run(io, why, &.{ "qemu-img", "convert", "-f", "qcow2", "-O", "raw", disk, raw });
    const v = std.process.run(gpa, io, .{ .argv = &.{ "tar", "--version" } }) catch null;
    const gnu = if (v) |r| std.mem.find(u8, r.stdout, "GNU tar") != null else false;
    try ww.run(io, why, &.{
        "tar",
        "-C",
        work,
        if (gnu) "--format=oldgnu" else "--format=gnutar",
        if (gnu) "-Sczf" else "-czf",
        tarball,
        "disk.raw",
    });
    const bucket = try gpa.print("gs://{s}-werewolf-images", .{p.project});
    if (ask(
        io,
        gpa,
        p,
        &.{ "storage", "buckets", "describe", bucket, "--format", "value(name)" },
    ) == null) {
        const region = p.zone[0 .. std.mem.findScalarLast(u8, p.zone, '-') orelse p.zone.len];
        try ww.run(io, why, try gcloud(gpa, p, &.{
            "storage",                       "buckets",
            "create",                        bucket,
            "--location",                    region,
            "--uniform-bucket-level-access",
        }));
    }
    const object = try gpa.print("{s}/{s}.tar.gz", .{ bucket, name });
    try ww.run(io, why, try gcloud(gpa, p, &.{ "storage", "cp", tarball, object }));
    defer _ = ask(io, gpa, p, &.{ "storage", "rm", object });
    try ww.run(io, why, try gcloud(gpa, p, &.{
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
    }));
    return name;
}

/// The form an instance was made from, as its label says; null if there is
/// no such instance.
pub fn formOf(io: Io, gpa: Allocator, p: Place, name: []const u8) ?[]const u8 {
    return ask(io, gpa, p, &.{
        "compute",  "instances",                     "describe", name, "--zone", p.zone,
        "--format", "value(labels." ++ label ++ ")",
    });
}

/// A VM of image, its config in user-data from b64: no service account,
/// no scopes, and Secure Boot off. size is the machine type, if not the
/// arch's smallest that werewolf runs well on.
pub fn create(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    form: []const u8,
    arch: []const u8,
    size: ?[]const u8,
    image: []const u8,
    b64: []const u8,
    why: *ww.Why,
) !void {
    const m = machine(arch);
    try ww.run(io, why, try gcloud(gpa, p, &.{
        "compute",
        "instances",
        "create",
        name,
        "--zone",
        p.zone,
        "--machine-type",
        size orelse m.kind,
        "--image",
        image,
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

/// A new config for an instance: its user-data replaced, and the machine
/// stopped, which GCP asks of it with its power button, and started again.
pub fn reconfigure(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    b64: []const u8,
    why: *ww.Why,
) !void {
    try ww.run(io, why, try gcloud(gpa, p, &.{
        "compute",              "instances",
        "add-metadata",         name,
        "--zone",               p.zone,
        "--metadata-from-file", try gpa.print("user-data={s}", .{b64}),
    }));
    try ww.run(
        io,
        why,
        try gcloud(gpa, p, &.{ "compute", "instances", "stop", name, "--zone", p.zone }),
    );
    try ww.run(
        io,
        why,
        try gcloud(gpa, p, &.{ "compute", "instances", "start", name, "--zone", p.zone }),
    );
}

/// The instance's external address.
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

/// The serial console, as GCP keeps it.
pub fn console(io: Io, gpa: Allocator, p: Place, name: []const u8) ?[]const u8 {
    return ask(
        io,
        gpa,
        p,
        &.{ "compute", "instances", "get-serial-port-output", name, "--zone", p.zone },
    );
}

/// Whether the console shows a boot finished: init's "up in" line.
pub fn booted(text: []const u8) bool {
    return std.mem.find(u8, text, "werewolf: up in ") != null;
}

/// Wait for the boot to finish, or a panic. GCP keeps the console of the
/// machine's current run only, so a stop and start begins it afresh.
pub fn awaitUp(io: Io, gpa: Allocator, p: Place, name: []const u8) !enum { up, panic, late } {
    var waited: u32 = 0;
    while (waited < wait_seconds) : (waited += 5) {
        if (console(io, gpa, p, name)) |text| {
            if (booted(text)) return .up;
            if (std.mem.find(u8, text, "Kernel panic") != null) return .panic;
        }
        try io.sleep(.fromSeconds(5), .awake);
    }
    return .late;
}

pub fn delete(io: Io, gpa: Allocator, p: Place, name: []const u8, why: *ww.Why) !void {
    try ww.run(
        io,
        why,
        try gcloud(gpa, p, &.{ "compute", "instances", "delete", name, "--zone", p.zone }),
    );
}

const testing = std.testing;

test booted {
    try testing.expect(!booted("stage0: ...\n"));
    try testing.expect(booted("...\nwerewolf: up in 0.6s (the kernel 0.2s)\n"));
}

test machine {
    try testing.expectEqualStrings("t2a-standard-1", machine("aarch64").kind);
    try testing.expectEqualStrings("VIRTIO_NET", machine("x86_64").nic);
}
