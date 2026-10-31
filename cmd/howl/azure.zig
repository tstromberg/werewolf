//! azure runs werewolf machines as Azure VMs through the az CLI. It is
//! experimental. See README.md.

const std = @import("std");
const howl = @import("howl.zig");
const images = @import("image.zig");
const booting = @import("boot.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// wait_seconds is how long create waits for the machine to boot.
const wait_seconds = 300;
/// enable_seconds is how long create retries enabling boot diagnostics while
/// az vm create runs. first_boot_seconds is how long the first boot may take
/// to show "up in" before create restarts the VM to watch a whole boot.
const enable_seconds = 90;
const first_boot_seconds = 60;
const tag = howl.form_tag;

/// Place is the resource group and its location.
pub const Place = struct { group: []const u8, location: []const u8 };

/// place returns az's default resource group and its location. werewolf
/// does not create the group; place refuses with how to set one.
pub fn place(io: Io, gpa: Allocator, why: *howl.Why) !Place {
    const group: Result = if (howl.environ.get("AZURE_DEFAULTS_GROUP")) |name|
        .{ .ok = true, .out = name }
    else
        call(
            io,
            gpa,
            &.{ "az", "config", "get", "defaults.group", "--query", "value", "-o", "tsv" },
        );
    if (!group.ok or group.out.len == 0) return why.refuse(
        "--on azure: no default resource group: az group create -n werewolf -l LOCATION, then " ++
            "az configure --defaults group=werewolf",
        .{},
    );
    const location = call(
        io,
        gpa,
        &.{ "az", "group", "show", "-n", group.out, "--query", "location", "-o", "tsv" },
    );
    // az's error tells whether the login or the group is at fault.
    if (!location.ok) return why.refuse(
        "--on azure: resource group {s}: {s}",
        .{ group.out, lastLine(location.err) },
    );
    return .{ .group = group.out, .location = location.out };
}

const Result = struct { ok: bool, out: []const u8 = "", err: []const u8 = "" };

/// call runs argv and returns its trimmed stdout and stderr and whether it
/// succeeded.
fn call(io: Io, gpa: Allocator, argv: []const []const u8) Result {
    const r = std.process.run(gpa, io, .{ .argv = argv }) catch |err|
        return .{ .ok = false, .err = if (err == error.FileNotFound)
            "no az command here (brew install azure-cli)"
        else
            @errorName(err) };
    return .{
        .ok = r.term == .exited and r.term.exited == 0,
        .out = std.mem.trim(u8, r.stdout, " \r\n"),
        .err = std.mem.trim(u8, r.stderr, " \r\n"),
    };
}

/// az returns the argv that runs az with args in p's resource group. az takes
/// -g only after the subcommand.
fn az(gpa: Allocator, p: Place, args: []const []const u8) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(gpa, "az");
    try argv.appendSlice(gpa, args);
    try argv.appendSlice(gpa, &.{ "-g", p.group, "--only-show-errors" });
    return argv.items;
}

/// ask runs az and returns its output, or null if it failed.
fn ask(io: Io, gpa: Allocator, p: Place, args: []const []const u8) ?[]const u8 {
    const r = call(io, gpa, az(gpa, p, args) catch return null);
    return if (r.ok) r.out else null;
}

/// need runs az and returns its output, or refuses with az's error.
fn need(io: Io, gpa: Allocator, p: Place, args: []const []const u8, why: *howl.Why) ![]const u8 {
    const r = call(io, gpa, try az(gpa, p, args));
    if (!r.ok) return why.refuse("az {s}: {s}", .{ args[0], lastLine(r.err) });
    return r.out;
}

/// lastLine picks the useful line of az's stderr: the service's exception
/// detail if any, else the ERROR: line (az follows it with a docs link),
/// else the last line.
fn lastLine(text: []const u8) []const u8 {
    var details = std.mem.splitScalar(u8, text, '\n');
    while (details.next()) |l| if (std.mem.startsWith(u8, l, "Exception Details:"))
        return std.mem.trim(u8, l["Exception Details:".len..], " \t\r");
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| if (std.mem.startsWith(u8, l, "ERROR:"))
        return std.mem.trim(u8, l, " \r");
    const t = std.mem.trimEnd(u8, text, "\r\n");
    var back = std.mem.splitBackwardsScalar(u8, t, '\n');
    return std.mem.trim(u8, back.next() orelse "", " \r");
}

/// Machine holds Azure's name for an arch and a small Gen2 VM size. x86_64
/// avoids the B-series, which new subscriptions are often refused. Arm
/// uses Cobalt, since older Arm sizes cannot enforce Trusted Launch.
/// Both sizes offer SCSI, which every werewolf kernel drives.
pub const Machine = struct { arch: []const u8, size: []const u8 };

pub fn machine(arch: howl.Arch) Machine {
    return switch (arch) {
        .aarch64 => .{ .arch = "Arm64", .size = "Standard_D2ps_v6" },
        .x86_64 => .{ .arch = "x64", .size = "Standard_D2as_v4" },
    };
}

/// ensureDisk returns the name of the managed disk made from disk, creating
/// it once: convert to a fixed VHD, create an upload disk of that size, copy
/// with bounded page writes under a write grant, then revoke the grant.
/// Empty pages stay sparse. A disk left mid-upload is remade on retry.
pub fn ensureDisk(
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
        &.{ "disk", "show", "-n", name, "--query", "diskState", "-o", "tsv" },
    )) |state| {
        if (!uploading(state)) {
            howl.say(io, "image {s}: there already", .{name});
            return name;
        }
        howl.say(io, "image {s}: left mid-upload ({s}); making it again", .{ name, state });
        _ = ask(io, gpa, p, &.{ "disk", "revoke-access", "-n", name, "-o", "none" });
        _ = try need(io, gpa, p, &.{ "disk", "delete", "-n", name, "--yes", "-o", "none" }, why);
    }
    howl.say(io, "image {s}: making it from {s}", .{ name, disk });
    const vhd = try gpa.print("{s}/disk.vhd", .{work});
    defer Dir.cwd().deleteFile(io, vhd) catch {};
    try howl.run(io, why, &.{
        "qemu-img", "convert",
        "-f",       "qcow2",
        "-O",       "vpc",
        "-o",       "subformat=fixed,force_size=on",
        disk,       vhd,
    });
    const size = (Dir.cwd().statFile(io, vhd, .{}) catch |err|
        return why.refuse("{s}: {s}", .{ vhd, @errorName(err) })).size;
    _ = try need(io, gpa, p, &.{
        "disk",
        "create",
        "-n",
        name,
        "-l",
        p.location,
        "--upload-type",
        "Upload",
        "--upload-size-bytes",
        try gpa.print("{d}", .{size}),
        "--os-type",
        "Linux",
        "--hyper-v-generation",
        "V2",
        "--architecture",
        machine(arch).arch,
        "--security-type",
        "Standard",
        "--sku",
        "Standard_LRS",
        "--tags",
        "werewolf=image",
        "-o",
        "none",
    }, why);
    const sas = try need(io, gpa, p, &.{
        "disk",
        "grant-access",
        "-n",
        name,
        "--access-level",
        "Write",
        "--duration-in-seconds",
        "86400",
        "--query",
        "accessSas || accessSAS",
        "-o",
        "tsv",
    }, why);
    howl.say(io, "image {s}: uploading {d} bytes", .{ name, size });
    const upload_err: ?anyerror = if (@import("data-cloud-disk.zig").uploadPages(
        io,
        gpa,
        sas,
        vhd,
        work,
    ))
        null
    else |err|
        err;
    // The write SAS is revoked even when the upload failed, so none
    // outlives the attempt: hours of write access buy nothing.
    _ = try need(io, gpa, p, &.{ "disk", "revoke-access", "-n", name, "-o", "none" }, why);
    if (upload_err) |err| return err;
    return name;
}

/// uploading reports whether a disk state means an unfinished upload.
fn uploading(state: []const u8) bool {
    return std.mem.eql(u8, state, "ReadyToUpload") or std.mem.eql(u8, state, "ActiveUpload");
}

/// Custom firmware keys belong to the gallery version, which the VM must inherit.
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
    // The image's own boot certificate is the one signer firmware admits:
    // the published vendor's for a download, the builder's for a --build.
    // Azure keeps Microsoft's PK (an image bringing its own boots in setup
    // mode), so the gallery version takes Microsoft's UEFI CA template,
    // adds the certificate to db and revokes the template's CAs in dbx.
    _ = try @import("secureboot.zig").certificate(io, gpa, disk, work, arch, why);
    const der = try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/boot.der", .{work}),
        gpa,
        .limited(8192),
    );
    const digest = try images.sha256(io, disk);
    const name = try images.name(gpa, form, arch, &digest);
    const gallery = try std.mem.replaceOwned(u8, gpa, name, "-", "_");
    if (ask(io, gpa, p, &.{
        "sig",            "image-version",           "show",
        "--gallery-name", gallery,                   "--gallery-image-definition",
        "boot",           "--gallery-image-version", "1.0.0",
        "--query",        "id",                      "-o",
        "tsv",
    })) |id| {
        try verifyGallery(io, gpa, id, der, why);
        howl.say(io, "image {s}: there already", .{name});
        return id;
    }
    const source = try ensureDisk(io, gpa, p, form, arch, disk, work, why);
    const source_id = try need(io, gpa, p, &.{
        "disk", "show", "-n", source, "--query", "id", "-o", "tsv",
    }, why);
    const gallery_id = try need(io, gpa, p, &.{
        "sig",    "create",         "--gallery-name", gallery, "--location", p.location,
        "--tags", "werewolf=image", "--query",        "id",    "-o",         "tsv",
    }, why);
    _ = try need(io, gpa, p, &.{
        "sig",
        "image-definitio" ++
            "n",
        "create",
        "--gallery-name",
        gallery,
        "--gallery-image-definitio" ++
            "n",
        "boot",
        "--location",
        p.location,
        "--publisher",
        "werewolf",
        "--offer",
        "werewolf",
        "--sku",
        name,
        "--os-type",
        "Linux",
        "--os-stat" ++
            "e",
        "Specialized",
        "--hyper-v-generation",
        "V2",
        "--architecture",
        machine(
            arch,
        ).arch,
        "--features",
        "SecurityType=TrustedLaunchSupported",
        "-o",
        "none",
    }, why);
    const version = try gpa.print("{s}/images/boot/versions/1.0.0", .{gallery_id});
    const body = try gpa.print("{s}/gallery-version.json", .{work});
    const body_text = try galleryVersion(gpa, p.location, source_id, der);
    try Dir.cwd().writeFile(io, .{ .sub_path = body, .data = body_text });
    defer Dir.cwd().deleteFile(io, body) catch {};
    try howl.run(io, why, try galleryRequest(gpa, version, body));
    const start = Io.Clock.awake.now(io);
    while (start.untilNow(io, .awake).toSeconds() < 600) {
        const state = ask(io, gpa, p, &.{
            "sig",               "image-version",
            "show",              "--gallery-name",
            gallery,             "--gallery-image-definition",
            "boot",              "--gallery-image-version",
            "1.0.0",             "--query",
            "provisioningState", "-o",
            "tsv",
        }) orelse "";
        if (std.mem.eql(u8, state, "Succeeded")) {
            try verifyGallery(io, gpa, version, der, why);
            return version;
        }
        if (std.mem.eql(u8, state, "Failed")) return why.refuse(
            "gallery {s} failed to provision its enrolled image",
            .{gallery},
        );
        try io.sleep(.fromSeconds(2), .awake);
    }
    return why.refuse(
        "gallery {s} did not finish enrolling its image within ten minutes",
        .{gallery},
    );
}

fn galleryRequest(gpa: Allocator, version: []const u8, body: []const u8) ![]const []const u8 {
    return gpa.dupe([]const u8, &.{
        "az",
        "rest",
        "--method",
        "put",
        "--url",
        try gpa.print("https://management.azure.com{s}?api-version=2024-03-03", .{version}),
        "--headers",
        "Content-Type=application/json",
        "--body",
        try gpa.print("@{s}", .{body}),
        "--output",
        "none",
    });
}

fn verifyGallery(
    io: Io,
    gpa: Allocator,
    version: []const u8,
    der: []const u8,
    why: *howl.Why,
) !void {
    const read = call(io, gpa, try galleryReadRequest(gpa, version));
    if (!read.ok or !try galleryEnrolled(gpa, read.out, der)) return why.refuse(
        "Azure did not retain the disk certificate in db and Microsoft's UEFI CAs in dbx " ++
            "under its UEFI CA template; refusing to launch its VM",
        .{},
    );
}

fn galleryReadRequest(gpa: Allocator, version: []const u8) ![]const []const u8 {
    return gpa.dupe([]const u8, &.{
        "az",      "rest",                                    "--method", "get",  "--url",
        try gpa.print(
            "https://management.azure.com{s}?api-version=2024-03-03&$expand=UefiSettings",
            .{version},
        ),
        "--query", "properties.securityProfile.uefiSettings", "-o",       "json",
    });
}

/// template is Azure's own PK, KEK and db: Microsoft's keys and the CAs
/// that sign other vendors' loaders. revokedCerts lists those CAs as X.509
/// DER certificates in dbx so UEFI DxeImageVerificationLib revokes them.
const template = "MicrosoftUefiCertificateAuthorityTemplate";

/// revokedCerts returns the base64-encoded X.509 DER certificates of every
/// signer in Azure's UEFI CA template that dbx must revoke.
fn revokedCerts(gpa: Allocator) ![]const []const u8 {
    const cas = @import("files").microsoft_uefi_cas;
    const out = try gpa.alloc([]const u8, cas.len);
    for (cas, out) |cert, *value| value.* = try base64(gpa, cert);
    return out;
}

const Key = struct { type: []const u8, value: []const []const u8 };

fn galleryEnrolled(gpa: Allocator, text: []const u8, der: []const u8) !bool {
    const Record = struct {
        signatureTemplateNames: []const []const u8,
        additionalSignatures: struct { db: []const Key = &.{}, dbx: []const Key = &.{} },
    };
    const parsed = std.json.parseFromSlice(Record, gpa, text, .{
        .ignore_unknown_fields = true,
    }) catch return false;
    defer parsed.deinit();
    const r = parsed.value;
    if (r.signatureTemplateNames.len != 1 or
        !std.mem.eql(u8, r.signatureTemplateNames[0], template))
        return false;
    // db holds our certificate; dbx holds the revoked CA X.509 certificates, nothing else.
    if (!sameValues(r.additionalSignatures.db, "x509", &.{try base64(gpa, der)})) return false;
    return sameValues(r.additionalSignatures.dbx, "x509", try revokedCerts(gpa));
}

/// sameValues is true when keys, every one of type kind, hold the exact set want
/// without missing or duplicate entries.
fn sameValues(keys: []const Key, kind: []const u8, want: []const []const u8) bool {
    var count: usize = 0;
    for (keys) |key| {
        if (!std.mem.eql(u8, key.type, kind)) return false;
        for (key.value) |value| {
            count += 1;
            var found = false;
            for (want) |w| {
                if (std.mem.eql(u8, value, w)) found = true;
            }
            if (!found) return false;
        }
    }
    if (count != want.len) return false;
    for (want) |w| {
        var seen = false;
        for (keys) |key| for (key.value) |value| {
            if (std.mem.eql(u8, value, w)) seen = true;
        };
        if (!seen) return false;
    }
    return true;
}

fn base64(gpa: Allocator, der: []const u8) ![]const u8 {
    const encoded = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(der.len));
    return std.base64.standard.Encoder.encode(encoded, der);
}

fn galleryVersion(
    gpa: Allocator,
    location: []const u8,
    source: []const u8,
    der: []const u8,
) ![]const u8 {
    return std.json.Stringify.valueAlloc(gpa, .{
        .location = location,
        .properties = .{
            .publishingProfile = .{
                .targetRegions = .{.{ .name = location, .regionalReplicaCount = 1 }},
                .storageAccountType = "Standard_LRS",
            },
            .storageProfile = .{ .osDiskImage = .{ .source = .{ .id = source } } },
            .securityProfile = .{ .uefiSettings = .{
                .signatureTemplateNames = .{template},
                .additionalSignatures = .{
                    .db = .{.{ .type = "x509", .value = .{try base64(gpa, der)} }},
                    .dbx = .{.{ .type = "x509", .value = try revokedCerts(gpa) }},
                },
            } },
        },
    }, .{});
}

/// Vm is a VM found by name. form is its form tag, or "" if it has none.
pub const Vm = struct { form: []const u8 };

/// find returns the VM called name, or null if there is none. Any other az
/// failure, such as an expired login, is refused: treating it as "no VM"
/// would make delete forget a VM that is still running.
pub fn find(io: Io, gpa: Allocator, p: Place, name: []const u8, why: *howl.Why) !?Vm {
    const r = call(io, gpa, try az(gpa, p, &.{
        "vm",
        "show",
        "-n",
        name,
        "--query",
        "tags.\"" ++ tag ++ "\"",
        "-o",
        "tsv",
    }));
    if (r.ok) return .{ .form = r.out };
    if (std.mem.find(u8, r.err, "NotFound") != null) return null;
    return why.refuse("az vm show {s}: {s}", .{ name, lastLine(r.err) });
}

/// copyDisk names the machine's copy of the image. Azure can only provision
/// from an image through an in-guest agent, which werewolf lacks, so each VM
/// is "specialized": it boots a private copy of the disk as is.
fn copyDisk(gpa: Allocator, name: []const u8) ![]const u8 {
    return gpa.print("werewolf-{s}", .{name});
}

/// create makes VM name from the enrolled specialized gallery image, with
/// the config tar as its userData. az makes it a network whose security group lets
/// nothing in. The OS disk and NIC are deleted with the VM. A null size
/// picks machine(arch).size.
pub fn create(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    form: []const u8,
    arch: howl.Arch,
    size: ?[]const u8,
    image: []const u8,
    tar: []const u8,
    why: *howl.Why,
) !void {
    const m = machine(arch);
    const disk = try copyDisk(gpa, name);
    // The CLI validates an SSH key for specialized images; its ARM template omits osProfile.
    const work = std.fs.path.dirname(tar) orelse ".";
    const public_pem = try gpa.print("{s}/boot.pub", .{work});
    const public_ssh = try gpa.print("{s}/azure-validator.pub", .{work});
    defer Dir.cwd().deleteFile(io, public_pem) catch {};
    defer Dir.cwd().deleteFile(io, public_ssh) catch {};
    const extracted = call(io, gpa, &.{
        "openssl", "x509", "-in", try gpa.print("{s}/boot.crt", .{work}), "-pubkey", "-noout",
    });
    if (!extracted.ok) return why.refuse(
        "cannot read the verified disk's public boot certificate",
        .{},
    );
    try Dir.cwd().writeFile(io, .{ .sub_path = public_pem, .data = extracted.out });
    const converted = call(io, gpa, &.{ "ssh-keygen", "-i", "-m", "PKCS8", "-f", public_pem });
    if (!converted.ok) return why.refuse(
        "cannot convert the public boot key for Azure's CLI validator",
        .{},
    );
    try Dir.cwd().writeFile(io, .{ .sub_path = public_ssh, .data = converted.out });
    // az vm create returns only once the VM runs, and can enable boot
    // diagnostics only with a storage account. Azure logs the console only
    // after diagnostics are on, and only for a VM it knows. So enable them
    // in parallel as soon as the VM exists, usually before the first boot
    // ends. If the boot was missed, restart the VM once.
    const err_path = try gpa.print("{s}/vm-create.err", .{std.fs.path.dirname(tar) orelse "."});
    defer Dir.cwd().deleteFile(io, err_path) catch {};
    const err_file = try Dir.cwd().createFile(io, err_path, .{});
    var maker = std.process.spawn(io, .{
        .argv = try az(gpa, p, &.{
            "vm",
            "create",
            "-n",
            name,
            "--image",
            image,
            "--specialized",
            "true",
            "--ssh-key-value",
            public_ssh,
            "--os-disk-name",
            disk,
            "--size",
            size orelse m.size,
            "--security-type",
            "TrustedLaunch",
            "--enable-secure-boot",
            "true",
            "--enable-vtpm",
            "true",
            "--enable-agent",
            "false",
            "--user-data",
            tar,
            "--nsg-rule",
            "NONE",
            "--public-ip-sku",
            "Standard",
            "--os-disk-delete-option",
            "Delete",
            "--nic-delete-option",
            "Delete",
            "--tags",
            try gpa.print("{s}={s}", .{ tag, form }),
            "-o",
            "none",
        }),
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .{ .file = err_file },
    }) catch |err| {
        err_file.close(io);
        return why.refuse("az vm create: {s}", .{@errorName(err)});
    };
    err_file.close(io);
    const start = Io.Clock.awake.now(io);
    var enabled = false;
    while (!enabled and start.untilNow(io, .awake).toSeconds() < enable_seconds) {
        enabled = call(io, gpa, try az(gpa, p, &.{
            "vm", "boot-diagnostics", "enable", "-n", name,
        })).ok;
        if (!enabled) try io.sleep(.fromSeconds(1), .awake);
    }
    const term = maker.wait(io) catch |err| return why.refuse(
        "az vm create: {s}",
        .{@errorName(err)},
    );
    if (term != .exited or term.exited != 0) {
        // Leave the disk copy, as create leaves what it made
        // (docs/design/implemented/cli.md), but tell the user how to remove it.
        const said = Dir.cwd().readFileAlloc(io, err_path, gpa, .limited(64 << 10)) catch "";
        return why.refuse(
            "az vm: {s}; its disk {s} is left, which howl delete {s} --on azure removes",
            .{ lastLine(said), disk, name },
        );
    }
    if (!enabled)
        _ = try need(io, gpa, p, &.{ "vm", "boot-diagnostics", "enable", "-n", name }, why);
    if (try awaitUpWithin(io, gpa, p, name, "", first_boot_seconds) != .late) return;
    howl.say(io, "{s}: its first boot was not watched from the start; restarting it once", .{name});
    _ = try need(io, gpa, p, &.{ "vm", "restart", "-n", name, "-o", "none" }, why);
}

/// publishConfig replaces userData while the VM runs, passing base64
/// through a private file (--set @FILE): az vm
/// update --user-data would encode the path, not the file, and a command
/// line would expose the secrets.
pub fn publishConfig(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    tar: []const u8,
    dir: []const u8,
    why: *howl.Why,
) !void {
    const set = try gpa.print("{s}/userdata.set", .{dir});
    const b64 = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(tar.len));
    try howl.writePrivate(
        io,
        gpa,
        set,
        try gpa.print("userData={s}", .{std.base64.standard.Encoder.encode(b64, tar)}),
        why,
    );
    defer Dir.cwd().deleteFile(io, set) catch {};
    _ = try need(
        io,
        gpa,
        p,
        &.{ "vm", "update", "-n", name, "--set", try gpa.print("@{s}", .{set}), "-o", "none" },
        why,
    );
}

pub fn reconfigure(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    tar: []const u8,
    dir: []const u8,
    why: *howl.Why,
) !void {
    try publishConfig(io, gpa, p, name, tar, dir, why);
    _ = try need(io, gpa, p, &.{ "vm", "restart", "-n", name, "-o", "none" }, why);
}

/// carried reports whether az vm create passes data through unchanged. az
/// reads the file as text, so it turns \r into \n and may change non-ASCII
/// bytes. A tar of keys, settings and JSON passes.
pub fn carried(data: []const u8) bool {
    for (data) |c| if (c >= 0x80 or c == '\r') return false;
    return true;
}

/// address returns the VM's public IP address.
pub fn address(io: Io, gpa: Allocator, p: Place, name: []const u8) ?[]const u8 {
    return ask(
        io,
        gpa,
        p,
        &.{ "vm", "show", "-d", "-n", name, "--query", "publicIps", "-o", "tsv" },
    );
}

/// console returns the boot diagnostics serial log, the last 64 KiB, which
/// az prints as a JSON string.
pub fn console(io: Io, gpa: Allocator, p: Place, name: []const u8) ?[]const u8 {
    const out = ask(
        io,
        gpa,
        p,
        &.{ "vm", "boot-diagnostics", "get-boot-log", "-n", name, "-o", "json" },
    ) orelse return null;
    return std.json.parseFromSliceLeaky([]const u8, gpa, out, .{}) catch null;
}

/// since returns the console text after before, the previous run's mark.
/// Azure keeps a sliding window across restarts, so the mark is searched
/// for, not counted; if it scrolled out, the whole window is new.
pub fn since(text: []const u8, before: []const u8) []const u8 {
    if (before.len == 0) return text;
    const at = std.mem.findLast(u8, text, before) orelse return text;
    return text[at + before.len ..];
}

/// mark returns the console from its last timestamped line ("time":"...")
/// to the end, for since to find after a restart. Plain trailing bytes would
/// not do: every boot prints the same lines, down to the pids, so they recur
/// after the next "up in". Without a timestamp it returns the last 256 bytes.
pub fn mark(text: []const u8) []const u8 {
    var end = text.len;
    while (std.mem.findScalarLast(u8, text[0..end], '\n')) |nl| : (end = nl) {
        const start = if (std.mem.findScalarLast(u8, text[0..nl], '\n')) |b| b + 1 else 0;
        if (std.mem.find(u8, text[start..nl], "\"time\":\"") != null) return text[start..];
    }
    return text[text.len -| 256..];
}

/// awaitUp waits for the boot to finish or panic, reading the console after
/// before, its mark from when the boot began.
pub fn awaitUp(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    before: []const u8,
) !booting.Outcome {
    return awaitUpWithin(io, gpa, p, name, before, wait_seconds);
}

fn awaitUpWithin(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    before: []const u8,
    seconds: i64,
) !booting.Outcome {
    const start = Io.Clock.awake.now(io);
    while (start.untilNow(io, .awake).toSeconds() < seconds) {
        if (console(io, gpa, p, name)) |text|
            if (booting.outcome(since(text, before))) |o| return o;
        try io.sleep(.fromSeconds(2), .awake);
    }
    return .late;
}

/// openArgs returns the command that lets source reach the VM on ports: a
/// rule in NAMENSG, the security group az made. delete removes the group.
pub fn openArgs(
    gpa: Allocator,
    p: Place,
    name: []const u8,
    ports: []const u16,
    source: []const u8,
) ![]const []const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{
        "az",                             "network",
        "nsg",                            "rule",
        "create",                         "-g",
        p.group,                          "--nsg-name",
        try gpa.print("{s}NSG", .{name}), "-n",
        "allow",                          "--priority",
        "1000",                           "--access",
        "Allow",                          "--protocol",
        "Tcp",                            "--source-address-prefixes",
        source,                           "-o",
        "none",                           "--destination-port-ranges",
    });
    for (ports) |port| try argv.append(gpa, try gpa.print("{d}", .{port}));
    return gpa.dupe([]const []const u8, &.{argv.items});
}

/// delete removes the VM with its OS disk and NIC, then the network pieces
/// az made for it, and the disk copy a failed create may have left. The
/// image stays.
pub fn delete(io: Io, gpa: Allocator, p: Place, name: []const u8, vm: ?Vm, why: *howl.Why) !void {
    if (vm != null)
        _ = try need(io, gpa, p, &.{ "vm", "delete", "-n", name, "--yes", "-o", "none" }, why);
    // Azure frees each piece only after its users are gone, which happens
    // in the background after the VM's delete. Retry for a while, then say
    // what is left and how to remove it.
    for ([_][]const u8{
        "public-ip",
        "nsg",
        "vnet",
    }, [_][]const u8{ "PublicIP", "NSG", "VNET" }) |kind, suffix| {
        const what = try gpa.print("{s}{s}", .{ name, suffix });
        const args = &.{ "network", kind, "delete", "-n", what, "-o", "none" };
        var r = call(io, gpa, try az(gpa, p, args));
        var tries: u32 = 1;
        while (!r.ok and tries < 10) : (tries += 1) {
            try io.sleep(.fromSeconds(3), .awake);
            r = call(io, gpa, try az(gpa, p, args));
        }
        if (!r.ok) howl.say(
            io,
            "{s}: its {s} {s} is left ({s}): az network {s} delete -g {s} -n {s}",
            .{ name, kind, what, lastLine(r.err), kind, p.group, what },
        );
    }
    _ = ask(
        io,
        gpa,
        p,
        &.{ "disk", "delete", "-n", try copyDisk(gpa, name), "--yes", "-o", "none" },
    );
}

const testing = std.testing;
test "gallery adds the disk certificate to db and revokes the template's signers in dbx" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const text = try galleryVersion(gpa, "eastus", "/disks/verified", &.{ 1, 2, 3 });
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
    defer parsed.deinit();
    const properties = parsed.value.object.get("properties").?.object;
    const storage = properties.get("storageProfile").?.object;
    const source = storage.get("osDiskImage").?.object.get("source").?.object;
    try testing.expectEqualStrings("/disks/verified", source.get("id").?.string);
    const uefi = properties.get("securityProfile").?.object.get("uefiSettings").?.object;
    const templates = uefi.get("signatureTemplateNames").?.array.items;
    try testing.expectEqual(@as(usize, 1), templates.len);
    try testing.expectEqualStrings(template, templates[0].string);
    const signatures = uefi.get("additionalSignatures").?.object;
    // No PK or KEK of our own: Azure refuses a PK beside a template, and a
    // PK alone leaves its firmware in setup mode.
    try testing.expect(signatures.get("pk") == null and signatures.get("kek") == null);
    const db = signatures.get("db").?.array.items[0].object;
    try testing.expectEqualStrings("x509", db.get("type").?.string);
    try testing.expectEqualStrings("AQID", db.get("value").?.array.items[0].string);
    const dbx = signatures.get("dbx").?.array.items[0].object;
    try testing.expectEqualStrings("x509", dbx.get("type").?.string);
    const want = try revokedCerts(gpa);
    try testing.expectEqual(@as(usize, 4), want.len);
    try testing.expectEqual(want.len, dbx.get("value").?.array.items.len);
    for (dbx.get("value").?.array.items, want) |value, w|
        try testing.expectEqualStrings(w, value.string);
    const retained = try std.json.Stringify.valueAlloc(
        gpa,
        @as(std.json.Value, .{ .object = uefi }),
        .{},
    );
    try testing.expect(try galleryEnrolled(gpa, retained, &.{ 1, 2, 3 }));
    try testing.expect(!try galleryEnrolled(gpa, retained, &.{ 1, 2, 4 }));
    try testing.expect(!try galleryEnrolled(gpa, "null", &.{ 1, 2, 3 }));
    try testing.expect(!try galleryEnrolled(gpa, "{}", &.{ 1, 2, 3 }));
    const request = try galleryRequest(gpa, "/gallery/version", "/private/public.json");
    try testing.expectEqualStrings("--headers", request[6]);
    try testing.expectEqualStrings("Content-Type=application/json", request[7]);
    const read = try galleryReadRequest(gpa, "/gallery/version");
    try testing.expect(std.mem.find(u8, read[5], "&$expand=UefiSettings") != null);
}

test "gallery enrollment holds only with every X.509 revocation and no extra signer" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const want = try revokedCerts(gpa);
    const first = want[0];
    const rest = try std.mem.join(gpa, "\",\"", want[1..]);
    // Split across entries and reordered, as Azure may store it: still enrolled.
    const split = try gpa.print(
        \\{{"signatureTemplateNames":["{s}"],"additionalSignatures":{{"pk":null,"kek":[],
        \\"db":[{{"type":"x509","value":["AQID"]}}],
        \\"dbx":[{{"type":"x509","value":["{s}"]}},{{"type":"x509","value":["{s}"]}}]}}}}
    , .{ template, rest, first });
    try testing.expect(try galleryEnrolled(gpa, split, &.{ 1, 2, 3 }));
    const cases = [_][]const u8{
        // A revocation missing: that signer's loaders would boot.
        try gpa.print(
            \\{{"signatureTemplateNames":["{s}"],"additionalSignatures":{{
            \\"db":[{{"type":"x509","value":["AQID"]}}],"dbx":[{{"type":"x509","value":["{s}"]}}]}}}}
        , .{ template, rest }),
        // Duplicate entries matching count without covering every CA.
        try gpa.print(
            \\{{"signatureTemplateNames":["{s}"],"additionalSignatures":{{
            \\"db":[{{"type":"x509","value":["AQID"]}}],
            \\"dbx":[{{"type":"x509","value":["{s}","{s}","{s}","{s}"]}}]}}}}
        , .{ template, first, first, first, first }),
        // A second signer in db.
        try gpa.print(
            \\{{"signatureTemplateNames":["{s}"],"additionalSignatures":{{
            \\"db":[{{"type":"x509","value":["AQID","BAUG"]}}],
            \\"dbx":[{{"type":"x509","value":["{s}","{s}"]}}]}}}}
        , .{ template, rest, first }),
        // dbx as bare sha256 image digests, which UEFI firmware ignores for X.509 signers!
        try gpa.print(
            \\{{"signatureTemplateNames":["{s}"],"additionalSignatures":{{
            \\"db":[{{"type":"x509","value":["AQID"]}}],
            \\"dbx":[{{"type":"sha256","value":["{s}","{s}"]}}]}}}}
        , .{ template, rest, first }),
        // Our own PK: the template Azure honours is the one named.
        try gpa.print(
            \\{{"signatureTemplateNames":["NoSignatureTemplate"],"additionalSignatures":{{
            \\"db":[{{"type":"x509","value":["AQID"]}}],
            \\"dbx":[{{"type":"x509","value":["{s}","{s}"]}}]}}}}
        , .{ rest, first }),
    };
    for (cases) |text| try testing.expect(!try galleryEnrolled(gpa, text, &.{ 1, 2, 3 }));
}
test openArgs {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const c = try openArgs(
        arena.allocator(),
        .{ .group = "werewolf", .location = "eastus" },
        "web",
        &.{ 22, 8080 },
        "0.0.0.0/0",
    );
    try testing.expectEqual(@as(usize, 1), c.len);
    try testing.expectEqualStrings("webNSG", c[0][8]);
    try testing.expectEqualStrings("0.0.0.0/0", c[0][18]);
    try testing.expectEqualStrings("8080", c[0][c[0].len - 1]);
}

test machine {
    try testing.expectEqualStrings("Arm64", machine(.aarch64).arch);
    try testing.expectEqualStrings("Standard_D2ps_v6", machine(.aarch64).size);
    try testing.expectEqualStrings("Standard_D2as_v4", machine(.x86_64).size);
}

test lastLine {
    try testing.expectEqualStrings(
        "ERROR: no such group",
        lastLine("WARNING: x\nERROR: no such group\n"),
    );
    try testing.expectEqualStrings("", lastLine(""));
    try testing.expectEqualStrings(
        "(SkuNotAvailable) The requested VM size is not available",
        lastLine("ERROR: The command failed with an unexpected error.\nMessage: x\n" ++
            "Exception Details:\t(SkuNotAvailable) The requested VM size is not available\n"),
    );
    try testing.expectEqualStrings(
        "ERROR: 'x' is misspelled",
        lastLine(
            "ERROR: 'x' is misspelled\n\nhttps://aka.ms/cli_ref\nRead more about the command\n",
        ),
    );
}

test uploading {
    try testing.expect(uploading("ActiveUpload") and uploading("ReadyToUpload"));
    try testing.expect(!uploading("Unattached") and !uploading("Attached"));
}

test carried {
    try testing.expect(carried("bastion/authorized_keys\x00ssh-ed25519 AAAA x\n"));
    try testing.expect(!carried("key\r\n"));
    try testing.expect(!carried("\xc3\xa9"));
}

test mark {
    const boot = "stage0: the kernel took 0.3s\r\n" ++
        "cloud-metadata: {\"time\":\"TIME\",\"event\":\"config\"}\r\n" ++
        "werewolf: up in 2.9s\r\nseal-watch: {\"event\":\"start\"}\r\n";
    const one = comptime replaced(boot, "2026-10-08T12:51:29Z");
    const two = comptime replaced(boot, "2026-10-08T12:54:40Z");
    const m = mark(one);
    try testing.expect(std.mem.find(u8, m, "12:51:29Z") != null);
    // The next run prints the same lines with a new time: only it follows
    // the mark, and it holds the new "up in".
    try testing.expectEqualStrings(two, since(one ++ two, m));
    // Before the restart prints anything, nothing follows the mark.
    try testing.expect(std.mem.find(u8, since(one, m), booting.up_line) == null);
    // With no timestamp on any line, mark returns the last bytes.
    try testing.expectEqualStrings("no clock", mark("no clock"));
}

fn replaced(comptime boot: []const u8, comptime time: []const u8) []const u8 {
    const at = std.mem.find(u8, boot, "TIME").?;
    return boot[0..at] ++ time ++ boot[at + "TIME".len ..];
}

test since {
    try testing.expectEqualStrings("boot two", since("boot one END boot two", "END "));
    try testing.expectEqualStrings("all new", since("all new", "gone"));
    try testing.expectEqualStrings("x", since("x", ""));
    try testing.expectEqualStrings("b", since("a END a END b", "END "));
}

test copyDisk {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("werewolf-edge", try copyDisk(arena.allocator(), "edge"));
}
