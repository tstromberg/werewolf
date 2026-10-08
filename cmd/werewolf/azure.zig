//! Azure: a werewolf machine as a VM there, experimental, from the same
//! two files every target takes. The boot disk becomes a managed disk,
//! named as GCP's image is (image.zig): converted to a fixed VHD, as Azure
//! takes it, and uploaded straight into a disk made for upload, so no
//! storage account is needed. Azure provisions a VM from an image only
//! through an agent in it, which werewolf has not, so each machine gets a
//! copy of that disk, attached as its OS disk: a specialized VM, which
//! Azure boots as it is. The config tar is the VM's userData, which az
//! encodes in base64 and cloud-metadata fetches from the instance
//! metadata service (docs/cloud.md). The VM gets a network of its own, as
//! az makes one, with a security group that lets nothing in until its
//! owner says what may, and a public address.
//!
//! The subscription is the az CLI's own (az login); the resource group is
//! its default (az configure --defaults group=RG), which werewolf does not
//! make, and names when it is missing. Azure is the state: a VM's name is
//! the machine's, and its werewolf-form tag the form it was made from. The
//! serial console is boot diagnostics', enabled after the VM is made,
//! since az makes one with none, so a new machine is restarted once to be
//! watched booting.

const std = @import("std");
const ww = @import("werewolf.zig");
const images = @import("image.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// How long create waits for a machine to say it is up.
const wait_seconds = 300;
const tag = "werewolf-form";

/// The resource group, and its location.
pub const Place = struct { group: []const u8, location: []const u8 };

/// The resource group the az CLI defaults to, and where it is, or a
/// refusal saying what to set.
pub fn place(io: Io, gpa: Allocator, why: *ww.Why) !Place {
    const account = call(io, gpa, &.{ "az", "account", "show", "--query", "name", "-o", "tsv" });
    if (!account.ok) return why.refuse("--on azure: {s}", .{lastLine(account.err)});
    const group = call(
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
    if (!location.ok) return why.refuse(
        "--on azure: no resource group {s}: az group create -n {s} -l LOCATION",
        .{ group.out, group.out },
    );
    return .{ .group = group.out, .location = location.out };
}

const Result = struct { ok: bool, out: []const u8 = "", err: []const u8 = "" };

/// A command's trimmed output and error, and whether it succeeded.
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

/// az with args, in p's resource group, which az takes only after the
/// command's own words.
fn az(gpa: Allocator, p: Place, args: []const []const u8) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(gpa, "az");
    try argv.appendSlice(gpa, args);
    try argv.appendSlice(gpa, &.{ "-g", p.group, "--only-show-errors" });
    return argv.items;
}

/// az's output, or null if it failed.
fn ask(io: Io, gpa: Allocator, p: Place, args: []const []const u8) ?[]const u8 {
    const r = call(io, gpa, az(gpa, p, args) catch return null);
    return if (r.ok) r.out else null;
}

/// az's output, or a refusal with its last line, which says what is
/// wrong.
fn need(io: Io, gpa: Allocator, p: Place, args: []const []const u8, why: *ww.Why) ![]const u8 {
    const r = call(io, gpa, try az(gpa, p, args));
    if (!r.ok) return why.refuse("az {s}: {s}", .{ args[0], lastLine(r.err) });
    return r.out;
}

/// What az's error output says is wrong: the service's own exception, as
/// az prints it when it fails unexpectedly, its ERROR: line, or else its
/// last, since az follows the error with a pointer to its docs.
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

/// A machine's kind: Azure's architecture name, and a small VM size of
/// it, both Gen2. Not the B-series on x86_64, which new subscriptions are
/// often refused; a size with a SCSI disk controller, which every
/// werewolf kernel drives, where the newest sizes offer NVMe alone.
pub const Machine = struct { arch: []const u8, size: []const u8 };

pub fn machine(arch: []const u8) Machine {
    return if (std.mem.eql(u8, arch, "aarch64"))
        .{ .arch = "Arm64", .size = "Standard_B2pls_v2" }
    else
        .{ .arch = "x64", .size = "Standard_D2as_v4" };
}

/// The managed disk the form's boot disk is, werewolf-FORM-ARCH-DIGEST,
/// made once: the disk converted to a fixed VHD beside it, a disk made
/// for upload of that size, the VHD put into it by azcopy, Microsoft's
/// tool for it, through the write access granted for the upload, then
/// revoked, which makes the disk usable. A disk's upload URL takes only
/// page writes, which az's own blob upload does not start with, and
/// azcopy writes only the pages that hold data: tens of MiB of 8 GiB.
/// A disk of the name left mid-upload by a failed create is made again.
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
        &.{ "disk", "show", "-n", name, "--query", "diskState", "-o", "tsv" },
    )) |state| {
        if (!uploading(state)) {
            ww.say(io, "image {s}: there already", .{name});
            return name;
        }
        ww.say(io, "image {s}: left mid-upload ({s}); making it again", .{ name, state });
        _ = ask(io, gpa, p, &.{ "disk", "revoke-access", "-n", name, "-o", "none" });
        _ = try need(io, gpa, p, &.{ "disk", "delete", "-n", name, "--yes", "-o", "none" }, why);
    }
    blk: {
        const r = call(io, gpa, &.{ "azcopy", "--version" });
        if (r.ok) break :blk;
        return why.refuse(
            "--on azure: no azcopy here, which uploads the disk (brew install azcopy)",
            .{},
        );
    }
    ww.say(io, "image {s}: making it from {s}", .{ name, disk });
    const vhd = try gpa.print("{s}/disk.vhd", .{work});
    defer Dir.cwd().deleteFile(io, vhd) catch {};
    try ww.run(io, why, &.{
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
    ww.say(io, "image {s}: uploading {d} bytes", .{ name, size });
    try ww.run(
        io,
        why,
        &.{ "azcopy", "copy", vhd, sas, "--blob-type", "PageBlob", "--log-level", "ERROR" },
    );
    _ = try need(io, gpa, p, &.{ "disk", "revoke-access", "-n", name, "-o", "none" }, why);
    return name;
}

/// Whether a disk's state is one of an upload not yet finished.
fn uploading(state: []const u8) bool {
    return std.mem.eql(u8, state, "ReadyToUpload") or std.mem.eql(u8, state, "ActiveUpload");
}

/// A VM of ours: its form, "" if its tag names none.
pub const Vm = struct { form: []const u8 };

/// The VM named name, if there is one.
pub fn find(io: Io, gpa: Allocator, p: Place, name: []const u8) ?Vm {
    const text = ask(io, gpa, p, &.{
        "vm",
        "show",
        "-n",
        name,
        "--query",
        "tags.\"" ++ tag ++ "\"",
        "-o",
        "tsv",
    }) orelse return null;
    return .{ .form = text };
}

/// The machine's own disk, a copy of the image: Azure has no VM without an
/// agent but a specialized one, whose OS disk is its own.
fn copyDisk(gpa: Allocator, name: []const u8) ![]const u8 {
    return gpa.print("werewolf-{s}", .{name});
}

/// The VM, made: its disk copied from the image; attached as its OS disk,
/// a Linux one, with Standard security, since werewolf's boot loader is
/// signed by no one Azure trusts; two CPUs, or --size; the tar as its
/// userData; a network of its own, as az makes one, letting nothing in;
/// its disk and NIC gone with it when it goes; then boot diagnostics, so
/// its console is kept, and a restart, so the console sees it boot.
pub fn create(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    form: []const u8,
    arch: []const u8,
    size: ?[]const u8,
    image: []const u8,
    tar: []const u8,
    why: *ww.Why,
) !void {
    const m = machine(arch);
    const disk = try copyDisk(gpa, name);
    _ = try need(io, gpa, p, &.{
        "disk",
        "create",
        "-n",
        disk,
        "--source",
        image,
        "--os-type",
        "Linux",
        "--hyper-v-generation",
        "V2",
        "--architecture",
        m.arch,
        "--security-type",
        "Standard",
        "--sku",
        "Standard_LRS",
        "--tags",
        try gpa.print("{s}={s}", .{ tag, form }),
        "-o",
        "none",
    }, why);
    _ = try need(io, gpa, p, &.{
        "vm",
        "create",
        "-n",
        name,
        "--attach-os-disk",
        disk,
        "--os-type",
        "linux",
        "--size",
        size orelse m.size,
        "--security-type",
        "Standard",
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
    }, why);
    _ = try need(io, gpa, p, &.{ "vm", "boot-diagnostics", "enable", "-n", name }, why);
    _ = try need(io, gpa, p, &.{ "vm", "restart", "-n", name, "-o", "none" }, why);
}

/// A new config for a VM: its userData replaced, which Azure allows while
/// it runs, and a restart, after which the machine reads it. Set as the
/// model's own userData, in base64 werewolf makes, from a file az reads
/// (--set @FILE): az vm update --user-data encodes its argument, which
/// is the path, not the file's bytes, and the file holds secrets, which a
/// command line would show.
pub fn reconfigure(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    tar: []const u8,
    dir: []const u8,
    why: *ww.Why,
) !void {
    const set = try gpa.print("{s}/userdata.set", .{dir});
    const b64 = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(tar.len));
    try ww.writePrivate(
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
    _ = try need(io, gpa, p, &.{ "vm", "restart", "-n", name, "-o", "none" }, why);
}

/// Whether az carries data as it is when vm create reads it from a file:
/// az reads the file as text, so a carriage return becomes a newline and
/// bytes past ASCII may change, then encodes what it read in base64. A
/// config tar of text, as keys, settings and JSON are, passes as it is.
pub fn carried(data: []const u8) bool {
    for (data) |c| if (c >= 0x80 or c == '\r') return false;
    return true;
}

/// The VM's public address.
pub fn address(io: Io, gpa: Allocator, p: Place, name: []const u8) ?[]const u8 {
    return ask(
        io,
        gpa,
        p,
        &.{ "vm", "show", "-d", "-n", name, "--query", "publicIps", "-o", "tsv" },
    );
}

/// The serial console, as boot diagnostics keep it: its last 64 KiB,
/// which az prints as a JSON string.
pub fn console(io: Io, gpa: Allocator, p: Place, name: []const u8) ?[]const u8 {
    const out = ask(
        io,
        gpa,
        p,
        &.{ "vm", "boot-diagnostics", "get-boot-log", "-n", name, "-o", "json" },
    ) orelse return null;
    return std.json.parseFromSliceLeaky([]const u8, gpa, out, .{}) catch null;
}

/// What the console says since before was its end: Azure keeps a window
/// of its last bytes, so the old end is found in it, not counted; where it
/// has scrolled out, all of the window is new.
pub fn since(text: []const u8, before: []const u8) []const u8 {
    if (before.len == 0) return text;
    const at = std.mem.findLast(u8, text, before) orelse return text;
    return text[at + before.len ..];
}

/// The console's last bytes, to find its end again after a restart.
pub fn tail(text: []const u8) []const u8 {
    return text[text.len -| 256..];
}

/// Wait for a boot to finish, or panic, in what the console says after
/// before, its end when the boot began.
pub fn awaitUp(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    before: []const u8,
) !enum { up, panic, late } {
    var waited: u32 = 0;
    while (waited < wait_seconds) : (waited += 10) {
        if (console(io, gpa, p, name)) |text| {
            const new = since(text, before);
            if (std.mem.find(u8, new, "werewolf: up in ") != null) return .up;
            if (std.mem.find(u8, new, "Kernel panic") != null) return .panic;
        }
        try io.sleep(.fromSeconds(10), .awake);
    }
    return .late;
}

/// The VM, with its OS disk and NIC; then the network az made for it,
/// named as az names them, and the disk copy, if a failed create left it;
/// the image stays. Nothing is said of what was gone already.
pub fn delete(io: Io, gpa: Allocator, p: Place, name: []const u8, why: *ww.Why) !void {
    if (find(io, gpa, p, name) != null)
        _ = try need(io, gpa, p, &.{ "vm", "delete", "-n", name, "--yes", "-o", "none" }, why);
    for ([_][]const u8{
        "public-ip",
        "nsg",
        "vnet",
    }, [_][]const u8{ "PublicIP", "NSG", "VNET" }) |kind, suffix|
        _ = ask(io, gpa, p, &.{
            "network",
            kind,
            "delete",
            "-n",
            try gpa.print("{s}{s}", .{ name, suffix }),
            "-o",
            "none",
        });
    _ = ask(
        io,
        gpa,
        p,
        &.{ "disk", "delete", "-n", try copyDisk(gpa, name), "--yes", "-o", "none" },
    );
}

const testing = std.testing;

test machine {
    try testing.expectEqualStrings("Arm64", machine("aarch64").arch);
    try testing.expectEqualStrings("Standard_D2as_v4", machine("x86_64").size);
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
