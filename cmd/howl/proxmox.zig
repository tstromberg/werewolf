//! Proxmox VE: a werewolf machine as a VM on a Proxmox node, experimental
//! and never yet run against a node, from the same two files every target
//! takes: the release's disk, which the node's OVMF boots, and the config
//! tar, imported as a second, read-only virtio disk, where init finds it.
//!
//! Proxmox's own command, qm, runs on the node, so everything here is qm
//! over ssh, with an explicit argument list, to the node PROXMOX_HOST
//! names (root@NODE, or an ssh config Host); PROXMOX_STORAGE (local-lvm)
//! holds the disks and PROXMOX_BRIDGE (vmbr0) is the network. The node
//! keeps werewolf's files in /var/lib/vz/werewolf: each image, named by
//! its digest, so a second create uploads nothing; each machine's config
//! tar, which qm imports; and each machine's console, a file QEMU writes
//! through an extra argument, since Proxmox keeps a serial port on a
//! socket and no log. qm is the state: a VM with the tag werewolf and a
//! description naming its form is one of ours, and nothing here remembers
//! more. The machine takes its address from the network's DHCP server,
//! which its console reports, or a static one from its tar.

const std = @import("std");
const howl = @import("howl.zig");
const images = @import("image.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;

/// Where the node keeps werewolf's files.
pub const dir = "/var/lib/vz/werewolf";
/// How long create waits for a machine to say it is up.
const wait_seconds = 180;

/// The node, and what on it the machine uses.
pub const Place = struct { host: []const u8, storage: []const u8, bridge: []const u8 };

pub fn place(environ: *const std.process.Environ.Map, why: *howl.Why) !Place {
    const host = environ.get("PROXMOX_HOST") orelse return why.refuse(
        "--on proxmox: PROXMOX_HOST=root@NODE names the node, by ssh; PROXMOX_STORAGE " ++
            "(local-lvm) and PROXMOX_BRIDGE (vmbr0) may follow",
        .{},
    );
    for ([_][]const u8{
        host,
        environ.get("PROXMOX_STORAGE") orelse "",
        environ.get("PROXMOX_BRIDGE") orelse "",
    }) |v|
        if (!plain(v)) return why.refuse(
            "PROXMOX_*: {s}: letters, digits and . _ - @ : only",
            .{v},
        );
    return .{
        .host = host,
        .storage = environ.get("PROXMOX_STORAGE") orelse "local-lvm",
        .bridge = environ.get("PROXMOX_BRIDGE") orelse "vmbr0",
    };
}

/// Whether s reaches the node's shell as itself: every word of a command
/// is joined by ssh and split there again, so none may hold a space or a
/// character the shell reads. Names, paths and ids here never do.
pub fn plain(s: []const u8) bool {
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, "._-@:", c) == null)
        return false;
    return true;
}

/// A command on the node: ssh, then its words.
fn remote(gpa: Allocator, p: Place, args: []const []const u8) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{ "ssh", "-o", "BatchMode=yes", p.host });
    try argv.appendSlice(gpa, args);
    return argv.items;
}

/// The node's answer, trimmed, or null if the command failed.
fn ask(io: Io, gpa: Allocator, p: Place, args: []const []const u8) ?[]const u8 {
    const r = std.process.run(gpa, io, .{ .argv = remote(gpa, p, args) catch return null }) catch
        return null;
    return if (r.term == .exited and r.term.exited == 0)
        std.mem.trim(u8, r.stdout, " \n")
    else
        null;
}

/// The image's file on the node, werewolf-FORM-ARCH-DIGEST.qcow2, uploaded
/// unless it is there already.
pub fn ensureImage(
    io: Io,
    gpa: Allocator,
    p: Place,
    form: []const u8,
    arch: []const u8,
    disk: []const u8,
    why: *howl.Why,
) ![]const u8 {
    const name = try images.name(gpa, form, arch, &try images.sha256(io, disk));
    const path = try gpa.print("{s}/{s}.qcow2", .{ dir, name });
    if (ask(io, gpa, p, &.{ "test", "-f", path }) != null) {
        howl.say(io, "image {s}: on {s} already", .{ name, p.host });
        return path;
    }
    howl.say(io, "image {s}: uploading {s} to {s}", .{ name, disk, p.host });
    try howl.run(io, why, try remote(gpa, p, &.{ "mkdir", "-p", dir }));
    try howl.run(io, why, &.{ "scp", "-q", disk, try gpa.print("{s}:{s}", .{ p.host, path }) });
    return path;
}

/// The machine's config tar's and console's files on the node.
pub fn tarPath(gpa: Allocator, name: []const u8) ![]const u8 {
    return gpa.print("{s}/{s}-config.tar", .{ dir, name });
}

pub fn logPath(gpa: Allocator, name: []const u8) ![]const u8 {
    return gpa.print("{s}/{s}.console", .{ dir, name });
}

/// The config tar, copied to the node as itself, kept 0600 as it was.
pub fn upload(
    io: Io,
    gpa: Allocator,
    p: Place,
    tar: []const u8,
    name: []const u8,
    why: *howl.Why,
) !void {
    try howl.run(io, why, try remote(gpa, p, &.{ "mkdir", "-p", dir }));
    try howl.run(io, why, &.{
        "scp",
        "-q",
        "-p",
        tar,
        try gpa.print("{s}:{s}", .{ p.host, try tarPath(gpa, name) }),
    });
}

/// A VM of ours on the node: its id, whether it runs, and its form.
pub const Machine = struct { vmid: []const u8, running: bool, form: []const u8 };

/// The VM named name that werewolf made, if any: qm list has the names,
/// and its config the form.
pub fn find(io: Io, gpa: Allocator, p: Place, name: []const u8) ?Machine {
    const list = ask(io, gpa, p, &.{ "qm", "list" }) orelse return null;
    var lines = std.mem.splitScalar(u8, list, '\n');
    while (lines.next()) |line| {
        const row = parseRow(line) orelse continue;
        if (!std.mem.eql(u8, row.name, name)) continue;
        const config = ask(io, gpa, p, &.{ "qm", "config", row.vmid }) orelse continue;
        const form = formOf(config) orelse continue;
        return .{
            .vmid = row.vmid,
            .running = std.mem.eql(u8, row.status, "running"),
            .form = form,
        };
    }
    return null;
}

/// A row of qm list: VMID NAME STATUS ..., skipping its header.
pub fn parseRow(line: []const u8) ?struct {
    vmid: []const u8,
    name: []const u8,
    status: []const u8,
} {
    var words = std.mem.tokenizeAny(u8, line, " \t\r");
    const vmid = words.next() orelse return null;
    if (vmid.len == 0 or !std.ascii.isDigit(vmid[0])) return null;
    return .{
        .vmid = vmid,
        .name = words.next() orelse return null,
        .status = words.next() orelse return null,
    };
}

/// The form a VM's config says it was made from, in the description
/// create wrote, or null for a VM that is not ours.
pub fn formOf(config: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, config, '\n');
    while (lines.next()) |l| if (std.mem.startsWith(u8, l, "description: werewolf form: ")) {
        const f = std.mem.trim(u8, l["description: werewolf form: ".len..], " \r");
        return if (f.len > 0) f else null;
    };
    return null;
}

/// The next free VMID in the cluster.
pub fn nextId(io: Io, gpa: Allocator, p: Place) ?[]const u8 {
    const id = ask(io, gpa, p, &.{ "pvesh", "get", "/cluster/nextid" }) orelse return null;
    const t = std.mem.trim(u8, id, "\"");
    return if (t.len > 0 and plain(t)) t else null;
}

/// The VM, made: q35 with OVMF and no vendor keys, since werewolf's boot
/// loader is signed by no one it knows; two CPUs of the host's kind and
/// 2 GiB; the image and the tar imported onto the storage, the tar raw and
/// read-only; virtio network on the bridge, and a virtio random number
/// device; and the serial console on a file on the node, by QEMU's own
/// arguments, which Proxmox passes through for root (args). The form is in
/// the description, and the tag werewolf marks it ours.
pub fn create(
    io: Io,
    gpa: Allocator,
    p: Place,
    vmid: []const u8,
    name: []const u8,
    form: []const u8,
    image: []const u8,
    why: *howl.Why,
) !void {
    try howl.run(io, why, try remote(gpa, p, try createArgs(gpa, p, vmid, name, form, image)));
}

pub fn createArgs(
    gpa: Allocator,
    p: Place,
    vmid: []const u8,
    name: []const u8,
    form: []const u8,
    image: []const u8,
) ![]const []const u8 {
    return try gpa.dupe([]const u8, &.{
        "qm",
        "create",
        vmid,
        "--name",
        name,
        // Quoted for the node's shell, which splits what ssh joined.
        "--description",
        try gpa.print("'werewolf form: {s}'", .{form}),
        "--tags",
        "werewolf",
        "--machine",
        "q35",
        "--bios",
        "ovmf",
        "--efidisk0",
        try gpa.print("{s}:1,efitype=4m,pre-enrolled-keys=0", .{p.storage}),
        "--cpu",
        "host",
        "--cores",
        "2",
        "--memory",
        "2048",
        "--ostype",
        "l26",
        "--scsihw",
        "virtio-scsi-single",
        "--virtio0",
        try gpa.print("{s}:0,import-from={s}", .{ p.storage, image }),
        "--virtio1",
        try configDisk(gpa, p, name),
        "--boot",
        "order=virtio0",
        "--net0",
        try gpa.print("virtio,bridge={s}", .{p.bridge}),
        "--rng0",
        "source=/dev/urandom",
        "--args",
        try gpa.print(
            "'-chardev file,id=werewolf,path={s} -device isa-serial,chardev=werewolf'",
            .{try logPath(gpa, name)},
        ),
    });
}

/// The config tar as a disk: imported raw, so the bytes are the tar's,
/// and read-only.
fn configDisk(gpa: Allocator, p: Place, name: []const u8) ![]const u8 {
    return gpa.print(
        "{s}:0,import-from={s},format=raw,ro=1",
        .{ p.storage, try tarPath(gpa, name) },
    );
}

pub fn start(io: Io, gpa: Allocator, p: Place, vmid: []const u8, why: *howl.Why) !void {
    try howl.run(io, why, try remote(gpa, p, &.{ "qm", "start", vmid }));
}

/// A hard stop: qm shutdown presses the ACPI power button, which no
/// werewolf machine answers on x86_64 yet.
pub fn stop(io: Io, gpa: Allocator, p: Place, vmid: []const u8, why: *howl.Why) !void {
    try howl.run(io, why, try remote(gpa, p, &.{ "qm", "stop", vmid }));
}

/// A new config for a VM that exists: stopped, its tar's disk replaced by
/// one imported from the new tar, the old one, left unused, removed, and
/// started again.
pub fn reconfigure(
    io: Io,
    gpa: Allocator,
    p: Place,
    m: Machine,
    name: []const u8,
    why: *howl.Why,
) !void {
    if (m.running) try stop(io, gpa, p, m.vmid, why);
    try howl.run(
        io,
        why,
        try remote(gpa, p, &.{ "qm", "set", m.vmid, "--virtio1", try configDisk(gpa, p, name) }),
    );
    try howl.run(
        io,
        why,
        try remote(gpa, p, &.{ "qm", "disk", "unlink", m.vmid, "--idlist", "unused0", "--force" }),
    );
}

/// The VM, its disks and its files on the node, gone; the image stays.
pub fn delete(
    io: Io,
    gpa: Allocator,
    p: Place,
    m: Machine,
    name: []const u8,
    why: *howl.Why,
) !void {
    if (m.running) try stop(io, gpa, p, m.vmid, why);
    try howl.run(io, why, try remote(gpa, p, &.{
        "qm",
        "destroy",
        m.vmid,
        "--purge",
        "1",
        "--destroy-unreferenced-disks",
        "1",
    }));
    _ = ask(io, gpa, p, &.{ "rm", "-f", try tarPath(gpa, name), try logPath(gpa, name) });
}

/// The console's size on the node now, so a wait reads only what follows.
pub fn logSize(io: Io, gpa: Allocator, p: Place, name: []const u8) u64 {
    const s = ask(io, gpa, p, &.{ "stat", "-c", "%s", logPath(gpa, name) catch return 0 }) orelse
        return 0;
    return std.fmt.parseInt(u64, s, 10) catch 0;
}

/// The console from byte from on: the whole of it for 0.
pub fn console(io: Io, gpa: Allocator, p: Place, name: []const u8, from: u64) ?[]const u8 {
    return ask(io, gpa, p, &.{
        "tail",
        "-c",
        gpa.print("+{d}", .{from + 1}) catch return null,
        logPath(gpa, name) catch return null,
    });
}

/// Wait for init's "up in" line on the console, past the first seen bytes.
pub fn awaitUp(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    seen: u64,
) !enum { up, panic, late } {
    var waited: u32 = 0;
    while (waited < wait_seconds) : (waited += 5) {
        if (console(io, gpa, p, name, seen)) |text| {
            if (std.mem.find(u8, text, "werewolf: up in ") != null) return .up;
            if (std.mem.find(u8, text, "Kernel panic") != null) return .panic;
        }
        try io.sleep(.fromSeconds(5), .awake);
    }
    return .late;
}

/// The address the console says the machine took: the last DHCP lease
/// dhcp-client reported ("event":"bound", "addr":"A/N"), without its
/// prefix length; null where none was.
pub fn address(text: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| {
        if (std.mem.find(u8, l, "\"event\":\"bound\"") == null) continue;
        const at = std.mem.find(u8, l, "\"addr\":\"") orelse continue;
        const rest = l[at + "\"addr\":\"".len ..];
        const end = std.mem.findScalar(u8, rest, '"') orelse continue;
        const addr = rest[0..end];
        found = addr[0 .. std.mem.findScalar(u8, addr, '/') orelse addr.len];
    }
    return found;
}

const testing = std.testing;

test parseRow {
    const r = parseRow("       101 edge                 running    2048              8.00 12345").?;
    try testing.expectEqualStrings("101", r.vmid);
    try testing.expectEqualStrings("edge", r.name);
    try testing.expectEqualStrings("running", r.status);
    try testing.expectEqual(
        null,
        parseRow("      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID"),
    );
    try testing.expectEqual(null, parseRow(""));
}

test formOf {
    try testing.expectEqualStrings(
        "bastion",
        formOf("boot: order=virtio0\ndescription: werewolf form: bastion\nname: edge\n").?,
    );
    try testing.expectEqual(null, formOf("description: someone else's\n"));
}

test address {
    const text = "dhcp-client: {\"event\":\"bound\",\"nic\":\"eth0\",\"addr\":\"10.0.2.15/24\"}" ++
        "\n" ++
        "werewolf: up in 0.7s\n" ++
        "dhcp-client: {\"event\":\"bound\",\"nic\":\"eth0\",\"addr\":\"192.168.1.40/24\"}\n";
    try testing.expectEqualStrings("192.168.1.40", address(text).?);
    try testing.expectEqual(null, address("werewolf: up in 0.7s\n"));
}

test createArgs {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = try createArgs(
        arena.allocator(),
        .{ .host = "root@pve", .storage = "local-lvm", .bridge = "vmbr0" },
        "101",
        "edge",
        "bastion",
        "/var/lib/vz/werewolf/werewolf-bastion-x86-64-0123456789abcdef.qcow2",
    );
    try testing.expectEqualStrings("101", a[2]);
    try testing.expectEqualStrings("'werewolf form: bastion'", a[6]);
    try testing.expectEqualStrings(
        "local-lvm:0,import-from=/var/lib/vz/werewolf/edge-config.tar,format=raw,ro=1",
        a[28],
    );
    try testing.expect(plain("root@pve1.example:22"));
    try testing.expect(!plain("a b") and !plain("a;b") and !plain("a$b"));
}
