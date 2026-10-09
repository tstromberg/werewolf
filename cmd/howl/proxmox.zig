//! proxmox runs werewolf machines as VMs on a Proxmox VE node, by running
//! qm over ssh. It is experimental and has never run against a real node.
//! See README.md.

const std = @import("std");
const howl = @import("howl.zig");
const images = @import("image.zig");
const booting = @import("boot.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;

/// dir holds werewolf's images, config tars and console logs on the node.
pub const dir = "/var/lib/vz/werewolf";
/// wait_seconds is how long create waits for the machine to boot.
const wait_seconds = 180;

/// Place is the node's ssh host and the storage and bridge VMs use there.
pub const Place = struct { host: []const u8, storage: []const u8, bridge: []const u8 };

/// place reads PROXMOX_HOST, PROXMOX_STORAGE (default local-lvm) and
/// PROXMOX_BRIDGE (default vmbr0). It refuses a missing host or any value
/// that is not plain.
pub fn place(environ: *const std.process.Environ.Map, why: *howl.Why) !Place {
    const host = environ.get("PROXMOX_HOST") orelse return why.refuse(
        "--on proxmox: PROXMOX_HOST=root@NODE names the node, by ssh; PROXMOX_STORAGE " ++
            "(local-lvm) and PROXMOX_BRIDGE (vmbr0) may follow",
        .{},
    );
    const p: Place = .{
        .host = host,
        .storage = environ.get("PROXMOX_STORAGE") orelse "local-lvm",
        .bridge = environ.get("PROXMOX_BRIDGE") orelse "vmbr0",
    };
    for ([_][]const u8{ p.host, p.storage, p.bridge }) |v| if (!plain(v)) return why.refuse(
        "PROXMOX_*: {s}: letters, digits and . _ - @ : only",
        .{v},
    );
    return p;
}

/// plain reports whether s passes through the node's shell unchanged. ssh
/// joins the words of a command and the remote shell splits them again, so
/// a space or shell metacharacter could inject commands.
pub fn plain(s: []const u8) bool {
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, "._-@:", c) == null)
        return false;
    return true;
}

/// remote returns the argv that runs args on the node over ssh.
fn remote(gpa: Allocator, p: Place, args: []const []const u8) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    // Time out in seconds, not TCP's minutes, so a node that drops packets
    // cannot stretch a wait past its limit.
    try argv.appendSlice(gpa, &.{
        "ssh", "-o",                     "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o",  "ServerAliveInterval=15", p.host,
    });
    try argv.appendSlice(gpa, args);
    return argv.items;
}

/// ask runs args on the node and returns its trimmed output, or null if it
/// failed.
fn ask(io: Io, gpa: Allocator, p: Place, args: []const []const u8) ?[]const u8 {
    const r = std.process.run(gpa, io, .{ .argv = remote(gpa, p, args) catch return null }) catch
        return null;
    return if (r.term == .exited and r.term.exited == 0)
        std.mem.trim(u8, r.stdout, " \n")
    else
        null;
}

/// ensureImage returns the image's path on the node, uploading disk unless
/// the file is there. The name holds the digest, so each build uploads once.
pub fn ensureImage(
    io: Io,
    gpa: Allocator,
    p: Place,
    form: []const u8,
    arch: howl.Arch,
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

/// tarPath returns the path of machine name's config tar on the node.
pub fn tarPath(gpa: Allocator, name: []const u8) ![]const u8 {
    return gpa.print("{s}/{s}-config.tar", .{ dir, name });
}

/// logPath returns the path of machine name's console log on the node.
pub fn logPath(gpa: Allocator, name: []const u8) ![]const u8 {
    return gpa.print("{s}/{s}.console", .{ dir, name });
}

/// upload copies the config tar to the node, keeping its 0600 mode.
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

/// Machine is a werewolf VM on the node.
pub const Machine = struct { vmid: []const u8, running: bool, form: []const u8 };

/// find returns the werewolf VM called name, or null if there is none. A
/// node that does not answer is refused: treating it as "no VM" would make
/// delete forget a VM that is still running.
pub fn find(io: Io, gpa: Allocator, p: Place, name: []const u8, why: *howl.Why) !?Machine {
    const list = ask(io, gpa, p, &.{ "qm", "list" }) orelse
        return why.refuse("{s}: qm list failed", .{p.host});
    var lines = std.mem.splitScalar(u8, list, '\n');
    while (lines.next()) |line| {
        const row = parseRow(line) orelse continue;
        if (!std.mem.eql(u8, row.name, name)) continue;
        const config = ask(io, gpa, p, &.{ "qm", "config", row.vmid }) orelse
            return why.refuse("{s}: qm config {s} failed", .{ p.host, row.vmid });
        const form = formOf(config) orelse continue;
        return .{
            .vmid = row.vmid,
            .running = std.mem.eql(u8, row.status, "running"),
            .form = form,
        };
    }
    return null;
}

/// parseRow parses a qm list row (VMID NAME STATUS ...). It returns null
/// for the header.
pub fn parseRow(line: []const u8) ?struct {
    vmid: []const u8,
    name: []const u8,
    status: []const u8,
} {
    var words = std.mem.tokenizeAny(u8, line, " \t\r");
    const vmid = words.next() orelse return null;
    // Accept digits only: the id is passed back to the node's shell.
    for (vmid) |c| if (!std.ascii.isDigit(c)) return null;
    return .{
        .vmid = vmid,
        .name = words.next() orelse return null,
        .status = words.next() orelse return null,
    };
}

/// formOf returns the form named in the description create wrote, or null
/// for a VM werewolf did not make.
pub fn formOf(config: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, config, '\n');
    const prefix = "description: " ++ howl.form_tag ++ ": ";
    while (lines.next()) |l| if (std.mem.startsWith(u8, l, prefix)) {
        const f = std.mem.trim(u8, l[prefix.len..], " \r");
        return if (f.len > 0) f else null;
    };
    return null;
}

/// nextId returns the cluster's next free VMID.
pub fn nextId(io: Io, gpa: Allocator, p: Place) ?[]const u8 {
    const id = ask(io, gpa, p, &.{ "pvesh", "get", "/cluster/nextid" }) orelse return null;
    const t = std.mem.trim(u8, id, "\"");
    return if (t.len > 0 and plain(t)) t else null;
}

/// create makes VM vmid from image, without starting it. See createArgs.
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

/// createArgs returns the qm create command. OVMF gets no pre-enrolled keys
/// because no vendor signs werewolf's loader. The config tar is a raw,
/// read-only second disk. Proxmox keeps no serial log, so QEMU args (root
/// only) write the console to a file. The tag and description mark the VM
/// as werewolf's.
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
        // Quote it: the node's shell splits what ssh joined.
        "--description",
        try gpa.print("'{s}: {s}'", .{ howl.form_tag, form }),
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
        std.fmt.comptimePrint("{d}", .{howl.local_cpus}),
        "--memory",
        std.fmt.comptimePrint("{d}", .{howl.local_mib}),
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

/// configDisk returns the spec that imports the config tar as a raw,
/// read-only disk, so init reads the tar's bytes as they are.
fn configDisk(gpa: Allocator, p: Place, name: []const u8) ![]const u8 {
    return gpa.print(
        "{s}:0,import-from={s},format=raw,ro=1",
        .{ p.storage, try tarPath(gpa, name) },
    );
}

pub fn start(io: Io, gpa: Allocator, p: Place, vmid: []const u8, why: *howl.Why) !void {
    try howl.run(io, why, try remote(gpa, p, &.{ "qm", "start", vmid }));
}

/// stop powers the VM off hard. qm shutdown would press the ACPI power
/// button, which werewolf does not yet answer on x86_64.
pub fn stop(io: Io, gpa: Allocator, p: Place, vmid: []const u8, why: *howl.Why) !void {
    try howl.run(io, why, try remote(gpa, p, &.{ "qm", "stop", vmid }));
}

/// reconfigure stops the VM, swaps its config disk for one imported from the
/// uploaded tar, and removes the old disk. The caller starts it again.
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

/// delete destroys the VM, its disks, and its config tar and console log.
/// The image stays for later machines.
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

/// logSize returns the console log's current size, so a later wait reads
/// only new output.
pub fn logSize(io: Io, gpa: Allocator, p: Place, name: []const u8) u64 {
    const s = ask(io, gpa, p, &.{ "stat", "-c", "%s", logPath(gpa, name) catch return 0 }) orelse
        return 0;
    return std.fmt.parseInt(u64, s, 10) catch 0;
}

/// console returns the console log from byte offset from on.
pub fn console(io: Io, gpa: Allocator, p: Place, name: []const u8, from: u64) ?[]const u8 {
    return ask(io, gpa, p, &.{
        "tail",
        "-c",
        gpa.print("+{d}", .{from + 1}) catch return null,
        logPath(gpa, name) catch return null,
    });
}

/// awaitUp waits for the boot to finish or panic, ignoring the first seen
/// bytes of the console.
pub fn awaitUp(
    io: Io,
    gpa: Allocator,
    p: Place,
    name: []const u8,
    seen: u64,
) !booting.Outcome {
    var waited: u32 = 0;
    while (waited < wait_seconds) : (waited += 5) {
        if (console(io, gpa, p, name, seen)) |text| if (booting.outcome(text)) |o| return o;
        try io.sleep(.fromSeconds(5), .awake);
    }
    return .late;
}

/// address returns the IPv4 address of the last lease dhcp-client logged on
/// the console ("event":"bound"), without its prefix length, or null.
pub fn address(text: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| {
        if (std.mem.find(u8, l, "\"event\":\"bound\"") == null) continue;
        const at = std.mem.find(u8, l, "\"addr\":\"") orelse continue;
        const rest = l[at + "\"addr\":\"".len ..];
        const end = std.mem.findScalar(u8, rest, '"') orelse continue;
        const addr = rest[0..end];
        const ip = addr[0 .. std.mem.findScalar(u8, addr, '/') orelse addr.len];
        // The guest wrote this text, so accept only a real address.
        if (isIp4(ip)) found = ip;
    }
    return found;
}

/// isIp4 reports whether s is a dotted-quad IPv4 address.
fn isIp4(s: []const u8) bool {
    var octets = std.mem.splitScalar(u8, s, '.');
    var n: usize = 0;
    while (octets.next()) |o| : (n += 1) {
        if (o.len == 0 or o.len > 3) return false;
        for (o) |c| if (!std.ascii.isDigit(c)) return false;
        if ((std.fmt.parseInt(u16, o, 10) catch return false) > 255) return false;
    }
    return n == 4;
}

test isIp4 {
    try testing.expect(isIp4("192.168.1.40"));
    try testing.expect(!isIp4("192.168.1"));
    try testing.expect(!isIp4("192.168.1.256"));
    try testing.expect(!isIp4("1.2.3.4.5"));
    try testing.expect(!isIp4("1.2.3.\x1b[2J"));
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
        formOf("boot: order=virtio0\ndescription: werewolf-form: bastion\nname: edge\n").?,
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
    try testing.expectEqualStrings("'werewolf-form: bastion'", a[6]);
    try testing.expectEqualStrings(
        "local-lvm:0,import-from=/var/lib/vz/werewolf/edge-config.tar,format=raw,ro=1",
        a[28],
    );
    try testing.expect(plain("root@pve1.example:22"));
    try testing.expect(!plain("a b") and !plain("a;b") and !plain("a$b"));
}
