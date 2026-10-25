//! check-image-updater QEMU... boots minimal with IPE, has its updater
//! fetch a signed update over HTTPS from this host, and checks each wrong
//! update (bad signature, wrong channel or arch, older or reused serial, a
//! tampered root, a missing or false ipe flag) is refused before a slot is
//! written, and the valid one installed, rebooted into and committed.
//! With IPE_UPDATE_BOOT=efi it boots one disk through firmware instead, and
//! with IPE_UPDATE_SECUREBOOT=1 a native signed UKI under Secure Boot,
//! after enrolled firmware refuses unsigned, tampered and wrongly signed
//! loaders and UKIs, a non-canonical slot path and setup mode. make
//! check-image-updater and check-image-updater-uki give CHECK_ENV, ARCH,
//! IPE_KEY, IPE_CERT, IPE_KERNEL and FIRMWARE; IPE_UPDATE_CASES picks cases.

const std = @import("std");
const host = @import("host");
const form = @import("form");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;
const join = std.fs.path.join;
const Machine = host.qemu.Machine;

const channel = "https://10.0.2.100/image";
const channel_host = "10.0.2.100";
// Native UKIs bind the boot filesystem identity from cmd/howl/disk.zig.
const native_slots = "57e1f000-77e2-4b0f-8a3c-0000000000a0";
const esp_serial = "57e1f000";

pub fn main(init: std.process.Init) void {
    const args = init.minimal.args.toSlice(init.arena.allocator()) catch std.process.exit(1);
    // QEMU's guestfwd runs this program again to reach the channel.
    if (args.len == 3 and mem.eql(u8, args[1], "--relay")) relay(init.io, args[2]);
    var c = host.Check.init(init, "image-updater") catch |err| {
        std.log.err("check-image-updater: {t}", .{err});
        std.process.exit(1);
    };
    c.finish(run(&c));
}

/// Case is one update the guest is offered, and the refusal it must meet.
const Case = struct { label: []const u8, expected: ?[]const u8 };

const cases = [_]Case{
    .{ .label = "bad-signature", .expected = "BadSignature" },
    .{ .label = "wrong-channel", .expected = "WrongImageChannel" },
    .{ .label = "wrong-arch", .expected = "WrongImageArch" },
    .{ .label = "older", .expected = "OlderImage" },
    .{ .label = "serial-reused", .expected = "ImageSerialReused" },
    .{ .label = "tampered-root", .expected = "ImageArtifactMismatch" },
    .{ .label = "missing-ipe", .expected = "MissingField" },
    .{ .label = "not-ipe", .expected = "NotAnIpeImage" },
    .{ .label = "valid", .expected = null },
};

const Updater = struct {
    c: *host.Check,
    table: host.evidence.Table,
    arch: []const u8,
    key: []const u8,
    cert: []const u8,
    debugfs: []const u8,
    e2fsck: []const u8,
    secure: bool,
    /// qemu is the machine's command line, its network the channel's relay.
    qemu: []const []const u8 = &.{},
    cmdline: []const u8 = "",
    slots: []const u8,
    /// out is the second release's howl output, whose public key and
    /// prebuilt bundle the cases use.
    out: []const u8 = "",
};

fn need(c: *host.Check, name: []const u8) ![]const u8 {
    return c.env.get(name) orelse c.fail("{s} is not set", .{name});
}

fn run(c: *host.Check) !void {
    const gpa = c.gpa;
    const io = c.io;
    try c.setWork(try join(gpa, &.{ try need(c, "CHECK"), "image-updater" }));
    const arch = try need(c, "ARCH");
    const debugfs = try need(c, "DEBUGFS");
    const firmware_boot = mem.eql(u8, c.env.get("IPE_UPDATE_BOOT") orelse "", "efi");
    const secure = firmware_boot and
        mem.eql(u8, c.env.get("IPE_UPDATE_SECUREBOOT") orelse "", "1");
    var u: Updater = .{
        .c = c,
        .table = try host.evidence.load(gpa, form),
        .arch = arch,
        .key = try c.absolute(try need(c, "IPE_KEY")),
        .cert = try c.absolute(try need(c, "IPE_CERT")),
        .debugfs = debugfs,
        .e2fsck = try sibling(gpa, debugfs, "e2fsck"),
        .secure = secure,
        .slots = if (secure) native_slots else try need(c, "SLOTS"),
    };
    const names = c.env.get("IPE_UPDATE_CASES") orelse "";
    const selected = try selection(gpa, names, firmware_boot);
    for (selected) |label| for (cases) |k| {
        if (mem.eql(u8, k.label, label)) break;
    } else return c.fail("unknown IPE_UPDATE_CASES", .{});

    // The channel's authority, which the images trust as their only roots.
    const ca = try host.tls.Authority.init(io, gpa, "prebuilt-check");
    const identity = try ca.issue(io, gpa, &.{channel_host});
    const ca_pem = try c.path("tls-ca.crt");
    try write(io, ca_pem, try ca.pem(gpa));

    const now: i64 = @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    const old_serial = serial(@intCast(now - 120));
    const new_serial = serial(@intCast(now - 60));
    const kernel = try c.absolute(try need(c, "IPE_KERNEL"));
    const howl = try c.absolute(try need(c, "HOWL"));
    var manifest_b: []const u8 = "";
    var build_b: []const u8 = "";
    for ([_][2][]const u8{ .{ "a", &old_serial }, .{ "b", &new_serial } }) |variant| {
        const label = variant[0];
        const app = try c.path(try gpa.print("app-{s}", .{label}));
        const certs = try join(gpa, &.{ app, "etc/ssl/certs" });
        try Io.Dir.cwd().createDirPath(io, certs);
        try copy(io, ca_pem, try join(gpa, &.{ certs, "ca-certificates.crt" }));
        try write(io, try join(gpa, &.{ app, "etc/prebuilt-marker" }), label);
        const built = try host.provider.buildArgv(gpa, .{
            .howl = howl,
            .form = "minimal",
            .arch = arch,
            .kernel = kernel,
            .key = u.key,
            .cert = u.cert,
            .build = try c.path("build"),
            .channel = channel,
            .serial = variant[1],
            .boot_key = if (secure) u.key else null,
            .boot_cert = if (secure) u.cert else null,
            .app = app,
            .goals = if (firmware_boot) &.{ "prebuilt", "disk" } else &.{"prebuilt"},
            .disk_args = if (secure) try need(c, "CMDLINE") else null,
        });
        const log = try gpa.print("build-{s}", .{label});
        _ = try c.must(built.argv, log, .{ .timeout = .fromSeconds(3600) });
        const slot = try c.path(try gpa.print("slot-{s}", .{label}));
        Io.Dir.cwd().deleteTree(io, slot) catch {};
        try host.check.copyTree(io, gpa, try join(gpa, &.{ built.output, "slot" }), slot);
        const latest = try join(gpa, &.{ built.output, "prebuilt", arch, "latest.json" });
        const manifest = try Io.Dir.cwd().readFileAlloc(io, latest, gpa, .limited(1 << 20));
        const parsed = try json.parseFromSliceLeaky(json.Value, gpa, manifest, .{});
        c.say("built  image-{s}: {s}", .{ label, try text(parsed, "build") });
        manifest_b = manifest;
        build_b = try text(parsed, "build");
        u.out = built.output;
    }

    const www = try c.path("www");
    Io.Dir.cwd().deleteTree(io, www) catch {};
    try Io.Dir.cwd().createDirPath(io, www);
    const image_dir = try join(gpa, &.{ www, "image" });
    try host.check.copyTree(io, gpa, try join(gpa, &.{ u.out, "prebuilt" }), image_dir);
    const latest = try join(gpa, &.{ image_dir, arch, "latest.json" });
    const signature = try join(gpa, &.{ image_dir, arch, "latest.json.sig" });
    const payload_root = try join(gpa, &.{ image_dir, arch, build_b, "root.erofs" });
    const original_root = try Io.Dir.cwd().readFileAlloc(
        io,
        try c.path("slot-b/root.erofs"),
        gpa,
        .unlimited,
    );
    const base = try slotDisk(&u);

    var files: host.http.Files = .{
        .io = io,
        .gpa = gpa,
        .root = try Io.Dir.cwd().openDir(io, www, .{}),
    };
    defer files.root.close(io);
    var server: host.http.Server = undefined;
    try server.start(io, gpa, .{ .identity = &identity, .handler = files.handler() });
    defer server.stop();
    const self = try std.process.executablePathAlloc(io, gpa);
    const port = try gpa.print("{d}", .{server.port()});
    const relay_command = try host.check.join(gpa, &.{ self, "--relay", port });
    const guestfwd = try gpa.print(
        "user,id=n0,restrict=on,guestfwd=tcp:{s}:443-cmd:{s}",
        .{ channel_host, relay_command },
    );
    const nic = "virtio-net-pci,netdev=n0,romfile=";
    const net = [_][]const u8{ "-netdev", guestfwd, "-device", nic };
    u.qemu = try mem.concat(gpa, []const u8, &.{ c.args[1..], &net });
    const slot_cmdline = try Io.Dir.cwd().readFileAlloc(
        io,
        try c.path("slot-a/cmdline"),
        gpa,
        .limited(64 << 10),
    );
    u.cmdline = try gpa.print("{s} {s} init=/init werewolf.slots={s} werewolf.esp=57E1-F000", .{
        try need(c, "CMDLINE"), mem.trim(u8, slot_cmdline, " \t\r\n"), u.slots,
    });

    const initial = try c.path("initial");
    try Io.Dir.cwd().createDirPath(io, initial);
    for ([_][]const u8{ "vmlinuz", "stage0.zst" }) |name| {
        const from = try c.path(try gpa.print("slot-a/{s}", .{name}));
        try copy(io, from, try join(gpa, &.{ initial, name }));
    }

    for (cases) |k| {
        if (selected.len > 0) for (selected) |s| {
            if (mem.eql(u8, s, k.label)) break;
        } else continue;
        var document = try json.parseFromSliceLeaky(json.Value, gpa, manifest_b, .{});
        try write(io, payload_root, original_root);
        try alter(gpa, &document, k.label, arch, now, &old_serial);
        if (mem.eql(u8, k.label, "tampered-root")) {
            const damaged = try gpa.dupe(u8, original_root);
            damaged[0] ^= 1;
            try write(io, payload_root, damaged);
        }
        const head = try json.Stringify.valueAlloc(gpa, document, .{ .whitespace = .indent_2 });
        try write(io, latest, try gpa.print("{s}\n", .{head}));
        const sign = [_][]const u8{ "openssl", "dgst", "-sha256", "-sign", u.key, "-out" };
        _ = try c.must(&(sign ++ .{ signature, latest }), "sign", .{});
        if (mem.eql(u8, k.label, "bad-signature")) try write(io, signature, "invalid signature");
        const image = try c.path(try gpa.print("{s}.img", .{k.label}));
        try copy(io, base, image);
        if (firmware_boot) {
            try firmwareUpdate(&u, image, document);
            continue;
        }
        try direct(&u, k, image, document);
    }
}

/// selection is the cases IPE_UPDATE_CASES names; a firmware boot tests
/// only the valid update. Empty selects every case.
fn selection(gpa: Allocator, names: []const u8, firmware_boot: bool) ![]const []const u8 {
    if (firmware_boot) return gpa.dupe([]const u8, &.{"valid"});
    var out: std.ArrayList([]const u8) = .empty;
    var it = mem.tokenizeScalar(u8, names, ',');
    while (it.next()) |n| try out.append(gpa, n);
    return out.items;
}

/// alter makes the second release's signed document the case's: wrong in
/// the one way the case is named for.
fn alter(
    gpa: Allocator,
    document: *json.Value,
    label: []const u8,
    arch: []const u8,
    now: i64,
    old_serial: []const u8,
) !void {
    const o = &document.object;
    if (mem.eql(u8, label, "wrong-channel")) {
        try o.put(gpa, "channel", .{ .string = "https://10.0.2.100/other" });
    } else if (mem.eql(u8, label, "wrong-arch")) {
        const other = if (mem.eql(u8, arch, "aarch64")) "x86_64" else "aarch64";
        try o.put(gpa, "arch", .{ .string = other });
    } else if (mem.eql(u8, label, "older")) {
        const day_old = serial(@intCast(now - 86400));
        try o.put(gpa, "serial", .{ .string = try gpa.dupe(u8, &day_old) });
    } else if (mem.eql(u8, label, "serial-reused")) {
        try o.put(gpa, "serial", .{ .string = old_serial });
    } else if (mem.eql(u8, label, "missing-ipe")) {
        _ = o.orderedRemove("ipe");
    } else if (mem.eql(u8, label, "not-ipe")) {
        try o.put(gpa, "ipe", .{ .bool = false });
    }
}

/// serial is a release serial, YYYYMMDDTHHMMSSZ, for seconds since 1970.
fn serial(seconds: u64) [16]u8 {
    const at: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year = at.getEpochDay().calculateYearDay();
    const month = year.calculateMonthDay();
    const day = at.getDaySeconds();
    var out: [16]u8 = undefined;
    _ = std.mem.print(&out, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        year.year,             month.month.numeric(),    month.day_index + 1,
        day.getHoursIntoDay(), day.getMinutesIntoHour(), day.getSecondsIntoMinute(),
    }) catch unreachable;
    return out;
}

fn text(v: json.Value, key: []const u8) ![]const u8 {
    if (v != .object) return error.BadManifest;
    const got = v.object.get(key) orelse return error.BadManifest;
    return if (got == .string) got.string else error.BadManifest;
}

/// fileDigest is a signed document's sha256 for one of its files.
fn fileDigest(document: json.Value, name: []const u8) ![]const u8 {
    if (document != .object) return error.BadManifest;
    const listed = document.object.get("files") orelse return error.BadManifest;
    if (listed != .object) return error.BadManifest;
    return text(listed.object.get(name) orelse return error.BadManifest, "sha256");
}

fn sibling(gpa: Allocator, path: []const u8, name: []const u8) ![]const u8 {
    return join(gpa, &.{ std.fs.path.dirname(path) orelse ".", name });
}

fn write(io: Io, path: []const u8, data: []const u8) !void {
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
}

fn copy(io: Io, from: []const u8, to: []const u8) !void {
    try Io.Dir.cwd().copyFile(from, .cwd(), to, io, .{});
}

fn same(io: Io, a: []const u8, b: []const u8) !bool {
    return mem.eql(u8, &try host.check.digest(io, a), &try host.check.digest(io, b));
}

fn signed(io: Io, path: []const u8, document: json.Value, name: []const u8) !bool {
    return mem.eql(u8, &try host.check.hexDigest(io, path), try fileDigest(document, name));
}

/// direct boots slot a from the kernel directly, on a native EFI
/// partition, and judges what its updater did with the offered update.
fn direct(u: *Updater, k: Case, image: []const u8, document: json.Value) !void {
    const c = u.c;
    const gpa = c.gpa;
    const io = c.io;
    const esp = try c.path("direct-esp.img");
    _ = try c.must(&.{ "sh", "test/slot-esp", esp, "a", u.cmdline }, "slot-esp", .{});
    const until = if (k.expected != null) "\"event\":\"error\"" else "\"event\":\"reboot\"";
    const outcome = try boot(u, k.label, image, "a", try c.path("initial"), until);
    replay(u, image);
    const root_file = try c.path(try gpa.print("{s}.erofs", .{k.label}));
    try dump(u, image, "/slot/b/root.erofs", root_file);
    const log = try c.path(try gpa.print("{s}.log", .{k.label}));
    if (k.expected) |expected| {
        const said = try gpa.print("\"error\":\"{s}\"", .{expected});
        const staged = mem.find(u8, outcome, "\"event\":\"stage\"") != null;
        if (mem.find(u8, outcome, said) == null or staged)
            return c.fail("{s}: unexpected outcome; see {s}", .{ k.label, log });
        if (!try same(io, root_file, try c.path("slot-a/root.erofs")))
            return c.fail("{s}: changed slot before verification", .{k.label});
        c.say("pass   {s}: held before slot writes", .{k.label});
        return;
    }
    if (!try signed(io, root_file, document, "root.erofs"))
        return c.fail("installed root differs from signed artifact", .{});
    const parked = try c.path("parked");
    try Io.Dir.cwd().createDirPath(io, parked);
    for ([_][]const u8{ "vmlinuz", "stage0.zst" }) |name| {
        const from = try gpa.print("::/werewolf/b/{s}", .{name});
        const to = try join(gpa, &.{ parked, name });
        _ = try c.must(&.{ "mcopy", "-o", "-i", esp, from, to }, "parked", .{});
    }
    for ([_][]const u8{ "image.json", "image.json.sig", "cmdline" }) |name| {
        const to = try join(gpa, &.{ parked, name });
        try dump(u, image, try gpa.print("/slot/b/{s}", .{name}), to);
    }
    const public = try join(gpa, &.{ u.out, "meta/usr/share/werewolf/image-update/image.pub" });
    const verify = [_][]const u8{ "openssl", "dgst", "-sha256", "-verify", public, "-signature" };
    const parked_signature = try join(gpa, &.{ parked, "image.json.sig" });
    const parked_head = try join(gpa, &.{ parked, "image.json" });
    _ = try c.must(&(verify ++ .{ parked_signature, parked_head }), "verify-parked", .{});
    if (!try signed(io, try join(gpa, &.{ parked, "stage0.zst" }), document, "stage0.zst"))
        return c.fail("EFI partition holds the wrong signed stage0", .{});
    const committed = "\"event\":\"commit\",\"slot\":\"b\"";
    const second = try boot(u, "commit", image, "b", parked, committed);
    const ipe = "IPE: only this root image may execute; policy administration removed";
    if (mem.find(u8, second, ipe) == null) return c.fail("new slot did not enforce IPE", .{});
    const what = "fetched, verified, installed, rebooted and committed with IPE";
    c.say("pass   signed-image: {s}", .{what});
}

/// slotDisk makes base.img, an ext4 slots filesystem whose slots a and b
/// both hold release a's root, owned by guest root as real slots are:
/// the broker has no DAC override.
fn slotDisk(u: *Updater) ![]const u8 {
    const c = u.c;
    const gpa = c.gpa;
    const io = c.io;
    const slots = try c.path("slots");
    Io.Dir.cwd().deleteTree(io, slots) catch {};
    for ([_][]const u8{ "a", "b" }) |name| {
        const dir = try join(gpa, &.{ slots, "slot", name });
        try Io.Dir.cwd().createDirPath(io, dir);
        try copy(io, try c.path("slot-a/root.erofs"), try join(gpa, &.{ dir, "root.erofs" }));
    }
    const base = try c.path("base.img");
    const mke2fs = try sibling(gpa, u.debugfs, "mke2fs");
    const format = [_][]const u8{ mke2fs, "-q", "-F", "-t", "ext4", "-U", u.slots, "-d" };
    _ = try c.must(&(format ++ .{ slots, base, "512M" }), "mke2fs", .{});
    const ownership = try c.path("ownership.debugfs");
    try write(io, ownership, try rootOwned(gpa));
    _ = try c.must(&.{ u.debugfs, "-w", "-f", ownership, base }, "ownership", .{});
    return base;
}

/// rootOwned is the debugfs script giving guest root the slot tree that
/// mke2fs gave the staging user.
fn rootOwned(gpa: Allocator) ![]const u8 {
    const paths = [_][]const u8{
        "/slot", "/slot/a", "/slot/b", "/slot/a/root.erofs", "/slot/b/root.erofs",
    };
    var out: std.ArrayList(u8) = .empty;
    for (paths) |p| for ([_][]const u8{ "uid", "gid" }) |owner|
        try out.print(gpa, "set_inode_field {s} {s} 0\n", .{ p, owner });
    return out.items;
}

/// boot runs slot from files' kernel and stage0 until the console says
/// until on a whole line, which must follow the coordinator's credentials.
fn boot(
    u: *Updater,
    label: []const u8,
    image: []const u8,
    slot: []const u8,
    files: []const u8,
    until: []const u8,
) ![]const u8 {
    const c = u.c;
    const gpa = c.gpa;
    const log = try c.path(try gpa.print("{s}.log", .{label}));
    const esp = try c.path("direct-esp.img");
    const argv = try mem.concat(gpa, []const u8, &.{ u.qemu, &.{
        "-kernel", try join(gpa, &.{ files, "vmlinuz" }),
        "-initrd", try join(gpa, &.{ files, "stage0.zst" }),
        "-append", try gpa.print("{s} werewolf.slot={s}", .{ u.cmdline, slot }),
        "-drive",  try gpa.print("file={s},format=raw,if=virtio", .{image}),
        "-drive",  try gpa.print("file={s},format=raw,if=virtio", .{esp}),
    } });
    var m: Machine = undefined;
    try m.start(c.io, gpa, argv, .{ .log = log, .environ_map = &c.env });
    const result = m.until(host.qemu.after(c.io, 300), Line{ .needle = until });
    m.stop(.fromSeconds(10));
    const console = try m.console(gpa);
    result catch return c.fail("{s}: no expected outcome; see {s}\n{s}", .{
        label, log, host.check.tail(console, 4000),
    });
    var why: host.check.Why = .{};
    host.evidence.updaterConsole(u.table, console, 1, &why) catch
        return c.fail("{s}: {s}", .{ label, why.text });
    return console;
}

/// Line is done once needle has been followed by the end of its line.
const Line = struct {
    needle: []const u8,

    pub fn done(l: Line, console: []const u8) !bool {
        return wholeLine(console, l.needle);
    }
};

fn wholeLine(console: []const u8, needle: []const u8) bool {
    var from: usize = 0;
    while (mem.findPos(u8, console, from, needle)) |at| : (from = at + 1) {
        const end = mem.findAnyPos(u8, console, at + needle.len, "\r\n") orelse continue;
        if (console[end] == '\n') return true;
        if (end + 1 < console.len and console[end + 1] == '\n') return true;
    }
    return false;
}

fn replay(u: *Updater, image: []const u8) void {
    _ = u.c.run(&.{ u.e2fsck, "-y", "-E", "journal_only", image }, "", .{}) catch {};
}

fn dump(u: *Updater, image: []const u8, source: []const u8, destination: []const u8) !void {
    const c = u.c;
    Io.Dir.cwd().deleteFile(c.io, destination) catch {};
    const request = try c.gpa.print("dump {s} {s}", .{ source, destination });
    _ = try c.must(&.{ u.debugfs, "-R", request, image }, "dump", .{});
    const st = Io.Dir.cwd().statFile(c.io, destination, .{}) catch
        return c.fail("no {s} in {s}", .{ source, image });
    if (st.kind != .file) return c.fail("no {s} in {s}", .{ source, image });
}

/// firmwareArgv is the machine booting from firmware: it may reboot, from
/// slot a into b, on a machine with flash (and SMM on x86).
fn firmwareArgv(gpa: Allocator, qemu: []const []const u8, arch: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < qemu.len) : (i += 1) {
        if (mem.eql(u8, qemu[i], "-no-reboot")) continue;
        try out.append(gpa, qemu[i]);
        if (mem.eql(u8, qemu[i], "-M") and i + 1 < qemu.len) {
            try out.append(gpa, if (mem.eql(u8, arch, "aarch64")) "virt" else "q35,smm=on");
            i += 1;
        }
    }
    return out.items;
}

/// entry is slot a's loader entry: Linux and stage0 with the slot's
/// command line, or, natively, the signed UKI. The UKI's options try to
/// redirect it, which its signed command line must ignore.
fn entry(gpa: Allocator, secure: bool, options: []const u8) ![]const u8 {
    const title = "title werewolf a\nversion 19800101T000000Z\n";
    if (secure) return title ++ "uki /werewolf/a/uki.efi\n" ++
        "options init=/untrusted werewolf.slot=b ipe.enforce=0\n";
    const kernel = "linux /werewolf/a/vmlinuz\ninitrd /werewolf/a/stage0.zst\n";
    return gpa.print(title ++ kernel ++ "options {s}\n", .{options});
}

/// makeEsp makes esp, slot a's FAT EFI partition with no partition table,
/// holding systemd-boot (signed natively) and slot a's entry and kernel.
fn makeEsp(u: *Updater, esp: []const u8, efi_name: []const u8) !void {
    const c = u.c;
    const gpa = c.gpa;
    const io = c.io;
    {
        const f = try Io.Dir.cwd().createFile(io, esp, .{});
        defer f.close(io);
        try f.setLength(io, 256 << 20);
    }
    _ = try c.must(&.{ "mformat", "-F", "-N", esp_serial, "-i", esp, "::" }, "esp", .{});
    {
        // No MBR partition table: firmware must take the whole disk as FAT.
        const f = try Io.Dir.cwd().openFile(io, esp, .{ .mode = .read_write });
        defer f.close(io);
        try f.writePositionalAll(io, &@as([64]u8, @splat(0)), 446);
    }
    const dirs = [_][]const u8{ "::/EFI", "::/EFI/BOOT", "::/loader", "::/loader/entries" };
    const slot_dirs = [_][]const u8{ "::/werewolf", "::/werewolf/a" };
    _ = try c.must(&([_][]const u8{ "mmd", "-i", esp } ++ dirs ++ slot_dirs), "esp", .{});
    const efi_arch = if (mem.eql(u8, u.arch, "aarch64")) "aa64" else "x64";
    var loader = try c.path("systemd-boot.efi");
    const member = try gpa.print("usr/lib/systemd/boot/efi/systemd-boot{s}.efi", .{efi_arch});
    const rootfs = try c.path("build/boot/rootfs.tar");
    const extracted = try c.must(&.{ "bsdtar", "-xOf", rootfs, member }, "", .{});
    try write(io, loader, extracted.stdout);
    if (u.secure) {
        const signed_loader = try c.path("systemd-boot.signed.efi");
        Io.Dir.cwd().deleteFile(io, signed_loader) catch {};
        const sign = [_][]const u8{ "osslsigncode", "sign", "-certs", u.cert, "-key", u.key };
        _ = try c.must(&(sign ++ .{ "-in", loader, "-out", signed_loader }), "sign-loader", .{});
        loader = signed_loader;
    }
    const boot_file = try gpa.print("::/EFI/BOOT/{s}", .{efi_name});
    _ = try c.must(&.{ "mcopy", "-i", esp, loader, boot_file }, "esp", .{});
    const entry_file = try c.path("entry.conf");
    const options = try gpa.print("{s} werewolf.slot=a", .{u.cmdline});
    try write(io, entry_file, try entry(gpa, u.secure, options));
    const startup = try c.path("startup.nsh");
    try write(io, startup, try gpa.print("@echo -on\r\nFS0:\\EFI\\BOOT\\{s}\r\n", .{efi_name}));
    const a_entry = "::/loader/entries/werewolf-a+1.conf";
    _ = try c.must(&.{ "mcopy", "-i", esp, entry_file, a_entry }, "esp", .{});
    _ = try c.must(&.{ "mcopy", "-i", esp, startup, "::/startup.nsh" }, "esp", .{});
    const direct_files: []const []const u8 = &.{ "vmlinuz", "stage0.zst" };
    const kernel_files: []const []const u8 = if (u.secure) &.{"uki.efi"} else direct_files;
    for (kernel_files) |name| {
        const from = try c.path(try gpa.print("slot-a/{s}", .{name}));
        const to = try gpa.print("::/werewolf/a/{s}", .{name});
        _ = try c.must(&.{ "mcopy", "-i", esp, from, to }, "esp", .{});
    }
}

/// firmwareUpdate boots one disk through firmware and systemd-boot, from
/// slot a to the update's slot b and its commit.
fn firmwareUpdate(u: *Updater, image: []const u8, document: json.Value) !void {
    const c = u.c;
    const gpa = c.gpa;
    const io = c.io;
    const arm = mem.eql(u8, u.arch, "aarch64");
    const efi_name = if (arm) "BOOTAA64.EFI" else "BOOTX64.EFI";
    const esp = try c.path("esp.img");
    try makeEsp(u, esp, efi_name);

    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(gpa, try firmwareArgv(gpa, u.qemu, u.arch));
    const enrolled = try c.path("enrolled");
    const vars = try join(gpa, &.{ enrolled, "vars.fd" });
    var enrolled_digest: [32]u8 = undefined;
    if (u.secure) {
        var env = try c.env.clone(gpa);
        try env.put("ENROLL_TEST_SETUP", "1");
        const enroll = [_][]const u8{ "tools/enroll-boot", u.arch, u.cert, enrolled };
        _ = try c.must(&enroll, "enroll", .{ .environ_map = &env });
        const smm = "driver=cfi.pflash01,property=secure,value=on";
        if (!arm) try args.appendSlice(gpa, &.{ "-global", smm });
        try firmwareRefusals(u, args.items, esp, image, enrolled, efi_name);
        enrolled_digest = try host.check.digest(io, vars);
        const code_fd = try gpa.print("{s}/code.fd", .{enrolled});
        const code = try gpa.print("if=pflash,format=raw,readonly=on,file={s}", .{code_fd});
        const frozen = if (arm) "readonly=on," else "";
        const flash = try gpa.print("if=pflash,format=raw,{s}file={s}", .{ frozen, vars });
        try args.appendSlice(gpa, &.{ "-drive", code, "-drive", flash });
    } else {
        const firmware = c.env.get("FIRMWARE") orelse return c.fail("FIRMWARE is not set", .{});
        try args.appendSlice(gpa, &.{ "-bios", firmware });
    }
    try args.appendSlice(gpa, &.{
        "-boot",  "menu=on,splash-time=0",
        "-drive", try gpa.print("file={s},format=raw,if=virtio", .{esp}),
        "-drive", try gpa.print("file={s},format=raw,if=virtio", .{image}),
    });
    var m: Machine = undefined;
    const log = try c.path("firmware.log");
    try m.start(io, gpa, args.items, .{ .log = log, .environ_map = &c.env });
    const result = m.waitFor("\"event\":\"commit\",\"slot\":\"b\"", host.qemu.after(io, 900));
    m.stop(.fromSeconds(30));
    result catch |err| return switch (err) {
        error.MachineExited => c.fail("firmware exited; see firmware.log", .{}),
        else => c.fail("firmware update did not commit; see firmware.log", .{}),
    };
    const seen = try m.console(gpa);
    if (u.secure and arm and !mem.eql(u8, &try host.check.digest(io, vars), &enrolled_digest))
        return c.fail("Arm firmware changed immutable enrollment", .{});
    var why: host.check.Why = .{};
    host.evidence.updaterConsole(u.table, seen, 2, &why) catch
        return c.fail("firmware: {s}", .{why.text});
    if (!verifiedSlotB(seen) or mem.count(u8, seen, "policy administration removed") < 2)
        return c.fail("firmware boot did not verify slot b with IPE", .{});
    const selected = mem.count(u8, seen, "native UKI selected slot");
    const enforced = mem.count(u8, seen, "Secure Boot enforced outside setup mode");
    if (u.secure and (selected < 2 or enforced < 2)) return c.fail(
        "Secure Boot did not preserve native slot identity and update; see firmware.log",
        .{},
    );
    const installed = try c.path("installed-uki.efi");
    Io.Dir.cwd().deleteFile(io, installed) catch {};
    _ = try c.must(&.{ "mcopy", "-i", esp, "::/werewolf/b/uki.efi", installed }, "esp", .{});
    if (!try signed(io, installed, document, "uki.efi"))
        return c.fail("firmware UKI differs from signed bundle", .{});
    const listing = try c.must(&.{ "mdir", "-b", "-i", esp, "::/loader/entries" }, "esp", .{});
    var names: std.ArrayList([]const u8) = .empty;
    var lines = mem.tokenizeScalar(u8, listing.stdout, '\n');
    while (lines.next()) |line| if (mem.find(u8, line, "werewolf-b") != null)
        try names.append(gpa, std.fs.path.basename(mem.trimEnd(u8, line, "\r")));
    if (names.items.len != 1) return c.fail("committed entry does not select the UKI", .{});
    const b_entry = try gpa.print("::/loader/entries/{s}", .{names.items[0]});
    const committed = try c.must(&.{ "mtype", "-i", esp, b_entry }, "esp", .{});
    if (mem.find(u8, committed.stdout, "uki /werewolf/b/uki.efi") == null)
        return c.fail("committed entry does not select the UKI", .{});
    replay(u, image);
    const parked_root = try c.path("firmware-root.erofs");
    try dump(u, image, "/slot/b/root.erofs", parked_root);
    if (!try signed(io, parked_root, document, "root.erofs"))
        return c.fail("firmware root differs from signed bundle", .{});
    const mode = if (u.secure) "Secure Boot" else "firmware";
    c.say("pass   signed-uki: continuous {s} boot, HTTPS update, verified slot b " ++
        "and commit with IPE", .{mode});
}

/// verifiedSlotB is whether stage0 said slot b's root was verified.
fn verifiedSlotB(console: []const u8) bool {
    var from: usize = 0;
    while (mem.findPos(u8, console, from, "slot b:")) |at| : (from = at + 1) {
        const end = mem.findAnyPos(u8, console, at, "\r\n") orelse console.len;
        if (mem.find(u8, console[at..end], "verified") != null) return true;
    }
    return false;
}

/// firmwareRefusals boots disposable clones that enrolled firmware or
/// stage0 must refuse before handover. Writable variables let AAVMF log
/// rejections; the continuous boot uses immutable ones and checks them.
fn firmwareRefusals(
    u: *Updater,
    args: []const []const u8,
    esp: []const u8,
    image: []const u8,
    enrolled: []const u8,
    efi_name: []const u8,
) !void {
    const c = u.c;
    const gpa = c.gpa;
    const io = c.io;
    const wrong_key = try c.path("wrong-boot.key");
    const wrong_cert = try c.path("wrong-boot.crt");
    const req = [_][]const u8{ "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes" };
    const subject = [_][]const u8{ "-days", "2", "-subj", "/CN=wrong-boot" };
    const keys = [_][]const u8{ "-keyout", wrong_key, "-out", wrong_cert };
    _ = try c.must(&(req ++ subject ++ keys), "wrong-boot", .{});
    try Io.Dir.cwd().setFilePermissions(io, wrong_key, .fromMode(0o600), .{});
    const vars = try c.path("refusal-vars.fd");
    const Target = struct { name: []const u8, original: []const u8, remote: []const u8 };
    const targets = [_]Target{
        .{
            .name = "loader",
            .original = try c.path("systemd-boot.signed.efi"),
            .remote = try gpa.print("::/EFI/BOOT/{s}", .{efi_name}),
        },
        .{
            .name = "uki",
            .original = try c.path("slot-a/uki.efi"),
            .remote = "::/werewolf/a/uki.efi",
        },
    };
    for (targets) |t| {
        const unsigned = try c.path(try gpa.print("unsigned-{s}.efi", .{t.name}));
        Io.Dir.cwd().deleteFile(io, unsigned) catch {};
        const strip = [_][]const u8{ "osslsigncode", "remove-signature", "-in", t.original };
        _ = try c.must(&(strip ++ .{ "-out", unsigned }), "refusals", .{});
        const tampered = try c.path(try gpa.print("tampered-{s}.efi", .{t.name}));
        const data = try Io.Dir.cwd().readFileAlloc(io, t.original, gpa, .unlimited);
        data[data.len / 2] ^= 1;
        try write(io, tampered, data);
        const wrong = try c.path(try gpa.print("wrong-{s}.efi", .{t.name}));
        Io.Dir.cwd().deleteFile(io, wrong) catch {};
        const sign = [_][]const u8{ "osslsigncode", "sign", "-certs", wrong_cert };
        const by = [_][]const u8{ "-key", wrong_key, "-in", unsigned, "-out", wrong };
        _ = try c.must(&(sign ++ by), "refusals", .{});
        const kinds = [_][2][]const u8{
            .{ "unsigned", unsigned }, .{ "tampered", tampered }, .{ "wrong-key", wrong },
        };
        for (kinds) |kind| {
            const cloned = try c.path(try gpa.print("{s}-{s}.img", .{ t.name, kind[0] }));
            try copy(io, esp, cloned);
            try copy(io, try join(gpa, &.{ enrolled, "vars.fd" }), vars);
            _ = try c.must(&.{ "mcopy", "-o", "-i", cloned, kind[1], t.remote }, "refusals", .{});
            const log = try c.path(try gpa.print("refuse-{s}-{s}.log", .{ t.name, kind[0] }));
            const argv = try refusalArgv(gpa, args, enrolled, vars, cloned, image);
            try refusedBoot(u, argv, log, "Access Denied");
            Io.Dir.cwd().deleteFile(io, cloned) catch {};
            c.say("pass   secureboot: {s} {s} refused by firmware", .{ t.name, kind[0] });
        }
    }
    for ([_][]const u8{ "wrong-path", "setup-mode" }) |kind| {
        const cloned = try c.path("native-refusal.img");
        const refusal_entry = try c.path("refusal.conf");
        const setup = mem.eql(u8, kind, "setup-mode");
        try copy(io, esp, cloned);
        try copy(io, try join(gpa, &.{ enrolled, if (setup) "setup.fd" else "vars.fd" }), vars);
        var uki: []const u8 = "/werewolf/a/uki.efi";
        if (!setup) {
            _ = try c.must(&.{ "mmd", "-i", cloned, "::/werewolf/other" }, "refusals", .{});
            uki = "/werewolf/other/uki.efi";
            const from = try c.path("slot-a/uki.efi");
            const to = try gpa.print("::{s}", .{uki});
            _ = try c.must(&.{ "mcopy", "-i", cloned, from, to }, "refusals", .{});
        }
        try write(io, refusal_entry, try gpa.print("title refusal\nuki {s}\n", .{uki}));
        const a_entry = "::/loader/entries/werewolf-a+1.conf";
        _ = try c.must(&.{ "mcopy", "-o", "-i", cloned, refusal_entry, a_entry }, "refusals", .{});
        const expected = if (setup)
            "Secure Boot required outside setup mode"
        else
            "no canonical firmware slot path";
        const log = try c.path(try gpa.print("refuse-{s}.log", .{kind}));
        const argv = try refusalArgv(gpa, args, enrolled, vars, cloned, image);
        try refusedBoot(u, argv, log, expected);
        Io.Dir.cwd().deleteFile(io, cloned) catch {};
        c.say("pass   secureboot: {s} refused before root handover", .{kind});
    }
}

fn refusalArgv(
    gpa: Allocator,
    args: []const []const u8,
    enrolled: []const u8,
    vars: []const u8,
    esp: []const u8,
    image: []const u8,
) ![]const []const u8 {
    const code = try gpa.print("if=pflash,format=raw,readonly=on,file={s}/code.fd", .{enrolled});
    return mem.concat(gpa, []const u8, &.{ args, &.{
        "-drive", code,
        "-drive", try gpa.print("if=pflash,format=raw,file={s}", .{vars}),
        "-drive", try gpa.print("file={s},format=raw,if=virtio", .{esp}),
        "-drive", try gpa.print("file={s},format=raw,if=virtio", .{image}),
    } });
}

/// refusedBoot requires the console to say expected, in any case, before
/// anything hands over or commits.
fn refusedBoot(u: *Updater, argv: []const []const u8, log: []const u8, expected: []const u8) !void {
    const c = u.c;
    var m: Machine = undefined;
    try m.start(c.io, c.gpa, argv, .{ .log = log, .environ_map = &c.env });
    const result = m.until(host.qemu.after(c.io, 120), Refusal{ .expected = expected });
    m.stop(.fromSeconds(30));
    result catch |err| return switch (err) {
        error.HandedOver => c.fail("rejected boot handed over: {s}", .{log}),
        else => c.fail("missing boot refusal: {s}", .{log}),
    };
}

const Refusal = struct {
    expected: []const u8,

    pub fn done(r: Refusal, console: []const u8) !bool {
        if (mem.find(u8, console, "up in ") != null) return error.HandedOver;
        if (mem.find(u8, console, "\"event\":\"commit\"") != null) return error.HandedOver;
        return std.ascii.findIgnoreCase(console, r.expected) != null;
    }
};

/// relay is QEMU's guestfwd command: it carries the guest's connection
/// on standard input and output to the channel's loopback server, until
/// either side ends or a minute passes with nothing said.
fn relay(io: Io, port_text: []const u8) noreturn {
    const port = std.fmt.parseInt(u16, port_text, 10) catch std.process.exit(2);
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const peer = address.connect(io, .{ .mode = .stream }) catch std.process.exit(1);
    var heard: std.atomic.Value(i64) = .init(uptime(io));
    var back = io.concurrent(toGuest, .{ io, peer, &heard }) catch std.process.exit(1);
    _ = io.concurrent(idle, .{ io, &heard }) catch {};
    var buf: [64 << 10]u8 = undefined;
    while (true) {
        const n = Io.File.stdin().readStreaming(io, &.{&buf}) catch break;
        if (n == 0) break;
        heard.store(uptime(io), .monotonic);
        var w = peer.writer(io, &.{});
        w.interface.writeAll(buf[0..n]) catch break;
    }
    _ = back.cancel(io);
    std.process.exit(0);
}

fn toGuest(io: Io, peer: Io.net.Stream, heard: *std.atomic.Value(i64)) void {
    var buf: [64 << 10]u8 = undefined;
    while (true) {
        var data = [_][]u8{&buf};
        const n = (peer.readWithControl(io, &data, &.{}) catch break).data_len;
        if (n == 0) break;
        heard.store(uptime(io), .monotonic);
        Io.File.stdout().writeStreamingAll(io, buf[0..n]) catch break;
    }
    std.process.exit(0);
}

fn idle(io: Io, heard: *std.atomic.Value(i64)) void {
    while (true) {
        io.sleep(.fromSeconds(5), .awake) catch return;
        if (uptime(io) - heard.load(.monotonic) >= 60) std.process.exit(0);
    }
}

fn uptime(io: Io) i64 {
    return @intCast(@divFloor(Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_s));
}

test "serial writes UTC release serials" {
    try std.testing.expectEqualStrings("19700101T000000Z", &serial(0));
    try std.testing.expectEqualStrings("20261024T235959Z", &serial(1792886399));
}

test "each case's document is wrong in its one way" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const manifest =
        \\{"channel": "https://10.0.2.100/image", "arch": "aarch64",
        \\ "serial": "20261024T000100Z", "ipe": true, "build": "b1",
        \\ "files": {"root.erofs": {"sha256": "aa"}}}
    ;
    const now: i64 = 1792886399;
    const Want = struct { label: []const u8, key: []const u8, value: ?[]const u8 };
    for ([_]Want{
        .{ .label = "wrong-channel", .key = "channel", .value = "\"https://10.0.2.100/other\"" },
        .{ .label = "wrong-arch", .key = "arch", .value = "\"x86_64\"" },
        .{ .label = "older", .key = "serial", .value = "\"20261023T235959Z\"" },
        .{ .label = "serial-reused", .key = "serial", .value = "\"20261024T000000Z\"" },
        .{ .label = "missing-ipe", .key = "ipe", .value = null },
        .{ .label = "not-ipe", .key = "ipe", .value = "false" },
        .{ .label = "valid", .key = "ipe", .value = "true" },
    }) |want| {
        var doc = try json.parseFromSliceLeaky(json.Value, gpa, manifest, .{});
        try alter(gpa, &doc, want.label, "aarch64", now, "20261024T000000Z");
        const got = doc.object.get(want.key);
        if (want.value) |v| {
            try std.testing.expectEqualStrings(v, try json.Stringify.valueAlloc(gpa, got.?, .{}));
        } else try std.testing.expectEqual(null, got);
        try std.testing.expectEqualStrings("b1", try text(doc, "build"));
    }
    var doc = try json.parseFromSliceLeaky(json.Value, gpa, manifest, .{});
    try std.testing.expectEqualStrings("aa", try fileDigest(doc, "root.erofs"));
    try alter(gpa, &doc, "wrong-arch", "x86_64", now, "");
    try std.testing.expectEqualStrings("aarch64", try text(doc, "arch"));
}

test "selection takes named cases, or only the valid one through firmware" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    try std.testing.expectEqual(0, (try selection(gpa, "", false)).len);
    const two = try selection(gpa, "older,,valid", false);
    try std.testing.expectEqual(2, two.len);
    try std.testing.expectEqualStrings("valid", two[1]);
    const firmware = try selection(gpa, "older", true);
    try std.testing.expectEqual(1, firmware.len);
    try std.testing.expectEqualStrings("valid", firmware[0]);
}

test "a firmware machine may reboot and has SMM on x86" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const qemu = [_][]const u8{ "qemu-system-x86_64", "-M", "q35", "-no-reboot", "-m", "2048" };
    const x86 = try firmwareArgv(gpa, &qemu, "x86_64");
    try std.testing.expectEqual(5, x86.len);
    try std.testing.expectEqualStrings("q35,smm=on", x86[2]);
    try std.testing.expectEqualStrings("virt", (try firmwareArgv(gpa, &qemu, "aarch64"))[2]);
}

test "whole lines, slot b's verification, refusals and entries" {
    const reboot = "\"event\":\"reboot\"";
    try std.testing.expect(!wholeLine("x \"event\":\"reboot\",\"at\":1", reboot));
    try std.testing.expect(wholeLine("x \"event\":\"reboot\"}\r\n", reboot));
    try std.testing.expect(wholeLine("x \"event\":\"reboot\"}\n", reboot));
    try std.testing.expect(!wholeLine("x \"event\":\"reboot\"}\r", reboot));
    try std.testing.expect(verifiedSlotB("stage0: slot b: root.erofs, read-only, verified\r\n"));
    try std.testing.expect(!verifiedSlotB("stage0: slot b: root.erofs\nverified\n"));
    const r: Refusal = .{ .expected = "Access Denied" };
    try std.testing.expect(try r.done("BdsDxe: failed to load: ACCESS DENIED"));
    try std.testing.expect(!try r.done("loading"));
    try std.testing.expectError(error.HandedOver, r.done("werewolf: up in 1s"));
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const plain = try entry(gpa, false, "console=ttyAMA0 werewolf.slot=a");
    try std.testing.expect(mem.endsWith(u8, plain, "options console=ttyAMA0 werewolf.slot=a\n"));
    const native = try entry(gpa, true, "");
    try std.testing.expect(mem.find(u8, native, "uki /werewolf/a/uki.efi\n") != null);
    try std.testing.expect(mem.startsWith(
        u8,
        try rootOwned(gpa),
        "set_inode_field /slot uid 0\nset_inode_field /slot gid 0\n",
    ));
}
