//! check-people-persist QEMU... boots real init again and again on one
//! /data volume and never lets a retired identity be reused: enrollment,
//! retirement, conflicting people and NoCloud requests, reactivation, and
//! refusal of a corrupt or missing reservation table before services
//! start. make check-people-persist supplies CHECK_ENV, ARCH and the QEMU
//! arguments, and OUT, people-persist's native test image. Successful boots
//! are its native boots (native-tests boot), whose driver
//! (test/scenarios/people-persist) knows each by the hostname its config
//! gives; damaged-ledger boots must panic before handover. NoCloud seeds
//! take hdiutil on macOS and xorriso elsewhere.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const join = std.fs.path.join;

// These distinct names collide under the current people mapping; the
// scenario's driver checks for the same names and key.
const person = "u2guv05clv";
const collision = "udm5vojgxd";
const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGf9JfLCEyq5b4u2jFqCi6Q7BSQx5vLzPVRzCPkTaq2f";
const scenario = "test/scenarios/people-persist";

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "people-persist") catch |err| {
        std.log.err("check-people-persist: {t}", .{err});
        std.process.exit(1);
    };
    c.finish(run(&c));
}

const Run = struct {
    c: *host.Check,
    qemu: []const []const u8,
    disk: []const u8,
    kernel: []const u8,
    initramfs: []const u8,
    cmdline: []const u8,
};

fn need(c: *host.Check, name: []const u8) ![]const u8 {
    return c.env.get(name) orelse c.fail("{s} is not set", .{name});
}

fn run(c: *host.Check) !void {
    const gpa = c.gpa;
    const qemu = c.args[1..];
    const debugfs = c.env.get("DEBUGFS") orelse host.consumer.which(c.io, gpa, &c.env, "debugfs");
    if (qemu.len == 0 or debugfs == null or debugfs.?.len == 0)
        return c.fail("requires QEMU arguments and DEBUGFS (e2fsprogs)", .{});
    try c.setWork(try join(gpa, &.{ try need(c, "CHECK"), "people-persist" }));
    const r: Run = .{
        .c = c,
        .qemu = qemu,
        .disk = try c.path("data.img"),
        .kernel = try need(c, "KERNEL"),
        .initramfs = try join(gpa, &.{ try need(c, "OUT"), "initramfs.zst" }),
        .cmdline = try need(c, "CMDLINE"),
    };
    // A new sparse disk for enrollment; every later successful boot reuses it.
    {
        const disk = try Io.Dir.cwd().createFile(c.io, r.disk, .{});
        defer disk.close(c.io);
        try disk.setLength(c.io, 256 << 20);
    }
    const original_seed = try seed(c, 1000);
    const changed_seed = try seed(c, 1001);
    try boot(r, "enroll", person, original_seed);
    try boot(r, "retire", null, null);
    try boot(r, "conflict", collision, changed_seed);
    try boot(r, "restore", person, original_seed);
    const damaged_config = try pack(c, try config(c, "damaged", person));
    try damaged(r, "corrupt", damaged_config, original_seed, debugfs.?, false);
    try damaged(r, "missing", damaged_config, original_seed, debugfs.?, true);
}

/// config writes the config directory of the boot people-NAME, naming who,
/// or no one, as the machine's one admin. It has no data.key: /data is
/// plain ext4, which the damaged boots edit offline.
fn config(c: *host.Check, name: []const u8, who: ?[]const u8) ![]const u8 {
    const dir = try c.path(name);
    try Io.Dir.cwd().deleteTree(c.io, dir);
    try Io.Dir.cwd().createDirPath(c.io, dir);
    try Io.Dir.cwd().writeFile(c.io, .{
        .sub_path = try join(c.gpa, &.{ dir, "hostname" }),
        .data = try c.gpa.print("people-{s}\n", .{name}),
    });
    var users: []const u8 = "";
    if (who) |p| users = try c.gpa.print("{s} admin {s} people-persist\n", .{ p, key });
    try Io.Dir.cwd().writeFile(c.io, .{
        .sub_path = try join(c.gpa, &.{ dir, "users" }),
        .data = users,
    });
    return dir;
}

/// pack is dir as a config disk, as howl packs one for prod.
fn pack(c: *host.Check, dir: []const u8) ![]const u8 {
    const tar = try c.gpa.print("{s}.tar", .{dir});
    _ = try c.must(
        &.{ try need(c, "HOWL"), "pack", "--build", "--with", "prod", "--config", dir, "-o", tar },
        "pack",
        .{},
    );
    return tar;
}

/// seed writes a NoCloud seed asking for lima at uid.
fn seed(c: *host.Check, uid: u32) ![]const u8 {
    const gpa = c.gpa;
    const io = c.io;
    const dir = try c.path(try gpa.print("seed-{d}", .{uid}));
    try Io.Dir.cwd().createDirPath(io, dir);
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = try join(gpa, &.{ dir, "meta-data" }),
        .data = "instance-id: people-persist\n",
    });
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = try join(gpa, &.{ dir, "user-data" }),
        .data = try userData(gpa, uid),
    });
    const iso = try c.path(try gpa.print("seed-{d}.iso", .{uid}));
    Io.Dir.cwd().deleteFile(io, iso) catch {};
    const hdiutil = [_][]const u8{ "hdiutil", "makehybrid", "-iso", "-joliet" };
    const xorriso = [_][]const u8{ "xorriso", "-as", "mkisofs", "-quiet", "-V", "cidata" };
    const argv: []const []const u8 = if (builtin.os.tag == .macos)
        &(hdiutil ++ .{ "-default-volume-name", "cidata", "-o", iso, dir })
    else
        &(xorriso ++ .{ "-J", "-r", "-o", iso, dir });
    _ = try c.must(argv, "seed", .{});
    return iso;
}

fn userData(gpa: Allocator, uid: u32) ![]const u8 {
    return gpa.print("#cloud-config\nusers:\n  - name: lima\n    uid: {d}\n" ++
        "    ssh_authorized_keys:\n      - {s} nocloud-persist\n", .{ uid, key });
}

/// machine is the QEMU command booting init on data with, when given, the
/// config disk and the NoCloud seed.
fn machine(
    r: Run,
    config_disk: ?[]const u8,
    seed_disk: ?[]const u8,
    data: []const u8,
) ![]const []const u8 {
    const gpa = r.c.gpa;
    const read_only = "file={s},format=raw,if=virtio,readonly=on";
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, r.qemu);
    try argv.appendSlice(gpa, &.{
        "-kernel", r.kernel,
        "-initrd", r.initramfs,
        "-append", try gpa.print("{s} werewolf.data=vda", .{r.cmdline}),
        "-drive",  try gpa.print("file={s},format=raw,if=virtio", .{data}),
    });
    for ([_]?[]const u8{ config_disk, seed_disk }) |disk| if (disk) |d|
        try argv.appendSlice(gpa, &.{ "-drive", try gpa.print(read_only, .{d}) });
    return argv.items;
}

/// boot is the native boot people-NAME, its admin who or no one: the
/// scenario's driver judges it inside, and its console must say no more
/// than that boot should. Only enrollment may format /data; the
/// conflicting boot must refuse both its colliding requests.
fn boot(r: Run, name: []const u8, who: ?[]const u8, seed_disk: ?[]const u8) !void {
    const c = r.c;
    const gpa = c.gpa;
    var env = try c.env.clone(gpa);
    try env.put("NATIVE_CONFIG", try config(c, name, who));
    const label = try gpa.print("people-{s}", .{name});
    const argv = try mem.concat(gpa, []const u8, &.{
        &.{ "build/host/native-tests", "boot", scenario, try need(c, "ARCH"), "seed", label },
        try machine(r, null, seed_disk, r.disk),
    });
    var child = try std.process.spawn(c.io, .{
        .argv = argv,
        .environ_map = &env,
        .stdin = .ignore,
    });
    const term = try child.wait(c.io);
    const log = try join(
        gpa,
        &.{ try need(c, "CHECK"), try gpa.print("{s}-native", .{label}), "seed.log" },
    );
    if (!term.success()) return c.fail("{s}: native-tests {f}; see {s}", .{ name, term, log });
    const console = try host.qemu.clean(
        gpa,
        try Io.Dir.cwd().readFileAlloc(c.io, log, gpa, .unlimited),
    );
    if (!mem.eql(u8, name, "enroll") and mem.find(u8, console, "werewolf: formatting ") != null)
        return c.fail("{s}: reformatted persistent data; see {s}", .{ name, log });
    if (!mem.eql(u8, name, "conflict")) return;
    for ([_][]const u8{
        "'" ++ collision ++ "': name or UID is already reserved",
        "NoCloud name or UID is already reserved",
    }) |refusal| if (mem.find(u8, console, refusal) == null)
        return c.fail("{s}: no refusal \"{s}\"; see {s}", .{ name, refusal, log });
}

/// damaged boots a copy of /data whose reservation table is corrupt or,
/// with remove_only, gone. Init must refuse to publish accounts and
/// panic before handover. Each starts from the same good state, edited
/// offline; debugfs says some errors with exit 0, so the fault is read back.
fn damaged(
    r: Run,
    name: []const u8,
    config_disk: []const u8,
    seed_disk: []const u8,
    debugfs: []const u8,
    remove_only: bool,
) !void {
    const c = r.c;
    const gpa = c.gpa;
    const disk = try c.path(try gpa.print("{s}.img", .{name}));
    try Io.Dir.cwd().copyFile(r.disk, .cwd(), disk, c.io, .{});
    // A shutdown may leave /data read-only with a journal to replay; replay
    // it first, or the boot could restore the intact table.
    const e2fsck = try join(gpa, &.{ std.fs.path.dirname(debugfs) orelse ".", "e2fsck" });
    const replay = try c.run(&.{ e2fsck, "-p", disk }, name, .{});
    if (replay.code() == null or replay.code().? > 1) return c.fail(
        "{s}: journal replay failed: {s}{s}",
        .{ name, replay.stdout, replay.stderr },
    );
    _ = try c.must(&.{ debugfs, "-w", "-R", "rm /.werewolf/identities", disk }, name, .{});
    if (!remove_only) {
        const bad = try c.path("invalid-identities");
        const table = "werewolf-identities 999\n";
        try Io.Dir.cwd().writeFile(c.io, .{ .sub_path = bad, .data = table });
        const put = try gpa.print("write {s} /.werewolf/identities", .{bad});
        _ = try c.must(&.{ debugfs, "-w", "-R", put, disk }, name, .{});
        const mode = "set_inode_field /.werewolf/identities mode 0100600";
        _ = try c.must(&.{ debugfs, "-w", "-R", mode, disk }, name, .{});
        const cat = "cat /.werewolf/identities";
        const read = try c.must(&.{ debugfs, "-w", "-R", cat, disk }, name, .{});
        if (!mem.eql(u8, read.stdout, table)) return c.fail(
            "{s}: could not corrupt the ledger: {s}{s}",
            .{ name, read.stdout, read.stderr },
        );
    } else {
        const stat = "stat /.werewolf/identities";
        const st = try c.must(&.{ debugfs, "-w", "-R", stat, disk }, name, .{});
        if (mem.find(u8, st.stderr, "File not found") == null)
            return c.fail("{s}: could not remove the ledger", .{name});
    }
    const log = try c.path(try gpa.print("{s}.log", .{name}));
    const seconds = std.fmt.parseInt(i64, c.env.get("BOOT_TIMEOUT") orelse "300", 10) catch 300;
    const argv = try machine(r, config_disk, seed_disk, disk);
    var m: host.qemu.Machine = undefined;
    try m.start(c.io, gpa, argv, .{ .log = log, .environ_map = &c.env });
    const Ends = struct {
        pub fn done(_: @This(), _: []const u8) !bool {
            return false;
        }
    };
    const ended = m.until(host.qemu.after(c.io, seconds), Ends{});
    m.stop(.fromSeconds(10));
    ended catch |err| switch (err) {
        error.MachineExited => {},
        else => return c.fail("{s}: no outcome in {d}s: {t}; see {s}", .{
            name, seconds, err, log,
        }),
    };
    const raw = try Io.Dir.cwd().readFileAlloc(c.io, log, gpa, .unlimited);
    if (!refused(try host.qemu.clean(gpa, raw), raw, remove_only))
        return c.fail("{s}: expected account publication refusal; see {s}", .{ name, log });
    c.say("PASS   people-{s} refuses account publication", .{name});
}

/// refused is whether a damaged-ledger boot said it would not publish
/// accounts for its reason, panicked, and never handed over.
fn refused(clean: []const u8, raw: []const u8, remove_only: bool) bool {
    const reason = if (remove_only)
        "people: unregistered data failed; not handing over"
    else
        "people: read identities failed; not handing over";
    // Init writes refusals to /dev/kmsg so the panic flushes their reason.
    // clean removes those kernel records, but still rejoins tty fragments.
    return (mem.find(u8, clean, reason) != null or mem.find(u8, raw, reason) != null) and
        mem.find(u8, raw, "Kernel panic") != null and
        mem.find(u8, clean, "handing over to runit") == null and
        mem.find(u8, raw, "handing over to runit") == null;
}

test "a damaged ledger must be refused for its reason, with a panic, before handover" {
    const panic = "[    0.4] Kernel panic - not syncing\n";
    const corrupt = "werewolf: people: read identities failed; not handing over\n";
    const missing = "werewolf: people: unregistered data failed; not handing over\n";
    try std.testing.expect(refused(corrupt, corrupt ++ panic, false));
    try std.testing.expect(refused(missing, missing ++ panic, true));
    try std.testing.expect(!refused(corrupt, corrupt ++ panic, true));
    try std.testing.expect(!refused(corrupt, corrupt, false));
    const over = corrupt ++ "werewolf: up in 1s, handing over to runit\n";
    try std.testing.expect(!refused(over, over ++ panic, false));
}

test "a panic-flushed kernel refusal survives console cleaning" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const panic = "[    0.422033] Kernel panic - not syncing: Attempted to kill init!\r\n";
    const corrupt = "[    0.422026] werewolf: people: read identities failed; not handing over\r\n";
    const missing = "[    0.422026] werewolf: people: unregistered data failed; not handing " ++
        "over\r\n";
    const clean = try host.qemu.clean(arena.allocator(), corrupt ++ panic);
    try std.testing.expect(refused(clean, corrupt ++ panic, false));
    try std.testing.expect(refused(clean, missing ++ panic, true));
    try std.testing.expect(!refused(clean, corrupt ++ panic, true));
    try std.testing.expect(!refused(clean, corrupt, false));
    const over = "[    0.5] werewolf: up in 1s, handing over to runit\r\n";
    try std.testing.expect(!refused(clean, corrupt ++ over ++ panic, false));
}

test "the NoCloud seed asks for lima at its uid with the test key" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "#cloud-config\nusers:\n  - name: lima\n    uid: 1001\n    ssh_authorized_keys:\n" ++
            "      - " ++ key ++ " nocloud-persist\n",
        try userData(arena.allocator(), 1001),
    );
}
