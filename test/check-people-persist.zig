//! check-people-persist QEMU... boots real init again and again on one
//! /data volume and never lets a retired identity be reused: enrollment,
//! retirement, conflicting people and NoCloud requests, reactivation, and
//! refusal of a corrupt or missing reservation table before services
//! start. make check-people-persist supplies CHECK_ENV and the QEMU
//! arguments. Successful boots go through test/boot; damaged-ledger boots
//! must panic before handover. NoCloud seeds take hdiutil on macOS and
//! xorriso elsewhere.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const join = std.fs.path.join;

// These distinct names collide under the current people mapping.
const person = "u2guv05clv";
const collision = "udm5vojgxd";
const person_uid = 982829894;
const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGf9JfLCEyq5b4u2jFqCi6Q7BSQx5vLzPVRzCPkTaq2f";

const Account = struct { name: []const u8, uid: u32, source: []const u8 };
const accounts_kept = [_]Account{
    .{ .name = person, .uid = person_uid, .source = "p" },
    .{ .name = "lima", .uid = 1000, .source = "n" },
};

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
    const original = try config(c, "original", person);
    const empty = try config(c, "empty", null);
    const colliding = try config(c, "collision", collision);
    const original_seed = try seed(c, 1000);
    const changed_seed = try seed(c, 1001);

    var enroll: std.ArrayList([]const u8) = .empty;
    try enroll.appendSlice(gpa, try accounts(gpa, true));
    for (accounts_kept) |a| {
        const private = try gpa.print("/data/home/{s}/private", .{a.name});
        try enroll.append(gpa, try gpa.print(
            "ok {s}-create printf '%s\\n' {s}-secret >{s} && chmod 600 {s} && " ++
                "chown {d}:{d} {s} && stat -c '%i:%u:%g:%a' {s} >/data/{s}.stat",
            .{ a.name, a.name, private, private, a.uid, a.uid, private, private, a.name },
        ));
    }
    try enroll.append(gpa, "ok save-ledger cp /data/.werewolf/identities /data/identities.saved");
    try enroll.appendSlice(gpa, try files(gpa, true));
    try boot(r, "enroll", enroll.items, original, original_seed);

    const retired = try mem.concat(gpa, []const u8, &.{
        try accounts(gpa, false), try files(gpa, false),
    });
    try boot(r, "retire", retired, empty, null);
    const refusals = [_][]const u8{
        "seen hash-refused '" ++ collision ++ "': name or UID is already reserved",
        "seen nocloud-refused NoCloud name or UID is already reserved",
        "ok collision-absent ! grep -q '^" ++ collision ++ ":' /etc/passwd && " ++
            "[ ! -e /data/home/" ++ collision ++ " ] && " ++
            "[ ! -e /run/werewolf/keys/" ++ collision ++ " ]",
    };
    const conflict = try mem.concat(gpa, []const u8, &.{ retired, &refusals });
    try boot(r, "conflict", conflict, colliding, changed_seed);
    const restored = try mem.concat(gpa, []const u8, &.{
        try accounts(gpa, true), try files(gpa, true),
    });
    try boot(r, "restore", restored, original, original_seed);
    try damaged(r, "corrupt", original, original_seed, debugfs.?, false);
    try damaged(r, "missing", original, original_seed, debugfs.?, true);
}

/// config writes name.tar, the config disk naming who, or no one, as the
/// machine's one admin.
fn config(c: *host.Check, name: []const u8, who: ?[]const u8) ![]const u8 {
    var out: Io.Writer.Allocating = .init(c.gpa);
    var tar: std.tar.Writer = .{ .underlying_writer = &out.writer };
    try tar.writeFileBytes("hostname", "people-persist\n", .{ .mode = 0o600 });
    var users: []const u8 = "";
    if (who) |p| users = try c.gpa.print("{s} admin {s} people-persist\n", .{ p, key });
    try tar.writeFileBytes("users", users, .{ .mode = 0o600 });
    try tar.finishPedantically();
    const path = try c.path(try c.gpa.print("{s}.tar", .{name}));
    try Io.Dir.cwd().writeFile(c.io, .{ .sub_path = path, .data = out.written() });
    return path;
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

/// machine is the QEMU command booting init on data with the config disk
/// and, when given, the NoCloud seed.
fn machine(
    r: Run,
    config_disk: []const u8,
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
        "-drive",  try gpa.print(read_only, .{config_disk}),
    });
    if (seed_disk) |s| try argv.appendSlice(gpa, &.{ "-drive", try gpa.print(read_only, .{s}) });
    return argv.items;
}

/// boot runs checks on a successful boot through test/boot, whose lines
/// are the check's own. Only enrollment may format /data.
fn boot(
    r: Run,
    name: []const u8,
    checks: []const []const u8,
    config_disk: []const u8,
    seed_disk: ?[]const u8,
) !void {
    const c = r.c;
    const gpa = c.gpa;
    const checks_file = try c.path(try gpa.print("{s}.checks", .{name}));
    var text: std.ArrayList(u8) = .empty;
    for (checks) |line| try text.print(gpa, "{s}\n", .{line});
    try Io.Dir.cwd().writeFile(c.io, .{ .sub_path = checks_file, .data = text.items });
    const log = try c.path(try gpa.print("{s}.log", .{name}));
    const label = try gpa.print("people-{s}", .{name});
    const argv = try mem.concat(gpa, []const u8, &.{
        &.{ "test/boot", label, checks_file, log },
        try machine(r, config_disk, seed_disk, r.disk),
    });
    var child = try std.process.spawn(c.io, .{
        .argv = argv,
        .environ_map = &c.env,
        .stdin = .ignore,
    });
    const term = try child.wait(c.io);
    if (!term.success()) return c.fail("{s}: test/boot {f}; see {s}", .{ name, term, log });
    if (mem.eql(u8, name, "enroll")) return;
    const console = try Io.Dir.cwd().readFileAlloc(c.io, log, gpa, .unlimited);
    if (mem.find(u8, console, "werewolf: formatting ") != null)
        return c.fail("{s}: reformatted persistent data; see {s}", .{ name, log });
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
    return mem.find(u8, clean, reason) != null and mem.find(u8, raw, "Kernel panic") != null and
        mem.find(u8, clean, "handing over to runit") == null;
}

/// accounts are the checks of both kept accounts, active or retired, and
/// of the private reservation table they share.
fn accounts(gpa: Allocator, active: bool) ![]const []const u8 {
    const shell = if (active) "/bin/mksh" else "/sbin/nologin";
    const shadow = if (active) "\\*" else "!";
    var out: std.ArrayList([]const u8) = .empty;
    for (accounts_kept) |a| {
        const home = try gpa.print("/data/home/{s}", .{a.name});
        try out.append(gpa, try gpa.print(
            "ok {s}-account grep -qx '{s}:x:{d}:{d}::{s}:{s}' /etc/passwd && " ++
                "grep -q '^{s}:{s}:' /etc/shadow && grep -qx '{s}:x:{d}:' /etc/group",
            .{ a.name, a.name, a.uid, a.uid, home, shell, a.name, shadow, a.name, a.uid },
        ));
        try out.append(gpa, try gpa.print(
            "ok {s}-reservation grep -qx '{s} {s} {d} {d}' /data/.werewolf/identities",
            .{ a.name, a.source, a.name, a.uid, a.uid },
        ));
        try out.append(gpa, try gpa.print(
            "ok {s}-home [ \"$(stat -c '%u:%g:%a' {s})\" = {d}:{d}:700 ]",
            .{ a.name, home, a.uid, a.uid },
        ));
        if (active) {
            try out.append(gpa, try gpa.print(
                "ok {s}-key [ \"$(stat -c '%u:%g:%a' /run/werewolf/keys/{s})\" = 0:{d}:640 ] " ++
                    "&& grep -q '{s}' /run/werewolf/keys/{s}",
                .{ a.name, a.name, a.uid, key, a.name },
            ));
        } else try out.append(gpa, try gpa.print(
            "ok {s}-revoked [ ! -e /run/werewolf/keys/{s} ]",
            .{ a.name, a.name },
        ));
    }
    try out.appendSlice(gpa, &.{
        "ok ledger-private [ \"$(stat -c '%u:%g:%a' /data/.werewolf)\" = 0:0:700 ] && " ++
            "[ \"$(stat -c '%u:%g:%a' /data/.werewolf/identities)\" = 0:0:600 ] && " ++
            "[ \"$(wc -l </data/.werewolf/identities)\" -eq 3 ]",
        if (active)
            "ok admin-key grep -q people-persist /run/werewolf/keys/root"
        else
            "ok admin-key [ ! -s /run/werewolf/keys/root ]",
        if (active)
            "ok active-list grep -qx " ++ person ++ " /run/werewolf/people"
        else
            "ok active-list [ ! -s /run/werewolf/people ]",
    });
    return out.items;
}

/// files are the checks that each account's private file kept its inode,
/// owner and mode, that no one else can read it, and, once restored, that
/// its owner can.
fn files(gpa: Allocator, restored: bool) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    try out.appendSlice(gpa, &.{
        "ok same-ledger cmp /data/identities.saved /data/.werewolf/identities",
        "ok outsider-uid [ \"$(chpst -u :1001:1001 id -u)\" = 1001 ]",
    });
    for (accounts_kept) |a| {
        const private = try gpa.print("/data/home/{s}/private", .{a.name});
        try out.append(gpa, try gpa.print(
            "ok {s}-ownership [ \"$(stat -c '%i:%u:%g:%a' {s})\" = \"$(cat /data/{s}.stat)\" ] " ++
                "&& grep -qx {s}-secret {s}",
            .{ a.name, private, a.name, a.name, private },
        ));
        try out.append(gpa, try gpa.print(
            "ok {s}-private ! chpst -u :1001:1001 cat {s} 2>/tmp/private-error && " ++
                "grep -q 'Permission denied' /tmp/private-error",
            .{ a.name, private },
        ));
        if (restored) try out.append(gpa, try gpa.print(
            "ok {s}-access chpst -u :{d}:{d} cat {s} | grep -qx {s}-secret",
            .{ a.name, a.uid, a.uid, private, a.name },
        ));
    }
    return out.items;
}

test "the account checks name the exact identities, active or retired" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const active = try accounts(gpa, true);
    try std.testing.expectEqual(11, active.len);
    try std.testing.expectEqualStrings(
        "ok u2guv05clv-account grep -qx 'u2guv05clv:x:982829894:982829894::" ++
            "/data/home/u2guv05clv:/bin/mksh' /etc/passwd && grep -q '^u2guv05clv:\\*:' " ++
            "/etc/shadow && grep -qx 'u2guv05clv:x:982829894:' /etc/group",
        active[0],
    );
    try std.testing.expectEqualStrings(
        "ok lima-reservation grep -qx 'n lima 1000 1000' /data/.werewolf/identities",
        active[5],
    );
    const retired = try accounts(gpa, false);
    try std.testing.expectEqual(11, retired.len);
    const revoked = "ok lima-revoked [ ! -e /run/werewolf/keys/lima ]";
    try std.testing.expectEqualStrings(revoked, retired[7]);
    try std.testing.expectEqualStrings("ok active-list [ ! -s /run/werewolf/people ]", retired[10]);
    try std.testing.expectEqual(6, (try files(gpa, false)).len);
    const restored = try files(gpa, true);
    try std.testing.expectEqual(8, restored.len);
    try std.testing.expectEqualStrings(
        "ok u2guv05clv-access chpst -u :982829894:982829894 cat " ++
            "/data/home/u2guv05clv/private | grep -qx u2guv05clv-secret",
        restored[4],
    );
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

test "the NoCloud seed asks for lima at its uid with the test key" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "#cloud-config\nusers:\n  - name: lima\n    uid: 1001\n    ssh_authorized_keys:\n" ++
            "      - " ++ key ++ " nocloud-persist\n",
        try userData(arena.allocator(), 1001),
    );
}
