//! slot-keep: keep this boot's slot, make it the default, once it has proved itself.
//!
//! A new slot boots on probation, chosen for this boot only; the next reset
//! goes back to the slot (or, after bite, the distro) that was good. Once
//! every other service has stayed up for a minute, /data is there, and,
//! where the form has an updater, the updater has said it can update
//! (/run/werewolf/updater-ready, which slot-update writes once its setup
//! succeeds), slot-keep makes this slot good, and leaves
//! /run/werewolf/committed for stage0's deadman, which otherwise reboots the
//! machine after ten minutes. A slot whose updater cannot run is the one
//! failure no later update could undo, so it is never kept. Then it parks,
//! as a service that has done its job.
//!
//! Two loaders choose slots:
//!
//!     werewolf.grubenv=UUID:PATH   a distro's GRUB, after bite: saved_entry
//!                                  in GRUB's environment block, which
//!                                  /usr/lib/werewolf/grub-setenv rewrites in place
//!     werewolf.esp=UUID            systemd-boot, on werewolf's own disk
//!                                  (docs/design/native-boot.md): the entry is
//!                                  renamed from werewolf-a+N-M.conf, which
//!                                  counts tries, to werewolf-a.conf, good for
//!                                  good
//!
//! runsv runs it as /etc/sv/slot-keep/run, with no arguments and no shell.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const broker = @import("broker");

const committed = "/run/werewolf/committed";
const updater_ready = "/run/werewolf/updater-ready";
const nodata = "/run/werewolf/nodata";
const wait = 15;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const cmd = parseCmdline(readAll(io, gpa, "/proc/cmdline"));
    const grubenv = trim(readAll(io, gpa, "/run/werewolf/grubenv"));
    if (grubenv.len == 0 and (cmd.esp.len == 0 or cmd.slot.len == 0)) park(io);
    // stage0 insists on a or b; the entry name goes into a path here, so
    // this does too.
    if (cmd.slot.len > 0 and !std.mem.eql(u8, cmd.slot, "a") and !std.mem.eql(u8, cmd.slot, "b")) {
        say(io, "werewolf.slot={s} is not a or b; not committing", .{cmd.slot});
        park(io);
    }
    const entry = try gpa.print("werewolf-{s}", .{if (cmd.slot.len > 0) cmd.slot else "a"});

    var said = false;
    // The service that holds the commit back, said when it changes once a
    // boot has had two minutes: a service crash-looping is otherwise a
    // deadman reboot and a rollback with nothing on the console to say why.
    var waited: u32 = 0;
    var blocker_buf: [Dir.max_name_bytes]u8 = undefined;
    var blocker_said: [Dir.max_name_bytes]u8 = undefined;
    var blocker_said_len: usize = 0;
    while (true) : ({
        try io.sleep(.fromSeconds(wait), .awake);
        waited += wait;
    }) {
        if (unhealthy(io, &blocker_buf)) |blocker| {
            if (waited >= 120 and
                !std.mem.eql(u8, blocker, blocker_said[0..blocker_said_len]))
            {
                say(io, "{s} is not up and settled; not committing", .{blocker});
                @memcpy(blocker_said[0..blocker.len], blocker);
                blocker_said_len = blocker.len;
            }
            continue;
        }
        if (!exists(io, "/etc/sv/autoupdate") or exists(io, updater_ready)) break;
        // Said once, and only when the updater is all that is missing.
        if (!said) say(io, "the updater has not said it can update; not committing", .{});
        said = true;
    }

    if (grubenv.len > 0)
        try commitGrub(io, gpa, grubenv, entry)
    else
        try commitEsp(io, gpa, entry);
    park(io);
}

/// systemd-boot: the EFI partition, which the mount broker mounts apart for
/// as long as the rename takes.
fn commitEsp(io: Io, gpa: Allocator, entry: []const u8) !void {
    const esp = broker.ask(.esp) catch |err|
        return say(
            io,
            "no EFI partition: {s} {s}; not committing",
            .{ @errorName(err), broker.refusal },
        );
    defer esp.release();

    const d = try gpa.print("{s}/loader/entries", .{esp.path()});
    const good = try gpa.print("{s}/{s}.conf", .{ d, entry });
    if (exists(io, good)) {
        say(io, "{s} is already good", .{entry});
        return markCommitted(io);
    }
    if (dataUnavailable(io, gpa)) return;
    const tried = (try triedEntry(io, gpa, d, entry)) orelse
        return say(io, "no entry for {s} in {s}; not committing", .{ entry, d });
    try Dir.rename(Dir.cwd(), tried, Dir.cwd(), good, io);
    linux.sync();
    markCommitted(io);
    say(io, "healthy for a minute; {s} is good", .{entry});
}

/// GRUB: the block is on the victim's root filesystem (Debian), its /boot
/// partition (Ubuntu, Rocky) or its /boot subvolume (Fedora). Either way the
/// mount broker mounts it apart and writable, for as long as the write
/// takes: /victim, if it is the same filesystem, is read-only.
fn commitGrub(io: Io, gpa: Allocator, spec: []const u8, entry: []const u8) !void {
    const colon = std.mem.findScalar(u8, spec, ':') orelse
        return say(io, "werewolf.grubenv={s} names no path; not committing", .{spec});
    // Joined to the broker's mount and written as root: within it only.
    if (!isCleanPath(spec[colon + 1 ..]))
        return say(io, "werewolf.grubenv={s}: not a plain absolute path; not committing", .{spec});
    const boot = broker.ask(.grub) catch |err| return say(
        io,
        "no GRUB environment block at {s}: {s} {s}; not committing",
        .{ spec, @errorName(err), broker.refusal },
    );
    defer boot.release();

    const f = try gpa.print("{s}{s}", .{ boot.path(), spec[colon + 1 ..] });
    const block = readAll(io, gpa, f);
    if (block.len == 0) return say(io, "no GRUB environment block at {s}; not committing", .{spec});
    if (isSaved(block, entry)) {
        say(io, "{s} is already GRUB's default", .{entry});
        return markCommitted(io);
    }
    if (dataUnavailable(io, gpa)) return;
    if (!run(io, &.{ "/usr/lib/werewolf/grub-setenv", f, "saved_entry", entry }))
        return say(io, "not committing", .{});
    markCommitted(io);
    say(io, "healthy for a minute; {s} is now GRUB's default", .{entry});
}

/// Whether this slot cannot reach the machine's data, said if so. A slot
/// that cannot is not healthy, whatever its services say. Leaving it
/// uncommitted lets the deadman take the machine back to the slot that
/// last could.
fn dataUnavailable(io: Io, gpa: Allocator) bool {
    if (!exists(io, nodata)) return false;
    say(io, "/data is unavailable ({s}); not committing", .{trim(readAll(io, gpa, nodata))});
    return true;
}

/// The first other service that has not been running for a minute, nor
/// is down because it asked to be, as its name in name_buf; null once
/// every one has, or is (a service that parks itself), by runsv's own
/// account in each supervise/status; not down while wanted up, between
/// crashes, nor finishing, as a crashed service does while leash-reap
/// clears it, and not one whose runsv has yet to say.
fn unhealthy(io: Io, name_buf: *[Dir.max_name_bytes]u8) ?[]const u8 {
    var d = Dir.cwd().openDir(io, "/etc/sv", .{ .iterate = true }) catch return "/etc/sv";
    defer d.close(io);
    const now: u64 = @intCast(@max(
        0,
        @divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s),
    ));
    var it = d.iterate();
    while (it.next(io) catch return "/etc/sv") |e| {
        if (std.mem.eql(u8, e.name, "slot-keep")) continue;
        const name = name_buf[0..e.name.len];
        @memcpy(name, e.name);
        var path_buf: [Dir.max_name_bytes + 32]u8 = undefined;
        const path = std.mem.print(&path_buf, "{s}/supervise/status", .{name}) catch return name;
        var f = d.openFile(io, path, .{}) catch return name;
        defer f.close(io);
        var status: [20]u8 = undefined;
        const n = f.readPositionalAll(io, &status, 0) catch return name;
        if (n != status.len or !serviceHealthy(status, now)) return name;
    }
    return null;
}

/// runsv's supervise/status: the time of the last change as TAI64N
/// (seconds since 1970 plus 2^62 + 10), the pid, paused, want ('u' or
/// 'd'), a term flag, and the state (0 down, 1 run, 2 finish).
fn serviceHealthy(status: [20]u8, now: u64) bool {
    const since = std.mem.readInt(u64, status[0..8], .big) -| ((1 << 62) + 10);
    return switch (status[19]) {
        0 => status[17] == 'd',
        1 => now -| since >= 60,
        else => false,
    };
}

/// The entry for this slot that still counts its tries:
/// werewolf-a+1.conf, or werewolf-a+0-1.conf once systemd-boot has spent one.
fn triedEntry(io: Io, gpa: Allocator, dir: []const u8, entry: []const u8) !?[]const u8 {
    var d = Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch return null;
    defer d.close(io);
    var it = d.iterate();
    while (try it.next(io)) |e| {
        if (isTried(e.name, entry)) return try gpa.print("{s}/{s}", .{ dir, e.name });
    }
    return null;
}

fn isTried(name: []const u8, entry: []const u8) bool {
    if (!std.mem.startsWith(u8, name, entry) or !std.mem.endsWith(u8, name, ".conf")) return false;
    return name.len > entry.len and name[entry.len] == '+';
}

/// Whether GRUB's block already has saved_entry=entry.
fn isSaved(block: []const u8, entry: []const u8) bool {
    var it = std.mem.splitScalar(u8, block, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "saved_entry=")) continue;
        if (std.mem.eql(u8, line["saved_entry=".len..], entry)) return true;
    }
    return false;
}

const Cmdline = struct { slot: []const u8 = "", esp: []const u8 = "" };

fn parseCmdline(text: []const u8) Cmdline {
    var c: Cmdline = .{};
    var it = std.mem.tokenizeAny(u8, text, " \n");
    while (it.next()) |arg| {
        if (std.mem.cutPrefix(u8, arg, "werewolf.slot=")) |v| c.slot = v;
        if (std.mem.cutPrefix(u8, arg, "werewolf.esp=")) |v| c.esp = v;
    }
    return c;
}

/// Left for stage0's deadman, which then lets the machine be.
fn markCommitted(io: Io) void {
    Dir.cwd().writeFile(
        io,
        .{ .sub_path = committed, .data = "" },
    ) catch |err| say(io, "{s}: {s}", .{ committed, @errorName(err) });
}

/// Down, as a service that has done its job: runsv will not restart it.
fn park(io: Io) noreturn {
    const err = std.process.replace(io, .{ .argv = &.{ "/usr/bin/sv", "down", "." } });
    say(io, "sv down: {s}", .{@errorName(err)});
    std.process.exit(1);
}

fn run(io: Io, argv: []const []const u8) bool {
    var child = std.process.spawn(io, .{ .argv = argv, .stdin = .ignore }) catch return false;
    const term = child.wait(io) catch return false;
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

/// path, read to its end: procfs reports a size of 0, so not readFileAlloc.
fn readAll(io: Io, gpa: Allocator, path: []const u8) []const u8 {
    var f = Dir.cwd().openFile(io, path, .{}) catch return "";
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var r = f.readerStreaming(io, &buf);
    return r.interface.allocRemaining(gpa, .limited(1 << 20)) catch "";
}

/// Absolute, with no empty, . or .. part.
fn isCleanPath(p: []const u8) bool {
    if (p.len < 2 or p[0] != '/') return false;
    var parts = std.mem.splitScalar(u8, p[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, ".."))
            return false;
    }
    return true;
}

fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \r\n");
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "slot-keep: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

/// A supervise/status for state, want, and the last change secs ago.
fn statusOf(state: u8, want: u8, ago: u64) [20]u8 {
    var st: [20]u8 = @splat(0);
    std.mem.writeInt(u64, st[0..8], (1 << 62) + 10 + 1000 - ago, .big);
    st[17] = want;
    st[19] = state;
    return st;
}

test serviceHealthy {
    try testing.expect(serviceHealthy(statusOf(1, 'u', 75), 1000));
    try testing.expect(!serviceHealthy(statusOf(1, 'u', 12), 1000));
    // Parked by design; the updater is held to more (updater_ready).
    try testing.expect(serviceHealthy(statusOf(0, 'd', 30), 1000));
    // Down between crashes, and finishing after one.
    try testing.expect(!serviceHealthy(statusOf(0, 'u', 1), 1000));
    try testing.expect(!serviceHealthy(statusOf(2, 'u', 600), 1000));
    try testing.expect(!serviceHealthy(statusOf(7, 'u', 600), 1000));
}

test isCleanPath {
    try testing.expect(isCleanPath("/boot/grub/grubenv"));
    try testing.expect(isCleanPath("/grub2/grubenv"));
    for ([_][]const u8{
        "",
        "/",
        "grub/grubenv",
        "/boot/../etc/shadow",
        "/./x",
        "/a//b",
        "/a/",
    }) |p|
        try testing.expect(!isCleanPath(p));
}

test isTried {
    try testing.expect(isTried("werewolf-b+1.conf", "werewolf-b"));
    try testing.expect(isTried("werewolf-b+0-1.conf", "werewolf-b"));
    try testing.expect(!isTried("werewolf-b.conf", "werewolf-b"));
    try testing.expect(!isTried("werewolf-bb+1.conf", "werewolf-b"));
    try testing.expect(!isTried("werewolf-b+1.tmp", "werewolf-b"));
}

test isSaved {
    const block = "# GRUB Environment Block\nnext_entry=\nsaved_entry=werewolf-a\n####";
    try testing.expect(isSaved(block, "werewolf-a"));
    try testing.expect(!isSaved(block, "werewolf-b"));
    try testing.expect(!isSaved("saved_entry=werewolf-ab\n", "werewolf-a"));
}

test parseCmdline {
    const c = parseCmdline("console=hvc0 werewolf.slot=b werewolf.esp=57E1-F000\n");
    try testing.expectEqualStrings("b", c.slot);
    try testing.expectEqualStrings("57E1-F000", c.esp);
}
