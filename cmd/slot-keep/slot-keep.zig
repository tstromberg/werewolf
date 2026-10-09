//! slot-keep makes this boot's slot the loader's default once every service
//! has run for a minute, /data works, and the updater is ready. Until then
//! stage0's deadman reboots into the last good slot. See README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const broker = @import("broker");
const cmdline = @import("cmdline");

const committed = "/run/werewolf/committed";
const updater_ready = "/run/werewolf/updater-ready";
const nodata = "/run/werewolf/nodata";
const wait = 15;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    // Parse as stage0 does (lib/cmdline.zig). It allows only slot a or b and
    // a plain GRUB path, since both end up in paths written as root.
    var refused: cmdline.Failure = .{};
    const cmd = cmdline.parse(readAll(io, gpa, "/proc/cmdline"), &refused) orelse {
        say(io, "the command line's {s}: {s}; not committing", .{ refused.word, refused.why });
        park(io);
    };
    if (cmd.grubenv == null and (cmd.esp == null or cmd.slot == null)) park(io);
    const entry = try gpa.print("werewolf-{s}", .{@tagName(cmd.slot orelse .a)});

    var said = false;
    // After two minutes, log the service that blocks the commit whenever it
    // changes. Otherwise a crash loop ends in a deadman rollback with nothing
    // on the console to say why.
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
        // A slot whose updater cannot run could never be updated away from,
        // so it is never kept. Log this once.
        if (!said) say(io, "the updater has not said it can update; not committing", .{});
        said = true;
    }

    if (cmd.grubenv) |grubenv|
        try commitGrub(io, gpa, grubenv, entry)
    else
        try commitEsp(io, gpa, entry);
    park(io);
}

/// commitEsp commits for systemd-boot by renaming this slot's counting entry
/// to entry.conf, on the EFI partition the mount broker lends for the rename.
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

/// commitGrub sets GRUB's saved_entry to entry. The block lives on the
/// victim's root (Debian), /boot partition (Ubuntu, Rocky) or /boot subvolume
/// (Fedora); /victim is read-only, so the mount broker lends a writable mount.
fn commitGrub(io: Io, gpa: Allocator, spec: cmdline.Place, entry: []const u8) !void {
    const boot = broker.ask(.grub) catch |err| return say(
        io,
        "no GRUB environment block at {s}:{s}: {s} {s}; not committing",
        .{ spec.uuid, spec.path, @errorName(err), broker.refusal },
    );
    defer boot.release();

    // lib/cmdline.zig rejects "." and "..", so f stays inside the mount.
    const f = try gpa.print("{s}{s}", .{ boot.path(), spec.path });
    const block = readAll(io, gpa, f);
    if (block.len == 0) return say(
        io,
        "no GRUB environment block at {s}:{s}; not committing",
        .{ spec.uuid, spec.path },
    );
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

/// dataUnavailable reports, and logs, whether /data failed this boot. Such a
/// slot is not healthy whatever its services say, so it is left for the
/// deadman to roll back.
fn dataUnavailable(io: Io, gpa: Allocator) bool {
    if (!exists(io, nodata)) return false;
    say(io, "/data is unavailable ({s}); not committing", .{trim(readAll(io, gpa, nodata))});
    return true;
}

/// unhealthy returns the name, in name_buf, of the first other service that
/// serviceHealthy rejects or that has no readable supervise/status yet. It
/// returns null when every service is healthy.
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

/// serviceHealthy reports whether a runsv supervise/status shows a service
/// running for 60 s, or down because it wants to be (parked). Down while
/// wanted up means between crashes; finish means leash-reap is clearing one.
/// The 20 bytes hold the last change as TAI64N (seconds since 1970 plus
/// 2^62 + 10), the pid, paused, want ('u' or 'd'), term, and state (0 down,
/// 1 run, 2 finish).
fn serviceHealthy(status: [20]u8, now: u64) bool {
    const since = std.mem.readInt(u64, status[0..8], .big) -| ((1 << 62) + 10);
    return switch (status[19]) {
        0 => status[17] == 'd',
        1 => now -| since >= 60,
        else => false,
    };
}

/// triedEntry returns the path of this slot's entry that still counts tries,
/// such as werewolf-a+1.conf, or werewolf-a+0-1.conf after one try.
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

/// isSaved reports whether GRUB's block already has saved_entry=entry.
fn isSaved(block: []const u8, entry: []const u8) bool {
    var it = std.mem.splitScalar(u8, block, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "saved_entry=")) continue;
        if (std.mem.eql(u8, line["saved_entry=".len..], entry)) return true;
    }
    return false;
}

/// markCommitted creates the file that tells stage0's deadman not to reboot.
fn markCommitted(io: Io) void {
    Dir.cwd().writeFile(
        io,
        .{ .sub_path = committed, .data = "" },
    ) catch |err| say(io, "{s}: {s}", .{ committed, @errorName(err) });
}

/// park marks the service down so runsv does not restart it.
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

/// readAll returns path's contents, or "" on error. It reads to the end
/// because procfs reports a size of 0.
fn readAll(io: Io, gpa: Allocator, path: []const u8) []const u8 {
    var f = Dir.cwd().openFile(io, path, .{}) catch return "";
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var r = f.readerStreaming(io, &buf);
    return r.interface.allocRemaining(gpa, .limited(1 << 20)) catch "";
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

/// statusOf builds a supervise/status with state, want, and the last change
/// ago seconds before 1000.
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
    // Parked on purpose. The updater must also write updater_ready.
    try testing.expect(serviceHealthy(statusOf(0, 'd', 30), 1000));
    // Down between crashes, and finishing after one.
    try testing.expect(!serviceHealthy(statusOf(0, 'u', 1), 1000));
    try testing.expect(!serviceHealthy(statusOf(2, 'u', 600), 1000));
    try testing.expect(!serviceHealthy(statusOf(7, 'u', 600), 1000));
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
