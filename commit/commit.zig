//! commit: make this boot's slot good, once it has proved itself.
//!
//! A new slot boots on probation, chosen for this boot only; the next reset
//! goes back to the slot (or, after bite, the distro) that was good. Once
//! every other service has stayed up for a minute, and /data is there,
//! commit makes this slot good, and leaves /run/werewolf/committed for
//! stage0's deadman, which otherwise reboots the machine after ten minutes.
//! Then it parks, as a service that has done its job.
//!
//! Two loaders choose slots:
//!
//!     werewolf.grubenv=UUID:PATH   a distro's GRUB, after bite: saved_entry
//!                                  in GRUB's environment block, which
//!                                  /usr/lib/werewolf/grubenv rewrites in place
//!     werewolf.esp=UUID            systemd-boot, on werewolf's own disk
//!                                  (design/native-boot.md): the entry is
//!                                  renamed from werewolf-a+N-M.conf, which
//!                                  counts tries, to werewolf-a.conf, good for
//!                                  good
//!
//! runsv runs it as /etc/sv/commit/run, with no arguments and no shell.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const mount_bin = "/usr/lib/werewolf/mount";
const committed = "/run/werewolf/committed";
const nodata = "/run/werewolf/nodata";
const wait = 15;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const cmd = parseCmdline(readAll(io, gpa, "/proc/cmdline"));
    const grubenv = trim(readAll(io, gpa, "/run/werewolf/grubenv"));
    if (grubenv.len == 0 and (cmd.esp.len == 0 or cmd.slot.len == 0)) park(io);
    const entry = try gpa.print(
        "werewolf-{s}",
        .{if (cmd.slot.len > 0) cmd.slot else "a"},
    );

    while (!healthy(io, gpa)) try io.sleep(.fromSeconds(wait), .awake);

    if (grubenv.len > 0)
        try commitGrub(io, gpa, grubenv, entry)
    else
        try commitEsp(io, gpa, cmd.esp, entry);
    park(io);
}

/// systemd-boot: the EFI partition, mounted apart for as long as the rename
/// takes. FAT is never probed, so it is named.
fn commitEsp(io: Io, gpa: Allocator, esp: []const u8, entry: []const u8) !void {
    const e = "/run/werewolf/esp";
    if (!mountUuid(
        io,
        gpa,
        esp,
        e,
        "vfat",
    )) return say(io, "no EFI partition {s}; not committing", .{esp});
    defer _ = linux.umount2(e, 0);

    const d = e ++ "/loader/entries";
    const good = try gpa.print("{s}/{s}.conf", .{ d, entry });
    if (exists(io, good)) {
        say(io, "{s} is already good", .{entry});
        return markCommitted(io);
    }
    if (exists(
        io,
        nodata,
    )) return say(
        io,
        "/data is unavailable ({s}); not committing",
        .{trim(readAll(io, gpa, nodata))},
    );
    const tried = (try triedEntry(
        io,
        gpa,
        d,
        entry,
    )) orelse return say(io, "no entry for {s} in {s}; not committing", .{ entry, d });
    try Dir.rename(Dir.cwd(), tried, Dir.cwd(), good, io);
    linux.sync();
    markCommitted(io);
    say(io, "healthy for a minute; {s} is good", .{entry});
}

/// GRUB: the block is on the victim's root filesystem (Debian), its /boot
/// partition (Ubuntu, Rocky) or its /boot subvolume (Fedora). Either way it
/// is mounted here, apart and writable, for as long as the write takes:
/// /victim, if it is the same filesystem, is read-only.
fn commitGrub(io: Io, gpa: Allocator, spec: []const u8, entry: []const u8) !void {
    const colon = std.mem.findScalar(
        u8,
        spec,
        ':',
    ) orelse return say(io, "werewolf.grubenv={s} names no path; not committing", .{spec});
    const uuid = spec[0..colon];
    const b = "/run/werewolf/boot";
    if (!mountUuid(
        io,
        gpa,
        uuid,
        b,
        null,
    )) return say(io, "no GRUB environment block at {s}; not committing", .{spec});
    defer _ = linux.umount2(b, 0);

    const f = try gpa.print("{s}{s}", .{ b, spec[colon + 1 ..] });
    const block = readAll(io, gpa, f);
    if (block.len == 0) return say(io, "no GRUB environment block at {s}; not committing", .{spec});
    if (isSaved(block, entry)) {
        say(io, "{s} is already GRUB's default", .{entry});
        return markCommitted(io);
    }
    // A slot that cannot reach the machine's data is not healthy, whatever
    // its services say. Leaving it uncommitted lets the deadman take the
    // machine back to the slot that last could.
    if (exists(
        io,
        nodata,
    )) return say(
        io,
        "/data is unavailable ({s}); not committing",
        .{trim(readAll(io, gpa, nodata))},
    );
    if (!run(
        io,
        &.{ "/usr/lib/werewolf/grubenv", f, "saved_entry", entry },
    )) return say(io, "not committing", .{});
    markCommitted(io);
    say(io, "healthy for a minute; {s} is now GRUB's default", .{entry});
}

/// Whether every other service has been running for a minute, or is down
/// because it asked to be (a service that parks itself); not down while
/// wanted up, between crashes.
fn healthy(io: Io, gpa: Allocator) bool {
    var d = Dir.cwd().openDir(io, "/etc/sv", .{ .iterate = true }) catch return false;
    defer d.close(io);
    var it = d.iterate();
    while (it.next(io) catch return false) |e| {
        if (std.mem.eql(u8, e.name, "commit")) continue;
        const dir = gpa.print("/etc/sv/{s}", .{e.name}) catch return false;
        const res = std.process.run(
            gpa,
            io,
            .{ .argv = &.{ "/usr/bin/sv", "status", dir } },
        ) catch return false;
        if (!statusHealthy(res.stdout)) return false;
    }
    return true;
}

/// One line of `sv status`: "run: /etc/sv/x: (pid 12) 75s", or "down: ...".
fn statusHealthy(line: []const u8) bool {
    if (std.mem.indexOf(u8, line, "want up") != null) return false;
    if (!std.mem.startsWith(u8, line, "run:")) return true;
    const close = std.mem.indexOf(u8, line, ") ") orelse return false;
    const rest = line[close + 2 ..];
    const end = std.mem.findScalar(u8, rest, 's') orelse return false;
    const up = std.fmt.parseInt(u32, rest[0..end], 10) catch return false;
    return up >= 60;
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
        if (std.mem.startsWith(u8, arg, "werewolf.slot=")) c.slot = arg["werewolf.slot=".len..];
        if (std.mem.startsWith(u8, arg, "werewolf.esp=")) c.esp = arg["werewolf.esp=".len..];
    }
    return c;
}

/// The filesystem with uuid on dir, through the mount helper.
fn mountUuid(io: Io, gpa: Allocator, uuid: []const u8, dir: []const u8, kind: ?[]const u8) bool {
    const tag = gpa.print("UUID={s}", .{uuid}) catch return false;
    const res = std.process.run(
        gpa,
        io,
        .{ .argv = &.{ "/usr/bin/blkid", "-c", "/dev/null", "-l", "-o", "device", "-t", tag } },
    ) catch return false;
    const dev = trim(res.stdout);
    if (dev.len == 0) return false;
    Dir.cwd().createDirPath(io, dir) catch return false;
    if (kind) |k| return run(io, &.{ mount_bin, "-t", k, "-o", "nosuid,nodev,noexec", dev, dir });
    return run(io, &.{ mount_bin, "-o", "nosuid,nodev,noexec", dev, dir });
}

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

fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \r\n");
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "commit: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test statusHealthy {
    try testing.expect(statusHealthy("run: /etc/sv/nginx: (pid 123) 75s\n"));
    try testing.expect(!statusHealthy("run: /etc/sv/nginx: (pid 123) 12s\n"));
    try testing.expect(statusHealthy("down: /etc/sv/autoupdate: 30s, normally up\n"));
    try testing.expect(!statusHealthy("down: /etc/sv/nginx: 1s, normally up, want up\n"));
    try testing.expect(!statusHealthy("run: /etc/sv/x: garbage\n"));
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
