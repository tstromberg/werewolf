//! stage: runit's three stages, one program under three names, as runit
//! runs them: /etc/runit/1, 2 and 3.
//!
//!     1   nothing: /init has done stage 1 by the time runit is PID 1
//!     2   run the services (runsvdir) until runit is told to stop
//!     3   stop the services, then put /data down before the power goes
//!
//! Without stage 3 a stop is a power cut, and ext4 loses its last few
//! seconds of writes. runit kills whatever is left, syncs, and powers off (or
//! reboots, if reboot asked) once stage 3 exits.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    switch (stageOf(std.fs.path.basename(args[0]))) {
        1 => return,
        2 => {
            // runit opens the console without blocking (djb's open_write),
            // so that PID 1 never waits on it, and all it starts shares
            // that open file: a service writing more than the serial port
            // holds gets EAGAIN and loses the rest. The services get a
            // console of their own that waits; runit keeps its.
            const fd = linux.open("/dev/console", .{ .ACCMODE = .WRONLY, .NOCTTY = true }, 0);
            if (linux.errno(fd) == .SUCCESS) {
                _ = linux.dup2(@intCast(fd), 1);
                _ = linux.dup2(@intCast(fd), 2);
                if (fd > 2) _ = linux.close(@intCast(fd));
            }
            const err = std.process.replace(
                io,
                .{ .argv = &.{ "/usr/bin/runsvdir", "-P", "/etc/sv" } },
            );
            say(io, "runsvdir: {s}", .{@errorName(err)});
            std.process.exit(1);
        },
        3 => try stop(io, gpa),
        else => {
            std.debug.print("stage: run as /etc/runit/1, 2 or 3\n", .{});
            std.process.exit(2);
        },
    }
}

/// The stage for the name runit ran this as: /etc/runit/1, 2 or 3.
fn stageOf(name: []const u8) u8 {
    if (name.len != 1 or name[0] < '1' or name[0] > '3') return 0;
    return name[0] - '0';
}

fn stop(io: Io, gpa: Allocator) !void {
    say(io, "stopping services", .{});
    const services = try serviceDirs(io, gpa);
    if (services.len > 0) {
        _ = run(io, gpa, &.{ "/usr/bin/sv", "-w", "30", "force-stop" }, services);
        _ = run(io, gpa, &.{ "/usr/bin/sv", "exit" }, services);
    }

    linux.sync();
    const mounts = readAll(io, gpa, "/proc/self/mounts");
    if (isMounted(mounts, "/data")) {
        if (umount("/data")) {
            say(io, "/data unmounted", .{});
        } else if (remountReadOnly("/data")) {
            say(io, "/data busy; remounted read-only", .{});
        }
    }
    if (exists(io, "/dev/mapper/data") and
        run(io, gpa, &.{ "/usr/bin/cryptsetup", "close", "data" }, &.{}))
    {
        say(io, "/data closed", .{});
    }
    // The victim's root filesystem, which /data was bound from, and which
    // may hold the root itself (a slot's root.erofs, held open by a loop
    // device, so it is never wholly unmounted). GRUB reads it without the
    // journal: a read-only remount of the filesystem itself, not this one
    // mount, writes everything the journal holds into place, so the next
    // boot's GRUB sees what this one wrote. Allowed with the loop open,
    // since it is open read-only.
    if (isMounted(mounts, "/victim")) {
        if (remountReadOnly("/victim")) say(
            io,
            "/victim's filesystem is read-only, its journal written in place",
            .{},
        );
        if (umount("/victim")) {
            say(io, "/victim unmounted", .{});
        } else if (remountReadOnly("/victim")) {
            say(io, "/victim busy; remounted read-only", .{});
        }
    }
}

/// /etc/sv/*, the services runsvdir ran.
fn serviceDirs(io: Io, gpa: Allocator) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var d = Dir.cwd().openDir(io, "/etc/sv", .{ .iterate = true }) catch return out.items;
    defer d.close(io);
    var it = d.iterate();
    while (it.next(io) catch null) |e| {
        if (e.kind == .directory or
            e.kind == .sym_link) try out.append(gpa, try gpa.print("/etc/sv/{s}", .{e.name}));
    }
    std.mem.sort([]const u8, out.items, {}, lessString);
    return out.items;
}

fn umount(path: [*:0]const u8) bool {
    return linux.errno(linux.umount2(path, 0)) == .SUCCESS;
}

/// The filesystem under dir read-only: mount(2)'s remount, which changes
/// the filesystem and so writes its journal into place, where
/// mount_setattr(2), which the mount helper uses, changes only the one
/// mount. The restrictions the mount has are given again, so it keeps them.
fn remountReadOnly(dir: [*:0]const u8) bool {
    const MS = linux.MS; // ziglint-ignore: Z032
    const flags = MS.REMOUNT | MS.RDONLY | MS.NOSUID | MS.NODEV | MS.NOEXEC;
    return linux.errno(linux.mount(null, dir, null, flags, 0)) == .SUCCESS;
}

/// Whether argv, then extra, runs and exits 0. Its output goes to the
/// console with this program's.
fn run(io: Io, gpa: Allocator, argv: []const []const u8, extra: []const []const u8) bool {
    const all = std.mem.concat(gpa, []const u8, &.{ argv, extra }) catch return false;
    var child = std.process.spawn(io, .{ .argv = all, .stdin = .ignore }) catch return false;
    const term = child.wait(io) catch return false;
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

/// Whether point is a mount point in /proc/self/mounts.
fn isMounted(mounts: []const u8, point: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, mounts, '\n');
    while (it.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        _ = f.next() orelse continue;
        if (std.mem.eql(u8, f.next() orelse continue, point)) return true;
    }
    return false;
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

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "werewolf: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

fn lessString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test stageOf {
    try testing.expectEqual(1, stageOf("1"));
    try testing.expectEqual(3, stageOf("3"));
    try testing.expectEqual(0, stageOf("4"));
    try testing.expectEqual(0, stageOf("stage"));
}

test isMounted {
    const mounts = "proc /proc proc rw 0 0\n/dev/vda1 /data ext4 rw 0 0\n";
    try testing.expect(isMounted(mounts, "/data"));
    try testing.expect(!isMounted(mounts, "/victim"));
    try testing.expect(!isMounted(mounts, "/dat"));
}
