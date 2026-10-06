//! runit-stage: runit's three stages, one program under three names, as runit
//! runs them: /etc/runit/1, 2 and 3.
//!
//!     1   nothing: /init has done stage 1 by the time runit is PID 1
//!     2   run the services (runsvdir) until runit is told to stop
//!     3   stop the services, then have the mount broker put /data and
//!         /victim down before the power goes
//!
//! Without stage 3 a stop is a power cut, and ext4 loses its last few
//! seconds of writes. runit kills whatever is left, syncs, and powers off (or
//! reboots, if reboot asked) once stage 3 exits.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const broker = @import("broker");

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
            std.debug.print("runit-stage: run as /etc/runit/1, 2 or 3\n", .{});
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
    // /data down (or read-only, if something still holds it), its LUKS
    // mapping closed, and the victim's filesystem remounted read-only, so
    // the journal is written in place before GRUB reads it without one:
    // the mount broker's (cmd/mount-broker), since fence's domain keeps
    // everyone else from unmounting. It says each step on the console.
    const done = broker.ask(.shutdown) catch |err| {
        say(
            io,
            "filesystems not put down: {s} {s}; the journal will repair them",
            .{ @errorName(err), broker.refusal },
        );
        return;
    };
    done.release();
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
    try testing.expectEqual(0, stageOf("runit-stage"));
}
