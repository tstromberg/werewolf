//! runit-stage: runit's three stages, one program under three names, as runit
//! runs them: /etc/runit/1, 2 and 3.
//!
//!     1   nothing: /init has done stage 1 by the time runit is PID 1
//!     2   run the services (runsvdir) until runit is told to stop
//!     3   stop the services (as sv force-stop, without its 420 ms poll),
//!         then have the mount broker put /data and /victim down before
//!         the power goes
//!
//! Without stage 3 a stop is a power cut, and ext4 loses its last few
//! seconds of writes. runit kills whatever is left, syncs, and powers off (or
//! reboots, if reboot asked) once stage 3 exits.
//!
//! Stage 2 that cannot start runsvdir exits 111, which runit answers by
//! running stage 2 again, not stage 3: a stop would kill stage0's deadman
//! and power off, where an uncommitted slot should reboot into the last
//! slot that worked.

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
            say(io, "runsvdir: {s}; runit will run stage 2 again", .{@errorName(err)});
            std.process.exit(111);
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
    // How long the stop took, which a reboot for an update waits on.
    const start = bootMs();
    var services_ms: u64 = 0;
    defer {
        const all = bootMs() -| start;
        const fs_ms = all -| services_ms;
        say(io, "down in {d}.{d:0>3}s (services {d}.{d:0>3}s, filesystems {d}.{d:0>3}s)", .{
            all / 1000,         all % 1000,
            services_ms / 1000, services_ms % 1000,
            fs_ms / 1000,       fs_ms % 1000,
        });
    }
    try stopServices(io, gpa, try serviceDirs(io, gpa));
    services_ms = bootMs() -| start;

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

const stop_for_ms = 30_000;
/// How long a killed service is given to be down: its ./finish, leash-reap,
/// waits up to five seconds for its cgroup to empty.
const reap_for_ms = 6_000;
const look_every_ms = 10;

/// Each service told to go down, as `sv -w 30 force-stop` does: runsv's
/// control `d` (TERM, then CONT), then a wait for its stat to say down,
/// and `k` (KILL) for one that is not in 30 seconds, which then has six
/// more to be down, so /data is not still held when it is put down. sv
/// looks every 420 ms, so even services that stop at once cost a reboot
/// that; this looks every 10. Then each runsv is told to exit (`x`) once
/// its service is down.
fn stopServices(io: Io, gpa: Allocator, dirs: []const []const u8) !void {
    const Service = struct { dir: []const u8, control: [:0]const u8, stat: []const u8, down: bool };
    const services = try gpa.alloc(Service, dirs.len);
    for (services, dirs) |*s, d| {
        s.* = .{
            .dir = d,
            .control = try gpa.printSentinel("{s}/supervise/control", .{d}, 0),
            .stat = try gpa.print("{s}/supervise/stat", .{d}),
            .down = false,
        };
        control(s.control, 'd');
    }
    const start = bootMs();
    var killed = false;
    while (true) {
        var up: usize = 0;
        for (services) |*s| {
            if (!s.down) s.down = isDown(io, s.stat);
            if (!s.down) up += 1;
        }
        if (up == 0) break;
        const waited = bootMs() -| start;
        if (!killed and waited >= stop_for_ms) {
            for (services) |s| if (!s.down) {
                say(io, "{s} not down in 30s; killed", .{s.dir});
                control(s.control, 'k');
            };
            killed = true;
        } else if (killed and waited >= stop_for_ms + reap_for_ms) {
            for (services) |s| if (!s.down) say(io, "{s} still not down; going on", .{s.dir});
            break;
        }
        io.sleep(.fromMilliseconds(look_every_ms), .awake) catch break;
    }
    for (services) |s| control(s.control, 'x');
}

/// One command to a service's runsv. Without a runsv reading its control,
/// there is nothing to tell, and the open fails at once (ENXIO).
fn control(path: [:0]const u8, cmd: u8) void {
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .NONBLOCK = true, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return;
    defer _ = linux.close(@intCast(fd));
    _ = linux.write(@intCast(fd), &[_]u8{cmd}, 1);
}

/// Whether runsv's stat says down. A service without one has no runsv to
/// wait on, and counts as down.
fn isDown(io: Io, path: []const u8) bool {
    var buf: [64]u8 = undefined;
    const text = Dir.cwd().readFile(io, path, &buf) catch return true;
    return std.mem.startsWith(u8, text, "down");
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "werewolf: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

/// Milliseconds since the kernel started its clock.
fn bootMs() u64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
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

test isDown {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const dir = buf[0..try tmp.dir.realPath(io, &buf)];
    const path = try std.fs.path.join(testing.allocator, &.{ dir, "stat" });
    defer testing.allocator.free(path);

    // What runsv writes: the state, then what it was told.
    try tmp.dir.writeFile(io, .{ .sub_path = "stat", .data = "run, want down\n" });
    try testing.expect(!isDown(io, path));
    try tmp.dir.writeFile(io, .{ .sub_path = "stat", .data = "finish, want down\n" });
    try testing.expect(!isDown(io, path));
    try tmp.dir.writeFile(io, .{ .sub_path = "stat", .data = "down\n" });
    try testing.expect(isDown(io, path));
    try tmp.dir.deleteFile(io, "stat");
    try testing.expect(isDown(io, path));
}
