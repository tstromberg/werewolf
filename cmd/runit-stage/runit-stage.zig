//! runit-stage is runit's three stages, run as /etc/runit/1, 2 and 3. Stage 1
//! does nothing, stage 2 runs runsvdir, and stage 3 stops the services and
//! has the mount broker unmount /data. See README.md.

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
            // runit opens the console non-blocking so PID 1 never waits on
            // it, and its children share that open file. A service writing
            // faster than the serial port would get EAGAIN and lose output,
            // so give the services a blocking console of their own.
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
            // Exit 111 makes runit retry stage 2. Any other exit runs stage
            // 3, which kills stage0's deadman and powers off instead of
            // rebooting an uncommitted slot into the last good one.
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

/// stageOf returns the stage named by the program's basename, 1 to 3, or 0
/// for any other name.
fn stageOf(name: []const u8) u8 {
    if (name.len != 1 or name[0] < '1' or name[0] > '3') return 0;
    return name[0] - '0';
}

fn stop(io: Io, gpa: Allocator) !void {
    say(io, "stopping services", .{});
    // Log how long the stop took: an update's reboot waits on it.
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
    // fence's domain forbids unmounting, so the mount broker (cmd/mount-broker)
    // unmounts /data (or remounts it read-only if held), closes its LUKS
    // mapping, and remounts the victim read-only so GRUB, which ignores the
    // journal, reads current blocks.
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

/// serviceDirs returns the service directories in /etc/sv, sorted. A missing
/// /etc/sv yields none.
fn serviceDirs(io: Io, gpa: Allocator) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var d = Dir.cwd().openDir(io, "/etc/sv", .{ .iterate = true }) catch return out.items;
    defer d.close(io);
    var it = d.iterate();
    while (it.next(io) catch null) |e| {
        if (e.kind == .directory or e.kind == .sym_link)
            try out.append(gpa, try gpa.print("/etc/sv/{s}", .{e.name}));
    }
    std.mem.sort([]const u8, out.items, {}, lessString);
    return out.items;
}

const stop_for_ms = 30_000;
/// reap_for_ms is how long a killed service gets to go down. Its ./finish,
/// leash-reap, waits up to five seconds for the cgroup to empty.
const reap_for_ms = 6_000;
const look_every_ms = 10;

/// stopServices does what `sv -w 30 force-stop` does, for all services at
/// once: it sends `d` (TERM, then CONT), sends `k` (KILL) to any still up
/// after 30 s, waits up to 6 s more, then tells every runsv to exit (`x`).
/// It polls every 10 ms, not sv's 420 ms, because a reboot waits on it.
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

/// control writes cmd to a runsv control pipe. The open is non-blocking, so
/// it fails at once (ENXIO) when no runsv reads the pipe.
fn control(path: [:0]const u8, cmd: u8) void {
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .NONBLOCK = true, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return;
    defer _ = linux.close(@intCast(fd));
    _ = linux.write(@intCast(fd), &[_]u8{cmd}, 1);
}

/// isDown reports whether runsv's stat file says down. A missing file means
/// no runsv to wait on, so it counts as down.
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

/// bootMs returns CLOCK_BOOTTIME in milliseconds, or 0 on error.
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

    // runsv writes the state, then the wanted state.
    try tmp.dir.writeFile(io, .{ .sub_path = "stat", .data = "run, want down\n" });
    try testing.expect(!isDown(io, path));
    try tmp.dir.writeFile(io, .{ .sub_path = "stat", .data = "finish, want down\n" });
    try testing.expect(!isDown(io, path));
    try tmp.dir.writeFile(io, .{ .sub_path = "stat", .data = "down\n" });
    try testing.expect(isDown(io, path));
    try tmp.dir.deleteFile(io, "stat");
    try testing.expect(isDown(io, path));
}
