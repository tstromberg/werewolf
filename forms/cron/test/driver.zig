//! Run real supercronic jobs through sh-shim, under the cron account and pledge.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const directory = "/data/svc/test-cron-jobs";
const program = "/usr/lib/werewolf/test-cron-jobs";

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len == 3 and std.mem.eql(u8, args[1], "job")) {
        if (!std.mem.eql(u8, args[2], "ran") and !std.mem.eql(u8, args[2], "shell-ran"))
            return error.JobPath;
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = args[2], .data = "ran\n" });
        return;
    }
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    if (std.mem.eql(u8, args[2], "prepare")) {
        try Io.Dir.cwd().deleteTree(io, directory);
        try ctx.result(io, args[1], "cron-fixture-clean", true);
    } else if (std.mem.eql(u8, args[2], "jobs")) {
        try jobs(io, a);
        try ctx.result(io, args[1], "cron-job-runs", true);
    } else if (std.mem.eql(u8, args[2], "audit")) {
        const uid = try driver.system.account(io, a, "supercronic");
        const size = linux.syscall3(.syslog, 10, 0, 0);
        if (linux.errno(size) != .SUCCESS or size > 8 << 20) return error.KernelLogSize;
        const buffer = try a.alloc(u8, size);
        const length = linux.syscall3(.syslog, 3, @intFromPtr(buffer.ptr), buffer.len);
        if (linux.errno(length) != .SUCCESS) return error.KernelLogRead;
        try ctx.result(io, args[1], "cron-pledged", try pledged(a, buffer[0..length], uid));
    } else return error.Usage;
}

fn jobs(io: Io, a: Allocator) !void {
    var dir = try Io.Dir.cwd().openDir(io, directory, .{});
    defer dir.close(io);
    const crontab = try a.print(
        "SHELL=/usr/lib/werewolf/sh-shim\n" ++
            "* * * * * * * {s} job ran\n" ++
            "* * * * * * * /usr/bin/zstd -V\n" ++
            "* * * * * * * {s} job shell-ran && {s} job shell-ran\n",
        .{ program, program, program },
    );
    try dir.writeFile(io, .{ .sub_path = "crontab", .data = crontab });
    var log = try dir.createFile(io, "cron.log", .{});
    defer log.close(io);
    var daemon = try std.process.spawn(io, .{
        .argv = &.{ "/usr/bin/supercronic", "-json", "-no-reap", directory ++ "/crontab" },
        .cwd = .{ .path = directory },
        .stdin = .ignore,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
    });
    defer daemon.kill(io);
    const stop = Io.Clock.awake.now(io).addDuration(.fromSeconds(30));
    while (true) {
        var attempt: std.heap.ArenaAllocator = .init(a);
        defer attempt.deinit();
        const gpa = attempt.allocator();
        const body = try driver.system.read(io, gpa, directory ++ "/cron.log");
        const marker: ?Io.File = dir.openFile(io, "ran", .{}) catch |err| blk: {
            if (err != error.FileNotFound) return err;
            break :blk null;
        };
        if (marker) |file| {
            file.close(io);
            if (std.mem.find(u8, body, "sh-shim: /usr/bin/zstd: permission denied") != null and
                std.mem.find(u8, body, "is shell syntax") != null) break;
        }
        if (Io.Clock.awake.now(io).compare(.gte, stop)) {
            try Io.File.stderr().writeStreamingAll(io, body[body.len - @min(body.len, 8192) ..]);
            return error.JobsNotObserved;
        }
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    const metadata = try driver.system.file(io, a, directory ++ "/ran", .{ .object = .empty });
    if (metadata.object.get("uid").?.integer != try driver.system.account(io, a, "supercronic"))
        return error.JobOwner;
}

fn pledged(a: Allocator, log: []const u8, uid: u32) !bool {
    const identity = try a.print(" uid={d} ", .{uid});
    defer a.free(identity);
    var lines = std.mem.splitScalar(u8, log, '\n');
    while (lines.next()) |line| {
        if (std.mem.find(u8, line, "type=1326") == null or
            std.mem.find(u8, line, identity) == null) continue;
        if (std.mem.find(u8, line, "comm=\"supercronic\"") != null or
            std.mem.find(u8, line, "comm=\"sh-shim\"") != null) return false;
    }
    return true;
}

test "cron audit matches the complete UID and the scheduler or shim" {
    try std.testing.expect(!try pledged(
        std.testing.allocator,
        "audit: type=1326 uid=123 comm=\"supercronic\" syscall=1",
        123,
    ));
    try std.testing.expect(!try pledged(
        std.testing.allocator,
        "audit: type=1326 uid=123 comm=\"sh-shim\" syscall=1",
        123,
    ));
    try std.testing.expect(try pledged(
        std.testing.allocator,
        "audit: type=1326 uid=1234 comm=\"supercronic\" syscall=1",
        123,
    ));
    try std.testing.expect(try pledged(
        std.testing.allocator,
        "audit: type=1326 uid=123 comm=\"test-cron-jobs\" syscall=1",
        123,
    ));
}
