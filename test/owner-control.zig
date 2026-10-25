//! owner-control checks that killing howl during an owner operation closes
//! its connection: howl holds the owner socket itself, and no helper
//! process outlives it to keep the VM's port.
//!
//!     owner-control HOWL
const std = @import("std");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 2) return error.Usage;
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const howl = try std.fs.path.resolveAlloc(gpa, &.{ cwd, args[1] });
    var nonce: [6]u8 = undefined;
    io.random(&nonce);
    // macOS limits a socket's path to 104 bytes: keep the root short.
    const root = try gpa.print("/tmp/ww-owner-test-{x}", .{&nonce});
    const machine = try gpa.print("{s}/build/machines/werewolf-run", .{root});
    try Io.Dir.cwd().createDirPath(io, machine);
    defer Io.Dir.cwd().deleteTree(io, root) catch {};
    const address = try Io.net.UnixAddress.init(try gpa.print("{s}/owner.sock", .{machine}));
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    var child = try std.process.spawn(io, .{
        .argv = &.{ howl, "owner", "status" },
        .cwd = .{ .path = root },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer if (child.id != null) child.kill(io);
    const stream = try within(io, .fromSeconds(5), requested, .{ io, &server }) orelse
        fail("owner: howl sent no owner request");
    defer stream.close(io);
    child.kill(io);
    if (!(try within(io, .fromSeconds(3), closed, .{ io, stream }) orelse false))
        fail("owner: an orphan kept the owner socket after howl was killed");
    std.debug.print("pass   owner: killing howl closes its owner connection\n", .{});
}

fn fail(comptime reason: []const u8) noreturn {
    std.debug.print("fail   " ++ reason ++ "\n", .{});
    std.process.exit(1);
}

/// within returns what function returns, or null if it takes longer than limit.
fn within(
    io: Io,
    limit: Io.Duration,
    comptime function: anytype,
    args: std.meta.ArgsTuple(@TypeOf(function)),
) !?@typeInfo(@typeInfo(@TypeOf(function)).@"fn".return_type.?).error_union.payload {
    const Result = @typeInfo(@TypeOf(function)).@"fn".return_type.?;
    const Event = union(enum) { done: Result, late: Io.Cancelable!void };
    var buffer: [2]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.done, function, args);
    try events.concurrent(.late, sleep, .{ io, limit });
    return switch (try events.await()) {
        .done => |result| try result,
        .late => |status| {
            try status;
            return null;
        },
    };
}

fn sleep(io: Io, limit: Io.Duration) Io.Cancelable!void {
    try io.sleep(limit, .awake);
}

/// requested accepts howl's connection and reads its request line.
fn requested(io: Io, server: *Io.net.Server) !Io.net.Stream {
    const stream = try server.accept(io);
    errdefer stream.close(io);
    var in: [256]u8 = undefined;
    var reader = stream.reader(io, &in);
    const line = try reader.interface.takeDelimiterExclusive('\n');
    if (!std.mem.endsWith(u8, line, " status")) return error.WrongOwnerRequest;
    return stream;
}

/// closed reports whether the peer closed stream rather than writing to it.
fn closed(io: Io, stream: Io.net.Stream) !bool {
    var in: [1]u8 = undefined;
    var reader = stream.reader(io, &in);
    _ = reader.interface.takeByte() catch |err| return switch (err) {
        error.EndOfStream => true,
        error.ReadFailed => reader.err.? == error.ConnectionResetByPeer,
    };
    return false;
}
