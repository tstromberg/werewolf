//! paperless-init prepares the library the four Paperless services share.
//! With no argument it makes the directories, clears the ready mark and
//! waits for Valkey. `ready`, after migrate, writes the mark. `wait`,
//! the other services' first command, returns once the mark is there.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const linux = std.os.linux;

const data = "/data/svc/paperless";
const ready = "/data/svc/paperless/ready";
const sock = "/run/svc/valkey/valkey.sock";

const dirs = [_][]const u8{
    data ++ "/media/documents/originals",
    data ++ "/media/documents/archive",
    data ++ "/media/documents/thumbnails",
    data ++ "/media/documents/share_link_bundles",
    data ++ "/index",
    data ++ "/log",
    data ++ "/consume",
    data ++ "/llm_index",
    "/run/svc/paperless/tmp",
};

const Mode = enum { begin, ready, wait };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = init.minimal.args.toSlice(gpa) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
    run(io, args) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, args: []const []const u8) !void {
    switch (try modeOf(args)) {
        .begin => {
            for (dirs) |path| try ensure(io, path);
            clearReady();
            try waitValkey(io);
        },
        .ready => try markReady(io),
        .wait => try waitReady(io),
    }
}

fn modeOf(args: []const []const u8) !Mode {
    if (args.len < 2) return .begin;
    if (args.len > 2) return error.BadMode;
    if (std.mem.eql(u8, args[1], "ready")) return .ready;
    if (std.mem.eql(u8, args[1], "wait")) return .wait;
    return error.BadMode;
}

fn ensure(io: Io, path: []const u8) !void {
    Dir.cwd().createDirPath(io, path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

fn clearReady() void {
    const rc = linux.unlink(ready);
    if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .NOENT) return;
}

fn markReady(io: Io) !void {
    var f = try Dir.cwd().createFile(io, ready, .{ .truncate = true });
    defer f.close(io);
    try f.writeStreamingAll(io, "ready\n");
    say(io, "library is ready", .{});
}

fn waitReady(io: Io) !void {
    var i: u32 = 0;
    while (i < 180) : (i += 1) {
        if (Dir.cwd().statFile(io, ready, .{})) |_| {
            say(io, "library is ready", .{});
            return;
        } else |_| {}
        pause();
    }
    say(io, "library is not ready", .{});
    return error.NotReady;
}

fn waitValkey(io: Io) !void {
    var i: u32 = 0;
    while (i < 60) : (i += 1) {
        if (valkeyUp()) {
            say(io, "valkey is up", .{});
            return;
        }
        pause();
    }
    say(io, "valkey is not listening", .{});
    return error.NoValkey;
}

fn pause() void {
    var req: linux.timespec = .{ .sec = 1, .nsec = 0 };
    _ = linux.nanosleep(&req, null);
}

fn valkeyUp() bool {
    const fd = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..sock.len], sock);
    return linux.errno(linux.connect(
        @intCast(fd),
        @ptrCast(&addr),
        @sizeOf(linux.sockaddr.un),
    )) == .SUCCESS;
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const line = std.mem.print(&buf, "paperless-init: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

test "the directories are the library, the queue's scratch, and the consume folder" {
    try std.testing.expectEqual(9, dirs.len);
    try std.testing.expectEqualStrings(data ++ "/consume", dirs[6]);
    try std.testing.expectEqualStrings("/run/svc/paperless/tmp", dirs[8]);
}

test "ready and wait are the only arguments" {
    try std.testing.expectEqual(Mode.begin, try modeOf(&.{"paperless-init"}));
    try std.testing.expectEqual(Mode.ready, try modeOf(&.{ "paperless-init", "ready" }));
    try std.testing.expectEqual(Mode.wait, try modeOf(&.{ "paperless-init", "wait" }));
    try std.testing.expectError(error.BadMode, modeOf(&.{ "paperless-init", "go" }));
    try std.testing.expectError(error.BadMode, modeOf(&.{ "paperless-init", "ready", "now" }));
}
