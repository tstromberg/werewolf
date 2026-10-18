//! Bounded client execution, with concurrent stdin and output collection.
const std = @import("std");
const Io = std.Io;
extern "c" fn kill(pid: std.posix.pid_t, signal: c_int) c_int;

pub fn run(
    a: std.mem.Allocator,
    io: Io,
    argv: []const []const u8,
    env: *const std.process.Environ.Map,
    input: []const u8,
    timeout_ms: i64,
) !std.process.RunResult {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .environ_map = env,
        .pgid = 0,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    const pid = child.id.?;
    defer child.kill(io);
    // Clients may fork helpers which retain pipes after the direct child exits.
    defer _ = kill(-pid, @backingInt(std.posix.SIG.KILL));
    const Event = union(enum) {
        input: anyerror!void,
        result: anyerror!std.process.RunResult,
        timeout: Io.Cancelable!void,
    };
    var buffer: [3]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.input, write, .{ io, child.stdin.?, input });
    child.stdin = null; // The writer owns and closes it, before wait can close pipes.
    try events.concurrent(.result, collect, .{ a, io, &child });
    try events.concurrent(.timeout, sleep, .{ io, timeout_ms });
    var result: ?std.process.RunResult = null;
    var written = false;
    while (!written or result == null) switch (try events.await()) {
        .input => |status| {
            try status;
            written = true;
        },
        .result => |status| result = try status,
        .timeout => |status| {
            try status;
            return error.Timeout;
        },
    };
    return result.?;
}

fn sleep(io: Io, ms: i64) Io.Cancelable!void {
    try io.sleep(.fromMilliseconds(ms), .awake);
}

fn write(io: Io, pipe: Io.File, bytes: []const u8) anyerror!void {
    defer pipe.close(io);
    try pipe.writeStreamingAll(io, bytes);
}

fn collect(a: std.mem.Allocator, io: Io, child: *std.process.Child) anyerror!std.process.RunResult {
    var buffer: Io.File.MultiReader.Buffer(2) = undefined;
    var reader: Io.File.MultiReader = undefined;
    reader.init(a, io, buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer reader.deinit();
    while (reader.fill(4096, .none)) |_| {
        if (reader.reader(0).buffered().len > 1 << 20 or reader.reader(1).buffered().len > 64 << 10)
            return error.StreamTooLong;
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => return err,
    }
    try reader.checkAnyError();
    const term = try child.wait(io);
    return .{
        .term = term,
        .stdout = try reader.toOwnedSlice(0),
        .stderr = try reader.toOwnedSlice(1),
    };
}
