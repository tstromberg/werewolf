//! swtpm keeps a local machine's swtpm in the invoking user's custody: the
//! guest gets only its emulated device, never the control socket. The
//! supervisor, `howl _tpm serve AUTHORITY SOCKETS BACKEND`, is what start
//! leaves running and stop ends. See docs/design/secure-local-deployment.md.

const std = @import("std");
const builtin = @import("builtin");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub const Backend = enum { qemu, bhyve };

/// Service is one machine's TPM: its authority directory, which holds the
/// emulator's state and the supervisor's lock, pid and log, and the private
/// directory the emulator's sockets are in.
pub const Service = struct {
    authority: []const u8,
    sockets: []const u8,
    backend: Backend,
    /// emulator is the swtpm the supervisor runs.
    emulator: []const u8 = "swtpm",
};

fn join(gpa: Allocator, dir: []const u8, name: []const u8) ![]const u8 {
    return gpa.print("{s}/{s}", .{ dir, name });
}

const socket_names = [_][]const u8{ "service.sock", "tpm.sock", "data.sock" };

/// checkPrivate refuses a socket directory that is not this user's own,
/// mode 0700 and no link: its name is predictable, so another user could
/// have made it first. A missing one is error.FileNotFound.
fn checkPrivate(gpa: Allocator, path: []const u8) !void {
    const z = try gpa.dupeSentinel(u8, path, 0);
    switch (builtin.os.tag) {
        .linux => {
            const linux = std.os.linux;
            var st: linux.Statx = undefined;
            switch (linux.errno(linux.statx(linux.AT.FDCWD, z, linux.AT.SYMLINK_NOFOLLOW, .{
                .TYPE = true,
                .MODE = true,
                .UID = true,
            }, &st))) {
                .SUCCESS => {},
                .NOENT => return error.FileNotFound,
                else => return error.UnsafeTpmSockets,
            }
            if (st.mode & linux.S.IFMT != linux.S.IFDIR or st.uid != linux.getuid() or
                st.mode & 0o777 != 0o700) return error.UnsafeTpmSockets;
        },
        else => {
            var st: std.c.Stat = undefined;
            if (std.c.fstatat(std.c.AT.FDCWD, z, &st, std.c.AT.SYMLINK_NOFOLLOW) != 0)
                return if (std.c._errno().* == @backingInt(std.c.E.NOENT))
                    error.FileNotFound
                else
                    error.UnsafeTpmSockets;
            if (st.mode & std.c.S.IFMT != std.c.S.IFDIR or st.uid != std.c.getuid() or
                st.mode & 0o777 != 0o700) return error.UnsafeTpmSockets;
        },
    }
}

/// within runs function, and fails with error.Timeout after timeout.
fn within(
    io: Io,
    timeout: Io.Duration,
    comptime T: type,
    function: anytype,
    args: anytype,
) !T {
    const Event = union(enum) { done: anyerror!T, late: Io.Cancelable!void };
    var buffer: [2]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.done, function, args);
    try events.concurrent(.late, Io.sleep, .{ io, timeout, .awake });
    return switch (try events.await()) {
        .done => |result| result,
        .late => |result| {
            try result;
            return error.Timeout;
        },
    };
}

/// heard reads what a client sent, at most 64 bytes, until it stopped sending.
fn heard(io: Io, stream: Io.net.Stream, out: *[64]u8) anyerror![]const u8 {
    var buf: [64]u8 = undefined;
    var reader = stream.reader(io, &buf);
    const n = try reader.interface.readSliceShort(out);
    return out[0..n];
}

/// request sends message to s's supervisor and reports whether it said OK.
fn request(io: Io, gpa: Allocator, s: Service, message: []const u8) !bool {
    try checkPrivate(gpa, s.sockets);
    const address = try Io.net.UnixAddress.init(try join(gpa, s.sockets, "service.sock"));
    const stream = try address.connect(io);
    defer stream.close(io);
    var buf: [64]u8 = undefined;
    var writer = stream.writer(io, &buf);
    try writer.interface.writeAll(message);
    try writer.interface.flush();
    try stream.shutdown(io, .send);
    var answered: [64]u8 = undefined;
    return std.mem.eql(u8, try within(io, .fromSeconds(15), []const u8, heard, .{
        io, stream, &answered,
    }), "OK");
}

fn absent(err: anyerror) bool {
    return err == error.FileNotFound or err == error.ConnectionRefused or
        err == error.ConnectionResetByPeer;
}

/// start makes sure s's supervisor runs: it asks a running one, else starts
/// one detached, in its own process group and logging to the authority.
pub fn start(io: Io, gpa: Allocator, s: Service) !void {
    const status = try gpa.print("STATUS {t}", .{s.backend});
    if (request(io, gpa, s, status)) |up| {
        if (up) return;
    } else |err| if (!absent(err)) return err;
    // Append, so each start follows the last.
    const log: Io.File = .{
        .handle = try std.posix.openat(
            std.posix.AT.FDCWD,
            try join(gpa, s.authority, "tpm-service.log"),
            .{ .ACCMODE = .WRONLY, .APPEND = true, .CREAT = true },
            0o600,
        ),
        .flags = .{ .nonblocking = false },
    };
    defer log.close(io);
    _ = try std.process.spawn(io, .{
        .argv = &.{
            try std.process.executablePathAlloc(io, gpa), "_tpm",    "serve",
            s.authority,                                  s.sockets, @tagName(s.backend),
        },
        .stdin = .ignore,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
        .pgid = 0,
    });
    for (0..160) |_| {
        if (request(io, gpa, s, status)) |up| {
            if (up) return;
        } else |err| if (!absent(err)) return err;
        try io.sleep(.fromMilliseconds(50), .awake);
    }
    howl.say(io, "TPM service did not start; see {s}/tpm-service.log", .{s.authority});
    return error.TpmServiceFailed;
}

/// stop asks s's supervisor to end and waits for it to: it acknowledges
/// before it cleans up, so another start waits for its lifetime lock.
pub fn stop(io: Io, gpa: Allocator, s: Service) !void {
    const guard = Dir.cwd().openFile(io, try join(gpa, s.authority, "tpm-service.lock"), .{
        .mode = .read_write,
    }) catch |err| switch (err) {
        error.FileNotFound => return, // No supervisor ever ran.
        else => return err,
    };
    defer guard.close(io);
    for (0..120) |_| {
        if (request(io, gpa, s, "STOP")) |stopped| {
            if (!stopped) return error.TpmServiceRefusedStop;
        } else |err| if (!absent(err)) return err;
        if (try guard.tryLock(io, .exclusive)) {
            guard.unlock(io);
            return;
        }
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    return error.TpmServiceStopTimeout;
}

/// answer serves the supervisor's socket until a client says STOP, and
/// returns that client's connection unanswered.
fn answer(io: Io, listener: *Io.net.Server, backend: Backend) anyerror!Io.net.Stream {
    var status: [16]u8 = undefined;
    const ready = try std.mem.print(&status, "STATUS {t}", .{backend});
    while (true) {
        const stream = try listener.accept(io);
        var buf: [64]u8 = undefined;
        const said = within(io, .fromSeconds(2), []const u8, heard, .{ io, stream, &buf }) catch
            "";
        if (std.mem.eql(u8, said, "STOP")) return stream;
        if (std.mem.eql(u8, said, ready)) reply(io, stream);
        stream.close(io);
    }
}

fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// serve is the supervisor. It holds the authority's lifetime lock, runs
/// swtpm with its state in the authority, answers STATUS and STOP, and
/// removes the sockets when it ends.
pub fn serve(io: Io, gpa: Allocator, s: Service) !void {
    const guard = try Dir.cwd().createFile(io, try join(gpa, s.authority, "tpm-service.lock"), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer guard.close(io);
    if (!try guard.tryLock(io, .exclusive)) return error.TpmServiceRunning;
    defer guard.unlock(io);
    // A new machine's TPM starts empty: its first boot makes it its own.
    const state = try join(gpa, s.authority, "swtpm");
    for ([_][]const u8{
        state,
        s.sockets,
    }) |dir| Dir.cwd().createDir(io, dir, .fromMode(0o700)) catch |err|
        if (err != error.PathAlreadyExists) return err;
    try checkPrivate(gpa, s.sockets);
    defer {
        for (socket_names) |name|
            Dir.cwd().deleteFile(io, join(gpa, s.sockets, name) catch continue) catch {};
        Dir.cwd().deleteDir(io, s.sockets) catch {};
    }
    for (socket_names) |name| Dir.cwd().deleteFile(io, try join(gpa, s.sockets, name)) catch {};
    // Clients wait in its backlog until swtpm is ready and answer starts.
    const address = try Io.net.UnixAddress.init(try join(gpa, s.sockets, "service.sock"));
    var listener = try address.listen(io, .{});
    defer listener.deinit(io);
    const ctrl = try join(gpa, s.sockets, "tpm.sock");
    const data = try join(gpa, s.sockets, "data.sock");
    const tpmstate = try gpa.print("dir={s}", .{state});
    const control = try gpa.print("type=unixio,path={s}", .{ctrl});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{
        s.emulator, "socket", "--tpm2",  "--tpmstate",    tpmstate,
        "--ctrl",   control,  "--flags", "not-need-init",
    });
    if (s.backend == .bhyve)
        try argv.appendSlice(gpa, &.{ "--server", try gpa.print("type=unixio,path={s}", .{data}) });
    var child = try std.process.spawn(io, .{ .argv = argv.items, .stdin = .ignore });
    const pid = child.id.?;
    const pid_file = try join(gpa, s.authority, "tpm.pid");
    defer Dir.cwd().deleteFile(io, pid_file) catch {};
    const Event = union(enum) {
        exited: anyerror!std.process.Child.Term,
        stop: anyerror!Io.net.Stream,
        late: Io.Cancelable!void,
    };
    var buffer: [3]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.exited, std.process.Child.wait, .{ &child, io });
    var running = true;
    // Whatever ends the supervisor ends swtpm first.
    defer if (running) end(io, &events, pid);
    try Dir.cwd().writeFile(io, .{ .sub_path = pid_file, .data = try gpa.print("{d}\n", .{pid}) });
    for (0..100) |_| {
        if (exists(io, ctrl) and (s.backend != .bhyve or exists(io, data))) break;
        try io.sleep(.fromMilliseconds(50), .awake);
    } else return error.SwtpmDidNotStart;
    try events.concurrent(.stop, answer, .{ io, &listener, s.backend });
    switch (try events.await()) {
        .exited => {
            running = false;
            howl.say(io, "TPM service: swtpm exited unexpectedly", .{});
            return error.SwtpmExited;
        },
        .stop => |result| {
            const stream = try result;
            defer stream.close(io);
            running = false;
            end(io, &events, pid);
            reply(io, stream);
        },
        .late => unreachable,
    }
}

fn reply(io: Io, stream: Io.net.Stream) void {
    var buf: [2]u8 = undefined;
    var writer = stream.writer(io, &buf);
    writer.interface.writeAll("OK") catch return;
    writer.interface.flush() catch {};
}

/// end stops swtpm: TERM, and KILL when it has not exited 10 s later.
fn end(io: Io, events: anytype, pid: std.posix.pid_t) void {
    std.posix.kill(pid, .TERM) catch {};
    events.concurrent(.late, Io.sleep, .{ io, Io.Duration.fromSeconds(10), .awake }) catch {};
    while (true) switch (events.await() catch return) {
        .exited => return,
        .late => std.posix.kill(pid, .KILL) catch {},
        .stop => |result| if (result) |stream| stream.close(io) else |_| {},
    };
}

/// command is `howl _tpm serve AUTHORITY SOCKETS BACKEND`.
pub fn command(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    const syntax = "_tpm serve AUTHORITY SOCKETS qemu|bhyve";
    if (args.len != 4 or !std.mem.eql(u8, args[0], "serve")) return why.refuse(syntax, .{});
    const backend = std.meta.stringToEnum(Backend, args[3]) orelse return why.refuse(syntax, .{});
    return serve(io, gpa, .{ .authority = args[1], .sockets = args[2], .backend = backend });
}

const testing = std.testing;

test "the socket directory must be this user's own, private, and no link" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const private = try gpa.print("{s}/private", .{root});
    try Dir.cwd().createDir(io, private, .fromMode(0o700));
    try checkPrivate(gpa, private);
    try testing.expectError(
        error.FileNotFound,
        checkPrivate(gpa, try gpa.print("{s}/missing", .{root})),
    );
    const open = try gpa.print("{s}/open", .{root});
    try Dir.cwd().createDir(io, open, .fromMode(0o700));
    try Dir.cwd().setFilePermissions(io, open, .fromMode(0o755), .{});
    try testing.expectError(error.UnsafeTpmSockets, checkPrivate(gpa, open));
    const link = try gpa.print("{s}/link", .{root});
    try Dir.cwd().symLink(io, private, link, .{});
    try testing.expectError(error.UnsafeTpmSockets, checkPrivate(gpa, link));
    const file = try gpa.print("{s}/file", .{root});
    try Dir.cwd().writeFile(io, .{ .sub_path = file, .data = "" });
    try Dir.cwd().setFilePermissions(io, file, .fromMode(0o700), .{});
    try testing.expectError(error.UnsafeTpmSockets, checkPrivate(gpa, file));
}

test "stopping a machine whose TPM never ran makes no TPM state" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "authority", .fromMode(0o700));
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    try stop(io, gpa, .{
        .authority = try gpa.print("{s}/authority", .{root}),
        .sockets = try gpa.print("{s}/sockets", .{root}),
        .backend = .qemu,
    });
    for ([_][]const u8{ "authority/swtpm", "authority/tpm-service.lock", "sockets" }) |name|
        try testing.expectError(error.FileNotFound, tmp.dir.access(io, name, .{}));
}

test "the supervisor answers its backend, stops swtpm and leaves nothing behind" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    // swtpm stands in for itself: it makes the sockets it was asked for
    // and runs until TERM.
    try tmp.dir.createDirPath(io, "bin");
    try tmp.dir.writeFile(io, .{ .sub_path = "bin/swtpm", .data =
        \\#!/bin/sh
        \\for arg in "$@"; do
        \\    case $arg in type=unixio,path=*) : >"${arg#type=unixio,path=}" ;; esac
        \\done
        \\trap 'exit 0' TERM
        \\while :; do sleep 1; done
        \\
    });
    try tmp.dir.setFilePermissions(io, "bin/swtpm", .fromMode(0o755), .{});
    const emulator = try gpa.print("{s}/bin/swtpm", .{root});
    var nonce: [6]u8 = undefined;
    io.random(&nonce);
    // macOS limits a socket's path to 104 bytes, too few for a test directory.
    const sockets = try gpa.print("/tmp/ww-tpm-test-{x}", .{&nonce});
    const authority = try gpa.print("{s}/authority", .{root});
    try Dir.cwd().createDir(io, authority, .fromMode(0o700));
    for ([_]Backend{ .qemu, .bhyve }) |backend| {
        const s: Service = .{
            .authority = authority,
            .sockets = sockets,
            .backend = backend,
            .emulator = emulator,
        };
        var served = try io.concurrent(serve, .{ io, gpa, s });
        var up = false;
        for (0..100) |_| {
            up = request(io, gpa, s, try gpa.print("STATUS {t}", .{backend})) catch false;
            if (up) break;
            try io.sleep(.fromMilliseconds(50), .awake);
        }
        try testing.expect(up);
        const other: Backend = if (backend == .qemu) .bhyve else .qemu;
        try testing.expect(!try request(io, gpa, s, try gpa.print("STATUS {t}", .{other})));
        try testing.expect(exists(io, try gpa.print("{s}/tpm.pid", .{authority})));
        try testing.expectEqual(
            backend == .bhyve,
            exists(io, try gpa.print("{s}/data.sock", .{sockets})),
        );
        try testing.expectError(error.TpmServiceRunning, serve(io, gpa, s));
        try testing.expect(try request(io, gpa, s, "STOP"));
        try served.await(io);
        try testing.expect(!exists(io, sockets));
        try testing.expect(!exists(io, try gpa.print("{s}/tpm.pid", .{authority})));
        try testing.expect(exists(io, try gpa.print("{s}/swtpm", .{authority})));
        // A stopped supervisor is stopped: stop returns at once.
        try stop(io, gpa, s);
    }
}
