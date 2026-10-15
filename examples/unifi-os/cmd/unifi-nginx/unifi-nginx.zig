//! Supervise one confined nginx master; accept only Core's fixed reload packet.
const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const socket_path = "/data/share/unifi/reload/nginx.sock";
const request = "reload\n";
const nginx = "/usr/bin/nginx";
const config = "/etc/nginx/nginx.conf";
var stopping: std.atomic.Value(bool) = .init(false);

pub fn main(init: std.process.Init) void {
    serve(init) catch |err| {
        var buf: [128]u8 = undefined;
        const line = std.mem.print(&buf, "unifi-nginx: {s}\n", .{@errorName(err)}) catch return;
        Io.File.stderr().writeStreamingAll(init.io, line) catch {};
        std.process.exit(1);
    };
}

fn serve(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const passwd = try Io.Dir.cwd().readFileAlloc(io, "/etc/passwd", gpa, .limited(64 << 10));
    const uid = try coreUid(passwd);
    const action: linux.Sigaction = .{
        .handler = .{ .handler = terminate },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(.TERM, &action, null);
    _ = linux.sigaction(.INT, &action, null);
    const master = try spawn(
        &.{ nginx, "-c", config, "-e", "stderr", "-g", "daemon off;" },
        init.minimal.environ,
    );
    // This child is never reaped while requests are processed, so its PID
    // cannot be reused for another process. No PID comes from a caller/file.
    defer {
        _ = linux.kill(master, linux.SIG.TERM);
        var status: i32 = 0;
        _ = linux.waitpid(master, &status, 0);
    }
    var fd: i32 = -1;
    defer if (fd >= 0) {
        _ = linux.close(fd);
    };
    while (!stopping.load(.acquire)) {
        var status: i32 = 0;
        const gone = linux.waitpid(master, &status, linux.W.NOHANG);
        if (gone != 0 and linux.errno(gone) != .INTR) {
            // Do not run the deferred signal after reaping this PID.
            std.process.exit(1);
        }
        if (fd < 0) fd = listener() catch {
            var empty: [0]linux.pollfd = .{};
            _ = linux.poll(&empty, 0, 100);
            continue;
        };
        var fds = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.errno(linux.poll(&fds, 1, 250)) == .INTR) continue;
        if (fds[0].revents & linux.POLL.IN == 0) continue;
        const raw = linux.accept4(fd, null, null, linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK);
        if (linux.errno(raw) != .SUCCESS) continue;
        const client: i32 = @intCast(raw);
        defer _ = linux.close(client);
        if (!corePeer(client, uid)) continue;
        var incoming = [_]linux.pollfd{.{ .fd = client, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&incoming, 1, 1000) != 1 or
            incoming[0].revents & linux.POLL.IN == 0) continue;
        var packet: [32]u8 = undefined;
        const n = linux.recvfrom(client, &packet, packet.len, linux.MSG.TRUNC, null, null);
        if (n != request.len or !std.mem.eql(u8, packet[0..request.len], request)) {
            _ = linux.sendto(client, "denied\n", 7, linux.MSG.NOSIGNAL, null, 0);
            continue;
        }
        var check = try std.process.spawn(io, .{
            .argv = &.{ nginx, "-c", config, "-e", "stderr", "-t", "-q" },
            .stdin = .ignore,
        });
        const result = try check.wait(io);
        const valid = result == .exited and result.exited == 0;
        const reloaded = valid and linux.errno(linux.kill(master, linux.SIG.HUP)) == .SUCCESS;
        const reply = if (reloaded) "ok\n" else "failed\n";
        _ = linux.sendto(client, reply.ptr, reply.len, linux.MSG.NOSIGNAL, null, 0);
    }
}

fn listener() !i32 {
    const raw = linux.socket(
        linux.AF.UNIX,
        linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    );
    if (linux.errno(raw) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(raw);
    errdefer _ = linux.close(fd);
    _ = linux.unlink(socket_path);
    var address: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(address.path[0..socket_path.len], socket_path);
    if (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.un))) != .SUCCESS or
        linux.errno(linux.fchmodat(linux.AT.FDCWD, socket_path, 0o660)) != .SUCCESS or
        linux.errno(linux.listen(fd, 4)) != .SUCCESS) return error.Listen;
    return fd;
}

const Credentials = extern struct { pid: i32, uid: u32, gid: u32 };

fn corePeer(fd: i32, uid: u32) bool {
    var credentials: Credentials = undefined;
    var size: linux.socklen_t = @sizeOf(Credentials);
    return linux.errno(linux.getsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.PEERCRED,
        @ptrCast(&credentials),
        &size,
    )) == .SUCCESS and
        size == @sizeOf(Credentials) and credentials.uid == uid;
}

fn coreUid(passwd: []const u8) !u32 {
    var lines = std.mem.splitScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, fields.next() orelse "", "_oci-unifi-core")) continue;
        _ = fields.next();
        return std.fmt.parseInt(u32, fields.next() orelse return error.NoCoreUser, 10);
    }
    return error.NoCoreUser;
}

fn spawn(argv: []const []const u8, environ: std.process.Environ) !i32 {
    var ptrs: [10:null]?[*:0]const u8 = @splat(null);
    var storage: [9][128:0]u8 = undefined;
    if (argv.len >= ptrs.len) return error.Arguments;
    for (argv, 0..) |arg, i| {
        if (arg.len >= storage[i].len) return error.Arguments;
        @memcpy(storage[i][0..arg.len], arg);
        storage[i][arg.len] = 0;
        ptrs[i] = &storage[i];
    }
    const raw = linux.fork();
    if (linux.errno(raw) != .SUCCESS) return error.Fork;
    if (raw == 0) {
        const entries = environ.block.view().slice;
        var env: [256:null]?[*:0]const u8 = @splat(null);
        if (entries.len >= env.len) linux.exit_group(127);
        for (entries, 0..) |entry, i| env[i] = entry;
        _ = linux.execve(ptrs[0].?, &ptrs, &env);
        linux.exit_group(127);
    }
    return @intCast(raw);
}

fn terminate(_: linux.SIG) callconv(.c) void {
    stopping.store(true, .release);
}

test "reload peer is the declared Core user, never root or a claimed identity" {
    try std.testing.expectEqual(
        @as(u32, 1234),
        try coreUid("root:x:0:0::/:\n_oci-unifi-core:x:1234:1234::/:\n"),
    );
    try std.testing.expectError(error.NoCoreUser, coreUid("root:x:0:0::/:\n"));
    try std.testing.expectError(error.InvalidCharacter, coreUid("_oci-unifi-core:x:bad:1::/:\n"));
}
