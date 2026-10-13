//! Root operator requests run in the supervised updater, retaining broker authentication.
const std = @import("std");
const linux = std.os.linux;
const path = "/run/werewolf/update-control.sock";
pub const limit = 68;
pub const Command = enum { check, outcome, @"try" };
pub const Request = struct { command: Command, declaration: ?[]const u8 = null };
const Credentials = extern struct { pid: i32, uid: u32, gid: u32 };

pub fn parse(raw: []const u8) !Request {
    if (raw.len == 0 or raw.len > limit) return error.BadUpdateRequest;
    var fields = std.mem.splitScalar(u8, raw, ' ');
    const command = std.meta.stringToEnum(Command, fields.next().?) orelse
        return error.BadUpdateRequest;
    const hash = fields.next();
    if (fields.next() != null) return error.BadUpdateRequest;
    if (hash) |h| {
        if (command != .@"try" or h.len != 64) return error.BadUpdateRequest;
        for (h) |c| if (!(c >= '0' and c <= '9') and !(c >= 'a' and c <= 'f'))
            return error.BadUpdateRequest;
    }
    return .{ .command = command, .declaration = hash };
}

fn address() linux.sockaddr.un {
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..path.len], path);
    return addr;
}

pub fn listen() !i32 {
    const raw = linux.socket(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(raw) != .SUCCESS) return error.UpdateControlSocket;
    const fd: i32 = @intCast(raw);
    errdefer _ = linux.close(fd);
    const previous = linux.syscall1(.umask, 0o077);
    defer _ = linux.syscall1(.umask, previous);
    _ = linux.unlinkat(linux.AT.FDCWD, path, 0);
    var addr = address();
    if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)))) != .SUCCESS or
        linux.errno(linux.listen(fd, 8)) != .SUCCESS) return error.UpdateControlListen;
    return fd;
}

/// One bounded packet from a root peer; a stalled peer consumes at most two seconds.
pub fn accept(listener: i32, buf: *[limit + 1]u8) ?struct { fd: i32, request: Request } {
    var item: linux.pollfd = .{ .fd = listener, .events = linux.POLL.IN, .revents = 0 };
    if (linux.errno(linux.poll(@ptrCast(&item), 1, 0)) != .SUCCESS or
        item.revents & linux.POLL.IN == 0) return null;
    const raw = linux.accept4(listener, null, null, linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK);
    if (linux.errno(raw) != .SUCCESS) return null;
    const fd: i32 = @intCast(raw);
    var accepted = false;
    defer {
        if (!accepted) _ = linux.close(fd);
    }
    var cred: Credentials = undefined;
    var size: linux.socklen_t = @sizeOf(Credentials);
    const peer = linux.getsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.PEERCRED,
        @ptrCast(&cred),
        &size,
    );
    if (linux.errno(peer) != .SUCCESS or size != @sizeOf(Credentials) or cred.uid != 0)
        return null;
    item = .{ .fd = fd, .events = linux.POLL.IN, .revents = 0 };
    if (linux.errno(linux.poll(@ptrCast(&item), 1, 2000)) != .SUCCESS or
        item.revents & linux.POLL.IN == 0) return null;
    const n = linux.recvfrom(fd, buf, buf.len, linux.MSG.TRUNC, null, null);
    if (linux.errno(n) != .SUCCESS or n > limit) return null;
    const request = parse(buf[0..n]) catch return null;
    accepted = true;
    return .{ .fd = fd, .request = request };
}

pub fn reply(fd: i32, err: ?anyerror) void {
    defer _ = linux.close(fd);
    var buf: [128]u8 = undefined;
    const text = if (err) |e|
        std.mem.print(&buf, "no {s}\n", .{@errorName(e)}) catch "no\n"
    else
        "ok\n";
    _ = linux.sendto(fd, text.ptr, text.len, linux.MSG.NOSIGNAL, null, 0);
}

pub fn submit(io: std.Io, gpa: std.mem.Allocator, mode: []const u8, hash: ?[]const u8) !void {
    const text = if (hash) |h| try gpa.print("{s} {s}", .{ mode, h }) else mode;
    _ = try parse(text);
    // A manual request is explicit authorization to start the existing updater service.
    // There is no direct broker fallback when that service is absent or cannot start.
    const raw = linux.socket(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(raw) != .SUCCESS) return error.UpdateControlSocket;
    const fd: i32 = @intCast(raw);
    defer _ = linux.close(fd);
    var addr = address();
    const queued = linux.errno(linux.connect(
        fd,
        @ptrCast(&addr),
        @sizeOf(@TypeOf(addr)),
    )) == .SUCCESS;
    // Queue before resuming a paused service, so the operator request precedes its scheduled pass.
    if (queued) try send(fd, text);
    for ([_][]const u8{ "up", "cont" }) |action| {
        var child = try std.process.spawn(io, .{
            .argv = &.{ "/usr/bin/sv", action, "/etc/sv/autoupdate" },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .inherit,
        });
        const term = try child.wait(io);
        if (term != .exited or term.exited != 0) return error.UpdateServiceUnavailable;
    }
    if (!queued) {
        var tries: usize = 0;
        while (linux.errno(linux.connect(
            fd,
            @ptrCast(&addr),
            @sizeOf(@TypeOf(addr)),
        )) != .SUCCESS) {
            if (tries == 100) return error.UpdateServiceUnavailable;
            tries += 1;
            try io.sleep(.fromMilliseconds(100), .awake);
        }
        try send(fd, text);
    }
    var buf: [128]u8 = undefined;
    const n = linux.recvfrom(fd, &buf, buf.len, linux.MSG.TRUNC, null, null);
    if (linux.errno(n) != .SUCCESS or n > buf.len or !std.mem.eql(u8, buf[0..n], "ok\n"))
        return error.UpdateControlRefused;
}

fn send(fd: i32, text: []const u8) !void {
    const n = linux.sendto(fd, text.ptr, text.len, linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(n) != .SUCCESS or n != text.len) return error.UpdateControlSend;
}

test "operator requests cannot select paths, commands or malformed declaration hashes" {
    const t = std.testing;
    try t.expectEqual(Command.check, (try parse("check")).command);
    try t.expectEqual(Command.outcome, (try parse("outcome")).command);
    try t.expectEqual(Command.@"try", (try parse("try")).command);
    const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const valid = "try " ++ hash;
    try t.expectEqualStrings(valid[4..], (try parse(valid)).declaration.?);
    for ([_][]const u8{ "", "daemon", "check extra", "outcome extra", "check\ntry" }) |bad|
        try t.expectError(error.BadUpdateRequest, parse(bad));
    for ([_][]const u8{ "try /data/file", "try  ", valid ++ "x", valid ++ " extra" }) |bad|
        try t.expectError(error.BadUpdateRequest, parse(bad));
    try t.expectError(error.BadUpdateRequest, parse("try G" ++ hash[1..]));
}
