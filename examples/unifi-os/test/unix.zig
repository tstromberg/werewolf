//! Accounts, Unix sockets and files used as another user by the root checks.
//! A child drops to the tested identity, so the kernel's own DAC and peer
//! credentials decide. Children make raw system calls only: the driver has
//! threads.
const std = @import("std");
const linux = std.os.linux;

pub const Identity = struct { uid: u32, gid: u32, groups: []const u32 = &.{} };

/// name's uid and primary gid in passwd.
pub fn account(passwd: []const u8, name: []const u8) !Identity {
    var lines = std.mem.splitScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, fields.next() orelse continue, name)) continue;
        _ = fields.next();
        const uid = fields.next() orelse return error.InvalidAccount;
        const gid = fields.next() orelse return error.InvalidAccount;
        return .{
            .uid = try std.fmt.parseInt(u32, uid, 10),
            .gid = try std.fmt.parseInt(u32, gid, 10),
        };
    }
    return error.UnknownAccount;
}

/// Run attempt(args) in a child holding only who's credentials, and return
/// the errno it reports.
pub fn as(who: Identity, comptime attempt: anytype, args: anytype) !linux.E {
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.Fork;
    if (pid == 0) {
        if (linux.errno(linux.setgroups(who.groups.len, who.groups.ptr)) != .SUCCESS or
            linux.errno(linux.setresgid(who.gid, who.gid, who.gid)) != .SUCCESS or
            linux.errno(linux.setresuid(who.uid, who.uid, who.uid)) != .SUCCESS)
            linux.exit_group(255);
        const e: linux.E = @call(.auto, attempt, args);
        linux.exit_group(@backingInt(e));
    }
    var status: i32 = 0;
    while (true) switch (linux.errno(linux.wait4(@intCast(pid), &status, 0, null))) {
        .SUCCESS => break,
        .INTR => {},
        else => return error.Wait,
    };
    const s: u32 = @bitCast(status);
    if (!linux.W.IFEXITED(s) or linux.W.EXITSTATUS(s) == 255) return error.Credentials;
    return @fromBackingInt(linux.W.EXITSTATUS(s));
}

/// A nonblocking Unix socket of kind connected to path by who, or by this
/// process when who is null. The server's SO_PEERCRED reports the
/// credentials of the connecting process.
pub fn connect(who: ?Identity, path: []const u8, kind: u32) !i32 {
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    if (path.len >= address.path.len) return error.NameTooLong;
    @memcpy(address.path[0..path.len], path);
    const rc = linux.socket(linux.AF.UNIX, kind | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);
    const e = if (who) |w| try as(w, connectTo, .{ fd, &address }) else connectTo(fd, &address);
    return switch (e) {
        .SUCCESS => fd,
        .ACCES, .PERM => error.AccessDenied,
        .NOENT => error.FileNotFound,
        .CONNREFUSED => error.ConnectionRefused,
        .AGAIN => error.WouldBlock,
        else => error.Connect,
    };
}

fn connectTo(fd: i32, address: *const linux.sockaddr.un) linux.E {
    return linux.errno(linux.connect(fd, address, @sizeOf(linux.sockaddr.un)));
}

/// Write all of bytes to a nonblocking socket, waiting at most 5 s at a time.
pub fn send(fd: i32, bytes: []const u8) !void {
    var n: usize = 0;
    while (n < bytes.len) {
        const rc = linux.sendto(fd, bytes[n..].ptr, bytes.len - n, linux.MSG.NOSIGNAL, null, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => n += rc,
            .AGAIN => try wait(fd, linux.POLL.OUT, 5000),
            .INTR => {},
            .PIPE, .CONNRESET => return error.ConnectionResetByPeer,
            else => return error.WriteFailed,
        }
    }
}

/// Read what arrives within milliseconds into buffer: one packet on a
/// SOCK_SEQPACKET socket. Zero is the end of the stream.
pub fn receive(fd: i32, buffer: []u8, milliseconds: i32) !usize {
    while (true) {
        try wait(fd, linux.POLL.IN, milliseconds);
        const rc = linux.recvfrom(fd, buffer.ptr, buffer.len, 0, null, null);
        switch (linux.errno(rc)) {
            .SUCCESS => return rc,
            .AGAIN, .INTR => {},
            .CONNRESET => return error.ConnectionResetByPeer,
            else => return error.ReadFailed,
        }
    }
}

fn wait(fd: i32, events: i16, milliseconds: i32) !void {
    var fds = [1]linux.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
    const rc = linux.poll(&fds, 1, milliseconds);
    switch (linux.errno(rc)) {
        .SUCCESS => if (rc == 0) return error.Timeout,
        .INTR => {},
        else => return error.Poll,
    }
}

test "accounts carry the uid and primary gid, never a prefix match" {
    const passwd = "root:x:0:0::/:\n_oci-unifi-core:x:1234:1235::/:\nnginx:x:101:102::/:\n";
    const core = try account(passwd, "_oci-unifi-core");
    try std.testing.expectEqual(@as(u32, 1234), core.uid);
    try std.testing.expectEqual(@as(u32, 1235), core.gid);
    try std.testing.expectError(error.UnknownAccount, account(passwd, "ngin"));
    try std.testing.expectError(error.InvalidAccount, account("nginx:x:101\n", "nginx"));
    try std.testing.expectError(error.InvalidCharacter, account("nginx:x:a:1::/:\n", "nginx"));
}
