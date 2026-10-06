//! broker: asking cmd/mount-broker for a mount, for root's own programs,
//! which fence's Landlock domain keeps from mounting themselves.
//!
//!     const grub = try broker.ask(.grub);   // mounted read-write
//!     defer grub.release();                 // and unmounted
//!     ... grub.path ...
//!
//! The mount lasts while the connection does: release closes it, and so
//! does the asker's exit, however it exits.

const std = @import("std");
const linux = std.os.linux;

pub const socket_path = "/run/werewolf/mount-broker.sock";

/// What can be asked for: three filesystems, and the shutdown.
pub const Word = enum { grub, esp, victim, shutdown };

/// A filesystem the broker has mounted for us, and where.
pub const Held = struct {
    fd: i32,
    path_buf: [64]u8,
    path_len: usize,

    pub fn path(h: *const Held) []const u8 {
        return h.path_buf[0..h.path_len];
    }

    /// Unmounted: the broker sees the connection close.
    pub fn release(h: Held) void {
        _ = linux.close(h.fd);
    }
};

/// What went wrong, in the broker's words, after error.Refused.
pub var refusal_buf: [128]u8 = undefined;
pub var refusal: []const u8 = "";

/// word, asked of the broker: for a filesystem, held until released.
pub fn ask(word: Word) !Held {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.NoSocket;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..socket_path.len], socket_path);
    if (linux.errno(linux.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS)
        return error.NoBroker;
    var line: [16]u8 = undefined;
    const request = std.mem.print(&line, "{s}\n", .{@tagName(word)}) catch unreachable;
    if (linux.errno(linux.sendto(
        fd,
        request.ptr,
        request.len,
        linux.MSG.NOSIGNAL,
        null,
        0,
    )) != .SUCCESS)
        return error.NoBroker;

    var h: Held = .{ .fd = fd, .path_buf = undefined, .path_len = 0 };
    var buf: [128]u8 = undefined;
    var got: usize = 0;
    while (std.mem.findScalar(u8, buf[0..got], '\n') == null) {
        if (got == buf.len) return error.BadAnswer;
        const n = linux.read(fd, buf[got..].ptr, buf.len - got);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return error.NoBroker;
        got += n;
    }
    const answer = buf[0..std.mem.findScalar(u8, buf[0..got], '\n').?];
    if (std.mem.eql(u8, answer, "ok") and word == .shutdown) return h;
    if (std.mem.startsWith(u8, answer, "ok /") and word != .shutdown and
        answer.len - 3 <= h.path_buf.len)
    {
        h.path_len = answer.len - 3;
        @memcpy(h.path_buf[0..h.path_len], answer[3..]);
        return h;
    }
    const n = @min(answer.len, refusal_buf.len);
    @memcpy(refusal_buf[0..n], answer[0..n]);
    refusal = refusal_buf[0..n];
    return error.Refused;
}
