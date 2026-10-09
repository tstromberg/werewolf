//! broker is the client for cmd/mount-broker. fence's Landlock domain stops
//! root's programs from mounting, so they ask the broker. See lib/README.md.

const std = @import("std");
const linux = std.os.linux;

pub const socket_path = "/run/werewolf/mount-broker.sock";

/// mnt_dir is where the broker mounts what it is asked for.
pub const mnt_dir = "/run/werewolf/mnt";

/// Word is a request: one of three filesystems, or shutdown.
pub const Word = enum {
    grub,
    esp,
    victim,
    shutdown,

    /// place returns where w's filesystem is mounted. It is fixed so the
    /// asker never takes a path from the answer: root inside fence's domain
    /// could put its own listener at the socket in /run.
    pub fn place(w: Word) [:0]const u8 {
        return switch (w) {
            .grub => mnt_dir ++ "/grub",
            .esp => mnt_dir ++ "/esp",
            .victim => mnt_dir ++ "/victim",
            .shutdown => unreachable,
        };
    }
};

/// Held is a filesystem the broker has mounted for us. It stays mounted
/// while fd, the connection, is open.
pub const Held = struct {
    fd: i32,
    word: Word,

    pub fn path(h: *const Held) []const u8 {
        return h.word.place();
    }

    /// release closes the connection, and the broker unmounts.
    pub fn release(h: Held) void {
        _ = linux.close(h.fd);
    }
};

/// refusal holds the broker's answer after error.Refused.
pub var refusal_buf: [128]u8 = undefined;
pub var refusal: []const u8 = "";

/// ask sends word to the broker. For a filesystem, the mount lasts until
/// release or until this process exits.
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
    const sent = linux.sendto(fd, request.ptr, request.len, linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(sent) != .SUCCESS) return error.NoBroker;

    var buf: [128]u8 = undefined;
    var got: usize = 0;
    const answer = while (true) {
        if (std.mem.findScalar(u8, buf[0..got], '\n')) |end| break buf[0..end];
        if (got == buf.len) return error.BadAnswer;
        const n = linux.read(fd, buf[got..].ptr, buf.len - got);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS or n == 0) return error.NoBroker;
        got += n;
    };
    const h: Held = .{ .fd = fd, .word = word };
    // The answer must name the word's fixed place. Otherwise a fake
    // listener at the socket could send the asker's writes anywhere.
    if (word == .shutdown) {
        if (std.mem.eql(u8, answer, "ok")) return h;
    } else if (std.mem.startsWith(u8, answer, "ok ") and
        std.mem.eql(u8, answer[3..], word.place()))
    {
        return h;
    }
    const n = @min(answer.len, refusal_buf.len);
    @memcpy(refusal_buf[0..n], answer[0..n]);
    refusal = refusal_buf[0..n];
    return error.Refused;
}
