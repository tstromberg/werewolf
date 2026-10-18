//! Optional, host-private virtio serial operator channel. No network listener,
//! shell, path selection, credential, or additional broker authority.
const std = @import("std");
const linux = std.os.linux;
const control = @import("control.zig");
pub const name = "werewolf.owner";
pub const limit = 17 + control.limit;
pub const Command = enum { status, pause, @"resume", check, outcome, @"try" };
pub const Request = struct { id: []const u8, command: Command, declaration: ?[]const u8 };

pub fn parse(raw: []const u8) !Request {
    if (raw.len < 18 or raw.len > limit or raw[16] != ' ') return error.BadOwnerRequest;
    for (raw[0..16]) |c| if (!(c >= '0' and c <= '9') and !(c >= 'a' and c <= 'f'))
        return error.BadOwnerRequest;
    const word = raw[17..];
    for ([_]Command{ .status, .pause, .@"resume" }) |cmd| {
        if (std.mem.eql(u8, word, @tagName(cmd)))
            return .{ .id = raw[0..16], .command = cmd, .declaration = null };
    }
    const operation = control.parse(word) catch return error.BadOwnerRequest;
    return .{ .id = raw[0..16], .command = std.meta.stringToEnum(Command, @tagName(operation.command)).?, .declaration = operation.declaration };
}

pub const Channel = struct {
    fd: i32 = -1,
    buffer: [limit]u8 = undefined,
    used: usize = 0,
    discard: bool = false,

    /// The broker opens the named device outside fence. Only its existing
    /// updater role can receive the descriptor; /dev permissions stay closed.
    pub fn open() !Channel {
        return .{ .fd = (try @import("broker").ownerChannel()) orelse -1 };
    }

    /// Consume at most one bounded line per pass; oversized frames are discarded
    /// through their newline, never interpreted as a suffix command.
    pub fn receive(self: *Channel) ?Request {
        if (self.fd < 0) return null;
        for (0..4096) |_| {
            var byte: [1]u8 = undefined;
            const n = linux.read(self.fd, &byte, 1);
            if (linux.errno(n) != .SUCCESS or n == 0) return null;
            if (byte[0] == '\n') {
                const length = self.used;
                self.used = 0;
                if (self.discard) {
                    self.discard = false;
                    return null;
                }
                return parse(self.buffer[0..length]) catch null;
            }
            if (self.discard) continue;
            if (self.used == self.buffer.len) {
                self.discard = true;
                continue;
            }
            self.buffer[self.used] = byte[0];
            self.used += 1;
        }
        return null;
    }

    pub fn send(self: *Channel, data: []const u8) void {
        if (self.fd < 0 or data.len > 64 << 10) return;
        var offset: usize = 0;
        for (0..20) |_| {
            if (offset == data.len) return;
            var item: linux.pollfd = .{ .fd = self.fd, .events = linux.POLL.OUT, .revents = 0 };
            if (linux.errno(linux.poll(@ptrCast(&item), 1, 100)) != .SUCCESS or
                item.revents & linux.POLL.OUT == 0) return;
            const n = linux.write(self.fd, data[offset..].ptr, data.len - offset);
            if (linux.errno(n) != .SUCCESS or n == 0) return;
            offset += n;
        }
    }
};

test "owner requests are correlated, bounded fixed operations without paths or shell" {
    const t = std.testing;
    const id = "0123456789abcdef ";
    try t.expectEqual(Command.status, (try parse(id ++ "status")).command);
    try t.expectEqual(Command.pause, (try parse(id ++ "pause")).command);
    try t.expectEqual(Command.check, (try parse(id ++ "check")).command);
    try t.expectEqual(Command.@"try", (try parse(id ++ "try")).command);
    const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try t.expectEqualStrings(hash, (try parse(id ++ "try " ++ hash)).declaration.?);
    for ([_][]const u8{ "status", id ++ "status extra", id ++ "check\ntry", id ++ "sh", id ++ "try /data/file", id ++ "try " ++ hash ++ "x", "G123456789abcdef status" }) |bad|
        try t.expectError(error.BadOwnerRequest, parse(bad));
}
