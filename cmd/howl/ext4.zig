//! Host tool discovery for private transfer volumes.
const std = @import("std");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub fn findMke2fs(io: Io, gpa: Allocator) ?[]const u8 {
    const fixed = [_][]const u8{
        "/opt/homebrew/opt/e2fsprogs/sbin/mke2fs",
        "/usr/local/opt/e2fsprogs/sbin/mke2fs",
        "/usr/local/sbin/mke2fs",
        "/usr/sbin/mke2fs",
        "/sbin/mke2fs",
    };
    for (fixed) |p| {
        if (Dir.cwd().access(io, p, .{ .execute = true })) |_| return p else |_| {}
    }
    var search = std.mem.tokenizeScalar(u8, howl.environ.get("PATH") orelse "", ':');
    while (search.next()) |d| {
        const p = gpa.print("{s}/mke2fs", .{d}) catch return null;
        if (Dir.cwd().access(io, p, .{ .execute = true })) |_| return p else |_| {}
    }
    return null;
}
