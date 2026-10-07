//! reboot, poweroff: stop the machine cleanly, then restart it or turn it
//! off. One program under two names, as OpenBSD's reboot and halt are.
//!
//! It asks runit, PID 1, to stop, through runit-init (6 to restart, 0 to
//! turn off). runit runs stage 3 (/etc/runit/3), which stops the services and
//! puts /data down, then restarts or powers off.

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const level = (if (args.len == 1) levelFor(std.fs.path.basename(args[0])) else null) orelse {
        std.debug.print("usage: reboot | poweroff\n", .{});
        std.process.exit(2);
    };
    const err = std.process.replace(init.io, .{ .argv = &.{ "/usr/bin/runit-init", level } });
    std.debug.print("{s}: runit-init: {s}\n", .{ args[0], @errorName(err) });
    std.process.exit(1);
}

/// runit-init's level for the name this was run as: 6 to restart, 0 to
/// turn off, and none for any other name, so a stray link (halt, say)
/// does nothing.
fn levelFor(name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "reboot")) return "6";
    if (std.mem.eql(u8, name, "poweroff")) return "0";
    return null;
}

test levelFor {
    try std.testing.expectEqualStrings("0", levelFor("poweroff").?);
    try std.testing.expectEqualStrings("6", levelFor("reboot").?);
    try std.testing.expectEqual(null, levelFor("halt"));
    try std.testing.expectEqual(null, levelFor("reboot2"));
}
