//! Reuse the native DNS source-port ownership attack.
const std = @import("std");
const driver = @import("test-driver");

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "squatter")) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    driver.udp.squatter(init.io, a, "adguard-home") catch |err| {
        std.debug.print("test-udp: adguard-home: {s}\n", .{@errorName(err)});
        return ctx.result(init.io, args[1], "agh-squatter", false);
    };
    try ctx.result(init.io, args[1], "agh-squatter", true);
}
