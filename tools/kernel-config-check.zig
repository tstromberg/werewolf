//! kernel-config-check fails the build if Alpine's kernel config has changed
//! so that it reopens a bug exploited in the wild. The rules are
//! lib/image.zig's, which howl checks in-process. See README.md.

const std = @import("std");
const Io = std.Io;
const image = @import("image");

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 2) {
        std.log.err("usage: kernel-config-check CONFIG", .{});
        std.process.exit(2);
    }
    const text = try Io.Dir.cwd().readFileAlloc(io, args[1], gpa, .limited(4 << 20));
    const misses = try image.configMisses(gpa, text);
    for (misses) |m| std.debug.print("kernel-config-check: {f}\n", .{m});
    if (misses.len > 0) std.process.exit(1);
}
