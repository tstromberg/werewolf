//! verity IMAGE PARAMS: appends IMAGE's dm-verity hash tree to it, and
//! writes the line stage0 opens it with to PARAMS (lib/verity.zig). The
//! build runs it on each root.erofs, on the build machine, which needs no
//! veritysetup and gives the same tree on macOS as on Linux.

const std = @import("std");
const Io = std.Io;
const verity = @import("verity");

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 3) {
        std.log.err("usage: verity IMAGE PARAMS", .{});
        std.process.exit(2);
    }
    const dir = Io.Dir.cwd();
    const image = try dir.readFileAlloc(io, args[1], gpa, .limited(4 << 30));
    const built = try verity.build(gpa, image);

    const file = try dir.openFile(io, args[1], .{ .mode = .write_only });
    defer file.close(io);
    try file.writePositionalAll(io, built.tree, image.len);

    var line: Io.Writer.Allocating = .init(gpa);
    try built.params.format(&line.writer);
    try dir.writeFile(io, .{ .sub_path = args[2], .data = line.written() });
}
