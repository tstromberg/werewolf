//! Fixed CPU inference checks under a leashed non-root identity.
const std = @import("std");
const driver = @import("test-driver");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(io, gpa, args[3]);
    const cases = [_]struct { name: []const u8, argument: []const u8 }{
        .{ .name = "python-version", .argument = "version" },
        .{ .name = "cpu-provider", .argument = "providers" },
        .{ .name = "inference", .argument = "inference" },
        .{ .name = "invalid-shape", .argument = "shape" },
        .{ .name = "unknown-input", .argument = "input" },
    };
    for (cases) |case| {
        const result = try std.process.run(gpa, io, .{
            .argv = &.{ "/usr/bin/python3.15", "-B", "/usr/lib/onnx/check.py", case.argument },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(16384),
            .timeout = driver.deadline(io, 30),
        });
        try std.Io.File.stderr().writeStreamingAll(io, result.stderr);
        const expected = try gpa.print("onnx-{s}: ok", .{case.argument});
        try ctx.result(
            io,
            args[1],
            case.name,
            result.term == .exited and result.term.exited == 0 and
                std.mem.indexOf(u8, result.stdout, expected) != null,
        );
    }
}
