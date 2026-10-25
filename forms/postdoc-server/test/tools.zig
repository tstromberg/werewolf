//! Verify that the real analysis tools can execute with MDWE inherited.
const std = @import("std");
const driver = @import("test-driver");

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "tools")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const linux = std.os.linux;
    const mdwe = linux.prctl(66, 0, 0, 0, 0); // PR_GET_MDWE
    try ctx.result(
        io,
        args[1],
        "postdoc-tools-mdwe",
        linux.errno(mdwe) == .SUCCESS and mdwe & 1 != 0,
    );
    for ([_][2][]const u8{
        .{ "rizin", "-v" },
        .{ "innoextract", "--version" },
        .{ "upx", "--version" },
    }) |tool| {
        const path = try a.print("/usr/bin/{s}", .{tool[0]});
        const result = try driver.within(io, 30, std.process.run, .{
            a, io, .{ .argv = &.{ path, tool[1] }, .environ_map = init.environ_map },
        });
        try ctx.result(
            io,
            args[1],
            try a.print("postdoc-{s}-executable", .{tool[0]}),
            result.term.success() and result.stdout.len > 0,
        );
    }
}
