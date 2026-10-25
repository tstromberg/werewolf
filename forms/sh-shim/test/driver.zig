//! Run sh-shim with standard descriptors closed, which a YAML exec cannot:
//! its /dev/null redirect must take the descriptor the caller left closed.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const StdIo = std.process.SpawnOptions.StdIo;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "fds")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    // echo fails writing to a closed stdout: only the redirect saves the others.
    const passed = !try succeeds(io, "echo discard", .ignore, .close, .ignore) and
        try succeeds(io, "head -c 1 < /dev/null", .close, .ignore, .ignore) and
        try succeeds(io, "echo discard > /dev/null", .ignore, .close, .ignore) and
        try succeeds(io, "echo discard > /dev/null 2>&1", .ignore, .close, .close);
    try ctx.result(io, args[1], "sh-shim-closed-fds", passed);
}

/// succeeds runs command through the shim with the given standard streams.
fn succeeds(io: Io, command: []const u8, in: StdIo, out: StdIo, err: StdIo) !bool {
    var child = try std.process.spawn(io, .{
        .argv = &.{ "/usr/lib/werewolf/sh-shim", "-c", command },
        .stdin = in,
        .stdout = out,
        .stderr = err,
    });
    defer child.kill(io);
    const term = try child.wait(io);
    return term == .exited and term.exited == 0;
}
