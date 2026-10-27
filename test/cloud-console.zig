//! cloud-console copies a console from standard input to standard output
//! with the kernel's records dropped, so the userspace records they
//! interrupted read whole again (host.qemu.clean). test/cloud and
//! test/check-firecracker read consoles through it.

const std = @import("std");
const host = @import("host");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    var buf: [64 << 10]u8 = undefined;
    var in = Io.File.stdin().readerStreaming(io, &buf);
    const console = try in.interface.allocRemaining(gpa, .unlimited);
    try Io.File.stdout().writeStreamingAll(io, try host.qemu.clean(gpa, console));
}
