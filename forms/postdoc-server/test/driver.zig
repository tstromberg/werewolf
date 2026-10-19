//! Require the analysis workload to finish without a seccomp denial for its UID.
const std = @import("std");
const driver = @import("test-driver");
const linux = std.os.linux;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "audit")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const uid = try driver.system.account(io, a, "postdoc");
    const size = linux.syscall3(.syslog, 10, 0, 0);
    if (linux.errno(size) != .SUCCESS or size > 8 << 20) return error.KernelLogSize;
    const buffer = try a.alloc(u8, size);
    const length = linux.syscall3(.syslog, 3, @intFromPtr(buffer.ptr), buffer.len);
    if (linux.errno(length) != .SUCCESS) return error.KernelLogRead;
    try ctx.result(io, args[1], "postdoc-pledged", try pledged(a, buffer[0..length], uid));
}

fn pledged(a: std.mem.Allocator, log: []const u8, uid: u32) !bool {
    const identity = try a.print(" uid={d} ", .{uid});
    defer a.free(identity);
    var lines = std.mem.splitScalar(u8, log, '\n');
    while (lines.next()) |line| {
        if (std.mem.find(u8, line, "type=1326") != null and
            std.mem.find(u8, line, identity) != null) return false;
    }
    return true;
}

test "seccomp denials match the complete service UID in one record" {
    const a = std.testing.allocator;
    try std.testing.expect(!try pledged(
        a,
        "audit: type=1326 uid=123 comm=\"postdoc\" syscall=1",
        123,
    ));
    try std.testing.expect(try pledged(
        a,
        "audit: type=1326 uid=1234 comm=\"postdoc\" syscall=1",
        123,
    ));
    try std.testing.expect(try pledged(a, "audit: type=1400 uid=123 comm=\"postdoc\"\n", 123));
    try std.testing.expect(try pledged(
        a,
        "audit: type=1326 uid=9 \naudit: type=1400 uid=123 ",
        123,
    ));
}
