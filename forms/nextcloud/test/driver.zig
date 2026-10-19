//! Attempt a real code write as Nextcloud's account, without a setuid helper.
const std = @import("std");
const driver = @import("test-driver");
const linux = std.os.linux;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "write-refused")) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    var parent = try std.Io.Dir.cwd().openDir(init.io, "/usr/share/nextcloud", .{});
    defer parent.close(init.io);
    const fd = linux.open(
        "/usr/share/nextcloud/werewolf-test-write",
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true },
        0o600,
    );
    const why = linux.errno(fd);
    if (why == .SUCCESS) {
        _ = linux.close(@intCast(fd));
        try parent.deleteFile(init.io, "werewolf-test-write");
    }
    switch (why) {
        .ACCES, .PERM, .ROFS => {},
        else => return error.CodeWriteNotRefused,
    }
    try ctx.result(init.io, args[1], "nc-code-write-refused", true);
}
