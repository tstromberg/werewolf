//! Host permit generation and protocol integration probe for the TPM floor.
const std = @import("std");
const apk = @import("apk");
const tpm = @import("tpm");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len < 5) return error.BadArguments;
    const key = try apk.parseKey(
        gpa,
        try std.Io.Dir.cwd().readFileAlloc(io, args[2], gpa, .limited(8192)),
    );
    const serial = try std.fmt.parseUnsigned(u64, args[3], 10);
    if (std.mem.eql(u8, args[1], "permit")) {
        const policy = try tpm.approved(key, serial);
        const data = try std.mem.concat(gpa, u8, &.{ &policy, tpm.qualifier });
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = args[4], .data = data });
        return;
    }
    const port = try std.fmt.parseUnsigned(u16, args[4], 10);
    const address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const stream = try address.connect(io, .{ .mode = .stream });
    var device: tpm.Device = .{
        .io = io,
        .file = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = false } },
    };
    defer device.close();
    try device.disablePlatform();
    if (std.mem.eql(u8, args[1], "check")) {
        try device.check(key, serial);
    } else if (std.mem.eql(u8, args[1], "advance") and args.len == 6) {
        const sig = try std.Io.Dir.cwd().readFileAlloc(io, args[5], gpa, .limited(8192));
        try device.advance(key, serial, sig);
    } else return error.BadArguments;
    try std.Io.File.stdout().writeStreamingAll(
        io,
        try gpa.print("floor {d}\n", .{try device.floor(key)}),
    );
}
