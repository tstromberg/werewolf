//! Relay one guest TLS connection to its host-private publisher socket.
const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;

pub fn command(io: Io, gpa: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 1) return error.BadPermitBridge;
    const path = args[0];
    const uid = if (@import("builtin").os.tag == .linux) std.os.linux.getuid() else std.c.getuid();
    const prefix = try gpa.print("/tmp/ww-permit-{d}-", .{uid});
    if (!std.mem.startsWith(u8, path, prefix) or
        !std.mem.eql(u8, std.fs.path.basename(path), "service.sock"))
        return error.BadPermitBridge;
    const parent = std.fs.path.dirname(path) orelse return error.BadPermitBridge;
    const digest = parent[prefix.len..];
    if (digest.len != 32) return error.BadPermitBridge;
    for (digest) |c| if (!std.ascii.isDigit(
        c,
    ) and !(c >= 'a' and c <= 'f')) return error.BadPermitBridge;
    var directory = try Dir.openDirAbsolute(io, parent, .{ .follow_symlinks = false });
    defer directory.close(io);
    const info = try directory.stat(io);
    if (info.permissions.toMode() & 0o777 != 0o700) return error.BadPermitBridge;
    // The publisher has eight request slots. Excess connections must not keep
    // a relay process or its buffers alive while waiting for admission.
    var lease: ?File = null;
    for (0..8) |n| {
        const file = try directory.createFile(io, try gpa.print("bridge-{d}.lock", .{n}), .{
            .truncate = false,
            .permissions = .fromMode(0o600),
        });
        if (try file.tryLock(io, .exclusive)) {
            lease = file;
            break;
        }
        file.close(io);
    }
    const held = lease orelse return error.PermitBridgeBusy;
    defer held.close(io);
    const address = try Io.net.UnixAddress.init(path);
    const stream = try address.connect(io);
    defer stream.close(io);
    var upload = try io.concurrent(send, .{ io, stream });
    defer upload.cancel(io);
    var buffer: [16 << 10]u8 = undefined;
    var chunks = [_][]u8{&buffer};
    var output: [16 << 10]u8 = undefined;
    var writer = File.stdout().writerStreaming(io, &output);
    while (true) {
        const count = (try stream.readWithControl(io, &chunks, &.{})).data_len;
        if (count == 0) break;
        try writer.interface.writeAll(buffer[0..count]);
        try writer.interface.flush();
    }
}

fn send(io: Io, stream: Io.net.Stream) void {
    defer stream.shutdown(io, .send) catch {};
    var buffer: [16 << 10]u8 = undefined;
    var chunks = [_][]u8{&buffer};
    var output: [16 << 10]u8 = undefined;
    var writer = stream.writer(io, &output);
    while (true) {
        const count = File.stdin().readStreaming(io, &chunks) catch return;
        if (count == 0) return;
        writer.interface.writeAll(buffer[0..count]) catch return;
        writer.interface.flush() catch return;
    }
}
