//! tpm-floor drives lib/tpm.zig's release floor against a TPM simulator,
//! as stage0 (boot) and the mount broker (raise) drive /dev/tpmrm0.
//!
//!     tpm-floor boot ENDPOINT CHANNEL INDEX    enroll or verify; print the floor
//!     tpm-floor raise ENDPOINT CHANNEL INDEX   raise the floor to INDEX
//!     tpm-floor read ENDPOINT CHANNEL          print the counter's state and value
//!     tpm-floor handle CHANNEL                 print the counter's NV handle
//!
//! ENDPOINT is a swtpm server port on 127.0.0.1, or unix:PATH. CHANNEL is
//! 64 hex digits.
const std = @import("std");
const tpm = @import("tpm");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    var out = std.Io.File.stdout().writerStreaming(io, &.{});
    const w = &out.interface;
    if (args.len == 3 and std.mem.eql(u8, args[1], "handle")) {
        return w.print("0x{x:0>8}\n", .{tpm.handle(try channel(args[2]))});
    }
    if (args.len < 4) return error.BadArguments;
    const id = try channel(args[3]);
    var device = try connect(io, args[2]);
    defer device.close();
    if (std.mem.eql(u8, args[1], "read") and args.len == 4) {
        const h = tpm.handle(id);
        const state = try device.counter(h);
        const value = if (state == .written) try device.read(h) else 0;
        return w.print("{t} {d}\n", .{ state, value });
    }
    if (args.len != 5) return error.BadArguments;
    const index = try std.fmt.parseUnsigned(u64, args[4], 10);
    if (std.mem.eql(u8, args[1], "boot")) {
        const floor = try device.boot(io, id, index);
        try w.print("floor {d}\n", .{floor});
        if (index < floor) return error.RollbackRefused;
    } else if (std.mem.eql(u8, args[1], "raise")) {
        try w.print("floor {d}\n", .{try device.raise(tpm.handle(id), index)});
    } else return error.BadArguments;
}

fn channel(hex: []const u8) ![32]u8 {
    var id: [32]u8 = undefined;
    if (hex.len != 64) return error.BadChannel;
    _ = try std.fmt.hexToBytes(&id, hex);
    return id;
}

fn connect(io: std.Io, endpoint: []const u8) !tpm.Device {
    const stream = if (std.mem.startsWith(u8, endpoint, "unix:")) blk: {
        const address = try std.Io.net.UnixAddress.init(endpoint[5..]);
        break :blk try address.connect(io);
    } else blk: {
        const address = try std.Io.net.IpAddress.parseIp4(
            "127.0.0.1",
            try std.fmt.parseUnsigned(u16, endpoint, 10),
        );
        break :blk try address.connect(io, .{ .mode = .stream });
    };
    return .{ .fd = stream.socket.handle };
}
