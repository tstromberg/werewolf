const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;

pub fn main(init: std.process.Init) void {
    media(init.io) catch |err| {
        std.debug.print("plex-media: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn media(io: Io) !void {
    const target = "/data/svc/plex-media";
    const ready = "/run/svc/plex-media/ready";
    Dir.cwd().deleteFile(io, ready) catch |err| if (err != error.FileNotFound) return err;
    try Dir.cwd().createDirPath(io, target);
    try Dir.cwd().setFilePermissions(io, target, .fromMode(0o755), .{});
    var mark = try Dir.cwd().createFile(
        io,
        ready,
        .{ .exclusive = true, .permissions = .fromMode(0o644) },
    );
    defer mark.close(io);
    try mark.writeStreamingAll(io, "ready\n");
    try mark.setPermissions(io, .fromMode(0o644));
    // Stable supervision and restart checks without a shell or network.
    while (true) {
        const wait: linux.timespec = .{ .sec = 3600, .nsec = 0 };
        _ = linux.nanosleep(&wait, null);
    }
}
