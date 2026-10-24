const std = @import("std");
const linux = std.os.linux;
const mem = std.mem;
const Io = std.Io;
const Dir = Io.Dir;
const data = @import("import-data");

pub fn main(init: std.process.Init) void {
    media(init.io, init.arena.allocator()) catch |err| {
        std.debug.print("plex-import: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn media(io: Io, a: mem.Allocator) !void {
    const target = "/data/svc/plex-media";
    const ready = "/run/svc/plex-media/ready";
    Dir.cwd().deleteFile(io, ready) catch |err| if (err != error.FileNotFound) return err;
    try Dir.cwd().createDirPath(io, target);
    try Dir.cwd().setFilePermissions(io, target, .fromMode(0o755), .{});
    var output = try Dir.cwd().openDir(io, target, .{ .iterate = true, .follow_symlinks = false });
    defer output.close(io);
    var source = Dir.cwd().openDir(
        io,
        "/run/werewolf/import",
        .{ .iterate = true },
    ) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (source) |*dir| {
        defer dir.close(io);
        // An absent disk leaves an empty mountpoint. A declared snapshot or
        // an init failure marker is handled by the shared data importer.
        var it = dir.iterate();
        if (try it.next(io) != null) try data.apply(io, a, dir.*, output);
    }
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
