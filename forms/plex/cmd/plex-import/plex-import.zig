const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const mem = std.mem;
const Io = std.Io;
const Dir = Io.Dir;

pub fn main(init: std.process.Init) void {
    media(init.io, init.arena.allocator()) catch |err| {
        std.debug.print("plex-import: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn media(io: Io, a: mem.Allocator) !void {
    const target = "/data/svc/plex-media";
    try Dir.cwd().createDirPath(io, target);
    try Dir.cwd().setFilePermissions(io, target, .fromMode(0o755), .{});
    var output = try Dir.cwd().openDir(io, target, .{});
    defer output.close(io);
    var source = Dir.cwd().openDir(io, "/run/werewolf/import", .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (source) |*dir| {
        defer dir.close(io);
        var walk = try dir.walk(a);
        defer walk.deinit();
        while (try walk.next(io)) |entry| switch (entry.kind) {
            .directory => {
                try output.createDirPath(io, entry.path);
                try output.setFilePermissions(io, entry.path, .fromMode(0o755), .{});
            },
            .file => {
                if (output.access(io, entry.path, .{})) continue else |_| {}
                try dir.copyFile(entry.path, output, entry.path, io, .{});
                try output.setFilePermissions(io, entry.path, .fromMode(0o644), .{});
            },
            else => return error.ImportLinksForbidden,
        };
    }
    // Stable supervision and restart checks without a shell or network.
    while (true) {
        const wait: linux.timespec = .{ .sec = 3600, .nsec = 0 };
        _ = linux.nanosleep(&wait, null);
    }
}
