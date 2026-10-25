//! webui-key makes Open WebUI's signing key before its first start: 32
//! random bytes as URL-safe base64, as Python's secrets.token_urlsafe(32)
//! makes them, in .webui_secret_key in the data directory it starts in,
//! 0600. A key already there is kept. Upstream would make one with random.
//!
//!     webui-key
//!
//! leash runs it as open-webui (forms/open-webui/form.yaml).

const std = @import("std");
const Io = std.Io;
const Base64 = std.base64.url_safe_no_pad.Encoder;

const name = ".webui_secret_key";

pub fn main(init: std.process.Init) void {
    const io = init.io;
    make(io, Io.Dir.cwd()) catch |err| {
        var buf: [128]u8 = undefined;
        var out = Io.File.stderr().writerStreaming(io, &buf);
        out.interface.print("webui-key: {s}: {s}\n", .{ name, @errorName(err) }) catch {};
        out.interface.flush() catch {};
        std.process.exit(1);
    };
}

fn make(io: Io, dir: Io.Dir) !void {
    var key: [32]u8 = undefined;
    try io.randomSecure(&key);
    var text: [Base64.calcSize(key.len)]u8 = undefined;
    _ = Base64.encode(&text, &key);
    const file = dir.createFile(
        io,
        name,
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    ) catch |err|
        switch (err) {
            error.PathAlreadyExists => {
                // A link to nothing, or a directory, is no key: refuse to start without one.
                if ((try dir.statFile(io, name, .{})).kind != .file) return error.NotAFile;
                return;
            },
            else => return err,
        };
    defer file.close(io);
    try file.writeStreamingAll(io, &text);
}

test "the first start makes a private key, later ones keep it, and a non-file is refused" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try make(io, tmp.dir);
    var buf: [64]u8 = undefined;
    const first = try tmp.dir.readFile(io, name, &buf);
    try std.testing.expectEqual(43, first.len);
    for (first) |c| try std.testing.expect(std.ascii.isAlphanumeric(c) or c == '-' or c == '_');
    try std.testing.expectEqual(
        0o600,
        (try tmp.dir.statFile(io, name, .{})).permissions.toMode() & 0o777,
    );
    const kept = try std.testing.allocator.dupe(u8, first);
    defer std.testing.allocator.free(kept);
    try make(io, tmp.dir);
    try std.testing.expectEqualStrings(kept, try tmp.dir.readFile(io, name, &buf));
    try tmp.dir.deleteFile(io, name);
    try tmp.dir.createDir(io, name, .default_dir);
    try std.testing.expectError(error.NotAFile, make(io, tmp.dir));
}
