//! --app DIR: an application's files, laid over a form's image where the
//! form keeps its application. The form says where, in etc/werewolf/app
//! (the app forms /usr/lib/app, nginx its html root), and its service file
//! how to run it and which settings it takes; DIR is what to run. DIR is
//! built by its own toolchain (go build, dotnet publish, mvn package), and
//! werewolf only copies it: regular files and directories, an executable
//! bit kept, nothing setuid, no links. The copy is staged apart, laid over
//! the image by make (APP), and verified and read-only there with the rest
//! of the root. Its digest, over every path, executable bit and byte, is
//! the application's name: the same DIR gives the same digest, and so the
//! same image.

const std = @import("std");
const ww = @import("werewolf.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Where the chain's last form keeps its application, or null.
pub fn place(io: Io, gpa: Allocator, forms: Dir, names: []const []const u8) !?[]const u8 {
    var found: ?[]const u8 = null;
    for (names) |name| {
        const text = forms.readFileAlloc(
            io,
            try gpa.print("{s}/etc/werewolf/app", .{name}),
            gpa,
            .limited(4096),
        ) catch
            continue;
        const p = std.mem.trim(u8, text, " \n");
        if (p.len < 2 or p[0] != '/' or std.mem.find(u8, p, "..") != null) return error.BadAppPlace;
        found = p;
    }
    return found;
}

const File = struct { path: []const u8, exec: bool };

pub const Staged = struct { files: usize, bytes: u64, digest: [64]u8 };

/// Copy src to root/place, refusing what an application has no need of,
/// and the digest of what was copied.
pub fn stage(
    io: Io,
    gpa: Allocator,
    src: []const u8,
    root: []const u8,
    at: []const u8,
    why: *ww.Why,
) !Staged {
    var from = Dir.cwd().openDir(io, src, .{ .iterate = true }) catch |err|
        return why.refuse("--app {s}: {s}", .{ src, @errorName(err) });
    defer from.close(io);

    var files: std.ArrayList(File) = .empty;
    var dirs: std.ArrayList([]const u8) = .empty;
    var walker = try from.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |e| {
        if (std.mem.eql(u8, e.basename, ".DS_Store") or
            std.mem.startsWith(u8, e.basename, "._")) continue;
        const path = try gpa.dupe(u8, e.path);
        switch (e.kind) {
            .directory => try dirs.append(gpa, path),
            .file => {
                const st = try e.dir.statFile(io, e.basename, .{ .follow_symlinks = false });
                const mode = st.permissions.toMode();
                if (mode & 0o6000 != 0)
                    return why.refuse("--app {s}: {s} is setuid or setgid", .{ src, path });
                try files.append(gpa, .{ .path = path, .exec = mode & 0o100 != 0 });
            },
            else => return why.refuse(
                "--app {s}: {s} is not a regular file or directory; an application is files",
                .{ src, path },
            ),
        }
    }
    if (files.items.len == 0) return why.refuse("--app {s}: no files", .{src});
    std.mem.sortUnstable(File, files.items, {}, struct {
        fn lt(_: void, a: File, b: File) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lt);

    Dir.cwd().deleteTree(io, root) catch {};
    const base = try std.fs.path.join(gpa, &.{ root, at[1..] });
    try Dir.cwd().createDirPath(io, base);
    var into = try Dir.cwd().openDir(io, base, .{});
    defer into.close(io);
    for (dirs.items) |d| try into.createDirPath(io, d);

    var h: Sha256 = .init(.{});
    var bytes: u64 = 0;
    var buf: [1 << 16]u8 = undefined;
    for (files.items) |f| {
        h.update(f.path);
        h.update(if (f.exec) "\x00x\x00" else "\x00-\x00");
        var in = try from.openFile(io, f.path, .{});
        defer in.close(io);
        var out = try into.createFile(
            io,
            f.path,
            .{ .permissions = .fromMode(if (f.exec) 0o755 else 0o644) },
        );
        defer out.close(io);
        while (true) {
            const n = in.readStreaming(io, &.{&buf}) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
            h.update(buf[0..n]);
            try out.writeStreamingAll(io, buf[0..n]);
            bytes += n;
        }
        h.update("\x00");
    }
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return .{
        .files = files.items.len,
        .bytes = bytes,
        .digest = std.fmt.bytesToHex(digest, .lower),
    };
}

const testing = std.testing;

test stage {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "src/lib");
    try tmp.dir.writeFile(io, .{ .sub_path = "src/main.py", .data = "print('hi')\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "src/lib/util.py", .data = "x = 1\n" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const src = try std.fs.path.join(gpa, &.{ root, "src" });
    var why: ww.Why = .{};

    const a = try stage(
        io,
        gpa,
        src,
        try std.fs.path.join(gpa, &.{ root, "stage" }),
        "/usr/lib/app",
        &why,
    );
    try testing.expectEqual(@as(usize, 2), a.files);
    const copied = try tmp.dir.readFileAlloc(
        io,
        "stage/usr/lib/app/lib/util.py",
        gpa,
        .limited(64),
    );
    try testing.expectEqualStrings("x = 1\n", copied);
    // The same files, the same digest; a byte changed, another.
    const b = try stage(
        io,
        gpa,
        src,
        try std.fs.path.join(gpa, &.{ root, "stage" }),
        "/usr/lib/app",
        &why,
    );
    try testing.expectEqualStrings(&a.digest, &b.digest);
    try tmp.dir.writeFile(io, .{ .sub_path = "src/main.py", .data = "print('hi!')\n" });
    const c = try stage(
        io,
        gpa,
        src,
        try std.fs.path.join(gpa, &.{ root, "stage" }),
        "/usr/lib/app",
        &why,
    );
    try testing.expect(!std.mem.eql(u8, &a.digest, &c.digest));

    try tmp.dir.symLink(io, "/etc/passwd", "src/link", .{});
    try testing.expectError(
        error.Refused,
        stage(io, gpa, src, try std.fs.path.join(gpa, &.{ root, "stage" }), "/usr/lib/app", &why),
    );
}
