//! import builds the read-only ext4 disk `howl create --import` attaches.
//! The label is werewolf-import. The files are the directory's top level,
//! mode 0644, so the service can read them and nothing in the image is
//! executed. See docs/design/data-import.md.

const std = @import("std");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Why = howl.Why;

pub const label = "werewolf-import";
const image_name = "import.img";

/// write builds dir/import.img from src, a directory of files or one file.
pub fn write(io: Io, gpa: Allocator, src: []const u8, dir: []const u8, why: *Why) !void {
    const out = try gpa.print("{s}/{s}", .{ dir, image_name });
    const stage = try gpa.print("{s}/import.d", .{dir});
    defer Dir.cwd().deleteTree(io, stage) catch {};
    const n = try stageFiles(io, gpa, src, stage, why);
    const bin = findMke2fs(io, gpa) orelse
        return why.refuse("no mke2fs; on macOS, brew install e2fsprogs", .{});
    Dir.cwd().deleteFile(io, out) catch {};
    // 16 MiB holds the filesystem's own tables. The rest is the files.
    // mke2fs will not create a file that has no size.
    const blocks = try gpa.print("{d}", .{@max(
        @as(u64, 4096),
        (try stagedBytes(io, stage) + (16 << 20) + 4095) / 4096,
    )});
    // No orphan_file: ext4 otherwise reads 512 blocks at every mount.
    try howl.run(io, why, &.{
        bin,    "-q", "-F", "-t",           "ext4", "-b",             "4096", "-L",  label,
        "-m",   "0",  "-O", "^orphan_file", "-E",   "root_owner=0:0", "-d",   stage, out,
        blocks,
    });
    howl.say(io, "import: {d} {s} on {s}", .{ n, if (n == 1) "file" else "files", out });
}

/// existing returns dir/import.img when a previous create left one.
pub fn existing(io: Io, gpa: Allocator, dir: []const u8) !?[]const u8 {
    const path = try gpa.print("{s}/{s}", .{ dir, image_name });
    Dir.cwd().access(io, path, .{}) catch return null;
    return path;
}

fn stageFiles(io: Io, gpa: Allocator, src: []const u8, stage: []const u8, why: *Why) !usize {
    const st = Dir.cwd().statFile(io, src, .{ .follow_symlinks = false }) catch |err|
        return why.refuse("--import {s}: {s}", .{ src, @errorName(err) });
    Dir.cwd().deleteTree(io, stage) catch {};
    try Dir.cwd().createDirPath(io, stage);
    switch (st.kind) {
        .sym_link => return why.refuse("--import {s}: a symlink", .{src}),
        .file => {
            if (st.permissions.toMode() & 0o6000 != 0)
                return why.refuse("--import {s}: setuid or setgid", .{src});
            const base = std.fs.path.basename(src);
            if (!want(base)) return why.refuse("--import {s}: no files", .{src});
            try copyFile(io, src, try gpa.print("{s}/{s}", .{ stage, base }));
            return 1;
        },
        .directory => {},
        else => return why.refuse("--import {s}: not a file or directory", .{src}),
    }
    var from = Dir.cwd().openDir(io, src, .{ .iterate = true }) catch |err|
        return why.refuse("--import {s}: {s}", .{ src, @errorName(err) });
    defer from.close(io);
    var n: usize = 0;
    var it = from.iterate();
    while (try it.next(io)) |e| {
        if (!want(e.name)) continue;
        switch (e.kind) {
            .file => {
                const one = try from.statFile(io, e.name, .{ .follow_symlinks = false });
                if (one.permissions.toMode() & 0o6000 != 0)
                    return why.refuse("--import {s}: {s} is setuid or setgid", .{ src, e.name });
                try copyFile(io, try gpa.print("{s}/{s}", .{ src, e.name }), try gpa.print("{s}/{s}", .{ stage, e.name }));
                n += 1;
            },
            .sym_link => return why.refuse("--import {s}: {s} is a symlink", .{ src, e.name }),
            .directory => {},
            else => return why.refuse("--import {s}: {s} is not a file", .{ src, e.name }),
        }
    }
    if (n == 0) return why.refuse("--import {s}: no files", .{src});
    return n;
}

/// want is a name that goes on the disk. Dotfiles are a host's clutter.
/// import-failed is init's marker on the mounted directory.
fn stagedBytes(io: Io, stage: []const u8) !u64 {
    var dir = try Dir.cwd().openDir(io, stage, .{ .iterate = true });
    defer dir.close(io);
    var n: u64 = 0;
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .file) continue;
        n += (try dir.statFile(io, e.name, .{})).size;
    }
    return n;
}

fn want(name: []const u8) bool {
    if (name.len == 0 or name[0] == '.') return false;
    return !std.mem.eql(u8, name, "import-failed");
}

fn copyFile(io: Io, from: []const u8, to: []const u8) !void {
    var in = try Dir.cwd().openFile(io, from, .{ .follow_symlinks = false });
    defer in.close(io);
    var out = try Dir.cwd().createFile(io, to, .{ .permissions = .fromMode(0o644) });
    defer out.close(io);
    var buf: [1 << 16]u8 = undefined;
    while (true) {
        const n = in.readStreaming(io, &.{&buf}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        try out.writeStreamingAll(io, buf[0..n]);
    }
}

fn findMke2fs(io: Io, gpa: Allocator) ?[]const u8 {
    const fixed = [_][]const u8{
        "/opt/homebrew/opt/e2fsprogs/sbin/mke2fs",
        "/usr/local/opt/e2fsprogs/sbin/mke2fs",
        "/usr/sbin/mke2fs",
        "/sbin/mke2fs",
    };
    for (fixed) |p| {
        if (Dir.cwd().access(io, p, .{ .execute = true })) |_| return p else |_| {}
    }
    var path = std.mem.tokenizeScalar(u8, howl.environ.get("PATH") orelse "", ':');
    while (path.next()) |d| {
        const p = gpa.print("{s}/mke2fs", .{d}) catch return null;
        if (Dir.cwd().access(io, p, .{ .execute = true })) |_| return p else |_| {}
    }
    return null;
}

const testing = std.testing;

test "import image is ext4 labelled werewolf-import" {
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    if (findMke2fs(io, gpa) == null) return;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "shop.sql", .data = "select 1;\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = ".DS_Store", .data = "x" });
    const src = std.fs.path.dirname(try tmp.dir.realPathFileAlloc(io, "shop.sql", gpa)).?;
    var why: Why = .{};
    const parent = try gpa.print("{s}/out", .{src});
    try Dir.cwd().createDirPath(io, parent);
    try write(io, gpa, src, parent, &why);
    var f = try Dir.cwd().openFile(io, try gpa.print("{s}/import.img", .{parent}), .{});
    defer f.close(io);
    var head: [2048]u8 = undefined;
    var got: usize = 0;
    while (got < head.len) {
        const n = f.readStreaming(io, &.{head[got..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        got += n;
    }
    try testing.expect(got >= 1160);
    try testing.expectEqual(@as(u16, 0xEF53), std.mem.readInt(u16, head[1080..1082], .little));
    try testing.expectEqualStrings(label, std.mem.sliceTo(head[1144..1160], 0));
}

test "import refuses a symlink" {
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "shop.sql", .data = "select 1;\n" });
    try tmp.dir.symLink(io, "shop.sql", "link.sql", .{});
    const src = std.fs.path.dirname(try tmp.dir.realPathFileAlloc(io, "shop.sql", gpa)).?;
    var why: Why = .{};
    try testing.expectError(error.Refused, write(io, gpa, src, src, &why));
}
