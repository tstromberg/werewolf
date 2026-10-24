//! Data-only snapshots and crash-safe file imports. No deletion or execution.
const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const Hash = std.crypto.hash.sha2.Sha256;
pub const Mode = enum { init, sync };
pub const manifest = ".werewolf-import";
const state_name = ".werewolf-import-state";
const part_name = ".werewolf-import-part";
pub const Header = struct { version: u8 = 1, mode: Mode, id: []const u8 };
pub const Totals = struct { files: u64 = 0, bytes: u64 = 0 };

pub fn syncDir(io: Io, dir: Dir) !void {
    try (File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}

// NONBLOCK closes the stat/open race with FIFOs; NOFOLLOW closes it with links.
pub fn openRegular(io: Io, dir: Dir, name: []const u8) !File {
    const fd = try std.posix.openat(dir.handle, name, .{
        .ACCMODE = .RDONLY,
        .NONBLOCK = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    const file: File = .{ .handle = fd, .flags = .{ .nonblocking = true } };
    errdefer file.close(io);
    const st = try file.stat(io);
    if (st.kind != .file or st.permissions.toMode() & 0o6000 != 0) return error.ImportFileType;
    return file;
}

pub fn readHeader(io: Io, a: Allocator, dir: Dir) !?Header {
    const file = openRegular(io, dir, manifest) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    var buf: [1024]u8 = undefined;
    var reader = file.readerStreaming(io, &buf);
    const h = try std.json.parseFromSliceLeaky(
        Header,
        a,
        try reader.interface.allocRemaining(a, .limited(1024)),
        .{},
    );
    if (h.version != 1 or !validId(h.id)) return error.ImportManifest;
    return h;
}

pub fn validId(id: []const u8) bool {
    if (id.len != 64) return false;
    for (id) |ch| if (!std.ascii.isDigit(ch) and (ch < 'a' or ch > 'f')) return false;
    return true;
}

pub fn writeHeader(io: Io, a: Allocator, dir: Dir, name: []const u8, header: Header) !void {
    const text = try std.json.Stringify.valueAlloc(a, header, .{});
    try atomicBytes(io, dir, name, text);
}

fn atomicBytes(io: Io, dir: Dir, name: []const u8, bytes: []const u8) !void {
    // The directory is private and the name is reserved. Unlinking a stale
    // temporary file never truncates a file to which it might be hard-linked.
    dir.deleteFile(io, part_name) catch |err| if (err != error.FileNotFound) return err;
    const file = try dir.createFile(
        io,
        part_name,
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    );
    defer file.close(io);
    errdefer dir.deleteFile(io, part_name) catch {};
    try file.writeStreamingAll(io, bytes);
    try file.setPermissions(io, .fromMode(0o600));
    try file.sync(io);
    try dir.rename(part_name, dir, name, io);
    try syncDir(io, dir);
}

fn entries(io: Io, a: Allocator, dir: Dir) ![]Dir.Entry {
    var list: std.ArrayList(Dir.Entry) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (list.items.len == 100_000) return error.ImportTooManyFiles;
        try list.append(
            a,
            .{ .name = try a.dupe(u8, entry.name), .kind = entry.kind, .inode = entry.inode },
        );
    }
    mem.sort(Dir.Entry, list.items, {}, struct {
        fn less(_: void, x: Dir.Entry, y: Dir.Entry) bool {
            return mem.lessThan(u8, x.name, y.name);
        }
    }.less);
    return list.items;
}

fn unchanged(before: File.Stat, after: File.Stat) bool {
    return before.inode == after.inode and before.size == after.size and
        before.mtime.nanoseconds == after.mtime.nanoseconds and
        before.ctime.nanoseconds == after.ctime.nanoseconds;
}

pub fn fileHash(io: Io, file: File) ![32]u8 {
    const before = try file.stat(io);
    var hash = Hash.init(.{});
    var buf: [65536]u8 = undefined;
    var size: u64 = 0;
    while (true) {
        const n = try file.readPositional(io, &.{&buf}, size);
        if (n == 0) break;
        size = try std.math.add(u64, size, n);
        if (size > before.size) return error.ImportSourceChanged;
        hash.update(buf[0..n]);
    }
    if (size != before.size or
        !unchanged(before, try file.stat(io))) return error.ImportSourceChanged;
    return hash.finalResult();
}

// Copy from pinned directory handles, one component at a time. Directory
// symlinks and nonregular leaves are refused, even if exchanged during a walk.
pub fn snapshot(io: Io, a: Allocator, source: Dir, target: Dir) !Totals {
    var total: Totals = .{};
    try copyTree(io, a, source, target, null, .init, true, 0, &total);
    return total;
}

pub fn snapshotFile(io: Io, source: Dir, target: Dir, name: []const u8) !Totals {
    if (reserved(name) or name.len == 0) return error.ImportReservedName;
    const file = try openRegular(io, source, name);
    defer file.close(io);
    const size = (try file.stat(io)).size;
    try copyFile(io, file, target, target, name, .init);
    return .{ .files = 1, .bytes = size };
}

fn reserved(name: []const u8) bool {
    return mem.eql(u8, name, manifest) or mem.eql(u8, name, state_name) or
        mem.eql(u8, name, part_name) or mem.eql(u8, name, "import-failed") or
        mem.eql(u8, name, "lost+found");
}

fn copyTree(
    io: Io,
    a: Allocator,
    source: Dir,
    target: Dir,
    scratch: ?Dir,
    mode: Mode,
    staging: bool,
    depth: u16,
    total: *Totals,
) !void {
    if (depth > 128) return error.ImportTooDeep;
    const before = try source.stat(io);
    for (try entries(io, a, source)) |entry| {
        if (reserved(entry.name)) {
            if (staging) return error.ImportReservedName;
            if (depth == 0 and (mem.eql(u8, entry.name, manifest) or
                mem.eql(u8, entry.name, "lost+found"))) continue;
            return error.ImportReservedName;
        }
        total.files = try std.math.add(u64, total.files, 1);
        if (total.files > 1_000_000) return error.ImportTooManyFiles;
        const st = try source.statFile(io, entry.name, .{ .follow_symlinks = false });
        if (st.permissions.toMode() & 0o6000 != 0) return error.ImportFileType;
        switch (st.kind) {
            .directory => {
                var from = try source.openDir(
                    io,
                    entry.name,
                    .{ .iterate = true, .follow_symlinks = false },
                );
                defer from.close(io);
                const created = if (target.createDir(io, entry.name, .fromMode(0o755)))
                    true
                else |err| blk: {
                    if (err != error.PathAlreadyExists) return err;
                    break :blk false;
                };
                var to = try target.openDir(
                    io,
                    entry.name,
                    .{ .iterate = true, .follow_symlinks = false },
                );
                defer to.close(io);
                if (created) try (File{
                    .handle = to.handle,
                    .flags = .{ .nonblocking = false },
                }).setPermissions(io, .fromMode(0o755));
                try copyTree(io, a, from, to, scratch, mode, staging, depth + 1, total);
                try syncDir(io, to);
            },
            .file => {
                var from = try openRegular(io, source, entry.name);
                defer from.close(io);
                total.bytes = try std.math.add(u64, total.bytes, (try from.stat(io)).size);
                try copyFile(io, from, target, scratch orelse target, entry.name, mode);
            },
            else => return error.ImportFileType,
        }
    }
    const after = try source.stat(io);
    if (before.inode != after.inode or before.mtime.nanoseconds != after.mtime.nanoseconds or
        before.ctime.nanoseconds != after.ctime.nanoseconds) return error.ImportSourceChanged;
    try syncDir(io, target);
}

fn copyFile(io: Io, from: File, target: Dir, scratch: Dir, name: []const u8, mode: Mode) !void {
    const old = openRegular(io, target, name) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (old) |f| f.close(io);
    const before = try from.stat(io);
    scratch.deleteFile(io, part_name) catch |err| if (err != error.FileNotFound) return err;
    if (old) |f| {
        if ((try f.stat(io)).size == before.size and
            mem.eql(u8, &try fileHash(io, from), &try fileHash(io, f)))
        {
            try syncDir(io, scratch);
            return;
        }
        if (mode == .init) return error.ImportConflict;
    }
    const temp = try scratch.createFile(
        io,
        part_name,
        .{ .read = true, .exclusive = true, .permissions = .fromMode(0o644) },
    );
    defer temp.close(io);
    defer scratch.deleteFile(io, part_name) catch {};
    var buf: [65536]u8 = undefined;
    var count: u64 = 0;
    while (true) {
        const n = try from.readPositional(io, &.{&buf}, count);
        if (n == 0) break;
        count = try std.math.add(u64, count, n);
        if (count > before.size) return error.ImportSourceChanged;
        try temp.writeStreamingAll(io, buf[0..n]);
    }
    if (count != before.size or
        !unchanged(before, try from.stat(io))) return error.ImportSourceChanged;
    try temp.setPermissions(io, .fromMode(0o644));
    try temp.sync(io);
    if (mode == .init)
        try scratch.renamePreserve(part_name, target, name, io)
    else
        try scratch.rename(part_name, target, name, io);
    try syncDir(io, scratch);
    try syncDir(io, target);
}

pub fn identity(io: Io, a: Allocator, source: Dir, mode: Mode) ![64]u8 {
    var hash = Hash.init(.{});
    hash.update("werewolf-import/1\x00");
    hash.update(@tagName(mode));
    try hashTree(io, a, source, &hash, 0);
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

fn hashTree(io: Io, a: Allocator, source: Dir, hash: *Hash, depth: u16) !void {
    if (depth > 128) return error.ImportTooDeep;
    for (try entries(io, a, source)) |entry| {
        if (depth == 0 and (mem.eql(u8, entry.name, manifest) or
            mem.eql(u8, entry.name, "lost+found"))) continue;
        if (reserved(entry.name)) return error.ImportReservedName;
        var length: [8]u8 = undefined;
        mem.writeInt(u64, &length, entry.name.len, .big);
        hash.update(&length);
        hash.update(entry.name);
        const st = try source.statFile(io, entry.name, .{ .follow_symlinks = false });
        switch (st.kind) {
            .directory => {
                hash.update("D");
                var sub = try source.openDir(
                    io,
                    entry.name,
                    .{ .iterate = true, .follow_symlinks = false },
                );
                defer sub.close(io);
                try hashTree(io, a, sub, hash, depth + 1);
                hash.update("E");
            },
            .file => {
                hash.update("F");
                const file = try openRegular(io, source, entry.name);
                defer file.close(io);
                hash.update(&try fileHash(io, file));
            },
            else => return error.ImportFileType,
        }
    }
}

/// The private pending receipt permits only the same interrupted import to
/// resume. Completion is durable after every installed file and directory.
pub fn apply(io: Io, a: Allocator, source: Dir, target: Dir) !void {
    if (source.access(io, "import-failed", .{}))
        return error.ImportUnavailable
    else |err| if (err != error.FileNotFound)
        return err;
    const header = (try readHeader(io, a, source)) orelse return error.ImportManifest;
    const actual = try identity(io, a, source, header.mode);
    if (!mem.eql(u8, &actual, header.id)) return error.ImportChecksum;
    target.createDir(
        io,
        state_name,
        .fromMode(0o700),
    ) catch |err| if (err != error.PathAlreadyExists) return err;
    var state = try target.openDir(io, state_name, .{ .iterate = true, .follow_symlinks = false });
    defer state.close(io);
    const lock_fd = try std.posix.openat(
        state.handle,
        "lock",
        .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true },
        0o600,
    );
    const lock: File = .{ .handle = lock_fd, .flags = .{ .nonblocking = true } };
    defer lock.close(io);
    if ((try lock.stat(io)).kind != .file) return error.ImportFileType;
    try lock.lock(io, .exclusive);
    const done = try receipt(io, a, state, "done");
    const pending = try receipt(io, a, state, "pending");
    if (pending.len != 0 and !mem.eql(u8, pending, header.id)) return error.ImportPending;
    if (pending.len == 0 and mem.eql(u8, done, header.id)) return;
    if (header.mode == .init and pending.len == 0) {
        for (try entries(
            io,
            a,
            target,
        )) |entry| if (!mem.eql(u8, entry.name, state_name)) return error.ImportDestinationNotEmpty;
    }
    try atomicBytes(io, state, "pending", header.id);
    try syncDir(io, target);
    var total: Totals = .{};
    try copyTree(io, a, source, target, state, header.mode, false, 0, &total);
    try state.rename("pending", state, "done", io);
    try syncDir(io, state);
}

fn receipt(io: Io, a: Allocator, dir: Dir, name: []const u8) ![]const u8 {
    const file = openRegular(io, dir, name) catch |err| switch (err) {
        error.FileNotFound => return "",
        else => return err,
    };
    defer file.close(io);
    var buf: [128]u8 = undefined;
    var reader = file.readerStreaming(io, &buf);
    const id = try reader.interface.allocRemaining(a, .limited(128));
    if (!validId(id)) return error.ImportState;
    return id;
}

const Fixture = struct {
    tmp: std.testing.TmpDir,
    source: Dir,
    target: Dir,
    fn init() !Fixture {
        const io = std.testing.io;
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        try tmp.dir.createDir(io, "source", .default_dir);
        try tmp.dir.createDir(io, "target", .default_dir);
        return .{
            .tmp = tmp,
            .source = try tmp.dir.openDir(io, "source", .{ .iterate = true }),
            .target = try tmp.dir.openDir(io, "target", .{ .iterate = true }),
        };
    }
    fn deinit(f: *Fixture) void {
        f.source.close(std.testing.io);
        f.target.close(std.testing.io);
        f.tmp.cleanup();
    }
    fn seal(f: Fixture, a: Allocator, mode: Mode) ![64]u8 {
        const id = try identity(std.testing.io, a, f.source, mode);
        try writeHeader(std.testing.io, a, f.source, manifest, .{ .mode = mode, .id = &id });
        return id;
    }
};

fn expectText(a: Allocator, dir: Dir, path: []const u8, text: []const u8) !void {
    try std.testing.expectEqualStrings(
        text,
        try dir.readFileAlloc(std.testing.io, path, a, .limited(1024)),
    );
}

test "init imports nested files and completed replay preserves user changes" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init();
    defer f.deinit();
    try f.source.createDir(io, "Movies", .default_dir);
    try f.source.writeFile(io, .{ .sub_path = "Movies/a.ts", .data = "original" });
    _ = try f.seal(a, .init);
    try apply(io, a, f.source, f.target);
    try expectText(a, f.target, "Movies/a.ts", "original");
    const st = try f.target.statFile(io, "Movies/a.ts", .{});
    try std.testing.expectEqual(@as(u32, 0o644), st.permissions.toMode() & 0o7777);
    try f.target.writeFile(io, .{ .sub_path = "Movies/a.ts", .data = "local edit" });
    try apply(io, a, f.source, f.target);
    try expectText(a, f.target, "Movies/a.ts", "local edit");
}

test "sync replaces atomically, preserves unchanged inodes and keeps destination-only files" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init();
    defer f.deinit();
    try f.source.writeFile(io, .{ .sub_path = "movie", .data = "new version" });
    try f.source.writeFile(io, .{ .sub_path = "same", .data = "unchanged" });
    try f.target.writeFile(io, .{ .sub_path = "movie", .data = "old version" });
    try f.target.writeFile(io, .{ .sub_path = "same", .data = "unchanged" });
    try f.target.writeFile(io, .{ .sub_path = "keep", .data = "only here" });
    const before = try f.target.statFile(io, "same", .{});
    const old = try openRegular(io, f.target, "movie");
    defer old.close(io);
    _ = try f.seal(a, .sync);
    try apply(io, a, f.source, f.target);
    try expectText(a, f.target, "movie", "new version");
    try expectText(a, f.target, "keep", "only here");
    try std.testing.expectEqual(before.inode, (try f.target.statFile(io, "same", .{})).inode);
    var buffer: [32]u8 = undefined;
    const n = try old.readStreaming(io, &.{&buffer});
    try std.testing.expectEqualStrings("old version", buffer[0..n]);
}

test "init refuses a nonempty target and never truncates an existing file" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init();
    defer f.deinit();
    try f.source.writeFile(io, .{ .sub_path = "movie", .data = "new" });
    try f.target.writeFile(io, .{ .sub_path = "movie", .data = "valuable original" });
    _ = try f.seal(a, .init);
    try std.testing.expectError(error.ImportDestinationNotEmpty, apply(io, a, f.source, f.target));
    try expectText(a, f.target, "movie", "valuable original");
}

test "source links and destination directory links cannot escape their roots" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init();
    defer f.deinit();
    try f.source.symLink(io, "../secret", "link", .{});
    try std.testing.expectError(error.ImportFileType, identity(io, a, f.source, .init));
    try f.source.deleteFile(io, "link");
    try f.source.createDir(io, "nested", .default_dir);
    try f.source.writeFile(io, .{ .sub_path = "nested/movie", .data = "new" });
    try f.tmp.dir.createDir(io, "outside", .default_dir);
    try f.tmp.dir.writeFile(io, .{ .sub_path = "outside/movie", .data = "untouched" });
    try f.target.symLink(io, "../outside", "nested", .{ .is_directory = true });
    _ = try f.seal(a, .sync);
    if (apply(io, a, f.source, f.target)) return error.FollowedDestinationLink else |_| {}
    try expectText(a, f.tmp.dir, "outside/movie", "untouched");
}

test "corrupt source is refused before any destination data changes" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init();
    defer f.deinit();
    try f.source.writeFile(io, .{ .sub_path = "movie", .data = "new" });
    try f.target.writeFile(io, .{ .sub_path = "movie", .data = "old" });
    _ = try f.seal(a, .sync);
    try f.source.writeFile(io, .{ .sub_path = "movie", .data = "corrupt" });
    try std.testing.expectError(error.ImportChecksum, apply(io, a, f.source, f.target));
    try expectText(a, f.target, "movie", "old");
}

test "interrupted init resumes the same snapshot and removes its abandoned partial file" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init();
    defer f.deinit();
    try f.source.writeFile(io, .{ .sub_path = "a", .data = "first complete file" });
    try f.source.writeFile(io, .{ .sub_path = "b", .data = "second complete file" });
    const id = try f.seal(a, .init);
    try f.target.createDir(io, state_name, .fromMode(0o700));
    try f.target.writeFile(io, .{ .sub_path = state_name ++ "/pending", .data = &id });
    try f.target.writeFile(io, .{ .sub_path = "a", .data = "first complete file" });
    try f.target.writeFile(io, .{ .sub_path = state_name ++ "/" ++ part_name, .data = "partial" });
    try apply(io, a, f.source, f.target);
    try expectText(a, f.target, "a", "first complete file");
    try expectText(a, f.target, "b", "second complete file");
    try expectText(a, f.target, state_name ++ "/done", &id);
    try std.testing.expectError(
        error.FileNotFound,
        f.target.access(io, state_name ++ "/" ++ part_name, .{}),
    );
}

test "a different pending batch blocks both sync and old completed replays" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init();
    defer f.deinit();
    try f.source.writeFile(io, .{ .sub_path = "movie", .data = "new" });
    const id = try f.seal(a, .sync);
    try f.target.createDir(io, state_name, .fromMode(0o700));
    try f.target.writeFile(
        io,
        .{
            .sub_path = state_name ++ "/pending",
            .data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
    );
    try f.target.writeFile(io, .{ .sub_path = state_name ++ "/done", .data = &id });
    try std.testing.expectError(error.ImportPending, apply(io, a, f.source, f.target));
    try std.testing.expectError(error.FileNotFound, f.target.access(io, "movie", .{}));
}

test "failed mount markers and reserved names cannot become imported files" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init();
    defer f.deinit();
    try f.source.writeFile(io, .{ .sub_path = "import-failed", .data = "mount failed" });
    try std.testing.expectError(error.ImportUnavailable, apply(io, a, f.source, f.target));
    try std.testing.expectError(error.ImportReservedName, snapshot(io, a, f.source, f.target));
}

test "sync never edits through hardlinks or a stale temporary symlink" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init();
    defer f.deinit();
    try f.source.writeFile(io, .{ .sub_path = "movie", .data = "new" });
    try f.target.writeFile(io, .{ .sub_path = "other", .data = "original" });
    try f.target.hardLink("other", f.target, "movie", io, .{});
    try f.target.symLink(io, "other", part_name, .{});
    _ = try f.seal(a, .sync);
    try apply(io, a, f.source, f.target);
    try expectText(a, f.target, "other", "original");
    try expectText(a, f.target, "movie", "new");
}

test "file directory conflicts preserve destination contents" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init();
    defer f.deinit();
    try f.source.writeFile(io, .{ .sub_path = "movie", .data = "file" });
    try f.target.createDir(io, "movie", .default_dir);
    try f.target.writeFile(io, .{ .sub_path = "movie/keep", .data = "valuable" });
    _ = try f.seal(a, .sync);
    try std.testing.expectError(error.ImportFileType, apply(io, a, f.source, f.target));
    try expectText(a, f.target, "movie/keep", "valuable");
}

test "mode changes require a new snapshot identity" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init();
    defer f.deinit();
    try f.source.writeFile(io, .{ .sub_path = "movie", .data = "new" });
    const id = try f.seal(a, .init);
    try writeHeader(io, a, f.source, manifest, .{ .mode = .sync, .id = &id });
    try std.testing.expectError(error.ImportChecksum, apply(io, a, f.source, f.target));
}

test "process death during a limited write preserves the old file and resumes the same batch" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f = try Fixture.init();
    defer f.deinit();
    const bytes = try a.alloc(u8, 65536);
    @memset(bytes, 'n');
    try f.source.writeFile(io, .{ .sub_path = "movie", .data = bytes });
    try f.target.writeFile(io, .{ .sub_path = "movie", .data = "old complete file" });
    const id = try f.seal(a, .sync);
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.Fork;
    if (pid == 0) {
        const limit: linux.rlimit = .{ .cur = 4096, .max = 4096 };
        if (linux.errno(linux.prlimit(0, .FSIZE, &limit, null)) != .SUCCESS) linux.exit_group(99);
        apply(io, a, f.source, f.target) catch linux.exit_group(42);
        linux.exit_group(98);
    }
    var status: i32 = 0;
    if (linux.errno(linux.waitpid(@intCast(pid), &status, 0)) != .SUCCESS) return error.Wait;
    // Either EFBIG was returned or SIGXFSZ killed the writer before cleanup.
    if (status == 0 or (linux.W.IFEXITED(@bitCast(status)) and
        linux.W.EXITSTATUS(@bitCast(status)) != 42)) return error.WriteLimitNotExercised;
    try expectText(a, f.target, "movie", "old complete file");
    try expectText(a, f.target, state_name ++ "/pending", &id);
    try apply(io, a, f.source, f.target);
    try std.testing.expectEqual(
        @as(u64, bytes.len),
        (try f.target.statFile(io, "movie", .{})).size,
    );
    try expectText(a, f.target, state_name ++ "/done", &id);
}
