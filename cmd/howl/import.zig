//! Immutable, data-only import disks. Existing artifacts are never overwritten.
const std = @import("std");
const data = @import("import-data");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Why = howl.Why;
pub const Mode = data.Mode;
pub const label = "werewolf-import";
pub const Record = struct {
    version: u8 = 1,
    id: []const u8,
    digest: []const u8,
    mode: Mode,
    sha256: []const u8,
    bytes: u64,
};

pub fn path(a: Allocator, dir: []const u8, record: Record) ![]const u8 {
    if (record.version != 1 or !data.validId(record.id) or
        !data.validId(record.sha256) or !data.validId(record.digest)) return error.ImportRecord;
    return a.print("{s}/imports/{s}/disk.img", .{ dir, record.id });
}

pub fn validate(io: Io, a: Allocator, dir: []const u8, record: Record) ![]const u8 {
    const name = try path(a, dir, record);
    const file = try data.openRegular(io, .cwd(), name);
    defer file.close(io);
    if ((try file.stat(io)).size != record.bytes) return error.ImportChecksum;
    const hash = std.fmt.bytesToHex(try data.fileHash(io, file), .lower);
    if (!std.mem.eql(u8, &hash, record.sha256)) return error.ImportChecksum;
    return name;
}

pub fn recordAt(io: Io, a: Allocator, dir: []const u8, file: []const u8) !Record {
    const f = try data.openRegular(io, .cwd(), try a.print("{s}/{s}", .{ dir, file }));
    defer f.close(io);
    var buf: [1024]u8 = undefined;
    var reader = f.readerStreaming(io, &buf);
    return std.json.parseFromSliceLeaky(
        Record,
        a,
        try reader.interface.allocRemaining(a, .limited(2048)),
        .{},
    );
}

/// Absence is optional; a declared disk which is missing or corrupt is an error.
pub fn existing(io: Io, a: Allocator, dir: []const u8) !?[]const u8 {
    const record = recordAt(io, a, dir, "import.json") catch |err| switch (err) {
        error.FileNotFound => {
            const legacy = try a.print("{s}/import.img", .{dir});
            const f = data.openRegular(io, .cwd(), legacy) catch |old| switch (old) {
                error.FileNotFound => return null,
                else => return old,
            };
            f.close(io);
            return legacy;
        },
        else => return err,
    };
    return try validate(io, a, dir, record);
}

pub fn activate(io: Io, a: Allocator, dir: []const u8, record: Record, replace: bool) !void {
    _ = try validate(io, a, dir, record);
    var parent = try Dir.cwd().openDir(io, dir, .{ .follow_symlinks = false });
    defer parent.close(io);
    const text = try std.json.Stringify.valueAlloc(a, record, .{});
    var nonce: [16]u8 = undefined;
    Io.random(io, &nonce);
    const temp = try a.print(".import-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
    const f = try parent.createFile(
        io,
        temp,
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    );
    defer f.close(io);
    defer parent.deleteFile(io, temp) catch {};
    try f.writeStreamingAll(io, text);
    try f.sync(io);
    if (replace)
        try parent.rename(temp, parent, "import.json", io)
    else
        try parent.renamePreserve(temp, parent, "import.json", io);
    try data.syncDir(io, parent);
}

pub fn write(io: Io, a: Allocator, src: []const u8, dir: []const u8, why: *Why) !void {
    const active = recordAt(io, a, dir, "import.json") catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (active) |record| {
        _ = try validate(io, a, dir, record);
    }
    const record = try prepareWithReuse(io, a, src, dir, .init, active, why);
    if (active != null) return;
    if (try existing(io, a, dir) != null) return error.LegacyImportExists;
    try activate(io, a, dir, record, false);
}

pub fn prepare(
    io: Io,
    a: Allocator,
    src: []const u8,
    dir: []const u8,
    mode: Mode,
    why: *Why,
) !Record {
    return prepareWithReuse(io, a, src, dir, mode, null, why);
}

fn prepareWithReuse(
    io: Io,
    a: Allocator,
    src: []const u8,
    dir: []const u8,
    mode: Mode,
    retained: ?Record,
    why: *Why,
) !Record {
    const given = if (std.mem.trimEnd(u8, src, "/").len == 0)
        "/"
    else
        std.mem.trimEnd(u8, src, "/");
    const source_info = try Dir.cwd().statFile(io, given, .{ .follow_symlinks = false });
    if (source_info.kind != .file and source_info.kind != .directory) return error.ImportFileType;
    const container = if (source_info.kind == .directory)
        given
    else
        std.fs.path.dirname(given) orelse ".";
    var from = try Dir.cwd().openDir(io, container, .{ .iterate = true, .follow_symlinks = false });
    defer from.close(io);
    const source_path = try from.realPathFileAlloc(io, ".", a);
    const destination_path = if (Dir.cwd().realPathFileAlloc(io, dir, a)) |real|
        real
    else |err| blk: {
        if (err != error.FileNotFound) return err;
        const parent = try Dir.cwd().realPathFileAlloc(io, std.fs.path.dirname(dir) orelse ".", a);
        break :blk try a.print("{s}/{s}", .{ parent, std.fs.path.basename(dir) });
    };
    if (source_info.kind == .directory and (std.mem.eql(u8, source_path, "/") or
        std.mem.eql(u8, source_path, destination_path) or
        (std.mem.startsWith(u8, destination_path, source_path) and
            destination_path[source_path.len] == '/')))
        return why.refuse("import destination is inside its source", .{});
    try Dir.cwd().createDirPath(io, dir);
    try Dir.cwd().setFilePermissions(io, dir, .fromMode(0o700), .{ .follow_symlinks = false });
    var nonce: [16]u8 = undefined;
    Io.random(io, &nonce);
    const work = try a.print("{s}/.import-build-{s}", .{ dir, std.fmt.bytesToHex(nonce, .lower) });
    try Dir.cwd().createDir(io, work, .fromMode(0o700));
    defer Dir.cwd().deleteTree(io, work) catch {};
    const stage_path = try a.print("{s}/files", .{work});
    var stage = try Dir.cwd().createDirPathOpen(
        io,
        stage_path,
        .{ .open_options = .{ .iterate = true } },
    );
    defer stage.close(io);
    try (Io.File{
        .handle = stage.handle,
        .flags = .{ .nonblocking = false },
    }).setPermissions(io, .fromMode(0o755));
    var totals: data.Totals = undefined;
    if (source_info.kind == .directory) {
        totals = try data.snapshot(io, a, from, stage);
    } else {
        // A one-file snapshot uses the same safe copy path as a directory.
        const name = std.fs.path.basename(given);
        totals = try data.snapshotFile(io, from, stage, name);
    }
    if (totals.files == 0) return error.ImportEmpty;
    const digest = try data.identity(io, a, stage, mode);
    if (retained) |record| {
        if (record.mode == mode and std.mem.eql(u8, record.digest, &digest)) return record;
        return why.refuse(
            "a different import is already selected; use howl import or howl sync explicitly",
            .{},
        );
    }
    var batch_nonce: [32]u8 = undefined;
    try io.randomSecure(&batch_nonce);
    const id = std.fmt.bytesToHex(batch_nonce, .lower);
    const home = try a.print("{s}/imports/{s}", .{ dir, id });
    try data.writeHeader(
        io,
        a,
        stage,
        data.manifest,
        .{ .mode = mode, .id = &id, .digest = &digest },
    );
    try stage.setFilePermissions(
        io,
        data.manifest,
        .fromMode(0o644),
        .{ .follow_symlinks = false },
    );
    const image = try a.print("{s}/disk.img", .{work});
    const image_file = try Dir.cwd().createFile(
        io,
        image,
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    );
    image_file.close(io);
    const bin = findMke2fs(io, a) orelse return why.refuse("no mke2fs; install e2fsprogs", .{});
    const overhead = try std.math.add(u64, 32 << 20, try std.math.mul(u64, totals.files, 16384));
    const size = try std.math.add(u64, totals.bytes, overhead);
    const blocks = try a.print("{d}", .{try std.math.add(u64, size, 4095) / 4096});
    try howl.run(
        io,
        why,
        &.{
            bin,
            "-q",
            "-F",
            "-t",
            "ext4",
            "-b",
            "4096",
            "-L",
            label,
            "-m",
            "0",
            "-O",
            "^orphan_file",
            "-E",
            "root_owner=0:0",
            "-d",
            stage_path,
            image,
            blocks,
        },
    );
    const f = try data.openRegular(io, .cwd(), image);
    defer f.close(io);
    try f.sync(io);
    const hash = std.fmt.bytesToHex(try data.fileHash(io, f), .lower);
    const record: Record = .{
        .id = try a.dupe(u8, &id),
        .digest = try a.dupe(u8, &digest),
        .mode = mode,
        .sha256 = try a.dupe(u8, &hash),
        .bytes = (try f.stat(io)).size,
    };
    var parent = try Dir.cwd().openDir(io, work, .{});
    defer parent.close(io);
    const record_file = try parent.createFile(
        io,
        "record.json",
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    );
    defer record_file.close(io);
    try record_file.writeStreamingAll(io, try std.json.Stringify.valueAlloc(a, record, .{}));
    try record_file.sync(io);
    try parent.deleteTree(io, "files");
    try data.syncDir(io, parent);
    try Dir.cwd().createDirPath(io, try a.print("{s}/imports", .{dir}));
    try publishSnapshot(io, a, work, home);
    var imports = try Dir.cwd().openDir(io, try a.print("{s}/imports", .{dir}), .{});
    defer imports.close(io);
    try data.syncDir(io, imports);
    return record;
}

fn publishSnapshot(io: Io, gpa: Allocator, work: []const u8, home: []const u8) !void {
    if (@import("builtin").os.tag != .freebsd)
        return Dir.cwd().renamePreserve(work, .cwd(), home, io);
    // Zig's FreeBSD renamePreserve fallback hard-links the source, which
    // cannot publish a directory. Serialize publishers in the private import
    // directory, reject any existing entry, then atomically rename the snapshot.
    const parent = std.fs.path.dirname(home) orelse return error.BadImportPath;
    const lock = try Dir.cwd().createFile(io, try gpa.print("{s}/publish.lock", .{parent}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer lock.close(io);
    try lock.lock(io, .exclusive);
    defer lock.unlock(io);
    if (Dir.cwd().statFile(io, home, .{ .follow_symlinks = false })) |_|
        return error.PathAlreadyExists
    else |err| if (err != error.FileNotFound) return err;
    try Dir.cwd().rename(work, .cwd(), home, io);
}

test "publishing an import snapshot never replaces an existing snapshot" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const root = try tmp.dir.realPathFileAlloc(testing.io, ".", gpa);
    try tmp.dir.createDir(testing.io, "work", .default_dir);
    try tmp.dir.createDir(testing.io, "kept", .default_dir);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "kept/record", .data = "original" });
    try testing.expectError(error.PathAlreadyExists, publishSnapshot(
        testing.io,
        gpa,
        try gpa.print("{s}/work", .{root}),
        try gpa.print("{s}/kept", .{root}),
    ));
    try testing.expectEqualStrings(
        "original",
        try tmp.dir.readFileAlloc(testing.io, "kept/record", gpa, .limited(32)),
    );
}

fn findMke2fs(io: Io, gpa: Allocator) ?[]const u8 {
    const fixed = [_][]const u8{
        "/opt/homebrew/opt/e2fsprogs/sbin/mke2fs",
        "/usr/local/opt/e2fsprogs/sbin/mke2fs",
        "/usr/local/sbin/mke2fs",
        "/usr/sbin/mke2fs",
        "/sbin/mke2fs",
    };
    for (fixed) |p| {
        if (Dir.cwd().access(io, p, .{ .execute = true })) |_| return p else |_| {}
    }
    var search = std.mem.tokenizeScalar(u8, howl.environ.get("PATH") orelse "", ':');
    while (search.next()) |d| {
        const p = gpa.print("{s}/mke2fs", .{d}) catch return null;
        if (Dir.cwd().access(io, p, .{ .execute = true })) |_| return p else |_| {}
    }
    return null;
}

const testing = std.testing;

fn importFixture(
    io: Io,
    a: Allocator,
    tmp: *testing.TmpDir,
) !struct { source: []const u8, machine: []const u8 } {
    try tmp.dir.createDir(io, "source", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/movie.ts", .data = "media" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    return .{
        .source = try a.print("{s}/source", .{root}),
        .machine = try a.print("{s}/machine", .{root}),
    };
}

test "snapshot staging is recursive, immutable, repeatable and private" {
    const io = testing.io;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    const previous = howl.environ;
    howl.environ = &env;
    defer howl.environ = previous;
    if (findMke2fs(io, a) == null) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try importFixture(io, a, &tmp);
    try tmp.dir.createDir(io, "source/Movies", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source/Movies/subtitle.srt", .data = "subtitle" });
    var why: Why = .{};
    const record = try prepare(io, a, f.source, f.machine, .init, &why);
    try activate(io, a, f.machine, record, false);
    const image = (try existing(io, a, f.machine)).?;
    try testing.expectEqual(
        @as(u32, 0o600),
        (try Dir.cwd().statFile(io, image, .{})).permissions.toMode() & 0o7777,
    );
    const repeated = try prepare(io, a, f.source, f.machine, .init, &why);
    try testing.expectEqualStrings(record.digest, repeated.digest);
    try testing.expect(!std.mem.eql(u8, record.id, repeated.id));
    try write(io, a, f.source, f.machine, &why); // Same create is idempotent.
    try tmp.dir.writeFile(io, .{ .sub_path = "source/movie.ts", .data = "changed" });
    try testing.expectError(error.Refused, write(io, a, f.source, f.machine, &why));
    try testing.expectEqualStrings(image, (try existing(io, a, f.machine)).?);
    const next = try prepare(io, a, f.source, f.machine, .sync, &why);
    try activate(io, a, f.machine, next, true);
    _ = try validate(io, a, f.machine, record); // Previous snapshot retained.
    try testing.expect(!std.mem.eql(u8, image, (try existing(io, a, f.machine)).?));
}

test "failed staging and corrupt artifacts cannot replace an active import" {
    const io = testing.io;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    const previous = howl.environ;
    howl.environ = &env;
    defer howl.environ = previous;
    if (findMke2fs(io, a) == null) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try importFixture(io, a, &tmp);
    var why: Why = .{};
    const record = try prepare(io, a, f.source, f.machine, .init, &why);
    try activate(io, a, f.machine, record, false);
    try tmp.dir.symLink(io, "/etc/passwd", "source/escape", .{});
    try testing.expectError(error.ImportFileType, prepare(io, a, f.source, f.machine, .sync, &why));
    _ = try validate(io, a, f.machine, record);
    try Dir.cwd().writeFile(io, .{ .sub_path = try path(a, f.machine, record), .data = "corrupt" });
    try testing.expectError(error.ImportChecksum, existing(io, a, f.machine));
}

test "source aliases, recursion into output and reserved names are refused" {
    const io = testing.io;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try importFixture(io, a, &tmp);
    var why: Why = .{};
    try tmp.dir.symLink(io, "source", "alias", .{ .is_directory = true });
    try testing.expectError(error.Refused, prepare(io, a, "/", f.machine, .init, &why));
    const alias = try a.print("{s}/alias/", .{std.fs.path.dirname(f.source).?});
    try testing.expectError(error.ImportFileType, prepare(io, a, alias, f.machine, .init, &why));
    try testing.expectError(
        error.Refused,
        prepare(io, a, f.source, try a.print("{s}/output", .{f.source}), .init, &why),
    );
    try tmp.dir.writeFile(io, .{ .sub_path = "source/import-failed", .data = "reserved" });
    try testing.expectError(
        error.ImportReservedName,
        prepare(io, a, f.source, f.machine, .init, &why),
    );
}
