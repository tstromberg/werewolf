//! The file worker owns this directory alone. Publishing an archive never
//! replaces an existing name, and compression never removes its only source.
const std = @import("std");
const builtin = @import("builtin");
const p = @import("policy.zig");
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const mem = std.mem;

pub const Store = struct {
    io: Io,
    dir: Dir,
    budget: u64,
    input: []u8,
    output: []u8,
    window: []u8,
    entries: []Entry,
    active: ?File = null,
    size: u64 = 0,
    opened: i64 = 0,
    total: u64 = 0,
    count: usize = 0,
    dirty: bool = false,

    const Entry = struct {
        name: [p.name_len + 3]u8 = undefined,
        len: usize,
        archive: p.Archive,
        size: u64,

        fn path(e: *const Entry) []const u8 {
            return e.name[0..e.len];
        }
        fn less(_: void, a: Entry, b: Entry) bool {
            return mem.lessThan(u8, a.path(), b.path());
        }
    };

    /// All allocations precede confinement and the first record.
    pub fn init(io: Io, gpa: mem.Allocator, dir: Dir, budget: u64) !Store {
        const input = try gpa.alloc(u8, p.segment_bytes);
        errdefer gpa.free(input);
        const output = try gpa.alloc(u8, p.scratch_bytes);
        errdefer gpa.free(output);
        const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
        errdefer gpa.free(window);
        return .{
            .io = io,
            .dir = dir,
            .budget = budget,
            .input = input,
            .output = output,
            .window = window,
            .entries = try gpa.alloc(Entry, p.max_segments + 2),
        };
    }

    pub fn deinit(s: *Store, gpa: mem.Allocator) void {
        if (s.active) |f| f.close(s.io);
        gpa.free(s.input);
        gpa.free(s.output);
        gpa.free(s.window);
        gpa.free(s.entries);
    }

    pub fn start(s: *Store, now: i64) !void {
        try s.scan();
        try s.openActive(now);
        // A restart seals the old active file conservatively at this boot's
        // time. It cannot shorten the retention of its newest record.
        if (s.size > 0) try s.rotate(now);
    }

    fn openActive(s: *Store, now: i64) !void {
        if (s.active != null) return;
        const f = safeOpen(s.dir, s.io, "messages", true) catch |err| switch (err) {
            error.FileNotFound => try s.create("messages"),
            else => return err,
        };
        errdefer f.close(s.io);
        const st = try f.stat(s.io);
        if (st.size > p.segment_bytes) return error.UnsafeFile;
        // File fsync alone does not persist a newly created directory entry.
        try f.sync(s.io);
        try syncDir(s.dir, s.io);
        s.active = f;
        s.size = st.size;
        s.opened = now;
    }

    pub fn append(s: *Store, line: []const u8, now: i64) !void {
        if (!p.validRecord(line)) return error.BadRecord;
        if (s.total + line.len > s.budget -| p.scratch_bytes) return error.StorageFull;
        try s.openActive(now);
        if (s.size + line.len > p.segment_bytes or p.oldEnough(now, s.opened, p.day))
            try s.rotate(now);
        const f = s.active.?;
        // A partial write is rolled back, so later records cannot turn it
        // into an apparently complete line. Keep accounting on failure.
        f.writePositionalAll(s.io, line, s.size) catch |err| {
            f.setLength(s.io, s.size) catch return error.RepairFailed;
            return err;
        };
        s.size += line.len;
        s.total += line.len;
        s.dirty = true;
    }

    pub fn sync(s: *Store) !void {
        if (s.dirty) if (s.active) |f| {
            try f.sync(s.io);
            s.dirty = false;
        };
    }

    pub fn rotate(s: *Store, now: i64) !void {
        try s.sealActive(now);
        try s.openActive(now);
    }

    fn sealActive(s: *Store, now: i64) !void {
        if (s.active == null or s.size == 0) return;
        if (s.count >= p.max_segments) return error.StorageFull;
        const f = s.active.?;
        try f.sync(s.io);
        const st = try f.stat(s.io);
        const modified: i64 = @intCast(@divFloor(st.mtime.nanoseconds, std.time.ns_per_s));
        const closed = @max(now, modified);
        var buf: [p.name_len]u8 = undefined;
        var gz_buf: [p.name_len + 3]u8 = undefined;
        var sequence: u16 = 1;
        while (sequence <= 999) : (sequence += 1) {
            const name = try p.archiveName(&buf, closed, sequence);
            const gz = try std.mem.print(&gz_buf, "{s}.gz", .{name});
            if (try exists(s.dir, s.io, gz)) continue;
            s.dir.renamePreserve("messages", s.dir, name, s.io) catch |err| switch (err) {
                error.PathAlreadyExists => continue,
                else => return err,
            };
            f.close(s.io);
            s.active = null;
            s.size = 0;
            s.dirty = false;
            s.count += 1;
            try syncDir(s.dir, s.io);
            return;
        }
        return error.NamesExhausted;
    }

    /// Scan before changing anything. Unknown names, links and non-regular
    /// files are faults, rather than candidates for an eager cleanup.
    fn scan(s: *Store) !void {
        s.total = 0;
        s.count = 0;
        var it = s.dir.iterate();
        while (try it.next(s.io)) |entry| {
            const name = entry.name;
            const f = try safeOpen(s.dir, s.io, name, false);
            const st = f.stat(s.io) catch |err| {
                f.close(s.io);
                return err;
            };
            f.close(s.io);
            if (mem.eql(u8, name, "messages")) {
                if (st.size > p.segment_bytes) return error.UnsafeFile;
                s.total += st.size;
                continue;
            }
            if (mem.endsWith(u8, name, ".gz.tmp")) {
                const base = name[0 .. name.len - 7];
                _ = p.Archive.parse(base) catch return error.UnsafeFile;
                const source = try safeOpen(s.dir, s.io, base, false);
                source.close(s.io);
                try s.dir.deleteFile(s.io, name);
                continue;
            }
            const a = p.Archive.parse(name) catch return error.UnsafeFile;
            if (s.count == s.entries.len) return error.TooManyFiles;
            var e: Entry = .{ .len = name.len, .archive = a, .size = st.size };
            @memcpy(e.name[0..name.len], name);
            s.entries[s.count] = e;
            s.count += 1;
            s.total = std.math.add(u64, s.total, st.size) catch return error.UnsafeFile;
        }
        mem.sort(Entry, s.entries[0..s.count], {}, Entry.less);
    }

    pub fn maintain(s: *Store, now: i64) !void {
        try s.sync();
        try s.scan();
        var compressed: usize = 0;
        const n = s.count;
        for (s.entries[0..n]) |*e| {
            if (p.oldEnough(now, e.archive.closed, p.retention)) {
                try s.dir.deleteFile(s.io, e.path());
                try syncDir(s.dir, s.io);
                s.total -= e.size;
                s.count -= 1;
            } else if (!e.archive.gzip and compressed < 16 and
                p.oldEnough(now, e.archive.closed, p.day))
            {
                try s.compress(e);
                compressed += 1;
            }
        }
        if (p.oldEnough(now, s.opened, p.day)) try s.rotate(now);
    }

    fn read(s: *Store, name: []const u8, buffer: []u8) ![]const u8 {
        const f = try safeOpen(s.dir, s.io, name, false);
        defer f.close(s.io);
        const st = try f.stat(s.io);
        if (st.size > buffer.len) return error.UnsafeFile;
        const len = try f.readPositionalAll(s.io, buffer[0..@intCast(st.size)], 0);
        if (len != st.size) return error.ShortRead;
        return buffer[0..len];
    }

    fn compress(s: *Store, e: *const Entry) !void {
        var gz_buf: [p.name_len + 3]u8 = undefined;
        var tmp_buf: [p.name_len + 7]u8 = undefined;
        const gz = try std.mem.print(&gz_buf, "{s}.gz", .{e.path()});
        const tmp = try std.mem.print(&tmp_buf, "{s}.gz.tmp", .{e.path()});
        const source = try s.read(e.path(), s.input);
        const duplicate = try exists(s.dir, s.io, gz);
        if (duplicate) {
            // A crash between publication and unlink leaves both files.
            // Verify the complete gzip, including its trailer, against raw.
            const compressed_bytes = try s.read(gz, s.output);
            try verifyGzip(compressed_bytes, source, s.window);
        } else {
            var out: Io.Writer = .fixed(s.output);
            var compressor = try std.compress.flate.Compress.init(&out, s.window, .gzip, .fastest);
            try compressor.writer.writeAll(source);
            try compressor.finish();
            const compressed_bytes = out.buffered();
            if (s.total + compressed_bytes.len > s.budget) return error.StorageFull;
            const f = try s.create(tmp);
            var open = true;
            defer if (open) f.close(s.io);
            errdefer s.dir.deleteFile(s.io, tmp) catch {};
            try f.writePositionalAll(s.io, compressed_bytes, 0);
            try f.sync(s.io);
            f.close(s.io);
            open = false;
            try s.dir.renamePreserve(tmp, s.dir, gz, s.io);
            try syncDir(s.dir, s.io);
            s.total += compressed_bytes.len;
        }
        try s.dir.deleteFile(s.io, e.path());
        try syncDir(s.dir, s.io);
        s.total -= e.size;
        if (duplicate) s.count -= 1;
    }

    fn create(s: *Store, name: []const u8) !File {
        return s.dir.createFile(s.io, name, .{
            .read = true,
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
    }

    pub fn finish(s: *Store, now: i64) !void {
        try s.sync();
        s.sealActive(now) catch |err| switch (err) {
            error.StorageFull, error.NamesExhausted => {},
            else => return err,
        };
        if (s.active) |f| f.close(s.io);
        s.active = null;
        try syncDir(s.dir, s.io);
    }
};

fn safeOpen(dir: Dir, io: Io, name: []const u8, write: bool) !File {
    const f: File = if (builtin.os.tag == .linux) b: {
        const linux = std.os.linux;
        var path_buf: [256]u8 = undefined;
        const path = std.mem.printSentinel(&path_buf, "{s}", .{name}, 0) catch
            return error.UnsafeFile;
        const rc = linux.openat(dir.handle, path, .{
            .ACCMODE = if (write) .RDWR else .RDONLY,
            .NOFOLLOW = true,
            .NONBLOCK = true,
            .CLOEXEC = true,
        }, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .NOENT => return error.FileNotFound,
            else => return error.UnsafeFile,
        }
        break :b .{ .handle = @intCast(rc), .flags = .{ .nonblocking = true } };
    } else b: {
        const st = try dir.statFile(io, name, .{ .follow_symlinks = false });
        if (st.kind != .file or st.nlink != 1) return error.UnsafeFile;
        break :b try dir.openFile(io, name, .{
            .mode = if (write) .read_write else .read_only,
            .follow_symlinks = false,
        });
    };
    errdefer f.close(io);
    const st = try f.stat(io);
    if (st.kind != .file or st.nlink != 1 or st.permissions.toMode() & 0o077 != 0)
        return error.UnsafeFile;
    return f;
}

fn exists(dir: Dir, io: Io, name: []const u8) !bool {
    _ = dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

fn syncDir(dir: Dir, io: Io) !void {
    const f: File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    try f.sync(io);
}

pub fn verifyGzip(compressed_bytes: []const u8, source: []const u8, window: []u8) !void {
    var input: Io.Reader = .fixed(compressed_bytes);
    var d: std.compress.flate.Decompress = .init(&input, .gzip, window);
    var at: usize = 0;
    var buf: [4096]u8 = undefined;
    while (at < source.len) {
        const n = @min(source.len - at, buf.len);
        d.reader.readSliceAll(buf[0..n]) catch return error.BadArchive;
        if (!mem.eql(u8, buf[0..n], source[at..][0..n])) return error.BadArchive;
        at += n;
    }
    if (d.reader.takeByte()) |_| return error.BadArchive else |err| {
        if (err != error.EndOfStream or d.err != null or input.seek != compressed_bytes.len)
            return error.BadArchive;
    }
    const trailer = d.container_metadata.gzip;
    if (trailer.crc != std.hash.Crc32.hash(source) or trailer.count != source.len)
        return error.BadArchive;
}

const t = std.testing;
const sample = "syslogd: {\"message\":\"test\"}\n";

fn put(dir: Dir, name: []const u8, bytes: []const u8) !void {
    const f = try dir.createFile(t.io, name, .{ .permissions = .fromMode(0o600) });
    defer f.close(t.io);
    try f.writePositionalAll(t.io, bytes, 0);
}

test "rotation names closing time, survives restart, and cannot reuse a compressed name" {
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var s = try Store.init(t.io, t.allocator, tmp.dir, 1 << 30);
    defer s.deinit(t.allocator);
    try s.start(0);
    try s.append(sample, 0);
    // Real filesystem mtime is later than the supplied test clock.
    const now: i64 = 2000000000;
    try s.rotate(now);
    const name = "messages.2033-05-18T03:33:20Z.001";
    try t.expect(try exists(tmp.dir, t.io, name));
    try s.append(sample, now);
    try s.rotate(now);
    try t.expect(try exists(tmp.dir, t.io, "messages.2033-05-18T03:33:20Z.002"));
    try s.maintain(now + p.day);
    try s.append(sample, now);
    try s.rotate(now);
    try t.expect(try exists(tmp.dir, t.io, "messages.2033-05-18T03:33:20Z.003"));
    try s.finish(now);
    try s.start(now);
}

test "compression and retention respect exact closing ages and keep gzip content" {
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const raw = "messages.2024-01-01T00:00:00Z.001";
    const compressed_bytes = raw ++ ".gz";
    try put(tmp.dir, raw, sample);
    var s = try Store.init(t.io, t.allocator, tmp.dir, 1 << 30);
    defer s.deinit(t.allocator);
    const closed = (try p.Archive.parse(raw)).closed;
    try s.start(closed);
    try s.maintain(closed + p.day - 1);
    try t.expect(try exists(tmp.dir, t.io, raw));
    try s.maintain(closed + p.day);
    try t.expect(!try exists(tmp.dir, t.io, raw));
    try verifyGzip(try s.read(compressed_bytes, s.output), sample, s.window);
    try s.maintain(closed + p.retention - 1);
    try t.expect(try exists(tmp.dir, t.io, compressed_bytes));
    try s.maintain(closed + p.retention);
    try t.expect(!try exists(tmp.dir, t.io, compressed_bytes));
}

test "pressure drops new records without deleting young archives" {
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const raw = "messages.2024-01-01T00:00:00Z.001";
    try put(tmp.dir, raw, sample);
    var s = try Store.init(t.io, t.allocator, tmp.dir, p.scratch_bytes + sample.len);
    defer s.deinit(t.allocator);
    const closed = (try p.Archive.parse(raw)).closed;
    try s.start(closed);
    try t.expectError(error.StorageFull, s.append(sample, closed));
    try t.expect(try exists(tmp.dir, t.io, raw));
    try s.maintain(closed + p.retention);
    try s.append(sample, closed + p.retention);
}

test "interrupted gzip keeps its source and verified duplicates recover" {
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const raw = "messages.2024-01-01T00:00:00Z.001";
    try put(tmp.dir, raw, sample);
    try put(tmp.dir, raw ++ ".gz.tmp", "partial gzip");
    var s = try Store.init(t.io, t.allocator, tmp.dir, 1 << 30);
    defer s.deinit(t.allocator);
    const closed = (try p.Archive.parse(raw)).closed;
    try s.start(closed);
    try t.expect(try exists(tmp.dir, t.io, raw));
    try t.expect(!try exists(tmp.dir, t.io, raw ++ ".gz.tmp"));
    try s.maintain(closed + p.day);
    try put(tmp.dir, raw, sample);
    try s.maintain(closed + p.day);
    try t.expect(!try exists(tmp.dir, t.io, raw));
    try put(tmp.dir, raw, sample ++ sample);
    try t.expectError(error.BadArchive, s.maintain(closed + p.day));
    try t.expect(try exists(tmp.dir, t.io, raw));
}

test "links, directories and unexpected names cannot become log files" {
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var s = try Store.init(t.io, t.allocator, tmp.dir, 1 << 30);
    defer s.deinit(t.allocator);
    try put(tmp.dir, "other", "untouched");
    try tmp.dir.symLink(t.io, "other", "messages", .{});
    try t.expectError(error.UnsafeFile, s.start(0));
    try tmp.dir.deleteFile(t.io, "messages");
    try tmp.dir.deleteFile(t.io, "other");
    try tmp.dir.createDir(t.io, "messages", .default_dir);
    try t.expectError(error.UnsafeFile, s.start(0));
}

test "idle and size rotation keep each file bounded" {
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var s = try Store.init(t.io, t.allocator, tmp.dir, 1 << 30);
    defer s.deinit(t.allocator);
    const now: i64 = 2000000000;
    try s.start(now);
    try s.append(sample, now);
    try s.maintain(now + p.day);
    try t.expectEqual(@as(u64, 0), s.size);
    try t.expectEqual(@as(usize, 1), s.count);
    var line: [p.max_record]u8 = @splat('a');
    @memcpy(line[0..10], "syslogd: {");
    line[line.len - 1] = '\n';
    for (0..p.segment_bytes / line.len + 1) |_| try s.append(&line, now + p.day);
    try t.expect(s.size <= p.segment_bytes);
    try t.expectEqual(@as(usize, 2), s.count);
}

test "gzip recovery checks the CRC and length before removing its source" {
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const raw = "messages.2024-01-01T00:00:00Z.001";
    try put(tmp.dir, raw, sample);
    var s = try Store.init(t.io, t.allocator, tmp.dir, 1 << 30);
    defer s.deinit(t.allocator);
    const closed = (try p.Archive.parse(raw)).closed;
    try s.start(closed);
    try s.maintain(closed + p.day);
    const compressed_bytes = try s.read(raw ++ ".gz", s.output);
    s.output[compressed_bytes.len - 8] ^= 1;
    try put(tmp.dir, raw ++ ".gz", compressed_bytes);
    try put(tmp.dir, raw, sample);
    try t.expectError(error.BadArchive, s.maintain(closed + p.day));
    try t.expect(try exists(tmp.dir, t.io, raw));
}

test "hardlinked files are refused before any write" {
    var tmp = t.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var outside = t.tmpDir(.{});
    defer outside.cleanup();
    try put(tmp.dir, "messages", sample);
    try tmp.dir.hardLink("messages", outside.dir, "witness", t.io, .{});
    var s = try Store.init(t.io, t.allocator, tmp.dir, 1 << 30);
    defer s.deinit(t.allocator);
    try t.expectError(error.UnsafeFile, s.start(0));
    var buf: [128]u8 = undefined;
    try t.expectEqualStrings(sample, try outside.dir.readFile(t.io, "witness", &buf));
}
