//! apk checks apk's cache before root's apk reads it. apk verifies indexes
//! and packages only while it unpacks them, after its gzip and tar parsers
//! have run; here nothing a trusted key has not vouched for gets that far.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const releases = @import("release.zig");
const package = @import("package");

/// Inflated size limits for a signature segment, a control segment and an
/// index, and how much of a package is read to find its control segment.
const max_signature = 64 << 10;
const max_control = 16 << 20;
const max_index = 256 << 20;
const max_head = 32 << 20;

/// Key is a key apk checks an index against. name is its file name, which
/// the index's signature file names.
pub const Key = struct { name: []const u8, key: releases.Key };

/// Index maps a package's cache name, NAME-VERSION.HASH (HASH is the first
/// 4 bytes of C: in hex), to the SHA-1 of its control segment.
pub const Index = std.StringHashMapUnmanaged([Sha1.digest_length]u8);

/// readIndex verifies an APKINDEX.tar.gz against keys and adds its packages
/// to idx. The index is two gzip segments: a tar holding only
/// .SIGN.RSA.KEY (SHA-1) or .SIGN.RSA256.KEY (SHA-256), signing the second,
/// which holds APKINDEX. It returns the index with the signature segment
/// rebuilt by root, so apk parses only bytes root has checked.
pub fn readIndex(gpa: Allocator, keys: []const Key, idx: *Index, data: []const u8) ![]const u8 {
    const sig = try segment(gpa, data, 0, max_signature);
    const files = try tarFiles(gpa, sig.bytes);
    if (files.len != 1) return error.BadSignatureSegment;
    const name = files[0].name;
    const signed = data[sig.end..];
    const key, const sha256 = for (keys) |k| {
        if (std.mem.startsWith(u8, name, ".SIGN.RSA256.") and
            std.mem.eql(u8, name[".SIGN.RSA256.".len..], k.name)) break .{ k.key, true };
        if (std.mem.startsWith(u8, name, ".SIGN.RSA.") and
            std.mem.eql(u8, name[".SIGN.RSA.".len..], k.name)) break .{ k.key, false };
    } else return error.UnknownKey;
    if (sha256)
        try releases.verifyHash(Sha256, key, signed, files[0].data)
    else
        try releases.verifyHash(Sha1, key, signed, files[0].data);

    // Refuse anything after the signed segment.
    const body = try segment(gpa, signed, 0, max_index);
    if (body.end != signed.len) return error.TrailingData;
    const list = for (try tarFiles(gpa, body.bytes)) |f| {
        if (std.mem.eql(u8, f.name, "APKINDEX")) break f.data;
    } else return error.NoApkIndex;
    try addPackages(gpa, idx, list);
    return std.mem.concat(gpa, u8, &.{ try signatureSegment(gpa, name, files[0].data), signed });
}

/// addPackages adds an APKINDEX's packages to idx. Records are KEY:VALUE
/// lines separated by blank lines; each needs P (name), V (version) and C
/// ("Q1" and the base64 SHA-1 of the control segment).
fn addPackages(gpa: Allocator, idx: *Index, list: []const u8) !void {
    var records = std.mem.splitSequence(u8, list, "\n\n");
    while (records.next()) |record| {
        var name: ?[]const u8 = null;
        var version: ?[]const u8 = null;
        var csum: ?[]const u8 = null;
        var lines = std.mem.tokenizeScalar(u8, record, '\n');
        while (lines.next()) |l| {
            if (l.len < 2 or l[1] != ':') return error.BadApkIndex;
            switch (l[0]) {
                'P' => name = l[2..],
                'V' => version = l[2..],
                'C' => csum = l[2..],
                else => {},
            }
        }
        if (name == null and version == null and csum == null) continue;
        const c = csum orelse return error.BadApkIndex;
        if (!std.mem.startsWith(u8, c, "Q1")) return error.BadApkIndex;
        var sha1: [Sha1.digest_length]u8 = undefined;
        const decoder = std.base64.standard.Decoder;
        if ((decoder.calcSizeForSlice(c[2..]) catch return error.BadApkIndex) != sha1.len)
            return error.BadApkIndex;
        decoder.decode(&sha1, c[2..]) catch return error.BadApkIndex;
        try idx.put(gpa, try gpa.print("{s}-{s}.{x}", .{
            name orelse return error.BadApkIndex,
            version orelse return error.BadApkIndex,
            sha1[0..4],
        }), sha1);
    }
}

/// Control locates a package's control segment and holds datahash, the
/// SHA-256 its .PKGINFO gives for the rest of the package.
const Control = struct { start: usize, end: usize, datahash: [Sha256.digest_length]u8 };

/// control finds the control segment in head, the start of a package: the
/// first segment, or the second after an Alpine signature, whose SHA-1 must
/// be want. A segment is inflated only to find its end, and parsed only
/// after its hash matches.
fn control(gpa: Allocator, head: []const u8, want: [Sha1.digest_length]u8) !Control {
    var start: usize = 0;
    var c = try segment(gpa, head, start, max_control);
    if (!std.mem.eql(u8, &sha1Of(head[start..c.end]), &want)) {
        start = c.end;
        c = try segment(gpa, head, start, max_control);
        if (!std.mem.eql(u8, &sha1Of(head[start..c.end]), &want)) return error.NotAsIndexed;
    }
    const info = for (try tarFiles(gpa, c.bytes)) |f| {
        if (std.mem.eql(u8, f.name, ".PKGINFO")) break f.data;
    } else return error.NoPkgInfo;
    var lines = std.mem.tokenizeScalar(u8, info, '\n');
    const hex = while (lines.next()) |l| {
        if (std.mem.startsWith(u8, l, "datahash = ")) break l["datahash = ".len..];
    } else return error.NoDataHash;
    var datahash: [Sha256.digest_length]u8 = undefined;
    const got = std.fmt.hexToBytes(&datahash, hex) catch return error.NoDataHash;
    if (got.len != datahash.len) return error.NoDataHash;
    return .{ .start = start, .end = c.end, .datahash = datahash };
}

/// checkPackage verifies package name in dir against idx: the control
/// segment by its SHA-1, the rest by datahash. Alpine packages carry a
/// signature segment that Wolfi's lack; the index vouches for both, so it
/// rewrites Alpine packages without it. A package no index lists, such as
/// one left from an older index, is error.NotInIndex.
pub fn checkPackage(
    gpa: Allocator,
    io: Io,
    dir: Io.Dir,
    name: []const u8,
    idx: *const Index,
) !void {
    if (!std.mem.endsWith(u8, name, ".apk")) return error.NotInIndex;
    const want = idx.get(name[0 .. name.len - ".apk".len]) orelse return error.NotInIndex;
    const file = try dir.openFile(io, name, .{});
    defer file.close(io);
    const size = try file.length(io);
    const head = try gpa.alloc(u8, @intCast(@min(size, max_head)));
    if (try file.readPositionalAll(io, head, 0) != head.len) return error.PackageChanged;
    const c = try control(gpa, head, want);

    // Hash the rest. For a signed package, also copy it after the control
    // segment into tmp, which replaces the package.
    const tmp = try gpa.print("{s}.tmp", .{name});
    const out: ?Io.File = if (c.start > 0) try dir.createFile(io, tmp, .{}) else null;
    defer if (out) |f| f.close(io);
    errdefer if (out != null) dir.deleteFile(io, tmp) catch {};
    if (out) |f| try f.writePositionalAll(io, head[c.start..c.end], 0);
    var h: Sha256 = .init(.{});
    const buf = try gpa.alloc(u8, 1 << 20);
    var off: u64 = c.end;
    while (off < size) {
        const piece = buf[0..@intCast(@min(buf.len, size - off))];
        if (try file.readPositionalAll(io, piece, off) != piece.len) return error.PackageChanged;
        h.update(piece);
        if (out) |f| try f.writePositionalAll(io, piece, off - c.start);
        off += piece.len;
    }
    if (!std.mem.eql(u8, &h.finalResult(), &c.datahash)) return error.NotAsIndexed;
    if (out) |f| {
        try f.sync(io);
        try dir.rename(tmp, dir, name, io);
    }
}

/// segment inflates the gzip member at start, up to max bytes, and returns
/// where it ends and its contents.
fn segment(gpa: Allocator, data: []const u8, start: usize, max: usize) !struct {
    end: usize,
    bytes: []u8,
} {
    var in: Io.Reader = .fixed(data[start..]);
    var d: std.compress.flate.Decompress = .init(&in, .gzip, &.{});
    const bytes = d.reader.allocRemaining(gpa, .limited(max)) catch |err| switch (err) {
        error.ReadFailed => return d.err orelse error.ReadFailed,
        else => return err,
    };
    return .{ .end = start + in.seek, .bytes = bytes };
}

const TarFile = struct { name: []const u8, data: []const u8 };

/// tarFiles returns the regular files of a tar segment, in order. apk's
/// segments may lack the two zero blocks that end an archive.
fn tarFiles(gpa: Allocator, tar: []const u8) ![]const TarFile {
    var r: Io.Reader = .fixed(tar);
    var name_buf: [256]u8 = undefined;
    var link_buf: [256]u8 = undefined;
    var it: std.tar.Iterator = .init(
        &r,
        .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
    );
    var files: std.ArrayList(TarFile) = .empty;
    while (try it.next()) |f| {
        if (f.kind != .file) continue;
        if (f.size > tar.len - r.seek) return error.UnexpectedEndOfStream;
        try files.append(gpa, .{
            .name = try gpa.dupe(u8, f.name),
            .data = tar[r.seek..][0..@intCast(f.size)],
        });
    }
    return files.items;
}

/// signatureSegment builds a signature segment as apk writes one: a gzip
/// member holding a tar of one file, without end-of-archive blocks. It is
/// stored, not compressed, since it is a few hundred bytes.
fn signatureSegment(gpa: Allocator, name: []const u8, sig: []const u8) ![]const u8 {
    if (name.len > 99 or sig.len > max_signature) return error.BadSignatureSegment;
    var header: [512]u8 = @splat(0);
    @memcpy(header[0..name.len], name);
    @memcpy(header[100..107], "0000644");
    @memcpy(header[108..115], "0000000");
    @memcpy(header[116..123], "0000000");
    _ = std.mem.print(header[124..135], "{o:0>11}", .{sig.len}) catch unreachable;
    @memcpy(header[136..147], "00000000000");
    header[156] = '0';
    @memcpy(header[257..263], "ustar\x00");
    @memcpy(header[263..265], "00");
    @memset(header[148..156], ' ');
    var sum: u32 = 0;
    for (header) |b| sum += b;
    _ = std.mem.print(header[148..155], "{o:0>6}\x00", .{sum}) catch unreachable;

    const tar = try std.mem.concat(gpa, u8, &.{ &header, sig, &@as([512]u8, @splat(0)) });
    const body = tar[0 .. 512 + std.mem.alignForward(usize, sig.len, 512)];
    var out: std.ArrayList(u8) = .empty;
    // gzip header: deflate, no flags, no time, Unix.
    try out.appendSlice(gpa, &.{ 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3 });
    // One final stored block; the body is far under 64 KiB.
    const len: u16 = @intCast(body.len);
    try out.append(gpa, 1);
    try out.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(u16, len)));
    try out.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(u16, ~len)));
    try out.appendSlice(gpa, body);
    const crc = std.hash.Crc32.hash(body);
    try out.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(u32, crc)));
    try out.appendSlice(gpa, &std.mem.toBytes(std.mem.nativeToLittle(u32, @as(u32, len))));
    return out.items;
}

fn sha1Of(data: []const u8) [Sha1.digest_length]u8 {
    var out: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(data, &out, .{});
    return out;
}

// --- tests ----------------------------------------------------------------------
// testdata/apk/ holds a key, an index signed with each hash, and two packages
// it lists: hello, built as Wolfi does, and signed, built as Alpine does.

const testing = std.testing;

fn testKeys(gpa: Allocator) ![]const Key {
    const k = try releases.parseKey(gpa, @embedFile("testdata/apk/test.rsa.pub"));
    return gpa.dupe(Key, &.{.{ .name = "test.rsa.pub", .key = k }});
}

test readIndex {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const keys = try testKeys(a);
    for ([_][]const u8{
        @embedFile("testdata/apk/APKINDEX.sha256.tar.gz"),
        @embedFile("testdata/apk/APKINDEX.sha1.tar.gz"),
    }) |data| {
        var idx: Index = .empty;
        const kept = try readIndex(a, keys, &idx, data);
        try testing.expectEqual(2, idx.count());
        try testing.expect(idx.contains("hello-1.0-r0.5c7ecd94"));
        try testing.expect(idx.contains("signed-1.0-r0.a8e22149"));
        // The index root keeps is valid too, with the same signature.
        var again: Index = .empty;
        try testing.expectEqualSlices(u8, kept, try readIndex(a, keys, &again, kept));
        try testing.expectEqual(2, again.count());

        // A flipped bit in the signed segment, or an unknown key name.
        const bad = try a.dupe(u8, data);
        bad[bad.len - 20] ^= 1;
        try testing.expectError(error.BadSignature, readIndex(a, keys, &idx, bad));
        const other = [_]Key{.{ .name = "other.rsa.pub", .key = keys[0].key }};
        try testing.expectError(error.UnknownKey, readIndex(a, &other, &idx, data));
        // Anything after the signed segment.
        const more = try std.mem.concat(a, u8, &.{ data, "x" });
        try testing.expectError(error.BadSignature, readIndex(a, keys, &idx, more));
    }
}

test "what lib/package.zig writes, the updater takes" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    // A package packed here, its stanza the index: checked as one fetched.
    const p = try package.pack(a, .{
        .name = "werewolf-hello",
        .version = "1-r0",
        .arch = "aarch64",
        .description = "hello",
        .time = 0,
    }, &.{
        .{ .path = "usr", .kind = .dir },
        .{ .path = "usr/bin", .kind = .dir },
        .{ .path = "usr/bin/hello", .kind = .file, .data = "hello\n" },
    });
    var idx: Index = .empty;
    try addPackages(a, &idx, p.stanza);
    try testing.expectEqual(1, idx.count());
    var keys = idx.keyIterator();
    const name = try a.print("{s}.apk", .{keys.next().?.*});
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = name, .data = p.bytes });
    try checkPackage(a, io, tmp.dir, name, &idx);
    const changed = try a.dupe(u8, p.bytes);
    changed[changed.len - 30] ^= 1;
    try tmp.dir.writeFile(io, .{ .sub_path = name, .data = changed });
    try testing.expectError(error.NotAsIndexed, checkPackage(a, io, tmp.dir, name, &idx));

    // The same package's index as build/host/package signs one (testdata,
    // signed offline with the key beside it): read, and the same package.
    const k = try releases.parseKey(a, @embedFile("testdata/apk/werewolf-test.rsa.pub"));
    var signed_idx: Index = .empty;
    _ = try readIndex(
        a,
        &.{.{ .name = "werewolf-test.rsa.pub", .key = k }},
        &signed_idx,
        @embedFile("testdata/apk/APKINDEX.werewolf.tar.gz"),
    );
    try testing.expectEqual(1, signed_idx.count());
    try testing.expect(signed_idx.contains(name[0 .. name.len - ".apk".len]));
}

test checkPackage {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var idx: Index = .empty;
    _ = try readIndex(a, try testKeys(a), &idx, @embedFile("testdata/apk/APKINDEX.sha256.tar.gz"));
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const hello = @embedFile("testdata/apk/hello-1.0-r0.5c7ecd94.apk");
    const signed = @embedFile("testdata/apk/signed-1.0-r0.a8e22149.apk");
    try tmp.dir.writeFile(io, .{ .sub_path = "hello-1.0-r0.5c7ecd94.apk", .data = hello });
    try tmp.dir.writeFile(io, .{ .sub_path = "signed-1.0-r0.a8e22149.apk", .data = signed });

    // Wolfi's is kept as is; Alpine's loses its signature.
    try checkPackage(a, io, tmp.dir, "hello-1.0-r0.5c7ecd94.apk", &idx);
    try testing.expectEqualSlices(
        u8,
        hello,
        try tmp.dir.readFileAlloc(io, "hello-1.0-r0.5c7ecd94.apk", a, .unlimited),
    );
    try checkPackage(a, io, tmp.dir, "signed-1.0-r0.a8e22149.apk", &idx);
    const kept = try tmp.dir.readFileAlloc(io, "signed-1.0-r0.a8e22149.apk", a, .unlimited);
    try testing.expect(std.mem.endsWith(u8, signed, kept) and kept.len < signed.len);
    try checkPackage(a, io, tmp.dir, "signed-1.0-r0.a8e22149.apk", &idx);

    // Not in an index; a control or data byte changed; another package's bytes.
    try tmp.dir.writeFile(io, .{ .sub_path = "hello-1.0-r1.5c7ecd94.apk", .data = hello });
    try testing.expectError(
        error.NotInIndex,
        checkPackage(a, io, tmp.dir, "hello-1.0-r1.5c7ecd94.apk", &idx),
    );
    for ([_]usize{ 30, hello.len - 30 }) |at| {
        const bad = try a.dupe(u8, hello);
        bad[at] ^= 1;
        try tmp.dir.writeFile(io, .{ .sub_path = "hello-1.0-r0.5c7ecd94.apk", .data = bad });
        try testing.expect(std.meta.isError(checkPackage(
            a,
            io,
            tmp.dir,
            "hello-1.0-r0.5c7ecd94.apk",
            &idx,
        )));
    }
    try tmp.dir.writeFile(io, .{ .sub_path = "hello-1.0-r0.5c7ecd94.apk", .data = kept });
    try testing.expectError(
        error.NotAsIndexed,
        checkPackage(a, io, tmp.dir, "hello-1.0-r0.5c7ecd94.apk", &idx),
    );
}

test addPackages {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var idx: Index = .empty;
    try addPackages(a, &idx, "C:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\nP:x\nV:1-r0\n\n\n");
    try testing.expect(idx.contains("x-1-r0.00000000"));
    for ([_][]const u8{
        "P:x\nV:1-r0\n",
        "C:Q2AAAAAAAAAAAAAAAAAAAAAAAAAAA=\nP:x\nV:1-r0\n",
        "C:Q1AAAA\nP:x\nV:1-r0\n",
        "C:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\nV:1-r0\n",
        "nonsense\n",
    }) |list| try testing.expectError(error.BadApkIndex, addPackages(a, &idx, list));
}
