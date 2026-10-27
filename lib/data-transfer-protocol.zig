//! Bounded decoder-to-publisher records. The publisher never receives tar,
//! compressed bytes or JSON. It rechecks every path, owner, mode and scope.
const std = @import("std");
const data = @import("data-transfer.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const magic = "WWDATA1\x00";
const end = "WWEND1\x00\x00";

pub fn write(w: *Io.Writer, result: data.Result) !void {
    const m = result.manifest;
    var size: usize = magic.len + 64 + 32 + 1 + 1 + 4 + end.len;
    size += if (m.service) |s| s.len else 0;
    for (m.entries) |e| size += 29 + e.path.len + e.owner.len + e.group.len;
    if (size > data.limits.manifest or m.entries.len > data.limits.entries) return error.TransferLimit;
    try w.writeAll(magic);
    try w.writeAll(&result.sha256);
    var image: [32]u8 = undefined;
    if (m.image.len != 64) return error.TransferImage;
    _ = try std.fmt.hexToBytes(&image, m.image);
    try w.writeAll(&image);
    try w.writeByte(@backingInt(m.arch));
    try w.writeByte(@intCast(if (m.service) |s| s.len else 0));
    if (m.service) |s| try w.writeAll(s);
    try integer(w, u32, @intCast(m.entries.len));
    for (m.entries) |e| {
        try integer(w, u16, @intCast(e.path.len));
        try w.writeByte(@intCast(e.owner.len));
        try w.writeByte(@intCast(e.group.len));
        try w.writeByte(@backingInt(e.kind));
        try integer(w, u32, e.mode);
        try integer(w, u64, e.size);
        try integer(w, i64, e.mtime_ns);
        if (e.default_acl) |acl| {
            try w.writeByte(1);
            try w.writeAll(&.{ acl.user, acl.group, acl.other });
        } else try w.writeAll(&.{ 0, 0, 0, 0 });
        try w.writeAll(e.path);
        try w.writeAll(e.owner);
        try w.writeAll(e.group);
    }
    try w.writeAll(end);
    try w.flush();
}

fn integer(w: *Io.Writer, comptime T: type, value: T) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    mem.writeInt(T, &bytes, value, .little);
    try w.writeAll(&bytes);
}

pub fn read(a: Allocator, reader: *Io.Reader, p: data.Policy, scope: ?[]const u8) !data.Result {
    var r: Input = .{ .reader = reader };
    var marker: [8]u8 = undefined;
    try r.take(&marker);
    if (!mem.eql(u8, &marker, magic)) return error.TransferProtocol;
    var sha256: [64]u8 = undefined;
    try r.take(&sha256);
    for (sha256) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f')) return error.TransferProtocol;
    var image: [32]u8 = undefined;
    try r.take(&image);
    if (!mem.eql(u8, &std.fmt.bytesToHex(image, .lower), p.image)) return error.TransferImage;
    const arch = try r.number(u8);
    if (arch != @backingInt(p.arch)) return error.TransferImage;
    const service_len = try r.number(u8);
    if (service_len > 64) return error.TransferLimit;
    const service = if (service_len == 0) null else try r.string(a, service_len);
    const count = try r.number(u32);
    if (count > data.limits.entries) return error.TransferLimit;
    const entries = try a.alloc(data.Entry, count);
    var total: u64 = 0;
    for (entries) |*entry| {
        const path_len = try r.number(u16);
        const owner_len = try r.number(u8);
        const group_len = try r.number(u8);
        if (path_len == 0 or path_len > data.limits.path or owner_len == 0 or owner_len > 31 or group_len == 0 or group_len > 31)
            return error.TransferLimit;
        const kind = try r.number(u8);
        if (kind > @backingInt(data.Kind.directory)) return error.TransferProtocol;
        const mode = try r.number(u32);
        const size = try r.number(u64);
        const mtime = try r.number(i64);
        var acl: [4]u8 = undefined;
        try r.take(&acl);
        if (acl[0] > 1 or acl[1] > 7 or acl[2] > 7 or acl[3] > 7 or
            (acl[0] == 0 and !mem.allEqual(u8, acl[1..], 0))) return error.TransferProtocol;
        entry.* = .{
            .path = try r.string(a, path_len),
            .owner = try r.string(a, owner_len),
            .group = try r.string(a, group_len),
            .kind = @fromBackingInt(@intCast(kind)),
            .mode = mode,
            .size = size,
            .mtime_ns = mtime,
            .default_acl = if (acl[0] == 0) null else .{ .user = @intCast(acl[1]), .group = @intCast(acl[2]), .other = @intCast(acl[3]) },
        };
        total = std.math.add(u64, total, size) catch return error.TransferLimit;
    }
    try r.take(&marker);
    if (!mem.eql(u8, &marker, end)) return error.TransferProtocol;
    if (reader.takeByte()) |_| return error.TransferTrailing else |err| if (err != error.EndOfStream) return err;
    const m: data.Manifest = .{ .image = p.image, .arch = p.arch, .service = service, .entries = entries };
    try data.check(a, m, p, scope);
    return .{ .manifest = m, .sha256 = sha256, .bytes = total };
}

const Input = struct {
    reader: *Io.Reader,
    bytes: usize = 0,
    fn take(r: *Input, out: []u8) !void {
        if (out.len > data.limits.manifest - r.bytes) return error.TransferLimit;
        try r.reader.readSliceAll(out);
        r.bytes += out.len;
    }
    fn number(r: *Input, comptime T: type) !T {
        var bytes: [@sizeOf(T)]u8 = undefined;
        try r.take(&bytes);
        return mem.readInt(T, &bytes, .little);
    }
    fn string(r: *Input, a: Allocator, n: usize) ![]const u8 {
        const out = try a.alloc(u8, n);
        try r.take(out);
        return out;
    }
};

test "publisher protocol rejects truncation, trailing bytes and widened scope" {
    const t = std.testing;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p: data.Policy = .{ .image = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", .arch = .aarch64, .services = &.{"plex"}, .users = &.{}, .groups = &.{} };
    const result: data.Result = .{ .manifest = .{ .image = p.image, .arch = p.arch, .entries = &.{} }, .sha256 = @splat('a'), .bytes = 0 };
    var out: Io.Writer.Allocating = .init(a);
    try write(&out.writer, result);
    var reader: Io.Reader = .fixed(out.written());
    _ = try read(a, &reader, p, null);
    for (0..out.written().len) |n| {
        reader = .fixed(out.written()[0..n]);
        if (read(a, &reader, p, null)) |_| return error.AcceptedTruncation else |_| {}
    }
    reader = .fixed(try mem.concat(a, u8, &.{ out.written(), "x" }));
    try t.expectError(error.TransferTrailing, read(a, &reader, p, null));
    reader = .fixed(out.written());
    try t.expectError(error.TransferService, read(a, &reader, p, "plex"));
}
