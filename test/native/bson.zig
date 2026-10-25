//! Narrow BSON encoder/reader and OP_MSG exchange for fixed MongoDB commands.
//! Formats: https://bsonspec.org/spec.html and
//! https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Json = std.json.Value;

/// Send one OP_MSG command document to the local server and return the
/// reply's body document, which has an ok field.
pub fn exchange(io: Io, a: Allocator, doc: []const u8) ![]const u8 {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(27017) };
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var out_buffer: [1024]u8 = undefined;
    var in_buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &out_buffer);
    var reader = stream.reader(io, &in_buffer);
    return message(&reader.interface, &writer.interface, a, doc);
}

fn message(in: *Io.Reader, out: *Io.Writer, a: Allocator, doc: []const u8) ![]const u8 {
    var header: [21]u8 = @splat(0);
    std.mem.writeInt(u32, header[0..4], @intCast(header.len + doc.len), .little);
    std.mem.writeInt(u32, header[4..8], 1, .little);
    std.mem.writeInt(u32, header[12..16], 2013, .little);
    try out.writeAll(&header);
    try out.writeAll(doc);
    try out.flush();
    try in.readSliceAll(header[0..16]);
    const n = std.mem.readInt(u32, header[0..4], .little);
    if (n < 26 or n > 1 << 20 or std.mem.readInt(u32, header[8..12], .little) != 1 or
        std.mem.readInt(u32, header[12..16], .little) != 2013) return error.ResponseHeader;
    const payload = try a.alloc(u8, n - 16);
    try in.readSliceAll(payload);
    if (std.mem.readInt(u32, payload[0..4], .little) != 0 or payload[4] != 0)
        return error.ResponseSections;
    _ = try require(payload[5..], "ok");
    return payload[5..];
}

pub fn encode(a: Allocator, json: []const u8) ![]const u8 {
    if (json.len > 65536) return error.RequestTooLarge;
    const value = try std.json.parseFromSliceLeaky(Json, a, json, .{});
    if (value != .object) return error.DocumentRequired;
    var buffer: std.ArrayList(u8) = .empty;
    try document(a, &buffer, value, 0);
    return buffer.toOwnedSlice(a);
}
fn document(a: Allocator, out: *std.ArrayList(u8), value: Json, depth: u8) anyerror!void {
    if (depth > 16) return error.NestingLimit;
    const start = out.items.len;
    try out.appendSlice(a, &.{ 0, 0, 0, 0 });
    if (value == .object) {
        var fields = value.object.iterator();
        while (fields.next()) |entry| try element(
            a,
            out,
            entry.key_ptr.*,
            entry.value_ptr.*,
            depth,
        );
    } else if (value == .array) {
        for (value.array.items, 0..) |item, index|
            try element(a, out, try a.print("{d}", .{index}), item, depth);
    } else return error.DocumentRequired;
    try out.append(a, 0);
    if (out.items.len > 65536) return error.RequestTooLarge;
    std.mem.writeInt(u32, out.items[start..][0..4], @intCast(out.items.len - start), .little);
}
fn element(a: Allocator, out: *std.ArrayList(u8), name: []const u8, value: Json, depth: u8) !void {
    if (std.mem.findScalar(u8, name, 0) != null) return error.InvalidName;
    const tag: u8 = switch (value) {
        .integer => 0x10,
        .string => 2,
        .bool => 8,
        .object => 3,
        .array => 4,
        .null => 10,
        else => return error.UnsupportedValue,
    };
    try out.append(a, tag);
    try out.appendSlice(a, name);
    try out.append(a, 0);
    switch (value) {
        .integer => |number| {
            const n = std.math.cast(i32, number) orelse return error.IntegerRange;
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(i32, &bytes, n, .little);
            try out.appendSlice(a, &bytes);
        },
        .string => |text| {
            if (text.len > 65536) return error.RequestTooLarge;
            var size_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &size_bytes, @intCast(text.len + 1), .little);
            try out.appendSlice(a, &size_bytes);
            try out.appendSlice(a, text);
            try out.append(a, 0);
        },
        .bool => |boolean| try out.append(a, @intFromBool(boolean)),
        .null => {},
        .object, .array => try document(a, out, value, depth + 1),
        else => unreachable,
    }
}

pub const Field = struct {
    tag: u8,
    bytes: []const u8,

    pub fn string(value: Field) ![]const u8 {
        if (value.tag != 2) return error.StringRequired;
        return value.bytes[4 .. value.bytes.len - 1];
    }
    pub fn number(value: Field) !f64 {
        return switch (value.tag) {
            1 => @bitCast(std.mem.readInt(u64, value.bytes[0..8], .little)),
            0x10 => @floatFromInt(std.mem.readInt(i32, value.bytes[0..4], .little)),
            0x12 => @floatFromInt(std.mem.readInt(i64, value.bytes[0..8], .little)),
            else => error.NumberRequired,
        };
    }
    pub fn object(value: Field, tag: u8) ![]const u8 {
        if (value.tag != tag) return error.DocumentRequired;
        return value.bytes;
    }
};

pub fn field(doc: []const u8, name: []const u8) !?Field {
    if (doc.len < 5 or doc.len > 1 << 20 or try length(doc) != doc.len or doc[doc.len - 1] != 0)
        return error.InvalidDocument;
    var offset: usize = 4;
    var found: ?Field = null;
    while (offset < doc.len - 1) {
        const tag = doc[offset];
        offset += 1;
        const key_end = std.mem.findScalar(u8, doc[offset .. doc.len - 1], 0) orelse
            return error.InvalidName;
        const key = doc[offset..][0..key_end];
        offset += key_end + 1;
        const rest = doc[offset .. doc.len - 1];
        const size: usize = switch (tag) {
            1, 9, 0x11, 0x12 => 8,
            2 => try stringSize(rest),
            3, 4 => try documentSize(rest),
            5 => 5 + try length(rest),
            7 => 12,
            8 => 1,
            10 => 0,
            0x10 => 4,
            0x13 => 16,
            else => return error.UnsupportedValue,
        };
        if (size > rest.len) return error.TruncatedValue;
        if (tag == 8 and rest[0] > 1) return error.InvalidBoolean;
        if (std.mem.eql(u8, key, name)) {
            if (found != null) return error.DuplicateField;
            found = .{ .tag = tag, .bytes = rest[0..size] };
        }
        offset += size;
    }
    return found;
}
pub fn require(doc: []const u8, name: []const u8) !Field {
    return try field(doc, name) orelse error.MissingField;
}
fn length(bytes: []const u8) !usize {
    if (bytes.len < 4) return error.TruncatedValue;
    return std.mem.readInt(u32, bytes[0..4], .little);
}
fn stringSize(bytes: []const u8) !usize {
    const n = try length(bytes);
    if (n < 1 or n > bytes.len - 4 or bytes[4 + n - 1] != 0) return error.InvalidString;
    return n + 4;
}
fn documentSize(bytes: []const u8) !usize {
    const n = try length(bytes);
    if (n < 5 or n > bytes.len or bytes[n - 1] != 0) return error.InvalidDocument;
    return n;
}

test "BSON fields are structural, bounded and reject duplicate status fields" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const reply = try encode(
        a,
        "{\"nested\":{\"ok\":1},\"ok\":0,\"text\":\"hello\",\"rows\":[{\"value\":\"kept\"}]}",
    );
    try std.testing.expectEqual(@as(f64, 0), try (try require(reply, "ok")).number());
    try std.testing.expectEqualStrings("hello", try (try require(reply, "text")).string());
    const rows = try (try require(reply, "rows")).object(4);
    const first = try (try require(rows, "0")).object(3);
    try std.testing.expectEqualStrings("kept", try (try require(first, "value")).string());
    try std.testing.expectError(error.InvalidDocument, field(reply[0 .. reply.len - 1], "ok"));
    const dup = "\x15\x00\x00\x00\x10ok\x00\x01\x00\x00\x00\x10ok\x00\x00\x00\x00\x00\x00";
    try std.testing.expectError(error.DuplicateField, field(dup, "ok"));
    const bad = "\x0f\x00\x00\x00\x02x\x00\xff\xff\xff\xffabc\x00";
    try std.testing.expectError(error.InvalidString, field(bad, "x"));
}

test "OP_MSG frames one body section and checks the reply's header" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = try encode(a, "{\"ping\":1}");
    const ok = try encode(a, "{\"ok\":1}");
    try std.testing.expectEqual(@as(usize, 13), ok.len);
    const reply = "\x22\x00\x00\x00\x09\x00\x00\x00\x01\x00\x00\x00\xdd\x07\x00\x00" ++
        "\x00\x00\x00\x00\x00";
    var sent: [64]u8 = undefined;
    var out: Io.Writer = .fixed(&sent);
    var in: Io.Reader = .fixed(try std.mem.concat(a, u8, &.{ reply, ok }));
    try std.testing.expectEqualSlices(u8, ok, try message(&in, &out, a, doc));
    try std.testing.expectEqualSlices(
        u8,
        "\x24\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00\x00",
        out.buffered()[0..21],
    );
    try std.testing.expectEqualSlices(u8, doc, out.buffered()[21..]);
    const stale = try std.mem.concat(a, u8, &.{ reply[0..8], "\x02\x00\x00\x00", reply[12..], ok });
    in = .fixed(stale);
    out.end = 0;
    try std.testing.expectError(error.ResponseHeader, message(&in, &out, a, doc));
}
