//! Explicit semantic comparisons shared by YAML probes and native tests.
const std = @import("std");
const Json = std.json.Value;
const Allocator = std.mem.Allocator;
extern fn werewolf_regex_match(pattern: [*:0]const u8, text: [*:0]const u8) c_int;

pub fn pointer(value: Json, path: []const u8) !Json {
    if (path.len == 0) return value;
    if (path[0] != '/') return error.InvalidJsonPointer;
    var current = value;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        var key: [1024]u8 = undefined;
        var n: usize = 0;
        var i: usize = 0;
        while (i < part.len) : (i += 1) {
            if (n == key.len) return error.InvalidJsonPointer;
            key[n] = part[i];
            if (part[i] == '~') {
                i += 1;
                if (i == part.len) return error.InvalidJsonPointer;
                key[n] = switch (part[i]) {
                    '0' => '~',
                    '1' => '/',
                    else => return error.InvalidJsonPointer,
                };
            }
            n += 1;
        }
        current = switch (current) {
            .object => |object| object.get(key[0..n]) orelse return error.MissingField,
            .array => |array| blk: {
                if (n == 0 or (n > 1 and key[0] == '0')) return error.InvalidJsonPointer;
                const index = std.fmt.parseInt(
                    usize,
                    key[0..n],
                    10,
                ) catch return error.InvalidJsonPointer;
                if (index >= array.items.len) return error.MissingField;
                break :blk array.items[index];
            },
            else => return error.MissingField,
        };
    }
    return current;
}

pub fn equal(a: Json, b: Json) bool {
    if (a == .integer and b == .float) return @as(f64, @floatFromInt(a.integer)) == b.float;
    if (a == .float and b == .integer) return a.float == @as(f64, @floatFromInt(b.integer));
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => a.bool == b.bool,
        .integer => a.integer == b.integer,
        .float => a.float == b.float,
        .string => std.mem.eql(u8, a.string, b.string),
        .number_string => std.mem.eql(u8, a.number_string, b.number_string),
        .array => blk: {
            if (a.array.items.len != b.array.items.len) break :blk false;
            for (a.array.items, b.array.items) |x, y| if (!equal(x, y)) break :blk false;
            break :blk true;
        },
        .object => blk: {
            if (a.object.count() != b.object.count()) break :blk false;
            var it = a.object.iterator();
            while (it.next()) |entry|
                if (!equal(
                    entry.value_ptr.*,
                    b.object.get(entry.key_ptr.*) orelse break :blk false,
                )) break :blk false;
            break :blk true;
        },
    };
}

fn contains(actual: Json, want: Json) !bool {
    if (actual == .string and
        want == .string) return std.mem.find(u8, actual.string, want.string) != null;
    if (actual == .array) {
        for (actual.array.items) |value| if (equal(value, want)) return true;
        return false;
    }
    return error.InvalidMatcher;
}

pub fn matches(arena: Allocator, got: Json, want: Json) !bool {
    if (want != .object) return equal(got, want);
    const operators = [_][]const u8{
        "equals",
        "contains",
        "contains_all",
        "contains_none",
        "absent",
        "one_of",
        "min",
        "max",
        "matches",
        "not_matches",
        "count",
        "occurrences",
        "type",
    };
    var special = false;
    for (operators) |op| if (want.object.contains(op)) {
        special = true;
        break;
    };
    if (!special) return equal(got, want);
    var it = want.object.iterator();
    var passed = true;
    while (it.next()) |entry| {
        const op = entry.key_ptr.*;
        const value = entry.value_ptr.*;
        const ok = if (std.mem.eql(u8, op, "equals"))
            equal(got, value)
        else if (std.mem.eql(u8, op, "contains"))
            try contains(got, value)
        else if (std.mem.eql(u8, op, "absent"))
            !try contains(got, value)
        else if (std.mem.eql(u8, op, "contains_all") or
            std.mem.eql(u8, op, "contains_none"))
        blk: {
            if (value != .array or value.array.items.len == 0) return error.InvalidMatcher;
            const present = std.mem.eql(u8, op, "contains_all");
            for (value.array.items) |item| {
                if (try contains(got, item) != present) break :blk false;
            }
            break :blk true;
        } else if (std.mem.eql(u8, op, "one_of")) blk: {
            if (value != .array) return error.InvalidMatcher;
            for (value.array.items) |allowed| if (equal(got, allowed)) break :blk true;
            break :blk false;
        } else if (std.mem.eql(u8, op, "occurrences")) blk: {
            if (got != .string or value != .object or value.object.count() == 0)
                return error.InvalidMatcher;
            var expected = value.object.iterator();
            var same = true;
            while (expected.next()) |entry_count| {
                const needle = entry_count.key_ptr.*;
                const count = entry_count.value_ptr.*;
                if (needle.len == 0 or count != .integer or count.integer < 0)
                    return error.InvalidMatcher;
                same = same and std.mem.count(u8, got.string, needle) == count.integer;
            }
            break :blk same;
        } else if (std.mem.eql(u8, op, "count")) blk: {
            if (value != .integer) return error.InvalidMatcher;
            const n: usize = switch (got) {
                .array => got.array.items.len,
                .object => got.object.count(),
                .string => got.string.len,
                else => return error.InvalidMatcher,
            };
            break :blk n == value.integer;
        } else if (std.mem.eql(u8, op, "min") or std.mem.eql(u8, op, "max")) blk: {
            const g: f64 = switch (got) {
                .integer => @floatFromInt(got.integer),
                .float => got.float,
                else => return error.InvalidMatcher,
            };
            const w: f64 = switch (value) {
                .integer => @floatFromInt(value.integer),
                .float => value.float,
                else => return error.InvalidMatcher,
            };
            break :blk if (std.mem.eql(u8, op, "min")) g >= w else g <= w;
        } else if (std.mem.eql(u8, op, "type")) blk: {
            if (value != .string) return error.InvalidMatcher;
            break :blk std.mem.eql(u8, @tagName(got), value.string);
        } else if (std.mem.eql(u8, op, "matches") or std.mem.eql(u8, op, "not_matches")) blk: {
            if (got != .string or value != .string or value.string.len > 512 or
                std.mem.findScalar(u8, value.string, 0) != null or
                std.mem.findScalar(u8, got.string, 0) != null)
                return error.InvalidMatcher;
            const result = werewolf_regex_match(
                (try arena.dupeSentinel(u8, value.string, 0)).ptr,
                (try arena.dupeSentinel(u8, got.string, 0)).ptr,
            );
            if (result < 0) return error.InvalidRegex;
            break :blk result == (if (std.mem.eql(u8, op, "matches")) @as(c_int, 1) else 0);
        } else return error.InvalidMatcher;
        passed = passed and ok;
    }
    return passed;
}

test "JSON comparisons preserve structure and resolve escaped pointers" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const actual = try std.json.parseFromSliceLeaky(
        Json,
        a,
        "{\"a/b\": [1, 2], \"ok\":true}",
        .{},
    );
    const reordered = try std.json.parseFromSliceLeaky(
        Json,
        a,
        "{\"ok\":true, \"a/b\":[1,2]}",
        .{},
    );
    try std.testing.expect(equal(actual, reordered));
    try std.testing.expectEqual(@as(i64, 2), (try pointer(actual, "/a~1b/1")).integer);
    try std.testing.expectError(error.MissingField, pointer(actual, "/missing"));
    try std.testing.expectError(error.InvalidJsonPointer, pointer(actual, "/a~1b/01"));
    const want = try std.json.parseFromSliceLeaky(Json, a, "{\"min\":1,\"max\":3}", .{});
    try std.testing.expect(try matches(a, .{ .integer = 2 }, want));
    try std.testing.expect(!try matches(a, .{ .integer = 4 }, want));
    const unknown = try std.json.parseFromSliceLeaky(Json, a, "{\"min\":1,\"typo\":3}", .{});
    try std.testing.expectError(error.InvalidMatcher, matches(a, .{ .integer = 2 }, unknown));
}

test "absence with an incompatible type must not pass" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const invalid = try std.json.parseFromSliceLeaky(Json, a, "{\"absent\":1}", .{});
    try std.testing.expectError(error.InvalidMatcher, matches(a, .{ .string = "secret" }, invalid));
}

test "negative regex rejects matches, malformed patterns and incompatible input" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try std.json.parseFromSliceLeaky(
        Json,
        a,
        "{\"not_matches\":\"[Ii][Nn][Ss][Tt][Aa][Ll][Ll]\"}",
        .{},
    );
    try std.testing.expect(try matches(a, .{ .string = "werewolf check site" }, want));
    try std.testing.expect(!try matches(a, .{ .string = "Install WordPress" }, want));
    try std.testing.expect(!try matches(a, .{ .string = "INSTALL WordPress" }, want));
    try std.testing.expectError(error.InvalidMatcher, matches(a, .{ .integer = 0 }, want));
    try std.testing.expectError(
        error.InvalidMatcher,
        matches(a, .{ .string = "safe\x00Install" }, want),
    );
    const invalid = try std.json.parseFromSliceLeaky(Json, a, "{\"not_matches\":\"[\"}", .{});
    try std.testing.expectError(error.InvalidRegex, matches(a, .{ .string = "safe" }, invalid));
}

test "literal occurrence counts are exact and do not prove absence in non-text values" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try std.json.parseFromSliceLeaky(Json, a,
        \\{"occurrences":{"<listenAddress>":3,"forbidden":0}}
    , .{});
    try std.testing.expect(try matches(
        a,
        .{ .string = "<listenAddress>a<listenAddress>b<listenAddress>c" },
        want,
    ));
    try std.testing.expect(!try matches(a, .{ .string = "<listenAddress><listenAddress>" }, want));
    try std.testing.expect(!try matches(
        a,
        .{ .string = "<listenAddress><listenAddress><listenAddress>forbidden" },
        want,
    ));
    try std.testing.expectError(error.InvalidMatcher, matches(a, .{ .integer = 0 }, want));
    for ([_][]const u8{ "{\"occurrences\":{\"\":0}}", "{\"occurrences\":{\"x\":-1}}" }) |bad| {
        const invalid = try std.json.parseFromSliceLeaky(Json, a, bad, .{});
        try std.testing.expectError(
            error.InvalidMatcher,
            matches(a, .{ .string = "text" }, invalid),
        );
    }
}
