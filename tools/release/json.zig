//! json reads and writes release records exactly as Python's json module
//! wrote them for the scripts this tool replaced: a signed or published
//! record keeps its bytes. encode is json.dumps(sort_keys=True,
//! separators=(',', ':')) plus a newline; dumps is plain json.dumps.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Writer = std.Io.Writer;

pub const Json = std.json.Value;
pub const Map = std.json.ObjectMap;
pub const List = std.json.Array;

/// parse reads one JSON document. A repeated key keeps its last value.
pub fn parse(gpa: Allocator, bytes: []const u8) !Json {
    var v = try std.json.parseFromSliceLeaky(Json, gpa, bytes, .{
        .duplicate_field_behavior = .use_last,
        .allocate = .alloc_always,
        .parse_numbers = false,
    });
    numbers(&v);
    return v;
}

/// numbers reads numbers as Python does: without a fraction or exponent
/// an int (so -0 is 0), otherwise a float. An int too big for i64 keeps
/// its digits.
fn numbers(v: *Json) void {
    switch (v.*) {
        .number_string => |s| {
            if (mem.findAny(u8, s, ".eE") != null) {
                v.* = .{ .float = std.fmt.parseFloat(f64, s) catch unreachable };
            } else if (std.fmt.parseInt(i64, s, 10)) |i| {
                v.* = .{ .integer = i };
            } else |_| {}
        },
        .array => |a| for (a.items) |*item| numbers(item),
        .object => |o| for (o.values()) |*item| numbers(item),
        else => {},
    }
}

pub const Style = enum {
    /// sorted keys, no spaces: what is hashed, signed and published.
    canonical,
    /// insertion order, ", " and ": ": what GitHub Actions reads.
    python,
};

/// encode is the canonical form of v and a newline.
pub fn encode(gpa: Allocator, v: Json) ![]u8 {
    var out: Writer.Allocating = .init(gpa);
    try write(gpa, &out.writer, v, .canonical);
    try out.writer.writeByte('\n');
    return out.toOwnedSlice();
}

/// dumps is v as Python's json.dumps(v) prints it.
pub fn dumps(gpa: Allocator, v: Json) ![]u8 {
    var out: Writer.Allocating = .init(gpa);
    try write(gpa, &out.writer, v, .python);
    return out.toOwnedSlice();
}

pub const WriteError = Writer.Error || Allocator.Error || error{InvalidUtf8};

pub fn write(gpa: Allocator, w: *Writer, v: Json, style: Style) WriteError!void {
    const comma = if (style == .canonical) "," else ", ";
    const colon = if (style == .canonical) ":" else ": ";
    switch (v) {
        .null => try w.writeAll("null"),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .integer => |i| try w.print("{d}", .{i}),
        .float => |f| try float(w, f),
        .number_string => |s| try w.writeAll(s),
        .string => |s| try string(w, s),
        .array => |a| {
            try w.writeByte('[');
            for (a.items, 0..) |item, i| {
                if (i > 0) try w.writeAll(comma);
                try write(gpa, w, item, style);
            }
            try w.writeByte(']');
        },
        .object => |o| {
            const names = try gpa.dupe([]const u8, o.keys());
            defer gpa.free(names);
            if (style == .canonical) mem.sort([]const u8, names, {}, less);
            try w.writeByte('{');
            for (names, 0..) |key, i| {
                if (i > 0) try w.writeAll(comma);
                try string(w, key);
                try w.writeAll(colon);
                try write(gpa, w, o.get(key).?, style);
            }
            try w.writeByte('}');
        },
    }
}

/// less orders keys as Python sorts str: by code point, which is UTF-8
/// byte order.
pub fn less(_: void, a: []const u8, b: []const u8) bool {
    return mem.order(u8, a, b) == .lt;
}

/// string escapes as ensure_ascii does: printable ASCII stays, the rest
/// is \uXXXX in lowercase hex, a surrogate pair above the BMP.
fn string(w: *Writer, s: []const u8) WriteError!void {
    if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8;
    try std.json.Stringify.encodeJsonString(s, .{ .escape_unicode = true }, w);
}

/// float is Python's repr: the shortest digits that read back the same,
/// positional from 1e-4 to 1e16 with at least one fractional digit,
/// otherwise d.ddde+XX.
fn float(w: *Writer, f: f64) Writer.Error!void {
    if (std.math.isNan(f)) return w.writeAll("NaN");
    if (std.math.isInf(f)) return w.writeAll(if (f < 0) "-Infinity" else "Infinity");
    var buf: [64]u8 = undefined;
    const sci = std.fmt.float.render(&buf, f, .{ .mode = .scientific }) catch unreachable;
    const e_at = mem.findScalar(u8, sci, 'e').?;
    const exp = std.fmt.parseInt(i32, sci[e_at + 1 ..], 10) catch unreachable;
    var digits_buf: [32]u8 = undefined;
    var n: usize = 0;
    const negative = sci[0] == '-';
    for (sci[@intFromBool(negative)..e_at]) |c| if (c != '.') {
        digits_buf[n] = c;
        n += 1;
    };
    const digits = digits_buf[0..n];
    if (negative) try w.writeByte('-');
    if (exp < -4 or exp >= 16) {
        try w.writeByte(digits[0]);
        if (digits.len > 1) {
            try w.writeByte('.');
            try w.writeAll(digits[1..]);
        }
        const sign: u8 = if (exp < 0) '-' else '+';
        return w.print("e{c}{d:0>2}", .{ sign, @abs(exp) });
    }
    if (exp < 0) {
        try w.writeAll("0.");
        try w.splatByteAll('0', @intCast(-exp - 1));
        return w.writeAll(digits);
    }
    const whole: usize = @intCast(exp + 1);
    if (digits.len <= whole) {
        try w.writeAll(digits);
        try w.splatByteAll('0', whole - digits.len);
        return w.writeAll(".0");
    }
    try w.writeAll(digits[0..whole]);
    try w.writeByte('.');
    try w.writeAll(digits[whole..]);
}

/// eql is Python's == on parsed JSON, except that a bool never equals a
/// number: every check here that compares records also refuses that.
pub fn eql(a: Json, b: Json) bool {
    switch (a) {
        .null => return b == .null,
        .bool => |x| return b == .bool and b.bool == x,
        .string => |x| return b == .string and mem.eql(u8, x, b.string),
        .integer, .float, .number_string => return number(a, b),
        .array => |x| {
            if (b != .array or b.array.items.len != x.items.len) return false;
            for (x.items, b.array.items) |l, r| if (!eql(l, r)) return false;
            return true;
        },
        .object => |x| {
            if (b != .object or b.object.count() != x.count()) return false;
            var it = x.iterator();
            while (it.next()) |e| {
                const other = b.object.get(e.key_ptr.*) orelse return false;
                if (!eql(e.value_ptr.*, other)) return false;
            }
            return true;
        },
    }
}

fn number(a: Json, b: Json) bool {
    if (b != .integer and b != .float and b != .number_string) return false;
    if (a == .number_string and
        b == .number_string) return mem.eql(u8, a.number_string, b.number_string);
    if (a == .integer and b == .integer) return a.integer == b.integer;
    if (a == .number_string or b == .number_string) return false;
    return asFloat(a) == asFloat(b);
}

fn asFloat(v: Json) f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        else => unreachable,
    };
}

/// from builds a Json from x: strings, integers, bools, null, optionals,
/// slices and structs, whose fields keep their declared order.
pub fn from(gpa: Allocator, x: anytype) Allocator.Error!Json {
    const T = @TypeOf(x);
    if (T == Json) return x;
    if (T == Map) return .{ .object = x };
    switch (@typeInfo(T)) {
        .null => return .null,
        .bool => return .{ .bool = x },
        .int, .comptime_int => return .{ .integer = @intCast(x) },
        .optional => return if (x) |inner| from(gpa, inner) else .null,
        .pointer => |p| {
            if (p.size == .one and @typeInfo(p.child) == .array) {
                const elem = @typeInfo(p.child).array.child;
                if (elem == u8) return .{ .string = x };
                return from(gpa, @as([]const elem, x));
            }
            if (p.size == .slice and p.child == u8) return .{ .string = x };
            if (p.size == .slice) {
                var list: List = .init(gpa);
                for (x) |item| try list.append(try from(gpa, item));
                return .{ .array = list };
            }
            @compileError("json.from: unsupported pointer " ++ @typeName(T));
        },
        .@"struct" => |s| {
            var map: Map = .empty;
            inline for (s.field_names) |name| {
                const value = try from(gpa, @field(x, name));
                // Default-selection records retain their historical wire shape.
                const omit = if (comptime mem.eql(u8, name, "variants"))
                    value == .array and value.array.items.len == 0
                else
                    false;
                if (!omit) try map.put(gpa, name, value);
            }
            return .{ .object = map };
        },
        else => @compileError("json.from: unsupported type " ++ @typeName(T)),
    }
}

/// get is v's member key, or null when v is no object or lacks it.
pub fn get(v: Json, key: []const u8) ?Json {
    if (v != .object) return null;
    return v.object.get(key);
}

/// field is v[key], as Python's KeyError refuses a record without it.
pub fn field(v: Json, key: []const u8) error{Record}!Json {
    return get(v, key) orelse error.Record;
}

pub fn text(v: Json, key: []const u8) error{Record}![]const u8 {
    const f = try field(v, key);
    return if (f == .string) f.string else error.Record;
}

/// int is v[key] when Python's type() would say int: never a bool.
pub fn int(v: Json, key: []const u8) error{Record}!i64 {
    const f = try field(v, key);
    return if (f == .integer) f.integer else error.Record;
}

pub fn object(v: Json) error{Record}!Map {
    return if (v == .object) v.object else error.Record;
}

pub fn items(v: Json) error{Record}![]Json {
    return if (v == .array) v.array.items else error.Record;
}

/// keys are an object's member names, sorted.
pub fn keys(gpa: Allocator, v: Json) ![]const []const u8 {
    const o = try object(v);
    const names = try gpa.dupe([]const u8, o.keys());
    mem.sort([]const u8, names, {}, less);
    return names;
}

/// hasKeys says whether v is an object with exactly these keys.
pub fn hasKeys(v: Json, names: []const []const u8) bool {
    if (v != .object or v.object.count() != names.len) return false;
    for (names) |n| if (v.object.get(n) == null) return false;
    return true;
}

const testing = std.testing;

test "canonical encoding sorts keys, escapes non-ASCII and keeps integers" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // json.dumps(json.loads(s), sort_keys=True, separators=(',', ':')) + '\n'
    const cases = [_][2][]const u8{
        .{ "{\"b\":1,\"a\":[true,null,\"x\"]}", "{\"a\":[true,null,\"x\"],\"b\":1}\n" },
        .{
            "\"caf\\u00e9 \\ud83d\\ude00 \\u007f\\t\\\"\"",
            "\"caf\\u00e9 \\ud83d\\ude00 \\u007f\\t\\\"\"\n",
        },
        .{ "\"\xc3\xa9\x7f/\"", "\"\\u00e9\\u007f/\"\n" },
        .{ "{\"\\u00e9\":0,\"z\":-0,\"e\":{}}", "{\"e\":{},\"z\":0,\"\\u00e9\":0}\n" },
        .{
            "[123456789012345678901234567890, 1.0, 1.5e20, 0.0001, 1e-5, 2.5]",
            "[123456789012345678901234567890,1.0,1.5e+20,0.0001,1e-05,2.5]\n",
        },
        .{
            "[1e16, 1234567890123456.0, 0.1, -3.25e-7, 100.0]",
            "[1e+16,1234567890123456.0,0.1,-3.25e-07,100.0]\n",
        },
    };
    for (cases) |c| try testing.expectEqualStrings(c[1], try encode(a, try parse(a, c[0])));
}

test "python style keeps insertion order and spaces" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = try from(
        a,
        .{ .include = &[_]Json{try from(a, .{ .z = "x", .a = 1 })}, .e = &[_]Json{} },
    );
    try testing.expectEqualStrings(
        "{\"include\": [{\"z\": \"x\", \"a\": 1}], \"e\": []}",
        try dumps(a, v),
    );
}

test "equality is Python's, but a bool is never a number" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expect(eql(
        try parse(a, "{\"a\":1,\"b\":[1.0]}"),
        try parse(a, "{\"b\":[1],\"a\":1}"),
    ));
    try testing.expect(!eql(try parse(a, "{\"a\":true}"), try parse(a, "{\"a\":1}")));
    try testing.expect(!eql(try parse(a, "{\"a\":1}"), try parse(a, "{\"a\":1,\"b\":1}")));
    try testing.expectError(error.Record, int(try parse(a, "{\"a\":true}"), "a"));
    try testing.expectError(error.Record, int(try parse(a, "{\"a\":1.0}"), "a"));
    try testing.expectEqual(@as(i64, 3), try int(try parse(a, "{\"a\":3}"), "a"));
}

test "invalid UTF-8 is never written" {
    var buf: [16]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try testing.expectError(
        error.InvalidUtf8,
        write(testing.allocator, &w, .{ .string = "\xff" }, .canonical),
    );
}
