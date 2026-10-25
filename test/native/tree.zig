//! tree audits what lies below a step's roots, never following symbolic
//! links: it counts entries and regular files, holds each entry's path,
//! name, type and mode to the step's rules, and searches each regular
//! file for bytes it must not contain. Entries, depth, bytes and time are
//! bounded; anything unreadable fails the audit rather than shrinking it.
const std = @import("std");
const match = @import("match.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Json = std.json.Value;
const mem = std.mem;

extern fn werewolf_regex_match(pattern: [*:0]const u8, text: [*:0]const u8) c_int;

pub const Limits = struct {
    entries: usize = 100_000,
    depth: usize = 64,
    bytes: u64 = 256 << 20,
};

/// max_needle bounds what content may refuse, and so what a search keeps
/// between reads.
pub const max_needle = 4096;
pub const max_violations = 4;

/// Rules are a step's per-entry expectations, in match.zig's vocabulary.
/// An entry whose root-relative path matches an allow pattern is counted
/// but exempt from them.
pub const Rules = struct {
    allow: []const []const u8 = &.{},
    type: ?Json = null,
    path: ?Json = null,
    name: ?Json = null,
    mode: ?Json = null,
    /// absent are byte strings no regular file may contain.
    absent: []const []const u8 = &.{},
};

/// Violation is a broken rule. value is never file content.
pub const Violation = struct { field: []const u8, path: []const u8, value: []const u8 };

pub const Found = struct {
    entries: usize = 0,
    files: usize = 0,
    /// violations holds the first few broken rules, in walk order.
    violations: std.ArrayList(Violation) = .empty,
};

pub fn audit(
    io: Io,
    a: Allocator,
    roots: []const []const u8,
    rules: Rules,
    limits: Limits,
    deadline: Io.Timestamp,
) !Found {
    var longest: usize = 0;
    for (rules.absent) |needle| {
        if (needle.len == 0 or needle.len > max_needle) return error.InvalidContentRule;
        longest = @max(longest, needle.len);
    }
    var w: Walk = .{
        .io = io,
        .a = a,
        .rules = rules,
        .limits = limits,
        .deadline = deadline,
        .keep = longest -| 1,
        .scratch = .init(a),
        .buffer = if (rules.absent.len > 0) try a.alloc(u8, 64 << 10) else &.{},
    };
    defer w.scratch.deinit();
    for (roots) |root| {
        var dir = try Io.Dir.cwd().openDir(
            io,
            root,
            .{ .iterate = true, .follow_symlinks = false },
        );
        defer dir.close(io);
        w.root = root;
        w.path.clearRetainingCapacity();
        try w.descend(dir, 0);
    }
    return w.found;
}

const Walk = struct {
    io: Io,
    a: Allocator,
    rules: Rules,
    limits: Limits,
    deadline: Io.Timestamp,
    /// keep is how many bytes a content search carries between reads.
    keep: usize,
    scratch: std.heap.ArenaAllocator,
    buffer: []u8,
    root: []const u8 = "",
    path: std.ArrayList(u8) = .empty,
    bytes: u64 = 0,
    found: Found = .{},

    fn descend(w: *Walk, dir: Io.Dir, depth: usize) anyerror!void {
        if (depth >= w.limits.depth) return error.TreeTooDeep;
        var it = dir.iterate();
        while (try it.next(w.io)) |entry| {
            if (Io.Clock.awake.now(w.io).compare(.gte, w.deadline)) return error.Timeout;
            // A live tree changes as it is read; what vanished cannot be judged.
            const stat = dir.statFile(w.io, entry.name, .{ .follow_symlinks = false }) catch |err|
                switch (err) {
                    error.FileNotFound => continue,
                    else => return err,
                };
            w.found.entries += 1;
            if (w.found.entries > w.limits.entries) return error.TooManyEntries;
            const parent = w.path.items.len;
            defer w.path.shrinkRetainingCapacity(parent);
            if (parent > 0) try w.path.append(w.a, '/');
            try w.path.appendSlice(w.a, entry.name);
            if (w.path.items.len > 4096) return error.NameTooLong;
            _ = w.scratch.reset(.retain_capacity);
            const exempt = try w.allowed();
            if (!exempt) try w.check(entry.name, stat);
            switch (stat.kind) {
                .file => {
                    w.found.files += 1;
                    if (!exempt and w.rules.absent.len > 0) try w.search(dir, entry.name);
                },
                .directory => {
                    var child = dir.openDir(w.io, entry.name, .{
                        .iterate = true,
                        .follow_symlinks = false,
                    }) catch |err| switch (err) {
                        error.FileNotFound => continue,
                        else => return err,
                    };
                    defer child.close(w.io);
                    try w.descend(child, depth + 1);
                },
                else => {},
            }
        }
    }

    fn allowed(w: *Walk) !bool {
        if (w.rules.allow.len == 0) return false;
        const a = w.scratch.allocator();
        const text = try a.dupeSentinel(u8, w.path.items, 0);
        for (w.rules.allow) |pattern| {
            const result = werewolf_regex_match((try a.dupeSentinel(u8, pattern, 0)).ptr, text.ptr);
            if (result < 0) return error.InvalidRegex;
            if (result == 1) return true;
        }
        return false;
    }

    fn check(w: *Walk, name: []const u8, stat: Io.File.Stat) !void {
        try w.rule("type", typeName(stat.kind), w.rules.type);
        try w.rule("path", w.path.items, w.rules.path);
        try w.rule("name", name, w.rules.name);
        // A symbolic link's mode is always 777 and means nothing.
        if (stat.kind != .sym_link and w.rules.mode != null) try w.rule(
            "mode",
            try w.scratch.allocator().print("{o}", .{stat.permissions.toMode() & 0o7777}),
            w.rules.mode,
        );
    }

    fn rule(w: *Walk, field: []const u8, value: []const u8, want: ?Json) !void {
        if (try match.matches(w.scratch.allocator(), .{ .string = value }, want orelse return))
            return;
        try w.violate(field, value);
    }

    fn violate(w: *Walk, field: []const u8, value: []const u8) !void {
        if (w.found.violations.items.len == max_violations) return;
        try w.found.violations.append(w.a, .{
            .field = field,
            .path = try w.a.print("{s}/{s}", .{ w.root, w.path.items }),
            .value = try w.a.dupe(u8, value),
        });
    }

    /// search reads one regular file in pieces, keeping the tail of each so
    /// a needle split between reads is still found.
    fn search(w: *Walk, dir: Io.Dir, name: []const u8) !void {
        var file = dir.openFile(w.io, name, .{
            .follow_symlinks = false,
            .allow_directory = false,
        }) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer file.close(w.io);
        if ((try file.stat(w.io)).kind != .file) return error.FileReplaced;
        var kept: usize = 0;
        while (true) {
            if (Io.Clock.awake.now(w.io).compare(.gte, w.deadline)) return error.Timeout;
            const n = file.readStreaming(w.io, &.{w.buffer[kept..]}) catch |err| switch (err) {
                error.EndOfStream => return,
                else => return err,
            };
            w.bytes += n;
            if (w.bytes > w.limits.bytes) return error.TooMuchContent;
            const window = w.buffer[0 .. kept + n];
            for (w.rules.absent) |needle| if (mem.find(u8, window, needle) != null)
                return w.violate("content", "");
            kept = @min(w.keep, window.len);
            @memmove(w.buffer[0..kept], window[window.len - kept ..]);
        }
    }
};

/// probe audits what a validated step asks for, its references resolved,
/// and says what it found: entries, files and violations.
pub fn probe(io: Io, a: Allocator, request: Json, expect: Json, timeout_ms: i64) !Json {
    const roots = if (request == .string) try a.dupe([]const u8, &.{request.string}) else blk: {
        const list = request.object.get("roots").?.array.items;
        const out = try a.alloc([]const u8, list.len);
        for (list, out) |root, *o| o.* = root.string;
        break :blk out;
    };
    var r: Rules = .{
        .type = expect.object.get("type"),
        .path = expect.object.get("path"),
        .name = expect.object.get("name"),
        .mode = expect.object.get("mode"),
    };
    if (request == .object) if (request.object.get("allow")) |allow| {
        const patterns = try a.alloc([]const u8, allow.array.items.len);
        for (allow.array.items, patterns) |p, *o| o.* = p.string;
        r.allow = patterns;
    };
    if (expect.object.get("content")) |content| {
        var needles: std.ArrayList([]const u8) = .empty;
        if (content.object.get("absent")) |n| try needles.append(a, try contentRule(n));
        if (content.object.get("contains_none")) |list| for (list.array.items) |n|
            try needles.append(a, try contentRule(n));
        r.absent = needles.items;
    }
    const deadline = Io.Clock.awake.now(io).addDuration(.fromMilliseconds(timeout_ms));
    const found = try audit(io, a, roots, r, .{}, deadline);
    var violations: std.json.Array = .init(a);
    for (found.violations.items) |v| {
        var entry: std.json.ObjectMap = .empty;
        try entry.put(a, "field", .{ .string = v.field });
        const shown = if (v.value.len == 0)
            v.path
        else
            try a.print("{s}: {s}", .{ v.path, v.value });
        try entry.put(a, "entry", .{ .string = shown[0..@min(shown.len, 160)] });
        try violations.append(.{ .object = entry });
    }
    var got: std.json.ObjectMap = .empty;
    try got.put(a, "entries", .{ .integer = @intCast(found.entries) });
    try got.put(a, "files", .{ .integer = @intCast(found.files) });
    try got.put(a, "violations", .{ .array = violations });
    return .{ .object = got };
}

fn contentRule(v: Json) ![]const u8 {
    return if (v == .string) v.string else error.InvalidContentRule;
}

/// typeName names a kind as the file probe does.
pub fn typeName(kind: Io.File.Kind) []const u8 {
    return switch (kind) {
        .file => "file",
        .directory => "directory",
        .sym_link => "symlink",
        .unix_domain_socket => "socket",
        else => "other",
    };
}

const testing = std.testing;

fn testAudit(a: Allocator, root: []const u8, r: Rules, limits: Limits) !Found {
    const io = testing.io;
    return audit(io, a, &.{root}, r, limits, Io.Clock.awake.now(io).addDuration(.fromSeconds(30)));
}

fn parse(a: Allocator, json: []const u8) !Json {
    return std.json.parseFromSliceLeaky(Json, a, json, .{});
}

test "the audit counts nested entries and never follows a symbolic link" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "audited/nested/deeper");
    try tmp.dir.createDirPath(io, "outside");
    try tmp.dir.writeFile(io, .{ .sub_path = "outside/secret", .data = "hunter2" });
    try tmp.dir.writeFile(io, .{ .sub_path = "audited/nested/deeper/conf", .data = "user=x\n" });
    try tmp.dir.symLink(io, "../outside", "audited/link", .{});
    try tmp.dir.symLink(io, "../../outside/secret", "audited/nested/secret", .{});
    const root = try tmp.dir.realPathFileAlloc(io, "audited", a);
    const found = try testAudit(a, root, .{ .absent = &.{"hunter2"} }, .{});
    try testing.expectEqual(5, found.entries);
    try testing.expectEqual(1, found.files);
    try testing.expectEqual(0, found.violations.items.len);
    try tmp.dir.writeFile(io, .{ .sub_path = "audited/nested/deeper/copy", .data = "a hunter2 b" });
    const leaked = try testAudit(a, root, .{ .absent = &.{"hunter2"} }, .{});
    try testing.expectEqual(1, leaked.violations.items.len);
    const v = leaked.violations.items[0];
    try testing.expectEqualStrings("content", v.field);
    try testing.expect(mem.endsWith(u8, v.path, "/nested/deeper/copy"));
    try testing.expectEqualStrings("", v.value);
}

test "a needle split between reads is found, and content is bounded" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const big = try a.alloc(u8, (64 << 10) * 3);
    @memset(big, 'x');
    const at = (64 << 10) - 3;
    @memcpy(big[at..][0..7], "hunter2");
    try tmp.dir.writeFile(io, .{ .sub_path = "big", .data = big });
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    const found = try testAudit(a, root, .{ .absent = &.{ "absent", "hunter2" } }, .{});
    try testing.expectEqual(1, found.violations.items.len);
    try testing.expectError(
        error.TooMuchContent,
        testAudit(a, root, .{ .absent = &.{"absent"} }, .{ .bytes = 1 << 10 }),
    );
    try testing.expectError(
        error.InvalidContentRule,
        testAudit(a, root, .{ .absent = &.{""} }, .{}),
    );
}

test "per-entry rules hold every entry, except the paths allow names" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "log/orders-0");
    try tmp.dir.writeFile(io, .{ .sub_path = "log/orders-0/00000.log", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = "log/meta.properties", .data = "" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    const no_logs = try parse(a, "{\"not_matches\":\"\\\\.log$\"}");
    const allow = [_][]const u8{"^log/[^/]+-[0-9]+/"};
    const exempt = try testAudit(a, root, .{ .path = no_logs, .allow = &allow }, .{});
    try testing.expectEqual(0, exempt.violations.items.len);
    try testing.expectEqual(4, exempt.entries);
    try tmp.dir.writeFile(io, .{ .sub_path = "log/server.log", .data = "" });
    const stray = try testAudit(a, root, .{ .path = no_logs, .allow = &allow }, .{});
    try testing.expectEqual(1, stray.violations.items.len);
    try testing.expectEqualStrings("log/server.log", stray.violations.items[0].value);
    const names = try testAudit(a, root, .{
        .name = try parse(a, "{\"not_matches\":\"^[0-9]+\\\\.\"}"),
        .type = try parse(a, "{\"one_of\":[\"file\",\"directory\"]}"),
    }, .{});
    try testing.expectEqual(1, names.violations.items.len);
    try testing.expectEqualStrings("name", names.violations.items[0].field);
    try testing.expectError(error.TooManyEntries, testAudit(a, root, .{}, .{ .entries = 3 }));
    try testing.expectError(error.TreeTooDeep, testAudit(a, root, .{}, .{ .depth = 1 }));
}

test "modes skip symbolic links, whose mode means nothing" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "nested");
    try tmp.dir.writeFile(io, .{ .sub_path = "nested/secret", .data = "secret" });
    try tmp.dir.symLink(io, "/missing-target", "ignored", .{});
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    var file = try tmp.dir.openFile(io, "nested/secret", .{ .mode = .read_write });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o600));
    const private = try parse(a, "{\"not_matches\":\"[2367]$\"}");
    try testing.expectEqual(
        0,
        (try testAudit(a, root, .{ .mode = private }, .{})).violations.items.len,
    );
    try file.setPermissions(io, .fromMode(0o666));
    const open = try testAudit(a, root, .{ .mode = private }, .{});
    try testing.expectEqual(1, open.violations.items.len);
    try testing.expectEqualStrings("666", open.violations.items[0].value);
}

test "a missing root fails rather than proving an empty tree" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(
        error.FileNotFound,
        testAudit(arena.allocator(), "/nonexistent-werewolf-tree", .{}, .{}),
    );
}
