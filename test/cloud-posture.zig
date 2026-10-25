//! cloud-posture HOSTNAME reads a cloud machine's root posture report on
//! standard input and exits 0 only if it is that host's, as root, not a
//! DEV build, nothing disabled, every runtime protection evidence.yaml's
//! cloud list names passing, and nothing failing or passing that its known
//! weaknesses did not predict. A declared weakness cannot excuse a
//! required protection (test/cloud).

const std = @import("std");
const host = @import("host");
const form = @import("form");
const json = std.json;
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    const table = try host.evidence.load(gpa, form);
    var buf: [64 << 10]u8 = undefined;
    var in = Io.File.stdin().readerStreaming(io, &buf);
    const text = try in.interface.allocRemaining(gpa, .limited(4 << 20));
    const report = json.parseFromSliceLeaky(json.Value, gpa, text, .{}) catch std.process.exit(1);
    std.process.exit(if (args.len == 2 and try valid(gpa, table.cloud, report, args[1])) 0 else 1);
}

fn valid(
    gpa: std.mem.Allocator,
    required: []const []const u8,
    report: json.Value,
    hostname: []const u8,
) !bool {
    if (report != .object) return false;
    const o = report.object;
    const name = o.get("host") orelse return false;
    if (name != .string or !std.mem.eql(u8, name.string, hostname)) return false;
    const root = o.get("root") orelse return false;
    if (root != .bool or !root.bool) return false;
    if (truthy(o.get("dev")) or truthy(o.get("disabled"))) return false;
    if (!host.evidence.passes(try host.evidence.results(gpa, report), required)) return false;
    const known = o.get("known") orelse return false;
    if (known != .object) return false;
    for ([_][]const u8{ "unexpected", "now_passing" }) |key| {
        const list = known.object.get(key) orelse return false;
        if (list != .array or list.array.items.len != 0) return false;
    }
    return true;
}

/// truthy is whether v is set as Python would read it: not absent, null,
/// false, zero or empty.
fn truthy(v: ?json.Value) bool {
    const x = v orelse return false;
    return switch (x) {
        .null => false,
        .bool => |b| b,
        .integer => |i| i != 0,
        .float => |f| f != 0,
        .number_string, .string => |s| s.len > 0,
        .array => |a| a.items.len > 0,
        .object => |m| m.count() > 0,
    };
}

test "no missing, skipped, failed or disabled runtime protection passes" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const required = (try host.evidence.load(gpa, form)).cloud;
    var checks: std.ArrayList(u8) = .empty;
    for (required, 0..) |id, i| {
        const comma = if (i > 0) "," else "";
        try checks.print(gpa, "{s}{{\"id\":\"{s}\",\"result\":\"pass\"}}", .{ comma, id });
    }
    const good = try gpa.print(
        "{{\"host\":\"fixture\",\"root\":true,\"dev\":false,\"disabled\":[],\"checks\":[{s}]," ++
            "\"known\":{{\"unexpected\":[],\"now_passing\":[]}}}}",
        .{checks.items},
    );
    const parse = struct {
        fn f(a: std.mem.Allocator, s: []const u8) !json.Value {
            return json.parseFromSliceLeaky(json.Value, a, s, .{});
        }
    }.f;
    try std.testing.expect(try valid(gpa, required, try parse(gpa, good), "fixture"));
    try std.testing.expect(!try valid(gpa, required, try parse(gpa, good), "another-host"));
    for (required) |id| {
        for ([_][]const u8{ "fail", "skip" }) |result| {
            const changed = try std.mem.replaceOwned(
                u8,
                gpa,
                good,
                try gpa.print("\"{s}\",\"result\":\"pass\"", .{id}),
                try gpa.print("\"{s}\",\"result\":\"{s}\"", .{ id, result }),
            );
            try std.testing.expect(!try valid(gpa, required, try parse(gpa, changed), "fixture"));
        }
        const dropped = try std.mem.replaceOwned(
            u8,
            gpa,
            good,
            try gpa.print("\"id\":\"{s}\"", .{id}),
            "\"id\":\"something-else\"",
        );
        try std.testing.expect(!try valid(gpa, required, try parse(gpa, dropped), "fixture"));
    }
    for ([_][2][]const u8{
        .{ "\"disabled\":[]", "\"disabled\":[\"tpm\"]" },
        .{ "\"dev\":false", "\"dev\":true" },
        .{ "\"root\":true", "\"root\":false" },
        .{ "\"known\":{\"unexpected\":[],\"now_passing\":[]}", "\"known\":null" },
        .{ "\"unexpected\":[]", "\"unexpected\":[\"kernel-seal\"]" },
        .{ "\"now_passing\":[]", "\"now_passing\":[\"network-no-login\"]" },
    }) |change| {
        const changed = try std.mem.replaceOwned(u8, gpa, good, change[0], change[1]);
        try std.testing.expect(!try valid(gpa, required, try parse(gpa, changed), "fixture"));
    }
}
