//! lookup compiles a form's DNS allowances, `PATTERN [TYPE...|all]
//! [unfiltered]`, into the lines unwound reads from the image's network
//! policy: `lookup USER PATTERN TYPE... [unfiltered]`. A pattern is a name,
//! `*.NAME` for every name below it, or `*`. Names become lowercase without
//! one final dot; no type means A and AAAA; `all` is every type unwound
//! forwards. Anything else fails the build (docs/design/implemented/unwound-policy.md).
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// types are the query types unwound forwards, as cmd/unwound/wire.zig's
/// Type names them; unwound checks every line again when it starts.
pub const types = [_][]const u8{
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "TXT",
    "SRV",
    "NS",
    "PTR",
    "CAA",
    "TLSA",
};
const default_types = [_][]const u8{ "A", "AAAA" };

/// compile returns the policy line for user's allowance spec, or
/// error.Invalid with why.
pub fn compile(gpa: Allocator, user: []const u8, spec: []const u8, why: *[]const u8) error{
    Invalid,
    OutOfMemory,
}![]const u8 {
    var words = mem.tokenizeAny(u8, spec, " \t");
    const raw = words.next() orelse return invalid(
        why,
        "lookup names a pattern: NAME, *.NAME or *",
    );
    const pattern = try canonical(gpa, raw, why);
    var chosen: std.ArrayList([]const u8) = .empty;
    var all = false;
    var unfiltered = false;
    while (words.next()) |w| {
        if (unfiltered) return invalid(why, "unfiltered comes last");
        if (mem.eql(u8, w, "unfiltered")) {
            if (!mem.eql(
                u8,
                pattern,
                "*",
            )) return invalid(why, "unfiltered is for * alone: a name is already exact");
            unfiltered = true;
        } else if (std.ascii.eqlIgnoreCase(w, "all")) {
            all = true;
        } else {
            const t = for (types) |t| {
                if (std.ascii.eqlIgnoreCase(w, t)) break t;
            } else {
                why.* = try gpa.print(
                    "{s} is not a type unwound forwards: {s} or all",
                    .{ w, try mem.join(gpa, " ", &types) },
                );
                return error.Invalid;
            };
            for (chosen.items) |c| {
                if (mem.eql(u8, c, t)) break;
            } else try chosen.append(gpa, t);
        }
    }
    if (all and
        chosen.items.len > 0) return invalid(why, "all is every type: name no others with it");
    const list: []const []const u8 = if (all)
        &types
    else if (chosen.items.len > 0)
        chosen.items
    else
        &default_types;
    return gpa.print("lookup {s} {s} {s}{s}", .{
        user, pattern, try mem.join(gpa, " ", list), if (unfiltered) " unfiltered" else "",
    });
}

fn invalid(why: *[]const u8, text: []const u8) error{Invalid} {
    why.* = text;
    return error.Invalid;
}

/// canonical lowercases a pattern and drops one final dot. Its name must be
/// ASCII labels of letters, digits, hyphens and underscores (an IDN is
/// written as its xn-- A-label), each 1 to 63 long, 253 in all.
fn canonical(
    gpa: Allocator,
    raw: []const u8,
    why: *[]const u8,
) error{ Invalid, OutOfMemory }![]const u8 {
    if (mem.eql(u8, raw, "*")) return raw;
    const below = mem.startsWith(u8, raw, "*.");
    var name = if (below) raw[2..] else raw;
    if (mem.endsWith(u8, name, ".")) name = name[0 .. name.len - 1];
    if (name.len == 0 or name.len > 253) {
        why.* = try gpa.print("{s} is not a name, *.NAME or *", .{raw});
        return error.Invalid;
    }
    const out = try gpa.alloc(u8, name.len);
    var labels = mem.splitScalar(u8, name, '.');
    var at: usize = 0;
    while (labels.next()) |l| {
        if (l.len == 0 or l.len > 63) {
            why.* = try gpa.print("{s}: each label is 1 to 63 characters", .{raw});
            return error.Invalid;
        }
        for (l) |c| switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_' => {},
            else => {
                why.* = try gpa.print(
                    "{s}: names are letters, digits, - and _ (an IDN as its xn-- form); no " ++
                        "wildcards inside",
                    .{raw},
                );
                return error.Invalid;
            },
        };
        _ = std.ascii.lowerString(out[at..][0..l.len], l);
        at += l.len;
        if (at < out.len) {
            out[at] = '.';
            at += 1;
        }
    }
    return if (below) gpa.print("*.{s}", .{out}) else out;
}

const testing = std.testing;

fn rep(comptime c: u8, comptime n: usize) *const [n]u8 {
    const r: [n]u8 = @splat(c);
    return &r;
}

test "allowances compile to canonical lines with their types" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: []const u8 = "";
    const cases = [_][2][]const u8{
        .{ "api.example.com", "lookup web api.example.com A AAAA" },
        .{ "API.Example.COM.", "lookup web api.example.com A AAAA" },
        .{ "*.example.net", "lookup web *.example.net A AAAA" },
        .{ "_acme.example.org TXT", "lookup web _acme.example.org TXT" },
        .{ "a.example txt mx TXT", "lookup web a.example TXT MX" },
        .{ "xn--bcher-kva.example", "lookup web xn--bcher-kva.example A AAAA" },
        .{ "*", "lookup web * A AAAA" },
        .{ "* all unfiltered", "lookup web * A AAAA CNAME MX TXT SRV NS PTR CAA TLSA unfiltered" },
        .{ "*\tA\tunfiltered", "lookup web * A unfiltered" },
        // The longest name: 253 characters.
        .{
            rep('a', 63) ++ "." ++ rep('a', 63) ++ "." ++ rep('a', 63) ++ "." ++ rep('a', 61),
            "lookup web " ++ rep('a', 63) ++ "." ++ rep('a', 63) ++ "." ++ rep('a', 63) ++ "." ++
                rep('a', 61) ++ " A AAAA",
        },
    };
    for (cases) |c| try testing.expectEqualStrings(c[1], try compile(gpa, "web", c[0], &why));
}

test "anything else fails the build, and says why" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    for ([_][]const u8{
        "",
        "a.example ANY",
        "a.example AXFR",
        "a.example unfiltered",
        "*.a.example unfiltered",
        "* unfiltered A",
        "* all A",
        "a..example",
        ".a.example",
        "a.*.example",
        "*a.example",
        "**",
        "*.",
        "a example",
        "bücher.example",
        "a.example/",
        "a.example!",
        rep('a', 64) ++ ".example",
        rep('a', 63) ++ "." ++ rep('a', 63) ++ "." ++ rep('a', 63) ++ "." ++ rep('a', 62),
    }) |bad| {
        var why: []const u8 = "";
        if (compile(gpa, "web", bad, &why)) |line| {
            std.debug.print("compiled {s} to {s}\n", .{ bad, line });
            return error.TestUnexpectedResult;
        } else |err| {
            try testing.expectEqual(error.Invalid, err);
            try testing.expect(why.len > 0);
        }
    }
}
