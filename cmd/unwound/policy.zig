//! policy reads unwound's grants from the image's compiled network policy,
//! `lookup UID PATTERN TYPE... [unfiltered]` lines, and decides questions.
//! Grants only add: no order, no denials, no modes. A pattern is an exact
//! name, `*.NAME` for every name below it (not NAME itself), or `*` for
//! any name, which is screened (screen.zig) unless the line says
//! `unfiltered`.
const std = @import("std");
const dns = @import("dns");
const wire = @import("wire.zig");
const mem = std.mem;

pub const max_grants = 1024;

pub const Kind = enum { exact, below, any };

pub const Grant = struct {
    /// service indexes users, which also gives its label.
    service: u8,
    kind: Kind,
    name: wire.Name,
    types: std.EnumSet(wire.Type),
    unfiltered: bool,
    /// line is where the grant is in the policy file, from 1: its rule.
    line: u16,

    fn covers(g: *const Grant, n: *const wire.Name) bool {
        const want = g.name.text();
        const have = n.text();
        return switch (g.kind) {
            .any => true,
            .exact => mem.eql(u8, have, want),
            .below => have.len > want.len + 1 and mem.endsWith(u8, have, want) and
                have[have.len - want.len - 1] == '.',
        };
    }
};

pub const Why = enum {
    granted,
    /// screened matched only a screened `*`: screen.zig decides the rest.
    screened,
    /// unsupported is a type no grant can name: ANY, AXFR, UPDATE's.
    unsupported,
    no_grant,
};

pub const Decision = struct {
    allow: bool,
    why: Why,
    /// line is the grant that decided, or 0.
    line: u16 = 0,
};

pub const Policy = struct {
    users: dns.Users = .{},
    grants: [max_grants]Grant = undefined,
    n: usize = 0,
    /// generation identifies the policy text in audit records.
    generation: u32 = 0,

    /// parse reads every lookup line of text and ignores the rest, which is
    /// fence's. Any malformed lookup line fails the whole policy.
    pub fn parse(p: *Policy, text: []const u8) !void {
        p.* = .{ .users = try dns.lookupUsers(text), .generation = std.hash.Crc32.hash(text) };
        var lines = mem.splitScalar(u8, text, '\n');
        var number: usize = 0;
        while (lines.next()) |line| {
            number += 1;
            var words = mem.tokenizeScalar(u8, line, ' ');
            if (!mem.eql(u8, words.next() orelse "", "lookup")) continue;
            if (p.n == max_grants or number > std.math.maxInt(u16)) return error.BadPolicy;
            const id = std.fmt.parseInt(
                u32,
                words.next() orelse "",
                10,
            ) catch return error.BadPolicy;
            const pattern = words.next() orelse return error.BadPolicy;
            var g: Grant = .{
                .service = for (p.users.ids[0..p.users.len], 0..) |u, i| {
                    if (u == id) break @intCast(i);
                } else unreachable,
                .kind = .exact,
                .name = .{},
                .types = .empty,
                .unfiltered = false,
                .line = @intCast(number),
            };
            if (mem.eql(u8, pattern, "*")) {
                g.kind = .any;
            } else {
                const below = mem.startsWith(u8, pattern, "*.");
                if (below) g.kind = .below;
                const text_name = if (below) pattern[2..] else pattern;
                if (text_name.len == 0) return error.BadPolicy;
                g.name = wire.Name.fromText(text_name) catch return error.BadPolicy;
            }
            while (words.next()) |w| {
                if (mem.eql(u8, w, "unfiltered")) {
                    if (g.kind != .any or words.peek() != null) return error.BadPolicy;
                    g.unfiltered = true;
                    break;
                }
                g.types.insert(wire.Type.parse(w) orelse return error.BadPolicy);
            }
            if (g.types.count() == 0) return error.BadPolicy;
            p.grants[p.n] = g;
            p.n += 1;
        }
    }

    /// service returns the service whose label ip is.
    pub fn service(p: *const Policy, ip: [4]u8) ?u8 {
        return if (dns.labelIndex(p.users, ip)) |i| @intCast(i) else null;
    }

    pub fn uid(p: *const Policy, s: u8) u32 {
        return p.users.ids[s];
    }

    /// decide answers whether service s may ask for name and type t. A
    /// grant that is not screened wins over one that is, whatever the order.
    pub fn decide(p: *const Policy, s: u8, n: *const wire.Name, t: u16) Decision {
        const qtype = wire.Type.from(t) orelse return .{ .allow = false, .why = .unsupported };
        var screened: u16 = 0;
        for (p.grants[0..p.n]) |*g| {
            if (g.service != s or !g.types.contains(qtype) or !g.covers(n)) continue;
            if (g.kind == .any and !g.unfiltered) {
                if (screened == 0) screened = g.line;
                continue;
            }
            return .{ .allow = true, .why = .granted, .line = g.line };
        }
        if (screened != 0) return .{ .allow = true, .why = .screened, .line = screened };
        return .{ .allow = false, .why = .no_grant };
    }
};

const testing = std.testing;

fn name(s: []const u8) wire.Name {
    return wire.Name.fromText(s) catch unreachable;
}

const example =
    \\connect 1001 tcp 443
    \\lookup 1001 api.example.com A AAAA
    \\lookup 1001 _acme-challenge.example.com TXT
    \\lookup 1001 *.example.net A
    \\dns 69
    \\lookup 1002 * A AAAA
    \\lookup 1003 * A AAAA TXT unfiltered
    \\lookup 1002 pinned.example.org A
    \\
;

test "grants: exact names, subtrees, wildcards and their types" {
    var p: Policy = .{};
    try p.parse(example);
    try testing.expectEqual(3, p.users.len);
    const svc = p.service(.{ 127, 53, 0, 1 }).?;
    try testing.expectEqual(1001, p.uid(svc));
    const cases = [_]struct { s: u8, n: []const u8, t: u16, d: Decision }{
        .{
            .s = 0,
            .n = "api.example.com",
            .t = 1,
            .d = .{ .allow = true, .why = .granted, .line = 2 },
        },
        .{
            .s = 0,
            .n = "api.example.com",
            .t = 28,
            .d = .{ .allow = true, .why = .granted, .line = 2 },
        },
        .{ .s = 0, .n = "api.example.com", .t = 16, .d = .{ .allow = false, .why = .no_grant } },
        .{ .s = 0, .n = "x.api.example.com", .t = 1, .d = .{ .allow = false, .why = .no_grant } },
        .{
            .s = 0,
            .n = "_acme-challenge.example.com",
            .t = 16,
            .d = .{ .allow = true, .why = .granted, .line = 3 },
        },
        // *.example.net is below it, never example.net, and on label boundaries.
        .{
            .s = 0,
            .n = "a.b.example.net",
            .t = 1,
            .d = .{ .allow = true, .why = .granted, .line = 4 },
        },
        .{ .s = 0, .n = "example.net", .t = 1, .d = .{ .allow = false, .why = .no_grant } },
        .{ .s = 0, .n = "evilexample.net", .t = 1, .d = .{ .allow = false, .why = .no_grant } },
        .{ .s = 0, .n = "example.net.evil", .t = 1, .d = .{ .allow = false, .why = .no_grant } },
        // Another service's grants are not this one's.
        .{
            .s = 1,
            .n = "api.example.com",
            .t = 1,
            .d = .{ .allow = true, .why = .screened, .line = 6 },
        },
        .{ .s = 1, .n = "api.example.com", .t = 16, .d = .{ .allow = false, .why = .no_grant } },
        // A screened * yields to an exact grant, whatever the order.
        .{
            .s = 1,
            .n = "pinned.example.org",
            .t = 1,
            .d = .{ .allow = true, .why = .granted, .line = 8 },
        },
        .{ .s = 1, .n = "pinned.example.org", .t = 16, .d = .{ .allow = false, .why = .no_grant } },
        .{
            .s = 2,
            .n = "anything.at.all",
            .t = 16,
            .d = .{ .allow = true, .why = .granted, .line = 7 },
        },
        .{ .s = 2, .n = "", .t = 1, .d = .{ .allow = true, .why = .granted, .line = 7 } },
        // ANY, AXFR and unknown types are never granted, even unfiltered.
        .{
            .s = 2,
            .n = "anything.at.all",
            .t = 255,
            .d = .{ .allow = false, .why = .unsupported },
        },
        .{
            .s = 2,
            .n = "anything.at.all",
            .t = 252,
            .d = .{ .allow = false, .why = .unsupported },
        },
        .{ .s = 2, .n = "anything.at.all", .t = 65, .d = .{ .allow = false, .why = .unsupported } },
    };
    for (cases) |c| try testing.expectEqual(c.d, p.decide(c.s, &name(c.n), c.t));
    try testing.expectEqual(null, p.service(.{ 127, 53, 0, 4 }));
    try testing.expectEqual(null, p.service(.{ 127, 0, 0, 1 }));
}

test "malformed lookup lines fail the whole policy" {
    for ([_][]const u8{
        "lookup",
        "lookup 1001",
        "lookup 1001 a.example",
        "lookup x a.example A",
        "lookup 4294967295 a.example A",
        "lookup 1001 A.example A",
        "lookup 1001 a.example. A",
        "lookup 1001 a.example a",
        "lookup 1001 a.example ANY",
        "lookup 1001 a.example all",
        "lookup 1001 a.example AXFR",
        "lookup 1001 a.example A unfiltered",
        "lookup 1001 *.a.example A unfiltered",
        "lookup 1001 * unfiltered",
        "lookup 1001 * A unfiltered A",
        "lookup 1001 *. A",
        "lookup 1001 *a.example A",
        "lookup 1001 a.*.example A",
        "lookup 1001 ** A",
    }) |bad| {
        var p: Policy = .{};
        try testing.expectError(error.BadPolicy, p.parse(bad));
    }
}

test "the policy names each grant's rule and generation" {
    var p: Policy = .{};
    try p.parse(example);
    var q: Policy = .{};
    try q.parse(example ++ "lookup 1004 b.example A\n");
    try testing.expect(p.generation != q.generation);
    try testing.expectEqual(4, q.users.len);
}
