//! doc-check fails when werewolf's markdown breaks its own rules: a relative
//! link or #anchor that leads nowhere, a program README over 100 lines, a
//! design doc over 120, or a line that starts with TODO. See README.md.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len < 2) {
        std.debug.print("usage: doc-check FILE.md...\n", .{});
        std.process.exit(2);
    }
    var docs: Docs = .{ .io = io, .gpa = gpa };
    var failed = false;
    for (args[1..]) |path| {
        if (!try docs.check(path)) failed = true;
    }
    if (failed) std.process.exit(1);
}

/// Docs reads each markdown file once and keeps its headings' anchors, so a
/// file many others link to is parsed once.
const Docs = struct {
    io: Io,
    gpa: Allocator,
    anchors: std.StringHashMapUnmanaged([]const []const u8) = .empty,

    /// check reports every broken rule in path and returns whether it had none.
    fn check(d: *Docs, path: []const u8) !bool {
        const text = try read(d.gpa, d.io, path);
        var ok = true;
        const lines = mem.count(u8, text, "\n");
        if (limit(path)) |max| if (lines > max) {
            std.debug.print("doc-check: {s}: {d} lines, more than {d}\n", .{ path, lines, max });
            ok = false;
        };
        var it: Lines = .{ .text = text };
        while (it.next()) |l| {
            if (mem.startsWith(u8, mem.trimStart(u8, l.text, " \t"), "TODO")) {
                std.debug.print("doc-check: {s}:{d}: a TODO\n", .{ path, l.number });
                ok = false;
            }
            var links: Links = .{ .line = l.text };
            while (links.next()) |target| {
                if (try d.broken(path, target)) |why| {
                    std.debug.print(
                        "doc-check: {s}:{d}: {s}: {s}\n",
                        .{ path, l.number, target, why },
                    );
                    ok = false;
                }
            }
        }
        return ok;
    }

    /// broken returns why target, a link in from, leads nowhere, or null.
    fn broken(d: *Docs, from: []const u8, target: []const u8) !?[]const u8 {
        if (mem.startsWith(u8, target, "http:") or mem.startsWith(u8, target, "https:") or
            mem.startsWith(u8, target, "mailto:")) return null;
        const hash = mem.findScalar(u8, target, '#');
        const file = target[0 .. hash orelse target.len];
        const to = if (file.len == 0)
            from
        else
            try normalize(
                d.gpa,
                try std.fs.path.join(d.gpa, &.{ std.fs.path.dirname(from) orelse ".", file }),
            );
        Io.Dir.cwd().access(d.io, to, .{}) catch return "no such file";
        const anchor = target[(hash orelse return null) + 1 ..];
        if (!mem.endsWith(u8, to, ".md")) return null;
        for (try d.anchorsOf(to)) |a| if (mem.eql(u8, a, anchor)) return null;
        return "no such heading";
    }

    fn anchorsOf(d: *Docs, path: []const u8) ![]const []const u8 {
        if (d.anchors.get(path)) |a| return a;
        const a = try headings(d.gpa, try read(d.gpa, d.io, path));
        try d.anchors.put(d.gpa, path, a);
        return a;
    }
};

/// limit returns how many lines path may have, or null for no limit: 120
/// for a design doc, 100 for a program's README (CONTRIBUTING.md, Style).
fn limit(path: []const u8) ?usize {
    if (mem.find(u8, path, "docs/design/") != null) return 120;
    if (mem.endsWith(u8, path, "/README.md") and
        (mem.startsWith(u8, path, "cmd/") or mem.find(u8, path, "/cmd/") != null)) return 100;
    return null;
}

fn read(gpa: Allocator, io: Io, path: []const u8) ![]const u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4 << 20));
}

/// Lines yields a file's lines outside fenced code blocks, numbered from 1.
const Lines = struct {
    text: []const u8,
    pos: usize = 0,
    number: usize = 0,
    fenced: bool = false,

    fn next(it: *Lines) ?struct { text: []const u8, number: usize } {
        while (it.pos < it.text.len) {
            const end = mem.findScalarPos(u8, it.text, it.pos, '\n') orelse it.text.len;
            const line = it.text[it.pos..end];
            it.pos = end + 1;
            it.number += 1;
            if (mem.startsWith(u8, mem.trimStart(u8, line, " "), "```")) {
                it.fenced = !it.fenced;
                continue;
            }
            if (!it.fenced) return .{ .text = line, .number = it.number };
        }
        return null;
    }
};

/// Links yields the targets of a line's inline links and images, `](target)`,
/// outside code spans, without a title.
const Links = struct {
    line: []const u8,
    pos: usize = 0,

    fn next(it: *Links) ?[]const u8 {
        while (it.pos < it.line.len) {
            const c = it.line[it.pos];
            if (c == '`') {
                // A code span runs to the next backtick; a link inside it is text.
                it.pos = (mem.findScalarPos(u8, it.line, it.pos + 1, '`') orelse it.line.len) + 1;
                continue;
            }
            if (c == ']' and it.pos + 1 < it.line.len and it.line[it.pos + 1] == '(') {
                const start = it.pos + 2;
                const close = mem.findScalarPos(u8, it.line, start, ')') orelse return null;
                it.pos = close + 1;
                const inner = mem.trim(u8, it.line[start..close], " ");
                const target = inner[0 .. mem.findScalar(u8, inner, ' ') orelse inner.len];
                if (target.len > 0) return target;
                continue;
            }
            it.pos += 1;
        }
        return null;
    }
};

/// headings returns the anchors GitHub gives a file's headings, in order.
fn headings(gpa: Allocator, text: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it: Lines = .{ .text = text };
    while (it.next()) |l| {
        const t = mem.trimStart(u8, l.text, "#");
        if (t.len == l.text.len or t.len == 0 or t[0] != ' ') continue;
        const base = try slug(gpa, t);
        var name = base;
        var n: usize = 1;
        // A repeated heading gets -1, -2, ... as GitHub numbers it.
        while (for (out.items) |o| {
            if (mem.eql(u8, o, name)) break true;
        } else false) : (n += 1) name = try gpa.print("{s}-{d}", .{ base, n });
        try out.append(gpa, name);
    }
    return out.items;
}

/// slug turns a heading into its anchor as GitHub does: lower case, spaces
/// to hyphens, and punctuation other than - and _ dropped.
fn slug(gpa: Allocator, heading: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (mem.trim(u8, heading, " \t")) |c| {
        if (c == ' ') {
            try out.append(gpa, '-');
        } else if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c >= 0x80) {
            try out.append(gpa, std.ascii.toLower(c));
        }
    }
    return out.items;
}

/// normalize removes . and resolves .. in a relative path, so two links to
/// one file share an entry; a .. past the start is kept, and fails later.
fn normalize(gpa: Allocator, path: []const u8) ![]const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    var it = mem.tokenizeScalar(u8, path, '/');
    while (it.next()) |p| {
        if (mem.eql(u8, p, ".")) continue;
        if (mem.eql(u8, p, "..") and parts.items.len > 0 and
            !mem.eql(u8, parts.items[parts.items.len - 1], ".."))
        {
            _ = parts.pop();
            continue;
        }
        try parts.append(gpa, p);
    }
    if (parts.items.len == 0) return ".";
    return mem.join(gpa, "/", parts.items);
}

const testing = std.testing;

test slug {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings(
        "config-the-config-tar-from-flags",
        try slug(a, "CONFIG: the config tar from flags"),
    );
    try testing.expectEqualStrings("werewolfs-own-fixes", try slug(a, "werewolf's own fixes"));
    try testing.expectEqualStrings("without-a-form---app", try slug(a, "Without a form: `--app`"));
    try testing.expectEqualStrings(
        "webshell-example-a-contained-vulnerability",
        try slug(a, "webshell-example: a contained vulnerability"),
    );
}

test headings {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const h = try headings(
        a,
        "# Title\n\n## Open questions\n```sh\n# not a heading\n```\n### Open questions\n#nospace\n",
    );
    try testing.expectEqual(3, h.len);
    try testing.expectEqualStrings("title", h[0]);
    try testing.expectEqualStrings("open-questions", h[1]);
    try testing.expectEqualStrings("open-questions-1", h[2]);
}

test Links {
    var it: Links = .{ .line = "see [a](b.md#c), `[x](y)` and ![i](img.png \"t\") or [](  )" };
    try testing.expectEqualStrings("b.md#c", it.next().?);
    try testing.expectEqualStrings("img.png", it.next().?);
    try testing.expectEqual(null, it.next());
}

test normalize {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings(
        "docs/forms.md",
        try normalize(a, "forms/x/../../docs/./forms.md"),
    );
    try testing.expectEqualStrings("../up.md", try normalize(a, "../up.md"));
    try testing.expectEqualStrings("README.md", try normalize(a, "docs/../README.md"));
}

test limit {
    try testing.expectEqual(120, limit("docs/design/cli.md").?);
    try testing.expectEqual(100, limit("cmd/howl/README.md").?);
    try testing.expectEqual(100, limit("forms/demo/cmd/status-page/README.md").?);
    try testing.expectEqual(null, limit("forms/bastion/README.md"));
    try testing.expectEqual(null, limit("README.md"));
}
