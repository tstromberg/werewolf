//! doc-check fails when werewolf's markdown breaks its own rules: a relative
//! link or #anchor that leads nowhere, a program README over 100 lines, a
//! design doc over 120, a doc in docs/ over 175, a line over 88 columns, or
//! a line that starts with TODO. `doc-check --fix` rewraps the paragraphs
//! that overflow. See README.md.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;

/// width is the longest line a doc may have, in code points. Code blocks
/// and table rows are exempt, as is a URL or path a line ends in.
const width = 88;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    const fix = args.len > 1 and mem.eql(u8, args[1], "--fix");
    const paths = args[@as(usize, if (fix) 2 else 1)..];
    if (paths.len == 0) {
        std.debug.print("usage: doc-check [--fix] FILE.md...\n", .{});
        std.process.exit(2);
    }
    var docs: Docs = .{ .io = io, .gpa = gpa };
    var failed = false;
    for (paths) |path| {
        if (fix) try rewrap(gpa, io, path);
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
            if (wide(l.text)) {
                std.debug.print(
                    "doc-check: {s}:{d}: {d} columns, more than {d}\n",
                    .{ path, l.number, columns(l.text), width },
                );
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

/// limit returns how many lines path may have, or null for no limit: 175
/// for a doc in docs/, 120 for a design doc, 100 for a program's README
/// (CONTRIBUTING.md, Style).
fn limit(path: []const u8) ?usize {
    const p = if (mem.startsWith(u8, path, "./")) path[2..] else path;
    if (mem.startsWith(u8, p, "docs/") and
        mem.findScalar(u8, p["docs/".len..], '/') == null) return 175;
    if (mem.find(u8, path, "docs/design/") != null) return 120;
    if (mem.endsWith(u8, path, "/README.md") and
        (mem.startsWith(u8, path, "cmd/") or mem.find(u8, path, "/cmd/") != null)) return 100;
    return null;
}

/// columns counts a line's code points, near enough to what a reader sees.
fn columns(line: []const u8) usize {
    return std.unicode.utf8CountCodepoints(line) catch line.len;
}

/// wide reports a line over `width` that wrapping could shorten: not a
/// table row, and not a line whose overflow is one URL or path at its end.
fn wide(line: []const u8) bool {
    if (columns(line) <= width) return false;
    if (mem.startsWith(u8, mem.trimStart(u8, line, " "), "|")) return false;
    const space = mem.findScalarLast(u8, line, ' ') orelse
        return mem.findScalar(u8, line, '/') == null;
    return columns(line[0..space]) > width or mem.findScalar(u8, line[space + 1 ..], '/') == null;
}

fn read(gpa: Allocator, io: Io, path: []const u8) ![]const u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4 << 20));
}

/// rewrap rewrites path with each paragraph that has a line over `width`
/// filled to it, and says so.
fn rewrap(gpa: Allocator, io: Io, path: []const u8) !void {
    const text = try read(gpa, io, path);
    const out = try rewrapped(gpa, text);
    if (mem.eql(u8, out, text)) return;
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = out });
    std.debug.print("doc-check: {s}: rewrapped\n", .{path});
}

/// rewrapped returns text with each paragraph that has a line over `width`
/// filled to it. Only runs of prose and list items are touched, and only
/// those that overflow; code blocks, tables, headings and the rest of
/// markdown's structure stay as they are.
fn rewrapped(gpa: Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var para: Paragraph = .{};
    var fenced = false;
    var after_blank = true;
    var pos: usize = 0;
    while (pos < text.len) {
        const end = mem.findScalarPos(u8, text, pos, '\n') orelse text.len;
        const line = text[pos..end];
        pos = end + 1;
        const fence = mem.startsWith(u8, mem.trimStart(u8, line, " "), "```");
        if (fence) fenced = !fenced;
        if (!fence and !fenced and para.continues(line)) {
            try para.lines.append(gpa, line);
            after_blank = false;
            continue;
        }
        try para.flush(gpa, &out);
        if (!fence and !fenced) if (Paragraph.first(line, after_blank)) |hang| {
            para.hang = hang;
            try para.lines.append(gpa, line);
            after_blank = false;
            continue;
        };
        try out.appendSlice(gpa, line);
        try out.append(gpa, '\n');
        after_blank = line.len == 0;
    }
    try para.flush(gpa, &out);
    return out.items;
}

/// A Paragraph is a run of prose lines, or one list item, that wraps as a
/// unit; `hang` is the indent its lines after the first take.
const Paragraph = struct {
    lines: std.ArrayList([]const u8) = .empty,
    hang: usize = 0,

    /// first returns the hanging indent of a line that may begin a
    /// paragraph, or null for one wrapping leaves alone: blank, a heading,
    /// a table row, a quote, HTML, a rule, a link definition, or a code
    /// block, which is what four spaces of indent mean after a blank line.
    fn first(line: []const u8, after_blank: bool) ?usize {
        const indent = line.len - mem.trimStart(u8, line, " ").len;
        if (indent >= 4 and after_blank) return null;
        return indent + (marker(line[indent..]) orelse return null);
    }

    /// marker returns the width of the list marker that starts t, 0 for
    /// plain prose, or null for a line that is not prose at all.
    fn marker(t: []const u8) ?usize {
        if (t.len == 0) return null;
        switch (t[0]) {
            '#', '|', '>', '<' => return null,
            '-', '+', '*' => {
                if (t.len > 1 and t[1] == ' ') return 2;
                return if (t[0] == '*' and !mem.startsWith(u8, t, "***")) 0 else null;
            },
            '[' => return if (mem.find(u8, t, "]: ") != null) null else 0,
            '0'...'9' => {
                var n: usize = 0;
                while (n < t.len and std.ascii.isDigit(t[n])) n += 1;
                if (n + 1 < t.len and (t[n] == '.' or t[n] == ')') and
                    t[n + 1] == ' ') return n + 2;
                return 0;
            },
            else => return 0,
        }
    }

    /// continues reports whether line carries on the open paragraph: prose,
    /// indented as its hang, and not a new list item.
    fn continues(p: *const Paragraph, line: []const u8) bool {
        if (p.lines.items.len == 0) return false;
        const indent = line.len - mem.trimStart(u8, line, " ").len;
        return indent == p.hang and marker(line[indent..]) == 0;
    }

    /// flush writes the paragraph out, filled to `width` if a line of it is
    /// over, and empties it. A hard break (two trailing spaces) or a line
    /// ending in a backslash keeps a paragraph as it is.
    fn flush(p: *Paragraph, gpa: Allocator, out: *std.ArrayList(u8)) !void {
        defer p.lines.clearRetainingCapacity();
        var over = false;
        var fixed = false;
        for (p.lines.items) |l| {
            if (columns(l) > width) over = true;
            if (mem.endsWith(u8, l, "  ") or mem.endsWith(u8, l, "\\")) fixed = true;
        }
        if (over and !fixed) return p.fill(gpa, out);
        for (p.lines.items) |l| {
            try out.appendSlice(gpa, l);
            try out.append(gpa, '\n');
        }
    }

    /// fill lays the paragraph's words out again, as many to a line as fit,
    /// the first line keeping its marker and the rest indented to hang. A
    /// word that would start a line as markup, and a word too long for any
    /// line, stay on the line before.
    fn fill(p: *Paragraph, gpa: Allocator, out: *std.ArrayList(u8)) !void {
        var line: std.ArrayList(u8) = .empty;
        try line.appendSlice(gpa, p.lines.items[0][0..p.hang]);
        var bare = true;
        for (p.lines.items, 0..) |l, i| {
            var words = mem.tokenizeScalar(u8, if (i == 0) l[p.hang..] else l, ' ');
            while (words.next()) |w| {
                if (bare) {
                    try line.appendSlice(gpa, w);
                    bare = false;
                } else if (columns(line.items) + 1 + columns(w) <= width or markup(w)) {
                    try line.append(gpa, ' ');
                    try line.appendSlice(gpa, w);
                } else {
                    try out.appendSlice(gpa, line.items);
                    try out.append(gpa, '\n');
                    line.clearRetainingCapacity();
                    try line.appendNTimes(gpa, ' ', p.hang);
                    try line.appendSlice(gpa, w);
                }
            }
        }
        try out.appendSlice(gpa, line.items);
        try out.append(gpa, '\n');
    }

    /// markup reports a word that would be read as a heading, quote, table,
    /// rule or list marker at the start of a line.
    fn markup(w: []const u8) bool {
        if (w.len == 0) return false;
        if (w[0] == '#' or w[0] == '>' or w[0] == '|') return true;
        if (w.len == 1 and (w[0] == '-' or w[0] == '+' or w[0] == '*')) return true;
        if (!std.ascii.isDigit(w[0])) return false;
        const last = w[w.len - 1];
        if (last != '.' and last != ')') return false;
        for (w[0 .. w.len - 1]) |c| if (!std.ascii.isDigit(c)) return false;
        return true;
    }
};

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

/// times repeats s n times, at compile time, for the tests' long lines.
fn times(comptime s: []const u8, comptime n: usize) *const [s.len * n]u8 {
    comptime {
        var out: [s.len * n]u8 = undefined;
        for (0..n) |i| @memcpy(out[i * s.len ..][0..s.len], s);
        const r = out;
        return &r;
    }
}

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
    try testing.expectEqual(175, limit("docs/forms.md").?);
    try testing.expectEqual(175, limit("./docs/forms.md").?);
    try testing.expectEqual(120, limit("./docs/design/cli.md").?);
    try testing.expectEqual(null, limit("forms/demo/docs/notes.md"));
    try testing.expectEqual(120, limit("docs/design/cli.md").?);
    try testing.expectEqual(100, limit("cmd/howl/README.md").?);
    try testing.expectEqual(100, limit("forms/demo/cmd/status-page/README.md").?);
    try testing.expectEqual(null, limit("forms/bastion/README.md"));
    try testing.expectEqual(null, limit("README.md"));
}

test wide {
    try testing.expect(!wide(comptime times("x", 88)));
    try testing.expect(wide(comptime times("x", 89)));
    try testing.expect(!wide(comptime "| " ++ times("x", 90)));
    try testing.expect(!wide(comptime "see https://example.com/" ++ times("a", 80)));
    try testing.expect(!wide(comptime "[a link](../../" ++ times("a", 80) ++ ".md)"));
    try testing.expect(wide(comptime times("a word ", 15) ++ "https://x/y"));
    try testing.expect(wide(comptime times("a word ", 12) ++ times("x", 20)));
    try testing.expect(!wide(comptime times("é", 88)));
}

test rewrapped {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // A heading, a short paragraph, a table row, a code block and a
    // paragraph with a hard break stay as they are, however long.
    const kept = comptime "# A heading " ++ times("on and ", 12) ++ "\n\nShort paragraph,\n" ++
        "left as it is.\n\n| a table | row " ++ times("on and ", 12) ++ "|\n\n```\ncode " ++
        times("on and ", 12) ++ "\n```\n\nA line with a hard break  \nthat stays " ++
        times("on and ", 12) ++ "\n";
    try testing.expectEqualStrings(kept, try rewrapped(a, kept));
    // An indented fence stays a line of its own; a nested item indented
    // four spaces after another list line is prose, and after a blank line
    // it is code.
    try testing.expectEqualStrings(
        comptime "- item\n   ```\n   code\n   ```\n   after " ++ times("on and ", 11) ++ "on\n" ++
            "   and\n  - nested\n    - deep " ++ times("on and ", 10) ++
            "on and\n      on and\n\n" ++
            "    code " ++ times("on and ", 12) ++ "\n",
        try rewrapped(
            a,
            comptime "- item\n   ```\n   code\n   ```\n   after " ++ times("on and ", 12) ++ "\n" ++
                "  - nested\n    - deep " ++ times("on and ", 12) ++ "\n\n" ++
                "    code " ++ times("on and ", 12) ++ "\n",
        ),
    );
    // A list item fills to the limit with a hanging indent; a word that
    // would start a line as a list marker (3.) stays on the line before; a
    // plain paragraph fills from column 0.
    try testing.expectEqualStrings(
        comptime "- " ++ times("word ", 16) ++ "word\n  word word word\n" ++
            "2. " ++ times("ab ", 27) ++ "ab 3.\n   ab ab\n\n" ++
            "plain " ++ times("w ", 40) ++ "w\nw w w w\n",
        try rewrapped(
            a,
            comptime "- " ++ times("word ", 19) ++ "word\n" ++
                "2. " ++ times("ab ", 28) ++ "3. ab ab\n\n" ++
                "plain " ++ times("w ", 44) ++ "w\n",
        ),
    );
}
