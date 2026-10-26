//! Compile the manual Markdown described in docs/manuals.md to mdoc.
//! This is a build tool: bounded input, no includes, no raw roff, no clock.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Writer = std.Io.Writer;
const limit = 256 * 1024;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 2) {
        std.debug.print("usage: mdoc FILE.[1-9].md\n", .{});
        std.process.exit(2);
    }
    const source = std.Io.Dir.cwd().readFileAlloc(
        init.io,
        args[1],
        a,
        .limited(limit),
    ) catch |err| {
        std.debug.print("mdoc: {s}: {t}\n", .{ args[1], err });
        std.process.exit(1);
    };
    var bad: Bad = .{};
    const output = compile(a, source, &bad) catch |err| {
        if (err == error.Invalid)
            std.debug.print("mdoc: {s}:{d}: {s}\n", .{ args[1], bad.line, bad.why })
        else
            std.debug.print("mdoc: {s}: {t}\n", .{ args[1], err });
        std.process.exit(1);
    };
    // Do not publish a partially parsed page, even when the caller redirects stdout.
    try std.Io.File.stdout().writeStreamingAll(init.io, output);
}

const Bad = struct {
    line: usize = 1,
    why: []const u8 = "",

    fn fail(b: *Bad, why: []const u8) error{Invalid} {
        b.why = why;
        return error.Invalid;
    }
};

const Line = struct { text: []const u8, number: usize };
const Error = Allocator.Error || Writer.Error || error{Invalid};

fn compile(a: Allocator, source: []const u8, bad: *Bad) Error![]const u8 {
    if (source.len > limit) return bad.fail("manual exceeds 256 KiB");
    if (!std.unicode.utf8ValidateSlice(source)) return bad.fail("invalid UTF-8");
    var lines: std.ArrayList(Line) = .empty;
    var split = mem.splitScalar(u8, source, '\n');
    while (split.next()) |raw| {
        bad.line = lines.items.len + 1;
        const text = mem.trimEnd(u8, raw, "\r");
        for (text) |c| if (c < 32 or c == 127) return bad.fail("control character in input");
        try lines.append(a, .{ .text = mem.trimEnd(u8, text, " "), .number = bad.line });
    }
    var output: std.Io.Writer.Allocating = .init(a);
    var p: Page = .{ .a = a, .lines = lines.items, .out = &output.writer, .bad = bad };
    try p.render();
    return output.toOwnedSlice();
}

const Page = struct {
    a: Allocator,
    lines: []const Line,
    out: *Writer,
    bad: *Bad,
    at: usize = 0,
    name: []const u8 = "",
    names: []const u8 = "",
    section: []const u8 = "",
    sections: std.StringHashMapUnmanaged(void) = .empty,
    paragraph: bool = false,
    populated: bool = false,

    fn line(p: *Page) []const u8 {
        p.bad.line = p.lines[p.at].number;
        return p.lines[p.at].text;
    }

    fn blanks(p: *Page) void {
        while (p.at < p.lines.len and p.lines[p.at].text.len == 0) p.at += 1;
    }

    fn required(p: *Page) Error![]const u8 {
        p.blanks();
        if (p.at == p.lines.len) return p.bad.fail("unexpected end of manual");
        const text = p.line();
        p.at += 1;
        return text;
    }

    fn metadata(p: *Page, prefix: []const u8) Error![]const u8 {
        const text = try p.required();
        if (!mem.startsWith(u8, text, prefix) or !mem.endsWith(u8, text, " -->"))
            return p.bad.fail("expected date and os metadata after the title");
        const value = text[prefix.len .. text.len - 4];
        if (value.len == 0) return p.bad.fail("empty metadata value");
        return value;
    }

    fn render(p: *Page) Error!void {
        const title = try p.required();
        if (!mem.startsWith(u8, title, "# ")) return p.bad.fail("expected # name(section)");
        const ref = reference(title[2..]) orelse return p.bad.fail("expected # name(section)");
        if (ref.len != title.len - 2) return p.bad.fail("text after manual title");
        p.name = ref.name;
        const date = try p.metadata("<!-- date: ");
        if (!validDate(date)) return p.bad.fail("date must be Month D, YYYY");
        const os = try p.metadata("<!-- os: ");
        try p.out.print(".Dd {s}", .{date});
        try p.out.writeAll("\n.Dt ");
        try argument(p.out, try std.ascii.allocUpperString(p.a, p.name));
        try p.out.print(" {c}\n.Os ", .{ref.section});
        try argument(p.out, os);
        try p.out.writeByte('\n');

        while (true) {
            p.blanks();
            if (p.at == p.lines.len) break;
            const text = p.line();
            if (mem.startsWith(u8, text, "## ")) {
                if (p.section.len > 0 and !p.populated) return p.bad.fail("empty section");
                const section = text[3..];
                if (p.sections.contains(section)) return p.bad.fail("duplicate section");
                const first = [_][]const u8{ "NAME", "SYNOPSIS", "DESCRIPTION" };
                if (p.sections.count() < first.len and
                    !mem.eql(u8, section, first[p.sections.count()]))
                    return p.bad.fail("begin with NAME, SYNOPSIS and DESCRIPTION, in that order");
                for (section) |c| if (!(std.ascii.isUpper(c) or c == ' '))
                    return p.bad.fail("section headings use uppercase words");
                if (section.len == 0) return p.bad.fail("empty section");
                try p.sections.put(p.a, section, {});
                p.section = section;
                p.paragraph = false;
                p.populated = false;
                try p.out.writeAll(".Sh ");
                try argument(p.out, section);
                try p.out.writeByte('\n');
                p.at += 1;
                if (mem.eql(u8, section, "NAME")) try p.nameSection();
                continue;
            }
            if (p.section.len == 0) return p.bad.fail("expected ## NAME");
            if (mem.startsWith(u8, text, "### ")) {
                if (text.len == 4) return p.bad.fail("empty subsection");
                try p.out.writeAll(".Ss ");
                try argument(p.out, text[4..]);
                try p.out.writeByte('\n');
                p.at += 1;
                p.paragraph = false;
            } else if (mem.startsWith(u8, text, "- ")) {
                try p.list();
                p.paragraph = true;
                p.populated = true;
            } else if (mem.startsWith(u8, text, "```")) {
                try p.literal();
                p.paragraph = true;
                p.populated = true;
            } else {
                const synopsis = mem.eql(u8, p.section, "SYNOPSIS");
                if (p.paragraph and !synopsis) try p.out.writeAll(".Pp\n");
                const body = try p.prose("");
                try p.inlineText(body, synopsis, false);
                p.paragraph = true;
                p.populated = true;
            }
        }
        if (p.sections.count() < 3) return p.bad.fail("missing NAME, SYNOPSIS or DESCRIPTION");
        if (!p.populated) return p.bad.fail("empty section");
    }

    fn nameSection(p: *Page) Error!void {
        const text = try p.required();
        const sep = mem.find(u8, text, " — ") orelse
            return p.bad.fail("NAME must be name[, alias] — description");
        p.names = text[0..sep];
        if (sep + " — ".len == text.len) return p.bad.fail("empty name description");
        var names = mem.splitSequence(u8, p.names, ", ");
        var first = true;
        while (names.next()) |name| {
            if (!validName(name)) return p.bad.fail("invalid command name");
            if (first and !mem.eql(u8, name, p.name))
                return p.bad.fail("NAME must begin with the title's command");
            first = false;
            try p.out.writeAll(".Nm ");
            try argument(p.out, name);
            try p.out.writeAll(if (names.peek() != null) " ,\n" else "\n");
        }
        try p.out.writeAll(".Nd ");
        try argument(p.out, text[sep + " — ".len ..]);
        try p.out.writeByte('\n');
        p.populated = true;
        p.blanks();
        if (p.at == p.lines.len or !mem.eql(u8, p.line(), "## SYNOPSIS"))
            return p.bad.fail("expected SYNOPSIS after the name description");
    }

    fn prose(p: *Page, indent: []const u8) Error![]const u8 {
        const number = p.lines[p.at].number;
        var body: std.ArrayList(u8) = .empty;
        while (p.at < p.lines.len) {
            const text = p.line();
            if (text.len == 0 or mem.startsWith(u8, text, "## ") or
                mem.startsWith(u8, text, "### ") or mem.startsWith(u8, text, "- ") or
                mem.startsWith(u8, text, "```")) break;
            if (!mem.startsWith(u8, text, indent)) break;
            const rest = text[indent.len..];
            var digits: usize = 0;
            while (digits < rest.len and std.ascii.isDigit(rest[digits])) : (digits += 1) {}
            if (digits > 0 and mem.startsWith(u8, rest[digits..], ". "))
                return p.bad.fail("numbered lists are not supported; use tagged descriptions");
            if (rest.len == 0 or rest[0] == ' ' or rest[0] == '#' or rest[0] == '>' or
                rest[0] == '|' or mem.startsWith(u8, rest, "<!--") or
                mem.startsWith(u8, rest, "- ") or mem.startsWith(u8, rest, "* ") or
                mem.startsWith(u8, rest, "```"))
                return p.bad.fail(
                    "unsupported block; use paragraphs, tagged lists or fenced examples",
                );
            if (body.items.len > 0) try body.append(p.a, ' ');
            try body.appendSlice(p.a, rest);
            p.at += 1;
        }
        if (body.items.len == 0) return p.bad.fail("unexpected indentation or block");
        p.bad.line = number;
        return body.toOwnedSlice(p.a);
    }

    fn list(p: *Page) Error!void {
        // File descriptions conventionally break after a long path. Other lists
        // align short terms, capped so a long invocation leaves room for prose.
        var width: usize = 6;
        if (!mem.eql(u8, p.section, "FILES")) {
            var at = p.at;
            while (at < p.lines.len) : (at += 1) {
                const text = p.lines[at].text;
                if (mem.startsWith(u8, text, "- ")) {
                    var n: usize = 0;
                    for (text[2..]) |c| if (c != '*' and c != '`') {
                        n += 1;
                    };
                    if (n <= 16) width = @max(width, n);
                } else if (text.len != 0 and !mem.startsWith(u8, text, "  ")) break;
            }
        }
        try p.out.print(".Bl -tag -width {d}n\n", .{width});
        while (p.at < p.lines.len and mem.startsWith(u8, p.line(), "- ")) {
            const term = p.line()[2..];
            if (term.len == 0) return p.bad.fail("empty list term");
            try p.out.writeAll(".It");
            try p.inlineText(term, false, true);
            p.at += 1;
            p.blanks();
            if (p.at == p.lines.len or !mem.startsWith(u8, p.line(), "  "))
                return p.bad.fail("a list term needs a description indented by two spaces");
            var first = true;
            while (p.at < p.lines.len and mem.startsWith(u8, p.line(), "  ")) {
                if (!first) try p.out.writeAll(".Pp\n");
                const body = try p.prose("  ");
                try p.inlineText(body, false, false);
                first = false;
                p.blanks();
            }
        }
        try p.out.writeAll(".El\n");
    }

    fn literal(p: *Page) Error!void {
        const start = p.line();
        if (!mem.eql(u8, start, "```") and !mem.eql(u8, start, "```sh") and
            !mem.eql(u8, start, "```text")) return p.bad.fail("unsupported example fence");
        try p.out.writeAll(".Bd -literal -offset indent\n");
        p.at += 1;
        while (p.at < p.lines.len) : (p.at += 1) {
            const text = p.line();
            if (mem.eql(u8, text, "```")) {
                p.at += 1;
                try p.out.writeAll(".Ed\n");
                return;
            }
            try p.out.writeAll("\\&");
            try escaped(p.out, text);
            try p.out.writeByte('\n');
        }
        return p.bad.fail("unclosed example fence");
    }

    fn isName(p: *Page, word: []const u8) bool {
        var it = mem.splitSequence(u8, p.names, ", ");
        while (it.next()) |name| if (mem.eql(u8, name, word)) return true;
        return false;
    }

    /// Each inline token becomes a semantic macro. Quoted, escaped arguments
    /// cannot turn a word such as "Sh" or a leading dot into roff instructions.
    /// Ns preserves adjacency; Oo/Oc preserve nested optional synopsis groups.
    fn inlineText(p: *Page, text: []const u8, synopsis: bool, tag: bool) Error!void {
        if (synopsis and !mem.startsWith(u8, text, "**"))
            return p.bad.fail("a synopsis starts with a bold command");
        var at: usize = 0;
        var depth: usize = 0;
        var first = true;
        var opened = false;
        var plain_line = false;
        var sep: []const u8 = if (tag) " " else ".";
        while (at < text.len) {
            var space = false;
            while (at < text.len and text[at] == ' ') : (at += 1) space = true;
            if (at == text.len) break;
            if (synopsis and !first and space and depth == 0 and !mem.eql(u8, sep, ".")) {
                try p.out.writeByte('\n');
                sep = ".";
            }
            if ((synopsis or tag) and !first and !space and !opened and text[at] != ']') {
                try p.out.print("{s}Ns", .{sep});
                sep = " ";
            }
            if ((synopsis or tag) and (text[at] == '[' or text[at] == ']')) {
                if (text[at] == '[') {
                    if (depth == 16) return p.bad.fail("optional groups nested too deeply");
                    depth += 1;
                    try p.out.print("{s}Oo", .{sep});
                    opened = true;
                } else {
                    if (depth == 0 or
                        opened) return p.bad.fail("unbalanced or empty optional group");
                    depth -= 1;
                    try p.out.print("{s}Oc", .{sep});
                    opened = false;
                }
                at += 1;
                sep = " ";
                first = false;
                continue;
            }
            var macro: []const u8 = "No";
            var word: []const u8 = undefined;
            var xr: ?Reference = null;
            if (text[at] == '*' or text[at] == '`') {
                const bold = mem.startsWith(u8, text[at..], "**");
                const delimiter: []const u8 = if (bold) "**" else text[at .. at + 1];
                const begin = at + delimiter.len;
                const close = mem.find(u8, text[begin..], delimiter) orelse
                    return p.bad.fail("unclosed inline markup");
                word = text[begin .. begin + close];
                if (word.len == 0 or word[0] == ' ' or word[word.len - 1] == ' ')
                    return p.bad.fail("empty or padded inline markup");
                if (text[at] == '*') {
                    if (mem.findAny(u8, word, "*`") != null)
                        return p.bad.fail("nested inline markup is not supported");
                    if (bold) {
                        macro = if (synopsis and first)
                            "Nm"
                        else if (p.isName(word))
                            "Nm"
                        else
                            "Cm";
                        if (!(synopsis and first) and word[0] == '-') {
                            macro = "Fl";
                            word = word[1..];
                        }
                    } else macro = "Ar";
                } else {
                    macro = if (word[0] == '/' or mem.startsWith(u8, word, "~/"))
                        "Pa"
                    else if (mem.eql(u8, p.section, "ENVIRONMENT") and environmentName(word))
                        "Ev"
                    else
                        "Li";
                }
                at = begin + close + delimiter.len;
            } else if (reference(text[at..])) |ref| {
                xr = ref;
                word = ref.name;
                macro = "Xr";
                at += ref.len;
            } else if (text[at] == '\\') {
                if (at + 1 == text.len or !std.ascii.isPunctuation(text[at + 1]))
                    return p.bad.fail("backslash must escape punctuation");
                word = text[at + 1 .. at + 2];
                at += 2;
            } else {
                const begin = at;
                while (at < text.len and text[at] != ' ' and
                    mem.findScalar(u8, "*`[]\\", text[at]) == null) : (at += 1)
                {
                    if (text[at] == '<') return p.bad.fail(
                        "HTML is not supported; quote literal text",
                    );
                }
                if (at == begin) return p.bad.fail(
                    "links and brackets must be quoted outside synopses",
                );
                word = text[begin..at];
            }
            if (!synopsis and !tag) {
                if (mem.eql(u8, macro, "No")) {
                    if (!space and !first and !plain_line) {
                        // mdoc recognizes punctuation after a macro and joins it
                        // without changing its font or losing sentence spacing.
                        if (mem.trim(u8, word, ".,;:!?)]").len != 0)
                            return p.bad.fail(
                                "inline markup must be separated by spaces or punctuation",
                            );
                        for (word) |c| try p.out.print(" {c}", .{c});
                    } else {
                        if (!mem.eql(u8, sep, "."))
                            try p.out.writeByte(if (plain_line) ' ' else '\n');
                        if (!plain_line and (word[0] == '.' or word[0] == '\''))
                            try p.out.writeAll("\\&");
                        try escaped(p.out, word);
                        plain_line = true;
                    }
                    sep = " ";
                    if (mem.findScalar(u8, ".!?", word[word.len - 1]) != null and
                        (at == text.len or text[at] == ' '))
                    {
                        try p.out.writeByte('\n');
                        sep = ".";
                        plain_line = false;
                    }
                    first = false;
                    continue;
                }
                if (!first and !space)
                    return p.bad.fail("inline markup must be separated by spaces");
                if (!mem.eql(u8, sep, ".")) try p.out.writeByte('\n');
                sep = ".";
                plain_line = false;
            }
            try p.out.print("{s}{s}", .{ sep, macro });
            if (word.len > 0) {
                try p.out.writeByte(' ');
                try argument(p.out, word);
            }
            if (xr) |ref| try p.out.print(" {c}", .{ref.section});
            sep = " ";
            first = false;
            opened = false;
        }
        if (depth != 0) return p.bad.fail("unclosed optional group");
        if (first) return p.bad.fail("empty inline text");
        if (!mem.eql(u8, sep, ".")) try p.out.writeByte('\n');
    }
};

const Reference = struct { name: []const u8, section: u8, len: usize };

fn nameByte(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '+';
}

fn validName(name: []const u8) bool {
    if (name.len == 0 or !std.ascii.isAlphanumeric(name[0])) return false;
    for (name) |c| if (!nameByte(c)) return false;
    return true;
}

fn reference(text: []const u8) ?Reference {
    var n: usize = 0;
    while (n < text.len and nameByte(text[n])) : (n += 1) {}
    if (!validName(text[0..n]) or n + 3 > text.len or text[n] != '(' or
        text[n + 1] < '1' or text[n + 1] > '9' or text[n + 2] != ')') return null;
    if (n + 3 < text.len and nameByte(text[n + 3]) and text[n + 3] != '.') return null;
    return .{ .name = text[0..n], .section = text[n + 1], .len = n + 3 };
}

fn environmentName(text: []const u8) bool {
    if (text.len == 0 or std.ascii.isDigit(text[0])) return false;
    for (text) |c| if (!(std.ascii.isUpper(c) or std.ascii.isDigit(c) or c == '_')) return false;
    return true;
}

fn validDate(text: []const u8) bool {
    var words = mem.splitScalar(u8, text, ' ');
    const month = words.next() orelse return false;
    const day = words.next() orelse return false;
    const year = words.next() orelse return false;
    if (words.next() != null or day.len < 2 or day[day.len - 1] != ',' or year.len != 4)
        return false;
    const d = std.fmt.parseInt(u8, day[0 .. day.len - 1], 10) catch return false;
    const y = std.fmt.parseInt(u16, year, 10) catch return false;
    if (d == 0 or d > 31 or y < 1970) return false;
    const months = [_][]const u8{
        "January", "February",  "March",   "April",    "May",      "June", "July",
        "August",  "September", "October", "November", "December",
    };
    const days = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    for (months, 0..) |m, i| if (mem.eql(u8, m, month)) {
        const leap: u8 = if (i == 1 and y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) 1 else 0;
        return d <= days[i] + leap;
    };
    return false;
}

fn escaped(out: *Writer, text: []const u8) Writer.Error!void {
    for (text) |c| switch (c) {
        '\\' => try out.writeAll("\\e"),
        '"' => try out.writeAll("\\(dq"),
        else => try out.writeByte(c),
    };
}

fn argument(out: *Writer, text: []const u8) Writer.Error!void {
    try out.writeAll("\"\\&");
    try escaped(out, text);
    try out.writeByte('"');
}

const testing = std.testing;
const test_head =
    "# sample(8)\n\n<!-- date: October 25, 2026 -->\n<!-- os: Werewolf -->\n\n" ++
    "## NAME\n\nsample — exercise the compiler\n\n## SYNOPSIS\n\n";

fn testCompile(a: Allocator, text: []const u8) ![]const u8 {
    var bad: Bad = .{};
    return compile(a, text, &bad) catch |err| {
        std.debug.print("line {d}: {s}\n", .{ bad.line, bad.why });
        return err;
    };
}

test "synopses preserve commands, flags, operands and nested optional groups" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const text = try testCompile(arena.allocator(), test_head ++
        "**sample** **-o** *remount*[,options] [*file* [*argument ...*]]\n\n" ++
        "## DESCRIPTION\n\nSee other(1), then **sample**.\n");
    try testing.expect(mem.find(u8, text, ".Nm \"\\&sample\"\n.Fl \"\\&o\"\n") != null);
    try testing.expect(mem.find(u8, text, ".Ar \"\\&remount\" Ns Oo ") != null);
    try testing.expect(mem.find(u8, text, " Oo Ar \"\\&argument ...\" Oc Oc\n") != null);
    try testing.expect(mem.find(u8, text, ".Xr \"\\&other\" 1 ,\n") != null);
}

test "tags, files, environment variables and examples retain their roles" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const text = try testCompile(arena.allocator(), test_head ++
        "**sample**\n\n## DESCRIPTION\n\n- **--verbose**\n\n  Show progress.\n\n" ++
        "  A second paragraph.\n\n## ENVIRONMENT\n\n- `PATH`\n\n  Search path.\n\n" ++
        "## FILES\n\n- `/etc/sample`\n\n  Settings.\n\n" ++
        "## EXAMPLES\n\n```sh\nsample --verbose\n```\n");
    for ([_][]const u8{
        ".It Fl \"\\&-verbose\"\n",
        ".It Ev \"\\&PATH\"\n",
        ".It Pa \"\\&/etc/sample\"\n",
        ".Bd -literal -offset indent\n\\&sample --verbose\n.Ed\n",
    }) |needle| try testing.expect(mem.find(u8, text, needle) != null);
}

test "roff control characters and macro names are data" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const text = try testCompile(arena.allocator(), test_head ++
        "**sample**\n\n## DESCRIPTION\n\n.Sh INJECTED\n\n" ++
        "**Sh** *Nm* `\\*[danger]` \"quoted\"\n\n```text\n.so /etc/passwd\n'br\n\\n[foo]\n```\n");
    try testing.expect(mem.find(u8, text, "\n\\&.Sh INJECTED\n") != null);
    try testing.expect(mem.find(u8, text, ".Cm \"\\&Sh\"") != null);
    try testing.expect(mem.find(u8, text, "\\e*[danger]") != null);
    try testing.expect(mem.find(u8, text, "\n\\&.so /etc/passwd\n\\&'br\n\\&\\en[foo]\n") != null);
    try testing.expect(mem.find(u8, text, "\n.so ") == null);
}

test "refuse incomplete or unsupported input instead of dropping it" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{
        "**sample** [*file*\n\n## DESCRIPTION\n\nText.\n",
        "sample --help\n\n## DESCRIPTION\n\nText.\n",
        "[**sample**]\n\n## DESCRIPTION\n\nText.\n",
        "**sample**\n\n## DESCRIPTION\n\n**unfinished\n",
        "**sample**\n\n## DESCRIPTION\n\n[link](file)\n",
        "**sample**\n\n## DESCRIPTION\n\n<b>HTML</b>\n",
        "**sample**\n\n## DESCRIPTION\n\n| table |\n",
        "**sample**\n\n## DESCRIPTION\n\n- **tag**\n\nNo description.\n",
        "**sample**\n\n## DESCRIPTION\n\n```\nunclosed\n",
        "**sample**\n\n## DESCRIPTION\n\ntext\x00\n",
        "**sample**\n\n## DESCRIPTION\n\n## DESCRIPTION\n",
        "**sample**\n\n## DESCRIPTION\n",
        "**sample**\n\n## DESCRIPTION\n\n1. numbered list\n",
        "`sample`\n\n## DESCRIPTION\n\nText.\n",
    }) |body| {
        var bad: Bad = .{};
        try testing.expectError(
            error.Invalid,
            compile(a, try mem.concat(a, u8, &.{ test_head, body }), &bad),
        );
        try testing.expect(bad.line > 1);
        try testing.expect(bad.why.len > 0);
    }
}

test "metadata is explicit, deterministic and bounded" {
    try testing.expect(validDate("February 29, 2024"));
    try testing.expect(!validDate("February 29, 2025"));
    try testing.expect(!validDate("October 0, 2026"));
    try testing.expect(!validDate("October 25, 2026 extra"));
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const input = test_head ++ "**sample**\n\n## DESCRIPTION\n\nText.\n";
    try testing.expectEqualStrings(try testCompile(a, input), try testCompile(a, input));
    var bad: Bad = .{};
    try testing.expectError(error.Invalid, compile(a, "# sample(8)\n## NAME\n", &bad));
    try testing.expectEqual(2, bad.line);
    const large = try a.alloc(u8, limit + 1);
    @memset(large, 'a');
    try testing.expectError(error.Invalid, compile(a, large, &bad));
    try testing.expectError(error.Invalid, compile(a, "\xff", &bad));
}
