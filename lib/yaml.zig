//! yaml parses the small, strict subset of YAML that form.yaml is written in,
//! and writes it back. The plan dialect, for tests.yaml on the build host,
//! adds quoted and path keys, the \n \t \r escapes, `|` blocks and flow lists
//! over several lines. Machines read only the form dialect: the plan's code
//! is not in their programs. Everything else YAML has is refused, with its
//! line. See lib/README.md.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;

pub const Node = union(enum) {
    scalar: Scalar,
    list: []const Node,
    map: []const Entry,

    /// get returns the value under key, or null if node is not a map with it.
    pub fn get(node: Node, key: []const u8) ?Node {
        if (node != .map) return null;
        for (node.map) |e| if (mem.eql(u8, e.key, key)) return e.value;
        return null;
    }
};

pub const Scalar = struct {
    /// raw keeps quotes as written and folds plain continuations to spaces,
    /// so a merged config gives apko the same value. A `|` block's is "|".
    raw: []const u8,
    /// text is the value, unquoted.
    text: []const u8,

    /// plain reports whether the scalar was written without quotes, so a
    /// reader may give it a type.
    pub fn plain(s: Scalar) bool {
        return mem.findScalar(u8, "\"'|", s.raw[0]) == null;
    }
};

/// Entry is a key, its value, and the line the key is on.
pub const Entry = struct { key: []const u8, value: Node, line: usize = 0 };

/// Diagnostic is the line where a parse failed, and why.
pub const Diagnostic = struct { line: usize = 0, why: []const u8 = "" };

pub const SyntaxError = error{ Syntax, OutOfMemory };

pub const Dialect = enum { form, plan };

/// Line is a line with its comment and indentation taken off. block holds
/// the raw lines of the `|` block it opens, in the plan dialect.
const Line = struct { n: usize, indent: usize, text: []const u8, block: []const []const u8 = &.{} };

/// parse parses text as a YAML map. An empty file is an empty map.
pub fn parse(
    gpa: Allocator,
    text: []const u8,
    comptime dialect: Dialect,
    diag: *Diagnostic,
) SyntaxError!Node {
    var lines: std.ArrayList(Line) = .empty;
    var it = mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (it.next()) |raw| {
        n += 1;
        const indent = spaces(raw);
        const body = mem.trimEnd(u8, uncomment(raw[indent..]), " \t\r");
        if (body.len == 0) continue;
        if (body[0] == '\t') return failAt(diag, n, "indented with a tab: indent with spaces");
        var line: Line = .{ .n = n, .indent = indent, .text = body };
        if (dialect == .plan) {
            if (blockKey(body)) |column| {
                // A block's lines are its text, comments and all, until a line
                // that is not blank is indented no more than its key.
                var block: std.ArrayList([]const u8) = .empty;
                while (it.peek()) |next| {
                    const content = mem.trimEnd(u8, next, "\r");
                    if (mem.trim(u8, content, " ").len > 0 and
                        spaces(content) <= indent + column) break;
                    try block.append(gpa, content);
                    _ = it.next();
                    n += 1;
                }
                line.block = block.items;
            }
        }
        try lines.append(gpa, line);
    }
    if (lines.items.len == 0) return .{ .map = &.{} };
    var p: Parser(dialect) = .{ .gpa = gpa, .lines = lines.items, .diag = diag };
    if (p.lines[0].indent != 0) return p.fail(p.lines[0].n, "the first line is indented");
    if (isItem(p.lines[0].text)) return p.fail(p.lines[0].n, "a list where the keys should be");
    const doc = try p.map(0);
    if (p.i < p.lines.len) return p.fail(p.lines[p.i].n, "indented less than its block");
    return doc;
}

fn spaces(line: []const u8) usize {
    return for (line, 0..) |c, i| {
        if (c != ' ') break i;
    } else line.len;
}

fn failAt(diag: *Diagnostic, n: usize, why: []const u8) error{Syntax} {
    diag.* = .{ .line = n, .why = why };
    return error.Syntax;
}

/// uncomment strips a comment: a # outside quotes that starts the line or
/// follows a space. A quote opens only where a value can start.
fn uncomment(line: []const u8) []const u8 {
    var quote: u8 = 0;
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        const c = line[i];
        if (quote != 0) {
            if (quote == '"' and c == '\\') {
                i += 1;
            } else if (c == quote) {
                quote = 0;
            }
            continue;
        }
        const starts = i == 0 or mem.findScalar(u8, " [,", line[i - 1]) != null;
        switch (c) {
            '#' => if (starts) return line[0..i],
            '"', '\'' => if (starts) {
                quote = c;
            },
            else => {},
        }
    }
    return line;
}

fn isItem(text: []const u8) bool {
    return text[0] == '-' and (text.len == 1 or text[1] == ' ');
}

/// blockKey returns where the key starts in body, after any list dashes,
/// when body is `key: |`, the start of a block.
fn blockKey(body: []const u8) ?usize {
    var at: usize = 0;
    while (isItem(body[at..]) and body.len > at + 1) at += spaces(body[at + 1 ..]) + 1;
    const key = splitKey(.plan, body[at..]) orelse return null;
    return if (mem.eql(u8, key[1], "|")) at else null;
}

/// splitKey splits `key: rest` or `key:` into the key and the trimmed rest.
/// A form's key is letters, digits, -, _ and ., and may start with ? (a
/// weakness a host may or may not show). A plan's may be quoted, or any
/// plain word that does not start with an indicator, such as a JSON Pointer.
fn splitKey(comptime dialect: Dialect, text: []const u8) ?struct { []const u8, []const u8 } {
    const colon = if (dialect == .plan and (text[0] == '"' or text[0] == '\''))
        (closing(text) orelse return null) + 1
    else
        mem.findScalar(u8, text, ':') orelse return null;
    if (colon >= text.len or text[colon] != ':') return null;
    const key = text[0..colon];
    switch (dialect) {
        .form => {
            const word = if (key.len > 1 and key[0] == '?') key[1..] else key;
            if (word.len == 0) return null;
            for (word) |c|
                if (!std.ascii.isAlphanumeric(c) and mem.findScalar(u8, "-_.", c) == null)
                    return null;
        },
        .plan => if (key.len == 0) {
            return null;
        } else if (key[0] != '"' and key[0] != '\'') {
            if (mem.findScalar(u8, indicators, key[0]) != null) return null;
            if (mem.findAny(u8, key, " \t#") != null) return null;
        },
    }
    const rest = text[colon + 1 ..];
    if (rest.len > 0 and rest[0] != ' ') return null;
    return .{ key, mem.trimStart(u8, rest, " ") };
}

const indicators = "[]{}&*!|>%@`,-?:#'\"";

/// closing returns the index of the quote that closes text's first.
fn closing(text: []const u8) ?usize {
    var i: usize = 1;
    while (i < text.len) : (i += 1) {
        if (text[0] == '"' and text[i] == '\\') {
            i += 1;
        } else if (text[i] == text[0]) {
            if (text[0] == '"' or i + 1 == text.len or text[i + 1] != '\'') return i;
            i += 1;
        }
    }
    return null;
}

fn Parser(comptime dialect: Dialect) type {
    return struct {
        gpa: Allocator,
        lines: []Line,
        i: usize = 0,
        diag: *Diagnostic,

        const P = @This();

        fn fail(p: *P, n: usize, why: []const u8) error{Syntax} {
            return failAt(p.diag, n, why);
        }

        fn map(p: *P, indent: usize) SyntaxError!Node {
            var entries: std.ArrayList(Entry) = .empty;
            while (p.i < p.lines.len) {
                const l = p.lines[p.i];
                if (l.indent < indent) break;
                if (l.indent > indent) return p.fail(l.n, "indented more than the keys around it");
                if (isItem(l.text)) return p.fail(l.n, "a list item among keys");
                const written, const rest = splitKey(dialect, l.text) orelse
                    return p.fail(l.n, "not `key: value`");
                const key = if (written[0] == '"' or written[0] == '\'')
                    (try p.scalar(written, l.n)).text
                else
                    written;
                for (entries.items) |e|
                    if (mem.eql(u8, e.key, key)) return p.fail(l.n, "a key given twice");
                p.i += 1;
                const value = if (rest.len > 0)
                    try p.flow(rest, l.n, indent, l.block)
                else
                    try p.nested(indent, l.n);
                try entries.append(p.gpa, .{ .key = key, .value = value, .line = l.n });
            }
            return .{ .map = entries.items };
        }

        /// nested parses the value of a key with nothing after its colon: the
        /// block under it, or a list at the key's own indent, as YAML allows.
        fn nested(p: *P, indent: usize, n: usize) SyntaxError!Node {
            if (p.i < p.lines.len) {
                const next = p.lines[p.i];
                if (next.indent > indent) {
                    return if (isItem(next.text)) p.list(next.indent) else p.map(next.indent);
                }
                if (next.indent == indent and isItem(next.text)) return p.list(indent);
            }
            return p.fail(n, "a key with no value");
        }

        fn list(p: *P, indent: usize) SyntaxError!Node {
            var items: std.ArrayList(Node) = .empty;
            while (p.i < p.lines.len) {
                const l = p.lines[p.i];
                if (l.indent < indent) break;
                if (l.indent > indent) return p.fail(l.n, "indented more than the items around it");
                // A key at the list's indent ends the list; the enclosing map
                // continues.
                if (!isItem(l.text)) break;
                const rest = mem.trimStart(u8, l.text[1..], " ");
                if (rest.len == 0) return p.fail(l.n, "an empty item");
                const keyed = switch (dialect) {
                    .form => rest[0] != '"' and rest[0] != '\'' and splitKey(.form, rest) != null,
                    .plan => splitKey(.plan, rest) != null,
                };
                if (keyed) {
                    // A map item: its first key is on the item's line, the rest below.
                    const at = l.indent + (l.text.len - rest.len);
                    p.lines[p.i] = .{ .n = l.n, .indent = at, .text = rest, .block = l.block };
                    try items.append(p.gpa, try p.map(at));
                } else {
                    p.i += 1;
                    try items.append(p.gpa, try p.flow(rest, l.n, indent, l.block));
                }
            }
            return .{ .list = items.items };
        }

        /// flow parses a value on its key's or item's line: a scalar, `[a, b]`
        /// or `{}`; in a plan, also `|` and its block, or a list over lines.
        fn flow(
            p: *P,
            text: []const u8,
            n: usize,
            indent: usize,
            block: []const []const u8,
        ) SyntaxError!Node {
            if (mem.eql(u8, text, "{}")) return .{ .map = &.{} };
            if (dialect == .plan and mem.eql(u8, text, "|"))
                return .{ .scalar = .{ .raw = "|", .text = try p.literal(block, n) } };
            if (text[0] != '[') {
                const first = try p.scalar(text, n);
                if (text[0] == '"' or text[0] == '\'' or
                    p.i == p.lines.len or p.lines[p.i].indent <= indent)
                    return .{ .scalar = first };
                // Plain YAML values may continue on adjacent, indented lines.
                // Blank lines have different folding rules and are outside this subset.
                var joined: std.ArrayList(u8) = .empty;
                try joined.appendSlice(p.gpa, text);
                var last = n;
                while (p.i < p.lines.len and p.lines[p.i].indent > indent) : (p.i += 1) {
                    const next = p.lines[p.i];
                    if (next.n != last + 1 or isItem(next.text))
                        return p.fail(next.n, "a continuation must be an adjacent plain value");
                    try joined.append(p.gpa, ' ');
                    try joined.appendSlice(p.gpa, next.text);
                    // Validate the joined value too, so nested keys cannot become text.
                    _ = try p.scalar(joined.items, next.n);
                    last = next.n;
                }
                return .{ .scalar = try p.scalar(joined.items, n) };
            }
            var whole = text;
            if (dialect == .plan and text[text.len - 1] != ']') {
                // A plan's list may go on over adjacent lines indented under its key.
                var joined: std.ArrayList(u8) = .empty;
                try joined.appendSlice(p.gpa, text);
                var last = n;
                while (joined.items[joined.items.len - 1] != ']') : (p.i += 1) {
                    if (p.i == p.lines.len or p.lines[p.i].indent <= indent or
                        p.lines[p.i].n != last + 1) break;
                    try joined.append(p.gpa, ' ');
                    try joined.appendSlice(p.gpa, p.lines[p.i].text);
                    last = p.lines[p.i].n;
                }
                whole = joined.items;
            }
            if (whole[whole.len - 1] != ']') return p.fail(n, "a list that does not end with ]");
            const inner = mem.trim(u8, whole[1 .. whole.len - 1], " ");
            var items: std.ArrayList(Node) = .empty;
            var start: usize = 0;
            var quote: u8 = 0;
            var i: usize = 0;
            while (i <= inner.len) : (i += 1) {
                if (i < inner.len) {
                    const c = inner[i];
                    if (quote != 0) {
                        if (quote == '"' and c == '\\') {
                            i += 1;
                        } else if (c == quote) {
                            quote = 0;
                        }
                        continue;
                    }
                    if ((c == '"' or c == '\'') and
                        mem.trim(u8, inner[start..i], " ").len == 0) quote = c;
                    if (c != ',') continue;
                }
                const item = mem.trim(u8, inner[start..@min(i, inner.len)], " ");
                start = i + 1;
                if (item.len == 0) {
                    if (i == inner.len and items.items.len == 0) break;
                    return p.fail(n, "an empty item in [ ]");
                }
                try items.append(p.gpa, .{ .scalar = try p.scalar(item, n) });
            }
            return .{ .list = items.items };
        }

        /// literal is a `|` block's text: its lines without the first line's
        /// indentation, each ending in a newline, and no blank lines at the end.
        fn literal(p: *P, block: []const []const u8, n: usize) SyntaxError![]const u8 {
            var out: std.ArrayList(u8) = .empty;
            var column: ?usize = null;
            for (block, n + 1..) |l, at| {
                if (mem.trim(u8, l, " ").len > 0) {
                    const c = column orelse spaces(l);
                    column = c;
                    if (spaces(l) < c)
                        return p.fail(at, "a block line indented less than its first line");
                    try out.appendSlice(p.gpa, l[c..]);
                }
                try out.append(p.gpa, '\n');
            }
            const text = mem.trimEnd(u8, out.items, "\n");
            return if (text.len == 0) "" else out.items[0 .. text.len + 1];
        }

        fn scalar(p: *P, text: []const u8, n: usize) SyntaxError!Scalar {
            switch (text[0]) {
                '"' => {
                    if (text.len < 2 or
                        text[text.len - 1] != '"') return p.fail(n, "a \" that is not closed");
                    var out: std.ArrayList(u8) = .empty;
                    var i: usize = 1;
                    while (i < text.len - 1) : (i += 1) {
                        var c = text[i];
                        if (c == '"') return p.fail(n, "a \" inside a \"string\": write \\\"");
                        if (c == '\\') {
                            i += 1;
                            if (i == text.len - 1) return p.fail(
                                n,
                                "a \\ at the end of a \"string\"",
                            );
                            c = text[i];
                            if (c != '"' and c != '\\') c = switch (dialect) {
                                .form => return p.fail(n, "an escape other than \\\" or \\\\"),
                                .plan => switch (c) {
                                    'n' => '\n',
                                    't' => '\t',
                                    'r' => '\r',
                                    else => return p.fail(
                                        n,
                                        "an escape other than \\n, \\t, \\r, \\\" or \\\\",
                                    ),
                                },
                            };
                        }
                        try out.append(p.gpa, c);
                    }
                    return .{ .raw = text, .text = out.items };
                },
                '\'' => {
                    if (text.len < 2 or
                        text[text.len - 1] != '\'') return p.fail(n, "a ' that is not closed");
                    const inner = text[1 .. text.len - 1];
                    var out: std.ArrayList(u8) = .empty;
                    var i: usize = 0;
                    while (i < inner.len) : (i += 1) {
                        if (inner[i] == '\'') {
                            if (i + 1 == inner.len or
                                inner[i + 1] != '\'') return p.fail(
                                n,
                                "a ' inside a 'string': write ''",
                            );
                            i += 1;
                        }
                        try out.append(p.gpa, inner[i]);
                    }
                    return .{ .raw = text, .text = out.items };
                },
                '[',
                ']',
                '{',
                '}',
                '&',
                '*',
                '!',
                '|',
                '>',
                '%',
                '@',
                '`',
                ',',
                => return p.fail(n, "a value that starts with a YAML indicator: quote it"),
                '-', '?', ':' => if (text.len == 1 or text[1] == ' ')
                    return p.fail(n, "a value that starts with a YAML indicator: quote it"),
                else => {},
            }
            if (mem.find(u8, text, ": ") != null or text[text.len - 1] == ':')
                return p.fail(n, "a value holding `: `: quote it");
            return .{ .raw = text, .text = text };
        }
    };
}

/// write writes node, a map, as block YAML, each scalar as it was written.
pub fn write(w: *Io.Writer, node: Node) Io.Writer.Error!void {
    try writeEntries(w, node.map, 0, false);
}

fn writeEntries(
    w: *Io.Writer,
    entries: []const Entry,
    indent: usize,
    inline_first: bool,
) Io.Writer.Error!void {
    for (entries, 0..) |e, i| {
        if (!inline_first or i > 0) try w.splatByteAll(' ', indent);
        try w.print("{s}:", .{e.key});
        try writeValue(w, e.value, indent + 2);
    }
}

/// writeValue writes the rest of a line after `key:` or `-`, and the block under it.
fn writeValue(w: *Io.Writer, node: Node, indent: usize) Io.Writer.Error!void {
    switch (node) {
        .scalar => |s| try w.print(" {s}\n", .{s.raw}),
        .map => |m| if (m.len == 0) try w.writeAll(" {}\n") else {
            try w.writeAll("\n");
            try writeEntries(w, m, indent, false);
        },
        .list => |l| if (l.len == 0) try w.writeAll(" []\n") else {
            try w.writeAll("\n");
            for (l) |item| {
                try w.splatByteAll(' ', indent);
                try w.writeAll("-");
                if (item == .map and item.map.len > 0) {
                    try w.writeAll(" ");
                    try writeEntries(w, item.map, indent + 2, true);
                } else {
                    try writeValue(w, item, indent + 2);
                }
            }
        },
    }
}

/// ambiguous reports a plain scalar a YAML 1.1 reader takes for something
/// other than a string: a boolean, null, number, timestamp, merge or value.
/// A plan types plain scalars as JSON does and refuses these, so no reader
/// can take it to say something else.
pub fn ambiguous(t: []const u8) bool {
    const words = [_][]const u8{
        "yes", "Yes", "YES", "no",  "No",  "NO", "True", "TRUE", "False", "FALSE", "on",
        "On",  "ON",  "off", "Off", "OFF", "~",  "Null", "NULL", "<<",    "=",
    };
    if (oneOf(&words, t)) return true;
    return number11(t) or timestamp(t) or exponent(t);
}

/// number11 is YAML 1.1's int and float, underscores, bases and sexagesimals.
fn number11(t: []const u8) bool {
    if (oneOf(&.{ ".nan", ".NaN", ".NAN" }, t)) return true;
    if (t.len > 1 and t[0] == '.' and std.ascii.isDigit(t[1]) and fraction(t[2..])) return true;
    const s = if (t.len > 0 and (t[0] == '-' or t[0] == '+')) t[1..] else t;
    if (oneOf(&.{ ".inf", ".Inf", ".INF" }, s)) return true;
    if (s.len == 0 or !std.ascii.isDigit(s[0])) return false;
    if (s.len > 2 and mem.startsWith(u8, s, "0b") and allIn(s[2..], "01_")) return true;
    if (s.len > 2 and mem.startsWith(u8, s, "0x") and
        allIn(s[2..], "0123456789abcdefABCDEF_")) return true;
    if (s.len > 1 and s[0] == '0' and allIn(s[1..], "01234567_")) return true;
    if (mem.eql(u8, s, "0") or (s[0] != '0' and allIn(s, "0123456789_"))) return true;
    var i: usize = 1;
    while (i < s.len and (std.ascii.isDigit(s[i]) or s[i] == '_')) i += 1;
    if (i == s.len) return false;
    if (s[i] == '.') return fraction(s[i + 1 ..]);
    if (s[i] != ':') return false;
    while (i < s.len and s[i] == ':') {
        i += 1;
        if (i + 1 < s.len and s[i] >= '0' and s[i] <= '5' and std.ascii.isDigit(s[i + 1])) {
            i += 2;
        } else if (i < s.len and std.ascii.isDigit(s[i])) {
            i += 1;
        } else return false;
    }
    if (i == s.len) return s[0] != '0';
    return s[i] == '.' and allIn(s[i + 1 ..], "0123456789_");
}

/// fraction is [0-9_]* and an optional [eE][-+][0-9]+.
fn fraction(s: []const u8) bool {
    var i: usize = 0;
    while (i < s.len and (std.ascii.isDigit(s[i]) or s[i] == '_')) i += 1;
    if (i == s.len) return true;
    const e = s[i..];
    return e.len > 2 and (e[0] == 'e' or e[0] == 'E') and (e[1] == '-' or e[1] == '+') and
        allIn(e[2..], "0123456789");
}

/// timestamp is a YAML 1.1 date, or a date and time.
fn timestamp(t: []const u8) bool {
    if (t.len < 8 or !allIn(t[0..4], "0123456789") or t[4] != '-') return false;
    var i: usize = 5;
    const month = digitsAt(t, &i);
    if (month == 0 or month > 2 or i >= t.len or t[i] != '-') return false;
    i += 1;
    const day = digitsAt(t, &i);
    if (day == 0 or day > 2) return false;
    if (i == t.len) return month == 2 and day == 2;
    return t[i] == 'T' or t[i] == 't' or t[i] == ' ' or t[i] == '\t';
}

fn digitsAt(t: []const u8, i: *usize) usize {
    const start = i.*;
    while (i.* < t.len and std.ascii.isDigit(t[i.*])) i.* += 1;
    return i.* - start;
}

/// exponent is [+-]?[0-9]+[eE][+-]?[0-9]+, a float to JSON though not YAML 1.1.
fn exponent(t: []const u8) bool {
    var s = if (t.len > 0 and (t[0] == '-' or t[0] == '+')) t[1..] else t;
    const e = mem.findAny(u8, s, "eE") orelse return false;
    var power = s[e + 1 ..];
    if (power.len > 0 and (power[0] == '-' or power[0] == '+')) power = power[1..];
    s = s[0..e];
    return s.len > 0 and power.len > 0 and allIn(s, "0123456789") and allIn(power, "0123456789");
}

fn oneOf(words: []const []const u8, t: []const u8) bool {
    for (words) |w| if (mem.eql(u8, w, t)) return true;
    return false;
}

fn allIn(s: []const u8, set: []const u8) bool {
    for (s) |c| if (mem.findScalar(u8, set, c) == null) return false;
    return true;
}

const testing = std.testing;

fn testParse(arena: Allocator, text: []const u8, comptime dialect: Dialect) !Node {
    var d: Diagnostic = .{};
    return parse(arena, text, dialect, &d) catch |err| {
        std.debug.print("line {d}: {s}\n", .{ d.line, d.why });
        return err;
    };
}

fn testWrite(arena: Allocator, node: Node) ![]const u8 {
    var out: Io.Writer.Allocating = .init(arena);
    try write(&out.writer, node);
    return out.written();
}

test "parse: maps, lists, item maps, inline lists, comments, quotes" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const doc = try testParse(a.allocator(),
        \\# a form
        \\contents:
        \\  packages:
        \\    - runit                 # PID 1 after init
        \\    - "a #b"
        \\accounts:
        \\  users:
        \\    - username: _seal
        \\      uid: 66
        \\  groups:
        \\  - groupname: _seal
        \\with: [postgresql, 'valkey', "nginx"]
        \\weaknesses:
        \\  ?kernel-no-hypervisor: it runs VMs, where its host lends the hardware
        \\paths:
        \\  - path: /usr/bin/x
        \\    permissions: 0o755
        \\empty: []
        \\
    , .form);
    const pkgs = doc.get("contents").?.get("packages").?.list;
    try testing.expectEqual(2, pkgs.len);
    try testing.expectEqualStrings("runit", pkgs[0].scalar.text);
    try testing.expectEqualStrings("a #b", pkgs[1].scalar.text);
    try testing.expectEqualStrings("\"a #b\"", pkgs[1].scalar.raw);
    const users = doc.get("accounts").?.get("users").?.list;
    try testing.expectEqualStrings("66", users[0].get("uid").?.scalar.text);
    try testing.expectEqual(8, users[0].map[0].line);
    try testing.expectEqual(9, users[0].map[1].line);
    try testing.expectEqualStrings(
        "_seal",
        doc.get("accounts").?.get("groups").?.list[0].get("groupname").?.scalar.text,
    );
    const with = doc.get("with").?.list;
    try testing.expectEqual(3, with.len);
    try testing.expectEqualStrings("valkey", with[1].scalar.text);
    try testing.expectEqualStrings("?kernel-no-hypervisor", doc.get("weaknesses").?.map[0].key);
    try testing.expectEqualStrings(
        "0o755",
        doc.get("paths").?.list[0].get("permissions").?.scalar.raw,
    );
    try testing.expectEqual(0, doc.get("empty").?.list.len);
}

test "parse: plain continuations preserve commands and round-trip" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const doc = try testParse(gpa,
        \\services:
        \\  web:
        \\    exec: /usr/bin/server --port 80
        \\      --config /etc/server.conf
        \\    before:
        \\      - /usr/bin/python -c
        \\        "print('ready')"
        \\      - /usr/bin/check
        \\    user: web
        \\accounts:
        \\  users:
        \\    - username: web
        \\      homedir: /data/web
        \\        directory
        \\      uid: 1000
    , .form);
    const web = doc.get("services").?.get("web").?;
    const command = "/usr/bin/server --port 80 --config /etc/server.conf";
    try testing.expectEqualStrings(command, web.get("exec").?.scalar.text);
    try testing.expectEqualStrings("web", web.get("user").?.scalar.text);
    const before = web.get("before").?.list;
    try testing.expectEqual(2, before.len);
    try testing.expectEqualStrings("/usr/bin/python -c \"print('ready')\"", before[0].scalar.text);
    const users = doc.get("accounts").?.get("users").?.list;
    try testing.expectEqualStrings("/data/web directory", users[0].get("homedir").?.scalar.text);
    try testing.expectEqualStrings("1000", users[0].get("uid").?.scalar.text);
    const written = try testWrite(gpa, doc);
    const again = try testParse(gpa, written, .form);
    try testing.expectEqualStrings(
        command,
        again.get("services").?.get("web").?.get("exec").?.scalar.text,
    );
    try testing.expectEqualStrings(written, try testWrite(gpa, again));
}

test "parse: what apko might read otherwise is refused, with its line" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const bad = [_]struct { []const u8, usize }{
        .{ "a: &x 1\n", 1 },
        .{ "a: 1\nb: |\n  text\n", 2 },
        .{ "a:\n  - b: c: d\n", 2 },
        .{ "a:\n  - x\n   - y\n", 3 },
        .{ "a: 1\na: 2\n", 2 },
        .{ "a: {b: c}\n", 1 },
        .{ "a: \"open\n", 1 },
        .{ "a:\n", 1 },
        .{ "- a\n", 1 },
        .{ "a:\n\t- b\n", 2 },
        .{ "a: [b, , c]\n", 1 },
        .{ "a: \"\\n\"\n", 1 },
        .{ "?: x\n", 1 },
        .{ "a: value\n  nested: value\n", 2 },
        .{ "a: value\n\n  continuation\n", 3 },
        .{ "a: value\n  # comment\n  continuation\n", 3 },
        .{ "a: \"value\"\n  continuation\n", 2 },
        .{ "a: [value]\n  continuation\n", 2 },
        // What a plan may write, a form may not.
        .{ "'/a': b\n", 1 },
        .{ "/a: b\n", 1 },
        .{ "a: [b,\n  c]\n", 1 },
    };
    for (bad) |b| {
        var d: Diagnostic = .{};
        try testing.expectError(error.Syntax, parse(a.allocator(), b[0], .form, &d));
        try testing.expectEqual(b[1], d.line);
    }
}

test "write: what parse reads, it writes back the same" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const text =
        \\contents:
        \\  packages:
        \\    - runit
        \\    - "quoted: yes"
        \\accounts:
        \\  users:
        \\    - username: _seal
        \\      uid: 66
        \\  run-as: ""
        \\archs:
        \\  - aarch64
        \\environment: {}
        \\volumes: []
        \\
    ;
    try testing.expectEqualStrings(
        text,
        try testWrite(a.allocator(), try testParse(a.allocator(), text, .form)),
    );
}

test "plan: quoted and path keys, escapes, blocks and lists over lines" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const doc = try testParse(a.allocator(),
        \\json:
        \\  /items/0: x    # a JSON Pointer
        \\  '': root
        \\  "/a b": "line\n\ttab\r\\ \"quoted\""
        \\steps:
        \\  - stdin: |
        \\      dn: uid=alice # not a comment
        \\
        \\        indented
        \\
        \\    argv: [/usr/bin/psql, -X,
        \\           'a, b', -d]   # a comment
        \\  - empty: |
        \\    after: x
        \\
    , .plan);
    const json = doc.get("json").?;
    try testing.expectEqualStrings("/items/0", json.map[0].key);
    try testing.expectEqualStrings("", json.map[1].key);
    try testing.expectEqualStrings("/a b", json.map[2].key);
    try testing.expectEqualStrings("line\n\ttab\r\\ \"quoted\"", json.map[2].value.scalar.text);
    try testing.expect(json.map[0].value.scalar.plain());
    try testing.expect(!json.map[2].value.scalar.plain());
    const steps = doc.get("steps").?.list;
    const stdin = steps[0].get("stdin").?.scalar;
    try testing.expectEqualStrings("dn: uid=alice # not a comment\n\n  indented\n", stdin.text);
    try testing.expect(!stdin.plain());
    const argv = steps[0].get("argv").?.list;
    try testing.expectEqual(4, argv.len);
    try testing.expectEqualStrings("a, b", argv[2].scalar.text);
    try testing.expectEqual(11, steps[0].map[1].line);
    try testing.expectEqualStrings("", steps[1].get("empty").?.scalar.text);
    try testing.expectEqualStrings("x", steps[1].get("after").?.scalar.text);
}

test "plan: what YAML reads otherwise, or a plan need not say, is refused" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const bad = [_]struct { []const u8, usize }{
        .{ "a: {b: c}\n", 1 },
        .{ "a: [{b: c}]\n", 1 },
        .{ "a: [[b]]\n", 1 },
        .{ "a: \"\\x41\"\n", 1 },
        .{ "a: |-\n  b\n", 1 },
        .{ "a: >\n  b\n", 1 },
        .{ "a: 'open\n  close'\n", 1 },
        .{ "a: [b,\n\n  c]\n", 1 },
        .{ "a: [b,\nc: d\n", 1 },
        .{ "-a: b\n", 1 },
        .{ "a b: c\n", 1 },
        .{ "'a': 1\na: 2\n", 2 },
        .{ "a: |\n    b\n  c\n", 3 },
        .{ "a: &x 1\n", 1 },
    };
    for (bad) |b| {
        var d: Diagnostic = .{};
        try testing.expectError(error.Syntax, parse(a.allocator(), b[0], .plan, &d));
        try testing.expectEqual(b[1], d.line);
    }
}

test "plain scalars take JSON's types and nothing YAML 1.1 reads otherwise" {
    for ([_][]const u8{
        "yes",                       "No",    "ON",
        "~",                         "NULL",  "True",
        "0x1F",                      "0b101", "017",
        "+1",                        "1_000", "12:30",
        "1:20.5",                    ".5",    ".inf",
        "-.Inf",                     ".NaN",  "1.",
        "1e3",                       "-2E-4", "2001-12-14",
        "2001-12-14 21:59:43.10 -5", "<<",    "=",
        "01.5",
    }) |t| {
        if (!ambiguous(t)) {
            std.debug.print("not ambiguous: {s}\n", .{t});
            return error.TestUnexpectedResult;
        }
    }
    for ([_][]const u8{
        "1.2.3", "0o755", "localhost:9093", "127.0.0.1:8080", "2001-1-1", "abc", "tcp/443",
        "x1e3",  "e5",    "-",              "v1.0",           "1a",
    }) |t| {
        if (ambiguous(t)) {
            std.debug.print("ambiguous: {s}\n", .{t});
            return error.TestUnexpectedResult;
        }
    }
}
