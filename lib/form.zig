//! A form (forms/README.md): a directory, forms/NAME, holding apko.yaml,
//! the packages, accounts and paths apko installs, and form.yaml, what
//! werewolf adds that apko cannot say: the form it is built on (`base`),
//! the forms it takes beside it (`with`), its network policy, the posture
//! checks it fails and why, and the rest. This reads both, resolves a
//! form's chain, and merges the chain's apko configs into the one apko
//! builds from, by the rules apko's own `include:` merged by. apko
//! deprecated `include:`, leaving composition to its caller, and its
//! include took one file, where a form may take several.
//!
//! Both files are YAML, in the small part of it they are written in:
//! block maps and lists, indented with spaces; scalars plain or quoted;
//! a list of scalars inline, `[a, b]`; `#` comments. Anchors, tags,
//! multi-line scalars and inline maps are refused, with the line, rather
//! than read some other way than apko would.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;

pub const Node = union(enum) {
    scalar: Scalar,
    list: []const Node,
    map: []const Entry,

    /// The value under key, when node is a map that has one.
    pub fn get(node: Node, key: []const u8) ?Node {
        if (node != .map) return null;
        for (node.map) |e| if (mem.eql(u8, e.key, key)) return e.value;
        return null;
    }
};

pub const Scalar = struct {
    /// As written, quotes and all: what a merged config repeats, so apko
    /// reads every value as the form's author wrote it.
    raw: []const u8,
    /// What it says, unquoted.
    text: []const u8,
};

pub const Entry = struct { key: []const u8, value: Node };

/// Where a parse failed, and why.
pub const Diagnostic = struct { line: usize = 0, why: []const u8 = "" };

pub const SyntaxError = error{ Syntax, OutOfMemory };

const Line = struct { n: usize, indent: usize, text: []const u8 };

/// text's YAML, a map; an empty file is an empty map.
pub fn parse(gpa: Allocator, text: []const u8, diag: *Diagnostic) SyntaxError!Node {
    var lines: std.ArrayList(Line) = .empty;
    var it = mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (it.next()) |raw| {
        n += 1;
        const indent = for (raw, 0..) |c, i| {
            if (c != ' ') break i;
        } else raw.len;
        const body = mem.trimEnd(u8, uncomment(raw[indent..]), " \t\r");
        if (body.len == 0) continue;
        if (body[0] == '\t') return failAt(diag, n, "indented with a tab: indent with spaces");
        try lines.append(gpa, .{ .n = n, .indent = indent, .text = body });
    }
    if (lines.items.len == 0) return .{ .map = &.{} };
    var p: Parser = .{ .gpa = gpa, .lines = lines.items, .diag = diag };
    if (p.lines[0].indent != 0) return p.fail(p.lines[0].n, "the first line is indented");
    if (isItem(p.lines[0].text)) return p.fail(p.lines[0].n, "a list where the keys should be");
    const doc = try p.map(0);
    if (p.i < p.lines.len) return p.fail(p.lines[p.i].n, "indented less than its block");
    return doc;
}

fn failAt(diag: *Diagnostic, n: usize, why: []const u8) error{Syntax} {
    diag.* = .{ .line = n, .why = why };
    return error.Syntax;
}

/// line without its comment: from a # that starts it or follows a space,
/// outside quotes. A quote opens only where a value can start.
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

/// `key: rest` or `key:`: the key, and the rest, trimmed. A key is a
/// word of letters, digits, -, _ and ., and may start with ? (a weakness
/// a host may or may not show).
fn splitKey(text: []const u8) ?struct { []const u8, []const u8 } {
    const colon = mem.findScalar(u8, text, ':') orelse return null;
    const key = text[0..colon];
    const word = if (key.len > 1 and key[0] == '?') key[1..] else key;
    if (word.len == 0) return null;
    for (word) |c|
        if (!std.ascii.isAlphanumeric(c) and mem.findScalar(u8, "-_.", c) == null) return null;
    const rest = text[colon + 1 ..];
    if (rest.len > 0 and rest[0] != ' ') return null;
    return .{ key, mem.trimStart(u8, rest, " ") };
}

const Parser = struct {
    gpa: Allocator,
    lines: []Line,
    i: usize = 0,
    diag: *Diagnostic,

    fn fail(p: *Parser, n: usize, why: []const u8) error{Syntax} {
        return failAt(p.diag, n, why);
    }

    fn map(p: *Parser, indent: usize) SyntaxError!Node {
        var entries: std.ArrayList(Entry) = .empty;
        while (p.i < p.lines.len) {
            const l = p.lines[p.i];
            if (l.indent < indent) break;
            if (l.indent > indent) return p.fail(l.n, "indented more than the keys around it");
            if (isItem(l.text)) return p.fail(l.n, "a list item among keys");
            const key, const rest = splitKey(l.text) orelse return p.fail(l.n, "not `key: value`");
            for (entries.items) |e|
                if (mem.eql(u8, e.key, key)) return p.fail(l.n, "a key given twice");
            p.i += 1;
            const value = if (rest.len > 0) try p.flow(rest, l.n) else try p.nested(indent, l.n);
            try entries.append(p.gpa, .{ .key = key, .value = value });
        }
        return .{ .map = entries.items };
    }

    /// The value of a key with nothing after its colon: the block under
    /// it, or a list at its own indent, as YAML allows.
    fn nested(p: *Parser, indent: usize, n: usize) SyntaxError!Node {
        if (p.i < p.lines.len) {
            const next = p.lines[p.i];
            if (next.indent > indent) {
                return if (isItem(next.text)) p.list(next.indent) else p.map(next.indent);
            }
            if (next.indent == indent and isItem(next.text)) return p.list(indent);
        }
        return p.fail(n, "a key with no value");
    }

    fn list(p: *Parser, indent: usize) SyntaxError!Node {
        var items: std.ArrayList(Node) = .empty;
        while (p.i < p.lines.len) {
            const l = p.lines[p.i];
            if (l.indent < indent) break;
            if (l.indent > indent) return p.fail(l.n, "indented more than the items around it");
            // A key at the list's indent: the list was a key's value, and
            // the keys around that key go on.
            if (!isItem(l.text)) break;
            const rest = mem.trimStart(u8, l.text[1..], " ");
            if (rest.len == 0) return p.fail(l.n, "an empty item");
            if (rest[0] != '"' and rest[0] != '\'' and splitKey(rest) != null) {
                // A map: its first key on the item's line, the rest under it.
                const at = l.indent + (l.text.len - rest.len);
                p.lines[p.i] = .{ .n = l.n, .indent = at, .text = rest };
                try items.append(p.gpa, try p.map(at));
            } else {
                p.i += 1;
                try items.append(p.gpa, try p.flow(rest, l.n));
            }
        }
        return .{ .list = items.items };
    }

    /// A value on its key's or item's line: a scalar, `[a, b]` or `{}`.
    fn flow(p: *Parser, text: []const u8, n: usize) SyntaxError!Node {
        if (mem.eql(u8, text, "{}")) return .{ .map = &.{} };
        if (text[0] != '[') return .{ .scalar = try p.scalar(text, n) };
        if (text[text.len - 1] != ']') return p.fail(n, "a list that does not end with ]");
        const inner = mem.trim(u8, text[1 .. text.len - 1], " ");
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

    fn scalar(p: *Parser, text: []const u8, n: usize) SyntaxError!Scalar {
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
                        if (i == text.len - 1) return p.fail(n, "a \\ at the end of a \"string\"");
                        c = text[i];
                        if (c != '"' and
                            c != '\\') return p.fail(n, "an escape other than \\\" or \\\\");
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

/// node, a map, as block YAML, each scalar as it was written.
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

/// The rest of a line after `key:` or `-`, and the block under it.
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

/// Keys whose value a merged config takes whole from the last form that
/// gives one, as apko's include did; every other list is joined, base
/// first, every other map merged key by key, and every other scalar the
/// last form's.
const whole = [_][]const u8{ "archs", "entrypoint", "layering", "certificates", "baseimage" };

/// base with over laid on it, by apko's include's rules.
pub fn merge(gpa: Allocator, base: Node, over: Node) Allocator.Error!Node {
    if (base != .map or over != .map) return over;
    var out: std.ArrayList(Entry) = .empty;
    for (base.map) |e| {
        const o = over.get(e.key) orelse {
            try out.append(gpa, e);
            continue;
        };
        const value: Node = if (isOneOf(e.key, &whole))
            o
        else if (e.value == .list and o == .list)
            .{ .list = try mem.concat(gpa, Node, &.{ e.value.list, o.list }) }
        else if (e.value == .map and o == .map)
            try merge(gpa, e.value, o)
        else
            o;
        try out.append(gpa, .{ .key = e.key, .value = value });
    }
    for (over.map) |e| if (base.get(e.key) == null) try out.append(gpa, e);
    return .{ .map = out.items };
}

/// Why a form could not be read, for the one who wrote it.
pub const Failure = struct {
    text: []const u8 = "",

    pub fn fail(f: *Failure, gpa: Allocator, comptime fmt: []const u8, args: anytype) Error {
        f.text = try gpa.print(fmt, args);
        return error.Form;
    }
};

pub const Error = error{ Form, OutOfMemory };

pub const Form = struct {
    name: []const u8,
    /// Its directory: forms/NAME, or wherever a form outside the tree is.
    dir: []const u8,
    /// form.yaml, or an empty map when the form has none.
    spec: Node,

    /// The items of one of form.yaml's lists, unquoted; none when the
    /// form does not give it, or gives it as something else than a list
    /// of values.
    pub fn items(form: Form, gpa: Allocator, key: []const u8) Allocator.Error![]const []const u8 {
        const list = form.spec.get(key) orelse return &.{};
        if (list != .list) return &.{};
        var out: std.ArrayList([]const u8) = .empty;
        for (list.list) |item| if (item == .scalar) try out.append(gpa, item.scalar.text);
        return out.items;
    }

    /// One of form.yaml's check settings: this form's own, never one a
    /// form it is built on gives.
    pub fn check(form: Form, key: []const u8) ?Node {
        const c = form.spec.get("check") orelse return null;
        return c.get(key);
    }

    /// The posture checks this form fails, each with its excuse: this
    /// form's own, since a form built on it may not fail them.
    pub fn weaknesses(form: Form) []const Entry {
        const w = form.spec.get("weaknesses") orelse return &.{};
        return w.map;
    }
};

/// form.yaml's keys: each a list of lines, but base, a name; weaknesses,
/// a map of posture checks to excuses; and check, a map of settings.
const keys = [_][]const u8{
    "base",
    "with",
    "programs",
    "net",
    "prune",
    "dev",
    "modules",
    "weaknesses",
    "check",
};
/// check's keys: each a scalar or a list.
const check_keys = [_][]const u8{ "memory", "offline", "native", "web", "skip" };

fn isOneOf(s: []const u8, set: []const []const u8) bool {
    for (set) |k| if (mem.eql(u8, s, k)) return true;
    return false;
}

fn isScalars(node: Node) bool {
    if (node != .list) return false;
    for (node.list) |item| if (item != .scalar) return false;
    return true;
}

/// A form's name: a-z, 0-9 and -, as a directory, a host name and a make
/// target all take it.
pub fn isName(s: []const u8) bool {
    if (s.len == 0 or s.len > 64 or s[0] == '-') return false;
    for (s) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-') return false;
    return true;
}

/// The form ref names: forms/REF, or, when ref holds a slash, the form in
/// that directory, named after it.
pub fn load(io: Io, gpa: Allocator, root: Dir, ref: []const u8, f: *Failure) Error!Form {
    const outside = mem.findScalar(u8, ref, '/') != null;
    const dir = if (outside)
        mem.trimEnd(u8, ref, "/")
    else
        try gpa.print("forms/{s}", .{ref});
    const name = std.fs.path.basename(dir);
    if (!isName(name)) return f.fail(gpa, "{s}: not a form's name (a-z, 0-9 and -)", .{ref});
    const apko_path = try gpa.print("{s}/apko.yaml", .{dir});
    root.access(io, apko_path, .{}) catch
        return f.fail(gpa, "no form {s}: no {s}", .{ ref, apko_path });
    const path = try gpa.print("{s}/form.yaml", .{dir});
    const text = root.readFileAlloc(io, path, gpa, .limited(64 << 10)) catch |err| switch (err) {
        error.FileNotFound => return .{ .name = name, .dir = dir, .spec = .{ .map = &.{} } },
        error.OutOfMemory => return error.OutOfMemory,
        else => return f.fail(gpa, "{s}: {s}", .{ path, @errorName(err) }),
    };
    const spec = try parseFile(gpa, path, text, f);
    for (spec.map) |e| {
        if (!isOneOf(e.key, &keys))
            return f.fail(gpa, "{s}: no key {s} (forms/README.md lists them)", .{ path, e.key });
        if (mem.eql(u8, e.key, "base")) {
            if (e.value != .scalar or !isName(e.value.scalar.text))
                return f.fail(gpa, "{s}: base is the name of a form in forms/", .{path});
        } else if (mem.eql(u8, e.key, "weaknesses")) {
            if (e.value != .map) return f.fail(
                gpa,
                "{s}: weaknesses maps posture checks to excuses",
                .{path},
            );
            for (e.value.map) |c| if (c.value != .scalar or c.value.scalar.text.len == 0)
                return f.fail(gpa, "{s}: weakness {s} has no excuse", .{ path, c.key });
        } else if (mem.eql(u8, e.key, "check")) {
            if (e.value != .map) return f.fail(gpa, "{s}: check is a map of settings", .{path});
            for (e.value.map) |c| {
                if (!isOneOf(c.key, &check_keys))
                    return f.fail(
                        gpa,
                        "{s}: check has no key {s} (forms/README.md lists them)",
                        .{ path, c.key },
                    );
                if (c.value != .scalar and !isScalars(c.value))
                    return f.fail(
                        gpa,
                        "{s}: check's {s} is a value or a list of them",
                        .{ path, c.key },
                    );
            }
        } else if (!isScalars(e.value)) {
            return f.fail(gpa, "{s}: {s} is a list of lines", .{ path, e.key });
        }
    }
    return .{ .name = name, .dir = dir, .spec = spec };
}

fn parseFile(gpa: Allocator, path: []const u8, text: []const u8, f: *Failure) Error!Node {
    var d: Diagnostic = .{};
    return parse(gpa, text, &d) catch |err| switch (err) {
        error.Syntax => f.fail(gpa, "{s}:{d}: {s}", .{ path, d.line, d.why }),
        error.OutOfMemory => error.OutOfMemory,
    };
}

const max_chain = 16;

/// A form's chain, base first, as the build lays its parts: each form it
/// is built on, after the forms it takes `with` it (their chains' forms
/// the chain lacks, in order), and the form itself last, so each form's
/// files win over what it takes.
pub fn chain(io: Io, gpa: Allocator, root: Dir, ref: []const u8, f: *Failure) Error![]const Form {
    const top = try load(io, gpa, root, ref, f);
    var out: std.ArrayList(Form) = .empty;
    for (try bases(io, gpa, root, top, f)) |form| {
        for (try form.items(gpa, "with")) |member| {
            if (!isName(member)) return f.fail(
                gpa,
                "{s}: with names forms in forms/, not {s}",
                .{ form.dir, member },
            );
            for (try bases(io, gpa, root, try load(io, gpa, root, member, f), f)) |c| {
                if (mem.eql(u8, c.dir, top.dir))
                    return f.fail(gpa, "{s}: takes itself, through {s}", .{ top.dir, member });
                try appendNew(gpa, &out, c);
            }
        }
        try appendNew(gpa, &out, form);
    }
    return out.items;
}

fn appendNew(gpa: Allocator, out: *std.ArrayList(Form), form: Form) Allocator.Error!void {
    for (out.items) |have| if (mem.eql(u8, have.dir, form.dir)) return;
    try out.append(gpa, form);
}

/// form and the forms it is built on, base first.
pub fn bases(io: Io, gpa: Allocator, root: Dir, form: Form, f: *Failure) Error![]const Form {
    var out: std.ArrayList(Form) = .empty;
    try out.append(gpa, form);
    var at = form;
    while (at.spec.get("base")) |b| {
        if (out.items.len == max_chain) return f.fail(
            gpa,
            "{s}: built on forms {d} deep",
            .{ form.dir, max_chain },
        );
        at = try load(io, gpa, root, b.scalar.text, f);
        for (out.items) |have| if (mem.eql(u8, have.dir, at.dir))
            return f.fail(gpa, "{s}: built on itself, through {s}", .{ form.dir, have.dir });
        try out.insert(gpa, 0, at);
    }
    return out.items;
}

/// The chain's apko configs as one, and extra's packages after theirs (a
/// DEV build's shell): what apko builds the form from.
pub fn apko(
    io: Io,
    gpa: Allocator,
    root: Dir,
    forms: []const Form,
    extra: []const []const u8,
    f: *Failure,
) Error!Node {
    var merged: Node = .{ .map = &.{} };
    for (forms) |form| {
        const path = try gpa.print("{s}/apko.yaml", .{form.dir});
        const text = root.readFileAlloc(io, path, gpa, .limited(256 << 10)) catch |err|
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return f.fail(gpa, "{s}: {s}", .{ path, @errorName(err) }),
            };
        const doc = try parseFile(gpa, path, text, f);
        if (doc.get("include") != null)
            return f.fail(
                gpa,
                "{s}: include: is apko's, and deprecated: name the form in form.yaml's base",
                .{path},
            );
        merged = try merge(gpa, merged, doc);
    }
    if (extra.len == 0) return merged;
    const packages = try gpa.alloc(Node, extra.len);
    for (extra, packages) |p, *node| node.* = .{ .scalar = .{ .raw = p, .text = p } };
    const contents = try gpa.dupe(
        Entry,
        &.{.{ .key = "packages", .value = .{ .list = packages } }},
    );
    const add = try gpa.dupe(Entry, &.{.{ .key = "contents", .value = .{ .map = contents } }});
    return merge(gpa, merged, .{ .map = add });
}

const testing = std.testing;

fn testParse(arena: Allocator, text: []const u8) !Node {
    var d: Diagnostic = .{};
    return parse(arena, text, &d) catch |err| {
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
    );
    const pkgs = doc.get("contents").?.get("packages").?.list;
    try testing.expectEqual(2, pkgs.len);
    try testing.expectEqualStrings("runit", pkgs[0].scalar.text);
    try testing.expectEqualStrings("a #b", pkgs[1].scalar.text);
    try testing.expectEqualStrings("\"a #b\"", pkgs[1].scalar.raw);
    const users = doc.get("accounts").?.get("users").?.list;
    try testing.expectEqualStrings("66", users[0].get("uid").?.scalar.text);
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
    };
    for (bad) |b| {
        var d: Diagnostic = .{};
        try testing.expectError(error.Syntax, parse(a.allocator(), b[0], &d));
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
        try testWrite(a.allocator(), try testParse(a.allocator(), text)),
    );
}

test "merge: lists joined base first, maps by key, scalars and whole keys the last form's" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const base = try testParse(gpa,
        \\contents:
        \\  repositories: [https://packages.wolfi.dev/os]
        \\  packages: [runit]
        \\archs: [aarch64, x86_64]
        \\accounts:
        \\  run-as: "0"
        \\  users:
        \\    - username: a
        \\environment:
        \\  A: "1"
        \\  B: "1"
        \\
    );
    const over = try testParse(gpa,
        \\contents:
        \\  packages: [gitea]
        \\archs: [x86_64]
        \\accounts:
        \\  users:
        \\    - username: b
        \\environment:
        \\  B: "2"
        \\paths:
        \\  - path: /x
        \\
    );
    try testing.expectEqualStrings(
        \\contents:
        \\  repositories:
        \\    - https://packages.wolfi.dev/os
        \\  packages:
        \\    - runit
        \\    - gitea
        \\archs:
        \\  - x86_64
        \\accounts:
        \\  run-as: "0"
        \\  users:
        \\    - username: a
        \\    - username: b
        \\environment:
        \\  A: "1"
        \\  B: "2"
        \\paths:
        \\  - path: /x
        \\
    , try testWrite(gpa, try merge(gpa, base, over)));
}

test "chain: base first, each form after what it takes, itself last" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    for ([_][2][]const u8{
        .{ "minimal", "" },
        .{ "prod", "base: minimal\n" },
        .{ "ruby", "base: prod\n" },
        .{ "postgresql", "base: prod\n" },
        .{ "nginx", "base: prod\n" },
        .{ "mastodon", "base: ruby\nwith: [postgresql, nginx]\n" },
        .{ "mine", "base: mastodon\n" },
        .{ "loop", "base: loop\n" },
        .{ "sshd", "base: minimal\nweaknesses:\n  programs-no-shell: a shell for logins\n" },
        .{ "bastion", "base: sshd\n" },
    }) |form| {
        try tmp.dir.createDirPath(io, try gpa.print("forms/{s}", .{form[0]}));
        try tmp.dir.writeFile(
            io,
            .{ .sub_path = try gpa.print("forms/{s}/apko.yaml", .{form[0]}), .data = "" },
        );
        if (form[1].len > 0) try tmp.dir.writeFile(
            io,
            .{ .sub_path = try gpa.print("forms/{s}/form.yaml", .{form[0]}), .data = form[1] },
        );
    }
    var f: Failure = .{};
    for ([_]struct { []const u8, []const []const u8 }{
        .{ "nginx", &.{ "minimal", "prod", "nginx" } },
        .{ "mastodon", &.{ "minimal", "prod", "ruby", "postgresql", "nginx", "mastodon" } },
        .{ "mine", &.{ "minimal", "prod", "ruby", "postgresql", "nginx", "mastodon", "mine" } },
    }) |c| {
        const got = try chain(io, gpa, tmp.dir, c[0], &f);
        try testing.expectEqual(c[1].len, got.len);
        for (c[1], got) |want, g| try testing.expectEqualStrings(want, g.name);
    }
    try testing.expectError(error.Form, chain(io, gpa, tmp.dir, "loop", &f));
    try testing.expectError(error.Form, chain(io, gpa, tmp.dir, "absent", &f));

    // No weaknesses key, or no form.yaml at all, is no weaknesses: any
    // posture failure fails the form. A form's own are never inherited.
    const forms = try chain(io, gpa, tmp.dir, "bastion", &f);
    try testing.expectEqual(0, forms[0].weaknesses().len);
    try testing.expectEqual(1, forms[1].weaknesses().len);
    try testing.expectEqualStrings("programs-no-shell", forms[1].weaknesses()[0].key);
    try testing.expectEqual(0, forms[2].weaknesses().len);
}

test "isName" {
    try testing.expect(isName("prod-ssh"));
    try testing.expect(isName("step-ca"));
    try testing.expect(!isName(""));
    try testing.expect(!isName("-x"));
    try testing.expect(!isName("Prod"));
    try testing.expect(!isName("a/b"));
    try testing.expect(!isName("a_b"));
}
