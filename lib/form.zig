//! form reads a form's form.yaml, resolves its chain of forms, and merges
//! what they give apko (packages, accounts, paths) into one apko config. It
//! parses only a small, strict subset of YAML. See lib/README.md and
//! forms/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const allow = @import("allow");
const sshd = @import("sshd");

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
    /// raw is the scalar as written, quotes and all. A merged config repeats
    /// it, so apko reads each value as the author wrote it.
    raw: []const u8,
    /// text is the value, unquoted.
    text: []const u8,
};

pub const Entry = struct { key: []const u8, value: Node };

/// Diagnostic is the line where a parse failed, and why.
pub const Diagnostic = struct { line: usize = 0, why: []const u8 = "" };

pub const SyntaxError = error{ Syntax, OutOfMemory };

const Line = struct { n: usize, indent: usize, text: []const u8 };

/// parse parses text as a YAML map. An empty file is an empty map.
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

/// splitKey splits `key: rest` or `key:` into the key and the trimmed rest.
/// A key is letters, digits, -, _ and ., and may start with ? (a weakness a
/// host may or may not show).
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

    /// nested parses the value of a key with nothing after its colon: the
    /// block under it, or a list at the key's own indent, as YAML allows.
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
            // A key at the list's indent ends the list; the enclosing map
            // continues.
            if (!isItem(l.text)) break;
            const rest = mem.trimStart(u8, l.text[1..], " ");
            if (rest.len == 0) return p.fail(l.n, "an empty item");
            if (rest[0] != '"' and rest[0] != '\'' and splitKey(rest) != null) {
                // A map item: its first key is on the item's line, the rest below.
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

    /// flow parses a value on its key's or item's line: a scalar, `[a, b]` or `{}`.
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

/// whole lists the keys a merged config takes whole from the last form
/// that sets them, as apko's include did. Other lists are joined base
/// first, maps merge key by key, and scalars come from the last form.
const whole = [_][]const u8{ "archs", "entrypoint", "layering", "certificates", "baseimage" };

/// merge lays over on base by the rules of apko's include.
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

/// Failure says why a form could not be read, for its author.
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
    /// dir is forms/NAME, or the directory of a form outside the tree.
    dir: []const u8,
    /// spec is form.yaml, or an empty map when the form has none.
    spec: Node,

    /// items returns the unquoted items of form.yaml's list key. It returns
    /// none if key is absent or not a list of values.
    pub fn items(form: Form, gpa: Allocator, key: []const u8) Allocator.Error![]const []const u8 {
        const list = form.spec.get(key) orelse return &.{};
        if (list != .list) return &.{};
        var out: std.ArrayList([]const u8) = .empty;
        for (list.list) |item| if (item == .scalar) try out.append(gpa, item.scalar.text);
        return out.items;
    }

    /// check returns one of this form's check settings. Check settings are
    /// never inherited from the forms it is built on.
    pub fn check(form: Form, key: []const u8) ?Node {
        const c = form.spec.get("check") orelse return null;
        return c.get(key);
    }

    /// weaknesses returns the posture checks this form fails, each with its
    /// excuse. They are not inherited: a form built on it may not fail them.
    pub fn weaknesses(form: Form) []const Entry {
        const w = form.spec.get("weaknesses") orelse return &.{};
        return w.map;
    }
};

/// keys are form.yaml's keys. Each is a list of lines except base (a name),
/// app (a path), weaknesses (checks to excuses), check (settings), sshd
/// (sshd_config keywords), bastion (its users; lib/sshd.zig), and what is
/// apko's, in apko's shape: accounts (groups and users) and paths.
const keys = [_][]const u8{
    "base",
    "with",
    "packages",
    "repositories",
    "keyring",
    "archs",
    "accounts",
    "paths",
    "allow",
    "app",
    "programs",
    "net",
    "prune",
    "dev",
    "modules",
    "weaknesses",
    "check",
    "sshd",
    "bastion",
};
/// check_keys are check's keys: memory (MiB) and web (a port) are numbers,
/// offline and native are true or false, and skip is a list of checks.
const check_keys = [_][]const u8{ "memory", "offline", "native", "web", "skip" };

/// checkMisfit says what check's key should hold, or returns null if value fits.
fn checkMisfit(key: []const u8, value: Node) ?[]const u8 {
    if (mem.eql(u8, key, "skip"))
        return if (isScalars(value)) null else "a list of checks: [listeners]";
    if (value != .scalar) return "one value";
    const text = value.scalar.text;
    if (mem.eql(u8, key, "offline") or mem.eql(u8, key, "native"))
        return if (mem.eql(u8, text, "true") or mem.eql(u8, text, "false"))
            null
        else
            "true or false";
    const n = std.fmt.parseInt(u32, text, 10) catch 0;
    if (mem.eql(u8, key, "web"))
        return if (n >= 1 and n <= 65535 and isDigits(text)) null else "a port, 1 to 65535";
    return if (n >= 1 and isDigits(text)) null else "a number of MiB";
}

fn isDigits(s: []const u8) bool {
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return s.len > 0;
}

fn isOneOf(s: []const u8, set: []const []const u8) bool {
    for (set) |k| if (mem.eql(u8, s, k)) return true;
    return false;
}

fn isScalars(node: Node) bool {
    if (node != .list) return false;
    for (node.list) |item| if (item != .scalar) return false;
    return true;
}

/// isName reports whether s is a form name: a-z, 0-9 and -, so it works as
/// a directory, a host name and a make target.
pub fn isName(s: []const u8) bool {
    if (s.len == 0 or s.len > 64 or s[0] == '-') return false;
    for (s) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-') return false;
    return true;
}

/// load reads the form ref names: forms/REF, or, when ref holds a slash,
/// the form in that directory, named after it. It checks every form.yaml key.
pub fn load(io: Io, gpa: Allocator, root: Dir, ref: []const u8, f: *Failure) Error!Form {
    return loadIn(io, gpa, root, "forms", ref, f);
}

/// loadIn is load with names resolved in directory names, not forms:
/// howl's published forms, fetched from werewolf's repository.
pub fn loadIn(
    io: Io,
    gpa: Allocator,
    root: Dir,
    names: []const u8,
    ref: []const u8,
    f: *Failure,
) Error!Form {
    const outside = mem.findScalar(u8, ref, '/') != null;
    const dir = if (outside)
        mem.trimEnd(u8, ref, "/")
    else
        try gpa.print("{s}/{s}", .{ names, ref });
    const name = std.fs.path.basename(dir);
    if (!isName(name)) return f.fail(gpa, "{s}: not a form's name (a-z, 0-9 and -)", .{ref});
    const path = try gpa.print("{s}/form.yaml", .{dir});
    const text = root.readFileAlloc(io, path, gpa, .limited(256 << 10)) catch |err| switch (err) {
        error.FileNotFound => return f.fail(gpa, "no form {s}: no {s}", .{ ref, path }),
        error.OutOfMemory => return error.OutOfMemory,
        else => return f.fail(gpa, "{s}: {s}", .{ path, @errorName(err) }),
    };
    const apko_path = try gpa.print("{s}/apko.yaml", .{dir});
    if (root.access(io, apko_path, .{})) |_| return f.fail(
        gpa,
        "{s}: apko.yaml is form.yaml's now: packages, accounts and paths go there",
        .{apko_path},
    ) else |_| {}
    const spec = try parseFile(gpa, path, text, f);
    for (spec.map) |e| {
        if (!isOneOf(e.key, &keys))
            return f.fail(gpa, "{s}: no key {s} (forms/README.md lists them)", .{ path, e.key });
        if (mem.eql(u8, e.key, "accounts")) {
            if (e.value != .map) return f.fail(
                gpa,
                "{s}: accounts is apko's: groups and users, each a list",
                .{path},
            );
        } else if (mem.eql(u8, e.key, "paths")) {
            if (e.value != .list) return f.fail(gpa, "{s}: paths is apko's: a list", .{path});
        } else if (mem.eql(u8, e.key, "base")) {
            if (e.value != .scalar or !isName(e.value.scalar.text))
                return f.fail(gpa, "{s}: base is the name of a form in forms/", .{path});
        } else if (mem.eql(u8, e.key, "app")) {
            // app must be absolute and must not contain "..".
            const p = if (e.value == .scalar) e.value.scalar.text else "";
            if (p.len < 2 or p[0] != '/' or mem.find(u8, p, "..") != null) return f.fail(
                gpa,
                "{s}: app is where the form keeps its application, an absolute path",
                .{path},
            );
        } else if (mem.eql(u8, e.key, "allow")) {
            if (!isScalars(e.value)) return f.fail(
                gpa,
                "{s}: allow is a list of allowances",
                .{path},
            );
            for (e.value.list) |a| if (std.meta.stringToEnum(
                allow.Allowance,
                a.scalar.text,
            ) == null)
                return f.fail(
                    gpa,
                    "{s}: allow {s}: no such allowance (lib/allow.zig lists them)",
                    .{ path, a.scalar.text },
                );
        } else if (mem.eql(u8, e.key, "weaknesses")) {
            if (e.value != .map) return f.fail(
                gpa,
                "{s}: weaknesses maps posture checks to excuses",
                .{path},
            );
            for (e.value.map) |c| if (c.value != .scalar or c.value.scalar.text.len == 0)
                return f.fail(gpa, "{s}: weakness {s} has no excuse", .{ path, c.key });
        } else if (mem.eql(u8, e.key, "sshd")) {
            var why: []const u8 = "";
            _ = sshd.fragment(gpa, try sshdPairs(gpa, path, e.value, f), &why) catch |err|
                switch (err) {
                    error.Invalid => return f.fail(gpa, "{s}: {s}", .{ path, why }),
                    error.OutOfMemory => return error.OutOfMemory,
                };
        } else if (mem.eql(u8, e.key, "bastion")) {
            // Check each user, allowing key files for now; whether sshd
            // takes them depends on the whole chain (bastionFiles).
            const users = try bastionUsers(gpa, path, e.value, f);
            var why: []const u8 = "";
            _ = sshd.authorizedKeys(gpa, users, true, &why) catch |err| switch (err) {
                error.Invalid => return f.fail(gpa, "{s}: {s}", .{ path, why }),
                error.OutOfMemory => return error.OutOfMemory,
            };
        } else if (mem.eql(u8, e.key, "check")) {
            if (e.value != .map) return f.fail(gpa, "{s}: check is a map of settings", .{path});
            for (e.value.map) |c| {
                if (!isOneOf(c.key, &check_keys))
                    return f.fail(
                        gpa,
                        "{s}: check has no key {s} (forms/README.md lists them)",
                        .{ path, c.key },
                    );
                if (checkMisfit(c.key, c.value)) |want|
                    return f.fail(gpa, "{s}: check's {s} is {s}", .{ path, c.key, want });
            }
        } else if (!isScalars(e.value)) {
            return f.fail(gpa, "{s}: {s} is a list of lines", .{ path, e.key });
        } else if (mem.eql(u8, e.key, "modules")) {
            for (e.value.list) |item| if (mem.findScalar(u8, item.scalar.text, ':') != null)
                return f.fail(
                    gpa,
                    "{s}: modules: {s}: ARCH and @TAG are words, without a colon: " ++
                        "aarch64 @hyperv hv_netvsc",
                    .{ path, item.scalar.text },
                );
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

/// chain returns ref's chain of forms, base first, in the order the build
/// lays them. Each form follows the forms it takes `with` it (and their
/// bases), and ref comes last, so each form's files win over what it takes.
pub fn chain(io: Io, gpa: Allocator, root: Dir, ref: []const u8, f: *Failure) Error![]const Form {
    return chainIn(io, gpa, root, "forms", ref, f);
}

/// chainIn is chain with names resolved in directory names (loadIn).
pub fn chainIn(
    io: Io,
    gpa: Allocator,
    root: Dir,
    names: []const u8,
    ref: []const u8,
    f: *Failure,
) Error![]const Form {
    const top = try loadIn(io, gpa, root, names, ref, f);
    var out: std.ArrayList(Form) = .empty;
    for (try basesIn(io, gpa, root, names, top, f)) |form| {
        for (try form.items(gpa, "with")) |member| {
            if (!isName(member)) return f.fail(
                gpa,
                "{s}: with names forms in forms/, not {s}",
                .{ form.dir, member },
            );
            const m = try loadIn(io, gpa, root, names, member, f);
            for (try basesIn(io, gpa, root, names, m, f)) |c| {
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

/// bases returns form and the forms it is built on, base first.
pub fn bases(io: Io, gpa: Allocator, root: Dir, form: Form, f: *Failure) Error![]const Form {
    return basesIn(io, gpa, root, "forms", form, f);
}

fn basesIn(
    io: Io,
    gpa: Allocator,
    root: Dir,
    names: []const u8,
    form: Form,
    f: *Failure,
) Error![]const Form {
    var out: std.ArrayList(Form) = .empty;
    try out.append(gpa, form);
    var at = form;
    while (at.spec.get("base")) |b| {
        if (out.items.len == max_chain) return f.fail(
            gpa,
            "{s}: built on forms {d} deep",
            .{ form.dir, max_chain },
        );
        at = try loadIn(io, gpa, root, names, b.scalar.text, f);
        for (out.items) |have| if (mem.eql(u8, have.dir, at.dir))
            return f.fail(gpa, "{s}: built on itself, through {s}", .{ form.dir, have.dir });
        try out.insert(gpa, 0, at);
    }
    return out.items;
}

/// Listen is a net listen line: its ports, and whether they are loopback
/// only (`listen tcp/5432 loopback`) and so unreachable from outside.
pub const Listen = struct { ports: []const u16, loopback: bool };

/// listen parses a net line of the form `listen tcp/PORT... [loopback]`.
/// It returns null for other kinds of line, and error.Invalid, with why,
/// for a malformed listen line.
pub fn listen(gpa: Allocator, line: []const u8, why: *[]const u8) error{
    Invalid,
    OutOfMemory,
}!?Listen {
    var words: std.ArrayList([]const u8) = .empty;
    var it = mem.tokenizeAny(u8, line, " \t");
    while (it.next()) |word| try words.append(gpa, word);
    const w = words.items;
    if (w.len == 0 or !mem.eql(u8, w[0], "listen")) return null;
    const loopback = mem.eql(u8, w[w.len - 1], "loopback");
    const named = w[1 .. w.len - @intFromBool(loopback)];
    if (named.len == 0) {
        why.* = "listen names tcp/PORT...";
        return error.Invalid;
    }
    const ports = try gpa.alloc(u16, named.len);
    for (named, ports) |word, *port| {
        port.* = if (mem.startsWith(u8, word, "tcp/") and isDigits(word[4..]))
            std.fmt.parseInt(u16, word[4..], 10) catch 0
        else
            0;
        if (port.* == 0) {
            why.* = try gpa.print("{s} is not tcp/PORT, 1 to 65535", .{word});
            return error.Invalid;
        }
    }
    return .{ .ports = ports, .loopback = loopback };
}

/// listens returns, in order and once each, the TCP ports the chain's net
/// listen lines serve: what a host forwards to the machine and reaches it
/// on. Loopback lines are skipped. A malformed listen line fails.
pub fn listens(gpa: Allocator, forms: []const Form, f: *Failure) Error![]const u16 {
    var ports: std.ArrayList(u16) = .empty;
    for (forms) |form| for (try form.items(gpa, "net")) |line| {
        var why: []const u8 = "";
        const l = (listen(gpa, line, &why) catch |err| switch (err) {
            error.Invalid => return f.fail(
                gpa,
                "{s}/form.yaml: net: {s}: {s}",
                .{ form.dir, line, why },
            ),
            error.OutOfMemory => return error.OutOfMemory,
        }) orelse continue;
        if (l.loopback) continue;
        for (l.ports) |port| if (mem.findScalar(u16, ports.items, port) == null)
            try ports.append(gpa, port);
    };
    return ports.items;
}

/// sshdPairs returns a form's sshd: map as pairs; each value must be a scalar.
fn sshdPairs(gpa: Allocator, path: []const u8, node: Node, f: *Failure) Error![]const sshd.Pair {
    if (node != .map) return f.fail(gpa, "{s}: sshd maps sshd_config keywords to values", .{path});
    var out: std.ArrayList(sshd.Pair) = .empty;
    for (node.map) |e| {
        if (e.value != .scalar) return f.fail(gpa, "{s}: sshd {s}: one value", .{ path, e.key });
        try out.append(gpa, .{ .flag = e.key, .value = e.value.scalar.text });
    }
    return out.items;
}

/// bastionUsers returns bastion: users:, each user a map of keys and
/// destinations lists.
fn bastionUsers(gpa: Allocator, path: []const u8, node: Node, f: *Failure) Error![]const sshd.User {
    const shape = "bastion: holds users:, each user's keys: and destinations:, lists";
    if (node != .map) return f.fail(gpa, "{s}: {s}", .{ path, shape });
    for (node.map) |e| if (!mem.eql(u8, e.key, "users"))
        return f.fail(gpa, "{s}: bastion has no key {s}: {s}", .{ path, e.key, shape });
    const users = node.get("users") orelse return &.{};
    if (users != .map) return f.fail(gpa, "{s}: {s}", .{ path, shape });
    var out: std.ArrayList(sshd.User) = .empty;
    for (users.map) |u| {
        if (u.value != .map) return f.fail(
            gpa,
            "{s}: bastion user {s}: {s}",
            .{ path, u.key, shape },
        );
        for (u.value.map) |e| if (!isOneOf(e.key, &.{ "keys", "destinations" }) or
            !isScalars(e.value))
            return f.fail(gpa, "{s}: bastion user {s}: {s}", .{ path, u.key, shape });
        try out.append(gpa, .{
            .name = u.key,
            .keys = try scalars(gpa, u.value.get("keys")),
            .destinations = try scalars(gpa, u.value.get("destinations")),
        });
    }
    return out.items;
}

fn scalars(gpa: Allocator, node: ?Node) Allocator.Error![]const []const u8 {
    const list = node orelse return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (list.list) |item| try out.append(gpa, item.scalar.text);
    return out.items;
}

/// has reports whether the chain has a form called name.
fn has(forms: []const Form, name: []const u8) bool {
    for (forms) |form| if (mem.eql(u8, form.name, name)) return true;
    return false;
}

/// runsSshd reports whether the chain runs sshd: it has the sshd form or
/// the bastion.
pub fn runsSshd(forms: []const Form) bool {
    return has(forms, "sshd") or has(forms, "bastion");
}

/// takesKeyFiles reports whether the chain's sshd accepts plain key files,
/// not only security keys (lib/sshd.zig).
pub fn takesKeyFiles(gpa: Allocator, forms: []const Form) Error!bool {
    return sshd.takesKeyFiles(try chainSshd(gpa, forms));
}

/// sshdConfig returns the image's sshd_config.d/form.conf from the chain's
/// sshd: keywords, a later form's value replacing an earlier one, or "" for
/// none. It fails unless the chain has the sshd or bastion form to read it.
pub fn sshdConfig(gpa: Allocator, forms: []const Form, f: *Failure) Error![]const u8 {
    const pairs = try chainSshd(gpa, forms);
    if (pairs.len == 0) return "";
    if (!has(forms, "sshd") and !has(forms, "bastion")) return f.fail(
        gpa,
        "{s}: sshd: no sshd in the chain reads it; with: [sshd] brings one",
        .{forms[forms.len - 1].dir},
    );
    var why: []const u8 = "";
    const frag = sshd.fragment(gpa, pairs, &why) catch |err| switch (err) {
        error.Invalid => return f.fail(gpa, "{s}: {s}", .{ forms[forms.len - 1].dir, why }),
        error.OutOfMemory => return error.OutOfMemory,
    };
    return frag.text;
}

fn chainSshd(gpa: Allocator, forms: []const Form) Error![]const sshd.Pair {
    var out: std.ArrayList(sshd.Pair) = .empty;
    var f: Failure = .{};
    for (forms) |form| {
        const node = form.spec.get("sshd") orelse continue;
        // load already checked it, so this cannot fail.
        next: for (try sshdPairs(gpa, form.dir, node, &f)) |p| {
            for (out.items) |*have| if (mem.eql(u8, have.flag, p.flag)) {
                have.* = p;
                continue :next;
            };
            try out.append(gpa, p);
        }
    }
    return out.items;
}

/// bastionFiles returns the bastion's authorized_keys and PermitOpen line
/// from the chain's bastion: users: (lib/sshd.zig). It fails if the chain
/// has no bastion form, or a destination's port has no net line
/// `connect bastion tcp/PORT`.
pub fn bastionFiles(
    gpa: Allocator,
    forms: []const Form,
    f: *Failure,
) Error!struct { keys: []const u8, permit: []const u8 } {
    const top = forms[forms.len - 1].dir;
    var users: std.ArrayList(sshd.User) = .empty;
    for (forms) |form| {
        const node = form.spec.get("bastion") orelse continue;
        try users.appendSlice(gpa, try bastionUsers(gpa, form.dir, node, f));
    }
    if (users.items.len > 0 and !has(forms, "bastion")) return f.fail(
        gpa,
        "{s}: bastion: users are the bastion's; base: bastion builds one",
        .{top},
    );
    var why: []const u8 = "";
    const text = sshd.authorizedKeys(
        gpa,
        users.items,
        sshd.takesKeyFiles(try chainSshd(gpa, forms)),
        &why,
    ) catch |err| switch (err) {
        error.Invalid => return f.fail(gpa, "{s}: {s}", .{ top, why }),
        error.OutOfMemory => return error.OutOfMemory,
    };
    const ports = try connects(gpa, forms, "bastion");
    for (users.items) |u| for (u.destinations) |d| {
        if (mem.findScalar(u16, ports, sshd.port(d)) == null) return f.fail(
            gpa,
            "{s}: bastion user {s}: destination {s}: the bastion connects to no port " ++
                "{d}; add to form.yaml's net:  - connect bastion tcp/{d}",
            .{ top, u.name, d, sshd.port(d), sshd.port(d) },
        );
    };
    return .{ .keys = text, .permit = try sshd.permitOpen(gpa, users.items) };
}

/// bastionService returns the chain's etc/sv/sshd/service with its connect
/// line replaced by the ports the chain's net lets the bastion connect to.
/// leash's Landlock and fence then agree, and a form opens a port in one
/// place, its net.
pub fn bastionService(
    io: Io,
    gpa: Allocator,
    root: Dir,
    forms: []const Form,
    f: *Failure,
) Error![]const u8 {
    const svc = for (try services(io, gpa, root, forms, f)) |s| {
        if (mem.eql(u8, s.name, "sshd")) break s;
    } else return f.fail(gpa, "{s}: the bastion has no etc/sv/sshd/service", .{forms[0].dir});
    const ports = try connects(gpa, forms, "bastion");
    var out: std.ArrayList(u8) = .empty;
    var lines = mem.splitScalar(u8, mem.trimEnd(u8, svc.text, "\n"), '\n');
    while (lines.next()) |line| {
        if (mem.startsWith(u8, line, "connect ") or mem.eql(u8, line, "connect")) continue;
        try out.print(gpa, "{s}\n", .{line});
    }
    if (ports.len > 0) {
        try out.appendSlice(
            gpa,
            "# Where the form's net lets the bastion connect (form.yaml).\nconnect",
        );
        for (ports) |p| try out.print(gpa, " tcp/{d}", .{p});
        try out.append(gpa, '\n');
    }
    return out.items;
}

/// connects returns, once each, the TCP ports in the chain's
/// `connect USER tcp/PORT...` net lines for user.
fn connects(gpa: Allocator, forms: []const Form, user: []const u8) Error![]const u16 {
    var ports: std.ArrayList(u16) = .empty;
    for (forms) |form| for (try form.items(gpa, "net")) |line| {
        var it = mem.tokenizeAny(u8, line, " \t");
        if (!mem.eql(u8, it.next() orelse "", "connect")) continue;
        if (!mem.eql(u8, it.next() orelse "", user)) continue;
        while (it.next()) |word| if (mem.startsWith(u8, word, "tcp/")) {
            const p = std.fmt.parseInt(u16, word[4..], 10) catch continue;
            if (mem.findScalar(u16, ports.items, p) == null) try ports.append(gpa, p);
        };
    };
    return ports.items;
}

/// Service is a service file, /etc/sv/NAME/service, as the image will hold it.
pub const Service = struct { name: []const u8, path: []const u8, text: []const u8 };

/// services returns the chain's service files, sorted by name. As in the
/// image, a later form's rootfs overrides an earlier one's file.
pub fn services(
    io: Io,
    gpa: Allocator,
    root: Dir,
    forms: []const Form,
    f: *Failure,
) Error![]const Service {
    var found: std.array_hash_map.String(Service) = .empty;
    for (forms) |form| {
        const sv_path = try gpa.print("{s}/rootfs/etc/sv", .{form.dir});
        var sv = root.openDir(io, sv_path, .{ .iterate = true }) catch continue;
        defer sv.close(io);
        var it = sv.iterate();
        while (it.next(io) catch |err| return f.fail(
            gpa,
            "{s}: {s}",
            .{ sv_path, @errorName(err) },
        )) |e| {
            if (e.kind != .directory) continue;
            const path = try gpa.print("{s}/{s}/service", .{ sv_path, e.name });
            const text = root.readFileAlloc(
                io,
                path,
                gpa,
                .limited(64 << 10),
            ) catch |err| switch (err) {
                error.FileNotFound => continue,
                error.OutOfMemory => return error.OutOfMemory,
                else => return f.fail(gpa, "{s}: {s}", .{ path, @errorName(err) }),
            };
            const name = try gpa.dupe(u8, e.name);
            try found.put(gpa, name, .{ .name = name, .path = path, .text = text });
        }
    }
    const out = found.values();
    std.mem.sortUnstable(Service, out, {}, struct {
        fn lt(_: void, a: Service, b: Service) bool {
            return mem.lessThan(u8, a.name, b.name);
        }
    }.lt);
    return out;
}

/// apko merges what the chain's forms give apko into the one config apko
/// builds from, base first, as apko's deprecated include: merged (lists
/// joined, maps by key, archs the last form's), adding extra's packages
/// last (a DEV build's shell). A form's repositories, keyring and packages
/// are apko's contents; its archs, accounts and paths are apko's own keys.
pub fn apko(gpa: Allocator, forms: []const Form, extra: []const []const u8) Allocator.Error!Node {
    var merged: Node = .{ .map = &.{} };
    for (forms) |form| {
        var contents: std.ArrayList(Entry) = .empty;
        for ([_][]const u8{ "repositories", "keyring", "packages" }) |key|
            if (form.spec.get(key)) |v| try contents.append(gpa, .{ .key = key, .value = v });
        var doc: std.ArrayList(Entry) = .empty;
        if (contents.items.len > 0)
            try doc.append(gpa, .{ .key = "contents", .value = .{ .map = contents.items } });
        for ([_][]const u8{ "archs", "accounts", "paths" }) |key|
            if (form.spec.get(key)) |v| try doc.append(gpa, .{ .key = key, .value = v });
        merged = try merge(gpa, merged, .{ .map = doc.items });
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

    // No weaknesses key, or no form.yaml, means no weaknesses: any posture
    // failure fails the form. Weaknesses are never inherited.
    const forms = try chain(io, gpa, tmp.dir, "bastion", &f);
    try testing.expectEqual(0, forms[0].weaknesses().len);
    try testing.expectEqual(1, forms[1].weaknesses().len);
    try testing.expectEqualStrings("programs-no-shell", forms[1].weaknesses()[0].key);
    try testing.expectEqual(0, forms[2].weaknesses().len);
}

test "load: allow names allowances; app is an absolute path" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    for ([_][2][]const u8{
        .{ "node", "allow: [jit]\napp: /usr/lib/app\n" },
        .{ "root", "allow: [root]\n" },
        .{ "scalar", "allow: jit\n" },
        .{ "relative", "app: usr/lib/app\n" },
        .{ "up", "app: /usr/../etc\n" },
    }) |form| {
        try tmp.dir.createDirPath(io, try gpa.print("forms/{s}", .{form[0]}));
        try tmp.dir.writeFile(
            io,
            .{ .sub_path = try gpa.print("forms/{s}/form.yaml", .{form[0]}), .data = form[1] },
        );
    }
    var f: Failure = .{};
    const node = try load(io, gpa, tmp.dir, "node", &f);
    try testing.expectEqualStrings("jit", (try node.items(gpa, "allow"))[0]);
    for ([_][]const u8{ "root", "scalar", "relative", "up" }) |name|
        try testing.expectError(error.Form, load(io, gpa, tmp.dir, name, &f));
}

test "services: of each name, the last form's file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    for ([_][3][]const u8{
        .{ "prod", "web", "pledge stdio\n" },
        .{ "prod", "db", "pledge ipc\n" },
        .{ "site", "web", "pledge inet\n" },
    }) |s| {
        try tmp.dir.createDirPath(
            io,
            try gpa.print("forms/{s}/rootfs/etc/sv/{s}", .{ s[0], s[1] }),
        );
        try tmp.dir.writeFile(io, .{
            .sub_path = try gpa.print("forms/{s}/rootfs/etc/sv/{s}/service", .{ s[0], s[1] }),
            .data = s[2],
        });
    }
    // A service directory with no service file (runit's run) is skipped.
    try tmp.dir.createDirPath(io, "forms/site/rootfs/etc/sv/own");
    const forms = [_]Form{
        .{ .name = "prod", .dir = "forms/prod", .spec = .{ .map = &.{} } },
        .{ .name = "site", .dir = "forms/site", .spec = .{ .map = &.{} } },
    };
    var f: Failure = .{};
    const got = try services(io, gpa, tmp.dir, &forms, &f);
    try testing.expectEqual(2, got.len);
    try testing.expectEqualStrings("db", got[0].name);
    try testing.expectEqualStrings("web", got[1].name);
    try testing.expectEqualStrings("pledge inet\n", got[1].text);
    try testing.expectEqualStrings("forms/site/rootfs/etc/sv/web/service", got[1].path);
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

test listen {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    var why: []const u8 = "";
    const l = (try listen(gpa, "listen tcp/9000 tcp/9001 loopback", &why)).?;
    try testing.expectEqualSlices(u16, &.{ 9000, 9001 }, l.ports);
    try testing.expect(l.loopback);
    try testing.expect(!(try listen(gpa, "listen tcp/80", &why)).?.loopback);
    try testing.expectEqual(null, try listen(gpa, "connect caddy tcp/443", &why));
    try testing.expectError(error.Invalid, listen(gpa, "listen loopback", &why));
}

test listens {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    var f: Failure = .{};
    const spec = try testParse(gpa,
        \\net:
        \\  - listen tcp/80 tcp/443
        \\  - connect caddy tcp/443
        \\  - listen tcp/9000 loopback
        \\  - listen tcp/22 tcp/80
        \\
    );
    try testing.expectEqualSlices(
        u16,
        &.{ 80, 443, 22 },
        try listens(gpa, &.{.{ .name = "x", .dir = "forms/x", .spec = spec }}, &f),
    );
    for ([_][]const u8{
        "net: [listen]\n",
        "net: [listen loopback]\n",
        "net: [listen udp/53]\n",
        "net: [listen tcp/0]\n",
        "net: [listen tcp/65536]\n",
        "net: [listen tcp/+80]\n",
        "net: [listen loopback tcp/80]\n",
    }) |text| {
        const bad: Form = .{ .name = "x", .dir = "forms/x", .spec = try testParse(gpa, text) };
        try testing.expectError(error.Form, listens(gpa, &.{bad}, &f));
    }
}

test checkMisfit {
    const s = struct {
        fn of(text: []const u8) Node {
            return .{ .scalar = .{ .raw = text, .text = text } };
        }
    }.of;
    try testing.expectEqual(null, checkMisfit("memory", s("2048")));
    try testing.expectEqual(null, checkMisfit("web", s("3000")));
    try testing.expectEqual(null, checkMisfit("offline", s("true")));
    try testing.expectEqual(null, checkMisfit("native", s("false")));
    try testing.expectEqual(null, checkMisfit("skip", .{ .list = &.{s("listeners")} }));
    for ([_]struct { []const u8, Node }{
        .{ "memory", s("2G") },
        .{ "memory", s("0") },
        .{ "web", s("70000") },
        .{ "offline", s("yes") },
        .{ "native", s("no") },
        .{ "skip", s("listeners") },
        .{ "memory", .{ .list = &.{s("1")} } },
    }) |c| try testing.expect(checkMisfit(c[0], c[1]) != null);
}

test "load: modules without colons, check values of their kind" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    try tmp.dir.createDirPath(io, "forms/x");
    var f: Failure = .{};
    for ([_]struct { []const u8, bool }{
        .{ "modules:\n  - aarch64 @hyperv hv_netvsc\n  - \"@xfs xfs\"\n", true },
        .{ "modules:\n  - \"aarch64: virtio_mmio\"\n", false },
        .{ "check:\n  memory: 2048\n  offline: true\n  skip: [listeners]\n", true },
        .{ "check:\n  offline: yes\n", false },
        .{ "check:\n  web: http\n", false },
    }) |c| {
        try tmp.dir.writeFile(io, .{ .sub_path = "forms/x/form.yaml", .data = c[0] });
        if (c[1]) {
            _ = try load(io, gpa, tmp.dir, "x", &f);
        } else try testing.expectError(error.Form, load(io, gpa, tmp.dir, "x", &f));
    }
}

test "sshd and bastion: what the image's sshd is given, along the chain" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    const sk = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t";
    const file = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    for ([_][2][]const u8{
        .{ "minimal", "" },
        .{ "sshd", "base: minimal\nsshd:\n  log-level: INFO\n  max-auth-tries: 2\n" },
        .{ "mine", "base: sshd\nsshd:\n  log-level: VERBOSE\n" },
        .{ "bare", "base: minimal\nsshd:\n  log-level: INFO\n" },
        .{ "bastion", "base: minimal\nnet:\n  - connect bastion tcp/22\n" },
        .{
            "edge",
            "base: bastion\nnet:\n  - connect bastion tcp/2222\nbastion:\n  users:\n" ++
                "    alice:\n      keys:\n        - " ++ sk ++ " alice@laptop\n" ++
                "      destinations: [10.0.0.1:22, 10.0.0.2:2222]\n",
        },
        .{
            "far",
            "base: bastion\nbastion:\n  users:\n    bob:\n      keys: [\"" ++ sk ++
                "\"]\n      destinations: [10.0.0.1:8443]\n",
        },
        .{
            "files",
            "base: bastion\nbastion:\n  users:\n    carol:\n      keys: [\"" ++ file ++
                "\"]\n      destinations: [10.0.0.1:22]\n",
        },
        .{
            "files-ok",
            "base: files\nsshd:\n" ++
                "  pubkey-accepted-algorithms: ssh-ed25519,sk-ssh-ed25519@openssh.com\n",
        },
        .{
            "stray",
            "base: minimal\nbastion:\n  users:\n    dan:\n      keys: [\"" ++ sk ++
                "\"]\n      destinations: [10.0.0.1:22]\n",
        },
        .{ "bad-key", "base: minimal\nsshd:\n  match: all\n" },
        .{
            "bad-user",
            "base: bastion\nbastion:\n  users:\n    eve:\n      keys: [x]\n" ++
                "      destinations: [10.0.0.1:22]\n",
        },
        .{ "bad-shape", "base: bastion\nbastion:\n  alice: x\n" },
    }) |form| {
        try tmp.dir.createDirPath(io, try gpa.print("forms/{s}", .{form[0]}));
        try tmp.dir.writeFile(
            io,
            .{ .sub_path = try gpa.print("forms/{s}/form.yaml", .{form[0]}), .data = form[1] },
        );
    }
    var f: Failure = .{};
    // A later form's value replaces its base's; the rest are kept.
    try testing.expectEqualStrings(
        "# From form.yaml's sshd: (forms/README.md). sshd takes a keyword's first\n" ++
            "# value, and this file sorts before werewolf.conf.\n" ++
            "LogLevel VERBOSE\nMaxAuthTries 2\n",
        try sshdConfig(gpa, try chain(io, gpa, tmp.dir, "mine", &f), &f),
    );
    try testing.expectEqualStrings(
        "",
        try sshdConfig(gpa, try chain(io, gpa, tmp.dir, "edge", &f), &f),
    );
    try testing.expectError(
        error.Form,
        sshdConfig(gpa, try chain(io, gpa, tmp.dir, "bare", &f), &f),
    );
    try testing.expect(mem.indexOf(u8, f.text, "with: [sshd]") != null);

    const edge = try bastionFiles(gpa, try chain(io, gpa, tmp.dir, "edge", &f), &f);
    try testing.expectEqualStrings(
        "restrict,port-forwarding,permitopen=\"10.0.0.1:22\",permitopen=\"10.0.0.2:2222\" " ++
            sk ++ " alice\n",
        edge.keys,
    );
    try testing.expectEqualStrings("PermitOpen 10.0.0.1:22 10.0.0.2:2222\n", edge.permit);
    const bare = try bastionFiles(gpa, try chain(io, gpa, tmp.dir, "bastion", &f), &f);
    try testing.expectEqualStrings("", bare.keys);
    try testing.expectEqualStrings("", bare.permit);
    // A port the bastion may not connect to fails, naming the line to add.
    try testing.expectError(
        error.Form,
        bastionFiles(gpa, try chain(io, gpa, tmp.dir, "far", &f), &f),
    );
    try testing.expect(mem.indexOf(u8, f.text, "connect bastion tcp/8443") != null);
    // A key file fails until sshd: takes them.
    try testing.expectError(
        error.Form,
        bastionFiles(gpa, try chain(io, gpa, tmp.dir, "files", &f), &f),
    );
    _ = try bastionFiles(gpa, try chain(io, gpa, tmp.dir, "files-ok", &f), &f);
    try testing.expectError(
        error.Form,
        bastionFiles(gpa, try chain(io, gpa, tmp.dir, "stray", &f), &f),
    );
    for ([_][]const u8{ "bad-key", "bad-user", "bad-shape" }) |name|
        try testing.expectError(error.Form, load(io, gpa, tmp.dir, name, &f));
}

test bastionService {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const io = testing.io;
    try tmp.dir.createDirPath(io, "forms/bastion/rootfs/etc/sv/sshd");
    try tmp.dir.createDirPath(io, "forms/edge");
    for ([_][2][]const u8{
        .{ "forms/bastion/form.yaml", "net:\n  - connect bastion tcp/22\n" },
        .{
            "forms/bastion/rootfs/etc/sv/sshd/service",
            "user    bastion\nconnect tcp/22\nmemory  256\n",
        },
        .{ "forms/edge/form.yaml", "base: bastion\nnet:\n  - connect bastion tcp/2222 tcp/22\n" },
    }) |file| try tmp.dir.writeFile(io, .{ .sub_path = file[0], .data = file[1] });
    var f: Failure = .{};
    try testing.expectEqualStrings(
        "user    bastion\nmemory  256\n" ++
            "# Where the form's net lets the bastion connect (form.yaml).\nconnect tcp/22 " ++
            "tcp/2222\n",
        try bastionService(io, gpa, tmp.dir, try chain(io, gpa, tmp.dir, "edge", &f), &f),
    );
}
