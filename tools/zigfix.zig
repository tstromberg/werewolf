//! zigfix does what `make fix` does to Zig beyond zig fmt: it rewrites
//! deprecated std calls and breaks lines longer than 100 bytes. With --check
//! it changes nothing and fails where it would. See README.md.

const std = @import("std");
const Io = std.Io;
const Ast = std.zig.Ast;
const Allocator = std.mem.Allocator;

/// deprecated maps each deprecated std call werewolf has used to the
/// replacement its doc comment names. A method is called on the first argument.
const deprecated = [_]struct { []const u8, Replacement }{
    .{ "std.fmt.allocPrint", .{ .method = "print" } },
    .{ "std.fmt.allocPrintSentinel", .{ .method = "printSentinel" } },
    .{ "std.fmt.bufPrint", .{ .function = "std.mem.print" } },
    .{ "std.fmt.bufPrintSentinel", .{ .function = "std.mem.printSentinel" } },
    .{ "std.mem.indexOfScalar", .{ .function = "std.mem.findScalar" } },
    .{ "std.mem.indexOfScalarPos", .{ .function = "std.mem.findScalarPos" } },
    .{ "std.mem.lastIndexOfScalar", .{ .function = "std.mem.findScalarLast" } },
};

const Replacement = union(enum) { function: []const u8, method: []const u8 };

/// Edit replaces source[start..end] with text.
const Edit = struct { start: usize, end: usize, text: []const u8 };

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    var max: usize = 100;
    var check = false;
    var i: usize = 1;
    while (i < args.len and std.mem.startsWith(u8, args[i], "--")) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--check")) {
            check = true;
        } else if (std.mem.eql(u8, args[i], "--max") and i + 1 < args.len) {
            i += 1;
            max = try std.fmt.parseUnsigned(usize, args[i], 10);
        } else break;
    }
    if (i == args.len) {
        std.debug.print("usage: zigfix [--check] [--max N] FILE...\n", .{});
        std.process.exit(2);
    }
    var failed = false;
    for (args[i..]) |path| {
        const ok = fixFile(gpa, init.io, path, max, check) catch |err| e: {
            std.debug.print("{s}: {s}\n", .{ path, @errorName(err) });
            break :e false;
        };
        if (!ok) failed = true;
    }
    if (failed) std.process.exit(1);
}

/// fixFile fixes the file at path, or with check reports what fixing would
/// change. It returns false if the file was not clean or has a long line left.
fn fixFile(gpa: Allocator, io: Io, path: []const u8, max: usize, check: bool) !bool {
    const dir = Io.Dir.cwd();
    const original = try dir.readFileAllocOptions(io, path, gpa, .limited(16 << 20), .of(u8), 0);
    var source: [:0]const u8 = original;
    var pass: usize = 0;
    while (pass < 20) : (pass += 1) source = try fixOnce(gpa, source, max) orelse break;
    source = try render(gpa, source);
    const changed = !std.mem.eql(u8, source, original);
    var ok = true;
    if (check and changed) {
        std.debug.print("{s}: not as `make fix` leaves it\n", .{path});
        ok = false;
    }
    for (try longLines(gpa, source, max)) |l| {
        if (commonSense(source, l, max)) continue;
        std.debug.print("{s}:{d}: {d} bytes\n", .{ path, l.line, l.len });
        ok = false;
    }
    if (!check and changed) try dir.writeFile(io, .{ .sub_path = path, .data = source });
    return ok;
}

/// commonSense reports whether a long line may stand, as the style guide's
/// "use common sense" allows: a multiline string line is data, and a
/// comment that overflows by one unbreakable word, such as a URL, cannot wrap.
fn commonSense(source: []const u8, l: Long, max: usize) bool {
    const text = source[l.start .. l.start + l.len];
    const trimmed = std.mem.trimStart(u8, text, " ");
    if (std.mem.startsWith(u8, trimmed, "\\\\")) return true;
    return std.mem.startsWith(u8, trimmed, "//") and
        std.mem.findScalar(u8, text[max..], ' ') == null;
}

/// render returns source as zig fmt would format it.
fn render(gpa: Allocator, source: [:0]const u8) ![:0]const u8 {
    var tree = try Ast.parse(gpa, source, .{});
    if (tree.errors.len > 0) return error.ParseFailed;
    return gpa.dupeSentinel(u8, try tree.renderAlloc(gpa), 0);
}

/// fixOnce rewrites deprecated calls, gives each long line one break, and
/// renders the result. It returns null when nothing changed.
fn fixOnce(gpa: Allocator, source: [:0]const u8, max: usize) !?[:0]const u8 {
    var tree = try Ast.parse(gpa, source, .{});
    if (tree.errors.len > 0) return error.ParseFailed;
    var edits: std.ArrayList(Edit) = .empty;
    try deprecations(gpa, &tree, &edits);
    for (try longLines(gpa, source, max)) |l| {
        if (try breakLine(gpa, &tree, l, max)) |es| try edits.appendSlice(gpa, es);
    }
    if (edits.items.len == 0) return null;
    const applied = try apply(gpa, source, edits.items) orelse return null;
    const rendered = try render(gpa, applied);
    if (std.mem.eql(u8, rendered, source)) return null;
    return rendered;
}

/// apply applies edits from the end back. An edit that overlaps one already
/// applied waits for the next pass. It returns null if none applied.
fn apply(gpa: Allocator, source: []const u8, edits: []Edit) !?[:0]const u8 {
    std.mem.sort(Edit, edits, {}, struct {
        fn lt(_: void, a: Edit, b: Edit) bool {
            return a.start > b.start;
        }
    }.lt);
    // Collect pieces back to front: the text after each edit, then the edit.
    var pieces: std.ArrayList([]const u8) = .empty;
    var end = source.len;
    for (edits) |e| {
        if (e.end > end) continue;
        try pieces.append(gpa, source[e.end..end]);
        try pieces.append(gpa, e.text);
        end = e.start;
    }
    if (pieces.items.len == 0) return null;
    try pieces.append(gpa, source[0..end]);
    var out: std.ArrayList(u8) = .empty;
    var k = pieces.items.len;
    while (k > 0) {
        k -= 1;
        try out.appendSlice(gpa, pieces.items[k]);
    }
    return try out.toOwnedSliceSentinel(gpa, 0);
}

fn deprecations(gpa: Allocator, tree: *const Ast, edits: *std.ArrayList(Edit)) !void {
    const starts = tree.tokens.items(.start);
    for (0..tree.nodes.len) |n| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(n));
        var buf: [1]Ast.Node.Index = undefined;
        const call = tree.fullCall(&buf, node) orelse continue;
        const callee = tree.getNodeSource(call.ast.fn_expr);
        const replacement = for (deprecated) |d| {
            if (std.mem.eql(u8, callee, d[0])) break d[1];
        } else continue;
        const callee_start = starts[tree.firstToken(call.ast.fn_expr)];
        switch (replacement) {
            .function => |f| try edits.append(gpa, .{
                .start = callee_start,
                .end = callee_start + callee.len,
                .text = f,
            }),
            .method => |m| {
                if (call.ast.params.len < 2) continue;
                // callee(first, rest...) -> first.m(rest...)
                const first = tree.getNodeSource(call.ast.params[0]);
                const rest_start = starts[tree.firstToken(call.ast.params[1])];
                const text = try gpa.print("{s}.{s}(", .{ first, m });
                try edits.append(gpa, .{ .start = callee_start, .end = rest_start, .text = text });
            },
        }
    }
}

const Long = struct { line: usize, start: usize, len: usize };

/// longLines returns every line longer than max bytes, numbered from 1.
fn longLines(gpa: Allocator, source: []const u8, max: usize) ![]const Long {
    var out: std.ArrayList(Long) = .empty;
    var start: usize = 0;
    var line: usize = 1;
    while (start < source.len) : (line += 1) {
        const end = std.mem.findScalarPos(u8, source, start, '\n') orelse source.len;
        if (end - start > max) try out.append(
            gpa,
            .{ .line = line, .start = start, .len = end - start },
        );
        start = end + 1;
    }
    return out.items;
}

/// breakLine returns the edits that break l, or null if it knows none. It
/// breaks the construct that starts first, the outermost, as a person would.
fn breakLine(gpa: Allocator, tree: *const Ast, l: Long, max: usize) !?[]const Edit {
    const source = tree.source;
    const text = source[l.start .. l.start + l.len];
    const trimmed = std.mem.trimStart(u8, text, " ");
    if (std.mem.startsWith(u8, trimmed, "\\\\")) return null;
    if (std.mem.startsWith(u8, trimmed, "//"))
        return single(gpa, try wrapComment(gpa, l, text, max));
    var best: ?Choice = null;
    for ([_]?Choice{
        try operatorBreak(gpa, tree, l, max),
        try listBreak(gpa, tree, l),
        try ifBreak(gpa, tree, l),
        try caseBreak(gpa, tree, l),
    }) |c| {
        const choice = c orelse continue;
        if (best == null or choice.start < best.?.start) best = choice;
    }
    if (best) |c| return try gpa.dupe(Edit, c.edits);
    if (try tableBreak(gpa, tree, l, max)) |e| return single(gpa, e);
    return single(gpa, try stringBreak(gpa, tree, l, max));
}

/// Choice is a way to break a line: where the broken construct starts, and
/// the edits.
const Choice = struct { start: usize, edits: []const Edit };

fn single(gpa: Allocator, e: ?Edit) !?[]const Edit {
    const edit = e orelse return null;
    return try gpa.dupe(Edit, &.{edit});
}

/// ifBreak puts each branch of the first if-else expression on the line on
/// its own line. It skips if statements, whose branches are blocks.
fn ifBreak(gpa: Allocator, tree: *const Ast, l: Long) !?Choice {
    const starts = tree.tokens.items(.start);
    const line_end = l.start + l.len;
    for (0..tree.nodes.len) |n| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(n));
        const first = tree.fullIf(node) orelse continue;
        const at = starts[first.ast.if_token];
        if (at < l.start or at >= line_end or first.ast.else_expr == .none) continue;
        if (isBlock(tree, first.ast.then_expr)) continue;
        // Skip an else-if: its chain starts earlier.
        if (first.ast.if_token > 0 and
            tree.tokenTag(first.ast.if_token - 1) == .keyword_else) continue;
        var edits: std.ArrayList(Edit) = .empty;
        var cur = first;
        while (true) {
            const then_at = starts[tree.firstToken(cur.ast.then_expr)];
            if (then_at < line_end) try edits.append(
                gpa,
                .{ .start = then_at, .end = then_at, .text = "\n" },
            );
            const e = cur.ast.else_expr.unwrap() orelse break;
            if (tree.fullIf(e)) |next| {
                cur = next;
                continue;
            }
            const else_at = starts[tree.firstToken(e)];
            if (else_at < line_end) try edits.append(
                gpa,
                .{ .start = else_at, .end = else_at, .text = "\n" },
            );
            break;
        }
        if (edits.items.len == 0) continue;
        return .{ .start = at, .edits = edits.items };
    }
    return null;
}

/// caseBreak adds a trailing comma to a switch prong's values, so zig fmt
/// puts one value on each line.
fn caseBreak(gpa: Allocator, tree: *const Ast, l: Long) !?Choice {
    const starts = tree.tokens.items(.start);
    const line_end = l.start + l.len;
    for (0..tree.nodes.len) |n| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(n));
        const case = tree.fullSwitchCase(node) orelse continue;
        if (case.ast.values.len < 2) continue;
        const at = starts[tree.firstToken(case.ast.values[0])];
        const arrow = starts[case.ast.arrow_token];
        if (at < l.start or arrow >= line_end) continue;
        if (tree.tokenTag(case.ast.arrow_token - 1) == .comma) continue;
        const last = tree.lastToken(case.ast.values[case.ast.values.len - 1]);
        const after = starts[last] + tree.tokenSlice(last).len;
        return .{
            .start = at,
            .edits = try gpa.dupe(Edit, &.{.{ .start = after, .end = after, .text = "," }}),
        };
    }
    return null;
}

fn isBlock(tree: *const Ast, n: Ast.Node.Index) bool {
    return switch (tree.nodeTag(n)) {
        .block, .block_semicolon, .block_two, .block_two_semicolon => true,
        else => false,
    };
}

/// wrapComment wraps a comment at its last space within max. The rest goes on
/// a new line with the same indent and marker.
fn wrapComment(gpa: Allocator, l: Long, text: []const u8, max: usize) !?Edit {
    const indent = text.len - std.mem.trimStart(u8, text, " ").len;
    const rest = text[indent..];
    const marker_len: usize = if (std.mem.startsWith(u8, rest, "///") or
        std.mem.startsWith(u8, rest, "//!"))
        3
    else
        2;
    const body_start = indent + marker_len + @as(
        usize,
        if (text.len > indent + marker_len and text[indent + marker_len] == ' ') 1 else 0,
    );
    var cut = max;
    while (cut > body_start and text[cut] != ' ') cut -= 1;
    if (cut <= body_start) return null;
    const next = try gpa.print(
        "\n{s}{s} ",
        .{ text[0..indent], rest[0..marker_len] },
    );
    return .{ .start = l.start + cut, .end = l.start + cut + 1, .text = next };
}

/// listBreak adds a trailing comma to the outermost list that opens and
/// closes on the line, preferring one with several items. zig fmt then puts
/// one item on each line.
fn listBreak(gpa: Allocator, tree: *const Ast, l: Long) !?Choice {
    const starts = tree.tokens.items(.start);
    const line_end = l.start + l.len;
    const List = struct {
        node: Ast.Node.Index,
        open: Ast.TokenIndex,
        close: Ast.TokenIndex,
        many: bool,
    };
    var best: ?List = null;
    for (0..tree.nodes.len) |n| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(n));
        const open = opener(tree, node) orelse continue;
        if (starts[open] < l.start or starts[open] >= line_end) continue;
        const close = matching(tree, open) orelse continue;
        if (starts[close] >= line_end) continue;
        // Skip an empty list, or one that already ends in a comma.
        if (close == open + 1 or tree.tokenTag(close - 1) == .comma) continue;
        const this: List = .{
            .node = node,
            .open = open,
            .close = close,
            .many = hasComma(tree, open, close),
        };
        const b = best orelse {
            best = this;
            continue;
        };
        if ((this.many and !b.many) or (this.many == b.many and open < b.open)) best = this;
    }
    const b = best orelse return null;
    const at = starts[b.close];
    const edits = try gpa.dupe(Edit, &.{.{ .start = at, .end = at, .text = "," }});
    return .{ .start = @max(l.start, starts[tree.firstToken(b.node)]), .edits = edits };
}

/// opener returns the token that opens n's list, if n is a node whose list
/// zig fmt splits one item per line after a trailing comma.
fn opener(tree: *const Ast, n: Ast.Node.Index) ?Ast.TokenIndex {
    var one: [1]Ast.Node.Index = undefined;
    var two: [2]Ast.Node.Index = undefined;
    if (tree.fullCall(&one, n)) |c| return c.ast.lparen;
    if (tree.fullFnProto(&one, n)) |p| return p.lparen;
    if (tree.fullStructInit(&two, n)) |s| return s.ast.lbrace;
    if (tree.fullArrayInit(&two, n)) |a| return a.ast.lbrace;
    // A type's fields. The root container has no braces.
    if (tree.nodeTag(n) != .root) if (tree.fullContainerDecl(&two, n)) |c| {
        var t = c.ast.main_token;
        while (t < tree.tokens.len and tree.tokenTag(t) != .l_brace) t += 1;
        if (t < tree.tokens.len) return t;
    };
    return switch (tree.nodeTag(n)) {
        .builtin_call_two, .builtin_call => tree.nodeMainToken(n) + 1,
        else => null,
    };
}

/// tableBreak reflows the innermost array the line is a row of into as many
/// columns as fit within max. zig fmt takes the column count from the first row.
fn tableBreak(gpa: Allocator, tree: *const Ast, l: Long, max: usize) !?Edit {
    const starts = tree.tokens.items(.start);
    const line_end = l.start + l.len;
    var best: ?struct {
        open: Ast.TokenIndex,
        close: Ast.TokenIndex,
        items: []const Ast.Node.Index,
    } = null;
    for (0..tree.nodes.len) |n| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(n));
        var two: [2]Ast.Node.Index = undefined;
        const a = tree.fullArrayInit(&two, node) orelse continue;
        const close = matching(tree, a.ast.lbrace) orelse continue;
        if (starts[a.ast.lbrace] >= l.start or starts[close] < line_end) continue;
        if (best != null and a.ast.lbrace < best.?.open) continue;
        // Copy: a short list's elements live in two, which the next node reuses.
        best = .{
            .open = a.ast.lbrace,
            .close = close,
            .items = try gpa.dupe(Ast.Node.Index, a.ast.elements),
        };
    }
    const b = best orelse return null;
    if (b.items.len < 2) return null;
    var widest: usize = 0;
    for (b.items) |item| {
        const text = tree.getNodeSource(item);
        if (std.mem.findScalar(u8, text, '\n') != null) return null;
        widest = @max(widest, text.len);
    }
    const indent = l.len - std.mem.trimStart(u8, tree.source[l.start..line_end], " ").len;
    // A column holds the widest item, its comma and a space.
    const columns = @max(1, (max - indent + 1) / (widest + 2));
    var out: std.ArrayList(u8) = .empty;
    try out.append(gpa, '\n');
    for (b.items, 1..) |item, k| {
        try out.appendSlice(gpa, tree.getNodeSource(item));
        try out.appendSlice(gpa, if (k % columns == 0 or k == b.items.len) ",\n" else ", ");
    }
    return .{ .start = starts[b.open] + 1, .end = starts[b.close], .text = out.items };
}

/// hasComma reports whether the list between open and close has a comma at
/// its own depth.
fn hasComma(tree: *const Ast, open: Ast.TokenIndex, close: Ast.TokenIndex) bool {
    var depth: usize = 0;
    var t = open + 1;
    while (t < close) : (t += 1) {
        switch (tree.tokenTag(t)) {
            .l_paren, .l_brace, .l_bracket => depth += 1,
            .r_paren, .r_brace, .r_bracket => depth -= 1,
            .comma => if (depth == 0) return true,
            else => {},
        }
    }
    return false;
}

/// matching returns the token that closes the bracket opened at open.
fn matching(tree: *const Ast, open: Ast.TokenIndex) ?Ast.TokenIndex {
    var depth: usize = 0;
    var t = open;
    while (t < tree.tokens.len) : (t += 1) {
        switch (tree.tokenTag(t)) {
            .l_paren, .l_brace, .l_bracket => depth += 1,
            .r_paren, .r_brace, .r_bracket => {
                depth -= 1;
                if (depth == 0) return t;
            },
            else => {},
        }
    }
    return null;
}

/// operatorBreak breaks the line after its last `and`, `or`, `|` or `++`
/// that ends within max. It reads the tree, so a capture's `|x|` is not an or.
fn operatorBreak(gpa: Allocator, tree: *const Ast, l: Long, max: usize) !?Choice {
    const starts = tree.tokens.items(.start);
    const line_end = l.start + l.len;
    var best: ?struct { end: usize, start: usize } = null;
    for (0..tree.nodes.len) |n| {
        const node: Ast.Node.Index = @fromBackingInt(@intCast(n));
        switch (tree.nodeTag(node)) {
            .bool_and, .bool_or, .array_cat, .bit_or => {},
            else => continue,
        }
        const op = tree.nodeMainToken(node);
        const end = starts[op] + tree.tokenSlice(op).len;
        if (starts[op] < l.start or end - l.start > max or end >= line_end) continue;
        if (best != null and end <= best.?.end) continue;
        best = .{ .end = end, .start = @max(l.start, starts[tree.firstToken(node)]) };
    }
    const b = best orelse return null;
    const edits = try gpa.dupe(Edit, &.{.{ .start = b.end, .end = b.end, .text = "\n" }});
    return .{ .start = b.start, .edits = edits };
}

/// stringBreak splits the first string literal of 12 or more bytes that
/// starts within max into two literals joined by `++`.
fn stringBreak(gpa: Allocator, tree: *const Ast, l: Long, max: usize) !?Edit {
    const starts = tree.tokens.items(.start);
    for (0..tree.tokens.len) |i| {
        const t: Ast.TokenIndex = @intCast(i);
        const at = starts[t];
        if (at < l.start) continue;
        if (at >= l.start + l.len) break;
        if (tree.tokenTag(t) != .string_literal) continue;
        const lit = tree.tokenSlice(t);
        // Skip a literal that starts past max, or is too short to split.
        if (at - l.start >= max or lit.len < 12) continue;
        // Parenthesize if a neighbour binds tighter than ++, so "a".*
        // becomes ("a" ++ "b").*.
        const bare = loose(tree.tokenTag(t - 1)) and loose(tree.tokenTag(t + 1));
        const room = max -| (at - l.start) -| @intFromBool(!bare);
        const cut = splitPoint(lit, room) orelse continue;
        const open = if (bare) "" else "(";
        const close = if (bare) "" else ")";
        const text = try gpa.print(
            "{s}{s}\" ++\n\"{s}{s}",
            .{ open, lit[0..cut], lit[cut..], close },
        );
        return .{ .start = at, .end = at + lit.len, .text = text };
    }
    return null;
}

/// loose reports whether tag, next to a string literal, binds no tighter
/// than ++: true for separators, parentheses, braces, assignment, return,
/// else and ++ itself; false for &, .*, [ and . among others.
fn loose(tag: std.zig.Token.Tag) bool {
    return switch (tag) {
        .comma,
        .semicolon,
        .l_paren,
        .r_paren,
        .l_brace,
        .r_brace,
        .equal,
        .equal_angle_bracket_right,
        .plus_plus,
        .colon,
        .keyword_return,
        .keyword_else,
        => true,
        else => false,
    };
}

/// splitPoint returns where to split lit, quotes included, so the first part
/// plus `" ++` fits in room bytes. It prefers a space within 24 bytes of the
/// last fit. It never splits an escape or a UTF-8 character, so the string
/// is unchanged. It returns null if nothing fits.
fn splitPoint(lit: []const u8, room: usize) ?usize {
    var space: ?usize = null;
    var any: ?usize = null;
    var i: usize = 1;
    while (i < lit.len - 1) {
        // Step one character: an escape, a UTF-8 sequence, or one byte.
        var next = i + 1;
        if (lit[i] == '\\') {
            next = i + 2;
            if (lit[i + 1] == 'x') next = i + 4;
            if (lit[i + 1] == 'u') next = (std.mem.findScalarPos(
                u8,
                lit,
                i,
                '}',
            ) orelse lit.len - 2) + 1;
        } else {
            while (next < lit.len - 1 and lit[next] & 0xc0 == 0x80) next += 1;
        }
        if (next + 4 > room or next >= lit.len - 1) break;
        any = next;
        if (lit[i] == ' ') space = next;
        i = next;
    }
    const a = any orelse return null;
    if (space) |sp| if (a - sp < 24) return sp;
    return a;
}

const testing = std.testing;

fn fixed(source: [:0]const u8, max: usize) ![]const u8 {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var s = source;
    while (try fixOnce(arena.allocator(), s, max)) |next| s = next;
    return testing.allocator.dupe(u8, try render(arena.allocator(), s));
}

test "deprecated calls" {
    const out = try fixed(
        \\const std = @import("std");
        \\fn f(gpa: std.mem.Allocator, b: []u8) !void {
        \\    _ = try std.fmt.allocPrint(gpa, "{d}", .{1});
        \\    _ = try std.fmt.bufPrint(b, "x", .{});
        \\    _ = std.mem.indexOfScalar(u8, b, 'x');
        \\}
        \\
    , 100);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(
        \\const std = @import("std");
        \\fn f(gpa: std.mem.Allocator, b: []u8) !void {
        \\    _ = try gpa.print("{d}", .{1});
        \\    _ = try std.mem.print(b, "x", .{});
        \\    _ = std.mem.findScalar(u8, b, 'x');
        \\}
        \\
    , out);
}

test "a split string keeps what binds to it" {
    const out = try fixed(
        \\var buf = "one two three four five six seven eight nine ten".*;
        \\const p = &"one two three four five six seven eight nine ten";
        \\const s = f("one two three four five six seven eight nine ten");
        \\
    , 40);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(
        \\var buf = ("one two three four five " ++
        \\    "six seven eight nine ten").*;
        \\const p = &("one two three four " ++
        \\    "five six seven eight nine ten");
        \\const s = f(
        \\    "one two three four five six " ++
        \\        "seven eight nine ten",
        \\);
        \\
    , out);
}

test "tables and types" {
    const out = try fixed(
        \\const T = struct { origin: []const u8, from: []const u8, to: []const u8 };
        \\const names = .{
        \\    "read", "readv", "pread64", "write", "writev", "pwrite64", "openat",
        \\    "open", "close",
        \\};
        \\
    , 40);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(
        \\const T = struct {
        \\    origin: []const u8,
        \\    from: []const u8,
        \\    to: []const u8,
        \\};
        \\const names = .{
        \\    "read",   "readv",  "pread64",
        \\    "write",  "writev", "pwrite64",
        \\    "openat", "open",   "close",
        \\};
        \\
    , out);
}

test "long lines" {
    const out = try fixed(
        \\fn f(alpha: u32, beta: u32, gamma: u32) bool {
        \\    // one two three four five six seven eight nine ten eleven twelve
        \\    return g(alpha, beta, gamma) and alpha > beta and beta > gamma;
        \\}
        \\const s = "one two three four five six seven eight nine";
        \\
    , 40);
    defer testing.allocator.free(out);
    var lines = std.mem.splitScalar(u8, out, '\n');
    while (lines.next()) |line| try testing.expect(line.len <= 40);
}
