//! update-unwound-age-data normalizes reviewed downloads of the Public
//! Suffix List and IANA's RDAP DNS bootstrap into cmd/unwound/data, under
//! the current directory, for the unwound image to embed. It makes no
//! network requests: fetch the two official URLs first.
//!
//!     update-unwound-age-data --psl FILE --rdap FILE
//!
//! A PSL rule becomes lowercase ASCII, each Unicode label an RFC 3492
//! A-label. Unicode mapping tables (UTS #46) are not carried here, so a
//! label must already be in its mapped, lowercase form: what that cannot be
//! proved for cheaply is refused, not guessed.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

const psl_url = "https://publicsuffix.org/list/public_suffix_list.dat";
const rdap_url = "https://data.iana.org/rdap/dns.json";
const output = "cmd/unwound/data";
const normalizer = "tools/update-unwound-age-data.zig: RFC 3492 Punycode, STD3";
const max_input = 16 << 20;
const markers = [_][]const u8{
    "// ===BEGIN ICANN DOMAINS===",
    "// ===END ICANN DOMAINS===",
    "// ===BEGIN PRIVATE DOMAINS===",
    "// ===END PRIVATE DOMAINS===",
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    var why: []const u8 = "";
    update(io, gpa, args[1..], &why) catch |err| {
        std.debug.print("update-unwound-age-data: {s}{s}\n", .{ @errorName(err), why });
        std.process.exit(1);
    };
}

fn update(io: Io, gpa: Allocator, args: []const []const u8, why: *[]const u8) !void {
    var psl_path: ?[]const u8 = null;
    var rdap_path: ?[]const u8 = null;
    var i: usize = 0;
    while (i + 1 < args.len) : (i += 2) {
        if (std.mem.eql(u8, args[i], "--psl")) {
            psl_path = args[i + 1];
        } else if (std.mem.eql(u8, args[i], "--rdap")) {
            rdap_path = args[i + 1];
        } else break;
    }
    if (i != args.len or psl_path == null or rdap_path == null) {
        why.* = ": usage: update-unwound-age-data --psl FILE --rdap FILE";
        return error.Usage;
    }
    const cwd = Io.Dir.cwd();
    const psl_raw = try cwd.readFileAlloc(io, psl_path.?, gpa, .limited(max_input));
    const rdap_raw = try cwd.readFileAlloc(io, rdap_path.?, gpa, .limited(max_input));
    const psl = try pslData(gpa, psl_raw, why);
    const rdap = try rdapData(gpa, rdap_raw);

    var meta: Io.Writer.Allocating = .init(gpa);
    const w = &meta.writer;
    try w.writeAll("{\n  \"psl\": {\n    \"source\": ");
    try string(w, psl_url);
    try w.print(",\n    \"sha256\": \"{s}\",\n    \"version\": ", .{&sha256(psl_raw)});
    try string(w, psl.version);
    try w.writeAll(",\n    \"commit\": ");
    try string(w, psl.commit);
    try w.print(",\n    \"rules\": {d}\n  }},\n  \"rdap\": {{\n    \"source\": ", .{psl.rules});
    try string(w, rdap_url);
    try w.print(",\n    \"sha256\": \"{s}\",\n    \"publication\": ", .{&sha256(rdap_raw)});
    try string(w, rdap.publication);
    try w.print(",\n    \"services\": {d}\n  }},\n  \"normalizer\": ", .{rdap.services});
    try string(w, normalizer);
    try w.writeAll("\n}\n");

    try cwd.createDirPath(io, output);
    var dir = try cwd.openDir(io, output, .{});
    defer dir.close(io);
    try dir.writeFile(io, .{ .sub_path = "public_suffix_list.ascii.dat", .data = psl.text });
    try dir.writeFile(io, .{ .sub_path = "rdap-dns.json", .data = rdap.text });
    try dir.writeFile(io, .{ .sub_path = "sources.json", .data = meta.written() });
}

fn sha256(data: []const u8) [Sha256.digest_length * 2]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

const Psl = struct { text: []const u8, version: []const u8, commit: []const u8, rules: usize };

fn pslData(gpa: Allocator, raw: []const u8, why: *[]const u8) !Psl {
    if (!std.unicode.utf8ValidateSlice(raw)) return error.PslNotUtf8;
    // Python's splitlines would end lines at these too; refuse rather than
    // decide which reading a reviewer meant.
    const view = std.unicode.Utf8View.initUnchecked(raw);
    var cps = view.iterator();
    while (cps.nextCodepoint()) |c| switch (c) {
        0x0b, 0x0c, 0x1c...0x1e, 0x85, 0x2028, 0x2029 => return error.PslLineSeparator,
        else => {},
    };
    var lines: std.ArrayList([]const u8) = .empty;
    var split = std.mem.splitScalar(u8, raw, '\n');
    while (split.next()) |line| {
        const text = if (std.mem.endsWith(u8, line, "\r")) line[0 .. line.len - 1] else line;
        if (std.mem.findScalar(u8, text, '\r') != null) return error.PslLineSeparator;
        try lines.append(gpa, text);
    }

    var version: ?[]const u8 = null;
    var commit: ?[]const u8 = null;
    var seen: usize = 0;
    for (lines.items) |line| {
        if (version == null and std.mem.startsWith(u8, line, "// VERSION: ")) version = line[12..];
        if (commit == null and std.mem.startsWith(u8, line, "// COMMIT: ")) commit = line[11..];
        if (!isMarker(line)) continue;
        if (seen == markers.len or !std.mem.eql(u8, line, markers[seen]))
            return error.PslMarkersOutOfOrder;
        seen += 1;
    }
    if (version == null or version.?.len == 0 or commit == null or commit.?.len == 0)
        return error.PslVersionOrCommitMissing;
    if (seen != markers.len) return error.PslMarkersOutOfOrder;

    var out: Io.Writer.Allocating = .init(gpa);
    const w = &out.writer;
    try w.print(
        \\// This Source Code Form is subject to the terms of the Mozilla Public
        \\// License, v. 2.0. If a copy of the MPL was not distributed with this
        \\// file, You can obtain one at https://mozilla.org/MPL/2.0/.
        \\// Source: {s}
        \\// VERSION: {s}
        \\// COMMIT: {s}
        \\
    , .{ psl_url, version.?, commit.? });
    var section = false;
    var rules: usize = 0;
    for (lines.items) |line| {
        if (isMarker(line)) {
            section = std.mem.startsWith(u8, line, "// ===BEGIN");
            try w.print("{s}\n", .{line});
            continue;
        }
        if (line.len == 0 or std.mem.startsWith(u8, line, "//")) continue;
        why.* = try gpa.print(": {s}", .{line});
        if (!section or spaced(line)) return error.UnexpectedPslRuleOrWhitespace;
        const prefix: []const u8 = if (std.mem.startsWith(u8, line, "*."))
            "*."
        else if (std.mem.startsWith(u8, line, "!")) "!" else "";
        const rule = line[prefix.len..];
        if (rule.len == 0 or std.mem.findAny(u8, rule, "*!") != null) return error.MalformedPslRule;
        try w.print("{s}{s}\n", .{ prefix, try domainToAscii(gpa, rule) });
        rules += 1;
    }
    why.* = "";
    return .{ .text = out.written(), .version = version.?, .commit = commit.?, .rules = rules };
}

fn isMarker(line: []const u8) bool {
    for (markers) |m| if (std.mem.eql(u8, line, m)) return true;
    return false;
}

/// spaced reports whether line starts or ends with what Python's str.strip
/// would remove: ASCII or Unicode white space.
fn spaced(line: []const u8) bool {
    const view = std.unicode.Utf8View.initUnchecked(line);
    var it = view.iterator();
    const first = it.nextCodepoint() orelse return false;
    var last = first;
    while (it.nextCodepoint()) |c| last = c;
    return isSpace(first) or isSpace(last);
}

fn isSpace(c: u21) bool {
    return switch (c) {
        0x09...0x0d, 0x1c...0x20, 0x85, 0xa0, 0x1680, 0x2000...0x200a => true,
        0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => true,
        else => false,
    };
}

/// domainToAscii gives a rule's name as lowercase A-labels, refusing what
/// IDNA 2008 with STD3 rules would refuse, or what cannot be proved valid
/// without Unicode's tables.
fn domainToAscii(gpa: Allocator, rule: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var labels = std.mem.splitScalar(u8, rule, '.');
    while (labels.next()) |label| {
        if (out.items.len > 0) try out.append(gpa, '.');
        const start = out.items.len;
        try labelToAscii(gpa, &out, label);
        if (out.items.len - start > 63) return error.PslRuleExceedsDnsLimits;
    }
    if (out.items.len > 253) return error.PslRuleExceedsDnsLimits;
    return out.items;
}

fn labelToAscii(gpa: Allocator, out: *std.ArrayList(u8), label: []const u8) !void {
    if (label.len == 0) return error.EmptyLabel;
    var cps: std.ArrayList(u21) = .empty;
    const view = try std.unicode.Utf8View.init(label);
    var it = view.iterator();
    var ascii = true;
    while (it.nextCodepoint()) |c| {
        const lower = if (c < 0x80) std.ascii.toLower(@intCast(c)) else c;
        ascii = ascii and lower < 0x80;
        try cps.append(gpa, lower);
    }
    if (!ascii) {
        try check(cps.items);
        try out.appendSlice(gpa, "xn--");
        try encode(gpa, out, cps.items);
        return;
    }
    const text = try gpa.alloc(u8, cps.items.len);
    for (text, cps.items) |*t, c| t.* = @intCast(c);
    if (std.mem.startsWith(u8, text, "xn--")) {
        // An A-label in the source must be the canonical one for a valid
        // U-label: decode it, check that, and encode it again.
        if (text.len == 4 or text[text.len - 1] == '-') return error.MalformedALabel;
        const decoded = try decode(gpa, text[4..]);
        try check(decoded);
        var again: std.ArrayList(u8) = .empty;
        try encode(gpa, &again, decoded);
        if (!std.mem.eql(u8, again.items, text[4..])) return error.NonCanonicalALabel;
    } else try check(cps.items);
    try out.appendSlice(gpa, text);
}

/// check refuses a U-label IDNA 2008 forbids with STD3 rules: one that is
/// not lowercase LDH in ASCII, puts hyphens where they may not go, or holds
/// a code point that UTS #46 maps or that is never valid. Unicode letters
/// outside the blocks refused here pass unproved: NFC, case mapping above
/// Latin-1, contextual rules and the Bidi rule need tables this lacks.
fn check(label: []const u21) !void {
    if (label.len == 0) return error.EmptyLabel;
    if (label[0] == '-' or label[label.len - 1] == '-') return error.HyphenAtLabelEdge;
    if (label.len >= 4 and label[2] == '-' and
        label[3] == '-') return error.HyphensInThirdAndFourth;
    if (combining(label[0])) return error.LeadingCombiningMark;
    for (label) |c| if (!plausible(c)) return error.UnprovableCodePoint;
}

fn combining(c: u21) bool {
    return switch (c) {
        0x0300...0x036f, 0x0483...0x0489, 0x1ab0...0x1aff, 0x1dc0...0x1dff => true,
        0x20d0...0x20ff, 0xfe20...0xfe2f => true,
        else => false,
    };
}

fn plausible(c: u21) bool {
    if (c < 0x80) return std.ascii.isLower(@intCast(c)) or std.ascii.isDigit(@intCast(c)) or
        c == '-';
    return switch (c) {
        // C1 controls, Latin-1 symbols, capitals, × and ÷.
        0x80...0xdf, 0xf7 => c == 0xdf,
        // Punctuation, symbols, ideographic space and marks, radicals,
        // enclosed and compatibility forms, presentation forms, specials.
        0x2000...0x2bff, 0x2e00...0x2fff, 0x3000...0x3004, 0x3200...0x33ff => false,
        0xe000...0xffff => false,
        // Mathematical letters, symbols and emoji, compatibility
        // ideographs, tags, private use.
        0x1d400...0x1d7ff, 0x1f000...0x1fbff, 0x2f800...0x2fa1f, 0xe0000...0x10ffff => false,
        else => c & 0xfffe != 0xfffe,
    };
}

// RFC 3492's parameters for Punycode.
const base = 36;
const tmin = 1;
const tmax = 26;
const skew = 38;
const damp = 700;
const initial_bias = 72;
const initial_n = 0x80;

fn adapt(delta_in: u32, points: u32, first: bool) u32 {
    var delta = if (first) delta_in / damp else delta_in / 2;
    delta += delta / points;
    var k: u32 = 0;
    while (delta > ((base - tmin) * tmax) / 2) : (k += base) delta /= base - tmin;
    return k + (base - tmin + 1) * delta / (delta + skew);
}

fn digit(d: u32) u8 {
    return @intCast(if (d < 26) 'a' + d else '0' + d - 26);
}

fn threshold(k: u32, bias: u32) u32 {
    return if (k <= bias) tmin else if (k >= bias + tmax) tmax else k - bias;
}

/// encode appends input's Punycode, RFC 3492 section 6.3.
fn encode(gpa: Allocator, out: *std.ArrayList(u8), input: []const u21) !void {
    var basic: u32 = 0;
    for (input) |c| {
        if (c >= 0x80) continue;
        try out.append(gpa, @intCast(c));
        basic += 1;
    }
    if (basic > 0) try out.append(gpa, '-');
    var n: u32 = initial_n;
    var delta: u32 = 0;
    var bias: u32 = initial_bias;
    var h = basic;
    while (h < input.len) {
        var m: u32 = std.math.maxInt(u32);
        for (input) |c| {
            if (c >= n and c < m) m = c;
        }
        delta = try add(delta, try std.math.mul(u32, m - n, h + 1));
        n = m;
        for (input) |c| {
            if (c < n) delta = try add(delta, 1);
            if (c != n) continue;
            var q = delta;
            var k: u32 = base;
            while (true) : (k += base) {
                const t = threshold(k, bias);
                if (q < t) break;
                try out.append(gpa, digit(t + (q - t) % (base - t)));
                q = (q - t) / (base - t);
            }
            try out.append(gpa, digit(q));
            bias = adapt(delta, h + 1, h == basic);
            delta = 0;
            h += 1;
        }
        delta = try add(delta, 1);
        n += 1;
    }
}

fn add(a: u32, b: u32) !u32 {
    return std.math.add(u32, a, b) catch error.PunycodeOverflow;
}

/// decode returns the code points input's Punycode encodes, RFC 3492 6.2.
fn decode(gpa: Allocator, input: []const u8) ![]const u21 {
    var out: std.ArrayList(u21) = .empty;
    var at: usize = 0;
    if (std.mem.findScalarLast(u8, input, '-')) |d| {
        for (input[0..d]) |c| {
            if (c >= 0x80) return error.BadPunycode;
            try out.append(gpa, c);
        }
        at = d + 1;
    }
    var n: u32 = initial_n;
    var i: u32 = 0;
    var bias: u32 = initial_bias;
    while (at < input.len) {
        const old = i;
        var w: u32 = 1;
        var k: u32 = base;
        while (true) : (k += base) {
            if (at == input.len) return error.BadPunycode;
            const c = std.ascii.toLower(input[at]);
            at += 1;
            const d: u32 = switch (c) {
                'a'...'z' => c - 'a',
                '0'...'9' => c - '0' + 26,
                else => return error.BadPunycode,
            };
            i = try add(i, try std.math.mul(u32, d, w));
            const t = threshold(k, bias);
            if (d < t) break;
            w = try std.math.mul(u32, w, base - t);
        }
        const points: u32 = @intCast(out.items.len + 1);
        bias = adapt(i - old, points, old == 0);
        n = try add(n, i / points);
        i %= points;
        if (n > 0x10ffff or (n >= 0xd800 and n <= 0xdfff)) return error.BadPunycode;
        try out.insert(gpa, i, @intCast(n));
        i += 1;
    }
    return out.items;
}

const Rdap = struct { text: []const u8, publication: []const u8, services: usize };

fn rdapData(gpa: Allocator, raw: []const u8) !Rdap {
    const data = std.json.parseFromSliceLeaky(std.json.Value, gpa, raw, .{}) catch
        return error.InvalidRdapJson;
    if (data != .object) return error.UnexpectedRdapBootstrapVersion;
    const version = data.object.get("version") orelse return error.UnexpectedRdapBootstrapVersion;
    const publication = data.object.get("publication") orelse
        return error.UnexpectedRdapBootstrapVersion;
    if (version != .string or !std.mem.eql(u8, version.string, "1.0") or publication != .string)
        return error.UnexpectedRdapBootstrapVersion;
    const services = data.object.get("services") orelse return error.InvalidRdapServices;
    if (services != .array or services.array.items.len == 0 or services.array.items.len > 4096)
        return error.InvalidRdapServices;
    for (services.array.items) |service| {
        if (service != .array or service.array.items.len != 2) return error.InvalidRdapService;
        for (service.array.items) |group| {
            if (group != .array) return error.InvalidRdapService;
            for (group.array.items) |item| if (item != .string) return error.InvalidRdapService;
        }
    }
    var out: Io.Writer.Allocating = .init(gpa);
    try compact(&out.writer, data);
    try out.writer.writeByte('\n');
    return .{
        .text = out.written(),
        .publication = publication.string,
        .services = services.array.items.len,
    };
}

/// compact writes value as Python's json.dumps with ensure_ascii and the
/// separators "," and ":": keys in their order, nothing but ASCII.
fn compact(w: *Io.Writer, value: std.json.Value) !void {
    switch (value) {
        .null => try w.writeAll("null"),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .integer => |n| try w.print("{d}", .{n}),
        // Python would print these its own way; the bootstrap has none.
        .float, .number_string => return error.UnexpectedRdapNumber,
        .string => |s| try string(w, s),
        .array => |a| {
            try w.writeByte('[');
            for (a.items, 0..) |item, i| {
                if (i > 0) try w.writeByte(',');
                try compact(w, item);
            }
            try w.writeByte(']');
        },
        .object => |o| {
            try w.writeByte('{');
            var it = o.iterator();
            var first = true;
            while (it.next()) |e| {
                if (!first) try w.writeByte(',');
                first = false;
                try string(w, e.key_ptr.*);
                try w.writeByte(':');
                try compact(w, e.value_ptr.*);
            }
            try w.writeByte('}');
        },
    }
}

/// string writes s as Python's json.dumps does with ensure_ascii: printable
/// ASCII as itself, the rest escaped, astral code points as surrogate pairs.
fn string(w: *Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    const view = try std.unicode.Utf8View.init(s);
    var it = view.iterator();
    while (it.nextCodepoint()) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0x08 => try w.writeAll("\\b"),
        0x0c => try w.writeAll("\\f"),
        0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try w.writeByte(@intCast(c)),
        0x10000...0x10ffff => {
            const v = c - 0x10000;
            try w.print("\\u{x:0>4}\\u{x:0>4}", .{ 0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff) });
        },
        else => try w.print("\\u{x:0>4}", .{c}),
    };
    try w.writeByte('"');
}

const testing = std.testing;

fn utf8ToCodepoints(gpa: Allocator, s: []const u8) ![]const u21 {
    var out: std.ArrayList(u21) = .empty;
    var it = (try std.unicode.Utf8View.init(s)).iterator();
    while (it.nextCodepoint()) |c| try out.append(gpa, c);
    return out.items;
}

test "Punycode matches RFC 3492's samples, both ways" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    for ([_][2][]const u8{
        .{ "ليهمابتكلموشعربي؟", "egbpdaj6bu4bxfgehfvwxn" },
        .{ "他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye" },
        .{ "他們爲什麽不說中文", "ihqwctvzc91f659drss3x8bo0yb" },
        .{ "Pročprostěnemluvíčesky", "Proprostnemluvesky-uyb24dma41a" },
        .{ "למההםפשוטלאמדבריםעברית", "4dbcagdahymbxekheh6e0a7fei0b" },
        .{
            "यहलोगहिन्दीक्यों" ++
                "नहींबोलसकतेहैं",
            "i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd",
        },
        .{
            "なぜみんな日本語を話してくれないのか",
            "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa",
        },
        .{
            "세계의모든사람들이한국어를이해한다면얼마나좋을까",
            "989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a0dt30a5jpsd879ccm6fea98c",
        },
        .{
            "почемужеонинеговорятпорусски",
            "b1abfaaepdrnnbgefbadotcwatmq2g4l",
        },
        .{
            "PorquénopuedensimplementehablarenEspañol",
            "PorqunopuedensimplementehablarenEspaol-fmd56a",
        },
        .{
            "TạisaohọkhôngthểchỉnóitiếngViệt",
            "TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g",
        },
        .{ "3年B組金八先生", "3B-ww4c5e180e575a65lsy2b" },
        .{ "安室奈美恵-with-SUPER-MONKEYS", "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n" },
        .{ "Hello-Another-Way-それぞれの場所", "Hello-Another-Way--fc4qua05auwb3674vfr0b" },
        .{ "ひとつ屋根の下2", "2-u9tlzr9756bt3uc0v" },
        .{ "MajiでKoiする5秒前", "MajiKoi5-783gue6qz075azm5e" },
        .{ "パフィーdeルンバ", "de-jg4avhby1noc0d" },
        .{ "そのスピードで", "d9juau41awczczp" },
        .{ "-> $1.00 <-", "-> $1.00 <--" },
    }) |sample| {
        const points = try utf8ToCodepoints(gpa, sample[0]);
        var out: std.ArrayList(u8) = .empty;
        try encode(gpa, &out, points);
        try testing.expectEqualStrings(sample[1], out.items);
        try testing.expectEqualSlices(u21, points, try decode(gpa, sample[1]));
    }
    for ([_][]const u8{ "b", "!", "99999999999", "\xc3\xa9-a" }) |bad|
        try testing.expect(std.meta.isError(decode(gpa, bad)));
}

test "rules become lowercase A-labels; what IDNA refuses is refused" {
    const a63: [63]u8 = @splat('a');
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    try testing.expectEqualStrings("xn--aroport-bya.ci", try domainToAscii(gpa, "aéroport.ci"));
    try testing.expectEqualStrings("xn--55qx5d.cn", try domainToAscii(gpa, "公司.cn"));
    try testing.expectEqualStrings("co.uk", try domainToAscii(gpa, "CO.uk"));
    try testing.expectEqualStrings("xn--55qx5d.cn", try domainToAscii(gpa, "XN--55QX5D.cn"));
    const long = a63 ++ "." ++ a63 ++ "." ++ a63 ++ "." ++ a63;
    for ([_][]const u8{
        "",               "a..b",       ".a",         "a.",
        "-a.b",           "a-.b",       "ab--c.d",    "a_b.c",
        "a b.c",
        "Éa.b",
        "a\u{3002}b",     "\u{ff41}.b", "\u{301}a.b", "x\u{200d}y",
        "xn--55qx5d-.cn", "xn--a.b",    a63 ++ "a.b", long,
    }) |bad| try testing.expect(std.meta.isError(domainToAscii(gpa, bad)));
}

test "PSL data keeps sections and refuses what the reviewed format forbids" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const head = "// VERSION: v1\n// COMMIT: c1\n";
    const body = markers[0] ++ "\nac\n*.ck\n!www.ck\n\n// a comment\n" ++ markers[1] ++
        "\n// between\n" ++ markers[2] ++ "\nblogspot.com\n" ++ markers[3] ++ "\n";
    var why: []const u8 = "";
    const psl = try pslData(gpa, head ++ body, &why);
    try testing.expectEqual(4, psl.rules);
    try testing.expectEqualStrings("v1", psl.version);
    try testing.expect(std.mem.endsWith(u8, psl.text, "// COMMIT: c1\n" ++ markers[0] ++
        "\nac\n*.ck\n!www.ck\n" ++ markers[1] ++ "\n" ++ markers[2] ++ "\nblogspot.com\n" ++
        markers[3] ++ "\n"));
    for ([_][]const u8{
        body,
        "// VERSION: v1\n" ++ body,
        "// VERSION: \n// COMMIT: c1\n" ++ body,
        head ++ markers[1] ++ "\n" ++ markers[0] ++ "\n" ++ markers[2] ++ "\n" ++ markers[3],
        head ++ "outside.com\n" ++ body,
        head ++ markers[0] ++ "\n ac\n" ++ body[markers[0].len..],
        head ++ markers[0] ++ "\nac\u{3000}\n" ++ body[markers[0].len..],
        head ++ markers[0] ++ "\n*.\n" ++ body[markers[0].len..],
        head ++ markers[0] ++ "\na.*.b\n" ++ body[markers[0].len..],
        head ++ markers[0] ++ "\n!a!b\n" ++ body[markers[0].len..],
        head ++ markers[0] ++ "\na\u{2028}b\n" ++ body[markers[0].len..],
        head ++ "\xff\n" ++ body,
    }) |bad| try testing.expect(std.meta.isError(pslData(gpa, bad, &why)));
}

test "RDAP data is Python's compact ASCII JSON, of the expected shape" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const rdap = try rdapData(gpa,
        \\{ "description": "é \"x\" / \u0001 \ud83d\ude00", "publication": "2026",
        \\  "services": [[["xn--p1ai"], ["https://rdap.example/"]]], "version": "1.0" }
    );
    try testing.expectEqualStrings(
        \\{"description":"\u00e9 \"x\" / \u0001 \ud83d\ude00","publication":"2026",
    ++
        \\"services":[[["xn--p1ai"],["https://rdap.example/"]]],"version":"1.0"}
        \\
    , rdap.text);
    try testing.expectEqual(1, rdap.services);
    for ([_][]const u8{
        "[]",
        \\{"version":"1.1","publication":"x","services":[[[],[]]]}
        ,
        \\{"version":"1.0","publication":1,"services":[[[],[]]]}
        ,
        \\{"version":"1.0","publication":"x","services":[]}
        ,
        \\{"version":"1.0","publication":"x","services":[[[]]]}
        ,
        \\{"version":"1.0","publication":"x","services":[[[1],[]]]}
        ,
        \\{"version":"1.0","publication":"x","services":[[{},[]]]}
        ,
    }) |bad| try testing.expect(std.meta.isError(rdapData(gpa, bad)));
    var many: std.ArrayList(u8) = .empty;
    try many.appendSlice(gpa, "{\"version\":\"1.0\",\"publication\":\"x\",\"services\":[");
    for (0..4097) |i| try many.appendSlice(gpa, if (i == 0) "[[],[]]" else ",[[],[]]");
    try many.appendSlice(gpa, "]}");
    try testing.expectError(error.InvalidRdapServices, rdapData(gpa, many.items));
}
