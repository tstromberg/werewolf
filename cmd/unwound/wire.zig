//! wire reads and writes DNS messages (RFC 1035), strictly. A query is one
//! question of class IN, and at most an OPT record, which is dropped. A
//! response must repeat the query's question byte for byte, which checks
//! its 0x20 case. Names become lowercase text without the final dot, made
//! of letters, digits, hyphens and underscores alone. An answer keeps only
//! the alias chain from the question and the records of its type, rebuilt
//! without compression, and how long a negative answer may be kept, from
//! its SOA (RFC 2308). No system calls: fuzz.zig drives all of it.
const std = @import("std");
const mem = std.mem;

pub const header_len = 12;
/// udp_max is the largest reply without EDNS; a longer one is truncated.
pub const udp_max = 512;
/// query_max bounds a query, whatever it arrives over.
pub const query_max = 512;
/// max_records bounds the records an answer keeps; max_rdata, their data.
pub const max_records = 64;
pub const max_rdata = 8192;
/// max_walk bounds the records a response may carry in all sections.
pub const max_walk = 1024;
/// max_hops bounds an alias chain.
pub const max_hops = 8;
/// max_ttl caps what a client may cache.
pub const max_ttl = 3600;
/// soa_len is the SOA writeResponse adds to carry a negative answer's TTL:
/// the root, its type, class, TTL and length, two roots and five numbers.
const soa_len = 1 + 10 + 2 + 20;
/// response_max fits any response writeResponse can build.
pub const response_max = header_len + 4 + 255 + max_records * (255 + 10) + max_rdata + soa_len;

/// Type is a query type unwound forwards. Each has its own rules for
/// reading and rebuilding its data; any other type is refused.
pub const Type = enum(u16) {
    a = 1,
    ns = 2,
    cname = 5,
    ptr = 12,
    mx = 15,
    txt = 16,
    aaaa = 28,
    srv = 33,
    tlsa = 52,
    caa = 257,

    /// from returns the supported type numbered n, or null.
    pub fn from(n: u16) ?Type {
        return std.enums.fromInt(Type, n);
    }

    /// parse reads a type's name as policy writes it: "A", "AAAA".
    pub fn parse(text: []const u8) ?Type {
        var lower: [8]u8 = undefined;
        if (text.len > lower.len) return null;
        for (text, 0..) |c, i| {
            if (!std.ascii.isUpper(c)) return null;
            lower[i] = std.ascii.toLower(c);
        }
        return std.meta.stringToEnum(Type, lower[0..text.len]);
    }
};

pub const Rcode = enum(u4) {
    noerror = 0,
    formerr = 1,
    servfail = 2,
    nxdomain = 3,
    refused = 5,
};

pub const Error = error{
    /// Short is too little to answer: no header to take an ID from.
    Short,
    /// NotQuery is a response sent to the listener; it gets no reply.
    NotQuery,
    /// Malformed breaks the format or these rules: FORMERR to a client,
    /// SERVFAIL from an upstream.
    Malformed,
    /// Unsupported is another opcode or class: REFUSED.
    Unsupported,
    /// TooLarge is an answer beyond max_records, max_rdata or max_hops.
    TooLarge,
};

/// Name is canonical text: lowercase labels joined by dots, no final dot.
/// The root is the empty name.
pub const Name = struct {
    buf: [253]u8 = undefined,
    len: u8 = 0,

    pub fn text(n: *const Name) []const u8 {
        return n.buf[0..n.len];
    }

    pub fn eql(a: *const Name, b: *const Name) bool {
        return mem.eql(u8, a.text(), b.text());
    }

    /// fromText accepts only canonical text, as policy and tests write it.
    pub fn fromText(s: []const u8) Error!Name {
        var n: Name = .{};
        if (s.len == 0) return n;
        if (s.len > n.buf.len) return error.Malformed;
        var labels = mem.splitScalar(u8, s, '.');
        while (labels.next()) |l| {
            if (l.len == 0 or l.len > 63) return error.Malformed;
            for (l) |c| if (!canonical(c)) return error.Malformed;
        }
        @memcpy(n.buf[0..s.len], s);
        n.len = @intCast(s.len);
        return n;
    }

    /// wireLen is the name's length in a message, without compression.
    pub fn wireLen(n: *const Name) usize {
        return if (n.len == 0) 1 else n.len + 2;
    }
};

fn canonical(c: u8) bool {
    return switch (c) {
        'a'...'z', '0'...'9', '-', '_' => true,
        else => false,
    };
}

/// readName reads the name at start in msg into out and returns the offset
/// just past it there. A pointer must aim into the message body, strictly
/// below where the labels it continues began, so every name ends.
fn readName(msg: []const u8, start: usize, out: *Name) Error!usize {
    var pos = start;
    var low = start;
    var after: ?usize = null;
    var wire: usize = 1;
    out.len = 0;
    while (true) {
        if (pos >= msg.len) return error.Malformed;
        const b = msg[pos];
        switch (b >> 6) {
            0 => {
                if (b == 0) return after orelse pos + 1;
                if (b > msg.len - pos - 1) return error.Malformed;
                wire += 1 + b;
                if (wire > 255) return error.Malformed;
                if (out.len > 0) {
                    out.buf[out.len] = '.';
                    out.len += 1;
                }
                for (msg[pos + 1 ..][0..b]) |raw| {
                    const c = std.ascii.toLower(raw);
                    if (!canonical(c)) return error.Malformed;
                    out.buf[out.len] = c;
                    out.len += 1;
                }
                pos += 1 + b;
            },
            3 => {
                if (pos + 2 > msg.len) return error.Malformed;
                const to = @as(usize, b & 0x3f) << 8 | msg[pos + 1];
                if (to < header_len or to >= low) return error.Malformed;
                if (after == null) after = pos + 2;
                low = to;
                pos = to;
            },
            else => return error.Malformed,
        }
    }
}

/// writeName writes n uncompressed. Bit i of mix, where given, uppercases
/// the name's i'th character if it is a letter: 0x20 case for upstreams.
fn writeName(w: *Writer, n: *const Name, mix: ?*const [32]u8) void {
    var labels = mem.splitScalar(u8, n.text(), '.');
    var i: usize = 0;
    if (n.len > 0) while (labels.next()) |l| {
        w.byte(@intCast(l.len));
        for (l) |c| {
            const up = if (mix) |m| m[i / 8] >> @intCast(i % 8) & 1 == 1 else false;
            w.byte(if (up) std.ascii.toUpper(c) else c);
            i += 1;
        }
        i += 1; // the dot
    };
    w.byte(0);
}

/// Writer appends to a buffer its caller has sized; overflow is a bug.
const Writer = struct {
    buf: []u8,
    len: usize = 0,

    fn byte(w: *Writer, b: u8) void {
        w.buf[w.len] = b;
        w.len += 1;
    }

    fn int(w: *Writer, comptime T: type, v: T) void {
        mem.writeInt(T, w.buf[w.len..][0..@sizeOf(T)], v, .big);
        w.len += @sizeOf(T);
    }

    fn bytes(w: *Writer, b: []const u8) void {
        @memcpy(w.buf[w.len..][0..b.len], b);
        w.len += b.len;
    }
};

fn int(comptime T: type, msg: []const u8, pos: usize) T {
    return mem.readInt(T, msg[pos..][0..@sizeOf(T)], .big);
}

/// Query is a client's question. type is the raw number: policy decides
/// what an unsupported one gets.
pub const Query = struct {
    id: u16,
    rd: bool,
    name: Name,
    type: u16,
};

const flag_qr: u16 = 0x8000;
const flag_tc: u16 = 0x0200;
const flag_rd: u16 = 0x0100;
const flag_ra: u16 = 0x0080;
const flag_ad: u16 = 0x0020;
const type_soa = 6;
const type_opt = 41;
const class_in = 1;

/// parseQuery reads a client's query. Anything but the header, one
/// question and one OPT record, in that order, is Malformed.
pub fn parseQuery(msg: []const u8) Error!Query {
    if (msg.len < header_len) return error.Short;
    const flags = int(u16, msg, 2);
    if (flags & flag_qr != 0) return error.NotQuery;
    if (msg.len > query_max) return error.Malformed;
    if (flags & flag_tc != 0) return error.Malformed;
    if (int(u16, msg, 4) != 1 or int(u16, msg, 6) != 0 or int(u16, msg, 8) != 0 or
        int(u16, msg, 10) > 1) return error.Malformed;
    var q: Query = .{ .id = int(u16, msg, 0), .rd = flags & flag_rd != 0, .name = .{}, .type = 0 };
    var pos = try readName(msg, header_len, &q.name);
    if (msg.len - pos < 4) return error.Malformed;
    q.type = int(u16, msg, pos);
    const class = int(u16, msg, pos + 2);
    pos += 4;
    if (int(u16, msg, 10) == 1) {
        // OPT: the root name, its type, then class, TTL and data, all ignored.
        if (msg.len - pos < 11 or msg[pos] != 0 or int(u16, msg, pos + 1) != type_opt)
            return error.Malformed;
        const rdlen = int(u16, msg, pos + 9);
        if (rdlen > msg.len - pos - 11) return error.Malformed;
        pos += 11 + rdlen;
    }
    if (pos != msg.len) return error.Malformed;
    if ((flags >> 11) & 0xf != 0 or class != class_in) return error.Unsupported;
    return q;
}

/// writeQuery writes a recursive query for name and type, cased by mix.
/// buf holds query_max bytes.
pub fn writeQuery(buf: []u8, id: u16, name: *const Name, t: Type, mix: ?*const [32]u8) []u8 {
    return writeQueryWithAd(buf, id, name, t, mix, false);
}

/// A trusted local validator receives AD in the request so it can return
/// authenticated data without sending DNSSEC proof records to the client.
pub fn writeQueryWithAd(
    buf: []u8,
    id: u16,
    name: *const Name,
    t: Type,
    mix: ?*const [32]u8,
    request_ad: bool,
) []u8 {
    var w: Writer = .{ .buf = buf };
    w.int(u16, id);
    w.int(u16, flag_rd | (if (request_ad) flag_ad else 0));
    w.int(u16, 1);
    w.int(u16, 0);
    w.int(u16, 0);
    w.int(u16, 0);
    writeName(&w, name, mix);
    w.int(u16, @backingInt(t));
    w.int(u16, class_in);
    return buf[0..w.len];
}

pub const Record = struct {
    name: Name,
    type: Type,
    ttl: u32,
    /// rdata is canonical: names uncompressed and lowercase.
    rdata: []const u8,
};

/// Answer is an upstream's answer to one query, cut to its alias chain
/// and the records of the query's type.
pub const Answer = struct {
    rcode: Rcode = .noerror,
    truncated: bool = false,
    /// The upstream asserted DNSSEC validation. The frontend trusts this
    /// only when the resolver is the form's local validator.
    authenticated: bool = false,
    /// negative is how long, in seconds, the answer's want of records may
    /// be kept: the least of its SOA's TTL and minimum, if it has one for
    /// the question's zone (RFC 2308).
    negative: ?u32 = null,
    records: [max_records]Record = undefined,
    n: usize = 0,
    data: [max_rdata]u8 = undefined,
    used: usize = 0,

    pub fn slice(a: *const Answer) []const Record {
        return a.records[0..a.n];
    }
};

/// parseResponse reads msg, an answer to query, which writeQuery wrote.
/// An upstream error other than NXDOMAIN is SERVFAIL, with no records.
pub fn parseResponse(msg: []const u8, query: []const u8, a: *Answer) Error!void {
    a.* = .{ .rcode = .noerror };
    if (msg.len < query.len or msg.len > std.math.maxInt(u16)) return error.Malformed;
    const flags = int(u16, msg, 2);
    if (int(u16, msg, 0) != int(u16, query, 0) or flags & flag_qr == 0 or
        (flags >> 11) & 0xf != 0 or int(u16, msg, 4) != 1) return error.Malformed;
    // The question, compared as bytes: name, case, type and class.
    if (!mem.eql(u8, msg[header_len..query.len], query[header_len..])) return error.Malformed;
    if (flags & flag_tc != 0) {
        a.truncated = true;
        return;
    }
    a.rcode = switch (flags & 0xf) {
        0 => .noerror,
        3 => .nxdomain,
        else => {
            a.rcode = .servfail;
            return;
        },
    };
    a.authenticated = flags & flag_ad != 0;
    const qtype = Type.from(int(u16, query, query.len - 4)) orelse return error.Malformed;
    var qname: Name = .{};
    _ = try readName(query, header_len, &qname);
    const ancount = int(u16, msg, 6);
    const nscount = int(u16, msg, 8);
    const total = @as(usize, ancount) + nscount + int(u16, msg, 10);
    if (total > max_walk) return error.Malformed;
    var pos = query.len;
    var owner: Name = .{};
    for (0..total) |i| {
        pos = try readName(msg, pos, &owner);
        if (msg.len - pos < 10) return error.Malformed;
        const n = int(u16, msg, pos);
        const class = int(u16, msg, pos + 2);
        const raw_ttl = int(u32, msg, pos + 4);
        const ttl = if (raw_ttl > std.math.maxInt(i32)) 0 else @min(raw_ttl, max_ttl);
        const rdlen = int(u16, msg, pos + 8);
        pos += 10;
        if (rdlen > msg.len - pos) return error.Malformed;
        const end = pos + rdlen;
        defer pos = end;
        if (i >= ancount) {
            if (n != type_opt and class != class_in) return error.Malformed;
            if (n == type_soa and i < ancount + nscount and within(&qname, &owner)) {
                // Two names, then serial, refresh, retry, expire and minimum.
                var skip: Name = .{};
                // The names may run past the record's data: check before counting.
                const numbers = try readName(msg, try readName(msg, pos, &skip), &skip);
                if (numbers > end or end - numbers != 20) return error.Malformed;
                const least = @min(ttl, int(u32, msg, numbers + 16));
                a.negative = @min(a.negative orelse least, least);
            }
            continue;
        }
        if (class != class_in) return error.Malformed;
        const t = Type.from(n) orelse continue;
        if (t != qtype and t != .cname) continue;
        if (a.n == max_records) return error.TooLarge;
        const start = a.used;
        try canonicalData(a, msg, pos, end, t);
        a.records[a.n] = .{ .name = owner, .type = t, .ttl = ttl, .rdata = a.data[start..a.used] };
        a.n += 1;
    }
    if (pos != msg.len) return error.Malformed;
    try chain(a, &qname, qtype);
}

/// within reports whether name is zone or a name below it.
fn within(name: *const Name, zone: *const Name) bool {
    const n = name.text();
    const z = zone.text();
    return z.len == 0 or mem.eql(u8, n, z) or
        (n.len > z.len and mem.endsWith(u8, n, z) and n[n.len - z.len - 1] == '.');
}

/// canonicalData appends the data of a record of type t at msg[pos..end]
/// to a.data, checked against its type and with any names uncompressed.
fn canonicalData(a: *Answer, msg: []const u8, pos: usize, end: usize, t: Type) Error!void {
    const data = msg[pos..end];
    // Fixed fields, then perhaps a name: MX's preference, SRV's three.
    const fixed: usize = switch (t) {
        .a => 4,
        .aaaa => 16,
        .cname, .ns, .ptr => 0,
        .mx => 2,
        .srv => 6,
        .txt, .caa, .tlsa => data.len,
    };
    if (data.len < fixed) return error.Malformed;
    switch (t) {
        .a, .aaaa => if (data.len != fixed) return error.Malformed,
        .txt => {
            if (data.len == 0) return error.Malformed;
            var i: usize = 0;
            while (i < data.len) i += 1 + @as(usize, data[i]);
            if (i != data.len) return error.Malformed;
        },
        .caa => {
            if (data.len < 2 or data[1] == 0 or data[1] > 15 or 2 + data[1] > data.len)
                return error.Malformed;
            for (data[2..][0..data[1]]) |c| if (!std.ascii.isAlphanumeric(
                c,
            )) return error.Malformed;
        },
        .tlsa => if (data.len < 4) return error.Malformed,
        else => {},
    }
    var name: Name = .{};
    const has_name = switch (t) {
        .cname, .ns, .ptr, .mx, .srv => true,
        else => false,
    };
    if (has_name and try readName(msg, pos + fixed, &name) != end) return error.Malformed;
    const need = fixed + if (has_name) name.wireLen() else 0;
    if (need > a.data.len - a.used) return error.TooLarge;
    var w: Writer = .{ .buf = a.data[a.used..] };
    w.bytes(data[0..fixed]);
    if (has_name) writeName(&w, &name, null);
    a.used += w.len;
}

/// chain keeps, in order, the aliases from qname and then the records of
/// qtype at the chain's end. A CNAME query keeps qname's alias alone.
fn chain(a: *Answer, qname: *const Name, qtype: Type) Error!void {
    var keep: [max_records]Record = undefined;
    var n: usize = 0;
    var at = qname.*;
    var hops: usize = 0;
    while (try aliasOf(a, &at)) |i| {
        keep[n] = a.records[i];
        n += 1;
        if (qtype == .cname) break;
        hops += 1;
        if (hops > max_hops) return error.TooLarge;
        _ = try readName(a.records[i].rdata, 0, &at);
    }
    if (qtype != .cname) for (a.slice()) |r| {
        if (r.type == qtype and r.name.eql(&at)) {
            keep[n] = r;
            n += 1;
        }
    };
    @memcpy(a.records[0..n], keep[0..n]);
    a.n = n;
}

/// aliasOf returns the index of name's one CNAME record. Two are ambiguous.
fn aliasOf(a: *const Answer, name: *const Name) Error!?usize {
    var found: ?usize = null;
    for (a.slice(), 0..) |r, i| {
        if (r.type != .cname or !r.name.eql(name)) continue;
        if (found != null) return error.Malformed;
        found = i;
    }
    return found;
}

/// target returns the name in a CNAME, NS, PTR, MX or SRV record's data.
pub fn target(r: *const Record) Name {
    const at: usize = switch (r.type) {
        .cname, .ns, .ptr => 0,
        .mx => 2,
        .srv => 6,
        .a, .aaaa, .txt, .caa, .tlsa => unreachable,
    };
    var n: Name = .{};
    // rdata is canonical, written by writeName: it always reads back.
    _ = readName(r.rdata[at..], 0, &n) catch unreachable;
    return n;
}

/// Question is what a reply repeats; null when the query could not be read.
pub const Question = struct { name: *const Name, type: u16 };

/// writeResponse writes a reply into buf, which holds response_max bytes.
/// If the records make it longer than limit, it is truncated: no records.
/// A negative TTL is carried as an SOA for the root, with that TTL and
/// minimum, which parseResponse reads back.
pub fn writeResponse(
    buf: []u8,
    id: u16,
    rd: bool,
    rcode: Rcode,
    q: ?Question,
    records: []const Record,
    negative: ?u32,
    limit: usize,
) []u8 {
    return writeResponseWithAd(buf, id, rd, rcode, q, records, negative, limit, false);
}

pub fn writeResponseWithAd(
    buf: []u8,
    id: u16,
    rd: bool,
    rcode: Rcode,
    q: ?Question,
    records: []const Record,
    negative: ?u32,
    limit: usize,
    authenticated: bool,
) []u8 {
    var w: Writer = .{ .buf = buf };
    w.int(u16, id);
    w.int(u16, 0);
    w.int(u16, @intFromBool(q != null));
    w.int(u16, 0);
    w.int(u16, 0);
    w.int(u16, 0);
    if (q) |question| {
        writeName(&w, question.name, null);
        w.int(u16, question.type);
        w.int(u16, class_in);
    }
    const question_end = w.len;
    const room = limit - @as(usize, if (negative == null) 0 else soa_len);
    var fits = true;
    for (records) |*r| {
        if (w.len + r.name.wireLen() + 10 + r.rdata.len > room) {
            fits = false;
            break;
        }
        writeName(&w, &r.name, null);
        w.int(u16, @backingInt(r.type));
        w.int(u16, class_in);
        w.int(u32, r.ttl);
        w.int(u16, @intCast(r.rdata.len));
        w.bytes(r.rdata);
    }
    if (!fits) w.len = question_end;
    if (fits) if (negative) |ttl| {
        w.bytes("\x00");
        w.int(u16, type_soa);
        w.int(u16, class_in);
        w.int(u32, ttl);
        w.int(u16, 22);
        // Root names, then serial, refresh, retry and expire, then minimum.
        w.bytes("\x00\x00");
        for (0..4) |_| w.int(u32, 0);
        w.int(u32, ttl);
        mem.writeInt(u16, buf[8..10], 1, .big);
    };
    const n: u16 = if (fits) @intCast(records.len) else 0;
    mem.writeInt(u16, buf[2..4], flag_qr | flag_ra | (if (rd) flag_rd else 0) |
        (if (authenticated and fits) flag_ad else 0) |
        (if (fits) 0 else flag_tc) | @as(u16, @backingInt(rcode)), .big);
    mem.writeInt(u16, buf[6..8], n, .big);
    return buf[0..w.len];
}

const testing = std.testing;

fn rep(comptime c: u8, comptime n: usize) *const [n]u8 {
    const r: [n]u8 = @splat(c);
    return &r;
}

fn nm(s: []const u8) Name {
    return Name.fromText(s) catch unreachable;
}

test "queries: one IN question, an optional OPT, nothing else" {
    var buf: [query_max]u8 = undefined;
    const q = writeQuery(&buf, 0x1234, &nm("www.example.com"), .aaaa, null);
    const got = try parseQuery(q);
    try testing.expectEqual(0x1234, got.id);
    try testing.expect(got.rd);
    try testing.expectEqualStrings("www.example.com", got.name.text());
    try testing.expectEqual(28, got.type);

    // Upper case is folded; an OPT is accepted and dropped.
    const opt = "\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00";
    var with: [query_max]u8 = undefined;
    @memcpy(with[0..q.len], q);
    with[13] = 'W';
    with[11] = 1;
    @memcpy(with[q.len..][0..opt.len], opt);
    const folded = try parseQuery(with[0 .. q.len + opt.len]);
    try testing.expectEqualStrings("www.example.com", folded.name.text());

    try testing.expectError(error.Short, parseQuery(q[0..11]));
    var bad: [query_max]u8 = undefined;
    const cases = [_]struct { at: usize, byte: u8, err: Error }{
        .{ .at = 2, .byte = 0x81, .err = error.NotQuery }, // QR
        .{ .at = 2, .byte = 0x29, .err = error.Unsupported }, // UPDATE
        .{ .at = 2, .byte = 0x03, .err = error.Malformed }, // TC
        .{ .at = 5, .byte = 2, .err = error.Malformed }, // two questions
        .{ .at = 7, .byte = 1, .err = error.Malformed }, // an answer
        .{ .at = 9, .byte = 1, .err = error.Malformed }, // authority
        .{ .at = 11, .byte = 1, .err = error.Malformed }, // additional, but none follows
        .{ .at = q.len - 1, .byte = 3, .err = error.Unsupported }, // class CH
        .{ .at = 16, .byte = '.', .err = error.Malformed }, // a dot inside a label
        .{ .at = 16, .byte = 0x80, .err = error.Malformed }, // not ASCII
        .{ .at = 16, .byte = ' ', .err = error.Malformed },
        .{ .at = 16, .byte = '*', .err = error.Malformed },
        .{ .at = 12, .byte = 0x40, .err = error.Malformed }, // extended label type
        .{ .at = 12, .byte = 0xc0, .err = error.Malformed }, // pointer into the header
    };
    for (cases) |c| {
        @memcpy(bad[0..q.len], q);
        bad[c.at] = c.byte;
        try testing.expectError(c.err, parseQuery(bad[0..q.len]));
    }
    @memcpy(bad[0..q.len], q);
    bad[q.len] = 0;
    try testing.expectError(error.Malformed, parseQuery(bad[0 .. q.len + 1])); // trailing
    try testing.expectError(error.Malformed, parseQuery(bad[0 .. q.len - 1])); // cut short
    var big: [query_max + 1]u8 = @splat(0);
    @memcpy(big[0..q.len], q);
    try testing.expectError(error.Malformed, parseQuery(&big));
}

test "names: canonical text, bounded labels and length" {
    try testing.expectEqual(0, (try Name.fromText("")).len);
    _ = try Name.fromText("_acme-challenge.example.com");
    for ([_][]const u8{
        "Example.com", "example.com.", ".example.com", "a..b", "a b", "*.a",
        "é",
    }) |s|
        try testing.expectError(error.Malformed, Name.fromText(s));
    try testing.expectError(error.Malformed, Name.fromText(rep('a', 64)));
    _ = try Name.fromText(rep('a', 63));
    // 253 characters is the longest name: 255 bytes on the wire.
    const long = rep('a', 63) ++ "." ++ rep('a', 63) ++ "." ++ rep('a', 63) ++ "." ++ rep('a', 61);
    try testing.expectEqual(253, long.len);
    const n = try Name.fromText(long);
    try testing.expectEqual(255, n.wireLen());
    var buf: [query_max]u8 = undefined;
    try testing.expectEqualStrings(
        long,
        (try parseQuery(writeQuery(&buf, 1, &n, .a, null))).name.text(),
    );
    // One more label byte on the wire is too long.
    var over: [query_max]u8 = undefined;
    const q = writeQuery(&over, 1, &n, .a, null);
    var longer: [query_max]u8 = undefined;
    @memcpy(longer[0..12], q[0..12]);
    longer[12] = 1;
    longer[13] = 'b';
    @memcpy(longer[14..][0 .. q.len - 12], q[12..]);
    try testing.expectError(error.Malformed, parseQuery(longer[0 .. q.len + 2]));
}

test "0x20: the query carries mixed case and the response must repeat it" {
    var mix: [32]u8 = @splat(0);
    mix[0] = 0b101; // the first and third letters
    var buf: [query_max]u8 = undefined;
    const q = writeQuery(&buf, 7, &nm("abc.de"), .a, &mix);
    try testing.expectEqualStrings("\x03AbC\x02de\x00", q[12 .. q.len - 4]);

    var r: Responder = .init(q);
    r.record("abc.de", .a, 60, "\x01\x02\x03\x04");
    var a: Answer = .{};
    try parseResponse(r.bytes(), q, &a);
    try testing.expectEqual(1, a.n);

    // The same name in other case is someone guessing.
    var lower: [query_max]u8 = undefined;
    @memcpy(lower[0..q.len], q);
    lower[13] = 'a';
    var forged: Responder = .init(lower[0..q.len]);
    forged.record("abc.de", .a, 60, "\x01\x02\x03\x04");
    try testing.expectError(error.Malformed, parseResponse(forged.bytes(), q, &a));
}

/// Responder builds an upstream's response for tests, compressed where
/// asked, as real servers write them.
const Responder = struct {
    buf: [4096]u8 = undefined,
    len: usize,

    fn init(q: []const u8) Responder {
        var r: Responder = .{ .len = q.len };
        @memcpy(r.buf[0..q.len], q);
        r.buf[2] |= 0x80; // QR
        r.buf[3] = 0x80; // RA
        return r;
    }

    fn bytes(r: *Responder) []const u8 {
        return r.buf[0..r.len];
    }

    fn raw(r: *Responder, b: []const u8) void {
        @memcpy(r.buf[r.len..][0..b.len], b);
        r.len += b.len;
    }

    fn count(r: *Responder, at: usize) void {
        mem.writeInt(u16, r.buf[at..][0..2], int(u16, &r.buf, at) + 1, .big);
    }

    fn owner(r: *Responder, s: []const u8) void {
        // The question's name, as a pointer, when it is the same.
        var q: Name = .{};
        _ = readName(&r.buf, header_len, &q) catch unreachable;
        if (mem.eql(u8, q.text(), s)) return r.raw("\xc0\x0c");
        var w: Writer = .{ .buf = r.buf[r.len..] };
        writeName(&w, &nm(s), null);
        r.len += w.len;
    }

    fn record(r: *Responder, owner_name: []const u8, t: Type, ttl: u32, data: []const u8) void {
        r.owner(owner_name);
        var w: Writer = .{ .buf = r.buf[r.len..] };
        w.int(u16, @backingInt(t));
        w.int(u16, class_in);
        w.int(u32, ttl);
        w.int(u16, @intCast(data.len));
        w.bytes(data);
        r.len += w.len;
        r.count(6);
    }

    /// soa adds zone's SOA to the authority section, after any answers.
    fn soa(r: *Responder, zone: []const u8, ttl: u32, minimum: u32) void {
        r.owner(zone);
        var w: Writer = .{ .buf = r.buf[r.len..] };
        w.int(u16, type_soa);
        w.int(u16, class_in);
        w.int(u32, ttl);
        w.int(u16, 0);
        writeName(&w, &nm("ns.example"), null);
        writeName(&w, &nm("admin.example"), null);
        for ([_]u32{ 1, 7200, 900, 86400, minimum }) |v| w.int(u32, v);
        mem.writeInt(u16, w.buf[8..10], @intCast(w.len - 10), .big);
        r.len += w.len;
        r.count(8);
    }

    fn alias(r: *Responder, from: []const u8, to: []const u8) void {
        var data: [256]u8 = undefined;
        var w: Writer = .{ .buf = &data };
        writeName(&w, &nm(to), null);
        r.record(from, .cname, 300, data[0..w.len]);
    }
};

test "answers keep the alias chain and the asked type, nothing else" {
    var buf: [query_max]u8 = undefined;
    const q = writeQuery(&buf, 9, &nm("www.example.com"), .a, null);
    var r: Responder = .init(q);
    r.record("www.example.com", .aaaa, 60, "\x20\x01" ++ rep(0, 14)); // wrong type
    r.alias("www.example.com", "edge.cdn.net");
    r.record("unrelated.example", .a, 60, "\x0a\x00\x00\x01"); // off the chain
    r.record("edge.cdn.net", .a, 0x8000_0000, "\x01\x02\x03\x04"); // TTL with its top bit set
    r.record("edge.cdn.net", .a, 99999, "\x01\x02\x03\x05");
    // Authority and additional sections are walked, then dropped.
    r.record("example.com", .ns, 60, "\x02ns\xc0\x10");
    mem.writeInt(u16, r.buf[6..8], int(u16, &r.buf, 6) - 1, .big);
    r.count(8);
    r.raw("\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00");
    r.count(10);
    var a: Answer = .{};
    try parseResponse(r.bytes(), q, &a);
    try testing.expectEqual(3, a.n);
    try testing.expectEqual(.cname, a.records[0].type);
    try testing.expectEqualStrings("edge.cdn.net", target(&a.records[0]).text());
    try testing.expectEqual(0, a.records[1].ttl);
    try testing.expectEqual(max_ttl, a.records[2].ttl);
    try testing.expectEqualStrings("edge.cdn.net", a.records[2].name.text());

    // Rebuilt, it reads as a client would read it.
    var out: [response_max]u8 = undefined;
    const reply = writeResponse(
        &out,
        77,
        true,
        a.rcode,
        .{ .name = &nm("www.example.com"), .type = 1 },
        a.slice(),
        null,
        udp_max,
    );
    try testing.expectEqual(77, int(u16, reply, 0));
    try testing.expectEqual(0x8180, int(u16, reply, 2));
    try testing.expectEqual(3, int(u16, reply, 6));
    try testing.expectEqual(0, int(u16, reply, 8) + int(u16, reply, 10));
}

test "responses: forged, malformed and oversized answers fail" {
    var buf: [query_max]u8 = undefined;
    const q = writeQuery(&buf, 9, &nm("a.example"), .a, null);
    var a: Answer = .{};

    var wrong_id: Responder = .init(q);
    wrong_id.buf[1] ^= 1;
    try testing.expectError(error.Malformed, parseResponse(wrong_id.bytes(), q, &a));

    var other: [query_max]u8 = undefined;
    var wrong_name: Responder = .init(writeQuery(&other, 9, &nm("b.example"), .a, null));
    try testing.expectError(error.Malformed, parseResponse(wrong_name.bytes(), q, &a));

    var wrong_type: Responder = .init(writeQuery(&other, 9, &nm("a.example"), .aaaa, null));
    try testing.expectError(error.Malformed, parseResponse(wrong_type.bytes(), q, &a));

    var not_response: Responder = .init(q);
    not_response.buf[2] &= 0x7f;
    try testing.expectError(error.Malformed, parseResponse(not_response.bytes(), q, &a));

    var trailing: Responder = .init(q);
    trailing.raw("\x00");
    try testing.expectError(error.Malformed, parseResponse(trailing.bytes(), q, &a));

    var short_a: Responder = .init(q);
    short_a.record("a.example", .a, 60, "\x01\x02\x03");
    try testing.expectError(error.Malformed, parseResponse(short_a.bytes(), q, &a));

    var bad_txt: Responder = .init(writeQuery(&other, 9, &nm("a.example"), .txt, null));
    bad_txt.record("a.example", .txt, 60, "\x05abc");
    try testing.expectError(
        error.Malformed,
        parseResponse(bad_txt.bytes(), bad_txt.buf[0..other.len], &a),
    );

    // A pointer to itself, and one forward, never end.
    var loop: Responder = .init(q);
    loop.raw("\xc0");
    loop.raw(&.{@intCast(loop.len - 1)});
    loop.raw("\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04");
    loop.count(6);
    try testing.expectError(error.Malformed, parseResponse(loop.bytes(), q, &a));
    var forward: Responder = .init(q);
    forward.raw("\xc0");
    forward.raw(&.{@intCast(forward.len + 1)});
    forward.raw("\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04");
    forward.count(6);
    try testing.expectError(error.Malformed, parseResponse(forward.bytes(), q, &a));

    // An alias loop, or a chain past max_hops, is too large; two aliases for one name are
    // ambiguous.
    var cycle: Responder = .init(q);
    cycle.alias("a.example", "b.example");
    cycle.alias("b.example", "a.example");
    try testing.expectError(error.TooLarge, parseResponse(cycle.bytes(), q, &a));
    var two: Responder = .init(q);
    two.alias("a.example", "b.example");
    two.alias("a.example", "c.example");
    try testing.expectError(error.Malformed, parseResponse(two.bytes(), q, &a));

    var many: Responder = .init(q);
    for (0..max_records + 1) |_| many.record("a.example", .a, 60, "\x01\x02\x03\x04");
    try testing.expectError(error.TooLarge, parseResponse(many.bytes(), q, &a));

    // Upstream refusals and failures are SERVFAIL; NXDOMAIN passes; TC asks for TCP.
    var refused: Responder = .init(q);
    refused.buf[3] |= 5;
    try parseResponse(refused.bytes(), q, &a);
    try testing.expectEqual(.servfail, a.rcode);
    var nx: Responder = .init(q);
    nx.buf[3] |= 3;
    try parseResponse(nx.bytes(), q, &a);
    try testing.expectEqual(.nxdomain, a.rcode);
    var tc: Responder = .init(q);
    tc.buf[2] |= 2;
    try parseResponse(tc.bytes(), q, &a);
    try testing.expect(a.truncated);
}

test "a negative answer is kept as long as its zone's SOA says" {
    var buf: [query_max]u8 = undefined;
    const q = writeQuery(&buf, 4, &nm("gone.example.com"), .a, null);
    var r: Responder = .init(q);
    r.buf[3] |= 3;
    // An SOA for another zone says nothing; the zone's own, the least of
    // its TTL and minimum.
    r.soa("example.net", 30, 30);
    r.soa("example.com", 600, 60);
    var a: Answer = .{};
    try parseResponse(r.bytes(), q, &a);
    try testing.expectEqual(.nxdomain, a.rcode);
    try testing.expectEqual(60, a.negative.?);

    // Rebuilt, as upstream sends it to the frontend, the TTL is the same.
    var out: [response_max]u8 = undefined;
    const question: Question = .{ .name = &nm("gone.example.com"), .type = 1 };
    const reply = writeResponse(&out, 4, true, .nxdomain, question, &.{}, 60, response_max);
    var b: Answer = .{};
    try parseResponse(reply, q, &b);
    try testing.expectEqual(60, b.negative.?);
    // An SOA whose names run past its data, into the next record, is
    // malformed.
    var past: Responder = .init(q);
    past.buf[3] |= 3;
    past.raw("\x07example\x03com\x00\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x01\x00");
    past.count(8);
    past.raw("\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04");
    past.count(8);
    try testing.expectError(error.Malformed, parseResponse(past.bytes(), q, &b));
    // Without an SOA, nothing says how long.
    const bare = writeResponse(&out, 4, true, .nxdomain, question, &.{}, null, response_max);
    try parseResponse(bare, q, &b);
    try testing.expectEqual(null, b.negative);
}

test "names in data are uncompressed and every type keeps its shape" {
    var buf: [query_max]u8 = undefined;
    const q = writeQuery(&buf, 3, &nm("example.com"), .mx, null);
    var r: Responder = .init(q);
    // mail.example.com, its suffix a pointer to the question's name.
    r.record("example.com", .mx, 60, "\x00\x0a\x04MAIL\xc0\x0c");
    var a: Answer = .{};
    try parseResponse(r.bytes(), q, &a);
    try testing.expectEqualStrings("\x00\x0a\x04mail\x07example\x03com\x00", a.records[0].rdata);

    const srv_q = writeQuery(&buf, 3, &nm("_x._tcp.example.com"), .srv, null);
    var srv: Responder = .init(srv_q);
    srv.record("_x._tcp.example.com", .srv, 60, "\x00\x01\x00\x02\x01\xbb\x00");
    try parseResponse(srv.bytes(), srv_q, &a);
    try testing.expectEqualStrings("\x00\x01\x00\x02\x01\xbb\x00", a.records[0].rdata);

    const caa_q = writeQuery(&buf, 3, &nm("example.com"), .caa, null);
    var caa: Responder = .init(caa_q);
    caa.record("example.com", .caa, 60, "\x00\x05issueletsencrypt.org");
    try parseResponse(caa.bytes(), caa_q, &a);
    var bad_caa: Responder = .init(caa_q);
    bad_caa.record("example.com", .caa, 60, "\x00\x05is ueletsencrypt.org");
    try testing.expectError(error.Malformed, parseResponse(bad_caa.bytes(), caa_q, &a));

    const tlsa_q = writeQuery(&buf, 3, &nm("_25._tcp.example.com"), .tlsa, null);
    var tlsa: Responder = .init(tlsa_q);
    const association = "\x03\x01\x01" ++ rep(0x5a, 32);
    tlsa.record("_25._tcp.example.com", .tlsa, 60, association);
    try parseResponse(tlsa.bytes(), tlsa_q, &a);
    try testing.expectEqualStrings(association, a.records[0].rdata);
    var short_tlsa: Responder = .init(tlsa_q);
    short_tlsa.record("_25._tcp.example.com", .tlsa, 60, "\x03\x01\x01");
    try testing.expectError(error.Malformed, parseResponse(short_tlsa.bytes(), tlsa_q, &a));
}

test "authenticated answers require a requested and trusted AD bit" {
    var buf: [query_max]u8 = undefined;
    const name = nm("_25._tcp.mail.example");
    const q = writeQueryWithAd(&buf, 7, &name, .tlsa, null, true);
    try testing.expectEqual(flag_rd | flag_ad, int(u16, q, 2));
    var r: Responder = .init(q);
    r.record(name.text(), .tlsa, 60, "\x03\x01\x01" ++ rep(0x41, 32));
    var reply: [response_max]u8 = undefined;
    @memcpy(reply[0..r.bytes().len], r.bytes());
    mem.writeInt(u16, reply[2..4], int(u16, reply[0..], 2) | flag_ad, .big);
    var a: Answer = .{};
    try parseResponse(reply[0..r.bytes().len], q, &a);
    try testing.expect(a.authenticated);
    const question: Question = .{ .name = &name, .type = @backingInt(Type.tlsa) };
    const rebuilt = writeResponseWithAd(
        &reply,
        7,
        true,
        a.rcode,
        question,
        a.slice(),
        null,
        response_max,
        a.authenticated,
    );
    try testing.expect(int(u16, rebuilt, 2) & flag_ad != 0);
    const ordinary = writeResponse(
        &reply,
        7,
        true,
        a.rcode,
        question,
        a.slice(),
        null,
        response_max,
    );
    try testing.expect(int(u16, ordinary, 2) & flag_ad == 0);
}

test "replies past the limit are truncated, and errors repeat the question" {
    var buf: [query_max]u8 = undefined;
    const q = writeQuery(&buf, 5, &nm("big.example"), .txt, null);
    var r: Responder = .init(q);
    const txt = "\xff" ++ rep('x', 255);
    for (0..3) |_| r.record("big.example", .txt, 60, txt);
    var a: Answer = .{};
    try parseResponse(r.bytes(), q, &a);
    var out: [response_max]u8 = undefined;
    const question: Question = .{ .name = &nm("big.example"), .type = @backingInt(Type.txt) };
    const udp = writeResponse(&out, 5, true, .noerror, question, a.slice(), null, udp_max);
    try testing.expect(udp.len <= udp_max);
    try testing.expectEqual(0x8380, int(u16, udp, 2)); // QR TC RD RA
    try testing.expectEqual(0, int(u16, udp, 6));
    const tcp = writeResponse(&out, 5, true, .noerror, question, a.slice(), null, response_max);
    try testing.expectEqual(3, int(u16, tcp, 6));

    const refused = writeResponse(&out, 6, false, .refused, question, &.{}, null, udp_max);
    try testing.expectEqual(0x8085, int(u16, refused, 2));
    try testing.expectEqual(1, int(u16, refused, 4));
    const formerr = writeResponse(&out, 6, false, .formerr, null, &.{}, null, udp_max);
    try testing.expectEqual(header_len, formerr.len);
}

test "types parse by their policy names" {
    try testing.expectEqual(Type.aaaa, Type.parse("AAAA").?);
    try testing.expectEqual(null, Type.parse("aaaa"));
    try testing.expectEqual(null, Type.parse("ANY"));
    try testing.expectEqual(Type.caa, Type.from(257).?);
    try testing.expectEqual(Type.tlsa, Type.parse("TLSA").?);
    try testing.expectEqual(null, Type.from(255));
    try testing.expectEqual(null, Type.from(252)); // AXFR
}
