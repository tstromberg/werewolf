//! tcp holds one text conversation with a stream server, over TCP, TLS or
//! a Unix socket: it sends, waits until each reply satisfies what is
//! expected of it, and can require the server to close. The reply an
//! expectation sees is everything received since the last send. Reads
//! are bounded by bytes, and the whole conversation by the step's time.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const tls = std.crypto.tls;

extern fn werewolf_regex_match(pattern: [*:0]const u8, text: [*:0]const u8) c_int;

pub const max_reply = 1 << 20;

/// Expect waits until the reply holds every one it names.
pub const Expect = struct {
    prefix: ?[]const u8 = null,
    contains: ?[]const u8 = null,
    matches: ?[]const u8 = null,
};

/// Close is how the server may end the conversation, with no byte after
/// what the last expectation saw.
pub const Close = struct { eof: bool = false, reset: bool = false };

pub const Item = union(enum) {
    send: []const u8,
    pause_seconds: u16,
    expect: Expect,
    close: Close,
};

pub const Target = union(enum) {
    /// host is an address literal or a name, which TLS also verifies.
    tcp: struct { host: []const u8, port: u16 },
    unix: []const u8,
};

pub const Security = union(enum) {
    plain,
    insecure,
    /// verify trusts the CA file named, or the system's when null.
    verify: ?[]const u8,
};

pub const Conversation = struct {
    target: Target,
    security: Security = .plain,
    items: []const Item,
};

/// Outcome names the 1-based item that failed, the part of it that did,
/// and the reply then; failed is 0 when every item held.
pub const Outcome = struct {
    failed: usize = 0,
    field: []const u8 = "",
    received: []const u8 = "",
};

pub fn converse(io: Io, a: Allocator, c: Conversation, timeout_ms: i64) !Outcome {
    var s: Talk = .{ .a = a };
    const Event = union(enum) { done: anyerror!void, timeout: Io.Cancelable!void };
    var buffer: [2]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.done, run, .{ io, &s, c });
    try events.concurrent(.timeout, sleep, .{ io, timeout_ms });
    switch (try events.await()) {
        .done => |result| try result,
        .timeout => |result| {
            try result;
            // Stop the conversation before reading what it left.
            events.cancelDiscard();
            if (s.item == 0) return error.Timeout;
            s.fail("timeout");
        },
    }
    return s.outcome;
}

/// probe holds the conversation a validated step asks for, its references
/// resolved, and says how it went: failed, field, received and want.
pub fn probe(io: Io, a: Allocator, request: std.json.Value, timeout_ms: i64) !std.json.Value {
    const r = request.object;
    const target: Target = if (r.get("unix")) |path| .{ .unix = path.string } else blk: {
        const text = r.get("connect").?.string;
        const colon = mem.findScalarLast(u8, text, ':') orelse return error.InvalidTarget;
        break :blk .{ .tcp = .{
            .host = mem.trim(u8, text[0..colon], "[]"),
            .port = try std.fmt.parseInt(u16, text[colon + 1 ..], 10),
        } };
    };
    const security: Security = if (r.get("tls")) |t| if (mem.eql(u8, t.string, "insecure"))
        .insecure
    else
        .{ .verify = if (r.get("ca")) |ca| ca.string else null } else .plain;
    const exchange = r.get("exchange").?.array.items;
    const items = try a.alloc(Item, exchange.len);
    for (exchange, items) |entry, *item| {
        const kind = entry.object.keys()[0];
        const v = entry.object.values()[0];
        item.* = if (mem.eql(u8, kind, "send"))
            .{ .send = try literal(v) }
        else if (mem.eql(u8, kind, "pause"))
            .{ .pause_seconds = @intCast(v.integer) }
        else if (mem.eql(u8, kind, "expect")) .{ .expect = .{
            .prefix = if (v.object.get("prefix")) |p| try literal(p) else null,
            .contains = if (v.object.get("contains")) |c| try literal(c) else null,
            .matches = if (v.object.get("matches")) |m| try regex(m) else null,
        } } else if (mem.eql(u8, kind, "close")) blk: {
            var close_: Close = .{};
            for (v.array.items) |name| {
                if (mem.eql(u8, name.string, "eof")) close_.eof = true;
                if (mem.eql(u8, name.string, "reset")) close_.reset = true;
            }
            break :blk .{ .close = close_ };
        } else return error.InvalidExchange;
    }
    const outcome = try converse(io, a, .{
        .target = target,
        .security = security,
        .items = items,
    }, timeout_ms);
    var got: std.json.ObjectMap = .empty;
    try got.put(a, "failed", .{ .integer = @intCast(outcome.failed) });
    if (outcome.failed > 0) {
        try got.put(a, "field", .{ .string = try a.print(
            "exchange/{d}/{s}",
            .{ outcome.failed, outcome.field },
        ) });
        // A diagnostic shows a reply's start, never more than it can hold.
        const shown = outcome.received[0..@min(outcome.received.len, 120)];
        try got.put(a, "received", .{ .string = try a.dupe(u8, shown) });
        try got.put(a, "want", exchange[outcome.failed - 1]);
    }
    return .{ .object = got };
}

fn literal(v: std.json.Value) ![]const u8 {
    return if (v == .string) v.string else error.InvalidTextInput;
}

fn regex(v: std.json.Value) ![]const u8 {
    const text = try literal(v);
    if (mem.findScalar(u8, text, 0) != null) return error.InvalidRegex;
    return text;
}

fn sleep(io: Io, ms: i64) Io.Cancelable!void {
    try io.sleep(.fromMilliseconds(ms), .awake);
}

const Ending = enum { eof, reset };

const Talk = struct {
    a: Allocator,
    /// item is the 1-based item running, 0 while connecting.
    item: usize = 0,
    /// reply is what arrived since the last send.
    reply: std.ArrayList(u8) = .empty,
    /// seen is how much of reply the last expectation judged.
    seen: usize = 0,
    ending: ?Ending = null,
    outcome: Outcome = .{},

    fn fail(s: *Talk, field: []const u8) void {
        s.outcome = .{ .failed = s.item, .field = field, .received = s.reply.items };
    }
};

fn run(io: Io, s: *Talk, c: Conversation) anyerror!void {
    const stream = switch (c.target) {
        .tcp => |t| if (Io.net.IpAddress.parse(t.host, t.port)) |address|
            try address.connect(io, .{ .mode = .stream })
        else |_|
            try (try Io.net.HostName.init(t.host)).connect(io, t.port, .{ .mode = .stream }),
        .unix => |path| try (try Io.net.UnixAddress.init(path)).connect(io),
    };
    defer stream.close(io);
    var stream_reader = stream.reader(io, try s.a.alloc(u8, tls.Client.min_buffer_len));
    var stream_writer = stream.writer(io, try s.a.alloc(u8, tls.Client.min_buffer_len));
    var bundle: std.crypto.Certificate.Bundle = .empty;
    var lock: Io.RwLock = .init;
    var client: ?tls.Client = null;
    if (c.security != .plain) {
        const now = Io.Clock.real.now(io);
        if (c.security == .verify) {
            if (c.security.verify) |ca|
                try bundle.addCertsFromFilePathAbsolute(s.a, io, now, ca)
            else
                try bundle.rescan(s.a, io, now);
        }
        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        io.random(&entropy);
        const host = if (c.target == .tcp) c.target.tcp.host else return error.TlsTarget;
        client = try tls.Client.init(&stream_reader.interface, &stream_writer.interface, .{
            .host = if (c.security == .verify) .{ .explicit = host } else .no_verification,
            .ca = if (c.security == .verify) .{ .bundle = .{
                .gpa = s.a,
                .io = io,
                .lock = &lock,
                .bundle = &bundle,
            } } else .no_verification,
            .read_buffer = try s.a.alloc(u8, tls.Client.min_buffer_len + 8192),
            .write_buffer = try s.a.alloc(u8, 1024),
            .entropy = &entropy,
            .realtime_now = now,
            // A text protocol may end with the connection; close says if it must.
            .allow_truncation_attacks = true,
        });
    }
    const r: *Io.Reader = if (client) |*t| &t.reader else &stream_reader.interface;
    const w: *Io.Writer = if (client) |*t| &t.writer else &stream_writer.interface;
    const link: Link = .{
        .stream = &stream_reader,
        .writer = &stream_writer,
        .tls = client != null,
    };
    for (c.items, 1..) |item, index| {
        s.item = index;
        switch (item) {
            .send => |bytes| {
                s.reply.clearRetainingCapacity();
                s.seen = 0;
                w.writeAll(bytes) catch return link.writeError();
                w.flush() catch return link.writeError();
                if (link.tls) stream_writer.interface.flush() catch return link.writeError();
            },
            .pause_seconds => |n| try io.sleep(.fromSeconds(n), .awake),
            .expect => |e| if (!try expect(s, r, link, e)) return,
            .close => |want| if (!try close(s, r, link, want)) return,
        }
    }
}

/// Link reports the stream's own errors, which a reader or writer only
/// says failed.
const Link = struct {
    stream: *Io.net.Stream.Reader,
    writer: *Io.net.Stream.Writer,
    tls: bool,

    fn writeError(l: Link) anyerror {
        return l.writer.err orelse error.WriteFailed;
    }
};

/// receive reads once more into the reply, reporting whether the stream
/// is still open.
fn receive(s: *Talk, r: *Io.Reader, link: Link) !bool {
    if (s.ending != null) return false;
    r.fillMore() catch |err| switch (err) {
        error.EndOfStream => {
            s.ending = .eof;
            return false;
        },
        error.ReadFailed => {
            const cause = link.stream.err orelse return error.TlsReadFailed;
            if (cause != error.ConnectionResetByPeer) return cause;
            s.ending = .reset;
            return false;
        },
    };
    const got = r.buffered();
    if (s.reply.items.len + got.len > max_reply) return error.ReplyTooLong;
    try s.reply.appendSlice(s.a, got);
    r.tossBuffered();
    return true;
}

fn expect(s: *Talk, r: *Io.Reader, link: Link, e: Expect) !bool {
    // Each judgement copies the reply for the regex; keep one copy at a time.
    var scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer scratch.deinit();
    while (true) {
        _ = scratch.reset(.retain_capacity);
        switch (try judge(scratch.allocator(), e, s.reply.items)) {
            .held => {
                s.seen = s.reply.items.len;
                return true;
            },
            .broken => |field| {
                s.fail(field);
                return false;
            },
            .waiting => |field| if (!try receive(s, r, link)) {
                s.fail(field);
                return false;
            },
        }
    }
}

fn close(s: *Talk, r: *Io.Reader, link: Link, want: Close) !bool {
    while (s.reply.items.len == s.seen and try receive(s, r, link)) {}
    const ending = s.ending orelse {
        s.fail("close");
        return false;
    };
    if (s.reply.items.len > s.seen or (ending == .eof and !want.eof) or
        (ending == .reset and !want.reset))
    {
        s.fail("close");
        return false;
    }
    return true;
}

const Verdict = union(enum) { held, waiting: []const u8, broken: []const u8 };

/// judge says whether reply satisfies e, can no longer, or might with more.
fn judge(a: Allocator, e: Expect, reply: []const u8) !Verdict {
    var waiting: ?[]const u8 = null;
    if (e.prefix) |p| {
        const n = @min(p.len, reply.len);
        if (!mem.eql(u8, reply[0..n], p[0..n])) return .{ .broken = "prefix" };
        if (reply.len < p.len) waiting = "prefix";
    }
    if (e.contains) |needle| if (mem.find(u8, reply, needle) == null) {
        waiting = waiting orelse "contains";
    };
    if (e.matches) |pattern| {
        // POSIX regular expressions read text, not binary records.
        if (mem.findScalar(u8, reply, 0) != null) return .{ .broken = "matches" };
        const result = werewolf_regex_match(
            (try a.dupeSentinel(u8, pattern, 0)).ptr,
            (try a.dupeSentinel(u8, reply, 0)).ptr,
        );
        if (result < 0) return error.InvalidRegex;
        if (result == 0) waiting = waiting orelse "matches";
    }
    return if (waiting) |field| .{ .waiting = field } else .held;
}

const testing = std.testing;

test "an expectation waits for more, holds, or is broken for good" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqual(Verdict.held, try judge(a, .{ .prefix = "220 " }, "220 ready\r\n"));
    try testing.expectEqualStrings("prefix", (try judge(a, .{ .prefix = "220 " }, "22")).waiting);
    try testing.expectEqualStrings("prefix", (try judge(a, .{ .prefix = "220 " }, "530")).broken);
    const line: Expect = .{ .prefix = "250", .matches = "(^|\n)250 [^\r\n]*\r\n$" };
    try testing.expectEqualStrings("matches", (try judge(a, line, "250-x\r\n")).waiting);
    try testing.expectEqual(Verdict.held, try judge(a, line, "250-x\r\n250 ok\r\n"));
    try testing.expectEqualStrings(
        "contains",
        (try judge(a, .{ .contains = "OSP" }, "<x>")).waiting,
    );
    try testing.expectEqualStrings("matches", (try judge(a, .{ .matches = "x" }, "x\x00")).broken);
    try testing.expectError(error.InvalidRegex, judge(a, .{ .matches = "[" }, "x"));
}

/// Script is a server's side of one test conversation.
const Script = struct {
    banner: []const u8 = "",
    /// reply answers once the client's request ends with request_end.
    request_end: []const u8 = "\r\n\r\n",
    reply: []const []const u8 = &.{},
    /// pieces_ms separates the reply's pieces.
    pieces_ms: i64 = 0,
    /// hold keeps the connection open this long after replying.
    hold_ms: i64 = 0,
};

fn serve(io: Io, server: *Io.net.Server, script: Script) !void {
    const stream = try server.accept(io);
    defer stream.close(io);
    var out: [1024]u8 = undefined;
    var writer = stream.writer(io, &out);
    try writer.interface.writeAll(script.banner);
    try writer.interface.flush();
    var in: [1024]u8 = undefined;
    var reader = stream.reader(io, &in);
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(testing.allocator);
    while (!mem.endsWith(u8, request.items, script.request_end))
        try request.append(testing.allocator, try reader.interface.takeByte());
    for (script.reply) |piece| {
        try writer.interface.writeAll(piece);
        try writer.interface.flush();
        try io.sleep(.fromMilliseconds(script.pieces_ms), .awake);
    }
    try io.sleep(.fromMilliseconds(script.hold_ms), .awake);
}

fn talk(script: Script, items: []const Item, timeout_ms: i64) !Outcome {
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    var serving = try io.concurrent(serve, .{ io, &server, script });
    defer serving.cancel(io) catch {};
    var outcome = try converse(io, arena.allocator(), .{
        .target = .{ .tcp = .{ .host = "127.0.0.1", .port = server.socket.address.getPort() } },
        .items = items,
    }, timeout_ms);
    outcome.received = try testing.allocator.dupe(u8, outcome.received);
    return outcome;
}

test "a fragmented request gets the whole framed reply, then the end of stream" {
    const body = "werewolf: Ruby 3.4.7 is answering\n";
    const outcome = try talk(.{
        .reply = &.{ "HTTP/1.1 200 OK\r\nContent-Length: 34\r\n\r\n", body },
        .pieces_ms = 50,
    }, &.{
        .{ .send = "GET / HTTP/1.1\r\nHost: localhost\r\n" },
        .{ .pause_seconds = 1 },
        .{ .send = "\r\n" },
        .{ .expect = .{
            .prefix = "HTTP/1.1 200 OK\r\n",
            .matches = "^HTTP/1\\.1 200 OK\r\nContent-Length: 34\r\n\r\nwerewolf: Ruby [^ ]{5} " ++
                "is answering\n$",
        } },
        .{ .close = .{ .eof = true } },
    }, 5000);
    defer testing.allocator.free(outcome.received);
    try testing.expectEqual(0, outcome.failed);
}

test "close refuses bytes after the last expectation and a server that stays open" {
    const extra = try talk(.{
        .banner = "220 ready\r\n",
        .request_end = "\r\n",
        .reply = &.{ "221 bye\r\n", "unexpected" },
        .pieces_ms = 50,
    }, &.{
        .{ .expect = .{ .matches = "^220 [^\r\n]*\r\n$" } },
        .{ .send = "QUIT\r\n" },
        .{ .expect = .{ .matches = "^221 [^\r\n]*\r\n$" } },
        .{ .close = .{ .eof = true, .reset = true } },
    }, 5000);
    defer testing.allocator.free(extra.received);
    try testing.expectEqual(4, extra.failed);
    try testing.expectEqualStrings("close", extra.field);
    const open = try talk(.{ .request_end = "\r\n", .hold_ms = 5000 }, &.{
        .{ .send = "PING\r\n" },
        .{ .close = .{ .eof = true } },
    }, 500);
    defer testing.allocator.free(open.received);
    try testing.expectEqual(2, open.failed);
    try testing.expectEqualStrings("timeout", open.field);
}

test "an unmet expectation reports the reply it saw" {
    const refused = try talk(.{
        .banner = "220 ready\r\n",
        .request_end = "\r\n",
        .reply = &.{"250 accepted\r\n"},
    }, &.{
        .{ .expect = .{ .prefix = "220 " } },
        .{ .send = "RCPT TO:<someone@example.net>\r\n" },
        .{ .expect = .{ .prefix = "550" } },
    }, 5000);
    defer testing.allocator.free(refused.received);
    try testing.expectEqual(3, refused.failed);
    try testing.expectEqualStrings("prefix", refused.field);
    try testing.expectEqualStrings("250 accepted\r\n", refused.received);
    const closed = try talk(.{ .request_end = "\r\n" }, &.{
        .{ .send = "HELLO\r\n" },
        .{ .expect = .{ .contains = "never" } },
    }, 5000);
    defer testing.allocator.free(closed.received);
    try testing.expectEqual(2, closed.failed);
    try testing.expectEqualStrings("contains", closed.field);
}

fn answer(io: Io, server: *Io.net.Server) !void {
    const stream = try server.accept(io);
    defer stream.close(io);
    var in: [256]u8 = undefined;
    var reader = stream.reader(io, &in);
    _ = try reader.interface.takeDelimiterInclusive('>');
    var out: [256]u8 = undefined;
    var writer = stream.writer(io, &out);
    try writer.interface.writeAll("<get_version_response status=\"200\"><name>OSP</name>" ++
        "</get_version_response>");
    try writer.interface.flush();
}

test "a Unix socket carries the same conversation" {
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try a.print("{s}/s", .{try tmp.dir.realPathFileAlloc(io, ".", a)});
    const address = try Io.net.UnixAddress.init(path);
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    var answering = try io.concurrent(answer, .{ io, &server });
    defer answering.cancel(io) catch {};
    const outcome = try converse(io, a, .{ .target = .{ .unix = path }, .items = &.{
        .{ .send = "<get_version/>" },
        .{ .expect = .{
            .prefix = "<get_version_response status=\"200\"",
            .matches = "<name>OSP</name>.*</get_version_response>$",
        } },
        .{ .close = .{ .eof = true } },
    } }, 5000);
    try testing.expectEqual(0, outcome.failed);
}
