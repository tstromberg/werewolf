//! Galène protocol joins over the same verified WSS endpoint its browser uses.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Json = std.json.Value;
const tls = std.crypto.tls;

const ca = "/data/svc/caddy/pki/authorities/local/root.crt";
const max_message = 1 << 20;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    if (std.mem.eql(u8, args[2], "media")) {
        const uid = try driver.system.account(io, a, "galene");
        const wanted = try a.print("listen {d} udp 10000", .{uid});
        const policy = try driver.system.read(io, a, "/usr/share/werewolf/net");
        var lines = std.mem.splitScalar(u8, policy, '\n');
        var found = false;
        while (lines.next()) |line| {
            if (std.mem.eql(u8, line, wanted)) found = true;
        }
        if (!found) return error.MediaPolicy;
        const sockets = try driver.system.listeners(io, a, "udp");
        found = false;
        for (sockets.array.items) |socket| {
            if (socket.object.get("port").?.integer == 10000) found = true;
        }
        if (!found) return error.MediaListener;
        try ctx.result(io, args[1], "galene-udp", true);
        return;
    }
    const allowed = std.mem.eql(u8, args[2], "join");
    if (!allowed and !std.mem.eql(u8, args[2], "refused")) return error.Usage;
    const password = if (allowed)
        try driver.system.read(io, a, "/run/config/galene/operator-password")
    else
        "guess";
    try driver.within(io, 30, join, .{ io, a, ctx.run, allowed, password });
    try ctx.result(io, args[1], if (allowed) "galene-join" else "galene-join-refused", true);
}

/// join connects to https://localhost/ws, verified by Caddy's local CA, and
/// asks to join the lecture group as ada or mallory.
fn join(io: Io, a: Allocator, run: []const u8, allowed: bool, password: []const u8) !void {
    const address = try Io.net.IpAddress.parse("127.0.0.1", 443);
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var stream_reader = stream.reader(io, try a.alloc(u8, tls.Client.min_buffer_len));
    var stream_writer = stream.writer(io, try a.alloc(u8, tls.Client.min_buffer_len));
    const now = Io.Clock.real.now(io);
    var bundle: std.crypto.Certificate.Bundle = .empty;
    try bundle.addCertsFromFilePathAbsolute(a, io, now, ca);
    var lock: Io.RwLock = .init;
    var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    var client = try tls.Client.init(&stream_reader.interface, &stream_writer.interface, .{
        .host = .{ .explicit = "localhost" },
        .ca = .{ .bundle = .{ .gpa = a, .io = io, .lock = &lock, .bundle = &bundle } },
        .read_buffer = try a.alloc(u8, tls.Client.min_buffer_len + 8192),
        .write_buffer = try a.alloc(u8, tls.Client.min_buffer_len),
        .entropy = &entropy,
        .realtime_now = now,
    });
    const ws: Socket = .{
        .io = io,
        .r = &client.reader,
        .w = &client.writer,
        .raw = &stream_writer.interface,
    };
    try ws.open();
    try ws.send(.text, try a.print(
        "{{\"type\":\"handshake\",\"version\":[\"2\"],\"id\":\"{s}\"}}",
        .{run},
    ));
    var message: Io.Writer.Allocating = .init(a);
    defer message.deinit();
    try std.json.Stringify.value(.{
        .type = "join",
        .kind = "join",
        .group = "lecture",
        .username = if (allowed) "ada" else "mallory",
        .password = password,
    }, .{}, &message.writer);
    try ws.send(.text, message.writer.buffered());
    for (0..64) |_| {
        const value = try std.json.parseFromSliceLeaky(Json, a, try ws.receive(a), .{});
        if (field(value, "type", "ping")) {
            try ws.send(.text, "{\"type\":\"pong\"}");
            continue;
        }
        if (field(value, "type", "joined")) return joined(value, allowed);
    }
    return error.JoinNotObserved;
}

fn field(value: Json, name: []const u8, expected: []const u8) bool {
    if (value != .object) return false;
    const got = value.object.get(name) orelse return false;
    return got == .string and std.mem.eql(u8, got.string, expected);
}

fn joined(value: Json, allowed: bool) !void {
    if (!field(value, "type", "joined") or !field(value, "group", "lecture"))
        return error.WrongGroup;
    if (!field(value, "kind", if (allowed) "join" else "fail")) return error.JoinDecision;
    if (allowed) {
        if (!field(value, "username", "ada")) return error.JoinIdentity;
        const permissions = value.object.get("permissions") orelse return error.OperatorMissing;
        if (permissions != .array) return error.OperatorMissing;
        for (permissions.array.items) |permission| {
            if (permission == .string and std.mem.eql(u8, permission.string, "op")) return;
        }
        return error.OperatorMissing;
    }
    if (!field(value, "value", "not authorised")) return error.WrongRefusal;
}

/// Socket is the client side of a WebSocket (RFC 6455): it masks every frame
/// it sends, answers pings, and takes only text, which may come in fragments.
const Socket = struct {
    io: Io,
    r: *Io.Reader,
    w: *Io.Writer,
    /// raw is the stream's own writer, flushed after w's when TLS sits between.
    raw: ?*Io.Writer = null,

    const Opcode = enum(u4) { continuation = 0, text = 1, close = 8, ping = 9, pong = 10, _ };

    /// open upgrades the connection with GET /ws and checks the server's
    /// Sec-WebSocket-Accept.
    fn open(ws: Socket) !void {
        var nonce: [16]u8 = undefined;
        ws.io.random(&nonce);
        var key: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key, &nonce);
        try ws.w.print("GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n" ++
            "Connection: Upgrade\r\nSec-WebSocket-Key: {s}\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n", .{&key});
        try ws.flush();
        const status = try ws.r.takeDelimiterInclusive('\n');
        if (!std.mem.startsWith(u8, status, "HTTP/1.1 101 ")) {
            std.debug.print("test-galene: upgrade answered {s}", .{status});
            return error.WebSocketUpgrade;
        }
        const want = accept(&key);
        var accepted = false;
        while (true) {
            const line = std.mem.trimEnd(u8, try ws.r.takeDelimiterInclusive('\n'), "\r\n");
            if (line.len == 0) break;
            const colon = std.mem.findScalar(u8, line, ':') orelse return error.WebSocketHeader;
            if (std.ascii.eqlIgnoreCase(line[0..colon], "sec-websocket-accept"))
                accepted = std.mem.eql(u8, std.mem.trim(u8, line[colon + 1 ..], " \t"), &want);
        }
        if (!accepted) return error.WebSocketAccept;
    }

    fn send(ws: Socket, opcode: Opcode, payload: []const u8) !void {
        try ws.w.writeByte(0x80 | @as(u8, @backingInt(opcode)));
        if (payload.len < 126) {
            try ws.w.writeByte(0x80 | @as(u8, @intCast(payload.len)));
        } else if (payload.len <= std.math.maxInt(u16)) {
            try ws.w.writeByte(0x80 | 126);
            try ws.w.writeInt(u16, @intCast(payload.len), .big);
        } else {
            try ws.w.writeByte(0x80 | 127);
            try ws.w.writeInt(u64, payload.len, .big);
        }
        var mask: [4]u8 = undefined;
        ws.io.random(&mask);
        try ws.w.writeAll(&mask);
        for (payload, 0..) |b, i| try ws.w.writeByte(b ^ mask[i % 4]);
        try ws.flush();
    }

    /// receive returns the next text message.
    fn receive(ws: Socket, a: Allocator) ![]const u8 {
        var message: std.ArrayList(u8) = .empty;
        var started = false;
        while (true) {
            const head = try ws.r.takeArray(2);
            const fin = head[0] & 0x80 != 0;
            const opcode: Opcode = @fromBackingInt(@intCast(@as(u4, @truncate(head[0]))));
            // No extensions were offered, and a server never masks.
            if (head[0] & 0x70 != 0 or head[1] & 0x80 != 0) return error.WebSocketFrame;
            const len: u64 = switch (head[1] & 0x7f) {
                126 => try ws.r.takeInt(u16, .big),
                127 => try ws.r.takeInt(u64, .big),
                else => |n| n,
            };
            if (@backingInt(opcode) >= 8 and (!fin or len > 125)) return error.WebSocketFrame;
            if (len > max_message - message.items.len) return error.WebSocketTooLarge;
            const payload = try a.alloc(u8, @intCast(len));
            try ws.r.readSliceAll(payload);
            switch (opcode) {
                .ping => try ws.send(.pong, payload),
                .pong => {},
                .close => return error.WebSocketClosed,
                .text, .continuation => {
                    if ((opcode == .text) == started) return error.WebSocketFrame;
                    started = true;
                    try message.appendSlice(a, payload);
                    if (fin) return message.items;
                },
                else => return error.WebSocketTextExpected,
            }
        }
    }

    fn flush(ws: Socket) !void {
        try ws.w.flush();
        if (ws.raw) |raw| try raw.flush();
    }
};

/// accept is the Sec-WebSocket-Accept a server must answer key with.
fn accept(key: []const u8) [28]u8 {
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(key);
    sha.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    var out: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &sha.finalResult());
    return out;
}

test "accept matches RFC 6455's example" {
    try std.testing.expectEqualStrings(
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        &accept("dGhlIHNhbXBsZSBub25jZQ=="),
    );
}

test "receive answers a ping and joins a fragmented text message" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var r: Io.Reader = .fixed("\x89\x02hi" ++ "\x01\x03{\"a" ++ "\x80\x05\":1}." ++ "\x82\x00");
    var out: [64]u8 = undefined;
    var w: Io.Writer = .fixed(&out);
    const ws: Socket = .{ .io = std.testing.io, .r = &r, .w = &w };
    try std.testing.expectEqualStrings("{\"a\":1}.", try ws.receive(arena.allocator()));
    const pong = w.buffered();
    try std.testing.expectEqual(@as(usize, 2 + 4 + 2), pong.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x8a, 0x82 }, pong[0..2]);
    for (pong[6..], "hi", 0..) |b, want, i| try std.testing.expectEqual(want, b ^ pong[2 + i % 4]);
    try std.testing.expectError(error.WebSocketTextExpected, ws.receive(arena.allocator()));
}

test "receive refuses masked, oversized-control and stray continuation frames" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var out: [64]u8 = undefined;
    for ([_][]const u8{ "\x81\x80\x00\x00\x00\x00", "\x09\x00", "\x80\x00", "\xc1\x00" }) |frames| {
        var r: Io.Reader = .fixed(frames);
        var w: Io.Writer = .fixed(&out);
        const ws: Socket = .{ .io = std.testing.io, .r = &r, .w = &w };
        try std.testing.expectError(error.WebSocketFrame, ws.receive(arena.allocator()));
    }
}

test "join proves the requested group, operator identity and exact refusal" {
    const a = std.testing.allocator;
    const good = try std.json.parseFromSlice(Json, a, "{\"type\":\"joined\",\"kind\":\"join\",\"" ++
        "group\":\"lecture\",\"username\":\"ada\",\"per" ++
        "missions\":[\"op\"]}", .{});
    defer good.deinit();
    try joined(good.value, true);
    try std.testing.expectError(error.JoinDecision, joined(good.value, false));
    const wrong = try std.json.parseFromSlice(Json, a, "{\"type\":\"joined\",\"kind\":\"fail\"," ++
        "\"group\":\"seminar\",\"value\":\"not " ++
        "authorised\"}", .{});
    defer wrong.deinit();
    try std.testing.expectError(error.WrongGroup, joined(wrong.value, false));
}
