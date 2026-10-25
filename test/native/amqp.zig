//! AMQP 0-9-1 client and the broker checks shared by forms that include
//! rabbitmq: PLAIN login, durable queues, confirmed persistent publishes and
//! basic.get, nothing else. https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

/// The largest frame either side may send: RabbitMQ's default.
pub const frame_max = 131072;

pub const Login = struct {
    user: []const u8,
    password: []const u8,
    port: u16 = 5672,
};

const Frame = struct { kind: u8, channel: u16, payload: []const u8 };

// Method identifiers, class << 16 | method.
const connection_start = 0x000a_000a;
const connection_tune = 0x000a_001e;
const connection_open_ok = 0x000a_0029;
const connection_close = 0x000a_0032;
const connection_close_ok = 0x000a_0033;
const channel_open_ok = 0x0014_000b;
const channel_close = 0x0014_0028;
const queue_declare_ok = 0x0032_000b;
const queue_purge_ok = 0x0032_001f;
const basic_ack = 0x003c_0050;
const basic_get_ok = 0x003c_0047;
const basic_get_empty = 0x003c_0048;
const confirm_select_ok = 0x0055_000b;

// Client properties asking for connection.close on a refused login, so a
// refusal is told apart from a broker that dropped the connection.
const properties = "\x00\x00\x00\x31\x0ccapabilities" ++
    "F\x00\x00\x00\x1f\x1cauthentication_failure_close" ++ "t\x01";

pub const Client = struct {
    in: *Io.Reader,
    out: *Io.Writer,
    /// Receives one frame payload; its length is the negotiated limit.
    payload: []u8,
    published: u64 = 0,

    /// Log in, then open channel 1 in confirm mode. error.AccessRefused
    /// means the broker answered the credentials with connection.close 403.
    pub fn login(
        in: *Io.Reader,
        out: *Io.Writer,
        payload: []u8,
        user: []const u8,
        password: []const u8,
    ) !Client {
        if (payload.len < frame_max - 8) return error.FrameBuffer;
        var c: Client = .{ .in = in, .out = out, .payload = payload[0 .. frame_max - 8] };
        try out.writeAll("AMQP\x00\x00\x09\x01");
        try out.flush();
        _ = try c.expect(0, connection_start);
        var buffer: [1024]u8 = undefined;
        var m: Io.Writer = .fixed(&buffer);
        try m.writeAll("\x00\x0a\x00\x0b" ++ properties ++ "\x05PLAIN");
        try m.writeInt(u32, @intCast(user.len + password.len + 2), .big);
        try m.writeByte(0);
        try m.writeAll(user);
        try m.writeByte(0);
        try m.writeAll(password);
        try m.writeAll("\x05en_US");
        try c.send(1, 0, m.buffered());
        try out.flush();
        const tune = try c.expect(0, connection_tune);
        if (tune.len < 8) return error.ShortMethod;
        const offered = std.mem.readInt(u32, tune[2..6], .big);
        const size: u32 = if (offered == 0) frame_max else @min(offered, frame_max);
        if (size < 4096) return error.FrameSize;
        c.payload = c.payload[0 .. size - 8];
        // One channel, no heartbeats.
        var tune_ok = "\x00\x0a\x00\x1f\x00\x01\x00\x00\x00\x00\x00\x00".*;
        std.mem.writeInt(u32, tune_ok[6..10], size, .big);
        try c.send(1, 0, &tune_ok);
        _ = try c.call(0, "\x00\x0a\x00\x28\x01/\x00\x00", connection_open_ok);
        _ = try c.call(1, "\x00\x14\x00\x0a\x00", channel_open_ok);
        _ = try c.call(1, "\x00\x55\x00\x0a\x00", confirm_select_ok);
        return c;
    }

    pub fn declare(c: *Client, queue: []const u8) !void {
        var buffer: [512]u8 = undefined;
        var m: Io.Writer = .fixed(&buffer);
        try m.writeAll("\x00\x32\x00\x0a\x00\x00");
        try shortString(&m, queue);
        try m.writeAll("\x02\x00\x00\x00\x00"); // durable, no arguments
        _ = try c.call(1, m.buffered(), queue_declare_ok);
    }

    pub fn purge(c: *Client, queue: []const u8) !void {
        var buffer: [512]u8 = undefined;
        var m: Io.Writer = .fixed(&buffer);
        try m.writeAll("\x00\x32\x00\x1e\x00\x00");
        try shortString(&m, queue);
        try m.writeByte(0);
        _ = try c.call(1, m.buffered(), queue_purge_ok);
    }

    /// Publish a persistent, mandatory message to queue through the default
    /// exchange and wait for the broker's confirm: it is routed and stored.
    pub fn publish(c: *Client, queue: []const u8, body: []const u8) !void {
        if (body.len > c.payload.len) return error.BodyTooLarge;
        var buffer: [512]u8 = undefined;
        var m: Io.Writer = .fixed(&buffer);
        try m.writeAll("\x00\x3c\x00\x28\x00\x00\x00");
        try shortString(&m, queue);
        try m.writeByte(1);
        try c.send(1, 1, m.buffered());
        var header = "\x00\x3c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x02".*;
        std.mem.writeInt(u64, header[4..12], body.len, .big);
        try c.send(2, 1, &header);
        if (body.len > 0) try c.send(3, 1, body);
        try c.out.flush();
        c.published += 1;
        // An unroutable message comes back as basic.return, never as this ack.
        const ack = try c.expect(1, basic_ack);
        if (ack.len < 9 or std.mem.readInt(u64, ack[0..8], .big) != c.published)
            return error.Unconfirmed;
    }

    /// The next message on queue, or null when it is empty. Unless consumed,
    /// the broker requeues it when the channel closes.
    pub fn get(c: *Client, a: Allocator, queue: []const u8, consume: bool) !?[]u8 {
        var buffer: [512]u8 = undefined;
        var m: Io.Writer = .fixed(&buffer);
        try m.writeAll("\x00\x3c\x00\x46\x00\x00");
        try shortString(&m, queue);
        try m.writeByte(@intFromBool(consume));
        try c.send(1, 1, m.buffered());
        try c.out.flush();
        const reply = try c.method(1);
        if (reply.id == basic_get_empty) return null;
        if (reply.id != basic_get_ok) return error.UnexpectedFrame;
        const header = try c.receive();
        if (header.kind != 2 or header.channel != 1 or header.payload.len < 14 or
            !std.mem.eql(u8, header.payload[0..2], "\x00\x3c")) return error.UnexpectedFrame;
        const size = std.mem.readInt(u64, header.payload[4..12], .big);
        if (size > 1 << 20) return error.MessageTooLarge;
        const body = try a.alloc(u8, @intCast(size));
        var n: usize = 0;
        while (n < body.len) {
            const f = try c.receive();
            if (f.kind != 3 or f.channel != 1 or f.payload.len == 0 or
                f.payload.len > body.len - n) return error.UnexpectedFrame;
            @memcpy(body[n..][0..f.payload.len], f.payload);
            n += f.payload.len;
        }
        return body;
    }

    /// Close the connection; unacknowledged messages return to their queues.
    pub fn close(c: *Client) !void {
        _ = try c.call(0, "\x00\x0a\x00\x32\x00\xc8\x04done\x00\x00\x00\x00", connection_close_ok);
    }

    fn call(c: *Client, channel: u16, payload: []const u8, reply: u32) ![]const u8 {
        try c.send(1, channel, payload);
        try c.out.flush();
        return c.expect(channel, reply);
    }

    fn send(c: *Client, kind: u8, channel: u16, payload: []const u8) !void {
        try c.out.writeByte(kind);
        try c.out.writeInt(u16, channel, .big);
        try c.out.writeInt(u32, @intCast(payload.len), .big);
        try c.out.writeAll(payload);
        try c.out.writeByte(0xce);
    }

    fn receive(c: *Client) !Frame {
        var header: [7]u8 = undefined;
        try c.in.readSliceAll(&header);
        const size = std.mem.readInt(u32, header[3..7], .big);
        if (size > c.payload.len) return error.FrameTooLarge;
        try c.in.readSliceAll(c.payload[0..size]);
        if (try c.in.takeByte() != 0xce) return error.FrameEnd;
        return .{
            .kind = header[0],
            .channel = std.mem.readInt(u16, header[1..3], .big),
            .payload = c.payload[0..size],
        };
    }

    fn method(c: *Client, channel: u16) !struct { id: u32, arguments: []const u8 } {
        const f = try c.receive();
        if (f.kind != 1 or f.payload.len < 4) return error.UnexpectedFrame;
        const id = std.mem.readInt(u32, f.payload[0..4], .big);
        if (id == connection_close or id == channel_close) {
            if (f.payload.len < 6) return error.ShortMethod;
            return switch (std.mem.readInt(u16, f.payload[4..6], .big)) {
                403 => error.AccessRefused,
                else => error.BrokerClosed,
            };
        }
        if (f.channel != channel) return error.UnexpectedFrame;
        return .{ .id = id, .arguments = f.payload[4..] };
    }

    fn expect(c: *Client, channel: u16, id: u32) ![]const u8 {
        const reply = try c.method(channel);
        if (reply.id != id) return error.UnexpectedFrame;
        return reply.arguments;
    }
};

fn shortString(w: *Io.Writer, text: []const u8) !void {
    if (text.len > 255) return error.NameTooLong;
    try w.writeByte(@intCast(text.len));
    try w.writeAll(text);
}

const probe_queue = "werewolf-probe";
const kept_queue = "werewolf-retained";

const Connection = struct {
    stream: Io.net.Stream,
    reader: Io.net.Stream.Reader,
    writer: Io.net.Stream.Writer,
    client: Client,

    fn open(n: *Connection, io: Io, a: Allocator, login: Login) !*Client {
        const address: Io.net.IpAddress = .{ .ip4 = .loopback(login.port) };
        n.stream = try address.connect(io, .{ .mode = .stream });
        errdefer n.stream.close(io);
        n.reader = n.stream.reader(io, try a.alloc(u8, 4096));
        n.writer = n.stream.writer(io, try a.alloc(u8, 4096));
        n.client = try .login(
            &n.reader.interface,
            &n.writer.interface,
            try a.alloc(u8, frame_max - 8),
            login.user,
            login.password,
        );
        return &n.client;
    }
};

/// Log in and out.
pub fn ready(io: Io, a: Allocator, login: Login) !void {
    var n: Connection = undefined;
    const c = try n.open(io, a, login);
    defer n.stream.close(io);
    try c.close();
}

/// A persistent message makes the round trip, and this run's second one
/// waits on a durable queue for retained to find after a reboot.
pub fn roundTrip(io: Io, a: Allocator, login: Login, run: []const u8) !bool {
    var n: Connection = undefined;
    const c = try n.open(io, a, login);
    defer n.stream.close(io);
    const body = try a.print("werewolf-amqp-check {s}", .{run});
    try c.declare(probe_queue);
    try c.purge(probe_queue);
    try c.publish(probe_queue, body);
    const got = try c.get(a, probe_queue, true) orelse return false;
    if (!std.mem.eql(u8, got, body)) return false;
    try c.declare(kept_queue);
    try c.purge(kept_queue);
    try c.publish(kept_queue, try a.print("werewolf-kept-message {s}", .{run}));
    try c.close();
    return true;
}

/// roundTrip's retained message is still queued, and stays queued.
pub fn retained(io: Io, a: Allocator, login: Login, run: []const u8) !bool {
    var n: Connection = undefined;
    const c = try n.open(io, a, login);
    defer n.stream.close(io);
    const got = try c.get(a, kept_queue, false) orelse return false;
    try c.close();
    return std.mem.eql(u8, got, try a.print("werewolf-kept-message {s}", .{run}));
}

/// The broker answers these credentials with connection.close 403.
pub fn refused(io: Io, a: Allocator, login: Login) !bool {
    var n: Connection = undefined;
    const c = n.open(io, a, login) catch |err| {
        if (err == error.AccessRefused) return true;
        return err;
    };
    defer n.stream.close(io);
    try c.close();
    return false;
}

fn testFrame(comptime kind: u8, comptime channel: u16, comptime payload: []const u8) []const u8 {
    const bytes = comptime blk: {
        var b: [payload.len + 8]u8 = undefined;
        b[0] = kind;
        std.mem.writeInt(u16, b[1..3], channel, .big);
        std.mem.writeInt(u32, b[3..7], payload.len, .big);
        @memcpy(b[7..][0..payload.len], payload);
        b[b.len - 1] = 0xce;
        break :blk b;
    };
    return &bytes;
}

const test_start = testFrame(1, 0, "\x00\x0a\x00\x0a\x00\x09\x00\x00\x00\x00" ++
    "\x00\x00\x00\x05PLAIN\x00\x00\x00\x05en_US");
const test_tune = testFrame(1, 0, "\x00\x0a\x00\x1e\x07\xff\x00\x02\x00\x00\x00\x3c");
const test_opened = testFrame(1, 0, "\x00\x0a\x00\x29\x00") ++
    testFrame(1, 1, "\x00\x14\x00\x0b\x00\x00\x00\x00") ++
    testFrame(1, 1, "\x00\x55\x00\x0b");
const test_login = "AMQP\x00\x00\x09\x01" ++
    testFrame(1, 0, "\x00\x0a\x00\x0b" ++ properties ++
        "\x05PLAIN\x00\x00\x00\x0b\x00app\x00secret\x05en_US") ++
    testFrame(1, 0, "\x00\x0a\x00\x1f\x00\x01\x00\x02\x00\x00\x00\x00") ++
    testFrame(1, 0, "\x00\x0a\x00\x28\x01/\x00\x00") ++
    testFrame(1, 1, "\x00\x14\x00\x0a\x00") ++
    testFrame(1, 1, "\x00\x55\x00\x0a\x00");
const test_header = testFrame(2, 1, "\x00\x3c\x00\x00" ++
    "\x00\x00\x00\x00\x00\x00\x00\x05\x10\x00\x02");
const test_session = test_start ++ test_tune ++ test_opened ++
    testFrame(1, 1, "\x00\x32\x00\x0b\x01q\x00\x00\x00\x00\x00\x00\x00\x00") ++
    testFrame(1, 1, "\x00\x3c\x00\x50\x00\x00\x00\x00\x00\x00\x00\x01\x00") ++
    testFrame(1, 1, "\x00\x3c\x00\x47\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x01q" ++
        "\x00\x00\x00\x00") ++
    test_header ++ testFrame(3, 1, "he") ++ testFrame(3, 1, "llo") ++
    testFrame(1, 1, "\x00\x3c\x00\x48\x00") ++
    testFrame(1, 0, "\x00\x0a\x00\x33");
const test_published = testFrame(1, 1, "\x00\x32\x00\x0a\x00\x00\x01q\x02\x00\x00\x00\x00") ++
    testFrame(1, 1, "\x00\x3c\x00\x28\x00\x00\x00\x01q\x01") ++
    test_header ++ testFrame(3, 1, "hello");
const test_closed = testFrame(1, 1, "\x00\x3c\x00\x46\x00\x00\x01q\x00") ++
    testFrame(1, 1, "\x00\x3c\x00\x46\x00\x00\x01q\x01") ++
    testFrame(1, 0, "\x00\x0a\x00\x32\x00\xc8\x04done\x00\x00\x00\x00");
const test_refusals = [_]struct { server: []const u8, want: anyerror }{
    .{
        .server = test_start ++
            testFrame(1, 0, "\x00\x0a\x00\x32\x01\x93\x0eACCESS_REFUSED\x00\x00\x00\x00"),
        .want = error.AccessRefused,
    },
    .{ .server = test_start, .want = error.EndOfStream },
    .{ .server = test_start[0 .. test_start.len - 1] ++ "\x00", .want = error.FrameEnd },
    .{ .server = "\x01\x00\x00\x00\x02\x00\x00", .want = error.FrameTooLarge },
    .{
        .server = test_start ++
            testFrame(1, 0, "\x00\x0a\x00\x1e\x00\x00\x00\x00\x08\x00\x00\x00"),
        .want = error.FrameSize,
    },
    .{ .server = test_tune, .want = error.UnexpectedFrame },
};
const test_rejected = test_start ++ test_tune ++ test_opened ++
    testFrame(1, 1, "\x00\x3c\x00\x50\x00\x00\x00\x00\x00\x00\x00\x07\x00") ++
    testFrame(1, 1, "\x00\x14\x00\x28\x01\x94\x00\x00\x3c\x00\x46");

test "client properties are one well-formed field table" {
    const t = std.testing;
    try t.expectEqual(properties.len - 4, std.mem.readInt(u32, properties[0..4], .big));
    const inner = properties[4 + 1 + "capabilities".len + 1 ..];
    try t.expectEqual(inner.len - 4, std.mem.readInt(u32, inner[0..4], .big));
}

test "login negotiates frames, then a confirmed publish, get and close" {
    const t = std.testing;
    var in: Io.Reader = .fixed(test_session);
    var sent: [4096]u8 = undefined;
    var out: Io.Writer = .fixed(&sent);
    const payload = try t.allocator.alloc(u8, frame_max - 8);
    defer t.allocator.free(payload);
    var c: Client = try .login(&in, &out, payload, "app", "secret");
    try t.expectEqual(@as(usize, 0x20000 - 8), c.payload.len);
    try t.expectEqualSlices(u8, test_login, out.buffered());
    out.end = 0;
    try c.declare("q");
    try c.publish("q", "hello");
    try t.expectEqualSlices(u8, test_published, out.buffered());
    out.end = 0;
    const body = (try c.get(t.allocator, "q", false)).?;
    defer t.allocator.free(body);
    try t.expectEqualStrings("hello", body);
    try t.expectEqual(null, try c.get(t.allocator, "q", true));
    try c.close();
    try t.expectEqualSlices(u8, test_closed, out.buffered());
}

test "refusals, wrong confirms and malformed frames are errors" {
    const t = std.testing;
    const payload = try t.allocator.alloc(u8, frame_max - 8);
    defer t.allocator.free(payload);
    var sent: [4096]u8 = undefined;
    for (test_refusals) |case| {
        var in: Io.Reader = .fixed(case.server);
        var out: Io.Writer = .fixed(&sent);
        try t.expectError(case.want, Client.login(&in, &out, payload, "guest", "guest"));
    }
    var in: Io.Reader = .fixed(test_rejected);
    var out: Io.Writer = .fixed(&sent);
    var c: Client = try .login(&in, &out, payload, "app", "secret");
    try t.expectError(error.Unconfirmed, c.publish("q", "x"));
    try t.expectError(error.BrokerClosed, c.get(t.allocator, "missing", false));
}
