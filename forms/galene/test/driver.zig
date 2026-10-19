//! Galène protocol joins over the same verified WSS endpoint its browser uses.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Json = std.json.Value;
const Handle = *anyopaque;
const Frame = extern struct { age: c_int, flags: c_int, offset: i64, bytesleft: i64, len: usize };
const Api = struct {
    curl_easy_init: *const fn () callconv(.c) ?Handle,
    curl_easy_cleanup: *const fn (Handle) callconv(.c) void,
    curl_easy_setopt: *const fn (Handle, c_int, ...) callconv(.c) c_int,
    curl_easy_perform: *const fn (Handle) callconv(.c) c_int,
    curl_ws_send: *const fn (Handle, [*]const u8, usize, *usize, i64, c_uint) callconv(.c) c_int,
    curl_ws_recv: *const fn (Handle, [*]u8, usize, *usize, *?*const Frame) callconv(.c) c_int,
};

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
    var ws = try Socket.init();
    defer ws.deinit();
    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(30));
    try ws.send(io, try a.print(
        "{{\"type\":\"handshake\",\"version\":[\"2\"],\"id\":\"{s}\"}}",
        .{ctx.run},
    ), deadline);
    var message: Io.Writer.Allocating = .init(a);
    defer message.deinit();
    try std.json.Stringify.value(.{
        .type = "join",
        .kind = "join",
        .group = "lecture",
        .username = if (allowed) "ada" else "mallory",
        .password = password,
    }, .{}, &message.writer);
    try ws.send(io, message.writer.buffered(), deadline);
    for (0..64) |_| {
        const data = try ws.receive(io, deadline);
        const value = try std.json.parseFromSliceLeaky(Json, a, data, .{});
        if (field(value, "type", "ping")) {
            try ws.send(io, "{\"type\":\"pong\"}", deadline);
            continue;
        }
        if (!field(value, "type", "joined")) continue;
        try joined(value, allowed);
        try ctx.result(io, args[1], if (allowed) "galene-join" else "galene-join-refused", true);
        return;
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

// libcurl owns TLS, upgrade validation, masks, control frames and wire framing.
const Socket = struct {
    lib: std.DynLib,
    api: Api,
    handle: Handle,
    buffer: [16384]u8 = undefined,

    fn init() !Socket {
        var lib = try std.DynLib.open("libcurl.so.4");
        errdefer lib.close();
        var api: Api = undefined;
        inline for (@typeInfo(
            Api,
        ).@"struct".field_names, @typeInfo(Api).@"struct".field_types) |name, T|
            @field(api, name) = lib.lookup(T, name) orelse return error.CurlSymbol;
        const handle = api.curl_easy_init() orelse return error.CurlInit;
        errdefer api.curl_easy_cleanup(handle);
        try check(api.curl_easy_setopt(handle, 10002, @as([*:0]const u8, "wss://localhost/ws")));
        try check(api.curl_easy_setopt(handle, 10004, @as([*:0]const u8, ""))); // no proxy env
        try check(api.curl_easy_setopt(
            handle,
            10065,
            @as([*:0]const u8, "/data/svc/caddy/pki/authorities/local/root.crt"),
        ));
        try check(api.curl_easy_setopt(handle, 52, @as(c_long, 0))); // no redirects
        try check(api.curl_easy_setopt(handle, 99, @as(c_long, 1))); // no signals
        try check(api.curl_easy_setopt(handle, 156, @as(c_long, 10000))); // request timeout
        try check(api.curl_easy_setopt(handle, 141, @as(c_long, 2))); // CONNECT_ONLY WebSocket
        try check(api.curl_easy_perform(handle));
        return .{ .lib = lib, .api = api, .handle = handle };
    }

    fn deinit(ws: *Socket) void {
        ws.api.curl_easy_cleanup(ws.handle);
        ws.lib.close();
    }

    fn send(ws: *Socket, io: Io, message: []const u8, deadline: Io.Timestamp) !void {
        var offset: usize = 0;
        while (offset < message.len) {
            if (Io.Clock.awake.now(io).compare(.gte, deadline)) return error.WebSocketTimeout;
            var sent: usize = 0;
            const rc = ws.api.curl_ws_send(
                ws.handle,
                message[offset..].ptr,
                message.len - offset,
                &sent,
                0,
                1,
            );
            if (rc != 81) try check(rc); // CURLE_AGAIN
            if (sent > message.len - offset) return error.WebSocketLength;
            offset += sent;
            if (offset < message.len) try pause(io, deadline);
        }
    }

    fn receive(ws: *Socket, io: Io, deadline: Io.Timestamp) ![]const u8 {
        var used: usize = 0;
        while (true) {
            if (Io.Clock.awake.now(io).compare(.gte, deadline)) return error.WebSocketTimeout;
            var count: usize = 0;
            var metadata: ?*const Frame = null;
            var chunk: [4096]u8 = undefined;
            const rc = ws.api.curl_ws_recv(ws.handle, &chunk, chunk.len, &count, &metadata);
            if (rc == 81) {
                try pause(io, deadline);
                continue;
            }
            try check(rc);
            const frame = metadata orelse return error.WebSocketMetadata;
            if (frame.flags & (16 | 64) != 0) continue; // automatic ping/pong
            if (frame.flags & 1 == 0) return error.WebSocketTextExpected;
            if (count > chunk.len or count > ws.buffer.len - used) return error.WebSocketTooLarge;
            @memcpy(ws.buffer[used..][0..count], chunk[0..count]);
            used += count;
            if (frame.bytesleft == 0 and frame.flags & 4 == 0) return ws.buffer[0..used];
            if (Io.Clock.awake.now(io).compare(.gte, deadline)) return error.WebSocketTimeout;
        }
    }
};

fn check(rc: c_int) !void {
    if (rc != 0) {
        std.debug.print("test-galene: libcurl error {d}\n", .{rc});
        return error.WebSocketTransport;
    }
}

fn pause(io: Io, deadline: Io.Timestamp) !void {
    if (Io.Clock.awake.now(io).compare(.gte, deadline)) return error.WebSocketTimeout;
    try io.sleep(.fromMilliseconds(10), .awake);
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
