//! D-Bus client for the adapter checks: EXTERNAL authentication and
//! little-endian method calls with string arguments.
//! https://dbus.freedesktop.org/doc/dbus-specification.html
const std = @import("std");
const unix = @import("unix.zig");
const linux = std.os.linux;

const socket_path = "/data/share/unifi/bus/system_bus_socket";
const bus = "org.freedesktop.DBus";
const systemd = "org.freedesktop.systemd1";
const manager = systemd ++ ".Manager";
const root = "/org/freedesktop/systemd1";
const unit = root ++ "/unit/unifi_2eservice";
const properties = bus ++ ".Properties";
const limit = 32768;

pub const Reply = struct {
    kind: u8,
    reply_serial: ?u32 = null,
    sender: []const u8 = "",
    error_name: []const u8 = "",
    body: []const u8,
};

const Writer = struct {
    bytes: []u8,
    len: usize = 0,

    fn append(w: *Writer, s: []const u8) !void {
        if (s.len > w.bytes.len - w.len) return error.MessageTooLarge;
        @memcpy(w.bytes[w.len..][0..s.len], s);
        w.len += s.len;
    }

    fn pad(w: *Writer, n: usize) !void {
        const zeros: [8]u8 = @splat(0);
        try w.append(zeros[0 .. std.mem.alignForward(usize, w.len, n) - w.len]);
    }

    fn uint(w: *Writer, n: u32) !void {
        try w.pad(4);
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, n, .little);
        try w.append(&bytes);
    }

    fn string(w: *Writer, s: []const u8, short: bool) !void {
        if (short) {
            if (s.len > 255) return error.MessageTooLarge;
            try w.append(&.{@intCast(s.len)});
        } else try w.uint(@intCast(s.len));
        try w.append(s);
        try w.append(&.{0});
    }

    fn field(w: *Writer, code: u8, kind: u8, value: []const u8) !void {
        try w.pad(8);
        try w.append(&.{ code, 1, kind, 0 });
        try w.string(value, kind == 'g');
    }
};

/// Encode a method call whose arguments, if any, are strings typed by signature.
pub fn encode(
    buffer: []u8,
    serial: u32,
    destination: []const u8,
    path: []const u8,
    interface: []const u8,
    member: []const u8,
    signature: []const u8,
    args: []const []const u8,
) ![]const u8 {
    var w: Writer = .{ .bytes = buffer };
    try w.append("l\x01\x00\x01\x00\x00\x00\x00");
    try w.uint(serial);
    try w.uint(0);
    try w.field(1, 'o', path);
    try w.field(2, 's', interface);
    try w.field(3, 's', member);
    try w.field(6, 's', destination);
    if (signature.len > 0) try w.field(8, 'g', signature);
    std.mem.writeInt(u32, buffer[12..16], @intCast(w.len - 16), .little);
    try w.pad(8);
    const body = w.len;
    for (args) |arg| try w.string(arg, false);
    std.mem.writeInt(u32, buffer[4..8], @intCast(w.len - body), .little);
    return buffer[0..w.len];
}

/// The size of the message whose fixed header is head.
pub fn length(head: *const [16]u8) !usize {
    if (head[0] != 'l' or head[3] != 1) return error.BadMessage;
    const body = std.mem.readInt(u32, head[4..8], .little);
    const fields = std.mem.readInt(u32, head[12..16], .little);
    if (body >= limit or fields >= limit) return error.MessageTooLarge;
    return 16 + std.mem.alignForward(usize, fields, 8) + body;
}

pub const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(c: *Cursor, n: usize) ![]const u8 {
        if (n > c.bytes.len - c.pos) return error.BadMessage;
        defer c.pos += n;
        return c.bytes[c.pos..][0..n];
    }

    fn skip(c: *Cursor, n: usize) !void {
        _ = try c.take(std.mem.alignForward(usize, c.pos, n) - c.pos);
    }

    fn uint(c: *Cursor) !u32 {
        try c.skip(4);
        return std.mem.readInt(u32, (try c.take(4))[0..4], .little);
    }

    /// A string, or a signature when short.
    pub fn string(c: *Cursor, short: bool) ![]const u8 {
        const n: usize = if (short) (try c.take(1))[0] else try c.uint();
        const s = try c.take(n);
        if ((try c.take(1))[0] != 0) return error.BadMessage;
        return s;
    }
};

/// Parse one whole message, as length measured it.
pub fn parse(message: []const u8) !Reply {
    if (message.len < 16 or try length(message[0..16]) != message.len) return error.BadMessage;
    const end = 16 + std.mem.readInt(u32, message[12..16], .little);
    var reply: Reply = .{
        .kind = message[1],
        .body = message[std.mem.alignForward(usize, end, 8)..],
    };
    var c: Cursor = .{ .bytes = message[0..end], .pos = 16 };
    var seen: u256 = 0;
    while (c.pos < end) {
        try c.skip(8);
        const code = (try c.take(1))[0];
        if (seen & @as(u256, 1) << code != 0) return error.BadMessage;
        seen |= @as(u256, 1) << code;
        const kind = try c.string(true);
        if (kind.len != 1) return error.BadMessage;
        switch (kind[0]) {
            'u' => {
                const value = try c.uint();
                if (code == 5) reply.reply_serial = value;
            },
            's', 'o', 'g' => {
                const value = try c.string(kind[0] == 'g');
                switch (code) {
                    4 => reply.error_name = value,
                    7 => reply.sender = value,
                    else => {},
                }
            },
            else => return error.BadMessage,
        }
    }
    return reply;
}

/// An authenticated connection that has said Hello.
pub const Session = struct {
    fd: i32,
    serial: u32 = 1,
    out: [1024]u8 = undefined,
    in: [16 + 2 * limit]u8 = undefined,

    /// Authenticate as uid, the account fd connected as, and say Hello.
    pub fn open(s: *Session, fd: i32, uid: u32) !void {
        s.* = .{ .fd = fd };
        var line: [128]u8 = undefined;
        const answer = try authenticate(fd, uid, &line);
        if (!std.mem.startsWith(u8, answer, "OK ")) return error.Rejected;
        try unix.send(fd, "BEGIN\r\n");
        if ((try s.call(bus, "/org/freedesktop/DBus", bus, "Hello", "", &.{})).kind != 2)
            return error.Hello;
    }

    /// Send a call and return its reply, which must answer it and come
    /// from the bus or the adapter's unique name.
    pub fn call(
        s: *Session,
        destination: []const u8,
        path: []const u8,
        interface: []const u8,
        member: []const u8,
        signature: []const u8,
        args: []const []const u8,
    ) !Reply {
        const serial = s.serial;
        s.serial += 1;
        const out = s.out[0..];
        try unix.send(
            s.fd,
            try encode(out, serial, destination, path, interface, member, signature, args),
        );
        try read(s.fd, s.in[0..16]);
        const n = try length(s.in[0..16]);
        try read(s.fd, s.in[16..n]);
        const reply = try parse(s.in[0..n]);
        if (reply.reply_serial != serial) return error.WrongReply;
        if (!std.mem.eql(u8, reply.sender, bus) and !std.mem.eql(u8, reply.sender, ":1.0"))
            return error.WrongSender;
        return reply;
    }
};

fn read(fd: i32, buffer: []u8) !void {
    var n: usize = 0;
    while (n < buffer.len) {
        const got = try unix.receive(fd, buffer[n..], 5000);
        if (got == 0) return error.EndOfStream;
        n += got;
    }
}

/// The NUL byte and an EXTERNAL claim to be uid: hex of its decimal digits.
fn claim(buffer: *[64]u8, uid: u32) []const u8 {
    var decimal: [10]u8 = undefined;
    const id = std.mem.print(&decimal, "{d}", .{uid}) catch unreachable;
    return std.mem.print(buffer, "\x00AUTH EXTERNAL {x}\r\n", .{id}) catch unreachable;
}

/// Claim to be uid; return the server's answer line.
fn authenticate(fd: i32, uid: u32, line: *[128]u8) ![]const u8 {
    var request: [64]u8 = undefined;
    try unix.send(fd, claim(&request, uid));
    var n: usize = 0;
    while (n == 0 or line[n - 1] != '\n') {
        if (n == line.len) return error.LongLine;
        const got = try unix.receive(fd, line[n..][0..1], 5000);
        if (got == 0) return error.EndOfStream;
        n += got;
    }
    return line[0..n];
}

/// Core reads unifi.service's state; StatusText claims no readiness.
pub fn serviceState(s: *Session) !bool {
    const load = try s.call(systemd, root, manager, "LoadUnit", "s", &.{"unifi.service"});
    if (load.kind != 2) return false;
    var body: Cursor = .{ .bytes = load.body };
    if (!std.mem.eql(u8, try body.string(false), unit)) return false;
    const active = try s.call(systemd, unit, properties, "Get", "ss", &.{
        systemd ++ ".Unit", "ActiveState",
    });
    if (active.kind != 2) return false;
    body = .{ .bytes = active.body };
    if (!std.mem.eql(u8, try body.string(true), "s")) return false;
    const state = try body.string(false);
    var known = false;
    for ([_][]const u8{ "active", "activating", "deactivating", "inactive" }) |name|
        known = known or std.mem.eql(u8, state, name);
    if (!known) return false;
    const status = try s.call(systemd, unit, properties, "Get", "ss", &.{
        systemd ++ ".Service", "StatusText",
    });
    if (status.kind != 2) return false;
    body = .{ .bytes = status.body };
    return std.mem.eql(u8, try body.string(true), "s") and (try body.string(false)).len == 0;
}

/// Core may not restart a unit.
pub fn noControl(s: *Session) !bool {
    const reply = try s.call(systemd, root, manager, "RestartUnit", "ss", &.{
        "unifi.service", "replace",
    });
    return reply.kind == 3 and std.mem.eql(u8, reply.error_name, bus ++ ".Error.AccessDenied");
}

/// Units outside the adapter's fixed table do not exist.
pub fn noOtherUnits(s: *Session) !bool {
    const reply = try s.call(systemd, root, manager, "LoadUnit", "s", &.{"sshd.service"});
    return reply.kind == 3 and std.mem.eql(u8, reply.error_name, systemd ++ ".NoSuchUnit");
}

/// Run check on a session Core opened.
pub fn asCore(core: unix.Identity, comptime check: anytype) !bool {
    const fd = try unix.connect(core, socket_path, linux.SOCK.STREAM);
    defer _ = linux.close(fd);
    var s: Session = undefined;
    try s.open(fd, core.uid);
    return check(&s);
}

/// Core's own kernel credentials cannot claim another UID.
pub fn badClaim(core: unix.Identity) !bool {
    const fd = try unix.connect(core, socket_path, linux.SOCK.STREAM);
    defer _ = linux.close(fd);
    var line: [128]u8 = undefined;
    return std.mem.eql(u8, try authenticate(fd, 0, &line), "REJECTED EXTERNAL\r\n");
}

/// A peer whose kernel UID is not Core's is disconnected unanswered, even
/// claiming Core's UID. Root passes the socket's DAC, so only the adapter's
/// SO_PEERCRED check can refuse it.
pub fn wrongPeer(core: unix.Identity) !bool {
    const fd = try unix.connect(null, socket_path, linux.SOCK.STREAM);
    defer _ = linux.close(fd);
    var line: [128]u8 = undefined;
    _ = authenticate(fd, core.uid, &line) catch |err| return switch (err) {
        error.EndOfStream, error.ConnectionResetByPeer => true,
        else => err,
    };
    return false;
}

const test_hello =
    "l\x01\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00m\x00\x00\x00\x01\x01o\x00\x15\x00\x00" ++
    "\x00/org/freedesktop/DBus\x00\x00\x00\x02\x01s\x00\x14\x00\x00\x00org.freedesktop.DB" ++
    "us\x00\x00\x00\x00\x03\x01s\x00\x05\x00\x00\x00Hello\x00\x00\x00\x06\x01s\x00\x14" ++
    "\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00";
const test_get =
    "l\x01\x00\x014\x00\x00\x00\x03\x00\x00\x00\xa0\x00\x00\x00\x01\x01o\x00.\x00\x00\x00" ++
    "/org/freedesktop/systemd1/unit/unifi_2eservice\x00\x00\x02\x01s\x00\x1f\x00\x00\x00o" ++
    "rg.freedesktop.DBus.Properties\x00\x03\x01s\x00\x03\x00\x00\x00Get\x00\x00\x00\x00" ++
    "\x00\x06\x01s\x00\x18\x00\x00\x00org.freedesktop.systemd1\x00\x00\x00\x00\x00\x00" ++
    "\x00\x00\x08\x01g\x00\x02ss\x00\x1d\x00\x00\x00org.freedesktop.systemd1.Unit\x00\x00" ++
    "\x00\x0b\x00\x00\x00ActiveState\x00";
const test_active =
    "l\x02\x00\x01\x0f\x00\x00\x00\x03\x00\x00\x00/\x00\x00\x00\x05\x01u\x00\x03\x00\x00" ++
    "\x00\x06\x01s\x00\x04\x00\x00\x00:1.1\x00\x00\x00\x00\x07\x01s\x00\x04\x00\x00\x00:1" ++
    ".0\x00\x00\x00\x00\x08\x01g\x00\x01v\x00\x00\x01s\x00\x00\x06\x00\x00\x00active\x00";
const test_denied =
    "l\x03\x00\x01,\x00\x00\x00\x04\x00\x00\x00`\x00\x00\x00\x05\x01u\x00\x04\x00\x00\x00" ++
    "\x06\x01s\x00\x04\x00\x00\x00:1.1\x00\x00\x00\x00\x07\x01s\x00\x04\x00\x00\x00:1.0" ++
    "\x00\x00\x00\x00\x08\x01g\x00\x01s\x00\x00\x04\x01s\x00'\x00\x00\x00org.freedesktop." ++
    "DBus.Error.AccessDenied\x00'\x00\x00\x00org.freedesktop.DBus.Error.AccessDenied\x00";

test "calls marshal like the retired Python client" {
    var buffer: [1024]u8 = undefined;
    try std.testing.expectEqualSlices(u8, test_hello, try encode(
        &buffer,
        1,
        bus,
        "/org/freedesktop/DBus",
        bus,
        "Hello",
        "",
        &.{},
    ));
    try std.testing.expectEqualSlices(u8, test_get, try encode(
        &buffer,
        3,
        systemd,
        unit,
        properties,
        "Get",
        "ss",
        &.{ systemd ++ ".Unit", "ActiveState" },
    ));
    try std.testing.expectError(error.MessageTooLarge, encode(
        buffer[0..64],
        1,
        bus,
        "/org/freedesktop/DBus",
        bus,
        "Hello",
        "",
        &.{},
    ));
}

test "EXTERNAL claims hex-encode the decimal UID" {
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings("\x00AUTH EXTERNAL 30\r\n", claim(&buffer, 0));
    try std.testing.expectEqualStrings(
        "\x00AUTH EXTERNAL 34323934393637323935\r\n",
        claim(&buffer, std.math.maxInt(u32)),
    );
}

test "replies yield serial, sender, error name and a variant body" {
    try std.testing.expectEqual(test_active.len, try length(test_active[0..16]));
    const reply = try parse(test_active);
    try std.testing.expectEqual(@as(u8, 2), reply.kind);
    try std.testing.expectEqual(@as(?u32, 3), reply.reply_serial);
    try std.testing.expectEqualStrings(":1.0", reply.sender);
    var body: Cursor = .{ .bytes = reply.body };
    try std.testing.expectEqualStrings("s", try body.string(true));
    try std.testing.expectEqualStrings("active", try body.string(false));
    try std.testing.expectError(error.BadMessage, body.string(false));
    const failure = try parse(test_denied);
    try std.testing.expectEqual(@as(u8, 3), failure.kind);
    try std.testing.expectEqualStrings(bus ++ ".Error.AccessDenied", failure.error_name);
}

test "replies refuse other byte orders, oversized, truncated and repeated fields" {
    var big = test_active.*;
    big[0] = 'B';
    try std.testing.expectError(error.BadMessage, length(big[0..16]));
    var huge = test_active.*;
    std.mem.writeInt(u32, huge[4..8], limit, .little);
    try std.testing.expectError(error.MessageTooLarge, length(huge[0..16]));
    for (16..test_active.len) |n|
        try std.testing.expectError(error.BadMessage, parse(test_active[0..n]));
    var repeated = test_active.*;
    repeated[24] = 5; // the destination field becomes a second reply serial
    try std.testing.expectError(error.BadMessage, parse(&repeated));
}
