//! Read-only systemd D-Bus vocabulary backed by runit's actual state.
//! This is neither a system bus nor a service-control interface.
const std = @import("std");
const wire = @import("wire.zig");
const linux = std.os.linux;
const Io = std.Io;
const mem = std.mem;
const bus = "org.freedesktop.DBus";
const manager = "org.freedesktop.systemd1.Manager";
const systemd = "org.freedesktop.systemd1";
const unit_interface = "org.freedesktop.systemd1.Unit";
const service_interface = "org.freedesktop.systemd1.Service";
const properties = "org.freedesktop.DBus.Properties";
const root = "/org/freedesktop/systemd1";
const owner = ":1.0";
const socket_path = "/data/share/unifi/bus/system_bus_socket";
const max_clients = 8;

const Unit = struct {
    name: []const u8,
    path: []const u8,
    status: ?[]const u8,
};

// Absent, bundled applications are explicitly inactive. They are not
// reported as running and cannot be enabled through this endpoint.
const units = [_]Unit{
    .{
        .name = "unifi.service",
        .path = root ++ "/unit/unifi_2eservice",
        .status = "/run/runit/supervise.unifi-network/status",
    },
    .{
        .name = "unifi-core.service",
        .path = root ++ "/unit/unifi_2dcore_2eservice",
        .status = "/run/runit/supervise.unifi-core/status",
    },
    .{ .name = "ulp-go.service", .path = root ++ "/unit/ulp_2dgo_2eservice", .status = null },
    .{ .name = "uos-agent.service", .path = root ++ "/unit/uos_2dagent_2eservice", .status = null },
};

const Activity = enum { active, inactive, activating, deactivating, failed };

fn stateOf(raw: []const u8) Activity {
    if (raw.len != 20) return .failed;
    const pid = mem.readInt(u32, raw[12..16], .little);
    return switch (raw[19]) {
        0 => if (raw[17] == 'd') .inactive else .activating,
        1 => if (pid != 0 and raw[16] == 0 and raw[18] == 0) .active else .deactivating,
        2 => .deactivating,
        else => .failed,
    };
}

fn state(io: Io, unit: Unit) Activity {
    const path = unit.status orelse return .inactive;
    var f = Io.Dir.cwd().openFile(io, path, .{}) catch return .failed;
    defer f.close(io);
    var raw: [21]u8 = undefined;
    const n = f.readPositionalAll(io, &raw, 0) catch return .failed;
    return stateOf(raw[0..n]);
}

fn unitByName(name: []const u8) ?usize {
    for (units, 0..) |u, i| if (mem.eql(u8, u.name, name)) return i;
    return null;
}

fn unitByPath(path: []const u8) ?usize {
    for (units, 0..) |u, i| if (mem.eql(u8, u.path, path)) return i;
    return null;
}

const manager_xml =
    "<node><interface name='org.freedesktop.systemd1.Manager'>" ++
    "<method name='Subscribe'/><method name='Unsubscribe'/>" ++
    "<method name='LoadUnit'><arg type='s' direction='in'/><arg type='o' " ++
    "direction='out'/></method>" ++
    "<signal name='UnitFilesChanged'/></interface></node>";
const unit_xml =
    "<node><interface name='org.freedesktop.DBus.Properties'>" ++
    "<method name='Get'><arg type='s' direction='in'/><arg type='s' direction='in'/><arg " ++
    "type='v' direction='out'/></method>" ++
    "<signal name='PropertiesChanged'><arg type='s'/><arg type='a{sv}'/><arg " ++
    "type='as'/></signal>" ++
    "</interface><interface name='org.freedesktop.systemd1.Unit'>" ++
    "<property name='ActiveState' type='s' access='read'/></interface>" ++
    "<interface name='org.freedesktop.systemd1.Service'>" ++
    "<property name='StatusText' type='s' access='read'/></interface></node>";

const Reply = struct {
    signature: []const u8 = "",
    body: wire.Buffer = .{},
    err: ?[]const u8 = null,

    fn string(r: *Reply, sig: []const u8, value: []const u8) !void {
        r.signature = sig;
        if (mem.eql(u8, sig, "v")) try r.body.string("s", true);
        try r.body.string(value, false);
    }

    fn fail(r: *Reply, name: []const u8) !void {
        r.err = name;
        try r.string("s", name);
    }
};

const Match = enum { unit_files, name_owner, unifi, core, users, agent };

fn matchRule(raw: []const u8) ?Match {
    const head = "type='signal',sender='";
    if (mem.eql(
        u8,
        raw,
        head ++ systemd ++ "',interface='" ++ manager ++ "',path='" ++ root ++
            "',member='UnitFilesChanged'",
    ))
        return .unit_files;
    if (mem.eql(
        u8,
        raw,
        "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus'," ++
            "path='/org/freedesktop/DBus',member='NameOwnerChanged'",
    ))
        return .name_owner;
    inline for (units, 0..) |u, i| {
        if (mem.eql(
            u8,
            raw,
            head ++ systemd ++ "',interface='" ++ properties ++ "',path='" ++ u.path ++
                "',member='PropertiesChanged'",
        ))
            return @fromBackingInt(@intCast(i + 2));
    }
    return null;
}

const Phase = enum { nul, auth, begin, binary };
const Client = struct {
    fd: i32 = -1,
    id: u32 = 0,
    phase: Phase = .nul,
    attempts: u8 = 0,
    hello: bool = false,
    subscribed: bool = false,
    matches: [6]u16 = @splat(0),
    input: wire.Buffer = .{},
    output: wire.Buffer = .{},
    sent: usize = 0,
    deadline: i64 = 0,

    fn close(c: *Client) void {
        if (c.fd >= 0) _ = linux.close(c.fd);
        c.fd = -1;
    }

    fn name(c: *const Client, buf: *[32]u8) []const u8 {
        return mem.print(buf, ":1.{d}", .{c.id}) catch unreachable;
    }

    fn consume(c: *Client, n: usize) void {
        @memmove(c.input.bytes[0 .. c.input.len - n], c.input.bytes[n..c.input.len]);
        c.input.len -= n;
    }

    fn reply(c: *Client, m: wire.Message, r: *const Reply, serial: *u32) !void {
        if (m.flags & 1 != 0) return;
        var fields: wire.Buffer = .{};
        try fields.uintField(5, m.serial);
        var name_buf: [32]u8 = undefined;
        try fields.field(6, 's', c.name(&name_buf));
        try fields.field(7, 's', if (mem.eql(u8, m.destination, bus)) bus else owner);
        if (r.signature.len > 0) try fields.field(8, 'g', r.signature);
        if (r.err) |err| try fields.field(4, 's', err);
        try wire.encode(
            &c.output,
            if (r.err != null) 3 else 2,
            nextSerial(serial),
            &fields,
            &r.body,
        );
    }
};

fn nextSerial(serial: *u32) u32 {
    const n = serial.*;
    serial.* +%= 1;
    if (serial.* == 0) serial.* = 1;
    return n;
}

fn args(m: wire.Message, signature: []const u8) !wire.Cursor {
    if (!mem.eql(u8, m.signature, signature)) return error.BadArguments;
    return m.body;
}

fn dispatch(c: *Client, m: wire.Message, states: [units.len]Activity, r: *Reply) !void {
    if (m.kind != 1) return error.BadArguments;
    if (!c.hello and !(mem.eql(u8, m.destination, bus) and mem.eql(u8, m.member, "Hello")))
        return r.fail("org.freedesktop.DBus.Error.AccessDenied");
    if (mem.eql(u8, m.destination, bus) and mem.eql(u8, m.path, "/org/freedesktop/DBus") and
        mem.eql(u8, m.interface, bus))
    {
        if (mem.eql(u8, m.member, "Hello")) {
            var a = try args(m, "");
            try a.done();
            if (c.hello) return r.fail("org.freedesktop.DBus.Error.Failed");
            c.hello = true;
            var buf: [32]u8 = undefined;
            return r.string("s", c.name(&buf));
        }
        if (mem.eql(u8, m.member, "GetNameOwner")) {
            var a = try args(m, "s");
            const name = try a.string(false);
            try a.done();
            if (mem.eql(u8, name, systemd)) return r.string("s", owner);
            if (mem.eql(u8, name, bus)) return r.string("s", bus);
            return r.fail("org.freedesktop.DBus.Error.NameHasNoOwner");
        }
        const add = mem.eql(u8, m.member, "AddMatch");
        if (add or mem.eql(u8, m.member, "RemoveMatch")) {
            var a = try args(m, "s");
            const rule = matchRule(try a.string(false));
            try a.done();
            const i = @backingInt(
                rule orelse return r.fail("org.freedesktop.DBus.Error.MatchRuleInvalid"),
            );
            if (add) {
                if (c.matches[i] >= 64) return r.fail("org.freedesktop.DBus.Error.LimitsExceeded");
                c.matches[i] += 1;
            } else {
                if (c.matches[i] == 0) return r.fail(
                    "org.freedesktop.DBus.Error.MatchRuleNotFound",
                );
                c.matches[i] -= 1;
            }
            return;
        }
        return r.fail("org.freedesktop.DBus.Error.AccessDenied");
    }
    if (!mem.eql(u8, m.destination, systemd) and !mem.eql(u8, m.destination, owner))
        return r.fail("org.freedesktop.DBus.Error.ServiceUnknown");
    const u = unitByPath(m.path);
    if (!mem.eql(u8, m.path, root) and
        u == null) return r.fail("org.freedesktop.DBus.Error.UnknownObject");
    if (mem.eql(u8, m.interface, "org.freedesktop.DBus.Introspectable") and
        mem.eql(u8, m.member, "Introspect"))
    {
        var a = try args(m, "");
        try a.done();
        return r.string("s", if (u == null) manager_xml else unit_xml);
    }
    if (mem.eql(u8, m.path, root) and mem.eql(u8, m.interface, manager)) {
        if (mem.eql(u8, m.member, "Subscribe") or mem.eql(u8, m.member, "Unsubscribe")) {
            var a = try args(m, "");
            try a.done();
            c.subscribed = mem.eql(u8, m.member, "Subscribe");
            return;
        }
        if (mem.eql(u8, m.member, "LoadUnit")) {
            var a = try args(m, "s");
            const name = try a.string(false);
            try a.done();
            const i = unitByName(name) orelse return r.fail("org.freedesktop.systemd1.NoSuchUnit");
            return r.string("o", units[i].path);
        }
        return r.fail("org.freedesktop.DBus.Error.AccessDenied");
    }
    if (u) |i| {
        if (mem.eql(u8, m.interface, properties) and mem.eql(u8, m.member, "Get")) {
            var a = try args(m, "ss");
            const interface = try a.string(false);
            const property = try a.string(false);
            try a.done();
            if (mem.eql(u8, interface, unit_interface) and mem.eql(u8, property, "ActiveState"))
                return r.string("v", @tagName(states[i]));
            // runsv does not receive sd_notify STATUS. Empty means no
            // status text, rather than inventing application readiness.
            if (mem.eql(u8, interface, service_interface) and mem.eql(u8, property, "StatusText"))
                return r.string("v", "");
            return r.fail("org.freedesktop.DBus.Error.UnknownProperty");
        }
    }
    return r.fail("org.freedesktop.DBus.Error.AccessDenied");
}

fn changed(c: *Client, i: usize, value: Activity, serial: *u32) !void {
    if (!c.hello or !c.subscribed or c.matches[i + 2] == 0) return;
    var body: wire.Buffer = .{};
    try body.string(unit_interface, false);
    // a{sv} containing the single changed string property.
    const size_pos = body.len + (4 - body.len % 4) % 4;
    try body.uint(0);
    try body.alignTo(8);
    const start = body.len;
    try body.string("ActiveState", false);
    try body.string("s", true);
    try body.string(@tagName(value), false);
    mem.writeInt(u32, body.bytes[size_pos..][0..4], @intCast(body.len - start), .little);
    try body.uint(0); // empty invalidated-properties string array
    var fields: wire.Buffer = .{};
    try fields.field(1, 'o', units[i].path);
    try fields.field(2, 's', properties);
    try fields.field(3, 's', "PropertiesChanged");
    try fields.field(7, 's', owner);
    try fields.field(8, 'g', "sa{sv}as");
    try wire.encode(&c.output, 4, nextSerial(serial), &fields, &body);
}

fn auth(c: *Client, expected: []const u8, guid: []const u8) !bool {
    if (c.phase == .nul) {
        if (c.input.len == 0) return false;
        if (c.input.bytes[0] != 0) return error.BadAuth;
        c.consume(1);
        c.phase = .auth;
    }
    const end = mem.indexOf(u8, c.input.slice(), "\r\n") orelse {
        if (c.input.len > 256) return error.BadAuth;
        return false;
    };
    if (end > 256 or c.attempts >= 8) return error.BadAuth;
    c.attempts += 1;
    const line = c.input.slice()[0..end];
    if (c.phase == .begin and mem.eql(u8, line, "BEGIN")) {
        c.phase = .binary;
    } else if (mem.eql(u8, line, "AUTH") or mem.startsWith(u8, line, "AUTH ")) {
        const claimed = mem.cutPrefix(u8, line, "AUTH EXTERNAL ") orelse "";
        if (c.phase == .auth and claimed.len > 0 and mem.eql(u8, claimed, expected)) {
            try c.output.append("OK ");
            try c.output.append(guid);
            try c.output.append("\r\n");
            c.phase = .begin;
        } else try c.output.append("REJECTED EXTERNAL\r\n");
    } else if (c.phase == .begin and mem.eql(u8, line, "NEGOTIATE_UNIX_FD")) {
        try c.output.append("ERROR\r\n");
    } else return error.BadAuth;
    c.consume(end + 2);
    return true;
}

fn handle(
    c: *Client,
    expected: []const u8,
    guid: []const u8,
    states: [units.len]Activity,
    serial: *u32,
) !void {
    var count: u8 = 0;
    while (count < 32) : (count += 1) {
        if (c.phase != .binary) {
            if (!try auth(c, expected, guid)) break;
            continue;
        }
        const n = (try wire.length(c.input.slice())) orelse break;
        if (c.input.len < n) break;
        const m = try wire.parse(c.input.slice()[0..n]);
        var reply: Reply = .{};
        dispatch(c, m, states, &reply) catch {
            reply = .{};
            try reply.fail("org.freedesktop.DBus.Error.InvalidArgs");
        };
        try c.reply(m, &reply, serial);
        c.consume(n);
    }
}

fn now() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec;
}

fn listener() !i32 {
    const raw = linux.socket(
        linux.AF.UNIX,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    );
    if (linux.errno(raw) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(raw);
    errdefer _ = linux.close(fd);
    _ = linux.unlink(socket_path);
    var address: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(address.path[0..socket_path.len], socket_path);
    if (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.un))) != .SUCCESS or
        linux.errno(linux.fchmodat(linux.AT.FDCWD, socket_path, 0o660)) != .SUCCESS or
        linux.errno(linux.listen(fd, max_clients)) != .SUCCESS) return error.Listen;
    return fd;
}

const Identity = struct { uid: u32, hex: []const u8 };

fn externalId(passwd: []const u8, out: *[32]u8) !Identity {
    var lines = mem.splitScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var fields = mem.splitScalar(u8, line, ':');
        if (!mem.eql(u8, fields.next() orelse "", "_oci-unifi-core")) continue;
        _ = fields.next();
        const uid = fields.next() orelse return error.NoCoreUser;
        if (uid.len == 0 or uid.len > 10) return error.NoCoreUser;
        const numeric = std.fmt.parseInt(u32, uid, 10) catch return error.NoCoreUser;
        const hex = "0123456789abcdef";
        for (uid, 0..) |b, i| {
            out[i * 2] = hex[b >> 4];
            out[i * 2 + 1] = hex[b & 15];
        }
        return .{ .uid = numeric, .hex = out[0 .. uid.len * 2] };
    }
    return error.NoCoreUser;
}

const Credentials = extern struct { pid: i32, uid: u32, gid: u32 };

fn corePeer(fd: i32, uid: u32) bool {
    var credentials: Credentials = undefined;
    var size: linux.socklen_t = @sizeOf(Credentials);
    return linux.errno(linux.getsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.PEERCRED,
        @ptrCast(&credentials),
        &size,
    )) == .SUCCESS and size == @sizeOf(Credentials) and credentials.uid == uid;
}

// Static storage keeps connection buffers out of the small service stack.
var clients: [max_clients]Client = @splat(.{});

pub fn main(init: std.process.Init) void {
    serve(init) catch |err| {
        var buf: [128]u8 = undefined;
        const line = mem.print(&buf, "unifi-systemd: {s}\n", .{@errorName(err)}) catch return;
        Io.File.stderr().writeStreamingAll(init.io, line) catch {};
        std.process.exit(1);
    };
}

fn serve(init: std.process.Init) !void {
    _ = linux.close_range(3, std.math.maxInt(linux.fd_t), .{ .UNSHARE = false, .CLOEXEC = false });
    const io = init.io;
    const gpa = init.arena.allocator();
    const passwd = try Io.Dir.cwd().readFileAlloc(io, "/etc/passwd", gpa, .limited(64 << 10));
    var id_buf: [32]u8 = undefined;
    const expected = try externalId(passwd, &id_buf);
    var random: [16]u8 = undefined;
    Io.random(io, &random);
    const guid = std.fmt.bytesToHex(random, .lower);
    const fd = try listener();
    defer _ = linux.close(fd);
    try Io.File.stdout().writeStreamingAll(
        io,
        "unifi-systemd: read-only service state on Core's Unix socket\n",
    );
    var states: [units.len]Activity = undefined;
    for (units, &states) |u, *s| s.* = state(io, u);
    var serial: u32 = 1;
    var client_id: u32 = 1;
    var tick = now();
    while (true) {
        var fds: [max_clients + 1]linux.pollfd = undefined;
        fds[0] = .{ .fd = fd, .events = linux.POLL.IN, .revents = 0 };
        for (&clients, fds[1..]) |*c, *p| p.* = .{
            .fd = c.fd,
            .events = linux.POLL.IN | if (c.output.len > c.sent) @as(i16, linux.POLL.OUT) else 0,
            .revents = 0,
        };
        const rc = linux.poll(&fds, fds.len, 250);
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS) return error.Poll;
        const time = now();
        for (&clients, fds[1..]) |*c, p| {
            if (c.fd < 0) continue;
            if (p.revents & (linux.POLL.ERR | linux.POLL.HUP | linux.POLL.NVAL) != 0 or
                (time >= c.deadline and (c.phase != .binary or c.input.len > 0 or
                    c.output.len > c.sent)))
            {
                c.close();
                continue;
            }
            if (p.revents & linux.POLL.IN != 0) {
                if (c.input.len == wire.limit) {
                    c.close();
                    continue;
                }
                const n = linux.recvfrom(
                    c.fd,
                    c.input.bytes[c.input.len..].ptr,
                    wire.limit - c.input.len,
                    0,
                    null,
                    null,
                );
                if (linux.errno(n) == .SUCCESS and n > 0) {
                    if (c.input.len == 0 and c.output.len == c.sent) c.deadline = time + 5;
                    c.input.len += n;
                } else if (linux.errno(n) != .AGAIN and linux.errno(n) != .INTR) {
                    c.close();
                    continue;
                }
            }
            handle(c, expected.hex, &guid, states, &serial) catch {
                c.close();
                continue;
            };
            if (c.output.len > c.sent) {
                const n = linux.sendto(
                    c.fd,
                    c.output.bytes[c.sent..c.output.len].ptr,
                    c.output.len - c.sent,
                    linux.MSG.NOSIGNAL,
                    null,
                    0,
                );
                if (linux.errno(n) == .SUCCESS) {
                    c.sent += n;
                    if (c.sent == c.output.len) {
                        c.output.len = 0;
                        c.sent = 0;
                    }
                } else if (linux.errno(n) != .AGAIN and linux.errno(n) != .INTR) c.close();
            }
        }
        if (fds[0].revents & linux.POLL.IN != 0) {
            const accepted = linux.accept4(
                fd,
                null,
                null,
                linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
            );
            if (linux.errno(accepted) == .SUCCESS) {
                const peer: i32 = @intCast(accepted);
                if (!corePeer(peer, expected.uid)) {
                    _ = linux.close(peer);
                    continue;
                }
                var placed = false;
                for (&clients) |*c| if (c.fd < 0) {
                    c.* = .{ .fd = peer, .id = nextSerial(&client_id), .deadline = time + 5 };
                    placed = true;
                    break;
                };
                if (!placed) _ = linux.close(peer);
            }
        }
        if (time > tick) {
            tick = time;
            for (units, 0..) |u, i| {
                const fresh = state(io, u);
                if (states[i] == fresh) continue;
                states[i] = fresh;
                for (&clients) |*c| if (c.fd >= 0) {
                    if (c.output.len == c.sent) c.deadline = time + 5;
                    changed(c, i, fresh, &serial) catch c.close();
                };
            }
        }
    }
}

test "runit state never invents a live service from invalid or finishing data" {
    var raw: [20]u8 = @splat(0);
    raw[17] = 'u';
    try std.testing.expectEqual(Activity.activating, stateOf(&raw));
    raw[17] = 'd';
    try std.testing.expectEqual(Activity.inactive, stateOf(&raw));
    raw[19] = 1;
    try std.testing.expectEqual(Activity.deactivating, stateOf(&raw));
    mem.writeInt(u32, raw[12..16], 42, .little);
    try std.testing.expectEqual(Activity.active, stateOf(&raw));
    raw[19] = 2;
    try std.testing.expectEqual(Activity.deactivating, stateOf(&raw));
    try std.testing.expectEqual(Activity.failed, stateOf(raw[0..19]));
    try std.testing.expect(unitByName("../../sshd.service") == null);
    try std.testing.expect(unitByName("sshd.service") == null);
}

test "authentication requires the Core identity and BEGIN before messages" {
    var c: Client = .{};
    try c.input.append("\x00AUTH EXTERNAL 30\r\n");
    try std.testing.expect(try auth(&c, "313233", "00000000000000000000000000000000"));
    try std.testing.expectEqual(Phase.auth, c.phase);
    try std.testing.expectEqualStrings("REJECTED EXTERNAL\r\n", c.output.slice());
    try c.input.append("AUTH EXTERNAL 313233\r\nBEGIN\r\n");
    try std.testing.expect(try auth(&c, "313233", "00000000000000000000000000000000"));
    try std.testing.expectEqual(Phase.begin, c.phase);
    try std.testing.expect(try auth(&c, "313233", "00000000000000000000000000000000"));
    try std.testing.expectEqual(Phase.binary, c.phase);
}

test "unknown units and management requests fail explicitly" {
    var c: Client = .{ .hello = true };
    var b: wire.Buffer = .{};
    try b.string("sshd.service", false);
    var m: wire.Message = .{
        .kind = 1,
        .flags = 0,
        .serial = 1,
        .path = root,
        .interface = manager,
        .member = "LoadUnit",
        .destination = systemd,
        .signature = "s",
        .body = .{
            .data = b.slice(),
        },
    };
    var r: Reply = .{};
    try dispatch(&c, m, @splat(.inactive), &r);
    try std.testing.expectEqualStrings("org.freedesktop.systemd1.NoSuchUnit", r.err.?);
    m.member = "RestartUnit";
    r = .{};
    try dispatch(&c, m, @splat(.inactive), &r);
    try std.testing.expectEqualStrings("org.freedesktop.DBus.Error.AccessDenied", r.err.?);
    m.member = "LoadUnit";
    m.signature = "ss";
    try std.testing.expectError(error.BadArguments, dispatch(&c, m, @splat(.inactive), &r));
}

test "status is real, missing readiness remains empty, and subscriptions are bounded" {
    var c: Client = .{ .hello = true, .subscribed = true };
    var b: wire.Buffer = .{};
    try b.string(unit_interface, false);
    try b.string("ActiveState", false);
    const m: wire.Message = .{
        .kind = 1,
        .flags = 0,
        .serial = 1,
        .path = units[0].path,
        .interface = properties,
        .member = "Get",
        .destination = systemd,
        .signature = "ss",
        .body = .{ .data = b.slice() },
    };
    var r: Reply = .{};
    try dispatch(&c, m, .{ .active, .inactive, .inactive, .inactive }, &r);
    var a: wire.Cursor = .{ .data = r.body.slice() };
    try std.testing.expectEqualStrings("s", try a.string(true));
    try std.testing.expectEqualStrings("active", try a.string(false));
    b.len = 0;
    try b.string(service_interface, false);
    try b.string("StatusText", false);
    var status_query = m;
    status_query.body = .{ .data = b.slice() };
    r = .{};
    try dispatch(&c, status_query, @splat(.inactive), &r);
    a = .{ .data = r.body.slice() };
    try std.testing.expectEqualStrings("s", try a.string(true));
    try std.testing.expectEqualStrings("", try a.string(false));
    var serial: u32 = 1;
    try changed(&c, 0, .inactive, &serial);
    try std.testing.expectEqual(@as(usize, 0), c.output.len);
    c.matches[2] = 1;
    try changed(&c, 0, .inactive, &serial);
    const signal = try wire.parse(c.output.slice());
    try std.testing.expectEqual(@as(u8, 4), signal.kind);
    try std.testing.expectEqualStrings("sa{sv}as", signal.signature);
    try std.testing.expect(matchRule("type='signal'") == null);
    var hex: [32]u8 = undefined;
    try std.testing.expectEqualStrings(
        "313233",
        (try externalId("_oci-unifi-core:x:123:123::/:/sbin/nologin\n", &hex)).hex,
    );
}

test "match registration and removal refuse overflow and underflow" {
    try std.testing.expectEqual(
        Match.name_owner,
        matchRule("type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus'," ++
            "path='/org/freedesktop/DBus',member='NameOwnerChanged'").?,
    );
    const rule = "type='signal',sender='org.freedesktop.systemd1',interface='org.freedesktop.DBu" ++
        "s.Properties',path='" ++ units[0].path ++ "',member='PropertiesChanged'";
    var c: Client = .{ .hello = true };
    var b: wire.Buffer = .{};
    try b.string(rule, false);
    var m: wire.Message = .{
        .kind = 1,
        .flags = 0,
        .serial = 1,
        .path = "/org/freedesktop/DBus",
        .interface = bus,
        .member = "AddMatch",
        .destination = bus,
        .signature = "s",
        .body = .{ .data = b.slice() },
    };
    for (0..64) |_| {
        var r: Reply = .{};
        try dispatch(&c, m, @splat(.inactive), &r);
        try std.testing.expect(r.err == null);
    }
    var r: Reply = .{};
    try dispatch(&c, m, @splat(.inactive), &r);
    try std.testing.expectEqualStrings("org.freedesktop.DBus.Error.LimitsExceeded", r.err.?);
    m.member = "RemoveMatch";
    for (0..64) |_| {
        r = .{};
        try dispatch(&c, m, @splat(.inactive), &r);
        try std.testing.expect(r.err == null);
    }
    r = .{};
    try dispatch(&c, m, @splat(.inactive), &r);
    try std.testing.expectEqualStrings("org.freedesktop.DBus.Error.MatchRuleNotFound", r.err.?);
}
