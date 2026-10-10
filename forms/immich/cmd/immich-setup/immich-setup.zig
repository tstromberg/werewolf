//! immich-setup makes Immich's administrator from the machine's config, and
//! sets werewolf's defaults, once, before Caddy opens Immich to anyone: the
//! admin sign-up that Immich leaves to its first visitor is taken first.
//!
//!     immich-setup
//!
//! leash runs it as the caddy user, before Caddy validates its
//! configuration (forms/immich/form.yaml). See forms/immich/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const net = Io.net;
const json = std.json;

/// password is leash's copy of the config's, removed once read.
const password_path = "/run/svc/caddy/admin-password";
/// done records on /data that setup finished, so it runs once.
const done = "/data/svc/caddy/immich-setup-done";
const port = 2283;
/// wait_seconds bounds the wait for Immich's first start, whose migrations
/// and geodata import take minutes on a small machine.
const wait_seconds = 900;

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa, init.minimal.environ) catch |err| {
        say(io, "{{\"event\":\"failed\",\"why\":\"{s}\"}}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    // The password is needed once; no copy outlives this step.
    defer Dir.cwd().deleteFile(io, password_path) catch {};
    if (Dir.cwd().access(io, done, .{})) |_| {
        say(io, "{{\"event\":\"set up already\"}}", .{});
        return;
    } else |_| {}

    const email = environ.getAlloc(gpa, "IMMICH_ADMIN_EMAIL") catch return error.NoAdminEmail;
    if (!address(email)) return error.AdminEmailNotAnAddress;
    const name: []const u8 = environ.getAlloc(gpa, "IMMICH_ADMIN_NAME") catch "Admin";
    const base_url: []const u8 = environ.getAlloc(gpa, "BASE_URL") catch "";
    const text = Dir.cwd().readFileAlloc(io, password_path, gpa, .limited(4 << 10)) catch |err|
        switch (err) {
            error.FileNotFound => return error.NoAdminPassword,
            else => return err,
        };
    const password = std.mem.trimEnd(u8, text, "\r\n");
    // bcrypt, which Immich hashes with, reads 72 bytes.
    if (password.len < 12) return error.PasswordTooShort;
    if (password.len > 72) return error.PasswordTooLong;

    try awaitImmich(io, gpa);
    const who = try json.Stringify.valueAlloc(gpa, .{
        .email = email,
        .password = password,
        .name = name,
    }, .{});
    const signup = try request(io, gpa, "POST", "/api/auth/admin-sign-up", null, who);
    switch (signup.status) {
        200, 201 => say(io, "{{\"event\":\"admin made\",\"email\":\"{s}\"}}", .{email}),
        else => {
            // An admin exists: a setup that stopped before its mark. The
            // login below proves it is the config's.
            if (std.mem.find(u8, signup.body, "not available") == null)
                return error.AdminSignUpRefused;
            say(io, "{{\"event\":\"admin exists\"}}", .{});
        },
    }

    const credentials = try json.Stringify.valueAlloc(gpa, .{
        .email = email,
        .password = password,
    }, .{});
    const login = try request(io, gpa, "POST", "/api/auth/login", null, credentials);
    if (login.status != 200 and login.status != 201) return error.AdminLoginRefused;
    const Session = struct { accessToken: []const u8 };
    const session = json.parseFromSliceLeaky(Session, gpa, login.body, .{
        .ignore_unknown_fields = true,
    }) catch return error.LoginAnswerNotUnderstood;

    const got = try request(io, gpa, "GET", "/api/system-config", session.accessToken, null);
    if (got.status != 200) return error.SystemConfigNotRead;
    const config = try defaults(gpa, got.body, base_url);
    const put = try request(io, gpa, "PUT", "/api/system-config", session.accessToken, config);
    if (put.status != 200) return error.SystemConfigNotWritten;
    _ = request(io, gpa, "POST", "/api/auth/logout", session.accessToken, null) catch {};

    try mark(io);
    say(io, "{{\"event\":\"set up\",\"external-domain\":\"{s}\"}}", .{base_url});
}

/// defaults returns Immich's system config, as it answered it, with
/// werewolf's defaults: no version check (the machine's updater brings new
/// versions), no machine learning (this form runs none), and the site's
/// address for shared links. The admin may change any of them later.
fn defaults(gpa: Allocator, body: []const u8, base_url: []const u8) ![]const u8 {
    var v = json.parseFromSliceLeaky(json.Value, gpa, body, .{}) catch
        return error.SystemConfigNotUnderstood;
    if (v != .object) return error.SystemConfigNotUnderstood;
    try set(gpa, &v, "newVersionCheck", "enabled", .{ .bool = false });
    try set(gpa, &v, "machineLearning", "enabled", .{ .bool = false });
    if (base_url.len > 0) try set(gpa, &v, "server", "externalDomain", .{ .string = base_url });
    return json.Stringify.valueAlloc(gpa, v, .{});
}

/// set sets v[section][key] to value, where v[section] is an object.
fn set(
    gpa: Allocator,
    v: *json.Value,
    section: []const u8,
    key: []const u8,
    value: json.Value,
) !void {
    const s = v.object.getPtr(section) orelse return error.SystemConfigNotUnderstood;
    if (s.* != .object) return error.SystemConfigNotUnderstood;
    try s.object.put(gpa, key, value);
}

/// awaitImmich waits until Immich answers its ping on loopback.
fn awaitImmich(io: Io, gpa: Allocator) !void {
    const started = Io.Clock.awake.now(io);
    var said = false;
    while (started.untilNow(io, .awake).toSeconds() < wait_seconds) {
        if (request(io, gpa, "GET", "/api/server/ping", null, null)) |r| {
            if (r.status == 200 and std.mem.find(u8, r.body, "pong") != null) return;
        } else |_| {}
        if (!said) say(io, "{{\"event\":\"waiting for Immich\"}}", .{});
        said = true;
        io.sleep(.fromSeconds(2), .awake) catch {};
    }
    return error.ImmichNeverAnswered;
}

const Response = struct { status: u16, body: []const u8 };

/// request sends one HTTP/1.1 request to Immich on loopback and returns its
/// answer, whole.
fn request(
    io: Io,
    gpa: Allocator,
    method: []const u8,
    path: []const u8,
    token: ?[]const u8,
    body: ?[]const u8,
) !Response {
    const addr = try net.IpAddress.parse("127.0.0.1", port);
    const s = try addr.connect(io, .{ .mode = .stream });
    defer s.close(io);
    var wbuf: [4096]u8 = undefined;
    var w = s.writer(io, &wbuf);
    const out = &w.interface;
    try out.print("{s} {s} HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAccept: application/json\r\n" ++
        "Connection: close\r\n", .{ method, path, port });
    if (token) |t| try out.print("Authorization: Bearer {s}\r\n", .{t});
    const b = body orelse "";
    if (body != null) try out.writeAll("Content-Type: application/json\r\n");
    try out.print("Content-Length: {d}\r\n\r\n{s}", .{ b.len, b });
    try out.flush();
    var rbuf: [4096]u8 = undefined;
    var r = s.reader(io, &rbuf);
    return parse(gpa, try r.interface.allocRemaining(gpa, .limited(8 << 20)));
}

/// parse returns raw's status and body, its chunks joined.
fn parse(gpa: Allocator, raw: []const u8) !Response {
    const end = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.BadAnswer;
    const head = raw[0..end];
    if (head.len < 12 or !std.mem.startsWith(u8, head, "HTTP/1.1 ")) return error.BadAnswer;
    const status = std.fmt.parseInt(u16, head[9..12], 10) catch return error.BadAnswer;
    var body = raw[end + 4 ..];
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |l| {
        const colon = std.mem.findScalar(u8, l, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(l[0..colon], "transfer-encoding") and
            std.ascii.findIgnoreCase(l[colon + 1 ..], "chunked") != null)
            body = try unchunk(gpa, body);
    }
    return .{ .status = status, .body = body };
}

/// unchunk joins a chunked body's chunks.
fn unchunk(gpa: Allocator, chunked: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var rest = chunked;
    while (true) {
        const eol = std.mem.find(u8, rest, "\r\n") orelse return error.BadAnswer;
        const size_text = rest[0 .. std.mem.findScalar(u8, rest[0..eol], ';') orelse eol];
        const size = std.fmt.parseInt(usize, std.mem.trim(u8, size_text, " "), 16) catch
            return error.BadAnswer;
        rest = rest[eol + 2 ..];
        if (size == 0) return out.items;
        if (rest.len < size + 2) return error.BadAnswer;
        try out.appendSlice(gpa, rest[0..size]);
        rest = rest[size + 2 ..];
    }
}

/// address reports whether s looks like an e-mail address Immich would take
/// and a JSON string carries plainly.
fn address(s: []const u8) bool {
    if (s.len < 3 or s.len > 254) return false;
    const at = std.mem.findScalar(u8, s, '@') orelse return false;
    if (at == 0 or at == s.len - 1) return false;
    for (s) |c| if (c <= ' ' or c == '"' or c == '\\' or c >= 0x7f) return false;
    return true;
}

/// mark writes the done mark and syncs it, so a power cut cannot leave a
/// machine set up twice.
fn mark(io: Io) !void {
    var f = try Dir.cwd().createFile(io, done, .{ .permissions = .fromMode(0o600) });
    defer f.close(io);
    try f.writeStreamingAll(io, "Immich's admin and defaults are set (forms/immich/README.md).\n");
    try f.sync(io);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "immich-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "parse reads the status and joins chunks" {
    const plain = try parse(
        testing.allocator,
        "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}",
    );
    try testing.expectEqual(201, plain.status);
    try testing.expectEqualStrings("{}", plain.body);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const chunked = try parse(
        arena.allocator(),
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n",
    );
    try testing.expectEqualStrings("{\"a\":1}", chunked.body);
    try testing.expectError(error.BadAnswer, parse(testing.allocator, "HTTP/1.0 200 OK\r\n\r\n"));
}

test "defaults turns the version check and machine learning off" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const out = try defaults(
        arena.allocator(),
        "{\"newVersionCheck\":{\"enabled\":true}," ++
            "\"machineLearning\":{\"enabled\":true,\"urls\":[]}," ++
            "\"server\":{\"externalDomain\":\"\"}}",
        "https://photos.example.com",
    );
    try testing.expectEqualStrings("{\"newVersionCheck\":{\"enabled\":false}," ++
        "\"machineLearning\":{\"enabled\":false,\"urls\":[]}," ++
        "\"server\":{\"externalDomain\":\"https://photos.example.com\"}}", out);
    try testing.expectError(error.SystemConfigNotUnderstood, defaults(arena.allocator(), "[]", ""));
}

test "address takes plain addresses" {
    try testing.expect(address("admin@example.com"));
    for ([_][]const u8{ "", "admin", "@example.com", "admin@", "a b@c", "a\"@b" }) |bad|
        try testing.expect(!address(bad));
}
