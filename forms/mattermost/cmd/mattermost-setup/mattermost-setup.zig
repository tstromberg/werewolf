//! mattermost-setup makes Mattermost's system admin from the machine's
//! config, once, before Caddy opens Mattermost to anyone: the first account,
//! which Mattermost makes system admin, is taken before a visitor can.
//!
//!     mattermost-setup
//!
//! leash runs it as the caddy user, before Caddy validates its
//! configuration (forms/mattermost/form.yaml). See forms/mattermost/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const net = Io.net;
const json = std.json;

/// password is leash's copy of the config's, removed once read.
const password_path = "/run/svc/caddy/admin-password";
/// done records on /data that setup finished, so it runs once.
const done = "/data/svc/caddy/mattermost-setup-done";
const port = 8065;
/// wait_seconds bounds the wait for Mattermost's first start, whose
/// migrations take minutes on a small machine.
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

    const username = environ.getAlloc(gpa, "MM_ADMIN_USERNAME") catch return error.NoAdmin;
    if (!validUsername(username)) return error.AdminNotAUsername;
    const email = environ.getAlloc(gpa, "MM_ADMIN_EMAIL") catch return error.NoAdminEmail;
    if (!address(email)) return error.AdminEmailNotAnAddress;
    const text = Dir.cwd().readFileAlloc(io, password_path, gpa, .limited(4 << 10)) catch |err|
        switch (err) {
            error.FileNotFound => return error.NoAdminPassword,
            else => return err,
        };
    const password = std.mem.trimEnd(u8, text, "\r\n");
    // bcrypt, which Mattermost hashes with, reads 72 bytes.
    if (password.len < 12) return error.PasswordTooShort;
    if (password.len > 72) return error.PasswordTooLong;

    try awaitMattermost(io, gpa);
    const who = try json.Stringify.valueAlloc(gpa, .{
        .email = email,
        .username = username,
        .password = password,
    }, .{});
    const signup = try request(io, gpa, "POST", "/api/v4/users", null, who);
    switch (signup.status) {
        201 => say(io, "{{\"event\":\"admin made\",\"username\":\"{s}\"}}", .{username}),
        else => {
            // An account exists: a setup that stopped before its mark. The
            // login below proves it is the config's admin.
            if (std.mem.find(u8, signup.body, "api.user.create_user.no_open_server") == null)
                return error.AdminSignUpRefused;
            say(io, "{{\"event\":\"admin exists\"}}", .{});
        },
    }

    const login = try request(io, gpa, "POST", "/api/v4/users/login", null, try json.Stringify.valueAlloc(
        gpa,
        .{ .login_id = username, .password = password },
        .{},
    ));
    if (login.status != 200) return error.AdminLoginRefused;
    const User = struct { roles: []const u8 };
    const user = json.parseFromSliceLeaky(User, gpa, login.body, .{
        .ignore_unknown_fields = true,
    }) catch return error.LoginAnswerNotUnderstood;
    if (std.mem.find(u8, user.roles, "system_admin") == null) return error.AdminNotSystemAdmin;
    if (login.token.len > 0)
        _ = request(io, gpa, "POST", "/api/v4/users/logout", login.token, null) catch {};

    try mark(io);
    say(io, "{{\"event\":\"set up\",\"username\":\"{s}\"}}", .{username});
}

/// awaitMattermost waits until Mattermost answers its ping on loopback.
fn awaitMattermost(io: Io, gpa: Allocator) !void {
    const started = Io.Clock.awake.now(io);
    var said = false;
    while (started.untilNow(io, .awake).toSeconds() < wait_seconds) {
        if (request(io, gpa, "GET", "/api/v4/system/ping", null, null)) |r| {
            if (r.status == 200 and std.mem.find(u8, r.body, "\"OK\"") != null) return;
        } else |_| {}
        if (!said) say(io, "{{\"event\":\"waiting for Mattermost\"}}", .{});
        said = true;
        io.sleep(.fromSeconds(2), .awake) catch {};
    }
    return error.MattermostNeverAnswered;
}

/// Response is an answer's status, its session token if it set one, and
/// its body.
const Response = struct { status: u16, token: []const u8 = "", body: []const u8 };

/// request sends one HTTP/1.1 request to Mattermost on loopback and returns
/// its answer, whole.
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
    // X-Requested-With: Mattermost refuses a token-authenticated POST
    // without it, as a guard against cross-site requests.
    try out.print("{s} {s} HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAccept: application/json\r\n" ++
        "X-Requested-With: XMLHttpRequest\r\nConnection: close\r\n", .{ method, path, port });
    if (token) |t| try out.print("Authorization: Bearer {s}\r\n", .{t});
    const b = body orelse "";
    if (body != null) try out.writeAll("Content-Type: application/json\r\n");
    try out.print("Content-Length: {d}\r\n\r\n{s}", .{ b.len, b });
    try out.flush();
    var rbuf: [4096]u8 = undefined;
    var r = s.reader(io, &rbuf);
    return parse(gpa, try r.interface.allocRemaining(gpa, .limited(8 << 20)));
}

/// parse returns raw's status, its Token header and its body, chunks joined.
fn parse(gpa: Allocator, raw: []const u8) !Response {
    const end = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.BadAnswer;
    const head = raw[0..end];
    if (head.len < 12 or !std.mem.startsWith(u8, head, "HTTP/1.1 ")) return error.BadAnswer;
    const status = std.fmt.parseInt(u16, head[9..12], 10) catch return error.BadAnswer;
    var body = raw[end + 4 ..];
    var token: []const u8 = "";
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |l| {
        const colon = std.mem.findScalar(u8, l, ':') orelse continue;
        const name = l[0..colon];
        const value = std.mem.trim(u8, l[colon + 1 ..], " ");
        if (std.ascii.eqlIgnoreCase(name, "token")) token = value;
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding") and
            std.ascii.findIgnoreCase(value, "chunked") != null)
            body = try unchunk(gpa, body);
    }
    return .{ .status = status, .token = token, .body = body };
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

/// validUsername reports whether s is a username Mattermost takes: 3 to 22
/// bytes, a lowercase letter first, then lowercase letters, digits, '.',
/// '-' and '_'.
fn validUsername(s: []const u8) bool {
    if (s.len < 3 or s.len > 22 or !std.ascii.isLower(s[0])) return false;
    for (s) |c| switch (c) {
        'a'...'z', '0'...'9', '.', '-', '_' => {},
        else => return false,
    };
    return true;
}

/// address reports whether s looks like an e-mail address Mattermost would
/// take and a JSON string carries plainly.
fn address(s: []const u8) bool {
    if (s.len < 3 or s.len > 128) return false;
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
    try f.writeStreamingAll(io, "Mattermost's system admin is made (forms/mattermost/README.md).\n");
    try f.sync(io);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "mattermost-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "parse reads the status and token and joins chunks" {
    const plain = try parse(testing.allocator, "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}");
    try testing.expectEqual(201, plain.status);
    try testing.expectEqualStrings("{}", plain.body);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const chunked = try parse(
        arena.allocator(),
        "HTTP/1.1 200 OK\r\nToken: abc\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n",
    );
    try testing.expectEqualStrings("abc", chunked.token);
    try testing.expectEqualStrings("{\"a\":1}", chunked.body);
    try testing.expectError(error.BadAnswer, parse(testing.allocator, "HTTP/1.0 200 OK\r\n\r\n"));
}

test "validUsername takes Mattermost's usernames" {
    for ([_][]const u8{ "alice", "a.b-c_d", "abc", "a23456789012345678901z" }) |good|
        try testing.expect(validUsername(good));
    for ([_][]const u8{ "", "ab", "Alice", "1abc", "a b", "a@b", "a234567890123456789012z" }) |bad|
        try testing.expect(!validUsername(bad));
}

test "address takes plain addresses" {
    try testing.expect(address("admin@example.com"));
    for ([_][]const u8{ "", "admin", "@example.com", "admin@", "a b@c", "a\"@b" }) |bad|
        try testing.expect(!address(bad));
}
