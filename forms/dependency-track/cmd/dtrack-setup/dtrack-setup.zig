//! dtrack-setup replaces Dependency-Track's published administrator
//! password, admin/admin, with the config's, before Caddy opens the API.
//! It runs once: a later boot finds the mark and the new password.
//!
//!     dtrack-setup
//!
//! leash runs it as the caddy user (forms/dependency-track/form.yaml).
//! See forms/dependency-track/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const net = Io.net;

const password_path = "/run/svc/caddy/admin-password";
const done = "/data/svc/caddy/dtrack-setup-done";
const port = 8080;
const wait_seconds = 900;

const Response = struct { status: u16, body: []const u8 };

pub fn main(init: std.process.Init) void {
    const io = init.io;
    run(io, init.arena.allocator()) catch |err| {
        say(io, "{{\"event\":\"failed\",\"why\":\"{s}\"}}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator) !void {
    defer Dir.cwd().deleteFile(io, password_path) catch {};
    if (Dir.cwd().access(io, done, .{})) |_| {
        say(io, "{{\"event\":\"set up already\"}}", .{});
        return;
    } else |_| {}

    const text = Dir.cwd().readFileAlloc(io, password_path, gpa, .limited(4 << 10)) catch |err|
        switch (err) {
            error.FileNotFound => return error.NoAdminPassword,
            else => return err,
        };
    const password = std.mem.trimEnd(u8, text, "\r\n");
    if (password.len < 12 or password.len > 128) return error.AdminPasswordRefused;
    for (password) |c| if (c < 0x20 or c == 0x7f) return error.AdminPasswordRefused;

    try awaitApi(io, gpa);
    // Its login and forceChangePassword take form fields and return the
    // token as text. JSON is refused, and admin/admin does not yield a
    // token while the published password still has to be changed.
    const fresh = try formFields(gpa, "admin", password, null);
    if ((try login(io, gpa, fresh)).len != 0) {
        try mark(io);
        say(io, "{{\"event\":\"admin already set\"}}", .{});
        return;
    }
    const change = try formFields(gpa, "admin", "admin", password);
    const changed = try request(
        io,
        gpa,
        "POST",
        "/api/v1/user/forceChangePassword",
        null,
        form_type,
        change,
    );
    if (changed.status != 200) return error.PasswordNotChanged;
    if ((try login(io, gpa, fresh)).len == 0) return error.NewPasswordRefused;
    try mark(io);
    say(io, "{{\"event\":\"admin set\"}}", .{});
}

const form_type = "application/x-www-form-urlencoded";

fn formFields(
    gpa: Allocator,
    user: []const u8,
    password: []const u8,
    new_password: ?[]const u8,
) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "username=");
    try encode(gpa, &out, user);
    try out.appendSlice(gpa, "&password=");
    try encode(gpa, &out, password);
    if (new_password) |n| {
        try out.appendSlice(gpa, "&newPassword=");
        try encode(gpa, &out, n);
        try out.appendSlice(gpa, "&confirmPassword=");
        try encode(gpa, &out, n);
    }
    return out.items;
}

fn encode(gpa: Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
    const hex = "0123456789ABCDEF";
    for (s) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try out.append(gpa, c);
        } else {
            try out.appendSlice(gpa, &[_]u8{ '%', hex[c >> 4], hex[c & 0xf] });
        }
    }
}

/// login returns the session token, or an empty slice when the password is
/// refused. The token is the body itself. Any other answer is an error.
fn login(io: Io, gpa: Allocator, body: []const u8) ![]const u8 {
    const got = try request(io, gpa, "POST", "/api/v1/user/login", null, form_type, body);
    if (got.status == 401 or got.status == 403) return "";
    if (got.status != 200) return error.LoginRefused;
    const token = std.mem.trim(u8, got.body, " \t\r\n");
    if (!sessionToken(token)) return error.LoginAnswerNotUnderstood;
    return token;
}

/// sessionToken is whether token is a Dependency-Track 5 session: 32
/// random bytes, unpadded base64url.
fn sessionToken(token: []const u8) bool {
    if (token.len != 43) return false;
    for (token) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
    return true;
}

test "a session token is 32 bytes of unpadded base64url" {
    const token = "q1x9Zc-_" ++ "AAAAAAAAAA" ++ "AAAAAAAAAA" ++ "AAAAAAAAAA" ++ "AAAAA";
    try std.testing.expect(sessionToken(token));
    try std.testing.expect(!sessionToken(token[1..]));
    try std.testing.expect(!sessionToken(token[1..] ++ "="));
    try std.testing.expect(!sessionToken("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2ln"));
}

fn awaitApi(io: Io, gpa: Allocator) !void {
    var i: u32 = 0;
    while (i < wait_seconds) : (i += 1) {
        const got = request(io, gpa, "GET", "/api/version", null, null, null) catch {
            try io.sleep(.fromSeconds(1), .awake);
            continue;
        };
        if (got.status == 200) return;
        try io.sleep(.fromSeconds(1), .awake);
    }
    return error.ApiNotUp;
}

fn request(
    io: Io,
    gpa: Allocator,
    method: []const u8,
    path: []const u8,
    token: ?[]const u8,
    content_type: ?[]const u8,
    body: ?[]const u8,
) !Response {
    const addr = try net.IpAddress.parse("127.0.0.1", port);
    const s = try addr.connect(io, .{ .mode = .stream });
    defer s.close(io);
    var wbuf: [4096]u8 = undefined;
    var w = s.writer(io, &wbuf);
    const out = &w.interface;
    try out.print("{s} {s} HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAccept: */*\r\n" ++
        "Connection: close\r\n", .{ method, path, port });
    if (token) |t| try out.print("Authorization: Bearer {s}\r\n", .{t});
    const b = body orelse "";
    if (content_type) |ct| try out.print("Content-Type: {s}\r\n", .{ct});
    try out.print("Content-Length: {d}\r\n\r\n{s}", .{ b.len, b });
    try out.flush();
    var rbuf: [4096]u8 = undefined;
    var r = s.reader(io, &rbuf);
    return parse(gpa, try r.interface.allocRemaining(gpa, .limited(1 << 20)));
}

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

fn mark(io: Io) !void {
    var f = try Dir.cwd().createFile(io, done, .{ .permissions = .fromMode(0o600) });
    defer f.close(io);
    try f.writeStreamingAll(io, "Dependency-Track's administrator password is the config's.\n");
    try f.sync(io);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "dtrack-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "form fields encode reserved characters" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const body = try formFields(arena.allocator(), "admin", "a b&c", "n=1");
    try testing.expectEqualStrings(
        "username=admin&password=a%20b%26c&newPassword=n%3D1&confirmPassword=n%3D1",
        body,
    );
}

test "parse reads the status and joins chunks" {
    const plain = try parse(testing.allocator, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
    try testing.expectEqual(200, plain.status);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const chunked = try parse(
        arena.allocator(),
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n",
    );
    try testing.expectEqualStrings("{\"a\":1}", chunked.body);
}
