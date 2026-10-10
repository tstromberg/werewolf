//! loki-auth writes the basic_auth block Caddy imports in front of Loki,
//! before each start: the user from the machine's settings and a bcrypt
//! hash of the config's password, whose copy it then removes.
//!
//!     loki-auth
//!
//! leash runs it as the caddy user, before Caddy validates its
//! configuration (forms/loki/form.yaml). See forms/loki/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const bcrypt = std.crypto.pwhash.bcrypt;

const run_dir = "/run/svc/caddy";
/// password is leash's copy of the config's.
const password = run_dir ++ "/loki-password";
/// auth is what the Caddyfile imports.
const auth = run_dir ++ "/loki-auth.caddy";

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa, init.minimal.environ) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const user = environ.getAlloc(gpa, "LOKI_USER") catch return error.NoUser;
    if (!name(user)) return error.UserNotAName;
    const text = Dir.cwd().readFileAlloc(
        io,
        password,
        gpa,
        .limited(4 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => return error.NoPassword,
        else => return err,
    };
    const secret = std.mem.trimEnd(u8, text, "\r\n");
    // bcrypt reads 72 bytes; Go's, which Caddy checks it with, refuses more.
    if (secret.len < 12) return error.PasswordTooShort;
    if (secret.len > 72) return error.PasswordTooLong;
    var buf: [bcrypt.hash_length]u8 = undefined;
    const hash = try bcrypt.strHash(secret, .{
        .params = .{ .rounds_log = 10, .silently_truncate_password = true },
        .encoding = .crypt,
    }, &buf, io);
    try replace(io, auth, try block(gpa, user, hash), 0o600);
    Dir.cwd().deleteFile(io, password) catch |err|
        say(io, "{s} not removed: {s}", .{ password, @errorName(err) });
    say(io, "Loki's push and query APIs take {s}, by its password", .{user});
}

/// block returns the Caddyfile basic_auth block for user and hash.
fn block(gpa: Allocator, user: []const u8, hash: []const u8) ![]const u8 {
    return gpa.print("# Written by loki-auth at each start " ++
        "(forms/loki/README.md).\n" ++
        "basic_auth {{\n\t{s} {s}\n}}\n", .{ user, hash });
}

/// name reports whether s is a plain user name: lower-case ASCII letters
/// and digits, with dots, hyphens and underscores between them.
fn name(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    for (s, 0..) |c, i| switch (c) {
        'a'...'z', '0'...'9' => {},
        '.', '-', '_' => if (i == 0 or i == s.len - 1) return false,
        else => return false,
    };
    return true;
}

/// replace writes p whole or not at all: a temporary file, synced, then
/// renamed over it.
fn replace(io: Io, p: []const u8, data: []const u8, mode: std.posix.mode_t) !void {
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(p).?, .{ .iterate = true });
    defer dir.close(io);
    const base = std.fs.path.basename(p);
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, ".{s}.tmp", .{base});
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(io, tmp, .{ .exclusive = true, .permissions = .fromMode(mode) });
        defer f.close(io);
        try f.writeStreamingAll(io, data);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, base, io);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "loki-auth: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "block is one user and its hash in Caddy's basic_auth" {
    const b = try block(testing.allocator, "alloy", "$2b$10$abc/def");
    defer testing.allocator.free(b);
    try testing.expect(std.mem.endsWith(u8, b, "basic_auth {\n\talloy $2b$10$abc/def\n}\n"));
}

test "name takes plain user names" {
    try testing.expect(name("alloy"));
    try testing.expect(name("grafana.reader"));
    for ([_][]const u8{
        "",
        "Alloy",
        "a b",
        "a}",
        "a\nb",
        "-a",
    }) |bad| try testing.expect(!name(bad));
}
