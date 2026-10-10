//! galene-setup writes Galène's configuration from the machine's settings
//! and config before each start: a group file for each group the settings
//! name, the operator's and the others' passwords in it as bcrypt hashes,
//! the URL Caddy serves it at, and the ICE servers the config may bring.
//!
//!     galene-setup
//!
//! leash runs it as the galene user, under the service's Landlock rules,
//! after service-config has written the settings (forms/galene/form.yaml).
//! See forms/galene/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const bcrypt = std.crypto.pwhash.bcrypt;

/// run_dir holds leash's copies of the config's files and the settings,
/// made each start, and the group files written from them.
const run_dir = "/run/svc/galene";
const settings_file = run_dir ++ "/galene.json";
const operator_password = run_dir ++ "/operator-password";
const others_password = run_dir ++ "/password";
const ice_config = run_dir ++ "/ice-servers";
const groups_dir = run_dir ++ "/groups";
/// data_dir keeps what outlives a start: the tokens an operator hands out.
const data_dir = "/data/svc/galene/data";
const recordings_dir = "/data/svc/galene/recordings";

/// Settings are the machine's, as service-config renders them.
const Settings = struct {
    @"base-url": []const u8 = "",
    groups: []const []const u8 = &.{},
    operator: []const u8 = "",
    recording: bool = false,
};

const Password = struct { type: []const u8 = "bcrypt", key: []const u8 };
const User = struct { password: Password, permissions: []const u8 };

/// Group is a Galène group file: never listed publicly, no anonymous
/// joining, the operator by name and the others, if a password lets them
/// in, under any name.
const Group = struct {
    users: std.json.ArrayHashMap(User),
    @"wildcard-user": ?User = null,
    @"allow-recording": bool = false,
};

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator) !void {
    const text = try Dir.cwd().readFileAlloc(io, settings_file, gpa, .limited(64 << 10));
    const s = try std.json.parseFromSliceLeaky(
        Settings,
        gpa,
        text,
        .{ .ignore_unknown_fields = true },
    );
    if (!std.mem.startsWith(u8, s.@"base-url", "https://")) return error.BaseUrlNotHttps;
    if (s.operator.len == 0) return error.NoOperator;
    if (s.groups.len == 0) return error.NoGroups;
    for (s.groups, 0..) |g, i| {
        if (!groupName(g)) return error.BadGroupName;
        for (s.groups[0..i]) |h| if (std.mem.eql(u8, g, h)) return error.RepeatedGroup;
    }

    // bcrypt reads 72 bytes; Go's, which checks them, refuses more.
    const op = try secret(io, gpa, operator_password) orelse return error.NoOperatorPassword;
    if (op.len < 12 or op.len > 72) return error.OperatorPasswordNot12To72Bytes;
    const others = try secret(io, gpa, others_password);
    if (others) |p| if (p.len < 8 or p.len > 72) return error.PasswordNot8To72Bytes;

    var users: std.json.ArrayHashMap(User) = .{};
    try users.map.put(
        gpa,
        s.operator,
        .{ .password = .{ .key = try hash(io, gpa, op) }, .permissions = "op" },
    );
    const group = try std.json.Stringify.valueAlloc(gpa, Group{
        .users = users,
        .@"wildcard-user" = if (others) |p|
            .{ .password = .{ .key = try hash(io, gpa, p) }, .permissions = "present" }
        else
            null,
        .@"allow-recording" = s.recording,
    }, .{ .emit_null_optional_fields = false, .whitespace = .indent_2 });

    try Dir.cwd().createDirPath(io, groups_dir);
    for (s.groups) |name|
        try replace(io, try std.mem.concat(gpa, u8, &.{ groups_dir, "/", name, ".json" }), group);
    try prune(io, gpa, s.groups);

    try Dir.cwd().createDirPath(io, data_dir);
    try Dir.cwd().createDirPath(io, recordings_dir);
    const url = s.@"base-url";
    const slash = if (std.mem.endsWith(u8, url, "/")) "" else "/";
    try replace(io, data_dir ++ "/config.json", try std.json.Stringify.valueAlloc(
        gpa,
        .{ .proxyURL = try std.mem.concat(gpa, u8, &.{ url, slash }) },
        .{},
    ));
    const ice = try iceServers(io, gpa);

    say(io, "groups {s}: operator {s}, others {s}, recording {s}, ICE servers {s}", .{
        try std.mem.join(gpa, ", ", s.groups),
        s.operator,
        if (others != null) "by password" else "none",
        if (s.recording) "allowed" else "off",
        if (ice) "from the config" else "none",
    });
}

/// groupName reports whether name is a group Galène serves at /group/NAME/
/// and a file name: letters, digits, dots, hyphens and underscores, not
/// starting with a dot.
fn groupName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64 or name[0] == '.') return false;
    for (name) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '-', '_' => {},
        else => return false,
    };
    return true;
}

/// hash returns password's bcrypt hash in the crypt format Go's bcrypt
/// reads, made anew each start.
fn hash(io: Io, gpa: Allocator, password: []const u8) ![]const u8 {
    var buf: [bcrypt.hash_length]u8 = undefined;
    const h = try bcrypt.strHash(password, .{
        .params = .{ .rounds_log = 10, .silently_truncate_password = false },
        .encoding = .crypt,
    }, &buf, io);
    return gpa.dupe(u8, h);
}

/// prune removes the group files of groups the settings no longer name.
fn prune(io: Io, gpa: Allocator, groups: []const []const u8) !void {
    var dir = try Dir.cwd().openDir(io, groups_dir, .{ .iterate = true });
    defer dir.close(io);
    var gone: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    next: while (try it.next(io)) |e| {
        for (groups) |g| if (e.name.len == g.len + 5 and std.mem.startsWith(u8, e.name, g) and
            std.mem.endsWith(u8, e.name, ".json")) continue :next;
        try gone.append(gpa, try gpa.dupe(u8, e.name));
    }
    for (gone.items) |name| try dir.deleteFile(io, name);
}

/// iceServers writes the config's ICE servers (an external TURN server)
/// where Galène reads them, or removes an old file. It reports whether
/// there are any.
fn iceServers(io: Io, gpa: Allocator) !bool {
    const path = data_dir ++ "/ice-servers.json";
    const text = try secret(io, gpa, ice_config) orelse {
        Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        return false;
    };
    const v = std.json.parseFromSliceLeaky(std.json.Value, gpa, text, .{}) catch
        return error.IceServersNotJson;
    if (v != .array) return error.IceServersNotAList;
    try replace(io, path, text);
    return true;
}

/// secret reads a file leash copied from the config and removes the copy:
/// it is needed here alone. null if the config has none.
fn secret(io: Io, gpa: Allocator, path: []const u8) !?[]const u8 {
    const text = Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        .limited(64 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    Dir.cwd().deleteFile(io, path) catch |err|
        say(io, "{s} not removed: {s}", .{ path, @errorName(err) });
    return std.mem.trimEnd(u8, text, "\r\n");
}

/// replace writes path whole or not at all, 0600: a temporary file, synced,
/// then renamed over it.
fn replace(io: Io, path: []const u8, data: []const u8) !void {
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(path).?, .{});
    defer dir.close(io);
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, ".{s}.tmp", .{std.fs.path.basename(path)});
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(
            io,
            tmp,
            .{ .exclusive = true, .permissions = .fromMode(0o600) },
        );
        defer f.close(io);
        try f.writeStreamingAll(io, data);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, std.fs.path.basename(path), io);
}

/// say prints one line to the console, control bytes as "?".
fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "galene-setup: " ++ fmt ++ "\n", args) catch return;
    for (line[0 .. line.len - 1]) |*c| switch (c.*) {
        0...0x1f, 0x7f => c.* = '?',
        else => {},
    };
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "groupName takes names Galène serves and files hold" {
    for ([_][]const u8{ "lecture", "cs101", "Physics-2", "a.b_c" }) |n|
        try testing.expect(groupName(n));
    const long: [65]u8 = @splat('x');
    for ([_][]const u8{ "", ".hidden", "a/b", "..", "a b", &long }) |n|
        try testing.expect(!groupName(n));
}

test "a group file: the operator by name, the others by password, nothing public" {
    const a = testing.allocator;
    var users: std.json.ArrayHashMap(User) = .{};
    defer users.deinit(a);
    try users.map.put(a, "ada", .{ .password = .{ .key = "$2b$10$x" }, .permissions = "op" });
    const text = try std.json.Stringify.valueAlloc(a, Group{
        .users = users,
        .@"wildcard-user" = .{ .password = .{ .key = "$2b$10$y" }, .permissions = "present" },
    }, .{ .emit_null_optional_fields = false });
    defer a.free(text);
    try testing.expectEqualStrings(
        \\{"users":{"ada":{"password":{"type":"bcrypt","key":"$2b$10$x"},"permissions":"op"}},
    ++
        \\"wildcard-user":{"password":{"type":"bcrypt","key":"$2b$10$y"},"permissions":"present"},
    ++
        \\"allow-recording":false}
    , text);
}

test "bcrypt hashes in the crypt format Go's bcrypt reads" {
    const h = try hash(testing.io, testing.allocator, "a long operator password");
    defer testing.allocator.free(h);
    try testing.expect(std.mem.startsWith(u8, h, "$2b$10$"));
    try bcrypt.strVerify(h, "a long operator password", .{ .silently_truncate_password = false });
}
