//! minecraft-init writes the server's files from the machine's settings
//! before each start. The properties stay the locked-down ones: whitelist
//! and online mode on, RCON and query off, the game port alone. Each
//! player name is resolved to the account Mojang has, so the whitelist
//! holds that account. A hand edit does not survive a start.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const settings_file = "/run/svc/minecraft/minecraft.json";
const data = "/data/svc/minecraft";
const properties_file = data ++ "/server.properties";
const whitelist_file = data ++ "/whitelist.json";
const eula_file = data ++ "/eula.txt";
const profile_url = "https://api.mojang.com/users/profiles/minecraft/";

const properties =
    \\server-port=25565
    \\server-ip=
    \\white-list=true
    \\enforce-whitelist=true
    \\online-mode=true
    \\enable-rcon=false
    \\enable-query=false
    \\enable-status=true
    \\motd=werewolf
    \\max-players=8
    \\view-distance=5
    \\simulation-distance=4
    \\
;

const Settings = struct {
    players: []const []const u8 = &.{},
};

const Profile = struct {
    id: []const u8,
    name: []const u8,
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
    if (s.players.len == 0) return error.NoPlayers;
    for (s.players, 0..) |name, i| {
        if (!playerName(name)) return error.BadPlayer;
        for (s.players[0..i]) |earlier|
            if (std.ascii.eqlIgnoreCase(name, earlier)) return error.RepeatedPlayer;
    }

    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    const now = Io.Clock.real.now(io);
    try client.ca_bundle.rescan(gpa, io, now);
    client.now = now;

    var profiles: std.ArrayList(Profile) = .empty;
    for (s.players) |name| try profiles.append(gpa, try lookup(gpa, &client, name));

    try replace(io, properties_file, properties);
    try replace(io, eula_file, "eula=true\n");
    try replace(io, whitelist_file, try whitelist(gpa, profiles.items));
    say(io, "{d} on the whitelist", .{profiles.items.len});
}

fn lookup(gpa: Allocator, client: *std.http.Client, name: []const u8) !Profile {
    var body: Io.Writer.Allocating = .init(gpa);
    const res = try client.fetch(.{
        .location = .{ .url = try std.mem.concat(gpa, u8, &.{ profile_url, name }) },
        .response_writer = &body.writer,
    });
    if (res.status == .not_found or res.status == .no_content) return error.NoSuchPlayer;
    if (res.status != .ok) return error.HttpStatus;
    const text = body.written();
    if (text.len > 4096) return error.HttpStatus;
    const profile = try std.json.parseFromSliceLeaky(Profile, gpa, text, .{});
    if (!std.ascii.eqlIgnoreCase(profile.name, name)) return error.NoSuchPlayer;
    _ = try formatUuid(profile.id);
    return profile;
}

fn playerName(name: []const u8) bool {
    if (name.len < 3 or name.len > 16) return false;
    for (name) |c| switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '_' => {},
        else => return false,
    };
    return true;
}

/// formatUuid inserts the hyphens Minecraft's whitelist wants. id is the
/// 32 hex characters Mojang returns.
fn formatUuid(id: []const u8) ![36]u8 {
    if (id.len != 32) return error.BadUuid;
    var out: [36]u8 = undefined;
    var i: usize = 0;
    var o: usize = 0;
    for ([_]usize{ 8, 4, 4, 4, 12 }, 0..) |n, group| {
        if (group > 0) {
            out[o] = '-';
            o += 1;
        }
        for (id[i..][0..n]) |c| {
            out[o] = std.ascii.toLower(c);
            if (!std.ascii.isHex(c)) return error.BadUuid;
            o += 1;
        }
        i += n;
    }
    return out;
}

fn whitelist(gpa: Allocator, profiles: []const Profile) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "[");
    for (profiles, 0..) |p, i| {
        if (i > 0) try out.append(gpa, ',');
        const uuid = try formatUuid(p.id);
        try out.print(gpa, "{{\"uuid\":\"{s}\",\"name\":\"{s}\"}}", .{ uuid[0..], p.name });
    }
    try out.appendSlice(gpa, "]\n");
    return out.items;
}

fn replace(io: Io, path: []const u8, body: []const u8) !void {
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(path).?, .{});
    defer dir.close(io);
    var tmp_buf: [64]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, ".{s}.tmp", .{std.fs.path.basename(path)});
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(
            io,
            tmp,
            .{ .exclusive = true, .permissions = .fromMode(0o600) },
        );
        defer f.close(io);
        try f.writeStreamingAll(io, body);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, std.fs.path.basename(path), io);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const line = std.mem.print(&buf, "minecraft-init: " ++ fmt ++ "\n", args) catch return;
    for (line[0 .. line.len - 1]) |*c| switch (c.*) {
        0...0x1f, 0x7f => c.* = '?',
        else => {},
    };
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

test "a player name is 3 to 16 of letters, digits and underscore" {
    try std.testing.expect(playerName("steve"));
    try std.testing.expect(playerName("Alex_2"));
    try std.testing.expect(!playerName("ab"));
    try std.testing.expect(!playerName("has space"));
    try std.testing.expect(!playerName(""));
}

test "a mojang id becomes a uuid" {
    const id = try formatUuid("8667ba71b85a4004af54457a9734eed7");
    try std.testing.expectEqualStrings("8667ba71-b85a-4004-af54-457a9734eed7", &id);
    try std.testing.expectError(error.BadUuid, formatUuid("short"));
    try std.testing.expectError(error.BadUuid, formatUuid("8667ba71b85a4004af54457a9734eedg"));
}
