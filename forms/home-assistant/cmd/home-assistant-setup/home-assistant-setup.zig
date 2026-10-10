//! home-assistant-setup prepares Home Assistant's configuration directory
//! before each start, inside its image: configuration.yaml, rewritten; on
//! the first start, the owner and a finished onboarding, so no visitor is
//! offered either; and at every start, the owner's password the config's.
//!
//!     home-assistant-setup
//!
//! leash runs it as _oci-home-assistant, before Home Assistant
//! (forms/home-assistant/form.yaml). See forms/home-assistant/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const bcrypt = std.crypto.pwhash.bcrypt;
const b64 = std.base64.standard;

/// config is Home Assistant's configuration directory, the service's /data.
const config = "/data";
const storage = config ++ "/.storage";
/// password is leash's copy of the config's, in the image's /tmp.
const password_copy = "/tmp/owner-password";

/// configuration is configuration.yaml, written at each start, so the
/// image decides it: what is set up in the UI lives in .storage instead.
const configuration =
    \\# Home Assistant on the home-assistant form. home-assistant-setup
    \\# writes this file at each start: an edit here does not last. What is
    \\# set up in the UI is kept in .storage. See forms/home-assistant/README.md.
    \\
    \\# Behind Caddy, on loopback: Caddy says who the client is. An address
    \\# that fails to log in five times is banned (ip_bans.yaml).
    \\http:
    \\  server_host: 127.0.0.1
    \\  server_port: 8123
    \\  use_x_forwarded_for: true
    \\  trusted_proxies: 127.0.0.1
    \\  ip_ban_enabled: true
    \\  login_attempts_threshold: 5
    \\
    \\# default_config, but for discovery (dhcp, ssdp, zeroconf), which needs
    \\# multicast; bluetooth and usb, which need devices; and go2rtc, which
    \\# would start a program of its own.
    \\assist_pipeline:
    \\backup:
    \\cloud:
    \\conversation:
    \\energy:
    \\file:
    \\history:
    \\homeassistant_alerts:
    \\logbook:
    \\media_source:
    \\mobile_app:
    \\my:
    \\stream:
    \\sun:
    \\usage_prediction:
    \\webhook:
    \\
    \\# The UI's editors write these.
    \\automation: !include automations.yaml
    \\script: !include scripts.yaml
    \\scene: !include scenes.yaml
    \\
;

/// Settings are what the machine's config says, from the environment
/// service-config renders.
const Settings = struct {
    owner: []const u8,
    domain: ?[]const u8 = null,
    time_zone: []const u8 = "UTC",
    latitude: f64 = 52.3731339,
    longitude: f64 = 4.8903147,
    country: ?[]const u8 = null,
    unit_system: []const u8 = "metric",
};

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa, init.minimal.environ) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const s = try settings(io, gpa, environ);
    const text = Dir.cwd().readFileAlloc(io, password_copy, gpa, .limited(4 << 10)) catch |err|
        switch (err) {
            error.FileNotFound => return error.NoOwnerPassword,
            else => return err,
        };
    const password = std.mem.trimEnd(u8, text, "\r\n");
    // bcrypt reads 72 bytes; Home Assistant's refuses more.
    if (password.len < 12) return error.OwnerPasswordTooShort;
    if (password.len > 72) return error.OwnerPasswordTooLong;

    try replace(io, config ++ "/configuration.yaml", configuration, 0o600);
    for ([_][2][]const u8{
        .{ "automations.yaml", "[]\n" },
        .{ "scripts.yaml", "{}\n" },
        .{ "scenes.yaml", "[]\n" },
    }) |f| {
        const p = try std.mem.concat(gpa, u8, &.{ config, "/", f[0] });
        if (!try exists(io, p)) try replace(io, p, f[1], 0o600);
    }
    try Dir.cwd().createDirPath(io, storage);
    if (try exists(io, storage ++ "/auth"))
        try keepPassword(io, gpa, s.owner, password)
    else
        try firstStart(io, gpa, s, password);
    Dir.cwd().deleteFile(io, password_copy) catch |err|
        say(io, "{s} not removed: {s}", .{ password_copy, @errorName(err) });
}

/// settings reads and checks the machine's settings: Home Assistant would
/// stop at a bad one, with its reason deep in its log.
fn settings(io: Io, gpa: Allocator, environ: std.process.Environ) !Settings {
    var s: Settings = .{ .owner = setting(gpa, environ, "OWNER") orelse return error.NoOwner };
    if (!name(s.owner)) return error.OwnerNotAName;
    if (setting(gpa, environ, "DOMAIN")) |d| s.domain = d;
    if (setting(gpa, environ, "TIME_ZONE")) |tz| {
        if (!zone(tz)) return error.TimeZoneNotAName;
        const p = try std.mem.concat(gpa, u8, &.{ "/usr/share/zoneinfo/", tz });
        if (!try exists(io, p)) return error.TimeZoneUnknown;
        s.time_zone = tz;
    }
    if (setting(gpa, environ, "LATITUDE")) |v| s.latitude = try degrees(v, 90);
    if (setting(gpa, environ, "LONGITUDE")) |v| s.longitude = try degrees(v, 180);
    if (setting(gpa, environ, "COUNTRY")) |c| {
        if (c.len != 2 or !std.ascii.isUpper(c[0]) or !std.ascii.isUpper(c[1]))
            return error.CountryNotTwoCapitals;
        s.country = c;
    }
    if (setting(gpa, environ, "UNIT_SYSTEM")) |u| {
        if (!std.mem.eql(u8, u, "metric") and !std.mem.eql(u8, u, "us_customary"))
            return error.UnitSystemNotMetricOrUsCustomary;
        s.unit_system = u;
    }
    return s;
}

/// setting returns the environment's value for key, or null if it is
/// unset or empty.
fn setting(gpa: Allocator, environ: std.process.Environ, key: []const u8) ?[]const u8 {
    const v = environ.getAlloc(gpa, key) catch return null;
    return if (v.len > 0) v else null;
}

/// degrees parses a latitude or longitude no further than limit from 0.
fn degrees(v: []const u8, limit: f64) !f64 {
    const d = std.fmt.parseFloat(f64, v) catch return error.NotDegrees;
    if (!std.math.isFinite(d) or @abs(d) > limit) return error.DegreesOutOfRange;
    return d;
}

/// firstStart makes the owner, an administrator, with the config's
/// password, and marks every onboarding step done, so Home Assistant never
/// offers onboarding to whoever reaches it first. Its location, units and
/// time zone are the settings', and later the UI's. auth is written last:
/// it is what says the first start is over.
fn firstStart(io: Io, gpa: Allocator, s: Settings, password: []const u8) !void {
    const user = try id(io);
    const credential = try id(io);
    try replace(io, storage ++ "/auth_provider.homeassistant", try provider(gpa, &.{.{
        .username = s.owner,
        .password = try hash(io, gpa, password),
    }}), 0o600);
    try replace(io, storage ++ "/core.config", try coreConfig(gpa, s), 0o600);
    try replace(io, storage ++ "/onboarding", onboarding, 0o600);
    try replace(io, storage ++ "/auth", try auth(gpa, s.owner, &user, &credential), 0o600);
    say(io, "made the owner, {s}; onboarding is done", .{s.owner});
}

/// keepPassword makes the owner's password the config's again, if it was
/// changed since: the config is how a forgotten one is reset.
fn keepPassword(io: Io, gpa: Allocator, owner: []const u8, password: []const u8) !void {
    const p = storage ++ "/auth_provider.homeassistant";
    const text = try Dir.cwd().readFileAlloc(io, p, gpa, .limited(1 << 20));
    const stored = try std.json.parseFromSliceLeaky(Provider, gpa, text, .{
        .ignore_unknown_fields = true,
    });
    for (stored.data.users) |*u| {
        if (!std.mem.eql(u8, u.username, owner)) continue;
        var buf: [128]u8 = undefined;
        const n = b64.Decoder.calcSizeForSlice(u.password) catch 0;
        if (n > 0 and n <= buf.len) if (b64.Decoder.decode(buf[0..n], u.password)) |_| {
            if (bcrypt.strVerify(buf[0..n], password, .{ .silently_truncate_password = true }))
                return
            else |_| {}
        } else |_| {};
        u.password = try hash(io, gpa, password);
        try replace(io, p, try provider(gpa, stored.data.users), 0o600);
        say(io, "{s}'s password set from the config", .{owner});
        return;
    }
    say(io, "{s} has no login here: the owner is whoever the first start made", .{owner});
}

/// Provider is Home Assistant's own logins, .storage/auth_provider.homeassistant.
const Provider = struct {
    data: struct { users: []Login },
};
const Login = struct { username: []const u8, password: []const u8 };

/// provider returns the logins as Home Assistant stores them.
fn provider(gpa: Allocator, users: []const Login) ![]const u8 {
    return std.json.Stringify.valueAlloc(gpa, .{
        .version = 1,
        .minor_version = 1,
        .key = "auth_provider.homeassistant",
        .data = .{ .users = users },
    }, .{ .whitespace = .indent_2 });
}

/// hash returns password's bcrypt hash, base64 as Home Assistant stores
/// it, at its own cost.
fn hash(io: Io, gpa: Allocator, password: []const u8) ![]const u8 {
    var buf: [bcrypt.hash_length]u8 = undefined;
    const h = try bcrypt.strHash(password, .{
        .params = .{ .rounds_log = 12, .silently_truncate_password = true },
        .encoding = .crypt,
    }, &buf, io);
    const out = try gpa.alloc(u8, b64.Encoder.calcSize(h.len));
    return b64.Encoder.encode(out, h);
}

/// auth returns Home Assistant's users: the owner, an administrator, with
/// one login, and the three groups it makes itself.
fn auth(gpa: Allocator, owner: []const u8, user: []const u8, credential: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(gpa, .{
        .version = 1,
        .minor_version = 1,
        .key = "auth",
        .data = .{
            .users = .{.{
                .id = user,
                .group_ids = .{"system-admin"},
                .is_owner = true,
                .is_active = true,
                .name = owner,
                .system_generated = false,
                .local_only = false,
            }},
            .groups = .{
                .{ .id = "system-admin", .name = "Administrators" },
                .{ .id = "system-users", .name = "Users" },
                .{ .id = "system-read-only", .name = "Read Only" },
            },
            .credentials = .{.{
                .id = credential,
                .user_id = user,
                .auth_provider_type = "homeassistant",
                .auth_provider_id = null,
                .data = .{ .username = owner },
            }},
            .refresh_tokens = .{},
        },
    }, .{ .whitespace = .indent_2 });
}

/// coreConfig returns the location, units and time zone, as the UI's
/// General settings keep them.
fn coreConfig(gpa: Allocator, s: Settings) ![]const u8 {
    return std.json.Stringify.valueAlloc(gpa, .{
        .version = 1,
        .minor_version = 4,
        .key = "core.config",
        .data = .{
            .latitude = s.latitude,
            .longitude = s.longitude,
            .elevation = 0,
            .unit_system_v2 = s.unit_system,
            .location_name = "Home",
            .time_zone = s.time_zone,
            .external_url = if (s.domain) |d| try std.mem.concat(gpa, u8, &.{ "https://", d }) else null,
            .internal_url = null,
            .currency = "EUR",
            .country = s.country,
            .language = "en",
            .radius = 100,
        },
    }, .{ .whitespace = .indent_2 });
}

/// onboarding says every step is done: the owner, the location, the
/// analytics choice (none: analytics stay off) and the integrations.
const onboarding =
    \\{
    \\  "version": 4,
    \\  "minor_version": 1,
    \\  "key": "onboarding",
    \\  "data": {
    \\    "done": ["user", "core_config", "analytics", "integration"]
    \\  }
    \\}
    \\
;

/// id returns a random id as Home Assistant makes them: 32 hex digits.
fn id(io: Io) ![32]u8 {
    var r: [16]u8 = undefined;
    io.random(&r);
    return std.fmt.bytesToHex(r, .lower);
}

/// name reports whether s is a plain user name: lower-case ASCII letters
/// and digits, with dots, hyphens and underscores between them. Home
/// Assistant folds a login's case, so an upper-case one would not match.
fn name(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    for (s, 0..) |c, i| switch (c) {
        'a'...'z', '0'...'9' => {},
        '.', '-', '_' => if (i == 0 or i == s.len - 1) return false,
        else => return false,
    };
    return true;
}

/// zone reports whether s can name a zone in the tz database, as
/// Europe/Berlin does, and no path outside it.
fn zone(s: []const u8) bool {
    if (s.len == 0 or s.len > 64 or s[0] == '/' or std.mem.find(u8, s, "..") != null)
        return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, "/_+-", c) == null)
        return false;
    return true;
}

fn exists(io: Io, path: []const u8) !bool {
    Dir.cwd().access(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
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
    const line = std.mem.print(&buf, "home-assistant-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "hash is base64 of a bcrypt hash that verifies" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const h = try hash(testing.io, a, "a long owner password");
    const raw = try a.alloc(u8, try b64.Decoder.calcSizeForSlice(h));
    try b64.Decoder.decode(raw, h);
    try testing.expect(std.mem.startsWith(u8, raw, "$2b$12$"));
    try bcrypt.strVerify(raw, "a long owner password", .{ .silently_truncate_password = true });
}

test "auth makes the one owner an administrator with one login" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const user = "0123456789abcdef0123456789abcdef";
    const a = try auth(arena.allocator(), "owner", user, "fedcba9876543210fedcba9876543210");
    for ([_][]const u8{
        "\"is_owner\": true",
        "\"system-admin\"",
        "\"auth_provider_type\": \"homeassistant\"",
        "\"auth_provider_id\": null",
        "\"user_id\": \"" ++ user ++ "\"",
        "\"refresh_tokens\": []",
    }) |want| try testing.expect(std.mem.find(u8, a, want) != null);
}

test "coreConfig keeps the settings and leaves unset ones null" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const c = try coreConfig(arena.allocator(), .{ .owner = "owner" });
    try testing.expect(std.mem.find(u8, c, "\"external_url\": null") != null);
    try testing.expect(std.mem.find(u8, c, "\"time_zone\": \"UTC\"") != null);
    const d = try coreConfig(arena.allocator(), .{ .owner = "o", .domain = "ha.example.com" });
    try testing.expect(std.mem.find(u8, d, "\"external_url\": \"https://ha.example.com\"") != null);
}

test "name, zone and degrees refuse what Home Assistant would" {
    try testing.expect(name("owner"));
    for ([_][]const u8{ "", "Owner", "a b", "-a", "a\"" }) |bad| try testing.expect(!name(bad));
    try testing.expect(zone("Europe/Berlin"));
    try testing.expect(zone("America/Argentina/Buenos_Aires"));
    for ([_][]const u8{ "", "/etc/passwd", "../x", "a b" }) |bad| try testing.expect(!zone(bad));
    try testing.expectEqual(52.5, try degrees("52.5", 90));
    try testing.expectError(error.DegreesOutOfRange, degrees("91", 90));
    try testing.expectError(error.NotDegrees, degrees("north", 90));
}
