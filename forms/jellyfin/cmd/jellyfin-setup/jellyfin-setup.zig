//! jellyfin-setup prepares Jellyfin in two steps of the machine's start:
//!
//!     jellyfin-setup network   before Jellyfin, as jellyfin
//!     jellyfin-setup wizard    before Caddy, as caddy
//!
//! network makes Jellyfin's directories and, once, its network.xml:
//! loopback alone, Caddy its one proxy, no discovery and no UPnP. wizard
//! waits for Jellyfin on loopback and, while its first-run wizard is open,
//! completes it with the administrator from the machine's settings and
//! config and adds the media library. Caddy, and so anyone, reaches
//! Jellyfin only after. See forms/jellyfin/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const home = "/data/svc/jellyfin";
const media = home ++ "/media";
const network_xml = home ++ "/config/network.xml";
const jellyfin = "http://127.0.0.1:8096";
/// password is leash's copy of the config's, in Caddy's directory.
const password_file = "/run/svc/caddy/jellyfin-password";
/// wait is how long the wizard step waits for Jellyfin, whose first start
/// makes its database.
const wait_seconds = 600;
/// client names this program to Jellyfin, which wants a client, a device
/// and a version on every authentication.
const client = "MediaBrowser Client=\"werewolf\", Device=\"jellyfin-setup\", " ++
    "DeviceId=\"jellyfin-setup\", Version=\"1\"";

/// network_config is what Jellyfin is told once; it keeps it, and rewrites
/// the file with its defaults for the rest. fence holds it to loopback
/// whatever the file later says.
const network_config =
    \\<?xml version="1.0" encoding="utf-8"?>
    \\<NetworkConfiguration>
    \\  <InternalHttpPort>8096</InternalHttpPort>
    \\  <AutoDiscovery>false</AutoDiscovery>
    \\  <EnableUPnP>false</EnableUPnP>
    \\  <EnableIPv6>false</EnableIPv6>
    \\  <EnableRemoteAccess>true</EnableRemoteAccess>
    \\  <LocalNetworkAddresses>
    \\    <string>127.0.0.1</string>
    \\  </LocalNetworkAddresses>
    \\  <KnownProxies>
    \\    <string>127.0.0.1</string>
    \\  </KnownProxies>
    \\</NetworkConfiguration>
    \\
;

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = init.minimal.args.toSlice(gpa) catch std.process.exit(1);
    const step = if (args.len == 2) args[1] else "";
    const result = if (std.mem.eql(u8, step, "network"))
        network(io)
    else if (std.mem.eql(u8, step, "wizard"))
        wizard(io, gpa, init.minimal.environ)
    else {
        say(io, "usage: jellyfin-setup network|wizard", .{});
        std.process.exit(1);
    };
    result catch |err| {
        say(io, "{s}: {s}", .{ step, @errorName(err) });
        std.process.exit(1);
    };
}

/// network makes Jellyfin's directories and its network.xml, once.
fn network(io: Io) !void {
    for ([_][]const u8{ "config", "data", "cache", "media" }) |sub| {
        var dir = try Dir.cwd().openDir(io, home, .{});
        defer dir.close(io);
        dir.createDir(io, sub, .fromMode(0o755)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
    if (Dir.cwd().access(io, network_xml, .{})) return else |_| {}
    try Dir.cwd().writeFile(io, .{ .sub_path = network_xml, .data = network_config });
    say(io, "network.xml written: loopback alone, Caddy its proxy, no discovery or UPnP", .{});
}

/// wizard completes Jellyfin's first-run wizard, if it is open, before
/// Caddy lets anyone reach it.
fn wizard(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const admin = environ.getAlloc(gpa, "JELLYFIN_ADMIN") catch return error.NoAdmin;
    const text = Dir.cwd().readFileAlloc(
        io,
        password_file,
        gpa,
        .limited(4 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => return error.NoPassword,
        else => return err,
    };
    const password = std.mem.trimEnd(u8, text, "\r\n");
    if (password.len < 12) return error.PasswordTooShort;
    defer Dir.cwd().deleteFile(io, password_file) catch |err|
        say(io, "{s} not removed: {s}", .{ password_file, @errorName(err) });

    var http: std.http.Client = .{ .allocator = gpa, .io = io };
    defer http.deinit();
    const info = try waitFor(io, gpa, &http);
    if (std.mem.find(u8, info, "\"StartupWizardCompleted\":true") != null) {
        say(io, "Jellyfin is set up; Caddy may serve it", .{});
        return;
    }
    if (std.mem.find(u8, info, "\"StartupWizardCompleted\":false") == null)
        return error.NoWizardState;

    say(io, "Jellyfin's first-run wizard is open; completing it on loopback", .{});
    _ = try call(gpa, &http, .GET, "/Startup/User", null, null, .ok);
    _ = try call(gpa, &http, .POST, "/Startup/Configuration", try json(gpa, .{
        .UICulture = "en-US",
        .MetadataCountryCode = "US",
        .PreferredMetadataLanguage = "en",
    }), null, .no_content);
    _ = try call(gpa, &http, .POST, "/Startup/User", try json(gpa, .{
        .Name = admin,
        .Password = password,
    }), null, .no_content);
    _ = try call(gpa, &http, .POST, "/Startup/RemoteAccess", try json(gpa, .{
        .EnableRemoteAccess = true,
    }), null, .no_content);
    _ = try call(gpa, &http, .POST, "/Startup/Complete", null, null, .no_content);

    const auth = try call(gpa, &http, .POST, "/Users/AuthenticateByName", try json(gpa, .{
        .Username = admin,
        .Pw = password,
    }), client, .ok);
    const token = field(auth, "AccessToken") orelse return error.NoAccessToken;
    const header = try gpa.print("MediaBrowser Token=\"{s}\"", .{token});
    _ = try call(
        gpa,
        &http,
        .POST,
        "/Library/VirtualFolders?name=Media&paths=%2Fdata%2Fsvc%2Fjellyfin%2Fmedia&refreshLibrar" ++
            "y=true",
        "{}",
        header,
        .no_content,
    );
    say(io, "set up: administrator {s}, library Media in {s}", .{ admin, media });
}

/// waitFor asks Jellyfin's public information until it answers, and
/// returns it.
fn waitFor(io: Io, gpa: Allocator, http: *std.http.Client) ![]const u8 {
    var tries: usize = 0;
    while (true) : (tries += 1) {
        // While it starts, Jellyfin serves a page of its own on the same
        // port, which says nothing of the wizard.
        if (call(gpa, http, .GET, "/System/Info/Public", null, null, .ok)) |body| {
            if (std.mem.find(u8, body, "\"StartupWizardCompleted\":") != null) return body;
        } else |_| {}
        if (tries == wait_seconds) return error.JellyfinDidNotAnswer;
        if (tries % 30 == 0) say(io, "waiting for Jellyfin on loopback", .{});
        io.sleep(.fromSeconds(1), .awake) catch {};
    }
}

/// call sends one request to Jellyfin and returns its body, or fails if
/// the status is not want.
fn call(
    gpa: Allocator,
    http: *std.http.Client,
    method: std.http.Method,
    path: []const u8,
    body: ?[]const u8,
    authorization: ?[]const u8,
    want: std.http.Status,
) ![]const u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    const url = try std.mem.concat(gpa, u8, &.{ jellyfin, path });
    const res = try http.fetch(.{
        .location = .{ .url = url },
        .method = method,
        // std.http asserts a POST has a body: an empty one, then.
        .payload = body orelse if (method == .POST) "" else null,
        .headers = .{
            .content_type = if (body != null) .{ .override = "application/json" } else .default,
            .authorization = if (authorization) |a| .{ .override = a } else .default,
        },
        .response_writer = &out.writer,
        .keep_alive = false,
    });
    if (res.status != want) return error.UnexpectedStatus;
    return out.written();
}

/// json returns value as JSON, so a name or password is quoted as it must be.
fn json(gpa: Allocator, value: anytype) ![]const u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    try std.json.Stringify.value(value, .{}, &out.writer);
    return out.written();
}

/// field returns the string value of "name" in a JSON object's text.
fn field(text: []const u8, name: []const u8) ?[]const u8 {
    var buf: [64]u8 = undefined;
    const key = std.mem.print(&buf, "\"{s}\":\"", .{name}) catch return null;
    const at = std.mem.find(u8, text, key) orelse return null;
    const rest = text[at + key.len ..];
    const end = std.mem.findScalar(u8, rest, '"') orelse return null;
    return rest[0..end];
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "jellyfin-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "json quotes what a name or password holds" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const j = try json(arena.allocator(), .{ .Name = "a\"b", .Password = "c\\d" });
    try testing.expectEqualStrings("{\"Name\":\"a\\\"b\",\"Password\":\"c\\\\d\"}", j);
}

test "field finds a string value" {
    const auth = "{\"User\":{\"Name\":\"x\"},\"AccessToken\":\"abc123\",\"ServerId\":\"s\"}";
    try testing.expectEqualStrings("abc123", field(auth, "AccessToken").?);
    try testing.expect(field(auth, "Missing") == null);
}
