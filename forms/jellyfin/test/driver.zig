//! Jellyfin's MediaBrowser authorization needs a quoted token header.
const std = @import("std");
const driver = @import("test-driver");
const Json = std.json.Value;
const Allocator = std.mem.Allocator;
const ca = "/data/svc/caddy/pki/authorities/local/root.crt";

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    const password = try driver.system.read(init.io, a, "/run/config/caddy/jellyfin-password");
    var client = try driver.fetch.Client.init(a);
    defer client.deinit();
    const login = try call(&client, a, .{
        .url = "https://localhost/Users/AuthenticateByName",
        .ca = ca,
        .method = "POST",
        .headers = .{ .Authorization = "MediaBrowser Client=\"check\", Device=\"check\", " ++
            "DeviceId=\"library-check\", Version=\"1\"" },
        .json = .{ .Username = "admin", .Pw = std.mem.trimEnd(u8, password, "\r\n") },
    });
    if (login != .object) return error.InvalidLogin;
    const token = login.object.get("AccessToken") orelse return error.NoToken;
    if (token != .string or token.string.len != 32) return error.InvalidToken;
    for (token.string) |c| if (!std.ascii.isHex(c)) return error.InvalidToken;
    const folders = try call(&client, a, .{
        .url = "https://localhost/Library/VirtualFolders",
        .ca = ca,
        .headers = .{ .Authorization = try a.print("MediaBrowser Token=\"{s}\"", .{token.string}) },
    });
    var found = false;
    if (folders != .array) return error.InvalidFolders;
    for (folders.array.items) |folder| {
        if (folder != .object) return error.InvalidFolder;
        const locations = folder.object.get("Locations") orelse return error.NoLocations;
        if (locations != .array) return error.InvalidLocations;
        for (locations.array.items) |location| {
            if (location != .string) return error.InvalidLocation;
            found = found or std.mem.eql(u8, location.string, "/data/svc/jellyfin/media");
        }
    }
    try ctx.result(init.io, args[1], "jf-library", found);
}

fn call(client: *driver.fetch.Client, a: Allocator, request: anytype) !Json {
    const json = try std.json.Stringify.valueAlloc(a, request, .{});
    const result = try client.request(
        try std.json.parseFromSliceLeaky(Json, a, json, .{}),
        10000,
        a,
    );
    if (result.object.get("status").?.integer != 200) return error.UnexpectedStatus;
    return std.json.parseFromSliceLeaky(Json, a, result.object.get("body").?.string, .{});
}
