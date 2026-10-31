//! Fetch one JavaScript asset selected from Mastodon's installed files.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "assets")) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    var dir = try Io.Dir.cwd().openDir(init.io, "/usr/lib/mastodon/public/packs", .{
        .iterate = true,
    });
    defer dir.close(init.io);
    var entries = dir.iterate();
    var count: usize = 0;
    while (try entries.next(init.io)) |entry| {
        count += 1;
        if (count > 10000) return error.TooManyAssets;
        if (!javascript(entry.name, entry.kind)) continue;
        var url: Io.Writer.Allocating = .init(a);
        defer url.deinit();
        try url.writer.writeAll("https://localhost/packs/");
        try (std.Uri.Component{ .raw = entry.name }).formatPath(&url.writer);
        var request = driver.system.object(a);
        try request.object.put(a, "url", driver.system.text(try url.toOwnedSlice()));
        try request.object.put(a, "ca", driver.system.text(
            "/data/svc/caddy/pki/authorities/local/root.crt",
        ));
        var client = try driver.fetch.Client.init(a);
        defer client.deinit();
        const reply = try client.request(request, 10000, a);
        const served = reply.object.get("status").?.integer == 200 and
            reply.object.get("body").?.string.len > 0;
        try ctx.result(init.io, args[1], "assets-served", served);

        const link_path = "/data/svc/mastodon/system/werewolf-escape-link";
        Io.Dir.cwd().deleteFile(init.io, link_path) catch {};
        try Io.Dir.cwd().symLink(init.io, "/etc/hosts", link_path, .{});
        defer Io.Dir.cwd().deleteFile(init.io, link_path) catch {};
        var link_req = driver.system.object(a);
        try link_req.object.put(
            a,
            "url",
            driver.system.text("https://localhost/system/werewolf-escape-link"),
        );
        try link_req.object.put(a, "ca", driver.system.text(
            "/data/svc/caddy/pki/authorities/local/root.crt",
        ));
        const link_reply = try client.request(link_req, 10000, a);
        const status = link_reply.object.get("status").?.integer;
        try ctx.result(init.io, args[1], "media-symlink-refused", status == 403 or status == 404);
        return;
    }
    return error.NoJavaScriptAsset;
}

fn javascript(name: []const u8, kind: Io.File.Kind) bool {
    return kind == .file and std.mem.endsWith(u8, name, ".js");
}

test "select a real JavaScript file, not compressed variants or directories" {
    try std.testing.expect(javascript("application-123.js", .file));
    try std.testing.expect(!javascript("application-123.js.gz", .file));
    try std.testing.expect(!javascript("application-123.css", .file));
    try std.testing.expect(!javascript("directory.js", .directory));
}
