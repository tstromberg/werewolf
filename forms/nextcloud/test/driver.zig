//! Verify custom_apps refuses a symlink pointing outside /data/svc/nextcloud/apps.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "symlink")) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    const link_path = "/data/svc/nextcloud/apps/werewolf-escape-link";
    Io.Dir.cwd().deleteFile(init.io, link_path) catch {};
    try Io.Dir.cwd().symLink(init.io, "/etc/hosts", link_path, .{});
    defer Io.Dir.cwd().deleteFile(init.io, link_path) catch {};

    var req = driver.system.object(a);
    try req.object.put(
        a,
        "url",
        driver.system.text("https://localhost/custom_apps/werewolf-escape-link"),
    );
    try req.object.put(
        a,
        "ca",
        driver.system.text("/data/svc/caddy/pki/authorities/local/root.crt"),
    );
    var client = try driver.fetch.Client.init(a);
    defer client.deinit();
    const reply = try client.request(req, 10000, a);
    const status = reply.object.get("status").?.integer;
    try ctx.result(init.io, args[1], "nc-symlink-refused", status == 403 or status == 404);
}
