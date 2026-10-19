//! Frontend asset and whole-service-set isolation checks beside the GMP clients.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    if (std.mem.eql(u8, args[2], "assets")) {
        var client = try driver.fetch.Client.init(a);
        defer client.deinit();
        const page = try request(&client, a, "/login");
        const path = try asset(page);
        if ((try request(&client, a, path)).len == 0) return error.EmptyAsset;
        try ctx.result(io, args[1], "greenbone-assets", true);
    } else if (std.mem.eql(u8, args[2], "isolation")) {
        const feed = try driver.system.account(io, a, "_oci-feed");
        const manager = try driver.system.account(io, a, "_oci-gvmd");
        const cache = try driver.system.file(io, a, "/data/share/gvm/vt", driver.system.object(a));
        const mode = try std.fmt.parseInt(u16, cache.object.get("mode").?.string, 8);
        try ctx.result(
            io,
            args[1],
            "greenbone-cache",
            feed != manager and cache.object.get("uid").?.integer == feed and mode & 7 == 0,
        );
        const feed_service = try driver.system.service(io, a, "feed");
        var running = false;
        for (feed_service.object.get("members").?.array.items) |member| {
            const path = try a.print("/proc/{d}/cmdline", .{member.object.get("pid").?.integer});
            const command = driver.system.read(io, a, path) catch |err| {
                if (err == error.FileNotFound) continue;
                return err;
            };
            running = running or feedCommand(command);
        }
        try ctx.result(io, args[1], "greenbone-feed-command", running);
        try services(io, a);
        const sockets = try driver.system.listeners(io, a, "tcp");
        var redis_bound = false;
        for (sockets.array.items) |socket| {
            if (socket.object.get("port").?.integer != 6379) continue;
            if (!std.mem.eql(u8, socket.object.get("address").?.string, "127.0.0.1"))
                return error.RedisPublic;
            redis_bound = true;
        }
        if (!redis_bound) return error.RedisMissing;
        try ctx.result(io, args[1], "greenbone-caps", true);
        try ctx.result(io, args[1], "greenbone-redis", true);
    } else return error.Usage;
}

fn request(client: *driver.fetch.Client, a: Allocator, path: []const u8) ![]const u8 {
    var url: Io.Writer.Allocating = .init(a);
    defer url.deinit();
    try url.writer.writeAll("https://localhost");
    try (std.Uri.Component{ .raw = path }).formatPath(&url.writer);
    var req = driver.system.object(a);
    try req.object.put(a, "url", driver.system.text(try url.toOwnedSlice()));
    try req.object.put(
        a,
        "ca",
        driver.system.text("/data/svc/caddy/pki/authorities/local/root.crt"),
    );
    const response = try client.request(req, 10000, a);
    if (response.object.get("status").?.integer != 200) return error.FrontendResponse;
    return response.object.get("body").?.string;
}

fn asset(page: []const u8) ![]const u8 {
    var rest = page;
    var found: ?[]const u8 = null;
    while (std.mem.find(u8, rest, "src=\"")) |start| {
        rest = rest[start + "src=\"".len ..];
        const end = std.mem.findScalar(u8, rest, '"') orelse return error.ScriptAttribute;
        const path = rest[0..end];
        if (std.mem.endsWith(u8, path, ".js")) {
            if (!std.mem.startsWith(u8, path, "/") or std.mem.startsWith(u8, path, "//") or
                std.mem.findAny(u8, path, "\x00\r\n") != null) return error.NonlocalAsset;
            found = path;
        }
        rest = rest[end + 1 ..];
    }
    return found orelse error.NoScript;
}

fn declarations(name: []const u8, service: []const u8) !usize {
    const scanner = std.mem.eql(u8, name, "openvas");
    var caps = false;
    var redis: usize = 0;
    var lines = std.mem.splitScalar(u8, service, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "caps ")) {
            if (!scanner or caps or !std.mem.eql(u8, line, "caps net_raw net_admin"))
                return error.UnexpectedCaps;
            caps = true;
        }
        if (std.mem.startsWith(u8, line, "connect ") and std.mem.find(u8, line, "6379") != null) {
            if (!scanner) return error.SharedRedis;
            redis += 1;
        }
    }
    if (scanner and !caps) return error.ScannerCapsMissing;
    return redis;
}

fn services(io: Io, a: Allocator) !void {
    var dir = try Io.Dir.cwd().openDir(io, "/etc/sv", .{ .iterate = true });
    defer dir.close(io);
    try serviceSet(io, a, dir);
}

fn serviceSet(io: Io, a: Allocator, dir: Io.Dir) !void {
    var entries = dir.iterate();
    var count: usize = 0;
    var redis: usize = 0;
    var scanner = false;
    while (try entries.next(io)) |entry| {
        if (entry.kind != .directory) return error.ServiceDirectory;
        count += 1;
        if (count > 128) return error.TooManyServices;
        scanner = scanner or std.mem.eql(u8, entry.name, "openvas");
        // Core programs have run scripts, without leash service descriptors.
        const path = try a.print("{s}/service", .{entry.name});
        const raw = dir.readFileAlloc(io, path, a, .limited(1 << 20)) catch |err| {
            if (err == error.FileNotFound) continue;
            return err;
        };
        redis += try declarations(entry.name, raw);
    }
    if (!scanner or redis != 1) return error.RedisOwner;
}

test "asset selection stays on the verified origin and uses a script" {
    try std.testing.expectEqualStrings(
        "/assets/app.js",
        try asset("<script src=\"/assets/app.js\">"),
    );
    try std.testing.expectError(error.NonlocalAsset, asset("src=\"//other/app.js\""));
    try std.testing.expectError(error.NonlocalAsset, asset("src=\"https://other/app.js\""));
    try std.testing.expectError(error.NoScript, asset("src=\"/app.css\""));
}

test "new services cannot gain scanner capabilities or Redis access unnoticed" {
    try std.testing.expectEqual(
        @as(usize, 1),
        try declarations("openvas", "caps net_raw net_admin\nconnect tcp/6379\n"),
    );
    try std.testing.expectError(
        error.SharedRedis,
        declarations("unexpected", "connect tcp/6379\n"),
    );
    try std.testing.expectError(error.UnexpectedCaps, declarations("unexpected", "caps net_raw\n"));
    try std.testing.expectError(
        error.ScannerCapsMissing,
        declarations("openvas", "connect tcp/6379\n"),
    );
}

test "core run scripts need no descriptor; scanner and unexpected declarations are checked" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "openvas");
    try tmp.dir.createDirPath(io, "posture");
    try tmp.dir.writeFile(io, .{ .sub_path = "posture/run", .data = "core program" });
    try tmp.dir.writeFile(io, .{
        .sub_path = "openvas/service",
        .data = "caps net_raw net_admin\nconnect tcp/6379\n",
    });
    try serviceSet(io, arena.allocator(), tmp.dir);
    try tmp.dir.deleteFile(io, "openvas/service");
    try std.testing.expectError(error.RedisOwner, serviceSet(io, arena.allocator(), tmp.dir));
    try tmp.dir.writeFile(io, .{ .sub_path = "posture/service", .data = "caps net_raw\n" });
    try std.testing.expectError(error.UnexpectedCaps, serviceSet(io, arena.allocator(), tmp.dir));
}

fn feedCommand(raw: []const u8) bool {
    var args = std.mem.splitScalar(u8, raw, 0);
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "/usr/lib/werewolf/feed-run")) return true;
    }
    return false;
}

test "the feed worker runs the declared script, not a similarly named command" {
    try std.testing.expect(feedCommand("/bin/bash\x00/usr/lib/werewolf/feed-run\x00"));
    try std.testing.expect(!feedCommand("/bin/bash\x00/usr/lib/werewolf/feed-run-other\x00"));
    try std.testing.expect(!feedCommand("/usr/bin/sleep\x00infinity\x00"));
}
