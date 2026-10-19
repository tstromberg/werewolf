//! MediaWiki's recursive upload check, throttle burst and schema restart attack.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Json = std.json.Value;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    const name = if (std.mem.eql(u8, args[2], "files")) blk: {
        try bannedFiles(init.io, a);
        break :blk "mw-no-banned-files";
    } else if (std.mem.eql(u8, args[2], "throttle")) blk: {
        try throttle(init.io, a);
        break :blk "mw-throttled";
    } else if (std.mem.eql(u8, args[2], "update")) blk: {
        try update(init.io, a);
        break :blk "mw-update";
    } else return error.Usage;
    try ctx.result(init.io, args[1], name, true);
}

fn bannedFiles(io: Io, a: Allocator) !void {
    var dir = try Io.Dir.cwd().openDir(io, "/data/svc/php-fpm/images", .{ .iterate = true });
    defer dir.close(io);
    var walk = try dir.walk(a);
    defer walk.deinit();
    var count: usize = 0;
    while (try walk.next(io)) |entry| {
        count += 1;
        if (count > 10000) return error.TooManyImages;
        for ([_][]const u8{ "x.svg", "x.html", "x.png" }) |name|
            if (std.ascii.eqlIgnoreCase(entry.basename, name)) return error.BannedUploadStored;
    }
}

fn get(a: Allocator, client: *driver.fetch.Client, path: []const u8) !Json {
    var req = driver.system.object(a);
    try req.object.put(a, "url", driver.system.text(try a.print("http://localhost{s}", .{path})));
    try req.object.put(a, "session", driver.system.text("login"));
    return client.request(req, 10000, a);
}

fn json(a: Allocator, response: Json) !Json {
    if (response.object.get("status").?.integer != 200) return error.ApiStatus;
    return std.json.parseFromSliceLeaky(Json, a, response.object.get("body").?.string, .{});
}

fn throttle(io: Io, a: Allocator) !void {
    var client = try driver.fetch.Client.init(a);
    defer client.deinit();
    const password = try driver.system.read(io, a, "/run/config/mediawiki/admin-password");
    var last: Json = undefined;
    for (0..7) |n| {
        const tokens = try json(a, try get(
            a,
            &client,
            "/api.php?action=query&meta=tokens&type=login&format=json",
        ));
        const token = try member(try member(try member(tokens, "query"), "tokens"), "logintoken");
        if (token != .string or token.string.len == 0) return error.LoginToken;
        var req = driver.system.object(a);
        try req.object.put(a, "url", driver.system.text("http://localhost/api.php"));
        try req.object.put(a, "method", driver.system.text("POST"));
        try req.object.put(a, "session", driver.system.text("login"));
        var form = driver.system.object(a);
        try form.object.put(a, "action", driver.system.text("login"));
        try form.object.put(a, "format", driver.system.text("json"));
        try form.object.put(a, "lgname", driver.system.text("Admin"));
        try form.object.put(a, "lgpassword", driver.system.text(if (n == 6)
            std.mem.trimEnd(u8, password, "\r\n")
        else
            "werewolf-throttle-guess"));
        try form.object.put(a, "lgtoken", token);
        try req.object.put(a, "form", form);
        last = try client.request(req, 10000, a);
        _ = try json(a, last);
    }
    if (!try throttled(a, last.object.get("body").?.string)) return error.LoginNotThrottled;
}

fn member(value: Json, name: []const u8) !Json {
    if (value != .object) return error.ApiObject;
    return value.object.get(name) orelse error.ApiField;
}

fn throttled(a: Allocator, body: []const u8) !bool {
    const parsed = try std.json.parseFromSlice(Json, a, body, .{});
    defer parsed.deinit();
    const result = try member(try member(parsed.value, "login"), "result");
    if (result != .string or std.mem.eql(u8, result.string, "Success")) return false;
    const lower = try std.ascii.allocLowerString(a, body);
    defer a.free(lower);
    return std.mem.find(u8, lower, "too many") != null;
}

fn update(io: Io, a: Allocator) !void {
    const schema = "/data/svc/php-fpm/database/schema";
    const original = try driver.system.read(io, a, schema);
    if (original.len == 0 or std.mem.find(u8, original, "stale") != null)
        return error.OriginalSchema;
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = schema, .data = "1.43.10 stale\n" });
    const result = try std.process.run(a, io, .{
        .argv = &.{ "/usr/bin/sv", "restart", "/etc/sv/php-fpm" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
        .timeout = driver.deadline(io, 25),
    });
    if (result.term != .exited or result.term.exited != 0) return error.RestartFailed;
    var client = try driver.fetch.Client.init(a);
    defer client.deinit();
    const stop = Io.Clock.awake.now(io).addDuration(.fromSeconds(140));
    while (true) {
        var attempt: std.heap.ArenaAllocator = .init(a);
        defer attempt.deinit();
        const gpa = attempt.allocator();
        const actual = try driver.system.read(io, gpa, schema);
        if (std.mem.eql(u8, actual, original)) {
            const response = try get(
                gpa,
                &client,
                "/api.php?action=query&meta=siteinfo&format=json",
            );
            if (response.object.get("status").?.integer == 200) {
                const value = try json(gpa, response);
                const code = try member(try member(value, "error"), "code");
                if (code == .string and std.mem.eql(u8, code.string, "readapidenied")) break;
            }
        }
        if (Io.Clock.awake.now(io).compare(.gte, stop)) return error.SchemaNotUpdated;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    const metadata = try driver.system.file(io, a, schema, .{ .object = .empty });
    if (metadata.object.get("uid").?.integer != try driver.system.account(io, a, "php") or
        !std.mem.eql(
            u8,
            metadata.object.get("mode").?.string,
            "600",
        )) return error.SchemaPermissions;
}

test "the final correct password must be refused by the throttle" {
    try std.testing.expect(try throttled(std.testing.allocator,
        \\{"login":{"result":"Failed","reason":"Too many login attempts"}}
    ));
    try std.testing.expect(!try throttled(std.testing.allocator,
        \\{"login":{"result":"Success","reason":"Too many unrelated messages"}}
    ));
    try std.testing.expect(!try throttled(std.testing.allocator,
        \\{"login":{"result":"Failed","reason":"Wrong password"}}
    ));
}
