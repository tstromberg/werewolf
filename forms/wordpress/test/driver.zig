//! WordPress attacks that need writes or a bounded burst; HTTP workflows use YAML.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    const name = if (std.mem.eql(u8, args[2], "uploads")) blk: {
        try uploads(init.io, a);
        break :blk "wp-uploads-data";
    } else if (std.mem.eql(u8, args[2], "rate-limit")) blk: {
        try rateLimit(a);
        break :blk "wp-rate-limited";
    } else return error.Usage;
    try ctx.result(init.io, args[1], name, true);
}

fn request(a: Allocator, client: *driver.fetch.Client, path: []const u8) !std.json.Value {
    var req = driver.system.object(a);
    try req.object.put(a, "url", driver.system.text(try a.print("http://localhost{s}", .{path})));
    return client.request(req, 3000, a);
}

fn rateLimit(a: Allocator) !void {
    var client = try driver.fetch.Client.init(a);
    defer client.deinit();
    var refused = false;
    for (0..30) |_| {
        var attempt: std.heap.ArenaAllocator = .init(a);
        defer attempt.deinit();
        const response = try request(attempt.allocator(), &client, "/wp-login.php");
        const status = response.object.get("status").?.integer;
        if (status == 503) refused = true else if (status != 200) return error.LoginStatus;
    }
    if (!refused) return error.LoginNotRateLimited;
}

fn uploads(io: Io, a: Allocator) !void {
    const blocked = [_][]const u8{
        "/data/svc/php-fpm/uploads/x.php",
        "/data/svc/php-fpm/uploads/x.phtml",
        "/data/svc/php-fpm/uploads/x.phar",
        "/data/svc/php-fpm/uploads/x.xhtml",
        "/data/svc/php-fpm/uploads/x.shtml",
        "/data/svc/php-fpm/uploads/x.xml",
    };
    const svg_path = "/data/svc/php-fpm/uploads/x.svg";
    const link_path = "/data/svc/php-fpm/uploads/leak.json";
    defer {
        for (blocked) |path| Io.Dir.cwd().deleteFile(io, path) catch {};
        Io.Dir.cwd().deleteFile(io, svg_path) catch {};
        Io.Dir.cwd().deleteFile(io, link_path) catch {};
    }
    for (blocked) |path| {
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "<script>alert(1)</script>" });
    }
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = svg_path,
        .data = "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
    });
    Io.Dir.cwd().deleteFile(io, link_path) catch {};
    try Io.Dir.cwd().symLink(io, "/data/svc/php-fpm/salts.json", link_path, .{});
    var client = try driver.fetch.Client.init(a);
    defer client.deinit();
    for ([_][]const u8{
        "/wp-content/uploads/x.php",
        "/wp-content/uploads/x.phtml",
        "/wp-content/uploads/x.phar",
        "/wp-content/uploads/x.xhtml",
        "/wp-content/uploads/x.shtml",
        "/wp-content/uploads/x.xml",
    }) |uri| {
        const res = try request(a, &client, uri);
        if (res.object.get("status").?.integer != 404) return error.UploadedCodeServed;
    }
    const leak = try request(a, &client, "/wp-content/uploads/leak.json");
    const leak_status = leak.object.get("status").?.integer;
    if (leak_status != 403 and leak_status != 404) return error.UploadSymlinkFollowed;
    const svg = try request(a, &client, "/wp-content/uploads/x.svg");
    if (svg.object.get("status").?.integer != 200) return error.UploadedDataMissing;
    const csp = svg.object.get("headers").?.object.get("content-security-policy") orelse
        return error.UploadNotSandboxed;
    if (csp != .string or !driver.sandboxed(csp.string)) return error.UploadNotSandboxed;
}
