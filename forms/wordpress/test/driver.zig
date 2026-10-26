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
    const paths = [_][]const u8{
        "/data/svc/php-fpm/uploads/x.php", "/data/svc/php-fpm/uploads/x.svg",
    };
    defer for (paths) |path| Io.Dir.cwd().deleteFile(io, path) catch {};
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = paths[0],
        .data = "<?php echo \"ran\"; ?>",
    });
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = paths[1],
        .data = "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
    });
    var client = try driver.fetch.Client.init(a);
    defer client.deinit();
    const php = try request(a, &client, "/wp-content/uploads/x.php");
    if (php.object.get("status").?.integer != 404) return error.UploadedCodeServed;
    const svg = try request(a, &client, "/wp-content/uploads/x.svg");
    if (svg.object.get("status").?.integer != 200) return error.UploadedDataMissing;
    const csp = svg.object.get("headers").?.object.get("content-security-policy") orelse
        return error.UploadNotSandboxed;
    if (csp != .string or !sandbox(csp.string)) return error.UploadNotSandboxed;
}

fn sandbox(value: []const u8) bool {
    var directives = std.mem.splitScalar(u8, value, ';');
    while (directives.next()) |directive| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, directive, " \t"), "sandbox")) return true;
    }
    return false;
}

test "upload sandbox must be its own restrictive CSP directive" {
    try std.testing.expect(sandbox("sandbox"));
    try std.testing.expect(sandbox("default-src 'none'; sandbox; img-src 'self'"));
    try std.testing.expect(!sandbox("default-src https://sandbox.example"));
    try std.testing.expect(!sandbox("sandbox allow-scripts"));
}
