//! Exercise the demonstration through HTTP without a root Python test runner.
const std = @import("std");
const driver = @import("test-driver");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(io, gpa, args[3]);
    const suite = args[1];
    var client = try driver.fetch.Client.init(gpa);
    defer client.deinit();
    var page: Response = undefined;
    const deadline = std.Io.Clock.awake.now(io).addDuration(.fromSeconds(60));
    while (true) {
        page = request(&client, gpa, "/", "GET", null) catch |err| {
            if ((err != error.ConnectionRefused and err != error.Timeout) or
                std.Io.Clock.awake.now(io).compare(.gte, deadline)) return err;
            try io.sleep(.fromMilliseconds(100), .awake);
            continue;
        };
        if (page.status != 200) return error.UnexpectedStatus;
        break;
    }
    try ctx.result(
        io,
        suite,
        "webshell-page",
        std.mem.find(u8, page.body, "a contained vulnerability") != null,
    );
    const history = try request(&client, gpa, "/attempts.json", "GET", null);
    const entries = try std.json.parseFromSliceLeaky(std.json.Value, gpa, history.body, .{});
    try ctx.result(io, suite, "webshell-history", history.status == 200 and
        entries == .array and entries.array.items.len <= 100);
    const secret = try request(&client, gpa, "/", "POST", "cmd=cat%20%2Fetc%2Fshadow");
    const attempts = try request(&client, gpa, "/attempts.json", "GET", null);
    const Attempt = struct { cmd: []const u8, source: []const u8, exit: ?i32, stdout: []const u8 };
    const records = try std.json.parseFromSliceLeaky([]const Attempt, gpa, attempts.body, .{
        .ignore_unknown_fields = true,
    });
    var last: ?Attempt = null;
    for (records) |record| {
        if (std.mem.eql(u8, record.cmd, "cat /etc/shadow") and
            !std.mem.eql(u8, record.source, "self-test")) last = record;
    }
    try ctx.result(io, suite, "webshell-secret-refused", secret.status == 200 and
        attempts.status == 200 and last != null and (last.?.exit orelse -1) != 0 and
        std.mem.find(u8, last.?.stdout, "root:") == null);
    const escaped = try request(
        &client,
        gpa,
        "/",
        "POST",
        "cmd=%3Cscript%3Ewerewolf-xss%3C%2Fscript%3E",
    );
    try ctx.result(io, suite, "webshell-escaped", escaped.status == 200 and
        std.mem.find(u8, escaped.body, "&lt;script&gt;werewolf-xss&lt;/script&gt;") != null and
        std.mem.find(u8, escaped.body, "<script>werewolf-xss</script>") == null);
    const missing = try request(&client, gpa, "/missing", "GET", null);
    try ctx.result(io, suite, "webshell-not-found", missing.status == 404);
    const put = try request(&client, gpa, "/", "PUT", null);
    try ctx.result(io, suite, "webshell-method-refused", put.status == 405);
}

const Response = struct { status: i64, body: []const u8 };

fn request(
    client: *driver.fetch.Client,
    a: std.mem.Allocator,
    path: []const u8,
    method: []const u8,
    body: ?[]const u8,
) !Response {
    var req = driver.system.object(a);
    try req.object.put(
        a,
        "url",
        driver.system.text(try a.print("http://127.0.0.1:8080{s}", .{path})),
    );
    try req.object.put(a, "method", driver.system.text(method));
    if (body) |b| {
        try req.object.put(a, "body", driver.system.text(b));
        var headers = driver.system.object(a);
        try headers.object.put(
            a,
            "Content-Type",
            driver.system.text("application/x-www-form-urlencoded"),
        );
        try req.object.put(a, "headers", headers);
    }
    const response = try client.request(req, 10000, a);
    return .{
        .status = response.object.get("status").?.integer,
        .body = response.object.get("body").?.string,
    };
}
