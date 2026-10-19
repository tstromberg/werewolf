//! Bugsink UI fixture setup, secure session attributes and its background worker.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Json = std.json.Value;
const Allocator = std.mem.Allocator;
const fixture = "/data/bugsink-test.json";
const Project = struct { project: []const u8, authorization: []const u8 };
const auth_prefix = "Sentry sentry_version=7, sentry_key=";

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    if (std.mem.eql(u8, args[2], "worker")) {
        try worker(io, a);
        return ctx.result(io, args[1], "bs-snappea", true);
    }
    var web = Web{ .a = a, .client = try driver.fetch.Client.init(a) };
    defer web.client.deinit();
    try web.login(io);
    if (std.mem.eql(u8, args[2], "login")) return ctx.result(io, args[1], "bs-login", true);
    if (!std.mem.eql(u8, args[2], "project")) return error.Usage;
    if (std.mem.eql(u8, ctx.phase, "seed")) {
        const team = try web.request("/teams/new/", &.{
            .{ "name", "check" }, .{ "visibility", "1" },
        });
        try status(team, 302);
        const location = try localPath(try header(team, "location"));
        if (!std.mem.startsWith(u8, location, "/teams/")) return error.TeamLocation;
        const rest = location["/teams/".len..];
        const end = std.mem.findScalar(u8, rest, '/') orelse return error.TeamLocation;
        if (end == 0) return error.TeamLocation;
        const page = try web.request("/projects/new/", null);
        try status(page, 200);
        const group = try selectedGroup(page.object.get("body").?.string);
        const made = try web.request("/projects/new/", &.{
            .{
                "team",
                rest[0..end],
            },
            .{ "name", "check" },
            .{ "visibility", "10" },
            .{ "retention_max_event_count", "10000" },
            .{ "grouping_mechanism", group },
        });
        try status(made, 302);
        const id = try projectId(try header(made, "location"));
        const sdk = try web.request(try a.print("/projects/{s}/sdk-setup/", .{id}), null);
        try status(sdk, 200);
        const key = try dsnKey(sdk.object.get("body").?.string, id);
        const data = Project{ .project = id, .authorization = try a.print("{s}{s}", .{
            auth_prefix, key,
        }) };
        var bytes: Io.Writer.Allocating = .init(a);
        defer bytes.deinit();
        try std.json.Stringify.value(data, .{}, &bytes.writer);
        var file = try Io.Dir.cwd().createFile(io, fixture, .{
            .permissions = .fromMode(0o600),
        });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes.writer.buffered());
        try file.sync(io);
        try ctx.result(io, args[1], "bs-project", true);
    } else {
        const data = try std.json.parseFromSliceLeaky(Project, a, try driver.system.read(
            io,
            a,
            fixture,
        ), .{});
        _ = try std.fmt.parseInt(u64, data.project, 10);
        if (!std.mem.startsWith(u8, data.authorization, auth_prefix)) return error.ProjectFixture;
        const sdk = try web.request(try a.print("/projects/{s}/sdk-setup/", .{
            data.project,
        }), null);
        try status(sdk, 200);
        const key = try dsnKey(sdk.object.get("body").?.string, data.project);
        if (!std.mem.eql(u8, key, data.authorization[auth_prefix.len..]))
            return error.ProjectChanged;
        try ctx.result(io, args[1], "bs-project-kept", true);
    }
}

const Web = struct {
    a: Allocator,
    client: driver.fetch.Client,
    csrf: []const u8 = "",

    fn request(w: *Web, path: []const u8, fields: ?[]const [2][]const u8) !Json {
        var req = driver.system.object(w.a);
        try req.object.put(w.a, "url", driver.system.text(try w.a.print(
            "https://localhost{s}",
            .{path},
        )));
        try req.object.put(w.a, "ca", driver.system.text(
            "/data/svc/caddy/pki/authorities/local/root.crt",
        ));
        try req.object.put(w.a, "session", driver.system.text("admin"));
        if (fields) |pairs| {
            try req.object.put(w.a, "method", driver.system.text("POST"));
            var form = driver.system.object(w.a);
            try form.object.put(w.a, "csrfmiddlewaretoken", driver.system.text(w.csrf));
            for (pairs) |pair| try form.object.put(w.a, pair[0], driver.system.text(pair[1]));
            try req.object.put(w.a, "form", form);
            var headers = driver.system.object(w.a);
            try headers.object.put(w.a, "Referer", req.object.get("url").?);
            try req.object.put(w.a, "headers", headers);
        }
        return w.client.request(req, 10000, w.a);
    }

    fn login(w: *Web, io: Io) !void {
        const page = try w.request("/accounts/login/", null);
        try status(page, 200);
        w.csrf = try cookie(page, "csrftoken");
        const secret = try driver.system.read(io, w.a, "/run/config/bugsink/admin");
        const split = std.mem.findScalar(u8, secret, ':') orelse return error.AdminFixture;
        const response = try w.request("/accounts/login/", &.{
            .{ "username", secret[0..split] },
            .{ "password", std.mem.trimEnd(u8, secret[split + 1 ..], "\r\n") },
        });
        try status(response, 302);
        if (!std.mem.eql(u8, try localPath(try header(response, "location")), "/"))
            return error.LoginLocation;
        _ = try cookie(response, "sessionid");
        const cookies = response.object.get("headers").?.object.get("set-cookie") orelse
            return error.SessionFlags;
        const secure = if (cookies == .string) secureSession(cookies.string) else blk: {
            if (cookies != .array) return error.SessionFlags;
            for (cookies.array.items) |value| {
                if (value != .string) return error.SessionFlags;
                if (secureSession(value.string)) break :blk true;
            }
            break :blk false;
        };
        if (!secure) return error.InsecureSession;
        w.csrf = try cookie(response, "csrftoken");
    }
};

fn status(response: Json, expected: i64) !void {
    if (response.object.get("status").?.integer != expected) return error.HttpStatus;
}
fn header(response: Json, name: []const u8) ![]const u8 {
    const value = response.object.get("headers").?.object.get(name) orelse return error.Header;
    if (value != .string) return error.AmbiguousHeader;
    return value.string;
}
fn cookie(response: Json, name: []const u8) ![]const u8 {
    const value = response.object.get("cookies").?.object.get(name) orelse return error.Cookie;
    if (value != .string or value.string.len == 0) return error.Cookie;
    return value.string;
}
fn secureSession(line: []const u8) bool {
    if (!std.mem.startsWith(u8, line, "sessionid=")) return false;
    var parts = std.mem.splitScalar(u8, line, ';');
    _ = parts.next();
    while (parts.next()) |part|
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), "Secure")) return true;
    return false;
}
fn localPath(location: []const u8) ![]const u8 {
    const path = if (std.mem.startsWith(u8, location, "https://localhost/"))
        location["https://localhost".len..]
    else
        location;
    if (!std.mem.startsWith(u8, path, "/") or std.mem.startsWith(u8, path, "//"))
        return error.ForeignRedirect;
    return path;
}
fn projectId(location: []const u8) ![]const u8 {
    const path = try localPath(location);
    const prefix = "/projects/";
    const suffix = "/sdk-setup/";
    if (!std.mem.startsWith(u8, path, prefix) or !std.mem.endsWith(u8, path, suffix) or
        path.len <= prefix.len + suffix.len) return error.ProjectLocation;
    const id = path[prefix.len .. path.len - suffix.len];
    if ((try std.fmt.parseInt(u64, id, 10)) == 0) return error.ProjectLocation;
    return id;
}
fn selectedGroup(body: []const u8) ![]const u8 {
    const start = std.mem.find(u8, body, "name=\"grouping_mechanism\"") orelse
        return error.GroupingSelect;
    const end = std.mem.find(u8, body[start..], "</select>") orelse return error.GroupingSelect;
    var rest = body[start .. start + end];
    while (std.mem.find(u8, rest, "<option")) |begin| {
        rest = rest[begin + "<option".len ..];
        const close = std.mem.findScalar(u8, rest, '>') orelse return error.GroupingOption;
        const tag = rest[0..close];
        if (std.mem.find(u8, tag, " selected")) |chosen| {
            const next = chosen + " selected".len;
            if (next == tag.len or std.mem.findScalar(u8, "= \t\r\n", tag[next]) != null) {
                const value = std.mem.find(u8, tag, "value=\"") orelse return error.GroupingValue;
                const text = tag[value + "value=\"".len ..];
                const quote = std.mem.findScalar(u8, text, '"') orelse return error.GroupingValue;
                if (quote == 0) return error.GroupingValue;
                return text[0..quote];
            }
        }
        rest = rest[close + 1 ..];
    }
    return error.NoSelectedGrouping;
}
fn dsnKey(body: []const u8, id: []const u8) ![]const u8 {
    var suffix_buffer: [64]u8 = undefined;
    const suffix = try std.mem.print(&suffix_buffer, "@localhost/{s}", .{id});
    var rest = body;
    while (std.mem.find(u8, rest, suffix)) |end| {
        const after = end + suffix.len;
        const boundary = after == rest.len or
            std.mem.findScalar(u8, "\"' \t\r\n<>`)", rest[after]) != null;
        if (boundary and end >= 40 and
            std.mem.eql(u8, rest[end - 40 .. end - 32], "https://"))
        {
            const key = rest[end - 32 .. end];
            var valid = true;
            for (key) |byte| valid = valid and std.ascii.isHex(byte);
            if (valid) return key;
        }
        rest = rest[end + suffix.len ..];
    }
    return error.ProjectDsn;
}
fn worker(io: Io, a: Allocator) !void {
    for (0..100) |_| {
        var attempt: std.heap.ArenaAllocator = .init(a);
        defer attempt.deinit();
        const gpa = attempt.allocator();
        const pids = try driver.system.read(io, gpa, "/run/cgroup/svc/bugsink/cgroup.procs");
        var lines = std.mem.tokenizeAny(u8, pids, "\r\n");
        while (lines.next()) |line| {
            const pid = try std.fmt.parseInt(u32, line, 10);
            const command = driver.system.read(io, gpa, try gpa.print(
                "/proc/{d}/cmdline",
                .{pid},
            )) catch |err| {
                if (err == error.FileNotFound) continue;
                return err;
            };
            if (std.mem.find(u8, command, "bugsink-runsnappea") != null) return;
        }
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    return error.WorkerMissing;
}

test "session security and fixed-origin redirects are explicit" {
    try std.testing.expect(secureSession("sessionid=x; HttpOnly; Secure; SameSite=Lax"));
    try std.testing.expect(!secureSession("csrftoken=x; Secure"));
    try std.testing.expect(!secureSession("sessionid=x; Secure=false"));
    try std.testing.expectEqualStrings("12", try projectId("/projects/12/sdk-setup/"));
    try std.testing.expectEqualStrings("12", try projectId(
        "https://localhost/projects/12/sdk-setup/",
    ));
    try std.testing.expectError(
        error.ForeignRedirect,
        projectId("https://other/projects/12/sdk-setup/"),
    );
    try std.testing.expectError(error.ForeignRedirect, localPath("//other/"));
}

test "select the advertised grouping and complete local DSN key" {
    try std.testing.expectEqualStrings("v3", try selectedGroup(
        \\<select name="grouping_mechanism"><option value="old">Old</option><option value="v3" selected="">Current</option></select>
    ));
    try std.testing.expectError(error.NoSelectedGrouping, selectedGroup(
        \\<select name="grouping_mechanism"><option value="old" selectedness="">Old</option></select>
    ));
    try std.testing.expectEqualStrings("0123456789abcdef0123456789abcdef", try dsnKey(
        "https://0123456789abcdef0123456789abcdef@localhost/12",
        "12",
    ));
    try std.testing.expectError(error.ProjectDsn, dsnKey("https://short@localhost/12", "12"));
    try std.testing.expectError(error.ProjectDsn, dsnKey(
        "https://0123456789abcdef0123456789abcdef@localhost/123",
        "12",
    ));
}
