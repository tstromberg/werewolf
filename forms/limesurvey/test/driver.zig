//! LimeSurvey attacks that plant files on /data; HTTP workflows use YAML.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    const name = if (std.mem.eql(u8, args[2], "planted")) blk: {
        try planted(init.io, a);
        break :blk "ls-plugin-planted";
    } else if (std.mem.eql(u8, args[2], "uploads")) blk: {
        try uploads(init.io, a);
        break :blk "ls-uploads-data";
    } else return error.Usage;
    try ctx.result(init.io, args[1], name, true);
}

fn request(
    a: Allocator,
    client: *driver.fetch.Client,
    path: []const u8,
    form: ?std.json.Value,
) !std.json.Value {
    var req = driver.system.object(a);
    try req.object.put(a, "url", driver.system.text(try a.print("http://localhost{s}", .{path})));
    try req.object.put(a, "session", driver.system.text("admin"));
    if (form) |f| {
        try req.object.put(a, "method", driver.system.text("POST"));
        try req.object.put(a, "form", f);
    }
    return client.request(req, 10000, a);
}

fn status(response: std.json.Value) i64 {
    return response.object.get("status").?.integer;
}

fn body(response: std.json.Value) []const u8 {
    return response.object.get("body").?.string;
}

/// A plugin someone managed to write under upload/ is not one: the admin's
/// scan of the plugin directories never finds it, so its code never runs and
/// it cannot be installed.
fn planted(io: Io, a: Allocator) !void {
    const plugins = "/data/svc/php-fpm/upload/plugins";
    const cwd = Io.Dir.cwd();
    defer cwd.deleteTree(io, plugins) catch {};
    try cwd.createDirPath(io, plugins ++ "/Evil");
    try cwd.writeFile(io, .{
        .sub_path = plugins ++ "/Evil/config.xml",
        .data = "<?xml version=\"1.0\"?><config><metadata><name>Evil</name>" ++
            "<type>plugin</type><version>1</version></metadata>" ++
            "<compatibility><version>7.0</version></compatibility></config>",
    });
    try cwd.writeFile(io, .{
        .sub_path = plugins ++ "/Evil/Evil.php",
        .data = "<?php file_put_contents(\"/run/svc/php-fpm/pwned\", \"x\");" ++
            " class Evil extends PluginBase {}",
    });

    var client = try driver.fetch.Client.init(a);
    defer client.deinit();
    const login = try request(a, &client, "/index.php/admin/authentication/sa/login", null);
    if (status(login) != 200) return error.LoginPage;
    var form = driver.system.object(a);
    for ([_][2][]const u8{
        .{ "YII_CSRF_TOKEN", try token(body(login)) },
        .{ "authMethod", "Authdb" },
        .{ "user", "admin" },
        .{ "password", "werewolf-check" },
        .{ "loginlang", "default" },
        .{ "action", "login" },
        .{ "width", "1280" },
        .{ "login_submit", "login" },
    }) |field| try form.object.put(a, field[0], driver.system.text(field[1]));
    _ = try request(a, &client, "/index.php/admin/authentication/sa/login", form);
    const scan = try request(a, &client, "/index.php/admin/pluginmanager/sa/scanFiles", null);
    if (status(scan) != 200 or std.mem.find(u8, body(scan), "Plugins - Scanned files") == null)
        return error.ScanNotRun;
    if (std.mem.find(u8, body(scan), "Evil") != null) return error.PlantedPluginFound;
    if (cwd.access(io, "/run/svc/php-fpm/pwned", .{})) |_| {
        return error.PlantedPluginRan;
    } else |err| if (err != error.FileNotFound) return err;

    var env: std.process.Environ.Map = .init(a);
    defer env.deinit();
    const rows = try driver.exec.run(a, io, &.{
        "/usr/bin/mariadb",
        "--socket=/run/svc/mariadb/mariadb.sock",
        "--skip-column-names",
        "--execute=select count(*) from limesurvey.lime_plugins where name='Evil'",
    }, &env, "", 30000);
    if (rows.term != .exited or rows.term.exited != 0 or !std.mem.eql(u8, rows.stdout, "0\n"))
        return error.PlantedPluginInstalled;
    // nginx lets six sign-in requests through at once, then one each 6 s
    // (rootfs/etc/nginx/nginx.conf). Give back this sign-in's two, so the
    // plan's own sign-ins after it keep their burst.
    try io.sleep(.fromSeconds(12), .awake);
}

/// The login form's CSRF token; signing in replaces it.
fn token(page: []const u8) ![]const u8 {
    const end = std.mem.find(u8, page, "\" name=\"YII_CSRF_TOKEN\"") orelse
        return error.MissingToken;
    const start = std.mem.findLast(u8, page[0..end], "value=\"") orelse
        return error.MissingToken;
    return page[start + "value=\"".len .. end];
}

/// Uploads are data, never code: a .php planted there is a 404, an SVG is
/// sandboxed; and the assets LimeSurvey published are served.
fn uploads(io: Io, a: Allocator) !void {
    const paths = [_][]const u8{
        "/data/svc/php-fpm/upload/global/x.php", "/data/svc/php-fpm/upload/global/x.svg",
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
    if (status(try request(a, &client, "/upload/global/x.php", null)) != 404)
        return error.UploadedCodeServed;
    const svg = try request(a, &client, "/upload/global/x.svg", null);
    if (status(svg) != 200) return error.UploadedDataMissing;
    const csp = svg.object.get("headers").?.object.get("content-security-policy") orelse
        return error.UploadNotSandboxed;
    if (csp != .string or !driver.sandboxed(csp.string)) return error.UploadNotSandboxed;

    const home = try request(a, &client, "/", null);
    const css = stylesheet(body(home)) orelse return error.NoPublishedAsset;
    if (status(try request(a, &client, css, null)) != 200) return error.AssetNotServed;
}

/// The first stylesheet the page links from LimeSurvey's published assets.
fn stylesheet(page: []const u8) ?[]const u8 {
    var rest = page;
    while (std.mem.find(u8, rest, "/tmp/assets/")) |start| {
        rest = rest[start..];
        const end = std.mem.findAny(u8, rest, "\"' ?") orelse return null;
        if (std.mem.endsWith(u8, rest[0..end], ".css")) return rest[0..end];
        rest = rest[end..];
    }
    return null;
}

test "the login form's token is the hidden field's value" {
    const page =
        \\<input type="hidden" value="aB-_c=" name="YII_CSRF_TOKEN" />
    ;
    try std.testing.expectEqualStrings("aB-_c=", try token(page));
    try std.testing.expectError(error.MissingToken, token("<form></form>"));
}

test "a published stylesheet is found past scripts and queries" {
    const page =
        \\<script src="/tmp/assets/1a/x.js"></script>
        \\<link href="http://localhost/tmp/assets/2b/css/y.css?v=3" rel="stylesheet">
    ;
    try std.testing.expectEqualStrings("/tmp/assets/2b/css/y.css", stylesheet(page).?);
    try std.testing.expect(stylesheet("<script src=\"/tmp/assets/1a/x.js\"></script>") == null);
}
