//! A bounded audit of mutable Moodle files, and a PATH_INFO avatar request.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    if (std.mem.eql(u8, args[2], "private")) {
        var dir = try Io.Dir.cwd().openDir(init.io, "/data/svc/moodle", .{ .iterate = true });
        defer dir.close(init.io);
        try ctx.result(init.io, args[1], "moodle-private-tree", try private(init.io, a, dir));
    } else if (std.mem.eql(u8, args[2], "avatar")) {
        try avatar(a);
        try ctx.result(init.io, args[1], "moodle-path-info", true);
    } else return error.Usage;
}

fn private(io: Io, a: std.mem.Allocator, dir: Io.Dir) !bool {
    if ((try dir.stat(io)).permissions.toMode() & 0o002 != 0) return false;
    var entries = try dir.walk(a);
    defer entries.deinit();
    var count: usize = 0;
    while (try entries.next(io)) |entry| {
        count += 1;
        if (count > 100000 or entry.path.len > 4096) return error.TooManyFiles;
        if (entry.kind == .sym_link) continue;
        const info = dir.statFile(io, entry.path, .{ .follow_symlinks = false }) catch |err| {
            if (err == error.FileNotFound) continue;
            return err;
        };
        if (info.kind != .sym_link and info.permissions.toMode() & 0o002 != 0) return false;
    }
    return true;
}

test "private tree includes nested files and directories but ignores symbolic links" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "nested");
    try tmp.dir.writeFile(io, .{ .sub_path = "nested/secret", .data = "secret" });
    try tmp.dir.symLink(io, "/missing-target", "ignored", .{});
    try std.testing.expect(try private(io, std.testing.allocator, tmp.dir));
    var file = try tmp.dir.openFile(io, "nested/secret", .{ .mode = .read_write });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o666));
    try std.testing.expect(!try private(io, std.testing.allocator, tmp.dir));
    try file.setPermissions(io, .fromMode(0o600));
    var dir = try tmp.dir.openDir(io, "nested", .{ .iterate = true });
    defer dir.close(io);
    try dir.setPermissions(io, .fromMode(0o777));
    try std.testing.expect(!try private(io, std.testing.allocator, tmp.dir));
}

fn avatar(a: std.mem.Allocator) !void {
    var client = try driver.fetch.Client.init(a);
    defer client.deinit();
    var url: []const u8 = "https://localhost/user/pix.php/0/f1.jpg";
    for (0..4) |_| {
        var request = driver.system.object(a);
        try request.object.put(a, "url", driver.system.text(url));
        try request.object.put(a, "ca", driver.system.text(
            "/data/svc/caddy/pki/authorities/local/root.crt",
        ));
        const response = try client.request(request, 20000, a);
        const status = response.object.get("status").?.integer;
        const headers = response.object.get("headers").?.object;
        if (status == 200) {
            const mime = headers.get("content-type") orelse return error.ImageType;
            if (mime != .string or mime.string.len <= 6 or
                !std.ascii.eqlIgnoreCase(mime.string[0..6], "image/") or
                response.object.get("body").?.string.len == 0) return error.EmptyImage;
            return;
        }
        switch (status) {
            301, 302, 303, 307, 308 => {},
            else => return error.ImageStatus,
        }
        const location = headers.get("location") orelse return error.MissingLocation;
        if (location != .string) return error.AmbiguousLocation;
        url = try localRedirect(a, location.string);
    }
    return error.TooManyRedirects;
}

fn localRedirect(a: std.mem.Allocator, value: []const u8) ![]const u8 {
    if (value.len == 0 or value.len > 4096 or
        std.mem.findAny(u8, value, " \t\r\n\\\x00") != null) return error.RedirectOrigin;
    if (std.mem.startsWith(u8, value, "https://localhost/")) return value;
    if (value[0] == '/' and !std.mem.startsWith(u8, value, "//"))
        return a.print("https://localhost{s}", .{value});
    return error.RedirectOrigin;
}

test "avatar redirects retain the literal trusted HTTPS origin" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings(
        "https://localhost/theme/image.php/rev/u/f1",
        try localRedirect(a, "/theme/image.php/rev/u/f1"),
    );
    try std.testing.expectEqualStrings(
        "https://localhost/theme/image.php/rev/u/f1",
        try localRedirect(a, "https://localhost/theme/image.php/rev/u/f1"),
    );
    for ([_][]const u8{
        "",                             "http://localhost/image",

        "https://elsewhere/image",      "//elsewhere/image",

        "https://localhost.evil/image", "https://localhost@elsewhere/image",

        "/\\elsewhere/image",           "/image\r\nInjected: x",
        "/image\x00hidden",
    }) |bad| try std.testing.expectError(error.RedirectOrigin, localRedirect(a, bad));
}
