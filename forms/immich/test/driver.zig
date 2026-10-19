//! Upload fixture identity and recursive storage checks; HTTP assertions live in YAML.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Json = std.json.Value;
const record = "/data/immich-test.json";
const Stored = struct { run: []const u8, asset: []const u8 };

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    if (std.mem.eql(u8, args[2], "upload")) {
        if (std.mem.eql(u8, ctx.phase, "verify")) {
            _ = try stored(io, a, ctx);
            return ctx.result(io, args[1], "immich-upload-kept", true);
        }
        var web = try driver.fetch.Client.init(a);
        defer web.deinit();
        var login = try request(a, "/api/auth/login");
        try login.object.put(a, "method", driver.system.text("POST"));
        var credentials = driver.system.object(a);
        try credentials.object.put(a, "email", driver.system.text("admin@example.com"));
        try credentials.object.put(
            a,
            "password",
            driver.system.text(try driver.system.read(io, a, "/run/config/caddy/admin-password")),
        );
        try login.object.put(a, "json", credentials);
        const auth = try web.request(login, 10000, a);
        const login_status = auth.object.get("status").?.integer;
        if (login_status != 200 and login_status != 201) {
            std.debug.print("test-immich: login status {d}\n", .{login_status});
            return error.Login;
        }
        const token = try std.json.parseFromSliceLeaky(
            struct { accessToken: []const u8 },
            a,
            auth.object.get("body").?.string,
            .{ .ignore_unknown_fields = true },
        );
        if (token.accessToken.len == 0) return error.EmptyToken;
        var upload = try request(a, "/api/assets");
        try upload.object.put(a, "method", driver.system.text("POST"));
        try upload.object.put(a, "bearer", driver.system.text(token.accessToken));
        var fields = driver.system.object(a);
        for ([_][]const u8{ "fileCreatedAt", "fileModifiedAt" }) |name|
            try fields.object.put(a, name, driver.system.text("2001-02-03T04:05:06.000Z"));
        var photo = driver.system.object(a);
        try photo.object.put(a, "file", driver.system.text("/run/config/tests/immich/photo"));
        try photo.object.put(a, "filename", driver.system.text("check.jpg"));
        try photo.object.put(a, "type", driver.system.text("image/jpeg"));
        try fields.object.put(a, "assetData", photo);
        try upload.object.put(a, "multipart", fields);
        const response = try web.request(upload, 30000, a);
        const status = response.object.get("status").?.integer;
        if (status != 200 and status != 201) return error.Upload;
        const asset = try std.json.parseFromSliceLeaky(
            struct { id: []const u8 },
            a,
            response.object.get("body").?.string,
            .{ .ignore_unknown_fields = true },
        );
        if (!uuid(asset.id)) return error.AssetId;
        const bytes = try std.json.Stringify.valueAlloc(
            a,
            Stored{ .run = ctx.run, .asset = asset.id },
            .{},
        );
        var file = try Io.Dir.cwd().createFile(io, record, .{ .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        try file.sync(io);
        try ctx.result(io, args[1], "immich-upload", true);
    } else if (std.mem.eql(u8, args[2], "files")) {
        _ = try stored(io, a, ctx);
        const metadata = try driver.system.file(
            io,
            a,
            "/data/svc/immich/upload",
            driver.system.object(a),
        );
        const uid = try driver.system.account(io, a, "_oci-immich");
        if (metadata.object.get("uid").?.integer != uid) return error.LibraryOwner;
        try ctx.result(
            io,
            args[1],
            "immich-library",
            try hasFile(io, "/data/svc/immich/upload", ".jpg"),
        );
        try ctx.result(
            io,
            args[1],
            "immich-thumbnail",
            try hasFile(io, "/data/svc/immich/thumbs", ".webp"),
        );
    } else return error.Usage;
}

fn request(a: Allocator, path: []const u8) !Json {
    var req = driver.system.object(a);
    try req.object.put(a, "url", driver.system.text(try a.print("https://localhost{s}", .{path})));
    try req.object.put(
        a,
        "ca",
        driver.system.text("/data/svc/caddy/pki/authorities/local/root.crt"),
    );
    return req;
}

fn stored(io: Io, a: Allocator, ctx: driver.Run) !Stored {
    const value = try std.json.parseFromSliceLeaky(
        Stored,
        a,
        try driver.system.read(io, a, record),
        .{},
    );
    if (!std.mem.eql(u8, value.run, ctx.run) or !uuid(value.asset)) return error.StaleAsset;
    return value;
}

fn uuid(value: []const u8) bool {
    if (value.len != 36) return false;
    for (value, 0..) |c, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (c != '-') return false;
        } else if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

fn hasFile(io: Io, path: []const u8, suffix: []const u8) !bool {
    var dir = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer dir.close(io);
    var remaining: usize = 10000;
    return walk(io, dir, suffix, 0, &remaining);
}

fn walk(io: Io, dir: Io.Dir, suffix: []const u8, depth: usize, remaining: *usize) anyerror!bool {
    if (depth > 8) return error.StorageTooDeep;
    var entries = dir.iterate();
    while (try entries.next(io)) |entry| {
        if (remaining.* == 0) return error.TooManyFiles;
        remaining.* -= 1;
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, suffix)) return true;
        if (entry.kind != .directory) continue;
        var child = try dir.openDir(io, entry.name, .{ .iterate = true });
        defer child.close(io);
        if (try walk(io, child, suffix, depth + 1, remaining)) return true;
    }
    return false;
}

test "asset IDs cannot turn capture values into filesystem paths" {
    try std.testing.expect(uuid("01234567-89ab-cdef-0123-456789abcdef"));
    try std.testing.expect(!uuid("../../other"));
    try std.testing.expect(!uuid("0123456789ab-cdef-0123-456789abcdef"));
}

test "storage search finds nested files, ignores symlinks and is bounded" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "owner/year");
    try tmp.dir.writeFile(io, .{ .sub_path = "owner/year/check.jpg", .data = "photo" });
    try tmp.dir.symLink(io, "owner/year/check.jpg", "fake.webp", .{});
    var remaining: usize = 100;
    try std.testing.expect(try walk(io, tmp.dir, ".jpg", 0, &remaining));
    remaining = 100;
    try std.testing.expect(!try walk(io, tmp.dir, ".webp", 0, &remaining));
    remaining = 0;
    try std.testing.expectError(error.TooManyFiles, walk(io, tmp.dir, ".jpg", 0, &remaining));
    try std.testing.expectError(error.StorageTooDeep, walk(io, tmp.dir, ".jpg", 9, &remaining));
}
