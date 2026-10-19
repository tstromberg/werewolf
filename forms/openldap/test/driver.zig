//! Audit regular service files for forgotten plaintext credentials.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "privacy")) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    const secret = std.mem.trimEnd(u8, try driver.system.read(
        init.io,
        a,
        "/run/config/openldap/admin-password",
    ), "\r\n");
    if (secret.len == 0) return error.EmptySecret;
    var dir = try Io.Dir.cwd().openDir(init.io, "/run/svc/openldap", .{ .iterate = true });
    defer dir.close(init.io);
    const ok = clean(init.io, a, dir, secret) catch |err| {
        std.debug.print("openldap privacy: {s}\n", .{@errorName(err)});
        return ctx.result(init.io, args[1], "ldap-secret-copies", false);
    };
    try ctx.result(init.io, args[1], "ldap-secret-copies", ok);
}

fn clean(io: Io, a: std.mem.Allocator, dir: Io.Dir, secret: []const u8) !bool {
    var walk = try dir.walk(a);
    defer walk.deinit();
    var files: usize = 0;
    var total: usize = 0;
    while (try walk.next(io)) |entry| {
        if (entry.kind != .file) continue;
        files += 1;
        if (files > 128) return error.TooManyFiles;
        const contents = try dir.readFileAlloc(io, entry.path, a, .limited(1 << 20));
        defer a.free(contents);
        total += contents.len;
        if (total > 8 << 20) return error.TooMuchData;
        if (std.mem.find(u8, contents, secret) != null) return false;
    }
    if (files == 0) return error.NoServiceFiles;
    return true;
}

test "a nested forgotten copy fails the credential audit" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "nested");
    try tmp.dir.writeFile(io, .{ .sub_path = "slapd.conf", .data = "rootpw {ARGON2}$hash\n" });
    try std.testing.expect(try clean(io, std.testing.allocator, tmp.dir, "secret-password"));
    try tmp.dir.writeFile(io, .{ .sub_path = "nested/copy", .data = "secret-password\n" });
    try std.testing.expect(!try clean(io, std.testing.allocator, tmp.dir, "secret-password"));
}
