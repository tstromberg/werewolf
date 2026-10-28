//! Require one current Log4j core without pinning Solr's bundled patch release.
const std = @import("std");
const driver = @import("test-driver");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "libraries")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    var dir = try std.Io.Dir.cwd().openDir(io, "/usr/lib/solr/server/lib/ext", .{
        .iterate = true,
    });
    defer dir.close(io);
    var it = dir.iterate();
    var entries: usize = 0;
    var cores: usize = 0;
    var safe = true;
    while (try it.next(io)) |entry| {
        entries += 1;
        if (entries > 1024) return error.TooManyLibraries;
        if (!std.mem.startsWith(u8, entry.name, "log4j-core-") or
            !std.mem.endsWith(u8, entry.name, ".jar")) continue;
        cores += 1;
        const stat = try dir.statFile(io, entry.name, .{ .follow_symlinks = false });
        safe = safe and safeCore(entry.name) and stat.kind == .file and stat.size > 0;
    }
    try ctx.result(io, args[1], "solr-log4j-version", cores == 1 and safe);
}

fn safeCore(name: []const u8) bool {
    const prefix = "log4j-core-";
    const suffix = ".jar";
    if (!std.mem.startsWith(u8, name, prefix) or !std.mem.endsWith(u8, name, suffix))
        return false;
    var parts = std.mem.splitScalar(u8, name[prefix.len .. name.len - suffix.len], '.');
    var version: [3]u32 = undefined;
    for (&version) |*part| {
        const text = parts.next() orelse return false;
        if (text.len == 0 or (text.len > 1 and text[0] == '0')) return false;
        for (text) |c| if (!std.ascii.isDigit(c)) return false;
        part.* = std.fmt.parseInt(u32, text, 10) catch return false;
    }
    // Retain the old probe's security floor, allowing newer Log4j 2 patches.
    return parts.next() == null and version[0] == 2 and
        (version[1] > 25 or (version[1] == 25 and version[2] >= 3));
}

test "Log4j's floor permits current releases and rejects old or ambiguous versions" {
    try std.testing.expect(safeCore("log4j-core-2.25.3.jar"));
    try std.testing.expect(safeCore("log4j-core-2.26.1.jar"));
    for ([_][]const u8{
        "log4j-core-2.14.1.jar",  "log4j-core-2.25.2.jar", "log4j-core-2.26.1-SNAPSHOT.jar",
        "log4j-core-2.026.1.jar", "log4j-core-3.0.0.jar",  "log4j-api-2.26.1.jar",
    }) |name| try std.testing.expect(!safeCore(name));
}
