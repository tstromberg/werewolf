//! Observe control-socket absence and attempt a non-mutating write-open of rules.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "security")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const cache = try driver.system.account(io, a, "_rules");
    const engine = try driver.system.account(io, a, "suricata");
    try ctx.result(io, args[1], "rules-cache-identities", cache != engine);
    var forbidden = false;
    var entries: usize = 0;
    for ([_][]const u8{ "/run", "/data/svc/suricata" }) |path| {
        var dir = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
        defer dir.close(io);
        var walk = try dir.walk(a);
        defer walk.deinit();
        while (try walk.next(io)) |entry| {
            entries += 1;
            if (entries > 100000) return error.TooManyEntries;
            forbidden = forbidden or controlSocket(entry.basename);
        }
    }
    try ctx.result(io, args[1], "suricata-socket", !forbidden);
    const control = "/data/werewolf-rules-write-control";
    var file = try Io.Dir.cwd().createFile(io, control, .{});
    file.close(io);
    try Io.Dir.cwd().deleteFile(io, control);
    const rules = "/usr/share/suricata/rules/werewolf.rules";
    file = Io.Dir.cwd().openFile(io, rules, .{ .mode = .write_only }) catch |err| {
        return ctx.result(io, args[1], "suricata-rules", err == error.ReadOnlyFileSystem);
    };
    file.close(io);
    try ctx.result(io, args[1], "suricata-rules", false);
}

fn controlSocket(name: []const u8) bool {
    return std.mem.eql(u8, name, "suricata-command.socket") or
        std.mem.eql(u8, name, "suricata.socket");
}

test "both control-socket names are refused without rejecting an unrelated file" {
    try std.testing.expect(controlSocket("suricata-command.socket"));
    try std.testing.expect(controlSocket("suricata.socket"));
    try std.testing.expect(!controlSocket("suricata.socket.log"));
    try std.testing.expect(!controlSocket("suricata.log"));
}
