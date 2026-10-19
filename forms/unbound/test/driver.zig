//! Check control sockets and policy overrides without adding guest tools.
const std = @import("std");
const driver = @import("test-driver");

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    var sockets: usize = 0;
    for ([_][]const u8{ "/run/svc/unbound", "/data/svc/unbound" }) |path| {
        var dir = try std.Io.Dir.cwd().openDir(init.io, path, .{ .iterate = true });
        defer dir.close(init.io);
        var walk = try dir.walk(a);
        defer walk.deinit();
        while (try walk.next(init.io)) |entry| {
            if (entry.kind == .unix_domain_socket) sockets += 1;
        }
    }
    try ctx.result(init.io, args[1], "unbound-no-sockets", sockets == 0);
    const config = try driver.system.read(init.io, a, "/etc/unbound/unbound.conf");
    const setup = try driver.system.read(init.io, a, "/run/svc/unbound/unbound-setup.conf");
    try ctx.result(init.io, args[1], "unbound-no-policy-override", !directive(
        config,
        "private-address:",
    ) and !directive(setup, "private-address:") and !directive(setup, "access-control:"));
}

fn directive(text: []const u8, name: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, std.mem.trimStart(u8, line, " \t\r"), name)) return true;
    }
    return false;
}

test "policy directives ignore comments and accept indentation" {
    try std.testing.expect(!directive("\t# No private-address: names\n", "private-address:"));
    try std.testing.expect(directive("  private-address: 10.0.0.0/8\n", "private-address:"));
    try std.testing.expect(directive("access-control: 0.0.0.0/0 allow\n", "access-control:"));
}
