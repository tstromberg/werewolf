//! No ingress grants beyond the base image's loopback DNS listener.
const std = @import("std");
const driver = @import("test-driver");

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "policy")) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    const policy = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        "/usr/share/werewolf/net",
        a,
        .limited(64 << 10),
    );
    try ctx.result(init.io, args[1], "tailscale-no-ingress", noIngress(policy));
}

fn noIngress(policy: []const u8) bool {
    var dns = false;
    var lines = std.mem.splitScalar(u8, policy, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        if (!std.mem.eql(u8, words.next() orelse continue, "listen")) continue;
        if (dns) return false;
        for ([_][]const u8{ "tcp", "53", "loopback" }) |want|
            if (!std.mem.eql(u8, words.next() orelse return false, want)) return false;
        if (words.next() != null) return false;
        dns = true;
    }
    return dns;
}

test "only the base loopback DNS grant is allowed" {
    try std.testing.expect(noIngress("connect 123 tcp 443\nlisten tcp 53 loopback\n"));
    try std.testing.expect(noIngress("listen\ttcp 53 loopback\n"));
    for ([_][]const u8{
        "listen tcp 53\n",
        "listen tcp 53 lan\n",
        "listen tcp 22\n",
        "listen 123 udp 41641\n",
        "listen tcp 53 loopback\nlisten tcp 22\n",
        "listen tcp 53 loopback\nlisten 123 udp 41641\n",
        "listen tcp 53 loopback\nlisten tcp 53 loopback\n",
        "connect 123 tcp 443\n",
    }) |policy| try std.testing.expect(!noIngress(policy));
}
