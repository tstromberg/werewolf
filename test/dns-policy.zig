//! Test-only driver for replacing DNS grants inside an isolated network namespace.
const std = @import("std");
const dns = @import("dns");
const route = @import("net-rule");

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len == 2) {
        const broad = std.mem.eql(u8, args[1], "--broad-root");
        const dns6 = std.mem.eql(u8, args[1], "--root-dns-v6");
        const https6 = std.mem.eql(u8, args[1], "--root-https-v6");
        if (!broad and !dns6 and !https6) return error.Usage;
        var socket = try dns.Socket.open();
        defer socket.close();
        for ([_]struct {
            route.Proto,
            u16,
        }{ .{ .udp, 53 }, .{ .tcp, 53 }, .{ .tcp, 443 } }) |target| {
            if (dns6 and target[1] != 53 or https6 and target[1] != 443) continue;
            var rule: route.Rule = .{
                .family = if (broad) std.os.linux.AF.INET else std.os.linux.AF.INET6,
                .priority = 200,
                .action = 1,
                .table = 254,
                .from_here = true,
                .uid = 0,
                .proto = target[0],
                .dport = target[1],
            };
            try socket.change(route.RTM_NEWRULE, rule);
            rule.action = 7;
            rule.table = 0;
            try socket.change(route.RTM_NEWRULE, rule);
        }
        return;
    }
    if (args.len != 3) return error.Usage;
    const users = try dns.users(try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        dns.policy_path,
        gpa,
        .limited(4096),
    ));
    var socket = try dns.Socket.open();
    defer socket.close();
    try dns.replace(&socket, users, try dns.resolvers(args[1]), try dns.resolvers(args[2]));
}
