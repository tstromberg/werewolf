//! DNS grants name immutable users and only the current IPv4 resolvers.
//! DHCP's trusted parent replaces these rules before publishing resolv.conf.
const std = @import("std");
const linux = std.os.linux;
const network = @import("network");
const route = @import("net-rule");
const sandbox = @import("sandbox");

pub const max_servers = 3;
const max_users = 64;
const max_rules = max_servers * (max_users * 4 + 2);
pub const policy_path = "/usr/share/werewolf/net";
pub const resolv_path = "/run/werewolf/network/resolv.conf";

pub const Users = struct {
    ids: [max_users]u32 = undefined,
    len: usize = 0,

    pub fn add(u: *Users, id: u32) !void {
        if (id == std.math.maxInt(u32)) return error.BadPolicy;
        for (u.ids[0..u.len]) |existing| if (existing == id) return;
        if (u.len == max_users) return error.BadPolicy;
        u.ids[u.len] = id;
        u.len += 1;
    }
};

/// users reads only dns lines; fence validates the complete compiled policy.
pub fn users(text: []const u8) !Users {
    var result: Users = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        if (!std.mem.eql(u8, words.next() orelse "", "dns")) continue;
        const id = std.fmt.parseInt(u32, words.next() orelse "", 10) catch return error.BadPolicy;
        if (words.next() != null) return error.BadPolicy;
        try result.add(id);
    }
    return result;
}

pub const Resolvers = struct {
    ips: [max_servers]network.Ip4 = undefined,
    len: usize = 0,

    pub fn add(r: *Resolvers, ip: network.Ip4) !void {
        if (!network.usable(ip)) return error.BadResolver;
        for (r.ips[0..r.len]) |existing| if (std.mem.eql(u8, &existing, &ip)) return;
        if (r.len == max_servers) return error.BadResolver;
        r.ips[r.len] = ip;
        r.len += 1;
    }

    pub fn same(a: Resolvers, b: Resolvers) bool {
        return std.mem.eql(network.Ip4, a.ips[0..a.len], b.ips[0..b.len]);
    }
};

/// resolvers accepts the nameserver lines init or DHCP wrote, never a hostname.
pub fn resolvers(text: []const u8) !Resolvers {
    var result: Resolvers = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        const key = words.next() orelse continue;
        if (key[0] == '#' or key[0] == ';') continue;
        if (!std.mem.eql(u8, key, "nameserver")) return error.BadResolver;
        const ip = network.ip4(words.next() orelse "") catch return error.BadResolver;
        if (words.next() != null) return error.BadResolver;
        try result.add(ip);
    }
    return result;
}

pub const Socket = struct {
    fd: i32,
    seq: u32 = 1,

    pub fn open() !Socket {
        return .{ .fd = @intCast(try sandbox.sys(linux.socket(
            linux.AF.NETLINK,
            linux.SOCK.RAW | linux.SOCK.CLOEXEC,
            linux.NETLINK.ROUTE,
        ), "DNS netlink socket")) };
    }

    pub fn close(s: Socket) void {
        _ = linux.close(s.fd);
    }

    pub fn change(s: *Socket, kind: u16, r: route.Rule) !void {
        var buf: [256]u8 = undefined;
        const seq = s.seq;
        s.seq +%= 1;
        route.send(s.fd, route.ruleMessage(&buf, seq, kind, r), seq, "DNS rule") catch |err| {
            if (err == error.SystemCall and
                ((kind == route.RTM_NEWRULE and sandbox.failed_errno == .EXIST) or
                    (kind == route.RTM_DELRULE and sandbox.failed_errno == .NOENT))) return;
            return err;
        };
    }
};

/// plan includes exact destination grants and exact source reply rules.
/// Priority 99 precedes the cloud metadata refusal: GCP uses its address for DNS.
/// Replies reach ephemeral ports alone, leaving unadvertised listeners closed.
pub fn plan(u: Users, r: *const Resolvers, buf: *[max_rules]route.Rule) []const route.Rule {
    var n: usize = 0;
    if (u.len == 0) return buf[0..0];
    for (r.ips[0..r.len]) |*ip| for ([_]route.Proto{ .udp, .tcp }) |proto| {
        for (u.ids[0..u.len]) |id| {
            buf[n] = .{
                .priority = 99,
                .action = 1,
                .table = 254,
                .from_here = true,
                .dst = ip,
                .proto = proto,
                .dport = 53,
                .uid = id,
            };
            n += 1;
            buf[n] = buf[n - 1];
            buf[n].action = 7; // A missing route is unreachable, not permission denied.
            buf[n].table = 0;
            n += 1;
        }
        buf[n] = .{
            .priority = 300,
            .action = 1,
            .table = 255,
            .src = ip,
            .proto = proto,
            .sport = 53,
            .dport = 32768,
            .dport_last = 60999,
        };
        n += 1;
    };
    return buf[0..n];
}

/// replace revokes old grants before adding new ones. No broad port-53 grant
/// exists during a renewal; an error prevents publishing the new resolver file.
/// A socket-like test double can exercise failures and renewal ordering.
pub fn replace(socket: anytype, u: Users, old: Resolvers, new: Resolvers) !void {
    if (old.same(new)) return;
    var buf: [max_rules]route.Rule = undefined;
    for (plan(u, &old, &buf)) |r| try socket.change(route.RTM_DELRULE, r);
    for (plan(u, &new, &buf)) |r| try socket.change(route.RTM_NEWRULE, r);
}

const testing = std.testing;

test "resolver and user input is bounded, deduplicated and fails closed" {
    const u = try users("connect 69 tcp 443\ndns 69\ndns 0\ndns 69\n");
    try testing.expectEqualSlices(u32, &.{ 69, 0 }, u.ids[0..u.len]);
    for ([_][]const u8{ "dns", "dns all", "dns nobody", "dns 4294967295", "dns 0 extra" }) |bad|
        try testing.expectError(error.BadPolicy, users(bad));
    const r = try resolvers("# detected\nnameserver 192.168.5.3\nnameserver 192.168.5.3\n");
    try testing.expectEqual(1, r.len);
    for ([_][]const u8{
        "nameserver bad",
        "nameserver 127.0.0.1",
        "nameserver 0.0.0.0",
        "nameserver 224.0.0.1",
        "nameserver ::1",
        "nameserver 1.2.3.4 extra",
        "search bad",
        "nameserver 1.1.1.1\nnameserver 2.2.2.2\nnameserver 3.3.3.3\nnameserver 4.4.4.4\n",
    }) |bad| try testing.expectError(error.BadResolver, resolvers(bad));
    try testing.expectEqual(0, (try resolvers("")).len);
    var full: Users = .{};
    for (0..max_users) |i| try full.add(@intCast(i));
    try testing.expectError(error.BadPolicy, full.add(100));
    const servers = try resolvers("nameserver 1.1.1.1\nnameserver 2.2.2.2\nnameserver 3.3.3.3\n");
    var buf: [max_rules]route.Rule = undefined;
    try testing.expectEqual(max_rules, plan(full, &servers, &buf).len);
}

test "DHCP renewal revokes first, skips unchanged leases, and stops on errors" {
    const Fake = struct {
        deleted: usize = 0,
        added: usize = 0,
        fail_delete: bool = false,
        fn change(f: *@This(), kind: u16, _: route.Rule) !void {
            if (kind == route.RTM_DELRULE) {
                try testing.expectEqual(0, f.added);
                if (f.fail_delete) return error.Refused;
                f.deleted += 1;
            } else f.added += 1;
        }
    };
    const u = try users("dns 69\n");
    const a = try resolvers("nameserver 192.168.5.3\n");
    const b = try resolvers("nameserver 169.254.169.254\n");
    var f: Fake = .{};
    try replace(&f, u, a, a);
    try testing.expectEqual(0, f.added + f.deleted);
    try replace(&f, u, a, b);
    try testing.expectEqual(6, f.deleted);
    try testing.expectEqual(6, f.added);
    f = .{ .fail_delete = true };
    try testing.expectError(error.Refused, replace(&f, u, a, b));
    try testing.expectEqual(0, f.added);
    f = .{};
    try replace(&f, u, a, .{});
    try testing.expectEqual(6, f.deleted);
    try testing.expectEqual(0, f.added);
}
