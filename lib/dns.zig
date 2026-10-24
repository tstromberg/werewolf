//! DNS grants name immutable users and only the current IPv4 resolvers.
//! Every program asks unwound, at 127.0.0.53; its upstream user alone has a
//! `dns` grant, to the resolvers in upstream_path. DHCP's trusted parent
//! replaces those rules before publishing a new upstream file.
const std = @import("std");
const linux = std.os.linux;
const network = @import("network");
const route = @import("net-rule");
const sandbox = @import("sandbox");

pub const max_servers = 3;
pub const max_users = 64;
const max_rules = max_servers * (max_users * 4 + 2);
pub const policy_path = "/usr/share/werewolf/net";
/// resolv_path is what /etc/resolv.conf links to: unwound, never upstream.
pub const resolv_path = "/run/werewolf/network/resolv.conf";
/// service_address_path is the LAN IPv4 address for DNS servers that share
/// port 53 with unwound's loopback listener.
pub const service_address_path = "/run/werewolf/network/service-address";
pub const resolv_text = "nameserver 127.0.0.53\n";
/// upstream_path names the resolvers DHCP or the command line gave, as
/// nameserver lines, for fence, DHCP and unwound alone.
pub const network_dir = "/run/werewolf/network";
pub const upstream_name = "upstream";
pub const upstream_path = network_dir ++ "/" ++ upstream_name;
pub const dhcp_domain_name = "dhcp-domain";
pub const config_domain_name = "config-domain";
pub const dhcp_domain_path = network_dir ++ "/" ++ dhcp_domain_name;
pub const config_domain_path = network_dir ++ "/" ++ config_domain_name;
/// A form that ships this immutable file runs a DNSSEC-validating resolver
/// on 127.0.0.1. DHCP cannot substitute a remote server for it.
pub const local_validator_path = "/usr/share/werewolf/dnssec-local";
pub const local_validator_text = "nameserver 127.0.0.1\n";
/// age_id is _unwoundage, the user the age authority and observer run as.
pub const age_id: u32 = 55;
/// The age authority binds this before init makes its directory read-only
/// to root's main mount namespace.
pub const age_socket_dir = "/run/werewolf-age";
pub const age_socket_path = age_socket_dir ++ "/age.sock";
/// An image that ships this marker enforces domain age; without it, unwound
/// only observes. Evidence lives on /data, or under /run when there is none.
pub const age_marker_path = "/usr/share/werewolf/age-enforce";
pub const age_durable_dir = "/data/svc/unwound-age";
pub const age_temporary_dir = "/run/werewolf-age-cache";

/// normalizeSystemDomain accepts one assigned DNS suffix for the automatic
/// age exemption. A single label or a malformed value cannot widen policy.
pub fn normalizeSystemDomain(raw: []const u8, out: *[253]u8) ?[]const u8 {
    if (raw.len == 0 or raw.len > 254) return null;
    const n = raw.len - @intFromBool(raw[raw.len - 1] == '.');
    if (n == 0 or n > out.len) return null;
    var dots: usize = 0;
    var first: usize = 0;
    for (raw[0..n], 0..) |c, i| {
        const lower = std.ascii.toLower(c);
        if (lower == '.') {
            if (i == first or i - first > 63 or out[i - 1] == '-') return null;
            dots += 1;
            first = i + 1;
        } else if (!std.ascii.isLower(lower) and !std.ascii.isDigit(lower) and lower != '-') {
            return null;
        } else if (i == first and lower == '-') return null;
        out[i] = lower;
    }
    if (dots == 0 or n == first or n - first > 63 or out[n - 1] == '-') return null;
    return out[0..n];
}

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

    pub fn has(u: Users, id: u32) bool {
        for (u.ids[0..u.len]) |existing| if (existing == id) return true;
        return false;
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

/// resolver is unwound's address, the one nameserver every program reads.
pub const resolver = [4]u8{ 127, 0, 0, 53 };
/// labels is the loopback network unwound's clients send from, one address
/// per user, chosen by the kernel: fence routes each user's queries through
/// a table of its own, whose one route gives that address as the source.
pub const labels = [4]u8{ 127, 53, 0, 0 };
pub const label_table_base: u32 = 0x5300;

/// lookupUsers returns the users of lookup lines in the order they first
/// appear. The nth (from 0) sends from label(n) through table labelTable(n);
/// fence and unwound read the same immutable file, so they agree.
pub fn lookupUsers(text: []const u8) !Users {
    var result: Users = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        if (!std.mem.eql(u8, words.next() orelse "", "lookup")) continue;
        const id = std.fmt.parseInt(u32, words.next() orelse "", 10) catch return error.BadPolicy;
        try result.add(id);
    }
    return result;
}

/// label_ips holds every label, so rules can point at them for good.
pub const label_ips = ips: {
    var ips: [max_users][4]u8 = undefined;
    for (&ips, 0..) |*ip, n| ip.* = .{ labels[0], labels[1], 0, n + 1 };
    break :ips ips;
};

pub fn label(n: usize) [4]u8 {
    return label_ips[n];
}

pub fn labelTable(n: usize) u32 {
    return label_table_base + @as(u32, @intCast(n + 1));
}

/// labelIndex returns the n whose label is ip, if it is one.
pub fn labelIndex(u: Users, ip: [4]u8) ?usize {
    if (ip[0] != labels[0] or ip[1] != labels[1] or ip[2] != 0 or ip[3] == 0) return null;
    const n: usize = ip[3] - 1;
    return if (n < u.len) n else null;
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

/// validatedLocal accepts only the fixed loopback resolver installed by a
/// form, never a loopback address supplied by DHCP or a boot argument.
pub fn validatedLocal(text: []const u8) !Resolvers {
    if (!std.mem.eql(u8, text, local_validator_text)) return error.BadResolver;
    var result: Resolvers = .{};
    result.ips[0] = .{ 127, 0, 0, 1 };
    result.len = 1;
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
        const local = std.mem.eql(u8, ip, &[_]u8{ 127, 0, 0, 1 });
        for (u.ids[0..u.len]) |id| {
            buf[n] = .{
                .priority = if (local) 6 else 99,
                .action = 1,
                .table = if (local) 255 else 254,
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
            // Keep dynamic, source-specific replies separate from fence's
            // broad reply rules (300). Netlink's EEXIST lookup treats an
            // omitted source selector as a wildcard, which can hide those
            // broader rules when these were installed first.
            .priority = 301,
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

test "assigned system domain is canonical and bounded" {
    var out: [253]u8 = undefined;
    try testing.expectEqualStrings(
        "corp.example.com",
        normalizeSystemDomain("Corp.Example.COM.", &out).?,
    );
    for ([_][]const u8{
        "",              "local",           ".example.com",   "example..com",   "example.com..",
        "*.example.com", "a_b.example.com", "-a.example.com", "a-.example.com",
    }) |bad| try testing.expect(normalizeSystemDomain(bad, &out) == null);
}

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
    const local = try validatedLocal(local_validator_text);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &local.ips[0]);
    try testing.expectError(error.BadResolver, resolvers(local_validator_text));
    try testing.expectError(error.BadResolver, validatedLocal("nameserver 127.0.0.2\n"));
    var local_rules: [max_rules]route.Rule = undefined;
    const routes = plan(try users("dns 54\n"), &local, &local_rules);
    try testing.expectEqual(@as(u32, 255), routes[0].table);
    var full: Users = .{};
    for (0..max_users) |i| try full.add(@intCast(i));
    try testing.expectError(error.BadPolicy, full.add(100));
    const servers = try resolvers("nameserver 1.1.1.1\nnameserver 2.2.2.2\nnameserver 3.3.3.3\n");
    var buf: [max_rules]route.Rule = undefined;
    try testing.expectEqual(max_rules, plan(full, &servers, &buf).len);
}

test "lookup users get labels in the order they first appear" {
    const u = try lookupUsers("dns 69\nlookup 1001 a.example A\nconnect 5 tcp 443\n" ++
        "lookup 7 * A unfiltered\nlookup 1001 b.example TXT\n");
    try testing.expectEqualSlices(u32, &.{ 1001, 7 }, u.ids[0..u.len]);
    try testing.expectEqualSlices(u8, &.{ 127, 53, 0, 2 }, &label(1));
    try testing.expectEqual(0x5302, labelTable(1));
    try testing.expectEqual(1, labelIndex(u, .{ 127, 53, 0, 2 }).?);
    for ([_][4]u8{
        .{ 127, 53, 0, 0 },
        .{ 127, 53, 0, 3 },
        .{ 127, 53, 1, 1 },
        .{ 127, 0, 0, 1 },
    }) |ip|
        try testing.expectEqual(null, labelIndex(u, ip));
    try testing.expectError(error.BadPolicy, lookupUsers("lookup x a.example A\n"));
    var full: Users = .{};
    for (0..max_users) |i| try full.add(@intCast(i));
    try testing.expectEqualSlices(u8, &.{ 127, 53, 0, max_users }, &label(max_users - 1));
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
