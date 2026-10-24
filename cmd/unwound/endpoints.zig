//! Default exclusions for arbitrary DNS grants: shared callback, request
//! capture, tunnel and address-to-DNS services, and IP-prefixed hostnames.
//! Explicit name grants remain deliberate authority.
const std = @import("std");
const mem = std.mem;

pub const Reason = enum { callback_domain, ip_prefix };

/// Match complete DNS suffixes, never substrings. Input is wire.Name's
/// canonical lowercase name without a terminal dot.
pub fn reason(name: []const u8) ?Reason {
    for (domains) |domain| {
        if (mem.eql(u8, name, domain) or
            (name.len > domain.len and mem.endsWith(u8, name, domain) and
                name[name.len - domain.len - 1] == '.')) return .callback_domain;
    }
    if (ipPrefix(name)) return .ip_prefix;
    return null;
}

/// Both public and private addresses count. Recognize dotted/dashed IPv4,
/// integer/hex IPv4 and dashed IPv6 before an arbitrary DNS suffix.
fn ipPrefix(name: []const u8) bool {
    var at: usize = 0;
    for (0..4) |octet| {
        const start = at;
        while (at < name.len and std.ascii.isDigit(name[at])) : (at += 1) {}
        if (at == start or at - start > 3) break;
        _ = std.fmt.parseInt(u8, name[start..at], 10) catch break;
        if (at == name.len or (name[at] != '.' and name[at] != '-')) break;
        at += 1;
        if (octet == 3 and at < name.len)
            return !mem.eql(u8, name[at..], "in-addr.arpa");
    }
    const dot = mem.findScalar(u8, name, '.') orelse return false;
    const label = name[0..dot];
    if (dot + 1 == name.len) return false;
    // Eight hex digits are a common IPv4 hostname encoding. Also recognize
    // explicit 0x notation and the decimal 32-bit address representation.
    if (label.len == 8 or (label.len == 10 and mem.startsWith(u8, label, "0x"))) {
        const hex = if (label.len == 10) label[2..] else label;
        if (std.fmt.parseInt(u32, hex, 16)) |_| return true else |_| {}
    }
    if (label.len >= 8 and label.len <= 10) {
        if (std.fmt.parseInt(u32, label, 10)) |_| return true else |_| {}
    }
    // IPv6 DNS services replace colons by hyphens, including -- for ::.
    if (label.len > 45 or mem.findScalar(u8, label, '-') == null) return false;
    var address: [45]u8 = undefined;
    for (label, 0..) |c, i| address[i] = if (c == '-') ':' else c;
    _ = std.Io.net.Ip6Address.parse(address[0..label.len], 0) catch return false;
    return true;
}

/// Compiled into the immutable resolver; no runtime downloads or mutable
/// blocklist files. These services also have legitimate uses, granted by name.
pub const domains = [_][]const u8{
    "1u.ms",
    "beeceptor.com",
    "burpcollaborator.net",
    "canarytokens.com",
    "ceye.io",
    "dnslog.cn",
    "eyes.sh",
    "gobygo.net",
    "hookbin.com",
    "httpbin.org",
    "interact.sh",
    "interactsh.com",
    "jsonkeeper.com",
    "lhr.life",
    "loca.lt",
    "localhost.run",
    "localtunnel.me",
    "mockbin.io",
    "mockbin.org",
    "ngrok-free.app",
    "ngrok-free.dev",
    "ngrok.app",
    "ngrok.dev",
    "ngrok.io",
    "nip.io",
    "oast.fun",
    "oast.live",
    "oast.me",
    "oast.online",
    "oast.pro",
    "oast.site",
    "oastify.com",
    "pipedream.net",
    "postman-echo.com",
    "putsreq.com",
    "rbndr.us",
    "requestbin.com",
    "requestbin.net",
    "requestcatcher.com",
    "requestinspector.com",
    "serveo.net",
    "sslip.io",
    "trycloudflare.com",
    "tu4.org",
    "webhook.site",
    "xip.io",
};

test "callback domains include their apex and descendants, on label boundaries" {
    var buf: [128]u8 = undefined;
    for (domains) |domain| {
        try std.testing.expectEqual(Reason.callback_domain, reason(domain).?);
        const child = try std.mem.print(&buf, "token.child.{s}", .{domain});
        try std.testing.expectEqual(Reason.callback_domain, reason(child).?);
        const sibling = try std.mem.print(&buf, "safe{s}", .{domain});
        try std.testing.expectEqual(null, reason(sibling));
        const suffix = try std.mem.print(&buf, "{s}.example.com", .{domain});
        try std.testing.expectEqual(null, reason(suffix));
    }
}

test "IP-prefixed hostnames are denied independently of their DNS provider" {
    for ([_][]const u8{
        "127.0.0.1.attacker.example",
        "127.0.0.1.203-0-113-5.attacker.example",
        "192-0-2-1.example.com",
        "192-0-2-1-app.example.com",
        "8.8.8.8.example.com",
        "000.000.000.000.example.com",
        "7f000001.example.com",
        "0x7f000001.example.com",
        "2130706433.example.com",
        "--1.example.com",
        "2001-db8--1.example.com",
        "2001-0db8-0000-0000-0000-0000-0000-0001.example.com",
    }) |name| try std.testing.expectEqual(Reason.ip_prefix, reason(name).?);
    for ([_][]const u8{
        "example.com",
        "1.example.com",
        "1.2.3.example.com",
        "256.0.0.1.example.com",
        "1234.0.0.1.example.com",
        "api.192.0.2.1.example.com",
        "ec2-54-123-45-67.compute-1.amazonaws.com",
        "v1-2-3-4.example.com",
        "2001-db8-z--1.example.com",
        "15.2.0.192.in-addr.arpa",
    }) |name| {
        try std.testing.expectEqual(null, reason(name));
    }
}
