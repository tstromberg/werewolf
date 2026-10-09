//! network parses and checks a static IPv4 network: werewolf.ip, .gw and
//! .dns, from the kernel command line or a config tar's `network` file.
//! See lib/README.md.

const std = @import("std");

/// max_len is the largest network file accepted, in bytes.
pub const max_len = 512;

pub const Network = struct {
    /// ip is the address and prefix, such as 10.0.0.5/24.
    ip: []const u8 = "",
    gw: []const u8 = "",
    dns: []const u8 = "",
};

/// parse reads and checks a network file. It returns null and sets why
/// on an unknown, repeated or empty key, or on a value check refuses.
pub fn parse(text: []const u8, why: *[]const u8) ?Network {
    if (text.len > max_len) return refuse(why, "over 512 bytes");
    var n: Network = .{};
    var it = std.mem.tokenizeAny(u8, text, " \t\r\n");
    while (it.next()) |word| {
        const eq = std.mem.findScalar(u8, word, '=') orelse
            return refuse(why, "a word that is not KEY=VALUE");
        const slot: *[]const u8 = if (std.mem.eql(u8, word[0..eq], "werewolf.ip"))
            &n.ip
        else if (std.mem.eql(u8, word[0..eq], "werewolf.gw"))
            &n.gw
        else if (std.mem.eql(u8, word[0..eq], "werewolf.dns"))
            &n.dns
        else
            return refuse(why, "a key other than werewolf.ip, werewolf.gw and werewolf.dns");
        if (slot.len > 0) return refuse(why, "a key given twice");
        slot.* = word[eq + 1 ..];
        if (slot.len == 0) return refuse(why, "a key with no value");
    }
    return check(n, why);
}

/// check returns n if it is valid, or null with why set. lib/cmdline.zig
/// applies it to the command line too, so both sources obey one set of rules.
pub fn check(n: Network, why: *[]const u8) ?Network {
    if (n.ip.len == 0) return refuse(why, "no werewolf.ip");
    const a = address(n.ip) catch return refuse(
        why,
        "werewolf.ip is not ADDRESS/PREFIX: a dotted quad, a prefix of 1 to 32, a usable host",
    );
    if (n.gw.len > 0) _ = gateway(a, n.gw) catch |err| return refuse(why, switch (err) {
        error.Address => "werewolf.gw is not a usable address",
        error.Gateway => "werewolf.gw is the address, or its subnet's network or broadcast",
    });
    if (n.dns.len > 0) {
        const dns = ip4(n.dns) catch return refuse(why, "werewolf.dns is not an IPv4 address");
        if (!usable(dns)) return refuse(why, "werewolf.dns is not a usable address");
    }
    return n;
}

/// format writes n as a network file.
pub fn format(buf: []u8, n: Network) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.print("werewolf.ip={s}", .{n.ip});
    if (n.gw.len > 0) try w.print(" werewolf.gw={s}", .{n.gw});
    if (n.dns.len > 0) try w.print(" werewolf.dns={s}", .{n.dns});
    try w.writeByte('\n');
    return w.buffered();
}

pub const Ip4 = [4]u8;
pub const Address = struct { addr: Ip4, prefix: u6 };

/// address parses ADDR/PREFIX for a host: a usable address, a prefix of 1
/// to 32 and, below /31 (RFC 3021), not the subnet's network or broadcast.
pub fn address(s: []const u8) error{Address}!Address {
    const a = try cidr(s);
    if (a.prefix == 0 or !usable(a.addr)) return error.Address;
    if (a.prefix <= 30 and edge(a.addr, a.prefix)) return error.Address;
    return a;
}

/// gateway parses a gateway for a: a usable address other than a's, and
/// not the network or broadcast of a's subnet. A gateway outside the subnet
/// is allowed (GCP gives a /32); iface-up adds a host route to it first.
pub fn gateway(a: Address, s: []const u8) error{ Address, Gateway }!Ip4 {
    const gw = try ip4(s);
    if (!usable(gw)) return error.Address;
    if (std.mem.eql(u8, &gw, &a.addr)) return error.Gateway;
    if (a.prefix <= 30 and inSubnet(gw, a.addr, a.prefix) and edge(gw, a.prefix))
        return error.Gateway;
    return gw;
}

/// cidr parses ADDR/PREFIX with any address and a prefix of 0 to 32, as a
/// route's destination, 0.0.0.0/0 included.
pub fn cidr(s: []const u8) error{Address}!Address {
    const slash = std.mem.findScalar(u8, s, '/') orelse return error.Address;
    return .{
        .addr = try ip4(s[0..slash]),
        .prefix = @intCast(try number(s[slash + 1 ..], 0, 32)),
    };
}

/// edge reports whether a is its subnet's network or broadcast address.
fn edge(a: Ip4, prefix: u6) bool {
    const host = toInt(a) & ~mask(prefix);
    return host == 0 or host == ~mask(prefix);
}

/// ip4 parses a dotted quad: four numbers 0 to 255 with no leading zeros.
pub fn ip4(s: []const u8) error{Address}!Ip4 {
    var out: Ip4 = undefined;
    var parts = std.mem.splitScalar(u8, s, '.');
    for (&out) |*o| o.* = @intCast(try number(parts.next() orelse return error.Address, 0, 255));
    if (parts.next() != null) return error.Address;
    return out;
}

/// number parses min to max: plain digits, no sign or leading zero.
fn number(s: []const u8, min: u32, max: u32) error{Address}!u32 {
    if (s.len == 0 or s.len > 3 or (s.len > 1 and s[0] == '0')) return error.Address;
    var v: u32 = 0;
    for (s) |c| {
        if (!std.ascii.isDigit(c)) return error.Address;
        v = v * 10 + (c - '0');
    }
    if (v < min or v > max) return error.Address;
    return v;
}

/// usable reports whether a can be a host: 1.0.0.0 to 223.255.255.255
/// outside 127.0.0.0/8. That excludes 0.0.0.0/8 (RFC 1122), loopback,
/// multicast, reserved and broadcast.
pub fn usable(a: Ip4) bool {
    return a[0] != 0 and a[0] != 127 and a[0] < 224;
}

pub fn inSubnet(a: Ip4, b: Ip4, prefix: u6) bool {
    return toInt(a) & mask(prefix) == toInt(b) & mask(prefix);
}

pub fn toInt(a: Ip4) u32 {
    return std.mem.readInt(u32, &a, .big);
}

pub fn mask(prefix: u6) u32 {
    return if (prefix == 0) 0 else ~@as(u32, 0) << @intCast(32 - prefix);
}

fn refuse(why: *[]const u8, text: []const u8) ?Network {
    why.* = text;
    return null;
}

const testing = std.testing;

test parse {
    var why: []const u8 = "";
    const n = parse(
        "werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2\nwerewolf.dns=10.0.2.3\n",
        &why,
    ).?;
    try testing.expectEqualStrings("10.0.2.15/24", n.ip);
    try testing.expectEqualStrings("10.0.2.2", n.gw);
    try testing.expectEqualStrings("10.0.2.3", n.dns);
    try testing.expectEqualStrings(
        "192.168.5.15/24",
        parse("werewolf.ip=192.168.5.15/24", &why).?.ip,
    );
    _ = parse("werewolf.ip=10.0.0.0/31 werewolf.gw=10.0.0.1", &why).?;
    _ = parse("werewolf.ip=10.0.0.9/32", &why).?;
    // A gateway outside the subnet is taken as on the link: GCP's /32,
    // or a provider's gateway elsewhere.
    _ = parse("werewolf.ip=10.128.0.5/32 werewolf.gw=10.128.0.1", &why).?;
    _ = parse("werewolf.ip=10.0.0.5/24 werewolf.gw=10.0.1.1", &why).?;
    for ([_][]const u8{
        "",
        "werewolf.gw=10.0.0.1",
        "werewolf.ip=10.0.0.5/24 werewolf.ip=10.0.0.6/24",
        "werewolf.ip=10.0.0.5/24 werewolf.data=vda",
        "werewolf.ip=10.0.0.5/24 init=/bin/sh",
        "werewolf.ip=10.0.0.5",
        "werewolf.ip=10.0.0.5/0",
        "werewolf.ip=10.0.0.5/33",
        "werewolf.ip=10.0.0.0/24",
        "werewolf.ip=10.0.0.255/24",
        "werewolf.ip=fd00::5/64",
        "werewolf.ip=127.0.0.5/8",
        "werewolf.ip=224.0.0.5/24",
        "werewolf.ip=10.0.0.5/+24",
        "werewolf.ip=10.0.0.5/024",
        "werewolf.ip=10.0.0.05/24",
        "werewolf.ip=10.0.0.5/24 werewolf.gw=10.0.0.5",
        "werewolf.ip=10.0.0.5/24 werewolf.gw=10.0.0.255",
        "werewolf.ip=10.0.0.5/24 werewolf.dns=255.255.255.255",
        "werewolf.ip=10.0.0.5/24 werewolf.dns=0.0.0.0",
        "werewolf.ip=10.0.0.5/24 werewolf.dns=0.1.2.3",
        "werewolf.ip=0.1.2.3/8",
        "werewolf.ip=10.0.0.5/24 werewolf.dns=",
        "werewolf.ip=10.0.0.5/24 stray",
    }) |text| try testing.expectEqual(null, parse(text, &why));
    var long: [600]u8 = @splat(' ');
    @memcpy(long[0..24], "werewolf.ip=10.0.0.5/24 ");
    try testing.expectEqual(null, parse(&long, &why));
    try testing.expectEqualStrings("over 512 bytes", why);
}

test cidr {
    const any = try cidr("0.0.0.0/0");
    try testing.expectEqual(0, any.prefix);
    try testing.expectEqual(32, (try cidr("10.128.0.1/32")).prefix);
    for ([_][]const u8{ "10.0.0.1", "10.0.0.1/33", "10.0.0.1/+8", "10.0.0.1/08", "1.2.3/8" }) |s|
        try testing.expectError(error.Address, cidr(s));
    try testing.expectError(error.Address, address("10.0.0.5/0"));
}

test format {
    var buf: [128]u8 = undefined;
    const text = try format(&buf, .{ .ip = "10.0.2.15/24", .gw = "10.0.2.2" });
    try testing.expectEqualStrings("werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2\n", text);
    var why: []const u8 = "";
    try testing.expectEqualStrings("10.0.2.2", parse(text, &why).?.gw);
}
