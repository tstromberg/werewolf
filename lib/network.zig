//! A static network, as a config tar's `network` file gives one: the
//! kernel command line's own words, and only these, each at most once.
//!
//!     werewolf.ip=CIDR werewolf.gw=ADDR werewolf.dns=ADDR
//!
//! For machines whose network gives no address by DHCP: a hypervisor of
//! your own, bare metal, a form with no DHCP client. init reads it when
//! the command line has no werewolf.ip, before it brings the network up,
//! and the host's werewolf pack checks it with this same parser; iface-up,
//! which gives the NIC the address, checks it with the same rules (address
//! and gateway, below), so what the host packs the machine takes. IPv4: a
//! dotted quad with no leading zeros, a prefix of 1 to 32 in plain digits,
//! a usable host that is not its subnet's network or broadcast address; a
//! gateway, usable, not the address, and inside the subnet not its network
//! or broadcast either, or outside it, on the link, as GCP gives a /32's;
//! a usable resolver.

const std = @import("std");

/// The most a network file may hold.
pub const max_len = 512;

pub const Network = struct {
    /// Address and prefix, as werewolf.ip takes them: 10.0.0.5/24.
    ip: []const u8 = "",
    gw: []const u8 = "",
    dns: []const u8 = "",
};

/// The file's words, checked; or null, with why set.
pub fn parse(text: []const u8, why: *[]const u8) ?Network {
    if (text.len > max_len) return refuse(why, "over 512 bytes");
    var n: Network = .{};
    var it = std.mem.tokenizeAny(u8, text, " \t\r\n");
    while (it.next()) |word| {
        const eq = std.mem.findScalar(
            u8,
            word,
            '=',
        ) orelse return refuse(why, "a word that is not KEY=VALUE");
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

/// The file's text for a network.
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

/// ADDR/PREFIX: a usable host, a prefix of 1 to 32 in plain digits, and,
/// below /31 (RFC 3021), neither its subnet's network nor its broadcast.
pub fn address(cidr: []const u8) error{Address}!Address {
    const slash = std.mem.findScalar(u8, cidr, '/') orelse return error.Address;
    const a: Address = .{
        .addr = try ip4(cidr[0..slash]),
        .prefix = @intCast(try number(cidr[slash + 1 ..], 1, 32)),
    };
    if (!usable(a.addr)) return error.Address;
    if (a.prefix <= 30) {
        const host = toInt(a.addr) & ~mask(a.prefix);
        if (host == 0 or host == ~mask(a.prefix)) return error.Address;
    }
    return a;
}

/// A gateway for a: a usable host, not a's own address, and inside its
/// subnet not the network or broadcast either. One outside the subnet is
/// on the link, as GCP gives a /32's, reached by a host route first.
pub fn gateway(a: Address, s: []const u8) error{ Address, Gateway }!Ip4 {
    const gw = try ip4(s);
    if (!usable(gw)) return error.Address;
    if (std.mem.eql(u8, &gw, &a.addr)) return error.Gateway;
    if (a.prefix <= 30 and inSubnet(gw, a.addr, a.prefix)) {
        const host = toInt(gw) & ~mask(a.prefix);
        if (host == 0 or host == ~mask(a.prefix)) return error.Gateway;
    }
    return gw;
}

/// A dotted quad: four numbers 0 to 255, no leading zeros, nothing else.
pub fn ip4(s: []const u8) error{Address}!Ip4 {
    var out: Ip4 = undefined;
    var parts = std.mem.splitScalar(u8, s, '.');
    for (&out) |*o| o.* = @intCast(try number(parts.next() orelse return error.Address, 0, 255));
    if (parts.next() != null) return error.Address;
    return out;
}

/// Plain digits, no sign and no leading zero, from min to max.
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

/// Not zero, broadcast, loopback or multicast.
pub fn usable(a: Ip4) bool {
    return toInt(a) != 0 and toInt(a) != 0xffffffff and a[0] != 127 and a[0] < 224;
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
    // A gateway outside the subnet is on the link, as iface-up and the
    // command line take it: GCP's /32, or a provider's gateway elsewhere.
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
        "werewolf.ip=10.0.0.5/24 werewolf.dns=",
        "werewolf.ip=10.0.0.5/24 stray",
    }) |text| try testing.expectEqual(null, parse(text, &why));
    var long: [600]u8 = @splat(' ');
    @memcpy(long[0..24], "werewolf.ip=10.0.0.5/24 ");
    try testing.expectEqual(null, parse(&long, &why));
    try testing.expectEqualStrings("over 512 bytes", why);
}

test format {
    var buf: [128]u8 = undefined;
    const text = try format(&buf, .{ .ip = "10.0.2.15/24", .gw = "10.0.2.2" });
    try testing.expectEqualStrings("werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2\n", text);
    var why: []const u8 = "";
    try testing.expectEqualStrings("10.0.2.2", parse(text, &why).?.gw);
}
