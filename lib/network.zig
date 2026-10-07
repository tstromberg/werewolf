//! A static network, as a config tar's `network` file gives one: the
//! kernel command line's own words, and only these, each at most once.
//!
//!     werewolf.ip=CIDR werewolf.gw=ADDR werewolf.dns=ADDR
//!
//! For machines whose network gives no address by DHCP: a hypervisor of
//! your own, bare metal, a form with no DHCP client. init reads it when
//! the command line has no werewolf.ip, before it brings the network up,
//! and the host's werewolf pack checks it with this same parser, so what
//! the host packs the machine takes. IPv4: an address within its subnet,
//! neither the subnet's network nor its broadcast address; a gateway
//! inside that subnet; a unicast resolver.

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
    const slash = std.mem.findScalar(
        u8,
        n.ip,
        '/',
    ) orelse return refuse(why, "werewolf.ip is not ADDRESS/PREFIX");
    const addr = ip4(n.ip[0..slash]) orelse return refuse(
        why,
        "werewolf.ip is not an IPv4 address",
    );
    const bits = std.fmt.parseInt(
        u6,
        n.ip[slash + 1 ..],
        10,
    ) catch return refuse(why, "werewolf.ip's prefix is not 1 to 32");
    if (bits < 1 or bits > 32) return refuse(why, "werewolf.ip's prefix is not 1 to 32");
    const mask: u32 = if (bits == 32) 0xffff_ffff else ~(@as(u32, 0xffff_ffff) >> @intCast(bits));
    // /31 and /32 have no network or broadcast address to avoid (RFC 3021).
    if (bits <= 30 and (addr & ~mask == 0 or addr & ~mask == ~mask))
        return refuse(why, "werewolf.ip is its subnet's network or broadcast address");
    if (!unicast(addr)) return refuse(why, "werewolf.ip is not a unicast address");
    if (n.gw.len > 0) {
        const gw = ip4(n.gw) orelse return refuse(why, "werewolf.gw is not an IPv4 address");
        if (gw & mask != addr & mask) return refuse(
            why,
            "werewolf.gw is outside werewolf.ip's subnet",
        );
        if (gw == addr) return refuse(why, "werewolf.gw is the machine's own address");
        if (bits <= 30 and (gw & ~mask == 0 or gw & ~mask == ~mask))
            return refuse(why, "werewolf.gw is its subnet's network or broadcast address");
    }
    if (n.dns.len > 0) {
        const dns = ip4(n.dns) orelse return refuse(why, "werewolf.dns is not an IPv4 address");
        if (!unicast(dns)) return refuse(why, "werewolf.dns is not a unicast address");
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

fn ip4(text: []const u8) ?u32 {
    const a = std.Io.net.Ip4Address.parse(text, 0) catch return null;
    return std.mem.readInt(u32, &a.bytes, .big);
}

/// Not 0.0.0.0/8, loopback, multicast or reserved (240.0.0.0/4, broadcast).
fn unicast(a: u32) bool {
    const first = a >> 24;
    return first != 0 and first != 127 and first < 224;
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
        "werewolf.ip=10.0.0.5/24 werewolf.gw=10.0.1.1",
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
