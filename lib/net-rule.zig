//! Bounded policy-routing netlink messages, shared by fence and DHCP DNS renewal.
const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const sys = sandbox.sys;
const IPPROTO_ICMPV6 = 58;

pub const Proto = enum(u8) {
    icmp = 1,
    ipip = 4,
    tcp = 6,
    udp = 17,
    dccp = 33,
    ipv6 = 41,
    gre = 47,
    esp = 50,
    ah = 51,
    sctp = 132,
    udplite = 136,
};

pub const Rule = struct {
    family: u8 = linux.AF.INET,
    priority: u32,
    action: u8,
    /// table is used by FR_ACT_TO_TBL. Above 255 it goes in FRA_TABLE alone.
    table: u32 = 0,
    /// from_here matches only locally sent traffic, whose lookups come from lo.
    from_here: bool = false,
    /// src and dst are 4 or 16 bytes, by the rule's family.
    src: ?[]const u8 = null,
    /// src_len is src's prefix length; null means the whole address.
    src_len: ?u8 = null,
    dst: ?[]const u8 = null,
    /// dst_len is dst's prefix length; null means the whole address.
    dst_len: ?u8 = null,
    proto: ?Proto = null,
    sport: ?u16 = null,
    dport: ?u16 = null,
    /// dport_last widens dport into a range. Null is dport alone.
    dport_last: ?u16 = null,
    uid: ?u32 = null,
};

pub const NLMSG_ERROR = 2;
pub const RTM_NEWRULE = 32;
pub const RTM_DELRULE = 33;
const NLM_F_REQUEST = 0x1;
const NLM_F_ACK = 0x4;
const NLM_F_EXCL = 0x200;
const NLM_F_CREATE = 0x400;
pub const FRA_DST = 1;
pub const FRA_SRC = 2;
pub const FRA_IIFNAME = 3;
pub const FRA_PRIORITY = 6;
pub const FRA_TABLE = 15;
pub const FRA_UID_RANGE = 20;
pub const FRA_IP_PROTO = 22;
pub const FRA_SPORT_RANGE = 23;
pub const FRA_DPORT_RANGE = 24;

/// ruleMessage builds an RTM_NEWRULE or RTM_DELRULE message for r in buf.
pub fn ruleMessage(buf: *[256]u8, seq: u32, kind: u16, r: Rule) []const u8 {
    @memset(buf, 0);
    var b: Builder = .{ .buf = buf, .len = 16 };
    // struct fib_rule_hdr: family, dst_len, src_len, tos, table, res1,
    // res2, action, flags.
    const dst_len: u8 = if (r.dst) |a| r.dst_len orelse @intCast(a.len * 8) else 0;
    const src_len: u8 = if (r.src) |a| r.src_len orelse @intCast(a.len * 8) else 0;
    b.bytes(&.{ r.family, dst_len, src_len, 0, compatTable(r.table), 0, 0, r.action, 0, 0, 0, 0 });
    b.attr(FRA_PRIORITY, std.mem.asBytes(&r.priority));
    if (r.table != 0) b.attr(FRA_TABLE, std.mem.asBytes(&r.table));
    if (r.from_here) b.attr(FRA_IIFNAME, "lo\x00");
    if (r.src) |a| b.attr(FRA_SRC, a);
    if (r.dst) |a| b.attr(FRA_DST, a);
    if (r.proto) |pr| b.attr(
        FRA_IP_PROTO,
        &.{if (pr == .icmp and r.family == linux.AF.INET6) IPPROTO_ICMPV6 else @backingInt(pr)},
    );
    if (r.sport) |s| b.attr(FRA_SPORT_RANGE, std.mem.sliceAsBytes(&[2]u16{ s, s }));
    if (r.dport) |d| b.attr(
        FRA_DPORT_RANGE,
        std.mem.sliceAsBytes(&[2]u16{ d, r.dport_last orelse d }),
    );
    if (r.uid) |u| b.attr(FRA_UID_RANGE, std.mem.sliceAsBytes(&[2]u32{ u, u }));
    // struct nlmsghdr: length, type, flags, sequence, port.
    std.mem.writeInt(u32, buf[0..4], @intCast(b.len), .little);
    std.mem.writeInt(u16, buf[4..6], kind, .little);
    const flags: u16 = if (kind == RTM_NEWRULE)
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE
    else
        NLM_F_REQUEST | NLM_F_ACK;
    std.mem.writeInt(u16, buf[6..8], flags, .little);
    std.mem.writeInt(u32, buf[8..12], seq, .little);
    return buf[0..b.len];
}

/// compatTable is a table's number for the one-byte header field. A table
/// above 255 has RT_TABLE_COMPAT there and its number in an attribute.
fn compatTable(table: u32) u8 {
    return if (table < 256) @intCast(table) else 252;
}

pub const RTM_NEWROUTE = 24;
const RTA_DST = 1;
const RTA_OIF = 4;
const RTA_PREFSRC = 7;
const RTA_TABLE = 15;
const RTN_LOCAL = 2;
const RT_SCOPE_HOST = 254;
const RTPROT_STATIC = 4;
/// loopback is lo's interface index, the same in every network namespace.
const loopback: u32 = 1;

/// localRouteMessage builds an RTM_NEWROUTE message for `local DST dev lo
/// table TABLE src SRC`: in that table, DST is this machine, reached from SRC.
pub fn localRouteMessage(
    buf: *[256]u8,
    seq: u32,
    table: u32,
    dst: *const [4]u8,
    src: *const [4]u8,
) []const u8 {
    @memset(buf, 0);
    var b: Builder = .{ .buf = buf, .len = 16 };
    // struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
    // type, flags.
    b.bytes(&.{
        linux.AF.INET,
        32,
        0,
        0,
        compatTable(table),
        RTPROT_STATIC,
        RT_SCOPE_HOST,
        RTN_LOCAL,
        0,
        0,
        0,
        0,
    });
    b.attr(RTA_DST, dst);
    b.attr(RTA_OIF, std.mem.asBytes(&loopback));
    b.attr(RTA_PREFSRC, src);
    b.attr(RTA_TABLE, std.mem.asBytes(&table));
    std.mem.writeInt(u32, buf[0..4], @intCast(b.len), .little);
    std.mem.writeInt(u16, buf[4..6], RTM_NEWROUTE, .little);
    std.mem.writeInt(
        u16,
        buf[6..8],
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        .little,
    );
    std.mem.writeInt(u32, buf[8..12], seq, .little);
    return buf[0..b.len];
}

/// Builder appends netlink attributes, four-byte aligned. buf fits the
/// largest message fence builds.
const Builder = struct {
    buf: *[256]u8,
    len: usize,

    fn bytes(b: *Builder, v: []const u8) void {
        @memcpy(b.buf[b.len..][0..v.len], v);
        b.len += v.len;
    }

    fn attr(b: *Builder, kind: u16, v: []const u8) void {
        std.mem.writeInt(u16, b.buf[b.len..][0..2], @intCast(4 + v.len), .little);
        std.mem.writeInt(u16, b.buf[b.len + 2 ..][0..2], kind, .little);
        @memcpy(b.buf[b.len + 4 ..][0..v.len], v);
        b.len += std.mem.alignForward(usize, 4 + v.len, 4);
    }
};

/// send sends msg and reads its acknowledgement, returning the kernel's errno
/// as an error.
pub fn send(nl: i32, msg: []const u8, seq: u32, comptime what: []const u8) !void {
    const kernel: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
    _ = try sys(
        linux.sendto(nl, msg.ptr, msg.len, 0, @ptrCast(&kernel), @sizeOf(linux.sockaddr.nl)),
        "netlink send",
    );
    var reply: [512]u8 align(4) = undefined;
    const n = try sys(linux.recvfrom(nl, &reply, reply.len, 0, null, null), "netlink receive");
    const e = ackError(reply[0..n], seq) orelse return error.BadAck;
    if (e == 0) return;
    _ = try sys(@bitCast(@as(isize, e)), what);
}

/// ackError returns the error in an NLMSG_ERROR acknowledging seq: 0 for
/// success, a negative errno for failure, or null if reply is not one.
pub fn ackError(reply: []const u8, seq: u32) ?i32 {
    if (reply.len < 20) return null;
    if (std.mem.readInt(u16, reply[4..6], .little) != NLMSG_ERROR) return null;
    if (std.mem.readInt(u32, reply[8..12], .little) != seq) return null;
    return std.mem.readInt(i32, reply[16..20], .little);
}

test "tables above 255 are named by attribute, and local routes name their source" {
    var buf: [256]u8 = undefined;
    const rule = ruleMessage(
        &buf,
        7,
        RTM_NEWRULE,
        .{ .priority = 3, .action = 1, .table = 0x5301, .uid = 1001 },
    );
    try std.testing.expectEqual(252, rule[16 + 4]); // RT_TABLE_COMPAT in the header
    try std.testing.expect(std.mem.indexOf(
        u8,
        rule,
        &.{ 8, 0, FRA_TABLE, 0, 0x01, 0x53, 0, 0 },
    ) != null);
    const small = ruleMessage(&buf, 7, RTM_NEWRULE, .{ .priority = 3, .action = 1, .table = 254 });
    try std.testing.expectEqual(254, small[16 + 4]);

    const route = localRouteMessage(&buf, 8, 0x5301, &.{ 127, 0, 0, 53 }, &.{ 127, 53, 0, 1 });
    try std.testing.expectEqual(route.len, std.mem.readInt(u32, route[0..4], .little));
    try std.testing.expectEqual(RTM_NEWROUTE, std.mem.readInt(u16, route[4..6], .little));
    // rtmsg: AF_INET, a /32, static, host scope, local.
    try std.testing.expectEqualSlices(
        u8,
        &.{ linux.AF.INET, 32, 0, 0, 252, 4, 254, 2 },
        route[16..24],
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        route,
        &.{ 8, 0, 7, 0, 127, 53, 0, 1 },
    ) != null); // RTA_PREFSRC
    try std.testing.expect(std.mem.indexOf(
        u8,
        route,
        &.{ 8, 0, 1, 0, 127, 0, 0, 53 },
    ) != null); // RTA_DST
    try std.testing.expect(std.mem.indexOf(
        u8,
        route,
        &.{ 8, 0, 4, 0, 1, 0, 0, 0 },
    ) != null); // RTA_OIF lo
}
