//! iface-up: bring a network interface up, with an address and a default route.
//!
//!     iface-up NIC                          bring NIC up (lo, say)
//!     iface-up NIC ADDR/PREFIX [GATEWAY]    and give it ADDR, and a default route
//!                                           through GATEWAY
//!
//! init runs it for the address the kernel command line gives; the dhcp
//! form's client applies its own leases. It replaces net-tools' ifconfig
//! and route, which brought nothing but those two commands.
//!
//! A gateway outside the subnet, as GCP gives a /32 address, gets a host
//! route through NIC first, so the default route through it can be added.
//!
//! As paranoid as werewolf's other programs (docs/programs.md):
//!
//! - Its arguments come from the kernel command line, so they are parsed
//!   strictly and refused if odd: an interface name of plain characters, a
//!   dotted quad with no leading zeros, a prefix of 1 to 32, an address
//!   that is not the subnet's network or broadcast, loopback, multicast or
//!   zero, and a gateway that is none of those either, nor the address.
//!   The rules are lib/network.zig's, which the config tar's network file
//!   and howl pack are held to as well, so all three agree.
//! - It opens its one socket, then pledges (lib/sandbox.zig): every
//!   capability but CAP_NET_ADMIN gone, from the bounding set too, never to
//!   come back, and a seccomp filter allowing ioctl only for the five
//!   requests it makes, and write, close and exit. Anything else, or
//!   another architecture's call, kills it.
//! - No environment, no files; nothing printed on success, one line on
//!   failure, naming the request that failed and the kernel's reason.
//!
//! There is no privilege separation: it reads nothing from the network,
//! and what it is told comes from whoever booted the machine.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const network = @import("network");

pub fn main(init: std.process.Init) void {
    const args = init.minimal.args.toSlice(init.arena.allocator()) catch fail(error.OutOfMemory);
    const p = parse(args[1..]) catch |err| fail(err);

    const rc = sandbox.sys(
        linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0),
        "socket",
    ) catch |err| fail(err);
    const sock: i32 = @intCast(rc);
    pledge() catch |err| fail(err);
    apply(sock, p) catch |err| fail(err);
    linux.exit_group(0);
}

// --- what it is asked --------------------------------------------------------------

const Ip4 = network.Ip4;

const Plan = struct {
    nic: [:0]const u8,
    addr: ?Ip4 = null,
    prefix: u6 = 0,
    gateway: ?Ip4 = null,
};

fn parse(args: []const [:0]const u8) !Plan {
    if (args.len < 1 or args.len > 3) return error.Usage;
    var p: Plan = .{ .nic = try nic(args[0]) };
    if (args.len == 1) return p;

    const a = try network.address(args[1]);
    p.addr = a.addr;
    p.prefix = a.prefix;
    if (args.len == 3) p.gateway = try network.gateway(a, args[2]);
    return p;
}

/// An interface name: 1 to 15 plain characters, as the kernel allows, but
/// none of its odder ones.
fn nic(s: [:0]const u8) ![:0]const u8 {
    if (s.len == 0 or s.len > 15 or std.mem.eql(u8, s, ".") or
        std.mem.eql(u8, s, "..")) return error.Interface;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and
        c != '.') return error.Interface;
    return s;
}

const maskInt = network.mask;
const inSubnet = network.inSubnet;

fn fromInt(v: u32) Ip4 {
    var a: Ip4 = undefined;
    std.mem.writeInt(u32, &a, v, .big);
    return a;
}

// --- asking the kernel ---------------------------------------------------------------

const SIOCADDRT = 0x890B;
const SIOCGIFFLAGS = 0x8913;
const SIOCSIFFLAGS = 0x8914;
const SIOCSIFADDR = 0x8916;
const SIOCSIFNETMASK = 0x891C;
const requests = [_]u32{ SIOCADDRT, SIOCGIFFLAGS, SIOCSIFFLAGS, SIOCSIFADDR, SIOCSIFNETMASK };

const IFF_UP = 0x1;
const RTF_UP = 0x1;
const RTF_GATEWAY = 0x2;
const RTF_HOST = 0x4;

const SockaddrIn = extern struct {
    family: u16 = linux.AF.INET,
    port: u16 = 0,
    addr: Ip4 = .{ 0, 0, 0, 0 },
    zero: [8]u8 = @splat(0),
};

/// struct ifreq: the name, then a 24-byte union, of which net uses an
/// address and the flags.
const Ifreq = extern struct {
    name: [16]u8 = @splat(0),
    data: extern union { addr: SockaddrIn, flags: i16, pad: [24]u8 } = .{ .pad = @splat(0) },
};

/// struct rtentry, as both 64-bit architectures lay it out.
const Rtentry = extern struct {
    pad1: usize = 0,
    dst: SockaddrIn = .{},
    gateway: SockaddrIn = .{},
    genmask: SockaddrIn = .{},
    flags: u16 = 0,
    pad2: i16 = 0,
    pad3: usize = 0,
    pad4: usize = 0,
    metric: i16 = 0,
    dev: ?[*:0]const u8 = null,
    mtu: usize = 0,
    window: usize = 0,
    irtt: u16 = 0,
};

fn apply(sock: i32, p: Plan) !void {
    if (p.addr) |addr| {
        try ioctl(sock, SIOCSIFADDR, &ifreq(p.nic, .{ .addr = .{ .addr = addr } }), "SIOCSIFADDR");
        try ioctl(
            sock,
            SIOCSIFNETMASK,
            &ifreq(p.nic, .{ .addr = .{ .addr = fromInt(maskInt(p.prefix)) } }),
            "SIOCSIFNETMASK",
        );
    }
    var flags = ifreq(p.nic, .{ .pad = @splat(0) });
    try ioctl(sock, SIOCGIFFLAGS, &flags, "SIOCGIFFLAGS");
    flags.data.flags |= IFF_UP;
    try ioctl(sock, SIOCSIFFLAGS, &flags, "SIOCSIFFLAGS");

    const gw = p.gateway orelse return;
    if (!inSubnet(gw, p.addr.?, p.prefix)) {
        // Reach the gateway itself through the NIC first.
        try route(
            sock,
            .{
                .dst = .{ .addr = gw },
                .genmask = .{ .addr = .{ 255, 255, 255, 255 } },
                .flags = RTF_UP | RTF_HOST,
                .dev = p.nic.ptr,
            },
        );
    }
    try route(
        sock,
        .{ .gateway = .{ .addr = gw }, .flags = RTF_UP | RTF_GATEWAY, .dev = p.nic.ptr },
    );
}

fn ifreq(name: []const u8, data: @FieldType(Ifreq, "data")) Ifreq {
    var r: Ifreq = .{ .data = data };
    @memcpy(r.name[0..name.len], name);
    return r;
}

fn route(sock: i32, rt: Rtentry) !void {
    var r = rt;
    const rc = linux.ioctl(sock, SIOCADDRT, @intFromPtr(&r));
    // The very route already there, gateway and all: as asked.
    if (linux.errno(rc) == .EXIST) return;
    _ = try sandbox.sys(rc, "SIOCADDRT");
}

fn ioctl(sock: i32, request: u32, arg: anytype, comptime what: []const u8) !void {
    _ = try sandbox.sys(linux.ioctl(sock, request, @intFromPtr(arg)), what);
}

// --- pledge --------------------------------------------------------------------------

const CAP_NET_ADMIN = 12;

/// CAP_NET_ADMIN alone, never to gain more, and a filter of what apply
/// calls: ioctl for its five requests, write, close and exit.
fn pledge() !void {
    try sandbox.keepOnly(1 << CAP_NET_ADMIN);
    var f: sandbox.Filter = .{};
    inline for (.{ "write", "close", "exit", "exit_group" }) |name| f.allow(name);
    for (requests) |req| f.allowArg("ioctl", 1, req);
    try f.install();
}

// --- saying so -----------------------------------------------------------------------

fn fail(err: anyerror) noreturn {
    var buf: [256]u8 = undefined;
    const line = switch (err) {
        error.Usage => "usage: iface-up NIC [ADDR/PREFIX [GATEWAY]]\n",
        error.Interface => "iface-up: refused: not an interface name\n",
        error.Address => "iface-up: refused: an address is a dotted quad, prefix 1 to 32, and a " ++
            "usable host\n",
        error.Gateway => "iface-up: refused: the gateway is the address, or the subnet's own or " ++
            "broadcast address\n",
        error.SystemCall => std.mem.print(
            &buf,
            "iface-up: {s}: {s}\n",
            .{ sandbox.failed, sandbox.errnoName(sandbox.failed_errno) },
        ) catch "iface-up: failed\n",
        else => std.mem.print(&buf, "iface-up: {t}\n", .{err}) catch "iface-up: failed\n",
    };
    _ = linux.write(2, line.ptr, line.len);
    linux.exit_group(if (err == error.Usage) 2 else 1);
}

// --- tests -----------------------------------------------------------------------------

const testing = std.testing;

test "what the kernel command line gives, parsed" {
    const p = try parse(&.{ "eth0", "10.0.2.15/24", "10.0.2.2" });
    try testing.expectEqualStrings("eth0", p.nic);
    try testing.expectEqual(Ip4{ 10, 0, 2, 15 }, p.addr.?);
    try testing.expectEqual(24, p.prefix);
    try testing.expectEqual(Ip4{ 10, 0, 2, 2 }, p.gateway.?);
    try testing.expect(inSubnet(p.gateway.?, p.addr.?, p.prefix));
    const lo = try parse(&.{"lo"});
    try testing.expectEqual(null, lo.addr);
}

test "a /32 with a gateway outside it, as GCP gives" {
    const p = try parse(&.{ "ens4", "10.128.0.5/32", "10.128.0.1" });
    try testing.expect(!inSubnet(p.gateway.?, p.addr.?, p.prefix));
}

test "odd input is refused" {
    for ([_][]const [:0]const u8{
        &.{ "eth0", "10.0.2.15" },
        &.{ "eth0", "10.0.2.15/0" },
        &.{ "eth0", "10.0.2.15/33" },
        &.{ "eth0", "10.0.2.015/24" },
        &.{ "eth0", "10.0.2/24" },
        &.{ "eth0", "10.0.2.15.1/24" },
        &.{ "eth0", "10.0.2.256/24" },
        &.{ "eth0", "10.0.2.0/24" },
        &.{ "eth0", "10.0.2.255/24" },
        &.{ "eth0", "127.0.0.2/8" },
        &.{ "eth0", "224.0.0.1/4" },
        &.{ "eth0", "0.0.0.0/8" },
        &.{ "eth0", "10.0.2.15/24", "255.255.255.255" },
        &.{ "eth0", "10.0.2.15/24", "-1" },
    }) |args| try testing.expectError(error.Address, parse(args));
    try testing.expectError(error.Gateway, parse(&.{ "eth0", "10.0.2.15/24", "10.0.2.15" }));
    // Not the subnet's own address nor its broadcast.
    try testing.expectError(error.Gateway, parse(&.{ "eth0", "10.0.2.15/24", "10.0.2.0" }));
    try testing.expectError(error.Gateway, parse(&.{ "eth0", "10.0.2.15/24", "10.0.2.255" }));
    // Outside the subnet, as GCP's for a /32, any host is a gateway.
    _ = try parse(&.{ "ens4", "10.128.0.5/32", "10.128.0.0" });
    try testing.expectError(error.Interface, parse(&.{ "eth0;reboot", "10.0.2.15/24" }));
    try testing.expectError(error.Interface, parse(&.{ "a-name-far-too-long", "10.0.2.15/24" }));
    try testing.expectError(error.Interface, parse(&.{ "..", "10.0.2.15/24" }));
    try testing.expectError(error.Usage, parse(&.{}));
    try testing.expectError(error.Usage, parse(&.{ "eth0", "10.0.2.15/24", "10.0.2.2", "x" }));
}

test "the kernel's structures, as it lays them out" {
    try testing.expectEqual(40, @sizeOf(Ifreq));
    try testing.expectEqual(16, @sizeOf(SockaddrIn));
    try testing.expectEqual(120, @sizeOf(Rtentry));
    try testing.expectEqual(56, @offsetOf(Rtentry, "flags"));
    try testing.expectEqual(88, @offsetOf(Rtentry, "dev"));
}
