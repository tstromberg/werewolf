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
//!   zero, and a gateway that is none of those either.
//! - It opens its one socket, then pledges: no_new_privs, every capability
//!   dropped but CAP_NET_ADMIN, and a seccomp filter allowing ioctl only
//!   for the five requests it makes, and write, close and exit. Anything
//!   else kills it.
//! - No environment, no files; nothing printed on success, one line on
//!   failure.
//!
//! There is no privilege separation: it reads nothing from the network,
//! and what it is told comes from whoever booted the machine.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub fn main(init: std.process.Init) void {
    const args = init.minimal.args.toSlice(init.arena.allocator()) catch fail(error.OutOfMemory);
    const p = parse(args[1..]) catch |err| fail(err);

    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    sys(rc) catch |err| fail(err);
    const sock: i32 = @intCast(rc);
    pledge() catch |err| fail(err);
    apply(sock, p) catch |err| fail(err);
    linux.exit_group(0);
}

// --- what it is asked --------------------------------------------------------------

const Ip4 = [4]u8;

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

    const cidr = args[1];
    const slash = std.mem.findScalar(u8, cidr, '/') orelse return error.Address;
    const addr = try ip4(cidr[0..slash]);
    const prefix = try number(cidr[slash + 1 ..], 1, 32);
    p.addr = addr;
    p.prefix = @intCast(prefix);
    try usable(addr);
    if (prefix <= 30) {
        const host = toInt(addr) & ~maskInt(p.prefix);
        if (host == 0 or host == ~maskInt(p.prefix)) return error.Address;
    }

    if (args.len == 3) {
        const gw = try ip4(args[2]);
        try usable(gw);
        if (std.mem.eql(u8, &gw, &addr)) return error.Gateway;
        p.gateway = gw;
    }
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

/// A dotted quad: four numbers 0 to 255, no leading zeros, nothing else.
fn ip4(s: []const u8) !Ip4 {
    var out: Ip4 = undefined;
    var parts = std.mem.splitScalar(u8, s, '.');
    for (&out) |*o| o.* = @intCast(try number(parts.next() orelse return error.Address, 0, 255));
    if (parts.next() != null) return error.Address;
    return out;
}

fn number(s: []const u8, min: u32, max: u32) !u32 {
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
fn usable(a: Ip4) !void {
    if (toInt(a) == 0 or toInt(a) == 0xffffffff or a[0] == 127 or a[0] >= 224) return error.Address;
}

fn toInt(a: Ip4) u32 {
    return std.mem.readInt(u32, &a, .big);
}

fn maskInt(prefix: u6) u32 {
    return if (prefix == 0) 0 else ~@as(u32, 0) << @intCast(32 - prefix);
}

fn fromInt(v: u32) Ip4 {
    var a: Ip4 = undefined;
    std.mem.writeInt(u32, &a, v, .big);
    return a;
}

fn inSubnet(a: Ip4, b: Ip4, prefix: u6) bool {
    return toInt(a) & maskInt(prefix) == toInt(b) & maskInt(prefix);
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
        try ioctl(sock, SIOCSIFADDR, &ifreq(p.nic, .{ .addr = .{ .addr = addr } }));
        try ioctl(
            sock,
            SIOCSIFNETMASK,
            &ifreq(p.nic, .{ .addr = .{ .addr = fromInt(maskInt(p.prefix)) } }),
        );
    }
    var flags = ifreq(p.nic, .{ .pad = @splat(0) });
    try ioctl(sock, SIOCGIFFLAGS, &flags);
    flags.data.flags |= IFF_UP;
    try ioctl(sock, SIOCSIFFLAGS, &flags);

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
    ioctl(sock, SIOCADDRT, &r) catch |err| switch (err) {
        error.Exists => {}, // already there: the machine is as asked
        else => return err,
    };
}

fn ioctl(sock: i32, request: u32, arg: anytype) !void {
    return sys(linux.ioctl(sock, request, @intFromPtr(arg)));
}

// --- pledge --------------------------------------------------------------------------

const PR_SET_NO_NEW_PRIVS = 38;
const CAP_NET_ADMIN = 12;
const LINUX_CAPABILITY_VERSION_3 = 0x20080522;
const SECCOMP_SET_MODE_FILTER = 1;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;

/// The kernel's __user_cap_header_struct, whose pid is an int; Zig 0.17's
/// cap_user_header_t has it as a usize (see cmd/mount/mount.zig).
const CapHeader = extern struct { version: u32, pid: i32 };
const CapSets = extern struct { effective: u32, permitted: u32, inheritable: u32 };

const simple_syscalls = [_]linux.SYS{ .write, .close, .exit, .exit_group };

const audit_arch: u32 = switch (builtin.cpu.arch) {
    .aarch64 => 0xc00000b7,
    .x86_64 => 0xc000003e,
    else => @compileError("net runs on aarch64 and x86_64"),
};

const Filter = extern struct { code: u16, jt: u8, jf: u8, k: u32 };
const LD_W_ABS = 0x20;
const JEQ_K = 0x15;
const JGE_K = 0x35;
const RET_K = 0x06;

/// The architecture; then write, close and exit; then ioctl, but only with
/// a request (args[1], whose high word must be zero) from requests.
const filter = blk: {
    const s = simple_syscalls.len;
    const r = requests.len;
    const kill = 6 + s;
    const allow = 12 + s + r;
    var f: [allow + 1]Filter = undefined;
    f[0] = .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 4 }; // seccomp_data.arch
    f[1] = .{ .code = JEQ_K, .jt = 1, .jf = 0, .k = audit_arch };
    f[2] = .{ .code = RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS };
    f[3] = .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 0 }; // seccomp_data.nr
    f[4] = .{ .code = JGE_K, .jt = kill - 5, .jf = 0, .k = 0x40000000 }; // x32
    for (simple_syscalls, 0..) |sc, j| f[5 + j] = .{
        .code = JEQ_K,
        .jt = allow - (5 + j) - 1,
        .jf = 0,
        .k = @intCast(@backingInt(sc)),
    };
    f[5 + s] = .{ .code = JEQ_K, .jt = 1, .jf = 0, .k = @intCast(@backingInt(linux.SYS.ioctl)) };
    f[kill] = .{ .code = RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS };
    f[7 + s] = .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 28 }; // args[1], high word
    f[8 + s] = .{ .code = JEQ_K, .jt = 1, .jf = 0, .k = 0 };
    f[9 + s] = .{ .code = RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS };
    f[10 + s] = .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 24 }; // args[1], low word
    for (requests, 0..) |req, j| f[11 + s + j] = .{
        .code = JEQ_K,
        .jt = allow - (11 + s + j) - 1,
        .jf = 0,
        .k = req,
    };
    f[11 + s + r] = .{ .code = RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS };
    f[allow] = .{ .code = RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_ALLOW };
    break :blk f;
};

fn pledge() !void {
    try sys(linux.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    const header: CapHeader = .{ .version = LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    const keep: u32 = 1 << CAP_NET_ADMIN;
    const data = [2]CapSets{
        .{ .effective = keep, .permitted = keep, .inheritable = 0 },
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
    };
    try sys(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&data)));
    const prog = extern struct {
        len: u16,
        filter: [*]const Filter,
    }{ .len = filter.len, .filter = &filter };
    try sys(linux.seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog));
}

// --- saying so -----------------------------------------------------------------------

fn sys(rc: usize) !void {
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM => error.PermissionDenied,
        .NODEV => error.NoSuchInterface,
        .EXIST => error.Exists,
        .NETUNREACH => error.GatewayUnreachable,
        .INVAL => error.InvalidArgument,
        else => error.Failed,
    };
}

fn fail(err: anyerror) noreturn {
    var buf: [256]u8 = undefined;
    const line = switch (err) {
        error.Usage => "usage: iface-up NIC [ADDR/PREFIX [GATEWAY]]\n",
        error.Interface => "iface-up: refused: not an interface name\n",
        error.Address => "iface-up: refused: an address is a dotted quad, prefix 1 to 32, and a " ++
            "usable host\n",
        error.Gateway => "iface-up: refused: the gateway is the address itself\n",
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
    try testing.expectEqual(8, @sizeOf(CapHeader));
}

test "the seccomp program ends where its jumps say" {
    try testing.expectEqual(SECCOMP_RET_ALLOW, filter[filter.len - 1].k);
    for (filter, 0..) |f, i| if (f.code == JEQ_K or f.code == JGE_K) {
        try testing.expect(i + 1 + f.jt < filter.len);
    };
    // Every request jumps to allow.
    for (requests, 0..) |_, j| {
        const at = 11 + simple_syscalls.len + j;
        try testing.expectEqual(filter.len - 1, at + 1 + filter[at].jt);
    }
}
