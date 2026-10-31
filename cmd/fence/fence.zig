//! fence sets the machine's network and file policy from the image, drops
//! CAP_NET_ADMIN, CAP_NET_RAW and CAP_SYS_ADMIN, then execs PROGRAM:
//! init's last step is `exec fence runit`. See fence.8.

const std = @import("std");
const sandbox = @import("sandbox");
const allow = @import("allow");
const dns = @import("dns");
const net_rule = @import("net-rule");
const network = @import("network");
const people = @import("people");
const linux = std.os.linux;
const Io = std.Io;

const policy_path = "/usr/share/werewolf/net";
const oci_path = "/usr/share/werewolf/oci";
const max_args = 16;
const max_entries = 64;

/// metadata_ip is the metadata server every cloud uses; metadata_ip6 is
/// AWS's IPv6 one.
const metadata_ip = [4]u8{ 169, 254, 169, 254 };
/// loopback_ip is the one address a wide connector may still use, on a
/// port it named. loopback_net is the rest of 127.0.0.0/8, refused to
/// that user. loopback6 is ::1.
const loopback_ip = [4]u8{ 127, 0, 0, 1 };
const loopback_net = [4]u8{ 127, 0, 0, 0 };
const loopback6 = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
/// ephemeral is Linux's default local port range. Replies to a
/// connection this machine opened arrive with a destination in it.
/// Service ports sit below it, so they stay closed without a listen line.
const ephemeral_lo: u16 = 32768;
const ephemeral_hi: u16 = 60999;
const metadata_ip6 = [16]u8{ 0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54 };
const IPPROTO_ICMPV6 = 58;
const metadata_port: u16 = 80;
/// wire_server_ip is Azure's wire server, which serves the VM's goal state
/// and certificates on these TCP ports. Its address is public, so a `public`
/// connect would reach it; nothing in werewolf reads it, so it is closed to
/// everyone. Its DNS and DHCP, over UDP, are untouched.
const wire_server_ip = [4]u8{ 168, 63, 129, 16 };
const wire_server_ports = [_]u16{ 80, 32526 };

/// pref holds the rule priorities, in the order the kernel tries them. The
/// kernel's local-table rule moves from 0 to 400, so arriving packets meet
/// the policy first. Its main and default rules (32766, 32767) are never
/// reached.
const pref = struct {
    /// label_own through label_refuse give each lookup user its own source
    /// address to unwound, and no one else: lib/dns.zig's labels.
    const label_own: u32 = 1;
    const label_forged: u32 = 2;
    const label_pick: u32 = 3;
    const label_refuse: u32 = 4;
    const public_refuse: u32 = 5;
    const local_validator_refuse: u32 = 7;
    /// loopback_allow is one user's explicit port on 127.0.0.1, before
    /// loopback_refuse takes the rest of 127.0.0.0/8 from that user.
    /// Both are before local_out, which would otherwise deliver loopback
    /// to every user. Other users are not named.
    const loopback_allow: u32 = 8;
    const loopback_refuse: u32 = 9;
    const local_out: u32 = 10;
    const metadata_allow: u32 = 100;
    const metadata_refuse: u32 = 101;
    /// dns_refuse sends every other DNS, plain or TLS, to unwound: it
    /// follows the upstream user's grants (lib/dns.zig, at 99) and precedes
    /// any broad connect.
    const dns_refuse: u32 = 150;
    const dns_direct_allow: u32 = 149;
    const out_allow: u32 = 200;
    const out_lan_refuse: u32 = 280;
    const in_private: u32 = 290;
    const out_refuse: u32 = 299;
    const in_allow: u32 = 300;
    const in_drop: u32 = 399;
    const local: u32 = 400;
};

pub fn main(init: std.process.Init) !void {
    const argv = init.minimal.args.vector;
    var log: Log = .{};
    if (argv.len < 2 or argv.len - 1 > max_args) {
        log.event("error", .{ .@"error" = "usage: fence PROGRAM [ARG...]" });
        linux.exit_group(2);
    }
    var lan: Lan = .{};
    const p = apply(&lan) catch |err| fail(&log, err);
    step = "capabilities";
    var kept_buf: [caps.len][]const u8 = undefined;
    const kept = dropCaps(&kept_buf) catch |err| fail(&log, err);
    var out: [max_entries][]const u8 = undefined;
    var text: [max_entries * 32]u8 = undefined;
    log.event(
        "fence",
        .{
            .listen = p.listen[0..p.nlisten],
            .loopback = p.loopback[0..p.nloopback],
            .udp = p.udp[0..p.nudp],
            .lan_subnets = p.lan.len,
            .connect = p.connectText(&out, &text),
            .dns = p.dns.ids[0..p.dns.len],
            .lookup = p.lookups.ids[0..p.lookups.len],
            .metadata = p.metadata[0..p.nmetadata],
            .ipv6 = hasIpv6(),
            .kept = kept,
        },
    );
    // Pass the base name as argv[0], as a shell would, so ps and the
    // kernel log show "runit", not its path.
    var next: [max_args + 1]?[*:0]const u8 = @splat(null);
    next[0] = baseName(argv[1]);
    for (argv[2..], 1..) |a, i| next[i] = a;
    const rc = linux.execve(
        argv[1],
        @ptrCast(&next),
        @ptrCast(init.minimal.environ.block.slice.ptr),
    );
    _ = sys(rc, "execve") catch {};
    log.event(
        "error",
        .{ .step = "exec", .detail = sandbox.failed, .errno = errnoName(sandbox.failed_errno) },
    );
    linux.exit_group(1);
}

/// baseName returns the last component of path.
fn baseName(path: [*:0]const u8) [*:0]const u8 {
    const s = std.mem.span(path);
    const slash = std.mem.findScalarLast(u8, s, '/') orelse return path;
    return s[slash + 1 ..].ptr;
}

/// step names the step under way, for the error log. sandbox.failed and
/// sandbox.failed_errno say what in it failed.
var step: []const u8 = "start";

/// fail logs the failed step and exits 1, so the machine fails closed.
fn fail(log: *Log, err: anyerror) noreturn {
    log.event(
        "error",
        .{
            .step = step,
            .@"error" = @errorName(err),
            .detail = sandbox.failed,
            .errno = errnoName(sandbox.failed_errno),
        },
    );
    linux.exit_group(1);
}

const errnoName = sandbox.errnoName;

/// caps are the capabilities fence drops from the bounding set unless the
/// form allows them (lib/allow.zig). NET_ADMIN and NET_RAW could bypass the
/// rules; SYS_ADMIN was needed only to apply Landlock.
const caps = [_]allow.Cap{ .net_admin, .net_raw, .sys_admin };

/// dropCaps drops each of caps the form does not allow from the bounding
/// set, and returns the names of those kept.
fn dropCaps(kept: *[caps.len][]const u8) ![]const []const u8 {
    const PR_CAPBSET_DROP = 24;
    var n: usize = 0;
    for (caps) |c| {
        if (c.allowance()) |a| if (allow.has(a)) {
            kept[n] = @tagName(c);
            n += 1;
            continue;
        };
        _ = try sys(linux.prctl(PR_CAPBSET_DROP, @backingInt(c), 0, 0, 0), "prctl");
    }
    return kept[0..n];
}

fn apply(lan: *Lan) !Policy {
    step = "policy";
    var buf: [policy_max]u8 = undefined;
    var p = try parsePolicy(try readPolicy(&buf));
    // The address plan is fixed for this boot. DHCP rejects a changed plan;
    // a missing lease leaves LAN grants closed until the next boot.
    if (p.needsLan()) {
        step = "LAN subnets";
        var routes: [32768]u8 = undefined;
        try lan.routes4(try readOptional("/proc/net/route", &routes));
        try lan.addresses6(try readOptional("/proc/net/if_inet6", &routes));
        p.lan = lan.prefixes[0..lan.len];
    }
    step = "dns";
    var resolv: [1024]u8 = undefined;
    var socket = try dns.Socket.open();
    defer socket.close();
    var local: [64]u8 = undefined;
    const validated = try readOptional(dns.local_validator_path, &local);
    const upstream_text = try readOptional(dns.upstream_path, &resolv);
    const servers = if (validated.len > 0) blk: {
        if (!std.mem.eql(u8, validated, dns.local_validator_text)) return error.BadResolver;
        break :blk try dns.validatedLocal(upstream_text);
    } else try dns.resolvers(upstream_text);
    p.local_validator = validated.len > 0;
    try dns.replace(&socket, p.dns, .{}, servers);
    step = "routes";
    try routeRules(p);
    step = "landlock";
    try restrict(p);
    return p;
}

// --- the policy --------------------------------------------------------------

/// Proto lists the IP protocols fence names. A policy may declare ICMP, TCP
/// and UDP. The rest are dropped on arrival: they have ports, or they are
/// tunnels or IPsec that would carry traffic past the rules if a handler
/// were ever loaded.
const Proto = net_rule.Proto;

/// dropped lists the protocols whose arriving packets are dropped unanswered.
const dropped = [_]Proto{ .tcp, .udp, .udplite, .sctp, .dccp, .ipip, .ipv6, .gre, .esp, .ah };

const Udp = struct { port: u16, uid: u32, lan: bool = false };

const Connect = struct {
    /// uid is null for every user.
    uid: ?u32,
    /// uid_last widens uid into a range, as for `:people`. Null is uid alone.
    uid_last: ?u32 = null,
    proto: Proto,
    /// port is 0 for ICMP, which has no ports, and for any.
    port: u16,
    /// any is every TCP port, for this user alone. Replies come back to
    /// the local port range. Loopback is refused except this user's
    /// other TCP ports. It is not `public`: a scan is of private nets.
    any: bool = false,
    /// public limits the connect to public addresses, refusing those in
    /// non_public4 and non_public6. It is for services that fetch URLs
    /// strangers name (a fediverse server's previews), so a forged request
    /// cannot reach the local network or the cloud's metadata server.
    public: bool = false,
    lan: bool = false,
    loopback: bool = false,
    destination: ?std.Io.net.IpAddress = null,
};

const Prefix = network.Prefix;
const non_public4 = network.non_public4;
const non_public6 = network.non_public6;
const v6 = network.v6;

const max_lan = 16;
/// LAN means directly connected subnets, including public-address LANs;
/// never the default route or all of RFC 1918. Storage outlives plan's rules.
const Lan = struct {
    addresses: [max_lan][16]u8 = undefined,
    prefixes: [max_lan]Prefix = undefined,
    len: usize = 0,

    fn add(l: *Lan, addr: []const u8, bits: u8) !void {
        if (bits == 0 or bits > addr.len * 8) return error.BadLan;
        var normalized: [16]u8 = @splat(0);
        for (addr, 0..) |byte, i| {
            const left = @min(8, bits -| (i * 8));
            normalized[i] = if (left == 0) 0 else byte & (@as(u8, 255) << @intCast(8 - left));
        }
        for (l.prefixes[0..l.len]) |p| if (p.len == bits and
            std.mem.eql(u8, p.addr, normalized[0..addr.len])) return;
        if (l.len == max_lan) return;
        l.addresses[l.len] = normalized;
        l.prefixes[l.len] = .{ .addr = l.addresses[l.len][0..addr.len], .len = bits };
        l.len += 1;
    }

    fn routes4(l: *Lan, text: []const u8) !void {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            var words = std.mem.tokenizeAny(u8, line, " \t");
            const nic = words.next() orelse continue;
            if (std.mem.eql(u8, nic, "Iface") or std.mem.eql(u8, nic, "lo")) continue;
            const dest = try std.fmt.parseInt(u32, words.next() orelse return error.BadLan, 16);
            const gateway = try std.fmt.parseInt(u32, words.next() orelse return error.BadLan, 16);
            const flags = try std.fmt.parseInt(u32, words.next() orelse return error.BadLan, 16);
            for (0..3) |_| _ = words.next() orelse return error.BadLan;
            const mask = try std.fmt.parseInt(u32, words.next() orelse return error.BadLan, 16);
            if (gateway != 0 or flags & 3 != 1 or mask == 0) continue;
            var addr: [4]u8 = undefined;
            std.mem.writeInt(u32, &addr, dest, .little);
            if (addr[0] == 0 or addr[0] == 127 or addr[0] >= 224) continue;
            const bits: u8 = @intCast(@popCount(mask));
            if (bits < 8) continue;
            try l.add(&addr, bits);
        }
    }

    fn addresses6(l: *Lan, text: []const u8) !void {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            var words = std.mem.tokenizeAny(u8, line, " \t");
            const hex = words.next() orelse continue;
            _ = words.next() orelse return error.BadLan; // interface index
            const bits = try std.fmt.parseInt(u8, words.next() orelse return error.BadLan, 16);
            _ = words.next() orelse return error.BadLan; // scope
            const flags = try std.fmt.parseInt(u32, words.next() orelse return error.BadLan, 16);
            const nic = words.next() orelse return error.BadLan;
            if (std.mem.eql(u8, nic, "lo") or flags & 0x48 != 0) continue; // tentative/DAD failed
            var addr: [16]u8 = undefined;
            _ = try std.fmt.hexToBytes(&addr, hex);
            if (hex.len != 32 or addr[0] == 255) return error.BadLan;
            // Ignore rogue Router Advertisement prefixes wider than /48 (or /64 on link-local).
            const link_local = addr[0] == 0xfe and (addr[1] & 0xc0) == 0x80;
            if (bits < (if (link_local) @as(u8, 64) else 48)) continue;
            try l.add(&addr, bits);
        }
    }
};

/// Only mDNS adds a multicast destination. Other LAN UDP ports and unicast
/// mDNS queries/replies stay within the connected subnets.
const mdns6 = v6(&.{ 0xff, 0x02 }, 0xfb);
fn discoveryGroup(family: u8, port_number: u16) ?[]const u8 {
    return switch (port_number) {
        5353 => if (family == linux.AF.INET) &.{ 224, 0, 0, 251 } else &mdns6,
        else => null,
    };
}

const Policy = struct {
    /// listen holds the served ports, reachable from the network.
    listen: [max_entries]u16 = undefined,
    nlisten: usize = 0,
    /// listen_lan holds TCP listeners open only to connected subnets.
    listen_lan: [max_entries]u16 = undefined,
    nlisten_lan: usize = 0,
    /// loopback holds ports bound and reached only from this machine.
    loopback: [max_entries]u16 = undefined,
    nloopback: usize = 0,
    /// udp holds the served UDP ports, each with the one user that may send
    /// from it: Landlock cannot hold a UDP bind, so the reply is what fence
    /// holds (docs/design/implemented/listen-udp.md).
    udp: [max_entries]Udp = undefined,
    nudp: usize = 0,
    connect: [max_entries]Connect = undefined,
    nconnect: usize = 0,
    metadata: [max_entries]u32 = undefined,
    nmetadata: usize = 0,
    dns: dns.Users = .{},
    dns_direct: dns.Users = .{},
    local_validator: bool = false,
    /// lookups are unwound's clients, in label order.
    lookups: dns.Users = .{},
    lan: []const Prefix = &.{},

    fn needsLan(p: Policy) bool {
        if (p.nlisten_lan > 0) return true;
        for (p.udp[0..p.nudp]) |u| if (u.lan) return true;
        for (p.connect[0..p.nconnect]) |c| if (c.lan or c.public) return true;
        return false;
    }

    /// connectText formats the connect entries for the log: "0 tcp 443".
    fn connectText(p: *const Policy, out: *[max_entries][]const u8, buf: []u8) []const []const u8 {
        var w: Io.Writer = .fixed(buf);
        for (p.connect[0..p.nconnect], 0..) |c, i| {
            const start = w.end;
            if (c.uid) |u|
                w.print("{d}", .{u}) catch return out[0..i]
            else
                w.writeAll("all") catch return out[0..i];
            if (c.uid_last) |u| w.print("-{d}", .{u}) catch return out[0..i];
            w.print(" {s}", .{@tagName(c.proto)}) catch return out[0..i];
            if (c.any)
                w.writeAll(" any") catch return out[0..i]
            else if (c.proto != .icmp)
                w.print(" {d}", .{c.port}) catch return out[0..i];
            if (c.public) w.writeAll(" public") catch return out[0..i];
            if (c.lan) w.writeAll(" lan") catch return out[0..i];
            if (c.loopback) w.writeAll(" loopback") catch return out[0..i];
            out[i] = buf[start..w.end];
        }
        return out[0..p.nconnect];
    }
};

/// parsePolicy parses `listen tcp PORT [loopback|lan]`, `listen UID udp PORT [lan]`,
/// `connect UIDS|all PROTO [PORT] [public|lan]`, `metadata UID`, `dns UID`,
/// `dns-direct UID`
/// and `lookup UIDS ...` lines, where UIDS is a uid or a range, FIRST-LAST;
/// the rest of a lookup line is unwound's to check. Only a named user's
/// UDP accepts lan. Anything else is BadPolicy.
fn parsePolicy(text: []const u8) !Policy {
    var p: Policy = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        const key = words.next() orelse continue;
        if (std.mem.eql(u8, key, "listen")) {
            const proto = words.next() orelse "";
            if (!std.mem.eql(u8, proto, "tcp")) {
                const uid = try user(proto);
                if (!std.mem.eql(u8, words.next() orelse "", "udp")) return error.BadPolicy;
                if (p.nudp == max_entries) return error.BadPolicy;
                p.udp[p.nudp] = .{ .port = try port(words.next()), .uid = uid };
                if (std.mem.eql(u8, words.peek() orelse "", "lan")) {
                    _ = words.next();
                    p.udp[p.nudp].lan = true;
                }
                p.nudp += 1;
                if (words.next() != null) return error.BadPolicy;
                continue;
            }
            const l = try port(words.next());
            if (std.mem.eql(u8, words.peek() orelse "", "loopback")) {
                _ = words.next();
                if (p.nloopback == max_entries) return error.BadPolicy;
                p.loopback[p.nloopback] = l;
                p.nloopback += 1;
            } else if (std.mem.eql(u8, words.peek() orelse "", "lan")) {
                _ = words.next();
                if (p.nlisten_lan == max_entries) return error.BadPolicy;
                p.listen_lan[p.nlisten_lan] = l;
                p.nlisten_lan += 1;
            } else {
                if (p.nlisten == max_entries) return error.BadPolicy;
                p.listen[p.nlisten] = l;
                p.nlisten += 1;
            }
        } else if (std.mem.eql(u8, key, "connect")) {
            const who = words.next() orelse return error.BadPolicy;
            const uids: ?dns.Uids = if (std.mem.eql(u8, who, "all")) null else try .parse(who);
            const uid = if (uids) |u| u.first else null;
            const proto = std.meta.stringToEnum(
                Proto,
                words.next() orelse "",
            ) orelse return error.BadPolicy;
            if (proto != .icmp and proto != .tcp and proto != .udp) return error.BadPolicy;
            if (p.nconnect == max_entries) return error.BadPolicy;
            var any = false;
            var pnum: u16 = 0;
            if (proto != .icmp) {
                const word = words.next() orelse return error.BadPolicy;
                if (std.mem.eql(u8, word, "any")) {
                    // One user, TCP. `all` would open every program. UDP
                    // any is not a scan's replies.
                    if (proto != .tcp or uid == null or
                        uids.?.last != uid.?) return error.BadPolicy;
                    any = true;
                } else pnum = try port(word);
            }
            p.connect[p.nconnect] = .{
                .uid = uid,
                .uid_last = if (uids) |u| if (u.last != u.first) u.last else null else null,
                .proto = proto,
                .port = pnum,
                .any = any,
            };
            if (proto != .icmp and std.mem.eql(u8, words.peek() orelse "", "public")) {
                if (any) return error.BadPolicy;
                p.connect[p.nconnect].public = true;
                _ = words.next();
            }
            if (std.mem.eql(u8, words.peek() orelse "", "lan")) {
                if (proto != .udp or uid == null or p.connect[p.nconnect].public)
                    return error.BadPolicy;
                p.connect[p.nconnect].lan = true;
                _ = words.next();
            }
            if (std.mem.eql(u8, words.peek() orelse "", "loopback")) {
                if (proto != .tcp or any or p.connect[p.nconnect].public or
                    p.connect[p.nconnect].lan)
                    return error.BadPolicy;
                p.connect[p.nconnect].loopback = true;
                _ = words.next();
            }
            if (std.mem.eql(u8, words.peek() orelse "", "destination")) {
                _ = words.next();
                if (proto != .tcp or any or p.connect[p.nconnect].loopback or
                    p.connect[p.nconnect].public)
                    return error.BadPolicy;
                p.connect[p.nconnect].destination = std.Io.net.IpAddress.parse(
                    words.next() orelse return error.BadPolicy,
                    0,
                ) catch return error.BadPolicy;
                const unsafe = switch (p.connect[p.nconnect].destination.?) {
                    .ip4 => |a| std.mem.eql(u8, &a.bytes, &metadata_ip) or
                        std.mem.eql(u8, &a.bytes, &wire_server_ip),
                    .ip6 => |a| std.mem.eql(u8, &a.bytes, &metadata_ip6) or
                        std.mem.eql(
                            u8,
                            a.bytes[0..12],
                            &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255 },
                        ),
                };
                if (unsafe) return error.BadPolicy;
            }
            p.nconnect += 1;
        } else if (std.mem.eql(u8, key, "dns")) {
            try p.dns.add(.one(try user(words.next() orelse "")));
        } else if (std.mem.eql(u8, key, "dns-direct")) {
            try p.dns_direct.add(.one(try user(words.next() orelse "")));
        } else if (std.mem.eql(u8, key, "lookup")) {
            try p.lookups.add(try .parse(words.next() orelse ""));
            if (words.next() == null) return error.BadPolicy;
            continue;
        } else if (std.mem.eql(u8, key, "metadata")) {
            if (p.nmetadata == max_entries) return error.BadPolicy;
            p.metadata[p.nmetadata] = try user(words.next() orelse "");
            p.nmetadata += 1;
        } else return error.BadPolicy;
        if (words.next() != null) return error.BadPolicy;
    }
    return p;
}

fn port(word: ?[]const u8) !u16 {
    const n = std.fmt.parseInt(u16, word orelse "", 10) catch return error.BadPolicy;
    return if (n == 0) error.BadPolicy else n;
}

fn user(word: []const u8) !u32 {
    const n = std.fmt.parseInt(u32, word, 10) catch return error.BadPolicy;
    return if (n == std.math.maxInt(u32)) error.BadPolicy else n;
}

// --- the rules ---------------------------------------------------------------

const FR_ACT_TO_TBL = 1;
const FR_ACT_BLACKHOLE = 6;
const FR_ACT_UNREACHABLE = 7;
const FR_ACT_PROHIBIT = 8;
const RT_TABLE_MAIN = 254;

test "bastion destinations constrain shell connections as well as forwarding" {
    const p = try parsePolicy(
        "listen tcp 22\nconnect 1000 tcp 22 loopback\n" ++
            "connect 1000 tcp 22 destination 192.0.2.5\n" ++
            "connect 1000 tcp 22 destination 2001:db8::5\n",
    );
    const decide = struct {
        fn action(rules: []const Rule, uid: u32, destination: []const u8, target: u16) u8 {
            for (rules) |r| {
                if (!r.from_here or (r.proto != null and r.proto != .tcp) or
                    r.sport != null) continue;
                if (r.uid) |id| if (uid < id or uid > (r.uid_last orelse id)) continue;
                if (r.dport) |port_number| if (target != port_number) continue;
                if (r.dst) |dst| if (!prefixMatches(
                    destination,
                    dst,
                    r.dst_len orelse @intCast(dst.len * 8),
                )) continue;
                if (r.action == FR_ACT_TO_TBL and r.table == RT_TABLE_LOCAL and
                    !std.mem.eql(u8, destination, &loopback_ip) and
                    !std.mem.eql(u8, destination, &loopback6)) continue;
                return r.action;
            }
            return 0;
        }
    }.action;
    var rules: [max_rules]Rule = undefined;
    const ipv4 = plan(&p, linux.AF.INET, &rules);
    try std.testing.expectEqual(FR_ACT_TO_TBL, decide(ipv4, 1000, &.{ 192, 0, 2, 5 }, 22));
    try std.testing.expectEqual(FR_ACT_PROHIBIT, decide(ipv4, 1000, &.{ 192, 0, 2, 6 }, 22));
    try std.testing.expectEqual(FR_ACT_PROHIBIT, decide(ipv4, 1001, &.{ 192, 0, 2, 5 }, 22));
    const ipv6 = plan(&p, linux.AF.INET6, &rules);
    const allowed = try std.Io.net.IpAddress.parse("2001:db8::5", 0);
    const denied = try std.Io.net.IpAddress.parse("2001:db8::6", 0);
    try std.testing.expectEqual(FR_ACT_TO_TBL, decide(ipv6, 1000, &allowed.ip6.bytes, 22));
    try std.testing.expectEqual(FR_ACT_PROHIBIT, decide(ipv6, 1000, &denied.ip6.bytes, 22));
}
const RT_TABLE_LOCAL = 255;

/// Rule is one policy-routing rule, as `ip rule` shows it.
const Rule = net_rule.Rule;

/// max_rules bounds plan's output. Per entry index, listen, UDP listen,
/// connect, metadata and private ports make at most 3 + 3 + 3 + 2 + 1
/// rules, and a public connect one more per non-public prefix; the rest are fixed.
/// policy_max bounds the compiled policy, lookup grants included.
const policy_max = 64 << 10;

const max_rules = 32 + 2 * dns.max_users + wire_server_ports.len + dropped.len +
    (44 + 13 * max_lan + @as(usize, @max(non_public4.len, non_public6.len))) * max_entries;

/// overlapsPeople reports whether c's uid or range intersects people.ids.
fn overlapsPeople(c: Connect) bool {
    const first = c.uid orelse return true;
    const last = c.uid_last orelse first;
    for (people.ids) |r| {
        if (first <= r[1] and last >= r[0]) return true;
    }
    return false;
}

/// plan returns the rules for family, in the order the kernel tries them:
///
///   5     a `public` connect to a non-public or connected-LAN address: refused
///   8     named ports on loopback for wide connectors and people: local table
///   9     the rest of loopback for wide connectors and people: refused
///   10    sent over loopback, or by root to this machine: local table
///   100   sent to the metadata server's TCP 80 by a named user: main
///   101   sent to it by anyone else, or to Azure's wire server: refused
///   200   sent as declared (user, protocol, port), from a served port (a
///         UDP one by its user alone), or ICMPv6 (which neighbour discovery
///         needs): main
///   290   arriving at a loopback-only TCP port: dropped
///   299   anything else sent: refused (EACCES)
///   300   arriving at a served port, from a connected port or the metadata
///         server, or ICMP: local
///   399   anything else arriving by TCP, UDP, UDP-Lite, SCTP, DCCP, or a
///         tunnel or IPsec: dropped
///   400   the kernel's local rule, moved from 0
///
/// The drops name their protocols because ARP asks whether an address is
/// local with a lookup that has no protocol; dropping that would leave the
/// machine unreachable.
///
/// Each rule that routes traffic out is followed by an unreachable twin. So
/// allowed traffic with no route (IPv6 on an IPv4 network) fails with
/// "network unreachable" and the client tries the next address, instead of
/// falling through to EACCES, which many clients take as final.
fn plan(p: *const Policy, family: u8, out: *[max_rules]Rule) []const Rule {
    const md: []const u8 = if (family == linux.AF.INET6) &metadata_ip6 else &metadata_ip;
    var rules: struct {
        out: *[max_rules]Rule,
        n: usize = 0,
        family: u8,

        /// add appends r in the list's family, and its unreachable twin if r
        /// routes traffic out.
        fn add(list: *@This(), r: Rule) void {
            var x = r;
            x.family = list.family;
            list.out[list.n] = x;
            list.n += 1;
            if (x.from_here and x.action == FR_ACT_TO_TBL and x.table == RT_TABLE_MAIN) {
                x.action = FR_ACT_UNREACHABLE;
                x.table = 0;
                list.out[list.n] = x;
                list.n += 1;
            }
        }

        fn onLan(list: *@This(), r: Rule, prefixes: []const Prefix, port_number: u16) void {
            for (prefixes) |prefix| {
                if (prefix.addr.len != (if (list.family == linux.AF.INET) @as(usize, 4) else 16))
                    continue;
                var x = r;
                if (r.from_here) {
                    x.dst = prefix.addr;
                    x.dst_len = prefix.len;
                } else {
                    x.src = prefix.addr;
                    x.src_len = prefix.len;
                }
                list.add(x);
            }
            if (r.from_here) if (discoveryGroup(list.family, port_number)) |group| {
                var x = r;
                x.dst = group;
                x.dport = port_number;
                list.add(x);
            };
        }
    } = .{ .out = out, .family = family };
    if (family == linux.AF.INET and p.lookups.len > 0) {
        // A lookup user may send from its own label, and the kernel picks
        // that label for it; no one else reaches unwound, or sends from one.
        const ids = p.lookups.ids[0..p.lookups.len];
        for (ids, 0..) |id, n| rules.add(.{
            .priority = pref.label_own,
            .action = FR_ACT_TO_TBL,
            .table = dns.labelTable(n),
            .from_here = true,
            .src = &dns.label_ips[n],
            .dst = &dns.resolver,
            .uid = id.first,
            .uid_last = id.last,
        });
        rules.add(.{
            .priority = pref.label_forged,
            .action = FR_ACT_PROHIBIT,
            .from_here = true,
            .src = &loopback_net,
            .src_len = 8,
            .dst = &dns.resolver,
        });
        for (ids, 0..) |id, n| rules.add(.{
            .priority = pref.label_pick,
            .action = FR_ACT_TO_TBL,
            .table = dns.labelTable(n),
            .from_here = true,
            .dst = &dns.resolver,
            .uid = id.first,
            .uid_last = id.last,
        });
    }
    if (family == linux.AF.INET) rules.add(.{
        .priority = pref.label_refuse,
        .action = FR_ACT_PROHIBIT,
        .from_here = true,
        .dst = &dns.resolver,
    });
    const non_public: []const Prefix = if (family == linux.AF.INET6) &non_public6 else &non_public4;
    const addr_len: usize = if (family == linux.AF.INET6) 16 else 4;
    for (p.connect[0..p.nconnect]) |c| if (c.public) {
        for (non_public) |np| rules.add(.{
            .priority = pref.public_refuse,
            .action = FR_ACT_PROHIBIT,
            .from_here = true,
            .dst = np.addr,
            .dst_len = np.len,
            .proto = c.proto,
            .dport = c.port,
            .uid = c.uid,
            .uid_last = c.uid_last,
        });
        for (p.lan) |lp| if (lp.addr.len == addr_len) {
            const covered = for (non_public) |np| {
                if (lp.len >= np.len and prefixMatches(lp.addr, np.addr, np.len)) break true;
            } else false;
            if (!covered) rules.add(.{
                .priority = pref.public_refuse,
                .action = FR_ACT_PROHIBIT,
                .from_here = true,
                .dst = lp.addr,
                .dst_len = lp.len,
                .proto = c.proto,
                .dport = c.port,
                .uid = c.uid,
                .uid_last = c.uid_last,
            });
        };
    };
    if (family == linux.AF.INET and p.local_validator) {
        for ([_]Proto{ .udp, .tcp }) |proto| rules.add(.{
            .priority = pref.local_validator_refuse,
            .action = FR_ACT_PROHIBIT,
            .from_here = true,
            .dst = &loopback_ip,
            .proto = proto,
            .dport = 53,
        });
    }
    // Wide connectors (`tcp any`) and interactive logins (`people.ids`) must
    // not reach undeclared internal loopback services. Emit all loopback_allow
    // rules before any loopback_refuse rule so priorities stay monotonic.
    var isolated: [max_entries]u32 = undefined;
    var niso: usize = 0;
    for (p.connect[0..p.nconnect]) |c| {
        if (!c.any or c.uid == null) continue;
        const id = c.uid.?;
        const seen = for (isolated[0..niso]) |u| {
            if (u == id) break true;
        } else false;
        if (!seen) {
            isolated[niso] = id;
            niso += 1;
        }
    }
    for (p.connect[0..p.nconnect]) |*c| {
        if (c.destination) |*address| {
            if ((address.* == .ip4) != (family == linux.AF.INET)) continue;
            rules.add(.{
                .priority = pref.loopback_allow,
                .action = FR_ACT_TO_TBL,
                .table = if (switch (address.*) {
                    .ip4 => |a| a.bytes[0] == 127,
                    .ip6 => |a| std.mem.eql(u8, &a.bytes, &loopback6),
                })
                    RT_TABLE_LOCAL
                else
                    RT_TABLE_MAIN,
                .from_here = true,
                .dst = switch (address.*) {
                    .ip4 => |*a| &a.bytes,
                    .ip6 => |*a| &a.bytes,
                },
                .proto = .tcp,
                .dport = c.port,
                .uid = c.uid,
                .uid_last = c.uid_last,
            });
            continue;
        }
        if (c.loopback) {
            rules.add(.{
                .priority = pref.loopback_allow,
                .action = FR_ACT_TO_TBL,
                .table = RT_TABLE_LOCAL,
                .from_here = true,
                .dst = if (family == linux.AF.INET6) &loopback6 else &loopback_ip,
                .proto = .tcp,
                .dport = c.port,
                .uid = c.uid,
                .uid_last = c.uid_last,
            });
            continue;
        }
        if (c.any or c.public or c.proto != .tcp) continue;
        const in_isolated = if (c.uid) |id| c.uid_last == null and for (isolated[0..niso]) |u| {
            if (u == id) break true;
        } else false else false;
        if (in_isolated or overlapsPeople(c.*)) rules.add(.{
            .priority = pref.loopback_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_LOCAL,
            .from_here = true,
            .dst = if (family == linux.AF.INET6) &loopback6 else &loopback_ip,
            .proto = .tcp,
            .dport = c.port,
            .uid = c.uid,
            .uid_last = c.uid_last,
        });
    }
    for (isolated[0..niso]) |id| rules.add(.{
        .priority = pref.loopback_refuse,
        .action = FR_ACT_PROHIBIT,
        .from_here = true,
        .dst = if (family == linux.AF.INET6) &loopback6 else &loopback_net,
        .dst_len = if (family == linux.AF.INET6) 128 else 8,
        .uid = id,
    });
    for (people.ids) |range| rules.add(.{
        .priority = pref.loopback_refuse,
        .action = FR_ACT_PROHIBIT,
        .from_here = true,
        .dst = if (family == linux.AF.INET6) &loopback6 else &loopback_net,
        .dst_len = if (family == linux.AF.INET6) 128 else 8,
        .uid = range[0],
        .uid_last = range[1],
    });
    // A loopback-only connector gets the named port on the two loopback
    // addresses. Refuse every other destination before the local table,
    // including another address assigned to this machine.
    for (p.connect[0..p.nconnect]) |c| if (c.loopback) rules.add(.{
        .priority = pref.loopback_refuse,
        .action = FR_ACT_PROHIBIT,
        .from_here = true,
        .proto = .tcp,
        .dport = c.port,
        .uid = c.uid,
        .uid_last = c.uid_last,
    });
    // Pin non-root local delivery to true loopback so assigned NIC addresses
    // cannot bypass loopback-only listeners, wide-connect isolation or public
    // egress restrictions. Root retains local-address delivery.
    rules.add(.{
        .priority = pref.local_out,
        .action = FR_ACT_TO_TBL,
        .table = RT_TABLE_LOCAL,
        .from_here = true,
        .dst = if (family == linux.AF.INET6) &loopback6 else &loopback_net,
        .dst_len = if (family == linux.AF.INET6) 128 else 8,
    });
    rules.add(.{
        .priority = pref.local_out,
        .action = FR_ACT_TO_TBL,
        .table = RT_TABLE_LOCAL,
        .from_here = true,
        .uid = 0,
    });
    for (p.metadata[0..p.nmetadata]) |uid| rules.add(.{
        .priority = pref.metadata_allow,
        .action = FR_ACT_TO_TBL,
        .table = RT_TABLE_MAIN,
        .from_here = true,
        .dst = md,
        .proto = .tcp,
        .dport = metadata_port,
        .uid = uid,
    });
    rules.add(.{
        .priority = pref.metadata_refuse,
        .action = FR_ACT_PROHIBIT,
        .from_here = true,
        .dst = md,
    });
    if (family == linux.AF.INET) for (wire_server_ports) |port_number| rules.add(.{
        .priority = pref.metadata_refuse,
        .action = FR_ACT_PROHIBIT,
        .from_here = true,
        .dst = &wire_server_ip,
        .proto = .tcp,
        .dport = port_number,
    });
    for (p.connect[0..p.nconnect]) |c| {
        if (c.loopback or c.uid == null or c.uid_last != null or
            !p.dns_direct.has(c.uid.?) or c.any or
            (c.proto != .udp and c.proto != .tcp) or
            (c.port != 53 and c.port != 853)) continue;
        const r: Rule = .{
            .priority = pref.dns_direct_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_MAIN,
            .from_here = true,
            .proto = c.proto,
            .dport = c.port,
            .uid = c.uid,
        };
        if (c.lan) rules.onLan(r, p.lan, c.port) else rules.add(r);
    }
    for ([_]Proto{ .udp, .tcp }) |proto| for ([_]u16{ 53, 853 }) |port_number| rules.add(.{
        .priority = pref.dns_refuse,
        .action = FR_ACT_PROHIBIT,
        .from_here = true,
        .proto = proto,
        .dport = port_number,
    });
    for (p.connect[0..p.nconnect]) |c| {
        if (c.loopback or c.destination != null) continue;
        const r: Rule = .{
            .priority = pref.out_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_MAIN,
            .from_here = true,
            .proto = c.proto,
            .dport = if (c.proto == .icmp or c.any) null else c.port,
            .uid = c.uid,
            .uid_last = c.uid_last,
        };
        if (c.lan) rules.onLan(r, p.lan, c.port) else rules.add(r);
    }
    for (p.listen[0..p.nlisten]) |l| rules.add(.{
        .priority = pref.out_allow,
        .action = FR_ACT_TO_TBL,
        .table = RT_TABLE_MAIN,
        .from_here = true,
        .proto = .tcp,
        .sport = l,
    });
    for (p.listen_lan[0..p.nlisten_lan]) |l| rules.onLan(.{
        .priority = pref.out_allow,
        .action = FR_ACT_TO_TBL,
        .table = RT_TABLE_MAIN,
        .from_here = true,
        .proto = .tcp,
        .sport = l,
    }, p.lan, 0);
    // Landlock holds a TCP port's bind; nothing holds a UDP one's, so only
    // its user's datagrams leave from it, and a squatter cannot answer.
    for (p.udp[0..p.nudp]) |u| {
        const r: Rule = .{
            .priority = pref.out_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_MAIN,
            .from_here = true,
            .proto = .udp,
            .sport = u.port,
            .uid = u.uid,
        };
        if (u.lan) rules.onLan(r, p.lan, u.port) else rules.add(r);
    }
    if (family == linux.AF.INET6) rules.add(.{
        .priority = pref.out_allow,
        .action = FR_ACT_TO_TBL,
        .table = RT_TABLE_MAIN,
        .from_here = true,
        .proto = .icmp,
    });
    // Incoming LAN grants below must never act as outgoing grants to an
    // undeclared user. Refuse those destinations before matching arrivals.
    for (p.udp[0..p.nudp]) |u| if (u.lan) rules.add(.{
        .priority = pref.out_lan_refuse,
        .action = FR_ACT_PROHIBIT,
        .from_here = true,
        .proto = .udp,
        .dport = u.port,
    });
    // A forged reply source port must not expose a private listener that
    // binds all interfaces. Local traffic has already matched local_out.
    for (p.loopback[0..p.nloopback]) |port_number| {
        // A DNS server can expose the same TCP port on LAN while unwound
        // owns only its loopback address. The LAN rule below supplies the
        // off-LAN drop for that port.
        const served_on_lan = blk: {
            for (p.listen_lan[0..p.nlisten_lan]) |l|
                if (l == port_number) break :blk true;
            break :blk false;
        };
        if (!served_on_lan) rules.add(.{
            .priority = pref.in_private,
            .action = FR_ACT_BLACKHOLE,
            .proto = .tcp,
            .dport = port_number,
        });
    }
    // Drop off-LAN traffic before any broad source-port reply allowance.
    // A forged packet from 53/443 must not expose a discovery listener.
    for (p.udp[0..p.nudp]) |u| if (u.lan) {
        rules.onLan(.{
            .priority = pref.in_private,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_LOCAL,
            .proto = .udp,
            .dport = u.port,
        }, p.lan, u.port);
        rules.add(.{
            .priority = pref.in_private,
            .action = FR_ACT_BLACKHOLE,
            .proto = .udp,
            .dport = u.port,
        });
    };
    for (p.listen_lan[0..p.nlisten_lan]) |port_number| {
        rules.onLan(.{
            .priority = pref.in_private,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_LOCAL,
            .proto = .tcp,
            .dport = port_number,
        }, p.lan, port_number);
        rules.add(.{
            .priority = pref.in_private,
            .action = FR_ACT_BLACKHOLE,
            .proto = .tcp,
            .dport = port_number,
        });
    }
    rules.add(.{ .priority = pref.out_refuse, .action = FR_ACT_PROHIBIT, .from_here = true });

    for (p.listen[0..p.nlisten]) |l| rules.add(.{
        .priority = pref.in_allow,
        .action = FR_ACT_TO_TBL,
        .table = RT_TABLE_LOCAL,
        .proto = .tcp,
        .dport = l,
    });
    for (p.udp[0..p.nudp]) |u| if (!u.lan) rules.add(.{
        .priority = pref.in_allow,
        .action = FR_ACT_TO_TBL,
        .table = RT_TABLE_LOCAL,
        .proto = .udp,
        .dport = u.port,
    });
    // Let replies in from each protocol and port some user connects to, once:
    // TCP to the kernel's ephemeral range, UDP to unprivileged ports (so
    // Unbound and dnsmasq may randomize across 1024..65534). The kernel
    // refuses a range that ends at 65535 (fib_rule_port_range_valid), so a
    // reply to that one port is dropped.
    for (p.connect[0..p.nconnect], 0..) |c, i| {
        if (c.proto == .icmp or c.any or c.loopback) continue;
        const seen = for (p.connect[0..i]) |d| {
            if (!d.loopback and d.proto == c.proto and d.port == c.port and (!d.lan or
                c.lan)) break true;
        } else false;
        const r: Rule = .{
            .priority = pref.in_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_LOCAL,
            .proto = c.proto,
            .sport = c.port,
            .dport = if (c.proto == .tcp) ephemeral_lo else 1024,
            .dport_last = if (c.proto == .tcp) ephemeral_hi else 65534,
        };
        if (!seen) {
            if (c.lan) rules.onLan(r, p.lan, c.port) else rules.add(r);
        }
    }
    // Replies to a connection opened to an arbitrary port. Matching every
    // source port would deliver new connections to every local port.
    // Matching the destination against the local port range delivers the
    // reply and leaves declared service ports on the listen lines.
    var wide = false;
    for (p.connect[0..p.nconnect]) |c| if (c.any) {
        wide = true;
        break;
    };
    if (wide) rules.add(.{
        .priority = pref.in_allow,
        .action = FR_ACT_TO_TBL,
        .table = RT_TABLE_LOCAL,
        .proto = .tcp,
        .dport = ephemeral_lo,
        .dport_last = ephemeral_hi,
    });
    if (p.nmetadata > 0) rules.add(.{
        .priority = pref.in_allow,
        .action = FR_ACT_TO_TBL,
        .table = RT_TABLE_LOCAL,
        .src = md,
        .proto = .tcp,
        .sport = metadata_port,
        .dport = ephemeral_lo,
        .dport_last = ephemeral_hi,
    });
    // Let ICMP in for the errors connections need (path MTU, unreachable).
    // An echo request gets no reply unless the policy lets root send ICMP.
    rules.add(.{
        .priority = pref.in_allow,
        .action = FR_ACT_TO_TBL,
        .table = RT_TABLE_LOCAL,
        .proto = .icmp,
    });
    for (dropped) |pr| rules.add(.{
        .priority = pref.in_drop,
        .action = FR_ACT_BLACKHOLE,
        .proto = pr,
    });
    rules.add(.{ .priority = pref.local, .action = FR_ACT_TO_TBL, .table = RT_TABLE_LOCAL });
    return out[0..rules.n];
}

/// routeRules adds each lookup user's label route and every rule, then
/// deletes the kernel's local rule at 0, which would otherwise deliver
/// arriving packets, and unwound's queries, before the policy sees them.
fn routeRules(p: Policy) !void {
    const nl: i32 = @intCast(try sys(
        linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.ROUTE),
        "netlink socket",
    ));
    defer _ = linux.close(nl);
    var seq: u32 = 1;
    for (0..p.lookups.len) |n| {
        var msg: [256]u8 = undefined;
        const route = net_rule.localRouteMessage(
            &msg,
            seq,
            dns.labelTable(n),
            &dns.resolver,
            &dns.label_ips[n],
        );
        send(nl, route, seq, "add label route") catch |err|
            if (err != error.SystemCall or sandbox.failed_errno != .EXIST) return err;
        seq += 1;
    }
    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |family| {
        if (family == linux.AF.INET6 and !hasIpv6()) continue;
        var rules: [max_rules]Rule = undefined;
        for (plan(&p, family, &rules)) |r| {
            var msg: [256]u8 = undefined;
            // Two forms, or a form and fence itself, may produce the same
            // rule. EEXIST under NLM_F_EXCL means it is already in, which is
            // not a failure, and PID 1 must not die on it.
            send(nl, ruleMessage(&msg, seq, RTM_NEWRULE, r), seq, "add rule") catch |err|
                if (err != error.SystemCall or sandbox.failed_errno != .EXIST) return err;
            seq += 1;
        }
        var msg: [256]u8 = undefined;
        try send(
            nl,
            ruleMessage(
                &msg,
                seq,
                RTM_DELRULE,
                .{
                    .family = family,
                    .priority = 0,
                    .action = FR_ACT_TO_TBL,
                    .table = RT_TABLE_LOCAL,
                },
            ),
            seq,
            "delete the local rule",
        );
        seq += 1;
    }
}

/// hasIpv6 reports whether the kernel has IPv6. With ipv6.disable=1, which
/// werewolf uses unless the form allows IPv6, /proc/net/if_inet6 is absent.
fn hasIpv6() bool {
    return linux.errno(linux.access("/proc/net/if_inet6", linux.F_OK)) == .SUCCESS;
}

const NLMSG_ERROR = net_rule.NLMSG_ERROR;
const RTM_NEWRULE = net_rule.RTM_NEWRULE;
const RTM_DELRULE = net_rule.RTM_DELRULE;
const FRA_DST = net_rule.FRA_DST;
const FRA_SRC = net_rule.FRA_SRC;
const FRA_IIFNAME = net_rule.FRA_IIFNAME;
const FRA_PRIORITY = net_rule.FRA_PRIORITY;
const FRA_TABLE = net_rule.FRA_TABLE;
const FRA_UID_RANGE = net_rule.FRA_UID_RANGE;
const FRA_IP_PROTO = net_rule.FRA_IP_PROTO;
const FRA_SPORT_RANGE = net_rule.FRA_SPORT_RANGE;
const FRA_DPORT_RANGE = net_rule.FRA_DPORT_RANGE;
const ruleMessage = net_rule.ruleMessage;
const send = net_rule.send;
const ackError = net_rule.ackError;

// --- the ports: Landlock -----------------------------------------------------

/// restrict applies a Landlock domain to this process and all it execs. TCP
/// may bind only the policy's ports and port 0, and connect only to declared,
/// served, loopback and metadata ports. The routing rule that lets a server
/// reply from its port names no user or destination, so without this limit a
/// compromised listener could connect anywhere from that port. Files are
/// limited too: see files, and /dev below.
fn restrict(p: Policy) !void {
    // The ruleset handles every filesystem right, TCP bind and connect, and
    // from ABI 6 scopes signals and abstract UNIX sockets. Scoping keeps root
    // in the domain from signalling what init started before fence: the
    // mount broker, DHCP's renewal and stage0's deadman.
    const ruleset: sandbox.Ruleset = try .init(.{});
    if (ruleset.abi < 4) {
        sandbox.failed = "Landlock without network rules (ABI 4)";
        return error.LandlockTooOld;
    }
    try ruleset.port(sandbox.bind_tcp, 0);
    for (p.listen[0..p.nlisten]) |l| {
        try ruleset.port(sandbox.bind_tcp, l);
        try ruleset.port(sandbox.connect_tcp, l);
    }
    for (p.listen_lan[0..p.nlisten_lan]) |l| {
        try ruleset.port(sandbox.bind_tcp, l);
        try ruleset.port(sandbox.connect_tcp, l);
    }
    // Private-port drops precede reply allowances; local traffic passes first.
    for (p.loopback[0..p.nloopback]) |l| {
        try ruleset.port(sandbox.bind_tcp, l);
        try ruleset.port(sandbox.connect_tcp, l);
    }
    for (p.connect[0..p.nconnect]) |c| if (c.proto == .tcp) {
        if (c.any) {
            var port_num: u32 = 1;
            while (port_num <= 65535) : (port_num += 1)
                try ruleset.port(sandbox.connect_tcp, @intCast(port_num));
        } else try ruleset.port(sandbox.connect_tcp, c.port);
    };
    if (p.dns.len > 0 or p.lookups.len > 0 or p.dns_direct.len > 0)
        try ruleset.port(sandbox.connect_tcp, 53);
    if (p.nmetadata > 0) try ruleset.port(sandbox.connect_tcp, metadata_port);
    for (files) |f| try allowPath(ruleset, linux.AT.FDCWD, f.path, f.access);
    // init creates this executable tmpfs only for a checked --dev boot with
    // Howl's dev marker. The machine-wide domain must admit its programs;
    // the selected test's nested leash still narrows them to its own policy.
    if (linux.errno(linux.access("/run/howl-dev", linux.F_OK)) == .SUCCESS)
        try allowPath(
            ruleset,
            linux.AT.FDCWD,
            "/run/howl-dev",
            sandbox.execute | sandbox.read_file,
        );
    // No service gets the TPM: stage0 checked its floor before handover, and
    // the mount broker, outside this domain, alone raises it.
    // Allow the writable binds under each image root (cmd/init/oci.zig).
    // Landlock judges a path by where it is mounted, not where a bind came
    // from, so /run's and /data's rules do not cover them.
    var oci_buf: [16384]u8 = undefined;
    var binds: Binds = .{ .text = try readOptional(oci_path, &oci_buf) };
    while (binds.next()) |b| try allowPath(
        ruleset,
        linux.AT.FDCWD,
        b.path,
        if (b.sockets) writable | sandbox.make_sock | sandbox.make_fifo else writable,
    );
    // Grant read on each entry of / but /dev, so /dev gets only the devices
    // named here and below.
    const root: i32 = @intCast(try sys(
        linux.openat(linux.AT.FDCWD, "/", .{ .DIRECTORY = true, .CLOEXEC = true }, 0),
        "open /",
    ));
    defer _ = linux.close(root);
    var buf: [8192]u8 align(8) = undefined;
    while (true) {
        const n = try sys(linux.getdents64(root, &buf, buf.len), "read /");
        if (n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const ent: *align(1) const linux.dirent64 = @ptrCast(&buf[off]);
            off += ent.reclen;
            const name: [*:0]const u8 = @ptrCast(&ent.name);
            const s_name = std.mem.sliceTo(name, 0);
            if (std.mem.eql(u8, s_name, ".") or std.mem.eql(u8, s_name, "..") or
                std.mem.eql(u8, s_name, "dev")) continue;
            // Directory rights apply only to directories; a link such as
            // bin resolves to usr/bin, which has its own rule.
            const access: u64 = if (ent.type == linux.DT.DIR)
                sandbox.read_file | sandbox.read_dir
            else
                sandbox.read_file;
            try allowPath(ruleset, root, name, access);
        }
    }
    // Pseudo-terminals, only if the form allows pty (only then does
    // cmd/init mount devpts).
    if (allow.has(.pty)) {
        try allowPath(ruleset, linux.AT.FDCWD, "/dev/ptmx", terminal);
        try allowPath(ruleset, linux.AT.FDCWD, "/dev/pts", terminal);
    }
    // Every terminal: the kernel's console (ttyS0, ttyAMA0 or hvc0), the
    // virtual consoles, and the rest.
    const dev: i32 = @intCast(try sys(
        linux.openat(linux.AT.FDCWD, "/dev", .{ .DIRECTORY = true, .CLOEXEC = true }, 0),
        "open /dev",
    ));
    defer _ = linux.close(dev);
    while (true) {
        const n = try sys(linux.getdents64(dev, &buf, buf.len), "read /dev");
        if (n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const ent: *align(1) const linux.dirent64 = @ptrCast(&buf[off]);
            off += ent.reclen;
            const name: [*:0]const u8 = @ptrCast(&ent.name);
            const s_name = std.mem.sliceTo(name, 0);
            if (ent.type != linux.DT.CHR) continue;
            if (!std.mem.startsWith(u8, s_name, "tty") and
                !std.mem.startsWith(u8, s_name, "hvc")) continue;
            try allowPath(ruleset, dev, name, terminal);
        }
    }
    // With CAP_SYS_ADMIN, no_new_privs is not needed, and setting it would
    // bind every process on the machine. Refusals are audited after exec
    // too, so a service reaching for a disk, a sysctl or an undeclared port
    // leaves a trace.
    try ruleset.restrict();
}

/// allowPath adds access to path, relative to dir, in ruleset. A missing
/// path is skipped, since a form may lack /data or /dev/ptmx.
fn allowPath(ruleset: sandbox.Ruleset, dir: i32, path: [*:0]const u8, access: u64) !void {
    const fd = linux.openat(dir, path, .{ .PATH = true, .CLOEXEC = true }, 0);
    if (linux.errno(fd) == .NOENT) return;
    const place: i32 = @intCast(try sys(fd, "open a place for Landlock"));
    defer _ = linux.close(place);
    try ruleset.add(place, access);
}

/// writable lets a process do what a directory's owner does with files,
/// directories and symlinks, including rename and link across directories.
const writable: u64 = sandbox.read_file | sandbox.write_file | sandbox.read_dir |
    sandbox.remove_dir | sandbox.remove_file | sandbox.make_dir | sandbox.make_reg |
    sandbox.make_sym | sandbox.refer | sandbox.truncate;
const device: u64 = sandbox.read_file | sandbox.write_file;
const terminal: u64 = device | sandbox.ioctl_dev;

/// files are the file rules every process gets. Landlock adds rights up the
/// path. / may only be listed here; restrict grants read on each entry of /
/// but /dev.
const files = [_]struct { path: [*:0]const u8, access: u64 }{
    .{ .path = "/", .access = sandbox.read_dir },
    .{ .path = "/usr", .access = sandbox.execute },
    // Image roots (docs/design/implemented/adhoc.md) are in the verified root like /usr,
    // so they may run too. Their writable binds are added in restrict.
    .{ .path = "/oci", .access = sandbox.execute },
    // runit's FIFOs and the services' sockets live in /run.
    .{ .path = "/run", .access = writable | sandbox.make_sock | sandbox.make_fifo },
    .{ .path = "/tmp", .access = writable },
    .{ .path = "/var/tmp", .access = writable },
    .{ .path = "/dev/shm", .access = writable },
    // apk may unpack device nodes here when building a slot; /data is nodev,
    // so they open nothing.
    .{ .path = "/data", .access = writable | sandbox.make_char | sandbox.make_block },
    .{ .path = "/dev/null", .access = device },
    .{ .path = "/dev/zero", .access = device },
    .{ .path = "/dev/full", .access = device },
    .{ .path = "/dev/random", .access = device },
    .{ .path = "/dev/urandom", .access = device },
    .{ .path = "/dev/kmsg", .access = device },
    .{ .path = "/dev/console", .access = terminal },
    // cmd/power-button finds the power button's input device by listing and
    // reads it, without ioctls.
    .{ .path = "/dev/input", .access = sandbox.read_file | sandbox.read_dir },
};

/// Binds iterates the writable places under each image root, from the
/// build's list (/usr/share/werewolf/oci): the root's /tmp and /run, which
/// may hold sockets, its /data, each `write` path, and writable shared
/// `data` paths on both sides of the bind. Shared directories may hold
/// local IPC sockets. Read-only shares get no write grant. Malformed lines
/// are skipped, as init skipped them, so nothing is mounted there.
const Binds = struct {
    text: []const u8,
    at: usize = 0,
    dir: []const u8 = "",
    name: []const u8 = "",
    source: ?[]const u8 = null,
    /// pending counts the current root's /tmp, /run and /data still to return.
    pending: u8 = 0,
    buf: [1024]u8 = undefined,

    const Bind = struct { path: [*:0]const u8, sockets: bool };

    fn next(b: *Binds) ?Bind {
        while (true) {
            if (b.source) |path| {
                b.source = null;
                return b.makeAt("", path, true) orelse continue;
            }
            if (b.pending > 0) {
                b.pending -= 1;
                return b.make(switch (b.pending) {
                    2 => "/tmp",
                    1 => "/run",
                    else => "/data",
                }, b.pending > 0);
            }
            if (b.at >= b.text.len) return null;
            const end = std.mem.findScalarPos(u8, b.text, b.at, '\n') orelse b.text.len;
            const line = b.text[b.at..end];
            b.at = end + 1;
            var words = std.mem.tokenizeScalar(u8, line, ' ');
            const key = words.next() orelse continue;
            if (std.mem.eql(u8, key, "root")) {
                b.name = words.next() orelse continue;
                b.dir = words.next() orelse continue;
                if (b.dir.len == 0 or b.dir[0] != '/') {
                    b.dir = "";
                    continue;
                }
                b.pending = 3;
            } else if (std.mem.eql(u8, key, "write") and b.dir.len > 0) {
                _ = words.next() orelse continue;
                const path = words.next() orelse continue;
                if (path.len == 0 or path[0] != '/') continue;
                return b.make(path, false) orelse continue;
            } else if (std.mem.eql(u8, key, "data") and b.dir.len > 0) {
                const name = words.next() orelse continue;
                const host = words.next() orelse continue;
                const image = words.next() orelse continue;
                const access = words.next() orelse continue;
                if (!std.mem.eql(u8, name, b.name) or words.next() != null or
                    !std.mem.eql(u8, access, "write") or !sharedSource(host) or
                    !cleanPath(image)) continue;
                const target = b.make(image, true) orelse continue;
                b.source = host;
                return target;
            }
        }
    }

    fn make(b: *Binds, path: []const u8, sockets: bool) ?Bind {
        return b.makeAt(b.dir, path, sockets);
    }

    fn makeAt(b: *Binds, prefix: []const u8, path: []const u8, sockets: bool) ?Bind {
        const s = std.mem.print(b.buf[0 .. b.buf.len - 1], "{s}{s}", .{ prefix, path }) catch
            return null;
        b.buf[s.len] = 0;
        return .{ .path = b.buf[0..s.len :0].ptr, .sockets = sockets };
    }
};

fn cleanPath(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/' or std.mem.findScalar(u8, path, 0) != null)
        return false;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| if (part.len == 0 or std.mem.eql(u8, part, ".") or
        std.mem.eql(u8, part, "..")) return false;
    return true;
}

fn sharedSource(path: []const u8) bool {
    const prefix = "/data/share/";
    if (!cleanPath(path) or !std.mem.startsWith(u8, path, prefix)) return false;
    const rest = path[prefix.len..];
    const slash = std.mem.findScalar(u8, rest, '/') orelse return false;
    return slash > 0 and slash + 1 < rest.len;
}

// --- files, errors, logging ----------------------------------------------------

/// readOptional returns the file at path, or "" if the build did not write it.
fn readOptional(path: [*:0]const u8, buf: []u8) ![]const u8 {
    const fd = linux.openat(linux.AT.FDCWD, path, .{ .CLOEXEC = true, .NOFOLLOW = true }, 0);
    if (linux.errno(fd) == .NOENT) return "";
    const f: i32 = @intCast(try sys(fd, "open a list"));
    defer _ = linux.close(f);
    var got: usize = 0;
    while (true) {
        if (got == buf.len) return error.PolicyTooLarge;
        const n = try sys(linux.read(f, buf[got..].ptr, buf.len - got), "read a list");
        if (n == 0) return buf[0..got];
        got += n;
    }
}

fn readPolicy(buf: []u8) ![]const u8 {
    const fd: i32 = @intCast(try sys(
        linux.openat(linux.AT.FDCWD, policy_path, .{ .CLOEXEC = true, .NOFOLLOW = true }, 0),
        "open " ++ policy_path,
    ));
    defer _ = linux.close(fd);
    var got: usize = 0;
    while (true) {
        if (got == buf.len) return error.PolicyTooLarge;
        const n = try sys(linux.read(fd, buf[got..].ptr, buf.len - got), "read " ++ policy_path);
        if (n == 0) return buf[0..got];
        got += n;
    }
}

const sys = sandbox.sys;

/// Log writes JSON lines on stdout: `fence: {"time":...,"event":...,...}`.
const Log = struct {
    buf: [4 << 10]u8 = undefined,

    fn event(l: *Log, name: []const u8, fields: anytype) void {
        var w: Io.Writer = .fixed(&l.buf);
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.REALTIME, &ts);
        var time: [20]u8 = undefined;
        w.print(
            "fence: {{\"time\":\"{s}\",\"event\":\"{s}\",",
            .{ rfc3339(&time, @intCast(@max(0, ts.sec))), name },
        ) catch return;
        const mark = w.end;
        std.json.Stringify.value(fields, .{}, &w) catch return;
        if (w.end <= mark) return;
        @memmove(l.buf[mark .. w.end - 1], l.buf[mark + 1 .. w.end]);
        w.end -= 1;
        w.writeByte('\n') catch return;
        _ = linux.write(1, w.buffered().ptr, w.buffered().len);
    }
};

fn rfc3339(buf: *[20]u8, secs: u64) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.mem.print(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,              md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

// --- tests -------------------------------------------------------------------

const example = "connect 0 tcp 443\nconnect 0 udp 53\nconnect all udp 53\nconnect 0 " ++
    "icmp\nlisten tcp 22\nlisten tcp 5432 loopback\nlisten 207 udp 53\nmetadata 68\n";

test "a program runs under its own name" {
    try std.testing.expectEqualStrings("runit", std.mem.span(baseName("/usr/bin/runit")));
    try std.testing.expectEqualStrings("runit", std.mem.span(baseName("runit")));
}

test "loopback-only TCP grants do not open an Internet port" {
    const p = try parsePolicy("connect 207 tcp 32402 loopback\n");
    const decide = struct {
        fn action(rules: []const Rule, uid: u32, destination: []const u8, port_number: u16) u8 {
            for (rules) |r| {
                if (r.proto != null and r.proto != .tcp) continue;
                if (r.uid) |u| if (uid < u or uid > (r.uid_last orelse u)) continue;
                if (r.dport != null and (port_number < r.dport.? or
                    port_number > (r.dport_last orelse r.dport.?))) continue;
                if (r.sport != null and r.sport.? != 40000) continue;
                if (r.src != null) continue;
                if (r.dst) |dst| if (!prefixMatches(
                    destination,
                    dst,
                    r.dst_len orelse @intCast(dst.len * 8),
                )) continue;
                // Model the local table for the addresses used below.
                if (r.table == RT_TABLE_LOCAL and !std.mem.eql(u8, destination, &loopback_ip) and
                    !std.mem.eql(u8, destination, &loopback6)) continue;
                return r.action;
            }
            return 0;
        }
    }.action;
    var rules: [max_rules]Rule = undefined;
    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |family| {
        const planned = plan(&p, family, &rules);
        const local: []const u8 = if (family == linux.AF.INET) &loopback_ip else &loopback6;
        const remote: []const u8 = if (family == linux.AF.INET)
            &.{ 1, 1, 1, 1 }
        else
            &v6(&.{ 0x26, 0x06, 0x47, 0 }, 1);
        try std.testing.expectEqual(FR_ACT_TO_TBL, decide(planned, 207, local, 32402));
        try std.testing.expectEqual(FR_ACT_PROHIBIT, decide(planned, 207, remote, 32402));
        try std.testing.expectEqual(FR_ACT_PROHIBIT, decide(planned, 208, remote, 32402));
        try std.testing.expectEqual(FR_ACT_PROHIBIT, decide(planned, 207, remote, 443));
    }
    for ([_][]const u8{
        "connect 207 udp 32402 loopback\n",
        "connect 207 tcp any loopback\n",
        "connect 207 tcp 443 public loopback\n",
    }) |bad| try std.testing.expectError(error.BadPolicy, parsePolicy(bad));
}

test "policies" {
    const p = try parsePolicy(example);
    try std.testing.expectEqualSlices(u16, &.{22}, p.listen[0..p.nlisten]);
    try std.testing.expectEqualSlices(u16, &.{5432}, p.loopback[0..p.nloopback]);
    try std.testing.expectEqualSlices(u32, &.{68}, p.metadata[0..p.nmetadata]);
    try std.testing.expectEqual(4, p.nconnect);
    try std.testing.expectEqual(null, p.connect[2].uid);
    try std.testing.expectEqual(.icmp, p.connect[3].proto);
    var out: [max_entries][]const u8 = undefined;
    var text: [max_entries * 32]u8 = undefined;
    const t = p.connectText(&out, &text);
    try std.testing.expectEqualStrings("0 tcp 443", t[0]);
    try std.testing.expectEqualStrings("all udp 53", t[2]);
    try std.testing.expectEqualStrings("0 icmp", t[3]);
    const pub_ = try parsePolicy("connect 207 tcp 443 public\nconnect 207 udp 53\n");
    try std.testing.expect(pub_.connect[0].public and !pub_.connect[1].public);
    const pt = pub_.connectText(&out, &text);
    try std.testing.expectEqualStrings("207 tcp 443 public", pt[0]);
    const names = try parsePolicy("dns 0\ndns 69\ndns 0\n");
    try std.testing.expectEqualSlices(
        dns.Uids,
        &.{ .one(0), .one(69) },
        names.dns.ids[0..names.dns.len],
    );
    const none = try parsePolicy("");
    try std.testing.expectEqual(0, none.nlisten + none.nconnect + none.nmetadata);
    for ([_][]const u8{
        "listen udp 53\n",
        "listen 207 udp\n",
        "listen 207 tcp 53\n",
        "listen 207 udp 53 loopback\n",
        "listen nobody udp 53\n",
        "listen tcp 0\n",
        "listen tcp 70000\n",
        "listen tcp 22 23\n",
        "listen tcp 22 loopback loopback\n",
        "listen tcp loopback\n",
        "listen tcp 22 public\n",
        "metadata _cloud\n",
        "dns all\n",
        "dns\n",
        "dns 0 tcp\n",
        "allow everything\n",
        "listen tcp\n",
        "connect 0 sctp 1\n",
        "connect 0 tcp\n",
        "connect 0 icmp 8\n",
        "connect nobody tcp 1\n",
        "connect 0 tcp 443 private\n",
        "connect 0 tcp 443 public public\n",
        "connect 0 icmp public\n",
        "connect all udp 5353 lan\n",
        "connect 0 tcp 5353 lan\n",
        "connect 0 udp 5353 public lan\n",
    }) |bad| {
        try std.testing.expectError(error.BadPolicy, parsePolicy(bad));
    }
}

test "LAN subnets exclude default routes, gateways and loopback" {
    var lan: Lan = .{};
    try lan.routes4(
        "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" ++
            "eth0 00000000 01014D0A 0003 0 0 0 00000000 0 0 0\n" ++
            "eth0 00014D0A 00000000 0001 0 0 0 00FFFFFF 0 0 0\n" ++
            "eth0 00000080 00000000 0001 0 0 0 00000080 0 0 0\n" ++
            "eth0 00000A0A 01014D0A 0003 0 0 0 0000FFFF 0 0 0\n" ++
            "lo 0000007F 00000000 0001 0 0 0 000000FF 0 0 0\n",
    );
    try lan.addresses6(
        "20010db8007700000000000000000001 02 40 00 80 eth0\n" ++
            "fe800000000000000000000000000001 02 40 20 80 eth0\n" ++
            "fe800000000000000000000000000002 02 0a 20 80 eth0\n" ++
            "20000000000000000000000000000001 02 03 00 80 eth0\n" ++
            "fd000000000000000000000000000002 02 20 00 80 eth0\n" ++
            "00000000000000000000000000000001 01 80 10 80 lo\n" ++
            "fd000000000000000000000000000001 02 40 00 40 eth0\n",
    );
    try std.testing.expectEqual(3, lan.len);
    try std.testing.expectEqualSlices(u8, &.{ 10, 77, 1, 0 }, lan.prefixes[0].addr);
    try std.testing.expectEqual(24, lan.prefixes[0].len);
    try std.testing.expectEqualSlices(
        u8,
        &v6(&.{ 0x20, 1, 0x0d, 0xb8, 0, 0x77 }, 0),
        lan.prefixes[1].addr,
    );
    try std.testing.expectEqual(64, lan.prefixes[1].len);
    for (0..max_lan + 8) |i| try lan.add(&.{ 10, 88, @intCast(i), 1 }, 24);
    try std.testing.expectEqual(max_lan, lan.len);
}

test "LAN discovery allows on-link peers and groups, refusing other addresses and users" {
    var p = try parsePolicy(
        "listen 207 udp 5353 lan\nconnect 207 udp 5353 lan\nconnect 207 udp 53\n",
    );
    var lan: Lan = .{};
    try lan.add(&.{ 10, 77, 0, 1 }, 24);
    try lan.add(&.{ 203, 0, 113, 1 }, 24); // a public-address LAN is still a LAN
    try lan.add(&v6(&.{ 0xfd, 0x77 }, 1), 64);
    try lan.add(&v6(&.{ 0xfe, 0x80 }, 1), 64);
    p.lan = lan.prefixes[0..lan.len];
    var rules: [max_rules]Rule = undefined;
    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |family| {
        const planned = plan(&p, family, &rules);
        const peer: []const u8 = if (family == linux.AF.INET)
            &.{ 10, 77, 0, 2 }
        else
            &v6(&.{ 0xfd, 0x77 }, 2);
        const off_link: []const u8 = if (family == linux.AF.INET)
            &.{ 10, 78, 0, 2 }
        else
            &v6(&.{ 0xfd, 0x78 }, 2);
        const internet: []const u8 = if (family == linux.AF.INET)
            &.{ 198, 51, 100, 2 }
        else
            &v6(&.{ 0x20, 1, 0x48, 0x60 }, 2);
        for ([_]u16{5353}) |port_number| {
            for ([_]u16{ 53, 5353, 1900, 40000 }) |source| {
                try std.testing.expectEqual(
                    FR_ACT_TO_TBL,
                    udpAction(planned, false, 207, peer, source, port_number),
                );
                for ([_][]const u8{ off_link, internet }) |remote|
                    try std.testing.expectEqual(
                        FR_ACT_BLACKHOLE,
                        udpAction(planned, false, 207, remote, source, port_number),
                    );
            }
            for ([_][]const u8{ peer, discoveryGroup(family, port_number).? }) |dest| {
                try std.testing.expectEqual(
                    FR_ACT_TO_TBL,
                    udpAction(planned, true, 207, dest, 40000, port_number),
                );
                try std.testing.expectEqual(
                    FR_ACT_PROHIBIT,
                    udpAction(planned, true, 208, dest, port_number, port_number),
                );
            }
            for ([_][]const u8{ off_link, internet }) |dest| {
                try std.testing.expectEqual(
                    FR_ACT_PROHIBIT,
                    udpAction(planned, true, 207, dest, 40000, port_number),
                );
                try std.testing.expectEqual(
                    FR_ACT_PROHIBIT,
                    udpAction(planned, true, 207, dest, port_number, 40000),
                );
            }
            try std.testing.expectEqual(
                FR_ACT_TO_TBL,
                udpAction(planned, false, 207, peer, port_number, 40000),
            );
            try std.testing.expectEqual(
                FR_ACT_BLACKHOLE,
                udpAction(planned, false, 207, internet, port_number, 40000),
            );
        }
        if (family == linux.AF.INET) try std.testing.expectEqual(
            FR_ACT_TO_TBL,
            udpAction(planned, false, 207, &.{ 203, 0, 113, 2 }, 5353, 5353),
        );
        // Without any detected subnets, incoming discovery fails closed.
        var offline = p;
        offline.lan = &.{};
        try std.testing.expectEqual(
            FR_ACT_BLACKHOLE,
            udpAction(plan(&offline, family, &rules), false, 207, peer, 5353, 5353),
        );
    }
    var encoded: [256]u8 = undefined;
    _ = ruleMessage(&encoded, 1, RTM_NEWRULE, .{
        .family = linux.AF.INET,
        .priority = 290,
        .action = FR_ACT_TO_TBL,
        .src = &.{ 10, 77, 0, 0 },
        .src_len = 24,
    });
    try std.testing.expectEqual(24, encoded[18]); // fib_rule_hdr.src_len
}

test "a TCP DNS listener accepts only connected subnets" {
    var p = try parsePolicy("listen tcp 53 loopback\nlisten tcp 53 lan\n");
    try std.testing.expect(p.needsLan());
    var lan: Lan = .{};
    try lan.add(&.{ 10, 77, 0, 1 }, 24);
    p.lan = lan.prefixes[0..lan.len];
    var rules: [max_rules]Rule = undefined;
    const planned = plan(&p, linux.AF.INET, &rules);
    var allow_lan = false;
    var deny_other = false;
    var reply_lan = false;
    var reply_wide = false;
    for (planned) |r| {
        if (r.priority == pref.out_allow and r.proto == .tcp and r.sport == 53 and
            r.action == FR_ACT_TO_TBL)
        {
            if (r.dst != null and prefixMatches(&.{ 10, 77, 0, 2 }, r.dst.?, r.dst_len.?))
                reply_lan = true
            else
                reply_wide = true;
        }
        if (r.priority != pref.in_private or r.proto != .tcp or r.dport != 53) continue;
        if (r.action == FR_ACT_TO_TBL and r.table == RT_TABLE_LOCAL and r.src != null and
            prefixMatches(&.{ 10, 77, 0, 2 }, r.src.?, r.src_len.?)) allow_lan = true;
        if (r.action == FR_ACT_BLACKHOLE and r.src == null) deny_other = true;
    }
    try std.testing.expect(allow_lan and deny_other and reply_lan and !reply_wide);
    try std.testing.expectError(error.BadPolicy, parsePolicy("listen tcp 53 lan extra\n"));
}

fn prefixMatches(address: []const u8, prefix: []const u8, bits: u8) bool {
    if (address.len != prefix.len) return false;
    for (address, prefix, 0..) |a, b, i| {
        const left = @min(8, bits -| (i * 8));
        const mask: u8 = if (left == 0) 0 else @as(u8, 255) << @intCast(8 - left);
        if (a & mask != b & mask) return false;
    }
    return true;
}

/// First matching UDP rule; outgoing local-table lookups miss this remote.
fn udpAction(
    rules: []const Rule,
    outgoing: bool,
    uid: u32,
    remote: []const u8,
    source: u16,
    destination: u16,
) u8 {
    for (rules) |r| {
        if (r.from_here and !outgoing) continue;
        if (outgoing and r.table == RT_TABLE_LOCAL) continue;
        if (r.proto != null and r.proto != .udp) continue;
        if (r.uid) |u| if (uid < u or uid > (r.uid_last orelse u)) continue;
        if (r.sport != null and r.sport != source) continue;
        if (r.dport) |first| if (destination < first or destination >
            (r.dport_last orelse first)) continue;
        if (if (outgoing) r.dst else r.src) |prefix| {
            const bits = (if (outgoing) r.dst_len else r.src_len) orelse
                @as(u8, @intCast(prefix.len * 8));
            if (!prefixMatches(remote, prefix, bits)) continue;
        }
        return r.action;
    }
    return 0;
}

test "the plan, in the order the kernel tries it" {
    var rules: [max_rules]Rule = undefined;
    const r = plan(&(try parsePolicy(example)), linux.AF.INET, &rules);
    var last: u32 = 0;
    for (r) |x| {
        try std.testing.expect(x.priority >= last); // ascending
        last = x.priority;
    }
    // Unwound's refusal and people's loopback isolation precede local traffic,
    // which is pinned to loopback and root. Drops precede the moved local rule.
    try std.testing.expectEqual(pref.label_refuse, r[0].priority);
    try std.testing.expectEqual(FR_ACT_PROHIBIT, r[0].action);
    try std.testing.expectEqual(pref.loopback_refuse, r[1].priority);
    try std.testing.expectEqual(pref.loopback_refuse, r[2].priority);
    try std.testing.expectEqual(pref.local_out, r[3].priority);
    try std.testing.expect(r[3].from_here and r[3].dst_len == 8);
    try std.testing.expectEqual(pref.local_out, r[4].priority);
    try std.testing.expect(r[4].from_here and r[4].uid == 0 and r[4].dst == null);
    try std.testing.expectEqual(FR_ACT_BLACKHOLE, r[r.len - 2].action);
    try std.testing.expectEqual(pref.local, r[r.len - 1].priority);

    // Arriving TCP and UDP are dropped. ARP's lookup, with no protocol or
    // port, first matches the local rule, so the machine still answers.
    var drops: usize = 0;
    for (r) |x| {
        if (x.priority == pref.in_drop and (x.proto == .tcp or x.proto == .udp)) drops += 1;
    }
    try std.testing.expectEqual(2, drops);
    const first = for (r) |x| {
        if (!x.from_here and x.proto == null and x.sport == null and x.dport == null and
            x.src == null and x.dst == null and x.uid == null) break x;
    } else unreachable;
    try std.testing.expectEqual(pref.local, first.priority);
    try std.testing.expectEqual(RT_TABLE_LOCAL, first.table);

    // Every rule for sent traffic is from lo; no rule for arriving traffic is.
    var refused_out = false;
    var dns_replies: usize = 0;
    for (r) |x| {
        if (x.priority < pref.in_allow and x.priority != pref.in_private)
            try std.testing.expect(x.from_here)
        else
            try std.testing.expect(!x.from_here);
        if (x.priority == pref.out_refuse and x.action == FR_ACT_PROHIBIT and x.uid == null and
            x.proto == null) refused_out = true;
        if (x.priority == pref.in_allow and x.proto == .udp and x.sport == 53) dns_replies += 1;
    }
    try std.testing.expect(refused_out);
    try std.testing.expectEqual(1, dns_replies); // two users connect to udp 53: one reply rule

    // A served UDP port: queries arrive for anyone, answers leave as its user.
    var udp_in = false;
    var udp_out = false;
    for (r) |x| {
        if (x.proto != .udp) continue;
        if (x.priority == pref.in_allow and x.dport == 53) udp_in = x.uid == null;
        if (x.priority == pref.out_allow and x.sport == 53 and x.action == FR_ACT_TO_TBL)
            udp_out = x.uid == 207;
    }
    try std.testing.expect(udp_in and udp_out);

    // Every rule that routes traffic out is followed by its unreachable twin.
    for (r, 0..) |x, i| {
        if (!(x.from_here and x.action == FR_ACT_TO_TBL and x.table == RT_TABLE_MAIN)) continue;
        const t = r[i + 1];
        try std.testing.expectEqual(FR_ACT_UNREACHABLE, t.action);
        try std.testing.expectEqual(x.priority, t.priority);
        try std.testing.expectEqual(x.uid, t.uid);
        try std.testing.expectEqual(x.dport, t.dport);
        try std.testing.expectEqual(x.proto, t.proto);
    }
}

test "the binds beneath image roots" {
    var b: Binds = .{
        .text = "root web /oci/web _oci-web\nwrite web /var/cache/web\nwrite web /srv\n" ++
            "nonsense here\nroot db /oci/db _oci-db\nwrite db relative\n",
    };
    const want = [_]struct { []const u8, bool }{
        .{ "/oci/web/tmp", true },
        .{ "/oci/web/run", true },
        .{ "/oci/web/data", false },
        .{ "/oci/web/var/cache/web", false },
        .{ "/oci/web/srv", false },
        .{ "/oci/db/tmp", true },
        .{ "/oci/db/run", true },
        .{ "/oci/db/data", false },
    };
    for (want) |w| {
        const got = b.next().?;
        try std.testing.expectEqualStrings(w[0], std.mem.span(got.path));
        try std.testing.expectEqual(w[1], got.sockets);
    }
    try std.testing.expectEqual(null, b.next());
    var none: Binds = .{ .text = "" };
    try std.testing.expectEqual(null, none.next());
}

test "shared writable binds allow IPC at both paths and read-only binds grant nothing" {
    var b: Binds = .{
        .text = "root app /oci/app _oci-app\n" ++
            "data app /data/share/unifi/bus /werewolf/bus write\n" ++
            "data app /data/share/unifi/files /files read\n" ++
            "data other /data/share/unifi/other /other write\n" ++
            "data app /etc/shadow /secret write\n" ++
            "data app /data/share/unifi/../private /escape write\n" ++
            "data app /data/share/unifi/files /../escape write\n" ++
            "data app /data/share/unifi/files /files write extra\n",
    };
    // The root's three private binds precede its declared shared bind.
    for (0..3) |_| _ = b.next().?;
    var item = b.next().?;
    try std.testing.expectEqualStrings("/oci/app/werewolf/bus", std.mem.span(item.path));
    try std.testing.expect(item.sockets);
    item = b.next().?;
    try std.testing.expectEqualStrings("/data/share/unifi/bus", std.mem.span(item.path));
    try std.testing.expect(item.sockets);
    try std.testing.expectEqual(null, b.next());
}

// The kernel refuses a port range that ends at 65535 with EINVAL, and
// fence, PID 1 then, dies on it.
test "every port range is one the kernel accepts" {
    var rules: [max_rules]Rule = undefined;
    const p = try parsePolicy(example ++ "connect 70 udp 7844\nconnect 71 tcp any\n");
    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |family| {
        for (plan(&p, family, &rules)) |r| {
            if (r.sport) |source| try std.testing.expect(source != 0 and source < 0xffff);
            if (r.dport) |first| {
                const last = r.dport_last orelse first;
                try std.testing.expect(first != 0 and first <= last and last < 0xffff);
            }
        }
    }
}

test "private ports drop arrivals before forged replies can admit them" {
    var rules: [max_rules]Rule = undefined;
    const p = try parsePolicy(
        example ++ "listen tcp 54000 loopback\nconnect 70 tcp 5432\nconnect 71 tcp any\n",
    );
    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |family| {
        const planned = plan(&p, family, &rules);
        for ([_]u16{ 443, 5432, 40000 }) |source| {
            for ([_]u16{ 5432, 54000 }) |destination|
                try std.testing.expectEqual(
                    FR_ACT_BLACKHOLE,
                    arrivingAction(planned, destination, source),
                );
            try std.testing.expectEqual(FR_ACT_TO_TBL, arrivingAction(planned, 22, source));
        }
        var private = false;
        for (planned) |r| {
            if (r.priority == pref.in_private and r.dport == 5432) {
                private = true;
                try std.testing.expect(!r.from_here and r.proto == .tcp);
                try std.testing.expect(r.priority > pref.local_out and r.priority < pref.in_allow);
            }
        }
        try std.testing.expect(private);
    }
}

/// First matching action for TCP arriving from an ordinary external address.
fn arrivingAction(rules: []const Rule, destination: u16, source: u16) u8 {
    for (rules) |r| {
        if (r.from_here or r.src != null or r.dst != null) continue;
        if (r.proto != null and r.proto != .tcp) continue;
        if (r.sport != null and r.sport != source) continue;
        if (r.dport) |first| {
            if (destination < first or destination > (r.dport_last orelse first)) continue;
        }
        return r.action;
    }
    return 0;
}

test "tunnels and IPsec arriving are dropped, like the transports" {
    var rules: [max_rules]Rule = undefined;
    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |family| {
        const r = plan(&(try parsePolicy(example)), family, &rules);
        for (dropped) |pr| {
            const found = for (r) |x| {
                if (x.priority == pref.in_drop and x.action == FR_ACT_BLACKHOLE and
                    x.proto == pr) break true;
            } else false;
            try std.testing.expect(found);
        }
    }
    // A policy cannot declare them.
    try std.testing.expectError(error.BadPolicy, parsePolicy("connect 0 gre 1\n"));
    try std.testing.expectError(error.BadPolicy, parsePolicy("connect all esp\n"));
}

test "an empty policy refuses everything but local traffic" {
    var rules: [max_rules]Rule = undefined;
    const r = plan(&.{}, linux.AF.INET, &rules);
    for (r) |x| {
        if (x.action != FR_ACT_TO_TBL) continue;
        // Only local traffic, ICMP in, and the moved local rule pass.
        try std.testing.expect(x.table == RT_TABLE_LOCAL);
        try std.testing.expect(x.from_here or x.proto == .icmp or x.priority == pref.local);
    }
}

test "IPv6: the same rules, its metadata address, and ICMPv6 sent by anyone" {
    var rules: [max_rules]Rule = undefined;
    const r = plan(&(try parsePolicy(example)), linux.AF.INET6, &rules);
    var icmp_out = false;
    var md_refused = false;
    for (r) |x| {
        try std.testing.expectEqual(linux.AF.INET6, x.family);
        if (x.priority == pref.out_allow and x.proto == .icmp and x.uid == null) icmp_out = true;
        if (x.priority == pref.metadata_refuse) md_refused = std.mem.eql(
            u8,
            x.dst.?,
            &metadata_ip6,
        );
    }
    try std.testing.expect(icmp_out and md_refused);
    var buf: [256]u8 = undefined;
    const m = ruleMessage(
        &buf,
        3,
        RTM_NEWRULE,
        .{
            .family = linux.AF.INET6,
            .priority = pref.metadata_refuse,
            .action = FR_ACT_PROHIBIT,
            .from_here = true,
            .dst = &metadata_ip6,
            .proto = .tcp,
            .dport = 80,
        },
    );
    try std.testing.expectEqualSlices(u8, &.{ linux.AF.INET6, 128 }, m[16..18]);
    try std.testing.expect(hasAttr(m, FRA_DST, &metadata_ip6));
    const icmp = ruleMessage(
        &buf,
        4,
        RTM_NEWRULE,
        .{
            .family = linux.AF.INET6,
            .priority = pref.in_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_LOCAL,
            .proto = .icmp,
        },
    );
    try std.testing.expect(hasAttr(icmp, FRA_IP_PROTO, &.{IPPROTO_ICMPV6}));
}

test "lookup users reach unwound from their own labels; DNS elsewhere is refused" {
    const p = try parsePolicy("lookup 1001 a.example A\nconnect 207 udp 53\n" ++
        "lookup 1002 * A unfiltered\nlookup 1001 b.example TXT\ndns 54\n");
    try std.testing.expectEqualSlices(
        dns.Uids,
        &.{ .one(1001), .one(1002) },
        p.lookups.ids[0..p.lookups.len],
    );
    var rules: [max_rules]Rule = undefined;
    const r = plan(&p, linux.AF.INET, &rules);
    // Own label, any forged loopback source, the kernel's pick, then no one.
    const want = [_]struct { u32, ?u32, ?[4]u8, u32, u8 }{
        .{ pref.label_own, 1001, .{ 127, 53, 0, 1 }, 0x5301, FR_ACT_TO_TBL },
        .{ pref.label_own, 1002, .{ 127, 53, 0, 2 }, 0x5302, FR_ACT_TO_TBL },
        .{ pref.label_forged, null, .{ 127, 0, 0, 0 }, 0, FR_ACT_PROHIBIT },
        .{ pref.label_pick, 1001, null, 0x5301, FR_ACT_TO_TBL },
        .{ pref.label_pick, 1002, null, 0x5302, FR_ACT_TO_TBL },
        .{ pref.label_refuse, null, null, 0, FR_ACT_PROHIBIT },
    };
    for (want, r[0..want.len]) |w, x| {
        try std.testing.expectEqual(w[0], x.priority);
        try std.testing.expectEqual(w[1], x.uid);
        try std.testing.expectEqual(w[3], x.table);
        try std.testing.expectEqual(w[4], x.action);
        try std.testing.expectEqualSlices(u8, &dns.resolver, x.dst.?);
        try std.testing.expect(x.from_here);
        if (w[2]) |src|
            try std.testing.expectEqualSlices(u8, &src, x.src.?)
        else
            try std.testing.expectEqual(null, x.src);
    }
    try std.testing.expectEqual(8, r[2].src_len.?);
    // A connect to UDP 53 or 853 is refused anyway: DNS goes through unwound.
    try std.testing.expectEqual(
        FR_ACT_PROHIBIT,
        udpAction(r, true, 207, &.{ 8, 8, 8, 8 }, 40000, 53),
    );
    try std.testing.expectEqual(
        FR_ACT_PROHIBIT,
        udpAction(r, true, 207, &.{ 8, 8, 8, 8 }, 40000, 853),
    );
    // IPv6 has no labels, and refuses DNS too.
    const r6 = plan(&p, linux.AF.INET6, &rules);
    for (r6) |x| try std.testing.expect(x.priority > pref.label_refuse);
    var refusals: usize = 0;
    for (r6) |x| if (x.priority == pref.dns_refuse) {
        refusals += 1;
    };
    try std.testing.expectEqual(4, refusals);
    try std.testing.expectError(error.BadPolicy, parsePolicy("lookup 1001\n"));
    try std.testing.expectError(error.BadPolicy, parsePolicy("lookup x a.example A\n"));
}

test "a range of uids, as :people, connects and looks up as one user" {
    const p = try parsePolicy("connect 500-60000 tcp 443\nconnect 0 tcp 443\n" ++
        "lookup 500-60000 * A unfiltered\nlookup 0 * A\n");
    var out: [max_entries][]const u8 = undefined;
    var text: [max_entries * 32]u8 = undefined;
    try std.testing.expectEqualStrings("500-60000 tcp 443", p.connectText(&out, &text)[0]);
    try std.testing.expectEqualStrings("0 tcp 443", p.connectText(&out, &text)[1]);
    var rules: [max_rules]Rule = undefined;
    var labelled: usize = 0;
    var allowed = false;
    var buf: [256]u8 = undefined;
    for (plan(&p, linux.AF.INET, &rules)) |r| {
        if (r.uid != 500) continue;
        try std.testing.expectEqual(60000, r.uid_last.?);
        try std.testing.expect(hasAttr(
            ruleMessage(&buf, 1, RTM_NEWRULE, r),
            FRA_UID_RANGE,
            std.mem.sliceAsBytes(&[2]u32{ 500, 60000 }),
        ));
        if (r.priority == pref.label_own or r.priority == pref.label_pick) labelled += 1;
        if (r.priority == pref.out_allow and r.dport == 443) allowed = true;
    }
    try std.testing.expectEqual(2, labelled);
    try std.testing.expect(allowed);
    for ([_][]const u8{
        "connect 500-60000 tcp any\n",
        "connect 60000-500 tcp 443\n",
        "connect 500- tcp 443\n",
        "lookup 500-60000 * A\nlookup 600 a.example A\n",
        "dns 500-60000\n",
        "metadata 500-60000\n",
    }) |bad| try std.testing.expectError(error.BadPolicy, parsePolicy(bad));
}

test "a DNS service reaches only its declared direct upstream ports" {
    const p = try parsePolicy("lookup 207 * A AAAA\ndns-direct 207\n" ++
        "connect 207 udp 53\nconnect 207 tcp 853 public\nconnect 208 udp 53\n");
    var rules: [max_rules]Rule = undefined;
    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |family| {
        const planned = plan(&p, family, &rules);
        var grants: usize = 0;
        for (planned) |r| if (r.priority == pref.dns_direct_allow and r.action == FR_ACT_TO_TBL) {
            grants += 1;
            try std.testing.expectEqual(207, r.uid.?);
            try std.testing.expect((r.proto == .udp and r.dport == 53) or
                (r.proto == .tcp and r.dport == 853));
        };
        try std.testing.expectEqual(2, grants);
        try std.testing.expectEqual(
            FR_ACT_TO_TBL,
            udpAction(planned, true, 207, &.{ 8, 8, 8, 8 }, 40000, 53),
        );
        try std.testing.expectEqual(
            FR_ACT_PROHIBIT,
            udpAction(planned, true, 208, &.{ 8, 8, 8, 8 }, 40000, 53),
        );
        try std.testing.expectEqual(
            FR_ACT_PROHIBIT,
            udpAction(planned, true, 207, &.{ 8, 8, 8, 8 }, 40000, 853),
        );
    }
    try std.testing.expectError(error.BadPolicy, parsePolicy("dns-direct\n"));
    try std.testing.expectError(error.BadPolicy, parsePolicy("dns-direct 207 extra\n"));
}

test "a local validator refuses loopback DNS except unwound upstream" {
    var p = try parsePolicy("dns 54\nlookup 2001 * A AAAA\nlisten tcp 53 loopback\n");
    p.local_validator = true;
    var rules: [max_rules]Rule = undefined;
    const planned = plan(&p, linux.AF.INET, &rules);
    for ([_]Proto{ .udp, .tcp }) |proto| {
        var found = false;
        for (planned) |r| if (r.priority == pref.local_validator_refuse and r.proto == proto and
            r.dport == 53 and r.action == FR_ACT_PROHIBIT)
        {
            found = true;
        };
        try std.testing.expect(found);
    }
}

test "a direct LAN DNS grant stays on connected subnets" {
    var p = try parsePolicy("dns-direct 207\nconnect 207 udp 53 lan\n");
    var lan: Lan = .{};
    try lan.add(&.{ 10, 77, 0, 1 }, 24);
    p.lan = lan.prefixes[0..lan.len];
    var rules: [max_rules]Rule = undefined;
    const planned = plan(&p, linux.AF.INET, &rules);
    for (planned) |r| {
        if (r.priority != pref.dns_direct_allow) continue;
        try std.testing.expect(r.dst != null);
        try std.testing.expect(prefixMatches(&.{ 10, 77, 0, 2 }, r.dst.?, r.dst_len.?));
    }
    try std.testing.expectEqual(
        FR_ACT_PROHIBIT,
        udpAction(planned, true, 207, &.{ 8, 8, 8, 8 }, 40000, 53),
    );
}

test "public: refused to every non-public prefix, first, on its port alone" {
    var p = try parsePolicy("connect 207 tcp 443 public\nconnect 207 udp 53\n");
    try std.testing.expect(p.needsLan());
    var lan: Lan = .{};
    try lan.add(&.{ 10, 77, 0, 1 }, 24);
    try lan.add(&.{ 203, 0, 113, 1 }, 24);
    try lan.add(&v6(&.{ 0x20, 1, 0x48, 0x60 }, 1), 64);
    p.lan = lan.prefixes[0..lan.len];
    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |fam| {
        var rules: [max_rules]Rule = undefined;
        const r = plan(&p, fam, &rules);
        const want: usize = (if (fam == linux.AF.INET6) non_public6.len else non_public4.len) + 1;
        var refusals: usize = 0;
        for (r, 0..) |x, i| {
            if (x.priority != pref.public_refuse) continue;
            refusals += 1;
            // These come before every other rule, local traffic's included,
            // but for unwound's: no one reaches 127.0.0.53 unlabeled.
            for (r[0..i]) |y| try std.testing.expect(y.priority == pref.public_refuse or
                (y.priority == pref.label_refuse and y.dst.?[3] == 53));
            try std.testing.expectEqual(FR_ACT_PROHIBIT, x.action);
            try std.testing.expectEqual(.tcp, x.proto.?);
            try std.testing.expectEqual(443, x.dport.?);
            try std.testing.expectEqual(207, x.uid.?);
        }
        try std.testing.expectEqual(want, refusals);
    }
    // The metadata server's prefix is among them, encoded as a prefix.
    var buf: [256]u8 = undefined;
    const m = ruleMessage(&buf, 1, RTM_NEWRULE, .{
        .priority = pref.public_refuse,
        .action = FR_ACT_PROHIBIT,
        .from_here = true,
        .dst = non_public4[4].addr,
        .dst_len = non_public4[4].len,
        .proto = .tcp,
        .dport = 443,
        .uid = 207,
    });
    try std.testing.expectEqual(16, m[17]); // fib_rule_hdr.dst_len
    try std.testing.expect(hasAttr(m, FRA_DST, &.{ 169, 254, 0, 0 }));
}

test "Azure's wire server is refused on its two ports, to everyone, IPv4 alone" {
    const p = try parsePolicy("connect 207 tcp 80 public\nmetadata 207\n");
    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |fam| {
        var rules: [max_rules]Rule = undefined;
        var refusals: usize = 0;
        for (plan(&p, fam, &rules)) |x| {
            const dst = x.dst orelse continue;
            if (!std.mem.eql(u8, dst, &wire_server_ip)) continue;
            refusals += 1;
            try std.testing.expectEqual(pref.metadata_refuse, x.priority);
            try std.testing.expectEqual(FR_ACT_PROHIBIT, x.action);
            try std.testing.expectEqual(.tcp, x.proto.?);
            try std.testing.expect(x.dport.? == 80 or x.dport.? == 32526);
            try std.testing.expectEqual(null, x.uid);
        }
        try std.testing.expectEqual(
            if (fam == linux.AF.INET) wire_server_ports.len else 0,
            refusals,
        );
    }
}

test "a full policy fits its rules" {
    var p: Policy = .{};
    var lan: Lan = .{};
    inline for (0..max_lan) |i|
        try lan.add(&v6(&.{ 0x20, 1, 0x48, 0x60, 0, @intCast(i) }, 1), 64);
    p.lan = lan.prefixes[0..lan.len];
    for (0..max_entries) |i| {
        p.listen[i] = @intCast(1000 + i);
        p.listen_lan[i] = @intCast(4000 + i);
        p.udp[i] = .{ .port = @intCast(5000 + i), .uid = @intCast(i), .lan = true };
        p.connect[i] = .{
            .uid = @intCast(i),
            .proto = .udp,
            .port = @intCast(2000 + i),
            .public = true,
        };
        p.metadata[i] = @intCast(i);
        p.loopback[i] = @intCast(3000 + i);
    }
    p.nloopback = max_entries;
    p.nlisten = max_entries;
    p.nlisten_lan = max_entries;
    p.nudp = max_entries;
    p.nconnect = max_entries;
    p.nmetadata = max_entries;
    var rules: [max_rules]Rule = undefined;
    _ = plan(&p, linux.AF.INET6, &rules);
}

test "local NIC addresses and undeclared loopback ports are refused to non-root and people" {
    const p = try parsePolicy(
        \\connect 70 tcp any
        \\connect 70 tcp 6379
        \\connect 500-60000 tcp 22
        \\connect 207 tcp 32402 loopback
        \\listen tcp 5432 loopback
    );
    const decide = struct {
        fn action(rules: []const Rule, uid: u32, destination: []const u8, port_number: u16) Rule {
            for (rules) |r| {
                if (!r.from_here) continue;
                if (r.proto != null and r.proto != .tcp) continue;
                if (r.uid) |u| if (uid < u or uid > (r.uid_last orelse u)) continue;
                if (r.dport != null and (port_number < r.dport.? or
                    port_number > (r.dport_last orelse r.dport.?))) continue;
                if (r.sport != null and r.sport.? != 40000) continue;
                if (r.src != null) continue;
                if (r.dst) |dst| if (!prefixMatches(
                    destination,
                    dst,
                    r.dst_len orelse @intCast(dst.len * 8),
                )) continue;
                return r;
            }
            return .{ .priority = 0, .action = 0 };
        }
    }.action;
    var rules: [max_rules]Rule = undefined;
    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |fam| {
        const planned = plan(&p, fam, &rules);
        var last: u32 = 0;
        for (planned) |x| {
            try std.testing.expect(x.priority >= last);
            last = x.priority;
        }
        const lo: []const u8 = if (fam == linux.AF.INET) &loopback_ip else &loopback6;
        const nic: []const u8 = if (fam == linux.AF.INET)
            &.{ 10, 0, 2, 15 }
        else
            &v6(&.{ 0xfd, 0 }, 15);
        // Root reaches both loopback and assigned NIC addresses via RT_TABLE_LOCAL;
        // non-root services reach loopback unless isolated, never the NIC address.
        try std.testing.expectEqual(RT_TABLE_LOCAL, decide(planned, 0, nic, 5432).table);
        try std.testing.expectEqual(FR_ACT_PROHIBIT, decide(planned, 208, nic, 5432).action);
        try std.testing.expectEqual(RT_TABLE_LOCAL, decide(planned, 208, lo, 5432).table);
        // Interactive people reach declared TCP ports on loopback, never
        // internal loopback services or undeclared ports on the NIC address.
        try std.testing.expectEqual(RT_TABLE_LOCAL, decide(planned, 1000, lo, 22).table);
        try std.testing.expectEqual(FR_ACT_PROHIBIT, decide(planned, 1000, lo, 5432).action);
        try std.testing.expectEqual(FR_ACT_PROHIBIT, decide(planned, 70000, lo, 5432).action);
        try std.testing.expectEqual(FR_ACT_PROHIBIT, decide(planned, 1000, nic, 5432).action);
        try std.testing.expectEqual(RT_TABLE_MAIN, decide(planned, 1000, nic, 22).table);
        try std.testing.expectEqual(FR_ACT_PROHIBIT, decide(planned, 207, nic, 32402).action);
    }
}

test "a scan reaches every port and not this machine's services" {
    const p = try parsePolicy(
        \\connect 70 tcp any
        \\connect 70 tcp 6379
        \\connect 71 tcp 5432
        \\listen tcp 80
        \\listen tcp 9392 loopback
    );
    try std.testing.expectError(error.BadPolicy, parsePolicy("connect all tcp any\n"));
    try std.testing.expectError(error.BadPolicy, parsePolicy("connect 70 tcp any public\n"));
    try std.testing.expectError(error.BadPolicy, parsePolicy("connect 70 udp any\n"));
    for ([_]u8{ linux.AF.INET, linux.AF.INET6 }) |fam| {
        var rules: [max_rules]Rule = undefined;
        const got = plan(&p, fam, &rules);
        var redis = false;
        var prohibited = false;
        var wide_out = false;
        var replies = false;
        var sport_zero = false;
        var other_user = false;
        var opened_service = false;
        var scanner_pg = false;
        const want_len: u8 = if (fam == linux.AF.INET6) 128 else 8;
        for (got) |x| {
            if (x.sport == 0) sport_zero = true;
            if (x.uid == 70 and x.priority == pref.loopback_allow and x.dport == 6379 and
                x.action == FR_ACT_TO_TBL)
                redis = true;
            if (x.uid == 70 and x.priority == pref.loopback_refuse and
                x.action == FR_ACT_PROHIBIT and x.dst_len == want_len)
                prohibited = true;
            if (x.uid == 70 and x.priority == pref.out_allow and x.dport == null and
                x.proto == .tcp)
                wide_out = true;
            if (x.priority == pref.in_allow and x.dport == ephemeral_lo and
                x.dport_last == ephemeral_hi)
                replies = true;
            // Another user's loopback is not prohibited, and a service port
            // is not opened by the reply range.
            if (x.uid == 71 and x.priority == pref.loopback_refuse) other_user = true;
            if (x.dport == 80 and x.priority == pref.in_allow and x.dport_last != null)
                opened_service = true;
            if (x.uid == 70 and x.dport == 5432) scanner_pg = true;
        }
        try std.testing.expect(redis and prohibited and wide_out and replies);
        try std.testing.expect(!sport_zero and !other_user and !opened_service and !scanner_pg);
    }
}

test "rule messages" {
    var buf: [256]u8 = undefined;
    const m = ruleMessage(
        &buf,
        7,
        RTM_NEWRULE,
        .{
            .priority = pref.metadata_allow,
            .action = FR_ACT_TO_TBL,
            .table = RT_TABLE_MAIN,
            .from_here = true,
            .dst = &metadata_ip,
            .proto = .tcp,
            .dport = 80,
            .uid = 68,
        },
    );
    try std.testing.expectEqual(m.len, std.mem.readInt(u32, m[0..4], .little));
    try std.testing.expectEqual(RTM_NEWRULE, std.mem.readInt(u16, m[4..6], .little));
    try std.testing.expectEqual(7, std.mem.readInt(u32, m[8..12], .little));
    // fib_rule_hdr: IPv4, a /32 destination, the main table, FR_ACT_TO_TBL.
    try std.testing.expectEqualSlices(
        u8,
        &.{ linux.AF.INET, 32, 0, 0, RT_TABLE_MAIN, 0, 0, FR_ACT_TO_TBL },
        m[16..24],
    );
    try std.testing.expect(hasAttr(m, FRA_IIFNAME, "lo\x00"));
    try std.testing.expect(hasAttr(m, FRA_DST, &metadata_ip));
    try std.testing.expect(hasAttr(m, FRA_IP_PROTO, &.{6}));
    try std.testing.expect(hasAttr(m, FRA_DPORT_RANGE, std.mem.sliceAsBytes(&[2]u16{ 80, 80 })));
    try std.testing.expect(hasAttr(m, FRA_UID_RANGE, std.mem.sliceAsBytes(&[2]u32{ 68, 68 })));

    const drop = ruleMessage(
        &buf,
        8,
        RTM_NEWRULE,
        .{ .priority = pref.in_drop, .action = FR_ACT_BLACKHOLE, .proto = .sctp },
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ linux.AF.INET, 0, 0, 0, 0, 0, 0, FR_ACT_BLACKHOLE },
        drop[16..24],
    );
    try std.testing.expect(!hasAttr(drop, FRA_IIFNAME, "lo\x00"));
    try std.testing.expect(hasAttr(drop, FRA_IP_PROTO, &.{132}));

    const del = ruleMessage(
        &buf,
        9,
        RTM_DELRULE,
        .{ .priority = 0, .action = FR_ACT_TO_TBL, .table = RT_TABLE_LOCAL },
    );
    try std.testing.expectEqual(RTM_DELRULE, std.mem.readInt(u16, del[4..6], .little));
    try std.testing.expect(hasAttr(del, FRA_PRIORITY, std.mem.asBytes(&@as(u32, 0))));
}

/// hasAttr reports whether netlink message m carries attribute kind with value v.
fn hasAttr(m: []const u8, kind: u16, v: []const u8) bool {
    var off: usize = 16 + 12;
    while (off + 4 <= m.len) {
        const len = std.mem.readInt(u16, m[off..][0..2], .little);
        if (len < 4 or off + len > m.len) return false;
        if (std.mem.readInt(u16, m[off + 2 ..][0..2], .little) == kind and
            std.mem.eql(u8, m[off + 4 .. off + len], v)) return true;
        off += std.mem.alignForward(usize, len, 4);
    }
    return false;
}

test "acknowledgements" {
    var ok: [36]u8 = @splat(0);
    std.mem.writeInt(u16, ok[4..6], NLMSG_ERROR, .little);
    std.mem.writeInt(u32, ok[8..12], 3, .little);
    try std.testing.expectEqual(0, ackError(&ok, 3).?);
    try std.testing.expectEqual(null, ackError(&ok, 4));
    std.mem.writeInt(i32, ok[16..20], -17, .little); // EEXIST
    try std.testing.expectEqual(-17, ackError(&ok, 3).?);
    try std.testing.expectEqual(null, ackError(ok[0..19], 3));
}
