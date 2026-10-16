//! network holds posture's network checks: listening ports, fence's rules,
//! IPv6, and sshd's settings.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const testing = std.testing;

const posture = @import("posture.zig");
const Posture = posture.Posture;
const exists = posture.exists;
const listAdd = posture.listAdd;
const statx = posture.statx;
const trim = posture.trim;

pub fn check(p: *Posture) !void {
    // IPv6 is on unless disable_ipv6 reads 1 or the kernel has no IPv6.
    const v6 = p.sysctl("net/ipv6/conf/all/disable_ipv6");
    const v6_on = v6.len > 0 and !std.mem.eql(u8, v6, "1");
    if (p.werewolf) try imageNetwork(p, v6_on) else try fence(p, "", v6_on);
    const init_status = p.read("/proc/1/status");
    const bypass = fenceBypass(init_status);
    try p.add(.{
        .id = if (p.werewolf) "network-fence-unbypassable" else "network-capabilities-restricted",
        .area = "network",
        .name = "Network capabilities restricted",
        .why = "CAP_NET_ADMIN can replace routing policy, and CAP_NET_RAW can send " ++
            "traffic beneath it with raw or packet sockets.",
        .how = "PID 1's capability bounding set lacks CAP_NET_ADMIN and CAP_NET_RAW, so every " ++
            "descendant lacks them too",
        .observed = posture.statusField(init_status, "CapBnd") orelse "CapBnd unavailable",
        .result = if (bypass) |can| (if (can) .fail else .pass) else .skip,
        .detail = if (bypass == null)
            "cannot read PID 1's capability bounding set"
        else if (bypass.?)
            "CAP_NET_ADMIN or CAP_NET_RAW remains in the bounding set"
        else
            "",
    });
    try p.absent(
        "network-no-login",
        "network",
        "No remote login",
        "There is no ssh or telnet server to log in through.",
        &.{ "sshd", "dropbear", "telnetd", "in.telnetd" },
    );
    try ssh(p);
    // With IPv6 off, there is no IPv6 forwarding to check.
    const forwarding = [_][2][]const u8{
        .{ "net/ipv4/ip_forward", "0" },
        .{ "net/ipv6/conf/all/forwarding", "0" },
    };
    try p.sysctls(
        "network-no-forwarding",
        "network",
        "No routing",
        "The machine forwards no traffic for others.",
        if (v6_on) &forwarding else forwarding[0..1],
    );
    // IPv4 uses redirects on an interface if either all or the interface
    // allows them, and all and default do not reach interfaces that already
    // existed, so every interface must say no. IPv6 has only the interface's
    // setting, which means nothing with IPv6 off.
    const redirects = [_][2][]const u8{
        .{ "net/ipv4/conf/*/accept_redirects", "0" },
        .{ "net/ipv4/conf/*/secure_redirects", "0" },
        .{ "net/ipv4/conf/*/send_redirects", "0" },
        .{ "net/ipv6/conf/*/accept_redirects", "0" },
    };
    try p.sysctls(
        "network-redirects",
        "network",
        "ICMP redirects ignored",
        "Nobody on the network can reroute the machine's traffic, and it reroutes nobody's.",
        if (v6_on) &redirects else redirects[0..3],
    );
    // IPv4 accepts a source route only if all and the interface both allow it.
    const source_route = [_][2][]const u8{
        .{ "net/ipv4/conf/all/accept_source_route", "0" },
        .{ "net/ipv6/conf/*/accept_source_route", "0" },
    };
    try p.sysctls(
        "network-source-route",
        "network",
        "Source routing refused",
        "Packets cannot choose their own way through the machine.",
        if (v6_on) &source_route else source_route[0..1],
    );
    // Loopback addresses are routed through an interface if either all or
    // the interface allows it, so every interface must say no.
    try p.sysctls(
        "network-localnet",
        "network",
        "Loopback stays local",
        "Nothing on the network can reach what listens on 127.0.0.1 alone, by routing " ++
            "a packet for it through an interface.",
        &.{.{ "net/ipv4/conf/*/route_localnet", "0" }},
    );
    // IPv6 takes its route from router advertisements, so they stay on,
    // limited to what they must provide.
    if (v6_on) try p.sysctls(
        "network-ipv6-ra-limits",
        "network",
        "Router advertisements limited",
        "A rogue router on the same network cannot rank itself above the real one, add a " ++
            "route to steal one destination's traffic, or flood the machine with addresses.",
        &.{
            .{ "net/ipv6/conf/*/accept_ra_rtr_pref", "0" },
            .{ "net/ipv6/conf/*/accept_ra_rt_info_max_plen", "0" },
            .{ "net/ipv6/conf/*/max_addresses", "4" },
        },
    );
    try p.sysctls(
        "network-martians",
        "network",
        "Impossible packets logged",
        "Packets from addresses that cannot be, a sign of spoofing, are logged.",
        &.{.{ "net/ipv4/conf/all/log_martians", "1" }},
    );
    // werewolf fails these by choice (docs/security.md, "Not done, by
    // choice"), so only --extended checks them: strict reverse-path filtering
    // is not yet shown to work with fence. Router advertisements pass where
    // the kernel has no IPv6, as werewolf's does not.
    if (p.extended) {
        // The kernel uses the stricter of all and the interface for both.
        try p.sysctls(
            "network-rp-filter",
            "network",
            "Spoofed sources dropped",
            "A packet claiming an address the machine would not reply to by that way is " ++
                "dropped.",
            &.{.{ "net/ipv4/conf/all/rp_filter", "1" }},
        );
        if (v6_on) {
            try p.sysctls(
                "network-ipv6-ra",
                "network",
                "Router advertisements ignored",
                "Nobody on the network can give the machine an IPv6 address or route by " ++
                    "advertising one.",
                &.{
                    .{ "net/ipv6/conf/*/accept_ra", "0" },
                    .{ "net/ipv6/conf/*/autoconf", "0" },
                },
            );
        } else try p.add(.{
            .id = "network-ipv6-ra",
            .area = "network",
            .name = "Router advertisements ignored",
            .why = "Nobody on the network can give the machine an IPv6 address or route by " ++
                "advertising one.",
            .how = "IPv6 is off, or net.ipv6.conf.*.accept_ra and autoconf are 0",
            .result = .pass,
            .detail = "IPv6 off",
        });
    }
    try p.sysctls(
        "network-syncookies",
        "network",
        "SYN flood protection",
        "A flood of half-open connections cannot exhaust it.",
        &.{.{ "net/ipv4/tcp_syncookies", "1" }},
    );
    try p.sysctls(
        "network-stray-packets",
        "network",
        "Stray packets ignored",
        "Pings to a broadcast address and bogus ICMP errors get no answer, and a forged " ++
            "reset cannot cut short a closing connection.",
        &.{
            .{ "net/ipv4/icmp_echo_ignore_broadcasts", "1" },
            .{ "net/ipv4/icmp_ignore_bogus_error_responses", "1" },
            .{ "net/ipv4/tcp_rfc1337", "1" },
        },
    );
}

fn imageNetwork(p: *Posture, v6_on: bool) !void {
    var ports: std.ArrayList(u16) = .empty;
    for ([_][]const u8{
        "/proc/net/tcp",
        "/proc/net/tcp6",
    }) |f| try listenPorts(p.gpa, p.read(f), &ports);
    var list: std.ArrayList(u8) = .empty;
    for (ports.items) |port| try listAdd(p.gpa, &list, "{d}", .{port});
    // Read fence's network policy, or else the older list of ports.
    const policy: ?[]const u8 = Dir.cwd().readFileAlloc(
        p.io,
        "/usr/share/werewolf/net",
        p.gpa,
        .limited(64 << 10),
    ) catch null;
    const declared: ?[]const u8 = if (policy) |net|
        try policyPorts(p.gpa, net)
    else
        Dir.cwd().readFileAlloc(p.io, "/etc/werewolf/listen", p.gpa, .limited(64 << 10)) catch
            null;
    var undeclared: std.ArrayList(u8) = .empty;
    if (declared) |text| for (ports.items) |port| {
        if (!isDeclared(text, port)) try listAdd(p.gpa, &undeclared, "{d}", .{port});
    };
    try p.add(.{
        .id = "network-ports",
        .area = "network",
        .name = "Only declared ports open",
        .why = "Nothing listens on the network that the machine is not meant to offer.",
        .how = "listening TCP ports (/proc/net/tcp, tcp6), but those bound to loopback alone, " ++
            "which the network never reaches, are those the machine's policy " ++
            "declares (/usr/share/werewolf/net)",
        .expected = if (declared) |ports_text|
            try p.gpa.print(
                "non-loopback listeners are a subset of declared ports: {s}",
                .{trim(ports_text)},
            )
        else
            "network policy required to compare listeners",
        .observed = try p.gpa.print(
            "non-loopback listening ports: {s}",
            .{if (list.items.len > 0) list.items else "none"},
        ),
        .result = if (declared == null)
            .skip
        else if (undeclared.items.len == 0)
            .pass
        else
            .fail,
        .detail = if (undeclared.items.len > 0)
            try p.gpa.print("undeclared: {s}", .{undeclared.items})
        else
            try p.gpa.print(
                "listening: {s}",
                .{if (list.items.len > 0) list.items else "none"},
            ),
    });
    try fence(p, policy orelse "", v6_on);
}

/// rootEgress measures root's DNS and HTTPS permissions without waiting for a
/// server. UDP connect sends nothing; TCP is nonblocking and closes at once.
/// Unknown routing failures are skipped, never treated as proof of restriction.
pub fn rootEgress(p: *Posture, resolv: []const u8, v6_on: bool) !void {
    const assigned = configuredResolvers(resolv);
    var dns_assigned: EgressEvidence = .{ .unknown = assigned.incomplete };
    var dns_other: EgressEvidence = .{};
    var https: EgressEvidence = .{};
    if (p.root) {
        for (assigned.targets[0..assigned.len]) |target| {
            try dns_assigned.probe(p.gpa, target.address, .udp);
            try dns_assigned.probe(p.gpa, target.address, .tcp);
        }
        // TEST-NET addresses need no responding public service. Exclude any
        // configured resolver, so an assigned-only grant cannot fail this check.
        for ([_][]const u8{ "192.0.2.1", "198.51.100.1", "203.0.113.1" }) |ip| {
            const address = std.Io.net.IpAddress.parse(ip, 53) catch unreachable;
            if (assigned.contains(address)) continue;
            try dns_other.probe(p.gpa, address, .udp);
            try dns_other.probe(p.gpa, address, .tcp);
        }
        for ([_][]const u8{ "192.0.2.1", "198.51.100.1", "203.0.113.1" }) |ip|
            try https.probe(p.gpa, std.Io.net.IpAddress.parse(ip, 443) catch unreachable, .tcp);
        if (v6_on) {
            const dns6 = std.Io.net.IpAddress.parse("2001:db8::1", 53) catch unreachable;
            if (!assigned.contains(dns6)) {
                try dns_other.probe(p.gpa, dns6, .udp);
                try dns_other.probe(p.gpa, dns6, .tcp);
            }
            try https.probe(
                p.gpa,
                std.Io.net.IpAddress.parse("2001:db8::1", 443) catch unreachable,
                .tcp,
            );
        }
    }
    for ([_]struct { id: []const u8, name: []const u8, why: []const u8, evidence: EgressEvidence }{
        .{
            .id = "network-root-dns-assigned",
            .name = "Root DNS to assigned resolvers blocked",
            .why = "Root cannot issue arbitrary DNS queries through the assigned resolvers; " ++
                "network fetchers have their own user permissions.",
            .evidence = dns_assigned,
        },
        .{
            .id = "network-root-dns-arbitrary",
            .name = "Root DNS to arbitrary servers blocked",
            .why = "Root cannot send DNS queries to servers outside the configured resolver set.",
            .evidence = dns_other,
        },
        .{
            .id = "network-root-https-arbitrary",
            .name = "Root HTTPS to arbitrary servers blocked",
            .why = "Root cannot fetch tools or send data over arbitrary HTTPS connections.",
            .evidence = https,
        },
    }) |c| try p.add(.{
        .id = c.id,
        .area = "network",
        .name = c.name,
        .why = c.why,
        .how = "root's UDP/TCP connect() probes are denied with EACCES or EPERM; " ++
            "TCP is nonblocking, without waiting for DNS, TLS or a server response",
        .expected = "every probe denied with EACCES or EPERM",
        .observed = if (!p.root) "requires root" else if (c.evidence.text.items.len > 0)
            c.evidence.text.items
        else
            "no configured resolver",
        .result = if (p.root) c.evidence.result() else .skip,
        .detail = if (!p.root) "requires root" else if (c.evidence.allowed)
            "root has network permission"
        else if (c.evidence.unknown)
            "permission is inconclusive: configuration, address family or route unavailable"
        else if (c.evidence.count == 0)
            "no configured resolver"
        else
            "",
    });
}

const ResolverTarget = struct { address: std.Io.net.IpAddress };
const ConfiguredResolvers = struct {
    targets: [3]ResolverTarget = undefined,
    len: usize = 0,
    incomplete: bool = false,

    fn contains(r: *const ConfiguredResolvers, address: std.Io.net.IpAddress) bool {
        for (r.targets[0..r.len]) |target| if (target.address.eql(&address)) return true;
        return false;
    }
};

fn configuredResolvers(text: []const u8) ConfiguredResolvers {
    var result: ConfiguredResolvers = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        if (!std.mem.eql(u8, words.next() orelse "", "nameserver")) continue;
        const address = std.Io.net.IpAddress.parse(words.next() orelse "", 53) catch {
            result.incomplete = true;
            continue;
        };
        if (result.contains(address)) continue;
        if (result.len == result.targets.len) {
            result.incomplete = true;
            continue;
        }
        result.targets[result.len] = .{ .address = address };
        result.len += 1;
    }
    return result;
}

const Egress = enum { denied, allowed, unknown };
const Transport = enum { udp, tcp };

fn egressResult(e: linux.E) Egress {
    return switch (e) {
        .ACCES, .PERM => .denied,
        .SUCCESS, .INPROGRESS, .CONNREFUSED => .allowed,
        else => .unknown,
    };
}

const EgressEvidence = struct {
    text: std.ArrayList(u8) = .empty,
    count: usize = 0,
    allowed: bool = false,
    unknown: bool = false,

    fn probe(
        e: *EgressEvidence,
        gpa: Allocator,
        address: std.Io.net.IpAddress,
        proto: Transport,
    ) !void {
        const errno = probeEgress(address, proto);
        const observed = egressResult(errno);
        e.count += 1;
        e.allowed = e.allowed or observed == .allowed;
        e.unknown = e.unknown or observed == .unknown;
        const outcome = if (errno == .SUCCESS)
            "allowed"
        else
            try gpa.print("E{s}", .{errnoText(errno)});
        try listAdd(gpa, &e.text, "{s} {f}: {s}", .{ @tagName(proto), address, outcome });
    }

    fn result(e: EgressEvidence) posture.Result {
        if (e.allowed) return .fail;
        if (e.unknown or e.count == 0) return .skip;
        return .pass;
    }
};

fn probeEgress(address: std.Io.net.IpAddress, proto: Transport) linux.E {
    const family: u32 = if (address == .ip4) linux.AF.INET else linux.AF.INET6;
    const kind: u32 = if (proto == .udp) linux.SOCK.DGRAM else linux.SOCK.STREAM;
    const rc = linux.socket(family, kind | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
    if (linux.errno(rc) != .SUCCESS) return linux.errno(rc);
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    return switch (address) {
        .ip4 => |ip| blk: {
            const a = inet(ip.bytes, ip.port);
            break :blk linux.errno(linux.connect(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in)));
        },
        .ip6 => |ip| blk: {
            const a: linux.sockaddr.in6 = .{
                .addr = ip.bytes,
                .port = std.mem.nativeToBig(u16, ip.port),
                .flowinfo = 0,
                .scope_id = 0,
            };
            break :blk linux.errno(linux.connect(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in6)));
        },
    };
}

test "root egress distinguishes permission denial from offline destinations" {
    try testing.expectEqual(.denied, egressResult(.ACCES));
    try testing.expectEqual(.denied, egressResult(.PERM));
    for ([_]linux.E{ .SUCCESS, .INPROGRESS, .CONNREFUSED }) |e|
        try testing.expectEqual(.allowed, egressResult(e));
    for ([_]linux.E{ .NETUNREACH, .HOSTUNREACH, .AFNOSUPPORT, .TIMEDOUT, .MFILE }) |e|
        try testing.expectEqual(.unknown, egressResult(e));
    try testing.expectEqual(.skip, (EgressEvidence{}).result());
    try testing.expectEqual(.skip, (EgressEvidence{ .count = 1, .unknown = true }).result());
    try testing.expectEqual(
        .fail,
        (EgressEvidence{ .count = 2, .unknown = true, .allowed = true }).result(),
    );
    try testing.expectEqual(.pass, (EgressEvidence{ .count = 2 }).result());
}

test "assigned resolver parsing accepts IPv4 and IPv6 but reports incomplete evidence" {
    const r = configuredResolvers("search local\nnameserver 192.0.2.1 # detected\n" ++
        "nameserver 192.0.2.1\nnameserver 2001:db8::53\noptions timeout:1\n");
    try testing.expectEqual(2, r.len);
    try testing.expect(!r.incomplete);
    try testing.expect(r.contains(try std.Io.net.IpAddress.parse("192.0.2.1", 53)));
    try testing.expect(!r.contains(try std.Io.net.IpAddress.parse("198.51.100.1", 53)));
    try testing.expect(configuredResolvers("nameserver bad\n").incomplete);
    try testing.expect(configuredResolvers("nameserver 1.1.1.1\nnameserver 2.2.2.2\n" ++
        "nameserver 3.3.3.3\nnameserver 4.4.4.4\n").incomplete);
}

test "root egress checks skip instead of measuring a non-root user" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var p: Posture = .{ .io = testing.io, .gpa = arena.allocator(), .root = false };
    try rootEgress(&p, "nameserver 192.168.5.3\n", false);
    try testing.expectEqual(3, p.checks.items.len);
    for (p.checks.items) |c| {
        try testing.expectEqual(.skip, c.result);
        try testing.expectEqualStrings("requires root", c.observed.?);
    }
}

/// fenceBypass reports whether PID 1's bounding set retains a capability
/// that can send traffic outside Fence's policy.
fn fenceBypass(status: []const u8) ?bool {
    const admin = posture.capBit(
        status,
        "CapBnd",
        @intCast(linux.CAP.NET_ADMIN),
    ) orelse return null;
    const raw = posture.capBit(status, "CapBnd", @intCast(linux.CAP.NET_RAW)) orelse return null;
    return admin or raw;
}

test fenceBypass {
    try testing.expectEqual(false, fenceBypass("Name:\tinit\nCapBnd:\t0000000000000000\n").?);
    try testing.expectEqual(true, fenceBypass("CapBnd:\t0000000000001000\n").?);
    try testing.expectEqual(true, fenceBypass("CapBnd:\t0000000000002000\n").?);
    try testing.expectEqual(null, fenceBypass("Name:\tinit\n"));
}

fn ssh(p: *Posture) !void {
    const sshd = for ([_][]const u8{ "/usr/sbin/sshd", "/usr/bin/sshd" }) |path| {
        if (exists(p.io, path)) break path;
    } else return;
    const dev = p.werewolf and exists(p.io, "/etc/sv/sshd-dev/service");
    if (!dev or exists(p.io, "/etc/sv/sshd/service"))
        try sshConfig(p, sshd, "/etc/ssh/sshd_config", false);
    if (dev) try sshConfig(p, sshd, "/etc/ssh/howl-dev.conf", true);
}

fn sshConfig(p: *Posture, sshd: []const u8, config: []const u8, dev: bool) !void {
    if (p.root) p.work("SSH settings (10 s timeout):", "sshd -T");
    const settings: ?[]const u8 = if (!p.root) null else if (std.process.run(p.gpa, p.io, .{
        .argv = &.{ sshd, "-T", "-f", config },
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(64 << 10),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
    })) |r| switch (r.term) {
        .exited => |code| if (code == 0) r.stdout else null,
        else => null,
    } else |_| null;
    const skipped = if (!p.root) "sshd -T needs root" else "sshd -T failed";

    var loose: std.ArrayList(u8) = .empty;
    if (settings) |s| {
        try loose.appendSlice(p.gpa, try sshMismatches(p.gpa, s, &ssh_settings));
        try loose.appendSlice(p.gpa, try sshLimits(p.gpa, s, loose.items.len > 0));
        if (statx(p.gpa, config)) |st| if (st.uid != 0 or st.mode & 0o022 != 0)
            try listAdd(p.gpa, &loose, "{s} is not root's alone", .{config});
        // sshd -T lists each host key on a "hostkey PATH" line.
        var lines = std.mem.tokenizeScalar(u8, s, '\n');
        while (lines.next()) |line| {
            if (!std.ascii.startsWithIgnoreCase(line, "hostkey ")) continue;
            const key = trim(line["hostkey ".len..]);
            const st = statx(p.gpa, key) orelse continue;
            if (st.mode & 0o077 != 0)
                try listAdd(p.gpa, &loose, "{s} is readable by others", .{key});
        }
    }
    try p.add(.{
        .id = if (dev) "network-ssh-dev-config" else "network-ssh-config",
        .area = "network",
        .name = "ssh offers keys and nothing more",
        .why = "Logging in takes a key; no one gets in without a password, through another " ++
            "host's trust, or with their own environment, and a session cannot forward " ++
            "ports or tunnel past the machine's network policy. A guesser gets few tries " ++
            "and little time, and a dead session is cut.",
        .how = "sshd -T reports " ++ comptime sshSettingsText() ++
            ", permitrootlogin no or prohibit-password, maxauthtries at most 4, " ++
            "logingracetime at most 60, maxsessions at most 10, maxstartups starting " ++
            "to refuse by 10 and refusing all by 60, clientaliveinterval set and " ++
            "clientalivecountmax at most 3; /etc/ssh/sshd_config is root's and writable " ++
            "by no one else, and no host key is readable by others",
        .result = if (settings == null) .skip else if (loose.items.len == 0) .pass else .fail,
        .detail = if (settings == null) skipped else loose.items,
    });
    const weak = if (settings) |s| try weakSshCrypto(p.gpa, s) else "";
    try p.add(.{
        .id = if (dev) "network-ssh-dev-crypto" else "network-ssh-crypto",
        .area = "network",
        .name = "ssh uses strong cryptography",
        .why = "No ssh connection can be made with a cipher, MAC, key exchange or signature " ++
            "that is broken or weakening, and a recording of one cannot be read by a " ++
            "quantum computer later.",
        .how = "sshd -T lists no CBC, arcfour or 3DES cipher, no MD5, SHA-1, 64-bit or " ++
            "truncated MAC, no SHA-1 or 1024-bit key exchange, no ssh-rsa or ssh-dss " ++
            "signature, and a post-quantum key exchange (mlkem768x25519-sha256 or " ++
            "sntrup761x25519-sha512)",
        .result = if (settings == null) .skip else if (weak.len == 0) .pass else .fail,
        .detail = if (settings == null) skipped else weak,
    });
    const plain = if (settings) |s| try plainSshKeys(p.gpa, s) else "";
    try p.add(.{
        .id = if (dev) "network-ssh-dev-security-keys" else "network-ssh-security-keys",
        .area = "network",
        .name = "ssh takes security keys alone",
        .why = "Logging in takes a security key, and a touch of it: a key file copied off " ++
            "an operator's laptop, or used there by malware while they are away, signs " ++
            "nothing.",
        .how = "sshd -T lists only security-key algorithms (sk-...) in " ++
            "pubkeyacceptedalgorithms, and touch-required in pubkeyauthoptions",
        .observed = if (settings) |s|
            try p.gpa.print("pubkeyacceptedalgorithms={s}; pubkeyauthoptions={s}", .{
                sshValue(
                    s,
                    "pubkeyacceptedalgorithms",
                ) orelse "absent",
                sshValue(s, "pubkeyauthoptions") orelse "absent",
            })
        else
            skipped,
        .result = if (settings == null) .skip else if (plain.len == 0) .pass else .fail,
        .detail = if (settings == null) skipped else plain,
    });
}

/// plainSshKeys lists what sshd -T accepts besides touched security keys:
/// each algorithm without a FIDO authenticator's sk- prefix, and
/// pubkeyauthoptions without touch-required, which an authorized_keys
/// no-touch-required could otherwise turn off.
fn plainSshKeys(gpa: Allocator, settings: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    const algs = sshValue(settings, "pubkeyacceptedalgorithms") orelse "absent";
    var it = std.mem.tokenizeScalar(u8, algs, ',');
    while (it.next()) |alg| {
        if (!std.mem.startsWith(u8, alg, "sk-")) try listAdd(gpa, &out, "{s}", .{alg});
    }
    const options = sshValue(settings, "pubkeyauthoptions") orelse "absent";
    var opts = std.mem.tokenizeAny(u8, options, ", ");
    const touch = while (opts.next()) |o| {
        if (std.mem.eql(u8, o, "touch-required")) break true;
    } else false;
    if (!touch) try listAdd(gpa, &out, "pubkeyauthoptions is {s}", .{options});
    return out.items;
}

test plainSshKeys {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("", try plainSshKeys(
        a,
        "PubkeyAcceptedAlgorithms sk-ssh-ed25519@openssh.com," ++
            "sk-ecdsa-sha2-nistp256@openssh.com\nPubkeyAuthOptions touch-required\n",
    ));
    try testing.expectEqualStrings("", try plainSshKeys(
        a,
        "pubkeyacceptedalgorithms sk-ssh-ed25519@openssh.com\n" ++
            "pubkeyauthoptions touch-required,verify-required\n",
    ));
    try testing.expectEqualStrings(
        "ssh-ed25519, rsa-sha2-512, pubkeyauthoptions is none",
        try plainSshKeys(
            a,
            "pubkeyacceptedalgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512\n" ++
                "pubkeyauthoptions none\n",
        ),
    );
    try testing.expectEqualStrings(
        "absent, pubkeyauthoptions is absent",
        try plainSshKeys(a, "port 22\n"),
    );
}

/// sshLimits lists the sshd -T settings that give a password guesser or a
/// forgotten session more than the benchmarks allow. If continuing, the
/// list starts with a comma.
fn sshLimits(gpa: Allocator, settings: []const u8, continuing: bool) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    const root = sshValue(settings, "permitrootlogin") orelse "absent";
    if (!std.mem.eql(u8, root, "no") and !std.mem.eql(u8, root, "prohibit-password") and
        !std.mem.eql(u8, root, "without-password"))
        try out.print(gpa, "{s}permitrootlogin is {s}", .{ sep(continuing, out.items), root });
    for ([_]struct { []const u8, u32 }{
        .{ "maxauthtries", 4 },
        .{ "logingracetime", 60 },
        .{ "maxsessions", 10 },
        .{ "clientalivecountmax", 3 },
    }) |limit| {
        const key, const most = limit;
        const v = sshValue(settings, key) orelse "absent";
        const n = std.fmt.parseInt(u32, v, 10) catch std.math.maxInt(u32);
        if (n > most) try out.print(gpa, "{s}{s} is {s}", .{ sep(continuing, out.items), key, v });
    }
    const interval = sshValue(settings, "clientaliveinterval") orelse "absent";
    if ((std.fmt.parseInt(u32, interval, 10) catch 0) == 0)
        try out.print(
            gpa,
            "{s}clientaliveinterval is {s}",
            .{ sep(continuing, out.items), interval },
        );
    // maxstartups is start:rate:full: sshd starts refusing unauthenticated
    // connections at start and refuses them all at full.
    const startups = sshValue(settings, "maxstartups") orelse "absent";
    var parts = std.mem.splitScalar(u8, startups, ':');
    const start = std.fmt.parseInt(u32, parts.next() orelse "", 10) catch std.math.maxInt(u32);
    _ = parts.next();
    const full = std.fmt.parseInt(u32, parts.next() orelse "", 10) catch std.math.maxInt(u32);
    if (start > 10 or full > 60)
        try out.print(gpa, "{s}maxstartups is {s}", .{ sep(continuing, out.items), startups });
    return out.items;
}

fn sep(continuing: bool, so_far: []const u8) []const u8 {
    return if (continuing or so_far.len > 0) ", " else "";
}

test sshLimits {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const good = "permitrootlogin prohibit-password\nmaxauthtries 3\nlogingracetime " ++
        "30\nmaxsessions " ++
        "0\nclientaliveinterval 60\nclientalivecountmax 3\nmaxstartups 10:30:30\n";
    try testing.expectEqualStrings("", try sshLimits(a, good, false));
    const defaults = "permitrootlogin yes\nmaxauthtries 6\nlogingracetime 120\nmaxsessions 10\n" ++
        "clientaliveinterval 0\nclientalivecountmax 3\nmaxstartups 10:30:100\n";
    try testing.expectEqualStrings(
        ", permitrootlogin is yes, maxauthtries is 6, logingracetime is 120, " ++
            "clientaliveinterval is 0, maxstartups is 10:30:100",
        try sshLimits(a, defaults, true),
    );
    try testing.expectEqualStrings(
        "permitrootlogin is absent, maxauthtries is absent, logingracetime is absent, " ++
            "maxsessions is absent, clientalivecountmax is absent, clientaliveinterval is " ++
            "absent, maxstartups is absent",
        try sshLimits(a, "", false),
    );
}

/// fence checks werewolf's network policy (docs/design/fence.md); policy is
/// "" if there is none. Only declared ports can be bound, only declared
/// traffic sent, nothing unsolicited received, the metadata server reached
/// only by those named, and IPv6 is off or under the same rules. Tests are
/// safe and quiet: a bind, a UDP connect that sends nothing, and a connect
/// the policy refuses at once. On any Linux, a missing protection fails.
fn fence(p: *Posture, policy: []const u8, v6_on: bool) !void {
    const port = unusedPort(policy);
    const bound = probeBind(port);
    try p.add(.{
        .id = if (p.werewolf) "network-bind" else "network-bind-restricted",
        .area = "network",
        .name = if (p.werewolf) "Undeclared ports cannot be opened" else "TCP listeners restricted",
        .why = "Arbitrary processes cannot open TCP listeners.",
        .source = try p.gpa.print("bind(AF_INET TCP, INADDR_ANY, port={d})", .{port}),
        .comparison = try p.gpa.print("bind(TCP, *:{d}) = {s}{s}", .{
            port,
            if (bound == .SUCCESS)
                "0"
            else
                try p.gpa.print("E{s}({d})", .{ errnoText(bound), @backingInt(bound) }),
            if (bound == .ACCES) "" else ", want EACCES",
        }),
        .how = try p.gpa.print(
            "bind() of a TCP socket to port {d} is refused with EACCES",
            .{port},
        ),
        .result = if (bound == .ACCES) .pass else .fail,
        .detail = try p.gpa.print("bind: {s}", .{errnoText(bound)}),
    });

    const sent = probeSend();
    try p.add(.{
        .id = if (p.werewolf) "network-outbound" else "network-outbound-restricted",
        .area = "network",
        .name = if (p.werewolf)
            "Only declared traffic leaves"
        else
            "Outbound connections restricted",
        .why = "A program can send nothing its form did not declare: no beacon, no " ++
            "exfiltration, no download.",
        .how = "connect() of a UDP socket to 192.0.2.1 port 9 (an address for " ++
            "documentation), which looks the route up without sending, is refused with EACCES",
        .comparison = try p.gpa.print("connect(UDP, 192.0.2.1:9) = {s}{s}", .{
            if (sent == .SUCCESS)
                "0"
            else
                try p.gpa.print("E{s}({d})", .{ errnoText(sent), @backingInt(sent) }),
            if (sent == .ACCES) "" else ", want EACCES",
        }),
        .result = if (sent == .ACCES) .pass else .fail,
        .detail = try p.gpa.print("connect: {s}", .{errnoText(sent)}),
    });

    p.work("network-metadata: TCP probe (1 s timeout):", "169.254.169.254:80");
    const md = probeMetadata();
    try rootEgress(p, p.read("/etc/resolv.conf"), v6_on);
    try p.add(.{
        .id = "network-metadata",
        .area = "network",
        .name = "Cloud metadata server closed",
        .why = "Only the programs named can read the instance's metadata, where its config " ++
            "and any secrets in it are.",
        .how = "a TCP connect() to 169.254.169.254 port 80, for a second at most, is " ++
            "refused with EACCES",
        .result = switch (md) {
            .refused => .pass,
            .reached => .fail,
            // Nothing answered and no policy refused it: not a cloud.
            .absent => if (policy.len == 0) .skip else .fail,
        },
        .detail = @tagName(md),
    });

    if (!p.werewolf) return;
    p.work("network policy routing: netlink dump (1 s reply timeout)", "");
    const rules: RuleSummary = if (ruleDump(p.gpa, linux.AF.INET)) |dump|
        summarizeRules(dump)
    else |_|
        .{};
    try p.add(.{
        .id = "network-inbound",
        .area = "network",
        .name = "Unsolicited traffic dropped",
        .why = "Packets the machine did not ask for and does not serve are dropped " ++
            "unanswered, whatever is listening.",
        .how = "the IPv4 policy-routing rules (RTM_GETRULE) blackhole arriving TCP and UDP " ++
            "(or everything) before any rule delivers it to the local table, and refuse " ++
            "locally sent traffic that no rule allows",
        .result = if (rules.inbound_dropped and rules.outbound_refused) .pass else .fail,
        .detail = try p.gpa.print("arriving: {s}; sent: {s}", .{
            if (rules.inbound_dropped) "dropped unless declared" else "delivered",
            if (rules.outbound_refused) "refused unless declared" else "routed",
        }),
    });

    const rules6: RuleSummary = if (!v6_on)
        .{}
    else if (ruleDump(p.gpa, linux.AF.INET6)) |dump|
        summarizeRules(dump)
    else |_|
        .{};
    try p.add(.{
        .id = "network-ipv6",
        .area = "network",
        .name = "IPv6 under the same policy",
        .why = "Every interface has an IPv6 address reachable from the network; IPv6 must " ++
            "not be a way around the IPv4 rules.",
        .how = "IPv6 is off (disable_ipv6 reads 1, or the kernel has none), or its " ++
            "policy-routing rules (RTM_GETRULE, AF_INET6) drop arriving traffic before " ++
            "delivering it and refuse locally sent traffic no rule allows",
        .result = if (!v6_on or (rules6.inbound_dropped and rules6.outbound_refused))
            .pass
        else
            .fail,
        .detail = if (!v6_on)
            "IPv6 off"
        else
            try p.gpa.print("arriving: {s}; sent: {s}", .{
                if (rules6.inbound_dropped) "dropped unless declared" else "delivered",
                if (rules6.outbound_refused) "refused unless declared" else "routed",
            }),
    });
}

/// ssh_settings is what sshd -T must report: keys only, no host-based
/// trust, and no forwarding, tunnels or user environment.
const ssh_settings = [_][2][]const u8{
    .{ "passwordauthentication", "no" },
    .{ "kbdinteractiveauthentication", "no" },
    .{ "permitemptypasswords", "no" },
    .{ "hostbasedauthentication", "no" },
    .{ "ignorerhosts", "yes" },
    .{ "strictmodes", "yes" },
    .{ "permituserenvironment", "no" },
    .{ "x11forwarding", "no" },
    .{ "gssapiauthentication", "no" },
    .{ "loglevel", "VERBOSE" },
    .{ "allowagentforwarding", "no" },
    .{ "allowtcpforwarding", "no" },
    .{ "allowstreamlocalforwarding", "no" },
    .{ "gatewayports", "no" },
    .{ "permittunnel", "no" },
};

fn sshSettingsText() []const u8 {
    comptime var s: []const u8 = "";
    inline for (ssh_settings, 0..) |kv, i| s = s ++ (if (i > 0) ", " else "") ++ kv[0] ++ " " ++
        kv[1];
    return s;
}

/// sshValue returns key's value in sshd -T output ("key value" lines), or
/// null. Keys are matched in any case, since some OpenSSH releases print
/// CamelCase (10.x: StrictModes yes).
fn sshValue(settings: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, settings, '\n');
    while (it.next()) |line| {
        if (line.len > key.len and std.ascii.startsWithIgnoreCase(line, key) and
            line[key.len] == ' ') return trim(line[key.len + 1 ..]);
    }
    return null;
}

/// sshMismatches lists the settings in want that sshd -T reports otherwise.
fn sshMismatches(gpa: Allocator, settings: []const u8, want: []const [2][]const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (want) |kv| {
        const v = sshValue(settings, kv[0]) orelse v: {
            // An sshd built without X11 or GSSAPI (Wolfi's) omits these
            // settings and cannot do either.
            if (std.mem.eql(u8, kv[0], "x11forwarding") or
                std.mem.eql(u8, kv[0], "gssapiauthentication")) continue;
            break :v "absent";
        };
        if (!std.mem.eql(u8, v, kv[1])) try listAdd(gpa, &out, "{s} is {s}", .{ kv[0], v });
    }
    return out.items;
}

/// ssh_weak names, for each sshd -T list, the substrings of weak algorithms.
const ssh_weak = [_]struct { []const u8, []const []const u8 }{
    .{ "ciphers", &.{ "-cbc", "arcfour", "3des" } },
    .{ "macs", &.{ "md5", "sha1", "umac-64", "-96" } },
    .{ "kexalgorithms", &.{"sha1"} },
    .{ "hostkeyalgorithms", &.{ "ssh-rsa", "ssh-dss" } },
    .{ "pubkeyacceptedalgorithms", &.{ "ssh-rsa", "ssh-dss" } },
};

/// ssh_post_quantum are key exchanges that resist a quantum computer. sshd
/// must offer one, or sessions recorded today could be read once one exists.
const ssh_post_quantum = [_][]const u8{ "mlkem768x25519-sha256", "sntrup761x25519-sha512" };

/// weakSshCrypto lists each weak algorithm sshd -T offers, once, and notes
/// a missing post-quantum key exchange.
fn weakSshCrypto(gpa: Allocator, settings: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (ssh_weak) |w| {
        var algs = std.mem.tokenizeScalar(u8, sshValue(settings, w[0]) orelse continue, ',');
        next: while (algs.next()) |alg| {
            for (w[1]) |needle| if (std.mem.indexOf(u8, alg, needle) != null) {
                var seen = std.mem.tokenizeSequence(u8, out.items, ", ");
                while (seen.next()) |s| if (std.mem.eql(u8, s, alg)) continue :next;
                try listAdd(gpa, &out, "{s}", .{alg});
                continue :next;
            };
        }
    }
    var kex = std.mem.tokenizeScalar(u8, sshValue(settings, "kexalgorithms") orelse "", ',');
    const post_quantum = offered: while (kex.next()) |alg| {
        for (ssh_post_quantum) |pq| if (std.mem.startsWith(u8, alg, pq)) break :offered true;
    } else false;
    if (!post_quantum) try listAdd(gpa, &out, "no post-quantum key exchange", .{});
    return out.items;
}

/// listenPorts adds to out, once each and sorted, the ports listening in
/// /proc/net/tcp or tcp6 text. Sockets bound only to loopback are skipped:
/// fence lets nothing from the network reach them.
fn listenPorts(gpa: Allocator, text: []const u8, out: *std.ArrayList(u16)) !void {
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    _ = lines.next(); // skip the header
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        _ = f.next() orelse continue; // sl
        const local = f.next() orelse continue;
        _ = f.next() orelse continue; // remote
        const state = f.next() orelse continue;
        if (!std.mem.eql(u8, state, "0A")) continue; // TCP_LISTEN
        const colon = std.mem.findScalarLast(u8, local, ':') orelse continue;
        if (isLoopback(local[0..colon])) continue;
        const port = std.fmt.parseInt(u16, local[colon + 1 ..], 16) catch continue;
        if (std.mem.findScalar(u16, out.items, port) == null) try out.append(gpa, port);
    }
    std.mem.sort(u16, out.items, {}, std.sort.asc(u16));
}

/// isLoopback reports whether a /proc/net/tcp local address, in
/// little-endian hex words, is 127.0.0.0/8, ::1 or ::ffff:127.0.0.0/8.
fn isLoopback(hex: []const u8) bool {
    if (hex.len == 8) return std.mem.endsWith(u8, hex, "7F");
    if (hex.len != 32) return false;
    if (std.mem.eql(u8, hex, "00000000000000000000000001000000")) return true;
    return std.mem.eql(u8, hex[0..24], "0000000000000000FFFF0000") and
        std.mem.endsWith(u8, hex, "7F");
}

/// policyPorts returns the ports of a policy's `listen tcp PORT` lines (not
/// `loopback`), one per line.
fn policyPorts(gpa: Allocator, policy: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, policy, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "listen tcp ")) continue;
        const rest = std.mem.trim(u8, line["listen tcp ".len..], " ");
        if (!std.mem.endsWith(u8, rest, " loopback")) try out.print(gpa, "{s}\n", .{rest});
    }
    return out.items;
}

/// isDeclared reports whether text, numbers separated by spaces or newlines,
/// holds port.
fn isDeclared(text: []const u8, port: u16) bool {
    var it = std.mem.tokenizeAny(u8, text, " \n");
    while (it.next()) |d| if ((std.fmt.parseInt(u16, d, 10) catch 0) == port) return true;
    return false;
}

/// unusedPort returns a TCP port no number in the policy names, to try binding.
fn unusedPort(policy: []const u8) u16 {
    var port: u16 = 47321;
    while (isDeclared(policy, port)) port += 1;
    return port;
}

fn inet(addr: [4]u8, port: u16) linux.sockaddr.in {
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(addr) };
}

/// probeBind binds a new TCP socket to port on every address and returns
/// the errno. The socket never listens and is closed.
fn probeBind(port: u16) linux.E {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return linux.errno(rc);
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const a = inet(.{ 0, 0, 0, 0 }, port);
    return linux.errno(linux.bind(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in)));
}

/// probeSend connects a UDP socket to 192.0.2.1:9, which looks up a route but
/// sends nothing, and returns the errno.
fn probeSend() linux.E {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return linux.errno(rc);
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const a = inet(.{ 192, 0, 2, 1 }, 9);
    return linux.errno(linux.connect(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in)));
}

const Metadata = enum { refused, reached, absent };

/// probeMetadata tries a TCP connect to 169.254.169.254:80 for up to a second:
/// refused by policy, reached (connected or actively refused), or absent.
fn probeMetadata() Metadata {
    const rc = linux.socket(
        linux.AF.INET,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    );
    if (linux.errno(rc) != .SUCCESS) return .absent;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const a = inet(.{ 169, 254, 169, 254 }, 80);
    switch (linux.errno(linux.connect(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in)))) {
        .ACCES, .PERM => return .refused,
        .SUCCESS => return .reached,
        .INPROGRESS => {},
        else => return .absent,
    }
    var fds = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
    if (linux.poll(&fds, 1, 1000) != 1) return .absent;
    var err: i32 = 0;
    var len: linux.socklen_t = @sizeOf(i32);
    _ = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&err), &len);
    return if (err == 0 or err == @backingInt(linux.E.CONNREFUSED)) .reached else .absent;
}

pub fn errnoText(e: linux.E) []const u8 {
    return if (e == .SUCCESS) "allowed" else std.enums.tagName(linux.E, e) orelse "unknown";
}

/// ruleDump returns family's policy-routing rules as the kernel's
/// RTM_GETRULE dump. Listing them needs no privilege.
fn ruleDump(gpa: Allocator, family: u8) ![]const u8 {
    const rc = linux.socket(
        linux.AF.NETLINK,
        linux.SOCK.RAW | linux.SOCK.CLOEXEC,
        linux.NETLINK.ROUTE,
    );
    if (linux.errno(rc) != .SUCCESS) return error.NoNetlink;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var req: [28]u8 = @splat(0);
    std.mem.writeInt(u32, req[0..4], req.len, .little);
    std.mem.writeInt(u16, req[4..6], 34, .little); // RTM_GETRULE
    std.mem.writeInt(u16, req[6..8], 0x301, .little); // NLM_F_REQUEST | NLM_F_DUMP
    std.mem.writeInt(u32, req[8..12], 1, .little);
    req[16] = family;
    if (linux.errno(linux.sendto(
        fd,
        &req,
        req.len,
        0,
        null,
        0,
    )) != .SUCCESS) return error.NoNetlink;
    var out: std.ArrayList(u8) = .empty;
    var buf: [32 << 10]u8 align(4) = undefined;
    while (out.items.len < 1 << 20) {
        var fds = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&fds, 1, 1000) != 1) return error.NoReply;
        const n = linux.recvfrom(fd, &buf, buf.len, 0, null, null);
        if (linux.errno(n) != .SUCCESS) return error.NoReply;
        try out.appendSlice(gpa, buf[0..n]);
        if (dumpDone(buf[0..n])) return out.items;
    }
    return error.TooLong;
}

/// dumpDone reports whether a batch of netlink messages ends the dump.
fn dumpDone(batch: []const u8) bool {
    var off: usize = 0;
    while (off + 16 <= batch.len) {
        const len = std.mem.readInt(u32, batch[off..][0..4], .little);
        const kind = std.mem.readInt(u16, batch[off + 4 ..][0..2], .little);
        if (kind == 3 or kind == 2) return true; // NLMSG_DONE, NLMSG_ERROR
        if (len < 16) return true;
        off += std.mem.alignForward(usize, len, 4);
    }
    return false;
}

const RuleSummary = struct {
    /// outbound_refused is set if a rule with no selector but iif lo
    /// prohibits whatever locally sent traffic no earlier rule allowed.
    outbound_refused: bool = false,
    /// inbound_dropped is set if arriving traffic is dropped before any
    /// rule without selectors delivers it to the local table.
    inbound_dropped: bool = false,
};

/// summarizeRules reads a policy-routing rule dump for traffic in and out.
fn summarizeRules(dump: []const u8) RuleSummary {
    // Find where arriving traffic is first dropped, either all of it or TCP
    // and UDP by name (as fence does, so ARP's lookup still finds the address
    // local), and where it is first delivered.
    var drop_at: ?u32 = null;
    var tcp_drop_at: ?u32 = null;
    var udp_drop_at: ?u32 = null;
    var local_at: ?u32 = null;
    var out_refused = false;
    var off: usize = 0;
    while (off + 28 <= dump.len) {
        const len = std.mem.readInt(u32, dump[off..][0..4], .little);
        if (len < 16 or off + len > dump.len) break;
        const msg = dump[off .. off + len];
        off += std.mem.alignForward(usize, len, 4);
        if (std.mem.readInt(u16, msg[4..6], .little) != 32 or msg.len < 28) continue; // RTM_NEWRULE
        var table: u32 = msg[16 + 4];
        const action = msg[16 + 7];
        var priority: u32 = 0;
        var from_lo = false;
        var iif = false;
        var selective = false;
        var proto: ?u8 = null;
        var a: usize = 28;
        while (a + 4 <= msg.len) {
            const alen = std.mem.readInt(u16, msg[a..][0..2], .little);
            if (alen < 4 or a + alen > msg.len) break;
            const kind = std.mem.readInt(u16, msg[a + 2 ..][0..2], .little) & 0x3fff;
            const v = msg[a + 4 .. a + alen];
            switch (kind) {
                6 => if (v.len == 4) {
                    priority = std.mem.readInt(u32, v[0..4], .little);
                },
                15 => if (v.len == 4) {
                    table = std.mem.readInt(u32, v[0..4], .little);
                },
                3 => {
                    iif = true;
                    from_lo = std.mem.eql(u8, std.mem.sliceTo(v, 0), "lo");
                },
                22 => if (v.len == 1) {
                    proto = v[0];
                },
                1, 2, 10, 17, 20, 23, 24 => selective = true, // dst, src, fwmark, oif, uid, ports
                else => {},
            }
            a += std.mem.alignForward(usize, alen, 4);
        }
        if (selective or (iif and proto != null)) continue;
        if (action == 8 and from_lo) out_refused = true; // FR_ACT_PROHIBIT
        if (iif) continue;
        if (action == 6) { // FR_ACT_BLACKHOLE
            const at: *?u32 = if (proto == null)
                &drop_at
            else if (proto == 6)
                &tcp_drop_at
            else if (proto == 17)
                &udp_drop_at
            else
                continue;
            at.* = @min(at.* orelse priority, priority);
        }
        // Delivery to the local table.
        if (action == 1 and table == 255 and proto == null)
            local_at = @min(local_at orelse priority, priority);
    }
    const before = struct {
        fn f(drop: ?u32, local: ?u32) bool {
            const d = drop orelse return false;
            return local == null or d < local.?;
        }
    }.f;
    const dropped = before(drop_at, local_at) or
        (before(tcp_drop_at, local_at) and before(udp_drop_at, local_at));
    return .{ .outbound_refused = out_refused, .inbound_dropped = dropped };
}

test listenPorts {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var ports: std.ArrayList(u16) = .empty;
    const tcp =
        \\  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        \\   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1
        \\   1: 0F05A8C0:0050 0105A8C0:C350 01 00000000:00000000 00:00000000 00000000   200        0 2 1
        \\   2: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1
        \\   3: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1
        \\   4: 0F05A8C0:2009 00000000:0000 0A 00000000:00000000 00:00000000 00000000   208        0 5 1
    ;
    try listenPorts(arena.allocator(), tcp, &ports);
    // 22 is bound only to 127.0.0.1, so it is not offered.
    try testing.expectEqualSlices(u16, &.{ 80, 8201 }, ports.items);
    try testing.expect(isLoopback("0100007F") and isLoopback("0A00007F"));
    try testing.expect(isLoopback("00000000000000000000000001000000"));
    try testing.expect(isLoopback("0000000000000000FFFF00000100007F"));
    try testing.expect(!isLoopback("00000000") and !isLoopback("0F05A8C0"));
    try testing.expect(!isLoopback("00000000000000000000000000000000"));
    try testing.expect(isDeclared("80\n", 80));
    const policy = try policyPorts(
        arena.allocator(),
        "listen tcp 22\nlisten tcp 80\nlisten tcp 5432 loopback\nmetadata 68\n",
    );
    try testing.expectEqualStrings("22\n80\n", policy);
    try testing.expect(isDeclared(policy, 80) and !isDeclared(policy, 68) and
        !isDeclared(policy, 5432));
    try testing.expect(!isDeclared("80\n", 22));
}

test sshMismatches {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const settings = "port 22\npasswordauthentication no\nallowtcpforwarding yes\npermittunnel " ++
        "no\nciphers chacha20-poly1305@openssh.com,aes256-cbc\nmacs hmac-sha2-256-etm@openssh.co" ++
        "m,umac-64-etm@openssh.com,hmac-sha1\nkexalgorithms curve25519-sha256,diffie-hellman-gro" ++
        "up14-sha1\nhostkeyalgorithms ssh-ed25519,ssh-rsa\npubkeyacceptedalgorithms " ++
        "ssh-ed25519,ssh-rsa,rsa-sha2-512\n";
    try testing.expectEqualStrings("no", sshValue(settings, "passwordauthentication").?);
    try testing.expectEqualStrings("yes", sshValue("Port 22\nStrictModes yes\n", "strictmodes").?);
    try testing.expectEqual(null, sshValue("StrictModesX yes\n", "strictmodes"));
    try testing.expectEqualStrings(
        "",
        try sshMismatches(
            a,
            "PermitTunnel no\n",
            &.{ .{ "x11forwarding", "no" }, .{ "permittunnel", "no" } },
        ),
    );
    try testing.expectEqualStrings(
        "x11forwarding is yes",
        try sshMismatches(a, "X11Forwarding yes\n", &.{.{ "x11forwarding", "no" }}),
    );
    try testing.expectEqual(null, sshValue(settings, "password"));
    try testing.expectEqualStrings(
        "allowtcpforwarding is yes, gatewayports is absent",
        try sshMismatches(
            a,
            settings,
            &.{
                .{ "passwordauthentication", "no" },
                .{ "allowtcpforwarding", "no" },
                .{ "permittunnel", "no" },
                .{ "gatewayports", "no" },
            },
        ),
    );
    try testing.expectEqualStrings(
        "aes256-cbc, umac-64-etm@openssh.com, hmac-sha1, diffie-hellman-group14-sha1, " ++
            "ssh-rsa, no post-quantum key exchange",
        try weakSshCrypto(a, settings),
    );
    try testing.expectEqualStrings(
        "",
        try weakSshCrypto(
            a,
            "ciphers aes256-gcm@openssh.com\nmacs hmac-sha2-512-etm@openssh.com\nkexalgorithms " ++
                "mlkem768x25519-sha256\nhostkeyalgorithms ssh-ed25519,rsa-sha2-256\n",
        ),
    );
}

/// testRule builds a netlink rule message with priority, action, table, and
/// the given iif name and protocol.
fn testRule(
    buf: []u8,
    priority: u32,
    action: u8,
    table: u8,
    iif: ?[]const u8,
    proto: ?u8,
) []const u8 {
    @memset(buf, 0);
    var n: usize = 28;
    buf[16] = linux.AF.INET;
    buf[16 + 4] = table;
    buf[16 + 7] = action;
    const put = struct {
        fn f(b: []u8, at: *usize, kind: u16, v: []const u8) void {
            std.mem.writeInt(u16, b[at.*..][0..2], @intCast(4 + v.len), .little);
            std.mem.writeInt(u16, b[at.* + 2 ..][0..2], kind, .little);
            @memcpy(b[at.* + 4 ..][0..v.len], v);
            at.* += std.mem.alignForward(usize, 4 + v.len, 4);
        }
    }.f;
    put(buf, &n, 6, std.mem.asBytes(&priority));
    if (iif) |name| put(buf, &n, 3, name);
    if (proto) |pr| put(buf, &n, 22, &.{pr});
    std.mem.writeInt(u32, buf[0..4], @intCast(n), .little);
    std.mem.writeInt(u16, buf[4..6], 32, .little);
    return buf[0..n];
}

test summarizeRules {
    var dump: std.ArrayList(u8) = .empty;
    defer dump.deinit(std.testing.allocator);
    var b: [64]u8 = undefined;
    // The kernel's own rules (local at 0, main) drop nothing.
    try dump.appendSlice(std.testing.allocator, testRule(&b, 0, 1, 255, null, null));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 32766, 1, 254, null, null));
    try std.testing.expectEqual(RuleSummary{}, summarizeRules(dump.items));

    // fence's rules: local first only for lo, allowances with selectors, the
    // refusal from lo, ICMP in, the TCP and UDP drops, then the moved local
    // rule.
    dump.clearRetainingCapacity();
    try dump.appendSlice(std.testing.allocator, testRule(&b, 10, 1, 255, "lo\x00", null));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 200, 1, 254, "lo\x00", 6));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 299, 8, 0, "lo\x00", null));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 300, 1, 255, null, 1));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, 6));
    const tcp_only = dump.items.len;
    try dump.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, 17));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 400, 1, 255, null, null));
    try std.testing.expectEqual(
        RuleSummary{ .outbound_refused = true, .inbound_dropped = true },
        summarizeRules(dump.items),
    );

    // Dropping TCP but not UDP does not count as dropped.
    var half: std.ArrayList(u8) = .empty;
    defer half.deinit(std.testing.allocator);
    try half.appendSlice(std.testing.allocator, dump.items[0..tcp_only]);
    try half.appendSlice(std.testing.allocator, testRule(&b, 400, 1, 255, null, null));
    try std.testing.expect(!summarizeRules(half.items).inbound_dropped);

    // Dropping everything counts too.
    var all: std.ArrayList(u8) = .empty;
    defer all.deinit(std.testing.allocator);
    try all.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, null));
    try all.appendSlice(std.testing.allocator, testRule(&b, 400, 1, 255, null, null));
    try std.testing.expect(summarizeRules(all.items).inbound_dropped);

    // A drop that comes after delivery to the local table drops nothing.
    var late: std.ArrayList(u8) = .empty;
    defer late.deinit(std.testing.allocator);
    try late.appendSlice(std.testing.allocator, testRule(&b, 0, 1, 255, null, null));
    try late.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, null));
    try std.testing.expect(!summarizeRules(late.items).inbound_dropped);

    // Truncated input is not trusted past its end.
    try std.testing.expectEqual(RuleSummary{}, summarizeRules(dump.items[0..20]));
}

test unusedPort {
    try std.testing.expectEqual(47321, unusedPort(""));
    try std.testing.expectEqual(47322, unusedPort("listen tcp 47321\n"));
}
