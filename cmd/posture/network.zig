//! network holds posture's network checks: listening ports, fence's rules,
//! IPv6, and sshd's settings.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const testing = std.testing;
const people = @import("people");

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
    try web(p);
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
    // limited to what they must provide, with overly broad prefixes refused.
    if (v6_on) try ipv6RaLimits(p);
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
/// rootEgress probes root's DNS: to what resolv.conf names, which is
/// unwound, and to anything else, the resolvers unwound asks (upstream)
/// among them.
pub fn rootEgress(p: *Posture, resolv: []const u8, upstream: []const u8, v6_on: bool) !void {
    const assigned = configuredResolvers(resolv);
    var dns_assigned: EgressEvidence = .{ .unknown = assigned.incomplete };
    var dns_other: EgressEvidence = .{};
    var https: EgressEvidence = .{};
    if (p.root) {
        for (assigned.targets[0..assigned.len]) |target| {
            try dns_assigned.probe(p.gpa, target.address, .udp);
            try dns_assigned.probe(p.gpa, target.address, .tcp);
        }
        // unwound's resolvers are its upstream user's alone.
        const behind = configuredResolvers(upstream);
        for (behind.targets[0..behind.len]) |target| if (!assigned.contains(target.address)) {
            try dns_other.probe(p.gpa, target.address, .udp);
            try dns_other.probe(p.gpa, target.address, .tcp);
        };
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
            .why = "Root cannot ask unwound, the one resolver every program is assigned; " ++
                "network fetchers have their own lookup grants.",
            .evidence = dns_assigned,
        },
        .{
            .id = "network-root-dns-arbitrary",
            .name = "Root DNS to arbitrary servers blocked",
            .why = "Root cannot send DNS queries past unwound: not to its upstream resolvers, " ++
                "nor to any other server.",
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
    try rootEgress(&p, "nameserver 192.168.5.3\n", "", false);
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
        try sshConfig(p, sshd, if (exists(p.io, "/etc/ssh/operator.conf"))
            "/etc/ssh/operator.conf"
        else
            "/etc/ssh/sshd_config", false);
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

/// fence checks werewolf's network policy (docs/design/implemented/fence.md); policy is
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
    try rootEgress(p, p.read("/etc/resolv.conf"), p.read("/run/werewolf/network/upstream"), v6_on);
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
    const rules = rulesOf(p.gpa, linux.AF.INET);
    const inbound: posture.Check = .{
        .id = "network-inbound",
        .area = "network",
        .name = "Unsolicited traffic dropped",
        .why = "Packets the machine did not ask for and does not serve are dropped " ++
            "unanswered, whatever is listening, and local delivery cannot be abused " ++
            "across NIC addresses or by interactive logins.",
        .how = "the IPv4 policy-routing rules (RTM_GETRULE) blackhole arriving TCP and UDP " ++
            "(or everything) before any rule delivers it to the local table, pin non-root " ++
            "local delivery to 127.0.0.0/8, isolate people's uid ranges from undeclared " ++
            "loopback ports, and refuse locally sent traffic that no rule allows",
        .result = if (rules) |r|
            (if (r.complete()) .pass else .fail)
        else
            .skip,
        .detail = if (rules) |r| try ruleDetail(p.gpa, r) else unreadable,
    };
    if (rules == null) try p.fromBoot(inbound) else try p.add(inbound);

    const rules6: ?RuleSummary = if (v6_on) rulesOf(p.gpa, linux.AF.INET6) else .{};
    const ipv6: posture.Check = .{
        .id = "network-ipv6",
        .area = "network",
        .name = "IPv6 under the same policy",
        .why = "Every interface has an IPv6 address reachable from the network; IPv6 must " ++
            "not be a way around the IPv4 rules.",
        .how = "IPv6 is off (disable_ipv6 reads 1, or the kernel has none), or its " ++
            "policy-routing rules (RTM_GETRULE, AF_INET6) drop arriving traffic before " ++
            "delivering it, pin non-root local delivery to ::1/128, isolate people's uid " ++
            "ranges on ::1/128, and refuse locally sent traffic no rule allows",
        .result = if (!v6_on)
            .pass
        else if (rules6) |r|
            (if (r.complete()) .pass else .fail)
        else
            .skip,
        .detail = if (!v6_on)
            "IPv6 off"
        else if (rules6) |r|
            try ruleDetail(p.gpa, r)
        else
            unreadable,
    };
    if (rules6 == null) try p.fromBoot(ipv6) else try p.add(ipv6);
}

const unreadable = "this process may not open netlink, as an SSH session may not";

fn rulesOf(gpa: Allocator, family: u8) ?RuleSummary {
    const dump = ruleDump(gpa, family) catch |err|
        return if (err == error.Filtered) null else .{};
    return summarizeRules(dump);
}

fn ruleDetail(gpa: Allocator, r: RuleSummary) ![]const u8 {
    return gpa.print("arriving: {s}; sent: {s}; local: {s}; people: {s}", .{
        if (r.inbound_dropped) "dropped unless declared" else "delivered",
        if (r.outbound_refused) "refused unless declared" else "routed",
        if (r.local_pinned) "pinned to loopback" else "unpinned",
        if (r.people_isolated) "isolated on loopback" else "exposed on loopback",
    });
}

/// ssh_settings is what sshd -T must report: keys only, no host-based
/// trust, and no port or socket forwarding, tunnels or user environment. An
/// agent may be forwarded: ssh-su reauthenticates through it.
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
    // ENOSYS is a seccomp filter's answer; the kernel's would be another.
    if (linux.errno(rc) == .NOSYS) return error.Filtered;
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

fn ipv6RaLimits(p: *Posture) !void {
    const want = [_][2][]const u8{
        .{ "net/ipv6/conf/*/accept_ra_rtr_pref", "0" },
        .{ "net/ipv6/conf/*/accept_ra_rt_info_max_plen", "0" },
        .{ "net/ipv6/conf/*/accept_ra_mtu", "0" },
        .{ "net/ipv6/conf/*/max_addresses", "4" },
    };
    var bad: std.ArrayList(u8) = .empty;
    var observed: std.ArrayList(u8) = .empty;
    for (want) |kv| {
        const keys = try p.expand(kv[0]);
        for (keys) |key| {
            const value = p.sysctl(key);
            try listAdd(p.gpa, &observed, "/proc/sys/{s}={s}", .{
                key, if (value.len > 0) value else "unavailable",
            });
            if (!std.mem.eql(u8, value, kv[1]))
                try listAdd(
                    p.gpa,
                    &bad,
                    "{s} is {s}",
                    .{ key, if (value.len > 0) value else "absent" },
                );
        }
    }
    const broad = try broadIpv6Prefixes(p.gpa, p.read("/proc/net/if_inet6"));
    if (broad.len > 0) try listAdd(p.gpa, &bad, "broad IPv6 prefix: {s}", .{broad});
    try listAdd(
        p.gpa,
        &observed,
        "/proc/net/if_inet6 broad={s}",
        .{if (broad.len > 0) broad else "none"},
    );
    try p.add(.{
        .id = "network-ipv6-ra-limits",
        .area = "network",
        .name = "Router advertisements limited",
        .why = "A rogue router on the same network cannot rank itself above the real one, add a " ++
            "route or broad prefix to steal traffic, lower the MTU, or flood the machine with " ++
            "addresses.",
        .how = "net.ipv6.conf.*.accept_ra_rtr_pref, accept_ra_rt_info_max_plen and " ++
            "accept_ra_mtu are 0, max_addresses is 4, and /proc/net/if_inet6 has no " ++
            "global/ULA prefix broader than /48 or link-local broader than /64",
        .source = "/proc/sys/net/ipv6/conf/*/{accept_ra_rtr_pref,accept_ra_rt_info_max_plen," ++
            "accept_ra_mtu,max_addresses}; /proc/net/if_inet6",
        .observed = observed.items,
        .result = if (bad.items.len == 0) .pass else .fail,
        .detail = bad.items,
    });
}

fn broadIpv6Prefixes(gpa: Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        const hex_addr = words.next() orelse continue;
        _ = words.next() orelse continue; // ifindex
        const plen_hex = words.next() orelse continue;
        _ = words.next() orelse continue; // scope
        _ = words.next() orelse continue; // dad_status
        const nic = words.next() orelse continue;
        if (std.mem.eql(u8, nic, "lo") or hex_addr.len != 32) continue;
        var addr: [16]u8 = undefined;
        _ = std.fmt.hexToBytes(&addr, hex_addr) catch continue;
        const plen = std.fmt.parseInt(u8, plen_hex, 16) catch continue;
        if (plen == 128) continue;
        const link_local = addr[0] == 0xfe and (addr[1] & 0xc0) == 0x80;
        const floor: u8 = if (link_local) 64 else 48;
        if (plen < floor) try listAdd(gpa, &out, "{s} /{d}", .{ nic, plen });
    }
    return out.items;
}

fn stripHashComments(gpa: Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var quote: u8 = 0;
    var in_comment = false;
    for (text) |c| {
        if (in_comment) {
            if (c == '\n') {
                in_comment = false;
                try out.append(gpa, '\n');
            }
            continue;
        }
        if (quote != 0) {
            if (c == quote) quote = 0;
            try out.append(gpa, c);
            continue;
        }
        if (c == '"' or c == '\'') {
            quote = c;
            try out.append(gpa, c);
            continue;
        }
        if (c == '#') {
            in_comment = true;
            continue;
        }
        try out.append(gpa, c);
    }
    return out.items;
}

fn isWritableServeRoot(path: []const u8) bool {
    const clean = std.mem.trim(u8, path, "\"' \t\r\n");
    return std.mem.eql(u8, clean, "/data") or std.mem.startsWith(u8, clean, "/data/") or
        std.mem.eql(u8, clean, "/var") or std.mem.startsWith(u8, clean, "/var/");
}

fn isUnsafeNginxInclude(path: []const u8) bool {
    const clean = std.mem.trim(u8, path, "\"' \t\r\n");
    for ([_][]const u8{
        "/data/",
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/home/",
        "/werewolf/config/",
    }) |bad| if (std.mem.startsWith(u8, clean, bad)) return true;
    return false;
}

fn webConfigProblems(
    gpa: Allocator,
    nginx_raw: []const u8,
    caddy_raw: []const u8,
    oauth2_raw: []const u8,
) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    if (nginx_raw.len > 0) {
        const clean = try stripHashComments(gpa, nginx_raw);
        var serves_writable = false;
        var symlinks_on = false;
        var symlinks_off = false;
        var stmts = std.mem.tokenizeAny(u8, clean, ";{}\r\n");
        while (stmts.next()) |stmt| {
            var words = std.mem.tokenizeAny(u8, stmt, " \t");
            const dir = words.next() orelse continue;
            const arg1 = words.next() orelse continue;
            if (std.mem.eql(u8, dir, "root") or std.mem.eql(u8, dir, "alias")) {
                if (isWritableServeRoot(arg1)) serves_writable = true;
            } else if (std.mem.eql(u8, dir, "disable_symlinks")) {
                if (std.mem.eql(u8, arg1, "on")) symlinks_on = true;
                if (std.mem.eql(u8, arg1, "off")) symlinks_off = true;
            } else if (std.mem.eql(u8, dir, "include")) {
                if (isUnsafeNginxInclude(arg1))
                    try listAdd(gpa, &out, "nginx.conf includes writable path {s}", .{arg1});
            } else if (std.mem.eql(u8, dir, "set_real_ip_from")) {
                const cidr = std.mem.trim(u8, arg1, "\"'");
                if (std.mem.eql(u8, cidr, "0.0.0.0/0") or std.mem.eql(u8, cidr, "::/0"))
                    try listAdd(gpa, &out, "nginx.conf trusts forwarded IP from {s}", .{cidr});
            }
        }
        if (serves_writable and (!symlinks_on or symlinks_off))
            try listAdd(
                gpa,
                &out,
                "nginx.conf serves /data or /var without disable_symlinks on",
                .{},
            );
    }
    if (caddy_raw.len > 0) {
        const clean = try stripHashComments(gpa, caddy_raw);
        var has_file_server = false;
        var writable_root = false;
        var auto_https_off = false;
        var lines = std.mem.tokenizeAny(u8, clean, "\r\n{};");
        while (lines.next()) |line| {
            var words = std.mem.tokenizeAny(u8, line, " \t");
            const dir = words.next() orelse continue;
            if (std.mem.eql(u8, dir, "file_server")) {
                has_file_server = true;
            } else if (std.mem.eql(u8, dir, "auto_https")) {
                if (std.mem.eql(u8, words.next() orelse "", "off")) auto_https_off = true;
            } else if (std.mem.eql(u8, dir, "root")) {
                const a = words.next() orelse continue;
                const path = if (words.next()) |b| b else a;
                if (isWritableServeRoot(path)) writable_root = true;
            } else if (std.mem.eql(u8, dir, "trusted_proxies")) {
                while (words.next()) |w| {
                    const cidr = std.mem.trim(u8, w, "\"'");
                    if (std.mem.eql(u8, cidr, "0.0.0.0/0") or std.mem.eql(u8, cidr, "::/0"))
                        try listAdd(
                            gpa,
                            &out,
                            "Caddyfile trusts forwarded headers from {s}",
                            .{cidr},
                        );
                }
            }
        }
        if (has_file_server and writable_root and !auto_https_off)
            try listAdd(
                gpa,
                &out,
                "Caddyfile serves /data or /var with file_server while managing TLS keys",
                .{},
            );
    }
    if (oauth2_raw.len > 0) {
        const clean = try stripHashComments(gpa, oauth2_raw);
        var reverse_proxy = false;
        var public_listener = false;
        var lines = std.mem.tokenizeAny(u8, clean, "\r\n");
        while (lines.next()) |line| {
            const eq = std.mem.findScalar(u8, line, '=') orelse continue;
            const key = trim(line[0..eq]);
            const val = std.mem.trim(u8, line[eq + 1 ..], " \t\"'");
            if (std.mem.eql(u8, key, "reverse_proxy") and std.mem.eql(u8, val, "true"))
                reverse_proxy = true;
            if (std.mem.eql(u8, key, "http_address") and
                !std.mem.startsWith(u8, val, "127.") and
                !std.mem.startsWith(u8, val, "[::1]") and
                !std.mem.startsWith(u8, val, "unix:"))
                public_listener = true;
        }
        if (reverse_proxy and public_listener)
            try listAdd(
                gpa,
                &out,
                "oauth2-proxy.cfg trusts X-Forwarded-* on a non-loopback listener",
                .{},
            );
    }
    return out.items;
}

fn web(p: *Posture) !void {
    const has_nginx = exists(p.io, "/etc/nginx/nginx.conf");
    const has_caddy = exists(p.io, "/etc/caddy/Caddyfile");
    const has_oauth2 = exists(p.io, "/etc/oauth2-proxy/oauth2-proxy.cfg");
    if (!has_nginx and !has_caddy and !has_oauth2) return;

    const nginx_raw = if (has_nginx) p.read("/etc/nginx/nginx.conf") else "";
    const caddy_raw = if (has_caddy) p.read("/etc/caddy/Caddyfile") else "";
    const oauth2_raw = if (has_oauth2) p.read("/etc/oauth2-proxy/oauth2-proxy.cfg") else "";
    const unread = (has_nginx and nginx_raw.len == 0) or
        (has_caddy and caddy_raw.len == 0) or
        (has_oauth2 and oauth2_raw.len == 0);

    var bad: std.ArrayList(u8) = .empty;
    const problems = try webConfigProblems(p.gpa, nginx_raw, caddy_raw, oauth2_raw);
    if (problems.len > 0) try bad.appendSlice(p.gpa, problems);

    if (nginx_raw.len > 0) {
        const clean = try stripHashComments(p.gpa, nginx_raw);
        var stmts = std.mem.tokenizeAny(u8, clean, ";{}\r\n");
        while (stmts.next()) |stmt| {
            var words = std.mem.tokenizeAny(u8, stmt, " \t");
            if (!std.mem.eql(u8, words.next() orelse "", "include")) continue;
            const target = std.mem.trim(u8, words.next() orelse continue, "\"'");
            if (!std.mem.startsWith(u8, target, "/run/") and
                !std.mem.startsWith(u8, target, "/var/")) continue;
            const dir = std.fs.path.dirname(target) orelse continue;
            if (statx(p.gpa, dir)) |st| if (st.mode & 0o022 != 0)
                try listAdd(
                    p.gpa,
                    &bad,
                    "nginx include directory {s} is writable by others",
                    .{dir},
                );
        }
    }

    try p.add(.{
        .id = "network-web-config",
        .area = "network",
        .name = "Web servers isolate symlinks, includes and client IP headers",
        .why = "A web server that follows symlinks in writable storage, includes configuration " ++
            "from writable paths, or trusts X-Forwarded-* from any client exposes TLS keys, " ++
            "code execution or IP spoofing.",
        .how = "nginx.conf disables symlinks when serving /data or /var, includes no writable " ++
            "tree, and never trusts real_ip from 0.0.0.0/0 or ::/0; Caddyfile never serves " ++
            "/data or /var with file_server while managing TLS; oauth2-proxy disables " ++
            "reverse_proxy on non-loopback listeners",
        .result = if (bad.items.len > 0) .fail else if (unread) .skip else .pass,
        .detail = if (bad.items.len > 0)
            bad.items
        else if (unread)
            "cannot read web server configuration"
        else
            "",
    });
}

const RuleSummary = struct {
    /// outbound_refused is set if a rule with no selector but iif lo
    /// prohibits whatever locally sent traffic no earlier rule allowed.
    outbound_refused: bool = false,
    /// inbound_dropped is set if arriving traffic is dropped before any
    /// rule without selectors delivers it to the local table.
    inbound_dropped: bool = false,
    /// local_pinned is set if non-root local-table delivery on lo is pinned to
    /// 127.0.0.0/8 (IPv4) or ::1/128 (IPv6), never assigned NIC addresses.
    local_pinned: bool = false,
    /// people_isolated is set if people's uid ranges are prohibited from
    /// undeclared loopback destinations before non-root local delivery.
    people_isolated: bool = false,

    fn complete(r: RuleSummary) bool {
        return r.inbound_dropped and r.outbound_refused and
            r.local_pinned and r.people_isolated;
    }
};

fn isLoopbackDst(family: u8, dst_len: u8, dst: []const u8, full_net_only: bool) bool {
    if (family == linux.AF.INET) {
        if (dst.len != 4 or dst[0] != 127) return false;
        return dst_len == 8 or (!full_net_only and dst_len == 32);
    }
    if (family == linux.AF.INET6) {
        return dst_len == 128 and dst.len == 16 and
            std.mem.allEqual(u8, dst[0..15], 0) and dst[15] == 1;
    }
    return false;
}

/// summarizeRules reads a policy-routing rule dump for traffic in and out.
fn summarizeRules(dump: []const u8) RuleSummary {
    // Find where arriving traffic is first dropped, either all of it or TCP
    // and UDP by name (as fence does, so ARP's lookup still finds the address
    // local), and where it is first delivered.
    var drop_at: ?u32 = null;
    var tcp_drop_at: ?u32 = null;
    var udp_drop_at: ?u32 = null;
    var local_at: ?u32 = null;
    var local_out_at: ?u32 = null;
    var unpinned_local_out = false;
    var people_refused_at: [people.ids.len]?u32 = @splat(null);
    var out_refused = false;
    var off: usize = 0;
    while (off + 28 <= dump.len) {
        const len = std.mem.readInt(u32, dump[off..][0..4], .little);
        if (len < 16 or off + len > dump.len) break;
        const msg = dump[off .. off + len];
        off += std.mem.alignForward(usize, len, 4);
        if (std.mem.readInt(u16, msg[4..6], .little) != 32 or msg.len < 28) continue; // RTM_NEWRULE
        const family = msg[16];
        const dst_len = msg[17];
        var table: u32 = msg[16 + 4];
        const action = msg[16 + 7];
        var priority: u32 = 0;
        var from_lo = false;
        var iif = false;
        var other_sel = false;
        var dst: []const u8 = "";
        var uid_range: ?[2]u32 = null;
        var has_dport = false;
        var proto: ?u8 = null;
        var a: usize = 28;
        while (a + 4 <= msg.len) {
            const alen = std.mem.readInt(u16, msg[a..][0..2], .little);
            if (alen < 4 or a + alen > msg.len) break;
            const kind = std.mem.readInt(u16, msg[a + 2 ..][0..2], .little) & 0x3fff;
            const v = msg[a + 4 .. a + alen];
            switch (kind) {
                1 => dst = v,
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
                20 => if (v.len == 8) {
                    uid_range = .{
                        std.mem.readInt(u32, v[0..4], .little),
                        std.mem.readInt(u32, v[4..8], .little),
                    };
                } else {
                    other_sel = true;
                },
                22 => if (v.len == 1) {
                    proto = v[0];
                },
                24 => has_dport = true,
                2, 10, 17, 23 => other_sel = true, // src, fwmark, oif, sport
                else => {},
            }
            a += std.mem.alignForward(usize, alen, 4);
        }
        const selective = dst_len != 0 or dst.len != 0 or uid_range != null or
            has_dport or other_sel;
        if (from_lo and !other_sel) {
            if (action == 1 and table == 255) {
                const root_only = uid_range != null and uid_range.?[0] == 0 and uid_range.?[1] == 0;
                if (isLoopbackDst(family, dst_len, dst, true) and
                    uid_range == null and proto == null and !has_dport)
                {
                    local_out_at = @min(local_out_at orelse priority, priority);
                } else if (!root_only and !isLoopbackDst(family, dst_len, dst, false)) {
                    unpinned_local_out = true;
                }
            } else if (action == 8 and proto == null and !has_dport and
                isLoopbackDst(family, dst_len, dst, true))
            {
                if (uid_range) |ur| {
                    for (people.ids, 0..) |want, idx| {
                        if (ur[0] == want[0] and ur[1] == want[1])
                            people_refused_at[idx] = @min(
                                people_refused_at[idx] orelse priority,
                                priority,
                            );
                    }
                }
            }
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
    const local_pinned = local_out_at != null and !unpinned_local_out;
    const people_isolated = if (local_out_at) |lo_at| blk: {
        for (people_refused_at) |ref_at| {
            if (ref_at == null or ref_at.? >= lo_at) break :blk false;
        }
        break :blk true;
    } else false;
    return .{
        .outbound_refused = out_refused,
        .inbound_dropped = dropped,
        .local_pinned = local_pinned,
        .people_isolated = people_isolated,
    };
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

const TestRuleOptions = struct {
    dst_len: u8 = 0,
    dst: ?[]const u8 = null,
    uid_range: ?[2]u32 = null,
};

/// testRule builds a netlink rule message with priority, action, table, and
/// the given iif name, protocol and optional selectors.
fn testRule(
    buf: []u8,
    priority: u32,
    action: u8,
    table: u8,
    iif: ?[]const u8,
    proto: ?u8,
    opts: TestRuleOptions,
) []const u8 {
    @memset(buf, 0);
    var n: usize = 28;
    buf[16] = linux.AF.INET;
    buf[17] = opts.dst_len;
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
    if (opts.dst) |d| put(buf, &n, 1, d);
    if (opts.uid_range) |ur| {
        var raw: [8]u8 = undefined;
        std.mem.writeInt(u32, raw[0..4], ur[0], .little);
        std.mem.writeInt(u32, raw[4..8], ur[1], .little);
        put(buf, &n, 20, &raw);
    }
    std.mem.writeInt(u32, buf[0..4], @intCast(n), .little);
    std.mem.writeInt(u16, buf[4..6], 32, .little);
    return buf[0..n];
}

test summarizeRules {
    var dump: std.ArrayList(u8) = .empty;
    defer dump.deinit(std.testing.allocator);
    var b: [96]u8 = undefined;
    // The kernel's own rules (local at 0, main) drop nothing.
    try dump.appendSlice(std.testing.allocator, testRule(&b, 0, 1, 255, null, null, .{}));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 32766, 1, 254, null, null, .{}));
    try std.testing.expectEqual(RuleSummary{}, summarizeRules(dump.items));

    // fence's rules: people's loopback refusal before loopback-pinned local_out
    // (plus root's local_out), allowances, refusal from lo, ICMP in, TCP/UDP
    // drops, then the moved local rule.
    dump.clearRetainingCapacity();
    for (people.ids) |range| try dump.appendSlice(
        std.testing.allocator,
        testRule(&b, 9, 8, 0, "lo\x00", null, .{
            .dst_len = 8,
            .dst = &.{ 127, 0, 0, 0 },
            .uid_range = range,
        }),
    );
    try dump.appendSlice(
        std.testing.allocator,
        testRule(&b, 10, 1, 255, "lo\x00", null, .{ .dst_len = 8, .dst = &.{ 127, 0, 0, 0 } }),
    );
    try dump.appendSlice(
        std.testing.allocator,
        testRule(&b, 10, 1, 255, "lo\x00", null, .{ .uid_range = .{ 0, 0 } }),
    );
    try dump.appendSlice(std.testing.allocator, testRule(&b, 200, 1, 254, "lo\x00", 6, .{}));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 299, 8, 0, "lo\x00", null, .{}));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 300, 1, 255, null, 1, .{}));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, 6, .{}));
    const tcp_only = dump.items.len;
    try dump.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, 17, .{}));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 400, 1, 255, null, null, .{}));
    const full = summarizeRules(dump.items);
    try std.testing.expectEqual(RuleSummary{
        .outbound_refused = true,
        .inbound_dropped = true,
        .local_pinned = true,
        .people_isolated = true,
    }, full);
    try std.testing.expect(full.complete());

    // Unpinned local_out on lo (without dst 127.0.0.0/8 or root uid 0..0) fails local_pinned.
    var unpinned: std.ArrayList(u8) = .empty;
    defer unpinned.deinit(std.testing.allocator);
    try unpinned.appendSlice(std.testing.allocator, dump.items);
    try unpinned.appendSlice(std.testing.allocator, testRule(&b, 11, 1, 255, "lo\x00", null, .{}));
    try std.testing.expect(!summarizeRules(unpinned.items).local_pinned);
    try std.testing.expect(!summarizeRules(unpinned.items).complete());

    // Dropping TCP but not UDP does not count as dropped.
    var half: std.ArrayList(u8) = .empty;
    defer half.deinit(std.testing.allocator);
    try half.appendSlice(std.testing.allocator, dump.items[0..tcp_only]);
    try half.appendSlice(std.testing.allocator, testRule(&b, 400, 1, 255, null, null, .{}));
    try std.testing.expect(!summarizeRules(half.items).inbound_dropped);

    // Dropping everything counts too.
    var all: std.ArrayList(u8) = .empty;
    defer all.deinit(std.testing.allocator);
    try all.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, null, .{}));
    try all.appendSlice(std.testing.allocator, testRule(&b, 400, 1, 255, null, null, .{}));
    try std.testing.expect(summarizeRules(all.items).inbound_dropped);

    // A drop that comes after delivery to the local table drops nothing.
    var late: std.ArrayList(u8) = .empty;
    defer late.deinit(std.testing.allocator);
    try late.appendSlice(std.testing.allocator, testRule(&b, 0, 1, 255, null, null, .{}));
    try late.appendSlice(std.testing.allocator, testRule(&b, 399, 6, 0, null, null, .{}));
    try std.testing.expect(!summarizeRules(late.items).inbound_dropped);

    // Truncated input is not trusted past its end.
    try std.testing.expectEqual(RuleSummary{}, summarizeRules(dump.items[0..20]));
}

test broadIpv6Prefixes {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const ok =
        "00000000000000000000000000000001 01 80 10 80 lo\n" ++
        "fe8000000000000002163efffe123456 02 40 20 80 eth0\n" ++
        "20010db8000000010000000000000001 02 40 00 80 eth0\n";
    try testing.expectEqualStrings("", try broadIpv6Prefixes(gpa, ok));

    const poisoned = ok ++
        "80000000000000000000000000000001 02 01 00 80 eth0\n" ++
        "fe8000000000000002163efffe123456 03 20 20 80 eth1\n";
    try testing.expectEqualStrings("eth0 /1, eth1 /32", try broadIpv6Prefixes(gpa, poisoned));
}

test webConfigProblems {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    // Clean nginx + Caddy + oauth2-proxy configurations pass.
    try testing.expectEqualStrings(
        "",
        try webConfigProblems(
            gpa,
            "http { disable_symlinks on from=$document_root; server { root /data/www; } }\n",
            "example.com {\n  root * /usr/share/www\n  file_server\n}\n",
            "http_address = \"0.0.0.0:4180\"\nreverse_proxy = false\n",
        ),
    );

    // Unsafe symlink, writable include, and spoofed X-Forwarded-* configurations fail.
    const bad = try webConfigProblems(
        gpa,
        "http { include /werewolf/config/http/*.conf; set_real_ip_from 0.0.0.0/0; server { root " ++
            "/data/www; } }\n",
        "example.com {\n  root * /data/svc/app\n  file_server\n}\n",
        "http_address = \"0.0.0.0:4180\"\nreverse_proxy = true\n",
    );
    try testing.expect(std.mem.find(u8, bad, "includes writable path") != null);
    try testing.expect(std.mem.find(u8, bad, "trusts forwarded IP") != null);
    try testing.expect(std.mem.find(u8, bad, "without disable_symlinks on") != null);
    try testing.expect(std.mem.find(u8, bad, "Caddyfile serves /data or /var") != null);
    try testing.expect(std.mem.find(u8, bad, "oauth2-proxy.cfg trusts X-Forwarded-*") != null);
}

test unusedPort {
    try std.testing.expectEqual(47321, unusedPort(""));
    try std.testing.expectEqual(47322, unusedPort("listen tcp 47321\n"));
}
