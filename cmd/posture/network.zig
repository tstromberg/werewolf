//! posture's network checks: listening ports, fence's rules, IPv6, and
//! ssh's settings.

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
    // IPv6 is on unless disable_ipv6 reads 1, or the kernel has none.
    const v6 = p.sysctl("net/ipv6/conf/all/disable_ipv6");
    const v6_on = v6.len > 0 and !std.mem.eql(u8, v6, "1");
    var ports: std.ArrayList(u16) = .empty;
    for ([_][]const u8{
        "/proc/net/tcp",
        "/proc/net/tcp6",
    }) |f| try listenPorts(p.gpa, p.read(f), &ports);
    var list: std.ArrayList(u8) = .empty;
    for (ports.items) |port| try listAdd(p.gpa, &list, "{d}", .{port});
    // The machine's network policy (fence), or the older list of ports.
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
    try p.absent(
        "network-no-login",
        "network",
        "No remote login",
        "There is no ssh or telnet server to log in through.",
        &.{ "sshd", "dropbear", "telnetd", "in.telnetd" },
    );
    try ssh(p);
    // With IPv6 off (ipv6.disable=1), there is no IPv6 forwarding to check.
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
    // A host takes and sends redirects on an interface if all or the
    // interface says so, so each interface must say no: all and default
    // do not reach an interface that was there before they were set.
    // IPv6 has only the interface's own setting. With IPv6 off, its
    // settings govern nothing.
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
    // IPv4 takes a source route only if all and the interface both allow it.
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
    // Loopback addresses are routed to an interface if all or the interface
    // says so.
    try p.sysctls(
        "network-localnet",
        "network",
        "Loopback stays local",
        "Nothing on the network can reach what listens on 127.0.0.1 alone, by routing " ++
            "a packet for it through an interface.",
        &.{.{ "net/ipv4/conf/*/route_localnet", "0" }},
    );
    // Router advertisements stay on (IPv6 takes its route from them), but
    // limited to what they must give.
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
    // --extended only, as werewolf fails them by choice (docs/security.md,
    // "Not done, by choice"): strict reverse-path filtering waits until it
    // is shown to work with fence, and IPv6 takes its route from router
    // advertisements.
    if (p.extended) {
        // The kernel takes the stricter of all and the interface for both.
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

fn ssh(p: *Posture) !void {
    const sshd = for ([_][]const u8{ "/usr/sbin/sshd", "/usr/bin/sshd" }) |path| {
        if (exists(p.io, path)) break path;
    } else return;
    const settings: ?[]const u8 = if (!p.root) null else if (std.process.run(p.gpa, p.io, .{
        .argv = &.{ sshd, "-T" },
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
        const config = "/etc/ssh/sshd_config";
        if (statx(p.gpa, config)) |st| if (st.uid != 0 or st.mode & 0o022 != 0)
            try listAdd(p.gpa, &loose, "{s} is not root's alone", .{config});
        // Each host key, as sshd -T lists them, one "hostkey PATH" a line.
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
        .id = "network-ssh-config",
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
        .id = "network-ssh-crypto",
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
        .id = "network-ssh-security-keys",
        .area = "network",
        .name = "ssh takes security keys alone",
        .why = "Logging in takes a security key, and a touch of it: a key file copied off " ++
            "an operator's laptop, or used there by malware while they are away, signs " ++
            "nothing.",
        .how = "sshd -T lists only security-key algorithms (sk-...) in " ++
            "pubkeyacceptedalgorithms, and touch-required in pubkeyauthoptions",
        .result = if (settings == null) .skip else if (plain.len == 0) .pass else .fail,
        .detail = if (settings == null) skipped else plain,
    });
}

/// What sshd -T takes that is not a security key's, touched: each
/// algorithm without the sk- of a FIDO authenticator's, and pubkeyauthoptions
/// without touch-required, which an authorized_keys line's no-touch-required
/// could otherwise turn off.
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

/// How far a guesser or a forgotten session gets: what sshd -T reports
/// beyond what the benchmarks allow, as a list, with a comma first if
/// continuing one.
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
    // start:rate:full. Refusing starts at start unauthenticated connections
    // and is total at full.
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

/// werewolf's network policy (docs/design/fence.md), "" where there is
/// none: only declared ports can be bound, only declared traffic sent,
/// nothing unsolicited received, the metadata server only for those named,
/// IPv6 off. Each protection is tested where a test is safe and quiet (a
/// bind, a UDP connect, which sends nothing, a connect the policy refuses
/// at once), and fails where it is missing, on any Linux.
fn fence(p: *Posture, policy: []const u8, v6_on: bool) !void {
    const port = unusedPort(policy);
    const bound = probeBind(port);
    try p.add(.{
        .id = "network-bind",
        .area = "network",
        .name = "Undeclared ports cannot be opened",
        .why = "Not even root can start a listener on a port the machine is not meant to " ++
            "offer.",
        .how = try p.gpa.print(
            "bind() of a TCP socket to port {d}, which the policy does not declare, is " ++
                "refused with EACCES (Landlock, inherited from PID 1)",
            .{port},
        ),
        .result = if (bound == .ACCES) .pass else .fail,
        .detail = try p.gpa.print("bind: {s}", .{errnoText(bound)}),
    });

    const sent = probeSend();
    try p.add(.{
        .id = "network-outbound",
        .area = "network",
        .name = "Only declared traffic leaves",
        .why = "A program can send nothing its form did not declare: no beacon, no " ++
            "exfiltration, no download.",
        .how = "connect() of a UDP socket to 192.0.2.1 port 9 (an address for " ++
            "documentation, never routed), which looks the route up without sending, is " ++
            "refused with EACCES (policy routing)",
        .result = if (sent == .ACCES) .pass else .fail,
        .detail = try p.gpa.print("connect: {s}", .{errnoText(sent)}),
    });

    const md = probeMetadata();
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
            // Nothing there and no policy to refuse it: not a cloud.
            .absent => if (policy.len == 0) .skip else .fail,
        },
        .detail = @tagName(md),
    });

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

/// What sshd -T must report, by its names: keys only, no host-based trust,
/// and no forwarding, tunnels or user environment.
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

/// key's value in sshd -T's output, "key value" a line, or null. Its names
/// are lowercase in some OpenSSH releases and CamelCase in others (10.x:
/// StrictModes yes).
fn sshValue(settings: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, settings, '\n');
    while (it.next()) |line| {
        if (line.len > key.len and std.ascii.startsWithIgnoreCase(line, key) and
            line[key.len] == ' ') return trim(line[key.len + 1 ..]);
    }
    return null;
}

/// The settings in want that sshd -T reports otherwise, as a list.
fn sshMismatches(gpa: Allocator, settings: []const u8, want: []const [2][]const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (want) |kv| {
        const v = sshValue(settings, kv[0]) orelse v: {
            // An sshd built without X11 or GSSAPI (Wolfi's) lists neither
            // setting, and can do neither at all.
            if (std.mem.eql(u8, kv[0], "x11forwarding") or
                std.mem.eql(u8, kv[0], "gssapiauthentication")) continue;
            break :v "absent";
        };
        if (!std.mem.eql(u8, v, kv[1])) try listAdd(gpa, &out, "{s} is {s}", .{ kv[0], v });
    }
    return out.items;
}

/// What makes an algorithm weak, by the sshd -T list it is in.
const ssh_weak = [_]struct { []const u8, []const []const u8 }{
    .{ "ciphers", &.{ "-cbc", "arcfour", "3des" } },
    .{ "macs", &.{ "md5", "sha1", "umac-64", "-96" } },
    .{ "kexalgorithms", &.{"sha1"} },
    .{ "hostkeyalgorithms", &.{ "ssh-rsa", "ssh-dss" } },
    .{ "pubkeyacceptedalgorithms", &.{ "ssh-rsa", "ssh-dss" } },
};

/// The key exchanges that stand up to a quantum computer, one of which
/// sshd must offer: a recording of a session made today could otherwise
/// be read once one exists.
const ssh_post_quantum = [_][]const u8{ "mlkem768x25519-sha256", "sntrup761x25519-sha512" };

/// The weak algorithms sshd -T lists, each once, and the post-quantum
/// key exchange it lacks.
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

/// The local ports of sockets listening on the network in /proc/net/tcp
/// or tcp6, each once, in order. A socket bound to a loopback address
/// alone serves the machine's own processes (a service's cluster port on
/// 127.0.0.1), and fence lets nothing from the network reach it, so it is
/// not a port the machine offers.
fn listenPorts(gpa: Allocator, text: []const u8, out: *std.ArrayList(u16)) !void {
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    _ = lines.next(); // the header
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

/// Whether a /proc/net/tcp local address, little-endian hex words, is
/// 127.0.0.0/8 or ::1 (or ::ffff:127.0.0.0/8).
fn isLoopback(hex: []const u8) bool {
    if (hex.len == 8) return std.mem.endsWith(u8, hex, "7F");
    if (hex.len != 32) return false;
    if (std.mem.eql(u8, hex, "00000000000000000000000001000000")) return true;
    return std.mem.eql(u8, hex[0..24], "0000000000000000FFFF0000") and
        std.mem.endsWith(u8, hex, "7F");
}

/// The ports in a network policy's `listen tcp PORT` lines, one a line.
fn policyPorts(gpa: Allocator, policy: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, policy, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "listen tcp "))
            try out.print(gpa, "{s}\n", .{std.mem.trim(u8, line["listen tcp ".len..], " ")});
    }
    return out.items;
}

/// Whether /etc/werewolf/listen declares port: one a line, or 22 for sshd,
/// which the image declares by carrying it.
fn isDeclared(text: []const u8, port: u16) bool {
    var it = std.mem.tokenizeAny(u8, text, " \n");
    while (it.next()) |d| if ((std.fmt.parseInt(u16, d, 10) catch 0) == port) return true;
    return false;
}

/// A TCP port the policy does not declare, to try binding.
fn unusedPort(policy: []const u8) u16 {
    var port: u16 = 47321;
    while (isDeclared(policy, port)) port += 1;
    return port;
}

fn inet(addr: [4]u8, port: u16) linux.sockaddr.in {
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(addr) };
}

/// bind() of a fresh TCP socket to `port` on every address: its errno. The
/// socket never listens, and is closed.
fn probeBind(port: u16) linux.E {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return linux.errno(rc);
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const a = inet(.{ 0, 0, 0, 0 }, port);
    return linux.errno(linux.bind(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in)));
}

/// connect() of a UDP socket to 192.0.2.1:9: a route lookup, and no packet.
fn probeSend() linux.E {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return linux.errno(rc);
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const a = inet(.{ 192, 0, 2, 1 }, 9);
    return linux.errno(linux.connect(fd, @ptrCast(&a), @sizeOf(linux.sockaddr.in)));
}

const Metadata = enum { refused, reached, absent };

/// A TCP connect() to 169.254.169.254:80, given a second: refused by
/// policy, reached (connected, or something answered), or absent.
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

/// A family's policy-routing rules, as the kernel lists them: RTM_GETRULE
/// messages, one after another. Listing them needs no privilege.
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

/// Whether a batch of netlink messages ends the dump.
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
    /// A rule refuses whatever is sent here (from lo) that no earlier rule
    /// allowed: no selector but the interface, action prohibit.
    outbound_refused: bool = false,
    /// A rule drops whatever arrives that no earlier rule allowed, and no
    /// rule without selectors delivers to the local table before it.
    inbound_dropped: bool = false,
};

/// What a dump of policy-routing rules says about traffic in and out.
fn summarizeRules(dump: []const u8) RuleSummary {
    // Where arriving traffic is first dropped: all of it, or TCP and UDP
    // by name, as fence does so that ARP's lookup still finds the address
    // local; and where it is first delivered.
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
        // To the local table.
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
    // 22 is bound to 127.0.0.1 alone: the machine's own, not offered.
    try testing.expectEqualSlices(u16, &.{ 80, 8201 }, ports.items);
    try testing.expect(isLoopback("0100007F") and isLoopback("0A00007F"));
    try testing.expect(isLoopback("00000000000000000000000001000000"));
    try testing.expect(isLoopback("0000000000000000FFFF00000100007F"));
    try testing.expect(!isLoopback("00000000") and !isLoopback("0F05A8C0"));
    try testing.expect(!isLoopback("00000000000000000000000000000000"));
    try testing.expect(isDeclared("80\n", 80));
    const policy = try policyPorts(
        arena.allocator(),
        "listen tcp 22\nlisten tcp 80\nmetadata 68\n",
    );
    try testing.expectEqualStrings("22\n80\n", policy);
    try testing.expect(isDeclared(policy, 80) and !isDeclared(policy, 68));
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

/// A netlink rule message for the tests: priority, action, table, and the
/// iif name and selectors given.
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
    // The kernel's own rules: local at 0, main, default. Nothing dropped.
    try dump.appendSlice(std.testing.allocator, testRule(&b, 0, 1, 255, null, null));
    try dump.appendSlice(std.testing.allocator, testRule(&b, 32766, 1, 254, null, null));
    try std.testing.expectEqual(RuleSummary{}, summarizeRules(dump.items));

    // fence's: local first only for lo, allowances with selectors, the
    // refusal from lo, ICMP in, the drops of TCP and UDP, then the local
    // rule moved after them.
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

    // TCP dropped and UDP not is not dropped.
    var half: std.ArrayList(u8) = .empty;
    defer half.deinit(std.testing.allocator);
    try half.appendSlice(std.testing.allocator, dump.items[0..tcp_only]);
    try half.appendSlice(std.testing.allocator, testRule(&b, 400, 1, 255, null, null));
    try std.testing.expect(!summarizeRules(half.items).inbound_dropped);

    // A drop of everything counts too.
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
