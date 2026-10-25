//! check-unwound-tunnels runs real DNS tunnel clients against their local
//! servers, first directly and then through the screened resolver, in
//! check-unwound's private world, as root.
//!
//!     check-unwound-tunnels FENCE UNWOUND SHELLACK_SERVER SHELLACK_CLIENT
//!
//! iodine, iodined, dns2tcpc, dns2tcpd, iptables-nft and timeout must be
//! installed. SHELLACK_SERVER is a Linux build of shellack's cmd/server and
//! SHELLACK_CLIENT its shellack.sh. No external network or DNS is used.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const lab = @import("unwound/lab.zig");
const linux = std.os.linux;
const mem = std.mem;
const netns = host.netns;
const fixture = lab.fixture;

// Separate services make a refused tunnel's budget independent of the others.
const policy =
    \\listen tcp 53 loopback
    \\dns 54
    \\lookup 0 * A AAAA
    \\lookup 2002 * TXT
    \\lookup 2003 * SRV CAA
    \\
;

pub fn main(init: std.process.Init) !void {
    const l = lab.Lab.init(init, "check-unwound-tunnels");
    const args = try init.minimal.args.toSlice(l.gpa);
    if (try lab.role(l, args)) return;
    if (args.len == 4 and
        mem.eql(
            u8,
            args[1],
            "--echo",
        )) return echo(args[2], try std.fmt.parseInt(u16, args[3], 10));
    if (args.len == 3 and
        mem.eql(
            u8,
            args[1],
            "--echo-probe",
        )) return echoProbe(try std.fmt.parseInt(u16, args[2], 10));
    if (args.len == 7 and mem.eql(u8, args[1], "--inside")) return inside(l, args[2], args[3..7]);
    if (args.len != 5) {
        l.log(
            "usage",
            .{ .usage = "check-unwound-tunnels FENCE UNWOUND SHELLACK_SERVER SHELLACK_CLIENT" },
        );
        std.process.exit(2);
    }
    if (builtin.os.tag != .linux or linux.geteuid() != 0) return l.fail("needs_linux_root", .{});
    var inner: std.ArrayList([]const u8) = .empty;
    try inner.appendSlice(l.gpa, &.{ "--inside", try l.namespace("net") });
    for (args[1..]) |path| try inner.append(
        l.gpa,
        try std.Io.Dir.cwd().realPathFileAlloc(l.io, path, l.gpa),
    );
    try l.enter(&.{ "--net", "--mount" }, inner.items);
}

fn inside(l: lab.Lab, parent_net: []const u8, paths: []const [:0]const u8) !void {
    if (mem.eql(u8, try l.namespace("net"), parent_net)) return l.fail("shared_network", .{});
    try l.private();
    var w = try lab.World.init(l, "werewolf-tunnels");
    defer w.stop();
    try w.mount(paths[1], policy, .{});
    try w.network(&.{fixture.upstream ++ "/24"});
    errdefer w.failed();
    // The driver keeps unwound answering on 127.0.0.53; the clients ask it.
    _ = try w.start(paths[0]);
    try checks(&w, paths[2], paths[3]);
    l.log("pass", .{ .why = "direct sessions worked; all three screened sessions stopped" });
}

/// Servers are the tunnel servers in the peer namespace.
const Servers = struct {
    w: *lab.World,
    running: std.ArrayList(netns.Child) = .empty,

    /// start runs argv in the peer namespace, its output in work/log.
    fn start(s: *Servers, argv: []const []const u8, log: []const u8) !void {
        const fd = try s.w.l.create(try s.w.path(log));
        defer netns.close(fd);
        try s.running.append(
            s.w.l.gpa,
            try s.w.l.spawn(
                try s.w.inPeer(argv),
                .{ .stdout = .{ .fd = fd }, .stderr = .{ .fd = fd } },
            ),
        );
        netns.nap(300);
        const child = &s.running.items[s.running.items.len - 1];
        if (try child.wait(0) != null) return s.w.l.fail(
            "server_exited",
            .{ .argv = argv, .log = try s.w.l.read(try s.w.path(log)) },
        );
    }

    fn stop(s: *Servers) void {
        for (s.running.items) |*child| child.signal(.TERM);
        for (s.running.items) |*child| child.stop();
    }
};

/// client runs a tunnel client for at most seconds and returns what it
/// said. A tunnel that works stays up, so its timeout is expected.
fn client(
    w: *lab.World,
    argv: []const []const u8,
    uid: ?u32,
    seconds: u32,
    env: ?[]const []const u8,
) ![]const u8 {
    const l = w.l;
    var all: std.ArrayList([]const u8) = .empty;
    try all.appendSlice(l.gpa, &.{ "timeout", "-s", "TERM", try l.gpa.print("{d}", .{seconds}) });
    try all.appendSlice(l.gpa, argv);
    const out = try w.path("client.out");
    const fd = try l.create(out);
    var child = try l.spawn(
        all.items,
        .{ .stdout = .{ .fd = fd }, .stderr = .{ .fd = fd }, .uid = uid, .env = env },
    );
    netns.close(fd);
    _ = try child.wait(null);
    return l.read(out);
}

/// config is what shellack.sh decodes with `tr 012. .201`.
fn config(gpa: mem.Allocator, address: []const u8, port: u16) ![]const u8 {
    const text = try gpa.print("-port={d} {s}", .{ port, address });
    for (text) |*ch| ch.* = switch (ch.*) {
        '.' => '0',
        '2' => '1',
        '0' => '2',
        '1' => '.',
        else => ch.*,
    };
    return text;
}

fn checks(w: *lab.World, shellack_server: []const u8, shellack_client: []const u8) !void {
    const l = w.l;
    // BIND's nslookup in the lab VM rejects the /etc tmpfs symlink.
    try std.Io.Dir.cwd().deleteFile(l.io, "/etc/resolv.conf");
    try l.write("/etc/resolv.conf", "nameserver 127.0.0.53\n");
    const magic = try l.gpa.print("unwound-test-{d}", .{linux.getpid()});
    const shellack_file = try l.gpa.print("/tmp/{s}.aiff", .{magic});
    var servers: Servers = .{ .w = w };
    defer servers.stop();
    defer std.Io.Dir.cwd().deleteFile(l.io, shellack_file) catch {};
    for ([_][]const u8{ "10.53.0.3/24", "10.53.0.4/24", "10.53.0.5/24" }) |a|
        try l.run(&.{ "ip", "-n", "unwound-peer", "addr", "add", a, "dev", "peer" });
    try l.write(try w.path("dns2tcpd.conf"),
        \\listen = 10.53.0.4
        \\port = 53
        \\user = nobody
        \\chroot = /tmp
        \\domain = tunnel.test
        \\resources = echo:10.53.0.4:16000
        \\
    );
    // dns2tcpd drops to nobody after binding its socket.
    try l.write(
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534::/tmp:/bin/sh\n",
    );
    try l.write("/etc/group", "root:x:0:\nnogroup:x:65534:\n");
    // Ubuntu's awk is an alternatives link; shellack's pipeline needs it.
    try l.mkdir("/etc/alternatives", 0o755);
    try l.symlink("/usr/bin/mawk", "/etc/alternatives/awk");

    try servers.start(
        &.{ "iodined", "-f", "-l", "10.53.0.3", "-P", "local-test", "10.88.0.1", "tunnel.test" },
        "iodined.log",
    );
    try servers.start(&.{ w.self, "--echo", "10.53.0.4", "16000" }, "echo.log");
    try servers.start(&.{ "dns2tcpd", "-F", "-f", try w.path("dns2tcpd.conf") }, "dns2tcpd.log");
    // shellack's server binds all interfaces, so it takes another port; the
    // peer redirects only questions for its own .5 address there.
    try servers.start(&.{ shellack_server, "10553", "printf shellack-ok" }, "shellack.log");

    const iodine = [_][]const u8{ "iodine", "-r", "-f", "-P", "local-test", "-T", "A" };
    const direct = try client(
        w,
        try w.inPeer(&(iodine ++ [_][]const u8{ "10.53.0.3", "tunnel.test" })),
        null,
        12,
        null,
    );
    if (mem.find(u8, direct, "Connection setup complete") == null)
        return l.fail(
            "iodine_direct",
            .{ .output = direct, .server = try l.read(try w.path("iodined.log")) },
        );
    l.log("iodine_direct", .{ .result = "connected" });
    try redirect(l, "10.53.0.3", 53);
    const screened = try client(
        w,
        &(iodine ++ [_][]const u8{ "127.0.0.53", "tunnel.test" }),
        null,
        8,
        null,
    );
    if (mem.find(
        u8,
        screened,
        "Connection setup complete",
    ) != null) return l.fail("iodine_screened", .{ .output = screened });
    l.log("iodine_screened", .{ .output = tail(screened) });

    // Listing resources is a real dns2tcp exchange before any opens. Its TXT
    // is granted to the screened service, so a refusal tests screening.
    const dns2tcp = [_][]const u8{ "dns2tcpc", "-z", "tunnel.test" };
    const listed = try client(
        w,
        try w.inPeer(&(dns2tcp ++ [_][]const u8{"10.53.0.4"})),
        null,
        8,
        null,
    );
    if (mem.find(u8, listed, "echo") == null)
        return l.fail(
            "dns2tcp_direct",
            .{ .output = listed, .server = try l.read(try w.path("dns2tcpd.log")) },
        );
    {
        var tunnel = try l.spawn(
            try w.inPeer(&(dns2tcp ++ [_][]const u8{ "-r", "echo", "-l", "16001", "10.53.0.4" })),
            .{ .stdout = .discard, .stderr = .discard },
        );
        defer tunnel.stop();
        const echoed = try client(
            w,
            try w.inPeer(&.{ w.self, "--echo-probe", "16001" }),
            null,
            12,
            null,
        );
        if (mem.find(u8, echoed, "dns2tcp-ok") == null)
            return l.fail(
                "dns2tcp_direct_data",
                .{ .output = echoed, .server = try l.read(try w.path("dns2tcpd.log")) },
            );
    }
    l.log("dns2tcp_direct", .{ .result = "data echoed" });
    try redirect(l, "10.53.0.4", 53);
    const refused = try client(w, &(dns2tcp ++ [_][]const u8{"127.0.0.53"}), 2002, 8, null);
    if (mem.find(
        u8,
        refused,
        "echo",
    ) != null) return l.fail("dns2tcp_screened", .{ .output = refused });
    l.log("dns2tcp_screened", .{ .output = tail(refused) });

    const env = try l.environWith(&.{ "TMPDIR=/tmp", try l.gpa.print("MAGIC_WORD={s}", .{magic}) });
    try l.write(shellack_file, try config(l.gpa, "10.53.0.5", 10553));
    const ran = try client(w, try w.inPeer(&.{ "/bin/sh", shellack_client }), null, 9, env);
    if (mem.find(u8, ran, "shellack-ok") == null)
        return l.fail(
            "shellack_direct",
            .{ .output = ran, .server = try l.read(try w.path("shellack.log")) },
        );
    if (mem.find(u8, try l.read(try w.path("shellack.log")), "decode <nil>: shellack-ok") == null)
        return l.fail("shellack_no_return", .{ .server = try l.read(try w.path("shellack.log")) });
    l.log("shellack_direct", .{ .result = "command ran" });
    try l.write(shellack_file, try config(l.gpa, "127.0.0.53", 53));
    try redirect(l, "10.53.0.5", 10553);
    const stopped = try client(w, &.{ "/bin/sh", shellack_client }, 2003, 7, env);
    if (mem.find(
        u8,
        stopped,
        "shellack-ok",
    ) != null) return l.fail("shellack_screened", .{ .output = stopped });
    l.log("shellack_screened", .{ .output = tail(stopped) });

    var iodine_empty = false;
    var dns2tcp_denied = false;
    var shellack_trimmed = false;
    for (try lab.audit(w)) |a| {
        const uid = lab.field(a, "uid") orelse continue;
        if (uid != .integer) continue;
        iodine_empty = iodine_empty or (uid.integer == 0 and is(a, "why", "screened") and
            is(a, "type", "A") and (integer(a, "answers") orelse -1) == 0);
        dns2tcp_denied = dns2tcp_denied or (uid.integer == 2002 and is(a, "decision", "deny") and
            (is(a, "why", "tunnel") or is(a, "why", "budget") or is(a, "why", "malformed")));
        shellack_trimmed = shellack_trimmed or (uid.integer == 2003 and
            (integer(a, "dropped_shape") orelse 0) > 0);
    }
    if (!iodine_empty or !dns2tcp_denied or !shellack_trimmed) return l.fail("tunnels_unaudited", .{
        .iodine = iodine_empty,
        .dns2tcp = dns2tcp_denied,
        .shellack = shellack_trimmed,
    });
}

fn is(a: std.json.Value, key: []const u8, want: []const u8) bool {
    const v = lab.field(a, key) orelse return false;
    return v == .string and mem.eql(u8, v.string, want);
}

fn integer(a: std.json.Value, key: []const u8) ?i64 {
    const v = lab.field(a, key) orelse return null;
    return if (v == .integer) v.integer else null;
}

fn tail(text: []const u8) []const u8 {
    const t = mem.trim(u8, text, " \n");
    return t[t.len -| 180..];
}

/// redirect gives the tunnel server at address:port the resolver's own
/// address: fence admits only the resolver DHCP named.
fn redirect(l: lab.Lab, address: []const u8, port: u16) !void {
    try l.run(&.{
        "ip",
        "netns",
        "exec",
        "unwound-peer",
        "/usr/sbin/iptables-nft",
        "-t",
        "nat",
        "-I",
        "PREROUTING",
        "-d",
        fixture.upstream,
        "-p",
        "udp",
        "--dport",
        "53",
        "-j",
        "DNAT",
        "--to-destination",
        try l.gpa.print("{s}:{d}", .{ address, port }),
    });
}

/// echo serves TCP echo on address:port, a connection at a time, for ever.
fn echo(address: []const u8, port: u16) !void {
    const s = try netns.socket(linux.SOCK.STREAM);
    try netns.listen(s, address, port, 16);
    while (true) {
        const rc = linux.accept4(s, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(rc) != .SUCCESS) continue;
        const peer: linux.fd_t = @intCast(rc);
        defer netns.close(peer);
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = linux.read(peer, &buf, buf.len);
            if (linux.errno(n) != .SUCCESS or n == 0) break;
            netns.writeAll(peer, buf[0..n]) catch break;
        }
    }
}

/// echoProbe sends a line through the dns2tcp tunnel's local port and
/// prints what comes back, trying for five seconds.
fn echoProbe(port: u16) !void {
    const to = try netns.address("127.0.0.1", port);
    for (0..50) |_| {
        const s = try netns.socket(linux.SOCK.STREAM);
        defer netns.close(s);
        netns.limit(s, 4000);
        if (linux.errno(linux.connect(s, &to, @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
            netns.nap(100);
            continue;
        }
        netns.writeAll(s, "dns2tcp-ok\n") catch continue;
        var buf: [100]u8 = undefined;
        const n = linux.read(s, &buf, buf.len);
        if (linux.errno(n) != .SUCCESS) {
            netns.nap(100);
            continue;
        }
        return netns.writeAll(1, buf[0..n]);
    }
    return error.TunnelNeverReady;
}
