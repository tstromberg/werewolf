//! check-lan exercises fence's LAN UDP rules against the real kernel:
//!
//!     check-lan FENCE
//!
//! FENCE is a Linux build. Everything runs in private mount and network
//! namespaces; no host interface, route, file or credential changes. This
//! program plays every role: --inside the namespaces, --peer (an mDNS echo)
//! and --send in the peer namespace, and --probe under fence.

const std = @import("std");
const host = @import("host");
const netns = host.netns;
const Io = std.Io;
const linux = std.os.linux;
const mem = std.mem;

const peer_ip = "10.77.0.2";
const wan = "198.51.100.2";
const client_ip = "10.77.0.1";
const pub_lan_client = "203.0.113.1";
const pub_lan_peer = "203.0.113.2";
const tcp_lan_port: u16 = 8053;
const groups = [_]struct { u16, []const u8 }{.{ 5353, "224.0.0.251" }};
const payload = "werewolf-lan-fixture";
/// Programs under fence run only from /usr: this one is bound there.
const installed = "/usr/local/bin/check-lan";

pub fn main(init: std.process.Init) !void {
    const l = netns.Lab.init(init, "check-lan");
    const args = try init.minimal.args.toSlice(l.gpa);
    if (args.len == 2 and eql(args[1], "--peer")) return peer(l);
    if (args.len == 2 and eql(args[1], "--probe")) return probe(l);
    if (args.len == 6 and eql(args[1], "--send")) return send(l, args[2..6].*);
    if (args.len == 5 and eql(args[1], "--tcp-send")) return tcpSend(args[2..5].*);
    if (args.len == 5 and eql(args[1], "--inside")) return inside(l, args[2], args[3], args[4]);
    if (args.len != 2 or args[1][0] == '-') {
        l.log("usage", .{ .usage = "check-lan FENCE" });
        std.process.exit(2);
    }
    // Root sets the rules itself; anyone else maps root from subordinate ids.
    const user: []const []const u8 = if (linux.geteuid() == 0)
        &.{}
    else
        &.{ "--user", "--map-auto", "--map-root-user" };
    var flags: std.ArrayList([]const u8) = .empty;
    try flags.appendSlice(l.gpa, user);
    try flags.appendSlice(l.gpa, &.{ "--net", "--mount" });
    try l.enter(flags.items, &.{
        "--inside",
        try Io.Dir.cwd().realPathFileAlloc(l.io, args[1], l.gpa),
        try l.namespace("net"),
        try l.namespace("mnt"),
    });
}

fn eql(a: []const u8, b: []const u8) bool {
    return mem.eql(u8, a, b);
}

/// peer echoes every datagram to an mDNS group's port, joined on the peer's
/// address, back to its sender, and echoes TCP connections on port 443.
fn peer(l: netns.Lab) !void {
    var fds: [groups.len + 1]linux.pollfd = undefined;
    for (groups, fds[0..groups.len]) |g, *p| {
        const fd = try netns.socket(linux.SOCK.DGRAM);
        try netns.listen(fd, "0.0.0.0", g[0], null);
        var membership: [8]u8 = undefined;
        membership[0..4].* = (try Io.net.Ip4Address.parse(g[1], 0)).bytes;
        membership[4..8].* = (try Io.net.Ip4Address.parse(peer_ip, 0)).bytes;
        if (linux.errno(linux.setsockopt(
            fd,
            linux.IPPROTO.IP,
            linux.IP.ADD_MEMBERSHIP,
            &membership,
            8,
        )) !=
            .SUCCESS) return l.fail("multicast_join_failed", .{ .group = g[1] });
        p.* = .{ .fd = fd, .events = linux.POLL.IN, .revents = 0 };
    }
    const tcp = try netns.socket(linux.SOCK.STREAM);
    try netns.listen(tcp, "0.0.0.0", 443, 16);
    fds[groups.len] = .{ .fd = tcp, .events = linux.POLL.IN, .revents = 0 };
    try netns.writeAll(1, "ready\n");
    while (true) {
        for (&fds) |*p| p.revents = 0;
        if (linux.errno(linux.poll(&fds, fds.len, -1)) != .SUCCESS) continue;
        for (fds[0..groups.len]) |p| if (p.revents != 0) {
            var data: [2048]u8 = undefined;
            var from: linux.sockaddr.in = undefined;
            var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
            const n = linux.recvfrom(p.fd, &data, data.len, 0, @ptrCast(&from), &len);
            if (linux.errno(n) == .SUCCESS) _ = linux.sendto(
                p.fd,
                &data,
                n,
                0,
                @ptrCast(&from),
                len,
            );
        };
        if (fds[groups.len].revents != 0) echoAccepted(tcp);
    }
}

fn echoAccepted(listener: linux.fd_t) void {
    const conn_rc = linux.accept4(listener, null, null, linux.SOCK.CLOEXEC);
    if (linux.errno(conn_rc) != .SUCCESS) return;
    const conn: linux.fd_t = @intCast(conn_rc);
    defer netns.close(conn);
    netns.limit(conn, 600);
    var data: [256]u8 = undefined;
    const n = linux.read(conn, &data, data.len);
    if (linux.errno(n) == .SUCCESS and n > 0) netns.writeAll(conn, data[0..n]) catch {};
}

/// tcpSend connects from FROM to TO:PORT in the peer namespace and prints
/// `received` on echoed payload or `lost` on timeout/failure.
fn tcpSend(args: [3][:0]const u8) !void {
    const fd = try netns.socket(linux.SOCK.STREAM);
    defer netns.close(fd);
    netns.limit(fd, 600);
    const from = try netns.address(args[0], 0);
    if (linux.errno(linux.bind(fd, @ptrCast(&from), @sizeOf(@TypeOf(from)))) != .SUCCESS)
        return netns.writeAll(1, "lost\n");
    const to = try netns.address(args[1], try std.fmt.parseInt(u16, args[2], 10));
    if (linux.errno(linux.connect(fd, @ptrCast(&to), @sizeOf(@TypeOf(to)))) != .SUCCESS)
        return netns.writeAll(1, "lost\n");
    netns.writeAll(fd, payload) catch return netns.writeAll(1, "lost\n");
    var data: [64]u8 = undefined;
    const n = linux.read(fd, &data, data.len);
    const ok = linux.errno(n) == .SUCCESS and eql(data[0..n], payload);
    try netns.writeAll(1, if (ok) "received\n" else "lost\n");
}

/// send sends the payload from ADDRESS:SOURCE to CLIENT:PORT, in the peer.
fn send(l: netns.Lab, args: [4][:0]const u8) !void {
    const fd = try netns.socket(linux.SOCK.DGRAM);
    try netns.listen(fd, args[0], try std.fmt.parseInt(u16, args[1], 10), null);
    const to = try netns.address(args[2], try std.fmt.parseInt(u16, args[3], 10));
    if (linux.errno(linux.sendto(
        fd,
        payload,
        payload.len,
        0,
        @ptrCast(&to),
        @sizeOf(@TypeOf(to)),
    )) !=
        .SUCCESS) return l.fail("send_failed", .{ .from = args[0], .to = args[2] });
}

/// probe answers requests under fence. `out UID ADDRESS PORT SOURCE` sends
/// the payload from SOURCE (0: any) and waits for its echo; `in UID SOURCE`
/// says `listening` and waits for the payload. Each is answered with
/// `received`, or `lost ERRNO` (0 when nothing came). A child drops to UID
/// for each; the probe starts no threads, so that child may run Zig.
fn probe(l: netns.Lab) !void {
    // Bind and serve the LAN TCP port under fence's Landlock domain.
    const lan_listener = try netns.socket(linux.SOCK.STREAM);
    try netns.listen(lan_listener, "0.0.0.0", tcp_lan_port, 16);
    const parent = linux.getpid();
    const srv_rc = linux.fork();
    if (linux.errno(srv_rc) != .SUCCESS) return error.ForkFailed;
    if (srv_rc == 0) {
        _ = linux.prctl(@backingInt(linux.PR.SET_PDEATHSIG), @backingInt(linux.SIG.KILL), 0, 0, 0);
        if (linux.getppid() != parent) linux.exit_group(0);
        while (true) echoAccepted(lan_listener);
    }
    netns.close(lan_listener);
    try netns.writeAll(1, "ready\n");
    const requests = try l.gpa.create(netns.Lines);
    requests.* = .{ .fd = 0 };
    while (true) {
        const line = requests.next(30 * 60_000) catch |err| switch (err) {
            error.EndOfStream => return,
            else => |e| return e,
        };
        var words = mem.tokenizeScalar(u8, line, ' ');
        const kind = words.next() orelse return error.BadRequest;
        const uid = try std.fmt.parseInt(u32, words.next() orelse return error.BadRequest, 10);
        const tcp_out = eql(kind, "tcp-out");
        var to: ?linux.sockaddr.in = null;
        if (eql(kind, "out") or tcp_out) {
            const address = words.next() orelse return error.BadRequest;
            to = try netns.address(address, try std.fmt.parseInt(u16, words.next() orelse
                return error.BadRequest, 10));
        } else if (!eql(kind, "in")) return error.BadRequest;
        const source = if (tcp_out) 0 else try std.fmt.parseInt(
            u16,
            words.next() orelse return error.BadRequest,
            10,
        );
        const rc = linux.fork();
        if (linux.errno(rc) != .SUCCESS) return error.ForkFailed;
        if (rc == 0) {
            const lost = if (tcp_out) attemptTcp(uid, to.?) else attempt(uid, to, source);
            var buf: [32]u8 = undefined;
            const text = if (lost) |e|
                std.mem.print(&buf, "lost {d}\n", .{e}) catch unreachable
            else
                "received\n";
            netns.writeAll(1, text) catch {};
            linux.exit_group(0);
        }
        var child: netns.Child = .{ .pid = @intCast(rc) };
        if (try child.wait(null) != 0) return error.ProbeChildFailed;
    }
}

fn dropUid(uid: u32) ?u16 {
    if (uid == 0) return null;
    // An unprivileged user namespace may deny setgroups.
    const none: [0]linux.gid_t = .{};
    const groups_rc = linux.errno(linux.setgroups(0, &none));
    if (groups_rc != .SUCCESS and groups_rc != .PERM) return @backingInt(groups_rc);
    var rc = linux.setgid(uid);
    if (linux.errno(rc) == .SUCCESS) rc = linux.setuid(uid);
    if (linux.errno(rc) != .SUCCESS) return @backingInt(linux.errno(rc));
    return null;
}

fn attemptTcp(uid: u32, to: linux.sockaddr.in) ?u16 {
    if (dropUid(uid)) |e| return e;
    const fd = netns.socket(linux.SOCK.STREAM) catch return @backingInt(linux.E.MFILE);
    defer netns.close(fd);
    netns.limit(fd, 600);
    const rc = linux.connect(fd, @ptrCast(&to), @sizeOf(@TypeOf(to)));
    if (linux.errno(rc) != .SUCCESS) return @backingInt(linux.errno(rc));
    netns.writeAll(fd, payload) catch return 0;
    var data: [64]u8 = undefined;
    const n = linux.read(fd, &data, data.len);
    return switch (linux.errno(n)) {
        .SUCCESS => if (eql(data[0..n], payload)) null else 0,
        .AGAIN => 0,
        else => |e| @backingInt(e),
    };
}

/// attempt runs one request as uid, in a forked child: it returns null if
/// the payload arrived, else the errno that stopped it, or 0 for silence.
fn attempt(uid: u32, to: ?linux.sockaddr.in, source: u16) ?u16 {
    if (dropUid(uid)) |e| return e;
    const fd = netns.socket(linux.SOCK.DGRAM) catch return @backingInt(linux.E.MFILE);
    netns.limit(fd, 600);
    const here = netns.address("0.0.0.0", source) catch unreachable;
    var rc = linux.bind(fd, @ptrCast(&here), @sizeOf(@TypeOf(here)));
    if (linux.errno(rc) != .SUCCESS) return @backingInt(linux.errno(rc));
    if (to) |t| {
        rc = linux.sendto(fd, payload, payload.len, 0, @ptrCast(&t), @sizeOf(@TypeOf(t)));
        if (linux.errno(rc) != .SUCCESS) return @backingInt(linux.errno(rc));
    } else netns.writeAll(1, "listening\n") catch {};
    var data: [2048]u8 = undefined;
    rc = linux.recvfrom(fd, &data, data.len, 0, null, null);
    return switch (linux.errno(rc)) {
        .SUCCESS => if (eql(data[0..rc], payload)) null else 0,
        .AGAIN => 0,
        else => |e| @backingInt(e),
    };
}

const Lan = struct {
    l: netns.Lab,
    server: ?netns.Child = null,
    client: ?netns.Child = null,
    replies: *netns.Lines,

    fn ask(t: *Lan, request: []const u8) ![]const u8 {
        try netns.writeAll(t.client.?.stdin.?, try t.l.gpa.print("{s}\n", .{request}));
        return t.replies.next(10_000) catch |err|
            t.l.fail("probe_unanswered", .{ .request = request, .@"error" = @errorName(err) });
    }

    fn deinit(t: *Lan) void {
        if (t.client) |*c| {
            c.closeStdin();
            if (c.wait(5000) catch null == null) {
                c.signal(.KILL);
                _ = c.wait(null) catch {};
            }
        }
        if (t.server) |*s| s.stop();
        t.l.run(&.{ "ip", "netns", "delete", "lan-peer" }) catch {};
    }
};

fn inside(l: netns.Lab, fence: []const u8, parent_net: []const u8, parent_mnt: []const u8) !void {
    if (eql(try l.namespace("net"), parent_net) or eql(try l.namespace("mnt"), parent_mnt))
        return l.fail("namespace_shared", .{ .net = parent_net, .mnt = parent_mnt });
    try l.private();
    const work = try l.temporary("werewolf-lan");
    defer l.remove(work);
    const bin = try l.gpa.print("{s}/bin", .{work});
    try l.mkdir(bin, 0o755);
    try l.copy(try l.self(), try l.gpa.print("{s}/check-lan", .{bin}), 0o755);
    try l.bind(bin, "/usr/local/bin");
    for ([_][]const u8{ "/run", "/etc", "/usr/share", "/var" }) |dir| try l.tmpfs(dir);
    try l.mkdir("/var/empty", 0o755);
    try l.symlink("/run", "/var/run");
    try l.mkdir("/usr/share/werewolf", 0o755);
    var policy: std.ArrayList(u8) = .empty;
    for (groups) |g| try policy.print(
        l.gpa,
        "listen 207 udp {d} lan\nconnect 207 udp {d} lan\n",
        .{ g[0], g[0] },
    );
    try policy.print(
        l.gpa,
        "connect 207 udp 53\nlisten tcp {d} lan\nconnect 207 tcp 443 public\n",
        .{tcp_lan_port},
    );
    try l.write("/usr/share/werewolf/net", policy.items);
    try l.veth(.{
        .peer = "lan-peer",
        .client = client_ip ++ "/24",
        .addresses = &.{ peer_ip ++ "/24", pub_lan_peer ++ "/24", wan ++ "/32" },
        .gateway = peer_ip,
        .peer_default = true,
    });
    try l.run(&.{ "ip", "addr", "add", pub_lan_client ++ "/24", "dev", "client" });

    var t: Lan = .{ .l = l, .replies = try l.gpa.create(netns.Lines) };
    defer t.deinit();
    t.server = try l.spawn(
        &.{ "ip", "netns", "exec", "lan-peer", installed, "--peer" },
        .{ .stdout = .pipe },
    );
    var server_lines: netns.Lines = .{ .fd = t.server.?.stdout.? };
    server_lines.ready(10_000) catch |err| return l.fail(
        "peer_not_ready",
        .{ .@"error" = @errorName(err) },
    );
    t.client = try l.spawn(&.{ fence, installed, "--probe" }, .{ .stdin = .pipe, .stdout = .pipe });
    t.replies.* = .{ .fd = t.client.?.stdout.? };
    // fence's structured startup log precedes the probe's ready.
    while (true) {
        const got = t.replies.next(10_000) catch |err|
            return l.fail("probe_not_ready", .{ .@"error" = @errorName(err) });
        if (eql(got, "ready")) break;
    }
    var count: usize = 0;
    for (groups) |g| {
        const port = g[0];
        const outgoing = [_]struct { u32, []const u8, u16, bool }{
            .{ 207, peer_ip, 0, true },    .{ 207, g[1], 0, true },
            .{ 207, peer_ip, port, true }, .{ 207, wan, 0, false },
            .{ 207, wan, port, false },    .{ 208, peer_ip, port, false },
            .{ 208, g[1], port, false },   .{ 207, "224.0.0.252", 0, false },
        };
        for (outgoing) |o| {
            const uid, const address, const source, const allowed = o;
            const got = try t.ask(try l.gpa.print(
                "out {d} {s} {d} {d}",
                .{ uid, address, port, source },
            ));
            const refused = eql(got, "lost 13") or eql(got, "lost 1"); // EACCES, EPERM
            if (eql(
                got,
                "received",
            ) != allowed or !allowed and !refused) return l.fail("outgoing", .{
                .port = port,
                .uid = uid,
                .address = address,
                .source = source,
                .allowed = allowed,
                .got = got,
            });
            count += 1;
        }
        const incoming = [_]struct { []const u8, u16, bool }{
            .{ peer_ip, port, true }, .{ peer_ip, 53, true },
            .{ wan, port, false },    .{ wan, 53, false },
            .{ wan, 443, false },
        };
        for (incoming) |i| {
            const address, const source, const allowed = i;
            const listening = try t.ask(try l.gpa.print("in 207 {d}", .{port}));
            if (!eql(listening, "listening")) return l.fail("not_listening", .{ .got = listening });
            try l.run(&.{
                "ip",      "netns",
                "exec",    "lan-peer",
                installed, "--send",
                address,   try l.gpa.print("{d}", .{source}),
                client_ip, try l.gpa.print("{d}", .{port}),
            });
            const got = t.replies.next(10_000) catch |err|
                return l.fail("probe_unanswered", .{ .@"error" = @errorName(err) });
            if (eql(got, "received") != allowed) return l.fail("incoming", .{
                .port = port,
                .address = address,
                .source = source,
                .allowed = allowed,
                .got = got,
            });
            count += 1;
        }
    }
    for ([_]struct { []const u8, bool }{
        .{ peer_ip, true },
        .{ pub_lan_peer, true },
        .{ wan, false },
    }) |in_tcp| {
        const out = try l.output(&.{
            "ip",                                    "netns",
            "exec",                                  "lan-peer",
            installed,                               "--tcp-send",
            in_tcp[0],                               client_ip,
            try l.gpa.print("{d}", .{tcp_lan_port}),
        });
        if (eql(mem.trim(u8, out, " \n"), "received") != in_tcp[1]) return l.fail("tcp_lan_in", .{
            .from = in_tcp[0],
            .allowed = in_tcp[1],
            .got = out,
        });
        count += 1;
    }
    for ([_]struct { u32, []const u8, u16, bool }{
        .{ 207, wan, 443, true },
        .{ 207, peer_ip, 443, false },
        .{ 207, pub_lan_peer, 443, false },
        .{ 207, pub_lan_client, 443, false },
        .{ 0, "127.0.0.1", tcp_lan_port, true },
        .{ 0, client_ip, tcp_lan_port, true },
        .{ 208, "127.0.0.1", tcp_lan_port, true },
        .{ 208, client_ip, tcp_lan_port, false },
        .{ 1000, "127.0.0.1", tcp_lan_port, false },
        .{ 1000, client_ip, tcp_lan_port, false },
    }) |tc| {
        const uid, const address, const port, const allowed = tc;
        const got = try t.ask(try l.gpa.print("tcp-out {d} {s} {d}", .{ uid, address, port }));
        const refused = eql(got, "lost 13") or eql(got, "lost 1");
        if (eql(got, "received") != allowed or (!allowed and !refused)) return l.fail("tcp_out", .{
            .uid = uid,
            .address = address,
            .port = port,
            .allowed = allowed,
            .got = got,
        });
        count += 1;
    }
    l.log("pass", .{ .checks = count, .what = "real-kernel LAN and local routing checks" });
}
