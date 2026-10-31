//! upstream forwards the questions the frontend allowed to the resolvers
//! that DHCP or the kernel command line named, as _unwoundnet: the one user
//! fence lets reach them, on port 53 alone. Each attempt gets a fresh
//! socket, so a fresh source port, plus a random ID and random 0x20 case:
//! an off-path forger must guess the port, the ID and the case of every
//! letter. A truncated answer is asked again over TCP. Every question gets
//! an answer, or a bare header and a Silence when no resolver gives one in
//! time.
const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const dns = @import("dns");
const wire = @import("wire.zig");
const unwound = @import("unwound.zig");
const sys = sandbox.sys;

pub const network_dir = dns.network_dir;
const resolvers_file = dns.upstream_name;
/// Each resolver gets two tries, in turn, before the question fails.
const tries_per_server = 2;
const udp_ms = 1000;
const tcp_ms = 2000;
/// reread_ms is how often the resolver file is checked for a new lease.
const reread_ms = 1000;
/// max_tcp bounds TCP attempts at once, each with a buffer of tcp_max.
const max_tcp = 16;
const tcp_max = 32 * 1024;

const Phase = enum { udp, connecting, reading };

/// Silence is why no resolver answered a question, as its last attempt
/// ended. It follows the bare header that says so, for the audit record.
pub const Silence = enum(u8) {
    /// no_resolvers: no lease or command line has named one.
    no_resolvers,
    /// send_failed: the socket, its connection or the send failed; fence
    /// refusing it shows here.
    send_failed,
    /// timeout: no answer to the question as sent came in time.
    timeout,
    /// tcp_failed: a truncated answer, asked again over TCP, failed.
    tcp_failed,
    /// busy: no room was left for another question or TCP attempt.
    busy,
};

const Pending = struct {
    used: bool = false,
    /// id is the frontend's, for its answer.
    id: u16 = 0,
    name: wire.Name = .{},
    type: wire.Type = .a,
    attempt: u8 = 0,
    /// silence is why the last attempt ended without an answer.
    silence: Silence = .no_resolvers,
    /// The resolver chosen for this attempt stays fixed across lease updates.
    server: [4]u8 = .{ 0, 0, 0, 0 },
    fd: i32 = -1,
    phase: Phase = .udp,
    tcp: u8 = 0,
    deadline: i64 = 0,
    /// sent is the query as sent: the answer must repeat its question.
    sent: [wire.query_max]u8 = undefined,
    sent_len: usize = 0,
};

const TcpBuf = struct {
    used: bool = false,
    have: usize = 0,
    buf: [2 + tcp_max]u8 = undefined,
};

const Upstream = struct {
    channel: i32,
    domain_channel: i32,
    network: i32,
    log: i32,
    local_validator: bool,
    servers: dns.Resolvers = .{},
    stamp: [3]u64 = .{ 0, 0, 0 },
    /// checked is when the resolver file was last looked at, if ever.
    checked: ?i64 = null,
    domain_checked: ?i64 = null,
    domain_sent: bool = false,
    domain: [253]u8 = undefined,
    domain_len: u8 = 0,
    rng: std.Random.DefaultCsprng,
    pending: [unwound.max_slots]Pending = @splat(.{}),
    tcp: [max_tcp]TcpBuf = @splat(.{}),
    in: [4096]u8 = undefined,
    out: [wire.response_max]u8 = undefined,
};

var u: Upstream = undefined;

/// run confines this process and serves the frontend until it goes away.
pub fn run(
    channel: i32,
    domain_channel: i32,
    network: i32,
    log: i32,
    local_validator: bool,
) noreturn {
    setup(channel, domain_channel, network, log, local_validator) catch |err| {
        var buf: [256]u8 = undefined;
        const why = std.mem.print(&buf, "setup: {s} ({s}: {t})", .{
            @errorName(err), sandbox.failed, sandbox.failed_errno,
        }) catch "setup";
        die(log, why);
    };
    serve();
}

/// die says why the upstream side stops; the frontend follows it.
fn die(log: i32, why: []const u8) noreturn {
    var buf: [384]u8 = undefined;
    const line = std.mem.print(
        &buf,
        "unwound: {{\"event\":\"exit\",\"side\":\"upstream\",\"why\":\"{s}\"}}\n",
        .{why},
    ) catch
        "unwound: {\"event\":\"exit\",\"side\":\"upstream\"}\n";
    _ = linux.write(log, line.ptr, line.len);
    linux.exit_group(1);
}

fn setup(channel: i32, domain_channel: i32, network: i32, log: i32, local_validator: bool) !void {
    var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
    if (try sys(
        linux.getrandom(&seed, seed.len, 0),
        "random seed",
    ) != seed.len) return error.ShortSeed;
    u = .{
        .channel = channel,
        .domain_channel = domain_channel,
        .network = network,
        .log = log,
        .local_validator = local_validator,
        .rng = .init(seed),
    };
    unwound.log_fd = log;
    unwound.side = "upstream";
    try sandbox.limit(.NOFILE, 17 + unwound.max_slots);
    try sandbox.dropTo(unwound.upstream_id, "/var/empty");
    _ = try sys(linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0), "dumpable");
    try sandbox.landlock(&.{.{ .fd = network, .access = sandbox.read_file }}, &.{53});
    var f: sandbox.Filter = .{};
    const flags = linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC;
    f.allowTwo("socket", 0, linux.AF.INET, 1, linux.SOCK.DGRAM | flags);
    f.allowTwo("socket", 0, linux.AF.INET, 1, linux.SOCK.STREAM | flags);
    f.allowArg("openat", 0, @intCast(network));
    f.allowArg("statx", 0, @intCast(network));
    f.allowArg("statx", 2, linux.AT.EMPTY_PATH);
    f.allowArg("write", 0, @intCast(log));
    f.allowArg("sendto", 0, @intCast(domain_channel));
    inline for (.{
        "connect",
        "sendto",
        "recvfrom",
        "getsockopt",
        "read",
        "write",
        "close",
        "poll",
        "ppoll",
        "clock_gettime",
        "rt_sigreturn",
        "restart_syscall",
        "exit",
        "exit_group",
    }) |call|
        f.allow(call);
    try f.install();
}

fn serve() noreturn {
    var fds: [1 + unwound.max_slots]linux.pollfd = undefined;
    var which: [unwound.max_slots]u8 = undefined;
    while (true) {
        refreshDomain();
        fds[0] = .{ .fd = u.channel, .events = linux.POLL.IN, .revents = 0 };
        var n: usize = 1;
        var wake: i64 = 1000;
        const t = unwound.now();
        for (&u.pending, 0..) |*p, i| if (p.used) {
            fds[n] = .{
                .fd = p.fd,
                .events = if (p.phase == .connecting) linux.POLL.OUT else linux.POLL.IN,
                .revents = 0,
            };
            which[n - 1] = @intCast(i);
            n += 1;
            wake = @min(wake, @max(0, p.deadline - t));
        };
        const rc = linux.poll(&fds, n, @intCast(wake));
        if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .INTR) die(u.log, "poll");
        if (fds[0].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0) linux.exit_group(0);
        if (fds[0].revents != 0) questions();
        for (fds[1..n], which[0 .. n - 1]) |pfd, i| if (pfd.revents != 0 and
            u.pending[i].used) ready(i);
        const after = unwound.now();
        for (&u.pending, 0..) |*p, i| if (p.used and after >= p.deadline)
            next(@intCast(i), if (p.phase == .udp) .timeout else .tcp_failed);
    }
}

/// refreshDomain sends only a validated boot-config suffix over a separate
/// private channel. Untrusted DHCP Option 15 domains are ignored so an on-link
/// DHCP server cannot widen DNS grants or bypass domain-age enforcement.
fn refreshDomain() void {
    const t = unwound.now();
    if (u.domain_checked) |last| if (t - last < reread_ms) return;
    u.domain_checked = t;
    var chosen: [253]u8 = undefined;
    const len = readDomain(dns.config_domain_name, 0, &chosen);
    if (u.domain_sent and len == u.domain_len and
        std.mem.eql(u8, chosen[0..len], u.domain[0..u.domain_len])) return;
    var packet: [254]u8 = undefined;
    packet[0] = @intCast(len);
    @memcpy(packet[1..][0..len], chosen[0..len]);
    const rc = linux.sendto(u.domain_channel, &packet, len + 1, 0, null, 0);
    if (linux.errno(rc) != .SUCCESS or rc != len + 1) return;
    @memcpy(u.domain[0..len], chosen[0..len]);
    u.domain_len = @intCast(len);
    u.domain_sent = true;
}

fn readDomain(comptime file: [:0]const u8, owner: u32, out: *[253]u8) usize {
    const fd = linux.openat(
        u.network,
        file,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(fd) != .SUCCESS) return 0;
    defer _ = linux.close(@intCast(fd));
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(
        @intCast(fd),
        "",
        linux.AT.EMPTY_PATH,
        .{ .TYPE = true, .MODE = true, .UID = true, .SIZE = true },
        &st,
    )) != .SUCCESS or
        st.mode & linux.S.IFMT != linux.S.IFREG or st.mode & 0o022 != 0 or
        st.uid != owner or
        st.size > 254) return 0;
    var raw: [255]u8 = undefined;
    const rc = linux.read(@intCast(fd), &raw, raw.len);
    if (linux.errno(rc) != .SUCCESS or rc != st.size) return 0;
    const name = dns.normalizeSystemDomain(raw[0..rc], out) orelse return 0;
    return name.len;
}

/// questions reads the frontend's questions. They were written by
/// wire.writeQuery, but are read as strictly as a client's.
fn questions() void {
    for (0..64) |_| {
        var buf: [wire.query_max + 1]u8 = undefined;
        const rc = linux.recvfrom(u.channel, &buf, buf.len, linux.MSG.TRUNC, null, null);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc == 0) linux.exit_group(0),
            .AGAIN => return,
            else => die(u.log, "frontend channel"),
        }
        const q = wire.parseQuery(buf[0..@min(
            rc,
            buf.len,
        )]) catch die(u.log, "frontend sent garbage");
        const t = wire.Type.from(q.type) orelse die(u.log, "frontend sent garbage");
        const free = for (&u.pending, 0..) |*p, i| {
            if (!p.used) break i;
        } else {
            unanswered(q.id, .busy);
            continue;
        };
        u.pending[free] = .{ .used = true, .id = q.id, .name = q.name, .type = t };
        refresh();
        start(@intCast(free));
    }
}

/// refresh rereads the resolver file when it changes, at most once a
/// second. A file that cannot be read leaves no resolvers: fail closed.
fn refresh() void {
    const t = unwound.now();
    if (u.checked) |last| if (t - last < reread_ms) return;
    u.checked = t;
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(
        u.network,
        resolvers_file,
        linux.AT.SYMLINK_NOFOLLOW,
        .{ .INO = true, .SIZE = true, .MTIME = true },
        &st,
    )) != .SUCCESS) {
        u.servers = .{};
        u.stamp = .{ 0, 0, 0 };
        return;
    }
    const stamp: [3]u64 = .{
        st.ino,
        st.size,
        @bitCast(st.mtime.sec *% std.time.ns_per_s +% st.mtime.nsec),
    };
    if (std.mem.eql(u64, &stamp, &u.stamp)) return;
    u.stamp = stamp;
    u.servers = .{};
    const fd = linux.openat(
        u.network,
        resolvers_file,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(fd) != .SUCCESS) return;
    defer _ = linux.close(@intCast(fd));
    var buf: [4096]u8 = undefined;
    const n = linux.read(@intCast(fd), &buf, buf.len);
    if (linux.errno(n) != .SUCCESS or n == buf.len) return;
    u.servers = if (u.local_validator)
        dns.validatedLocal(buf[0..n]) catch .{}
    else
        dns.resolvers(buf[0..n]) catch .{};
}

/// start tries the question's next resolver over UDP, or fails it.
fn start(i: u8) void {
    const p = &u.pending[i];
    while (p.attempt < tries_per_server * u.servers.len) {
        const server = u.servers.ips[p.attempt % u.servers.len];
        p.attempt += 1;
        p.server = server;
        var id: u16 = undefined;
        var mix: [32]u8 = undefined;
        u.rng.fill(std.mem.asBytes(&id));
        u.rng.fill(&mix);
        p.sent_len = wire.writeQueryWithAd(
            &p.sent,
            id,
            &p.name,
            p.type,
            &mix,
            u.local_validator,
        ).len;
        p.silence = .send_failed;
        p.fd = open(linux.SOCK.DGRAM, server) orelse continue;
        const rc = linux.sendto(p.fd, &p.sent, p.sent_len, 0, null, 0);
        if (linux.errno(rc) != .SUCCESS) {
            closeFd(p);
            continue;
        }
        p.phase = .udp;
        p.deadline = unwound.now() + udp_ms;
        return;
    }
    fail(i);
}

/// open makes a socket connected to server's port 53. A connected UDP
/// socket takes datagrams from that address and port alone.
fn open(kind: u32, server: [4]u8) ?i32 {
    const rc = linux.socket(linux.AF.INET, kind | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(rc);
    const addr: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, 53),
        .addr = @bitCast(server),
    };
    const c = linux.connect(fd, &addr, @sizeOf(linux.sockaddr.in));
    if (linux.errno(c) == .SUCCESS or linux.errno(c) == .INPROGRESS) return fd;
    _ = linux.close(fd);
    return null;
}

fn ready(i: u8) void {
    const p = &u.pending[i];
    switch (p.phase) {
        .udp => datagrams(i),
        .connecting => {
            var err: i32 = 0;
            var len: linux.socklen_t = @sizeOf(i32);
            _ = linux.getsockopt(
                p.fd,
                linux.SOL.SOCKET,
                linux.SO.ERROR,
                std.mem.asBytes(&err),
                &len,
            );
            var frame: [2 + wire.query_max]u8 = undefined;
            std.mem.writeInt(u16, frame[0..2], @intCast(p.sent_len), .big);
            @memcpy(frame[2..][0..p.sent_len], p.sent[0..p.sent_len]);
            const rc = linux.sendto(p.fd, &frame, 2 + p.sent_len, linux.MSG.NOSIGNAL, null, 0);
            if (err != 0 or linux.errno(rc) != .SUCCESS or rc != 2 + p.sent_len)
                return next(i, .tcp_failed);
            p.phase = .reading;
        },
        .reading => stream(i),
    }
}

/// datagrams reads what arrived for a UDP attempt. Anything that is not
/// an answer to the query as sent is ignored: a forger's guesses cannot
/// end the wait for the real answer.
fn datagrams(i: u8) void {
    const p = &u.pending[i];
    for (0..8) |_| {
        const rc = linux.recvfrom(p.fd, &u.in, u.in.len, linux.MSG.TRUNC, null, null);
        if (linux.errno(rc) != .SUCCESS) return;
        if (rc > u.in.len) continue;
        var a: wire.Answer = undefined;
        wire.parseResponse(u.in[0..rc], p.sent[0..p.sent_len], &a) catch continue;
        if (!a.truncated) return done(i, &a);
        // A lease change may have revoked this attempt's resolver. Do not
        // open its TCP connection after revocation.
        const still_allowed = for (u.servers.ips[0..u.servers.len]) |server| {
            if (std.mem.eql(u8, &server, &p.server)) break true;
        } else false;
        if (!still_allowed) return next(i, .tcp_failed);
        // Ask the same resolver the same question over TCP.
        const tcp = for (&u.tcp, 0..) |*b, k| {
            if (!b.used) break k;
        } else return next(i, .busy);
        closeFd(p);
        p.fd = open(linux.SOCK.STREAM, p.server) orelse return next(i, .tcp_failed);
        u.tcp[tcp] = .{ .used = true };
        p.tcp = @intCast(tcp);
        p.phase = .connecting;
        p.deadline = unwound.now() + tcp_ms;
        return;
    }
}

fn stream(i: u8) void {
    const p = &u.pending[i];
    const b = &u.tcp[p.tcp];
    const rc = linux.read(p.fd, b.buf[b.have..].ptr, b.buf.len - b.have);
    if (linux.errno(rc) == .AGAIN) return;
    if (linux.errno(rc) != .SUCCESS or rc == 0) return next(i, .tcp_failed);
    b.have += rc;
    if (b.have < 2) return;
    const need = std.mem.readInt(u16, b.buf[0..2], .big);
    if (need > tcp_max) return next(i, .tcp_failed);
    if (b.have < 2 + need) return;
    if (b.have > 2 + need) return next(i, .tcp_failed);
    var a: wire.Answer = undefined;
    wire.parseResponse(b.buf[2..][0..need], p.sent[0..p.sent_len], &a) catch
        return next(i, .tcp_failed);
    if (a.truncated) return next(i, .tcp_failed);
    done(i, &a);
}

/// next abandons the current attempt, for why, and tries the next resolver.
fn next(i: u8, why: Silence) void {
    u.pending[i].silence = why;
    closeFd(&u.pending[i]);
    start(i);
}

fn closeFd(p: *Pending) void {
    if (p.fd >= 0) _ = linux.close(p.fd);
    p.fd = -1;
    if (p.phase != .udp) u.tcp[p.tcp].used = false;
    p.phase = .udp;
}

/// done sends the frontend a canonical answer to the question it asked.
fn done(i: u8, a: *const wire.Answer) void {
    const p = &u.pending[i];
    send(wire.writeResponseWithAd(
        &u.out,
        p.id,
        true,
        a.rcode,
        .{ .name = &p.name, .type = @backingInt(p.type) },
        a.slice(),
        a.negative,
        wire.response_max,
        a.authenticated,
    ));
    closeFd(p);
    p.used = false;
}

fn fail(i: u8) void {
    const p = &u.pending[i];
    unanswered(p.id, p.silence);
    closeFd(p);
    p.used = false;
}

/// unanswered tells the frontend that no resolver answered, and why: a
/// bare header and a Silence, which no resolver's answer can be, as an
/// answer repeats its question.
fn unanswered(id: u16, why: Silence) void {
    const h = wire.writeResponse(&u.out, id, true, .servfail, null, &.{}, null, wire.response_max);
    u.out[h.len] = @backingInt(why);
    send(u.out[0 .. h.len + 1]);
}

fn send(msg: []const u8) void {
    const rc = linux.sendto(u.channel, msg.ptr, msg.len, 0, null, 0);
    // A full channel loses the answer; the frontend's deadline answers it.
    if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .AGAIN) die(u.log, "frontend channel");
}
