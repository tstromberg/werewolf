//! unwound answers every program's DNS at 127.0.0.53, and decides what each
//! service may look up. fence gives each service with lookup grants a
//! source address of its own (lib/dns.zig's labels), chosen by the kernel
//! from the sender's UID, so the address a query arrives from names the
//! service that asked, and no process can claim another's.
//!
//! Setup, as root, reads the policy, binds the listeners, opens the log
//! and a channel, and forks. This process becomes the frontend: as
//! _unwound, chrooted, with no files and no way to open a socket, it reads
//! queries, decides them, and answers. Its child is upstream.zig: as
//! _unwoundnet, the one user fence lets reach the resolvers, it forwards
//! what the frontend allowed. Each side treats the other's messages as
//! input to check. An observe-only age child classifies screened requests
//! without changing answers. See docs/design/implemented/unwound.md and cmd/unwound/unwound.8.
const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const dns = @import("dns");
const wire = @import("wire.zig");
const Policy = @import("policy.zig").Policy;
const Why = @import("policy.zig").Why;
const screen = @import("screen.zig");
const endpoints = @import("endpoints.zig");
const cache = @import("cache.zig");
const upstream = @import("upstream.zig");
const needsAge = @import("policy.zig").needsAge;
const age = @import("age.zig");
const age_ipc = @import("age_ipc.zig");
const age_gate = @import("age_gate.zig");
const age_worker = @import("age_worker.zig");
const sys = sandbox.sys;

const frontend_id = 53;
pub const upstream_id = 54;
const policy_path = dns.policy_path;
const log_socket = "/run/syslog/dev-log";
const age_marker_text = "enforce\n";
const max_policy = 256 * 1024;

/// max_slots bounds the questions waiting on the upstream side; a service
/// may hold max_per_service of them, so a flood from one starves no other.
pub const max_slots = 256;
const max_per_service = 32;
/// max_conns bounds TCP clients; a service may hold max_conns_per_service.
const max_conns = 64;
const max_conns_per_service = 8;
/// slot_ms backstops upstream's own deadlines, which always answer sooner.
const slot_ms = 15_000;
/// idle_ms closes TCP clients that send nothing.
const idle_ms = 10_000;
const stats_ms = 60_000;

var policy: Policy = .{};
var policy_text: [max_policy]u8 = undefined;
/// screens are what screening remembers of each service; a service whose
/// grants are not screened never touches its pages. screen_key keys its
/// hashes, so no one can choose a name that passes for another.
var screens: [dns.max_users]screen.Service = @splat(.{});
var screen_key: [screen.key_len]u8 = @splat(0);
/// caches are each service's answers, its own, so that no service learns
/// what another asked from how fast it is answered.
var caches: [dns.max_users]cache.Cache = @splat(.{});

/// log_fd is where a panic is said, once there is somewhere to say it, and
/// side which process said it.
pub var log_fd: i32 = 2;
pub var side: []const u8 = "setup";

/// panic writes one line where audit records go and exits: under seccomp
/// the default handler's abort would be killed before it said anything.
pub const panic = std.debug.FullPanic(struct {
    fn panic(msg: []const u8, _: ?usize) noreturn {
        var buf: [320]u8 = undefined;
        const line = std.mem.print(&buf, "unwound: {{\"event\":\"panic\",\"side\":\"{s}\",\"mess" ++
            "age\":{f}}}\n", .{
            side, std.json.fmt(msg, .{}),
        }) catch "unwound: {\"event\":\"panic\"}\n";
        _ = linux.write(log_fd, line.ptr, line.len);
        linux.exit_group(1);
    }
}.panic);

pub fn main() void {
    run() catch |err| {
        var buf: [256]u8 = undefined;
        const line = std.mem.print(&buf, "unwound: setup failed: {s} ({s}: {t})\n", .{
            @errorName(err), sandbox.failed, sandbox.failed_errno,
        }) catch "unwound: setup failed\n";
        _ = linux.write(2, line.ptr, line.len);
        linux.exit_group(1);
    };
}

fn run() !void {
    if (linux.getuid() != 0) return error.RootSetupRequired;
    _ = try sys(
        linux.close_range(3, std.math.maxInt(i32), .{ .UNSHARE = false, .CLOEXEC = false }),
        "close inherited files",
    );
    try policy.parse((readRootFile(policy_path, &policy_text, "policy") catch
        return error.UnsafePolicy) orelse return error.NoPolicy);
    // The upstream file must independently name the same loopback resolver.
    const local_validator = readMarker(
        dns.local_validator_path,
        dns.local_validator_text,
        "local validator",
    ) catch return error.LocalValidator;
    // Without the age marker, unwound only observes domain age.
    const enforce_age = readMarker(dns.age_marker_path, age_marker_text, "age marker") catch
        return error.AgeMarker;
    const udp = try listener(linux.SOCK.DGRAM);
    const tcp = try listener(linux.SOCK.STREAM);
    _ = try sys(linux.listen(tcp, 64), "listen");
    const log = try openLog();
    const network: i32 = @intCast(try sys(linux.open(upstream.network_dir, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0), "open network directory"));
    var pair: [2]i32 = undefined;
    _ = try sys(linux.socketpair(
        linux.AF.UNIX,
        linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
        &pair,
    ), "upstream channel");
    var domain_pair: [2]i32 = undefined;
    _ = try sys(linux.socketpair(
        linux.AF.UNIX,
        linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
        &domain_pair,
    ), "system domain channel");
    var age_pair: [2]i32 = .{ -1, -1 };
    if (enforce_age) {
        age_pair[0] = try connectAge();
    } else _ = try sys(linux.socketpair(
        linux.AF.UNIX,
        linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
        &age_pair,
    ), "age observation channel");
    const parent = linux.getpid();
    if (try sys(linux.fork(), "fork upstream") == 0) {
        sandbox.tieTo(parent);
        try sandbox.closeAllBut(&.{ pair[1], domain_pair[1], network, log });
        upstream.run(pair[1], domain_pair[1], network, log, local_validator);
    }
    _ = linux.close(pair[1]);
    _ = linux.close(domain_pair[1]);
    _ = linux.close(network);
    if (!enforce_age) {
        if (try sys(linux.fork(), "fork age observer") == 0) {
            sandbox.tieTo(parent);
            try sandbox.closeAllBut(&.{ age_pair[1], log });
            age_worker.run(age_pair[1], log, &policy);
        }
        _ = linux.close(age_pair[1]);
    }
    try sandbox.closeAllBut(&.{ udp, tcp, pair[0], domain_pair[0], age_pair[0], log });
    log_fd = log;
    side = "frontend";
    if (try sys(
        linux.getrandom(&screen_key, screen_key.len, 0),
        "screen key",
    ) != screen_key.len) return error.ShortKey;
    try sandbox.limit(.NOFILE, 17 + max_conns);
    try sandbox.dropTo(frontend_id, "/var/empty");
    _ = try sys(linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0), "dumpable");
    try sandbox.landlock(&.{}, &.{});
    const no_pipe: linux.Sigaction = .{
        .handler = .{ .handler = linux.SIG.IGN },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = try sys(linux.sigaction(.PIPE, &no_pipe, null), "ignore SIGPIPE");
    try confine(udp, tcp, pair[0], domain_pair[0], age_pair[0], log, enforce_age);
    var f: Frontend = .{
        .udp = udp,
        .tcp = tcp,
        .channel = pair[0],
        .domain_channel = domain_pair[0],
        .age_channel = age_pair[0],
        .log = log,
        .trust_ad = local_validator,
        .enforce_age = enforce_age,
        .last_stats = now(),
    };
    var ready: [1]linux.pollfd = .{.{
        .fd = domain_pair[0],
        .events = linux.POLL.IN,
        .revents = 0,
    }};
    if (linux.poll(&ready, 1, 5000) != 1 or ready[0].revents & linux.POLL.IN == 0)
        f.fail("initial system domain");
    f.domainUpdate();
    f.say("{{\"event\":\"start\",\"services\":{d},\"grants\":{d},\"generation\":\"{x:0>8}\"}}", .{
        policy.users.len, policy.n, policy.generation,
    });
    f.serve();
}

/// readMarker reports whether the image ships the marker at path. A marker
/// must be immutable image data holding exactly text; any other fails
/// startup rather than silently changing what unwound does.
fn readMarker(path: [*:0]const u8, comptime text: []const u8, comptime what: []const u8) !bool {
    var buf: [text.len + 1]u8 = undefined;
    const got = try readRootFile(path, &buf, what) orelse return false;
    if (!std.mem.eql(u8, got, text)) return error.BadMarker;
    return true;
}

fn connectAge() !i32 {
    const fd: i32 = @intCast(try sys(
        linux.socket(
            linux.AF.UNIX,
            linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
            0,
        ),
        "age authority socket",
    ));
    errdefer _ = linux.close(fd);
    var address: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(address.path[0..dns.age_socket_path.len], dns.age_socket_path);
    _ = try sys(
        linux.connect(fd, @ptrCast(&address), @intCast(2 + dns.age_socket_path.len + 1)),
        "connect age authority",
    );
    return fd;
}

/// readRootFile reads all of path, which must be a regular file of root's
/// that no one else may write and shorter than buf, or null if there is none.
pub fn readRootFile(path: [*:0]const u8, buf: []u8, comptime what: []const u8) !?[]const u8 {
    const opened = linux.open(path, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.errno(opened) == .NOENT) return null;
    const fd: i32 = @intCast(try sys(opened, "open " ++ what));
    defer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    _ = try sys(
        linux.statx(
            fd,
            "",
            linux.AT.EMPTY_PATH,
            .{ .TYPE = true, .MODE = true, .UID = true, .SIZE = true },
            &st,
        ),
        "stat " ++ what,
    );
    if (st.uid != 0 or st.mode & 0o022 != 0 or st.mode & linux.S.IFMT != linux.S.IFREG or
        st.size >= buf.len) return error.UnsafeFile;
    var got: usize = 0;
    while (got < buf.len) {
        const n = try sys(linux.read(fd, buf[got..].ptr, buf.len - got), "read " ++ what);
        if (n == 0) break;
        got += n;
    }
    if (got != st.size) return error.UnsafeFile;
    return buf[0..got];
}

fn listener(kind: u32) !i32 {
    const fd: i32 = @intCast(try sys(
        linux.socket(linux.AF.INET, kind | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0),
        "listener",
    ));
    // A restart must not wait out the last one's TCP TIME_WAIT.
    const yes: i32 = 1;
    _ = try sys(
        linux.setsockopt(
            fd,
            linux.SOL.SOCKET,
            linux.SO.REUSEADDR,
            std.mem.asBytes(&yes),
            @sizeOf(i32),
        ),
        "reuse address",
    );
    const addr: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, 53),
        .addr = @bitCast(dns.resolver),
    };
    _ = try sys(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in)), "bind 127.0.0.53:53");
    return fd;
}

/// openLog connects to syslogd, waiting up to five seconds for it to start
/// with the other services. Without it, stderr goes to runit's console.
fn openLog() !i32 {
    const fd: i32 = @intCast(try sys(
        linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0),
        "log socket",
    ));
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..log_socket.len], log_socket);
    for (0..100) |_| {
        if (linux.errno(linux.connect(
            fd,
            &addr,
            @sizeOf(linux.sockaddr.un),
        )) == .SUCCESS) return fd;
        const tick: linux.timespec = .{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
        _ = linux.nanosleep(&tick, null);
    }
    _ = linux.close(fd);
    return @intCast(try sys(linux.fcntl(2, linux.F.DUPFD_CLOEXEC, 3), "log to stderr"));
}

/// confine allows the frontend reads and writes on what it holds, accepts
/// on its listener, and nothing that opens a file or makes a socket.
fn confine(
    udp: i32,
    tcp: i32,
    channel: i32,
    domain_channel: i32,
    age_channel: i32,
    log: i32,
    enforce_age: bool,
) !void {
    var f: sandbox.Filter = .{};
    f.allowArg("recvfrom", 0, @intCast(udp));
    f.allowArg("sendto", 0, @intCast(udp));
    f.allowArg("accept4", 0, @intCast(tcp));
    f.allowArg("recvfrom", 0, @intCast(channel));
    f.allowArg("sendto", 0, @intCast(channel));
    f.allowArg("recvfrom", 0, @intCast(domain_channel));
    f.allowArg("sendto", 0, @intCast(age_channel));
    if (enforce_age) f.allowArg("recvfrom", 0, @intCast(age_channel));
    f.allowArg("write", 0, @intCast(log));
    // TCP clients' descriptors are made by accept4; nothing else can be.
    inline for (.{
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

pub fn now() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return ts.sec * std.time.ms_per_s + @divFloor(ts.nsec, std.time.ns_per_ms);
}

const Client = union(enum) {
    udp: linux.sockaddr.in,
    tcp: u8,
};

const Stage = enum { age, upstream };

const Slot = struct {
    used: bool = false,
    /// gen changes each time the slot is reused, so a late answer for its
    /// last question cannot answer the next.
    gen: u8 = 0,
    service: u8 = 0,
    client: Client = .{ .tcp = 0 },
    id: u16 = 0,
    rd: bool = false,
    name: wire.Name = .{},
    type: wire.Type = .a,
    line: u16 = 0,
    why: Why = .granted,
    /// screened is a question only a screened `*` allowed.
    screened: bool = false,
    age_required: bool = false,
    age_source: age_ipc.Source = .none,
    stage: Stage = .upstream,
    /// follows is a question asked while the same one was out: it waits
    /// for that one's answer rather than asking again.
    follows: bool = false,
    start: i64 = 0,
    seq: u64 = 0,
};

const Conn = struct {
    fd: i32 = -1,
    service: u8 = 0,
    buf: [2 + wire.query_max]u8 = undefined,
    have: usize = 0,
    deadline: i64 = 0,
    /// waiting stops reading while a question is out: one at a time.
    waiting: bool = false,
};

const Stats = struct {
    queries: u64 = 0,
    refused: u64 = 0,
    /// tunnel counts screened questions refused for a name shaped like data.
    tunnel: u64 = 0,
    servfail: u64 = 0,
    busy: u64 = 0,
    malformed: u64 = 0,
    lost: u64 = 0,
    age_lost: u64 = 0,
    /// cached counts questions answered from the cache; merged, those that
    /// waited on the same question already out.
    cached: u64 = 0,
    merged: u64 = 0,
};

const Frontend = struct {
    udp: i32,
    tcp: i32,
    channel: i32,
    domain_channel: i32,
    age_channel: i32,
    log: i32,
    trust_ad: bool,
    enforce_age: bool,
    slots: [max_slots]Slot = @splat(.{}),
    pending: [dns.max_users]u16 = @splat(0),
    conns: [max_conns]Conn = @splat(.{}),
    open: [dns.max_users]u8 = @splat(0),
    seq: u64 = 0,
    age_seq: u64 = 0,
    stats: Stats = .{},
    reported: Stats = .{},
    last_stats: i64,
    out: [2 + wire.response_max]u8 = undefined,
    in: [wire.response_max + 1]u8 = undefined,
    /// records holds what the cache gives back, for one reply at a time.
    records: [wire.max_records]wire.Record = undefined,

    fn serve(f: *Frontend) noreturn {
        var fds: [5 + max_conns]linux.pollfd = undefined;
        var which: [max_conns]u8 = undefined;
        while (true) {
            // A read may have brought in the start of another TCP query.
            // Process it after the preceding answer, even if the socket has
            // no new data to wake poll.
            for (&f.conns, 0..) |*c, i| if (c.fd >= 0 and !c.waiting and c.have >= 2)
                f.consumeConn(@intCast(i));
            fds[0] = .{ .fd = f.channel, .events = linux.POLL.IN, .revents = 0 };
            fds[1] = .{ .fd = f.udp, .events = linux.POLL.IN, .revents = 0 };
            fds[2] = .{ .fd = f.tcp, .events = linux.POLL.IN, .revents = 0 };
            fds[3] = .{ .fd = f.domain_channel, .events = linux.POLL.IN, .revents = 0 };
            fds[4] = .{
                .fd = f.age_channel,
                .events = if (f.enforce_age) linux.POLL.IN else 0,
                .revents = 0,
            };
            var n: usize = 5;
            for (&f.conns, 0..) |*c, i| if (c.fd >= 0 and !c.waiting) {
                fds[n] = .{ .fd = c.fd, .events = linux.POLL.IN, .revents = 0 };
                which[n - 5] = @intCast(i);
                n += 1;
            };
            const rc = linux.poll(&fds, n, 1000);
            if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .INTR) f.fail("poll");
            if (fds[3].revents != 0) f.domainUpdate();
            if (fds[4].revents & (linux.POLL.HUP | linux.POLL.ERR) != 0)
                f.fail("age worker closed");
            if (f.enforce_age and fds[4].revents & linux.POLL.IN != 0) f.ageAnswers();
            if (fds[0].revents != 0) f.answers();
            if (fds[1].revents != 0) f.datagrams();
            if (fds[2].revents != 0) f.accept();
            for (fds[5..n], which[0 .. n - 5]) |p, i| if (p.revents != 0) f.readConn(i);
            f.expire();
        }
    }

    fn domainUpdate(f: *Frontend) void {
        var buf: [255]u8 = undefined;
        const rc = linux.recvfrom(f.domain_channel, &buf, buf.len, linux.MSG.TRUNC, null, null);
        const err = linux.errno(rc);
        const got = err == .SUCCESS and rc > 0 and rc <= buf.len;
        if (!got or buf[0] != rc - 1 or !policy.setSystemDomain(buf[1..rc])) {
            f.say("{{\"event\":\"system_domain_error\",\"rc\":{d},\"errno\":\"{t}\"," ++
                "\"length\":{d}}}", .{ rc, err, if (got) buf[0] else 0 });
            f.fail("system domain channel");
        }
        // DHCP is not trusted to open a public suffix, such as co.uk, or a
        // hosting provider's tenants to every service without age checks.
        if (policy.system_domain) |*d| if (!age.exemptable(d.text(), age.psl)) {
            f.say("{{\"event\":\"system_domain_refused\",\"name\":\"{s}\"}}", .{d.text()});
            policy.system_domain = null;
        };
        f.say("{{\"event\":\"system_domain\",\"name\":\"{s}\"}}", .{
            if (policy.system_domain) |*d| d.text() else "",
        });
    }

    fn fail(f: *Frontend, comptime what: []const u8) noreturn {
        f.say("{{\"event\":\"exit\",\"why\":\"" ++ what ++ "\"}}", .{});
        linux.exit_group(1);
    }

    /// datagrams reads up to 64 queries, so TCP clients and answers wait no
    /// longer than that behind a flood.
    fn datagrams(f: *Frontend) void {
        for (0..64) |_| {
            var from: linux.sockaddr.in = undefined;
            var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
            var buf: [wire.query_max + 1]u8 = undefined;
            const rc = linux.recvfrom(f.udp, &buf, buf.len, linux.MSG.TRUNC, @ptrCast(&from), &len);
            if (linux.errno(rc) != .SUCCESS) return;
            if (len != @sizeOf(linux.sockaddr.in) or from.family != linux.AF.INET) continue;
            const service = policy.service(@bitCast(from.addr));
            f.question(service, buf[0..@min(rc, buf.len)], .{ .udp = from }, @bitCast(from.addr));
        }
    }

    fn accept(f: *Frontend) void {
        for (0..16) |_| {
            var from: linux.sockaddr.in = undefined;
            var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
            const rc = linux.accept4(
                f.tcp,
                @ptrCast(&from),
                &len,
                linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
            );
            if (linux.errno(rc) != .SUCCESS) return;
            const fd: i32 = @intCast(rc);
            const service = if (from.family == linux.AF.INET)
                policy.service(@bitCast(from.addr))
            else
                null;
            const free = for (&f.conns, 0..) |*c, i| {
                if (c.fd < 0) break i;
            } else null;
            if (service == null or free == null or f.open[service.?] >= max_conns_per_service) {
                if (service) |s| {
                    f.stats.busy += 1;
                    f.say("{{\"event\":\"connection\",\"uid\":{f},\"decision\":\"deny\",\"why\":" ++
                        "\"busy\",\"detail\":\"{s}\"}}", .{
                        std.json.fmt(policy.uid(s), .{}),
                        if (free == null) "connections" else "service_connections",
                    });
                } else f.unlabeled(@bitCast(from.addr));
                _ = linux.close(fd);
                continue;
            }
            f.open[service.?] += 1;
            f.conns[free.?] = .{ .fd = fd, .service = service.?, .deadline = now() + idle_ms };
        }
    }

    /// readConn buffers a length-prefixed query and any following frames.
    fn readConn(f: *Frontend, i: u8) void {
        const c = &f.conns[i];
        const rc = linux.read(c.fd, c.buf[c.have..].ptr, c.buf.len - c.have);
        if (linux.errno(rc) == .AGAIN) return;
        if (linux.errno(rc) != .SUCCESS or rc == 0) return f.closeConn(i);
        c.have += rc;
        f.consumeConn(i);
    }

    fn consumeConn(f: *Frontend, i: u8) void {
        const c = &f.conns[i];
        while (c.fd >= 0 and !c.waiting) {
            if (c.have < 2) return;
            const need = std.mem.readInt(u16, c.buf[0..2], .big);
            if (need < wire.header_len or need > wire.query_max) {
                f.stats.malformed += 1;
                f.audit(c.service, null, 0, false, "malformed", 0, .{ .detail = "tcp_length" });
                return f.closeConn(i);
            }
            if (c.have < 2 + need) return;
            var query: [wire.query_max]u8 = undefined;
            @memcpy(query[0..need], c.buf[2..][0..need]);
            const rest = c.have - 2 - need;
            @memmove(c.buf[0..rest], c.buf[2 + need .. c.have]);
            c.have = rest;
            c.waiting = true;
            c.deadline = now() + idle_ms;
            f.question(c.service, query[0..need], .{ .tcp = i }, dns.label(c.service));
        }
    }

    fn closeConn(f: *Frontend, i: u8) void {
        const c = &f.conns[i];
        _ = linux.close(c.fd);
        f.open[c.service] -= 1;
        c.fd = -1;
        // A question still out for it is answered to no one.
        for (&f.slots) |*s| if (s.used and s.client == .tcp and s.client.tcp == i) {
            s.client = .{ .tcp = max_conns };
        };
    }

    /// question decides one query and either answers it or sends it upstream.
    fn question(f: *Frontend, service: ?u8, msg: []const u8, client: Client, from: [4]u8) void {
        f.stats.queries += 1;
        const s = service orelse {
            f.unlabeled(from);
            return f.reply(client, f.header(msg, .refused));
        };
        const q = wire.parseQuery(msg) catch |err| {
            f.stats.malformed += 1;
            const why = if (err == error.Unsupported) "unsupported" else "malformed";
            f.audit(s, null, 0, false, why, 0, .{ .detail = switch (err) {
                error.Short => "short",
                error.NotQuery => "response",
                error.Unsupported => "opcode_or_class",
                else => "format",
            } });
            return switch (err) {
                error.Short, error.NotQuery => f.reply(client, &.{}),
                error.Unsupported => f.reply(client, f.header(msg, .refused)),
                else => f.reply(client, f.header(msg, .formerr)),
            };
        };
        const d = policy.decide(s, &q.name, q.type);
        if (!d.allow) return f.refuse(client, s, &q, @tagName(d.why), d.line, .{
            .detail = if (d.why == .endpoint) @tagName(endpoints.reason(q.name.text()).?) else null,
        });
        const t = wire.Type.from(q.type).?;
        const screened = d.why == .screened or d.why == .system_domain;
        if (screened) if (screens[s].ask(&screen_key, q.name.text(), now())) |r| {
            if (r.sign.tunnel()) f.stats.tunnel += 1;
            const why = if (r.sign.tunnel()) "tunnel" else "budget";
            return f.refuse(client, s, &q, why, d.line, .{
                .detail = @tagName(r.sign),
                .bits = r.bits,
            });
        };
        const age_required = needsAge(d.why);
        const gated = age_required and f.enforce_age;
        if (age_required and !f.enforce_age) f.observeAge(s, &q, d.line, t, client);
        if (!gated) {
            if (caches[s].find(q.name.text(), t, now())) |e| {
                f.stats.cached += 1;
                const records = e.records(&q.name, now(), &f.records);
                const cached: Slot = .{ .service = s, .name = q.name, .type = t };
                if (f.forbiddenAlias(&cached, records)) |to|
                    return f.refuse(client, s, &q, "alias", d.line, .{ .alias = &to });
                f.audit(s, &q.name, q.type, true, @tagName(d.why), d.line, .{
                    .rcode = e.rcode,
                    .answers = records.len,
                    .cached = true,
                    .dropped = e.dropped,
                    .authenticated = e.authenticated,
                });
                return f.answer(
                    client,
                    q.id,
                    q.rd,
                    e.rcode,
                    &q.name,
                    q.type,
                    records,
                    e.authenticated,
                );
            }
        }
        const free = for (&f.slots, 0..) |*slot, i| {
            if (!slot.used) break i;
        } else null;
        if (free == null or f.pending[s] >= max_per_service)
            return f.busy(client, s, &q, d.line, if (free == null) "slots" else "service_slots");
        // The same question already out answers this one too.
        const out = for (&f.slots) |*o| {
            if (o.used and !o.follows and o.service == s and o.type == t and
                o.name.eql(&q.name)) break true;
        } else false;
        const i = free.?;
        const slot = &f.slots[i];
        f.seq += 1;
        slot.* = .{
            .used = true,
            .gen = slot.gen +% 1,
            .service = s,
            .client = client,
            .id = q.id,
            .rd = q.rd,
            .name = q.name,
            .type = t,
            .line = d.line,
            .why = d.why,
            .screened = screened,
            .age_required = gated,
            .stage = if (gated) .age else .upstream,
            .follows = out,
            .start = now(),
            .seq = f.seq,
        };
        f.pending[s] += 1;
        if (out) {
            f.stats.merged += 1;
            return;
        }
        if (!gated) return f.sendUpstream(i);
        if (!f.sendAge(&slotAgeRequest(slot)))
            f.settle(i, false, .refused, &.{}, "age", .{ .detail = "queue_full" });
    }

    fn sendUpstream(f: *Frontend, i: usize) void {
        const slot = &f.slots[i];
        var buf: [wire.query_max]u8 = undefined;
        const ask = wire.writeQuery(&buf, ipcId(i, slot.gen), &slot.name, slot.type, null);
        if (linux.errno(linux.sendto(f.channel, ask.ptr, ask.len, 0, null, 0)) != .SUCCESS) {
            f.stats.busy += 1;
            f.settle(i, true, .servfail, &.{}, "busy", .{ .detail = "channel" });
        }
    }

    fn slotAgeRequest(slot: *const Slot) age_ipc.Request {
        return .{
            .request_id = slot.seq,
            .dns_id = slot.id,
            .qtype = slot.type,
            .service = slot.service,
            .line = slot.line,
            .policy_generation = policy.generation,
            .transport = switch (slot.client) {
                .udp => .udp,
                .tcp => .tcp,
            },
            .name = slot.name,
        };
    }

    /// sendAge asks the age worker about request. A full channel loses it,
    /// counted in age_lost; any other failure ends the frontend.
    fn sendAge(f: *Frontend, request: *const age_ipc.Request) bool {
        var buf: [age_ipc.max_len]u8 = undefined;
        const packet = age_ipc.encode(&buf, request);
        const sent = linux.sendto(
            f.age_channel,
            packet.ptr,
            packet.len,
            linux.MSG.NOSIGNAL,
            null,
            0,
        );
        if (linux.errno(sent) == .AGAIN) {
            f.stats.age_lost += 1;
            return false;
        }
        if (linux.errno(sent) != .SUCCESS or sent != packet.len) f.fail("age worker channel");
        return true;
    }

    fn ageAnswers(f: *Frontend) void {
        for (0..64) |_| {
            var packet: [age_ipc.response_max + 1]u8 = undefined;
            const rc = linux.recvfrom(
                f.age_channel,
                &packet,
                packet.len,
                linux.MSG.TRUNC,
                null,
                null,
            );
            if (linux.errno(rc) == .AGAIN) return;
            if (linux.errno(rc) != .SUCCESS or rc == 0 or rc > age_ipc.response_max)
                f.fail("age worker reply");
            const age_reply = age_ipc.decodeResponse(packet[0..rc]) orelse
                f.fail("age worker reply");
            const i = for (&f.slots, 0..) |*slot, index| {
                if (slot.used and !slot.follows and slot.stage == .age and
                    slot.seq == age_reply.request_id) break index;
            } else continue;
            const slot = &f.slots[i];
            const request = slotAgeRequest(slot);
            switch (age_gate.decide(&request, &age_reply, age.psl)) {
                .ignore => continue,
                .refuse_young => f.settle(i, false, .refused, &.{}, "age", .{ .detail = "young" }),
                .refuse_unknown => f.settle(
                    i,
                    false,
                    .refused,
                    &.{},
                    "age",
                    .{ .detail = "unknown" },
                ),
                .allow => {
                    slot.stage = .upstream;
                    slot.age_source = age_reply.source;
                    if (caches[slot.service].find(slot.name.text(), slot.type, now())) |e| {
                        f.stats.cached += 1;
                        const records = e.records(&slot.name, now(), &f.records);
                        if (f.forbiddenAlias(slot, records)) |to| {
                            f.settle(i, false, .refused, &.{}, "alias", .{ .alias = &to });
                            continue;
                        }
                        f.settle(i, true, e.rcode, records, "screened", .{
                            .detail = @tagName(age_reply.source),
                            .cached = true,
                            .dropped = e.dropped,
                            .authenticated = e.authenticated,
                        });
                    } else f.sendUpstream(i);
                },
            }
        }
    }

    fn observeAge(
        f: *Frontend,
        s: u8,
        q: *const wire.Query,
        line: u16,
        t: wire.Type,
        client: Client,
    ) void {
        f.age_seq +%= 1;
        _ = f.sendAge(&.{
            .request_id = f.age_seq,
            .dns_id = q.id,
            .qtype = t,
            .service = s,
            .line = line,
            .policy_generation = policy.generation,
            .transport = switch (client) {
                .udp => .udp,
                .tcp => .tcp,
            },
            .name = q.name,
        });
    }

    fn refuse(
        f: *Frontend,
        client: Client,
        s: u8,
        q: *const wire.Query,
        why: []const u8,
        line: u16,
        x: Extra,
    ) void {
        f.stats.refused += 1;
        f.audit(s, &q.name, q.type, false, why, line, x);
        f.answer(client, q.id, q.rd, .refused, &q.name, q.type, &.{}, false);
    }

    /// busy answers SERVFAIL for want of room: detail names which.
    fn busy(
        f: *Frontend,
        client: Client,
        s: u8,
        q: *const wire.Query,
        line: u16,
        detail: []const u8,
    ) void {
        f.stats.busy += 1;
        f.stats.servfail += 1;
        f.audit(s, &q.name, q.type, false, "busy", line, .{ .detail = detail });
        f.answer(client, q.id, q.rd, .servfail, &q.name, q.type, &.{}, false);
    }

    fn ipcId(i: usize, gen: u8) u16 {
        return @as(u16, gen) << 8 | @as(u16, @intCast(i));
    }

    /// A checked origin's aliases stay in its registered domain. An exempt
    /// origin does not confer its exemption on a screened target.
    fn forbiddenAlias(f: *Frontend, slot: *const Slot, records: []const wire.Record) ?wire.Name {
        for (records) |*record| {
            if (record.type != .cname) continue;
            const to = wire.target(record);
            const target = policy.decide(slot.service, &to, @backingInt(slot.type));
            // A direct CNAME query does not follow the alias, but must not
            // return an excluded endpoint without a named grant either.
            if (slot.type == .cname) {
                if (target.why == .endpoint) return to;
                continue;
            }
            if (!target.allow) return to;
            if (slot.age_required) {
                if (!age_gate.sameRegistered(slot.name.text(), to.text(), age.psl)) return to;
            } else if (f.enforce_age and needsAge(target.why)) return to;
        }
        return null;
    }

    /// answers reads the upstream side's answers. Each must answer a slot's
    /// question as the frontend asked it; its alias targets must be granted
    /// too, since the client would follow them. A bare header and a Silence
    /// say no resolver answered, and why. EOF means upstream died.
    fn answers(f: *Frontend) void {
        for (0..64) |_| {
            const rc = linux.recvfrom(f.channel, &f.in, f.in.len, linux.MSG.TRUNC, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => if (rc == 0) f.fail("upstream closed"),
                .AGAIN => return,
                else => f.fail("upstream channel"),
            }
            if (rc > wire.response_max or rc < wire.header_len) f.fail("upstream sent garbage");
            const msg = f.in[0..rc];
            const id = std.mem.readInt(u16, msg[0..2], .big);
            const i: usize = id & 0xff;
            const slot = &f.slots[i];
            // Late, for a slot that timed out and moved on: drop it.
            if (!slot.used or slot.gen != id >> 8 or slot.stage != .upstream) continue;
            if (msg.len == wire.header_len + 1) {
                const why = std.enums.fromInt(upstream.Silence, msg[wire.header_len]) orelse
                    f.fail("upstream sent garbage");
                f.settle(i, true, .servfail, &.{}, "unanswered", .{ .detail = @tagName(why) });
                continue;
            }
            var buf: [wire.query_max]u8 = undefined;
            const asked = wire.writeQuery(&buf, id, &slot.name, slot.type, null);
            var a: wire.Answer = undefined;
            wire.parseResponse(msg, asked, &a) catch f.fail("upstream sent garbage");
            a.authenticated = a.authenticated and f.trust_ad;
            if (f.forbiddenAlias(slot, a.slice())) |to| {
                f.settle(i, false, .refused, &.{}, "alias", .{ .alias = &to });
                continue;
            }
            f.resolved(i, &a);
        }
    }

    /// resolved answers slot i's question, and those following it, with a,
    /// upstream's answer, and keeps it as long as it says. A screened answer
    /// is trimmed first. What stands is what the cache kept.
    fn resolved(f: *Frontend, i: usize, a: *wire.Answer) void {
        const slot = &f.slots[i];
        const s = slot.service;
        const why = @tagName(slot.why);
        const age_detail: ?[]const u8 = if (slot.age_required) @tagName(slot.age_source) else null;
        const ttl = cache.lifetime(a, slot.type, slot.screened);
        const dropped: screen.Dropped = if (slot.screened)
            screen.trim(a, &slot.name, slot.type)
        else
            .{};
        if (slot.screened) a.authenticated = false;
        const kept = if (ttl) |keep| caches[s].put(
            &screens[s],
            &screen_key,
            &slot.name,
            slot.type,
            a,
            keep,
            slot.screened,
            dropped,
            now(),
        ) else null;
        const e = kept orelse return f.settle(
            i,
            true,
            a.rcode,
            a.slice(),
            why,
            .{ .detail = age_detail, .dropped = dropped, .authenticated = a.authenticated },
        );
        const records = e.records(&slot.name, now(), &f.records);
        f.settle(
            i,
            true,
            e.rcode,
            records,
            why,
            .{ .detail = age_detail, .dropped = e.dropped, .authenticated = e.authenticated },
        );
    }

    /// settle finishes slot i's question and every question following it.
    fn settle(
        f: *Frontend,
        i: usize,
        allow: bool,
        rcode: wire.Rcode,
        records: []const wire.Record,
        why: []const u8,
        x: Extra,
    ) void {
        const asked = f.slots[i];
        f.finish(i, allow, rcode, records, why, x);
        var merged = x;
        merged.merged = true;
        for (&f.slots, 0..) |*o, j| if (o.used and o.follows and o.service == asked.service and
            o.type == asked.type and o.name.eql(&asked.name))
        {
            f.finish(j, allow, rcode, records, why, merged);
        };
    }

    /// finish answers a slot's question, records how it went, and frees
    /// the slot.
    fn finish(
        f: *Frontend,
        i: usize,
        allow: bool,
        rcode: wire.Rcode,
        records: []const wire.Record,
        why: []const u8,
        x: Extra,
    ) void {
        const slot = &f.slots[i];
        if (rcode == .servfail) f.stats.servfail += 1;
        if (rcode == .refused) f.stats.refused += 1;
        var done = x;
        done.rcode = rcode;
        done.answers = records.len;
        done.ms = now() - slot.start;
        const t = @backingInt(slot.type);
        f.audit(slot.service, &slot.name, t, allow, why, slot.line, done);
        f.answer(slot.client, slot.id, slot.rd, rcode, &slot.name, t, records, x.authenticated);
        f.pending[slot.service] -= 1;
        slot.used = false;
    }

    /// expire answers SERVFAIL to questions upstream never answered, and
    /// closes idle TCP clients.
    fn expire(f: *Frontend) void {
        const t = now();
        for (&f.slots, 0..) |*s, i| if (s.used and t - s.start > slot_ms) {
            if (s.stage == .age)
                f.settle(i, false, .refused, &.{}, "age", .{ .detail = "timeout" })
            else
                f.settle(i, true, .servfail, &.{}, "timeout", .{});
        };
        for (&f.conns, 0..) |*c, i| if (c.fd >= 0 and !c.waiting and
            t > c.deadline) f.closeConn(@intCast(i));
        if (t - f.last_stats >= stats_ms) {
            f.last_stats = t;
            if (!std.meta.eql(f.stats, f.reported)) {
                f.reported = f.stats;
                const s = f.stats;
                f.say("{{\"event\":\"stats\",\"queries\":{d},\"cached\":{d},\"merged\":{d},\"" ++
                    "refused\":{d},\"tunnel\":{d},\"servfail\":{d},\"busy\":{d},\"malformed\":{d" ++
                    "},\"" ++
                    "lost\":{d},\"age_lost\":{d}}}", .{
                    s.queries,  s.cached, s.merged,    s.refused, s.tunnel,
                    s.servfail, s.busy,   s.malformed, s.lost,    s.age_lost,
                });
            }
        }
    }

    /// header is the reply to a query that could not be read: its ID alone.
    fn header(f: *Frontend, msg: []const u8, rcode: wire.Rcode) []const u8 {
        if (msg.len < wire.header_len) return &.{};
        const id = std.mem.readInt(u16, msg[0..2], .big);
        return wire.writeResponse(f.out[2..], id, false, rcode, null, &.{}, null, wire.udp_max);
    }

    fn answer(
        f: *Frontend,
        client: Client,
        id: u16,
        rd: bool,
        rcode: wire.Rcode,
        name: *const wire.Name,
        t: u16,
        records: []const wire.Record,
        authenticated: bool,
    ) void {
        const limit: usize = if (client == .udp) wire.udp_max else wire.response_max;
        f.reply(
            client,
            wire.writeResponseWithAd(
                f.out[2..],
                id,
                rd,
                rcode,
                .{ .name = name, .type = t },
                records,
                null,
                limit,
                authenticated,
            ),
        );
    }

    /// reply sends msg, which is in f.out after two bytes left for TCP's
    /// length. An empty msg sends nothing, but frees a TCP client to ask again.
    fn reply(f: *Frontend, client: Client, msg: []const u8) void {
        switch (client) {
            .udp => |addr| if (msg.len > 0) {
                _ = linux.sendto(
                    f.udp,
                    msg.ptr,
                    msg.len,
                    0,
                    @ptrCast(&addr),
                    @sizeOf(linux.sockaddr.in),
                );
            },
            .tcp => |i| {
                if (i == max_conns) return;
                const c = &f.conns[i];
                c.waiting = false;
                if (msg.len == 0) return f.closeConn(i);
                std.mem.writeInt(u16, f.out[0..2], @intCast(msg.len), .big);
                // A client that cannot take its whole answer now is closed.
                const rc = linux.write(c.fd, &f.out, msg.len + 2);
                if (linux.errno(rc) != .SUCCESS or rc != msg.len + 2) f.closeConn(i);
            },
        }
    }

    fn unlabeled(f: *Frontend, from: [4]u8) void {
        f.stats.refused += 1;
        f.say(
            "{{\"event\":\"query\",\"source\":\"{d}.{d}.{d}.{d}\",\"decision\":\"deny\",\"why\":" ++
                "\"unlabeled\"}}",
            .{ from[0], from[1], from[2], from[3] },
        );
    }

    /// Extra is what an audit record says beyond who asked what and why.
    const Extra = struct {
        /// detail names which sign, budget, limit or failure: every
        /// question that gets no answer says why.
        detail: ?[]const u8 = null,
        /// bits is a name's score, in bits per character, when it looked
        /// like data.
        bits: f32 = 0,
        /// rcode is set once a question is answered, with answers and ms.
        rcode: ?wire.Rcode = null,
        answers: usize = 0,
        ms: i64 = 0,
        alias: ?*const wire.Name = null,
        /// dropped counts the records a screened answer left out.
        dropped: screen.Dropped = .{},
        /// cached is an answer from the cache; merged, one to the same
        /// question asked while this one was out.
        cached: bool = false,
        merged: bool = false,
        authenticated: bool = false,
    };

    /// audit records one decision: who asked what, the answer and why.
    /// Names are canonical, so they need no escaping.
    fn audit(
        f: *Frontend,
        s: u8,
        name: ?*const wire.Name,
        t: u16,
        allow: bool,
        why: []const u8,
        line: u16,
        x: Extra,
    ) void {
        f.seq += 1;
        var tbuf: [8]u8 = undefined;
        const type_text = if (wire.Type.from(t)) |known|
            std.ascii.upperString(&tbuf, @tagName(known))
        else
            std.mem.print(&tbuf, "{d}", .{t}) catch unreachable;
        var buf: [768]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        w.print("unwound: {{\"event\":\"query\",\"seq\":{d},\"uid\":{f},\"decision\":\"{s}\",\"w" ++
            "hy\":\"{s}\"", .{
            f.seq, std.json.fmt(policy.uid(s), .{}), if (allow) "allow" else "deny", why,
        }) catch {};
        if (x.detail) |d| w.print(",\"detail\":\"{s}\"", .{d}) catch {};
        if (x.bits > 0) w.print(",\"bits\":{d:.2}", .{x.bits}) catch {};
        if (name) |n| w.print(
            ",\"name\":\"{s}\",\"type\":\"{s}\"",
            .{ n.text(), type_text },
        ) catch {};
        if (line != 0) w.print(",\"rule\":{d}", .{line}) catch {};
        w.print(",\"generation\":\"{x:0>8}\"", .{policy.generation}) catch {};
        if (x.rcode) |rcode| w.print(
            ",\"rcode\":\"{s}\",\"answers\":{d},\"ms\":{d}",
            .{ @tagName(rcode), x.answers, x.ms },
        ) catch {};
        if (x.alias) |a| w.print(",\"alias\":\"{s}\"", .{a.text()}) catch {};
        if (x.cached) w.writeAll(",\"cached\":true") catch {};
        if (x.merged) w.writeAll(",\"merged\":true") catch {};
        if (x.authenticated) w.writeAll(",\"dnssec\":true") catch {};
        inline for (comptime std.meta.fieldNames(screen.Dropped)) |field| {
            const n = @field(x.dropped, field);
            if (n > 0) w.print(",\"dropped_" ++ field ++ "\":{d}", .{n}) catch {};
        }
        w.writeAll("}\n") catch {};
        f.send(w.buffered());
    }

    fn say(f: *Frontend, comptime fmt: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        f.send(std.mem.print(&buf, "unwound: " ++ fmt ++ "\n", args) catch return);
    }

    fn send(f: *Frontend, line: []const u8) void {
        const rc = linux.write(f.log, line.ptr, line.len);
        // Logging is best effort and never changes a DNS decision or answer.
        if (linux.errno(rc) != .SUCCESS or rc != line.len) f.stats.lost +|= 1;
    }
};

test {
    _ = @import("wire.zig");
    _ = @import("policy.zig");
    _ = @import("screen.zig");
    _ = @import("cache.zig");
    _ = @import("upstream.zig");
}
