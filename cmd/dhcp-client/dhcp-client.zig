//! dhcp-client gets an IPv4 address from the network's DHCP server and keeps
//! it: `dhcp up NIC` gets a lease, `dhcp keep` renews it. An unprivileged
//! engine parses the wire; its parent applies leases. See README.md.

const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const sandbox = @import("sandbox");
const network = @import("network");
const sys = sandbox.sys;

const state_dir = "/run/werewolf/network";
const nic_path = state_dir ++ "/nic";
const lease_path = state_dir ++ "/lease.json";
const empty_dir = "/var/empty";
/// engine_id is the uid of _dhcp, defined in forms/prod/apko.yaml.
const engine_id: u32 = 67;

const client_port = 68;
const server_port = 67;
const cookie = [4]u8{ 99, 130, 83, 99 };
const max_routes = 8;
const max_dns = 3;
/// wanted lists the options we ask for: subnet mask, router, DNS, MTU, lease
/// time, server, renewal and rebinding times, classless static routes.
const wanted = [_]u8{ 1, 3, 6, 26, 51, 54, 58, 59, 121 };

const Ip4 = [4]u8;
const zero: Ip4 = .{ 0, 0, 0, 0 };

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    // Disable Speculative Store Bypass for both processes. werewolf leaves
    // this to each program so workloads do not pay for it
    // (docs/security.md). On a CPU without the control, prctl fails and
    // nothing changes.
    _ = linux.prctl(
        @backingInt(linux.PR.SET_SPECULATION_CTRL),
        linux.PR.SPEC_STORE_BYPASS,
        linux.PR.SPEC_FORCE_DISABLE,
        0,
        0,
    );
    const args = try init.minimal.args.toSlice(gpa);
    const mode: Mode = if (args.len == 3 and std.mem.eql(u8, args[1], "up"))
        .up
    else if (args.len == 2 and std.mem.eql(u8, args[1], "keep"))
        .keep
    else {
        std.debug.print("usage: dhcp up NIC | dhcp keep\n", .{});
        std.process.exit(2);
    };
    start(init.io, gpa, mode, if (mode == .up) args[2] else "") catch |err| {
        var log: Log = .{};
        log.event(
            "error",
            .{
                .step = "start",
                .@"error" = @errorName(err),
                .detail = sandbox.failed,
                .errno = sandbox.errnoName(sandbox.failed_errno),
            },
        );
        std.process.exit(1);
    };
}

const Mode = enum { up, keep };

/// start runs as root. It opens everything both processes need, including
/// the filtered packet socket, before it forks, so neither process needs
/// privilege to open anything later.
fn start(io: Io, gpa: Allocator, mode: Mode, arg_nic: []const u8) !void {
    var log: Log = .{};
    try Dir.cwd().createDirPath(io, state_dir);
    const nic = switch (mode) {
        .up => arg_nic,
        .keep => std.mem.trim(u8, Dir.cwd().readFileAlloc(
            io,
            nic_path,
            gpa,
            .limited(64),
        ) catch |err| switch (err) {
            error.FileNotFound => park(),
            else => return err,
        }, " \n"),
    };
    if (mode == .up) try Dir.cwd().writeFile(io, .{ .sub_path = nic_path, .data = nic });

    // keep renews the lease up left. If it cannot be read, the engine gets
    // a new one.
    var held: ?Wire = null;
    if (mode == .keep) {
        if (Dir.cwd().readFileAlloc(io, lease_path, gpa, .limited(64 << 10))) |data| {
            held = heldFrom(gpa, data);
            if (held == null) log.event("unreadable", .{ .nic = nic, .file = lease_path });
        } else |err| if (err != error.FileNotFound) return err;
    }

    const link = try Link.open(nic);
    // Log the carrier wait separately, so a NIC that comes up late (Hyper-V's,
    // after its VMBus handshake) is not blamed on the DHCP exchange.
    log.event("link", .{ .nic = nic, .carrier = link.carrier, .waited_ms = link.waited_ms });
    const dir = try sys(
        linux.openat(
            linux.AT.FDCWD,
            state_dir,
            .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true },
            0,
        ),
        "open " ++ state_dir,
    );
    var sp: [2]i32 = undefined;
    _ = try sys(
        linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &sp),
        "socketpair",
    );
    const parent_pid = linux.getpid();

    const pid = try sys(linux.fork(), "fork");
    if (pid == 0) {
        _ = linux.close(sp[0]);
        _ = linux.close(link.inet);
        _ = linux.close(@intCast(dir));
        var e: Engine = .{ .pkt = link.packet, .sp = sp[1], .index = link.index, .mac = link.mac };
        e.confine(parent_pid) catch e.fail();
        e.run(mode, held) catch e.fail();
        linux.exit_group(0);
    }
    _ = linux.close(sp[1]);
    _ = linux.close(link.packet);
    var p: Parent = .{
        .mode = mode,
        .sp = sp[0],
        .dir = @intCast(dir),
        .link = link,
        .nic = nic,
        .applied = held,
    };
    try p.confine();
    p.run();
}

/// park idles forever when up left no NIC to keep. It runs as _dhcp in an
/// empty root and may only sleep.
fn park() noreturn {
    sandbox.dropTo(engine_id, empty_dir) catch linux.exit_group(1);
    var f: sandbox.Filter = .{};
    inline for (.{ "nanosleep", "clock_nanosleep", "restart_syscall", "exit_group" }) |call|
        f.allow(call);
    f.install() catch linux.exit_group(1);
    while (true) sleep(1 << 30);
}

// --- the engine --------------------------------------------------------------

const Engine = struct {
    pkt: i32,
    sp: i32,
    index: i32,
    mac: [6]u8,
    step: Step = .sandbox,
    errno: u16 = 0,
    /// sent counts the broadcasts for the lease being sought, DISCOVERs then
    /// REQUESTs. With the fields below it lets the log show how slow a
    /// server was, or how many broadcasts went unheard (Azure takes 2 s).
    sent: u8 = 0,
    offered_after: u8 = 0,
    started: i64 = 0,
    offer_ms: u32 = 0,

    const Step = enum(u8) { sandbox, discover, request, renew, send };

    /// confine ties the engine to the parent's life, drops to _dhcp in an
    /// empty chroot with no capabilities, and installs a seccomp filter that
    /// kills it for any call beyond its packet socket, writes to the parent,
    /// polling, the clock and random numbers.
    fn confine(e: *Engine, parent_pid: linux.pid_t) !void {
        _ = try e.sys(linux.prctl(
            @backingInt(linux.PR.SET_PDEATHSIG),
            @backingInt(linux.SIG.KILL),
            0,
            0,
            0,
        ));
        if (linux.getppid() != parent_pid) return error.ParentGone;
        sandbox.dropTo(engine_id, empty_dir) catch |err| {
            e.errno = @backingInt(linux.E.PERM);
            return err;
        };
        var f: sandbox.Filter = .{};
        f.allowArg("sendto", 0, @intCast(e.pkt));
        f.allowArg("recvfrom", 0, @intCast(e.pkt));
        f.allowArg("write", 0, @intCast(e.sp));
        inline for (.{
            "poll",      "ppoll",           "clock_gettime", "nanosleep", "clock_nanosleep",
            "getrandom", "restart_syscall", "exit_group",    "exit",
        }) |call| f.allow(call);
        try f.install();
    }

    fn run(e: *Engine, mode: Mode, start_held: ?Wire) !void {
        if (mode == .up) {
            const w = try e.acquire(30) orelse return e.send(.failed, std.mem.zeroes(Wire));
            return e.send(.bound, w);
        }
        var held = start_held;
        while (true) {
            const now = boottime();
            if (held) |h| {
                const t = timers(h.lease, h.t1, h.t2);
                if (now < h.bound + t.t1) {
                    sleep(h.bound + t.t1 - now);
                    continue;
                }
                if (now < h.bound + t.lease) {
                    const left: u32 = @intCast(h.bound + t.lease - now);
                    if (try e.renew(h, @min(left, 60))) |r| switch (r.kind) {
                        .ack => {
                            held = r.lease;
                            try e.send(.renewed, r.lease);
                        },
                        .nak => {
                            try e.send(.refused, h);
                            held = null;
                        },
                        .offer => unreachable,
                    } else sleep(@max(10, @min(60, left / 2)));
                    continue;
                }
                try e.send(.expired, h);
                held = null;
            }
            if (try e.acquire(60)) |w| {
                held = w;
                try e.send(.bound, w);
            } else try e.send(.waiting, std.mem.zeroes(Wire));
        }
    }

    /// acquire runs DISCOVER, OFFER, REQUEST, ACK and returns the lease, or
    /// null if no server finished within seconds. The ACK must come from the
    /// server that offered, for the address it offered.
    fn acquire(e: *Engine, seconds: u32) !?Wire {
        e.begin();
        const deadline = e.started + @as(i64, seconds) * 1000;
        // After a round with no lease (an unusable OFFER, an answer from
        // another server, a NAK), wait 0.25 s, doubling to 8 s. Otherwise a
        // peer that answers at once with junk would set our broadcast rate.
        var pause: i64 = 0;
        while (nowMs() < deadline) {
            if (pause > 0) {
                const ms = @min(pause, deadline - nowMs());
                if (ms > 0) {
                    const ts: linux.timespec = .{
                        .sec = @divFloor(ms, 1000),
                        .nsec = @mod(ms, 1000) * std.time.ns_per_ms,
                    };
                    _ = linux.nanosleep(&ts, null);
                }
            }
            pause = if (pause == 0) 250 else @min(pause * 2, 8000);
            const xid = newXid();
            var buf: [576]u8 = undefined;
            e.step = .discover;
            const offer = try e.exchange(
                message(&buf, 1, xid, e.mac, zero, null, null),
                zero,
                xid,
                deadline,
                true,
            ) orelse return null;
            if (!usable(offer.lease.addr) or
                !usable(offer.lease.server)) continue;
            e.offered_after = e.sent;
            e.offer_ms = e.since();
            e.step = .request;
            const ack = try e.exchange(
                message(&buf, 3, xid, e.mac, zero, offer.lease.addr, offer.lease.server),
                zero,
                xid,
                deadline,
                false,
            ) orelse return null;
            if (!std.mem.eql(u8, &ack.lease.server, &offer.lease.server)) continue;
            switch (ack.kind) {
                .ack => if (std.mem.eql(u8, &ack.lease.addr, &offer.lease.addr) and
                    valid(ack.lease))
                {
                    var w = ack.lease;
                    w.bound = boottime();
                    return w;
                },
                .nak => try e.send(.refused, offer.lease),
                .offer => {},
            }
        }
        return null;
    }

    /// renew sends a REQUEST for the held lease. It returns the server's ACK
    /// for the same address, or its NAK; null for no answer, or an answer
    /// from any other server.
    fn renew(e: *Engine, h: Wire, seconds: u32) !?Reply {
        e.begin();
        const xid = newXid();
        var buf: [576]u8 = undefined;
        e.step = .renew;
        var r = try e.exchange(
            message(&buf, 3, xid, e.mac, h.addr, null, null),
            h.addr,
            xid,
            nowMs() + @as(i64, seconds) * 1000,
            false,
        ) orelse return null;
        if (!std.mem.eql(u8, &r.lease.server, &h.server)) return null;
        switch (r.kind) {
            .ack => {
                if (!std.mem.eql(u8, &r.lease.addr, &h.addr) or !valid(r.lease)) return null;
                r.lease.bound = boottime();
                return r;
            },
            .nak => return r,
            .offer => return null,
        }
    }

    /// exchange broadcasts msg from src until a reply to xid arrives or
    /// deadline passes. It resends every 0.25 s for the first quick_ms, then
    /// backs off 0.5, 1, 2, 4 and 8 s. offer says whether to take an OFFER
    /// or an ACK/NAK.
    ///
    /// The first broadcasts of a boot often go unheard (one boot in three
    /// under Lima's vzNAT, most on Azure, for 0.6 to 4.4 s), so the quick
    /// phase saves up to 2 s per boot. A server may answer the same xid
    /// twice (ISC dhcpd, dnsmasq), so a late second OFFER is skipped while
    /// waiting for the ACK. Each wait is jittered from half to one and a half
    /// of its value (RFC 2131 4.1) so machines booting together do not
    /// resend in step. A failed send or receive, such as a brief link drop,
    /// counts as an unanswered round, because nothing restarts keep.
    fn exchange(
        e: *Engine,
        msg: []const u8,
        src: Ip4,
        xid: u32,
        deadline: i64,
        offer: bool,
    ) !?Reply {
        var out: [28 + 576]u8 = undefined;
        const pkt = frame(&out, src, msg);
        const to: linux.sockaddr.ll = .{
            .protocol = std.mem.nativeToBig(u16, linux.ETH.P.IP),
            .ifindex = e.index,
            .hatype = 0,
            .pkttype = 0,
            .halen = 6,
            .addr = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0 },
        };
        var wait: i64 = 250;
        while (nowMs() < deadline) {
            // RFC 2131 has the client fill secs with the seconds since its
            // first broadcast, and some servers act on it.
            const secs: u16 = @intCast(@min(e.since() / 1000, 0xffff));
            std.mem.writeInt(u16, out[28 + 8 ..][0..2], secs, .big);
            _ = linux.sendto(e.pkt, pkt.ptr, pkt.len, 0, @ptrCast(&to), @sizeOf(linux.sockaddr.ll));
            e.sent +|= 1;
            const spread: i64 = newXid() % @as(u32, @intCast(wait));
            const until = @min(deadline, nowMs() + @divFloor(wait, 2) + spread);
            while (true) {
                const left = until - nowMs();
                if (left <= 0) break;
                var fds = [1]linux.pollfd{.{ .fd = e.pkt, .events = linux.POLL.IN, .revents = 0 }};
                const n = linux.poll(&fds, 1, @intCast(left));
                if (linux.errno(n) == .INTR) continue;
                if (try e.sys(n) == 0) break;
                var in: [1536]u8 = undefined;
                const got = linux.recvfrom(e.pkt, &in, in.len, linux.MSG.DONTWAIT, null, null);
                switch (linux.errno(got)) {
                    .SUCCESS => {},
                    .INTR, .AGAIN => continue,
                    else => {
                        // Sleep out the round: poll would report the error
                        // at once, and we would spin.
                        const ts: linux.timespec = .{
                            .sec = @divFloor(left, 1000),
                            .nsec = @mod(left, 1000) * std.time.ns_per_ms,
                        };
                        _ = linux.nanosleep(&ts, null);
                        break;
                    },
                }
                const payload = unframe(in[0..got]) orelse continue;
                if (parseReply(payload, xid, e.mac)) |r| if ((r.kind == .offer) == offer) return r;
            }
            wait = if (e.since() < quick_ms) 250 else @min(wait * 2, 8000);
        }
        return null;
    }

    fn send(e: *Engine, event: Event, w: Wire) !void {
        e.step = .send;
        const m: Msg = .{
            .event = @backingInt(event),
            .step = @backingInt(e.step),
            .errno = e.errno,
            .sent = e.sent,
            .offered_after = e.offered_after,
            .offer_ms = e.offer_ms,
            .ms = e.since(),
            .lease = w,
        };
        const n = try e.sys(linux.write(e.sp, std.mem.asBytes(&m), @sizeOf(Msg)));
        if (n != @sizeOf(Msg)) return error.ShortWrite;
    }

    /// fail tells the parent which step failed, and exits.
    fn fail(e: *Engine) noreturn {
        if (e.errno == 0) e.errno = 1;
        const m: Msg = .{
            .event = @backingInt(Event.@"error"),
            .step = @backingInt(e.step),
            .errno = e.errno,
            .lease = std.mem.zeroes(Wire),
        };
        _ = linux.write(e.sp, std.mem.asBytes(&m), @sizeOf(Msg));
        linux.exit_group(1);
    }

    /// begin resets the counters and starts the clock for a new lease.
    fn begin(e: *Engine) void {
        e.sent = 0;
        e.offered_after = 0;
        e.offer_ms = 0;
        e.started = nowMs();
    }

    /// since returns the ms since begin.
    fn since(e: *const Engine) u32 {
        return @intCast(std.math.clamp(nowMs() - e.started, 0, std.math.maxInt(u32)));
    }

    fn sys(e: *Engine, rc: usize) !usize {
        const err = linux.errno(rc);
        if (err == .SUCCESS) return rc;
        e.errno = @backingInt(err);
        return error.SystemCall;
    }
};

// --- the parent --------------------------------------------------------------

const Parent = struct {
    mode: Mode,
    sp: i32,
    dir: i32,
    link: Link,
    nic: []const u8,
    /// applied is the lease on the NIC. keep starts from the one up applied.
    applied: ?Wire = null,
    log: Log = .{},

    /// confine keeps only CAP_NET_ADMIN, lets Landlock limit writes to
    /// /run/werewolf/network, and installs a seccomp filter that kills the
    /// parent for any call but the four ioctls and the file calls it needs.
    fn confine(p: *Parent) !void {
        try sandbox.keepOnly(1 << linux.CAP.NET_ADMIN);
        try sandbox.landlock(&.{.{ .fd = p.dir, .access = sandbox.own_files }}, &.{});

        var f: sandbox.Filter = .{};
        f.allowArg("read", 0, @intCast(p.sp));
        f.allowArg("ioctl", 1, linux.SIOCSIFADDR);
        f.allowArg("ioctl", 1, linux.SIOCSIFNETMASK);
        f.allowArg("ioctl", 1, linux.SIOCSIFMTU);
        f.allowArg("ioctl", 1, linux.SIOCADDRT);
        inline for (.{
            "write",         "openat",          "close",      "renameat", "renameat2",
            "clock_gettime", "restart_syscall", "exit_group", "exit",
        }) |call| f.allow(call);
        try f.install();
    }

    /// run handles the engine's messages. When the engine exits or sends a
    /// bad message, the parent exits too.
    fn run(p: *Parent) noreturn {
        while (true) {
            var m: Msg = undefined;
            const n = linux.read(p.sp, std.mem.asBytes(&m), @sizeOf(Msg));
            if (linux.errno(n) == .INTR) continue;
            if (linux.errno(n) != .SUCCESS or n != @sizeOf(Msg)) {
                p.log.event(
                    "error",
                    .{
                        .nic = p.nic,
                        .step = "engine",
                        .@"error" = if (n == 0) "EngineExited" else "BadMessage",
                    },
                );
                linux.exit_group(1);
            }
            p.handle(m) catch |err| {
                p.log.event(
                    "error",
                    .{
                        .nic = p.nic,
                        .step = "apply",
                        .@"error" = @errorName(err),
                        .detail = sandbox.failed,
                        .errno = sandbox.errnoName(sandbox.failed_errno),
                    },
                );
                linux.exit_group(1);
            };
        }
    }

    fn handle(p: *Parent, m: Msg) !void {
        const event = std.enums.fromInt(Event, m.event) orelse return error.BadMessage;
        switch (event) {
            .bound, .renewed => {
                // The engine checked this already. A lease that fails here
                // means the engine is compromised.
                if (!valid(m.lease) or m.lease.bound > boottime()) return error.InvalidLease;
                if (p.applied) |a| if (!samePlan(a, m.lease)) {
                    try p.link.withdraw();
                    var ip: [16]u8 = undefined;
                    p.log.event("withdrawn", .{
                        .nic = p.nic,
                        .ip = ipText(&ip, a.addr),
                        .reason = "the new lease differs",
                    });
                };
                try p.link.apply(p.dir, m.lease, &p.log, p.nic);
                p.applied = m.lease;
                var fba: [16 << 10]u8 = undefined;
                var a: std.heap.FixedBufferAllocator = .init(&fba);
                const text = try describe(a.allocator(), p.nic, m.lease);
                var json: [8 << 10]u8 = undefined;
                var w: Io.Writer = .fixed(&json);
                try std.json.Stringify.value(text, .{}, &w);
                try writeFile(p.dir, "lease.json", w.buffered());
                p.log.event("exchange", .{
                    .nic = p.nic,
                    .sent = m.sent,
                    .ms = m.ms,
                    .discovers = m.offered_after,
                    .offer_ms = m.offer_ms,
                });
                p.log.event(@tagName(event), text);
                if (p.mode == .up) linux.exit_group(0);
            },
            .refused => {
                // The server says the address is not ours. Remove it if it
                // is the one on the NIC.
                const ours = if (p.applied) |a| std.mem.eql(u8, &a.addr, &m.lease.addr) else false;
                if (ours) {
                    try p.link.withdraw();
                    p.applied = null;
                }
                var ip: [16]u8 = undefined;
                p.log.event("refused", .{
                    .nic = p.nic,
                    .ip = ipText(&ip, m.lease.addr),
                    .withdrawn = ours,
                });
            },
            .expired => {
                // No server answered. Keep the address until a new lease
                // comes: a cloud's address does not change, and a server
                // that is briefly down should not take the machine offline.
                var ip: [16]u8 = undefined;
                p.log.event("expired", .{
                    .nic = p.nic,
                    .ip = ipText(&ip, m.lease.addr),
                    .kept = p.applied != null,
                });
            },
            .waiting => p.log.event("waiting", .{ .nic = p.nic }),
            .failed => {
                p.log.event("failed", .{ .nic = p.nic, .seconds = 30 });
                linux.exit_group(1);
            },
            .@"error" => {
                const step = std.enums.fromInt(Engine.Step, m.step) orelse return error.BadMessage;
                const err: linux.E = @fromBackingInt(@intCast(m.errno));
                p.log.event(
                    "error",
                    .{ .nic = p.nic, .step = @tagName(step), .errno = sandbox.errnoName(err) },
                );
                linux.exit_group(1);
            },
        }
    }
};

/// writeFile replaces name in dir atomically: it writes name.new, then
/// renames it over name.
fn writeFile(dir: i32, comptime name: [:0]const u8, data: []const u8) !void {
    const tmp = std.fmt.comptimePrint("{s}.new", .{name});
    const fd = try sys(
        linux.openat(
            dir,
            tmp,
            .{
                .ACCMODE = .WRONLY,
                .CREAT = true,
                .TRUNC = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            },
            0o644,
        ),
        "open " ++ name,
    );
    defer _ = linux.close(@intCast(fd));
    var off: usize = 0;
    while (off < data.len) off += try sys(
        linux.write(@intCast(fd), data[off..].ptr, data.len - off),
        "write " ++ name,
    );
    _ = try sys(linux.renameat(dir, tmp, dir, name), "rename " ++ name);
}

// --- messages between the two ------------------------------------------------

const Event = enum(u8) { bound, renewed, refused, expired, waiting, failed, @"error" };

/// Msg is one message from the engine to the parent. It has a fixed size, so
/// the parent rejects any read of another length.
const Msg = extern struct {
    event: u8,
    step: u8,
    errno: u16,
    /// ms and offer_ms are the ms from the first broadcast to the lease and
    /// to the offer; sent and offered_after count broadcasts likewise.
    ms: u32 = 0,
    offer_ms: u32 = 0,
    sent: u8 = 0,
    offered_after: u8 = 0,
    pad: u16 = 0,
    lease: Wire,
};

/// Wire is a lease as the engine parsed it and the parent applies it.
const Wire = extern struct {
    addr: Ip4,
    mask: Ip4 = .{ 255, 255, 255, 255 },
    server: Ip4 = zero,
    /// router is zero when the server sent none.
    router: Ip4 = zero,
    dns: [max_dns]Ip4 = @splat(zero),
    routes: [max_routes]Route = @splat(.{ .dst = zero, .gw = zero, .prefix = 0 }),
    ndns: u8 = 0,
    nroutes: u8 = 0,
    mtu: u16 = 0,
    lease: u32 = 0,
    t1: u32 = 0,
    t2: u32 = 0,
    /// bound is the CLOCK_BOOTTIME second the lease was given.
    bound: i64 = 0,
};

/// quick_ms is how long Engine.exchange resends every 0.25 s before backing
/// off. It is longer than Azure's server takes to hear the first broadcast.
const quick_ms = 5000;

/// max_mtu is the largest MTU taken from a server. EC2 offers 9001, and ENA
/// allows up to 9216.
const max_mtu = 9216;

const Route = extern struct {
    dst: Ip4,
    /// gw is zero for a route on the link.
    gw: Ip4,
    prefix: u8,
    pad: [3]u8 = .{ 0, 0, 0 },
};

/// valid reports whether a lease is safe to put on a NIC. The engine checks
/// before sending a lease, and the parent again before applying it.
fn valid(w: Wire) bool {
    if (!usable(w.addr) or !usable(w.server)) return false;
    const p = prefixOf(w.mask);
    if (p < 8 or p > 32) return false;
    if (p <= 30) {
        // Reject the subnet's network and broadcast addresses.
        const host = std.mem.readInt(u32, &w.addr, .big) & ~std.mem.readInt(u32, &w.mask, .big);
        if (host == 0 or host == ~std.mem.readInt(u32, &w.mask, .big)) return false;
    }
    if (!usableGateway(w.router, w.addr)) return false;
    if (w.ndns > max_dns or w.nroutes > max_routes) return false;
    for (w.dns[0..w.ndns]) |d| if (!usable(d)) return false;
    for (w.routes[0..w.nroutes]) |r| {
        if (r.prefix > 32 or !std.mem.eql(u8, &masked(r.dst, r.prefix), &r.dst)) return false;
        if (r.prefix > 0 and !usable(r.dst)) return false;
        if (!usableGateway(r.gw, w.addr)) return false;
    }
    if (w.mtu != 0 and (w.mtu < 576 or w.mtu > max_mtu)) return false;
    // Cap bound so adding any u32 lease time cannot overflow. The parent
    // also checks it against the clock (Parent.handle).
    if (w.bound < 0 or w.bound > 1 << 40) return false;
    return w.lease > 0;
}

/// usableGateway reports whether gw is zero (none), or a usable address
/// other than the lease's.
fn usableGateway(gw: Ip4, addr: Ip4) bool {
    if (std.mem.eql(u8, &gw, &zero)) return true;
    return usable(gw) and !std.mem.eql(u8, &gw, &addr);
}

// --- the parent's view: text, logged and kept --------------------------------

/// Lease is the lease as text, kept in lease.json and logged. ip and gw use
/// the same names as a static network's (lib/network.zig).
const Lease = struct {
    nic: []const u8,
    /// ip is the address and prefix, such as "10.128.0.5/32".
    ip: []const u8,
    server: []const u8,
    gw: ?[]const u8 = null,
    /// routes holds "10.128.0.1/32" (on the link) or "0.0.0.0/0 via 10.128.0.1".
    routes: []const []const u8 = &.{},
    dns: []const []const u8 = &.{},
    mtu: u16 = 0,
    lease: u32,
    t1: u32,
    t2: u32,
    bound: i64,
};

fn describe(gpa: Allocator, nic: []const u8, w: Wire) !Lease {
    var routes: std.ArrayList([]const u8) = .empty;
    var plan_buf: [max_routes + 2]Route = undefined;
    for (plan(w, &plan_buf)) |rt| {
        const dst = try gpa.print(
            "{s}/{d}",
            .{ try ipString(gpa, rt.dst), rt.prefix },
        );
        try routes.append(
            gpa,
            if (std.mem.eql(u8, &rt.gw, &zero))
                dst
            else
                try gpa.print("{s} via {s}", .{ dst, try ipString(gpa, rt.gw) }),
        );
    }
    var dns: std.ArrayList([]const u8) = .empty;
    for (w.dns[0..w.ndns]) |d| try dns.append(gpa, try ipString(gpa, d));
    return .{
        .nic = nic,
        .ip = try gpa.print(
            "{s}/{d}",
            .{ try ipString(gpa, w.addr), prefixOf(w.mask) },
        ),
        .server = try ipString(gpa, w.server),
        .gw = if (std.mem.eql(u8, &w.router, &zero)) null else try ipString(gpa, w.router),
        .routes = routes.items,
        .dns = dns.items,
        .mtu = w.mtu,
        .lease = w.lease,
        .t1 = w.t1,
        .t2 = w.t2,
        .bound = w.bound,
    };
}

/// heldFrom parses lease.json into the lease on the NIC, or returns null.
/// The engine needs the address, server and times to renew; the parent needs
/// the mask and routes to tell whether a new lease changes the NIC.
fn heldFrom(gpa: Allocator, data: []const u8) ?Wire {
    const l = std.json.parseFromSliceLeaky(
        Lease,
        gpa,
        data,
        .{ .ignore_unknown_fields = true },
    ) catch return null;
    const a = network.cidr(l.ip) catch return null;
    var w: Wire = .{
        .addr = a.addr,
        .mask = maskOf(a.prefix),
        .server = network.ip4(l.server) catch return null,
        .lease = l.lease,
        .t1 = l.t1,
        .t2 = l.t2,
        .bound = l.bound,
    };
    if (l.routes.len > max_routes) return null;
    for (l.routes, 0..) |text, i| w.routes[i] = parseRoute(text) orelse return null;
    w.nroutes = @intCast(l.routes.len);
    return if (valid(w)) w else null;
}

/// parseRoute parses a route as describe writes it: "D.D.D.D/N" on the
/// link, or "D.D.D.D/N via G.G.G.G".
fn parseRoute(s: []const u8) ?Route {
    var dst_text = s;
    var gw = zero;
    if (std.mem.find(u8, s, " via ")) |i| {
        dst_text = s[0..i];
        gw = network.ip4(s[i + " via ".len ..]) catch return null;
    }
    const dst = network.cidr(dst_text) catch return null;
    return .{ .dst = dst.addr, .gw = gw, .prefix = dst.prefix };
}

/// Log writes JSON lines to stdout: `dhcp-client: {"time":...,"event":...}`.
/// It uses a fixed buffer, so logging cannot fail for lack of memory.
const Log = struct {
    buf: [8 << 10]u8 = undefined,

    fn event(l: *Log, name: []const u8, fields: anytype) void {
        var w: Io.Writer = .fixed(&l.buf);
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.REALTIME, &ts);
        var time: [20]u8 = undefined;
        w.print(
            "dhcp-client: {{\"time\":\"{s}\",\"event\":\"{s}\",",
            .{ rfc3339(&time, @intCast(ts.sec)), name },
        ) catch return;
        const mark = w.end;
        std.json.Stringify.value(fields, .{}, &w) catch return;
        // Drop the fields' opening brace so they continue the line's object.
        @memmove(l.buf[mark .. w.end - 1], l.buf[mark + 1 .. w.end]);
        w.end -= 1;
        w.writeByte('\n') catch return;
        _ = linux.write(1, w.buffered().ptr, w.buffered().len);
    }
};

// --- the link ----------------------------------------------------------------

const Link = struct {
    /// name is NUL-terminated, as the kernel wants it.
    name: [linux.IFNAMESIZE]u8,
    index: i32,
    mac: [6]u8,
    /// packet is the engine's packet socket.
    packet: i32,
    /// inet is an inet socket for the parent's ioctls.
    inet: i32,
    /// waited_ms is how long open waited for carrier; carrier says if it came.
    waited_ms: i64,
    carrier: bool,

    fn open(nic: []const u8) !Link {
        if (nic.len == 0 or nic.len >= linux.IFNAMESIZE) {
            sandbox.failed = "the NIC's name";
            return error.BadNicName;
        }
        var l: Link = undefined;
        l.name = @splat(0);
        @memcpy(l.name[0..nic.len], nic);
        l.inet = @intCast(try sys(
            linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0),
            "socket inet",
        ));

        var ifr = l.ifreq();
        _ = try sys(linux.ioctl(l.inet, linux.SIOCGIFINDEX, @intFromPtr(&ifr)), "SIOCGIFINDEX");
        l.index = ifr.ifru.ivalue;
        ifr = l.ifreq();
        _ = try sys(linux.ioctl(l.inet, linux.SIOCGIFHWADDR, @intFromPtr(&ifr)), "SIOCGIFHWADDR");
        l.mac = ifr.ifru.hwaddr.data[0..6].*;
        ifr = l.ifreq();
        _ = try sys(linux.ioctl(l.inet, linux.SIOCGIFFLAGS, @intFromPtr(&ifr)), "SIOCGIFFLAGS");
        ifr.ifru.flags.UP = true;
        _ = try sys(linux.ioctl(l.inet, linux.SIOCSIFFLAGS, @intFromPtr(&ifr)), "SIOCSIFFLAGS");
        // Wait up to 2 s for carrier (IFF_RUNNING). Until then the NIC's
        // queue drops what is sent: the first DISCOVER was lost this way in
        // three boots of four under QEMU and one of three under Lima. Retries
        // cover a slower link.
        const since = nowMs();
        l.carrier = false;
        for (0..400) |_| {
            ifr = l.ifreq();
            _ = try sys(linux.ioctl(l.inet, linux.SIOCGIFFLAGS, @intFromPtr(&ifr)), "SIOCGIFFLAGS");
            l.carrier = ifr.ifru.flags.RUNNING;
            if (l.carrier) break;
            const ts: linux.timespec = .{ .sec = 0, .nsec = 5 * std.time.ns_per_ms };
            _ = linux.nanosleep(&ts, null);
        }
        l.waited_ms = nowMs() - since;

        // Attach and lock the filter before bind, so the socket never sees
        // an unfiltered packet. Without it the kernel would copy every IPv4
        // packet the machine receives into the socket.
        l.packet = @intCast(try sys(
            linux.socket(linux.AF.PACKET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0),
            "socket packet",
        ));
        const prog: SockFprog = .{ .len = reply_filter.len, .filter = &reply_filter };
        _ = try sys(
            linux.setsockopt(
                l.packet,
                linux.SOL.SOCKET,
                SO_ATTACH_FILTER,
                @ptrCast(&prog),
                @sizeOf(SockFprog),
            ),
            "SO_ATTACH_FILTER",
        );
        const one: i32 = 1;
        _ = try sys(
            linux.setsockopt(
                l.packet,
                linux.SOL.SOCKET,
                SO_LOCK_FILTER,
                @ptrCast(&one),
                @sizeOf(i32),
            ),
            "SO_LOCK_FILTER",
        );
        const proto = std.mem.nativeToBig(u16, linux.ETH.P.IP);
        const sll: linux.sockaddr.ll = .{
            .protocol = proto,
            .ifindex = l.index,
            .hatype = 0,
            .pkttype = 0,
            .halen = 0,
            .addr = @splat(0),
        };
        _ = try sys(
            linux.bind(l.packet, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll)),
            "bind packet",
        );
        return l;
    }

    fn ifreq(l: *const Link) linux.ifreq {
        var ifr: linux.ifreq = std.mem.zeroes(linux.ifreq);
        ifr.ifrn.name = l.name;
        return ifr;
    }

    /// apply puts a lease on the NIC: address, netmask, MTU, routes and
    /// resolvers. Reapplying the same lease changes nothing. A refused MTU or
    /// route is logged and skipped, because the address is already on and
    /// failing would end keep, and with it every later renewal.
    fn apply(l: *Link, dir: i32, w: Wire, log: *Log, nic: []const u8) !void {
        try l.setAddr(linux.SIOCSIFADDR, w.addr, "SIOCSIFADDR");
        try l.setAddr(linux.SIOCSIFNETMASK, w.mask, "SIOCSIFNETMASK");
        if (w.mtu != 0) {
            var ifr = l.ifreq();
            ifr.ifru.mtu = w.mtu;
            _ = sys(linux.ioctl(l.inet, linux.SIOCSIFMTU, @intFromPtr(&ifr)), "SIOCSIFMTU") catch
                log.event("mtu_refused", .{
                    .nic = nic,
                    .mtu = w.mtu,
                    .errno = sandbox.errnoName(sandbox.failed_errno),
                });
        }
        var plan_buf: [max_routes + 2]Route = undefined;
        for (plan(w, &plan_buf)) |rt| l.addRoute(rt) catch {
            var dst: [16]u8 = undefined;
            var gw: [16]u8 = undefined;
            log.event("route_refused", .{
                .nic = nic,
                .dst = ipText(&dst, rt.dst),
                .prefix = rt.prefix,
                .gw = ipText(&gw, rt.gw),
                .errno = sandbox.errnoName(sandbox.failed_errno),
            });
        };
        if (w.ndns > 0) {
            var text: [max_dns * 28]u8 = undefined;
            var tw: Io.Writer = .fixed(&text);
            for (w.dns[0..w.ndns]) |d| try tw.print(
                "nameserver {d}.{d}.{d}.{d}\n",
                .{ d[0], d[1], d[2], d[3] },
            );
            try writeFile(dir, "resolv.conf", tw.buffered());
        }
    }

    /// withdraw removes the address by setting it to 0.0.0.0. With the
    /// NIC's last address gone, the kernel flushes every route through it.
    fn withdraw(l: *Link) !void {
        try l.setAddr(linux.SIOCSIFADDR, zero, "SIOCSIFADDR");
    }

    fn setAddr(l: *Link, req: u32, a: Ip4, comptime what: []const u8) !void {
        var ifr = l.ifreq();
        ifr.ifru.addr = inetAddr(a);
        _ = try sys(linux.ioctl(l.inet, req, @intFromPtr(&ifr)), what);
    }

    fn addRoute(l: *Link, rt: Route) !void {
        const on_link = std.mem.eql(u8, &rt.gw, &zero);
        var e: RtEntry = .{
            .dst = inetAddr(rt.dst),
            .gateway = inetAddr(rt.gw),
            .genmask = inetAddr(maskOf(rt.prefix)),
            .flags = RTF_UP | (if (on_link) 0 else RTF_GATEWAY) |
                (if (rt.prefix == 32) RTF_HOST else 0),
            .dev = @ptrCast(&l.name),
        };
        const rc = linux.ioctl(l.inet, linux.SIOCADDRT, @intFromPtr(&e));
        if (linux.errno(rc) == .EXIST) return;
        _ = try sys(rc, "SIOCADDRT");
    }
};

/// RtEntry is Linux's struct rtentry, for SIOCADDRT. The layout is the same
/// on both 64-bit architectures werewolf builds for.
const RtEntry = extern struct {
    pad1: usize = 0,
    dst: linux.sockaddr,
    gateway: linux.sockaddr,
    genmask: linux.sockaddr,
    flags: u16,
    pad2: i16 = 0,
    pad3: usize = 0,
    pad4: ?*anyopaque = null,
    metric: i16 = 0,
    dev: ?[*:0]const u8,
    mtu: usize = 0,
    window: usize = 0,
    irtt: u16 = 0,

    comptime {
        std.debug.assert(@sizeOf(RtEntry) == 120);
    }
};
const RTF_UP: u16 = 0x1;
const RTF_GATEWAY: u16 = 0x2;
const RTF_HOST: u16 = 0x4;

fn inetAddr(a: Ip4) linux.sockaddr {
    var s: linux.sockaddr = .{ .family = linux.AF.INET, .data = @splat(0) };
    s.data[2..6].* = a; // after the port
    return s;
}

// --- BPF: the socket filter -----------------------------------------------

const SockFilter = extern struct { code: u16, jt: u8 = 0, jf: u8 = 0, k: u32 = 0 };
const SockFprog = extern struct { len: u16, filter: [*]const SockFilter };
const SO_ATTACH_FILTER = 26;
const SO_LOCK_FILTER = 44;

const BPF_LD_H_ABS = 0x28;
const BPF_LD_B_ABS = 0x30;
const BPF_LD_H_IND = 0x48;
const BPF_LDX_B_MSH = 0xb1;
const BPF_JEQ_K = 0x15;
const BPF_JSET_K = 0x45;
const BPF_RET_K = 0x06;

/// reply_filter passes only what could be a DHCP reply: unfragmented UDP
/// from port 67 to port 68. Offsets start at the IPv4 header.
const reply_filter = [_]SockFilter{
    .{ .code = BPF_LD_B_ABS, .k = 9 }, // protocol
    .{ .code = BPF_JEQ_K, .jf = 8, .k = 17 },
    .{ .code = BPF_LD_H_ABS, .k = 6 }, // flags and fragment offset
    .{ .code = BPF_JSET_K, .jt = 6, .k = 0x3fff },
    .{ .code = BPF_LDX_B_MSH, .k = 0 }, // X = header length
    .{ .code = BPF_LD_H_IND, .k = 0 }, // source port
    .{ .code = BPF_JEQ_K, .jf = 3, .k = server_port },
    .{ .code = BPF_LD_H_IND, .k = 2 }, // destination port
    .{ .code = BPF_JEQ_K, .jf = 1, .k = client_port },
    .{ .code = BPF_RET_K, .k = 0xffff },
    .{ .code = BPF_RET_K, .k = 0 },
};

// --- DHCP messages -----------------------------------------------------------

/// message builds a DHCP message of kind (1 DISCOVER, 3 REQUEST) from mac.
/// A REQUEST that answers an OFFER names the address and server; a renewal
/// puts the held address in ciaddr instead.
fn message(
    buf: *[576]u8,
    kind: u8,
    xid: u32,
    mac: [6]u8,
    ciaddr: Ip4,
    requested: ?Ip4,
    server: ?Ip4,
) []const u8 {
    @memset(buf, 0);
    buf[0] = 1; // BOOTREQUEST
    buf[1] = 1; // Ethernet
    buf[2] = 6;
    std.mem.writeInt(u32, buf[4..8], xid, .big);
    buf[12..16].* = ciaddr;
    buf[28..34].* = mac;
    buf[236..240].* = cookie;
    var i: usize = 240;
    const opts = struct {
        fn put(b: *[576]u8, at: *usize, code: u8, v: []const u8) void {
            b[at.*] = code;
            b[at.* + 1] = @intCast(v.len);
            @memcpy(b[at.* + 2 ..][0..v.len], v);
            at.* += 2 + v.len;
        }
    };
    opts.put(buf, &i, 53, &.{kind});
    if (requested) |a| opts.put(buf, &i, 50, &a);
    if (server) |a| opts.put(buf, &i, 54, &a);
    opts.put(buf, &i, 55, &wanted);
    opts.put(buf, &i, 57, &.{ 0x05, 0xdc }); // replies up to 1500 bytes
    // Send the client identifier (type 1, the MAC) as dhclient and
    // systemd-networkd do: a server may key its leases by it.
    opts.put(buf, &i, 61, &([1]u8{1} ++ mac));
    buf[i] = 255;
    // BOOTP's minimum: some servers drop anything shorter.
    return buf[0..@max(i + 1, 300)];
}

const Kind = enum { offer, ack, nak };

const Reply = struct {
    kind: Kind,
    lease: Wire,
};

/// parseReply returns a server's reply to transaction xid for mac, or null
/// if it is short, malformed, someone else's, or of a kind we do not take.
/// A malformed option rejects the message, except that bad routes are
/// ignored, as RFC 3442 asks, and so is an MTU out of range.
fn parseReply(msg: []const u8, xid: u32, mac: [6]u8) ?Reply {
    if (msg.len < 240) return null;
    if (msg[0] != 2 or msg[1] != 1 or msg[2] != 6) return null;
    if (std.mem.readInt(u32, msg[4..8], .big) != xid) return null;
    if (!std.mem.eql(u8, msg[28..34], &mac)) return null;
    if (!std.mem.eql(u8, msg[236..240], &cookie)) return null;
    var w: Wire = .{ .addr = msg[16..20].* };
    var kind: ?Kind = null;
    var i: usize = 240;
    while (i < msg.len) {
        const code = msg[i];
        if (code == 0) {
            i += 1;
            continue;
        }
        if (code == 255) break;
        if (i + 2 > msg.len) return null;
        const len = msg[i + 1];
        if (i + 2 + len > msg.len) return null;
        const v = msg[i + 2 ..][0..len];
        i += 2 + len;
        switch (code) {
            53 => {
                if (len != 1) return null;
                kind = switch (v[0]) {
                    2 => .offer,
                    5 => .ack,
                    6 => .nak,
                    else => return null,
                };
            },
            54 => w.server = ip4(v) orelse return null,
            1 => {
                const m = ip4(v) orelse return null;
                if (prefixOf(m) > 32) return null;
                w.mask = m;
            },
            3 => {
                if (len < 4 or len % 4 != 0) return null;
                w.router = v[0..4].*;
            },
            6 => {
                if (len < 4 or len % 4 != 0) return null;
                w.ndns = 0;
                var j: usize = 0;
                while (j < len and w.ndns < max_dns) : (j += 4) {
                    w.dns[w.ndns] = v[j..][0..4].*;
                    w.ndns += 1;
                }
            },
            26 => {
                if (len != 2) return null;
                const mtu = std.mem.readInt(u16, v[0..2], .big);
                w.mtu = if (mtu >= 576 and mtu <= max_mtu) mtu else 0;
            },
            51 => w.lease = u32Of(v) orelse return null,
            58 => w.t1 = u32Of(v) orelse return null,
            59 => w.t2 = u32Of(v) orelse return null,
            121 => w.nroutes = parseRoutes(v, &w.routes) orelse 0,
            else => {},
        }
    }
    return .{ .kind = kind orelse return null, .lease = w };
}

/// parseRoutes parses RFC 3442 classless static routes (prefix length,
/// significant destination octets, router) into out and returns the count.
/// It keeps the first max_routes and returns null for a malformed option.
fn parseRoutes(v: []const u8, out: *[max_routes]Route) ?u8 {
    var n: u8 = 0;
    var i: usize = 0;
    while (i < v.len) {
        const width = v[i];
        if (width > 32) return null;
        const sig: usize = (width + 7) / 8;
        if (i + 1 + sig + 4 > v.len) return null;
        var dst = zero;
        @memcpy(dst[0..sig], v[i + 1 ..][0..sig]);
        if (n < max_routes) {
            out[n] = .{
                .dst = masked(dst, width),
                .prefix = width,
                .gw = v[i + 1 + sig ..][0..4].*,
            };
            n += 1;
        }
        i += 1 + sig + 4;
    }
    return n;
}

/// plan returns the routes to add for a lease. Classless routes, when sent,
/// replace the router (RFC 3442). Routes on the link go first, so a gateway
/// is reachable before a route through it is added. A router outside the
/// subnet, such as GCP's for a /32 address, gets a host route on the link.
fn plan(w: Wire, out: *[max_routes + 2]Route) []const Route {
    if (w.nroutes > 0) {
        var n: usize = 0;
        for ([_]bool{ true, false }) |on_link| for (w.routes[0..w.nroutes]) |r| {
            if (std.mem.eql(u8, &r.gw, &zero) != on_link) continue;
            out[n] = r;
            n += 1;
        };
        return out[0..n];
    }
    if (std.mem.eql(u8, &w.router, &zero)) return out[0..0];
    var n: usize = 0;
    if (!sameSubnet(w.router, w.addr, w.mask)) {
        out[n] = .{ .dst = w.router, .prefix = 32, .gw = zero };
        n += 1;
    }
    out[n] = .{ .dst = zero, .prefix = 0, .gw = w.router };
    return out[0 .. n + 1];
}

/// samePlan reports whether two leases put the same address, mask and
/// routes on the NIC.
fn samePlan(a: Wire, b: Wire) bool {
    if (!std.mem.eql(u8, &a.addr, &b.addr) or !std.mem.eql(u8, &a.mask, &b.mask)) return false;
    var pa: [max_routes + 2]Route = undefined;
    var pb: [max_routes + 2]Route = undefined;
    const ra = plan(a, &pa);
    const rb = plan(b, &pb);
    if (ra.len != rb.len) return false;
    for (ra, rb) |x, y| if (!std.meta.eql(x, y)) return false;
    return true;
}

/// timers returns when to renew and when the lease ends, in seconds from
/// when it was given: by default half and seven eighths of the lease. A lease
/// is at least a minute, so a server cannot keep the client busy.
fn timers(lease: u32, t1: u32, t2: u32) struct { t1: i64, t2: i64, lease: i64 } {
    const l: i64 = @max(lease, 60);
    var a: i64 = if (t1 > 0) t1 else @divFloor(l, 2);
    var b: i64 = if (t2 > 0) t2 else @divFloor(l * 7, 8);
    if (a >= l or a < 30) a = @divFloor(l, 2);
    if (b <= a or b >= l) b = @divFloor(l * 7, 8);
    return .{ .t1 = a, .t2 = b, .lease = l };
}

// --- IP and UDP --------------------------------------------------------------

/// frame wraps payload in UDP from port 68 to 67 and IPv4 from src to the
/// broadcast address.
fn frame(out: []u8, src: Ip4, payload: []const u8) []const u8 {
    const total = 28 + payload.len;
    const ip = out[0..20];
    ip.* = [12]u8{ 0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0 } ++ src ++ [4]u8{ 255, 255, 255, 255 };
    std.mem.writeInt(u16, ip[2..4], @intCast(total), .big);
    std.mem.writeInt(u16, ip[10..12], checksum(ip), .big);
    const udp = out[20..28];
    std.mem.writeInt(u16, udp[0..2], client_port, .big);
    std.mem.writeInt(u16, udp[2..4], server_port, .big);
    std.mem.writeInt(u16, udp[4..6], @intCast(8 + payload.len), .big);
    udp[6..8].* = .{ 0, 0 }; // no UDP checksum, which IPv4 allows
    @memcpy(out[28..total], payload);
    return out[0..total];
}

/// unframe returns the UDP payload of an unfragmented IPv4 packet from port
/// 67 to 68, or null. The socket filter checked this already; it is checked
/// again here because the bounds matter. Checksums are not checked: the
/// packet came from the hypervisor's virtual NIC.
fn unframe(pkt: []const u8) ?[]const u8 {
    if (pkt.len < 28 or pkt[0] >> 4 != 4) return null;
    const ihl: usize = @as(usize, pkt[0] & 0x0f) * 4;
    if (ihl < 20) return null;
    const total = std.mem.readInt(u16, pkt[2..4], .big);
    if (total < ihl + 8 or total > pkt.len) return null;
    if (std.mem.readInt(u16, pkt[6..8], .big) & 0x3fff != 0) return null;
    if (pkt[9] != 17) return null;
    const udp = pkt[ihl..total];
    if (std.mem.readInt(u16, udp[0..2], .big) != server_port) return null;
    if (std.mem.readInt(u16, udp[2..4], .big) != client_port) return null;
    const len = std.mem.readInt(u16, udp[4..6], .big);
    if (len < 8 or len > udp.len) return null;
    return udp[8..len];
}

fn checksum(header: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < header.len) : (i += 2) sum += std.mem.readInt(u16, header[i..][0..2], .big);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
    return ~@as(u16, @intCast(sum));
}

// --- addresses ---------------------------------------------------------------

fn ip4(v: []const u8) ?Ip4 {
    return if (v.len == 4) v[0..4].* else null;
}

fn u32Of(v: []const u8) ?u32 {
    return if (v.len == 4) std.mem.readInt(u32, v[0..4], .big) else null;
}

/// usable reports whether an address can be a host's. Static networks use
/// the same check.
const usable = network.usable;

fn maskOf(prefix: u8) Ip4 {
    const bits: u32 = if (prefix == 0) 0 else ~@as(u32, 0) << @intCast(32 - @min(prefix, 32));
    var m: Ip4 = undefined;
    std.mem.writeInt(u32, &m, bits, .big);
    return m;
}

fn masked(a: Ip4, prefix: u8) Ip4 {
    var out = a;
    for (&out, maskOf(prefix)) |*o, m| o.* &= m;
    return out;
}

/// prefixOf returns the prefix length of a contiguous mask, or 33 if it is
/// not contiguous.
fn prefixOf(m: Ip4) u8 {
    const bits = std.mem.readInt(u32, &m, .big);
    const ones: u8 = @clz(~bits);
    return if (std.mem.eql(u8, &maskOf(ones), &m)) ones else 33;
}

fn sameSubnet(a: Ip4, b: Ip4, m: Ip4) bool {
    for (a, b, m) |x, y, z| if (x & z != y & z) return false;
    return true;
}

fn ipString(gpa: Allocator, a: Ip4) ![]const u8 {
    return gpa.print("{d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] });
}

fn ipText(buf: *[16]u8, a: Ip4) []const u8 {
    return std.mem.print(buf, "{d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] }) catch unreachable;
}

// --- time and chance ---------------------------------------------------------

fn boottime() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.BOOTTIME, &ts);
    return ts.sec;
}

fn nowMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.BOOTTIME, &ts);
    return ts.sec * 1000 + @divFloor(ts.nsec, std.time.ns_per_ms);
}

fn sleep(seconds: i64) void {
    const ts: linux.timespec = .{ .sec = @intCast(@max(seconds, 1)), .nsec = 0 };
    _ = linux.nanosleep(&ts, null);
}

fn newXid() u32 {
    var b: [4]u8 = undefined;
    if (linux.getrandom(&b, b.len, 0) != b.len) linux.exit_group(1);
    return std.mem.readInt(u32, &b, .big);
}

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

const test_mac = [6]u8{ 0x42, 0x01, 0x0a, 0x80, 0x00, 0x05 };
const test_xid: u32 = 0x5eed_beef;

/// testReply builds a server reply carrying options (code, length, value
/// triples) and the end option.
fn testReply(buf: []u8, kind: u8, yiaddr: Ip4, options: []const u8) []const u8 {
    @memset(buf, 0);
    buf[0] = 2;
    buf[1] = 1;
    buf[2] = 6;
    std.mem.writeInt(u32, buf[4..8], test_xid, .big);
    buf[16..20].* = yiaddr;
    buf[28..34].* = test_mac;
    buf[236..240].* = cookie;
    buf[240..243].* = .{ 53, 1, kind };
    @memcpy(buf[243..][0..options.len], options);
    buf[243 + options.len] = 255;
    return buf[0 .. 244 + options.len];
}

// GCP's server: a /32 address, the router reached by a classless route on
// the link, the metadata server for DNS, and VPC's 1460-byte MTU. The
// hostname and domain it also sends are ignored.
const gcp_options = [_]u8{
    54, 4, 169, 254, 169, 254,
    51, 4, 0,   0,   0x0e, 0x10, // 3600 s
    1,  4, 255, 255, 255,  255,
    3,  4, 10,  128, 0,    1,
    6,  4, 169, 254, 169,  254,
    26,  2,   0x05, 0xb4, // 1460
    12,  10,  'i',  'n',
    's', 't', 'a',  'n',
    'c', 'e', '-',  '1',
    15,  19,  'c',  '.',
    'p', 'r', 'o',  'j',
    'e', 'c', 't',  '.',
    'i', 'n', 't',  'e',
    'r', 'n', 'a',  'l',
    '.',
} ++ [_]u8{ 121, 14, 32, 10, 128, 0, 1, 0, 0, 0, 0, 0, 10, 128, 0, 1 };

// QEMU's user network: 10.0.2.15/24, router .2, DNS .3, a day's lease.
const qemu_options = [_]u8{
    54, 4, 10,  0,   2,   2,
    1,  4, 255, 255, 255, 0,
    3,  4, 10,  0,   2,   2,
    6,  4, 10,  0,   2,   3,
    51, 4, 0, 1, 0x51, 0x80, // 86400 s
};

fn testLease(options: []const u8, yiaddr: Ip4) Wire {
    var buf: [576]u8 = undefined;
    return parseReply(testReply(&buf, 5, yiaddr, options), test_xid, test_mac).?.lease;
}

test "messages" {
    var buf: [576]u8 = undefined;
    const d = message(&buf, 1, test_xid, test_mac, zero, null, null);
    try std.testing.expectEqual(300, d.len);
    try std.testing.expectEqual(1, d[0]);
    try std.testing.expectEqual(test_xid, std.mem.readInt(u32, d[4..8], .big));
    try std.testing.expectEqualSlices(u8, &test_mac, d[28..34]);
    try std.testing.expectEqualSlices(u8, &cookie, d[236..240]);
    try std.testing.expectEqualSlices(u8, &.{ 53, 1, 1, 55, wanted.len }, d[240..245]);

    const r = message(
        &buf,
        3,
        test_xid,
        test_mac,
        zero,
        .{ 10, 128, 0, 5 },
        .{ 169, 254, 169, 254 },
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 53, 1, 3, 50, 4, 10, 128, 0, 5, 54, 4, 169, 254, 169, 254 },
        r[240..255],
    );

    const id = std.mem.find(u8, r[240..], &([2]u8{ 61, 7 } ++ [1]u8{1} ++ test_mac));
    try std.testing.expect(id != null);

    const renewal = message(&buf, 3, test_xid, test_mac, .{ 10, 128, 0, 5 }, null, null);
    try std.testing.expectEqualSlices(u8, &.{ 10, 128, 0, 5 }, renewal[12..16]);
    try std.testing.expectEqualSlices(u8, &.{ 53, 1, 3, 55 }, renewal[240..244]);
}

test "frame and unframe" {
    var buf: [576]u8 = undefined;
    const msg = message(&buf, 1, test_xid, test_mac, zero, null, null);
    var out: [28 + 576]u8 = undefined;
    const pkt = frame(&out, zero, msg);
    try std.testing.expectEqual(28 + msg.len, pkt.len);
    try std.testing.expectEqual(0, checksum(pkt[0..20])); // a valid header sums to all ones
    try std.testing.expectEqualSlices(u8, &.{ 255, 255, 255, 255 }, pkt[16..20]);

    // Swap the ports to make it a server's packet, then unframe it.
    var reply = out;
    std.mem.writeInt(u16, reply[20..22], server_port, .big);
    std.mem.writeInt(u16, reply[22..24], client_port, .big);
    try std.testing.expectEqualSlices(u8, msg, unframe(reply[0..pkt.len]).?);
    // Trailing link padding is not payload.
    try std.testing.expectEqualSlices(u8, msg, unframe(reply[0 .. pkt.len + 4]).?);

    try std.testing.expectEqual(null, unframe(pkt)); // to the server, not us
    var frag = reply;
    frag[6] = 0x20; // more fragments
    try std.testing.expectEqual(null, unframe(frag[0..pkt.len]));
    var long = reply;
    std.mem.writeInt(u16, long[2..4], @intCast(pkt.len + 1), .big);
    try std.testing.expectEqual(null, unframe(long[0..pkt.len]));
    var udp_long = reply;
    std.mem.writeInt(u16, udp_long[24..26], @intCast(msg.len + 9), .big);
    try std.testing.expectEqual(null, unframe(udp_long[0..pkt.len]));
    try std.testing.expectEqual(null, unframe(reply[0..27]));
}

test "GCP's lease" {
    const w = testLease(&gcp_options, .{ 10, 128, 0, 5 });
    try std.testing.expect(valid(w));
    try std.testing.expectEqual(1460, w.mtu);
    try std.testing.expectEqual(3600, w.lease);

    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const l = try describe(a.allocator(), "eth0", w);
    try std.testing.expectEqualStrings("10.128.0.5/32", l.ip);
    try std.testing.expectEqualStrings("10.128.0.1", l.gw.?);
    try std.testing.expectEqualStrings("169.254.169.254", l.server);
    try std.testing.expectEqual(2, l.routes.len);
    try std.testing.expectEqualStrings("10.128.0.1/32", l.routes[0]);
    try std.testing.expectEqualStrings("0.0.0.0/0 via 10.128.0.1", l.routes[1]);
    try std.testing.expectEqualStrings("169.254.169.254", l.dns[0]);
}

test "QEMU's lease" {
    const w = testLease(&qemu_options, .{ 10, 0, 2, 15 });
    try std.testing.expect(valid(w));
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    const l = try describe(a.allocator(), "eth0", w);
    try std.testing.expectEqualStrings("10.0.2.15/24", l.ip);
    try std.testing.expectEqual(1, l.routes.len); // the router is on the subnet
    try std.testing.expectEqualStrings("0.0.0.0/0 via 10.0.2.2", l.routes[0]);
    try std.testing.expectEqual(0, l.mtu);
}

test "lease.json round trip" {
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    var w = testLease(&gcp_options, .{ 10, 128, 0, 5 });
    w.bound = 1234;
    var out: Io.Writer.Allocating = .init(a.allocator());
    try std.json.Stringify.value(try describe(a.allocator(), "eth0", w), .{}, &out.writer);
    const h = heldFrom(a.allocator(), out.written()).?;
    try std.testing.expectEqualSlices(u8, &w.addr, &h.addr);
    try std.testing.expectEqualSlices(u8, &w.server, &h.server);
    try std.testing.expectEqual(1234, h.bound);
    try std.testing.expectEqual(3600, h.lease);
    try std.testing.expectEqual(null, heldFrom(a.allocator(), "{\"ip\":"));
    try std.testing.expectEqual(
        null,
        heldFrom(
            a.allocator(),
            "{\"nic\":\"eth0\",\"ip\":\"10.0.0.5\",\"server\":\"10.0.0.1\",\"lease\":60,\"t1\"" ++
                ":0,\"t2\":0,\"bound\":0}",
        ),
    );
}

test "a lease that changes the NIC is told apart" {
    const qemu = testLease(&qemu_options, .{ 10, 0, 2, 15 });
    try std.testing.expect(samePlan(qemu, qemu));
    // A renewal with new times leaves the NIC unchanged.
    var later = qemu;
    later.bound += 3600;
    later.lease = 7200;
    try std.testing.expect(samePlan(qemu, later));
    // A new router, mask or address changes it.
    var moved = qemu;
    moved.router = .{ 10, 0, 2, 1 };
    try std.testing.expect(!samePlan(qemu, moved));
    var wider = qemu;
    wider.mask = .{ 255, 255, 0, 0 };
    try std.testing.expect(!samePlan(qemu, wider));
    var other = qemu;
    other.addr = .{ 10, 0, 2, 16 };
    try std.testing.expect(!samePlan(qemu, other));

    // lease.json must round-trip the plan, so the parent can compare a
    // renewal against it after keep starts.
    var a: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer a.deinit();
    for ([_]Wire{ qemu, testLease(&gcp_options, .{ 10, 128, 0, 5 }) }) |w| {
        var out: Io.Writer.Allocating = .init(a.allocator());
        try std.json.Stringify.value(try describe(a.allocator(), "eth0", w), .{}, &out.writer);
        try std.testing.expect(samePlan(heldFrom(a.allocator(), out.written()).?, w));
    }
}

test "routes on the link come first, whatever the server's order" {
    // Azure-like: the default route sent before the route to its gateway.
    const w = testLease(
        &([_]u8{ 54, 4, 10, 0, 0, 1, 51, 4, 0, 0, 0x0e, 0x10, 1, 4, 255, 255, 255, 255 } ++
            [_]u8{ 121, 14, 0, 10, 0, 0, 1, 32, 10, 0, 0, 1, 0, 0, 0, 0 }),
        .{ 10, 0, 0, 5 },
    );
    var p: [max_routes + 2]Route = undefined;
    const routes = plan(w, &p);
    try std.testing.expectEqual(2, routes.len);
    try std.testing.expectEqual(32, routes[0].prefix);
    try std.testing.expectEqualSlices(u8, &zero, &routes[0].gw);
    try std.testing.expectEqual(0, routes[1].prefix);
}

test parseRoute {
    const on_link = parseRoute("10.128.0.1/32").?;
    try std.testing.expectEqual(32, on_link.prefix);
    try std.testing.expectEqualSlices(u8, &zero, &on_link.gw);
    const via = parseRoute("0.0.0.0/0 via 10.0.2.2").?;
    try std.testing.expectEqual(0, via.prefix);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 2, 2 }, &via.gw);
    try std.testing.expectEqual(null, parseRoute("10.0.0.0/33"));
    try std.testing.expectEqual(null, parseRoute("10.0.0.0"));
    try std.testing.expectEqual(null, parseRoute("0.0.0.0/0 via 10.0.2"));
}

test "a /32 with only a router reaches the router on the link first" {
    const w = testLease(
        &.{ 54, 4, 10, 128, 0, 1, 51, 4, 0, 0, 0x0e, 0x10, 3, 4, 10, 128, 0, 1 },
        .{ 10, 128, 0, 5 },
    );
    var p: [max_routes + 2]Route = undefined;
    const routes = plan(w, &p);
    try std.testing.expectEqual(2, routes.len);
    try std.testing.expectEqual(32, routes[0].prefix);
    try std.testing.expectEqualSlices(u8, &zero, &routes[0].gw);
    try std.testing.expectEqual(0, routes[1].prefix);
}

test "replies that are not ours, or are malformed" {
    var okbuf: [576]u8 = undefined;
    const ok = testReply(&okbuf, 5, .{ 10, 0, 2, 15 }, &qemu_options);
    var buf: [576]u8 = undefined;
    try std.testing.expect(parseReply(ok, test_xid, test_mac) != null);
    try std.testing.expectEqual(null, parseReply(ok, test_xid + 1, test_mac));
    try std.testing.expectEqual(null, parseReply(ok, test_xid, .{ 0, 0, 0, 0, 0, 1 }));
    try std.testing.expectEqual(null, parseReply(ok[0..239], test_xid, test_mac));

    var m = okbuf;
    m[0] = 1; // a request, not a reply
    try std.testing.expectEqual(null, parseReply(m[0..ok.len], test_xid, test_mac));
    m = okbuf;
    m[236] = 0; // no magic cookie
    try std.testing.expectEqual(null, parseReply(m[0..ok.len], test_xid, test_mac));
    m = okbuf;
    m[242] = 4; // DECLINE: not a kind a server sends
    try std.testing.expectEqual(null, parseReply(m[0..ok.len], test_xid, test_mac));

    // An option running past the end.
    try std.testing.expectEqual(null, parseReply(ok[0 .. ok.len - 3], test_xid, test_mac));
    // A server address of the wrong size, a mask with holes, no type.
    try std.testing.expectEqual(
        null,
        parseReply(
            testReply(&buf, 5, .{ 10, 0, 2, 15 }, &.{ 54, 3, 10, 0, 2 }),
            test_xid,
            test_mac,
        ),
    );
    try std.testing.expectEqual(
        null,
        parseReply(
            testReply(&buf, 5, .{ 10, 0, 2, 15 }, &.{ 1, 4, 255, 0, 255, 0 }),
            test_xid,
            test_mac,
        ),
    );
    var none = okbuf;
    none[240] = 0; // the type option becomes padding
    none[241] = 0;
    none[242] = 0;
    try std.testing.expectEqual(null, parseReply(none[0..ok.len], test_xid, test_mac));
}

test "routes and MTU that are malformed are ignored" {
    const w = testLease(
        &.{
            54,
            4,
            10,
            0,
            2,
            2,
            51,
            4,
            0,
            0,
            1,
            0,
            121,
            5,
            33,
            10,
            0,
            0,
            1,
            26,
            2,
            0,
            100,
            3,
            4,
            10,
            0,
            2,
            2,
        },
        .{ 10, 0, 2, 15 },
    );
    try std.testing.expectEqual(0, w.nroutes);
    try std.testing.expectEqual(0, w.mtu);
    var p: [max_routes + 2]Route = undefined;
    try std.testing.expectEqual(2, plan(w, &p).len); // falls back to the router
}

test "classless routes" {
    var out: [max_routes]Route = undefined;
    // 10.1.2.0/23 via 10.0.0.1, sent with a host bit the server should
    // have left out; and the default route on the link.
    const n = parseRoutes(&.{ 23, 10, 1, 3, 10, 0, 0, 1, 0, 0, 0, 0, 0 }, &out).?;
    try std.testing.expectEqual(2, n);
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 2, 0 }, &out[0].dst);
    try std.testing.expectEqual(23, out[0].prefix);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &out[0].gw);
    try std.testing.expectEqual(0, out[1].prefix);
    var many: [9 * 5]u8 = undefined;
    for (0..9) |k| many[k * 5 ..][0..5].* = .{ 0, 10, 0, 0, @intCast(k + 1) };
    try std.testing.expectEqual(max_routes, parseRoutes(&many, &out).?);
    try std.testing.expectEqual(null, parseRoutes(&.{ 24, 10, 1, 2, 10, 0, 0 }, &out));
    try std.testing.expectEqual(null, parseRoutes(&.{ 40, 10, 1, 2, 3, 4, 5, 6, 7, 8 }, &out));
    try std.testing.expectEqual(0, parseRoutes(&.{}, &out).?);
}

test "leases that must not be applied" {
    const good = testLease(&qemu_options, .{ 10, 0, 2, 15 });
    try std.testing.expect(valid(good));
    var w = good;
    w.mask = .{ 255, 0, 0, 0 }; // /8 is the widest allowed
    try std.testing.expect(valid(w));
    w.mask = .{ 254, 0, 0, 0 }; // /7: half the internet on the link
    try std.testing.expect(!valid(w));
    w = good;
    w.addr = .{ 10, 0, 2, 0 }; // the subnet's own address
    try std.testing.expect(!valid(w));
    w.addr = .{ 10, 0, 2, 255 }; // its broadcast address
    try std.testing.expect(!valid(w));
    w = good;
    w.router = .{ 255, 255, 255, 255 };
    try std.testing.expect(!valid(w));
    w.router = good.addr; // ourselves
    try std.testing.expect(!valid(w));
    w = good;
    w.dns[0] = .{ 224, 0, 0, 1 };
    try std.testing.expect(!valid(w));
    w = good;
    w.nroutes = 1;
    w.routes[0] = .{ .dst = .{ 127, 0, 0, 0 }, .prefix = 8, .gw = .{ 10, 0, 2, 2 } };
    try std.testing.expect(!valid(w));
    w.routes[0] = .{ .dst = .{ 10, 1, 2, 3 }, .prefix = 24, .gw = .{ 10, 0, 2, 2 } }; // host bits
    try std.testing.expect(!valid(w));
    w.routes[0] = .{ .dst = zero, .prefix = 0, .gw = .{ 0, 1, 2, 3 } };
    try std.testing.expect(!valid(w));
    w = good;
    w.ndns = max_dns + 1;
    try std.testing.expect(!valid(w));
    w = good;
    w.lease = 0;
    try std.testing.expect(!valid(w));
    w = good;
    w.server = zero;
    try std.testing.expect(!valid(w));
}

test "masks and addresses" {
    try std.testing.expectEqual(24, prefixOf(.{ 255, 255, 255, 0 }));
    try std.testing.expectEqual(32, prefixOf(.{ 255, 255, 255, 255 }));
    try std.testing.expectEqual(0, prefixOf(zero));
    try std.testing.expectEqual(33, prefixOf(.{ 255, 0, 255, 0 }));
    try std.testing.expectEqualSlices(u8, &.{ 255, 255, 240, 0 }, &maskOf(20));
    try std.testing.expect(sameSubnet(.{ 10, 0, 2, 2 }, .{ 10, 0, 2, 15 }, .{ 255, 255, 255, 0 }));
    try std.testing.expect(!sameSubnet(
        .{ 10, 128, 0, 1 },
        .{ 10, 128, 0, 5 },
        .{ 255, 255, 255, 255 },
    ));
    try std.testing.expect(!usable(zero));
    try std.testing.expect(!usable(.{ 0, 1, 2, 3 }));
    try std.testing.expect(!usable(.{ 255, 255, 255, 255 }));
    try std.testing.expect(!usable(.{ 127, 0, 0, 1 }));
}

test "timers" {
    try std.testing.expectEqual(1800, timers(3600, 0, 0).t1);
    try std.testing.expectEqual(3150, timers(3600, 0, 0).t2);
    try std.testing.expectEqual(1000, timers(3600, 1000, 2000).t1);
    // A renewal time past the lease's end, or a lease of seconds.
    try std.testing.expectEqual(1800, timers(3600, 4000, 0).t1);
    try std.testing.expectEqual(60, timers(5, 0, 0).lease);
    try std.testing.expectEqual(30, timers(5, 0, 0).t1);
}

test "socket filter jumps" {
    for (reply_filter, 0..) |insn, i| {
        if (insn.code != BPF_JEQ_K and insn.code != BPF_JSET_K) continue;
        try std.testing.expect(
            i + 1 + insn.jt < reply_filter.len and i + 1 + insn.jf < reply_filter.len,
        );
    }
    // Every rejection is the final `ret 0`.
    try std.testing.expectEqual(reply_filter.len - 1, 1 + 1 + reply_filter[1].jf);
    try std.testing.expectEqual(reply_filter.len - 1, 3 + 1 + reply_filter[3].jt);
    try std.testing.expectEqual(reply_filter.len - 1, 6 + 1 + reply_filter[6].jf);
    try std.testing.expectEqual(reply_filter.len - 1, 8 + 1 + reply_filter[8].jf);
}

test "messages between the processes are fixed" {
    try std.testing.expectEqual(0, @sizeOf(Msg) % 8);
    try std.testing.expect(@sizeOf(Msg) < 256);
}

test "fuzz: anything off the wire" {
    try std.testing.fuzz({}, fuzzWire, .{ .corpus = &.{ &gcp_options, &qemu_options } });
}

fn fuzzWire(_: void, smith: *std.testing.Smith) anyerror!void {
    var in: [1536]u8 = undefined;
    const n = smith.slice(&in);
    const pkt = in[0..n];
    if (unframe(pkt)) |payload| _ = parseReply(payload, test_xid, test_mac);
    // Also feed the bytes as options of a reply that is ours, so the option
    // parser is reached.
    var msg: [1536]u8 = undefined;
    const m = testReply(&msg, 5, .{ 10, 0, 2, 15 }, pkt[0..@min(n, msg.len - 245)]);
    if (parseReply(m, test_xid, test_mac)) |r| {
        var p: [max_routes + 2]Route = undefined;
        _ = plan(r.lease, &p);
        _ = valid(r.lease);
        _ = timers(r.lease.lease, r.lease.t1, r.lease.t2);
    }
}
