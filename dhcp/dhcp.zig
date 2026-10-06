//! dhcp: an IPv4 address from the network's DHCP server.
//!
//!     dhcp up NIC   get a lease for NIC and apply it; exit 0 once bound, or
//!                   1 if no server has given one within 30 seconds
//!     dhcp keep     keep that lease for as long as the machine runs: renew
//!                   it, or get another; the dhcp service runs this. Where
//!                   init did not use DHCP, it sleeps
//!
//! init runs `dhcp up` when the kernel command line names no werewolf.ip.
//!
//! The program is two processes, as OpenBSD's dhclient is, so the one that
//! reads the network can do nothing else:
//!
//!   engine   speaks DHCP. It alone parses what comes off the wire. It runs
//!            as _dhcp (uid 67), chrooted to the empty /var/empty, with no
//!            capabilities, and a seccomp filter that kills it for any system
//!            call beyond sending and receiving on its packet socket, writing
//!            to the parent, waiting, the clock and random numbers. When a
//!            lease is given or renewed, it sends the parent a fixed-size
//!            message describing it.
//!   parent   applies leases. It stays root but keeps one capability,
//!            CAP_NET_ADMIN, for the ioctls that set the address, MTU and
//!            routes. It never sees a packet: it checks every field of the
//!            engine's message again, and treats one it does not like as a
//!            compromised engine, ending both. Landlock confines what it
//!            writes to /run/werewolf/dhcp (lease.json, resolv.conf, to which
//!            /etc/resolv.conf links), and seccomp to the few calls that takes.
//!
//! Both are set up before either touches the network: the packet socket is
//! opened, filtered in the kernel to DHCP replies, and locked first.
//!
//! The engine treats every reply as hostile: it is read with strict bounds,
//! must answer our transaction from our hardware address, renewals must come
//! from the server that gave the lease, and only these options are used:
//! message type, server, subnet mask, router, classless static routes (RFC
//! 3442, which GCP sends with a /32 address), DNS servers, MTU, and the lease
//! times. Every event is one JSON line on stdout, from the parent.

const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const state_dir = "/run/werewolf/dhcp";
const nic_path = state_dir ++ "/nic";
const lease_path = state_dir ++ "/lease.json";
const empty_dir = "/var/empty";
/// _dhcp, in minimal.yaml's accounts.
const engine_id: u32 = 67;

const client_port = 68;
const server_port = 67;
const cookie = [4]u8{ 99, 130, 83, 99 };
const max_routes = 8;
const max_dns = 3;
/// The options asked for: subnet mask, router, DNS, MTU, lease time,
/// server, renewal and rebinding times, classless static routes.
const wanted = [_]u8{ 1, 3, 6, 26, 51, 54, 58, 59, 121 };

const Ip4 = [4]u8;
const zero: Ip4 = .{ 0, 0, 0, 0 };

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
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
        log.event("error", .{ .step = "start", .@"error" = @errorName(err), .detail = detail, .errno = errnoName(detail_errno) });
        std.process.exit(1);
    };
}

const Mode = enum { up, keep };

/// What failed, and how, for the error event: set by sys() and the setup
/// steps.
var detail: []const u8 = "";
var detail_errno: linux.E = .SUCCESS;

/// The name of an errno, or "unknown" for one Linux does not have: the
/// engine's errors come from a process the parent does not trust.
fn errnoName(e: linux.E) []const u8 {
    return std.enums.tagName(linux.E, e) orelse "unknown";
}

/// As root: everything both processes need, then the fork.
fn start(io: Io, gpa: Allocator, mode: Mode, arg_nic: []const u8) !void {
    var log: Log = .{};
    try Dir.cwd().createDirPath(io, state_dir);
    const nic = switch (mode) {
        .up => arg_nic,
        .keep => std.mem.trim(u8, Dir.cwd().readFileAlloc(io, nic_path, gpa, .limited(64)) catch |err| switch (err) {
            error.FileNotFound => park(),
            else => return err,
        }, " \n"),
    };
    if (mode == .up) try Dir.cwd().writeFile(io, .{ .sub_path = nic_path, .data = nic });

    // The lease `up` left, for `keep` to renew. One that cannot be read is
    // no lease: the engine gets another.
    var held: ?Wire = null;
    if (mode == .keep) {
        if (Dir.cwd().readFileAlloc(io, lease_path, gpa, .limited(64 << 10))) |data| {
            held = heldFrom(gpa, data);
            if (held == null) log.event("unreadable", .{ .nic = nic, .file = lease_path });
        } else |err| if (err != error.FileNotFound) return err;
    }

    const link = try Link.open(nic);
    const dir = try sys(linux.openat(linux.AT.FDCWD, state_dir, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true }, 0), "open " ++ state_dir);
    var sp: [2]i32 = undefined;
    _ = try sys(linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, &sp), "socketpair");
    const parent_pid = linux.getpid();

    const pid = try sys(linux.fork(), "fork");
    if (pid == 0) {
        _ = linux.close(sp[0]);
        _ = linux.close(link.inet);
        _ = linux.close(@intCast(dir));
        var e: Engine = .{ .pkt = link.packet, .sp = sp[1], .index = link.index, .mac = link.mac };
        e.sandbox(parent_pid) catch e.fail();
        e.run(mode, held) catch e.fail();
        linux.exit_group(0);
    }
    _ = linux.close(sp[1]);
    _ = linux.close(link.packet);
    var p: Parent = .{ .mode = mode, .sp = sp[0], .dir = @intCast(dir), .link = link, .nic = nic };
    try p.sandbox();
    p.run();
}

/// Where init did not use DHCP: nothing to do, for as long as the service
/// runs, as _dhcp in an empty root with nothing but sleep allowed.
fn park() noreturn {
    dropTo(engine_id) catch linux.exit_group(1);
    var f: Filter = .{};
    f.allow(sysnr("nanosleep"));
    f.allow(sysnr("clock_nanosleep"));
    f.allow(sysnr("restart_syscall"));
    f.allow(sysnr("exit_group"));
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

    const Step = enum(u8) { sandbox, discover, request, renew, send };

    /// Never to return to root: die with the parent, give up every
    /// capability, live as _dhcp in an empty root, and make any system call
    /// beyond these few fatal.
    fn sandbox(e: *Engine, parent_pid: linux.pid_t) !void {
        _ = try e.sys(linux.prctl(@backingInt(linux.PR.SET_PDEATHSIG), @backingInt(linux.SIG.KILL), 0, 0, 0));
        if (linux.getppid() != parent_pid) return error.ParentGone;
        dropTo(engine_id) catch |err| {
            e.errno = @backingInt(linux.E.PERM);
            return err;
        };
        var f: Filter = .{};
        f.allowArg(sysnr("sendto"), 0, @intCast(e.pkt));
        f.allowArg(sysnr("recvfrom"), 0, @intCast(e.pkt));
        f.allowArg(sysnr("write"), 0, @intCast(e.sp));
        f.allow(sysnr("poll"));
        f.allow(sysnr("ppoll"));
        f.allow(sysnr("clock_gettime"));
        f.allow(sysnr("nanosleep"));
        f.allow(sysnr("clock_nanosleep"));
        f.allow(sysnr("getrandom"));
        f.allow(sysnr("restart_syscall"));
        f.allow(sysnr("exit_group"));
        f.allow(sysnr("exit"));
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

    /// DISCOVER, OFFER, REQUEST, ACK: the lease, or null if no server
    /// finished one within `seconds`. The ACK must come from the server
    /// that offered, for the address offered.
    fn acquire(e: *Engine, seconds: u32) !?Wire {
        const deadline = nowMs() + @as(i64, seconds) * 1000;
        while (nowMs() < deadline) {
            const xid = newXid();
            var buf: [576]u8 = undefined;
            e.step = .discover;
            const offer = try e.exchange(message(&buf, 1, xid, e.mac, zero, null, null), zero, xid, deadline) orelse return null;
            if (offer.kind != .offer or !usable(offer.lease.addr) or !usable(offer.lease.server)) continue;
            e.step = .request;
            const ack = try e.exchange(message(&buf, 3, xid, e.mac, zero, offer.lease.addr, offer.lease.server), zero, xid, deadline) orelse return null;
            if (!std.mem.eql(u8, &ack.lease.server, &offer.lease.server)) continue;
            switch (ack.kind) {
                .ack => if (std.mem.eql(u8, &ack.lease.addr, &offer.lease.addr) and valid(ack.lease)) {
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

    /// A renewing REQUEST for the lease held: the server's ACK, for the same
    /// address, or its NAK; null for no answer, or one from anyone else.
    fn renew(e: *Engine, h: Wire, seconds: u32) !?Reply {
        const xid = newXid();
        var buf: [576]u8 = undefined;
        e.step = .renew;
        var r = try e.exchange(message(&buf, 3, xid, e.mac, h.addr, null, null), h.addr, xid, nowMs() + @as(i64, seconds) * 1000) orelse return null;
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

    /// Broadcast `msg` from `src`, again at 1, 2, 4 and then every 8
    /// seconds, until a reply to `xid` arrives or `deadline` passes. A send
    /// that fails, as when the link drops for a moment, counts as a round
    /// with no answer.
    fn exchange(e: *Engine, msg: []const u8, src: Ip4, xid: u32, deadline: i64) !?Reply {
        var out: [28 + 576]u8 = undefined;
        const pkt = frame(&out, src, msg);
        const to: linux.sockaddr.ll = .{ .protocol = std.mem.nativeToBig(u16, linux.ETH.P.IP), .ifindex = e.index, .hatype = 0, .pkttype = 0, .halen = 6, .addr = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0 } };
        var wait: i64 = 1000;
        while (nowMs() < deadline) {
            _ = linux.sendto(e.pkt, pkt.ptr, pkt.len, 0, @ptrCast(&to), @sizeOf(linux.sockaddr.ll));
            const until = @min(deadline, nowMs() + wait);
            while (true) {
                const left = until - nowMs();
                if (left <= 0) break;
                var fds = [1]linux.pollfd{.{ .fd = e.pkt, .events = linux.POLL.IN, .revents = 0 }};
                const n = linux.poll(&fds, 1, @intCast(left));
                if (linux.errno(n) == .INTR) continue;
                if (try e.sys(n) == 0) break;
                var in: [1536]u8 = undefined;
                const got = try e.sys(linux.recvfrom(e.pkt, &in, in.len, linux.MSG.DONTWAIT, null, null));
                const payload = unframe(in[0..got]) orelse continue;
                if (parseReply(payload, xid, e.mac)) |r| return r;
            }
            wait = @min(wait * 2, 8000);
        }
        return null;
    }

    fn send(e: *Engine, event: Event, w: Wire) !void {
        e.step = .send;
        const m: Msg = .{ .event = @backingInt(event), .step = @backingInt(e.step), .errno = e.errno, .lease = w };
        const n = try e.sys(linux.write(e.sp, std.mem.asBytes(&m), @sizeOf(Msg)));
        if (n != @sizeOf(Msg)) return error.ShortWrite;
    }

    /// Tell the parent what failed, and end.
    fn fail(e: *Engine) noreturn {
        if (e.errno == 0) e.errno = 1;
        const m: Msg = .{ .event = @backingInt(Event.@"error"), .step = @backingInt(e.step), .errno = e.errno, .lease = std.mem.zeroes(Wire) };
        _ = linux.write(e.sp, std.mem.asBytes(&m), @sizeOf(Msg));
        linux.exit_group(1);
    }

    fn sys(e: *Engine, rc: usize) !usize {
        const err = linux.errno(rc);
        if (err == .SUCCESS) return rc;
        e.errno = @backingInt(err);
        return error.SystemCall;
    }
};

/// Become `id`, user and group, in an empty root, with no capabilities left
/// to anything that follows: the bounding set emptied, no supplementary
/// groups, and a check that root cannot be had back.
fn dropTo(id: u32) !void {
    var cap: usize = 0;
    while (cap < 64) : (cap += 1) _ = linux.prctl(@backingInt(linux.PR.CAPBSET_DROP), cap, 0, 0, 0);
    _ = try sys(linux.chroot(empty_dir), "chroot " ++ empty_dir);
    _ = try sys(linux.chdir("/"), "chdir /");
    _ = try sys(linux.setgroups(0, &[_]linux.gid_t{}), "setgroups");
    _ = try sys(linux.setresgid(id, id, id), "setresgid");
    _ = try sys(linux.setresuid(id, id, id), "setresuid");
    if (linux.errno(linux.setresuid(0, 0, 0)) == .SUCCESS) return error.StillRoot;
}

// --- the parent --------------------------------------------------------------

const Parent = struct {
    mode: Mode,
    sp: i32,
    dir: i32,
    link: Link,
    nic: []const u8,
    log: Log = .{},

    /// Keep CAP_NET_ADMIN and nothing else, never gain more, write only in
    /// /run/werewolf/dhcp, and make any other system call fatal.
    fn sandbox(p: *Parent) !void {
        var cap: usize = 0;
        while (cap < 64) : (cap += 1) {
            if (cap != linux.CAP.NET_ADMIN) _ = linux.prctl(@backingInt(linux.PR.CAPBSET_DROP), cap, 0, 0, 0);
        }
        // NOROOT, NO_SETUID_FIXUP, KEEP_CAPS and NO_CAP_AMBIENT_RAISE, each
        // locked: root's uid no longer brings capabilities.
        _ = try sys(linux.prctl(@backingInt(linux.PR.SET_SECUREBITS), 0xef, 0, 0, 0), "securebits");
        var hdr: CapHeader = .{};
        const caps = [2]CapData{ .{ .effective = 1 << linux.CAP.NET_ADMIN, .permitted = 1 << linux.CAP.NET_ADMIN }, .{} };
        _ = try sys(linux.syscall2(.capset, @intFromPtr(&hdr), @intFromPtr(&caps)), "capset");
        try landlock(p.dir);

        var f: Filter = .{};
        f.allowArg(sysnr("read"), 0, @intCast(p.sp));
        f.allowArg(sysnr("ioctl"), 1, linux.SIOCSIFADDR);
        f.allowArg(sysnr("ioctl"), 1, linux.SIOCSIFNETMASK);
        f.allowArg(sysnr("ioctl"), 1, linux.SIOCSIFMTU);
        f.allowArg(sysnr("ioctl"), 1, linux.SIOCADDRT);
        f.allow(sysnr("write"));
        f.allow(sysnr("openat"));
        f.allow(sysnr("close"));
        f.allow(sysnr("renameat"));
        f.allow(sysnr("renameat2"));
        f.allow(sysnr("clock_gettime"));
        f.allow(sysnr("restart_syscall"));
        f.allow(sysnr("exit_group"));
        f.allow(sysnr("exit"));
        try f.install();
    }

    /// Take the engine's messages until it ends, which ends the parent too.
    fn run(p: *Parent) noreturn {
        while (true) {
            var m: Msg = undefined;
            const n = linux.read(p.sp, std.mem.asBytes(&m), @sizeOf(Msg));
            if (linux.errno(n) == .INTR) continue;
            if (linux.errno(n) != .SUCCESS or n != @sizeOf(Msg)) {
                p.log.event("error", .{ .nic = p.nic, .step = "engine", .@"error" = if (n == 0) "EngineExited" else "BadMessage" });
                linux.exit_group(1);
            }
            p.handle(m) catch |err| {
                p.log.event("error", .{ .nic = p.nic, .step = "apply", .@"error" = @errorName(err), .detail = detail, .errno = errnoName(detail_errno) });
                linux.exit_group(1);
            };
        }
    }

    fn handle(p: *Parent, m: Msg) !void {
        const event = std.enums.fromInt(Event, m.event) orelse return error.BadMessage;
        switch (event) {
            .bound, .renewed => {
                // The engine checked this already; a lease that fails here
                // means the engine is not what it was.
                if (!valid(m.lease)) return error.InvalidLease;
                try p.link.apply(p.dir, m.lease);
                var fba: [16 << 10]u8 = undefined;
                var a: std.heap.FixedBufferAllocator = .init(&fba);
                const text = try describe(a.allocator(), p.nic, m.lease);
                var json: [8 << 10]u8 = undefined;
                var w: Io.Writer = .fixed(&json);
                try std.json.Stringify.value(text, .{}, &w);
                try writeFile(p.dir, "lease.json", w.buffered());
                p.log.event(@tagName(event), text);
                if (p.mode == .up) linux.exit_group(0);
            },
            .refused, .expired => {
                var ip: [16]u8 = undefined;
                p.log.event(@tagName(event), .{ .nic = p.nic, .addr = ipText(&ip, m.lease.addr) });
            },
            .waiting => p.log.event("waiting", .{ .nic = p.nic }),
            .failed => {
                p.log.event("failed", .{ .nic = p.nic, .seconds = 30 });
                linux.exit_group(1);
            },
            .@"error" => {
                const step = std.enums.fromInt(Engine.Step, m.step) orelse return error.BadMessage;
                const err: linux.E = @fromBackingInt(@intCast(m.errno));
                p.log.event("error", .{ .nic = p.nic, .step = @tagName(step), .errno = errnoName(err) });
                linux.exit_group(1);
            },
        }
    }
};

/// Landlock: the parent may write files only beneath `dir`, make no TCP
/// connection, and reach no abstract socket or process outside itself.
fn landlock(dir: i32) !void {
    const abi = linux.syscall3(.landlock_create_ruleset, 0, 0, 1); // LANDLOCK_CREATE_RULESET_VERSION
    _ = try sys(abi, "landlock version");
    const fs_all: u64 = if (abi >= 5) 0xffff else if (abi >= 3) 0x7fff else if (abi >= 2) 0x3fff else 0x1fff;
    const attr: [3]u64 = .{
        fs_all,
        if (abi >= 4) 0x3 else 0, // bind and connect TCP
        if (abi >= 6) 0x3 else 0, // abstract UNIX sockets, signals
    };
    const size: usize = if (abi >= 6) 24 else if (abi >= 4) 16 else 8;
    const ruleset = try sys(linux.syscall3(.landlock_create_ruleset, @intFromPtr(&attr), size, 0), "landlock ruleset");
    // READ_FILE, WRITE_FILE, REMOVE_FILE, MAKE_REG, and TRUNCATE where
    // the kernel knows it: replacing a file by renaming another over it.
    const allowed: u64 = 0x4 | 0x2 | 0x20 | 0x100 | (if (abi >= 3) @as(u64, 0x4000) else 0);
    var beneath: [12]u8 = undefined; // struct landlock_path_beneath_attr, packed
    std.mem.writeInt(u64, beneath[0..8], allowed, .little);
    std.mem.writeInt(i32, beneath[8..12], dir, .little);
    _ = try sys(linux.syscall4(.landlock_add_rule, ruleset, 1, @intFromPtr(&beneath), 0), "landlock rule");
    _ = try sys(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0), "no_new_privs");
    _ = try sys(linux.syscall2(.landlock_restrict_self, ruleset, 0), "landlock restrict");
    _ = linux.close(@intCast(ruleset));
}

/// The kernel's struct __user_cap_header_struct: pid is an int, not the
/// usize std.os.linux declares, which would leave padding the kernel reads.
const CapHeader = extern struct {
    version: u32 = 0x20080522, // _LINUX_CAPABILITY_VERSION_3
    pid: i32 = 0,

    comptime {
        std.debug.assert(@sizeOf(CapHeader) == 8);
    }
};
const CapData = extern struct {
    effective: u32 = 0,
    permitted: u32 = 0,
    inheritable: u32 = 0,
};

/// Write a file whole beneath `dir`: to a new name, then renamed over the old.
fn writeFile(dir: i32, comptime name: [:0]const u8, data: []const u8) !void {
    const tmp = std.fmt.comptimePrint("{s}.new", .{name});
    const fd = try sys(linux.openat(dir, tmp, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true, .NOFOLLOW = true }, 0o644), "open " ++ name);
    defer _ = linux.close(@intCast(fd));
    var off: usize = 0;
    while (off < data.len) off += try sys(linux.write(@intCast(fd), data[off..].ptr, data.len - off), "write " ++ name);
    _ = try sys(linux.renameat(dir, tmp, dir, name), "rename " ++ name);
}

fn sys(rc: usize, comptime what: []const u8) !usize {
    const err = linux.errno(rc);
    if (err == .SUCCESS) return rc;
    detail = what;
    detail_errno = err;
    return error.SystemCall;
}

// --- messages between the two ------------------------------------------------

const Event = enum(u8) { bound, renewed, refused, expired, waiting, failed, @"error" };

/// One message from the engine to the parent, always this size.
const Msg = extern struct {
    event: u8,
    step: u8,
    errno: u16,
    pad: u32 = 0,
    lease: Wire,
};

/// A lease, as the engine read it and the parent applies it.
const Wire = extern struct {
    addr: Ip4,
    mask: Ip4 = .{ 255, 255, 255, 255 },
    server: Ip4 = zero,
    /// zero: none.
    router: Ip4 = zero,
    dns: [max_dns]Ip4 = @splat(zero),
    routes: [max_routes]Route = @splat(.{ .dst = zero, .gw = zero, .prefix = 0 }),
    ndns: u8 = 0,
    nroutes: u8 = 0,
    mtu: u16 = 0,
    lease: u32 = 0,
    t1: u32 = 0,
    t2: u32 = 0,
    /// CLOCK_BOOTTIME seconds when the lease was given.
    bound: i64 = 0,
};

const Route = extern struct {
    dst: Ip4,
    /// zero: on the link, no gateway.
    gw: Ip4,
    prefix: u8,
    pad: [3]u8 = .{ 0, 0, 0 },
};

/// Whether a lease is one to put on a NIC. The engine asks before sending a
/// lease, and the parent again before applying it.
fn valid(w: Wire) bool {
    if (!usable(w.addr) or !usable(w.server)) return false;
    const p = prefixOf(w.mask);
    if (p < 8 or p > 32) return false;
    if (p <= 30) {
        // Not the subnet's own address, nor its broadcast address.
        const host = std.mem.readInt(u32, &w.addr, .big) & ~std.mem.readInt(u32, &w.mask, .big);
        if (host == 0 or host == ~std.mem.readInt(u32, &w.mask, .big)) return false;
    }
    if (!std.mem.eql(u8, &w.router, &zero) and (!usable(w.router) or std.mem.eql(u8, &w.router, &w.addr))) return false;
    if (w.ndns > max_dns or w.nroutes > max_routes) return false;
    for (w.dns[0..w.ndns]) |d| if (!usable(d)) return false;
    for (w.routes[0..w.nroutes]) |r| {
        if (r.prefix > 32 or !std.mem.eql(u8, &masked(r.dst, r.prefix), &r.dst)) return false;
        if (r.prefix > 0 and !usable(r.dst)) return false;
        if (!std.mem.eql(u8, &r.gw, &zero) and (!usable(r.gw) or std.mem.eql(u8, &r.gw, &w.addr))) return false;
    }
    if (w.mtu != 0 and (w.mtu < 576 or w.mtu > 9000)) return false;
    return w.lease > 0;
}

// --- the parent's view: text, logged and kept --------------------------------

/// What is kept in lease.json and logged: the lease, as text.
const Lease = struct {
    nic: []const u8,
    /// The address and prefix: "10.128.0.5/32".
    addr: []const u8,
    server: []const u8,
    router: ?[]const u8 = null,
    /// "10.128.0.1/32" (on the link) or "0.0.0.0/0 via 10.128.0.1".
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
        const dst = try std.fmt.allocPrint(gpa, "{s}/{d}", .{ try ipString(gpa, rt.dst), rt.prefix });
        try routes.append(gpa, if (std.mem.eql(u8, &rt.gw, &zero)) dst else try std.fmt.allocPrint(gpa, "{s} via {s}", .{ dst, try ipString(gpa, rt.gw) }));
    }
    var dns: std.ArrayList([]const u8) = .empty;
    for (w.dns[0..w.ndns]) |d| try dns.append(gpa, try ipString(gpa, d));
    return .{
        .nic = nic,
        .addr = try std.fmt.allocPrint(gpa, "{s}/{d}", .{ try ipString(gpa, w.addr), prefixOf(w.mask) }),
        .server = try ipString(gpa, w.server),
        .router = if (std.mem.eql(u8, &w.router, &zero)) null else try ipString(gpa, w.router),
        .routes = routes.items,
        .dns = dns.items,
        .mtu = w.mtu,
        .lease = w.lease,
        .t1 = w.t1,
        .t2 = w.t2,
        .bound = w.bound,
    };
}

/// What the engine needs from lease.json to renew: the address, the server
/// and the times. Null for anything it cannot use.
fn heldFrom(gpa: Allocator, data: []const u8) ?Wire {
    const l = std.json.parseFromSliceLeaky(Lease, gpa, data, .{ .ignore_unknown_fields = true }) catch return null;
    const slash = std.mem.indexOfScalar(u8, l.addr, '/') orelse return null;
    const prefix = std.fmt.parseInt(u8, l.addr[slash + 1 ..], 10) catch return null;
    if (prefix > 32) return null;
    const w: Wire = .{
        .addr = parseIp4(l.addr[0..slash]) orelse return null,
        .mask = maskOf(prefix),
        .server = parseIp4(l.server) orelse return null,
        .lease = l.lease,
        .t1 = l.t1,
        .t2 = l.t2,
        .bound = l.bound,
    };
    return if (valid(w)) w else null;
}

/// JSON lines on stdout: `dhcp: {"time":...,"event":...,...}`. Built in a
/// fixed buffer, so logging allocates nothing.
const Log = struct {
    buf: [8 << 10]u8 = undefined,

    fn event(l: *Log, name: []const u8, fields: anytype) void {
        var w: Io.Writer = .fixed(&l.buf);
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.REALTIME, &ts);
        var time: [20]u8 = undefined;
        w.print("dhcp: {{\"time\":\"{s}\",\"event\":\"{s}\",", .{ rfc3339(&time, @intCast(ts.sec)), name }) catch return;
        const mark = w.end;
        std.json.Stringify.value(fields, .{}, &w) catch return;
        // Drop the fields' own opening brace: they continue the line's object.
        @memmove(l.buf[mark .. w.end - 1], l.buf[mark + 1 .. w.end]);
        w.end -= 1;
        w.writeByte('\n') catch return;
        _ = linux.write(1, w.buffered().ptr, w.buffered().len);
    }
};

// --- the link ----------------------------------------------------------------

const Link = struct {
    /// NUL-terminated, as the kernel wants it.
    name: [linux.IFNAMESIZE]u8,
    index: i32,
    mac: [6]u8,
    /// The packet socket, for the engine.
    packet: i32,
    /// An inet socket, for the parent's ioctls.
    inet: i32,

    fn open(nic: []const u8) !Link {
        if (nic.len == 0 or nic.len >= linux.IFNAMESIZE) {
            detail = "the NIC's name";
            return error.BadNicName;
        }
        var l: Link = undefined;
        l.name = @splat(0);
        @memcpy(l.name[0..nic.len], nic);
        l.inet = @intCast(try sys(linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0), "socket inet"));

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

        // The packet socket hears nothing until it is bound: the filter goes
        // on, and is locked, first. Without the filter the kernel would copy
        // every IPv4 packet the machine receives into it.
        l.packet = @intCast(try sys(linux.socket(linux.AF.PACKET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0), "socket packet"));
        const prog: SockFprog = .{ .len = reply_filter.len, .filter = &reply_filter };
        _ = try sys(linux.setsockopt(l.packet, linux.SOL.SOCKET, SO_ATTACH_FILTER, @ptrCast(&prog), @sizeOf(SockFprog)), "SO_ATTACH_FILTER");
        const one: i32 = 1;
        _ = try sys(linux.setsockopt(l.packet, linux.SOL.SOCKET, SO_LOCK_FILTER, @ptrCast(&one), @sizeOf(i32)), "SO_LOCK_FILTER");
        const proto = std.mem.nativeToBig(u16, linux.ETH.P.IP);
        const sll: linux.sockaddr.ll = .{ .protocol = proto, .ifindex = l.index, .hatype = 0, .pkttype = 0, .halen = 0, .addr = @splat(0) };
        _ = try sys(linux.bind(l.packet, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll)), "bind packet");
        return l;
    }

    fn ifreq(l: *const Link) linux.ifreq {
        var ifr: linux.ifreq = std.mem.zeroes(linux.ifreq);
        ifr.ifrn.name = l.name;
        return ifr;
    }

    /// Put a lease on the NIC: address and netmask, MTU, routes, resolvers.
    /// Applying one that is already there changes nothing: the kernel keeps
    /// an address or mask set to what it is, and a route that exists is
    /// left as it is.
    fn apply(l: *Link, dir: i32, w: Wire) !void {
        try l.setAddr(linux.SIOCSIFADDR, w.addr, "SIOCSIFADDR");
        try l.setAddr(linux.SIOCSIFNETMASK, w.mask, "SIOCSIFNETMASK");
        if (w.mtu != 0) {
            var ifr = l.ifreq();
            ifr.ifru.mtu = w.mtu;
            _ = try sys(linux.ioctl(l.inet, linux.SIOCSIFMTU, @intFromPtr(&ifr)), "SIOCSIFMTU");
        }
        var plan_buf: [max_routes + 2]Route = undefined;
        for (plan(w, &plan_buf)) |rt| try l.addRoute(rt);
        if (w.ndns > 0) {
            var text: [max_dns * 28]u8 = undefined;
            var tw: Io.Writer = .fixed(&text);
            for (w.dns[0..w.ndns]) |d| try tw.print("nameserver {d}.{d}.{d}.{d}\n", .{ d[0], d[1], d[2], d[3] });
            try writeFile(dir, "resolv.conf", tw.buffered());
        }
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
            .flags = RTF_UP | (if (on_link) 0 else RTF_GATEWAY) | (if (rt.prefix == 32) RTF_HOST else 0),
            .dev = @ptrCast(&l.name),
        };
        const rc = linux.ioctl(l.inet, linux.SIOCADDRT, @intFromPtr(&e));
        if (linux.errno(rc) == .EXIST) return;
        _ = try sys(rc, "SIOCADDRT");
    }
};

/// Linux's struct rtentry, for SIOCADDRT; the layout is the same on both
/// 64-bit architectures werewolf builds for.
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

// --- BPF: the socket filter and the seccomp filters --------------------------

const SockFilter = extern struct { code: u16, jt: u8 = 0, jf: u8 = 0, k: u32 = 0 };
const SockFprog = extern struct { len: u16, filter: [*]const SockFilter };
const SO_ATTACH_FILTER = 26;
const SO_LOCK_FILTER = 44;

const BPF_LD_W_ABS = 0x20;
const BPF_LD_H_ABS = 0x28;
const BPF_LD_B_ABS = 0x30;
const BPF_LD_H_IND = 0x48;
const BPF_LDX_B_MSH = 0xb1;
const BPF_JEQ_K = 0x15;
const BPF_JSET_K = 0x45;
const BPF_RET_K = 0x06;

/// The packet socket keeps only what could be a DHCP reply: unfragmented
/// UDP from port 67 to port 68. It sees the packet from its IPv4 header.
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

/// A seccomp filter that allows the calls named, some only with one
/// argument equal to a value, and kills the process for anything else,
/// including a call made as another architecture.
const Filter = struct {
    prog: [max_insns]SockFilter = undefined,
    n: usize = 3,

    const max_insns = 120;
    /// AUDIT_ARCH_X86_64 and AUDIT_ARCH_AARCH64, from linux/audit.h.
    const audit_arch: u32 = switch (@import("builtin").cpu.arch) {
        .x86_64 => 0xc000003e,
        .aarch64 => 0xc00000b7,
        else => @compileError("werewolf builds for x86_64 and aarch64"),
    };

    /// Allow `nr`, if this architecture has it.
    fn allow(f: *Filter, nr: ?u32) void {
        const n = nr orelse return;
        f.prog[f.n] = .{ .code = BPF_JEQ_K, .jt = 0xff, .k = n }; // jt: to ALLOW, fixed up below
        f.n += 1;
    }

    /// Allow `nr` when argument `arg`'s low 32 bits equal `value`.
    fn allowArg(f: *Filter, nr: ?u32, comptime arg: u3, value: u32) void {
        const n = nr orelse return;
        f.prog[f.n] = .{ .code = BPF_JEQ_K, .jf = 3, .k = n };
        f.prog[f.n + 1] = .{ .code = BPF_LD_W_ABS, .k = 16 + 8 * @as(u32, arg) };
        f.prog[f.n + 2] = .{ .code = BPF_JEQ_K, .jt = 0xff, .k = value };
        f.prog[f.n + 3] = .{ .code = BPF_LD_W_ABS, .k = 0 }; // the number again
        f.n += 4;
    }

    fn finish(f: *Filter) []const SockFilter {
        f.prog[0] = .{ .code = BPF_LD_W_ABS, .k = 4 }; // arch
        f.prog[1] = .{ .code = BPF_JEQ_K, .jf = @intCast(f.n - 2), .k = audit_arch }; // else KILL
        f.prog[2] = .{ .code = BPF_LD_W_ABS, .k = 0 }; // nr
        const kill = f.n;
        const allow_at = f.n + 1;
        f.prog[kill] = .{ .code = BPF_RET_K, .k = linux.SECCOMP.RET.KILL_PROCESS };
        f.prog[allow_at] = .{ .code = BPF_RET_K, .k = linux.SECCOMP.RET.ALLOW };
        for (f.prog[3..kill], 3..) |*insn, i| {
            if (insn.code == BPF_JEQ_K and insn.jt == 0xff) insn.jt = @intCast(allow_at - i - 1);
        }
        return f.prog[0 .. kill + 2];
    }

    fn install(f: *Filter) !void {
        const insns = f.finish();
        const prog: SockFprog = .{ .len = @intCast(insns.len), .filter = insns.ptr };
        _ = try sys(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0), "no_new_privs");
        _ = try sys(linux.seccomp(linux.SECCOMP.SET_MODE_FILTER, 0, &prog), "seccomp");
    }
};

fn sysnr(comptime name: []const u8) ?u32 {
    return if (@hasField(linux.SYS, name)) @intCast(@backingInt(@field(linux.SYS, name))) else null;
}

// --- DHCP messages -----------------------------------------------------------

/// A DHCP message of `kind` (1 DISCOVER, 3 REQUEST) from `mac`. A REQUEST
/// that answers an OFFER names the address and the server; one that renews
/// has the address held in ciaddr instead.
fn message(buf: *[576]u8, kind: u8, xid: u32, mac: [6]u8, ciaddr: Ip4, requested: ?Ip4, server: ?Ip4) []const u8 {
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
    buf[i] = 255;
    // BOOTP's minimum: some servers drop anything shorter.
    return buf[0..@max(i + 1, 300)];
}

const Kind = enum { offer, ack, nak };

const Reply = struct {
    kind: Kind,
    lease: Wire,
};

/// A server's reply to transaction `xid` for `mac`, or null for anything
/// else: too short, malformed, someone else's, or of no kind we take. An
/// option we use that is malformed rejects the message, except the routes
/// and MTU, which are then ignored, as RFC 3442 asks for the routes.
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
                w.mtu = if (mtu >= 576 and mtu <= 9000) mtu else 0;
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

/// RFC 3442's classless static routes: a prefix length, the significant
/// octets of the destination, then the router. The first `max_routes` are
/// kept; a malformed option is null.
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
            out[n] = .{ .dst = masked(dst, width), .prefix = width, .gw = v[i + 1 + sig ..][0..4].* };
            n += 1;
        }
        i += 1 + sig + 4;
    }
    return n;
}

/// The routes a lease asks for. Classless routes, when sent, replace the
/// router (RFC 3442). A router outside the subnet, such as GCP's for a /32
/// address, is first made reachable on the link.
fn plan(w: Wire, out: *[max_routes + 2]Route) []const Route {
    if (w.nroutes > 0) {
        @memcpy(out[0..w.nroutes], w.routes[0..w.nroutes]);
        return out[0..w.nroutes];
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

/// When to renew and when the lease ends, in seconds from when it was given:
/// half and seven eighths of the lease unless the server says otherwise, and
/// never sooner than a minute, so a server that hands out short leases
/// cannot keep the client busy.
fn timers(lease: u32, t1: u32, t2: u32) struct { t1: i64, t2: i64, lease: i64 } {
    const l: i64 = @max(lease, 60);
    var a: i64 = if (t1 > 0) t1 else @divFloor(l, 2);
    var b: i64 = if (t2 > 0) t2 else @divFloor(l * 7, 8);
    if (a >= l or a < 30) a = @divFloor(l, 2);
    if (b <= a or b >= l) b = @divFloor(l * 7, 8);
    return .{ .t1 = a, .t2 = b, .lease = l };
}

// --- IP and UDP --------------------------------------------------------------

/// `payload` in UDP from port 68 to 67, in IPv4 from `src` to everyone.
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

/// The UDP payload of an unfragmented IPv4 packet from port 67 to 68, or
/// null. The socket filter has checked this much already; it is checked
/// again here, where the bounds matter. Checksums are left to the link: the
/// packet arrived whole from the hypervisor's NIC.
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

/// Neither zero, loopback, multicast nor broadcast: 1.0.0.0 to 223.255.255.255
/// outside 127.0.0.0/8.
fn usable(a: Ip4) bool {
    return a[0] != 0 and a[0] != 127 and a[0] < 224;
}

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

/// The prefix length of a contiguous mask, or 33 for one that is not.
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
    return std.fmt.allocPrint(gpa, "{d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] });
}

fn ipText(buf: *[16]u8, a: Ip4) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] }) catch unreachable;
}

fn parseIp4(s: []const u8) ?Ip4 {
    var a: Ip4 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    for (&a) |*o| o.* = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
    return if (it.next() == null) a else null;
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
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

// --- tests -------------------------------------------------------------------

const test_mac = [6]u8{ 0x42, 0x01, 0x0a, 0x80, 0x00, 0x05 };
const test_xid: u32 = 0x5eed_beef;

/// A server's reply carrying `options` (each code, length, value), ended.
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

    const r = message(&buf, 3, test_xid, test_mac, zero, .{ 10, 128, 0, 5 }, .{ 169, 254, 169, 254 });
    try std.testing.expectEqualSlices(u8, &.{ 53, 1, 3, 50, 4, 10, 128, 0, 5, 54, 4, 169, 254, 169, 254 }, r[240..255]);

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

    // The same packet, as a server's: ports swapped, unframed.
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
    try std.testing.expectEqualStrings("10.128.0.5/32", l.addr);
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
    try std.testing.expectEqualStrings("10.0.2.15/24", l.addr);
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
    try std.testing.expectEqual(null, heldFrom(a.allocator(), "{\"addr\":"));
    try std.testing.expectEqual(null, heldFrom(a.allocator(), "{\"nic\":\"eth0\",\"addr\":\"10.0.0.5\",\"server\":\"10.0.0.1\",\"lease\":60,\"t1\":0,\"t2\":0,\"bound\":0}"));
}

test "a /32 with only a router reaches the router on the link first" {
    const w = testLease(&.{ 54, 4, 10, 128, 0, 1, 51, 4, 0, 0, 0x0e, 0x10, 3, 4, 10, 128, 0, 1 }, .{ 10, 128, 0, 5 });
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
    try std.testing.expectEqual(null, parseReply(testReply(&buf, 5, .{ 10, 0, 2, 15 }, &.{ 54, 3, 10, 0, 2 }), test_xid, test_mac));
    try std.testing.expectEqual(null, parseReply(testReply(&buf, 5, .{ 10, 0, 2, 15 }, &.{ 1, 4, 255, 0, 255, 0 }), test_xid, test_mac));
    var none = okbuf;
    none[240] = 0; // the type option becomes padding
    none[241] = 0;
    none[242] = 0;
    try std.testing.expectEqual(null, parseReply(none[0..ok.len], test_xid, test_mac));
}

test "routes and MTU that are malformed are ignored" {
    const w = testLease(&.{ 54, 4, 10, 0, 2, 2, 51, 4, 0, 0, 1, 0, 121, 5, 33, 10, 0, 0, 1, 26, 2, 0, 100, 3, 4, 10, 0, 2, 2 }, .{ 10, 0, 2, 15 });
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
    try std.testing.expect(!sameSubnet(.{ 10, 128, 0, 1 }, .{ 10, 128, 0, 5 }, .{ 255, 255, 255, 255 }));
    try std.testing.expect(!usable(zero));
    try std.testing.expect(!usable(.{ 255, 255, 255, 255 }));
    try std.testing.expect(!usable(.{ 127, 0, 0, 1 }));
    try std.testing.expectEqualSlices(u8, &.{ 10, 128, 0, 5 }, &parseIp4("10.128.0.5").?);
    try std.testing.expectEqual(null, parseIp4("10.128.0"));
    try std.testing.expectEqual(null, parseIp4("10.128.0.256"));
    try std.testing.expectEqual(null, parseIp4("10.128.0.5.1"));
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

test "seccomp filter" {
    var f: Filter = .{};
    f.allow(1000);
    f.allowArg(1001, 0, 7);
    f.allow(1002);
    const p = f.finish();
    try std.testing.expectEqual(3 + 1 + 4 + 1 + 2, p.len);
    // Every jump lands inside the program, and every allowing jump on ALLOW.
    for (p, 0..) |insn, i| {
        if (insn.code != BPF_JEQ_K) continue;
        try std.testing.expect(i + 1 + insn.jt < p.len and i + 1 + insn.jf < p.len);
        if (insn.jt != 0) try std.testing.expectEqual(linux.SECCOMP.RET.ALLOW, p[i + 1 + insn.jt].k);
    }
    // A wrong architecture lands on KILL.
    try std.testing.expectEqual(linux.SECCOMP.RET.KILL_PROCESS, p[2 + p[1].jf].k);
}

test "socket filter jumps" {
    for (reply_filter, 0..) |insn, i| {
        if (insn.code != BPF_JEQ_K and insn.code != BPF_JSET_K) continue;
        try std.testing.expect(i + 1 + insn.jt < reply_filter.len and i + 1 + insn.jf < reply_filter.len);
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
    // And the same bytes as a reply already out of its packet, ours from
    // the start, so the options are reached.
    var msg: [1536]u8 = undefined;
    const m = testReply(&msg, 5, .{ 10, 0, 2, 15 }, pkt[0..@min(n, msg.len - 245)]);
    if (parseReply(m, test_xid, test_mac)) |r| {
        var p: [max_routes + 2]Route = undefined;
        _ = plan(r.lease, &p);
        _ = valid(r.lease);
        _ = timers(r.lease.lease, r.lease.t1, r.lease.t2);
    }
}
