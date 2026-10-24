//! Early domain-age authority. Init starts it before fence removes mount
//! privilege, then covers its database and socket directories with read-only
//! binds in the main namespace. This process keeps a private writable view.
//! The production age marker stays absent until the full path passes.
//!
//! Three kinds of process split the work, so that none holds more than it
//! needs. The supervisor holds no database: it restarts the writer, forks a
//! fetch child for each check the writer asks for, kills it at its deadline
//! and relays its fixed-size record. The writer holds the database and
//! unwound's channel; it makes no TCP connection and parses no provider
//! reply. A fetch child holds nothing at all (age_fetch.zig).
const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const dns = @import("dns");
const age = @import("age.zig");
const bootstrap = @import("bootstrap.zig");
const db_mod = @import("age_db.zig");
const evidence = @import("age_evidence.zig");
const fetch = @import("age_fetch.zig");
const http = @import("age_http.zig");
const ipc = @import("age_ipc.zig");
const Policy = @import("policy.zig").Policy;
const unwound = @import("unwound.zig");
const wire = @import("wire.zig");
const sys = sandbox.sys;

const control: i32 = 3;
const socket_path = dns.age_socket_path;
const durable_db = dns.age_durable_dir ++ "/age.db";
const temporary_db = dns.age_temporary_dir ++ "/age.db";
const max_policy = 256 * 1024;
/// max_fetches bounds checks out at once; each service may have one.
const max_fetches = 4;
/// fetch_ms bounds one check: DNS, TLS, RDAP and crt.sh together. It is
/// shorter than unwound's own deadline for a question, so a stalled registry
/// is refused as unknown and recorded, and nothing else waits on it.
const fetch_ms = 10_000;

var policy: Policy = .{};
var policy_text: [max_policy]u8 = undefined;

pub fn main() void {
    run() catch |err| {
        var buf: [256]u8 = undefined;
        const line = std.mem.print(&buf, "unwound-age: {s} ({s}: {t})\n", .{
            @errorName(err), sandbox.failed, sandbox.failed_errno,
        }) catch "unwound-age: failed\n";
        _ = linux.write(2, line.ptr, line.len);
        linux.exit_group(1);
    };
}

fn run() !void {
    if (linux.getuid() != 0) return error.RootSetupRequired;
    try policy.parse((unwound.readRootFile(dns.policy_path, &policy_text, "age policy") catch
        return error.UnsafePolicy) orelse return error.NoPolicy);
    const ephemeral = linux.errno(linux.access("/run/werewolf/nodata", linux.F_OK)) == .SUCCESS;
    const db_dir: [:0]const u8 = if (ephemeral) dns.age_temporary_dir else dns.age_durable_dir;
    const db_path: [:0]const u8 = if (ephemeral) temporary_db else durable_db;
    _ = try sys(linux.unshare(linux.CLONE.NEWNS), "private age mount namespace");
    _ = try sys(
        linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0),
        "private age mount propagation",
    );
    const listener = try listen();
    // Init does not let runit start until it has made the main namespace's
    // view read-only. This handshake keeps the writable view private.
    if (linux.write(control, "R", 1) != 1) return error.InitClosed;
    var go: [1]u8 = undefined;
    if (linux.read(control, &go, 1) != 1 or go[0] != 'G') return error.InitClosed;
    _ = linux.close(control);
    try sandbox.limit(.NOFILE, 32);
    try sandbox.dropTo(dns.age_id, null);
    _ = try sys(linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0), "dumpable");
    const data: i32 = @intCast(try sys(
        linux.open(
            db_dir,
            .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
            0,
        ),
        "open age directory",
    ));
    const etc: i32 = @intCast(try sys(
        linux.open("/etc", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0),
        "open /etc",
    ));
    const network: i32 = @intCast(try sys(
        linux.open(dns.network_dir, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0),
        "open resolver directory",
    ));
    const random: i32 = @intCast(try sys(
        linux.open("/dev/urandom", .{ .PATH = true, .CLOEXEC = true }, 0),
        "open randomness",
    ));
    try sandbox.landlock(&.{
        .{ .fd = data, .access = sandbox.read_file | sandbox.read_dir |
            sandbox.write_file | sandbox.truncate | sandbox.make_reg | sandbox.remove_file },
        .{ .fd = etc, .access = sandbox.read_file | sandbox.read_dir },
        .{ .fd = network, .access = sandbox.read_file | sandbox.read_dir },
        .{ .fd = random, .access = sandbox.read_file },
    }, &.{ 53, 443 });
    _ = linux.close(data);
    _ = linux.close(etc);
    _ = linux.close(network);
    _ = linux.close(random);
    try confineSupervisor(listener);
    supervise(listener, db_dir, db_path);
}

/// confineSupervisor allows the supervisor's calls and those of every child
/// it forks, which narrow it with their own filters. Nothing here may exec,
/// trace, mount, change identity, or make a socket but IPv4 or IPv6 and
/// the writer's channel pair.
fn confineSupervisor(listener: i32) !void {
    var f: sandbox.Filter = .{};
    fetch.allowBasics(&f);
    fetch.allowFetch(&f);
    allowWriter(&f, listener);
    f.allow("write");
    f.allow("fork");
    f.allowArg("clone", 0, @backingInt(linux.SIG.CHLD));
    f.allowArg("kill", 1, @backingInt(linux.SIG.KILL));
    inline for (.{
        linux.PR.SET_PDEATHSIG,
        linux.PR.GET_PDEATHSIG,
        linux.PR.SET_NO_NEW_PRIVS,
    }) |option| f.allowArg("prctl", 0, @backingInt(option));
    f.allowArg("prctl", 0, 65); // PR_SET_MDWE, in Filter.install
    inline for (.{
        "wait4",
        "socketpair",
        "pipe2",
        "dup3",
        "close_range",
        "prlimit64",
        "landlock_create_ruleset",
        "landlock_add_rule",
        "landlock_restrict_self",
        "seccomp",
    }) |call| f.allow(call);
    try f.install();
}

/// allowWriter allows the writer's channels, and what SQLite does with the
/// files Landlock leaves it.
fn allowWriter(f: *sandbox.Filter, listener: i32) void {
    f.allowArg("accept4", 0, @intCast(listener));
    inline for (.{
        "recvfrom",
        "sendto",
        "poll",
        "ppoll",
        "openat",
        "read",
        "pread64",
        "pwrite64",
        "lseek",
        "fstat",
        "newfstatat",
        "fstatat64",
        "statx",
        "fcntl",
        "fsync",
        "fdatasync",
        "ftruncate",
        "unlink",
        "unlinkat",
        "geteuid",
        "nanosleep",
        "clock_nanosleep",
        "sched_getaffinity",
    }) |call| f.allow(call);
}

fn listen() !i32 {
    const fd: i32 = @intCast(try sys(
        linux.socket(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0),
        "age socket",
    ));
    errdefer _ = linux.close(fd);
    const unlinked = linux.unlink(socket_path);
    if (linux.errno(unlinked) != .SUCCESS and linux.errno(unlinked) != .NOENT)
        return error.UnsafeSocketPath;
    var address: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(address.path[0..socket_path.len], socket_path);
    _ = try sys(
        linux.bind(fd, @ptrCast(&address), @intCast(2 + socket_path.len + 1)),
        "bind age socket",
    );
    _ = try sys(
        linux.fchmodat2(linux.AT.FDCWD, socket_path, 0o600, linux.AT.SYMLINK_NOFOLLOW),
        "age socket permissions",
    );
    _ = try sys(linux.listen(fd, 8), "listen age socket");
    return fd;
}

/// supervise keeps the private mount view across writer crashes. It never
/// opens the database, so the fetch children it forks inherit none of it.
fn supervise(listener: i32, db_dir: [:0]const u8, db_path: [:0]const u8) noreturn {
    const self = linux.getpid();
    while (true) {
        var pair: [2]i32 = undefined;
        if (linux.errno(linux.socketpair(
            linux.AF.UNIX,
            linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC,
            0,
            &pair,
        )) != .SUCCESS) @panic("age writer channel");
        const pid = linux.fork();
        if (linux.errno(pid) != .SUCCESS) @panic("fork age writer");
        if (pid == 0) {
            sandbox.tieTo(self);
            _ = linux.close(pair[0]);
            writer(listener, pair[1], db_dir, db_path);
        }
        _ = linux.close(pair[1]);
        relay(pair[0]);
        _ = linux.close(pair[0]);
        var status: i32 = 0;
        _ = linux.waitpid(@intCast(pid), &status, 0);
        var delay: linux.timespec = .{ .sec = 1, .nsec = 0 };
        _ = linux.nanosleep(&delay, null);
    }
}

/// The writer asks the supervisor for a fetch with an id and the registered
/// domain. The answer repeats the id, says how the fetch ended and, for one
/// that found something, carries the child's record unread.
const How = enum(u8) { found = 0, timeout = 1, failed = 2 };
const ask_max = 4 + 253;
const answer_len = 5 + evidence.found_len;

const Fetch = struct {
    pid: linux.pid_t = 0,
    /// fd reads the child's record; -1 marks a free slot.
    fd: i32 = -1,
    id: u32 = 0,
    deadline: i64 = 0,
    domain: wire.Name = .{},
};

/// relay runs the writer's fetches until the writer goes away, then kills
/// any still out. Each fetch is killed at its deadline, whatever it is doing.
fn relay(ctl: i32) void {
    var fetches: [max_fetches]Fetch = @splat(.{});
    defer for (&fetches) |*f| if (f.fd >= 0) {
        _ = reap(f);
    };
    while (true) {
        var fds: [1 + max_fetches]linux.pollfd = undefined;
        fds[0] = .{ .fd = ctl, .events = linux.POLL.IN, .revents = 0 };
        const t = unwound.now();
        var wait: i64 = -1;
        for (&fetches, fds[1..]) |*f, *p| {
            p.* = .{ .fd = f.fd, .events = linux.POLL.IN, .revents = 0 };
            if (f.fd < 0) continue;
            const left = @max(0, f.deadline - t);
            wait = if (wait < 0) left else @min(wait, left);
        }
        const rc = linux.poll(&fds, fds.len, @intCast(wait));
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS) @panic("age supervisor poll");
        if (fds[0].revents & linux.POLL.IN != 0) {
            if (!start(ctl, &fetches)) return;
        } else if (fds[0].revents != 0) return;
        const late = unwound.now();
        for (&fetches, fds[1..]) |*f, p| {
            if (f.fd < 0) continue;
            if (p.revents != 0) {
                finish(ctl, f);
            } else if (late >= f.deadline) {
                const id = f.id;
                const domain = f.domain;
                say(&domain, "timeout", reap(f));
                answer(ctl, id, .timeout, null);
            }
        }
    }
}

/// start reads one ask from the writer and forks its fetch. An ask it cannot
/// run is answered failed at once. It returns false when the writer is gone.
fn start(ctl: i32, fetches: *[max_fetches]Fetch) bool {
    var packet: [ask_max + 1]u8 = undefined;
    const n = linux.recvfrom(ctl, &packet, packet.len, linux.MSG.TRUNC, null, null);
    if (linux.errno(n) == .INTR) return true;
    if (linux.errno(n) != .SUCCESS or n == 0) return false;
    if (n < 4) return true;
    const id = std.mem.readInt(u32, packet[0..4], .big);
    const free = for (fetches) |*f| {
        if (f.fd < 0) break f;
    } else null;
    const domain = packet[4..@min(n, packet.len)];
    if (n > ask_max or !bootstrap.validName(domain) or free == null) {
        answer(ctl, id, .failed, null);
        return true;
    }
    var pipe: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&pipe, .{ .CLOEXEC = true })) != .SUCCESS) {
        answer(ctl, id, .failed, null);
        return true;
    }
    const self = linux.getpid();
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) {
        _ = linux.close(pipe[0]);
        _ = linux.close(pipe[1]);
        answer(ctl, id, .failed, null);
        return true;
    }
    if (pid == 0) {
        sandbox.tieTo(self);
        fetch.run(pipe[1], domain);
    }
    _ = linux.close(pipe[1]);
    free.?.* = .{
        .pid = @intCast(pid),
        .fd = pipe[0],
        .id = id,
        .deadline = unwound.now() + fetch_ms,
        .domain = wire.Name.fromText(domain) catch .{},
    };
    return true;
}

/// finish relays a child's record. Anything but one whole record is a
/// failed fetch, logged with how the child ended.
fn finish(ctl: i32, f: *Fetch) void {
    var record: [evidence.found_len + 1]u8 = undefined;
    const n = linux.read(f.fd, &record, record.len);
    const id = f.id;
    const domain = f.domain;
    const status = reap(f);
    if (linux.errno(n) == .SUCCESS and n == evidence.found_len)
        return answer(ctl, id, .found, record[0..n]);
    say(&domain, "failed", status);
    answer(ctl, id, .failed, null);
}

/// reap kills a fetch, waits for it and frees its slot, returning its status.
fn reap(f: *Fetch) i32 {
    _ = linux.kill(f.pid, linux.SIG.KILL);
    var status: i32 = 0;
    _ = linux.waitpid(f.pid, &status, 0);
    _ = linux.close(f.fd);
    f.* = .{};
    return status;
}

fn answer(ctl: i32, id: u32, how: How, record: ?[]const u8) void {
    var packet: [answer_len]u8 = @splat(0);
    std.mem.writeInt(u32, packet[0..4], id, .big);
    packet[4] = @backingInt(how);
    if (record) |r| @memcpy(packet[5..], r);
    _ = linux.sendto(ctl, &packet, packet.len, linux.MSG.NOSIGNAL, null, 0);
}

/// say logs a fetch that ended without usable evidence, and its wait status.
fn say(domain: *const wire.Name, comptime why: []const u8, status: i32) void {
    var buf: [384]u8 = undefined;
    const line = std.mem.print(
        &buf,
        "unwound-age: {{\"event\":\"fetch_" ++ why ++ "\",\"domain\":\"{s}\",\"status\":{d}}}\n",
        .{ domain.text(), status },
    ) catch return;
    _ = linux.write(2, line.ptr, line.len);
}

const unknown: age.Decision = .{ .source = .none, .verdict = .unknown };

/// Waiter is one of unwound's questions, waiting on its domain's check.
const Waiter = struct {
    request: ipc.Request,
    domain: wire.Name,
    cause: @FieldType(db_mod.Trigger, "cause"),
};

/// Check is one fetch out at the supervisor.
const Check = struct {
    id: u32,
    row: i64,
    domain: wire.Name,
    service: u8,
};

/// writer narrows the supervisor's Landlock domain to its database
/// directory and randomness, with no TCP connect, and its filter to its
/// channels and SQLite's files: no socket, fork or signal. Then it serves.
fn writer(listener: i32, ctl: i32, db_dir: [:0]const u8, db_path: [:0]const u8) noreturn {
    confineWriter(db_dir, listener) catch @panic("age writer sandbox");
    var w: Writer = .{
        .db = db_mod.Db.open(db_path) catch @panic("age database"),
        .listener = listener,
        .ctl = ctl,
        .psl_generation = generation(age.psl),
        .bootstrap_generation = generation(http.rdap_bootstrap),
    };
    w.serve();
}

fn confineWriter(db_dir: [:0]const u8, listener: i32) !void {
    const data: i32 = @intCast(try sys(
        linux.open(
            db_dir,
            .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
            0,
        ),
        "open age directory",
    ));
    const random: i32 = @intCast(try sys(
        linux.open("/dev/urandom", .{ .PATH = true, .CLOEXEC = true }, 0),
        "open randomness",
    ));
    try sandbox.landlock(&.{
        .{ .fd = data, .access = sandbox.read_file | sandbox.read_dir |
            sandbox.write_file | sandbox.truncate | sandbox.make_reg | sandbox.remove_file },
        .{ .fd = random, .access = sandbox.read_file },
    }, &.{});
    _ = linux.close(data);
    _ = linux.close(random);
    var f: sandbox.Filter = .{};
    fetch.allowBasics(&f);
    allowWriter(&f, listener);
    f.allowArg("write", 0, 2);
    try f.install();
}

/// Writer holds the database and unwound's channel. It answers from dated
/// evidence, and sends each domain that needs a check to the supervisor.
const Writer = struct {
    db: db_mod.Db,
    listener: i32,
    ctl: i32,
    /// channel is unwound's connection, or -1 while none is open.
    channel: i32 = -1,
    waiting: [unwound.max_slots]?Waiter = @splat(null),
    checks: [max_fetches]?Check = @splat(null),
    next_id: u32 = 0,
    /// turn is the service considered first for the next check, so that
    /// services take turns and none can hold up the others.
    turn: u8 = 0,
    psl_generation: [64]u8,
    bootstrap_generation: [64]u8,

    fn serve(w: *Writer) noreturn {
        while (true) {
            var fds: [2]linux.pollfd = .{
                .{
                    .fd = if (w.channel >= 0) w.channel else w.listener,
                    .events = linux.POLL.IN,
                    .revents = 0,
                },
                .{ .fd = w.ctl, .events = linux.POLL.IN, .revents = 0 },
            };
            const rc = linux.poll(&fds, fds.len, -1);
            if (linux.errno(rc) == .INTR) continue;
            if (linux.errno(rc) != .SUCCESS) @panic("age writer poll");
            if (fds[1].revents != 0) w.answers();
            if (fds[0].revents != 0) {
                if (w.channel >= 0) {
                    w.requests();
                } else {
                    const accepted = linux.accept4(
                        w.listener,
                        null,
                        null,
                        linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
                    );
                    if (linux.errno(accepted) == .SUCCESS) w.channel = @intCast(accepted);
                }
            }
            w.schedule();
        }
    }

    /// requests reads unwound's questions until none is left. Each is
    /// answered from evidence at once, or waits for its domain's check.
    fn requests(w: *Writer) void {
        var packet: [ipc.max_len + 1]u8 = undefined;
        while (true) {
            const n = linux.recvfrom(w.channel, &packet, packet.len, linux.MSG.TRUNC, null, null);
            switch (linux.errno(n)) {
                .SUCCESS => {},
                .INTR => continue,
                .AGAIN => return,
                else => return w.hangUp(),
            }
            if (n == 0) return w.hangUp();
            if (n > ipc.max_len) continue;
            const request = ipc.decode(packet[0..n]) orelse continue;
            w.ask(&request);
        }
    }

    /// hangUp forgets unwound's questions. Checks already out still finish
    /// and are recorded.
    fn hangUp(w: *Writer) void {
        _ = linux.close(w.channel);
        w.channel = -1;
        w.waiting = @splat(null);
    }

    fn ask(w: *Writer, request: *const ipc.Request) void {
        if (request.policy_generation != policy.generation or
            request.service >= policy.users.len) return;
        const id = request.request_id;
        const text = switch (age.boundary(request.name.text(), age.psl)) {
            .registered => |domain| domain,
            else => return w.reply(id, unknown, null),
        };
        const domain = wire.Name.fromText(text) catch return w.reply(id, unknown, null);
        const now = fetch.realtime();
        const cached = w.db.probe(text, now) catch return w.reply(id, unknown, &domain);
        if (!cached.due(now)) return w.reply(id, cached.decision, &domain);
        if (id > std.math.maxInt(i64)) return w.reply(id, unknown, &domain);
        const free = for (&w.waiting) |*x| {
            if (x.* == null) break x;
        } else return w.reply(id, unknown, &domain);
        free.* = .{
            .request = request.*,
            .domain = domain,
            .cause = if (cached.retry_after == 0) .miss else .retry,
        };
    }

    /// schedule starts checks while fetch slots are free, taking the oldest
    /// question of each service in turn: one check out per service, and one
    /// per domain, which every question for that domain then waits on.
    fn schedule(w: *Writer) void {
        while (for (&w.checks) |*c| {
            if (c.* == null) break c;
        } else null) |free| {
            const i = w.next() orelse return;
            w.begin(free, i);
        }
    }

    fn next(w: *Writer) ?usize {
        for (0..dns.max_users) |k| {
            const s: u8 = @intCast((w.turn + k) % dns.max_users);
            const busy = for (w.checks) |c| {
                if (c != null and c.?.service == s) break true;
            } else false;
            if (busy) continue;
            var oldest: ?usize = null;
            for (&w.waiting, 0..) |*maybe, i| if (maybe.*) |*x| {
                if (x.request.service != s) continue;
                const checking = for (w.checks) |c| {
                    if (c != null and c.?.domain.eql(&x.domain)) break true;
                } else false;
                if (checking) continue;
                if (oldest) |o| if (w.waiting[o].?.request.request_id < x.request.request_id)
                    continue;
                oldest = i;
            };
            if (oldest) |i| {
                w.turn = @intCast((s + 1) % dns.max_users);
                return i;
            }
        }
        return null;
    }

    /// begin records the check's first question, then asks the supervisor to
    /// fetch. If either fails, the domain's questions are answered unknown.
    fn begin(w: *Writer, free: *?Check, i: usize) void {
        const x = w.waiting[i].?;
        const r = &x.request;
        const label = dns.label(r.service);
        var label_text: [15]u8 = undefined;
        const source = std.mem.print(&label_text, "{d}.{d}.{d}.{d}", .{
            label[0], label[1], label[2], label[3],
        }) catch return w.settle(&x.domain, unknown);
        var namespace: [24]u8 = undefined;
        const uid = policy.uid(r.service);
        const policy_namespace = std.mem.print(&namespace, "uid:{d}", .{uid}) catch
            return w.settle(&x.domain, unknown);
        const row = w.db.beginCheck(.{
            .domain = x.domain.text(),
            .started_at = fetch.realtime(),
            .cause = x.cause,
            .request_id = @intCast(r.request_id),
            .dns_id = r.dns_id,
            .qname = r.name.text(),
            .qtype = @backingInt(r.qtype),
            .transport = r.transport,
            .source_label = source,
            .service_uid = uid,
            .policy_namespace = policy_namespace,
            .policy_generation = r.policy_generation,
        }) catch return w.settle(&x.domain, unknown);
        w.next_id +%= 1;
        var packet: [ask_max]u8 = undefined;
        std.mem.writeInt(u32, packet[0..4], w.next_id, .big);
        const text = x.domain.text();
        @memcpy(packet[4..][0..text.len], text);
        const sent = linux.sendto(w.ctl, &packet, 4 + text.len, linux.MSG.NOSIGNAL, null, 0);
        if (linux.errno(sent) != .SUCCESS) return w.settle(&x.domain, unknown);
        free.* = .{ .id = w.next_id, .row = row, .domain = x.domain, .service = r.service };
    }

    /// answers takes one ended fetch from the supervisor, checks and records
    /// what it found, and answers every question waiting on that domain. A
    /// fetch that timed out, failed or sent nonsense is an RDAP outage.
    fn answers(w: *Writer) void {
        var packet: [answer_len + 1]u8 = undefined;
        const n = linux.recvfrom(w.ctl, &packet, packet.len, linux.MSG.TRUNC, null, null);
        if (linux.errno(n) == .INTR) return;
        if (linux.errno(n) != .SUCCESS or n == 0) linux.exit_group(1);
        if (n != answer_len) return;
        const id = std.mem.readInt(u32, packet[0..4], .big);
        const slot = for (&w.checks) |*c| {
            if (c.* != null and c.*.?.id == id) break c;
        } else return;
        const check = slot.*.?;
        slot.* = null;
        const now = fetch.realtime();
        const found: evidence.Found = if (packet[4] == @backingInt(How.found))
            evidence.decode(packet[5..answer_len], now) orelse malformed: {
                say(&check.domain, "malformed", 0);
                break :malformed .{ .rdap = .unavailable };
            }
        else
            .{ .rdap = .unavailable };
        const text = check.domain.text();
        var url: [512]u8 = undefined;
        const rdap_url = bootstrap.rdapUrl(
            std.heap.page_allocator,
            text,
            http.rdap_bootstrap,
            &url,
        );
        const result = evidence.record(
            text,
            found,
            rdap_url,
            now,
            &w.psl_generation,
            &w.bootstrap_generation,
        );
        w.db.finishCheck(check.row, result) catch say(&check.domain, "unrecorded", 0);
        w.settle(&check.domain, w.db.decision(text, now) catch unknown);
    }

    fn settle(w: *Writer, domain: *const wire.Name, decision: age.Decision) void {
        for (&w.waiting) |*maybe| if (maybe.*) |x| if (x.domain.eql(domain)) {
            maybe.* = null;
            w.reply(x.request.request_id, decision, domain);
        };
    }

    /// reply never waits: if unwound is behind, its question times out there.
    fn reply(w: *Writer, request_id: u64, decision: age.Decision, domain: ?*const wire.Name) void {
        if (w.channel < 0) return;
        const response: ipc.Response = .{
            .request_id = request_id,
            .verdict = decision.verdict,
            .source = decision.source,
            .domain = if (domain) |d| d.* else null,
        };
        var out: [ipc.response_max]u8 = undefined;
        const sent = ipc.encodeResponse(&out, &response);
        const rc = linux.sendto(w.channel, sent.ptr, sent.len, linux.MSG.NOSIGNAL, null, 0);
        if (linux.errno(rc) == .AGAIN) return;
        if (linux.errno(rc) != .SUCCESS or rc != sent.len) w.hangUp();
    }
};

fn generation(comptime contents: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(contents, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}
