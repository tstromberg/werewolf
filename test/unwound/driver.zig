//! driver runs under fence as the services that ask unwound. It starts
//! unwound, keeps its audit log by draining the syslog socket into a file,
//! and answers the check's requests, a JSON line each, each asked by a
//! forked child that has become the asking uid. Between fork and exit a
//! child makes system calls and uses its own fixed memory, nothing more.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const linux = std.os.linux;
const mem = std.mem;
const netns = host.netns;
const dnswire = host.dnswire;

pub const Op = enum {
    ask,
    /// pipeline puts two whole queries in one TCP write, then reads both.
    pipeline,
    /// abandon closes pipelined TCP queries before unwound can answer.
    abandon,
    /// many asks one question from parallel sockets at once.
    many,
    /// race revokes the resolvers while a question waits on one.
    race,
    pause_log,
    audit_full,
    remove_log,
    start_without_log,
    upstream,
    domain,
    kill_upstream,
    restart,
};

pub const Request = struct {
    op: Op = .ask,
    uid: u32 = 0,
    name: []const u8 = "",
    second: []const u8 = "",
    type: u16 = 1,
    tcp: bool = false,
    server: []const u8 = "127.0.0.53",
    bind: []const u8 = "",
    /// timeout is in seconds.
    timeout: u32 = 8,
    parallel: u32 = 0,
    socket_uid: ?u32 = null,
    /// raw, in hex, is sent as it is instead of a query for name.
    raw: []const u8 = "",
    /// text is the new upstream file, or the domain.
    text: []const u8 = "",
    source: enum { dhcp, config } = .dhcp,
};

pub const Answer = struct {
    id: u16 = 0,
    rcode: u8 = 0,
    tc: bool = false,
    ad: bool = false,
    /// answers is each A record's address and any other record's type.
    answers: []const []const u8 = &.{},
    ttls: []const u32 = &.{},
    rdata: []const []const u8 = &.{},
    ms: u32 = 0,
    /// error is the errno tag a system call failed with, or timeout.
    @"error": []const u8 = "",
    sender_uid: ?u32 = null,
    results: []const Answer = &.{},
    closed: u32 = 0,
};

/// Reply is every request's reply; exit, unwound's, is null while it runs.
pub const Reply = struct {
    answer: ?Answer = null,
    refresh: ?Answer = null,
    exit: ?i32 = null,
};

const dev_log = "/run/syslog/dev-log";
const network = "/run/werewolf/network/";

/// run serves requests on standard input until it closes. unwound's stderr
/// goes to stderr; the fixture resolver's log is upstream.log beside audit.
pub fn run(l: netns.Lab, unwound: []const u8, audit: []const u8, stderr: []const u8) !void {
    var d: Driver = .{
        .l = l,
        .unwound = unwound,
        .stderr = stderr,
        .upstream_log = try l.gpa.print(
            "{s}/upstream.log",
            .{std.fs.path.dirname(audit) orelse "."},
        ),
        .daemon = undefined,
        .drain = undefined,
    };
    _ = linux.mkdir("/run/syslog", 0o755);
    try d.startDrain(audit);
    // Nothing outlives the driver: its end is the check's.
    defer if (d.drain > 0) {
        _ = linux.kill(d.drain, .KILL);
    };
    try d.start();
    defer {
        d.daemon.signal(.KILL);
        _ = d.daemon.wait(null) catch {};
    }
    try netns.writeAll(1, "ready\n");
    var lines: netns.Lines = .{ .fd = 0 };
    while (true) {
        const text = lines.next(24 * 3600 * 1000) catch |err| switch (err) {
            error.EndOfStream => return,
            else => |e| return e,
        };
        const r = try std.json.parseFromSliceLeaky(Request, l.gpa, text, .{});
        var out: std.Io.Writer.Allocating = .init(l.gpa);
        try std.json.Stringify.value(try d.serve(r), .{}, &out.writer);
        try out.writer.writeByte('\n');
        try netns.writeAll(1, out.written());
    }
}

const Driver = struct {
    l: netns.Lab,
    unwound: []const u8,
    stderr: []const u8,
    upstream_log: []const u8,
    daemon: netns.Child,
    /// drain is the audit reader's pid, 0 once reaped.
    drain: linux.pid_t,

    /// start runs unwound, its stderr new, and waits for its UDP listener.
    fn start(d: *Driver) !void {
        const stderr = try d.l.create(d.stderr);
        defer netns.close(stderr);
        d.daemon = try d.l.spawn(&.{d.unwound}, .{ .stderr = .{ .fd = stderr } });
        for (0..100) |_| {
            const udp = d.l.read("/proc/net/udp") catch "";
            if (mem.find(u8, udp, ":0035 ") != null) break;
            netns.nap(50);
        }
    }

    /// startDrain binds the syslog socket and forks the reader that appends
    /// each record to audit, a line each. It alone keeps the socket.
    fn startDrain(d: *Driver, audit: []const u8) !void {
        const sink = try sys(linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0));
        var at: linux.sockaddr.un = .{ .path = @splat(0) };
        @memcpy(at.path[0..dev_log.len], dev_log);
        _ = try sys(linux.bind(@intCast(sink), @ptrCast(&at), @sizeOf(linux.sockaddr.un)));
        const out = try sys(linux.open(try d.l.gpa.dupeSentinel(u8, audit, 0), .{
            .ACCMODE = .WRONLY,
            .APPEND = true,
            .CREAT = true,
            .CLOEXEC = true,
        }, 0o644));
        const pid = try sys(linux.fork());
        if (pid == 0) {
            _ = linux.prctl(
                @backingInt(linux.PR.SET_PDEATHSIG),
                @backingInt(linux.SIG.KILL),
                0,
                0,
                0,
            );
            var buf: [4097]u8 = undefined;
            while (true) {
                const n = linux.recvfrom(@intCast(sink), &buf, 4096, 0, null, null);
                if (linux.errno(n) != .SUCCESS) continue;
                const record = mem.trimEnd(u8, buf[0..n], "\n");
                buf[record.len] = '\n';
                netns.writeAll(@intCast(out), buf[0 .. record.len + 1]) catch {};
            }
        }
        netns.close(@intCast(sink));
        netns.close(@intCast(out));
        d.drain = @intCast(pid);
    }

    fn serve(d: *Driver, r: Request) !Reply {
        const gpa = d.l.gpa;
        switch (r.op) {
            .ask,
            .pipeline,
            .abandon,
            .many,
            => return .{ .answer = try (try probe(r)).finish(gpa) },
            .race => {
                const pending = try probe(.{ .uid = 2003, .name = "race.example.test" });
                for (0..100) |_| {
                    const asked = d.l.read(d.upstream_log) catch "";
                    if (std.ascii.findIgnoreCase(asked, "race.example.test") != null) break;
                    netns.nap(10);
                } else return d.l.fail("race_unasked", .{});
                netns.nap(1100);
                try d.replace(network ++ "upstream", "", null);
                const refresh = try (try probe(.{
                    .uid = 2003,
                    .name = "refresh.example.test",
                })).finish(gpa);
                return .{
                    .answer = try pending.finish(gpa),
                    .refresh = refresh,
                    .exit = try d.daemon.wait(0),
                };
            },
            .pause_log => {
                if (d.drain == 0) return d.l.fail("no_audit_reader", .{});
                _ = linux.kill(d.drain, .STOP);
                _ = try (try probe(.{ .uid = 2001, .name = "denied.example.test" })).finish(gpa);
                const deadline = netns.now() + 1000;
                while (netns.now() < deadline) : (netns.nap(10)) {
                    var status: u32 = 0;
                    const rc = linux.wait4(
                        d.drain,
                        @ptrCast(&status),
                        linux.W.UNTRACED | linux.W.NOHANG,
                        null,
                    );
                    if (linux.errno(rc) == .SUCCESS and rc != 0 and
                        linux.W.IFSTOPPED(status)) return .{};
                }
                return d.l.fail("audit_reader_running", .{});
            },
            .audit_full => {
                const filler = try sys(linux.socket(
                    linux.AF.UNIX,
                    linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
                    0,
                ));
                defer netns.close(@intCast(filler));
                var at: linux.sockaddr.un = .{ .path = @splat(0) };
                @memcpy(at.path[0..dev_log.len], dev_log);
                _ = try sys(linux.connect(@intCast(filler), &at, @sizeOf(linux.sockaddr.un)));
                while (true) {
                    const rc = linux.sendto(@intCast(filler), "full", 4, 0, null, 0);
                    switch (linux.errno(rc)) {
                        .SUCCESS => {},
                        .AGAIN => break,
                        else => |e| return d.l.fail("filler_failed", .{ .errno = @tagName(e) }),
                    }
                }
                const answer = try (try probe(.{
                    .uid = 2003,
                    .name = "audit-proof.example.test",
                })).finish(gpa);
                return .{ .answer = answer, .exit = try d.daemon.wait(0) };
            },
            .remove_log => {
                if (d.drain == 0) return d.l.fail("no_audit_reader", .{});
                _ = linux.kill(d.drain, .KILL);
                var status: u32 = 0;
                _ = linux.wait4(d.drain, @ptrCast(&status), 0, null);
                d.drain = 0;
                _ = try sys(linux.unlink(dev_log));
                return .{};
            },
            .start_without_log => {
                d.daemon.signal(.KILL);
                _ = try d.daemon.wait(null);
                try d.start();
                const answer = try (try probe(.{
                    .uid = 2003,
                    .name = "audit-startup.example.test",
                })).finish(gpa);
                return .{ .answer = answer, .exit = try d.daemon.wait(0) };
            },
            .upstream => {
                try d.replace(network ++ "upstream", r.text, null);
                netns.nap(1100);
                return .{};
            },
            .domain => {
                const base = switch (r.source) {
                    .dhcp => network ++ "dhcp-domain",
                    .config => network ++ "config-domain",
                };
                // DHCP's user writes its domain; the configuration is root's.
                try d.replace(base, r.text, if (r.source == .dhcp) 73 else 0);
                netns.nap(1100);
                return .{};
            },
            .kill_upstream => {
                const path = try gpa.print(
                    "/proc/{d}/task/{d}/children",
                    .{ d.daemon.pid, d.daemon.pid },
                );
                var children = mem.tokenizeScalar(u8, try d.l.read(path), ' ');
                const child = try std.fmt.parseInt(linux.pid_t, children.next() orelse
                    return d.l.fail("no_upstream_child", .{}), 10);
                _ = linux.kill(child, .KILL);
                return .{ .exit = try d.daemon.wait(3000) };
            },
            .restart => {
                const previous = try d.daemon.wait(3000);
                if (previous == null) {
                    d.daemon.signal(.KILL);
                    _ = try d.daemon.wait(null);
                }
                try d.start();
                return .{ .exit = previous };
            },
        }
    }

    /// replace writes path.new, owned by owner:owner if given, and renames
    /// it over path, as DHCP and the configuration publish.
    fn replace(d: *Driver, path: []const u8, text: []const u8, owner: ?u32) !void {
        const new = try d.l.gpa.print("{s}.new", .{path});
        try d.l.write(new, text);
        if (owner) |id| try d.l.chown(new, id, id);
        try std.Io.Dir.cwd().rename(new, std.Io.Dir.cwd(), path, d.l.io);
    }
};

fn sys(rc: usize) !usize {
    if (linux.errno(rc) != .SUCCESS) return error.SystemCallFailed;
    return rc;
}

/// Pending is a forked question: its child and the pipe its answer comes on.
const Pending = struct {
    pid: linux.pid_t,
    fd: linux.fd_t,

    /// finish reads the child's answer and reaps it.
    fn finish(p: Pending, gpa: mem.Allocator) !Answer {
        defer netns.close(p.fd);
        var out: std.ArrayList(u8) = .empty;
        var buf: [4096]u8 = undefined;
        const deadline = netns.now() + 120_000;
        while (true) {
            var fds = [1]linux.pollfd{.{ .fd = p.fd, .events = linux.POLL.IN, .revents = 0 }};
            const left = deadline - netns.now();
            if (left <= 0) return error.ProbeTimeout;
            if (linux.poll(&fds, 1, @intCast(left)) == 0) continue;
            const n = linux.read(p.fd, &buf, buf.len);
            if (linux.errno(n) == .INTR) continue;
            if (linux.errno(n) != .SUCCESS or n == 0) break;
            try out.appendSlice(gpa, buf[0..n]);
        }
        var status: u32 = 0;
        _ = linux.wait4(p.pid, @ptrCast(&status), 0, null);
        return std.json.parseFromSliceLeaky(Answer, gpa, out.items, .{});
    }
};

/// memory is a probe child's heap: each fork starts with its own copy.
var memory: [1 << 20]u8 = undefined;

/// probe forks a child that becomes r.uid, if not 0, and asks r. A socket
/// another uid made first, as r.socket_uid asks, is passed to it.
fn probe(r: Request) !Pending {
    const passed: ?linux.fd_t = if (r.socket_uid) |uid| try passSocket(uid, r.tcp) else null;
    defer if (passed) |fd| netns.close(fd);
    var pipe: [2]linux.fd_t = undefined;
    _ = try sys(linux.pipe2(&pipe, .{ .CLOEXEC = true }));
    const pid = try sys(linux.fork());
    if (pid == 0) {
        netns.close(pipe[0]);
        var fba: std.heap.FixedBufferAllocator = .init(&memory);
        const answer = perform(fba.allocator(), r, passed);
        var out: std.Io.Writer.Allocating = .init(fba.allocator());
        std.json.Stringify.value(answer, .{}, &out.writer) catch linux.exit_group(1);
        netns.writeAll(pipe[1], out.written()) catch {};
        linux.exit_group(0);
    }
    netns.close(pipe[1]);
    return .{ .pid = @intCast(pid), .fd = pipe[0] };
}

/// drop gives up root's groups and becomes uid:uid.
fn drop(uid: u32) !void {
    const none: [0]linux.gid_t = .{};
    _ = try call(linux.setgroups(0, &none));
    _ = try call(linux.setgid(uid));
    _ = try call(linux.setuid(uid));
}

const native = builtin.cpu.arch.endian();

/// passSocket has uid open a socket and send it here, then exit, so the
/// socket outlives its maker before another user asks with it.
fn passSocket(uid: u32, tcp: bool) !linux.fd_t {
    var pair: [2]linux.fd_t = undefined;
    _ = try sys(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &pair));
    const pid = try sys(linux.fork());
    if (pid == 0) {
        netns.close(pair[0]);
        drop(uid) catch linux.exit_group(1);
        const kind: u32 = if (tcp) linux.SOCK.STREAM else linux.SOCK.DGRAM;
        const s = linux.socket(linux.AF.INET, kind, 0);
        if (linux.errno(s) != .SUCCESS) linux.exit_group(1);
        var control: [24]u8 align(8) = @splat(0);
        mem.writeInt(usize, control[0..8], 20, native);
        mem.writeInt(i32, control[8..12], linux.SOL.SOCKET, native);
        mem.writeInt(i32, control[12..16], linux.SCM.RIGHTS, native);
        mem.writeInt(i32, control[16..20], @intCast(s), native);
        const iov = [_]std.posix.iovec_const{.{ .base = "F", .len = 1 }};
        const msg: linux.msghdr_const = .{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &control,
            .controllen = control.len,
            .flags = 0,
        };
        linux.exit_group(if (linux.sendmsg(pair[1], &msg, 0) == 1) 0 else 1);
    }
    netns.close(pair[1]);
    defer netns.close(pair[0]);
    var data: [1]u8 = undefined;
    var control: [64]u8 align(8) = undefined;
    var iov = [_]std.posix.iovec{.{ .base = &data, .len = 1 }};
    var msg: linux.msghdr = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    const n = linux.recvmsg(pair[0], &msg, 0);
    var status: u32 = 0;
    _ = linux.wait4(@intCast(pid), @ptrCast(&status), 0, null);
    if (status != 0) return error.SocketMakerFailed;
    // One byte, untruncated, with exactly one descriptor in one SCM_RIGHTS.
    if (linux.errno(n) != .SUCCESS or n != 1 or data[0] != 'F' or msg.flags != 0 or
        msg.controllen < 20 or mem.readInt(usize, control[0..8], native) != 20 or
        mem.readInt(i32, control[8..12], native) != linux.SOL.SOCKET or
        mem.readInt(i32, control[12..16], native) != linux.SCM.RIGHTS) return error.BadSocketPass;
    return mem.readInt(i32, control[16..20], native);
}

// What follows runs in a probe child.

/// errno is the first failed call's error, in a probe child.
var errno: linux.E = .SUCCESS;

fn call(rc: usize) error{Failed}!usize {
    const e = linux.errno(rc);
    if (e == .SUCCESS) return rc;
    errno = e;
    return error.Failed;
}

fn perform(gpa: mem.Allocator, r: Request, passed: ?linux.fd_t) Answer {
    if (r.uid != 0) drop(r.uid) catch return failure();
    const start = netns.now();
    var a = switch (r.op) {
        .pipeline => pipeline(gpa, r),
        .abandon => abandon(r),
        .many => many(gpa, r),
        else => ask(gpa, r, passed),
    } catch |err| switch (err) {
        error.Failed => failure(),
        error.EndOfStream => Answer{ .@"error" = "closed" },
        else => Answer{ .@"error" = @errorName(err) },
    };
    a.ms = @intCast(netns.now() - start);
    if (passed != null) a.sender_uid = linux.getuid();
    return a;
}

fn failure() Answer {
    return .{ .@"error" = if (errno == .AGAIN) "timeout" else @tagName(errno) };
}

fn ask(gpa: mem.Allocator, r: Request, passed: ?linux.fd_t) !Answer {
    var query_buf: [512]u8 = undefined;
    const query = if (r.raw.len > 0)
        try std.fmt.hexToBytes(&query_buf, r.raw)
    else
        try dnswire.query(&query_buf, 0x4242, r.name, r.type);
    const kind: u32 = if (r.tcp) linux.SOCK.STREAM else linux.SOCK.DGRAM;
    const s: linux.fd_t = passed orelse @intCast(try call(linux.socket(linux.AF.INET, kind, 0)));
    netns.limit(s, r.timeout * 1000);
    if (r.bind.len > 0) {
        const at = try netns.address(r.bind, 0);
        _ = try call(linux.bind(s, @ptrCast(&at), @sizeOf(linux.sockaddr.in)));
    }
    const to = try netns.address(r.server, 53);
    var buf: [65535]u8 = undefined;
    if (!r.tcp) {
        _ = try call(linux.sendto(
            s,
            query.ptr,
            query.len,
            0,
            @ptrCast(&to),
            @sizeOf(linux.sockaddr.in),
        ));
        return render(gpa, buf[0..try call(linux.recvfrom(s, &buf, 4096, 0, null, null))]);
    }
    _ = try call(linux.connect(s, &to, @sizeOf(linux.sockaddr.in)));
    try send(s, &.{query});
    return render(gpa, try receive(s, &buf));
}

fn pipeline(gpa: mem.Allocator, r: Request) !Answer {
    const s: linux.fd_t = @intCast(try call(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0)));
    netns.limit(s, 8000);
    const to = try netns.address("127.0.0.53", 53);
    _ = try call(linux.connect(s, &to, @sizeOf(linux.sockaddr.in)));
    var one: [512]u8 = undefined;
    var two: [512]u8 = undefined;
    try send(s, &.{
        try dnswire.query(&one, 0x4242, r.name, 1),
        try dnswire.query(&two, 0x4243, r.second, 1),
    });
    const results = try gpa.alloc(Answer, 2);
    var buf: [65535]u8 = undefined;
    for (results) |*a| a.* = try render(gpa, try receive(s, &buf));
    return .{ .results = results };
}

fn abandon(r: Request) !Answer {
    var buf: [512]u8 = undefined;
    const query = try dnswire.query(&buf, 0x4242, r.name, 1);
    const to = try netns.address("127.0.0.53", 53);
    for (0..16) |_| {
        const s: linux.fd_t = @intCast(try call(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0)));
        defer netns.close(s);
        netns.limit(s, 3000);
        _ = try call(linux.connect(s, &to, @sizeOf(linux.sockaddr.in)));
        const frames: [10][]const u8 = @splat(query);
        try send(s, &frames);
        _ = linux.shutdown(s, linux.SHUT.RDWR);
        netns.nap(20);
    }
    return .{ .closed = 16 };
}

fn many(gpa: mem.Allocator, r: Request) !Answer {
    const sockets = try gpa.alloc(linux.fd_t, r.parallel);
    const to = try netns.address("127.0.0.53", 53);
    for (sockets, 0..) |*s, i| {
        s.* = @intCast(try call(linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0)));
        netns.limit(s.*, 8000);
        var buf: [512]u8 = undefined;
        const query = try dnswire.query(&buf, @intCast(0x4300 + i), r.name, r.type);
        _ = try call(linux.sendto(
            s.*,
            query.ptr,
            query.len,
            0,
            @ptrCast(&to),
            @sizeOf(linux.sockaddr.in),
        ));
    }
    const results = try gpa.alloc(Answer, sockets.len);
    var buf: [4096]u8 = undefined;
    for (results, sockets) |*a, s| a.* = try render(
        gpa,
        buf[0..try call(linux.recvfrom(s, &buf, buf.len, 0, null, null))],
    );
    return .{ .results = results };
}

/// send writes each query as a TCP frame, all in one write.
fn send(s: linux.fd_t, queries: []const []const u8) !void {
    var buf: [8192]u8 = undefined;
    var n: usize = 0;
    for (queries) |q| {
        mem.writeInt(u16, buf[n..][0..2], @intCast(q.len), .big);
        @memcpy(buf[n + 2 ..][0..q.len], q);
        n += 2 + q.len;
    }
    var at: usize = 0;
    while (at < n) at += try call(linux.write(s, buf[at..n].ptr, n - at));
}

/// receive reads one TCP frame into buf.
fn receive(s: linux.fd_t, buf: *[65535]u8) ![]const u8 {
    var size: [2]u8 = undefined;
    try exact(s, &size);
    const msg = buf[0..mem.readInt(u16, &size, .big)];
    try exact(s, msg);
    return msg;
}

fn exact(s: linux.fd_t, buf: []u8) !void {
    var at: usize = 0;
    while (at < buf.len) {
        const n = try call(linux.read(s, buf[at..].ptr, buf.len - at));
        if (n == 0) return error.EndOfStream;
        at += n;
    }
}

/// render is msg as an Answer: each A record's address, others' types.
fn render(gpa: mem.Allocator, msg: []const u8) !Answer {
    var records: [dnswire.max_records]dnswire.Record = undefined;
    const reply = try dnswire.parse(msg, &records);
    const answers = try gpa.alloc([]const u8, reply.answers.len);
    const ttls = try gpa.alloc(u32, reply.answers.len);
    const rdata = try gpa.alloc([]const u8, reply.answers.len);
    for (reply.answers, answers, ttls, rdata) |rr, *a, *t, *d| {
        a.* = if (rr.kind == 1 and rr.data.len == 4)
            try gpa.print("{d}.{d}.{d}.{d}", .{ rr.data[0], rr.data[1], rr.data[2], rr.data[3] })
        else if (dnswire.typeName(rr.kind)) |n| n else try gpa.print("{d}", .{rr.kind});
        t.* = rr.ttl;
        d.* = try gpa.print("{x}", .{rr.data});
    }
    return .{
        .id = reply.id,
        .rcode = reply.rcode(),
        .tc = reply.truncated(),
        .ad = reply.authentic(),
        .answers = answers,
        .ttls = ttls,
        .rdata = rdata,
    };
}
