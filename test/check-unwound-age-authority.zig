//! check-unwound-age-authority runs the early age writer as init would, as
//! root: it hands over a control socket, waits for the writer's R, makes its
//! database directory and socket read-only to root's view, then sends G. A
//! request over the socket must be answered and leave evidence in a WAL
//! database the writer made (cold) or reopened (seeded), and the writer must
//! say nothing on stderr. Run it from the checkout's root, which holds
//! cmd/unwound/age.sql. --live lets the writer ask the real registry, with
//! the host's resolver and CA certificates, for a cold database alone.
//!
//!     check-unwound-age-authority [--live] AGE_BINARY

const std = @import("std");
const host = @import("host");
const netns = host.netns;
const sqlite = host.sqlite;
const linux = std.os.linux;
const mem = std.mem;
const Lab = netns.Lab;

const usage = "usage: check-unwound-age-authority [--live] AGE_BINARY, from the checkout's root";
const schema_path = "cmd/unwound/age.sql";
const ca_path = "/etc/ssl/certs/ca-certificates.crt";
const policy = "lookup 2002 * A AAAA\n";
const db_dir = "/data/svc/unwound-age";
const socket_path = "/run/werewolf-age/age.sock";
const day = 86400;

const Case = enum { cold, seeded, live };

pub fn main(init: std.process.Init) !void {
    const l: Lab = .init(init, "check-unwound-age-authority");
    const args = try init.minimal.args.toSlice(l.gpa);
    if (linux.geteuid() != 0) return l.fail("refused", .{ .why = "requires root on Linux" });
    if (args.len == 4 and mem.eql(u8, args[1], "--inside")) {
        const case = std.meta.stringToEnum(
            Case,
            args[3],
        ) orelse return l.fail("usage", .{ .usage = usage });
        return inside(l, args[2], case);
    }
    const live = args.len == 3 and mem.eql(u8, args[1], "--live");
    if (args.len != 2 and !live) return l.fail("usage", .{ .usage = usage });
    std.Io.Dir.cwd().access(l.io, schema_path, .{}) catch
        return l.fail("usage", .{ .usage = usage, .missing = schema_path });
    const binary = try std.Io.Dir.cwd().realPathFileAlloc(l.io, args[args.len - 1], l.gpa);
    const self = try l.self();
    const cases: []const Case = if (live) &.{.live} else &.{ .cold, .seeded };
    for (cases) |case| {
        // Only a live run may reach a network; the others get none.
        var run = try l.spawn(if (live)
            &.{ "unshare", "--mount", "--fork", self, "--inside", binary, @tagName(case) }
        else
            &.{
                "unshare",
                "--mount",
                "--net",
                "--fork",
                self,
                "--inside",
                binary,
                @tagName(case),
            }, .{});
        const exit = try run.wait(null);
        if (exit != 0) return l.fail("case_failed", .{ .case = @tagName(case), .exit = exit });
    }
}

fn inside(l: Lab, binary: []const u8, case: Case) !void {
    const ca = if (case == .live) try l.read(ca_path) else null;
    const schema = if (case == .seeded) try l.read(schema_path) else null;
    try l.private();
    std.Io.Dir.cwd().access(l.io, "/data", .{}) catch try l.mkdir("/data", 0o755);
    for ([_][]const u8{ "/run", "/usr/share", "/data", "/etc" }) |p| try l.tmpfs(p);
    if (ca) |bundle| {
        try std.Io.Dir.cwd().createDirPath(l.io, "/etc/ssl/certs");
        try l.write(ca_path, bundle);
        try l.write("/etc/resolv.conf", "nameserver 127.0.0.53\n");
    } else {
        // No provider traffic: the private network has no route here.
        try l.write("/etc/resolv.conf", "nameserver 192.0.2.1\noptions attempts:1 timeout:1\n");
    }
    try l.mkdir("/usr/share/werewolf", 0o755);
    try l.write("/usr/share/werewolf/net", policy);
    try std.Io.Dir.cwd().createDirPath(l.io, db_dir);
    var clock: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &clock);
    const now: i64 = clock.sec;
    if (schema) |sql| {
        const db = try sqlite.Db.open(l.gpa, db_dir ++ "/age.db", .read_write);
        defer db.close();
        try db.exec(sql);
        _ = try db.one("PRAGMA journal_mode=WAL", &.{});
        try db.run(
            \\INSERT INTO domain_age
            \\    (domain,source,status,registered_at,effective_at,fetched_at,
            \\     retry_after,last_used_at,psl_generation,bootstrap_generation)
            \\    VALUES (?,?,?,?,?,?,?,?,?,?)
        , &.{
            .{ .text = "example.com" }, .{ .text = "rdap" },    .{ .text = "valid" },
            .{ .int = 946684800 },      .{ .int = 946684800 },  .{ .int = now },
            .{ .int = now + 7 * day },  .{ .int = now - 7200 }, .{ .text = "fixture" },
            .{ .text = "fixture" },
        });
    }
    try l.chown(db_dir, 55, 55);
    try l.chmod(db_dir, 0o700);
    var dir = try std.Io.Dir.cwd().openDir(l.io, db_dir, .{ .iterate = true });
    var entries = dir.iterate();
    while (try entries.next(l.io)) |entry|
        try l.chown(try l.gpa.print("{s}/{s}", .{ db_dir, entry.name }), 55, 55);
    dir.close(l.io);
    try l.mkdir("/run/werewolf-age", 0o755);
    try std.Io.Dir.cwd().createDirPath(l.io, "/run/werewolf/network");

    var pair: [2]linux.fd_t = undefined;
    if (linux.errno(linux.socketpair(
        linux.AF.UNIX,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
        0,
        &pair,
    )) != .SUCCESS)
        return error.SocketFailed;
    var worker = try l.spawn(&.{binary}, .{ .fds = &.{pair[1]}, .stderr = .pipe });
    netns.close(pair[1]);
    var mounted: [2][]const u8 = undefined;
    var n: usize = 0;
    const result = authority(l, pair[0], &worker, case, now, &mounted, &n);
    worker.signal(.KILL);
    const errors = try drain(l, worker.stderr.?, 5000);
    _ = try worker.wait(null);
    netns.close(pair[0]);
    while (n > 0) : (n -= 1) try l.unmount(mounted[n - 1]);
    if (errors.len > 0) return l.fail("worker_stderr", .{ .stderr = errors });
    return result;
}

fn authority(
    l: Lab,
    control: linux.fd_t,
    worker: *netns.Child,
    case: Case,
    now: i64,
    mounted: *[2][]const u8,
    n: *usize,
) !void {
    try timeout(control, 10);
    var ready: [1]u8 = undefined;
    const got = linux.recvfrom(control, &ready, 1, 0, null, null);
    if (linux.errno(got) != .SUCCESS or got != 1 or ready[0] != 'R')
        return l.fail("not_ready", .{ .stderr = try drain(l, worker.stderr.?, 5000) });
    for ([_][]const u8{ db_dir, "/run/werewolf-age" }) |p| {
        try l.bind(p, p);
        try l.readOnly(p);
        mounted[n.*] = p;
        n.* += 1;
    }
    try netns.writeAll(control, "G");
    const db_path = db_dir ++ "/age.db";
    const opened = linux.open(
        db_path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true },
        0o666,
    );
    try blocked(l, db_path, opened);
    if (linux.errno(opened) == .SUCCESS) netns.close(@intCast(opened));
    try blocked(l, socket_path, linux.unlink(socket_path));

    const name = "a.example.com";
    var request: [23 + name.len]u8 = undefined;
    request[0..4].* = .{ 1, 0, 0, 0 };
    mem.writeInt(u64, request[4..12], 42, .big);
    mem.writeInt(u16, request[12..14], 7, .big);
    mem.writeInt(u16, request[14..16], 1, .big);
    mem.writeInt(u16, request[16..18], 1, .big);
    mem.writeInt(u32, request[18..22], std.hash.Crc32.hash(policy), .big);
    request[22] = name.len;
    request[23..].* = name.*;
    const client = try seqpacket(socket_path);
    defer netns.close(client);
    try timeout(client, 13);
    try netns.writeAll(client, &request);
    var response: [300]u8 = undefined;
    const size = linux.recvfrom(client, &response, response.len, 0, null, null);
    if (linux.errno(size) != .SUCCESS) return l.fail(
        "no_response",
        .{ .errno = @backingInt(linux.errno(size)) },
    );
    const answer = response[0..size];
    const answered = case != .cold;
    const head = [4]u8{ 1, if (answered) 2 else 0, if (answered) 1 else 0, 11 };
    if (answer.len < 12 or !mem.eql(u8, answer[0..4], &head) or
        mem.readInt(u64, answer[4..12], .big) != 42 or !mem.eql(u8, answer[12..], "example.com"))
        return l.fail("response", .{ .response = answer });

    // A cold start must create the database, schema and WAL under the actual
    // writer filter; a seeded start must reopen and update it.
    const db = try sqlite.Db.open(l.gpa, db_path, .read_only);
    defer db.close();
    try expect(l, db, "PRAGMA journal_mode", &.{}, &.{.{ .text = "wal" }});
    try expect(l, db, "PRAGMA integrity_check", &.{}, &.{.{ .text = "ok" }});
    if (case == .seeded) {
        const touched = (try db.one("SELECT last_used_at FROM domain_age", &.{})) orelse
            return l.fail("evidence", .{ .why = "no domain_age row" });
        if (touched[0] != .int or
            touched[0].int < now) return l.fail("evidence", .{ .last_used_at = touched[0] });
    } else {
        try expect(l, db, "SELECT source,status FROM domain_age WHERE domain=?", &.{
            .{ .text = "example.com" },
        }, if (case == .live)
            &.{ .{ .text = "rdap" }, .{ .text = "valid" } }
        else
            &.{ .{ .text = "none" }, .{ .text = "error" } });
        try expect(l, db,
            \\SELECT request_id,dns_id,qname,qtype,transport,source_label,service_uid,
            \\policy_namespace FROM age_check WHERE domain=?
        , &.{.{ .text = "example.com" }}, &.{
            .{ .int = 42 },            .{ .int = 7 },    .{ .text = name },       .{ .int = 1 },
            .{
                .text = "udp",
            },
            .{ .text = "127.53.0.1" }, .{ .int = 2002 }, .{ .text = "uid:2002" },
        });
    }
    l.log("pass", .{
        .database = if (case == .seeded) "seeded" else "cold",
        .what = "WAL, request and root read-only views",
    });
}

/// expect requires a query's first row to be want.
fn expect(
    l: Lab,
    db: sqlite.Db,
    sql: []const u8,
    params: []const sqlite.Cell,
    want: []const sqlite.Cell,
) !void {
    const row = try db.one(sql, params);
    if (row == null or
        !sqlite.eqlRow(
            row.?,
            want,
        )) return l.fail("evidence", .{ .query = sql, .got = row, .want = want });
}

/// blocked requires rc, root's write to p, to fail as a read-only filesystem.
fn blocked(l: Lab, p: []const u8, rc: usize) !void {
    switch (linux.errno(rc)) {
        .ROFS => {},
        .SUCCESS => return l.fail(
            "modified",
            .{ .why = "root modified a read-only view", .path = p },
        ),
        else => |e| return l.fail("blocked", .{ .path = p, .errno = @backingInt(e) }),
    }
}

/// drain reads fd to its end, for up to ms.
fn drain(l: Lab, fd: linux.fd_t, ms: u32) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    const deadline = netns.now() + ms;
    while (netns.now() < deadline) {
        var fds = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        const polled = linux.poll(&fds, 1, @intCast(@max(deadline - netns.now(), 0)));
        if (linux.errno(polled) == .INTR) continue;
        if (linux.errno(polled) != .SUCCESS or polled == 0) break;
        var buf: [4096]u8 = undefined;
        const got = linux.read(fd, &buf, buf.len);
        if (linux.errno(got) != .SUCCESS or got == 0) break;
        try out.appendSlice(l.gpa, buf[0..got]);
    }
    return out.items;
}

fn timeout(fd: linux.fd_t, seconds: isize) !void {
    const t: linux.timeval = .{ .sec = seconds, .usec = 0 };
    for ([_]u32{ linux.SO.RCVTIMEO, linux.SO.SNDTIMEO }) |opt|
        if (linux.errno(linux.setsockopt(
            fd,
            linux.SOL.SOCKET,
            opt,
            mem.asBytes(&t),
            @sizeOf(linux.timeval),
        )) != .SUCCESS)
            return error.SocketFailed;
}

fn seqpacket(p: []const u8) !linux.fd_t {
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(address.path[0..p.len], p);
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: linux.fd_t = @intCast(rc);
    if (linux.errno(linux.connect(fd, &address, @sizeOf(linux.sockaddr.un))) != .SUCCESS) {
        netns.close(fd);
        return error.ConnectFailed;
    }
    return fd;
}
