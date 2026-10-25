//! check-unwound-age-mount checks one mount boundary, as root: a writer in
//! its own mount namespace keeps SQLite in WAL mode and a socket in a
//! directory that root's namespace sees only read-only, under any alias.
//! Root without CAP_SYS_ADMIN cannot remount it, nor reach it through the
//! writer's /proc without CAP_SYS_PTRACE. It checks the boundary, not every
//! attack on the worker, which must also drop capabilities and deny tracing.
//!
//!     check-unwound-age-mount

const std = @import("std");
const host = @import("host");
const netns = host.netns;
const sqlite = host.sqlite;
const linux = std.os.linux;
const mem = std.mem;
const Lab = netns.Lab;

const writer_id = 74;
const suffixes = [_][]const u8{ "age.db", "age.db-wal", "age.db-shm" };

extern "c" fn setgroups(size: usize, list: ?[*]const linux.gid_t) c_int;

pub fn main(init: std.process.Init) !void {
    const l: Lab = .init(init, "check-unwound-age-mount");
    const args = try init.minimal.args.toSlice(l.gpa);
    if (linux.geteuid() != 0) return l.fail("refused", .{ .why = "requires root on Linux" });
    if (args.len == 1) try l.enter(&.{"--mount"}, &.{"--inside"});
    if (args.len == 2 and mem.eql(u8, args[1], "--inside")) return inside(l);
    if (args.len == 3 and mem.eql(u8, args[1], "--writer")) return writer(l, args[2]);
    if (args.len == 3 and mem.eql(u8, args[1], "--probe")) return probe(l, args[2]);
    return l.fail("usage", .{ .usage = "check-unwound-age-mount" });
}

fn inside(l: Lab) !void {
    try l.private();
    const dir = try l.temporary("unwound-age-mount");
    defer l.remove(dir);
    try l.chmod(dir, 0o700);
    try l.chown(dir, writer_id, writer_id);
    var worker = try l.spawn(
        &.{ "unshare", "--mount", "--fork", "--kill-child", try l.self(), "--writer", dir },
        .{ .stdin = .pipe, .stdout = .pipe },
    );
    var mounted = false;
    defer {
        if (worker.exit == null) {
            worker.signal(.KILL);
            _ = worker.wait(null) catch {};
        }
        if (mounted) l.unmount(dir) catch {};
    }
    var lines: netns.Lines = .{ .fd = worker.stdout.? };
    const ready = try lines.next(10_000);
    if (!mem.startsWith(u8, ready, "ready ")) return l.fail("writer_not_ready", .{ .line = ready });
    const pid = try std.fmt.parseInt(linux.pid_t, ready["ready ".len..], 10);
    try l.bind(dir, dir);
    try l.readOnly(dir);
    mounted = true;

    // Another bind of the directory, as an OCI root would get, is read-only too.
    const alias = try l.temporary("oci-age-alias");
    try l.bind(dir, alias);
    for (suffixes) |s| try denied(l, try path(l, alias, s));
    try l.unmount(alias);
    l.remove(alias);

    const remount = try std.process.run(l.gpa, l.io, .{
        .argv = &.{ "setpriv", "--bounding-set=-sys_admin", "mount", "-o", "remount,bind,rw", dir },
    });
    if (remount.term == .exited and remount.term.exited == 0)
        return l.fail("remounted", .{ .why = "root without CAP_SYS_ADMIN remounted age data" });
    for (suffixes) |s| try denied(l, try path(l, dir, s));
    const socket = try l.gpa.dupeSentinel(u8, try path(l, dir, "age.sock"), 0);
    switch (linux.errno(linux.unlink(socket))) {
        .ROFS => {},
        .SUCCESS => return l.fail(
            "socket_replaced",
            .{ .why = "root replaced the protected age socket" },
        ),
        else => |e| return l.fail("socket_unlink", .{ .errno = @backingInt(e) }),
    }

    try netns.writeAll(worker.stdin.?, "write\n");
    const written = try lines.next(10_000);
    if (!mem.eql(u8, written, "written")) return l.fail("writer_failed", .{ .line = written });
    for (suffixes) |s| {
        const p = try path(l, dir, s);
        std.Io.Dir.cwd().access(l.io, p, .{}) catch return l.fail("missing", .{ .path = p });
        try denied(l, p);
        try deniedWithoutPtrace(l, try l.gpa.print("/proc/{d}/root{s}/{s}", .{ pid, dir, s }));
    }
    const fds = try l.gpa.print("/proc/{d}/fd", .{pid});
    var held: usize = 0;
    var fd_dir = try std.Io.Dir.cwd().openDir(l.io, fds, .{ .iterate = true });
    defer fd_dir.close(l.io);
    var entries = fd_dir.iterate();
    while (try entries.next(l.io)) |entry| {
        const p = try path(l, fds, entry.name);
        var target: [4096]u8 = undefined;
        const n = std.Io.Dir.cwd().readLink(l.io, p, &target) catch continue;
        if (mem.find(u8, target[0..n], "age.db") == null) continue;
        try deniedWithoutPtrace(l, p);
        held += 1;
    }
    if (held == 0) return l.fail(
        "no_descriptor",
        .{ .why = "SQLite did not keep a database descriptor" },
    );

    try netns.writeAll(worker.stdin.?, "connect\n");
    const peer = try unixSocket(socket, .connect);
    defer netns.close(peer);
    var reply: [3]u8 = undefined;
    const got = linux.recvfrom(peer, &reply, reply.len, 0, null, null);
    if (linux.errno(got) != .SUCCESS or !mem.eql(u8, reply[0..got], "age"))
        return l.fail("socket_reply", .{ .why = "the age socket did not answer" });
    try netns.writeAll(worker.stdin.?, "close\n");
    const exit = try worker.wait(5000);
    if (exit != 0) return l.fail("writer_exit", .{ .exit = exit });
    l.log("pass", .{ .what = "private SQLite WAL and immutable socket" });
}

/// writer runs in its own mount namespace, where dir stays writable, as the
/// age writer would: its own user, not dumpable, holding the database open.
fn writer(l: Lab, dir: []const u8) !void {
    try l.private();
    if (setgroups(0, null) != 0 or std.c.setgid(writer_id) != 0 or std.c.setuid(writer_id) != 0)
        return l.fail("writer_privileges", .{ .why = "could not become the writer" });
    if (linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0) != 0)
        return l.fail("writer_dumpable", .{ .why = "PR_SET_DUMPABLE failed" });
    const listener = try unixSocket(
        try l.gpa.dupeSentinel(u8, try path(l, dir, "age.sock"), 0),
        .listen,
    );
    try netns.writeAll(1, try l.gpa.print("ready {d}\n", .{linux.getpid()}));
    var commands: netns.Lines = .{ .fd = 0 };
    try expect(l, &commands, "write");
    const db = try sqlite.Db.open(l.gpa, try path(l, dir, "age.db"), .read_write);
    const mode = try db.one("PRAGMA journal_mode=WAL", &.{});
    if (mode == null or !sqlite.eqlRow(mode.?, &.{.{ .text = "wal" }}))
        return l.fail("writer_wal", .{ .mode = mode });
    try db.exec("CREATE TABLE evidence (domain TEXT PRIMARY KEY)");
    try db.exec("INSERT INTO evidence VALUES ('example.com')");
    try netns.writeAll(1, "written\n");
    try expect(l, &commands, "connect");
    const rc = linux.accept4(listener, null, null, linux.SOCK.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return l.fail(
        "writer_accept",
        .{ .errno = @backingInt(linux.errno(rc)) },
    );
    const peer: linux.fd_t = @intCast(rc);
    try netns.writeAll(peer, "age");
    netns.close(peer);
    try expect(l, &commands, "close");
    db.close();
    netns.close(listener);
}

fn expect(l: Lab, commands: *netns.Lines, want: []const u8) !void {
    const got = try commands.next(30_000);
    if (!mem.eql(u8, got, want)) return l.fail("writer_command", .{ .want = want, .got = got });
}

/// probe runs under setpriv without CAP_SYS_PTRACE: opening p to write
/// must be refused as a permission, not succeed nor fail otherwise.
fn probe(l: Lab, p: []const u8) !void {
    const rc = linux.open(
        try l.gpa.dupeSentinel(u8, p, 0),
        .{ .ACCMODE = .WRONLY, .CLOEXEC = true },
        0,
    );
    switch (linux.errno(rc)) {
        .ACCES, .PERM => {},
        .SUCCESS => {
            netns.close(@intCast(rc));
            return l.fail("writable", .{ .why = "private writer path was writable", .path = p });
        },
        else => |e| return l.fail("probe", .{ .path = p, .errno = @backingInt(e) }),
    }
}

fn deniedWithoutPtrace(l: Lab, p: []const u8) !void {
    try l.run(&.{ "setpriv", "--bounding-set=-sys_ptrace", try l.self(), "--probe", p });
}

/// denied requires creating or writing p to fail as a read-only filesystem.
fn denied(l: Lab, p: []const u8) !void {
    const rc = linux.open(
        try l.gpa.dupeSentinel(u8, p, 0),
        .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true },
        0o600,
    );
    switch (linux.errno(rc)) {
        .ROFS => {},
        .SUCCESS => {
            netns.close(@intCast(rc));
            return l.fail("writable", .{ .why = "read-only view accepted a write", .path = p });
        },
        else => |e| return l.fail("denied", .{ .path = p, .errno = @backingInt(e) }),
    }
}

fn path(l: Lab, dir: []const u8, name: []const u8) ![]const u8 {
    return l.gpa.print("{s}/{s}", .{ dir, name });
}

fn unixSocket(p: [:0]const u8, how: enum { listen, connect }) !linux.fd_t {
    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    if (p.len >= address.path.len) return error.NameTooLong;
    @memcpy(address.path[0..p.len], p);
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: linux.fd_t = @intCast(rc);
    errdefer netns.close(fd);
    const size: linux.socklen_t = @sizeOf(linux.sockaddr.un);
    switch (how) {
        .listen => {
            if (linux.errno(linux.bind(
                fd,
                @ptrCast(&address),
                size,
            )) != .SUCCESS) return error.BindFailed;
            if (linux.errno(linux.listen(fd, 1)) != .SUCCESS) return error.ListenFailed;
        },
        .connect => if (linux.errno(linux.connect(fd, &address, size)) != .SUCCESS)
            return error.ConnectFailed,
    }
    return fd;
}
