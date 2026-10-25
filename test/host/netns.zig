//! netns runs Linux checks as root in private namespaces. A check enters
//! them through unshare, joins a peer namespace over a veth pair, starts
//! fixtures with their descriptors in place, and waits for their lines.
//! Children are forked by hand so a fixture can get descriptor 3 or a uid,
//! as the programs under test expect. See test/host/README.md.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const mem = std.mem;

const nosymfollow = 256; // MS_NOSYMFOLLOW, Linux 5.10

/// Lab is what a check's namespace work needs. name starts its log lines.
pub const Lab = struct {
    io: Io,
    gpa: Allocator,
    environ: std.process.Environ,
    name: []const u8,

    pub fn init(process: std.process.Init, name: []const u8) Lab {
        return .{
            .io = process.io,
            .gpa = process.arena.allocator(),
            .environ = process.minimal.environ,
            .name = name,
        };
    }

    /// log writes `NAME: {"event":EVENT,...}` to stderr, fields as JSON.
    pub fn log(l: Lab, event: []const u8, fields: anytype) void {
        var buf: [16 << 10]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        line(&w, l.name, event, fields) catch {};
        if (w.end == buf.len) buf[buf.len - 1] = '\n';
        writeAll(2, w.buffered()) catch {};
    }

    /// fail logs event and returns error.CheckFailed, for a broken assertion.
    pub fn fail(l: Lab, event: []const u8, fields: anytype) error{CheckFailed} {
        l.log(event, fields);
        return error.CheckFailed;
    }

    /// run runs argv, which must exit 0; what it printed is logged if not.
    pub fn run(l: Lab, argv: []const []const u8) !void {
        _ = try l.output(argv);
    }

    /// output runs argv, which must exit 0, and returns its standard output.
    pub fn output(l: Lab, argv: []const []const u8) ![]u8 {
        return try l.attempt(argv, .{}) orelse error.CommandFailed;
    }

    pub const Attempt = struct {
        cwd: ?[]const u8 = null,
        /// quiet logs nothing of a failure, for a command tried again.
        quiet: bool = false,
    };

    /// attempt runs argv and returns its standard output if it exits 0.
    pub fn attempt(l: Lab, argv: []const []const u8, o: Attempt) !?[]u8 {
        const r = try std.process.run(l.gpa, l.io, .{
            .argv = argv,
            .cwd = if (o.cwd) |dir| .{ .path = dir } else .inherit,
            .stdout_limit = .limited(4 << 20),
            .stderr_limit = .limited(64 << 10),
        });
        if (r.term == .exited and r.term.exited == 0) return r.stdout;
        if (!o.quiet) l.log(
            "command_failed",
            .{ .argv = argv, .stdout = r.stdout, .stderr = r.stderr },
        );
        return null;
    }

    /// environWith is this environment with each NAME=VALUE of set in place
    /// of its name's own.
    pub fn environWith(l: Lab, set: []const []const u8) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        next: for (l.environ.block.slice) |entry| {
            const e = mem.span(entry.?);
            const name = e[0 .. (mem.findScalar(u8, e, '=') orelse e.len) + 1];
            for (set) |s| if (mem.startsWith(u8, s, name)) continue :next;
            try out.append(l.gpa, e);
        }
        try out.appendSlice(l.gpa, set);
        return out.items;
    }

    /// create opens path anew for a child's output.
    pub fn create(l: Lab, path: []const u8) !linux.fd_t {
        const rc = linux.open(try l.z(path), .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
            .CLOEXEC = true,
        }, 0o644);
        try sys(rc, "create", path);
        return @intCast(rc);
    }

    /// enter runs this program again as args, in the new namespaces that
    /// unshare's flags name, and returns only on failure. The check's exit
    /// status is then its own, inside them.
    pub fn enter(l: Lab, flags: []const []const u8, args: []const []const u8) !noreturn {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.append(l.gpa, "unshare");
        try argv.appendSlice(l.gpa, flags);
        try argv.appendSlice(l.gpa, &.{ "--fork", try l.self() });
        try argv.appendSlice(l.gpa, args);
        return std.process.replace(l.io, .{ .argv = argv.items });
    }

    /// self is this program's path.
    pub fn self(l: Lab) ![]const u8 {
        return std.process.executablePathAlloc(l.io, l.gpa);
    }

    /// namespace names this process's namespace of kind (net, mnt, ...).
    pub fn namespace(l: Lab, kind: []const u8) ![]const u8 {
        var buf: [64]u8 = undefined;
        const path = try l.gpa.print("/proc/self/ns/{s}", .{kind});
        const n = try Io.Dir.cwd().readLink(l.io, path, &buf);
        return l.gpa.dupe(u8, buf[0..n]);
    }

    /// temporary makes a fresh directory, mode 0755, under /tmp.
    pub fn temporary(l: Lab, prefix: []const u8) ![]const u8 {
        var random: [8]u8 = undefined;
        l.io.random(&random);
        const path = try l.gpa.print(
            "/tmp/{s}-{s}",
            .{ prefix, &std.fmt.bytesToHex(random, .lower) },
        );
        try l.mkdir(path, 0o755);
        return path;
    }

    pub fn remove(l: Lab, path: []const u8) void {
        Io.Dir.cwd().deleteTree(l.io, path) catch |err|
            l.log("remove_failed", .{ .path = path, .@"error" = @errorName(err) });
    }

    pub fn write(l: Lab, path: []const u8, data: []const u8) !void {
        try Io.Dir.cwd().writeFile(l.io, .{ .sub_path = path, .data = data });
    }

    /// read reads a file to its end, as /proc's files, which claim no size, need.
    pub fn read(l: Lab, path: []const u8) ![]u8 {
        const file = try Io.Dir.cwd().openFile(l.io, path, .{});
        defer file.close(l.io);
        var buf: [4096]u8 = undefined;
        var reader = file.readerStreaming(l.io, &buf);
        return reader.interface.allocRemaining(l.gpa, .limited(64 << 20));
    }

    pub fn mkdir(l: Lab, path: []const u8, mode: u32) !void {
        try sys(linux.mkdir(try l.z(path), mode), "mkdir", path);
        try l.chmod(path, mode);
    }

    pub fn chmod(l: Lab, path: []const u8, mode: u32) !void {
        try sys(linux.chmod(try l.z(path), mode), "chmod", path);
    }

    pub fn chown(l: Lab, path: []const u8, uid: u32, gid: u32) !void {
        try sys(linux.chown(try l.z(path), uid, gid), "chown", path);
    }

    pub fn symlink(l: Lab, target: []const u8, path: []const u8) !void {
        try sys(linux.symlink(try l.z(target), try l.z(path)), "symlink", path);
    }

    /// copy copies a file's bytes to path, mode mode.
    pub fn copy(l: Lab, from: []const u8, to: []const u8, mode: u32) !void {
        try l.write(to, try l.read(from));
        try l.chmod(to, mode);
    }

    /// private stops this mount namespace's mounts propagating anywhere.
    pub fn private(l: Lab) !void {
        _ = l;
        try sys(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0), "private", "/");
    }

    pub fn tmpfs(l: Lab, path: []const u8) !void {
        try sys(linux.mount("tmpfs", try l.z(path), "tmpfs", 0, 0), "tmpfs", path);
    }

    pub fn bind(l: Lab, from: []const u8, to: []const u8) !void {
        try sys(linux.mount(try l.z(from), try l.z(to), null, linux.MS.BIND, 0), "bind", to);
    }

    /// readOnly remounts the bind at path read-only, with no devices, setuid
    /// or programs, and no symbolic links followed.
    pub fn readOnly(l: Lab, path: []const u8) !void {
        const flags = linux.MS.REMOUNT | linux.MS.BIND | linux.MS.RDONLY | linux.MS.NOSUID |
            linux.MS.NODEV | linux.MS.NOEXEC | nosymfollow;
        try sys(linux.mount(null, try l.z(path), null, flags, 0), "read-only", path);
    }

    pub fn unmount(l: Lab, path: []const u8) !void {
        try sys(linux.umount(try l.z(path)), "umount", path);
    }

    /// veth joins this namespace to v.peer, a new one, over a veth pair:
    /// "client" here and "peer" there.
    pub fn veth(l: Lab, v: Veth) !void {
        try l.run(&.{ "ip", "link", "set", "lo", "up" });
        try l.run(&.{ "ip", "netns", "add", v.peer });
        try l.run(&.{ "ip", "link", "add", "client", "type", "veth", "peer", "name", "peer" });
        try l.run(&.{ "ip", "link", "set", "peer", "netns", v.peer });
        try l.run(&.{ "ip", "addr", "add", v.client, "dev", "client" });
        try l.run(&.{ "ip", "link", "set", "client", "up" });
        for ([_][]const u8{ "all", "default", "client" }) |scope| try l.write(
            try l.gpa.print("/proc/sys/net/ipv4/conf/{s}/rp_filter", .{scope}),
            try l.gpa.print("{s}\n", .{v.rp_filter}),
        );
        if (v.gateway) |gateway| try l.run(&.{ "ip", "route", "add", "default", "via", gateway });
        for (v.addresses) |a|
            try l.run(&.{ "ip", "-n", v.peer, "addr", "add", a, "dev", "peer" });
        try l.run(&.{ "ip", "-n", v.peer, "link", "set", "peer", "up" });
        try l.run(&.{ "ip", "-n", v.peer, "link", "set", "lo", "up" });
        if (v.peer_default) try l.run(&.{
            "ip",
            "-n",
            v.peer,
            "route",
            "add",
            "default",
            "dev",
            "peer",
        });
    }

    /// dump shows the end of a fixture's log, for a failure.
    pub fn dump(l: Lab, path: []const u8) void {
        const text = l.read(path) catch |err| return l.log("log_unreadable", .{
            .path = path,
            .@"error" = @errorName(err),
        });
        const tail = text[text.len -| 8192..];
        l.log("log", .{ .path = path, .bytes = text.len });
        writeAll(2, tail) catch {};
        if (tail.len > 0 and tail[tail.len - 1] != '\n') writeAll(2, "\n") catch {};
    }

    /// spawn starts argv, found on PATH unless it names a path.
    pub fn spawn(l: Lab, argv: []const []const u8, s: Spawn) !Child {
        const path = try l.which(argv[0]);
        const args = try l.gpa.allocSentinel(?[*:0]const u8, argv.len, null);
        for (args, argv) |*a, v| a.* = try l.z(v);
        const envp: [*:null]const ?[*:0]const u8 = if (s.env) |env| blk: {
            const e = try l.gpa.allocSentinel(?[*:0]const u8, env.len, null);
            for (e, env) |*a, v| a.* = try l.z(v);
            break :blk e.ptr;
        } else @ptrCast(l.environ.block.slice.ptr);
        const cwd: ?[*:0]const u8 = if (s.cwd) |c| try l.z(c) else null;
        if (s.fds.len > max_fds) return error.TooManyDescriptors;

        var pipes: [3][2]linux.fd_t = @splat(.{ -1, -1 });
        defer for (pipes) |p| for (p) |fd| if (fd >= 0) close(fd);
        var nul: linux.fd_t = -1;
        defer if (nul >= 0) close(nul);
        var sources: [3 + max_fds]linux.fd_t = @splat(-1);
        for ([_]Stdio{ s.stdin, s.stdout, s.stderr }, 0..) |stdio, i| sources[i] = switch (stdio) {
            .inherit => -1,
            .fd => |fd| fd,
            .discard => blk: {
                if (nul < 0) {
                    const rc = linux.open("/dev/null", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
                    try sys(rc, "open", "/dev/null");
                    nul = @intCast(rc);
                }
                break :blk nul;
            },
            .pipe => blk: {
                try sys(linux.pipe2(&pipes[i], .{ .CLOEXEC = true }), "pipe", argv[0]);
                break :blk pipes[i][@intFromBool(i != 0)];
            },
        };
        for (s.fds, 3..) |fd, i| sources[i] = fd;
        var report: [2]linux.fd_t = undefined;
        try sys(linux.pipe2(&report, .{ .CLOEXEC = true }), "pipe", argv[0]);
        defer close(report[0]);

        const rc = linux.fork();
        if (linux.errno(rc) != .SUCCESS) {
            close(report[1]);
            return error.ForkFailed;
        }
        if (rc == 0) exec(path, args.ptr, envp, cwd, s, sources[0 .. 3 + s.fds.len], report[1]);
        close(report[1]);
        var child: Child = .{ .pid = @intCast(rc), .group = s.group };
        for (&pipes, 0..) |*p, i| if (p[0] >= 0) {
            // Keep the parent's end; the deferred close takes the child's.
            if (i == 0) {
                child.stdin = p[1];
                p[1] = -1;
            } else if (i == 1) {
                child.stdout = p[0];
                p[0] = -1;
            } else {
                child.stderr = p[0];
                p[0] = -1;
            }
        };
        var failed: [4]u8 = undefined;
        if (linux.read(report[0], &failed, failed.len) == failed.len) {
            _ = child.wait(null) catch {};
            l.log("exec_failed", .{ .path = path, .errno = mem.readInt(u32, &failed, .little) });
            return error.ExecFailed;
        }
        return child;
    }

    /// which finds name on PATH, or takes it as a path if it has a slash.
    pub fn which(l: Lab, name: []const u8) ![:0]const u8 {
        if (mem.findScalar(u8, name, '/') != null) return l.z(name);
        const path = l.environ.getPosix(
            "PATH",
        ) orelse "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        var dirs = mem.tokenizeScalar(u8, path, ':');
        while (dirs.next()) |dir| {
            const candidate = try l.gpa.printSentinel("{s}/{s}", .{ dir, name }, 0);
            if (linux.errno(linux.access(candidate, linux.X_OK)) == .SUCCESS) return candidate;
        }
        l.log("not_found", .{ .program = name });
        return error.FileNotFound;
    }

    fn z(l: Lab, s: []const u8) ![:0]const u8 {
        return l.gpa.dupeSentinel(u8, s, 0);
    }
};

pub const Veth = struct {
    peer: []const u8,
    /// client is this end's address and prefix.
    client: []const u8,
    /// addresses go on the peer's end.
    addresses: []const []const u8,
    /// gateway, if given, is this namespace's default route.
    gateway: ?[]const u8 = null,
    /// peer_default routes everything in the peer namespace out its end.
    peer_default: bool = false,
    /// rp_filter is reverse-path filtering here; werewolf leaves it off.
    rp_filter: []const u8 = "0",
};

pub const Stdio = union(enum) { inherit, discard, pipe, fd: linux.fd_t };

pub const max_fds = 8;

pub const Spawn = struct {
    stdin: Stdio = .inherit,
    stdout: Stdio = .inherit,
    stderr: Stdio = .inherit,
    /// fds become the child's descriptors 3, 4, and so on.
    fds: []const linux.fd_t = &.{},
    /// uid, if given, drops every group and runs the child as uid:uid.
    uid: ?u32 = null,
    /// env, NAME=VALUE strings, replaces the environment.
    env: ?[]const []const u8 = null,
    cwd: ?[]const u8 = null,
    /// group gives the child a process group of its own, so that stop
    /// ends what it started too.
    group: bool = false,
};

/// exec places sources at 0, 1, 2, 3... and runs path. It runs between fork
/// and exec, so it makes system calls alone; report learns why it failed.
fn exec(
    path: [*:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    cwd: ?[*:0]const u8,
    s: Spawn,
    sources: []const linux.fd_t,
    report: linux.fd_t,
) noreturn {
    // Lift every source above the targets first, so none overwrites another.
    var lifted: [3 + max_fds]linux.fd_t = @splat(-1);
    for (sources, 0..) |fd, i| {
        if (fd < 0) continue;
        const rc = linux.fcntl(fd, linux.F.DUPFD_CLOEXEC, 64);
        if (linux.errno(rc) != .SUCCESS) bail(report, rc);
        lifted[i] = @intCast(rc);
    }
    for (lifted[0..sources.len], 0..) |fd, i| {
        if (fd < 0) continue;
        const rc = linux.dup2(fd, @intCast(i));
        if (linux.errno(rc) != .SUCCESS) bail(report, rc);
    }
    if (s.group) {
        const rc = linux.setpgid(0, 0);
        if (linux.errno(rc) != .SUCCESS) bail(report, rc);
    }
    if (cwd) |dir| {
        const rc = linux.chdir(dir);
        if (linux.errno(rc) != .SUCCESS) bail(report, rc);
    }
    if (s.uid) |id| {
        const none: [0]linux.gid_t = .{};
        var rc = linux.setgroups(0, &none);
        if (linux.errno(rc) == .SUCCESS) rc = linux.setgid(id);
        if (linux.errno(rc) == .SUCCESS) rc = linux.setuid(id);
        if (linux.errno(rc) != .SUCCESS) bail(report, rc);
    }
    bail(report, linux.execve(path, argv, envp));
}

fn bail(report: linux.fd_t, rc: usize) noreturn {
    var errno: [4]u8 = undefined;
    mem.writeInt(u32, &errno, @intCast(@backingInt(linux.errno(rc))), .little);
    _ = linux.write(report, &errno, errno.len);
    linux.exit_group(127);
}

pub const Child = struct {
    pid: linux.pid_t,
    stdin: ?linux.fd_t = null,
    stdout: ?linux.fd_t = null,
    stderr: ?linux.fd_t = null,
    /// exit is the exit code, or minus the signal, once reaped.
    exit: ?i32 = null,
    /// group is set when the child leads a process group of its own.
    group: bool = false,

    /// wait waits up to ms (null: for ever) for the child to exit, and
    /// returns its exit, or null while it runs.
    pub fn wait(c: *Child, ms: ?u32) !?i32 {
        if (c.exit) |e| return e;
        const deadline = if (ms) |n| now() + n else 0;
        while (true) {
            var status: u32 = 0;
            const flags: u32 = if (ms == null) 0 else linux.W.NOHANG;
            const rc = linux.wait4(c.pid, @ptrCast(&status), flags, null);
            switch (linux.errno(rc)) {
                .SUCCESS => if (rc != 0) {
                    c.exit = if (linux.W.IFEXITED(status))
                        linux.W.EXITSTATUS(status)
                    else
                        -@as(i32, @intCast(status & 0x7f));
                    return c.exit;
                },
                .INTR => continue,
                else => return error.WaitFailed,
            }
            if (now() >= deadline) return null;
            nap(10);
        }
    }

    pub fn signal(c: *Child, sig: linux.SIG) void {
        if (c.exit == null) _ = linux.kill(c.pid, sig);
    }

    /// stop ends the child: TERM, then KILL if it outlives a few seconds.
    pub fn stop(c: *Child) void {
        c.signal(.TERM);
        if (c.wait(5000) catch null == null) {
            c.signal(.KILL);
            _ = c.wait(null) catch {};
        }
        c.sweep();
    }

    /// sweep kills what is left of the child's own process group.
    pub fn sweep(c: *Child) void {
        if (c.group) _ = linux.kill(-c.pid, .KILL);
    }

    /// closeStdin closes the child's standard input, an end of requests.
    pub fn closeStdin(c: *Child) void {
        if (c.stdin) |fd| close(fd);
        c.stdin = null;
    }
};

/// Lines reads lines from a descriptor, each within a deadline.
pub const Lines = struct {
    fd: linux.fd_t,
    buf: [256 << 10]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    /// next returns the next line, without its newline, waiting up to ms.
    /// It stays valid until the next call.
    pub fn next(r: *Lines, ms: u32) ![]const u8 {
        const deadline = now() + ms;
        while (true) {
            if (mem.findScalar(u8, r.buf[r.start..r.end], '\n')) |n| {
                defer r.start += n + 1;
                return r.buf[r.start .. r.start + n];
            }
            if (r.start > 0) {
                @memmove(r.buf[0 .. r.end - r.start], r.buf[r.start..r.end]);
                r.end -= r.start;
                r.start = 0;
            }
            if (r.end == r.buf.len) return error.LineTooLong;
            const left = deadline - now();
            if (left <= 0) return error.Timeout;
            var fds = [1]linux.pollfd{.{ .fd = r.fd, .events = linux.POLL.IN, .revents = 0 }};
            const polled = linux.poll(&fds, 1, @intCast(left));
            if (linux.errno(polled) == .INTR) continue;
            if (linux.errno(polled) != .SUCCESS) return error.PollFailed;
            if (polled == 0) return error.Timeout;
            const got = linux.read(r.fd, r.buf[r.end..].ptr, r.buf.len - r.end);
            if (linux.errno(got) == .INTR) continue;
            if (linux.errno(got) != .SUCCESS) return error.ReadFailed;
            if (got == 0) return error.EndOfStream;
            r.end += got;
        }
    }

    /// ready waits up to ms for a fixture's `ready` line.
    pub fn ready(r: *Lines, ms: u32) !void {
        const got = try r.next(ms);
        if (!mem.eql(u8, mem.trim(u8, got, " \r"), "ready")) return error.NotReady;
    }
};

// Raw IPv4 sockets, for fixtures and for children between fork and exit.

/// address is an IPv4 address in text, with port.
pub fn address(text: []const u8, port: u16) !linux.sockaddr.in {
    const ip = try Io.net.Ip4Address.parse(text, port);
    return .{ .port = mem.nativeToBig(u16, port), .addr = @bitCast(ip.bytes) };
}

/// socket opens an IPv4 socket of kind (linux.SOCK.DGRAM or STREAM).
pub fn socket(kind: u32) !linux.fd_t {
    const rc = linux.socket(linux.AF.INET, kind | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    return @intCast(rc);
}

/// limit bounds each send and receive on fd, and a stream's connect, to ms.
pub fn limit(fd: linux.fd_t, ms: u32) void {
    const t: linux.timeval = .{ .sec = ms / 1000, .usec = @as(i64, ms % 1000) * 1000 };
    for ([_]u32{ linux.SO.RCVTIMEO, linux.SO.SNDTIMEO }) |opt|
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, opt, @ptrCast(&t), @sizeOf(linux.timeval));
}

/// listen binds fd to text:port, as a stream listener if backlog is given.
pub fn listen(fd: linux.fd_t, text: []const u8, port: u16, backlog: ?u31) !void {
    const one: c_int = 1;
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&one), @sizeOf(c_int));
    const at = try address(text, port);
    if (linux.errno(linux.bind(fd, @ptrCast(&at), @sizeOf(@TypeOf(at)))) != .SUCCESS)
        return error.BindFailed;
    if (backlog) |n| if (linux.errno(linux.listen(fd, n)) != .SUCCESS) return error.ListenFailed;
}

/// readExact fills buf from a stream, or fails on its end or an error.
pub fn readExact(fd: linux.fd_t, buf: []u8) !void {
    var at: usize = 0;
    while (at < buf.len) {
        const rc = linux.read(fd, buf[at..].ptr, buf.len - at);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc == 0) return error.EndOfStream else {
                at += rc;
            },
            .INTR => {},
            else => return error.ReadFailed,
        }
    }
}

/// writeAll writes all of data to fd.
pub fn writeAll(fd: linux.fd_t, data: []const u8) !void {
    var at: usize = 0;
    while (at < data.len) {
        const rc = linux.write(fd, data[at..].ptr, data.len - at);
        switch (linux.errno(rc)) {
            .SUCCESS => at += rc,
            .INTR => {},
            else => return error.WriteFailed,
        }
    }
}

/// now is the monotonic clock in milliseconds.
pub fn now() i64 {
    var t: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &t);
    return @as(i64, t.sec) * 1000 + @divTrunc(@as(i64, t.nsec), std.time.ns_per_ms);
}

/// nap sleeps ms milliseconds, with no Io: forked children use it too.
pub fn nap(ms: u32) void {
    var t: linux.timespec = .{
        .sec = ms / 1000,
        .nsec = @as(isize, ms % 1000) * std.time.ns_per_ms,
    };
    while (linux.errno(linux.nanosleep(&t, &t)) == .INTR) {}
}

pub fn close(fd: linux.fd_t) void {
    _ = linux.close(fd);
}

fn sys(rc: usize, what: []const u8, path: []const u8) !void {
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |e| {
            var buf: [512]u8 = undefined;
            const text = std.mem.print(
                &buf,
                "netns: {s} {s}: {t}\n",
                .{ what, path, e },
            ) catch "";
            writeAll(2, text) catch {};
            return error.SystemCallFailed;
        },
    }
}

fn line(w: *Io.Writer, program: []const u8, event: []const u8, fields: anytype) !void {
    try w.print("{s}: {{\"event\":", .{program});
    try std.json.Stringify.value(event, .{}, w);
    inline for (comptime std.meta.fieldNames(@TypeOf(fields))) |name| {
        try w.print(",\"{s}\":", .{name});
        try std.json.Stringify.value(@field(fields, name), .{}, w);
    }
    try w.writeAll("}\n");
}

test "log lines are the program's name and one JSON object" {
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try line(&w, "check-dns", "pass", .{ .checks = 3, .why = "a \"quoted\" reason" });
    try std.testing.expectEqualStrings(
        "check-dns: {\"event\":\"pass\",\"checks\":3,\"why\":\"a \\\"quoted\\\" reason\"}\n",
        w.buffered(),
    );
}
