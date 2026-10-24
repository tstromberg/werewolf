//! Local syslog, with a receiver that cannot reach its file worker's logs.
const std = @import("std");
const sandbox = @import("sandbox");
const p = @import("policy.zig");
const Store = @import("store.zig").Store;
const linux = std.os.linux;
const Io = std.Io;
const sys = sandbox.sys;

const receiver_id = 75;
const writer_id = 76;
const socket_path = "/run/syslog/dev-log";
const log_path = "/data/log";
var stopping: std.atomic.Value(bool) = .init(false);

fn stop(_: linux.SIG) callconv(.c) void {
    stopping.store(true, .monotonic);
}

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var buf: [256]u8 = undefined;
        const line = std.mem.print(&buf, "syslogd: setup failed: {s} ({s}: {t})\n", .{
            @errorName(err), sandbox.failed, sandbox.failed_errno,
        }) catch "syslogd: setup failed\n";
        _ = linux.write(2, line.ptr, line.len);
        linux.exit_group(1);
    };
}

fn run(init: std.process.Init) !void {
    if (linux.getuid() != 0) return error.RootSetupRequired;
    _ = try sys(linux.close_range(3, std.math.maxInt(i32), .{
        .UNSHARE = false,
        .CLOEXEC = false,
    }), "close inherited files");
    const config = try readConfig();
    const socket_dir = try directory("/run/syslog", 0, 0o755);
    // Lock the stable, root-owned directory, so a second daemon cannot
    // unlink the first one's socket. Only the receiver keeps this lock.
    _ = try sys(linux.flock(socket_dir, 2 | 4), "lock socket directory");
    const ready = try statusFile(socket_dir, "ready");
    const health = try statusFile(socket_dir, "status");
    const console = openDevice("/dev/console", .WRONLY, 5, 1) catch -1;
    const kernel = openDevice("/dev/kmsg", .RDONLY, 1, 11) catch b: {
        consoleWrite(console, "syslogd: kernel log unavailable\n");
        break :b -1;
    };
    const socket: i32 = @intCast(try sys(
        linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0),
        "syslog socket",
    ));
    const yes: i32 = 1;
    _ = try sys(
        linux.setsockopt(
            socket,
            linux.SOL.SOCKET,
            linux.SO.PASSCRED,
            std.mem.asBytes(&yes),
            @sizeOf(i32),
        ),
        "sender credentials",
    );
    // Its parent directory is not writable by any service or either worker.
    const unlinked = linux.unlink(socket_path);
    if (linux.errno(unlinked) != .SUCCESS and linux.errno(unlinked) != .NOENT)
        return error.UnsafeSocketPath;
    var address: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(address.path[0..socket_path.len], socket_path);
    _ = try sys(
        linux.bind(socket, @ptrCast(&address), @intCast(2 + socket_path.len + 1)),
        "bind syslog socket",
    );
    _ = try sys(
        linux.fchmodat2(linux.AT.FDCWD, socket_path, 0o666, linux.AT.SYMLINK_NOFOLLOW),
        "socket permissions",
    );

    var writer: i32 = -1;
    var child: linux.pid_t = -1;
    if (config.file) {
        const log_dir = persistentDirectory() catch |err| b: {
            var buf: [192]u8 = undefined;
            const line = std.mem.print(
                &buf,
                "syslogd: file output unavailable ({s}); console only\n",
                .{@errorName(err)},
            ) catch
                "syslogd: file output unavailable; console only\n";
            consoleWrite(console, line);
            break :b null;
        };
        if (log_dir) |dir_fd| {
            var store = try Store.init(
                init.io,
                init.arena.allocator(),
                .{ .handle = dir_fd },
                config.budget,
            );
            var pair: [2]i32 = undefined;
            _ = try sys(
                linux.socketpair(
                    linux.AF.UNIX,
                    linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
                    0,
                    &pair,
                ),
                "writer channel",
            );
            const parent = linux.getpid();
            const forked = try sys(linux.fork(), "fork file worker");
            if (forked == 0) {
                sandbox.tieTo(parent);
                try sandbox.closeAllBut(&.{ pair[1], dir_fd });
                try sandbox.dropTo(writer_id, log_path);
                _ = try sys(
                    linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0),
                    "writer dumpability",
                );
                try sandbox.landlock(&.{.{ .fd = dir_fd, .access = sandbox.own_dir }}, &.{});
                try signals();
                try confineWriter(dir_fd, pair[1]);
                writeLogs(&store, pair[1]) catch linux.exit_group(1);
                linux.exit_group(0);
            }
            child = @intCast(forked);
            writer = pair[0];
            _ = linux.close(pair[1]);
            _ = linux.close(dir_fd);
            // The receiver does not retain even a copy of log-file buffers.
            store.deinit(init.arena.allocator());
        }
    }
    var keep: [7]i32 = .{ socket, socket_dir, ready, health, -1, -1, -1 };
    var nkeep: usize = 4;
    if (console >= 0) {
        keep[nkeep] = console;
        nkeep += 1;
    }
    if (writer >= 0) {
        keep[nkeep] = writer;
        nkeep += 1;
    }
    if (kernel >= 0) {
        keep[nkeep] = kernel;
        nkeep += 1;
    }
    try sandbox.closeAllBut(keep[0..nkeep]);
    try sandbox.dropTo(receiver_id, "/var/empty");
    _ = try sys(
        linux.prctl(@backingInt(linux.PR.SET_DUMPABLE), 0, 0, 0, 0),
        "receiver dumpability",
    );
    try sandbox.landlock(&.{}, &.{});
    try signals();
    const fds: Endpoints = .{
        .pid = linux.getpid(),
        .socket = socket,
        .console = console,
        .ready = ready,
        .health = health,
        .kernel = kernel,
        .writer = writer,
        .child = child,
        .echo = config.console or (config.file and writer < 0),
        .file_requested = config.file,
    };
    try confineReceiver(fds);
    receive(fds);
    linux.exit_group(0);
}

fn statusFile(dir: i32, name: [:0]const u8) !i32 {
    const fd: i32 = @intCast(try sys(linux.openat(dir, name, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    }, 0o644), "open status file"));
    errdefer _ = linux.close(fd);
    const st = try stat(fd);
    if (st.uid != 0 or st.nlink != 1 or st.mode & 0o022 != 0 or
        st.mode & linux.S.IFMT != linux.S.IFREG) return error.UnsafeStatusFile;
    _ = try sys(linux.ftruncate(fd, 0), "clear status file");
    return fd;
}

fn openDevice(path: [:0]const u8, access: std.posix.ACCMODE, major: u32, minor: u32) !i32 {
    const fd: i32 = @intCast(try sys(linux.open(path, .{
        .ACCMODE = access,
        .NONBLOCK = true,
        .NOFOLLOW = true,
        .NOCTTY = true,
        .CLOEXEC = true,
    }, 0), "open logging device"));
    errdefer _ = linux.close(fd);
    const st = try stat(fd);
    if (st.mode & linux.S.IFMT != linux.S.IFCHR or
        st.rdev_major != major or st.rdev_minor != minor) return error.UnsafeDevice;
    return fd;
}

fn readConfig() !p.Config {
    for ([_][:0]const u8{ "/run/config/syslog.conf", "/etc/werewolf/syslog.conf" }) |path| {
        const rc = linux.open(path, .{
            .ACCMODE = .RDONLY,
            .NOFOLLOW = true,
            .NONBLOCK = true,
            .CLOEXEC = true,
        }, 0);
        if (linux.errno(rc) == .NOENT) continue;
        const fd: i32 = @intCast(try sys(rc, "open syslog configuration"));
        defer _ = linux.close(fd);
        const st = try stat(fd);
        if (st.uid != 0 or st.nlink != 1 or st.mode & linux.S.IFMT != linux.S.IFREG or
            st.mode & 0o022 != 0 or st.size > 4096) return error.UnsafeConfig;
        var buf: [4097]u8 = undefined;
        const n = try sys(linux.read(fd, &buf, buf.len), "read syslog configuration");
        if (n != st.size) return error.BadConfig;
        return p.Config.parse(buf[0..n]);
    }
    return .{};
}

fn stat(fd: i32) !linux.Statx {
    var st: linux.Statx = undefined;
    _ = try sys(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{
        .TYPE = true,
        .MODE = true,
        .NLINK = true,
        .UID = true,
        .SIZE = true,
    }, &st), "stat");
    return st;
}

fn directory(path: [:0]const u8, owner: u32, mode: u32) !i32 {
    const made = linux.mkdirat(linux.AT.FDCWD, path, mode);
    if (linux.errno(made) != .SUCCESS and linux.errno(made) != .EXIST) return error.NoDirectory;
    const fd: i32 = @intCast(try sys(linux.open(path, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0), "open private directory"));
    errdefer _ = linux.close(fd);
    const st = try stat(fd);
    if ((st.uid != 0 and st.uid != owner) or st.mode & 0o022 != 0)
        return error.UnsafeDirectory;
    _ = try sys(linux.fchmod(fd, mode), "private directory permissions");
    _ = try sys(linux.fchown(fd, owner, owner), "private directory owner");
    return fd;
}

fn persistentDirectory() !?i32 {
    const data: i32 = @intCast(try sys(linux.open("/data", .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0), "open data directory"));
    defer _ = linux.close(data);
    // Only f_type is needed; leave room for every supported 64-bit statfs.
    var fs: [32]usize = @splat(0);
    _ = try sys(linux.syscall2(.fstatfs, @intCast(data), @intFromPtr(&fs)), "data filesystem");
    if (fs[0] == 0x01021994 or fs[0] == 0x858458f6) return error.VolatileData;
    const dir_fd = try directory(log_path, writer_id, 0o700);
    errdefer _ = linux.close(dir_fd);
    _ = try sys(linux.flock(dir_fd, 2 | 4), "lock log directory");
    _ = try sys(linux.fsync(data), "sync log directory entry");
    return dir_fd;
}

fn signals() !void {
    const action: linux.Sigaction = .{
        .handler = .{ .handler = stop },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    for ([_]linux.SIG{ .TERM, .INT }) |sig|
        _ = try sys(linux.sigaction(sig, &action, null), "shutdown handler");
}

const Endpoints = struct {
    pid: linux.pid_t,
    socket: i32,
    console: i32,
    ready: i32,
    health: i32,
    kernel: i32,
    writer: i32,
    child: i32,
    echo: bool,
    file_requested: bool,
};

fn confineReceiver(fds: Endpoints) !void {
    var f: sandbox.Filter = .{};
    f.allowArg("recvmsg", 0, @intCast(fds.socket));
    f.allowArg("write", 0, @intCast(fds.ready));
    f.allowArg("ftruncate", 0, @intCast(fds.ready));
    f.allowArg("pwrite64", 0, @intCast(fds.health));
    f.allowArg("ftruncate", 0, @intCast(fds.health));
    if (fds.kernel >= 0) f.allowArg("read", 0, @intCast(fds.kernel));
    if (fds.console >= 0) f.allowArg("write", 0, @intCast(fds.console));
    if (fds.writer >= 0) {
        f.allowArg("sendto", 0, @intCast(fds.writer));
        f.allowArg("recvfrom", 0, @intCast(fds.writer));
        f.allowArg("shutdown", 0, @intCast(fds.writer));
        f.allowArg("wait4", 0, @intCast(fds.child));
    }
    inline for (.{
        "poll",
        "ppoll",
        "clock_gettime",
        "close",
        "rt_sigreturn",
        "restart_syscall",
        "exit",
        "exit_group",
    }) |call| f.allow(call);
    try f.install();
}

fn confineWriter(dir: i32, channel: i32) !void {
    var f: sandbox.Filter = .{};
    f.allowArg("openat", 0, @intCast(dir));
    f.allowArg("unlinkat", 0, @intCast(dir));
    f.allowTwo("renameat2", 0, @intCast(dir), 2, @intCast(dir));
    f.allowArg("sendto", 0, @intCast(channel));
    f.allowArg("recvfrom", 0, @intCast(channel));
    inline for (.{
        "read",
        "readv",
        "write",
        "writev",
        "pread64",
        "preadv",
        "pwrite64",
        "pwritev",
        "close",
        "fstat",
        "statx",
        "newfstatat",
        "getdents64",
        "lseek",
        "fsync",
        "fdatasync",
        "ftruncate",
        "fcntl",
        "poll",
        "ppoll",
        "clock_gettime",
        "futex",
        "rt_sigreturn",
        "restart_syscall",
        "exit",
        "exit_group",
    }) |call| f.allow(call);
    try f.install();
}

fn seconds(clock: linux.clockid_t) i64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(clock, &ts)) != .SUCCESS) linux.exit_group(1);
    return ts.sec;
}

const Stats = extern struct { ready: u64 = 0, healthy: u64 = 0, dropped: u64 = 0, errors: u64 = 0 };

fn writeLogs(store: *Store, channel: i32) !void {
    var stats: Stats = .{};
    var available = true;
    store.start(seconds(.REALTIME)) catch {
        stats.errors +|= 1;
        available = false;
    };
    stats.ready = 1;
    stats.healthy = @intFromBool(available);
    var buffer: [p.max_record + 1]u8 = undefined;
    var last_sync = seconds(.BOOTTIME);
    var last_maintain = last_sync - 60;
    while (true) {
        const now = seconds(.BOOTTIME);
        if (now != last_sync) {
            store.sync() catch {
                stats.errors +|= 1;
                available = false;
                stats.healthy = 0;
            };
            last_sync = now;
        }
        if (now - last_maintain >= 60) {
            if (available) {
                store.maintain(seconds(.REALTIME)) catch {
                    stats.errors +|= 1;
                    available = false;
                    stats.healthy = 0;
                };
            } else {
                available = true;
                store.start(seconds(.REALTIME)) catch {
                    stats.errors +|= 1;
                    available = false;
                };
                stats.healthy = @intFromBool(available);
            }
            last_maintain = now;
        }
        _ = linux.sendto(
            channel,
            std.mem.asBytes(&stats),
            @sizeOf(Stats),
            linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL,
            null,
            0,
        );
        var pollfd: [1]linux.pollfd = .{.{ .fd = channel, .events = linux.POLL.IN, .revents = 0 }};
        const polled = linux.poll(&pollfd, 1, 1000);
        if (linux.errno(polled) == .INTR) continue;
        _ = try sys(polled, "writer poll");
        if (polled == 0) continue;
        const rc = linux.recvfrom(channel, &buffer, buffer.len, linux.MSG.DONTWAIT |
            linux.MSG.TRUNC, null, null);
        if (linux.errno(rc) == .AGAIN or linux.errno(rc) == .INTR) continue;
        const n = try sys(rc, "writer receive");
        if (n == 0) break;
        if (n > p.max_record or !p.validRecord(buffer[0..n])) return error.BadRecord;
        if (!available) {
            stats.dropped +|= 1;
            continue;
        }
        store.append(buffer[0..n], seconds(.REALTIME)) catch |err| {
            stats.healthy = 0;
            if (err != error.StorageFull and err != error.NamesExhausted) {
                available = false;
                stats.errors +|= 1;
            }
            stats.dropped +|= 1;
            continue;
        };
        stats.healthy = 1;
    }
    if (available) try store.finish(seconds(.REALTIME)) else try store.sync();
    // Give the receiver a bounded chance to drain stale counters before
    // delivering the final totals, including records dropped during stop.
    for (0..100) |_| {
        const sent = linux.sendto(
            channel,
            std.mem.asBytes(&stats),
            @sizeOf(Stats),
            linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL,
            null,
            0,
        );
        if (linux.errno(sent) != .AGAIN) break;
        var fd: [1]linux.pollfd = .{.{ .fd = channel, .events = linux.POLL.OUT, .revents = 0 }};
        _ = linux.poll(&fd, 1, 10);
    }
}

const Received = struct { length: usize, credentials: ?p.Credentials };

fn datagram(socket: i32, buf: *[p.max_input]u8) !?Received {
    var iov: [1]std.posix.iovec = .{.{ .base = buf, .len = buf.len }};
    // Enough for all 253 SCM_RIGHTS descriptors plus credentials. Every
    // received descriptor is closed, even on a truncated or refused message.
    var control: [2048]u8 align(8) = undefined;
    var msg: linux.msghdr = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    const rc = linux.recvmsg(socket, &msg, linux.MSG.DONTWAIT | linux.MSG.CMSG_CLOEXEC);
    if (linux.errno(rc) == .AGAIN or linux.errno(rc) == .INTR) return null;
    const n = try sys(rc, "receive syslog");
    var cred: ?p.Credentials = null;
    var invalid = msg.flags & (linux.MSG.TRUNC | linux.MSG.CTRUNC) != 0;
    var at: usize = 0;
    while (at + @sizeOf(linux.cmsghdr) <= msg.controllen) {
        const h: *align(1) const linux.cmsghdr = @ptrCast(&control[at]);
        if (h.len < @sizeOf(linux.cmsghdr) or h.len > msg.controllen - at) {
            invalid = true;
            break;
        }
        const bytes = control[at + @sizeOf(linux.cmsghdr) .. at + h.len];
        if (h.level == linux.SOL.SOCKET and h.type == linux.SCM.RIGHTS) {
            var pos: usize = 0;
            while (pos + 4 <= bytes.len) : (pos += 4) {
                const fd = std.mem.readInt(i32, bytes[pos..][0..4], .native);
                _ = linux.close(fd);
            }
            invalid = true;
        } else if (h.level == linux.SOL.SOCKET and h.type == linux.SCM.CREDENTIALS and
            bytes.len == 12 and cred == null)
        {
            cred = .{
                .pid = std.mem.readInt(i32, bytes[0..4], .native),
                .uid = std.mem.readInt(u32, bytes[4..8], .native),
                .gid = std.mem.readInt(u32, bytes[8..12], .native),
            };
        } else invalid = true;
        at += std.mem.alignForward(usize, h.len, @sizeOf(usize));
    }
    return .{ .length = n, .credentials = if (invalid) null else cred };
}

fn consoleWrite(console: i32, bytes: []const u8) void {
    if (console >= 0) _ = linux.write(console, bytes.ptr, bytes.len);
}

fn flush(queue: *p.Queue, console: i32) void {
    if (console < 0 or queue.pending().len == 0) return;
    const bytes = queue.pending();
    const rc = linux.write(console, bytes.ptr, bytes.len);
    if (linux.errno(rc) == .SUCCESS) queue.consumed(rc);
}

const Receiver = struct {
    queue: p.Queue = .{},
    limiter: p.Limiter = .{},
    refused: u64 = 0,
    console_lost: u64 = 0,
    file_lost: u64 = 0,
    kernel_lost: u64 = 0,
    kernel_errors: u64 = 0,
    next_sequence: u64 = 0,
    stats: Stats = .{},

    fn deliver(s: *Receiver, fds: Endpoints, line: []const u8, echo: bool) void {
        if (echo and !s.queue.append(line)) s.console_lost +|= 1;
        if (fds.writer >= 0) {
            const sent = linux.sendto(
                fds.writer,
                line.ptr,
                line.len,
                linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL,
                null,
                0,
            );
            if (linux.errno(sent) != .SUCCESS or sent != line.len) s.file_lost +|= 1;
        }
    }

    fn application(
        s: *Receiver,
        fds: Endpoints,
        input: *[p.max_input]u8,
        output: []u8,
    ) !bool {
        const got = try datagram(fds.socket, input) orelse return false;
        const cred = got.credentials orelse {
            s.refused +|= 1;
            return true;
        };
        if (!s.limiter.admit(cred, seconds(.BOOTTIME))) {
            s.refused +|= 1;
            return true;
        }
        const line = p.record(output, seconds(.REALTIME), cred, input[0..got.length]) catch {
            s.refused +|= 1;
            return true;
        };
        s.deliver(fds, line, fds.echo);
        return true;
    }

    fn floods(s: *Receiver, fds: Endpoints, now: i64) void {
        var buf: [384]u8 = undefined;
        for (0..4) |_| {
            const flood = s.limiter.notice(now) orelse break;
            const line = p.floodRecord(&buf, seconds(.REALTIME), flood) catch unreachable;
            // Receiver-generated notices bypass sender limits; their own limit
            // bounds output even when many UIDs or PIDs flood at once.
            s.deliver(fds, line, fds.echo);
        }
    }

    fn kernel(s: *Receiver, fds: Endpoints) bool {
        var input: [p.max_kernel_input]u8 = undefined;
        var output: [p.max_record]u8 = undefined;
        for (0..64) |_| {
            const rc = linux.read(fds.kernel, &input, input.len);
            switch (linux.errno(rc)) {
                .SUCCESS => if (rc == 0) break,
                .AGAIN => break,
                .INTR => continue,
                .PIPE => {
                    // The next sequence number measures overwritten records.
                    s.kernel_errors +|= 1;
                    continue;
                },
                else => {
                    s.kernel_errors +|= 1;
                    _ = linux.close(fds.kernel);
                    return false;
                },
            }
            const entry = p.Kernel.parse(input[0..rc]) catch {
                s.kernel_errors +|= 1;
                continue;
            };
            if (entry.sequence < s.next_sequence) {
                s.kernel_errors +|= 1;
                continue;
            }
            s.kernel_lost +|= entry.sequence - s.next_sequence;
            s.next_sequence = entry.sequence +| 1;
            const line = p.kernelRecord(&output, seconds(.REALTIME), entry) catch {
                s.kernel_errors +|= 1;
                continue;
            };
            // Kernel input never goes back to the console or kernel ring.
            s.deliver(fds, line, false);
        }
        return true;
    }

    fn publish(s: *const Receiver, fds: Endpoints, running: bool, kernel_ok: bool) void {
        var buf: [512]u8 = @splat(' ');
        _ = std.mem.print(&buf, "{{\"running\":{s},\"pid\":{d},\"boottime\":{d}," ++
            "\"file\":\"{s}\",\"kernel\":\"{s}\",\"console\":\"{s}\"," ++
            "\"input_dropped\":{d},\"console_dropped\":{d}," ++
            "\"file_queue_dropped\":{d},\"file_dropped\":{d},\"storage_errors\":{d}," ++
            "\"kernel_lost\":{d},\"kernel_errors\":{d}}}", .{
            if (running) "true" else "false",
            fds.pid,
            seconds(.BOOTTIME),
            if (!fds.file_requested)
                "disabled"
            else if (fds.writer < 0)
                "unavailable"
            else if (s.stats.healthy == 1)
                "active"
            else
                "degraded",
            if (kernel_ok) "active" else "unavailable",
            if (!fds.echo) "disabled" else if (fds.console < 0) "unavailable" else "active",
            s.refused,
            s.console_lost,
            s.file_lost,
            s.stats.dropped,
            s.stats.errors,
            s.kernel_lost,
            s.kernel_errors,
        }) catch unreachable;
        buf[buf.len - 1] = '\n';
        // One fixed-size positional write avoids stale tails and empty updates.
        const rc = linux.pwrite(fds.health, &buf, buf.len, 0);
        if (linux.errno(rc) != .SUCCESS or rc != buf.len) {
            _ = linux.ftruncate(fds.ready, 0);
            linux.exit_group(1);
        }
    }
};

fn reportLoss(s: *Receiver) bool {
    var buf: [384]u8 = undefined;
    const line = std.mem.print(
        &buf,
        "syslogd: {{\"source\":\"syslogd\",\"event\":\"loss\",\"input\":{d},\"console\":{d}," ++
            "\"file_queue\":{d},\"file\":{d},\"storage_errors\":{d}," ++
            "\"kernel_lost\":{d},\"kernel_errors\":{d}}}\n",
        .{
            s.refused,
            s.console_lost,
            s.file_lost,
            s.stats.dropped,
            s.stats.errors,
            s.kernel_lost,
            s.kernel_errors,
        },
    ) catch unreachable;
    return s.queue.append(line);
}

fn receive(fds: Endpoints) void {
    const console = fds.console;
    const ready = fds.ready;
    const writer = fds.writer;
    var kernel = fds.kernel;
    var state: Receiver = .{};
    var input: [p.max_input]u8 = undefined;
    var output: [p.max_record]u8 = undefined;
    var announced: Stats = .{};
    var last_report = seconds(.BOOTTIME) - 60;
    var last_status: i64 = -1;
    var published = writer < 0;
    state.publish(fds, published, kernel >= 0);
    if (published) _ = linux.write(ready, "1", 1);
    while (!stopping.load(.monotonic)) {
        const now = seconds(.BOOTTIME);
        state.floods(fds, now);
        flush(&state.queue, console);
        if (now != last_status) {
            state.publish(fds, published, kernel >= 0);
            last_status = now;
        }
        if (now - last_report >= 60) {
            if (state.refused != 0 or state.console_lost != 0 or state.file_lost != 0 or
                state.kernel_lost != 0 or state.kernel_errors != 0 or
                state.stats.dropped != announced.dropped or state.stats.errors != announced.errors)
            {
                // Keep counts cumulative, so a full console queue can retry.
                if (reportLoss(&state)) {
                    last_report = now;
                    announced = state.stats;
                }
            }
        }
        var pollfds: [4]linux.pollfd = .{
            .{ .fd = fds.socket, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = writer, .events = linux.POLL.IN, .revents = 0 },
            .{
                .fd = if (state.queue.pending().len > 0) console else -1,
                .events = linux.POLL.OUT,
                .revents = 0,
            },
            .{ .fd = kernel, .events = linux.POLL.IN, .revents = 0 },
        };
        const rc = linux.poll(&pollfds, pollfds.len, 1000);
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS) linux.exit_group(1);
        if (writer >= 0 and pollfds[1].revents != 0) {
            const n = linux.recvfrom(
                writer,
                std.mem.asBytes(&state.stats),
                @sizeOf(Stats),
                linux.MSG.DONTWAIT | linux.MSG.TRUNC,
                null,
                null,
            );
            if (linux.errno(n) == .SUCCESS) {
                if (n != @sizeOf(Stats)) {
                    _ = linux.ftruncate(ready, 0);
                    state.stats.healthy = 0;
                    state.publish(fds, false, kernel >= 0);
                    consoleWrite(console, "syslogd: file worker exited; restarting\n");
                    linux.exit_group(1);
                }
                if (!published and state.stats.ready == 1) {
                    state.publish(fds, true, kernel >= 0);
                    _ = linux.write(ready, "1", 1);
                    published = true;
                }
            } else if (linux.errno(n) != .AGAIN and linux.errno(n) != .INTR) linux.exit_group(1);
        }
        if (kernel >= 0 and pollfds[3].revents != 0)
            if (!state.kernel(fds)) {
                kernel = -1;
            };
        if (pollfds[0].revents & linux.POLL.IN == 0) continue;
        // Bound each batch so floods cannot starve shutdown or diagnostics.
        for (0..128) |_| {
            if (!(state.application(fds, &input, &output) catch linux.exit_group(1))) break;
        }
    }
    _ = linux.ftruncate(ready, 0);
    state.publish(fds, false, kernel >= 0);
    // The application services have stopped. Drain a bounded final batch.
    for (0..4096) |_| {
        if (!(state.application(fds, &input, &output) catch break)) break;
    }
    state.floods(fds, seconds(.BOOTTIME));
    if (kernel >= 0) _ = state.kernel(fds);
    if (writer >= 0) {
        _ = linux.shutdown(writer, linux.SHUT.WR);
        const until = seconds(.BOOTTIME) + 3;
        while (seconds(.BOOTTIME) < until) {
            flush(&state.queue, console);
            for (0..256) |_| {
                const n = linux.recvfrom(
                    writer,
                    std.mem.asBytes(&state.stats),
                    @sizeOf(Stats),
                    linux.MSG.DONTWAIT | linux.MSG.TRUNC,
                    null,
                    null,
                );
                if (linux.errno(n) != .SUCCESS or n != @sizeOf(Stats)) break;
            }
            var status: i32 = 0;
            const waited = linux.waitpid(fds.child, &status, linux.W.NOHANG);
            if (linux.errno(waited) == .SUCCESS and waited != 0) {
                if (status != 0) linux.exit_group(1);
                break;
            }
            var none: [0]linux.pollfd = .{};
            _ = linux.poll(&none, 0, 10);
        }
    }
    if (state.refused != 0 or state.console_lost != 0 or state.file_lost != 0 or
        state.stats.dropped != 0 or state.stats.errors != 0 or
        state.kernel_lost != 0 or state.kernel_errors != 0)
        _ = reportLoss(&state);
    state.publish(fds, false, kernel >= 0);
    flush(&state.queue, console);
}

test {
    _ = @import("policy.zig");
    _ = @import("store.zig");
    _ = @import("fuzz.zig");
}
