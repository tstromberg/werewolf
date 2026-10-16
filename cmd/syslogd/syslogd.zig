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
const ready_path = "/run/syslog/ready";
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
    const ready: i32 = @intCast(try sys(linux.open(ready_path, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
        .CLOEXEC = true,
    }, 0o644), "open readiness file"));
    const ready_stat = try stat(ready);
    if (ready_stat.uid != 0 or ready_stat.nlink != 1 or
        ready_stat.mode & linux.S.IFMT != linux.S.IFREG) return error.UnsafeReadyFile;
    _ = try sys(linux.ftruncate(ready, 0), "clear readiness");
    const console_rc = linux.open("/dev/console", .{
        .ACCMODE = .WRONLY,
        .NONBLOCK = true,
        .NOCTTY = true,
        .CLOEXEC = true,
    }, 0);
    const console: i32 = if (linux.errno(console_rc) == .SUCCESS) @intCast(console_rc) else -1;
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
    var keep: [5]i32 = .{ socket, socket_dir, ready, -1, -1 };
    var nkeep: usize = 3;
    if (console >= 0) {
        keep[nkeep] = console;
        nkeep += 1;
    }
    if (writer >= 0) {
        keep[nkeep] = writer;
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
    try confineReceiver(socket, console, ready, writer, child);
    receive(socket, console, ready, writer, child, config.console or (config.file and writer < 0));
    linux.exit_group(0);
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

fn confineReceiver(socket: i32, console: i32, ready: i32, writer: i32, child: i32) !void {
    var f: sandbox.Filter = .{};
    f.allowArg("recvmsg", 0, @intCast(socket));
    f.allowArg("write", 0, @intCast(ready));
    f.allowArg("ftruncate", 0, @intCast(ready));
    if (console >= 0) f.allowArg("write", 0, @intCast(console));
    if (writer >= 0) {
        f.allowArg("sendto", 0, @intCast(writer));
        f.allowArg("recvfrom", 0, @intCast(writer));
        f.allowArg("shutdown", 0, @intCast(writer));
        f.allowArg("wait4", 0, @intCast(child));
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

const Stats = extern struct { ready: u64 = 0, dropped: u64 = 0, errors: u64 = 0 };

fn writeLogs(store: *Store, channel: i32) !void {
    var stats: Stats = .{};
    var available = true;
    store.start(seconds(.REALTIME)) catch {
        stats.errors +|= 1;
        available = false;
    };
    stats.ready = 1;
    var buffer: [p.max_record + 1]u8 = undefined;
    var last_sync = seconds(.BOOTTIME);
    var last_maintain = last_sync - 60;
    while (true) {
        const now = seconds(.BOOTTIME);
        if (now != last_sync) {
            store.sync() catch {
                stats.errors +|= 1;
                available = false;
            };
            last_sync = now;
        }
        if (now - last_maintain >= 60) {
            if (available) {
                store.maintain(seconds(.REALTIME)) catch {
                    stats.errors +|= 1;
                    available = false;
                };
            } else {
                available = true;
                store.start(seconds(.REALTIME)) catch {
                    stats.errors +|= 1;
                    available = false;
                };
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
            if (err != error.StorageFull and err != error.NamesExhausted) {
                available = false;
                stats.errors +|= 1;
            }
            stats.dropped +|= 1;
        };
    }
    if (available) try store.finish(seconds(.REALTIME)) else try store.sync();
    _ = linux.sendto(channel, std.mem.asBytes(&stats), @sizeOf(Stats), linux.MSG.NOSIGNAL, null, 0);
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

fn receive(socket: i32, console: i32, ready: i32, writer: i32, child: i32, echo: bool) void {
    var queue: p.Queue = .{};
    var limiter: p.Limiter = .{};
    var input: [p.max_input]u8 = undefined;
    var output: [p.max_record]u8 = undefined;
    var refused: u64 = 0;
    var console_lost: u64 = 0;
    var file_lost: u64 = 0;
    var stats: Stats = .{};
    var announced: Stats = .{};
    var last_report = seconds(.BOOTTIME) - 60;
    var published = writer < 0;
    if (published) _ = linux.write(ready, "1", 1);
    while (!stopping.load(.monotonic)) {
        flush(&queue, console);
        const now = seconds(.BOOTTIME);
        if (now - last_report >= 60) {
            if (refused != 0 or console_lost != 0 or file_lost != 0 or
                stats.dropped != announced.dropped or stats.errors != announced.errors)
            {
                var buf: [256]u8 = undefined;
                const line = std.mem.print(&buf, "syslogd: {{\"event\":\"loss\",\"input\":{d},\"" ++
                    "console\":{d}," ++
                    "\"file_queue\":{d},\"file\":{d},\"storage_errors\":{d}}}\n", .{
                    refused,
                    console_lost,
                    file_lost,
                    stats.dropped,
                    stats.errors,
                }) catch unreachable;
                // Keep counts cumulative, so a full console queue can retry.
                if (queue.append(line)) {
                    last_report = now;
                    announced = stats;
                }
            }
        }
        var fds: [3]linux.pollfd = .{
            .{ .fd = socket, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = writer, .events = linux.POLL.IN, .revents = 0 },
            .{
                .fd = if (queue.pending().len > 0) console else -1,
                .events = linux.POLL.OUT,
                .revents = 0,
            },
        };
        const rc = linux.poll(&fds, fds.len, 1000);
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS) linux.exit_group(1);
        if (writer >= 0 and fds[1].revents != 0) {
            const n = linux.recvfrom(
                writer,
                std.mem.asBytes(&stats),
                @sizeOf(Stats),
                linux.MSG.DONTWAIT | linux.MSG.TRUNC,
                null,
                null,
            );
            if (linux.errno(n) == .SUCCESS) {
                if (n != @sizeOf(Stats)) {
                    _ = linux.ftruncate(ready, 0);
                    consoleWrite(console, "syslogd: file worker exited; restarting\n");
                    linux.exit_group(1);
                }
                if (!published and stats.ready == 1) {
                    _ = linux.write(ready, "1", 1);
                    published = true;
                }
            } else if (linux.errno(n) != .AGAIN and linux.errno(n) != .INTR) linux.exit_group(1);
        }
        if (fds[0].revents & linux.POLL.IN == 0) continue;
        // Bound each batch so floods cannot starve shutdown or diagnostics.
        for (0..128) |_| {
            const got = datagram(socket, &input) catch linux.exit_group(1) orelse break;
            const cred = got.credentials orelse {
                refused +|= 1;
                continue;
            };
            if (!limiter.admit(cred.uid, now)) {
                refused +|= 1;
                continue;
            }
            const line = p.record(&output, seconds(.REALTIME), cred, input[0..got.length]) catch {
                refused +|= 1;
                continue;
            };
            if (echo and !queue.append(line)) console_lost +|= 1;
            if (writer >= 0) {
                const sent = linux.sendto(
                    writer,
                    line.ptr,
                    line.len,
                    linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL,
                    null,
                    0,
                );
                if (linux.errno(sent) != .SUCCESS or sent != line.len) file_lost +|= 1;
            }
        }
    }
    _ = linux.ftruncate(ready, 0);
    // The application services have stopped. Drain a bounded final batch.
    for (0..4096) |_| {
        const got = datagram(socket, &input) catch break orelse break;
        const cred = got.credentials orelse continue;
        const line = p.record(
            &output,
            seconds(.REALTIME),
            cred,
            input[0..got.length],
        ) catch continue;
        if (echo) _ = queue.append(line);
        if (writer >= 0) _ = linux.sendto(
            writer,
            line.ptr,
            line.len,
            linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL,
            null,
            0,
        );
    }
    if (writer >= 0) {
        _ = linux.shutdown(writer, linux.SHUT.WR);
        const until = seconds(.BOOTTIME) + 3;
        while (seconds(.BOOTTIME) < until) {
            flush(&queue, console);
            var status: i32 = 0;
            const waited = linux.waitpid(child, &status, linux.W.NOHANG);
            if (linux.errno(waited) == .SUCCESS and waited != 0) {
                if (status != 0) linux.exit_group(1);
                break;
            }
            var none: [0]linux.pollfd = .{};
            _ = linux.poll(&none, 0, 10);
        }
    }
    flush(&queue, console);
}

test {
    _ = @import("policy.zig");
    _ = @import("store.zig");
}
