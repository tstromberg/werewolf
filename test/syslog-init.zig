//! Run the shipped daemon, its seal and real Linux confinement on ext4.
const std = @import("std");
const linux = std.os.linux;
const seal = @import("seal");
const p = @import("log-policy");
const Io = std.Io;
const Dir = Io.Dir;
const mem = std.mem;

pub fn main(init: std.process.Init) noreturn {
    const args = init.minimal.args.toSlice(init.arena.allocator()) catch linux.exit_group(1);
    if (args.len > 1 and mem.eql(u8, args[1], "client")) {
        send("<13>leashed: hello") catch linux.exit_group(1);
        linux.exit_group(0);
    }
    check(init.io, init.arena.allocator()) catch |err| {
        std.debug.print("syslog-check: FAIL {s}\n", .{@errorName(err)});
        poweroff();
    };
    std.debug.print("syslog-check: PASS\n", .{});
    poweroff();
}

fn call(rc: usize) !usize {
    if (linux.errno(rc) != .SUCCESS) {
        std.debug.print("syslog-check: syscall {t}\n", .{linux.errno(rc)});
        return error.SystemCall;
    }
    return rc;
}

fn check(io: Io, gpa: mem.Allocator) !void {
    _ = try call(linux.mount("proc", "/proc", "proc", 0, 0));
    _ = try call(linux.mount("devtmpfs", "/dev", "devtmpfs", 0, 0));
    _ = try call(linux.mount("/dev/vda", "/data", "ext4", 0, 0));
    _ = try call(linux.symlink("/run/syslog/dev-log", "/dev/log"));
    const dir = Dir.cwd();
    try dir.createDirPath(io, "/data/log");
    _ = try call(linux.chmod("/data/log", 0o700));
    const now = try realtime();
    var old_buf: [p.name_len]u8 = undefined;
    var young_buf: [p.name_len]u8 = undefined;
    var expired_buf: [p.name_len]u8 = undefined;
    const old = try p.archiveName(&old_buf, now - 2 * p.day, 1);
    const young = try p.archiveName(&young_buf, now - p.retention + 3600, 1);
    const expired = try p.archiveName(&expired_buf, now - p.retention - 1, 1);
    for ([_][]const u8{ old, young, expired }) |name|
        try fixture(io, gpa, name, "syslogd: {\"message\":\"retained\"}\n");
    const pid = try launch();
    try ready(io, pid);
    const receiver = try status(io, gpa, pid);
    try confined(receiver, "75");
    const writer = try childOf(io, gpa, pid);
    try confined(try status(io, gpa, writer), "76");
    std.debug.print("syslog-check: identities and seccomp verified\n", .{});
    try waitExists(io, try gpa.print("/data/log/{s}.gz", .{old}));
    try waitExists(io, try gpa.print("/data/log/{s}.gz", .{young}));
    if (exists(io, try gpa.print("/data/log/{s}", .{expired}))) return error.RetentionFailed;
    std.debug.print("syslog-check: gzip and 90-day retention verified\n", .{});

    const sender_pid = try call(linux.fork());
    if (sender_pid == 0) {
        _ = linux.setresgid(65534, 65534, 65534);
        _ = linux.setresuid(65534, 65534, 65534);
        send("<13>guest[1]: hello\n\x1b[2J") catch linux.exit_group(1);
        var too_long: [p.max_input + 1]u8 = @splat('x');
        send(&too_long) catch linux.exit_group(1);
        linux.exit_group(0);
    }
    var result: i32 = 0;
    _ = try call(linux.waitpid(@intCast(sender_pid), &result, 0));
    if (result != 0) return error.SenderFailed;
    const until = try realtime() + 5;
    var received = false;
    while (try realtime() < until) {
        const text = dir.readFileAlloc(io, "/data/log/messages", gpa, .limited(1 << 20)) catch "";
        if (mem.find(u8, text, "hello") != null) {
            if (mem.find(u8, text, "\"uid\":65534") == null or
                mem.find(u8, text, "\\u000a\\u001b[2J") == null or
                mem.count(u8, text, "\n") != 1) return error.BadRecord;
            received = true;
            break;
        }
        try io.sleep(.fromMilliseconds(20), .awake);
    }
    if (!received) return error.NoRecord;
    // Exercise the real launcher and its socket floor, without adding a
    // broad write grant or changing the application's declared promises.
    try dir.createDirPath(io, "/etc/sv/client");
    try dir.createDirPath(io, "/usr/share/werewolf/etc");
    try dir.writeFile(
        io,
        .{
            .sub_path = "/usr/share/werewolf/etc/passwd",
            .data = "app:x:65536:65536::/var/empty:/sbin/nologin\n",
        },
    );
    try dir.writeFile(
        io,
        .{ .sub_path = "/usr/share/werewolf/etc/group", .data = "app:x:65536:\n" },
    );
    try dir.writeFile(
        io,
        .{
            .sub_path = "/etc/sv/client/service",
            .data = "exec /client client\nuser app\npledge stdio rpath unix connect\n",
        },
    );
    const app = try call(linux.fork());
    if (app == 0) {
        _ = linux.chdir("/etc/sv/client");
        const argv = [_:null]?[*:0]const u8{"/leash"};
        const env = [_:null]?[*:0]const u8{};
        _ = linux.execve("/leash", &argv, &env);
        linux.exit_group(1);
    }
    _ = try call(linux.waitpid(@intCast(app), &result, 0));
    if (result != 0) return error.LeashedClientFailed;
    try io.sleep(.fromMilliseconds(100), .awake);
    const text = try dir.readFileAlloc(io, "/data/log/messages", gpa, .limited(1 << 20));
    if (mem.find(u8, text, "\"uid\":65536") == null or
        mem.find(u8, text, "leashed: hello") == null) return error.LeashedLogMissing;
    std.debug.print("syslog-check: leashed client socket access verified\n", .{});
    const before = try fdCount(io, gpa, pid);
    for (0..16) |_| try sendRights();
    try io.sleep(.fromMilliseconds(100), .awake);
    if (try fdCount(io, gpa, pid) != before) return error.DescriptorLeak;
    std.debug.print(
        "syslog-check: credentials, escaping, truncation and fd rejection verified\n",
        .{},
    );
    try shutdown(io, pid);
    if (exists(io, "/data/log/messages") and
        (try dir.statFile(io, "/data/log/messages", .{})).size != 0) return error.NotDrained;

    // Pressure must not evict an unexpired archive. Sparse files exercise
    // the byte budget without needing to fill the guest's whole filesystem.
    try dir.writeFile(io, .{ .sub_path = "/run/config/syslog.conf", .data = "max-mib 16\n" });
    for (10..13) |sequence| {
        var buf: [p.name_len]u8 = undefined;
        const name = try p.archiveName(&buf, now, @intCast(sequence));
        const path = try gpa.print("/data/log/{s}", .{name});
        const f = try dir.createFile(io, path, .{ .permissions = .fromMode(0o600) });
        try f.setLength(io, p.segment_bytes);
        f.close(io);
        const zpath = try gpa.dupeSentinel(u8, path, 0);
        _ = try call(linux.chown(zpath, 76, 76));
    }
    const pressured = try launch();
    try ready(io, pressured);
    try send("<13>guest: pressure-drop");
    try io.sleep(.fromMilliseconds(100), .awake);
    if ((try dir.statFile(io, "/data/log/messages", .{})).size != 0) return error.BudgetExceeded;
    try shutdown(io, pressured);
    std.debug.print("syslog-check: pressure preserved young archives\n", .{});

    try dir.writeFile(io, .{ .sub_path = "/run/config/syslog.conf", .data = "max-mib 1024\n" });
    const fill_file = try dir.createFile(io, "/data/fill", .{});
    const block: [64 << 10]u8 = @splat(0);
    var full = false;
    for (0..4096) |_| {
        fill_file.writeStreamingAll(io, &block) catch {
            full = true;
            break;
        };
    }
    fill_file.close(io);
    if (!full) return error.DiskDidNotFill;
    const full_disk = try launch();
    try ready(io, full_disk);
    try send("<13>guest: full-disk-drop");
    try io.sleep(.fromMilliseconds(100), .awake);
    if ((try dir.statFile(io, "/data/log/messages", .{})).size != 0) return error.FullDiskWrite;
    if (!exists(io, try gpa.print("/data/log/{s}.gz", .{young}))) return error.YoungFileEvicted;
    try shutdown(io, full_disk);
    try dir.deleteFile(io, "/data/fill");
    std.debug.print("syslog-check: full filesystem preserved logs and kept receiver ready\n", .{});
    // A RAM-only system must still receive logs without claiming persistence.
    _ = try call(linux.umount2("/data", 0));
    _ = try call(linux.mount("tmpfs", "/data", "tmpfs", 0, 0));
    const ram_logger = try launch();
    try ready(io, ram_logger);
    try send("<13>guest: console-only");
    try io.sleep(.fromMilliseconds(100), .awake);
    if (exists(io, "/data/log")) return error.VolatileLogging;
    try shutdown(io, ram_logger);
    std.debug.print("syslog-check: clean shutdown and volatile-data fallback verified\n", .{});
}

fn fixture(io: Io, gpa: mem.Allocator, name: []const u8, text: []const u8) !void {
    const path = try gpa.printSentinel("/data/log/{s}", .{name}, 0);
    const f = try Dir.cwd().createFile(io, path, .{ .permissions = .fromMode(0o600) });
    try f.writePositionalAll(io, text, 0);
    f.close(io);
    _ = try call(linux.chown(path, 76, 76));
}

fn launch() !i32 {
    const pid = try call(linux.fork());
    if (pid == 0) {
        var filter: [seal.max_filter]seal.Filter = undefined;
        _ = seal.install(
            seal.buildFilter(&filter, seal.base, false),
            false,
        ) catch linux.exit_group(1);
        const argv = [_:null]?[*:0]const u8{"/syslogd"};
        const env = [_:null]?[*:0]const u8{};
        _ = linux.execve("/syslogd", &argv, &env);
        linux.exit_group(1);
    }
    return @intCast(pid);
}

fn ready(io: Io, pid: i32) !void {
    var buf: [2]u8 = undefined;
    for (0..500) |_| {
        var state: i32 = 0;
        if (linux.waitpid(pid, &state, linux.W.NOHANG) == @as(usize, @intCast(pid))) {
            std.debug.print("syslog-check: daemon exited with status {d}\n", .{state});
            return error.DaemonExited;
        }
        const value = Dir.cwd().readFile(io, "/run/syslog/ready", &buf) catch "";
        if (mem.eql(u8, value, "1")) return;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    return error.NotReady;
}

fn confined(text: []const u8, uid: []const u8) !void {
    var buf: [64]u8 = undefined;
    const uid_line = try std.mem.print(
        &buf,
        "Uid:\t{s}\t{s}\t{s}\t{s}",
        .{ uid, uid, uid, uid },
    );
    for ([_][]const u8{
        uid_line,
        "CapEff:\t0000000000000000",
        "CapBnd:\t0000000000000000",
        "NoNewPrivs:\t1",
        "Seccomp:\t2",
    }) |line|
        if (mem.find(u8, text, line) == null) {
            std.debug.print("syslog-check: missing {s}\n{s}\n", .{ line, text });
            return error.NotConfined;
        };
}

fn status(io: Io, gpa: mem.Allocator, pid: i32) ![]const u8 {
    return readProc(io, gpa, try gpa.print("/proc/{d}/status", .{pid}));
}

fn readProc(io: Io, gpa: mem.Allocator, path: []const u8) ![]const u8 {
    const f = Dir.cwd().openFile(io, path, .{}) catch |err| {
        std.debug.print("syslog-check: {s}: {s}\n", .{ path, @errorName(err) });
        return err;
    };
    defer f.close(io);
    var reader = f.readerStreaming(io, &.{});
    return reader.interface.allocRemaining(gpa, .limited(8192));
}

fn fdCount(io: Io, gpa: mem.Allocator, pid: i32) !usize {
    var d = try Dir.cwd().openDir(io, try gpa.print("/proc/{d}/fd", .{pid}), .{ .iterate = true });
    defer d.close(io);
    var it = d.iterate();
    var count: usize = 0;
    while (try it.next(io)) |_| count += 1;
    return count;
}

fn childOf(io: Io, gpa: mem.Allocator, parent: i32) !i32 {
    var d = try Dir.cwd().openDir(io, "/proc", .{ .iterate = true });
    defer d.close(io);
    var it = d.iterate();
    var buf: [64]u8 = undefined;
    const expected = try std.mem.print(&buf, "PPid:\t{d}\n", .{parent});
    while (try it.next(io)) |entry| {
        const pid = std.fmt.parseInt(i32, entry.name, 10) catch continue;
        const text = status(io, gpa, pid) catch continue;
        if (mem.find(u8, text, expected) != null) return pid;
    }
    return error.NoWriter;
}

fn send(text: []const u8) !void {
    const fd = try sender();
    defer _ = linux.close(fd);
    if (try call(linux.sendto(fd, text.ptr, text.len, linux.MSG.NOSIGNAL, null, 0)) != text.len)
        return error.SendFailed;
}

fn sender() !i32 {
    const fd: i32 = @intCast(try call(linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM, 0)));
    errdefer _ = linux.close(fd);
    var address: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(address.path[0..8], "/dev/log");
    _ = try call(linux.connect(fd, @ptrCast(&address), 11));
    return fd;
}

fn sendRights() !void {
    const fd = try sender();
    defer _ = linux.close(fd);
    const extra: i32 = @intCast(try call(linux.open("/dev/null", .{ .ACCMODE = .RDONLY }, 0)));
    defer _ = linux.close(extra);
    var control: [24]u8 align(8) = @splat(0);
    const h: *linux.cmsghdr = @ptrCast(&control);
    h.* = .{ .len = 20, .level = linux.SOL.SOCKET, .type = linux.SCM.RIGHTS };
    mem.writeInt(i32, control[16..20], extra, .native);
    var iov = [_]std.posix.iovec_const{.{ .base = "bad", .len = 3 }};
    const msg: linux.msghdr_const = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    _ = try call(linux.sendmsg(fd, &msg, linux.MSG.NOSIGNAL));
}

fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn waitExists(io: Io, path: []const u8) !void {
    for (0..500) |_| {
        if (exists(io, path)) return;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    return error.FileMissing;
}

fn shutdown(io: Io, pid: i32) !void {
    _ = try call(linux.kill(pid, linux.SIG.TERM));
    for (0..500) |_| {
        var state: i32 = 0;
        if (linux.waitpid(pid, &state, linux.W.NOHANG) == @as(usize, @intCast(pid))) {
            if (state != 0) return error.UncleanShutdown;
            return;
        }
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    return error.ShutdownTimeout;
}

fn realtime() !i64 {
    var ts: linux.timespec = undefined;
    _ = try call(linux.clock_gettime(.REALTIME, &ts));
    return ts.sec;
}

fn poweroff() noreturn {
    while (linux.errno(linux.tcdrain(2)) == .INTR) {}
    linux.sync();
    _ = linux.reboot(.MAGIC1, .MAGIC2, .POWER_OFF, null);
    while (true) _ = linux.pause();
}
