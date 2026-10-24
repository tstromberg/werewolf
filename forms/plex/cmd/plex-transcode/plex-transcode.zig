//! Plex's transcoder crosses a UID boundary through a fixed Unix socket.
//! The client forwards argv and stdio, never an environment or executable.
//! Leash confines the worker to read-only media and its own scratch directory;
//! the worker starts only the vendor transcoder, with a fixed environment.
const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");
const mem = std.mem;
const Io = std.Io;
const Dir = Io.Dir;
const home = "/usr/lib/plexmediaserver";
const socket_path = "/run/svc/plex-transcode/control.sock";
const jobs = "/run/svc/plex-transcode/jobs";
const native = home ++ "/isolated/Plex Transcoder";
const max_packet = 32 * 1024;
const max_args = 256;
const Credentials = extern struct { pid: i32, uid: u32, gid: u32 };
const endian = @import("builtin").cpu.arch.endian();

pub fn main(init: std.process.Init) void {
    const a = init.arena.allocator();
    const args = init.minimal.args.toSlice(a) catch std.process.exit(1);
    const shim = args.len > 0 and mem.eql(u8, std.fs.path.basename(args[0]), "Plex Transcoder");
    const result = if (shim)
        client(init.io, a, args[1..])
    else if (args.len == 2 and mem.eql(u8, args[1], "worker"))
        worker(init.io, a)
    else if (args.len > 2 and mem.eql(u8, args[1], "client"))
        client(init.io, a, args[2..])
    else
        error.Usage;
    result catch |err| {
        var buf: [256]u8 = undefined;
        const text = std.mem.print(
            &buf,
            "plex-transcode: {{\"event\":\"refused\",\"reason\":\"{s}\"}}\n",
            .{@errorName(err)},
        ) catch unreachable;
        _ = linux.write(2, text.ptr, text.len);
        std.process.exit(1);
    };
}

fn address() linux.sockaddr.un {
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(addr.path[0..socket_path.len], socket_path);
    return addr;
}

fn peer(fd: i32, uid: u32) !void {
    var cred: Credentials = undefined;
    var size: linux.socklen_t = @sizeOf(Credentials);
    _ = try sandbox.sys(
        linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.PEERCRED, @ptrCast(&cred), &size),
        "peer credentials",
    );
    if (size != @sizeOf(Credentials) or cred.uid != uid) return error.WrongPeer;
}

fn user(io: Io, a: mem.Allocator, name: []const u8) !u32 {
    const text = try Dir.cwd().readFileAlloc(io, "/etc/passwd", a, .limited(1 << 20));
    defer a.free(text);
    var lines = mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = mem.splitScalar(u8, line, ':');
        if (!mem.eql(u8, fields.next() orelse "", name)) continue;
        _ = fields.next() orelse return error.BadAccount;
        return std.fmt.parseInt(u32, fields.next() orelse return error.BadAccount, 10);
    }
    return error.NoAccount;
}

fn client(io: Io, a: mem.Allocator, args: []const [:0]const u8) !void {
    var packet: [max_packet]u8 = undefined;
    var cwd: [Dir.max_path_bytes]u8 = undefined;
    const where = cwd[0..try std.process.currentPath(io, &cwd)];
    if (args.len == 0 or args.len > max_args) return error.BadArguments;
    @memcpy(packet[0..4], "PXT1");
    mem.writeInt(u16, packet[4..6], @intCast(args.len), .big);
    var n: usize = 6;
    for (args) |arg| {
        if (arg.len + 1 > packet.len - n) return error.LongRequest;
        @memcpy(packet[n..][0..arg.len], arg);
        n += arg.len;
        packet[n] = 0;
        n += 1;
    }
    const dir = if (inJobs(where)) where else jobs;
    if (dir.len + 1 > packet.len - n) return error.LongRequest;
    @memcpy(packet[n..][0..dir.len], dir);
    n += dir.len;
    packet[n] = 0;
    n += 1;
    const fd: i32 = @intCast(try sandbox.sys(
        linux.socket(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0),
        "client socket",
    ));
    defer _ = linux.close(fd);
    var addr = address();
    _ = try sandbox.sys(
        linux.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))),
        "connect worker",
    );
    try peer(fd, try user(io, a, "plex-transcode"));
    var control: [32]u8 align(8) = @splat(0);
    mem.writeInt(usize, control[0..8], 28, endian);
    mem.writeInt(i32, control[8..12], linux.SOL.SOCKET, endian);
    mem.writeInt(i32, control[12..16], linux.SCM.RIGHTS, endian);
    for (0..3) |i| mem.writeInt(i32, control[16 + 4 * i ..][0..4], @intCast(i), endian);
    const iov = [_]std.posix.iovec_const{.{ .base = &packet, .len = n }};
    const msg: linux.msghdr_const = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    if (linux.sendmsg(fd, &msg, linux.MSG.NOSIGNAL) != n) return error.SendRequest;
    var status: [1]u8 = undefined;
    if (linux.recvfrom(fd, &status, 1, 0, null, null) != 1) return error.WorkerLost;
    std.process.exit(status[0]);
}

fn inJobs(path: []const u8) bool {
    if (!mem.eql(u8, path, jobs) and !mem.startsWith(u8, path, jobs ++ "/")) return false;
    var parts = mem.splitScalar(u8, path, '/');
    _ = parts.next();
    while (parts.next()) |part| if (part.len == 0 or mem.eql(u8, part, ".") or
        mem.eql(u8, part, "..")) return false;
    return true;
}

fn worker(io: Io, a: mem.Allocator) !void {
    if (linux.geteuid() == 0) return error.RootForbidden;
    const caller = try user(io, a, "plex");
    try Dir.cwd().createDirPath(io, jobs);
    try Dir.cwd().setFilePermissions(io, jobs, .fromMode(0o770), .{});
    const fd: i32 = @intCast(try sandbox.sys(
        linux.socket(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0),
        "worker socket",
    ));
    defer _ = linux.close(fd);
    _ = linux.unlinkat(linux.AT.FDCWD, socket_path, 0);
    var addr = address();
    _ = try sandbox.sys(linux.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))), "bind worker");
    try Dir.cwd().setFilePermissions(io, socket_path, .fromMode(0o660), .{});
    _ = try sandbox.sys(linux.listen(fd, 8), "listen worker");
    while (true) {
        const rc = linux.accept4(fd, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(rc) == .INTR) continue;
        const connection: i32 = @intCast(try sandbox.sys(rc, "accept worker"));
        defer _ = linux.close(connection);
        peer(connection, caller) catch continue;
        // One job at a time. The backlog is bounded; a client that vanishes
        // cancels its job. No privileged supervisor or setuid program exists.
        serve(connection) catch {};
    }
}

fn serve(connection: i32) !void {
    var ready = [_]linux.pollfd{.{ .fd = connection, .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&ready, 1, 2000) != 1 or
        ready[0].revents & linux.POLL.IN == 0) return error.RequestTimeout;
    var packet: [max_packet + 1]u8 = undefined;
    // All possible passed descriptors fit, so every received fd can be
    // closed even when the sender supplied a malformed control message.
    var control: [1040]u8 align(8) = @splat(0);
    var iov = [_]std.posix.iovec{.{ .base = &packet, .len = packet.len }};
    var msg: linux.msghdr = .{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &control,
        .controllen = control.len,
        .flags = 0,
    };
    const n = try sandbox.sys(
        linux.recvmsg(connection, &msg, linux.MSG.CMSG_CLOEXEC | linux.MSG.TRUNC),
        "receive job",
    );
    var descriptors: [253]i32 = undefined;
    var count: usize = 0;
    defer for (descriptors[0..count]) |fd| {
        _ = linux.close(fd);
    };
    var offset: usize = 0;
    while (offset + 16 <= msg.controllen) {
        const len = mem.readInt(usize, control[offset..][0..8], endian);
        if (len < 16 or len > msg.controllen - offset) return error.BadControl;
        if (mem.readInt(i32, control[offset + 8 ..][0..4], endian) != linux.SOL.SOCKET or
            mem.readInt(i32, control[offset + 12 ..][0..4], endian) != linux.SCM.RIGHTS or
            (len - 16) % 4 != 0) return error.BadControl;
        var at = offset + 16;
        while (at < offset + len) : (at += 4) {
            if (count == descriptors.len) return error.BadControl;
            descriptors[count] = mem.readInt(i32, control[at..][0..4], endian);
            count += 1;
        }
        offset += mem.alignForward(usize, len, 8);
    }
    if (n == 0 or n > max_packet or count != 3 or msg.flags & (linux.MSG.TRUNC |
        linux.MSG.CTRUNC) != 0) return error.BadRequest;
    var argv: [max_args + 2:null]?[*:0]const u8 = @splat(null);
    argv[0] = native;
    const cwd = try parseRequest(packet[0..n], &argv);
    // The native helper gets only the callback proxy, never the owner API.
    // Rebuild these URLs here, so the server cannot select another target.
    var callback_urls: [2][2048]u8 = undefined;
    var rewritten: usize = 0;
    for (1..max_args) |i| {
        const arg = argv[i] orelse break;
        if (!mem.eql(u8, mem.span(arg), "-progressurl") and
            !mem.eql(u8, mem.span(arg), "-segment_list")) continue;
        const url = argv[i + 1] orelse return error.BadCallback;
        const value = mem.span(url);
        if (!mem.startsWith(
            u8,
            value,
            "http://127.0.0.1:32400/video/:/transcode/session/",
        )) return error.BadCallback;
        if (rewritten == callback_urls.len or value.len > 1900) return error.BadCallback;
        const at = try std.mem.printSentinel(
            &callback_urls[rewritten],
            "http://127.0.0.1:32402{s}",
            .{value[22..]},
            0,
        );
        argv[i + 1] = at;
        rewritten += 1;
    }
    const How = extern struct { flags: u64, mode: u64 = 0, resolve: u64 = 6 };
    const how: How = .{ .flags = @as(
        u32,
        @bitCast(linux.O{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }),
    ) };
    const opened = linux.syscall4(
        .openat2,
        @bitCast(@as(isize, linux.AT.FDCWD)),
        @intFromPtr(cwd.ptr),
        @intFromPtr(&how),
        @sizeOf(How),
    );
    const directory: i32 = @intCast(try sandbox.sys(opened, "job directory"));
    defer _ = linux.close(directory);
    const pid: i32 = @intCast(try sandbox.sys(linux.fork(), "fork transcoder"));
    if (pid == 0) {
        if (linux.errno(linux.setpgid(0, 0)) != .SUCCESS or
            linux.errno(linux.fchdir(directory)) != .SUCCESS) linux.exit_group(126);
        for (descriptors[0..3], 0..) |fd, i| {
            if (linux.errno(linux.dup3(fd, @intCast(i), 0)) != .SUCCESS) linux.exit_group(126);
        }
        if (linux.errno(linux.close_range(
            3,
            std.math.maxInt(i32),
            .{ .UNSHARE = false, .CLOEXEC = false },
        )) != .SUCCESS)
            linux.exit_group(126);
        const codecs = home ++
            "/Codecs/Plex Media Server/Codecs/a336ba9-16a9aaf440ee9a92b75f070b-linux-" ++
            @tagName(@import("builtin").cpu.arch);
        const env = [_:null]?[*:0]const u8{
            "HOME=" ++ jobs,                                     "TMPDIR=" ++ jobs,
            "PLEX_MEDIA_SERVER_CODEC_DIR=" ++ home ++ "/Codecs",
            "LD_LIBRARY_PATH=" ++ codecs ++
                ":" ++ home ++ "/lib",
            "PLEX_MEDIA_SERVER_HOME=" ++ home,
            "FFMPEG_EXTERNAL_LIBS=" ++
                codecs ++ "/",
        };
        _ = linux.execve(native, &argv, &env);
        linux.exit_group(126);
    }
    var status: i32 = 0;
    while (true) {
        const result = linux.waitpid(pid, &status, linux.W.NOHANG);
        if (result == @as(usize, @intCast(pid))) break;
        if (linux.errno(result) != .SUCCESS and linux.errno(result) != .INTR) return error.WaitJob;
        ready[0].revents = 0;
        _ = linux.poll(&ready, 1, 100);
        if (ready[0].revents & (linux.POLL.HUP | linux.POLL.ERR | linux.POLL.IN) != 0) {
            _ = linux.kill(-pid, linux.SIG.KILL);
            _ = linux.kill(pid, linux.SIG.KILL);
            _ = linux.waitpid(pid, &status, 0);
            return error.ClientLost;
        }
    }
    const code = [_]u8{if (status & 0x7f == 0)
        @intCast((status >> 8) & 0xff)
    else
        128 + @as(u8, @intCast(status & 0x7f))};
    if (linux.sendto(
        connection,
        &code,
        1,
        linux.MSG.NOSIGNAL,
        null,
        0,
    ) != 1) return error.ReplyLost;
}

fn parseRequest(packet: []u8, argv: *[max_args + 2:null]?[*:0]const u8) ![:0]const u8 {
    if (packet.len < 8 or !mem.eql(u8, packet[0..4], "PXT1")) return error.BadRequest;
    const argc = mem.readInt(u16, packet[4..6], .big);
    if (argc == 0 or argc > max_args) return error.BadArguments;
    var at: usize = 6;
    for (1..@as(usize, argc) + 1) |i| {
        const end = mem.findScalarPos(u8, packet, at, 0) orelse return error.BadRequest;
        argv[i] = packet[at..end :0];
        at = end + 1;
    }
    if (at >= packet.len or packet[packet.len - 1] != 0) return error.BadRequest;
    const cwd = packet[at .. packet.len - 1 :0];
    if (!inJobs(cwd) or mem.findScalar(u8, cwd, 0) != null) return error.BadDirectory;
    return cwd;
}

test "job directories stay under the worker's scratch tree" {
    try std.testing.expect(inJobs(jobs));
    try std.testing.expect(inJobs(jobs ++ "/session/output"));
    for ([_][]const u8{
        "/",
        "/data/svc/plex",
        jobs ++ "-other",
        jobs ++ "/../state",
        jobs ++ "/./x",
        jobs ++ "//x",
    }) |path|
        try std.testing.expect(!inJobs(path));
}

test "worker protocol preserves empty arguments and rejects malformed requests" {
    var argv: [max_args + 2:null]?[*:0]const u8 = @splat(null);
    var good = ("PXT1\x00\x02-version\x00\x00" ++ jobs ++ "\x00").*;
    try std.testing.expectEqualStrings(jobs, try parseRequest(&good, &argv));
    try std.testing.expectEqualStrings("-version", mem.span(argv[1].?));
    try std.testing.expectEqualStrings("", mem.span(argv[2].?));
    try std.testing.expect(argv[3] == null);
    for ([_][]const u8{
        "PXT0\x00\x01-version\x00" ++ jobs ++ "\x00",
        "PXT1\x00\x00" ++ jobs ++ "\x00",
        "PXT1\x01\x01-version\x00" ++ jobs ++ "\x00",
        "PXT1\x00\x01-version\x00" ++ jobs,
        "PXT1\x00\x01-version\x00/var/tmp\x00",
        "PXT1\x00\x01-version\x00" ++ jobs ++ "/../plex\x00",
        "PXT1\x00\x01-version\x00" ++ jobs ++ "\x00extra\x00",
    }) |bad| {
        var buf: [512]u8 = undefined;
        @memcpy(buf[0..bad.len], bad);
        if (parseRequest(buf[0..bad.len], &argv)) |_| return error.AcceptedBadRequest else |_| {}
    }
}
