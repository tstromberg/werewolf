//! swtpm stands between QEMU and its swtpm, so a check can cut the power at
//! the exact TPM command that raises a release floor: before the TPM runs
//! it, or after it has but before QEMU hears. Proxy forwards the control
//! channel and the data channels it hands over; interpose, run as QEMU,
//! points QEMU's TPM at the proxy.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const posix = std.posix;
const net = Io.net;

/// Cut is where an armed proxy holds a floor increment.
pub const Cut = enum { before, after };

/// Observer sees every command the TPM answered, and its response.
pub const Observer = struct {
    context: *anyopaque,
    observe: *const fn (context: *anyopaque, command: []const u8, response: []const u8) void,
};

/// increment is whether command is NV_Increment of a release floor
/// (lib/tpm.zig): TPM_CC 0x134 on an index under 0x0150xxxx.
pub fn increment(command: []const u8) bool {
    return code(command) == 0x134 and mem.readInt(u32, command[10..14], .big) >> 16 == 0x0150;
}

/// code is a TPM packet's command or response code.
pub fn code(bytes: []const u8) u32 {
    return mem.readInt(u32, bytes[6..10], .big);
}

pub const max_packet = 65536;

pub const Proxy = struct {
    io: Io,
    gpa: Allocator,
    path: []const u8,
    backend: []const u8,
    observer: ?Observer,
    server: net.Server,
    accepting: Io.Future(void),
    tasks: Io.Group = .init,
    mutex: Io.Mutex = .init,
    changed: Io.Condition = .init,
    cut: ?Cut = null,
    hit: bool = false,
    released: bool = false,
    closed: bool = false,
    failure: ?[]const u8 = null,

    /// start listens at path, for QEMU, and forwards each connection to
    /// the swtpm control socket at backend. p must not move until close;
    /// gpa, an arena safe to use from several threads, outlives the proxy.
    pub fn start(
        p: *Proxy,
        io: Io,
        gpa: Allocator,
        path: []const u8,
        backend: []const u8,
        observer: ?Observer,
    ) !void {
        const address = try net.UnixAddress.init(path);
        p.* = .{
            .io = io,
            .gpa = gpa,
            .path = try gpa.dupe(u8, path),
            .backend = try gpa.dupe(u8, backend),
            .observer = observer,
            .server = try address.listen(io, .{}),
            .accepting = undefined,
        };
        errdefer p.server.deinit(io);
        p.accepting = try io.concurrent(accept, .{p});
    }

    /// arm holds the next floor increment at cut.
    pub fn arm(p: *Proxy, cut: Cut) void {
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        p.cut = cut;
        p.hit = false;
        p.released = false;
    }

    /// cancel disarms, and drops the TPM connection a held increment is on.
    pub fn cancel(p: *Proxy) void {
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        p.cut = null;
        p.released = true;
        p.changed.broadcast(p.io);
    }

    /// waitHit waits up to timeout for the armed increment, or a failure,
    /// and reports whether it came.
    pub fn waitHit(p: *Proxy, timeout: Io.Duration) bool {
        const until: Io.Timeout = .{ .deadline = .fromNow(
            p.io,
            .{ .raw = timeout, .clock = .awake },
        ) };
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        while (!p.hit) p.changed.waitTimeout(p.io, &p.mutex, until) catch return p.hit;
        return true;
    }

    /// failed is why forwarding failed, if it has.
    pub fn failed(p: *Proxy) ?[]const u8 {
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        return p.failure;
    }

    /// close ends every connection and removes the listening socket.
    pub fn close(p: *Proxy) void {
        {
            p.mutex.lockUncancelable(p.io);
            defer p.mutex.unlock(p.io);
            p.closed = true;
            p.released = true;
            p.changed.broadcast(p.io);
        }
        p.accepting.cancel(p.io);
        p.tasks.cancel(p.io);
        p.server.deinit(p.io);
        Io.Dir.cwd().deleteFile(p.io, p.path) catch {};
    }

    fn fail(p: *Proxy, comptime fmt: []const u8, args: anytype) void {
        const why = p.gpa.print(fmt, args) catch "tpm proxy: out of memory";
        std.log.err("tpm proxy: {s}", .{why});
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        if (p.failure == null) p.failure = why;
        p.hit = true;
        p.changed.broadcast(p.io);
    }

    /// gate marks the armed increment reached and holds it until cancel or
    /// close, after which its connection ends.
    fn gate(p: *Proxy) void {
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        p.hit = true;
        p.changed.broadcast(p.io);
        while (!p.released) p.changed.waitUncancelable(p.io, &p.mutex);
    }

    fn armed(p: *Proxy) ?Cut {
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        return p.cut;
    }
};

fn accept(p: *Proxy) void {
    while (true) {
        const client = p.server.accept(p.io) catch |err| switch (err) {
            error.Canceled => return,
            else => continue,
        };
        const address = net.UnixAddress.init(p.backend) catch unreachable;
        const backend = address.connect(p.io) catch |err| {
            p.fail("connect {s}: {t}", .{ p.backend, err });
            client.close(p.io);
            continue;
        };
        const conn = p.gpa.create(Connection) catch {
            client.close(p.io);
            backend.close(p.io);
            continue;
        };
        conn.* = .{ .client = client, .backend = backend };
        for ([_]bool{ true, false }) |outbound|
            p.tasks.concurrent(p.io, control, .{ p, conn, outbound }) catch conn.done(p);
    }
}

/// Connection is QEMU's control connection and the proxy's to swtpm. The
/// last of its two directions to end closes it.
const Connection = struct {
    client: net.Stream,
    backend: net.Stream,
    directions: std.atomic.Value(u8) = .init(2),

    fn done(c: *Connection, p: *Proxy) void {
        c.client.shutdown(p.io, .both) catch {};
        c.backend.shutdown(p.io, .both) catch {};
        if (c.directions.fetchSub(1, .acq_rel) != 1) return;
        c.client.close(p.io);
        c.backend.close(p.io);
        p.gpa.destroy(c);
    }
};

/// control forwards one direction of the control channel. QEMU hands
/// swtpm its data channel as a descriptor; the proxy keeps it and hands
/// swtpm the other end of a channel of its own.
fn control(p: *Proxy, conn: *Connection, outbound: bool) Io.Cancelable!void {
    const io = p.io;
    defer conn.done(p);
    const source = if (outbound) conn.client else conn.backend;
    const target = if (outbound) conn.backend else conn.client;
    var buf: [65536]u8 = undefined;
    var ancillary: [net.cmsg.space(16)]u8 align(net.cmsg_align) = undefined;
    while (true) {
        var data = [_][]u8{&buf};
        const got = source.readWithControl(io, &data, &ancillary) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        if (got.data_len == 0) return;
        const raw = buf[0..got.data_len];
        if (got.control_len == 0) {
            send(io, target, raw, &.{}) catch return;
            continue;
        }
        const fd = passed(ancillary[0..got.control_len], got.control_truncated) orelse {
            p.fail("unexpected swtpm descriptor message", .{});
            return;
        };
        if (!outbound) {
            p.fail("unexpected swtpm descriptor message", .{});
            return;
        }
        cloexec(fd);
        var pair: [2]posix.fd_t = undefined;
        if (posix.errno(posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &pair)) !=
            .SUCCESS)
        {
            p.fail("socketpair failed", .{});
            return;
        }
        cloexec(pair[0]);
        cloexec(pair[1]);
        const qemu = stream(fd);
        const local = stream(pair[0]);
        const remote = stream(pair[1]);
        var out: [net.cmsg.space(@sizeOf(posix.fd_t))]u8 align(net.cmsg_align) = @splat(0);
        const header: *align(net.cmsg_align) posix.cmsghdr = @ptrCast(&out);
        header.* = .{
            .len = net.cmsg.len(@sizeOf(posix.fd_t)),
            .level = posix.SOL.SOCKET,
            .type = posix.SCM.RIGHTS,
        };
        @memcpy(net.cmsg.data(header)[0..@sizeOf(posix.fd_t)], mem.asBytes(&pair[1]));
        const sent = send(io, target, raw, &out);
        remote.close(io);
        sent catch {
            qemu.close(io);
            local.close(io);
            return;
        };
        p.tasks.concurrent(io, dataChannel, .{ p, qemu, local }) catch {
            qemu.close(io);
            local.close(io);
        };
    }
}

/// passed is the one descriptor control carries as SCM_RIGHTS, or null.
fn passed(ancillary: []align(net.cmsg_align) u8, truncated: bool) ?posix.fd_t {
    if (truncated) return null;
    var it: net.cmsg.Iterator = .{ .control = ancillary };
    const message = it.next() orelse return null;
    if (it.next() != null) return null;
    if (message.header.level != posix.SOL.SOCKET or message.header.type != posix.SCM.RIGHTS or
        message.data.len != @sizeOf(posix.fd_t)) return null;
    return mem.bytesToValue(posix.fd_t, message.data[0..@sizeOf(posix.fd_t)]);
}

fn cloexec(fd: posix.fd_t) void {
    _ = posix.system.fcntl(fd, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC));
}

fn stream(fd: posix.fd_t) net.Stream {
    return .{ .socket = .{ .handle = fd, .address = .{ .ip4 = .unspecified(0) } } };
}

fn send(io: Io, target: net.Stream, data: []const u8, ancillary: []const u8) !void {
    var rest = data;
    var with = ancillary;
    while (rest.len > 0) {
        const n = try (try io.operate(.{ .net_write = .{
            .socket_handle = target.socket.handle,
            .data = &.{rest},
            .control = with,
        } })).net_write;
        rest = rest[n..];
        with = &.{};
    }
}

/// dataChannel carries TPM commands from QEMU and the TPM's responses
/// back, holding an armed floor increment at its cut.
fn dataChannel(p: *Proxy, qemu: net.Stream, tpm: net.Stream) Io.Cancelable!void {
    const io = p.io;
    defer {
        qemu.close(io);
        tpm.close(io);
    }
    var qemu_in: [max_packet]u8 = undefined;
    var tpm_in: [max_packet]u8 = undefined;
    var command: [max_packet]u8 = undefined;
    var response: [max_packet]u8 = undefined;
    var from_qemu = qemu.reader(io, &qemu_in);
    var from_tpm = tpm.reader(io, &tpm_in);
    while (true) {
        const asked = packet(&from_qemu.interface, &command) catch |err| switch (err) {
            error.BadPacket => return p.fail("invalid TPM packet length", .{}),
            else => return,
        };
        const cut = if (increment(asked)) p.armed() else null;
        if (cut == .before) return p.gate();
        send(io, tpm, asked, &.{}) catch return;
        const answer = packet(&from_tpm.interface, &response) catch |err| switch (err) {
            error.BadPacket => return p.fail("invalid TPM packet length", .{}),
            else => return,
        };
        if (p.observer) |o| o.observe(o.context, asked, answer);
        if (cut == .after) {
            if (code(answer) != 0) return p.fail("increment refused before cut", .{});
            return p.gate();
        }
        send(io, qemu, answer, &.{}) catch return;
    }
}

/// packet reads one TPM packet: a ten-byte header whose size field counts
/// the whole packet, header included.
fn packet(r: *Io.Reader, buf: *[max_packet]u8) ![]const u8 {
    try r.readSliceAll(buf[0..10]);
    const len = mem.readInt(u32, buf[2..6], .big);
    if (len < 10 or len > max_packet) return error.BadPacket;
    try r.readSliceAll(buf[10..len]);
    return buf[0..len];
}

/// Rule says how interpose rewrites a QEMU command line.
pub const Rule = struct {
    /// dir holds the proxy's socket, backend.json and ready.
    dir: []const u8,
    /// only, when set, proxies only a QEMU with an argument containing it.
    only: ?[]const u8 = null,
    /// monitor, when set, also gives that QEMU dir/qmp.sock, and names
    /// the boot drive whose file contains this, so QMP can reopen it.
    monitor: ?[]const u8 = null,
};

pub const Rewritten = struct {
    args: []const []const u8,
    /// backend is swtpm's own control socket, when the TPM was moved.
    backend: ?[]const u8,
};

pub const node_name = "werewolf-lifecycle-boot";

/// rewrite points a TPM chardev in args at the proxy, as rule says.
pub fn rewrite(gpa: Allocator, args: []const []const u8, rule: Rule) !Rewritten {
    var out: std.ArrayList([]const u8) = .empty;
    try out.appendSlice(gpa, args);
    const selected = if (rule.only) |only| for (args) |a| {
        if (mem.find(u8, a, only) != null) break true;
    } else false else true;
    var backend: ?[]const u8 = null;
    for (out.items, 0..) |a, i| {
        if (i == 0) continue;
        const flag = out.items[i - 1];
        if (rule.monitor) |disk| if (mem.eql(u8, flag, "-drive") and
            mem.find(u8, a, disk) != null and mem.find(u8, a, ",node-name=") == null)
        {
            out.items[i] = try gpa.print("{s},node-name={s}", .{ a, node_name });
        };
        if (!selected or !mem.eql(u8, flag, "-chardev") or mem.find(u8, a, "socket,") == null or
            mem.find(u8, a, "tpm") == null) continue;
        var parts: std.ArrayList([]const u8) = .empty;
        var it = mem.splitScalar(u8, a, ',');
        while (it.next()) |part| if (mem.startsWith(u8, part, "path=")) {
            if (backend == null) backend = part["path=".len..];
            try parts.append(gpa, try gpa.print("path={s}/proxy.sock", .{rule.dir}));
        } else try parts.append(gpa, part);
        out.items[i] = try mem.join(gpa, ",", parts.items);
    }
    if (backend != null and rule.monitor != null) {
        for (out.items) |a| if (mem.eql(u8, a, "-qmp")) break else {
            try out.appendSlice(gpa, &.{
                "-qmp",
                try gpa.print("unix:{s}/qmp.sock,server=on,wait=off", .{rule.dir}),
            });
        };
    }
    return .{ .args = out.items, .backend = backend };
}

/// Environment variables a check sets for interpose.
pub const env_qemu = "WEREWOLF_TEST_QEMU";
pub const env_dir = "WEREWOLF_TEST_TPM_PROXY";
pub const env_only = "WEREWOLF_TEST_TPM_ONLY";
pub const env_monitor = "WEREWOLF_TEST_TPM_MONITOR";

/// interpose is main for a check run as qemu-system-ARCH, by its name, from
/// a PATH the check gave howl or Lima: it moves the TPM to the proxy, says
/// where swtpm is in dir/backend.json, waits for dir/ready, then becomes
/// the real QEMU. It returns at once if the check was not run as QEMU.
pub fn interpose(
    io: Io,
    gpa: Allocator,
    args: []const []const u8,
    env: *const std.process.Environ.Map,
) void {
    if (!mem.startsWith(u8, std.fs.path.basename(args[0]), "qemu-system-")) return;
    // A QEMU started without the check's environment, as Melange starts its
    // build VM, is none of the check's machines: it runs as it was asked.
    const real = env.get(env_qemu) orelse passthrough(io, gpa, args, env);
    const dir = env.get(env_dir) orelse fatal("{s} is not set", .{env_dir});
    const rule: Rule = .{ .dir = dir, .only = env.get(env_only), .monitor = env.get(env_monitor) };
    const moved = rewrite(gpa, args, rule) catch |err| fatal("{t}", .{err});
    if (moved.backend) |backend| {
        var root = Io.Dir.cwd().openDir(io, dir, .{}) catch |err| fatal("{s}: {t}", .{ dir, err });
        if (rule.monitor != null) root.deleteFile(io, "qmp.sock") catch {};
        const record = std.json.Stringify.valueAlloc(gpa, backend, .{}) catch fatal("oom", .{});
        root.writeFile(io, .{ .sub_path = "backend.json", .data = record }) catch |err|
            fatal("backend.json: {t}", .{err});
        while (true) {
            if (root.access(io, "ready", .{})) break else |_| {}
            io.sleep(.fromMilliseconds(50), .awake) catch {};
        }
    }
    var argv: std.ArrayList([]const u8) = .empty;
    argv.append(gpa, real) catch fatal("oom", .{});
    argv.appendSlice(gpa, moved.args[1..]) catch fatal("oom", .{});
    const err = std.process.replace(io, .{ .argv = argv.items });
    fatal("{s}: {t}", .{ real, err });
}

/// passthrough becomes the QEMU that PATH names after this check's own
/// link, with args unchanged.
fn passthrough(
    io: Io,
    gpa: Allocator,
    args: []const []const u8,
    env: *const std.process.Environ.Map,
) noreturn {
    const self = std.process.executablePathAlloc(io, gpa) catch |err| fatal("{t}", .{err});
    const name = std.fs.path.basename(args[0]);
    var dirs = mem.tokenizeScalar(u8, env.get("PATH") orelse "", ':');
    while (dirs.next()) |dir| {
        const candidate = std.fs.path.join(gpa, &.{ dir, name }) catch fatal("oom", .{});
        const resolved = Io.Dir.cwd().realPathFileAlloc(io, candidate, gpa) catch continue;
        if (mem.eql(u8, resolved, self)) continue;
        var argv: std.ArrayList([]const u8) = .empty;
        argv.append(gpa, candidate) catch fatal("oom", .{});
        argv.appendSlice(gpa, args[1..]) catch fatal("oom", .{});
        const err = std.process.replace(io, .{ .argv = argv.items });
        fatal("{s}: {t}", .{ candidate, err });
    }
    fatal("no {s} on PATH but this check", .{name});
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err("tpm interpose: " ++ fmt, args);
    std.process.exit(1);
}

test "rewrite moves only the TPM socket, and names the boot drive for QMP" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const args = [_][]const u8{
        "qemu-system-aarch64",                       "-chardev",
        "socket,id=chrtpm,path=/run/tpm/swtpm.sock", "-chardev",
        "socket,id=con,path=/m/console.sock",        "-drive",
        "file=/m/werewolf-run/disk.img,format=raw",  "-tpmdev",
        "emulator,id=tpm0,chardev=chrtpm",
    };
    const all = try rewrite(gpa, &args, .{ .dir = "/p" });
    try std.testing.expectEqualStrings("/run/tpm/swtpm.sock", all.backend.?);
    try std.testing.expectEqualStrings("socket,id=chrtpm,path=/p/proxy.sock", all.args[2]);
    try std.testing.expectEqualStrings(args[4], all.args[4]);
    try std.testing.expectEqualStrings(args[6], all.args[6]);
    try std.testing.expectEqual(args.len, all.args.len);

    const other = try rewrite(gpa, &args, .{ .dir = "/p", .only = "/ww-second/" });
    try std.testing.expectEqual(null, other.backend);
    try std.testing.expectEqualStrings(args[2], other.args[2]);

    const watched = try rewrite(gpa, &args, .{
        .dir = "/p",
        .only = "/werewolf-run/",
        .monitor = "/werewolf-run/disk.img,",
    });
    try std.testing.expectEqualStrings(
        "file=/m/werewolf-run/disk.img,format=raw,node-name=" ++ node_name,
        watched.args[6],
    );
    try std.testing.expectEqualStrings("-qmp", watched.args[args.len]);
    try std.testing.expectEqualStrings(
        "unix:/p/qmp.sock,server=on,wait=off",
        watched.args[args.len + 1],
    );
}

test "increment selects only NV_Increment of a release floor" {
    var command = [_]u8{ 0x80, 0x02, 0, 0, 0, 22, 0, 0, 1, 0x34, 0x01, 0x50, 0, 7 } ++
        @as([8]u8, @splat(0));
    try std.testing.expect(increment(&command));
    command[11] = 0x40;
    try std.testing.expect(!increment(&command));
    command[11] = 0x50;
    command[9] = 0x35;
    try std.testing.expect(!increment(&command));
}

test "the proxy forwards a data channel and holds an armed increment before the TPM" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const backend_path = try gpa.print("{s}/tpm.sock", .{dir});
    const proxy_path = try gpa.print("{s}/proxy.sock", .{dir});
    var backend = try (try net.UnixAddress.init(backend_path)).listen(io, .{});
    defer backend.deinit(io);
    var proxy: Proxy = undefined;
    try proxy.start(io, gpa, proxy_path, backend_path, null);
    defer proxy.close();

    // QEMU's side: connect, hand over one end of a data channel.
    const qemu_control = try (try net.UnixAddress.init(proxy_path)).connect(io);
    defer qemu_control.close(io);
    const swtpm_control = try backend.accept(io);
    defer swtpm_control.close(io);
    var pair: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(
        .SUCCESS,
        posix.errno(posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &pair)),
    );
    const qemu_data = stream(pair[0]);
    defer qemu_data.close(io);
    var out: [net.cmsg.space(@sizeOf(posix.fd_t))]u8 align(net.cmsg_align) = @splat(0);
    const header: *align(net.cmsg_align) posix.cmsghdr = @ptrCast(&out);
    header.* = .{
        .len = net.cmsg.len(@sizeOf(posix.fd_t)),
        .level = posix.SOL.SOCKET,
        .type = posix.SCM.RIGHTS,
    };
    @memcpy(net.cmsg.data(header)[0..@sizeOf(posix.fd_t)], mem.asBytes(&pair[1]));
    try send(io, qemu_control, "\x00\x00\x00\x10", &out);
    stream(pair[1]).close(io);

    // swtpm's side: the same message, with the proxy's descriptor.
    var buf: [64]u8 = undefined;
    var ancillary: [net.cmsg.space(16)]u8 align(net.cmsg_align) = undefined;
    var data = [_][]u8{&buf};
    const got = try swtpm_control.readWithControl(io, &data, &ancillary);
    try std.testing.expectEqualStrings("\x00\x00\x00\x10", buf[0..got.data_len]);
    const swtpm_data = stream(passed(ancillary[0..got.control_len], got.control_truncated).?);
    defer swtpm_data.close(io);

    // An ordinary command passes through, and its response comes back.
    const startup = "\x80\x01\x00\x00\x00\x0c\x00\x00\x01\x44\x00\x00";
    try send(io, qemu_data, startup, &.{});
    var tpm_buf: [256]u8 = undefined;
    var tpm_reader = swtpm_data.reader(io, &tpm_buf);
    var seen: [max_packet]u8 = undefined;
    try std.testing.expectEqualStrings(startup, try packet(&tpm_reader.interface, &seen));
    const ok = "\x80\x01\x00\x00\x00\x0a\x00\x00\x00\x00";
    try send(io, swtpm_data, ok, &.{});
    var qemu_buf: [256]u8 = undefined;
    var qemu_reader = qemu_data.reader(io, &qemu_buf);
    try std.testing.expectEqualStrings(ok, try packet(&qemu_reader.interface, &seen));

    // An armed increment never reaches the TPM; cancel ends its channel.
    proxy.arm(.before);
    const bump = "\x80\x02\x00\x00\x00\x0e\x00\x00\x01\x34\x01\x50\x00\x07";
    try send(io, qemu_data, bump, &.{});
    try std.testing.expect(proxy.waitHit(.fromSeconds(10)));
    try std.testing.expectEqual(null, proxy.failed());
    proxy.cancel();
    try std.testing.expectError(error.EndOfStream, packet(&qemu_reader.interface, &seen));
    try std.testing.expectError(error.EndOfStream, packet(&tpm_reader.interface, &seen));
}
