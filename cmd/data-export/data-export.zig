//! Fixed SSH operations on an explicitly enabled image. Export is read-only;
//! separate owner requests stop or start one named application service.
const std = @import("std");
const data = @import("data-transfer");
const source = @import("data-source");
const read = @import("data-read");
const sandbox = @import("sandbox");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const mem = std.mem;

pub const greeting = "WWEXPORT1\n";
const Request = struct { action: enum { capture, down, up }, service: ?[]const u8 };
var phase: []const u8 = "invocation";

fn request(command: []const u8) !Request {
    for ([_]struct { []const u8, @FieldType(Request, "action") }{
        .{ "service-down-v1 ", .down }, .{ "service-up-v1 ", .up },
    }) |verb| if (mem.cutPrefix(u8, command, verb[0])) |name| {
        if (!data.validName(name)) return error.TransferService;
        return .{ .action = verb[1], .service = name };
    };
    return .{ .action = .capture, .service = try scope(command) };
}

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var line: [256]u8 = undefined;
        const message = std.mem.print(&line, "data-export: {s}: {s}; keep application writers down until export exits\n", .{ phase, @errorName(err) }) catch unreachable;
        File.stderr().writeStreamingAll(init.io, message) catch {};
        std.process.exit(1);
    };
}

pub fn scope(command: []const u8) !?[]const u8 {
    if (mem.eql(u8, command, "export-v1")) return null;
    const name = mem.cutPrefix(u8, command, "export-v1 ") orelse return error.TransferInvocation;
    if (!data.validName(name)) return error.TransferService;
    return name;
}

fn run(init: std.process.Init) !void {
    var threaded: Io.Threaded = .init_single_threaded;
    threaded.allocator = init.arena.allocator();
    defer threaded.deinit();
    const io = threaded.io();
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 3 or !mem.eql(u8, args[1], "-c") or
        !mem.eql(u8, args[2], "export-v1") or linux.getuid() != 0)
        return error.TransferInvocation;
    const operation = try request(init.environ_map.get("SSH_ORIGINAL_COMMAND") orelse return error.TransferInvocation);
    const service = operation.service;
    sandbox.tieTo(linux.getppid());
    try sandbox.limit(.AS, 1 << 30);
    // A stalled connection cannot retain this reader indefinitely. setitimer
    // uses seconds here (the fractional fields are zero on both supported ABIs).
    _ = try sandbox.sys(linux.setitimer(0, &.{ .it_interval = .{ .sec = 0, .nsec = 0 }, .it_value = .{ .sec = 12 * 3600, .nsec = 0 } }, null), "export deadline");
    phase = "transfer lock";
    const lock_fd = try std.posix.openat(linux.AT.FDCWD, "/run/runit/data-export.lock", .{
        .ACCMODE = .RDONLY,
        .CREAT = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0o600);
    const lock: File = .{ .handle = lock_fd, .flags = .{ .nonblocking = false } };
    defer lock.close(io);
    const lock_stat = try lock.stat(io);
    if (lock_stat.kind != .file or lock_stat.nlink != 1 or lock_stat.permissions.toMode() & 0o7777 != 0o600)
        return error.TransferLock;
    const lock_owner = try data.metadata.owner(null, lock);
    if (lock_owner.uid != 0 or lock_owner.gid != 0) return error.TransferLock;
    try lock.lock(io, .exclusive);
    defer lock.unlock(io);
    phase = "data directory";
    var root = try Dir.cwd().openDir(io, "/data", .{ .iterate = true, .follow_symlinks = false });
    defer root.close(io);
    phase = "source policy";
    const policy = try currentPolicy(io, a, root);
    if (service) |name| if (!policy.serviceAllowed(name)) return error.TransferService;
    phase = "supervision directory";
    var supervision = try Dir.cwd().openDir(io, "/run/runit", .{ .follow_symlinks = false });
    defer supervision.close(io);
    if (operation.action != .capture) {
        phase = "service control";
        try serviceRequest(io, a, supervision, service.?, operation.action == .down);
        return;
    }
    phase = "stopped writers";
    const app_stamps = blk: {
        var cgroups = try Dir.cwd().openDir(io, "/run/cgroup/svc", .{ .follow_symlinks = false });
        defer cgroups.close(io);
        const captured = try a.alloc(data.supervision.Stamp, policy.services.len);
        for (policy.services, captured) |name, *stamp| {
            phase = try a.print("stopped writer {s}", .{name});
            const one = try data.supervision.capture(io, a, supervision, cgroups, &.{name});
            stamp.* = one[0];
            a.free(one);
        }
        break :blk captured;
    };
    // The one-shot posture check can write its disposable /data probes. It
    // must have published its report and parked before capture can begin.
    phase = "posture completion";
    _ = try Dir.cwd().statFile(io, "/run/werewolf/posture.json", .{ .follow_symlinks = false });
    const stamps = try a.alloc(data.supervision.Stamp, app_stamps.len + 1);
    @memcpy(stamps[0..app_stamps.len], app_stamps);
    stamps[app_stamps.len] = try data.supervision.snapshot(io, a, supervision, "posture");
    phase = "PostgreSQL shutdown";
    if (service == null or mem.eql(u8, service.?, "postgres"))
        try source.cleanPostgres(io, a, root, true);
    // Everything below is read-only. Policy and PostgreSQL control bytes were
    // obtained through pinned descriptors; no archive or path is supplied here.
    const text = try std.json.Stringify.valueAlloc(a, policy, .{});
    if (text.len > 1 << 20) return error.TransferLimit;
    var length: [4]u8 = undefined;
    mem.writeInt(u32, &length, @intCast(text.len), .big);
    try File.stdout().writeStreamingAll(io, greeting);
    try File.stdout().writeStreamingAll(io, &length);
    try File.stdout().writeStreamingAll(io, text);
    var env = std.process.Environ.Map.init(a);
    var compressor = try std.process.spawn(io, .{
        .argv = &.{ "/usr/lib/werewolf/data-transfer-tool", "compress-session" },
        .environ_map = &env,
        .stdin = .pipe,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    defer compressor.kill(io);
    const pipe = compressor.stdin.?;
    compressor.stdin = null;
    var pipe_open = true;
    defer if (pipe_open) pipe.close(io);
    phase = "reader confinement";
    root = try read.confine(io, root, service, .{
        .session = true,
        .child = @intCast(compressor.id.?),
        .keep = &.{ pipe.handle, supervision.handle, lock.handle },
    });
    const owners: data.Ownership = .{ .get = data.metadata.owner };
    phase = "data scan";
    const manifest = try data.scan(io, a, root, policy, service, owners);
    var buf: [64 << 10]u8 = undefined;
    var output = pipe.writerStreaming(io, &buf);
    phase = "archive stream";
    _ = try data.emit(io, a, root, manifest, policy, owners, &output.interface);
    try output.interface.flush();
    try data.supervision.unchanged(io, supervision, stamps);
    pipe.close(io);
    pipe_open = false;
    if (!(try compressor.wait(io)).success()) return error.TransferCompression;
    try data.supervision.unchanged(io, supervision, stamps);
}

fn serviceRequest(io: Io, a: mem.Allocator, supervision: Dir, name: []const u8, down: bool) !void {
    const path = try a.print("supervise.{s}/control", .{name});
    var parent = try data.parentDir(io, supervision, path);
    defer parent.close(io);
    const fd = try std.posix.openat(parent.handle, "control", .{
        .ACCMODE = .WRONLY,
        .NONBLOCK = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    const file: File = .{ .handle = fd, .flags = .{ .nonblocking = true } };
    if ((try file.stat(io)).kind != .named_pipe) {
        file.close(io);
        return error.TransferSupervision;
    }
    file.writeStreamingAll(io, if (down) "d" else "u") catch |err| {
        file.close(io);
        return err;
    };
    file.close(io);
    // No KILL, dependency expansion, saved state or automatic restart. This
    // operation is an explicit owner request and never runs in the data reader.
    if (down) {
        var cgroups = try Dir.cwd().openDir(io, "/run/cgroup/svc", .{ .follow_symlinks = false });
        defer cgroups.close(io);
        var stopped_cleanly = false;
        for (0..600) |_| {
            if (data.supervision.capture(io, a, supervision, cgroups, &.{name})) |_| {
                stopped_cleanly = true;
                break;
            } else |err| switch (err) {
                error.TransferWritersRunning => {},
                else => return err,
            }
            try io.sleep(.fromMilliseconds(100), .awake);
        }
        if (!stopped_cleanly) return error.TransferServiceTimeout;
    }
    try File.stdout().writeStreamingAll(io, if (down) "service stopped\n" else "service start requested\n");
}

fn currentPolicy(io: Io, a: mem.Allocator, root: Dir) !data.Policy {
    var image_dir = try Dir.cwd().openDir(io, "/", .{});
    defer image_dir.close(io);
    try data.images.requireBarrier(io, image_dir);
    var parent = try data.parentDir(io, root, data.images.record_path);
    defer parent.close(io);
    const file = try data.openRegular(io, parent, "data-image");
    defer file.close(io);
    var identity: [65]u8 = undefined;
    if (try file.readPositionalAll(io, &identity, 0) != 65 or identity[64] != '\n')
        return error.TransferImage;
    const image = try a.dupe(u8, identity[0..64]);
    try data.images.requireRecorded(io, root, image);
    const arch: data.Arch = switch (@import("builtin").cpu.arch) {
        .aarch64 => .aarch64,
        .x86_64 => .x86_64,
        else => return error.TransferArchitecture,
    };
    return source.catalog(io, a, image_dir, root, .{ .image = image, .arch = arch }, false);
}

test "forced command accepts only one exact export scope" {
    const t = std.testing;
    try t.expectEqual(@as(?[]const u8, null), try scope("export-v1"));
    try t.expectEqualStrings("plex", (try scope("export-v1 plex")).?);
    for ([_][]const u8{ "sh", "export-v1;id", "export-v1 ../plex", "export-v1 plex extra", "export-v1\n" }) |word|
        if (scope(word)) |_| return error.AcceptedCommand else |_| {};
}

test "manual service requests accept exactly one bounded name" {
    const t = std.testing;
    try t.expectEqual(.down, (try request("service-down-v1 postgres")).action);
    try t.expectEqual(.up, (try request("service-up-v1 plex")).action);
    try t.expectEqualStrings("plex", (try request("service-up-v1 plex")).service.?);
    for ([_][]const u8{ "service-down-v1", "service-up-v1 ", "service-down-v1 ../plex", "service-up-v1 plex;id", "service-up-v1 plex extra", "service-down-v1 plex\n" }) |word|
        if (request(word)) |_| return error.AcceptedCommand else |_| {};
}
