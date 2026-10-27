//! Forced SSH operation on an explicitly enabled image. It never controls
//! services. The authenticated owner must keep all application writers down.
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

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var line: [256]u8 = undefined;
        const message = std.mem.print(&line, "data-export: {s}; application writers must remain administratively down until export exits\n", .{@errorName(err)}) catch unreachable;
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
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 3 or !mem.eql(u8, args[1], "-c") or
        !mem.eql(u8, args[2], "export-v1") or linux.getuid() != 0)
        return error.TransferInvocation;
    const service = try scope(init.environ_map.get("SSH_ORIGINAL_COMMAND") orelse return error.TransferInvocation);
    sandbox.tieTo(linux.getppid());
    // A stalled connection cannot retain this reader indefinitely. setitimer
    // uses seconds here (the fractional fields are zero on both supported ABIs).
    _ = try sandbox.sys(linux.setitimer(0, &.{ .it_interval = .{ .sec = 0, .nsec = 0 }, .it_value = .{ .sec = 12 * 3600, .nsec = 0 } }, null), "export deadline");
    const lock = try Dir.cwd().createFile(io, "/run/werewolf/export.lock", .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer lock.close(io);
    try lock.lock(io, .exclusive);
    defer lock.unlock(io);
    var root = try Dir.cwd().openDir(io, "/data", .{ .iterate = true, .follow_symlinks = false });
    defer root.close(io);
    const policy = try currentPolicy(io, a, root);
    if (service) |name| if (!policy.serviceAllowed(name)) return error.TransferService;
    var supervision = try Dir.cwd().openDir(io, "/run/runit", .{ .follow_symlinks = false });
    defer supervision.close(io);
    const stamps = blk: {
        var cgroups = try Dir.cwd().openDir(io, "/run/cgroup/svc", .{ .follow_symlinks = false });
        defer cgroups.close(io);
        break :blk try data.supervision.capture(io, a, supervision, cgroups, policy.services);
    };
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
    root = try read.confine(io, root, service, .{
        .session = true,
        .child = @intCast(compressor.id.?),
        .keep = &.{ pipe.handle, supervision.handle, lock.handle },
    });
    const owners: data.Ownership = .{ .get = data.metadata.owner };
    const manifest = try data.scan(io, a, root, policy, service, owners);
    var buf: [64 << 10]u8 = undefined;
    var output = pipe.writerStreaming(io, &buf);
    _ = try data.emit(io, a, root, manifest, policy, owners, &output.interface);
    try output.interface.flush();
    try data.supervision.unchanged(io, supervision, stamps);
    pipe.close(io);
    pipe_open = false;
    if (!(try compressor.wait(io)).success()) return error.TransferCompression;
    try data.supervision.unchanged(io, supervision, stamps);
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
