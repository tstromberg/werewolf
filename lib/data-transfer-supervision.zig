//! Read-only evidence that application writers stayed administratively down.
//! There is no service-control descriptor and no stop/restart operation here.
const std = @import("std");
const data = @import("data-transfer.zig");
const Io = std.Io;
const Dir = Io.Dir;
const mem = std.mem;
const A = mem.Allocator;

pub const Stamp = struct { path: []const u8, stat: Io.File.Stat };

pub fn capture(io: Io, a: A, supervise: Dir, cgroups: Dir, services: []const []const u8) ![]Stamp {
    if (services.len > 4096) return error.TransferService;
    const stamps = try a.alloc(Stamp, services.len);
    errdefer a.free(stamps);
    for (services, stamps) |name, *stamp| {
        stamp.* = try snapshot(io, a, supervise, name);
        // A down main process is insufficient while descendants still write.
        var parent = try data.parentDir(io, cgroups, try a.print("{s}/cgroup.procs", .{name}));
        defer parent.close(io);
        const file = try data.openRegular(io, parent, "cgroup.procs");
        defer file.close(io);
        // cgroupfs reports size zero even when processes remain. A positional
        // reader can treat that size as EOF; read the bounded stream instead.
        var buffer: [4096]u8 = undefined;
        var reader = file.readerStreaming(io, &buffer);
        const procs = try reader.interface.allocRemaining(a, .limited(64 << 10));
        defer a.free(procs);
        if (mem.trim(u8, procs, " \t\r\n").len != 0) return error.TransferWritersRunning;
    }
    return stamps;
}

pub fn snapshot(io: Io, a: A, supervise: Dir, name: []const u8) !Stamp {
    if (!data.validName(name)) return error.TransferService;
    const path = try a.print("supervise.{s}/status", .{name});
    var parent = try data.parentDir(io, supervise, path);
    defer parent.close(io);
    const file = try data.openRegular(io, parent, "status");
    defer file.close(io);
    const st = try file.stat(io);
    if (st.size != 20 or st.permissions.toMode() & 0o7022 != 0)
        return error.TransferSupervision;
    if (@import("builtin").os.tag == .linux) {
        const owner = try data.metadata.owner(null, file);
        if (owner.uid != 0 or owner.gid != 0) return error.TransferSupervision;
    }
    var status: [20]u8 = undefined;
    if (try file.readPositionalAll(io, &status, 0) != status.len)
        return error.TransferSupervision;
    try stopped(&status);
    return .{ .path = path, .stat = st };
}

pub fn unchanged(io: Io, supervise: Dir, stamps: []const Stamp) !void {
    for (stamps) |stamp| {
        const now = try supervise.statFile(io, stamp.path, .{ .follow_symlinks = false });
        const old = stamp.stat;
        // runsv replaces status on transitions. Even a complete up/down cycle
        // during capture invalidates the result, regardless of its final state.
        if (now.kind != .file or now.inode != old.inode or now.size != old.size or
            now.nlink != old.nlink or now.permissions.toMode() != old.permissions.toMode() or
            !std.meta.eql(now.mtime, old.mtime) or !std.meta.eql(now.ctime, old.ctime))
            return error.TransferWritersChanged;
    }
}

pub fn stopped(status: *const [20]u8) !void {
    // runsv: TAI64N[12], little-endian PID[4], paused, wanted, TERM, state.
    if (mem.readInt(u32, status[12..16], .little) != 0 or status[16] != 0 or
        status[17] != 'd' or status[19] != 0) return error.TransferWritersRunning;
}

test "capture requires wanted-down, no process and no remaining cgroup writers" {
    const t = std.testing;
    var status: [20]u8 = @splat(0);
    try t.expectError(error.TransferWritersRunning, stopped(&status));
    status[17] = 'u';
    try t.expectError(error.TransferWritersRunning, stopped(&status));
    status[17] = 'd';
    try stopped(&status);
    status[12] = 42;
    try t.expectError(error.TransferWritersRunning, stopped(&status));
    status[12] = 0;
    status[19] = 2;
    try t.expectError(error.TransferWritersRunning, stopped(&status));
}

test "even a completed writer restart invalidates a capture" {
    // Linux root metadata enforcement is exercised by the appliance matrix.
    if (@import("builtin").os.tag == .linux and std.os.linux.geteuid() != 0)
        return error.SkipZigTest;
    const t = std.testing;
    const io = t.io;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "supervise.postgres");
    try tmp.dir.createDirPath(io, "postgres");
    try tmp.dir.writeFile(io, .{ .sub_path = "postgres/cgroup.procs", .data = "" });
    var status: [20]u8 = @splat(0);
    status[17] = 'd';
    try tmp.dir.writeFile(
        io,
        .{
            .sub_path = "supervise.postgres/status",
            .data = &status,
            .flags = .{ .permissions = .fromMode(0o600) },
        },
    );
    const stamps = try capture(io, arena.allocator(), tmp.dir, tmp.dir, &.{"postgres"});
    try unchanged(io, tmp.dir, stamps);
    try tmp.dir.writeFile(
        io,
        .{
            .sub_path = "supervise.postgres/status.new",
            .data = &status,
            .flags = .{ .permissions = .fromMode(0o600) },
        },
    );
    try tmp.dir.rename("supervise.postgres/status.new", tmp.dir, "supervise.postgres/status", io);
    try t.expectError(error.TransferWritersChanged, unchanged(io, tmp.dir, stamps));
    try tmp.dir.writeFile(io, .{ .sub_path = "postgres/cgroup.procs", .data = "42\n" });
    try t.expectError(
        error.TransferWritersRunning,
        capture(io, arena.allocator(), tmp.dir, tmp.dir, &.{"postgres"}),
    );
}
