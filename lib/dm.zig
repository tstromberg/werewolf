//! dm: the device mapper, through its ioctls (linux/dm-ioctl.h), for the
//! programs that run before any tool could: stage0 opens the root through
//! dm-verity, and the mount broker removes /data's LUKS mapping at
//! shutdown, as `dmsetup create` and `cryptsetup close` would.

const std = @import("std");
const linux = std.os.linux;

/// The kernel's struct dm_ioctl, version 4.
const Ioctl = extern struct {
    version: [3]u32 = .{ 4, 0, 0 },
    data_size: u32 = @sizeOf(Ioctl),
    data_start: u32 = @sizeOf(Ioctl),
    target_count: u32 = 0,
    open_count: i32 = 0,
    flags: u32 = 0,
    event_nr: u32 = 0,
    padding: u32 = 0,
    dev: u64 = 0,
    name: [128]u8 = @splat(0),
    uuid: [129]u8 = @splat(0),
    data: [7]u8 = @splat(0),
};

/// The kernel's struct dm_target_spec, which a table load's targets follow
/// the header as, each with its parameters after it.
const TargetSpec = extern struct {
    sector_start: u64 = 0,
    length: u64,
    status: i32 = 0,
    next: u32 = 0,
    target_type: [16]u8 = @splat(0),
};

const readonly_flag = 1 << 0;

/// _IOWR(0xfd, nr, struct dm_ioctl).
fn request(nr: u8) u32 {
    return 0xc0000000 | (@as(u32, @sizeOf(Ioctl)) << 16) | (0xfd << 8) | nr;
}
const dev_create = request(3);
pub const dev_remove = request(4);
const dev_suspend = request(6);
const table_load = request(9);

/// A device named name, read-only, of sectors 512-byte sectors, all mapped
/// by one target of kind with params, and live: created, loaded and
/// resumed. Its device number, encoded as mknod takes one.
/// The kernel says why on the console when it refuses a table.
pub fn create(name: []const u8, kind: []const u8, sectors: u64, params: []const u8) !linux.dev_t {
    if (name.len >= 128 or kind.len >= 16) return error.NameTooLong;
    const ctl = try control();
    defer _ = linux.close(ctl);

    var io = named(name);
    try call(ctl, dev_create, &io, error.Create);
    errdefer _ = remove(name);

    // The header, one target, its parameters with their NUL, 8-byte aligned.
    var buf: [@sizeOf(Ioctl) + @sizeOf(TargetSpec) + 512]u8 align(8) = @splat(0);
    const params_at = @sizeOf(Ioctl) + @sizeOf(TargetSpec);
    if (params.len + 1 > buf.len - params_at) return error.ParamsTooLong;
    const size = std.mem.alignForward(usize, params_at + params.len + 1, 8);
    const head: *Ioctl = @ptrCast(&buf);
    head.* = named(name);
    head.data_size = @intCast(size);
    head.target_count = 1;
    head.flags = readonly_flag;
    const spec: *align(8) TargetSpec = @ptrCast(buf[@sizeOf(Ioctl)..]);
    spec.* = .{ .length = sectors };
    @memcpy(spec.target_type[0..kind.len], kind);
    @memcpy(buf[params_at..][0..params.len], params);
    try call(ctl, table_load, head, error.TableLoad);

    // Without the suspend flag, DM_DEV_SUSPEND resumes: the loaded table goes
    // live.
    io = named(name);
    try call(ctl, dev_suspend, &io, error.Resume);
    return std.math.cast(linux.dev_t, io.dev) orelse error.DeviceNumber;
}

/// The device named name removed, and whatever its table held with it: a
/// LUKS mapping's key. Whether there was one.
pub fn remove(name: []const u8) bool {
    if (name.len >= 128) return false;
    const ctl = control() catch return false;
    defer _ = linux.close(ctl);
    var io = named(name);
    return linux.errno(linux.ioctl(ctl, dev_remove, @intFromPtr(&io))) == .SUCCESS;
}

fn named(name: []const u8) Ioctl {
    var io: Ioctl = .{};
    @memcpy(io.name[0..name.len], name);
    return io;
}

fn control() !i32 {
    const fd = linux.openat(
        linux.AT.FDCWD,
        "/dev/mapper/control",
        .{ .ACCMODE = .RDWR, .CLOEXEC = true },
        0,
    );
    if (linux.errno(fd) != .SUCCESS) return error.NoControl;
    return @intCast(fd);
}

fn call(ctl: i32, req: u32, io: *Ioctl, comptime err: anyerror) !void {
    if (linux.errno(linux.ioctl(ctl, req, @intFromPtr(io))) != .SUCCESS) return err;
}

const testing = std.testing;

test Ioctl {
    try testing.expectEqual(312, @sizeOf(Ioctl));
    try testing.expectEqual(40, @sizeOf(TargetSpec));
    try testing.expectEqual(0xc138fd04, dev_remove);
    try testing.expectEqual(0xc138fd09, table_load);
}
