//! paperless-group.so is preloaded into the four Paperless processes.
//! SQLite creates its database and journal with mode 0644, which has no
//! group write, so a directory ACL cannot grant it and the user who
//! created the journal is the only one who can write it. New files in
//! the library get the group write bit.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

// O_CREAT, the bit that means the call passes a mode.
const o_creat: c_int = 0o100;

const Open = *const fn ([*:0]const u8, c_int, c_uint) callconv(.c) c_int;
const OpenAt = *const fn (c_int, [*:0]const u8, c_int, c_uint) callconv(.c) c_int;

extern "c" fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) ?*anyopaque;
extern "c" fn __errno_location() *c_int;

const rtld_next: ?*anyopaque = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

fn setErrno(err: linux.E) void {
    const slot = if (builtin.os.tag == .linux) __errno_location() else std.c._errno();
    slot.* = @intFromEnum(err);
}

fn library(path: []const u8) bool {
    return std.mem.eql(u8, path, "/data/svc/paperless") or
        std.mem.startsWith(u8, path, "/data/svc/paperless/");
}

fn modeFor(path: [*:0]const u8, flags: c_int, mode: c_uint) c_uint {
    if (flags & o_creat == 0) return mode;
    if (!library(std.mem.span(path))) return mode;
    return mode | 0o020;
}

// dlsym calls open, so the first lookup cannot call back into itself.
var resolving: bool = false;

fn resolve(comptime name: [*:0]const u8, comptime T: type) ?T {
    const found = &(struct { var next: ?T = null; }).next;
    if (found.*) |f| return f;
    if (resolving) return null;
    resolving = true;
    defer resolving = false;
    const sym = dlsym(rtld_next, name) orelse return null;
    const f: T = @ptrCast(@alignCast(sym));
    found.* = f;
    return f;
}

const at_fdcwd: usize = @bitCast(@as(isize, -100));

fn sysOpenAt(dirfd: usize, path: [*:0]const u8, flags: c_int, mode: c_uint) c_int {
    if (comptime builtin.os.tag != .linux) {
        setErrno(.NOSYS);
        return -1;
    }
    const rc = linux.syscall4(
        .openat,
        dirfd,
        @intFromPtr(path),
        @as(usize, @bitCast(@as(isize, flags))),
        mode,
    );
    const s: isize = @bitCast(rc);
    if (s < 0) {
        setErrno(@enumFromInt(@as(u16, @intCast(-s))));
        return -1;
    }
    return @intCast(s);
}

fn openAs(comptime name: [*:0]const u8, path: [*:0]const u8, flags: c_int, mode: c_uint) c_int {
    const mode2 = modeFor(path, flags, mode);
    if (resolve(name, Open)) |f| return f(path, flags, mode2);
    if (resolving) return sysOpenAt(at_fdcwd, path, flags, mode2);
    setErrno(.NOSYS);
    return -1;
}

fn openAtAs(comptime name: [*:0]const u8, dirfd: c_int, path: [*:0]const u8, flags: c_int, mode: c_uint) c_int {
    const mode2 = modeFor(path, flags, mode);
    if (resolve(name, OpenAt)) |f| return f(dirfd, path, flags, mode2);
    if (resolving) return sysOpenAt(@as(usize, @bitCast(@as(isize, dirfd))), path, flags, mode2);
    setErrno(.NOSYS);
    return -1;
}

export fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int {
    return openAs("open", path, flags, mode);
}

export fn open64(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int {
    return openAs("open64", path, flags, mode);
}

const Creat = *const fn ([*:0]const u8, c_uint) callconv(.c) c_int;
const o_wronly: c_int = 1;
const o_trunc: c_int = 0o1000;

fn creatAs(comptime name: [*:0]const u8, path: [*:0]const u8, mode: c_uint) c_int {
    const mode2 = modeFor(path, o_creat, mode);
    if (resolve(name, Creat)) |f| return f(path, mode2);
    if (resolving) return sysOpenAt(at_fdcwd, path, o_creat | o_wronly | o_trunc, mode2);
    setErrno(.NOSYS);
    return -1;
}

export fn creat(path: [*:0]const u8, mode: c_uint) c_int {
    return creatAs("creat", path, mode);
}

export fn creat64(path: [*:0]const u8, mode: c_uint) c_int {
    return creatAs("creat64", path, mode);
}

export fn openat(dirfd: c_int, path: [*:0]const u8, flags: c_int, mode: c_uint) c_int {
    return openAtAs("openat", dirfd, path, flags, mode);
}

export fn openat64(dirfd: c_int, path: [*:0]const u8, flags: c_int, mode: c_uint) c_int {
    return openAtAs("openat64", dirfd, path, flags, mode);
}

test "the library's new files are group writable" {
    try std.testing.expectEqual(@as(c_uint, 0o664), modeFor("/data/svc/paperless/db.sqlite3", o_creat, 0o644));
    try std.testing.expectEqual(@as(c_uint, 0o664), modeFor("/data/svc/paperless/db.sqlite3-wal", o_creat, 0o644));
    try std.testing.expectEqual(@as(c_uint, 0o644), modeFor("/tmp/db.sqlite3", o_creat, 0o644));
    try std.testing.expectEqual(@as(c_uint, 0o644), modeFor("/data/svc/paperless/db.sqlite3", 0, 0o644));
}
