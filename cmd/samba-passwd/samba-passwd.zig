//! samba-passwd.so answers getpwnam for the share users. smbpasswd refuses a
//! name that is not a UNIX account, and the root is read-only, so samba-init
//! writes those accounts to /run/svc/samba/passwd and smbd loads this first.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const accounts = "/run/svc/samba/passwd";

const Passwd = extern struct {
    pw_name: ?[*:0]u8 = null,
    pw_passwd: ?[*:0]u8 = null,
    pw_uid: u32 = 0,
    pw_gid: u32 = 0,
    pw_gecos: ?[*:0]u8 = null,
    pw_dir: ?[*:0]u8 = null,
    pw_shell: ?[*:0]u8 = null,
};

const GetpwnamR = *const fn ([*:0]const u8, *Passwd, [*]u8, usize, *?*Passwd) callconv(.c) c_int;
const GetpwuidR = *const fn (u32, *Passwd, [*]u8, usize, *?*Passwd) callconv(.c) c_int;

extern "c" fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) ?*anyopaque;
extern "c" fn __errno_location() *c_int;

fn setErrno(err: linux.E) void {
    const slot = if (builtin.os.tag == .linux) __errno_location() else std.c._errno();
    slot.* = @backingInt(err);
}

const rtld_next: ?*anyopaque = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

fn realName() ?GetpwnamR {
    const sym = dlsym(rtld_next, "getpwnam_r") orelse return null;
    return @ptrCast(@alignCast(sym));
}

fn realUid() ?GetpwuidR {
    const sym = dlsym(rtld_next, "getpwuid_r") orelse return null;
    return @ptrCast(@alignCast(sym));
}

/// found is one account, its fields pointing into the line it was parsed from.
const Found = struct { name: []const u8, uid: u32, gid: u32, dir: []const u8, shell: []const u8 };

fn parseLine(line: []const u8) ?Found {
    var f: [7][]const u8 = undefined;
    var n: usize = 0;
    var rest = line;
    while (n < 7) {
        const cut = std.mem.findScalar(u8, rest, ':') orelse {
            f[n] = rest;
            n += 1;
            break;
        };
        f[n] = rest[0..cut];
        n += 1;
        rest = rest[cut + 1 ..];
    }
    if (n != 7 or f[0].len == 0) return null;
    return .{
        .name = f[0],
        .uid = std.fmt.parseInt(u32, f[2], 10) catch return null,
        .gid = std.fmt.parseInt(u32, f[3], 10) catch return null,
        .dir = f[5],
        .shell = f[6],
    };
}

fn matches(have: Found, name: []const u8) bool {
    return std.mem.eql(u8, have.name, name);
}

fn matchesUid(have: Found, uid: u32) bool {
    return have.uid == uid;
}

/// search reads the accounts file and returns the line pred accepts, copied
/// into buf so the caller can keep it.
fn search(buf: []u8, key: anytype, comptime pred: fn (Found, @TypeOf(key)) bool) ?Found {
    var file: [8192]u8 = undefined;
    const fd = linux.open(accounts, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return null;
    defer _ = linux.close(@intCast(fd));
    const n = linux.read(@intCast(fd), &file, file.len);
    if (linux.errno(n) != .SUCCESS or n == 0 or n == file.len) return null;
    var lines = std.mem.splitScalar(u8, file[0..n], '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const have = parseLine(line) orelse continue;
        if (!pred(have, key)) continue;
        if (line.len + 1 > buf.len) return null;
        @memcpy(buf[0..line.len], line);
        buf[line.len] = 0;
        return parseLine(buf[0..line.len]);
    }
    return null;
}

fn fill(into: []u8, pwd: *Passwd, have: Found) bool {
    // name, "x", gecos (empty), dir, shell, each with a trailing NUL.
    const need = have.name.len + 1 + 2 + 1 + have.dir.len + 1 + have.shell.len + 1;
    if (need > into.len) return false;
    var at: usize = 0;
    const name = place(into, &at, have.name);
    const pass = place(into, &at, "x");
    const gecos = place(into, &at, "");
    const dir = place(into, &at, have.dir);
    const shell = place(into, &at, have.shell);
    pwd.* = .{
        .pw_name = name,
        .pw_passwd = pass,
        .pw_uid = have.uid,
        .pw_gid = have.gid,
        .pw_gecos = gecos,
        .pw_dir = dir,
        .pw_shell = shell,
    };
    return true;
}

fn place(into: []u8, at: *usize, text: []const u8) [*:0]u8 {
    const start = at.*;
    @memcpy(into[start..][0..text.len], text);
    into[start + text.len] = 0;
    at.* = start + text.len + 1;
    return @ptrCast(into[start..].ptr);
}

fn lookupName(name: [*:0]const u8, buf: [*]u8, len: usize, pwd: *Passwd) ?bool {
    var raw: [512]u8 = undefined;
    const have = search(&raw, std.mem.span(name), matches) orelse return null;
    if (!fill(buf[0..len], pwd, have)) return false;
    return true;
}

fn lookupUid(uid: u32, buf: [*]u8, len: usize, pwd: *Passwd) ?bool {
    var raw: [512]u8 = undefined;
    const have = search(&raw, uid, matchesUid) orelse return null;
    if (!fill(buf[0..len], pwd, have)) return false;
    return true;
}

export fn getpwnam_r(
    name: [*:0]const u8,
    pwd: *Passwd,
    buf: [*]u8,
    len: usize,
    result: *?*Passwd,
) c_int {
    result.* = null;
    if (lookupName(name, buf, len, pwd)) |ok| {
        if (!ok) {
            setErrno(.RANGE);
            return @backingInt(linux.E.RANGE);
        }
        result.* = pwd;
        return 0;
    }
    const next = realName() orelse {
        setErrno(.NOENT);
        return @backingInt(linux.E.NOENT);
    };
    return next(name, pwd, buf, len, result);
}

export fn getpwuid_r(uid: u32, pwd: *Passwd, buf: [*]u8, len: usize, result: *?*Passwd) c_int {
    result.* = null;
    if (lookupUid(uid, buf, len, pwd)) |ok| {
        if (!ok) {
            setErrno(.RANGE);
            return @backingInt(linux.E.RANGE);
        }
        result.* = pwd;
        return 0;
    }
    const next = realUid() orelse {
        setErrno(.NOENT);
        return @backingInt(linux.E.NOENT);
    };
    return next(uid, pwd, buf, len, result);
}

var once_name: Passwd = .{};
var once_name_buf: [512]u8 = undefined;
var once_uid: Passwd = .{};
var once_uid_buf: [512]u8 = undefined;

export fn getpwnam(name: [*:0]const u8) ?*Passwd {
    var result: ?*Passwd = null;
    if (getpwnam_r(name, &once_name, &once_name_buf, once_name_buf.len, &result) != 0) return null;
    return result;
}

export fn getpwuid(uid: u32) ?*Passwd {
    var result: ?*Passwd = null;
    if (getpwuid_r(uid, &once_uid, &once_uid_buf, once_uid_buf.len, &result) != 0) return null;
    return result;
}

test "a share account is a passwd line" {
    const have = parseLine("alice:x:70000:9::/var/empty:/sbin/nologin").?;
    try std.testing.expectEqualStrings("alice", have.name);
    try std.testing.expectEqual(@as(u32, 70000), have.uid);
    try std.testing.expectEqualStrings("/sbin/nologin", have.shell);
    try std.testing.expect(parseLine("short") == null);
}
