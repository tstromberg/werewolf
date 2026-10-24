//! Compatibility adapter: Plex has no setting for its main bind address.
//! Fence still enforces loopback-only ingress independently of this library.
const std = @import("std");
const linux = std.os.linux;
extern fn __errno_location() *c_int;

fn datagram(fd: c_int) bool {
    var kind: c_int = 0;
    var size: linux.socklen_t = @sizeOf(c_int);
    return linux.errno(linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.TYPE, @ptrCast(&kind), &size)) == .SUCCESS and
        kind == linux.SOCK.DGRAM;
}

export fn bind(fd: c_int, address: *const linux.sockaddr, length: linux.socklen_t) c_int {
    var v4: linux.sockaddr.in = undefined;
    var v6: linux.sockaddr.in6 = undefined;
    var target = address;
    if (address.family == linux.AF.INET and length == @sizeOf(linux.sockaddr.in)) {
        v4 = @as(*const linux.sockaddr.in, @ptrCast(@alignCast(address))).*;
        if (v4.port == std.mem.nativeToBig(u16, 32400) or datagram(fd)) {
            v4.addr = @bitCast([4]u8{ 127, 0, 0, 1 });
            target = @ptrCast(&v4);
        }
    } else if (address.family == linux.AF.INET6 and length == @sizeOf(linux.sockaddr.in6)) {
        v6 = @as(*const linux.sockaddr.in6, @ptrCast(@alignCast(address))).*;
        if (v6.port == std.mem.nativeToBig(u16, 32400) or datagram(fd)) {
            v6.addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
            target = @ptrCast(&v6);
        }
    }
    return checked(linux.bind(fd, target, length));
}

// Some discovery code sends on a fresh socket without calling bind. Bind it
// locally before the kernel can assign a wildcard source address. The firewall
// still denies discovery traffic; this only controls socket binding.
fn bindDatagram(fd: c_int) bool {
    if (!datagram(fd)) return true;
    var addr: linux.sockaddr.storage = undefined;
    var len: linux.socklen_t = @sizeOf(@TypeOf(addr));
    if (checked(linux.getsockname(fd, @ptrCast(&addr), &len)) < 0) return false;
    if (addr.family == linux.AF.INET) {
        const v4: *const linux.sockaddr.in = @ptrCast(@alignCast(&addr));
        if (v4.port == 0) return bind(fd, @ptrCast(&addr), len) == 0;
    } else if (addr.family == linux.AF.INET6) {
        const v6: *const linux.sockaddr.in6 = @ptrCast(@alignCast(&addr));
        if (v6.port == 0) return bind(fd, @ptrCast(&addr), len) == 0;
    }
    return true;
}

export fn connect(fd: c_int, addr: *const linux.sockaddr, len: linux.socklen_t) c_int {
    if (!bindDatagram(fd)) return -1;
    return checked(linux.connect(fd, addr, len));
}

export fn sendto(fd: c_int, buf: [*]const u8, len: usize, flags: c_uint, addr: ?*const linux.sockaddr, addrlen: linux.socklen_t) isize {
    if (!bindDatagram(fd)) return -1;
    return checkedWide(linux.sendto(fd, buf, len, flags, addr, addrlen));
}

export fn sendmsg(fd: c_int, msg: *const linux.msghdr_const, flags: c_uint) isize {
    if (!bindDatagram(fd)) return -1;
    return checkedWide(linux.sendmsg(fd, msg, flags));
}

fn checked(result: usize) c_int {
    return @intCast(checkedWide(result));
}

fn checkedWide(result: usize) isize {
    const err = linux.errno(result);
    if (err == .SUCCESS) return @intCast(result);
    __errno_location().* = @backingInt(err);
    return -1;
}
