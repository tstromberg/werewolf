//! rtnetlink for the exposure check: this host's IPv4 addresses, and the
//! kernel's route for a packet arriving from outside.
//! https://man7.org/linux/man-pages/man7/rtnetlink.7.html
const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const native = @import("builtin").cpu.arch.endian();

pub const Address = struct { index: u32, ip: [4]u8 };

/// RTN_LOCAL: the kernel would deliver the packet to this host.
pub const local = 2;

// QEMU's user-network gateway, where traffic from outside comes from.
const gateway = [4]u8{ 10, 0, 2, 2 };

/// IPv4 addresses outside 127.0.0.0/8, with their interfaces.
pub fn addresses(a: Allocator) ![]const Address {
    const fd = try open();
    defer _ = linux.close(fd);
    var request: [24]u8 = @splat(0);
    std.mem.writeInt(u32, request[0..4], request.len, native);
    std.mem.writeInt(u16, request[4..6], 22, native); // RTM_GETADDR
    std.mem.writeInt(u16, request[6..8], 0x301, native); // NLM_F_REQUEST | NLM_F_DUMP
    std.mem.writeInt(u32, request[8..12], 1, native);
    request[16] = linux.AF.INET;
    try send(fd, &request);
    var list: std.ArrayList(Address) = .empty;
    var buffer: [32 << 10]u8 align(4) = undefined;
    while (!try addressBatch(a, &list, try receive(fd, &buffer))) {}
    return list.items;
}

/// Add one batch of an RTM_GETADDR dump to list; true at the dump's end.
fn addressBatch(a: Allocator, list: *std.ArrayList(Address), batch: []const u8) !bool {
    var off: usize = 0;
    while (off < batch.len) {
        if (batch.len - off < 16) return error.Netlink;
        const len = std.mem.readInt(u32, batch[off..][0..4], native);
        if (len < 16 or len > batch.len - off) return error.Netlink;
        const message = batch[off..][0..len];
        off += std.mem.alignForward(usize, len, 4);
        switch (std.mem.readInt(u16, message[4..6], native)) {
            3 => return true, // NLMSG_DONE
            2 => return error.Netlink, // NLMSG_ERROR
            20 => {}, // RTM_NEWADDR
            else => continue,
        }
        if (message.len < 24 or message[16] != linux.AF.INET) continue;
        var ip: ?[4]u8 = null;
        var at: usize = 24;
        while (message.len - at >= 4) {
            const size = std.mem.readInt(u16, message[at..][0..2], native);
            if (size < 4 or size > message.len - at) return error.Netlink;
            const kind = std.mem.readInt(u16, message[at + 2 ..][0..2], native);
            // IFA_LOCAL is this host's end; IFA_ADDRESS is a point-to-point peer's.
            if (size == 8 and (kind == 2 or (kind == 1 and ip == null)))
                ip = message[at + 4 ..][0..4].*;
            at += std.mem.alignForward(usize, size, 4);
            if (at > message.len) break;
        }
        const address = ip orelse continue;
        if (address[0] == 127) continue;
        try list.append(
            a,
            .{ .index = std.mem.readInt(u32, message[20..24], native), .ip = address },
        );
    }
    return false;
}

/// The route type for TCP from the gateway's port source arriving on
/// interface index for address:port, or the negated errno of a refused
/// lookup. RTA_IIF asks about input; connecting to an own address would
/// take the local output path instead.
pub fn ingress(index: u32, address: [4]u8, port: u16, source: u16) !i32 {
    const fd = try open();
    defer _ = linux.close(fd);
    var request: [76]u8 = undefined;
    try send(fd, routeRequest(&request, index, address, port, source));
    var buffer: [8192]u8 align(4) = undefined;
    return routeReply(try receive(fd, &buffer));
}

fn routeRequest(out: *[76]u8, index: u32, address: [4]u8, port: u16, source: u16) []const u8 {
    @memset(out, 0);
    std.mem.writeInt(u32, out[0..4], out.len, native);
    std.mem.writeInt(u16, out[4..6], 26, native); // RTM_GETROUTE
    std.mem.writeInt(u16, out[6..8], 1, native); // NLM_F_REQUEST
    std.mem.writeInt(u32, out[8..12], 1, native);
    out[16..19].* = .{ linux.AF.INET, 32, 32 }; // rtmsg: family, dst_len, src_len
    var value: [4]u8 = undefined;
    attribute(out[28..36], 1, &address); // RTA_DST
    attribute(out[36..44], 2, &gateway); // RTA_SRC
    std.mem.writeInt(u32, &value, index, native);
    attribute(out[44..52], 3, &value); // RTA_IIF
    attribute(out[52..60], 27, &.{linux.IPPROTO.TCP}); // RTA_IP_PROTO
    std.mem.writeInt(u16, value[0..2], source, .big);
    attribute(out[60..68], 28, value[0..2]); // RTA_SPORT
    std.mem.writeInt(u16, value[0..2], port, .big);
    attribute(out[68..76], 29, value[0..2]); // RTA_DPORT
    return out;
}

fn attribute(out: *[8]u8, kind: u16, data: []const u8) void {
    std.mem.writeInt(u16, out[0..2], @intCast(4 + data.len), native);
    std.mem.writeInt(u16, out[2..4], kind, native);
    @memcpy(out[4..][0..data.len], data);
}

fn routeReply(reply: []const u8) !i32 {
    if (reply.len < 20) return error.Netlink;
    const len = std.mem.readInt(u32, reply[0..4], native);
    if (len < 20 or len > reply.len or std.mem.readInt(u32, reply[8..12], native) != 1)
        return error.Netlink;
    return switch (std.mem.readInt(u16, reply[4..6], native)) {
        2 => std.mem.readInt(i32, reply[16..20], native), // NLMSG_ERROR; blackholes give -EINVAL
        24 => if (len < 28) error.Netlink else reply[16 + 7], // RTM_NEWROUTE's rtm_type
        else => error.Netlink,
    };
}

fn open() !i32 {
    const rc = linux.socket(
        linux.AF.NETLINK,
        linux.SOCK.RAW | linux.SOCK.CLOEXEC,
        linux.NETLINK.ROUTE,
    );
    if (linux.errno(rc) != .SUCCESS) return error.Netlink;
    return @intCast(rc);
}

fn send(fd: i32, request: []const u8) !void {
    const kernel: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
    const rc = linux.sendto(
        fd,
        request.ptr,
        request.len,
        0,
        @ptrCast(&kernel),
        @sizeOf(@TypeOf(kernel)),
    );
    if (linux.errno(rc) != .SUCCESS or rc != request.len) return error.Netlink;
}

/// One datagram from the kernel, within two seconds.
fn receive(fd: i32, buffer: []u8) ![]const u8 {
    var fds = [1]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&fds, 1, 2000) != 1) return error.Timeout;
    var peer: linux.sockaddr.nl = undefined;
    var size: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
    const rc = linux.recvfrom(fd, buffer.ptr, buffer.len, 0, @ptrCast(&peer), &size);
    if (linux.errno(rc) != .SUCCESS or peer.pid != 0) return error.Netlink;
    return buffer[0..rc];
}

test "route lookups ask about input like the retired Python probe" {
    if (native != .little) return error.SkipZigTest;
    var request: [76]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        "\x4c\x00\x00\x00\x1a\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x20\x20\x00" ++
            "\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x01\x00\x0a\x00\x02\x0f\x08\x00\x02\x00" ++
            "\x0a\x00\x02\x02\x08\x00\x03\x00\x02\x00\x00\x00\x05\x00\x1b\x00\x06\x00\x00\x00" ++
            "\x06\x00\x1c\x00\x9c\x40\x00\x00\x06\x00\x1d\x00\x01\xbb\x00\x00",
        routeRequest(&request, 2, .{ 10, 0, 2, 15 }, 443, 40000),
    );
}

test "route replies give a type or a negated errno, never a stale answer" {
    if (native != .little) return error.SkipZigTest;
    const header = "\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"; // flags, seq 1, pid
    try std.testing.expectEqual(@as(i32, -22), try routeReply("\x24\x00\x00\x00\x02\x00" ++
        header ++ "\xea\xff\xff\xff" ++ @as([16]u8, @splat(0))));
    try std.testing.expectEqual(@as(i32, 2), try routeReply("\x1c\x00\x00\x00\x18\x00" ++
        header ++ "\x02\x20\x00\x00\xfe\x00\x00\x02\x00\x00\x00\x00"));
    try std.testing.expectError(error.Netlink, routeReply("\x1c\x00\x00\x00\x18\x00" ++
        "\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00" ++
        "\x02\x20\x00\x00\xfe\x00\x00\x02\x00\x00\x00\x00"));
    try std.testing.expectError(error.Netlink, routeReply("\x40\x00\x00\x00\x18\x00" ++
        header ++ "\x02\x20\x00\x00\xfe\x00\x00\x02\x00\x00\x00\x00"));
}

test "address dumps keep local IPv4 ends, skip loopback and stop at done" {
    if (native != .little) return error.SkipZigTest;
    const t = std.testing;
    const loopback = "\x28\x00\x00\x00\x14\x00\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00" ++
        "\x02\x08\x80\xfe\x01\x00\x00\x00\x08\x00\x01\x00\x7f\x00\x00\x01\x08\x00\x02\x00" ++
        "\x7f\x00\x00\x01";
    const ethernet = "\x28\x00\x00\x00\x14\x00\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00" ++
        "\x02\x18\x00\x00\x02\x00\x00\x00\x08\x00\x01\x00\x0a\x00\x02\x63\x08\x00\x02\x00" ++
        "\x0a\x00\x02\x0f";
    const done = "\x14\x00\x00\x00\x03\x00\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    var list: std.ArrayList(Address) = .empty;
    defer list.deinit(t.allocator);
    try t.expect(!try addressBatch(t.allocator, &list, loopback ++ ethernet));
    try t.expect(try addressBatch(t.allocator, &list, done));
    try t.expectEqual(@as(usize, 1), list.items.len);
    try t.expectEqual(@as(u32, 2), list.items[0].index);
    try t.expectEqualSlices(u8, &.{ 10, 0, 2, 15 }, &list.items[0].ip);
    try t.expectError(error.Netlink, addressBatch(t.allocator, &list, ethernet[0..20]));
}
