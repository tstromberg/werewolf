//! Verify the LAN policy and query mDNS on the VM's actual interface address.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const service_name = "_home-assistant._tcp.local.";

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "discovery")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const uid = try driver.system.account(io, a, "_oci-home-assistant");
    const policy = try driver.system.read(io, a, "/usr/share/werewolf/net");
    const listen = try a.print("listen {d} udp 5353 lan", .{uid});
    const connect = try a.print("connect {d} udp 5353 lan", .{uid});
    const lan = linePresent(policy, listen) and linePresent(policy, connect);
    try ctx.result(io, args[1], "ha-discovery-policy", lan);
    const interface = try defaultInterface(try driver.system.read(io, a, "/proc/net/route"));
    const address = try interfaceAddress(a, interface);
    const server = try a.print("@{s}", .{address});
    const stop = Io.Clock.awake.now(io).addDuration(.fromSeconds(60));
    while (true) {
        var attempt: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer attempt.deinit();
        const result = std.process.run(attempt.allocator(), io, .{
            .argv = &.{ "/usr/bin/drill", "-Q", "-p", "5353", service_name, server, "PTR" },
            .stdout_limit = .limited(16384),
            .stderr_limit = .limited(4096),
            .timeout = driver.deadline(io, 3),
        }) catch |err| {
            if (err != error.Timeout) return err;
            if (Io.Clock.awake.now(io).compare(.gte, stop)) return error.MdnsTimeout;
            continue;
        };
        if (result.term == .exited and result.term.exited == 0 and instance(result.stdout)) break;
        if (Io.Clock.awake.now(io).compare(.gte, stop)) {
            try Io.File.stderr().writeStreamingAll(io, result.stdout);
            try Io.File.stderr().writeStreamingAll(io, result.stderr);
            return error.MdnsAnswer;
        }
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    try ctx.result(io, args[1], "ha-mdns-answer", true);
}

fn linePresent(raw: []const u8, wanted: []const u8) bool {
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| if (std.mem.eql(u8, line, wanted)) return true;
    return false;
}
fn defaultInterface(routes: []const u8) ![]const u8 {
    var lines = std.mem.splitScalar(u8, routes, '\n');
    if (!std.mem.startsWith(u8, lines.next() orelse return error.Routes, "Iface"))
        return error.Routes;
    var found: ?[]const u8 = null;
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t");
        const name = words.next() orelse continue;
        const destination = words.next() orelse return error.Routes;
        _ = words.next() orelse return error.Routes;
        const flags = try std.fmt.parseInt(u16, words.next() orelse return error.Routes, 16);
        if (!std.mem.eql(u8, destination, "00000000") or flags & 1 == 0 or
            std.mem.eql(u8, name, "lo")) continue;
        if (found != null or name.len >= linux.IFNAMESIZE) return error.Routes;
        found = name;
    }
    return found orelse error.DefaultRoute;
}
fn interfaceAddress(a: Allocator, name: []const u8) ![]const u8 {
    const fd = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(fd) != .SUCCESS) return error.Socket;
    defer _ = linux.close(@intCast(fd));
    var request = std.mem.zeroes(linux.ifreq);
    @memcpy(request.ifrn.name[0..name.len], name);
    const result = linux.ioctl(@intCast(fd), linux.SIOCGIFADDR, @intFromPtr(&request));
    if (linux.errno(result) != .SUCCESS) return error.InterfaceAddress;
    const address: *const linux.sockaddr.in = @ptrCast(&request.ifru);
    if (address.family != linux.AF.INET) return error.InterfaceAddress;
    const bytes = std.mem.asBytes(&address.addr);
    if (bytes[0] == 127 or bytes[0] == 0) return error.LanAddress;
    return a.print("{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
}
fn instance(output: []const u8) bool {
    var lines = std.mem.tokenizeAny(u8, output, "\r\n");
    while (lines.next()) |line| {
        if (line.len > service_name.len + 1 and
            std.mem.endsWith(u8, line, "." ++ service_name) and
            std.mem.findAny(u8, line, " \t") == null) return true;
    }
    return false;
}

test "mDNS needs an instance answer, not an echoed question or diagnostic" {
    try std.testing.expect(instance("Home._home-assistant._tcp.local.\n"));
    try std.testing.expect(!instance(service_name ++ "\n"));
    try std.testing.expect(!instance(";; query: Home._home-assistant._tcp.local.\n"));
    try std.testing.expect(!instance("rcode: NOERROR\n"));
    const routes = "Iface\tDestination Gateway Flags\nens5\t00000000 0202000A 0003\n";
    try std.testing.expectEqualStrings("ens5", try defaultInterface(routes));
    const loopback = "Iface Destination Gateway Flags\nlo 00000000 00000000 0001\n";
    try std.testing.expectError(error.DefaultRoute, defaultInterface(loopback));
    try std.testing.expect(linePresent("listen 42 udp 5353 lan\n", "listen 42 udp 5353 lan"));
    try std.testing.expect(!linePresent("listen 42 udp 5353\n", "listen 42 udp 5353 lan"));
    try std.testing.expect(!linePresent("listen 420 udp 5353 lan\n", "listen 42 udp 5353 lan"));
}
