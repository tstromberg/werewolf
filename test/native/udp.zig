//! Exercise UDP source-port ownership, then restore the real DNS service.
const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;
const system = @import("system.zig");

pub fn squatter(io: Io, a: std.mem.Allocator, service: []const u8) !void {
    const path = try a.print("/etc/sv/{s}", .{service});
    var failure: ?anyerror = null;
    attack(io, a, path) catch |err| {
        failure = err;
    };
    // A failed assertion must not leave production service state changed.
    recover(io, a, path) catch |err| {
        std.debug.print("test-udp: restoring {s}: {s}\n", .{ service, @errorName(err) });
        failure = failure orelse err;
    };
    if (failure) |err| return err;
}

fn attack(io: Io, a: std.mem.Allocator, path: []const u8) !void {
    try control(io, a, "down", path);
    const bind_ip = try serviceAddress(io, a);
    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(30));
    while (true) {
        const entries = try system.listeners(io, a, "udp");
        var held = false;
        for (entries.array.items) |entry| {
            if (entry.object.get("port").?.integer != 53) continue;
            const address = entry.object.get("address").?.string;
            // unwound stays on 127.0.0.53 while the DNS server is down.
            held = held or !std.mem.eql(u8, address, "127.0.0.53");
        }
        if (!held) break;
        if (Io.Clock.awake.now(io).compare(.gte, deadline)) return error.PortStillHeld;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    // Root has no arbitrary outbound UDP grant. Prove the bound socket can
    // send locally, then require the external send to fail with EACCES.
    try sendFromListener(bind_ip, bind_ip, false);
    try sendFromListener(bind_ip, 0x0a000202, true);
}

fn serviceAddress(io: Io, a: std.mem.Allocator) !u32 {
    const raw = try system.read(io, a, "/run/werewolf/network/service-address");
    const parsed = try Io.net.Ip4Address.parse(raw, 0);
    return std.mem.readInt(u32, &parsed.bytes, .big);
}

fn sendFromListener(bind_ip: u32, address: u32, refused: bool) !void {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Socket;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    const local: linux.sockaddr.in = .{
        .addr = std.mem.nativeToBig(u32, bind_ip),
        .port = std.mem.nativeToBig(u16, 53),
    };
    if (linux.errno(linux.bind(fd, @ptrCast(&local), @sizeOf(@TypeOf(local)))) != .SUCCESS)
        return error.Bind;
    const peer: linux.sockaddr.in = .{
        .addr = std.mem.nativeToBig(u32, address),
        .port = std.mem.nativeToBig(u16, 40000),
    };
    const message = "x";
    const sent = linux.sendto(
        fd,
        message.ptr,
        message.len,
        0,
        @ptrCast(&peer),
        @sizeOf(@TypeOf(peer)),
    );
    if (refused) {
        if (linux.errno(sent) != .ACCES) return error.SquatterNotRefused;
    } else if (linux.errno(sent) != .SUCCESS or sent != message.len) {
        return error.PositiveControlDenied;
    }
}

fn control(io: Io, a: std.mem.Allocator, action: []const u8, path: []const u8) !void {
    const result = try command(io, a, &.{ "/usr/bin/sv", "-w", "30", action, path }, 40);
    if (result.term != .exited or result.term.exited != 0) {
        std.debug.print("test-udp: sv {s}: {s}{s}", .{ action, result.stdout, result.stderr });
        return error.ServiceControl;
    }
}

fn recover(io: Io, a: std.mem.Allocator, path: []const u8) !void {
    try control(io, a, "up", path);
    const address = try system.read(io, a, "/run/werewolf/network/service-address");
    const server = try a.print("@{s}", .{address});
    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(30));
    while (true) {
        const result = command(
            io,
            a,
            &.{ "/usr/bin/drill", "-Q", "example.org", server },
            5,
        ) catch null;
        if (result) |r| if (r.term == .exited and r.term.exited == 0 and answers(r.stdout)) return;
        if (Io.Clock.awake.now(io).compare(.gte, deadline)) return error.ResolverNotRestored;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
}

fn command(
    io: Io,
    a: std.mem.Allocator,
    argv: []const []const u8,
    seconds: i64,
) !std.process.RunResult {
    return std.process.run(a, io, .{
        .argv = argv,
        .stdout_limit = .limited(64 << 10),
        .stderr_limit = .limited(16 << 10),
        .timeout = (Io.Timeout{ .duration = .{
            .raw = .fromSeconds(seconds),
            .clock = .awake,
        } }).toDeadline(io),
    });
}

fn answers(text: []const u8) bool {
    // drill -Q prints answers alone; a server address or glue is not an answer.
    var lines = std.mem.tokenizeAny(u8, text, "\r\n");
    while (lines.next()) |line| {
        const ip = Io.net.Ip4Address.parse(line, 0) catch continue;
        if (ip.bytes[0] != 0) return true;
    }
    return false;
}

test "DNS recovery needs a positive IPv4 answer, not a banner or zero-IP block" {
    try std.testing.expect(answers("203.0.113.7\n"));
    try std.testing.expect(answers("alias.example.\n203.0.113.7\n"));
    for ([_][]const u8{
        "",
        "0.0.0.0\n",
        "SERVER: 127.0.0.1\n",
        "999.1.1.1\n",
        "NXDOMAIN\n",
    }) |text|
        try std.testing.expect(!answers(text));
}
