//! check-mount-broker runs the real confined broker, as root, in a private
//! mount namespace with a fixture /run/runit, over its three role channels:
//! roles, exact and oversized requests, stalled readers, empty requests. No
//! request mounts, writes boot media or reboots. The broker's unit tests run
//! after, staging their files in a fresh /tmp directory.
//!
//!     check-mount-broker BROKER [UNIT-TESTS]

const std = @import("std");
const host = @import("host");
const netns = host.netns;
const linux = std.os.linux;
const mem = std.mem;
const Lab = netns.Lab;

const usage = "usage: check-mount-broker BROKER [UNIT-TESTS]";

pub fn main(init: std.process.Init) !void {
    const l: Lab = .init(init, "check-mount-broker");
    const args = try init.minimal.args.toSlice(l.gpa);
    if (linux.geteuid() != 0)
        return l.fail(
            "refused",
            .{ .why = "run as root: the broker's fixture is a private /run/runit" },
        );
    if (args.len >= 4 and mem.eql(u8, args[1], "--inside"))
        return inside(l, args[2], args[3], if (args.len > 4) args[4] else null);
    if (args.len != 2 and args.len != 3) return l.fail("usage", .{ .usage = usage });
    var paths: [2][]const u8 = undefined;
    for (args[1..], 0..) |arg, i|
        paths[i] = try std.Io.Dir.cwd().realPathFileAlloc(l.io, arg, l.gpa);
    const parent = try l.namespace("mnt");
    try l.enter(&.{"--mount"}, if (args.len == 3)
        &.{ "--inside", parent, paths[0], paths[1] }
    else
        &.{ "--inside", parent, paths[0] });
}

fn inside(l: Lab, parent: []const u8, broker: []const u8, unit: ?[]const u8) !void {
    if (mem.eql(u8, try l.namespace("mnt"), parent))
        return l.fail("refused", .{ .why = "not in a private mount namespace" });
    try l.private();
    try l.tmpfs("/run");
    try l.mkdir("/run/runit", 0o755);
    try channels(l, broker);
    const u = unit orelse return;
    const dir = try l.temporary("broker-files");
    defer l.remove(dir);
    var tests = try l.spawn(&.{u}, .{ .cwd = dir });
    const exit = try tests.wait(60_000) orelse {
        tests.signal(.KILL);
        _ = try tests.wait(null);
        return l.fail("unit_tests", .{ .why = "still running after 60 s" });
    };
    if (exit != 0) return l.fail("unit_tests", .{ .exit = exit });
    l.log("pass", .{ .what = "broker unit tests" });
}

fn channels(l: Lab, path: []const u8) !void {
    const created = linux.memfd_create("broker-log", linux.MFD.CLOEXEC);
    try ok(created);
    const log: linux.fd_t = @intCast(created);
    defer netns.close(log);
    var pairs: [3][2]linux.fd_t = undefined;
    for (&pairs) |*p| {
        try ok(linux.socketpair(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0, p));
        const size: c_int = 4096;
        try ok(linux.setsockopt(
            p[0],
            linux.SOL.SOCKET,
            linux.SO.SNDBUF,
            mem.asBytes(&size),
            @sizeOf(c_int),
        ));
    }
    var broker = try l.spawn(&.{path}, .{
        .stdout = .{ .fd = log },
        .stderr = .{ .fd = log },
        .fds = &.{ pairs[0][0], pairs[1][0], pairs[2][0] },
    });
    defer {
        broker.signal(.KILL);
        _ = broker.wait(5000) catch null;
    }
    var clients: [3]linux.fd_t = undefined;
    for (pairs, &clients) |p, *c| {
        netns.close(p[0]);
        c.* = p[1];
        const three: linux.timeval = .{ .sec = 3, .usec = 0 };
        for ([_]u32{ linux.SO.RCVTIMEO, linux.SO.SNDTIMEO }) |opt|
            try ok(linux.setsockopt(
                c.*,
                linux.SOL.SOCKET,
                opt,
                mem.asBytes(&three),
                @sizeOf(linux.timeval),
            ));
    }
    defer for (clients) |c| netns.close(c);
    exercise(l, &broker, clients) catch |err| {
        var tail: [4096]u8 = undefined;
        const size = linux.lseek(log, 0, linux.SEEK.END);
        const start = size -| tail.len;
        const n = linux.pread(log, &tail, tail.len, @intCast(start));
        if (linux.errno(n) == .SUCCESS) netns.writeAll(2, tail[0..n]) catch {};
        return err;
    };
}

fn exercise(l: Lab, broker: *netns.Child, clients: [3]linux.fd_t) !void {
    const updater, const keeper, const stage = clients;
    try exchange(l, updater, "owner-channel", "ok none\n");
    try exchange(l, keeper, "shutdown", "no NotStageThree\n");
    try exchange(l, stage, "reboot", "no NotSlotService\n");
    try exchange(l, updater, "reboot extra", "no BadRequest\n");
    try exchange(l, updater, "reboot", "no UnauthorizedPeer\n");
    try exchange(l, keeper, "esp-status", "no UnauthorizedPeer\n");
    try exchange(l, updater, &@as([1025]u8, @splat('x')), "no BadRequest\n");
    try exchange(l, updater, "owner-channel", "ok none\n");
    l.log("pass", .{ .what = "role, peer credential, exact request and oversized packet checks" });
    // Stop reading replies: fill the broker's send queue without filling its
    // log or touching a device or file.
    try stall(l, updater, "owner-channel");
    try exchange(l, stage, "reboot", "no NotSlotService\n");
    try exchange(l, keeper, "shutdown", "no NotStageThree\n");
    try closed(l, updater);
    l.log("pass", .{ .what = "stalled updater cannot block keeper or shutdown channel" });
    try stall(l, stage, "reboot");
    try exchange(l, keeper, "shutdown", "no NotStageThree\n");
    try closed(l, stage);
    l.log("pass", .{ .what = "ordinary replies also disconnect stalled readers" });
    try ok(linux.sendto(keeper, "", 0, linux.MSG.NOSIGNAL, null, 0));
    try closed(l, keeper);
    l.log("pass", .{ .what = "empty request closes its channel" });
    if (try broker.wait(0) != null) return l.fail("broker_exited", .{ .exit = broker.exit });
}

fn exchange(l: Lab, client: linux.fd_t, request: []const u8, expected: []const u8) !void {
    try ok(linux.sendto(client, request.ptr, request.len, linux.MSG.NOSIGNAL, null, 0));
    var answer: [2048]u8 = undefined;
    const n = linux.recvfrom(client, &answer, answer.len, 0, null, null);
    const got: []const u8 = if (linux.errno(n) == .SUCCESS)
        answer[0..n]
    else
        try l.gpa.print("errno {d}", .{@backingInt(linux.errno(n))});
    if (!mem.eql(u8, got, expected)) return l.fail("unexpected_reply", .{
        .request = request[0..@min(request.len, 64)],
        .expected = expected,
        .got = got,
    });
}

/// stall queues requests without reading a reply, for up to a second.
fn stall(l: Lab, client: linux.fd_t, request: []const u8) !void {
    var sent: usize = 0;
    const until = netns.now() + 1000;
    while (sent < 4096 and netns.now() < until) {
        const rc = linux.sendto(
            client,
            request.ptr,
            request.len,
            linux.MSG.NOSIGNAL | linux.MSG.DONTWAIT,
            null,
            0,
        );
        switch (linux.errno(rc)) {
            .SUCCESS => sent += 1,
            .AGAIN => netns.nap(1),
            .PIPE, .CONNRESET => break,
            else => |e| return l.fail("stall_send", .{ .errno = @backingInt(e) }),
        }
    }
    if (sent < 2) return l.fail(
        "stall",
        .{ .why = "fixture could not queue requests", .sent = sent },
    );
}

/// closed requires the broker to have dropped client's channel.
fn closed(l: Lab, client: linux.fd_t) !void {
    var buf: [2048]u8 = undefined;
    for (0..4096) |_| {
        const n = linux.recvfrom(client, &buf, buf.len, 0, null, null);
        switch (linux.errno(n)) {
            .SUCCESS => if (n == 0) return,
            .CONNRESET => return,
            else => |e| return l.fail("channel_kept", .{ .errno = @backingInt(e) }),
        }
    }
    return l.fail("channel_kept", .{ .why = "stalled channel retained after losing replies" });
}

fn ok(rc: usize) !void {
    if (linux.errno(rc) != .SUCCESS) return error.SystemCallFailed;
}
