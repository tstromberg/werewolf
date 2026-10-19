//! NATS concurrency and config-copy attacks; ordinary checks live in YAML.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const client = [_][]const u8{
    "/usr/bin/nats",            "--server", "tls://localhost:4222", "--tlsca",
    "/run/config/nats/tls.crt", "--user",   "check",                "--password",
    "werewolf-check",
};

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    if (std.mem.eql(u8, args[2], "round-trip")) {
        try roundTrip(init.io, a, ctx);
        try ctx.result(init.io, args[1], "nats-round-trip", true);
    } else if (std.mem.eql(u8, args[2], "plaintext")) {
        try plaintext(a);
        try ctx.result(init.io, args[1], "nats-tls-only", true);
    } else if (std.mem.eql(u8, args[2], "config-restart")) {
        try configRestart(init.io, a);
        try ctx.result(init.io, args[1], "config-restart", true);
    } else return error.Usage;
}

fn plaintext(a: Allocator) !void {
    const linux = std.os.linux;
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    const timeout: linux.timeval = .{ .sec = 5, .usec = 0 };
    const timed = linux.setsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.RCVTIMEO,
        @ptrCast(&timeout),
        @sizeOf(@TypeOf(timeout)),
    );
    if (linux.errno(timed) != .SUCCESS) return error.SocketTimeout;
    const address: linux.sockaddr.in = .{
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
        .port = std.mem.nativeToBig(u16, 4222),
    };
    if (linux.errno(linux.connect(fd, @ptrCast(&address), @sizeOf(@TypeOf(address)))) != .SUCCESS)
        return error.Connect;
    var info: [4096]u8 = undefined;
    var used: usize = 0;
    while (used < info.len) {
        const got = linux.read(fd, info[used..].ptr, info.len - used);
        if (linux.errno(got) != .SUCCESS or got == 0) return error.ServerGreeting;
        used += got;
        if (std.mem.findScalar(u8, info[0..used], '\n')) |end| {
            used = end + 1;
            break;
        }
    }
    if (!std.mem.startsWith(u8, info[0..used], "INFO ")) return error.ServerGreeting;
    const value = try std.json.parseFromSliceLeaky(std.json.Value, a, info[5..used], .{});
    if (value != .object) return error.ServerGreeting;
    const required = value.object.get("tls_required") orelse return error.TlsNotRequired;
    if (required != .bool or !required.bool) return error.TlsNotRequired;
    const message = "CONNECT {\"user\":\"check\",\"pass\":\"werewolf-check\"}\r\nPING\r\n";
    const sent = linux.sendto(fd, message, message.len, linux.MSG.NOSIGNAL, null, 0);
    if (linux.errno(sent) != .SUCCESS or sent != message.len) return error.Send;
    var response: [1]u8 = undefined;
    const got = linux.read(fd, &response, response.len);
    switch (linux.errno(got)) {
        .CONNRESET => return,
        .SUCCESS => if (got == 0) return,
        else => return error.PlaintextRead,
    }
    return error.PlaintextAccepted;
}

fn command(a: Allocator, io: Io, argv: []const []const u8) !std.process.RunResult {
    return std.process.run(
        a,
        io,
        .{
            .argv = argv,
            .stdout_limit = .limited(8192),
            .stderr_limit = .limited(8192),
            .timeout = driver.deadline(io, 20),
        },
    );
}
fn successful(result: std.process.RunResult) !void {
    if (result.term != .exited or result.term.exited != 0) return error.ClientFailed;
}

fn roundTrip(io: Io, a: Allocator, ctx: driver.Run) !void {
    const subject = try a.print("check.round.{s}.{s}", .{ ctx.run, ctx.phase });
    const sub_args = client ++ [_][]const u8{ "sub", subject, "--count", "1", "--raw" };
    // The subscriber allocates concurrently with monitoring; do not share an arena.
    const concurrent_a = std.heap.smp_allocator;
    var subscriber = try io.concurrent(command, .{ concurrent_a, io, &sub_args });
    defer {
        if (subscriber.cancel(io)) |result| {
            concurrent_a.free(result.stdout);
            concurrent_a.free(result.stderr);
        } else |_| {}
    }
    var http = try driver.fetch.Client.init(a);
    defer http.deinit();
    const request = try std.json.parseFromSliceLeaky(std.json.Value, a,
        \\{"url":"http://127.0.0.1:8222/subsz?subs=1"}
    , .{});
    var ready = false;
    for (0..100) |_| {
        var poll: std.heap.ArenaAllocator = .init(a);
        defer poll.deinit();
        const response = try http.request(request, 1000, poll.allocator());
        if (response.object.get("status").?.integer != 200) return error.MonitorStatus;
        if (try subscribed(poll.allocator(), response.object.get("body").?.string, subject)) {
            ready = true;
            break;
        }
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    if (!ready) return error.SubscriptionNotReady;
    const published = try command(a, io, &(client ++ [_][]const u8{ "pub", subject, ctx.run }));
    try successful(published);
    const received = try subscriber.await(io);
    try successful(received);
    if (!std.mem.eql(u8, std.mem.trim(u8, received.stdout, "\r\n"), ctx.run))
        return error.MessageMismatch;
}

fn subscribed(a: Allocator, body: []const u8, subject: []const u8) !bool {
    const value = try std.json.parseFromSliceLeaky(std.json.Value, a, body, .{});
    if (value != .object) return error.MonitorFormat;
    const list = value.object.get("subscriptions_list") orelse return false;
    if (list != .array) return error.MonitorFormat;
    for (list.array.items) |entry| {
        if (entry != .object) return error.MonitorFormat;
        const name = entry.object.get("subject") orelse return error.MonitorFormat;
        if (name != .string) return error.MonitorFormat;
        if (std.mem.eql(u8, name.string, subject)) return true;
    }
    return false;
}

fn configRestart(io: Io, a: Allocator) !void {
    const users = "/run/svc/nats/users";
    const victim = "/run/nats-test-victim";
    try successful(try command(a, io, &.{ "/usr/bin/sv", "-w", "20", "down", "/etc/sv/nats" }));
    errdefer _ = command(a, io, &.{ "/usr/bin/sv", "up", "/etc/sv/nats" }) catch {};
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = victim, .data = "unchanged\n" });
    try Io.Dir.cwd().deleteFile(io, users);
    try Io.Dir.cwd().symLink(io, victim, users, .{});
    try successful(try command(a, io, &.{ "/usr/bin/sv", "-w", "20", "up", "/etc/sv/nats" }));
    for (0..100) |_| {
        const stat = Io.Dir.cwd().statFile(io, users, .{ .follow_symlinks = false }) catch |err| {
            if (err != error.FileNotFound) return err;
            try io.sleep(.fromMilliseconds(100), .awake);
            continue;
        };
        if (stat.kind == .file) {
            const actual = try driver.system.read(io, a, users);
            const expected = try driver.system.read(io, a, "/run/config/nats/users.conf");
            if (!std.mem.eql(u8, actual, expected) or !std.mem.eql(u8, try driver.system.read(
                io,
                a,
                victim,
            ), "unchanged\n")) return error.UnsafeConfigCopy;
            return;
        }
        if (stat.kind != .sym_link) return error.ConfigFileType;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    return error.ConfigNotReplaced;
}

test "subscription readiness requires the exact subject, not counts or a prefix" {
    const a = std.testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    try std.testing.expect(try subscribed(arena.allocator(),
        \\{"subscriptions_list":[{"subject":"check.round.1"}]}
    , "check.round.1"));
    try std.testing.expect(!try subscribed(arena.allocator(),
        \\{"subscriptions_list":[{"subject":"check.round.10"}]}
    , "check.round.1"));
    try std.testing.expect(!try subscribed(
        arena.allocator(),
        "{\"num_subscriptions\":3}",
        "check.round.1",
    ));
    try std.testing.expectError(
        error.MonitorFormat,
        subscribed(
            arena.allocator(),
            "{\"subscriptions_list\":[{\"subject\":1}]}",
            "check.round.1",
        ),
    );
}
