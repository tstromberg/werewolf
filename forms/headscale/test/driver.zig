//! Run the real Tailscale client and require an explicit registration refusal.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "join-refused")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    var random: [8]u8 = undefined;
    io.random(&random);
    var key_bytes: [38]u8 = undefined;
    io.random(&key_bytes);
    const key = try a.print("hskey-auth-{x}-{x}", .{ key_bytes[0..6], key_bytes[6..] });
    const directory = try a.print("/run/test-headscale-{s}-{x}", .{ ctx.run, &random });
    try Io.Dir.cwd().createDir(io, directory, .fromMode(0o700));
    defer Io.Dir.cwd().deleteTree(io, directory) catch {};
    const socket = try a.print("--socket={s}/sock", .{directory});
    const status_argv = [_][]const u8{ "/usr/bin/tailscale", socket, "status", "--json" };
    const log_path = try a.print("{s}/daemon.log", .{directory});
    var log = try Io.Dir.cwd().createFile(io, log_path, .{});
    defer log.close(io);
    errdefer {
        const bytes = driver.system.read(io, a, log_path) catch "no daemon log";
        Io.File.stderr().writeStreamingAll(
            io,
            bytes[bytes.len - @min(bytes.len, 4096) ..],
        ) catch {};
    }
    var env: std.process.Environ.Map = .init(a);
    defer env.deinit();
    try env.put("HOME", directory);
    try env.put("TMPDIR", directory);
    try env.put("SSL_CERT_FILE", "/data/svc/caddy/pki/authorities/local/root.crt");
    var daemon = try std.process.spawn(io, .{
        .argv = &.{
            "/usr/bin/tailscaled",
            "--no-logs-no-support",
            "--tun=userspace-networking",
            "--state=mem:",
            try a.print("--statedir={s}", .{directory}),
            socket,
        },
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
    });
    defer daemon.kill(io);
    const stop = Io.Clock.awake.now(io).addDuration(.fromSeconds(30));
    while (true) {
        var attempt: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer attempt.deinit();
        const status = try command(
            io,
            attempt.allocator(),
            &env,
            &status_argv,
            5,
        );
        if (succeeded(status) and try loggedOut(attempt.allocator(), status.stdout)) break;
        if (Io.Clock.awake.now(io).compare(.gte, stop)) return error.DaemonNotReady;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    const result = try command(io, a, &env, &.{
        "/usr/bin/tailscale",
        socket,
        "up",
        "--login-server",
        "http://127.0.0.1:8080",
        "--auth-key",
        key,
        "--timeout",
        "30s",
    }, 40);
    if (result.term != .exited or result.term.exited == 0 or
        (!registrationRefused(result.stderr) and !registrationRefused(result.stdout)))
    {
        try Io.File.stderr().writeStreamingAll(io, result.stderr);
        return error.RegistrationNotRefused;
    }
    const status = try command(io, a, &env, &status_argv, 5);
    if (!succeeded(status) or !try loggedOut(a, status.stdout)) return error.NodeJoined;
    try ctx.result(io, args[1], "hs-join-refused", true);
}

fn command(
    io: Io,
    a: Allocator,
    env: *const std.process.Environ.Map,
    argv: []const []const u8,
    seconds: i64,
) !std.process.RunResult {
    return std.process.run(a, io, .{
        .argv = argv,
        .environ_map = env,
        .stdout_limit = .limited(16384),
        .stderr_limit = .limited(16384),
        .timeout = driver.deadline(io, seconds),
    });
}
fn succeeded(result: std.process.RunResult) bool {
    return result.term == .exited and result.term.exited == 0;
}
fn loggedOut(a: Allocator, bytes: []const u8) !bool {
    const parsed = try std.json.parseFromSlice(std.json.Value, a, bytes, .{});
    defer parsed.deinit();
    const object = parsed.value;
    if (object != .object) return error.ClientStatus;
    const state = object.object.get("BackendState") orelse return error.ClientStatus;
    const ips = object.object.get("TailscaleIPs") orelse return error.ClientStatus;
    if (state != .string) return error.ClientStatus;
    return std.mem.eql(u8, state.string, "NeedsLogin") and
        (ips == .null or (ips == .array and ips.array.items.len == 0));
}
fn registrationRefused(output: []const u8) bool {
    var lines = std.mem.tokenizeAny(u8, output, "\r\n");
    while (lines.next()) |line| {
        if (std.ascii.eqlIgnoreCase(line, "backend error: invalid pre auth key")) return true;
    }
    return false;
}

test "join refusal requires a server error and an operational logged-out client" {
    try std.testing.expect(registrationRefused("backend error: invalid pre auth key\n"));
    try std.testing.expect(!registrationRefused("context deadline exceeded"));
    try std.testing.expect(!registrationRefused("failed to parse auth-key: key too short"));
    try std.testing.expect(
        !registrationRefused("could not authenticate: certificate is not trusted"),
    );
    try std.testing.expect(try loggedOut(std.testing.allocator,
        \\{"BackendState":"NeedsLogin","TailscaleIPs":null}
    ));
    try std.testing.expect(!try loggedOut(std.testing.allocator,
        \\{"BackendState":"Running","TailscaleIPs":["100.64.0.1"]}
    ));
    try std.testing.expect(!try loggedOut(std.testing.allocator,
        \\{"BackendState":"NeedsLogin","TailscaleIPs":["100.64.0.1"]}
    ));
    try std.testing.expectError(error.ClientStatus, loggedOut(std.testing.allocator, "{}"));
}
