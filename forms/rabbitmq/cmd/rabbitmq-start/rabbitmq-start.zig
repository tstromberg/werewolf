//! rabbitmq-start replaces rabbitmq-server and erl's shell wrappers.
//! It writes a hashed local user's definitions, keeps the Erlang cookie
//! on /data, and starts epmd on loopback before leash execs Erlang.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const bindir = "/opt/erlang/lib/erlang/erts-15.2.7.13/bin";

pub fn main(init: std.process.Init) void {
    run(init.io, init.arena.allocator(), init.minimal.environ) catch |err| {
        var buf: [160]u8 = undefined;
        const line = std.mem.print(&buf, "rabbitmq-start: {s}\n", .{@errorName(err)}) catch return;
        Io.File.stderr().writeStreamingAll(init.io, line) catch {};
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const user = environ.getAlloc(gpa, "RABBITMQ_USER") catch "app";
    if (!usernameOk(user)) return error.BadUsername;
    const raw = try Dir.cwd().readFileAlloc(io, "/tmp/password", gpa, .limited(1024));
    const password = std.mem.trimEnd(u8, raw, "\r\n");
    if (!passwordOk(password)) return error.BadPassword;
    var salt: [4]u8 = undefined;
    io.random(&salt);
    const hash = passwordHash(password, salt);
    const defs = try definitions(gpa, user, &hash);
    try replace(io, "/run/definitions.json", defs);
    // A restart gets a fresh copy from the boot config; BEAM never needs
    // the plaintext password. Its user and permissions are imported at boot.
    try Dir.cwd().deleteFile(io, "/tmp/password");
    var random: [32]u8 = undefined;
    io.random(&random);
    const disabled = std.fmt.bytesToHex(random, .lower);
    try replace(io, "/run/rabbitmq.config", try configuration(gpa, &disabled));
    try cookie(io);

    var env: std.process.Environ.Map = .init(gpa);
    try env.put("ERL_EPMD_ADDRESS", "127.0.0.1");

    var epmd = try std.process.spawn(io, .{
        .argv = &.{ bindir ++ "/epmd", "-daemon", "-address", "127.0.0.1" },
        .environ_map = &env,
    });
    const result = try epmd.wait(io);
    if (result != .exited or result.exited != 0) return error.EpmdFailed;
    Io.File.stdout().writeStreamingAll(io, "rabbitmq-start: local broker initialized\n") catch {};
}

fn usernameOk(user: []const u8) bool {
    if (user.len == 0 or user.len > 64 or std.mem.eql(u8, user, "guest") or
        std.mem.eql(u8, user, "werewolf-disabled")) return false;
    for (user) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.')
        return false;
    return true;
}

fn passwordOk(password: []const u8) bool {
    if (password.len < 12 or password.len > 256) return false;
    for (password) |c| if (c < 0x20 or c > 0x7e) return false;
    return true;
}

/// RabbitMQ's SHA-256 password format: four salt bytes followed by the
/// SHA-256 of salt || password, encoded in base64.
fn passwordHash(password: []const u8, salt: [4]u8) [48]u8 {
    var raw: [36]u8 = undefined;
    @memcpy(raw[0..4], &salt);
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    sha.update(&salt);
    sha.update(password);
    sha.final(raw[4..36]);
    var encoded: [48]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &raw);
    return encoded;
}

fn definitions(gpa: Allocator, user: []const u8, hash: []const u8) ![]const u8 {
    if (!usernameOk(user)) return error.BadUsername;
    return gpa.print(
        \\{{"users":[{{"name":"{s}","password_hash":"{s}","hashing_algorithm":"rabbit_password_hashing_sha256","tags":[]}}],
        \\"vhosts":[{{"name":"/"}}],"permissions":[{{"user":"{s}","vhost":"/","configure":".*","write":".*","read":".*"}}]}}
        \\
    , .{ user, hash, user });
}

fn configuration(gpa: Allocator, disabled: []const u8) ![]const u8 {
    return gpa.print(
        \\[
        \\ {{rabbit, [{{tcp_listeners, [{{"127.0.0.1",5672}}]}},
        \\           {{default_user, <<"werewolf-disabled">>}}, {{default_pass, <<"{s}">>}},
        \\           {{loopback_users, []}}, {{load_definitions, "/run/definitions.json"}},
        \\           {{vm_memory_high_watermark, {{absolute, 536870912}}}},
        \\           {{disk_free_limit, 50000000}}]}}
        \\].
        \\
    , .{disabled});
}

fn cookie(io: Io) !void {
    var dir = try Dir.cwd().openDir(io, "/data", .{});
    defer dir.close(io);
    // Read whole: a truncated cookie must fail rather than change this
    // broker's identity. Never follow a planted link to read or overwrite it.
    if (dir.statFile(io, ".erlang.cookie", .{ .follow_symlinks = false })) |st| {
        if (st.kind != .file) return error.BadCookie;
        var buf: [65]u8 = undefined;
        const text = try dir.readFile(io, ".erlang.cookie", &buf);
        if (text.len != 64) return error.BadCookie;
        for (text) |c| if (!std.ascii.isHex(c)) return error.BadCookie;
        return;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    var raw: [32]u8 = undefined;
    io.random(&raw);
    const encoded = std.fmt.bytesToHex(raw, .upper);
    try replace(io, "/data/.erlang.cookie", &encoded);
}

fn replace(io: Io, path: []const u8, text: []const u8) !void {
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(path).?, .{});
    defer dir.close(io);
    const tmp = ".rabbitmq-start.tmp";
    dir.deleteFile(io, tmp) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    {
        var file = try dir.createFile(io, tmp, .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        defer file.close(io);
        try file.writeStreamingAll(io, text);
        try file.sync(io);
    }
    try dir.rename(tmp, dir, std.fs.path.basename(path), io);
}

test "broker usernames cannot inject definitions or restore guest" {
    for ([_][]const u8{ "", "guest", "werewolf-disabled", "x\"", "x\\", "x\n", "x y" }) |user|
        try std.testing.expect(!usernameOk(user));
    try std.testing.expect(usernameOk("unifi-core"));
    try std.testing.expectError(error.BadUsername, definitions(std.testing.allocator, "\"", ""));
}

test "password hashing is salted SHA-256 in RabbitMQ's format" {
    const hash = passwordHash("werewolf-check-pass-1", .{ 1, 2, 3, 4 });
    var raw: [36]u8 = undefined;
    try std.base64.standard.Decoder.decode(&raw, &hash);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, raw[0..4]);
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("\x01\x02\x03\x04werewolf-check-pass-1", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, raw[4..36]);
    try std.testing.expect(passwordOk("quotes\" and \\ are hashed safely"));
    try std.testing.expect(!passwordOk("short"));
    try std.testing.expect(!passwordOk("werewolf\npassword"));
}
