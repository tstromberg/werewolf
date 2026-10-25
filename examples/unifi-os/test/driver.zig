//! UniFi OS integration checks that need code: MongoDB and RabbitMQ wire
//! protocols, the D-Bus adapter and nginx reload boundary as Core, ingress
//! routing, HTTPS and the identity kept across a reboot. Each runs as root,
//! dropping to the tested account where the kernel decides.
const std = @import("std");
const driver = @import("test-driver");
const dbus = @import("dbus.zig");
const route = @import("route.zig");
const unix = @import("unix.zig");
const web = @import("web.zig");
const amqp = driver.amqp;
const bson = driver.bson;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const Mode = enum { ready, stores, dbus, nginx, network, web, identity };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const suite = args[1];
    const mode = std.meta.stringToEnum(Mode, args[2]) orelse return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const seed = std.mem.eql(u8, ctx.phase, "seed");
    const passwd = try Io.Dir.cwd().readFileAlloc(io, "/etc/passwd", a, .limited(1 << 20));
    const core = try unix.account(passwd, "_oci-unifi-core");
    const r: Reporter = .{ .io = io, .ctx = ctx, .suite = suite };
    switch (mode) {
        .ready, .stores => {
            const secret = try Io.Dir.cwd().readFileAlloc(
                io,
                "/run/config/rabbitmq/password",
                a,
                .limited(1024),
            );
            const app: amqp.Login = .{
                .user = "app",
                .password = std.mem.trimEnd(u8, secret, "\r\n"),
            };
            // A restart attack may come between readiness and these checks.
            try poll(io, suite, "MongoDB", 60, mongodbAnswers, .{io});
            try poll(io, suite, "RabbitMQ", 90, brokerAnswers, .{ io, app });
            if (mode == .ready) return ctx.result(io, suite, "unifi-stores-ready", true);
            if (seed) {
                try r.report("unifi-mongodb", mongodb(io, a, ctx.run, true));
                try r.report("unifi-rabbitmq", driver.within(io, 10, amqp.roundTrip, .{
                    io, a, app, ctx.run,
                }));
            } else {
                try r.report("unifi-mongodb-kept", mongodb(io, a, ctx.run, false));
                try r.report("unifi-rabbitmq-kept", driver.within(io, 10, amqp.retained, .{
                    io, a, app, ctx.run,
                }));
            }
            try r.report("unifi-rabbitmq-no-guest", driver.within(io, 10, amqp.refused, .{
                io, a, amqp.Login{ .user = "guest", .password = "guest" },
            }));
        },
        .dbus => {
            try r.report("unifi-service-state", dbus.asCore(core, dbus.serviceState));
            try r.report("unifi-no-service-control", dbus.asCore(core, dbus.noControl));
            try r.report("unifi-no-other-units", dbus.asCore(core, dbus.noOtherUnits));
            try r.report("unifi-dbus-identity", dbus.badClaim(core));
            try r.report("unifi-dbus-peer", dbus.wrongPeer(core));
        },
        .nginx => {
            try r.report("unifi-nginx-reload", reload(io, a, core));
            if (seed) try r.report("unifi-nginx-invalid-config", invalidConfig(io, a, core));
            try r.report("unifi-nginx-commands-denied", denied(core));
            // Root passes the socket's DAC; only the supervisor's peer check refuses it.
            try r.report("unifi-nginx-peer", answers(null, "reload\n", ""));
            const nginx = try unix.account(passwd, "nginx");
            try r.report("unifi-nginx-private", private(nginx, core.gid));
        },
        .network => {
            try poll(io, suite, "Network", 300, networkAnswers, .{io});
            try r.report("unifi-internal-listeners", exposure(io, a, suite));
        },
        .web => {
            try poll(io, suite, "Core", 300, coreAnswers, .{io});
            if (seed) try r.report("unifi-core-stable", stable(io));
            // nginx serves the console page over HTTPS.
            try r.report("unifi-console", if (poll(io, suite, "console", 60, consoleAnswers, .{io}))
                true
            else |err|
                err);
        },
        .identity => if (seed)
            try r.report("unifi-persistence-record", record(io, a, ctx.run))
        else
            try r.report("unifi-identity-kept", kept(io, a, ctx.run)),
    }
}

const Reporter = struct {
    io: Io,
    ctx: driver.Run,
    suite: []const u8,

    /// Emit case's result; an error fails it, with the error's name logged.
    fn report(r: Reporter, case: []const u8, outcome: anyerror!bool) !void {
        const passed = outcome catch |err| blk: {
            std.debug.print("{s}: {s}: {s}\n", .{ r.suite, case, @errorName(err) });
            break :blk false;
        };
        try r.ctx.result(r.io, r.suite, case, passed);
    }
};

/// Retry check every second until it succeeds or seconds pass.
fn poll(
    io: Io,
    suite: []const u8,
    what: []const u8,
    seconds: i64,
    comptime check: anytype,
    args: anytype,
) !void {
    const stop = Io.Clock.awake.now(io).addDuration(.fromSeconds(seconds));
    while (true) {
        if (@call(.auto, check, args)) |_| return else |err| {
            if (Io.Clock.awake.now(io).compare(.gte, stop)) {
                std.debug.print("{s}: {s} not ready: {s}\n", .{ suite, what, @errorName(err) });
                return err;
            }
        }
        try io.sleep(.fromSeconds(1), .awake);
    }
}

const database = "werewolf_check";

fn command(io: Io, a: Allocator, value: anytype) ![]const u8 {
    const json = try std.json.Stringify.valueAlloc(a, value, .{});
    return driver.within(io, 5, bson.exchange, .{ io, a, try bson.encode(a, json) });
}

fn succeeded(reply: []const u8) !bool {
    return try (try bson.require(reply, "ok")).number() == 1;
}

fn mongodbAnswers(io: Io) !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const reply = try command(io, arena.allocator(), .{ .ping = 1, .@"$db" = database });
    if (!try succeeded(reply)) return error.NotReady;
}

fn brokerAnswers(io: Io, app: amqp.Login) !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    try driver.within(io, 5, amqp.ready, .{ io, arena.allocator(), app });
}

/// This run's document, written on seed, is the only one with its _id.
fn mongodb(io: Io, a: Allocator, run: []const u8, write: bool) !bool {
    if (write and !try succeeded(try command(io, a, .{
        .update = "probe",
        .updates = .{.{
            .q = .{ ._id = run },
            .u = .{ .@"$set" = .{ .value = "werewolf-wire-check" } },
            .upsert = true,
        }},
        .@"$db" = database,
    }))) return false;
    const found = try command(io, a, .{
        .find = "probe",
        .filter = .{ ._id = run },
        .@"$db" = database,
    });
    if (!try succeeded(found)) return false;
    const cursor = try (try bson.require(found, "cursor")).object(3);
    const batch = try (try bson.require(cursor, "firstBatch")).object(4);
    const first = try (try bson.field(batch, "0") orelse return false).object(3);
    return std.mem.eql(u8, try (try bson.require(first, "_id")).string(), run) and
        std.mem.eql(u8, try (try bson.require(first, "value")).string(), "werewolf-wire-check") and
        try bson.field(batch, "1") == null;
}

const reload_socket = "/data/share/unifi/reload/nginx.sock";
const upstream = "/data/share/unifi/config/http/upstream-uos.conf";

/// Send one packet to the reload supervisor as who (root when null) and
/// return its answer, empty when it hangs up instead.
fn request(who: ?unix.Identity, packet: []const u8, answer: *[64]u8) ![]const u8 {
    const fd = try unix.connect(who, reload_socket, linux.SOCK.SEQPACKET);
    defer _ = linux.close(fd);
    unix.send(fd, packet) catch |err| {
        if (err == error.ConnectionResetByPeer) return answer[0..0];
        return err;
    };
    // The supervisor runs nginx -t before it answers a reload.
    const n = unix.receive(fd, answer, 10_000) catch |err| {
        if (err == error.ConnectionResetByPeer) return answer[0..0];
        return err;
    };
    return answer[0..n];
}

fn answers(who: ?unix.Identity, packet: []const u8, want: []const u8) !bool {
    var answer: [64]u8 = undefined;
    return std.mem.eql(u8, try request(who, packet, &answer), want);
}

/// PIDs of nginx's worker processes.
fn workers(io: Io, a: Allocator) ![]const u32 {
    var proc = try Io.Dir.cwd().openDir(io, "/proc", .{ .iterate = true });
    defer proc.close(io);
    var pids: std.ArrayList(u32) = .empty;
    var it = proc.iterate();
    while (try it.next(io)) |entry| {
        const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
        var path: [32]u8 = undefined;
        var command_line: [32]u8 = undefined;
        // A process may exit between the listing and the read.
        const text = proc.readFile(
            io,
            try std.mem.print(&path, "{d}/cmdline", .{pid}),
            &command_line,
        ) catch continue;
        if (std.mem.startsWith(u8, text, "nginx: worker process")) try pids.append(a, pid);
    }
    return pids.items;
}

fn subset(small: []const u32, large: []const u32) bool {
    for (small) |pid| if (std.mem.findScalar(u32, large, pid) == null) return false;
    return true;
}

/// Core's reload request starts new workers within five seconds.
fn reload(io: Io, a: Allocator, core: unix.Identity) !bool {
    const before = try workers(io, a);
    if (before.len == 0) return error.NoWorkers;
    if (!try answers(core, "reload\n", "ok\n")) return false;
    const stop = Io.Clock.awake.now(io).addDuration(.fromSeconds(5));
    while (true) {
        const after = try workers(io, a);
        if (after.len > 0 and !subset(after, before)) return true;
        if (Io.Clock.awake.now(io).compare(.gte, stop)) return false;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
}

/// A configuration nginx -t refuses is not loaded and the running workers
/// stay; once repaired, reload works again.
fn invalidConfig(io: Io, a: Allocator, core: unix.Identity) !bool {
    const original = try Io.Dir.cwd().readFileAlloc(io, upstream, a, .limited(1 << 20));
    const before = try workers(io, a);
    if (before.len == 0) return error.NoWorkers;
    const broken = try std.mem.concat(a, u8, &.{ original, "\nwerewolf_invalid_directive;\n" });
    const refused = brokenReload(io, a, core, broken, before);
    try rewrite(core, original);
    if (!try refused) return false;
    return answers(core, "reload\n", "ok\n");
}

fn brokenReload(
    io: Io,
    a: Allocator,
    core: unix.Identity,
    broken: []const u8,
    before: []const u32,
) !bool {
    try rewrite(core, broken);
    if (!try answers(core, "reload\n", "failed\n")) return false;
    return subset(before, try workers(io, a));
}

/// Replace the upstream configuration as Core, who owns it.
fn rewrite(core: unix.Identity, bytes: []const u8) !void {
    if (try unix.as(core, writeFile, .{ upstream, bytes }) != .SUCCESS) return error.Rewrite;
}

fn writeFile(path: [*:0]const u8, bytes: []const u8) linux.E {
    const rc = linux.open(path, .{ .ACCMODE = .WRONLY, .TRUNC = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return linux.errno(rc);
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var n: usize = 0;
    while (n < bytes.len) {
        const wrote = linux.write(fd, bytes[n..].ptr, bytes.len - n);
        if (linux.errno(wrote) != .SUCCESS) return linux.errno(wrote);
        n += wrote;
    }
    return linux.errno(linux.fsync(fd));
}

/// Anything but the exact reload packet is denied.
fn denied(core: unix.Identity) !bool {
    const many: [128]u8 = @splat('x');
    for ([_][]const u8{ "stop\n", "reload\nextra", "reload\x00", &many }) |packet|
        if (!try answers(core, packet, "denied\n")) return false;
    return true;
}

/// nginx, with Core's group, can neither list Core's private data nor
/// rewrite Core's shared configuration.
fn private(nginx: unix.Identity, core_group: u32) !bool {
    const groups = [_]u32{core_group};
    const who: unix.Identity = .{ .uid = nginx.uid, .gid = nginx.gid, .groups = &groups };
    const listed = try unix.as(who, opens, .{
        "/data/svc/unifi-core",
        linux.O{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
    });
    const written = try unix.as(who, opens, .{
        upstream,
        linux.O{ .ACCMODE = .WRONLY, .CLOEXEC = true },
    });
    return refusal(listed) and refusal(written);
}

fn opens(path: [*:0]const u8, flags: linux.O) linux.E {
    const rc = linux.open(path, flags, 0);
    if (linux.errno(rc) == .SUCCESS) _ = linux.close(@intCast(rc));
    return linux.errno(rc);
}

fn refusal(e: linux.E) bool {
    return e == .ACCES or e == .PERM;
}

/// Network's status API reports a running server on a connected database.
fn networkReady(a: Allocator, body: []const u8) !bool {
    const value = try std.json.parseFromSliceLeaky(std.json.Value, a, body, .{});
    if (value != .object) return false;
    const meta = value.object.get("meta") orelse return false;
    if (meta != .object) return false;
    const rc = meta.object.get("rc") orelse return false;
    if (rc != .string or !std.mem.eql(u8, rc.string, "ok")) return false;
    for ([_][]const u8{ "server_running", "db_running", "db_connected" }) |name| {
        const field = meta.object.get(name) orelse return false;
        if (field != .bool or !field.bool) return false;
    }
    for ([_][]const u8{ "db_repairing", "db_importing" }) |name| {
        const field = meta.object.get(name) orelse return false;
        if (field != .bool or field.bool) return false;
    }
    return true;
}

fn networkAnswers(io: Io) !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const reply = try driver.within(io, 5, web.get, .{ io, a, 8081, "/status", false });
    if (reply.status != 200 or !try networkReady(a, reply.body)) return error.NotReady;
}

fn coreAnswers(io: Io) !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const reply = try driver.within(io, 5, web.get, .{
        io, arena.allocator(), 11081, "/api/system", false,
    });
    if (reply.status != 200) return error.NotReady;
}

/// Core keeps answering for five seconds after it first does.
fn stable(io: Io) !bool {
    for (0..5) |_| {
        try io.sleep(.fromSeconds(1), .awake);
        try coreAnswers(io);
    }
    return true;
}

fn consoleAnswers(io: Io) !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const reply = try driver.within(io, 10, web.get, .{ io, arena.allocator(), 443, "/", true });
    if (reply.status != 200 or !web.manifest(reply.body)) return error.NoConsole;
}

// Ports nothing outside may reach, and the ones also bound to loopback only.
const private_ports = [_]u16{
    5432, 27017, 5672, 4369, 25672, 11051, 11081, 11083, 11084, 8081, 8443, 8843, 8880, 6789, 28082,
};
const loopback_ports = private_ports[0..10];
// Packets claiming to answer a local client's connection, and an ephemeral port.
const sources = [_]u16{ 5432, 8081, 40000 };
// Errors of a blackholed or prohibited input route.
const refusals = [_]linux.E{ .INVAL, .ACCES, .NETUNREACH, .HOSTUNREACH };

/// The kernel routes outside TCP to public HTTPS on every address but
/// refuses each listening private port, whatever source port it claims.
fn exposure(io: Io, a: Allocator, suite: []const u8) !bool {
    const listeners = (try driver.system.listeners(io, a, "tcp")).array.items;
    for ([_]u16{ 8080, 8081, 28082 }) |port| if (!listening(listeners, port)) {
        std.debug.print("{s}: Network listener {d} missing\n", .{ suite, port });
        return false;
    };
    for (listeners) |listener| {
        const port: u16 = @intCast(listener.object.get("port").?.integer);
        const address = listener.object.get("address").?.string;
        if (std.mem.findScalar(u16, loopback_ports, port) != null and
            !std.mem.eql(u8, address, "127.0.0.1"))
        {
            std.debug.print("{s}: port {d} listens on {s}\n", .{ suite, port, address });
            return false;
        }
    }
    const addresses = try route.addresses(a);
    if (addresses.len == 0) return error.NoExternalAddress;
    for (addresses) |host| for (sources) |source| {
        const kind = try route.ingress(host.index, host.ip, 443, source);
        if (kind != route.local) {
            std.debug.print("{s}: HTTPS to {d}.{d}.{d}.{d} from port {d} refused: {d}\n", .{
                suite, host.ip[0], host.ip[1], host.ip[2], host.ip[3], source, kind,
            });
            return false;
        }
    };
    for (private_ports) |port| {
        if (!listening(listeners, port)) continue;
        // A refused lookup proves something only for a port that answers.
        try driver.within(io, 1, answersLocally, .{ io, port });
        for (addresses) |host| for (sources) |source| {
            const kind = try route.ingress(host.index, host.ip, port, source);
            const blocked = for (refusals) |e| {
                if (kind == -@as(i32, @backingInt(e))) break true;
            } else false;
            if (!blocked) {
                std.debug.print("{s}: port {d} on {d}.{d}.{d}.{d} from port {d}: {d}\n", .{
                    suite, port, host.ip[0], host.ip[1], host.ip[2], host.ip[3], source, kind,
                });
                return false;
            }
        };
    }
    return true;
}

fn listening(listeners: []const std.json.Value, port: u16) bool {
    for (listeners) |listener| if (listener.object.get("port").?.integer == port) return true;
    return false;
}

fn answersLocally(io: Io, port: u16) !void {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const stream = try address.connect(io, .{ .mode = .stream });
    stream.close(io);
}

const identity_path = "/data/svc/unifi-core/unifi-core/uuid";
const certificate_path = "/data/share/unifi/config/tls/unifi-core.crt";
const record_path = "/data/.unifi-identity-check";

const Identity = struct { run: []const u8, uuid: []const u8, certificate: []const u8 };

fn current(io: Io, a: Allocator, run: []const u8) !Identity {
    const certificate = try Io.Dir.cwd().readFileAlloc(io, certificate_path, a, .limited(1 << 20));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(certificate, &digest, .{});
    return .{
        .run = run,
        .uuid = try Io.Dir.cwd().readFileAlloc(io, identity_path, a, .limited(64)),
        .certificate = try a.dupe(u8, &std.fmt.bytesToHex(digest, .lower)),
    };
}

/// Record the console's UUID and certificate digest for this run.
fn record(io: Io, a: Allocator, run: []const u8) !bool {
    const json = try std.json.Stringify.valueAlloc(a, try current(io, a, run), .{});
    var file = try Io.Dir.cwd().createFile(io, record_path, .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, json);
    try file.sync(io);
    return true;
}

/// The reboot kept the UUID and certificate this run recorded.
fn kept(io: Io, a: Allocator, run: []const u8) !bool {
    const raw = try Io.Dir.cwd().readFileAlloc(io, record_path, a, .limited(4096));
    const saved = try std.json.parseFromSliceLeaky(Identity, a, raw, .{});
    const now = try current(io, a, run);
    return std.mem.eql(u8, saved.run, run) and std.mem.eql(u8, saved.uuid, now.uuid) and
        std.mem.eql(u8, saved.certificate, now.certificate);
}

test {
    _ = dbus;
    _ = route;
    _ = unix;
    _ = web;
}

test "Network is ready only with every health field present and right" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ready = "{\"meta\":{\"rc\":\"ok\",\"server_running\":true,\"db_running\":true," ++
        "\"db_connected\":true,\"db_repairing\":false,\"db_importing\":false}}";
    try t.expect(try networkReady(a, ready));
    try t.expect(!try networkReady(a, "{\"meta\":{\"rc\":\"ok\",\"server_running\":true," ++
        "\"db_running\":true,\"db_connected\":true,\"db_repairing\":false}}"));
    try t.expect(!try networkReady(a, "{\"meta\":{\"rc\":\"ok\",\"server_running\":true," ++
        "\"db_running\":true,\"db_connected\":\"true\",\"db_repairing\":false," ++
        "\"db_importing\":false}}"));
    try t.expect(!try networkReady(a, "[]"));
    try t.expectError(error.UnexpectedEndOfInput, networkReady(a, "{"));
}

test "worker sets compare by membership" {
    try std.testing.expect(subset(&.{ 2, 3 }, &.{ 1, 2, 3 }));
    try std.testing.expect(!subset(&.{ 2, 4 }, &.{ 1, 2, 3 }));
}
