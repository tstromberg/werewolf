//! RabbitMQ over AMQP 0-9-1 as the configured application user, and the
//! broker's runtime directory searched for that user's password.
const std = @import("std");
const driver = @import("test-driver");
const amqp = driver.amqp;
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const suite = args[1];
    const ready = std.mem.eql(u8, args[2], "ready");
    if (!ready and !std.mem.eql(u8, args[2], "wire")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const secret = try Io.Dir.cwd().readFileAlloc(
        io,
        "/run/config/rabbitmq/password",
        a,
        .limited(1024),
    );
    const app: amqp.Login = .{ .user = "app", .password = std.mem.trimEnd(u8, secret, "\r\n") };
    // A restart attack may come between the readiness and wire suites.
    try waitReady(io, suite, app);
    if (ready) return ctx.result(io, suite, "rabbitmq-ready", true);
    if (std.mem.eql(u8, ctx.phase, "seed")) {
        try report(io, ctx, suite, "rabbitmq-works", driver.within(io, 10, amqp.roundTrip, .{
            io, a, app, ctx.run,
        }));
    } else try report(io, ctx, suite, "rabbitmq-kept", driver.within(io, 10, amqp.retained, .{
        io, a, app, ctx.run,
    }));
    try report(io, ctx, suite, "rabbitmq-guest", driver.within(io, 10, amqp.refused, .{
        io, a, amqp.Login{ .user = "guest", .password = "guest" },
    }));
    try report(
        io,
        ctx,
        suite,
        "rabbitmq-secret",
        hidden(io, a, suite, "/run/svc/rabbitmq", app.password),
    );
}

fn waitReady(io: Io, suite: []const u8, app: amqp.Login) !void {
    const stop = Io.Clock.awake.now(io).addDuration(.fromSeconds(90));
    while (true) {
        var attempt: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer attempt.deinit();
        driver.within(io, 5, amqp.ready, .{ io, attempt.allocator(), app }) catch |err| {
            if (Io.Clock.awake.now(io).compare(.gte, stop)) {
                std.debug.print("{s}: broker not ready: {s}\n", .{ suite, @errorName(err) });
                return err;
            }
            try io.sleep(.fromSeconds(1), .awake);
            continue;
        };
        return;
    }
}

fn report(
    io: Io,
    ctx: driver.Run,
    suite: []const u8,
    case: []const u8,
    outcome: anyerror!bool,
) !void {
    const passed = outcome catch |err| blk: {
        std.debug.print("{s}: {s}: {s}\n", .{ suite, case, @errorName(err) });
        break :blk false;
    };
    try ctx.result(io, suite, case, passed);
}

/// No regular file under root holds secret, like grep -r. Unreadable files fail.
fn hidden(io: Io, a: Allocator, suite: []const u8, root: []const u8, secret: []const u8) !bool {
    if (secret.len == 0) return error.EmptySecret;
    var dir = try Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(a);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const text = try entry.dir.readFileAlloc(io, entry.basename, a, .limited(16 << 20));
        defer a.free(text);
        if (std.mem.find(u8, text, secret) != null) {
            std.debug.print("{s}: password found in {s}/{s}\n", .{ suite, root, entry.path });
            return false;
        }
    }
    return true;
}

test "the password search descends directories and skips links" {
    const t = std.testing;
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(t.io, ".", t.allocator);
    defer t.allocator.free(root);
    try tmp.dir.createDirPath(t.io, "a/b");
    try tmp.dir.writeFile(t.io, .{ .sub_path = "a/b/config", .data = "user=app\n" });
    try tmp.dir.symLink(t.io, "/run/config/rabbitmq/password", "a/link", .{});
    try t.expect(try hidden(t.io, t.allocator, "test", root, "werewolf-check-pass-1"));
    try tmp.dir.writeFile(t.io, .{ .sub_path = "a/b/leak", .data = "x werewolf-check-pass-1 y" });
    try t.expect(!try hidden(t.io, t.allocator, "test", root, "werewolf-check-pass-1"));
    try t.expectError(error.EmptySecret, hidden(t.io, t.allocator, "test", root, ""));
}
