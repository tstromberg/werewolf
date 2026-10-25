//! Fixed MongoDB OP_MSG probes; no Python or database shell in the test image.
const std = @import("std");
const driver = @import("test-driver");
const bson = driver.bson;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const database = "werewolf_check";

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const ready = std.mem.eql(u8, args[2], "ready");
    if (!ready and !std.mem.eql(u8, args[2], "wire")) return error.Usage;
    try waitReady(io);
    if (ready) {
        try ctx.result(io, args[1], "mongodb-ready", true);
        return;
    }
    try wire(io, a, ctx, args[1]);
}

fn waitReady(io: Io) !void {
    const stop = Io.Clock.awake.now(io).addDuration(.fromSeconds(60));
    while (true) {
        var attempt: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer attempt.deinit();
        const reply = command(
            io,
            attempt.allocator(),
            .{ .ping = 1, .@"$db" = database },
        ) catch |err| {
            switch (err) {
                error.ConnectionRefused,
                error.ConnectionResetByPeer,
                error.ReadFailed,
                error.WriteFailed,
                error.EndOfStream,
                error.Timeout,
                => {},
                else => return err,
            }
            if (Io.Clock.awake.now(io).compare(.gte, stop)) return error.DatabaseNotReady;
            try io.sleep(.fromMilliseconds(100), .awake);
            continue;
        };
        if (try success(reply)) break;
        if (Io.Clock.awake.now(io).compare(.gte, stop)) return error.DatabaseNotReady;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
}

fn wire(io: Io, a: Allocator, ctx: driver.Run, suite: []const u8) !void {
    if (!try success(try command(io, a, .{ .ping = 1, .@"$db" = database }))) return error.Ping;
    const seed = std.mem.eql(u8, ctx.phase, "seed");
    if (seed) {
        const updated = try command(io, a, .{
            .update = "probe",
            .updates = .{.{
                .q = .{ ._id = ctx.run },
                .u = .{ .@"$set" = .{ .value = "werewolf-wire-check" } },
                .upsert = true,
            }},
            .@"$db" = database,
        });
        if (!try success(updated)) return error.Update;
    }
    const found = try command(io, a, .{
        .find = "probe",
        .filter = .{ ._id = ctx.run },
        .@"$db" = database,
    });
    if (!try success(found)) return error.Find;
    const cursor = try (try bson.require(found, "cursor")).object(3);
    const batch = try (try bson.require(cursor, "firstBatch")).object(4);
    const first = try (try bson.require(batch, "0")).object(3);
    try ctx.result(io, suite, if (seed)
        "mongodb-works"
    else
        "mongodb-kept", std.mem.eql(u8, try (try bson.require(first, "_id")).string(), ctx.run) and
        std.mem.eql(
            u8,
            try (try bson.require(first, "value")).string(),
            "werewolf-wire-check",
        ) and
        try bson.field(batch, "1") == null);
    const refused = try command(io, a, .{
        .find = "probe",
        .filter = .{ .@"$where" = "return true" },
        .@"$db" = database,
    });
    try ctx.result(io, suite, "mongodb-no-javascript", try (try bson.require(
        refused,
        "ok",
    )).number() == 0 and
        try (try bson.require(refused, "code")).number() > 0 and
        std.mem.find(u8, try (try bson.require(refused, "errmsg")).string(), "$where") != null);
}
fn success(reply: []const u8) !bool {
    return try (try bson.require(reply, "ok")).number() == 1;
}
fn command(io: Io, a: Allocator, value: anytype) ![]const u8 {
    const json = try std.json.Stringify.valueAlloc(a, value, .{});
    return driver.within(io, 5, bson.exchange, .{ io, a, try bson.encode(a, json) });
}
