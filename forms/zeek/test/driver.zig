//! Correlate a fresh DNS transaction with Zeek's DNS and connection records.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Json = std.json.Value;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "traffic")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    // Iteration keeps its run ID; each invocation still needs fresh traffic.
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const suffix = std.fmt.bytesToHex(nonce, .lower);
    const query = try a.print("ww-{s}-{s}-{s}.invalid", .{ ctx.run, &suffix, ctx.phase });
    const dns = try capturedQuery(io, a, query);
    try ctx.result(io, args[1], "zeek-dns-log", stringIs(dns, "rcode_name", "NXDOMAIN"));
    const uid = dns.object.get("uid") orelse return error.ConnectionId;
    if (uid != .string or uid.string.len == 0) return error.ConnectionId;
    const conn = try awaitRecord(
        io,
        a,
        "/data/svc/zeek/conn.log",
        "uid",
        uid.string,
        Io.Clock.awake.now(io).addDuration(.fromSeconds(45)),
    );
    const port = conn.object.get("id.resp_p") orelse return error.ConnectionPort;
    try ctx.result(io, args[1], "zeek-connection-log", port == .integer and
        port.integer == 53 and stringIs(conn, "id.orig_h", "10.0.2.15"));
}

fn capturedQuery(io: Io, a: Allocator, query: []const u8) !Json {
    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(45));
    var attempts: usize = 0;
    while (Io.Clock.awake.now(io).compare(.lt, deadline)) {
        attempts += 1;
        const request_end = Io.Clock.awake.now(io).addDuration(.fromSeconds(15));
        const stop = if (request_end.compare(.lt, deadline)) request_end else deadline;
        const result = try std.process.run(a, io, .{
            .argv = &.{ "/usr/bin/drill", query, "@10.0.2.3" },
            .stdout_limit = .limited(16384),
            .stderr_limit = .limited(4096),
            .timeout = .{ .deadline = .{ .clock = .awake, .raw = stop } },
        });
        if (result.term != .exited or result.term.exited != 0 or
            std.mem.find(u8, result.stdout, "rcode: NXDOMAIN") == null) return error.DnsQuery;
        // Require a captured packet, rather than just script initialization.
        const poll_end = Io.Clock.awake.now(io).addDuration(.fromSeconds(2));
        const record = awaitRecord(
            io,
            a,
            "/data/svc/zeek/dns.log",
            "query",
            query,
            if (poll_end.compare(.lt, deadline)) poll_end else deadline,
        ) catch |err| {
            if (err == error.RecordNotFound) continue;
            return err;
        };
        std.debug.print("test-zeek: captured DNS after {d} query attempt(s)\n", .{attempts});
        return record;
    }
    std.debug.print("test-zeek: no captured DNS record for {s}\n", .{query});
    return error.CaptureNotReady;
}

fn stringIs(value: Json, field: []const u8, expected: []const u8) bool {
    if (value != .object) return false;
    const actual = value.object.get(field) orelse return false;
    return actual == .string and std.mem.eql(u8, actual.string, expected);
}

fn awaitRecord(
    io: Io,
    a: Allocator,
    path: []const u8,
    field: []const u8,
    value: []const u8,
    deadline: Io.Timestamp,
) !Json {
    while (true) {
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        const attempt = arena.allocator();
        const raw = Io.Dir.cwd().readFileAlloc(
            io,
            path,
            attempt,
            .limited(4 << 20),
        ) catch |err| blk: {
            if (err != error.FileNotFound) return err;
            break :blk "";
        };
        if (try findRecord(attempt, raw, field, value)) |record| {
            const kept = try a.dupe(u8, record);
            return std.json.parseFromSliceLeaky(Json, a, kept, .{});
        }
        if (Io.Clock.awake.now(io).compare(.gte, deadline)) return error.RecordNotFound;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
}

fn findRecord(a: Allocator, raw: []const u8, field: []const u8, value: []const u8) !?[]const u8 {
    // A writer can still be appending its final line. Complete malformed lines fail.
    const end = std.mem.findScalarLast(u8, raw, '\n') orelse return null;
    var lines = std.mem.splitScalar(u8, raw[0..end], '\n');
    var count: usize = 0;
    var found: ?[]const u8 = null;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        count += 1;
        if (count > 16384) return error.TooManyRecords;
        const record = std.json.parseFromSliceLeaky(Json, a, line, .{}) catch
            return error.RecordFormat;
        if (record != .object) return error.RecordFormat;
        if (found == null and stringIs(record, field, value)) found = line;
    }
    return found;
}

test "log records match the exact fresh query and tolerate only an unfinished final line" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const old = "{\"query\":\"werewolf-old.invalid\"}\n";
    const fresh = "{\"query\":\"werewolf-new.invalid\",\"uid\":\"C1\"}\n";
    try std.testing.expectEqualStrings(
        std.mem.trimEnd(u8, fresh, "\n"),
        (try findRecord(a, old ++ fresh, "query", "werewolf-new.invalid")).?,
    );
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try findRecord(a, old ++ "{\"query\":", "query", "werewolf-new.invalid"),
    );
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try findRecord(a, fresh, "query", "werewolf-new"),
    );
    try std.testing.expectError(
        error.RecordFormat,
        findRecord(a, "{\"query\":\n", "query", "werewolf-new.invalid"),
    );
    try std.testing.expectError(
        error.RecordFormat,
        findRecord(a, "[]\n", "query", "werewolf-new.invalid"),
    );
    // Read-only queries can be repeated while capture starts; keep one packet's UID.
    try std.testing.expectEqualStrings(
        std.mem.trimEnd(u8, fresh, "\n"),
        (try findRecord(a, fresh ++ fresh, "query", "werewolf-new.invalid")).?,
    );
    try std.testing.expectError(
        error.RecordFormat,
        findRecord(a, fresh ++ "[]\n", "query", "werewolf-new.invalid"),
    );
}
