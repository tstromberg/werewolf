//! Kafka's partition logs are expected; application log files are not.
const std = @import("std");
const driver = @import("test-driver");

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(init.io, a, args[3]);
    var unexpected: usize = 0;
    for ([_][]const u8{ "/data/svc/kafka", "/run/svc/kafka" }) |path| {
        var dir = try std.Io.Dir.cwd().openDir(init.io, path, .{ .iterate = true });
        defer dir.close(init.io);
        var walk = try dir.walk(a);
        defer walk.deinit();
        while (try walk.next(init.io)) |entry| {
            if (std.mem.endsWith(u8, entry.basename, ".log") and
                !partitionLog(entry.path))
            {
                if (unexpected == 0) {
                    const full = try a.print("{s}/{s}", .{ path, entry.path });
                    try std.Io.File.stderr().writeStreamingAll(
                        init.io,
                        try a.print("kafka-test: unexpected log {s}\n", .{full}),
                    );
                    if (std.mem.startsWith(u8, entry.basename, "hs_err_pid"))
                        try crashDetails(init.io, a, full);
                }
                unexpected += 1;
            }
        }
    }
    try ctx.result(init.io, args[1], "kafka-console-logs", unexpected == 0);
}

fn crashDetails(io: std.Io, a: std.mem.Allocator, path: []const u8) !void {
    const report = driver.system.read(io, a, path) catch |err| {
        try std.Io.File.stderr().writeStreamingAll(io, try a.print(
            "kafka-test: crash report: {s}\n",
            .{@errorName(err)},
        ));
        return;
    };
    const Section = struct { marker: []const u8, limit: usize };
    for ([_]Section{
        .{ .marker = "siginfo:", .limit = 512 },
        .{ .marker = "Instructions: (pc=", .limit = 4096 },
        .{ .marker = "CPU:", .limit = 1024 },
    }) |section| {
        if (std.mem.find(u8, report, section.marker)) |at| {
            var text = report[at..@min(report.len, at + section.limit)];
            if (std.mem.find(u8, text, "\n\n")) |end| text = text[0 .. end + 1];
            try std.Io.File.stderr().writeStreamingAll(io, text);
            try std.Io.File.stderr().writeStreamingAll(io, "\n");
        }
    }
}

fn partitionLog(path: []const u8) bool {
    var parts = std.mem.splitScalar(u8, path, '/');
    if (!std.mem.eql(u8, parts.next() orelse return false, "log")) return false;
    const topic = parts.next() orelse return false;
    const dash = std.mem.findScalarLast(u8, topic, '-') orelse return false;
    if (dash == 0 or dash + 1 == topic.len or
        !std.ascii.isDigit(topic[dash + 1])) return false;
    _ = std.fmt.parseInt(u32, topic[dash + 1 ..], 10) catch return false;
    return parts.next() != null;
}

test "only partition log trees are allowed" {
    try std.testing.expect(partitionLog("log/orders-0/00000000000000000000.log"));
    try std.testing.expect(partitionLog("log/__cluster_metadata-0/00000000000000000000.log"));
    try std.testing.expect(!partitionLog("server.log"));
    try std.testing.expect(!partitionLog("log/server.log"));
    try std.testing.expect(!partitionLog("log/orders-x/server.log"));
    try std.testing.expect(!partitionLog("log/orders-+1/server.log"));
    try std.testing.expect(!partitionLog("log/-0/server.log"));
    try std.testing.expect(!partitionLog("log/orders-0"));
    try std.testing.expect(!partitionLog("somewhere/orders-0/server.log"));
}
