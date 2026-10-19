//! Real bait protocols: refuse an FTP login and require its fresh audit event.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "wire")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    var random: [8]u8 = undefined;
    io.random(&random);
    const user = try a.print("integration-bait-{s}-{x}", .{ ctx.run, &random });
    const Event = union(enum) { checked: anyerror!void, timeout: Io.Cancelable!void };
    var buffer: [2]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.checked, protocols, .{ io, a, ctx, args[1], user });
    try events.concurrent(.timeout, sleep, .{io});
    switch (try events.await()) {
        .checked => |result| try result,
        .timeout => |result| {
            try result;
            return error.BaitProtocolTimeout;
        },
    }
}
fn sleep(io: Io) Io.Cancelable!void {
    try io.sleep(.fromSeconds(60), .awake);
}

fn protocols(io: Io, a: Allocator, ctx: driver.Run, suite: []const u8, user: []const u8) !void {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(21) };
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var in_buffer: [4096]u8 = undefined;
    var out_buffer: [1024]u8 = undefined;
    var reader = stream.reader(io, &in_buffer);
    var writer = stream.writer(io, &out_buffer);
    const banner = try reader.interface.takeDelimiterInclusive('\n');
    try ctx.result(io, suite, "oc-ftp", status(banner, "220") and
        std.mem.startsWith(u8, banner, "220 FTP server ready"));
    try writer.interface.print("USER {s}\r\n", .{user});
    try writer.interface.flush();
    if (!status(try reader.interface.takeDelimiterInclusive('\n'), "331")) return error.UserReply;
    try writer.interface.writeAll("PASS wrong-password\r\n");
    try writer.interface.flush();
    if (!status(
        try reader.interface.takeDelimiterInclusive('\n'),
        "530",
    )) return error.LoginAccepted;
    try writer.interface.writeAll("QUIT\r\n");
    try writer.interface.flush();
    if (!status(try reader.interface.takeDelimiterInclusive('\n'), "221")) return error.QuitReply;

    const ssh_address: Io.net.IpAddress = .{ .ip4 = .loopback(22) };
    const ssh = try ssh_address.connect(io, .{ .mode = .stream });
    defer ssh.close(io);
    var ssh_reader = ssh.reader(io, &in_buffer);
    const identification = try ssh_reader.interface.takeDelimiterInclusive('\n');
    try ctx.result(io, suite, "oc-ssh", std.mem.startsWith(u8, identification, "SSH-2.0-"));

    const stop = Io.Clock.awake.now(io).addDuration(.fromSeconds(15));
    while (true) {
        var attempt: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer attempt.deinit();
        const log = try driver.system.read(
            io,
            attempt.allocator(),
            "/data/svc/opencanary/opencanary.log",
        );
        if (try logged(log, user)) break;
        if (Io.Clock.awake.now(io).compare(.gte, stop)) return error.LoginNotLogged;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    const passwd = try driver.system.read(io, a, "/etc/passwd");
    var lines = std.mem.splitScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        if (std.mem.eql(u8, line[0..colon], user)) return error.BaitAccountCreated;
    }
    try ctx.result(io, suite, "oc-login-logged", true);
}

fn status(line: []const u8, code: *const [3]u8) bool {
    return line.len >= 6 and std.mem.eql(u8, line[0..3], code) and
        line[3] == ' ' and std.mem.endsWith(u8, line, "\r\n");
}
fn logged(log: []const u8, user: []const u8) !bool {
    // Ignore an unfinished final line; a partial write is not an audit record.
    const end = std.mem.findScalarLast(u8, log, '\n') orelse return false;
    var lines = std.mem.splitScalar(u8, log[0..end], '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const parsed = try std.json.parseFromSlice(
            std.json.Value,
            std.heap.page_allocator,
            line,
            .{},
        );
        defer parsed.deinit();
        const record = parsed.value;
        if (record != .object) return error.AuditRecord;
        const kind = record.object.get("logtype") orelse return error.AuditRecord;
        if (kind != .integer or kind.integer != 2000) continue;
        const data = record.object.get("logdata") orelse return error.AuditRecord;
        if (data != .object) return error.AuditRecord;
        const username = data.object.get("USERNAME") orelse return error.AuditRecord;
        const password = data.object.get("PASSWORD") orelse return error.AuditRecord;
        if (username != .string or password != .string) return error.AuditRecord;
        if (std.mem.eql(u8, username.string, user) and
            std.mem.eql(u8, password.string, "wrong-password")) return true;
    }
    return false;
}

test "require an exact FTP status and a completed audit record for this invocation" {
    try std.testing.expect(status("530 denied\r\n", "530"));
    try std.testing.expect(!status("230 logged in\r\n", "530"));
    try std.testing.expect(!status("530-more\r\n", "530"));
    try std.testing.expect(!status("530 denied\n", "530"));
    const record = "{\"logtype\":2000,\"logdata\":{\"USERNAME\":\"fresh\"," ++
        "\"PASSWORD\":\"wrong-password\"}}";
    try std.testing.expect(!try logged(record, "fresh"));
    try std.testing.expect(!try logged(record ++ "\n", "fres"));
    try std.testing.expect(try logged(record ++ "\n", "fresh"));
    try std.testing.expect(!try logged("{\"logtype\":1000,\"message\":\"fresh\"}\n", "fresh"));
    try std.testing.expectError(error.SyntaxError, logged("broken\n", "fresh"));
}
