//! Speak SMTP to the real server and find this run's delivered message.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const Event = union(enum) { checked: anyerror!void, timeout: Io.Cancelable!void };
    var buffer: [2]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.checked, check, .{ io, a, ctx, args[1], args[2] });
    try events.concurrent(.timeout, timeout, .{io});
    switch (try events.await()) {
        .checked => |result| try result,
        .timeout => |result| {
            try result;
            return error.SmtpTimeout;
        },
    }
}

fn timeout(io: Io) Io.Cancelable!void {
    try io.sleep(.fromSeconds(120), .awake);
}

fn check(io: Io, a: Allocator, ctx: driver.Run, suite: []const u8, mode: []const u8) !void {
    const ready = std.mem.eql(u8, mode, "ready");
    const mail = std.mem.eql(u8, mode, "mail");
    if (!ready and !mail and !std.mem.eql(u8, mode, "relay")) return error.Usage;
    if (mail and std.mem.eql(u8, ctx.phase, "verify")) {
        try delivered(io, a, ctx.run);
        return ctx.result(io, suite, "mox-inbound", true);
    }
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(25) };
    const stream = while (true) {
        break address.connect(io, .{ .mode = .stream }) catch |err| {
            if (!ready or err != error.ConnectionRefused) return err;
            try io.sleep(.fromMilliseconds(100), .awake);
            continue;
        };
    };
    defer stream.close(io);
    var in_buffer: [4096]u8 = undefined;
    var out_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &in_buffer);
    var writer = stream.writer(io, &out_buffer);
    const greeting = try reply(&reader.interface, "220");
    if (!std.mem.startsWith(u8, greeting, "220 mail.example.com ESMTP")) return error.SmtpHostname;
    if (!ready) {
        try send(&writer.interface, "EHLO check.example.org\r\n");
        _ = try reply(&reader.interface, "250");
        try send(&writer.interface, "MAIL FROM:<>\r\n");
        _ = try reply(&reader.interface, "250");
        try send(&writer.interface, if (mail)
            "RCPT TO:<postmaster@example.com>\r\n"
        else
            "RCPT TO:<someone@example.net>\r\n");
        _ = try reply(&reader.interface, if (mail) "250" else "550");
        if (mail) {
            try send(&writer.interface, "DATA\r\n");
            _ = try reply(&reader.interface, "354");
            try send(&writer.interface, try a.print(
                "From: mailer-daemon@check.invalid\r\nTo: postmaster@example.com\r\n" ++
                    "Subject: werewolf-inbound-{s}\r\n\r\nhello {s}\r\n.\r\n",
                .{ ctx.run, ctx.run },
            ));
            const accepted = try reply(&reader.interface, "250");
            if (!std.mem.startsWith(u8, accepted, "250 2.2.0")) return error.MailNotAccepted;
        }
    }
    try send(&writer.interface, "QUIT\r\n");
    _ = try reply(&reader.interface, "221");
    if (mail) try delivered(io, a, ctx.run);
    try ctx.result(
        io,
        suite,
        if (ready) "mox-smtp" else if (mail) "mox-inbound" else "mox-no-relay",
        true,
    );
}

fn send(writer: *Io.Writer, command: []const u8) !void {
    try writer.writeAll(command);
    try writer.flush();
}

fn reply(reader: *Io.Reader, code: *const [3]u8) ![]const u8 {
    for (0..64) |_| {
        const line = try reader.takeDelimiterInclusive('\n');
        if (!valid(line, code)) return error.SmtpReply;
        if (line[3] == ' ') return line;
    }
    return error.TooManyReplyLines;
}

fn valid(line: []const u8, code: *const [3]u8) bool {
    return line.len >= 6 and line.len <= 512 and std.mem.eql(u8, line[0..3], code) and
        (line[3] == '-' or line[3] == ' ') and std.mem.endsWith(u8, line, "\r\n");
}

fn delivered(io: Io, a: Allocator, run: []const u8) !void {
    const subject = try a.print("Subject: werewolf-inbound-{s}\r\n", .{run});
    const body = try a.print("hello {s}\r\n", .{run});
    var directory = try Io.Dir.cwd().openDir(
        io,
        "/data/svc/mox/data/accounts/postmaster/msg",
        .{ .iterate = true },
    );
    defer directory.close(io);
    var walk = try directory.walk(a);
    defer walk.deinit();
    const uid = try driver.system.account(io, a, "mox");
    var count: usize = 0;
    while (try walk.next(io)) |entry| {
        count += 1;
        if (count > 10000) return error.TooManyMessageFiles;
        if (entry.kind != .file) continue;
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        const scratch = arena.allocator();
        const message = try directory.readFileAlloc(io, entry.path, scratch, .limited(1 << 20));
        if (std.mem.find(u8, message, subject) != null and
            std.mem.find(u8, message, body) != null)
        {
            const path = try a.print(
                "/data/svc/mox/data/accounts/postmaster/msg/{s}",
                .{entry.path},
            );
            const metadata = try driver.system.file(
                io,
                scratch,
                path,
                driver.system.object(scratch),
            );
            if (metadata.object.get("uid").?.integer != uid)
                return error.MessageOwner;
            return;
        }
    }
    return error.MessageNotStored;
}

test "SMTP replies require a complete bounded line and the expected status" {
    try std.testing.expect(valid("250-first capability\r\n", "250"));
    try std.testing.expect(valid("250 ready\r\n", "250"));
    for ([_][]const u8{ "250 ready\n", "250 ready", "250Xready\r\n", "550 refused\r\n" }) |line|
        try std.testing.expect(!valid(line, "250"));
    var long: [513]u8 = @splat('x');
    @memcpy(long[0..4], "250 ");
    @memcpy(long[511..], "\r\n");
    try std.testing.expect(!valid(&long, "250"));
}

test "multiline SMTP replies must end with the same status" {
    var good: Io.Reader = .fixed("250-first\r\n250 done\r\n");
    try std.testing.expectEqualStrings("250 done\r\n", try reply(&good, "250"));
    var wrong: Io.Reader = .fixed("250-first\r\n550 wrong\r\n");
    try std.testing.expectError(error.SmtpReply, reply(&wrong, "250"));
    var incomplete: Io.Reader = .fixed("250-first\r\n");
    try std.testing.expectError(error.EndOfStream, reply(&incomplete, "250"));
}
