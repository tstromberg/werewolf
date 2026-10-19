//! Submit through Mox's public API and inspect that exact queue entry with its CLI.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const record_dir = "/data/test-mox-submitted";
const record = record_dir ++ "/submission.json";
const Stored = struct { run: []const u8, id: i64, subject: []const u8 };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "submitted")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    var env: std.process.Environ.Map = .init(a);
    defer env.deinit();
    try env.put("MOX_CTL", "/run/svc/mox/ctl");
    try env.put("LC_ALL", "C");
    var stored: Stored = undefined;
    if (std.mem.eql(u8, ctx.phase, "seed")) {
        _ = try command(
            io,
            a,
            &env,
            &.{ "setaccountpassword", "postmaster" },
            "werewolf-check-pass-1\n",
        );
        var random: [8]u8 = undefined;
        io.random(&random);
        const subject = try a.print("werewolf-submitted-{s}-{x}", .{ ctx.run, &random });
        const body = try std.json.Stringify.valueAlloc(a, .{
            .To = [_]struct { Address: []const u8 }{.{ .Address = "someone@example.net" }},
            .Subject = subject,
            .Text = "hello",
        }, .{});
        var req = driver.system.object(a);
        try req.object.put(a, "url", driver.system.text("https://mail.example.com/webapi/v0/Send"));
        try req.object.put(a, "method", driver.system.text("POST"));
        try req.object.put(a, "ca", driver.system.text("/run/svc/mox/tls-cert"));
        var resolve: std.json.Array = .init(a);
        try resolve.append(driver.system.text("mail.example.com:443:127.0.0.1"));
        try req.object.put(a, "resolve", .{ .array = resolve });
        const credentials = "postmaster@example.com:werewolf-check-pass-1";
        const encoder = std.base64.standard.Encoder;
        const encoded = try a.alloc(u8, encoder.calcSize(credentials.len));
        _ = encoder.encode(encoded, credentials);
        var auth = driver.system.object(a);
        try auth.object.put(a, "scheme", driver.system.text("Basic"));
        try auth.object.put(
            a,
            "credentials",
            driver.system.text(encoded),
        );
        try req.object.put(a, "authorization", auth);
        var form = driver.system.object(a);
        try form.object.put(a, "request", driver.system.text(body));
        try req.object.put(a, "form", form);
        var client = try driver.fetch.Client.init(a);
        defer client.deinit();
        const response = try client.request(req, 30000, a);
        const status = response.object.get("status").?.integer;
        if (status != 200) {
            try Io.File.stderr().writeStreamingAll(io, try a.print(
                "mox-test: submission HTTP {d} (expected 200)\n",
                .{status},
            ));
            return error.SubmissionStatus;
        }
        const Reply = struct { Submissions: []const struct {
            Address: []const u8,
            QueueMsgID: i64,
        } };
        const result = try std.json.parseFromSliceLeaky(Reply, a, response.object.get(
            "body",
        ).?.string, .{
            .ignore_unknown_fields = true,
        });
        if (result.Submissions.len != 1 or result.Submissions[0].QueueMsgID <= 0 or
            !std.mem.eql(
                u8,
                result.Submissions[0].Address,
                "someone@example.net",
            )) return error.SubmissionIdentity;
        stored = .{ .run = ctx.run, .id = result.Submissions[0].QueueMsgID, .subject = subject };
        const bytes = try std.json.Stringify.valueAlloc(a, stored, .{});
        try Io.Dir.cwd().createDirPath(io, record_dir);
        const file = try Io.Dir.cwd().createFile(io, record, .{ .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        try file.sync(io);
    } else {
        stored = try std.json.parseFromSliceLeaky(
            Stored,
            a,
            try driver.system.read(io, a, record),
            .{},
        );
        if (!std.mem.eql(u8, stored.run, ctx.run) or stored.id <= 0 or stored.subject.len == 0)
            return error.StaleSubmission;
    }
    const raw = try command(
        io,
        a,
        &env,
        &.{ "queue", "dump", try a.print("{d}", .{stored.id}) },
        "",
    );
    if (!signed(raw.stdout, stored.subject)) return error.UnsignedSubmission;
    try ctx.result(io, args[1], "mox-submitted", true);
}

fn command(
    io: Io,
    a: Allocator,
    env: *const std.process.Environ.Map,
    tail: []const []const u8,
    input: []const u8,
) !std.process.RunResult {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, &.{ "/usr/bin/mox", "-config", "/data/svc/mox/config/mox.conf" });
    try argv.appendSlice(a, tail);
    const result = try driver.exec.run(a, io, argv.items, env, input, 30000);
    if (result.term != .exited or result.term.exited != 0) {
        try Io.File.stderr().writeStreamingAll(io, result.stderr);
        return error.MoxCommand;
    }
    return result;
}

fn signed(raw: []const u8, subject: []const u8) bool {
    var signature = false;
    var identity = false;
    var lines = std.mem.splitSequence(u8, raw, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) break;
        signature = signature or std.mem.startsWith(u8, line, "DKIM-Signature: ");
        if (std.mem.startsWith(u8, line, "Subject: "))
            identity = std.mem.eql(u8, line["Subject: ".len..], subject);
    }
    return signature and identity;
}

test "a queued signature and exact subject must be in the headers" {
    try std.testing.expect(signed(
        "Subject: this-run\r\nDKIM-Signature: signed\r\n\r\nhello",
        "this-run",
    ));
    try std.testing.expect(!signed(
        "Subject: old-run\r\nDKIM-Signature: signed\r\n\r\nhello",
        "this-run",
    ));
    try std.testing.expect(!signed("Subject: this-run\r\n\r\nDKIM-Signature: body", "this-run"));
    try std.testing.expect(!signed("Subject: this-run\r\n\r\nhello", "this-run"));
}
