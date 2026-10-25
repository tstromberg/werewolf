//! Host-local operator actions for an enrolled QEMU machine without guest SSH:
//! one fixed operation over its host-private werewolf.owner serial port
//! (docs/owner-control.md). howl holds the connection itself, so killing howl
//! closes it.
const std = @import("std");
const howl = @import("howl.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const json = std.json;

const Operation = enum { status, pause, @"resume", check, outcome, @"try" };

/// Request is a validated operation: a declaration hash goes only with try.
pub const Request = struct { operation: Operation, hash: ?[]const u8 = null };

/// max_reply bounds a reply line; a previous client's partial frame may precede it.
pub const max_reply = 64 << 10;

/// parse admits one operation, and for try an optional 64-hex-digit
/// declaration hash: nothing a request carries names a path or command.
pub fn parse(actions: []const []const u8) !Request {
    if (actions.len == 0 or actions.len > 2) return error.BadOwnerOperation;
    const operation = std.meta.stringToEnum(Operation, actions[0]) orelse
        return error.BadOwnerOperation;
    if (actions.len == 1) return .{ .operation = operation };
    const hash = actions[1];
    if (operation != .@"try" or hash.len != 64) return error.BadOwnerOperation;
    for (hash) |c| if (!std.ascii.isDigit(c) and (c < 'a' or c > 'f'))
        return error.BadOwnerOperation;
    return .{ .operation = operation, .hash = hash };
}

pub fn command(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    const syntax = "owner [NAME] status|pause|resume|check|outcome|try [DECLARATION-HASH]";
    if (args.len == 0) return why.refuse("{s}", .{syntax});
    const unnamed = std.meta.stringToEnum(Operation, args[0]) != null and
        !(args.len > 1 and std.meta.stringToEnum(Operation, args[1]) != null);
    const name = if (unnamed) "werewolf-run" else args[0];
    if (!howl.isMachineName(name)) return why.refuse("{s}", .{syntax});
    const r = parse(args[@intFromBool(!unnamed)..]) catch return why.refuse("{s}", .{syntax});
    const path = try gpa.print("{s}/owner.sock", .{try howl.machineDir(gpa, name)});
    Io.Dir.cwd().access(io, path, .{}) catch return why.refuse(
        "{s}: no owner channel; start an enrolled QEMU image with current howl",
        .{name},
    );
    const slow = r.operation == .check or r.operation == .@"try";
    const reply = try request(io, gpa, path, r, .fromSeconds(if (slow) 240 else 15), why);
    // The guest wrote the reply: escaped, it carries no control to a terminal.
    const text = try json.Stringify.valueAlloc(gpa, reply, .{ .escape_unicode = true });
    try Io.File.stdout().writeStreamingAll(io, try gpa.print("{s}\n", .{text}));
}

/// request sends r to the owner socket at path and returns the reply that
/// carries its id, if that reply says ok within timeout, connect included.
pub fn request(
    io: Io,
    gpa: Allocator,
    path: []const u8,
    r: Request,
    timeout: Io.Duration,
    why: *howl.Why,
) !json.Value {
    var nonce: [8]u8 = undefined;
    try io.randomSecure(&nonce);
    const id = std.fmt.bytesToHex(nonce, .lower);
    const line = if (r.hash) |hash|
        try gpa.print("{s} {t} {s}\n", .{ &id, r.operation, hash })
    else
        try gpa.print("{s} {t}\n", .{ &id, r.operation });
    const Event = union(enum) {
        reply: anyerror!json.Value,
        late: Io.Cancelable!void,
    };
    var buffer: [2]Event = undefined;
    var events: Io.Select(Event) = .init(io, &buffer);
    defer events.cancelDiscard();
    try events.concurrent(.reply, exchange, .{ io, gpa, path, line, &id });
    try events.concurrent(.late, sleep, .{ io, timeout });
    const reply = switch (try events.await()) {
        .reply => |result| result catch |err| return switch (err) {
            error.EndOfStream => why.refuse("VM owner channel disconnected", .{}),
            error.StreamTooLong => why.refuse("oversized owner response", .{}),
            else => why.refuse("owner channel: {s}", .{@errorName(err)}),
        },
        .late => |status| {
            try status;
            return why.refuse("no owner reply within {f}", .{timeout});
        },
    };
    const ok = reply.object.get("ok") orelse json.Value{ .null = {} };
    if (ok != .bool or !ok.bool) {
        const reason = reply.object.get("error") orelse json.Value{ .null = {} };
        if (reason == .string) return why.refuse("owner operation refused: {s}", .{reason.string});
        return why.refuse("owner operation refused: {f}", .{json.fmt(reason, .{})});
    }
    return reply;
}

fn sleep(io: Io, timeout: Io.Duration) Io.Cancelable!void {
    try io.sleep(timeout, .awake);
}

/// exchange writes line and reads reply lines until one is a JSON object
/// whose id is id, skipping what an earlier client left unread.
fn exchange(
    io: Io,
    gpa: Allocator,
    path: []const u8,
    line: []const u8,
    id: []const u8,
) !json.Value {
    const address = try Io.net.UnixAddress.init(path);
    const stream = try address.connect(io);
    defer stream.close(io);
    var out: [128]u8 = undefined;
    var writer = stream.writer(io, &out);
    try writer.interface.writeAll(line);
    try writer.interface.flush();
    var reader = stream.reader(io, try gpa.alloc(u8, max_reply));
    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();
    while (true) {
        _ = scratch.reset(.retain_capacity);
        const text = reader.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.ReadFailed => return reader.err.?,
            else => |e| return e,
        };
        const reply = json.parseFromSliceLeaky(json.Value, scratch.allocator(), text, .{}) catch
            continue;
        if (reply != .object) continue;
        const got = reply.object.get("id") orelse continue;
        if (got != .string or !std.mem.eql(u8, got.string, id)) continue;
        return json.parseFromSliceLeaky(json.Value, gpa, text, .{ .allocate = .alloc_always });
    }
}

const testing = std.testing;

const Fake = enum { matching, refusing, unbooleaned, oversized, disconnecting, silent };

/// serve answers one connection on server as an owner port would, or would not.
fn serve(io: Io, server: *Io.net.Server, fake: Fake) !void {
    const stream = try server.accept(io);
    defer stream.close(io);
    var in: [256]u8 = undefined;
    var reader = stream.reader(io, &in);
    const line = try reader.interface.takeDelimiterExclusive('\n');
    const space = std.mem.findScalar(u8, line, ' ') orelse return error.BadOwnerRequest;
    var id: [16]u8 = undefined;
    if (space != id.len) return error.BadOwnerRequest;
    @memcpy(&id, line[0..space]);
    const operation = line[space + 1 ..];
    var out: [1024]u8 = undefined;
    var writer = stream.writer(io, &out);
    const w = &writer.interface;
    switch (fake) {
        .matching => {
            if (!std.mem.eql(u8, operation, "status")) return error.WrongOwnerOperation;
            try w.writeAll("partial old frame\n{\"id\":\"0000000000000000\",\"ok\":true}\n");
            const status = "\"ok\":true,\"format\":\"werewolf-owner-status/1\"";
            try w.print("{{\"id\":\"{s}\",{s}}}\n", .{ &id, status });
        },
        .refusing, .unbooleaned => {
            if (!std.mem.eql(u8, operation, "try")) return error.WrongOwnerOperation;
            try w.print("{{\"id\":\"{s}\",\"ok\":{s},\"error\":\"ImageRolledBack\"}}\n", .{
                &id, if (fake == .refusing) "false" else "1",
            });
        },
        // howl closes once the line overflows, so the rest may not be written.
        .oversized => {
            w.splatByteAll('x', max_reply + 1) catch {};
            w.flush() catch {};
            return;
        },
        .disconnecting => return,
        .silent => {
            // Hold the connection until the client gives up and closes it.
            _ = reader.interface.discardRemaining() catch {};
            return;
        },
    }
    try w.flush();
}

/// owned runs one request against a fake owner and returns its reply.
fn owned(gpa: Allocator, fake: Fake, r: Request, timeout: Io.Duration, why: *howl.Why) !json.Value {
    const io = testing.io;
    var nonce: [6]u8 = undefined;
    io.random(&nonce);
    // macOS limits a socket's path to 104 bytes, too few for a test directory.
    const path = try gpa.print("/tmp/ww-owner-{x}.sock", .{&nonce});
    const address = try Io.net.UnixAddress.init(path);
    var server = try address.listen(io, .{});
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    defer server.deinit(io);
    var served = try io.concurrent(serve, .{ io, &server, fake });
    const reply = request(io, gpa, path, r, timeout, why);
    try served.await(io);
    return reply;
}

test "only the matching response can complete an operation" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var why: howl.Why = .{};
    const reply = try owned(
        arena.allocator(),
        .matching,
        .{ .operation = .status },
        .fromSeconds(5),
        &why,
    );
    try testing.expectEqualStrings("werewolf-owner-status/1", reply.object.get("format").?.string);
}

test "refusal and non-boolean success are errors" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    for ([_]Fake{ .refusing, .unbooleaned }) |fake| {
        var why: howl.Why = .{};
        try testing.expectError(
            error.Refused,
            owned(arena.allocator(), fake, .{ .operation = .@"try" }, .fromSeconds(5), &why),
        );
        try testing.expectEqualStrings("owner operation refused: ImageRolledBack", why.text);
    }
}

test "commands cannot select paths or shell commands" {
    const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try testing.expectEqual(Operation.status, (try parse(&.{"status"})).operation);
    try testing.expectEqualStrings(hash, (try parse(&.{ "try", hash })).hash.?);
    for ([_][]const []const u8{
        &.{},
        &.{"sh"},
        &.{ "try", "/data/file" },
        &.{ "status", "extra" },
        &.{"check\ntry"},
        &.{"try " ++ hash},
        &.{ "check", hash },
        &.{ "try", &@as([64]u8, @splat('g')) },
        &.{ "try", &@as([64]u8, @splat('A')) },
        &.{ "try", &@as([65]u8, @splat('a')) },
        &.{ "try", hash, "extra" },
    }) |actions| try testing.expectError(error.BadOwnerOperation, parse(actions));
}

test "response limit, disconnect and silence fail closed" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    for ([_]struct { Fake, []const u8 }{
        .{ .oversized, "oversized owner response" },
        .{ .disconnecting, "VM owner channel disconnected" },
        .{ .silent, "no owner reply within 200ms" },
    }) |case| {
        var why: howl.Why = .{};
        try testing.expectError(
            error.Refused,
            owned(
                arena.allocator(),
                case[0],
                .{ .operation = .status },
                .fromMilliseconds(200),
                &why,
            ),
        );
        try testing.expectEqualStrings(case[1], why.text);
    }
}
