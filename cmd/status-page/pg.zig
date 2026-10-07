//! status-page's PostgreSQL client: the wire protocol over the server's
//! UNIX socket, every value a parameter, never part of the SQL.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const main = @import("status-page.zig");
const pg_socket = main.pg_socket;

const pg_max_message = 16 << 20;

/// PostgreSQL's own words for the last refusal: its ErrorResponse's
/// message (M), each control character as ?, at most 200 bytes.
var refusal_buf: [200]u8 = undefined;

var refusal: []const u8 = "";

fn keepRefusal(body: []const u8) void {
    refusal = "";
    var fields = std.mem.splitScalar(u8, body, 0);
    while (fields.next()) |f| {
        if (f.len < 2 or f[0] != 'M') continue;
        const text = f[1..@min(f.len, refusal_buf.len + 1)];
        for (text, refusal_buf[0..text.len]) |c, *o| o.* = if (c < 0x20 or c == 0x7f) '?' else c;
        refusal = refusal_buf[0..text.len];
        return;
    }
}

/// Why the database could not be used: the error, and PostgreSQL's words
/// where it refused.
pub fn dbWhy(err: anyerror) []const u8 {
    return if (err == error.Refused and refusal.len > 0) refusal else @errorName(err);
}

/// One connection to the server, as one role, to the postgres database.
pub const Pg = struct {
    fd: i32,

    pub fn connect(gpa: Allocator, as: []const u8) !Pg {
        const linux = std.os.linux;
        const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.NoSocket;
        var p: Pg = .{ .fd = @intCast(rc) };
        errdefer _ = linux.close(p.fd);
        // A server that stops answering costs the page half its minute,
        // not the page; one that is merely slow, on a loaded machine, is
        // waited for.
        const tv: linux.timeval = .{ .sec = 30, .usec = 0 };
        for ([_]u32{
            linux.SO.RCVTIMEO,
            linux.SO.SNDTIMEO,
        }) |opt| _ = linux.setsockopt(
            p.fd,
            linux.SOL.SOCKET,
            opt,
            std.mem.asBytes(&tv),
            @sizeOf(linux.timeval),
        );
        var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
        @memcpy(addr.path[0..pg_socket.len], pg_socket);
        if (linux.errno(linux.connect(
            p.fd,
            @ptrCast(&addr),
            @sizeOf(linux.sockaddr.un),
        )) != .SUCCESS) return error.NoServer;

        var m: std.ArrayList(u8) = .empty;
        try m.appendNTimes(gpa, 0, 4);
        try m.appendSlice(gpa, &.{ 0, 3, 0, 0 }); // protocol 3.0
        for ([_][]const u8{
            "user",
            as,
            "database",
            "postgres",
            "application_name",
            "werewolf-status",
        }) |field| {
            if (std.mem.findScalar(u8, field, 0) != null) return error.BadValue;
            try m.appendSlice(gpa, field);
            try m.append(gpa, 0);
        }
        try m.append(gpa, 0);
        std.mem.writeInt(u32, m.items[0..4], @intCast(m.items.len), .big);
        try p.send(m.items);
        while (true) {
            const msg = try p.receive(gpa);
            switch (msg.kind) {
                'R' => if (msg.body.len < 4 or
                    std.mem.readInt(
                        u32,
                        msg.body[0..4],
                        .big,
                    ) != 0) return error.AuthenticationRefused,
                'E' => {
                    keepRefusal(msg.body);
                    return error.Refused;
                },
                'Z' => return p,
                else => {},
            }
        }
    }

    /// One statement, its parameters as text; its rows, each column text,
    /// or null for NULL.
    pub fn query(
        p: *Pg,
        gpa: Allocator,
        sql: []const u8,
        params: []const []const u8,
    ) ![]const []const ?[]const u8 {
        if (std.mem.findScalar(u8, sql, 0) != null) return error.BadValue;
        var m: std.ArrayList(u8) = .empty;
        // Parse: the unnamed statement, its parameters' types inferred.
        var start = try messageStart(gpa, &m, 'P');
        try m.appendSlice(gpa, "\x00");
        try m.appendSlice(gpa, sql);
        try m.appendSlice(gpa, &.{ 0, 0, 0 });
        messageEnd(&m, start);
        // Bind: the unnamed portal, every value as text.
        start = try messageStart(gpa, &m, 'B');
        try m.appendSlice(gpa, &.{ 0, 0, 0, 0 });
        try appendInt(gpa, &m, u16, @intCast(params.len));
        for (params) |v| {
            try appendInt(gpa, &m, u32, @intCast(v.len));
            try m.appendSlice(gpa, v);
        }
        try m.appendSlice(gpa, &.{ 0, 0 });
        messageEnd(&m, start);
        start = try messageStart(gpa, &m, 'E'); // Execute, every row
        try m.appendSlice(gpa, &.{ 0, 0, 0, 0, 0 });
        messageEnd(&m, start);
        start = try messageStart(gpa, &m, 'S'); // Sync
        messageEnd(&m, start);
        try p.send(m.items);

        var rows: std.ArrayList([]const ?[]const u8) = .empty;
        var failed = false;
        while (true) {
            const msg = try p.receive(gpa);
            switch (msg.kind) {
                'D' => try rows.append(gpa, try dataRow(gpa, msg.body)),
                'E' => {
                    keepRefusal(msg.body);
                    failed = true;
                },
                'Z' => return if (failed) error.Refused else rows.items,
                else => {}, // completions, notices, parameter changes
            }
        }
    }

    pub fn close(p: *Pg) void {
        _ = std.os.linux.write(p.fd, "X\x00\x00\x00\x04", 5);
        _ = std.os.linux.close(p.fd);
    }

    fn send(p: *Pg, bytes: []const u8) !void {
        var off: usize = 0;
        while (off < bytes.len) {
            const n = std.os.linux.write(p.fd, bytes[off..].ptr, bytes.len - off);
            try ioError(n);
            off += n;
        }
    }

    const Message = struct { kind: u8, body: []const u8 };

    fn receive(p: *Pg, gpa: Allocator) !Message {
        var head: [5]u8 = undefined;
        try p.fill(&head);
        const len = std.mem.readInt(u32, head[1..5], .big);
        if (len < 4 or len > pg_max_message) return error.Lost;
        const body = try gpa.alloc(u8, len - 4);
        try p.fill(body);
        return .{ .kind = head[0], .body = body };
    }

    fn fill(p: *Pg, buf: []u8) !void {
        var off: usize = 0;
        while (off < buf.len) {
            const n = std.os.linux.read(p.fd, buf[off..].ptr, buf.len - off);
            try ioError(n);
            off += n;
        }
    }

    /// What a read or write on the socket that moved nothing means: the
    /// timeout passing, or the server gone.
    fn ioError(n: usize) !void {
        switch (std.os.linux.errno(n)) {
            .SUCCESS => if (n == 0) return error.Lost,
            .AGAIN => return error.Timeout,
            else => return error.Lost,
        }
    }
};

fn messageStart(gpa: Allocator, m: *std.ArrayList(u8), kind: u8) !usize {
    try m.append(gpa, kind);
    const at = m.items.len;
    try m.appendNTimes(gpa, 0, 4);
    return at;
}

/// The length of the message whose length field is at start: itself and
/// what follows.
fn messageEnd(m: *std.ArrayList(u8), start: usize) void {
    std.mem.writeInt(u32, m.items[start..][0..4], @intCast(m.items.len - start), .big);
}

fn appendInt(gpa: Allocator, m: *std.ArrayList(u8), comptime T: type, v: T) !void {
    var b: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &b, v, .big);
    try m.appendSlice(gpa, &b);
}

/// A DataRow's columns: a count, then each a length (-1 for NULL) and
/// its bytes.
fn dataRow(gpa: Allocator, body: []const u8) ![]const ?[]const u8 {
    if (body.len < 2) return error.Lost;
    const n = std.mem.readInt(u16, body[0..2], .big);
    const cols = try gpa.alloc(?[]const u8, n);
    var at: usize = 2;
    for (cols) |*c| {
        if (at + 4 > body.len) return error.Lost;
        const len = std.mem.readInt(i32, body[at..][0..4], .big);
        at += 4;
        if (len < 0) {
            c.* = null;
            continue;
        }
        if (at + @as(usize, @intCast(len)) > body.len) return error.Lost;
        c.* = body[at .. at + @as(usize, @intCast(len))];
        at += @intCast(len);
    }
    return cols;
}

test dataRow {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const cols = try dataRow(
        arena.allocator(),
        &.{ 0, 3, 0, 0, 0, 2, 'h', 'i', 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 },
    );
    try testing.expectEqual(3, cols.len);
    try testing.expectEqualStrings("hi", cols[0].?);
    try testing.expectEqual(null, cols[1]);
    try testing.expectEqualStrings("", cols[2].?);
    try testing.expectError(error.Lost, dataRow(arena.allocator(), &.{ 0, 1, 0, 0, 0, 9, 'x' }));
    try testing.expectError(error.Lost, dataRow(arena.allocator(), &.{0}));
}

test keepRefusal {
    keepRefusal("SERROR\x00C42P01\x00Mrelation \"status.scans\" does not exist\x1b[31m\x00\x00");
    try testing.expectEqualStrings("relation \"status.scans\" does not exist?[31m", refusal);
    try testing.expectEqualStrings(refusal, dbWhy(error.Refused));
    try testing.expectEqualStrings("Lost", dbWhy(error.Lost));
    keepRefusal("SFATAL\x00C28000\x00\x00");
    try testing.expectEqualStrings("", refusal);
}
