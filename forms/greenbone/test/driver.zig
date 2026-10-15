//! Local GMP checks. No shell, feed download, scan, or production policy change.
//! Protocol: https://docs.greenbone.net/API/GMP/gmp-22.7.html
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const manager = "/run/svc/gvmd/run/gvmd.sock";
const bridge = "/run/svc/gsad/run/manager.sock";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len != 4) return error.Usage;
    const suite = args[1];
    const ctx = try driver.Run.load(io, gpa, args[3]);
    if (std.mem.eql(u8, args[2], "denied")) {
        const rc = connectSocket(manager);
        if (rc) |fd| {
            _ = linux.close(fd);
            try ctx.result(io, suite, "socket-refused", false);
        } else |err| try ctx.result(io, suite, "socket-refused", err == error.AccessDenied);
        return;
    }
    const via_bridge = std.mem.eql(u8, args[2], "bridge");
    if (!via_bridge and !std.mem.eql(u8, args[2], "manager")) return error.Usage;
    const path = if (via_bridge) bridge else manager;
    const secret = try gpa.print("/run/svc/{s}/password", .{suite});
    const password = try Io.Dir.cwd().readFileAlloc(io, secret, gpa, .limited(256));
    const escaped = try escape(gpa, std.mem.trimEnd(u8, password, "\r\n"));
    var client = Client{ .fd = try connectSocket(path), .gpa = gpa };
    defer client.close();
    const auth = try gpa.print(
        "<authenticate><credentials><username>admin</username><password>{s}</password></credenti" ++
            "als></authenticate>",
        .{escaped},
    );
    const authenticated = try client.command(auth, "authenticate_response");
    try ctx.result(
        io,
        suite,
        "configured-login",
        try status(authenticated, "authenticate_response") == 200,
    );
    const name = try gpa.print("native-{s}", .{ctx.run});
    if (!via_bridge and std.mem.eql(u8, ctx.phase, "seed")) {
        const create = try gpa.print(
            "<create_target><name>{s}</name><hosts>192.0.2.1</hosts><port_range>T:80</port_range" ++
                "></create_target>",
            .{name},
        );
        const created = try client.command(create, "create_target_response");
        try ctx.result(
            io,
            suite,
            "create-target",
            try status(created, "create_target_response") == 201,
        );
    }
    // The verify boot reads before any setup write. The bridge also reads the
    // manager driver's row, proving the gsad-to-gvmd socket relay carries GMP.
    const query = try gpa.print("<get_targets filter=\"name={s} rows=-1\"/>", .{name});
    const found = try client.command(query, "get_targets_response");
    try ctx.result(io, suite, "persisted-target", try status(
        found,
        "get_targets_response",
    ) == 200 and
        std.mem.count(u8, found, "<target id=") == 1 and
        std.mem.indexOf(u8, found, try gpa.print("<name>{s}</name>", .{name})) != null and
        std.mem.indexOf(u8, found, "<hosts>192.0.2.1</hosts>") != null);
    for ([_][]const u8{ "admin", "werewolf-incorrect-password" }, 0..) |wrong, i| {
        var denied = Client{ .fd = try connectSocket(path), .gpa = gpa };
        defer denied.close();
        const command = try gpa.print(
            "<authenticate><credentials><username>admin</username><password>{s}</password></cred" ++
                "entials></authenticate>",
            .{wrong},
        );
        const response = try denied.command(command, "authenticate_response");
        // GMP uses 400 for authentication failure. A transport error, timeout,
        // unsupported command or a successful login cannot satisfy this case.
        try ctx.result(io, suite, if (i == 0)
            "default-password-refused"
        else
            "wrong-password-refused", try status(response, "authenticate_response") == 400);
    }
    if (!via_bridge) {
        for ([_]u16{ 5432, 6379, 9391, 9392 }) |port| {
            try ctx.result(
                io,
                suite,
                try gpa.print("private-port-{d}", .{port}),
                try driver.tcpPrivate(io, gpa, port, true),
            );
        }
    }
}

const Client = struct {
    fd: i32,
    gpa: Allocator,

    fn close(c: Client) void {
        _ = linux.close(c.fd);
    }

    fn command(c: Client, request: []const u8, tag: []const u8) ![]const u8 {
        var offset: usize = 0;
        while (offset < request.len) {
            const n = linux.write(c.fd, request[offset..].ptr, request.len - offset);
            if (linux.errno(n) == .INTR) continue;
            if (linux.errno(n) != .SUCCESS or n == 0) return error.Write;
            offset += n;
        }
        const buffer = try c.gpa.alloc(u8, 256 << 10);
        var used: usize = 0;
        while (used < buffer.len) {
            var poll = [_]linux.pollfd{.{ .fd = c.fd, .events = linux.POLL.IN, .revents = 0 }};
            const polled = linux.poll(&poll, 1, 15000);
            if (linux.errno(polled) == .INTR) continue;
            if (linux.errno(polled) != .SUCCESS or polled == 0) return error.ResponseTimeout;
            const n = linux.read(c.fd, buffer[used..].ptr, buffer.len - used);
            if (linux.errno(n) == .INTR) continue;
            if (linux.errno(n) != .SUCCESS or n == 0) return error.Read;
            used += n;
            if (try complete(buffer[0..used], tag)) return buffer[0..used];
        }
        return error.ResponseTooLarge;
    }
};

fn connectSocket(path: []const u8) !i32 {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);
    const Address = extern struct { family: u16, path: [108]u8 };
    var address: Address = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    if (path.len >= address.path.len) return error.PathTooLong;
    @memcpy(address.path[0..path.len], path);
    switch (linux.errno(linux.connect(fd, @ptrCast(&address), @intCast(2 + path.len + 1)))) {
        .SUCCESS => return fd,
        .ACCES, .PERM => return error.AccessDenied,
        else => return error.Connect,
    }
}

// A bounded, deliberately narrow GMP response envelope. Reject foreign roots,
// duplicate attributes and trailing records; never search arbitrary XML text
// for a status that might belong to an inner element.
fn header(raw: []const u8, tag: []const u8) !?[]const u8 {
    const text = std.mem.trim(u8, raw, " \r\n\t");
    if (text.len < tag.len + 2) return null;
    if (text[0] != '<' or !std.mem.eql(u8, text[1 .. tag.len + 1], tag) or
        text[tag.len + 1] != ' ') return error.ResponseRoot;
    const end = std.mem.findScalar(u8, text, '>') orelse return null;
    return text[tag.len + 1 .. end];
}

fn complete(raw: []const u8, tag: []const u8) !bool {
    const attrs = (try header(raw, tag)) orelse return false;
    const text = std.mem.trim(u8, raw, " \r\n\t");
    const end = std.mem.findScalar(u8, text, '>').?;
    if (std.mem.endsWith(u8, attrs, "/")) {
        if (end + 1 != text.len) return error.TrailingResponse;
        return true;
    }
    var buf: [128]u8 = undefined;
    const closing = try std.mem.print(&buf, "</{s}>", .{tag});
    const at = std.mem.indexOf(u8, text, closing) orelse return false;
    if (at + closing.len != text.len) return error.TrailingResponse;
    return true;
}

fn status(raw: []const u8, tag: []const u8) !u16 {
    var attrs = (try header(raw, tag)) orelse return error.IncompleteResponse;
    var result: ?u16 = null;
    while (true) {
        attrs = std.mem.trimStart(u8, attrs, " \t\r\n");
        if (attrs.len == 0 or std.mem.eql(u8, attrs, "/")) break;
        const eq = std.mem.findScalar(u8, attrs, '=') orelse return error.Attribute;
        const name = std.mem.trimEnd(u8, attrs[0..eq], " \t\r\n");
        attrs = std.mem.trimStart(u8, attrs[eq + 1 ..], " \t\r\n");
        if (attrs.len == 0 or (attrs[0] != '"' and attrs[0] != '\'')) return error.Attribute;
        const end = std.mem.findScalarPos(u8, attrs, 1, attrs[0]) orelse return error.Attribute;
        if (std.mem.eql(u8, name, "status")) {
            if (result != null) return error.DuplicateStatus;
            result = try std.fmt.parseInt(u16, attrs[1..end], 10);
        }
        attrs = attrs[end + 1 ..];
    }
    return result orelse error.MissingStatus;
}

fn escape(gpa: Allocator, text: []const u8) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    for (text) |ch| try out.writer.writeAll(switch (ch) {
        '&' => "&amp;",
        '<' => "&lt;",
        '>' => "&gt;",
        '"' => "&quot;",
        '\'' => "&apos;",
        else => &.{ch},
    });
    return out.toOwnedSlice();
}

test "password XML escapes syntax without changing the credential" {
    const value = try escape(std.testing.allocator, "a&b<c>\"d'");
    defer std.testing.allocator.free(value);
    try std.testing.expectEqualStrings("a&amp;b&lt;c&gt;&quot;d&apos;", value);
}

test "GMP envelope refuses partial, foreign, duplicate and trailing responses" {
    const tag = "authenticate_response";
    try std.testing.expect(!try complete("<authenticate_response status=\"200\"", tag));
    try std.testing.expect(try complete(
        "<authenticate_response status=\"200\"><role>Admin</role></authenticate_response>",
        tag,
    ));
    try std.testing.expectEqual(
        @as(u16, 400),
        try status(
            "<authenticate_response status_text=\"Authentication failed\" status='400'/>",
            tag,
        ),
    );
    try std.testing.expectError(
        error.ResponseRoot,
        complete("<get_version_response status=\"200\"/>", tag),
    );
    try std.testing.expectError(
        error.TrailingResponse,
        complete("<authenticate_response status=\"200\"/><x/>", tag),
    );
    try std.testing.expectError(
        error.DuplicateStatus,
        status("<authenticate_response status=\"400\" status=\"200\"/>", tag),
    );
    try std.testing.expectError(
        error.MissingStatus,
        status("<authenticate_response status_text=\"200\"/>", tag),
    );
}
