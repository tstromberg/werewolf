//! http serves HTTP/1.1 to host-side tests, over TLS when given an identity:
//! a test's own handler, or Files, a directory and the paths asked of it.
//! Connections persist until the client or the handler closes them. See
//! test/host/README.md.

const std = @import("std");
const tls = @import("tls.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;

pub const Header = struct { name: []const u8, value: []const u8 };

pub const Request = struct {
    method: []const u8,
    /// target is the request target as sent, query and all.
    target: []const u8,
    headers: []const Header,
    body: []const u8,

    /// header is name's first value, ignoring case.
    pub fn header(r: *const Request, name: []const u8) ?[]const u8 {
        for (r.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }

    /// path is the target without its query.
    pub fn path(r: *const Request) []const u8 {
        return r.target[0 .. mem.findScalar(u8, r.target, '?') orelse r.target.len];
    }
};

pub const Response = struct {
    out: *Io.Writer,
    head: bool,
    /// close ends the connection after this response.
    close: bool = false,
    sent: bool = false,

    /// send writes a whole response, adding Content-Length unless headers
    /// name one: a test may promise more than it sends, then close.
    pub fn send(r: *Response, status: u16, headers: []const Header, body: []const u8) !void {
        try r.start(status, headers, body.len);
        if (!r.head) try r.out.writeAll(body);
    }

    /// start writes the status line and headers of a length-byte body the
    /// caller writes to out.
    pub fn start(r: *Response, status: u16, headers: []const Header, length: u64) !void {
        if (r.sent) return error.AlreadySent;
        r.sent = true;
        try r.out.print("HTTP/1.1 {d} {s}\r\n", .{ status, reason(status) });
        var counted = false;
        for (headers) |h| {
            counted = counted or std.ascii.eqlIgnoreCase(h.name, "content-length");
            try r.out.print("{s}: {s}\r\n", .{ h.name, h.value });
        }
        if (!counted) try r.out.print("Content-Length: {d}\r\n", .{length});
        if (r.close) try r.out.writeAll("Connection: close\r\n");
        try r.out.writeAll("\r\n");
    }
};

fn reason(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        else => "Status",
    };
}

/// Handler answers one request. gpa is the request's own arena.
pub const Handler = struct {
    context: *anyopaque,
    serve: *const fn (
        context: *anyopaque,
        gpa: Allocator,
        request: *const Request,
        response: *Response,
    ) anyerror!void,
};

pub const max_head = 64 << 10;
pub const max_body = 64 << 20;

pub const Server = struct {
    io: Io,
    gpa: Allocator,
    listener: Io.net.Server,
    identity: ?*const tls.Identity,
    handler: Handler,
    accepting: Io.Future(void),
    connections: Io.Group = .init,

    pub const Options = struct {
        address: Io.net.IpAddress = .{ .ip4 = .loopback(0) },
        /// identity serves TLS; null serves plain HTTP.
        identity: ?*const tls.Identity = null,
        handler: Handler,
    };

    /// start listens and serves until stop. s must not move until then, and
    /// gpa must be safe to use from several threads.
    pub fn start(s: *Server, io: Io, gpa: Allocator, options: Options) !void {
        s.* = .{
            .io = io,
            .gpa = gpa,
            .listener = try options.address.listen(io, .{ .reuse_address = true }),
            .identity = options.identity,
            .handler = options.handler,
            .accepting = undefined,
        };
        errdefer s.listener.deinit(io);
        s.accepting = try io.concurrent(accept, .{s});
    }

    pub fn port(s: *const Server) u16 {
        return s.listener.socket.address.getPort();
    }

    /// stop cancels accepting and every open connection.
    pub fn stop(s: *Server) void {
        s.accepting.cancel(s.io);
        s.connections.cancel(s.io);
        s.listener.deinit(s.io);
    }
};

fn accept(s: *Server) void {
    while (true) {
        const stream = s.listener.accept(s.io) catch |err| switch (err) {
            error.Canceled => return,
            else => continue,
        };
        s.connections.concurrent(s.io, serve, .{ s, stream }) catch {
            stream.close(s.io);
            continue;
        };
    }
}

fn serve(s: *Server, stream: Io.net.Stream) Io.Cancelable!void {
    const io = s.io;
    defer stream.close(io);
    var arena: std.heap.ArenaAllocator = .init(s.gpa);
    defer arena.deinit();
    var in_buf: [tls.input_buffer_len]u8 = undefined;
    var out_buf: [16 << 10]u8 = undefined;
    var net_reader = stream.reader(io, &in_buf);
    var net_writer = stream.writer(io, &out_buf);
    var reader = &net_reader.interface;
    var writer = &net_writer.interface;
    var conn: tls.Connection = undefined;
    var clear_in: [tls.clear_buffer_len]u8 = undefined;
    var clear_out: [16 << 10]u8 = undefined;
    if (s.identity) |identity| {
        conn.accept(io, reader, writer, identity, &clear_in, &clear_out) catch return;
        reader = &conn.reader;
        writer = &conn.writer;
    }
    defer if (s.identity != null) conn.end() catch {};
    while (true) {
        _ = arena.reset(.retain_capacity);
        const gpa = arena.allocator();
        var response: Response = .{ .out = writer, .head = false };
        const request = readRequest(gpa, reader) catch |err| {
            const status: u16 = switch (err) {
                error.EndOfStream, error.ReadFailed => return,
                error.ChunkedBody => 501,
                error.TooLarge => 413,
                else => 400,
            };
            response.close = true;
            response.send(status, &.{}, "") catch {};
            writer.flush() catch {};
            return;
        };
        response.head = mem.eql(u8, request.method, "HEAD");
        const keep = !mem.eql(u8, request.header("connection") orelse "", "close");
        response.close = !keep;
        s.handler.serve(s.handler.context, gpa, &request, &response) catch |err| {
            if (err == error.Canceled) return error.Canceled;
            if (!response.sent) {
                response.close = true;
                response.send(500, &.{}, @errorName(err)) catch {};
            }
        };
        if (!response.sent) response.send(204, &.{}, "") catch return;
        writer.flush() catch return;
        if (response.close) return;
    }
}

fn readRequest(gpa: Allocator, reader: *Io.Reader) !Request {
    var head: usize = 0;
    const first = try line(reader, &head);
    var words = mem.splitScalar(u8, first, ' ');
    const method = try gpa.dupe(u8, words.next() orelse return error.BadRequest);
    const target = try gpa.dupe(u8, words.next() orelse return error.BadRequest);
    const version = words.next() orelse return error.BadRequest;
    if (words.next() != null or !mem.startsWith(u8, version, "HTTP/1.") or
        target.len == 0) return error.BadRequest;
    var headers: std.ArrayList(Header) = .empty;
    while (true) {
        const text = try line(reader, &head);
        if (text.len == 0) break;
        const colon = mem.findScalar(u8, text, ':') orelse return error.BadRequest;
        try headers.append(gpa, .{
            .name = try gpa.dupe(u8, mem.trim(u8, text[0..colon], " \t")),
            .value = try gpa.dupe(u8, mem.trim(u8, text[colon + 1 ..], " \t")),
        });
    }
    var request: Request = .{
        .method = method,
        .target = target,
        .headers = headers.items,
        .body = "",
    };
    if (request.header("transfer-encoding") != null) return error.ChunkedBody;
    if (request.header("content-length")) |value| {
        const length = std.fmt.parseInt(usize, value, 10) catch return error.BadRequest;
        if (length > max_body) return error.TooLarge;
        const body = try gpa.alloc(u8, length);
        try reader.readSliceAll(body);
        request.body = body;
    }
    return request;
}

/// line takes one CRLF-terminated line, counting it against max_head.
fn line(reader: *Io.Reader, head: *usize) ![]const u8 {
    const text = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.StreamTooLong => return error.TooLarge,
        else => |e| return e,
    };
    head.* += text.len;
    if (head.* > max_head) return error.TooLarge;
    return mem.trimEnd(u8, text, "\r\n");
}

/// Files serves a directory's files to GET and HEAD and keeps every path
/// asked, in order, found or not.
pub const Files = struct {
    io: Io,
    gpa: Allocator,
    root: Io.Dir,
    mutex: Io.Mutex = .init,
    paths: std.ArrayList([]const u8) = .empty,

    pub fn handler(f: *Files) Handler {
        return .{ .context = f, .serve = serveFile };
    }

    /// asked is a copy of the paths asked so far.
    pub fn asked(f: *Files, gpa: Allocator) ![]const []const u8 {
        f.mutex.lockUncancelable(f.io);
        defer f.mutex.unlock(f.io);
        const out = try gpa.alloc([]const u8, f.paths.items.len);
        for (out, f.paths.items) |*o, p| o.* = try gpa.dupe(u8, p);
        return out;
    }

    fn serveFile(
        context: *anyopaque,
        gpa: Allocator,
        request: *const Request,
        response: *Response,
    ) !void {
        const f: *Files = @ptrCast(@alignCast(context));
        const path = request.path();
        {
            f.mutex.lockUncancelable(f.io);
            defer f.mutex.unlock(f.io);
            try f.paths.append(f.gpa, try f.gpa.dupe(u8, path));
        }
        if (!mem.eql(u8, request.method, "GET") and
            !response.head) return response.send(405, &.{}, "");
        const name = local(gpa, path) catch return response.send(404, &.{}, "");
        const file = f.root.openFile(f.io, name, .{}) catch return response.send(404, &.{}, "");
        defer file.close(f.io);
        const stat = try file.stat(f.io);
        if (stat.kind != .file) return response.send(404, &.{}, "");
        try response.start(
            200,
            &.{.{ .name = "Content-Type", .value = "application/octet-stream" }},
            stat.size,
        );
        if (response.head) return;
        var buf: [64 << 10]u8 = undefined;
        var file_reader = file.reader(f.io, &buf);
        _ = try file_reader.interface.streamRemaining(response.out);
    }
};

/// local is a request path as a relative name under the root, refusing
/// any segment that would leave it.
fn local(gpa: Allocator, path: []const u8) ![]const u8 {
    if (path.len < 2 or path[0] != '/') return error.NotFound;
    var out: std.ArrayList(u8) = .empty;
    var segments = mem.splitScalar(u8, path[1..], '/');
    while (segments.next()) |segment| {
        if (segment.len == 0 or mem.eql(u8, segment, ".") or mem.eql(u8, segment, "..") or
            mem.findAny(u8, segment, "\\%\x00") != null) return error.NotFound;
        if (out.items.len > 0) try out.append(gpa, '/');
        try out.appendSlice(gpa, segment);
    }
    return out.items;
}

test "local keeps names under the root" {
    const gpa = std.testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("boot/latest.json", try local(a, "/boot/latest.json"));
    for ([_][]const u8{
        "/",
        "",
        "boot",
        "/../x",
        "/a/../b",
        "/a//b",
        "/a/%2e%2e/b",
        "/a\\b",
    }) |bad|
        try std.testing.expectError(error.NotFound, local(a, bad));
}

const Echo = struct {
    fn serve(_: *anyopaque, gpa: Allocator, request: *const Request, response: *Response) !void {
        if (mem.eql(u8, request.target, "/truncated")) {
            response.close = true;
            return response.send(200, &.{.{ .name = "Content-Length", .value = "20" }}, "{}");
        }
        const body = try gpa.print("{s} {s} {s} {s}", .{
            request.method, request.target, request.header("x-token") orelse "-", request.body,
        });
        try response.send(
            200,
            &.{ .{ .name = "X-Token", .value = "one" }, .{ .name = "X-Token", .value = "two" } },
            body,
        );
    }
};

test "requests persist on a connection, over plain HTTP and TLS" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = std.testing.io;
    const ca = try tls.Authority.init(io, gpa, "werewolf test authority");
    const identity = try ca.issue(io, gpa, &.{"127.0.0.1"});
    for ([_]?*const tls.Identity{ null, &identity }) |id| {
        var server: Server = undefined;
        var context: u8 = 0;
        try server.start(
            io,
            std.testing.allocator,
            .{ .identity = id, .handler = .{ .context = &context, .serve = Echo.serve } },
        );
        defer server.stop();
        var bundle: std.crypto.Certificate.Bundle = .empty;
        try bundle.bytes.appendSlice(gpa, ca.der);
        try bundle.parseCert(
            gpa,
            0,
            @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s)),
        );
        var client: std.http.Client = .{
            .allocator = gpa,
            .io = io,
            .ca_bundle = bundle,
            .now = Io.Clock.real.now(io),
        };
        defer client.deinit();
        const url = try gpa.print(
            "{s}://127.0.0.1:{d}",
            .{ if (id == null) "http" else "https", server.port() },
        );
        for (0..2) |i| {
            var body: Io.Writer.Allocating = .init(gpa);
            const result = try client.fetch(.{
                .location = .{ .url = try gpa.print("{s}/echo?{d}", .{ url, i }) },
                .method = .POST,
                .payload = "hello",
                .extra_headers = &.{.{ .name = "X-Token", .value = "secret" }},
                .response_writer = &body.writer,
            });
            try std.testing.expectEqual(.ok, result.status);
            try std.testing.expectEqualStrings(
                try gpa.print("POST /echo?{d} secret hello", .{i}),
                body.written(),
            );
        }
        if (id != null) continue;
        // A handler may promise more than it sends, then close.
        try std.testing.expectEqualStrings(
            "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{}",
            try exchange(io, gpa, server.port(), "GET /truncated"),
        );
    }
}

test "Files serves GET and HEAD and keeps every path asked, in order" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "boot");
    try tmp.dir.writeFile(io, .{ .sub_path = "boot/latest.json", .data = "{\"serial\":7}" });
    var files: Files = .{ .io = io, .gpa = gpa, .root = tmp.dir };
    var server: Server = undefined;
    try server.start(io, std.testing.allocator, .{ .handler = files.handler() });
    defer server.stop();
    const found = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n" ++
        "Content-Length: 12\r\nConnection: close\r\n\r\n";
    const missing = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    for ([_][2][]const u8{
        .{ "GET /boot/latest.json", found ++ "{\"serial\":7}" },
        .{ "HEAD /boot/latest.json", found },
        .{ "GET /boot/missing", missing },
        .{ "GET /boot/../boot/latest.json", missing },
    }) |case| try std.testing.expectEqualStrings(
        case[1],
        try exchange(io, gpa, server.port(), case[0]),
    );
    const asked = try files.asked(gpa);
    try std.testing.expectEqual(4, asked.len);
    try std.testing.expectEqualStrings("/boot/missing", asked[2]);
    try std.testing.expectEqualStrings("/boot/../boot/latest.json", asked[3]);
}

/// exchange sends one request line, closing, and returns all the server says.
fn exchange(io: Io, gpa: Allocator, port: u16, request: []const u8) ![]const u8 {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var out_buf: [256]u8 = undefined;
    var writer = stream.writer(io, &out_buf);
    try writer.interface.print(
        "{s} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
        .{request},
    );
    try writer.interface.flush();
    var in_buf: [1024]u8 = undefined;
    var reader = stream.reader(io, &in_buf);
    var got: Io.Writer.Allocating = .init(gpa);
    _ = try reader.interface.streamRemaining(&got.writer);
    return got.written();
}
