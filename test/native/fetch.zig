//! HTTP transport for test probes. libcurl owns TLS, framing and cookie semantics.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Json = std.json.Value;
const Handle = *anyopaque;
const List = extern struct { data: [*:0]const u8, next: ?*List };
const Api = struct {
    curl_easy_init: *const fn () callconv(.c) ?Handle,
    curl_easy_cleanup: *const fn (Handle) callconv(.c) void,
    curl_easy_reset: *const fn (Handle) callconv(.c) void,
    curl_easy_setopt: *const fn (Handle, c_int, ...) callconv(.c) c_int,
    curl_easy_getinfo: *const fn (Handle, c_int, ...) callconv(.c) c_int,
    curl_easy_perform: *const fn (Handle) callconv(.c) c_int,
    curl_slist_append: *const fn (?*List, [*:0]const u8) callconv(.c) ?*List,
    curl_slist_free_all: *const fn (?*List) callconv(.c) void,
    curl_easy_escape: *const fn (Handle, [*:0]const u8, c_int) callconv(.c) ?[*:0]u8,
    curl_free: *const fn (?*anyopaque) callconv(.c) void,
    curl_mime_init: *const fn (Handle) callconv(.c) ?Handle,
    curl_mime_free: *const fn (Handle) callconv(.c) void,
    curl_mime_addpart: *const fn (Handle) callconv(.c) ?Handle,
    curl_mime_name: *const fn (Handle, [*:0]const u8) callconv(.c) c_int,
    curl_mime_data: *const fn (Handle, [*]const u8, usize) callconv(.c) c_int,
    curl_mime_filedata: *const fn (Handle, [*:0]const u8) callconv(.c) c_int,
    curl_mime_filename: *const fn (Handle, [*:0]const u8) callconv(.c) c_int,
    curl_mime_type: *const fn (Handle, [*:0]const u8) callconv(.c) c_int,
};

pub const Client = struct {
    lib: std.DynLib,
    api: Api,
    arena: Allocator,
    sessions: std.StringHashMapUnmanaged(Handle) = .empty,

    pub fn init(arena: Allocator) !Client {
        var lib = try std.DynLib.open(if (@import("builtin").os.tag == .macos)
            "/usr/lib/libcurl.dylib"
        else
            "libcurl.so.4");
        errdefer lib.close();
        var api: Api = undefined;
        inline for (@typeInfo(
            Api,
        ).@"struct".field_names, @typeInfo(Api).@"struct".field_types) |name, T|
            @field(api, name) = lib.lookup(T, name) orelse return error.CurlSymbol;
        return .{ .lib = lib, .api = api, .arena = arena };
    }

    fn requestUrl(req: Json, a: Allocator) ![:0]const u8 {
        const base = req.object.get("url").?.string;
        const parts = req.object.get("path") orelse return a.dupeSentinel(u8, base, 0);
        if (base.len > 65536) return error.UrlTooLong;
        var url: std.Io.Writer.Allocating = .init(a);
        defer url.deinit();
        try url.writer.writeAll(std.mem.trimEnd(u8, base, "/"));
        for (parts.array.items) |part| {
            try url.writer.writeByte('/');
            // URI path characters such as ':' stay literal; a slash is segment data.
            var pieces = std.mem.splitScalar(u8, part.string, '/');
            var first = true;
            while (pieces.next()) |piece| {
                if (!first) try url.writer.writeAll("%2F");
                try (std.Uri.Component{ .raw = piece }).formatPath(&url.writer);
                first = false;
            }
            if (url.writer.buffered().len > 65536) return error.UrlTooLong;
        }
        return a.dupeSentinel(u8, url.writer.buffered(), 0);
    }

    pub fn deinit(self: *Client) void {
        var it = self.sessions.valueIterator();
        while (it.next()) |handle| self.api.curl_easy_cleanup(handle.*);
        self.sessions.deinit(self.arena);
        self.lib.close();
    }

    pub fn request(self: *Client, req: Json, timeout_ms: i64, a: Allocator) !Json {
        const api = self.api;
        const session = req.object.get("session");
        const handle = if (session) |s| blk: {
            const entry = try self.sessions.getOrPut(self.arena, s.string);
            if (!entry.found_existing) {
                entry.value_ptr.* = api.curl_easy_init() orelse return error.CurlInit;
            }
            break :blk entry.value_ptr.*;
        } else api.curl_easy_init() orelse return error.CurlInit;
        defer if (session == null) api.curl_easy_cleanup(handle);
        api.curl_easy_reset(handle);
        var output: Output = .{ .arena = a };
        const url = try requestUrl(req, a);
        try check(api.curl_easy_setopt(handle, 10002, url.ptr)); // URL
        // Hardened libcurl omits proxy support and reports an unknown option.
        // Other builds must explicitly ignore proxy environment variables.
        const proxy = api.curl_easy_setopt(handle, 10004, @as([*:0]const u8, ""));
        if (proxy != 48) try check(proxy);
        try check(api.curl_easy_setopt(handle, 181, @as(c_long, 3))); // HTTP + HTTPS only
        try check(api.curl_easy_setopt(handle, 52, @as(c_long, 0))); // no automatic redirects
        try check(api.curl_easy_setopt(handle, 99, @as(c_long, 1))); // no signals
        try check(api.curl_easy_setopt(handle, 155, @as(c_long, @intCast(timeout_ms))));
        try check(api.curl_easy_setopt(handle, 156, @as(c_long, @intCast(@min(timeout_ms, 5000)))));
        try check(api.curl_easy_setopt(handle, 64, @as(c_long, 1))); // verify peer
        try check(api.curl_easy_setopt(handle, 81, @as(c_long, 2))); // verify hostname
        try check(api.curl_easy_setopt(handle, 234, @as(c_long, 1))); // preserve literal path
        try check(api.curl_easy_setopt(handle, 10102, @as([*:0]const u8, ""))); // decode encoding
        try check(api.curl_easy_setopt(handle, 20011, &bodyCallback));
        try check(api.curl_easy_setopt(handle, 10001, &output));
        try check(api.curl_easy_setopt(handle, 20079, &headerCallback));
        try check(api.curl_easy_setopt(handle, 10029, &output));
        try check(api.curl_easy_setopt(handle, 10031, @as([*:0]const u8, "")));
        if (req.object.get("ca")) |ca|
            try check(api.curl_easy_setopt(
                handle,
                10065,
                (try a.dupeSentinel(u8, ca.string, 0)).ptr,
            ));
        var resolves: ?*List = null;
        defer api.curl_slist_free_all(resolves);
        if (req.object.get("resolve")) |resolve| {
            for (resolve.array.items) |entry|
                resolves = api.curl_slist_append(
                    resolves,
                    (try a.dupeSentinel(u8, entry.string, 0)).ptr,
                ) orelse return error.OutOfMemory;
            try check(api.curl_easy_setopt(handle, 10203, resolves));
        }
        var headers: ?*List = null;
        defer api.curl_slist_free_all(headers);
        if (req.object.get("headers")) |values| {
            var it = values.object.iterator();
            while (it.next()) |entry| {
                const line = try a.printSentinel(
                    "{s}: {s}",
                    .{ entry.key_ptr.*, entry.value_ptr.string },
                    0,
                );
                headers = api.curl_slist_append(headers, line.ptr) orelse return error.OutOfMemory;
            }
        }
        if (req.object.get("bearer")) |token| {
            const line = try a.printSentinel("Authorization: Bearer {s}", .{token.string}, 0);
            headers = api.curl_slist_append(headers, line.ptr) orelse return error.OutOfMemory;
        }
        if (req.object.get("authorization")) |auth| {
            const line = try a.printSentinel("Authorization: {s} {s}", .{
                auth.object.get("scheme").?.string,
                auth.object.get("credentials").?.string,
            }, 0);
            headers = api.curl_slist_append(headers, line.ptr) orelse return error.OutOfMemory;
        }
        const method = if (req.object.get("method")) |m| m.string else "GET";
        if (std.mem.eql(
            u8,
            method,
            "HEAD",
        )) try check(api.curl_easy_setopt(handle, 44, @as(c_long, 1)));
        var body: ?[]const u8 = null;
        if (req.object.get("body")) |b| body = b.string;
        if (req.object.get("json")) |j| {
            body = try std.json.Stringify.valueAlloc(a, j, .{});
            headers = api.curl_slist_append(
                headers,
                "Content-Type: application/json",
            ) orelse return error.OutOfMemory;
        }
        if (req.object.get("form")) |form| {
            var encoded: std.Io.Writer.Allocating = .init(a);
            var it = form.object.iterator();
            var first = true;
            while (it.next()) |entry| {
                const k = api.curl_easy_escape(
                    handle,
                    (try a.dupeSentinel(u8, entry.key_ptr.*, 0)).ptr,
                    0,
                ) orelse return error.OutOfMemory;
                defer api.curl_free(k);
                const v = api.curl_easy_escape(
                    handle,
                    (try a.dupeSentinel(u8, entry.value_ptr.string, 0)).ptr,
                    0,
                ) orelse return error.OutOfMemory;
                defer api.curl_free(v);
                if (!first) try encoded.writer.writeByte('&');
                first = false;
                try encoded.writer.print("{s}={s}", .{ std.mem.span(k), std.mem.span(v) });
            }
            body = try encoded.toOwnedSlice();
        }
        var mime: ?Handle = null;
        defer if (mime) |m| api.curl_mime_free(m);
        if (req.object.get("multipart")) |parts| {
            mime = api.curl_mime_init(handle) orelse return error.CurlInit;
            var it = parts.object.iterator();
            while (it.next()) |entry| {
                const part = api.curl_mime_addpart(mime.?) orelse return error.OutOfMemory;
                try check(api.curl_mime_name(
                    part,
                    (try a.dupeSentinel(u8, entry.key_ptr.*, 0)).ptr,
                ));
                const value = entry.value_ptr.*;
                if (value == .string) {
                    try check(api.curl_mime_data(part, value.string.ptr, value.string.len));
                } else {
                    try check(api.curl_mime_filedata(
                        part,
                        (try a.dupeSentinel(u8, value.object.get("file").?.string, 0)).ptr,
                    ));
                    if (value.object.get("type")) |t| try check(api.curl_mime_type(
                        part,
                        (try a.dupeSentinel(u8, t.string, 0)).ptr,
                    ));
                    if (value.object.get("filename")) |f| try check(api.curl_mime_filename(
                        part,
                        (try a.dupeSentinel(u8, f.string, 0)).ptr,
                    ));
                }
            }
            try check(api.curl_easy_setopt(handle, 10269, mime.?));
        }
        if (body) |b| {
            try check(api.curl_easy_setopt(handle, 10015, b.ptr));
            try check(api.curl_easy_setopt(handle, 60, @as(c_long, @intCast(b.len))));
        }
        try check(api.curl_easy_setopt(handle, 10023, headers));
        try check(api.curl_easy_setopt(handle, 10036, (try a.dupeSentinel(u8, method, 0)).ptr));
        const code = api.curl_easy_perform(handle);
        if (output.failed) return error.ResponseTooLarge;
        if (code != 0) return switch (code) {
            28 => error.Timeout,
            35 => error.TlsHandshake,
            60 => error.CertificateVerification,
            7 => error.ConnectionRefused,
            else => error.HttpTransport,
        };
        var status: c_long = 0;
        try check(api.curl_easy_getinfo(handle, 0x200002, &status));
        var result: std.json.ObjectMap = .empty;
        try result.put(a, "status", .{ .integer = status });
        try result.put(a, "body", .{ .string = output.body.items });
        try result.put(a, "headers", .{ .object = output.headers });
        var cookies: std.json.ObjectMap = .empty;
        var list: ?*List = null;
        try check(api.curl_easy_getinfo(handle, 0x40001c, &list));
        defer api.curl_slist_free_all(list);
        var cursor = list;
        while (cursor) |item| : (cursor = item.next) {
            var parts = std.mem.splitScalar(u8, std.mem.span(item.data), '\t');
            for (0..5) |_| _ = parts.next();
            const name = parts.next() orelse return error.CookieFormat;
            const value = parts.next() orelse return error.CookieFormat;
            // Ambiguous cookie names cannot be used as captures.
            if (cookies.contains(name)) {
                try cookies.put(a, name, .null);
                continue;
            }
            try cookies.put(a, try a.dupe(u8, name), .{ .string = try a.dupe(u8, value) });
        }
        try result.put(a, "cookies", .{ .object = cookies });
        return .{ .object = result };
    }
};

fn check(code: c_int) !void {
    if (code != 0) return error.CurlOption;
}

const Output = struct {
    arena: Allocator,
    body: std.ArrayList(u8) = .empty,
    headers: std.json.ObjectMap = .{},
    header_bytes: usize = 0,
    failed: bool = false,
};

fn bodyCallback(
    ptr: [*]const u8,
    size: usize,
    count: usize,
    userdata: *anyopaque,
) callconv(.c) usize {
    const out: *Output = @ptrCast(@alignCast(userdata));
    const n = std.math.mul(usize, size, count) catch return 0;
    if (n > (1 << 20) -| out.body.items.len) {
        out.failed = true;
        return 0;
    }
    out.body.appendSlice(out.arena, ptr[0..n]) catch return 0;
    return n;
}

fn headerCallback(
    ptr: [*]const u8,
    size: usize,
    count: usize,
    userdata: *anyopaque,
) callconv(.c) usize {
    const out: *Output = @ptrCast(@alignCast(userdata));
    const n = std.math.mul(usize, size, count) catch return 0;
    out.header_bytes += n;
    if (out.header_bytes > 64 << 10) {
        out.failed = true;
        return 0;
    }
    const line = std.mem.trim(u8, ptr[0..n], "\r\n");
    if (std.mem.startsWith(u8, line, "HTTP/")) {
        out.headers = .empty;
    } else if (std.mem.findScalar(u8, line, ':')) |colon| {
        const key = out.arena.dupe(u8, line[0..colon]) catch return 0;
        for (key) |*c| c.* = std.ascii.toLower(c.*);
        const value = out.arena.dupe(
            u8,
            std.mem.trim(u8, line[colon + 1 ..], " \t"),
        ) catch return 0;
        if (out.headers.get(key)) |prior| {
            var values: std.json.Array = if (prior == .array) prior.array else .init(out.arena);
            if (prior != .array) values.append(prior) catch return 0;
            values.append(.{ .string = value }) catch return 0;
            out.headers.put(out.arena, key, .{ .array = values }) catch return 0;
        } else out.headers.put(out.arena, key, .{ .string = value }) catch return 0;
    }
    return n;
}
