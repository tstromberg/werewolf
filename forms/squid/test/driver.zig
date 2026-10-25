//! Inspect Squid's control sockets and unconnected resolver socket ownership.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len == 6 and std.mem.eql(u8, args[1], "request"))
        return request(io, a, args[2..]);
    if (args.len != 4 or !std.mem.eql(u8, args[2], "policy")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    var dir = try Io.Dir.cwd().openDir(io, "/run/svc/squid", .{ .iterate = true });
    defer dir.close(io);
    var walk = try dir.walk(a);
    defer walk.deinit();
    var socket = false;
    var count: usize = 0;
    while (try walk.next(io)) |entry| {
        count += 1;
        if (count > 10000) return error.TooManyEntries;
        socket = socket or entry.kind == .unix_domain_socket;
    }
    try ctx.result(io, args[1], "squid-no-control-socket", !socket);
    const uid = try driver.system.account(io, a, "squid");
    // This also verifies that any missing IPv6 table means the stack is absent.
    _ = try driver.system.listeners(io, a, "udp");
    for ([_][]const u8{ "/proc/net/udp", "/proc/net/udp6" }) |path| {
        const table = driver.system.read(io, a, path) catch |err| {
            if (err == error.FileNotFound and std.mem.endsWith(u8, path, "6")) continue;
            return err;
        };
        if (!try resolverSockets(table, uid)) return error.UndeclaredUdpListener;
    }
    try ctx.result(io, args[1], "squid-resolver", true);
}

const Handle = *anyopaque;
const List = extern struct { data: [*:0]const u8, next: ?*List };
const Api = struct {
    curl_easy_init: *const fn () callconv(.c) ?Handle,
    curl_easy_cleanup: *const fn (Handle) callconv(.c) void,
    curl_easy_setopt: *const fn (Handle, c_int, ...) callconv(.c) c_int,
    curl_easy_perform: *const fn (Handle) callconv(.c) c_int,
    curl_slist_append: *const fn (?*List, [*:0]const u8) callconv(.c) ?*List,
    curl_slist_free_all: *const fn (?*List) callconv(.c) void,
};

fn request(io: Io, a: std.mem.Allocator, args: []const []const u8) !void {
    if (!validRequest(args)) return error.Usage;
    var lib = try std.DynLib.open(if (@import("builtin").os.tag == .macos)
        "/usr/lib/libcurl.dylib"
    else
        "libcurl.so.4");
    defer lib.close();
    var api: Api = undefined;
    inline for (@typeInfo(
        Api,
    ).@"struct".field_names, @typeInfo(Api).@"struct".field_types) |name, T|
        @field(api, name) = lib.lookup(T, name) orelse return error.CurlSymbol;
    const handle = api.curl_easy_init() orelse return error.CurlInit;
    defer api.curl_easy_cleanup(handle);
    const target = try a.dupeSentinel(u8, args[1], 0);
    const host = if (std.mem.eql(u8, args[0], "CONNECT")) args[1] else blk: {
        const start = (std.mem.find(u8, args[1], "://") orelse return error.Usage) + 3;
        const end = std.mem.findScalarPos(u8, args[1], start, '/') orelse args[1].len;
        break :blk args[1][start..end];
    };
    const headers = api.curl_slist_append(
        null,
        (try a.printSentinel("Host: {s}", .{host}, 0)).ptr,
    ) orelse return error.OutOfMemory;
    defer api.curl_slist_free_all(headers);
    var out: Output = .{};
    try option(api.curl_easy_setopt(
        handle,
        10002,
        @as([*:0]const u8, "http://127.0.0.1:3128/"),
    )); // Fixed proxy endpoint, never the requested destination.
    // No proxy from the environment. A libcurl built without proxies, which
    // knows no proxy option (CURLE_NOT_BUILT_IN or CURLE_UNKNOWN_OPTION), has
    // none to take.
    const proxy = api.curl_easy_setopt(handle, 10004, @as([*:0]const u8, ""));
    if (proxy != 4 and proxy != 48) try option(proxy);
    try option(api.curl_easy_setopt(handle, 99, @as(c_long, 1)));
    try option(api.curl_easy_setopt(handle, 155, @as(c_long, 10000)));
    try option(api.curl_easy_setopt(handle, 156, @as(c_long, 5000)));
    try option(api.curl_easy_setopt(handle, 84, @as(c_long, 2))); // HTTP/1.1.
    try option(api.curl_easy_setopt(handle, 42, @as(c_long, 1))); // Include response headers.
    try option(api.curl_easy_setopt(
        handle,
        44,
        @as(c_long, if (std.mem.eql(u8, args[3], "headers")) 1 else 0),
    ));
    try option(api.curl_easy_setopt(handle, 10036, (try a.dupeSentinel(u8, args[0], 0)).ptr));
    try option(api.curl_easy_setopt(handle, 10266, target.ptr)); // Exact request target.
    try option(api.curl_easy_setopt(handle, 10062, (try a.dupeSentinel(u8, args[2], 0)).ptr));
    try option(api.curl_easy_setopt(handle, 10023, headers));
    try option(api.curl_easy_setopt(handle, 20011, &receive));
    try option(api.curl_easy_setopt(handle, 10001, &out));
    try option(api.curl_easy_perform(handle));
    try Io.File.stdout().writeStreamingAll(io, out.bytes[0..out.len]);
}

fn option(code: c_int) !void {
    if (code != 0) return error.CurlFailed;
}

fn validRequest(args: []const []const u8) bool {
    if (args.len != 4) return false;
    if (!std.mem.eql(u8, args[0], "CONNECT") and !std.mem.eql(u8, args[0], "GET"))
        return false;
    if (args[1].len == 0 or args[1].len > 1024) return false;
    for (args[1]) |ch| if (ch <= ' ' or ch >= 127) return false;
    if (!std.mem.eql(u8, args[2], "127.0.0.1") and
        !std.mem.eql(u8, args[2], "127.0.0.2") and
        !std.mem.eql(u8, args[2], "127.0.0.3")) return false;
    return std.mem.eql(u8, args[3], "headers") or std.mem.eql(u8, args[3], "body");
}

const Output = struct { bytes: [1 << 20]u8 = undefined, len: usize = 0 };
fn receive(ptr: [*]const u8, size: usize, count: usize, data: *Output) callconv(.c) usize {
    const length = std.math.mul(usize, size, count) catch return 0;
    if (length > data.bytes.len - data.len) return 0;
    @memcpy(data.bytes[data.len..][0..length], ptr[0..length]);
    data.len += length;
    return length;
}

test "proxy helper bounds its requests and captured output" {
    try std.testing.expect(validRequest(&.{
        "CONNECT",
        "example.com:443",
        "127.0.0.2",
        "headers",
    }));
    try std.testing.expect(!validRequest(&.{ "GET", "bad\r\nHost: evil", "127.0.0.1", "body" }));
    try std.testing.expect(!validRequest(&.{ "CONNECT", "x:443", "0.0.0.0", "headers" }));
    var out: Output = .{};
    try std.testing.expectEqual(1, receive("x", 1, 1, &out));
    try std.testing.expectEqual(0, receive("x", std.math.maxInt(usize), 2, &out));
    out.len = out.bytes.len;
    try std.testing.expectEqual(0, receive("x", 1, 1, &out));
}

fn resolverSockets(table: []const u8, uid: u32) !bool {
    var lines = std.mem.splitScalar(u8, table, '\n');
    const header = lines.next() orelse return error.NetworkTable;
    if (std.mem.find(u8, header, "local_address") == null) return error.NetworkTable;
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t");
        _ = words.next() orelse continue;
        const local = words.next() orelse return error.NetworkTable;
        _ = words.next() orelse return error.NetworkTable;
        const state = words.next() orelse return error.NetworkTable;
        for (0..3) |_| _ = words.next() orelse return error.NetworkTable;
        const owner = try std.fmt.parseInt(u32, words.next() orelse return error.NetworkTable, 10);
        const colon = std.mem.findScalar(u8, local, ':') orelse return error.NetworkTable;
        const port = try std.fmt.parseInt(u16, local[colon + 1 ..], 16);
        if (try loopback(local[0..colon]) or !std.mem.eql(u8, state, "07")) continue;
        if (owner != uid or port < 32768) return false;
    }
    return true;
}
fn loopback(address: []const u8) !bool {
    if (address.len == 8) {
        const word = try std.fmt.parseInt(u32, address, 16);
        return std.mem.nativeToBig(u32, word) >> 24 == 127;
    }
    if (address.len != 32) return error.NetworkTable;
    for (address[0..24]) |ch| if (ch != '0') return false;
    return std.mem.nativeToBig(u32, try std.fmt.parseInt(u32, address[24..], 16)) == 1;
}

test "only Squid owns non-loopback ephemeral UDP listeners" {
    const header = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid\n";
    const tail = " 00000000:0000 07 00000000:00000000 00:00000000 00000000 ";
    try std.testing.expect(try resolverSockets(header ++ "0: 00000000:8000" ++ tail ++ "42\n", 42));
    try std.testing.expect(!try resolverSockets(header ++ "0: 00000000:8000" ++ tail ++ "0\n", 42));
    try std.testing.expect(!try resolverSockets(
        header ++ "0: 00000000:7FFF" ++ tail ++ "42\n",
        42,
    ));
    try std.testing.expect(try resolverSockets(header ++ "0: 0100007F:0035" ++ tail ++ "0\n", 42));
    try std.testing.expectError(
        error.NetworkTable,
        resolverSockets(header ++ "0: malformed\n", 42),
    );
}
