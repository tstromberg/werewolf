//! haproxy-setup writes HAProxy's configuration before each start, from
//! the machine's settings: the backends, a health check path, and TLS
//! when the config holds a certificate. It refuses a backend on a port
//! fence will not let HAProxy reach, and checks the result with HAProxy.
//!
//!     haproxy-setup
//!
//! leash runs it as the haproxy user, under the service's Landlock rules
//! (forms/haproxy/form.yaml). See forms/haproxy/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const haproxy = "/usr/bin/haproxy";
const run_dir = "/run/svc/haproxy";
const config = run_dir ++ "/haproxy.cfg";
const tls_cert = run_dir ++ "/tls-cert";
const tls_key = run_dir ++ "/tls-key";
/// net is fence's policy, which the build writes from each service's
/// listen and connect lines.
const net = "/usr/share/werewolf/net";
const max_backends = 32;

const Settings = struct {
    backends: []const Backend,
    /// health is the path of an HTTP health check, or null for HAProxy's
    /// TCP connect check.
    health: ?[]const u8 = null,
    tls: bool = false,
};

const Backend = struct { host: []const u8, port: u16 };

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa, init.minimal.environ) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const list = setting(gpa, environ, "HAPROXY_BACKENDS") orelse return error.NoBackends;
    var s: Settings = .{
        .backends = try backends(gpa, list),
        .health = setting(gpa, environ, "HAPROXY_HEALTH"),
    };
    if (s.health) |h| if (!path(h)) return error.HealthNotAPath;
    const cert = try exists(io, tls_cert);
    if (cert != try exists(io, tls_key)) return error.TlsNeedsCertAndKey;
    s.tls = cert;

    if (Dir.cwd().readFileAlloc(io, net, gpa, .limited(64 << 10))) |policy| {
        const uid = std.os.linux.getuid();
        for (s.backends) |b| if (!reaches(policy, uid, b.port)) {
            say(io, "backend {s}:{d}: fence lets haproxy reach no port {d}; " ++
                "use a backend on 80, 443 or 8080, or a form of your own that " ++
                "connects to it (forms/haproxy/README.md)", .{ b.host, b.port, b.port });
            return error.BackendPortNotReached;
        };
    } else |err| say(io, "{s}: {s}; backends' ports not checked", .{ net, @errorName(err) });

    try replace(io, config, try render(gpa, s), 0o600);
    const r = try std.process.run(gpa, io, .{
        .argv = &.{ haproxy, "-c", "-q", "-f", config },
        .stdout_limit = .limited(64 << 10),
        .stderr_limit = .limited(64 << 10),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } },
    });
    if (r.term != .exited or r.term.exited != 0) {
        var lines = std.mem.splitScalar(u8, if (r.stderr.len > 0) r.stderr else r.stdout, '\n');
        while (lines.next()) |line| if (line.len > 0) say(io, "haproxy -c: {s}", .{line});
        return error.ConfigRefused;
    }
    var names: std.ArrayList(u8) = .empty;
    for (s.backends, 0..) |b, i|
        try names.print(gpa, "{s}{s}:{d}", .{ if (i > 0) ", " else "", b.host, b.port });
    say(io, "haproxy.cfg written: {s} on :80{s}, to {s}, checked {s}", .{
        if (s.tls) "HTTPS on :443, redirects" else "HTTP",
        if (s.tls) "" else " alone",
        names.items,
        if (s.health) |h| h else "by TCP connect",
    });
}

/// backends parses HOST:PORT,... as service-config renders a hostport
/// list. The host goes into HAProxy's configuration unquoted, so only a
/// name's or an IPv4 address's characters are taken.
fn backends(gpa: Allocator, list: []const u8) ![]const Backend {
    var out: std.ArrayList(Backend) = .empty;
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |item| {
        const colon = std.mem.findScalarLast(u8, item, ':') orelse return error.BackendWithoutPort;
        const host = item[0..colon];
        if (host.len == 0 or host.len > 253) return error.BadBackendHost;
        for (host) |c| switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '-' => {},
            else => return error.BadBackendHost,
        };
        const port = std.fmt.parseInt(
            u16,
            item[colon + 1 ..],
            10,
        ) catch return error.BadBackendPort;
        if (port == 0) return error.BadBackendPort;
        if (out.items.len == max_backends) return error.TooManyBackends;
        try out.append(gpa, .{ .host = host, .port = port });
    }
    return out.items;
}

/// reaches reports whether policy lets uid connect to TCP port.
fn reaches(policy: []const u8, uid: u32, port: u16) bool {
    var lines = std.mem.splitScalar(u8, policy, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        if (!std.mem.eql(u8, words.next() orelse continue, "connect")) continue;
        const who = std.fmt.parseInt(u32, words.next() orelse continue, 10) catch continue;
        if (who != uid or !std.mem.eql(u8, words.next() orelse continue, "tcp")) continue;
        if ((std.fmt.parseInt(u16, words.next() orelse continue, 10) catch continue) == port)
            return true;
    }
    return false;
}

/// render returns haproxy.cfg for s. HTTP on :80, and with TLS HTTPS on
/// :443 and :80 sending there. Nothing to control HAProxy by but this
/// file: no stats socket, no Lua, no external checks, which would fork.
fn render(gpa: Allocator, s: Settings) ![]const u8 {
    var w: Io.Writer.Allocating = .init(gpa);
    const o = &w.writer;
    try o.writeAll(
        "# Written by haproxy-setup at each start, from the machine's settings\n" ++
            "# (forms/haproxy/README.md): change those, not this file.\n" ++
            "global\n" ++
            "    log stdout format raw local0\n" ++
            // About 32 KiB a connection, two 16 KiB buffers: 4000 of them
            // fit the 200 MiB -m gives it, under leash's 256.
            "    maxconn 4000\n" ++
            "    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets\n" ++
            "defaults\n" ++
            "    mode http\n" ++
            "    log global\n" ++
            "    option httplog\n" ++
            // Errors and slow or failed requests alone: every request on a
            // serial console would hold the machine back.
            "    option dontlog-normal\n" ++
            "    option forwardfor\n" ++
            "    timeout connect 5s\n" ++
            "    timeout client 30s\n" ++
            "    timeout server 30s\n" ++
            "    timeout http-request 10s\n" ++
            "    timeout http-keep-alive 10s\n" ++
            "    timeout tunnel 1h\n" ++
            // A backend whose name does not resolve yet starts down, not
            // HAProxy's whole start.
            "    default-server init-addr last,libc,none\n",
    );
    if (s.tls) try o.writeAll(
        "crt-store\n" ++
            "    load crt \"" ++ tls_cert ++ "\" key \"" ++ tls_key ++ "\" alias \"site\"\n",
    );
    try o.writeAll("frontend web\n    bind :80\n");
    if (s.tls) try o.writeAll(
        "    bind :443 ssl crt \"@/site\" alpn h2,http/1.1\n" ++
            "    http-request redirect scheme https code 301 unless { ssl_fc }\n" ++
            // After every response, HAProxy's own errors too.
            "    http-after-response set-header Strict-Transport-Security \"max-age=63072000\" " ++
            "if { ssl_fc }\n",
    );
    // httpoxy: a Proxy header becomes HTTP_PROXY in a CGI backend.
    try o.writeAll("    http-request del-header Proxy\n    default_backend app\n" ++
        "backend app\n    balance roundrobin\n");
    if (s.health) |h| try o.print("    option httpchk GET {s}\n", .{h});
    for (s.backends, 1..) |b, i| try o.print(
        "    server app{d} {s}:{d} check\n",
        .{ i, b.host, b.port },
    );
    return w.written();
}

/// path reports whether s is an absolute URL path of plain characters.
fn path(s: []const u8) bool {
    if (s.len == 0 or s.len > 256 or s[0] != '/') return false;
    for (s) |c| if (c <= ' ' or c >= 0x7f or c == '"' or c == '\\' or c == '#') return false;
    return true;
}

/// setting returns the environment's value for name, or null if it is
/// unset or empty.
fn setting(gpa: Allocator, environ: std.process.Environ, name: []const u8) ?[]const u8 {
    const v = environ.getAlloc(gpa, name) catch return null;
    return if (v.len > 0) v else null;
}

fn exists(io: Io, p: []const u8) !bool {
    Dir.cwd().access(io, p, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

/// replace writes p whole or not at all: a temporary file, synced, then
/// renamed over it.
fn replace(io: Io, p: []const u8, data: []const u8, mode: std.posix.mode_t) !void {
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(p).?, .{ .iterate = true });
    defer dir.close(io);
    const name = std.fs.path.basename(p);
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, ".{s}.tmp", .{name});
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(io, tmp, .{ .exclusive = true, .permissions = .fromMode(mode) });
        defer f.close(io);
        try f.writeStreamingAll(io, data);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, name, io);
}

/// say prints one line to the console. HAProxy's errors quote what it
/// read, so control bytes become "?" to stop escape sequences and forged
/// log lines.
fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "haproxy-setup: " ++ fmt ++ "\n", args) catch return;
    for (line[0 .. line.len - 1]) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = '?';
    };
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "backends parses the rendered list and refuses what is not a host and port" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const b = try backends(a, "10.0.0.5:8080,app.internal:80");
    try testing.expectEqual(2, b.len);
    try testing.expectEqualStrings("10.0.0.5", b[0].host);
    try testing.expectEqual(8080, b[0].port);
    try testing.expectEqualStrings("app.internal", b[1].host);
    for ([_][]const u8{
        "10.0.0.5",
        ":80",
        "a:0",
        "a:65536",
        "a b:80",
        "a\"b:80",
        "a:80,",
        "[::1]:80",
    }) |bad|
        try testing.expect(std.meta.isError(backends(a, bad)));
}

test "reaches reads fence's connect lines for one user" {
    const policy = "connect 1000 tcp 8080\nconnect 1000 udp 53\nconnect 2000 tcp 80\n" ++
        "connect 1000 tcp 443 public\nlisten tcp 80\n";
    try testing.expect(reaches(policy, 1000, 8080));
    try testing.expect(reaches(policy, 1000, 443));
    try testing.expect(!reaches(policy, 1000, 80));
    try testing.expect(!reaches(policy, 1000, 53));
    try testing.expect(!reaches(policy, 3000, 8080));
}

test "render: HTTP alone, TCP checks" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const cfg = try render(arena.allocator(), .{
        .backends = &.{
            .{ .host = "10.0.0.5", .port = 8080 },
            .{ .host = "10.0.0.6", .port = 8080 },
        },
    });
    for ([_][]const u8{
        "frontend web\n    bind :80\n    http-request del-header Proxy\n",
        "    server app1 10.0.0.5:8080 check\n    server app2 10.0.0.6:8080 check\n",
        "    timeout http-request 10s\n",
    }) |want| try testing.expect(std.mem.find(u8, cfg, want) != null);
    for ([_][]const u8{ ":443", "crt-store", "httpchk", "stats", "lua", "external-check" }) |absent|
        try testing.expect(std.mem.find(u8, cfg, absent) == null);
}

test "render: HTTPS with a health path" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const cfg = try render(arena.allocator(), .{
        .backends = &.{.{ .host = "app", .port = 80 }},
        .health = "/health",
        .tls = true,
    });
    for ([_][]const u8{
        "crt-store\n    load crt \"/run/svc/haproxy/tls-cert\" key \"/run/svc/haproxy/tls-key\"",
        "    bind :443 ssl crt \"@/site\"",
        "redirect scheme https code 301 unless { ssl_fc }",
        "    http-after-response set-header Strict-Transport-Security \"max-age=63072000\" " ++
            "if { ssl_fc }\n",
        "    option httpchk GET /health\n",
    }) |want| try testing.expect(std.mem.find(u8, cfg, want) != null);
}

test "path takes plain absolute paths" {
    try testing.expect(path("/health"));
    try testing.expect(path("/a/b?c=d"));
    for ([_][]const u8{ "", "health", "/a b", "/a\nb", "/\"", "/#x" }) |bad|
        try testing.expect(!path(bad));
}
