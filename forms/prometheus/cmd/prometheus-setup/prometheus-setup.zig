//! prometheus-setup writes Prometheus's configuration before each start,
//! from the machine's settings: what it scrapes, the user its web and API
//! take, as a bcrypt hash of the config's password, and TLS when the
//! config holds a certificate. It refuses a target on a port fence will
//! not let Prometheus reach, and checks the result with promtool.
//!
//!     prometheus-setup
//!
//! leash runs it as the prometheus user, under the service's Landlock
//! rules (forms/prometheus/form.yaml). See forms/prometheus/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const bcrypt = std.crypto.pwhash.bcrypt;

const promtool = "/usr/bin/promtool";
const run_dir = "/run/svc/prometheus";
const config = run_dir ++ "/prometheus.yml";
const web_config = run_dir ++ "/web.yml";
/// password is leash's copy of the config's, which Prometheus also reads
/// to scrape itself.
const password = run_dir ++ "/admin-password";
const tls_cert = run_dir ++ "/tls-cert";
const tls_key = run_dir ++ "/tls-key";
/// net is fence's policy, which the build writes from each service's
/// listen and connect lines.
const net = "/usr/share/werewolf/net";
const max_targets = 256;

const Settings = struct {
    targets: []const Target,
    admin: []const u8,
    tls: bool = false,
};

const Target = struct { host: []const u8, port: u16 };

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa, init.minimal.environ) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const list = setting(gpa, environ, "PROMETHEUS_TARGETS") orelse return error.NoTargets;
    var s: Settings = .{
        .targets = try targets(gpa, list),
        .admin = setting(gpa, environ, "PROMETHEUS_ADMIN") orelse return error.NoAdmin,
    };
    if (!name(s.admin)) return error.AdminNotAName;
    const cert = try exists(io, tls_cert);
    if (cert != try exists(io, tls_key)) return error.TlsNeedsCertAndKey;
    s.tls = cert;

    const text = Dir.cwd().readFileAlloc(
        io,
        password,
        gpa,
        .limited(4 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => return error.NoAdminPassword,
        else => return err,
    };
    const secret = std.mem.trimEnd(u8, text, "\r\n");
    // bcrypt reads 72 bytes; Go's, which Prometheus checks it with, refuses more.
    if (secret.len < 12) return error.AdminPasswordTooShort;
    if (secret.len > 72) return error.AdminPasswordTooLong;

    if (Dir.cwd().readFileAlloc(io, net, gpa, .limited(64 << 10))) |policy| {
        const uid = std.os.linux.getuid();
        for (s.targets) |t| if (!reaches(policy, uid, t.port)) {
            say(io, "target {s}:{d}: fence lets prometheus reach no port {d}; " ++
                "use 80, 443, 8080, 9090 or 9100, or a form of your own that " ++
                "connects to it (forms/prometheus/README.md)", .{ t.host, t.port, t.port });
            return error.TargetPortNotReached;
        };
    } else |err| say(io, "{s}: {s}; targets' ports not checked", .{ net, @errorName(err) });

    var buf: [bcrypt.hash_length]u8 = undefined;
    const hash = try bcrypt.strHash(secret, .{
        .params = .{ .rounds_log = 10, .silently_truncate_password = true },
        .encoding = .crypt,
    }, &buf, io);
    try replace(io, web_config, try web(gpa, s, hash), 0o600);
    try replace(io, config, try scrape(gpa, s), 0o600);
    try check(io, gpa, &.{ promtool, "check", "web-config", web_config });
    try check(io, gpa, &.{ promtool, "check", "config", "--syntax-only", config });
    say(io, "prometheus.yml written: {d} targets and itself, every 30 s; {s} for {s}", .{
        s.targets.len,
        if (s.tls) "HTTPS" else "HTTP",
        s.admin,
    });
}

/// targets parses HOST:PORT,... as service-config renders a hostport
/// list. A host goes into YAML in quotes, so only a name's or an IPv4
/// address's characters are taken.
fn targets(gpa: Allocator, list: []const u8) ![]const Target {
    var out: std.ArrayList(Target) = .empty;
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |item| {
        const colon = std.mem.findScalarLast(u8, item, ':') orelse return error.TargetWithoutPort;
        const host = item[0..colon];
        if (host.len == 0 or host.len > 253) return error.BadTargetHost;
        for (host) |c| switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '-' => {},
            else => return error.BadTargetHost,
        };
        const port = std.fmt.parseInt(u16, item[colon + 1 ..], 10) catch return error.BadTargetPort;
        if (port == 0) return error.BadTargetPort;
        if (out.items.len == max_targets) return error.TooManyTargets;
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

/// web returns web.yml: the one user the web and the API take, and TLS.
fn web(gpa: Allocator, s: Settings, hash: []const u8) ![]const u8 {
    var w: Io.Writer.Allocating = .init(gpa);
    const o = &w.writer;
    try o.print("# Written by prometheus-setup at each start (forms/prometheus/README.md).\n" ++
        "basic_auth_users:\n  {s}: '{s}'\n", .{ s.admin, hash });
    if (s.tls) try o.writeAll("tls_server_config:\n  cert_file: " ++ tls_cert ++
        "\n  key_file: " ++ tls_key ++ "\n  min_version: TLS12\n");
    return w.written();
}

/// scrape returns prometheus.yml: the targets, and Prometheus itself with
/// its own user, so a broken scrape shows. Rules, alerting and remote
/// write are none.
fn scrape(gpa: Allocator, s: Settings) ![]const u8 {
    var w: Io.Writer.Allocating = .init(gpa);
    const o = &w.writer;
    try o.print(
        "# Written by prometheus-setup at each start, from the machine's settings\n" ++
            "# (forms/prometheus/README.md): change those, not this file.\n" ++
            "global:\n  scrape_interval: 30s\n  evaluation_interval: 30s\n" ++
            "scrape_configs:\n" ++
            "  - job_name: prometheus\n" ++
            "    scheme: {s}\n" ++
            "    basic_auth:\n      username: {s}\n      password_file: " ++ password ++ "\n",
        .{ if (s.tls) "https" else "http", s.admin },
    );
    // Its own certificate names the machine, not localhost.
    if (s.tls) try o.writeAll("    tls_config:\n      insecure_skip_verify: true\n");
    try o.writeAll("    static_configs:\n      - targets: ['127.0.0.1:9090']\n" ++
        "  - job_name: targets\n    static_configs:\n      - targets:\n");
    for (s.targets) |t| try o.print("          - '{s}:{d}'\n", .{ t.host, t.port });
    return w.written();
}

/// check runs promtool, printing what it says when it refuses.
fn check(io: Io, gpa: Allocator, argv: []const []const u8) !void {
    const r = try std.process.run(gpa, io, .{
        .argv = argv,
        .stdout_limit = .limited(64 << 10),
        .stderr_limit = .limited(64 << 10),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } },
    });
    if (r.term == .exited and r.term.exited == 0) return;
    var lines = std.mem.splitScalar(u8, if (r.stderr.len > 0) r.stderr else r.stdout, '\n');
    while (lines.next()) |line| if (line.len > 0) say(io, "promtool {s}: {s}", .{ argv[2], line });
    return error.ConfigRefused;
}

/// name reports whether s is a plain user name: lower-case ASCII letters
/// and digits, with dots, hyphens and underscores between them.
fn name(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    for (s, 0..) |c, i| switch (c) {
        'a'...'z', '0'...'9' => {},
        '.', '-', '_' => if (i == 0 or i == s.len - 1) return false,
        else => return false,
    };
    return true;
}

/// setting returns the environment's value for key, or null if it is
/// unset or empty.
fn setting(gpa: Allocator, environ: std.process.Environ, key: []const u8) ?[]const u8 {
    const v = environ.getAlloc(gpa, key) catch return null;
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
    const base = std.fs.path.basename(p);
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, ".{s}.tmp", .{base});
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(io, tmp, .{ .exclusive = true, .permissions = .fromMode(mode) });
        defer f.close(io);
        try f.writeStreamingAll(io, data);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, base, io);
}

/// say prints one line to the console. promtool's errors quote what it
/// read, so control bytes become "?" to stop escape sequences and forged
/// log lines.
fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "prometheus-setup: " ++ fmt ++ "\n", args) catch return;
    for (line[0 .. line.len - 1]) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = '?';
    };
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "targets parses the rendered list and refuses what is not a host and port" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t = try targets(a, "10.0.0.5:9100,app.internal:8080");
    try testing.expectEqual(2, t.len);
    try testing.expectEqualStrings("app.internal", t[1].host);
    try testing.expectEqual(9100, t[0].port);
    for ([_][]const u8{ "10.0.0.5", ":80", "a:0", "a b:80", "a':80", "a:80,", "[::1]:80" }) |bad|
        try testing.expect(std.meta.isError(targets(a, bad)));
}

test "reaches reads fence's connect lines for one user" {
    const policy = "connect 1000 tcp 9100\nconnect 1000 udp 53\nconnect 2000 tcp 80\n";
    try testing.expect(reaches(policy, 1000, 9100));
    try testing.expect(!reaches(policy, 1000, 80));
    try testing.expect(!reaches(policy, 1000, 53));
}

test "web: the hash quoted, TLS only with a certificate" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const plain = try web(a, .{ .targets = &.{}, .admin = "ops" }, "$2b$10$abc/def");
    try testing.expect(std.mem.find(
        u8,
        plain,
        "basic_auth_users:\n  ops: '$2b$10$abc/def'\n",
    ) != null);
    try testing.expect(std.mem.find(u8, plain, "tls_server_config") == null);
    const tls = try web(a, .{ .targets = &.{}, .admin = "ops", .tls = true }, "h");
    try testing.expect(std.mem.find(
        u8,
        tls,
        "  cert_file: /run/svc/prometheus/tls-cert\n",
    ) != null);
}

test "scrape: itself with its user, then the targets" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const cfg = try scrape(arena.allocator(), .{
        .targets = &.{ .{ .host = "10.0.0.5", .port = 9100 }, .{ .host = "db", .port = 9187 } },
        .admin = "ops",
    });
    for ([_][]const u8{
        "  - job_name: prometheus\n    scheme: http\n    basic_auth:\n      username: ops\n",
        "      password_file: /run/svc/prometheus/admin-password\n",
        "      - targets: ['127.0.0.1:9090']\n",
        "          - '10.0.0.5:9100'\n          - 'db:9187'\n",
    }) |want| try testing.expect(std.mem.find(u8, cfg, want) != null);
    for ([_][]const u8{ "insecure_skip_verify", "remote_write", "rule_files", "alerting" }) |absent|
        try testing.expect(std.mem.find(u8, cfg, absent) == null);
}

test "name takes plain user names" {
    try testing.expect(name("ops"));
    try testing.expect(name("grafana-reader"));
    for ([_][]const u8{
        "",
        "Ops",
        "-a",
        "a:b",
        "a b",
        "a'b",
    }) |bad| try testing.expect(!name(bad));
}
