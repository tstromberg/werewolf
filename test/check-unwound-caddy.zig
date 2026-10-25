//! check-unwound-caddy runs Caddy's staging-ACME lookup through a form's
//! composed DNS policy, in check-unwound's private world, as root: Caddy's
//! questions must reach unwound as its screened user, and none be refused.
//! The fixture resolver answers; nothing reaches the public ACME service.
//!
//!     check-unwound-caddy FENCE UNWOUND POLICY DOMAIN
//!
//! /usr/bin/caddy must be installed.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const lab = @import("unwound/lab.zig");
const linux = std.os.linux;
const mem = std.mem;
const netns = host.netns;
const fixture = lab.fixture;

pub fn main(init: std.process.Init) !void {
    const l = lab.Lab.init(init, "check-unwound-caddy");
    const args = try init.minimal.args.toSlice(l.gpa);
    if (try lab.role(l, args)) return;
    if (args.len == 7 and
        mem.eql(
            u8,
            args[1],
            "--inside",
        )) return inside(l, args[2], args[3], args[4], args[5], args[6]);
    if (args.len != 5) {
        l.log("usage", .{ .usage = "check-unwound-caddy FENCE UNWOUND POLICY DOMAIN" });
        std.process.exit(2);
    }
    if (builtin.os.tag != .linux or linux.geteuid() != 0) return l.fail("needs_linux_root", .{});
    var inner: std.ArrayList([]const u8) = .empty;
    try inner.appendSlice(l.gpa, &.{ "--inside", try l.namespace("net") });
    for (args[1..4]) |path| try inner.append(
        l.gpa,
        try std.Io.Dir.cwd().realPathFileAlloc(l.io, path, l.gpa),
    );
    try inner.append(l.gpa, args[4]);
    try l.enter(&.{ "--net", "--mount" }, inner.items);
}

fn inside(
    l: lab.Lab,
    parent_net: []const u8,
    fence: []const u8,
    unwound: []const u8,
    policy_path: []const u8,
    domain: []const u8,
) !void {
    if (mem.eql(u8, try l.namespace("net"), parent_net)) return l.fail("shared_network", .{});
    const policy = try l.read(policy_path);
    // Caddy runs as the screened A/AAAA user the form's policy grants.
    const uid = screened: {
        var lines = mem.tokenizeScalar(u8, policy, '\n');
        while (lines.next()) |line| {
            var words = mem.tokenizeScalar(u8, line, ' ');
            if (!mem.eql(u8, words.next() orelse "", "lookup")) continue;
            const user = words.next() orelse continue;
            if (!mem.eql(u8, words.rest(), "* A AAAA")) continue;
            break :screened std.fmt.parseInt(u32, user, 10) catch continue;
        }
        return l.fail("no_screened_grant", .{ .why = "Caddy needs a screened A/AAAA grant" });
    };
    try l.private();
    var w = try lab.World.init(l, "werewolf-caddy");
    defer w.stop();
    try w.mount(unwound, policy, .{});
    try w.network(&.{fixture.upstream ++ "/24"});
    errdefer w.failed();
    _ = try w.start(fence);

    const config = try w.path("Caddyfile");
    try l.write(config, try l.gpa.print(
        \\{{
        \\    admin off
        \\    auto_https disable_redirects
        \\    acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
        \\}}
        \\{s}:8443 {{
        \\    respond "dns pilot"
        \\}}
        \\
    , .{domain}));
    const data = try w.path("caddy-data");
    try l.mkdir(data, 0o777);
    const caddy_log = try w.path("caddy.log");
    const fd = try l.create(caddy_log);
    var caddy = try l.spawn(&.{
        "/usr/bin/caddy",
        "run",
        "--config",
        config,
        "--adapter",
        "caddyfile",
    }, .{
        .uid = uid,
        .stdout = .{ .fd = fd },
        .stderr = .{ .fd = fd },
        .env = try l.environWith(&.{
            try l.gpa.print("HOME={s}", .{data}),
            try l.gpa.print("XDG_DATA_HOME={s}", .{data}),
            try l.gpa.print("XDG_CONFIG_HOME={s}", .{data}),
        }),
    });
    netns.close(fd);
    defer caddy.stop();
    const deadline = netns.now() + 25_000;
    const asked = try l.gpa.print("\"uid\":{d}", .{uid});
    while (true) : (netns.nap(200)) {
        var lines = mem.tokenizeScalar(u8, try l.read(try w.path("audit")), '\n');
        const found = while (lines.next()) |line| {
            if (mem.find(u8, line, asked) != null and
                mem.find(u8, line, "\"event\":\"query\"") != null) break true;
        } else false;
        if (found) {
            netns.nap(2000);
            break;
        }
        if (try caddy.wait(0) != null) return l.fail(
            "caddy_exited",
            .{ .log = try l.read(caddy_log) },
        );
        if (netns.now() >= deadline) return l.fail(
            "caddy_asked_nothing",
            .{ .log = try l.read(caddy_log) },
        );
    }
    caddy.stop();

    var a = false;
    var aaaa = false;
    var names: std.ArrayList([]const u8) = .empty;
    for (try lab.queries(l.gpa, try lab.audit(&w))) |q| {
        const user = lab.field(q, "uid") orelse continue;
        if (user != .integer or user.integer != uid) continue;
        if (lab.field(q, "decision")) |d| if (d == .string and mem.eql(u8, d.string, "deny"))
            return l.fail("caddy_refused", .{ .query = q });
        const kind = lab.field(q, "type") orelse continue;
        if (kind != .string) continue;
        a = a or mem.eql(u8, kind.string, "A");
        aaaa = aaaa or mem.eql(u8, kind.string, "AAAA");
        const name = lab.field(q, "name") orelse continue;
        if (name != .string) continue;
        for (names.items) |n| {
            if (mem.eql(u8, n, name.string)) break;
        } else try names.append(l.gpa, name.string);
    }
    if (names.items.len == 0) return l.fail("caddy_unaudited", .{});
    if (!a or !aaaa) return l.fail("caddy_types", .{ .a = a, .aaaa = aaaa });
    l.log("pass", .{ .uid = uid, .allowed = names.items });
}
