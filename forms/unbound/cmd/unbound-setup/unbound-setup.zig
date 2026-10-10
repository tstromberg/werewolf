//! unbound-setup readies Unbound before each start: it seeds the root's
//! trust anchor from the image on the first start, and writes the include
//! that names the addresses Unbound listens on and the forward zones the
//! machine's settings name.
//!
//!     unbound-setup
//!
//! leash runs it as the unbound user, under the service's Landlock rules
//! (forms/unbound/form.yaml). See README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// image_anchor is the root's keys as the image ships them (dnssec-root).
const image_anchor = "/usr/share/dnssec-root/trusted-key.key";
/// anchor is Unbound's auto-trust-anchor-file, which it rewrites as the
/// root's keys roll (RFC 5011).
const anchor = "/data/svc/unbound/root.key";
const include = "/run/svc/unbound/unbound-setup.conf";
/// inet6 exists while the kernel has IPv6: werewolf boots without it
/// unless the form allows ipv6.
const inet6 = "/proc/net/if_inet6";
/// max_list is service-config's longest list.
const max_list = 32;

const Settings = struct {
    zones: []const []const u8 = &.{},
    servers: []const []const u8 = &.{},
    ipv6: bool = false,
};

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa, init.minimal.environ) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    if (try exists(io, anchor)) {
        say(io, "trust anchor kept: {s}", .{anchor});
    } else {
        const keys = try Dir.cwd().readFileAlloc(io, image_anchor, gpa, .limited(64 << 10));
        try replace(io, anchor, keys, 0o600);
        say(io, "trust anchor seeded from {s} into {s}", .{ image_anchor, anchor });
    }

    const s: Settings = .{
        .zones = try list(gpa, setting(gpa, environ, "UNBOUND_FORWARD_ZONES"), zone),
        .servers = try list(gpa, setting(gpa, environ, "UNBOUND_FORWARD_TO"), address),
        .ipv6 = try exists(io, inet6),
    };
    if ((s.zones.len == 0) != (s.servers.len == 0)) {
        say(io, "forward-zones and forward-to go together: the zones, and the " ++
            "servers that answer for them", .{});
        return error.ForwardIncomplete;
    }
    try replace(io, include, try render(gpa, s), 0o600);

    var names: std.ArrayList(u8) = .empty;
    for (s.zones, 0..) |z, i| try names.print(gpa, "{s}{s}", .{ if (i > 0) ", " else "", z });
    var to: std.ArrayList(u8) = .empty;
    for (s.servers, 0..) |a, i| try to.print(gpa, "{s}{s}", .{ if (i > 0) ", " else "", a });
    say(io, "unbound-setup.conf written: {s} on :53, {s}{s}{s}", .{
        if (s.ipv6) "IPv4 and IPv6" else "IPv4",
        if (s.zones.len == 0) "no forward zones" else names.items,
        if (s.zones.len == 0) "" else " forwarded to ",
        to.items,
    });
}

/// render returns the include for s. A forward zone is also insecure,
/// since a private zone has no chain of trust from the root, and loses
/// any default local zone Unbound serves for it (10.in-addr.arpa).
fn render(gpa: Allocator, s: Settings) ![]const u8 {
    var w: Io.Writer.Allocating = .init(gpa);
    const o = &w.writer;
    try o.writeAll(
        "# Written by unbound-setup at each start, from the machine's settings\n" ++
            "# (forms/unbound/README.md): change those, not this file.\n" ++
            "server:\n\tinterface: 0.0.0.0\n",
    );
    try o.writeAll(if (s.ipv6) "\tinterface: ::0\n\tdo-ip6: yes\n" else "\tdo-ip6: no\n");
    for (s.zones) |z| try o.print(
        "\tdomain-insecure: \"{s}.\"\n\tlocal-zone: \"{s}.\" nodefault\n",
        .{ z, z },
    );
    for (s.zones) |z| {
        try o.print("forward-zone:\n\tname: \"{s}.\"\n", .{z});
        for (s.servers) |a| try o.print("\tforward-addr: {s}\n", .{a});
    }
    return w.written();
}

/// list splits a list service-config rendered, joined by commas, and
/// checks each value with ok.
fn list(gpa: Allocator, value: ?[]const u8, ok: fn ([]const u8) bool) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, value orelse return &.{}, ',');
    while (it.next()) |v| {
        if (!ok(v)) return error.BadForwardSetting;
        if (out.items.len == max_list) return error.TooManyForwardValues;
        try out.append(gpa, v);
    }
    return out.items;
}

/// zone reports whether s is a domain name of letters, digits, dashes and
/// dots, which Unbound's configuration takes quoted as it is.
fn zone(s: []const u8) bool {
    if (s.len == 0 or s.len > 253 or s[0] == '.' or s[s.len - 1] == '.') return false;
    if (std.mem.find(u8, s, "..") != null) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '.') return false;
    return true;
}

/// address reports whether s is a literal IPv4 or IPv6 address, without a
/// zone or port.
fn address(s: []const u8) bool {
    for (s) |c| if (!std.ascii.isHex(c) and c != '.' and c != ':') return false;
    _ = Io.net.IpAddress.parse(s, 0) catch return false;
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
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(p).?, .{});
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

/// say prints one line to the console.
fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "unbound-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "list splits the rendered list and refuses what Unbound could misread" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const z = try list(a, "corp.example,10.in-addr.arpa", zone);
    try testing.expectEqual(2, z.len);
    try testing.expectEqualStrings("10.in-addr.arpa", z[1]);
    try testing.expectEqual(0, (try list(a, null, zone)).len);
    for ([_][]const u8{ "", "a,", "a..b", ".a", "a.", "a b", "a\"b", "a\nb", "a#b" }) |bad|
        try testing.expectError(error.BadForwardSetting, list(a, bad, zone));
    const s = try list(a, "10.0.0.2,fd00::53", address);
    try testing.expectEqualStrings("fd00::53", s[1]);
    for ([_][]const u8{ "10.0.0", "10.0.0.2:53", "fe80::1%eth0", "dns.corp", "10.0.0.2 #" }) |bad|
        try testing.expectError(error.BadForwardSetting, list(a, bad, address));
}

test "render: IPv4 alone, no forward zones" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const conf = try render(arena.allocator(), .{});
    try testing.expect(std.mem.find(u8, conf, "server:\n\tinterface: 0.0.0.0\n\tdo-ip6: no\n") != null);
    for ([_][]const u8{ "::0", "forward-zone", "domain-insecure" }) |absent|
        try testing.expect(std.mem.find(u8, conf, absent) == null);
}

test "render: forward zones, each insecure, to every server" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const conf = try render(arena.allocator(), .{
        .zones = &.{ "corp.example", "10.in-addr.arpa" },
        .servers = &.{ "10.0.0.2", "10.0.0.3" },
        .ipv6 = true,
    });
    for ([_][]const u8{
        "\tinterface: 0.0.0.0\n\tinterface: ::0\n\tdo-ip6: yes\n",
        "\tdomain-insecure: \"corp.example.\"\n\tlocal-zone: \"corp.example.\" nodefault\n",
        "\tlocal-zone: \"10.in-addr.arpa.\" nodefault\n",
        "forward-zone:\n\tname: \"corp.example.\"\n\tforward-addr: 10.0.0.2\n\tforward-addr: 10.0.0.3\n",
        "forward-zone:\n\tname: \"10.in-addr.arpa.\"\n\tforward-addr: 10.0.0.2\n",
    }) |want| try testing.expect(std.mem.find(u8, conf, want) != null);
}
