//! squid-setup writes the two lists Squid's configuration reads before
//! each start, from the machine's settings: the client networks, and the
//! destination domains, one to a line.
//!
//!     squid-setup
//!
//! leash runs it as the squid user, under the service's Landlock rules
//! (forms/squid/form.yaml). See README.md.

const std = @import("std");
const settings = @import("settings");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const run_dir = "/run/svc/squid";
/// site is what service-config rendered from settings.json.
const site = run_dir ++ "/site.json";
const networks_file = run_dir ++ "/networks";
const domains_file = run_dir ++ "/domains";

const Site = struct {
    networks: []const []const u8 = &.{},
    domains: []const []const u8 = &.{},
};

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator) !void {
    const text = try Dir.cwd().readFileAlloc(io, site, gpa, .limited(64 << 10));
    const s = try std.json.parseFromSliceLeaky(Site, gpa, text, .{});
    if (s.networks.len == 0) return error.NoNetworks;
    if (s.domains.len == 0) return error.NoDomains;
    for (s.networks) |n| if (!network(n)) return error.BadNetwork;
    for (s.domains) |d| if (domain(d)) |why| {
        say(io, "domain {s}: {s}", .{ d, why });
        return error.BadDomain;
    };
    try replace(io, networks_file, try lines(gpa, s.networks));
    try replace(io, domains_file, try lines(gpa, s.domains));
    say(io, "clients from {s}", .{try joined(gpa, s.networks)});
    say(io, "CONNECT to port 443 of {s}", .{try joined(gpa, s.domains)});
}

/// network reports whether n holds only a CIDR's characters, as
/// service-config already checked it, so nothing else reaches Squid.
fn network(n: []const u8) bool {
    if (n.len == 0 or n.len > 43) return false;
    for (n) |c| switch (c) {
        '0'...'9', 'a'...'f', 'A'...'F', '.', ':', '/' => {},
        else => return false,
    };
    return true;
}

/// domain returns why d is not a name for Squid's dstdomain, or null: a
/// host, or with a leading dot a domain and its subdomains, never a whole
/// top-level domain.
fn domain(d: []const u8) ?[]const u8 {
    const subdomains = d.len > 0 and d[0] == '.';
    const name = if (subdomains) d[1..] else d;
    if (!settings.isHostname(name)) return "not a hostname, or a dot and one";
    if (subdomains and std.mem.findScalar(u8, name, '.') == null)
        return "a whole top-level domain";
    return null;
}

fn lines(gpa: Allocator, items: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (items) |item| {
        try out.appendSlice(gpa, item);
        try out.append(gpa, '\n');
    }
    return out.items;
}

fn joined(gpa: Allocator, items: []const []const u8) ![]const u8 {
    return std.mem.join(gpa, " ", items);
}

/// replace writes p whole or not at all: a temporary file, synced, then
/// renamed over it.
fn replace(io: Io, p: []const u8, data: []const u8) !void {
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(p).?, .{ .iterate = true });
    defer dir.close(io);
    const name = std.fs.path.basename(p);
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, ".{s}.tmp", .{name});
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(
            io,
            tmp,
            .{ .exclusive = true, .permissions = .fromMode(0o600) },
        );
        defer f.close(io);
        try f.writeStreamingAll(io, data);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, name, io);
}

/// say prints one line to the console, control bytes as "?".
fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [16 << 10]u8 = undefined;
    const line = std.mem.print(&buf, "squid-setup: " ++ fmt ++ "\n", args) catch return;
    for (line[0 .. line.len - 1]) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = '?';
    };
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "domain takes hosts and dotted domains, never a whole TLD" {
    for ([_][]const u8{ "pypi.org", ".github.com", "localhost", ".s3.us-east-1.amazonaws.com" }) |d|
        try testing.expectEqual(null, domain(d));
    for ([_][]const u8{
        "",
        ".",
        ".com",
        "..github.com",
        "github.com.",
        "a b.com",
        "*.github.com",
        "a\"b",
        "-x.com",
    }) |d|
        try testing.expect(domain(d) != null);
}

test "network takes a CIDR's characters alone" {
    try testing.expect(network("10.0.0.0/8"));
    try testing.expect(network("fd00::/8"));
    for ([_][]const u8{ "", "10.0.0.0/8 all", "\"/etc/x\"", "10.0.0.0/8\n" }) |n|
        try testing.expect(!network(n));
}

test "lines writes one item to a line" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings(
        ".github.com\npypi.org\n",
        try lines(arena.allocator(), &.{ ".github.com", "pypi.org" }),
    );
}
