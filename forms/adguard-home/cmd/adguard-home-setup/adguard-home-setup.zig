//! adguard-home-setup readies AdGuard Home's configuration before each
//! start: on the first, it copies the form's to /data, so the setup wizard
//! never runs; at every start, the machine's settings, where given, replace
//! its upstreams and blocklists. The rest is the web UI's to change.
//!
//!     adguard-home-setup
//!
//! leash runs it inside AdGuard Home's image, as its user
//! (forms/adguard-home/form.yaml). See forms/adguard-home/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// first is the form's configuration, in the image.
const first = "/opt/adguardhome/werewolf.yaml";
/// conf is AdGuard Home's, which it rewrites.
const conf = "/data/AdGuardHome.yaml";
/// settings is service-config's rendering of the machine's settings.
const settings = "/tmp/adguard.json";
const max_file = 4 << 20;

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator) !void {
    var fresh = false;
    var text: []const u8 = Dir.cwd().readFileAlloc(
        io,
        conf,
        gpa,
        .limited(max_file),
    ) catch |err| switch (err) {
        error.FileNotFound => blk: {
            fresh = true;
            break :blk try Dir.cwd().readFileAlloc(io, first, gpa, .limited(max_file));
        },
        else => return err,
    };
    const given = Dir.cwd().readFileAlloc(io, settings, gpa, .limited(64 << 10)) catch |err|
        switch (err) {
            error.FileNotFound => "{}",
            else => return err,
        };
    const s = try std.json.parseFromSliceLeaky(
        Settings,
        gpa,
        given,
        .{ .ignore_unknown_fields = true },
    );
    if (s.upstreams) |u| text = try replace(
        gpa,
        text,
        "dns",
        "upstream_dns",
        try upstreams(gpa, u),
    );
    if (s.blocklists) |b| text = try replace(gpa, text, null, "filters", try filters(gpa, b));
    if (!fresh and s.upstreams == null and s.blocklists == null) {
        say(io, "configuration as AdGuard Home left it", .{});
        return;
    }
    try write(io, conf, text);
    say(io, "{s}{s}{s}", .{
        if (fresh) "first start: configuration copied to /data" else "configuration kept",
        if (s.upstreams) |u| try gpa.print("; {d} upstreams from settings", .{u.len}) else "",
        if (s.blocklists) |b| try gpa.print("; {d} blocklists from settings", .{b.len}) else "",
    });
}

const Settings = struct {
    upstreams: ?[]const []const u8 = null,
    blocklists: ?[]const []const u8 = null,
};

/// upstreams returns dns.upstream_dns as AdGuard Home writes it.
fn upstreams(gpa: Allocator, list: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "  upstream_dns:\n");
    for (list) |u| try out.print(gpa, "    - {f}\n", .{std.json.fmt(u, .{})});
    return out.items;
}

/// filters returns the filters list for the blocklists. Each id is a hash
/// of its URL, so a list keeps the cache AdGuard Home names by id.
fn filters(gpa: Allocator, list: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "filters:\n");
    for (list) |url| try out.print(gpa,
        \\  - enabled: true
        \\    url: {f}
        \\    name: {f}
        \\    id: {d}
        \\
    , .{
        std.json.fmt(url, .{}),
        std.json.fmt(url, .{}),
        1 + @as(u64, std.hash.Fnv1a_32.hash(url)),
    });
    return out.items;
}

/// replace returns text with key's block replaced by block: a top-level
/// key, or one directly in parent's map. A block is its line and the lines
/// beneath it, indented further, or as far for a list's items. AdGuard
/// Home writes every key it knows, so one missing is an error, not a guess.
fn replace(
    gpa: Allocator,
    text: []const u8,
    parent: ?[]const u8,
    key: []const u8,
    block: []const u8,
) ![]const u8 {
    const indent: usize = if (parent == null) 0 else 2;
    var start: ?usize = null;
    var end: usize = 0;
    var in_parent = parent == null;
    var at: usize = 0;
    while (at < text.len) {
        const nl = std.mem.findScalarPos(u8, text, at, '\n') orelse text.len;
        const line = text[at..nl];
        const next = @min(nl + 1, text.len);
        defer at = next;
        const lead = line.len - std.mem.trimStart(u8, line, " ").len;
        if (start) |_| {
            const body = line.len > 0 and (lead > indent or
                (lead == indent and std.mem.startsWith(u8, line[lead..], "- ")));
            if (!body) break;
            end = next;
            continue;
        }
        if (parent) |p| if (lead == 0 and line.len > 0) {
            in_parent = std.mem.startsWith(u8, line, p) and std.mem.eql(u8, line[p.len..], ":");
            continue;
        };
        if (in_parent and lead == indent and isKey(line[lead..], key)) {
            start = at;
            end = next;
        }
    }
    const s = start orelse return error.KeyNotInConfiguration;
    return std.mem.concat(gpa, u8, &.{ text[0..s], block, text[end..] });
}

/// isKey reports whether line, unindented, starts key's mapping entry.
fn isKey(line: []const u8, key: []const u8) bool {
    return std.mem.startsWith(u8, line, key) and line.len > key.len and line[key.len] == ':' and
        (line.len == key.len + 1 or line[key.len + 1] == ' ');
}

/// write writes p whole or not at all: a temporary file, synced, then
/// renamed over it.
fn write(io: Io, p: []const u8, data: []const u8) !void {
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(p).?, .{});
    defer dir.close(io);
    const base = std.fs.path.basename(p);
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, ".{s}.tmp", .{base});
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
    try Dir.rename(dir, tmp, dir, base, io);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "adguard-home-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "replace swaps a nested list and a top-level one, and nothing else" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const conf_text =
        \\http:
        \\  address: 127.0.0.1:3000
        \\dns:
        \\  port: 53
        \\  upstream_dns:
        \\    - tls://old.example
        \\  upstream_mode: load_balance
        \\filters:
        \\  - enabled: true
        \\    url: https://old.example/list
        \\    id: 1
        \\whitelist_filters: []
        \\schema_version: 34
        \\
    ;
    var t = try replace(
        a,
        conf_text,
        "dns",
        "upstream_dns",
        try upstreams(a, &.{"tls://new.example"}),
    );
    t = try replace(a, t, null, "filters", try filters(a, &.{"https://new.example/list"}));
    try testing.expect(std.mem.indexOf(u8, t, "old.example") == null);
    try testing.expect(std.mem.indexOf(
        u8,
        t,
        "    - \"tls://new.example\"\n  upstream_mode:",
    ) != null);
    try testing.expect(std.mem.indexOf(u8, t, "    url: \"https://new.example/list\"\n") != null);
    try testing.expect(std.mem.endsWith(u8, t, "whitelist_filters: []\nschema_version: 34\n"));
    try testing.expect(std.mem.startsWith(
        u8,
        t,
        "http:\n  address: 127.0.0.1:3000\ndns:\n  port: 53\n",
    ));
}

test "replace takes an empty list written inline, and refuses a missing key" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t = try replace(
        a,
        "dns:\n  upstream_dns: []\n  port: 53\n",
        "dns",
        "upstream_dns",
        "  upstream_dns:\n    - x\n",
    );
    try testing.expectEqualStrings("dns:\n  upstream_dns:\n    - x\n  port: 53\n", t);
    try testing.expectError(
        error.KeyNotInConfiguration,
        replace(a, "dns:\n  port: 53\n", "dns", "upstream_dns", ""),
    );
    // A key of the same name in another map is not the one.
    try testing.expectError(
        error.KeyNotInConfiguration,
        replace(a, "tls:\n  upstream_dns: []\n", "dns", "upstream_dns", ""),
    );
}
