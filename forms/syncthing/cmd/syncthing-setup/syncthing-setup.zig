//! syncthing-setup holds Syncthing's config to the form before each
//! start: it makes the device key and config once, with Syncthing's own
//! generate, and then sets the options werewolf decides, leaving the rest
//! (devices, folders, the GUI's choices) as Syncthing keeps them.
//!
//!     syncthing-setup
//!
//! leash runs it in Syncthing's image, as _oci-syncthing, with
//! SYNCTHING_RELAYS and SYNCTHING_DISCOVERY from the machine's settings
//! (forms/syncthing/form.yaml). See forms/syncthing/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const syncthing = "/bin/syncthing";
const home = "/var/syncthing/config";
const config = home ++ "/config.xml";
const relay_pool = "dynamic+https://relays.syncthing.net/endpoint";
const max_config = 16 << 20;

/// Option is one element of <options> the form sets, whatever it held.
const Option = struct { name: []const u8, value: []const u8 };

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa, init.minimal.environ) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const relays = flag(gpa, environ, "SYNCTHING_RELAYS");
    const discovery = flag(gpa, environ, "SYNCTHING_DISCOVERY");
    if (!exists(io, config) or !exists(io, home ++ "/cert.pem")) {
        const r = try std.process.run(gpa, io, .{
            .argv = &.{ syncthing, "--home=" ++ home, "generate", "--no-port-probing" },
            .stdout_limit = .limited(64 << 10),
            .stderr_limit = .limited(64 << 10),
        });
        if (r.term != .exited or r.term.exited != 0) {
            say(io, "syncthing generate failed: {s}", .{std.mem.trim(u8, r.stderr, " \n")});
            return error.GenerateFailed;
        }
        say(io, "made the device key and config in {s}", .{home});
    }
    const text = try Dir.cwd().readFileAlloc(io, config, gpa, .limited(max_config));
    const options = [_]Option{
        // UDP to the LAN, which fence neither sends nor delivers.
        .{ .name = "localAnnounceEnabled", .value = "false" },
        // UPnP and NAT-PMP would open the router's ports to the machine.
        .{ .name = "natEnabled", .value = "false" },
        // Declined, so the GUI never asks; nothing is reported.
        .{ .name = "urAccepted", .value = "-1" },
        .{ .name = "crashReportingEnabled", .value = "false" },
        .{ .name = "autoUpgradeIntervalH", .value = "0" },
        .{ .name = "startBrowser", .value = "false" },
        .{ .name = "relaysEnabled", .value = if (relays) "true" else "false" },
        .{ .name = "globalAnnounceEnabled", .value = if (discovery) "true" else "false" },
    };
    const listen: []const []const u8 = if (relays)
        &.{ "tcp://0.0.0.0:22000", "quic://0.0.0.0:22000", relay_pool }
    else
        &.{ "tcp://0.0.0.0:22000", "quic://0.0.0.0:22000" };
    const out = try edit(gpa, text, &options, listen);
    if (std.mem.eql(u8, out, text)) return;
    try replace(io, config, out);
    say(io, "set its options: relays {s}, global discovery {s}", .{
        if (relays) "on" else "off",
        if (discovery) "on" else "off",
    });
}

/// edit returns config.xml text with each option's element set to its
/// value and the listen addresses replaced by listen. Syncthing writes one
/// element a line; an option it left out is added before </options>.
fn edit(
    gpa: Allocator,
    text: []const u8,
    options: []const Option,
    listen: []const []const u8,
) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var seen = try gpa.alloc(bool, options.len);
    @memset(seen, false);
    var in_options = false;
    var found = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var first = true;
    while (lines.next()) |line| {
        const t = std.mem.trim(u8, line, " \t\r");
        const indent = line[0 .. std.mem.findNonePos(u8, line, 0, " \t") orelse line.len];
        if (!first) try out.append(gpa, '\n');
        first = false;
        if (std.mem.eql(u8, t, "<options>")) {
            in_options = true;
            found = true;
            try out.appendSlice(gpa, line);
            for (listen) |a| try out.print(gpa, "\n{s}    <listenAddress>{s}</listenAddress>", .{ indent, a });
            continue;
        }
        if (in_options and std.mem.eql(u8, t, "</options>")) {
            for (options, seen) |o, s| if (!s)
                try out.print(gpa, "{s}    <{s}>{s}</{s}>\n", .{ indent, o.name, o.value, o.name });
            in_options = false;
            try out.appendSlice(gpa, line);
            continue;
        }
        if (in_options and std.mem.startsWith(u8, t, "<listenAddress>")) {
            // Dropped; ours were written after <options>. Undo its newline.
            out.items.len -= 1;
            continue;
        }
        if (in_options) if (option(options, t)) |i| {
            seen[i] = true;
            try out.print(gpa, "{s}<{s}>{s}</{s}>", .{
                indent,
                options[i].name,
                options[i].value,
                options[i].name,
            });
            continue;
        };
        try out.appendSlice(gpa, line);
    }
    if (!found) return error.NoOptionsInConfig;
    return out.items;
}

/// option returns the index of the option whose element line t is.
fn option(options: []const Option, t: []const u8) ?usize {
    for (options, 0..) |o, i| {
        if (t.len > o.name.len + 1 and t[0] == '<' and
            std.mem.startsWith(u8, t[1..], o.name) and
            (t[1 + o.name.len] == '>' or t[1 + o.name.len] == '/')) return i;
    }
    return null;
}

/// flag reads a bool setting; absent, it is true, as Syncthing ships it.
fn flag(gpa: Allocator, environ: std.process.Environ, key: []const u8) bool {
    const v = environ.getAlloc(gpa, key) catch return true;
    return !std.mem.eql(u8, v, "false");
}

fn exists(io: Io, p: []const u8) bool {
    Dir.cwd().access(io, p, .{}) catch return false;
    return true;
}

/// replace writes p whole or not at all: a temporary file, synced, then
/// renamed over it.
fn replace(io: Io, p: []const u8, data: []const u8) !void {
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(p).?, .{ .iterate = true });
    defer dir.close(io);
    const base = std.fs.path.basename(p);
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, ".{s}.tmp", .{base});
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(io, tmp, .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer f.close(io);
        try f.writeStreamingAll(io, data);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, base, io);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "syncthing-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "edit sets options and listen addresses, and keeps the rest" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const in =
        \\<configuration version="52">
        \\    <device id="X" name="m"></device>
        \\    <options>
        \\        <listenAddress>default</listenAddress>
        \\        <globalAnnounceEnabled>true</globalAnnounceEnabled>
        \\        <localAnnounceEnabled>true</localAnnounceEnabled>
        \\        <natEnabled>true</natEnabled>
        \\        <natLeaseMinutes>60</natLeaseMinutes>
        \\    </options>
        \\</configuration>
        \\
    ;
    const want =
        \\<configuration version="52">
        \\    <device id="X" name="m"></device>
        \\    <options>
        \\        <listenAddress>tcp://0.0.0.0:22000</listenAddress>
        \\        <globalAnnounceEnabled>false</globalAnnounceEnabled>
        \\        <localAnnounceEnabled>false</localAnnounceEnabled>
        \\        <natEnabled>false</natEnabled>
        \\        <natLeaseMinutes>60</natLeaseMinutes>
        \\        <urAccepted>-1</urAccepted>
        \\    </options>
        \\</configuration>
        \\
    ;
    const got = try edit(arena.allocator(), in, &.{
        .{ .name = "localAnnounceEnabled", .value = "false" },
        .{ .name = "natEnabled", .value = "false" },
        .{ .name = "globalAnnounceEnabled", .value = "false" },
        .{ .name = "urAccepted", .value = "-1" },
    }, &.{"tcp://0.0.0.0:22000"});
    try testing.expectEqualStrings(want, got);
    // A second pass changes nothing.
    try testing.expectEqualStrings(want, try edit(arena.allocator(), got, &.{
        .{ .name = "localAnnounceEnabled", .value = "false" },
        .{ .name = "natEnabled", .value = "false" },
        .{ .name = "globalAnnounceEnabled", .value = "false" },
        .{ .name = "urAccepted", .value = "-1" },
    }, &.{"tcp://0.0.0.0:22000"}));
}

test "option matches the element, not a longer name" {
    const opts = [_]Option{.{ .name = "natEnabled", .value = "false" }};
    try testing.expectEqual(@as(?usize, 0), option(&opts, "<natEnabled>true</natEnabled>"));
    try testing.expectEqual(@as(?usize, null), option(&opts, "<natEnabledX>1</natEnabledX>"));
    try testing.expectEqual(@as(?usize, null), option(&opts, "<natLeaseMinutes>60</natLeaseMinutes>"));
}

test "edit refuses a config without options" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.NoOptionsInConfig, edit(arena.allocator(), "<configuration/>\n", &.{}, &.{}));
}
