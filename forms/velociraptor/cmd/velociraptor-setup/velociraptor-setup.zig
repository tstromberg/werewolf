//! velociraptor-setup writes the server's config the first time, and sets
//! the administrator from the config every time, before the frontend
//! serves. The keys stay in /data. The password is never written into the
//! server config.
//!
//!     velociraptor-setup
//!
//! leash runs it as the velociraptor user (forms/velociraptor/form.yaml).
//! See forms/velociraptor/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const bin = "/usr/bin/velociraptor";
const run_dir = "/run/svc/velociraptor";
const data_dir = "/data/svc/velociraptor";
const password_path = run_dir ++ "/admin-password";
const merge_path = run_dir ++ "/merge.json";
const config_path = data_dir ++ "/server.config.yaml";

pub fn main(init: std.process.Init) void {
    const io = init.io;
    run(io, init.arena.allocator(), init.minimal.environ) catch |err| {
        say(io, "{{\"event\":\"failed\",\"why\":\"{s}\"}}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const domain = environ.getAlloc(gpa, "DOMAIN") catch return error.NoDomain;
    if (!hostname(domain)) return error.DomainRefused;
    const text = Dir.cwd().readFileAlloc(io, password_path, gpa, .limited(4 << 10)) catch |err|
        switch (err) {
            error.FileNotFound => return error.NoAdminPassword,
            else => return err,
        };
    const password = std.mem.trimEnd(u8, text, "\r\n");
    if (!acceptable(password)) return error.AdminPasswordRefused;
    // The password is in memory for user add. The copy on /run does not
    // stay, and the server config never holds it.
    defer Dir.cwd().deleteFile(io, password_path) catch {};

    if (Dir.cwd().access(io, config_path, .{})) |_| {
        say(io, "{{\"event\":\"config kept\"}}", .{});
    } else |_| {
        try writeFile(io, merge_path, try merge(gpa, domain));
        const generated = try capture(io, gpa, &.{
            bin,            "--nobanner",
            "--tempdir",    run_dir,
            "config",       "generate",
            "--merge_file", merge_path,
        });
        if (!std.mem.startsWith(u8, std.mem.trimStart(u8, generated, " \t\r\n"), "version:"))
            return error.ConfigNotGenerated;
        try writeFile(io, config_path, generated);
        say(io, "{{\"event\":\"config generated\",\"domain\":\"{s}\"}}", .{domain});
    }

    // user add changes the password when the user already exists, so the
    // config file is the password, including after a reboot.
    try runOk(io, &.{
        bin,         "--nobanner",
        "--tempdir", run_dir,
        "--config",  config_path,
        "user",      "add",
        "--role",    "administrator",
        "admin",     password,
    });
    say(io, "{{\"event\":\"admin set\"}}", .{});
}

/// merge is the JSON merge patch config generate applies. It names this
/// machine and puts the datastore on /data. It holds no keys and no
/// password: generate makes the keys, and user add sets the password.
fn merge(gpa: Allocator, domain: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(gpa, .{
        .Client = .{ .server_urls = .{try gpa.print("https://{s}:8000/", .{domain})} },
        .API = .{ .bind_address = "127.0.0.1", .bind_port = 8001 },
        .GUI = .{
            .bind_address = "127.0.0.1",
            .bind_port = 8889,
            .public_url = try gpa.print("https://{s}/", .{domain}),
        },
        .Frontend = .{
            .hostname = domain,
            .bind_address = "0.0.0.0",
            .bind_port = 8000,
            .resources = .{ .expected_clients = 200 },
        },
        .Datastore = .{
            .location = data_dir ++ "/datastore",
            .filestore_directory = data_dir ++ "/filestore",
        },
        .Logging = .{ .debug = .{ .disabled = true } },
        .Monitoring = .{ .bind_address = "127.0.0.1", .bind_port = 8003 },
    }, .{});
}

fn capture(io: Io, gpa: Allocator, argv: []const []const u8) ![]const u8 {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    var buf: [4096]u8 = undefined;
    var rd = child.stdout.?.readerStreaming(io, &buf);
    const out = try rd.interface.allocRemaining(gpa, .limited(1 << 20));
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) return error.CommandFailed;
    return out;
}

fn writeFile(io: Io, path: []const u8, data: []const u8) !void {
    var f = try Dir.cwd().createFile(io, path, .{ .permissions = .fromMode(0o600) });
    defer f.close(io);
    try f.writeStreamingAll(io, data);
}

fn runOk(io: Io, argv: []const []const u8) !void {
    var child = try std.process.spawn(io, .{ .argv = argv, .stdin = .ignore });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) return error.CommandFailed;
}

fn hostname(s: []const u8) bool {
    if (s.len < 1 or s.len > 253) return false;
    for (s) |c| if (!((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or c == '.' or c == '-')) return false;
    return true;
}

fn acceptable(s: []const u8) bool {
    if (s.len < 12 or s.len > 128 or s[0] == '-') return false;
    for (s) |c| if (c < 0x20 or c == 0x7f) return false;
    return true;
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "velociraptor-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "merge names the machine and keeps the password out" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const text = try merge(arena.allocator(), "vr.example");
    try testing.expect(std.mem.indexOf(u8, text, "https://vr.example:8000/") != null);
    try testing.expect(std.mem.indexOf(u8, text, "https://vr.example/") != null);
    try testing.expect(std.mem.indexOf(u8, text, "/data/svc/velociraptor/datastore") != null);
    try testing.expect(std.mem.indexOf(u8, text, "password") == null);
    try testing.expect(std.mem.indexOf(u8, text, "PRIVATE") == null);
}

test "a password is long and not a flag" {
    try testing.expect(acceptable("werewolf-check-pass-1"));
    try testing.expect(!acceptable("short"));
    try testing.expect(!acceptable("-werewolf-check-pass"));
    try testing.expect(hostname("vr.example"));
    try testing.expect(!hostname("vr example"));
    try testing.expect(!hostname(""));
}
