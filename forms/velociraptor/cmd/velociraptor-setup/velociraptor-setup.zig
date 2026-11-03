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
const password_name = "admin-password";
const merge_name = "merge.json";
const config_name = "server.config.yaml";
const password_path = run_dir ++ "/" ++ password_name;
const merge_path = run_dir ++ "/" ++ merge_name;
const config_path = data_dir ++ "/" ++ config_name;

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
    var rdir = try Dir.cwd().openDir(io, run_dir, .{ .follow_symlinks = false });
    defer rdir.close(io);
    defer scrubFile(io, rdir, password_name);
    defer scrubFile(io, rdir, merge_name);

    const text = Dir.cwd().readFileAlloc(io, password_path, gpa, .limited(4 << 10)) catch |err|
        switch (err) {
            error.FileNotFound => return error.NoAdminPassword,
            else => return err,
        };
    defer std.crypto.secureZero(u8, text);
    const password = std.mem.trimEnd(u8, text, "\r\n");
    if (!acceptable(password)) return error.AdminPasswordRefused;

    var ddir = try Dir.cwd().openDir(io, data_dir, .{ .follow_symlinks = false });
    defer ddir.close(io);
    if (try regularConfigExists(io, ddir, config_name)) {
        say(io, "{{\"event\":\"config kept\"}}", .{});
    } else {
        try writeAtomic(io, rdir, merge_name, try merge(gpa, domain));
        const generated = try capture(io, gpa, &.{
            bin,            "--nobanner",
            "--tempdir",    run_dir,
            "config",       "generate",
            "--merge_file", merge_path,
        });
        if (!std.mem.startsWith(u8, std.mem.trimStart(u8, generated, " \t\r\n"), "version:"))
            return error.ConfigNotGenerated;
        try writeAtomic(io, ddir, config_name, generated);
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
            .public_url = try gpa.print("https://{s}/app/index.html", .{domain}),
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

fn regularConfigExists(io: Io, dir: Dir, name: []const u8) !bool {
    const st = dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    if (st.kind != .file) return error.UnsafeConfigFile;
    return true;
}

fn writeAtomic(io: Io, dir: Dir, name: []const u8, data: []const u8) !void {
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, ".{s}.tmp", .{name});
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(io, tmp, .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        defer f.close(io);
        try f.writeStreamingAll(io, data);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, name, io);
}

fn scrubFile(io: Io, dir: Dir, sub_path: []const u8) void {
    if (dir.openFile(io, sub_path, .{ .mode = .read_write, .follow_symlinks = false })) |file| {
        defer file.close(io);
        if (file.stat(io)) |st| {
            if (st.kind == .file and st.size > 0) {
                var zeros: [4096]u8 = @splat(0);
                var left: u64 = @min(st.size, 1 << 20);
                while (left > 0) {
                    const chunk: usize = @intCast(@min(left, zeros.len));
                    file.writeStreamingAll(io, zeros[0..chunk]) catch break;
                    left -= chunk;
                }
                file.sync(io) catch {};
            }
        } else |_| {}
    } else |_| {}
    dir.deleteFile(io, sub_path) catch {};
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
    try testing.expect(std.mem.indexOf(u8, text, "https://vr.example/app/index.html") != null);
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

test "writeAtomic and regularConfigExists refuse symlinks without touching targets" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "victim", .data = "untouched" });
    try tmp.dir.symLink(io, "victim", config_name, .{});
    try testing.expectError(error.UnsafeConfigFile, regularConfigExists(io, tmp.dir, config_name));

    try writeAtomic(io, tmp.dir, config_name, "version: {}\n");
    try testing.expect(try regularConfigExists(io, tmp.dir, config_name));
    const victim = try tmp.dir.readFileAlloc(io, "victim", testing.allocator, .limited(64));
    defer testing.allocator.free(victim);
    try testing.expectEqualStrings("untouched", victim);

    try tmp.dir.writeFile(io, .{ .sub_path = password_name, .data = "secret-password\n" });
    scrubFile(io, tmp.dir, password_name);
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, password_name, .{}));
}
