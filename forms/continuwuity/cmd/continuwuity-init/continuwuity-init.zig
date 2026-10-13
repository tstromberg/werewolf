//! continuwuity-init writes Continuwuity's configuration before each
//! start, and on the first start names the administrator to create.
//! Registration stays closed. The server name cannot change later.
//!
//! leash runs it as the continuwuity user, with SERVER_NAME and ADMIN
//! set. The password is /run/svc/continuwuity/admin-password.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const data_dir = "/data/svc/continuwuity";
const run_dir = "/run/svc/continuwuity";
const config_name = "continuwuity.toml";
const password_file = run_dir ++ "/admin-password";
const db_mark = "CURRENT";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa, init.minimal.environ) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const domain = setting(gpa, environ, "SERVER_NAME") orelse return error.NoDomain;
    const admin = setting(gpa, environ, "ADMIN") orelse return error.NoAdmin;
    if (!nameOk(domain) or !nameOk(admin)) {
        say(io, "the server name and the admin are one word, with no quotes", .{});
        return error.BadName;
    }
    const password = try passwordOf(io, gpa);
    if (!passwordOk(password)) {
        say(io, "the admin password is 8 to 256 characters, with no space or quote", .{});
        return error.BadPassword;
    }
    Dir.cwd().createDirPath(io, data_dir) catch |err| {
        say(io, "{s}: {s}", .{ data_dir, @errorName(err) });
        return err;
    };
    const create = !dbExists(io);
    const text = try configText(gpa, domain, admin, password, create);
    defer gpa.free(text);
    var dir = try Dir.cwd().openDir(io, run_dir, .{});
    defer dir.close(io);
    const tmp = ".continuwuity.toml.tmp";
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(io, tmp, .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        defer f.close(io);
        try f.writeStreamingAll(io, text);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, config_name, io);
    if (create)
        say(io, "creating admin {s}", .{admin})
    else
        say(io, "keeping the database", .{});
}

fn dbExists(io: Io) bool {
    var dir = Dir.cwd().openDir(io, data_dir, .{}) catch return false;
    defer dir.close(io);
    dir.access(io, db_mark, .{}) catch return false;
    return true;
}

fn passwordOf(io: Io, gpa: Allocator) ![]u8 {
    const raw = Dir.cwd().readFileAlloc(io, password_file, gpa, .limited(4096)) catch |err| {
        say(io, "{s}: {s}", .{ password_file, @errorName(err) });
        return err;
    };
    const n = if (raw.len > 0 and raw[raw.len - 1] == '\n') raw.len - 1 else raw.len;
    return raw[0..n];
}

fn setting(gpa: Allocator, environ: std.process.Environ, key: []const u8) ?[]const u8 {
    const v = environ.getAlloc(gpa, key) catch return null;
    return if (v.len > 0) v else null;
}

fn nameOk(name: []const u8) bool {
    if (name.len == 0 or name.len > 253) return false;
    for (name) |c| if (c <= 0x20 or c >= 0x7f or c == '"' or c == '\'' or c == '\\') return false;
    return true;
}

fn passwordOk(password: []const u8) bool {
    if (password.len < 8 or password.len > 256) return false;
    for (password) |c| if (c <= 0x20 or c >= 0x7f or c == '"' or c == '\'' or c == '\\' or
        c == '#') return false;
    return true;
}

/// configText is continuwuity.toml. The administrator is created once,
/// while RocksDB has not been opened. Registration stays closed.
fn configText(
    gpa: Allocator,
    domain: []const u8,
    admin: []const u8,
    password: []const u8,
    create: bool,
) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    try buf.print(gpa,
        \\[global]
        \\server_name = "{s}"
        \\address = ["127.0.0.1"]
        \\port = 8008
        \\database_path = "{s}"
        \\allow_registration = false
        \\allow_federation = true
        \\allow_public_room_directory_over_federation = false
        \\lockdown_public_room_directory = true
        \\allow_device_name_federation = false
        \\require_auth_for_profile_requests = true
        \\allow_inbound_profile_lookup_federation_requests = false
        \\proxy = "none"
        \\max_request_size = 20971520
        \\allow_web_indexing = false
        \\admin_console_automatic = false
        \\accepted_ip_sources = ["x_forwarded_for"]
        \\sentry = false
        \\url_preview_domain_contains_allowlist = []
        \\url_preview_domain_explicit_allowlist = []
        \\url_preview_url_contains_allowlist = []
        \\
    , .{ domain, data_dir });
    if (create) {
        try buf.print(
            gpa,
            "admin_execute = [\"users create_user {s} {s}\"]\n",
            .{ admin, password },
        );
    }
    try buf.print(gpa,
        \\
        \\[global.well_known]
        \\client = "https://{s}"
        \\server = "{s}:443"
        \\
    , .{ domain, domain });
    return buf.toOwnedSlice(gpa);
}

test "the first start names the admin and a later one does not" {
    const gpa = std.testing.allocator;
    const first = try configText(
        gpa,
        "matrix.example.com",
        "alice",
        "werewolf-check-password",
        true,
    );
    defer gpa.free(first);
    try std.testing.expect(std.mem.indexOf(
        u8,
        first,
        "server_name = \"matrix.example.com\"\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, first, "allow_registration = false\n") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        first,
        "admin_execute = [\"users create_user alice werewolf-check-password\"]\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        first,
        "client = \"https://matrix.example.com\"\n",
    ) != null);
    const again = try configText(
        gpa,
        "matrix.example.com",
        "alice",
        "werewolf-check-password",
        false,
    );
    defer gpa.free(again);
    try std.testing.expect(std.mem.indexOf(u8, again, "admin_execute") == null);
    try std.testing.expect(!passwordOk("short"));
    try std.testing.expect(!passwordOk("has a space"));
    try std.testing.expect(passwordOk("werewolf-check-password"));
    try std.testing.expect(!nameOk("bad name"));
    try std.testing.expect(nameOk("matrix.example.com"));
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "continuwuity-init: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
