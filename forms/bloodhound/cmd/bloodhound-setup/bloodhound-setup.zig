//! bloodhound-setup writes BloodHound's config before each start. The
//! administrator password and Neo4j's password come from the config. The
//! file is rewritten every start, and BloodHound recreates the
//! administrator from it, so the config stays the password.
//!
//!     bloodhound-setup
//!
//! leash runs it as _oci-bloodhound, inside the image, where /tmp is the
//! service's /run and /data is /data/svc/bloodhound
//! (forms/bloodhound/form.yaml). See forms/bloodhound/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const admin_path = "/tmp/admin-password";
const neo4j_path = "/tmp/graph-password";
const config_path = "/data/bloodhound.config.json";

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
    const admin = try secret(io, gpa, admin_path);
    const neo = try secret(io, gpa, neo4j_path);
    defer Dir.cwd().deleteFile(io, admin_path) catch {};
    defer Dir.cwd().deleteFile(io, neo4j_path) catch {};

    const body = try std.json.Stringify.valueAlloc(gpa, .{
        .version = 1,
        .bind_addr = "127.0.0.1:8080",
        .metrics_port = "127.0.0.1:2112",
        .root_url = try gpa.print("https://{s}/", .{domain}),
        .work_dir = "/data/work",
        .log_level = "INFO",
        .graph_driver = "neo4j",
        .tls = .{ .cert_file = "", .key_file = "" },
        .collectors_base_path = "/etc/bloodhound/collectors",
        .database = .{
            .connection = "user=bloodhound dbname=postgres host=127.0.0.1 sslmode=disable",
        },
        .neo4j = .{ .connection = try gpa.print(
            "neo4j://neo4j:{s}@127.0.0.1:7687",
            .{try encode(gpa, neo)},
        ) },
        .recreate_default_admin = true,
        .default_admin = .{
            .principal_name = "admin",
            .password = admin,
            .first_name = "Admin",
            .last_name = "User",
            .email_address = "admin@localhost",
        },
        .disable_cypher_complexity_limit = false,
        .enable_cypher_mutations = false,
        .enable_user_analytics = false,
        // A gibibyte, which is BloodHound's own default, on two threads:
        // a small machine has two CPUs, and eight threads only waits.
        .crypto = .{
            .argon2 = .{
                .memory_kibibytes = 1048576,
                .num_iterations = 1,
                .num_threads = 2,
            },
        },
    }, .{});
    var f = try Dir.cwd().createFile(io, config_path, .{ .permissions = .fromMode(0o600) });
    defer f.close(io);
    try f.writeStreamingAll(io, body);
    try f.sync(io);
    say(io, "{{\"event\":\"config written\",\"domain\":\"{s}\"}}", .{domain});
}

fn secret(io: Io, gpa: Allocator, path: []const u8) ![]const u8 {
    const text = Dir.cwd().readFileAlloc(io, path, gpa, .limited(4 << 10)) catch |err|
        switch (err) {
            error.FileNotFound => return error.NoPassword,
            else => return err,
        };
    const s = std.mem.trimEnd(u8, text, "\r\n");
    if (s.len < 12 or s.len > 128 or s[0] == '-') return error.PasswordRefused;
    for (s) |c| if (c < 0x20 or c == 0x7f) return error.PasswordRefused;
    return s;
}

fn encode(gpa: Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (s) |c| {
        if ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or
            c == '-' or c == '_' or c == '.' or c == '~')
        {
            try out.append(gpa, c);
        } else {
            const hexd = "0123456789ABCDEF";
            try out.appendSlice(gpa, &.{ '%', hexd[c >> 4], hexd[c & 0xf] });
        }
    }
    return out.items;
}

fn hostname(s: []const u8) bool {
    if (s.len < 1 or s.len > 253) return false;
    for (s) |c| if (!((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or c == '.' or c == '-')) return false;
    return true;
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "bloodhound-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "encode keeps a password out of the query syntax" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings(
        "werewolf-check-pass-1",
        try encode(arena.allocator(), "werewolf-check-pass-1"),
    );
    try testing.expectEqualStrings("a%40b%2Fc", try encode(arena.allocator(), "a@b/c"));
}
