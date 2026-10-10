//! opensearch-setup writes OpenSearch's configuration directory before
//! each start: the image's opensearch.yml, logging and security plugin
//! files, copied from /etc/opensearch, and internal_users.yml, which holds
//! one user, admin, with a bcrypt hash of the config's password. It then
//! removes leash's copy of the password, so OpenSearch never reads it.
//!
//!     opensearch-setup
//!
//! leash runs it as the opensearch user, under the service's Landlock
//! rules (forms/opensearch/form.yaml). See forms/opensearch/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const bcrypt = std.crypto.pwhash.bcrypt;

/// etc holds the image's configuration; conf is OpenSearch's
/// configuration directory, which it must write (its keystore), and where
/// leash copies the config's files.
const etc = "/etc/opensearch";
const conf = "/run/svc/opensearch";
const password = conf ++ "/admin-password";
const users = conf ++ "/opensearch-security/internal_users.yml";
/// nodes is where OpenSearch keeps its data, the security index too.
const nodes = "/data/svc/opensearch/nodes";

/// files are what /etc/opensearch holds, each copied to conf.
const files = [_][]const u8{
    "opensearch.yml",
    "log4j2.properties",
    "opensearch-security/action_groups.yml",
    "opensearch-security/allowlist.yml",
    "opensearch-security/audit.yml",
    "opensearch-security/config.yml",
    "opensearch-security/nodes_dn.yml",
    "opensearch-security/roles.yml",
    "opensearch-security/roles_mapping.yml",
    "opensearch-security/tenants.yml",
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
    const text = Dir.cwd().readFileAlloc(io, password, gpa, .limited(4 << 10)) catch |err|
        switch (err) {
            error.FileNotFound => return error.NoAdminPassword,
            else => return err,
        };
    const secret = std.mem.trimEnd(u8, text, "\r\n");
    // bcrypt reads 72 bytes; the security plugin's refuses more.
    if (secret.len < 12) return error.AdminPasswordTooShort;
    if (secret.len > 72) return error.AdminPasswordTooLong;
    var buf: [bcrypt.hash_length]u8 = undefined;
    const hash = try bcrypt.strHash(secret, .{
        .params = .{ .rounds_log = 12, .silently_truncate_password = false },
        .encoding = .crypt,
    }, &buf, io);

    // The security plugin wants its directory for itself alone.
    Dir.cwd().createDir(io, conf ++ "/opensearch-security", .fromMode(0o700)) catch |err|
        switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    for (files) |name| {
        const data = try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/{s}", .{ etc, name }),
            gpa,
            .limited(1 << 20),
        );
        try replace(io, try gpa.print("{s}/{s}", .{ conf, name }), data, 0o600);
    }
    try replace(io, users, try internalUsers(gpa, hash), 0o600);
    Dir.cwd().deleteFile(io, password) catch |err|
        say(io, "{s} not removed: {s}", .{ password, @errorName(err) });

    // The security index is made from these files once, at the first
    // start; after that it is the index on /data that OpenSearch reads.
    if (try exists(io, nodes))
        say(io, "configuration written; admin's password is the one the security " ++
            "index on /data took at its first start", .{})
    else
        say(io, "configuration written; the security index is made from it, " ++
            "admin's password with it", .{});
}

/// internalUsers returns internal_users.yml: admin alone, by hash.
fn internalUsers(gpa: Allocator, hash: []const u8) ![]const u8 {
    return gpa.print(
        \\# Written by opensearch-setup at each start (forms/opensearch/README.md).
        \\_meta:
        \\  type: "internalusers"
        \\  config_version: 2
        \\admin:
        \\  hash: "{s}"
        \\  reserved: true
        \\  description: "The administrator, its password from the machine's config"
        \\
    , .{hash});
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

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "opensearch-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "internalUsers holds admin alone, by its hash" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const y = try internalUsers(arena.allocator(), "$2b$12$abc/def");
    try testing.expect(std.mem.find(u8, y, "admin:\n  hash: \"$2b$12$abc/def\"\n  reserved: true\n") != null);
    try testing.expectEqual(1, std.mem.count(u8, y, "hash:"));
}

test "a bcrypt hash of the password, which the security plugin verifies" {
    var buf: [bcrypt.hash_length]u8 = undefined;
    const hash = try bcrypt.strHash("werewolf-check-pass-1", .{
        .params = .{ .rounds_log = 4, .silently_truncate_password = false },
        .encoding = .crypt,
    }, &buf, testing.io);
    try testing.expect(std.mem.startsWith(u8, hash, "$2b$04$"));
    try bcrypt.strVerify(hash, "werewolf-check-pass-1", .{ .silently_truncate_password = false });
}
