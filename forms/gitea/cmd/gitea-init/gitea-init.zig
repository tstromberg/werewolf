//! gitea-init prepares Gitea before each start and creates its first
//! administrator, so no visitor can claim a fresh site.
//!
//!     gitea-init CONFIG
//!
//! leash runs it as the gitea user (forms/gitea/rootfs/etc/sv/gitea/service),
//! with GITEA_WORK_DIR, GITEA_ADMIN and GITEA_ADMIN_EMAIL set. It keeps an
//! Ed25519 SSH host key and Gitea's secrets, runs `gitea migrate`, and creates
//! the named administrator if missing, with the password in
//! /run/svc/gitea/admin-password. The password is passed as an argument;
//! hidepid hides it from everyone but root. It is never printed.

const std = @import("std");
const hostkey = @import("hostkey");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const gitea = "/usr/bin/gitea";
const password_file = "/run/svc/gitea/admin-password";
const secrets_dir = "/data/svc/gitea/secrets";
/// host_key is the key for Gitea's SSH server. We make it with ssh-keygen
/// because Gitea would make an RSA key.
const host_key = "/data/svc/gitea/ssh/gitea.ed25519";

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = init.minimal.args.toSlice(gpa) catch std.process.exit(1);
    if (args.len != 2 or !std.fs.path.isAbsolute(args[1])) {
        say(io, "usage: gitea-init CONFIG", .{});
        std.process.exit(1);
    }
    run(io, gpa, init.minimal.environ, args[1]) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ, config: []const u8) !void {
    const admin: []const u8 = environ.getAlloc(gpa, "GITEA_ADMIN") catch "admin";
    const email: []const u8 = environ.getAlloc(gpa, "GITEA_ADMIN_EMAIL") catch
        return error.NoAdminEmail;
    Dir.cwd().createDirPath(io, secrets_dir) catch |err| {
        say(io, "{s}: {s}", .{ secrets_dir, @errorName(err) });
        return err;
    };

    Dir.cwd().createDirPath(io, std.fs.path.dirname(host_key).?) catch |err| {
        say(io, "{s}: {s}", .{ host_key, @errorName(err) });
        return err;
    };
    const kept = try hostkey.keep(io, gpa, host_key);
    const public = try Dir.cwd().readFileAlloc(io, host_key ++ ".pub", gpa, .limited(16 << 10));
    var fp: [hostkey.fingerprint_len]u8 = undefined;
    say(io, "ssh host key {s}, {s}", .{
        hostkey.fingerprint(public, &fp) orelse return error.NotAPublicKey,
        if (kept == .new) "new, kept in /data" else "kept in /data",
    });
    // app.ini names these secrets by file. Gitea reads them but never
    // creates them, so we do, once.
    for ([_][2][]const u8{
        .{ "secret_key", "SECRET_KEY" },
        .{ "internal_token", "INTERNAL_TOKEN" },
        .{ "oauth2_jwt_secret", "JWT_SECRET" },
        .{ "lfs_jwt_secret", "LFS_JWT_SECRET" },
    }) |secret| try makeSecret(io, gpa, secret[0], secret[1]);
    _ = try giteaRun(io, gpa, &.{ gitea, "--config", config, "migrate" });
    const list = try giteaRun(
        io,
        gpa,
        &.{ gitea, "--config", config, "admin", "user", "list", "--admin" },
    );
    // The list is a header line, then one user per line:
    // ID, Username, Email, IsActive, IsAdmin.
    var lines = std.mem.tokenizeScalar(u8, list, '\n');
    _ = lines.next();
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        _ = words.next() orelse continue;
        const name = words.next() orelse continue;
        if (std.mem.eql(u8, name, admin)) {
            say(io, "administrator {s} exists; keeping the site as it is", .{admin});
            return;
        }
    }

    const text = Dir.cwd().readFileAlloc(io, password_file, gpa, .limited(4 << 10)) catch
        return error.NoAdminPassword;
    const password = std.mem.trimEnd(u8, text, "\r\n");
    if (password.len < 12) return error.AdminPasswordTooShort;
    _ = try giteaRun(io, gpa, &.{
        gitea,
        "--config",
        config,
        "admin",
        "user",
        "create",
        "--admin",
        "--username",
        admin,
        "--email",
        email,
        "--password",
        password,
        "--must-change-password=false",
    });
    say(io, "made administrator {s} ({s}) with the password from the config", .{ admin, email });
    // The password is no longer needed, and nothing running as Gitea's uid
    // should read it. This is the service's copy; leash makes it again at
    // every start.
    Dir.cwd().deleteFile(io, password_file) catch |err|
        say(io, "{s} not removed: {s}", .{ password_file, @errorName(err) });
}

/// makeSecret creates secrets_dir/name, mode 0600, with `gitea generate
/// secret kind` if it is missing or short. It writes a temporary file and
/// renames it, so a crash never leaves half a secret.
fn makeSecret(io: Io, gpa: Allocator, name: []const u8, kind: []const u8) !void {
    // Open for reading, not with O_PATH (Dir's default): fsync refuses an
    // O_PATH descriptor, and we sync the rename through it.
    var dir = try Dir.cwd().openDir(io, secrets_dir, .{ .iterate = true });
    defer dir.close(io);
    // Keep an existing secret unless it is short. A power cut could have
    // left it empty, and Gitea would then never start.
    if (dir.statFile(io, name, .{})) |st| {
        if (st.size >= 32) return;
        say(io, "{s} in {s} is too short; made again", .{ name, secrets_dir });
    } else |_| {}
    const value = std.mem.trim(
        u8,
        try giteaRun(io, gpa, &.{ gitea, "generate", "secret", kind }),
        " \n",
    );
    if (value.len < 32) return error.ShortSecret;
    const tmp = try std.mem.concat(gpa, u8, &.{ name, ".tmp" });
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(
            io,
            tmp,
            .{ .exclusive = true, .permissions = .fromMode(0o600) },
        );
        defer f.close(io);
        try f.writeStreamingAll(io, value);
        // Sync the data before the rename and the rename after it, so a
        // power cut leaves the secret whole or absent, never empty.
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, name, io);
    if (std.os.linux.errno(std.os.linux.fsync(dir.handle)) != .SUCCESS) return error.SyncFailed;
    say(io, "made {s} in {s}", .{ name, secrets_dir });
}

/// giteaRun runs argv and returns its standard output. On failure it logs
/// the step (argv[3..6], never the password) and Gitea's stderr.
fn giteaRun(io: Io, gpa: Allocator, argv: []const []const u8) ![]const u8 {
    const r = try std.process.run(gpa, io, .{
        .argv = argv,
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(1 << 20),
    });
    if (r.term == .exited and r.term.exited == 0) return r.stdout;
    const step = argv[@min(argv.len, 3)..@min(argv.len, 6)];
    say(io, "gitea {s} failed: {s}", .{
        try std.mem.join(gpa, " ", step),
        std.mem.trim(u8, if (r.stderr.len > 0) r.stderr else r.stdout, " \n"),
    });
    return error.GiteaFailed;
}

/// say prints one line to the console. Gitea's errors can quote database
/// contents, so control bytes become "?" to stop escape sequences and forged
/// log lines.
fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "gitea-init: " ++ fmt ++ "\n", args) catch return;
    for (line[0 .. line.len - 1]) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = '?';
    };
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
