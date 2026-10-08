//! gitea-init: Gitea's first administrator, made once from the config,
//! before Gitea serves, so that no visitor can claim a fresh site.
//!
//!     gitea-init CONFIG
//!
//! leash runs it before each start of Gitea, as the gitea user, inside its
//! leash (forms/gitea/rootfs/etc/sv/gitea/service), with Gitea's
//! environment (GITEA_WORK_DIR, and the settings' GITEA_ADMIN and
//! GITEA_ADMIN_EMAIL). It makes its SSH host key once, Ed25519, by
//! ssh-keygen (lib/hostkey.zig), and says its fingerprint; the directory
//! Gitea keeps its secrets in, and each secret once (`gitea generate
//! secret`, 0600), brings the database's schema up to this Gitea's (`gitea
//! migrate`, which does nothing when it is current), asks Gitea for its
//! administrators, and if the one the settings name is not among them,
//! makes it with the password the config brought
//! (/run/svc/gitea/admin-password; leash's copy). Nothing is printed of
//! the password, which goes to Gitea as an argument, visible to root
//! alone (hidepid). A site with its admin is left as it is.

const std = @import("std");
const hostkey = @import("hostkey");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const gitea = "/usr/bin/gitea";
const password_file = "/run/svc/gitea/admin-password";
const secrets_dir = "/data/svc/gitea/secrets";
/// Gitea's SSH server's host key: Ed25519, made once by ssh-keygen. Gitea
/// would make an RSA key of any name it is given.
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
    // The secrets app.ini names by file, which Gitea reads and never makes:
    // made once here, 0600, by Gitea's own generator, and kept.
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
    // ID, Username, Email, IsActive, IsAdmin: a header, then one a line.
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
    // The password has done its one job. Its copy here is the service's
    // own (leash makes it as the service user, and again at every start),
    // and nothing in Gitea's uid should keep reading the operator's choice.
    Dir.cwd().deleteFile(io, password_file) catch |err|
        say(io, "{s} not removed: {s}", .{ password_file, @errorName(err) });
}

/// secrets_dir/name, made with `gitea generate secret kind` if missing,
/// written beside its place and renamed over it, so it is never half a
/// secret, 0600.
fn makeSecret(io: Io, gpa: Allocator, name: []const u8, kind: []const u8) !void {
    // Opened to be read, as iterate does, not O_PATH, Dir's default,
    // whose descriptor fsync refuses: the rename below is synced on it.
    var dir = try Dir.cwd().openDir(io, secrets_dir, .{ .iterate = true });
    defer dir.close(io);
    // One there already is kept, unless it is short: a power cut could
    // have left an empty one, and Gitea with it would stay down for good.
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
        // On disk before it is named, and the name on disk before it is
        // trusted: whole or absent after a power cut, never empty.
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, name, io);
    if (std.os.linux.errno(std.os.linux.fsync(dir.handle)) != .SUCCESS) return error.SyncFailed;
    say(io, "made {s} in {s}", .{ name, secrets_dir });
}

/// argv, run: its standard output, or, when it fails, a line naming the
/// step (argv[2..4], never the password) and what Gitea said on stderr.
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

/// One line on the console. What Gitea says on failure may hold anything
/// its database does, so each control byte becomes a "?": nothing from
/// outside carries an escape sequence or a false line to the console log.
fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "gitea-init: " ++ fmt ++ "\n", args) catch return;
    for (line[0 .. line.len - 1]) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = '?';
    };
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
