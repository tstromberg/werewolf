//! openldap-setup writes slapd's configuration before each start, from the
//! machine's settings: the suffix its domain names, its admin, whose
//! password from the config it keeps only as an Argon2id hash, and LDAPS
//! with the config's certificate. On the first start it makes the
//! directory: its base entry and the password policy, with slapadd.
//!
//!     openldap-setup
//!
//! leash runs it as the openldap user, under the service's Landlock rules
//! (forms/openldap/form.yaml). See forms/openldap/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const argon2 = std.crypto.pwhash.argon2;

const slapd = "/usr/bin/slapd";
const run_dir = "/run/svc/openldap";
const slapd_conf = run_dir ++ "/slapd.conf";
/// admin_password is leash's copy of the config's, removed once hashed.
const admin_password = run_dir ++ "/admin-password";
const tls_cert = run_dir ++ "/tls-cert";
const tls_key = run_dir ++ "/tls-key";
const svc_dir = "/data/svc/openldap";
const db_dir = svc_dir ++ "/db";
/// made holds the suffix of the directory made in db. If db is gone but
/// made is not, the directory was lost, and openldap-setup refuses to
/// make an empty one over it.
const made = "made";
/// argon2_params are OWASP's for Argon2id, for the admin's hash and, by
/// the argon2 module's arguments, every password slapd hashes.
const argon2_params: argon2.Params = .owasp_2id;
const min_password = 12;

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa, init.minimal.environ) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const domain = setting(gpa, environ, "OPENLDAP_DOMAIN") orelse return error.NoDomain;
    const admin = setting(gpa, environ, "OPENLDAP_ADMIN") orelse "admin";
    if (!name(admin)) return error.AdminNotAName;
    const base = try suffix(gpa, domain);
    const rootdn = try gpa.print("cn={s},{s}", .{ admin, base });

    const text = Dir.cwd().readFileAlloc(io, admin_password, gpa, .limited(4 << 10)) catch |err|
        switch (err) {
            error.FileNotFound => return error.NoAdminPassword,
            else => return err,
        };
    const secret = std.mem.trimEnd(u8, text, "\r\n");
    if (secret.len < min_password) return error.AdminPasswordTooShort;
    var buf: [256]u8 = undefined;
    const hash = try argon2.strHash(secret, .{
        .allocator = gpa,
        .params = argon2_params,
        .mode = .argon2id,
    }, &buf, io);
    // slapd reads the hash alone; the password leaves the machine's tmpfs.
    try Dir.cwd().deleteFile(io, admin_password);

    try replace(io, run_dir, "slapd.conf", try conf(gpa, base, rootdn, hash), 0o600);
    if (try makeDirectory(io, gpa, base))
        say(io, "made the directory {s} in {s}", .{ base, db_dir });
    say(io, "slapd.conf written: {s}, its admin {s}, LDAPS alone", .{ base, rootdn });
}

/// makeDirectory makes the directory on the first start, with slapadd, and
/// reports whether it did. Later starts find the suffix it was made for,
/// and refuse another, which slapd would serve over entries it cannot hold.
fn makeDirectory(io: Io, gpa: Allocator, base: []const u8) !bool {
    var svc = try Dir.cwd().openDir(io, svc_dir, .{});
    defer svc.close(io);
    if (svc.readFileAlloc(io, made, gpa, .limited(1 << 10))) |kept| {
        const was = std.mem.trimEnd(u8, kept, "\n");
        if (!std.mem.eql(u8, was, base)) {
            say(io, "{s} holds {s}, not {s}: a directory's domain does not change " ++
                "(forms/openldap/README.md)", .{ db_dir, was, base });
            return error.SuffixChanged;
        }
        svc.access(io, "db/data.mdb", .{}) catch {
            say(io, "the directory in {s} is gone, though it was made here; not making " ++
                "it empty over its loss", .{db_dir});
            return error.DirectoryLost;
        };
        return false;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    // No mark: nothing, or a slapadd a stop cut short, which can have
    // added only what this one adds again.
    svc.deleteTree(io, "db") catch {};
    try svc.createDir(io, "db", .fromMode(0o700));
    var child = try std.process.spawn(io, .{
        .argv = &.{ slapd, "-T", "add", "-f", slapd_conf, "-b", base },
        .stdin = .pipe,
    });
    child.stdin.?.writeStreamingAll(io, try ldif(gpa, base)) catch {};
    child.stdin.?.close(io);
    child.stdin = null;
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) {
        say(io, "{s} -T add failed; see above", .{slapd});
        return error.SlapaddFailed;
    }
    try syncDir(io, db_dir);
    try replace(io, svc_dir, made, try gpa.print("{s}\n", .{base}), 0o600);
    return true;
}

/// suffix returns the DN a DNS domain names (RFC 2247): example.com is
/// dc=example,dc=com. A label is taken in lower case, and only a host
/// name's characters, so the DN needs no escaping in slapd.conf or LDIF.
fn suffix(gpa: Allocator, domain: []const u8) ![]const u8 {
    if (domain.len == 0 or domain.len > 253) return error.BadDomain;
    var out: std.ArrayList(u8) = .empty;
    var labels = std.mem.splitScalar(u8, domain, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.BadDomain;
        if (label[0] == '-' or label[label.len - 1] == '-') return error.BadDomain;
        if (out.items.len > 0) try out.append(gpa, ',');
        try out.appendSlice(gpa, "dc=");
        for (label) |c| switch (c) {
            'a'...'z', '0'...'9', '-' => try out.append(gpa, c),
            'A'...'Z' => try out.append(gpa, c - 'A' + 'a'),
            else => return error.BadDomain,
        };
    }
    return out.items;
}

/// conf returns slapd.conf. Before any database: the schemas, modules,
/// what every connection must do, and the ACLs every database ends with.
/// The config database is no one's; the mdb database holds the suffix.
fn conf(gpa: Allocator, base: []const u8, rootdn: []const u8, hash: []const u8) ![]const u8 {
    return gpa.print(
        \\# Written by openldap-setup at each start, from the machine's settings
        \\# (forms/openldap/README.md): change those, not this file.
        \\include /etc/openldap/schema/core.schema
        \\include /etc/openldap/schema/cosine.schema
        \\include /etc/openldap/schema/inetorgperson.schema
        \\include /etc/openldap/schema/nis.schema
        \\
        \\modulepath /usr/lib/openldap
        \\moduleload back_mdb
        \\moduleload ppolicy
        \\moduleload argon2 m={d} t={d}
        \\
        \\password-hash {{ARGON2}}
        \\disallow bind_anon
        \\require authc
        \\security ssf=128
        \\sizelimit 500
        \\timelimit 60
        \\loglevel 0
        \\
        \\TLSCertificateFile {s}
        \\TLSCertificateKeyFile {s}
        \\TLSProtocolMin 3.3
        \\
        \\access to attrs=userPassword
        \\  by self =xw
        \\  by anonymous auth
        \\  by * none
        \\access to *
        \\  by users read
        \\  by * none
        \\
        \\database config
        \\access to * by * none
        \\
        \\database mdb
        \\suffix "{s}"
        \\rootdn "{s}"
        \\rootpw {{ARGON2}}{s}
        \\directory {s}
        \\maxsize 4294967296
        \\index objectClass eq
        \\index cn,uid,mail,memberUid eq
        \\index uidNumber,gidNumber eq
        \\overlay ppolicy
        \\ppolicy_default "cn=password-policy,{s}"
        \\ppolicy_hash_cleartext
        \\
    , .{ argon2_params.m, argon2_params.t, tls_cert, tls_key, base, rootdn, hash, db_dir, base });
}

/// ldif returns the entries slapadd makes the directory with: the base,
/// and the default password policy, which refuses a password a user
/// sends already hashed (pwdCheckQuality 2), and so one whose hash names
/// a cost of the user's choosing.
fn ldif(gpa: Allocator, base: []const u8) ![]const u8 {
    const dc = base["dc=".len .. std.mem.findScalar(u8, base, ',') orelse base.len];
    return gpa.print(
        \\dn: {s}
        \\objectClass: domain
        \\dc: {s}
        \\
        \\dn: cn=password-policy,{s}
        \\objectClass: device
        \\objectClass: pwdPolicy
        \\cn: password-policy
        \\pwdAttribute: userPassword
        \\pwdCheckQuality: 2
        \\pwdMinLength: {d}
        \\pwdLockout: TRUE
        \\pwdMaxFailure: 10
        \\pwdFailureCountInterval: 300
        \\pwdLockoutDuration: 300
        \\
    , .{ base, dc, base, min_password });
}

/// name reports whether s is a plain user name: lower-case ASCII letters
/// and digits, with dots, hyphens and underscores between them.
fn name(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    for (s, 0..) |c, i| switch (c) {
        'a'...'z', '0'...'9' => {},
        '.', '-', '_' => if (i == 0 or i == s.len - 1) return false,
        else => return false,
    };
    return true;
}

/// setting returns the environment's value for key, or null if it is
/// unset or empty.
fn setting(gpa: Allocator, environ: std.process.Environ, key: []const u8) ?[]const u8 {
    const v = environ.getAlloc(gpa, key) catch return null;
    return if (v.len > 0) v else null;
}

/// replace writes base in dir_path whole or not at all: a temporary file,
/// synced, then renamed over it, and the directory synced.
fn replace(
    io: Io,
    dir_path: [:0]const u8,
    base: []const u8,
    data: []const u8,
    mode: std.posix.mode_t,
) !void {
    var dir = try Dir.cwd().openDir(io, dir_path, .{});
    defer dir.close(io);
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
    try syncDir(io, dir_path);
}

/// syncDir syncs the entries of the directory at p to disk.
fn syncDir(io: Io, p: [:0]const u8) !void {
    const linux = std.os.linux;
    const rc = linux.open(p, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    var e = linux.errno(rc);
    if (e == .SUCCESS) {
        e = linux.errno(linux.fsync(@intCast(rc)));
        _ = linux.close(@intCast(rc));
    }
    if (e == .SUCCESS) return;
    say(io, "syncing {s}: {s}", .{ p, @tagName(e) });
    return error.SyncFailed;
}

/// say prints one line to the console, control bytes as "?".
fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "openldap-setup: " ++ fmt ++ "\n", args) catch return;
    for (line[0 .. line.len - 1]) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = '?';
    };
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "suffix names the domain's components, in lower case" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("dc=example,dc=com", try suffix(a, "example.com"));
    try testing.expectEqualStrings("dc=corp", try suffix(a, "Corp"));
    try testing.expectEqualStrings("dc=a-1,dc=example,dc=org", try suffix(a, "a-1.example.org"));
    for ([_][]const u8{
        "",       ".",       "example.", ".com", "-a.com",
        "a-.com", "a b.com", "a,dc=x",   "a\"b", "a=b",
    }) |bad|
        try testing.expect(std.meta.isError(suffix(a, bad)));
}

test "conf: LDAPS's files, no one's config database, the admin's hash" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const base = "dc=example,dc=com";
    const c = try conf(arena.allocator(), base, "cn=admin," ++ base, "$argon2id$x");
    for ([_][]const u8{
        "moduleload argon2 m=19456 t=2\n",
        "password-hash {ARGON2}\ndisallow bind_anon\nrequire authc\n",
        "TLSCertificateKeyFile /run/svc/openldap/tls-key\n",
        "database config\naccess to * by * none\n",
        "suffix \"dc=example,dc=com\"\nrootdn \"cn=admin,dc=example,dc=com\"\n",
        "rootpw {ARGON2}$argon2id$x\ndirectory /data/svc/openldap/db\n",
        "ppolicy_default \"cn=password-policy,dc=example,dc=com\"\nppolicy_hash_cleartext\n",
    }) |want| try testing.expect(std.mem.find(u8, c, want) != null);
    for ([_][]const u8{ "rootpw {ARGON2}\n", "database monitor", "ldapi" }) |absent|
        try testing.expect(std.mem.find(u8, c, absent) == null);
}

test "ldif: the base entry, then the policy beneath it" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const l = try ldif(arena.allocator(), "dc=example,dc=com");
    const head = "dn: dc=example,dc=com\nobjectClass: domain\ndc: example\n\n";
    try testing.expect(std.mem.startsWith(u8, l, head));
    try testing.expect(std.mem.find(u8, l, "dn: cn=password-policy,dc=example,dc=com\n") != null);
    try testing.expect(std.mem.find(u8, l, "pwdCheckQuality: 2\npwdMinLength: 12\n") != null);
    const one = try ldif(arena.allocator(), "dc=corp");
    try testing.expect(std.mem.startsWith(u8, one, "dn: dc=corp\nobjectClass: domain\ndc: corp\n"));
}

test "the admin's hash is in the PHC form libsodium reads" {
    var buf: [256]u8 = undefined;
    const h = try argon2.strHash("werewolf-check-pass", .{
        .allocator = testing.allocator,
        .params = argon2_params,
        .mode = .argon2id,
    }, &buf, testing.io);
    try testing.expect(std.mem.startsWith(u8, h, "$argon2id$v=19$m=19456,t=2,p=1$"));
}

test "name takes plain user names" {
    try testing.expect(name("admin"));
    try testing.expect(name("ldap-admin"));
    for ([_][]const u8{ "", "Admin", "-a", "a,b", "a b", "a=b", "a\"b" }) |bad|
        try testing.expect(!name(bad));
}
