//! mox-setup prepares Mox before each start. On the first it makes the
//! domain, its DKIM keys and the first account with `mox quickstart`; at
//! every start it writes mox.conf from the machine's settings and the
//! admin password from the config, checks the result with Mox, and prints
//! the DNS records the domain needs.
//!
//!     mox-setup
//!
//! leash runs it as the mox user in /data/svc/mox, under the service's
//! Landlock rules (forms/mox/form.yaml). See forms/mox/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const bcrypt = std.crypto.pwhash.bcrypt;

const mox = "/usr/bin/mox";
const home = "/data/svc/mox";
const config_dir = home ++ "/config";
const mox_conf = config_dir ++ "/mox.conf";
const domains_conf = config_dir ++ "/domains.conf";
const admin_hash = config_dir ++ "/adminpasswd";
/// received_id is a key Mox makes on its first start and chowns to root,
/// which only root may do; made here, Mox finds it and logs no error.
const received_id = home ++ "/data/receivedid.key";
/// run_dir holds leash's copies of the config's files, made each start.
const run_dir = "/run/svc/mox";
const admin_password = run_dir ++ "/admin-password";
const relay_password = run_dir ++ "/relay-password";
const tls_cert = run_dir ++ "/tls-cert";
const tls_key = run_dir ++ "/tls-key";

/// Settings are what the machine's config says, from the environment
/// leash renders (forms/mox/form.yaml) and the files it copies.
const Settings = struct {
    domain: []const u8,
    host: []const u8,
    postmaster: []const u8,
    admin_web: bool = true,
    relay: ?Relay = null,
    /// tls is set when the config holds a certificate and its key, which
    /// take ACME's place.
    tls: bool = false,
};

const Relay = struct {
    host: []const u8,
    port: u16,
    login: ?[]const u8 = null,
    password: ?[]const u8 = null,
};

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa, init.minimal.environ) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const s = try settings(io, gpa, environ);
    if (try firstStart(io, gpa, s))
        say(
            io,
            "made {s}, its DKIM keys and the account {s}; set its password in the admin web",
            .{ s.domain, s.postmaster },
        );
    try adminPassword(io, gpa);
    try receivedId(io);

    const conf = try render(gpa, s, try hostKeys(io, gpa));
    try replace(io, mox_conf, conf, 0o600);
    const domains = try Dir.cwd().readFileAlloc(io, domains_conf, gpa, .limited(4 << 20));
    switch (try route(gpa, domains, s.relay != null)) {
        .same => {},
        .foreign => say(io, "domains.conf has global Routes of its own; kept as they are", .{}),
        .changed => |text| {
            try replace(io, domains_conf, text, 0o600);
            say(
                io,
                "{s} the route through the relay in domains.conf",
                .{if (s.relay != null) "added" else "removed"},
            );
        },
    }
    _ = try moxRun(io, gpa, &.{ mox, "-config", mox_conf, "config", "test" }, "config test");
    say(io, "mox.conf written: {s} for {s}, {s}, admin web {s}, mail out {s}", .{
        s.host,
        s.domain,
        if (s.tls) "certificate from the config" else "certificates from Let's Encrypt",
        if (s.admin_web) "on" else "off",
        if (s.relay) |r| r.host else "direct",
    });
    dnsRecords(io, gpa, s.domain);
}

/// settings reads the machine's settings and checks what goes into Mox's
/// configuration, which has no quoting: one line a value.
fn settings(io: Io, gpa: Allocator, environ: std.process.Environ) !Settings {
    const domain = setting(gpa, environ, "MOX_DOMAIN") orelse return error.NoDomain;
    var s: Settings = .{
        .domain = domain,
        .host = setting(gpa, environ, "MOX_HOSTNAME") orelse
            try std.mem.concat(gpa, u8, &.{ "mail.", domain }),
        .postmaster = setting(gpa, environ, "MOX_POSTMASTER") orelse return error.NoPostmaster,
        .admin_web = !std.mem.eql(
            u8,
            setting(gpa, environ, "MOX_ADMIN_WEB") orelse "true",
            "false",
        ),
    };
    if (!localpart(s.postmaster)) return error.PostmasterNotALocalpart;
    if (setting(gpa, environ, "MOX_RELAY_SERVER")) |host| {
        var r: Relay = .{ .host = host, .port = 587 };
        if (setting(gpa, environ, "MOX_RELAY_PORT")) |p|
            r.port = std.fmt.parseInt(u16, p, 10) catch return error.BadRelayPort;
        r.login = setting(gpa, environ, "MOX_RELAY_LOGIN");
        r.password = try secret(io, gpa, relay_password);
        if ((r.login == null) != (r.password == null)) return error.RelayNeedsLoginAndPassword;
        for ([_]?[]const u8{ r.host, r.login, r.password }) |v|
            if (v) |text| if (!plain(text)) return error.RelaySettingNotPrintable;
        s.relay = r;
    }
    const cert = try exists(io, tls_cert);
    if (cert != try exists(io, tls_key)) return error.TlsNeedsCertAndKey;
    s.tls = cert;
    return s;
}

/// setting returns the environment's value for name, or null if it is
/// unset or empty.
fn setting(gpa: Allocator, environ: std.process.Environ, name: []const u8) ?[]const u8 {
    const v = environ.getAlloc(gpa, name) catch return null;
    return if (v.len > 0) v else null;
}

fn exists(io: Io, path: []const u8) !bool {
    Dir.cwd().access(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

/// firstStart runs `mox quickstart` once, when Mox has no domains.conf:
/// it makes the domain, its DKIM keys, the host keys for DANE, and the
/// first account, with a random password nobody is told. Its output and
/// log name the passwords it makes, so neither is kept.
fn firstStart(io: Io, gpa: Allocator, s: Settings) !bool {
    if (try exists(io, domains_conf)) return false;
    const address = try std.mem.concat(gpa, u8, &.{ s.postmaster, "@", s.domain });
    const r = try std.process.run(gpa, io, .{
        .argv = &.{ mox, "quickstart", "-skipdial", "-hostname", s.host, address, "mox" },
        .cwd = .{ .path = home },
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(1 << 20),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(120), .clock = .awake } },
    });
    for ([_][]const u8{ "quickstart.log", "mox.service" }) |name| {
        const path = try std.mem.concat(gpa, u8, &.{ home, "/", name });
        Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => say(io, "{s} not removed: {s}", .{ path, @errorName(err) }),
        };
    }
    if (r.term == .exited and r.term.exited == 0) return true;
    // Its last lines say why, but the earlier ones may name a password.
    var lines = std.mem.splitBackwardsScalar(u8, r.stdout, '\n');
    var n: usize = 0;
    while (lines.next()) |line| : (n += 1) {
        if (n == 4) break;
        if (std.ascii.findIgnoreCase(line, "password") == null and line.len > 0)
            say(io, "quickstart: {s}", .{line});
    }
    return error.QuickstartFailed;
}

/// adminPassword keeps Mox's admin password the config's: a bcrypt hash in
/// adminpasswd, made again only when the password changed. The copy leash
/// made is removed once read.
fn adminPassword(io: Io, gpa: Allocator) !void {
    const password = try secret(io, gpa, admin_password) orelse return error.NoAdminPassword;
    // bcrypt reads 72 bytes; Go's, which checks it, refuses more.
    if (password.len < 12) return error.AdminPasswordTooShort;
    if (password.len > 72) return error.AdminPasswordTooLong;
    if (Dir.cwd().readFileAlloc(io, admin_hash, gpa, .limited(1 << 10))) |old| {
        const hash = std.mem.trimEnd(u8, old, "\n");
        if (bcrypt.strVerify(hash, password, .{ .silently_truncate_password = true }))
            return
        else |_| {}
    } else |_| {}
    var buf: [bcrypt.hash_length]u8 = undefined;
    const hash = try bcrypt.strHash(password, .{
        .params = .{ .rounds_log = 10, .silently_truncate_password = true },
        .encoding = .crypt,
    }, &buf, io);
    try replace(io, admin_hash, hash, 0o600);
    say(io, "admin password set from the config", .{});
}

fn receivedId(io: Io) !void {
    if (try exists(io, received_id)) return;
    var key: [24]u8 = undefined;
    io.random(&key);
    try replace(io, received_id, &key, 0o640);
}

/// hostKeys returns the newest RSA and ECDSA host keys quickstart made,
/// relative to the config directory: with them ACME's certificates keep
/// one key, which DANE records name.
fn hostKeys(io: Io, gpa: Allocator) ![]const []const u8 {
    var dir = Dir.cwd().openDir(
        io,
        config_dir ++ "/hostkeys",
        .{ .iterate = true },
    ) catch |err| switch (err) {
        error.FileNotFound => return &.{},
        else => return err,
    };
    defer dir.close(io);
    var newest: [2]?[]const u8 = .{ null, null };
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        for ([_][]const u8{
            ".rsa2048.privatekey.pkcs8.pem",
            ".ecdsap256.privatekey.pkcs8.pem",
        }, 0..) |suffix, i| {
            if (!std.mem.endsWith(u8, e.name, suffix)) continue;
            if (newest[i] == null or std.mem.order(u8, e.name, newest[i].?) == .gt)
                newest[i] = try gpa.dupe(u8, e.name);
        }
    }
    var keys: std.ArrayList([]const u8) = .empty;
    for (newest) |name| if (name) |n|
        try keys.append(gpa, try std.mem.concat(gpa, u8, &.{ "hostkeys/", n }));
    return keys.items;
}

/// render returns mox.conf for s: one public listener on every IPv4
/// address, serving SMTP, submission, IMAP over TLS, and the web and
/// ACME's challenges on 443. No plain IMAP, nothing on :80, and no
/// internal listener, which would need a tunnel to reach.
fn render(gpa: Allocator, s: Settings, host_keys: []const []const u8) ![]const u8 {
    var w: Io.Writer.Allocating = .init(gpa);
    const o = &w.writer;
    try o.print(
        "# Written by mox-setup at each start, from the machine's settings\n" ++
            "# (forms/mox/README.md): change those, not this file. domains.conf,\n" ++
            "# beside it, is Mox's, and its admin web's.\n" ++
            "DataDir: ../data\nLogLevel: info\nUser: mox\nHostname: {s}\n" ++
            "AdminPasswordFile: adminpasswd\n",
        .{s.host},
    );
    if (!s.tls) try o.print(
        "ACME:\n\tletsencrypt:\n" ++
            "\t\tDirectoryURL: https://acme-v02.api.letsencrypt.org/directory\n" ++
            "\t\tContactEmail: {s}@{s}\n\t\tIssuerDomainName: letsencrypt.org\n",
        .{ s.postmaster, s.domain },
    );
    try o.writeAll("Listeners:\n\tpublic:\n\t\tIPs:\n\t\t\t- 0.0.0.0\n\t\tTLS:\n");
    if (s.tls) {
        try o.writeAll("\t\t\tKeyCerts:\n\t\t\t\t-\n" ++
            "\t\t\t\t\tCertFile: " ++ tls_cert ++ "\n\t\t\t\t\tKeyFile: " ++ tls_key ++ "\n");
    } else {
        try o.writeAll("\t\t\tACME: letsencrypt\n");
        if (host_keys.len > 0) try o.writeAll("\t\t\tHostPrivateKeyFiles:\n");
        for (host_keys) |k| try o.print("\t\t\t\t- {s}\n", .{k});
    }
    for ([_][]const u8{
        "SMTP",           "Submission",   "Submissions", "IMAPS",           "AccountHTTPS",
        "AdminHTTPS",     "WebmailHTTPS", "WebAPIHTTPS", "AutoconfigHTTPS", "MTASTSHTTPS",
        "WebserverHTTPS",
    }) |service| {
        if (!s.admin_web and std.mem.eql(u8, service, "AdminHTTPS")) continue;
        try o.print("\t\t{s}:\n\t\t\tEnabled: true\n", .{service});
    }
    try o.print(
        "Postmaster:\n\tAccount: {s}\n\tMailbox: Postmaster\n" ++
            "HostTLSRPT:\n\tAccount: {s}\n\tMailbox: TLSRPT\n\tLocalpart: tlsreports\n",
        .{ s.postmaster, s.postmaster },
    );
    if (s.relay) |r| {
        // 465 is TLS from the start; any other port starts plain, and Mox
        // then requires STARTTLS and checks the relay's certificate.
        try o.print("Transports:\n\trelay:\n\t\t{s}:\n\t\t\tHost: {s}\n\t\t\tPort: {d}\n", .{
            if (r.port == 465) "Submissions" else "Submission", r.host, r.port,
        });
        if (r.login) |login|
            try o.print(
                "\t\t\tAuth:\n\t\t\t\tUsername: {s}\n\t\t\t\tPassword: {s}\n",
                .{ login, r.password.? },
            );
    }
    return w.written();
}

/// relay_route is the global route that sends all mail through the relay.
const relay_route = "Routes:\n\t-\n\t\tTransport: relay\n";

const RouteEdit = union(enum) {
    same,
    /// foreign: domains.conf has global Routes someone made in the admin
    /// web, which are left alone.
    foreign,
    changed: []const u8,
};

/// route makes domains.conf's global Routes relay_route when there is a
/// relay, and removes it when there is none. Routes live there, not in
/// mox.conf, and mox.conf's transport is named by them.
fn route(gpa: Allocator, text: []const u8, relay: bool) !RouteEdit {
    const start: ?usize = if (std.mem.startsWith(u8, text, "Routes:\n"))
        0
    else if (std.mem.find(u8, text, "\nRoutes:\n")) |i| i + 1 else null;
    const at = start orelse {
        if (!relay) return .same;
        const sep: []const u8 = if (text.len == 0 or text[text.len - 1] == '\n') "" else "\n";
        return .{ .changed = try std.mem.concat(gpa, u8, &.{ text, sep, relay_route }) };
    };
    // The block is its line and those indented under it.
    var end = at + "Routes:\n".len;
    while (end < text.len and text[end] == '\t') {
        end = if (std.mem.findScalarPos(u8, text, end, '\n')) |nl| nl + 1 else text.len;
    }
    if (!std.mem.eql(u8, text[at..end], relay_route)) return .foreign;
    if (relay) return .same;
    return .{ .changed = try std.mem.concat(gpa, u8, &.{ text[0..at], text[end..] }) };
}

/// dnsRecords prints the records Mox wants for domain, a zone file
/// without its comments, for the operator to make. They are public.
fn dnsRecords(io: Io, gpa: Allocator, domain: []const u8) void {
    const zone = moxRun(
        io,
        gpa,
        &.{ mox, "-config", mox_conf, "config", "dnsrecords", domain },
        "config dnsrecords",
    ) catch return;
    say(io, "DNS records for {s}, to make at its DNS provider:", .{domain});
    var lines = std.mem.splitScalar(u8, zone, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == ';') continue;
        say(io, "  {s}", .{line});
    }
}

/// secret reads a file leash copied from the config and removes the copy:
/// it is needed here alone. null if the config has none.
fn secret(io: Io, gpa: Allocator, path: []const u8) !?[]const u8 {
    const text = Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        .limited(4 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    Dir.cwd().deleteFile(io, path) catch |err|
        say(io, "{s} not removed: {s}", .{ path, @errorName(err) });
    return std.mem.trimEnd(u8, text, "\r\n");
}

/// replace writes path whole or not at all: a temporary file, synced, then
/// renamed over it, and the rename synced.
fn replace(io: Io, path: []const u8, data: []const u8, mode: std.posix.mode_t) !void {
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(path).?, .{ .iterate = true });
    defer dir.close(io);
    const name = std.fs.path.basename(path);
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, ".{s}.tmp", .{name});
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(io, tmp, .{ .exclusive = true, .permissions = .fromMode(mode) });
        defer f.close(io);
        try f.writeStreamingAll(io, data);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, name, io);
    if (std.os.linux.errno(std.os.linux.fsync(dir.handle)) != .SUCCESS) return error.SyncFailed;
}

/// moxRun runs argv and returns its standard output. On failure it says
/// which step failed and what Mox said.
fn moxRun(io: Io, gpa: Allocator, argv: []const []const u8, step: []const u8) ![]const u8 {
    const r = try std.process.run(gpa, io, .{
        .argv = argv,
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(1 << 20),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(60), .clock = .awake } },
    });
    if (r.term == .exited and r.term.exited == 0) return r.stdout;
    say(io, "mox {s} failed: {s}", .{
        step,
        std.mem.trim(u8, if (r.stderr.len > 0) r.stderr else r.stdout, " \n"),
    });
    return error.MoxFailed;
}

/// localpart reports whether s is a plain mailbox name: lower-case ASCII
/// letters and digits, with dots, hyphens and underscores between them.
fn localpart(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    for (s, 0..) |c, i| switch (c) {
        'a'...'z', '0'...'9' => {},
        '.', '-', '_' => if (i == 0 or i == s.len - 1) return false,
        else => return false,
    };
    return true;
}

/// plain reports whether s is printable ASCII without spaces, which a
/// line of Mox's configuration holds as written.
fn plain(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (c <= ' ' or c >= 0x7f) return false;
    return true;
}

/// say prints one line to the console. Mox's errors can quote what it
/// read, so control bytes become "?", tabs spaces, to stop escape
/// sequences and forged log lines.
fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "mox-setup: " ++ fmt ++ "\n", args) catch return;
    for (line[0 .. line.len - 1]) |*c| switch (c.*) {
        '\t' => c.* = ' ',
        0...8, 10...0x1f, 0x7f => c.* = '?',
        else => {},
    };
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "localpart takes plain mailbox names only" {
    for ([_][]const u8{ "alice", "postmaster", "a.b", "a-b_c", "x1" }) |s|
        try testing.expect(localpart(s));
    for ([_][]const u8{ "", "Alice", ".a", "a.", "a b", "a@b", "a:b", "ä", "a\nb" }) |s|
        try testing.expect(!localpart(s));
}

test "plain refuses what would break a configuration line" {
    try testing.expect(plain("smtp.example.com"));
    try testing.expect(plain("p@ss:w0rd!"));
    for ([_][]const u8{ "", "a b", "a\tb", "a\nb", "\x7f", "é" }) |s|
        try testing.expect(!plain(s));
}

test "render: ACME, host keys, admin web and a relay on 587" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const conf = try render(arena.allocator(), .{
        .domain = "example.com",
        .host = "mail.example.com",
        .postmaster = "alice",
        .relay = .{ .host = "smtp.example.net", .port = 587, .login = "u", .password = "p" },
    }, &.{"hostkeys/k.rsa2048.privatekey.pkcs8.pem"});
    for ([_][]const u8{
        "Hostname: mail.example.com\n",
        "\t\tContactEmail: alice@example.com\n",
        "\t\t\tACME: letsencrypt\n\t\t\tHostPrivateKeyFiles:\n" ++
            "\t\t\t\t- hostkeys/k.rsa2048.privatekey.pkcs8.pem\n",
        "\t\tAdminHTTPS:\n\t\t\tEnabled: true\n",
        "\t\tSubmission:\n\t\t\tEnabled: true\n",
        "Postmaster:\n\tAccount: alice\n",
        "Transports:\n\trelay:\n\t\tSubmission:\n\t\t\tHost: smtp.example.net\n\t\t\tPort: 587\n",
        "\t\t\tAuth:\n\t\t\t\tUsername: u\n\t\t\t\tPassword: p\n",
    }) |want| if (std.mem.find(u8, conf, want) == null) {
        std.debug.print("missing {s} in\n{s}", .{ want, conf });
        return error.TestUnexpectedResult;
    };
    try testing.expect(std.mem.find(u8, conf, "IMAP:") == null);
    try testing.expect(std.mem.find(u8, conf, "KeyCerts") == null);
}

test "render: a certificate from the config, no admin web, no relay, 465" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const conf = try render(arena.allocator(), .{
        .domain = "example.com",
        .host = "mail.example.com",
        .postmaster = "alice",
        .admin_web = false,
        .tls = true,
    }, &.{"hostkeys/ignored"});
    try testing.expect(std.mem.find(
        u8,
        conf,
        "\t\t\tKeyCerts:\n\t\t\t\t-\n" ++
            "\t\t\t\t\tCertFile: /run/svc/mox/tls-cert\n\t\t\t\t\tKeyFile: /run/svc/mox/tls-key\n",
    ) != null);
    for ([_][]const u8{ "ACME", "AdminHTTPS", "Transports", "hostkeys" }) |absent|
        try testing.expect(std.mem.find(u8, conf, absent) == null);
    const relayed = try render(arena.allocator(), .{
        .domain = "example.com",
        .host = "mail.example.com",
        .postmaster = "alice",
        .relay = .{ .host = "smtp.example.net", .port = 465 },
    }, &.{});
    try testing.expect(std.mem.find(
        u8,
        relayed,
        "\t\tSubmissions:\n\t\t\tHost: smtp.example.net\n\t\t\tPort: 465\n",
    ) != null);
    try testing.expect(std.mem.find(u8, relayed, "Auth:") == null);
}

test "route adds, keeps and removes the relay's global route" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const base = "Domains:\n\texample.com:\n\t\tDKIM: x\nAccounts:\n\talice: y\n";
    const with = (try route(a, base, true)).changed;
    try testing.expectEqualStrings(base ++ relay_route, with);
    try testing.expectEqual(RouteEdit.same, try route(a, with, true));
    try testing.expectEqualStrings(base, (try route(a, with, false)).changed);
    try testing.expectEqual(RouteEdit.same, try route(a, base, false));
    // Routes in the middle, as Mox writes them after an edit.
    const middle = "Domains:\n\tx: y\n" ++ relay_route ++ "Accounts:\n\ta: b\n";
    try testing.expectEqualStrings(
        "Domains:\n\tx: y\nAccounts:\n\ta: b\n",
        (try route(a, middle, false)).changed,
    );
    // Someone's own routes stay, relay or not.
    const own = "Routes:\n\t-\n\t\tToDomain:\n\t\t\t- example.org\n\t\tTransport: relay\n";
    try testing.expectEqual(RouteEdit.foreign, try route(a, own, true));
    try testing.expectEqual(RouteEdit.foreign, try route(a, own, false));
    // A file without a final newline still gets the route on a line of its own.
    try testing.expectEqualStrings("A: b\n" ++ relay_route, (try route(a, "A: b", true)).changed);
}

test "bcrypt hashes in the crypt format Go's bcrypt reads" {
    var buf: [bcrypt.hash_length]u8 = undefined;
    const hash = try bcrypt.strHash("a long admin password", .{
        .params = .{ .rounds_log = 10, .silently_truncate_password = true },
        .encoding = .crypt,
    }, &buf, testing.io);
    try testing.expect(std.mem.startsWith(u8, hash, "$2b$10$"));
    try testing.expectEqual(@as(usize, 60), hash.len);
    try bcrypt.strVerify(hash, "a long admin password", .{ .silently_truncate_password = true });
}
