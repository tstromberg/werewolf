//! kafka-setup writes Kafka's configuration before each start, and formats
//! its log directory once. The configuration is the image's
//! /etc/kafka/server.properties with what the machine gives added: the name
//! clients reach it by, its admin as the super user, and a password made
//! now for the controller listener, which only this node's broker uses. On
//! a log directory with no meta.properties it runs Kafka's StorageTool with
//! a cluster ID and SCRAM-SHA-512 credentials for the config's users, so
//! they exist before the broker serves. A directory holding another
//! cluster's ID is refused, never formatted over.
//!
//!     kafka-setup
//!
//! leash runs it as the kafka user, under the service's Landlock rules
//! (forms/kafka/form.yaml). See forms/kafka/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
const b64 = std.base64.standard.Encoder;

const java = "/usr/bin/java";
const image_properties = "/etc/kafka/server.properties";
const run_dir = "/run/svc/kafka";
const properties = run_dir ++ "/server.properties";
/// keystore is the key and certificate chain in one PEM file, as Kafka's
/// ssl.keystore.location takes them (the image's server.properties).
const keystore = run_dir ++ "/tls.pem";
const log_dir = "/data/svc/kafka/log";
const meta = log_dir ++ "/meta.properties";
/// node is the principal this node's broker logs in to its controller as.
/// No config user can take it: a name starts with a letter or digit.
const node = "_node";
const node_id = "1";
const iterations = 8192;
const max_users = 64;

const User = struct { name: []const u8, password: []const u8 };

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    run(io, gpa, init.minimal.environ) catch |err| {
        say(io, "{s}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, environ: std.process.Environ) !void {
    const domain = setting(gpa, environ, "KAFKA_DOMAIN") orelse return error.NoDomain;
    if (!hostname(domain)) return error.BadDomain;
    const admin = setting(gpa, environ, "KAFKA_ADMIN") orelse return error.NoAdmin;
    if (!name(admin)) return error.AdminNotAName;
    const wanted = setting(gpa, environ, "KAFKA_CLUSTER_ID");
    if (wanted) |id| if (!clusterId(id)) {
        say(io, "cluster-id {s}: not a Kafka cluster ID, 22 characters of URL-safe base64", .{id});
        return error.BadClusterId;
    };

    const cert = try read(io, gpa, run_dir ++ "/tls-cert");
    const key = try read(io, gpa, run_dir ++ "/tls-key");
    try pem(io, cert, key);
    var secret: [16]u8 = undefined;
    io.random(&secret);
    const image = try read(io, gpa, image_properties);
    try replace(io, keystore, try std.mem.concat(gpa, u8, &.{ key, "\n", cert }), 0o600);
    try replace(io, properties, try server(gpa, image, domain, admin, &std.fmt.bytesToHex(secret, .lower)), 0o600);

    if (try formatted(io, gpa)) |id| {
        if (wanted) |w| if (!std.mem.eql(u8, w, id)) {
            say(io, "{s} holds cluster {s}, but the settings name {s}; not formatting over it", .{
                log_dir, id, w,
            });
            return error.AnotherCluster;
        };
        say(io, "server.properties written for {s}:9093; keeping cluster {s} in {s}", .{ domain, id, log_dir });
        return;
    }

    var list: std.ArrayList(User) = .empty;
    try list.append(gpa, .{ .name = admin, .password = try password(io, gpa, "admin-password") });
    if (Dir.cwd().readFileAlloc(io, run_dir ++ "/users", gpa, .limited(64 << 10))) |text| {
        try users(gpa, text, &list);
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    var id_buf: [22]u8 = undefined;
    const id = wanted orelse newClusterId(io, &id_buf);
    try format(io, gpa, id, list.items);
    var names: std.ArrayList(u8) = .empty;
    for (list.items, 0..) |u, i| try names.print(gpa, "{s}{s}", .{ if (i == 0) "" else ", ", u.name });
    say(io, "formatted cluster {s} in {s}, with users {s}; {s} is the super user", .{
        id, log_dir, names.items, admin,
    });
}

/// server returns server.properties: the image's, then the lines only this
/// machine can give.
fn server(gpa: Allocator, image: []const u8, domain: []const u8, admin: []const u8, secret: []const u8) ![]const u8 {
    var w: Io.Writer.Allocating = .init(gpa);
    const o = &w.writer;
    try o.writeAll(image);
    if (image.len > 0 and image[image.len - 1] != '\n') try o.writeByte('\n');
    try o.print(
        "\n# Added by kafka-setup at each start, from the machine's settings.\n" ++
            "advertised.listeners=CLIENTS://{s}:9093,CONTROLLER://127.0.0.1:9094\n" ++
            "super.users=User:{s};User:" ++ node ++ "\n" ++
            "listener.name.controller.plain.sasl.jaas.config=" ++
            "org.apache.kafka.common.security.plain.PlainLoginModule required " ++
            "username=\"" ++ node ++ "\" password=\"{s}\" user_" ++ node ++ "=\"{s}\";\n",
        .{ domain, admin, secret, secret },
    );
    return w.written();
}

/// formatted returns the cluster ID of the log directory, or null if it
/// has none yet. A directory made for another node is refused.
fn formatted(io: Io, gpa: Allocator) !?[]const u8 {
    const text = Dir.cwd().readFileAlloc(io, meta, gpa, .limited(4 << 10)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    const m = try metaProperties(text);
    if (!std.mem.eql(u8, m.node, node_id)) {
        say(io, "{s} is node {s}'s, not node " ++ node_id ++ "'s", .{ log_dir, m.node });
        return error.AnotherNode;
    }
    return m.cluster;
}

fn metaProperties(text: []const u8) !struct { cluster: []const u8, node: []const u8 } {
    var cluster: ?[]const u8 = null;
    var node_line: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r");
        const eq = std.mem.findScalar(u8, line, '=') orelse continue;
        const v = line[eq + 1 ..];
        if (std.mem.eql(u8, line[0..eq], "cluster.id")) cluster = v;
        if (std.mem.eql(u8, line[0..eq], "node.id")) node_line = v;
    }
    const id = cluster orelse return error.MetaPropertiesWithoutClusterId;
    if (!clusterId(id)) return error.MetaPropertiesBadClusterId;
    return .{ .cluster = id, .node = node_line orelse return error.MetaPropertiesWithoutNodeId };
}

/// format runs Kafka's StorageTool, which writes meta.properties last, so
/// a format cut short is formatted again at the next start. Each user is
/// given as a salted password, never the password itself: the formatter
/// splits its arguments at commas, and a command line is not for secrets.
/// Its output prints the records it writes, SCRAM keys among them, so only
/// its errors reach the console.
fn format(io: Io, gpa: Allocator, id: []const u8, list: []const User) !void {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{
        java,
        "-Xmx128m",
        "-XX:-UsePerfData",
        "-XX:TieredStopAtLevel=1",
        "-Djava.io.tmpdir=" ++ run_dir,
        "-Dlog4j2.configurationFile=/etc/kafka/log4j2.properties",
        "-cp",
        "/usr/lib/kafka/libs/*",
        "kafka.tools.StorageTool",
        "format",
        "--config",
        properties,
        "--cluster-id",
        id,
        "--standalone",
    });
    for (list) |u| try argv.appendSlice(gpa, &.{ "--add-scram", try scram(io, gpa, u) });
    const r = try std.process.run(gpa, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(1 << 20),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(300), .clock = .awake } },
    });
    if (r.term == .exited and r.term.exited == 0) return;
    var lines = std.mem.splitScalar(u8, r.stderr, '\n');
    while (lines.next()) |line| if (line.len > 0) say(io, "StorageTool: {s}", .{line});
    return error.FormatFailed;
}

/// scram returns the formatter's argument for u: SCRAM-SHA-512's salted
/// password (RFC 5802's Hi, PBKDF2 with HMAC-SHA-512), as Kafka computes
/// it from a password.
fn scram(io: Io, gpa: Allocator, u: User) ![]const u8 {
    var salt: [24]u8 = undefined;
    io.random(&salt);
    return scramArgument(gpa, u, &salt);
}

fn scramArgument(gpa: Allocator, u: User, salt: []const u8) ![]const u8 {
    var salted: [HmacSha512.mac_length]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&salted, u.password, salt, iterations, HmacSha512);
    var salt_buf: [64]u8 = undefined;
    var salted_buf: [b64.calcSize(HmacSha512.mac_length)]u8 = undefined;
    return gpa.print("SCRAM-SHA-512=[name={s},salt={s},saltedpassword={s},iterations={d}]", .{
        u.name,
        b64.encode(&salt_buf, salt),
        b64.encode(&salted_buf, &salted),
        iterations,
    });
}

/// users appends the users file's: a line each, NAME PASSWORD, the
/// password the rest of the line. Blank lines and # comments are skipped.
fn users(gpa: Allocator, text: []const u8, list: *std.ArrayList(User)) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0 or line[0] == '#') continue;
        const sp = std.mem.findScalar(u8, line, ' ') orelse return error.UserWithoutPassword;
        const u: User = .{ .name = line[0..sp], .password = line[sp + 1 ..] };
        if (!name(u.name)) return error.UserNotAName;
        if (!strong(u.password)) return error.UserPasswordNot12To1024Printable;
        for (list.items) |o| if (std.mem.eql(u8, o.name, u.name)) return error.UserTwice;
        if (list.items.len == max_users) return error.TooManyUsers;
        try list.append(gpa, u);
    }
}

fn password(io: Io, gpa: Allocator, file: []const u8) ![]const u8 {
    const text = try read(io, gpa, try std.mem.concat(gpa, u8, &.{ run_dir, "/", file }));
    const p = std.mem.trimEnd(u8, text, "\r\n");
    if (!strong(p)) return error.AdminPasswordNot12To1024Printable;
    return p;
}

/// strong reports whether p is 12 to 1024 bytes with no control
/// characters.
fn strong(p: []const u8) bool {
    if (p.len < 12 or p.len > 1024) return false;
    for (p) |c| if (c < 0x20 or c == 0x7f) return false;
    return true;
}

/// pem checks the certificate and key are what Kafka's PEM keystore
/// reads: certificates, and one unencrypted PKCS#8 key.
fn pem(io: Io, cert: []const u8, key: []const u8) !void {
    if (std.mem.find(u8, cert, "-----BEGIN CERTIFICATE-----") == null) {
        say(io, "tls-cert holds no PEM certificate", .{});
        return error.BadTlsCert;
    }
    const k = std.mem.trimStart(u8, key, " \t\r\n");
    if (std.mem.startsWith(u8, k, "-----BEGIN PRIVATE KEY-----")) return;
    say(io, "tls-key is not an unencrypted PKCS#8 key, which Kafka reads; " ++
        "openssl pkcs8 -topk8 -nocrypt converts one", .{});
    return error.BadTlsKey;
}

/// newClusterId returns a random cluster ID as Kafka makes one: 16 bytes
/// of URL-safe base64, never starting with "-", which reads as an option.
fn newClusterId(io: Io, buf: *[22]u8) []const u8 {
    while (true) {
        var raw: [16]u8 = undefined;
        io.random(&raw);
        const id = std.base64.url_safe_no_pad.Encoder.encode(buf, &raw);
        if (id[0] != '-') return id;
    }
}

/// clusterId reports whether s is a Kafka cluster ID: 16 bytes in 22
/// characters of URL-safe base64, not starting with "-".
fn clusterId(s: []const u8) bool {
    if (s.len != 22 or s[0] == '-') return false;
    var raw: [16]u8 = undefined;
    std.base64.url_safe_no_pad.Decoder.decode(&raw, s) catch return false;
    return true;
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

/// hostname reports whether s holds only a host name's characters, as a
/// line of server.properties takes it.
fn hostname(s: []const u8) bool {
    if (s.len == 0 or s.len > 253) return false;
    for (s) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '-' => {},
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

fn read(io: Io, gpa: Allocator, p: []const u8) ![]const u8 {
    return Dir.cwd().readFileAlloc(io, p, gpa, .limited(64 << 10)) catch |err| {
        say(io, "{s}: {s}", .{ p, @errorName(err) });
        return err;
    };
}

/// replace writes p whole or not at all: a temporary file, synced, then
/// renamed over it.
fn replace(io: Io, p: []const u8, data: []const u8, mode: std.posix.mode_t) !void {
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(p).?, .{});
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

/// say prints one line to the console. Kafka's errors may quote what it
/// read, so control bytes become "?" to stop escape sequences and forged
/// log lines.
fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "kafka-setup: " ++ fmt ++ "\n", args) catch return;
    for (line[0 .. line.len - 1]) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = '?';
    };
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "server: the image's lines, then the machine's" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const s = try server(arena.allocator(), "node.id=1", "kafka.corp.example", "ops", "abc");
    try testing.expect(std.mem.startsWith(u8, s, "node.id=1\n"));
    for ([_][]const u8{
        "advertised.listeners=CLIENTS://kafka.corp.example:9093,CONTROLLER://127.0.0.1:9094\n",
        "super.users=User:ops;User:_node\n",
        "username=\"_node\" password=\"abc\" user__node=\"abc\";\n",
    }) |want| try testing.expect(std.mem.find(u8, s, want) != null);
}

test "scramArgument: Kafka's salted password for a known salt" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = try scramArgument(arena.allocator(), .{ .name = "app", .password = "pencil-pencil" }, "salt");
    // Python's hashlib.pbkdf2_hmac('sha512', b'pencil-pencil', b'salt', 8192, 64).
    try testing.expectEqualStrings("SCRAM-SHA-512=[name=app,salt=c2FsdA==,saltedpassword=" ++
        "gN/D31iRgK+ya4O3s3gZ4RqmgmUnph3NwkDRN3Ad8/7ccMh7MGs2wNN6+8Pz+3A3BVl2e7Gi1fQrr54vtorrNA==," ++
        "iterations=8192]", a);
    // No comma inside, which the formatter splits at.
    try testing.expectEqual(3, std.mem.count(u8, a, ","));
}

test "users: NAME PASSWORD lines, each name once" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var list: std.ArrayList(User) = .empty;
    try list.append(a, .{ .name = "ops", .password = "x" });
    try users(a, "# apps\napp a pass with spaces\r\n\nbilling 0123456789ab\n", &list);
    try testing.expectEqual(3, list.items.len);
    try testing.expectEqualStrings("a pass with spaces", list.items[1].password);
    for ([_][]const u8{
        "ops 0123456789ab",
        "app short",
        "app",
        "App 0123456789ab",
        "_node 0123456789ab",
        "a,b 0123456789ab",
        "app 0123456789ab\napp 0123456789ab",
    }) |bad| {
        var l: std.ArrayList(User) = .empty;
        try l.append(a, .{ .name = "ops", .password = "x" });
        try testing.expect(std.meta.isError(users(a, bad, &l)));
    }
}

test "metaProperties: the cluster and node" {
    const m = try metaProperties("#\nversion=1\nnode.id=1\ncluster.id=MkU3OEVBNTcwNTJENDM2Qg\ndirectory.id=x\n");
    try testing.expectEqualStrings("MkU3OEVBNTcwNTJENDM2Qg", m.cluster);
    try testing.expectEqualStrings("1", m.node);
    try testing.expectError(error.MetaPropertiesWithoutClusterId, metaProperties("node.id=1\n"));
}

test "clusterId takes Kafka's IDs alone" {
    try testing.expect(clusterId("MkU3OEVBNTcwNTJENDM2Qg"));
    for ([_][]const u8{ "", "MkU3OEVBNTcwNTJENDM2Q", "-kU3OEVBNTcwNTJENDM2Qg", "MkU3OEVBNTcwNTJENDM2Q=", "MkU3OEVBNTcwNTJENDM2Q+" }) |bad|
        try testing.expect(!clusterId(bad));
}

test "name and hostname" {
    try testing.expect(name("ops") and name("billing-app"));
    for ([_][]const u8{ "", "Ops", "-a", "_node", "a;b", "a b" }) |bad| try testing.expect(!name(bad));
    try testing.expect(hostname("kafka.corp.example") and hostname("10.0.0.5"));
    for ([_][]const u8{ "", "a b", "a:9093", "a\nb" }) |bad| try testing.expect(!hostname(bad));
}
