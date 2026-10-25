//! fixture is what the release tool's tests share: a Sys over a private
//! directory, test signing keys, and a fake that answers howl, gh and aws
//! and refuses the network, so no test reaches either.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const Result = sys.Result;
const json = @import("json.zig");
const catalog = @import("catalog.zig");

pub const Answer = *const fn (f: *Fixture, argv: []const []const u8) anyerror!?Result;
pub const GetAnswer = *const fn (f: *Fixture, url: []const u8, limit: usize) anyerror!?sys.Got;
pub const FetchAnswer = *const fn (
    f: *Fixture,
    s: *Sys,
    url: []const u8,
    to: []const u8,
    limit: u64,
    expected: ?sys.Record,
) anyerror!void;

pub const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    env: std.process.Environ.Map,
    s: Sys,
    /// root is this test's private directory, absolute.
    root: []const u8,
    /// calls are the commands answer answered, in order.
    calls: std.ArrayList([]const []const u8) = .empty,
    answer: ?Answer = null,
    get_answer: ?GetAnswer = null,
    fetch_answer: ?FetchAnswer = null,
    /// bucket, when set, answers aws s3 cp as R2 would.
    bucket: ?*FakeBucket = null,
    /// state a test's answer keeps between calls.
    state: usize = 0,
    text: []const u8 = "",

    /// init makes f in place: s and its fake point into f.
    pub fn init(f: *Fixture) !void {
        f.* = .{
            .arena = .init(testing.allocator),
            .env = undefined,
            .s = undefined,
            .root = "",
        };
        const arena = f.arena.allocator();
        // Only what tools need: a test sets the rest, never the runner.
        f.env = .init(arena);
        for ([_][]const u8{ "PATH", "TMPDIR", "HOME", "LANG" }) |name|
            if (std.testing.environ.getPosix(name)) |v| try f.env.put(name, v);
        f.s = .{
            .io = testing.io,
            .gpa = arena,
            .env = &f.env,
            .fake = .{ .ctx = f, .run = run, .get = get, .fetch = fetch },
        };
        f.root = try sys.resolve(&f.s, try sys.scratch(&f.s, null, "ww-release-test-"));
    }

    pub fn deinit(f: *Fixture) void {
        sys.remove(&f.s, f.root);
        f.arena.deinit();
    }

    pub fn gpa(f: *Fixture) mem.Allocator {
        return f.arena.allocator();
    }

    /// path is rel under root.
    pub fn path(f: *Fixture, rel: []const u8) []const u8 {
        return sys.join(&f.s, &.{ f.root, rel }) catch @panic("out of memory");
    }

    /// called says whether answer saw a command whose words start so.
    pub fn called(f: *Fixture, words: []const []const u8) usize {
        var n: usize = 0;
        outer: for (f.calls.items) |argv| {
            if (argv.len < words.len) continue;
            for (words, argv[0..words.len]) |w, a| if (w.len > 0 and
                !mem.eql(u8, w, a)) continue :outer;
            n += 1;
        }
        return n;
    }

    fn run(ctx: *anyopaque, s: *Sys, argv: []const []const u8) anyerror!?Result {
        const f: *Fixture = @ptrCast(@alignCast(ctx));
        const r = blk: {
            if (f.bucket) |b| if (try b.answer(s, argv)) |got| break :blk got;
            const answer = f.answer orelse return null;
            break :blk try answer(f, argv);
        };
        if (r != null) try f.calls.append(f.gpa(), try f.gpa().dupe([]const u8, argv));
        return r;
    }

    fn fetch(
        ctx: *anyopaque,
        s: *Sys,
        url: []const u8,
        to: []const u8,
        limit: u64,
        expected: ?sys.Record,
    ) anyerror!bool {
        const f: *Fixture = @ptrCast(@alignCast(ctx));
        const answer = f.fetch_answer orelse return error.NetworkInTest;
        try answer(f, s, url, to, limit, expected);
        return true;
    }

    fn get(ctx: *anyopaque, s: *Sys, url: []const u8, limit: usize) anyerror!?sys.Got {
        const f: *Fixture = @ptrCast(@alignCast(ctx));
        _ = s;
        const answer = f.get_answer orelse return error.NetworkInTest;
        return answer(f, url, limit);
    }
};

/// Keys are a test signing key and its self-signed certificate.
pub const Keys = struct { key: []const u8, crt: []const u8 };

/// keys are the named test identity, made once and kept under .zig-cache
/// while they stay valid: RSA key generation is slow.
pub fn keys(f: *Fixture, name: []const u8) !Keys {
    const s = &f.s;
    const dir = try sys.resolve(s, ".zig-cache/tmp/release-test-keys");
    try sys.mkdirs(s, dir);
    const k: Keys = .{
        .key = try sys.join(s, &.{ dir, try f.gpa().print("{s}.key", .{name}) }),
        .crt = try sys.join(s, &.{ dir, try f.gpa().print("{s}.crt", .{name}) }),
    };
    if (sys.exists(s, k.key) and sys.exists(s, k.crt)) {
        const r = try sys.exec(
            s,
            &.{ "openssl", "x509", "-in", k.crt, "-checkend", "7200", "-noout" },
            .{ .capture = .both },
        );
        if (r.ok()) return k;
    }
    const subject = try f.gpa().print("/CN=release-test-{s}", .{name});
    const fresh: Keys = .{
        .key = try f.gpa().print("{s}.new", .{k.key}),
        .crt = try f.gpa().print("{s}.new", .{k.crt}),
    };
    const r = try sys.exec(s, &.{
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",  "-x509",   "-sha256",
        "-days",   "2",   "-subj",   subject,    "-keyout", fresh.key, "-out",
        fresh.crt,
    }, .{ .capture = .both });
    try testing.expect(r.ok());
    try std.Io.Dir.cwd().setFilePermissions(s.io, fresh.key, .fromMode(0o600), .{});
    try sys.rename(s, fresh.key, k.key);
    try sys.rename(s, fresh.crt, k.crt);
    return k;
}

/// signed is an RSA signature over bytes by the named test key.
pub fn signed(f: *Fixture, name: []const u8, bytes: []const u8) ![]const u8 {
    return catalog.sign(&f.s, bytes, (try keys(f, name)).key);
}

/// admit answers howl's native admission as tests need it: a bundle is
/// admitted when its boot.json signature verifies against the image
/// certificate; head prints the descriptor, verify an empty object.
pub fn admit(f: *Fixture, argv: []const []const u8) anyerror!?Result {
    if (argv.len < 8 or !mem.eql(u8, argv[1], "_boot-image")) return null;
    const s = &f.s;
    const dir = argv[3];
    const head = try sys.read(s, try sys.join(s, &.{ dir, "boot.json" }), 1 << 20);
    const signature = try sys.read(s, try sys.join(s, &.{ dir, "boot.json.sig" }), 512);
    catalog.verify(s, head, signature, argv[5]) catch
        return .{ .term = .{ .exited = 1 }, .stderr = "boot descriptor signature refused" };
    return .{
        .term = .{ .exited = 0 },
        .stdout = if (mem.eql(u8, argv[2], "head")) head else "{}",
    };
}

test {
    _ = json;
}

/// rep is c repeated n times, as Python's c * n.
pub fn rep(comptime c: u8, comptime n: usize) *const [n]u8 {
    const repeated = struct {
        const v: [n]u8 = @splat(c);
    };
    return &repeated.v;
}

/// FakeBucket answers aws s3 cp from a directory, records each upload and
/// fails those whose key ends with fail, as R2 would refuse a write.
pub const FakeBucket = struct {
    root: []const u8,
    fail: ?[]const u8 = null,
    writes: std.ArrayList(Write) = .empty,

    pub const Write = struct { key: []const u8, immutable: bool };

    /// answer answers aws s3 cp, or returns null for any other command.
    pub fn answer(b: *FakeBucket, s: *Sys, argv: []const []const u8) !?sys.Result {
        if (argv.len < 3 or !mem.eql(u8, argv[0], "aws") or !mem.eql(u8, argv[1], "s3") or
            !mem.eql(u8, argv[2], "cp")) return null;
        const from = argv[argv.len - 2];
        const to = argv[argv.len - 1];
        if (mem.startsWith(u8, from, "s3://")) {
            const source = try sys.join(s, &.{ b.root, keyOf(from) });
            if (!sys.exists(
                s,
                source,
            )) return .{
                .term = .{ .exited = 1 },
                .stderr = "An error occurred (404) when calling the HeadObject operation: Not " ++
                    "Found",
            };
            try sys.copy(s, source, to);
            return sys.Result.passed;
        }
        const key = keyOf(to);
        if (b.fail) |suffix| if (mem.endsWith(
            u8,
            key,
            suffix,
        )) return .{ .term = .{ .exited = 1 }, .stderr = "injected upload failure" };
        const destination = try sys.join(s, &.{ b.root, key });
        try sys.mkdirs(s, std.fs.path.dirname(destination).?);
        try sys.copy(s, from, destination);
        var immutable = false;
        for (argv, 0..) |a, i| {
            if (mem.eql(
                u8,
                a,
                "--cache-control",
            )) immutable = mem.endsWith(u8, argv[i + 1], "immutable");
        }
        try b.writes.append(s.gpa, .{ .key = try s.gpa.dupe(u8, key), .immutable = immutable });
        return sys.Result.passed;
    }

    /// keyOf drops s3://BUCKET/ from an object URL.
    fn keyOf(url: []const u8) []const u8 {
        const rest = url["s3://".len..];
        const slash = mem.findScalar(u8, rest, '/') orelse return "";
        return rest[slash + 1 ..];
    }
};
