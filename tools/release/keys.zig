//! keys hands signing keys to builds. A key, a PEM secret or a file, is
//! checked against its committed certificate, put in a private directory
//! (0700, the key 0600) for one child, and removed when the child ends,
//! whatever ends it: a signal is passed on to the child first.

const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const catalog = @import("catalog.zig");

/// withBootKey runs argv with WEREWOLF_BOOT_KEY, a PEM secret or a key
/// file, as a private file matching WEREWOLF_BOOT_CRT (release/boot.crt).
pub fn withBootKey(s: *Sys, argv: []const []const u8) !u8 {
    const guard: Guard = .install();
    defer guard.restore();
    const supplied = s.getenv("WEREWOLF_BOOT_KEY") orelse "";
    if (supplied.len == 0) return s.refuse(
        "WEREWOLF_BOOT_KEY is required; unsigned release builds are refused",
        .{},
    );
    const certificate = try sys.resolve(s, s.getenv("WEREWOLF_BOOT_CRT") orelse "release/boot.crt");
    const work = try sys.scratch(s, null, "ww-release-signing-");
    defer sys.remove(s, work);
    const key = try sys.join(s, &.{ work, "boot.key" });
    try materialize(s, supplied, key);
    // Capture diagnostics: malformed PEM can otherwise expose input text.
    const public = try sys.exec(
        s,
        &.{ "openssl", "pkey", "-in", key, "-pubout" },
        .{ .capture = .both },
    );
    const pinned = try sys.exec(
        s,
        &.{ "openssl", "x509", "-in", certificate, "-pubkey", "-noout" },
        .{ .capture = .both },
    );
    if (!public.ok() or !pinned.ok() or !mem.eql(u8, public.stdout, pinned.stdout))
        return s.refuse("boot key does not match the release certificate", .{});
    var env = try s.env.clone(s.gpa);
    try env.put("WEREWOLF_BOOT_KEY", key);
    try env.put("WEREWOLF_BOOT_CRT", certificate);
    return supervise(s, argv, &env);
}

/// withProtectedKeys runs argv with the dedicated protected boot and image
/// keys, each matching its committed certificate, valid a day more, not a
/// legacy release key, and not each other.
pub fn withProtectedKeys(s: *Sys, argv: []const []const u8) !u8 {
    const guard: Guard = .install();
    defer guard.restore();
    // The child inherits this: its work trees hold signing inputs.
    const umask = std.c.umask(0o077);
    defer _ = std.c.umask(umask);
    const work = try sys.scratch(s, null, "ww-protected-signing-");
    defer sys.remove(s, work);
    var env = try s.env.clone(s.gpa);
    var publics: [2][]const u8 = undefined;
    for ([_][2][]const u8{ .{ "BOOT", "boot" }, .{ "IMAGE", "image" } }, &publics) |kind, *public| {
        const supplied = s.getenv(try s.gpa.print(
            "WEREWOLF_PROTECTED_{s}_KEY",
            .{kind[0]},
        )) orelse "";
        if (supplied.len == 0) return s.refuse("protected signing keys are required", .{});
        const cert = try sys.resolve(s, s.getenv(try s.gpa.print(
            "WEREWOLF_PROTECTED_{s}_CRT",
            .{kind[0]},
        )) orelse
            try s.gpa.print("release/protected/{s}.crt", .{kind[1]}));
        const key = try sys.join(s, &.{ work, try s.gpa.print("{s}.key", .{kind[1]}) });
        try materialize(s, supplied, key);
        public.* = try checked(s, &.{ "openssl", "pkey", "-in", key, "-pubout" });
        const pinned = try checked(s, &.{ "openssl", "x509", "-in", cert, "-pubkey", "-noout" });
        _ = try checked(s, &.{ "openssl", "x509", "-in", cert, "-checkend", "86400", "-noout" });
        if (!mem.eql(
            u8,
            public.*,
            pinned,
        )) return s.refuse("protected key differs from committed certificate", .{});
        // A dedicated identity cannot be the legacy release signer.
        const old = if (kind[0][0] == 'B')
            try checked(s, &.{ "openssl", "x509", "-in", "release/boot.crt", "-pubkey", "-noout" })
        else
            try sys.read(s, "release/image.pub", 64 << 10);
        if (mem.eql(
            u8,
            public.*,
            old,
        )) return s.refuse("protected images cannot reuse legacy signing authority", .{});
        try env.put(try s.gpa.print("WEREWOLF_PROTECTED_{s}_KEY", .{kind[0]}), key);
        try env.put(try s.gpa.print("WEREWOLF_PROTECTED_{s}_CRT", .{kind[0]}), cert);
        const short = if (kind[0][0] == 'B') "BOOT" else "IPE";
        try env.put(try s.gpa.print("WEREWOLF_{s}_KEY", .{short}), key);
        try env.put(try s.gpa.print("WEREWOLF_{s}_CRT", .{short}), cert);
    }
    if (mem.eql(
        u8,
        publics[0],
        publics[1],
    )) return s.refuse("boot and policy authorities must be separate", .{});
    return supervise(s, argv, &env);
}

/// materialize writes a PEM secret, or a copy of a key file, as a new
/// private file.
fn materialize(s: *Sys, supplied: []const u8, key: []const u8) !void {
    const bytes = if (mem.startsWith(u8, supplied, "-----BEGIN "))
        supplied
    else
        try sys.read(s, supplied, 1 << 20);
    const f = try std.Io.Dir.cwd().createFile(
        s.io,
        key,
        .{ .exclusive = true, .permissions = .fromMode(0o600) },
    );
    defer f.close(s.io);
    try f.writeStreamingAll(s.io, bytes);
}

/// checked is what an openssl command printed; its failure, and what it
/// said, stay here: a key's text must never reach a log.
fn checked(s: *Sys, argv: []const []const u8) ![]const u8 {
    const r = try sys.exec(s, argv, .{ .capture = .both });
    if (!r.ok()) return s.refuse("invalid protected signing identity", .{});
    return r.stdout;
}

var child_pid: std.atomic.Value(posix.pid_t) = .init(0);
var interrupted: std.atomic.Value(bool) = .init(false);

/// forward passes a termination on to the child and gives it ten
/// seconds; the alarm then kills it.
fn forward(sig: posix.SIG) callconv(.c) void {
    const pid = child_pid.load(.seq_cst);
    if (sig == .ALRM) {
        if (pid > 0) _ = std.c.kill(pid, .KILL);
        return;
    }
    interrupted.store(true, .seq_cst);
    if (pid > 0) {
        _ = std.c.kill(pid, .TERM);
        _ = std.c.alarm(10);
    }
}

/// Guard catches the signals that end a wrapper from before a key is
/// written until it is removed: a termination is noted and passed on to
/// the child, and the wrapper cleans up and exits 130.
const Guard = struct {
    saved: [signals.len]posix.Sigaction,

    const signals = [_]posix.SIG{ .TERM, .INT, .HUP, .ALRM };

    fn install() Guard {
        var g: Guard = undefined;
        const action: posix.Sigaction = .{
            .handler = .{ .handler = forward },
            .mask = posix.sigemptyset(),
            .flags = posix.SA.RESTART,
        };
        interrupted.store(false, .seq_cst);
        child_pid.store(0, .seq_cst);
        for (signals, &g.saved) |sig, *old| posix.sigaction(sig, &action, old);
        return g;
    }

    fn restore(g: *const Guard) void {
        _ = std.c.alarm(0);
        child_pid.store(0, .seq_cst);
        for (signals, &g.saved) |sig, *old| posix.sigaction(sig, old, null);
    }
};

/// supervise runs argv with env and returns its exit status: 128 and the
/// signal for a child a signal ended, 130 when one ended this wrapper.
fn supervise(s: *Sys, argv: []const []const u8, env: *const std.process.Environ.Map) !u8 {
    if (interrupted.load(.seq_cst)) return 130;
    var child = try std.process.spawn(s.io, .{ .argv = argv, .environ_map = env });
    child_pid.store(child.id.?, .seq_cst);
    if (interrupted.load(.seq_cst)) forward(.TERM);
    const term = try child.wait(s.io);
    if (interrupted.load(.seq_cst)) return 130;
    return switch (term) {
        .exited => |code| code,
        .signal => |sig| 128 +| @as(u8, @truncate(@backingInt(sig))),
        else => 1,
    };
}

/// createTrust makes production trust once: the boot and image keys in
/// private, their certificates committed in public. Partial custody or
/// trust committed without its keys refuses rather than rotating it.
pub fn createTrust(s: *Sys, private_dir: []const u8, public_dir: []const u8) !void {
    const private = try sys.resolve(s, private_dir);
    const public = try sys.resolve(s, public_dir);
    try sys.mkdirs(s, private);
    try std.Io.Dir.cwd().setFilePermissions(s.io, private, .fromMode(0o700), .{});
    try sys.mkdirs(s, public);
    const guard = try std.Io.Dir.cwd().createFile(s.io, try sys.join(
        s,
        &.{ private, "identity.lock" },
    ), .{
        .truncate = false,
        .lock = .exclusive,
    });
    defer guard.close(s.io);
    const names = [_][]const u8{ "boot.key", "boot.crt", "image.key", "image.crt" };
    var existing: usize = 0;
    for (names) |n| {
        if (sys.exists(s, try sys.join(s, &.{ private, n }))) existing += 1;
    }
    if (existing != 0 and existing != names.len)
        return s.refuse("partial protected identity; restore it instead of rotating trust", .{});
    if (existing == 0) {
        for ([_][]const u8{
            "boot.crt",
            "image.crt",
        }) |n| if (sys.exists(s, try sys.join(s, &.{ public, n })))
            return s.refuse("committed trust already exists; restore its private keys", .{});
        const work = try sys.scratch(s, private, "tmp");
        defer sys.remove(s, work);
        for ([_][]const u8{ "boot", "image" }) |kind| {
            const subject = try s.gpa.print("/CN=werewolf-protected-{s}", .{kind});
            const key = try sys.join(s, &.{ work, try s.gpa.print("{s}.key", .{kind}) });
            const cert = try sys.join(s, &.{ work, try s.gpa.print("{s}.crt", .{kind}) });
            const r = try sys.exec(s, &.{
                "openssl", "req",  "-newkey", "rsa:4096", "-nodes",  "-x509", "-sha256",
                "-days",   "3650", "-subj",   subject,    "-keyout", key,     "-out",
                cert,
            }, .{ .capture = .both });
            if (!r.ok()) return s.refuse("protected identity creation failed", .{});
        }
        for (names) |n| try sys.rename(
            s,
            try sys.join(s, &.{ work, n }),
            try sys.join(s, &.{ private, n }),
        );
    }
    for ([_][]const u8{ "boot", "image" }) |kind| {
        const key = try sys.join(s, &.{ private, try s.gpa.print("{s}.key", .{kind}) });
        const cert = try sys.join(s, &.{ private, try s.gpa.print("{s}.crt", .{kind}) });
        const st = try std.Io.Dir.cwd().statFile(s.io, key, .{});
        if (st.permissions.toMode() & 0o777 != 0o600)
            return s.refuse("protected private key permissions must be 0600", .{});
        const a = try sys.output(s, &.{ "openssl", "pkey", "-in", key, "-pubout" });
        const b = try catalog.publicKey(s, cert);
        if (!mem.eql(u8, a, b)) return s.refuse("protected identity key/certificate mismatch", .{});
        const destination = try sys.join(s, &.{ public, try s.gpa.print("{s}.crt", .{kind}) });
        if (sys.exists(s, destination)) {
            if (!mem.eql(u8, try sys.read(s, destination, 1 << 20), try sys.read(s, cert, 1 << 20)))
                return s.refuse("committed protected trust differs; refusing replacement", .{});
        } else {
            try sys.copy(s, cert, destination);
            try std.Io.Dir.cwd().setFilePermissions(s.io, destination, .fromMode(0o644), .{});
        }
    }
}

const testing = std.testing;
const fixture = @import("fixture.zig");

/// probe is a child that reports where its key was and how private, then
/// exits code.
fn probe(
    f: *fixture.Fixture,
    variable: []const u8,
    marker: []const u8,
    code: u8,
) ![]const []const u8 {
    const script = try f.gpa().print(
        \\k=${s}
        \\[ "$(ls -ld "$k" | cut -c1-10)" = "-rw-------" ] || exit 90
        \\[ "$(ls -ld "$(dirname "$k")" | cut -c1-10)" = "drwx------" ] || exit 91
        \\head -c 11 "$k" | grep -q -e '-----BEGIN ' || exit 92
        \\printf %s "$k" >'{s}'
        \\exit {d}
    , .{ variable, marker, code });
    return f.gpa().dupe([]const u8, &.{ "/bin/sh", "-c", script });
}

test "a boot key becomes a private file the child sees and is removed after" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const k = try fixture.keys(&f, "first");
    try f.env.put("WEREWOLF_BOOT_CRT", k.crt);
    const marker = f.path("location");
    // As a PEM secret, then as a file whose bytes must stay as they were.
    const pem = try sys.read(s, k.key, 1 << 20);
    for ([_]struct { []const u8, u8 }{ .{ pem, 0 }, .{ k.key, 23 } }) |c| {
        try f.env.put("WEREWOLF_BOOT_KEY", c[0]);
        try testing.expectEqual(
            c[1],
            try withBootKey(s, try probe(&f, "WEREWOLF_BOOT_KEY", marker, c[1])),
        );
        const seen = try sys.read(s, marker, 4096);
        try testing.expect(!sys.exists(s, seen));
        try testing.expect(!sys.exists(s, std.fs.path.dirname(seen).?));
    }
    try testing.expectEqualStrings(pem, try sys.read(s, k.key, 1 << 20));
}

test "a wrong, missing or malformed boot key refuses before the child runs, unechoed" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    try f.env.put("WEREWOLF_BOOT_CRT", (try fixture.keys(&f, "first")).crt);
    const marker = f.path("must-not-run");
    const argv = [_][]const u8{ "/bin/sh", "-c", try f.gpa().print("touch '{s}'", .{marker}) };
    const secret = "-----BEGIN PRIVATE KEY-----\nPRIVATE_SENTINEL_DO_NOT_LOG\n-----END PRIVATE " ++
        "KEY-----";
    for ([_][]const u8{
        "",
        (try fixture.keys(&f, "other")).key,
        "-----BEGIN INVALID PRIVATE KEY-----\nsecret",
        secret,
    }) |supplied| {
        try f.env.put("WEREWOLF_BOOT_KEY", supplied);
        try testing.expectError(error.Refused, withBootKey(s, &argv));
        try testing.expect(!sys.exists(s, marker));
        try testing.expect(mem.find(u8, s.why.text, "SENTINEL") == null);
    }
}

fn protectedEnv(f: *fixture.Fixture) !void {
    for ([_][2][]const u8{ .{ "BOOT", "boot" }, .{ "IMAGE", "image" } }) |kind| {
        const k = try fixture.keys(f, kind[1]);
        try f.env.put(
            try f.gpa().print("WEREWOLF_PROTECTED_{s}_KEY", .{kind[0]}),
            try sys.read(&f.s, k.key, 1 << 20),
        );
        try f.env.put(try f.gpa().print("WEREWOLF_PROTECTED_{s}_CRT", .{kind[0]}), k.crt);
    }
}

test "protected keys become private files and are removed after success or failure" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    try protectedEnv(&f);
    for ([_]u8{
        0,
        7,
    }) |code| for ([_][]const u8{ "WEREWOLF_BOOT_KEY", "WEREWOLF_IPE_KEY" }) |variable| {
        const marker = f.path("key-location");
        try testing.expectEqual(
            code,
            try withProtectedKeys(s, try probe(&f, variable, marker, code)),
        );
        try testing.expect(!sys.exists(s, try sys.read(s, marker, 4096)));
    };
}

test "missing, foreign, malformed or shared protected keys never run the child" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const marker = f.path("must-not-execute");
    const argv = [_][]const u8{ "/bin/sh", "-c", try f.gpa().print("touch '{s}'", .{marker}) };
    const secret = "-----BEGIN PRIVATE KEY-----\nSECRET_SENTINEL\n-----END PRIVATE KEY-----";
    for ([_][]const u8{
        "",
        try sys.read(s, (try fixture.keys(&f, "foreign")).key, 1 << 20),
        "-----BEGIN INVALID PRIVATE KEY-----\nsecret",
        secret,
    }) |value| {
        try protectedEnv(&f);
        try f.env.put("WEREWOLF_PROTECTED_BOOT_KEY", value);
        try testing.expectError(error.Refused, withProtectedKeys(s, &argv));
        try testing.expect(!sys.exists(s, marker));
        try testing.expect(mem.find(u8, s.why.text, "SENTINEL") == null);
    }
    try protectedEnv(&f);
    try f.env.put("WEREWOLF_PROTECTED_IMAGE_KEY", f.env.get("WEREWOLF_PROTECTED_BOOT_KEY").?);
    try f.env.put("WEREWOLF_PROTECTED_IMAGE_CRT", f.env.get("WEREWOLF_PROTECTED_BOOT_CRT").?);
    try testing.expectError(error.Refused, withProtectedKeys(s, &argv));
    try testing.expectEqualStrings("boot and policy authorities must be separate", s.why.text);
    try testing.expect(!sys.exists(s, marker));
}

test "a termination reaches the child and still removes the key" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const k = try fixture.keys(&f, "first");
    try f.env.put("WEREWOLF_BOOT_CRT", k.crt);
    try f.env.put("WEREWOLF_BOOT_KEY", k.key);
    const marker = f.path("location");
    const script = try f.gpa().print(
        "printf %s \"$WEREWOLF_BOOT_KEY\" >'{s}'; kill -TERM $PPID; exec sleep 30",
        .{marker},
    );
    try testing.expectEqual(@as(u8, 130), try withBootKey(s, &.{ "/bin/sh", "-c", script }));
    try testing.expect(!sys.exists(s, try sys.read(s, marker, 4096)));
}

test "trust is created once and never rotated, replaced or partial" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const private = f.path("partial/private");
    const public = f.path("partial/public");
    try sys.mkdirs(s, private);
    try sys.mkdirs(s, public);
    try sys.write(s, try sys.join(s, &.{ private, "boot.key" }), "partial");
    try testing.expectError(error.Refused, createTrust(s, private, public));
    try std.Io.Dir.cwd().deleteFile(s.io, try sys.join(s, &.{ private, "boot.key" }));
    try sys.write(s, try sys.join(s, &.{ public, "boot.crt" }), "committed");
    try testing.expectError(error.Refused, createTrust(s, private, public));
    try testing.expect(!sys.exists(s, try sys.join(s, &.{ private, "boot.key" })));

    const kept = f.path("kept/private");
    const pins = f.path("kept/public");
    try sys.mkdirs(s, kept);
    for ([_][]const u8{ "boot", "image" }) |kind| {
        const k = try fixture.keys(&f, kind);
        for ([_][2][]const u8{ .{ k.key, ".key" }, .{ k.crt, ".crt" } }) |pair| {
            const target = try sys.join(
                s,
                &.{ kept, try f.gpa().print("{s}{s}", .{ kind, pair[1] }) },
            );
            try sys.write(s, target, try sys.read(s, pair[0], 1 << 20));
            try std.Io.Dir.cwd().setFilePermissions(s.io, target, .fromMode(0o600), .{});
        }
    }
    try createTrust(s, kept, pins);
    const pin = try sys.join(s, &.{ pins, "boot.crt" });
    const original = try sys.read(s, pin, 1 << 20);
    try createTrust(s, kept, pins);
    try testing.expectEqualStrings(original, try sys.read(s, pin, 1 << 20));
    try sys.write(s, pin, "other pin");
    try testing.expectError(error.Refused, createTrust(s, kept, pins));
    try testing.expectEqualStrings("other pin", try sys.read(s, pin, 1 << 20));
}
