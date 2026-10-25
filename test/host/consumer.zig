//! consumer sets up a source-free howl user for checks of published
//! images: build tools that refuse, an environment without vendor keys,
//! ssh with one identity, and the public TLS roots plus a test mirror's.

const std = @import("std");
const pem = @import("pem.zig");
const quote = @import("check.zig").quote;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const Environ = std.process.Environ;

/// build_tools are what a consumer that built something would run.
pub const build_tools = [_][]const u8{
    "apko", "melange", "zig", "make", "gmake", "mkfs.erofs", "mformat", "mke2fs",
};

/// refuseBuilds writes, in dir, each build tool as a program that says
/// the consumer attempted a build and fails.
pub fn refuseBuilds(io: Io, gpa: Allocator, dir: []const u8) !void {
    for (build_tools) |tool| {
        const script = try gpa.print(
            "#!/bin/sh\necho \"consumer attempted a build: {s}\" >&2\nexit 99\n",
            .{tool},
        );
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = try std.fs.path.join(gpa, &.{ dir, tool }),
            .data = script,
            .flags = .{ .permissions = .fromMode(0o755) },
        });
    }
}

/// sshWith writes dir/ssh, which runs the real ssh with only identity,
/// no user configuration, and never a prompt.
pub fn sshWith(
    io: Io,
    gpa: Allocator,
    dir: []const u8,
    real: []const u8,
    identity: []const u8,
) !void {
    return sshWithProvider(io, gpa, dir, real, identity, null);
}

/// A host-only software security key exercises a form's FIDO-only policy
/// without weakening the guest's accepted key types.
pub fn sshWithProvider(
    io: Io,
    gpa: Allocator,
    dir: []const u8,
    real: []const u8,
    identity: []const u8,
    provider: ?[]const u8,
) !void {
    const option = if (provider) |p|
        try gpa.print(" -o {s}", .{try quote(gpa, try gpa.print("SecurityKeyProvider={s}", .{p}))})
    else
        "";
    const script = try gpa.print(
        "#!/bin/sh\nexec {s} -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -i {s}{s} " ++
            "\"$@\"\n",
        .{ try quote(gpa, real), try quote(gpa, identity), option },
    );
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = try std.fs.path.join(gpa, &.{ dir, "ssh" }),
        .data = script,
        .flags = .{ .permissions = .fromMode(0o755) },
    });
}

/// scrub removes what only a vendor's build host holds: boot, IPE,
/// protected-image and TPM signing settings, the UKI stub, the build VM.
pub fn scrub(gpa: Allocator, env: *Environ.Map) !void {
    var doomed: std.ArrayList([]const u8) = .empty;
    var it = env.iterator();
    while (it.next()) |e| {
        const name = e.key_ptr.*;
        for ([_][]const u8{
            "WEREWOLF_BOOT_",
            "WEREWOLF_IPE_",
            "WEREWOLF_PROTECTED_",
            "WEREWOLF_TPM_",
        }) |p| {
            if (mem.startsWith(u8, name, p)) break;
        } else if (!mem.eql(u8, name, "UKI_STUB") and
            !mem.eql(u8, name, "WEREWOLF_BUILD_VM")) continue;
        try doomed.append(gpa, try gpa.dupe(u8, name));
    }
    for (doomed.items) |name| _ = env.swapRemove(name);
}

/// which is the first executable named name on env's PATH.
pub fn which(io: Io, gpa: Allocator, env: *const Environ.Map, name: []const u8) ?[]const u8 {
    var dirs = mem.tokenizeScalar(u8, env.get("PATH") orelse return null, ':');
    while (dirs.next()) |dir| {
        const p = std.fs.path.join(gpa, &.{ dir, name }) catch return null;
        Io.Dir.cwd().access(io, p, .{ .execute = true }) catch continue;
        return p;
    }
    return null;
}

/// system_bundles are where Linux distributions, macOS and Homebrew keep
/// the public TLS roots.
pub const system_bundles = [_][]const u8{
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/usr/local/etc/ca-certificates/cert.pem",
};

/// mirrorRoots is the public roots this host trusts, from SSL_CERT_FILE,
/// CURL_CA_BUNDLE and every one of bundles there is, then mirror: a
/// client given it keeps public TLS while it trusts a private mirror. It
/// refuses when there are no public roots, rather than trust the mirror
/// alone.
pub fn mirrorRoots(
    io: Io,
    gpa: Allocator,
    env: *const Environ.Map,
    bundles: []const []const u8,
    mirror: []const u8,
) ![]u8 {
    var files: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{ "SSL_CERT_FILE", "CURL_CA_BUNDLE" }) |name|
        if (env.get(name)) |f| try files.append(gpa, f);
    try files.appendSlice(gpa, bundles);
    var out: std.ArrayList(u8) = .empty;
    var seen: std.ArrayList([]const u8) = .empty;
    for (files.items) |f| {
        const text = Io.Dir.cwd().readFileAlloc(io, f, gpa, .limited(16 << 20)) catch continue;
        for (try pem.certificates(gpa, text)) |cert| {
            for (seen.items) |der| {
                if (mem.eql(u8, der, cert.der)) break;
            } else {
                try seen.append(gpa, cert.der);
                try out.appendSlice(gpa, try pem.encode(gpa, "CERTIFICATE", cert.der));
            }
        }
    }
    if (seen.items.len == 0) return error.NoPublicRoots;
    try out.appendSlice(gpa, mirror);
    return out.items;
}

test "a private mirror extends the public roots, and needs them" {
    const tls = @import("tls.zig");
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const system = try (try tls.Authority.init(io, gpa, "system")).pem(gpa);
    const mirror = try (try tls.Authority.init(io, gpa, "mirror")).pem(gpa);
    try tmp.dir.writeFile(io, .{ .sub_path = "system.crt", .data = system });
    const system_path = try gpa.print("{s}/system.crt", .{dir});
    var env: Environ.Map = .init(gpa);

    // Fedora's bundle alone, as when Python reported no default file.
    const roots = try mirrorRoots(io, gpa, &env, &.{ system_path, system_path }, mirror);
    try std.testing.expectEqual(2, (try pem.certificates(gpa, roots)).len);
    try std.testing.expect(mem.find(u8, roots, system) != null);
    try std.testing.expect(mem.find(u8, roots, mirror) != null);

    // A bundle curl was told to use counts.
    try env.put("CURL_CA_BUNDLE", system_path);
    try std.testing.expect(mem.find(
        u8,
        try mirrorRoots(io, gpa, &env, &.{}, mirror),
        system,
    ) != null);

    // No public roots: refuse, rather than trust only the mirror.
    _ = env.swapRemove("CURL_CA_BUNDLE");
    const missing = try gpa.print("{s}/missing", .{dir});
    try std.testing.expectError(
        error.NoPublicRoots,
        mirrorRoots(io, gpa, &env, &.{missing}, mirror),
    );
}

test "scrub keeps a consumer free of vendor keys" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var env: Environ.Map = .init(gpa);
    for ([_][]const u8{
        "WEREWOLF_BOOT_KEY", "WEREWOLF_IPE_CRT",  "WEREWOLF_PROTECTED_IMAGE_KEY", "WEREWOLF_TPM_X",
        "UKI_STUB",          "WEREWOLF_BUILD_VM", "PATH",                         "WEREWOLF_DEBUG",
    }) |name| try env.put(name, "x");
    try scrub(gpa, &env);
    try std.testing.expectEqual(2, env.count());
    try std.testing.expect(env.get("PATH") != null and env.get("WEREWOLF_DEBUG") != null);
}
