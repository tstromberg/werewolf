//! packages holds build's steps that install packages with apko: the
//! form's apko config, the locks, the root's packages and the kernel's.
//! See build.zig.

const std = @import("std");
const forms = @import("form");
const compose = @import("compose");
const image = @import("image");
const package = @import("package");
const progress = @import("progress.zig");
const build = @import("build.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const B = build.B;

/// apkoConfig writes the chain's apko config, its forms' packages, accounts and paths merged,
/// and under dev the dev packages after the rest. It is replaced only when
/// it says something new, so a change to howl that changes nothing apko
/// is asked for rebuilds no root.
pub fn apkoConfig(b: *B, target: []const u8) !void {
    var extra: std.ArrayList([]const u8) = .empty;
    if (b.spec.dev) {
        try extra.append(b.gpa, "busybox-full");
        for (b.chain) |c| for (try c.items(b.gpa, "dev")) |item| {
            var it = mem.tokenizeAny(u8, item, " \t");
            while (it.next()) |pkg| try extra.append(b.gpa, pkg);
        };
    }
    var f: forms.Failure = .{};
    var node = compose.apko(
        b.io,
        b.gpa,
        Dir.cwd(),
        b.chain,
        extra.items,
        &f,
    ) catch |err| switch (err) {
        error.Form => return b.steps.fail(f.text),
        else => |e| return e,
    };
    // Published, werewolf's repository, its key under the name the index's
    // signature gives, and as packages the forms from it, which bring
    // theirs, and the rest's (compose.published).
    if (b.spec.published) {
        const key = try b.path("{s}/keys/{s}", .{ b.p.build, package.repository_key });
        const pub_key = package.repository_pem ++ "\n";
        const had = Dir.cwd().readFileAlloc(b.io, key, b.gpa, .limited(64 << 10)) catch "";
        if (!mem.eql(u8, had, pub_key)) {
            try Dir.cwd().createDirPath(b.io, std.fs.path.dirname(key).?);
            try b.write(key, pub_key);
        }
        const keyring = try b.path("../keys/{s}", .{package.repository_key});
        node = try compose.published(b.gpa, node, b.chain, b.from_repo, extra.items, keyring);
    }
    var out: Io.Writer.Allocating = .init(b.gpa);
    try forms.write(&out.writer, node);
    const was = Dir.cwd().readFileAlloc(b.io, target, b.gpa, .limited(1 << 20)) catch "";
    if (mem.eql(u8, was, out.written())) return;
    if (progress.phaseOf(target)) |ph| try b.steps.enter(ph);
    try Dir.cwd().createDirPath(b.io, std.fs.path.dirname(target).?);
    try b.write(target, out.written());
    try b.steps.note("{s} written", .{target});
}

/// relock resolves target, an apko lock of config for both arches, from
/// the repositories as they are now, when it is missing or older than
/// inputs.
pub fn relock(b: *B, target: []const u8, config: []const u8, inputs: []const []const u8) !void {
    const began = try b.begin(target, inputs) orelse return;
    try Dir.cwd().createDirPath(b.io, "build/lock");
    const t = try b.tmp(target);
    const out = try b.absolute(t);
    try apko(b, config, &.{ "lock", "--arch", "aarch64,x86_64", "--output", out }, &.{});
    try b.rename(t, target);
    try b.done(target, began);
}

/// apkoBuild installs config's packages into target, a tar, verified
/// against its keyring, at the versions the repositories hold now; with
/// freeze, pinned to those lock names, for a reproducible build.
pub fn apkoBuild(
    b: *B,
    target: []const u8,
    config: []const u8,
    lock: []const u8,
    inputs: []const []const u8,
) !void {
    const began = try b.begin(target, inputs) orelse return;
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(b.gpa, &.{ "build-minirootfs", "--build-arch", @tagName(b.spec.arch) });
    if (b.spec.freeze) {
        const locked = try b.read(lock, 64 << 20);
        for (try pins(b.gpa, locked, @tagName(b.spec.arch))) |pin|
            try args.appendSlice(b.gpa, &.{ "-p", pin });
    }
    try Dir.cwd().createDirPath(b.io, std.fs.path.dirname(target).?);
    const t = try b.tmp(target);
    try apko(b, config, args.items, &.{try b.absolute(t)});
    try b.rename(t, target);
    try b.done(target, began);
}

/// apko runs `apko ARGS CONFIG AFTER` in config's directory, where apko
/// resolves its relative paths. It tries again 15, 30 and 45 seconds on
/// when apko fails to reach the package server: Wolfi's turns a burst of
/// requests away for a few seconds. Any other failure fails at once.
fn apko(b: *B, config: []const u8, args: []const []const u8, after: []const []const u8) !void {
    const argv = try mem.concat(
        b.gpa,
        []const u8,
        &.{ &.{"apko"}, args, &.{std.fs.path.basename(config)}, after },
    );
    const dir = std.fs.path.dirname(config).?;
    var t: i64 = 1;
    while (true) : (t += 1) {
        const ran = try b.steps.exec(&.{.{ .argv = argv, .cwd = dir }}, .{});
        if (ran.ok) return;
        if (t == 4 or !unreachableServer(ran.output))
            return b.fail("apko {s} {s} failed", .{ args[0], config });
        try b.steps.note(
            "apko could not reach the package server; trying again in {d}s",
            .{t * 15},
        );
        try b.io.sleep(.fromSeconds(t * 15), .awake);
    }
}

/// unreachableServer reports whether apko's output says it could not
/// reach the package server (Makefile, APKO_NETWORK).
fn unreachableServer(output: []const u8) bool {
    for ([_][]const u8{
        "connection reset", "i/o timeout",     "TLS handshake",   "deadline exceeded",
        "unexpected EOF",   "failed to fetch", "status code 403", "status code 408",
        "status code 429",
    }) |s| if (mem.find(u8, output, s) != null) return true;
    const key = "status code 5";
    var at: usize = 0;
    while (mem.findPos(u8, output, at, key)) |i| : (at = i + 1) {
        const code = output[i + key.len ..];
        if (code.len >= 2 and std.ascii.isDigit(code[0]) and
            std.ascii.isDigit(code[1])) return true;
    }
    return false;
}

/// pins returns the packages a lock names for arch, NAME=VER-rN each, from
/// the lock's "url" lines.
pub fn pins(gpa: Allocator, lock: []const u8, arch: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var lines = mem.splitScalar(u8, lock, '\n');
    while (lines.next()) |line| {
        // NAME-VER-rN, where VER has no dash.
        const apk = apkOf(line, arch) orelse continue;
        const rel = mem.findScalarLast(u8, apk, '-') orelse continue;
        if (apk.len < rel + 2 or apk[rel + 1] != 'r' or !digits(apk[rel + 2 ..])) continue;
        const ver = mem.findScalarLast(u8, apk[0..rel], '-') orelse continue;
        try out.append(gpa, try gpa.print("{s}={s}", .{ apk[0..ver], apk[ver + 1 ..] }));
    }
    return out.items;
}

fn digits(s: []const u8) bool {
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// lockedKernel returns the kernel packages a lock names for arch,
/// linux-virt-VER-rN, separated by spaces.
pub fn lockedKernel(gpa: Allocator, lock: []const u8, arch: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = mem.splitScalar(u8, lock, '\n');
    while (lines.next()) |line| {
        const apk = apkOf(line, arch) orelse continue;
        if (!mem.startsWith(u8, apk, "linux-virt-") or
            mem.findScalar(u8, apk, '/') != null) continue;
        if (out.items.len > 0) try out.append(gpa, ' ');
        try out.appendSlice(gpa, apk);
    }
    return out.items;
}

/// apkOf returns what follows /ARCH/ in a lock line's "url", without
/// .apk, or null if the line names no package of arch.
fn apkOf(line: []const u8, arch: []const u8) ?[]const u8 {
    const key = "\"url\": \"";
    const at = mem.findLast(u8, line, key) orelse return null;
    const rest = line[at + key.len ..];
    const url = rest[0 .. mem.findScalar(u8, rest, '"') orelse return null];
    if (!mem.endsWith(u8, url, ".apk")) return null;
    var buf: [32]u8 = undefined;
    const dir = std.mem.print(&buf, "/{s}/", .{arch}) catch return null;
    const in = mem.findLast(u8, url, dir) orelse return null;
    return url[in + dir.len .. url.len - ".apk".len];
}

// --- kernel -----------------------------------------------------------------------------

/// kernel installs Alpine's linux-virt, unpacks its kernel, modules and
/// config into BUILD/kernel/x, checks the config for what werewolf relies
/// on it to leave out (image.configMisses), and writes BUILD/vmlinuz.
pub fn kernel(b: *B) !void {
    const yaml = "boot/kernel.yaml";
    const lock = "build/lock/kernel.lock.json";
    const rootfs = try b.path("{s}/kernel/rootfs.tar", .{b.p.build});
    try relock(b, lock, yaml, &.{yaml});
    try apkoBuild(b, rootfs, yaml, lock, &.{lock});
    const target = try b.path("{s}/vmlinuz", .{b.p.build});
    // The step's own stamp says when it last ran; vmlinuz is rewritten only
    // when its bytes change, so a new howl that unpacks the same kernel
    // leaves what is built from it, melange's guest among them, up to date.
    const stamp = try b.path("{s}/kernel/unpacked", .{b.p.build});
    Dir.cwd().access(b.io, target, .{}) catch Dir.cwd().deleteFile(b.io, stamp) catch {};
    const began = try b.begin(stamp, &.{ rootfs, b.self }) orelse return;
    const x = try b.path("{s}/kernel/x", .{b.p.build});
    try Dir.cwd().deleteTree(b.io, x);
    try Dir.cwd().createDirPath(b.io, x);
    var config: ?[]const u8 = null;
    var names = mem.splitScalar(u8, try b.capture(target, &.{ "bsdtar", "-tf", rootfs }), '\n');
    while (names.next()) |n| if (mem.startsWith(u8, n, "boot/config-")) {
        if (config != null) return b.fail("{s}: more than one boot/config-", .{rootfs});
        config = n;
    };
    const cfg = config orelse return b.fail("{s}: no boot/config-", .{rootfs});
    try b.run(&.{ "bsdtar", "-xf", rootfs, "-C", x, "boot/vmlinuz-virt", "lib/modules", cfg }, .{});
    const config_text = try b.read(try b.path("{s}/{s}", .{ x, cfg }), 4 << 20);
    const misses = try image.configMisses(b.gpa, config_text);
    for (misses) |m| try b.steps.note("kernel config: {f}", .{m});
    if (misses.len > 0) return b.fail("{s} reopens what werewolf relies on it to close", .{cfg});
    // On aarch64 Alpine ships an EFI zboot image, which QEMU boots and
    // Apple's Virtualization framework does not: unwrap it.
    const shipped = try b.read(try b.path("{s}/boot/vmlinuz-virt", .{x}), image.max_gunzip);
    const kern = image.unwrapZboot(b.gpa, shipped) catch |err|
        return b.fail("{s}: {t}", .{ target, err });
    // unwrapZboot returns any other image as it is.
    if (kern.ptr != shipped.ptr) try b.steps.note(
        "unwrapping EFI zboot image (payload at {d}, {d} bytes)",
        .{ mem.readInt(u32, shipped[8..12], .little), mem.readInt(u32, shipped[12..16], .little) },
    );
    const was = Dir.cwd().readFileAlloc(b.io, target, b.gpa, .limited(image.max_gunzip)) catch "";
    if (!mem.eql(u8, was, kern)) try b.write(target, kern);
    try b.write(stamp, "");
    try b.done(target, began);
}

/// vmlinux unpacks x86_64's bzImage into the ELF kernel Firecracker boots.
pub fn vmlinux(b: *B) !void {
    const src = try b.path("{s}/vmlinuz", .{b.p.build});
    const target = try b.path("{s}/vmlinux", .{b.p.build});
    const began = try b.begin(target, &.{src}) orelse return;
    const elf = image.vmlinux(b.gpa, try b.read(src, image.max_gunzip)) catch |err|
        return b.fail("{s}: {t}", .{ src, err });
    try b.write(target, elf);
    try b.done(target, began);
}

const testing = std.testing;

test pins {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const lock =
        \\        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/APKINDEX.tar.gz",
        \\        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/zlib-1.3.1-r0.apk",
        \\        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/ca-certificates-bundle-20260909-r0.apk",
        \\        "url": "https://packages.wolfi.dev/os/aarch64/py3.13-pip-25.2-r1.apk",
        \\        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/linux-virt-6.18.55-r0.apk",
        \\        "url": "https://packages.wolfi.dev/os/aarch64/odd-1.0.apk",
        \\
    ;
    const p = try pins(a, lock, "aarch64");
    try testing.expectEqual(3, p.len);
    try testing.expectEqualStrings("ca-certificates-bundle=20260909-r0", p[0]);
    try testing.expectEqualStrings("py3.13-pip=25.2-r1", p[1]);
    try testing.expectEqualStrings("linux-virt=6.18.55-r0", p[2]);
    try testing.expectEqualStrings("zlib=1.3.1-r0", (try pins(a, lock, "x86_64"))[0]);
    try testing.expectEqualStrings("linux-virt-6.18.55-r0", try lockedKernel(a, lock, "aarch64"));
    try testing.expectEqualStrings("", try lockedKernel(a, lock, "x86_64"));
}

test unreachableServer {
    try testing.expect(
        unreachableServer("GET https://x: unexpected status code 503 Service Unavailable"),
    );
    try testing.expect(unreachableServer("read tcp: connection reset by peer"));
    try testing.expect(!unreachableServer("unexpected status code 404 Not Found"));
    try testing.expect(!unreachableServer("solving \"foo\": nothing provides foo"));
}
