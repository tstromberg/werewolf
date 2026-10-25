//! firmware provisions the tested public Secure Boot firmware and
//! virt-firmware's virt-fw-vars for native enrollment, with no build VM:
//! `howl _native-firmware ARCH`, which tools/enroll-boot runs. See
//! docs/macos-builds.md.

const std = @import("std");
const builtin = @import("builtin");
const howl = @import("howl.zig");
const fetching = @import("boot-download");
const prebuilt = @import("prebuilt");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const package_url = "https://ports.ubuntu.com/ubuntu-ports/pool/main/e/edk2/" ++
    "qemu-efi-aarch64_2024.02-2ubuntu0.10_all.deb";
const package: prebuilt.Artifact = .{
    .size = 4114848,
    .sha256 = "fad8e80e929cd00dae8c5c8e5dd3ec85f37d9a832eea776957e5e2cf86ef2ab5",
};

/// Part is one file of the tested pair, by its name in the cache and in
/// the package.
const Part = struct { name: []const u8, member: []const u8, sha256: []const u8 };

/// pair is the secure code and the empty variable store. The package's
/// default and snakeoil trust and its sample keys never reach the cache.
const pair = [_]Part{ .{
    .name = "code.fd",
    .member = "./usr/share/AAVMF/AAVMF_CODE.secboot.fd",
    .sha256 = "d37119b2c1173ecdc88d09c00848842fdf575899403b7549a5b51f06766c20d6",
}, .{
    .name = "template.fd",
    .member = "./usr/share/AAVMF/AAVMF_VARS.fd",
    .sha256 = "b3b855c5a80310168051164986855692d1bdb06e67619856177965cd87c6774f",
} };
const part_size = 64 << 20;

pub const Firmware = struct { code: []const u8, template: []const u8, tool: []const u8 };

/// Python is the interpreter virt-fw-vars runs on, and what it says it is.
pub const Python = struct { path: []const u8, version: []const u8 };

/// candidates are where an interpreter the pinned wheels support may be,
/// in the order tried: the default, then by version, newest first, on PATH,
/// then where Homebrew and /usr/local put them, for a PATH that has neither.
fn candidates(gpa: Allocator) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    try out.append(gpa, "python3");
    for ([_][]const u8{ "", "/opt/homebrew/bin/", "/usr/local/bin/" }) |dir| {
        var minor: u8 = 14;
        while (minor >= 10) : (minor -= 1) try out.append(gpa, try gpa.print("{s}python3.{d}", .{
            dir, minor,
        }));
    }
    return out.items;
}

/// supported reports whether `python --version` printed 3.10 to 3.14.
fn supported(version: []const u8) bool {
    const number = std.mem.cutPrefix(u8, std.mem.trim(u8, version, " \r\n"), "Python 3.") orelse
        return false;
    const end = std.mem.findScalar(u8, number, '.') orelse number.len;
    const minor = std.fmt.parseInt(u8, number[0..end], 10) catch return false;
    return minor >= 10 and minor <= 14;
}

/// interpreter is the first candidate that runs and is supported. Xcode's
/// may be too old and Homebrew's default newer than the pinned wheels.
pub fn interpreter(io: Io, gpa: Allocator) !?Python {
    for (try candidates(gpa)) |path| {
        const result = std.process.run(gpa, io, .{
            .argv = &.{ path, "--version" },
            .stdout_limit = .limited(4096),
            .stderr_limit = .limited(4096),
        }) catch continue;
        if (result.term == .exited and result.term.exited == 0 and supported(result.stdout))
            return .{ .path = path, .version = std.mem.trim(u8, result.stdout, " \r\n") };
    }
    return null;
}

/// valid reports whether directory holds parts: regular files of exactly
/// their size and bytes.
fn valid(io: Io, gpa: Allocator, directory: []const u8, parts: []const Part) bool {
    for (parts) |p| {
        const path = gpa.print("{s}/{s}", .{ directory, p.name }) catch return false;
        const st = Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return false;
        if (st.kind != .file or st.size != part_size) return false;
        const got = fetching.sha256(io, path) catch return false;
        if (!std.mem.eql(u8, &got, p.sha256)) return false;
    }
    return true;
}

/// extract writes parts from the authenticated package's data.tar.zst,
/// and nothing else from it, into directory.
fn extract(
    io: Io,
    gpa: Allocator,
    deb: []const u8,
    directory: []const u8,
    parts: []const Part,
) !void {
    const file = try Dir.cwd().openFile(io, deb, .{});
    defer file.close(io);
    var buf: [64 << 10]u8 = undefined;
    var reader = file.reader(io, &buf);
    const r = &reader.interface;
    if (!std.mem.eql(u8, try r.takeArray(8), "!<arch>\n")) return error.BadFirmwarePackage;
    while (true) {
        const header = try r.takeArray(60);
        if (!std.mem.eql(u8, header[58..60], "`\n")) return error.BadFirmwarePackage;
        const size = std.fmt.parseInt(u64, std.mem.trim(u8, header[48..58], " "), 10) catch
            return error.BadFirmwarePackage;
        if (!std.mem.eql(u8, std.mem.trimEnd(u8, header[0..16], " /"), "data.tar.zst")) {
            try r.discardAll64(size + size % 2);
            continue;
        }
        var compressed: [64 << 10]u8 = undefined;
        var limited = r.limited(.limited64(size), &compressed);
        const window = try gpa.alloc(u8, std.compress.zstd.default_window_len +
            std.compress.zstd.block_size_max);
        defer gpa.free(window);
        var zstd: std.compress.zstd.Decompress = .init(&limited.interface, window, .{});
        var names: [256]u8 = undefined;
        var links: [256]u8 = undefined;
        var it: std.tar.Iterator = .init(&zstd.reader, .{
            .file_name_buffer = &names,
            .link_name_buffer = &links,
        });
        var found: usize = 0;
        while (try it.next()) |entry| for (parts) |p| {
            if (entry.kind != .file or !std.mem.eql(u8, entry.name, p.member)) continue;
            const out = try Dir.cwd().createFile(io, try gpa.print("{s}/{s}", .{
                directory, p.name,
            }), .{ .exclusive = true, .permissions = .fromMode(0o600) });
            defer out.close(io);
            var wbuf: [64 << 10]u8 = undefined;
            var w = out.writer(io, &wbuf);
            try it.streamRemaining(entry, &w.interface);
            try w.interface.flush();
            found += 1;
        };
        if (found != parts.len) return error.UntestedFirmware;
        return;
    }
}

fn isFile(io: Io, path: []const u8) bool {
    const st = Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return false;
    return st.kind == .file;
}

/// run runs argv to success, its output on standard error: standard output
/// is the verb's answer.
fn run(io: Io, argv: []const []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .{ .file = Io.File.stderr() },
    });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) return error.FirmwareToolFailed;
}

/// provision returns the tested firmware pair and virt-fw-vars for arch,
/// from cache when they are there and intact. The package is authenticated
/// before anything parses it, and the tools are installed only from the
/// pinned wheels.
pub fn provision(
    io: Io,
    gpa: Allocator,
    transport: fetching.Transport,
    python: Python,
    arch: []const u8,
    cache: []const u8,
) !Firmware {
    if (!std.mem.eql(u8, arch, "aarch64")) return error.UnsupportedFirmwareArch;
    const requirements = @import("files").firmware_requirements;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(requirements, &digest, .{});
    h.update(&std.fmt.bytesToHex(digest, .lower));
    h.update(package.sha256);
    h.update(python.version);
    h.update(@tagName(builtin.cpu.arch));
    const identity = std.fmt.bytesToHex(h.finalResult(), .lower);
    const target = try gpa.print("{s}/{s}", .{ cache, &identity });
    _ = try Dir.cwd().createDirPathStatus(io, target, .fromMode(0o700));
    const guard = try Dir.cwd().createFile(io, try gpa.print("{s}/native.lock", .{cache}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    if (!valid(io, gpa, target, &pair)) try fetchPair(io, gpa, transport, target, &pair);
    const env = try gpa.print("{s}/venv", .{target});
    const marker = try gpa.print("{s}/tools-complete", .{target});
    const tool = try gpa.print("{s}/bin/virt-fw-vars", .{env});
    if (!isFile(io, marker) or !isFile(io, tool)) {
        try Dir.cwd().deleteTree(io, env);
        const pinned = try gpa.print("{s}/requirements.txt", .{target});
        try Dir.cwd().writeFile(io, .{ .sub_path = pinned, .data = requirements });
        try run(io, &.{ python.path, "-m", "venv", env });
        try run(io, &.{
            try gpa.print("{s}/bin/python", .{env}), "-m",
            "pip",                                   "install",
            "--disable-pip-version-check",           "--require-hashes",
            "--no-deps",                             "--only-binary=:all:",
            "-r",                                    pinned,
        });
        try run(io, &.{ tool, "--help" });
        try Dir.cwd().writeFile(
            io,
            .{ .sub_path = marker, .data = try gpa.print("{s}\n", .{&identity}) },
        );
    }
    return .{
        .code = try gpa.print("{s}/code.fd", .{target}),
        .template = try gpa.print("{s}/template.fd", .{target}),
        .tool = tool,
    };
}

fn fetchPair(
    io: Io,
    gpa: Allocator,
    transport: fetching.Transport,
    target: []const u8,
    parts: []const Part,
) !void {
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const work = try gpa.print("{s}/public-firmware-{x}", .{ target, &nonce });
    try Dir.cwd().createDir(io, work, .fromMode(0o700));
    defer Dir.cwd().deleteTree(io, work) catch {};
    const deb = try gpa.print("{s}/firmware.deb", .{work});
    try transport.fetch(transport.context, package_url, deb, package.size, package);
    const st = try Dir.cwd().statFile(io, deb, .{ .follow_symlinks = false });
    if (st.kind != .file or st.size != package.size or
        !std.mem.eql(u8, &try fetching.sha256(io, deb), package.sha256))
        return error.UntrustedFirmwarePackage;
    try extract(io, gpa, deb, work, parts);
    if (!valid(io, gpa, work, parts)) return error.UntestedFirmware;
    for (parts) |p| try Dir.rename(
        Dir.cwd(),
        try gpa.print("{s}/{s}", .{ work, p.name }),
        Dir.cwd(),
        try gpa.print("{s}/{s}", .{ target, p.name }),
        io,
    );
}

/// command is `howl _native-firmware ARCH`. It prints virt-fw-vars, the
/// code and the variable template, a path a line, for tools/enroll-boot.
pub fn command(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    if (args.len != 1) return why.refuse("_native-firmware ARCH", .{});
    const python = try interpreter(io, gpa) orelse return why.refuse(
        "native firmware tools need Python 3.10-3.14; run make install-deps",
        .{},
    );
    var h: fetching.Https = undefined;
    try h.init(io, gpa, .{ .ca_file = howl.environ.get("SSL_CERT_FILE"), .environ = howl.environ });
    defer h.deinit();
    const cache = howl.environ.get("WEREWOLF_FIRMWARE_CACHE") orelse "build/secure-cache/firmware";
    const absolute = try std.fs.path.resolveAlloc(
        gpa,
        &.{ try std.process.currentPathAlloc(io, gpa), cache },
    );
    const f = provision(
        io,
        gpa,
        h.transport(),
        python,
        args[0],
        absolute,
    ) catch |err| return why.refuse(
        "native Secure Boot firmware preparation failed: {s}; no plain fallback",
        .{fetching.describe(err)},
    );
    for ([_][]const u8{ f.tool, f.code, f.template }) |path|
        if (std.mem.findAny(u8, path, "\r\n") != null) return error.BadFirmwarePath;
    try Io.File.stdout().writeStreamingAll(io, try gpa.print("{s}\n{s}\n{s}\n", .{
        f.tool, f.code, f.template,
    }));
}

const testing = std.testing;

test "interpreters are tried default first, then newest, then by full path" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const all = try candidates(arena.allocator());
    try testing.expectEqualStrings("python3", all[0]);
    try testing.expectEqualStrings("python3.14", all[1]);
    try testing.expectEqualStrings("python3.12", all[3]);
    try testing.expectEqualStrings("python3.10", all[5]);
    try testing.expectEqualStrings("/opt/homebrew/bin/python3.14", all[6]);
    try testing.expectEqualStrings("/usr/local/bin/python3.10", all[all.len - 1]);
    for ([_][]const u8{ "Python 3.10.0\n", "Python 3.14.2", "Python 3.12.1rc1\n" }) |v|
        try testing.expect(supported(v));
    for ([_][]const u8{
        "Python 3.9.18",
        "Python 3.15.0",
        "Python 4.0.0",
        "Python 2.7.18",
        "",
        "3.12",
    }) |v|
        try testing.expect(!supported(v));
}

test "the firmware pair must be regular files of exactly the tested bytes" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    var parts: [2]Part = undefined;
    for (&parts, pair) |*p, real| {
        const path = try gpa.print("{s}/{s}", .{ root, real.name });
        const file = try Dir.cwd().createFile(io, path, .{});
        try file.writeStreamingAll(io, real.name);
        try file.setLength(io, part_size);
        file.close(io);
        p.* = .{
            .name = real.name,
            .member = real.member,
            .sha256 = try gpa.dupe(u8, &try fetching.sha256(io, path)),
        };
    }
    try testing.expect(valid(io, gpa, root, &parts));
    const code = try gpa.print("{s}/code.fd", .{root});
    const file = try Dir.cwd().openFile(io, code, .{ .mode = .read_write });
    try file.writePositionalAll(io, "tamper", 0);
    try testing.expect(!valid(io, gpa, root, &parts));
    try file.writePositionalAll(io, "code.fd", 0);
    file.close(io);
    try testing.expect(valid(io, gpa, root, &parts));
    const template = try gpa.print("{s}/template.fd", .{root});
    const original = try gpa.print("{s}/original", .{root});
    try Dir.rename(Dir.cwd(), template, Dir.cwd(), original, io);
    try Dir.cwd().symLink(io, original, template, .{});
    try testing.expect(!valid(io, gpa, root, &parts));
    try Dir.cwd().deleteFile(io, template);
    try Dir.cwd().copyFile(code, Dir.cwd(), template, io, .{});
    try testing.expect(!valid(io, gpa, root, &parts));
}

/// Forged serves a package of the right size and the wrong bytes.
const Forged = struct {
    fn fetch(
        context: *anyopaque,
        url: []const u8,
        path: []const u8,
        limit: u64,
        expected: ?prebuilt.Artifact,
    ) anyerror!void {
        _ = context;
        _ = url;
        _ = expected;
        const file = try Dir.cwd().createFile(testing.io, path, .{ .exclusive = true });
        defer file.close(testing.io);
        try file.setLength(testing.io, limit);
    }
};

test "an untrusted package is refused before any parser or installer" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    // An installer that ran would fail differently: this interpreter is absent.
    const python: Python = .{ .path = "/nonexistent/python3", .version = "Python 3.14.0" };
    var context: u8 = 0;
    const forged: fetching.Transport = .{ .context = &context, .fetch = Forged.fetch };
    const cache = try gpa.print("{s}/cache", .{root});
    try testing.expectError(
        error.UntrustedFirmwarePackage,
        provision(io, gpa, forged, python, "aarch64", cache),
    );
    var walker = try (try Dir.cwd().openDir(io, cache, .{ .iterate = true })).walk(gpa);
    while (try walker.next(io)) |entry|
        try testing.expect(std.mem.find(u8, entry.path, "public-firmware-") == null);
    const missing = try gpa.print("{s}/must-not-exist", .{root});
    try testing.expectError(
        error.UnsupportedFirmwareArch,
        provision(io, gpa, forged, python, "unknown", missing),
    );
    try testing.expectError(error.FileNotFound, Dir.cwd().access(io, missing, .{}));
}

test "enrollment keeps the platform owner apart from executable trust" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    try tmp.dir.createDirPath(io, "firmware");
    for ([_][]const u8{ "code.fd", "vars.fd" }) |name| try tmp.dir.writeFile(io, .{
        .sub_path = try gpa.print("firmware/{s}", .{name}),
        .data = "public firmware fixture",
    });
    // virt-fw-vars records its arguments, one a line, and writes its outputs.
    try tmp.dir.createDirPath(io, "bin");
    try tmp.dir.writeFile(io, .{ .sub_path = "bin/virt-fw-vars", .data =
        \\#!/bin/sh
        \\printf '%s\n' "$@" >"$WW_ENROLL_ARGS"
        \\while [ $# -gt 0 ]; do
        \\    case $1 in --output | --output-aws | --output-json) printf 'public output' >"$2" ;; esac
        \\    shift
        \\done
        \\
    });
    try tmp.dir.setFilePermissions(io, "bin/virt-fw-vars", .fromMode(0o755), .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "enroll-boot", .data = @import("files").enroll_boot });
    const pem = struct {
        fn of(a: Allocator, der: []const u8) ![]const u8 {
            const E = std.base64.standard.Encoder;
            const text = try a.alloc(u8, E.calcSize(der.len));
            _ = E.encode(text, der);
            var out: std.ArrayList(u8) = .empty;
            try out.appendSlice(a, "-----BEGIN CERTIFICATE-----\n");
            var i: usize = 0;
            while (i < text.len) : (i += 64) {
                try out.appendSlice(a, text[i..@min(i + 64, text.len)]);
                try out.append(a, '\n');
            }
            try out.appendSlice(a, "-----END CERTIFICATE-----\n");
            return out.items;
        }
    }.of;
    const vendor_der = try Dir.cwd().readFileAlloc(
        io,
        "lib/testdata/boot-authority/vendor.der",
        gpa,
        .limited(1 << 16),
    );
    const owner_der = try Dir.cwd().readFileAlloc(
        io,
        "lib/testdata/boot-authority/owner.der",
        gpa,
        .limited(1 << 16),
    );
    try tmp.dir.writeFile(io, .{ .sub_path = "vendor.crt", .data = try pem(gpa, vendor_der) });
    try tmp.dir.writeFile(io, .{ .sub_path = "owner.crt", .data = try pem(gpa, owner_der) });
    var env = try testing.environ.createMap(gpa);
    try env.put(
        "PATH",
        try gpa.print("{s}/bin:{s}", .{ root, env.get("PATH") orelse "/usr/bin:/bin" }),
    );
    try env.put("SECUREBOOT_DIR", try gpa.print("{s}/firmware", .{root}));
    try env.put("WW_ENROLL_ARGS", try gpa.print("{s}/args", .{root}));
    _ = env.swapRemove("WEREWOLF_BUILD_VM");
    const vendor = try gpa.print("{s}/vendor.crt", .{root});
    const owner = try gpa.print("{s}/owner.crt", .{root});
    for ([_]struct { []const u8, []const []const u8 }{
        .{ "enrolled", &.{ "local", owner } },
        // A single-certificate source build keeps its original enrollment.
        .{ "legacy", &.{} },
    }) |case| {
        const out = try gpa.print("{s}/{s}", .{ root, case[0] });
        const argv = try std.mem.concat(gpa, []const u8, &.{
            &.{ "sh", try gpa.print("{s}/enroll-boot", .{root}), "x86_64", vendor, out }, case[1],
        });
        const result = try std.process.run(gpa, io, .{ .argv = argv, .environ_map = &env });
        if (result.term != .exited or result.term.exited != 0) {
            std.debug.print("{s}\n", .{result.stderr});
            return error.TestUnexpectedResult;
        }
        const text = try tmp.dir.readFileAlloc(io, "args", gpa, .limited(1 << 16));
        var args: std.ArrayList([]const u8) = .empty;
        var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, text, "\n"), '\n');
        while (lines.next()) |line| try args.append(gpa, line);
        const signer = if (case[1].len > 0) owner else vendor;
        var deleted: std.ArrayList([]const u8) = .empty;
        for (args.items, 0..) |a, i| {
            if (std.mem.eql(u8, a, "--set-pk") or std.mem.eql(u8, a, "--add-kek"))
                try testing.expectEqualStrings(signer, args.items[i + 2]);
            if (std.mem.eql(
                u8,
                a,
                "--add-db",
            )) try testing.expectEqualStrings(vendor, args.items[i + 2]);
            if (std.mem.eql(u8, a, "--delete")) try deleted.append(gpa, args.items[i + 1]);
        }
        try testing.expectEqual(4, deleted.items.len);
        for ([_][]const u8{ "PK", "KEK", "db", "dbx" }, deleted.items) |w, got|
            try testing.expectEqualStrings(w, got);
        try testing.expectEqualSlices(u8, vendor_der, try tmp.dir.readFileAlloc(
            io,
            try gpa.print("{s}/boot.der", .{case[0]}),
            gpa,
            .limited(1 << 16),
        ));
    }
}

test "extraction takes the tested pair from the package's data alone" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    // A small package as dpkg-deb lays one out, compressed by the zstd tool.
    var tar: Io.Writer.Allocating = .init(gpa);
    var w: std.tar.Writer = .{ .underlying_writer = &tar.writer };
    try w.writeFileBytes("./usr/share/AAVMF/AAVMF_VARS.ms.fd", "Microsoft trust", .{});
    for (pair) |p| try w.writeFileBytes(p.member, p.name, .{});
    try w.finishPedantically();
    try tmp.dir.writeFile(io, .{ .sub_path = "data.tar", .data = tar.written() });
    const zstd = try std.process.run(gpa, io, .{ .argv = &.{
        "zstd", "-q",
        try gpa.print(
            "{s}/data.tar",
            .{root},
        ),
        "-o",   try gpa.print("{s}/data.tar.zst", .{root}),
    } });
    try testing.expect(zstd.term == .exited and zstd.term.exited == 0);
    const data = try tmp.dir.readFileAlloc(io, "data.tar.zst", gpa, .limited(1 << 20));
    var deb: std.ArrayList(u8) = .empty;
    try deb.appendSlice(gpa, "!<arch>\n");
    for ([_][2][]const u8{
        .{ "debian-binary", "2.0\n" },
        .{ "control.tar.zst", "x" },
        .{ "data.tar.zst", data },
    }) |m| {
        try deb.print(
            gpa,
            "{s: <16}{s: <12}{s: <6}{s: <6}{s: <8}{d: <10}`\n",
            .{ m[0], "0", "0", "0", "100644", m[1].len },
        );
        try deb.appendSlice(gpa, m[1]);
        if (m[1].len % 2 == 1) try deb.append(gpa, '\n');
    }
    try tmp.dir.writeFile(io, .{ .sub_path = "firmware.deb", .data = deb.items });
    try tmp.dir.createDirPath(io, "out");
    try extract(
        io,
        gpa,
        try gpa.print("{s}/firmware.deb", .{root}),
        try gpa.print("{s}/out", .{root}),
        &pair,
    );
    for (pair) |p| try testing.expectEqualStrings(p.name, try tmp.dir.readFileAlloc(
        io,
        try gpa.print("out/{s}", .{p.name}),
        gpa,
        .limited(64),
    ));
    var out = try tmp.dir.openDir(io, "out", .{ .iterate = true });
    defer out.close(io);
    var it = out.iterate();
    var n: usize = 0;
    while (try it.next(io)) |_| n += 1;
    try testing.expectEqual(pair.len, n);
}
