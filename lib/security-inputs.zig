//! security-inputs builds and caches, on a trusted host, the pinned inputs
//! a protected image needs: an IPE test kernel that trusts a local policy
//! certificate and the measured EFI stub, each cached by the digests of its
//! own inputs. Builders see public inputs only. It also keeps the isolated
//! Lima helper a Mac builds Linux code in. howl and the release tools share
//! it; see lib/README.md.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Environ = std.process.Environ;
const Sha256 = std.crypto.hash.sha2.Sha256;
const mem = std.mem;

pub const stub_sources = [_][]const u8{
    "boot/stub-source",
    "tools/build-tpm-stub",
    "boot/tpm-stub.melange.yaml",
};
pub const kernel_sources = [_][]const u8{ "boot/kernel-build", "tools/test-kernel" };
const stub_package = "werewolf-tpm-stub-build-0.1.0-r0.apk";
const stub_member = "usr/share/werewolf-build/linux.efi.stub";

pub const Command = struct {
    argv: []const []const u8,
    /// env replaces the environment; null keeps the host's.
    env: ?*const Environ.Map = null,
    /// stdin is written to the command's standard input.
    stdin: ?[]const u8 = null,
};

/// Runner runs what a build needs, so howl can show its progress and a
/// test can stand in for the tools.
pub const Runner = struct {
    context: *anyopaque,
    /// run runs command to success.
    run: *const fn (context: *anyopaque, gpa: Allocator, command: Command) anyerror!void,
    /// capture returns the standard output of argv, run to success.
    capture: *const fn (
        context: *anyopaque,
        gpa: Allocator,
        argv: []const []const u8,
    ) anyerror![]const u8,
    /// phase says what the build does next.
    phase: *const fn (context: *anyopaque, short: []const u8, name: []const u8) void,
};

/// Host is where a build runs: its system, machine and environment, and
/// how it runs commands.
pub const Host = struct {
    io: Io,
    os: std.Target.Os.Tag = builtin.os.tag,
    /// machine is the host's architecture: aarch64 or x86_64.
    machine: []const u8 = @tagName(builtin.cpu.arch),
    env: *const Environ.Map,
    runner: Runner,

    fn run(h: Host, gpa: Allocator, command: Command) !void {
        return h.runner.run(h.runner.context, gpa, command);
    }

    fn capture(h: Host, gpa: Allocator, argv: []const []const u8) ![]const u8 {
        return h.runner.capture(h.runner.context, gpa, argv);
    }

    fn phase(h: Host, short: []const u8, name: []const u8) void {
        h.runner.phase(h.runner.context, short, name);
    }
};

/// Plain runs commands with this process's output, and says phases on
/// standard error as howl's progress reads them.
pub const Plain = struct {
    io: Io,

    pub fn runner(p: *Plain) Runner {
        return .{ .context = p, .run = run, .capture = capture, .phase = phase };
    }

    fn run(context: *anyopaque, gpa: Allocator, command: Command) anyerror!void {
        _ = gpa;
        const p: *Plain = @ptrCast(@alignCast(context));
        var child = try std.process.spawn(p.io, .{
            .argv = command.argv,
            .environ_map = command.env,
            .stdin = if (command.stdin != null) .pipe else .inherit,
        });
        defer if (child.id != null) child.kill(p.io);
        if (command.stdin) |data| {
            const pipe = child.stdin.?;
            child.stdin = null;
            defer pipe.close(p.io);
            try pipe.writeStreamingAll(p.io, data);
        }
        const term = try child.wait(p.io);
        if (term != .exited or term.exited != 0) return error.CommandFailed;
    }

    fn capture(context: *anyopaque, gpa: Allocator, argv: []const []const u8) anyerror![]const u8 {
        const p: *Plain = @ptrCast(@alignCast(context));
        const result = try std.process.run(gpa, p.io, .{
            .argv = argv,
            .stdout_limit = .limited(1 << 20),
            .stderr_limit = .limited(64 << 10),
        });
        if (result.term != .exited or result.term.exited != 0) return error.CommandFailed;
        return result.stdout;
    }

    fn phase(context: *anyopaque, short: []const u8, name: []const u8) void {
        const p: *Plain = @ptrCast(@alignCast(context));
        var buf: [512]u8 = undefined;
        var w = Io.File.stderr().writerStreaming(p.io, &buf);
        w.interface.print("howl: phase {s}: {s}\n", .{ short, name }) catch return;
        w.interface.flush() catch {};
    }
};

/// Input is a file a cached output depends on, by name.
pub const Input = struct { name: []const u8, path: []const u8 };

fn digest(io: Io, path: []const u8) ![32]u8 {
    const file = try Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var h = Sha256.init(.{});
    var buf: [64 << 10]u8 = undefined;
    var at: u64 = 0;
    while (true) {
        const n = try file.readPositionalAll(io, &buf, at);
        if (n == 0) break;
        h.update(buf[0..n]);
        at += n;
    }
    return h.finalResult();
}

fn byName(_: void, a: Input, b: Input) bool {
    return mem.order(u8, a.name, b.name) == .lt;
}

/// fingerprint names a build of arch from its inputs' names and bytes,
/// never their times. It is the Python builder's, so its caches stay valid.
pub fn fingerprint(io: Io, gpa: Allocator, arch: []const u8, inputs: []const Input) ![64]u8 {
    const sorted = try gpa.dupe(Input, inputs);
    mem.sort(Input, sorted, {}, byName);
    var h = Sha256.init(.{});
    h.update(arch);
    for (sorted) |input| {
        h.update(input.name);
        h.update(&.{0});
        h.update(&try digest(io, input.path));
    }
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

/// packagePins returns NAME=VERSION for each of arch's packages in an
/// apko lock, refusing a lock that lists none or one twice.
pub fn packagePins(io: Io, gpa: Allocator, lock: []const u8, arch: []const u8) ![]const []const u8 {
    const Lock = struct {
        contents: struct {
            packages: []const struct {
                name: []const u8,
                version: []const u8,
                architecture: []const u8,
            },
        },
    };
    const parsed = try std.json.parseFromSliceLeaky(
        Lock,
        gpa,
        try Dir.cwd().readFileAlloc(io, lock, gpa, .limited(16 << 20)),
        .{ .ignore_unknown_fields = true },
    );
    var pins: std.ArrayList([]const u8) = .empty;
    for (parsed.contents.packages, 0..) |p, i| {
        if (!mem.eql(u8, p.architecture, arch)) continue;
        for (parsed.contents.packages[0..i]) |q| if (mem.eql(u8, q.architecture, arch) and
            mem.eql(u8, q.name, p.name)) return error.BadPackageLock;
        try pins.append(gpa, try gpa.print("{s}={s}", .{ p.name, p.version }));
    }
    if (pins.items.len == 0) return error.BadPackageLock;
    return pins.items;
}

/// stubInputs are what the stub's build depends on: its sources in tree,
/// and with WEREWOLF_PROTECTED_INPUTS the builder's package lock.
pub fn stubInputs(gpa: Allocator, env: *const Environ.Map, tree: []const u8) ![]const Input {
    var out: std.ArrayList(Input) = .empty;
    for (stub_sources) |name|
        try out.append(gpa, .{ .name = name, .path = try gpa.print("{s}/{s}", .{ tree, name }) });
    if (env.get("WEREWOLF_PROTECTED_INPUTS")) |snapshot| try out.append(gpa, .{
        .name = "stub-packages",
        .path = try gpa.print("{s}/stub-builder.lock.json", .{snapshot}),
    });
    return out.items;
}

fn isFile(io: Io, path: ?[]const u8) bool {
    const st = Dir.cwd().statFile(io, path orelse return false, .{}) catch return false;
    return st.kind == .file;
}

/// guest reports whether env names the stock kernel and initramfs Melange
/// boots its QEMU runner with.
fn guest(io: Io, env: *const Environ.Map) bool {
    return isFile(io, env.get("QEMU_KERNEL_IMAGE")) and isFile(io, env.get("QEMU_BASE_INITRAMFS"));
}

/// testKernel builds linux-werewolf with IPE trusting cert, natively;
/// tools/test-kernel passes no secret on.
pub fn testKernel(
    gpa: Allocator,
    host: Host,
    tree: []const u8,
    arch: []const u8,
    cert: []const u8,
    output: []const u8,
) !void {
    if ((host.os == .linux and !mem.eql(u8, host.machine, arch)) or
        (host.os == .macos and !mem.eql(u8, arch, "aarch64"))) return error.ForeignKernelArch;
    if (host.os == .macos and !guest(host.io, host.env)) return error.MissingMelangeGuest;
    var env: Environ.Map = .init(gpa);
    defer env.deinit();
    for ([_][]const u8{
        "PATH",              "HOME",                "LANG",        "SSL_CERT_FILE",
        "QEMU_KERNEL_IMAGE", "QEMU_BASE_INITRAMFS", "MELANGE_CPU", "MELANGE_MEMORY",
    }) |name| if (host.env.get(name)) |value| try env.put(name, value);
    try host.run(gpa, .{ .argv = &.{
        "sh", try gpa.print("{s}/tools/test-kernel", .{tree}), arch, cert, output,
    }, .env = &env });
}

/// melange builds the measured stub from its public sources alone: QEMU
/// runs Melange on macOS, bubblewrap on Linux.
pub fn melange(
    gpa: Allocator,
    host: Host,
    tree: []const u8,
    cache: []const u8,
    arch: []const u8,
    output: []const u8,
) !void {
    const io = host.io;
    host.phase("stub-builder", "Preparing the EFI stub build environment");
    const runner = if (host.os == .macos) "qemu" else "bubblewrap";
    // No private signing paths, PEM secrets or key directories reach the runner.
    var env: Environ.Map = .init(gpa);
    for ([_][]const u8{
        "PATH", "HOME", "LANG", "SSL_CERT_FILE", "QEMU_KERNEL_IMAGE", "QEMU_BASE_INITRAMFS",
    }) |name| if (host.env.get(name)) |v| try env.put(name, v);
    if (host.os == .macos and !guest(io, &env)) return error.MissingMelangeGuest;
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const work = try gpa.print("{s}/melange-public-{x}", .{
        std.fs.path.dirname(output) orelse ".", &nonce,
    });
    try Dir.cwd().createDir(io, work, .fromMode(0o700));
    defer Dir.cwd().deleteTree(io, work) catch {};
    const source = try gpa.print("{s}/source", .{work});
    for (stub_sources) |name| {
        const target = try gpa.print("{s}/{s}", .{ source, name });
        try Dir.cwd().createDirPath(io, std.fs.path.dirname(target).?);
        try Dir.cwd().copyFile(
            try gpa.print("{s}/{s}", .{ tree, name }),
            Dir.cwd(),
            target,
            io,
            .{},
        );
    }
    const scratch = try gpa.print("{s}/scratch", .{work});
    try Dir.cwd().createDir(io, scratch, .fromMode(0o700));
    try env.put("TMPDIR", scratch);
    try env.put("QEMU_DISKS_PATH", scratch);
    try env.put("SOURCE_DATE_EPOCH", "0");
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{
        "melange",                                                  "build",
        try gpa.print("{s}/boot/tpm-stub.melange.yaml", .{source}), "--runner",
        runner,                                                     "--arch",
        arch,                                                       "--source-dir",
        source,                                                     "--out-dir",
        try gpa.print("{s}/packages", .{work}),                     "--cache-dir",
        try gpa.print("{s}/melange-cache", .{cache}),               "--cpu",
        host.env.get("MELANGE_CPU") orelse try gpa.print("{d}", .{
            @max(1, (std.Thread.getCpuCount() catch 2) / 2),
        }),
        "--memory",
        host.env.get(
            "MELANGE_MEMORY",
        ) orelse "8Gi",
        "--disk",                                                   "24Gi",
        "--generate-index=false",
    });
    if (host.env.get("WEREWOLF_PROTECTED_INPUTS")) |snapshot| {
        const lock = try gpa.print("{s}/stub-builder.lock.json", .{snapshot});
        for (try packagePins(io, gpa, lock, arch)) |pin|
            try argv.appendSlice(gpa, &.{ "--package-append", pin });
    }
    try host.run(gpa, .{ .argv = argv.items, .env = &env });
    host.phase("stub-collect", "Collecting the measured EFI stub build output");
    const package = try gpa.print("{s}/packages/{s}/{s}", .{ work, arch, stub_package });
    const stub_bytes = try member(gpa, try Dir.cwd().readFileAlloc(
        io,
        package,
        gpa,
        .limited(256 << 20),
    ), stub_member);
    if (stub_bytes.len == 0) return error.MissingStubArtifact;
    try replaceFile(io, gpa, output, stub_bytes);
}

/// member returns the file name in an apk: gzip members, each a tar.
fn member(gpa: Allocator, package: []const u8, name: []const u8) ![]const u8 {
    var at: usize = 0;
    while (at < package.len) {
        var in: Io.Reader = .fixed(package[at..]);
        var d: std.compress.flate.Decompress = .init(&in, .gzip, &.{});
        const tar = d.reader.allocRemaining(gpa, .limited(512 << 20)) catch |err| switch (err) {
            error.ReadFailed => return d.err orelse error.ReadFailed,
            else => return err,
        };
        if (in.seek == 0) return error.BadPackage;
        at += in.seek;
        var r: Io.Reader = .fixed(tar);
        var names: [256]u8 = undefined;
        var links: [256]u8 = undefined;
        var it: std.tar.Iterator = .init(
            &r,
            .{ .file_name_buffer = &names, .link_name_buffer = &links },
        );
        while (try it.next()) |f| {
            if (f.kind != .file or !mem.eql(u8, f.name, name)) continue;
            if (f.size > tar.len - r.seek) return error.BadPackage;
            return tar[r.seek..][0..@intCast(f.size)];
        }
    }
    return error.MissingStubArtifact;
}

/// replaceFile writes bytes beside path, syncs them and renames them over it.
fn replaceFile(io: Io, gpa: Allocator, path: []const u8, bytes: []const u8) !void {
    const temporary = try gpa.print("{s}.new", .{path});
    Dir.cwd().deleteFile(io, temporary) catch {};
    defer Dir.cwd().deleteFile(io, temporary) catch {};
    const file = try Dir.cwd().createFile(io, temporary, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    {
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
        try file.sync(io);
    }
    try Dir.rename(Dir.cwd(), temporary, Dir.cwd(), path, io);
}

const default_vm = "werewolf-build-26.04";

/// helperStub builds the measured stub in the arm64 Mac's Linux build
/// helper, a trusted builder and never the protected workload VM.
fn helperStub(gpa: Allocator, host: Host, tree: []const u8, output: []const u8) !void {
    const vm = host.env.get("WEREWOLF_BUILD_VM") orelse default_vm;
    host.phase("build-helper", "Preparing the Linux build helper");
    try prepareHelper(gpa, host, vm, try gpa.print("{s}/boot/build-helper.yaml", .{tree}));
    const prefix = "/var/tmp/ww-prerequisites.";
    const remote = mem.trim(u8, try host.capture(gpa, &.{
        "limactl", "shell", vm, "mktemp", "-d", prefix ++ "XXXXXXXX",
    }), " \r\n");
    const suffix = mem.cutPrefix(u8, remote, prefix) orelse return error.BadHelperDirectory;
    if (suffix.len == 0 or mem.findAny(u8, suffix, "/ \t\n") != null)
        return error.BadHelperDirectory;
    defer host.run(
        gpa,
        .{ .argv = &.{ "limactl", "shell", vm, "rm", "-rf", "--", remote } },
    ) catch {};
    host.phase("build-inputs", "Copying public EFI stub inputs to the Linux build helper");
    try host.run(gpa, .{ .argv = &.{
        "limactl",                             "shell",
        vm,                                    "mkdir",
        "-p",                                  try gpa.print("{s}/boot", .{remote}),
        try gpa.print("{s}/tools", .{remote}),
    } });
    for ([_][]const u8{ "boot/stub-source", "tools/build-tpm-stub" }) |name| try host.run(gpa, .{
        .argv = &.{
            "limactl",
            "copy",
            try gpa.print("{s}/{s}", .{ tree, name }),
            try gpa.print("{s}:{s}/{s}", .{ vm, remote, name }),
        },
    });
    try host.run(gpa, .{ .argv = &.{
        "limactl",
        "shell",
        vm,
        "sh",
        try gpa.print("{s}/tools/build-tpm-stub", .{remote}),
        try gpa.print("{s}/stub", .{remote}),
    } });
    host.phase("stub-collect", "Collecting the measured EFI stub");
    try host.run(gpa, .{ .argv = &.{
        "limactl", "copy", try gpa.print("{s}:{s}/stub/linux.efi.stub", .{ vm, remote }), output,
    } });
}

/// stub builds the measured stub: Melange on Linux and on a Mac without
/// WEREWOLF_BUILD_VM, else that Mac's Linux build helper.
pub fn stub(
    gpa: Allocator,
    host: Host,
    tree: []const u8,
    cache: []const u8,
    arch: []const u8,
    output: []const u8,
) !void {
    if (host.os == .linux or (host.os == .macos and host.env.get("WEREWOLF_BUILD_VM") == null))
        return melange(gpa, host, tree, cache, arch, output);
    if (host.os == .macos and
        mem.eql(u8, arch, "aarch64")) return helperStub(gpa, host, tree, output);
    return error.UnsupportedBuildHost;
}

/// Make makes one cached output at a path.
pub const Make = struct {
    context: *anyopaque,
    make: *const fn (context: *anyopaque, gpa: Allocator, output: []const u8) anyerror!void,
};

/// cached returns directory/name, made by make unless a verified earlier
/// build of pin is there.
pub fn cached(
    io: Io,
    gpa: Allocator,
    directory: []const u8,
    pin: []const u8,
    name: []const u8,
    make: Make,
) ![]const u8 {
    _ = try Dir.cwd().createDirPathStatus(io, directory, .fromMode(0o700));
    const output = try gpa.print("{s}/{s}", .{ directory, name });
    if (!valid(io, gpa, directory, pin, &.{name})) {
        try make.make(make.context, gpa, output);
        try complete(io, gpa, directory, pin, &.{name});
    }
    return output;
}

const Completion = struct { inputs: []const u8, outputs: std.json.ArrayHashMap([]const u8) };

/// valid reports whether directory holds exactly outputs, each a regular
/// file whose digest complete.json records for the build of expected.
pub fn valid(
    io: Io,
    gpa: Allocator,
    directory: []const u8,
    expected: []const u8,
    outputs: []const []const u8,
) bool {
    const saved = std.json.parseFromSliceLeaky(Completion, gpa, Dir.cwd().readFileAlloc(
        io,
        gpa.print("{s}/complete.json", .{directory}) catch return false,
        gpa,
        .limited(64 << 10),
    ) catch return false, .{}) catch return false;
    if (!mem.eql(u8, saved.inputs, expected) or saved.outputs.map.count() != outputs.len)
        return false;
    for (outputs) |name| {
        const want = saved.outputs.map.get(name) orelse return false;
        const path = gpa.print("{s}/{s}", .{ directory, name }) catch return false;
        const st = Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return false;
        if (st.kind != .file) return false;
        const got = digest(io, path) catch return false;
        if (!mem.eql(u8, &std.fmt.bytesToHex(got, .lower), want)) return false;
    }
    return true;
}

/// complete records outputs' digests as directory's build of expected.
fn complete(
    io: Io,
    gpa: Allocator,
    directory: []const u8,
    expected: []const u8,
    outputs: []const []const u8,
) !void {
    var record: Completion = .{ .inputs = expected, .outputs = .{} };
    for (outputs) |name| try record.outputs.map.put(gpa, name, try gpa.dupe(
        u8,
        &std.fmt.bytesToHex(try digest(io, try gpa.print("{s}/{s}", .{ directory, name })), .lower),
    ));
    const json = try std.json.Stringify.valueAlloc(gpa, record, .{});
    try replaceFile(io, gpa, try gpa.print("{s}/complete.json", .{directory}), try gpa.print(
        "{s}\n",
        .{json},
    ));
}

/// share links source at destination, or copies it where links fail.
fn share(io: Io, gpa: Allocator, source: []const u8, destination: []const u8) !void {
    const temporary = try gpa.print("{s}.new", .{destination});
    Dir.cwd().deleteFile(io, temporary) catch {};
    defer Dir.cwd().deleteFile(io, temporary) catch {};
    Dir.hardLink(Dir.cwd(), source, Dir.cwd(), temporary, io, .{}) catch
        try Dir.cwd().copyFile(source, Dir.cwd(), temporary, io, .{});
    try Dir.rename(Dir.cwd(), temporary, Dir.cwd(), destination, io);
}

/// Identity is the local IPE policy signer: every machine made with it
/// trusts only roots its key signs.
pub const Identity = struct { key: []const u8, cert: []const u8 };

/// identity returns directory's policy signer, making one only where none
/// ever was: a lost or partial signer refuses rather than rotating trust.
pub fn identity(gpa: Allocator, host: Host, directory: []const u8) !Identity {
    const io = host.io;
    _ = try Dir.cwd().createDirPathStatus(io, directory, .fromMode(0o700));
    const key = try gpa.print("{s}/policy.key", .{directory});
    const cert = try gpa.print("{s}/policy.crt", .{directory});
    const marker = try gpa.print("{s}/identity.sha256", .{directory});
    const has_key = isFile(io, key);
    const has_cert = isFile(io, cert);
    const marked = if (Dir.cwd().access(io, marker, .{})) |_| true else |_| false;
    if (marked and (!has_key or !has_cert)) return error.LostPolicyIdentity;
    if (has_key != has_cert) return error.PartialPolicyIdentity;
    if (!has_key) {
        // Unfinished identities stay private and apart from the real one.
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const scratch = try gpa.print("{s}/new-{x}", .{ directory, &nonce });
        try Dir.cwd().createDir(io, scratch, .fromMode(0o700));
        defer Dir.cwd().deleteTree(io, scratch) catch {};
        const new_key = try gpa.print("{s}/policy.key", .{scratch});
        const new_cert = try gpa.print("{s}/policy.crt", .{scratch});
        try host.run(gpa, .{ .argv = &.{
            "openssl", "req",   "-newkey", "rsa:4096", "-nodes",                 "-x509",
            "-sha256", "-days", "3650",    "-subj",    "/CN=werewolf-local-ipe", "-keyout",
            new_key,   "-out",  new_cert,
        } });
        try Dir.cwd().setFilePermissions(io, new_key, .fromMode(0o600), .{});
        try Dir.rename(Dir.cwd(), new_key, Dir.cwd(), key, io);
        try Dir.rename(Dir.cwd(), new_cert, Dir.cwd(), cert, io);
    }
    const st = try Dir.cwd().statFile(io, key, .{ .follow_symlinks = false });
    if (st.permissions.toMode() & 0o777 != 0o600) return error.PublicPolicyKey;
    try host.run(
        gpa,
        .{ .argv = &.{ "openssl", "x509", "-checkend", "86400", "-noout", "-in", cert } },
    );
    const from_key = try host.capture(gpa, &.{ "openssl", "pkey", "-in", key, "-pubout" });
    const from_cert = try host.capture(
        gpa,
        &.{ "openssl", "x509", "-in", cert, "-pubkey", "-noout" },
    );
    if (!mem.eql(u8, from_key, from_cert)) return error.MismatchedPolicyIdentity;
    const wanted = try gpa.print("{x}\n", .{&try digest(io, cert)});
    if (marked) {
        const saved = try Dir.cwd().readFileAlloc(io, marker, gpa, .limited(256));
        if (!mem.eql(u8, saved, wanted)) return error.ChangedPolicyIdentity;
    } else {
        const out = try Dir.cwd().createFile(io, marker, .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        defer out.close(io);
        try out.writeStreamingAll(io, wanted);
        try out.sync(io);
    }
    return .{ .key = key, .cert = cert };
}

const Build = struct {
    host: Host,
    tree: []const u8,
    cache: []const u8,
    arch: []const u8,
    cert: []const u8 = "",

    fn kernel(context: *anyopaque, gpa: Allocator, output: []const u8) anyerror!void {
        const b: *Build = @ptrCast(@alignCast(context));
        return testKernel(gpa, b.host, b.tree, b.arch, b.cert, output);
    }

    fn efi(context: *anyopaque, gpa: Allocator, output: []const u8) anyerror!void {
        const b: *Build = @ptrCast(@alignCast(context));
        return stub(gpa, b.host, b.tree, b.cache, b.arch, output);
    }
};

/// build returns the cache directory holding a test kernel that trusts
/// cert, rootfs.tar, and the measured stub, linux.efi.stub. Each is cached
/// by its own inputs, so a change to one keeps the other.
pub fn build(
    gpa: Allocator,
    host: Host,
    tree: []const u8,
    cache: []const u8,
    arch: []const u8,
    cert: []const u8,
) ![]const u8 {
    const io = host.io;
    host.phase("security-cache", "Checking cached kernel and EFI stub");
    var kernels: [kernel_sources.len + 1]Input = undefined;
    for (kernels[0..kernel_sources.len], kernel_sources) |*k, name|
        k.* = .{ .name = name, .path = try gpa.print("{s}/{s}", .{ tree, name }) };
    kernels[kernel_sources.len] = .{ .name = "certificate", .path = cert };
    const stubs = try stubInputs(gpa, host.env, tree);
    const expected = try fingerprint(
        io,
        gpa,
        arch,
        try mem.concat(gpa, Input, &.{ &kernels, stubs }),
    );
    const target = try gpa.print("{s}/{s}/{s}", .{ cache, arch, &expected });
    const outputs = [_][]const u8{ "rootfs.tar", "linux.efi.stub" };
    if (valid(io, gpa, target, &expected, &outputs)) return target;
    var b: Build = .{ .host = host, .tree = tree, .cache = cache, .arch = arch, .cert = cert };
    const kernel_pin = try fingerprint(io, gpa, arch, &kernels);
    const kernel = try cached(io, gpa, try gpa.print("{s}/{s}/test-kernel-{s}", .{
        cache, arch, &kernel_pin,
    }), &kernel_pin, "rootfs.tar", .{ .context = &b, .make = Build.kernel });
    const stub_pin = try fingerprint(io, gpa, arch, stubs);
    const efi = try cached(io, gpa, try gpa.print("{s}/{s}/stub-{s}", .{
        cache, arch, &stub_pin,
    }), &stub_pin, "linux.efi.stub", .{ .context = &b, .make = Build.efi });
    host.phase("security-cache", "Saving verified kernel and EFI stub");
    _ = try Dir.cwd().createDirPathStatus(io, target, .fromMode(0o700));
    try share(io, gpa, kernel, try gpa.print("{s}/rootfs.tar", .{target}));
    try share(io, gpa, efi, try gpa.print("{s}/linux.efi.stub", .{target}));
    try complete(io, gpa, target, &expected, &outputs);
    return target;
}

/// Prepared are the paths of a protected build's security inputs.
pub const Prepared = struct {
    kernel: ?[]const u8 = null,
    key: ?[]const u8 = null,
    cert: ?[]const u8 = null,
    stub: []const u8,
};

/// Direct boot needs an IPE kernel but no EFI stub or firmware toolchain.
pub fn prepareKernel(
    gpa: Allocator,
    host: Host,
    tree: []const u8,
    cache: []const u8,
    arch: []const u8,
    signing: []const u8,
) !Prepared {
    _ = try Dir.cwd().createDirPathStatus(host.io, cache, .fromMode(0o700));
    const guard = try Dir.cwd().createFile(host.io, try gpa.print("{s}/build.lock", .{cache}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer guard.close(host.io);
    host.phase("security-lock", "Waiting for the security input build lock");
    try guard.lock(host.io, .exclusive);
    defer guard.unlock(host.io);
    const signer = try identity(gpa, host, signing);
    var inputs: [kernel_sources.len + 1]Input = undefined;
    for (inputs[0..kernel_sources.len], kernel_sources) |*input, name|
        input.* = .{ .name = name, .path = try gpa.print("{s}/{s}", .{ tree, name }) };
    inputs[kernel_sources.len] = .{ .name = "certificate", .path = signer.cert };
    const pin = try fingerprint(host.io, gpa, arch, &inputs);
    var b: Build = .{
        .host = host,
        .tree = tree,
        .cache = cache,
        .arch = arch,
        .cert = signer.cert,
    };
    const kernel = try cached(host.io, gpa, try gpa.print("{s}/{s}/test-kernel-{s}", .{
        cache, arch, &pin,
    }), &pin, "rootfs.tar", .{ .context = &b, .make = Build.kernel });
    return .{ .kernel = kernel, .key = signer.key, .cert = signer.cert, .stub = "" };
}

/// prepare makes arch's stub under cache's lock, and given signing, the
/// policy identity kept there and a test kernel that trusts it.
pub fn prepare(
    gpa: Allocator,
    host: Host,
    tree: []const u8,
    cache: []const u8,
    arch: []const u8,
    signing: ?[]const u8,
) !Prepared {
    const io = host.io;
    _ = try Dir.cwd().createDirPathStatus(io, cache, .fromMode(0o700));
    const guard = try Dir.cwd().createFile(io, try gpa.print("{s}/build.lock", .{cache}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer guard.close(io);
    host.phase("security-lock", "Waiting for the security input build lock");
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    host.phase("security-cache", "Checking cached security inputs");
    const dir = signing orelse {
        const pin = try fingerprint(io, gpa, arch, try stubInputs(gpa, host.env, tree));
        var b: Build = .{ .host = host, .tree = tree, .cache = cache, .arch = arch };
        return .{ .stub = try cached(io, gpa, try gpa.print("{s}/{s}/stub-{s}", .{
            cache, arch, &pin,
        }), &pin, "linux.efi.stub", .{ .context = &b, .make = Build.efi }) };
    };
    host.phase("policy-identity", "Checking the local IPE signing identity");
    const signer = try identity(gpa, host, dir);
    const target = try build(gpa, host, tree, cache, arch, signer.cert);
    return .{
        .kernel = try gpa.print("{s}/rootfs.tar", .{target}),
        .stub = try gpa.print("{s}/linux.efi.stub", .{target}),
        .key = signer.key,
        .cert = signer.cert,
    };
}

/// helper_setup converges the helper's packages: compilers, firmware and
/// virt-firmware, installed only when one is missing.
const helper_setup =
    \\set -eu
    \\test "$(uname -m)" = aarch64
    \\packages='build-essential flex bison libssl-dev libelf-dev bc kmod curl xz-utils
    \\    bsdextrautils meson ninja-build gperf libcap-dev libmount-dev python3-jinja2
    \\    python3-pyelftools python3-venv qemu-efi-aarch64 python3-virt-firmware
    \\    systemd-boot-efi'
    \\missing=0
    \\for package in $packages; do
    \\    if [ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)" != 'install ok installed' ]; then
    \\        missing=1
    \\    fi
    \\done
    \\if [ "$missing" = 1 ]; then
    \\    sudo -n apt-get update -qq
    \\    sudo -n apt-get install -y -qq $packages
    \\fi
    \\command -v virt-fw-vars >/dev/null
    \\test -f /usr/share/AAVMF/AAVMF_CODE.secboot.fd
    \\test -f /usr/share/AAVMF/AAVMF_VARS.fd
    \\
;

/// helperName reports whether name is a Lima instance name the helper may take.
pub fn helperName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64 or !std.ascii.isAlphanumeric(name[0])) return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and mem.findScalar(u8, "_.-", c) == null)
        return false;
    return true;
}

/// prepareHelper makes the isolated native Linux build helper name exist
/// and run, from template if it is new, before anything uses it. One
/// preparation at a time, across machine builds.
pub fn prepareHelper(gpa: Allocator, host: Host, name: []const u8, template: []const u8) !void {
    if (!helperName(name)) return error.BadHelperName;
    const io = host.io;
    const root = if (host.env.get("LIMA_HOME")) |home|
        home
    else
        try gpa.print("{s}/.lima", .{host.env.get("HOME") orelse return error.NoHome});
    _ = try Dir.cwd().createDirPathStatus(io, root, .fromMode(0o700));
    const guard = try Dir.cwd().createFile(io, try gpa.print("{s}/.werewolf-build-{s}.lock", .{
        root, name,
    }), .{ .truncate = false, .permissions = .fromMode(0o600) });
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    return ensureHelper(gpa, host, name, template);
}

fn ensureHelper(gpa: Allocator, host: Host, name: []const u8, template: []const u8) !void {
    if (!helperName(name)) return error.BadHelperName;
    var record = try helperInstance(gpa, host, name);
    if (record == null) {
        host.phase(
            "build-helper",
            try gpa.print("Creating isolated Linux build helper {s}", .{name}),
        );
        try host.run(
            gpa,
            .{ .argv = &.{ "limactl", "create", "--tty=false", "--name", name, template } },
        );
        record = try helperInstance(gpa, host, name) orelse return error.HelperNotCreated;
    }
    try checkHelper(record.?);
    if (!isRunning(record.?)) {
        host.phase("build-helper", try gpa.print("Starting Linux build helper {s}", .{name}));
        try host.run(gpa, .{ .argv = &.{ "limactl", "start", "--tty=false", name } });
        record = try helperInstance(gpa, host, name);
        if (record == null or !isRunning(record.?)) return error.HelperNotStarted;
        try checkHelper(record.?);
    }
    try host.run(
        gpa,
        .{ .argv = &.{ "limactl", "shell", name, "--", "sh", "-s" }, .stdin = helper_setup },
    );
}

fn isRunning(record: std.json.Value) bool {
    const status = record.object.get("status") orelse return false;
    return status == .string and mem.eql(u8, status.string, "Running");
}

/// helperInstance returns Lima's record of instance name, or null.
fn helperInstance(gpa: Allocator, host: Host, name: []const u8) !?std.json.Value {
    const listing = try host.capture(gpa, &.{ "limactl", "list", "--json" });
    var found: ?std.json.Value = null;
    var lines = mem.tokenizeScalar(u8, listing, '\n');
    while (lines.next()) |line| {
        const record = try std.json.parseFromSliceLeaky(std.json.Value, gpa, line, .{});
        if (record != .object) return error.BadLimaListing;
        const n = record.object.get("name") orelse continue;
        if (n != .string or !mem.eql(u8, n.string, name)) continue;
        if (found != null) return error.AmbiguousHelper;
        found = record;
    }
    return found;
}

/// checkHelper refuses a helper that is not native arm64 Linux, or that
/// mounts host files or forwards the SSH agent, as Lima reports it running.
fn checkHelper(record: std.json.Value) !void {
    const arch = record.object.get("arch") orelse return error.ForeignHelper;
    if (arch != .string or !mem.eql(u8, arch.string, "aarch64")) return error.ForeignHelper;
    const config = record.object.get("config") orelse return error.ForeignHelper;
    if (config != .object) return error.ForeignHelper;
    const os = config.object.get("os") orelse return error.ForeignHelper;
    if (os != .string or !mem.eql(u8, os.string, "Linux")) return error.ForeignHelper;
    if (config.object.get("mounts")) |mounts| switch (mounts) {
        .null => {},
        .array => |a| if (a.items.len != 0) return error.ExposedHelper,
        else => return error.ExposedHelper,
    };
    if (config.object.get("ssh")) |ssh| if (ssh == .object) if (ssh.object.get("forwardAgent")) |f|
        if (f != .bool or f.bool) return error.ExposedHelper;
}

const testing = std.testing;

/// Fake stands in for the build tools: it records what a build ran and
/// makes what each tool would.
const Fake = struct {
    gpa: Allocator,
    io: Io,
    calls: std.ArrayList([]const u8) = .empty,
    runs: std.ArrayList(Command) = .empty,
    /// sources are the files melange was given, by name.
    sources: std.ArrayList([]const u8) = .empty,
    listings: []const []const u8 = &.{},
    listed: usize = 0,
    fail: ?[]const u8 = null,

    fn runner(f: *Fake) Runner {
        return .{ .context = f, .run = run, .capture = capture, .phase = phase };
    }

    fn value(argv: []const []const u8, flag: []const u8) []const u8 {
        for (argv, 0..) |a, i| if (mem.eql(u8, a, flag)) return argv[i + 1];
        unreachable;
    }

    fn run(context: *anyopaque, gpa: Allocator, command: Command) anyerror!void {
        const f: *Fake = @ptrCast(@alignCast(context));
        const argv = command.argv;
        var copy = command;
        copy.argv = try f.gpa.dupe([]const u8, argv);
        if (command.env) |env| {
            const kept = try f.gpa.create(Environ.Map);
            kept.* = try env.clone(f.gpa);
            copy.env = kept;
        }
        try f.runs.append(f.gpa, copy);
        const tool = if (mem.eql(u8, argv[0], "limactl"))
            argv[1]
        else if (mem.eql(u8, argv[0], "sh"))
            "kernel"
        else if (mem.eql(u8, argv[0], "melange"))
            "stub"
        else
            argv[0];
        if (f.fail) |failing| if (mem.eql(u8, failing, tool)) {
            try f.calls.append(f.gpa, try f.gpa.print("{s} failure", .{tool}));
            return error.CommandFailed;
        };
        try f.calls.append(f.gpa, tool);
        const made = try gpa.print("{s}{d}", .{ tool, f.calls.items.len });
        if (mem.eql(u8, tool, "kernel")) {
            try Dir.cwd().writeFile(f.io, .{ .sub_path = argv[4], .data = made });
        } else if (mem.eql(u8, tool, "stub")) {
            const source = value(argv, "--source-dir");
            var dir = try Dir.cwd().openDir(f.io, source, .{ .iterate = true });
            defer dir.close(f.io);
            var walker = try dir.walk(gpa);
            while (try walker.next(f.io)) |entry| if (entry.kind == .file)
                try f.sources.append(f.gpa, try f.gpa.dupe(u8, entry.path));
            const out = try gpa.print(
                "{s}/{s}",
                .{ value(argv, "--out-dir"), value(argv, "--arch") },
            );
            try Dir.cwd().createDirPath(f.io, out);
            try Dir.cwd().writeFile(f.io, .{
                .sub_path = try gpa.print("{s}/{s}", .{ out, stub_package }),
                .data = try testApk(gpa, made),
            });
        }
    }

    fn capture(context: *anyopaque, gpa: Allocator, argv: []const []const u8) anyerror![]const u8 {
        _ = gpa;
        const f: *Fake = @ptrCast(@alignCast(context));
        try testing.expectEqualStrings("list", argv[1]);
        f.listed += 1;
        return f.listings[f.listed - 1];
    }

    fn phase(context: *anyopaque, short: []const u8, name: []const u8) void {
        _ = context;
        _ = short;
        _ = name;
    }
};

/// Quiet runs the real tools, keeping their chatter out of the test's output.
const Quiet = struct {
    io: Io,

    fn runner(q: *Quiet) Runner {
        return .{ .context = q, .run = run, .capture = capture, .phase = Fake.phase };
    }

    fn run(context: *anyopaque, gpa: Allocator, command: Command) anyerror!void {
        _ = try capture(context, gpa, command.argv);
    }

    fn capture(context: *anyopaque, gpa: Allocator, argv: []const []const u8) anyerror![]const u8 {
        const q: *Quiet = @ptrCast(@alignCast(context));
        const result = try std.process.run(gpa, q.io, .{ .argv = argv });
        if (result.term != .exited or result.term.exited != 0) return error.CommandFailed;
        return result.stdout;
    }
};

/// testApk is an apk as melange writes one: a control member, then the
/// data member holding the stub.
fn testApk(gpa: Allocator, stub_bytes: []const u8) ![]u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    for ([_][2][]const u8{
        .{ ".PKGINFO", "pkgname = stub\n" },
        .{ stub_member, stub_bytes },
    }) |file| {
        var buf: [64 << 10]u8 = undefined;
        var raw = try std.compress.flate.Compress.Raw.init(&out.writer, &buf, .gzip);
        var tar: std.tar.Writer = .{ .underlying_writer = &raw.writer };
        try tar.writeFileBytes(file[0], file[1], .{});
        try raw.finish();
    }
    return out.written();
}

const Scratch = struct {
    tmp: testing.TmpDir,
    root: []const u8,
    env: Environ.Map,

    fn init(gpa: Allocator) !Scratch {
        var tmp = testing.tmpDir(.{});
        return .{
            .root = try tmp.dir.realPathFileAlloc(testing.io, ".", gpa),
            .tmp = tmp,
            .env = .init(gpa),
        };
    }

    fn path(s: *const Scratch, gpa: Allocator, name: []const u8) ![]const u8 {
        return gpa.print("{s}/{s}", .{ s.root, name });
    }

    fn write(s: *const Scratch, gpa: Allocator, name: []const u8, data: []const u8) ![]const u8 {
        const p = try s.path(gpa, name);
        try Dir.cwd().createDirPath(testing.io, std.fs.path.dirname(p).?);
        try Dir.cwd().writeFile(testing.io, .{ .sub_path = p, .data = data });
        return p;
    }

    /// tree writes the public build inputs, each holding its own name.
    fn tree(s: *const Scratch, gpa: Allocator) ![]const u8 {
        for (kernel_sources ++
            stub_sources) |name| _ = try s.write(gpa, try gpa.print("tree/{s}", .{name}), name);
        return s.path(gpa, "tree");
    }

    fn host(s: *Scratch, runner: Runner) Host {
        return .{
            .io = testing.io,
            .os = .linux,
            .machine = "aarch64",
            .env = &s.env,
            .runner = runner,
        };
    }
};

fn completed(io: Io, gpa: Allocator, dir: []const u8) !void {
    for ([_][]const u8{ "rootfs.tar", "linux.efi.stub" }) |name|
        try Dir.cwd().writeFile(
            io,
            .{ .sub_path = try gpa.print("{s}/{s}", .{ dir, name }), .data = name },
        );
    try complete(io, gpa, dir, "pinned", &.{ "rootfs.tar", "linux.efi.stub" });
}

test "tampered, missing, extra or linked outputs invalidate the cache" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var s: Scratch = try .init(gpa);
    defer s.tmp.cleanup();
    const both = [_][]const u8{ "rootfs.tar", "linux.efi.stub" };
    try completed(io, gpa, s.root);
    try testing.expect(valid(io, gpa, s.root, "pinned", &both));
    try testing.expect(!valid(io, gpa, s.root, "other", &both));
    _ = try s.write(gpa, "rootfs.tar", "tampered");
    try testing.expect(!valid(io, gpa, s.root, "pinned", &both));
    try completed(io, gpa, s.root);
    try Dir.cwd().deleteFile(io, try s.path(gpa, "linux.efi.stub"));
    try testing.expect(!valid(io, gpa, s.root, "pinned", &both));
    try completed(io, gpa, s.root);
    try Dir.rename(
        Dir.cwd(),
        try s.path(gpa, "complete.json"),
        Dir.cwd(),
        try s.path(gpa, "complete.json.new"),
        io,
    );
    try testing.expect(!valid(io, gpa, s.root, "pinned", &both));
    try completed(io, gpa, s.root);
    const json = try Dir.cwd().readFileAlloc(
        io,
        try s.path(gpa, "complete.json"),
        gpa,
        .limited(4096),
    );
    _ = try s.write(
        gpa,
        "complete.json",
        try mem.replaceOwned(
            u8,
            gpa,
            json,
            "{\"rootfs.tar\"",
            "{\"../private.key\":\"00\",\"rootfs.tar\"",
        ),
    );
    try testing.expect(!valid(io, gpa, s.root, "pinned", &both));
    try completed(io, gpa, s.root);
    try Dir.rename(
        Dir.cwd(),
        try s.path(gpa, "linux.efi.stub"),
        Dir.cwd(),
        try s.path(gpa, "other.stub"),
        io,
    );
    try Dir.cwd().symLink(
        io,
        try s.path(gpa, "other.stub"),
        try s.path(gpa, "linux.efi.stub"),
        .{},
    );
    try testing.expect(!valid(io, gpa, s.root, "pinned", &both));
}

test "the cache follows bytes and architecture, not times" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var s: Scratch = try .init(gpa);
    defer s.tmp.cleanup();
    const pin = try s.write(gpa, "pin", "source 1");
    const inputs = [_]Input{.{ .name = "pin", .path = pin }};
    const before = try fingerprint(io, gpa, "aarch64", &inputs);
    const file = try Dir.cwd().openFile(io, pin, .{ .mode = .read_write });
    try file.setTimestamps(
        io,
        .{
            .access_timestamp = .{ .new = .fromNanoseconds(1) },
            .modify_timestamp = .{ .new = .fromNanoseconds(1) },
        },
    );
    file.close(io);
    try testing.expectEqualStrings(&before, &try fingerprint(io, gpa, "aarch64", &inputs));
    try testing.expect(!mem.eql(u8, &before, &try fingerprint(io, gpa, "x86_64", &inputs)));
    _ = try s.write(gpa, "pin", "source 2");
    try testing.expect(!mem.eql(u8, &before, &try fingerprint(io, gpa, "aarch64", &inputs)));
}

test "package pins take one architecture's packages, each once" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var s: Scratch = try .init(gpa);
    defer s.tmp.cleanup();
    const package = "{{\"name\":\"{s}\",\"version\":\"{s}\",\"architecture\":\"{s}\"}}";
    const lock = try s.write(gpa, "lock.json", try gpa.print("{{\"contents\":{{\"packages\":[" ++
        package ++ "," ++ package ++ "," ++ package ++ "]}}}}", .{
        "libc", "1-r0", "x86_64", "shell", "2-r0", "x86_64", "libc", "1-r1", "aarch64",
    }));
    const pins = try packagePins(testing.io, gpa, lock, "x86_64");
    try testing.expectEqual(2, pins.len);
    try testing.expectEqualStrings("libc=1-r0", pins[0]);
    try testing.expectEqualStrings("shell=2-r0", pins[1]);
    try testing.expectError(error.BadPackageLock, packagePins(testing.io, gpa, lock, "riscv64"));
    const twice = try s.write(gpa, "twice.json", try gpa.print("{{\"contents\":{{\"packages\":[" ++
        package ++ "," ++ package ++
        "]}}}}", .{ "libc", "1-r0", "x86_64", "libc", "1-r1", "x86_64" }));
    try testing.expectError(error.BadPackageLock, packagePins(testing.io, gpa, twice, "x86_64"));
}

test "the policy signer survives restarts and is never rotated implicitly" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var s: Scratch = try .init(gpa);
    defer s.tmp.cleanup();
    var quiet: Quiet = .{ .io = io };
    const host = s.host(quiet.runner());
    const partial = try s.write(gpa, "partial/policy.key", "private");
    try testing.expectError(
        error.PartialPolicyIdentity,
        identity(gpa, host, try s.path(gpa, "partial")),
    );
    try testing.expectEqualStrings(
        "private",
        try Dir.cwd().readFileAlloc(io, partial, gpa, .limited(64)),
    );
    const dir = try s.path(gpa, "signer");
    const first = try identity(gpa, host, dir);
    const key = try digest(io, first.key);
    const cert = try digest(io, first.cert);
    const again = try identity(gpa, host, dir);
    try testing.expectEqual(key, try digest(io, again.key));
    try testing.expectEqual(cert, try digest(io, again.cert));
    try Dir.cwd().setFilePermissions(io, first.key, .fromMode(0o644), .{});
    try testing.expectError(error.PublicPolicyKey, identity(gpa, host, dir));
    try Dir.cwd().deleteFile(io, first.key);
    try Dir.cwd().deleteFile(io, first.cert);
    try testing.expectError(error.LostPolicyIdentity, identity(gpa, host, dir));
    try testing.expectError(error.FileNotFound, Dir.cwd().access(io, first.key, .{}));
    try testing.expectError(error.FileNotFound, Dir.cwd().access(io, first.cert, .{}));
}

test "melange sees public inputs only, and no signing environment" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var s: Scratch = try .init(gpa);
    defer s.tmp.cleanup();
    const tree = try s.tree(gpa);
    const key = try s.write(gpa, "private.key", "PRIVATE_SENTINEL");
    try s.env.put("WEREWOLF_BOOT_KEY", "PRIVATE_SENTINEL");
    try s.env.put("WEREWOLF_IPE_KEY", key);
    try s.env.put("QEMU_KERNEL_IMAGE", try s.write(gpa, "kernel", ""));
    try s.env.put("QEMU_BASE_INITRAMFS", try s.write(gpa, "initrd", ""));
    try s.env.put("PATH", "/usr/bin:/bin");
    var fake: Fake = .{ .gpa = gpa, .io = io };
    var host = s.host(fake.runner());
    host.os = .macos;
    const output = try s.path(gpa, "linux.efi.stub");
    try melange(gpa, host, tree, s.root, "aarch64", output);
    try testing.expectEqualStrings(
        "stub1",
        try Dir.cwd().readFileAlloc(io, output, gpa, .limited(64)),
    );
    try testing.expectEqual(stub_sources.len, fake.sources.items.len);
    for (stub_sources) |name| {
        for (fake.sources.items) |got| {
            if (mem.eql(u8, got, name)) break;
        } else return error.TestUnexpectedResult;
    }
    const run = fake.runs.items[0];
    try testing.expectEqualStrings("qemu", Fake.value(run.argv, "--runner"));
    try testing.expect(run.env.?.get("WEREWOLF_BOOT_KEY") == null);
    try testing.expect(run.env.?.get("WEREWOLF_IPE_KEY") == null);
    try testing.expectEqualStrings("0", run.env.?.get("SOURCE_DATE_EPOCH").?);
    try testing.expectEqualStrings("/usr/bin:/bin", run.env.?.get("PATH").?);
    try testing.expectEqualStrings(
        "PRIVATE_SENTINEL",
        try Dir.cwd().readFileAlloc(io, key, gpa, .limited(64)),
    );
    // The staging is gone.
    try testing.expectError(
        error.FileNotFound,
        Dir.cwd().access(io, std.fs.path.dirname(Fake.value(run.argv, "--source-dir")).?, .{}),
    );

    s.env.clearRetainingCapacity();
    try s.env.put("WEREWOLF_IPE_KEY", "PRIVATE_SENTINEL");
    var linux: Fake = .{ .gpa = gpa, .io = io };
    try melange(gpa, s.host(linux.runner()), tree, s.root, "x86_64", output);
    try testing.expectEqualStrings("bubblewrap", Fake.value(linux.runs.items[0].argv, "--runner"));
    try testing.expect(linux.runs.items[0].env.?.get("WEREWOLF_IPE_KEY") == null);
}

test "a Mac without Melange's guest refuses before any runner starts" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var s: Scratch = try .init(gpa);
    defer s.tmp.cleanup();
    const tree = try s.tree(gpa);
    try s.env.put("QEMU_KERNEL_IMAGE", "/missing/kernel");
    try s.env.put("QEMU_BASE_INITRAMFS", "/missing/initrd");
    var fake: Fake = .{ .gpa = gpa, .io = io };
    var host = s.host(fake.runner());
    host.os = .macos;
    try testing.expectError(
        error.MissingMelangeGuest,
        melange(gpa, host, tree, s.root, "aarch64", try s.path(gpa, "stub")),
    );
    try testing.expectError(
        error.MissingMelangeGuest,
        testKernel(gpa, host, tree, "aarch64", "cert", "out"),
    );
    try testing.expectError(
        error.ForeignKernelArch,
        testKernel(gpa, host, tree, "x86_64", "cert", "out"),
    );
    host.os = .linux;
    try testing.expectError(
        error.ForeignKernelArch,
        testKernel(gpa, host, tree, "x86_64", "cert", "out"),
    );
    try testing.expectEqual(0, fake.runs.items.len);
    var dir = try Dir.cwd().openDir(io, s.root, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |entry| try testing.expect(!mem.startsWith(
        u8,
        entry.name,
        "melange-public-",
    ));

    host.machine = "x86_64";
    const cert = try s.path(gpa, "policy.crt");
    const output = try s.path(gpa, "rootfs.tar");
    try testKernel(gpa, host, tree, "x86_64", cert, output);
    try testing.expectEqual(1, fake.runs.items.len);
    const argv = fake.runs.items[0].argv;
    try testing.expectEqual(5, argv.len);
    try testing.expectEqualStrings("sh", argv[0]);
    try testing.expectEqualStrings(try gpa.print("{s}/tools/test-kernel", .{tree}), argv[1]);
    for ([_][]const u8{ "x86_64", cert, output }, argv[2..]) |want, got|
        try testing.expectEqualStrings(want, got);
    try testing.expectEqualStrings(
        "/missing/kernel",
        fake.runs.items[0].env.?.get("QEMU_KERNEL_IMAGE").?,
    );
    try testing.expectEqualStrings(
        "/missing/initrd",
        fake.runs.items[0].env.?.get("QEMU_BASE_INITRAMFS").?,
    );
}

test "the test kernel receives the prepared guest and only its build environment" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var s: Scratch = try .init(gpa);
    defer s.tmp.cleanup();
    const tree = try s.tree(gpa);
    const kernel = try s.write(gpa, "kernel", "guest kernel");
    const initrd = try s.write(gpa, "initrd", "guest initramfs");
    const names = [_][]const u8{
        "PATH",              "HOME",                "LANG",        "SSL_CERT_FILE",
        "QEMU_KERNEL_IMAGE", "QEMU_BASE_INITRAMFS", "MELANGE_CPU", "MELANGE_MEMORY",
    };
    const values = [_][]const u8{
        "/usr/bin:/bin", s.root, "C", "/public/ca.pem", kernel, initrd, "2", "4096",
    };
    for (names, values) |name, value| try s.env.put(name, value);
    try s.env.put("WEREWOLF_BOOT_KEY", "PRIVATE_SENTINEL");
    try s.env.put("WEREWOLF_IPE_KEY", "PRIVATE_SENTINEL");
    var fake: Fake = .{ .gpa = gpa, .io = testing.io };
    var host = s.host(fake.runner());
    host.os = .macos;
    try testKernel(gpa, host, tree, "aarch64", "public.crt", try s.path(gpa, "rootfs.tar"));
    try testing.expectEqual(1, fake.runs.items.len);
    const env = fake.runs.items[0].env.?;
    try testing.expectEqual(names.len, env.count());
    for (names, values) |name, value| try testing.expectEqualStrings(value, env.get(name).?);
    try testing.expect(env.get("WEREWOLF_BOOT_KEY") == null);
    try testing.expect(env.get("WEREWOLF_IPE_KEY") == null);
}

const Cached = struct {
    s: Scratch,
    tree: []const u8,
    cache: []const u8,
    cert: []const u8,
    fake: Fake,

    fn init(gpa: Allocator) !*Cached {
        const c = try gpa.create(Cached);
        c.s = try .init(gpa);
        c.tree = try c.s.tree(gpa);
        c.cache = try c.s.path(gpa, "cache");
        c.cert = try c.s.write(gpa, "cert", "public policy certificate");
        c.fake = .{ .gpa = gpa, .io = testing.io };
        return c;
    }

    fn build(c: *Cached, gpa: Allocator) ![]const u8 {
        return @import("security-inputs.zig").build(
            gpa,
            c.s.host(c.fake.runner()),
            c.tree,
            c.cache,
            "aarch64",
            c.cert,
        );
    }

    fn expectCalls(c: *Cached, want: []const []const u8) !void {
        try testing.expectEqual(want.len, c.fake.calls.items.len);
        for (want, c.fake.calls.items) |w, got| try testing.expectEqualStrings(w, got);
    }
};

test "the kernel and stub rebuild for their own inputs alone" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    const c = try Cached.init(gpa);
    defer c.s.tmp.cleanup();
    const first = try c.build(gpa);
    try c.expectCalls(&.{ "kernel", "stub" });
    const kernel = try gpa.print("{s}/rootfs.tar", .{first});
    const before = (try Dir.cwd().statFile(io, kernel, .{})).mtime;
    try testing.expectEqualStrings(first, try c.build(gpa));
    try c.expectCalls(&.{ "kernel", "stub" });
    try testing.expectEqual(before, (try Dir.cwd().statFile(io, kernel, .{})).mtime);
    _ = try c.s.write(gpa, "tree/boot/stub-source", "changed measured stub pin");
    const second = try c.build(gpa);
    try c.expectCalls(&.{ "kernel", "stub", "stub" });
    try testing.expectEqualStrings(
        "kernel1",
        try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/rootfs.tar", .{second}),
            gpa,
            .limited(64),
        ),
    );
    _ = try c.s.write(gpa, "cert", "changed policy authority");
    const third = try c.build(gpa);
    try c.expectCalls(&.{ "kernel", "stub", "stub", "kernel" });
    try testing.expectEqualStrings(
        "stub3",
        try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/linux.efi.stub", .{third}),
            gpa,
            .limited(64),
        ),
    );
    _ = try c.s.write(gpa, "tree/boot/kernel-build", "commit=another");
    _ = try c.build(gpa);
    try c.expectCalls(&.{ "kernel", "stub", "stub", "kernel", "kernel" });
}

test "a combined cache is adopted, and an interrupted stub keeps its kernel" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    const c = try Cached.init(gpa);
    defer c.s.tmp.cleanup();
    c.fake.fail = "stub";
    try testing.expectError(error.CommandFailed, c.build(gpa));
    c.fake.fail = null;
    const target = try c.build(gpa);
    try c.expectCalls(&.{ "kernel", "stub failure", "stub" });
    var dir = try Dir.cwd().openDir(
        io,
        try gpa.print("{s}/aarch64", .{c.cache}),
        .{ .iterate = true },
    );
    defer dir.close(io);
    var parts: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |entry| if (mem.startsWith(u8, entry.name, "test-kernel-") or
        mem.startsWith(
            u8,
            entry.name,
            "stub-",
        )) try parts.append(gpa, try gpa.dupe(u8, entry.name));
    try testing.expectEqual(2, parts.items.len);
    for (parts.items) |part| try dir.deleteTree(io, part);
    try testing.expectEqualStrings(target, try c.build(gpa));
    try c.expectCalls(&.{ "kernel", "stub failure", "stub" });
}

test "a corrupt kernel and its cache rebuild the kernel, not the stub" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    const c = try Cached.init(gpa);
    defer c.s.tmp.cleanup();
    const target = try c.build(gpa);
    // Built outputs are links of the parts' outputs: overwrite both in place.
    try Dir.cwd().deleteFile(io, try gpa.print("{s}/rootfs.tar", .{target}));
    _ = try c.s.write(
        gpa,
        try gpa.print("cache/aarch64/{s}/rootfs.tar", .{std.fs.path.basename(target)}),
        "corrupt kernel",
    );
    var dir = try Dir.cwd().openDir(
        io,
        try gpa.print("{s}/aarch64", .{c.cache}),
        .{ .iterate = true },
    );
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |entry| if (mem.startsWith(u8, entry.name, "test-kernel-")) {
        try dir.deleteFile(io, try gpa.print("{s}/rootfs.tar", .{entry.name}));
        try dir.writeFile(
            io,
            .{
                .sub_path = try gpa.print("{s}/rootfs.tar", .{entry.name}),
                .data = "corrupt build",
            },
        );
    };
    _ = try c.build(gpa);
    try c.expectCalls(&.{ "kernel", "stub", "kernel" });
    const saved = try std.json.parseFromSliceLeaky(
        Completion,
        gpa,
        try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/complete.json", .{target}),
            gpa,
            .limited(4096),
        ),
        .{},
    );
    try testing.expect(valid(io, gpa, target, saved.inputs, &.{ "rootfs.tar", "linux.efi.stub" }));
}

fn limaRecord(gpa: Allocator, status: []const u8, change: []const u8) ![]const u8 {
    const base = "{\"name\":\"werewolf-build\",\"arch\":\"aarch64\",\"status\":\"STATUS\"," ++
        "\"config\":{\"os\":\"Linux\",\"mounts\":[],\"ssh\":{\"forwardAgent\":false}}}";
    const named = try mem.replaceOwned(u8, gpa, base, "STATUS", status);
    if (change.len == 0) return named;
    var parts = mem.splitScalar(u8, change, '|');
    return mem.replaceOwned(u8, gpa, named, parts.next().?, parts.next().?);
}

test "the build helper is created and started before its shell, and only safe" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var s: Scratch = try .init(gpa);
    defer s.tmp.cleanup();
    const stopped = try limaRecord(gpa, "Stopped", "");
    const running = try limaRecord(gpa, "Running", "");
    for ([_]struct { []const []const u8, []const []const u8 }{
        .{ &.{ "", stopped, running }, &.{ "create", "start", "shell" } },
        .{ &.{ stopped, running }, &.{ "start", "shell" } },
        .{ &.{running}, &.{"shell"} },
    }) |case| {
        var fake: Fake = .{ .gpa = gpa, .io = io, .listings = case[0] };
        try ensureHelper(gpa, s.host(fake.runner()), "werewolf-build", "/embedded/template.yaml");
        try testing.expectEqual(case[1].len, fake.calls.items.len);
        for (case[1], fake.calls.items) |want, got| try testing.expectEqualStrings(want, got);
        if (case[0][0].len == 0)
            try testing.expectEqualStrings("/embedded/template.yaml", fake.runs.items[0].argv[5]);
        try testing.expectEqualStrings(helper_setup, fake.runs.getLast().stdin.?);
    }
    for ([_][]const []const u8{
        &.{ "", "" },
        &.{ stopped, "" },
        &.{ stopped, stopped },
    }) |states| {
        var fake: Fake = .{ .gpa = gpa, .io = io, .listings = states };
        try testing.expect(std.meta.isError(ensureHelper(
            gpa,
            s.host(fake.runner()),
            "werewolf-build",
            "t.yaml",
        )));
        for (fake.calls.items) |call| try testing.expect(!mem.eql(u8, call, "shell"));
    }
    for ([_][]const u8{
        "\"arch\":\"aarch64\"|\"arch\":\"x86_64\"",
        "\"os\":\"Linux\"|\"os\":\"Other\"",
        "\"mounts\":[]|\"mounts\":[{\"location\":\"/Users/somebody\",\"writable\":false}]",
        "\"forwardAgent\":false|\"forwardAgent\":true",
    }) |change| {
        var fake: Fake = .{
            .gpa = gpa,
            .io = io,
            .listings = &.{try limaRecord(gpa, "Stopped", change)},
        };
        try testing.expect(std.meta.isError(ensureHelper(
            gpa,
            s.host(fake.runner()),
            "werewolf-build",
            "t.yaml",
        )));
        try testing.expectEqual(0, fake.runs.items.len);
    }
    for ([_][]const u8{
        "",
        "../somebody",
        "-flag",
        "space name",
        &@as([65]u8, @splat('a')),
    }) |name| {
        var fake: Fake = .{ .gpa = gpa, .io = io };
        try testing.expectError(
            error.BadHelperName,
            ensureHelper(gpa, s.host(fake.runner()), name, "t.yaml"),
        );
        try testing.expectEqual(0, fake.listed);
    }
    const two = try gpa.print("{s}\n{s}", .{ stopped, stopped });
    var fake: Fake = .{ .gpa = gpa, .io = io, .listings = &.{ two, "{\"name\":\"other\"}" } };
    try testing.expectError(
        error.AmbiguousHelper,
        helperInstance(gpa, s.host(fake.runner()), "werewolf-build"),
    );
    try testing.expectEqual(null, try helperInstance(gpa, s.host(fake.runner()), "werewolf-build"));
}

test "helper preparation takes a private lock and releases it after a failure" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var s: Scratch = try .init(gpa);
    defer s.tmp.cleanup();
    try s.env.put("LIMA_HOME", s.root);
    var fake: Fake = .{
        .gpa = gpa,
        .io = io,
        .listings = &.{ try limaRecord(gpa, "Running", ""), try limaRecord(gpa, "Running", "") },
    };
    fake.fail = "shell";
    try testing.expectError(
        error.CommandFailed,
        prepareHelper(gpa, s.host(fake.runner()), "werewolf-build", "t.yaml"),
    );
    fake.fail = null;
    try prepareHelper(gpa, s.host(fake.runner()), "werewolf-build", "t.yaml");
    const st = try Dir.cwd().statFile(
        io,
        try s.path(gpa, ".werewolf-build-werewolf-build.lock"),
        .{},
    );
    try testing.expectEqual(0o600, st.permissions.toMode() & 0o777);
}
