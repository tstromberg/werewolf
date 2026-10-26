//! Cached local security inputs (lib/security-inputs.zig); only public IPE
//! trust reaches a builder.
const std = @import("std");
const howl = @import("howl.zig");
const native = @import("build.zig");
const progress = @import("progress.zig");
const security = @import("security-inputs");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub const Inputs = struct {
    kernel: ?[]const u8 = null,
    key: ?[]const u8 = null,
    cert: ?[]const u8 = null,
    stub: []const u8,
};

pub fn supplied(kernel: ?[]const u8, key: ?[]const u8, cert: ?[]const u8) !bool {
    const count = @intFromBool(kernel != null) + @as(u8, @intFromBool(key != null)) +
        @as(u8, @intFromBool(cert != null));
    if (count != 0 and count != 3) return error.PartialIpeInputs;
    return count == 3;
}

/// Shown runs a build's commands under howl's progress, which logs them.
const Shown = struct {
    io: Io,
    steps: *progress.Steps,
    /// scratch holds a command's standard input while it runs.
    scratch: []const u8,

    fn runner(s: *Shown) security.Runner {
        return .{ .context = s, .run = run, .capture = capture, .phase = phase };
    }

    fn run(context: *anyopaque, gpa: Allocator, command: security.Command) anyerror!void {
        const s: *Shown = @ptrCast(@alignCast(context));
        var input: ?Io.File = null;
        defer if (input) |f| f.close(s.io);
        if (command.stdin) |data| {
            var nonce: [8]u8 = undefined;
            s.io.random(&nonce);
            const path = try gpa.print("{s}/stdin-{x}", .{ s.scratch, &nonce });
            try Dir.cwd().writeFile(s.io, .{ .sub_path = path, .data = data });
            input = try Dir.cwd().openFile(s.io, path, .{});
            try Dir.cwd().deleteFile(s.io, path);
        }
        const ran = try s.steps.exec(&.{.{ .argv = command.argv, .env = command.env }}, .{
            .stdin = input,
            .phases = true,
        });
        if (!ran.ok) return error.CommandFailed;
    }

    fn capture(context: *anyopaque, gpa: Allocator, argv: []const []const u8) anyerror![]const u8 {
        const s: *Shown = @ptrCast(@alignCast(context));
        const result = try std.process.run(gpa, s.io, .{
            .argv = argv,
            .stdout_limit = .limited(1 << 20),
            .stderr_limit = .limited(64 << 10),
        });
        if (result.term != .exited or result.term.exited != 0) {
            try s.steps.note("{s}: {s}", .{ argv[0], std.mem.trim(u8, result.stderr, " \n") });
            return error.CommandFailed;
        }
        return result.stdout;
    }

    fn phase(context: *anyopaque, short: []const u8, name: []const u8) void {
        const s: *Shown = @ptrCast(@alignCast(context));
        s.steps.enter(.{ .name = name, .short = short }) catch {};
    }
};

pub fn resolve(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    arch: howl.Arch,
    why: *howl.Why,
) !Inputs {
    return resolveFor(io, gpa, steps, arch, why, true);
}

pub fn resolveIpe(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    arch: howl.Arch,
    why: *howl.Why,
) !Inputs {
    return resolveFor(io, gpa, steps, arch, why, false);
}

fn resolveFor(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    arch: howl.Arch,
    why: *howl.Why,
    need_stub: bool,
) !Inputs {
    const kernel = howl.environ.get("WEREWOLF_IPE_KERNEL");
    const key = howl.environ.get("WEREWOLF_IPE_KEY");
    const cert = howl.environ.get("WEREWOLF_IPE_CRT");
    const external = supplied(kernel, key, cert) catch return why.refuse(
        "supply all three IPE kernel/key/certificate overrides, or let howl manage them",
        .{},
    );
    const cwd = try std.process.currentPathAlloc(io, gpa);
    if (external and (!need_stub or howl.environ.get("UKI_STUB") != null)) return .{
        .kernel = try absolute(gpa, cwd, kernel.?),
        .key = try absolute(gpa, cwd, key.?),
        .cert = try absolute(gpa, cwd, cert.?),
        .stub = if (need_stub) try absolute(gpa, cwd, howl.environ.get("UKI_STUB").?) else "",
    };
    const cache = try gpa.print("{s}/build/secure-cache", .{cwd});
    // The IPE signing identity is no cache: every machine made with it
    // trusts only roots its key signs, so it lives in howl's data directory.
    const identity = if (external)
        null
    else
        try howl.keysDir(io, gpa, "ipe", try gpa.print("{s}/signing", .{cache}));
    try Dir.cwd().createDirPath(io, cache);
    try Dir.cwd().setFilePermissions(io, cache, .fromMode(0o700), .{});
    const source = try materialize(io, gpa, cache);
    var env = try howl.environ.clone(gpa);
    defer env.deinit();
    if (@import("builtin").os.tag == .macos) {
        var build = try native.prepare(io, gpa, steps, .{
            .form = "minimal",
            .arch = arch,
            .build = try gpa.print("{s}/guest/{t}", .{ cache, arch }),
        });
        const guest = try @import("melange.zig").guest(&build);
        try env.put("QEMU_KERNEL_IMAGE", try absolute(gpa, cwd, guest.kernel));
        try env.put("QEMU_BASE_INITRAMFS", try absolute(gpa, cwd, guest.initramfs));
    }
    try steps.enter(.{
        .name = "Checking cached security inputs",
        .short = "security inputs",
    });
    var shown: Shown = .{ .io = io, .steps = steps, .scratch = cache };
    const host: security.Host = .{
        .io = io,
        .env = &env,
        .runner = shown.runner(),
    };
    const made = (if (need_stub)
        security.prepare(gpa, host, source, cache, @tagName(arch), identity)
    else
        security.prepareKernel(
            gpa,
            host,
            source,
            cache,
            @tagName(arch),
            identity.?,
        )) catch |err| return steps.fail(try gpa.print(
        "preparing security inputs failed: {s}; see the builder dependencies in docs/testing.md",
        .{@errorName(err)},
    ));
    var inputs: Inputs = .{
        .kernel = made.kernel,
        .key = made.key,
        .cert = made.cert,
        .stub = made.stub,
    };
    if (external) {
        inputs.kernel = try absolute(gpa, cwd, kernel.?);
        inputs.key = try absolute(gpa, cwd, key.?);
        inputs.cert = try absolute(gpa, cwd, cert.?);
    }
    if (howl.environ.get("UKI_STUB")) |stub| inputs.stub = try absolute(gpa, cwd, stub);
    return inputs;
}

/// helper is `howl _build-helper NAME TEMPLATE`: tools/enroll-boot's way
/// to the isolated Linux build helper, prepared as security-inputs does.
pub fn helper(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    const template = if (args.len == 2) Dir.cwd().statFile(io, args[1], .{}) catch null else null;
    if (template == null or template.?.kind != .file)
        return why.refuse("_build-helper NAME TEMPLATE.yaml", .{});
    var plain: security.Plain = .{ .io = io };
    security.prepareHelper(gpa, .{
        .io = io,
        .env = howl.environ,
        .runner = plain.runner(),
    }, args[0], args[1]) catch |err| return why.refuse(
        "Linux build helper preparation failed: {s}; no unprotected fallback",
        .{@errorName(err)},
    );
}

fn absolute(gpa: Allocator, cwd: []const u8, path: []const u8) ![]const u8 {
    return if (std.fs.path.isAbsolute(path)) path else gpa.print("{s}/{s}", .{ cwd, path });
}

fn materialize(io: Io, gpa: Allocator, cache: []const u8) ![]const u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (@import("files").secure_sources) |file| {
        for ([_][]const u8{ file.path, file.data }) |part| {
            var length: [8]u8 = undefined;
            std.mem.writeInt(u64, &length, part.len, .big);
            hash.update(&length);
            hash.update(part);
        }
    }
    const source = try gpa.print("{s}/source/{x}", .{ cache, &hash.finalResult() });
    for (@import("files").secure_sources) |file| {
        const path = try gpa.print("{s}/{s}", .{ source, file.path });
        const previous = Dir.cwd().readFileAlloc(
            io,
            path,
            gpa,
            .limited(file.data.len + 1),
        ) catch null;
        if (previous) |bytes| if (std.mem.eql(u8, bytes, file.data)) continue;
        try Dir.cwd().createDirPath(io, std.fs.path.dirname(path).?);
        try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = file.data });
    }
    return source;
}

test "cached builder sources keep timestamps and repair altered inputs" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const cache = try tmp.dir.realPathFileAlloc(t.io, ".", gpa);
    const source = try materialize(t.io, gpa, cache);
    const file = @import("files").secure_sources[0];
    const path = try gpa.print("{s}/{s}", .{ source, file.path });
    const before = try Dir.cwd().statFile(t.io, path, .{});
    try t.expectEqualStrings(source, try materialize(t.io, gpa, cache));
    const after = try Dir.cwd().statFile(t.io, path, .{});
    try t.expectEqual(before.mtime.nanoseconds, after.mtime.nanoseconds);
    try Dir.cwd().writeFile(t.io, .{ .sub_path = path, .data = "altered builder" });
    _ = try materialize(t.io, gpa, cache);
    try t.expectEqualStrings(
        file.data,
        try Dir.cwd().readFileAlloc(t.io, path, gpa, .limited(file.data.len + 1)),
    );
}

test "every builder source security-inputs reads is materialized" {
    for (security.stub_sources ++ security.kernel_sources ++ .{"boot/build-helper.yaml"}) |name| {
        for (@import("files").secure_sources) |file| {
            if (std.mem.eql(u8, file.path, name)) break;
        } else return error.TestUnexpectedResult;
    }
}

test "managed IPE inputs refuse partial overrides" {
    try std.testing.expect(!try supplied(null, null, null));
    try std.testing.expect(try supplied("kernel", "key", "cert"));
    try std.testing.expectError(error.PartialIpeInputs, supplied("kernel", null, null));
    try std.testing.expectError(error.PartialIpeInputs, supplied(null, "key", "cert"));
}
