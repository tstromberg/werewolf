//! Cached local security inputs; only public IPE trust reaches a build helper.
const std = @import("std");
const howl = @import("howl.zig");
const native = @import("build.zig");
const progress = @import("progress.zig");
const Dir = std.Io.Dir;

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

pub fn resolve(
    io: std.Io,
    gpa: std.mem.Allocator,
    steps: *progress.Steps,
    arch: howl.Arch,
    why: *howl.Why,
) !Inputs {
    const kernel = howl.environ.get("WEREWOLF_IPE_KERNEL");
    const key = howl.environ.get("WEREWOLF_IPE_KEY");
    const cert = howl.environ.get("WEREWOLF_IPE_CRT");
    const external = supplied(kernel, key, cert) catch return why.refuse(
        "supply all three IPE kernel/key/certificate overrides, or let howl manage them",
        .{},
    );
    const cwd = try std.process.currentPathAlloc(io, gpa);
    if (external and howl.environ.get("UKI_STUB") != null) return .{
        .kernel = try absolute(gpa, cwd, kernel.?),
        .key = try absolute(gpa, cwd, key.?),
        .cert = try absolute(
            gpa,
            cwd,
            cert.?,
        ),
        .stub = try absolute(gpa, cwd, howl.environ.get("UKI_STUB").?),
    };
    const cache = try gpa.print("{s}/build/secure-cache", .{cwd});
    try Dir.cwd().createDirPath(io, cache);
    try Dir.cwd().setFilePermissions(io, cache, .fromMode(0o700), .{});
    const source = try materialize(io, gpa, cache);
    const script = try gpa.print("{s}/local-prerequisites", .{source});
    var nonce: [8]u8 = undefined;
    try io.randomSecure(&nonce);
    const report = try gpa.print("{s}/paths-{x}.json", .{ cache, &nonce });
    defer Dir.cwd().deleteFile(io, report) catch {};
    var base: []const u8 = "unused";
    var env = try howl.environ.clone(gpa);
    defer env.deinit();
    if (!external or @import("builtin").os.tag == .macos) {
        var build = try native.prepare(io, gpa, steps, .{
            .form = "minimal",
            .arch = arch,
            .build = try gpa.print("{s}/alpine/{t}", .{ cache, arch }),
        });
        try @import("packages.zig").kernel(&build);
        base = try gpa.print("{s}/kernel/rootfs.tar", .{build.p.build});
        if (@import("builtin").os.tag == .macos) {
            try env.put("QEMU_KERNEL_IMAGE", try gpa.print("{s}/vmlinuz", .{build.p.build}));
            try env.put("QEMU_BASE_INITRAMFS", try absolute(
                gpa,
                cwd,
                try @import("melange.zig").guest(&build),
            ));
        }
    }
    try steps.enter(.{
        .name = "Checking cached security inputs",
        .short = "security inputs",
    });
    if (!(try steps.exec(&.{.{ .argv = &.{
        "python3",      script,
        if (external)
            "stub"
        else
            "all",
        source,         cache,
        @tagName(arch), base,
        report,
    }, .env = &env }}, .{ .phases = true })).ok) return steps.fail(
        "preparing security inputs failed; see the builder dependencies in docs/testing.md",
    );
    var inputs = try std.json.parseFromSliceLeaky(Inputs, gpa, try Dir.cwd().readFileAlloc(
        io,
        report,
        gpa,
        .limited(4096),
    ), .{});
    if (external) {
        inputs.kernel = try absolute(gpa, cwd, kernel.?);
        inputs.key = try absolute(gpa, cwd, key.?);
        inputs.cert = try absolute(gpa, cwd, cert.?);
    }
    if (howl.environ.get("UKI_STUB")) |stub| inputs.stub = try absolute(gpa, cwd, stub);
    return inputs;
}

fn absolute(gpa: std.mem.Allocator, cwd: []const u8, path: []const u8) ![]const u8 {
    return if (std.fs.path.isAbsolute(path)) path else gpa.print("{s}/{s}", .{ cwd, path });
}

fn materialize(io: std.Io, gpa: std.mem.Allocator, cache: []const u8) ![]const u8 {
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

test "managed IPE inputs refuse partial overrides" {
    try std.testing.expect(!try supplied(null, null, null));
    try std.testing.expect(try supplied("kernel", "key", "cert"));
    try std.testing.expectError(error.PartialIpeInputs, supplied("kernel", null, null));
    try std.testing.expectError(error.PartialIpeInputs, supplied(null, "key", "cert"));
}
