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
    const source = try gpa.print("{s}/source", .{cache});
    for (@import("files").secure_sources) |file| {
        const path = try gpa.print("{s}/{s}", .{ source, file.path });
        try Dir.cwd().createDirPath(io, std.fs.path.dirname(path).?);
        try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = file.data });
    }
    const script = try gpa.print("{s}/local-prerequisites", .{source});
    var nonce: [8]u8 = undefined;
    try io.randomSecure(&nonce);
    const report = try gpa.print("{s}/paths-{x}.json", .{ cache, &nonce });
    defer Dir.cwd().deleteFile(io, report) catch {};
    var base: []const u8 = "unused";
    if (!external) {
        var build = try native.prepare(io, gpa, steps, .{
            .form = "minimal",
            .arch = arch,
            .build = try gpa.print("{s}/alpine/{t}", .{ cache, arch }),
        });
        try @import("packages.zig").kernel(&build);
        base = try gpa.print("{s}/kernel/rootfs.tar", .{build.p.build});
    }
    try steps.enter(.{
        .name = "Preparing pinned IPE kernel and measured EFI stub",
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
    }, .env = howl.environ }}, .{})).ok) return steps.fail(
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

test "managed IPE inputs refuse partial overrides" {
    try std.testing.expect(!try supplied(null, null, null));
    try std.testing.expect(try supplied("kernel", "key", "cert"));
    try std.testing.expectError(error.PartialIpeInputs, supplied("kernel", null, null));
    try std.testing.expectError(error.PartialIpeInputs, supplied(null, "key", "cert"));
}
