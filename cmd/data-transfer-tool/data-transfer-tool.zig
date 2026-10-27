//! Two fixed helper-image tools: pipe compression and checking a bounded
//! pg_control copy. Drop privileges before either tool processes source bytes.
const std = @import("std");
const sandbox = @import("sandbox");
const seal = @import("seal");
const linux = std.os.linux;
const Dir = std.Io.Dir;

pub fn main(init: std.process.Init) !void {
    sandbox.tieTo(linux.getppid());
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.TransferInvocation;
    const mode = std.meta.stringToEnum(enum { compress, postgres, @"compress-session", @"postgres-session" }, args[1]) orelse return error.TransferInvocation;
    const compress = mode == .compress or mode == .@"compress-session";
    const session = mode == .@"compress-session" or mode == .@"postgres-session";
    const program: []const u8 = if (compress) "/usr/bin/zstd" else "/usr/bin/pg_controldata";
    const io = init.io;
    var rules = try sandbox.Ruleset.init(.{});
    // These are helper-image runtime files, never code on an attached disk.
    const binary = try Dir.cwd().openFile(io, program, .{});
    try rules.add(binary.handle, sandbox.execute | sandbox.read_file);
    binary.close(io);
    for ([_][]const u8{ "/lib", "/usr/lib" }) |path| {
        const dir = try Dir.cwd().openDir(io, path, .{});
        try rules.add(dir.handle, sandbox.execute | sandbox.read_file);
        dir.close(io);
    }
    if (!compress) {
        const scratch = try Dir.cwd().openDir(io, "/run/pg-check", .{});
        try rules.add(scratch.handle, sandbox.read_dir | sandbox.read_file);
        scratch.close(io);
    }
    try sandbox.closeExcept(&.{rules.fd});
    try sandbox.limit(.AS, 256 << 20);
    if (!compress) try sandbox.limit(.CPU, 10);
    if (session) try sandbox.dropSession(78, 0) else try sandbox.dropTo(78, null);
    try rules.restrict();
    _ = linux.close(rules.fd);
    var filter: [seal.max_filter]seal.Filter = undefined;
    _ = try seal.install(seal.buildFilter(&filter, .initMany(&.{ .stdio, .rpath, .exec }), true), false);
    var env: std.process.Environ.Map = .init(init.arena.allocator());
    try env.put("LC_ALL", "C");
    return std.process.replace(io, .{ .argv = if (compress)
        &.{ program, "-1", "-q", "-c", "--single-thread", "--no-asyncio" }
    else
        &.{ program, "/run/pg-check" }, .environ_map = &env });
}
