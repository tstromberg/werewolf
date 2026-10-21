//! Small SSH command utility, included only in disposable iteration images.
//! sh-shim runs this one command; no shell or coreutils are needed.
const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;
const driver = @import("driver.zig");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len == 2 and std.mem.eql(u8, args[1], "ping")) return;
    if (args.len != 3) return error.Usage;
    if (std.mem.eql(u8, args[1], "ready")) {
        try Io.Dir.cwd().access(io, args[2], .{});
        return;
    }
    const name = args[2];
    if (!driverName(name)) return error.InvalidDriver;
    const directory = try gpa.print("/usr/share/werewolf/tests/{s}", .{name});
    // Descriptors come from the immutable image, never from an upload.
    try Io.Dir.cwd().access(io, try gpa.print("{s}/service", .{directory}), .{});
    const Launch = struct { root: bool, mode: []const u8, probes: bool };
    const launch_raw = try Io.Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/launch.json", .{directory}),
        gpa,
        .limited(4096),
    );
    const launch = try std.json.parseFromSliceLeaky(Launch, gpa, launch_raw, .{});
    if (std.mem.eql(u8, args[1], "install")) {
        const temporary = try gpa.print("/run/howl-dev/.{s}.new", .{name});
        try installFile(
            io,
            .cwd(),
            temporary,
            try gpa.print("/run/howl-dev/{s}", .{name}),
            0o755,
        );
        if (launch.probes) try installFile(
            io,
            .cwd(),
            try gpa.print("/run/howl-dev/.{s}.json.new", .{name}),
            try gpa.print("/run/howl-dev/{s}.json", .{name}),
            0o644,
        );
        try Io.Dir.cwd().rename(
            "/run/config/.native-iterate-context.new",
            Io.Dir.cwd(),
            "/run/config/native-iterate-context",
            io,
        );
        return;
    }
    if (!std.mem.eql(u8, args[1], "run")) return error.Usage;
    const context = try driver.Run.load(io, gpa, "/run/config/native-iterate-context");
    if (linux.errno(linux.chdir(try gpa.dupeSentinel(u8, directory, 0))) != .SUCCESS)
        return error.ChangeDirectory;
    const result = try std.process.run(gpa, io, .{
        .argv = if (launch.root) &.{
            try gpa.print(
                "/usr/lib/werewolf/{s}",
                .{name},
            ),
            name,
            launch.mode,
            "/run/config/native-iterate-context",
        } else &.{"/usr/lib/werewolf/leash"},
        .stdout_limit = .limited(64 << 10),
        .stderr_limit = .limited(16 << 10),
        .timeout = driver.deadline(io, context.timeout_seconds),
    });
    try Io.File.stdout().writeStreamingAll(io, result.stdout);
    try Io.File.stderr().writeStreamingAll(io, result.stderr);
    if (result.term != .exited or result.term.exited != 0)
        std.process.exit(if (result.term == .exited) result.term.exited else 1);
}

fn driverName(name: []const u8) bool {
    if (name.len == 0 or name.len > 128 or name[0] < 'a' or name[0] > 'z') return false;
    for (name) |c| if (!(c >= 'a' and c <= 'z') and !(c >= '0' and c <= '9') and c != '-')
        return false;
    return true;
}

test "driver names cannot select an uploaded descriptor" {
    try std.testing.expect(driverName("test-postgres"));
    for ([_][]const u8{ "", "../test-postgres", "/run/x", "test;id", "test/x" }) |name|
        try std.testing.expect(!driverName(name));
}

fn installFile(io: Io, dir: Io.Dir, temporary: []const u8, target: []const u8, mode: u16) !void {
    const file = try dir.openFile(io, temporary, .{});
    defer file.close(io);
    try file.setPermissions(io, .fromMode(mode));
    try dir.rename(temporary, dir, target, io);
}

test "uploaded plans are readable data, binaries executable, and contexts private" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "program.new", "plan.new", "context" }) |name| {
        const file = try tmp.dir.createFile(io, name, .{ .permissions = .fromMode(0o600) });
        file.close(io);
    }
    try installFile(io, tmp.dir, "program.new", "program", 0o755);
    try installFile(io, tmp.dir, "plan.new", "plan", 0o644);
    for ([_]struct { name: []const u8, mode: u16 }{
        .{ .name = "program", .mode = 0o755 },
        .{ .name = "plan", .mode = 0o644 },
        .{ .name = "context", .mode = 0o600 },
    }) |expected| {
        const stat = try tmp.dir.statFile(io, expected.name, .{});
        try std.testing.expectEqual(expected.mode, stat.permissions.toMode() & 0o777);
    }
}
