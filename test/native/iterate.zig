//! Small SSH command utility, included only in disposable iteration images.
//! sh-shim runs this one command; no shell or coreutils are needed.
const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;

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
    if (std.mem.eql(u8, args[1], "install")) {
        const temporary = try gpa.print("/run/howl-dev/.{s}.new", .{name});
        const file = try Io.Dir.cwd().openFile(io, temporary, .{});
        defer file.close(io);
        try file.setPermissions(io, .fromMode(0o755));
        try Io.Dir.cwd().rename(
            temporary,
            Io.Dir.cwd(),
            try gpa.print("/run/howl-dev/{s}", .{name}),
            io,
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
    if (linux.errno(linux.chdir(try gpa.dupeSentinel(u8, directory, 0))) != .SUCCESS)
        return error.ChangeDirectory;
    return std.process.replace(io, .{ .argv = &.{"/usr/lib/werewolf/leash"} });
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
