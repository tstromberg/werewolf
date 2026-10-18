//! Host-local operator actions for an enrolled QEMU machine without guest SSH.
const std = @import("std");
const howl = @import("howl.zig");
const Operation = enum { status, pause, @"resume", check, outcome, @"try" };

pub fn command(io: std.Io, gpa: std.mem.Allocator, args: []const []const u8, why: *howl.Why) !void {
    const syntax = "owner [NAME] status|pause|resume|check|outcome|try [DECLARATION-HASH]";
    if (args.len == 0) return why.refuse("{s}", .{syntax});
    const unnamed = std.meta.stringToEnum(Operation, args[0]) != null and
        !(args.len > 1 and std.meta.stringToEnum(Operation, args[1]) != null);
    const name = if (unnamed) "werewolf-run" else args[0];
    const actions = args[@intFromBool(!unnamed)..];
    if (!howl.isMachineName(name) or actions.len == 0 or actions.len > 2 or
        std.meta.stringToEnum(Operation, actions[0]) == null)
        return why.refuse("{s}", .{syntax});
    const path = try gpa.print("{s}/owner.sock", .{try howl.machineDir(gpa, name)});
    std.Io.Dir.cwd().access(io, path, .{}) catch return why.refuse("{s}: no owner channel; start an enrolled QEMU image with current howl", .{name});
    // Resolve the actual interpreter before exec: a wrapper on PATH must not
    // keep the owner connection in a child after the caller kills howl.
    const probe = try std.process.run(gpa, io, .{
        .argv = &.{ "python3", "-c", "import sys; print(sys.executable)" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    const python = std.mem.trim(u8, probe.stdout, "\r\n");
    if (probe.term != .exited or probe.term.exited != 0 or !std.fs.path.isAbsolute(python) or
        std.mem.findScalar(u8, python, '\n') != null or std.mem.findScalar(u8, python, '\r') != null)
        return why.refuse("cannot resolve the owner-control Python interpreter", .{});
    const argv = try std.mem.concat(gpa, []const u8, &.{
        &.{ python, "-c", @import("files").owner_control, path }, actions,
    });
    const err = std.process.replace(io, .{ .argv = argv });
    return why.refuse("cannot start owner control: {s}", .{@errorName(err)});
}
