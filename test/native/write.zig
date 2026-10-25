//! write opens a path for writing, as the suite's user, where the open
//! must be refused. It creates a new file, or opens one that exists
//! without truncating it; an open that succeeds removes what it created.
const std = @import("std");
const Io = std.Io;

pub const Mode = enum { create, existing };

/// attempt returns how the open was refused, as an errno name where one
/// applies, or error.WriteNotRefused.
pub fn attempt(io: Io, path: []const u8, mode: Mode) ![]const u8 {
    const cwd = Io.Dir.cwd();
    const opened = switch (mode) {
        // Exclusive creation never follows a symbolic link or reuses a file.
        .create => cwd.createFile(io, path, .{
            .exclusive = true,
            .truncate = false,
            .permissions = .fromMode(0o600),
        }),
        .existing => cwd.openFile(io, path, .{
            .mode = .write_only,
            .follow_symlinks = false,
            .allow_directory = false,
        }),
    } catch |err| return errno(err);
    opened.close(io);
    if (mode == .create) try cwd.deleteFile(io, path);
    return error.WriteNotRefused;
}

/// probe attempts the write a validated step asks for, and says its errno.
pub fn probe(io: Io, a: std.mem.Allocator, request: std.json.Value) !std.json.Value {
    const why = if (request == .string)
        try attempt(io, request.string, .create)
    else
        try attempt(io, request.object.get("path").?.string, .existing);
    var got: std.json.ObjectMap = .empty;
    try got.put(a, "errno", .{ .string = why });
    return .{ .object = got };
}

fn errno(err: anyerror) []const u8 {
    return switch (err) {
        error.AccessDenied => "EACCES",
        error.PermissionDenied => "EPERM",
        error.ReadOnlyFileSystem => "EROFS",
        error.FileNotFound => "ENOENT",
        error.PathAlreadyExists => "EEXIST",
        error.IsDir => "EISDIR",
        error.NotDir => "ENOTDIR",
        error.SymLinkLoop => "ELOOP",
        error.FileBusy => "ETXTBSY",
        else => @errorName(err),
    };
}

const testing = std.testing;

test "a refused write reports why, and one that succeeds leaves nothing" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "code");
    try tmp.dir.writeFile(io, .{ .sub_path = "code/kept", .data = "original" });
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    const fresh = try a.print("{s}/code/new", .{root});
    try testing.expectError(error.WriteNotRefused, attempt(io, fresh, .create));
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, "code/new", .{}));
    const kept = try a.print("{s}/code/kept", .{root});
    try testing.expectEqualStrings("EEXIST", try attempt(io, kept, .create));
    try testing.expectError(error.WriteNotRefused, attempt(io, kept, .existing));
    try testing.expectEqualStrings(
        "original",
        try tmp.dir.readFileAlloc(io, "code/kept", a, .unlimited),
    );
    try testing.expectEqualStrings("ENOENT", try attempt(io, fresh, .existing));
    try tmp.dir.symLink(io, kept, "code/link", .{});
    try testing.expectEqualStrings(
        "ELOOP",
        try attempt(io, try a.print("{s}/code/link", .{root}), .existing),
    );
    try testing.expectEqualStrings(
        "EEXIST",
        try attempt(io, try a.print("{s}/code/link", .{root}), .create),
    );
    var code = try tmp.dir.openDir(io, "code", .{});
    defer code.close(io);
    try code.setPermissions(io, .fromMode(0o500));
    defer code.setPermissions(io, .fromMode(0o700)) catch {};
    if (attempt(io, fresh, .create)) |why|
        try testing.expectEqualStrings("EACCES", why)
    else |err| {
        // Root writes regardless of modes; only another user is refused.
        try testing.expectEqual(error.WriteNotRefused, err);
    }
}
