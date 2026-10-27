//! Descriptor-confined read worker, shared by offline and SSH capture.
const std = @import("std");
const data = @import("data-transfer");
const sandbox = @import("sandbox");
const seal = @import("seal");
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const reader_id = 78;
pub const Options = struct { keep: []const i32 = &.{}, session: bool = false, child: ?u32 = null };

pub fn confine(io: Io, root: Dir, service: ?[]const u8, options: Options) !Dir {
    var rules = try sandbox.Ruleset.init(.{});
    defer _ = linux.close(rules.fd);
    var confined = root;
    if (service) |name| {
        // O_PATH parents allow traversal but do not hand the reader an open
        // enumeration handle for unselected service or machine directories.
        confined = try root.openDir(io, ".", .{});
        root.close(io);
        var services = try confined.openDir(io, "svc", .{ .follow_symlinks = false });
        defer services.close(io);
        try grant(io, &rules, services, name);
    } else {
        try rules.add(root.handle, sandbox.read_dir);
        var it = root.iterate();
        while (try it.next(io)) |entry| {
            if (data.excluded(entry.name)) continue;
            if (std.mem.eql(u8, entry.name, "svc")) {
                var services = try root.openDir(io, "svc", .{ .iterate = true, .follow_symlinks = false });
                defer services.close(io);
                try rules.add(services.handle, sandbox.read_dir);
                var children = services.iterate();
                while (try children.next(io)) |child| {
                    var path: [data.limits.path]u8 = undefined;
                    const name = try std.fmt.bufPrint(&path, "svc/{s}", .{child.name});
                    if (!data.excluded(name)) try grant(io, &rules, services, child.name);
                }
            } else try grant(io, &rules, root, entry.name);
        }
    }
    if (options.keep.len > 6) return error.TooManyKept;
    var kept: [8]i32 = undefined;
    kept[0] = confined.handle;
    kept[1] = rules.fd;
    @memcpy(kept[2..][0..options.keep.len], options.keep);
    try sandbox.closeExcept(kept[0 .. 2 + options.keep.len]);
    if (options.session) try sandbox.dropSession(reader_id, 1 << linux.CAP.DAC_READ_SEARCH) else try sandbox.dropKeeping(reader_id, 1 << linux.CAP.DAC_READ_SEARCH);
    _ = try sandbox.sys(linux.prctl(@backingInt(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0), "no_new_privs");
    try rules.restrict();
    try restrictPathMetadata();
    var filter: [seal.max_filter]seal.Filter = undefined;
    _ = try seal.install(if (options.child) |child| seal.buildPipeReaderFilter(&filter, child) else seal.buildFilter(&filter, .initMany(&.{ .stdio, .rpath }), true), false);
    return confined;
}

pub fn restrictPathMetadata() !void {
    // Landlock does not mediate these path-based metadata reads. Scanning
    // needs only fd-based xattr calls after opening an approved inode.
    var filter: [14]seal.Filter = undefined;
    filter[0] = .{ .code = seal.LD_W_ABS, .k = 0 };
    var n: usize = 1;
    inline for (.{ "getxattr", "lgetxattr", "listxattr", "llistxattr", "readlink", "readlinkat" }) |name| {
        if (@hasField(linux.SYS, name)) {
            filter[n] = .{ .code = seal.JEQ_K, .jf = 1, .k = @backingInt(@field(linux.SYS, name)) };
            filter[n + 1] = .{ .code = seal.RET_K, .k = linux.SECCOMP.RET.ERRNO | @as(u32, @backingInt(linux.E.ACCES)) };
            n += 2;
        }
    }
    filter[n] = .{ .code = seal.RET_K, .k = linux.SECCOMP.RET.ALLOW };
    _ = try seal.install(filter[0 .. n + 1], false);
}

fn grant(io: Io, rules: *sandbox.Ruleset, parent: Dir, name: []const u8) !void {
    if (!data.validPath(name) or std.mem.findScalar(u8, name, '/') != null) return error.TransferPath;
    const fd = try std.posix.openat(parent.handle, name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    const file: File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    defer file.close(io);
    switch ((try file.stat(io)).kind) {
        .file => try rules.add(fd, sandbox.read_file),
        .directory => try rules.add(fd, sandbox.read_file | sandbox.read_dir),
        else => return error.TransferFileType,
    }
}
