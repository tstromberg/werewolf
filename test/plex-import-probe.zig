//! Test-image-only probes, invoked by the operator's root SSH session.
const std = @import("std");
const linux = std.os.linux;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 3) return error.Usage;
    if (std.mem.eql(u8, args[1], "map")) {
        const file = try std.Io.Dir.cwd().openFile(io, args[2], .{});
        defer file.close(io);
        const mapped = linux.mmap(
            null,
            4096,
            .{ .READ = true, .EXEC = true },
            .{ .TYPE = .PRIVATE },
            file.handle,
            0,
        );
        if (linux.errno(mapped) == .SUCCESS) {
            _ = linux.munmap(@ptrFromInt(mapped), 4096);
            return error.ImportedCodeWasExecutable;
        }
        if (linux.errno(mapped) != .ACCES) return error.UnexpectedMappingFailure;
        return;
    }
    if (!std.mem.eql(u8, args[1], "decode")) return error.Usage;
    const passwd = try std.Io.Dir.cwd().readFileAlloc(io, "/etc/passwd", a, .limited(1 << 20));
    const uid = try account(passwd, "plex");
    const group = try std.Io.Dir.cwd().readFileAlloc(io, "/etc/group", a, .limited(1 << 20));
    const gid = try account(group, "plex-transcode");
    const groups = [_]u32{gid};
    if (linux.errno(linux.setgroups(groups.len, &groups)) != .SUCCESS or
        linux.errno(linux.setresgid(gid, gid, gid)) != .SUCCESS or
        linux.errno(linux.setresuid(uid, uid, uid)) != .SUCCESS) return error.DropIdentity;
    const program = "/usr/lib/werewolf/plex-transcode";
    const argv = [_:null]?[*:0]const u8{
        program, "client", "-v",       "error", "-i",       args[2], "-frames:v",
        "1",     "-c:v",   "rawvideo", "-f",    "framemd5", "-",
    };
    const env = [_:null]?[*:0]const u8{};
    _ = linux.execve(program, &argv, &env);
    return error.Exec;
}

fn account(text: []const u8, name: []const u8) !u32 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, fields.next() orelse "", name)) continue;
        _ = fields.next();
        return std.fmt.parseInt(u32, fields.next() orelse return error.Account, 10);
    }
    return error.Account;
}
