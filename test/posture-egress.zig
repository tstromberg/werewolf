//! Focused real-kernel posture driver; never walks unrelated host files.
const std = @import("std");
const posture = @import("posture");
const sandbox = @import("sandbox");
const service = @import("service");

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--watch-resolvers")) {
        var grants: [service.floor.len]sandbox.Rule = undefined;
        var n: usize = 0;
        // Use the service floor's real directory grant, retaining the domain
        // across DHCP's atomic file replacements. No root-wide /run access.
        for (service.floor) |path| if (std.mem.eql(u8, path, "/run/werewolf/network")) {
            const fd = try sandbox.sys(std.os.linux.openat(
                std.os.linux.AT.FDCWD,
                path,
                .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true },
                0,
            ), "resolver floor");
            grants[n] = .{ .fd = @intCast(fd), .access = sandbox.read_file | sandbox.read_dir };
            n += 1;
        };
        try sandbox.landlock(grants[0..n], &.{});
        for (grants[0..n]) |grant| _ = std.os.linux.close(grant.fd);
        var byte: [1]u8 = undefined;
        while (std.os.linux.read(0, &byte, 1) == 1) {
            const text = try std.Io.Dir.cwd().readFileAlloc(
                init.io,
                "/etc/resolv.conf",
                gpa,
                .limited(1024),
            );
            try writeJson(gpa, text, true);
        }
        return;
    }
    var p: posture.Posture = .{ .io = init.io, .gpa = gpa, .root = std.os.linux.geteuid() == 0 };
    const resolv = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        "/etc/resolv.conf",
        gpa,
        .limited(1024),
    );
    const v6 = std.os.linux.errno(std.os.linux.access(
        "/proc/net/if_inet6",
        std.os.linux.F_OK,
    )) == .SUCCESS;
    // check-dns links resolv.conf to the upstream file itself.
    try posture.network.rootEgress(&p, resolv, "", v6);
    try writeJson(gpa, p.checks.items, false);
}

fn writeJson(gpa: std.mem.Allocator, value: anytype, newline: bool) !void {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try std.json.Stringify.value(value, .{}, &out.writer);
    if (newline) try out.writer.writeByte('\n');
    const data = out.written();
    var off: usize = 0;
    while (off < data.len) {
        const n = std.os.linux.write(1, data[off..].ptr, data.len - off);
        if (std.os.linux.errno(n) != .SUCCESS) return error.Write;
        off += n;
    }
}
