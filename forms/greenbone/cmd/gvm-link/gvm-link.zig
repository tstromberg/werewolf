//! gvm-link carries gvmd's socket to gsad. The two images do not share a
//! directory. Leash runs it as _glink in the groups _oci-gvmd and _oci-gsad;
//! gsad's /run is setgid _oci-gsad (share: group), so the socket inherits
//! _oci-gsad and mode 0660 lets gsad alone connect. See its README.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const config_path = "/etc/werewolf/gvm-link";

const Config = struct { listen: []const u8, dial: []const u8 };

const SockaddrUn = extern struct {
    family: u16,
    path: [108]u8,
};

pub fn main(init: std.process.Init) void {
    _ = linux.close_range(3, std.math.maxInt(linux.fd_t), .{ .UNSHARE = false, .CLOEXEC = false });
    const io = init.io;
    run(io, init.arena.allocator()) catch |err| {
        say(io, "{{\"event\":\"down\",\"why\":\"{s}\"}}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator) !void {
    const cfg = try parse(try readFile(io, gpa, config_path, 512));
    const listen_fd = try bindListen(cfg.listen);
    say(
        io,
        "{{\"event\":\"start\",\"listen\":\"{s}\",\"dial\":\"{s}\"}}",
        .{ cfg.listen, cfg.dial },
    );
    while (true) {
        const got = linux.accept4(listen_fd, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(got) == .INTR) continue;
        if (linux.errno(got) != .SUCCESS) linux.exit_group(1);
        const client: i32 = @intCast(got);
        const dial = cfg.dial;
        const thread = std.Thread.spawn(.{}, shuttle, .{ client, dial }) catch {
            _ = linux.close(client);
            continue;
        };
        thread.detach();
    }
}

fn shuttle(client: i32, dial: []const u8) void {
    const up = connectTo(dial) catch {
        _ = linux.close(client);
        return;
    };
    var buf: [8192]u8 = undefined;
    var fds = [2]linux.pollfd{
        .{ .fd = client, .events = linux.POLL.IN, .revents = 0 },
        .{ .fd = up, .events = linux.POLL.IN, .revents = 0 },
    };
    while (true) {
        fds[0].revents = 0;
        fds[1].revents = 0;
        const n = linux.poll(&fds, 2, -1);
        if (linux.errno(n) == .INTR) continue;
        if (linux.errno(n) != .SUCCESS) break;
        if (fds[0].revents & (linux.POLL.IN | linux.POLL.HUP | linux.POLL.ERR) != 0) {
            if (!copySome(client, up, &buf)) break;
        }
        if (fds[1].revents & (linux.POLL.IN | linux.POLL.HUP | linux.POLL.ERR) != 0) {
            if (!copySome(up, client, &buf)) break;
        }
    }
    _ = linux.close(client);
    _ = linux.close(up);
}

fn copySome(from: i32, to: i32, buf: []u8) bool {
    const n = linux.read(from, buf.ptr, buf.len);
    if (linux.errno(n) == .INTR) return true;
    if (linux.errno(n) != .SUCCESS or n == 0) return false;
    var off: usize = 0;
    while (off < n) {
        const w = linux.write(to, buf[off..n].ptr, n - off);
        if (linux.errno(w) == .INTR) continue;
        if (linux.errno(w) != .SUCCESS or w == 0) return false;
        off += w;
    }
    return true;
}

fn bindListen(path: []const u8) !i32 {
    if (std.fs.path.dirname(path)) |dir| {
        var i: u8 = 0;
        while (i < 60) : (i += 1) {
            var dz: [129]u8 = undefined;
            const rc = linux.access(try z(dir, &dz), linux.W_OK | linux.X_OK);
            if (linux.errno(rc) == .SUCCESS) break;
            _ = linux.nanosleep(&.{ .sec = 1, .nsec = 0 }, null);
        }
    }
    var pz: [129]u8 = undefined;
    const pathz = try z(path, &pz);
    _ = linux.unlink(pathz);
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(rc);
    var addr: SockaddrUn = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    if (path.len + 1 > addr.path.len) return error.BadConfig;
    @memcpy(addr.path[0..path.len], path);
    const len: linux.socklen_t = @intCast(2 + path.len + 1);
    if (linux.errno(linux.bind(fd, @ptrCast(&addr), len)) != .SUCCESS) return error.Bind;
    // gsad's /run is setgid _oci-gsad (share: group); mode 0660 lets gsad connect.
    if (linux.errno(linux.fchmod(fd, 0o660)) != .SUCCESS) return error.Mode;
    if (linux.errno(linux.chmod(pathz, 0o660)) != .SUCCESS) return error.Mode;
    if (linux.errno(linux.listen(fd, 16)) != .SUCCESS) return error.Listen;
    return fd;
}

fn connectTo(path: []const u8) !i32 {
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.Socket;
    const fd: i32 = @intCast(rc);
    var addr: SockaddrUn = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    if (path.len + 1 > addr.path.len) return error.BadConfig;
    @memcpy(addr.path[0..path.len], path);
    const len: linux.socklen_t = @intCast(2 + path.len + 1);
    if (linux.errno(linux.connect(fd, @ptrCast(&addr), len)) != .SUCCESS) {
        _ = linux.close(fd);
        return error.Connect;
    }
    return fd;
}

fn parse(text: []const u8) !Config {
    var listen_at: ?[]const u8 = null;
    var dial: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const sp = std.mem.findScalar(u8, line, ' ') orelse return error.BadConfig;
        const key = line[0..sp];
        const value = std.mem.trim(u8, line[sp + 1 ..], " \t");
        if (value.len == 0 or value[0] != '/' or value.len > 108) return error.BadConfig;
        if (std.mem.eql(u8, key, "listen")) {
            if (listen_at != null) return error.BadConfig;
            listen_at = value;
        } else if (std.mem.eql(u8, key, "dial")) {
            if (dial != null) return error.BadConfig;
            dial = value;
        } else return error.BadConfig;
    }
    return .{
        .listen = listen_at orelse return error.BadConfig,
        .dial = dial orelse return error.BadConfig,
    };
}

fn readFile(io: Io, gpa: Allocator, path: []const u8, limit: usize) ![]const u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(limit));
}

fn z(s: []const u8, buf: []u8) ![*:0]u8 {
    if (s.len + 1 > buf.len) return error.BadConfig;
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return buf[0..s.len :0];
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "gvm-link: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

test "parse reads the two sockets" {
    const cfg = try parse(
        \\# both on the host
        \\listen /run/svc/gsad/run/manager.sock
        \\dial /run/svc/gvmd/run/gvmd.sock
    );
    try std.testing.expectEqualStrings("/run/svc/gsad/run/manager.sock", cfg.listen);
    try std.testing.expectEqualStrings("/run/svc/gvmd/run/gvmd.sock", cfg.dial);
}

test "parse refuses a relative path and a second listen" {
    try std.testing.expectError(error.BadConfig, parse("listen relative\n"));
    try std.testing.expectError(error.BadConfig, parse("listen /a\nlisten /b\ndial /c\n"));
}
