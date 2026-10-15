//! Fixed metadata queries and an authenticated request to confined nginx.
//! Never changes privilege or executes a command.
const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;

pub fn main(init: std.process.Init) void {
    run(init.io, init.arena.allocator(), init.minimal.args) catch |err| {
        var buf: [128]u8 = undefined;
        const line = std.mem.print(&buf, "unifi-host-info: {s}\n", .{@errorName(err)}) catch return;
        Io.File.stderr().writeStreamingAll(init.io, line) catch {};
        std.process.exit(126);
    };
}

fn run(io: Io, gpa: std.mem.Allocator, args: std.process.Args) !void {
    const argv = try args.toSlice(gpa);
    if (reloadCall(argv)) return reload();
    if (osVersionCall(argv)) {
        const release = try Io.Dir.cwd().readFileAlloc(io, "/etc/os-release", gpa, .limited(4096));
        var lines = std.mem.splitScalar(u8, release, '\n');
        while (lines.next()) |line| {
            if (std.mem.cutPrefix(u8, line, "VERSION_CODENAME=")) |value| {
                try Io.File.stdout().writeStreamingAll(io, value);
                try Io.File.stdout().writeStreamingAll(io, "\n");
                return;
            }
        }
        return error.NoOsVersion;
    }
    if (!metadataCall(argv)) return error.UnsupportedHostAction;
    const uuid = try Io.Dir.cwd().readFileAlloc(io, "/data/unifi-core/uuid", gpa, .limited(64));
    if (!uuidOk(uuid)) return error.BadIdentity;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(uuid, &digest, .{});
    digest[0] = (digest[0] | 2) & 0xfe;
    const serial = std.fmt.bytesToHex(digest[0..6].*, .lower);
    var output: [512]u8 = undefined;
    const text = try std.mem.print(
        &output,
        "board.sysid=0xae01\nboard.name=UniFi OS Server\nboard.shortname=UOSSERVER\n" ++
            "board.uuid={s}\nboard.hwrev=0x0000\nboard.serialno={s}\n",
        .{ uuid, &serial },
    );
    try Io.File.stdout().writeStreamingAll(io, text);
}

fn reloadCall(argv: []const []const u8) bool {
    return argv.len == 6 and std.mem.eql(u8, argv[1], "-E") and
        std.mem.eql(u8, argv[2], "-n") and std.mem.eql(u8, argv[3], "nginx") and
        std.mem.eql(u8, argv[4], "-s") and std.mem.eql(u8, argv[5], "reload");
}

fn reload() !void {
    const path = "/werewolf/reload/nginx.sock";
    const raw = linux.socket(linux.AF.UNIX, linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(raw) != .SUCCESS) return error.ReloadSocket;
    const fd: i32 = @intCast(raw);
    defer _ = linux.close(fd);
    var address: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    @memcpy(address.path[0..path.len], path);
    if (linux.errno(linux.connect(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.un))) != .SUCCESS)
        return error.ReloadUnavailable;
    if (linux.sendto(
        fd,
        "reload\n",
        7,
        linux.MSG.NOSIGNAL,
        null,
        0,
    ) != 7) return error.ReloadRequest;
    var poll = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    if (linux.poll(&poll, 1, 5000) != 1 or
        poll[0].revents & linux.POLL.IN == 0) return error.ReloadTimeout;
    var reply: [16]u8 = undefined;
    const n = linux.recvfrom(fd, &reply, reply.len, linux.MSG.TRUNC, null, null);
    if (n != 3 or !std.mem.eql(u8, reply[0..3], "ok\n")) return error.ReloadFailed;
}

fn osVersionCall(argv: []const []const u8) bool {
    return argv.len == 4 and std.mem.eql(u8, argv[1], "-F=") and
        std.mem.eql(u8, argv[2], "$1==\"VERSION_CODENAME\" { print $2 ;}") and
        std.mem.eql(u8, argv[3], "/etc/os-release");
}

fn metadataCall(argv: []const []const u8) bool {
    if (argv.len != 5) return false;
    return std.mem.eql(u8, argv[1], "-E") and std.mem.eql(u8, argv[2], "-n") and
        std.mem.eql(u8, argv[3], "ubnt-tools") and std.mem.eql(u8, argv[4], "id");
}

fn uuidOk(uuid: []const u8) bool {
    if (uuid.len != 36) return false;
    for (uuid, 0..) |c, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (c != '-') return false;
        } else if (!std.ascii.isHex(c)) return false;
    }
    return uuid[14] == '5' and (uuid[19] == '8' or uuid[19] == '9' or
        uuid[19] == 'a' or uuid[19] == 'b');
}

test "only the fixed read-only metadata call is accepted" {
    try std.testing.expect(metadataCall(&.{ "sudo", "-E", "-n", "ubnt-tools", "id" }));
    try std.testing.expect(!metadataCall(&.{ "sudo", "-E", "-n", "systemctl", "restart" }));
    try std.testing.expect(!metadataCall(&.{ "sudo", "-E", "-n", "ubnt-tools", "upgrade" }));
    try std.testing.expect(uuidOk("12345678-1234-5234-8234-123456789abc"));
    try std.testing.expect(!uuidOk("12345678-1234-4234-8234-123456789abc"));
    try std.testing.expect(!uuidOk("12345678-1234-5234-7234-123456789abc"));
    try std.testing.expect(!uuidOk("12345678-1234-4234-8234-123456789ab\n"));
}

test "the OS query cannot run arbitrary awk or read another file" {
    const query = "$1==\"VERSION_CODENAME\" { print $2 ;}";
    try std.testing.expect(osVersionCall(&.{ "awk", "-F=", query, "/etc/os-release" }));
    try std.testing.expect(!osVersionCall(&.{ "awk", "-F=", query, "/etc/shadow" }));
    try std.testing.expect(!osVersionCall(&.{
        "awk",
        "-F=",
        "BEGIN {system(\"id\")}",
        "/etc/os-release",
    }));
}

test "only the fixed nginx reload call can reach the reload socket" {
    try std.testing.expect(reloadCall(&.{ "sudo", "-E", "-n", "nginx", "-s", "reload" }));
    try std.testing.expect(!reloadCall(&.{ "sudo", "-E", "-n", "nginx", "-s", "stop" }));
    try std.testing.expect(!reloadCall(&.{ "sudo", "-E", "-n", "nginx", "-c", "/tmp/config" }));
    try std.testing.expect(!reloadCall(&.{ "sudo", "-E", "-n", "nginx", "-s", "reload", "extra" }));
}
