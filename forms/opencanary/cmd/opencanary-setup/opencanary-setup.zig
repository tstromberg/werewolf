//! opencanary-setup writes OpenCanary's config before each start, so the
//! image's defaults (and any edit under /data) do not decide what listens.
//! FTP, SSH, HTTP, Telnet, RDP and VNC are on. Everything else is off, and
//! events go to the console and to a file on /data.
//!
//!     opencanary-setup
//!
//! leash runs it as _oci-opencanary (forms/opencanary/form.yaml). See
//! forms/opencanary/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;

const data_dir = "/data";
const config_name = ".opencanary.conf";

/// config is what this form runs. The telnet honeycreds are bait: they
/// open nothing on the machine.
const config =
    \\{
    \\    "device.node_id": "opencanary",
    \\    "ip.ignorelist": [],
    \\    "logtype.ignorelist": [],
    \\    "git.enabled": false,
    \\    "ftp.enabled": true,
    \\    "ftp.port": 21,
    \\    "ftp.banner": "FTP server ready",
    \\    "http.enabled": true,
    \\    "http.port": 80,
    \\    "http.banner": "Apache/2.2.22 (Ubuntu)",
    \\    "http.skin": "nasLogin",
    \\    "https.enabled": false,
    \\    "httpproxy.enabled": false,
    \\    "llmnr.enabled": false,
    \\    "portscan.enabled": false,
    \\    "smb.enabled": false,
    \\    "mysql.enabled": false,
    \\    "ssh.enabled": true,
    \\    "ssh.port": 22,
    \\    "ssh.key_path": "/data",
    \\    "ssh.version": "SSH-2.0-OpenSSH_5.1p1 Debian-4",
    \\    "redis.enabled": false,
    \\    "rdp.enabled": true,
    \\    "rdp.port": 3389,
    \\    "sip.enabled": false,
    \\    "snmp.enabled": false,
    \\    "ntp.enabled": false,
    \\    "tftp.enabled": false,
    \\    "tcpbanner.enabled": false,
    \\    "telnet.enabled": true,
    \\    "telnet.port": 23,
    \\    "telnet.banner": "",
    \\    "mssql.enabled": false,
    \\    "vnc.enabled": true,
    \\    "vnc.port": 5900,
    \\    "logger": {
    \\        "class": "PyLogger",
    \\        "kwargs": {
    \\            "formatters": {"plain": {"format": "%(message)s"}},
    \\            "handlers": {
    \\                "console": {"class": "logging.StreamHandler", "stream": "ext://sys.stdout"},
    \\                "file": {"class": "logging.FileHandler", "filename": "/data/opencanary.log"}
    \\            }
    \\        }
    \\    }
    \\}
;

pub fn main(init: std.process.Init) void {
    const io = init.io;
    run(io) catch |err| {
        say(io, "{{\"event\":\"failed\",\"why\":\"{s}\"}}", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run(io: Io) !void {
    var dir = try Dir.cwd().openDir(io, data_dir, .{ .follow_symlinks = false });
    defer dir.close(io);
    try writeAtomic(io, dir, config_name, config);
    say(io, "{{\"event\":\"config written\"}}", .{});
}

fn writeAtomic(io: Io, dir: Dir, name: []const u8, data: []const u8) !void {
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, "{s}.tmp", .{name});
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(io, tmp, .{
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        defer f.close(io);
        try f.writeStreamingAll(io, data);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, name, io);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const line = std.mem.print(&buf, "opencanary-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test "the bait is on and the host services are off" {
    try testing.expect(std.mem.indexOf(u8, config, "\"ftp.enabled\": true") != null);
    try testing.expect(std.mem.indexOf(u8, config, "\"ssh.enabled\": true") != null);
    try testing.expect(std.mem.indexOf(u8, config, "\"smb.enabled\": false") != null);
    try testing.expect(std.mem.indexOf(u8, config, "\"portscan.enabled\": false") != null);
    try testing.expect(std.mem.indexOf(u8, config, "\"https.enabled\": false") != null);
    try testing.expect(std.mem.indexOf(u8, config, "\"vnc.port\": 5900") != null);
}

test "writeAtomic replaces a pre-existing symlink without touching its target" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "id_rsa", .data = "host-key-material" });
    try tmp.dir.symLink(io, "id_rsa", config_name, .{});
    try writeAtomic(io, tmp.dir, config_name, config);

    const st = try tmp.dir.statFile(io, config_name, .{ .follow_symlinks = false });
    try testing.expectEqual(Io.File.Kind.file, st.kind);
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o7777);

    const kept = try tmp.dir.readFileAlloc(io, "id_rsa", testing.allocator, .limited(64));
    defer testing.allocator.free(kept);
    try testing.expectEqualStrings("host-key-material", kept);
}
