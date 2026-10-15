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

const path = "/data/.opencanary.conf";

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
    var f = try Dir.cwd().createFile(io, path, .{ .permissions = .fromMode(0o600) });
    defer f.close(io);
    try f.writeStreamingAll(io, config);
    try f.sync(io);
    say(io, "{{\"event\":\"config written\"}}", .{});
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
