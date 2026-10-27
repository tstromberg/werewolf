//! su opens a root login through the existing SSH server. It has no
//! privileges and accepts no SSH options or commands. See su.1.

const std = @import("std");
const linux = std.os.linux;
const people = @import("people");

pub fn main(init: std.process.Init) !void {
    if (linux.getauxval(std.elf.AT.SECURE) != 0)
        fail("must not run set-user-ID, set-group-ID or with gained capabilities");
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (!validArgs(args[1..])) fail("usage: su [-] [root]");
    if (!sshSession(init.environ_map.get("SSH_CONNECTION"), init.environ_map.get("SSH_TTY")) or
        !(std.Io.File.stdin().isTty(init.io) catch false) or
        !(std.Io.File.stdout().isTty(init.io) catch false))
        fail("unauthenticated session");
    const passwd = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        "/etc/passwd",
        gpa,
        .limited(1 << 20),
    );
    const group = try std.Io.Dir.cwd().readFileAlloc(init.io, "/etc/group", gpa, .limited(1 << 20));
    if (!people.administrator(
        passwd,
        group,
        linux.getuid(),
    )) fail("administrator membership required");
    const agent_needed = "agent forwarding required; reconnect with ssh -A";
    const socket = init.environ_map.get("SSH_AUTH_SOCK") orelse fail(agent_needed);
    if (!std.fs.path.isAbsolute(socket)) fail(agent_needed);

    // Nothing else from the caller reaches the SSH client or its child.
    var env = std.process.Environ.Map.init(gpa);
    try env.put("PATH", "/usr/bin");
    try env.put("SSH_AUTH_SOCK", socket);
    if (init.environ_map.get("TERM")) |term| try env.put("TERM", term);
    const err = std.process.replace(init.io, .{
        .argv = &.{
            "/usr/bin/ssh", "-F", "/etc/ssh/su_config", "-S",             "none",
            "-a",           "-x", "-t",                 "root@127.0.0.1",
        },
        .environ_map = &env,
        .cwd = .{ .path = "/" },
    });
    std.debug.print("su: ssh: {s}\n", .{@errorName(err)});
    std.process.exit(1);
}

// These variables are only a diagnostic hint. They are not credentials;
// the server authenticates the new connection independently.
fn sshSession(connection: ?[]const u8, terminal: ?[]const u8) bool {
    const tty = terminal orelse return false;
    const prefix = "/dev/pts/";
    if (!std.mem.startsWith(u8, tty, prefix) or tty.len == prefix.len) return false;
    for (tty[prefix.len..]) |c| if (!std.ascii.isDigit(c)) return false;
    const text = connection orelse return false;
    if (text.len > 256) return false;
    var words = std.mem.tokenizeScalar(u8, text, ' ');
    for (0..2) |_| {
        const address = words.next() orelse return false;
        const port = std.fmt.parseInt(u16, words.next() orelse return false, 10) catch return false;
        if (port == 0) return false;
        _ = std.Io.net.IpAddress.parse(address, port) catch return false;
    }
    return words.next() == null;
}

fn validArgs(args: []const []const u8) bool {
    const rest = if (args.len > 0 and std.mem.eql(u8, args[0], "-")) args[1..] else args;
    return rest.len == 0 or (rest.len == 1 and std.mem.eql(u8, rest[0], "root"));
}

fn fail(message: []const u8) noreturn {
    std.debug.print("su: {s}\n", .{message});
    std.process.exit(1);
}

test "only a root login, never client options or a remote command" {
    const t = std.testing;
    for ([_][]const []const u8{ &.{}, &.{"-"}, &.{"root"}, &.{ "-", "root" } }) |args|
        try t.expect(validArgs(args));
    for ([_][]const []const u8{
        &.{
            "alice",
        },
        &.{"-l"},
        &.{"--"},
        &.{"-oProxyCommand=evil"},
        &.{ "root", "id" },
        &.{ "-", "-", "root" },
        &.{ "-", "root", "-c", "id" },
    }) |args| try t.expect(!validArgs(args));
}

test "missing and malformed SSH session hints fail closed" {
    const t = std.testing;
    const connection = "192.0.2.1 54321 192.0.2.2 22";
    try t.expect(sshSession(connection, "/dev/pts/0"));
    try t.expect(sshSession("::1 1234 ::1 22", "/dev/pts/123"));
    for ([_]?[]const u8{
        null,               "",             "192.0.2.1 0 192.0.2.2 22", "host 1234 ::1 22",
        "::1 65536 ::1 22", "::1 1234 ::1", "::1 1234 ::1 22 extra",
    }) |bad|
        try t.expect(!sshSession(bad, "/dev/pts/0"));
    for ([_]?[]const u8{ null, "", "/dev/tty", "/dev/pts/", "/dev/pts/../tty" }) |bad|
        try t.expect(!sshSession(connection, bad));
}
