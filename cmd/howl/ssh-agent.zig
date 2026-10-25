//! A per-connection agent for selected identities. OpenSSH owns
//! its lifetime; no shell script, persistent socket or agent state is kept.
const std = @import("std");
const howl = @import("howl.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn start(
    io: Io,
    gpa: Allocator,
    known_hosts: []const u8,
    alias: []const u8,
    user: []const u8,
    identities: []const []const u8,
    ssh: []const []const u8,
    command_len: usize,
    why: *howl.Why,
) !void {
    if (!try hasPin(io, gpa, known_hosts, alias)) {
        _ = try std.process.run(gpa, io, .{ .argv = try pinArgv(gpa, ssh, command_len) });
        if (!try hasPin(io, gpa, known_hosts, alias)) return why.refuse(
            "{s}: could not establish a host key pin; check that the machine is reachable",
            .{alias},
        );
    }
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{
        "ssh-agent", try std.process.executablePathAlloc(io, gpa), "_ssh-agent",
        known_hosts, alias,                                        user,
    });
    try argv.appendSlice(gpa, identities);
    try argv.append(gpa, "--");
    try argv.appendSlice(gpa, ssh);
    const err = std.process.replace(io, .{ .argv = argv.items });
    return why.refuse("ssh-agent: {s}", .{@errorName(err)});
}

/// pinArgv is the handshake that pins a first host key. Destination
/// constrained keys need the server's host key before ssh-add can load
/// them, so ssh connects with the ordinary accept-new policy, offering no
/// authentication and running no command.
fn pinArgv(gpa: Allocator, ssh: []const []const u8, command_len: usize) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "GSSAPIAuthentication=no",
    });
    for (ssh[1 .. ssh.len - command_len]) |arg| try argv.append(
        gpa,
        if (std.mem.eql(u8, arg, "StrictHostKeyChecking=yes"))
            "StrictHostKeyChecking=accept-new"
        else
            arg,
    );
    return argv.items;
}

fn hasPin(io: Io, gpa: Allocator, known_hosts: []const u8, alias: []const u8) !bool {
    const pin = try std.process.run(gpa, io, .{
        .argv = &.{ "ssh-keygen", "-F", alias, "-f", known_hosts },
    });
    return pin.term == .exited and pin.term.exited == 0;
}

/// Line is _ssh-agent's: KNOWN_HOSTS ALIAS USER IDENTITY... -- SSH...
const Line = struct {
    known_hosts: []const u8,
    alias: []const u8,
    user: []const u8,
    identities: []const []const u8,
    ssh: []const []const u8,
};

fn parse(args: []const []const u8, why: *howl.Why) !Line {
    if (args.len < 6) return why.refuse("invalid internal SSH agent arguments", .{});
    const split = for (args[3..], 3..) |arg, n| {
        if (std.mem.eql(u8, arg, "--")) break n;
    } else return why.refuse("missing internal SSH command", .{});
    if (split == 3 or split + 1 == args.len)
        return why.refuse("missing SSH identity or command", .{});
    for (args[3..split]) |path| if (!std.fs.path.isAbsolute(path))
        return why.refuse("SSH identity must be an absolute path", .{});
    return .{
        .known_hosts = args[0],
        .alias = args[1],
        .user = args[2],
        .identities = args[3..split],
        .ssh = args[split + 1 ..],
    };
}

/// addArgv loads the identities for 20 hours, each usable only to log in
/// to the pinned alias as user, or through it as root.
fn addArgv(gpa: Allocator, l: Line) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{
        "ssh-add",
        "-t",
        "20h",
        "-H",
        l.known_hosts,
        "-h",
        try gpa.print("{s}@{s}", .{ l.user, l.alias }),
        "-h",
        try gpa.print("{s}>root@{s}", .{ l.alias, l.alias }),
    });
    try argv.appendSlice(gpa, l.identities);
    return argv.items;
}

/// Run by ssh-agent, whose fresh socket is inherited through SSH_AUTH_SOCK.
/// Replacing this process with ssh lets the agent observe the connection's end.
pub fn command(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    const line = try parse(args, why);
    const socket = howl.environ.get("SSH_AUTH_SOCK") orelse
        return why.refuse("ssh-agent did not provide a socket", .{});
    if (!std.fs.path.isAbsolute(socket)) return why.refuse("invalid SSH agent socket", .{});
    var child = try std.process.spawn(io, .{ .argv = try addArgv(gpa, line) });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0)
        return why.refuse("ssh-add failed; no SSH connection opened", .{});
    const err = std.process.replace(io, .{ .argv = line.ssh });
    return why.refuse("ssh: {s}", .{@errorName(err)});
}

const testing = std.testing;

test "the first connection pins the host key without authenticating or running a command" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const ssh: []const []const u8 = &.{
        "ssh", "-o",                        "StrictHostKeyChecking=yes",
        "-o",  "HostKeyAlias=werewolf-run", "alice@127.0.0.1",
        "id",
    };
    try testing.expectEqualStrings(
        "ssh -o BatchMode=yes -o IdentityAgent=none -o PubkeyAuthentication=no " ++
            "-o PasswordAuthentication=no -o KbdInteractiveAuthentication=no " ++
            "-o GSSAPIAuthentication=no -o StrictHostKeyChecking=accept-new " ++
            "-o HostKeyAlias=werewolf-run alice@127.0.0.1",
        try std.mem.join(gpa, " ", try pinArgv(gpa, ssh, 1)),
    );
}

test "the agent loads absolute identities, bound to the pinned machine" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: howl.Why = .{};
    const line = try parse(&.{
        "build/machines/werewolf-run/known_hosts", "werewolf-run",
        "alice",                                   "/keys/admin key",
        "/keys/second;key",                        "--",
        "ssh",                                     "alice@127.0.0.1",
    }, &why);
    try testing.expectEqualStrings("ssh alice@127.0.0.1", try std.mem.join(gpa, " ", line.ssh));
    try testing.expectEqualStrings(
        "ssh-add -t 20h -H build/machines/werewolf-run/known_hosts -h alice@werewolf-run " ++
            "-h werewolf-run>root@werewolf-run /keys/admin key /keys/second;key",
        try std.mem.join(gpa, " ", try addArgv(gpa, line)),
    );
    for ([_][]const []const u8{
        &.{ "kh", "alias", "alice", "/key", "--" },
        &.{ "kh", "alias", "alice", "/key", "ssh", "x" },
        &.{ "kh", "alias", "alice", "--", "ssh", "x" },
        &.{ "kh", "alias", "alice", "/key", "/other", "--" },
        &.{ "kh", "alias", "alice", "relative", "--", "ssh" },
    }) |args| try testing.expectError(error.Refused, parse(args, &why));
}
