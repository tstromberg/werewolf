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
        // Destination constrained keys need the server's host key before
        // ssh-add can load them. Use the same accept-new policy as ordinary
        // SSH, but make an authentication-free handshake with no command so
        // first use can establish that pin without a separate --no-agent run.
        var first: std.ArrayList([]const u8) = .empty;
        try first.appendSlice(gpa, &.{
            "ssh",                             "-o",                      "BatchMode=yes",           "-o",                        "IdentityAgent=none",
            "-o",                              "PubkeyAuthentication=no", "-o",                      "PasswordAuthentication=no", "-o",
            "KbdInteractiveAuthentication=no", "-o",                      "GSSAPIAuthentication=no",
        });
        const target_args = ssh[1 .. ssh.len - command_len];
        for (target_args) |arg| try first.append(gpa, if (std.mem.eql(u8, arg, "StrictHostKeyChecking=yes")) "StrictHostKeyChecking=accept-new" else arg);
        _ = try std.process.run(gpa, io, .{ .argv = first.items });
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

fn hasPin(io: Io, gpa: Allocator, known_hosts: []const u8, alias: []const u8) !bool {
    const pin = try std.process.run(gpa, io, .{
        .argv = &.{ "ssh-keygen", "-F", alias, "-f", known_hosts },
    });
    return pin.term == .exited and pin.term.exited == 0;
}

/// Run by ssh-agent, whose fresh socket is inherited through SSH_AUTH_SOCK.
/// Replacing this process with ssh lets the agent observe the connection's end.
pub fn command(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    if (args.len < 6) return why.refuse("invalid internal SSH agent arguments", .{});
    const split = for (args[3..], 3..) |arg, n| {
        if (std.mem.eql(u8, arg, "--")) break n;
    } else return why.refuse("missing internal SSH command", .{});
    if (split == 3 or split + 1 == args.len)
        return why.refuse("missing SSH identity or command", .{});
    for (args[3..split]) |path| if (!std.fs.path.isAbsolute(path))
        return why.refuse("SSH identity must be an absolute path", .{});
    const socket = howl.environ.get("SSH_AUTH_SOCK") orelse
        return why.refuse("ssh-agent did not provide a socket", .{});
    if (!std.fs.path.isAbsolute(socket)) return why.refuse("invalid SSH agent socket", .{});

    var add: std.ArrayList([]const u8) = .empty;
    const login = try gpa.print("{s}@{s}", .{ args[2], args[1] });
    const root = try gpa.print("{s}>root@{s}", .{ args[1], args[1] });
    try add.appendSlice(gpa, &.{
        "ssh-add", "-t", "20h", "-H", args[0], "-h", login, "-h", root,
    });
    try add.appendSlice(gpa, args[3..split]);
    var child = try std.process.spawn(io, .{ .argv = add.items });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0)
        return why.refuse("ssh-add failed; no SSH connection opened", .{});
    const err = std.process.replace(io, .{ .argv = args[split + 1 ..] });
    return why.refuse("ssh: {s}", .{@errorName(err)});
}
