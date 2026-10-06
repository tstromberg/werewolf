//! sshd-start: the sshd service. In forms that install OpenSSH (sshd, lima,
//! prod-ssh) it makes this boot's host key and becomes sshd; elsewhere it
//! parks itself, so a form adds ssh with a package and no files. The host
//! key lives in /run, since the root is read-only: it never outlives the
//! machine.
//!
//! runsv runs it as /etc/sv/sshd/run, with no arguments and no shell.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;

const key = "/run/sshd/ssh_host_ed25519_key";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    if (linux.errno(linux.access("/usr/bin/sshd", linux.X_OK)) != .SUCCESS) {
        // Down, as a service with nothing to do: runsv will not restart it.
        const err = std.process.replace(io, .{ .argv = &.{ "/usr/bin/sv", "down", "." } });
        say(io, "sv down: {s}", .{@errorName(err)});
        std.process.exit(1);
    }

    // Speculative Store Bypass mitigated for ssh-keygen, sshd and every
    // session, which werewolf leaves to each program, so workloads do not
    // pay (docs/security.md). Where the CPU has no control, the kernel
    // refuses and nothing changes.
    _ = linux.prctl(@backingInt(linux.PR.SET_SPECULATION_CTRL), linux.PR.SPEC_STORE_BYPASS, linux.PR.SPEC_FORCE_DISABLE, 0, 0);
    _ = linux.mkdir("/run/sshd", 0o700);
    if (linux.errno(linux.access(key, linux.F_OK)) != .SUCCESS) {
        var child = try std.process.spawn(io, .{ .argv = &.{ "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key }, .stdin = .ignore });
        const term = try child.wait(io);
        if (term != .exited or term.exited != 0) {
            say(io, "ssh-keygen failed; trying again", .{});
            std.process.exit(1);
        }
    }
    const err = std.process.replace(io, .{ .argv = &.{ "/usr/bin/sshd", "-D", "-e" } });
    say(io, "sshd: {s}", .{@errorName(err)});
    std.process.exit(1);
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "sshd-start: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
