//! sshd-start: the sshd form's service, in every form that takes it
//! (prod-ssh, lima): it makes sure of the host key and becomes sshd.
//!
//! The host key is made on the machine's first boot and kept in /data, at
//! /data/svc/sshd/host-key as a leashed sshd keeps its own (ssh-host-key),
//! root's alone, as a distribution's first boot makes /etc/ssh's; the root
//! is read-only, so sshd reads a copy in /run. Without /data the key is
//! made for this boot alone, and a client sees a new one at the next: an
//! operator who logs in here must still be able to. Every start logs the
//! key's fingerprint and public half, for an operator to pin (howl
//! console NAME), never the private half. lib/hostkey.zig keeps the key
//! whole: a boot cut short leaves a whole key or none.
//!
//! A start that fails waits ten seconds before it ends, and runsv tries
//! again: a passing fault clears, and a lasting one is not a line a second.
//!
//! runsv runs it as /etc/sv/sshd/run, with no arguments and no shell.

const std = @import("std");
const hostkey = @import("hostkey");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

/// Where sshd reads it (the sshd form's sshd_config.d/werewolf.conf).
const key = "/run/sshd/ssh_host_ed25519_key";
/// Where the machine keeps it, while /data is usable: the sshd service's
/// directory, as every service's is /data/svc/NAME.
const kept = "/data/svc/sshd/host-key";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();

    // Speculative Store Bypass mitigated for ssh-keygen, sshd and every
    // session, which werewolf leaves to each program, so workloads do not
    // pay (docs/security.md). Where the CPU has no control, the kernel
    // refuses and nothing changes.
    _ = linux.prctl(
        @backingInt(linux.PR.SET_SPECULATION_CTRL),
        linux.PR.SPEC_STORE_BYPASS,
        linux.PR.SPEC_FORCE_DISABLE,
        0,
        0,
    );
    _ = linux.mkdir("/run/sshd", 0o700);
    const from = hostKey(io, gpa) catch |err| {
        say(io, "host key: {s}; trying again in 10s", .{@errorName(err)});
        io.sleep(.fromSeconds(10), .awake) catch {};
        std.process.exit(1);
    };
    logKey(io, gpa, from);
    const err = std.process.replace(io, .{ .argv = &.{ "/usr/bin/sshd", "-D", "-e" } });
    say(io, "sshd: {s}", .{@errorName(err)});
    std.process.exit(1);
}

/// Make sure of key: the kept one, copied, or a new one, kept if it can be.
fn hostKey(io: Io, gpa: Allocator) ![]const u8 {
    const nodata = linux.errno(linux.access("/run/werewolf/nodata", linux.F_OK)) == .SUCCESS;
    const unkept: ?[]const u8 = if (nodata)
        "no /data to keep it in"
    else if (hostkey.onRam("/data"))
        "/data is RAM"
    else
        null;
    if (unkept) |why| {
        _ = try hostkey.keep(io, gpa, key);
        return gpa.print("for this boot alone: {s}", .{why});
    }
    _ = linux.mkdir("/data/svc", 0o755);
    _ = linux.mkdir("/data/svc/sshd", 0o700);
    const from: []const u8 = switch (try hostkey.keep(io, gpa, kept)) {
        .new => "new, kept in /data",
        .kept => "kept in /data",
    };
    for ([_][]const u8{ "", ".pub" }) |ext| {
        const src = try gpa.print("{s}{s}", .{ kept, ext });
        const dst = try gpa.print("{s}{s}", .{ key, ext });
        const data = try Dir.cwd().readFileAlloc(io, src, gpa, .limited(16 << 10));
        Dir.cwd().deleteFile(io, dst) catch |e| switch (e) {
            error.FileNotFound => {},
            else => return e,
        };
        var f = try Dir.cwd().createFile(
            io,
            dst,
            .{ .exclusive = true, .permissions = .fromMode(0o600) },
        );
        defer f.close(io);
        try f.writeStreamingAll(io, data);
    }
    return from;
}

/// The key's fingerprint and public half, as one line on the console.
fn logKey(io: Io, gpa: Allocator, from: []const u8) void {
    const public = std.mem.trim(
        u8,
        Dir.cwd().readFileAlloc(io, key ++ ".pub", gpa, .limited(16 << 10)) catch return,
        " \n",
    );
    var fp: [hostkey.fingerprint_len]u8 = undefined;
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    w.writeAll("sshd-start: ") catch return;
    std.json.Stringify.value(.{
        .event = "host-key",
        .key = key,
        .from = from,
        .fingerprint = hostkey.fingerprint(public, &fp) orelse "unreadable",
        .public = public,
    }, .{}, &w) catch return;
    w.writeByte('\n') catch return;
    Io.File.stdout().writeStreamingAll(io, w.buffered()) catch {};
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const line = std.mem.print(&buf, "sshd-start: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
