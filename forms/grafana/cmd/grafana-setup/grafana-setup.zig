//! grafana-setup keeps the secret key Grafana encrypts data sources'
//! credentials with, before each start: the config's if it brings one,
//! else one made once from random bytes, in /data either way.
//!
//!     grafana-setup
//!
//! leash runs it as _oci-grafana inside Grafana's image, whose /tmp is the
//! service's run directory and /data its data directory
//! (forms/grafana/form.yaml). See forms/grafana/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// given is leash's copy of the config's key, if it brings one.
const given = "/tmp/secret-key";
/// key is what Grafana reads, by $__file{} in its environment.
const key = "/data/secret-key";
/// min_key is the shortest key taken from the config: 128 bits as hex.
const min_key = 32;

pub fn main(init: std.process.Init) void {
    const io = init.io;
    run(io, init.arena.allocator()) catch |err| {
        say(io, "{s}: {s}", .{ key, @errorName(err) });
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator) !void {
    if (try read(io, gpa, given)) |text| {
        const k = std.mem.trim(u8, text, " \t\r\n");
        if (k.len < min_key) return error.ConfigKeyTooShort;
        const kept = try read(io, gpa, key);
        if (kept != null and std.mem.eql(u8, k, kept.?)) {
            say(io, "secret key from the config", .{});
            return;
        }
        try replace(io, key, k, 0o600);
        // A new key leaves what the old one encrypted unreadable: say so.
        say(io, "secret key from the config, {s}", .{
            if (kept == null) "kept in /data" else "replacing /data's",
        });
        return;
    }
    if (try read(io, gpa, key)) |kept| if (kept.len >= min_key) {
        say(io, "secret key kept in /data", .{});
        return;
    };
    var raw: [32]u8 = undefined;
    io.random(&raw);
    const hex = std.fmt.bytesToHex(raw, .lower);
    try replace(io, key, &hex, 0o600);
    say(io, "secret key new, kept in /data", .{});
}

/// read returns the file at path, or null if there is none.
fn read(io: Io, gpa: Allocator, path: []const u8) !?[]const u8 {
    return Dir.cwd().readFileAlloc(io, path, gpa, .limited(4 << 10)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => err,
    };
}

/// replace writes path whole or not at all: a temporary file, synced, then
/// renamed over it, and the directory synced.
fn replace(io: Io, path: []const u8, data: []const u8, mode: std.posix.mode_t) !void {
    var dir = try Dir.cwd().openDir(io, std.fs.path.dirname(path).?, .{ .iterate = true });
    defer dir.close(io);
    const name = std.fs.path.basename(path);
    var tmp_buf: [256]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, ".{s}.tmp", .{name});
    dir.deleteFile(io, tmp) catch {};
    {
        var f = try dir.createFile(io, tmp, .{ .exclusive = true, .permissions = .fromMode(mode) });
        defer f.close(io);
        try f.writeStreamingAll(io, data);
        try f.sync(io);
    }
    try Dir.rename(dir, tmp, dir, name, io);
    if (std.os.linux.errno(std.os.linux.fsync(dir.handle)) != .SUCCESS) return error.SyncFailed;
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "grafana-setup: " ++ fmt ++ "\n", args) catch return;
    Io.File.stdout().writeStreamingAll(io, line) catch {};
}
