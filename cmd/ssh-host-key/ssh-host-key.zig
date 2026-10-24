//! ssh-host-key makes a leashed sshd's Ed25519 host key in /data on first boot,
//! keeps it after, and logs its fingerprint on every start. When COPY is
//! given, it copies the key to COPY (or makes it there for this boot alone
//! when /data is unavailable or on RAM). See README.md.
//!
//!     ssh-host-key KEY [COPY [KNOWN_HOSTS]]

const std = @import("std");
const hostkey = @import("hostkey");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = init.minimal.args.toSlice(gpa) catch std.process.exit(1);
    if (args.len < 2 or args.len > 4) {
        log(io, .{ .event = "host-key", .why = "usage: ssh-host-key KEY [COPY [KNOWN_HOSTS]]" });
        std.process.exit(1);
    }
    for (args[1..]) |path| if (!std.fs.path.isAbsolute(path)) {
        log(io, .{ .event = "host-key", .why = "paths must be absolute" });
        std.process.exit(1);
    };
    const copy: ?[]const u8 = if (args.len >= 3) args[2] else null;
    const known_hosts: ?[]const u8 = if (args.len == 4) args[3] else null;
    run(io, gpa, args[1], copy, known_hosts) catch |err| {
        log(io, .{ .event = "host-key", .key = copy orelse args[1], .why = @errorName(err) });
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, key: []const u8, copy: ?[]const u8, known_hosts: ?[]const u8) !void {
    const dir = std.fs.path.dirname(key) orelse return error.NoDataToKeepItIn;
    const nodata = linux.errno(linux.access("/run/werewolf/nodata", linux.F_OK)) == .SUCCESS;
    const has_dir = if (Dir.cwd().access(io, dir, .{})) |_| true else |_| false;
    const on_ram = has_dir and hostkey.onRam(try gpa.dupeSentinel(u8, dir, 0));
    const at = copy orelse key;
    const from: []const u8 = if (copy) |dst_key| blk: {
        const unkept: ?[]const u8 = if (nodata or !has_dir)
            "no /data to keep it in"
        else if (on_ram)
            "/data is RAM"
        else
            null;
        if (unkept) |why| {
            _ = try hostkey.keep(io, gpa, dst_key);
            break :blk try gpa.print("for this boot alone: {s}", .{why});
        }
        const kept = try hostkey.keep(io, gpa, key);
        for ([_][]const u8{ "", ".pub" }) |ext| {
            const src = try gpa.print("{s}{s}", .{ key, ext });
            const dst = try gpa.print("{s}{s}", .{ dst_key, ext });
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
        break :blk if (kept == .new) "new, kept in /data" else "kept in /data";
    } else blk: {
        if (!has_dir) return error.NoDataToKeepItIn;
        if (on_ram) return error.DataIsRam;
        const kept = try hostkey.keep(io, gpa, key);
        break :blk if (kept == .new) "new, kept in /data" else "kept in /data";
    };
    const public = std.mem.trim(
        u8,
        Dir.cwd().readFileAlloc(io, try gpa.print("{s}.pub", .{at}), gpa, .limited(16 << 10)) catch
            return error.NoPublicKey,
        " \n",
    );
    var fp: [hostkey.fingerprint_len]u8 = undefined;
    const fingerprint = hostkey.fingerprint(public, &fp) orelse return error.NotAPublicKey;
    if (known_hosts) |path| try publish(io, gpa, path, try knownHost(gpa, public));
    log(io, .{
        .event = "host-key",
        .key = at,
        .from = from,
        .fingerprint = fingerprint,
        .public = public,
    });
}

fn knownHost(gpa: Allocator, public: []const u8) ![]const u8 {
    if (std.mem.findAny(u8, public, "\r\n\x00") != null) return error.NotAPublicKey;
    var words = std.mem.tokenizeAny(u8, public, " \t");
    const kind = words.next() orelse return error.NotAPublicKey;
    const key = words.next() orelse return error.NotAPublicKey;
    if (!std.mem.eql(u8, kind, "ssh-ed25519")) return error.NotAPublicKey;
    return gpa.print("werewolf-local {s} {s}\n", .{ kind, key });
}

/// Only the public half is readable by callers. Rename before sshd starts;
/// a failed write must not leave a partial pin for a concurrent client.
fn publish(io: Io, gpa: Allocator, path: []const u8, text: []const u8) !void {
    const tmp = try gpa.print("{s}.new", .{path});
    Dir.cwd().deleteFile(io, tmp) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    var f = try Dir.cwd().createFile(
        io,
        tmp,
        .{ .exclusive = true, .permissions = .fromMode(0o644) },
    );
    defer f.close(io);
    errdefer Dir.cwd().deleteFile(io, tmp) catch {};
    try f.writeStreamingAll(io, text);
    try f.setPermissions(io, .fromMode(0o644));
    try Dir.rename(Dir.cwd(), tmp, Dir.cwd(), path, io);
}

test "localhost pin contains one host and no public-key comment" {
    const gpa = std.testing.allocator;
    const line = try knownHost(gpa, "ssh-ed25519 AAAA comment with spaces");
    defer gpa.free(line);
    try std.testing.expectEqualStrings("werewolf-local ssh-ed25519 AAAA\n", line);
    for ([_][]const u8{ "ssh-ed25519", "ssh-rsa AAAA", "ssh-ed25519 AAAA\nevil AAAA" }) |bad|
        try std.testing.expectError(error.NotAPublicKey, knownHost(gpa, bad));
}

fn log(io: Io, fields: anytype) void {
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    w.writeAll("ssh-host-key: ") catch return;
    std.json.Stringify.value(fields, .{ .emit_null_optional_fields = false }, &w) catch return;
    w.writeByte('\n') catch return;
    Io.File.stdout().writeStreamingAll(io, w.buffered()) catch {};
}
