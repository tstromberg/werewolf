//! ssh-host-key makes a leashed sshd's Ed25519 host key in /data on first boot,
//! keeps it after, and logs its fingerprint on every start. When COPY is
//! given, it copies the key to COPY (or makes it there for this boot alone
//! when /data is unavailable or on RAM). See README.md.
//!
//!     ssh-host-key KEY [COPY]

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
    const copy: ?[]const u8 = if (args.len == 3) args[2] else null;
    if ((args.len != 2 and args.len != 3) or !std.fs.path.isAbsolute(args[1]) or
        (copy != null and !std.fs.path.isAbsolute(copy.?)))
    {
        log(io, .{ .event = "host-key", .why = "usage: ssh-host-key KEY [COPY]" });
        std.process.exit(1);
    }
    run(io, gpa, args[1], copy) catch |err| {
        log(io, .{ .event = "host-key", .key = copy orelse args[1], .why = @errorName(err) });
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, key: []const u8, copy: ?[]const u8) !void {
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
    log(io, .{
        .event = "host-key",
        .key = at,
        .from = from,
        .fingerprint = hostkey.fingerprint(public, &fp) orelse return error.NotAPublicKey,
        .public = public,
    });
}

fn log(io: Io, fields: anytype) void {
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    w.writeAll("ssh-host-key: ") catch return;
    std.json.Stringify.value(fields, .{ .emit_null_optional_fields = false }, &w) catch return;
    w.writeByte('\n') catch return;
    Io.File.stdout().writeStreamingAll(io, w.buffered()) catch {};
}
