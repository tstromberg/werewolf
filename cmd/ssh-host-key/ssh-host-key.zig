//! ssh-host-key makes a leashed sshd's Ed25519 host key in /data on first boot,
//! keeps it after, and logs its fingerprint on every start. See README.md.
//!
//!     ssh-host-key KEY

const std = @import("std");
const hostkey = @import("hostkey");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = init.minimal.args.toSlice(gpa) catch std.process.exit(1);
    if (args.len != 2 or !std.fs.path.isAbsolute(args[1])) {
        log(io, .{ .event = "host-key", .why = "usage: ssh-host-key KEY" });
        std.process.exit(1);
    }
    run(io, gpa, args[1]) catch |err| {
        log(io, .{ .event = "host-key", .key = args[1], .why = @errorName(err) });
        std.process.exit(1);
    };
}

fn run(io: Io, gpa: Allocator, key: []const u8) !void {
    const dir = std.fs.path.dirname(key) orelse return error.NoDataToKeepItIn;
    Dir.cwd().access(io, dir, .{}) catch return error.NoDataToKeepItIn;
    if (hostkey.onRam(try gpa.dupeSentinel(u8, dir, 0))) return error.DataIsRam;
    const kept = try hostkey.keep(io, gpa, key);
    const public = std.mem.trim(
        u8,
        Dir.cwd().readFileAlloc(io, try gpa.print("{s}.pub", .{key}), gpa, .limited(16 << 10)) catch
            return error.NoPublicKey,
        " \n",
    );
    var fp: [hostkey.fingerprint_len]u8 = undefined;
    log(io, .{
        .event = "host-key",
        .key = key,
        .from = if (kept == .new) "new, kept in /data" else "kept in /data",
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
