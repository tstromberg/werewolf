//! ssh-host-key: a leashed sshd's host key, made on the machine's first
//! boot and kept, as a distribution's first boot makes /etc/ssh's.
//!
//!     ssh-host-key KEY
//!
//! leash runs it as a service's `before`, as the service's user, inside its
//! Landlock rules. KEY is in the service's /data directory, since the root
//! is read-only: if it is there, it stands; if not, ssh-keygen makes an
//! Ed25519 key, once. Without /data, or with /data in RAM, there is nowhere
//! to keep one, and a key made each boot would change the machine's
//! identity each boot, so the service stays down and says why.
//!
//! lib/hostkey.zig keeps it whole: made beside its place and renamed in,
//! so a boot cut short leaves a whole key or none, and a lost public half
//! made again from the key.
//!
//! Every start logs the key's fingerprint and public half, for an operator
//! to pin (howl console NAME), never the private half.

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
