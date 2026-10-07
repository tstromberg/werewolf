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
//! The key is made as KEY.new, synced, and renamed into place public half
//! first, so a boot cut short leaves either a whole key or none: never a
//! private half alone, nor a cut-off one, that every later boot would keep.
//! A key whose public half is missing has it made again from the key.
//!
//! Every start logs the key's fingerprint, SHA-256 of the public key as
//! ssh-keygen -l gives it, and its public half, for an operator to pin
//! (werewolf console NAME), never the private half.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const keygen = "/usr/bin/ssh-keygen";

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
    const pub_path = try gpa.print("{s}.pub", .{key});
    var made = false;
    if (exists(io, key)) {
        // A key kept without its public half: made again from the key.
        if (!exists(io, pub_path)) {
            const r = try std.process.run(gpa, io, .{ .argv = &.{ keygen, "-y", "-f", key } });
            if (r.term != .exited or r.term.exited != 0) return error.KeyUnreadable;
            try replace(io, gpa, dir, pub_path, r.stdout);
        }
    } else {
        Dir.cwd().access(io, dir, .{}) catch return error.NoDataToKeepItIn;
        if (onRam(try gpa.dupeSentinel(u8, dir, 0))) return error.DataIsRam;
        try make(io, gpa, dir, key, pub_path);
        made = true;
    }
    const public = std.mem.trim(
        u8,
        Dir.cwd().readFileAlloc(io, pub_path, gpa, .limited(16 << 10)) catch
            return error.NoPublicKey,
        " \n",
    );
    var fp: [fingerprint_len]u8 = undefined;
    log(io, .{
        .event = "host-key",
        .key = key,
        .from = if (made) "new, kept in /data" else "kept in /data",
        .fingerprint = fingerprintOf(public, &fp) orelse return error.NotAPublicKey,
        .public = public,
    });
}

/// key made by ssh-keygen as key.new and key.new.pub, each synced, then the
/// public half renamed into place and the key last: the key's presence
/// says the pair is whole.
fn make(io: Io, gpa: Allocator, dir: []const u8, key: []const u8, pub_path: []const u8) !void {
    const new = try gpa.print("{s}.new", .{key});
    const new_pub = try gpa.print("{s}.new.pub", .{key});
    // What a boot cut short left: ssh-keygen would ask before overwriting.
    for ([_][]const u8{ new, new_pub }) |p| Dir.cwd().deleteFile(io, p) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    const r = try std.process.run(gpa, io, .{
        .argv = &.{ keygen, "-q", "-t", "ed25519", "-N", "", "-C", "werewolf", "-f", new },
    });
    if (r.term != .exited or r.term.exited != 0) return error.KeygenFailed;
    try syncFile(io, new);
    try syncFile(io, new_pub);
    try Dir.rename(Dir.cwd(), new_pub, Dir.cwd(), pub_path, io);
    try Dir.rename(Dir.cwd(), new, Dir.cwd(), key, io);
    try syncDir(gpa, dir);
}

/// path's contents replaced by text, whole: written beside it, synced, and
/// renamed over it.
fn replace(io: Io, gpa: Allocator, dir: []const u8, path: []const u8, text: []const u8) !void {
    const new = try gpa.print("{s}.new", .{path});
    try Dir.cwd().writeFile(io, .{ .sub_path = new, .data = text });
    try syncFile(io, new);
    try Dir.rename(Dir.cwd(), new, Dir.cwd(), path, io);
    try syncDir(gpa, dir);
}

fn syncFile(io: Io, path: []const u8) !void {
    const f = try Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    try f.sync(io);
}

/// dir's entries on the disk: its own descriptor, as Dir's may be O_PATH,
/// which cannot be synced.
fn syncDir(gpa: Allocator, dir: []const u8) !void {
    const rc = linux.open(
        try gpa.dupeSentinel(u8, dir, 0),
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    if (linux.errno(rc) != .SUCCESS) return error.SyncFailed;
    defer _ = linux.close(@intCast(rc));
    if (linux.errno(linux.fsync(@intCast(rc))) != .SUCCESS) return error.SyncFailed;
}

const Sha256 = std.crypto.hash.sha2.Sha256;
const b64 = std.base64.standard;
const fingerprint_len = "SHA256:".len + b64.Encoder.calcSize(Sha256.digest_length) - 1;

/// An OpenSSH public key line's fingerprint, as ssh-keygen -l says it:
/// SHA256: and the SHA-256 of the key's decoded blob, in base64 without
/// its padding. Null if the line is not TYPE BASE64 [COMMENT].
fn fingerprintOf(line: []const u8, out: *[fingerprint_len]u8) ?[]const u8 {
    var words = std.mem.tokenizeScalar(u8, line, ' ');
    _ = words.next() orelse return null;
    const encoded = words.next() orelse return null;
    var blob: [1024]u8 = undefined;
    const n = b64.Decoder.calcSizeForSlice(encoded) catch return null;
    if (n > blob.len) return null;
    b64.Decoder.decode(blob[0..n], encoded) catch return null;
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(blob[0..n], &digest, .{});
    var full: [b64.Encoder.calcSize(Sha256.digest_length)]u8 = undefined;
    _ = b64.Encoder.encode(&full, &digest);
    @memcpy(out[0.."SHA256:".len], "SHA256:");
    @memcpy(out["SHA256:".len..], full[0 .. full.len - 1]); // its one '='
    return out;
}

/// Whether path is on RAM (tmpfs), so nothing kept there outlives the boot:
/// /data, where a machine has no disk for it.
fn onRam(path: [*:0]const u8) bool {
    // struct statfs, whose first word is the filesystem's type.
    var buf: [128]u8 align(8) = undefined;
    const rc = linux.syscall2(.statfs, @intFromPtr(path), @intFromPtr(&buf));
    if (linux.errno(rc) != .SUCCESS) return false;
    return std.mem.readInt(u64, buf[0..8], .little) == 0x01021994; // TMPFS_MAGIC
}

fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn log(io: Io, fields: anytype) void {
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    w.writeAll("ssh-host-key: ") catch return;
    std.json.Stringify.value(fields, .{ .emit_null_optional_fields = false }, &w) catch return;
    w.writeByte('\n') catch return;
    Io.File.stdout().writeStreamingAll(io, w.buffered()) catch {};
}

test fingerprintOf {
    // A key ssh-keygen made, and the fingerprint ssh-keygen -l gave it.
    var fp: [fingerprint_len]u8 = undefined;
    try std.testing.expectEqualStrings(
        "SHA256:xt7MKcl8CR6CVB+wYaRvOu2p3Xo8cPAYEwXx4ZNcIB8",
        fingerprintOf(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOh1Xu4CePIw8O7EMEiP1iadyGZHfEfytEt/PFOAjHq " ++
                "werewolf",
            &fp,
        ).?,
    );
    try std.testing.expectEqual(null, fingerprintOf("garbage", &fp));
    try std.testing.expectEqual(null, fingerprintOf("ssh-ed25519 not*base64", &fp));
}
