//! hostkey makes an ssh host key once with ssh-keygen and installs it so a
//! crash never leaves half a key. See lib/README.md.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

pub const keygen = "/usr/bin/ssh-keygen";

pub const Kept = enum { new, kept };

/// keep makes key if it is missing, or rebuilds only its public half if
/// that is missing. It returns .new if it made the key now.
pub fn keep(io: Io, gpa: Allocator, key: []const u8) !Kept {
    const dir = std.fs.path.dirname(key) orelse return error.NoDirectory;
    const pub_path = try gpa.print("{s}.pub", .{key});
    if (!exists(io, key)) {
        try make(io, gpa, key);
        return .new;
    }
    if (!exists(io, pub_path)) {
        const r = try std.process.run(gpa, io, .{ .argv = &.{ keygen, "-y", "-f", key } });
        if (r.term != .exited or r.term.exited != 0) return error.KeyUnreadable;
        const new = try gpa.print("{s}.new", .{pub_path});
        try Dir.cwd().writeFile(io, .{ .sub_path = new, .data = r.stdout });
        try syncFile(io, new);
        try Dir.rename(Dir.cwd(), new, Dir.cwd(), pub_path, io);
        try syncDir(gpa, dir);
    }
    return .kept;
}

/// make runs ssh-keygen for an Ed25519 key as key.new and key.new.pub,
/// syncs both, and renames the public half into place first and the key
/// last, so the key exists only if the pair is whole.
pub fn make(io: Io, gpa: Allocator, key: []const u8) !void {
    const dir = std.fs.path.dirname(key) orelse return error.NoDirectory;
    const new = try gpa.print("{s}.new", .{key});
    const new_pub = try gpa.print("{s}.new.pub", .{key});
    // Remove what an interrupted boot left; ssh-keygen would prompt.
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
    try Dir.rename(Dir.cwd(), new_pub, Dir.cwd(), try gpa.print("{s}.pub", .{key}), io);
    try Dir.rename(Dir.cwd(), new, Dir.cwd(), key, io);
    try syncDir(gpa, dir);
}

const Sha256 = std.crypto.hash.sha2.Sha256;
const b64 = std.base64.standard;
pub const fingerprint_len = "SHA256:".len + b64.Encoder.calcSize(Sha256.digest_length) - 1;

/// fingerprint returns an OpenSSH public key line's fingerprint as
/// ssh-keygen -l prints it: SHA256: and unpadded base64. It returns null if
/// the line is not TYPE BASE64 [COMMENT].
pub fn fingerprint(line: []const u8, out: *[fingerprint_len]u8) ?[]const u8 {
    var words = std.mem.tokenizeAny(u8, line, " \n");
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
    @memcpy(out["SHA256:".len..], full[0 .. full.len - 1]); // drop the one '='
    return out;
}

/// onRam reports whether path is on tmpfs, so nothing kept there outlives
/// the boot. /data is tmpfs on a machine with no disk for it.
pub fn onRam(path: [*:0]const u8) bool {
    // struct statfs; its first word is the filesystem type.
    var buf: [128]u8 align(8) = undefined;
    const rc = linux.syscall2(.statfs, @intFromPtr(path), @intFromPtr(&buf));
    if (linux.errno(rc) != .SUCCESS) return false;
    return std.mem.readInt(u64, buf[0..8], .little) == 0x01021994; // TMPFS_MAGIC
}

fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

fn syncFile(io: Io, path: []const u8) !void {
    const f = try Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    try f.sync(io);
}

/// syncDir flushes dir's entries to disk. It opens its own descriptor
/// because a Dir may be O_PATH, which cannot be synced.
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

test fingerprint {
    // A key from ssh-keygen, and the fingerprint ssh-keygen -l gave it.
    var fp: [fingerprint_len]u8 = undefined;
    try std.testing.expectEqualStrings(
        "SHA256:xt7MKcl8CR6CVB+wYaRvOu2p3Xo8cPAYEwXx4ZNcIB8",
        fingerprint(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOh1Xu4CePIw8O7EMEiP1iadyGZHfEfytEt/PFOAjHq " ++
                "werewolf\n",
            &fp,
        ).?,
    );
    try std.testing.expectEqual(null, fingerprint("garbage", &fp));
    try std.testing.expectEqual(null, fingerprint("ssh-ed25519 not*base64", &fp));
}
