//! A disk's name in a cloud's image store: werewolf-FORM-ARCH-DIGEST, the
//! first 16 hex digits of the disk's sha256. The same build has the same
//! name everywhere, so a second create, or a second person, finds the
//! image there and uploads nothing.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// werewolf-FORM-ARCH-DIGEST: lower case, at most 63, as GCP wants; AWS
/// takes it as it is.
pub fn name(gpa: Allocator, form: []const u8, arch: []const u8, digest: []const u8) ![]const u8 {
    return gpa.print("werewolf-{s}-{s}-{s}", .{
        form,
        if (std.mem.eql(u8, arch, "aarch64")) "arm64" else "x86-64",
        digest[0..16],
    });
}

/// The hex sha256 of a file.
pub fn sha256(io: Io, path: []const u8) ![64]u8 {
    var f = try Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    var buf: [1 << 16]u8 = undefined;
    while (true) {
        const n = f.readStreaming(io, &.{&buf}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        h.update(buf[0..n]);
    }
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

const testing = std.testing;

test name {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const n = try name(arena.allocator(), "webshell-example", "aarch64", digest);
    try testing.expectEqualStrings("werewolf-webshell-example-arm64-0123456789abcdef", n);
    try testing.expect(n.len <= 63);
    try testing.expectEqualStrings(
        "werewolf-prod-x86-64-0123456789abcdef",
        try name(arena.allocator(), "prod", "x86_64", digest),
    );
}

test sha256 {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "f", .data = "abc" });
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const path = try tmp.dir.realPathFileAlloc(io, "f", arena.allocator());
    try testing.expectEqualStrings(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        &try sha256(io, path),
    );
}
