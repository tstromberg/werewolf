//! verity: a dm-verity hash tree for a root image, as the kernel reads one
//! (Documentation/admin-guide/device-mapper/verity.rst, format version 1,
//! no superblock): 4 KiB blocks, SHA-256 of the salt and each block, the
//! levels laid out top first, right after the data. stage0 opens the image
//! through dm-verity with the parameters this gives, so every block read is
//! checked against the tree, and the tree against its root hash
//! (docs/design/verified-boot.md).
//!
//! The build and the updater both make the tree, and must make the same one
//! for the same image: the salt is derived from the image, not drawn at
//! random, so builds stay byte for byte reproducible.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const block_size = 4096;
const digest_len = Sha256.digest_length;
const per_block_bits = 7; // 4096 / 32 digests a block
const per_block = 1 << per_block_bits;

/// What stage0 needs to open an image: as dm-verity's table takes them.
pub const Params = struct {
    data_blocks: u64,
    /// Where the tree starts, in blocks from the image's start: right after
    /// the data.
    hash_start: u64,
    salt: [digest_len]u8,
    root: [digest_len]u8,

    /// One line, as stage0 reads it from /verity:
    /// `DATA_BLOCKS HASH_START SALT ROOT`, the last two in hex.
    pub fn format(p: Params, w: *std.Io.Writer) !void {
        try w.print("{d} {d} {x} {x}\n", .{ p.data_blocks, p.hash_start, &p.salt, &p.root });
    }

    /// The line format writes, back.
    pub fn parse(line: []const u8) !Params {
        var it = std.mem.tokenizeAny(u8, line, " \n");
        var p: Params = undefined;
        p.data_blocks = std.fmt.parseUnsigned(
            u64,
            it.next() orelse return error.BadVerity,
            10,
        ) catch return error.BadVerity;
        p.hash_start = std.fmt.parseUnsigned(
            u64,
            it.next() orelse return error.BadVerity,
            10,
        ) catch return error.BadVerity;
        _ = std.fmt.hexToBytes(
            &p.salt,
            it.next() orelse return error.BadVerity,
        ) catch return error.BadVerity;
        _ = std.fmt.hexToBytes(
            &p.root,
            it.next() orelse return error.BadVerity,
        ) catch return error.BadVerity;
        if (it.next() != null or p.data_blocks == 0 or
            p.hash_start < p.data_blocks) return error.BadVerity;
        return p;
    }
};

/// The tree for data, whole blocks of it, to go right after it, and the
/// parameters to open the two with.
pub fn build(gpa: Allocator, data: []const u8) !struct { tree: []u8, params: Params } {
    if (data.len == 0 or data.len % block_size != 0) return error.NotWholeBlocks;
    const data_blocks: u64 = data.len / block_size;
    var salt: [digest_len]u8 = undefined;
    Sha256.hash(data, &salt, .{});

    // One block needs no tree: the kernel counts no levels, and the root
    // hash is the block's own digest.
    if (data_blocks == 1) return .{ .tree = &.{}, .params = .{
        .data_blocks = 1,
        .hash_start = 1,
        .salt = salt,
        .root = digest(&salt, data[0..block_size]),
    } };

    // Each level's blocks, bottom first: level 0 holds the data blocks'
    // digests, each level above its own blocks', up to one block.
    var levels: std.ArrayList([]u8) = .empty;
    var below: []const u8 = data;
    while (true) {
        const n = below.len / block_size;
        const level = try gpa.alloc(u8, (n + per_block - 1) / per_block * block_size);
        @memset(level, 0);
        for (0..n) |i| level[i * digest_len ..][0..digest_len].* = digest(
            &salt,
            below[i * block_size ..][0..block_size],
        );
        try levels.append(gpa, level);
        if (level.len == block_size) break;
        below = level;
    }
    const top = levels.items[levels.items.len - 1];

    // Top first, as the kernel lays them out.
    var size: usize = 0;
    for (levels.items) |l| size += l.len;
    const tree = try gpa.alloc(u8, size);
    var at: usize = 0;
    var i = levels.items.len;
    while (i > 0) {
        i -= 1;
        @memcpy(tree[at..][0..levels.items[i].len], levels.items[i]);
        at += levels.items[i].len;
    }
    return .{ .tree = tree, .params = .{
        .data_blocks = data_blocks,
        .hash_start = data_blocks,
        .salt = salt,
        .root = digest(&salt, top[0..block_size]),
    } };
}

/// The digest of a block: SHA-256 of the salt, then the block (version 1).
fn digest(salt: *const [digest_len]u8, block: *const [block_size]u8) [digest_len]u8 {
    var h: Sha256 = .init(.{});
    h.update(salt);
    h.update(block);
    return h.finalResult();
}

/// The table dm-verity takes for a device holding both data and tree, as
/// stage0 loads it: version 1, the same device twice, block sizes, the
/// data's size and the tree's start, the hash, the root and the salt.
pub fn table(buf: []u8, dev: []const u8, p: Params) ![]const u8 {
    return std.mem.print(buf, "1 {s} {s} {d} {d} {d} {d} sha256 {x} {x}", .{
        dev, dev, block_size, block_size, p.data_blocks, p.hash_start, &p.root, &p.salt,
    });
}

const testing = std.testing;

test "one block: no tree, the block's own digest" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const data: [block_size]u8 = @splat(0);
    const t = try build(arena.allocator(), &data);
    try testing.expectEqual(0, t.tree.len);
    try testing.expectEqual(1, t.params.data_blocks);
    try testing.expectEqualSlices(u8, &digest(&t.params.salt, &data), &t.params.root);
}

test "two blocks, one level" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const data: [2 * block_size]u8 = @splat(0);
    const t = try build(arena.allocator(), &data);
    try testing.expectEqual(block_size, t.tree.len);
    // The one hash block: the data blocks' digests, then zeros.
    const d = digest(&t.params.salt, data[0..block_size]);
    try testing.expectEqualSlices(u8, &(d ++ d), t.tree[0 .. 2 * digest_len]);
    try testing.expect(std.mem.allEqual(u8, t.tree[2 * digest_len ..], 0));
    try testing.expectEqualSlices(
        u8,
        &digest(&t.params.salt, t.tree[0..block_size]),
        &t.params.root,
    );
}

test "levels, top first" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    // 129 data blocks: two level-0 blocks, then a top block of two digests.
    const data = try arena.allocator().alloc(u8, 129 * block_size);
    for (data, 0..) |*b, i| b.* = @truncate(i / block_size);
    const t = try build(arena.allocator(), data);
    try testing.expectEqual(3 * block_size, t.tree.len);
    const top = t.tree[0..block_size];
    try testing.expectEqualSlices(
        u8,
        &digest(&t.params.salt, t.tree[block_size..][0..block_size]),
        top[0..digest_len],
    );
    try testing.expectEqualSlices(
        u8,
        &digest(&t.params.salt, t.tree[2 * block_size ..][0..block_size]),
        top[digest_len .. 2 * digest_len],
    );
    try testing.expectEqualSlices(
        u8,
        &digest(&t.params.salt, data[128 * block_size ..][0..block_size]),
        t.tree[2 * block_size ..][0..digest_len],
    );
    try testing.expectEqualSlices(u8, &digest(&t.params.salt, top), &t.params.root);
}

test Params {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const data: [2 * block_size]u8 = @splat(7);
    const p = (try build(arena.allocator(), &data)).params;
    var out: std.Io.Writer.Allocating = .init(arena.allocator());
    try p.format(&out.writer);
    try testing.expectEqual(p, try Params.parse(out.written()));
    try testing.expectError(error.BadVerity, Params.parse("2 1 00 00\n"));
    try testing.expectError(error.NotWholeBlocks, build(arena.allocator(), data[0..100]));
    var buf: [512]u8 = undefined;
    const t = try table(&buf, "/dev/loop0", p);
    try testing.expect(std.mem.startsWith(u8, t, "1 /dev/loop0 /dev/loop0 4096 4096 2 2 sha256 "));
}
