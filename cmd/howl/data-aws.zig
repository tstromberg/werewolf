//! Read an immutable EBS snapshot into private raw storage. Sparse blocks are
//! zero; every returned block must match its index, size and SHA-256 checksum.
const std = @import("std");
const api = @import("data-cloud-disk.zig");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const A = std.mem.Allocator;
const block_size = 512 << 10;

pub fn copy(io: Io, a: A, region: []const u8, volume: []const u8, name: []const u8, raw: []const u8, work: []const u8) !void {
    const response = try api.aws(io, a, region, &.{ "ec2", "create-snapshot", "--volume-id", volume, "--description", name, "--tag-specifications", try a.print("ResourceType=snapshot,Tags=[{{Key=werewolf,Value=transfer}},{{Key=Name,Value={s}}}]", .{name}) });
    const created = try std.json.parseFromSliceLeaky(struct { SnapshotId: []const u8 }, a, response, .{ .ignore_unknown_fields = true });
    const snapshot = created.SnapshotId;
    defer {
        _ = api.aws(io, a, region, &.{ "ec2", "delete-snapshot", "--snapshot-id", snapshot }) catch {
            howl.say(io, "temporary snapshot {s} remains in {s}", .{ snapshot, region });
        };
    }
    _ = try api.aws(io, a, region, &.{ "ec2", "wait", "snapshot-completed", "--snapshot-ids", snapshot });
    const file = try Dir.cwd().createFile(io, raw, .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    var slots: [4]Slot = undefined;
    for (&slots, 0..) |*slot, i| slot.* = .{
        .request = try a.print("{s}/ebs-{d}.json", .{ work, i }),
        .data = try a.print("{s}/ebs-{d}.block", .{ work, i }),
    };
    defer for (&slots) |*slot| {
        if (slot.child) |*child| child.kill(io);
        Dir.cwd().deleteFile(io, slot.request) catch {};
        Dir.cwd().deleteFile(io, slot.data) catch {};
    };
    const request = try a.print("{s}/ebs-list.json", .{work});
    defer Dir.cwd().deleteFile(io, request) catch {};
    var next: ?[]const u8 = null;
    var size: ?u64 = null;
    var previous: ?u64 = null;
    var pages: u64 = 0;
    var session = try @import("aws.zig").credentials(io, a);
    defer session.deinit();
    var refreshed = Io.Clock.awake.now(io);
    while (true) {
        const previous_token = next;
        // Tokens stay in private request files, never command arguments/logs.
        const body = if (next) |token|
            try std.json.Stringify.valueAlloc(a, .{ .SnapshotId = snapshot, .MaxResults = 128, .NextToken = token }, .{})
        else
            try std.json.Stringify.valueAlloc(a, .{ .SnapshotId = snapshot, .MaxResults = 128 }, .{});
        try Dir.cwd().writeFile(io, .{ .sub_path = request, .data = body, .flags = .{ .permissions = .fromMode(0o600) } });
        const bytes = try api.aws(io, a, region, &.{ "ebs", "list-snapshot-blocks", "--no-paginate", "--cli-input-json", try a.print("file://{s}", .{request}) });
        const page = try std.json.parseFromSliceLeaky(Page, a, bytes, .{ .ignore_unknown_fields = true });
        const length = try pageSize(page);
        if (size) |expected| {
            if (length != expected) return error.TransferCloudDisk;
        } else {
            size = length;
            try file.setLength(io, length);
        }
        pages += 1;
        if (pages > length / block_size + 1) return error.TransferCloudDisk;
        for (page.Blocks, 0..) |block, i| {
            if (refreshed.untilNow(io, .awake).toSeconds() >= 60) {
                const fresh = try @import("aws.zig").credentials(io, a);
                session.deinit();
                session = fresh;
                refreshed = Io.Clock.awake.now(io);
            }
            if (previous) |last| if (block.BlockIndex <= last) return error.TransferCloudDisk;
            previous = block.BlockIndex;
            const slot = &slots[i % slots.len];
            try finish(io, a, slot, file);
            slot.index = block.BlockIndex;
            try Dir.cwd().writeFile(io, .{ .sub_path = slot.request, .data = block.BlockToken, .flags = .{ .permissions = .fromMode(0o600) } });
            const reserved = try Dir.cwd().createFile(io, slot.data, .{ .permissions = .fromMode(0o600) });
            reserved.close(io);
            // This streaming CLI command requires explicit flags; its custom
            // handler ignores required fields supplied in --cli-input-json.
            slot.child = try std.process.spawn(io, .{ .argv = try api.awsArgs(a, region, &.{ "ebs", "get-snapshot-block", "--snapshot-id", snapshot, "--block-index", try a.print("{d}", .{block.BlockIndex}), "--block-token", try a.print("file://{s}", .{slot.request}), slot.data }), .environ_map = &session, .stdin = .ignore, .stdout = .pipe, .stderr = .ignore });
        }
        for (&slots) |*slot| try finish(io, a, slot, file);
        next = page.NextToken;
        if (next == null) break;
        if (next.?.len == 0 or next.?.len > 256) return error.TransferCloudDisk;
        if (previous_token) |token| if (std.mem.eql(u8, token, next.?)) return error.TransferCloudDisk;
    }
    try file.sync(io);
}

const Page = struct {
    VolumeSize: u64,
    BlockSize: u64,
    Blocks: []const struct { BlockIndex: u64, BlockToken: []const u8 },
    NextToken: ?[]const u8 = null,
};

fn pageSize(page: Page) !u64 {
    if (page.VolumeSize == 0 or page.VolumeSize > (1 << 20) or page.BlockSize != block_size or page.Blocks.len > 128) return error.TransferCloudDisk;
    const size = page.VolumeSize << 30;
    for (page.Blocks) |block| if (block.BlockIndex >= size / block_size or block.BlockToken.len == 0 or block.BlockToken.len > 256) return error.TransferCloudDisk;
    return size;
}

const Slot = struct { child: ?std.process.Child = null, index: u64 = 0, request: []const u8, data: []const u8 };

fn finish(io: Io, a: A, slot: *Slot, target: Io.File) !void {
    const child = if (slot.child) |*c| c else return;
    const pipe = child.stdout.?;
    child.stdout = null;
    defer pipe.close(io);
    var buffer: [1024]u8 = undefined;
    var reader = pipe.readerStreaming(io, &buffer);
    const response = try reader.interface.allocRemaining(a, .limited(4096));
    if (!(try child.wait(io)).success()) return error.TransferCloudDownload;
    slot.child = null;
    const metadata = try std.json.parseFromSliceLeaky(struct { DataLength: u64, Checksum: []const u8, ChecksumAlgorithm: []const u8 }, a, response, .{ .ignore_unknown_fields = true });
    const bytes = try Dir.cwd().readFileAlloc(io, slot.data, a, .limited(block_size + 1));
    defer a.free(bytes);
    try checkBlock(bytes, metadata.DataLength, metadata.ChecksumAlgorithm, metadata.Checksum);
    if (!std.mem.allEqual(u8, bytes, 0)) try target.writePositionalAll(io, bytes, slot.index * block_size);
}

fn checkBlock(bytes: []const u8, length: u64, algorithm: []const u8, checksum: []const u8) !void {
    if (length != block_size or bytes.len != block_size or !std.mem.eql(u8, algorithm, "SHA256")) return error.TransferCloudDisk;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    var encoded: [44]u8 = undefined;
    if (!std.mem.eql(u8, checksum, std.base64.standard.Encoder.encode(&encoded, &digest))) return error.TransferCloudDisk;
}

test "EBS refuses invalid volume sizes, block bounds and corrupted blocks" {
    const t = std.testing;
    try t.expectEqual(@as(u64, 1 << 30), try pageSize(.{ .VolumeSize = 1, .BlockSize = block_size, .Blocks = &.{} }));
    try t.expectError(error.TransferCloudDisk, pageSize(.{ .VolumeSize = 0, .BlockSize = block_size, .Blocks = &.{} }));
    try t.expectError(error.TransferCloudDisk, pageSize(.{ .VolumeSize = 1, .BlockSize = 4096, .Blocks = &.{} }));
    try t.expectError(error.TransferCloudDisk, pageSize(.{ .VolumeSize = 1, .BlockSize = block_size, .Blocks = &.{.{ .BlockIndex = 2048, .BlockToken = "token" }} }));
    const bytes = try t.allocator.alloc(u8, block_size);
    defer t.allocator.free(bytes);
    @memset(bytes, 0);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    var encoded: [44]u8 = undefined;
    const sum = std.base64.standard.Encoder.encode(&encoded, &digest);
    try checkBlock(bytes, block_size, "SHA256", sum);
    bytes[0] = 1;
    try t.expectError(error.TransferCloudDisk, checkBlock(bytes, block_size, "SHA256", sum));
    try t.expectError(error.TransferCloudDisk, checkBlock(bytes, block_size, "SHA1", sum));
    try t.expectError(error.TransferCloudDisk, checkBlock(bytes[0..10], 10, "SHA256", sum));
}
