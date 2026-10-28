//! A single-frame Zstandard boundary around the standard streaming decoder.
//! The standard decoder accepts concatenated/skippable frames and currently
//! cannot verify frame checksums; neither behavior is our archive contract.
const std = @import("std");
const transfer = @import("data-transfer.zig");
const Io = std.Io;
const Reader = Io.Reader;
pub const max_window = 8 << 20;

/// Read a bounded, untrusted hint without extracting any filesystem entry.
pub fn manifest(a: std.mem.Allocator, input: *Reader) !transfer.Manifest {
    const frame_buffer = try a.alloc(u8, std.compress.zstd.block_size_max + 18);
    defer a.free(frame_buffer);
    var frame = try Frame.init(input, frame_buffer);
    const buffer = try a.alloc(u8, max_window + std.compress.zstd.block_size_max);
    defer a.free(buffer);
    var decoder = std.compress.zstd.Decompress.init(
        &frame.reader,
        buffer,
        .{ .window_len = max_window },
    );
    return transfer.manifest(a, &decoder.reader);
}

pub fn validate(
    a: std.mem.Allocator,
    input: *Reader,
    policy: transfer.Policy,
    service: ?[]const u8,
    sink: ?transfer.Sink,
) !transfer.Result {
    const frame_buffer = try a.alloc(u8, std.compress.zstd.block_size_max + 18);
    defer a.free(frame_buffer);
    var frame = try Frame.init(input, frame_buffer);
    const buffer = try a.alloc(u8, max_window + std.compress.zstd.block_size_max);
    defer a.free(buffer);
    var decoder = std.compress.zstd.Decompress.init(
        &frame.reader,
        buffer,
        .{ .window_len = max_window },
    );
    var checksum = std.hash.XxHash64.init(0);
    const result = transfer.validateChecksummed(
        a,
        &decoder.reader,
        policy,
        service,
        sink,
        &checksum,
    ) catch |err| {
        if (frame.err) |e| return e;
        if (decoder.err) |e| return e;
        return err;
    };
    if (frame.state != .done or frame.pending_at != frame.pending_len) return error.TransferFrame;
    if (frame.checksummed and
        @as(u32, @truncate(checksum.final())) != frame.checksum) return error.TransferFrameChecksum;
    if (input.takeByte()) |_|
        return error.TransferTrailing
    else |err| if (err != error.EndOfStream)
        return err;
    return result;
}

const Frame = struct {
    input: *Reader,
    reader: Reader,
    pending: [18]u8 = undefined,
    pending_at: usize = 0,
    pending_len: usize,
    state: enum { block, payload, checksum, done } = .block,
    remaining: usize = 0,
    last: bool = false,
    checksummed: bool,
    checksum: u32 = 0,
    err: ?anyerror = null,

    fn init(input: *Reader, buffer: []u8) !Frame {
        var bytes: [18]u8 = undefined;
        try input.readSliceAll(bytes[0..5]);
        if (!std.mem.eql(u8, bytes[0..4], "\x28\xb5\x2f\xfd")) return error.TransferFrame;
        const flags = bytes[4];
        if (flags & 0x1b != 0) return error.TransferFrame;
        const single = flags & 0x20 != 0;
        const size_flag: u2 = @truncate(flags >> 6);
        const size_len: usize = switch (size_flag) {
            0 => @intFromBool(single),
            1 => 2,
            2 => 4,
            3 => 8,
        };
        const len = 5 + @as(usize, @intFromBool(!single)) + size_len;
        try input.readSliceAll(bytes[5..len]);
        return .{
            .input = input,
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
            .pending = bytes,
            .pending_len = len,
            .checksummed = flags & 4 != 0,
        };
    }

    fn stream(r: *Reader, w: *Io.Writer, limit: Io.Limit) Reader.StreamError!usize {
        const f: *Frame = @fieldParentPtr("reader", r);
        return f.next(w, limit) catch |err| switch (err) {
            error.WriteFailed, error.EndOfStream => |e| return e,
            else => {
                f.err = err;
                return error.ReadFailed;
            },
        };
    }

    fn next(f: *Frame, w: *Io.Writer, limit: Io.Limit) !usize {
        while (true) {
            if (f.pending_at < f.pending_len) {
                const n = limit.minInt(f.pending_len - f.pending_at);
                try w.writeAll(f.pending[f.pending_at..][0..n]);
                f.pending_at += n;
                return n;
            }
            switch (f.state) {
                .block => {
                    f.input.readSliceAll(f.pending[0..3]) catch return error.TransferTruncated;
                    const bits = std.mem.readInt(u24, f.pending[0..3], .little);
                    const kind = (bits >> 1) & 3;
                    if (kind == 3 or bits >> 3 > 128 << 10) return error.TransferFrame;
                    f.remaining = if (kind == 1) 1 else bits >> 3;
                    f.last = bits & 1 != 0;
                    f.pending_at = 0;
                    f.pending_len = 3;
                    f.state = .payload;
                },
                .payload => {
                    if (f.remaining != 0) {
                        const n = f.input.stream(w, limit.min(.limited(f.remaining))) catch |err|
                            return if (err == error.EndOfStream) error.TransferTruncated else err;
                        f.remaining -= n;
                        return n;
                    }
                    f.state = if (!f.last) .block else if (f.checksummed) .checksum else .done;
                },
                .checksum => {
                    f.input.readSliceAll(f.pending[0..4]) catch return error.TransferTruncated;
                    f.checksum = std.mem.readInt(u32, f.pending[0..4], .little);
                    f.pending_at = 0;
                    f.pending_len = 4;
                    f.state = .done;
                },
                .done => return error.EndOfStream,
            }
        }
    }
};

test "Zstandard frame boundary rejects concatenation, damage and truncation" {
    const t = std.testing;
    const io = t.io;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const policy: transfer.Policy = .{
        .image = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .arch = .aarch64,
        .services = &.{},
        .users = &.{},
        .groups = &.{},
    };
    const empty_manifest: transfer.Manifest = .{
        .image = policy.image,
        .arch = policy.arch,
        .entries = &.{},
    };
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var tar: Io.Writer.Allocating = .init(a);
    const owners: transfer.Ownership = .{ .get = struct {
        fn get(_: ?*anyopaque, _: Io.File) !transfer.Owner {
            return error.UnexpectedOwnerLookup;
        }
    }.get };
    _ = try transfer.emit(io, a, tmp.dir, empty_manifest, policy, owners, &tar.writer);
    try tmp.dir.writeFile(io, .{ .sub_path = "input.tar", .data = tar.written() });
    const path = try tmp.dir.realPathFileAlloc(io, "input.tar", a);
    const result = try std.process.run(
        a,
        io,
        .{
            .argv = &.{ "zstd", "-1", "-q", "-c", "--", path },
            .stdout_limit = .limited(1 << 20),
            .stderr_limit = .limited(4096),
        },
    );
    try t.expect(result.term == .exited and result.term.exited == 0);
    var input: Reader = .fixed(result.stdout);
    _ = try validate(a, &input, policy, null, null);
    const doubled = try std.mem.concat(a, u8, &.{ result.stdout, result.stdout });
    input = .fixed(doubled);
    try t.expectError(error.TransferTrailing, validate(a, &input, policy, null, null));
    const damaged = try a.dupe(u8, result.stdout);
    damaged[damaged.len - 1] ^= 1;
    input = .fixed(damaged);
    try t.expectError(error.TransferFrameChecksum, validate(a, &input, policy, null, null));
    for (0..result.stdout.len) |n| {
        var scratch = std.heap.ArenaAllocator.init(t.allocator);
        defer scratch.deinit();
        input = .fixed(result.stdout[0..n]);
        if (validate(scratch.allocator(), &input, policy, null, null)) |_|
            return error.AcceptedTruncation
        else |_| {}
    }
    // No allocation or decoder execution is needed to reject these frame kinds.
    input = .fixed("\x50\x2a\x4d\x18\x00");
    try t.expectError(error.TransferFrame, validate(a, &input, policy, null, null));
    input = .fixed("\x28\xb5\x2f\xfd\x01");
    try t.expectError(error.TransferFrame, validate(a, &input, policy, null, null));
}
