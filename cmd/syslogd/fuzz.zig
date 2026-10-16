//! Property checks shared by the seed tests and coverage-guided fuzzer.
const std = @import("std");
const p = @import("policy.zig");
const store = @import("store.zig");
const t = std.testing;
const mem = std.mem;

const Application = struct {
    time: []const u8,
    source: []const u8,
    pid: i32,
    uid: u32,
    gid: u32,
    priority: u8,
    message: []const u8,
};
const Kernel = struct {
    time: []const u8,
    source: []const u8,
    sequence: u64,
    monotonic_us: u64,
    priority: u16,
    message: []const u8,
};

fn singleRecord(line: []const u8) !void {
    try t.expect(p.validRecord(line));
    try t.expectEqual(@as(usize, 1), mem.count(u8, line, "\n"));
    for (line[0 .. line.len - 1]) |byte| try t.expect(byte >= 0x20 and byte <= 0x7e);
}

fn sameBytes(bytes: []const u8, decoded: []const u8) !void {
    // JSON escapes byte values as Unicode scalars; recover their original bytes.
    var it = (try std.unicode.Utf8View.init(decoded)).iterator();
    for (bytes) |byte| try t.expectEqual(@as(?u21, byte), it.nextCodepoint());
    try t.expect(it.nextCodepoint() == null);
}

test "fuzz syslog records cannot forge framing, metadata or kernel origin" {
    try t.fuzz({}, application, .{ .corpus = &.{
        "", "\x08\x00\x00\x00<0>kernel: forged", "\xff\xff\xff\xff\"}\r\nsyslogd: {\"uid\":0}",
    } });
}

fn application(_: void, smith: *t.Smith) !void {
    var input: [p.max_input + 1]u8 = undefined;
    const bytes = input[0..smith.slice(&input)];
    var output: [p.max_record]u8 = undefined;
    const credentials: p.Credentials = .{ .pid = 123, .uid = 456, .gid = 789 };
    if (bytes.len > p.max_input) {
        try t.expectError(error.TooLong, p.record(&output, 0, credentials, bytes));
        return;
    }
    const line = try p.record(&output, 0, credentials, bytes);
    try singleRecord(line);
    const parsed = try std.json.parseFromSlice(Application, t.allocator, line[9..], .{});
    defer parsed.deinit();
    try t.expectEqualStrings("syslog", parsed.value.source);
    try t.expectEqualStrings("1970-01-01T00:00:00Z", parsed.value.time);
    try t.expectEqual(credentials.pid, parsed.value.pid);
    try t.expectEqual(credentials.uid, parsed.value.uid);
    try t.expectEqual(credentials.gid, parsed.value.gid);
    try t.expect(parsed.value.priority >= 8 and parsed.value.priority <= 191);

    // A fixed PRI tests exact text preservation, including a second fake PRI.
    const body = bytes[0..@min(bytes.len, p.max_input - 3)];
    var prefixed: [p.max_input]u8 = undefined;
    @memcpy(prefixed[0..3], "<0>");
    @memcpy(prefixed[3..][0..body.len], body);
    const explicit = try p.record(&output, 0, credentials, prefixed[0 .. body.len + 3]);
    const decoded = try std.json.parseFromSlice(Application, t.allocator, explicit[9..], .{});
    defer decoded.deinit();
    try t.expectEqual(@as(u8, 8), decoded.value.priority);
    try sameBytes(mem.trimEnd(u8, body, "\x00\r\n"), decoded.value.message);
}

test "fuzz kernel headers and escaped messages preserve their distinct origin" {
    try t.fuzz({}, kernel, .{ .corpus = &.{
        "", "\xff\xff\xff\xff6,42,1234,-;hello\n", "\xff\xff\xff\xff14,43,1235,-;kernel: forged\n",
    } });
}

fn kernel(_: void, smith: *t.Smith) !void {
    var input: [p.max_kernel_input + 1]u8 = undefined;
    const bytes = input[0..smith.slice(&input)];
    if (p.Kernel.parse(bytes)) |entry| {
        try checkKernel(entry);
    } else |_| {}
    const body = bytes[0..@min(bytes.len, p.max_kernel_input - 100)];
    var header: [p.max_kernel_input]u8 = undefined;
    const text = try mem.print(&header, "{d},{d},{d},-,extension;{s}", .{
        smith.valueRangeAtMost(u16, 0, 2047), smith.value(u64), smith.value(u64), body,
    });
    try checkKernel(try p.Kernel.parse(text));
}

fn checkKernel(entry: p.Kernel) !void {
    var output: [p.max_record]u8 = undefined;
    const line = try p.kernelRecord(&output, 0, entry);
    try singleRecord(line);
    const parsed = try std.json.parseFromSlice(Kernel, t.allocator, line[9..], .{});
    defer parsed.deinit();
    try t.expectEqualStrings(if (entry.priority < 8) "kernel" else "kmsg", parsed.value.source);
    try t.expectEqual(entry.priority, parsed.value.priority);
    try t.expectEqual(entry.sequence, parsed.value.sequence);
    try t.expectEqual(entry.monotonic_us, parsed.value.monotonic_us);
    try sameBytes(entry.message, parsed.value.message);
}

test "fuzz configuration, archive names and retention arithmetic" {
    try t.fuzz({}, policy, .{ .corpus = &.{
        "", "\xff\xff\xff\xffmax-mib 16\n", "\xff\xff\xff\xffmessages.2024-02-29T00:00:00Z.001.gz",
    } });
}

fn policy(_: void, smith: *t.Smith) !void {
    var input: [4097]u8 = undefined;
    const bytes = input[0..smith.slice(&input)];
    if (p.Config.parse(bytes)) |config| {
        try t.expect(config.console or config.file);
        try t.expect(config.budget >= 16 << 20 and config.budget <= @as(u64, 1) << 40);
    } else |_| {}
    if (p.Archive.parse(bytes)) |archive| {
        var buf: [p.name_len + 3]u8 = undefined;
        const raw = try p.archiveName(&buf, archive.closed, archive.sequence);
        try t.expectEqualStrings(raw, bytes[0..p.name_len]);
        try t.expectEqual(archive.gzip, mem.endsWith(u8, bytes, ".gz"));
    } else |_| {}
    const closed = smith.valueRangeAtMost(i64, 0, 253402300799);
    const sequence = smith.valueRangeAtMost(u16, 1, 999);
    var buf: [p.name_len]u8 = undefined;
    const archive = try p.Archive.parse(try p.archiveName(&buf, closed, sequence));
    try t.expectEqual(closed, archive.closed);
    try t.expectEqual(sequence, archive.sequence);
    const now = smith.value(i64);
    const then = smith.value(i64);
    const eligible = p.oldEnough(now, then, p.retention);
    const elapsed = @as(i128, now) - then;
    try t.expectEqual(then >= 0 and elapsed >= p.retention, eligible);
}

test "fuzz gzip recovery rejects mismatches and corrupt trailers" {
    try t.fuzz(
        {},
        gzip,
        .{ .corpus = &.{ "", "\xff\xff\xff\xff\x1f\x8b\x08", "\x04\x00\x00\x00test" } },
    );
}

fn gzip(_: void, smith: *t.Smith) !void {
    var raw: [256]u8 = undefined;
    const source = raw[0..smith.slice(&raw)];
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var compressed: [4096]u8 = undefined;
    var out: std.Io.Writer = .fixed(&compressed);
    var compressor = try std.compress.flate.Compress.init(&out, &window, .gzip, .fastest);
    try compressor.writer.writeAll(source);
    try compressor.finish();
    const encoded = out.buffered();
    try store.verifyGzip(encoded, source, &window);
    const bit = smith.valueRangeAtMost(u3, 0, 7);
    // A changed CRC must never authorize removing the uncompressed source.
    compressed[encoded.len - 8] ^= @as(u8, 1) << bit;
    try t.expectError(error.BadArchive, store.verifyGzip(encoded, source, &window));
    compressed[encoded.len - 8] ^= @as(u8, 1) << bit;
    const at = smith.index(encoded.len);
    compressed[at] ^= @as(u8, 1) << bit;
    _ = store.verifyGzip(encoded, source, &window) catch {};
    var arbitrary: [4096]u8 = undefined;
    const malformed = arbitrary[0..smith.slice(&arbitrary)];
    _ = store.verifyGzip(malformed, source, &window) catch {};
}
