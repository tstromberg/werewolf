//! gpt writes a sparse disk image with werewolf's partition table: an EFI
//! system partition and a root partition, both empty. howl's disk step
//! (cmd/howl/disk.zig) imports it as the module "gpt", so a build host
//! needs no sfdisk. See docs/design/native-boot.md.

const std = @import("std");
const Io = std.Io;

pub const sector = 512;
/// margin is the gap before the first partition and after the last, in
/// sectors: 1 MiB each.
pub const margin = 2048;
const entries = 128;
const entry_size = 128;
const entry_sectors = entries * entry_size / sector;

const esp_type = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
const linux_type = "0fc63daf-8483-4772-8e79-3d69d8477de4";
// Fixed GUIDs make the same sizes give the same bytes.
const disk_guid = "57e1f000-77e2-4b0f-8a3c-000000000000";
const esp_guid = "57e1f000-77e2-4b0f-8a3c-000000000001";
const root_guid = "57e1f000-77e2-4b0f-8a3c-000000000002";

/// create writes path, a sparse disk of l.sectors sectors that holds the
/// partition table and nothing else.
pub fn create(io: Io, path: []const u8, l: Layout) !void {
    var primary: [(2 + entry_sectors) * sector]u8 = undefined;
    var backup: [(entry_sectors + 1) * sector]u8 = undefined;
    encode(l, &primary, &backup);

    var f = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer f.close(io);
    try f.setLength(io, l.sectors * sector);
    try f.writePositionalAll(io, &primary, 0);
    try f.writePositionalAll(io, &backup, (l.sectors - entry_sectors - 1) * sector);
}

/// Layout holds the disk size and partition bounds, in sectors.
pub const Layout = struct {
    sectors: u64,
    esp_first: u64,
    esp_last: u64,
    root_first: u64,
    root_last: u64,
};

/// layout places an EFI partition of esp_mib MiB and the root on a disk of
/// size_mib MiB. It fails with error.TooSmall if the root gets under 1 MiB.
pub fn layout(size_mib: u32, esp_mib: u32) !Layout {
    const per_mib = 1024 * 1024 / sector;
    const total = @as(u64, size_mib) * per_mib;
    const esp_first: u64 = margin;
    const root_first = esp_first + @as(u64, esp_mib) * per_mib;
    // Leave the root at least 1 MiB, and the end room for the backup table.
    if (esp_mib == 0 or root_first + per_mib + margin > total) return error.TooSmall;
    return .{
        .sectors = total,
        .esp_first = esp_first,
        .esp_last = root_first - 1,
        .root_first = root_first,
        .root_last = total - margin - 1,
    };
}

/// encode writes the protective MBR, primary header and entries into
/// primary, and the backup entries and header, which end the disk, into backup.
pub fn encode(l: Layout, primary: []u8, backup: []u8) void {
    @memset(primary, 0);
    @memset(backup, 0);

    // Protective MBR: one partition of type 0xEE over the whole disk.
    const mbr = primary[0..sector];
    const p = mbr[446..462];
    p[1] = 0x00;
    p[2] = 0x02;
    p[3] = 0x00;
    p[4] = 0xee;
    @memset(p[5..8], 0xff);
    std.mem.writeInt(u32, p[8..12], 1, .little);
    std.mem.writeInt(u32, p[12..16], @intCast(@min(l.sectors - 1, 0xffffffff)), .little);
    mbr[510] = 0x55;
    mbr[511] = 0xaa;

    const table = primary[2 * sector ..][0 .. entry_sectors * sector];
    writeEntry(table[0..entry_size], esp_type, esp_guid, l.esp_first, l.esp_last, "EFI");
    writeEntry(
        table[entry_size..][0..entry_size],
        linux_type,
        root_guid,
        l.root_first,
        l.root_last,
        "werewolf",
    );
    @memcpy(backup[0 .. entry_sectors * sector], table);
    const table_crc = std.hash.Crc32.hash(table);

    const last = l.sectors - 1;
    writeHeader(primary[sector..][0..sector], 1, last, 2, l, table_crc);
    writeHeader(
        backup[entry_sectors * sector ..][0..sector],
        last,
        1,
        last - entry_sectors,
        l,
        table_crc,
    );
}

fn writeHeader(h: []u8, mine: u64, alternate: u64, table_lba: u64, l: Layout, table_crc: u32) void {
    @memcpy(h[0..8], "EFI PART");
    std.mem.writeInt(u32, h[8..12], 0x00010000, .little);
    std.mem.writeInt(u32, h[12..16], 92, .little);
    std.mem.writeInt(u64, h[24..32], mine, .little);
    std.mem.writeInt(u64, h[32..40], alternate, .little);
    std.mem.writeInt(u64, h[40..48], 2 + entry_sectors, .little);
    std.mem.writeInt(u64, h[48..56], l.sectors - entry_sectors - 2, .little);
    guid(h[56..72], disk_guid);
    std.mem.writeInt(u64, h[72..80], table_lba, .little);
    std.mem.writeInt(u32, h[80..84], entries, .little);
    std.mem.writeInt(u32, h[84..88], entry_size, .little);
    std.mem.writeInt(u32, h[88..92], table_crc, .little);
    // The header CRC covers its 92 bytes with the CRC field still zero.
    std.mem.writeInt(u32, h[16..20], std.hash.Crc32.hash(h[0..92]), .little);
}

fn writeEntry(
    e: []u8,
    kind: []const u8,
    id: []const u8,
    first: u64,
    last: u64,
    name: []const u8,
) void {
    guid(e[0..16], kind);
    guid(e[16..32], id);
    std.mem.writeInt(u64, e[32..40], first, .little);
    std.mem.writeInt(u64, e[40..48], last, .little);
    // The name is UTF-16LE; ours are ASCII.
    for (name, 0..) |c, i| e[56 + 2 * i] = c;
}

/// guid encodes s as GPT stores a GUID: the first three fields little-endian,
/// the rest in order. Every s is a constant, so the tests catch a bad one.
fn guid(out: *[16]u8, s: []const u8) void {
    var raw: [16]u8 = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '-') continue;
        raw[n] = std.fmt.parseInt(u8, s[i .. i + 2], 16) catch unreachable;
        n += 1;
        i += 1;
    }
    std.debug.assert(n == 16);
    for (0..4) |k| out[k] = raw[3 - k];
    out[4] = raw[5];
    out[5] = raw[4];
    out[6] = raw[7];
    out[7] = raw[6];
    @memcpy(out[8..16], raw[8..16]);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test layout {
    const l = try layout(1024, 256);
    try testing.expectEqual(1024 * 2048, l.sectors);
    try testing.expectEqual(2048, l.esp_first);
    try testing.expectEqual(2048 + 256 * 2048 - 1, l.esp_last);
    try testing.expectEqual(l.esp_last + 1, l.root_first);
    try testing.expectEqual(1024 * 2048 - 2048 - 1, l.root_last);
    try testing.expectError(error.TooSmall, layout(258, 256));
    try testing.expectError(error.TooSmall, layout(64, 0));
}

test guid {
    var g: [16]u8 = undefined;
    guid(&g, esp_type);
    try testing.expectEqualSlices(
        u8,
        &.{
            0x28,
            0x73,
            0x2a,
            0xc1,
            0x1f,
            0xf8,
            0xd2,
            0x11,
            0xba,
            0x4b,
            0x00,
            0xa0,
            0xc9,
            0x3e,
            0xc9,
            0x3b,
        },
        &g,
    );
}

test encode {
    const l = try layout(64, 16);
    var primary: [(2 + entry_sectors) * sector]u8 = undefined;
    var backup: [(entry_sectors + 1) * sector]u8 = undefined;
    encode(l, &primary, &backup);

    try testing.expectEqual(0x55, primary[510]);
    try testing.expectEqual(0xee, primary[446 + 4]);
    const h = primary[sector..][0..sector];
    try testing.expectEqualStrings("EFI PART", h[0..8]);
    try testing.expectEqual(1, std.mem.readInt(u64, h[24..32], .little));
    try testing.expectEqual(l.sectors - 1, std.mem.readInt(u64, h[32..40], .little));

    // Both headers check out, and agree on the table.
    const b = backup[entry_sectors * sector ..][0..sector];
    for ([_]*[sector]u8{ h, b }) |x| {
        var copy = x[0..92].*;
        @memset(copy[16..20], 0);
        try testing.expectEqual(
            std.mem.readInt(u32, x[16..20], .little),
            std.hash.Crc32.hash(&copy),
        );
        try testing.expectEqual(
            std.hash.Crc32.hash(primary[2 * sector ..][0 .. entry_sectors * sector]),
            std.mem.readInt(u32, x[88..92], .little),
        );
    }
    try testing.expectEqual(l.sectors - 1, std.mem.readInt(u64, b[24..32], .little));
    try testing.expectEqual(
        l.sectors - 1 - entry_sectors,
        std.mem.readInt(u64, b[72..80], .little),
    );
    try testing.expectEqualSlices(
        u8,
        primary[2 * sector ..][0 .. entry_sectors * sector],
        backup[0 .. entry_sectors * sector],
    );

    // The second entry is the root, named in UTF-16LE.
    const e = primary[2 * sector + entry_size ..][0..entry_size];
    try testing.expectEqual(l.root_first, std.mem.readInt(u64, e[32..40], .little));
    try testing.expectEqual(l.root_last, std.mem.readInt(u64, e[40..48], .little));
    try testing.expectEqualSlices(u8, "w\x00e\x00r\x00", e[56..62]);
}
