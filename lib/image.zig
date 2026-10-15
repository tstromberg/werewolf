//! image holds the steps of making a slot that the build host and the
//! updater share: gunzip, the kernel unwraps, the kernel config check and
//! mkfs.erofs's options. See lib/README.md.

const std = @import("std");
const Allocator = std.mem.Allocator;
const mem = std.mem;

/// max_gunzip bounds what gunzip inflates: the kernel's Image is 40 MB.
pub const max_gunzip = 256 << 20;

/// gunzip inflates the first gzip member of data, as a kernel payload is one
/// member. It refuses more than max_gunzip bytes.
pub fn gunzip(gpa: Allocator, data: []const u8) ![]u8 {
    var in: std.Io.Reader = .fixed(data);
    var gz: std.compress.flate.Decompress = .init(&in, .gzip, &.{});
    return gz.reader.allocRemaining(gpa, .limited(max_gunzip)) catch |err| switch (err) {
        error.ReadFailed => return gz.err orelse error.ReadFailed,
        else => return err,
    };
}

/// max_zstd_window is the largest window zstd -22 --ultra, the kernel's
/// setting, uses. The kernel pipes its payload in, so zstd takes it whole.
const max_zstd_window = 1 << 27;

/// unzstd inflates a payload compressed as the kernel's build does: one zstd
/// frame, then the inflated size as a little-endian u32.
pub fn unzstd(gpa: Allocator, data: []const u8) ![]u8 {
    if (data.len < 4) return error.BadZstd;
    var in: std.Io.Reader = .fixed(data[0 .. data.len - 4]);
    const window = try gpa.alloc(u8, max_zstd_window + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var z: std.compress.zstd.Decompress = .init(&in, window, .{ .window_len = max_zstd_window });
    const out = z.reader.allocRemaining(gpa, .limited(max_gunzip)) catch |err| switch (err) {
        error.ReadFailed => return z.err orelse error.ReadFailed,
        else => return err,
    };
    if (out.len != mem.readInt(u32, data[data.len - 4 ..][0..4], .little)) return error.BadZstd;
    return out;
}

/// unwrapZboot returns the Image inside an arm64 EFI zboot image: a PE
/// whose header holds "zimg" at 4, then the gzipped Image's offset and
/// size as little-endian u32s. Apple's Virtualization framework cannot
/// boot the wrapper. Any other image is returned as it is.
pub fn unwrapZboot(gpa: Allocator, image: []const u8) ![]const u8 {
    if (image.len < 16 or !mem.eql(u8, image[4..8], "zimg")) return image;
    const off = mem.readInt(u32, image[8..12], .little);
    const size = mem.readInt(u32, image[12..16], .little);
    if (@as(u64, off) + size > image.len) return error.BadZboot;
    return gunzip(gpa, image[off .. off + size]);
}

/// vmlinux returns the ELF kernel inside an x86 bzImage, which Firecracker
/// boots without waiting for the bzImage's stub to inflate it. The setup
/// header gives the setup sectors at 0x1f1 (0 means 4), then the payload's
/// offset past the setup and its length, u32s at 0x248 and 0x24c. werewolf's
/// kernel compresses it with zstd; gzip is read too.
pub fn vmlinux(gpa: Allocator, bzimage: []const u8) ![]const u8 {
    if (bzimage.len < 0x250) return error.BadBzImage;
    const sects: u64 = if (bzimage[0x1f1] == 0) 4 else bzimage[0x1f1];
    const start = (sects + 1) * 512 + mem.readInt(u32, bzimage[0x248..0x24c], .little);
    const len = mem.readInt(u32, bzimage[0x24c..0x250], .little);
    if (start + len > bzimage.len) return error.BadBzImage;
    const payload = bzimage[start..][0..len];
    const elf = if (mem.startsWith(u8, payload, "\x28\xb5\x2f\xfd"))
        try unzstd(gpa, payload)
    else
        try gunzip(gpa, payload);
    if (!mem.startsWith(u8, elf, "\x7fELF")) return error.NotElf;
    return elf;
}

/// erofs_options are mkfs.erofs's options for a root: zstd in 64 KiB
/// clusters, small files packed together, duplicates kept once, which
/// boots fastest (Makefile, root.erofs). 4 KiB blocks, since mkfs.erofs
/// otherwise takes the builder's page size, 16 KiB on Apple silicon, which
/// a 4 KiB-page kernel will not mount.
pub const erofs_options = [_][]const u8{
    "-b",
    "4096",
    "-zzstd,level=9",
    "-C65536",
    "-Eall-fragments,dedupe",
};

/// checkErofs refuses a mkfs.erofs that would make a bad root. Before 1.9
/// it takes -Eall-fragments from a tar and writes every file empty, without
/// an error; without zstd it cannot write erofs_options. version_out is
/// what `mkfs.erofs --version` wrote to standard output, help_out all that
/// --version and --help wrote. On error.ErofsTooOld, version holds the
/// version it reported, or "" if none.
pub fn checkErofs(
    version_out: []const u8,
    help_out: []const u8,
    version: *[]const u8,
) error{ ErofsTooOld, ErofsNoZstd }!void {
    version.* = "";
    var lines = mem.splitScalar(u8, version_out, '\n');
    while (lines.next()) |line| if (mem.findLast(u8, line, "erofs-utils)")) |at| {
        version.* = mem.trimStart(u8, line[at + "erofs-utils)".len ..], " ");
        break;
    };
    const v = version.*;
    const old = v.len == 0 or (v.len >= 3 and mem.startsWith(u8, v, "1.") and
        v[2] >= '0' and v[2] <= '8' and (v.len == 3 or v[3] == '.'));
    if (old) return error.ErofsTooOld;
    lines = mem.splitScalar(u8, help_out, '\n');
    while (lines.next()) |line| if (mem.find(u8, line, "available compressors:")) |at| {
        if (mem.find(u8, line[at..], "zstd") != null) return;
    };
    return error.ErofsNoZstd;
}

/// Want is the value a kernel config rule requires of an option.
const Want = enum {
    /// yes means built in, because werewolf relies on it.
    yes,
    /// off means left out entirely; with no module loader, nothing else is out.
    off,

    fn holds(want: Want, v: []const u8) bool {
        return switch (want) {
            .yes => mem.eql(u8, v, "y"),
            .off => v.len == 0,
        };
    }

    fn text(want: Want) []const u8 {
        return switch (want) {
            .yes => "built in",
            .off => "off",
        };
    }
};

/// config_rules are what werewolf relies on its kernel's config to leave out,
/// or keep in, whatever config/*.cfg in werewolf-linux/kernel-build says
/// later. Each names what it closes.
const config_rules = [_]struct { []const u8, Want, []const u8 }{
    .{ "CONFIG_CRYPTO_USER_API", .off, "AF_ALG: CVE-2025-39964, CVE-2026-31431" },
    .{ "CONFIG_CRYPTO_USER_API_AEAD", .off, "AF_ALG: CVE-2026-31431" },
    .{ "CONFIG_CRYPTO_USER_API_SKCIPHER", .off, "AF_ALG" },
    .{ "CONFIG_CRYPTO_USER_API_HASH", .off, "AF_ALG" },
    .{ "CONFIG_CRYPTO_USER_API_RNG", .off, "AF_ALG" },
    .{ "CONFIG_TLS", .off, "kernel TLS: CVE-2025-39682" },
    .{ "CONFIG_BRIDGE_NF_EBTABLES", .off, "ebtables: CVE-2026-53266" },
    .{ "CONFIG_NF_TABLES", .off, "nf_tables: CVE-2022-2586, CVE-2024-1086" },
    .{ "CONFIG_NETFILTER_XTABLES", .off, "x_tables: CVE-2021-22555" },
    .{ "CONFIG_OVERLAY_FS", .off, "overlayfs: CVE-2023-0386" },
    .{ "CONFIG_HID", .off, "HID: CVE-2024-50302" },
    .{ "CONFIG_USB", .off, "USB: CVE-2024-53150, CVE-2024-53197, CVE-2024-53104" },
    .{ "CONFIG_WATCH_QUEUE", .off, "watch queues: CVE-2022-0995" },
    .{ "CONFIG_SND_USB_AUDIO", .off, "USB audio: CVE-2024-53150, CVE-2024-53197" },
    .{ "CONFIG_USB_VIDEO_CLASS", .off, "USB video: CVE-2024-53104" },
    .{ "CONFIG_POSIX_CPU_TIMERS_TASK_WORK", .yes, "closes CVE-2025-38352's race" },
    .{ "CONFIG_AUDIT", .yes, "init logs every refused exec through audit (lib/audit.zig)" },
    .{ "CONFIG_AUDITSYSCALL", .yes, "audit's system call rules, the refused-exec rule among them" },
};

/// ConfigMiss is a kernel config option that breaks its rule.
pub const ConfigMiss = struct {
    name: []const u8,
    value: []const u8,
    want: []const u8,
    why: []const u8,

    pub fn format(m: ConfigMiss, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{s} is {s}, werewolf needs it {s} ({s})", .{
            m.name, if (m.value.len == 0) "off" else m.value, m.want, m.why,
        });
    }
};

/// configMisses returns the options of a kernel config, text, that break
/// werewolf's rules. A running machine cannot read its config, so the
/// build checks it.
pub fn configMisses(gpa: Allocator, text: []const u8) Allocator.Error![]const ConfigMiss {
    var out: std.ArrayList(ConfigMiss) = .empty;
    for (config_rules) |r| {
        const name, const want, const why = r;
        const v = configValue(text, name);
        if (!want.holds(v)) try out.append(gpa, .{
            .name = name,
            .value = v,
            .want = want.text(),
            .why = why,
        });
    }
    return out.toOwnedSlice(gpa);
}

/// configValue returns name's value in a kernel config, such as "y", "m"
/// or a string, or "" for an option that is not set or not present.
fn configValue(text: []const u8, name: []const u8) []const u8 {
    var it = mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len > name.len and mem.startsWith(u8, line, name) and line[name.len] == '=')
            return line[name.len + 1 ..];
    }
    return "";
}

const testing = std.testing;

/// hello_gz is `printf 'hello\n' | gzip -n`.
const hello_gz = [_]u8{
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xcb, 0x48,
    0xcd, 0xc9, 0xc9, 0xe7, 0x02, 0x00, 0x20, 0x30, 0x3a, 0x36, 0x06, 0x00,
    0x00, 0x00,
};

test gunzip {
    const hello = try gunzip(testing.allocator, &hello_gz);
    defer testing.allocator.free(hello);
    try testing.expectEqualStrings("hello\n", hello);
    try testing.expectError(error.BadGzipHeader, gunzip(testing.allocator, "not gzip, but text\n"));
}

test unwrapZboot {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const plain = "not a zboot image, at all";
    try testing.expectEqualStrings(plain, try unwrapZboot(a, plain));
    var image: [16 + hello_gz.len]u8 = @splat(0);
    @memcpy(image[0..2], "MZ");
    @memcpy(image[4..8], "zimg");
    mem.writeInt(u32, image[8..12], 16, .little);
    mem.writeInt(u32, image[12..16], hello_gz.len, .little);
    @memcpy(image[16..], &hello_gz);
    try testing.expectEqualStrings("hello\n", try unwrapZboot(a, &image));
    mem.writeInt(u32, image[12..16], 100, .little);
    try testing.expectError(error.BadZboot, unwrapZboot(a, &image));
}

test vmlinux {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // `printf '\177ELF' | gzip -n`, after 0 setup sectors (so 4) and a
    // payload offset of 8.
    const elf_gz = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xab, 0x77,
        0xf5, 0x71, 0x03, 0x00, 0x51, 0xc4, 0x3a, 0xa7, 0x04, 0x00, 0x00, 0x00,
    };
    var bz: [5 * 512 + 8 + elf_gz.len]u8 = @splat(0);
    mem.writeInt(u32, bz[0x248..0x24c], 8, .little);
    mem.writeInt(u32, bz[0x24c..0x250], elf_gz.len, .little);
    @memcpy(bz[5 * 512 + 8 ..], &elf_gz);
    try testing.expectEqualStrings("\x7fELF", try vmlinux(a, &bz));
    mem.writeInt(u32, bz[0x24c..0x250], elf_gz.len + 1, .little);
    try testing.expectError(error.BadBzImage, vmlinux(a, &bz));
    try testing.expectError(error.BadBzImage, vmlinux(a, bz[0..0x100]));

    // `printf '\177ELF' | zstd -22 --ultra`, then the size, as the kernel's build appends it.
    const elf_zst = [_]u8{
        0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x88, 0x21, 0x00, 0x00, 0x7f, 0x45, 0x4c, 0x46, 0xad, 0x7f,
        0x12, 0x44, 0x04, 0x00, 0x00, 0x00,
    };
    var zbz: [5 * 512 + 8 + elf_zst.len]u8 = @splat(0);
    mem.writeInt(u32, zbz[0x248..0x24c], 8, .little);
    mem.writeInt(u32, zbz[0x24c..0x250], elf_zst.len, .little);
    @memcpy(zbz[5 * 512 + 8 ..], &elf_zst);
    try testing.expectEqualStrings("\x7fELF", try vmlinux(a, &zbz));
    // A wrong size trailer means a truncated or altered payload.
    zbz[zbz.len - 4] = 5;
    try testing.expectError(error.BadZstd, vmlinux(a, &zbz));
}

test checkErofs {
    var v: []const u8 = undefined;
    const zstd = "available compressors: lz4, lz4hc, deflate, zstd\n";
    try checkErofs("mkfs.erofs (erofs-utils) 1.9.4\n", zstd, &v);
    try testing.expectEqualStrings("1.9.4", v);
    try checkErofs("mkfs.erofs (erofs-utils) 1.10\n", zstd, &v);
    for ([_][]const u8{
        "mkfs.erofs (erofs-utils) 1.7.1\n",
        "mkfs.erofs (erofs-utils) 1.8",
        "",
    }) |out|
        try testing.expectError(error.ErofsTooOld, checkErofs(out, zstd, &v));
    try testing.expectEqualStrings("", v);
    try testing.expectError(error.ErofsNoZstd, checkErofs(
        "mkfs.erofs (erofs-utils) 1.9.4\n",
        "mkfs.erofs (erofs-utils) 1.9.4\navailable compressors: lz4, lz4hc, deflate\n",
        &v,
    ));
}

test configMisses {
    const config =
        \\# CONFIG_TLS is not set
        \\# CONFIG_WATCH_QUEUE is not set
        \\CONFIG_TLS_DEVICE=y
        \\CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y
        \\CONFIG_LSM="landlock,lockdown"
        \\CONFIG_AUDIT=y
        \\CONFIG_AUDITSYSCALL=y
        \\CONFIG_HID=y
    ;
    try testing.expectEqualStrings("", configValue(config, "CONFIG_TLS"));
    try testing.expectEqualStrings("", configValue(config, "CONFIG_WATCH_QUEUE"));
    try testing.expectEqualStrings("\"landlock,lockdown\"", configValue(config, "CONFIG_LSM"));
    const misses = try configMisses(testing.allocator, config);
    defer testing.allocator.free(misses);
    try testing.expectEqual(1, misses.len);
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "CONFIG_HID is y, werewolf needs it off (HID: CVE-2024-50302)",
        try std.mem.print(&buf, "{f}", .{misses[0]}),
    );
    try testing.expect(Want.off.holds(""));
    try testing.expect(!Want.off.holds("m"));
    try testing.expect(!Want.yes.holds("m"));
}
