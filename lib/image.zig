//! image holds the steps of making a slot that the build host and the
//! updater share: the modules stage0 loads, gunzip, the kernel unwraps,
//! the kernel config check and mkfs.erofs's options. See lib/README.md.

const std = @import("std");
const Allocator = std.mem.Allocator;
const mem = std.mem;

/// Param is a parameter the image loads a module with: kvm-intel, nested=0.
pub const Param = struct { module: []const u8, value: []const u8 };

/// Modules is what a stage0 loads: werewolf.modules and the files it names.
pub const Modules = struct {
    /// list is werewolf.modules, a line per module in load order:
    /// `[@TAG ]PATH[ KEY=VALUE...]`, PATH as modules.dep has it without .gz.
    list: []const u8,
    /// files are the distinct modules.dep paths the list names, sorted:
    /// what to decompress beside it.
    files: []const []const u8,
};

/// modules resolves words, the leaf modules a stage0 loads (`NAME`, or
/// `@TAG:NAME` for a machine stage0 tags TAG), against modules.dep. Each
/// leaf brings its line of modules.dep back to front, a load order. A
/// module is listed once untagged; a tagged one only if no untagged leaf
/// needs it, once per tag. A module's params go on its first line.
/// It refuses an empty words and words that lack one of native, since
/// every stage0 loads what werewolf's own does; on error, bad names the
/// module at fault.
pub fn modules(
    gpa: Allocator,
    dep: []const u8,
    words: []const []const u8,
    native: []const []const u8,
    params: []const Param,
    bad: *[]const u8,
) !Modules {
    if (words.len == 0) return error.NoModules;
    for (native) |n| if (!contains(words, n)) {
        bad.* = n;
        return error.NativeModuleMissing;
    };

    // Every leaf's line back to front, tagged as its leaf is.
    var all: std.ArrayList(Mod) = .empty;
    for (words) |w| {
        const tagged = w.len > 0 and w[0] == '@';
        const colon = mem.findScalar(u8, w, ':');
        const tag = if (tagged) w[0 .. colon orelse w.len] else "";
        const name = if (tagged and colon != null) w[colon.? + 1 ..] else w;
        const suffix = try gpa.print("/{s}.ko.gz:", .{name});
        var found = false;
        var lines = mem.splitScalar(u8, dep, '\n');
        while (lines.next()) |line| {
            var fields: std.ArrayList([]const u8) = .empty;
            var it = mem.tokenizeAny(u8, line, " \t");
            while (it.next()) |f| try fields.append(gpa, f);
            if (fields.items.len == 0 or !mem.endsWith(u8, fields.items[0], suffix)) continue;
            found = true;
            fields.items[0] = fields.items[0][0 .. fields.items[0].len - 1];
            var i = fields.items.len;
            while (i > 0) {
                i -= 1;
                try all.append(gpa, .{ .tag = tag, .path = fields.items[i] });
            }
        }
        if (!found) {
            bad.* = name;
            return error.ModuleNotFound;
        }
    }

    // Untagged modules once; a tagged one only where nothing untagged
    // loads it, once per tag.
    var base: std.array_hash_map.String(void) = .empty;
    for (all.items) |m| if (m.tag.len == 0) try base.put(gpa, m.path, {});
    var seen: std.array_hash_map.String(void) = .empty;
    var kept: std.ArrayList(Mod) = .empty;
    for (all.items) |m| {
        if (m.tag.len > 0 and base.contains(m.path)) continue;
        const key = try gpa.print("{s} {s}", .{ m.tag, m.path });
        if ((try seen.getOrPut(gpa, key)).found_existing) continue;
        try kept.append(gpa, m);
    }

    var want: std.array_hash_map.String([]const u8) = .empty;
    for (params) |p| {
        const r = try want.getOrPut(gpa, p.module);
        r.value_ptr.* = try gpa.print(
            "{s} {s}",
            .{ if (r.found_existing) r.value_ptr.* else "", p.value },
        );
    }
    var list: std.ArrayList(u8) = .empty;
    var files: std.array_hash_map.String(void) = .empty;
    for (kept.items) |m| {
        const path = if (mem.endsWith(u8, m.path, ".gz")) m.path[0 .. m.path.len - 3] else m.path;
        if (m.tag.len > 0) try list.print(gpa, "{s} ", .{m.tag});
        try list.appendSlice(gpa, path);
        const stem = std.fs.path.basename(path);
        const name = if (mem.endsWith(u8, stem, ".ko")) stem[0 .. stem.len - 3] else stem;
        if (want.fetchSwapRemove(name)) |p| try list.appendSlice(gpa, p.value);
        try list.append(gpa, '\n');
        try files.put(gpa, m.path, {});
    }
    if (want.count() > 0) {
        bad.* = want.keys()[0];
        return error.ParamsForMissingModule;
    }
    const sorted = files.keys();
    mem.sortUnstable([]const u8, sorted, {}, lessThan);
    return .{ .list = list.items, .files = sorted };
}

/// Mod is one line of a load order: a modules.dep path, and the tag
/// (`@xfs`) of the leaf that brought it, or "".
const Mod = struct { tag: []const u8, path: []const u8 };

fn contains(set: []const []const u8, s: []const u8) bool {
    for (set) |x| if (mem.eql(u8, x, s)) return true;
    return false;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return mem.lessThan(u8, a, b);
}

/// max_gunzip bounds what gunzip inflates: the kernel's Image is 40 MB.
pub const max_gunzip = 256 << 20;

/// gunzip inflates the first gzip member of data, as the kernel's modules
/// and payloads are one member each. It refuses more than max_gunzip bytes.
pub fn gunzip(gpa: Allocator, data: []const u8) ![]u8 {
    var in: std.Io.Reader = .fixed(data);
    var gz: std.compress.flate.Decompress = .init(&in, .gzip, &.{});
    return gz.reader.allocRemaining(gpa, .limited(max_gunzip)) catch |err| switch (err) {
        error.ReadFailed => return gz.err orelse error.ReadFailed,
        else => return err,
    };
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
/// header gives the setup sectors at 0x1f1 (0 means 4), then the gzipped
/// payload's offset past the setup and its length, u32s at 0x248 and 0x24c.
pub fn vmlinux(gpa: Allocator, bzimage: []const u8) ![]const u8 {
    if (bzimage.len < 0x250) return error.BadBzImage;
    const sects: u64 = if (bzimage[0x1f1] == 0) 4 else bzimage[0x1f1];
    const start = (sects + 1) * 512 + mem.readInt(u32, bzimage[0x248..0x24c], .little);
    const len = mem.readInt(u32, bzimage[0x24c..0x250], .little);
    if (start + len > bzimage.len) return error.BadBzImage;
    const elf = try gunzip(gpa, bzimage[start..][0..len]);
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
    /// not_built_in allows a module or off. The machine never loads the
    /// module, and cannot once modload closes the loader.
    not_built_in,
    /// off means left out entirely.
    off,

    fn holds(want: Want, v: []const u8) bool {
        return switch (want) {
            .yes => mem.eql(u8, v, "y"),
            .not_built_in => !mem.eql(u8, v, "y"),
            .off => v.len == 0,
        };
    }

    fn text(want: Want) []const u8 {
        return switch (want) {
            .yes => "built in",
            .not_built_in => "a module or off",
            .off => "off",
        };
    }
};

/// config_rules are what werewolf relies on Alpine's kernel config to
/// leave out, or keep in: built in, code the module loader keeps out today
/// would be in every machine. Each names what it closes.
const config_rules = [_]struct { []const u8, Want, []const u8 }{
    .{ "CONFIG_CRYPTO_USER_API", .not_built_in, "AF_ALG: CVE-2025-39964, CVE-2026-31431" },
    .{ "CONFIG_CRYPTO_USER_API_AEAD", .not_built_in, "AF_ALG: CVE-2026-31431" },
    .{ "CONFIG_CRYPTO_USER_API_SKCIPHER", .not_built_in, "AF_ALG" },
    .{ "CONFIG_CRYPTO_USER_API_HASH", .not_built_in, "AF_ALG" },
    .{ "CONFIG_CRYPTO_USER_API_RNG", .not_built_in, "AF_ALG" },
    .{ "CONFIG_TLS", .not_built_in, "kernel TLS: CVE-2025-39682" },
    .{ "CONFIG_BRIDGE_NF_EBTABLES", .not_built_in, "ebtables: CVE-2026-53266" },
    .{ "CONFIG_NF_TABLES", .not_built_in, "nf_tables: CVE-2022-2586, CVE-2024-1086" },
    .{ "CONFIG_NETFILTER_XTABLES", .not_built_in, "x_tables: CVE-2021-22555" },
    .{ "CONFIG_OVERLAY_FS", .not_built_in, "overlayfs: CVE-2023-0386" },
    .{ "CONFIG_HID", .not_built_in, "HID: CVE-2024-50302" },
    .{ "CONFIG_USB", .not_built_in, "USB: CVE-2024-53150, CVE-2024-53197, CVE-2024-53104" },
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

test modules {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const dep =
        \\kernel/fs/ext4/ext4.ko.gz: kernel/lib/crc/crc16.ko.gz kernel/fs/mbcache.ko.gz kernel/fs/jbd2/jbd2.ko.gz
        \\kernel/fs/xfs/xfs.ko.gz: kernel/lib/crc/crc16.ko.gz kernel/fs/xfs/libxfs.ko.gz
        \\kernel/fs/jbd2/jbd2.ko.gz:
        \\kernel/fs/btrfs/btrfs.ko.gz: kernel/lib/raid6/raid6_pq.ko.gz kernel/lib/xor.ko.gz
        \\kernel/lib/raid6/raid6_pq.ko.gz:
        \\kernel/lib/xor.ko.gz:
        \\kernel/fs/zfs/zfs.ko.gz: kernel/lib/raid6/raid6_pq.ko.gz
        \\kernel/arch/x86/kvm/kvm-intel.ko.gz: kernel/arch/x86/kvm/kvm.ko.gz
        \\kernel/arch/x86/kvm/kvm.ko.gz:
        \\
    ;
    var bad: []const u8 = "";
    // Tagged and untagged leaves mixed: the chain's order stays. xfs's
    // crc16 is ext4's too, so it stays untagged; raid6_pq, which two tags
    // need, is listed under each; jbd2, named again, is listed once.
    const words = [_][]const u8{ "@xfs:xfs", "ext4", "@btrfs:btrfs", "jbd2", "@zfs:zfs" };
    const m = try modules(a, dep, &words, &.{ "ext4", "jbd2" }, &.{}, &bad);
    try testing.expectEqualStrings(
        \\@xfs kernel/fs/xfs/libxfs.ko
        \\@xfs kernel/fs/xfs/xfs.ko
        \\kernel/fs/jbd2/jbd2.ko
        \\kernel/fs/mbcache.ko
        \\kernel/lib/crc/crc16.ko
        \\kernel/fs/ext4/ext4.ko
        \\@btrfs kernel/lib/xor.ko
        \\@btrfs kernel/lib/raid6/raid6_pq.ko
        \\@btrfs kernel/fs/btrfs/btrfs.ko
        \\@zfs kernel/lib/raid6/raid6_pq.ko
        \\@zfs kernel/fs/zfs/zfs.ko
        \\
    , m.list);
    try testing.expectEqual(10, m.files.len);
    try testing.expectEqualStrings("kernel/fs/btrfs/btrfs.ko.gz", m.files[0]);
    try testing.expectEqualStrings("kernel/lib/xor.ko.gz", m.files[9]);

    // Parameters go on the module's first line, in order.
    const kvm = try modules(a, dep, &.{"kvm-intel"}, &.{}, &.{
        .{ .module = "kvm-intel", .value = "nested=0" },
        .{ .module = "kvm-intel", .value = "ept=1" },
    }, &bad);
    try testing.expectEqualStrings(
        "kernel/arch/x86/kvm/kvm.ko\nkernel/arch/x86/kvm/kvm-intel.ko nested=0 ept=1\n",
        kvm.list,
    );

    try testing.expectError(error.NoModules, modules(a, dep, &.{}, &.{}, &.{}, &bad));
    try testing.expectError(
        error.NativeModuleMissing,
        modules(a, dep, &.{"@xfs:xfs"}, &.{"ext4"}, &.{}, &bad),
    );
    try testing.expectEqualStrings("ext4", bad);
    try testing.expectError(error.ModuleNotFound, modules(a, dep, &.{"f2fs"}, &.{}, &.{}, &bad));
    try testing.expectEqualStrings("f2fs", bad);
    try testing.expectError(error.ModuleNotFound, modules(a, dep, &.{"crc"}, &.{}, &.{}, &bad));
    try testing.expectError(error.ParamsForMissingModule, modules(a, dep, &.{"ext4"}, &.{}, &.{
        .{ .module = "kvm-amd", .value = "nested=0" },
    }, &bad));
    try testing.expectEqualStrings("kvm-amd", bad);
}

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
        \\CONFIG_TLS=m
        \\# CONFIG_WATCH_QUEUE is not set
        \\CONFIG_TLS_DEVICE=y
        \\CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y
        \\CONFIG_LSM="landlock,lockdown"
        \\CONFIG_AUDIT=y
        \\CONFIG_AUDITSYSCALL=y
        \\CONFIG_HID=y
    ;
    try testing.expectEqualStrings("m", configValue(config, "CONFIG_TLS"));
    try testing.expectEqualStrings("", configValue(config, "CONFIG_WATCH_QUEUE"));
    try testing.expectEqualStrings("\"landlock,lockdown\"", configValue(config, "CONFIG_LSM"));
    const misses = try configMisses(testing.allocator, config);
    defer testing.allocator.free(misses);
    try testing.expectEqual(1, misses.len);
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "CONFIG_HID is y, werewolf needs it a module or off (HID: CVE-2024-50302)",
        try std.mem.print(&buf, "{f}", .{misses[0]}),
    );
    try testing.expect(Want.not_built_in.holds(""));
    try testing.expect(!Want.off.holds("m"));
    try testing.expect(!Want.yes.holds("m"));
}
