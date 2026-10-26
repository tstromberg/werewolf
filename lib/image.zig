//! image holds the steps of making a slot that the build host and the
//! updater share: gunzip, the kernel unwraps, the kernel config check,
//! the program check and mkfs.erofs's options. See lib/README.md.

const std = @import("std");
const Allocator = std.mem.Allocator;
const mem = std.mem;

/// Remove package-provided account switching before form overlays. ssh-su
/// may then install its unprivileged replacement at the same path.
pub const package_prune = [_][]const u8{ "usr/bin/su", "bin/su" };

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
/// clusters and small files packed together, which boots fastest
/// (Makefile, root.erofs). Not dedupe, which keeps mkfs.erofs to one
/// thread: Overleaf's root took 7 times as long, to save 0.5% of it.
/// 4 KiB blocks, since mkfs.erofs otherwise takes the builder's page size,
/// 16 KiB on Apple silicon, which a 4 KiB-page kernel will not mount.
pub const erofs_options = [_][]const u8{
    "-b",
    "4096",
    "-zzstd,level=9",
    "-C65536",
    "-Eall-fragments",
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
    .{ "CONFIG_TCG_TPM", .yes, "stage0 holds each release to its TPM floor (lib/tpm.zig)" },
    .{ "CONFIG_TCG_TIS", .yes, "the TIS-interface TPMs QEMU, Lima and clouds give" },
    .{ "CONFIG_TCG_CRB", .yes, "the CRB-interface TPMs clouds give" },
    .{ "CONFIG_SERIAL_8250_PCI", .yes, "AWS Graviton's console is a PCI 16550 (1d0f:8250)" },
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

/// ElfProblem is what a root refuses in a program built for its machine.
pub const ElfProblem = enum {
    /// fixed_address is an executable linked to load at one address
    /// (ET_EXEC), whose code and data ASLR cannot move.
    fixed_address,
    /// executable_stack asks the kernel for a stack code can run from.
    executable_stack,
    /// unreadable_headers puts the program headers past elf_head_len, where
    /// no linker does, so neither of the others can be ruled out.
    unreadable_headers,

    pub fn text(p: ElfProblem) []const u8 {
        return switch (p) {
            .fixed_address => "loads at a fixed address, which ASLR cannot move " ++
                "(build it as a PIE: -buildmode=pie, -fPIE, -pie)",
            .executable_stack => "asks for an executable stack",
            .unreadable_headers => "has its program headers too far in to check",
        };
    }
};

/// elf_head_len is how much of a file judgeElf needs: the ELF header and
/// the program headers every linker puts right after it.
pub const elf_head_len = 4096;

/// judgeElf returns what a root refuses in a file, given its first
/// elf_head_len bytes, or null. It judges only a 64-bit little-endian ELF
/// executable or shared object for machine. Other files pass, and so do
/// other machines' ELF files, such as the firmware QEMU loads into guests.
pub fn judgeElf(head: []const u8, machine: std.elf.EM) ?ElfProblem {
    if (head.len < 64 or !mem.startsWith(u8, head, "\x7fELF\x02\x01")) return null;
    if (mem.readInt(u16, head[18..20], .little) != @backingInt(machine)) return null;
    const exec = switch (mem.readInt(u16, head[16..18], .little)) {
        @backingInt(std.elf.ET.EXEC) => true,
        @backingInt(std.elf.ET.DYN) => false,
        else => return null,
    };
    const phoff = mem.readInt(u64, head[32..40], .little);
    const phentsize = mem.readInt(u16, head[54..56], .little);
    const phnum = mem.readInt(u16, head[56..58], .little);
    if (phentsize < 8 or phoff > head.len or phnum > (head.len - phoff) / phentsize)
        return .unreadable_headers;
    for (0..phnum) |i| {
        const ph = head[@intCast(phoff + i * phentsize)..][0..8];
        if (mem.readInt(u32, ph[0..4], .little) == @backingInt(std.elf.PT.GNU_STACK) and
            mem.readInt(u32, ph[4..8], .little) & std.elf.PF_X != 0) return .executable_stack;
    }
    return if (exec) .fixed_address else null;
}

/// ElfException is a program a root may hold at a fixed address, and why.
pub const ElfException = struct {
    /// path is where the root holds it, without a leading slash.
    path: []const u8,
    why: []const u8,
    /// form limits it to one form's root, for an application's path.
    form: ?[]const u8 = null,
    /// machine limits it to one architecture.
    machine: ?std.elf.EM = null,
};

const wolfi_go = "Wolfi builds Go programs without -buildmode=pie";
const upstream_binary = "upstream's own release binary, which ../packages fetches as it is";
const typescript = "TypeScript's prebuilt compiler, from npm, among n8n's dependencies";

/// elf_exceptions are the fixed-address programs forms take today. A new
/// one fails the build until it is a PIE or listed here with its reason.
pub const elf_exceptions = [_]ElfException{
    .{ .path = "usr/bin/runit", .why = "Wolfi's static runit supervises; it reads no one's input" },
    .{ .path = "usr/bin/runit-init", .why = "Wolfi's static runit, as runit's PID 1 handoff" },
    .{ .path = "usr/bin/cloudflared", .why = wolfi_go },
    .{ .path = "usr/bin/gatus", .why = wolfi_go },
    .{ .path = "usr/bin/gitea", .why = wolfi_go },
    .{ .path = "usr/bin/grype", .why = wolfi_go },
    .{ .path = "usr/bin/loki", .why = wolfi_go },
    .{ .path = "usr/bin/minio", .why = wolfi_go },
    .{ .path = "usr/bin/nats-server", .why = wolfi_go },
    .{ .path = "usr/bin/oauth2-proxy", .why = wolfi_go },
    .{ .path = "usr/bin/ollama", .why = wolfi_go },
    .{ .path = "usr/bin/bao", .why = wolfi_go },
    .{ .path = "usr/bin/otelcol-contrib", .why = wolfi_go },
    .{ .path = "usr/bin/prometheus", .why = wolfi_go },
    .{ .path = "usr/bin/promtool", .why = wolfi_go },
    .{ .path = "usr/bin/sftpgo", .why = wolfi_go },
    .{ .path = "usr/bin/step-ca", .why = wolfi_go },
    .{ .path = "usr/bin/supercronic", .why = wolfi_go },
    .{ .path = "usr/bin/containerboot", .why = wolfi_go },
    .{ .path = "usr/bin/tailscale", .why = wolfi_go },
    .{ .path = "usr/bin/tailscaled", .why = wolfi_go },
    .{ .path = "usr/bin/velociraptor", .why = upstream_binary },
    .{ .path = "usr/lib/mattermost/bin/mattermost", .why = upstream_binary },
    .{
        .path = "usr/lib/n8n/node_modules/@typescript/typescript-linux-arm64/lib/tsc",
        .machine = .AARCH64,
        .why = typescript,
    },
    .{
        .path = "usr/lib/n8n/node_modules/@typescript/typescript-linux-x64/lib/tsc",
        .machine = .X86_64,
        .why = typescript,
    },
    .{
        .path = "usr/lib/app/server",
        .form = "rust-example",
        .machine = .AARCH64,
        .why = "rustc's aarch64-unknown-linux-musl target links no static PIE",
    },
};

/// elfExcused returns why form's root may hold path at a fixed address on
/// machine, or null. Nothing excuses the other problems.
pub fn elfExcused(path: []const u8, form: []const u8, machine: std.elf.EM) ?[]const u8 {
    for (elf_exceptions) |e| {
        if (!mem.eql(u8, e.path, path)) continue;
        if (e.form) |f| if (!mem.eql(u8, f, form)) continue;
        if (e.machine) |m| if (m != machine) continue;
        return e.why;
    }
    return null;
}

/// OCI programs retain their publisher's build, including the copy staged
/// for the updater. Native files elsewhere in a staged form are still checked.
pub fn isOciPath(path: []const u8) bool {
    if (mem.startsWith(u8, path, "oci/")) return true;
    const staged = mem.cutPrefix(u8, path, "usr/share/werewolf/forms/") orelse return false;
    const end = mem.findScalar(u8, staged, '/') orelse return false;
    return end > 0 and mem.startsWith(u8, staged[end..], "/rootfs/oci/");
}

/// Stripped is a file or directory whose setuid or setgid bit stripSetid
/// removed, and its mode before.
pub const Stripped = struct { name: []const u8, mode: u32 };

/// stripSetid removes the setuid and setgid bits from every file and
/// directory in a root's tar, in place, as the updater does to the root it
/// builds (cmd/slot-update/slot.zig): no program runs with more than its
/// caller's privilege, whatever a package ships, and on a nosuid mount or
/// not. A hard link needs nothing: mkfs.erofs gives it its target's inode.
pub fn stripSetid(gpa: Allocator, io: std.Io, file: std.Io.File) ![]Stripped {
    var buf: [64 << 10]u8 = undefined;
    var r = file.reader(io, &buf);
    var name_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var link_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    // Hard links and device nodes come back as diagnostics, skipped.
    var skipped: std.tar.Diagnostics = .{ .allocator = gpa };
    defer skipped.deinit();
    var it: std.tar.Iterator = .init(&r.interface, .{
        .file_name_buffer = &name_buf,
        .link_name_buffer = &link_buf,
        .diagnostics = &skipped,
    });
    var stripped: std.ArrayList(Stripped) = .empty;
    while (try it.next()) |e| {
        if (e.kind == .sym_link or e.mode & 0o6000 == 0) continue;
        // next has read the entry's header, which it checksummed, and
        // nothing past it.
        const at = r.logicalPos() - 512;
        var h: [512]u8 = undefined;
        if (try file.readPositionalAll(io, &h, at) != h.len) return error.TarHeader;
        const mode = try octalDigits(h[100..108]);
        if (try std.fmt.parseInt(u32, mode, 8) != e.mode) return error.TarHeader;
        writeOctal(mode, e.mode & ~@as(u32, 0o6000));
        // The checksum counts its own field as spaces.
        const field = h[148..156].*;
        @memset(h[148..156], ' ');
        var sum: u64 = 0;
        for (h) |c| sum += c;
        h[148..156].* = field;
        const checksum = try octalDigits(h[148..156]);
        if (sum >> @intCast(3 * checksum.len) != 0) return error.TarHeader;
        writeOctal(checksum, sum);
        try file.writePositionalAll(io, &h, at);
        try stripped.append(gpa, .{ .name = try gpa.dupe(u8, e.name), .mode = e.mode });
    }
    return stripped.toOwnedSlice(gpa);
}

/// octalDigits is the run of octal digits in a tar header field, inside
/// the padding its writer chose: libarchive's "000755 \0", Zig's
/// "0000755\0". Rewriting it at its width keeps the header as written.
fn octalDigits(field: []u8) ![]u8 {
    const start = mem.findNone(u8, field, " ") orelse return error.TarHeader;
    const end = mem.findNonePos(u8, field, start, "01234567") orelse field.len;
    if (start == end) return error.TarHeader;
    return field[start..end];
}

/// writeOctal fills out with value's octal digits, zero-padded. The caller
/// checks value fits.
fn writeOctal(out: []u8, value: u64) void {
    var v = value;
    var i = out.len;
    while (i > 0) : (v >>= 3) {
        i -= 1;
        out[i] = '0' + @as(u8, @intCast(v & 7));
    }
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

/// testElf returns the head of an ELF file of type and machine with one
/// PT_GNU_STACK program header of flags, as linkers lay one out.
fn testElf(@"type": std.elf.ET, machine: std.elf.EM, stack_flags: u32) [64 + 56]u8 {
    var h: [64 + 56]u8 = @splat(0);
    @memcpy(h[0..6], "\x7fELF\x02\x01");
    mem.writeInt(u16, h[16..18], @backingInt(@"type"), .little);
    mem.writeInt(u16, h[18..20], @backingInt(machine), .little);
    mem.writeInt(u64, h[32..40], 64, .little); // e_phoff
    mem.writeInt(u16, h[54..56], 56, .little); // e_phentsize
    mem.writeInt(u16, h[56..58], 1, .little); // e_phnum
    mem.writeInt(u32, h[64..68], @backingInt(std.elf.PT.GNU_STACK), .little);
    mem.writeInt(u32, h[68..72], stack_flags, .little);
    return h;
}

test judgeElf {
    const rw = std.elf.PF_R | std.elf.PF_W;
    const pie = testElf(.DYN, .AARCH64, rw);
    try testing.expectEqual(null, judgeElf(&pie, .AARCH64));
    const exe = testElf(.EXEC, .AARCH64, rw);
    try testing.expectEqual(.fixed_address, judgeElf(&exe, .AARCH64));
    try testing.expectEqual(.fixed_address, judgeElf(&testElf(.EXEC, .X86_64, rw), .X86_64));
    // A fixed address is excusable, so an executable stack is found first.
    const rwx = rw | std.elf.PF_X;
    try testing.expectEqual(.executable_stack, judgeElf(&testElf(.EXEC, .AARCH64, rwx), .AARCH64));
    try testing.expectEqual(.executable_stack, judgeElf(&testElf(.DYN, .AARCH64, rwx), .AARCH64));
    // Another machine's firmware, an object file and a script are not programs here.
    try testing.expectEqual(null, judgeElf(&testElf(.EXEC, .ALPHA, rw), .AARCH64));
    try testing.expectEqual(null, judgeElf(&testElf(.EXEC, .X86_64, rw), .AARCH64));
    try testing.expectEqual(null, judgeElf(&testElf(.REL, .AARCH64, rw), .AARCH64));
    try testing.expectEqual(null, judgeElf("#!/bin/sh\necho not elf\n", .AARCH64));
    try testing.expectEqual(null, judgeElf(exe[0..63], .AARCH64));
    var far = pie;
    mem.writeInt(u64, far[32..40], elf_head_len, .little);
    try testing.expectEqual(.unreadable_headers, judgeElf(&far, .AARCH64));
    // Headers that would run past the bytes read are not read.
    try testing.expectEqual(.unreadable_headers, judgeElf(pie[0..100], .AARCH64));
}

test elfExcused {
    try testing.expect(elfExcused("usr/bin/runit", "minimal", .X86_64) != null);
    try testing.expectEqual(null, elfExcused("usr/bin/runitx", "minimal", .X86_64));
    try testing.expectEqual(null, elfExcused("/usr/bin/runit", "minimal", .X86_64));
    try testing.expect(elfExcused("usr/lib/app/server", "rust-example", .AARCH64) != null);
    try testing.expectEqual(null, elfExcused("usr/lib/app/server", "rust-example", .X86_64));
    try testing.expectEqual(null, elfExcused("usr/lib/app/server", "go-example", .AARCH64));
}

test "OCI trees include staged copies, not native form files" {
    for ([_][]const u8{
        "oci/dns/usr/bin/server",
        "usr/share/werewolf/forms/dns/rootfs/oci/dns/usr/bin/server",
    }) |path| try testing.expect(isOciPath(path));
    for ([_][]const u8{
        "usr/bin/server",
        "usr/share/werewolf/forms/dns/rootfs/usr/bin/server",
        "usr/share/werewolf/forms/dns/rootfs/oci-other/server",
        "usr/share/werewolf/forms/dns/oci/server",
        "usr/share/werewolf/forms//rootfs/oci/server",
    }) |path| try testing.expect(!isOciPath(path));
}

test stripSetid {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // Past ustar's name and prefix, so a long-name entry precedes its header.
    const long = "usr/lib/" ++ &@as([250]u8, @splat('x')) ++ "/helper";
    {
        const f = try tmp.dir.createFile(io, "root.tar", .{});
        defer f.close(io);
        var wbuf: [4096]u8 = undefined;
        var fw = f.writer(io, &wbuf);
        var w: std.tar.Writer = .{ .underlying_writer = &fw.interface };
        try w.writeDir("usr/share/group", .{ .mode = 0o2775 });
        try w.writeFileBytes("usr/bin/unix_chkpwd", "pam", .{ .mode = 0o2755 });
        try w.writeFileBytes(long, "setuid", .{ .mode = 0o4755 });
        try w.writeFileBytes("usr/bin/plain", "plain", .{ .mode = 0o755 });
        try w.writeLink("usr/bin/link", "unix_chkpwd", .{});
        try w.finishPedantically();
        try fw.interface.flush();
    }
    // libarchive pads its octal fields otherwise: "000755 \0".
    var padded = "002755 \x00".*;
    try testing.expectEqualStrings("002755", try octalDigits(&padded));
    var blank = "       \x00".*;
    try testing.expectError(error.TarHeader, octalDigits(&blank));

    const f = try tmp.dir.openFile(io, "root.tar", .{ .mode = .read_write });
    defer f.close(io);
    const stripped = try stripSetid(gpa, io, f);
    defer {
        for (stripped) |s| gpa.free(s.name);
        gpa.free(stripped);
    }
    try testing.expectEqual(3, stripped.len);
    try testing.expectEqualStrings("usr/share/group", stripped[0].name);
    try testing.expectEqual(0o2775, stripped[0].mode);
    try testing.expectEqualStrings("usr/bin/unix_chkpwd", stripped[1].name);
    try testing.expectEqualStrings(long, stripped[2].name);
    try testing.expectEqual(0o4755, stripped[2].mode);
    // Read back, checksums and all: each mode without the bits, contents
    // as they were. A second pass finds nothing.
    var rbuf: [4096]u8 = undefined;
    var r = f.reader(io, &rbuf);
    var name_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var link_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(
        &r.interface,
        .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
    );
    const want = [_]struct { []const u8, u32 }{
        .{ "usr/share/group", 0o775 }, .{ "usr/bin/unix_chkpwd", 0o755 },
        .{ long, 0o755 },              .{ "usr/bin/plain", 0o755 },
        .{ "usr/bin/link", 0o777 },
    };
    for (want) |w| {
        const e = (try it.next()).?;
        try testing.expectEqualStrings(w[0], e.name);
        try testing.expectEqual(w[1], e.mode);
        if (mem.eql(u8, w[0], "usr/bin/unix_chkpwd")) {
            var data: [3]u8 = undefined;
            try it.reader.readSliceAll(&data);
            it.unread_file_bytes = 0;
            try testing.expectEqualStrings("pam", &data);
        }
    }
    try testing.expectEqual(null, try it.next());
    const again = try stripSetid(gpa, io, f);
    defer gpa.free(again);
    try testing.expectEqual(0, again.len);
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
        \\CONFIG_TCG_TPM=y
        \\CONFIG_TCG_TIS=y
        \\CONFIG_TCG_CRB=y
        \\CONFIG_SERIAL_8250_PCI=y
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
