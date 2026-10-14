//! Signed, immutable slot bundles. Nothing is unpacked on the machine.
const std = @import("std");
const apk = @import("apk");
const policy = @import("update-policy");
const mem = std.mem;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const format = "werewolf-image/1";
pub const metadata = "/usr/share/werewolf/image-update";
pub const max_manifest = 1 << 20;
pub const max_artifact: u64 = 8 << 30;
pub const Package = struct { name: []const u8, version: []const u8, origin: []const u8 };
pub const Artifact = struct { sha256: []const u8, size: u64 };
pub const Files = struct {
    vmlinuz: Artifact,
    @"root.erofs": Artifact,
    @"stage0.zst": Artifact,
    cmdline: Artifact,
    @"uki.efi": ?Artifact = null,
};
pub const names = [_][]const u8{
    "vmlinuz",
    "root.erofs",
    "stage0.zst",
    "cmdline",
    "uki.efi",
};
pub const Manifest = struct {
    format: []const u8,
    channel: []const u8,
    arch: []const u8,
    serial: []const u8,
    build: []const u8,
    ipe: bool,
    root_hash: []const u8,
    kernel: []const u8,
    packages: []const Package,
    advisories: []const policy.Advisory = &.{},
    declaration: ?[]const u8 = null,
    boot_context: ?[]const u8 = null,
    files: Files,

    pub fn artifact(m: Manifest, name: []const u8) ?Artifact {
        inline for (names) |n| if (mem.eql(u8, name, n)) return @field(m.files, n);
        return null;
    }
};
pub const Floor = struct { serial: []const u8, build: []const u8 };
pub const Identity = struct { channel: []const u8, arch: []const u8 };

/// Authenticate bytes before JSON parsing. A signature authorizes a whole
/// bundle only for the channel and architecture enrolled in the running root.
pub fn open(
    gpa: mem.Allocator,
    key: apk.Key,
    data: []const u8,
    sig: []const u8,
    identity: Identity,
) !Manifest {
    if (data.len > max_manifest or sig.len > 8192) return error.ImageTooBig;
    try apk.verify(key, data, sig);
    const m = try std.json.parseFromSliceLeaky(
        Manifest,
        gpa,
        data,
        .{ .ignore_unknown_fields = false },
    );
    try check(m, identity);
    return m;
}

pub fn check(m: Manifest, identity: Identity) !void {
    if (!mem.eql(u8, m.format, format) or !m.ipe) return error.NotAnIpeImage;
    try channel(m.channel);
    if (!mem.eql(u8, m.channel, identity.channel)) return error.WrongImageChannel;
    if (!mem.eql(u8, m.arch, identity.arch) or
        (!mem.eql(u8, m.arch, "aarch64") and
            !mem.eql(u8, m.arch, "x86_64"))) return error.WrongImageArch;
    _ = policy.parseSerial(m.serial) catch return error.BadImageSerial;
    if (!hex(m.root_hash) or !hex(m.build)) return error.BadImageHash;
    if (m.declaration) |d| if (!hex(d)) return error.BadImageHash;
    if (m.boot_context) |c| if (!hex(c) or m.files.@"uki.efi" == null)
        return error.BadImageBootContext;
    if (m.kernel.len == 0 or m.kernel.len > 256 or
        !printable(m.kernel)) return error.BadImageKernel;
    inline for (names) |n| if (m.artifact(n)) |a| {
        if (!hex(a.sha256) or a.size == 0 or a.size > max_artifact) return error.BadImageArtifact;
        if (mem.eql(u8, n, "cmdline") and a.size > 4096) return error.BadImageArtifact;
    };
    if (!mem.eql(u8, m.build, &buildId(m.files))) return error.BadImageBuild;
    if (m.packages.len == 0 or m.packages.len > 16384 or
        m.advisories.len > 4096) return error.BadImagePackages;
    for (m.packages, 0..) |p, i| {
        for ([_][]const u8{ p.name, p.version, p.origin }) |s|
            if (s.len == 0 or s.len > 256 or !printable(s)) return error.BadImagePackages;
        if (i > 0 and
            mem.order(u8, m.packages[i - 1].name, p.name) != .lt) return error.BadImagePackages;
    }
    for (m.advisories) |a| {
        if (a.id.len == 0 or a.id.len > 256 or a.title.len > 4096 or !printable(a.id) or
            a.date.len != 10)
            return error.BadImageAdvisory;
        for (a.title) |c| if (c < ' ' or c > '~') return error.BadImageAdvisory;
        var date: [20]u8 = undefined;
        _ = policy.parseTime(std.mem.print(
            &date,
            "{s}T00:00:00Z",
            .{a.date},
        ) catch unreachable) catch return error.BadImageAdvisory;
    }
}

/// Release time is persistent state, not a TPM counter. Equal serials must
/// identify identical files; the running root's own serial is the initial floor.
pub fn freshness(
    m: Manifest,
    minimum: []const u8,
    current_root: [32]u8,
    floor: ?Floor,
    now: i64,
) !void {
    const serial = policy.parseSerial(m.serial) catch return error.BadImageSerial;
    _ = policy.parseSerial(minimum) catch return error.BadImageSerial;
    if (serial > now + policy.day) return error.FutureImage;
    if (mem.order(u8, m.serial, minimum) == .lt) return error.OlderImage;
    if (mem.eql(u8, m.serial, minimum) and
        !mem.eql(u8, m.root_hash, &std.fmt.bytesToHex(current_root, .lower)))
        return error.ImageSerialReused;
    if (floor) |f| {
        _ = policy.parseSerial(f.serial) catch return error.BadImageFloor;
        if (!hex(f.build)) return error.BadImageFloor;
        switch (mem.order(u8, m.serial, f.serial)) {
            .lt => return error.OlderImage,
            .eq => if (!mem.eql(u8, m.build, f.build)) return error.ImageSerialReused,
            .gt => {},
        }
    }
}

pub fn buildId(files: Files) [64]u8 {
    var h = Sha256.init(.{});
    inline for (names) |n| {
        const a: ?Artifact = @field(files, n);
        if (a) |f| {
            h.update(n);
            h.update(" ");
            h.update(f.sha256);
            var buf: [32]u8 = undefined;
            h.update(std.mem.print(&buf, " {d}\n", .{f.size}) catch unreachable);
        }
    }
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

pub fn matches(a: Artifact, size: u64, digest: []const u8) !void {
    if (a.size != size or !mem.eql(u8, a.sha256, digest)) return error.ImageArtifactMismatch;
}

pub fn hashFile(io: std.Io, gpa: mem.Allocator, path: []const u8) !Artifact {
    const f = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    var h = Sha256.init(.{});
    var buf: [64 << 10]u8 = undefined;
    var size: u64 = 0;
    while (true) {
        const n = try f.readPositionalAll(io, &buf, size);
        if (n == 0) break;
        h.update(buf[0..n]);
        size += n;
        if (size > max_artifact) return error.ImageTooBig;
    }
    return .{
        .sha256 = try gpa.dupe(u8, &std.fmt.bytesToHex(h.finalResult(), .lower)),
        .size = size,
    };
}

/// Keep URLs free of credentials, queries and traversal. The publisher
/// uploads ARCH/BUILD/NAME first, then ARCH/latest.json and its signature.
pub fn channel(url: []const u8) !void {
    if (!mem.startsWith(u8, url, "https://") or url.len > 2048 or mem.endsWith(u8, url, "/"))
        return error.BadImageChannel;
    const uri = std.Uri.parse(url) catch return error.BadImageChannel;
    if (uri.host == null or uri.user != null or uri.password != null or uri.query != null or
        uri.fragment != null)
        return error.BadImageChannel;
    if (uri.port == 0) return error.BadImageChannel;
    for (url) |c| if (!std.ascii.isAlphanumeric(c) and mem.indexOfScalar(u8, "-._:/[]", c) == null)
        return error.BadImageChannel;
    var parts = mem.splitScalar(u8, url["https://".len..], '/');
    while (parts.next()) |p| if (mem.eql(u8, p, ".") or mem.eql(u8, p, "..") or p.len == 0)
        return error.BadImageChannel;
}

pub fn cmdline(text: []const u8) ![]const u8 {
    const line = mem.trimEnd(u8, text, "\n");
    if (line.len > 4096) return error.BadCmdline;
    for (line) |c| if (c < ' ' or c > '~' or c == '\\') return error.BadCmdline;
    return line;
}

/// loaderEntry returns a Boot Loader Specification type 1 entry for slot.
/// version orders the slots, newest first; sort-key groups them. A UKI must
/// use `uki`: systemd-boot does not count attempts for generic `efi` entries.
pub fn loaderEntry(
    gpa: mem.Allocator,
    slot: []const u8,
    version: []const u8,
    options: []const u8,
    uki: bool,
) ![]const u8 {
    if (uki) return gpa.print(
        \\title werewolf {s}
        \\sort-key werewolf
        \\version {s}
        \\uki /werewolf/{s}/uki.efi
        \\options {s}
        \\
    , .{ slot, version, slot, options });
    return gpa.print(
        \\title werewolf {s}
        \\sort-key werewolf
        \\version {s}
        \\linux /werewolf/{s}/vmlinuz
        \\initrd /werewolf/{s}/stage0.zst
        \\options {s}
        \\
    , .{ slot, version, slot, slot, options });
}

/// isEntryOf reports whether name is an entry of slot: werewolf-b.conf,
/// werewolf-b+1.conf with tries left, or werewolf-b+0-1.conf with none.
pub fn isEntryOf(name: []const u8, slot: []const u8) bool {
    const prefix = "werewolf-";
    if (!mem.startsWith(u8, name, prefix) or !mem.endsWith(u8, name, ".conf")) return false;
    const rest = name[prefix.len .. name.len - ".conf".len];
    if (!mem.startsWith(u8, rest, slot)) return false;
    return rest.len == slot.len or rest[slot.len] == '+';
}

/// isCountingEntry reports whether name is entry's counting form, such as
/// werewolf-a+1.conf for entry werewolf-a.
pub fn isCountingEntry(name: []const u8, entry: []const u8) bool {
    if (!mem.startsWith(u8, name, entry) or !mem.endsWith(u8, name, ".conf")) return false;
    return name.len > entry.len and name[entry.len] == '+';
}

/// entrySecs returns an entry's version, a policy.Serial, in Unix seconds,
/// or null if it has none or another format.
pub fn entrySecs(entry: []const u8) ?i64 {
    var it = mem.tokenizeScalar(u8, entry, '\n');
    while (it.next()) |line| {
        if (mem.startsWith(u8, line, "version "))
            return policy.parseSerial(line["version ".len..]) catch null;
    }
    return null;
}

/// withSlot returns the other slot's command line. Machine arguments from
/// this boot (console, werewolf.mac) carry over, but the image's arguments
/// replace any of the same name, so a loosened entry does not outlive an
/// update and new arguments reach older machines. werewolf.slot is set to
/// slot; the loader's initrd= and BOOT_IMAGE= are dropped.
pub fn withSlot(
    gpa: mem.Allocator,
    boot: []const u8,
    image: []const u8,
    slot: []const u8,
) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = mem.tokenizeAny(u8, boot, " \n");
    next: while (it.next()) |arg| {
        if (mem.startsWith(u8, arg, "werewolf.slot=") or
            mem.startsWith(u8, arg, "initrd=") or
            mem.startsWith(u8, arg, "BOOT_IMAGE=")) continue;
        var own = mem.tokenizeAny(u8, image, " \n");
        while (own.next()) |o| if (mem.eql(u8, argName(arg), argName(o))) continue :next;
        try out.print(gpa, "{s} ", .{arg});
    }
    var own = mem.tokenizeAny(u8, image, " \n");
    while (own.next()) |o| try out.print(gpa, "{s} ", .{o});
    try out.print(gpa, "werewolf.slot={s}", .{slot});
    return out.items;
}

fn argName(arg: []const u8) []const u8 {
    return arg[0 .. mem.findScalar(u8, arg, '=') orelse arg.len];
}

/// Native UKIs seal their options; a factory EFI entry has no options line.
pub fn rollbackOptions(
    gpa: mem.Allocator,
    text: []const u8,
    slot_name: []const u8,
    uki: bool,
) ![]const u8 {
    var options: ?[]const u8 = null;
    var efi: ?[]const u8 = null;
    var lines = mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (mem.cutPrefix(u8, line, "options ")) |o| options = o;
        const path = mem.cutPrefix(u8, line, "uki ") orelse mem.cutPrefix(u8, line, "efi ");
        if (path) |p| {
            if (efi != null) return error.NoOtherSlotEntry;
            efi = p;
        }
    }
    if (uki) {
        const expected = try gpa.print("/werewolf/{s}/uki.efi", .{slot_name});
        if (efi == null or !mem.eql(u8, efi.?, expected)) return error.NoOtherSlotEntry;
        return "";
    }
    return options orelse error.NoOtherSlotEntry;
}

fn hex(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| if (!(c >= '0' and c <= '9') and !(c >= 'a' and c <= 'f')) return false;
    return true;
}

fn printable(s: []const u8) bool {
    for (s) |c| if (c <= ' ' or c > '~') return false;
    return true;
}

const testing = std.testing;
fn fixture() Manifest {
    const a: Artifact = .{
        .sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .size = 1,
    };
    return .{
        .format = format,
        .ipe = true,
        .channel = "https://example.test/shop",
        .arch = "aarch64",
        .serial = "20261011T000000Z",
        .build = "",
        .root_hash = "0000000000000000000000000000000000000000000000000000000000000" ++
            "000",
        .kernel = "linux-virt-6.18.55-werewolf",
        .packages = &.{.{
            .name = "busybox",
            .version = "1",
            .origin = "busybox",
        }},
        .files = .{
            .vmlinuz = a,
            .@"root.erofs" = a,
            .@"stage0.zst" = a,
            .cmdline = a,
        },
    };
}

test "signed image identity and complete artifact contract" {
    var m = fixture();
    const id = buildId(m.files);
    m.build = &id;
    const identity: Identity = .{ .channel = m.channel, .arch = m.arch };
    try check(m, identity);
    try testing.expectError(
        error.WrongImageChannel,
        check(m, .{ .channel = "https://other.test/shop", .arch = m.arch }),
    );
    try testing.expectError(
        error.WrongImageArch,
        check(m, .{ .channel = m.channel, .arch = "x86_64" }),
    );
    m.ipe = false;
    try testing.expectError(error.NotAnIpeImage, check(m, identity));
    m.ipe = true;
    m.files.@"stage0.zst".size = 0;
    try testing.expectError(error.BadImageArtifact, check(m, identity));
    m.files.@"stage0.zst".size = 2;
    try testing.expectError(error.BadImageBuild, check(m, identity));
    try testing.expectError(
        error.ImageArtifactMismatch,
        matches(m.files.vmlinuz, 2, m.files.vmlinuz.sha256),
    );
    try testing.expectError(error.ImageArtifactMismatch, matches(m.files.vmlinuz, 1, m.root_hash));
}

test "image floor rejects replay, equivocation and future releases" {
    var m = fixture();
    const id = buildId(m.files);
    m.build = &id;
    const now = try policy.parseSerial(m.serial);
    try freshness(m, m.serial, @splat(0), null, now);
    try testing.expectError(
        error.OlderImage,
        freshness(m, "20261012T000000Z", @splat(0), null, now),
    );
    try testing.expectError(error.ImageSerialReused, freshness(m, m.serial, @splat(1), null, now));
    try testing.expectError(
        error.OlderImage,
        freshness(m, m.serial, @splat(0), .{ .serial = "20261012T000000Z", .build = &id }, now),
    );
    try testing.expectError(
        error.ImageSerialReused,
        freshness(m, m.serial, @splat(0), .{ .serial = m.serial, .build = m.root_hash }, now),
    );
    try testing.expectError(
        error.FutureImage,
        freshness(m, m.serial, @splat(0), null, now - 2 * policy.day),
    );
}

test "image URLs and kernel arguments cannot escape their records" {
    try channel("https://example.test/shop");
    try channel("https://10.0.2.2:443/shop");
    for ([_][]const u8{
        "http://example.test/shop",
        "https://a/../b",
        "https://a/%2e/b",
        "https://user@a/b",
        "https://a/b?c",
        "https://a/b#c",
        "https://a/b/",
    }) |s|
        try testing.expectError(error.BadImageChannel, channel(s));
    try testing.expectEqualStrings("a=b", try cmdline("a=b\n"));
    try testing.expectError(error.BadCmdline, cmdline("a=b\nlinux /evil"));
    try testing.expectError(error.BadCmdline, cmdline("a=\\b"));
}

test "loader entries are generated and matched canonically" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expect(isEntryOf("werewolf-b.conf", "b"));
    try testing.expect(isEntryOf("werewolf-b+1.conf", "b"));
    try testing.expect(isEntryOf("werewolf-b+0-1.conf", "b"));
    try testing.expect(!isEntryOf("werewolf-bb.conf", "b"));
    try testing.expect(isCountingEntry("werewolf-a+1.conf", "werewolf-a"));
    try testing.expect(!isCountingEntry("werewolf-a.conf", "werewolf-a"));
    try testing.expectEqualStrings(
        "console=tty werewolf.slot=b",
        try withSlot(a, "console=tty werewolf.slot=a", "", "b"),
    );
    const entry = try loaderEntry(a, "b", "20261007T140211Z", "console=tty werewolf.slot=b", false);
    try testing.expect(std.mem.containsAtLeast(u8, entry, 1, "linux /werewolf/b/vmlinuz"));
    try testing.expectEqual(@as(?i64, 1791381731), entrySecs(entry));

    const native = "efi /werewolf/a/uki.efi\n";
    const counted = "uki /werewolf/a/uki.efi\n";
    try testing.expectEqualStrings("", try rollbackOptions(a, counted, "a", true));
    try testing.expectError(
        error.NoOtherSlotEntry,
        rollbackOptions(a, native ++ counted, "a", true),
    );
    try testing.expectEqualStrings("", try rollbackOptions(a, native, "a", true));
    try testing.expectError(error.NoOtherSlotEntry, rollbackOptions(a, native, "b", true));
    try testing.expectEqualStrings(
        "x werewolf.slot=b",
        try rollbackOptions(a, "options x werewolf.slot=b\n", "b", false),
    );
}

test "manifest authentication precedes parsing and pins the enrolled key" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const key = try apk.parseKey(gpa, @embedFile("testdata/prebuilt/image.pub"));
    const data = @embedFile("testdata/prebuilt/image.json");
    const sig = @embedFile("testdata/prebuilt/image.json.sig");
    const identity: Identity = .{ .channel = "https://example.test/shop", .arch = "aarch64" };
    _ = try open(gpa, key, data, sig, identity);
    try testing.expectError(error.BadSignature, open(gpa, key, "{ invalid JSON", sig, identity));
    const other = try apk.parseKey(gpa, @embedFile("testdata/apk/test.rsa.pub"));
    try testing.expectError(error.BadSignature, open(gpa, other, data, sig, identity));
    try testing.expectError(
        error.WrongImageArch,
        open(gpa, key, data, sig, .{ .channel = identity.channel, .arch = "x86_64" }),
    );
}
