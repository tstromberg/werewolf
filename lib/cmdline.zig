//! The kernel command line's werewolf.* words, read one way by every
//! program that reads them:
//!
//!     werewolf.ip=CIDR werewolf.gw=ADDR werewolf.dns=ADDR
//!                                a static network, by lib/network.zig's rules
//!     werewolf.mac=ADDR          which NIC, when there are several
//!     werewolf.data=DEV          /data's disk, by its name in /dev: vda
//!     werewolf.victim=UUID:/DIR  the filesystem holding the slots, and their
//!                                directory on it
//!     werewolf.slot=a|b          which slot this boot is; with werewolf.victim
//!     werewolf.grubenv=UUID:/PATH  GRUB's environment block, after bite
//!     werewolf.esp=XXXX-XXXX     the EFI system partition, by its FAT serial,
//!                                on werewolf's own disk
//!     werewolf.root=DEV          booted directly, the disk holding the image
//!     werewolf.deadman=SECONDS   the deadman's wait, 1 to 600
//!     werewolf.seal=learn|enforce  a DEV=1 build's seal, learning or not
//!     werewolf.debug=1           a DEV=1 build's root shell on the console
//!     werewolf.check=1           posture's attacks, for werewolf's tests
//!
//! Each at most once, and well formed, or the whole line is refused: a
//! word that is not werewolf's, a value two programs could read two ways,
//! or a key given twice is a mistake, not a choice between readings.
//! stage0, the first program to read the line, panics on one it refuses,
//! so every program after it reads a line this took.

const std = @import("std");
const network = @import("network");

pub const Slot = enum {
    a,
    b,

    pub fn other(s: Slot) Slot {
        return switch (s) {
            .a => .b,
            .b => .a,
        };
    }
};

/// UUID:/PATH: a filesystem, by the UUID in its superblock, and a path on
/// it, absolute and plain (isPlainPath).
pub const Place = struct { uuid: []const u8, path: []const u8 };

pub const Seal = enum { enforce, learn };

/// The line's words, each werewolf.NAME by its NAME.
pub const Cmdline = struct {
    ip: []const u8 = "",
    gw: []const u8 = "",
    dns: []const u8 = "",
    mac: []const u8 = "",
    data: []const u8 = "",
    victim: ?Place = null,
    slot: ?Slot = null,
    grubenv: ?Place = null,
    /// The FAT serial, as a number.
    esp: ?u32 = null,
    root: []const u8 = "",
    /// Seconds, or 0 for none given.
    deadman: u32 = 0,
    seal: Seal = .enforce,
    debug: bool = false,
    check: bool = false,
};

const Key = std.meta.FieldEnum(Cmdline);

/// The most the deadman may wait, in seconds.
pub const max_deadman = 600;

/// What parse refused: the word, and why.
pub const Failure = struct { word: []const u8 = "", why: []const u8 = "" };

/// The werewolf.* words of text, the kernel's command line; or null, with
/// f set. Words that are not werewolf's are the kernel's and init's.
pub fn parse(text: []const u8, f: *Failure) ?Cmdline {
    var c: Cmdline = .{};
    var seen: std.EnumSet(Key) = .empty;
    var it = std.mem.tokenizeAny(u8, text, " \t\n");
    while (it.next()) |word| {
        const rest = std.mem.cutPrefix(u8, word, "werewolf.") orelse continue;
        f.word = word;
        const eq = std.mem.findScalar(u8, rest, '=') orelse
            return refuse(f, "not werewolf.NAME=VALUE");
        const key = std.meta.stringToEnum(Key, rest[0..eq]) orelse
            return refuse(f, "not a word werewolf takes");
        const v = rest[eq + 1 ..];
        if (seen.contains(key)) return refuse(f, "given twice");
        seen.insert(key);
        if (v.len == 0) return refuse(f, "no value");
        switch (key) {
            .ip => c.ip = v,
            .gw => c.gw = v,
            .dns => c.dns = v,
            .mac => c.mac = if (isMac(v)) v else return refuse(f, "not a MAC address"),
            .data => c.data = if (isDeviceName(v)) v else return refuse(f, not_device),
            .root => c.root = if (isDeviceName(v)) v else return refuse(f, not_device),
            .victim => c.victim = place(v) orelse return refuse(f, not_place),
            .grubenv => c.grubenv = place(v) orelse return refuse(f, not_place),
            .slot => c.slot = std.meta.stringToEnum(Slot, v) orelse return refuse(f, "not a or b"),
            .esp => c.esp = serial(v) orelse return refuse(f, "not a FAT serial, XXXX-XXXX"),
            .deadman => c.deadman = seconds(v) orelse return refuse(f, "not 1 to 600 seconds"),
            .seal => c.seal = std.meta.stringToEnum(Seal, v) orelse
                return refuse(f, "not learn or enforce"),
            .debug => c.debug = if (isOne(v)) true else return refuse(f, "not 1"),
            .check => c.check = if (isOne(v)) true else return refuse(f, "not 1"),
        }
    }
    if ((c.victim == null) != (c.slot == null)) {
        f.word = "werewolf.victim";
        return refuse(f, "comes with werewolf.slot, and only with it");
    }
    if (c.root.len > 0 and c.slot != null) {
        f.word = "werewolf.root";
        return refuse(f, "is for a direct boot, not a slot's");
    }
    if (c.ip.len > 0 or c.gw.len > 0 or c.dns.len > 0) {
        f.word = "werewolf.ip";
        var why: []const u8 = "";
        _ = network.check(.{ .ip = c.ip, .gw = c.gw, .dns = c.dns }, &why) orelse
            return refuse(f, why);
    }
    f.* = .{};
    return c;
}

const not_device = "not a disk's name in /dev, as vdc";
const not_place = "not UUID:/PATH, a plain absolute path";

/// A block device's name in /dev, as the kernel gives it: vdc, nvme0n1.
/// A letter, then up to 15 lower-case letters and digits; no path.
pub fn isDeviceName(name: []const u8) bool {
    if (name.len == 0 or name.len > 16 or !std.ascii.isLower(name[0])) return false;
    for (name) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c)) return false;
    return true;
}

/// An absolute path of plain names: no ., no .., no empty parts, not /
/// itself, and only the characters a path here may hold; @ for btrfs
/// subvolumes, as Ubuntu's /@.
pub fn isPlainPath(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |p| {
        if (p.len == 0 or std.mem.eql(u8, p, ".") or std.mem.eql(u8, p, "..")) return false;
        for (p) |c| if (!std.ascii.isAlphanumeric(c) and
            std.mem.findScalar(u8, "._-@", c) == null) return false;
    }
    return true;
}

/// 57e1f000-77e2-4b0f-8a3c-0000000000a0 as its 16 bytes, in order: hex
/// digits only, dashes where a UUID has them.
pub fn uuid(s: []const u8) ?[16]u8 {
    if (s.len != 36) return null;
    var out: [16]u8 = undefined;
    var j: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (s[i] != '-') return null;
            i += 1;
            continue;
        }
        const hi = std.fmt.charToDigit(s[i], 16) catch return null;
        const lo = std.fmt.charToDigit(s[i + 1], 16) catch return null;
        out[j] = hi << 4 | lo;
        j += 1;
        i += 2;
    }
    return out;
}

/// A FAT volume's serial, XXXX-XXXX in hex digits, as blkid shows it.
pub fn serial(s: []const u8) ?u32 {
    if (s.len != 9 or s[4] != '-') return null;
    var n: u32 = 0;
    for (s, 0..) |c, i| {
        if (i == 4) continue;
        n = n << 4 | (std.fmt.charToDigit(c, 16) catch return null);
    }
    return n;
}

fn place(s: []const u8) ?Place {
    const colon = std.mem.findScalar(u8, s, ':') orelse return null;
    const p: Place = .{ .uuid = s[0..colon], .path = s[colon + 1 ..] };
    if (uuid(p.uuid) == null or !isPlainPath(p.path)) return null;
    return p;
}

fn isOne(s: []const u8) bool {
    return std.mem.eql(u8, s, "1");
}

/// Six pairs of hex digits, joined by colons.
fn isMac(s: []const u8) bool {
    if (s.len != 17) return false;
    for (s, 0..) |c, i| if (if (i % 3 == 2) c != ':' else !std.ascii.isHex(c)) return false;
    return true;
}

/// Plain digits, no sign and no leading zero, 1 to max_deadman.
fn seconds(s: []const u8) ?u32 {
    if (s.len == 0 or s.len > 3 or s[0] == '0') return null;
    for (s) |c| if (!std.ascii.isDigit(c)) return null;
    const n = std.fmt.parseInt(u32, s, 10) catch return null;
    return if (n <= max_deadman) n else null;
}

fn refuse(f: *Failure, why: []const u8) ?Cmdline {
    f.why = why;
    return null;
}

const testing = std.testing;

const id = "57e1f000-77e2-4b0f-8a3c-0000000000a0";

fn refused(text: []const u8) !Failure {
    var f: Failure = .{};
    try testing.expectEqual(null, parse(text, &f));
    return f;
}

test parse {
    var f: Failure = .{};
    const slot = parse(
        "console=hvc0 werewolf.victim=" ++ id ++ ":/var/lib/werewolf werewolf.slot=b " ++
            "werewolf.grubenv=" ++ id ++ ":/@/boot/grub/grubenv werewolf.esp=57E1-F000 " ++
            "werewolf.mac=52:55:55:0a:Bc:01 werewolf.seal=learn werewolf.debug=1\n",
        &f,
    ).?;
    try testing.expectEqualStrings(id, slot.victim.?.uuid);
    try testing.expectEqualStrings("/var/lib/werewolf", slot.victim.?.path);
    try testing.expectEqualStrings("/@/boot/grub/grubenv", slot.grubenv.?.path);
    try testing.expectEqual(Slot.b, slot.slot.?);
    try testing.expectEqual(Slot.a, slot.slot.?.other());
    try testing.expectEqual(0x57E1F000, slot.esp.?);
    try testing.expectEqual(Seal.learn, slot.seal);
    try testing.expect(slot.debug and !slot.check);

    const direct = parse(
        "console=ttyAMA0 werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3 " ++
            "werewolf.data=vda werewolf.root=vdc werewolf.deadman=20 werewolf.check=1",
        &f,
    ).?;
    try testing.expectEqualStrings("10.0.2.15/24", direct.ip);
    try testing.expectEqualStrings("vda", direct.data);
    try testing.expectEqualStrings("vdc", direct.root);
    try testing.expectEqual(20, direct.deadman);
    try testing.expectEqual(null, direct.slot);
    try testing.expect(direct.check);
    try testing.expectEqual(Seal.enforce, parse("", &f).?.seal);
    // Words that are not werewolf's are not read.
    _ = parse("ip=dhcp root=/dev/vda werewolfx=1 init=/init", &f).?;

    try testing.expectEqualStrings("given twice", (try refused("werewolf.ip=10.0.0.5/24 " ++
        "werewolf.ip=10.0.0.6/24")).why);
    try testing.expectEqualStrings("werewolf.seal=enforce", (try refused(
        "werewolf.seal=learn werewolf.seal=enforce",
    )).word);
    for ([_][]const u8{
        "werewolf.data=/dev/vda",
        "werewolf.data=vdA",
        "werewolf.root=../vdc",
        "werewolf.root=abcdefghijklmnopq",
        "werewolf.slot=c werewolf.victim=" ++ id ++ ":/w",
        "werewolf.slot=a",
        "werewolf.victim=" ++ id ++ ":/w",
        "werewolf.victim=ab:/w werewolf.slot=a",
        "werewolf.victim=" ++ id ++ ":w werewolf.slot=a",
        "werewolf.victim=" ++ id ++ ":/w/../etc werewolf.slot=a",
        "werewolf.victim=" ++ id ++ ":/ werewolf.slot=a",
        "werewolf.victim=" ++ id ++ ":/w werewolf.slot=a werewolf.root=vdc",
        "werewolf.grubenv=" ++ id ++ ":/b//g",
        "werewolf.esp=57E1F000",
        "werewolf.esp=57E1-+000",
        "werewolf.mac=52:55:55:0a:bc",
        "werewolf.mac=52-55-55-0a-bc-01",
        "werewolf.deadman=0",
        "werewolf.deadman=601",
        "werewolf.deadman=020",
        "werewolf.deadman=+20",
        "werewolf.seal=on",
        "werewolf.debug=0",
        "werewolf.check=yes",
        "werewolf.gw=10.0.0.1",
        "werewolf.dns=10.0.0.1",
        "werewolf.ip=10.0.0.5",
        "werewolf.ip=10.0.0.5/24 werewolf.dns=fd00::1",
        "werewolf.ip=10.0.0.5/24 werewolf.gw=10.0.0.5",
        "werewolf.dat=vda",
        "werewolf.ip=",
        "werewolf.ip= werewolf.gw=10.0.0.1",
        "werewolf.debug",
    }) |text| _ = try refused(text);
}

test uuid {
    try testing.expectEqualSlices(
        u8,
        &.{ 0x57, 0xe1, 0xf0, 0x00, 0x77, 0xe2, 0x4b, 0x0f, 0x8a, 0x3c, 0, 0, 0, 0, 0, 0xa0 },
        &uuid(id).?,
    );
    try testing.expectEqual(null, uuid("57e1f000x77e2-4b0f-8a3c-0000000000a0"));
    try testing.expectEqual(null, uuid("57e1f000-77e2-4b0f-8a3c-0000000000a"));
    try testing.expectEqual(null, uuid("57e1f000-77e2-4b0f-8a3c-0000000000+a"));
    try testing.expectEqual(null, uuid("57e1f000-77e2-4b0f-8a3c-00000000000g"));
}

test serial {
    try testing.expectEqual(0x57E1F000, serial("57e1-f000").?);
    for ([_][]const u8{ "57E1F000", "57E1-F00", "57E1-G000", "+7E1-F000", "" }) |s|
        try testing.expectEqual(null, serial(s));
}

test isPlainPath {
    for ([_][]const u8{ "/var/lib/werewolf", "/@/boot/grub/grubenv", "/root/var/x" }) |p|
        try testing.expect(isPlainPath(p));
    for ([_][]const u8{ "", "/", "w", "/w/", "/a//b", "/a/./b", "/a/../b", "/a b", "/a:b" }) |p|
        try testing.expect(!isPlainPath(p));
}
