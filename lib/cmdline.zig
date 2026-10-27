//! cmdline parses the werewolf.* words of the kernel command line, so every
//! program reads them the same way. See lib/README.md for the words.

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

/// Protection is one of werewolf's protections a machine can be made
/// without: howl's --disable gives them up, and werewolf.disable names those
/// a machine lacks.
pub const Protection = enum { secureboot, tpm, ipe };

pub const Protections = std.EnumSet(Protection);

/// protections parses NAME[,NAME...], each a Protection, none twice, or
/// returns null.
pub fn protections(text: []const u8) ?Protections {
    var set: Protections = .empty;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |name| {
        const p = std.meta.stringToEnum(Protection, name) orelse return null;
        if (set.contains(p)) return null;
        set.insert(p);
    }
    return set;
}

/// writeProtections writes the names in set, in a fixed order, sep between.
pub fn writeProtections(w: *std.Io.Writer, set: Protections, sep: []const u8) !void {
    var first = true;
    for (std.enums.values(Protection)) |p| if (set.contains(p)) {
        if (!first) try w.writeAll(sep);
        try w.writeAll(@tagName(p));
        first = false;
    };
}

test protections {
    const t = std.testing;
    const all = protections("secureboot,tpm,ipe").?;
    try t.expect(all.eql(.full));
    try t.expect(protections("ipe,tpm").?.eql(.initMany(&.{ .tpm, .ipe })));
    for ([_][]const u8{ "", "ipe,", "ipe,ipe", "IPE", "landlock", "secureboot tpm" }) |bad|
        try t.expectEqual(null, protections(bad));
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeProtections(&w, protections("ipe,secureboot,tpm").?, ", ");
    try t.expectEqualStrings("secureboot, tpm, ipe", w.buffered());
}

/// Cmdline holds each werewolf.NAME word in the field NAME.
pub const Cmdline = struct {
    ip: []const u8 = "",
    gw: []const u8 = "",
    dns: []const u8 = "",
    mac: []const u8 = "",
    data: []const u8 = "",
    slots: ?[]const u8 = null,
    slot: ?Slot = null,
    /// esp is the FAT serial, as a number.
    esp: ?u32 = null,
    root: []const u8 = "",
    /// deadman is in seconds; 0 means none was given.
    deadman: u32 = 0,
    debug: bool = false,
    check: bool = false,
    /// native selects the slot from the signed UKI's canonical firmware path.
    native: bool = false,
    secure: bool = false,
    /// disable names the protections the machine was made without (howl's
    /// --disable), less any its provider supplies regardless.
    disable: Protections = .empty,
    /// channel is the release channel's 32-byte identity, from the signed UKI;
    /// with index it selects the machine's TPM floor (docs/design/independent-updates.md).
    channel: ?[32]u8 = null,
    /// index is this release's place in its channel: 1, 2, 3, ...
    index: ?u64 = null,
};

const Key = std.meta.FieldEnum(Cmdline);

test "the TPM floor requires a sealed secure native release and rejects overrides" {
    const t = std.testing;
    var f: Failure = .{};
    const native = "werewolf.native=1 werewolf.secure=1 " ++
        "werewolf.slots=57e1f000-77e2-4b0f-8a3c-0000000000a0 werewolf.esp=57E1-F000";
    const channel = " werewolf.channel=" ++ @as([64]u8, @splat('a'));
    const release = parse(native ++ channel ++ " werewolf.index=42", &f).?;
    try t.expectEqual(@as(u64, 42), release.index.?);
    try t.expectEqual(@as(u8, 0xaa), release.channel.?[31]);
    try t.expect(parse("werewolf.disable=secureboot,tpm,ipe", &f).?.disable.eql(.full));
    // Signed native boot without the TPM or IPE, as QEMU makes one.
    try t.expect(parse(native ++ " werewolf.disable=tpm,ipe", &f).?.secure);
    for ([_][]const u8{
        native ++ channel,
        native ++ " werewolf.index=1",
        native ++ channel ++ " werewolf.index=0",
        native ++ channel ++ " werewolf.index=01",
        native ++ channel ++ " werewolf.index=-1",
        native ++ channel ++ " werewolf.index=18446744073709551616",
        native ++ " werewolf.channel=" ++ @as([63]u8, @splat('a')) ++ " werewolf.index=1",
        native ++ " werewolf.channel=" ++ @as([64]u8, @splat('g')) ++ " werewolf.index=1",
        native ++ channel ++ channel ++ " werewolf.index=1",
        native ++ channel ++ " werewolf.index=1 werewolf.disable=tpm,ipe",
        native ++ " werewolf.disable=secureboot,tpm",
        native ++ " werewolf.tpm=2",
        native ++ " werewolf.release=" ++ @as([64]u8, @splat('a')),
        native ++ " werewolf.bootstrap=1",
        "werewolf.disable=secureboot",
        "werewolf.disable=ipe,ipe",
        "werewolf.disable=landlock",
        "werewolf.disable=1",
        channel ++ " werewolf.index=1",
    }) |bad| try t.expect(parse(bad, &f) == null);
}

/// max_deadman is the longest the deadman may wait, in seconds.
pub const max_deadman = 600;

/// Failure is the word parse refused, and why.
pub const Failure = struct { word: []const u8 = "", why: []const u8 = "" };

/// parse reads the werewolf.* words of text, the kernel command line. It
/// returns null and sets f on any bad, unknown or repeated word. Other words
/// belong to the kernel and init and are skipped.
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
            .slots => c.slots = if (uuid(v) != null) v else return refuse(f, "not a UUID"),
            .slot => c.slot = std.meta.stringToEnum(Slot, v) orelse return refuse(f, "not a or b"),
            .esp => c.esp = serial(v) orelse return refuse(f, "not a FAT serial, XXXX-XXXX"),
            .deadman => c.deadman = seconds(v) orelse return refuse(f, "not 1 to 600 seconds"),
            .debug => c.debug = if (isOne(v)) true else return refuse(f, "not 1"),
            .check => c.check = if (isOne(v)) true else return refuse(f, "not 1"),
            .native => c.native = if (isOne(v)) true else return refuse(f, "not 1"),
            .secure => c.secure = if (isOne(v)) true else return refuse(f, "not 1"),
            .disable => c.disable = protections(v) orelse
                return refuse(f, "not secureboot, tpm or ipe, comma-separated, each once"),
            .channel => {
                var digest: [32]u8 = undefined;
                if (v.len != 64) return refuse(f, "not a 64-digit hex channel identity");
                _ = std.fmt.hexToBytes(&digest, v) catch
                    return refuse(f, "not a 64-digit hex channel identity");
                c.channel = digest;
            },
            .index => c.index = releaseIndex(v) orelse
                return refuse(f, "not a release index: 1 or more, in decimal"),
        }
    }
    if (c.native and (c.slots == null or c.esp == null or c.root.len > 0)) {
        f.word = "werewolf.native";
        return refuse(f, "needs native slots and ESP, without a direct root");
    }
    if (c.secure and !c.native) {
        f.word = "werewolf.secure";
        return refuse(f, "requires signed native boot identity");
    }
    if ((c.channel == null) != (c.index == null) or (c.channel != null and !c.secure)) {
        f.word = "werewolf.channel";
        return refuse(f, "comes with werewolf.index, on a secure native boot");
    }
    // What a machine lacks cannot also be what it booted with; and the TPM's
    // floor means something only while signed boot code enforces it.
    if ((c.disable.contains(.secureboot) and c.secure) or
        (c.disable.contains(.tpm) and c.channel != null))
    {
        f.word = "werewolf.disable";
        return refuse(f, "names a protection this boot has");
    }
    if (c.disable.contains(.secureboot) and !c.disable.contains(.tpm)) {
        f.word = "werewolf.disable";
        return refuse(f, "secureboot without tpm: unsigned boot code would ignore the TPM");
    }
    if (!c.native and (c.slots == null) != (c.slot == null)) {
        f.word = "werewolf.slots";
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

/// The stub's path is a routing hint. The signed verity root remains the authority.
pub fn firmwareSlot(variable: []const u8) ?Slot {
    if (variable.len < 6 or variable.len > 516 or variable.len % 2 != 0) return null;
    var path: [256]u8 = undefined;
    var n: usize = 0;
    var at: usize = 4;
    while (at + 2 <= variable.len) : (at += 2) {
        const c = std.mem.readInt(u16, variable[at..][0..2], .little);
        if (c == 0) {
            if (at + 2 != variable.len) return null;
            const text = path[0..n];
            if (std.mem.eql(u8, text, "/werewolf/a/uki.efi")) return .a;
            if (std.mem.eql(u8, text, "/werewolf/b/uki.efi")) return .b;
            return null;
        }
        if (c > 127 or c < 32 or n == path.len) return null;
        path[n] = if (c == '\\') '/' else std.ascii.toLower(@intCast(c));
        n += 1;
    }
    return null;
}

test "native boot binds the disk while firmware supplies only a canonical slot hint" {
    const t = std.testing;
    var f: Failure = .{};
    const line = "werewolf.native=1 werewolf.slots=57e1f000-77e2-4b0f-8a3c-0000000000a0 " ++
        "werewolf.esp=57E1-F000";
    const native = parse(line, &f) orelse return error.TestUnexpectedResult;
    try t.expect(native.native and native.slot == null and native.slots != null);
    try t.expect(parse("werewolf.native=1", &f) == null);
    try t.expect(parse("werewolf.secure=1", &f) == null);
    try t.expect(parse(line ++ " werewolf.secure=1", &f).?.secure);
    try t.expect(parse(line ++ " werewolf.root=vda", &f) == null);
    try t.expect(parse(
        line ++ " werewolf.grubenv=57e1f000-77e2-4b0f-8a3c-0000000000a0:/boot/grubenv",
        &f,
    ) == null);
    var raw: [516]u8 = @splat(0);
    for ([_][]const u8{
        "\\werewolf\\a\\uki.efi",
        "\\WEREWOLF\\B\\UKI.EFI",
        "\\werewolf\\a\\..\\b\\uki.efi",
        "\\EFI\\BOOT\\BOOTAA64.EFI",
    }, 0..) |path, i| {
        @memset(&raw, 0);
        for (path, 0..) |c, j| std.mem.writeInt(u16, raw[4 + j * 2 ..][0..2], c, .little);
        const value = raw[0 .. 6 + path.len * 2];
        try t.expectEqual(
            if (i == 0) Slot.a else if (i == 1) Slot.b else null,
            firmwareSlot(value),
        );
        try t.expect(firmwareSlot(value[0 .. value.len - 2]) == null);
    }
}

const not_device = "not a disk's name in /dev, as vdc";

/// isDeviceName reports whether name is a block device name in /dev, such
/// as vdc or nvme0n1: a lower-case letter, then up to 15 letters and digits.
pub fn isDeviceName(name: []const u8) bool {
    if (name.len == 0 or name.len > 16 or !std.ascii.isLower(name[0])) return false;
    for (name) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c)) return false;
    return true;
}

/// uuid parses a UUID such as 57e1f000-77e2-4b0f-8a3c-0000000000a0 into
/// its 16 bytes, in order. It returns null unless the form is exact.
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

/// serial parses a FAT volume serial, XXXX-XXXX in hex, as blkid shows it.
pub fn serial(s: []const u8) ?u32 {
    if (s.len != 9 or s[4] != '-') return null;
    var n: u32 = 0;
    for (s, 0..) |c, i| {
        if (i == 4) continue;
        n = n << 4 | (std.fmt.charToDigit(c, 16) catch return null);
    }
    return n;
}

/// releaseIndex parses a release index: 1 or more, plain decimal digits,
/// no sign or leading zero, that fits in 64 bits.
pub fn releaseIndex(s: []const u8) ?u64 {
    if (s.len == 0 or s.len > 20 or s[0] == '0') return null;
    for (s) |c| if (!std.ascii.isDigit(c)) return null;
    return std.fmt.parseInt(u64, s, 10) catch null;
}

fn isOne(s: []const u8) bool {
    return std.mem.eql(u8, s, "1");
}

/// isMac reports whether s is six pairs of hex digits joined by colons.
pub fn isMac(s: []const u8) bool {
    if (s.len != 17) return false;
    for (s, 0..) |c, i| if (if (i % 3 == 2) c != ':' else !std.ascii.isHex(c)) return false;
    return true;
}

/// seconds parses 1 to max_deadman: plain digits, no sign or leading zero.
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
        "console=hvc0 werewolf.slots=" ++ id ++ " werewolf.slot=b " ++
            "werewolf.esp=57E1-F000 " ++
            "werewolf.mac=52:55:55:0a:Bc:01 werewolf.debug=1\n",
        &f,
    ).?;
    try testing.expectEqualStrings(id, slot.slots.?);
    try testing.expectEqual(Slot.b, slot.slot.?);
    try testing.expectEqual(Slot.a, slot.slot.?.other());
    try testing.expectEqual(0x57E1F000, slot.esp.?);
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
    // Words that are not werewolf's are skipped.
    _ = parse("ip=dhcp root=/dev/vda werewolfx=1 init=/init", &f).?;

    try testing.expectEqualStrings("given twice", (try refused("werewolf.ip=10.0.0.5/24 " ++
        "werewolf.ip=10.0.0.6/24")).why);
    try testing.expectEqualStrings("werewolf.debug=1", (try refused(
        "werewolf.debug=1 werewolf.debug=1",
    )).word);
    for ([_][]const u8{
        "werewolf.data=/dev/vda",
        "werewolf.data=vdA",
        "werewolf.root=../vdc",
        "werewolf.root=abcdefghijklmnopq",
        "werewolf.slot=c werewolf.slots=" ++ id,
        "werewolf.slot=a",
        "werewolf.slots=" ++ id,
        "werewolf.slots=ab werewolf.slot=a",
        "werewolf.slots=" ++ id ++ ":/w werewolf.slot=a",
        "werewolf.slots=" ++ id ++ " werewolf.slot=a werewolf.root=vdc",
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
