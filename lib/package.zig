//! package writes apk packages and the index that vouches for them, as
//! apk-tools 2 reads them, so werewolf's own programs update the way Wolfi's
//! packages do. See lib/README.md.

const std = @import("std");
const Allocator = std.mem.Allocator;
const mem = std.mem;
const flate = std.compress.flate;
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Info is what a package says of itself, in .PKGINFO and its index entry.
pub const Info = struct {
    name: []const u8,
    /// version is apk's, such as 20261009.142233-r0.
    version: []const u8,
    arch: []const u8,
    description: []const u8,
    url: []const u8 = "https://github.com/werewolf-linux/werewolf",
    license: []const u8 = "Apache-2.0",
    /// time is when the source was committed, in seconds since the epoch. It
    /// dates .PKGINFO and the index entry, never the files, so the same files
    /// pack to the same data member in every commit.
    time: u64,
    /// depends lists apk dependencies: names, `so:` libraries, `name=version`.
    depends: []const []const u8 = &.{},
    provides: []const []const u8 = &.{},
};

/// version returns the version of a package whose source was committed at
/// time: YYYYMMDD.HHMMSS-r0 in UTC, which apk orders as time does.
pub fn version(gpa: Allocator, time: u64) Allocator.Error![]const u8 {
    const secs: std.time.epoch.EpochSeconds = .{ .secs = time };
    const day = secs.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const s = secs.getDaySeconds();
    return gpa.print("{d:0>4}{d:0>2}{d:0>2}.{d:0>2}{d:0>2}{d:0>2}-r0", .{
        day.year,            md.month.numeric(),     md.day_index + 1,
        s.getHoursIntoDay(), s.getMinutesIntoHour(), s.getSecondsIntoMinute(),
    });
}

/// Entry is a relative path in a package, with a file's bytes or a link's target.
pub const Entry = struct {
    path: []const u8,
    kind: enum { dir, file, link },
    /// mode is a file's or directory's permissions; a link takes its target's.
    mode: u32 = 0o755,
    data: []const u8 = "",
};

/// Packed is a package and the index stanza that lists it.
pub const Packed = struct {
    /// bytes is the .apk.
    bytes: []const u8,
    /// stanza is its APKINDEX entry, ending in a blank line.
    stanza: []const u8,
};

/// pack builds a package of entries, which come in tar order: each directory
/// before what is in it.
pub fn pack(gpa: Allocator, info: Info, entries: []const Entry) !Packed {
    var data_tar: std.ArrayList(u8) = .empty;
    var size: u64 = 0;
    for (entries) |e| switch (e.kind) {
        .dir => try header(gpa, &data_tar, e.path, '5', e.mode, 0, ""),
        .link => try header(gpa, &data_tar, e.path, '2', 0o777, 0, e.data),
        .file => {
            var sha: [Sha1.digest_length]u8 = undefined;
            Sha1.hash(e.data, &sha, .{});
            const record = try pax(
                gpa,
                "APK-TOOLS.checksum.SHA1",
                &std.fmt.bytesToHex(sha, .lower),
            );
            try header(gpa, &data_tar, "PaxHeader", 'x', 0o644, record.len, "");
            try body(gpa, &data_tar, record);
            try header(gpa, &data_tar, e.path, '0', e.mode, e.data.len, "");
            try body(gpa, &data_tar, e.data);
            size += e.data.len;
        },
    };
    try data_tar.appendNTimes(gpa, 0, 2 * block);
    const data = try gzip(gpa, data_tar.items);
    var datahash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &datahash, .{});

    var pkginfo: std.ArrayList(u8) = .empty;
    try pkginfo.print(gpa,
        \\pkgname = {s}
        \\pkgver = {s}
        \\arch = {s}
        \\size = {d}
        \\origin = {s}
        \\pkgdesc = {s}
        \\url = {s}
        \\builddate = {d}
        \\license = {s}
        \\
    , .{
        info.name,
        info.version,
        info.arch,
        size,
        info.name,
        info.description,
        info.url,
        info.time,
        info.license,
    });
    for (info.depends) |d| try pkginfo.print(gpa, "depend = {s}\n", .{d});
    for (info.provides) |p| try pkginfo.print(gpa, "provides = {s}\n", .{p});
    try pkginfo.print(gpa, "datahash = {s}\n", .{&std.fmt.bytesToHex(datahash, .lower)});
    var control_tar: std.ArrayList(u8) = .empty;
    try header(gpa, &control_tar, ".PKGINFO", '0', 0o644, pkginfo.items.len, "");
    try body(gpa, &control_tar, pkginfo.items);
    const control = try gzip(gpa, control_tar.items);

    var c: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(control, &c, .{});
    var c64: [std.base64.standard.Encoder.calcSize(Sha1.digest_length)]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&c64, &c);
    const bytes = try mem.concat(gpa, u8, &.{ control, data });
    var stanza: std.ArrayList(u8) = .empty;
    try stanza.print(gpa,
        \\C:Q1{s}
        \\P:{s}
        \\V:{s}
        \\A:{s}
        \\S:{d}
        \\I:{d}
        \\T:{s}
        \\U:{s}
        \\L:{s}
        \\o:{s}
        \\t:{d}
        \\
    , .{
        &c64,
        info.name,
        info.version,
        info.arch,
        bytes.len,
        size,
        info.description,
        info.url,
        info.license,
        info.name,
        info.time,
    });
    if (info.depends.len > 0) try stanza.print(
        gpa,
        "D:{s}\n",
        .{try mem.join(gpa, " ", info.depends)},
    );
    if (info.provides.len > 0) try stanza.print(
        gpa,
        "p:{s}\n",
        .{try mem.join(gpa, " ", info.provides)},
    );
    try stanza.append(gpa, '\n');
    return .{ .bytes = bytes, .stanza = stanza.items };
}

/// index returns an APKINDEX: the stanzas of old, an index already published,
/// plus the new ones, sorted by name and version. It never removes or
/// replaces a published stanza, because a machine may resolve through it.
/// A new stanza for a published name and version must be identical, as a
/// rebuild of the same source is.
pub fn index(gpa: Allocator, old: []const u8, new: []const []const u8) ![]const u8 {
    var stanzas: std.ArrayList([]const u8) = .empty;
    var it = mem.splitSequence(u8, old, "\n\n");
    while (it.next()) |s| {
        const trimmed = mem.trim(u8, s, "\n");
        if (trimmed.len > 0) try stanzas.append(gpa, try gpa.print("{s}\n\n", .{trimmed}));
    }
    next: for (new) |s| {
        for (stanzas.items) |have| if (mem.eql(u8, field(have, 'P'), field(s, 'P')) and
            mem.eql(u8, field(have, 'V'), field(s, 'V')))
        {
            if (mem.eql(u8, have, s)) continue :next;
            return error.VersionPublished;
        };
        try stanzas.append(gpa, s);
    }
    mem.sortUnstable([]const u8, stanzas.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            const order = mem.order(u8, field(a, 'P'), field(b, 'P'));
            if (order != .eq) return order == .lt;
            return mem.lessThan(u8, field(a, 'V'), field(b, 'V'));
        }
    }.lt);
    return mem.concat(gpa, u8, stanzas.items);
}

/// field returns a stanza's value for key, from its first line starting `key:`.
fn field(stanza: []const u8, key: u8) []const u8 {
    var it = mem.splitScalar(u8, stanza, '\n');
    while (it.next()) |line| {
        if (line.len >= 2 and line[0] == key and line[1] == ':') return line[2..];
    }
    return "";
}

/// indexMember returns the member an index's signature signs: DESCRIPTION
/// and APKINDEX.
pub fn indexMember(gpa: Allocator, description: []const u8, apkindex: []const u8) ![]const u8 {
    var tar: std.ArrayList(u8) = .empty;
    try header(gpa, &tar, "DESCRIPTION", '0', 0o644, description.len, "");
    try body(gpa, &tar, description);
    try header(gpa, &tar, "APKINDEX", '0', 0o644, apkindex.len, "");
    try body(gpa, &tar, apkindex);
    try tar.appendNTimes(gpa, 0, 2 * block);
    return gzip(gpa, tar.items);
}

/// signed returns APKINDEX.tar.gz: the signature member, then member. The
/// signature is RSA PKCS#1 v1.5 over member's SHA-256, by the key apk knows
/// as key_name, its file name in /etc/apk/keys.
pub fn signed(
    gpa: Allocator,
    key_name: []const u8,
    signature: []const u8,
    member: []const u8,
) ![]const u8 {
    var tar: std.ArrayList(u8) = .empty;
    const name = try gpa.print(".SIGN.RSA256.{s}", .{key_name});
    try header(gpa, &tar, name, '0', 0o644, signature.len, "");
    try body(gpa, &tar, signature);
    return mem.concat(gpa, u8, &.{ try gzip(gpa, tar.items), member });
}

const block = 512;

/// header appends a ustar header for path, owned by root and dated 1970, so
/// the same files give the same member whenever they are packed.
fn header(
    gpa: Allocator,
    tar: *std.ArrayList(u8),
    path: []const u8,
    kind: u8,
    mode: u32,
    size: u64,
    link: []const u8,
) !void {
    var h: [block]u8 = @splat(0);
    // A name past 100 bytes goes in the prefix, split at a slash.
    var name = path;
    if (path.len > 100) {
        const cut = mem.findScalarLast(
            u8,
            path[0..@min(path.len, 156)],
            '/',
        ) orelse return error.NameTooLong;
        if (cut > 155 or path.len - cut - 1 > 100) return error.NameTooLong;
        @memcpy(h[345..][0..cut], path[0..cut]);
        name = path[cut + 1 ..];
    }
    if (link.len > 100) return error.NameTooLong;
    @memcpy(h[0..name.len], name);
    _ = try mem.print(h[100..108], "{o:0>7}", .{mode & 0o7777});
    _ = try mem.print(h[108..116], "{o:0>7}", .{0});
    _ = try mem.print(h[116..124], "{o:0>7}", .{0});
    _ = try mem.print(h[124..136], "{o:0>11}", .{size});
    _ = try mem.print(h[136..148], "{o:0>11}", .{0});
    h[156] = kind;
    @memcpy(h[157..][0..link.len], link);
    @memcpy(h[257..265], "ustar\x0000");
    @memcpy(h[265..][0..4], "root");
    @memcpy(h[297..][0..4], "root");
    @memset(h[148..156], ' ');
    var sum: u32 = 0;
    for (h) |b| sum += b;
    _ = try mem.print(h[148..156], "{o:0>6}\x00 ", .{sum});
    try tar.appendSlice(gpa, &h);
}

/// body appends data, padded to a whole block.
fn body(gpa: Allocator, tar: *std.ArrayList(u8), data: []const u8) !void {
    try tar.appendSlice(gpa, data);
    try tar.appendNTimes(gpa, 0, (block - data.len % block) % block);
}

/// pax returns one PAX record, `LEN KEY=VALUE\n`, where LEN counts itself.
fn pax(gpa: Allocator, key: []const u8, value: []const u8) ![]const u8 {
    const rest = key.len + value.len + 3;
    var len = rest + 1;
    while (std.math.log10_int(len) + 1 + rest != len) len += 1;
    return gpa.print("{d} {s}={s}\n", .{ len, key, value });
}

/// gzip compresses data into one gzip member.
fn gzip(gpa: Allocator, data: []const u8) ![]const u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(gpa, data.len / 2 + 64);
    defer out.deinit();
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var c = try flate.Compress.init(&out.writer, window, .gzip, .default);
    try c.writer.writeAll(data);
    try c.finish();
    return out.toOwnedSlice();
}

/// Opened is a signed index split for a verifier: the signature, and the
/// member it signs.
pub const Opened = struct { signature: []const u8, member: []const u8 };

/// open splits whole, an APKINDEX.tar.gz, into its signature by the key apk
/// knows as key_name and the member that signature covers. A key holder must
/// verify the signature before trusting the member: whoever can write the
/// bucket can write an index.
pub fn open(gpa: Allocator, whole: []const u8, key_name: []const u8) !Opened {
    const tar, const end = try inflate(gpa, whole, max_signature);
    if (tar.len < block) return error.BadIndex;
    const want = try gpa.print(".SIGN.RSA256.{s}", .{key_name});
    if (!mem.eql(u8, mem.sliceTo(tar[0..100], 0), want)) return error.UnknownKey;
    const size = std.fmt.parseInt(usize, mem.trim(u8, tar[124..136], "\x00 "), 8) catch
        return error.BadIndex;
    // One file, cut: nothing after its padded data.
    if (tar.len != block + (size + block - 1) / block * block) return error.BadIndex;
    return .{ .signature = tar[block..][0..size], .member = whole[end..] };
}

/// max_signature bounds a signature member, inflated: a tar of one RSA
/// signature is 1 KiB.
const max_signature = 64 << 10;

/// inflate returns the first gzip member of data, decompressed up to limit
/// bytes, and where the next member begins.
fn inflate(gpa: Allocator, data: []const u8, limit: usize) !struct { []const u8, usize } {
    var in: std.Io.Reader = .fixed(data);
    var window: [flate.max_window_len]u8 = undefined;
    var d: flate.Decompress = .init(&in, .gzip, &window);
    const out = try d.reader.allocRemaining(gpa, .limited(limit));
    return .{ out, in.seek };
}

const testing = std.testing;

test "pack: a control member vouched for by C:, then the data its datahash names" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const p = try pack(gpa, .{
        .name = "werewolf-fence",
        .version = "20261009.142233-r0",
        .arch = "aarch64",
        .description = "werewolf's network policy",
        .time = 1791555753,
        .depends = &.{"werewolf-format=1"},
        .provides = &.{"cmd:fence=20261009.142233-r0"},
    }, &.{
        .{ .path = "usr", .kind = .dir },
        .{ .path = "usr/lib", .kind = .dir },
        .{ .path = "usr/lib/werewolf", .kind = .dir },
        .{ .path = "usr/lib/werewolf/fence", .kind = .file, .data = "\x7fELF fence" },
        .{ .path = "usr/lib/werewolf/fence-link", .kind = .link, .data = "fence" },
    });
    const control, const at = try inflate(gpa, p.bytes, 1 << 20);
    // A tar of .PKGINFO, cut: no end blocks, so the data's tar reads on.
    try testing.expectEqual(0, control.len % block);
    try testing.expectEqualStrings(".PKGINFO", mem.sliceTo(control[0..100], 0));
    const pkginfo = control[block..][0..try std.fmt.parseInt(
        usize,
        mem.trim(u8, control[124..135], "\x00 "),
        8,
    )];
    var datahash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(p.bytes[at..], &datahash, .{});
    try testing.expect(mem.indexOf(u8, pkginfo, &std.fmt.bytesToHex(datahash, .lower)) != null);
    try testing.expect(mem.indexOf(u8, pkginfo, "depend = werewolf-format=1\n") != null);
    var c: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(p.bytes[0..at], &c, .{});
    var c64: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&c64, &c);
    try testing.expectEqualStrings(&c64, field(p.stanza, 'C')[2..]);
    try testing.expectEqualStrings(try gpa.print("{d}", .{p.bytes.len}), field(p.stanza, 'S'));

    // The data: each file after its SHA-1, and the tar's end.
    const data, const end = try inflate(gpa, p.bytes[at..], 1 << 20);
    try testing.expectEqual(p.bytes.len - at, end);
    var data_reader: std.Io.Reader = .fixed(data);
    var it: std.tar.Iterator = .init(&data_reader, .{
        .file_name_buffer = try gpa.alloc(u8, 256),
        .link_name_buffer = try gpa.alloc(u8, 256),
    });
    var seen: std.ArrayList([]const u8) = .empty;
    while (try it.next()) |f| try seen.append(gpa, try gpa.dupe(u8, f.name));
    try testing.expectEqual(5, seen.items.len);
    try testing.expectEqualStrings("usr/lib/werewolf/fence", seen.items[3]);
    try testing.expect(mem.indexOf(u8, data, "APK-TOOLS.checksum.SHA1=") != null);

    // The same input, the same bytes.
    const again = try pack(gpa, .{
        .name = "werewolf-fence",
        .version = "20261009.142233-r0",
        .arch = "aarch64",
        .description = "werewolf's network policy",
        .time = 1791555753,
        .depends = &.{"werewolf-format=1"},
        .provides = &.{"cmd:fence=20261009.142233-r0"},
    }, &.{
        .{ .path = "usr", .kind = .dir },
        .{ .path = "usr/lib", .kind = .dir },
        .{ .path = "usr/lib/werewolf", .kind = .dir },
        .{ .path = "usr/lib/werewolf/fence", .kind = .file, .data = "\x7fELF fence" },
        .{ .path = "usr/lib/werewolf/fence-link", .kind = .link, .data = "fence" },
    });
    try testing.expectEqualSlices(u8, p.bytes, again.bytes);
}

test "version: the commit's time, in UTC, as apk orders it" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    try testing.expectEqualStrings("19700101.000000-r0", try version(gpa, 0));
    try testing.expectEqualStrings("20261009.081500-r0", try version(gpa, 1791533700));
}

test "index: published stanzas kept, new ones added in order, a version never replaced" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const old = "C:Q1aaa=\nP:werewolf-init\nV:1-r0\n\nC:Q1bbb=\nP:werewolf-fence\nV:1-r0\n\n";
    const got = try index(gpa, old, &.{
        "C:Q1ccc=\nP:werewolf-fence\nV:2-r0\n\n",
        "C:Q1aaa=\nP:werewolf-init\nV:1-r0\n\n",
    });
    try testing.expectEqualStrings(
        "C:Q1bbb=\nP:werewolf-fence\nV:1-r0\n\nC:Q1ccc=\nP:werewolf-fence\nV:2-r0\n\n" ++
            "C:Q1aaa=\nP:werewolf-init\nV:1-r0\n\n",
        got,
    );
    try testing.expectError(
        error.VersionPublished,
        index(gpa, old, &.{"C:Q1zzz=\nP:werewolf-init\nV:1-r0\n\n"}),
    );
}

test "signed: the signature member, cut, then the member it signs" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const member = try indexMember(gpa, "werewolf", "C:Q1aaa=\nP:x\nV:1-r0\n\n");
    const whole = try signed(gpa, "packages.rsa.pub", "SIGNATURE", member);
    const sig, const at = try inflate(gpa, whole, 1 << 20);
    try testing.expectEqualStrings(".SIGN.RSA256.packages.rsa.pub", mem.sliceTo(sig[0..100], 0));
    try testing.expectEqual(2 * block, sig.len);
    try testing.expectEqualSlices(u8, member, whole[at..]);
    const idx, _ = try inflate(gpa, member, 1 << 20);
    try testing.expectEqualStrings("DESCRIPTION", mem.sliceTo(idx[0..100], 0));

    // open gives back what signed was given, and only for its key.
    const o = try open(gpa, whole, "packages.rsa.pub");
    try testing.expectEqualStrings("SIGNATURE", o.signature);
    try testing.expectEqualSlices(u8, member, o.member);
    try testing.expectError(error.UnknownKey, open(gpa, whole, "other.rsa.pub"));
}

test "pack: the same files in another commit, the same data member" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    const files = [_]Entry{
        .{ .path = "usr", .kind = .dir },
        .{ .path = "usr/bin", .kind = .dir },
        .{ .path = "usr/bin/hello", .kind = .file, .data = "hello\n" },
    };
    var data: [2][]const u8 = undefined;
    for ([_]u64{ 1791555753, 1791642153 }, &data) |time, *d| {
        const p = try pack(gpa, .{
            .name = "werewolf-hello",
            .version = try version(gpa, time),
            .arch = "aarch64",
            .description = "hello",
            .time = time,
        }, &files);
        _, const at = try inflate(gpa, p.bytes, 1 << 20);
        d.* = p.bytes[at..];
    }
    try testing.expectEqualSlices(u8, data[0], data[1]);
}
