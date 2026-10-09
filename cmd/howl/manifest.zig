//! manifest writes a form's release into a directory: each file renamed
//! FORM-ARCH-NAME, and the unsigned manifest FORM-ARCH.json. See
//! docs/releases.md.
//!
//! release/sign and release/publish edit and read the manifest as text, so
//! its field order, indentation and line breaks must not change.

const std = @import("std");
const progress = @import("progress.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const mem = std.mem;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// File is one file of a release.
pub const File = struct {
    /// name is the file's name in the manifest, such as disk.qcow2.
    name: []const u8,
    /// path is where the build left it.
    path: []const u8,
};

/// Release is what a manifest is made from.
pub const Release = struct {
    form: []const u8,
    arch: []const u8,
    /// rootfs is the form's apko tar; the manifest lists its packages.
    rootfs: []const u8,
    /// kernel is the file that names the kernel package.
    kernel: []const u8,
    files: []const File,
};

/// advisories_path is werewolf's own advisories, which every manifest carries.
const advisories_path = "release/advisories";

/// write copies r's files into dir and writes the manifest there, and
/// returns the manifest's build. Everything in it follows from the files,
/// so a rebuild writes the same manifest.
pub fn write(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    dir: []const u8,
    r: Release,
) ![16]u8 {
    const kernel_text = Dir.cwd().readFileAlloc(io, r.kernel, gpa, .limited(4096)) catch |err|
        return steps.fail(try gpa.print("{s}: {t}", .{ r.kernel, err }));
    const kernel = mem.trimEnd(u8, kernel_text, "\n");

    const text = Dir.cwd().readFileAlloc(io, advisories_path, gpa, .limited(1 << 20)) catch |err|
        return steps.fail(try gpa.print("{s}: {t}", .{ advisories_path, err }));
    var bad: Bad = .{};
    const advisories = parseAdvisories(gpa, text, &bad) catch |err| switch (err) {
        // A line this cannot read fails the release, so nothing ships unread.
        error.BadAdvisory => return steps.fail(try gpa.print(
            "{s}:{d}: cannot read: {s}",
            .{ advisories_path, bad.n, bad.line },
        )),
        error.OutOfMemory => return error.OutOfMemory,
    };

    const db = std.process.run(gpa, io, .{
        .argv = &.{ "bsdtar", "-xOf", r.rootfs, "usr/lib/apk/db/installed" },
        .stdout_limit = .limited(64 << 20),
    }) catch |err| return steps.fail(try gpa.print("bsdtar: {t}", .{err}));
    if (db.term != .exited or db.term.exited != 0) return steps.fail(try gpa.print(
        "{s}: no apk database: {s}",
        .{ r.rootfs, mem.trimEnd(u8, db.stderr, "\n") },
    ));
    const packages = try parsePackages(gpa, db.stdout);
    if (packages.len == 0) return steps.fail(try gpa.print("no packages in {s}", .{r.rootfs}));

    try Dir.cwd().createDirPath(io, dir);
    const entries = try gpa.alloc(Entry, r.files.len);
    for (r.files, entries) |f, *e| {
        const to = try gpa.print("{s}/{s}-{s}-{s}", .{ dir, r.form, r.arch, f.name });
        const sum, const size = copy(io, f.path, to) catch |err|
            return steps.fail(try gpa.print("{s}: {t}", .{ f.path, err }));
        e.* = .{ .name = f.name, .sha256 = sum, .size = size };
    }
    const m: Manifest = .{
        .form = r.form,
        .arch = r.arch,
        .build = buildId(entries),
        .kernel = kernel,
        .files = entries,
        .packages = packages,
        .advisories = advisories,
    };
    const json = render(gpa, m) catch |err| switch (err) {
        error.Unsafe => return steps.fail(
            "the manifest would hold a quote, backslash or control character",
        ),
        error.OutOfMemory => return error.OutOfMemory,
    };
    const name = try gpa.print("{s}/{s}-{s}.json", .{ dir, r.form, r.arch });
    const tmp = try gpa.print("{s}.tmp", .{name});
    try Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = json });
    try Dir.rename(Dir.cwd(), tmp, Dir.cwd(), name, io);
    return m.build;
}

/// copy copies from to to with from's mode, through a temporary name, and
/// returns the copy's sha256, in hex, and size.
fn copy(io: Io, from: []const u8, to: []const u8) !struct { [64]u8, u64 } {
    const in = try Dir.cwd().openFile(io, from, .{});
    defer in.close(io);
    const st = try in.stat(io);
    var tmp_buf: [Dir.max_path_bytes]u8 = undefined;
    const tmp = try std.mem.print(&tmp_buf, "{s}.tmp", .{to});
    const out = try Dir.cwd().createFile(io, tmp, .{ .permissions = st.permissions });
    var h: Sha256 = .init(.{});
    var size: u64 = 0;
    {
        defer out.close(io);
        errdefer Dir.cwd().deleteFile(io, tmp) catch {};
        var buf: [1 << 16]u8 = undefined;
        while (true) {
            const n = in.readStreaming(io, &.{&buf}) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
            h.update(buf[0..n]);
            try out.writeStreamingAll(io, buf[0..n]);
            size += n;
        }
    }
    try Dir.rename(Dir.cwd(), tmp, Dir.cwd(), to, io);
    return .{ std.fmt.bytesToHex(h.finalResult(), .lower), size };
}

/// Entry is a released file as the manifest lists it.
const Entry = struct { name: []const u8, sha256: [64]u8, size: u64 };

/// Package is one package of the rootfs, from apk's installed database.
const Package = struct { name: []const u8, version: []const u8, origin: []const u8 };

/// Advisory is one line of release/advisories.
const Advisory = struct { id: []const u8, date: []const u8, tier: []const u8, title: []const u8 };

/// Bad is the line parseAdvisories refused, and its number from 1.
const Bad = struct { n: usize = 0, line: []const u8 = "" };

const Manifest = struct {
    form: []const u8,
    arch: []const u8,
    build: [16]u8,
    kernel: []const u8,
    files: []const Entry,
    packages: []const Package,
    advisories: []const Advisory,
};

/// buildId is the first 16 hex digits of the sha256 of the files'
/// sha256sum lines ("SUM  NAME\n"), in the order given.
fn buildId(entries: []const Entry) [16]u8 {
    var h: Sha256 = .init(.{});
    for (entries) |e| {
        h.update(&e.sha256);
        h.update("  ");
        h.update(e.name);
        h.update("\n");
    }
    const sum = h.finalResult();
    return std.fmt.bytesToHex(sum[0..8], .lower);
}

/// parsePackages reads apk's installed database: one stanza per package
/// (P: name, V: version, o: origin), with a blank line between stanzas. A
/// package with no origin is its own. They are sorted as their "name
/// version origin" lines sort bytewise, as `LC_ALL=C sort` did.
fn parsePackages(gpa: Allocator, db: []const u8) ![]const Package {
    var lines: std.ArrayList([]const u8) = .empty;
    var p: []const u8 = "";
    var v: []const u8 = "";
    var o: []const u8 = "";
    var it = mem.splitScalar(u8, db, '\n');
    while (true) {
        const line = it.next();
        if (line) |l| {
            if (mem.startsWith(u8, l, "P:")) p = l[2..];
            if (mem.startsWith(u8, l, "V:")) v = l[2..];
            if (mem.startsWith(u8, l, "o:")) o = l[2..];
            if (l.len > 0) continue;
        }
        if (p.len > 0)
            try lines.append(gpa, try gpa.print("{s} {s} {s}", .{ p, v, if (o.len > 0) o else p }));
        p = "";
        v = "";
        o = "";
        if (line == null) break;
    }
    mem.sortUnstable([]const u8, lines.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return mem.lessThan(u8, a, b);
        }
    }.lt);
    // awk split each sorted line into fields again, so do the same: an
    // empty version shifts the origin into its place, as it did there.
    const out = try gpa.alloc(Package, lines.items.len);
    for (lines.items, out) |l, *pkg| {
        var f = mem.tokenizeAny(u8, l, " \t");
        pkg.* = .{
            .name = f.next() orelse "",
            .version = f.next() orelse "",
            .origin = f.next() orelse "",
        };
    }
    return out;
}

/// parseAdvisories reads release/advisories: lines of ID DATE TIER TITLE,
/// and blank or # lines. The title is the rest of the line, as it is. On
/// error.BadAdvisory, bad holds the line.
fn parseAdvisories(gpa: Allocator, text: []const u8, bad: *Bad) ![]const Advisory {
    var out: std.ArrayList(Advisory) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    var lines = mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (lines.next()) |line| {
        n += 1;
        const rest = mem.trimStart(u8, line, " \t");
        if (rest.len == 0 or rest[0] == '#') continue;
        bad.* = .{ .n = n, .line = line };
        var fields = mem.tokenizeAny(u8, line, " \t");
        const id = fields.next() orelse return error.BadAdvisory;
        const date = fields.next() orelse return error.BadAdvisory;
        const tier = fields.next() orelse return error.BadAdvisory;
        if (fields.next() == null) return error.BadAdvisory;
        // The title starts at the fourth field and keeps trailing blanks.
        var i: usize = 0;
        for (0..3) |_| {
            while (line[i] == ' ' or line[i] == '\t') i += 1;
            while (line[i] != ' ' and line[i] != '\t') i += 1;
        }
        const title = mem.trimStart(u8, line[i..], " \t");

        // ID is WW-YEAR-NUMBER, with a number of three digits or more.
        if (id.len < 11 or !mem.startsWith(u8, id, "WW-") or id[7] != '-' or
            !digits(id[3..7]) or !digits(id[8..])) return error.BadAdvisory;
        // DATE is YYYY-MM-DD, with a month of 0x or 1x and a day of 0x to 3x.
        if (date.len != 10 or date[4] != '-' or date[7] != '-' or !digits(date[0..4]) or
            date[5] > '1' or !digits(date[5..7]) or date[8] > '3' or !digits(date[8..10]))
            return error.BadAdvisory;
        if (std.meta.stringToEnum(enum { urgent, high, medium, low }, tier) == null)
            return error.BadAdvisory;
        // TITLE is at most 200 characters of printable ASCII, with no quote
        // or backslash, which the manifest's JSON would have to escape.
        if (title.len > 200) return error.BadAdvisory;
        for (title) |c| if (c < ' ' or c > '~' or c == '"' or c == '\\') return error.BadAdvisory;
        if (try seen.fetchPut(gpa, id, {}) != null) return error.BadAdvisory;
        try out.append(gpa, .{ .id = id, .date = date, .tier = tier, .title = title });
    }
    return out.items;
}

fn digits(s: []const u8) bool {
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// render writes m in the layout release/sign edits, with no escaping. It
/// fails with error.Unsafe if a string holds what JSON would need escaped.
fn render(gpa: Allocator, m: Manifest) ![]const u8 {
    for ([_][]const u8{ m.form, m.arch, m.kernel }) |s| try safe(s);
    var out: std.ArrayList(u8) = .empty;
    try out.print(gpa,
        \\{{
        \\  "format": "werewolf-release/1",
        \\  "form": "{s}",
        \\  "arch": "{s}",
        \\  "build": "{s}",
        \\  "kernel": "{s}",
        \\  "files": {{
        \\
    , .{ m.form, m.arch, &m.build, m.kernel });
    for (m.files, 0..) |f, i| {
        try safe(f.name);
        try out.print(gpa, "{s}    \"{s}\": {{\"sha256\": \"{s}\", \"size\": {d}}}", .{
            if (i > 0) ",\n" else "", f.name, &f.sha256, f.size,
        });
    }
    try out.appendSlice(gpa, "\n  },\n  \"packages\": [\n");
    for (m.packages, 0..) |p, i| {
        for ([_][]const u8{ p.name, p.version, p.origin }) |s| try safe(s);
        try out.print(
            gpa,
            "{s}    {{\"name\": \"{s}\", \"version\": \"{s}\", \"origin\": \"{s}\"}}",
            .{ if (i > 0) ",\n" else "", p.name, p.version, p.origin },
        );
    }
    try out.appendSlice(gpa, "\n  ],\n  \"advisories\": [\n");
    for (m.advisories, 0..) |a, i| {
        try out.print(
            gpa,
            "{s}    {{\"id\": \"{s}\", \"date\": \"{s}\", \"tier\": \"{s}\", \"title\": \"{s}\"}}",
            .{ if (i > 0) ",\n" else "", a.id, a.date, a.tier, a.title },
        );
    }
    try out.appendSlice(gpa, "\n  ]\n}\n");
    return out.items;
}

/// safe fails if s holds a quote, a backslash, a control character or
/// invalid UTF-8, any of which would make the unescaped JSON wrong.
fn safe(s: []const u8) error{Unsafe}!void {
    for (s) |c| if (c < ' ' or c == '"' or c == '\\') return error.Unsafe;
    if (!std.unicode.utf8ValidateSlice(s)) return error.Unsafe;
}

const testing = std.testing;

test buildId {
    // The sha256 of "<64 a>  vmlinuz\n<64 b>  cmdline\n", as
    // printf ... | shasum -a 256 gives it.
    const e = [_]Entry{
        .{ .name = "vmlinuz", .sha256 = @splat('a'), .size = 1 },
        .{ .name = "cmdline", .sha256 = @splat('b'), .size = 2 },
    };
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    for (e) |x| try text.print(testing.allocator, "{s}  {s}\n", .{ &x.sha256, x.name });
    var sum: [32]u8 = undefined;
    Sha256.hash(text.items, &sum, .{});
    const want = std.fmt.bytesToHex(sum[0..8], .lower);
    try testing.expectEqualStrings(&want, &buildId(&e));
    // Order matters: the build names the files as listed.
    try testing.expect(!mem.eql(u8, &buildId(&e), &buildId(&.{ e[1], e[0] })));
}

test parsePackages {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const db =
        \\C:Q1abc=
        \\P:runit
        \\V:2.3.1-r3
        \\o:runit
        \\
        \\P:libblkid
        \\V:2.42.4-r0
        \\o:util-linux
        \\
        \\P:solo
        \\V:1-r0
    ;
    const got = try parsePackages(arena.allocator(), db);
    try testing.expectEqual(3, got.len);
    try testing.expectEqualStrings("libblkid", got[0].name);
    try testing.expectEqualStrings("util-linux", got[0].origin);
    try testing.expectEqualStrings("runit", got[1].name);
    // No origin: the package is its own.
    try testing.expectEqualStrings("solo", got[2].origin);
    try testing.expectEqual(0, (try parsePackages(arena.allocator(), "\n\nV:1\n")).len);
}

test parseAdvisories {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var bad: Bad = .{};
    const text = "# a comment\n\n  \t# indented\n" ++
        "WW-2026-001  2026-10-07  high\tfence: a title  \n" ++
        "\tWW-2026-0002 2026-10-08 low x\n";
    const got = try parseAdvisories(a, text, &bad);
    try testing.expectEqual(2, got.len);
    try testing.expectEqualStrings("WW-2026-001", got[0].id);
    try testing.expectEqualStrings("2026-10-07", got[0].date);
    try testing.expectEqualStrings("high", got[0].tier);
    // The title keeps its trailing blanks, as awk's sub left them.
    try testing.expectEqualStrings("fence: a title  ", got[0].title);
    try testing.expectEqualStrings("x", got[1].title);
    try testing.expectEqual(0, (try parseAdvisories(a, "", &bad)).len);

    const long: [201]u8 = @splat('t');
    for ([_][]const u8{
        "WW-2026-001 2026-10-07 high",
        "WW-2026-01 2026-10-07 high x",
        "WW-26-001 2026-10-07 high x",
        "WX-2026-001 2026-10-07 high x",
        "WW-2026-00a 2026-10-07 high x",
        "WW-2026-001 2026-20-07 high x",
        "WW-2026-001 2026-10-40 high x",
        "WW-2026-001 2026/10/07 high x",
        "WW-2026-001 2026-10-07 severe x",
        "WW-2026-001 2026-10-07 high a \"quote\"",
        "WW-2026-001 2026-10-07 high back\\slash",
        "WW-2026-001 2026-10-07 high tab\there",
        "WW-2026-001 2026-10-07 high caf\xc3\xa9",
        "WW-2026-001 2026-10-07 high " ++ long,
        "WW-2026-001 2026-10-07 high x\r",
        "\r",
    }) |line| {
        const t = try a.dupe(u8, "# ok\n" ++ "WW-2026-009 2026-10-07 low fine\n");
        const all = try mem.concat(a, u8, &.{ t, line, "\n" });
        try testing.expectError(error.BadAdvisory, parseAdvisories(a, all, &bad));
        try testing.expectEqual(3, bad.n);
        try testing.expectEqualStrings(line, bad.line);
    }
    const twice = "WW-2026-001 2026-10-07 high x\nWW-2026-001 2026-10-08 low y\n";
    try testing.expectError(error.BadAdvisory, parseAdvisories(a, twice, &bad));
    try testing.expectEqual(2, bad.n);
}

test render {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var m: Manifest = .{
        .form = "minimal",
        .arch = "aarch64",
        .build = "db34f461b8d2ee21".*,
        .kernel = "linux-virt-6.18.55-r0",
        .files = &.{
            .{ .name = "vmlinuz", .sha256 = @splat('a'), .size = 36306944 },
            .{ .name = "cmdline", .sha256 = @splat('b'), .size = 120 },
        },
        .packages = &.{
            .{ .name = "blkid", .version = "2.42.4-r0", .origin = "util-linux" },
            .{ .name = "runit", .version = "2.3.1-r3", .origin = "runit" },
        },
        .advisories = &.{},
    };
    const aa: [64]u8 = @splat('a');
    const bb: [64]u8 = @splat('b');
    // An empty list leaves a blank line, as the shell's here-document did.
    try testing.expectEqualStrings(
        \\{
        \\  "format": "werewolf-release/1",
        \\  "form": "minimal",
        \\  "arch": "aarch64",
        \\  "build": "db34f461b8d2ee21",
        \\  "kernel": "linux-virt-6.18.55-r0",
        \\  "files": {
        \\    "vmlinuz": {"sha256": "
    ++ aa ++
        \\", "size": 36306944},
        \\    "cmdline": {"sha256": "
    ++ bb ++
        \\", "size": 120}
        \\  },
        \\  "packages": [
        \\    {"name": "blkid", "version": "2.42.4-r0", "origin": "util-linux"},
        \\    {"name": "runit", "version": "2.3.1-r3", "origin": "runit"}
        \\  ],
        \\  "advisories": [
        \\
        \\  ]
        \\}
        \\
    , try render(a, m));

    m.advisories = &.{
        .{ .id = "WW-2026-001", .date = "2026-10-07", .tier = "high", .title = "fence: x" },
        .{ .id = "WW-2026-002", .date = "2026-10-08", .tier = "low", .title = "y" },
    };
    const json = try render(a, m);
    try testing.expect(mem.endsWith(u8, json,
        \\  "advisories": [
        \\    {"id": "WW-2026-001", "date": "2026-10-07", "tier": "high", "title": "fence: x"},
        \\    {"id": "WW-2026-002", "date": "2026-10-08", "tier": "low", "title": "y"}
        \\  ]
        \\}
        \\
    ));
    // The updater parses what this writes.
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, a, json, .{});
    try testing.expectEqualStrings("minimal", parsed.object.get("form").?.string);

    m.kernel = "linux\"virt";
    try testing.expectError(error.Unsafe, render(a, m));
    m.kernel = "linux-virt";
    m.packages = &.{.{ .name = "a\\b", .version = "1", .origin = "a" }};
    try testing.expectError(error.Unsafe, render(a, m));
}
