//! compare refuses a test image whose dependencies changed what production
//! runs: service policies, accounts, machine-wide policy, runtime files, or
//! added configuration. It reads the images' tars as they are mounted, the
//! form's files over the packages'. The production package database also
//! pins the test image's versions, and its command aliases are kept.

const std = @import("std");
const plans = @import("test-plan");
const tests = @import("native-tests.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const mem = std.mem;
const Tool = tests.Tool;
const Form = tests.Form;

/// productionPins freezes the baseline's actual packages, transitive
/// dependencies included, as NAME=VERSION.
pub fn productionPins(t: *Tool, rootfs: []const u8) ![]const []const u8 {
    var installed: ?[]const u8 = null;
    var archive = try Archive.open(t.io, rootfs);
    defer archive.close(t.io);
    while (try archive.next(t.gpa)) |m| {
        if (mem.eql(u8, m.name, "usr/lib/apk/db/installed") and m.kind == '0')
            installed = try archive.contents(t.gpa, m, 64 << 20);
    }
    return packageVersions(
        t,
        installed orelse return t.fail("{s}: no package database", .{rootfs}),
    );
}

fn packageVersions(t: *Tool, installed: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var names: std.ArrayList([]const u8) = .empty;
    var records = mem.splitSequence(u8, installed, "\n\n");
    while (records.next()) |record| {
        if (mem.trim(u8, record, " \t\r\n").len == 0) continue;
        var name: ?[]const u8 = null;
        var version: ?[]const u8 = null;
        var lines = mem.splitScalar(u8, record, '\n');
        while (lines.next()) |line| {
            const field = if (mem.startsWith(u8, line, "P:"))
                &name
            else if (mem.startsWith(u8, line, "V:"))
                &version
            else
                continue;
            if (field.* != null) return t.fail("invalid production package database", .{});
            field.* = line[2..];
        }
        const n = name orelse return t.fail("invalid production package database", .{});
        const v = version orelse return t.fail("invalid production package database", .{});
        if (n.len == 0 or !std.ascii.isAlphanumeric(n[0]) or !allIn(n, alnum ++ "+_.-") or
            v.len == 0 or !allIn(v, alnum ++ "_.+-"))
            return t.fail("invalid production package database", .{});
        if (tests.has(names.items, n)) return t.fail("duplicate production package {s}", .{n});
        try names.append(t.gpa, n);
        try out.append(t.gpa, try t.gpa.print("{s}={s}", .{ n, v }));
    }
    if (out.items.len == 0) return t.fail("empty production package database", .{});
    mem.sort([]const u8, out.items, {}, tests.lessThan);
    return out.items;
}

const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn allIn(s: []const u8, set: []const u8) bool {
    for (s) |c| if (mem.findScalar(u8, set, c) == null) return false;
    return true;
}

/// commandLinks keeps the package-provided command aliases (busybox-style
/// links in bin and sbin) a test library's package would otherwise replace.
pub fn commandLinks(t: *Tool, baseline: []const u8, root: []const u8) !void {
    const io = t.io;
    const gpa = t.gpa;
    if (isLink(io, root)) return t.fail("symlink at generated test root", .{});
    try Dir.cwd().createDirPath(io, root);
    const overlay = try members(t, try gpa.print("{s}/overlay.tar", .{baseline}), false);
    const rootfs = try members(t, try gpa.print("{s}/rootfs.tar", .{baseline}), false);
    for (rootfs.keys(), rootfs.values()) |name, entry| {
        const parent = std.fs.path.dirname(name) orelse continue;
        if (!tests.has(&.{ "bin", "sbin", "usr/bin", "usr/sbin" }, parent) or
            overlay.contains(name) or
            entry.kind != '2' or entry.uid != 0 or entry.gid != 0 or entry.mode != 0o777) continue;
        const directory = rootfs.get(parent) orelse continue;
        if (directory.kind != '5') continue;
        var at: usize = 0;
        while (mem.findScalarPos(u8, parent, at, '/')) |slash| : (at = slash + 1) {
            const path = try gpa.print("{s}/{s}", .{ root, parent[0..slash] });
            if (isLink(
                io,
                path,
            )) return t.fail("symlink in command parent: {s}", .{parent[0..slash]});
            Dir.cwd().createDir(
                io,
                path,
                .default_dir,
            ) catch |err| if (err != error.PathAlreadyExists) return err;
        }
        const dir = try gpa.print("{s}/{s}", .{ root, parent });
        if (isLink(io, dir)) return t.fail("symlink in command parent: {s}", .{parent});
        Dir.cwd().createDir(
            io,
            dir,
            .default_dir,
        ) catch |err| if (err != error.PathAlreadyExists) return err;
        try Dir.cwd().setFilePermissions(
            io,
            dir,
            .fromMode(@intCast(directory.mode & 0o7777)),
            .{},
        );
        const target = try gpa.print("{s}/{s}", .{ dir, std.fs.path.basename(name) });
        if (Dir.cwd().statFile(io, target, .{ .follow_symlinks = false })) |_| {
            return t.fail("test client replaces a production command: {s}", .{name});
        } else |_| {}
        try Dir.cwd().symLink(io, entry.link, target, .{});
    }
}

fn isLink(io: Io, path: []const u8) bool {
    const stat = Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return false;
    return stat.kind == .sym_link;
}

/// Member is a tar member as compare weighs it.
const Member = struct {
    name: []const u8,
    /// kind is ustar's type flag, '0' for a regular file.
    kind: u8,
    mode: u64,
    uid: u64,
    gid: u64,
    link: []const u8,
    size: u64,
    /// sha256 is a regular file's contents' digest.
    sha256: [64]u8 = @splat(' '),

    fn same(a: Member, b: Member) bool {
        return a.kind == b.kind and a.mode == b.mode and a.uid == b.uid and a.gid == b.gid and
            mem.eql(u8, a.link, b.link) and mem.eql(u8, &a.sha256, &b.sha256);
    }
};

/// Archive reads a ustar or pax archive's members, as images' tars are.
const Archive = struct {
    file: Io.File,
    reader: Io.File.Reader,
    buffer: [64 << 10]u8 = undefined,
    pending: u64 = 0,

    fn open(io: Io, path: []const u8) !*Archive {
        const a = try std.heap.page_allocator.create(Archive);
        a.file = try Dir.cwd().openFile(io, path, .{});
        a.reader = a.file.reader(io, &a.buffer);
        a.pending = 0;
        return a;
    }

    fn close(a: *Archive, io: Io) void {
        a.file.close(io);
        std.heap.page_allocator.destroy(a);
    }

    fn next(a: *Archive, gpa: Allocator) !?Member {
        const r = &a.reader.interface;
        try r.discardAll64(a.pending);
        a.pending = 0;
        var long_name: ?[]const u8 = null;
        var long_link: ?[]const u8 = null;
        var pax_size: ?u64 = null;
        while (true) {
            var block: [512]u8 = undefined;
            r.readSliceAll(&block) catch |err| switch (err) {
                error.EndOfStream => return null,
                else => return err,
            };
            if (mem.allEqual(u8, &block, 0)) return null;
            try checksum(&block);
            const size = try number(block[124..136]);
            const padded = mem.alignForward(u64, size, 512);
            const kind = if (block[156] == 0) '0' else block[156];
            switch (kind) {
                'x', 'L', 'K', 'g' => {
                    if (size > 1 << 20) return error.BadTar;
                    const data = try gpa.alloc(u8, @intCast(size));
                    try r.readSliceAll(data);
                    try r.discardAll64(padded - size);
                    switch (kind) {
                        'L' => long_name = mem.trimEnd(u8, data, "\x00"),
                        'K' => long_link = mem.trimEnd(u8, data, "\x00"),
                        'x' => try pax(data, &long_name, &long_link, &pax_size),
                        else => {},
                    }
                    continue;
                },
                else => {},
            }
            const short = cString(block[0..100]);
            const prefix = if (mem.eql(u8, block[257..262], "ustar"))
                cString(block[345..500])
            else
                "";
            const name = long_name orelse if (prefix.len > 0)
                try gpa.print("{s}/{s}", .{ prefix, short })
            else
                try gpa.dupe(u8, short);
            const link = long_link orelse try gpa.dupe(u8, cString(block[157..257]));
            const body = pax_size orelse size;
            a.pending = mem.alignForward(u64, body, 512);
            var clean = name;
            if (mem.startsWith(u8, clean, "./")) clean = clean[2..];
            clean = mem.trimEnd(u8, clean, "/");
            return .{
                .name = clean,
                .kind = kind,
                .mode = try octal(block[100..108]),
                .uid = try octal(block[108..116]),
                .gid = try octal(block[116..124]),
                .link = link,
                .size = body,
            };
        }
    }

    /// contents reads a member next returned, at most limit bytes.
    fn contents(a: *Archive, gpa: Allocator, m: Member, limit: u64) ![]const u8 {
        if (m.size > limit) return error.BadTar;
        const data = try gpa.alloc(u8, @intCast(m.size));
        try a.reader.interface.readSliceAll(data);
        a.pending -= m.size;
        return data;
    }

    fn hash(a: *Archive, m: *Member) !void {
        var h = Sha256.init(.{});
        var left = m.size;
        var chunk: [64 << 10]u8 = undefined;
        while (left > 0) {
            const n: usize = @intCast(@min(left, chunk.len));
            try a.reader.interface.readSliceAll(chunk[0..n]);
            h.update(chunk[0..n]);
            left -= n;
        }
        a.pending -= m.size;
        m.sha256 = std.fmt.bytesToHex(h.finalResult(), .lower);
    }
};

fn pax(data: []const u8, name: *?[]const u8, link: *?[]const u8, size: *?u64) !void {
    var rest = data;
    while (rest.len > 0) {
        const space = mem.findScalar(u8, rest, ' ') orelse return error.BadTar;
        const length = std.fmt.parseInt(usize, rest[0..space], 10) catch return error.BadTar;
        if (length <= space + 1 or length > rest.len or
            rest[length - 1] != '\n') return error.BadTar;
        const record = rest[space + 1 .. length - 1];
        rest = rest[length..];
        const equals = mem.findScalar(u8, record, '=') orelse return error.BadTar;
        const key = record[0..equals];
        const value = record[equals + 1 ..];
        if (mem.eql(u8, key, "path")) name.* = value;
        if (mem.eql(u8, key, "linkpath")) link.* = value;
        if (mem.eql(
            u8,
            key,
            "size",
        )) size.* = std.fmt.parseInt(u64, value, 10) catch return error.BadTar;
    }
}

fn octal(bytes: []const u8) !u64 {
    const digits = mem.trim(u8, bytes, " \x00");
    if (digits.len == 0) return 0;
    return std.fmt.parseInt(u64, digits, 8) catch error.BadTar;
}

/// number is a header's size: octal, or GNU's base-256 for large ones.
fn number(bytes: []const u8) !u64 {
    if (bytes[0] & 0x80 == 0) return octal(bytes);
    if (bytes[0] != 0x80 or !mem.allEqual(u8, bytes[1..4], 0)) return error.BadTar;
    return mem.readInt(u64, bytes[4..12], .big);
}

fn cString(bytes: []const u8) []const u8 {
    return bytes[0 .. mem.findScalar(u8, bytes, 0) orelse bytes.len];
}

/// checksum refuses a header whose sum, its own field read as spaces, differs.
fn checksum(block: *const [512]u8) !void {
    var sum: u64 = 0;
    for (block, 0..) |b, i| sum += if (i >= 148 and i < 156) ' ' else b;
    if (try octal(block[148..156]) != sum) return error.BadTar;
}

/// members reads every member of the tar at path; a later member of a name
/// replaces an earlier one, as extraction does.
fn members(t: *Tool, path: []const u8, hashed: bool) !std.array_hash_map.String(Member) {
    var out: std.array_hash_map.String(Member) = .empty;
    var archive = Archive.open(
        t.io,
        path,
    ) catch |err| return t.fail("{s}: {s}", .{ path, @errorName(err) });
    defer archive.close(t.io);
    while (archive.next(t.gpa) catch |err| return t.fail(
        "{s}: {s}",
        .{ path, @errorName(err) },
    )) |entry| {
        var m = entry;
        if (hashed and m.kind == '0') try archive.hash(&m);
        // Linux ignores a symlink's permission bits; its owner and target count.
        if (m.kind == '2') m.mode = 0o777;
        try out.put(t.gpa, m.name, m);
    }
    return out;
}

/// compare refuses a test image whose dependencies changed what production
/// runs: service policies, accounts, machine-wide policy, runtime files,
/// or added configuration. Test clients may only add their own files.
pub fn compare(t: *Tool, f: Form, arch: []const u8) !void {
    const gpa = t.gpa;
    const base = t.variable("BUILD") orelse try gpa.print("build/{s}", .{arch});
    const before = t.variable("PRODUCTION_OUT") orelse try gpa.print("{s}/{s}", .{ base, f.name });
    const after = t.variable("TEST_OUT") orelse try gpa.print(
        "{s}/native-test-{s}",
        .{ base, f.name },
    );
    try compareDirs(t, f.name, before, after, try t.bootPlan(f));
    try t.say("native-tests: production service policies, accounts and runtime payload match", .{});
}

/// compareDirs compares the production build before with the test build
/// after, for the boot plan's drivers.
fn compareDirs(
    t: *Tool,
    form: []const u8,
    before: []const u8,
    after: []const u8,
    plan: plans.Plan,
) !void {
    const gpa = t.gpa;
    // Generated records legitimately identify a different form and root.
    for ([_][]const u8{ "etc/sv", "etc/werewolf/allow" }) |directory| {
        const one = try tree(t, try gpa.print("{s}/ro/{s}", .{ before, directory }));
        const two = try tree(t, try gpa.print("{s}/ro/{s}", .{ after, directory }));
        if (!mem.eql(
            u8,
            one,
            two,
        )) return t.fail("native tests changed production {s}", .{directory});
    }
    for ([_][]const u8{ "pledge", "net", "weaknesses" }) |name| {
        const path = "meta/usr/share/werewolf/";
        if (!mem.eql(u8, try read(t, before, path, name), try read(t, after, path, name)))
            return t.fail("native tests changed production {s}", .{name});
    }
    for ([_][]const u8{ "passwd", "group" }) |name| {
        const path = "ro/usr/share/werewolf/etc/";
        if (!mem.eql(u8, try read(t, before, path, name), try read(t, after, path, name)))
            return t.fail("native tests changed account identities", .{});
    }
    var a = try members(t, try gpa.print("{s}/rootfs.tar", .{before}), true);
    var b = try members(t, try gpa.print("{s}/rootfs.tar", .{after}), true);
    const overlay_a = try members(t, try gpa.print("{s}/overlay.tar", .{before}), true);
    const overlay_b = try members(t, try gpa.print("{s}/overlay.tar", .{after}), true);
    // Compare what is mounted: form files take precedence over package files.
    for (overlay_a.keys(), overlay_a.values()) |k, v| try a.put(gpa, k, v);
    for (overlay_b.keys(), overlay_b.values()) |k, v| try b.put(gpa, k, v);
    try comparePayload(t, form, a, b, overlay_b, plan);
}

fn read(t: *Tool, root: []const u8, path: []const u8, name: []const u8) ![]const u8 {
    const full = try t.gpa.print("{s}/{s}{s}", .{ root, path, name });
    return Dir.cwd().readFileAlloc(t.io, full, t.gpa, .limited(16 << 20)) catch |err|
        t.fail("{s}: {s}", .{ full, @errorName(err) });
}

/// tree lists a directory's files and links, with digests and targets.
fn tree(t: *Tool, path: []const u8) ![]const u8 {
    const io = t.io;
    var dir = Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return "",
        else => return err,
    };
    defer dir.close(io);
    var entries: std.ArrayList([]const u8) = .empty;
    var walker = try dir.walk(t.gpa);
    defer walker.deinit();
    while (try walker.next(io)) |entry| switch (entry.kind) {
        .sym_link => {
            var buffer: [Dir.max_path_bytes]u8 = undefined;
            const link = buffer[0..try dir.readLink(io, entry.path, &buffer)];
            try entries.append(t.gpa, try t.gpa.print("{s}\x00link\x00{s}", .{ entry.path, link }));
        },
        .file => {
            const full = try t.gpa.print("{s}/{s}", .{ path, entry.path });
            try entries.append(t.gpa, try t.gpa.print("{s}\x00file\x00{s}", .{
                entry.path, &try tests.hexDigest(io, full),
            }));
        },
        else => {},
    };
    mem.sort([]const u8, entries.items, {}, tests.lessThan);
    return mem.join(t.gpa, "\n", entries.items);
}

// A plan's prune lengthens the prune list; a production file it named
// would be missing, which comparePayload refuses.
const changed_metadata = [_][]const u8{
    "etc/runit/2",                "etc/apk/world",              "usr/share/werewolf/form",
    "usr/share/werewolf/overlay", "usr/share/werewolf/release", "etc/apko.json",
    "etc/ld.so.cache",            "lib/apk/db/installed",       "lib/apk/db/scripts.tar",
    "lib/apk/db/triggers",        "usr/lib/apk/db/installed",   "usr/lib/apk/db/scripts.tar",
    "usr/lib/apk/db/triggers",    "usr/share/werewolf/prune",
};

const shells = [_][]const u8{ "sh", "ash", "bash", "dash", "busybox", "zsh", "ksh", "fish" };

/// comparePayload is compare's decision over the mounted files before (a)
/// and after (b), and the test overlay.
fn comparePayload(
    t: *Tool,
    name: []const u8,
    a: std.array_hash_map.String(Member),
    b: std.array_hash_map.String(Member),
    overlay_b: std.array_hash_map.String(Member),
    plan: plans.Plan,
) !void {
    const gpa = t.gpa;
    // The selected overlay moves from the production leaf to the generated
    // test leaf. Its parent retains the original, unselected declaration.
    const parent_spec = try gpa.print("usr/share/werewolf/forms/{s}/form.yaml", .{name});
    const variant_selection: []const u8 = t.variable("VARIANTS") orelse "";
    for (a.keys(), a.values()) |path, record| {
        if (tests.has(&changed_metadata, path)) continue;
        if (variant_selection.len > 0 and mem.eql(u8, path, parent_spec)) continue;
        const other = b.get(path) orelse return t.fail(
            "native dependency changed runtime file: {s}",
            .{path},
        );
        if (!record.same(other)) return t.fail(
            "native dependency changed runtime file: {s}",
            .{path},
        );
    }
    for ([_][]const u8{ "bin", "usr/bin" }) |directory| for (shells) |shell| {
        const path = try gpa.print("{s}/{s}", .{ directory, shell });
        if (b.contains(path) and !a.contains(path))
            return t.fail("native dependency introduced a shell: {s}", .{path});
    };
    // New configuration can change a service just as replacing a file can.
    // Permit only the declared clients, their launcher and inert form metadata.
    var additions: std.ArrayList([]const u8) = .empty;
    try additions.appendSlice(
        gpa,
        &.{ "usr/lib/werewolf/test-stage", "usr/share/werewolf/test-image" },
    );
    for (plan.drivers) |d| {
        try additions.append(gpa, try gpa.print("usr/lib/werewolf/{s}", .{d.name}));
        try additions.append(gpa, try gpa.print("usr/share/werewolf/tests/{s}/service", .{d.name}));
        if (d.probes != null)
            try additions.append(
                gpa,
                try gpa.print("usr/share/werewolf/tests/{s}/probes.json", .{d.name}),
            );
        for (d.allow) |grant| {
            const colon = mem.findScalar(u8, grant, ':').?;
            const allowance = try gpa.print("etc/runtime-hardening/allow/{s}/{s}/{s}", .{
                d.name, grant[0..colon], grant[colon + 1 ..],
            });
            try additions.append(gpa, allowance);
            const file = overlay_b.get(allowance) orelse return t.fail(
                "invalid native runtime allowance file",
                .{},
            );
            const empty = std.fmt.bytesToHex(blk: {
                var out: [Sha256.digest_length]u8 = undefined;
                Sha256.hash("", &out, .{});
                break :blk out;
            }, .lower);
            if (file.kind != '0' or !mem.eql(u8, &file.sha256, &empty))
                return t.fail("invalid native runtime allowance file", .{});
        }
    }
    const metadata = try gpa.print("usr/share/werewolf/forms/native-test-{s}", .{name});
    for (overlay_b.keys()) |path| {
        if (a.contains(path) or tests.has(additions.items, path) or
            mem.eql(u8, path, metadata)) continue;
        if (mem.startsWith(u8, path, metadata) and path[metadata.len] == '/') continue;
        const parent = for (additions.items) |addition| {
            if (mem.startsWith(u8, addition, path) and addition.len > path.len and
                addition[path.len] == '/')
                break true;
        } else false;
        if (!parent) return t.fail("native instrumentation added runtime overlay: {s}", .{path});
    }
    for (plan.drivers) |d| for (d.run) |executable| {
        const m = b.get(executable[1..]) orelse return t.fail(
            "native test client missing from image: {s}",
            .{executable},
        );
        if (m.kind != '0' and m.kind != '1' and m.kind != '2')
            return t.fail("native test client missing from image: {s}", .{executable});
    };
}

const testing = std.testing;

test "production packages are frozen from the actual image, or refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = undefined;
    var t = tests.testTool(a, &env);
    const installed = "P:python-3.15\nV:3.15.0_git20261010-r2000\n\nP:libx11\nV:1.8.13-r7\n\nP:l" ++
        "ibLLVM-19\nV:19.1.7-r30\n\n";
    try testing.expectEqualDeep(@as([]const []const u8, &.{
        "libLLVM-19=19.1.7-r30", "libx11=1.8.13-r7", "python-3.15=3.15.0_git20261010-r2000",
    }), try packageVersions(&t, installed));
    for ([_][]const u8{
        "",
        "P:python-3.15\n",
        "P:bad/name\nV:1-r0\n",
        "P:python-3.15\nV:1-r0\n\nP:python-3.15\nV:2-r0\n",
        "P:a\nP:b\nV:1\n",
    }) |bad| try testing.expectError(error.Refused, packageVersions(&t, bad));
}

const Entry = struct {
    name: []const u8,
    kind: u8 = '0',
    mode: u32 = 0o644,
    uid: u32 = 0,
    data: []const u8 = "",
    link: []const u8 = "",
};

/// writeTar writes entries, in order, as a ustar archive.
fn writeTar(io: Io, dir: Dir, path: []const u8, entries: []const Entry) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    for (entries) |e| {
        var h: [512]u8 = @splat(0);
        @memcpy(h[0..e.name.len], e.name);
        _ = try std.mem.print(h[100..107], "{o:0>7}", .{e.mode});
        _ = try std.mem.print(h[108..115], "{o:0>7}", .{e.uid});
        _ = try std.mem.print(h[116..123], "{o:0>7}", .{0});
        _ = try std.mem.print(h[124..135], "{o:0>11}", .{e.data.len});
        _ = try std.mem.print(h[136..147], "{o:0>11}", .{0});
        h[156] = e.kind;
        @memcpy(h[157..][0..e.link.len], e.link);
        @memcpy(h[257..263], "ustar\x00");
        @memcpy(h[263..265], "00");
        @memset(h[148..156], ' ');
        var sum: u32 = 0;
        for (h) |b| sum += b;
        _ = try std.mem.print(h[148..155], "{o:0>6}\x00", .{sum});
        try out.appendSlice(testing.allocator, &h);
        try out.appendSlice(testing.allocator, e.data);
        try out.appendNTimes(testing.allocator, 0, (512 - e.data.len % 512) % 512);
    }
    try out.appendNTimes(testing.allocator, 0, 1024);
    try dir.writeFile(io, .{ .sub_path = path, .data = out.items });
}

/// Builds holds a production build and its test build in a scratch
/// directory, as compare finds them.
const Builds = struct {
    tmp: testing.TmpDir,
    root: []const u8,
    t: Tool,
    plan: plans.Plan,

    const rootfs = [_]Entry{.{ .name = "usr/bin/postgres", .data = "production database" }};
    const clients = rootfs ++ [_]Entry{
        .{ .name = "usr/bin/psql", .data = "client" },
        .{ .name = "usr/lib/werewolf/sh-shim", .data = "command shim" },
    };
    const overlay = [_]Entry{.{ .name = "usr/lib/werewolf/init", .data = "production init" }};
    const instrumented = overlay ++
        [_]Entry{.{ .name = "usr/lib/werewolf/test-postgres-policy", .data = "test driver" }};

    fn init(b: *Builds, a: Allocator, env: *std.process.Environ.Map) !void {
        b.tmp = testing.tmpDir(.{});
        b.t = tests.testTool(a, env);
        b.root = try b.tmp.dir.realPathFileAlloc(b.t.io, ".", a);
        b.plan = .{ .drivers = &.{.{
            .name = "test-postgres-policy",
            .source = "probes.zig",
            .mode = "probes",
            .run = &.{"/usr/bin/psql"},
            .seed = &.{"a"},
            .probes = .null,
        }} };
        for ([_][]const u8{ "base", "native-test-base" }) |build| {
            for ([_][]const u8{
                "ro/etc/sv/postgres/service",         "ro/etc/werewolf/allow/jit",
                "ro/usr/share/werewolf/etc/passwd",   "ro/usr/share/werewolf/etc/group",
                "meta/usr/share/werewolf/pledge",     "meta/usr/share/werewolf/net",
                "meta/usr/share/werewolf/weaknesses",
            }) |name| try b.file(
                try a.print("{s}/{s}", .{ build, name }),
                try a.print("{s}\n", .{name}),
            );
        }
        try b.tar("base/rootfs.tar", &rootfs);
        try b.tar("base/overlay.tar", &overlay);
        try b.tar("native-test-base/rootfs.tar", &clients);
        try b.tar("native-test-base/overlay.tar", &instrumented);
    }

    fn file(b: *Builds, path: []const u8, data: []const u8) !void {
        try b.tmp.dir.createDirPath(b.t.io, std.fs.path.dirname(path).?);
        try b.tmp.dir.writeFile(b.t.io, .{ .sub_path = path, .data = data });
    }

    fn tar(b: *Builds, path: []const u8, entries: []const Entry) !void {
        try writeTar(b.t.io, b.tmp.dir, path, entries);
    }

    fn compare(b: *Builds) !void {
        return b.compareAt("base", "native-test-base");
    }

    fn compareAt(b: *Builds, before: []const u8, after: []const u8) !void {
        const a = b.t.gpa;
        return compareDirs(&b.t, "base", try a.print("{s}/{s}", .{ b.root, before }), try a.print(
            "{s}/{s}",
            .{ b.root, after },
        ), b.plan);
    }

    fn refused(b: *Builds, why: []const u8) !void {
        try testing.expectError(error.Refused, b.compare());
        if (mem.find(u8, b.t.why, why) == null) {
            std.debug.print("refused for {s}, not {s}\n", .{ b.t.why, why });
            return error.TestUnexpectedResult;
        }
    }
};

test "test clients may add files, never change what production runs" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = undefined;
    var b: Builds = undefined;
    try b.init(a, &env);
    defer b.tmp.cleanup();
    try b.compare();
    try b.tar("native-test-base/rootfs.tar", &Builds.rootfs);
    try b.refused("client missing from image: /usr/bin/psql");
    try b.tar("native-test-base/rootfs.tar", &Builds.clients);
    // A change the overlay hides from the package view is still a change.
    try b.tar("native-test-base/overlay.tar", &(Builds.instrumented ++ [_]Entry{
        .{ .name = "usr/bin/postgres", .data = "changed" },
    }));
    try b.refused("runtime file: usr/bin/postgres");
    try b.tar(
        "native-test-base/overlay.tar",
        &[_]Entry{.{ .name = "usr/lib/werewolf/init", .data = "changed init" }},
    );
    try b.refused("runtime file: usr/lib/werewolf/init");
    try b.tar("native-test-base/overlay.tar", &Builds.instrumented);
    try b.tar(
        "native-test-base/rootfs.tar",
        &[_]Entry{.{ .name = "usr/bin/postgres", .data = "changed server" }},
    );
    try b.refused("runtime file: usr/bin/postgres");
    for ([_][]const u8{ "bin/sh", "bin/ash", "usr/bin/dash", "usr/bin/busybox" }) |shell| {
        try b.tar(
            "native-test-base/rootfs.tar",
            &(Builds.clients ++ [_]Entry{.{ .name = shell, .data = "shell" }}),
        );
        try b.refused("introduced a shell");
    }
    try b.tar("native-test-base/rootfs.tar", &Builds.clients);
    try b.tar("native-test-base/overlay.tar", &(Builds.instrumented ++ [_]Entry{
        .{
            .name = "etc/postgresql/conf.d/test.conf",
            .data = "changed behavior without replacing a file",
        },
    }));
    try b.refused("added runtime overlay");
    try b.tar("native-test-base/overlay.tar", &Builds.instrumented);
    for ([_][]const u8{
        "ro/etc/sv/postgres/service",     "ro/usr/share/werewolf/etc/passwd",
        "meta/usr/share/werewolf/pledge",
    }) |name| {
        const path = try a.print("native-test-base/{s}", .{name});
        try b.file(path, "weakened");
        try testing.expectError(error.Refused, b.compare());
        try b.file(path, try a.print("{s}\n", .{name}));
    }
    try b.compare();
    // Pruning what a client brought lengthens the list; pruning production is refused.
    const prune = "usr/share/werewolf/prune";
    try b.tar("base/rootfs.tar", &(Builds.rootfs ++ [_]Entry{.{ .name = prune, .data = "a\n" }}));
    try b.tar("native-test-base/rootfs.tar", &(Builds.clients ++ [_]Entry{
        .{ .name = prune, .data = "a\nusr/bin/scp\n" },
    }));
    try b.compare();
    try b.tar("native-test-base/rootfs.tar", &[_]Entry{
        .{ .name = "usr/bin/psql", .data = "client" },
        .{ .name = prune, .data = "a\nusr/bin/postgres\n" },
    });
    try b.refused("runtime file: usr/bin/postgres");
    try b.tar("base/rootfs.tar", &Builds.rootfs);
    try b.tar("native-test-base/rootfs.tar", &Builds.clients);
    // Explicit IPE build directories are compared the same way.
    try b.compareAt("base", "native-test-base");
    try b.file("native-test-base/ro/etc/sv/postgres/service", "weakened");
    try b.refused("production etc/sv");
}

test "only the declared driver's runtime grant may be added, and empty" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = undefined;
    var b: Builds = undefined;
    try b.init(a, &env);
    defer b.tmp.cleanup();
    var driver = b.plan.drivers[0];
    driver.allow = &.{"python:native"};
    b.plan.drivers = &.{driver};
    const grant = "etc/runtime-hardening/allow/test-postgres-policy/python/native";
    try b.refused("invalid native runtime allowance file");
    try b.tar(
        "native-test-base/overlay.tar",
        &(Builds.instrumented ++ [_]Entry{.{ .name = grant }}),
    );
    try b.compare();
    try b.tar(
        "native-test-base/overlay.tar",
        &(Builds.instrumented ++ [_]Entry{.{ .name = grant, .data = "unexpected content" }}),
    );
    try b.refused("invalid native runtime allowance file");
    try b.tar("native-test-base/overlay.tar", &(Builds.instrumented ++ [_]Entry{
        .{ .name = grant },
        .{ .name = "etc/runtime-hardening/allow/all/python/native" },
    }));
    try b.refused("added runtime overlay");
}

test "owners, directory modes and command aliases are production's" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = undefined;
    var b: Builds = undefined;
    try b.init(a, &env);
    defer b.tmp.cleanup();
    const usr: Entry = .{ .name = "usr", .kind = '5', .mode = 0o755 };
    try b.tar("base/rootfs.tar", &[_]Entry{ usr, .{ .name = "usr/bin/postgres", .data = "x" } });
    for ([_][2]Entry{
        .{ usr, .{ .name = "usr/bin/postgres", .uid = 123, .data = "x" } },
        .{
            .{ .name = "usr", .kind = '5', .mode = 0o777 },
            .{ .name = "usr/bin/postgres", .data = "x" },
        },
    }) |entries| {
        try b.tar("native-test-base/rootfs.tar", &(entries ++ Builds.clients[1..].*));
        try b.refused("runtime file: usr");
    }
    // A library's command, replacing a package's alias, is refused...
    const bin: Entry = .{ .name = "usr/bin", .kind = '5', .mode = 0o755 };
    const alias: Entry = .{
        .name = "usr/bin/clear",
        .kind = '2',
        .mode = 0o777,
        .link = "/bin/busybox",
    };
    try b.tar("base/rootfs.tar", &(Builds.rootfs ++ [_]Entry{ bin, alias }));
    try b.tar("native-test-base/rootfs.tar", &(Builds.clients ++ [_]Entry{
        bin, .{ .name = "usr/bin/clear", .mode = 0o755, .data = "ncurses" },
    }));
    try b.refused("runtime file: usr/bin/clear");
    // ...but the test form keeps the alias as production made it.
    const generated = try a.print("{s}/clients", .{b.root});
    try commandLinks(&b.t, try a.print("{s}/base", .{b.root}), generated);
    var link: [64]u8 = undefined;
    const target = link[0..try b.tmp.dir.readLink(b.t.io, "clients/usr/bin/clear", &link)];
    try testing.expectEqualStrings("/bin/busybox", target);
    try testing.expectError(
        error.Refused,
        commandLinks(&b.t, try a.print("{s}/base", .{b.root}), generated),
    );
    try testing.expect(mem.find(
        u8,
        b.t.why,
        "replaces a production command: usr/bin/clear",
    ) != null);
    try b.tar("native-test-base/overlay.tar", &(Builds.instrumented ++ [_]Entry{
        bin, .{ .name = "usr/bin/clear", .kind = '2', .mode = 0o755, .link = "/bin/busybox" },
    }));
    try b.compare();
    for ([_]Entry{
        .{ .name = "usr/bin/clear", .kind = '2', .uid = 123, .link = "/bin/busybox" },
        .{ .name = "usr/bin/clear", .kind = '2', .link = "/usr/bin/changed" },
    }) |changed| {
        try b.tar(
            "native-test-base/overlay.tar",
            &(Builds.instrumented ++ [_]Entry{ bin, changed }),
        );
        try b.refused("runtime file: usr/bin/clear");
    }
}
