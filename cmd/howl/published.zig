//! published fetches the forms a build takes by name from werewolf's
//! repository (docs/design/custom-updates.md): each NAME-form, checked
//! against the index the packages key signs, unpacked into
//! build/published/ARCH/NAME. A form given as a path is the caller's own;
//! the names it is built on and takes are published too. See README.md.

const std = @import("std");
const apk = @import("apk");
const compose = @import("compose");
const forms = @import("form");
const package = @import("package");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const Why = howl.Why;

/// arch is set once a run, by main, before any chain is read: a run builds
/// from published forms for arch, or, when null (--build, or make's _build
/// without --published), from the tree's forms/.
pub var arch: ?howl.Arch = null;

/// index is the repository's packages for arch, fetched once a run.
var index: ?[]const apk.Record = null;

/// warned are the forms a run has warned are not published, so it warns once.
var warned: std.array_hash_map.String(void) = .empty;

const max_index = 64 << 20;
const max_package = 16 << 20;

/// choose sets arch from a run's arguments: published unless --build is
/// given, or, for make's _build, unless --published is not.
pub fn choose(verb: []const u8, args: []const []const u8) void {
    var a = howl.hostArch();
    var published = !mem.eql(u8, verb, "_build");
    for (args, 0..) |x, i| {
        if (mem.eql(u8, x, "--published")) published = true;
        if (mem.eql(u8, x, "--build") and !mem.eql(u8, verb, "_build")) published = false;
        if (mem.eql(u8, x, "--arch") and i + 1 < args.len)
            a = howl.archName(args[i + 1]) orelse a;
    }
    arch = if (published) a else null;
}

/// names returns the directory names in ref's chain resolve in: forms/, or
/// for a published build of arch, the published forms ref takes, fetched.
/// pins, NAME=VERSION each, fix their versions (a frozen build's lock);
/// otherwise each is the newest for compose's format.
pub fn names(
    io: Io,
    gpa: Allocator,
    for_arch: ?howl.Arch,
    ref: []const u8,
    pins: []const []const u8,
    why: *Why,
) ![]const u8 {
    const a = for_arch orelse return "forms";
    const dir = try gpa.print("build/published/{t}", .{a});
    const records = try fetchIndex(io, gpa, a, why);
    // Every program depends on the format's package: without it, nothing
    // published installs.
    for (records) |r| {
        if (mem.eql(u8, r.name, compose.format_package)) break;
    } else return why.refuse(
        "werewolf's repository has no {s} yet, this checkout's format: CI publishes it " ++
            "once main's checks pass; --build builds from this checkout until then",
        .{compose.format_package},
    );
    var queue: std.ArrayList([]const u8) = .empty;
    if (mem.findScalar(u8, ref, '/') == null) {
        try queue.append(gpa, ref);
    } else {
        var f: forms.Failure = .{};
        const own = forms.load(io, gpa, Dir.cwd(), ref, &f) catch |err| switch (err) {
            error.Form => return why.refuse("{s}", .{f.text}),
            else => |e| return e,
        };
        try queue.appendSlice(gpa, try named(gpa, own));
    }
    var done: std.array_hash_map.String(void) = .empty;
    while (queue.pop()) |name| {
        // A name becomes a path here and a URL there: only a form's name will do.
        if (!forms.isName(name)) return why.refuse(
            "{s}: not a form's name (a-z, 0-9 and -)",
            .{name},
        );
        if ((try done.getOrPut(gpa, name)).found_existing) continue;
        try fetchForm(io, gpa, a, dir, records, name, pins, why);
        var f: forms.Failure = .{};
        const fm = forms.loadIn(io, gpa, Dir.cwd(), dir, name, &f) catch |err| switch (err) {
            error.Form => return why.refuse("{s}", .{f.text}),
            else => |e| return e,
        };
        try queue.appendSlice(gpa, try named(gpa, fm));
    }
    return dir;
}

/// named returns the forms fm is built on and takes, by name.
fn named(gpa: Allocator, fm: forms.Form) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    if (fm.spec.get("base")) |b| try out.append(gpa, b.scalar.text);
    try out.appendSlice(gpa, try fm.items(gpa, "with"));
    return out.items;
}

/// fetchIndex returns the repository's packages for a, its index checked
/// against the packages key howl carries.
fn fetchIndex(io: Io, gpa: Allocator, a: howl.Arch, why: *Why) ![]const apk.Record {
    if (index) |i| return i;
    const url = try gpa.print("{s}/{t}/APKINDEX.tar.gz", .{ package.repository, a });
    const data = try get(io, gpa, url, max_index, why);
    const key = try apk.parseKey(gpa, package.repository_pem);
    const trusted = [_]apk.Trusted{.{ .name = package.repository_key, .key = key }};
    index = apk.records(gpa, &trusted, data) catch |err|
        return why.refuse("{s}: {t}: not as werewolf's packages key signs it", .{ url, err });
    return index.?;
}

/// fetchForm unpacks NAME-form into dir/name, unless the version there is
/// the one wanted already.
fn fetchForm(
    io: Io,
    gpa: Allocator,
    a: howl.Arch,
    dir: []const u8,
    records: []const apk.Record,
    name: []const u8,
    pins: []const []const u8,
    why: *Why,
) !void {
    const pkg = try gpa.print("{s}-form", .{name});
    const into = try gpa.print("{s}/{s}", .{ dir, name });
    const mark = try gpa.print("{s}/.{s}.version", .{ dir, name });
    const want = pick(
        records,
        pkg,
        pins,
    ) orelse return fromTree(io, gpa, name, pkg, into, mark, why);
    const had = Dir.cwd().readFileAlloc(io, mark, gpa, .limited(256)) catch "";
    if (mem.eql(u8, had, want.version)) {
        if (Dir.cwd().access(io, into, .{})) |_| return else |_| {}
    }
    const url = try gpa.print("{s}/{t}/{s}-{s}.apk", .{ package.repository, a, pkg, want.version });
    const bytes = try get(io, gpa, url, max_package, why);
    const tar = apk.contents(gpa, bytes, want) catch |err|
        return why.refuse("{s}: {t}: not as the signed index lists it", .{ url, err });
    const tmp = try gpa.print("{s}/.{s}.tmp", .{ dir, name });
    try Dir.cwd().deleteTree(io, tmp);
    try Dir.cwd().createDirPath(io, tmp);
    const prefix = try gpa.print("usr/share/werewolf/forms/{s}/", .{name});
    try unpack(io, tar, prefix, tmp, url, why);
    try Dir.cwd().deleteTree(io, into);
    try Dir.cwd().rename(tmp, Dir.cwd(), into, io);
    try Dir.cwd().writeFile(io, .{ .sub_path = mark, .data = want.version });
}

/// fromTree takes forms/NAME from this checkout for a form the repository
/// does not have yet, as main's new forms are until CI publishes them: into
/// links to it, with no version mark, so the build counts it local
/// (fetched), and a machine made from it never updates it. It warns.
fn fromTree(
    io: Io,
    gpa: Allocator,
    name: []const u8,
    pkg: []const u8,
    into: []const u8,
    mark: []const u8,
    why: *Why,
) !void {
    const tree = try gpa.print("forms/{s}", .{name});
    Dir.cwd().access(io, try gpa.print("{s}/form.yaml", .{tree}), .{}) catch return why.refuse(
        "no published form {s}: werewolf's repository has no {s} for format {d}; " ++
            "a form of your own is a path (./{s}), and --build takes forms/{s}",
        .{ name, pkg, compose.format, name, name },
    );
    if (!(try warned.getOrPut(gpa, name)).found_existing) howl.say(
        io,
        "warning: {s} is not published yet ({s}): building ./forms/{s}, " ++
            "which a machine made now never updates; make it again once CI publishes it",
        .{ name, pkg, name },
    );
    Dir.cwd().deleteFile(io, mark) catch {};
    Dir.cwd().deleteTree(io, into) catch {};
    try Dir.cwd().createDirPath(io, std.fs.path.dirname(into).?);
    const abs = try std.fs.path.resolveAlloc(
        gpa,
        &.{ try std.process.currentPathAlloc(io, gpa), tree },
    );
    try Dir.cwd().symLink(io, abs, into, .{});
}

/// fetched reports whether form name in dir came from werewolf's
/// repository: it has a version mark, which fromTree's never has.
pub fn fetched(io: Io, gpa: Allocator, dir: []const u8, name: []const u8) bool {
    const mark = gpa.print("{s}/.{s}.version", .{ dir, name }) catch return false;
    Dir.cwd().access(io, mark, .{}) catch return false;
    return true;
}

/// pick returns pkg's record: the version pins name, or the newest for
/// compose's format. Versions are the commit's time, YYYYMMDD.HHMMSS-r0,
/// so the newest sorts last.
fn pick(records: []const apk.Record, pkg: []const u8, pins: []const []const u8) ?apk.Record {
    const pinned = for (pins) |p| {
        if (mem.cutPrefix(u8, p, pkg)) |rest| if (rest.len > 1 and rest[0] == '=') break rest[1..];
    } else null;
    var best: ?apk.Record = null;
    for (records) |r| {
        if (!mem.eql(u8, r.name, pkg)) continue;
        for (r.depends) |d| {
            if (mem.eql(u8, d, compose.format_package)) break;
        } else continue;
        if (pinned) |v| {
            if (mem.eql(u8, r.version, v)) return r;
            continue;
        }
        if (best == null or mem.order(u8, r.version, best.?.version) == .gt) best = r;
    }
    return best;
}

/// unpack writes the entries of tar under prefix into dir: directories,
/// files with their modes, links as links. A name that would leave dir is
/// refused.
fn unpack(
    io: Io,
    tar: []const u8,
    prefix: []const u8,
    dir: []const u8,
    url: []const u8,
    why: *Why,
) !void {
    var out = try Dir.cwd().openDir(io, dir, .{});
    defer out.close(io);
    var r: Io.Reader = .fixed(tar);
    var name_buf: [Dir.max_path_bytes]u8 = undefined;
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(
        &r,
        .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
    );
    while (try it.next()) |e| {
        const rel = mem.cutPrefix(u8, e.name, prefix) orelse continue;
        if (rel.len == 0) continue;
        if (!clean(rel)) return why.refuse(
            "{s}: {s}: not a name within the form",
            .{ url, e.name },
        );
        if (std.fs.path.dirname(rel)) |parent| try out.createDirPath(io, parent);
        switch (e.kind) {
            .directory => try out.createDirPath(io, rel),
            .file => {
                if (e.size > tar.len - r.seek) return error.UnexpectedEndOfStream;
                try out.writeFile(io, .{
                    .sub_path = rel,
                    .data = tar[r.seek..][0..@intCast(e.size)],
                    .flags = .{ .permissions = .fromMode(@intCast(e.mode & 0o777)) },
                });
            },
            .sym_link => try out.symLink(io, e.link_name, rel, .{}),
        }
    }
}

/// clean reports whether rel is a plain relative path: no empty, . or ..
/// parts.
fn clean(rel: []const u8) bool {
    var parts = mem.splitScalar(u8, mem.trimEnd(u8, rel, "/"), '/');
    while (parts.next()) |p| {
        if (p.len == 0 or mem.eql(u8, p, ".") or mem.eql(u8, p, "..")) return false;
    }
    return true;
}

/// get fetches url, of at most limit bytes.
fn get(io: Io, gpa: Allocator, url: []const u8, limit: usize, why: *Why) ![]const u8 {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    var body: Io.Writer.Allocating = .init(gpa);
    const res = client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &body.writer,
    }) catch |err|
        return why.refuse("{s}: {t}; --build takes this checkout's forms instead", .{ url, err });
    if (res.status != .ok)
        return why.refuse("{s}: HTTP {d}", .{ url, @backingInt(res.status) });
    if (body.written().len > limit) return why.refuse("{s}: more than {d} bytes", .{ url, limit });
    return body.written();
}

const testing = std.testing;

test pick {
    const sha: [20]u8 = @splat(0);
    const f1: []const []const u8 = &.{"werewolf-format1"};
    const f2: []const []const u8 = &.{"werewolf-format2"};
    const records = [_]apk.Record{
        .{ .name = "prod-form", .version = "20261009.100000-r0", .depends = f1, .sha1 = sha },
        .{ .name = "prod-form", .version = "20261009.120000-r0", .depends = f1, .sha1 = sha },
        .{ .name = "prod-form", .version = "20261010.090000-r0", .depends = f2, .sha1 = sha },
        .{ .name = "caddy-form", .version = "20261011.000000-r0", .depends = f1, .sha1 = sha },
    };
    if (compose.format != 1) return error.SkipZigTest;
    try testing.expectEqualStrings(
        "20261009.120000-r0",
        pick(&records, "prod-form", &.{}).?.version,
    );
    const pins: []const []const u8 = &.{
        "caddy-form=20261011.000000-r0",
        "prod-form=20261009.100000-r0",
    };
    try testing.expectEqualStrings(
        "20261009.100000-r0",
        pick(&records, "prod-form", pins).?.version,
    );
    try testing.expectEqual(null, pick(&records, "prod-form", &.{"prod-form=20261010.090000-r0"}));
    try testing.expectEqual(null, pick(&records, "nginx-form", &.{}));
}

test clean {
    try testing.expect(clean("rootfs/etc/sv/x/run"));
    try testing.expect(clean("rootfs/"));
    for ([_][]const u8{ "../x", "a/../b", "a//b", "./a", "/a" }) |p| try testing.expect(!clean(p));
}
