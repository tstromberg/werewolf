//! sys is what the release tool asks of its host: other programs, files,
//! HTTPS and the time. Tests answer programs and downloads through fake,
//! so no test runs gh, aws or howl or reaches the network.

const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Allocator = mem.Allocator;
const json = @import("json.zig");
const Json = json.Json;
const bd = @import("boot-download");
const prebuilt = @import("prebuilt");

pub const Sys = struct {
    io: Io,
    /// An arena: the tool runs once and exits.
    gpa: Allocator,
    /// The environment children get; a step may change it for those after.
    env: *std.process.Environ.Map,
    why: Why = .{},
    fake: ?Fake = null,
    /// log, when set, takes children's output: a form's own log file.
    log: ?File = null,

    /// refuse fails with a reason, which reason gives back.
    pub fn refuse(s: *Sys, comptime fmt: []const u8, args: anytype) error{Refused} {
        s.why.text = std.mem.print(&s.why.buf, fmt, args) catch "(reason too long)";
        return error.Refused;
    }

    /// reason says why err happened: a refusal's text, or the error's name.
    pub fn reason(s: *Sys, err: anyerror) []const u8 {
        return if (err == error.Refused) s.why.text else @errorName(err);
    }

    /// say writes one log line, to the form's log while one is open, else
    /// to stderr. Every line names its program.
    pub fn say(s: *Sys, comptime fmt: []const u8, args: anytype) void {
        var buf: [4096]u8 = undefined;
        const line = std.mem.print(&buf, fmt ++ "\n", args) catch return;
        (s.log orelse File.stderr()).writeStreamingAll(s.io, line) catch {};
    }

    pub fn getenv(s: *Sys, name: []const u8) ?[]const u8 {
        return s.env.get(name);
    }

    /// now is the time in seconds since the epoch.
    pub fn now(s: *Sys) i64 {
        return Io.Clock.real.now(s.io).toSeconds();
    }
};

pub const Why = struct {
    buf: [2048]u8 = undefined,
    text: []const u8 = "",
};

/// Fake answers what tests must not do for real. A null answer runs the
/// program, or fetches the URL, for real.
pub const Fake = struct {
    ctx: *anyopaque,
    run: *const fn (ctx: *anyopaque, s: *Sys, argv: []const []const u8) anyerror!?Result,
    get: *const fn (ctx: *anyopaque, s: *Sys, url: []const u8, limit: usize) anyerror!?Got,
    /// fetch writes url to path and says true, or says false to fetch it for real.
    fetch: *const fn (
        ctx: *anyopaque,
        s: *Sys,
        url: []const u8,
        path: []const u8,
        limit: u64,
        expected: ?Record,
    ) anyerror!bool,
};

pub const Got = union(enum) { missing, body: []const u8 };

pub const Result = struct {
    term: std.process.Child.Term,
    stdout: []const u8 = "",
    stderr: []const u8 = "",

    pub fn ok(r: Result) bool {
        return r.term == .exited and r.term.exited == 0;
    }

    pub const passed: Result = .{ .term = .{ .exited = 0 } };
};

pub const Capture = enum { none, stdout, both };

pub const Options = struct {
    capture: Capture = .none,
    env: ?*const std.process.Environ.Map = null,
};

/// exec runs argv and says how it ended, with its output if captured.
pub fn exec(s: *Sys, argv: []const []const u8, o: Options) !Result {
    if (s.fake) |f| if (try f.run(f.ctx, s, argv)) |r| return r;
    const env = o.env orelse s.env;
    switch (o.capture) {
        .both => {
            const r = try std.process.run(s.gpa, s.io, .{ .argv = argv, .environ_map = env });
            return .{ .term = r.term, .stdout = r.stdout, .stderr = r.stderr };
        },
        .stdout => {
            var child = try std.process.spawn(s.io, .{
                .argv = argv,
                .environ_map = env,
                .stdout = .pipe,
                .stderr = if (s.log) |l| .{ .file = l } else .inherit,
            });
            defer child.kill(s.io);
            var buf: [4096]u8 = undefined;
            var reader = child.stdout.?.readerStreaming(s.io, &buf);
            const out = try reader.interface.allocRemaining(s.gpa, .unlimited);
            return .{ .term = try child.wait(s.io), .stdout = out };
        },
        .none => {
            const to: std.process.SpawnOptions.StdIo = if (s.log) |l| .{ .file = l } else .inherit;
            var child = try std.process.spawn(s.io, .{
                .argv = argv,
                .environ_map = env,
                .stdout = to,
                .stderr = to,
            });
            defer child.kill(s.io);
            return .{ .term = try child.wait(s.io) };
        },
    }
}

/// run runs argv and refuses unless it exits 0.
pub fn run(s: *Sys, argv: []const []const u8, o: Options) !void {
    const r = try exec(s, argv, o);
    if (!r.ok()) return failed(s, argv, r);
}

/// output is what argv printed; it refuses unless argv exits 0.
pub fn output(s: *Sys, argv: []const []const u8) ![]const u8 {
    const r = try exec(s, argv, .{ .capture = .stdout });
    if (!r.ok()) return failed(s, argv, r);
    return r.stdout;
}

fn failed(s: *Sys, argv: []const []const u8, r: Result) error{Refused} {
    var buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    for (argv[0..@min(argv.len, 6)], 0..) |a, i| {
        if (i > 0) w.writeByte(' ') catch break;
        w.writeAll(a) catch break;
    }
    if (argv.len > 6) w.writeAll(" ...") catch {};
    return switch (r.term) {
        .exited => |code| s.refuse("command '{s}' exited {d}", .{ w.buffered(), code }),
        else => s.refuse("command '{s}' ended {f}", .{ w.buffered(), r.term }),
    };
}

/// lines splits a program's output as Python's splitlines does for it.
pub fn lines(s: *Sys, text: []const u8) ![]const []const u8 {
    var all: std.ArrayList([]const u8) = .empty;
    var it = mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (it.index == null and line.len == 0) break;
        try all.append(s.gpa, mem.trimEnd(u8, line, "\r"));
    }
    return all.items;
}

/// get is the body at url, at most limit bytes, or .missing for a 404.
pub fn get(s: *Sys, url: []const u8, limit: usize) !Got {
    if (s.fake) |f| if (try f.get(f.ctx, s, url, limit)) |g| return g;
    var client: std.http.Client = .{ .allocator = s.gpa, .io = s.io };
    defer client.deinit();
    const body = try s.gpa.alloc(u8, limit + 1);
    var w: Io.Writer = .fixed(body);
    const r = client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &w,
        .headers = .{ .user_agent = .{ .override = "Werewolf-form-images/1" } },
    }) catch |err| {
        if (w.end == body.len) return s.refuse("{s} is larger than {d} bytes", .{ url, limit });
        return err;
    };
    if (r.status == .not_found) return .missing;
    if (r.status != .ok) return s.refuse("{s} answered HTTP {d}", .{ url, @backingInt(r.status) });
    if (w.end > limit) return s.refuse("{s} is larger than {d} bytes", .{ url, limit });
    return .{ .body = w.buffered() };
}

/// download writes url's body to a new file at path, as howl's downloader
/// fetches a bundle: HTTPS only, at most limit bytes, exactly expected's.
pub fn download(s: *Sys, url: []const u8, path: []const u8, limit: u64, expected: ?Record) !void {
    if (s.fake) |f| if (try f.fetch(f.ctx, s, url, path, limit, expected)) return;
    var https: bd.Https = undefined;
    try https.init(s.io, s.gpa, .{ .ca_file = s.getenv("SSL_CERT_FILE"), .environ = s.env });
    defer https.deinit();
    const artifact: ?prebuilt.Artifact = if (expected) |e|
        .{ .sha256 = &e.sha256, .size = e.size }
    else
        null;
    https.fetch(
        url,
        path,
        limit,
        artifact,
    ) catch |err| return s.refuse("{s}: {s}", .{ url, bd.describe(err) });
}

pub const Hex = [64]u8;

pub fn hex(digest: [32]u8) Hex {
    return std.fmt.bytesToHex(digest, .lower);
}

/// hexAlloc is bytes in lowercase hex, as Python's bytes.hex().
pub fn hexAlloc(gpa: Allocator, bytes: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, bytes.len * 2);
    const digits = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[2 * i] = digits[b >> 4];
        out[2 * i + 1] = digits[b & 15];
    }
    return out;
}

pub fn sha256(bytes: []const u8) Hex {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &d, .{});
    return hex(d);
}

/// sha is the SHA-256 of the file at path, read a MiB at a time.
pub fn sha(s: *Sys, path: []const u8) !Hex {
    const f = try Dir.cwd().openFile(s.io, path, .{});
    defer f.close(s.io);
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    const buf = try s.gpa.alloc(u8, 1 << 20);
    defer s.gpa.free(buf);
    var reader = f.readerStreaming(s.io, &.{});
    while (true) {
        const n = try reader.interface.readSliceShort(buf);
        if (n == 0) break;
        h.update(buf[0..n]);
    }
    return hex(h.finalResult());
}

pub const Record = struct {
    sha256: Hex,
    size: u64,

    pub fn eql(a: Record, b: Record) bool {
        return a.size == b.size and mem.eql(u8, &a.sha256, &b.sha256);
    }

    /// toJson is the record as Python wrote it: {"sha256": ..., "size": ...}.
    pub fn toJson(r: Record, gpa: Allocator) !Json {
        return json.from(gpa, .{ .sha256 = try gpa.dupe(u8, &r.sha256), .size = r.size });
    }

    /// matches says whether v holds exactly this sha256 and size, perhaps
    /// with other members, as Python compared those two keys.
    pub fn matches(r: Record, v: Json) bool {
        const digest = json.get(v, "sha256") orelse return false;
        const size = json.get(v, "size") orelse return false;
        return digest == .string and mem.eql(u8, digest.string, &r.sha256) and
            size == .integer and size.integer >= 0 and @as(u64, @intCast(size.integer)) == r.size;
    }
};

/// record is a regular file's digest and size; links and others refuse.
pub fn record(s: *Sys, path: []const u8) !Record {
    const st = Dir.cwd().statFile(
        s.io,
        path,
        .{ .follow_symlinks = false },
    ) catch |err| switch (err) {
        error.FileNotFound => return s.refuse("image assets must be regular files: {s}", .{path}),
        else => return err,
    };
    if (st.kind != .file) return s.refuse("image assets must be regular files: {s}", .{path});
    return .{ .sha256 = try sha(s, path), .size = st.size };
}

/// read is a file of at most limit bytes.
pub fn read(s: *Sys, path: []const u8, limit: usize) ![]u8 {
    const bytes = try Dir.cwd().readFileAlloc(s.io, path, s.gpa, .limited(limit + 1));
    if (bytes.len > limit) return s.refuse("image metadata is too large: {s}", .{path});
    return bytes;
}

/// readJson parses a file of at most limit bytes.
pub fn readJson(s: *Sys, path: []const u8, limit: usize) !Json {
    return json.parse(s.gpa, try read(s, path, limit));
}

/// write puts bytes at path, making its directory.
pub fn write(s: *Sys, path: []const u8, bytes: []const u8) !void {
    if (std.fs.path.dirname(path)) |d| try Dir.cwd().createDirPath(s.io, d);
    try Dir.cwd().writeFile(s.io, .{ .sub_path = path, .data = bytes });
}

/// writeJson writes v's canonical encoding to path, making its directory.
pub fn writeJson(s: *Sys, path: []const u8, v: Json) !void {
    try write(s, path, try json.encode(s.gpa, v));
}

/// atomic replaces path with v's encoding, mode 0600: written, synced,
/// renamed and the directory synced, so a cut leaves the old or the new.
pub fn atomic(s: *Sys, path: []const u8, v: Json) !void {
    try bd.writeAtomic(s.io, path, try json.encode(s.gpa, v));
}

/// copy copies a file's bytes, as shutil.copyfile: the mode is a new
/// file's, not the source's.
pub fn copy(s: *Sys, from_path: []const u8, to_path: []const u8) !void {
    try Dir.cwd().copyFile(from_path, Dir.cwd(), to_path, s.io, .{ .permissions = .default_file });
}

/// copyTree copies a directory as shutil.copytree: modes kept, a link's
/// target copied in its place. to_path must not exist.
pub fn copyTree(s: *Sys, from_path: []const u8, to_path: []const u8) !void {
    try Dir.cwd().createDirPath(s.io, std.fs.path.dirname(to_path) orelse ".");
    try Dir.cwd().createDir(s.io, to_path, .default_dir);
    for (try walk(s, from_path)) |e| {
        const src = try join(s, &.{ from_path, e.path });
        const dst = try join(s, &.{ to_path, e.path });
        const target = if (e.kind == .sym_link)
            (try Dir.cwd().statFile(s.io, src, .{})).kind
        else
            e.kind;
        switch (target) {
            .directory => try Dir.cwd().createDir(s.io, dst, .default_dir),
            else => try Dir.cwd().copyFile(src, Dir.cwd(), dst, s.io, .{}),
        }
    }
}

pub fn exists(s: *Sys, path: []const u8) bool {
    Dir.cwd().access(s.io, path, .{}) catch return false;
    return true;
}

/// kind is what path names, without following a link, or null.
pub fn kind(s: *Sys, path: []const u8) ?File.Kind {
    const st = Dir.cwd().statFile(s.io, path, .{ .follow_symlinks = false }) catch return null;
    return st.kind;
}

/// isFile is Python's Path.is_file: a regular file, through any link.
pub fn isFile(s: *Sys, path: []const u8) bool {
    const st = Dir.cwd().statFile(s.io, path, .{}) catch return false;
    return st.kind == .file;
}

pub fn isDir(s: *Sys, path: []const u8) bool {
    const st = Dir.cwd().statFile(s.io, path, .{}) catch return false;
    return st.kind == .directory;
}

/// remove deletes a tree, as shutil.rmtree(ignore_errors=True).
pub fn remove(s: *Sys, path: []const u8) void {
    Dir.cwd().deleteTree(s.io, path) catch {};
}

pub fn mkdirs(s: *Sys, path: []const u8) !void {
    try Dir.cwd().createDirPath(s.io, path);
}

/// mkdir makes one new directory; an existing one refuses.
pub fn mkdir(s: *Sys, path: []const u8) !void {
    try Dir.cwd().createDir(s.io, path, .default_dir);
}

pub fn rename(s: *Sys, from_path: []const u8, to_path: []const u8) !void {
    try Dir.cwd().rename(from_path, Dir.cwd(), to_path, s.io);
}

/// scratch makes a private directory (0700) named prefix and a random
/// suffix, in parent or TMPDIR. The caller removes it.
pub fn scratch(s: *Sys, parent: ?[]const u8, prefix: []const u8) ![]const u8 {
    const root = parent orelse s.getenv("TMPDIR") orelse "/tmp";
    while (true) {
        var nonce: [8]u8 = undefined;
        s.io.random(&nonce);
        const path = try join(
            s,
            &.{ root, try s.gpa.print("{s}{s}", .{ prefix, std.fmt.bytesToHex(nonce, .lower) }) },
        );
        Dir.cwd().createDir(s.io, path, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => return err,
        };
        return path;
    }
}

pub fn join(s: *Sys, parts: []const []const u8) ![]const u8 {
    return std.fs.path.join(s.gpa, parts);
}

/// resolve is Python's Path.resolve(): absolute, with links resolved as
/// far as the path exists.
pub fn resolve(s: *Sys, path: []const u8) ![]const u8 {
    if (Dir.cwd().realPathFileAlloc(s.io, path, s.gpa)) |real| {
        return real;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    const absolute = if (std.fs.path.isAbsolute(path))
        try std.fs.path.resolveAlloc(s.gpa, &.{path})
    else
        try std.fs.path.resolveAlloc(
            s.gpa,
            &.{ try std.process.currentPathAlloc(s.io, s.gpa), path },
        );
    const parent = std.fs.path.dirname(absolute) orelse return absolute;
    return join(s, &.{ try resolve(s, parent), std.fs.path.basename(absolute) });
}

pub const Entry = struct { path: []const u8, kind: File.Kind };

/// walk lists every entry under root, without entering linked
/// directories, ordered as Python sorts Paths: by component.
pub fn walk(s: *Sys, root: []const u8) ![]Entry {
    var dir = try Dir.cwd().openDir(s.io, root, .{ .iterate = true });
    defer dir.close(s.io);
    var walker = try dir.walk(s.gpa);
    defer walker.deinit();
    var all: std.ArrayList(Entry) = .empty;
    while (try walker.next(s.io)) |e| {
        try all.append(s.gpa, .{ .path = try s.gpa.dupe(u8, e.path), .kind = e.kind });
    }
    mem.sort(Entry, all.items, {}, entryLess);
    return all.items;
}

/// list is a directory's entry names, sorted.
pub fn list(s: *Sys, root: []const u8) ![]const []const u8 {
    var dir = try Dir.cwd().openDir(s.io, root, .{ .iterate = true });
    defer dir.close(s.io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(s.io)) |e| try names.append(s.gpa, try s.gpa.dupe(u8, e.name));
    mem.sort([]const u8, names.items, {}, json.less);
    return names.items;
}

fn entryLess(_: void, a: Entry, b: Entry) bool {
    return pathLess({}, a.path, b.path);
}

/// pathLess orders paths as Python's PurePath: component by component.
pub fn pathLess(_: void, a: []const u8, b: []const u8) bool {
    var x = mem.splitScalar(u8, a, '/');
    var y = mem.splitScalar(u8, b, '/');
    while (true) {
        const l = x.next() orelse return y.next() != null;
        const r = y.next() orelse return false;
        switch (mem.order(u8, l, r)) {
            .lt => return true,
            .gt => return false,
            .eq => {},
        }
    }
}

/// serial is the UTC time t as werewolf names releases: 20261015T120000Z.
pub fn serial(t: i64) [16]u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(t) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    var out: [16]u8 = undefined;
    _ = std.mem.print(&out, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        yd.year,              md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
    return out;
}

/// serialTime is the time a serial names, or null unless it names one
/// exactly as serial writes it.
pub fn serialTime(text: []const u8) ?i64 {
    if (text.len != 16 or text[8] != 'T' or text[15] != 'Z') return null;
    for (text, 0..) |c, i| if (i != 8 and i != 15 and !std.ascii.isDigit(c)) return null;
    const n = struct {
        fn at(t: []const u8) u32 {
            return std.fmt.parseUnsigned(u32, t, 10) catch unreachable;
        }
    }.at;
    const year = n(text[0..4]);
    const month = n(text[4..6]);
    const day = n(text[6..8]);
    const hour = n(text[9..11]);
    const minute = n(text[11..13]);
    const second = n(text[13..15]);
    if (year < 1970 or month < 1 or month > 12 or hour > 23 or minute > 59 or
        second > 59) return null;
    const y: std.time.epoch.Year = @intCast(year);
    if (day < 1 or
        day > std.time.epoch.getDaysInMonth(
            y,
            @fromBackingInt(@as(u4, @intCast(month))),
        )) return null;
    var days: i64 = 0;
    var i: std.time.epoch.Year = 1970;
    while (i < y) : (i += 1) days += std.time.epoch.getDaysInYear(i);
    var m: u4 = 1;
    while (m < month) : (m += 1) days += std.time.epoch.getDaysInMonth(y, @fromBackingInt(m));
    days += day - 1;
    return days * 86400 + hour * 3600 + minute * 60 + second;
}

const testing = std.testing;

test "serials round trip and refuse what strftime would not write" {
    try testing.expectEqualStrings("20261015T120000Z", &serial(serialTime("20261015T120000Z").?));
    try testing.expectEqualStrings("20240229T235959Z", &serial(serialTime("20240229T235959Z").?));
    try testing.expectEqualStrings("19700101T000000Z", &serial(0));
    for ([_][]const u8{
        "20230229T000000Z",
        "20261315T120000Z",
        "2026101T120000Z",
        "20261015T126000Z",
        "20261015 120000Z",
    }) |bad|
        try testing.expect(serialTime(bad) == null);
}

test "paths sort by component, as Python's do" {
    var names = [_][]const u8{ "a.b", "a/b", "a", "b", "a/b/c", "a-b" };
    mem.sort([]const u8, &names, {}, pathLess);
    const want = [_][]const u8{ "a", "a/b", "a/b/c", "a-b", "a.b", "b" };
    for (want, names) |w, n| try testing.expectEqualStrings(w, n);
}
