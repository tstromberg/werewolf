//! cve: which CVEs an update fixes, found where nothing in them can reach
//! root. update.zig runs each source through two children of its own
//! (docs/updater.md, Separation):
//!
//!   fetcher   as _update, rooted in a directory holding only the
//!             resolver's files, with TCP to 443 and 53 alone: GET the
//!             source into a file root opened for it.
//!   reader    as _update in the empty /var/empty, with no network, no
//!             files, and pread64, write and memory calls alone: parse it,
//!             and send root a line per CVE.
//!
//! Root checks every line again here (packageFixes, kernelFixes) before any
//! goes in the report. apk's version order and the kernel's, which both
//! sides use, are here too.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const sandbox = @import("sandbox.zig");

/// The most a fetcher may write, the memory a reader may map, all told,
/// and the longest kernel CVE title root takes.
const max_fetch = 256 << 20;
const reader_memory = 1 << 30;
const max_title = 512;

pub const Body = struct { fd: i32, size: usize };
pub const Job = union(enum) {
    secdb: []const OriginChange,
    kernel: struct { branch: []const u8, old: [3]u32, new: [3]u32 },
};

/// As id, rooted in root with only the resolver's files to read, TCP only
/// to ports 443 and 53, and no file bigger than max_fetch: GET url into
/// body, then say "ok", or why not.
pub fn fetcher(
    id: u32,
    root: [*:0]const u8,
    url: []const u8,
    body: i32,
    out: i32,
    parent: linux.pid_t,
) noreturn {
    sandbox.tieTo(parent);
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const status = fetchInto(
        arena.allocator(),
        id,
        root,
        url,
        body,
        out,
    ) catch |err| sandbox.whyNot(arena.allocator(), err);
    sandbox.say(out, 0, status, "");
}

fn fetchInto(
    gpa: Allocator,
    id: u32,
    root: [*:0]const u8,
    url: []const u8,
    body: i32,
    out: i32,
) ![]const u8 {
    try sandbox.closeAllBut(&.{ body, out });
    var threaded: Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    // The CA bundle, read before the chroot hides it.
    const now = Io.Clock.real.now(io);
    try client.ca_bundle.rescan(gpa, io, now);
    client.now = now;
    try sandbox.limit(.FSIZE, max_fetch);
    try sandbox.dropTo(id, root);
    const etc: i32 = @intCast(try sandbox.sys(
        linux.openat(
            linux.AT.FDCWD,
            "/etc",
            .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true },
            0,
        ),
        "open /etc",
    ));
    try sandbox.landlock(&.{.{ .fd = etc, .access = sandbox.read_file }}, &.{ 443, 53 });
    _ = linux.close(etc);
    // What the request takes, as traced: the resolver's files, DNS over
    // UDP (bound to port 0) or TCP, TLS over TCP, and the body to the file;
    // nothing else is written anywhere but the status pipe and /dev/null.
    var f: sandbox.Filter = .{};
    f.allowArg("socket", 0, linux.AF.INET);
    f.allowArg("socket", 0, linux.AF.INET6);
    f.allow("bind");
    f.allow("connect");
    f.allow("getsockname");
    f.allow("sendmsg");
    f.allow("sendmmsg");
    f.allow("recvmsg");
    f.allow("openat");
    f.allow("preadv");
    f.allowArg("writev", 0, @intCast(body));
    f.allowArg("write", 0, @intCast(out));
    f.allowArg("write", 0, 2);
    f.allow("close");
    f.allow("poll");
    f.allow("ppoll");
    f.allow("mmap");
    f.allow("munmap");
    f.allow("mremap");
    f.allow("getrandom");
    f.allow("clock_gettime");
    f.allow("exit_group");
    try f.install();

    var buf: [64 << 10]u8 = undefined;
    const file: Io.File = .{ .handle = body, .flags = .{ .nonblocking = false } };
    var w = file.writerStreaming(io, &buf);
    const res = try client.fetch(.{ .location = .{ .url = url }, .response_writer = &w.interface });
    try w.interface.flush();
    if (res.status != .ok) return std.enums.tagName(
        std.http.Status,
        res.status,
    ) orelse "HttpStatus";
    return "ok";
}

/// As _update in the empty /var/empty, with no network, no files, and at
/// most reader_memory of memory: parse body for job, and say "ok" and a
/// line per CVE, or why not.
pub fn reader(id: u32, job: Job, body: Body, out: i32, parent: linux.pid_t) noreturn {
    sandbox.tieTo(parent);
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const gpa = arena.allocator();
    var lines: Io.Writer.Allocating = .init(gpa);
    readInto(
        gpa,
        id,
        job,
        body,
        out,
        &lines.writer,
    ) catch |err| sandbox.say(out, 0, sandbox.whyNot(gpa, err), "");
    sandbox.say(out, 0, "ok", lines.written());
}

fn readInto(gpa: Allocator, id: u32, job: Job, body: Body, out: i32, w: *Io.Writer) !void {
    try sandbox.closeAllBut(&.{ body.fd, out });
    try sandbox.limit(.AS, reader_memory);
    try sandbox.dropTo(id, "/var/empty");
    try sandbox.landlock(&.{}, &.{});
    var f: sandbox.Filter = .{};
    f.allowArg("pread64", 0, @intCast(body.fd));
    f.allowArg("write", 0, @intCast(out));
    f.allow("mmap");
    f.allow("munmap");
    f.allow("mremap");
    f.allow("exit_group");
    try f.install();

    const data = try gpa.alloc(u8, body.size);
    var got: usize = 0;
    while (got < data.len) {
        const n = try sandbox.sys(
            linux.pread(body.fd, data[got..].ptr, data.len - got, @intCast(got)),
            "pread",
        );
        if (n == 0) return error.ShortRead;
        got += n;
    }
    switch (job) {
        .secdb => |origins| try secdbLines(gpa, data, origins, w),
        .kernel => |k| try kernelLines(gpa, data, k.branch, k.old, k.new, w),
    }
}

pub const PackageFix = struct {
    origin: []const u8,
    from: []const u8,
    to: []const u8,
    cves: []const []const u8,
};
pub const KernelFix = struct { id: []const u8, fixed_in: []const u8, title: []const u8 };
pub const KernelFixes = struct {
    branch: []const u8 = "",
    from: []const u8 = "",
    to: []const u8 = "",
    cves: []const KernelFix = &.{},
};
pub const OriginChange = struct { origin: []const u8, from: []const u8, to: []const u8 };

/// openssl-4.0 -> openssl; a name without a version suffix is its own base.
fn streamBase(origin: []const u8) []const u8 {
    const i = std.mem.findScalarLast(u8, origin, '-') orelse return origin;
    const tail = origin[i + 1 ..];
    if (tail.len == 0) return origin;
    for (tail) |c| if (!std.ascii.isDigit(c) and c != '.') return origin;
    return origin[0..i];
}

// apk's version order, as apk-tools 2.14's src/version.c defines it, so no
// apk need run to compare two: {digit}{.digit}...{letter}{_suffix{#}}...{-r#}.
// A version is read as tokens, each kind known from the character that ends
// the last, in an order that only rises but for a few steps back.
const Tok = enum(i8) {
    invalid = -1,
    digit_or_zero,
    digit,
    letter,
    suffix,
    suffix_no,
    revision_no,
    end,
};

const VersionReader = struct {
    s: []const u8,
    t: Tok = .digit,

    const pre_suffixes = [_][]const u8{ "alpha", "beta", "pre", "rc" };
    const post_suffixes = [_][]const u8{ "cvs", "svn", "git", "hg", "p" };

    /// The kind of the next token, from what separates it from the last.
    fn next(r: *VersionReader) void {
        const s = r.s;
        var n: Tok = .invalid;
        if (s.len == 0 or s[0] == 0) {
            n = .end;
        } else if ((r.t == .digit or r.t == .digit_or_zero) and std.ascii.isLower(s[0])) {
            n = .letter;
        } else if (r.t == .letter and std.ascii.isDigit(s[0])) {
            n = .digit;
        } else if (r.t == .suffix and std.ascii.isDigit(s[0])) {
            n = .suffix_no;
        } else {
            switch (s[0]) {
                '.' => n = .digit_or_zero,
                '_' => n = .suffix,
                '-' => if (s.len > 1 and s[1] == 'r') {
                    n = .revision_no;
                    r.s = r.s[1..];
                },
                else => {},
            }
            r.s = r.s[1..];
        }
        if (@backingInt(n) < @backingInt(r.t) and !((n == .digit_or_zero and r.t == .digit) or
            (n == .suffix and r.t == .suffix_no) or (n == .digit and r.t == .letter))) n = .invalid;
        r.t = n;
    }

    /// The value of the token of kind r.t, and past it.
    fn token(r: *VersionReader) i64 {
        const s = r.s;
        if (s.len == 0) {
            r.t = .end;
            return 0;
        }
        var i: usize = 0;
        var v: i64 = 0;
        var nt: Tok = .invalid;
        switch (r.t) {
            .digit_or_zero,
            .digit,
            .suffix_no,
            .revision_no,
            => if (r.t == .digit_or_zero and s[0] == '0') {
                // Leading zeros: 1.01 is older than 1.1.
                while (i + 1 < s.len and s[i + 1] == '0') i += 1;
                nt = .digit;
                v = -@as(i64, @intCast(i));
            } else {
                while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) v = v * 10 + (s[i] - '0');
                if (i >= 18) return r.fail();
            },
            .letter => {
                v = s[0];
                i = 1;
            },
            .suffix => suffix: {
                // Before the release (alpha, -4, to rc, -1), or after it.
                for (pre_suffixes, 0..) |p, k| if (std.mem.startsWith(u8, s, p)) {
                    i = p.len;
                    v = @as(i64, @intCast(k)) - pre_suffixes.len;
                    break :suffix;
                };
                for (post_suffixes, 0..) |p, k| if (std.mem.startsWith(u8, s, p)) {
                    i = p.len;
                    v = @intCast(k);
                    break :suffix;
                };
                return r.fail();
            },
            else => return r.fail(),
        }
        r.s = s[i..];
        if (r.s.len == 0) {
            r.t = .end;
        } else if (nt != .invalid) {
            r.t = nt;
        } else {
            r.next();
        }
        return v;
    }

    fn fail(r: *VersionReader) i64 {
        r.t = .invalid;
        return -1;
    }
};

/// a against b, as `apk version -t a b` orders them.
fn apkOrder(a: []const u8, b: []const u8) std.math.Order {
    var x: VersionReader = .{ .s = a };
    var y: VersionReader = .{ .s = b };
    var xv: i64 = 0;
    var yv: i64 = 0;
    while (x.t == y.t and x.t != .end and x.t != .invalid and xv == yv) {
        xv = x.token();
        yv = y.token();
    }
    if (xv != yv) return std.math.order(xv, yv);
    if (x.t == y.t) return .eq;
    // Equal as far as one goes: the longer is newer, unless what it goes
    // on with is a pre-release suffix.
    var xs = x;
    var ys = y;
    if (x.t == .suffix and xs.token() < 0) return .lt;
    if (y.t == .suffix and ys.token() < 0) return .gt;
    return std.math.order(@backingInt(y.t), @backingInt(x.t));
}

/// Whether apk would take s as a version.
fn validVersion(s: []const u8) bool {
    var r: VersionReader = .{ .s = s };
    while (r.t != .end and r.t != .invalid) _ = r.token();
    return r.t == .end;
}

/// linux-virt-6.18.55-r0, or 6.18.55, as {6, 18, 55}.
pub fn kernelVersion(s: []const u8) ?[3]u32 {
    var v = s;
    if (std.mem.startsWith(u8, v, "linux-virt-")) v = v["linux-virt-".len..];
    if (std.mem.findScalar(u8, v, '-')) |i| v = v[0..i];
    var out: [3]u32 = .{ 0, 0, 0 };
    var it = std.mem.splitScalar(u8, v, '.');
    for (&out) |*part| {
        const field = it.next() orelse return null;
        part.* = std.fmt.parseInt(u32, field, 10) catch return null;
    }
    if (it.next() != null) return null;
    return out;
}

fn kernelLess(a: [3]u32, b: [3]u32) bool {
    return std.mem.order(u32, &a, &b) == .lt;
}

/// The parts of a kernel CNA record (CVE JSON 5) that say which stable
/// release fixed it on which branch.
const KernelRecord = struct {
    cveMetadata: struct { cveId: []const u8 },
    containers: struct {
        cna: struct {
            title: []const u8 = "",
            affected: []const struct {
                versions: []const struct {
                    version: []const u8,
                    status: []const u8,
                    lessThanOrEqual: ?[]const u8 = null,
                    versionType: ?[]const u8 = null,
                } = &.{},
            } = &.{},
        },
    },
};

/// The version that fixed this CVE on branch, if it is in (old, new].
fn kernelFixedIn(rec: KernelRecord, branch: []const u8, old: [3]u32, new: [3]u32) ?[]const u8 {
    for (rec.containers.cna.affected) |a| {
        for (a.versions) |v| {
            if (!std.mem.eql(u8, v.status, "unaffected")) continue;
            if (!std.mem.eql(u8, v.versionType orelse "", "semver")) continue;
            const le = v.lessThanOrEqual orelse continue;
            if (!std.mem.endsWith(u8, le, ".*") or
                !std.mem.eql(u8, le[0 .. le.len - 2], branch)) continue;
            const fixed = kernelVersion(v.version) orelse continue;
            if (kernelLess(old, fixed) and !kernelLess(new, fixed)) return v.version;
        }
    }
    return null;
}

/// Wolfi's security.json, as the reader's lines, "INDEX FIXED CVE": a CVE
/// fixed at version FIXED, in the window of origins[INDEX].
fn secdbLines(
    gpa: Allocator,
    json: []const u8,
    origins: []const OriginChange,
    w: *Io.Writer,
) !void {
    const db = try std.json.parseFromSliceLeaky(
        SecDb,
        gpa,
        json,
        .{ .ignore_unknown_fields = true },
    );
    for (origins, 0..) |o, i| {
        const base = streamBase(o.origin);
        for (db.packages) |p| {
            if (!std.mem.eql(u8, p.pkg.name, o.origin) and
                !std.mem.eql(u8, p.pkg.name, base)) continue;
            const secfixes = p.pkg.secfixes orelse continue;
            var it = secfixes.map.iterator();
            while (it.next()) |e| {
                if (!inWindow(e.key_ptr.*, o.from, o.to)) continue;
                for (e.value_ptr.*) |id| {
                    if (validCve(id)) try w.print("{d} {s} {s}\n", .{ i, e.key_ptr.*, id });
                }
            }
        }
    }
}

/// The reader's lines from secdbLines, checked: each names an origin asked
/// about, a version in its window, and a CVE id. A reader that sends any
/// other line is not believed at all.
pub fn packageFixes(
    gpa: Allocator,
    text: []const u8,
    origins: []const OriginChange,
) ![]const PackageFix {
    const cves = try gpa.alloc(std.ArrayList([]const u8), origins.len);
    @memset(cves, .empty);
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ' ');
        const i = std.fmt.parseUnsigned(usize, f.next().?, 10) catch return error.BadLine;
        const fixed = f.next() orelse return error.BadLine;
        const id = f.next() orelse return error.BadLine;
        if (f.next() != null or i >= origins.len or !validCve(id)) return error.BadLine;
        if (!inWindow(fixed, origins[i].from, origins[i].to)) return error.BadLine;
        try cves[i].append(gpa, id);
    }
    var fixes: std.ArrayList(PackageFix) = .empty;
    for (origins, cves) |o, c| {
        if (c.items.len == 0) continue;
        std.mem.sort([]const u8, c.items, {}, lessString);
        var n: usize = 1;
        for (c.items[1..]) |id| {
            if (std.mem.eql(u8, id, c.items[n - 1])) continue;
            c.items[n] = id;
            n += 1;
        }
        try fixes.append(
            gpa,
            .{ .origin = o.origin, .from = o.from, .to = o.to, .cves = c.items[0..n] },
        );
    }
    return fixes.items;
}

/// Whether fixed is a version newer than from and no newer than to. "0",
/// never affected, is in no window.
fn inWindow(fixed: []const u8, from: []const u8, to: []const u8) bool {
    return validVersion(fixed) and !std.mem.eql(u8, fixed, "0") and
        apkOrder(fixed, from) == .gt and apkOrder(fixed, to) != .gt;
}

/// CVE-2026-52988: the year, and four digits or more.
fn validCve(id: []const u8) bool {
    if (id.len < 13 or id.len > 32 or !std.mem.startsWith(u8, id, "CVE-") or
        id[8] != '-') return false;
    for (id[4..8]) |c| if (!std.ascii.isDigit(c)) return false;
    for (id[9..]) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// The kernel CNA's tarball, as the reader's lines, "CVE FIXED TITLE": each
/// CVE fixed on branch in (old, new], with its title made one line.
fn kernelLines(
    gpa: Allocator,
    tarball_gz: []const u8,
    branch: []const u8,
    old: [3]u32,
    new: [3]u32,
    w: *Io.Writer,
) !void {
    var in: Io.Reader = .fixed(tarball_gz);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var gz: std.compress.flate.Decompress = .init(&in, .gzip, &window);
    var name_buf: [Dir.max_path_bytes]u8 = undefined;
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(
        &gz.reader,
        .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
    );
    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();
    while (try it.next()) |file| {
        if (file.kind != .file or !isKernelRecord(file.name)) continue;
        _ = scratch.reset(.retain_capacity);
        const s = scratch.allocator();
        var body: Io.Writer.Allocating = .init(s);
        try it.streamRemaining(file, &body.writer);
        const rec = std.json.parseFromSliceLeaky(
            KernelRecord,
            s,
            body.written(),
            .{ .ignore_unknown_fields = true },
        ) catch continue;
        const fixed = kernelFixedIn(rec, branch, old, new) orelse continue;
        if (!validCve(rec.cveMetadata.cveId)) continue;
        try w.print(
            "{s} {s} {s}\n",
            .{ rec.cveMetadata.cveId, fixed, try oneLine(s, rec.containers.cna.title) },
        );
    }
}

/// s with control characters as spaces, and cut, on a character's
/// boundary, to max_title bytes.
fn oneLine(gpa: Allocator, s: []const u8) ![]const u8 {
    var end = @min(s.len, max_title);
    if (end < s.len) while (end > 0 and s[end] & 0xc0 == 0x80) : (end -= 1) {};
    const out = try gpa.dupe(u8, s[0..end]);
    for (out) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = ' ';
    };
    return out;
}

/// The reader's lines from kernelLines, checked: a CVE id, a version on
/// new's branch in (old, new], and a title of printable UTF-8. A reader
/// that sends any other line is not believed at all.
pub fn kernelFixes(gpa: Allocator, text: []const u8, old: [3]u32, new: [3]u32) ![]const KernelFix {
    var out: std.ArrayList(KernelFix) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ' ');
        const id = f.next().?;
        const fixed = f.next() orelse return error.BadLine;
        const title = f.rest();
        const v = kernelVersion(fixed) orelse return error.BadLine;
        if (!validCve(id) or v[0] != new[0] or v[1] != new[1] or !kernelLess(old, v) or
            kernelLess(new, v)) return error.BadLine;
        if (title.len > max_title or !std.unicode.utf8ValidateSlice(title)) return error.BadLine;
        for (title) |c| if (c < 0x20 or c == 0x7f) return error.BadLine;
        try out.append(gpa, .{ .id = id, .fixed_in = fixed, .title = title });
    }
    std.mem.sort(KernelFix, out.items, {}, struct {
        fn lt(_: void, a: KernelFix, b: KernelFix) bool {
            return std.mem.lessThan(u8, a.id, b.id);
        }
    }.lt);
    return out.items;
}

/// vulns-master/cve/published/2026/CVE-2026-52988.json
fn isKernelRecord(name: []const u8) bool {
    const base = name[(std.mem.findScalarLast(u8, name, '/') orelse return false) + 1 ..];
    return std.mem.indexOf(u8, name, "/cve/published/") != null and
        std.mem.startsWith(u8, base, "CVE-") and std.mem.endsWith(u8, base, ".json");
}

/// Wolfi's security.json, as much of it as is used.
const SecDb = struct {
    packages: []const struct {
        pkg: struct {
            name: []const u8,
            secfixes: ?std.json.ArrayHashMap([]const []const u8) = null,
        },
    },
};

fn lessString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test streamBase {
    try testing.expectEqualStrings("openssl", streamBase("openssl-4.0"));
    try testing.expectEqualStrings("glibc", streamBase("glibc-2.44"));
    try testing.expectEqualStrings("busybox", streamBase("busybox"));
    try testing.expectEqualStrings("ca-certificates", streamBase("ca-certificates"));
    try testing.expectEqualStrings("py3-", streamBase("py3-"));
}

test apkOrder {
    // Each as apk-tools 2.14.10's `apk version -t` answered.
    const cases = [_]struct { []const u8, []const u8, std.math.Order }{
        .{ "1.0", "1.0.1", .lt },
        .{ "1.0_alpha", "1.0", .lt },
        .{ "1.0_alpha1", "1.0_alpha2", .lt },
        .{ "1.0_beta", "1.0_alpha", .gt },
        .{ "1.0_rc1", "1.0", .lt },
        .{ "1.0_p1", "1.0", .gt },
        .{ "1.0-r1", "1.0-r0", .gt },
        .{ "1.0-r10", "1.0-r9", .gt },
        .{ "1.0a", "1.0", .gt },
        .{ "1.0a", "1.0b", .lt },
        .{ "1.01", "1.1", .lt },
        .{ "1.010", "1.9", .lt },
        .{ "1.001", "1.01", .lt },
        .{ "2.0", "1.99", .gt },
        .{ "1.3.2.1_rc20260601-r0", "1.3.2.1-r0", .lt },
        .{ "1.3.2.1_rc20260601-r0", "1.3.2-r5", .gt },
        .{ "4.0.3-r3", "4.0.2-r0", .gt },
        .{ "1.38.0-r2", "1.37.0-r30", .gt },
        .{ "1.0", "1.0", .eq },
        .{ "1.0-r0", "1.0", .gt },
        .{ "0", "1.0", .lt },
        .{ "1.0_git20260101", "1.0", .gt },
        .{ "1.0_cvs", "1.0_svn", .lt },
        .{ "6.18.55-r0", "6.18.9-r0", .gt },
        .{ "1.2.3_p4-r1", "1.2.3_p4-r0", .gt },
        .{ "1.2.3_pre1", "1.2.3_p1", .lt },
        .{ "2.39.4", "2.39.4_p0", .lt },
        .{ "1.0_bad", "1.0", .lt },
        .{ "abc", "1.0", .lt },
        .{ "1.0.", "1.0", .gt },
        .{ "1.0", "1.0-r", .lt },
        .{ "1.2.3a1", "1.2.3a", .gt },
        .{ "5.2.37_p20250701-r0", "5.2.37-r40", .gt },
        .{ "2026.04.13-r1", "2026.4.13-r1", .lt },
        .{ "1.0.0.0.0.0", "1.0", .gt },
        .{ "1.0_alpha_p1", "1.0_alpha", .gt },
    };
    for (cases) |c| {
        errdefer std.debug.print("{s} {s}\n", .{ c[0], c[1] });
        try testing.expectEqual(c[2], apkOrder(c[0], c[1]));
        try testing.expectEqual(c[2].invert(), apkOrder(c[1], c[0]));
    }
    // And as `apk version -c` judged them.
    for ([_][]const u8{
        "1.0",
        "1.0.",
        "1.0-r",
        "0",
        "",
        "1.0_alpha_p1",
        "1.3.2.1_rc20260601-r0",
    }) |v| try testing.expect(validVersion(v));
    for ([_][]const u8{
        "1.0_bad",
        "abc",
        "1.0-x",
        "1.0 ",
        "1.0-r1a",
        "1234567890123456789",
    }) |v| try testing.expect(!validVersion(v));
}

test kernelVersion {
    try testing.expectEqual([3]u32{ 6, 18, 55 }, kernelVersion("linux-virt-6.18.55-r0").?);
    try testing.expectEqual([3]u32{ 6, 18, 42 }, kernelVersion("6.18.42").?);
    try testing.expectEqual(null, kernelVersion("6.18"));
    try testing.expectEqual(null, kernelVersion("6.18.x"));
}

test "kernel CVE window" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const json =
        \\{"cveMetadata":{"cveId":"CVE-2026-52988"},"containers":{"cna":{"title":"netfilter: x",
        \\ "affected":[{"versions":[{"version":"0","lessThan":"5.15","status":"unaffected","versionType":"semver"},
        \\   {"version":"6.12.101","lessThanOrEqual":"6.12.*","status":"unaffected","versionType":"semver"},
        \\   {"version":"6.18.55","lessThanOrEqual":"6.18.*","status":"unaffected","versionType":"semver"},
        \\   {"version":"abc","lessThan":"def","status":"affected","versionType":"git"}]}]}}}
    ;
    const rec = try std.json.parseFromSliceLeaky(
        KernelRecord,
        arena.allocator(),
        json,
        .{ .ignore_unknown_fields = true },
    );
    try testing.expectEqualStrings(
        "6.18.55",
        kernelFixedIn(rec, "6.18", .{ 6, 18, 54 }, .{ 6, 18, 55 }).?,
    );
    try testing.expectEqualStrings(
        "6.18.55",
        kernelFixedIn(rec, "6.18", .{ 6, 18, 1 }, .{ 6, 18, 60 }).?,
    );
    try testing.expectEqual(null, kernelFixedIn(rec, "6.18", .{ 6, 18, 55 }, .{ 6, 18, 60 }));
    try testing.expectEqual(null, kernelFixedIn(rec, "6.18", .{ 6, 18, 50 }, .{ 6, 18, 54 }));
    try testing.expectEqual(null, kernelFixedIn(rec, "6.1", .{ 6, 1, 1 }, .{ 6, 1, 999 }));
    try testing.expect(isKernelRecord("vulns-master/cve/published/2026/CVE-2026-52988.json"));
    try testing.expect(!isKernelRecord("vulns-master/cve/published/2026/CVE-2026-52988.mbox"));
    try testing.expect(!isKernelRecord("vulns-master/cve/rejected/2026/CVE-2026-1.json"));
}

test "secdb parses with versions as keys" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const db = try std.json.parseFromSliceLeaky(SecDb, arena.allocator(),
        \\{"apkurl":"x","packages":[{"pkg":{"name":"zlib","secfixes":{"0":["CVE-2026-22184"],"1.3.2.1_rc20260601-r0":["CVE-2026-85091","GHSA-x"]}}},{"pkg":{"name":"none"}}]}
    , .{ .ignore_unknown_fields = true });
    try testing.expectEqual(2, db.packages.len);
    try testing.expectEqual(2, db.packages[0].pkg.secfixes.?.map.count());
    try testing.expectEqual(null, db.packages[1].pkg.secfixes);
}

test "package CVEs, from a reader and checked" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const origins: []const OriginChange = &.{
        .{ .origin = "zlib", .from = "1.3.1-r0", .to = "1.3.2.1-r0" },
        .{ .origin = "openssl-4.0", .from = "4.0.2-r0", .to = "4.0.3-r3" },
    };
    var out: Io.Writer.Allocating = .init(a);
    try secdbLines(a,
        \\{"packages":[
        \\ {"pkg":{"name":"zlib","secfixes":{"0":["CVE-2026-22184"],"1.3.2.1_rc20260601-r0":["CVE-2026-85091","GHSA-x"],"1.3.2-r0":["CVE-2026-1111"],"1.4-r0":["CVE-2026-2222"]}}},
        \\ {"pkg":{"name":"openssl","secfixes":{"4.0.3-r0":["CVE-2026-3333"],"3.5.9-r0":["CVE-2026-4444"],"4.0.3 -r1":["CVE-2026-5555"]}}},
        \\ {"pkg":{"name":"other","secfixes":{"4.0.3-r0":["CVE-2026-6666"]}}}]}
    , origins, &out.writer);
    try testing.expectEqualStrings(
        \\0 1.3.2.1_rc20260601-r0 CVE-2026-85091
        \\0 1.3.2-r0 CVE-2026-1111
        \\1 4.0.3-r0 CVE-2026-3333
        \\
    , out.written());

    const fixes = try packageFixes(a, out.written(), origins);
    try testing.expectEqual(2, fixes.len);
    try testing.expectEqualStrings("zlib", fixes[0].origin);
    try testing.expectEqualStrings("CVE-2026-1111", fixes[0].cves[0]);
    try testing.expectEqualStrings("CVE-2026-85091", fixes[0].cves[1]);
    try testing.expectEqualStrings("4.0.2-r0", fixes[1].from);
    try testing.expectEqual(0, (try packageFixes(a, "", origins)).len);

    // A reader that lies in any one line is believed in none.
    for ([_][]const u8{
        "2 4.0.3-r0 CVE-2026-3333", // no such origin
        "1 4.0.4-r0 CVE-2026-3333", // after the window
        "1 4.0.2-r0 CVE-2026-3333", // the old version itself
        "1 0 CVE-2026-3333",
        "1 4.0.3-r0 GHSA-xxxx-xxxx-xxxx",
        "1 4.0.3-r0 CVE-2026-3333 more",
        "1 4.0.3-r0",
        "1 4.0.3-r0 CVE-26-3333",
        "-1 4.0.3-r0 CVE-2026-3333",
        "1 4.0.3-r0 CVE-2026-3333\x00",
    }) |bad| {
        const text = try a.print("0 1.3.2-r0 CVE-2026-1111\n{s}\n", .{bad});
        try testing.expectError(error.BadLine, packageFixes(a, text, origins));
    }
}

test "kernel CVEs, from a reader and checked" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const old: [3]u32 = .{ 6, 18, 50 };
    const new: [3]u32 = .{ 6, 18, 55 };
    const fixes = try kernelFixes(
        a,
        "CVE-2026-9000 6.18.55 b: \xc3\xa9t\xc3\xa9\nCVE-2026-10001 6.18.51 a: x\n",
        old,
        new,
    );
    try testing.expectEqual(2, fixes.len);
    try testing.expectEqualStrings("CVE-2026-10001", fixes[0].id);
    try testing.expectEqualStrings("a: x", fixes[0].title);
    try testing.expectEqualStrings("6.18.55", fixes[1].fixed_in);
    for ([_][]const u8{
        "CVE-2026-9999 6.18.50 x", // the old version itself
        "CVE-2026-9999 6.18.56 x",
        "CVE-2026-9999 6.12.52 x",
        "CVE-2026-9999 6.18 x",
        "CVE-2026-9999 6.18.52 \x1b[2Jx",
        "CVE-2026-9999 6.18.52 \xff",
        "CVE-2026-99x9 6.18.52 x",
    }) |bad| try testing.expectError(error.BadLine, kernelFixes(a, bad, old, new));

    try testing.expectEqualStrings("a b  c", try oneLine(a, "a\nb\t\x7fc"));
    var long: [max_title + 1]u8 = @splat('x');
    long[max_title - 1] = 0xc3;
    long[max_title] = 0xa9;
    try testing.expectEqual(max_title - 1, (try oneLine(a, &long)).len);
}

test validCve {
    for ([_][]const u8{
        "CVE-2026-0001",
        "CVE-1999-1234567",
    }) |id| try testing.expect(validCve(id));
    for ([_][]const u8{
        "CVE-2026-001",
        "cve-2026-0001",
        "CVE-2026-0001 ",
        "CVE-20260-0001",
        "GHSA-2026-0001",
        "CVE-2026-0001a",
    }) |id| try testing.expect(!validCve(id));
}
