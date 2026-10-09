//! cve finds which CVEs an update fixes without letting CVE data reach root.
//! slot-update.zig runs each source through two sandboxed children
//! (docs/updater.md, Separation):
//!
//!   fetcher   as _update, chrooted with only the resolver's files, TCP to
//!             ports 443 and 53 only: GETs the source into a file root opened.
//!   reader    as _update in /var/empty, with no network or files, and only
//!             pread64, write and memory calls: parses it and sends root a
//!             line per CVE.
//!
//! Root then checks every line (packageFixes, kernelFixes). The sources'
//! formats are in lib/cve.zig.

const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const sandbox = @import("sandbox");
const sources = @import("cve");

/// Limits: the most a fetcher may write, the total memory a reader may map,
/// and the longest kernel CVE title root accepts.
const max_fetch = 256 << 20;
const reader_memory = 1 << 30;
const max_title = 512;

pub const Body = struct { fd: i32, size: usize };
pub const Job = union(enum) {
    secdb: []const OriginChange,
    kernel: struct { branch: []const u8, old: [3]u32, new: [3]u32 },
};

/// fetcher runs as id, chrooted in root with only the resolver's files
/// readable, TCP only to ports 443 and 53, and files capped at max_fetch. It
/// GETs url into body, then writes "ok" or the reason to out.
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
    // Read the CA bundle before the chroot hides it.
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
    // Only what a traced request needs: the resolver's files, DNS over UDP
    // (bound to port 0) or TCP, TLS over TCP, and writes to body, out and
    // stderr.
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

/// reader runs as id in the empty /var/empty, with no network or files and
/// at most reader_memory of memory. It parses body for job and writes "ok"
/// and a line per CVE, or the reason, to out.
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

/// streamBase strips a versioned stream's suffix: openssl-4.0 -> openssl.
/// Other names are returned unchanged.
pub fn streamBase(origin: []const u8) []const u8 {
    const i = std.mem.findScalarLast(u8, origin, '-') orelse return origin;
    const tail = origin[i + 1 ..];
    if (tail.len == 0) return origin;
    for (tail) |c| if (!std.ascii.isDigit(c) and c != '.') return origin;
    return origin[0..i];
}

// apk's version order, ported from apk-tools 2.14's src/version.c so no apk
// need run: {digit}{.digit}...{letter}{_suffix{#}}...{-r#}. A version is a
// series of tokens; the separator before each gives its kind, and kinds may
// only rise, with a few exceptions.
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

    /// next sets r.t to the next token's kind, from the separator before it.
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

    /// token returns the value of the token of kind r.t and moves past it.
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
                // Refuse more than 17 digits before they overflow: versions
                // come from untrusted input.
                while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) {
                    if (i == 17) return r.fail();
                    v = v * 10 + (s[i] - '0');
                }
            },
            .letter => {
                v = s[0];
                i = 1;
            },
            .suffix => suffix: {
                // Pre-release suffixes are negative (alpha -4 to rc -1);
                // post-release ones are not.
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

/// apkOrder compares a with b as `apk version -t a b` does.
pub fn apkOrder(a: []const u8, b: []const u8) std.math.Order {
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
    // Equal up to the shorter one: the longer is newer, unless it continues
    // with a pre-release suffix.
    var xs = x;
    var ys = y;
    if (x.t == .suffix and xs.token() < 0) return .lt;
    if (y.t == .suffix and ys.token() < 0) return .gt;
    return std.math.order(@backingInt(y.t), @backingInt(x.t));
}

/// validVersion reports whether apk would accept s as a version.
fn validVersion(s: []const u8) bool {
    var r: VersionReader = .{ .s = s };
    while (r.t != .end and r.t != .invalid) _ = r.token();
    return r.t == .end;
}

/// secdbLines writes a line "INDEX FIXED CVE" for each CVE that Wolfi's
/// security.json says was fixed at FIXED within origins[INDEX]'s window. A
/// versioned stream (openssl-4.0) is also looked up under its base name; the
/// window keeps other streams' fixes out. "0" lists CVEs that never applied.
fn secdbLines(
    gpa: Allocator,
    json: []const u8,
    origins: []const OriginChange,
    w: *Io.Writer,
) !void {
    const db = try std.json.parseFromSliceLeaky(
        sources.SecDb,
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
                    if (sources.validCve(id)) try w.print("{d} {s} {s}\n", .{ i, e.key_ptr.*, id });
                }
            }
        }
    }
}

/// packageFixes checks the reader's secdbLines output and groups it by
/// origin. Each line must name an origin asked about, a version in its
/// window, and a CVE id; one bad line rejects the whole answer.
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
        if (f.next() != null or i >= origins.len or !sources.validCve(id)) return error.BadLine;
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

/// inWindow reports whether fixed is a valid version in (from, to] in apk's
/// order. "0" means never affected, so it is never in a window.
fn inWindow(fixed: []const u8, from: []const u8, to: []const u8) bool {
    return validVersion(fixed) and !std.mem.eql(u8, fixed, "0") and
        apkOrder(fixed, from) == .gt and apkOrder(fixed, to) != .gt;
}

/// kernelLines writes "CVE FIXED TITLE" for each CVE in the kernel CNA's
/// tarball fixed on branch in (old, new]. Each of the ~17,000 records is
/// parsed in a scratch arena reset between records.
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
        if (file.kind != .file or !sources.isKernelRecord(file.name)) continue;
        _ = scratch.reset(.retain_capacity);
        const s = scratch.allocator();
        var body: Io.Writer.Allocating = .init(s);
        try it.streamRemaining(file, &body.writer);
        const rec = std.json.parseFromSliceLeaky(
            sources.KernelRecord,
            s,
            body.written(),
            .{ .ignore_unknown_fields = true },
        ) catch continue;
        // Keep fixes on the branch in (old, new].
        const fixed = sources.kernelFixedOn(rec, branch) orelse continue;
        const v = sources.kernelVersion(fixed).?;
        if (!sources.kernelLess(old, v) or sources.kernelLess(new, v)) continue;
        if (!sources.validCve(rec.cveMetadata.cveId)) continue;
        try w.print(
            "{s} {s} {s}\n",
            .{ rec.cveMetadata.cveId, fixed, try oneLine(s, rec.containers.cna.title) },
        );
    }
}

/// oneLine returns s with ASCII controls replaced by spaces, cut on a UTF-8
/// boundary to at most max_title bytes.
fn oneLine(gpa: Allocator, s: []const u8) ![]const u8 {
    var end = @min(s.len, max_title);
    if (end < s.len) while (end > 0 and s[end] & 0xc0 == 0x80) : (end -= 1) {};
    const out = try gpa.dupe(u8, s[0..end]);
    for (out) |*c| if (c.* < 0x20 or c.* == 0x7f) {
        c.* = ' ';
    };
    return out;
}

/// printable reports whether s is UTF-8 safe to show in a log or page: no
/// C0 or C1 controls, and no bidi marks (U+200E, U+200F, U+202A-U+202E,
/// U+2066-U+2069), which could make a title read as something else.
pub fn printable(s: []const u8) bool {
    var it = (std.unicode.Utf8View.init(s) catch return false).iterator();
    while (it.nextCodepoint()) |c| switch (c) {
        0...0x1f, 0x7f...0x9f, 0x200e, 0x200f, 0x202a...0x202e, 0x2066...0x2069 => return false,
        else => {},
    };
    return true;
}

test printable {
    try std.testing.expect(printable("net: fix a use-after-free in Jürgen's driver"));
    try std.testing.expect(!printable("tab\there"));
    try std.testing.expect(!printable("c1 \u{85} control"));
    try std.testing.expect(!printable("reads \u{202e}backwards"));
    try std.testing.expect(!printable("\xff not utf-8"));
}

test "versions too long to hold are refused, not overflowed" {
    try std.testing.expect(!validVersion("99999999999999999999"));
    try std.testing.expect(!validVersion("1.99999999999999999999-r0"));
    try std.testing.expect(validVersion("12345678901234567-r0"));
}

/// kernelFixes checks the reader's kernelLines output. Each line must have
/// a CVE id, a version on new's branch in (old, new], and a printable title;
/// one bad line rejects the whole answer.
pub fn kernelFixes(gpa: Allocator, text: []const u8, old: [3]u32, new: [3]u32) ![]const KernelFix {
    var out: std.ArrayList(KernelFix) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ' ');
        const id = f.next().?;
        const fixed = f.next() orelse return error.BadLine;
        const title = f.rest();
        const v = sources.kernelVersion(fixed) orelse return error.BadLine;
        if (!sources.validCve(id) or v[0] != new[0] or v[1] != new[1] or
            !sources.kernelLess(old, v) or
            sources.kernelLess(new, v)) return error.BadLine;
        if (title.len > max_title or !printable(title)) return error.BadLine;
        try out.append(gpa, .{ .id = id, .fixed_in = fixed, .title = title });
    }
    std.mem.sort(KernelFix, out.items, {}, struct {
        fn lt(_: void, a: KernelFix, b: KernelFix) bool {
            return std.mem.lessThan(u8, a.id, b.id);
        }
    }.lt);
    return out.items;
}

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
    // Each answer is from apk-tools 2.14.10's `apk version -t`.
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
    // Validity as `apk version -c` judged it.
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

    // A reader that lies in one line is believed in none.
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
