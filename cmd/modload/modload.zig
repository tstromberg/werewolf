//! modload loads the kernel modules listed in
//! /usr/lib/modules/RELEASE/werewolf.modules, then sets
//! kernel.modules_disabled so nothing can load another. See README.md.

const std = @import("std");
const linux = std.os.linux;
const sandbox = @import("sandbox");

const max_modules = 256;
const max_list = 64 << 10;

pub fn main() void {
    var before: [4]u8 = undefined;
    if (std.mem.startsWith(u8, readSmall(modules_disabled, &before) orelse "", "1")) {
        say("modload: the loader is closed already\n", .{});
        linux.exit_group(0);
    }
    // Open both descriptors before the pledge: one to close the loader and
    // one to read the result back. A sysctl write lands only at offset 0, so
    // the write needs its own; and the kernel's answer is what is read back,
    // not what the write returns.
    const disabled = openPath(
        modules_disabled,
        O_WRONLY,
    ) catch |err| fail("cannot open kernel.modules_disabled", err);
    const verify = openPath(
        modules_disabled,
        O_RDONLY,
    ) catch |err| fail("cannot open kernel.modules_disabled", err);

    // The loader closes whatever load does.
    const result = load() catch |err| blk: {
        say("modload: {s}; loading none\n", .{describe(err)});
        break :blk null;
    };

    _ = linux.write(disabled, "1", 1);
    close(disabled);
    var state: [4]u8 = undefined;
    const got = linux.read(verify, &state, state.len);
    const closed = linux.errno(got) == .SUCCESS and got > 0 and state[0] == '1';
    const door = if (closed) "closed" else "STILL OPEN";
    if (result) |r| {
        var absent: [48]u8 = undefined;
        var skipped: [64]u8 = undefined;
        say("modload: {d} of {d} loaded{s}{s}; the loader is {s}\n", .{
            r.count - r.refused - r.absent - r.skipped,
            r.count,
            if (r.absent > 0)
                std.mem.print(&absent, ", {d} with no hardware here", .{r.absent}) catch ""
            else
                "",
            if (r.skipped > 0)
                std.mem.print(
                    &skipped,
                    ", {d} for what this machine does not have",
                    .{r.skipped},
                ) catch ""
            else
                "",
            door,
        });
        linux.exit_group(if (r.refused == 0 and closed) 0 else 1);
    }
    say("modload: the loader is {s}\n", .{door});
    linux.exit_group(1);
}

const Result = struct { count: usize, refused: usize, absent: usize, skipped: usize };

/// load checks enforcement, reads the list, opens every module, pledges,
/// and loads them. It does everything but close the loader.
fn load() !Result {
    if (!enforced()) return error.Unenforced;

    var uts: linux.utsname = undefined;
    _ = linux.uname(&uts);
    const release = std.mem.sliceTo(&uts.release, 0);
    var dir_buf: [128]u8 = undefined;
    const dir_path = std.mem.printSentinel(&dir_buf, "/usr/lib/modules/{s}", .{release}, 0) catch
        return error.Release;
    const dir = try openPath(dir_path, O_PATH);
    defer close(dir);

    var list: [max_list]u8 = undefined;
    const text = try readBeneath(dir, "werewolf.modules", &list);
    var lines: [max_modules][256:0]u8 = undefined;
    var mods: [max_modules]Module = undefined;
    const count = try parse(text, &lines, &mods);

    var fds: [max_modules]i32 = undefined;
    for (mods[0..count], 0..) |m, i| {
        fds[i] = openBeneath(dir, m.path, O_RDONLY) catch |err| {
            say("modload: {s}: cannot open\n", .{m.path});
            return err;
        };
    }

    try pledge();

    var r: Result = .{ .count = count, .refused = 0, .absent = 0, .skipped = 0 };
    // Load untagged modules first, then each tag's as stdin names it.
    for (fds[0..count], mods[0..count]) |*fd, m| if (m.tag.len == 0) insert(fd, m, &r);
    var tags: Tags = .{};
    var named = false;
    while (tags.next()) |tag| {
        named = true;
        if (!isTag(tag)) {
            say("modload: stdin named no tag; ignored\n", .{});
            continue;
        }
        for (fds[0..count], mods[0..count]) |*fd, m|
            if (std.mem.eql(u8, m.tag, tag)) insert(fd, m, &r);
    }
    for (fds[0..count], mods[0..count]) |*fd, m| if (fd.* >= 0) {
        if (named) {
            r.skipped += 1;
            close(fd.*);
            fd.* = -1;
        } else insert(fd, m, &r);
    };
    return r;
}

/// insert hands one module to the kernel and counts the result. It closes
/// the file and sets fd to -1, so no module is tried twice.
fn insert(fd: *i32, m: Module, r: *Result) void {
    if (fd.* < 0) return;
    defer {
        close(fd.*);
        fd.* = -1;
    }
    const rc = linux.syscall3(
        .finit_module,
        @bitCast(@as(isize, fd.*)),
        @intFromPtr(m.params.ptr),
        0,
    );
    switch (linux.errno(rc)) {
        .SUCCESS => if (m.params.len > 0) say(
            "modload: {s}: loaded with {s}\n",
            .{ m.path, m.params },
        ),
        .EXIST => {}, // built in, or loaded already
        // The hardware is absent, as for one CPU vendor's KVM on the
        // other's. Nothing is wrong.
        .NODEV, .OPNOTSUPP => |e| {
            say("modload: {s}: no hardware for it ({t})\n", .{ m.path, e });
            r.absent += 1;
        },
        else => |e| {
            say("modload: {s}: refused by the kernel: {t}\n", .{ m.path, e });
            r.refused += 1;
        },
    }
}

/// Tags reads stdin's lines, each a tag, as stage0 writes them: `hyperv`
/// and `esp` when needed, then the slot's filesystem (`xfs`, `btrfs`, or
/// `ext4` or `none`, which no line is for).
const Tags = struct {
    buf: [64]u8 = undefined,
    start: usize = 0,
    end: usize = 0,
    done: bool = false,

    /// next returns the next line without its newline, or null at the end
    /// of stdin.
    fn next(t: *Tags) ?[]const u8 {
        while (true) {
            if (t.line()) |l| return l;
            if (t.done) return null;
            t.fill();
        }
    }

    /// line returns the next whole line buffered, or what is left at the
    /// end of stdin.
    fn line(t: *Tags) ?[]const u8 {
        const rest = t.buf[t.start..t.end];
        const i = std.mem.findScalar(u8, rest, '\n') orelse {
            if (!t.done or rest.len == 0) return null;
            t.start = t.end;
            return rest;
        };
        t.start += i + 1;
        return rest[0..i];
    }

    fn fill(t: *Tags) void {
        @memmove(t.buf[0 .. t.end - t.start], t.buf[t.start..t.end]);
        t.end -= t.start;
        t.start = 0;
        if (t.end == t.buf.len) {
            say("modload: stdin's line is too long for a tag; reading no more\n", .{});
            t.end = 0;
            t.done = true;
            return;
        }
        while (true) {
            const rc = linux.read(0, t.buf[t.end..].ptr, t.buf.len - t.end);
            if (linux.errno(rc) == .INTR) continue;
            if (linux.errno(rc) != .SUCCESS or rc == 0) t.done = true else t.end += rc;
            return;
        }
    }
};

fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.Unenforced => "refused: the kernel would load unsigned modules (no lockdown, no " ++
            "module.sig_enforce)",
        error.BadPath, error.TooMany => "refused: werewolf.modules is not a clean list",
        error.SystemCall => sandbox.errnoName(sandbox.failed_errno),
        else => @errorName(err),
    };
}

const modules_disabled = "/proc/sys/kernel/modules_disabled";

/// enforced reports whether the kernel will refuse an unsigned module:
/// lockdown at integrity or confidentiality, or module.sig_enforce.
fn enforced() bool {
    var buf: [128]u8 = undefined;
    if (readSmall("/sys/kernel/security/lockdown", &buf)) |s| {
        if (std.mem.indexOf(u8, s, "[integrity]") != null or
            std.mem.indexOf(u8, s, "[confidentiality]") != null) return true;
    }
    if (readSmall("/sys/module/module/parameters/sig_enforce", &buf)) |s| {
        if (s.len > 0 and s[0] == 'Y') return true;
    }
    return false;
}

// --- the list --------------------------------------------------------------------

const Module = struct { path: [:0]const u8, params: [:0]const u8, tag: []const u8 = "" };

/// parse reads werewolf.modules: each line is an optional `@TAG `, a clean
/// path to a .ko under kernel/, and optional parameters after a space. It
/// copies each into lines, with NULs ending the path and the parameters
/// for the kernel. One bad line, or too many, refuses the whole list.
fn parse(text: []const u8, lines: *[max_modules][256:0]u8, mods: *[max_modules]Module) !usize {
    var n: usize = 0;
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |whole| {
        if (n == max_modules) return error.TooMany;
        var line = whole;
        var tag: []const u8 = "";
        if (std.mem.startsWith(u8, line, "@")) {
            const end = std.mem.findScalar(u8, line, ' ') orelse return error.BadPath;
            tag = line[1..end];
            if (!isTag(tag)) return error.BadPath;
            line = line[end + 1 ..];
        }
        if (line.len > 255) return error.BadPath;
        const space = std.mem.findScalar(u8, line, ' ') orelse line.len;
        try checkPath(line[0..space]);
        if (space < line.len) try checkParams(line[space + 1 ..]);
        const l = &lines[n];
        @memcpy(l[0..line.len], line);
        l[space] = 0;
        l[line.len] = 0;
        mods[n] = .{
            .path = l[0..space :0],
            .params = if (space < line.len) l[space + 1 .. line.len :0] else "",
            .tag = tag,
        };
        n += 1;
    }
    return n;
}

/// isTag reports whether t, such as `xfs` or `hyperv`, is 1 to 15
/// lower-case letters and digits.
fn isTag(t: []const u8) bool {
    if (t.len == 0 or t.len > 15) return false;
    for (t) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c)) return false;
    return true;
}

/// checkParams accepts KEY=VALUE words one space apart: a key of lower-case
/// letters, digits and underscores, a value of letters, digits and _ , . -.
fn checkParams(p: []const u8) !void {
    var words = std.mem.splitScalar(u8, p, ' ');
    while (words.next()) |w| {
        const eq = std.mem.findScalar(u8, w, '=') orelse return error.BadPath;
        if (eq == 0 or eq + 1 == w.len) return error.BadPath;
        for (w[0..eq]) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and
            c != '_') return error.BadPath;
        for (w[eq + 1 ..]) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != ',' and
            c != '.' and c != '-') return error.BadPath;
    }
}

fn checkPath(p: []const u8) !void {
    if (p.len == 0 or p.len > 255) return error.BadPath;
    if (!std.mem.startsWith(u8, p, "kernel/") or
        !std.mem.endsWith(u8, p, ".ko")) return error.BadPath;
    for (p) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '/' and c != '_' and c != '-' and
            c != '.') return error.BadPath;
    }
    var parts = std.mem.splitScalar(u8, p, '/');
    while (parts.next()) |c| {
        if (c.len == 0 or std.mem.eql(u8, c, ".") or std.mem.eql(u8, c, "..")) return error.BadPath;
    }
}

// --- files -----------------------------------------------------------------------

const O_RDONLY = 0;
const O_WRONLY = 1;
const O_PATH = 0o10000000;
const O_CLOEXEC = 0o2000000;
const RESOLVE_NO_MAGICLINKS = 0x02;
const RESOLVE_NO_SYMLINKS = 0x04;
const RESOLVE_BENEATH = 0x08;
const OpenHow = extern struct { flags: u64, mode: u64, resolve: u64 };

fn openPath(path: [:0]const u8, flags: u64) !i32 {
    return openat2(linux.AT.FDCWD, path, flags, RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
}

fn openBeneath(dir: i32, path: [:0]const u8, flags: u64) !i32 {
    return openat2(dir, path, flags, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
}

fn openat2(dir: i32, path: [:0]const u8, flags: u64, resolve: u64) !i32 {
    var how: OpenHow = .{ .flags = flags | O_CLOEXEC, .mode = 0, .resolve = resolve };
    const rc = linux.syscall4(
        .openat2,
        @bitCast(@as(isize, dir)),
        @intFromPtr(path.ptr),
        @intFromPtr(&how),
        @sizeOf(OpenHow),
    );
    _ = try sandbox.sys(rc, "openat2");
    return @intCast(rc);
}

/// readBeneath reads the file at path beneath dir into buf.
fn readBeneath(dir: i32, path: [:0]const u8, buf: []u8) ![]const u8 {
    const fd = try openBeneath(dir, path, O_RDONLY);
    defer close(fd);
    return readAll(fd, buf);
}

fn readSmall(path: [:0]const u8, buf: []u8) ?[]const u8 {
    const fd = openPath(path, O_RDONLY) catch return null;
    defer close(fd);
    return readAll(fd, buf) catch null;
}

/// readAll reads fd to its end, since procfs and sysfs report a size of 0.
/// It fails if the file fills buf.
fn readAll(fd: i32, buf: []u8) ![]const u8 {
    var n: usize = 0;
    while (true) {
        if (n == buf.len) return error.TooLarge;
        const rc = try sandbox.sys(linux.read(fd, buf[n..].ptr, buf.len - n), "read");
        if (rc == 0) return buf[0..n];
        n += rc;
    }
}

fn close(fd: i32) void {
    _ = linux.close(fd);
}

// --- pledge ----------------------------------------------------------------------

const CAP_SYS_MODULE = 16;

/// pledge keeps only CAP_SYS_MODULE, for good, and installs a seccomp filter
/// of the calls loading and closing the loader need.
fn pledge() !void {
    try sandbox.keepOnly(1 << CAP_SYS_MODULE);
    var f: sandbox.Filter = .{};
    inline for (.{ "finit_module", "read", "write", "close", "exit", "exit_group" }) |name|
        f.allow(name);
    try f.install();
}

// --- saying so -------------------------------------------------------------------

fn say(comptime format: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, format, args) catch "modload: (message too long)\n";
    _ = linux.write(2, line.ptr, line.len);
}

fn fail(what: []const u8, err: anyerror) noreturn {
    if (err == error.SystemCall)
        say(
            "modload: {s}: {s}: {s}\n",
            .{ what, sandbox.failed, sandbox.errnoName(sandbox.failed_errno) },
        )
    else
        say("modload: {s}: {s}\n", .{ what, @errorName(err) });
    linux.exit_group(1);
}

// --- tests -----------------------------------------------------------------------

const testing = std.testing;

test "a clean list parses, in order, with parameters" {
    var lines: [max_modules][256:0]u8 = undefined;
    var mods: [max_modules]Module = undefined;
    const n = try parse(
        "kernel/drivers/block/virtio_blk.ko\nkernel/arch/x86/kvm/kvm-intel.ko nested=0 " ++
            "ept=1\nkernel/net/packet/af_packet.ko\n",
        &lines,
        &mods,
    );
    try testing.expectEqual(3, n);
    try testing.expectEqualStrings("kernel/drivers/block/virtio_blk.ko", mods[0].path);
    try testing.expectEqualStrings("", mods[0].params);
    try testing.expectEqualStrings("kernel/arch/x86/kvm/kvm-intel.ko", mods[1].path);
    try testing.expectEqualStrings("nested=0 ept=1", mods[1].params);
    try testing.expectEqual(0, mods[1].params.ptr[mods[1].params.len]);
    try testing.expectEqualStrings("kernel/net/packet/af_packet.ko", mods[2].path);
}

test "one bad line refuses the list" {
    var lines: [max_modules][256:0]u8 = undefined;
    var mods: [max_modules]Module = undefined;
    for ([_][]const u8{
        "kernel/drivers/x.ko\n/etc/x.ko\n",
        "kernel/../x.ko\n",
        "kernel/./x.ko\n",
        "kernel//x.ko\n",
        "kernel/drivers/x.ko.gz\n",
        "drivers/x.ko\n",
        "kernel/x y.ko\n",
        "kernel/x.ko\x00\n",
        "kernel/x.ko \n",
        "kernel/x.ko nested\n",
        "kernel/x.ko =1\n",
        "kernel/x.ko nested=\n",
        "kernel/x.ko nested=0  ept=1\n",
        "kernel/x.ko Nested=0\n",
        "kernel/x.ko nested=$(x)\n",
        "kernel/x.ko nested=0\tept=1\n",
        "@ kernel/x.ko\n",
        "@Xfs kernel/x.ko\n",
        "@xfs\n",
        "@x-fs kernel/x.ko\n",
        "@abcdefghijklmnop kernel/x.ko\n",
        "@xfs @btrfs kernel/x.ko\n",
        "@xfs /etc/x.ko\n",
    }) |text| try testing.expectError(error.BadPath, parse(text, &lines, &mods));
}

test "a line for one filesystem keeps its tag apart from its path" {
    var lines: [max_modules][256:0]u8 = undefined;
    var mods: [max_modules]Module = undefined;
    const n = try parse(
        "kernel/fs/ext4/ext4.ko\n@btrfs kernel/lib/raid6/raid6_pq.ko\n" ++
            "@xfs kernel/fs/xfs/xfs.ko opt=1\n",
        &lines,
        &mods,
    );
    try testing.expectEqual(3, n);
    try testing.expectEqualStrings("", mods[0].tag);
    try testing.expectEqualStrings("btrfs", mods[1].tag);
    try testing.expectEqualStrings("kernel/lib/raid6/raid6_pq.ko", mods[1].path);
    try testing.expectEqualStrings("", mods[1].params);
    try testing.expectEqualStrings("xfs", mods[2].tag);
    try testing.expectEqualStrings("kernel/fs/xfs/xfs.ko", mods[2].path);
    try testing.expectEqualStrings("opt=1", mods[2].params);
    try testing.expectEqual(0, mods[2].path.ptr[mods[2].path.len]);
}

test Tags {
    var tags: Tags = .{ .done = true };
    const text = "hyperv\nxfs\nbtr";
    @memcpy(tags.buf[0..text.len], text);
    tags.end = text.len;
    try testing.expectEqualStrings("hyperv", tags.next().?);
    try testing.expectEqualStrings("xfs", tags.next().?);
    try testing.expectEqualStrings("btr", tags.next().?);
    try testing.expectEqual(null, tags.next());

    tags = .{ .done = true };
    try testing.expectEqual(null, tags.next());

    tags = .{};
    @memcpy(tags.buf[0..4], "xfs\n");
    tags.end = 4;
    try testing.expectEqualStrings("xfs", tags.line().?);
    try testing.expectEqual(null, tags.line());
}

test "too many modules refuses the list" {
    var lines: [max_modules][256:0]u8 = undefined;
    var mods: [max_modules]Module = undefined;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    for (0..max_modules + 1) |_| try text.appendSlice(testing.allocator, "kernel/x.ko\n");
    try testing.expectError(error.TooMany, parse(text.items, &lines, &mods));
}
