//! posture: measure a Linux machine's security posture, and print it as a
//! list of what passed and failed, or as JSON.
//!
//!     posture           check, print, and exit 1 if any check fails
//!     posture --json    the same, as JSON, with why and how each was checked
//!     posture --line    the same, as one line for a console or a log:
//!                       posture: fail=ID,ID pass=N skip=N {JSON}
//!     posture --noop    exit 0 at once: what the run-a-program checks run
//!     posture --attack  also attack the machine (attacks, below), as
//!                       werewolf.check=1 does, where the command line cannot
//!                       say so -- a check run in a container. WEREWOLF_CHECK=1
//!                       in the environment asks the same of the boot service.
//!
//! --extended adds the checks werewolf fails by choice, because meeting
//! them would slow what machines run, or is not yet shown safe with fence
//! (docs/security.md, "Not done, by choice"): wiping freed memory,
//! forced CPU mitigations, strict reverse-path filtering, and ignoring
//! IPv6 router advertisements. Any Linux can be measured against them.
//!
//! Each check says what it protects against in plain words, how it was
//! checked, and whether it passed. Where it is safe, a check tests rather
//! than reads: it asks the kernel to undo a one-way setting and expects a
//! refusal, and it copies itself into each writable place and into a memfd
//! and expects the copy not to start. It asks the kernel only when the
//! setting already reads as locked, when the refusal is certain, so a check
//! that fails never weakens the machine. Nothing touches another process or
//! /dev/mem, which would write to the kernel log, unless asked: the kernel
//! command line has werewolf.check=1 (werewolf's tests set it), or --attack
//! or WEREWOLF_CHECK=1 asks where the command line cannot be set. posture then
//! also attacks the machine and expects each attack refused (attacks, below).
//! None of the attacks harm a sound machine; each expects to be refused.
//!
//! Run as root for the whole picture; as another user some checks read what
//! they can and some are skipped. It assumes nothing of werewolf: run it on
//! any Linux to compare. werewolf's own checks (its services, its declared
//! ports, /victim) are skipped where those do not exist.
//!
//! In werewolf it is also a service, run once a boot as /etc/sv/posture/run:
//! it waits for the other services to settle, so it sees the machine as it
//! runs, checks, keeps the JSON in /run/werewolf/posture.json, says the
//! --line on the console, and parks itself.
const attacks = @import("attacks.zig");
const files = @import("files.zig");
const kernel = @import("kernel.zig");
const network = @import("network.zig");
const processes = @import("processes.zig");
const probe = @import("attacks.zig").probe;

const std = @import("std");

const Io = std.Io;

const Dir = Io.Dir;

const Allocator = std.mem.Allocator;

const linux = std.os.linux;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len == 2 and std.mem.eql(u8, args[1], "--noop")) return;
    if (args.len == 2 and std.mem.eql(u8, args[1], "--probe")) std.process.exit(probe());
    if (std.mem.eql(u8, std.fs.path.basename(args[0]), "run")) return serve(io, gpa);
    var format: Format = .text;
    var extended = false;
    var attack = false;
    for (args[1..]) |a| {
        if (std.mem.eql(u8, a, "--extended") and !extended) {
            extended = true;
        } else if (std.mem.eql(u8, a, "--attack") and !attack) {
            attack = true;
        } else if (std.mem.eql(u8, a, "--json") and format == .text) {
            format = .json;
        } else if (std.mem.eql(u8, a, "--line") and format == .text) {
            format = .line;
        } else {
            std.debug.print("usage: posture [--extended] [--attack] [--json | --line]\n", .{});
            std.process.exit(2);
        }
    }

    var p: Posture = .{
        .io = io,
        .gpa = gpa,
        .root = linux.geteuid() == 0,
        .extended = extended,
        .attack = attack,
    };
    try p.run();
    const report = try p.report();
    var out: Io.Writer.Allocating = .init(gpa);
    switch (format) {
        .text => try printText(&out.writer, report, columns()),
        .json => {
            try std.json.Stringify.value(report, .{ .whitespace = .indent_2 }, &out.writer);
            try out.writer.writeByte('\n');
        },
        .line => try printLine(gpa, &out.writer, report),
    }
    try Io.File.stdout().writeStreamingAll(io, out.written());
    if (report.summary.fail > 0) std.process.exit(1);
}

const Format = enum { text, json, line };

const service_json = "/run/werewolf/posture.json";

/// How long every other service must have run, or been down by choice.
const settle_s = 5;

/// How long to wait for that before checking anyway.
const settle_max_s = 60;

fn serve(io: Io, gpa: Allocator) !void {
    var waited: u32 = 0;
    while (waited < settle_max_s and
        !settled(io, gpa)) : (waited += 1) io.sleep(.fromSeconds(1), .awake) catch {};

    var p: Posture = .{ .io = io, .gpa = gpa, .root = linux.geteuid() == 0 };
    try p.run();
    const report = try p.report();
    var json: Io.Writer.Allocating = .init(gpa);
    try std.json.Stringify.value(report, .{ .whitespace = .indent_2 }, &json.writer);
    try json.writer.writeByte('\n');
    const tmp = service_json ++ ".tmp";
    Dir.cwd().writeFile(
        io,
        .{ .sub_path = tmp, .data = json.written() },
    ) catch |err| std.debug.print("posture: {s}: {s}\n", .{ tmp, @errorName(err) });
    Dir.rename(
        Dir.cwd(),
        tmp,
        Dir.cwd(),
        service_json,
        io,
    ) catch |err| std.debug.print("posture: {s}: {s}\n", .{ service_json, @errorName(err) });

    var line: Io.Writer.Allocating = .init(gpa);
    try printLine(gpa, &line.writer, report);
    try Io.File.stdout().writeStreamingAll(io, line.written());

    // Down, so runsv does not run it again until the next boot.
    const err = std.process.replace(io, .{ .argv = &.{ "/usr/bin/sv", "down", "." } });
    std.debug.print("posture: sv down: {s}\n", .{@errorName(err)});
    std.process.exit(1);
}

/// Whether every service but this one has settled, by runsv's own account.
fn settled(io: Io, gpa: Allocator) bool {
    var d = Dir.cwd().openDir(io, "/etc/sv", .{ .iterate = true }) catch return true;
    defer d.close(io);
    const now = nowSecs(io);
    var it = d.iterate();
    while (it.next(io) catch return false) |e| {
        if (std.mem.eql(u8, e.name, "posture")) continue;
        var f = d.openFile(
            io,
            gpa.print("{s}/supervise/status", .{e.name}) catch return false,
            .{},
        ) catch return false;
        defer f.close(io);
        var status: [20]u8 = undefined;
        const n = f.readPositionalAll(io, &status, 0) catch return false;
        if (n != status.len or !serviceSettled(status, now)) return false;
    }
    return true;
}

/// Whether runsv's supervise/status says the service is down because it
/// was asked to be, or has run for settle_s. The 20 bytes are the time of
/// the last change, as TAI64N (seconds since 1970 plus 2^62 + 10), the pid,
/// paused, want ('u' or 'd'), a term flag, and the state (0 down, 1 run, 2
/// finish).
fn serviceSettled(status: [20]u8, now: u64) bool {
    const since = std.mem.readInt(u64, status[0..8], .big) -| ((1 << 62) + 10);
    return switch (status[19]) {
        0 => status[17] == 'd',
        1 => now -| since >= settle_s,
        else => false,
    };
}

/// What posture prints.
pub const Report = struct {
    tool: []const u8 = "posture",
    version: u32 = 1,
    time: []const u8,
    /// The distribution, as /etc/os-release names it.
    os: []const u8,
    host: []const u8,
    kernel: []const u8,
    root: bool,
    /// What the machine's form took back of werewolf's defaults when it was
    /// built (/etc/werewolf/allow), sorted. The checks still measure it.
    allow: []const []const u8 = &.{},
    summary: struct { pass: usize = 0, fail: usize = 0, skip: usize = 0 },
    checks: []const Check,
};

pub const Check = struct {
    id: []const u8,
    /// kernel, processes, programs, files or network.
    area: []const u8,
    name: []const u8,
    /// What it protects against, in plain words.
    why: []const u8,
    /// How it was checked, exactly.
    how: []const u8,
    result: Result,
    /// What was found, when that adds to the result.
    detail: []const u8 = "",
};

pub const Result = enum {
    pass,
    fail,
    skip,

    fn mark(r: Result) []const u8 {
        return switch (r) {
            .pass => "✅",
            .fail => "❌",
            .skip => "⚠️",
        };
    }
};

pub const Posture = struct {
    io: Io,
    gpa: Allocator,
    root: bool,
    /// Also the checks werewolf fails by choice (--extended).
    extended: bool = false,
    /// Attack the machine (attacks, below), whatever the command line says:
    /// --attack, or WEREWOLF_CHECK=1 in the environment, for a check that
    /// cannot set the kernel command line, such as one run in a container.
    attack: bool = false,
    checks: std.ArrayList(Check) = .empty,

    pub fn add(p: *Posture, c: Check) !void {
        try p.checks.append(p.gpa, c);
    }

    /// The names in /etc/werewolf/allow, sorted.
    pub fn allowances(p: *Posture) ![]const []const u8 {
        var names: std.ArrayList([]const u8) = .empty;
        var d = Dir.cwd().openDir(
            p.io,
            "/etc/werewolf/allow",
            .{ .iterate = true },
        ) catch return names.items;
        defer d.close(p.io);
        var it = d.iterate();
        while (it.next(p.io) catch null) |e| try names.append(p.gpa, try p.gpa.dupe(u8, e.name));
        std.mem.sort([]const u8, names.items, {}, lessString);
        return names.items;
    }

    pub fn report(p: *Posture) !Report {
        const uts = std.posix.uname();
        const os_release = p.read("/etc/os-release");
        var r: Report = .{
            .time = try rfc3339(p.gpa, nowSecs(p.io)),
            .os = prettyName(if (os_release.len > 0) os_release else p.read("/usr/lib/os-release")),
            .host = try p.gpa.dupe(u8, std.mem.sliceTo(&uts.nodename, 0)),
            .kernel = try p.gpa.dupe(u8, std.mem.sliceTo(&uts.release, 0)),
            .root = p.root,
            .allow = try p.allowances(),
            .summary = .{},
            .checks = p.checks.items,
        };
        for (p.checks.items) |c| switch (c.result) {
            .pass => r.summary.pass += 1,
            .fail => r.summary.fail += 1,
            .skip => r.summary.skip += 1,
        };
        return r;
    }

    pub fn run(p: *Posture) !void {
        try kernel.check(p);
        try processes.check(p);
        try processes.programs(p);
        try files.check(p);
        try network.check(p);
        if (p.root and p.attacksAsked()) return attacks.run(p);
    }

    /// Whether to attack: --attack or WEREWOLF_CHECK=1 (a container cannot set
    /// the kernel command line), or werewolf.check=1 on a real machine's line.
    pub fn attacksAsked(p: *Posture) bool {
        if (p.attack) return true;
        var env = std.mem.tokenizeScalar(u8, p.read("/proc/self/environ"), 0);
        while (env.next()) |kv| {
            if (std.mem.eql(u8, kv, "WEREWOLF_CHECK=1")) return true;
        }
        var args = std.mem.tokenizeAny(u8, p.read("/proc/cmdline"), " \n");
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "werewolf.check=1")) return true;
        }
        return false;
    }

    /// None of names is on the system's PATH directories.
    pub fn absent(
        p: *Posture,
        id: []const u8,
        name: []const u8,
        why: []const u8,
        names: []const []const u8,
    ) !void {
        var found: std.ArrayList(u8) = .empty;
        var how: std.ArrayList(u8) = .empty;
        try how.appendSlice(p.gpa, "none of ");
        for (names, 0..) |n, i| {
            if (i > 0) try how.appendSlice(p.gpa, ", ");
            try how.appendSlice(p.gpa, n);
            for ([_][]const u8{
                "/bin",
                "/sbin",
                "/usr/bin",
                "/usr/sbin",
                "/usr/local/bin",
                "/usr/local/sbin",
            }) |dir| {
                const path = try p.gpa.print("{s}/{s}", .{ dir, n });
                if (!exists(p.io, path)) continue;
                try found.print(p.gpa, "{s}{s}", .{ if (found.items.len > 0) ", " else "", path });
                break;
            }
        }
        try how.appendSlice(p.gpa, " in /bin, /sbin, /usr/bin, /usr/sbin or /usr/local");
        try p.add(.{
            .id = id,
            .area = "programs",
            .name = name,
            .why = why,
            .how = how.items,
            .result = if (found.items.len == 0) .pass else .fail,
            .detail = found.items,
        });
    }

    pub fn absentNamed(
        p: *Posture,
        id: []const u8,
        area: []const u8,
        name: []const u8,
        why: []const u8,
        names: []const []const u8,
    ) !void {
        try p.absent(id, name, why, names);
        p.checks.items[p.checks.items.len - 1].area = area;
    }

    /// A setting the kernel lets rise but never fall: it must read locked,
    /// and as root, writing the unlocked value must be refused.
    pub fn oneWay(
        p: *Posture,
        id: []const u8,
        name: []const u8,
        why: []const u8,
        key: []const u8,
        locked: []const u8,
        unlocked: []const u8,
    ) !void {
        const path = try p.gpa.print("/proc/sys/{s}", .{key});
        const value = trim(p.read(path));
        const is_locked = std.mem.eql(u8, value, locked);
        const lowered = is_locked and p.root and !p.refused(path, unlocked);
        try p.add(.{
            .id = id,
            .area = "kernel",
            .name = name,
            .why = why,
            .how = if (p.root)
                try p.gpa.print(
                    "{s} is {s}, and writing {s} is refused",
                    .{ dotted(p.gpa, key), locked, unlocked },
                )
            else
                try p.gpa.print("{s} is {s}", .{ dotted(p.gpa, key), locked }),
            .result = if (is_locked and !lowered) .pass else .fail,
            .detail = if (is_locked) "" else try p.gpa.print(
                "{s} is {s}",
                .{ dotted(p.gpa, key), if (value.len > 0) value else "absent" },
            ),
        });
    }

    /// Settings that must hold these values. A * in a key stands for every
    /// entry in its directory, such as every interface, all and default
    /// among them; a directory that is not there has none to fail.
    pub fn sysctls(
        p: *Posture,
        id: []const u8,
        area: []const u8,
        name: []const u8,
        why: []const u8,
        want: []const [2][]const u8,
    ) !void {
        var how: std.ArrayList(u8) = .empty;
        var bad: std.ArrayList(u8) = .empty;
        for (want, 0..) |kv, i| {
            if (i > 0) try how.appendSlice(p.gpa, ", ");
            try how.print(p.gpa, "{s} = {s}", .{ dotted(p.gpa, kv[0]), kv[1] });
            for (try p.expand(kv[0])) |key| {
                const value = p.sysctl(key);
                if (!std.mem.eql(
                    u8,
                    value,
                    kv[1],
                )) try bad.print(
                    p.gpa,
                    "{s}{s} is {s}",
                    .{
                        if (bad.items.len > 0) ", " else "",
                        dotted(p.gpa, key),
                        if (value.len > 0) value else "absent",
                    },
                );
            }
        }
        try p.add(.{
            .id = id,
            .area = area,
            .name = name,
            .why = why,
            .how = how.items,
            .result = if (bad.items.len == 0) .pass else .fail,
            .detail = bad.items,
        });
    }

    /// key, or where it has a /*/, the key for each entry in that directory
    /// of /proc/sys, in order.
    pub fn expand(p: *Posture, key: []const u8) ![]const []const u8 {
        const star = std.mem.indexOf(u8, key, "/*/") orelse return p.gpa.dupe([]const u8, &.{key});
        var d = Dir.cwd().openDir(
            p.io,
            try p.gpa.print("/proc/sys/{s}", .{key[0..star]}),
            .{ .iterate = true },
        ) catch return &.{};
        defer d.close(p.io);
        var keys: std.ArrayList([]const u8) = .empty;
        var it = d.iterate();
        while (it.next(p.io) catch null) |e| try keys.append(
            p.gpa,
            try p.gpa.print("{s}/{s}{s}", .{ key[0..star], e.name, key[star + 2 ..] }),
        );
        std.mem.sort([]const u8, keys.items, {}, lessString);
        return keys.items;
    }

    /// A setting's value, without its newline.
    pub fn sysctl(p: *Posture, key: []const u8) []const u8 {
        return trim(p.read(p.gpa.print("/proc/sys/{s}", .{key}) catch return ""));
    }

    /// path, read to its end, or "". Not Dir.readFileAlloc, which reads
    /// only as much as stat reports: procfs reports 0.
    pub fn read(p: *Posture, path: []const u8) []const u8 {
        var f = Dir.cwd().openFile(p.io, path, .{}) catch return "";
        defer f.close(p.io);
        var buf: [4096]u8 = undefined;
        var r = f.readerStreaming(p.io, &buf);
        return r.interface.allocRemaining(p.gpa, .limited(16 << 20)) catch "";
    }

    /// Whether writing value to path fails.
    pub fn refused(p: *Posture, path: []const u8, value: []const u8) bool {
        Dir.cwd().writeFile(p.io, .{ .sub_path = path, .data = value }) catch return true;
        return false;
    }

    pub fn isElf(p: *Posture, path: []const u8) bool {
        var f = Dir.cwd().openFile(p.io, path, .{}) catch return false;
        defer f.close(p.io);
        var magic: [4]u8 = undefined;
        const n = f.readPositionalAll(p.io, &magic, 0) catch return false;
        return n == 4 and std.mem.eql(u8, &magic, "\x7fELF");
    }
};

/// The report as people read it: a mark for each check, by area, and what
/// was found where a check did not pass. Details are cut to fit cols, the
/// terminal's width, when there is one.
fn printText(w: *Io.Writer, r: Report, cols: ?usize) !void {
    try writeClean(w, r.os);
    try w.writeAll(", Linux ");
    try writeClean(w, r.kernel);
    try w.writeAll(", on ");
    try writeClean(w, r.host);
    try w.print(" ({s})\n", .{if (r.root) "root" else "not root: some checks are limited"});
    if (r.allow.len > 0) {
        try w.writeAll("Its form allows:");
        for (r.allow) |a| {
            try w.writeByte(' ');
            try writeClean(w, a);
        }
        try w.writeByte('\n');
    }
    var width: usize = 0;
    for (r.checks) |c| width = @max(width, c.name.len);
    // Two spaces, a mark two columns wide, a space, the name padded to
    // width, two spaces, then the detail.
    const room = if (cols) |n| n -| (width + 7) else std.math.maxInt(usize);
    var area: []const u8 = "";
    for (r.checks) |c| {
        if (!std.mem.eql(u8, c.area, area)) {
            area = c.area;
            try w.print("\n{c}{s}\n", .{ std.ascii.toUpper(area[0]), area[1..] });
        }
        try w.print("  {s} {s}", .{ c.result.mark(), c.name });
        if (c.result != .pass and c.detail.len > 0) {
            const f = fit(c.detail, room);
            try w.splatByteAll(' ', width - c.name.len + 2);
            try writeClean(w, c.detail[0..f.len]);
            if (f.more > 0) try w.print(", +{d} more", .{f.more});
        }
        try w.writeByte('\n');
    }
    try w.print("\n{s} {d} passed   {s} {d} failed   {s} {d} skipped\n", .{
        Result.pass.mark(), r.summary.pass, Result.fail.mark(), r.summary.fail,
        Result.skip.mark(), r.summary.skip,
    });
}

/// text, each control character in it, and each byte that is not UTF-8,
/// as ?: what a check found is the machine's, file names others chose
/// among it, and must not write to the terminal it is shown on. The JSON
/// escapes them itself.
fn writeClean(w: *Io.Writer, text: []const u8) !void {
    var i: usize = 0;
    while (i < text.len) {
        const n = std.unicode.utf8ByteSequenceLength(text[i]) catch 0;
        const char = if (n > 0 and i + n <= text.len) text[i..][0..n] else "";
        // C0 and DEL, and C1, which a terminal may take even as UTF-8.
        const control = (char.len == 1 and (char[0] < 0x20 or char[0] == 0x7f)) or
            (char.len == 2 and char[0] == 0xc2 and char[1] < 0xa0);
        if (char.len > 0 and !control and std.unicode.utf8ValidateSlice(char)) {
            try w.writeAll(char);
            i += n;
        } else {
            try w.writeByte('?');
            i += @max(char.len, 1);
        }
    }
}

/// One line: the ids that failed, sorted and between commas (none: fail=
/// and a space), the counts, then the whole report as JSON. A harness can
/// match the start and parse the rest.
fn printLine(gpa: Allocator, w: *Io.Writer, r: Report) !void {
    var failed: std.ArrayList([]const u8) = .empty;
    for (r.checks) |c| if (c.result == .fail) try failed.append(gpa, c.id);
    std.mem.sort([]const u8, failed.items, {}, lessString);
    try w.writeAll("posture: fail=");
    for (failed.items, 0..) |id, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll(id);
    }
    try w.print(" pass={d} skip={d} ", .{ r.summary.pass, r.summary.skip });
    try std.json.Stringify.value(r, .{}, w);
    try w.writeByte('\n');
}

/// How much of detail, items between ", ", fits in max bytes: whole items,
/// with room left to say how many more there are. The first item is kept
/// even when it alone is too long.
fn fit(detail: []const u8, max: usize) struct { len: usize, more: usize } {
    if (detail.len <= max) return .{ .len = detail.len, .more = 0 };
    const items = std.mem.count(u8, detail, ", ") + 1;
    var len: usize = 0;
    var shown: usize = 0;
    var it = std.mem.splitSequence(u8, detail, ", ");
    while (it.next()) |item| : (shown += 1) {
        const end = if (shown == 0) item.len else len + 2 + item.len;
        if (shown > 0 and end + std.fmt.count(", +{d} more", .{items - shown - 1}) > max) break;
        len = end;
    }
    return .{ .len = len, .more = items - shown };
}

/// stdout's width in columns, or null when it is not a terminal.
fn columns() ?usize {
    var ws: std.posix.winsize = undefined;
    const rc = linux.ioctl(Io.File.stdout().handle, linux.T.IOCGWINSZ, @intFromPtr(&ws));
    if (linux.errno(rc) != .SUCCESS or ws.col == 0) return null;
    return ws.col;
}

/// PRETTY_NAME in an os-release file, unquoted, or "Linux", its default.
fn prettyName(text: []const u8) []const u8 {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "PRETTY_NAME=")) continue;
        const name = std.mem.trim(u8, line["PRETTY_NAME=".len..], "\"' \r");
        if (name.len > 0) return name;
    }
    return "Linux";
}

/// Whether the mount at point (the last there, which is the one that shows)
/// has option among its options.
pub fn hasOption(mounts: []const u8, point: []const u8, option: []const u8) bool {
    var found = false;
    var it = std.mem.tokenizeScalar(u8, mounts, '\n');
    while (it.next()) |line| {
        const m = parseMount(line) orelse continue;
        if (!std.mem.eql(u8, m.dir, point)) continue;
        found = false;
        var o = std.mem.tokenizeScalar(u8, m.opts, ',');
        while (o.next()) |x| found = found or std.mem.eql(u8, x, option);
    }
    return found;
}

pub fn mountType(mounts: []const u8, point: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    var it = std.mem.tokenizeScalar(u8, mounts, '\n');
    while (it.next()) |line| {
        const m = parseMount(line) orelse continue;
        if (std.mem.eql(u8, m.dir, point)) found = m.kind;
    }
    return found;
}

/// names, between commas.
pub fn joined(comptime names: []const []const u8) []const u8 {
    comptime var s: []const u8 = "";
    inline for (names, 0..) |n, i| s = s ++ (if (i > 0) ", " else "") ++ n;
    return s;
}

const Mount = struct { dir: []const u8, kind: []const u8, opts: []const u8 };

fn parseMount(line: []const u8) ?Mount {
    var f = std.mem.tokenizeScalar(u8, line, ' ');
    _ = f.next() orelse return null;
    const dir = f.next() orelse return null;
    const kind = f.next() orelse return null;
    const opts = f.next() orelse return null;
    return .{ .dir = dir, .kind = kind, .opts = opts };
}

/// The mount points, but those in except, whose options lack option, each
/// once.
pub fn missingOption(
    gpa: Allocator,
    mounts: []const u8,
    option: []const u8,
    except: []const []const u8,
) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, mounts, '\n');
    next: while (it.next()) |line| {
        const m = parseMount(line) orelse continue;
        for (except) |e| if (std.mem.eql(u8, m.dir, e)) continue :next;
        if (hasOption(line, m.dir, option)) continue;
        var seen = std.mem.tokenizeAny(u8, out.items, ", ");
        while (seen.next()) |d| if (std.mem.eql(u8, d, m.dir)) continue :next;
        try out.print(gpa, "{s}{s}", .{ if (out.items.len > 0) ", " else "", m.dir });
    }
    return out.items;
}

/// Whether capability n is in a /proc/PID/status set, given in hex, or null
/// if the field is missing.
pub fn capBit(status: []const u8, field: []const u8, n: u6) ?bool {
    const hex = statusField(status, field) orelse return null;
    const set = std.fmt.parseInt(u64, hex, 16) catch return null;
    return set & (@as(u64, 1) << n) != 0;
}

/// A field's value on a /proc/PID/status line, "Name:\tvalue".
pub fn statusField(status: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, status, '\n');
    while (it.next()) |line| {
        if (line.len > name.len and std.mem.startsWith(u8, line, name) and
            line[name.len] == ':') return std.mem.trim(u8, line[name.len + 1 ..], " \t");
    }
    return null;
}

pub fn uidOf(status: []const u8) ?u32 {
    var it = std.mem.tokenizeScalar(u8, status, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "Uid:")) continue;
        var f = std.mem.tokenizeAny(u8, line[4..], " \t");
        return std.fmt.parseInt(u32, f.next() orelse return null, 10) catch null;
    }
    return null;
}

/// kernel/yama/ptrace_scope as sysctl names it: kernel.yama.ptrace_scope.
fn dotted(gpa: Allocator, key: []const u8) []const u8 {
    const out = gpa.dupe(u8, key) catch return key;
    std.mem.replaceScalar(u8, out, '/', '.');
    return out;
}

pub fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \r\n");
}

pub fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

pub fn statx(gpa: Allocator, path: []const u8) ?linux.Statx {
    const z = gpa.printSentinel("{s}", .{path}, 0) catch return null;
    var st: linux.Statx = undefined;
    const rc = linux.statx(
        linux.AT.FDCWD,
        z,
        linux.AT.SYMLINK_NOFOLLOW,
        .{ .TYPE = true, .MODE = true, .UID = true },
        &st,
    );
    if (linux.errno(rc) != .SUCCESS) return null;
    return st;
}

pub fn lessString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn nowSecs(io: Io) u64 {
    return @intCast(@max(0, @divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s)));
}

fn rfc3339(gpa: Allocator, secs: u64) ![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return gpa.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,              md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
}

const testing = std.testing;

// Each area's tests, with these.
test {
    _ = attacks;
    _ = files;
    _ = kernel;
    _ = network;
    _ = processes;
}

const test_mounts =
    \\/dev/root / ext4 rw,relatime 0 0
    \\proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=invisible 0 0
    \\dev /dev devtmpfs rw,nosuid,noexec,relatime 0 0
    \\tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0
    \\tmpfs /run tmpfs rw,nosuid,nodev 0 0
    \\/dev/vda1 /victim ext4 ro,nosuid,nodev,noexec 0 0
    \\/dev/vda1 /data ext4 rw,nosuid,nodev,noexec,noatime 0 0
    \\mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec 0 0
;

test hasOption {
    try testing.expect(hasOption(test_mounts, "/proc", "hidepid=invisible"));
    try testing.expect(hasOption(test_mounts, "/victim", "ro"));
    try testing.expect(!hasOption(test_mounts, "/", "ro"));
    try testing.expect(!hasOption(test_mounts, "/run", "noexec"));
    try testing.expectEqualStrings("ext4", mountType(test_mounts, "/data").?);
    try testing.expectEqual(null, mountType(test_mounts, "/nowhere"));
}

test missingOption {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("/", try missingOption(a, test_mounts, "nosuid", &.{}));
    try testing.expectEqualStrings("/run", try missingOption(a, test_mounts, "noexec", &.{"/"}));
    try testing.expectEqualStrings(
        "",
        try missingOption(a, test_mounts, "nodev", &.{ "/", "/dev" }),
    );
}

test capBit {
    const status = "CapEff:\t000001ffffffffff\nCapBnd:\t000001fffe7cfdff\n";
    try testing.expect(capBit(status, "CapEff", 17).?);
    try testing.expect(!capBit(status, "CapBnd", 16).?);
    try testing.expect(capBit(status, "CapBnd", 12).?);
    try testing.expectEqual(null, capBit(status, "CapPrm", 0));
}

test statusField {
    const status = "Name:\trunit\nSeccomp:\t2\nSeccomp_filters:\t1\n";
    try testing.expectEqualStrings("2", statusField(status, "Seccomp").?);
    try testing.expectEqualStrings("1", statusField(status, "Seccomp_filters").?);
    try testing.expectEqual(null, statusField(status, "NoNewPrivs"));
}

test uidOf {
    try testing.expectEqual(200, uidOf("Name:\tnginx\nUid:\t200\t200\t200\t200\nGid:\t200\n").?);
    try testing.expectEqual(null, uidOf("Name:\tx\n"));
}

test dotted {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings(
        "kernel.yama.ptrace_scope",
        dotted(arena.allocator(), "kernel/yama/ptrace_scope"),
    );
}

test printText {
    const checks = [_]Check{
        .{
            .id = "a",
            .area = "kernel",
            .name = "Kernel lockdown",
            .why = "",
            .how = "",
            .result = .pass,
            .detail = "integrity",
        },
        .{
            .id = "b",
            .area = "kernel",
            .name = "No SysRq",
            .why = "",
            .how = "",
            .result = .fail,
            .detail = "kernel.sysrq is 176",
        },
        .{
            .id = "c",
            .area = "processes",
            .name = "No setuid or setgid programs",
            .why = "",
            .how = "",
            .result = .fail,
            .detail = "/usr/bin/su, /usr/bin/sudo, /usr/bin/passwd, /usr/bin/mount",
        },
        .{
            .id = "d",
            .area = "network",
            .name = "Only declared ports open",
            .why = "",
            .how = "",
            .result = .skip,
            .detail = "listening: 22",
        },
    };
    const r: Report = .{
        .time = "",
        .os = "Wolfi",
        .host = "h",
        .kernel = "6.12.1",
        .root = true,
        .summary = .{ .pass = 1, .fail = 2, .skip = 1 },
        .checks = &checks,
    };
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try printText(&out.writer, r, 60);
    try testing.expectEqualStrings(
        \\Wolfi, Linux 6.12.1, on h (root)
        \\
        \\Kernel
        \\  ✅ Kernel lockdown
        \\  ❌ No SysRq                      kernel.sysrq is 176
        \\
        \\Processes
        \\  ❌ No setuid or setgid programs  /usr/bin/su, +3 more
        \\
        \\Network
        \\  ⚠️ Only declared ports open      listening: 22
        \\
        \\✅ 1 passed   ❌ 2 failed   ⚠️ 1 skipped
        \\
    , out.written());

    // Not a terminal: nothing is cut.
    out.clearRetainingCapacity();
    try printText(&out.writer, r, null);
    try testing.expect(std.mem.indexOf(
        u8,
        out.written(),
        "/usr/bin/passwd, /usr/bin/mount\n",
    ) != null);
}

test writeClean {
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    // A title, a colour, a C1 CSI as UTF-8 and as a byte, a byte that is no
    // UTF-8, and a sequence cut short; what is printable stays, é included.
    try writeClean(&out.writer, "/tmp/\x1b]0;owned\x07 \x1b[31m é \xc2\x9b2J \x9b \xff\x7f\xc3");
    try testing.expectEqualStrings("/tmp/?]0;owned? ?[31m é ?2J ? ???", out.written());

    // What printText shows of the host and of a check's detail.
    const checks = [_]Check{.{
        .id = "w",
        .area = "files",
        .name = "Shared places are sticky",
        .why = "",
        .how = "",
        .result = .fail,
        .detail = "/tmp/\x1b[2J",
    }};
    out.clearRetainingCapacity();
    try printText(&out.writer, .{
        .time = "",
        .os = "Wolfi",
        .host = "h\x1b[8m",
        .kernel = "6.12.1",
        .root = true,
        .summary = .{ .fail = 1 },
        .checks = &checks,
    }, null);
    try testing.expect(std.mem.findScalar(u8, out.written(), 0x1b) == null);
    try testing.expect(std.mem.find(u8, out.written(), "on h?[8m (root)") != null);
    try testing.expect(std.mem.find(u8, out.written(), "/tmp/?[2J\n") != null);
}

test printLine {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const checks = [_]Check{
        .{
            .id = "programs-shell",
            .area = "programs",
            .name = "No shell",
            .why = "",
            .how = "",
            .result = .fail,
        },
        .{
            .id = "kernel-lockdown",
            .area = "kernel",
            .name = "Kernel lockdown",
            .why = "",
            .how = "",
            .result = .pass,
        },
        .{
            .id = "kernel-io-uring",
            .area = "kernel",
            .name = "No io_uring",
            .why = "",
            .how = "",
            .result = .fail,
        },
    };
    const r: Report = .{
        .time = "t",
        .os = "o",
        .host = "h",
        .kernel = "k",
        .root = true,
        .summary = .{ .pass = 1, .fail = 2 },
        .checks = &checks,
    };
    var out: Io.Writer.Allocating = .init(arena.allocator());
    try printLine(arena.allocator(), &out.writer, r);
    const line = out.written();
    try testing.expect(std.mem.startsWith(
        u8,
        line,
        "posture: fail=kernel-io-uring,programs-shell pass=1 skip=0 {\"tool\":\"posture\",",
    ));
    try testing.expectEqual(1, std.mem.count(u8, line, "\n"));
    try testing.expect(std.mem.endsWith(u8, line, "}\n"));

    const clean: Report = .{
        .time = "t",
        .os = "o",
        .host = "h",
        .kernel = "k",
        .root = true,
        .summary = .{ .pass = 1 },
        .checks = checks[1..2],
    };
    out.clearRetainingCapacity();
    try printLine(arena.allocator(), &out.writer, clean);
    try testing.expect(std.mem.startsWith(u8, out.written(), "posture: fail= pass=1 skip=0 {"));
}

test serviceSettled {
    const now = 1_760_000_000;
    var st: [20]u8 = @splat(0);
    std.mem.writeInt(u64, st[0..8], (1 << 62) + 10 + now - 30, .big);
    st[17] = 'u';
    st[19] = 1;
    try testing.expect(serviceSettled(st, now)); // running 30 s
    try testing.expect(!serviceSettled(st, now - 28)); // running 2 s
    st[19] = 0;
    try testing.expect(!serviceSettled(st, now)); // down, wanted up: restarting
    st[17] = 'd';
    try testing.expect(serviceSettled(st, now)); // parked
    st[19] = 2;
    try testing.expect(!serviceSettled(st, now)); // finishing
}

test fit {
    const list = "/usr/bin/su, /usr/bin/sudo, /usr/bin/passwd";
    try testing.expectEqual(list.len, fit(list, list.len).len);
    try testing.expectEqual(0, fit(list, list.len).more);
    // "/usr/bin/su, /usr/bin/sudo, +1 more" is 35 bytes.
    try testing.expectEqualStrings("/usr/bin/su, /usr/bin/sudo", list[0..fit(list, 35).len]);
    try testing.expectEqual(1, fit(list, 35).more);
    try testing.expectEqualStrings("/usr/bin/su", list[0..fit(list, 34).len]);
    try testing.expectEqual(2, fit(list, 34).more);
    // The first item stays, however little room.
    try testing.expectEqual(11, fit(list, 0).len);
    try testing.expectEqual(2, fit(list, 0).more);
    try testing.expectEqual(13, fit("ran from /tmp", 3).len);
    try testing.expectEqual(0, fit("ran from /tmp", 3).more);
}

test prettyName {
    try testing.expectEqualStrings(
        "Ubuntu 24.04.1 LTS",
        prettyName("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n"),
    );
    try testing.expectEqualStrings("Wolfi", prettyName("ID=wolfi\nPRETTY_NAME=Wolfi\n"));
    try testing.expectEqualStrings("Linux", prettyName("PRETTY_NAME=\"\"\n"));
    try testing.expectEqualStrings("Linux", prettyName(""));
}
