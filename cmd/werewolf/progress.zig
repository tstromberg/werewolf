//! Progress: a long make, or another long command, as one line that says
//! which phase it is in, how long it has run, and the last thing it said,
//! with all it said kept in a log. On success the line goes, and the verb
//! says what it made and what to do next; on failure it says which phase
//! failed, the last lines that say why, and where the whole log is.
//! --verbose shows everything as it happens, as make shows it.
//!
//! make names its phases itself: run with --debug=b, it says which target
//! it must remake, and a target's path says what it is (phaseOf). Off a
//! terminal there is no line to redraw, so nothing is said until the end.

const std = @import("std");
const builtin = @import("builtin");
const ww = @import("werewolf.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const posix = std.posix;

pub const Options = struct {
    /// Everything, as it runs, and no log.
    verbose: bool = false,
    /// What was run, to say again in a failure: "werewolf build caddy".
    command: []const u8,
    /// Where the output goes.
    log: []const u8,
    /// The phase until make names one, or the only one, for a command that
    /// is not make.
    first: Phase,
    /// argv is make's: ask it to say which targets it remakes.
    make: bool = true,
};

/// A phase: what the line says, and the word the summary times it by.
pub const Phase = struct { name: []const u8, short: []const u8 };

/// How long a phase took, all its turns together.
pub const Spent = struct { short: []const u8, ns: i96 };

/// How a run went: its seconds, and where they went, phase by phase, in
/// the order the phases came.
pub const Done = struct {
    seconds: i64,
    phases: []const Spent = &.{},

    /// Where the time went, as one line: each phase that took a second or
    /// more, "packages 21s · seal 14s".
    pub fn format(d: Done, w: *Io.Writer) Io.Writer.Error!void {
        var first = true;
        for (d.phases) |p| {
            if (p.ns < std.time.ns_per_s) continue;
            if (!first) try w.writeAll(" · ");
            first = false;
            try w.print(
                "{s} {f}",
                .{ p.short, Clock{ .seconds = @intCast(@divTrunc(p.ns, std.time.ns_per_s)) } },
            );
        }
    }
};

/// The last lines kept, to show why a run failed.
const tail_lines = 10;
/// How often the line is drawn again: the spinner's pace.
const frame_ms = 80;
const frames = [_][]const u8{
    "⠋",
    "⠙",
    "⠹",
    "⠸",
    "⠼",
    "⠴",
    "⠦",
    "⠧",
    "⠇",
    "⠏",
};

/// Run argv as o says. A failure has been said in full when this returns
/// error.Refused with nothing in why, so the caller adds nothing.
pub fn run(io: Io, gpa: Allocator, why: *ww.Why, argv: []const []const u8, o: Options) !Done {
    const start = Io.Clock.awake.now(io);
    if (o.verbose) {
        try ww.run(io, why, argv);
        return .{ .seconds = start.untilNow(io, .awake).toSeconds() };
    }
    const err = Io.File.stderr();
    const look: Look = .of(io, err);

    var args: std.ArrayList([]const u8) = .empty;
    try args.append(gpa, argv[0]);
    if (o.make) try args.append(gpa, "--debug=b");
    try args.appendSlice(gpa, argv[1..]);

    if (std.fs.path.dirname(o.log)) |d| Dir.cwd().createDirPath(io, d) catch {};
    const log = Dir.cwd().createFile(io, o.log, .{}) catch |e|
        return why.refuse("{s}: {s}", .{ o.log, @errorName(e) });
    defer log.close(io);

    var child = std.process.spawn(io, .{
        .argv = args.items,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch |e| return why.refuse("{s}: {s}", .{ argv[0], @errorName(e) });

    var said: Said = .{ .gpa = gpa, .phase = o.first, .since = start, .banner = o.make };
    var fds = [2]posix.pollfd{
        .{ .fd = child.stdout.?.handle, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = child.stderr.?.handle, .events = posix.POLL.IN, .revents = 0 },
    };
    var partial = [2]std.ArrayList(u8){ .empty, .empty };
    var open: usize = 2;
    var frame: usize = 0;
    var buf: [16 << 10]u8 = undefined;
    while (open > 0) {
        _ = posix.poll(&fds, frame_ms) catch 0;
        for (&fds, &partial) |*p, *part| {
            if (p.fd < 0 or p.revents == 0) continue;
            const n = posix.read(p.fd, &buf) catch 0;
            if (n == 0) {
                if (part.items.len > 0) try said.line(io, part.items);
                part.clearRetainingCapacity();
                p.fd = -1;
                open -= 1;
                continue;
            }
            log.writeStreamingAll(io, buf[0..n]) catch {};
            for (buf[0..n]) |c| {
                if (c == '\n' or c == '\r') {
                    try said.line(io, part.items);
                    part.clearRetainingCapacity();
                } else try part.append(gpa, c);
            }
        }
        if (look.tty) {
            frame += 1;
            look.draw(
                io,
                err,
                frames[frame % frames.len],
                said.phase.name,
                start.untilNow(io, .awake),
                said.detail,
            );
        }
    }
    const term = child.wait(io) catch |e| return why.refuse(
        "{s}: {s}",
        .{ argv[0], @errorName(e) },
    );
    const seconds = start.untilNow(io, .awake).toSeconds();
    try said.enter(io, null);
    if (look.tty) err.writeStreamingAll(io, "\r\x1b[2K") catch {};
    if (term == .exited and
        term.exited == 0) return .{ .seconds = seconds, .phases = said.spent.items };

    // What failed, why, and where to read more.
    var out: Io.Writer.Allocating = .init(gpa);
    const w = &out.writer;
    try w.print(
        "{s} {s} failed, after {f}\n",
        .{ look.cross(), said.phase.name, Clock{ .seconds = seconds } },
    );
    for (said.tail()) |l| try w.print("  {s}\n", .{l});
    try w.print("  {f}\n", .{look.dim(try gpa.print("the whole log: {s}", .{o.log}))});
    try w.print(
        "  {f}\n",
        .{look.dim(try gpa.print("everything, as it runs: {s} --verbose", .{o.command}))},
    );
    err.writeStreamingAll(io, out.written()) catch {};
    why.text = "";
    return error.Refused;
}

/// What a run has said so far, as the line shows it.
const Said = struct {
    gpa: Allocator,
    phase: Phase,
    /// When phase began.
    since: Io.Timestamp,
    spent: std.ArrayList(Spent) = .empty,
    /// make with --debug says who it is first: nothing to show, until it
    /// says it is reading makefiles.
    banner: bool = false,
    /// The last thing said that is not make's own bookkeeping.
    detail: []const u8 = "",
    /// The last lines said, a ring of tail_lines.
    last: [tail_lines][]const u8 = @splat(""),
    count: usize = 0,

    fn line(s: *Said, io: Io, raw: []const u8) !void {
        if (s.banner) {
            if (std.mem.find(u8, raw, "Reading makefiles") != null) s.banner = false;
            return;
        }
        if (remade(raw)) |target| {
            if (phaseOf(target)) |p| try s.enter(io, p);
            return;
        }
        if (isBookkeeping(raw)) return;
        const text = try clean(s.gpa, raw);
        if (text.len == 0) return;
        s.detail = text;
        s.last[s.count % tail_lines] = text;
        s.count += 1;
    }

    /// The phase done for now, its time added to its own, and next begun:
    /// none at the end.
    fn enter(s: *Said, io: Io, next: ?Phase) !void {
        if (next) |n| if (std.mem.eql(u8, n.name, s.phase.name)) return;
        const now = Io.Clock.awake.now(io);
        const ns = s.since.durationTo(now).toNanoseconds();
        s.since = now;
        for (s.spent.items) |*x| {
            if (std.mem.eql(u8, x.short, s.phase.short)) {
                x.ns += ns;
                break;
            }
        } else try s.spent.append(s.gpa, .{ .short = s.phase.short, .ns = ns });
        if (next) |n| s.phase = n;
    }

    /// The last lines, oldest first, each once: a command tried again says
    /// the same thing again.
    fn tail(s: *const Said) []const []const u8 {
        const n = @min(s.count, tail_lines);
        var out: std.ArrayList([]const u8) = .empty;
        for (0..n) |i| {
            const l = s.last[(s.count - n + i) % tail_lines];
            for (out.items, 0..) |have, j| {
                if (std.mem.eql(u8, have, l)) {
                    _ = out.orderedRemove(j);
                    break;
                }
            }
            out.append(s.gpa, l) catch return out.items;
        }
        return out.items;
    }
};

/// The target a --debug=b line says make must remake, or null.
fn remade(line: []const u8) ?[]const u8 {
    const key = "Must remake target ";
    const at = std.mem.find(u8, line, key) orelse return null;
    const rest = line[at + key.len ..];
    if (rest.len < 3) return null;
    // `target' from make 3.81, 'target' from 4.
    const end = std.mem.findScalarLast(u8, rest, '\'') orelse return null;
    if (end < 1) return null;
    return rest[1..end];
}

/// Whether a line is make's --debug=b bookkeeping, not anything a command said.
fn isBookkeeping(line: []const u8) bool {
    const t = std.mem.trimStart(u8, line, " ");
    for ([_][]const u8{
        "Reading makefiles",   "Updating goal targets",  "Updating makefiles",
        "Successfully remade", "File `",                 "File '",
        "Prerequisite `",      "Prerequisite '",         "No need to remake",
        "Considering target",  "Finished prerequisites", "Pruning file",
        "Trying ",             "Must remake",            "GNU Make",
        "Built for",           "Copyright",              "This program built",
    }) |p| if (std.mem.startsWith(u8, t, p)) return true;
    return false;
}

/// What a target's path says the build is doing, in words, or null for a
/// target that names no phase of its own.
pub fn phaseOf(target: []const u8) ?Phase {
    const t = target;
    const ends = struct {
        fn f(s: []const u8, suffix: []const u8) bool {
            return std.mem.endsWith(u8, s, suffix);
        }
    }.f;
    const has = struct {
        fn f(s: []const u8, part: []const u8) bool {
            return std.mem.find(u8, s, part) != null;
        }
    }.f;
    const P = struct {
        fn p(name: []const u8, short: []const u8) Phase {
            return .{ .name = name, .short = short };
        }
    }.p;
    if (ends(t, ".lock.json")) return P("Resolving packages", "resolve");
    if (has(t, "/kernel/") or ends(t, "/vmlinuz") or
        ends(t, "/vmlinux")) return P("Fetching the kernel", "kernel");
    if (has(t, "/stage0/")) return P("Building stage0", "stage0");
    if (ends(t, "/boot/rootfs.tar")) return P("Fetching the boot loader", "boot loader");
    if (has(t, "/form/") and ends(t, ".yaml")) return P("Reading the form", "form");
    if (ends(t, "/rootfs.tar")) return P("Installing packages", "packages");
    if (has(t, "/programs/") or
        std.mem.startsWith(
            u8,
            t,
            "build/host/",
        )) return P("Compiling werewolf's programs", "programs");
    if (has(t, "melange") or
        ends(t, ".built")) return P("Building packages with melange", "melange");
    if (ends(t, "modules.tar") or
        ends(t, "modules-bitten.tar")) return P("Choosing kernel modules", "modules");
    if (ends(t, "/ro.stamp")) return P("Laying out the read-only root", "layout");
    if (ends(t, "/meta.stamp")) return P("Recording what the image holds", "metadata");
    if (ends(t, "/overlay.tar") or has(t, "/apps/") or
        ends(t, "application.stamp")) return P("Adding the form's files", "files");
    if (ends(t, "/root.erofs")) return P("Sealing the root (erofs, dm-verity)", "seal");
    if (ends(t, "initramfs.zst") or
        ends(t, "initramfs-bitten.zst")) return P("Packing the boot image", "boot image");
    if (ends(t, "/disk.img") or ends(t, "/disk.qcow2")) return P("Making the boot disk", "disk");
    if (ends(t, "/data.img")) return P("Making a disk for /data", "data disk");
    if (ends(t, "config.tar")) return P("Packing the config", "config");
    if (std.mem.eql(u8, t, "_dist-form")) return P("Writing the release", "release");
    return null;
}

/// A line as the spinner shows it: without terminal escapes, a log's
/// timestamp and level, or control characters, its spaces collapsed.
pub fn clean(gpa: Allocator, raw: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        const c = raw[i];
        if (c == 0x1b) {
            // CSI: ESC [ parameters, then a final byte @ to ~.
            if (i + 1 < raw.len and raw[i + 1] == '[') {
                i += 2;
                while (i < raw.len and (raw[i] < 0x40 or raw[i] > 0x7e)) : (i += 1) {}
            }
            continue;
        }
        if (c < 0x20 or c == 0x7f) {
            if (out.items.len > 0 and out.items[out.items.len - 1] != ' ') try out.append(gpa, ' ');
            continue;
        }
        if (c == ' ' and out.items.len > 0 and out.items[out.items.len - 1] == ' ') continue;
        try out.append(gpa, c);
    }
    var s: []const u8 = std.mem.trim(u8, out.items, " ");
    // Lima's and others' logfmt, time="..." level=info msg="...": the message.
    if (std.mem.startsWith(u8, s, "time=")) if (std.mem.find(u8, s, "msg=\"")) |m| {
        const rest = s[m + 5 ..];
        s = rest[0 .. std.mem.findScalar(u8, rest, '"') orelse rest.len];
    };
    // melange's and apko's "2026/10/08 09:45:53 WARN ", or "time=... level=... msg=".
    if (s.len > 20 and s[4] == '/' and s[7] == '/' and s[10] == ' ' and s[13] == ':') {
        s = std.mem.trimStart(u8, s[19..], " ");
        for ([_][]const u8{ "INFO ", "WARN ", "DEBUG ", "ERRO ", "ERROR " }) |l| {
            if (std.mem.startsWith(u8, s, l)) s = std.mem.trimStart(u8, s[l.len..], " ");
        }
    }
    return s;
}

/// m:ss, as the line and a summary say a time.
pub const Clock = struct {
    seconds: i64,

    pub fn format(c: Clock, w: *Io.Writer) Io.Writer.Error!void {
        const s: u64 = @intCast(@max(c.seconds, 0));
        if (s < 60) return w.print("{d}s", .{s});
        try w.print("{d}m{d:0>2}s", .{ s / 60, s % 60 });
    }
};

/// How the terminal is drawn on: whether it is one, its width, whether it
/// takes color (not when NO_COLOR is set, or TERM is dumb).
pub const Look = struct {
    tty: bool,
    color: bool,
    cols: usize,

    pub fn of(io: Io, f: Io.File) Look {
        const tty = f.isTty(io) catch false;
        const dumb = if (ww.environ.get("TERM")) |t| std.mem.eql(u8, t, "dumb") else false;
        return .{
            .tty = tty,
            .color = tty and !dumb and ww.environ.get("NO_COLOR") == null,
            .cols = if (tty) columns(f) else 80,
        };
    }

    pub fn check(l: Look) []const u8 {
        return if (l.color) "\x1b[32m✓\x1b[0m" else "✓";
    }

    pub fn cross(l: Look) []const u8 {
        return if (l.color) "\x1b[31m✗\x1b[0m" else "✗";
    }

    /// text, faint: what matters less than the line around it.
    pub fn dim(l: Look, text: []const u8) Dim {
        return .{ .text = text, .on = l.color };
    }

    pub const Dim = struct {
        text: []const u8,
        on: bool,

        pub fn format(d: Dim, w: *Io.Writer) Io.Writer.Error!void {
            if (d.on) try w.writeAll("\x1b[2m");
            try w.writeAll(d.text);
            if (d.on) try w.writeAll("\x1b[22m");
        }
    };

    /// The line again, in place: spinner, phase, time, and as much of the
    /// last thing said as fits.
    fn draw(
        l: Look,
        io: Io,
        f: Io.File,
        spin: []const u8,
        phase: []const u8,
        ran: Io.Duration,
        detail: []const u8,
    ) void {
        var buf: [1024]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        var tbuf: [16]u8 = undefined;
        const time = std.mem.print(
            &tbuf,
            "{f}",
            .{Clock{ .seconds = ran.toSeconds() }},
        ) catch "";
        w.print("\r\x1b[2K{s} {s}  {s}", .{ spin, phase, time }) catch return;
        // The spinner is one column, the rest one a byte, but what a command
        // said, one a character.
        const used = 2 + phase.len + 2 + time.len;
        const room = l.cols -| (used + 5);
        if (detail.len > 0 and room > 8) {
            const d = fitColumns(detail, room);
            if (l.color) w.writeAll("  \x1b[2m") catch return else w.writeAll("  ") catch return;
            w.writeAll(d) catch return;
            if (d.len < detail.len) w.writeAll("…") catch return;
            if (l.color) w.writeAll("\x1b[22m") catch return;
        }
        f.writeStreamingAll(io, w.buffered()) catch {};
    }
};

/// The line, for a wait that is not a command's: draw it as often as the
/// wait looks, then clear it.
pub const Spinner = struct {
    io: Io,
    look: Look,
    start: Io.Timestamp,
    frame: usize = 0,

    pub fn init(io: Io) Spinner {
        return .{ .io = io, .look = .of(io, Io.File.stderr()), .start = Io.Clock.awake.now(io) };
    }

    pub fn tick(s: *Spinner, phase: []const u8, detail: []const u8) void {
        if (!s.look.tty) return;
        s.frame += 1;
        s.look.draw(
            s.io,
            Io.File.stderr(),
            frames[s.frame % frames.len],
            phase,
            s.start.untilNow(s.io, .awake),
            detail,
        );
    }

    pub fn clear(s: *Spinner) void {
        if (s.look.tty) Io.File.stderr().writeStreamingAll(s.io, "\r\x1b[2K") catch {};
    }
};

/// The longest start of s that is at most n characters, whole ones.
fn fitColumns(s: []const u8, n: usize) []const u8 {
    var cols: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        if (cols == n) return s[0..i];
        const len = std.unicode.utf8ByteSequenceLength(s[i]) catch 1;
        if (i + len > s.len) return s[0..i];
        i += len;
        cols += 1;
    }
    return s;
}

/// The terminal's width, or 80 when it will not say.
fn columns(f: Io.File) usize {
    var ws: posix.winsize = undefined;
    const ok = switch (builtin.os.tag) {
        .linux => std.os.linux.errno(std.os.linux.ioctl(
            f.handle,
            std.os.linux.T.IOCGWINSZ,
            @intFromPtr(&ws),
        )) == .SUCCESS,
        else => std.c.ioctl(f.handle, @intCast(std.c.T.IOCGWINSZ), &ws) == 0,
    };
    return if (ok and ws.col > 20) ws.col else 80;
}

const testing = std.testing;

test phaseOf {
    try testing.expectEqualStrings(
        "Installing packages",
        phaseOf("build/aarch64/caddy/rootfs.tar").?.name,
    );
    try testing.expectEqualStrings(
        "Fetching the kernel",
        phaseOf("build/aarch64/kernel/rootfs.tar").?.name,
    );
    try testing.expectEqualStrings(
        "Building stage0",
        phaseOf("build/aarch64/stage0/rootfs.tar").?.name,
    );
    try testing.expectEqualStrings(
        "Resolving packages",
        phaseOf("build/lock/caddy.lock.json").?.name,
    );
    try testing.expectEqualStrings(
        "Reading the form",
        phaseOf("build/aarch64/form/caddy.yaml").?.name,
    );
    try testing.expectEqualStrings(
        "Compiling werewolf's programs",
        phaseOf("build/aarch64/programs/fence/usr/lib/werewolf/fence").?.name,
    );
    try testing.expectEqualStrings(
        "Sealing the root (erofs, dm-verity)",
        phaseOf("build/aarch64/caddy/slot/root.erofs").?.name,
    );
    try testing.expectEqualStrings(
        "Making the boot disk",
        phaseOf("build/aarch64/caddy/disk.qcow2").?.name,
    );
    try testing.expectEqualStrings("Writing the release", phaseOf("_dist-form").?.name);
    try testing.expectEqual(null, phaseOf("image"));
}

test remade {
    try testing.expectEqualStrings(
        "build/a/x.tar",
        remade("    Must remake target `build/a/x.tar'.").?,
    );
    try testing.expectEqualStrings(
        "build/a/x.tar",
        remade("Must remake target 'build/a/x.tar'.").?,
    );
    try testing.expectEqual(null, remade("Successfully remade target file `x'."));
}

test clean {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const gpa = a.allocator();
    try testing.expectEqualStrings(
        "Compiling serde v1.0",
        try clean(gpa, "2026/10/08 09:45:53 WARN    Compiling serde v1.0"),
    );
    try testing.expectEqualStrings("ok done", try clean(gpa, "\x1b[32mok\x1b[0m\tdone  "));
    try testing.expectEqualStrings("", try clean(gpa, "   "));
    try testing.expectEqualStrings(
        "Starting the instance",
        try clean(
            gpa,
            "time=\"2026-10-08T11:37:17-04:00\" level=info msg=\"Starting the instance\" name=x",
        ),
    );
}

test isBookkeeping {
    try testing.expect(isBookkeeping("      Successfully remade target file `x'."));
    try testing.expect(isBookkeeping("Reading makefiles..."));
    try testing.expect(!isBookkeeping("apko build-minirootfs --build-arch aarch64"));
}

test fitColumns {
    try testing.expectEqualStrings("ab", fitColumns("abc", 2));
    try testing.expectEqualStrings("⠋a", fitColumns("⠋ab", 2));
    try testing.expectEqualStrings("abc", fitColumns("abc", 9));
}

test Done {
    var buf: [64]u8 = undefined;
    const d: Done = .{ .seconds = 9, .phases = &.{
        .{ .short = "resolve", .ns = 300 * std.time.ns_per_ms },
        .{ .short = "packages", .ns = 21 * std.time.ns_per_s },
        .{ .short = "seal", .ns = 75 * std.time.ns_per_s },
    } };
    try testing.expectEqualStrings(
        "packages 21s · seal 1m15s",
        try std.mem.print(&buf, "{f}", .{d}),
    );
}

test Clock {
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings(
        "7s",
        try std.mem.print(&buf, "{f}", .{Clock{ .seconds = 7 }}),
    );
    try testing.expectEqualStrings(
        "2m05s",
        try std.mem.print(&buf, "{f}", .{Clock{ .seconds = 125 }}),
    );
}
