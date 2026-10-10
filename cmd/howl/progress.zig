//! progress shows a long run, such as a build, as one status line and
//! keeps its full output in a log. On failure it prints the failed
//! phase, the last lines and the log's path. See README.md.

const std = @import("std");
const builtin = @import("builtin");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const posix = std.posix;

pub const Options = struct {
    /// verbose streams all output as it runs and keeps no log.
    verbose: bool = false,
    /// command is what the user ran, repeated on failure: "howl build caddy".
    command: []const u8,
    /// log is the file that receives all output.
    log: []const u8,
    /// first is the phase shown until a step names another.
    first: Phase,
};

/// Phase is a build step: name is shown on the line, short in the summary.
pub const Phase = struct { name: []const u8, short: []const u8 };

/// Spent is the total time of a phase, summed over all its turns.
pub const Spent = struct { short: []const u8, ns: i96 };

/// Done is a successful run's duration and its phases in first-seen order.
pub const Done = struct {
    seconds: i64,
    phases: []const Spent = &.{},

    /// format writes each phase of a second or more on one line:
    /// "packages 21s · seal 14s".
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

/// tail_lines is how many output lines a failure shows.
const tail_lines = 10;
/// frame_ms is the redraw interval.
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

/// run runs argv as o says. On failure it prints the report itself and
/// returns error.Refused with why empty, so the caller adds nothing.
pub fn run(io: Io, gpa: Allocator, why: *howl.Why, argv: []const []const u8, o: Options) !Done {
    if (o.verbose) {
        const start = Io.Clock.awake.now(io);
        try howl.run(io, why, argv);
        return .{ .seconds = start.untilNow(io, .awake).toSeconds() };
    }
    var steps: Steps = try .init(io, gpa, why, o);
    if (!(try steps.exec(&.{.{ .argv = argv }}, .{})).ok) return steps.fail("");
    return steps.finish();
}

/// Steps shows a run of commands and work of howl's own, such as a build
/// howl makes itself, as one status line, and keeps all their output in a
/// log. Each step enters its phase; a failure prints the phase, the last
/// lines and the log's path. Verbose, the output streams to standard error
/// and there is no log.
pub const Steps = struct {
    io: Io,
    gpa: Allocator,
    why: *howl.Why,
    o: Options,
    look: Look,
    /// log is null when verbose.
    log: ?Io.File,
    start: Io.Timestamp,
    said: Said,
    frame: usize = 0,

    pub fn init(io: Io, gpa: Allocator, why: *howl.Why, o: Options) !Steps {
        var log: ?Io.File = null;
        if (!o.verbose) {
            if (std.fs.path.dirname(o.log)) |d| Dir.cwd().createDirPath(io, d) catch {};
            log = Dir.cwd().createFile(io, o.log, .{}) catch |e|
                return why.refuse("{s}: {s}", .{ o.log, @errorName(e) });
        }
        const start = Io.Clock.awake.now(io);
        return .{
            .io = io,
            .gpa = gpa,
            .why = why,
            .o = o,
            .look = .of(io, Io.File.stderr()),
            .log = log,
            .start = start,
            .said = .{ .gpa = gpa, .phase = o.first, .since = start },
        };
    }

    /// enter starts phase p, adding the time since the last change to the
    /// phase before it.
    pub fn enter(s: *Steps, p: Phase) !void {
        try s.said.enter(s.io, p);
        s.draw();
    }

    /// note writes one line of howl's own to the log, prefixed "howl: ".
    pub fn note(s: *Steps, comptime fmt: []const u8, args: anytype) !void {
        const line = try s.gpa.print("howl: " ++ fmt ++ "\n", args);
        s.write(line);
        try s.said.line(line[0 .. line.len - 1]);
        s.draw();
    }

    /// Cmd is one command of a pipeline: its arguments, and the directory
    /// and environment it runs in, or howl's.
    pub const Cmd = struct {
        argv: []const []const u8,
        cwd: ?[]const u8 = null,
        env: ?*const std.process.Environ.Map = null,
    };

    /// Ran says whether every command succeeded, and holds all they
    /// printed but the last one's standard output when that went to a file.
    pub const Ran = struct { ok: bool, output: []const u8 };

    /// exec runs cmds as a pipeline, each one's standard output the next
    /// one's input; the first reads stdin, or nothing, and the last writes
    /// stdout, or the log. Their standard error goes to the log.
    pub fn exec(
        s: *Steps,
        cmds: []const Cmd,
        files: struct { stdin: ?Io.File = null, stdout: ?Io.File = null },
    ) !Ran {
        const io = s.io;
        const children = try s.gpa.alloc(std.process.Child, cmds.len);
        var outs: std.ArrayList(Io.File) = .empty;
        var spawned: usize = 0;
        defer for (children[0..spawned]) |*c| {
            if (c.id != null) c.kill(io);
        };
        for (cmds, children, 0..) |c, *child, i| {
            const last = i + 1 == cmds.len;
            child.* = std.process.spawn(io, .{
                .argv = c.argv,
                .cwd = if (c.cwd) |d| .{ .path = d } else .inherit,
                .environ_map = c.env,
                .stdin = if (i > 0)
                    .{ .file = children[i - 1].stdout.? }
                else if (files.stdin) |f| .{ .file = f } else .ignore,
                .stdout = if (!last) .pipe else if (files.stdout) |f| .{ .file = f } else .pipe,
                .stderr = .pipe,
            }) catch |e| return s.fail(try s.gpa.print("{s}: {s}", .{ c.argv[0], @errorName(e) }));
            spawned += 1;
            // The child has the pipe now; the reader sees its end only once
            // this copy is closed too.
            if (i > 0) {
                children[i - 1].stdout.?.close(io);
                children[i - 1].stdout = null;
            }
            try outs.append(s.gpa, child.stderr.?);
            if (last and files.stdout == null) try outs.append(s.gpa, child.stdout.?);
        }
        const output = try s.pump(outs.items);
        var ok = true;
        for (children) |*c| {
            const term = c.wait(io) catch |e|
                return s.fail(try s.gpa.print("{s}: {s}", .{ cmds[0].argv[0], @errorName(e) }));
            if (term != .exited or term.exited != 0) ok = false;
        }
        return .{ .ok = ok, .output = output };
    }

    /// pump reads files until each ends, copying what it reads to the log
    /// (or, verbose, to standard error) and its lines to the status line,
    /// and returns it all.
    fn pump(s: *Steps, files: []const Io.File) ![]const u8 {
        const fds = try s.gpa.alloc(posix.pollfd, files.len);
        const partial = try s.gpa.alloc(std.ArrayList(u8), files.len);
        for (fds, partial, files) |*p, *part, f| {
            p.* = .{ .fd = f.handle, .events = posix.POLL.IN, .revents = 0 };
            part.* = .empty;
        }
        var all: std.ArrayList(u8) = .empty;
        var open = files.len;
        var buf: [16 << 10]u8 = undefined;
        while (open > 0) {
            _ = posix.poll(fds, frame_ms) catch 0;
            for (fds, partial) |*p, *part| {
                if (p.fd < 0 or p.revents == 0) continue;
                const n = posix.read(p.fd, &buf) catch 0;
                if (n == 0) {
                    if (part.items.len > 0) try s.said.line(part.items);
                    part.clearRetainingCapacity();
                    p.fd = -1;
                    open -= 1;
                    continue;
                }
                s.write(buf[0..n]);
                try all.appendSlice(s.gpa, buf[0..n]);
                for (buf[0..n]) |c| {
                    if (c == '\n' or c == '\r') {
                        try s.said.line(part.items);
                        part.clearRetainingCapacity();
                    } else try part.append(s.gpa, c);
                }
            }
            s.draw();
        }
        return all.items;
    }

    fn write(s: *Steps, bytes: []const u8) void {
        const to = s.log orelse Io.File.stderr();
        to.writeStreamingAll(s.io, bytes) catch {};
    }

    fn draw(s: *Steps) void {
        if (!s.look.tty or s.o.verbose) return;
        s.frame += 1;
        s.look.draw(
            s.io,
            Io.File.stderr(),
            frames[s.frame % frames.len],
            s.said.phase.name,
            s.start.untilNow(s.io, .awake),
            s.said.detail,
        );
    }

    /// finish ends a run that succeeded and returns its time and phases.
    pub fn finish(s: *Steps) !Done {
        try s.said.enter(s.io, null);
        if (s.look.tty and
            !s.o.verbose) Io.File.stderr().writeStreamingAll(s.io, "\r\x1b[2K") catch {};
        if (s.log) |l| l.close(s.io);
        return .{
            .seconds = s.start.untilNow(s.io, .awake).toSeconds(),
            .phases = s.said.spent.items,
        };
    }

    /// fail ends a run that failed for reason, which may be "" when the
    /// output says it. It reports the phase, the last lines and the log,
    /// and returns error.Refused with why empty, so the caller adds
    /// nothing. Verbose, the output is above, and why holds reason.
    pub fn fail(s: *Steps, reason: []const u8) error{Refused} {
        if (s.o.verbose) {
            s.why.text = if (reason.len > 0) reason else "failed; the output is above";
            return error.Refused;
        }
        if (reason.len > 0) s.write(s.gpa.print("howl: {s}\n", .{reason}) catch reason);
        if (s.log) |l| l.close(s.io);
        const err = Io.File.stderr();
        if (s.look.tty) err.writeStreamingAll(s.io, "\r\x1b[2K") catch {};
        const seconds = s.start.untilNow(s.io, .awake).toSeconds();
        var out: Io.Writer.Allocating = .init(s.gpa);
        const w = &out.writer;
        report: {
            w.print(
                "{s} {s} failed, after {f}\n",
                .{ s.look.cross(), s.said.phase.name, Clock{ .seconds = seconds } },
            ) catch break :report;
            for (s.said.tail()) |l| w.print("  {s}\n", .{l}) catch break :report;
            if (reason.len > 0) w.print("  {s}\n", .{reason}) catch break :report;
            const log = s.gpa.print("the whole log: {s}", .{s.o.log}) catch break :report;
            w.print("  {f}\n", .{s.look.dim(log)}) catch break :report;
            const again = s.gpa.print("everything, as it runs: {s} --verbose", .{s.o.command}) catch
                break :report;
            w.print("  {f}\n", .{s.look.dim(again)}) catch break :report;
        }
        err.writeStreamingAll(s.io, out.written()) catch {};
        s.why.text = "";
        return error.Refused;
    }
};

/// Said tracks a run's output for the status line and the failure report.
const Said = struct {
    gpa: Allocator,
    phase: Phase,
    /// since is when phase began.
    since: Io.Timestamp,
    spent: std.ArrayList(Spent) = .empty,
    /// detail is the last line, shown beside the phase.
    detail: []const u8 = "",
    /// last is a ring of the last tail_lines lines.
    last: [tail_lines][]const u8 = @splat(""),
    count: usize = 0,

    fn line(s: *Said, raw: []const u8) !void {
        const text = try clean(s.gpa, raw);
        if (text.len == 0) return;
        s.detail = text;
        s.last[s.count % tail_lines] = text;
        s.count += 1;
    }

    /// enter adds the current phase's time to its total and starts next.
    /// A null next ends the run.
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

    /// tail returns the last lines, oldest first, without repeats, since a
    /// retried command prints the same lines again.
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

/// phaseOf names the build phase a step's target implies, or returns null
/// if the target names none.
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
    if (has(t, "/kernel/") or ends(t, "/vmlinuz")) return P("Fetching the kernel", "kernel");
    if (has(t, "/stage0/")) return P("Building stage0", "stage0");
    if (ends(t, "/boot/rootfs.tar")) return P("Fetching the boot loader", "boot loader");
    if (has(t, "/form/") and ends(t, ".yaml")) return P("Reading the form", "form");
    if (ends(t, "/rootfs.tar")) return P("Installing packages", "packages");
    if (has(t, "/programs/")) return P("Compiling werewolf's programs", "programs");
    if (has(t, "melange")) return P("Building packages with melange", "melange");
    if (ends(t, "modules.tar") or
        ends(t, "modules-bitten.tar")) return P("Choosing kernel modules", "modules");
    if (ends(t, "/meta.stamp")) return P("Recording what the image holds", "metadata");
    if (ends(t, "/overlay.tar") or
        has(t, "/application")) return P("Adding the form's files", "files");
    if (ends(t, "/root.erofs")) return P("Sealing the root (erofs, dm-verity)", "seal");
    if (ends(t, "initramfs.zst") or ends(t, "/stage0.zst") or
        ends(t, "/stage0-bitten.zst")) return P("Packing the boot image", "boot image");
    if (ends(t, "/disk.img") or ends(t, "/disk.qcow2")) return P("Making the boot disk", "disk");
    if (std.mem.eql(u8, t, "_dist-form")) return P("Writing the release", "release");
    return null;
}

/// clean strips terminal escapes, control characters, and log timestamps
/// and levels from raw, and collapses runs of spaces.
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
    // From logfmt, time="..." level=info msg="...", as Lima writes, keep msg.
    if (std.mem.startsWith(u8, s, "time=")) if (std.mem.find(u8, s, "msg=\"")) |m| {
        const rest = s[m + 5 ..];
        s = rest[0 .. std.mem.findScalar(u8, rest, '"') orelse rest.len];
    };
    // Strip melange's and apko's "2026/10/08 09:45:53 WARN " prefix.
    if (s.len > 20 and s[4] == '/' and s[7] == '/' and s[10] == ' ' and s[13] == ':') {
        s = std.mem.trimStart(u8, s[19..], " ");
        for ([_][]const u8{ "INFO ", "WARN ", "DEBUG ", "ERRO ", "ERROR " }) |l| {
            if (std.mem.startsWith(u8, s, l)) s = std.mem.trimStart(u8, s[l.len..], " ");
        }
    }
    return s;
}

/// Clock formats seconds as "7s" or "2m05s".
pub const Clock = struct {
    seconds: i64,

    pub fn format(c: Clock, w: *Io.Writer) Io.Writer.Error!void {
        const s: u64 = @intCast(@max(c.seconds, 0));
        if (s < 60) return w.print("{d}s", .{s});
        try w.print("{d}m{d:0>2}s", .{ s / 60, s % 60 });
    }
};

/// Look describes the output: whether it is a terminal, its width, and
/// whether to use color (not with NO_COLOR set or TERM=dumb).
pub const Look = struct {
    tty: bool,
    color: bool,
    cols: usize,

    pub fn of(io: Io, f: Io.File) Look {
        const tty = f.isTty(io) catch false;
        const dumb = if (howl.environ.get("TERM")) |t| std.mem.eql(u8, t, "dumb") else false;
        return .{
            .tty = tty,
            .color = tty and !dumb and howl.environ.get("NO_COLOR") == null,
            .cols = if (tty) columns(f) else 80,
        };
    }

    pub fn check(l: Look) []const u8 {
        return if (l.color) "\x1b[32m✓\x1b[0m" else "✓";
    }

    pub fn cross(l: Look) []const u8 {
        return if (l.color) "\x1b[31m✗\x1b[0m" else "✗";
    }

    /// dim formats text faint, for what matters less than its line.
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

    /// draw redraws the line in place: spinner, phase, time, and as much
    /// of detail as fits.
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
        // The spinner takes one column, and phase and time one per byte;
        // detail may hold multibyte characters, so fitColumns counts those.
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

/// Spinner draws the status line for a wait that is not a command. Call
/// tick on each poll and clear when done.
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

/// fitColumns returns the longest prefix of s with at most n whole UTF-8
/// characters.
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

/// columns returns the terminal's width, or 80 if it is unknown or tiny.
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
        "Packing the boot image",
        phaseOf("build/aarch64/caddy/slot/stage0-bitten.zst").?.name,
    );
    try testing.expectEqualStrings(
        "Making the boot disk",
        phaseOf("build/aarch64/caddy/disk.qcow2").?.name,
    );
    try testing.expectEqualStrings("Writing the release", phaseOf("_dist-form").?.name);
    try testing.expectEqual(null, phaseOf("image"));
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
