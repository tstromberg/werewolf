//! console NAME CHECKS LOG QEMU... boots a werewolf image under QEMU and
//! judges it from outside, for a machine with no shell (test/boot keeps
//! the legacy shell checks). QEMU must set -no-reboot, so a panic ends the
//! run, and -nographic: its standard input and output are the console and,
//! behind Ctrl-A c, the monitor.
//!
//! It judges the posture line posture prints once the services settle: the
//! failing checks must be exactly POSTURE_KNOWN's, a ?ID failing or not.
//! It runs HOST_STEPS, a native run's host suites, and then CHECKS, - or a
//! file of console lines:
//!
//!   seen NAME RE       RE matches the console
//!   unseen NAME RE     RE does not
//!   up NAME [SERVICE]  leash says no service, or SERVICE alone, went down
//!                      or retried, but to wait for syslogd
//!
//! RE is a POSIX extended regular expression in which \r, \n and \t are
//! those characters; a line counts as it came or with the kernel's records
//! taken out of it. Then it presses the power button, as a hypervisor
//! does: the machine must stop its services and power off. Nothing waits a
//! fixed time. BOOT_TIMEOUT bounds the boot and the posture line, and
//! CONSOLE_TIMEOUT the seen lines, 300 s each by default; HOST_STEPS_TIMEOUT
//! bounds the host steps. The console goes to LOG. It exits 0 only if the
//! machine booted, every judgement held and it powered off cleanly.
//! CONSOLE_POWER_CUT cuts its power after the judgements instead, for the
//! next boot to find what that leaves. CONSOLE_ENDS judges a machine that
//! must end by itself, refusing to boot or resetting: QEMU must exit within
//! CONSOLE_TIMEOUT, with no posture line asked for nor button pressed, and
//! its console is judged.

const std = @import("std");
const host = @import("host");
const qemu = host.qemu;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;

extern fn werewolf_regex_match(pattern: [*:0]const u8, text: [*:0]const u8) c_int;

const Kind = enum { seen, unseen, up };

/// Line is one console judgement: a regular expression, or for up the one
/// service it is about, or all of them.
const Line = struct { kind: Kind, name: []const u8, arg: []const u8 };

const Failed = error{Failed};

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "console") catch |err|
        std.process.fatal("console: {t}", .{err});
    if (c.args.len < 5) std.process.fatal("usage: console NAME CHECKS LOG QEMU...", .{});
    var b: Boot = .{ .c = &c, .name = c.args[1], .log = c.args[3] };
    b.run(c.args[2], c.args[4..]) catch |err| switch (err) {
        error.Failed => std.process.exit(1),
        else => {
            b.say("FAIL", @errorName(err), b.diagnosis());
            std.process.exit(1);
        },
    };
    std.process.exit(if (b.failed > 0) 1 else 0);
}

const Boot = struct {
    c: *host.Check,
    name: []const u8,
    log: []const u8,
    m: qemu.Machine = undefined,
    started: bool = false,
    failed: usize = 0,
    host: []const u8 = "",

    fn run(b: *Boot, checks: []const u8, argv: []const []const u8) !void {
        const gpa = b.c.gpa;
        const lines = if (mem.eql(u8, checks, "-")) &.{} else parse(
            gpa,
            try Io.Dir.cwd().readFileAlloc(b.c.io, checks, gpa, .limited(1 << 20)),
        ) catch |err| return b.giveUp(
            "checks",
            try gpa.print("{s}: {t}", .{ checks, err }),
            false,
        );
        b.host = try describe(b.c, argv);
        try b.m.start(b.c.io, gpa, argv, .{ .log = b.log, .input = true });
        b.started = true;
        defer b.m.stop(.fromSeconds(10));
        b.m.note(try gpa.print("werewolf-check: host {s}\n", .{b.host}));
        if (b.c.env.get("CONSOLE_ENDS") != null)
            return b.ends(lines, b.seconds("CONSOLE_TIMEOUT", 300));
        const boot_timeout = b.seconds("BOOT_TIMEOUT", 300);
        try b.handover(boot_timeout);
        try b.posture(boot_timeout);
        const console_timeout = b.seconds("CONSOLE_TIMEOUT", 300);
        try b.hostSteps(lines, console_timeout);
        try b.judge(lines, console_timeout);
        if (b.c.env.get("CONSOLE_POWER_CUT") != null) try b.powerCut() else try b.shutdown();
        if (b.failed == 0) b.say("pass", "all checks", "");
    }

    fn seconds(b: *Boot, variable: []const u8, default: i64) i64 {
        const text = b.c.env.get(variable) orelse return default;
        return std.fmt.parseInt(i64, text, 10) catch default;
    }

    /// say prints a result as test/boot does: status, machine, what, and
    /// any detail indented beneath.
    fn say(b: *Boot, status: []const u8, what: []const u8, detail: []const u8) void {
        b.c.say("{s: <6} {s: <18} {s}", .{ status, b.name, what });
        var lines = mem.splitScalar(u8, mem.trim(u8, detail, " \r\n"), '\n');
        if (detail.len > 0) while (lines.next()) |l|
            b.c.say("         | {s}", .{mem.trimEnd(u8, l, " \r")});
    }

    fn fail(b: *Boot, what: []const u8, detail: []const u8) void {
        b.failed += 1;
        b.say("FAIL", what, detail);
    }

    /// giveUp ends the run: a hung machine's CPUs go to the log first.
    fn giveUp(b: *Boot, what: []const u8, why: []const u8, hung: bool) Failed {
        if (hung and b.started) b.dumpCpus();
        const detail = b.c.gpa.print("{s}{s}{s}\nsee {s}", .{
            why,
            if (why.len > 0) "\n" else "",
            b.diagnosis(),
            b.log,
        }) catch why;
        b.fail(what, detail);
        return error.Failed;
    }

    /// dumpCpus logs each virtual CPU's state from QEMU's monitor and
    /// ends QEMU: a CPU that never wakes is the hypervisor's fault.
    fn dumpCpus(b: *Boot) void {
        for ([_][]const u8{ "\x01c", "info cpus\r", "info registers -a\r", "quit\r" }) |command| {
            const start = (b.m.console(b.c.gpa) catch return).len;
            b.m.send(command) catch return;
            b.m.until(qemu.after(b.c.io, 10), After{ .start = start, .needle = "(qemu)" }) catch {};
        }
    }

    fn handover(b: *Boot, timeout: i64) !void {
        var panic: []const u8 = "";
        b.m.until(
            qemu.after(b.c.io, timeout),
            Handover{ .panic = &panic },
        ) catch |err| return switch (err) {
            error.Panicked => b.giveUp("boot", panic, false),
            error.Timeout => b.giveUp(
                "boot",
                try b.c.gpa.print("no handover to runit in {d} s", .{timeout}),
                true,
            ),
            error.MachineExited => b.giveUp("boot", "QEMU exited", false),
            else => err,
        };
    }

    /// posture waits for the posture line and judges it. A line still
    /// missing after 20 s gets a carriage return: under KVM on x86_64, a
    /// UART can stall with the line half sent until something is received.
    fn posture(b: *Boot, timeout: i64) !void {
        const gpa = b.c.gpa;
        var line: Posture = .{};
        const deadline = qemu.after(b.c.io, timeout);
        const poke = qemu.after(b.c.io, @min(timeout, 20));
        b.m.until(poke, Waiting{ .line = &line, .gpa = gpa }) catch |err| switch (err) {
            error.Timeout => {
                b.m.note(
                    "\nwerewolf-check: no posture line after 20 s; sending a carriage return\n",
                );
                b.m.send("\r") catch {};
                b.m.until(
                    deadline,
                    Waiting{ .line = &line, .gpa = gpa },
                ) catch |e| return b.postureMissing(e, timeout);
            },
            else => return b.postureMissing(err, timeout),
        };
        const known = b.c.env.get("POSTURE_KNOWN") orelse "";
        if (try judgePosture(gpa, line, known)) |why|
            b.fail("posture", why)
        else
            b.say("ok", "posture", "");
    }

    fn postureMissing(b: *Boot, err: anyerror, timeout: i64) Failed {
        const gpa = b.c.gpa;
        return switch (err) {
            error.Panicked => b.giveUp("posture", "Kernel panic", false),
            error.MachineExited => b.giveUp("posture", "QEMU exited", false),
            error.Timeout => b.giveUp(
                "posture",
                gpa.print("no posture line in {d} s", .{timeout}) catch "",
                true,
            ),
            else => b.giveUp("posture", @errorName(err), false),
        };
    }

    /// hostSteps runs a native run's host suites, while the machine's
    /// console keeps being read: QEMU stalls a machine nobody reads. They
    /// start once every seen line is in, after the guest's own cases, one of
    /// which restarts the service they log in to (test-lifecycle's reaped).
    fn hostSteps(b: *Boot, lines: []const Line, timeout: i64) !void {
        const command = b.c.env.get("HOST_STEPS") orelse return;
        if (command.len == 0) return;
        var look: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer look.deinit();
        _ = try b.settled(&look, lines, timeout) orelse
            return b.giveUp("console", "QEMU exited", false);
        const gpa = b.c.gpa;
        const argv = braced(
            gpa,
            command,
        ) catch return b.giveUp("host-steps", "HOST_STEPS is not a braced list", false);
        const r = host.check.command(b.c.io, gpa, argv, .{
            .environ_map = &b.c.env,
            .timeout = .fromSeconds(b.seconds("HOST_STEPS_TIMEOUT", 60)),
        }) catch |err| {
            b.fail("host-steps", @errorName(err));
            return;
        };
        const out = try mem.concat(gpa, u8, &.{ r.stdout, r.stderr });
        if (r.ok()) b.say("ok", "host-steps", out) else b.fail("host-steps", out);
    }

    /// judge waits up to timeout, reading the console, for every seen
    /// line, then judges every line. No unseen line may appear.
    fn judge(b: *Boot, lines: []const Line, timeout: i64) !void {
        if (lines.len == 0) return;
        const gpa = b.c.gpa;
        var look: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer look.deinit();
        const t = try b.settled(&look, lines, timeout) orelse
            return b.giveUp("console", "QEMU exited", false);
        const a = look.allocator();
        for (lines) |l| switch (l.kind) {
            .seen => if (try t.found(a, l.arg)) b.say("ok", l.name, "") else b.fail(
                l.name,
                try gpa.print("not on the console in {d} s: {s}", .{ timeout, l.arg }),
            ),
            .unseen => if (try t.offending(a, l.arg)) |line|
                b.fail(l.name, try gpa.print("on the console: {s}", .{line}))
            else
                b.say("ok", l.name, ""),
            .up => if (down(t.clean, l.arg)) |line|
                b.fail(l.name, try gpa.print("on the console: {s}", .{line}))
            else
                b.say("ok", l.name, ""),
        };
    }

    /// ends judges a machine that must end by itself, never booting or
    /// resetting, as CONSOLE_ENDS asks: under -no-reboot QEMU exits. Once
    /// it has, every seen line must be on its console and no unseen line.
    fn ends(b: *Boot, lines: []const Line, timeout: i64) !void {
        const gpa = b.c.gpa;
        b.m.until(qemu.after(b.c.io, timeout), Never{}) catch |err| switch (err) {
            error.MachineExited => {},
            error.Timeout => return b.giveUp(
                "end",
                try gpa.print("still running after {d} s", .{timeout}),
                true,
            ),
            else => return err,
        };
        const t = try Text.of(gpa, try b.m.console(gpa));
        for (lines) |l| switch (l.kind) {
            .seen => if (try t.found(gpa, l.arg))
                b.say("ok", l.name, "")
            else
                b.fail(l.name, try gpa.print("not on the console: {s}", .{l.arg})),
            .unseen => if (try t.offending(gpa, l.arg)) |line|
                b.fail(l.name, try gpa.print("on the console: {s}", .{line}))
            else
                b.say("ok", l.name, ""),
            .up => b.fail(l.name, "up needs a machine that stays up"),
        };
        if (b.failed == 0) b.say("pass", "all checks", "");
    }

    /// settled waits up to timeout, reading the console, for every seen
    /// line, and is the console as it last read it, or null when QEMU
    /// exited first. Each look reads the whole console, so look is reset
    /// before the next.
    fn settled(b: *Boot, look: *std.heap.ArenaAllocator, lines: []const Line, timeout: i64) !?Text {
        const io = b.c.io;
        const deadline = qemu.after(io, timeout);
        while (true) {
            _ = look.reset(.retain_capacity);
            const t = try Text.of(look.allocator(), try b.m.console(look.allocator()));
            const missing = for (lines) |l| {
                if (l.kind == .seen and !try t.found(look.allocator(), l.arg)) break true;
            } else false;
            if (!missing or deadline.compare(.lte, .now(io, .awake))) return t;
            if (b.m.exited()) return null;
            try io.sleep(.fromSeconds(1), .awake);
        }
    }

    /// shutdown presses the power button from QEMU's monitor, ACPI on
    /// x86_64 and the device tree's GPIO line on arm64, which power-button
    /// reads. The machine must stop its services and power off.
    fn shutdown(b: *Boot) !void {
        const io = b.c.io;
        const gpa = b.c.gpa;
        var start = (try b.m.console(gpa)).len;
        try b.m.send("\x01c");
        b.m.until(qemu.after(io, 10), After{ .start = start, .needle = "(qemu)" }) catch
            return b.giveUp("shutdown", "no QEMU monitor", false);
        start = (try b.m.console(gpa)).len;
        try b.m.send("system_powerdown\r");
        b.m.until(qemu.after(io, 10), After{ .start = start, .needle = "(qemu)" }) catch {};
        try b.m.send("\x01c");
        b.m.waitFor("reboot: Power down", qemu.after(io, 60)) catch |err| switch (err) {
            error.MachineExited => b.fail("shutdown", "QEMU ended without the kernel powering off"),
            error.Timeout => b.fail("shutdown", "no power-off 60 s after the power button"),
            else => return err,
        };
        b.m.until(qemu.after(io, 30), Never{}) catch |err| switch (err) {
            error.MachineExited => {},
            else => return b.giveUp("shutdown", "QEMU did not exit after powering off", false),
        };
        const text = try b.m.console(gpa);
        if (mem.find(u8, text, "werewolf: filesystems not put down: ")) |at| {
            const end = mem.findAnyPos(u8, text, at, "\r\n") orelse text.len;
            b.fail("shutdown", text[at..end]);
        } else if (b.failed == 0) b.say("ok", "shutdown", "");
    }

    /// powerCut cuts the machine's power, as a reset or a host's hard stop
    /// does, for the next boot to find what is left: QEMU's monitor quits.
    fn powerCut(b: *Boot) !void {
        const io = b.c.io;
        const start = (try b.m.console(b.c.gpa)).len;
        try b.m.send("\x01c");
        b.m.until(qemu.after(io, 10), After{ .start = start, .needle = "(qemu)" }) catch
            return b.giveUp("power-cut", "no QEMU monitor", false);
        try b.m.send("quit\r");
        b.m.until(qemu.after(io, 30), Never{}) catch |err| switch (err) {
            error.MachineExited => {},
            else => return b.giveUp("power-cut", "QEMU did not quit", false),
        };
        if (b.failed == 0) b.say("ok", "power-cut", "");
    }

    /// diagnosis says what the machine was doing when it failed: werewolf's
    /// last progress line, the first kernel message of each known kind of
    /// error, and this host, so a failure on one host and not another shows
    /// why at a glance.
    fn diagnosis(b: *Boot) []const u8 {
        const gpa = b.c.gpa;
        const text = if (b.started) b.m.console(gpa) catch "" else "";
        return explain(gpa, qemu.clean(gpa, text) catch text, b.host) catch b.host;
    }
};

const Handover = struct {
    panic: *[]const u8,
    pub fn done(h: Handover, text: []const u8) !bool {
        if (panicLine(text)) |line| {
            h.panic.* = line;
            return error.Panicked;
        }
        return mem.find(u8, text, "handing over to runit") != null;
    }
};

/// Posture is the posture line's counts and its failing checks.
const Posture = struct { failing: []const u8 = "", passed: u32 = 0 };

const Waiting = struct {
    line: *Posture,
    gpa: Allocator,
    pub fn done(w: Waiting, text: []const u8) !bool {
        if (mem.find(u8, text, "Kernel panic") != null) return error.Panicked;
        // A kernel record can land inside the line: judge the tail cleaned.
        // clean needs twice what it reads.
        const tail = text[text.len -| (64 << 10)..];
        var buffer: [2 * (64 << 10) + 4096]u8 = undefined;
        var fixed: std.heap.FixedBufferAllocator = .init(&buffer);
        const clean = try qemu.clean(fixed.allocator(), tail);
        const parsed = postureLine(clean) orelse return false;
        w.line.* = .{ .failing = try w.gpa.dupe(u8, parsed.failing), .passed = parsed.passed };
        return true;
    }
};

const After = struct {
    start: usize,
    needle: []const u8,
    pub fn done(a: After, text: []const u8) !bool {
        return a.start <= text.len and mem.find(u8, text[a.start..], a.needle) != null;
    }
};

const Never = struct {
    pub fn done(_: Never, _: []const u8) !bool {
        return false;
    }
};

/// parse reads a CHECKS file. Shell checks are the legacy test/boot's.
fn parse(gpa: Allocator, text: []const u8) ![]const Line {
    var out: std.ArrayList(Line) = .empty;
    var lines = mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var words = mem.tokenizeAny(u8, line, " \t");
        const kind_word = words.next().?;
        const kind = std.meta.stringToEnum(Kind, kind_word) orelse
            return if (mem.eql(u8, kind_word, "ok") or mem.eql(u8, kind_word, "gap"))
                error.ShellChecksNeedTestBoot
            else
                error.UnknownLine;
        const name = words.next() orelse return error.UnnamedLine;
        const arg = mem.trim(u8, words.rest(), " \t");
        if (kind != .up and arg.len == 0) return error.MissingExpression;
        if (kind == .up and mem.findAny(u8, arg, " \t\"") != null) return error.InvalidService;
        if (kind != .up) {
            // Refuse a bad expression now, not after a boot.
            const probe = try regex(gpa, arg);
            if (werewolf_regex_match(probe.ptr, "") < 0) return error.InvalidExpression;
        }
        try out.append(gpa, .{ .kind = kind, .name = name, .arg = arg });
    }
    return out.items;
}

/// regex is RE for regcomp: \r, \n and \t become those characters.
fn regex(gpa: Allocator, re: []const u8) ![:0]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < re.len) : (i += 1) {
        if (re[i] == 0) return error.InvalidExpression;
        if (re[i] == '\\' and i + 1 < re.len) {
            const literal: ?u8 = switch (re[i + 1]) {
                'r' => '\r',
                'n' => '\n',
                't' => '\t',
                else => null,
            };
            if (literal) |ch| {
                try out.append(gpa, ch);
                i += 1;
                continue;
            }
            try out.appendSlice(gpa, re[i .. i + 2]);
            i += 1;
            continue;
        }
        try out.append(gpa, re[i]);
    }
    return out.toOwnedSliceSentinel(gpa, 0);
}

fn matches(gpa: Allocator, re: []const u8, text: [:0]const u8) !bool {
    const pattern = try regex(gpa, re);
    const result = werewolf_regex_match(pattern.ptr, text.ptr);
    if (result < 0) return error.InvalidExpression;
    return result == 1;
}

/// Text is the console as it came and with the kernel's records taken out,
/// each ready for regexec: a NUL the machine wrote reads as a space.
const Text = struct {
    raw: [:0]const u8,
    clean: [:0]const u8,

    fn of(gpa: Allocator, console: []u8) !Text {
        for (console) |*ch| if (ch.* == 0) {
            ch.* = ' ';
        };
        return .{
            .raw = try gpa.dupeSentinel(u8, console, 0),
            .clean = try gpa.dupeSentinel(u8, try qemu.clean(gpa, console), 0),
        };
    }

    fn found(t: Text, gpa: Allocator, re: []const u8) !bool {
        return try matches(gpa, re, t.raw) or try matches(gpa, re, t.clean);
    }

    /// offending is the console line an unseen expression matched, or the
    /// expression itself when it matched across lines, or null.
    fn offending(t: Text, gpa: Allocator, re: []const u8) !?[]const u8 {
        if (!try t.found(gpa, re)) return null;
        for ([_][]const u8{ t.clean, t.raw }) |text| {
            var lines = mem.splitScalar(u8, text, '\n');
            while (lines.next()) |line| {
                if (try matches(gpa, re, try gpa.dupeSentinel(u8, line, 0)))
                    return mem.trimEnd(u8, line, "\r");
            }
        }
        return re;
    }
};

/// down is a leash line saying a service, or service alone if named, went
/// down or retried for anything but syslogd: services must stay up.
fn down(clean: []const u8, service: []const u8) ?[]const u8 {
    var lines = mem.splitScalar(u8, clean, '\n');
    while (lines.next()) |line| {
        const at = mem.find(u8, line, "leash: {\"event\":\"") orelse continue;
        const record = mem.trimEnd(u8, line[at + "leash: ".len ..], "\r");
        const event = record["{\"event\":\"".len..];
        const bad = mem.startsWith(u8, event, "down\"") or (mem.startsWith(u8, event, "retry\"") and
            mem.find(u8, record, "\"why\":\"waiting for syslogd\"") == null);
        if (!bad) continue;
        if (service.len > 0) {
            var key: [128]u8 = undefined;
            const want = std.mem.print(
                &key,
                "\",\"service\":\"{s}\"",
                .{service},
            ) catch continue;
            if (mem.find(u8, event, want) == null) continue;
        }
        return mem.trimEnd(u8, line, "\r");
    }
    return null;
}

/// postureLine reads "posture: fail=IDS pass=N skip=N ".
fn postureLine(text: []const u8) ?Posture {
    var at: usize = 0;
    while (mem.findPos(u8, text, at, "posture: fail=")) |i| : (at = i + 1) {
        var words = mem.splitScalar(u8, text[i + "posture: fail=".len ..], ' ');
        const failing = words.next() orelse continue;
        const pass = words.next() orelse continue;
        const skip = words.next() orelse continue;
        if (!mem.startsWith(u8, pass, "pass=") or !mem.startsWith(u8, skip, "skip=")) continue;
        const passed = std.fmt.parseInt(u32, pass["pass=".len..], 10) catch continue;
        _ = std.fmt.parseInt(u32, skip["skip=".len..], 10) catch continue;
        return .{ .failing = failing, .passed = passed };
    }
    return null;
}

/// judgePosture is why line breaks the known failures, or null. Each known
/// ID must fail, ?ID may, and nothing else may; fewer than 20 passes means
/// posture did not run.
fn judgePosture(gpa: Allocator, line: Posture, known: []const u8) !?[]const u8 {
    if (line.passed < 20)
        return try gpa.print("only {d} checks passed; did posture run?", .{line.passed});
    var sure: std.ArrayList([]const u8) = .empty;
    var maybe: std.ArrayList([]const u8) = .empty;
    var ids = mem.tokenizeAny(u8, known, " \t\n,");
    while (ids.next()) |id| if (id[0] == '?')
        try maybe.append(gpa, id[1..])
    else
        try sure.append(gpa, id);
    var got: std.ArrayList([]const u8) = .empty;
    var fails = mem.tokenizeScalar(u8, line.failing, ',');
    while (fails.next()) |id| try got.append(gpa, id);
    var detail: std.ArrayList(u8) = .empty;
    for (got.items) |id| if (!has(sure.items, id) and !has(maybe.items, id))
        try detail.print(
            gpa,
            "{s}{s}",
            .{ if (detail.items.len == 0) "failing, not known: " else " ", id },
        );
    var closed = false;
    for (sure.items) |id| if (!has(got.items, id)) {
        try detail.print(gpa, "{s}{s}", .{ if (!closed) "\nknown, now passing: " else " ", id });
        closed = true;
    };
    if (closed) try detail.appendSlice(gpa, "; take it out of the form's weaknesses " ++
        "(or test/posture-known), and update the docs");
    return if (detail.items.len == 0) null else mem.trim(u8, detail.items, "\n");
}

fn has(names: []const []const u8, name: []const u8) bool {
    for (names) |n| if (mem.eql(u8, n, name)) return true;
    return false;
}

/// braced reads a list of words each in braces, as tools/native-ssh.zig
/// writes HOST_STEPS: "{a b} {c}".
fn braced(gpa: Allocator, text: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var rest = mem.trim(u8, text, " ");
    while (rest.len > 0) {
        if (rest[0] != '{') return error.NotBraced;
        const close = mem.findScalar(u8, rest, '}') orelse return error.NotBraced;
        try out.append(gpa, rest[1..close]);
        rest = mem.trimStart(u8, rest[close + 1 ..], " ");
    }
    if (out.items.len == 0) return error.NotBraced;
    return out.items;
}

fn panicLine(text: []const u8) ?[]const u8 {
    for ([_][]const u8{ "Kernel panic", "stage0: " }) |start| {
        var at: usize = 0;
        while (mem.findPos(u8, text, at, start)) |i| : (at = i + 1) {
            const end = mem.findAnyPos(u8, text, i, "\r\n") orelse text.len;
            const line = text[i..end];
            if (start[0] == 'K' or mem.find(u8, line, "panicking") != null) return line;
        }
    }
    return null;
}

/// explain is werewolf's last progress line, the first line of each kernel
/// error, and the host.
fn explain(gpa: Allocator, text: []const u8, host_line: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var last: ?[]const u8 = null;
    var lines = mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| for ([_][]const u8{
        "stage0: ", "werewolf: ", "fence: ",       "slot-keep: ",
        "leash: ",  "pg-init: ",  "dhcp-client: ", "cloud-metadata: ",
    }) |prefix| if (mem.find(u8, line, prefix)) |at| {
        last = line[at..];
        break;
    };
    if (last) |l| try out.print(gpa, "last progress: {s}\n", .{mem.trim(u8, l, " \r")});
    for ([_][]const u8{
        "Kernel panic",                  "rcu: INFO: ",
        "Possible timer handling issue", "blocked for more than",
        "watchdog: BUG: soft lockup",    "BUG: ",
        "Unable to handle kernel",       "Internal error: ",
    }) |needle| if (mem.find(u8, text, needle)) |at| {
        const begin = (mem.findScalarLast(u8, text[0..at], '\n') orelse 0);
        const end = mem.findScalarPos(u8, text, at, '\n') orelse text.len;
        try out.print(gpa, "kernel: {s}\n", .{mem.trim(u8, text[begin..end], " \r\n")});
    };
    try out.print(gpa, "host: {s}", .{host_line});
    return out.items;
}

/// describe is this host as a failure reports it: system, QEMU, its
/// accelerator, CPUs and load.
fn describe(c: *host.Check, argv: []const []const u8) ![]const u8 {
    const gpa = c.gpa;
    const u = std.posix.uname();
    const version = host.check.command(c.io, gpa, &.{ argv[0], "--version" }, .{
        .timeout = .fromSeconds(10),
    }) catch null;
    const uptime = host.check.command(
        c.io,
        gpa,
        &.{"uptime"},
        .{ .timeout = .fromSeconds(10) },
    ) catch null;
    var accel: []const u8 = "default";
    for (argv, 0..) |a, i| if (mem.eql(u8, a, "-accel") and i + 1 < argv.len) {
        accel = argv[i + 1];
    };
    const load = if (uptime) |r| blk: {
        const at = mem.find(u8, r.stdout, "load average") orelse break :blk "?";
        const colon = mem.findScalarPos(u8, r.stdout, at, ':') orelse break :blk "?";
        break :blk mem.trim(u8, r.stdout[colon + 1 ..], " \n");
    } else "?";
    return gpa.print("{s} {s} {s}; {s}; accel {s}; {d} CPUs; load {s}", .{
        mem.sliceTo(&u.sysname, 0),
        mem.sliceTo(&u.release, 0),
        mem.sliceTo(&u.machine, 0),
        if (version) |r| mem.sliceTo(r.stdout, '\n') else "?",
        accel,
        std.Thread.getCpuCount() catch 0,
        load,
    });
}

const testing = std.testing;

test "console lines are seen, unseen or up; shell checks are test/boot's" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const lines = try parse(a,
        \\# a form's console
        \\seen    caddy-needs-user   leash: \{"event":"down","service":"caddy"\}
        \\unseen  boot-errors        werewolf: [^\r\n]*error
        \\up      service-down
        \\up      postgres-down      postgres
    );
    try testing.expectEqual(4, lines.len);
    try testing.expectEqual(Kind.up, lines[3].kind);
    try testing.expectEqualStrings("postgres", lines[3].arg);
    try testing.expectEqualStrings("", lines[2].arg);
    try testing.expectError(error.ShellChecksNeedTestBoot, parse(a, "ok  root  [ -e / ]\n"));
    try testing.expectError(error.MissingExpression, parse(a, "seen nothing\n"));
    try testing.expectError(error.InvalidExpression, parse(a, "seen bad (unclosed\n"));
    try testing.expectError(error.UnknownLine, parse(a, "maybe x y\n"));
}

test "expressions take \\r, \\n and \\t as characters, other escapes as written" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("[^\r\n]*\\}\r*\n", try regex(a, "[^\\r\\n]*\\}\\r*\\n"));
    const record = "x\nwerewolf-test: {\"event\":\"complete\",\"run\":\"r\"}\r\r\n";
    const t = try Text.of(a, try a.dupe(u8, record));
    try testing.expect(try t.found(
        a,
        "werewolf-test: [^\\r\\n]*\"event\":\"complete\"[^\\r\\n]*\\}\\r*\\n",
    ));
    try testing.expect(!try t.found(a, "\"event\":\"fail\""));
}

test "services stay up but for a retry that waits for syslogd" {
    const calm =
        \\leash: {"event":"start","service":"web"}
        \\leash: {"event":"retry","service":"web","why":"waiting for syslogd"}
    ;
    try testing.expectEqual(null, down(calm, ""));
    const fell = calm ++ "\nleash: {\"event\":\"down\",\"service\":\"db\",\"why\":\"exit 1\"}\r";
    try testing.expectEqualStrings(
        "leash: {\"event\":\"down\",\"service\":\"db\",\"why\":\"exit 1\"}",
        down(fell, "").?,
    );
    try testing.expectEqual(null, down(fell, "web"));
    try testing.expect(down(fell, "db") != null);
    try testing.expect(down(
        "leash: {\"event\":\"retry\",\"service\":\"web\",\"why\":\"exit 2\"}",
        "web",
    ) != null);
}

test "posture holds only the known failures, and needs posture to have run" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const line = postureLine(
        "x posture: fail=boot-ipe-enforced,kernel-wx pass=95 skip=4 disabled=ipe {",
    ).?;
    try testing.expectEqualStrings("boot-ipe-enforced,kernel-wx", line.failing);
    try testing.expectEqual(95, line.passed);
    try testing.expectEqual(null, try judgePosture(a, line, "boot-ipe-enforced kernel-wx ?net-x"));
    try testing.expectEqual(null, try judgePosture(a, line, "boot-ipe-enforced,?kernel-wx"));
    const new = (try judgePosture(a, line, "boot-ipe-enforced")).?;
    try testing.expect(mem.find(u8, new, "failing, not known: kernel-wx") != null);
    const closed = (try judgePosture(a, line, "boot-ipe-enforced kernel-wx gone")).?;
    try testing.expect(mem.find(u8, closed, "known, now passing: gone") != null);
    try testing.expect((try judgePosture(a, .{ .passed = 3 }, "")) != null);
    try testing.expectEqual(null, postureLine("posture: fail= pass=x skip=1 "));
}

test "host steps are a braced list; panics and progress are found" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const argv = try braced(a, "{build/host/native-host} {a plan.json} {seed}");
    try testing.expectEqual(3, argv.len);
    try testing.expectEqualStrings("a plan.json", argv[1]);
    try testing.expectError(error.NotBraced, braced(a, "native-host plan"));
    try testing.expectEqualStrings(
        "stage0: no root: panicking",
        panicLine("stage0: verity\r\nstage0: no root: panicking\r\n").?,
    );
    try testing.expectEqual(null, panicLine("stage0: fine\n"));
    const why = try explain(a, "leash: {\"event\":\"start\"}\n[ 1.0] BUG: oops\n", "h");
    try testing.expect(mem.find(u8, why, "last progress: leash: {\"event\":\"start\"}") != null);
    try testing.expect(mem.find(u8, why, "kernel: [ 1.0] BUG: oops") != null);
}

test "every form's console lines parse, their expressions compile" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var forms = try Io.Dir.cwd().openDir(io, "forms", .{ .iterate = true });
    defer forms.close(io);
    var it = forms.iterate();
    var seen: usize = 0;
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const path = try a.print("{s}/test/console", .{entry.name});
        const text = forms.readFileAlloc(io, path, a, .limited(1 << 20)) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        _ = parse(a, text) catch |err| {
            std.debug.print("forms/{s}: {t}\n", .{ path, err });
            return err;
        };
        seen += 1;
    }
    try testing.expect(seen > 0);
}
