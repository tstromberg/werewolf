//! native-tests-regression drives, as black boxes, what the harness's unit
//! tests cannot: the console transport of test/boot and of build/host/console
//! (test/console.zig) with a fake QEMU, which is this program run again, test/check-one's kept
//! evidence, and howl test's
//! handing over to make. Run it from the checkout root with HOWL, as
//! `make _test/howl-smoke` does.

const std = @import("std");
const plans = @import("test-plan");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const posix = std.posix;

const consoles = [_][]const u8{ "test/boot", "build/host/console" };

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(gpa);
    for (args[1..]) |arg| if (mem.eql(u8, arg, "--version")) {
        try Io.File.stdout().writeStreamingAll(io, "fake QEMU for console transport regression\n");
        return;
    };
    if (args.len == 4 and mem.eql(u8, args[1], "fake-qemu")) return qemu(io, args[2], args[3]);
    if (args.len != 2) {
        std.debug.print("usage: native-tests-regression HOWL\n", .{});
        std.process.exit(2);
    }
    const self = try std.process.executablePathAlloc(io, gpa);
    var failed = false;
    inline for (.{
        .{ "a completion record keeps its own newline", fragments, true },
        .{ "a serial console's split UTF-8 survives until power off", utf8, true },
        .{ "console collection obeys the explicit budget", budget, true },
        .{ "QEMU exiting without a kernel power off is refused", exited, true },
        .{ "check-one keeps each failure's native logs", repeated, false },
        .{ "howl test becomes make, without an outer make's flags", handover, false },
    }) |t| for (if (t[2]) &consoles else consoles[0..1]) |console| {
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        var c: Case = .{
            .io = io,
            .gpa = arena.allocator(),
            .self = self,
            .howl = try Dir.cwd().realPathFileAlloc(io, args[1], arena.allocator()),
            .env = init.environ_map,
            .console = console,
        };
        const label = if (t[2]) console else "";
        if (t[1](&c)) {
            std.debug.print("native-tests-regression: pass {s} {s}\n", .{ t[0], label });
        } else |err| {
            failed = true;
            std.debug.print(
                "native-tests-regression: FAIL {s} {s}: {s} {s}\n",
                .{ t[0], label, @errorName(err), c.why },
            );
        }
    };
    if (failed) std.process.exit(1);
}

const Case = struct {
    io: Io,
    gpa: Allocator,
    self: []const u8,
    howl: []const u8,
    env: *const std.process.Environ.Map,
    /// console is the transport under test: test/boot or build/host/console.
    console: []const u8,
    why: []const u8 = "",

    fn expect(c: *Case, ok: bool, comptime fmt: []const u8, args: anytype) !void {
        if (ok) return;
        c.why = try c.gpa.print(fmt, args);
        return error.Unexpected;
    }

    /// boot runs the console on the fake QEMU, as the harness runs it on a
    /// real one, and returns its result and the console log.
    /// scratch is a new directory under .zig-cache/tmp, removed by the caller.
    fn scratch(c: *Case) ![]const u8 {
        var bytes: [8]u8 = undefined;
        c.io.random(&bytes);
        const path = try c.gpa.print(
            ".zig-cache/tmp/regression-{s}",
            .{std.fmt.bytesToHex(bytes, .lower)},
        );
        try Dir.cwd().createDirPath(c.io, path);
        return Dir.cwd().realPathFileAlloc(c.io, path, c.gpa);
    }

    fn boot(
        c: *Case,
        power: []const u8,
        mode: []const u8,
        checks: []const u8,
        timeout: []const u8,
    ) !Boot {
        const root = try c.scratch();
        defer Dir.cwd().deleteTree(c.io, root) catch {};
        const checks_path = try c.gpa.print("{s}/checks", .{root});
        const log = try c.gpa.print("{s}/console.log", .{root});
        try Dir.cwd().writeFile(c.io, .{ .sub_path = checks_path, .data = checks });
        var env = try c.env.clone(c.gpa);
        for ([_][]const u8{ "POSTURE_KNOWN", "SSH_PORT", "GITEA_PORT" }) |key| try env.put(key, "");
        try env.put("CONSOLE_TIMEOUT", timeout);
        const result = try std.process.run(c.gpa, c.io, .{
            .argv = &.{
                c.console,
                "serial-utf8",
                checks_path,
                log,
                c.self,
                "fake-qemu",
                power,
                mode,
            },
            .environ_map = &env,
            .stdout_limit = .limited(1 << 20),
            .stderr_limit = .limited(1 << 20),
            .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
        });
        return .{
            .ok = result.term == .exited and result.term.exited == 0,
            .stdout = result.stdout,
            .log = try Dir.cwd().readFileAlloc(c.io, log, c.gpa, .limited(1 << 20)),
        };
    }
};

const Boot = struct { ok: bool, stdout: []const u8, log: []const u8 };

/// fragments waits for a completion record whose newline arrives late, or
/// at once, and finds it whole, with no newline test/boot made up.
fn fragments(c: *Case) !void {
    for ([_][]const u8{ "fragment", "immediate" }) |mode| {
        const b = try c.boot("poweroff", mode, "seen complete " ++ plans.completion ++ "\n", "300");
        try c.expect(b.ok, "{s}: test/boot failed: {s}", .{ mode, b.stdout });
        var records: std.ArrayList([]const u8) = .empty;
        var lines = mem.splitScalar(u8, b.log, '\n');
        while (lines.next()) |line| {
            const at = mem.find(u8, line, "werewolf-test: ") orelse continue;
            try records.append(c.gpa, mem.trimEnd(u8, line[at + "werewolf-test: ".len ..], "\r"));
        }
        try c.expect(records.items.len == 1 and
            mem.eql(
                u8,
                records.items[0],
                "{\"event\":\"complete\",\"status\":\"pass\"}",
            ), "{s}: records {d}", .{
            mode, records.items.len,
        });
    }
}

const squares = blk: {
    var bytes: [90]u8 = undefined;
    for (0..30) |i| @memcpy(bytes[i * 3 ..][0..3], "\xe2\x96\xa1");
    break :blk bytes;
};

/// utf8 needs Expect to keep reading a character split across reads, which
/// macOS's text decoder once took for the end of the console.
fn utf8(c: *Case) !void {
    const b = try c.boot("poweroff", "whole", "seen complete COMPLETE\n", "300");
    try c.expect(b.ok, "test/boot failed: {s}", .{b.stdout});
    try c.expect(mem.find(u8, b.log, &squares) != null, "split characters lost", .{});
    try c.expect(mem.find(u8, b.log, "reboot: Power down") != null, "no power off logged", .{});
}

fn budget(c: *Case) !void {
    const b = try c.boot("poweroff", "missing", "seen complete " ++ plans.completion ++ "\n", "1");
    try c.expect(!b.ok, "a missing completion passed", .{});
    try c.expect(
        mem.find(u8, b.stdout, "FAIL") != null and mem.find(u8, b.stdout, "complete") != null,
        "{s}",
        .{b.stdout},
    );
    try c.expect(
        mem.find(u8, b.log, "reboot: Power down") != null,
        "QEMU was not powered off",
        .{},
    );
}

fn exited(c: *Case) !void {
    const b = try c.boot("exit", "whole", "seen complete COMPLETE\n", "300");
    try c.expect(!b.ok, "an exit without power off passed", .{});
    try c.expect(
        mem.find(u8, b.stdout, "QEMU ended without the kernel powering off") != null,
        "{s}",
        .{b.stdout},
    );
}

/// repeated runs test/check-one with a command that fails its first and
/// third boots, the third before booting.
fn repeated(c: *Case) !void {
    const root = try c.scratch();
    defer Dir.cwd().deleteTree(c.io, root) catch {};
    var dir = try Dir.cwd().openDir(c.io, root, .{});
    defer dir.close(c.io);
    try dir.writeFile(c.io, .{ .sub_path = "run", .flags = .{
        .permissions = .fromMode(0o700),
    }, .data =
        \\#!/bin/sh
        \\n=$(cat "$1/count" 2>/dev/null || echo 0)
        \\n=$((n + 1))
        \\echo "$n" >"$1/count"
        \\if [ "$n" -eq 3 ]; then echo "build failed"; exit 1; fi
        \\mkdir -p "$1/sample-native"
        \\echo "seed $n" >"$1/sample-native/seed.log"
        \\echo "verify $n" >"$1/sample-native/verify.log"
        \\echo "result $n"
        \\[ "$n" -ne 1 ]
        \\
    });
    const result = try std.process.run(c.gpa, c.io, .{
        .argv = &.{
            "test/check-one",
            "3",
            root,
            "sample",
            try c.gpa.print("{s}/run", .{root}),
            root,
        },
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(1 << 20),
    });
    try c.expect(
        result.term == .exited and result.term.exited == 1,
        "check-one: {s}",
        .{result.stdout},
    );
    try c.expect(
        mem.find(u8, result.stdout, "2 of 3 boots failed") != null,
        "{s}",
        .{result.stdout},
    );
    try c.expect(
        mem.eql(u8, try dir.readFileAlloc(c.io, "count", c.gpa, .limited(4096)), "3\n"),
        "count",
        .{},
    );
    try c.expect(
        mem.eql(
            u8,
            try dir.readFileAlloc(c.io, "sample-one-1.out", c.gpa, .limited(4096)),
            "result 1\n",
        ),
        "first output",
        .{},
    );
    for ([_][]const u8{ "seed", "verify" }) |phase| {
        const kept = try dir.readFileAlloc(
            c.io,
            try c.gpa.print("sample-one-1/{s}.log", .{phase}),
            c.gpa,
            .limited(4096),
        );
        try c.expect(mem.eql(u8, kept, try c.gpa.print("{s} 1\n", .{phase})), "{s} log", .{phase});
        // A build failure must not inherit the preceding boot's evidence.
        const stale = dir.access(c.io, try c.gpa.print("sample-one-3/{s}.log", .{phase}), .{});
        try c.expect(std.meta.isError(stale), "boot 3 kept boot 2's {s} log", .{phase});
    }
}

/// handover runs howl test in a scratch checkout whose make records what it
/// was given: howl must replace itself with make, so make's exit status is
/// howl's, and must not hand make an outer make's dry-run flags.
fn handover(c: *Case) !void {
    const root = try c.scratch();
    defer Dir.cwd().deleteTree(c.io, root) catch {};
    var dir = try Dir.cwd().openDir(c.io, root, .{});
    defer dir.close(c.io);
    for ([_][]const u8{
        "Makefile",               "test/check-form",       "test/check-shellfree",
        "tools/native-tests.zig", "forms/caddy/form.yaml",
    }) |path| {
        if (std.fs.path.dirname(path)) |parent| try dir.createDirPath(c.io, parent);
        try dir.writeFile(c.io, .{ .sub_path = path, .data = "" });
    }
    try dir.createDirPath(c.io, "bin");
    for ([_][]const u8{ "make", "gmake" }) |name| try dir.writeFile(c.io, .{
        .sub_path = try c.gpa.print("bin/{s}", .{name}),
        .flags = .{ .permissions = .fromMode(0o755) },
        .data =
        \\#!/bin/sh
        \\{ printf '%s\n' "$@"; env | grep -E '^(MAKEFLAGS|MFLAGS|MAKELEVEL)=' || true; } >"$HOWL_TEST_RECORD"
        \\echo 'form checks ran'
        \\exit 17
        \\
        ,
    });
    var env = try c.env.clone(c.gpa);
    try env.put(
        "PATH",
        try c.gpa.print("{s}/bin:{s}", .{ root, c.env.get("PATH") orelse "/usr/bin:/bin" }),
    );
    try env.put("HOWL_TEST_RECORD", try c.gpa.print("{s}/record", .{root}));
    for ([_][2][]const u8{ .{ "MAKEFLAGS", "n" }, .{ "MFLAGS", "-n" }, .{ "MAKELEVEL", "1" } }) |v|
        try env.put(v[0], v[1]);
    const Expected = struct { args: []const []const u8, record: []const u8 };
    for ([_]Expected{
        .{
            .args = &.{ "--with", "caddy", "--arch", "amd64" },
            .record = "--no-print-directory\n-k\nARCH=x86_64\ncheck-caddy\ncheck-shellfree-caddy\n",
        },
        .{
            .args = &.{ "--with", "caddy", "--arch", "arm64", "--iterate" },
            .record = try c.gpa.print("--no-print-directory\nARCH=aarch64\nITERATE=ensure\nPHASE" ++
                "=seed\n" ++
                "DRIVER=\nITERATE_HOWL={s}\niterate-caddy\n", .{c.howl}),
        },
    }) |e| {
        if (mem.eql(u8, e.args[e.args.len - 1], "--iterate")) {
            try dir.createDirPath(c.io, "forms/caddy/test");
            try dir.writeFile(c.io, .{ .sub_path = "forms/caddy/test/tests.yaml", .data =
                \\version: 1
                \\suites:
                \\  - name: web
                \\    cases:
                \\      - name: health
                \\        steps:
                \\          - file: /etc/caddy
                \\            expect:
                \\              exists: true
                \\
            });
        }
        const result = try std.process.run(c.gpa, c.io, .{
            .argv = try mem.concat(c.gpa, []const u8, &.{ &.{ c.howl, "test" }, e.args }),
            .cwd = .{ .path = root },
            .environ_map = &env,
            .stdout_limit = .limited(1 << 20),
            .stderr_limit = .limited(1 << 20),
        });
        try c.expect(result.term == .exited and result.term.exited == 17, "howl test {s}: {s}", .{
            e.args[e.args.len - 1], result.stderr,
        });
        try c.expect(
            mem.eql(u8, result.stdout, "form checks ran\n"),
            "stdout {s}",
            .{result.stdout},
        );
        const record = try dir.readFileAlloc(c.io, "record", c.gpa, .limited(4096));
        try c.expect(mem.eql(u8, record, e.record), "make was given:\n{s}", .{record});
    }
}

/// qemu is the fake QEMU: on a raw console it prints a boot, its completion
/// record split or whole, answers the monitor's power down, then prints
/// UTF-8 a byte at a time, and powers off or simply exits.
fn qemu(io: Io, power: []const u8, mode: []const u8) !void {
    // test/boot gives QEMU a terminal, build/host/console a pipe: make a
    // terminal raw, as QEMU's -nographic does.
    if (posix.tcgetattr(0)) |raw| {
        var t = raw;
        inline for (.{
            "IGNBRK",
            "BRKINT",
            "PARMRK",
            "ISTRIP",
            "INLCR",
            "IGNCR",
            "ICRNL",
            "IXON",
        }) |flag|
            @field(t.iflag, flag) = false;
        t.oflag.OPOST = false;
        inline for (.{
            "ECHO",
            "ECHONL",
            "ICANON",
            "ISIG",
            "IEXTEN",
        }) |flag| @field(t.lflag, flag) = false;
        t.cflag.CSIZE = .CS8;
        t.cflag.PARENB = false;
        t.cc[@backingInt(posix.V.MIN)] = 1;
        t.cc[@backingInt(posix.V.TIME)] = 0;
        try posix.tcsetattr(0, .NOW, t);
    } else |_| {}
    const out = Io.File.stdout();
    try out.writeStreamingAll(
        io,
        "handing over to runit\nposture: fail= pass=100 skip=0 COMPLETE\n",
    );
    if (!mem.eql(u8, mode, "whole") and !mem.eql(u8, mode, "missing")) {
        if (mem.eql(u8, mode, "fragment")) try io.sleep(.fromMilliseconds(200), .awake);
        try out.writeStreamingAll(
            io,
            "werewolf-test: {\"event\":\"complete\",\"status\":\"pass\"}\r",
        );
        try io.sleep(.fromMilliseconds(200), .awake);
        var pending = [_]posix.pollfd{.{ .fd = 0, .events = posix.POLL.IN, .revents = 0 }};
        // The host must wait for the record's newline before it answers.
        if (try posix.poll(&pending, 0) != 0) std.process.exit(3);
        try out.writeStreamingAll(io, "\r\n");
    }
    var line: [256]u8 = undefined;
    _ = try until(&line, "\x01c");
    try out.writeStreamingAll(io, "(qemu) ");
    if (!mem.eql(u8, try until(&line, "\r"), "system_powerdown\r")) std.process.exit(4);
    try out.writeStreamingAll(io, "(qemu) ");
    _ = try until(&line, "\x01c");
    try out.writeStreamingAll(io, "power button on\r");
    try io.sleep(.fromMilliseconds(10), .awake);
    // Serial devices can split a UTF-8 character across reads.
    for (0..30) |_| for ("\xe2\x96\xa1") |byte| {
        try out.writeStreamingAll(io, &.{byte});
        try io.sleep(.fromMilliseconds(1), .awake);
    };
    if (mem.eql(u8, power, "poweroff")) try out.writeStreamingAll(io, "\nreboot: Power down\n");
    try io.sleep(.fromMilliseconds(10), .awake);
}

/// until reads the console a byte at a time through ending.
fn until(buffer: []u8, ending: []const u8) ![]const u8 {
    var n: usize = 0;
    while (n < ending.len or !mem.endsWith(u8, buffer[0..n], ending)) {
        if (n == buffer.len) n = 0;
        if (try posix.read(0, buffer[n .. n + 1]) == 0) std.process.exit(1);
        n += 1;
    }
    return buffer[0..n];
}
