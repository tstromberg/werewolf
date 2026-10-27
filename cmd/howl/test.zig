//! Run a checkout's existing form checks with their output, logs and exit status.
const std = @import("std");
const forms = @import("form");
const plans = @import("test-plan");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;

const syntax = "usage: howl test --with FORM [--arch ARCH]\n" ++
    "       howl test --with FORM --iterate [--driver NAME] [--phase seed|verify]\n" ++
    "       howl test --with FORM --iterate --reset|--stop\n" ++
    "Runs the clean release gate, or reuses one disposable SSH VM for iteration.\n" ++
    "Uses this checkout; logs and iteration state remain under build/.";

pub fn command(
    io: std.Io,
    gpa: std.mem.Allocator,
    args: []const []const u8,
    why: *howl.Why,
) !void {
    for (args) |arg| if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
        howl.say(io, "{s}", .{syntax});
        return;
    };
    const step = try decide(
        io,
        gpa,
        Dir.cwd(),
        args,
        try std.process.executablePathAlloc(io, gpa),
        why,
    );
    // An outer make's dry-run flags or command-line overrides must not turn
    // a test invocation into a successful run that never executes its checks.
    var env = try howl.environ.clone(gpa);
    defer env.deinit();
    for (inherited) |key| _ = env.swapRemove(key);
    howl.say(io, "{s}", .{step.note});
    const err = std.process.replace(io, .{ .argv = step.argv, .environ_map = &env });
    return why.refuse("{s}: {s}", .{ howl.make_cmd, @errorName(err) });
}

const inherited = [_][]const u8{ "MAKEFLAGS", "MFLAGS", "MAKELEVEL" };

/// Options are what howl test was asked.
const Options = struct {
    form: []const u8,
    arch: ?howl.Arch = null,
    iterate: bool = false,
    reset: bool = false,
    stop: bool = false,
    driver: ?[]const u8 = null,
    phase: []const u8 = "seed",
    phase_given: bool = false,
};

fn parse(args: []const []const u8, why: *howl.Why) !Options {
    var o: Options = .{ .form = "" };
    var form: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const switches = [_]struct { []const u8, *bool }{
            .{ "--iterate", &o.iterate }, .{ "--reset", &o.reset }, .{ "--stop", &o.stop },
        };
        const toggled = for (switches) |s| {
            if (!mem.eql(u8, args[i], s[0])) continue;
            if (s[1].*) return why.refuse("{s} given twice", .{s[0]});
            s[1].* = true;
            break true;
        } else false;
        if (toggled) continue;
        const flag, const value = try howl.flagValue(args, &i, why);
        if (mem.eql(u8, flag, "--with")) {
            if (form != null) return why.refuse("--with given twice; test one form at a time", .{});
            if (!forms.isName(value)) return why.refuse("--with needs one existing form name", .{});
            form = value;
        } else if (mem.eql(u8, flag, "--arch")) {
            if (o.arch != null) return why.refuse("--arch given twice", .{});
            o.arch = howl.archName(value) orelse return why.refuse(howl.arch_refusal, .{value});
        } else if (mem.eql(u8, flag, "--driver")) {
            if (o.driver != null) return why.refuse("--driver given twice", .{});
            if (!forms.isName(value)) return why.refuse("--driver needs one test driver name", .{});
            o.driver = value;
        } else if (mem.eql(u8, flag, "--phase")) {
            if (o.phase_given) return why.refuse("--phase given twice", .{});
            if (!mem.eql(u8, value, "seed") and !mem.eql(u8, value, "verify"))
                return why.refuse("--phase is seed or verify", .{});
            o.phase = value;
            o.phase_given = true;
        } else return why.refuse("{s}: unsupported test option\n{s}", .{ flag, syntax });
    }
    o.form = form orelse return why.refuse("no form\n{s}", .{syntax});
    return o;
}

/// Step is the make howl test becomes, and what howl says first.
const Step = struct { argv: []const []const u8, note: []const u8 };

/// decide reads the arguments and the checkout at root, and the form's plan,
/// and chooses the make to run: the release gate, or one iteration step.
/// self is this howl, which iteration drives the VM with.
fn decide(
    io: Io,
    gpa: Allocator,
    root: Dir,
    args: []const []const u8,
    self: []const u8,
    why: *howl.Why,
) !Step {
    const o = try parse(args, why);
    const target = o.arch orelse try howl.localArch(why);
    for ([_][]const u8{
        "Makefile", "test/check-shellfree", "tools/native-tests.zig",
    }) |path|
        root.access(io, path, .{}) catch
            return why.refuse(
                "howl test needs a werewolf checkout; run it from the checkout root",
                .{},
            );
    const manifest = try gpa.print("forms/{s}/form.yaml", .{o.form});
    root.access(io, manifest, .{}) catch
        return why.refuse("no {s}; test one form from this checkout", .{manifest});
    const path = try gpa.print("forms/{s}/test/tests.yaml", .{o.form});
    const native = if (root.access(io, path, .{})) true else |err| switch (err) {
        error.FileNotFound => false,
        else => return err,
    };
    if (native) {
        var failure: plans.Failure = .{};
        _ = plans.form(
            io,
            gpa,
            root,
            try gpa.print("forms/{s}", .{o.form}),
            &failure,
        ) catch |err|
            return switch (err) {
                error.Plan => why.refuse("{s}", .{failure.text}),
                error.OutOfMemory => error.OutOfMemory,
            };
    }
    const arch = try gpa.print("ARCH={t}", .{target});
    if (o.iterate) {
        if (!native) return why.refuse("{s} has no native test plan to iterate", .{o.form});
        if (o.reset and
            o.stop) return why.refuse("--reset and --stop are separate operations", .{});
        if ((o.reset or o.stop) and o.driver != null)
            return why.refuse("--driver cannot accompany --reset or --stop", .{});
        if (o.phase_given and
            o.driver == null) return why.refuse("--phase accompanies --driver", .{});
        const action = if (o.stop)
            "stop"
        else if (o.reset)
            "reset"
        else if (o.driver != null)
            "run"
        else
            "ensure";
        return .{
            .argv = try gpa.dupe([]const u8, &.{
                howl.make_cmd,
                "--no-print-directory",
                arch,
                try gpa.print("ITERATE={s}", .{action}),
                try gpa.print("PHASE={s}", .{o.phase}),
                try gpa.print("DRIVER={s}", .{o.driver orelse ""}),
                try gpa.print("ITERATE_HOWL={s}", .{self}),
                try gpa.print("iterate-{s}", .{o.form}),
            }),
            .note = try gpa.print("iterating {s} on {t}; this SSH VM is not release evidence", .{
                o.form, target,
            }),
        };
    }
    if (o.driver != null or o.phase_given or o.reset or o.stop)
        return why.refuse("--driver, --phase, --reset and --stop require --iterate", .{});
    return .{
        .argv = try gpa.dupe([]const u8, &.{
            howl.make_cmd,
            "--no-print-directory",
            "-k",
            arch,
            try gpa.print(
                "check-{s}{s}",
                .{ if (native) "native-tests-" else "", o.form },
            ),
            try gpa.print("check-shellfree-{s}", .{o.form}),
        }),
        .note = try gpa.print("testing {s} on {t} ({s}); logs in build/{t}/check/", .{
            o.form,
            target,
            // A runtime has no plan of its own: its check boots a hello-world app.
            if (native) "native clients, no DEV" else "a hello-world application",
            target,
        }),
    };
}

const testing = std.testing;

fn checkout(io: Io, tmp: *testing.TmpDir) !void {
    for ([_][]const u8{
        "Makefile",              "test/check-shellfree", "tools/native-tests.zig",
        "forms/caddy/form.yaml",
    }) |path| {
        if (std.fs.path.dirname(path)) |parent| try tmp.dir.createDirPath(io, parent);
        try tmp.dir.writeFile(io, .{ .sub_path = path, .data = "" });
    }
    try tmp.dir.writeFile(io, .{
        .sub_path = "test/form-coverage-exceptions",
        .data = "minimal 0 foundation\n",
    });
}

fn expectArgv(want: []const []const u8, got: Step) !void {
    try testing.expectEqual(want.len, got.argv.len);
    for (want, got.argv) |w, g| try testing.expectEqualStrings(w, g);
}

const plan_text =
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
;

test "howl test runs the form's native checks, or a runtime's hello-world application" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var why: howl.Why = .{};
    try testing.expectError(
        error.Refused,
        decide(io, a, tmp.dir, &.{ "--with", "caddy" }, "howl", &why),
    );
    try testing.expect(mem.find(u8, why.text, "checkout root") != null);
    try checkout(io, &tmp);
    var step = try decide(io, a, tmp.dir, &.{ "--with", "caddy", "--arch", "amd64" }, "howl", &why);
    try expectArgv(&.{
        howl.make_cmd, "--no-print-directory", "-k",
        "ARCH=x86_64", "check-caddy",          "check-shellfree-caddy",
    }, step);
    try testing.expect(mem.find(u8, step.note, "build/x86_64/check/") != null);
    try testing.expect(mem.find(u8, step.note, "a hello-world application") != null);
    step = try decide(io, a, tmp.dir, &.{ "--with=caddy", "--arch=arm64" }, "howl", &why);
    try testing.expectEqualStrings("ARCH=aarch64", step.argv[3]);
    try tmp.dir.createDirPath(io, "forms/caddy/test");
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/caddy/test/tests.yaml", .data = plan_text });
    step = try decide(io, a, tmp.dir, &.{ "--with", "caddy" }, "howl", &why);
    try testing.expectEqualStrings("check-native-tests-caddy", step.argv[4]);
    try testing.expect(mem.find(u8, step.note, "native clients, no DEV") != null);
    // Retired shell checks would no longer run, so they are refused.
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = "forms/caddy/test/checks", .data = "ok retained true\n" },
    );
    try testing.expectError(
        error.Refused,
        decide(io, a, tmp.dir, &.{ "--with", "caddy" }, "howl", &why),
    );
    try testing.expect(mem.find(u8, why.text, "shell checks are retired") != null);
    try tmp.dir.deleteFile(io, "forms/caddy/test/checks");
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = "forms/caddy/test/tests.yaml", .data = "version: 2\nsuites: []\n" },
    );
    try testing.expectError(
        error.Refused,
        decide(io, a, tmp.dir, &.{ "--with", "caddy" }, "howl", &why),
    );
    try testing.expect(mem.find(
        u8,
        why.text,
        "forms/caddy/test/tests.yaml:1: unsupported test plan version",
    ) != null);
}

test "howl test --iterate drives one SSH VM through make with this howl" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try checkout(io, &tmp);
    var why: howl.Why = .{};
    try testing.expectError(
        error.Refused,
        decide(io, a, tmp.dir, &.{ "--with", "caddy", "--iterate" }, "/bin/howl", &why),
    );
    try testing.expect(mem.find(u8, why.text, "no native test plan") != null);
    try tmp.dir.createDirPath(io, "forms/caddy/test");
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/caddy/test/tests.yaml", .data = plan_text });
    const base = [_][]const u8{ "--with", "caddy", "--arch", "arm64", "--iterate" };
    var step = try decide(io, a, tmp.dir, &base, "/bin/howl", &why);
    try expectArgv(&.{
        howl.make_cmd, "--no-print-directory", "ARCH=aarch64",           "ITERATE=ensure",
        "PHASE=seed",  "DRIVER=",              "ITERATE_HOWL=/bin/howl", "iterate-caddy",
    }, step);
    try testing.expect(mem.find(u8, step.note, "not release evidence") != null);
    step = try decide(
        io,
        a,
        tmp.dir,
        &(base ++ [_][]const u8{ "--driver=test-driver", "--phase=verify" }),
        "/bin/howl",
        &why,
    );
    try testing.expectEqualStrings("ITERATE=run", step.argv[3]);
    try testing.expectEqualStrings("PHASE=verify", step.argv[4]);
    try testing.expectEqualStrings("DRIVER=test-driver", step.argv[5]);
    step = try decide(io, a, tmp.dir, &(base ++ [_][]const u8{"--reset"}), "/bin/howl", &why);
    try testing.expectEqualStrings("ITERATE=reset", step.argv[3]);
    step = try decide(io, a, tmp.dir, &(base ++ [_][]const u8{"--stop"}), "/bin/howl", &why);
    try testing.expectEqualStrings("ITERATE=stop", step.argv[3]);
    for ([_][]const []const u8{
        &(base ++ [_][]const u8{ "--reset", "--stop" }),
        &(base ++ [_][]const u8{ "--reset", "--driver", "x" }),
        &(base ++ [_][]const u8{ "--phase", "verify" }),
        &(base ++ [_][]const u8{"--iterate"}),
    }) |args| try testing.expectError(
        error.Refused,
        decide(io, a, tmp.dir, args, "/bin/howl", &why),
    );
}

test "howl test refuses what it cannot run before running anything" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try checkout(io, &tmp);
    for ([_][]const []const u8{
        &.{},
        &.{"--with"},
        &.{"caddy"},
        &.{ "--with", "missing" },
        &.{ "--with", "caddy,sshd" },
        &.{ "--with", "../caddy" },
        &.{ "--with", "caddy", "--with", "caddy" },
        &.{ "--with", "caddy", "--arch", "riscv64" },
        &.{ "--with", "caddy", "--arch", "arm64", "--arch", "amd64" },
        &.{ "--with", "caddy", "--on", "qemu" },
        &.{ "--with", "caddy", "--iterate" },
        &.{ "--with", "caddy", "--driver", "test-driver" },
        &.{ "--with", "caddy", "--reset" },
        &.{ "--with", "caddy", "--phase", "verify" },
        &.{ "--with", "caddy", "--iterate", "--reset", "--stop" },
        &.{ "--with", "caddy", "--phase", "later" },
        &.{ "--with", "caddy", "--driver", "Bad" },
    }) |args| {
        var why: howl.Why = .{};
        if (decide(io, a, tmp.dir, args, "howl", &why)) |step| {
            std.debug.print(
                "ran {s} with {d} arguments\n",
                .{ step.argv[step.argv.len - 1], args.len },
            );
            return error.TestExpectedError;
        } else |err| try testing.expectEqual(error.Refused, err);
    }
}
