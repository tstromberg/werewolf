//! Run a checkout's existing form checks with their output, logs and exit status.
const std = @import("std");
const forms = @import("form");
const howl = @import("howl.zig");

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
    for (args) |arg| if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
        howl.say(io, "{s}", .{syntax});
        return;
    };
    var form: ?[]const u8 = null;
    var arch: ?howl.Arch = null;
    var iterate = false;
    var reset = false;
    var stop = false;
    var driver: ?[]const u8 = null;
    var phase: []const u8 = "seed";
    var phase_given = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--iterate")) {
            if (iterate) return why.refuse("--iterate given twice", .{});
            iterate = true;
            continue;
        }
        if (std.mem.eql(u8, args[i], "--reset")) {
            if (reset) return why.refuse("--reset given twice", .{});
            reset = true;
            continue;
        }
        if (std.mem.eql(u8, args[i], "--stop")) {
            if (stop) return why.refuse("--stop given twice", .{});
            stop = true;
            continue;
        }
        const flag, const value = try howl.flagValue(args, &i, why);
        if (std.mem.eql(u8, flag, "--with")) {
            if (form != null) return why.refuse("--with given twice; test one form at a time", .{});
            if (!forms.isName(value)) return why.refuse("--with needs one existing form name", .{});
            form = value;
        } else if (std.mem.eql(u8, flag, "--arch")) {
            if (arch != null) return why.refuse("--arch given twice", .{});
            arch = howl.archName(value) orelse return why.refuse(howl.arch_refusal, .{value});
        } else if (std.mem.eql(u8, flag, "--driver")) {
            if (driver != null) return why.refuse("--driver given twice", .{});
            if (!forms.isName(value)) return why.refuse("--driver needs one test driver name", .{});
            driver = value;
        } else if (std.mem.eql(u8, flag, "--phase")) {
            if (phase_given) return why.refuse("--phase given twice", .{});
            if (!std.mem.eql(u8, value, "seed") and !std.mem.eql(u8, value, "verify"))
                return why.refuse("--phase is seed or verify", .{});
            phase = value;
            phase_given = true;
        } else return why.refuse("{s}: unsupported test option\n{s}", .{ flag, syntax });
    }
    const name = form orelse return why.refuse("no form\n{s}", .{syntax});
    const target = arch orelse try howl.localArch(why);
    for ([_][]const u8{
        "Makefile", "test/check-form", "test/check-shellfree", "test/native-iterate",
    }) |path|
        std.Io.Dir.cwd().access(io, path, .{}) catch
            return why.refuse(
                "howl test needs a werewolf checkout; run it from the checkout root",
                .{},
            );
    const manifest = try gpa.print("forms/{s}/form.yaml", .{name});
    std.Io.Dir.cwd().access(io, manifest, .{}) catch
        return why.refuse("no {s}; test one form from this checkout", .{manifest});
    var legacy = false;
    const native = blk: {
        const path = try gpa.print("forms/{s}/test/native.json", .{name});
        const yaml_path = try gpa.print("forms/{s}/test/tests.yaml", .{name});
        const yaml = if (std.Io.Dir.cwd().access(io, yaml_path, .{})) true else |err| blk2: {
            if (err != error.FileNotFound) return err;
            break :blk2 false;
        };
        if (!yaml) std.Io.Dir.cwd().access(io, path, .{}) catch |err| {
            if (err == error.FileNotFound) break :blk false;
            return err;
        };
        const result = try std.process.run(gpa, io, .{
            .argv = &.{ "python3", "test/native-tests", "describe", name, @tagName(target) },
            .stdout_limit = .limited(64 << 10),
            .stderr_limit = .limited(64 << 10),
        });
        if (result.term != .exited or result.term.exited != 0)
            return why.refuse("{s}: {s}", .{ if (yaml) yaml_path else path, result.stderr });
        const raw = result.stdout;
        const plan = std.json.parseFromSliceLeaky(
            struct { legacy: bool = false },
            gpa,
            raw,
            .{ .ignore_unknown_fields = true },
        ) catch
            return why.refuse("invalid native test plan: {s}", .{path});
        legacy = plan.legacy;
        break :blk true;
    };
    if (iterate) {
        if (!native) return why.refuse("{s} has no native test plan to iterate", .{name});
        if (reset and stop) return why.refuse("--reset and --stop are separate operations", .{});
        if ((reset or stop) and driver != null)
            return why.refuse("--driver cannot accompany --reset or --stop", .{});
        if (phase_given and driver == null) return why.refuse("--phase accompanies --driver", .{});
        const action: []const u8 = if (stop)
            "stop"
        else if (reset)
            "reset"
        else if (driver != null)
            "run"
        else
            "ensure";
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(gpa, &.{
            "python3",
            "test/native-iterate",
            try std.process.executablePathAlloc(io, gpa),
            name,
            try gpa.print("{t}", .{target}),
            action,
            phase,
        });
        if (driver) |selected| try argv.append(gpa, selected);
        var env = try howl.environ.clone(gpa);
        defer env.deinit();
        for ([_][]const u8{ "MAKEFLAGS", "MFLAGS", "MAKELEVEL" }) |key| _ = env.swapRemove(key);
        howl.say(
            io,
            "iterating {s} on {t}; this SSH VM is not release evidence",
            .{ name, target },
        );
        const err = std.process.replace(io, .{ .argv = argv.items, .environ_map = &env });
        return why.refuse("python3: {s}", .{@errorName(err)});
    }
    if (driver != null or phase_given or reset or stop)
        return why.refuse("--driver, --phase, --reset and --stop require --iterate", .{});
    const argv = &.{
        howl.make_cmd,
        "--no-print-directory",
        "-k",
        try gpa.print("ARCH={t}", .{target}),
        try gpa.print("check-{s}{s}", .{ if (native and !legacy) "native-tests-" else "", name }),
        try gpa.print("check-shellfree-{s}", .{name}),
    };
    // An outer make's dry-run flags or command-line overrides must not turn
    // a test invocation into a successful run that never executes its checks.
    var env = try howl.environ.clone(gpa);
    defer env.deinit();
    for ([_][]const u8{ "MAKEFLAGS", "MFLAGS", "MAKELEVEL" }) |key| _ = env.swapRemove(key);
    howl.say(io, "testing {s} on {t} ({s}); logs in build/{t}/check/", .{
        name,   target,
        if (native and legacy)
            "native clients plus legacy DEV checks"
        else if (native)
            "native clients, no DEV"
        else
            "legacy DEV checks",
        target,
    });
    const err = std.process.replace(io, .{ .argv = argv, .environ_map = &env });
    return why.refuse("{s}: {s}", .{ howl.make_cmd, @errorName(err) });
}
