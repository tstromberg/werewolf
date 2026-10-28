//! native-tests builds and runs a form's shell-free integration clients:
//! it generates a test form beside the production one, checks the test
//! image changed no production policy, account or runtime byte, boots it
//! twice on one data disk, and accepts only complete, fresh transcripts.
//! iterate keeps one SSH VM for editing one suite. See test/native/README.md.

const std = @import("std");
const forms = @import("form");
const plans = @import("test-plan");
const iteration = @import("native-iterate.zig");
const payload = @import("native-compare.zig");
const hosts = @import("native-ssh.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const mem = std.mem;

const usage = "usage: native-tests describe|prepare|compare FORM ARCH\n" ++
    "       native-tests run FORM ARCH QEMU...\n" ++
    "       native-tests boot FORM ARCH seed|verify NAME QEMU...\n" ++
    "       native-tests iterate HOWL FORM ARCH ensure|reset|stop|run PHASE [DRIVER]";

pub const platform_plan = "test/native/platform.yaml";
pub const platform_driver = "test/native/platform.zig";
/// compiled examples' applications are built for the production form; a
/// test form reuses those exact bytes rather than compiling them again.
const compiled_examples = [_][]const u8{ "go-example", "rust-example", "aspnet-example" };
const probe_flags = [_][]const u8{ "-lc", "-O", "ReleaseSafe", "-fstrip", "-fPIE" };

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    var t: Tool = .{ .io = init.io, .gpa = gpa, .env = init.environ_map };
    dispatch(&t, args[1..]) catch |err| {
        std.debug.print(
            "native-tests: {s}\n",
            .{if (err == error.Refused) t.why else @errorName(err)},
        );
        std.process.exit(1);
    };
}

fn dispatch(t: *Tool, args: []const []const u8) !void {
    if (args.len >= 1 and mem.eql(u8, args[0], "iterate")) return iteration.main(t, args[1..]);
    if (args.len < 3) return t.fail("{s}", .{usage});
    const form = try t.ref(args[1]);
    const arch = args[2];
    if (!mem.eql(u8, arch, "aarch64") and !mem.eql(u8, arch, "x86_64"))
        return t.fail("invalid architecture {s}", .{arch});
    const verb = args[0];
    if (mem.eql(u8, verb, "describe") and args.len == 3) {
        // A valid plan lists its suites; an invalid one is refused.
        for ((try t.formPlan(form)).drivers) |d| try t.say("{s}", .{d.name});
    } else if (mem.eql(u8, verb, "prepare") and args.len == 3) {
        try prepare(t, form, arch);
    } else if (mem.eql(u8, verb, "compare") and args.len == 3) {
        try payload.compare(t, form, arch);
    } else if (mem.eql(u8, verb, "run") and args.len > 3) {
        try run(t, form, arch, args[3..]);
    } else if (mem.eql(u8, verb, "boot") and args.len > 5) {
        const phase = std.meta.stringToEnum(plans.Phase, args[3]) orelse
            return t.fail("{s}", .{usage});
        try once(t, form, try t.bootPlan(form), .{}, phase, args[4], args[5..]);
    } else return t.fail("{s}", .{usage});
}

/// Tool holds what every step needs, and why it refused.
pub const Tool = struct {
    io: Io,
    gpa: Allocator,
    env: *const std.process.Environ.Map,
    why: []const u8 = "",

    pub fn fail(t: *Tool, comptime fmt: []const u8, args: anytype) error{ Refused, OutOfMemory } {
        t.why = try t.gpa.print(fmt, args);
        return error.Refused;
    }

    pub fn say(t: *Tool, comptime fmt: []const u8, args: anytype) !void {
        const line = try t.gpa.print(fmt ++ "\n", args);
        try Io.File.stdout().writeStreamingAll(t.io, line);
    }

    /// variable is an environment variable, or null when unset or empty.
    pub fn variable(t: *Tool, name: []const u8) ?[]const u8 {
        const value = t.env.get(name) orelse return null;
        return if (value.len == 0) null else value;
    }

    /// ref reads a form reference: a name in forms/, a path to a form
    /// directory such as examples/unifi-os, or a scenario's directory under
    /// test/scenarios, which boots the stock form its plan names.
    pub fn ref(t: *Tool, text: []const u8) !Form {
        if (mem.findScalar(u8, text, '/') == null) {
            if (!forms.isName(text)) return t.fail("invalid form {s}", .{text});
            const dir = try t.gpa.print("forms/{s}", .{text});
            return .{
                .name = text,
                .ref = text,
                .dir = dir,
                .tests = try t.gpa.print("{s}/test", .{dir}),
            };
        }
        const dir = mem.trimEnd(u8, text, "/");
        var parts = mem.splitScalar(u8, dir, '/');
        while (parts.next()) |part| if (part.len == 0 or mem.eql(u8, part, "..") or
            mem.eql(u8, part, "."))
            return t.fail("invalid form {s}", .{text});
        const name = std.fs.path.basename(dir);
        if (!forms.isName(name)) return t.fail("invalid form {s}", .{text});
        if (mem.startsWith(u8, dir, "test/scenarios/")) {
            var failure: plans.Failure = .{};
            const plan = plans.scenario(t.io, t.gpa, Dir.cwd(), dir, &failure) catch |err|
                return switch (err) {
                    error.Plan => t.fail("{s}", .{failure.text}),
                    error.OutOfMemory => error.OutOfMemory,
                };
            return .{
                .name = try t.gpa.print("scenario-{s}", .{name}),
                .ref = plan.form.?,
                .dir = dir,
                .tests = dir,
                .scenario = true,
            };
        }
        return .{
            .name = name,
            .ref = dir,
            .dir = dir,
            .tests = try t.gpa.print("{s}/test", .{dir}),
        };
    }

    /// formPlan is the form's own validated plan, as iteration runs it.
    pub fn formPlan(t: *Tool, f: Form) !plans.Plan {
        var failure: plans.Failure = .{};
        const loaded = if (f.scenario)
            plans.scenario(t.io, t.gpa, Dir.cwd(), f.dir, &failure)
        else
            plans.form(t.io, t.gpa, Dir.cwd(), f.dir, &failure);
        return loaded catch |err| switch (err) {
            error.Plan => t.fail("{s}", .{failure.text}),
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    /// bootPlan is the clean boot's plan: the form's suites around the
    /// shared checks it does not exclude.
    pub fn bootPlan(t: *Tool, f: Form) !plans.Plan {
        const plan = try t.formPlan(f);
        var failure: plans.Failure = .{};
        const platform = plans.load(t.io, t.gpa, Dir.cwd(), platform_plan, &failure) catch |err|
            return switch (err) {
                error.Plan => t.fail("{s}", .{failure.text}),
                error.OutOfMemory => error.OutOfMemory,
            };
        // A form skips what its missing code rules out; supplied, it answers.
        const skip = if (plan.app != null)
            ""
        else
            try t.output(&.{ "build/host/form", "check", f.ref, "skip" });
        var words: std.ArrayList([]const u8) = .empty;
        var it = mem.tokenizeAny(u8, skip, " \t\n");
        while (it.next()) |word| try words.append(t.gpa, word);
        try words.appendSlice(t.gpa, plan.skip);
        return plans.boot(t.gpa, plan, platform, words.items, &failure) catch |err| switch (err) {
            error.Plan => t.fail("{s}", .{failure.text}),
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    fn selectedCommand(t: *Tool, argv: []const []const u8) ![]const []const u8 {
        const selection = t.variable("VARIANTS") orelse return argv;
        const program = std.fs.path.basename(argv[0]);
        if (!mem.eql(u8, program, "form") and !mem.eql(u8, program, "howl")) return argv;
        return mem.concat(t.gpa, []const u8, &.{ argv, &.{ "--variant", selection } });
    }

    /// call runs argv and refuses unless it exits 0.
    pub fn call(t: *Tool, argv: []const []const u8, options: Call) !void {
        var child = try std.process.spawn(t.io, .{
            .argv = try t.selectedCommand(argv),
            .environ_map = options.env orelse t.env,
            .stdout = if (options.log) |log| .{ .file = log } else .inherit,
            .stderr = if (options.log) |log| .{ .file = log } else .inherit,
            .stdin = .ignore,
        });
        const term = try child.wait(t.io);
        if (term != .exited or term.exited != 0)
            return t.fail("{s} failed: {f}", .{ argv[0], fmtTerm(term) });
    }

    /// output is what argv prints, refusing unless it exits 0.
    pub fn output(t: *Tool, argv: []const []const u8) ![]const u8 {
        const result = try std.process.run(t.gpa, t.io, .{
            .argv = try t.selectedCommand(argv),
            .environ_map = t.env,
            .stdout_limit = .limited(16 << 20),
            .stderr_limit = .limited(1 << 20),
        });
        if (result.term != .exited or result.term.exited != 0)
            return t.fail("{s} failed: {s}", .{ argv[0], mem.trimEnd(u8, result.stderr, "\n") });
        return result.stdout;
    }

    /// write writes data at path, making its directories.
    pub fn write(t: *Tool, path: []const u8, data: []const u8) !void {
        if (std.fs.path.dirname(path)) |parent| try Dir.cwd().createDirPath(t.io, parent);
        try Dir.cwd().writeFile(t.io, .{ .sub_path = path, .data = data });
    }
};

/// Call runs a child with env, by default the tool's own, and its output
/// to log, by default the tool's.
pub const Call = struct { env: ?*const std.process.Environ.Map = null, log: ?Io.File = null };

pub const Form = struct {
    /// name is the form's name, the last part of its directory, and for a
    /// scenario scenario-NAME.
    name: []const u8,
    /// ref is how howl and build/host/form name it, a scenario's stock form.
    ref: []const u8,
    dir: []const u8,
    /// tests holds its tests.yaml, config hooks and driver sources.
    tests: []const u8,
    scenario: bool = false,
};

fn fmtTerm(term: std.process.Child.Term) std.fmt.Alt(std.process.Child.Term, formatTerm) {
    return .{ .data = term };
}

fn formatTerm(term: std.process.Child.Term, w: *Io.Writer) Io.Writer.Error!void {
    switch (term) {
        .exited => |code| try w.print("exit {d}", .{code}),
        .signal => |signal| try w.print("signal {d}", .{@backingInt(signal)}),
        else => try w.writeAll("abnormal exit"),
    }
}

fn prepare(t: *Tool, f: Form, arch: []const u8) !void {
    const io = t.io;
    const gpa = t.gpa;
    const plan = try t.bootPlan(f);
    const selected = if (t.variable("VARIANTS")) |names|
        try gpa.print("/variants-{s}", .{names})
    else
        "";
    const work = try gpa.print("build/native-tests/{s}{s}/{s}", .{ arch, selected, f.name });
    const generated = try gpa.print("{s}/native-test-{s}", .{ work, f.name });
    const root = try gpa.print("{s}/rootfs", .{generated});
    // This directory is exclusively generated test output; clear stale drivers.
    try Dir.cwd().deleteTree(io, generated);
    const baseline = t.variable("PRODUCTION_OUT");
    const pins = if (baseline) |b|
        try payload.productionPins(t, try gpa.print("{s}/rootfs.tar", .{b}))
    else
        &.{};
    if (compiled(f.name) and baseline == null)
        return t.fail("compiled native tests need PRODUCTION_OUT", .{});
    if (baseline) |b| {
        try applicationOverlay(t, f.name, b, root);
        try payload.commandLinks(t, b, root);
    }
    try t.write(try gpa.print("{s}/form.yaml", .{generated}), try formConfig(t, f, plan, pins));
    try t.write(
        try gpa.print("{s}/usr/share/werewolf/test-image", .{root}),
        "werewolf-native-tests/1\n",
    );
    try runtimeGrants(t, root, plan.drivers);
    const compile_dir = try gpa.print("{s}/compile", .{work});
    try t.write(try gpa.print("{s}/stage.zig", .{compile_dir}), try Dir.cwd().readFileAlloc(
        io,
        "test/native/stage.zig",
        gpa,
        .limited(1 << 20),
    ));
    try t.write(try gpa.print("{s}/plan.json", .{compile_dir}), try stagePlan(gpa, plan));
    const transport = has(plan.packages, "libcurl-openssl4");
    try compile(t, arch, try gpa.print("{s}/stage.zig", .{compile_dir}), try gpa.print(
        "{s}/usr/lib/werewolf/test-stage",
        .{root},
    ), false);
    try Dir.cwd().createDirPath(io, try gpa.print("{s}/etc/runit", .{root}));
    try Dir.cwd().symLink(io, "/usr/lib/werewolf/test-stage", try gpa.print(
        "{s}/etc/runit/2",
        .{root},
    ), .{});
    for (plan.drivers) |d| {
        const binary = try gpa.print("{s}/usr/lib/werewolf/{s}", .{ root, d.name });
        const tests = try gpa.print("{s}/usr/share/werewolf/tests/{s}", .{ root, d.name });
        if (d.probes) |probes| {
            try Dir.cwd().createDirPath(io, std.fs.path.dirname(binary).?);
            try Dir.cwd().copyFile(try probeBinary(t, arch), Dir.cwd(), binary, io, .{
                .permissions = .fromMode(0o755),
            });
            try t.write(try gpa.print("{s}/probes.json", .{tests}), try plans.json(gpa, probes));
        } else {
            var source = try gpa.print("{s}/{s}", .{ f.tests, d.source });
            if (has(&plans.reserved, d.name)) {
                // The shared checks compile with their phase's cases embedded.
                source = try gpa.print("{s}/{s}/platform.zig", .{ compile_dir, d.name });
                try t.write(
                    source,
                    try Dir.cwd().readFileAlloc(io, platform_driver, gpa, .limited(1 << 20)),
                );
                try t.write(
                    try gpa.print("{s}/{s}/platform.json", .{ compile_dir, d.name }),
                    try std.json.Stringify.valueAlloc(
                        gpa,
                        .{ .seed = d.seed, .verify = d.verify },
                        .{},
                    ),
                );
            }
            try compile(t, arch, source, binary, transport);
        }
        try t.write(try gpa.print("{s}/service", .{tests}), try service(gpa, d, .clean));
    }
    try t.say("native-tests: prepared {s}", .{generated});
}

fn compiled(name: []const u8) bool {
    return has(&compiled_examples, name);
}

pub fn has(names: []const []const u8, name: []const u8) bool {
    for (names) |n| if (mem.eql(u8, n, name)) return true;
    return false;
}

/// stagePlan is what test-stage embeds: each driver's launch and the
/// production paths it must wait for.
fn stagePlan(gpa: Allocator, plan: plans.Plan) ![]const u8 {
    const Start = struct {
        name: []const u8,
        mode: []const u8,
        root: bool,
        wait: []const []const u8,
        readiness: bool,
        phases: []const []const u8,
    };
    var drivers: std.ArrayList(Start) = .empty;
    for (plan.drivers) |d| {
        var phases: std.ArrayList([]const u8) = .empty;
        if (d.seed.len > 0) try phases.append(gpa, "seed");
        if (d.verify.len > 0) try phases.append(gpa, "verify");
        try drivers.append(gpa, .{
            .name = d.name,
            .mode = d.mode,
            .root = mem.eql(u8, d.user, "root"),
            .wait = try waitPaths(gpa, d),
            .readiness = d.readiness,
            .phases = phases.items,
        });
    }
    return std.json.Stringify.valueAlloc(
        gpa,
        .{ .drivers = drivers.items },
        .{ .whitespace = .indent_2 },
    );
}

/// waitPaths are the driver's grants production startup creates. Landlock
/// binds inodes before the client starts, so the stage waits for them.
pub fn waitPaths(gpa: Allocator, d: plans.Driver) ![]const []const u8 {
    var paths: std.ArrayList([]const u8) = .empty;
    for ([_][]const []const u8{ d.read, d.connect }) |grants| for (grants) |p| {
        for ([_][]const u8{
            "/run/svc/",
            "/run/cgroup/svc/",
            "/data/share/",
            "/data/svc/",
        }) |prefix| {
            if (mem.startsWith(u8, p, prefix) and !has(paths.items, p)) try paths.append(gpa, p);
        }
    };
    mem.sort([]const u8, paths.items, {}, lessThan);
    return paths.items;
}

pub fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return mem.lessThan(u8, a, b);
}

pub const Launch = enum { clean, iterate };

/// service is the driver's leash descriptor. Iteration reads its context
/// and uploaded probe data from paths the clean image never has.
pub fn service(gpa: Allocator, d: plans.Driver, launch: Launch) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.print(gpa, "exec /usr/lib/werewolf/{s} {s} {s} /run/svc/{s}/context\n", .{
        d.name, d.name, d.mode, d.name,
    });
    try out.print(gpa, "user {s}\npledge {s}\nconfig context {s}\nmemory {d}\nnofile 128\n", .{
        d.user,
        d.pledge,
        switch (launch) {
            .clean => "/run/config/tests/context",
            .iterate => "/run/config/native-iterate-context",
        },
        d.memory,
    });
    if (launch == .iterate and d.probes != null)
        try out.print(gpa, "read /run/howl-dev/{s}.json\n", .{d.name});
    for ([_][]const u8{
        "read",
        "connect",
        "run",
    }, [_][]const []const u8{ d.read, d.connect, d.run }) |field, grants|
        for (grants) |g| try out.print(gpa, "{s} {s}\n", .{ field, g });
    for (d.config) |c| try out.print(gpa, "config {s} {s}\n", .{ c.name, c.path });
    for (d.groups) |g| try out.print(gpa, "group {s}\n", .{g});
    return out.items;
}

/// runtimeGrants lets only the declared driver use a runtime's native code.
pub fn runtimeGrants(t: *Tool, root: []const u8, drivers: []const plans.Driver) !void {
    for (drivers) |d| for (d.allow) |grant| {
        const colon = mem.findScalar(u8, grant, ':').?;
        try t.write(try t.gpa.print("{s}/etc/runtime-hardening/allow/{s}/{s}/{s}", .{
            root, d.name, grant[0..colon], grant[colon + 1 ..],
        }), "");
    };
}

/// formConfig is the generated test form: the production form, its exact
/// package versions, and the check settings and weaknesses generated forms
/// do not inherit, notably Greenbone's memory budget and offline forms.
pub fn formConfig(t: *Tool, f: Form, plan: plans.Plan, pins: []const []const u8) ![]const u8 {
    const gpa = t.gpa;
    var out: std.ArrayList(u8) = .empty;
    // Written as the harness always has, so existing test locks still match.
    if (t.variable("VARIANTS") != null) {
        var failure: forms.Failure = .{};
        const production = try forms.load(t.io, gpa, Dir.cwd(), f.ref, &failure);
        if (production.spec.get("variants")) |definitions| {
            var text: Io.Writer.Allocating = .init(gpa);
            try forms.write(
                &text.writer,
                .{ .map = &.{.{ .key = "variants", .value = definitions }} },
            );
            try out.appendSlice(gpa, text.written());
        }
    }
    try out.print(gpa, "base: {s}\npackages: [", .{f.ref});
    for (try mem.concat(gpa, []const u8, &.{ pins, plan.packages }), 0..) |p, i|
        try out.print(gpa, "{s}\"{s}\"", .{ if (i > 0) ", " else "", p });
    try out.appendSlice(gpa, "]\n");
    if (plan.prune.len > 0) {
        try out.appendSlice(gpa, "prune: [");
        for (plan.prune, 0..) |p, i| {
            if (i > 0) try out.appendSlice(gpa, ", ");
            try out.print(gpa, "\"{s}\"", .{p});
        }
        try out.appendSlice(gpa, "]\n");
    }
    const memory = mem.trim(
        u8,
        try t.output(&.{ "build/host/form", "check", f.ref, "memory" }),
        " \n",
    );
    const offline = mem.trim(
        u8,
        try t.output(&.{ "build/host/form", "check", f.ref, "offline" }),
        " \n",
    );
    if (memory.len > 0 or mem.eql(u8, offline, "true")) {
        try out.appendSlice(gpa, "check:\n");
        if (memory.len > 0) {
            _ = std.fmt.parseInt(
                u32,
                memory,
                10,
            ) catch return t.fail("invalid check memory {s}", .{memory});
            try out.print(gpa, "  memory: {s}\n", .{memory});
        }
        if (mem.eql(u8, offline, "true")) try out.appendSlice(gpa, "  offline: true\n");
    }
    const excuses = try t.output(&.{ "build/host/form", "excuses", f.ref });
    if (mem.trim(u8, excuses, " \n").len > 0) {
        try out.appendSlice(gpa, "weaknesses:\n");
        var lines = mem.tokenizeScalar(u8, excuses, '\n');
        while (lines.next()) |line| {
            const space = mem.findScalar(
                u8,
                line,
                ' ',
            ) orelse return t.fail("invalid excuse {s}", .{line});
            try out.print(gpa, "  {s}: \"", .{line[0..space]});
            for (line[space + 1 ..]) |c| {
                if (c == '"' or c == '\\') try out.append(gpa, '\\');
                try out.append(gpa, c);
            }
            try out.appendSlice(gpa, "\"\n");
        }
    }
    return out.items;
}

/// applicationOverlay copies a compiled example's production application:
/// its generated form has another name, so the builder compiles nothing
/// for it, and compiling again could change .NET metadata.
pub fn applicationOverlay(
    t: *Tool,
    name: []const u8,
    baseline: []const u8,
    root: []const u8,
) !void {
    if (!compiled(name)) return;
    const io = t.io;
    const source = try t.gpa.print("{s}/application", .{baseline});
    var dir = Dir.cwd().openDir(io, source, .{ .iterate = true }) catch
        return t.fail("missing compiled production application: {s}", .{source});
    defer dir.close(io);
    try Dir.cwd().createDirPath(io, root);
    var walker = try dir.walk(t.gpa);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        const target = try t.gpa.print("{s}/{s}", .{ root, entry.path });
        switch (entry.kind) {
            .directory => try Dir.cwd().createDirPath(io, target),
            .sym_link => {
                var buffer: [Dir.max_path_bytes]u8 = undefined;
                const link = buffer[0..try dir.readLink(io, entry.path, &buffer)];
                try Dir.cwd().symLink(io, link, target, .{});
            },
            .file => try dir.copyFile(entry.path, Dir.cwd(), target, io, .{}),
            else => return t.fail("{s}/{s}: not a file or directory", .{ source, entry.path }),
        }
    }
}

/// probeBinary is the shared probe runner for arch, built once per source
/// digest. The flags are in the digest: one built otherwise is not this one.
pub fn probeBinary(t: *Tool, arch: []const u8) ![]const u8 {
    const io = t.io;
    const gpa = t.gpa;
    const target = try gpa.print("{s}-linux-gnu", .{arch});
    var sources: std.ArrayList([]const u8) = .empty;
    var dir = try Dir.cwd().openDir(io, "test/native", .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |entry| if (entry.kind == .file and
        mem.endsWith(u8, entry.name, ".zig"))
        try sources.append(gpa, try gpa.print("test/native/{s}", .{entry.name}));
    mem.sort([]const u8, sources.items, {}, lessThan);
    try sources.append(gpa, "test/native/regex.c");
    var identity = Sha256.init(.{});
    identity.update(target);
    for (probe_flags) |flag| identity.update(flag);
    identity.update(try t.output(&.{ "zig", "version" }));
    for (sources.items) |path| identity.update(&try digest(io, path));
    const hex = std.fmt.bytesToHex(identity.finalResult(), .lower);
    const cache = try gpa.print("build/test-probes/{s}-{s}", .{ arch, hex[0..20] });
    const binary = try gpa.print("{s}/test-probes", .{cache});
    try Dir.cwd().createDirPath(io, cache);
    const lock = try Dir.cwd().createFile(
        io,
        try gpa.print("{s}/lock", .{cache}),
        .{ .truncate = false },
    );
    defer lock.close(io);
    try lock.lock(io, .exclusive);
    if (Dir.cwd().access(io, binary, .{})) |_| return binary else |_| {}
    const temporary = try gpa.print("{s}/test-probes.new", .{cache});
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{ "zig", "build-exe" });
    try argv.appendSlice(gpa, &probe_flags);
    try argv.appendSlice(gpa, &.{
        "-target",                                     target,
        "test/native/probes.zig",                      "test/native/regex.c",
        try gpa.print("-femit-bin={s}", .{temporary}),
    });
    try t.call(argv.items, .{});
    try Dir.cwd().rename(temporary, Dir.cwd(), binary, io);
    return binary;
}

/// compile builds a driver for the guest against test/native/driver.zig;
/// libcurl's transport needs glibc, everything else is static musl.
pub fn compile(
    t: *Tool,
    arch: []const u8,
    source: []const u8,
    binary: []const u8,
    transport: bool,
) !void {
    if (std.fs.path.dirname(binary)) |parent| try Dir.cwd().createDirPath(t.io, parent);
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(t.gpa, &.{
        "zig",
        "build-exe",
        "-O",
        "ReleaseSafe",
        "-fstrip",
        "-fPIE",
        "-target",
        try t.gpa.print("{s}-linux-{s}", .{ arch, if (transport) "gnu" else "musl" }),
    });
    if (transport) try argv.append(t.gpa, "-lc");
    try argv.appendSlice(t.gpa, &.{
        "--dep",                                      "test-driver",
        try t.gpa.print("-Mroot={s}", .{source}),     "-Mtest-driver=test/native/driver.zig",
        try t.gpa.print("-femit-bin={s}", .{binary}),
    });
    try t.call(argv.items, .{});
}

pub fn digest(io: Io, path: []const u8) ![Sha256.digest_length]u8 {
    const file = try Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var buffer: [64 << 10]u8 = undefined;
    var reader = file.reader(io, &.{});
    var hash = Sha256.init(.{});
    while (true) {
        const n = reader.interface.readSliceShort(&buffer) catch return error.ReadFailed;
        if (n == 0) break;
        hash.update(buffer[0..n]);
    }
    return hash.finalResult();
}

pub fn hexDigest(io: Io, path: []const u8) ![64]u8 {
    return std.fmt.bytesToHex(try digest(io, path), .lower);
}

const Input = struct { name: []const u8, path: []const u8, digest: [64]u8 = undefined };

fn run(t: *Tool, f: Form, arch: []const u8, qemu: []const []const u8) !void {
    try runPlan(t, f, try t.bootPlan(f), arch, qemu, .{});
}

/// Harness is what runPlan boots with, and the shared plan it hashes.
const Harness = struct {
    /// boot judges a machine with no shell from its console (test/console.zig).
    boot: []const u8 = "build/host/console",
    platform_plan: []const u8 = platform_plan,
    platform_driver: []const u8 = platform_driver,
};

/// runPlan boots the test image twice on one data disk and accepts each
/// phase's transcript, recording what the run was made of.
fn runPlan(
    t: *Tool,
    f: Form,
    plan: plans.Plan,
    arch: []const u8,
    qemu: []const []const u8,
    harness: Harness,
) !void {
    const io = t.io;
    const gpa = t.gpa;
    const out = t.variable("OUT") orelse return t.fail("OUT names the test image", .{});
    const kernel = t.variable("KERNEL") orelse return t.fail("KERNEL names the kernel", .{});
    const check = t.variable("CHECK") orelse return t.fail("CHECK names the check directory", .{});
    // A scenario may leave the address off the kernel command line (BOOT has
    // none), for init to take it from the config or DHCP.
    const cmdline = if (plan.kernel_address)
        t.env.get("CMDLINE") orelse ""
    else
        t.variable("BOOT") orelse
            return t.fail("BOOT names the kernel command line without an address", .{});
    const production = t.variable("PRODUCTION_OUT") orelse
        try gpa.print("{s}/{s}", .{ std.fs.path.dirname(out) orelse ".", f.name });
    var inputs: std.ArrayList(Input) = .empty;
    try inputs.appendSlice(gpa, &.{
        .{ .name = "kernel", .path = kernel },
        .{ .name = "image", .path = try gpa.print("{s}/initramfs.zst", .{out}) },
        .{ .name = "production_image", .path = try gpa.print("{s}/initramfs.zst", .{production}) },
        .{ .name = "plan", .path = try gpa.print("{s}/tests.yaml", .{f.tests}) },
        .{ .name = "platform_plan", .path = harness.platform_plan },
        .{ .name = "platform_driver", .path = harness.platform_driver },
    });
    const fixtures = [2][]const u8{
        try gpa.print("{s}/config", .{f.tests}),
        try gpa.print("{s}/config-again", .{f.tests}),
    };
    for (fixtures, [_][]const u8{ "seed_config", "verify_config" }) |path, name| {
        Dir.cwd().access(io, path, .{}) catch continue;
        try inputs.append(gpa, .{ .name = name, .path = path });
    }
    for (inputs.items) |*input| input.digest = try hexDigest(io, input.path);
    const w = try freshWork(t, check, f.name, f);
    const disk = try gpa.print("{s}/data.img", .{w.dir});
    {
        const file = try Dir.cwd().createFile(io, disk, .{ .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.setLength(io, 4 << 30);
    }
    var run_bytes: [16]u8 = undefined;
    try io.randomSecure(&run_bytes);
    const run_id = std.fmt.bytesToHex(run_bytes, .lower);
    const ssh: ?hosts.Ssh = if (plan.host.len > 0)
        try hosts.setup(t, plan, f, w.dir, w.config, &run_id)
    else
        null;
    const machine = if (ssh) |s| try hosts.forwarded(t, qemu, s.port) else qemu;
    if (ssh != null) try inputs.append(gpa, .{
        .name = "host_runner",
        .path = hosts.runner,
        .digest = try hexDigest(io, hosts.runner),
    });
    const b: Booting = .{
        .f = f,
        .plan = plan,
        .harness = harness,
        .name = f.name,
        .run_id = &run_id,
        .work = w,
        .ssh = ssh,
        .inputs = inputs.items,
    };
    var results: std.ArrayList(Result) = .empty;
    for ([_]plans.Phase{ .seed, .verify }, fixtures) |phase, fixture| {
        const result = try boot(t, b, phase, fixture, try mem.concat(gpa, []const u8, &.{
            machine,
            &.{
                "-kernel", kernel,
                "-initrd", try gpa.print("{s}/initramfs.zst", .{out}),
                "-append", try gpa.print("{s} werewolf.data=vda", .{cmdline}),
                "-drive",  try gpa.print("file={s},format=raw,if=virtio", .{disk}),
            },
        }));
        try results.append(gpa, result);
    }
    var report: Io.Writer.Allocating = .init(gpa);
    var json: std.json.Stringify = .{
        .writer = &report.writer,
        .options = .{ .whitespace = .indent_2 },
    };
    try json.beginObject();
    for ([_][2][]const u8{
        .{ "format", "werewolf-native-results/1" }, .{ "form", f.name },          .{ "arch", arch },
        .{ "run", &run_id },                        .{ "profile", "local-qemu" },
    }) |field| {
        try json.objectField(field[0]);
        try json.write(field[1]);
    }
    try json.objectField("timeout_seconds");
    try json.write(plan.timeout_seconds);
    for (inputs.items) |input| {
        try json.objectField(input.name);
        try json.write(&input.digest);
    }
    try json.objectField("phases");
    try json.write(results.items);
    try json.endObject();
    try report.writer.writeByte('\n');
    try t.write(try gpa.print("{s}/results.json", .{w.dir}), report.written());
}

/// Work is a run's directory under CHECK, its config directory, and the
/// digest of the data key that holds, unless the config is a check's own.
const Work = struct { dir: []const u8, config: []const u8, key_path: []const u8, key: ?[64]u8 };

/// freshWork makes a run's directory anew, as CHECK/NAME-native, with f's
/// config directory and a new data key in it.
fn freshWork(t: *Tool, check: []const u8, name: []const u8, f: Form) !Work {
    const io = t.io;
    const gpa = t.gpa;
    const dir = try gpa.print("{s}/{s}-native", .{ check, name });
    try Dir.cwd().deleteTree(io, dir);
    try Dir.cwd().createDirPath(io, check);
    try Dir.cwd().createDir(io, dir, .fromMode(0o700));
    // Named as check-form names it: a form's test/config finds the run's
    // key file beside it, as FORM-key.pub.
    const config = try gpa.print("{s}/{s}-config", .{ dir, f.name });
    try Dir.cwd().createDir(io, config, .fromMode(0o700));
    const key_path = try gpa.print("{s}/data.key", .{config});
    var key: [32]u8 = undefined;
    try io.randomSecure(&key);
    try Dir.cwd().writeFile(
        io,
        .{ .sub_path = key_path, .data = &key, .flags = .{ .permissions = .fromMode(0o600) } },
    );
    return .{
        .dir = dir,
        .config = config,
        .key_path = key_path,
        .key = try hexDigest(io, key_path),
    };
}

/// Result is one boot's: its phase, how many assertions held, and its
/// transcript and that transcript's digest.
const Result = struct { phase: []const u8, cases: usize, log: []const u8, sha256: []const u8 };

/// Booting is what a run's boots share.
const Booting = struct {
    f: Form,
    plan: plans.Plan,
    harness: Harness,
    /// name is the machine's in its logs: the form's, or a check's.
    name: []const u8,
    run_id: []const u8,
    work: Work,
    ssh: ?hosts.Ssh = null,
    /// inputs must be as they were when the run began.
    inputs: []const Input = &.{},
    /// context, if set, is the file the run's context goes to, for the check
    /// to deliver itself: the machine then gets no config disk.
    context: ?[]const u8 = null,
};

/// boot makes phase's config, with fixture if there is one, packs it, boots
/// machine with it as a read-only disk, and accepts the phase's transcript.
/// A check that delivers the context itself (Booting.context) gets no disk.
fn boot(
    t: *Tool,
    b: Booting,
    phase: plans.Phase,
    fixture: []const u8,
    machine: []const []const u8,
) !Result {
    const io = t.io;
    const gpa = t.gpa;
    const plan = b.plan;
    const w = b.work;
    const howl = t.variable("HOWL") orelse return t.fail("HOWL names howl", .{});
    if (Dir.cwd().access(io, fixture, .{})) |_|
        try t.call(&.{ fixture, w.config }, .{})
    else |_| {}
    if (w.key) |key| if (!mem.eql(u8, &try hexDigest(io, w.key_path), &key))
        return t.fail("test configuration replaced the data key", .{});
    const context: Run = .{
        .run = b.run_id,
        .phase = @tagName(phase),
        .timeout_seconds = plan.timeout_seconds,
    };
    const context_json = try std.json.Stringify.valueAlloc(gpa, context, .{});
    var disk: []const []const u8 = &.{};
    if (b.context) |path| {
        try t.write(path, context_json);
    } else {
        try t.write(try gpa.print("{s}/tests/context", .{w.config}), context_json);
        const packed_path = try gpa.print("{s}/{s}.tar", .{ w.dir, @tagName(phase) });
        // A boot without data.key packs its config without it, held outside
        // it, and puts it back for the next (scenario.zig, Boot).
        const without_key = !switch (phase) {
            .seed => plan.boots.seed,
            .verify => plan.boots.verify,
        }.data_key;
        const held = try gpa.print("{s}/held.key", .{w.dir});
        if (without_key) try Dir.rename(Dir.cwd(), w.key_path, Dir.cwd(), held, io);
        {
            const log = try Dir.cwd().createFile(
                io,
                try gpa.print("{s}/{s}-pack.log", .{ w.dir, @tagName(phase) }),
                .{},
            );
            defer log.close(io);
            try t.call(
                &.{
                    howl,
                    "pack",
                    "--build",
                    "--with",
                    b.f.ref,
                    "--config",
                    w.config,
                    "-o",
                    packed_path,
                },
                .{ .log = log },
            );
        }
        if (without_key) try Dir.rename(Dir.cwd(), held, Dir.cwd(), w.key_path, io);
        disk = &.{
            "-drive",
            try gpa.print("file={s},format=raw,if=virtio,readonly=on", .{packed_path}),
        };
    }
    const console = try gpa.print("{s}/console", .{w.dir});
    var lines: std.ArrayList(u8) = .empty;
    try lines.appendSlice(gpa, "seen native-completed " ++ plans.completion ++ "\n" ++
        "unseen native-failures werewolf-test: .*\"status\":\"fail\"\n");
    for (plan.console) |l| if (l.only == null or l.only.? == phase)
        try lines.appendSlice(gpa, try plans.consoleLine(gpa, l));
    try t.write(console, lines.items);
    const log = try gpa.print("{s}/{s}.log", .{ w.dir, @tagName(phase) });
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{
        b.harness.boot,
        try gpa.print("{s}-native-{s}", .{ b.name, @tagName(phase) }),
        console,
        log,
    });
    try argv.appendSlice(gpa, machine);
    try argv.appendSlice(gpa, disk);
    var env = try t.env.clone(gpa);
    try env.put(
        "CONSOLE_TIMEOUT",
        try gpa.print("{d}", .{@as(u32, plan.timeout_seconds) + 30}),
    );
    const host_results = try gpa.print("{s}/{s}-host.json", .{ w.dir, @tagName(phase) });
    if (b.ssh) |s| if (hosts.cases(plan, phase) > 0) {
        try env.put("HOST_STEPS", try hosts.braced(t, &.{
            hosts.runner, s.plan, @tagName(phase), host_results,
        }));
        try env.put("HOST_STEPS_TIMEOUT", try gpa.print("{d}", .{plan.timeout_seconds}));
        try env.put("NATIVE_SSH_PORT", s.port);
        try env.put("NATIVE_SSH_KEYS", s.keys);
        try env.put("SSH_SK_PROVIDER", s.provider);
    };
    try t.call(argv.items, .{ .env = &env });
    for (b.inputs) |input| if (!mem.eql(u8, &try hexDigest(io, input.path), &input.digest))
        return t.fail("native test inputs changed during the run; rebuild and retry", .{});
    const transcript = try Dir.cwd().readFileAlloc(io, log, gpa, .limited(256 << 20));
    var count = validate(gpa, transcript, plan, context, null) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return t.fail("{s}: {s}", .{ log, transcriptError(err) }),
    };
    if (hosts.cases(plan, phase) > 0) count += try hosts.results(t, host_results, plan, context);
    if (phase == .verify and reformatted(transcript))
        return t.fail("data was reformatted during verify boot", .{});
    try t.say(
        "native-tests: {s} {s}: {d} assertions passed",
        .{ b.name, @tagName(phase), count },
    );
    var d: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(transcript, &d, .{});
    return .{
        .phase = @tagName(phase),
        .cases = count,
        .log = log,
        .sha256 = try gpa.dupe(u8, &std.fmt.bytesToHex(d, .lower)),
    };
}

/// once boots f's test image, judged by plan, as phase of a run of its own, on the machine
/// qemu describes whole but for the config disk: a check's own kernel,
/// disks and command line (test/check-slot). Host suites need a run's
/// forwarded login, so a plan with them is refused. NATIVE_CONFIG names a
/// config directory the check keeps from boot to boot, with its own data
/// key or none, in place of a fresh one (test/check-people-persist.zig).
/// NATIVE_CONTEXT names a file for the run's context, which the check
/// delivers itself, as a cloud's metadata server does a config: the
/// machine then gets no config disk (test/cloud-boot).
fn once(
    t: *Tool,
    f: Form,
    plan: plans.Plan,
    harness: Harness,
    phase: plans.Phase,
    name: []const u8,
    qemu: []const []const u8,
) !void {
    if (hosts.cases(plan, phase) > 0)
        return t.fail("{s}: host suites run in native-tests run alone", .{f.name});
    const check = t.variable("CHECK") orelse return t.fail("CHECK names the check directory", .{});
    var run_bytes: [16]u8 = undefined;
    try t.io.randomSecure(&run_bytes);
    const run_id = std.fmt.bytesToHex(run_bytes, .lower);
    const fixture = try t.gpa.print("{s}/{s}", .{
        f.tests, if (phase == .seed) "config" else "config-again",
    });
    var work = try freshWork(t, check, name, f);
    if (t.variable("NATIVE_CONFIG")) |config| work = .{
        .dir = work.dir,
        .config = config,
        .key_path = try t.gpa.print("{s}/data.key", .{config}),
        .key = null,
    };
    _ = try boot(t, .{
        .f = f,
        .plan = plan,
        .harness = harness,
        .name = name,
        .run_id = &run_id,
        .work = work,
        .context = t.variable("NATIVE_CONTEXT"),
    }, phase, fixture, qemu);
}

fn reformatted(transcript: []const u8) bool {
    return mem.find(u8, transcript, "werewolf: formatting ") != null or
        mem.find(u8, transcript, "werewolf: making LUKS2 ") != null;
}

pub const Run = struct { run: []const u8, phase: []const u8, timeout_seconds: u16 };

pub const TranscriptError = error{
    UnknownDriver,
    OversizeRecord,
    MalformedRecord,
    StaleRecord,
    FailedRecord,
    OutOfOrder,
    UnexpectedCase,
    UnexpectedDriver,
    OmittedCases,
    IncompleteRun,
    UnknownEvent,
    NoCompletion,
    OutOfMemory,
};

fn transcriptError(err: TranscriptError) []const u8 {
    return switch (err) {
        error.UnknownDriver => "unknown test driver",
        error.OversizeRecord => "oversize test record",
        error.MalformedRecord => "test record must be a JSON object",
        error.StaleRecord => "stale or foreign test result",
        error.FailedRecord => "failed test or output after completion",
        error.OutOfOrder => "test suites ran out of order",
        error.UnexpectedCase => "unexpected or duplicate case",
        error.UnexpectedDriver => "unexpected or duplicate driver",
        error.OmittedCases => "driver omitted cases",
        error.IncompleteRun => "incomplete test run",
        error.UnknownEvent => "unknown test event",
        error.NoCompletion => "no completion record",
        error.OutOfMemory => "out of memory",
    };
}

/// validate accepts a transcript only when every selected suite reports
/// each of its cases passing, in plan order, then the run completes, all
/// for this run and phase. It returns the number of passed cases.
pub fn validate(
    gpa: Allocator,
    transcript: []const u8,
    plan: plans.Plan,
    context: Run,
    only: ?[]const u8,
) TranscriptError!usize {
    const phase = std.meta.stringToEnum(plans.Phase, context.phase) orelse return error.StaleRecord;
    var selected: std.ArrayList(plans.Driver) = .empty;
    for (plan.drivers) |d| if (d.cases(phase).len > 0 and (only == null or
        mem.eql(u8, d.name, only.?)))
        try selected.append(gpa, d);
    if (selected.items.len == 0) return error.UnknownDriver;
    var seen: std.ArrayList([]const u8) = .empty;
    var expected: usize = 0;
    for (selected.items) |d| expected += d.cases(phase).len;
    var finished: usize = 0;
    var completed = false;
    var lines = mem.splitScalar(u8, try consoleClean(gpa, transcript), '\n');
    while (lines.next()) |line| {
        const at = mem.find(u8, line, "werewolf-test: ") orelse continue;
        const raw = line[at + "werewolf-test: ".len ..];
        if (raw.len > 4096) return error.OversizeRecord;
        const record = std.json.parseFromSliceLeaky(std.json.Value, gpa, raw, .{}) catch
            return error.MalformedRecord;
        if (record != .object) return error.MalformedRecord;
        const r = record.object;
        if (!is(r, "run", context.run) or !is(r, "phase", context.phase)) return error.StaleRecord;
        if (completed or !is(r, "status", "pass")) return error.FailedRecord;
        const event = r.get("event") orelse return error.UnknownEvent;
        if (event != .string) return error.UnknownEvent;
        if (mem.eql(u8, event.string, "complete")) {
            if (seen.items.len != expected or
                finished != selected.items.len) return error.IncompleteRun;
            completed = true;
            continue;
        }
        const is_case = mem.eql(u8, event.string, "case");
        if (!is_case and !mem.eql(u8, event.string, "driver")) return error.UnknownEvent;
        if (finished >= selected.items.len) return error.OutOfOrder;
        const d = selected.items[finished];
        if (!is(r, "suite", d.name)) return error.OutOfOrder;
        if (is_case) {
            const case = r.get("case") orelse return error.UnexpectedCase;
            if (case != .string) return error.UnexpectedCase;
            if (!has(d.cases(phase), case.string)) return error.UnexpectedCase;
            const key = try gpa.print("{s}\x00{s}", .{ d.name, case.string });
            if (has(seen.items, key)) return error.UnexpectedCase;
            try seen.append(gpa, key);
        } else {
            for (d.cases(phase)) |case| if (!has(
                seen.items,
                try gpa.print("{s}\x00{s}", .{ d.name, case }),
            ))
                return error.OmittedCases;
            finished += 1;
        }
    }
    if (!completed) return error.NoCompletion;
    return seen.items.len;
}

fn is(record: std.json.ObjectMap, key: []const u8, want: []const u8) bool {
    const value = record.get(key) orelse return false;
    return value == .string and mem.eql(u8, value.string, want);
}

/// consoleClean drops carriage returns and the kernel's console lines,
/// which can interrupt a userspace record anywhere, rejoining the record.
pub fn consoleClean(gpa: Allocator, data: []const u8) ![]const u8 {
    var text: std.ArrayList(u8) = .empty;
    for (data) |c| if (c != '\r') try text.append(gpa, c);
    const t = text.items;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < t.len) {
        if (kernelLine(t[i..])) |n| {
            i += n;
            continue;
        }
        try out.append(gpa, t[i]);
        i += 1;
    }
    return out.items;
}

/// kernelLine is the length of `[  SECONDS.FRACTION] ...\n` at the start
/// of t, or of the kernel's `** N printk messages dropped **\n`, which has
/// no time but lands inside a record as the others do; or null.
fn kernelLine(t: []const u8) ?usize {
    if (mem.startsWith(u8, t, "** ")) {
        const end = mem.findScalar(u8, t, '\n') orelse return null;
        return if (mem.endsWith(u8, t[0..end], " printk messages dropped **")) end + 1 else null;
    }
    if (t.len == 0 or t[0] != '[') return null;
    var i: usize = 1;
    while (i < t.len and std.ascii.isWhitespace(t[i])) i += 1;
    const whole = i;
    while (i < t.len and std.ascii.isDigit(t[i])) i += 1;
    if (i == whole or i >= t.len or t[i] != '.') return null;
    i += 1;
    const fraction = i;
    while (i < t.len and std.ascii.isDigit(t[i])) i += 1;
    if (i == fraction or i >= t.len or t[i] != ']') return null;
    const end = mem.findScalarPos(u8, t, i, '\n') orelse return null;
    return end + 1;
}

const testing = std.testing;

test {
    _ = iteration;
    _ = payload;
    _ = hosts;
}

pub fn testTool(a: Allocator, env: *std.process.Environ.Map) Tool {
    env.* = .init(a);
    return .{ .io = testing.io, .gpa = a, .env = env };
}

/// Transcript writes a stage's records for drivers in a phase, as the
/// guest prints them on its console.
const Transcript = struct {
    a: Allocator,
    context: Run,
    lines: std.ArrayList([]const u8) = .empty,

    fn record(
        r: *Transcript,
        event: []const u8,
        suite: ?[]const u8,
        case: ?[]const u8,
        status: []const u8,
    ) !void {
        var out: Io.Writer.Allocating = .init(r.a);
        var json: std.json.Stringify = .{ .writer = &out.writer };
        try json.beginObject();
        for ([_]?[]const u8{
            event,
            suite,
            case,
            r.context.run,
            r.context.phase,
            status,
        }, [_][]const u8{
            "event", "suite", "case", "run", "phase", "status",
        }) |value, key| if (value) |v| {
            try json.objectField(key);
            try json.write(v);
        };
        try json.endObject();
        try r.lines.append(r.a, try r.a.print("werewolf-test: {s}", .{out.written()}));
    }

    fn drivers(r: *Transcript, ds: []const plans.Driver) !void {
        const phase = std.meta.stringToEnum(plans.Phase, r.context.phase).?;
        for (ds) |d| {
            if (d.cases(phase).len == 0) continue;
            for (d.cases(phase)) |c| try r.record("case", d.name, c, "pass");
            try r.record("driver", d.name, null, "pass");
        }
    }

    fn text(r: *Transcript, records: []const []const u8) ![]const u8 {
        return mem.concat(
            r.a,
            u8,
            &.{ "other service: ready\n", try mem.join(r.a, "\n", records) },
        );
    }
};

const run32 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const seed: Run = .{ .run = run32, .phase = "seed", .timeout_seconds = 300 };

test "transcripts pass only when complete, in order, fresh and passing" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = undefined;
    var t = testTool(a, &env);
    const plan = try t.formPlan(try t.ref("postgresql"));
    var r: Transcript = .{ .a = a, .context = seed };
    try r.drivers(plan.drivers);
    try r.record("complete", null, null, "pass");
    var cases: usize = 0;
    for (plan.drivers) |d| cases += d.seed.len;
    try testing.expectEqual(cases, try validate(a, try r.text(r.lines.items), plan, seed, null));
    // Removing or repeating any record fails.
    for (0..r.lines.items.len) |i| {
        const without = try mem.concat(
            a,
            []const u8,
            &.{ r.lines.items[0..i], r.lines.items[i + 1 ..] },
        );
        try testing.expect(std.meta.isError(validate(a, try r.text(without), plan, seed, null)));
        const twice = try mem.concat(
            a,
            []const u8,
            &.{ r.lines.items[0 .. i + 1], r.lines.items[i..] },
        );
        try testing.expect(std.meta.isError(validate(a, try r.text(twice), plan, seed, null)));
    }
    // A failed, stale, foreign-phase or invented first case fails.
    const first = r.lines.items[0];
    for ([_][2][]const u8{
        .{ "\"status\":\"pass\"", "\"status\":\"fail\"" },
        .{ run32, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
        .{ "\"phase\":\"seed\"", "\"phase\":\"verify\"" },
        .{ plan.drivers[0].seed[0], "invented" },
    }) |change| {
        var changed = try a.dupe([]const u8, r.lines.items);
        changed[0] = try mem.replaceOwned(u8, a, first, change[0], change[1]);
        try testing.expect(std.meta.isError(validate(a, try r.text(changed), plan, seed, null)));
    }
    // A failed driver is not hidden by its passed cases.
    var failed = try a.dupe([]const u8, r.lines.items);
    failed[failed.len - 2] = try mem.replaceOwned(
        u8,
        a,
        failed[failed.len - 2],
        "\"pass\"",
        "\"fail\"",
    );
    try testing.expectError(error.FailedRecord, validate(a, try r.text(failed), plan, seed, null));
    const lines = r.lines.items;
    for ([_][]const []const u8{
        &.{}, lines[0 .. lines.len - 1], lines[lines.len - 1 ..],
        try mem.concat(
            a,
            []const u8,
            &.{ lines, lines[0..1] },
        ),
    }) |records| try testing.expect(std.meta.isError(validate(
        a,
        try r.text(records),
        plan,
        seed,
        null,
    )));
    const long: [4097]u8 = @splat('x');
    for ([_][]const u8{ "{", &long, "null", "[]" }) |raw|
        try testing.expect(std.meta.isError(validate(
            a,
            try a.print("werewolf-test: {s}", .{raw}),
            plan,
            seed,
            null,
        )));
    // Kernel lines interrupting a record are dropped; other trailing data is not.
    for ([_]usize{ 0, lines.len - 1 }) |index| for ([_]usize{ 25, lines[index].len - 2 }) |offset| {
        var interrupted = try a.dupe([]const u8, lines);
        interrupted[index] = try mem.concat(a, u8, &.{
            lines[index][0..offset], "[ 16.429304] audit: type=1302 denied\r\n",
            lines[index][offset..],
        });
        try testing.expectEqual(
            cases,
            try validate(a, try mem.join(a, "\r\n", interrupted), plan, seed, null),
        );
    };
    var trailing = try a.dupe([]const u8, lines);
    trailing[0] = try a.print("{s}unexpected output", .{lines[0]});
    try testing.expect(std.meta.isError(validate(a, try r.text(trailing), plan, seed, null)));
}

test "iteration accepts one suite's records, and only its own" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = undefined;
    var t = testTool(a, &env);
    const plan = try t.formPlan(try t.ref("postgresql"));
    const name = "test-postgres";
    var r: Transcript = .{ .a = a, .context = seed };
    var other: ?plans.Driver = null;
    for (plan.drivers) |d| {
        if (mem.eql(u8, d.name, name)) try r.drivers(&.{d}) else other = d;
    }
    const own = r.lines.items.len;
    try r.record("complete", null, null, "pass");
    var cases: usize = 0;
    for (plan.drivers) |d| if (mem.eql(u8, d.name, name)) {
        cases = d.seed.len;
    };
    try testing.expectEqual(cases, try validate(a, try r.text(r.lines.items), plan, seed, name));
    try testing.expectError(
        error.UnknownDriver,
        validate(a, try r.text(r.lines.items), plan, seed, "missing"),
    );
    var foreign: Transcript = .{ .a = a, .context = seed };
    try foreign.record("driver", other.?.name, null, "pass");
    const mixed = try mem.concat(
        a,
        []const u8,
        &.{ r.lines.items[0..own], foreign.lines.items, r.lines.items[own..] },
    );
    try testing.expect(std.meta.isError(validate(a, try r.text(mixed), plan, seed, name)));
}

test "a phase's suites are only those with cases in that phase" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]plans.Phase{ .seed, .verify }) |selected| {
        const only: []const []const u8 = &.{"phase-only"};
        const plan: plans.Plan = .{ .drivers = &.{
            .{
                .name = "test-control",
                .source = "probes.zig",
                .mode = "probes",
                .seed = &.{"control"},
                .verify = &.{"control"},
            },
            .{
                .name = "test-gatus",
                .source = "probes.zig",
                .mode = "probes",
                .seed = if (selected == .seed) only else &.{},
                .verify = if (selected == .verify) only else &.{},
            },
        } };
        for ([_]plans.Phase{ .seed, .verify }) |phase| {
            const context: Run = .{
                .run = run32,
                .phase = @tagName(phase),
                .timeout_seconds = 300,
            };
            var control: Transcript = .{ .a = a, .context = context };
            try control.drivers(plan.drivers[0..1]);
            var suite: Transcript = .{ .a = a, .context = context };
            try suite.record("case", "test-gatus", "phase-only", "pass");
            try suite.record("driver", "test-gatus", null, "pass");
            var done: Transcript = .{ .a = a, .context = context };
            try done.record("complete", null, null, "pass");
            const with = try mem.concat(
                a,
                []const u8,
                &.{ control.lines.items, suite.lines.items, done.lines.items },
            );
            const without = try mem.concat(
                a,
                []const u8,
                &.{ control.lines.items, done.lines.items },
            );
            const right, const wrong = if (phase == selected)
                .{ with, without }
            else
                .{ without, with };
            try testing.expectEqual(
                @as(usize, if (phase == selected) 2 else 1),
                try validate(a, try mem.join(a, "\n", right), plan, context, null),
            );
            try testing.expect(std.meta.isError(validate(
                a,
                try mem.join(a, "\n", wrong),
                plan,
                context,
                null,
            )));
        }
    }
}

test "the clean boot runs readiness, then shared checks, then the form's suites" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = undefined;
    var t = testTool(a, &env);
    const gatus = try t.ref("gatus");
    const application = try t.formPlan(gatus);
    const clean = try t.bootPlan(gatus);
    try testing.expectEqualStrings("test-platform", clean.drivers[0].name);
    try testing.expectEqual(16, clean.drivers[0].seed.len);
    try testing.expect(has(clean.drivers[0].seed, "age-cache-protected"));
    try testing.expectEqualDeep(
        @as([]const []const u8, &.{ "data-usable", "data-kept", "age-cache-protected" }),
        clean.drivers[0].verify,
    );
    try testing.expectEqualStrings("test-lifecycle", clean.drivers[1].name);
    try testing.expectEqualDeep(@as([]const []const u8, &.{"reaped"}), clean.drivers[1].seed);
    try testing.expectEqual(0, clean.drivers[1].verify.len);
    for (application.drivers) |d| try testing.expect(!has(&plans.reserved, d.name));
    var r: Transcript = .{ .a = a, .context = seed };
    try r.drivers(application.drivers);
    try r.record("complete", null, null, "pass");
    try testing.expectEqual(
        application.drivers[0].seed.len,
        try validate(a, try r.text(r.lines.items), application, seed, null),
    );
    try testing.expect(std.meta.isError(validate(a, try r.text(r.lines.items), clean, seed, null)));
    // The reboot does not claim seed-only lifecycle checks.
    const verify: Run = .{ .run = run32, .phase = "verify", .timeout_seconds = 300 };
    var reboot: Transcript = .{ .a = a, .context = verify };
    try reboot.drivers(clean.drivers);
    try reboot.record("complete", null, null, "pass");
    _ = try validate(a, try reboot.text(reboot.lines.items), clean, verify, null);
    // Declared readiness precedes the shared checks and their restarts.
    var ready = application.drivers[0];
    ready.name = "test-ready";
    ready.readiness = true;
    ready.seed = &.{"ready"};
    ready.verify = &.{"ready"};
    var with_ready = application;
    with_ready.drivers = try mem.concat(a, plans.Driver, &.{ &.{ready}, application.drivers });
    var failure: plans.Failure = .{};
    const platform = try plans.load(t.io, a, Dir.cwd(), platform_plan, &failure);
    const ordered = try plans.boot(a, with_ready, platform, &.{}, &failure);
    var names: [4][]const u8 = undefined;
    for (ordered.drivers, &names) |d, *n| n.* = d.name;
    try testing.expectEqualDeep(
        [4][]const u8{ "test-ready", "test-platform", "test-lifecycle", "test-gatus" },
        names,
    );
    var good: Transcript = .{ .a = a, .context = seed };
    try good.drivers(ordered.drivers);
    try good.record("complete", null, null, "pass");
    _ = try validate(a, try good.text(good.lines.items), ordered, seed, null);
    for ([_][4]usize{ .{ 1, 0, 2, 3 }, .{ 0, 2, 1, 3 } }) |order| {
        var swapped: Transcript = .{ .a = a, .context = seed };
        for (order) |i| try swapped.drivers(ordered.drivers[i .. i + 1]);
        try swapped.record("complete", null, null, "pass");
        try testing.expectError(
            error.OutOfOrder,
            validate(a, try swapped.text(swapped.lines.items), ordered, seed, null),
        );
    }
}

test "kernel interleaving preserves complete userspace records" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const wanted = "posture: fail= pass=90 {\"tool\":\"posture\",\"host\":\"new-host\"}\n";
    try testing.expectEqualStrings(wanted, try consoleClean(a, "posture: fail= pass=90 " ++
        "{\"tool\":\"posture\",\"[ 5.125] audit: syscall " ++
        "denied\r\nhost\":\"new-host\"}\r\n"));
    try testing.expectEqualStrings(wanted, try consoleClean(a, wanted));
    try testing.expectEqualStrings(
        "ordinary [1, 2] data\n",
        try consoleClean(a, "ordinary [1, 2] data\n"),
    );
    try testing.expectEqualStrings(
        "werewolf: unregistered data failed\n",
        try consoleClean(
            a,
            "werewolf: unregistered d[    0.408051] Kernel panic - not syncing\r\nata failed\r\n",
        ),
    );
    try testing.expectEqualStrings("[ 1.5] no newline", try consoleClean(a, "[ 1.5] no newline"));
    // A flood of kernel messages drops some, and says so where it was.
    try testing.expectEqualStrings(
        "werewolf-test: {\"event\":\"case\"}\n",
        try consoleClean(a, "werewolf-test: {\"event\":\"case\"}[ 1.43] audit: seccomp\r\n" ++
            "** 9 printk messages dropped **\r\n\r\n"),
    );
    try testing.expectEqualStrings(
        "** not dropped **\n",
        try consoleClean(a, "** not dropped **\n"),
    );
}

test "drivers' grants, waits and descriptors are their own" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = undefined;
    var t = testTool(a, &env);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(t.io, ".", a);
    try runtimeGrants(
        &t,
        root,
        &.{.{
            .name = "test-langflow",
            .source = "driver.zig",
            .mode = "http",
            .allow = &.{"python:native"},
        }},
    );
    const grant = try tmp.dir.readFileAlloc(
        t.io,
        "etc/runtime-hardening/allow/test-langflow/python/native",
        a,
        .limited(1),
    );
    try testing.expectEqual(0, grant.len);
    var d: plans.Driver = .{
        .name = "test-app",
        .source = "probes.zig",
        .mode = "probes",
        .user = "app",
        .read = &.{ "/etc/passwd", "/run/cgroup/svc/app", "/data/svc/app/database" },
        .connect = &.{ "tcp/8080", "/run/svc/app/socket", "/data/share/app/socket" },
        .config = &.{.{ .name = "password", .path = "/run/config/app/password" }},
        .groups = &.{"web"},
        .probes = .null,
    };
    try testing.expectEqualDeep(@as([]const []const u8, &.{
        "/data/share/app/socket", "/data/svc/app/database", "/run/cgroup/svc/app",
        "/run/svc/app/socket",
    }), try waitPaths(a, d));
    const clean = try service(a, d, .clean);
    try testing.expect(mem.startsWith(
        u8,
        clean,
        "exec /usr/lib/werewolf/test-app test-app probes /run/svc/test-app/context\nuser app\n",
    ));
    try testing.expect(mem.find(
        u8,
        clean,
        "config context /run/config/tests/context\nmemory 128\nnofile 128\n",
    ) != null);
    try testing.expect(mem.find(u8, clean, "connect tcp/8080\n") != null);
    try testing.expect(mem.find(
        u8,
        clean,
        "config password /run/config/app/password\ngroup web\n",
    ) != null);
    try testing.expect(mem.find(u8, clean, "howl-dev") == null);
    d.memory = 1024;
    const iterate = try service(a, d, .iterate);
    try testing.expect(mem.find(
        u8,
        iterate,
        "config context /run/config/native-iterate-context\nmemory 1024\n",
    ) != null);
    try testing.expect(mem.find(u8, iterate, "read /run/howl-dev/test-app.json\n") != null);
}

test "a compiled example reuses its production application's exact bytes" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = undefined;
    var t = testTool(a, &env);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realPathFileAlloc(t.io, ".", a);
    try tmp.dir.createDirPath(t.io, "production/application/usr/lib/app");
    try tmp.dir.writeFile(t.io, .{
        .sub_path = "production/application/usr/lib/app/server",
        .data = "production executable, not a recompilation",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const generated = try a.print("{s}/generated/rootfs", .{base});
    try applicationOverlay(&t, "go-example", try a.print("{s}/production", .{base}), generated);
    const stat = try tmp.dir.statFile(t.io, "generated/rootfs/usr/lib/app/server", .{});
    try testing.expectEqual(0o755, stat.permissions.toMode() & 0o777);
    try tmp.dir.writeFile(
        t.io,
        .{ .sub_path = "generated/rootfs/usr/lib/app/server", .data = "changed test copy" },
    );
    try testing.expectEqualStrings(
        "production executable, not a recompilation",
        try tmp.dir.readFileAlloc(
            t.io,
            "production/application/usr/lib/app/server",
            a,
            .limited(64),
        ),
    );
    for (compiled_examples) |name| {
        try testing.expectError(
            error.Refused,
            applicationOverlay(&t, name, try a.print("{s}/missing", .{base}), generated),
        );
        try testing.expect(mem.find(u8, t.why, "missing compiled production application") != null);
    }
    try applicationOverlay(&t, "gatus", try a.print("{s}/missing", .{base}), generated);
}

test "the generated form keeps the real form's check budget and weaknesses" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = undefined;
    var t = testTool(a, &env);
    Dir.cwd().access(t.io, "build/host/form", .{}) catch return error.SkipZigTest;
    const greenbone = try t.ref("greenbone");
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const generated = try a.print(".zig-cache/tmp/{s}/native-test-greenbone", .{tmp.sub_path});
    try t.write(
        try a.print("{s}/form.yaml", .{generated}),
        try formConfig(&t, greenbone, try t.formPlan(greenbone), &.{}),
    );
    for ([_][]const []const u8{ &.{ "check", "", "memory" }, &.{"weaknesses"} }) |verb| {
        var want: std.ArrayList([]const u8) = .empty;
        var got: std.ArrayList([]const u8) = .empty;
        try want.appendSlice(a, &.{ "build/host/form", verb[0], "greenbone" });
        try got.appendSlice(a, &.{ "build/host/form", verb[0], generated });
        if (verb.len > 1) {
            try want.append(a, verb[2]);
            try got.append(a, verb[2]);
        }
        try testing.expectEqualStrings(try t.output(want.items), try t.output(got.items));
    }
}

test "the generated form leaves out what test packages bring and no test runs" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = undefined;
    var t = testTool(a, &env);
    Dir.cwd().access(t.io, "build/host/form", .{}) catch return error.SkipZigTest;
    const gitea = try t.ref("gitea");
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const generated = try a.print(".zig-cache/tmp/{s}/native-test-gitea", .{tmp.sub_path});
    var plan = try t.formPlan(gitea);
    plan.prune = &.{ "usr/bin/scp", "usr/bin/sftp" };
    try t.write(try a.print("{s}/form.yaml", .{generated}), try formConfig(&t, gitea, plan, &.{}));
    const own = try t.output(&.{ "build/host/form", "list", "gitea", "prune" });
    const listed = try t.output(&.{ "build/host/form", "list", generated, "prune" });
    var lines = mem.tokenizeScalar(u8, own, '\n');
    while (lines.next()) |line| try testing.expect(mem.find(u8, listed, line) != null);
    for (plan.prune) |p| try testing.expect(mem.find(u8, listed, p) != null);
}

/// fake_howl packs only the run context, which fake_boot reads back,
/// and says beside it whether the config held data.key.
const fake_howl =
    \\#!/bin/sh
    \\while [ $# -gt 0 ]; do
    \\    case $1 in --config) config=$2; shift ;; -o) out=$2; shift ;; esac
    \\    shift
    \\done
    \\cp "$config/tests/context" "$out"
    \\if [ -f "$config/data.key" ]; then echo key; else echo none; fi >"$out.key"
    \\
;

/// fake_boot boots nothing: it checks what a boot is given, keeps or checks
/// the data disk, and prints the records the cases file lists for the phase,
/// a kernel line cutting the first, as a serial console does.
const fake_boot =
    \\#!/bin/sh
    \\set -eu
    \\log=$3
    \\cp "$2" "$log.console"
    \\for arg; do
    \\    case $arg in
    \\    file=*readonly=on) packed=${arg#file=} packed=${packed%%,*} ;;
    \\    file=*) disk=${arg#file=} disk=${disk%%,*} ;;
    \\    esac
    \\done
    \\# A check delivering the context itself gives the machine no config disk.
    \\if [ -n "${NATIVE_CONTEXT:-}" ]; then [ -z "${packed:-}" ]; packed=$NATIVE_CONTEXT; fi
    \\context=$(cat "$packed")
    \\run=$(printf '%s' "$context" | sed 's/.*"run":"\([0-9a-f]*\)".*/\1/')
    \\phase=$(printf '%s' "$context" | sed 's/.*"phase":"\([a-z]*\)".*/\1/')
    \\case $context in *'"timeout_seconds":300'*) ;; *) exit 9 ;; esac
    \\[ "$CONSOLE_TIMEOUT" = 330 ] || exit 9
    \\updated=$CHECK/postgresql-native/postgresql-config/updated
    \\if [ -n "${UPDATE:-}" ]; then
    \\    if [ "$phase" = verify ]; then [ -f "$updated" ]; else [ ! -f "$updated" ]; fi
    \\fi
    \\if [ "$phase" = seed ]; then
    \\    printf 'kept data' | dd of="$disk" conv=notrunc 2>/dev/null
    \\else
    \\    [ "$(head -c 9 "$disk")" = 'kept data' ]
    \\fi
    \\[ -z "${CHANGE:-}" ] || echo 'replaced during boot' >"$CHANGE"
    \\cut=1
    \\while read -r event suite case; do
    \\    fields="\"event\":\"$event\",\"run\":\"$run\",\"phase\":\"$phase\""
    \\    [ "$suite" = - ] || fields="$fields,\"suite\":\"$suite\""
    \\    [ "$case" = - ] || fields="$fields,\"case\":\"$case\""
    \\    if [ $cut = 1 ]; then
    \\        printf 'werewolf-test: {[ 16.429304] audit: type=1302 denied\r\r\n'
    \\        cut=0
    \\    else
    \\        printf 'werewolf-test: {'
    \\    fi
    \\    printf '%s,"status":"pass"}\r\r\n' "$fields"
    \\done <"$CASES.$phase" >"$log"
    \\if [ -n "${REFORMAT:-}" ] && [ "$phase" = verify ]; then
    \\    echo 'werewolf: making LUKS2 on /dev/vda' >>"$log"
    \\fi
    \\
;

/// Scratch is a checkout's worth of what runPlan reads, with fakes for howl
/// and the console.
const Scratch = struct {
    tmp: testing.TmpDir,
    root: []const u8,
    t: Tool,
    env: std.process.Environ.Map,
    /// boots and console are a scenario's, for the plan run gives runPlan.
    boots: plans.Boots = .{},
    console: []const plans.Console = &.{},

    fn init(s: *Scratch, a: Allocator) !void {
        s.tmp = testing.tmpDir(.{});
        s.env = .init(a);
        s.boots = .{};
        s.console = &.{};
        s.t = .{ .io = testing.io, .gpa = a, .env = &s.env };
        s.root = try s.tmp.dir.realPathFileAlloc(s.t.io, ".", a);
        for ([_][2][]const u8{
            .{ "build/vmlinuz", "kernel" },
            .{ "build/native-test-postgresql/initramfs.zst", "image" },
            .{ "build/postgresql/initramfs.zst", "production image" },
            .{ "forms/postgresql/test/tests.yaml", "plan" },
            .{ "platform.yaml", "platform plan" },
            .{ "platform.zig", "platform driver" },
            .{
                "cases.seed",
                "case test-a one\ncase test-a two\ndriver test-a -\n" ++
                    "case test-b three\ndriver test-b -\ncomplete - -\n",
            },
            .{ "cases.verify", "case test-a one\ndriver test-a -\ncomplete - -\n" },
        }) |f| try s.file(f[0], f[1], 0o644);
        try s.file("howl", fake_howl, 0o755);
        try s.file("boot", fake_boot, 0o755);
        for ([_][2][]const u8{
            .{ "OUT", "build/native-test-postgresql" }, .{ "PRODUCTION_OUT", "build/postgresql" },
            .{ "KERNEL", "build/vmlinuz" },             .{ "CHECK", "check" },
            .{ "HOWL", "howl" },                        .{ "CASES", "cases" },
        }) |v| try s.env.put(v[0], try s.path(v[1]));
        try s.env.put("CMDLINE", "test");
        try s.env.put("PATH", "/usr/bin:/bin");
    }

    fn path(s: *Scratch, name: []const u8) ![]const u8 {
        return s.t.gpa.print("{s}/{s}", .{ s.root, name });
    }

    fn file(s: *Scratch, name: []const u8, data: []const u8, mode: std.posix.mode_t) !void {
        if (std.fs.path.dirname(name)) |parent| try s.tmp.dir.createDirPath(s.t.io, parent);
        try s.tmp.dir.writeFile(
            s.t.io,
            .{ .sub_path = name, .data = data, .flags = .{ .permissions = .fromMode(mode) } },
        );
    }

    fn run(s: *Scratch) !void {
        try runPlan(&s.t, try s.form(), s.plan(), "x86_64", &.{}, try s.harness());
    }

    fn plan(s: *Scratch) plans.Plan {
        return .{
            .drivers = &.{
                .{
                    .name = "test-a",
                    .source = "probes.zig",
                    .mode = "probes",
                    .seed = &.{ "one", "two" },
                    .verify = &.{"one"},
                },
                .{
                    .name = "test-b",
                    .source = "probes.zig",
                    .mode = "probes",
                    .seed = &.{"three"},
                },
            },
            .boots = s.boots,
            .console = s.console,
        };
    }

    fn form(s: *Scratch) !Form {
        return .{
            .name = "postgresql",
            .ref = "postgresql",
            .dir = try s.path("forms/postgresql"),
            .tests = try s.path("forms/postgresql/test"),
        };
    }

    fn harness(s: *Scratch) !Harness {
        return .{
            .boot = try s.path("boot"),
            .platform_plan = try s.path("platform.yaml"),
            .platform_driver = try s.path("platform.zig"),
        };
    }

    fn results(s: *Scratch) !?std.json.Value {
        const text = s.tmp.dir.readFileAlloc(
            s.t.io,
            "check/postgresql-native/results.json",
            s.t.gpa,
            .limited(1 << 20),
        ) catch
            return null;
        return try std.json.parseFromSliceLeaky(std.json.Value, s.t.gpa, text, .{});
    }

    fn refused(s: *Scratch, why: []const u8) !void {
        try testing.expectError(error.Refused, s.run());
        if (mem.find(u8, s.t.why, why) == null) {
            std.debug.print("refused for {s}, not {s}\n", .{ s.t.why, why });
            return error.TestUnexpectedResult;
        }
        try testing.expect(try s.results() == null);
    }
};

test "a run boots seed then verify on one disk and keeps serial records whole" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var s: Scratch = undefined;
    try s.init(arena.allocator());
    defer s.tmp.cleanup();
    try s.run();
    const report = (try s.results()).?.object;
    const phases = report.get("phases").?.array.items;
    try testing.expectEqual(3, phases[0].object.get("cases").?.integer);
    try testing.expectEqual(1, phases[1].object.get("cases").?.integer);
    try testing.expect(!mem.eql(
        u8,
        phases[0].object.get("sha256").?.string,
        phases[1].object.get("sha256").?.string,
    ));
    try testing.expectEqual(300, report.get("timeout_seconds").?.integer);
    try testing.expectEqualStrings("werewolf-native-results/1", report.get("format").?.string);
    try testing.expectEqual(32, report.get("run").?.string.len);
    try testing.expect(report.get("verify_config") == null);
}

test "a verify boot that reformats data cannot pass" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var s: Scratch = undefined;
    try s.init(arena.allocator());
    defer s.tmp.cleanup();
    try s.env.put("REFORMAT", "1");
    try s.refused("reformatted");
}

test "config-again updates once before verify, on the same disk and key" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s: Scratch = undefined;
    try s.init(a);
    defer s.tmp.cleanup();
    try s.file("forms/postgresql/test/config-again",
        \\#!/bin/sh
        \\echo 'new config' >"$1/updated"
        \\[ -z "${ROTATE:-}" ] || echo 'wrong key' >"$1/data.key"
        \\
    , 0o755);
    try s.env.put("UPDATE", "1");
    try s.run();
    const report = (try s.results()).?.object;
    try testing.expectEqualStrings(
        &try hexDigest(s.t.io, try s.path("forms/postgresql/test/config-again")),
        report.get("verify_config").?.string,
    );
    try s.env.put("ROTATE", "1");
    try s.refused("data key");
}

test "a boot without data.key packs none, gets it back, and is judged by its own lines" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s: Scratch = undefined;
    try s.init(a);
    defer s.tmp.cleanup();
    s.boots = .{ .verify = .{ .data_key = false } };
    s.console = &.{
        .{ .kind = .seen, .name = "both", .arg = "anywhere" },
        .{ .kind = .seen, .name = "refused", .arg = "LUKS", .only = .verify },
    };
    try s.run();
    const work = "check/postgresql-native";
    for ([_][2][]const u8{ .{ "seed", "key\n" }, .{ "verify", "none\n" } }) |p| {
        const io = s.t.io;
        try testing.expectEqualStrings(p[1], try s.tmp.dir.readFileAlloc(
            io,
            try a.print("{s}/{s}.tar.key", .{ work, p[0] }),
            a,
            .limited(16),
        ));
        const lines = try s.tmp.dir.readFileAlloc(
            io,
            try a.print("{s}/{s}.log.console", .{ work, p[0] }),
            a,
            .limited(4096),
        );
        try testing.expect(mem.find(u8, lines, "seen both anywhere\n") != null);
        try testing.expectEqual(
            mem.eql(u8, p[0], "verify"),
            mem.find(u8, lines, "seen refused LUKS\n") != null,
        );
    }
    _ = try s.tmp.dir.statFile(s.t.io, work ++ "/postgresql-config/data.key", .{});
}

test "a check's own machine boots one phase, with only the config disk added" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s: Scratch = undefined;
    try s.init(a);
    defer s.tmp.cleanup();
    try s.file("slot.img", "", 0o644);
    try once(&s.t, try s.form(), s.plan(), try s.harness(), .seed, "slot", &.{
        "-drive", try a.print("file={s},format=raw,if=virtio", .{try s.path("slot.img")}),
    });
    const io = s.t.io;
    // The disk the boot wrote is the check's, not a data disk of the run's.
    try testing.expectEqualStrings(
        "kept data",
        try s.tmp.dir.readFileAlloc(io, "slot.img", a, .limited(64)),
    );
    _ = try s.tmp.dir.statFile(io, "check/slot-native/seed.tar", .{});
    try testing.expectError(
        error.FileNotFound,
        s.tmp.dir.statFile(io, "check/slot-native/data.img", .{}),
    );
}

test "a check keeping its config, or delivering the context, boots as it says" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s: Scratch = undefined;
    try s.init(a);
    defer s.tmp.cleanup();
    const io = s.t.io;
    try s.file("slot.img", "", 0o644);
    const disk = [_][]const u8{
        "-drive", try a.print("file={s},format=raw,if=virtio", .{try s.path("slot.img")}),
    };
    // Its own config, with no data key, is packed as it is, context and all.
    try s.file("kept/hostname", "people-enroll\n", 0o600);
    try s.env.put("NATIVE_CONFIG", try s.path("kept"));
    try once(&s.t, try s.form(), s.plan(), try s.harness(), .seed, "kept", &disk);
    try testing.expectEqualStrings(
        "none\n",
        try s.tmp.dir.readFileAlloc(io, "check/kept-native/seed.tar.key", a, .limited(64)),
    );
    _ = try s.tmp.dir.statFile(io, "kept/tests/context", .{});
    // A context the check delivers is written for it, and no disk is packed.
    _ = s.env.swapRemove("NATIVE_CONFIG");
    try s.env.put("NATIVE_CONTEXT", try s.path("served/context"));
    try once(&s.t, try s.form(), s.plan(), try s.harness(), .seed, "cloud", &disk);
    const context = try s.tmp.dir.readFileAlloc(io, "served/context", a, .limited(4096));
    try testing.expect(mem.find(u8, context, "\"phase\":\"seed\"") != null);
    try testing.expectError(
        error.FileNotFound,
        s.tmp.dir.statFile(io, "check/cloud-native/seed.tar", .{}),
    );
}

test "inputs changed during a run cannot write a passing report" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{
        "build/vmlinuz",                  "build/native-test-postgresql/initramfs.zst",
        "build/postgresql/initramfs.zst", "forms/postgresql/test/tests.yaml",
        "platform.yaml",                  "platform.zig",
        "forms/postgresql/test/config",   "forms/postgresql/test/config-again",
    }) |input| {
        var s: Scratch = undefined;
        try s.init(a);
        defer s.tmp.cleanup();
        for ([_][]const u8{ "config", "config-again" }) |name|
            try s.file(try a.print("forms/postgresql/test/{s}", .{name}), "#!/bin/sh\n", 0o755);
        try s.env.put("CHANGE", try s.path(input));
        try s.refused("inputs changed");
    }
}
