//! iterate keeps one disposable SSH VM per form for `howl test --iterate`:
//! it builds the image once, with each driver a link to an upload, then
//! replaces and reruns one suite. A change to what the image is made of
//! rebuilds the VM; driver sources and YAML assertions upload as data.

const std = @import("std");
const builtin = @import("builtin");
const plans = @import("test-plan");
const tests = @import("native-tests.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const mem = std.mem;
const Tool = tests.Tool;

const control = "/usr/lib/werewolf/native-iterate";
const usage = "usage: native-tests iterate HOWL FORM ARCH ensure|reset|stop|run PHASE [DRIVER]";

pub const Action = enum { ensure, reset, stop, run };

pub fn main(t: *Tool, args: []const []const u8) !void {
    if (args.len != 5 and args.len != 6) return t.fail("{s}", .{usage});
    const howl = args[0];
    const f = try t.ref(args[1]);
    if (f.scenario) return t.fail("{s}: a scenario runs clean, not under --iterate", .{f.dir});
    const arch = args[2];
    if (!mem.eql(u8, arch, local))
        return t.fail("SSH iteration runs the host architecture, aarch64 or x86_64", .{});
    const action = std.meta.stringToEnum(Action, args[3]) orelse return t.fail("{s}", .{usage});
    const phase = std.meta.stringToEnum(plans.Phase, args[4]) orelse
        return t.fail("phase is seed or verify", .{});
    const driver_name: ?[]const u8 = if (args.len == 6) args[5] else null;
    const plan = try t.formPlan(f);
    if (plan.drivers.len == 0 and action != .stop)
        return t.fail(
            "this foundation has only shared boot checks; run howl test without --iterate",
            .{},
        );
    const gpa = t.gpa;
    const name = try machineName(gpa, f.name);
    const machine = try gpa.print("build/machines/{s}", .{name});
    const work = try gpa.print("build/native-iterate/{s}/{s}", .{ arch, f.name });
    const generated = try gpa.print("{s}/native-iterate-{s}", .{ work, f.name });
    try prepare(t, f, arch, plan, generated);
    if (action == .stop) {
        if (exists(t.io, machine)) try t.call(&.{ howl, "stop", name }, .{});
        return;
    }
    const state = try ensure(t, .{
        .howl = howl,
        .form = f,
        .arch = arch,
        .plan = plan,
        .work = work,
        .generated = generated,
        .machine = machine,
        .name = name,
    }, action == .reset);
    if (action != .run) {
        if (driver_name != null) return t.fail("{s}", .{usage});
        try t.say(
            "native-iterate: {s} is ready; use --driver NAME to upload and run a test",
            .{name},
        );
        return;
    }
    const wanted = driver_name orelse return t.fail("run needs a driver", .{});
    for (plan.drivers) |d| if (mem.eql(u8, d.name, wanted))
        return runDriver(t, howl, f, arch, plan, d, phase, work, machine, name, state.run);
    return t.fail("unknown test driver: {s}", .{wanted});
}

const local = switch (builtin.cpu.arch) {
    .aarch64 => "aarch64",
    .x86_64 => "x86_64",
    else => "unsupported",
};

/// machineName is the form's iteration VM: a host name howl accepts, unique
/// to the form however long its name.
pub fn machineName(gpa: Allocator, form: []const u8) ![]const u8 {
    var hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(form, &hash, .{});
    const hex = std.fmt.bytesToHex(hash, .lower);
    return gpa.print(
        "test-{s}-{s}",
        .{ mem.trimEnd(u8, form[0..@min(form.len, 18)], "-"), hex[0..8] },
    );
}

fn exists(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// prepare regenerates the iteration form in full, so a removed driver
/// never leaves a runnable descriptor or link behind.
fn prepare(
    t: *Tool,
    f: tests.Form,
    arch: []const u8,
    plan: plans.Plan,
    generated: []const u8,
) !void {
    const io = t.io;
    const gpa = t.gpa;
    try Dir.cwd().deleteTree(io, generated);
    const root = try gpa.print("{s}/rootfs", .{generated});
    try t.write(
        try gpa.print("{s}/form.yaml", .{generated}),
        try tests.formConfig(t, f, plan, &.{}),
    );
    if (mem.eql(u8, f.name, "go-example") or mem.eql(u8, f.name, "rust-example") or
        mem.eql(u8, f.name, "aspnet-example"))
    {
        try t.call(&.{
            "make",                             "--no-print-directory",
            try gpa.print("ARCH={s}", .{arch}), try gpa.print("FORM={s}", .{f.ref}),
            "DEV=",                             "image",
        }, .{});
        try tests.applicationOverlay(
            t,
            f.name,
            try gpa.print("build/{s}/{s}", .{ arch, f.name }),
            root,
        );
    }
    const binary = try gpa.print("{s}{s}", .{ root, control });
    try Dir.cwd().createDirPath(io, std.fs.path.dirname(binary).?);
    try t.call(&.{
        "zig",                     "build-exe",
        "-O",                      "ReleaseSafe",
        "-fstrip",                 "-fPIE",
        "-target",                 try gpa.print("{s}-linux-musl", .{arch}),
        "test/native/iterate.zig", try gpa.print("-femit-bin={s}", .{binary}),
    }, .{});
    try t.write(
        try gpa.print("{s}/usr/share/werewolf/test-image", .{root}),
        "werewolf-native-iteration/1\n",
    );
    try tests.runtimeGrants(t, root, plan.drivers);
    for (plan.drivers) |d| {
        const tests_dir = try gpa.print("{s}/usr/share/werewolf/tests/{s}", .{ root, d.name });
        try Dir.cwd().createDirPath(io, tests_dir);
        try Dir.cwd().symLink(io, try gpa.print("/run/howl-dev/{s}", .{d.name}), try gpa.print(
            "{s}/usr/lib/werewolf/{s}",
            .{ root, d.name },
        ), .{});
        try t.write(
            try gpa.print("{s}/service", .{tests_dir}),
            try tests.service(gpa, d, .iterate),
        );
        try t.write(try gpa.print(
            "{s}/launch.json",
            .{tests_dir},
        ), try std.json.Stringify.valueAlloc(gpa, .{
            .mode = d.mode,
            .probes = d.probes != null,
            .root = mem.eql(u8, d.user, "root"),
        }, .{}));
        if (d.probes != null) try Dir.cwd().symLink(
            io,
            try gpa.print("/run/howl-dev/{s}.json", .{d.name}),
            try gpa.print("{s}/probes.json", .{tests_dir}),
            .{},
        );
    }
}

const Vm = struct {
    howl: []const u8,
    form: tests.Form,
    arch: []const u8,
    plan: plans.Plan,
    work: []const u8,
    generated: []const u8,
    machine: []const u8,
    name: []const u8,
};

const Saved = struct {
    format: []const u8 = "werewolf-native-iteration/1",
    form: []const u8 = "",
    arch: []const u8 = "",
    machine: []const u8 = "",
    fingerprint: []const u8 = "",
    run: []const u8 = "",
};

/// ensure starts the form's VM unless one built from these inputs runs.
fn ensure(t: *Tool, vm: Vm, reset: bool) !Saved {
    const io = t.io;
    const gpa = t.gpa;
    const state_path = try gpa.print("{s}/state.json", .{vm.work});
    var state: Saved = blk: {
        const raw = Dir.cwd().readFileAlloc(
            io,
            state_path,
            gpa,
            .limited(64 << 10),
        ) catch break :blk .{};
        break :blk std.json.parseFromSliceLeaky(
            Saved,
            gpa,
            raw,
            .{ .ignore_unknown_fields = true },
        ) catch .{};
    };
    var wanted = try fingerprint(t, vm.form, vm.plan, vm.generated);
    const changed = !mem.eql(u8, state.fingerprint, &wanted);
    if (reset or changed) {
        if (exists(io, vm.machine)) {
            const result = try std.process.run(
                gpa,
                io,
                .{ .argv = &.{ vm.howl, "delete", vm.name } },
            );
            if (result.term != .exited or result.term.exited != 0)
                return t.fail("{s} delete {s} failed: {s}", .{ vm.howl, vm.name, result.stderr });
        }
        state = .{};
    }
    if (!try running(t, vm)) {
        const fresh = reset or changed or state.run.len == 0;
        const config = try configFor(t, vm.form, vm.work, fresh);
        try t.call(&.{
            vm.howl,      "create",
            vm.name,      "--with",
            vm.generated, "--build",
            "--dev=ssh",  "--disable=secureboot,tpm,ipe",
            "--on",       "qemu",
            "--config",   config,
        }, .{});
        // A first build may create or resolve its package locks. Record the
        // resolved inputs so the next driver edit can reuse this very boot.
        wanted = try fingerprint(t, vm.form, vm.plan, vm.generated);
    }
    if (state.run.len == 0) {
        var bytes: [16]u8 = undefined;
        try io.randomSecure(&bytes);
        state.run = try gpa.dupe(u8, &std.fmt.bytesToHex(bytes, .lower));
    }
    state.form = vm.form.name;
    state.arch = vm.arch;
    state.machine = vm.name;
    state.fingerprint = try gpa.dupe(u8, &wanted);
    try Dir.cwd().createDirPath(io, vm.work);
    try Dir.cwd().writeFile(io, .{
        .sub_path = state_path,
        .data = try std.json.Stringify.valueAlloc(gpa, state, .{ .whitespace = .indent_2 }),
        .flags = .{ .permissions = .fromMode(0o600) },
    });
    return state;
}

fn running(t: *Tool, vm: Vm) !bool {
    if (!exists(t.io, vm.machine)) return false;
    const result = try std.process.run(t.gpa, t.io, .{
        .argv = &.{
            vm.howl,
            "ssh",
            try t.gpa.print("root@{s}", .{vm.name}),
            "--",
            control ++ " ping",
        },
        .timeout = .{ .duration = .{ .raw = .fromSeconds(60), .clock = .awake } },
    });
    return result.term == .exited and result.term.exited == 0;
}

/// configFor is the VM's config: its data key, kept across rebuilds unless
/// fresh, and the form's own test fixtures.
fn configFor(t: *Tool, f: tests.Form, work: []const u8, fresh: bool) ![]const u8 {
    const io = t.io;
    const config = try t.gpa.print("{s}/config", .{work});
    if (fresh) try Dir.cwd().deleteTree(io, config);
    try Dir.cwd().createDirPath(io, work);
    Dir.cwd().createDir(
        io,
        config,
        .fromMode(0o700),
    ) catch |err| if (err != error.PathAlreadyExists) return err;
    const key = try t.gpa.print("{s}/data.key", .{config});
    if (!exists(io, key)) {
        var bytes: [32]u8 = undefined;
        try io.randomSecure(&bytes);
        try Dir.cwd().writeFile(
            io,
            .{ .sub_path = key, .data = &bytes, .flags = .{ .permissions = .fromMode(0o600) } },
        );
    }
    const fixture = try t.gpa.print("{s}/config", .{f.tests});
    if (exists(io, fixture)) try t.call(&.{ fixture, config }, .{});
    return config;
}

/// fingerprint is a digest of what the VM's image is made of: the form's
/// chain without tests, the plan less what uploads as data, the image's
/// programs and locks, the generated overlay, fixtures, and a candidate
/// kernel. Driver sources and YAML assertions are not in it.
fn fingerprint(t: *Tool, f: tests.Form, plan: plans.Plan, generated: []const u8) ![64]u8 {
    const dirs = try t.output(&.{ "build/host/form", "dirs", f.ref });
    var lines = mem.tokenizeScalar(u8, dirs, '\n');
    var chain: std.ArrayList([]const u8) = .empty;
    while (lines.next()) |line| try chain.append(t.gpa, line);
    return digestInputs(t, Dir.cwd(), .{
        .chain = chain.items,
        .plan = plan,
        .tests = f.tests,
        .generated = generated,
        .kernel = t.env.get("KERNEL_ROOTFS"),
    });
}

pub const Inputs = struct {
    chain: []const []const u8,
    plan: plans.Plan,
    tests: []const u8,
    generated: []const u8,
    kernel: ?[]const u8,
};

const image_inputs = [_][]const u8{
    "boot",                      "cmd",                     "lib",
    "files.zig",                 "Makefile",                "build/lock/kernel.lock.json",
    "build/lock/boot.lock.json", "test/native/iterate.zig",
};

/// digestInputs hashes in's paths under root.
pub fn digestInputs(t: *Tool, root: Dir, in: Inputs) ![64]u8 {
    var h = Sha256.init(.{});
    for (in.chain) |dir| try hashTree(t, root, &h, dir, .{ .tests = true });
    var fixed: std.ArrayList(u8) = .empty;
    try fixed.print(t.gpa, "legacy {}\n", .{in.plan.legacy});
    for (in.plan.packages) |p| try fixed.print(t.gpa, "package {s}\n", .{p});
    for (in.plan.prune) |p| try fixed.print(t.gpa, "prune {s}\n", .{p});
    for (in.plan.drivers) |d| {
        try fixed.print(
            t.gpa,
            "driver {s} {s} {s} {s} {d} {}\n",
            .{ d.name, d.source, d.mode, d.user, d.memory, d.readiness },
        );
        try fixed.appendSlice(t.gpa, try tests.service(t.gpa, d, .iterate));
        for (d.allow) |grant| try fixed.print(t.gpa, "allow {s}\n", .{grant});
    }
    h.update(fixed.items);
    for (image_inputs) |path| try hashTree(t, root, &h, path, .{});
    const lock = try t.gpa.print(
        "build/lock/{s}-dev-ssh.lock.json",
        .{std.fs.path.basename(in.generated)},
    );
    try hashTree(t, root, &h, lock, .{});
    try hashTree(t, root, &h, in.generated, .{});
    try hashTree(t, root, &h, in.tests, .{ .sources = true });
    if (in.kernel) |kernel| {
        const stat = root.statFile(t.io, kernel, .{}) catch null;
        if (kernel.len == 0 or stat == null or stat.?.kind != .file)
            return t.fail("KERNEL_ROOTFS must name a kernel archive", .{});
        try hashTree(t, root, &h, kernel, .{});
    }
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

const Exclude = struct {
    /// tests skips a form's test directory, which has its own rule.
    tests: bool = false,
    /// sources skips Zig sources and the plan, which upload as data.
    sources: bool = false,
};

/// hashTree hashes path's names, modes, link targets and contents.
fn hashTree(t: *Tool, root: Dir, h: *Sha256, path: []const u8, exclude: Exclude) !void {
    const io = t.io;
    const stat = root.statFile(io, path, .{ .follow_symlinks = false }) catch {
        h.update("absent\x00");
        h.update(path);
        h.update("\x00");
        return;
    };
    try entry(t, h, root, path, path, stat);
    if (stat.kind != .directory) return;
    var dir = try root.openDir(io, path, .{ .iterate = true });
    defer dir.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var walker = try dir.walk(t.gpa);
    defer walker.deinit();
    while (try walker.next(io)) |e| {
        if (exclude.sources and (mem.endsWith(u8, e.path, ".zig") or
            mem.eql(u8, e.path, "tests.yaml")))
            continue;
        if (exclude.tests and (mem.eql(u8, e.path, "test") or mem.startsWith(u8, e.path, "test/")))
            continue;
        try names.append(t.gpa, try t.gpa.dupe(u8, e.path));
    }
    mem.sort([]const u8, names.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return mem.lessThan(u8, a, b);
        }
    }.less);
    for (names.items) |name| {
        h.update(path);
        h.update("\x00");
        try entry(t, h, dir, name, name, try dir.statFile(io, name, .{ .follow_symlinks = false }));
    }
}

fn entry(
    t: *Tool,
    h: *Sha256,
    dir: Dir,
    sub: []const u8,
    label: []const u8,
    stat: Io.File.Stat,
) !void {
    var buffer: [32]u8 = undefined;
    h.update(label);
    h.update(try std.mem.print(&buffer, "\x00{o}\x00", .{stat.permissions.toMode() & 0o7777}));
    switch (stat.kind) {
        .sym_link => {
            var link: [Dir.max_path_bytes]u8 = undefined;
            h.update("L");
            h.update(link[0..try dir.readLink(t.io, sub, &link)]);
            h.update("\x00");
        },
        .file => {
            h.update("F");
            const file = try dir.openFile(t.io, sub, .{});
            defer file.close(t.io);
            var chunk: [64 << 10]u8 = undefined;
            var reader = file.reader(t.io, &.{});
            while (true) {
                const n = reader.interface.readSliceShort(&chunk) catch return error.ReadFailed;
                if (n == 0) break;
                h.update(chunk[0..n]);
            }
            h.update("\x00");
        },
        .directory => h.update("D\x00"),
        else => h.update("?\x00"),
    }
}

fn runDriver(
    t: *Tool,
    howl: []const u8,
    f: tests.Form,
    arch: []const u8,
    plan: plans.Plan,
    d: plans.Driver,
    phase: plans.Phase,
    work: []const u8,
    machine: []const u8,
    name: []const u8,
    run_id: []const u8,
) !void {
    const gpa = t.gpa;
    const binary = if (d.probes != null) try tests.probeBinary(t, arch) else blk: {
        const out = try gpa.print("{s}/drivers/{s}.new", .{ work, d.name });
        try tests.compile(
            t,
            arch,
            try gpa.print("{s}/{s}", .{ f.tests, d.source }),
            out,
            has(plan.packages, "libcurl-openssl4"),
        );
        break :blk out;
    };
    const context: tests.Run = .{
        .run = run_id,
        .phase = @tagName(phase),
        .timeout_seconds = plan.timeout_seconds,
    };
    const context_path = try gpa.print("{s}/context.new", .{work});
    try Dir.cwd().writeFile(t.io, .{
        .sub_path = context_path,
        .data = try std.json.Stringify.valueAlloc(gpa, context, .{}),
        .flags = .{ .permissions = .fromMode(0o600) },
    });
    const ssh = try sshDetails(t, machine, name);
    try scp(t, ssh, machine, name, binary, try gpa.print("/run/howl-dev/.{s}.new", .{d.name}));
    if (d.probes) |probes| {
        const recipe = try gpa.print("{s}/{s}.json.new", .{ work, d.name });
        try Dir.cwd().writeFile(t.io, .{
            .sub_path = recipe,
            .data = try plans.json(gpa, probes),
            .flags = .{ .permissions = .fromMode(0o600) },
        });
        try scp(
            t,
            ssh,
            machine,
            name,
            recipe,
            try gpa.print("/run/howl-dev/.{s}.json.new", .{d.name}),
        );
    }
    try scp(t, ssh, machine, name, context_path, "/run/config/.native-iterate-context.new");
    const remote = try gpa.print("root@{s}", .{name});
    try t.call(
        &.{ howl, "ssh", remote, "--", try gpa.print(control ++ " install {s}", .{d.name}) },
        .{},
    );
    for (try tests.waitPaths(gpa, d)) |path| {
        const command = try gpa.print(control ++ " ready {s}", .{path});
        for (0..240) |_| {
            const result = try std.process.run(
                gpa,
                t.io,
                .{ .argv = &.{ howl, "ssh", remote, "--", command } },
            );
            if (result.term == .exited and result.term.exited == 0) break;
            try t.io.sleep(.fromMilliseconds(250), .awake);
        } else return t.fail("service path did not appear: {s}", .{path});
    }
    const result = try std.process.run(gpa, t.io, .{
        .argv = &.{ howl, "ssh", remote, "--", try gpa.print(control ++ " run {s}", .{d.name}) },
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(1 << 20),
        .timeout = .{ .duration = .{
            .raw = .fromSeconds(@as(i64, plan.timeout_seconds) + 30),
            .clock = .awake,
        } },
    });
    try Io.File.stdout().writeStreamingAll(t.io, result.stdout);
    try Io.File.stderr().writeStreamingAll(t.io, result.stderr);
    if (result.term != .exited or result.term.exited != 0)
        return t.fail("{s} exited abnormally", .{d.name});
    const count = output(gpa, result.stdout, d, context) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.UnexpectedRecord => return t.fail("{s}: unexpected test record", .{d.name}),
        error.MissingCases => return t.fail("{s}: missing test cases", .{d.name}),
    };
    try t.say("native-iterate: {s}: {d} assertions passed", .{ d.name, count });
}

fn has(names: []const []const u8, name: []const u8) bool {
    for (names) |n| if (mem.eql(u8, n, name)) return true;
    return false;
}

/// output accepts one suite's records over SSH: each declared case of this
/// run and phase, passing, once, and nothing else.
pub fn output(
    gpa: Allocator,
    text: []const u8,
    d: plans.Driver,
    context: tests.Run,
) error{ OutOfMemory, UnexpectedRecord, MissingCases }!usize {
    const phase = std.meta.stringToEnum(
        plans.Phase,
        context.phase,
    ) orelse return error.UnexpectedRecord;
    var seen: std.ArrayList([]const u8) = .empty;
    var lines = mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const at = mem.find(u8, line, "werewolf-test: ") orelse continue;
        const record = std.json.parseFromSliceLeaky(
            std.json.Value,
            gpa,
            line[at + "werewolf-test: ".len ..],
            .{},
        ) catch
            return error.UnexpectedRecord;
        if (record != .object) return error.UnexpectedRecord;
        const r = record.object;
        const case = r.get("case") orelse return error.UnexpectedRecord;
        if (!is(r, "event", "case") or !is(r, "run", context.run) or
            !is(r, "phase", context.phase) or
            !is(r, "suite", d.name) or !is(r, "status", "pass") or case != .string or
            !has(d.cases(phase), case.string) or has(seen.items, case.string))
            return error.UnexpectedRecord;
        try seen.append(gpa, case.string);
    }
    if (seen.items.len != d.cases(phase).len) return error.MissingCases;
    return seen.items.len;
}

fn is(record: std.json.ObjectMap, key: []const u8, want: []const u8) bool {
    const value = record.get(key) orelse return false;
    return value == .string and mem.eql(u8, value.string, want);
}

const Ssh = struct { port: []const u8, key: []const u8 };

/// sshDetails reads a --dev machine's SSH port and howl's developer key.
fn sshDetails(t: *Tool, machine: []const u8, name: []const u8) !Ssh {
    const text = try Dir.cwd().readFileAlloc(
        t.io,
        try t.gpa.print("{s}/machine", .{machine}),
        t.gpa,
        .limited(64 << 10),
    );
    var port: ?[]const u8 = null;
    var dev = false;
    var lines = mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const space = mem.findScalar(u8, line, ' ') orelse continue;
        if (mem.eql(u8, line[0..space], "ssh")) port = line[space + 1 ..];
        if (mem.eql(u8, line[0..space], "dev")) dev = mem.eql(u8, line[space + 1 ..], "1");
    }
    if (!dev) return t.fail("{s} is not a --dev machine", .{name});
    const data = t.variable("XDG_DATA_HOME") orelse
        try t.gpa.print(
            "{s}/.local/share",
            .{t.variable("HOME") orelse return t.fail("no HOME", .{})},
        );
    const key = try t.gpa.print("{s}/howl/keys/dev/ssh-ed25519", .{data});
    if (!exists(t.io, key)) return t.fail("missing Howl developer key: {s}", .{key});
    return .{ .port = port orelse return t.fail("{s} has no SSH port", .{name}), .key = key };
}

fn scp(
    t: *Tool,
    ssh: Ssh,
    machine: []const u8,
    name: []const u8,
    source: []const u8,
    destination: []const u8,
) !void {
    try t.call(&.{
        "scp",
        "-q",
        "-F",
        "/dev/null",
        "-P",
        ssh.port,
        "-i",
        ssh.key,
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        try t.gpa.print("UserKnownHostsFile={s}/known_hosts", .{machine}),
        "-o",
        try t.gpa.print("HostKeyAlias={s}", .{name}),
        source,
        try t.gpa.print("root@127.0.0.1:{s}", .{destination}),
    }, .{});
}

const testing = std.testing;

test "iteration machines are host names unique to their form" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const gatus = try machineName(a, "gatus");
    try testing.expect(mem.startsWith(u8, gatus, "test-gatus-") and
        gatus.len == "test-gatus-".len + 8);
    const long = try machineName(a, "a-very-long-form-n-ame");
    try testing.expect(mem.startsWith(u8, long, "test-a-very-long-form-n-"));
    const cut = try machineName(a, "abcdefghijklmnopq-rest");
    try testing.expect(mem.startsWith(u8, cut, "test-abcdefghijklmnopq-"));
    try testing.expect(!mem.eql(u8, try machineName(a, "abcdefghijklmnopq-other"), cut));
}

test "the VM is rebuilt for what its image is made of, not for driver edits" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var t: Tool = .{ .io = testing.io, .gpa = a, .env = &env };
    const io = t.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const d = tmp.dir;
    for ([_][]const u8{
        "lib/sandbox.zig",               "build/lock/kernel.lock.json",
        "forms/example/form.yaml",       "forms/example/test/driver.zig",
        "forms/example/test/tests.yaml", "forms/example/test/photo.jpg",
        "forms/example/test/payload.c",  "generated/form.yaml",
        "kernel.tar",
    }) |path| {
        if (std.fs.path.dirname(path)) |parent| try d.createDirPath(io, parent);
        try d.writeFile(io, .{ .sub_path = path, .data = "original" });
    }
    const driver: plans.Driver = .{
        .name = "test-example",
        .source = "probes.zig",
        .mode = "probes",
        .seed = &.{"a"},
        .probes = .null,
    };
    var in: Inputs = .{
        .chain = &.{"forms/example"},
        .plan = .{ .packages = &.{"libcurl-openssl4"}, .drivers = &.{driver} },
        .tests = "forms/example/test",
        .generated = "generated",
        .kernel = null,
    };
    const original = try digestInputs(&t, d, in);
    const Change = struct { path: []const u8, rebuilds: bool };
    for ([_]Change{
        .{ .path = "forms/example/test/driver.zig", .rebuilds = false },
        .{ .path = "forms/example/test/tests.yaml", .rebuilds = false },
        .{ .path = "lib/sandbox.zig", .rebuilds = true },
        .{ .path = "build/lock/kernel.lock.json", .rebuilds = true },
        .{ .path = "forms/example/form.yaml", .rebuilds = true },
        .{ .path = "forms/example/test/photo.jpg", .rebuilds = true },
        .{ .path = "forms/example/test/payload.c", .rebuilds = true },
        .{ .path = "generated/form.yaml", .rebuilds = true },
    }) |change| {
        try d.writeFile(io, .{ .sub_path = change.path, .data = "updated" });
        const got = try digestInputs(&t, d, in);
        try testing.expectEqual(change.rebuilds, !mem.eql(u8, &original, &got));
        try d.writeFile(io, .{ .sub_path = change.path, .data = "original" });
    }
    try d.setFilePermissions(io, "lib/sandbox.zig", .fromMode(0o700), .{});
    try testing.expect(!mem.eql(u8, &original, &try digestInputs(&t, d, in)));
    try d.setFilePermissions(io, "lib/sandbox.zig", .fromMode(0o644), .{});
    try d.deleteFile(io, "forms/example/test/photo.jpg");
    try testing.expect(!mem.eql(u8, &original, &try digestInputs(&t, d, in)));
    try d.writeFile(io, .{ .sub_path = "forms/example/test/photo.jpg", .data = "original" });
    try testing.expectEqualStrings(&original, &try digestInputs(&t, d, in));
    // YAML assertions, cases and the phase budget upload as data.
    var edited = driver;
    edited.seed = &.{ "a", "b" };
    edited.probes = .{ .bool = true };
    in.plan = .{
        .timeout_seconds = 1200,
        .packages = &.{"libcurl-openssl4"},
        .drivers = &.{edited},
    };
    try testing.expectEqualStrings(&original, &try digestInputs(&t, d, in));
    // An identity, a package or what is pruned from them is the image's.
    edited.user = "gatus";
    in.plan.drivers = &.{edited};
    try testing.expect(!mem.eql(u8, &original, &try digestInputs(&t, d, in)));
    in.plan = .{ .packages = &.{ "libcurl-openssl4", "postgresql-client" }, .drivers = &.{driver} };
    try testing.expect(!mem.eql(u8, &original, &try digestInputs(&t, d, in)));
    in.plan = .{
        .packages = &.{"libcurl-openssl4"},
        .prune = &.{"usr/bin/scp"},
        .drivers = &.{driver},
    };
    try testing.expect(!mem.eql(u8, &original, &try digestInputs(&t, d, in)));
    in.plan = .{ .packages = &.{"libcurl-openssl4"}, .drivers = &.{driver} };
    // A first build's resolved lock is an input of the next.
    try d.writeFile(
        io,
        .{ .sub_path = "build/lock/generated-dev-ssh.lock.json", .data = "resolved" },
    );
    const locked = try digestInputs(&t, d, in);
    try testing.expect(!mem.eql(u8, &original, &locked));
    // A candidate kernel counts by its bytes, not its time.
    in.kernel = "kernel.tar";
    const kernel = try digestInputs(&t, d, in);
    const stat = try d.statFile(io, "kernel.tar", .{});
    try d.writeFile(io, .{ .sub_path = "kernel.tar", .data = "next kernel" });
    try d.setTimestamps(io, "kernel.tar", .{ .modify_timestamp = .{ .new = stat.mtime } });
    try testing.expect(!mem.eql(u8, &kernel, &try digestInputs(&t, d, in)));
    try d.deleteFile(io, "kernel.tar");
    try testing.expectError(error.Refused, digestInputs(&t, d, in));
    try testing.expect(mem.find(u8, t.why, "kernel archive") != null);
    in.kernel = "";
    try testing.expectError(error.Refused, digestInputs(&t, d, in));
}

test "an iterated suite's records are its own, for this run and phase, each once" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d: plans.Driver = .{
        .name = "test-web",
        .source = "probes.zig",
        .mode = "probes",
        .seed = &.{ "one", "two" },
    };
    const context: tests.Run = .{
        .run = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .phase = "seed",
        .timeout_seconds = 300,
    };
    const line = "werewolf-test: {\"event\":\"case\",\"run\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
        "\"," ++
        "\"phase\":\"seed\",\"suite\":\"test-web\",\"case\":\"CASE\",\"status\":\"pass\"}";
    const one = try mem.replaceOwned(u8, a, line, "CASE", "one");
    const two = try mem.replaceOwned(u8, a, line, "CASE", "two");
    try testing.expectEqual(
        2,
        try output(a, try mem.join(a, "\n", &.{ "noise", one, two }), d, context),
    );
    try testing.expectError(error.MissingCases, output(a, one, d, context));
    try testing.expectError(
        error.UnexpectedRecord,
        output(a, try mem.join(a, "\n", &.{ one, one, two }), d, context),
    );
    for ([_][2][]const u8{
        .{
            "\"pass\"",
            "\"fail\"",
        },
        .{ "aaaa", "bbbb" },
        .{ "\"seed\"", "\"verify\"" },
        .{
            "test-web",
            "test-other",
        },
        .{ "\"case\",", "\"driver\"," },
        .{ "\"one\"", "\"three\"" },
    }) |change| try testing.expectError(error.UnexpectedRecord, output(
        a,
        try mem.join(a, "\n", &.{ try mem.replaceOwned(u8, a, one, change[0], change[1]), two }),
        d,
        context,
    ));
}

test "a foundation's iteration refuses before it makes a VM" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var t: Tool = .{ .io = testing.io, .gpa = a, .env = &env };
    try testing.expectError(
        error.Refused,
        main(&t, &.{ "howl", "minimal", local, "ensure", "seed" }),
    );
    try testing.expect(mem.find(u8, t.why, "shared boot checks") != null);
    try testing.expectError(
        error.Refused,
        main(&t, &.{ "howl", "gatus", local, "ensure", "later" }),
    );
    try testing.expectError(
        error.Refused,
        main(&t, &.{ "howl", "gatus", "riscv64", "ensure", "seed" }),
    );
    try testing.expectError(
        error.Refused,
        main(&t, &.{ "howl", "gatus", local, "explode", "seed" }),
    );
}
