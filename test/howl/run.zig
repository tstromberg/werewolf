//! run runs the cases in cases.yaml: howl, or make, in a scratch tree, with
//! this program standing in for each tool a suite names. See README.md.

const std = @import("std");
const form = @import("form");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Environ = std.process.Environ;
const Map = std.json.ArrayHashMap;
const mem = std.mem;

const usage = "usage: run HOWL CASES.yaml [SUITE...]";

/// Suite is a suite as cases.yaml gives it. Its cases run in order in one
/// tree, which the Step of the suite's name lays out first.
const Suite = struct {
    program: enum { howl, make } = .howl,
    cwd: enum { tree, checkout } = .tree,
    tools: []const []const u8 = &.{},
    env: Map([]const u8) = .{},
    unset: []const []const u8 = &.{},
    record: []const []const u8 = &.{},
    reply: Map([]const Reply) = .{},
    keep: []const []const u8 = &.{},
    cases: []const std.json.Value,
};

const Case = struct {
    args: []const []const u8,
    before: ?Step = null,
    after: ?Check = null,
    env: Map([]const u8) = .{},
    cwd: ?[]const u8 = null,
    reply: Map([]const Reply) = .{},
    status: u8 = 0,
    stdout: []const []const u8 = &.{},
    stderr: []const []const u8 = &.{},
    @"stdout-lacks": []const []const u8 = &.{},
    ran: []const []const u8 = &.{},
    calls: Map(Match) = .{},
    files: []const Content = &.{},
    absent: []const []const u8 = &.{},
    changed: []const []const u8 = &.{},
    unchanged: []const []const u8 = &.{},
};

/// Match checks the arguments of a tool's last call.
const Match = struct {
    starts: []const []const u8 = &.{},
    ends: []const []const u8 = &.{},
    has: []const []const u8 = &.{},
    lacks: []const []const u8 = &.{},
};

/// Content checks a file, or TAR:ENTRY, an entry of a tar: its lines, or
/// strings it holds.
const Content = struct {
    path: []const u8,
    lines: ?[]const []const u8 = null,
    has: []const []const u8 = &.{},
};

/// Reply is how a stub answers a call whose arguments hold every word of when.
const Reply = struct {
    when: []const []const u8 = &.{},
    exit: u8 = 0,
    stdout: []const u8 = "",
    stderr: []const u8 = "",
    action: ?Action = null,
};

/// Action is what a stub does besides answering. apko-lock writes, where
/// --output says, a lock of the config named last, as apko lock would.
const Action = enum { @"apko-lock" };

/// Plan is what the runner tells the stubs: the replies, and the
/// environment variables each call records.
const Plan = struct { record: []const []const u8, tools: Map([]const Reply) };

/// Call is one stub call as recorded: the tool, its arguments, and
/// NAME=VALUE for each recorded variable set.
const Call = struct { tool: []const u8, argv: []const []const u8, env: []const []const u8 };

/// Step lays out files: a suite's tree, by the suite's name, or a change
/// a case makes before it runs.
const Step = enum {
    protections,
    forms,
    lock,
    ssh,
    @"current-user",
    @"engine-gcp",
    @"dev-custom",
    @"dev-ended",
    @"identity-files",
    @"security-keys",
    @"rootfs-bytes",
    @"rootfs-removed",
    @"rootfs-dangling",
    @"rootfs-relinked",
    app,
    @"app-executable",
    @"lock-unbound",
    @"form-created",
    @"form-applied",
    @"form-image",
    @"config-users-empty",
    @"config-users-alice",
    @"fido-removed",
    @"software-removed",
};

/// Check is what a case checks in Zig after the table's checks.
/// dedicated-agent: ssh-add and the ssh after it shared one agent socket,
/// not the caller's, and the socket went with the command.
const Check = enum { @"dedicated-agent" };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (init.environ_map.get("HOWL_STUB_CALLS")) |calls|
        return stub(io, gpa, init.environ_map, args, calls);
    if (args.len < 3) fatal(io, "{s}", .{usage});
    const text = Dir.cwd().readFileAlloc(io, args[2], gpa, .limited(1 << 20)) catch |err|
        fatal(io, "{s}: {t}", .{ args[2], err });
    var diag: form.Diagnostic = .{};
    const doc = form.parse(gpa, text, &diag) catch |err| switch (err) {
        error.Syntax => fatal(io, "{s}:{d}: {s}", .{ args[2], diag.line, diag.why }),
        error.OutOfMemory => return err,
    };
    const howl = Dir.cwd().realPathFileAlloc(io, args[1], gpa) catch |err|
        fatal(io, "{s}: {t}", .{ args[1], err });
    var failed = false;
    for (doc.map) |entry| {
        const wanted = args.len == 3 or for (args[3..]) |name| {
            if (mem.eql(u8, name, entry.key)) break true;
        } else false;
        if (!wanted) continue;
        var why: []const u8 = "";
        const suite, const cases = load(gpa, entry, &why) catch |err| switch (err) {
            error.Table => fatal(io, "{s}: {s}: {s}", .{ args[2], entry.key, why }),
            else => return err,
        };
        var s: Scene = .{
            .io = io,
            .gpa = gpa,
            .name = entry.key,
            .suite = suite,
            .program = if (suite.program == .make) try make(io, gpa, init.environ_map) else howl,
            .self = try std.process.executablePathAlloc(io, gpa),
            .checkout = try Dir.cwd().realPathFileAlloc(io, ".", gpa),
            .env = try init.environ_map.clone(gpa),
        };
        if (!try s.run(cases)) failed = true;
    }
    if (failed) std.process.exit(1);
}

fn fatal(io: Io, comptime fmt: []const u8, args: anytype) noreturn {
    say(io, fmt, args);
    std.process.exit(2);
}

/// say prints a line on standard error, which make shows as the test runs.
fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var out = Io.File.stderr().writerStreaming(io, &buf);
    out.interface.print("howl-cases: " ++ fmt ++ "\n", args) catch return;
    out.interface.flush() catch {};
}

/// make is GNU make: gmake where make may be another.
fn make(io: Io, gpa: Allocator, env: *const Environ.Map) ![]const u8 {
    var dirs = mem.splitScalar(u8, env.get("PATH") orelse "", ':');
    while (dirs.next()) |dir| {
        const path = try std.fs.path.join(gpa, &.{ dir, "gmake" });
        if (Dir.cwd().access(io, path, .{})) |_| return path else |_| {}
    }
    return "make";
}

// --- the stub ----------------------------------------------------------------------------

/// stub is this program run as a tool: it records the call in the calls
/// directory and answers with the first reply the plan gives that tool.
fn stub(
    io: Io,
    gpa: Allocator,
    env: *const Environ.Map,
    args: []const [:0]const u8,
    calls: []const u8,
) !void {
    const tool = std.fs.path.basename(args[0]);
    const argv = try gpa.alloc([]const u8, args.len - 1);
    for (argv, args[1..]) |*a, arg| a.* = arg;
    const plan_path = env.get("HOWL_STUB_PLAN") orelse return error.NoStubPlan;
    const plan_text = try Dir.cwd().readFileAlloc(io, plan_path, gpa, .limited(1 << 20));
    const plan = try std.json.parseFromSliceLeaky(Plan, gpa, plan_text, .{});
    var recorded: std.ArrayList([]const u8) = .empty;
    for (plan.record) |name| if (env.get(name)) |value|
        try recorded.append(gpa, try gpa.print("{s}={s}", .{ name, value }));
    const call: Call = .{ .tool = tool, .argv = argv, .env = recorded.items };
    // One file a call, numbered in order: exclusive creation needs no lock.
    var dir = try Dir.cwd().openDir(io, calls, .{});
    defer dir.close(io);
    for (0..1000) |n| {
        const name = try gpa.print("{d}", .{n});
        var file = dir.createFile(io, name, .{ .exclusive = true }) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => return err,
        };
        defer file.close(io);
        try file.writeStreamingAll(io, try std.json.Stringify.valueAlloc(gpa, call, .{}));
        break;
    } else return error.TooManyCalls;
    const replies = plan.tools.map.get(tool) orelse &.{};
    const r = for (replies) |r| {
        const answers = for (r.when) |word| {
            if (!contains(argv, word)) break false;
        } else true;
        if (answers) break r;
    } else {
        const line = try mem.join(gpa, " ", argv);
        const said = try gpa.print("stub {s}: no reply for {s}\n", .{ tool, line });
        try Io.File.stderr().writeStreamingAll(io, said);
        std.process.exit(97);
    };
    if (r.action) |action| switch (action) {
        .@"apko-lock" => try apkoLock(io, gpa, argv),
    };
    if (r.stdout.len > 0)
        try Io.File.stdout().writeStreamingAll(io, try gpa.print("{s}\n", .{r.stdout}));
    if (r.stderr.len > 0)
        try Io.File.stderr().writeStreamingAll(io, try gpa.print("{s}\n", .{r.stderr}));
    std.process.exit(r.exit);
}

fn contains(list: []const []const u8, word: []const u8) bool {
    for (list) |item| if (mem.eql(u8, item, word)) return true;
    return false;
}

/// apkoLock writes a lock that names one package for each architecture and
/// binds its config's sha256, as apko's does.
fn apkoLock(io: Io, gpa: Allocator, argv: []const []const u8) !void {
    if (argv.len < 2) return error.NoLockOutput;
    const out = for (argv[0 .. argv.len - 1], 0..) |a, i| {
        if (mem.eql(u8, a, "--output")) break argv[i + 1];
    } else return error.NoLockOutput;
    const config = try Dir.cwd().readFileAlloc(io, argv[argv.len - 1], gpa, .limited(1 << 20));
    var sum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(config, &sum, .{});
    var b64: [44]u8 = undefined;
    const Package = struct { url: []const u8 };
    const lock = .{
        .version = "v1",
        .config = .{ .checksum = try gpa.print("sha256-{s}", .{
            std.base64.standard.Encoder.encode(&b64, &sum),
        }) },
        .contents = .{ .packages = [_]Package{
            .{ .url = "https://example.invalid/aarch64/busybox-1.0-r0.apk" },
            .{ .url = "https://example.invalid/x86_64/busybox-1.0-r0.apk" },
        } },
    };
    try Dir.cwd().writeFile(io, .{
        .sub_path = out,
        .data = try std.json.Stringify.valueAlloc(gpa, lock, .{ .whitespace = .indent_2 }),
    });
}

// --- the table ---------------------------------------------------------------------------

/// load reads a suite and its cases from the table, refusing a key, step,
/// check or tool it does not know.
fn load(gpa: Allocator, entry: form.Entry, why: *[]const u8) !struct { Suite, []const Case } {
    const suite = try typed(Suite, gpa, entry.value, why);
    for (suite.reply.map.keys()) |tool| if (!contains(suite.tools, tool))
        return fail(gpa, why, "reply: {s} is not among the tools", .{tool});
    const cases = try gpa.alloc(Case, suite.cases.len);
    const nodes = entry.value.get("cases").?.list;
    for (cases, nodes, 1..) |*c, node, n| {
        c.* = typed(Case, gpa, node, why) catch |err| switch (err) {
            error.Table => return fail(gpa, why, "case {d}: {s}", .{ n, why.* }),
            else => return err,
        };
        for (c.reply.map.keys()) |tool| if (!contains(suite.tools, tool))
            return fail(gpa, why, "case {d}: reply: {s} is not among the tools", .{ n, tool });
        for (c.ran) |tool| if (!contains(suite.tools, tool))
            return fail(gpa, why, "case {d}: ran: {s} is not among the tools", .{ n, tool });
        for (c.calls.map.keys()) |tool| if (!contains(c.ran, tool))
            return fail(gpa, why, "case {d}: calls: {s} is not in ran", .{ n, tool });
    }
    return .{ suite, cases };
}

fn fail(gpa: Allocator, why: *[]const u8, comptime fmt: []const u8, args: anytype) error{Table} {
    why.* = gpa.print(fmt, args) catch "out of memory";
    return error.Table;
}

/// typed reads node as a T: each scalar a string, which std.json reads as
/// the number or name a field takes.
fn typed(comptime T: type, gpa: Allocator, node: form.Node, why: *[]const u8) !T {
    return std.json.parseFromValueLeaky(T, gpa, try toJson(gpa, node), .{}) catch |err| {
        if (node == .map) for (node.map) |e| {
            const known = for (std.meta.fieldNames(T)) |name| {
                if (mem.eql(u8, name, e.key)) break true;
            } else false;
            if (!known) return fail(gpa, why, "no key {s}", .{e.key});
        };
        return fail(gpa, why, "{t}", .{err});
    };
}

fn toJson(gpa: Allocator, node: form.Node) !std.json.Value {
    switch (node) {
        .scalar => |s| return .{ .string = s.text },
        .list => |items| {
            var array: std.json.Array = .init(gpa);
            for (items) |item| try array.append(try toJson(gpa, item));
            return .{ .array = array };
        },
        .map => |entries| {
            var object: std.json.ObjectMap = .empty;
            for (entries) |e| try object.put(gpa, e.key, try toJson(gpa, e.value));
            return .{ .object = object };
        },
    }
}

// --- running -----------------------------------------------------------------------------

/// Scene is a suite running: its scratch tree, environment and the case
/// at hand.
const Scene = struct {
    io: Io,
    gpa: Allocator,
    name: []const u8,
    suite: Suite,
    /// program is howl's path, or make's.
    program: []const u8,
    /// self is this program, which stands in for the tools.
    self: []const u8,
    checkout: []const u8,
    env: Environ.Map,
    /// root is the tree the cases run in, {root} in the table.
    root: []const u8 = "",
    dir: Dir = undefined,
    calls: []const u8 = "",
    plan: []const u8 = "",
    n: usize = 0,
    ok: bool = true,
    /// command is the case's line, for reports.
    command: []const u8 = "",

    /// run runs the cases in order and reports whether all passed. It
    /// keeps the scratch tree of a suite that failed.
    fn run(s: *Scene, cases: []const Case) !bool {
        const io = s.io;
        const gpa = s.gpa;
        var random: [8]u8 = undefined;
        io.random(&random);
        const made = try gpa.print("/tmp/howl-cases-{s}-{s}", .{
            s.name,
            &std.fmt.bytesToHex(random, .lower),
        });
        try Dir.cwd().createDirPath(io, made);
        const scratch = try Dir.cwd().realPathFileAlloc(io, made, gpa);
        s.root = try std.fs.path.join(gpa, &.{ scratch, "root" });
        s.calls = try std.fs.path.join(gpa, &.{ scratch, "calls" });
        s.plan = try std.fs.path.join(gpa, &.{ scratch, "plan.json" });
        try Dir.cwd().createDirPath(io, s.root);
        s.dir = try Dir.cwd().openDir(io, s.root, .{});
        defer s.dir.close(io);
        if (std.meta.stringToEnum(Step, s.name)) |fixture| try s.prepare(fixture);
        for (s.suite.unset) |name| _ = s.env.swapRemove(name);
        if (s.suite.tools.len > 0) {
            const bin = try std.fs.path.join(gpa, &.{ scratch, "bin" });
            try Dir.cwd().createDirPath(io, bin);
            for (s.suite.tools) |tool|
                try Dir.cwd().symLink(io, s.self, try std.fs.path.join(gpa, &.{ bin, tool }), .{});
            const path = s.env.get("PATH") orelse "/usr/bin:/bin";
            try s.env.put("PATH", try gpa.print("{s}:{s}", .{ bin, path }));
            try s.env.put("HOWL_STUB_CALLS", s.calls);
            try s.env.put("HOWL_STUB_PLAN", s.plan);
        }
        var env = s.suite.env.map.iterator();
        while (env.next()) |e| try s.env.put(e.key_ptr.*, try s.expand(e.value_ptr.*));
        const kept = try s.snapshot(s.suite.keep);
        var failed: usize = 0;
        for (cases, 1..) |c, n| {
            s.n = n;
            s.ok = true;
            try s.runCase(c);
            for (s.suite.keep, kept) |path, was| s.same(path, was, "kept");
            if (!s.ok) failed += 1;
        }
        if (failed > 0) {
            say(
                io,
                "suite={s} cases={d} failed={d} tree={s}",
                .{ s.name, cases.len, failed, scratch },
            );
            return false;
        }
        Dir.cwd().deleteTree(io, scratch) catch {};
        say(io, "suite={s} cases={d} passed", .{ s.name, cases.len });
        return true;
    }

    fn expand(s: *Scene, text: []const u8) ![]const u8 {
        return mem.replaceOwned(u8, s.gpa, text, "{root}", s.root);
    }

    fn expandAll(s: *Scene, list: []const []const u8) ![]const []const u8 {
        const out = try s.gpa.alloc([]const u8, list.len);
        for (list, out) |item, *e| e.* = try s.expand(item);
        return out;
    }

    /// bad reports a failed check, after the case's line the first time.
    fn bad(s: *Scene, comptime fmt: []const u8, args: anytype) void {
        if (s.ok) say(s.io, "suite={s} case={d} FAIL {s}", .{ s.name, s.n, s.command });
        s.ok = false;
        say(s.io, "suite={s} case={d} " ++ fmt, .{ s.name, s.n } ++ args);
    }

    fn runCase(s: *Scene, c: Case) !void {
        const io = s.io;
        const gpa = s.gpa;
        if (c.before) |step| try s.prepare(step);
        // A case's replies come before its suite's.
        var tools: Map([]const Reply) = .{};
        for (s.suite.tools) |name| try tools.map.put(gpa, name, try mem.concat(gpa, Reply, &.{
            c.reply.map.get(name) orelse &.{},
            s.suite.reply.map.get(name) orelse &.{},
        }));
        const plan: Plan = .{ .record = s.suite.record, .tools = tools };
        try Dir.cwd().writeFile(io, .{
            .sub_path = s.plan,
            .data = try std.json.Stringify.valueAlloc(gpa, plan, .{}),
        });
        try Dir.cwd().deleteTree(io, s.calls);
        try Dir.cwd().createDirPath(io, s.calls);
        const changed = try s.snapshot(c.changed);
        const unchanged = try s.snapshot(c.unchanged);
        var env = try s.env.clone(gpa);
        var it = c.env.map.iterator();
        while (it.next()) |e| try env.put(e.key_ptr.*, try s.expand(e.value_ptr.*));
        const argv = try mem.concat(gpa, []const u8, &.{ &.{s.program}, try s.expandAll(c.args) });
        s.command = try mem.join(gpa, " ", argv);
        const cwd = if (s.suite.cwd == .checkout)
            s.checkout
        else
            try std.fs.path.join(gpa, &.{ s.root, c.cwd orelse "." });
        const result = std.process.run(gpa, io, .{
            .argv = argv,
            .cwd = .{ .path = cwd },
            .environ_map = &env,
            .stdout_limit = .limited(4 << 20),
            .stderr_limit = .limited(4 << 20),
            .timeout = .{ .duration = .{ .raw = .fromSeconds(120), .clock = .awake } },
        }) catch |err| return s.bad("error={t}", .{err});
        const calls = try s.recorded();
        try s.verify(c, result, calls);
        for (c.changed, changed) |path, was| {
            const now = try s.content(path);
            if (was != null and now != null and mem.eql(u8, was.?, now.?))
                s.bad("unchanged={s}", .{path});
        }
        for (c.unchanged, unchanged) |path, was| s.same(path, was, "changed");
        if (c.after) |check| switch (check) {
            .@"dedicated-agent" => try s.dedicatedAgent(calls),
        };
        if (s.ok or result.stderr.len == 0) return;
        var lines = mem.splitScalar(u8, mem.trimEnd(u8, result.stderr, "\n"), '\n');
        while (lines.next()) |line| s.bad("stderr: {s}", .{line});
    }

    fn verify(s: *Scene, c: Case, result: std.process.RunResult, calls: []const Call) !void {
        const status: ?u8 = if (result.term == .exited) result.term.exited else null;
        if (status != c.status) s.bad("status={d} want={d}", .{ status orelse 255, c.status });
        for (c.stdout) |want| if (mem.find(u8, result.stdout, want) == null)
            s.bad("stdout lacks \"{s}\"", .{want});
        for (c.@"stdout-lacks") |want| if (mem.find(u8, result.stdout, want) != null)
            s.bad("stdout holds \"{s}\"", .{want});
        for (c.stderr) |want| if (mem.find(u8, result.stderr, want) == null)
            s.bad("stderr lacks \"{s}\"", .{want});
        // ran is the tools that ran, in order, a tool run again at once once.
        var ran: std.ArrayList([]const u8) = .empty;
        for (calls) |call| if (ran.items.len == 0 or !mem.eql(u8, ran.getLast(), call.tool))
            try ran.append(s.gpa, call.tool);
        const got = try mem.join(s.gpa, ",", ran.items);
        const want = try mem.join(s.gpa, ",", c.ran);
        if (!mem.eql(u8, got, want)) s.bad("ran=[{s}] want=[{s}]", .{ got, want });
        var matches = c.calls.map.iterator();
        while (matches.next()) |m| try s.match(m.key_ptr.*, m.value_ptr.*, calls);
        for (c.files) |f| s.file(f) catch |err| s.bad("file={s} error={t}", .{ f.path, err });
        for (c.absent) |path| if (try s.content(path) != null) s.bad("present={s}", .{path});
    }

    fn match(s: *Scene, tool: []const u8, m: Match, calls: []const Call) !void {
        var last: ?Call = null;
        for (calls) |call| if (mem.eql(u8, call.tool, tool)) {
            last = call;
        };
        const argv = (last orelse return s.bad("{s} never ran", .{tool})).argv;
        const line = try mem.join(s.gpa, " ", argv);
        const starts = try s.expandAll(m.starts);
        const ends = try s.expandAll(m.ends);
        if (argv.len < starts.len or !equal(argv[0..starts.len], starts))
            s.bad("{s} starts otherwise: {s}", .{ tool, line });
        if (argv.len < ends.len or !equal(argv[argv.len - ends.len ..], ends))
            s.bad("{s} ends otherwise: {s}", .{ tool, line });
        for (try s.expandAll(m.has)) |word| if (!contains(argv, word))
            s.bad("{s} lacks {s}: {s}", .{ tool, word, line });
        for (try s.expandAll(m.lacks)) |word| if (contains(argv, word))
            s.bad("{s} has {s}: {s}", .{ tool, word, line });
    }

    fn file(s: *Scene, f: Content) !void {
        const got = try s.content(f.path) orelse return s.bad("absent={s}", .{f.path});
        if (f.lines) |lines| {
            var want: std.ArrayList(u8) = .empty;
            for (lines) |line| try want.print(s.gpa, "{s}\n", .{try s.expand(line)});
            if (!mem.eql(u8, got, want.items))
                s.bad("file={s} holds \"{f}\" want \"{f}\"", .{
                    f.path,
                    std.zig.fmtString(got),
                    std.zig.fmtString(want.items),
                });
        }
        for (f.has) |want| if (mem.find(u8, got, try s.expand(want)) == null)
            s.bad("file={s} lacks \"{s}\"", .{ f.path, want });
    }

    /// content returns path's bytes, for TAR:ENTRY the entry's, or null if
    /// there is no such file.
    fn content(s: *Scene, path: []const u8) !?[]const u8 {
        const colon = mem.findScalar(u8, path, ':');
        const name = path[0 .. colon orelse path.len];
        const bytes = s.dir.readFileAlloc(s.io, name, s.gpa, .limited(64 << 20)) catch |err|
            switch (err) {
                error.FileNotFound => return null,
                else => return err,
            };
        const at = colon orelse return bytes;
        var reader: Io.Reader = .fixed(bytes);
        var name_buf: [256]u8 = undefined;
        var link_buf: [256]u8 = undefined;
        var it: std.tar.Iterator = .init(&reader, .{
            .file_name_buffer = &name_buf,
            .link_name_buffer = &link_buf,
        });
        while (try it.next()) |entry| {
            if (!mem.eql(u8, entry.name, path[at + 1 ..])) continue;
            var out: Io.Writer.Allocating = .init(s.gpa);
            try it.streamRemaining(entry, &out.writer);
            return out.written();
        }
        return null;
    }

    fn snapshot(s: *Scene, paths: []const []const u8) ![]const ?[]const u8 {
        const out = try s.gpa.alloc(?[]const u8, paths.len);
        for (paths, out) |path, *was| was.* = try s.content(path);
        return out;
    }

    fn same(s: *Scene, path: []const u8, was: ?[]const u8, what: []const u8) void {
        const now = s.content(path) catch return s.bad("{s}={s} unreadable", .{ what, path });
        if (was == null or now == null or
            !mem.eql(u8, was.?, now.?)) s.bad("{s}={s}", .{ what, path });
    }

    /// recorded returns the stubs' calls in the order they were made.
    fn recorded(s: *Scene) ![]const Call {
        var calls: std.ArrayList(Call) = .empty;
        for (0..1000) |n| {
            const path = try s.gpa.print("{s}/{d}", .{ s.calls, n });
            const line = Dir.cwd().readFileAlloc(s.io, path, s.gpa, .limited(1 << 20)) catch |err|
                switch (err) {
                    error.FileNotFound => break,
                    else => return err,
                };
            try calls.append(s.gpa, try std.json.parseFromSliceLeaky(Call, s.gpa, line, .{}));
        }
        return calls.items;
    }

    fn dedicatedAgent(s: *Scene, calls: []const Call) !void {
        var socket: ?[]const u8 = null;
        var started = false;
        for (calls) |call| {
            started = started or mem.eql(u8, call.tool, "ssh-add");
            if (!started) continue;
            const value = for (call.env) |pair| {
                if (mem.cutPrefix(u8, pair, "SSH_AUTH_SOCK=")) |v| break v;
            } else return s.bad("{s} had no agent socket", .{call.tool});
            if (socket) |was| if (!mem.eql(u8, was, value))
                return s.bad("{s} had agent {s}, not {s}", .{ call.tool, value, was });
            socket = value;
        }
        const path = socket orelse return s.bad("ssh-add never ran", .{});
        if (mem.eql(u8, path, s.env.get("SSH_AUTH_SOCK") orelse ""))
            return s.bad("the caller's agent {s} was used", .{path});
        // ssh-agent looks for its parent every 10 seconds.
        for (0..300) |_| {
            Dir.cwd().access(s.io, path, .{}) catch |err| switch (err) {
                error.FileNotFound => return,
                else => return s.bad("agent {s}: {t}", .{ path, err }),
            };
            try s.io.sleep(.fromMilliseconds(50), .awake);
        }
        s.bad("agent {s} outlived its command", .{path});
    }

    /// prepare lays out step's files in the tree.
    fn prepare(s: *Scene, step: Step) !void {
        const io = s.io;
        const d = s.dir;
        const machine = "build/machines/werewolf-run/";
        const message = "forms/minimal/rootfs/message";
        switch (step) {
            .protections => {
                try put(io, d, "forms/minimal/form.yaml", "");
                try put(io, d, "forms/prod-ssh/form.yaml", "base: minimal\n");
                try put(io, d, "forms/playground/form.yaml", "base: minimal\n");
                try put(io, d, machine ++ "engine", "qemu");
                try put(io, d, machine ++ "disk.img", "previous machine must survive refusal");
            },
            .forms => {
                try put(io, d, "forms/minimal/form.yaml", "archs: [aarch64, x86_64]\n");
                try put(io, d, "forms/web/form.yaml", "base: minimal\n");
                try put(io, d, "forms/intel-only/form.yaml", "base: minimal\narchs: [x86_64]\n");
                try put(io, d, "docs/forms-catalog.md", "| [web](../forms/web/README.md) | " ++
                    "A searchable web server. |\n");
                try d.createDirPath(io, "outside");
            },
            .lock => {
                try put(io, d, "forms/minimal/form.yaml", "packages: [busybox]\n");
                try put(io, d, message, "first");
            },
            .ssh => {
                try put(io, d, machine ++ "engine", "lima");
                try put(io, d, machine ++ "lima.yaml", "# werewolf lima: managed\n");
                try d.createDirPath(io, "home/.ssh");
            },
            // The checkout's forms, and three that declare accounts.
            .@"current-user" => {
                var forms = try Dir.cwd().openDir(io, "forms", .{ .iterate = true });
                defer forms.close(io);
                try d.createDirPath(io, "forms");
                var it = forms.iterate();
                while (try it.next(io)) |e| if (e.kind == .directory) try d.symLink(
                    io,
                    try std.fs.path.join(s.gpa, &.{ s.checkout, "forms", e.name }),
                    try s.gpa.print("forms/{s}", .{e.name}),
                    .{ .is_directory = true },
                );
                try put(io, d, "forms/named-users/form.yaml", "base: playground\nusers:\n" ++
                    "  bob:\n    keys: [" ++ security_key ++ "]\n");
                try put(io, d, "forms/empty-users/form.yaml", "base: playground\nusers: {}\n");
                try put(io, d, "forms/existing-current-user/form.yaml", "base: playground\n" ++
                    "users:\n  alice: {}\n");
                try put(io, d, "home/.ssh/fido.pub", security_key ++ "\n");
                try put(
                    io,
                    d,
                    "home/.ssh/software.pub",
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 fixture\n",
                );
                try put(io, d, "root.pub", "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE6 " ++
                    "root-only\n");
            },
            .@"engine-gcp" => try put(io, d, machine ++ "engine", "gcp"),
            .@"dev-custom" => {
                try put(io, d, machine ++ "engine", "lima");
                try put(io, d, machine ++ "dev", "custom\n");
                try put(io, d, machine ++ "dev-address", "192.168.64.40");
            },
            .@"dev-ended" => try d.deleteFile(io, machine ++ "dev"),
            .@"identity-files" => {
                try put(io, d, "admin key", "test identity");
                try put(io, d, "second;key", "test identity");
            },
            .@"security-keys" => {
                try put(io, d, "home/.ssh/fido.pub", "sk-ssh-ed25519@openssh.com AAAA test\n");
                try put(io, d, "home/.ssh/fido", "test private stub");
                try put(io, d, "home/.ssh/software.pub", "ssh-ed25519 AAAA test\n");
                try put(io, d, "home/.ssh/software", "test private stub");
                try put(
                    io,
                    d,
                    "home/.ssh/orphan.pub",
                    "sk-ecdsa-sha2-nistp256@openssh.com AAAA test\n",
                );
            },
            // The same size and times: only the bytes say it changed.
            .@"rootfs-bytes" => {
                const was = try d.statFile(io, message, .{});
                try put(io, d, message, "other");
                try d.setTimestamps(io, message, .{
                    .access_timestamp = if (was.atime) |t| .{ .new = t } else .unchanged,
                    .modify_timestamp = .{ .new = was.mtime },
                });
            },
            .@"rootfs-removed" => try d.deleteFile(io, message),
            .@"rootfs-dangling" => try d.symLink(io, "missing", message, .{}),
            .@"rootfs-relinked" => {
                try d.deleteFile(io, message);
                try d.symLink(io, "elsewhere", message, .{});
            },
            .app => try put(io, d, "app/server", "app"),
            .@"app-executable" => try d.setFilePermissions(io, "app/server", .fromMode(0o755), .{}),
            // The lock an older howl wrote: apko's alone, bound to no inputs.
            .@"lock-unbound" => try put(
                io,
                d,
                "build/lock/minimal.lock.json",
                "{\"version\":\"v1\"}",
            ),
            .@"form-created" => try put(io, d, "forms/minimal/form.yaml", "# Generated by howl\n" ++
                "# create\npackages: [busybox]\n"),
            .@"form-applied" => try put(io, d, "forms/minimal/form.yaml", "# Generated by howl\n" ++
                "# apply --arch aarch64\npackages: [busybox]\n"),
            .@"form-image" => try put(io, d, "forms/minimal/form.yaml", "packages: [busybox]\n" ++
                "services:\n  web:\n    image: example.invalid/web:latest\n"),
            .@"config-users-empty" => try put(io, d, "config/users", ""),
            .@"config-users-alice" => try put(io, d, "config/users", "alice\n"),
            .@"fido-removed" => try d.deleteFile(io, "home/.ssh/fido.pub"),
            .@"software-removed" => try d.deleteFile(io, "home/.ssh/software.pub"),
        }
    }
};

const security_key = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5 fixture";

fn put(io: Io, dir: Dir, path: []const u8, data: []const u8) !void {
    if (std.fs.path.dirname(path)) |parent| try dir.createDirPath(io, parent);
    try dir.writeFile(io, .{ .sub_path = path, .data = data });
}

fn equal(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!mem.eql(u8, x, y)) return false;
    return true;
}

const testing = std.testing;

test "the table is strict: unknown keys, steps and tools are refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    for ([_][]const u8{
        "s:\n  cases:\n    - args: [x]\n      stdout-lack: [y]\n",
        "s:\n  cases:\n    - args: [x]\n      before: nothing\n",
        "s:\n  cases:\n    - args: [x]\n      status: many\n",
        "s:\n  tools: [ssh]\n  cases:\n    - args: [x]\n      ran: [scp]\n",
        "s:\n  tools: [ssh]\n  cases:\n    - args: [x]\n      calls:\n        ssh:\n" ++
            "          ends: [a]\n",
        "s:\n  tools: [ssh]\n  reply:\n    scp:\n      - exit: 1\n  cases:\n    - args: [x]\n",
        "s:\n  program: python3\n  cases:\n    - args: [x]\n",
        "s:\n  cases:\n    - status: 1\n",
    }) |text| {
        var diag: form.Diagnostic = .{};
        const doc = try form.parse(gpa, text, &diag);
        var why: []const u8 = "";
        try testing.expectError(error.Table, load(gpa, doc.map[0], &why));
    }
    var diag: form.Diagnostic = .{};
    const doc = try form.parse(gpa,
        \\s:
        \\  tools: [ssh]
        \\  reply:
        \\    ssh:
        \\      - when: [PubkeyAuthentication=no]
        \\        exit: 255
        \\  cases:
        \\    - args: [ssh]
        \\      status: 42
        \\      ran: [ssh]
        \\      calls:
        \\        ssh:
        \\          ends: ['{root}/key']
        \\
    , &diag);
    var why: []const u8 = "";
    const suite, const cases = try load(gpa, doc.map[0], &why);
    try testing.expectEqual(255, suite.reply.map.get("ssh").?[0].exit);
    try testing.expectEqual(42, cases[0].status);
    try testing.expectEqualStrings("{root}/key", cases[0].calls.map.get("ssh").?.ends[0]);
}
