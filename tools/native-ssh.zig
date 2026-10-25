//! ssh readies a native run's host suites (test/native/host.zig): the
//! run's keys and root's authorized_keys, the port QEMU forwards to the
//! machine's 22, and the plan test/native-host.zig runs when test/boot
//! starts it. Then it holds the runner's results to the plan: the runner
//! writes them on the host, where the machine cannot.

const std = @import("std");
const plans = @import("test-plan");
const tests = @import("native-tests.zig");
const Dir = std.Io.Dir;
const mem = std.mem;
const Json = std.json.Value;
const Tool = tests.Tool;
const Form = tests.Form;

pub const runner = "build/host/native-host";

pub const Ssh = struct {
    port: []const u8,
    /// keys is the prefix of the run's keys: KEYS-key and KEYS-sk-key.
    keys: []const u8,
    provider: []const u8,
    /// plan is the runner's plan file.
    plan: []const u8,
};

/// setup makes the run's keys, unless NATIVE_SSH_KEYS names those a
/// generated form already holds, gives root both in config's
/// authorized_keys, as check-form does, and writes the runner's plan.
pub fn setup(
    t: *Tool,
    plan: plans.Plan,
    f: Form,
    work: []const u8,
    config: []const u8,
    run: []const u8,
) !Ssh {
    const gpa = t.gpa;
    const port = t.variable("NATIVE_SSH_PORT") orelse
        return t.fail("{s}: host suites need NATIVE_SSH_PORT", .{f.name});
    _ = std.fmt.parseInt(u16, port, 10) catch return t.fail("invalid NATIVE_SSH_PORT {s}", .{port});
    const provider = t.variable("SSH_SK_PROVIDER") orelse
        return t.fail("{s}: host suites need SSH_SK_PROVIDER", .{f.name});
    const keys = t.variable("NATIVE_SSH_KEYS") orelse blk: {
        const prefix = try gpa.print("{s}/{s}", .{ work, f.name });
        try t.call(&.{ "test/keys", prefix, provider }, .{});
        break :blk prefix;
    };
    var authorized: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "-key.pub", "-sk-key.pub" }) |suffix| {
        const path = try mem.concat(gpa, u8, &.{ keys, suffix });
        try authorized.appendSlice(gpa, Dir.cwd().readFileAlloc(
            t.io,
            path,
            gpa,
            .limited(64 << 10),
        ) catch |err|
            return t.fail("{s}: {t}", .{ path, err }));
    }
    try t.write(try gpa.print("{s}/authorized_keys", .{config}), authorized.items);
    var suites: std.json.Array = .init(gpa);
    for (plan.host) |s| try suites.append(s.data);
    var data: std.json.ObjectMap = .empty;
    try data.put(gpa, "run", .{ .string = run });
    try data.put(gpa, "suites", .{ .array = suites });
    const path = try gpa.print("{s}/host-plan.json", .{work});
    try t.write(path, try plans.json(gpa, .{ .object = data }));
    return .{ .port = port, .keys = keys, .provider = provider, .plan = path };
}

/// forwarded is qemu with the machine's 22 forwarded to port on loopback.
pub fn forwarded(t: *Tool, qemu: []const []const u8, port: []const u8) ![]const []const u8 {
    const out = try t.gpa.dupe([]const u8, qemu);
    for (out) |*arg| if (mem.startsWith(u8, arg.*, "user,id=n0")) {
        arg.* = try t.gpa.print("{s},hostfwd=tcp:127.0.0.1:{s}-:22", .{ arg.*, port });
        return out;
    };
    return t.fail("host suites need QEMU's user network, -netdev user,id=n0", .{});
}

/// tclList is words as test/boot reads one command: each braced, so none
/// may hold a brace or a backslash.
pub fn tclList(t: *Tool, words: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (words, 0..) |word, i| {
        if (mem.findAny(u8, word, "{}\\\n") != null)
            return t.fail("{s}: a path test/boot cannot pass on", .{word});
        try out.print(t.gpa, "{s}{{{s}}}", .{ if (i > 0) " " else "", word });
    }
    return out.items;
}

/// cases is how many host cases run in phase.
pub fn cases(plan: plans.Plan, phase: plans.Phase) usize {
    var n: usize = 0;
    for (plan.host) |s| n += s.cases(phase).len;
    return n;
}

/// results is how many host cases passed in the runner's file at path,
/// refusing one that another run or phase wrote, or that leaves out, adds,
/// repeats or failed a case.
pub fn results(t: *Tool, path: []const u8, plan: plans.Plan, context: tests.Run) !usize {
    const gpa = t.gpa;
    const text = Dir.cwd().readFileAlloc(t.io, path, gpa, .limited(1 << 20)) catch |err|
        return t.fail("{s}: no host results: {t}", .{ path, err });
    const v = std.json.parseFromSliceLeaky(Json, gpa, text, .{}) catch
        return t.fail("{s}: malformed host results", .{path});
    if (v != .object or !is(v.object, "run", context.run) or !is(v.object, "phase", context.phase))
        return t.fail("{s}: host results of another run", .{path});
    const list = v.object.get("cases") orelse return t.fail("{s}: no host cases", .{path});
    if (list != .array) return t.fail("{s}: malformed host results", .{path});
    const phase = std.meta.stringToEnum(plans.Phase, context.phase).?;
    var seen: std.ArrayList([]const u8) = .empty;
    for (list.array.items) |item| {
        if (item != .object) return t.fail("{s}: malformed host results", .{path});
        const r = item.object;
        const suite = for (plan.host) |s| {
            if (is(r, "suite", s.name)) break s;
        } else return t.fail("{s}: an unexpected host suite", .{path});
        const case = r.get("case") orelse return t.fail("{s}: a result names no case", .{path});
        if (case != .string or !plans.has(suite.cases(phase), case.string))
            return t.fail("{s}: an unexpected host case", .{path});
        const key = try gpa.print("{s}\x00{s}", .{ suite.name, case.string });
        if (plans.has(seen.items, key)) return t.fail("{s}: {s} twice", .{ path, case.string });
        if (!is(r, "status", "pass")) {
            const reason = r.get("reason") orelse Json{ .string = "" };
            return t.fail("{s}: {s} failed: {s}", .{
                path,
                case.string,
                if (reason == .string) reason.string else "",
            });
        }
        try seen.append(gpa, key);
    }
    if (seen.items.len != cases(plan, phase))
        return t.fail("{s}: host cases left out", .{path});
    return seen.items.len;
}

fn is(record: std.json.ObjectMap, key: []const u8, want: []const u8) bool {
    const value = record.get(key) orelse return false;
    return value == .string and mem.eql(u8, value.string, want);
}

const testing = std.testing;

const two_cases =
    \\version: 1
    \\suites: []
    \\host:
    \\  - name: logins
    \\    cases:
    \\      - name: ssh-login
    \\        steps:
    \\          - ssh:
    \\              user: root
    \\              key: security
    \\            expect:
    \\              status: 0
    \\      - name: ssh-keys-only
    \\        phases: [seed]
    \\        steps:
    \\          - ssh:
    \\              user: root
    \\              key: none
    \\            expect:
    \\              stderr:
    \\                contains: Permission denied (publickey)
;

test "the machine's 22 is forwarded on QEMU's user network, or the run refuses" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var t = tests.testTool(a, &env);
    const machine = try forwarded(
        &t,
        &.{ "qemu", "-netdev", "user,id=n0,restrict=on", "-m", "1G" },
        "24210",
    );
    try testing.expectEqualStrings(
        "user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:24210-:22",
        machine[2],
    );
    try testing.expectError(
        error.Refused,
        forwarded(&t, &.{ "qemu", "-netdev", "tap,id=n0" }, "1"),
    );
    try testing.expectEqualStrings("{a b} {c}", try tclList(&t, &.{ "a b", "c" }));
    try testing.expectError(error.Refused, tclList(&t, &.{"a}b"}));
}

test "host results count only this run's phase, every case once and passed" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(a);
    var t = tests.testTool(a, &env);
    const plan = try plans.expectPlan(a, two_cases);
    try testing.expectEqual(2, cases(plan, .seed));
    try testing.expectEqual(1, cases(plan, .verify));
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(testing.io, ".", a);
    const path = try std.fs.path.join(a, &.{ dir, "seed-host.json" });
    const seed: tests.Run = .{ .run = "r1", .phase = "seed", .timeout_seconds = 300 };
    const pass = "{\"suite\":\"logins\",\"case\":\"ssh-login\",\"status\":\"pass\"}";
    const other = "{\"suite\":\"logins\",\"case\":\"ssh-keys-only\",\"status\":\"pass\"}";
    for ([_]struct { []const u8, ?usize }{
        .{ "{\"run\":\"r1\",\"phase\":\"seed\",\"cases\":[" ++ pass ++ "," ++ other ++ "]}", 2 },
        .{ "{\"run\":\"r0\",\"phase\":\"seed\",\"cases\":[" ++ pass ++ "," ++ other ++ "]}", null },
        .{ "{\"run\":\"r1\",\"phase\":\"verify\",\"cases\":[" ++ pass ++ "]}", null },
        .{ "{\"run\":\"r1\",\"phase\":\"seed\",\"cases\":[" ++ pass ++ "]}", null },
        .{ "{\"run\":\"r1\",\"phase\":\"seed\",\"cases\":[" ++ pass ++ "," ++ pass ++ "]}", null },
        .{ "{\"run\":\"r1\",\"phase\":\"seed\",\"cases\":[" ++ pass ++ "," ++
            "{\"suite\":\"logins\",\"case\":\"ssh-keys-only\",\"status\":\"fail\",\"reason\":\"x" ++
            "\"}]}", null },
    }) |row| {
        try tmp.dir.writeFile(testing.io, .{ .sub_path = "seed-host.json", .data = row[0] });
        if (row[1]) |n|
            try testing.expectEqual(n, try results(&t, path, plan, seed))
        else
            try testing.expectError(error.Refused, results(&t, path, plan, seed));
    }
    try tmp.dir.deleteFile(testing.io, "seed-host.json");
    try testing.expectError(error.Refused, results(&t, path, plan, seed));
}
