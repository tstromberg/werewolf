//! host checks a tests.yaml's host suites: cases a client on the build host
//! runs against the booted machine, as an operator's would, through the
//! port QEMU forwards to its 22. test/native-host.zig runs them with
//! OpenSSH's own ssh and sftp, once the console (test/console.zig) has the
//! machine's posture. Their results come back in a file of the host's: the
//! machine's console cannot speak for them. See docs/testing-host.md.

const std = @import("std");
const yaml = @import("form").yaml;
const plan = @import("plan.zig");
const steps = @import("steps.zig");
const mem = std.mem;
const Json = std.json.Value;
const Check = plan.Check;
const Error = plan.Error;

/// Suite is one host suite: its cases by phase, and the data
/// test/native-host.zig runs.
pub const Suite = struct {
    name: []const u8,
    seed: []const []const u8 = &.{},
    verify: []const []const u8 = &.{},
    data: Json,

    pub fn cases(s: Suite, phase: plan.Phase) []const []const u8 {
        return switch (phase) {
            .seed => s.seed,
            .verify => s.verify,
        };
    }
};

/// keys are the run's two keys for root and the form's users, and none:
/// security, its security key; file, its key file; none offers only a
/// password, which a keys-only sshd must not ask for.
pub const keys = [_][]const u8{ "security", "file", "none" };

/// programs are the host's own attacks a step may run, as build/host/NAME
/// from test/NAME.zig: given the run's port, keys and security key
/// provider, then the step's args, each passes by exiting 0.
pub const programs = [_][]const u8{"ssh-su"};

const probes = [_][]const u8{ "ssh", "sftp", "program" };

const expected = std.StaticStringMap([]const []const u8).initComptime(.{
    .{ "ssh", &[_][]const u8{ "status", "stdout", "stderr" } },
    .{ "sftp", &[_][]const u8{ "status", "content", "stderr" } },
    .{ "program", &[_][]const u8{ "status", "stdout", "stderr" } },
});

pub fn suite(c: *Check, node: yaml.Node, data: Json, phase_seconds: u16) Error!Suite {
    const line = c.line;
    try c.fields(data, &.{ "name", "cases" }, &.{ "name", "cases" });
    const name = try c.identity(data.object.get("name").?);
    const cases = data.object.get("cases").?;
    if (cases != .array or cases.array.items.len == 0 or cases.array.items.len > 64)
        return c.fail("expected 1..64 host cases", .{});
    var seed: std.ArrayList([]const u8) = .empty;
    var verify: std.ArrayList([]const u8) = .empty;
    var compiled: std.json.Array = .init(c.gpa);
    for (cases.array.items, node.get("cases").?.list) |entry, case_node| {
        c.line = plan.lineOf(case_node, line);
        try c.fields(entry, &.{ "name", "phases", "steps" }, &.{ "name", "steps" });
        const k = entry.object;
        const case = try c.identity(k.get("name").?);
        if (plan.has(seed.items, case) or plan.has(verify.items, case))
            return c.fail("duplicate case {s}", .{case});
        const phases = try plan.phasesOf(c, k.get("phases"));
        for (phases.array.items) |phase| {
            const list = if (mem.eql(u8, phase.string, "seed")) &seed else &verify;
            try list.append(c.gpa, case);
        }
        const list = k.get("steps").?;
        if (list != .array or list.array.items.len == 0 or list.array.items.len > 32)
            return c.fail("expected 1..32 host steps", .{});
        var out: std.json.Array = .init(c.gpa);
        for (list.array.items, case_node.get("steps").?.list) |item, item_node| {
            c.line = plan.lineOf(item_node, c.line);
            try out.append(try step(c, item, phase_seconds));
        }
        var result: std.json.ObjectMap = .empty;
        try result.put(c.gpa, "name", .{ .string = case });
        try result.put(c.gpa, "phases", phases);
        try result.put(c.gpa, "steps", .{ .array = out });
        try compiled.append(.{ .object = result });
    }
    var out: std.json.ObjectMap = .empty;
    try out.put(c.gpa, "name", .{ .string = name });
    try out.put(c.gpa, "cases", .{ .array = compiled });
    return .{
        .name = name,
        .seed = seed.items,
        .verify = verify.items,
        .data = .{ .object = out },
    };
}

fn step(c: *Check, data: Json, phase_seconds: u16) Error!Json {
    try c.fields(data, &(probes ++ [_][]const u8{ "await", "timeout", "expect" }), &.{"expect"});
    const s = data.object;
    var probe: ?[]const u8 = null;
    for (probes) |p| if (s.contains(p)) {
        if (probe != null) return c.fail("step needs one of ssh, sftp or program", .{});
        probe = p;
    };
    const name = probe orelse return c.fail("step needs one of ssh, sftp or program", .{});
    const request = s.get(name).?;
    if (mem.eql(u8, name, "ssh"))
        try ssh(c, request)
    else if (mem.eql(u8, name, "sftp"))
        try sftp(c, request)
    else
        try program(c, request);
    const wait = if (s.get("await")) |given|
        plan.seconds(given, 0, phase_seconds) orelse
            return c.fail("await must fit within the phase timeout", .{})
    else
        0;
    const timeout = if (s.get("timeout")) |given|
        plan.seconds(given, 1, 300) orelse return c.fail("timeout must be 1s..300s", .{})
    else
        60;
    const expect = s.get("expect").?;
    if (expect != .object or expect.object.count() == 0)
        return c.fail("expect must be a nonempty mapping", .{});
    try c.fields(expect, expected.get(name).?, &.{});
    for (expect.object.keys(), expect.object.values()) |key, v| {
        if (mem.eql(u8, key, "status")) {
            if (v != .integer and v != .object)
                return c.fail("status requires an exit status or a matcher", .{});
            try steps.matcher(c, v);
            continue;
        }
        // The host runs no probe whose output a step could refer to.
        if (v == .object and (v.object.contains("step") or v.object.contains("fixture") or
            v.object.contains("run"))) return c.fail("host steps take no references", .{});
        try steps.textMatcher(c, v);
    }
    var out: std.json.ObjectMap = .empty;
    try out.put(c.gpa, "probe", .{ .string = name });
    try out.put(c.gpa, "request", request);
    try out.put(c.gpa, "expect", expect);
    try out.put(c.gpa, "await_seconds", .{ .integer = wait });
    try out.put(c.gpa, "timeout_seconds", .{ .integer = timeout });
    try out.put(c.gpa, "line", .{ .integer = @intCast(c.line) });
    return .{ .object = out };
}

/// ssh is one login: as user, by key, running command or forwarding stdio
/// to forward, optionally asking for a remote forward or offering only kex.
/// same_host_key holds the machine to the host key it first offered in the
/// run: a key that changed on the reboot refuses the login.
fn ssh(c: *Check, request: Json) Error!void {
    try c.fields(request, &.{
        "user", "key", "command", "forward", "remote_forward", "kex", "same_host_key",
    }, &.{ "user", "key" });
    const r = request.object;
    try login(c, r, &keys);
    if (r.contains("command") and r.contains("forward"))
        return c.fail("ssh runs a command or forwards stdio, not both", .{});
    if (r.get("command")) |command| if (command != .string or command.string.len == 0 or
        command.string.len > 1024 or mem.findAny(u8, command.string, "\x00\n") != null)
        return c.fail("command must be one line of 1..1024 bytes", .{});
    if (r.get("forward")) |forward| if (forward != .string or !steps.hostPort(forward.string))
        return c.fail("forward must be host:port", .{});
    for ([_][]const u8{ "remote_forward", "same_host_key" }) |flag| if (r.get(flag)) |v|
        if (v != .bool) return c.fail("{s} must be boolean", .{flag});
    if (r.get("kex")) |kex| if (kex != .string or kex.string.len == 0 or kex.string.len > 128 or
        !plan.allIn(kex.string, "abcdefghijklmnopqrstuvwxyz0123456789@.,-"))
        return c.fail("kex must name OpenSSH key exchange methods", .{});
}

/// sftp downloads path, as user, by key, after uploading put to it.
fn sftp(c: *Check, request: Json) Error!void {
    try c.fields(request, &.{ "user", "key", "path", "put" }, &.{ "user", "key", "path" });
    const r = request.object;
    try login(c, r, keys[0..2]);
    const path = r.get("path").?;
    // One plain name: sftp's batch language splits on spaces and globs.
    if (path != .string or path.string.len == 0 or path.string.len > 128 or
        path.string[0] == '.' or path.string[0] == '-' or
        !plan.allIn(path.string, "abcdefghijklmnopqrstuvwxyz0123456789._-"))
        return c.fail("path must be a plain file name", .{});
    if (r.get("put")) |put| if (put != .string or put.string.len == 0 or put.string.len > 4096 or
        mem.findScalar(u8, put.string, 0) != null)
        return c.fail("put requires 1..4096 bytes of text", .{});
}

/// program runs one of programs, with plain args such as a mode.
fn program(c: *Check, request: Json) Error!void {
    try c.fields(request, &.{ "name", "args" }, &.{"name"});
    const r = request.object;
    const name = r.get("name").?;
    if (name != .string or !plan.has(&programs, name.string))
        return c.fail("program must be {s}", .{try mem.join(c.gpa, ", ", &programs)});
    if (r.get("args")) |args| {
        const words = try c.strings(args);
        if (words.len > 8) return c.fail("expected 0..8 program args", .{});
        for (words) |word| if (word.len == 0 or word.len > 64 or
            !plan.allIn(word, "abcdefghijklmnopqrstuvwxyz0123456789-"))
            return c.fail("program args are plain words: a-z, 0-9 and -", .{});
    }
}

fn login(c: *Check, r: std.json.ObjectMap, allowed: []const []const u8) Error!void {
    const user = r.get("user").?;
    if (user != .string or !plan.account(user.string)) return c.fail("invalid ssh user", .{});
    const key = r.get("key").?;
    if (key != .string or !plan.has(allowed, key.string))
        return c.fail("key must be {s}", .{try mem.join(c.gpa, ", ", allowed)});
}

const testing = std.testing;

test "host suites compile their steps and phases" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try plan.expectPlan(a,
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
        \\              command: id -u
        \\            await: 30s
        \\            expect:
        \\              status: 0
        \\              stdout:
        \\                matches: "(^|\n)0$"
        \\      - name: sftp-kept
        \\        phases: [verify]
        \\        steps:
        \\          - sftp:
        \\              user: check
        \\              key: file
        \\              path: werewolf-check
        \\            expect:
        \\              content: "werewolf check\n"
        \\      - name: ssh-su
        \\        steps:
        \\          - program:
        \\              name: ssh-su
        \\              args: [prod-ssh]
        \\            timeout: 180s
        \\            expect:
        \\              status: 0
    );
    try testing.expectEqual(1, p.host.len);
    const s = p.host[0];
    try testing.expectEqualStrings("logins", s.name);
    try testing.expectEqual(2, s.seed.len);
    try testing.expectEqual(3, s.verify.len);
    const cases = s.data.object.get("cases").?.array.items;
    const first = cases[0].object.get("steps").?.array.items[0];
    try testing.expectEqual(30, first.object.get("await_seconds").?.integer);
    try testing.expectEqual(60, first.object.get("timeout_seconds").?.integer);
    try testing.expectEqualStrings("ssh", first.object.get("probe").?.string);
    const su = cases[2].object.get("steps").?.array.items[0];
    try testing.expectEqualStrings("program", su.object.get("probe").?.string);
    try testing.expectEqual(180, su.object.get("timeout_seconds").?.integer);
}

test "host steps refuse what the runner could not do as written" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const head = "version: 1\nsuites: []\nhost:\n  - name: logins\n    cases:\n" ++
        "      - name: one\n        steps:\n          - ";
    const root = "ssh:\n              user: root\n              key: file\n";
    const ok = "            expect:\n              status: 0\n";
    for ([_][2][]const u8{
        .{ "ssh:\n              user: root\n              key: agent\n" ++ ok, "key must be" },
        .{ "sftp:\n              user: check\n              key: none\n              path: x\n" ++
            ok, "key must be" },
        .{
            root ++ "              command: id\n              forward: '127.0.0.1:22'\n" ++ ok,
            "not both",
        },
        .{ root ++ "              forward: nowhere\n" ++ ok, "host:port" },
        .{ "sftp:\n              user: check\n              key: file\n              path: 'a " ++
            "b'\n" ++ ok, "plain file name" },
        .{ root ++ "            expect:\n              content: x\n", "unknown field content" },
        .{
            root ++ "            expect:\n              stdout:\n                step: one\n",
            "no references",
        },
        .{ root ++ "            expect:\n              status: '0'\n", "exit status or a matcher" },
        .{ root ++ "            sftp:\n              user: root\n              key: file\n" ++
            "              path: x\n" ++ ok, "one of ssh, sftp or program" },
        .{ root ++ "              same_host_key: 'yes'\n" ++ ok, "same_host_key must be boolean" },
        .{ root ++ "            timeout: 301s\n" ++ ok, "timeout must be 1s..300s" },
        .{ "program:\n              name: rm\n" ++ ok, "program must be ssh-su" },
        .{
            "program:\n              name: ssh-su\n              args: ['--x;y']\n" ++ ok,
            "plain words",
        },
        .{
            "program:\n              name: ssh-su\n            expect:\n              content: x\n",
            "unknown field content",
        },
    }) |refused| try plan.expectRefused(
        a,
        try mem.concat(a, u8, &.{ head, refused[0] }),
        refused[1],
    );
}
