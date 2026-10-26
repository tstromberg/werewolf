//! native-host PLAN PHASE RESULTS runs a native test plan's host suites
//! (test/native/host.zig) in PHASE against the machine the console
//! (test/console.zig) is running, from this host as an operator's client
//! would: OpenSSH's own ssh and sftp, through the port QEMU forwards to the
//! machine's 22. It writes each case's result to RESULTS, a file of the
//! host's, never through the console the machine writes, and exits 0 only
//! if every case held.
//!
//! PLAN is what native-tests wrote for the run, {"run": ID, "suites": [...]}.
//! The environment names NATIVE_SSH_PORT, NATIVE_SSH_KEYS, the prefix of
//! the run's keys (PREFIX-key, a key file, and PREFIX-sk-key, a security
//! key), and SSH_SK_PROVIDER, the software security key that holds it
//! (tools/test-sk.zig).

const std = @import("std");
const host = @import("host");
const match = @import("native/match.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const Json = std.json.Value;

const name = "native-host";

/// common holds every client to the machine alone: no configuration or
/// agent of this host's, and what sshd said at DEBUG1 on stderr.
const common = [_][]const u8{
    "-F", "/dev/null",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=10",
    "-o", "LogLevel=DEBUG1",
    "-o", "IdentitiesOnly=yes",
};

/// Machine is the run's way in: its forwarded port, the prefix of its keys
/// (PREFIX-key and PREFIX-sk-key), their provider, and the directory a
/// step's files and the host key the machine first offered are kept in.
const Machine = struct {
    port: []const u8,
    keys: []const u8,
    provider: []const u8,
    work: []const u8,
};

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, name) catch |err| std.process.fatal("{s}: {t}", .{ name, err });
    c.finish(run(&c));
}

fn run(c: *host.Check) !void {
    if (c.args.len != 4) return c.fail("usage: native-host PLAN PHASE RESULTS", .{});
    const phase = c.args[2];
    if (!mem.eql(u8, phase, "seed") and !mem.eql(u8, phase, "verify"))
        return c.fail("phase is seed or verify, not {s}", .{phase});
    const results = c.args[3];
    _ = c.env.swapRemove("SSH_AUTH_SOCK");
    const work = std.fs.path.dirname(results) orelse ".";
    // sftp's batch language and ssh's known hosts read words: keep paths plain.
    if (mem.findAny(u8, work, " \t\n\"'\\") != null)
        return c.fail("{s}: a directory ssh cannot name", .{work});
    var r: Runner = .{ .c = c, .m = .{
        .port = c.env.get("NATIVE_SSH_PORT") orelse return c.fail("NATIVE_SSH_PORT is unset", .{}),
        .keys = c.env.get("NATIVE_SSH_KEYS") orelse return c.fail("NATIVE_SSH_KEYS is unset", .{}),
        .provider = c.env.get("SSH_SK_PROVIDER") orelse
            return c.fail("SSH_SK_PROVIDER is unset", .{}),
        .work = work,
    } };
    const text = try Io.Dir.cwd().readFileAlloc(c.io, c.args[1], c.gpa, .limited(1 << 20));
    const plan = try std.json.parseFromSliceLeaky(Json, c.gpa, text, .{});
    var out: Io.Writer.Allocating = .init(c.gpa);
    var json: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{ .whitespace = .indent_2 },
    };
    try json.beginObject();
    try json.objectField("run");
    try json.write(plan.object.get("run").?.string);
    try json.objectField("phase");
    try json.write(phase);
    try json.objectField("cases");
    try json.beginArray();
    var failed: usize = 0;
    for (plan.object.get("suites").?.array.items) |s| {
        const suite = s.object.get("name").?.string;
        for (s.object.get("cases").?.array.items) |k| {
            const case = k.object;
            const phases = case.get("phases").?.array.items;
            const runs = for (phases) |p| {
                if (mem.eql(u8, p.string, phase)) break true;
            } else false;
            if (!runs) continue;
            const why = try r.case(case.get("steps").?.array.items);
            const label = case.get("name").?.string;
            if (why) |reason| {
                failed += 1;
                c.say("FAIL   {s} {s}: {s}", .{ suite, label, reason });
            } else c.say("pass   {s} {s}", .{ suite, label });
            try json.write(.{
                .suite = suite,
                .case = label,
                .status = if (why == null) "pass" else "fail",
                .reason = why orelse "",
            });
        }
    }
    try json.endArray();
    try json.endObject();
    try out.writer.writeByte('\n');
    try Io.Dir.cwd().writeFile(c.io, .{ .sub_path = results, .data = out.written() });
    if (failed > 0) return c.fail("{d} host cases failed", .{failed});
}

/// Outcome is what one client said, and for sftp what came back.
const Outcome = struct {
    status: ?u8,
    stdout: []const u8,
    stderr: []const u8,
    content: ?[]const u8 = null,
};

const Runner = struct {
    c: *host.Check,
    m: Machine,

    /// case runs steps in order, each until it holds or its await ends,
    /// and is why the first that did not hold failed, or null.
    fn case(r: *Runner, list: []const Json) !?[]const u8 {
        for (list) |item| {
            const s = item.object;
            const probe = s.get("probe").?.string;
            const request = s.get("request").?.object;
            const expect = s.get("expect").?.object;
            const wait: i64 = s.get("await_seconds").?.integer;
            const timeout: Io.Duration = .fromSeconds(s.get("timeout_seconds").?.integer);
            const deadline = Io.Clock.awake.now(r.c.io).addDuration(.fromSeconds(wait));
            while (true) {
                const got = try r.attempt(probe, request, timeout);
                const why = try judge(r.c.gpa, expect, got) orelse break;
                if (Io.Clock.awake.now(r.c.io).compare(.gte, deadline))
                    return try r.c.gpa.print("line {d}: {s}", .{ s.get("line").?.integer, why });
                try r.c.io.sleep(.fromSeconds(1), .awake);
            }
        }
        return null;
    }

    fn attempt(
        r: *Runner,
        probe: []const u8,
        request: std.json.ObjectMap,
        timeout: Io.Duration,
    ) !Outcome {
        const gpa = r.c.gpa;
        if (!mem.eql(u8, probe, "sftp")) {
            const argv = if (mem.eql(u8, probe, "ssh"))
                try sshArgv(gpa, r.m, request)
            else
                try programArgv(gpa, r.m, request);
            const got = try r.c.run(argv, "", .{ .timeout = timeout });
            return .{ .status = got.code(), .stdout = got.stdout, .stderr = got.stderr };
        }
        const path = request.get("path").?.string;
        const local = try std.fs.path.join(gpa, &.{ r.m.work, try gpa.print("sftp-{s}", .{path}) });
        const back = try gpa.print("{s}.back", .{local});
        Io.Dir.cwd().deleteFile(r.c.io, back) catch |err| switch (err) {
            error.FileNotFound => {},
            else => |e| return e,
        };
        var batch: std.ArrayList(u8) = .empty;
        if (request.get("put")) |put| {
            try Io.Dir.cwd().writeFile(r.c.io, .{ .sub_path = local, .data = put.string });
            try batch.print(gpa, "put {s} {s}\n", .{ local, path });
        }
        try batch.print(gpa, "get {s} {s}\n", .{ path, back });
        const batch_path = try gpa.print("{s}.batch", .{local});
        try Io.Dir.cwd().writeFile(r.c.io, .{ .sub_path = batch_path, .data = batch.items });
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(gpa, &.{ "sftp", "-P", r.m.port });
        try argv.appendSlice(gpa, &common);
        try argv.appendSlice(gpa, try known(gpa, r.m, false));
        try credentials(gpa, &argv, r.m, request.get("key").?.string);
        try argv.appendSlice(gpa, &.{
            "-b",
            batch_path,
            try gpa.print("{s}@127.0.0.1", .{request.get("user").?.string}),
        });
        const got = try r.c.run(argv.items, "", .{ .timeout = timeout });
        const content = Io.Dir.cwd().readFileAlloc(r.c.io, back, gpa, .limited(1 << 20)) catch |err|
            switch (err) {
                error.FileNotFound => null,
                else => |e| return e,
            };
        return .{
            .status = got.code(),
            .stdout = got.stdout,
            .stderr = got.stderr,
            .content = content,
        };
    }
};

/// sshArgv is one ssh login, as host.zig validated it: a command, by
/// default true, or stdio forwarded to forward.
fn sshArgv(gpa: Allocator, m: Machine, request: std.json.ObjectMap) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{ "ssh", "-p", m.port });
    try argv.appendSlice(gpa, &common);
    const same = if (request.get("same_host_key")) |v| v.bool else false;
    try argv.appendSlice(gpa, try known(gpa, m, same));
    try credentials(gpa, &argv, m, request.get("key").?.string);
    if (request.get("kex")) |kex| try argv.appendSlice(gpa, &.{
        "-o",
        try gpa.print("KexAlgorithms={s}", .{kex.string}),
    });
    if (request.get("remote_forward")) |remote| if (remote.bool) try argv.appendSlice(gpa, &.{
        "-o", "ExitOnForwardFailure=yes", "-R", "127.0.0.1:0:127.0.0.1:22",
    });
    if (request.get("forward")) |forward| try argv.appendSlice(gpa, &.{ "-W", forward.string });
    try argv.append(gpa, try gpa.print("{s}@127.0.0.1", .{request.get("user").?.string}));
    if (request.get("forward") == null)
        try argv.append(gpa, if (request.get("command")) |command| command.string else "true");
    return argv.items;
}

/// programArgv runs a host program (test/native/host.zig's programs) on the
/// machine: build/host/NAME PORT KEYS PROVIDER ARGS...
fn programArgv(gpa: Allocator, m: Machine, request: std.json.ObjectMap) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{
        try gpa.print("build/host/{s}", .{request.get("name").?.string}),
        m.port,
        m.keys,
        m.provider,
    });
    if (request.get("args")) |args| for (args.array.items) |arg| try argv.append(gpa, arg.string);
    return argv.items;
}

/// known is how a client takes the machine's host key: any, kept nowhere,
/// or, for the same host key, the one the machine first offered in the run.
fn known(gpa: Allocator, m: Machine, same: bool) ![]const []const u8 {
    if (!same) return &.{ "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null" };
    return gpa.dupe([]const u8, &.{
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        try gpa.print("UserKnownHostsFile={s}/known_hosts", .{m.work}),
    });
}

/// credentials is how a client proves who it is: the run's security key,
/// its key file, or none, offering only a password.
fn credentials(
    gpa: Allocator,
    argv: *std.ArrayList([]const u8),
    m: Machine,
    key: []const u8,
) !void {
    if (mem.eql(u8, key, "security")) try argv.appendSlice(gpa, &.{
        "-o",
        try gpa.print("SecurityKeyProvider={s}", .{m.provider}),
        "-i",
        try gpa.print("{s}-sk-key", .{m.keys}),
    }) else if (mem.eql(u8, key, "file")) try argv.appendSlice(gpa, &.{
        "-i",
        try gpa.print("{s}-key", .{m.keys}),
    }) else try argv.appendSlice(gpa, &.{
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "PreferredAuthentications=password,keyboard-interactive",
    });
}

/// judge is why got does not meet expect, or null when it does.
fn judge(gpa: Allocator, expect: std.json.ObjectMap, got: Outcome) !?[]const u8 {
    for (expect.keys(), expect.values()) |key, want| {
        const value: Json = if (mem.eql(u8, key, "status"))
            .{ .integer = got.status orelse return "the client ended by a signal" }
        else if (mem.eql(u8, key, "stdout"))
            .{ .string = got.stdout }
        else if (mem.eql(u8, key, "stderr"))
            .{ .string = got.stderr }
        else
            .{ .string = got.content orelse return try gpa.print(
                "nothing came back (exit {?d}): {s}",
                .{ got.status, host.check.tail(got.stderr, 600) },
            ) };
        const holds = match.matches(gpa, value, want) catch |err|
            return try gpa.print("{s}: {t}", .{ key, err });
        if (!holds) return try gpa.print("{s}: got {s} (exit {?d}; stderr: {s})", .{
            key,
            if (value == .integer)
                try gpa.print("{d}", .{value.integer})
            else
                host.check.tail(value.string, 600),
            got.status,
            host.check.tail(got.stderr, 600),
        });
    }
    return null;
}

const testing = std.testing;

test "logins take only the run's key, or none" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const request = try std.json.parseFromSliceLeaky(Json, a,
        \\{"user": "bastion", "key": "security", "forward": "127.0.0.3:22",
        \\ "kex": "curve25519-sha256", "remote_forward": true}
    , .{});
    const m: Machine = .{
        .port = "24210",
        .keys = "/k/bastion-check",
        .provider = "/p/test-sk.so",
        .work = "/w",
    };
    const line = try host.check.join(a, try sshArgv(a, m, request.object));
    try testing.expect(mem.startsWith(u8, line, "ssh -p 24210 -F /dev/null "));
    try testing.expect(mem.find(
        u8,
        line,
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ",
    ) != null);
    try testing.expect(mem.endsWith(
        u8,
        line,
        "-o SecurityKeyProvider=/p/test-sk.so -i /k/bastion-check-sk-key " ++
            "-o KexAlgorithms=curve25519-sha256 -o ExitOnForwardFailure=yes " ++
            "-R 127.0.0.1:0:127.0.0.1:22 -W 127.0.0.3:22 bastion@127.0.0.1",
    ));
    const password = try std.json.parseFromSliceLeaky(Json, a,
        \\{"user": "root", "key": "none", "command": "id -u", "same_host_key": true}
    , .{});
    const plain = try host.check.join(a, try sshArgv(a, m, password.object));
    try testing.expect(mem.endsWith(u8, plain, "-o PubkeyAuthentication=no " ++
        "-o PreferredAuthentications=password,keyboard-interactive root@127.0.0.1 'id -u'"));
    try testing.expect(mem.find(u8, plain, "-i ") == null);
    // The first host key the run saw is kept; another refuses the login.
    try testing.expect(mem.find(u8, plain, "-o StrictHostKeyChecking=accept-new " ++
        "-o UserKnownHostsFile=/w/known_hosts ") != null);
    try testing.expect(mem.find(u8, plain, "UserKnownHostsFile=/dev/null") == null);
    const su = try std.json.parseFromSliceLeaky(Json, a,
        \\{"name": "ssh-su", "args": ["prod-ssh"]}
    , .{});
    try testing.expectEqualStrings(
        "build/host/ssh-su 24210 /k/bastion-check /p/test-sk.so prod-ssh",
        try host.check.join(a, try programArgv(a, m, su.object)),
    );
}

test "a result holds only when every expectation does" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const expect = try std.json.parseFromSliceLeaky(Json, a,
        \\{"status": {"not_equals": 0}, "stderr": {"contains": "administratively prohibited"}}
    , .{});
    try testing.expectEqual(null, try judge(a, expect.object, .{
        .status = 255,
        .stdout = "",
        .stderr = "channel 0: open failed: administratively prohibited: open failed\n",
    }));
    // A machine that never answered refuses nothing.
    const why = (try judge(a, expect.object, .{
        .status = 255,
        .stdout = "",
        .stderr = "ssh: connect to host 127.0.0.1 port 24210: Connection refused\n",
    })).?;
    try testing.expect(mem.startsWith(u8, why, "stderr: got ssh: connect"));
    const back = try std.json.parseFromSliceLeaky(
        Json,
        a,
        "{\"content\": \"werewolf check\\n\"}",
        .{},
    );
    try testing.expect((try judge(
        a,
        back.object,
        .{ .status = 1, .stdout = "", .stderr = "" },
    )) != null);
    try testing.expectEqual(null, try judge(a, back.object, .{
        .status = 0,
        .stdout = "",
        .stderr = "",
        .content = "werewolf check\n",
    }));
}
