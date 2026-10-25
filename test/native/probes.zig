//! Shared test runner; data selects fixed probes, never shell code.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Json = std.json.Value;
const driver = @import("driver.zig");
const http = @import("fetch.zig");
const match = @import("match.zig");
const system = @import("system.zig");
const command = @import("exec.zig");
const process = @import("process.zig");
const tcp = @import("tcp.zig");
const tree = @import("tree.zig");
const udp = @import("udp.zig");
const writes = @import("write.zig");
const Step = struct {
    name: []const u8,
    probe: []const u8,
    request: Json,
    expect: Json,
    await_seconds: u16,
    timeout_seconds: u16 = 10,
    line: usize,
};
const Case = struct { name: []const u8, phases: []const []const u8, steps: []const Step };
const Plan = struct { source: []const u8, fixtures: Json, cases: []const Case };

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 and args.len != 5) return error.Usage;
    const name = args[1];
    const ctx = try driver.Run.load(io, a, args[3]);
    const path = if (args.len == 5)
        args[4]
    else
        try a.print("/usr/share/werewolf/tests/{s}/probes.json", .{name});
    const plan = try std.json.parseFromSliceLeaky(Plan, a, try system.read(io, a, path), .{});
    var passed = true;
    for (plan.cases) |case| {
        var selected = false;
        for (case.phases) |phase| selected = selected or std.mem.eql(u8, phase, ctx.phase);
        if (!selected) continue;
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        var run: Workflow = .{
            .io = io,
            .a = arena.allocator(),
            .ctx = ctx,
            .plan = plan,
            .suite = name,
        };
        defer if (run.client) |*client| client.deinit();
        var ok = true;
        for (case.steps) |step| {
            run.step = step;
            run.failures = .empty;
            const success = run.execute(step) catch |err| blk: {
                try run.failures.append(
                    run.a,
                    .{
                        .field = "operation",
                        .got = system.text(@errorName(err)),
                        .want = system.text("successful probe"),
                    },
                );
                break :blk false;
            };
            if (!success) {
                try driver.emit(io, .{
                    .event = "case",
                    .run = ctx.run,
                    .phase = ctx.phase,
                    .suite = name,
                    .case = case.name,
                    .status = "fail",
                    .source = plan.source,
                    .line = step.line,
                    .step = step.name,
                    .probe = step.probe,
                    .failures = run.failures.items,
                });
                ok = false;
                break; // Later steps depend on this workflow's successful prefix.
            }
        }
        if (ok) try ctx.result(io, name, case.name, true);
        passed = passed and ok;
    }
    if (!passed) std.process.exit(1);
}

// A response body may contain arbitrary bytes; a JSON round trip changes them.
fn copyValue(a: Allocator, value: Json) Allocator.Error!Json {
    return switch (value) {
        .string => |text| .{ .string = try a.dupe(u8, text) },
        .number_string => |text| .{ .number_string = try a.dupe(u8, text) },
        .array => |items| blk: {
            var result: std.json.Array = .init(a);
            for (items.items) |item| try result.append(try copyValue(a, item));
            break :blk .{ .array = result };
        },
        .object => |object| blk: {
            var result = system.object(a);
            var it = object.iterator();
            while (it.next()) |entry| try result.object.put(
                a,
                try a.dupe(u8, entry.key_ptr.*),
                try copyValue(a, entry.value_ptr.*),
            );
            break :blk result;
        },
        else => value,
    };
}

const Failure = struct { field: []const u8, got: Json, want: Json };

fn onlyPort(listeners: Json, port: i64) Json {
    var result = listeners;
    var count: usize = 0;
    for (result.array.items) |entry| {
        if (entry.object.get("port").?.integer != port) continue;
        result.array.items[count] = entry;
        count += 1;
    }
    result.array.items = result.array.items[0..count];
    return result;
}

const Workflow = struct {
    io: Io,
    a: Allocator,
    ctx: driver.Run,
    plan: Plan,
    suite: []const u8,
    step: Step = undefined,
    previous: std.StringHashMapUnmanaged(Json) = .empty,
    client: ?http.Client = null,
    sensitive: bool = false,
    failures: std.ArrayList(Failure) = .empty,

    fn resolve(w: *Workflow, value: Json) anyerror!Json {
        if (value == .object) {
            if (value.object.contains("run")) return system.text(w.ctx.run);
            if (value.object.get("fixture")) |fixture| {
                w.sensitive = true;
                const path = w.plan.fixtures.object.get(
                    fixture.string,
                ) orelse return error.UnknownFixture;
                const bytes = try system.read(w.io, w.a, path.string);
                return system.text(if (value.object.contains("raw"))
                    bytes
                else
                    std.mem.trimEnd(u8, bytes, "\r\n"));
            }
            if (value.object.get("step")) |step| {
                w.sensitive = true;
                const prior = w.previous.get(step.string) orelse return error.MissingCapture;
                if (value.object.get("json")) |pointer| {
                    return match.pointer(
                        try std.json.parseFromSliceLeaky(Json, w.a, try jsonOutput(prior), .{}),
                        pointer.string,
                    );
                }
                if (value.object.get("header")) |header| {
                    const headers = prior.object.get("headers") orelse return error.MissingCapture;
                    return capture(headers.object.get(header.string));
                }
                if (value.object.get("cookie")) |cookie| {
                    const cookies = prior.object.get("cookies") orelse return error.MissingCapture;
                    return capture(cookies.object.get(cookie.string));
                }
                if (value.object.get("regex")) |pattern| {
                    return system.text(try match.extract(
                        w.a,
                        pattern.string,
                        try jsonOutput(prior),
                    ));
                }
                if (value.object.get(
                    "body",
                )) |_| return prior.object.get("body") orelse error.MissingCapture;
                return error.InvalidCapture;
            }
            var result = system.object(w.a);
            var it = value.object.iterator();
            while (it.next()) |entry| try result.object.put(
                w.a,
                entry.key_ptr.*,
                try w.resolve(entry.value_ptr.*),
            );
            return result;
        }
        if (value == .array) {
            var result: std.json.Array = .init(w.a);
            for (value.array.items) |item| try result.append(try w.resolve(item));
            return .{ .array = result };
        }
        return value;
    }

    fn execute(w: *Workflow, step: Step) !bool {
        const req = try w.resolve(step.request);
        const expected = try w.resolve(step.expect);
        try validateRequest(step.probe, req);
        if (std.mem.eql(u8, step.probe, "fetch") and
            w.client == null) w.client = try http.Client.init(w.a);
        if (std.mem.eql(
            u8,
            step.probe,
            "fetch",
        ) and (req.object.contains("bearer") or req.object.contains("authorization") or
            req.object.contains("session") or
            req.object.contains("headers") or req.object.contains("json") or
            req.object.contains("body") or req.object.contains("form") or
            req.object.contains("multipart"))) w.sensitive = true;
        const deadline = Io.Clock.awake.now(
            w.io,
        ).addDuration(.fromSeconds(if (step.await_seconds > 0)
            step.await_seconds
        else
            step.timeout_seconds));
        while (true) {
            var attempt: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer attempt.deinit();
            const original = w.a;
            w.a = attempt.allocator();
            const remaining = Io.Clock.awake.now(w.io).durationTo(deadline).toMilliseconds();
            const got = w.probe(
                step.probe,
                req,
                expected,
                @max(1, @min(remaining, @as(i64, step.timeout_seconds) * 1000)),
            ) catch |err| {
                w.a = original;
                const transient = switch (err) {
                    error.ConnectionRefused,
                    error.TlsHandshake,
                    error.Timeout,
                    error.ServiceNotRunning,
                    error.ProcessSetChanged,
                    error.FileNotFound,
                    error.MountNotFound,
                    => true,
                    else => false,
                };
                if (!transient or step.await_seconds == 0 or
                    Io.Clock.awake.now(w.io).compare(.gte, deadline)) return err;
                try w.io.sleep(.fromMilliseconds(100), .awake);
                continue;
            };
            w.a = original;
            w.failures = .empty;
            const ok = try w.check(step.probe, got, expected);
            if (ok) {
                // Captures outlive this attempt, but retries release their response data.
                try w.previous.put(original, step.name, try copyValue(original, got));
                return true;
            }
            if (step.await_seconds == 0 or
                Io.Clock.awake.now(w.io).compare(.gte, deadline)) return false;
            try w.io.sleep(.fromMilliseconds(100), .awake);
        }
    }

    fn probe(
        w: *Workflow,
        name: []const u8,
        request: Json,
        expect: Json,
        timeout_ms: i64,
    ) !Json {
        if (std.mem.eql(u8, name, "fetch")) {
            return w.client.?.request(request, timeout_ms, w.a);
        }
        if (std.mem.eql(u8, name, "file")) return system.file(w.io, w.a, request.string, expect);
        if (std.mem.eql(u8, name, "service")) {
            var got = try system.service(w.io, w.a, request.string);
            try process.add(w.io, w.a, &got, expect);
            if (expect.object.contains("connect_rules")) {
                const rules = try system.read(w.io, w.a, "/usr/share/werewolf/net");
                for (got.object.get("members").?.array.items) |*member| {
                    const uid = member.object.get("uids").?.array.items[1].integer;
                    try member.object.put(w.a, "connect_rules", try system.connectRules(
                        w.a,
                        rules,
                        @intCast(uid),
                    ));
                }
            }
            return got;
        }
        if (std.mem.eql(u8, name, "listeners")) {
            const scoped = request == .object;
            const proto = if (scoped) request.object.get("protocol").?.string else request.string;
            const listeners = try system.listeners(w.io, w.a, proto);
            return if (scoped)
                onlyPort(listeners, request.object.get("port").?.integer)
            else
                listeners;
        }
        if (std.mem.eql(u8, name, "mount")) return system.mount(w.io, w.a, request.string);
        if (std.mem.eql(u8, name, "exec")) return w.exec(request, timeout_ms);
        if (std.mem.eql(u8, name, "tree"))
            return tree.probe(w.io, w.a, request, expect, timeout_ms);
        if (std.mem.eql(u8, name, "write")) return writes.probe(w.io, w.a, request);
        if (std.mem.eql(u8, name, "tcp")) return tcp.probe(w.io, w.a, request, timeout_ms);
        if (std.mem.eql(u8, name, "squat")) {
            try udp.squatter(w.io, w.a, request.string);
            return system.object(w.a);
        }
        return error.UnknownProbe;
    }

    fn exec(w: *Workflow, request: Json, timeout_ms: i64) !Json {
        var argv: std.ArrayList([]const u8) = .empty;
        for (request.object.get("argv").?.array.items) |arg| {
            if (arg != .string) return error.InvalidArgument;
            try argv.append(w.a, arg.string);
        }
        var env: std.process.Environ.Map = .init(w.a);
        try env.put("LANG", "C.UTF-8");
        if (request.object.get("env")) |environment| {
            var it = environment.object.iterator();
            while (it.next()) |entry| try env.put(entry.key_ptr.*, entry.value_ptr.string);
        }
        const result = try command.run(
            w.a,
            w.io,
            argv.items,
            &env,
            if (request.object.get("stdin")) |input| input.string else "",
            timeout_ms,
        );
        if (result.term != .exited) return error.ClientCrashed;
        var got = system.object(w.a);
        try got.object.put(w.a, "exit", system.number(result.term.exited));
        try got.object.put(w.a, "stdout", system.text(result.stdout));
        try got.object.put(w.a, "stderr", system.text(result.stderr));
        return got;
    }

    fn check(w: *Workflow, probe_name: []const u8, actual: Json, expected: Json) !bool {
        // A starting proxy may return an empty 502. Check the protocol status
        // before parsing a body whose format belongs to the expected response.
        if (std.mem.eql(u8, probe_name, "fetch")) {
            if (expected.object.get("status")) |want| {
                if (!try w.compare("status", actual.object.get("status") orelse
                    return error.MissingField, want)) return false;
            }
        }
        if (std.mem.eql(u8, probe_name, "exec")) {
            if (expected.object.get("exit")) |want| {
                if (!try w.compare("exit", actual.object.get("exit") orelse
                    return error.MissingField, want)) return false;
            }
        }
        if (std.mem.eql(u8, probe_name, "tcp")) {
            if (actual.object.get("failed").?.integer == 0) return true;
            try w.failure(
                actual.object.get("field").?.string,
                actual.object.get("received").?,
                actual.object.get("want").?,
            );
            return false;
        }
        var ok = true;
        const audit = std.mem.eql(u8, probe_name, "tree");
        if (audit) for (actual.object.get("violations").?.array.items) |v| {
            const field = v.object.get("field").?.string;
            try w.failure(field, v.object.get("entry").?, expected.object.get(field).?);
            ok = false;
        };
        var it = expected.object.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const want = entry.value_ptr.*;
            // An audit judged each entry as it walked.
            if (audit and !std.mem.eql(u8, key, "entries") and !std.mem.eql(u8, key, "files"))
                continue;
            if (std.mem.eql(u8, probe_name, "service") and !std.mem.eql(u8, key, "processes") and
                !std.mem.eql(u8, key, "pids_max") and !std.mem.eql(u8, key, "comm") and
                !std.mem.eql(u8, key, "cmdline"))
            {
                for (actual.object.get("members").?.array.items) |member| {
                    if (std.mem.eql(u8, key, "user")) {
                        const uid = if (want == .string)
                            try system.account(w.io, w.a, want.string)
                        else
                            @as(u32, @intCast(want.integer));
                        for (member.object.get("uids").?.array.items) |id| ok = (try w.compare(
                            key,
                            id,
                            system.number(uid),
                        )) and ok;
                    } else if (std.mem.eql(u8, key, "uid")) {
                        for (member.object.get("uids").?.array.items) |id|
                            ok = (try w.compare(key, id, want)) and ok;
                    } else if (std.mem.eql(u8, key, "groups")) {
                        ok = (try w.compare(key, member.object.get(key).?, try w.groups(want))) and
                            ok;
                    } else {
                        ok = (try w.compare(
                            key,
                            member.object.get(key) orelse return error.UnknownServiceField,
                            want,
                        )) and ok;
                    }
                }
                continue;
            }
            if (std.mem.eql(u8, probe_name, "listeners")) {
                if (want != .array) return error.InvalidMatcher;
                var matched: usize = 0;
                for (want.array.items) |needle| {
                    var found = false;
                    for (actual.array.items) |listener| {
                        var fields = needle.object.iterator();
                        var same = true;
                        while (fields.next()) |f| same = same and
                            match.equal(
                                listener.object.get(f.key_ptr.*) orelse return error.MissingField,
                                f.value_ptr.*,
                            );
                        found = found or same;
                    }
                    if (found) matched += 1;
                }
                const success = if (std.mem.eql(u8, key, "absent"))
                    matched == 0
                else
                    matched == want.array.items.len and (!std.mem.eql(u8, key, "equals") or
                        actual.array.items.len == matched);
                if (!success) {
                    try w.failure(key, actual, want);
                    ok = false;
                }
                continue;
            }
            if (std.mem.eql(
                u8,
                probe_name,
                "mount",
            ) and (std.mem.eql(u8, key, "flags") or std.mem.eql(u8, key, "absent_flags"))) {
                for (want.array.items) |flag| {
                    var found = false;
                    for (actual.object.get("flags").?.array.items) |item| found = found or
                        match.equal(item, flag);
                    if (found == std.mem.eql(u8, key, "absent_flags")) {
                        try w.failure(key, actual.object.get("flags").?, want);
                        ok = false;
                    }
                }
                continue;
            }
            if (std.mem.eql(u8, key, "json")) {
                const parsed = try std.json.parseFromSliceLeaky(
                    Json,
                    w.a,
                    try jsonOutput(actual),
                    .{},
                );
                var paths = want.object.iterator();
                while (paths.next()) |path| {
                    const value = match.pointer(parsed, path.key_ptr.*) catch |err| {
                        try w.failure(
                            path.key_ptr.*,
                            system.text(@errorName(err)),
                            path.value_ptr.*,
                        );
                        ok = false;
                        continue;
                    };
                    ok = (try w.compare(path.key_ptr.*, value, path.value_ptr.*)) and ok;
                }
            } else if (std.mem.eql(u8, key, "headers") or std.mem.eql(u8, key, "cookies")) {
                var headers = want.object.iterator();
                while (headers.next()) |header| {
                    const value = actual.object.get(key).?.object.get(header.key_ptr.*);
                    if (header.value_ptr.* == .null) {
                        ok = (try w.compare(
                            header.key_ptr.*,
                            .{ .bool = value != null },
                            .{ .bool = false },
                        )) and ok;
                        continue;
                    }
                    if (value == null) {
                        try w.failure(
                            header.key_ptr.*,
                            system.text("missing field"),
                            header.value_ptr.*,
                        );
                        ok = false;
                    } else ok = (try w.compare(header.key_ptr.*, value.?, header.value_ptr.*)) and
                        ok;
                }
            } else {
                const value = actual.object.get(key) orelse {
                    try w.failure(key, system.text("missing field"), want);
                    ok = false;
                    continue;
                };
                const expected_value = if (std.mem.eql(u8, probe_name, "file") and
                    (std.mem.eql(u8, key, "uid") or std.mem.eql(u8, key, "gid")) and
                    want == .string)
                    system.number(try system.identity(
                        w.io,
                        w.a,
                        want.string,
                        std.mem.eql(u8, key, "gid"),
                    ))
                else
                    want;
                ok = (try w.compare(key, value, expected_value)) and ok;
            }
        }
        return ok;
    }

    fn groups(w: *Workflow, value: Json) anyerror!Json {
        if (value == .string) return system.number(try system.identity(
            w.io,
            w.a,
            value.string,
            true,
        ));
        if (value == .array) {
            var result: std.json.Array = .init(w.a);
            for (value.array.items) |v| try result.append(try w.groups(v));
            std.mem.sort(Json, result.items, {}, struct {
                fn less(_: void, a: Json, b: Json) bool {
                    return a.integer < b.integer;
                }
            }.less);
            for (result.items, 0..) |id, i| {
                if (i > 0 and
                    id.integer == result.items[i - 1].integer) return error.DuplicateGroup;
            }
            return .{ .array = result };
        }
        if (value == .object) {
            var result = system.object(w.a);
            var it = value.object.iterator();
            while (it.next()) |e| try result.object.put(
                w.a,
                e.key_ptr.*,
                try w.groups(e.value_ptr.*),
            );
            return result;
        }
        return value;
    }

    fn compare(w: *Workflow, field_name: []const u8, got: Json, want: Json) !bool {
        const ok = try match.matches(w.a, got, want);
        if (!ok) try w.failure(field_name, got, want);
        return ok;
    }

    fn diagnostic(w: *Workflow, value: Json) !Json {
        if (w.sensitive and value != .integer and value != .bool and
            value != .null) return system.text("<redacted>");
        var buffer: [256]u8 = undefined;
        var writer: Io.Writer = .fixed(&buffer);
        std.json.Stringify.value(value, .{}, &writer) catch
            return system.text("<value exceeds diagnostic limit>");
        return try std.json.parseFromSliceLeaky(Json, w.a, writer.buffered(), .{});
    }

    fn failure(w: *Workflow, key: []const u8, got: Json, want: Json) !void {
        if (w.failures.items.len == 4) return;
        try w.failures.append(
            w.a,
            .{
                // A probe's own field name lives only as long as its attempt.
                .field = try w.a.dupe(u8, key[0..@min(key.len, 128)]),
                .got = try w.diagnostic(got),
                .want = try w.diagnostic(want),
            },
        );
    }
};

fn textInput(value: Json, header: bool) !void {
    if (value != .string or
        std.mem.findScalar(u8, value.string, 0) != null) return error.InvalidTextInput;
    if (header and std.mem.findAny(u8, value.string, "\r\n") != null) return error.InvalidHeader;
}

fn validateRequest(name: []const u8, req: Json) !void {
    if (std.mem.eql(u8, name, "fetch")) {
        for ([_][]const u8{ "url", "method", "bearer", "session", "ca" }) |key|
            if (req.object.get(key)) |value| try textInput(value, std.mem.eql(u8, key, "bearer"));
        if (req.object.get("path")) |parts| {
            const uri = std.Uri.parse(req.object.get("url").?.string) catch
                return error.InvalidPathBase;
            const path = switch (uri.path) {
                .raw, .percent_encoded => |p| p,
            };
            if (uri.host == null or uri.user != null or uri.password != null or
                uri.query != null or uri.fragment != null or
                (path.len > 0 and !std.mem.eql(u8, path, "/"))) return error.InvalidPathBase;
            if (parts != .array or parts.array.items.len == 0 or parts.array.items.len > 32)
                return error.InvalidPath;
            for (parts.array.items, 0..) |part, index| {
                try textInput(part, false);
                const text = part.string;
                if (text.len > 1024 or std.mem.eql(u8, text, ".") or
                    std.mem.eql(u8, text, "..") or
                    (text.len == 0 and index + 1 != parts.array.items.len))
                    return error.InvalidPath;
            }
        }
        if (req.object.get("authorization")) |auth| {
            if (auth != .object) return error.InvalidAuthorization;
            const scheme = auth.object.get("scheme") orelse return error.InvalidAuthorization;
            const credentials = auth.object.get("credentials") orelse
                return error.InvalidAuthorization;
            try textInput(scheme, true);
            try textInput(credentials, true);
            if (scheme.string.len == 0 or req.object.contains("bearer"))
                return error.InvalidAuthorization;
            for (scheme.string) |ch| {
                if (!std.ascii.isAlphanumeric(ch) and
                    std.mem.findScalar(u8, "!#$%&'*+-.^_`|~", ch) == null)
                    return error.InvalidAuthorization;
            }
        }
        // libcurl receives the body's explicit length; unlike headers it may be binary.
        if (req.object.get("body")) |body| if (body != .string) return error.InvalidTextInput;
        for ([_][]const u8{ "headers", "form" }) |key| {
            if (req.object.get(key)) |values| {
                if (values != .object) return error.InvalidTextMap;
                var it = values.object.iterator();
                while (it.next()) |entry| {
                    if (std.mem.eql(u8, key, "headers") and
                        std.ascii.eqlIgnoreCase(entry.key_ptr.*, "authorization") and
                        (req.object.contains("bearer") or req.object.contains("authorization")))
                        return error.InvalidAuthorization;
                    try textInput(entry.value_ptr.*, std.mem.eql(u8, key, "headers"));
                }
            }
        }
        if (req.object.get("multipart")) |parts| {
            var it = parts.object.iterator();
            while (it.next()) |entry| {
                const value = entry.value_ptr.*;
                if (value == .object and value.object.contains("file")) {
                    var fields = value.object.iterator();
                    while (fields.next()) |field| try textInput(field.value_ptr.*, false);
                } else try textInput(value, false);
            }
        }
    } else if (std.mem.eql(u8, name, "exec")) {
        for (req.object.get("argv").?.array.items) |arg| try textInput(arg, false);
        if (req.object.get("stdin")) |value| try textInput(value, false);
        if (req.object.get("env")) |env| {
            var it = env.object.iterator();
            while (it.next()) |entry| try textInput(entry.value_ptr.*, false);
        }
    }
}

fn capture(value: ?Json) !Json {
    const v = value orelse return error.MissingCapture;
    if (v != .string) return error.AmbiguousCapture;
    return v;
}

test "port scope retains every address so a wildcard listener still fails" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const listeners = try std.json.parseFromSliceLeaky(Json, a,
        \\[{"protocol":"tcp","address":"127.0.0.1","port":11434},
        \\ {"protocol":"tcp","address":"::","port":443},
        \\ {"protocol":"tcp","address":"0.0.0.0","port":11434}]
    , .{});
    const scoped = onlyPort(listeners, 11434);
    var workflow: Workflow = .{
        .a = a,
        .io = std.testing.io,
        .ctx = undefined,
        .plan = undefined,
        .suite = "",
    };
    const expected = try std.json.parseFromSliceLeaky(Json, a,
        \\{"equals":[{"protocol":"tcp","address":"127.0.0.1","port":11434}]}
    , .{});
    try std.testing.expectEqual(@as(usize, 2), scoped.array.items.len);
    try std.testing.expect(!try workflow.check("listeners", scoped, expected));
    try std.testing.expectEqual(@as(usize, 0), onlyPort(scoped, 8080).array.items.len);
}

test "group assertions compare sets and reject duplicate identities" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var workflow: Workflow = .{
        .a = a,
        .io = std.testing.io,
        .ctx = undefined,
        .plan = undefined,
        .suite = "",
    };
    const unsorted = try std.json.parseFromSliceLeaky(Json, a, "[9,2]", .{});
    const sorted = try workflow.groups(unsorted);
    try std.testing.expectEqual(@as(i64, 2), sorted.array.items[0].integer);
    try std.testing.expectError(
        error.DuplicateGroup,
        workflow.groups(try std.json.parseFromSliceLeaky(Json, a, "[2,2]", .{})),
    );
}

test "service uid range covers every real effective saved and filesystem identity" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var workflow: Workflow = .{
        .a = a,
        .io = std.testing.io,
        .ctx = undefined,
        .plan = undefined,
        .suite = "",
    };
    const expected = try std.json.parseFromSliceLeaky(Json, a, "{\"uid\":{\"min\":65536}}", .{});
    for ([_][]const u8{
        "{\"members\":[{\"uids\":[65536,65536,65536,65536]}]}",
        "{\"members\":[{\"uids\":[65536,0,65536,65536]}]}",
        "{\"members\":[{\"uids\":[65536,65536,65536,65536]},{\"uids\":[0,0,0,0]}]}",
    }, 0..) |raw, index| {
        const actual = try std.json.parseFromSliceLeaky(Json, a, raw, .{});
        try std.testing.expectEqual(index == 0, try workflow.check("service", actual, expected));
    }
}

fn jsonOutput(value: Json) ![]const u8 {
    const output = value.object.get("body") orelse value.object.get("stdout") orelse
        return error.MissingJsonOutput;
    return output.string;
}
