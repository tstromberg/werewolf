//! probe-tests runs the probe runner, test/native/probes.zig, against real
//! HTTP and HTTPS servers, with this program as its exec client: captures,
//! cookies, polling, redaction, limits, TLS trust and timeouts.
//! make _test/probes builds the runner and runs
//!
//!     probe-tests RUNNER
//!
//! The plans' exec steps run `probe-tests client MODE ...`.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const plans = @import("test-plan");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const http = host.http;
const Result = host.check.Result;
const stringify = std.json.Stringify.valueAlloc;

const secret = "secret-password\n";

/// suite is the plan around a test's cases, which go under cases: indented.
/// $SELF, $BASE and $TMP stand for this program, the HTTP server's origin
/// and the directory the tests write in.
const suite =
    \\version: 1
    \\suites:
    \\  - name: web
    \\    policy:
    \\      run: [$SELF]
    \\    fixtures:
    \\      password: /run/config/test/password
    \\    cases:
    \\
;

/// login posts the password fixture and names the response for its token.
const login =
    \\    - name: login
    \\      fetch:
    \\        url: $BASE/login
    \\        method: POST
    \\        json:
    \\          username: admin
    \\          password:
    \\            fixture: password
    \\      expect:
    \\        status: 200
    \\
;

/// independent is a case that passes whatever another case did.
const independent =
    \\- name: independent
    \\  steps:
    \\    - fetch:
    \\        url: $BASE/redirect
    \\      expect:
    \\        status: 302
    \\
;

/// csrf_capture sends the token a regex takes from step form.
const csrf_capture =
    \\    - fetch:
    \\        url: $BASE/protected
    \\        bearer:
    \\          step: form
    \\          regex: 'name="csrf" value="([^"]+)"'
    \\      expect:
    \\        status: 200
;

const tests = [_]struct { []const u8, *const fn (*Tests) anyerror!void }{
    .{ "html-capture-fails-before-dependent-requests", htmlCapture },
    .{ "capture-takes-file-bodies-and-client-stdout", textCapture },
    .{ "nonempty-binary-body-uses-literal-inequality", binaryInequality },
    .{ "path-capture-is-one-escaped-segment", pathCapture },
    .{ "membership-requires-every-positive-and-refusal", membership },
    .{ "invalid-captured-paths-fail-before-request", invalidPaths },
    .{ "binary-body-keeps-nuls-but-headers-refuse-them", binaryBody },
    .{ "binary-response-capture-keeps-bytes", binaryCapture },
    .{ "token-cookie-polling-and-literal-redirect", tokenCookiePolling },
    .{ "token-authorization-captures-and-redacts", tokenAuthorization },
    .{ "failure-stops-dependent-steps-only", failureStops },
    .{ "header-absence-is-explicit", headerAbsence },
    .{ "negative-regex-tells-absence-match-and-invalid", negativeRegex },
    .{ "readiness-checks-status-before-json", readinessStatus },
    .{ "form-multipart-and-literal-paths", formEncoding },
    .{ "ambiguous-header-capture-fails", ambiguousHeader },
    .{ "cookies-tell-missing-from-ambiguous", cookieAssertions },
    .{ "truncated-and-oversized-responses-fail", truncatedOversized },
    .{ "timeout-kills-helpers-retaining-pipes", helperTimeout },
    .{ "tls-requires-trusted-ca-and-hostname", tlsTrust },
    .{ "tls-startup-retries-only-with-await", tlsStartup },
    .{ "exec-drains-both-pipes-and-reports-exit", execDrain },
    .{ "exec-captures-are-literal-arguments", execJson },
    .{ "exec-timeout-after-output-closes-fails", closedOutput },
    .{ "exec-timeout-can-exceed-the-default", slowClient },
    .{ "exec-output-limit-fails", outputLimit },
    .{ "capture-type-error-fails-only-its-case", captureTypeError },
    .{ "run-id-is-literal-typed-data", runId },
    .{ "tcp-converses-over-plain-and-verified-tls", tcpConversation },
    .{ "tree-audits-without-following-links", treeAudit },
    .{ "write-refusals-leave-nothing-behind", writeRefusal },
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len > 2 and mem.eql(u8, args[1], "client")) return client(init.io, gpa, args[2..]);
    if (args.len != 2) std.process.fatal("usage: probe-tests RUNNER", .{});
    if (!try all(init, args[1])) std.process.exit(1);
}

/// all runs every test with runner, saying how each went, and reports
/// whether they all passed.
fn all(init: std.process.Init, runner: []const u8) !bool {
    const io = init.io;
    const gpa = init.arena.allocator();
    var nonce: [6]u8 = undefined;
    io.random(&nonce);
    const root = try std.fs.path.join(gpa, &.{
        init.environ_map.get("TMPDIR") orelse "/tmp",
        try gpa.print("probe-tests-{x}", .{&nonce}),
    });
    try Io.Dir.cwd().createDirPath(io, root);
    defer Io.Dir.cwd().deleteTree(io, root) catch {};
    const ca = try host.tls.Authority.init(io, gpa, "probe-tests authority");
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = try gpa.print("{s}/ca.pem", .{root}),
        .data = try ca.pem(gpa),
    });
    var t: Tests = .{
        .io = io,
        .gpa = gpa,
        .runner = runner,
        .self = try std.process.executablePathAlloc(io, gpa),
        .root = root,
        .routes = .{ .io = io, .gpa = gpa },
        .identity = try ca.issue(io, gpa, &.{"localhost"}),
    };
    var server: http.Server = undefined;
    try server.start(io, std.heap.smp_allocator, .{ .handler = t.routes.handler() });
    defer server.stop();
    t.base = try gpa.print("http://127.0.0.1:{d}", .{server.port()});
    var failed: usize = 0;
    for (tests) |entry| {
        t.routes.reset();
        t.why = "";
        entry[1](&t) catch |err| {
            failed += 1;
            say(io, "FAIL {s}: {s}", .{
                entry[0],
                if (err == error.TestFailed) t.why else @errorName(err),
            });
            continue;
        };
        say(io, "pass {s}", .{entry[0]});
    }
    say(io, "{d} of {d} tests failed", .{ failed, tests.len });
    return failed == 0;
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var out = Io.File.stdout().writerStreaming(io, &buf);
    out.interface.print("probe-tests: " ++ fmt ++ "\n", args) catch {};
    out.interface.flush() catch {};
}

const Tests = struct {
    io: Io,
    gpa: Allocator,
    runner: []const u8,
    self: []const u8,
    root: []const u8,
    base: []const u8 = "",
    routes: Routes,
    identity: host.tls.Identity,
    runs: usize = 0,
    why: []const u8 = "",

    /// runPlan runs cases, YAML under the suite's cases: key, with password
    /// as the password fixture's content.
    fn runPlan(t: *Tests, cases: []const u8, password: []const u8) !Result {
        const io = t.io;
        const gpa = t.gpa;
        t.runs += 1;
        const path = try gpa.print("{s}/run-{d}", .{ t.root, t.runs });
        try Io.Dir.cwd().createDirPath(io, path);
        var dir = try Io.Dir.cwd().openDir(io, path, .{});
        defer dir.close(io);
        var yaml: std.ArrayList(u8) = .empty;
        try yaml.appendSlice(gpa, suite);
        var lines = mem.splitScalar(u8, cases, '\n');
        while (lines.next()) |line| {
            if (line.len > 0) try yaml.appendNTimes(gpa, ' ', 6);
            try yaml.appendSlice(gpa, line);
            try yaml.append(gpa, '\n');
        }
        var text: []const u8 = yaml.items;
        for ([_][2][]const u8{
            .{ "$SELF", t.self },
            .{ "$BASE", t.base },
            .{ "$TMP", t.root },
        }) |sub| text = try mem.replaceOwned(u8, gpa, text, sub[0], sub[1]);
        try dir.writeFile(io, .{ .sub_path = "tests.yaml", .data = text });
        try dir.writeFile(io, .{ .sub_path = "password", .data = password });
        var failure: plans.Failure = .{};
        const plan = plans.load(io, gpa, dir, "tests.yaml", &failure) catch |err| switch (err) {
            error.Plan => return t.fail("plan refused: {s}", .{failure.text}),
            else => |e| return e,
        };
        var data = plan.drivers[0].probes.?;
        try data.object.getPtr("fixtures").?.object.put(gpa, "password", .{
            .string = try gpa.print("{s}/password", .{path}),
        });
        try dir.writeFile(io, .{ .sub_path = "plan.json", .data = try plans.json(gpa, data) });
        try dir.writeFile(io, .{
            .sub_path = "context",
            .data = "{\"run\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"phase\":\"seed\"}",
        });
        return host.check.command(io, gpa, &.{
            t.runner,
            "test-web",
            "probes",
            try gpa.print("{s}/context", .{path}),
            try gpa.print("{s}/plan.json", .{path}),
        }, .{ .timeout = .fromSeconds(20) });
    }

    fn fail(t: *Tests, comptime fmt: []const u8, args: anytype) error{TestFailed} {
        t.why = t.gpa.print(fmt, args) catch "out of memory saying why";
        return error.TestFailed;
    }

    /// exits fails unless the runner exited with code.
    fn exits(t: *Tests, r: Result, code: u8) !void {
        if (r.code() != code) return t.fail("runner exited {?d}, want {d}:\n{s}{s}", .{
            r.code(), code, r.stdout, r.stderr,
        });
    }

    /// says fails unless the runner's results hold text.
    fn says(t: *Tests, r: Result, text: []const u8) !void {
        if (mem.find(u8, r.stdout, text) == null)
            return t.fail("runner did not say {s}:\n{s}{s}", .{ text, r.stdout, r.stderr });
    }

    /// counts fails unless the runner's results hold text n times.
    fn counts(t: *Tests, r: Result, text: []const u8, n: usize) !void {
        const got = mem.count(u8, r.stdout, text);
        if (got != n) return t.fail("runner said {s} {d} times, want {d}:\n{s}{s}", .{
            text, got, n, r.stdout, r.stderr,
        });
    }

    /// hides fails if the runner printed text anywhere.
    fn hides(t: *Tests, r: Result, text: []const u8) !void {
        if (mem.find(u8, r.stdout, text) != null or mem.find(u8, r.stderr, text) != null)
            return t.fail("runner revealed {s}:\n{s}{s}", .{ text, r.stdout, r.stderr });
    }

    /// asked fails unless the servers were asked for target n times.
    fn asked(t: *Tests, target: []const u8, n: u32) !void {
        const got = blk: {
            t.routes.mutex.lockUncancelable(t.io);
            defer t.routes.mutex.unlock(t.io);
            break :blk t.routes.calls.get(target) orelse 0;
        };
        if (got != n) return t.fail("{s} asked {d} times, want {d}", .{ target, got, n });
    }
};

/// Routes answers what the plans fetch and counts each target asked, over
/// HTTP and HTTPS alike.
const Routes = struct {
    io: Io,
    gpa: Allocator,
    mutex: Io.Mutex = .init,
    calls: std.StringHashMapUnmanaged(u32) = .empty,

    fn handler(r: *Routes) http.Handler {
        return .{ .context = r, .serve = serve };
    }

    fn reset(r: *Routes) void {
        r.mutex.lockUncancelable(r.io);
        defer r.mutex.unlock(r.io);
        r.calls.clearRetainingCapacity();
    }

    /// seen is how many distinct targets were asked.
    fn seen(r: *Routes) usize {
        r.mutex.lockUncancelable(r.io);
        defer r.mutex.unlock(r.io);
        return r.calls.count();
    }
};

fn serve(
    context: *anyopaque,
    gpa: Allocator,
    request: *const http.Request,
    response: *http.Response,
) !void {
    const r: *Routes = @ptrCast(@alignCast(context));
    const path = request.target;
    const n = blk: {
        r.mutex.lockUncancelable(r.io);
        defer r.mutex.unlock(r.io);
        const entry = try r.calls.getOrPut(r.gpa, path);
        if (!entry.found_existing) {
            entry.key_ptr.* = try r.gpa.dupe(u8, path);
            entry.value_ptr.* = 0;
        }
        entry.value_ptr.* += 1;
        break :blk entry.value_ptr.*;
    };
    if (mem.eql(u8, request.method, "POST")) {
        const body = request.body;
        if (mem.eql(u8, path, "/binary")) {
            const hex = try gpa.print("{x}", .{body});
            return reply(response, 200, try stringify(gpa, .{ .hex = hex }, .{}), null);
        }
        if (mem.eql(u8, path, "/echo")) {
            const echo = .{ .body = body, .type = request.header("content-type") };
            return reply(response, 200, try stringify(gpa, echo, .{}), null);
        }
        const Login = struct { username: []const u8, password: []const u8 };
        if (mem.eql(u8, path, "/login")) {
            const got = std.json.parseFromSliceLeaky(Login, gpa, body, .{}) catch
                return reply(response, 400, "{}", null);
            if (mem.eql(u8, got.username, "admin") and mem.eql(u8, got.password, "secret-password"))
                return reply(response, 200, "{\"token\":\"secret-token\"}", null);
        }
        return reply(response, 400, "{}", null);
    }
    const field = "<input name=\"csrf\" value=\"secret-token\">";
    const html: http.Header = .{ .name = "Content-Type", .value = "text/html" };
    if (mem.eql(u8, path, "/path-value"))
        return reply(response, 200, "{\"id\":\"a/b ?#%\\u00e9\",\"number\":42}", null);
    if (mem.eql(u8, path, "/html-token")) return response.send(200, &.{html}, field);
    if (mem.eql(u8, path, "/html-duplicate")) return response.send(200, &.{html}, field ++ field);
    if (mem.eql(u8, path, "/html-missing")) return response.send(200, &.{html}, "<form></form>");
    if (mem.eql(u8, path, "/membership")) return reply(
        response,
        200,
        "{\"items\":[\"network\",\"zeroconf\"],\"text\":\"hello world\"}",
        null,
    );
    if (mem.startsWith(u8, path, "/path/") or mem.eql(u8, path, "/../../literal"))
        return reply(response, 200, try stringify(gpa, .{ .path = path }, .{}), null);
    if (mem.eql(u8, path, "/binary-body")) return response.send(
        200,
        &.{.{ .name = "Content-Type", .value = "application/octet-stream" }},
        "\x00\xff\r\n",
    );
    if (mem.eql(u8, path, "/cookie")) return reply(response, 200, "{}", .{
        .name = "Set-Cookie",
        .value = "session=secret-cookie; Path=/; HttpOnly",
    });
    if (mem.eql(u8, path, "/protected")) {
        const good = mem.eql(u8, request.header("authorization") orelse "", "Bearer secret-token");
        return reply(response, if (good) 200 else 401, "{\"results\":[]}", null);
    }
    if (mem.eql(u8, path, "/token-protected")) {
        // One Authorization header exactly: an injected second one fails.
        var tokens: usize = 0;
        var good = false;
        for (request.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "authorization")) {
            tokens += 1;
            good = mem.eql(u8, h.value, "Token secret-token");
        };
        return reply(response, if (good and tokens == 1) 200 else 401, "{\"results\":[]}", null);
    }
    if (mem.eql(u8, path, "/cookie-protected")) {
        const good = mem.eql(u8, request.header("cookie") orelse "", "session=secret-cookie");
        return reply(response, if (good) 200 else 401, "{}", null);
    }
    if (mem.eql(u8, path, "/ready"))
        return reply(response, 200, if (n >= 3) "{\"ready\":true}" else "{\"ready\":false}", null);
    if (mem.eql(u8, path, "/starting")) {
        if (n >= 3) return reply(response, 200, "{\"ready\":true}", null);
        return response.send(502, &.{}, "");
    }
    if (mem.eql(u8, path, "/invalid-json")) return response.send(200, &.{}, "");
    if (mem.eql(u8, path, "/duplicate")) return response.send(200, &.{
        .{ .name = "X-Token", .value = "one" },
        .{ .name = "X-Token", .value = "two" },
    }, "{}");
    if (mem.eql(u8, path, "/two-cookies")) return response.send(200, &.{
        .{ .name = "Set-Cookie", .value = "session=one; Path=/" },
        .{ .name = "Set-Cookie", .value = "session=two; Path=/protected" },
    }, "{}");
    if (mem.eql(u8, path, "/too-large")) {
        const body = try gpa.alloc(u8, (2 << 20) + 2);
        @memset(body, 'x');
        body[0] = '"';
        body[body.len - 1] = '"';
        return reply(response, 200, body, null);
    }
    if (mem.eql(u8, path, "/truncated")) {
        response.close = true;
        return response.send(200, &.{.{ .name = "Content-Length", .value = "20" }}, "{}");
    }
    if (mem.eql(u8, path, "/redirect"))
        return reply(response, 302, "{}", .{ .name = "Location", .value = "/must-not-fetch" });
    return reply(response, 404, "{}", null);
}

/// reply sends a JSON body, and extra if given.
fn reply(response: *http.Response, status: u16, body: []const u8, extra: ?http.Header) !void {
    const json: http.Header = .{ .name = "Content-Type", .value = "application/json" };
    if (extra) |h| return response.send(status, &.{ json, h }, body);
    return response.send(status, &.{json}, body);
}

fn htmlCapture(t: *Tests) !void {
    for ([_]struct { []const u8, u8, ?[]const u8 }{
        .{ "/html-token", 0, null },
        .{ "/html-missing", 1, "MissingCapture" },
        .{ "/html-duplicate", 1, "AmbiguousCapture" },
    }) |case| {
        t.routes.reset();
        const r = try t.runPlan(try t.gpa.print(
            \\- name: csrf
            \\  steps:
            \\    - name: form
            \\      fetch:
            \\        url: $BASE{s}
            \\      expect:
            \\        status: 200
            \\
        ++ csrf_capture, .{case[0]}), secret);
        try t.exits(r, case[1]);
        try t.asked("/protected", @intFromBool(case[1] == 0));
        if (case[2]) |err| try t.says(r, err);
        try t.hides(r, "secret-token");
    }
}

fn textCapture(t: *Tests) !void {
    try Io.Dir.cwd().writeFile(t.io, .{
        .sub_path = try t.gpa.print("{s}/form", .{t.root}),
        .data = "name=\"csrf\" value=\"secret-token\"",
    });
    const file =
        \\      file: $TMP/form
        \\      expect:
        \\        type: file
        \\        body:
        \\          contains: csrf
    ;
    const exec =
        \\      exec:
        \\        argv: [$SELF, client, print, 'name="csrf" value="secret-token"']
        \\      expect:
        \\        exit: 0
    ;
    // The file probe reads statx, which only Linux has.
    const probes: []const []const u8 = if (builtin.os.tag == .linux) &.{ file, exec } else &.{exec};
    for (probes) |probe| {
        const r = try t.runPlan(try t.gpa.print(
            \\- name: text-capture
            \\  steps:
            \\    - name: form
            \\{s}
            \\
        ++ csrf_capture, .{probe}), secret);
        try t.exits(r, 0);
    }
}

fn binaryInequality(t: *Tests) !void {
    try t.exits(try t.runPlan(
        \\- name: bytes
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/binary-body
        \\      expect:
        \\        status: 200
        \\        body:
        \\          not_equals: ''
    , secret), 0);
}

fn pathCapture(t: *Tests) !void {
    try t.exits(try t.runPlan(
        \\- name: paths
        \\  steps:
        \\    - name: value
        \\      fetch:
        \\        url: $BASE/path-value
        \\      expect:
        \\        status: 200
        \\    - fetch:
        \\        url: $BASE
        \\        path:
        \\          - path
        \\          - step: value
        \\            json: /id
        \\          - ''
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /path: '/path/a%2Fb%20%3F%23%25%C3%A9/'
        \\    - fetch:
        \\        url: $BASE/
        \\        path:
        \\          - path
        \\          - fixture: password
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /path: '/path/https:%2F%2Fother.invalid%2F'
        \\    - fetch:
        \\        url: $BASE
        \\        path: [path, 'sha256:abcdef']
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /path: '/path/sha256:abcdef'
    , "https://other.invalid/"), 0);
    try t.asked("/path-value", 1);
}

fn membership(t: *Tests) !void {
    try t.exits(try t.runPlan(
        \\- name: membership
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/membership
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /items:
        \\            contains_all: [network, zeroconf]
        \\            contains_none: [ssdp, dhcp]
        \\          /text:
        \\            contains_all: [hello, world]
        \\            contains_none: [bad]
    , secret), 0);
    for ([_][]const u8{
        "contains_all: [network, missing]",
        "contains_none: [ssdp, network]",
    }) |refused| try t.exits(try t.runPlan(try t.gpa.print(
        \\- name: missing-member
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/membership
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /items:
        \\            {s}
    , .{refused}), secret), 1);
}

fn invalidPaths(t: *Tests) !void {
    for ([_][]const u8{ "..", ".", "a\x00b", &@as([1025]u8, @splat('x')) }) |segment| {
        t.routes.reset();
        try t.exits(try t.runPlan(
            \\- name: bad-path
            \\  steps:
            \\    - fetch:
            \\        url: $BASE
            \\        path:
            \\          - path
            \\          - fixture: password
            \\      expect:
            \\        status: 200
        , segment), 1);
        if (t.routes.seen() != 0) return t.fail("a request ran with path segment {s}", .{segment});
    }
    t.routes.reset();
    try t.exits(try t.runPlan(
        \\- name: numeric-path
        \\  steps:
        \\    - name: value
        \\      fetch:
        \\        url: $BASE/path-value
        \\      expect:
        \\        status: 200
        \\    - fetch:
        \\        url: $BASE
        \\        path:
        \\          - path
        \\          - step: value
        \\            json: /number
        \\      expect:
        \\        status: 200
    , secret), 1);
    try t.asked("/path-value", 1);
    if (t.routes.seen() != 1) return t.fail("a request ran with a numeric path segment", .{});
}

fn binaryBody(t: *Tests) !void {
    try t.exits(try t.runPlan(
        \\- name: binary
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/binary
        \\        method: POST
        \\        body:
        \\          fixture: password
        \\          raw: true
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /hex: '00ff0d0a'
    , "\x00\xff\r\n"), 0);
    const r = try t.runPlan(
        \\- name: invalid-header
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/must-not-fetch
        \\        bearer:
        \\          fixture: password
        \\          raw: true
        \\      expect:
        \\        status: 200
    , &@as([5]u8, @splat(0)));
    try t.exits(r, 1);
    try t.says(r, "InvalidTextInput");
    try t.asked("/must-not-fetch", 0);
}

fn binaryCapture(t: *Tests) !void {
    try t.exits(try t.runPlan(
        \\- name: download
        \\  steps:
        \\    - name: download
        \\      fetch:
        \\        url: $BASE/binary-body
        \\      expect:
        \\        status: 200
        \\        body:
        \\          fixture: password
        \\          raw: true
        \\    - fetch:
        \\        url: $BASE/binary
        \\        method: POST
        \\        body:
        \\          step: download
        \\          body: true
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /hex: '00ff0d0a'
    , "\x00\xff\r\n"), 0);
}

fn tokenCookiePolling(t: *Tests) !void {
    const r = try t.runPlan(
        \\- name: login
        \\  steps:
        \\
    ++ login ++
        \\    - fetch:
        \\        url: $BASE/protected
        \\        bearer:
        \\          step: login
        \\          json: /token
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /results: []
        \\- name: cookies
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/cookie
        \\        session: browser
        \\      expect:
        \\        status: 200
        \\    - fetch:
        \\        url: $BASE/cookie-protected
        \\        session: browser
        \\      expect:
        \\        status: 200
        \\- name: readiness
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/ready
        \\      await: 2s
        \\      expect:
        \\        json:
        \\          /ready: true
        \\- name: redirect
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/redirect
        \\      expect:
        \\        status: 302
    , secret);
    try t.exits(r, 0);
    try t.counts(r, "\"status\":\"pass\"", 4);
    try t.asked("/login", 1);
    try t.asked("/must-not-fetch", 0);
}

fn tokenAuthorization(t: *Tests) !void {
    const r = try t.runPlan(
        \\- name: token
        \\  steps:
        \\
    ++ login ++
        \\    - fetch:
        \\        url: $BASE/token-protected
        \\        authorization:
        \\          scheme: Token
        \\          credentials:
        \\            step: login
        \\            json: /token
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /results: []
    , secret);
    try t.exits(r, 0);
    try t.asked("/login", 1);
    try t.hides(r, "secret-token");
    for ([_][]const u8{ "bad\r\nInjected: yes", "bad\x00value" }) |credential| {
        const refused = try t.runPlan(
            \\- name: invalid-auth
            \\  steps:
            \\    - fetch:
            \\        url: $BASE/must-not-fetch
            \\        authorization:
            \\          scheme: Token
            \\          credentials:
            \\            fixture: password
            \\            raw: true
            \\      expect:
            \\        status: 200
        , credential);
        try t.exits(refused, 1);
        try t.asked("/must-not-fetch", 0);
        try t.hides(refused, "Injected");
        try t.hides(refused, "secret-");
    }
}

fn failureStops(t: *Tests) !void {
    const r = try t.runPlan(
        \\- name: failure
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/missing
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /missing: true
        \\    - fetch:
        \\        url: $BASE/must-not-fetch
        \\      expect:
        \\        status: 200
        \\
    ++ independent, secret);
    try t.exits(r, 1);
    try t.says(r, "\"status\":\"fail\"");
    try t.says(r, "\"status\":\"pass\"");
    try t.says(r, "\"got\":404");
    try t.asked("/must-not-fetch", 0);
}

fn headerAbsence(t: *Tests) !void {
    for ([_]struct { []const u8, u8 }{
        .{ "x-missing: null", 0 },
        .{ "content-type: null", 1 },
        .{ "x-missing:\n            absent: secret", 1 },
        .{ "x-missing: ''", 1 },
    }) |case| try t.exits(try t.runPlan(try t.gpa.print(
        \\- name: headers
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/ready
        \\      expect:
        \\        status: 200
        \\        headers:
        \\          {s}
    , .{case[0]}), secret), case[1]);
}

fn negativeRegex(t: *Tests) !void {
    const r = try t.runPlan(
        \\- name: absent
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/ready
        \\      expect:
        \\        status: 200
        \\        body:
        \\          not_matches: '[Ii][Nn][Ss][Tt][Aa][Ll][Ll]'
        \\- name: present
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/ready
        \\      expect:
        \\        status: 200
        \\        body:
        \\          not_matches: '[Rr][Ee][Aa][Dd][Yy]'
        \\- name: invalid
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/ready
        \\      expect:
        \\        status: 200
        \\        body:
        \\          not_matches: '['
    , secret);
    try t.exits(r, 1);
    try t.says(r, "\"case\":\"absent\",\"status\":\"pass\"");
    try t.says(r, "\"case\":\"present\",\"status\":\"fail\"");
    try t.says(r, "InvalidRegex");
}

fn readinessStatus(t: *Tests) !void {
    for ([_]struct { []const u8, u8, u32 }{
        .{ "/starting", 0, 3 },
        .{ "/invalid-json", 1, 1 },
    }) |case| {
        try t.exits(try t.runPlan(try t.gpa.print(
            \\- name: ready
            \\  steps:
            \\    - fetch:
            \\        url: $BASE{s}
            \\      await: 2s
            \\      expect:
            \\        status: 200
            \\        json:
            \\          /ready: true
        , .{case[0]}), secret), case[1]);
        try t.asked(case[0], case[2]);
    }
}

fn formEncoding(t: *Tests) !void {
    try t.exits(try t.runPlan(
        \\- name: form
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/echo
        \\        method: POST
        \\        form:
        \\          q: 'a & b'
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /body: 'q=a%20%26%20b'
        \\          /type: application/x-www-form-urlencoded
        \\- name: multipart
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/echo
        \\        method: POST
        \\        multipart:
        \\          title: example
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /body:
        \\            contains: example
        \\          /type:
        \\            contains: 'multipart/form-data; boundary='
        \\- name: literal
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/../../literal
        \\      expect:
        \\        status: 200
        \\        json:
        \\          /path: '/../../literal'
    , secret), 0);
}

fn ambiguousHeader(t: *Tests) !void {
    const r = try t.runPlan(
        \\- name: ambiguous
        \\  steps:
        \\    - name: tokens
        \\      fetch:
        \\        url: $BASE/duplicate
        \\      expect:
        \\        status: 200
        \\    - fetch:
        \\        url: $BASE/must-not-fetch
        \\        bearer:
        \\          step: tokens
        \\          header: X-Token
        \\      expect:
        \\        status: 200
    , secret);
    try t.exits(r, 1);
    try t.says(r, "AmbiguousCapture");
    try t.asked("/must-not-fetch", 0);
}

fn cookieAssertions(t: *Tests) !void {
    try t.exits(try t.runPlan(
        \\- name: cookies
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/cookie
        \\      expect:
        \\        status: 200
        \\        cookies:
        \\          session: secret-cookie
        \\    - fetch:
        \\        url: $BASE/cookie-protected
        \\      expect:
        \\        status: 401
        \\        cookies:
        \\          session: null
    , secret), 0);
    const r = try t.runPlan(
        \\- name: ambiguous
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/two-cookies
        \\      expect:
        \\        status: 200
        \\        cookies:
        \\          session: null
    , secret);
    try t.exits(r, 1);
    try t.says(r, "\"field\":\"session\"");
}

fn truncatedOversized(t: *Tests) !void {
    const r = try t.runPlan(
        \\- name: large
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/too-large
        \\      expect:
        \\        status: 200
        \\- name: truncated
        \\  steps:
        \\    - fetch:
        \\        url: $BASE/truncated
        \\      expect:
        \\        status: 200
    , secret);
    try t.exits(r, 1);
    try t.counts(r, "\"status\":\"fail\"", 2);
    try t.says(r, "ResponseTooLarge");
    try t.says(r, "HttpTransport");
}

fn helperTimeout(t: *Tests) !void {
    const r = try t.runPlan(
        \\- name: helper
        \\  steps:
        \\    - exec:
        \\        argv: [$SELF, client, helper, $TMP/pid]
        \\        readonly: true
        \\      await: 1s
        \\      expect:
        \\        exit: 0
    , secret);
    try t.exits(r, 1);
    try t.says(r, "Timeout");
    const text = try Io.Dir.cwd().readFileAlloc(
        t.io,
        try t.gpa.print("{s}/pid", .{t.root}),
        t.gpa,
        .limited(32),
    );
    const pid = try t.gpa.print("{d}", .{try std.fmt.parseInt(u32, text, 10)});
    // The runner must kill the client's process group, not only the client.
    const deadline = Io.Clock.awake.now(t.io).addDuration(.fromSeconds(2));
    while (true) {
        const ps = try host.check.command(t.io, t.gpa, &.{ "ps", "-o", "stat=", "-p", pid }, .{
            .timeout = .fromSeconds(2),
        });
        const state = mem.trim(u8, ps.stdout, " \n");
        if (state.len == 0 or state[0] == 'Z') return;
        if (Io.Clock.awake.now(t.io).compare(.gte, deadline))
            return t.fail("client helper {s} survived the timeout: {s}", .{ pid, state });
        try t.io.sleep(.fromMilliseconds(50), .awake);
    }
}

fn tlsTrust(t: *Tests) !void {
    var server: http.Server = undefined;
    try server.start(t.io, std.heap.smp_allocator, .{
        .identity = &t.identity,
        .handler = t.routes.handler(),
    });
    defer server.stop();
    const r = try t.runPlan(try t.gpa.print(
        \\- name: untrusted
        \\  steps:
        \\    - fetch:
        \\        url: https://localhost:{[port]d}/redirect
        \\      expect:
        \\        status: 302
        \\- name: wrong-host
        \\  steps:
        \\    - fetch:
        \\        url: https://127.0.0.1:{[port]d}/redirect
        \\        ca: $TMP/ca.pem
        \\      expect:
        \\        status: 302
        \\- name: trusted
        \\  steps:
        \\    - fetch:
        \\        url: https://localhost:{[port]d}/redirect
        \\        ca: $TMP/ca.pem
        \\      expect:
        \\        status: 302
    , .{ .port = server.port() }), secret);
    try t.exits(r, 1);
    try t.counts(r, "CertificateVerification", 2);
    try t.says(r, "\"case\":\"trusted\",\"status\":\"pass\"");
}

fn tlsStartup(t: *Tests) !void {
    for ([_]bool{ false, true }) |wait| {
        const address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        var listener = try address.listen(t.io, .{ .reuse_address = true });
        defer listener.deinit(t.io);
        var attempts: u32 = 0;
        var accepting = try t.io.concurrent(starting, .{ t, &listener, &attempts });
        defer accepting.cancel(t.io) catch {};
        const r = try t.runPlan(try t.gpa.print(
            \\- name: startup
            \\  steps:
            \\    - fetch:
            \\        url: https://localhost:{d}/redirect
            \\        ca: $TMP/ca.pem
            \\      expect:
            \\        status: 302
            \\{s}
        , .{ listener.socket.address.getPort(), if (wait) "      await: 3s" else "" }), secret);
        accepting.cancel(t.io) catch {};
        try t.exits(r, if (wait) 0 else 1);
        if (attempts != @as(u32, if (wait) 2 else 1))
            return t.fail("{d} TLS connections with await {}", .{ attempts, wait });
        if (!wait) try t.says(r, "TlsHandshake");
    }
}

/// starting serves listener over TLS but refuses its first connection with
/// an internal_error alert: Caddy can accept TLS before it has a serving
/// certificate. attempts counts the connections.
fn starting(t: *Tests, listener: *Io.net.Server, attempts: *u32) Io.Cancelable!void {
    const io = t.io;
    while (true) {
        const stream = listener.accept(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => continue,
        };
        defer stream.close(io);
        attempts.* += 1;
        var in_buf: [host.tls.input_buffer_len]u8 = undefined;
        var out_buf: [16 << 10]u8 = undefined;
        var net_reader = stream.reader(io, &in_buf);
        var net_writer = stream.writer(io, &out_buf);
        if (attempts.* == 1) {
            net_writer.interface.writeAll(&.{ 0x15, 3, 3, 0, 2, 2, 0x50 }) catch {};
            net_writer.interface.flush() catch {};
            continue;
        }
        var clear_in: [host.tls.clear_buffer_len]u8 = undefined;
        var clear_out: [16 << 10]u8 = undefined;
        var conn: host.tls.Connection = undefined;
        conn.accept(
            io,
            &net_reader.interface,
            &net_writer.interface,
            &t.identity,
            &clear_in,
            &clear_out,
        ) catch
            continue;
        answer(t, &conn) catch |err| if (err == error.Canceled) return error.Canceled;
    }
}

/// answer reads one request from conn and has the routes answer it.
fn answer(t: *Tests, conn: *host.tls.Connection) !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.smp_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var words = mem.splitScalar(u8, try conn.reader.takeDelimiterInclusive('\n'), ' ');
    const method = try gpa.dupe(u8, words.next().?);
    const target = try gpa.dupe(u8, words.next() orelse return error.BadRequest);
    while (mem.trimEnd(u8, try conn.reader.takeDelimiterInclusive('\n'), "\r\n").len > 0) {}
    var response: http.Response = .{ .out = &conn.writer, .head = false, .close = true };
    const request: http.Request = .{
        .method = method,
        .target = target,
        .headers = &.{},
        .body = "",
    };
    try serve(&t.routes, gpa, &request, &response);
    try conn.end();
}

fn execDrain(t: *Tests) !void {
    try t.exits(try t.runPlan(try t.gpa.print(
        \\- name: client
        \\  steps:
        \\    - exec:
        \\        argv: [$SELF, client, drain]
        \\        stdin: {s}
        \\      expect:
        \\        exit: 7
        \\        stdout:
        \\          count: 200000
        \\        stderr:
        \\          count: 10000
    , .{&@as([100000]u8, @splat('i'))}), secret), 0);
}

fn execJson(t: *Tests) !void {
    try t.exits(try t.runPlan(
        \\- name: client-json
        \\  steps:
        \\    - name: list
        \\      exec:
        \\        argv: [$SELF, client, print, '[{"id": "literal; $(exit 9)"}]']
        \\      expect:
        \\        exit: 0
        \\        json:
        \\          '':
        \\            count: 1
        \\          /0/id: 'literal; $(exit 9)'
        \\    - exec:
        \\        argv:
        \\          - $SELF
        \\          - client
        \\          - print
        \\          - step: list
        \\            json: /0/id
        \\      expect:
        \\        exit: 0
        \\        stdout: "literal; $(exit 9)\n"
    , secret), 0);
    const r = try t.runPlan(
        \\- name: client-failed
        \\  steps:
        \\    - exec:
        \\        argv: [$SELF, client, print, 'not JSON', '7']
        \\      expect:
        \\        exit: 0
        \\        json:
        \\          /id: unused
    , secret);
    try t.exits(r, 1);
    try t.says(r, "\"field\":\"exit\"");
    try t.hides(r, "SyntaxError");
}

fn closedOutput(t: *Tests) !void {
    const start = Io.Clock.awake.now(t.io);
    const r = try t.runPlan(
        \\- name: timeout
        \\  steps:
        \\    - exec:
        \\        argv: [$SELF, client, close-and-sleep]
        \\        readonly: true
        \\      await: 1s
        \\      expect:
        \\        exit: 0
    , secret);
    const took = start.durationTo(Io.Clock.awake.now(t.io)).toMilliseconds();
    try t.exits(r, 1);
    try t.says(r, "Timeout");
    if (took >= 5000) return t.fail("a 1s await took {d}ms", .{took});
}

fn slowClient(t: *Tests) !void {
    try t.exits(try t.runPlan(
        \\- name: slow-client
        \\  steps:
        \\    - exec:
        \\        argv: [$SELF, client, slow]
        \\      timeout: 15s
        \\      expect:
        \\        exit: 0
        \\        stdout: "done\n"
    , secret), 0);
}

fn outputLimit(t: *Tests) !void {
    const r = try t.runPlan(
        \\- name: large
        \\  steps:
        \\    - exec:
        \\        argv: [$SELF, client, big]
        \\      expect:
        \\        exit: 0
    , secret);
    try t.exits(r, 1);
    try t.says(r, "StreamTooLong");
}

fn captureTypeError(t: *Tests) !void {
    const r = try t.runPlan(
        \\- name: bad-capture
        \\  steps:
        \\
    ++ login ++
        \\    - fetch:
        \\        url: $BASE/protected
        \\        bearer:
        \\          step: login
        \\          json: ''
        \\      expect:
        \\        status: 200
        \\
    ++ independent, secret);
    try t.exits(r, 1);
    try t.says(r, "\"case\":\"independent\",\"status\":\"pass\"");
}

fn runId(t: *Tests) !void {
    try t.exits(try t.runPlan(
        \\- name: run-id
        \\  steps:
        \\    - exec:
        \\        argv:
        \\          - $SELF
        \\          - client
        \\          - print
        \\          - run: true
        \\      expect:
        \\        exit: 0
        \\        stdout: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    , secret), 0);
}

fn tcpConversation(t: *Tests) !void {
    var server: http.Server = undefined;
    try server.start(t.io, std.heap.smp_allocator, .{
        .identity = &t.identity,
        .handler = t.routes.handler(),
    });
    defer server.stop();
    const plain = t.base[mem.findScalarLast(u8, t.base, ':').? + 1 ..];
    const r = try t.runPlan(try t.gpa.print(
        \\- name: fragmented
        \\  steps:
        \\    - tcp:
        \\        connect: 127.0.0.1:{[plain]s}
        \\        exchange:
        \\          - send: "GET /redirect HTTP/1.1\r\nHost: localhost\r\n"
        \\          - pause: 1s
        \\          - send: "Connection: close\r\n\r\n"
        \\          - expect:
        \\              prefix: "HTTP/1.1 302 Found\r\n"
        \\              matches: "\r\n\r\n[{{][}}]$"
        \\          - close: eof
        \\- name: refused
        \\  steps:
        \\    - tcp:
        \\        connect: 127.0.0.1:{[plain]s}
        \\        exchange:
        \\          - send: "GET /redirect HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        \\          - expect:
        \\              prefix: "HTTP/1.1 200 "
        \\- name: verified
        \\  steps:
        \\    - tcp:
        \\        connect: localhost:{[tls]d}
        \\        tls: verify
        \\        ca: $TMP/ca.pem
        \\        exchange:
        \\          - send: "GET /redirect HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        \\          - expect:
        \\              prefix: "HTTP/1.1 302 Found\r\n"
        \\          - close: [eof, reset]
        \\- name: untrusted
        \\  steps:
        \\    - tcp:
        \\        connect: localhost:{[tls]d}
        \\        tls: verify
        \\        exchange:
        \\          - send: "GET /redirect HTTP/1.1\r\nHost: localhost\r\n\r\n"
        \\- name: insecure
        \\  steps:
        \\    - tcp:
        \\        connect: 127.0.0.1:{[tls]d}
        \\        tls: insecure
        \\        exchange:
        \\          - send: "GET /redirect HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        \\          - expect:
        \\              contains: "Location: /must-not-fetch\r\n"
    , .{ .plain = plain, .tls = server.port() }), secret);
    try t.exits(r, 1);
    for ([_][]const u8{ "fragmented", "verified", "insecure" }) |name|
        try t.says(r, try t.gpa.print("\"case\":\"{s}\",\"status\":\"pass\"", .{name}));
    try t.says(r, "\"field\":\"exchange/2/prefix\",\"got\":\"HTTP/1.1 302 Found");
    try t.says(r, "\"case\":\"untrusted\",\"status\":\"fail\"");
    try t.asked("/redirect", 4);
}

fn treeAudit(t: *Tests) !void {
    const io = t.io;
    const cwd = Io.Dir.cwd();
    for ([_][]const u8{ "tree/clean/nested", "tree/leak" }) |path|
        try cwd.createDirPath(io, try t.gpa.print("{s}/{s}", .{ t.root, path }));
    for ([_][2][]const u8{
        .{ "tree/outside", secret },
        .{ "tree/clean/nested/conf", "user=admin\n" },
        .{ "tree/leak/copy", "password=" ++ secret },
    }) |file| try cwd.writeFile(io, .{
        .sub_path = try t.gpa.print("{s}/{s}", .{ t.root, file[0] }),
        .data = file[1],
    });
    try cwd.symLink(io, "../outside", try t.gpa.print("{s}/tree/clean/link", .{t.root}), .{});
    const r = try t.runPlan(
        \\- name: clean
        \\  steps:
        \\    - tree: $TMP/tree/clean
        \\      expect:
        \\        entries: 3
        \\        files: 1
        \\        type:
        \\          one_of: [file, directory, symlink]
        \\        content:
        \\          absent:
        \\            fixture: password
        \\- name: leaked
        \\  steps:
        \\    - tree: $TMP/tree/leak
        \\      expect:
        \\        content:
        \\          absent:
        \\            fixture: password
        \\- name: named
        \\  steps:
        \\    - tree:
        \\        roots: [$TMP/tree/clean, $TMP/tree/leak]
        \\        allow: ['^copy$']
        \\      expect:
        \\        name:
        \\          not_matches: ^(conf|link)$
    , secret);
    try t.exits(r, 1);
    try t.says(r, "\"case\":\"clean\",\"status\":\"pass\"");
    try t.says(r, "\"case\":\"leaked\",\"status\":\"fail\"");
    try t.says(r, "\"field\":\"content\"");
    try t.says(r, "/tree/clean/link: link\"");
    try t.hides(r, "secret-password");
}

fn writeRefusal(t: *Tests) !void {
    const io = t.io;
    const cwd = Io.Dir.cwd();
    for ([_][]const u8{ "locked", "open" }) |name|
        try cwd.createDirPath(io, try t.gpa.print("{s}/{s}", .{ t.root, name }));
    var locked = try cwd.openDir(io, try t.gpa.print("{s}/locked", .{t.root}), .{});
    defer locked.close(io);
    try locked.setPermissions(io, .fromMode(0o500));
    defer locked.setPermissions(io, .fromMode(0o700)) catch {};
    const r = try t.runPlan(
        \\- name: refused
        \\  steps:
        \\    - write: $TMP/locked/code
        \\      expect:
        \\        errno:
        \\          one_of: [EACCES, EPERM, EROFS]
        \\- name: allowed
        \\  steps:
        \\    - write: $TMP/open/code
        \\      expect:
        \\        errno: EACCES
    , secret);
    try t.exits(r, 1);
    try t.says(r, "\"case\":\"refused\",\"status\":\"pass\"");
    try t.says(r, "WriteNotRefused");
    if (cwd.access(io, try t.gpa.print("{s}/open/code", .{t.root}), .{})) |_|
        return t.fail("an unrefused write left its file", .{})
    else |_| {}
}

/// client is what the plans' exec steps run, standing in for a service's
/// own client.
fn client(io: Io, gpa: Allocator, args: []const []const u8) !void {
    const mode = args[0];
    const stdout = Io.File.stdout();
    if (mem.eql(u8, mode, "print") and (args.len == 2 or args.len == 3)) {
        // print TEXT [STATUS]
        try stdout.writeStreamingAll(io, try gpa.print("{s}\n", .{args[1]}));
        if (args.len == 3) std.process.exit(try std.fmt.parseInt(u8, args[2], 10));
    } else if (mem.eql(u8, mode, "drain")) {
        // Output before input: a runner that only wrote stdin first would hang.
        try repeat(io, stdout, 'o', 100000);
        try repeat(io, Io.File.stderr(), 'e', 10000);
        var in_buf: [4096]u8 = undefined;
        var out_buf: [4096]u8 = undefined;
        var in = Io.File.stdin().readerStreaming(io, &in_buf);
        var out = stdout.writerStreaming(io, &out_buf);
        _ = try in.interface.streamRemaining(&out.interface);
        try out.interface.flush();
        std.process.exit(7);
    } else if (mem.eql(u8, mode, "helper") and args.len == 2) {
        // A helper that outlives the client keeps its output pipes open.
        const self = try std.process.executablePathAlloc(io, gpa);
        const helper = try std.process.spawn(io, .{ .argv = &.{ self, "client", "sleep" } });
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = args[1],
            .data = try gpa.print("{d}", .{helper.id.?}),
        });
    } else if (mem.eql(u8, mode, "sleep")) {
        try io.sleep(.fromSeconds(60), .awake);
    } else if (mem.eql(u8, mode, "close-and-sleep")) {
        stdout.close(io);
        Io.File.stderr().close(io);
        try io.sleep(.fromSeconds(60), .awake);
    } else if (mem.eql(u8, mode, "slow")) {
        try io.sleep(.fromMilliseconds(10200), .awake);
        try stdout.writeStreamingAll(io, "done\n");
    } else if (mem.eql(u8, mode, "big")) {
        try repeat(io, stdout, 'x', 2000000);
    } else return error.Usage;
}

fn repeat(io: Io, file: Io.File, byte: u8, n: usize) !void {
    var buf: [4096]u8 = undefined;
    var w = file.writerStreaming(io, &buf);
    try w.interface.splatByteAll(byte, n);
    try w.interface.flush();
}
