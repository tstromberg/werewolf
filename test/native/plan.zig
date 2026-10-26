//! plan reads a form's tests.yaml and test/native/platform.yaml on the build
//! host, refuses what the guest runner would otherwise have to trust, and
//! gives the drivers the harness builds, each YAML suite with the probe data
//! probes.zig runs. The guest parses no YAML. See test/native/README.md.

const std = @import("std");
const yaml = @import("form").yaml;
const checks = @import("steps.zig");
const hosts = @import("host.zig");
const scenarios = @import("scenario.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const Json = std.json.Value;

pub const max_bytes = 256 << 10;
const max_depth = 32;

pub const Fixture = struct { name: []const u8, path: []const u8 };

/// Driver is one suite: a test client the stage starts, as root or through
/// leash under the suite's user and policy.
pub const Driver = struct {
    name: []const u8,
    /// source is the Zig file beside tests.yaml, or probes.zig for YAML.
    source: []const u8,
    mode: []const u8,
    user: []const u8 = "root",
    groups: []const []const u8 = &.{},
    pledge: []const u8 = "stdio rpath",
    read: []const []const u8 = &.{},
    connect: []const []const u8 = &.{},
    run: []const []const u8 = &.{},
    memory: u16 = 128,
    allow: []const []const u8 = &.{},
    readiness: bool = false,
    config: []const Fixture = &.{},
    seed: []const []const u8 = &.{},
    verify: []const []const u8 = &.{},
    /// probes is a YAML suite's data for probes.zig; null for native code.
    probes: ?Json = null,

    pub fn cases(d: Driver, phase: Phase) []const []const u8 {
        return switch (phase) {
            .seed => d.seed,
            .verify => d.verify,
        };
    }
};

pub const Phase = enum { seed, verify };

pub const Plan = struct {
    legacy: bool = false,
    timeout_seconds: u16 = 300,
    /// packages are the test image's extra packages, sorted.
    packages: []const []const u8 = &.{},
    /// prune is what those packages bring that no test runs, as a form's
    /// prune is (docs/forms.md): usr/bin/scp. Sorted.
    prune: []const []const u8 = &.{},
    drivers: []const Driver = &.{},
    /// host are the suites run from the build host (host.zig).
    host: []const hosts.Suite = &.{},
    /// form, skip, console and kernel_address are a scenario's (scenario.zig).
    form: ?[]const u8 = null,
    skip: []const []const u8 = &.{},
    console: []const scenarios.Console = &.{},
    kernel_address: bool = true,
};

pub const HostSuite = hosts.Suite;
pub const Console = scenarios.Console;
pub const consoleLine = scenarios.line;

/// Failure says why a plan was refused, with its file and line.
pub const Failure = struct { text: []const u8 = "" };

pub const Error = error{ Plan, OutOfMemory };

pub const reserved = [_][]const u8{ "test-platform", "test-lifecycle" };

/// completion is the Expect pattern test/boot waits for: the stage's whole
/// completion record, newline and all, so the run's last record is never
/// cut short by test/boot printing its own result.
pub const completion = "werewolf-test: [^\\r\\n]*\"event\":\"complete\"[^\\r\\n]*\\}\\r*\\n";
const runtime_grants = [_][]const u8{ "python:native", "node:native", "java:native" };
const test_pledges = [_][]const u8{
    "stdio",
    "rpath",
    "wpath",
    "proc",
    "unix",
    "connect",
    "exec",
    "inet",
};
const forbidden_packages = [_][]const u8{ "busybox", "busybox-full", "bash", "dash", "mksh" };

/// load reads the plan at path in dir, whose native sources it checks are
/// beside it. A form's own plan also goes through form, below.
pub fn load(
    io: Io,
    gpa: Allocator,
    dir: Io.Dir,
    path: []const u8,
    failure: *Failure,
) Error!Plan {
    const text = dir.readFileAlloc(
        io,
        path,
        gpa,
        .limited(max_bytes + 1),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return refuse(
            gpa,
            failure,
            "{s}: test plan exceeds 256 KiB",
            .{path},
        ),
        else => return refuse(gpa, failure, "{s}: {s}", .{ path, @errorName(err) }),
    };
    var c: Check = .{ .gpa = gpa, .path = path, .failure = failure };
    const plan = try c.parse(text);
    const parent = std.fs.path.dirname(path) orelse ".";
    for (plan.drivers) |d| {
        if (d.probes != null) continue;
        const source = try gpa.print("{s}/{s}", .{ parent, d.source });
        const stat = dir.statFile(io, source, .{}) catch null;
        if (stat == null or stat.?.kind != .file)
            return refuse(gpa, failure, "{s}: {s}: driver source must be adjacent Zig source", .{
                path, d.name,
            });
    }
    return plan;
}

/// form loads FORM's plan from dir, a form's directory, and holds it to what
/// a form may declare: retained shell checks keep the legacy path, a form
/// without suites must be a declared foundation, and the shared suites'
/// names are not a form's.
pub fn form(
    io: Io,
    gpa: Allocator,
    root: Io.Dir,
    dir: []const u8,
    failure: *Failure,
) Error!Plan {
    const path = try gpa.print("{s}/test/tests.yaml", .{dir});
    var plan = try load(io, gpa, root, path, failure);
    if (plan.form != null or plan.skip.len > 0 or plan.console.len > 0 or !plan.kernel_address)
        return refuse(gpa, failure, "{s}: form, skip, console and kernel_address are a " ++
            "scenario's (test/scenarios); a form says check.skip and test/console", .{path});
    for ([_][]const u8{ "checks", "checks-again" }) |name| {
        const stat = root.statFile(io, try gpa.print("{s}/test/{s}", .{ dir, name }), .{}) catch
            continue;
        // Retaining a shell suite must not silently stop running its assertions.
        if (stat.kind == .file) plan.legacy = true;
    }
    for (plan.drivers) |d| for (reserved) |name| if (mem.eql(u8, d.name, name))
        return refuse(gpa, failure, "{s}: {s} is reserved for shared checks", .{ path, name });
    if (plan.drivers.len == 0) {
        const exceptions = root.readFileAlloc(
            io,
            "test/form-coverage-exceptions",
            gpa,
            .limited(64 << 10),
        ) catch |err| return refuse(
            gpa,
            failure,
            "test/form-coverage-exceptions: {s}",
            .{@errorName(err)},
        );
        if (!foundation(exceptions, std.fs.path.basename(dir)))
            return refuse(
                gpa,
                failure,
                "{s}: service forms require their own test suites",
                .{path},
            );
    }
    return plan;
}

/// scenario loads the plan in dir, a scenario's directory (scenario.zig),
/// which names the form it boots, and may have no suites of its own: the
/// shared checks and its console lines can be all it asks.
pub fn scenario(
    io: Io,
    gpa: Allocator,
    root: Io.Dir,
    dir: []const u8,
    failure: *Failure,
) Error!Plan {
    const path = try gpa.print("{s}/tests.yaml", .{dir});
    const plan = try load(io, gpa, root, path, failure);
    if (plan.form == null) return refuse(gpa, failure, "{s}: a scenario names its form", .{path});
    for (plan.drivers) |d| for (reserved) |name| if (mem.eql(u8, d.name, name))
        return refuse(gpa, failure, "{s}: {s} is reserved for shared checks", .{ path, name });
    return plan;
}

/// foundation reports whether exceptions excuse name from every case.
fn foundation(exceptions: []const u8, name: []const u8) bool {
    var lines = mem.splitScalar(u8, exceptions, '\n');
    while (lines.next()) |line| {
        var words = mem.tokenizeAny(u8, line, " \t");
        const first = words.next() orelse continue;
        if (mem.eql(u8, first, name) and mem.eql(u8, words.next() orelse "", "0")) return true;
    }
    return false;
}

/// boot is the clean boot's plan: declared readiness first, then the shared
/// startup and lifecycle checks less the form's known exclusions, then the
/// form's own suites. Killing a database's before-command could otherwise
/// erase a half-initialized first boot.
pub fn boot(
    gpa: Allocator,
    plan: Plan,
    platform: Plan,
    skip: []const []const u8,
    failure: *Failure,
) Error!Plan {
    for (skip) |name| {
        const known = for (platform.drivers) |d| {
            if (has(d.seed, name) or has(d.verify, name)) break true;
        } else false;
        if (!known) return refuse(gpa, failure, "unknown shared check exclusion: {s}", .{name});
    }
    var drivers: std.ArrayList(Driver) = .empty;
    for (plan.drivers) |d| if (d.readiness) try drivers.append(gpa, d);
    for (reserved) |name| for (platform.drivers) |d| {
        if (!mem.eql(u8, d.name, name)) continue;
        var shared = d;
        shared.seed = try without(gpa, d.seed, skip);
        shared.verify = try without(gpa, d.verify, skip);
        if (shared.seed.len + shared.verify.len > 0) try drivers.append(gpa, shared);
    };
    for (plan.drivers) |d| if (!d.readiness) try drivers.append(gpa, d);
    var out = plan;
    out.packages = try sorted(gpa, try mem.concat(gpa, []const u8, &.{
        plan.packages,
        platform.packages,
    }));
    out.drivers = drivers.items;
    return out;
}

fn without(
    gpa: Allocator,
    names: []const []const u8,
    skip: []const []const u8,
) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (names) |name| if (!has(skip, name)) try out.append(gpa, name);
    return out.items;
}

pub fn has(names: []const []const u8, name: []const u8) bool {
    for (names) |n| if (mem.eql(u8, n, name)) return true;
    return false;
}

/// sorted is names sorted, without duplicates.
fn sorted(gpa: Allocator, names: []const []const u8) ![]const []const u8 {
    const out = try gpa.dupe([]const u8, names);
    mem.sort([]const u8, out, {}, lessThan);
    var n: usize = 0;
    for (out) |name| {
        if (n > 0 and mem.eql(u8, out[n - 1], name)) continue;
        out[n] = name;
        n += 1;
    }
    return out[0..n];
}

pub fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return mem.lessThan(u8, a, b);
}

fn refuse(gpa: Allocator, failure: *Failure, comptime fmt: []const u8, args: anytype) Error {
    failure.text = try gpa.print(fmt, args);
    return error.Plan;
}

/// Check validates one plan file, reporting the line of the suite, case or
/// step at fault.
pub const Check = struct {
    gpa: Allocator,
    path: []const u8,
    failure: *Failure,
    line: usize = 1,

    pub fn fail(c: *const Check, comptime fmt: []const u8, args: anytype) Error {
        return refuse(c.gpa, c.failure, "{s}:{d}: " ++ fmt, .{ c.path, c.line } ++ args);
    }

    fn parse(c: *Check, text: []const u8) Error!Plan {
        if (text.len > max_bytes) return c.fail("test plan exceeds 256 KiB", .{});
        if (!std.unicode.utf8ValidateSlice(text)) return c.fail("test plan is not UTF-8", .{});
        for (text, 0..) |ch, i| if (ch < ' ' and ch != '\n' and ch != '\t' and ch != '\r') {
            c.line = mem.count(u8, text[0..i], "\n") + 1;
            return c.fail("a control character", .{});
        };
        var diag: yaml.Diagnostic = .{};
        const node = yaml.parse(c.gpa, text, .plan, &diag) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Syntax => {
                c.line = diag.line;
                return c.fail("{s}", .{diag.why});
            },
        };
        if (node.map.len == 0) return c.fail("empty test plan", .{});
        return c.plan(node, try c.value(node, 1, 0));
    }

    /// value is node as JSON: quoted scalars are text, plain ones typed as
    /// JSON would read them, and anything YAML 1.1 reads as another type is
    /// refused, so no reader can take a plan to say something else.
    fn value(c: *Check, node: yaml.Node, line: usize, depth: usize) Error!Json {
        c.line = line;
        if (depth > max_depth) return c.fail("test plan nesting exceeds 32 levels", .{});
        switch (node) {
            .scalar => |s| return c.scalar(s),
            .list => |items| {
                var out: std.json.Array = .init(c.gpa);
                for (items) |item| try out.append(try c.value(item, lineOf(item, line), depth + 1));
                return .{ .array = out };
            },
            .map => |entries| {
                var out: std.json.ObjectMap = .empty;
                for (entries) |e| try out.put(
                    c.gpa,
                    e.key,
                    try c.value(e.value, e.line, depth + 1),
                );
                return .{ .object = out };
            },
        }
    }

    fn scalar(c: *Check, s: yaml.Scalar) Error!Json {
        const t = s.text;
        if (!s.plain()) return .{ .string = t };
        if (mem.eql(u8, t, "true")) return .{ .bool = true };
        if (mem.eql(u8, t, "false")) return .{ .bool = false };
        if (mem.eql(u8, t, "null")) return .null;
        const digits = if (t[0] == '-') t[1..] else t;
        const integral = digits.len > 0 and allIn(digits, "0123456789") and
            (digits[0] != '0' or digits.len == 1);
        if (integral) {
            const n = std.fmt.parseInt(i64, t, 10) catch
                return c.fail("integer exceeds exact numeric range: {s}", .{t});
            if (@abs(n) >= 1 << 53) return c.fail("integer exceeds exact numeric range: {s}", .{t});
            return .{ .integer = n };
        }
        if (decimal(digits)) {
            const f = std.fmt.parseFloat(f64, t) catch unreachable;
            if (!std.math.isFinite(f)) return c.fail("nonfinite number: {s}", .{t});
            return .{ .float = f };
        }
        if (yaml.ambiguous(t)) return c.fail("quote ambiguous scalar {s}", .{t});
        return .{ .string = t };
    }

    fn plan(c: *Check, node: yaml.Node, data: Json) Error!Plan {
        c.line = 1;
        try c.fields(data, &([_][]const u8{
            "version", "packages", "prune", "suites", "host", "legacy", "timeout",
        } ++ scenarios.keys), &.{ "version", "suites" });
        const top = data.object;
        const version = top.get("version").?;
        c.line = keyLine(node, "version");
        if (version != .integer or version.integer != 1)
            return c.fail("unsupported test plan version", .{});
        var out: Plan = .{};
        if (top.get("legacy")) |legacy| {
            c.line = keyLine(node, "legacy");
            if (legacy != .bool) return c.fail("legacy must be boolean", .{});
            out.legacy = legacy.bool;
        }
        if (top.get("timeout")) |timeout| {
            c.line = keyLine(node, "timeout");
            out.timeout_seconds = seconds(timeout, 1, 1800) orelse
                return c.fail("phase timeout must be 1s..1800s", .{});
        }
        try scenarios.read(c, node, top, &out);
        const suites = top.get("suites").?;
        c.line = keyLine(node, "suites");
        if (suites != .array or suites.array.items.len > 32)
            return c.fail("expected 0..32 suites", .{});
        var packages: std.ArrayList([]const u8) = .empty;
        if (top.get("packages")) |list| {
            c.line = keyLine(node, "packages");
            try packages.appendSlice(c.gpa, try c.strings(list));
        }
        var drivers: std.ArrayList(Driver) = .empty;
        const suite_nodes = node.get("suites").?;
        for (suites.array.items, 0..) |entry, i| {
            c.line = lineOf(suite_nodes.list[i], 1);
            const d = try c.suite(suite_nodes.list[i], entry, out.timeout_seconds, &packages);
            for (drivers.items) |other| if (mem.eql(u8, other.name, d.name)) {
                c.line = lineOf(suite_nodes.list[i], 1);
                return c.fail("duplicate suite {s}", .{d.name});
            };
            try drivers.append(c.gpa, d);
        }
        c.line = keyLine(node, "packages");
        for (packages.items) |p| if (!packageName(p) or has(&forbidden_packages, p))
            return c.fail("invalid test package {s}", .{p});
        out.packages = try sorted(c.gpa, packages.items);
        if (top.get("prune")) |list| {
            c.line = keyLine(node, "prune");
            const paths = try c.strings(list);
            for (paths) |p| if (!imagePath(p))
                return c.fail("invalid test prune {s}: relative and clean, usr/bin/scp", .{p});
            out.prune = try sorted(c.gpa, paths);
        }
        out.drivers = drivers.items;
        if (top.get("host")) |list| {
            c.line = keyLine(node, "host");
            if (list != .array or list.array.items.len == 0 or list.array.items.len > 8)
                return c.fail("expected 1..8 host suites", .{});
            var host: std.ArrayList(hosts.Suite) = .empty;
            for (list.array.items, node.get("host").?.list) |entry, host_node| {
                c.line = lineOf(host_node, c.line);
                const s = try hosts.suite(c, host_node, entry, out.timeout_seconds);
                // Coverage counts a case by its name, wherever it runs.
                for (try mem.concat(c.gpa, []const u8, &.{ s.seed, s.verify })) |name| {
                    for (drivers.items) |d| if (has(d.seed, name) or has(d.verify, name))
                        return c.fail("duplicate case {s}", .{name});
                    for (host.items) |other| if (has(other.seed, name) or has(other.verify, name))
                        return c.fail("duplicate case {s}", .{name});
                }
                for (host.items) |other| if (mem.eql(u8, other.name, s.name))
                    return c.fail("duplicate suite {s}", .{s.name});
                try host.append(c.gpa, s);
            }
            out.host = host.items;
        }
        return out;
    }

    fn suite(
        c: *Check,
        node: yaml.Node,
        data: Json,
        phase_seconds: u16,
        packages: *std.ArrayList([]const u8),
    ) Error!Driver {
        const line = c.line;
        try c.fields(data, &.{
            "name",   "user", "groups", "policy", "fixtures",  "cases",
            "source", "mode", "memory", "allow",  "readiness",
        }, &.{"name"});
        const s = data.object;
        const given = try c.identity(s.get("name").?);
        var d: Driver = .{
            .name = if (mem.startsWith(u8, given, "test-")) given else try c.gpa.print(
                "test-{s}",
                .{given},
            ),
            .source = "probes.zig",
            .mode = "probes",
        };
        if (s.get("readiness")) |r| d.readiness = if (r == .bool)
            r.bool
        else
            return c.fail("readiness must be boolean", .{});
        if (s.get("user")) |user| d.user = if (user == .string and account(user.string))
            user.string
        else
            return c.fail("invalid suite user", .{});
        if (s.get("groups")) |groups| d.groups = try c.strings(groups);
        if (d.groups.len > 16) return c.fail("invalid test groups", .{});
        for (d.groups, 0..) |g, i| if (!account(g) or mem.eql(u8, g, "root") or
            has(d.groups[0..i], g))
            return c.fail("invalid test groups", .{});
        if (s.get("memory")) |memory| {
            if (memory != .integer or memory.integer < 16 or memory.integer > 8192)
                return c.fail("driver memory must be 16..8192 MiB", .{});
            d.memory = @intCast(memory.integer);
        }
        if (s.get("allow")) |allow| d.allow = try c.strings(allow);
        for (d.allow, 0..) |grant, i| if (!has(&runtime_grants, grant) or has(d.allow[0..i], grant))
            return c.fail("invalid driver runtime allowance {s}", .{grant});
        if (s.get("policy")) |policy| {
            try c.fields(policy, &.{ "pledge", "read", "connect", "run" }, &.{});
            const p = policy.object;
            if (p.get("pledge")) |pledge| d.pledge = if (pledge == .string)
                pledge.string
            else
                return c.fail("pledge must be a string", .{});
            if (p.get("read")) |read| d.read = try c.strings(read);
            if (p.get("connect")) |connect| d.connect = try c.strings(connect);
            if (p.get("run")) |run| d.run = try c.strings(run);
        }
        var words = mem.tokenizeAny(u8, d.pledge, " \t\n\r");
        while (words.next()) |word| if (!has(&test_pledges, word))
            return c.fail("unsupported test pledge {s}", .{word});
        for ([_][]const []const u8{ d.read, d.connect, d.run }, 0..) |grants, field| {
            for (grants) |grant| {
                if (field == 1 and mem.startsWith(u8, grant, "tcp/") and
                    allIn(grant[4..], "0123456789"))
                {
                    const number = std.fmt.parseInt(u32, grant[4..], 10) catch 0;
                    if (grant.len < 5 or grant.len > 9 or grant[4] == '0' or number > 65535)
                        return c.fail("invalid test TCP port {s}", .{grant});
                    continue;
                }
                if (!absolute(grant) or mem.findAny(u8, grant, " \t\n\r\x0b\x0c") != null)
                    return c.fail("test grants must be explicit absolute paths: {s}", .{grant});
            }
        }
        var config: std.ArrayList(Fixture) = .empty;
        if (s.get("fixtures")) |fixtures| {
            if (fixtures != .object) return c.fail("fixtures must be a map", .{});
            var it = fixtures.object.iterator();
            while (it.next()) |e| {
                const name = e.key_ptr.*;
                const path = e.value_ptr.*;
                if (!ident(name) or mem.eql(u8, name, "context"))
                    return c.fail("invalid fixture name {s}", .{name});
                if (path != .string or !absolute(path.string) or
                    !mem.startsWith(u8, path.string, "/run/config/") or
                    path.string.len == "/run/config/".len or
                    !allIn(
                        path.string["/run/config/".len..],
                        "abcdefghijklmnopqrstuvwxyz0123456789/-",
                    ))
                    return c.fail("fixtures must name /run/config files: {s}", .{name});
                try config.append(c.gpa, .{ .name = name, .path = path.string });
            }
        }
        d.config = config.items;
        if (s.get("source")) |source| {
            if (s.get("policy") == null or s.get("mode") == null)
                return c.fail("native source requires mode/policy", .{});
            d.source = if (source == .string and source.string.len > 4 and
                mem.endsWith(u8, source.string, ".zig") and
                mem.findAny(u8, source.string, "/\\") == null and
                !mem.startsWith(u8, source.string, "."))
                source.string
            else
                return c.fail("driver source must be adjacent Zig source", .{});
            d.mode = try c.identity(s.get("mode").?);
            const cases = s.get("cases") orelse return c.fail("declare seed and verify cases", .{});
            try c.fields(cases, &.{ "seed", "verify" }, &.{ "seed", "verify" });
            d.seed = try c.caseSet(cases.object.get("seed").?);
            d.verify = try c.caseSet(cases.object.get("verify").?);
            if (d.seed.len + d.verify.len == 0)
                return c.fail("driver requires at least one case", .{});
            return d;
        }
        if (s.get("mode") != null) return c.fail("mode requires native source", .{});
        const cases = s.get("cases") orelse return c.fail("expected 1..256 cases", .{});
        if (cases != .array or cases.array.items.len == 0 or cases.array.items.len > 256)
            return c.fail("expected 1..256 cases", .{});
        const case_nodes = node.get("cases").?.list;
        var seed: std.ArrayList([]const u8) = .empty;
        var verify: std.ArrayList([]const u8) = .empty;
        var compiled: std.json.Array = .init(c.gpa);
        for (cases.array.items, case_nodes) |entry, case_node| {
            c.line = lineOf(case_node, line);
            const out = try c.case(case_node, entry, d, phase_seconds, &compiled, packages);
            for (out.phases.array.items) |phase| {
                const list = if (mem.eql(u8, phase.string, "seed")) &seed else &verify;
                try list.append(c.gpa, out.name);
            }
        }
        d.seed = seed.items;
        d.verify = verify.items;
        var fixtures: std.json.ObjectMap = .empty;
        for (d.config) |f| try fixtures.put(c.gpa, f.name, .{ .string = if (mem.eql(
            u8,
            d.user,
            "root",
        ))
            f.path
        else
            try c.gpa.print("/run/svc/{s}/{s}", .{ d.name, f.name }) });
        var probes: std.json.ObjectMap = .empty;
        try probes.put(c.gpa, "source", .{ .string = c.path });
        try probes.put(c.gpa, "fixtures", .{ .object = fixtures });
        try probes.put(c.gpa, "cases", .{ .array = compiled });
        d.probes = .{ .object = probes };
        return d;
    }

    fn caseSet(c: *Check, list: Json) Error![]const []const u8 {
        const names = c.strings(list) catch return c.fail("invalid case set", .{});
        for (names, 0..) |name, i| if (!ident(name) or has(names[0..i], name))
            return c.fail("invalid case set", .{});
        return names;
    }

    const Case = struct { name: []const u8, phases: Json };

    fn case(
        c: *Check,
        node: yaml.Node,
        data: Json,
        d: Driver,
        phase_seconds: u16,
        compiled: *std.json.Array,
        packages: *std.ArrayList([]const u8),
    ) Error!Case {
        const line = c.line;
        try c.fields(data, &.{ "name", "phases", "steps" }, &.{ "name", "steps" });
        const k = data.object;
        const name = try c.identity(k.get("name").?);
        for (compiled.items) |other| if (mem.eql(u8, other.object.get("name").?.string, name))
            return c.fail("duplicate case {s}", .{name});
        const phases = try phasesOf(c, k.get("phases"));
        const steps = k.get("steps").?;
        if (steps != .array or steps.array.items.len == 0 or steps.array.items.len > 64)
            return c.fail("expected 1..64 steps", .{});
        const step_nodes = node.get("steps").?.list;
        var previous: std.array_hash_map.String([]const u8) = .empty;
        var out: std.json.Array = .init(c.gpa);
        for (steps.array.items, step_nodes, 1..) |item, item_node, index| {
            c.line = lineOf(item_node, line);
            try out.append(try checks.step(c, item, d, phase_seconds, index, &previous, packages));
        }
        var result: std.json.ObjectMap = .empty;
        try result.put(c.gpa, "name", .{ .string = name });
        try result.put(c.gpa, "phases", phases);
        try result.put(c.gpa, "steps", .{ .array = out });
        try compiled.append(.{ .object = result });
        return .{ .name = name, .phases = phases };
    }

    pub fn identity(c: *Check, v: Json) Error![]const u8 {
        if (v != .string or !ident(v.string)) return c.fail("invalid test identity", .{});
        return v.string;
    }

    pub fn strings(c: *Check, v: Json) Error![]const []const u8 {
        if (v != .array) return c.fail("expected string list", .{});
        const out = try c.gpa.alloc([]const u8, v.array.items.len);
        for (v.array.items, out) |item, *s| s.* = if (item == .string)
            item.string
        else
            return c.fail("expected string list", .{});
        return out;
    }

    /// fields refuses a value that is not a map with only allowed keys and
    /// every required one.
    pub fn fields(
        c: *Check,
        v: Json,
        allowed: []const []const u8,
        required: []const []const u8,
    ) Error!void {
        if (v != .object) return c.fail("expected a map with {s}", .{try listing(c.gpa, allowed)});
        for (v.object.keys()) |key| if (!has(allowed, key))
            return c.fail("unknown field {s}: expected {s}", .{ key, try listing(c.gpa, allowed) });
        for (required) |key| if (!v.object.contains(key)) return c.fail(
            "missing field {s}",
            .{key},
        );
    }
};

/// phasesOf is a case's phases, both unless it names them.
pub fn phasesOf(c: *Check, given: ?Json) Error!Json {
    if (given) |list| {
        const names = try c.strings(list);
        if (names.len == 0) return c.fail("invalid phases", .{});
        for (names, 0..) |phase, i| if ((!mem.eql(u8, phase, "seed") and
            !mem.eql(u8, phase, "verify")) or has(names[0..i], phase))
            return c.fail("invalid phases", .{});
        return list;
    }
    var both: Json = .{ .array = .init(c.gpa) };
    try both.array.append(.{ .string = "seed" });
    try both.array.append(.{ .string = "verify" });
    return both;
}

fn listing(gpa: Allocator, names: []const []const u8) ![]const u8 {
    return mem.join(gpa, ", ", try sorted(gpa, names));
}

pub fn lineOf(node: yaml.Node, fallback: usize) usize {
    return if (node == .map and node.map.len > 0) node.map[0].line else fallback;
}

pub fn keyLine(node: yaml.Node, key: []const u8) usize {
    for (node.map) |e| if (mem.eql(u8, e.key, key)) return e.line;
    return 1;
}

/// seconds reads `Ns` within min..max.
pub fn seconds(v: Json, min: u16, max: u16) ?u16 {
    if (v != .string or v.string.len < 2 or !mem.endsWith(u8, v.string, "s")) return null;
    const digits = v.string[0 .. v.string.len - 1];
    if (!allIn(digits, "0123456789") or (digits[0] == '0' and digits.len > 1)) return null;
    const n = std.fmt.parseInt(u16, digits, 10) catch return null;
    return if (n >= min and n <= max) n else null;
}

pub fn allIn(s: []const u8, set: []const u8) bool {
    for (s) |ch| if (mem.findScalar(u8, set, ch) == null) return false;
    return true;
}

/// ident is a suite, case, step or fixture name.
pub fn ident(s: []const u8) bool {
    return s.len > 0 and s.len <= 128 and std.ascii.isLower(s[0]) and
        allIn(s, "abcdefghijklmnopqrstuvwxyz0123456789-");
}

pub fn account(s: []const u8) bool {
    return s.len > 0 and s.len <= 128 and (std.ascii.isLower(s[0]) or s[0] == '_') and
        allIn(s, "abcdefghijklmnopqrstuvwxyz0123456789_-");
}

fn packageName(s: []const u8) bool {
    return s.len > 0 and (std.ascii.isLower(s[0]) or std.ascii.isDigit(s[0])) and
        allIn(s, "abcdefghijklmnopqrstuvwxyz0123456789+_.-");
}

/// imagePath is a file as it is in the image: relative, with no empty, .
/// or .. component.
fn imagePath(s: []const u8) bool {
    if (s.len == 0 or s.len > 1024 or s[0] == '/' or
        !allIn(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_.-/"))
        return false;
    var parts = mem.splitScalar(u8, s, '/');
    while (parts.next()) |part| if (part.len == 0 or mem.eql(u8, part, ".") or
        mem.eql(u8, part, "..")) return false;
    return true;
}

/// absolute is an explicit absolute path with no .. component.
pub fn absolute(s: []const u8) bool {
    if (s.len == 0 or s[0] != '/') return false;
    var parts = mem.splitScalar(u8, s, '/');
    while (parts.next()) |part| if (mem.eql(u8, part, "..")) return false;
    return true;
}

/// decimal is digits.digits, the only float a plan writes plainly.
fn decimal(s: []const u8) bool {
    const dot = mem.findScalar(u8, s, '.') orelse return false;
    const whole = s[0..dot];
    const tail = s[dot + 1 ..];
    return whole.len > 0 and tail.len > 0 and allIn(whole, "0123456789") and
        allIn(tail, "0123456789") and (whole[0] != '0' or whole.len == 1);
}

/// writeJson writes value with each object's keys sorted, so equal plans
/// are equal bytes, and floats stay floats.
pub fn writeJson(gpa: Allocator, w: *Io.Writer, value: Json) !void {
    switch (value) {
        .object => |o| {
            const keys = try sorted(gpa, o.keys());
            try w.writeByte('{');
            for (keys, 0..) |key, i| {
                if (i > 0) try w.writeByte(',');
                try std.json.Stringify.encodeJsonString(key, .{}, w);
                try w.writeByte(':');
                try writeJson(gpa, w, o.get(key).?);
            }
            try w.writeByte('}');
        },
        .array => |a| {
            try w.writeByte('[');
            for (a.items, 0..) |item, i| {
                if (i > 0) try w.writeByte(',');
                try writeJson(gpa, w, item);
            }
            try w.writeByte(']');
        },
        .float => |f| {
            var buffer: [64]u8 = undefined;
            const text = std.mem.print(&buffer, "{}", .{f}) catch unreachable;
            try w.writeAll(text);
            if (mem.findAny(u8, text, ".eE") == null) try w.writeAll(".0");
        },
        else => try std.json.Stringify.value(value, .{}, w),
    }
}

/// json is value as writeJson writes it.
pub fn json(gpa: Allocator, value: Json) ![]const u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    writeJson(gpa, &out.writer, value) catch return error.OutOfMemory;
    return out.written();
}

const testing = std.testing;

fn testParse(a: Allocator, text: []const u8, failure: *Failure) Error!Plan {
    var c: Check = .{ .gpa = a, .path = "tests.yaml", .failure = failure };
    return c.parse(text);
}

/// expectPlan and expectRefused are steps.zig's tests' too.
pub fn expectPlan(a: Allocator, text: []const u8) !Plan {
    var failure: Failure = .{};
    return testParse(a, text, &failure) catch |err| {
        std.debug.print("refused: {s}\n{s}\n", .{ failure.text, text });
        return err;
    };
}

pub fn expectRefused(a: Allocator, text: []const u8, why: []const u8) !void {
    var failure: Failure = .{};
    if (testParse(a, text, &failure)) |_| {
        std.debug.print("accepted:\n{s}\n", .{text});
        return error.TestExpectedError;
    } else |err| {
        if (err != error.Plan) return err;
        if (mem.find(u8, failure.text, why) == null) {
            std.debug.print("refused for {s}, not {s}:\n{s}\n", .{ failure.text, why, text });
            return error.TestUnexpectedError;
        }
    }
}

pub fn firstStep(plan: Plan) std.json.ObjectMap {
    const cases = plan.drivers[0].probes.?.object.get("cases").?.array.items;
    return cases[0].object.get("steps").?.array.items[0].object;
}

/// web is a one-suite plan whose case runs steps, a YAML list at column 10.
pub fn web(a: Allocator, steps: []const u8) ![]const u8 {
    return a.print(
        \\version: 1
        \\suites:
        \\  - name: web
        \\    fixtures:
        \\      password: /run/config/app/password
        \\    policy:
        \\      run: [/usr/bin/client]
        \\    cases:
        \\      - name: health
        \\        steps:
        \\{s}
    , .{steps});
}

test "a plain suite runs both phases as root, with pinned transport" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const plan = try expectPlan(a, try web(a,
        \\          - fetch:
        \\              url: http://localhost/
        \\            expect:
        \\              status: 200
    ));
    const d = plan.drivers[0];
    try testing.expectEqualStrings("test-web", d.name);
    try testing.expectEqualStrings("root", d.user);
    try testing.expectEqualStrings("probes", d.mode);
    try testing.expectEqualStrings("health", d.seed[0]);
    try testing.expectEqualStrings("health", d.verify[0]);
    try testing.expectEqual(1, plan.packages.len);
    try testing.expectEqualStrings("libcurl-openssl4", plan.packages[0]);
    try testing.expectEqual(300, plan.timeout_seconds);
    const step = firstStep(plan);
    try testing.expectEqual(11, step.get("line").?.integer);
    try testing.expectEqual(10, step.get("timeout_seconds").?.integer);
    try testing.expectEqualStrings(
        "/run/config/app/password",
        d.probes.?.object.get("fixtures").?.object.get("password").?.string,
    );
}

test "YAML that could be read two ways, or not at all, is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][2][]const u8{
        .{ "version: 1\nversion: 1\nsuites: []\n", "a key given twice" },
        .{ "version: 1\nsuites: &x [*x]\n", "YAML indicator" },
        .{ "version: 01\nsuites: []\n", "ambiguous" },
        .{ "version: !!int 1\nsuites: []\n", "YAML indicator" },
        .{ "", "empty test plan" },
        .{ "version: [\n", "does not end with ]" },
        .{ "version: [[[1]]]\n", "YAML indicator" },
        .{ "version: 1\nsuites: []\nlegacy: yes\n", "ambiguous" },
        .{ "version: 1.0\nsuites: []\n", "unsupported test plan version" },
        .{ "version: 1\nsuites: []\ntimeout: 1e3\n", "ambiguous" },
        .{ "version: 1\nsuites: []\nx: 9007199254740992\n", "exact numeric range" },
        .{ "version: 1\nsuites: []\nnul: \"a\x00b\"\n", "control character" },
        .{ "version: 1\nsuites: [\xff]\n", "UTF-8" },
    }) |case| try expectRefused(a, case[0], case[1]);
    var deep: std.ArrayList(u8) = .empty;
    try deep.appendSlice(a, "version: 1\nsuites: []\nx:\n");
    for (1..40) |level| {
        try deep.appendNTimes(a, ' ', level * 2);
        try deep.appendSlice(a, "y:\n");
    }
    try deep.appendNTimes(a, ' ', 82);
    try deep.appendSlice(a, "z: 1\n");
    try expectRefused(a, deep.items, "nesting exceeds 32 levels");
    try testing.expectEqual(0, (try expectPlan(a, "version: 1\nsuites: []\n")).drivers.len);
}

/// native is a plan with one native suite, its fields at column 4.
fn native(a: Allocator, fields: []const u8) ![]const u8 {
    return a.print(
        \\version: 1
        \\suites:
        \\  - name: client
        \\    source: driver.zig
        \\    mode: protocol
        \\{s}
        \\
    , .{fields});
}

const native_defaults =
    \\    user: nobody
    \\    policy:
    \\      pledge: stdio rpath
    \\    cases:
    \\      seed: [login]
    \\      verify: [login]
;

test "native suites declare their client, identity, policy and cases" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const plan = try expectPlan(a, try native(a, native_defaults ++
        "\n    fixtures:\n      password: /run/config/app/password"));
    const d = plan.drivers[0];
    try testing.expectEqualStrings("test-client", d.name);
    try testing.expectEqualStrings("driver.zig", d.source);
    try testing.expectEqualStrings("password", d.config[0].name);
    try testing.expectEqualStrings("/run/config/app/password", d.config[0].path);
    try testing.expect(d.probes == null);
    try testing.expectEqual(128, d.memory);
    for ([_][]const u8{
        "relative", "/etc/shadow", "/run/config/../shadow", "/run/config/", "/run/config/A",
    }) |path| try expectRefused(a, try native(a, try a.print(native_defaults ++
        "\n    fixtures:\n      password: {s}", .{path})), "/run/config");
    for ([_][]const u8{ "context: /run/config/gvmd/admin-password", "Bad: /run/config/x" }) |f|
        try expectRefused(a, try native(a, try a.print(native_defaults ++
            "\n    fixtures:\n      {s}", .{f})), "invalid fixture name");
    const cases = "    user: nobody\n    policy:\n      pledge: stdio\n    cases:\n";
    for ([_][]const u8{
        "      seed: []\n      verify: []",
        "      seed: ready\n      verify: []",
        "      seed: [42]\n      verify: []",
        "      seed:\n        - [x]\n      verify: []",
        "      seed: [duplicate, duplicate]\n      verify: []",
        "      seed: [ready]",
        "      - seed\n      - verify",
        "      seed: [Bad]\n      verify: []",
    }) |set| try expectRefused(a, try native(a, try a.print(cases ++ "{s}", .{set})), "");
    for ([_][]const u8{ "true", "'1024'", "0", "15", "8193", "[1024]" }) |m|
        try expectRefused(a, try native(a, try a.print(native_defaults ++
            "\n    memory: {s}", .{m})), "driver memory must be 16..8192 MiB");
    try testing.expectEqual(1024, (try expectPlan(a, try native(a, native_defaults ++
        "\n    memory: 1024"))).drivers[0].memory);
    for ([_][]const u8{
        "python:native",                  "[all:native]",
        "[python:exec]",                  "['../all:native']",
        "[python:native, python:native]", "\n      - [python:native]",
    }) |g| try expectRefused(a, try native(a, try a.print(native_defaults ++
        "\n    allow: {s}", .{g})), "");
    for ([_][]const u8{
        "_oci-openvas",      "[root]", "[_oci-openvas, _oci-openvas]", "\n      - [nested]",
        "[\"bad\\ngroup\"]",
    }) |g| try expectRefused(a, try native(a, try a.print(native_defaults ++
        "\n    groups: {s}", .{g})), "");
    for ([_][]const u8{ "tcp/0", "tcp/65536", "tcp/any", "tcp/443 public", "udp/53", "tcp/" }) |p|
        try expectRefused(a, try native(a, try a.print(
            "    user: nobody\n    policy:\n      pledge: stdio\n      connect: ['{s}']\n" ++
                "    cases:\n      seed: [x]\n      verify: []",
            .{p},
        )), "");
    for ([_][]const u8{ "read: [relative]", "run: ['/a/../b']", "read: ['/a b']" }) |grant|
        try expectRefused(a, try native(a, try a.print(
            "    user: nobody\n    policy:\n      pledge: stdio\n      {s}\n" ++
                "    cases:\n      seed: [x]\n      verify: []",
            .{grant},
        )), "explicit absolute paths");
    try expectRefused(a, try native(a,
        \\    user: nobody
        \\    policy:
        \\      pledge: stdio rpath sendfd
        \\    cases:
        \\      seed: [x]
        \\      verify: []
    ), "unsupported test pledge");
    try expectRefused(a, try native(a, native_defaults ++ "\n    observe: []"), "unknown field");
    try expectRefused(a, "version: 1\nsuites:\n  - name: x\n    source: ../x.zig\n" ++
        "    mode: x\n" ++ native_defaults ++ "\n", "adjacent Zig source");
    try expectRefused(a, "version: 1\nsuites:\n  - name: x\n    source: x.zig\n" ++
        native_defaults ++ "\n", "mode/policy");
    try expectRefused(a, try native(a, native_defaults ++ "\n    user: root"), "a key given twice");
    _ = try expectPlan(
        a,
        try mem.replaceOwned(u8, a, try native(a, native_defaults), "nobody", "root"),
    );
    try expectRefused(a, try mem.concat(a, u8, &.{
        try native(a, native_defaults), "legacy: 'false'\n",
    }), "legacy must be boolean");
    try expectRefused(a, try mem.concat(a, u8, &.{
        try native(a, native_defaults), "packages: [bash]\n",
    }), "invalid test package");
    const pruned = try expectPlan(a, try mem.concat(a, u8, &.{
        try native(a, native_defaults), "prune: [usr/bin/sftp, usr/bin/scp, usr/bin/scp]\n",
    }));
    try testing.expectEqualDeep(
        @as([]const []const u8, &.{ "usr/bin/scp", "usr/bin/sftp" }),
        pruned.prune,
    );
    for ([_][]const u8{
        "usr/bin/scp",         "[/usr/bin/scp]",    "[usr/bin/]",      "[usr//bin/scp]",
        "[usr/../etc/shadow]", "['./usr/bin/scp']", "['usr/bin/a b']", "[[usr/bin/scp]]",
    }) |p| try expectRefused(a, try mem.concat(a, u8, &.{
        try native(a, native_defaults), "prune: ", p, "\n",
    }), "");
    try expectRefused(a, try mem.concat(a, u8, &.{
        try native(a, native_defaults),
        "  - name: test-client\n    cases:\n      - name: x\n        steps:\n" ++
            "          - file: /x\n            expect:\n              exists: true\n",
    }), "duplicate suite");
}

test "the clean boot orders readiness, shared checks and the form's suites" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const platform: Plan = .{ .packages = &.{"libcurl-openssl4"}, .drivers = &.{
        .{ .name = "test-platform", .source = "platform.zig", .mode = "platform", .seed = &.{
            "network", "http-answering", "data-usable",
        }, .verify = &.{"data-usable"} },
        .{ .name = "test-lifecycle", .source = "platform.zig", .mode = "platform", .seed = &.{
            "reaped",
        } },
    } };
    const form_plan: Plan = .{ .packages = &.{"postgresql-client"}, .drivers = &.{
        .{ .name = "test-app", .source = "probes.zig", .mode = "probes", .seed = &.{"a"} },
        .{
            .name = "test-ready",
            .source = "probes.zig",
            .mode = "probes",
            .readiness = true,
            .seed = &.{"r"},
        },
    } };
    var failure: Failure = .{};
    const plan = try boot(a, form_plan, platform, &.{}, &failure);
    var names: [4][]const u8 = undefined;
    for (plan.drivers, &names) |d, *n| n.* = d.name;
    try testing.expectEqualDeep(
        [4][]const u8{ "test-ready", "test-platform", "test-lifecycle", "test-app" },
        names,
    );
    try testing.expectEqualDeep(
        @as([]const []const u8, &.{ "libcurl-openssl4", "postgresql-client" }),
        plan.packages,
    );
    const skipped = try boot(a, form_plan, platform, &.{ "http-answering", "reaped" }, &failure);
    try testing.expectEqual(3, skipped.drivers.len);
    try testing.expectEqualDeep(
        @as([]const []const u8, &.{ "network", "data-usable" }),
        skipped.drivers[1].seed,
    );
    try testing.expectError(error.Plan, boot(a, form_plan, platform, &.{"misspelled"}, &failure));
    try testing.expect(mem.find(u8, failure.text, "unknown shared check") != null);
}

test "foundations alone may have no suites of their own" {
    const exceptions =
        \\# Form     Minimum  Why fewer form-specific cases are useful
        \\minimal    0        Boot foundation
        \\jre21      2        Runtime only
        \\
    ;
    try testing.expect(foundation(exceptions, "minimal"));
    try testing.expect(!foundation(exceptions, "jre21"));
    try testing.expect(!foundation(exceptions, "gatus"));
    try testing.expect(!foundation(exceptions, "#"));
}

test "every form's plan and the platform plan load" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var failure: Failure = .{};
    const root = Io.Dir.cwd();
    const platform = load(io, a, root, "test/native/platform.yaml", &failure) catch |err| {
        std.debug.print("{s}\n", .{failure.text});
        return err;
    };
    try testing.expectEqual(16, platform.drivers[0].seed.len);
    try testing.expectEqualDeep(
        @as([]const []const u8, &.{ "data-usable", "data-kept", "age-cache-protected" }),
        platform.drivers[0].verify,
    );
    var forms = try root.openDir(io, "forms", .{ .iterate = true });
    defer forms.close(io);
    var it = forms.iterate();
    var count: usize = 0;
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const dir = try a.print("forms/{s}", .{entry.name});
        root.access(io, try a.print("{s}/test/tests.yaml", .{dir}), .{}) catch continue;
        const plan = form(io, a, root, dir, &failure) catch |err| {
            std.debug.print("{s}\n", .{failure.text});
            return err;
        };
        count += 1;
        if (mem.eql(u8, entry.name, "minimal")) try testing.expectEqual(0, plan.drivers.len);
        if (mem.eql(u8, entry.name, "gatus")) try testing.expect(!plan.legacy);
        if (mem.eql(u8, entry.name, "greenbone")) {
            try testing.expectEqualDeep(
                @as([]const []const u8, &.{ "libcurl-openssl4", "postgresql-client" }),
                plan.packages,
            );
            for (plan.drivers) |d| if (mem.eql(u8, d.mode, "manager"))
                try testing.expectEqualStrings("_oci-gvmd", d.user);
        }
    }
    try testing.expect(count > 50);
}

test "a form's plan keeps retained shell checks and refuses shared names" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "forms/app/test");
    try tmp.dir.createDirPath(io, "test");
    try tmp.dir.writeFile(io, .{
        .sub_path = "test/form-coverage-exceptions",
        .data = "minimal 0 foundation\n",
    });
    const plan = try web(a,
        \\          - file: /etc/passwd
        \\            expect:
        \\              exists: true
    );
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/app/test/tests.yaml", .data = plan });
    var failure: Failure = .{};
    try testing.expect(!(try form(io, a, tmp.dir, "forms/app", &failure)).legacy);
    for ([_][]const u8{ "checks", "checks-again" }) |name| {
        const path = try a.print("forms/app/test/{s}", .{name});
        try tmp.dir.writeFile(io, .{ .sub_path = path, .data = "ok retained true\n" });
        try testing.expect((try form(io, a, tmp.dir, "forms/app", &failure)).legacy);
        try tmp.dir.deleteFile(io, path);
    }
    for (reserved) |name| {
        try tmp.dir.writeFile(io, .{
            .sub_path = "forms/app/test/tests.yaml",
            .data = try mem.replaceOwned(
                u8,
                a,
                plan,
                "name: web",
                try a.print("name: {s}", .{name}),
            ),
        });
        try testing.expectError(error.Plan, form(io, a, tmp.dir, "forms/app", &failure));
        try testing.expect(mem.find(u8, failure.text, "reserved") != null);
    }
    try tmp.dir.writeFile(io, .{
        .sub_path = "forms/app/test/tests.yaml",
        .data = "version: 1\nsuites: []\n",
    });
    try testing.expectError(error.Plan, form(io, a, tmp.dir, "forms/app", &failure));
    try testing.expect(mem.find(u8, failure.text, "own test suites") != null);
    try tmp.dir.createDirPath(io, "forms/minimal/test");
    try tmp.dir.writeFile(io, .{
        .sub_path = "forms/minimal/test/tests.yaml",
        .data = "version: 1\nsuites: []\n",
    });
    try testing.expectEqual(0, (try form(io, a, tmp.dir, "forms/minimal", &failure)).drivers.len);
    try tmp.dir.writeFile(io, .{
        .sub_path = "forms/app/test/tests.yaml",
        .data = try native(a, native_defaults),
    });
    try testing.expectError(error.Plan, form(io, a, tmp.dir, "forms/app", &failure));
    try testing.expect(mem.find(u8, failure.text, "adjacent Zig source") != null);
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/app/test/driver.zig", .data = "" });
    _ = try form(io, a, tmp.dir, "forms/app", &failure);
    // A form is itself: it names no form, and boots as forms do.
    for ([_][]const u8{ "form: minimal\n", "kernel_address: false\n" }) |key| {
        try tmp.dir.writeFile(io, .{
            .sub_path = "forms/app/test/tests.yaml",
            .data = try mem.concat(a, u8, &.{ key, plan }),
        });
        try testing.expectError(error.Plan, form(io, a, tmp.dir, "forms/app", &failure));
        try testing.expect(mem.find(u8, failure.text, "scenario's") != null);
    }
    // A scenario names the form it boots, and may ask nothing of its own.
    try tmp.dir.createDirPath(io, "test/scenarios/lease");
    try tmp.dir.writeFile(io, .{
        .sub_path = "test/scenarios/lease/tests.yaml",
        .data = "version: 1\nform: prod\nkernel_address: false\nsuites: []\n",
    });
    const s = try scenario(io, a, tmp.dir, "test/scenarios/lease", &failure);
    try testing.expectEqualStrings("prod", s.form.?);
    try tmp.dir.writeFile(io, .{
        .sub_path = "test/scenarios/lease/tests.yaml",
        .data = "version: 1\nsuites: []\n",
    });
    try testing.expectError(error.Plan, scenario(io, a, tmp.dir, "test/scenarios/lease", &failure));
}

test "writeJson sorts keys and keeps floats floats" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const value = try std.json.parseFromSliceLeaky(Json, a,
        \\{"b":[1,1.0,1.5,"x"],"a":{"d":null,"c":true}}
    , .{});
    try testing.expectEqualStrings(
        \\{"a":{"c":true,"d":null},"b":[1,1.0,1.5,"x"]}
    , try json(a, value));
}
