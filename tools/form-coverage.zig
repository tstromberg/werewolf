//! form-coverage checks that each service form declares at least five
//! distinct integration cases, and accounts for every case of the legacy
//! inventory (test/form-probe-baseline.yaml) by what implements it now.
//! Shared platform checks do not count; a supplied-code fixture or a host
//! SSH suite counts only for the forms the harness runs it on. It guards
//! coverage quantity; review still judges whether cases are useful.

const std = @import("std");
const plans = @import("test-plan");
const yaml = @import("form").yaml;
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;

const usage = "usage: form-coverage [--root DIR] [--list] [--form NAME] [--probes] [--mapping]";

const ssh_cases = [_][]const u8{
    "ssh-login",         "ssh-command-output",     "ssh-command-status",
    "ssh-no-forwarding", "ssh-security-keys-only",
};
const playground_cases = [_][]const u8{
    "ssh-login",         "ssh-command-output", "ssh-command-status",
    "ssh-no-forwarding", "ssh-keys-only",
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    var c: Coverage = .{ .io = init.io, .gpa = gpa, .root = Dir.cwd() };
    const code = run(&c, args[1..]) catch |err| blk: {
        std.debug.print(
            "form-coverage: {s}\n",
            .{if (err == error.Refused) c.why else @errorName(err)},
        );
        break :blk 1;
    };
    std.process.exit(code);
}

fn run(c: *Coverage, args: []const []const u8) !u8 {
    var list = false;
    var probes = false;
    var mapping = false;
    var only: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.eql(u8, arg, "--list")) {
            list = true;
        } else if (mem.eql(u8, arg, "--probes")) {
            probes = true;
        } else if (mem.eql(u8, arg, "--mapping")) {
            mapping = true;
        } else if ((mem.eql(u8, arg, "--form") or mem.eql(u8, arg, "--root")) and
            i + 1 < args.len)
        {
            i += 1;
            if (mem.eql(u8, arg, "--form"))
                only = args[i]
            else
                c.root = try Dir.cwd().openDir(c.io, args[i], .{});
        } else return c.fail("{s}", .{usage});
    }
    const rows = try audit(c);
    if (probes or mapping) _ = try probeCoverage(c, mapping);
    var selected: std.ArrayList(Row) = .empty;
    for (rows) |row| if (only == null or
        mem.eql(u8, row.name, only.?)) try selected.append(c.gpa, row);
    if (selected.items.len == 0) return c.fail("no form {s}", .{only.?});
    var failed = false;
    var exceptions: usize = 0;
    for (selected.items) |row| {
        if (list) try c.say("{s: <20} {d: >2} cases ({d} guest, {d} supplied-code, {d} host, " ++
            "{d} native){s}{s}", .{
            row.name,
            row.count,
            row.own,
            row.fixture,
            row.host,
            row.native,
            if (row.reason.len > 0) "; exception: " else "",
            row.reason,
        });
        if (row.reason.len > 0) exceptions += 1;
        if (row.count < row.minimum) {
            std.debug.print(
                "form-coverage: {s}: {d} cases, needs {d}\n",
                .{ row.name, row.count, row.minimum },
            );
            failed = true;
        }
    }
    if (failed) return 1;
    try c.say("form-coverage: {d} forms meet the five-case minimum; {d} foundation/runtime " ++
        "exceptions", .{
        selected.items.len - exceptions, exceptions,
    });
    return 0;
}

const Coverage = struct {
    io: Io,
    gpa: Allocator,
    root: Dir,
    why: []const u8 = "",

    fn fail(c: *Coverage, comptime fmt: []const u8, args: anytype) error{ Refused, OutOfMemory } {
        c.why = try c.gpa.print(fmt, args);
        return error.Refused;
    }

    fn say(c: *Coverage, comptime fmt: []const u8, args: anytype) !void {
        try Io.File.stdout().writeStreamingAll(c.io, try c.gpa.print(fmt ++ "\n", args));
    }

    /// read is path's text, or null if there is no such file.
    fn read(c: *Coverage, path: []const u8) !?[]const u8 {
        return c.root.readFileAlloc(
            c.io,
            path,
            c.gpa,
            .limited(16 << 20),
        ) catch |err| switch (err) {
            error.FileNotFound => null,
            else => c.fail("{s}: {s}", .{ path, @errorName(err) }),
        };
    }

    /// plan is the form's tests.yaml, or none.
    fn plan(c: *Coverage, form: []const u8) !?plans.Plan {
        const path = try c.gpa.print("forms/{s}/test/tests.yaml", .{form});
        c.root.access(c.io, path, .{}) catch return null;
        var failure: plans.Failure = .{};
        return plans.load(c.io, c.gpa, c.root, path, &failure) catch |err| switch (err) {
            error.Plan => c.fail("{s}", .{failure.text}),
            error.OutOfMemory => error.OutOfMemory,
        };
    }
};

/// records are a table's lines that are neither blank nor comments, each
/// split into at most three fields, with their line numbers.
const Record = struct { line: usize, fields: []const []const u8 };

fn records(gpa: Allocator, text: []const u8) ![]const Record {
    var out: std.ArrayList(Record) = .empty;
    var lines = mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (lines.next()) |line| {
        n += 1;
        const body = mem.trim(u8, line, " \t\r");
        if (body.len == 0 or body[0] == '#') continue;
        var fields: std.ArrayList([]const u8) = .empty;
        var rest = body;
        while (rest.len > 0 and fields.items.len < 2) {
            const end = mem.findAny(u8, rest, " \t") orelse rest.len;
            try fields.append(gpa, rest[0..end]);
            rest = mem.trimStart(u8, rest[end..], " \t");
        }
        if (rest.len > 0) try fields.append(gpa, rest);
        try out.append(gpa, .{ .line = n, .fields = fields.items });
    }
    return out.items;
}

/// cases are the check names of a console checks file: KIND NAME COMMAND.
fn cases(c: *Coverage, path: []const u8) ![]const []const u8 {
    const text = try c.read(path) orelse return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (try records(c.gpa, text)) |r| {
        if (r.fields.len != 3 or !has(&.{ "ok", "gap", "seen", "unseen" }, r.fields[0]))
            return c.fail("{s}:{d}: expected KIND NAME COMMAND", .{ path, r.line });
        if (has(
            out.items,
            r.fields[1],
        )) return c.fail("{s}:{d}: duplicate check {s}", .{ path, r.line, r.fields[1] });
        try out.append(c.gpa, r.fields[1]);
    }
    return out.items;
}

fn has(names: []const []const u8, name: []const u8) bool {
    for (names) |n| if (mem.eql(u8, n, name)) return true;
    return false;
}

const Row = struct {
    name: []const u8,
    count: usize,
    minimum: usize,
    own: usize,
    fixture: usize,
    host: usize,
    native: usize,
    reason: []const u8,
};

fn audit(c: *Coverage) ![]const Row {
    const gpa = c.gpa;
    var names: std.ArrayList([]const u8) = .empty;
    {
        var dir = try c.root.openDir(c.io, "forms", .{ .iterate = true });
        defer dir.close(c.io);
        var it = dir.iterate();
        while (try it.next(c.io)) |entry| {
            if (entry.kind != .directory) continue;
            c.root.access(
                c.io,
                try gpa.print("forms/{s}/form.yaml", .{entry.name}),
                .{},
            ) catch continue;
            try names.append(gpa, try gpa.dupe(u8, entry.name));
        }
    }
    if (names.items.len == 0) return c.fail("no forms found", .{});
    mem.sort([]const u8, names.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return mem.lessThan(u8, a, b);
        }
    }.less);
    const Exception = struct { name: []const u8, minimum: usize, reason: []const u8 };
    var exceptions: std.ArrayList(Exception) = .empty;
    for (try records(gpa, try c.read("test/form-coverage-exceptions") orelse "")) |r| {
        const known = for (exceptions.items) |e| {
            if (mem.eql(u8, e.name, r.fields[0])) break true;
        } else false;
        if (r.fields.len != 3 or !has(names.items, r.fields[0]) or known)
            return c.fail("form-coverage-exceptions:{d}: invalid exception", .{r.line});
        const minimum = std.fmt.parseInt(u8, r.fields[1], 10) catch 5;
        if (minimum >= 5 or r.fields[1][0] == '+' or r.fields[1][0] == '-')
            return c.fail(
                "form-coverage-exceptions:{d}: needs a minimum below five and a reason",
                .{r.line},
            );
        try exceptions.append(
            gpa,
            .{ .name = r.fields[0], .minimum = minimum, .reason = r.fields[2] },
        );
    }
    // A fixture's cases are its scenario's, app-NAME (docs/testing-scenarios.md).
    const Fixture = struct { name: []const u8, cases: usize };
    var fixtures: std.ArrayList(Fixture) = .empty;
    for (try records(gpa, try c.read("test/app-fixtures") orelse "")) |r| {
        const known = for (fixtures.items) |f| {
            if (mem.eql(u8, f.name, r.fields[0])) break true;
        } else false;
        // Carrier, the code laid on it, and the runtime whose check boots it.
        if (r.fields.len != 3 or !has(names.items, r.fields[0]) or
            !has(names.items, r.fields[2]) or known)
            return c.fail("app-fixtures:{d}: invalid fixture", .{r.line});
        const source = if (mem.eql(u8, r.fields[1], "java"))
            "test/app-fixture-java/Main.java"
        else
            r.fields[1];
        c.root.access(c.io, source, .{}) catch
            return c.fail("app-fixtures:{d}: missing fixture", .{r.line});
        const dir = try gpa.print("test/scenarios/app-{s}", .{r.fields[0]});
        var failure: plans.Failure = .{};
        const p = plans.scenario(c.io, gpa, c.root, dir, &failure) catch |err| switch (err) {
            error.Plan => return c.fail("app-fixtures:{d}: {s}", .{ r.line, failure.text }),
            error.OutOfMemory => return error.OutOfMemory,
        };
        var n: usize = 0;
        for (p.drivers) |d| n += distinct(d.seed, d.verify);
        try fixtures.append(gpa, .{ .name = r.fields[0], .cases = n });
    }
    const boot = try c.read("test/boot") orelse return c.fail("no test/boot", .{});
    var rows: std.ArrayList(Row) = .empty;
    for (names.items) |name| {
        const own = try cases(c, try gpa.print("forms/{s}/test/checks", .{name}));
        var native: usize = 0;
        // A plan's host suites are its own: test/boot's are a legacy form's.
        var host_cases: usize = 0;
        if (try c.plan(name)) |p| {
            for (p.drivers) |d| native += distinct(d.seed, d.verify);
            for (p.host) |s| host_cases += distinct(s.seed, s.verify);
        }
        const fixture = for (fixtures.items) |f| {
            if (mem.eql(u8, f.name, name)) break f.cases;
        } else 0;
        const host: []const []const u8 = if (host_cases > 0)
            &.{}
        else if (mem.eql(u8, name, "sshd") or mem.eql(u8, name, "prod-ssh"))
            &ssh_cases
        else if (mem.eql(u8, name, "playground"))
            &playground_cases
        else
            &.{};
        for (host) |check| if (!hostCheck(
            boot,
            check,
        )) return c.fail("test/boot: missing host check {s}", .{check});
        host_cases += host.len;
        const exception = for (exceptions.items) |e| {
            if (mem.eql(u8, e.name, name)) break e;
        } else Exception{ .name = name, .minimum = 5, .reason = "" };
        // Counts refer to deployments: an unshipped-code boot and a supplied-code
        // boot exercise different contracts even when a name is shared. A shell
        // assertion migrated to a native client must not count twice, so the
        // larger suite counts until the legacy one is retired.
        try rows.append(gpa, .{
            .name = name,
            .count = @max(own.len, native) + fixture + host_cases,
            .minimum = exception.minimum,
            .own = own.len,
            .fixture = fixture,
            .host = host_cases,
            .native = native,
            .reason = exception.reason,
        });
    }
    return rows.items;
}

/// hostCheck reports whether test/boot runs check: `say ok CHECK`,
/// `refused CHECK`, or CHECK first on an indented line.
/// distinct counts a suite's cases once: one repeated after the reboot is
/// still one behavioral case.
fn distinct(seed: []const []const u8, verify: []const []const u8) usize {
    var n = seed.len;
    for (verify) |case| if (!has(seed, case)) {
        n += 1;
    };
    return n;
}

fn hostCheck(boot: []const u8, check: []const u8) bool {
    var lines = mem.splitScalar(u8, boot, '\n');
    while (lines.next()) |line| {
        var at: usize = 0;
        while (mem.findPos(u8, line, at, check)) |i| : (at = i + 1) {
            const end = i + check.len;
            if (end < line.len and !std.ascii.isWhitespace(line[end])) continue;
            const before = line[0..i];
            if (mem.endsWith(u8, before, "say ok ") or
                mem.endsWith(u8, before, "refused ")) return true;
            if (before.len > 0 and mem.trim(u8, before, " \t").len == 0) return true;
        }
    }
    return false;
}

pub const Counts = struct { probes: usize = 0, native: usize = 0, legacy: usize = 0 };

/// probeCoverage accounts for every baseline case: implemented by YAML
/// probes, by native code, or still by a legacy check. A YAML case that
/// runs a form's own native client is native code too.
fn probeCoverage(c: *Coverage, listing: bool) !Counts {
    const gpa = c.gpa;
    const path = "test/form-probe-baseline.yaml";
    var diag: yaml.Diagnostic = .{};
    const baseline = yaml.parse(
        gpa,
        try c.read(path) orelse return c.fail("no {s}", .{path}),
        .plan,
        &diag,
    ) catch |err|
        return switch (err) {
            error.Syntax => c.fail("{s}:{d}: {s}", .{ path, diag.line, diag.why }),
            error.OutOfMemory => error.OutOfMemory,
        };
    const base = baseline.get("base") orelse return c.fail("{s}: no base", .{path});
    const forms = baseline.get("forms") orelse return c.fail("{s}: no forms", .{path});
    const replacements = baseline.get("replacements") orelse yaml.Node{ .map = &.{} };
    if (base != .scalar or base.scalar.text.len < 7 or forms != .map or replacements != .map)
        return c.fail("{s}: expected base, forms and replacements", .{path});
    var counts: Counts = .{};
    var missing: std.ArrayList([]const u8) = .empty;
    for (forms.map) |entry| {
        const form = entry.key;
        const expected = try scalars(c, entry.value, path, entry.line);
        const Kind = enum { probes, native, legacy };
        const Target = struct { name: []const u8, kind: Kind };
        var targets: std.ArrayList(Target) = .empty;
        var migrated: std.ArrayList(Target) = .empty;
        if (try c.plan(form)) |p| {
            var clients: std.ArrayList([]const u8) = .empty;
            for (p.drivers) |d| if (d.probes == null) try clients.append(
                gpa,
                try gpa.print("/usr/lib/werewolf/{s}", .{d.name}),
            );
            for (p.drivers) |d| {
                var custom: std.ArrayList([]const u8) = .empty;
                if (d.probes) |probes| for (probes.object.get("cases").?.array.items) |case| {
                    for (case.object.get("steps").?.array.items) |step| {
                        if (!mem.eql(u8, step.object.get("probe").?.string, "exec")) continue;
                        const client = step.object.get(
                            "request",
                        ).?.object.get("argv").?.array.items[0];
                        if (client == .string and has(clients.items, client.string)) {
                            try custom.append(gpa, case.object.get("name").?.string);
                            break;
                        }
                    }
                };
                for ([_][]const []const u8{ d.seed, d.verify }) |phase| for (phase) |case| {
                    const kind: Kind = if (d.probes != null and !has(custom.items, case))
                        .probes
                    else
                        .native;
                    try targets.append(
                        gpa,
                        .{ .name = try gpa.print("{s}/{s}", .{ d.name, case }), .kind = kind },
                    );
                    for (migrated.items) |*m| {
                        if (mem.eql(u8, m.name, case)) {
                            if (kind == .native) m.kind = .native;
                            break;
                        }
                    } else try migrated.append(gpa, .{ .name = case, .kind = kind });
                };
            }
        }
        const legacy = try mem.concat(gpa, []const u8, &.{
            try cases(c, try gpa.print("forms/{s}/test/checks", .{form})),
            try cases(c, try gpa.print("forms/{s}/test/checks-again", .{form})),
        });
        const replaced = replacements.get(form);
        for (expected) |case| {
            var kind: ?Kind = null;
            if (if (replaced) |r| r.get(case) else null) |node| {
                const names = try scalars(c, node, path, 0);
                if (names.len == 0) return c.fail(
                    "{s}/{s}: missing replacement assertion",
                    .{ form, case },
                );
                kind = .probes;
                for (names) |name| {
                    const target = for (targets.items) |t| {
                        if (mem.eql(u8, t.name, name)) break t;
                    } else return c.fail("{s}/{s}: missing replacement assertion", .{ form, case });
                    if (target.kind == .native) kind = .native;
                }
            } else {
                for (migrated.items) |m| if (mem.eql(u8, m.name, case)) {
                    kind = m.kind;
                };
                if (kind == null and has(legacy, case)) kind = .legacy;
            }
            if (kind) |k| switch (k) {
                .probes => counts.probes += 1,
                .native => counts.native += 1,
                .legacy => counts.legacy += 1,
            } else try missing.append(gpa, try gpa.print("{s}/{s}", .{ form, case }));
            if (listing) try c.say(
                "{s}/{s}: {s}",
                .{ form, case, if (kind) |k| @tagName(k) else "MISSING" },
            );
        }
    }
    if (missing.items.len > 0) return c.fail(
        "unmapped baseline cases: {s}",
        .{try mem.join(gpa, ", ", missing.items)},
    );
    const total = counts.probes + counts.native + counts.legacy;
    try c.say("form-coverage: baseline {s}: {d}/{d} ({d:.1}%) probe cases; {d} native, {d} " ++
        "legacy; target 80%", .{
        base.scalar.text[0..7],
        counts.probes,
        total,
        @as(f64, @floatFromInt(counts.probes * 100)) / @as(f64, @floatFromInt(@max(total, 1))),
        counts.native,
        counts.legacy,
    });
    return counts;
}

fn scalars(c: *Coverage, node: yaml.Node, path: []const u8, line: usize) ![]const []const u8 {
    if (node != .list) return c.fail("{s}:{d}: expected a list of cases", .{ path, line });
    const out = try c.gpa.alloc([]const u8, node.list.len);
    for (node.list, out) |item, *o| o.* = if (item == .scalar)
        item.scalar.text
    else
        return c.fail("{s}:{d}: expected a list of cases", .{ path, line });
    return out;
}

const testing = std.testing;

test "native clients a YAML case runs do not count as standard probes" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "forms/example/test");
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = "forms/example/test/driver.zig", .data = "// Native client fixture.\n" },
    );
    try tmp.dir.writeFile(io, .{ .sub_path = "forms/example/test/tests.yaml", .data =
        \\version: 1
        \\suites:
        \\  - name: helper
        \\    source: driver.zig
        \\    mode: wire
        \\    user: root
        \\    policy:
        \\      pledge: stdio
        \\    cases:
        \\      seed: [control]
        \\      verify: [control]
        \\  - name: cases
        \\    policy:
        \\      run: [/usr/lib/werewolf/test-helper, /usr/bin/psql]
        \\    cases:
        \\      - name: custom
        \\        steps:
        \\          - exec:
        \\              argv: [/usr/lib/werewolf/test-helper]
        \\            expect:
        \\              exit: 0
        \\      - name: client
        \\        steps:
        \\          - exec:
        \\              argv: [/usr/bin/psql]
        \\            expect:
        \\              exit: 0
        \\      - name: file
        \\        steps:
        \\          - file: /etc/passwd
        \\            expect:
        \\              type: file
        \\
    });
    try tmp.dir.createDirPath(io, "test");
    try tmp.dir.writeFile(io, .{ .sub_path = "test/form-probe-baseline.yaml", .data =
        \\base: fixture-base
        \\forms:
        \\  example: [custom, client, file]
        \\
    });
    var c: Coverage = .{ .io = io, .gpa = a, .root = tmp.dir };
    try testing.expectEqualDeep(
        Counts{ .probes = 2, .native = 1, .legacy = 0 },
        try probeCoverage(&c, false),
    );
    try tmp.dir.writeFile(io, .{ .sub_path = "test/form-probe-baseline.yaml", .data =
        \\base: fixture-base
        \\forms:
        \\  example: [custom, client, file, gone, kept]
        \\replacements:
        \\  example:
        \\    gone: [test-cases/file, test-helper/control]
        \\
    });
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = "forms/example/test/checks", .data = "ok kept true\n" },
    );
    try testing.expectEqualDeep(
        Counts{ .probes = 2, .native = 2, .legacy = 1 },
        try probeCoverage(&c, false),
    );
    try tmp.dir.writeFile(io, .{ .sub_path = "test/form-probe-baseline.yaml", .data =
        \\base: fixture-base
        \\forms:
        \\  example: [custom, unmapped]
        \\
    });
    try testing.expectError(error.Refused, probeCoverage(&c, false));
    try testing.expect(mem.find(u8, c.why, "unmapped baseline cases: example/unmapped") != null);
    try tmp.dir.writeFile(io, .{ .sub_path = "test/form-probe-baseline.yaml", .data =
        \\base: fixture-base
        \\forms:
        \\  example: [gone]
        \\replacements:
        \\  example:
        \\    gone: [test-cases/missing]
        \\
    });
    try testing.expectError(error.Refused, probeCoverage(&c, false));
    try testing.expect(mem.find(u8, c.why, "missing replacement assertion") != null);
}

test "checks, exceptions and fixtures are strict tables" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var c: Coverage = .{ .io = io, .gpa = a, .root = tmp.dir };
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = "checks", .data = "# comment\nok  one  true\nseen two  ready\n" },
    );
    try testing.expectEqualDeep(
        @as([]const []const u8, &.{ "one", "two" }),
        try cases(&c, "checks"),
    );
    for ([_][]const u8{ "ok one\n", "maybe one true\n", "ok one true\nok one again\n" }) |bad| {
        try tmp.dir.writeFile(io, .{ .sub_path = "checks", .data = bad });
        try testing.expectError(error.Refused, cases(&c, "checks"));
    }
    try testing.expectEqual(0, (try cases(&c, "absent")).len);
    try testing.expect(hostCheck("\tsay ok ssh-login\n", "ssh-login"));
    try testing.expect(hostCheck("refused ssh-no-forwarding root -N\n", "ssh-no-forwarding"));
    try testing.expect(hostCheck("\t\tssh-command-output {echo}\n", "ssh-command-output"));
    try testing.expect(!hostCheck("say ok ssh-login-extra\n", "ssh-login"));
    try testing.expect(!hostCheck("# ssh-login\n", "ssh-login"));
}

test "every form meets its minimum and the inventory is accounted for" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var c: Coverage = .{ .io = testing.io, .gpa = a, .root = Dir.cwd() };
    const rows = audit(&c) catch |err| {
        std.debug.print("{s}\n", .{c.why});
        return err;
    };
    for (rows) |row| if (row.count < row.minimum) {
        std.debug.print("{s}: {d} cases, needs {d}\n", .{ row.name, row.count, row.minimum });
        return error.TestUnexpectedResult;
    };
}
