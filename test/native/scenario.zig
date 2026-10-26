//! scenario checks what a scenario's plan says beyond a form's: a scenario
//! (test/scenarios/NAME/tests.yaml) boots a stock form some other way, as
//! the platform's own tests do. form names that form; skip drops the shared
//! checks its way of booting rules out; console adds what its console must
//! and must not show (test/console.zig); kernel_address: false boots it
//! with no address on the kernel command line, for init to find one itself;
//! and app boots it with code supplied as howl --app supplies it, the
//! fixture test/app-fixtures names, with none of the form's check.skip.
//! A form's own plan may say none of these. See docs/testing-scenarios.md.

const std = @import("std");
const yaml = @import("form").yaml;
const plan = @import("plan.zig");
const mem = std.mem;
const Json = std.json.Value;
const Check = plan.Check;
const Error = plan.Error;

pub const keys = [_][]const u8{ "form", "skip", "console", "kernel_address", "app", "boots" };

/// Console is one console line, as test/console.zig reads it: seen and
/// unseen take a POSIX extended regular expression, up a service or none.
pub const Console = struct {
    kind: Kind,
    name: []const u8,
    arg: []const u8 = "",
    /// only is the one boot it is judged in, or null for both.
    only: ?plan.Phase = null,

    pub const Kind = enum { seen, unseen, up };
};

/// Boot is how a scenario changes one boot: with data_key false, its config
/// holds no data.key, so init must refuse the disk the seed boot made.
pub const Boot = struct { data_key: bool = true };

/// Boots are a scenario's two boots, each as it changes it.
pub const Boots = struct { seed: Boot = .{}, verify: Boot = .{} };

/// read takes a scenario's own keys from top into out.
pub fn read(c: *Check, node: yaml.Node, top: std.json.ObjectMap, out: *plan.Plan) Error!void {
    if (top.get("form")) |form| {
        c.line = plan.keyLine(node, "form");
        out.form = if (form == .string and plan.ident(form.string))
            form.string
        else
            return c.fail("form names a form in forms/", .{});
    }
    if (top.get("skip")) |list| {
        c.line = plan.keyLine(node, "skip");
        const names = try c.strings(list);
        for (names, 0..) |name, i| if (!plan.ident(name) or plan.has(names[0..i], name))
            return c.fail("skip names shared checks, each once", .{});
        out.skip = names;
    }
    if (top.get("kernel_address")) |v| {
        c.line = plan.keyLine(node, "kernel_address");
        out.kernel_address = if (v == .bool)
            v.bool
        else
            return c.fail("kernel_address must be boolean", .{});
    }
    if (top.get("app")) |app| {
        c.line = plan.keyLine(node, "app");
        out.app = if (app == .string and plan.ident(app.string))
            app.string
        else
            return c.fail("app names a fixture in test/app-fixtures", .{});
    }
    if (top.get("boots")) |boots| {
        c.line = plan.keyLine(node, "boots");
        try c.fields(boots, &.{ "seed", "verify" }, &.{});
        inline for (.{ "seed", "verify" }) |name| if (boots.object.get(name)) |b| {
            try c.fields(b, &.{"data_key"}, &.{});
            if (b.object.get("data_key")) |k| @field(out.boots, name).data_key = if (k == .bool)
                k.bool
            else
                return c.fail("data_key must be boolean", .{});
        };
        if (!out.boots.seed.data_key)
            return c.fail("the seed boot makes the data disk, with data.key", .{});
    }
    if (top.get("console")) |list| {
        c.line = plan.keyLine(node, "console");
        if (list != .array or list.array.items.len == 0 or list.array.items.len > 64)
            return c.fail("expected 1..64 console lines", .{});
        var lines: std.ArrayList(Console) = .empty;
        for (list.array.items, node.get("console").?.list) |entry, entry_node| {
            c.line = plan.lineOf(entry_node, c.line);
            try lines.append(c.gpa, try console(c, entry));
        }
        out.console = lines.items;
    }
}

fn console(c: *Check, data: Json) Error!Console {
    try c.fields(data, &.{ "seen", "unseen", "up", "matches", "service", "phases" }, &.{});
    const s = data.object;
    const phases = (try plan.phasesOf(c, s.get("phases"))).array.items;
    const only: ?plan.Phase = if (phases.len == 1)
        std.meta.stringToEnum(plan.Phase, phases[0].string).?
    else
        null;
    var kind: ?Console.Kind = null;
    for ([_]Console.Kind{ .seen, .unseen, .up }) |k| if (s.contains(@tagName(k))) {
        if (kind != null) return c.fail("a console line is seen, unseen or up", .{});
        kind = k;
    };
    const k = kind orelse return c.fail("a console line is seen, unseen or up", .{});
    const name = try c.identity(s.get(@tagName(k)).?);
    if (k == .up) {
        if (s.contains("matches")) return c.fail("up takes a service, not matches", .{});
        const service = s.get("service") orelse return .{ .kind = k, .name = name, .only = only };
        if (service != .string or !plan.account(service.string))
            return c.fail("up names one service", .{});
        return .{ .kind = k, .name = name, .arg = service.string, .only = only };
    }
    if (s.contains("service")) return c.fail("{t} takes matches, not a service", .{k});
    const re = s.get("matches") orelse return c.fail("{t} needs matches", .{k});
    if (re != .string or re.string.len == 0 or re.string.len > 512 or
        mem.findAny(u8, re.string, "\x00\n") != null)
        return c.fail("matches is one line of 1..512 bytes", .{});
    return .{ .kind = k, .name = name, .arg = re.string, .only = only };
}

/// line is c as a CHECKS file line for test/console.zig.
pub fn line(gpa: std.mem.Allocator, l: Console) ![]const u8 {
    return gpa.print("{t} {s} {s}\n", .{ l.kind, l.name, l.arg });
}

const testing = std.testing;
const Phase = plan.Phase;

test "a scenario names its form, its skips, its console and how it boots" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try plan.expectPlan(a,
        \\version: 1
        \\form: minimal
        \\skip: [data-encrypted]
        \\kernel_address: false
        \\app: node-app
        \\boots:
        \\  verify:
        \\    data_key: false
        \\console:
        \\  - seen: from-tar
        \\    matches: 'werewolf: [^ ]+ 10[.]0[.]2[.]15/24'
        \\    phases: [verify]
        \\  - up: service-down
        \\  - up: postgres-down
        \\    service: postgres
        \\suites: []
    );
    try testing.expectEqualStrings("minimal", p.form.?);
    try testing.expectEqualStrings("data-encrypted", p.skip[0]);
    try testing.expect(!p.kernel_address);
    try testing.expectEqualStrings("node-app", p.app.?);
    try testing.expect(p.boots.seed.data_key and !p.boots.verify.data_key);
    try testing.expectEqual(3, p.console.len);
    try testing.expectEqual(Phase.verify, p.console[0].only.?);
    try testing.expectEqual(null, p.console[1].only);
    try testing.expectEqualStrings(
        "seen from-tar werewolf: [^ ]+ 10[.]0[.]2[.]15/24\n",
        try line(a, p.console[0]),
    );
    try testing.expectEqualStrings("up postgres-down postgres\n", try line(a, p.console[2]));
    const head = "version: 1\nsuites: []\n";
    for ([_][2][]const u8{
        .{ "form: Bad\n", "form names a form" },
        .{ "skip: [network, network]\n", "each once" },
        .{ "kernel_address: 'false'\n", "kernel_address must be boolean" },
        .{ "app: [node-app]\n", "app names a fixture" },
        .{ "boots:\n  seed:\n    data_key: false\n", "the seed boot makes the data disk" },
        .{ "boots:\n  verify:\n    data_key: 'no'\n", "data_key must be boolean" },
        .{ "boots:\n  later: {}\n", "unknown field later" },
        .{ "console:\n  - seen: x\n    matches: y\n    phases: [later]\n", "invalid phases" },
        .{ "console:\n  - seen: x\n", "seen needs matches" },
        .{ "console:\n  - up: x\n    matches: y\n", "up takes a service" },
        .{ "console:\n  - seen: x\n    unseen: y\n    matches: z\n", "seen, unseen or up" },
        .{ "console:\n  - unseen: x\n    matches: y\n    service: z\n", "takes matches" },
    }) |refused| try plan.expectRefused(
        a,
        try mem.concat(a, u8, &.{ head, refused[0] }),
        refused[1],
    );
}
