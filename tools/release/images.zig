//! images is release/images.yaml: which forms werewolf publishes, for which
//! architectures, providers and boot profiles, and who gates them.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const form = @import("form");
const Sys = @import("sys.zig").Sys;

pub const path = "release/images.yaml";

pub const Images = struct {
    forms: []const []const u8,
    profiles: []const []const u8,
    arches: []const Arch,
    gates: []const Gate,
    runners: []const Runner,
    shards: u32,
    checks: []const []const u8,
    focused: Target,
    variants: []const Variant = &.{},
    catalog_forms: []const []const u8 = &.{},

    pub fn entire(t: Images, s: *Sys) !Images {
        var out = t;
        if (t.catalog_forms.len == 0) return out;
        out.forms = t.catalog_forms;
        var gates: std.ArrayList(Gate) = .empty;
        for (t.gates) |gate| try gates.append(s.gpa, .{
            .provider = gate.provider,
            .forms = if (mem.eql(u8, gate.provider, "qemu")) out.forms else gate.forms,
        });
        out.gates = gates.items;
        return out;
    }

    pub fn selections(t: Images, s: *Sys) ![]const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        try out.appendSlice(s.gpa, &.{ "", "ssh" });
        for (t.variants) |variant| for (variant.combinations) |combination| {
            const base = try canonical(s, combination);
            const ssh = try canonical(s, try s.gpa.print("{s},ssh", .{combination}));
            for ([_][]const u8{
                base,
                ssh,
            }) |selection| if (!has(out.items, selection)) try out.append(s.gpa, selection);
        };
        return out.items;
    }

    pub fn selected(t: Images, s: *Sys) !Images {
        var out = t;
        var names_: std.ArrayList([]const u8) = .empty;
        var workload: std.ArrayList([]const u8) = .empty;
        for (try s.variantNames()) |name| if (!mem.eql(
            u8,
            name,
            "ssh",
        )) try workload.append(s.gpa, name);
        const wanted = try mem.join(s.gpa, ",", workload.items);
        for (t.forms) |name| {
            var allowed = wanted.len == 0;
            for (t.variants) |variant| if (mem.eql(u8, name, variant.form)) {
                for (variant.combinations) |combination| if (mem.eql(
                    u8,
                    try canonical(s, combination),
                    wanted,
                )) {
                    allowed = true;
                    break;
                };
            };
            if (allowed) try names_.append(s.gpa, name);
        }
        out.forms = names_.items;
        if (has(try s.variantNames(), "ssh")) {
            var gates: std.ArrayList(Gate) = .empty;
            for (t.gates) |gate| try gates.append(
                s.gpa,
                .{ .provider = gate.provider, .forms = out.forms },
            );
            out.gates = gates.items;
        }
        return out;
    }

    pub fn hasForm(t: Images, name: []const u8) bool {
        return has(t.forms, name);
    }

    pub fn arch(t: Images, name: []const u8) ?Arch {
        for (t.arches) |a| if (mem.eql(u8, a.name, name)) return a;
        return null;
    }

    /// providers are an architecture's, empty for one the table lacks.
    pub fn providers(t: Images, name: []const u8) []const []const u8 {
        return if (t.arch(name)) |a| a.providers else &.{};
    }

    /// identity says whether form, arch and profile name a published image.
    pub fn identity(t: Images, name: []const u8, arch_name: []const u8, profile: []const u8) bool {
        return t.hasForm(name) and t.arch(arch_name) != null and has(t.profiles, profile);
    }

    /// supportsGate says whether provider's lifecycle gates test form.
    pub fn supportsGate(t: Images, name: []const u8, provider: []const u8) bool {
        for (t.gates) |g| if (mem.eql(u8, g.provider, provider)) return has(g.forms, name);
        return false;
    }

    /// gated says whether any provider gates form: only those can publish.
    pub fn gated(t: Images, name: []const u8) bool {
        for (t.gates) |g| if (has(g.forms, name)) return true;
        return false;
    }

    /// target says whether form/provider/arch is the focused target.
    pub fn isFocused(
        t: Images,
        name: []const u8,
        provider: []const u8,
        arch_name: []const u8,
    ) bool {
        return mem.eql(u8, name, t.focused.form) and mem.eql(u8, provider, t.focused.provider) and
            mem.eql(u8, arch_name, t.focused.arch);
    }
};

pub const Variant = struct { form: []const u8, combinations: []const []const u8 };

fn canonical(s: *Sys, value: []const u8) ![]const u8 {
    var f: form.Failure = .{};
    const names_ = form.variantNames(s.gpa, &.{value}, &f) catch return s.refuse("{s}", .{f.text});
    return mem.join(s.gpa, ",", names_);
}

pub const Arch = struct {
    name: []const u8,
    runner: []const u8,
    providers: []const []const u8,
};

pub const Gate = struct { provider: []const u8, forms: []const []const u8 };

/// Runner is a gate target's runner: hosted labels, or the variable that
/// holds a self-hosted runner's as a JSON list.
pub const Runner = struct {
    provider: []const u8,
    arch: []const u8,
    labels: []const []const u8 = &.{},
    variable: ?[]const u8 = null,
};

pub const Target = struct { form: []const u8, provider: []const u8, arch: []const u8 };

pub fn has(set: []const []const u8, name: []const u8) bool {
    for (set) |item| if (mem.eql(u8, item, name)) return true;
    return false;
}

/// isName is a form name as a published path holds one: [a-z][a-z0-9-]{0,63}.
pub fn isName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64 or !std.ascii.isLower(name[0])) return false;
    for (name) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-') return false;
    return true;
}

pub fn load(s: *Sys) !Images {
    const text = try std.Io.Dir.cwd().readFileAlloc(s.io, path, s.gpa, .limited(64 << 10));
    return parse(s, text);
}

pub fn parse(s: *Sys, text: []const u8) !Images {
    var diag: form.Diagnostic = .{};
    const doc = form.parse(s.gpa, text, &diag) catch |err| switch (err) {
        error.Syntax => return s.refuse("{s}:{d}: {s}", .{ path, diag.line, diag.why }),
        else => |e| return e,
    };
    const known = [_][]const u8{
        "forms",
        "profiles",
        "arches",
        "gates",
        "runners",
        "shards",
        "checks",
        "focused",
        "variants",
        "catalog",
    };
    for (doc.map) |e| if (!has(
        &known,
        e.key,
    )) return s.refuse("{s}: unknown key {s}", .{ path, e.key });
    var t: Images = .{
        .forms = try catalogForms(s, doc.get("forms") orelse return missing(s, "forms")),
        .profiles = try names(s, doc, "profiles"),
        .arches = &.{},
        .gates = &.{},
        .runners = &.{},
        .shards = 0,
        .checks = try scalars(s, doc.get("checks") orelse return missing(s, "checks"), "checks"),
        .focused = undefined,
    };
    if (doc.get("catalog")) |catalog| t.catalog_forms = try catalogForms(s, catalog);
    if (doc.get("variants")) |variants| {
        if (variants != .map) return s.refuse(
            "variants must map forms to supported combinations",
            .{},
        );
        var combinations: std.ArrayList(Variant) = .empty;
        for (variants.map) |entry| {
            if (!t.hasForm(entry.key) and
                !has(
                    t.catalog_forms,
                    entry.key,
                )) return s.refuse("variants name unpublished form {s}", .{entry.key});
            const sets = try scalars(s, entry.value, "variants");
            for (sets) |set| _ = try canonical(s, set);
            try combinations.append(s.gpa, .{ .form = entry.key, .combinations = sets });
        }
        t.variants = combinations.items;
    }
    for ([_][]const u8{ "secure-boot", "legacy-boot" }) |p|
        if (!has(t.profiles, p)) return s.refuse("{s}: profiles must name {s}", .{ path, p });
    var arches: std.ArrayList(Arch) = .empty;
    const arch_map = doc.get("arches") orelse return missing(s, "arches");
    if (arch_map != .map) return s.refuse("{s}: arches is a map", .{path});
    for (arch_map.map) |e| {
        if (!mem.eql(u8, e.key, "x86_64") and !mem.eql(u8, e.key, "aarch64"))
            return s.refuse("{s}: unknown architecture {s}", .{ path, e.key });
        const runner = e.value.get("runner") orelse return missing(s, "arches runner");
        if (runner != .scalar) return s.refuse(
            "{s}: an architecture's runner is one label",
            .{path},
        );
        try arches.append(s.gpa, .{
            .name = e.key,
            .runner = runner.scalar.text,
            .providers = try names(s, e.value, "providers"),
        });
    }
    t.arches = arches.items;
    var gates: std.ArrayList(Gate) = .empty;
    const gate_map = doc.get("gates") orelse return missing(s, "gates");
    if (gate_map != .map) return s.refuse("{s}: gates is a map", .{path});
    for (gate_map.map) |e| {
        const gated_forms = if (e.value == .scalar and mem.eql(u8, e.value.scalar.text, "all"))
            t.forms
        else
            try scalars(s, e.value, "gates");
        for (gated_forms) |f| if (!t.hasForm(f)) return s.refuse(
            "{s}: gates name unpublished form {s}",
            .{ path, f },
        );
        try gates.append(s.gpa, .{ .provider = e.key, .forms = gated_forms });
    }
    t.gates = gates.items;
    var runners: std.ArrayList(Runner) = .empty;
    const runner_list = doc.get("runners") orelse return missing(s, "runners");
    if (runner_list != .list) return s.refuse("{s}: runners is a list", .{path});
    for (runner_list.list) |item| {
        const target = item.get("target") orelse return missing(s, "runners target");
        const pair = try split(s, target, 2);
        var r: Runner = .{ .provider = pair[0], .arch = pair[1] };
        if (!has(
            t.providers(r.arch),
            r.provider,
        )) return s.refuse("{s}: no {s} images for {s}", .{ path, r.provider, r.arch });
        if (item.get("labels")) |labels| r.labels = try scalars(s, labels, "labels");
        if (item.get("variable")) |v| r.variable = if (v == .scalar)
            v.scalar.text
        else
            return s.refuse("{s}: a variable is one name", .{path});
        if ((r.labels.len == 0) == (r.variable == null)) return s.refuse(
            "{s}: a runner has labels or a variable",
            .{path},
        );
        try runners.append(s.gpa, r);
    }
    t.runners = runners.items;
    const shards = doc.get("shards") orelse return missing(s, "shards");
    t.shards = if (shards == .scalar)
        std.fmt.parseUnsigned(u32, shards.scalar.text, 10) catch 0
    else
        0;
    if (t.shards < 1 or t.shards > 32) return s.refuse("{s}: shards is 1 to 32", .{path});
    const focused = try split(s, doc.get("focused") orelse return missing(s, "focused"), 3);
    t.focused = .{ .form = focused[0], .provider = focused[1], .arch = focused[2] };
    if (!t.hasForm(t.focused.form) or !has(t.providers(t.focused.arch), t.focused.provider))
        return s.refuse("{s}: focused is a published form/provider/arch", .{path});
    return t;
}

fn missing(s: *Sys, key: []const u8) error{Refused} {
    return s.refuse("{s}: {s} is missing", .{ path, key });
}

fn names(s: *Sys, node: form.Node, key: []const u8) ![]const []const u8 {
    const list = try scalars(s, node.get(key) orelse return missing(s, key), key);
    for (list) |n| if (!isName(n) and
        !mem.eql(u8, n, "x86_64")) return s.refuse("{s}: {s}: invalid name {s}", .{ path, key, n });
    return list;
}

fn scalars(s: *Sys, node: form.Node, key: []const u8) ![]const []const u8 {
    if (node != .list) return s.refuse("{s}: {s} is a list", .{ path, key });
    var out: std.ArrayList([]const u8) = .empty;
    for (node.list) |item| {
        if (item != .scalar) return s.refuse("{s}: {s} lists names", .{ path, key });
        if (has(
            out.items,
            item.scalar.text,
        )) return s.refuse("{s}: {s} repeats {s}", .{ path, key, item.scalar.text });
        try out.append(s.gpa, item.scalar.text);
    }
    return out.items;
}

fn split(s: *Sys, node: form.Node, comptime n: usize) ![n][]const u8 {
    if (node != .scalar) return s.refuse(
        "{s}: a target is PROVIDER/ARCH or FORM/PROVIDER/ARCH",
        .{path},
    );
    var out: [n][]const u8 = undefined;
    var it = mem.splitScalar(u8, node.scalar.text, '/');
    for (&out) |*part| part.* = it.next() orelse return s.refuse(
        "{s}: invalid target {s}",
        .{ path, node.scalar.text },
    );
    if (it.next() != null) return s.refuse("{s}: invalid target {s}", .{ path, node.scalar.text });
    return out;
}

const testing = std.testing;
const fixture = @import("fixture.zig");

test "each workload combination has one canonical SSH counterpart" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    var t = try load(&f.s);
    t.variants = &.{.{
        .form = "playground",
        .combinations = &.{ "vector", "tcp,vector", "vector" },
    }};
    const selections_ = try t.selections(&f.s);
    try testing.expectEqual(@as(usize, 6), selections_.len);
    for ([_][]const u8{
        "",
        "ssh",
        "vector",
        "ssh,vector",
        "tcp,vector",
        "ssh,tcp,vector",
    }) |expected|
        try testing.expect(has(selections_, expected));
    f.s.variants = "ssh,vector";
    const selected = try t.selected(&f.s);
    try testing.expectEqual(@as(usize, 1), selected.forms.len);
    try testing.expectEqualStrings("playground", selected.forms[0]);
    f.s.variants = "ssh";
    try testing.expectEqual(t.forms.len, (try t.selected(&f.s)).forms.len);
}

test "the published forms in both profiles are the only publication identities" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const t = try load(&f.s);
    try testing.expectEqual(@as(usize, 4), t.forms.len);
    for ([_][]const u8{
        "minimal",
        "prod-ssh",
        "playground",
        "postdoc-server",
    }) |name| try testing.expect(t.hasForm(name));
    for (t.forms) |name| for (t.profiles) |profile| try testing.expect(t.identity(
        name,
        "aarch64",
        profile,
    ));
    for ([_][]const u8{
        "prod",
        "caddy",
        "postgresql",
        "greenbone",
        "missing-form",
        "../minimal",
    }) |name|
        for (t.profiles) |profile| try testing.expect(!t.identity(name, "x86_64", profile));
    try testing.expect(!t.identity("minimal", "riscv64", "legacy-boot"));
    try testing.expect(!t.identity("minimal", "x86_64", "unknown"));
    for (t.forms) |name| try testing.expect(t.gated(name));
    try testing.expect(t.supportsGate("playground", "lima") and !t.supportsGate("minimal", "lima"));
    try testing.expect(t.isFocused("playground", "qemu", "x86_64"));
}

test "a table that is not exactly the release dialect refuses" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const good = try std.Io.Dir.cwd().readFileAlloc(s.io, path, s.gpa, .limited(64 << 10));
    _ = try parse(s, good);
    for ([_][2][]const u8{
        .{ "shards: 16", "shards: 99" },
        .{ "focused: playground/qemu/x86_64", "focused: playground/lima/x86_64" },
        .{ "  lima: [playground, postdoc-server]", "  lima: [unpublished]" },
        .{ "profiles: [secure-boot, legacy-boot]", "profiles: [secure-boot]" },
        .{ "forms: [minimal, prod-ssh, playground, postdoc-server]", "forms: [minimal, minimal]" },
        .{ "    variable: LIMA_RUNNER", "    labels: [mac]\n    variable: LIMA_RUNNER" },
        .{ "shards: 16", "shards: 16\nextra: 1" },
    }) |change| {
        const bad = try mem.replaceOwned(u8, s.gpa, good, change[0], change[1]);
        try testing.expect(!mem.eql(u8, bad, good));
        try testing.expectError(error.Refused, parse(s, bad));
    }
}

fn catalogForms(s: *Sys, node: form.Node) ![]const []const u8 {
    if (node != .scalar or !mem.eql(u8, node.scalar.text, "all")) return scalars(s, node, "forms");
    var dir = try std.Io.Dir.cwd().openDir(s.io, "forms", .{ .iterate = true });
    defer dir.close(s.io);
    var it = dir.iterate();
    var out: std.ArrayList([]const u8) = .empty;
    while (try it.next(s.io)) |entry| {
        if (entry.kind != .directory or !form.isName(entry.name)) continue;
        dir.access(s.io, try s.gpa.print("{s}/form.yaml", .{entry.name}), .{}) catch continue;
        try out.append(s.gpa, try s.gpa.dupe(u8, entry.name));
    }
    mem.sortUnstable([]const u8, out.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return mem.lessThan(u8, a, b);
        }
    }.less);
    return out.items;
}
