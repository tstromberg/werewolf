//! plan is how form-images chooses its work: the build and gate matrices
//! the workflow fans out, and each target's resolved inputs, whose
//! identity says whether a published target must be built again.

const std = @import("std");
const mem = std.mem;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const images = @import("images.zig");
const catalog = @import("catalog.zig");
const inputs = @import("inputs.zig");
const legacy = @import("legacy.zig");

/// Tree is where form-images finds its tools, trust and working state,
/// all relative to the checkout it runs in. Tests move it.
pub const Tree = struct {
    howl: []const u8 = "build/host/howl",
    form: []const u8 = "build/host/form",
    trust: []const u8 = "release/protected",
    catalog: []const u8 = "docs/forms-catalog.md",
    lock: []const u8 = "build/lock",
    lifecycle: []const u8 = "build/lifecycle",
    packages: []const u8 = "build/vendor/packages",
    protected_work: []const u8 = "build/protected-images",
    legacy_work: []const u8 = "build/legacy-images",
    /// The exact-bundle lifecycle check and the legacy image boots.
    lifecycle_check: []const u8 = "build/host/check-published-lifecycle",
    legacy_check: []const u8 = "build/host/check-legacy-image",
    /// The form's integration coverage check, run with --form FORM.
    coverage: []const []const u8 = &.{"build/host/form-coverage"},
    /// native requires builds and release tests to run on a Linux host of
    /// the target's architecture; only tests of the pipeline's logic lift it.
    native: bool = true,

    pub fn certificate(tree: Tree, s: *Sys) ![]const u8 {
        return sys.join(s, &.{ tree.trust, "image.crt" });
    }
};

/// query asks build/host/form about forms.
pub fn query(s: *Sys, tree: Tree, args: []const []const u8) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(s.gpa, try sys.resolve(s, tree.form));
    try argv.appendSlice(s.gpa, args);
    return sys.lines(s, try sys.output(s, argv.items));
}

pub fn variantDescriptions(s: *Sys, tree: Tree, name: []const u8) !Json {
    const lines = try query(s, tree, &.{ "variant-descriptions", name });
    const value = try json.parse(s.gpa, try mem.join(s.gpa, "\n", lines));
    try catalog.validateVariantDescriptions(s, value);
    return value;
}

/// native refuses unless this is a Linux host of arch: builds and release
/// tests are not cross-built.
pub fn native(s: *Sys, tree: Tree, arch: []const u8) !void {
    if (!tree.native) return;
    const builtin = @import("builtin");
    const here = @tagName(builtin.cpu.arch);
    if (builtin.os.tag != .linux or !mem.eql(u8, here, arch))
        return s.refuse("form image builds and release tests require a native Linux runner", .{});
}

/// focused says whether FORM_IMAGES_TARGET names the recovery target
/// rather than all forms (all and base select the same published set).
pub fn focused(s: *Sys, t: images.Images) !bool {
    const value = s.getenv("FORM_IMAGES_TARGET") orelse "all";
    const recovery = try s.gpa.print(
        "{s}/{s}/{s}",
        .{ t.focused.form, t.focused.provider, t.focused.arch },
    );
    if (mem.eql(u8, value, "all") or mem.eql(u8, value, "base")) return false;
    if (mem.eql(u8, value, recovery)) return true;
    return s.refuse("target must be all, base or {s}", .{recovery});
}

/// shard is forms[shard - 1 :: shards].
pub fn shard(s: *Sys, forms: []const []const u8, n: usize, shards: usize) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var i = n - 1;
    while (i < forms.len) : (i += shards) try out.append(s.gpa, forms[i]);
    return out.items;
}

/// matrix is the build jobs: one per shard of each architecture.
pub fn matrix(s: *Sys, t: images.Images, shards: i64, recovery: bool) !Json {
    if (shards < 1 or shards > 32) return s.refuse("use between 1 and 32 shards", .{});
    var include: std.ArrayList(Json) = .empty;
    if (recovery) {
        const arch = t.arch(t.focused.arch).?;
        try include.append(
            s.gpa,
            try json.from(
                s.gpa,
                .{ .arch = arch.name, .runner = arch.runner, .shard = 1, .shards = 1 },
            ),
        );
    } else {
        const n = @min(@as(usize, @intCast(shards)), t.forms.len);
        for (t.arches) |a| for (1..n + 1) |i| try include.append(s.gpa, try json.from(s.gpa, .{
            .arch = a.name,
            .runner = a.runner,
            .shard = i,
            .shards = n,
        }));
    }
    return json.from(s.gpa, .{ .include = include.items });
}

/// gates are the lifecycle gate jobs: per target with a runner, the forms
/// of each build shard that provider gates and the arch supports.
pub fn gates(s: *Sys, t: images.Images, tree: Tree, recovery: bool, shards: i64) !Json {
    var include: std.ArrayList(Json) = .empty;
    for (t.runners) |r| {
        if (recovery and (!mem.eql(u8, r.provider, t.focused.provider) or
            !mem.eql(u8, r.arch, t.focused.arch))) continue;
        var labels: []const Json = &.{};
        if (r.variable) |name| {
            const value = s.getenv(name) orelse "";
            if (value.len == 0) continue;
            const parsed = json.parse(
                s.gpa,
                value,
            ) catch return s.refuse("a gate runner is a JSON list of labels", .{});
            labels = json.items(parsed) catch return s.refuse(
                "a gate runner is a JSON list of labels",
                .{},
            );
            if (labels.len == 0) return s.refuse("a gate runner is a JSON list of labels", .{});
            for (labels) |l| if (l != .string or
                l.string.len == 0) return s.refuse("a gate runner is a JSON list of labels", .{});
        } else {
            var list: std.ArrayList(Json) = .empty;
            for (r.labels) |l| try list.append(s.gpa, .{ .string = l });
            labels = list.items;
        }
        const supported = try query(s, tree, &.{ "for-arch", r.arch });
        const count: usize = if (recovery) 1 else @min(@as(usize, @intCast(shards)), t.forms.len);
        for (1..count + 1) |n| {
            const focused_form = [_][]const u8{t.focused.form};
            const candidates: []const []const u8 = if (recovery)
                &focused_form
            else
                try shard(s, t.forms, n, count);
            var selected: std.ArrayList([]const u8) = .empty;
            for (candidates) |f| if (images.has(supported, f) and
                t.supportsGate(f, r.provider)) try selected.append(s.gpa, f);
            if (selected.items.len == 0) continue;
            try include.append(s.gpa, try json.from(s.gpa, .{
                .forms = selected.items,
                .provider = r.provider,
                .arch = r.arch,
                .runner = labels,
                .shard = n,
                .shards = count,
            }));
        }
    }
    return json.from(s.gpa, .{ .include = include.items });
}

/// sourceIdentity binds the tree a form is built from: common programs,
/// build tools, tests, trust, examples and publication policy, and the
/// forms of its chain, but not unrelated forms or prose.
pub fn sourceIdentity(s: *Sys, chain: []const []const u8) ![64]u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(
        s.gpa,
        &.{
            "git",
            "ls-tree",
            "-rz",
            "HEAD",
            "--",
            "Makefile",
            "files.zig",
            "boot",
            "cmd",
            "lib",
            "tools",
            "test",
            "release",
            ".github",
            "examples",
        },
    );
    for (chain) |name| try argv.append(s.gpa, try s.gpa.print("forms/{s}", .{name}));
    return inputs.sourceIdentity(try sys.output(s, argv.items));
}

/// recipeIdentity binds recipes' build contexts, whose bytes may lie
/// outside the Git tree: every file's digest and mode, every link's target.
pub fn recipeIdentity(s: *Sys, recipes: []const []const u8) ![64]u8 {
    var contexts: std.ArrayList([]const u8) = .empty;
    for (recipes) |r| {
        const dir = std.fs.path.dirname(r) orelse ".";
        if (!images.has(contexts.items, dir)) try contexts.append(s.gpa, dir);
    }
    mem.sort([]const u8, contexts.items, {}, json.less);
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    for (contexts.items) |dir| {
        if (!sys.isDir(s, dir)) return s.refuse("missing recipe context: {s}", .{dir});
        for (try sys.walk(s, dir)) |e| {
            if (mem.startsWith(u8, std.fs.path.basename(e.path), ".")) continue;
            var parts = mem.splitScalar(u8, e.path, '/');
            const cached = while (parts.next()) |p| {
                if (mem.eql(u8, p, "__pycache__")) break true;
            } else false;
            if (cached) continue;
            const path = try sys.join(s, &.{ dir, e.path });
            const record: Json = switch (e.kind) {
                .sym_link => blk: {
                    var buf: [std.fs.max_path_bytes]u8 = undefined;
                    const n = try std.Io.Dir.cwd().readLink(s.io, path, &buf);
                    break :blk try json.from(
                        s.gpa,
                        .{ .context = dir, .path = e.path, .link = try s.gpa.dupe(u8, buf[0..n]) },
                    );
                },
                .file => blk: {
                    const st = try std.Io.Dir.cwd().statFile(s.io, path, .{});
                    break :blk try json.from(s.gpa, .{
                        .context = dir,
                        .path = e.path,
                        .sha256 = try s.gpa.dupe(u8, &try sys.sha(s, path)),
                        .mode = st.permissions.toMode() & 0o7777,
                    });
                },
                else => continue,
            };
            h.update(try json.encode(s.gpa, record));
        }
    }
    return sys.hex(h.finalResult());
}

/// lockFiles are a snapshot's locks, its shared ones first, by name: a
/// target's own replaces a shared one of the same name.
pub fn lockFiles(s: *Sys, snapshot: []const u8) ![]inputs.Lock {
    var locks: std.ArrayList(inputs.Lock) = .empty;
    for ([_][]const u8{
        std.fs.path.dirname(snapshot).?,
        snapshot,
    }) |dir| for (try sys.list(s, dir)) |name| {
        if (!mem.endsWith(u8, name, ".lock.json")) continue;
        const lock = try sys.readJson(s, try sys.join(s, &.{ dir, name }), 64 << 20);
        for (locks.items) |*l| {
            if (mem.eql(u8, l.name, name)) {
                l.lock = lock;
                break;
            }
        } else try locks.append(s.gpa, .{ .name = name, .lock = lock });
    };
    return locks.items;
}

/// resolvedIdentity is a target's inputs: source, package bytes, OCI
/// images, tool versions and recipe contexts.
pub fn resolvedIdentity(
    s: *Sys,
    name: []const u8,
    arch: []const u8,
    snapshot: []const u8,
    chain: []const []const u8,
) ![64]u8 {
    const packages = try inputs.identity(
        s,
        &try sourceIdentity(s, chain),
        arch,
        try lockFiles(s, snapshot),
    );
    var oci: std.ArrayList(Json) = .empty;
    const own = try sys.list(s, snapshot);
    for (own) |file| {
        if (!mem.startsWith(u8, file, name) or !mem.endsWith(u8, file, ".lock.json")) continue;
        const lock = try sys.readJson(s, try sys.join(s, &.{ snapshot, file }), 64 << 20);
        try oci.append(s.gpa, try json.field(try json.field(lock, "werewolf"), "images"));
    }
    const tools = try sys.readJson(s, try sys.join(s, &.{ snapshot, "tools.json" }), 1 << 20);
    const mapping = try json.object(try sys.readJson(
        s,
        try sys.join(s, &.{ snapshot, "melange.json" }),
        1 << 20,
    ));
    const contexts = try recipeIdentity(s, mapping.keys());
    return sys.sha256(try json.encode(s.gpa, try json.from(s.gpa, .{
        .packages = &packages,
        .images = oci.items,
        .tools = tools,
        .recipes = &contexts,
    })));
}

/// lockRecipe resolves a Melange recipe's build environment to output.
pub fn lockRecipe(s: *Sys, recipe: []const u8, arch: []const u8, output: []const u8) !void {
    const config = try s.gpa.print("{s}.apko.json", .{output});
    try sys.writeJson(s, config, try json.from(s.gpa, .{
        .contents = try inputs.melangeContents(s, recipe),
        .archs = &[_][]const u8{arch},
    }));
    try inputs.resolve(
        s,
        std.fs.path.basename(config),
        output,
        arch,
        std.fs.path.dirname(output).?,
    );
    try std.Io.Dir.cwd().deleteFile(s.io, config);
}

/// toolVersions are what each build tool says its version is.
pub fn toolVersions(s: *Sys, name: ?[]const u8) !Json {
    var versions: json.Map = .empty;
    var commands: std.ArrayList([]const []const u8) = .empty;
    try commands.appendSlice(s.gpa, &.{
        &.{
            "zig",
            "version",
        },
        &.{ "apko", "version" },
        &.{ "melange", "version" },
        &.{
            "qemu-img",
            "--version",
        },
        &.{ "mkfs.erofs", "--version" },
        &.{ "osslsigncode", "--version" },
    });
    if (name) |n| for (compilers) |c| if (mem.eql(u8, c[0], n)) try commands.append(s.gpa, c[1]);
    for (commands.items) |argv| {
        const r = try sys.exec(s, argv, .{ .capture = .both });
        if (!r.ok()) return s.refuse("{s} failed to say its version", .{argv[0]});
        const said = try s.gpa.print("{s}{s}", .{ r.stdout, r.stderr });
        try versions.put(
            s.gpa,
            try mem.join(s.gpa, " ", argv),
            .{ .string = mem.trim(u8, said, " \t\n\r\x0b\x0c\x1c\x1d\x1e\x1f") },
        );
    }
    return .{ .object = versions };
}

/// compilers are the host compilers a tutorial form builds with.
const compilers = [_]struct { []const u8, []const []const u8 }{
    .{ "go-example", &.{ "go", "version" } },
    .{ "rust-example", &.{ "rustc", "--version" } },
    .{ "aspnet-example", &.{ "dotnet", "--version" } },
};

/// sharedInputs resolves what every form of an arch shares: the kernel
/// and boot locks, the stub's Melange builder, and the security tools.
fn sharedInputs(s: *Sys, arch: []const u8, output: []const u8) !void {
    {
        const work = try sys.scratch(s, null, "ww-form-shared-");
        defer sys.remove(s, work);
        const configs = try inputs.bootConfigs(s, work);
        for ([_][]const u8{ "kernel", "boot" }) |name|
            try inputs.resolve(
                s,
                try s.gpa.print("{s}.yaml", .{name}),
                try s.gpa.print("{s}/{s}.lock.json", .{ output, name }),
                "aarch64,x86_64",
                configs,
            );
    }
    try lockRecipe(
        s,
        "boot/tpm-stub.melange.yaml",
        arch,
        try sys.join(s, &.{ output, "stub-builder.lock.json" }),
    );
    try sys.writeJson(s, try sys.join(s, &.{ output, "tools.json" }), try toolVersions(s, null));
}

/// resolve writes a shard's plan: each form's locks and inputs, and
/// whether its secure and legacy targets must be built.
pub fn resolve(
    s: *Sys,
    t: images.Images,
    tree: Tree,
    arch: []const u8,
    n: i64,
    shards: i64,
    output_dir: []const u8,
    recovery: bool,
) !void {
    if (n < 1 or n > shards or shards > 32) return s.refuse("invalid form image shard", .{});
    if (recovery and (!mem.eql(u8, arch, t.focused.arch) or n != 1 or shards != 1))
        return s.refuse("focused publication requires the single {s} shard", .{t.focused.arch});
    if (t.arch(arch) == null) return s.refuse("unsupported architecture {s}", .{arch});
    const output = try sys.resolve(s, output_dir);
    if (sys.exists(s, output)) return s.refuse("{s} already exists", .{output});
    try sys.mkdirs(s, output);
    const focused_form = [_][]const u8{t.focused.form};
    const selected: []const []const u8 = if (recovery)
        &focused_form
    else
        try shard(s, t.forms, @intCast(n), @intCast(shards));
    try sharedInputs(s, arch, output);
    const commit = mem.trim(u8, try sys.output(s, &.{ "git", "rev-parse", "HEAD" }), " \t\r\n");
    const serial = sys.serial(s.now());
    const previous = catalog.readIndex(s, t, try tree.certificate(s)) catch |err| blk: {
        // Nothing is skipped on faith: without the signed index, rebuild.
        s.say(
            "form-images: published index unreadable; rebuilding every form: {s}",
            .{s.reason(err)},
        );
        break :blk catalog.Index{};
    };
    const force = mem.eql(u8, s.getenv("FORM_IMAGES_FORCE") orelse "", "1");
    var targets: std.ArrayList(Json) = .empty;
    const plan_path = try sys.join(s, &.{ output, "plan.json" });
    for (selected) |name| {
        var target = try json.from(
            s.gpa,
            .{
                .form = name,
                .variants = try s.variantNames(),
                .arch = arch,
                .status = "resolution failed",
            },
        );
        try targets.append(s.gpa, target);
        resolveOne(
            s,
            t,
            tree,
            &target,
            output,
            try s.gpa.dupe(u8, commit),
            &serial,
            previous,
            force,
        ) catch |err|
            s.say("form-images: {s}/{s} resolution failed: {s}", .{ name, arch, s.reason(err) });
        targets.items[targets.items.len - 1] = target;
        try sys.writeJson(s, plan_path, try planJson(s, arch, n, shards, targets.items));
    }
    try sys.writeJson(s, plan_path, try planJson(s, arch, n, shards, targets.items));
}

fn planJson(s: *Sys, arch: []const u8, n: i64, shards: i64, targets: []const Json) !Json {
    return json.from(
        s.gpa,
        .{
            .format = "werewolf-form-plan/1",
            .arch = arch,
            .shard = n,
            .shards = shards,
            .targets = targets,
        },
    );
}

fn resolveOne(
    s: *Sys,
    t: images.Images,
    tree: Tree,
    target: *Json,
    output: []const u8,
    commit: []const u8,
    serial: []const u8,
    previous: catalog.Index,
    force: bool,
) !void {
    const gpa = s.gpa;
    const name = try json.text(target.*, "form");
    const arch = try json.text(target.*, "arch");
    const o = &target.object;
    if (!images.has(try query(s, tree, &.{ "archs", name }), arch)) {
        try o.put(gpa, "status", .{ .string = "unsupported architecture" });
        return;
    }
    const snapshot = try sys.join(s, &.{ output, name });
    try sys.mkdir(s, snapshot);
    const chain = try query(s, tree, &.{ "names", name });
    const lock = try gpa.print("{s}/{s}.lock.json", .{ tree.lock, try s.variantKey(name) });
    std.Io.Dir.cwd().deleteFile(s.io, lock) catch {};
    try sys.run(s, &.{
        try sys.resolve(s, tree.howl), "_build", "--with", name, "--arch", arch, "lock",
    }, .{});
    try sys.copy(s, lock, try sys.join(s, &.{ snapshot, std.fs.path.basename(lock) }));
    var mapping: json.Map = .empty;
    for (try query(s, tree, &.{ "recipes", name })) |recipe| {
        const recipe_digest = sys.sha256(recipe);
        const file = try gpa.print("melange-{s}.lock.json", .{recipe_digest[0..16]});
        try lockRecipe(s, recipe, arch, try sys.join(s, &.{ snapshot, file }));
        try mapping.put(gpa, recipe, .{ .string = file });
    }
    try sys.writeJson(s, try sys.join(s, &.{ snapshot, "melange.json" }), .{ .object = mapping });
    try sys.writeJson(s, try sys.join(s, &.{ snapshot, "tools.json" }), try toolVersions(s, name));
    const digest = try gpa.dupe(u8, &try resolvedIdentity(s, name, arch, snapshot, chain));
    try o.put(gpa, "inputs", .{ .string = digest });
    try o.put(gpa, "commit", .{ .string = commit });
    try o.put(gpa, "serial", .{ .string = serial });
    const unchanged = legacy.settled(
        s,
        t,
        name,
        arch,
        digest,
        try tree.certificate(s),
    ) catch |err| blk: {
        s.say(
            "form-images: {s}/{s} legacy receipt unreadable; rebuilding: {s}",
            .{ name, arch, s.reason(err) },
        );
        break :blk false;
    };
    try o.put(
        gpa,
        "legacy_status",
        .{ .string = if (unchanged and !force) "unchanged" else "build" },
    );
    var settled = true;
    var index: i64 = 0;
    for (t.providers(arch)) |provider| {
        // Unchanged inputs in a settled state need no rebuild.
        const row = previous.row(name, provider, arch) orelse Json{ .null = {} };
        const was = json.get(row, "inputs") orelse Json{ .null = {} };
        const status = json.get(row, "status") orelse Json{ .null = {} };
        if (was != .string or !mem.eql(u8, was.string, digest) or status != .string or
            !catalog.isSettled(status.string)) settled = false;
        if (json.get(
            row,
            "latest",
        )) |latest| if (json.get(latest, "index")) |i| if (i == .integer) {
            index = @max(index, i.integer);
        };
    }
    // Each release takes the next index of its channel, never one used: the TPM
    // floor of every machine on it rises by these (docs/design/implemented/independent-updates.md).
    try o.put(gpa, "index", .{ .integer = index + 1 });
    try o.put(gpa, "status", .{ .string = if (settled and !force) "unchanged" else "build" });
    try sys.writeJson(s, try sys.join(s, &.{ snapshot, "input.json" }), try json.from(gpa, .{
        .chain = chain,
        .variants = try s.variantNames(),
        .form = name,
        .arch = arch,
        .inputs = digest,
        .commit = commit,
        .serial = serial,
        .index = index + 1,
    }));
}

/// Bundle is one bundle a target builds: each provider's, at the target's
/// serial and its channel's next index. A candidate's updates cannot be
/// tested before it is published (test/check-published-lifecycle.zig).
pub const Bundle = struct { provider: []const u8, serial: [16]u8, index: i64 };

pub fn bundles(s: *Sys, t: images.Images, target: Json) ![]Bundle {
    const arch = try json.text(target, "arch");
    const serial = try json.text(target, "serial");
    const start = sys.serialTime(serial) orelse return s.refuse("invalid serial {s}", .{serial});
    const index = try json.int(target, "index");
    var out: std.ArrayList(Bundle) = .empty;
    for (t.providers(arch)) |provider|
        try out.append(
            s.gpa,
            .{ .provider = provider, .serial = sys.serial(start), .index = index },
        );
    return out.items;
}

/// installLocks puts a snapshot's locks where howl's builds read them.
pub fn installLocks(s: *Sys, tree: Tree, snapshot: []const u8) !void {
    try sys.mkdirs(s, tree.lock);
    for ([_][]const u8{
        std.fs.path.dirname(snapshot).?,
        snapshot,
    }) |dir| for (try sys.list(s, dir)) |name| {
        if (mem.endsWith(u8, name, ".lock.json") and !mem.startsWith(u8, name, "melange-"))
            try sys.copy(
                s,
                try sys.join(s, &.{ dir, name }),
                try sys.join(s, &.{ tree.lock, name }),
            );
    };
}

const testing = std.testing;
const fixture = @import("fixture.zig");

fn testTarget(s: *Sys, name: []const u8, arch: []const u8, index: i64) !Json {
    return json.from(
        s.gpa,
        .{ .form = name, .arch = arch, .serial = "20261015T120000Z", .index = index },
    );
}

test "each provider builds one bundle, at the target's serial and index" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const t = try images.load(s);
    for ([_][]const u8{ "minimal", "prod-ssh", "playground", "postdoc-server" }) |name| {
        const got = try bundles(s, t, try testTarget(s, name, "aarch64", 7));
        try testing.expectEqual(@as(usize, 2), got.len);
        for ([_][]const u8{ "lima", "qemu" }, got) |provider, b| {
            try testing.expectEqualStrings(provider, b.provider);
            try testing.expectEqualStrings("20261015T120000Z", &b.serial);
            try testing.expectEqual(@as(i64, 7), b.index);
        }
    }
}

fn formQueries(f: *fixture.Fixture, argv: []const []const u8) anyerror!?sys.Result {
    if (!mem.endsWith(u8, argv[0], "form-tool")) return null;
    if (mem.eql(u8, argv[1], "for-arch")) {
        // f.state 1 drops prod-ssh from arm64, as a form some arch lacks.
        if (f.state == 1 and
            mem.eql(
                u8,
                argv[2],
                "aarch64",
            )) return .{
            .term = .{ .exited = 0 },
            .stdout = "minimal\nplayground\npostdoc-server\n",
        };
        return .{
            .term = .{ .exited = 0 },
            .stdout = "minimal\nprod-ssh\nplayground\npostdoc-server\n",
        };
    }
    return .{ .term = .{ .exited = 0 }, .stdout = "x86_64\n" };
}

test "gate runners are label lists, and x86 needs none" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const t = try images.load(s);
    const tree: Tree = .{ .form = f.path("form-tool") };
    f.answer = formQueries;
    const hosted = try gates(s, t, tree, false, 16);
    var seen: std.ArrayList([]const u8) = .empty;
    for (try json.items(json.get(hosted, "include").?)) |g| {
        try testing.expectEqualStrings("qemu", try json.text(g, "provider"));
        try testing.expectEqualStrings("x86_64", try json.text(g, "arch"));
        for (try json.items(json.get(g, "forms").?)) |name| try seen.append(s.gpa, name.string);
    }
    try testing.expectEqual(t.forms.len, seen.items.len);
    try f.env.put("ARM64_KVM_RUNNER", "[\"self-hosted\", \"linux\", \"arm64\"]");
    try f.env.put("LIMA_RUNNER", "[\"self-hosted\", \"macOS\"]");
    const all = try json.items(json.get(try gates(s, t, tree, false, 16), "include").?);
    try testing.expectEqual(@as(usize, 10), all.len);
    for (all) |g| if (mem.eql(u8, try json.text(g, "provider"), "lima")) {
        const lima = try json.items(json.get(g, "forms").?);
        try testing.expectEqual(@as(usize, 1), lima.len);
        try testing.expect(images.has(&.{ "playground", "postdoc-server" }, lima[0].string));
    };
    _ = f.env.swapRemove("ARM64_KVM_RUNNER");
    for ([_][]const u8{ "self-hosted", "[]", "[\"\"]", "{\"a\": 1}" }) |bad| {
        try f.env.put("LIMA_RUNNER", bad);
        try testing.expectError(error.Refused, gates(s, t, tree, false, 16));
    }
}

test "the focused lane uses only hosted x86 and refuses unknown targets" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const t = try images.load(s);
    const tree: Tree = .{ .form = f.path("form-tool") };
    f.answer = formQueries;
    try f.env.put("FORM_IMAGES_TARGET", "all");
    try testing.expect(!try focused(s, t));
    try f.env.put("FORM_IMAGES_TARGET", "playground/qemu/x86_64");
    try testing.expect(try focused(s, t));
    for ([_][]const u8{ "prod/qemu/x86_64", "playground/lima/x86_64", "", "../playground" }) |bad| {
        try f.env.put("FORM_IMAGES_TARGET", bad);
        try testing.expectError(error.Refused, focused(s, t));
        try testing.expectStringStartsWith(
            s.why.text,
            "target must be all, base or playground/qemu/x86_64",
        );
    }
    try testing.expectEqualStrings(
        "{\"include\": [{\"arch\": \"x86_64\", \"runner\": \"ubuntu-26.04\", \"shard\": 1, " ++
            "\"shards\": 1}]}",
        try json.dumps(s.gpa, try matrix(s, t, 8, true)),
    );
    try testing.expectEqual(
        @as(usize, 8),
        (try json.items(json.get(try matrix(s, t, 8, false), "include").?)).len,
    );
    try testing.expectError(error.Refused, matrix(s, t, 0, false));
    try testing.expectError(error.Refused, matrix(s, t, 33, false));
    // A broken or absent self-hosted runner must not affect this lane.
    try f.env.put("ARM64_KVM_RUNNER", "invalid");
    try f.env.put("LIMA_RUNNER", "invalid");
    try testing.expectEqualStrings(
        "{\"include\": [{\"forms\": [\"playground\"], \"provider\": \"qemu\", \"arch\": " ++
            "\"x86_64\", \"runner\": [\"ubuntu-26.04\"], \"shard\": 1, \"shards\": 1}]}",
        try json.dumps(s.gpa, try gates(s, t, tree, true, 16)),
    );
}

test "builds and gates select the same scope" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const t = try images.load(s);
    const tree: Tree = .{ .form = f.path("form-tool") };
    f.answer = formQueries;
    for ([_]struct {
        []const u8,
        usize,
    }{ .{ "all", 8 }, .{ "base", 8 }, .{ "playground/qemu/x86_64", 1 } }) |c| {
        try f.env.put("FORM_IMAGES_TARGET", c[0]);
        const recovery = try focused(s, t);
        const builds = try json.items(json.get(try matrix(s, t, t.shards, recovery), "include").?);
        try testing.expectEqual(c[1], builds.len);
        var gated: std.ArrayList([]const u8) = .empty;
        for (try json.items(json.get(try gates(s, t, tree, recovery, t.shards), "include").?)) |g| {
            for (builds) |b| {
                if (mem.eql(u8, try json.text(b, "arch"), try json.text(g, "arch"))) break;
            } else return error.TestGateWithoutBuild;
            for (try json.items(json.get(
                g,
                "forms",
            ).?)) |name| if (!images.has(
                gated.items,
                name.string,
            )) try gated.append(s.gpa, name.string);
        }
        try testing.expectEqual(if (c[1] == 1) @as(usize, 1) else t.forms.len, gated.items.len);
    }
}

test "gate groups cover supported forms without another shard's downloads" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const t = try images.load(s);
    const tree: Tree = .{ .form = f.path("form-tool") };
    f.answer = formQueries;
    f.state = 1;
    try f.env.put("ARM64_KVM_RUNNER", "[\"arm\"]");
    try f.env.put("LIMA_RUNNER", "[\"mac\"]");
    const groups = try json.items(json.get(try gates(s, t, tree, false, 2), "include").?);
    var targets: std.ArrayList([]const u8) = .empty;
    for (groups) |g| {
        const n: usize = @intCast(try json.int(g, "shard"));
        const shards: usize = @intCast(try json.int(g, "shards"));
        const allowed = try shard(s, t.forms, n, shards);
        for (try json.items(json.get(g, "forms").?)) |name| {
            try testing.expect(images.has(allowed, name.string));
            try targets.append(
                s.gpa,
                try s.gpa.print(
                    "{s}/{s}/{s}",
                    .{ name.string, try json.text(g, "provider"), try json.text(g, "arch") },
                ),
            );
        }
    }
    const want = [_][]const u8{
        "minimal/qemu/x86_64",        "prod-ssh/qemu/x86_64",        "playground/qemu/x86_64",
        "minimal/qemu/aarch64",       "playground/qemu/aarch64",     "playground/lima/aarch64",
        "postdoc-server/qemu/x86_64", "postdoc-server/qemu/aarch64", "postdoc-server/lima/aarch64",
    };
    try testing.expectEqual(want.len, targets.items.len);
    for (want) |w| try testing.expect(images.has(targets.items, w));
}

test "a recipe's context identity binds bytes, modes and removals" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const recipe = f.path("recipe/recipe.yaml");
    try sys.write(s, recipe, "package: original\n");
    const patch = f.path("recipe/port.patch");
    try sys.write(s, patch, "original patch\n");
    try sys.write(s, f.path("recipe/.hidden"), "ignored");
    try sys.write(s, f.path("recipe/__pycache__/x.pyc"), "ignored");
    const original = try recipeIdentity(s, &.{recipe});
    try sys.write(s, f.path("recipe/.hidden"), "still ignored");
    try testing.expectEqualStrings(&original, &try recipeIdentity(s, &.{recipe}));
    try sys.write(s, patch, "modified patch\n");
    const changed = try recipeIdentity(s, &.{recipe});
    try testing.expect(!mem.eql(u8, &original, &changed));
    try std.Io.Dir.cwd().setFilePermissions(s.io, patch, .fromMode(0o755), .{});
    const executable = try recipeIdentity(s, &.{recipe});
    try testing.expect(!mem.eql(u8, &changed, &executable));
    try std.Io.Dir.cwd().deleteFile(s.io, patch);
    try testing.expect(!mem.eql(u8, &executable, &try recipeIdentity(s, &.{recipe})));
    try std.Io.Dir.cwd().symLink(s.io, "recipe.yaml", f.path("recipe/link"), .{});
    try testing.expect(!mem.eql(u8, &executable, &try recipeIdentity(s, &.{recipe})));
    try testing.expectError(error.Refused, recipeIdentity(s, &.{f.path("missing/recipe.yaml")}));
    try testing.expectStringStartsWith(s.why.text, "missing recipe context");
}

const head_commit = fixture.rep('b', 40) ++ "\n";

fn resolution(f: *fixture.Fixture, argv: []const []const u8) anyerror!?sys.Result {
    const s = &f.s;
    if (mem.endsWith(u8, argv[0], "form-tool")) {
        const out = if (mem.eql(u8, argv[1], "archs"))
            "x86_64\n"
        else if (mem.eql(u8, argv[1], "names"))
            try f.gpa().print("{s}\n", .{argv[2]})
        else
            "";
        return .{ .term = .{ .exited = 0 }, .stdout = out };
    }
    if (mem.eql(
        u8,
        argv[0],
        "git",
    )) return .{
        .term = .{ .exited = 0 },
        .stdout = if (mem.eql(u8, argv[1], "rev-parse"))
            head_commit
        else
            "100644 blob x\tMakefile\x00",
    };
    if (mem.eql(u8, argv[1], "_build")) {
        // howl _build --with FORM --arch ARCH lock
        const lock = try f.gpa().print("{s}/{s}.lock.json", .{ f.text, argv[3] });
        try sys.write(
            s,
            lock,
            "{\"contents\":{\"packages\":[{\"name\":\"p\",\"architecture\":\"x86_64\",\"version" ++
                "\":\"1\",\"url\":\"u\"}],\"keyring\":[]},\"werewolf\":{\"images\":[]}}",
        );
        return sys.Result.passed;
    }
    if (mem.eql(u8, argv[0], "apko")) {
        for (argv, 0..) |a, i| if (mem.eql(
            u8,
            a,
            "--output",
        )) try sys.write(
            s,
            argv[i + 1],
            "{\"contents\":{\"packages\":[{\"name\":\"k\",\"architecture\":\"x86_64\",\"version" ++
                "\":\"1\",\"url\":\"u\"}],\"keyring\":[]}}",
        );
        return sys.Result.passed;
    }
    if (mem.eql(u8, argv[0], "melange")) return .{ .term = .{ .exited = 0 }, .stdout = "line\n" };
    if (argv.len == 2 and (mem.eql(u8, argv[1], "version") or mem.eql(u8, argv[1], "--version")))
        return .{ .term = .{ .exited = 0 }, .stdout = "1.0\n" };
    return null;
}

test "focused resolution locks only playground, at its channel's next index" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const t = try images.load(s);
    const k = try fixture.keys(&f, "image");
    try sys.mkdirs(s, f.path("trust"));
    try sys.copy(s, k.crt, f.path("trust/image.crt"));
    const tree: Tree = .{
        .form = f.path("form-tool"),
        .howl = "howl",
        .lock = f.path("lock"),
        .trust = f.path("trust"),
    };
    f.text = tree.lock;
    f.answer = resolution;
    // No published index, and then one whose playground release is index 4.
    var index_body: []const u8 = "";
    const Get = struct {
        var body: *[]const u8 = undefined;
        fn get(fx: *fixture.Fixture, url: []const u8, limit: usize) anyerror!?sys.Got {
            _ = fx;
            _ = limit;
            if (mem.endsWith(u8, url, "/index.json") and body.len > 0) return .{ .body = body.* };
            return .missing;
        }
    };
    Get.body = &index_body;
    f.get_answer = Get.get;
    try resolve(s, t, tree, "x86_64", 1, 1, f.path("snapshot"), true);
    const latest = try json.from(s.gpa, .{
        .serial = "20261015T120000Z",
        .commit = fixture.rep(
            'b',
            40,
        ),
        .descriptor = fixture.rep('d', 64),
        .size = 1,
        .index = 4,
        .object = "playground/qemu/x86_64/objects/" ++ fixture.rep('d', 64),
    });
    const row = try json.from(
        s.gpa,
        .{
            .form = "playground",
            .provider = "qemu",
            .arch = "x86_64",
            .status = "tests failed",
            .latest = latest,
        },
    );
    index_body = try catalog.envelope(
        s,
        try json.from(s.gpa, .{ .format = catalog.format, .forms = &[_]Json{row} }),
        k.key,
    );
    try resolve(s, t, tree, "x86_64", 1, 1, f.path("next"), true);
    var queries: std.ArrayList([]const u8) = .empty;
    for (f.calls.items) |argv| if (mem.endsWith(
        u8,
        argv[0],
        "form-tool",
    )) try queries.append(s.gpa, try mem.join(s.gpa, " ", argv[1..]));
    const want = [_][]const u8{ "archs playground", "names playground", "recipes playground" };
    try testing.expectEqual(want.len * 2, queries.items.len);
    for (queries.items, 0..) |q, i| try testing.expectEqualStrings(want[i % want.len], q);
    const first = try sys.readJson(s, f.path("snapshot/plan.json"), 1 << 20);
    const targets = try json.items(json.get(first, "targets").?);
    try testing.expectEqual(@as(usize, 1), targets.len);
    try testing.expectEqualStrings("playground", try json.text(targets[0], "form"));
    try testing.expectEqualStrings("build", try json.text(targets[0], "status"));
    try testing.expectEqual(@as(i64, 1), try json.int(targets[0], "index"));
    try testing.expectEqual(
        @as(i64, 1),
        try json.int(try sys.readJson(s, f.path("snapshot/playground/input.json"), 4096), "index"),
    );
    const next = try json.items(json.get(
        try sys.readJson(s, f.path("next/plan.json"), 1 << 20),
        "targets",
    ).?);
    try testing.expectEqual(@as(i64, 5), try json.int(next[0], "index"));
    // One release lock for each plan.
    try testing.expectEqual(@as(usize, 2), f.called(&.{ "", "_build" }));
    for ([_]struct { []const u8, i64, i64 }{ .{ "aarch64", 1, 1 }, .{ "x86_64", 1, 8 } }) |c| {
        try testing.expectError(
            error.Refused,
            resolve(s, t, tree, c[0], c[1], c[2], f.path("invalid"), true),
        );
        try testing.expectStringStartsWith(
            s.why.text,
            "focused publication requires the single x86_64 shard",
        );
    }
}
