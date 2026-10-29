//! release builds, tests, signs and publishes werewolf's images
//! (docs/releases.md). Each verb is one of the release scripts it
//! replaced, with the same arguments; tools/release/README.md lists them.

const std = @import("std");
const mem = std.mem;
const json = @import("json.zig");
const sys = @import("sys.zig");
const Sys = sys.Sys;
const images = @import("images.zig");
const keys = @import("keys.zig");
const health = @import("health.zig");
const inputs = @import("inputs.zig");
const plan = @import("plan.zig");
const candidates = @import("candidates.zig");
const publication = @import("publication.zig");
const legacy = @import("legacy.zig");
const github = @import("github.zig");
const exporter = @import("exporter.zig");
const prepare = @import("prepare.zig");
const publish = @import("publish.zig");
const admission = @import("admission.zig");
const protected = @import("protected.zig");
const Store = @import("store.zig").Store;

const usage =
    \\usage: release VERB ARG...
    \\  form-images matrix|gates [--shards N]
    \\  form-images resolve ARCH SHARD SHARDS OUTPUT
    \\  form-images build SNAPSHOT OUTPUT
    \\  form-images check SNAPSHOT FIRST SECOND OUTPUT LIFECYCLE
    \\  form-images gate LIFECYCLE OUTPUT --provider qemu|lima --arch ARCH --forms FORM,...
    \\      --updates DIR
    \\  form-images export SNAPSHOTS VERIFIED GATED ASSETS LISTING [--legacy-verified DIR]
    \\  form-images publish SNAPSHOTS VERIFIED LISTING
    \\  legacy-images build SNAPSHOT OUTPUT
    \\  legacy-images check SNAPSHOT FIRST SECOND OUTPUT
    \\  protected-inputs HOWL ARCH OUTPUT
    \\  build-protected FORM PROVIDER ARCH SERIAL INDEX OUTPUT
    \\  authorize-protected HOWL PROVIDER BUNDLE...
    \\  prepare-protected HOWL BUNDLE GATES_JSON PROVIDER OUTPUT
    \\  export-protected HOWL BUNDLE GATES_JSON PROVIDER OUTPUT
    \\  publish-protected HOWL BUNDLE GATES_JSON PROVIDER RELEASE_ASSETS
    \\  check-protected-download HOWL BUNDLE PROVIDER RELEASE_ASSETS
    \\  github-protected EXPORTED_JSON
    \\  create-protected-trust PRIVATE_DIRECTORY PUBLIC_DIRECTORY
    \\  with-boot-key COMMAND [ARG...]
    \\  with-protected-keys COMMAND [ARG...]
    \\  report-publishing-health
    \\
;

/// Verb is a release script: its name, what it says when it fails, and
/// whether it works on signing inputs, which it keeps private (umask 077).
const Verb = struct {
    name: []const u8,
    failure: ?[]const u8 = null,
    private: bool = false,
};

const verbs = [_]Verb{
    .{ .name = "form-images" },
    .{ .name = "legacy-images" },
    .{ .name = "protected-inputs" },
    .{
        .name = "build-protected",
        .failure = "protected build failed; no unsigned output is published",
        .private = true,
    },
    .{ .name = "authorize-protected", .failure = "candidate admission failed", .private = true },
    .{
        .name = "prepare-protected",
        .failure = "admission, dedicated trust or artifact-bound lifecycle gates failed",
        .private = true,
    },
    .{ .name = "export-protected", .private = true },
    .{
        .name = "publish-protected",
        .failure = "admission, lifecycle gates, release floor or ordered upload failed",
        .private = true,
    },
    .{ .name = "check-protected-download" },
    .{ .name = "github-protected" },
    .{
        .name = "create-protected-trust",
        .failure = "invalid or partial identity; no automatic trust replacement",
        .private = true,
    },
    // Never echo the supplied secret, or a child's arguments.
    .{
        .name = "with-boot-key",
        .failure = "missing/invalid signing input or key/certificate mismatch",
    },
    .{
        .name = "with-protected-keys",
        .failure = "missing/invalid dedicated keys or public identity mismatch",
    },
    .{ .name = "report-publishing-health" },
};

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.arena.allocator();
    var s: Sys = .{ .io = init.io, .gpa = gpa, .env = init.environ_map };
    const args = try init.minimal.args.toSlice(gpa);
    const verb = for (verbs) |v| {
        if (args.len >= 2 and mem.eql(u8, args[1], v.name)) break v;
    } else {
        try std.Io.File.stderr().writeStreamingAll(init.io, usage);
        return 2;
    };
    if (verb.private) _ = std.c.umask(0o077);
    return run(&s, verb.name, args[2..]) catch |err| {
        const why = s.reason(err);
        if (verb.failure) |f| {
            if (mem.startsWith(u8, verb.name, "with-")) {
                s.say("{s}: {s}", .{ verb.name, f });
            } else s.say("{s}: {s}: {s}", .{ verb.name, f, why });
        } else s.say("{s}: {s}", .{ verb.name, why });
        return 1;
    };
}

fn run(s: *Sys, verb: []const u8, args: []const [:0]const u8) !u8 {
    if (mem.eql(u8, verb, "with-boot-key")) {
        if (args.len < 1) return s.refuse("usage: with-boot-key COMMAND [ARG...]", .{});
        return keys.withBootKey(s, try strings(s, args));
    }
    if (mem.eql(u8, verb, "with-protected-keys")) {
        if (args.len < 1) return s.refuse("usage: with-protected-keys COMMAND [ARG...]", .{});
        return keys.withProtectedKeys(s, try strings(s, args));
    }
    const a = try Args.parse(s, args);
    s.variants = a.option("variant") orelse s.getenv("FORM_IMAGES_VARIANTS") orelse "";
    _ = try s.variantNames();
    if (mem.eql(u8, verb, "report-publishing-health")) {
        const event = try sys.readJson(
            s,
            s.getenv("GITHUB_EVENT_PATH") orelse return s.refuse(
                "GITHUB_EVENT_PATH is required",
                .{},
            ),
            16 << 20,
        );
        try health.report(s, try json.field(event, "workflow_run"));
        return 0;
    }
    if (mem.eql(u8, verb, "create-protected-trust")) {
        try a.want(s, 2, "create-protected-trust PRIVATE_DIRECTORY PUBLIC_DIRECTORY");
        try keys.createTrust(s, a.at(0), a.at(1));
        return 0;
    }
    const t = try images.load(s);
    const tree: plan.Tree = .{};
    if (mem.eql(u8, verb, "form-images")) return formImages(s, t, tree, a);
    if (mem.eql(u8, verb, "legacy-images")) {
        const selected = try (try imageScope(s, t)).selected(s);
        if (a.positional.len < 1) return s.refuse("usage: legacy-images build|check ...", .{});
        if (mem.eql(u8, a.at(0), "build")) {
            try a.want(s, 3, "legacy-images build SNAPSHOT OUTPUT");
            return @intFromBool(try legacy.build(s, selected, tree, a.at(1), a.at(2)));
        }
        try a.want(s, 5, "legacy-images check SNAPSHOT FIRST SECOND OUTPUT");
        if (!mem.eql(
            u8,
            a.at(0),
            "check",
        )) return s.refuse("usage: legacy-images build|check ...", .{});
        return @intFromBool(try legacy.check(
            s,
            selected,
            tree,
            a.at(1),
            a.at(2),
            a.at(3),
            a.at(4),
        ));
    }
    if (mem.eql(u8, verb, "protected-inputs")) {
        try a.want(s, 3, "protected-inputs HOWL ARCH OUTPUT");
        _ = try inputs.prepare(s, t, a.at(0), a.at(1), a.at(2));
        return 0;
    }
    if (mem.eql(u8, verb, "build-protected")) {
        try a.want(s, 6, "build-protected FORM PROVIDER ARCH SERIAL INDEX OUTPUT");
        const index = std.fmt.parseInt(
            i64,
            a.at(4),
            10,
        ) catch return s.refuse("a release index is a number", .{});
        try protected.build(s, tree, a.at(0), a.at(1), a.at(2), a.at(3), index, a.at(5));
        return 0;
    }
    if (mem.eql(u8, verb, "authorize-protected")) {
        if (a.positional.len < 3) return s.refuse(
            "usage: authorize-protected HOWL PROVIDER BUNDLE...",
            .{},
        );
        const howl = try sys.resolve(s, a.at(0));
        for (a.positional[2..]) |bundle| try admission.authorize(s, tree, howl, a.at(1), bundle);
        return 0;
    }
    if (mem.eql(u8, verb, "prepare-protected") or mem.eql(u8, verb, "export-protected") or
        mem.eql(u8, verb, "publish-protected"))
    {
        try a.want(s, 5, "HOWL BUNDLE GATES_JSON PROVIDER OUTPUT");
        const howl = try sys.resolve(s, a.at(0));
        const report = try sys.readJson(s, a.at(2), 64 << 10);
        if (mem.eql(u8, verb, "prepare-protected")) {
            _ = try prepare.prepare(s, howl, a.at(1), report, a.at(3), a.at(4), tree.trust, null);
        } else if (mem.eql(u8, verb, "export-protected")) {
            _ = try exporter.exportBundle(
                s,
                howl,
                a.at(1),
                report,
                a.at(3),
                a.at(4),
                tree.trust,
                null,
            );
        } else {
            const store = Store.init(s.getenv("PROTECTED_BUCKET") orelse "s3://werewolf/boot/v1");
            _ = try publish.publish(
                s,
                howl,
                try sys.resolve(s, a.at(1)),
                report,
                a.at(3),
                store,
                tree.trust,
                try sys.resolve(s, a.at(4)),
            );
        }
        return 0;
    }
    if (mem.eql(u8, verb, "check-protected-download")) {
        try a.want(s, 4, "check-protected-download HOWL BUNDLE PROVIDER RELEASE_ASSETS");
        try admission.checkMirror(s, tree, try sys.resolve(s, a.at(0)), a.at(1), a.at(2), a.at(3));
        try std.Io.File.stdout().writeStreamingAll(
            s.io,
            "pass: fresh public download matches the published signed bundle and complete " ++
                "native admission\n",
        );
        return 0;
    }
    if (mem.eql(u8, verb, "github-protected")) {
        try a.want(s, 1, "github-protected EXPORTED_JSON");
        _ = try github.fromListing(s, try imageScope(s, t), a.at(0));
        return 0;
    }
    unreachable;
}

fn imageScope(s: *Sys, configured: images.Images) !images.Images {
    return if (mem.eql(u8, s.getenv("FORM_IMAGES_TARGET") orelse "base", "all"))
        try configured.entire(s)
    else
        configured;
}

fn formImages(s: *Sys, configured: images.Images, tree: plan.Tree, a: Args) !u8 {
    if (a.positional.len < 1) return s.refuse(
        "usage: form-images matrix|gates|resolve|build|check|gate|export|publish ...",
        .{},
    );
    const command = a.at(0);
    s.variants = a.option("variant") orelse s.getenv("FORM_IMAGES_VARIANTS") orelse "";
    _ = try s.variantNames();
    const all = try imageScope(s, configured);
    const t = try all.selected(s);
    const recovery = try plan.focused(s, t);
    const store = Store.init(s.getenv("PROTECTED_BUCKET") orelse "s3://werewolf/boot/v1");
    if (mem.eql(u8, command, "selections")) {
        try std.Io.File.stdout().writeStreamingAll(
            s.io,
            try json.dumps(s.gpa, try json.from(s.gpa, try all.selections(s))),
        );
        return 0;
    }
    if (mem.eql(u8, command, "matrix") or mem.eql(u8, command, "gates")) {
        try a.want(s, 1, "form-images matrix|gates [--shards N]");
        const shards = if (a.option("shards")) |n|
            std.fmt.parseInt(i64, n, 10) catch return s.refuse("--shards takes a number", .{})
        else
            t.shards;
        var include: std.ArrayList(json.Json) = .empty;
        const saved = s.variants;
        defer s.variants = saved;
        for (try all.selections(s)) |selection| {
            s.variants = selection;
            const selected = try all.selected(s);
            if (selected.forms.len == 0 or (recovery and
                !selected.hasForm(selected.focused.form))) continue;
            const matrix = if (mem.eql(u8, command, "matrix"))
                try plan.matrix(s, selected, shards, recovery)
            else if (shards < 1 or shards > 32)
                return s.refuse("invalid lifecycle gate shards", .{})
            else
                try plan.gates(s, selected, tree, recovery, shards);
            for (try json.items(try json.field(matrix, "include"))) |entry| {
                var item = entry;
                try item.object.put(s.gpa, "variants", .{ .string = selection });
                try include.append(s.gpa, item);
            }
        }
        const value = try json.from(s.gpa, .{ .include = include.items });
        try std.Io.File.stdout().writeStreamingAll(
            s.io,
            try s.gpa.print("{s}\n", .{try json.dumps(s.gpa, value)}),
        );
        return 0;
    }
    if (mem.eql(u8, command, "resolve")) {
        try a.want(s, 5, "form-images resolve ARCH SHARD SHARDS OUTPUT");
        const n = std.fmt.parseInt(
            i64,
            a.at(2),
            10,
        ) catch return s.refuse("invalid form image shard", .{});
        const shards = std.fmt.parseInt(
            i64,
            a.at(3),
            10,
        ) catch return s.refuse("invalid form image shard", .{});
        try plan.resolve(s, t, tree, a.at(1), n, shards, a.at(4), recovery);
        return 0;
    }
    if (mem.eql(u8, command, "build")) {
        try a.want(s, 3, "form-images build SNAPSHOT OUTPUT");
        return @intFromBool(try candidates.build(s, t, tree, a.at(1), a.at(2)));
    }
    if (mem.eql(u8, command, "check")) {
        try a.want(s, 6, "form-images check SNAPSHOT FIRST SECOND OUTPUT LIFECYCLE");
        return @intFromBool(try candidates.check(
            s,
            t,
            tree,
            a.at(1),
            a.at(2),
            a.at(3),
            a.at(4),
            a.at(5),
        ));
    }
    if (mem.eql(u8, command, "gate")) {
        try a.want(
            s,
            3,
            "form-images gate LIFECYCLE OUTPUT --provider qemu|lima --arch ARCH --forms " ++
                "FORM,... " ++
                "--updates DIR",
        );
        const provider = a.option("provider") orelse return s.refuse("--provider is required", .{});
        const updates = a.option("updates") orelse return s.refuse("--updates is required", .{});
        const arch = a.option("arch") orelse return s.refuse("--arch is required", .{});
        const forms = a.option("forms") orelse return s.refuse("--forms is required", .{});
        if (!mem.eql(u8, provider, "qemu") and
            !mem.eql(u8, provider, "lima")) return s.refuse("--provider is qemu or lima", .{});
        if (t.arch(arch) == null) return s.refuse("--arch is one of the image architectures", .{});
        var selected: std.ArrayList([]const u8) = .empty;
        var it = mem.splitScalar(u8, forms, ',');
        while (it.next()) |f| try selected.append(s.gpa, f);
        return @intFromBool(try candidates.gate(
            s,
            t,
            tree,
            a.at(1),
            updates,
            a.at(2),
            provider,
            arch,
            selected.items,
        ));
    }
    if (mem.eql(u8, command, "export")) {
        try a.want(
            s,
            6,
            "form-images export SNAPSHOTS VERIFIED GATED ASSETS LISTING [--legacy-verified DIR]",
        );
        var exported: std.ArrayList(json.Json) = .empty;
        const selections: []const []const u8 = if (s.variants.len > 0)
            &.{s.variants}
        else
            try all.selections(s);
        const saved = s.variants;
        defer s.variants = saved;
        s.collect_outputs = true;
        defer s.collect_outputs = false;
        for (selections) |selection| {
            s.variants = selection;
            const selected = try all.selected(s);
            if (selected.forms.len == 0 or (recovery and
                !selected.hasForm(selected.focused.form))) continue;
            const listing = try s.gpa.print(
                "{s}.{s}",
                .{ a.at(5), if (selection.len == 0) "default" else selection },
            );
            try publication.exportAll(
                s,
                selected,
                tree,
                a.at(1),
                a.at(2),
                a.at(3),
                store,
                a.at(4),
                listing,
                a.option("legacy-verified"),
            );
            try exported.appendSlice(s.gpa, try json.items(try sys.readJson(s, listing, 16 << 20)));
        }
        try sys.writeJson(s, a.at(5), try json.from(s.gpa, exported.items));
        s.collect_outputs = false;
        try publication.githubOutput(
            s,
            &.{.{ "targets", try s.gpa.print("{d}", .{exported.items.len}) }},
        );
        return 0;
    }
    if (mem.eql(u8, command, "publish")) {
        try a.want(s, 4, "form-images publish SNAPSHOTS VERIFIED LISTING");
        const groups = try json.parse(
            s.gpa,
            s.getenv("FORM_IMAGES_GATES") orelse return s.refuse(
                "FORM_IMAGES_GATES is required",
                .{},
            ),
        );
        var failed = false;
        var released = true;
        var smoke: std.ArrayList(json.Json) = .empty;
        var count: usize = 0;
        const selections: []const []const u8 = if (s.variants.len > 0)
            &.{s.variants}
        else
            try all.selections(s);
        const saved = s.variants;
        defer s.variants = saved;
        s.collect_outputs = true;
        defer s.collect_outputs = false;
        for (selections) |selection| {
            s.variants = selection;
            const selected = try all.selected(s);
            if (selected.forms.len == 0 or (recovery and
                !selected.hasForm(selected.focused.form))) continue;
            failed = (try publication.publishAll(s, all, tree, a.at(
                1,
            ), a.at(2), try publication.gatedTargets(
                s,
                groups,
            ), a.at(3), store, recovery, selected.forms)) or failed;
            released = released and mem.eql(u8, s.outputs.get("released") orelse "false", "true");
            count += try std.fmt.parseInt(usize, s.outputs.get("public_targets") orelse "0", 10);
            const matrix = try json.parse(s.gpa, s.outputs.get("smoke") orelse "{\"include\":[]}");
            try smoke.appendSlice(s.gpa, try json.items(try json.field(matrix, "include")));
        }
        s.collect_outputs = false;
        try publication.githubOutput(s, &.{
            .{ "released", if (released) "true" else "false" },
            .{ "public_targets", try s.gpa.print("{d}", .{count}) },
            .{ "smoke", try json.dumps(s.gpa, try json.from(s.gpa, .{ .include = smoke.items })) },
        });
        return @intFromBool(failed);
    }
    return s.refuse("unknown form-images command {s}", .{command});
}

fn strings(s: *Sys, args: []const [:0]const u8) ![]const []const u8 {
    const out = try s.gpa.alloc([]const u8, args.len);
    for (args, out) |arg, *o| o.* = arg;
    return out;
}

/// Args are positional arguments and --name VALUE (or --name=VALUE)
/// options, in any order, as argparse took them.
const Args = struct {
    positional: []const []const u8,
    options: []const [2][]const u8,

    fn parse(s: *Sys, args: []const [:0]const u8) !Args {
        var positional: std.ArrayList([]const u8) = .empty;
        var options: std.ArrayList([2][]const u8) = .empty;
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            const arg: []const u8 = args[i];
            if (!mem.startsWith(u8, arg, "--") or arg.len == 2) {
                try positional.append(s.gpa, arg);
            } else if (mem.findScalar(u8, arg, '=')) |eq| {
                try options.append(s.gpa, .{ arg[2..eq], arg[eq + 1 ..] });
            } else {
                i += 1;
                if (i == args.len) return s.refuse("{s} takes a value", .{arg});
                try options.append(s.gpa, .{ arg[2..], args[i] });
            }
        }
        return .{ .positional = positional.items, .options = options.items };
    }

    fn at(a: Args, i: usize) []const u8 {
        return a.positional[i];
    }

    fn option(a: Args, name: []const u8) ?[]const u8 {
        var found: ?[]const u8 = null;
        for (a.options) |o| {
            if (mem.eql(u8, o[0], name)) found = o[1];
        }
        return found;
    }

    fn want(a: Args, s: *Sys, n: usize, comptime use: []const u8) !void {
        if (a.positional.len != n) return s.refuse("usage: " ++ use, .{});
    }
};

test "legacy build and check use the scheduled full catalog selection" {
    const testing = std.testing;
    const fixture = @import("fixture.zig");
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const configured = try images.load(s);
    const extra = for (configured.catalog_forms) |name| {
        if (!configured.hasForm(name)) break name;
    } else return error.TestExpectedCatalogForm;
    try testing.expect(!(try imageScope(s, configured)).hasForm(extra));
    try f.env.put("FORM_IMAGES_TARGET", "all");
    const selected = try (try imageScope(s, configured)).selected(s);
    try testing.expect(selected.hasForm(extra));
    try sys.writeJson(s, f.path("snapshot/plan.json"), try json.from(s.gpa, .{
        .arch = "x86_64",
        .targets = &[_]json.Json{try json.from(s.gpa, .{
            .form = extra,
            .arch = "x86_64",
            .status = "unchanged",
            .legacy_status = "unchanged",
        })},
    }));
    const tree: plan.Tree = .{ .native = false };
    try testing.expect(!try legacy.build(s, selected, tree, f.path("snapshot"), f.path("built")));
    try testing.expect(!try legacy.check(
        s,
        selected,
        tree,
        f.path("snapshot"),
        f.path("first"),
        f.path("second"),
        f.path("checked"),
    ));
    try testing.expectError(
        error.Refused,
        legacy.build(s, configured, tree, f.path("snapshot"), f.path("base")),
    );
}

test {
    _ = @import("json.zig");
    _ = @import("sys.zig");
    _ = @import("images.zig");
    _ = @import("catalog.zig");
    _ = @import("notes.zig");
    _ = @import("keys.zig");
    _ = @import("health.zig");
    _ = @import("boot.zig");
    _ = @import("publish.zig");
    _ = @import("exporter.zig");
    _ = @import("prepare.zig");
    _ = @import("inputs.zig");
    _ = @import("plan.zig");
    _ = @import("candidates.zig");
    _ = @import("publication.zig");
    _ = @import("legacy.zig");
    _ = @import("github.zig");
    _ = @import("admission.zig");
    _ = @import("protected.zig");
}
