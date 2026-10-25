//! publication is form-images' last two steps: signing release assets for
//! every bundle that passed its lifecycle gates, then publishing them and
//! the signed catalog of every target, failures and all.

const std = @import("std");
const mem = std.mem;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const images = @import("images.zig");
const catalog = @import("catalog.zig");
const notes = @import("notes.zig");
const plan = @import("plan.zig");
const Tree = plan.Tree;
const exporter = @import("exporter.zig");
const prepare = @import("prepare.zig");
const publish_protected = @import("publish.zig");
const admission = @import("admission.zig");
const legacy = @import("legacy.zig");
const Store = @import("store.zig").Store;

/// artifactDirectories are root's PATTERN/MARKER directories, or root when
/// it holds MARKER itself: download-artifact flattens a single match.
pub fn artifactDirectories(
    s: *Sys,
    root: []const u8,
    pattern: []const u8,
    marker: []const u8,
) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    if (sys.isDir(s, root)) for (try sys.list(s, root)) |name| {
        if (mem.startsWith(u8, name, pattern) and
            sys.exists(s, try sys.join(s, &.{ root, name, marker })))
            try out.append(s.gpa, try sys.join(s, &.{ root, name }));
    };
    if (sys.isFile(s, try sys.join(s, &.{ root, marker }))) {
        if (out.items.len > 0) return s.refuse("mixed flat and named form image artifacts", .{});
        try out.append(s.gpa, root);
    }
    return out.items;
}

/// Targets are every plan's targets, each with its shard.
pub const Targets = struct {
    items: []const Json,

    pub fn get(x: Targets, name: []const u8, arch: []const u8) ?Json {
        for (x.items) |t| {
            if (mem.eql(u8, json.text(t, "form") catch "", name) and
                mem.eql(u8, json.text(t, "arch") catch "", arch)) return t;
        }
        return null;
    }
};

pub fn plans(s: *Sys, snapshots: []const u8) !Targets {
    const directories = try artifactDirectories(s, snapshots, "inputs-", "plan.json");
    if (directories.len == 0) return s.refuse("form image plans are missing", .{});
    var out: std.ArrayList(Json) = .empty;
    for (directories) |dir| {
        const p = try sys.readJson(s, try sys.join(s, &.{ dir, "plan.json" }), 1 << 20);
        for (try json.items(try json.field(p, "targets"))) |target| {
            const x: Targets = .{ .items = out.items };
            if (x.get(try json.text(target, "form"), try json.text(target, "arch")) != null or
                !json.eql(try json.field(target, "arch"), try json.field(p, "arch")))
                return s.refuse("foreign or duplicate form image plan", .{});
            var t = try json.parse(s.gpa, try json.encode(s.gpa, target));
            try t.object.put(s.gpa, "shard", try json.field(p, "shard"));
            try out.append(s.gpa, t);
        }
    }
    return .{ .items = out.items };
}

/// verifiedResults are the check jobs' results, each naming the
/// directory of its evidence.
pub fn verifiedResults(s: *Sys, verified: []const u8) !Targets {
    var out: std.ArrayList(Json) = .empty;
    for (try artifactDirectories(s, verified, "verified-", "results.json")) |dir| {
        for (try json.items(try sys.readJson(
            s,
            try sys.join(s, &.{ dir, "results.json" }),
            1 << 20,
        ))) |result| {
            var r = try json.parse(s.gpa, try json.encode(s.gpa, result));
            try r.object.put(
                s.gpa,
                "directory",
                .{ .string = try sys.join(s, &.{ dir, try json.text(result, "form") }) },
            );
            // A later result of a target replaces an earlier one, in its place.
            for (out.items) |*old| {
                if (mem.eql(u8, try json.text(old.*, "form"), try json.text(r, "form")) and
                    mem.eql(u8, try json.text(old.*, "arch"), try json.text(r, "arch")))
                {
                    old.* = r;
                    break;
                }
            } else try out.append(s.gpa, r);
        }
    }
    return .{ .items = out.items };
}

/// index is the store's signed catalog, or none before the first release.
pub fn index(s: *Sys, t: images.Images, tree: Tree, store: Store) !catalog.Index {
    const work = try sys.scratch(s, null, "ww-form-index-");
    defer sys.remove(s, work);
    const raw = try sys.join(s, &.{ work, "index.json" });
    if (!try store.fetch(s, "index.json", raw)) return .{};
    return catalog.openIndex(s, t, try sys.read(s, raw, 4 << 20), try tree.certificate(s));
}

/// inventory is the package inventory a previous release signed, or null
/// for a release that carried none.
pub fn inventory(s: *Sys, tree: Tree, store: Store, latest: Json, work: []const u8) !?Json {
    const object = try json.text(latest, "object");
    for ([_][]const u8{ "downloads.json", "downloads.json.sig" }) |name| {
        if (!try store.fetch(
            s,
            try s.gpa.print("{s}/{s}", .{ object, name }),
            try sys.join(s, &.{ work, name }),
        ))
            return s.refuse("previous release manifest is missing", .{});
    }
    const head = try sys.read(s, try sys.join(s, &.{ work, "downloads.json" }), 4 << 20);
    try catalog.verify(
        s,
        head,
        try sys.read(s, try sys.join(s, &.{ work, "downloads.json.sig" }), 512),
        try tree.certificate(s),
    );
    const signed = try json.parse(s.gpa, head);
    const listed = try json.field(signed, "files");
    if (!json.eql(try json.field(signed, "descriptor"), try json.field(latest, "descriptor")) or
        json.get(listed, "packages.json") == null) return null;
    const expected = json.get(listed, "packages.json").?;
    const path = try sys.join(s, &.{ work, "packages.json" });
    if (!try store.fetch(s, try s.gpa.print("{s}/packages.json", .{object}), path) or
        !(try sys.record(s, path)).matches(expected))
        return s.refuse("previous release package inventory is missing or changed", .{});
    return try sys.readJson(s, path, 4 << 20);
}

/// reuseExport reuses the authenticated bytes of a bundle already
/// exported by this workflow run: a retry never signs new bytes under an
/// immutable identity.
fn reuseExport(
    s: *Sys,
    tree: Tree,
    store: Store,
    key: []const u8,
    bundle: []const u8,
    report: Json,
    provider: []const u8,
    output: []const u8,
    verified: []const u8,
    work: []const u8,
) !bool {
    const base = try s.gpa.print(
        "{s}/objects/{s}",
        .{ key, &try sys.sha(s, try sys.join(s, &.{ bundle, "boot.json" })) },
    );
    const head = try sys.join(s, &.{ work, "downloads.json" });
    const signature = try sys.join(s, &.{ work, "downloads.json.sig" });
    if (!try store.fetch(s, try s.gpa.print("{s}/downloads.json", .{base}), head)) return false;
    if (!try store.fetch(
        s,
        try s.gpa.print("{s}/downloads.json.sig", .{base}),
        signature,
    )) return s.refuse("existing export is missing its signature", .{});
    const head_bytes = try sys.read(s, head, 4 << 20);
    try catalog.verify(s, head_bytes, try sys.read(s, signature, 512), try tree.certificate(s));
    const signed = try json.parse(s.gpa, head_bytes);
    const current = try exporter.provenance(s);
    for ([_][]const u8{ "repository", "commit", "run" }) |k| {
        if (!json.eql(
            try json.field(try json.field(signed, "provenance"), k),
            try json.field(current, k),
        ))
            return s.refuse("existing export is from another workflow build", .{});
    }
    const trust = try sys.resolve(s, tree.trust);
    const originals = try exporter.sources(s, bundle, trust);
    const listed = try json.object(try json.field(signed, "files"));
    for (listed.keys()) |name| {
        const known = for (originals) |o| {
            if (mem.eql(u8, o.name, name)) break true;
        } else mem.eql(u8, name, "disk.qcow2") or mem.eql(u8, name, "gates.json") or
            exporter.isExtra(name);
        if (!known) return s.refuse("existing export contains unexpected files", .{});
    }
    _ = try prepare.prepare(
        s,
        try sys.resolve(s, tree.howl),
        bundle,
        report,
        provider,
        try sys.join(s, &.{ work, "admitted" }),
        trust,
        null,
    );
    const staging = try sys.join(s, &.{ work, "assets" });
    try sys.mkdir(s, staging);
    const prefix = try dashed(s, key);
    var names: std.ArrayList([]const u8) = .empty;
    try names.appendSlice(s.gpa, &.{ "downloads.json", "downloads.json.sig" });
    try names.appendSlice(s.gpa, listed.keys());
    for (names.items) |name| {
        if (!try store.fetch(
            s,
            try s.gpa.print("{s}/{s}", .{ base, name }),
            try sys.join(s, &.{ staging, try s.gpa.print("{s}-{s}", .{ prefix, name }) }),
        ))
            return s.refuse("existing export is incomplete", .{});
    }
    _ = try exporter.verify(s, staging, bundle, report, provider, trust);
    for ([_][]const u8{ "inputs.tar.gz", "packages.json", "tests.json" }) |name| {
        if (!mem.eql(
            u8,
            &try sys.sha(
                s,
                try sys.join(s, &.{ staging, try s.gpa.print("{s}-{s}", .{ prefix, name }) }),
            ),
            &try sys.sha(s, try sys.join(s, &.{ verified, name })),
        ))
            return s.refuse("existing export differs from the verified build inputs", .{});
    }
    try sys.rename(s, staging, output);
    return true;
}

/// dashed is FORM/PROVIDER/ARCH as an asset prefix.
fn dashed(s: *Sys, key: []const u8) ![]const u8 {
    return mem.replaceOwned(u8, s.gpa, key, "/", "-");
}

fn exportOne(
    s: *Sys,
    t: images.Images,
    tree: Tree,
    directory: []const u8,
    targets: Targets,
    results: Targets,
    previous: catalog.Index,
    store: Store,
    assets: []const u8,
) !Json {
    const gates_path = try sys.join(s, &.{ directory, "gates.json" });
    const report = try sys.readJson(s, gates_path, 64 << 10);
    const bundle = try sys.join(s, &.{ directory, "bundle" });
    const manifest = try sys.readJson(s, try sys.join(s, &.{ bundle, "boot.json" }), 1 << 20);
    const name = try json.text(manifest, "form");
    const provider = try json.text(report, "provider");
    const arch = try json.text(try json.field(manifest, "image"), "arch");
    if (!t.identity(
        name,
        arch,
        "secure-boot",
    )) return s.refuse("unsupported published image identity", .{});
    const key = try catalog.namespace(s, t, name, provider, arch);
    const target = targets.get(
        name,
        arch,
    ) orelse return s.refuse("gated bundle is not this workflow's verified build", .{});
    const result = results.get(
        name,
        arch,
    ) orelse return s.refuse("gated bundle is not this workflow's verified build", .{});
    if (!mem.eql(u8, try json.text(target, "commit"), s.getenv("GITHUB_SHA") orelse "") or
        !mem.eql(u8, try json.text(result, "status"), "passed"))
        return s.refuse("gated bundle is not this workflow's verified build", .{});
    const verified = try json.text(result, "directory");
    const tests = try sys.readJson(s, try sys.join(s, &.{ verified, "tests.json" }), 1 << 20);
    const checks = json.get(tests, "checks") orelse .null;
    var good = json.eql(
        json.get(tests, "inputs") orelse .null,
        try json.field(target, "inputs"),
    ) and json.hasKeys(checks, t.checks);
    if (good) for (t.checks) |c| {
        const v = checks.object.get(c).?;
        good = good and v == .bool and v.bool;
    };
    const descriptor = try sys.sha(s, try sys.join(s, &.{ bundle, "boot.json" }));
    const tested = json.get(json.get(tests, "bundles") orelse .null, provider) orelse .null;
    if (!good or tested != .string or
        !mem.eql(
            u8,
            tested.string,
            &descriptor,
        )) return s.refuse("gated bundle differs from the verified build", .{});
    const output = try sys.join(s, &.{ assets, try dashed(s, key) });
    const entry = try json.from(s.gpa, .{
        .form = name,
        .provider = provider,
        .arch = arch,
        .bundle = try sys.resolve(s, bundle),
        .gates = try sys.resolve(s, gates_path),
        .assets = output,
    });
    const work = try sys.scratch(s, assets, "ww-form-extras-");
    defer sys.remove(s, work);
    if (try reuseExport(
        s,
        tree,
        store,
        key,
        bundle,
        report,
        provider,
        output,
        verified,
        work,
    )) return entry;
    const latest = previous.latest(name, provider, arch);
    const old = if (latest) |l| try inventory(s, tree, store, l, work) else null;
    const packages = try sys.readJson(s, try sys.join(s, &.{ verified, "packages.json" }), 4 << 20);
    const release = try notes.release(s, .{
        .form = name,
        .provider = provider,
        .arch = arch,
        .serial = try json.text(try json.field(manifest, "image"), "serial"),
        .commit = try json.text(target, "commit"),
    }, packages, if (old != null) latest else null, old);
    try sys.writeJson(s, try sys.join(s, &.{ work, "release-notes.json" }), release);
    try sys.write(
        s,
        try sys.join(s, &.{ work, "release-notes.html" }),
        try notes.page(s, release, ""),
    );
    var extras: std.ArrayList(exporter.Extra) = .empty;
    for ([_][]const u8{
        "inputs.tar.gz",
        "packages.json",
        "tests.json",
    }) |n| try extras.append(s.gpa, .{ .name = n, .path = try sys.join(s, &.{ verified, n }) });
    for ([_][]const u8{
        "release-notes.json",
        "release-notes.html",
    }) |n| try extras.append(s.gpa, .{ .name = n, .path = try sys.join(s, &.{ work, n }) });
    _ = try exporter.exportBundle(
        s,
        try sys.resolve(s, tree.howl),
        bundle,
        report,
        provider,
        output,
        tree.trust,
        extras.items,
    );
    return entry;
}

/// exportAll signs release assets for every bundle that passed its gates
/// and every verified legacy image. A target that fails here is left out
/// of listing; publish records it as failed.
pub fn exportAll(
    s: *Sys,
    t: images.Images,
    tree: Tree,
    snapshots: []const u8,
    verified: []const u8,
    gated: []const u8,
    store: Store,
    assets_dir: []const u8,
    listing: []const u8,
    legacy_verified: ?[]const u8,
) !void {
    _ = try exporter.provenance(s);
    const targets = try plans(s, snapshots);
    const results = try verifiedResults(s, verified);
    const previous = try index(s, t, tree, store);
    const assets = try sys.resolve(s, assets_dir);
    if (sys.exists(s, assets)) return s.refuse("{s} already exists", .{assets});
    try sys.mkdirs(s, assets);
    var exported: std.ArrayList(Json) = .empty;
    var directories: std.ArrayList([]const u8) = .empty;
    if (sys.isDir(s, gated)) for (try sys.walk(s, gated)) |e| {
        if (e.kind == .file and mem.eql(u8, std.fs.path.basename(e.path), "gates.json"))
            try directories.append(
                s.gpa,
                std.fs.path.dirname(try sys.join(s, &.{ gated, e.path })).?,
            );
    };
    mem.sort([]const u8, directories.items, {}, sys.pathLess);
    for (directories.items) |dir| {
        if (exportOne(s, t, tree, dir, targets, results, previous, store, assets)) |entry| {
            try exported.append(s.gpa, entry);
        } else |err| s.say(
            "form-images: {s} export failed: {s}",
            .{ std.fs.path.basename(dir), s.reason(err) },
        );
    }
    if (legacy_verified) |root| {
        if (sys.isDir(s, root)) for (try sys.walk(s, root)) |e| {
            if (e.kind != .file or
                !mem.eql(u8, std.fs.path.basename(e.path), "manifest.json")) continue;
            const dir = std.fs.path.dirname(try sys.join(s, &.{ root, e.path })).?;
            const provenance = try exporter.provenance(s);
            if (legacy.exportVerified(
                s,
                t,
                dir,
                assets,
                provenance,
                targets.items,
                try tree.certificate(s),
                store,
            )) |more| {
                try exported.appendSlice(s.gpa, more);
            } else |err| s.say(
                "form-images: {s} legacy export failed: {s}",
                .{ std.fs.path.basename(dir), s.reason(err) },
            );
        };
    }
    try sys.writeJson(s, listing, .{ .array = .fromOwnedSlice(s.gpa, exported.items) });
    try githubOutput(s, &.{.{ "targets", try s.gpa.print("{d}", .{exported.items.len}) }});
}

/// githubOutput adds step outputs for later jobs, when run by Actions.
pub fn githubOutput(s: *Sys, values: []const [2][]const u8) !void {
    const path = s.getenv("GITHUB_OUTPUT") orelse return;
    var text: std.ArrayList(u8) = .empty;
    for (values) |v| try text.print(s.gpa, "{s}={s}\n", .{ v[0], v[1] });
    try append(s, path, text.items);
}

fn append(s: *Sys, path: []const u8, bytes: []const u8) !void {
    const f = try std.Io.Dir.cwd().createFile(s.io, path, .{ .truncate = false });
    defer f.close(s.io);
    const end = (try f.stat(s.io)).size;
    try f.writePositionalAll(s.io, bytes, end);
}

/// publicMatrix is the public-check jobs: each gate runner's newly
/// published QEMU targets, downloaded and booted as a consumer would.
pub fn publicMatrix(s: *Sys, t: images.Images, published: []const Published, groups: Json) !Json {
    var include: std.ArrayList(Json) = .empty;
    for (try json.items(try json.field(groups, "include"))) |group| {
        if (!mem.eql(u8, try json.text(group, "provider"), "qemu")) continue;
        const arch = try json.text(group, "arch");
        var targets: std.ArrayList(Json) = .empty;
        for (try json.items(try json.field(group, "forms"))) |f| {
            const name = try catalog.namespace(s, t, f.string, "qemu", arch);
            const p = for (published) |x| {
                if (mem.eql(u8, x.name, name)) break x;
            } else continue;
            var target: json.Map = .empty;
            try target.put(s.gpa, "form", f);
            try target.put(s.gpa, "provider", .{ .string = "qemu" });
            try target.put(s.gpa, "arch", .{ .string = arch });
            var it = p.latest.object.iterator();
            while (it.next()) |e| try target.put(s.gpa, e.key_ptr.*, e.value_ptr.*);
            try targets.append(s.gpa, .{ .object = target });
        }
        if (targets.items.len > 0) try include.append(
            s.gpa,
            try json.from(
                s.gpa,
                .{ .runner = try json.field(group, "runner"), .targets = targets.items },
            ),
        );
    }
    return json.from(s.gpa, .{ .include = include.items });
}

pub const Published = struct { name: []const u8, latest: Json };

/// Gated is a target a lifecycle gate job covered.
pub const Gated = struct { form: []const u8, provider: []const u8, arch: []const u8 };

/// gatedTargets are the form/provider/arch triples of FORM_IMAGES_GATES.
pub fn gatedTargets(s: *Sys, groups: Json) ![]const Gated {
    var out: std.ArrayList(Gated) = .empty;
    for (try json.items(try json.field(
        groups,
        "include",
    ))) |g| for (try json.items(try json.field(g, "forms"))) |f| {
        try out.append(
            s.gpa,
            .{
                .form = f.string,
                .provider = try json.text(g, "provider"),
                .arch = try json.text(g, "arch"),
            },
        );
    };
    return out.items;
}

/// publishAll advances each exported target, then signs and uploads the
/// catalog of every target in scope: a focused run only its own, keeping
/// every other row as it was. It says whether any target is unsettled.
pub fn publishAll(
    s: *Sys,
    t: images.Images,
    tree: Tree,
    snapshots: []const u8,
    verified: []const u8,
    gated: []const Gated,
    listing: []const u8,
    store: Store,
    recovery: bool,
    scope: []const []const u8,
) !bool {
    const provenance = try exporter.provenance(s);
    const key = s.getenv("WEREWOLF_PROTECTED_IMAGE_KEY") orelse return s.refuse(
        "WEREWOLF_PROTECTED_IMAGE_KEY is required",
        .{},
    );
    const targets = try plans(s, snapshots);
    const results = try verifiedResults(s, verified);
    const previous = try index(s, t, tree, store);
    const listed = try json.items(try sys.readJson(s, listing, 16 << 20));
    var secure: std.ArrayList(Json) = .empty;
    var legacy_listed: std.ArrayList(Json) = .empty;
    for (listed) |target| {
        const profile = if (json.get(target, "boot_profile")) |p| p.string else "secure-boot";
        if (!t.identity(try json.text(target, "form"), try json.text(target, "arch"), profile))
            return s.refuse("unsupported published image identity", .{});
        if (mem.eql(u8, profile, "legacy-boot")) try legacy_listed.append(s.gpa, target);
        if (mem.eql(u8, profile, "secure-boot")) try secure.append(s.gpa, target);
    }
    if (recovery) {
        const f = t.focused;
        for (targets.items) |x| if (!mem.eql(u8, try json.text(x, "form"), f.form) or
            !mem.eql(u8, try json.text(x, "arch"), f.arch))
            return s.refuse("focused publication contains an unrelated target", .{});
        for (secure.items) |x| if (!t.isFocused(
            try json.text(x, "form"),
            try json.text(x, "provider"),
            try json.text(x, "arch"),
        ))
            return s.refuse("focused publication contains an unrelated target", .{});
        for (legacy_listed.items) |x| if (!mem.eql(u8, try json.text(x, "form"), f.form) or
            !mem.eql(u8, try json.text(x, "arch"), f.arch))
            return s.refuse("focused publication contains an unrelated target", .{});
    }
    // Exported targets by name; a later listing of one replaces the first.
    var exported_names: std.ArrayList([]const u8) = .empty;
    var exported: std.ArrayList(Json) = .empty;
    for (secure.items) |x| {
        const name = try catalog.namespace(
            s,
            t,
            try json.text(x, "form"),
            try json.text(x, "provider"),
            try json.text(x, "arch"),
        );
        for (exported_names.items, 0..) |n, i| {
            if (mem.eql(u8, n, name)) {
                exported.items[i] = x;
                break;
            }
        } else {
            try exported_names.append(s.gpa, name);
            try exported.append(s.gpa, x);
        }
    }
    const order = try s.gpa.alloc(usize, exported.items.len);
    for (order, 0..) |*o, i| o.* = i;
    mem.sort(usize, order, exported_names.items, struct {
        fn less(names: [][]const u8, a: usize, b: usize) bool {
            return json.less({}, names[a], names[b]);
        }
    }.less);
    var published: std.ArrayList(Published) = .empty;
    const trust = try sys.resolve(s, tree.trust);
    for (order) |i| {
        const name = exported_names.items[i];
        if (publishOne(s, tree, exported.items[i], name, store, trust)) |latest| {
            try published.append(s.gpa, .{ .name = name, .latest = latest });
        } else |err| s.say("form-images: {s} publication failed: {s}", .{ name, s.reason(err) });
    }
    // The GitHub release carries every exported target, so it follows R2 only
    // when all of them are there.
    const legacy_rows = try legacy.publish(
        s,
        t,
        legacy_listed.items,
        store,
        try tree.certificate(s),
    );
    var rows: std.ArrayList(Json) = .empty;
    // A focused run has no evidence about other targets. Preserve their signed
    // rows, including failures, inputs and last publications, without relabeling.
    for (previous.rows) |row| {
        const name = try json.text(row, "form");
        if (!t.hasForm(name)) continue;
        if (recovery) {
            if (!t.isFocused(
                name,
                try json.text(row, "provider"),
                try json.text(row, "arch"),
            )) try rows.append(s.gpa, row);
        } else if (!images.has(scope, name)) try rows.append(s.gpa, row);
    }
    var attempted: std.ArrayList(Json) = .empty;
    const descriptions = try catalog.descriptions(s, tree.catalog);
    const focused_form = [_][]const u8{t.focused.form};
    const forms: []const []const u8 = if (recovery) &focused_form else scope;
    var arches: std.ArrayList([]const u8) = .empty;
    if (recovery)
        try arches.append(s.gpa, t.focused.arch)
    else for (t.arches) |a| try arches.append(s.gpa, a.name);
    for (forms) |name| for (arches.items) |arch| {
        const target = targets.get(name, arch);
        var status: []const u8 = if (target) |x|
            try json.text(x, "status")
        else
            "resolution or runner failed";
        if (target == null) {
            if (plan.query(s, tree, &.{ "archs", name })) |supported| {
                if (!images.has(supported, arch)) status = "unsupported architecture";
            } else |_| {}
        }
        for (t.providers(arch)) |provider| {
            const namespace = try catalog.namespace(s, t, name, provider, arch);
            const last = previous.row(name, provider, arch) orelse Json{ .null = {} };
            var row: json.Map = .empty;
            try row.put(s.gpa, "form", .{ .string = name });
            try row.put(s.gpa, "provider", .{ .string = provider });
            try row.put(s.gpa, "arch", .{ .string = arch });
            try row.put(s.gpa, "status", .{ .string = status });
            try row.put(s.gpa, "run", try json.field(provenance, "run"));
            if (catalog.description(descriptions, name)) |d| {
                try row.put(s.gpa, "summary", .{ .string = d.summary });
                try row.put(s.gpa, "guide", .{ .string = d.guide });
            }
            if (json.get(last, "latest")) |l| try row.put(s.gpa, "latest", l);
            if (mem.eql(u8, status, "unchanged")) {
                for ([_][]const u8{
                    "status",
                    "inputs",
                    "run",
                }) |k| if (json.get(last, k)) |v| try row.put(s.gpa, k, v);
            } else if (mem.eql(u8, status, "build")) {
                try row.put(s.gpa, "inputs", try json.field(target.?, "inputs"));
                const result = if (results.get(name, arch)) |r|
                    json.text(r, "status") catch ""
                else
                    "";
                const now_published = for (published.items) |p| {
                    if (mem.eql(u8, p.name, namespace)) break p.latest;
                } else null;
                const label: []const u8 = if (!mem.eql(u8, result, "passed"))
                    "build, tests or reproducibility failed"
                else if (now_published) |l| blk: {
                    try row.put(s.gpa, "latest", l);
                    break :blk catalog.published;
                } else if (images.has(exported_names.items, namespace))
                    "publication failed"
                else if (!t.supportsGate(name, provider))
                    catalog.ungated
                else if (for (gated) |g| {
                    if (mem.eql(u8, g.form, name) and mem.eql(u8, g.provider, provider) and
                        mem.eql(u8, g.arch, arch)) break false;
                } else true)
                    catalog.no_runner
                else
                    "lifecycle gates or export failed";
                try row.put(s.gpa, "status", .{ .string = label });
            }
            const valid = try catalog.validate(s, t, .{ .object = row });
            try rows.append(s.gpa, valid);
            try attempted.append(s.gpa, valid);
        }
    };
    mem.sort(Json, rows.items, {}, byTarget);
    {
        const work = try sys.scratch(s, null, "ww-image-catalog-");
        defer sys.remove(s, work);
        const index_path = try sys.join(s, &.{ work, "index.json" });
        try sys.write(
            s,
            index_path,
            try catalog.envelope(
                s,
                try json.from(s.gpa, .{ .format = catalog.format, .forms = rows.items }),
                key,
            ),
        );
        _ = try catalog.openIndex(
            s,
            t,
            try sys.read(s, index_path, 4 << 20),
            try tree.certificate(s),
        );
        try store.upload(s, "index.json", index_path, false);
        const profiles_path = try sys.join(s, &.{ work, "boot-profiles.json" });
        try sys.write(s, profiles_path, try catalog.envelope(s, try json.from(s.gpa, .{
            .format = "werewolf-boot-profiles/1",
            .secure_boot = rows.items,
            .legacy_boot = legacy_rows,
        }), key));
        try store.upload(s, "boot-profiles.json", profiles_path, false);
        var pages: std.ArrayList([]const u8) = .empty;
        for (scope) |f| if (!images.has(pages.items, f)) try pages.append(s.gpa, f);
        for (rows.items) |r| {
            const f = try json.text(r, "form");
            if (!images.has(pages.items, f)) try pages.append(s.gpa, f);
        }
        mem.sort([]const u8, pages.items, {}, json.less);
        const page_path = try sys.join(s, &.{ work, "form.html" });
        for (pages.items) |f| {
            var mine: std.ArrayList(Json) = .empty;
            for (rows.items) |r| if (mem.eql(
                u8,
                try json.text(r, "form"),
                f,
            )) try mine.append(s.gpa, r);
            var theirs: std.ArrayList(Json) = .empty;
            for (legacy_rows) |r| if (mem.eql(
                u8,
                try json.text(r, "form"),
                f,
            )) try theirs.append(s.gpa, r);
            try sys.write(
                s,
                page_path,
                try catalog.page(
                    s,
                    t,
                    mine.items,
                    try s.gpa.print("{s} images", .{f}),
                    theirs.items,
                ),
            );
            try store.upload(s, try s.gpa.print("{s}/index.html", .{f}), page_path, false);
        }
        const all_path = try sys.join(s, &.{ work, "index.html" });
        try sys.write(
            s,
            all_path,
            try catalog.page(s, t, rows.items, "Werewolf images", legacy_rows),
        );
        try store.upload(s, "index.html", all_path, false);
    }
    const groups = try json.parse(s.gpa, s.getenv("FORM_IMAGES_GATES") orelse "{\"include\":[]}");
    const smoke = try publicMatrix(s, t, published.items, groups);
    var public_targets: usize = 0;
    for (try json.items(json.get(
        smoke,
        "include",
    ).?)) |g| public_targets += (try json.items(json.get(g, "targets").?)).len;
    try githubOutput(s, &.{
        .{ "released", if (published.items.len == exported_names.items.len) "true" else "false" },
        .{ "public_targets", try s.gpa.print("{d}", .{public_targets}) },
        .{ "smoke", try json.dumps(s.gpa, smoke) },
    });
    if (s.getenv("GITHUB_STEP_SUMMARY")) |summary| {
        var text: std.ArrayList(u8) = .empty;
        try text.appendSlice(
            s.gpa,
            "### Form images\n\n| Form | Target | Latest attempt | Latest published |\n| --- | " ++
                "--- | --- | --- |\n",
        );
        const base = try catalog.public(s);
        for (rows.items) |r| {
            const link = if (json.get(r, "latest")) |l|
                try s.gpa.print(
                    "[{s}]({s}/{s}/release-notes.html)",
                    .{ try json.text(l, "serial"), base, try json.text(l, "object") },
                )
            else
                "Not published";
            try text.print(
                s.gpa,
                "| {s} | {s}/{s} | {s} | {s} |\n",
                .{
                    try json.text(r, "form"),
                    try json.text(r, "provider"),
                    try json.text(r, "arch"),
                    try json.text(r, "status"),
                    link,
                },
            );
        }
        try append(s, summary, text.items);
    }
    for (attempted.items) |r| {
        const status = try json.text(r, "status");
        if (!catalog.isSettled(status) and
            !mem.eql(u8, status, "unsupported architecture")) return true;
    }
    return false;
}

fn publishOne(
    s: *Sys,
    tree: Tree,
    target: Json,
    name: []const u8,
    store: Store,
    trust: []const u8,
) !Json {
    const report = try sys.readJson(s, try json.text(target, "gates"), 64 << 10);
    const assets = try json.text(target, "assets");
    const bundle = try json.text(target, "bundle");
    const provider = try json.text(target, "provider");
    const howl = try sys.resolve(s, tree.howl);
    _ = try publish_protected.publish(s, howl, bundle, report, provider, store, trust, assets);
    if (store.remote()) try admission.checkMirror(s, tree, howl, bundle, provider, assets);
    const signed = try sys.readJson(
        s,
        try sys.join(
            s,
            &.{ assets, try s.gpa.print("{s}-downloads.json", .{try dashed(s, name)}) },
        ),
        4 << 20,
    );
    const head = try sys.readJson(s, try sys.join(s, &.{ bundle, "boot.json" }), 4 << 20);
    const descriptor = try json.text(signed, "descriptor");
    return json.from(s.gpa, .{
        .serial = try json.field(signed, "serial"),
        .commit = try json.field(try json.field(signed, "provenance"), "commit"),
        .descriptor = descriptor,
        .object = try s.gpa.print("{s}/objects/{s}", .{ name, descriptor }),
        .size = try json.field(
            try json.field(try json.field(signed, "files"), "disk.qcow2"),
            "size",
        ),
        .index = try json.field(try json.field(head, "image"), "index"),
    });
}

fn byTarget(_: void, a: Json, b: Json) bool {
    for ([_][]const u8{
        "form",
        "arch",
        "provider",
    }) |k| switch (mem.order(u8, json.text(a, k) catch "", json.text(b, k) catch "")) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    };
    return false;
}

const testing = std.testing;
const fixture = @import("fixture.zig");
const sha256 = sys.sha256;

/// Pipeline is a store and the jobs of form-images runs against it: a plan,
/// verified evidence and a gated playground bundle, then export and
/// publish. Admission is the fixture's; signatures, zstd and qemu-img are
/// real.
const Pipeline = struct {
    f: fixture.Fixture,
    t: images.Images,
    tree: Tree,
    store: Store,
    keys: fixture.Keys,
    disk: []const u8,
    serial: [16]u8,
    /// packages are every verified build's inventory.
    packages: std.ArrayList(Json),

    fn init(p: *Pipeline) !void {
        try p.f.init();
        const f = &p.f;
        const s = &f.s;
        p.t = try images.load(s);
        p.keys = try fixture.keys(f, "image");
        const trust = f.path("trust");
        try sys.mkdirs(s, trust);
        try sys.copy(s, p.keys.crt, f.path("trust/image.crt"));
        try sys.copy(s, p.keys.crt, f.path("trust/boot.crt"));
        try sys.copy(s, "release/protected/trust.json", f.path("trust/trust.json"));
        p.tree = .{ .trust = trust, .howl = "howl", .form = f.path("form-tool"), .native = false };
        const raw = f.path("disk.raw");
        {
            const out = try std.Io.Dir.cwd().createFile(s.io, raw, .{});
            defer out.close(s.io);
            try out.writePositionalAll(s.io, "protected disk header", 0);
            try out.setLength(s.io, 512 << 20);
        }
        p.disk = f.path("disk.img.zst");
        try sys.run(s, &.{ "zstd", "-q", raw, "-o", p.disk }, .{});
        p.store = Store.init(f.path("store"));
        p.serial = sys.serial(s.now());
        for ([_][2][]const u8{
            .{
                "WEREWOLF_PROTECTED_IMAGE_KEY",
                p.keys.key,
            },
            .{ "GITHUB_REPOSITORY", "werewolf-linux/werewolf" },
            .{ "GITHUB_SHA", fixture.rep('b', 40) },
            .{ "GITHUB_RUN_ID", "123" },
            .{ "GITHUB_RUN_ATTEMPT", "1" },
        }) |kv| try f.env.put(kv[0], kv[1]);
        f.answer = answer;
        p.packages = .empty;
        for ([_][4][]const u8{
            .{ "runtime", "busybox", "1.37-r0", fixture.rep('a', 64) },
            .{ "runtime", "removed", "1-r0", fixture.rep('b', 64) },
            .{ "build:kernel", "gcc", "15-r0", fixture.rep('e', 64) },
        }) |x| try p.packages.append(
            f.gpa(),
            try json.from(
                f.gpa(),
                .{ .scope = x[0], .name = x[1], .version = x[2], .checksum = x[3] },
            ),
        );
    }

    fn deinit(p: *Pipeline) void {
        p.f.deinit();
    }

    /// answer admits bundles as the fixture does, and answers form queries:
    /// every form is for every arch, but each form only for x86_64.
    fn answer(f: *fixture.Fixture, argv: []const []const u8) anyerror!?sys.Result {
        if (mem.endsWith(u8, argv[0], "form-tool")) {
            const out = if (mem.eql(u8, argv[1], "for-arch"))
                "minimal\nprod-ssh\nplayground\n"
            else
                "x86_64\n";
            return .{ .term = .{ .exited = 0 }, .stdout = out };
        }
        return fixture.admit(f, argv);
    }

    fn later(p: *Pipeline, seconds: i64) [16]u8 {
        return sys.serial(sys.serialTime(&p.serial).? + seconds);
    }

    fn bundle(
        p: *Pipeline,
        dir: []const u8,
        serial: []const u8,
        name: []const u8,
        release_index: i64,
    ) !void {
        const s = &p.f.s;
        const gpa = p.f.gpa();
        for (@import("boot.zig").files) |file| try sys.write(
            s,
            try sys.join(s, &.{ dir, "slot", file }),
            try gpa.print("{s}{s}", .{ file, serial }),
        );
        for ([_][]const u8{ "latest.json", "latest.json.sig" }) |file|
            try sys.write(
                s,
                try sys.join(s, &.{ dir, "prebuilt/x86_64", file }),
                try gpa.print("{s}{s}", .{ file, serial }),
            );
        try sys.copy(s, p.disk, try sys.join(s, &.{ dir, "disk.img.zst" }));
        const head = try sys.join(s, &.{ dir, "boot.json" });
        try sys.write(s, head, try json.dumps(gpa, try json.from(gpa, .{
            .form = name,
            .image = .{
                .arch = "x86_64",
                .build = try gpa.dupe(u8, &sha256(serial)),
                .serial = serial,
                .index = release_index,
            },
            .raw_size = 512 << 20,
        })));
        try sys.write(
            s,
            try sys.join(s, &.{ dir, "boot.json.sig" }),
            try fixture.signed(&p.f, "image", try sys.read(s, head, 4096)),
        );
    }

    fn rows(p: *Pipeline) !catalog.Index {
        return index(&p.f.s, p.t, p.tree, p.store);
    }

    fn inventory(p: *Pipeline, name: []const u8) !Json {
        return json.from(p.f.gpa(), .{
            .format = notes.format,
            .form = name,
            .arch = "x86_64",
            .packages = p.packages.items,
            .images = &[_]Json{},
        });
    }

    const Run = struct {
        statuses: []const [2][]const u8 = &.{},
        gated: bool = true,
        recovery: bool = false,
        flat: bool = false,
        only: ?[]const []const u8 = null,
        scope: ?[]const []const u8 = null,
    };

    const Outcome = struct { failed: bool, listing: []const Json, work: []const u8 };

    /// run is one workflow run: plan, evidence, a gated bundle, export and
    /// publish.
    fn run(p: *Pipeline, serial: []const u8, r: Run) !Outcome {
        const f = &p.f;
        const s = &f.s;
        const gpa = f.gpa();
        const work = f.path(try gpa.print("run-{s}", .{serial}));
        const selected: []const []const u8 = r.only orelse if (r.recovery)
            &.{"playground"}
        else
            &.{ "minimal", "playground" };
        const previous = try p.rows();
        var targets: std.ArrayList(Json) = .empty;
        for (selected) |name| {
            var status: []const u8 = "build";
            for (r.statuses) |kv| if (mem.eql(u8, kv[0], name)) {
                status = kv[1];
            };
            try targets.append(gpa, try json.from(gpa, .{
                .form = name,
                .arch = "x86_64",
                .status = status,
                .inputs = try gpa.dupe(u8, &sha256(name)),
                .commit = fixture.rep('b', 40),
                .serial = serial,
                .index = nextIndex(previous, name),
            }));
        }
        if (!r.recovery and r.only == null)
            try targets.append(
                gpa,
                try json.from(
                    gpa,
                    .{ .form = "prod-ssh", .arch = "x86_64", .status = "resolution failed" },
                ),
            );
        const snapshots = try sys.join(
            s,
            &.{ work, if (r.flat) "snapshots" else "snapshots/inputs-x86_64-1" },
        );
        try sys.writeJson(
            s,
            try sys.join(s, &.{ snapshots, "plan.json" }),
            try json.from(gpa, .{ .arch = "x86_64", .shard = 1, .targets = targets.items }),
        );
        const verified = try sys.join(
            s,
            &.{ work, if (r.flat) "verified" else "verified/verified-x86_64-1" },
        );
        const gated = try sys.join(
            s,
            &.{ work, if (r.flat) "gated" else "gated/gated-qemu-x86_64" },
        );
        const bundle_dir = try sys.join(s, &.{ gated, "bundle" });
        try p.bundle(bundle_dir, serial, "playground", nextIndex(previous, "playground"));
        const descriptor = try gpa.dupe(
            u8,
            &try sys.sha(s, try sys.join(s, &.{ bundle_dir, "boot.json" })),
        );
        var results: std.ArrayList(Json) = .empty;
        for (targets.items) |target| {
            var result = try json.parse(gpa, try json.encode(gpa, target));
            const status = try json.text(target, "status");
            try result.object.put(
                gpa,
                "status",
                .{ .string = if (mem.eql(u8, status, "build")) "passed" else status },
            );
            try results.append(gpa, result);
            if (!mem.eql(u8, status, "build")) continue;
            const name = try json.text(target, "form");
            const dir = try sys.join(s, &.{ verified, name });
            try sys.writeJson(
                s,
                try sys.join(s, &.{ dir, "packages.json" }),
                try p.inventory(name),
            );
            try sys.write(s, try sys.join(s, &.{ dir, "inputs.tar.gz" }), "locks");
            var checks: json.Map = .empty;
            for (p.t.checks) |c| try checks.put(gpa, c, .{ .bool = true });
            var tested: json.Map = .empty;
            try tested.put(gpa, "qemu", .{ .string = descriptor });
            try sys.writeJson(s, try sys.join(s, &.{ dir, "tests.json" }), try json.from(gpa, .{
                .format = "werewolf-form-tests/1",
                .form = name,
                .arch = "x86_64",
                .inputs = try json.field(target, "inputs"),
                .checks = checks,
                .bundles = tested,
            }));
        }
        try sys.writeJson(
            s,
            try sys.join(s, &.{ verified, "results.json" }),
            .{ .array = .fromOwnedSlice(gpa, results.items) },
        );
        var checks: json.Map = .empty;
        for (prepare.gates) |g| try checks.put(gpa, g, .{ .bool = true });
        try sys.writeJson(s, try sys.join(s, &.{ gated, "gates.json" }), try json.from(gpa, .{
            .format = "werewolf-boot-gates/" ++
                "1",
            .descriptor = descriptor,
            .arch = "x86_64",
            .provider = "qemu",
            .checks = checks,
        }));
        if (!r.gated) sys.remove(s, try sys.join(s, &.{ work, "gated" }));
        const listing = try sys.join(s, &.{ work, "exported.json" });
        try exportAll(
            s,
            p.t,
            p.tree,
            try sys.join(s, &.{ work, "snapshots" }),
            try sys.join(s, &.{ work, "verified" }),
            try sys.join(s, &.{ work, "gated" }),
            p.store,
            try sys.join(s, &.{ work, "assets" }),
            listing,
            null,
        );
        const failed = try publishAll(
            s,
            p.t,
            p.tree,
            try sys.join(s, &.{ work, "snapshots" }),
            try sys.join(s, &.{ work, "verified" }),
            &.{.{ .form = "playground", .provider = "qemu", .arch = "x86_64" }},
            listing,
            p.store,
            r.recovery,
            r.scope orelse p.t.forms,
        );
        return .{
            .failed = failed,
            .listing = try json.items(try sys.readJson(s, listing, 1 << 20)),
            .work = work,
        };
    }

    /// nextIndex is the release after a channel's last, as resolve plans it.
    fn nextIndex(previous: catalog.Index, name: []const u8) i64 {
        var n: i64 = 0;
        if (previous.latest(name, "qemu", "x86_64")) |l| n = @max(n, json.int(l, "index") catch 0);
        return n + 1;
    }
};

fn outputs(p: *Pipeline, name: []const u8) ![]const u8 {
    const path = p.f.path(name);
    try p.f.env.put("GITHUB_OUTPUT", path);
    return path;
}

fn latestOf(p: *Pipeline, name: []const u8, provider: []const u8, arch: []const u8) !Json {
    return (try p.rows()).latest(name, provider, arch) orelse error.TestUnpublished;
}

test "single artifact downloads publish with flat directories" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    for ([_]bool{ false, true }, 0..) |recovery, offset| {
        const serial = p.later(@intCast(offset));
        const out = try outputs(&p, try s.gpa.print("flat-outputs-{d}", .{offset}));
        const r = try p.run(&serial, .{ .recovery = recovery, .flat = true });
        // The full run includes an unresolved prod-ssh.
        try testing.expectEqual(!recovery, r.failed);
        const said = try sys.read(s, out, 1 << 20);
        try testing.expectStringStartsWith(said, "targets=1\nreleased=true\npublic_targets=0\n");
        try testing.expect(mem.find(u8, said, "smoke={\"include\": []}") != null);
        try testing.expectEqual(@as(usize, 1), r.listing.len);
        try testing.expectEqualStrings("playground", try json.text(r.listing[0], "form"));
        const row = (try p.rows()).row("playground", "qemu", "x86_64").?;
        try testing.expectEqualStrings(catalog.published, try json.text(row, "status"));
        const latest = json.get(row, "latest").?;
        try testing.expectEqualStrings(&serial, try json.text(latest, "serial"));
        try testing.expect(sys.isFile(
            s,
            p.f.path(try s.gpa.print("store/{s}/disk.qcow2", .{try json.text(latest, "object")})),
        ));
    }
}

test "missing plans fail before the catalog changes" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const listing = p.f.path("exported.json");
    try sys.writeJson(s, listing, .{ .array = .init(s.gpa) });
    try testing.expectError(
        error.Refused,
        publishAll(
            s,
            p.t,
            p.tree,
            p.f.path("snapshots"),
            p.f.path("verified"),
            &.{},
            listing,
            p.store,
            true,
            p.t.forms,
        ),
    );
    try testing.expectStringStartsWith(s.why.text, "form image plans are missing");
    try testing.expect(!sys.exists(s, p.f.path("store")));
}

test "unlisted profiles and forms, and an unrelated focused legacy target, never publish" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    try sys.writeJson(
        s,
        p.f.path("snapshots/plan.json"),
        try json.parse(
            s.gpa,
            "{\"arch\":\"x86_64\",\"shard\":1,\"targets\":[{\"form\":\"playground\",\"arch\":\"x" ++
                "86_64\"}]}",
        ),
    );
    try sys.writeJson(s, p.f.path("verified/results.json"), .{ .array = .init(s.gpa) });
    const listing = p.f.path("exported.json");
    for ([_][]const u8{
        "{\"form\":\"prod\",\"arch\":\"x86_64\",\"boot_profile\":\"legacy-boot\"}",
        "{\"form\":\"playground\",\"arch\":\"x86_64\",\"boot_profile\":\"unknown\"}",
        "{\"form\":\"minimal\",\"arch\":\"x86_64\",\"boot_profile\":\"legacy-boot\"}",
    }) |target| {
        try sys.write(s, listing, try s.gpa.print("[{s}]", .{target}));
        try testing.expectError(
            error.Refused,
            publishAll(
                s,
                p.t,
                p.tree,
                p.f.path("snapshots"),
                p.f.path("verified"),
                &.{},
                listing,
                p.store,
                true,
                p.t.forms,
            ),
        );
        try testing.expect(!sys.exists(s, p.f.path("store")));
    }
}

test "mixed artifact layouts are refused" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    try sys.writeJson(s, f.path("snapshots/plan.json"), .{ .object = .empty });
    try sys.writeJson(s, f.path("snapshots/inputs-x86_64-1/plan.json"), .{ .object = .empty });
    try testing.expectError(error.Refused, plans(s, f.path("snapshots")));
    try testing.expectEqualStrings("mixed flat and named form image artifacts", s.why.text);
}

test "a gated target publishes and every target is cataloged" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const out = try outputs(&p, "outputs");
    const r = try p.run(&p.serial, .{});
    try testing.expect(r.failed); // prod-ssh did not resolve
    const said = try sys.read(s, out, 1 << 20);
    try testing.expectStringStartsWith(said, "targets=1\nreleased=true\npublic_targets=0\n");
    try testing.expectEqual(@as(usize, 1), r.listing.len);
    const rows = try p.rows();
    const published = rows.row("playground", "qemu", "x86_64").?;
    try testing.expectEqualStrings(catalog.published, try json.text(published, "status"));
    const latest = json.get(published, "latest").?;
    try testing.expectEqualStrings(&p.serial, try json.text(latest, "serial"));
    try testing.expectEqual(@as(i64, 1), try json.int(latest, "index"));
    try testing.expectEqualStrings(
        catalog.no_runner,
        try json.text(rows.row("minimal", "qemu", "x86_64").?, "status"),
    );
    try testing.expect(json.get(rows.row("minimal", "qemu", "x86_64").?, "latest") == null);
    try testing.expectEqualStrings(
        "resolution failed",
        try json.text(rows.row("prod-ssh", "qemu", "x86_64").?, "status"),
    );
    try testing.expectEqualStrings(
        "unsupported architecture",
        try json.text(rows.row("minimal", "lima", "aarch64").?, "status"),
    );
    const objects = p.f.path(try s.gpa.print("store/{s}", .{try json.text(latest, "object")}));
    const head = try sys.read(s, try sys.join(s, &.{ objects, "downloads.json" }), 1 << 20);
    try catalog.verify(
        s,
        head,
        try sys.read(s, try sys.join(s, &.{ objects, "downloads.json.sig" }), 512),
        p.keys.crt,
    );
    const signed = try json.parse(s.gpa, head);
    var names: std.ArrayList([]const u8) = .empty;
    try names.appendSlice(s.gpa, &exporter.extras);
    try names.appendSlice(s.gpa, &.{ "disk.qcow2", "gates.json", "boot.json" });
    for (names.items) |name| try testing.expectEqualStrings(
        try json.text(json.get(json.get(signed, "files").?, name).?, "sha256"),
        &try sys.sha(s, try sys.join(s, &.{ objects, name })),
    );
    try testing.expect(mem.find(
        u8,
        try sys.read(s, try sys.join(s, &.{ objects, "release-notes.html" }), 1 << 20),
        "Initial published image",
    ) != null);
    try testing.expect(sys.exists(s, p.f.path("store/playground/qemu/x86_64/latest/boot.json")));
    try testing.expect(sys.exists(s, p.f.path("store/minimal/index.html")));
    try testing.expect(mem.find(
        u8,
        try sys.read(s, p.f.path("store/index.html"), 1 << 20),
        "playground/qemu/x86_64/objects/",
    ) != null);
}

test "a retry reuses signed exports and keeps immutable objects" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const r = try p.run(&p.serial, .{ .recovery = true });
    try testing.expect(!r.failed);
    const objects = p.f.path(try s.gpa.print(
        "store/{s}",
        .{try json.text(try latestOf(&p, "playground", "qemu", "x86_64"), "object")},
    ));
    var before: std.ArrayList([]const u8) = .empty;
    for (try sys.list(
        s,
        objects,
    )) |name| try before.append(
        s.gpa,
        try s.gpa.dupe(u8, &try sys.sha(s, try sys.join(s, &.{ objects, name }))),
    );
    try p.f.env.put("GITHUB_RUN_ATTEMPT", "2");
    const exported = try sys.join(s, &.{ r.work, "retry.json" });
    try exportAll(
        s,
        p.t,
        p.tree,
        try sys.join(s, &.{ r.work, "snapshots" }),
        try sys.join(s, &.{ r.work, "verified" }),
        try sys.join(s, &.{ r.work, "gated" }),
        p.store,
        try sys.join(s, &.{ r.work, "retry-assets" }),
        exported,
        null,
    );
    try testing.expect(!try publishAll(
        s,
        p.t,
        p.tree,
        try sys.join(s, &.{ r.work, "snapshots" }),
        try sys.join(s, &.{ r.work, "verified" }),
        &.{.{ .form = "playground", .provider = "qemu", .arch = "x86_64" }},
        exported,
        p.store,
        true,
        p.t.forms,
    ));
    const retried = try json.items(try sys.readJson(s, exported, 1 << 20));
    try testing.expectEqual(@as(usize, 1), retried.len);
    for (try sys.list(
        s,
        objects,
    ), before.items) |name, digest| try testing.expectEqualStrings(
        digest,
        &try sys.sha(s, try sys.join(s, &.{ objects, name })),
    );
    // A new export would carry this attempt; the reused one keeps the first.
    const signed = try sys.readJson(
        s,
        try sys.join(
            s,
            &.{ try json.text(retried[0], "assets"), "playground-qemu-x86_64-downloads.json" },
        ),
        1 << 20,
    );
    try testing.expectEqualStrings("1", try json.text(json.get(signed, "provenance").?, "attempt"));
}

test "a retry refuses damaged signed exports" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const r = try p.run(&p.serial, .{ .recovery = true });
    const objects = p.f.path(try s.gpa.print(
        "store/{s}",
        .{try json.text(try latestOf(&p, "playground", "qemu", "x86_64"), "object")},
    ));
    try p.f.env.put("GITHUB_RUN_ATTEMPT", "2");
    for ([_][]const u8{ "downloads.json.sig", "packages.json" }) |name| {
        const path = try sys.join(s, &.{ objects, name });
        const original = try sys.read(s, path, 1 << 20);
        try sys.write(s, path, "corrupted");
        defer sys.write(s, path, original) catch {};
        const listing = try sys.join(s, &.{ r.work, "retry.json" });
        try exportAll(
            s,
            p.t,
            p.tree,
            try sys.join(s, &.{ r.work, "snapshots" }),
            try sys.join(s, &.{ r.work, "verified" }),
            try sys.join(s, &.{ r.work, "gated" }),
            p.store,
            try sys.join(s, &.{ r.work, try s.gpa.print("retry-{s}", .{name}) }),
            listing,
            null,
        );
        try testing.expectEqual(
            @as(usize, 0),
            (try json.items(try sys.readJson(s, listing, 1 << 20))).len,
        );
    }
}

test "release notes compare with the target's last publication" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    _ = try p.run(&p.serial, .{});
    const previous = try latestOf(&p, "playground", "qemu", "x86_64");
    try p.packages.items[0].object.put(s.gpa, "version", .{ .string = "1.38-r0" });
    try p.packages.items[0].object.put(s.gpa, "checksum", .{ .string = fixture.rep('1', 64) });
    _ = p.packages.orderedRemove(1);
    const later = p.later(5);
    _ = try p.run(&later, .{ .statuses = &.{.{ "minimal", "unchanged" }} });
    const rows = try p.rows();
    const latest = rows.latest("playground", "qemu", "x86_64").?;
    try testing.expectEqualStrings(&later, try json.text(latest, "serial"));
    try testing.expectEqual(try json.int(previous, "index") + 1, try json.int(latest, "index"));
    const object = p.f.path(try s.gpa.print("store/{s}", .{try json.text(latest, "object")}));
    const release = try sys.readJson(
        s,
        try sys.join(s, &.{ object, "release-notes.json" }),
        1 << 20,
    );
    for ([_][]const u8{ "serial", "commit", "object" }) |k|
        try testing.expect(json.eql(
            json.get(previous, k).?,
            json.get(json.get(release, "previous").?, k).?,
        ));
    const changes = try json.items(json.get(release, "packages").?);
    try testing.expectEqual(@as(usize, 2), changes.len);
    try testing.expectEqualStrings("busybox", try json.text(changes[0], "name"));
    try testing.expectEqualStrings("updated", try json.text(changes[0], "kind"));
    try testing.expectEqualStrings("removed", try json.text(changes[1], "name"));
    try testing.expectEqualStrings("removed", try json.text(changes[1], "kind"));
    const html = try sys.read(s, try sys.join(s, &.{ object, "release-notes.html" }), 1 << 20);
    try testing.expect(mem.find(
        u8,
        html,
        try s.gpa.print(
            "href=\"../{s}/release-notes.html\"",
            .{try json.text(previous, "descriptor")},
        ),
    ) != null);
    // An unchanged target keeps its settled status and the inputs it settled on.
    try testing.expectEqualStrings(
        catalog.no_runner,
        try json.text(rows.row("minimal", "qemu", "x86_64").?, "status"),
    );
    try testing.expectEqualStrings(
        &sha256("minimal"),
        try json.text(rows.row("minimal", "qemu", "x86_64").?, "inputs"),
    );
}

test "a target without gates keeps its previous release" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    _ = try p.run(&p.serial, .{});
    const previous = try latestOf(&p, "playground", "qemu", "x86_64");
    const later = p.later(5);
    const r = try p.run(&later, .{ .gated = false });
    try testing.expect(r.failed);
    try testing.expectEqual(@as(usize, 0), r.listing.len);
    const row = (try p.rows()).row("playground", "qemu", "x86_64").?;
    try testing.expectEqualStrings(
        "lifecycle gates or export failed",
        try json.text(row, "status"),
    );
    try testing.expect(json.eql(previous, json.get(row, "latest").?));
}

test "focused publication keeps allowed rows and retires unlisted forms" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    _ = try p.run(&p.serial, .{});
    var previous: std.ArrayList(Json) = .empty;
    try previous.appendSlice(s.gpa, (try p.rows()).rows);
    // Keep other targets of allowed forms without relabeling their health,
    // and drop forms retired from the publication allowlist.
    try previous.append(
        s.gpa,
        try json.from(
            s.gpa,
            .{
                .form = "retired-form",
                .provider = "qemu",
                .arch = "aarch64",
                .status = "tests failed",
                .inputs = fixture.rep('a', 64),
            },
        ),
    );
    for (previous.items) |*row| {
        if (!mem.eql(u8, try json.text(row.*, "form"), "playground") or
            !mem.eql(u8, try json.text(row.*, "provider"), "lima")) continue;
        try row.object.put(s.gpa, "status", .{ .string = catalog.published });
        try row.object.put(s.gpa, "inputs", .{ .string = fixture.rep('c', 64) });
        try row.object.put(s.gpa, "latest", try json.from(s.gpa, .{
            .serial = &p.serial,
            .commit = fixture.rep(
                'b',
                40,
            ),
            .descriptor = fixture.rep('d', 64),
            .size = 123,
            .object = "playground/lima/aarch64/objects/" ++ fixture.rep('d', 64),
        }));
    }
    try sys.write(
        s,
        p.f.path("store/index.json"),
        try catalog.envelope(
            s,
            try json.from(s.gpa, .{ .format = catalog.format, .forms = previous.items }),
            p.keys.key,
        ),
    );
    const later = p.later(5);
    const r = try p.run(&later, .{ .recovery = true });
    try testing.expect(!r.failed); // Existing prod-ssh and retired-form failures are unrelated.
    try testing.expectEqual(@as(usize, 1), r.listing.len);
    const rows = try p.rows();
    var kept: usize = 0;
    for (previous.items) |row| {
        const name = try json.text(row, "form");
        const provider = try json.text(row, "provider");
        const arch = try json.text(row, "arch");
        if (!p.t.hasForm(name)) {
            try testing.expect(rows.row(name, provider, arch) == null);
            continue;
        }
        kept += 1;
        if (!p.t.isFocused(
            name,
            provider,
            arch,
        )) try testing.expect(json.eql(row, rows.row(name, provider, arch).?));
    }
    try testing.expectEqual(kept, rows.rows.len);
    try testing.expectEqualStrings(
        &later,
        try json.text(rows.latest("playground", "qemu", "x86_64").?, "serial"),
    );
}

test "failed focused gates keep the last release and report failure" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    _ = try p.run(&p.serial, .{ .recovery = true });
    const previous = try latestOf(&p, "playground", "qemu", "x86_64");
    const later = p.later(5);
    const r = try p.run(&later, .{ .recovery = true, .gated = false });
    try testing.expect(r.failed);
    try testing.expectEqual(@as(usize, 0), r.listing.len);
    const row = (try p.rows()).row("playground", "qemu", "x86_64").?;
    try testing.expectEqualStrings(
        "lifecycle gates or export failed",
        try json.text(row, "status"),
    );
    try testing.expect(json.eql(previous, json.get(row, "latest").?));
}

test "a focused publisher refuses unrelated plans before uploading" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const r = try p.run(&p.serial, .{});
    const before = try sys.walk(s, p.f.path("store"));
    try testing.expectError(
        error.Refused,
        publishAll(
            s,
            p.t,
            p.tree,
            try sys.join(s, &.{ r.work, "snapshots" }),
            try sys.join(s, &.{ r.work, "verified" }),
            &.{},
            try sys.join(s, &.{ r.work, "exported.json" }),
            p.store,
            true,
            p.t.forms,
        ),
    );
    try testing.expectEqualStrings("focused publication contains an unrelated target", s.why.text);
    try testing.expectEqual(before.len, (try sys.walk(s, p.f.path("store"))).len);
}

test "the previous inventory must match its signed digest" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    _ = try p.run(&p.serial, .{});
    const latest = try latestOf(&p, "playground", "qemu", "x86_64");
    try sys.write(
        s,
        p.f.path(try s.gpa.print("store/{s}/packages.json", .{try json.text(latest, "object")})),
        "changed",
    );
    try sys.mkdirs(s, p.f.path("work"));
    try testing.expectError(error.Refused, inventory(s, p.tree, p.store, latest, p.f.path("work")));
    try testing.expectEqualStrings(
        "previous release package inventory is missing or changed",
        s.why.text,
    );
}

test "a gated bundle must be the verified build" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const gpa = s.gpa;
    const target = try json.from(
        gpa,
        .{
            .form = "playground",
            .arch = "x86_64",
            .status = "build",
            .inputs = try gpa.dupe(u8, &sha256("playground")),
            .commit = fixture.rep('b', 40),
            .serial = &p.serial,
        },
    );
    try sys.writeJson(
        s,
        p.f.path("tampered/snapshots/inputs-x86_64-1/plan.json"),
        try json.from(gpa, .{ .arch = "x86_64", .shard = 1, .targets = &[_]Json{target} }),
    );
    try p.bundle(p.f.path("tampered/gated/gated-qemu-x86_64/bundle"), &p.serial, "playground", 1);
    var passed = try json.parse(gpa, try json.encode(gpa, target));
    try passed.object.put(gpa, "status", .{ .string = "passed" });
    try sys.writeJson(
        s,
        p.f.path("tampered/verified/verified-x86_64-1/results.json"),
        try json.from(gpa, &[_]Json{passed}),
    );
    var checks: json.Map = .empty;
    for (p.t.checks) |c| try checks.put(gpa, c, .{ .bool = true });
    var tested: json.Map = .empty;
    try tested.put(gpa, "qemu", .{ .string = fixture.rep('f', 64) });
    try sys.writeJson(s, p.f.path(
        "tampered/verified/verified-x86_64-1/playground/tests.json",
    ), try json.from(gpa, .{
        .format = "werewolf-form-tests/1",
        .form = "playground",
        .arch = "x86_64",
        .inputs = try gpa.dupe(
            u8,
            &sha256("playground"),
        ),
        .checks = checks,
        .bundles = tested,
    }));
    try sys.writeJson(
        s,
        p.f.path("tampered/gated/gated-qemu-x86_64/gates.json"),
        try json.parse(gpa, "{\"format\":\"werewolf-boot-gates/1\",\"provider\":\"qemu\"}"),
    );
    try exportAll(
        s,
        p.t,
        p.tree,
        p.f.path("tampered/snapshots"),
        p.f.path("tampered/verified"),
        p.f.path("tampered/gated"),
        p.store,
        p.f.path("tampered/assets"),
        p.f.path("tampered/listing.json"),
        null,
    );
    try testing.expectEqual(
        @as(usize, 0),
        (try json.items(try sys.readJson(s, p.f.path("tampered/listing.json"), 4096))).len,
    );
    try testing.expectEqual(@as(usize, 0), (try sys.list(s, p.f.path("tampered/assets"))).len);
}

test "the base lane keeps other forms' heads and failures" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    _ = try p.run(&p.serial, .{});
    const previous = try p.rows();
    const later = p.later(1);
    _ = try p.run(&later, .{ .only = &.{"playground"}, .scope = &.{"playground"} });
    const current = try p.rows();
    for (previous.rows) |row| {
        const name = try json.text(row, "form");
        if (mem.eql(u8, name, "playground")) continue;
        try testing.expect(json.eql(
            row,
            current.row(name, try json.text(row, "provider"), try json.text(row, "arch")).?,
        ));
    }
    try testing.expectEqualStrings(
        &later,
        try json.text(current.latest("playground", "qemu", "x86_64").?, "serial"),
    );
}

test "public checks select only newly published QEMU targets" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const groups = try json.parse(s.gpa,
        \\{"include":[{"forms":["minimal","prod-ssh"],"provider":"qemu","arch":"x86_64","runner":["linux"]},
        \\{"forms":["playground"],"provider":"lima","arch":"aarch64","runner":["mac"]}]}
    );
    const published = [_]Published{
        .{
            .name = "minimal/qemu/x86_64",
            .latest = try json.from(s.gpa, .{ .descriptor = fixture.rep('a', 64) }),
        },
        .{
            .name = "playground/lima/aarch64",
            .latest = try json.from(s.gpa, .{ .descriptor = fixture.rep('b', 64) }),
        },
    };
    const smoke = try publicMatrix(s, try images.load(s), &published, groups);
    try testing.expectEqualStrings(
        "{\"include\": [{\"runner\": [\"linux\"], \"targets\": [{\"form\": \"minimal\", " ++
            "\"provider\": \"qemu\", \"arch\": \"x86_64\", \"descriptor\": \"" ++ fixture.rep(
            'a',
            64,
        ) ++ "\"}]}]}",
        try json.dumps(s.gpa, smoke),
    );
}

test "the GitHub release waits for the public catalog to finish" {
    var p: Pipeline = undefined;
    try p.init();
    defer p.deinit();
    const s = &p.f.s;
    const out = try outputs(&p, "outputs");
    // A directory where the catalog page's upload lands fails that upload.
    try sys.mkdirs(s, p.f.path("store/index.html.new"));
    try testing.expectError(error.IsDir, p.run(&p.serial, .{}));
    try testing.expect(mem.find(u8, try sys.read(s, out, 1 << 20), "released=true") == null);
}
