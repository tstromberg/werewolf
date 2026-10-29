//! github creates one draft GitHub release carrying the exact signed
//! assets exported for R2, both boot profiles, of one workflow run. It
//! becomes public only after the public mirror matches.

const std = @import("std");
const mem = std.mem;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const images = @import("images.zig");
const catalog = @import("catalog.zig");
const boot = @import("boot.zig");
const exporter = @import("exporter.zig");
const legacy = @import("legacy.zig");

/// Secure is one exported secure-boot bundle.
pub const Secure = struct {
    assets: []const u8,
    bundle: []const u8,
    report: Json,
    provider: []const u8,
    variants: []const u8 = "",
};

pub const Legacy = struct { assets: []const u8, variants: []const u8 = "" };

/// draft verifies every export and creates the draft release with gh; it
/// returns the tag. now names a retry's tag: published releases are
/// immutable, so a retry gets a fresh one and the image serials stay.
pub fn draft(
    s: *Sys,
    t: images.Images,
    targets: []const Secure,
    trust: []const u8,
    legacy_assets: []const Legacy,
    now: i64,
) ![]const u8 {
    var manifests: std.ArrayList(Json) = .empty;
    var assets: std.ArrayList([]const u8) = .empty;
    var lines: std.ArrayList([]const u8) = .empty;
    const sha = s.getenv("GITHUB_SHA") orelse "";
    const repository = s.getenv("GITHUB_REPOSITORY") orelse "";
    const saved_variants = s.variants;
    defer s.variants = saved_variants;
    for (targets) |target| {
        s.variants = target.variants;
        const directory = try sys.resolve(s, target.assets);
        const manifest = try exporter.verify(
            s,
            directory,
            target.bundle,
            target.report,
            target.provider,
            trust,
        );
        const name = try json.text(manifest, "form");
        if (!t.identity(
            name,
            try json.text(manifest, "arch"),
            "secure-boot",
        )) return s.refuse("unsupported published image identity", .{});
        const provenance = try json.field(manifest, "provenance");
        if (!mem.eql(u8, try json.text(provenance, "commit"), sha) or
            !mem.eql(u8, try json.text(provenance, "repository"), repository))
            return s.refuse("release provenance differs from this workflow", .{});
        if (!catalog.isSerial(try json.text(
            manifest,
            "serial",
        ))) return s.refuse("invalid protected release serial", .{});
        try manifests.append(s.gpa, manifest);
        if (t.hasForm(name)) for (try sys.list(
            s,
            directory,
        )) |f| try assets.append(s.gpa, try sys.join(s, &.{ directory, f }));
        const prefix = try s.gpa.print(
            "{s}-{s}-{s}",
            .{
                try s.variantKey(name),
                try json.text(manifest, "provider"),
                try json.text(manifest, "arch"),
            },
        );
        const mirror = try s.gpa.print("https://dist.werewolf-linux.org/boot/v1/{s}/{s}/{s}/obje" ++
            "cts/{s}", .{
            try s.variantPath(name),
            try json.text(
                manifest,
                "provider",
            ),
            try json.text(manifest, "arch"),
            try json.text(manifest, "descriptor"),
        });
        try lines.append(s.gpa, try s.gpa.print("- `{s}`, serial {s}: [R2 " ++
            "bundle]({s}/boot.json), [package changes]({s}/release-notes.html), " ++
            "evidence `{s}-gates.json`, manifest `{s}-downloads.json`.", .{
            prefix,
            try json.text(manifest, "serial"),
            mirror,
            mirror,
            prefix,
            prefix,
        }));
    }
    const public = try catalog.public(s);
    var legacy_lines: std.ArrayList([]const u8) = .empty;
    for (legacy_assets) |target| {
        s.variants = target.variants;
        const directory = target.assets;
        const manifest = try legacy.verify(
            s,
            t,
            directory,
            try sys.join(s, &.{ trust, "image.crt" }),
        );
        if (!sys.selectionMatches(manifest, s.variants))
            return s.refuse("legacy release describes another variant selection", .{});
        const provenance = try json.field(manifest, "provenance");
        if (!mem.eql(u8, try json.text(provenance, "commit"), sha) or
            !mem.eql(u8, try json.text(provenance, "repository"), repository))
            return s.refuse("legacy release provenance differs from this workflow", .{});
        try manifests.append(s.gpa, manifest);
        const name = try json.text(manifest, "form");
        const arch = try json.text(manifest, "arch");
        if (t.hasForm(name)) for (try sys.list(
            s,
            directory,
        )) |f| try assets.append(s.gpa, try sys.join(s, &.{ directory, f }));
        var changes: []const u8 = "";
        if (json.get(try json.field(manifest, "files"), "release-notes.html")) |page| {
            const head = try sys.join(
                s,
                &.{
                    directory,
                    try s.gpa.print(
                        "{s}-{s}-legacy-boot-downloads.json",
                        .{ try s.variantKey(name), arch },
                    ),
                },
            );
            changes = try s.gpa.print(" [Package changes]({s}/legacy-boot/{s}/{s}/objects/{s}/{s" ++
                "}).", .{
                public,                       try s.variantKey(name), arch,
                &try sys.sha(
                    s,
                    head,
                ),
                try json.text(page, "asset"),
            });
        }
        try legacy_lines.append(s.gpa, try s.gpa.print("- `{s}-{s}-legacy-boot`, serial {s}: " ++
            "boots without Secure Boot, TPM or IPE.{s}", .{
            try s.variantKey(name), arch, try json.text(manifest, "serial"), changes,
        }));
    }
    // Lines list the bundles in the order Python wrote them: secure, then legacy.
    try lines.appendSlice(s.gpa, legacy_lines.items);
    if (manifests.items.len == 0) return s.refuse(
        "a release carries the bundles of one workflow run",
        .{},
    );
    const run = try json.text(try json.field(manifests.items[0], "provenance"), "run");
    var serial = try json.text(manifests.items[0], "serial");
    for (manifests.items) |m| {
        if (!mem.eql(
            u8,
            try json.text(try json.field(m, "provenance"), "run"),
            run,
        )) return s.refuse("a release carries the bundles of one workflow run", .{});
        const this = try json.text(m, "serial");
        if (mem.order(u8, this, serial) == .gt) serial = this;
    }
    const attempt = std.fmt.parseInt(
        i64,
        s.getenv("GITHUB_RUN_ATTEMPT") orelse "1",
        10,
    ) catch return s.refuse("invalid GITHUB_RUN_ATTEMPT", .{});
    if (attempt > 1) serial = try s.gpa.dupe(u8, &sys.serial(now));
    const tag = try s.gpa.print("base-images-{s}", .{serial});
    const commit = try json.text(try json.field(manifests.items[0], "provenance"), "commit");
    var listed: std.ArrayList(u8) = .empty;
    for (t.forms, 0..) |f, i| try listed.print(s.gpa, "{s}`{s}`", .{ if (i > 0) ", " else "", f });
    const body = try s.gpa.print("Base images built from {s} in [GitHub " ++
        "Actions]({s}).\n\n{s}\n\n" ++
        "Changed images ({s}) are attached here and listed in " ++
        "[the R2 catalog](https://dist.werewolf-linux.org/boot/v1/index.html). " ++
        "Each attached boot/image manifest and detached signature is byte-identical to its R2 " ++
        "bundle. " ++
        "Each standalone qcow2 has the same disk contents as the authenticated compressed raw " ++
        "disk; " ++
        "its size and SHA-256 are covered by the target's downloads manifest and RSA/SHA-256 " ++
        "signature.\n\n" ++
        "Secure-boot targets passed all twelve exact-bundle lifecycle gates and require " ++
        "Secure Boot with the matching certificate and a TPM, which their first boot takes. " ++
        "They update from the public mirror themselves. Legacy-boot targets " ++
        "passed independent-build comparison, integration and package-update tests, and " ++
        "exact-image UEFI/direct boots " ++
        "without Secure Boot or TPM. Their signed manifests identify the boot profile.\n\n" ++
        "Verify each download manifest against the committed `release/protected/image.crt`, " ++
        "then check asset digests. GitHub build provenance attestations also cover every " ++
        "asset.\n", .{
        commit, run, try mem.join(s.gpa, "\n", lines.items), listed.items,
    });
    const work = try sys.scratch(s, null, "ww-github-release-");
    defer sys.remove(s, work);
    const notes_file = try sys.join(s, &.{ work, "notes.md" });
    try sys.write(s, notes_file, body);
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(s.gpa, &.{
        "gh",
        "release",
        "create",
        tag,
        "--draft",
        "--generate-notes",
        "--target",
        commit,
        "--title",
        try s.gpa.print("Base images {s}", .{serial}),
        "--notes-file",
        notes_file,
    });
    try argv.appendSlice(s.gpa, assets.items);
    try sys.run(s, argv.items, .{});
    const output = s.getenv("GITHUB_OUTPUT") orelse return s.refuse(
        "GITHUB_OUTPUT is required",
        .{},
    );
    const f = try std.Io.Dir.cwd().createFile(s.io, output, .{ .truncate = false });
    defer f.close(s.io);
    try f.writePositionalAll(s.io, try s.gpa.print("tag={s}\n", .{tag}), (try f.stat(s.io)).size);
    return tag;
}

/// fromListing drafts the release of an exported.json listing.
pub fn fromListing(s: *Sys, t: images.Images, listing: []const u8) ![]const u8 {
    return fromListingAt(s, t, listing, "release/protected");
}

fn fromListingAt(s: *Sys, t: images.Images, listing: []const u8, trust: []const u8) ![]const u8 {
    var secure: std.ArrayList(Secure) = .empty;
    var legacy_assets: std.ArrayList(Legacy) = .empty;
    for (try json.items(try sys.readJson(s, listing, 16 << 20))) |target| {
        const profile = if (json.get(target, "boot_profile")) |p| p.string else "secure-boot";
        if (!t.identity(
            try json.text(target, "form"),
            try json.text(target, "arch"),
            profile,
        )) return s.refuse("unsupported published image identity", .{});
        if (mem.eql(u8, profile, "secure-boot")) try secure.append(s.gpa, .{
            .assets = try json.text(target, "assets"),
            .bundle = try json.text(target, "bundle"),
            .report = try sys.readJson(s, try json.text(target, "gates"), 64 << 10),
            .provider = try json.text(target, "provider"),
            .variants = try sys.selection(s, target),
        });
        if (mem.eql(
            u8,
            profile,
            "legacy-boot",
        )) try legacy_assets.append(s.gpa, .{
            .assets = try json.text(target, "assets"),
            .variants = try sys.selection(s, target),
        });
    }
    return draft(s, t, secure.items, trust, legacy_assets.items, s.now());
}

const testing = std.testing;
const fixture = @import("fixture.zig");

fn gh(f: *fixture.Fixture, argv: []const []const u8) anyerror!?sys.Result {
    if (!mem.eql(u8, argv[0], "gh")) return fixture.admit(f, argv);
    // A published release is immutable: the same tag twice refuses.
    for (f.calls.items) |old| if (mem.eql(u8, old[0], "gh") and mem.eql(u8, old[3], argv[3]))
        return .{ .term = .{ .exited = 1 }, .stderr = "immutable release" };
    f.text = try sys.read(&f.s, argv[argIndex(argv, "--notes-file") + 1], 1 << 20);
    return sys.Result.passed;
}

fn argIndex(argv: []const []const u8, word: []const u8) usize {
    for (argv, 0..) |a, i| if (mem.eql(u8, a, word)) return i;
    return argv.len;
}

test "a draft carries every asset and the workflow's exact commit" {
    var e: exporter.Exported = undefined;
    try e.init();
    defer e.deinit();
    const s = &e.f.s;
    const t = try images.load(s);
    const copied = try e.copy("copy");
    try e.f.env.put("GITHUB_OUTPUT", e.f.path("outputs"));
    e.f.answer = struct {
        fn answer(f: *fixture.Fixture, argv: []const []const u8) anyerror!?sys.Result {
            if (!mem.eql(u8, argv[0], "gh")) return fixture.admit(f, argv);
            return sys.Result.passed;
        }
    }.answer;
    const tag = try draft(
        s,
        t,
        &.{.{ .assets = copied, .bundle = e.bundle, .report = e.report, .provider = "qemu" }},
        e.trust,
        &.{},
        s.now(),
    );
    const argv = e.f.calls.items[e.f.calls.items.len - 1];
    try testing.expect(argIndex(argv, "--draft") < argv.len);
    try testing.expectEqualStrings(fixture.rep('a', 40), argv[argIndex(argv, "--target") + 1]);
    const present = try sys.list(s, copied);
    for (present, argv[argv.len - present.len ..]) |name, arg| try testing.expectEqualStrings(
        try sys.join(s, &.{ try sys.resolve(s, copied), name }),
        arg,
    );
    const head = try sys.readJson(s, try sys.join(s, &.{ e.bundle, "boot.json" }), 4096);
    try testing.expectEqualStrings(
        try s.gpa.print("base-images-{s}", .{try json.text(json.get(head, "image").?, "serial")}),
        tag,
    );
    try testing.expectEqualStrings(
        try s.gpa.print("tag={s}\n", .{tag}),
        try sys.read(s, e.f.path("outputs"), 4096),
    );
}

test "a draft never uploads extra or tampered files, nor another run's" {
    var e: exporter.Exported = undefined;
    try e.init();
    defer e.deinit();
    const s = &e.f.s;
    const t = try images.load(s);
    const copied = try e.copy("copy");
    try sys.write(s, try sys.join(s, &.{ copied, "private.key" }), "must never upload");
    e.f.answer = gh;
    try testing.expectError(
        error.Refused,
        draft(
            s,
            t,
            &.{.{ .assets = copied, .bundle = e.bundle, .report = e.report, .provider = "qemu" }},
            e.trust,
            &.{},
            s.now(),
        ),
    );
    try testing.expectEqualStrings("unexpected files in protected release export", s.why.text);
    try testing.expectError(error.Refused, draft(s, t, &.{}, e.trust, &.{}, s.now()));
    try testing.expectEqualStrings("a release carries the bundles of one workflow run", s.why.text);
    try testing.expectEqual(@as(usize, 0), e.f.called(&.{"gh"}));
}

test "a retry keeps the signed images and takes a fresh release tag" {
    var e: exporter.Exported = undefined;
    try e.init();
    defer e.deinit();
    const s = &e.f.s;
    const t = try images.load(s);
    const copied = try e.copy("copy");
    var before: std.ArrayList([]const u8) = .empty;
    for (try sys.list(
        s,
        copied,
    )) |n| try before.append(s.gpa, try sys.read(s, try sys.join(s, &.{ copied, n }), 64 << 20));
    try e.f.env.put("GITHUB_OUTPUT", e.f.path("outputs"));
    e.f.answer = gh;
    const target: Secure = .{
        .assets = copied,
        .bundle = e.bundle,
        .report = e.report,
        .provider = "qemu",
    };
    const first = try draft(s, t, &.{target}, e.trust, &.{}, s.now());
    try e.f.env.put("GITHUB_RUN_ATTEMPT", "2");
    const head = try sys.readJson(s, try sys.join(s, &.{ e.bundle, "boot.json" }), 4096);
    const later = sys.serialTime(try json.text(json.get(head, "image").?, "serial")).? + 1;
    const second = try draft(s, t, &.{target}, e.trust, &.{}, later);
    try testing.expect(!mem.eql(u8, first, second));
    try testing.expectEqual(@as(usize, 2), e.f.called(&.{"gh"}));
    for (try sys.list(
        s,
        copied,
    ), before.items) |n, bytes| try testing.expectEqualStrings(
        bytes,
        try sys.read(s, try sys.join(s, &.{ copied, n }), 64 << 20),
    );
}

test "one GitHub release carries both boot profiles" {
    var e: exporter.Exported = undefined;
    try e.init();
    defer e.deinit();
    const s = &e.f.s;
    const t = try images.load(s);
    const dir = try legacy.testCandidate(&e.f, "minimal", "20261017T010000Z", "1");
    const legacy_exported = try legacy.exportVerified(
        s,
        t,
        std.fs.path.dirname(dir).?,
        e.f.path("legacy-assets"),
        try exporter.provenance(s),
        try legacy.testTargets(s, dir, "build"),
        e.keys.crt,
        null,
    );
    const legacy_assets = try json.text(legacy_exported[0], "assets");
    try e.f.env.put("GITHUB_OUTPUT", e.f.path("outputs"));
    e.f.answer = gh;
    _ = try draft(
        s,
        t,
        &.{.{
            .assets = try e.copy("secure"),
            .bundle = e.bundle,
            .report = e.report,
            .provider = "qemu",
        }},
        e.trust,
        &.{.{ .assets = legacy_assets }},
        s.now(),
    );
    try testing.expectEqual(@as(usize, 1), e.f.called(&.{"gh"}));
    const argv = e.f.calls.items[e.f.calls.items.len - 1];
    try testing.expect(argIndex(
        argv,
        try sys.join(
            s,
            &.{
                try sys.resolve(s, e.f.path("secure")),
                "playground-qemu-x86_64-secure-boot.qcow2",
            },
        ),
    ) < argv.len);
    try testing.expect(argIndex(
        argv,
        try sys.join(s, &.{ legacy_assets, "minimal-x86_64-legacy-boot.qcow2" }),
    ) < argv.len);
    try testing.expect(argIndex(argv, "--generate-notes") < argv.len);
    try testing.expect(mem.find(u8, e.f.text, "/release-notes.html") != null);
    try testing.expect(mem.find(u8, e.f.text, "-legacy-boot-release-notes.html") != null);
    try testing.expect(mem.find(
        u8,
        e.f.text,
        "(`minimal`, `prod-ssh`, `playground`, `postdoc-server`)",
    ) != null);
}

test "one GitHub release verifies default and SSH variants together" {
    var e: exporter.Exported = undefined;
    try e.init();
    defer e.deinit();
    const s = &e.f.s;
    const t = try images.load(s);
    const ssh_bundle = e.f.path("ssh-bundle");
    try sys.copyTree(s, e.bundle, ssh_bundle);
    const head_path = try sys.join(s, &.{ ssh_bundle, "boot.json" });
    var head = try sys.readJson(s, head_path, boot.head_limit);
    try head.object.put(s.gpa, "variants", try json.from(s.gpa, &[_][]const u8{"ssh"}));
    try sys.writeJson(s, head_path, head);
    try sys.write(
        s,
        try sys.join(s, &.{ ssh_bundle, "boot.json.sig" }),
        try fixture.signed(&e.f, "image", try sys.read(s, head_path, boot.head_limit)),
    );
    var report = try json.parse(s.gpa, try json.encode(s.gpa, e.report));
    try report.object.put(
        s.gpa,
        "descriptor",
        .{ .string = try s.gpa.dupe(u8, &try sys.sha(s, head_path)) },
    );
    s.variants = "ssh";
    const ssh_assets = e.f.path("ssh-assets");
    _ = try exporter.exportBundle(s, "howl", ssh_bundle, report, "qemu", ssh_assets, e.trust, null);
    const legacy_dir = try legacy.testCandidate(&e.f, "minimal", "20261017T010001Z", "1");
    const exported = try legacy.exportVerified(
        s,
        t,
        std.fs.path.dirname(legacy_dir).?,
        e.f.path("ssh-legacy"),
        try exporter.provenance(s),
        try legacy.testTargets(
            s,
            legacy_dir,
            "build",
        ),
        e.keys.crt,
        null,
    );
    const legacy_assets = try json.text(exported[0], "assets");
    s.variants = "";
    try sys.writeJson(s, e.f.path("default-gates.json"), e.report);
    try sys.writeJson(s, e.f.path("ssh-gates.json"), report);
    const listing = try json.from(s.gpa, &[_]Json{
        try json.from(s.gpa, .{
            .form = "playground",
            .arch = "x86_64",
            .provider = "qemu",
            .assets = e.assets,
            .bundle = e.bundle,
            .gates = e.f.path("default-gates.json"),
            .variants = &[_][]const u8{},
        }),
        try json.from(s.gpa, .{
            .form = "playground",
            .arch = "x86_64",
            .provider = "qemu",
            .assets = ssh_assets,
            .bundle = ssh_bundle,
            .gates = e.f.path("ssh-gates.json"),
            .variants = &[_][]const u8{"ssh"},
        }),
        try json.from(s.gpa, .{
            .form = "minimal",
            .arch = "x86_64",
            .boot_profile = "legacy-boot",
            .assets = legacy_assets,
            .variants = &[_][]const u8{"ssh"},
        }),
    });
    try sys.writeJson(s, e.f.path("mixed-listing.json"), listing);
    try e.f.env.put("GITHUB_OUTPUT", e.f.path("outputs-mixed"));
    e.f.answer = gh;
    _ = try fromListingAt(s, t, e.f.path("mixed-listing.json"), e.trust);
    try testing.expectEqualStrings("", s.variants);
    try testing.expect(mem.find(u8, e.f.text, "playground-variants-ssh-qemu-x86_64") != null);
    try testing.expect(mem.find(u8, e.f.text, "/playground/variants/ssh/qemu/") != null);
    try testing.expect(mem.find(u8, e.f.text, "minimal-variants-ssh-x86_64-legacy-boot") != null);
    try testing.expect(mem.find(u8, e.f.text, "/legacy-boot/minimal-variants-ssh/x86_64/") != null);
}

/// fake_gh answers release/publish as GitHub would: the release listing
/// through jq, and a download of the legacy release it must find.
const fake_gh =
    \\#!/bin/sh
    \\case "$1" in
    \\api)
    \\  paginate= slurp= expr=
    \\  while [ $# -gt 0 ]; do
    \\    case "$1" in --paginate) paginate=1 ;; --slurp) slurp=1 ;; --jq) shift; expr=$1 ;; esac
    \\    shift
    \\  done
    \\  [ -n "$paginate" ] && [ -n "$slurp" ] || exit 3
    \\  jq -r "$expr" "$STUB_PAGES" ;;
    \\release)
    \\  [ "$2" = download ] && [ "$3" = 20261010T091704Z ] || { echo "unchanged legacy images must not create a release" >&2; exit 4; }
    \\  while [ $# -gt 0 ]; do [ "$1" = --dir ] && dir=$2; shift; done
    \\  cp "$STUB_MANIFEST" "$dir/prod-x86_64.json" ;;
    \\*) echo "unchanged legacy images must not create a release" >&2; exit 5 ;;
    \\esac
    \\
;

test "the legacy publisher finds its release beyond a page of base-image tags" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    if (!(sys.exec(
        s,
        &.{ "jq", "--version" },
        .{ .capture = .both },
    ) catch return error.SkipZigTest).ok()) return error.SkipZigTest;
    const manifest = f.path("dist/prod-x86_64.json");
    try sys.write(s, manifest, "{\n  \"build\": \"unchanged\",\n  \"kernel\": \"unchanged\"\n}\n");
    var page: std.ArrayList(Json) = .empty;
    for ([_][]const u8{ "protected-", "base-images-" }) |prefix| for (0..50) |_|
        try page.append(
            s.gpa,
            try json.from(
                s.gpa,
                .{ .draft = false, .tag_name = try s.gpa.print("{s}20261014T000000Z", .{prefix}) },
            ),
        );
    const pages = try json.from(s.gpa, &[_]Json{ try json.from(
        s.gpa,
        page.items,
    ), try json.from(s.gpa, &[_]Json{
        try json.from(s.gpa, .{ .draft = true, .tag_name = "20261012T000000Z" }),
        try json.from(s.gpa, .{ .draft = false, .tag_name = "20261010T091704Z" }),
    }) });
    try sys.write(s, f.path("pages.json"), try json.dumps(s.gpa, pages));
    try sys.write(s, f.path("bin/gh"), fake_gh);
    try std.Io.Dir.cwd().setFilePermissions(s.io, f.path("bin/gh"), .fromMode(0o755), .{});
    var env = try s.env.clone(s.gpa);
    try env.put(
        "PATH",
        try s.gpa.print("{s}:{s}", .{ f.path("bin"), s.getenv("PATH") orelse "/usr/bin:/bin" }),
    );
    try env.put("STUB_PAGES", f.path("pages.json"));
    try env.put("STUB_MANIFEST", manifest);
    const r = try sys.exec(
        s,
        &.{ "sh", "release/publish", f.path("dist"), f.path("unused-locks") },
        .{ .capture = .both, .env = &env },
    );
    try testing.expect(r.ok());
    try testing.expect(mem.find(u8, r.stdout, "nothing to publish") != null);
}
