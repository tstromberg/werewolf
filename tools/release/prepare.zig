//! prepare lays out a bundle's public objects only after native admission
//! and lifecycle evidence for that exact artifact, provider and
//! architecture: immutable objects, the channel's files, the signed heads
//! and an upload plan, in a new directory, atomically.

const std = @import("std");
const mem = std.mem;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const boot = @import("boot.zig");
const exporter = @import("exporter.zig");

/// gates are the twelve lifecycle checks every published bundle passed.
pub const gates = [_][]const u8{
    "secure_boot",    "ipe",                "verified_root",          "rollback_protected",
    "ab_upgrade",     "operator_rollback",  "unhealthy_fallback",     "retirement_cuts",
    "tamper_refused", "no_consumer_builds", "no_vendor_private_keys", "fresh_download",
};

/// checkGates refuses evidence of another artifact, architecture or
/// provider, and any gate missing, added or not exactly true.
pub fn checkGates(
    s: *Sys,
    report: Json,
    manifest: Json,
    descriptor: []const u8,
    provider: []const u8,
) !void {
    if (!json.hasKeys(report, &.{ "format", "descriptor", "arch", "provider", "checks" }) or
        !mem.eql(u8, json.text(report, "format") catch "", "werewolf-boot-gates/1"))
        return s.refuse("invalid protected publication evidence", .{});
    const arch = try json.text(try json.field(manifest, "image"), "arch");
    if (!mem.eql(u8, json.text(report, "descriptor") catch "", descriptor) or
        !mem.eql(u8, json.text(report, "arch") catch "", arch) or
        !mem.eql(u8, json.text(report, "provider") catch "", provider))
        return s.refuse("boot evidence describes a different artifact or provider", .{});
    const checks = json.get(report, "checks").?;
    if (!json.hasKeys(
        checks,
        &gates,
    )) return s.refuse("protected boot lifecycle gates are incomplete", .{});
    for (gates) |g| {
        const v = checks.object.get(g).?;
        if (v != .bool or
            !v.bool) return s.refuse("protected boot lifecycle gates are incomplete", .{});
    }
}

/// Bundle is an admitted bundle's identity.
pub const Bundle = struct {
    form: []const u8,
    arch: []const u8,
    descriptor: []const u8,
    manifest: Json,
    request: boot.Request,
};

/// admit authenticates bundle natively and checks its evidence.
pub fn admit(
    s: *Sys,
    howl: []const u8,
    bundle: []const u8,
    report: Json,
    provider: []const u8,
    trust: []const u8,
) !Bundle {
    // The form and architecture here only choose expected identities. They do not
    // authorize bytes; native signature/profile admission runs before copying files.
    const raw = try sys.readJson(s, try sys.join(s, &.{ bundle, "boot.json" }), boot.head_limit);
    const form = try json.text(raw, "form");
    const arch = try json.text(try json.field(raw, "image"), "arch");
    const request = try boot.request(s, trust, form, arch, provider);
    const manifest = try boot.native(s, howl, "head", bundle, request);
    const descriptor = try s.gpa.dupe(
        u8,
        &try sys.sha(s, try sys.join(s, &.{ bundle, "boot.json" })),
    );
    try checkGates(s, report, manifest, descriptor, provider);
    _ = try boot.freshness(s, manifest, descriptor, null, s.now());
    _ = try boot.native(s, howl, "verify", bundle, request);
    return .{
        .form = form,
        .arch = arch,
        .descriptor = descriptor,
        .manifest = manifest,
        .request = request,
    };
}

/// prepare writes the publication tree of an admitted bundle to output
/// and returns its upload plan. With release_assets, the signed export's
/// extra files and downloads manifest join the bundle's objects.
pub fn prepare(
    s: *Sys,
    howl: []const u8,
    bundle_dir: []const u8,
    report: Json,
    provider: []const u8,
    output_dir: []const u8,
    trust_dir: []const u8,
    release_assets: ?[]const u8,
) !Json {
    const bundle = try sys.resolve(s, bundle_dir);
    const output = try sys.resolve(s, output_dir);
    const trust = try sys.resolve(s, trust_dir);
    const b = try admit(s, howl, bundle, report, provider, trust);
    const exported: ?Json = if (release_assets) |assets|
        try exporter.verify(s, assets, bundle, report, provider, trust)
    else
        null;
    if (sys.exists(s, output)) return s.refuse("publication output already exists", .{});
    const parent = std.fs.path.dirname(output).?;
    try sys.mkdirs(s, parent);
    const temporary = try sys.scratch(s, parent, "protected-public-");
    defer sys.remove(s, temporary);
    const staging = try sys.join(s, &.{ temporary, "tree" });
    const relative = try s.gpa.print(
        "{s}/{s}/{s}",
        .{ try s.variantPath(b.form), provider, b.arch },
    );
    const channel = try sys.join(s, &.{ staging, relative });
    const objects = try sys.join(s, &.{ channel, "objects", b.descriptor });
    const latest = try sys.join(s, &.{ channel, "latest" });
    try sys.mkdirs(s, objects);
    try sys.mkdir(s, latest);
    const slot = try sys.join(s, &.{ bundle, "slot" });
    const prebuilt = try sys.join(s, &.{ bundle, "prebuilt", b.arch });
    for (boot.files) |name| try sys.copy(
        s,
        try sys.join(s, &.{ slot, name }),
        try sys.join(s, &.{ objects, name }),
    );
    try sys.copy(
        s,
        try sys.join(s, &.{ bundle, "disk.img.zst" }),
        try sys.join(s, &.{ objects, "disk.img.zst" }),
    );
    for ([_][]const u8{ "latest.json", "latest.json.sig" }) |name|
        try sys.copy(
            s,
            try sys.join(s, &.{ prebuilt, name }),
            try sys.join(s, &.{ objects, name }),
        );
    for ([_][]const u8{ "boot.json", "boot.json.sig" }) |name| {
        try sys.copy(s, try sys.join(s, &.{ bundle, name }), try sys.join(s, &.{ latest, name }));
        try sys.copy(s, try sys.join(s, &.{ bundle, name }), try sys.join(s, &.{ objects, name }));
    }
    // The channel machines follow: CHANNEL/ARCH/BUILD/FILE and CHANNEL/ARCH/latest.json
    // (lib/prebuilt.zig), where CHANNEL is SOURCE/FORM/PROVIDER.
    const build = try sys.join(
        s,
        &.{ channel, try json.text(try json.field(b.manifest, "image"), "build") },
    );
    try sys.mkdir(s, build);
    for (boot.files) |name| try sys.copy(
        s,
        try sys.join(s, &.{ slot, name }),
        try sys.join(s, &.{ build, name }),
    );
    for ([_][]const u8{ "latest.json", "latest.json.sig" }) |name|
        try sys.copy(
            s,
            try sys.join(s, &.{ prebuilt, name }),
            try sys.join(s, &.{ channel, name }),
        );
    if (exported) |signed| {
        // Existing boot/image heads stay byte-identical. The additional
        // downloads signature covers qcow2, runtime evidence and GHA provenance.
        const bundled = boot.files ++
            [_][]const u8{
                "disk.img.zst",
                "latest.json",
                "latest.json.sig",
                "boot.json",
                "boot.json.sig",
            };
        var it = (try json.object(try json.field(signed, "files"))).iterator();
        while (it.next()) |e| {
            for (bundled) |n| {
                if (mem.eql(u8, n, e.key_ptr.*)) break;
            } else try sys.copy(
                s,
                try sys.join(s, &.{ release_assets.?, try json.text(e.value_ptr.*, "asset") }),
                try sys.join(s, &.{ objects, e.key_ptr.* }),
            );
        }
        const prefix = try s.gpa.print(
            "{s}-{s}-{s}",
            .{ try s.variantKey(b.form), provider, b.arch },
        );
        for ([_][]const u8{ "downloads.json", "downloads.json.sig" }) |name|
            try sys.copy(
                s,
                try sys.join(
                    s,
                    &.{ release_assets.?, try s.gpa.print("{s}-{s}", .{ prefix, name }) },
                ),
                try sys.join(s, &.{ objects, name }),
            );
    }
    var entries: std.ArrayList(Json) = .empty;
    const heads = [_][]const u8{
        try s.gpa.print("{s}/latest.json", .{relative}),
        try s.gpa.print("{s}/latest.json.sig", .{relative}),
    };
    for (try sys.walk(s, staging)) |e| {
        if (e.kind != .file) continue;
        // The boot head and the channel's update head change; the objects'
        // copies of latest.json are content-addressed and never do.
        const head = mem.endsWith(u8, e.path, "/latest/boot.json") or
            mem.endsWith(u8, e.path, "/latest/boot.json.sig") or
            mem.eql(u8, e.path, heads[0]) or mem.eql(u8, e.path, heads[1]);
        const r = try sys.record(s, try sys.join(s, &.{ staging, e.path }));
        try entries.append(s.gpa, try json.from(s.gpa, .{
            .key = e.path,
            .size = r.size,
            .sha256 = try s.gpa.dupe(u8, &r.sha256),
            .immutable = !head,
        }));
    }
    // Consumers never trust this unsigned upload plan. Each signed descriptor
    // and its separately signed image head are independently authenticated.
    const image = try json.field(b.manifest, "image");
    const plan = try json.from(s.gpa, .{
        .format = "werewolf-boot-upload/2",
        .form = b.form,
        .variants = try s.variantNames(),
        .provider = provider,
        .arch = b.arch,
        .descriptor = b.descriptor,
        .serial = try json.field(image, "serial"),
        .index = try json.field(image, "index"),
        .files = entries.items,
    });
    try sys.atomic(s, try sys.join(s, &.{ staging, "publication.json" }), plan);
    try sys.rename(s, staging, output);
    return plan;
}

const testing = std.testing;
const fixture = @import("fixture.zig");

fn validReport(f: *fixture.Fixture, descriptor: []const u8) !Json {
    var checks: json.Map = .empty;
    for (gates) |g| try checks.put(f.gpa(), g, .{ .bool = true });
    return json.from(
        f.gpa(),
        .{
            .format = "werewolf-boot-gates/1",
            .descriptor = descriptor,
            .arch = "aarch64",
            .provider = "lima",
            .checks = checks,
        },
    );
}

test "every publication gate is mandatory and exactly true" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const gpa = f.gpa();
    const manifest = try json.parse(gpa, "{\"image\":{\"arch\":\"aarch64\"}}");
    const descriptor = fixture.rep('1', 64);
    try checkGates(s, try validReport(&f, descriptor), manifest, descriptor, "lima");
    for (gates) |g| {
        for ([_][]const u8{ "false", "\"true\"", "1", "null" }) |value| {
            var changed = try validReport(&f, descriptor);
            try changed.object.getPtr("checks").?.object.put(gpa, g, try json.parse(gpa, value));
            try testing.expectError(
                error.Refused,
                checkGates(s, changed, manifest, descriptor, "lima"),
            );
        }
        var missing = try validReport(&f, descriptor);
        _ = missing.object.getPtr("checks").?.object.orderedRemove(g);
        try testing.expectError(
            error.Refused,
            checkGates(s, missing, manifest, descriptor, "lima"),
        );
    }
}

test "evidence cannot be reused for another disk, architecture or provider" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const gpa = f.gpa();
    const manifest = try json.parse(gpa, "{\"image\":{\"arch\":\"aarch64\"}}");
    const descriptor = fixture.rep('1', 64);
    for ([_][2][]const u8{
        .{ "descriptor", fixture.rep('2', 64) },
        .{ "arch", "x86_64" },
        .{ "provider", "qemu" },
        .{ "format", "old" },
    }) |c| {
        var changed = try validReport(&f, descriptor);
        try changed.object.put(gpa, c[0], .{ .string = c[1] });
        try testing.expectError(
            error.Refused,
            checkGates(s, changed, manifest, descriptor, "lima"),
        );
    }
    // Protocol v2 evidence named gates v3 no longer has; exactly these gates are accepted.
    var older = try validReport(&f, descriptor);
    try older.object.getPtr("checks").?.object.put(gpa, "shared_issuer", .{ .bool = true });
    try older.object.getPtr("checks").?.object.put(gpa, "independent_owners", .{ .bool = true });
    try testing.expectError(error.Refused, checkGates(s, older, manifest, descriptor, "lima"));
}

fn answerHeads(f: *fixture.Fixture, argv: []const []const u8) anyerror!?sys.Result {
    if (argv.len < 8 or !mem.eql(u8, argv[1], "_boot-image")) return null;
    try testing.expectEqualStrings("https://vendor.test/boot/v1/playground/lima", argv[6]);
    return .{ .term = .{ .exited = 0 }, .stdout = f.text };
}

test "preparation admits before an atomic layout of immutable objects" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const gpa = f.gpa();
    const bundle = f.path("bundle");
    const trust = f.path("trust");
    const output = f.path("public");
    const serial = sys.serial(s.now());
    const manifest = try json.from(
        gpa,
        .{
            .form = "playground",
            .image = .{
                .arch = "aarch64",
                .build = fixture.rep('2', 64),
                .index = 3,
                .serial = &serial,
            },
        },
    );
    try sys.write(s, f.path("bundle/boot.json"), try json.dumps(gpa, manifest));
    try sys.write(s, f.path("bundle/boot.json.sig"), "signed-boot-head");
    try sys.write(s, f.path("bundle/disk.img.zst"), "compressed-disk");
    for (boot.files) |name| try sys.write(s, try sys.join(s, &.{ bundle, "slot", name }), name);
    try sys.write(s, f.path("bundle/prebuilt/aarch64/latest.json"), "signed-image-head");
    try sys.write(s, f.path("bundle/prebuilt/aarch64/latest.json.sig"), "signed-image-signature");
    const descriptor = try gpa.dupe(u8, &try sys.sha(s, f.path("bundle/boot.json")));
    const report = try validReport(&f, descriptor);
    f.answer = answerHeads;
    f.text = try json.dumps(gpa, manifest);
    // Protocol v2 trust named a host permit service; v3 trust is the mirror alone.
    try sys.write(
        s,
        f.path("trust/trust.json"),
        "{\"format\": \"werewolf-boot-trust/1\", \"source\": \"https://vendor.test/boot/v1\", " ++
            "\"permit_port\": 9443}",
    );
    try testing.expectError(
        error.Refused,
        prepare(s, "howl", bundle, report, "lima", output, trust, null),
    );
    try testing.expectEqual(@as(usize, 0), f.calls.items.len);
    try sys.write(
        s,
        f.path("trust/trust.json"),
        "{\"format\": \"werewolf-boot-trust/2\", \"source\": \"https://vendor.test/boot/v1\"}",
    );
    var invalid = try validReport(&f, descriptor);
    try invalid.object.getPtr("checks").?.object.put(gpa, "unhealthy_fallback", .{ .bool = false });
    try testing.expectError(
        error.Refused,
        prepare(s, "howl", bundle, invalid, "lima", output, trust, null),
    );
    try testing.expectEqual(@as(usize, 1), f.called(&.{ "howl", "_boot-image", "head" }));
    try testing.expectEqual(@as(usize, 1), f.calls.items.len);
    try testing.expect(!sys.exists(s, output));
    f.calls.clearRetainingCapacity();
    const plan = try prepare(s, "howl", bundle, report, "lima", output, trust, null);
    try testing.expectEqual(@as(usize, 1), f.called(&.{ "howl", "_boot-image", "head" }));
    try testing.expectEqual(@as(usize, 1), f.called(&.{ "howl", "_boot-image", "verify" }));
    try testing.expectEqual(@as(usize, 2), f.calls.items.len);
    try testing.expectEqualStrings(descriptor, try json.text(plan, "descriptor"));
    try testing.expectEqualStrings("werewolf-boot-upload/2", try json.text(plan, "format"));
    try testing.expectEqual(@as(i64, 3), try json.int(plan, "index"));
    // Only the signed boot and update heads change in place; every other object is immutable.
    var mutable: std.ArrayList([]const u8) = .empty;
    var immutable: usize = 0;
    for (try json.items(json.get(plan, "files").?)) |entry| {
        if (json.get(entry, "immutable").?.bool)
            immutable += 1
        else
            try mutable.append(gpa, try json.text(entry, "key"));
    }
    try testing.expectEqual(@as(usize, 15), immutable);
    mem.sort([]const u8, mutable.items, {}, json.less);
    const want = [_][]const u8{
        "playground/lima/aarch64/latest.json",
        "playground/lima/aarch64/latest.json.sig",
        "playground/lima/aarch64/latest/boot.json",
        "playground/lima/aarch64/latest/boot.json.sig",
    };
    try testing.expectEqual(want.len, mutable.items.len);
    for (want, mutable.items) |w, m| try testing.expectEqualStrings(w, m);
    const objects = try sys.join(s, &.{ output, "playground/lima/aarch64/objects", descriptor });
    try testing.expectEqualStrings(
        "compressed-disk",
        try sys.read(s, try sys.join(s, &.{ objects, "disk.img.zst" }), 4096),
    );
    try testing.expectEqualStrings(
        try sys.read(s, f.path("bundle/boot.json"), 4096),
        try sys.read(
            s,
            try sys.join(s, &.{ output, "playground/lima/aarch64/latest/boot.json" }),
            4096,
        ),
    );
    // Machines update from CHANNEL/ARCH/latest.json and CHANNEL/ARCH/BUILD/FILE.
    const channel = try sys.join(s, &.{ output, "playground/lima/aarch64" });
    try testing.expectEqualStrings(
        "signed-image-head",
        try sys.read(s, try sys.join(s, &.{ channel, "latest.json" }), 4096),
    );
    try testing.expectEqualStrings(
        "signed-image-signature",
        try sys.read(s, try sys.join(s, &.{ channel, "latest.json.sig" }), 4096),
    );
    for (boot.files) |name| try testing.expectEqualStrings(
        name,
        try sys.read(s, try sys.join(s, &.{ channel, fixture.rep('2', 64), name }), 4096),
    );
    try testing.expectError(
        error.Refused,
        prepare(s, "howl", bundle, report, "lima", output, trust, null),
    );
    try testing.expectEqualStrings("publication output already exists", s.why.text);
}
