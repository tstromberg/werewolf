//! legacy builds, verifies, signs and publishes the explicitly unprotected
//! legacy-boot images from the same resolved inputs as the secure ones.
//! They never carry signing credentials or write a protected head, and
//! their signed manifests say which protections they lack.

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
const candidates = @import("candidates.zig");
const exporter = @import("exporter.zig");
const Store = @import("store.zig").Store;

pub const format = "werewolf-legacy-downloads/1";
pub const files = [_][]const u8{
    "cmdline",
    "disk.img.zst",
    "disk.qcow2",
    "initramfs.zst",
    "inputs.tar.gz",
    "packages.json",
    "root.erofs",
    "stage0.zst",
    "vmlinuz",
};
pub const checks = [_][]const u8{
    "coverage",
    "direct_boot",
    "disk_parity",
    "integration",
    "package_update",
    "reproducible",
    "uefi_boot",
};
pub const release_notes = [_][]const u8{ "release-notes.html", "release-notes.json" };
const disabled = [_][]const u8{ "secureboot", "tpm", "ipe" };

fn isFile(name: []const u8) bool {
    return images.has(&files, name);
}

/// prefix is FORM-ARCH-legacy-boot, as legacy assets are named.
fn prefix(s: *Sys, t: images.Images, name: []const u8, arch: []const u8) ![]const u8 {
    if (!t.identity(
        name,
        arch,
        "legacy-boot",
    )) return s.refuse("unsupported published image identity", .{});
    return s.gpa.print("{s}-{s}-legacy-boot", .{ try s.variantKey(name), arch });
}

/// assetName is a file's release asset name: the disk is FORM-ARCH-legacy-boot.qcow2.
fn assetName(s: *Sys, p: []const u8, name: []const u8) ![]const u8 {
    return if (mem.eql(u8, name, "disk.qcow2"))
        s.gpa.print("{s}.qcow2", .{p})
    else
        s.gpa.print("{s}-{s}", .{ p, name });
}

fn checksJson(s: *Sys) !Json {
    var m: json.Map = .empty;
    for (checks) |c| try m.put(s.gpa, c, .{ .bool = true });
    return .{ .object = m };
}

fn disabledJson(s: *Sys) !Json {
    return json.from(s.gpa, @as([]const []const u8, &disabled));
}

/// allTrue says whether v is an object of exactly checks, each true.
fn allTrue(v: Json) bool {
    if (!json.hasKeys(v, &checks)) return false;
    for (checks) |c| {
        const x = v.object.get(c).?;
        if (x != .bool or !x.bool) return false;
    }
    return true;
}

/// settled says whether the published legacy receipt is signed for these
/// inputs with every check passed, so the profile need not build again.
pub fn settled(
    s: *Sys,
    t: images.Images,
    name: []const u8,
    arch: []const u8,
    inputs: []const u8,
    certificate: []const u8,
) !bool {
    if (!t.identity(
        name,
        arch,
        "legacy-boot",
    )) return s.refuse("unsupported published image identity", .{});
    const url = try s.gpa.print(
        "{s}/legacy-boot/{s}/{s}/latest/accepted.json",
        .{ try catalog.public(s), try s.variantKey(name), arch },
    );
    const raw = switch (try sys.get(s, url, 4 << 20)) {
        .missing => return false,
        .body => |b| b,
    };
    const manifest = try catalog.opened(s, raw, certificate);
    if (!mem.eql(u8, try json.text(manifest, "form"), name) or
        !mem.eql(u8, try json.text(manifest, "arch"), arch) or
        !mem.eql(u8, try json.text(manifest, "boot_profile"), "legacy-boot") or
        !mem.eql(u8, try json.text(manifest, "format"), format))
        return s.refuse("foreign legacy publication receipt", .{});
    const tests = try json.field(try json.field(manifest, "tests"), "checks");
    return json.eql(try json.field(manifest, "inputs"), .{ .string = inputs }) and allTrue(tests);
}

/// validate refuses a legacy manifest that is not exactly a compatibility
/// image of a published form, or that its directory's bytes differ from.
pub fn validate(s: *Sys, t: images.Images, manifest: Json, directory: []const u8) !Json {
    const name = try json.text(manifest, "form");
    const arch = try json.text(manifest, "arch");
    const profile = try json.text(manifest, "boot_profile");
    if (!t.identity(
        name,
        arch,
        profile,
    )) return s.refuse("unsupported published image identity", .{});
    if (!s.matchesVariants(manifest)) return s.refuse(
        "legacy image describes another variant selection",
        .{},
    );
    const listed = try json.field(manifest, "files");
    if (!mem.eql(u8, try json.text(manifest, "format"), format) or
        !mem.eql(u8, profile, "legacy-boot") or
        !json.eql(try json.field(manifest, "disabled"), try disabledJson(s)) or
        !json.hasKeys(listed, &files))
        return s.refuse("invalid legacy boot manifest", .{});
    if (!catalog.isSerial(json.text(manifest, "serial") catch "") or
        !catalog.isHex(json.text(manifest, "commit") catch "", 40) or
        !catalog.isHex(json.text(manifest, "inputs") catch "", 64))
        return s.refuse("invalid legacy release identity", .{});
    const raw_size = try json.field(manifest, "raw_size");
    if (raw_size != .integer or raw_size.integer < 512 << 20 or raw_size.integer > 16 << 30)
        return s.refuse("invalid legacy raw disk size", .{});
    var it = listed.object.iterator();
    while (it.next()) |e| {
        const r = try sys.record(s, try sys.join(s, &.{ directory, e.key_ptr.* }));
        if (!json.eql(
            try r.toJson(s.gpa),
            e.value_ptr.*,
        )) return s.refuse("legacy image differs from its manifest: {s}", .{e.key_ptr.*});
    }
    const cmdline = try sys.read(s, try sys.join(s, &.{ directory, "cmdline" }), 64 << 10);
    var words = mem.tokenizeAny(u8, cmdline, " \t\n\r\x0b\x0c");
    var refused = true;
    while (words.next()) |w| {
        for ([_][]const u8{
            "werewolf.secure=",
            "werewolf.tpm=",
            "werewolf.release=",
            "werewolf.native=",
        }) |p|
            if (mem.startsWith(
                u8,
                w,
                p,
            )) return s.refuse("legacy image has an incompatible boot identity", .{});
        if (mem.eql(u8, w, "werewolf.disable=secureboot,tpm,ipe")) refused = false;
    }
    if (refused) return s.refuse("legacy image has an incompatible boot identity", .{});
    return manifest;
}

fn buildOne(
    s: *Sys,
    t: images.Images,
    tree: plan.Tree,
    target: Json,
    snapshot: []const u8,
    output: []const u8,
) !void {
    const name = try json.text(target, "form");
    const arch = try json.text(target, "arch");
    _ = try prefix(s, t, name, arch);
    try plan.installLocks(s, tree, snapshot);
    try sys.mkdirs(s, output);
    const work = try sys.join(s, &.{ try sys.resolve(s, tree.legacy_work), arch, name });
    sys.remove(s, work);
    var env = try s.env.clone(s.gpa);
    try env.put("SOURCE_DATE_EPOCH", "0");
    try env.put("WEREWOLF_FORM_INPUTS", snapshot);
    // No code-signing or TPM credentials enter a compatibility build.
    var drop: std.ArrayList([]const u8) = .empty;
    var it = env.iterator();
    while (it.next()) |e| for ([_][]const u8{
        "WEREWOLF_BOOT_",
        "WEREWOLF_IPE_",
        "WEREWOLF_PROTECTED_",
        "WEREWOLF_TPM_",
    }) |p| {
        if (mem.startsWith(u8, e.key_ptr.*, p)) try drop.append(s.gpa, e.key_ptr.*);
    };
    for (drop.items) |k| _ = env.swapRemove(k);
    try sys.run(s, &.{
        try sys.resolve(
            s,
            tree.howl,
        ),
        "_build",
        "--with",
        name,
        "--arch",
        arch,
        "--build",
        work,
        "--disable=secureboot,tpm,ipe",
        "image",
        "slot",
        "qcow2",
    }, .{ .env = &env });
    const root = try sys.join(s, &.{ work, try s.variantKey(name) });
    if (sys.exists(
        s,
        try sys.join(s, &.{ root, "meta/usr/share/werewolf/dev" }),
    )) return s.refuse("development images cannot be published", .{});
    for ([_][]const u8{
        "stage0.zst",
        "root.erofs",
        "cmdline",
    }) |f| try sys.copy(
        s,
        try sys.join(s, &.{ root, "slot", f }),
        try sys.join(s, &.{ output, f }),
    );
    for ([_][]const u8{
        "disk.qcow2",
        "initramfs.zst",
    }) |f| try sys.copy(s, try sys.join(s, &.{ root, f }), try sys.join(s, &.{ output, f }));
    try sys.copy(
        s,
        try sys.join(s, &.{ work, "vmlinuz" }),
        try sys.join(s, &.{ output, "vmlinuz" }),
    );
    const raw = try sys.join(s, &.{ work, "export.raw" });
    try sys.run(
        s,
        &.{
            "qemu-img",
            "convert",
            "-f",
            "qcow2",
            "-O",
            "raw",
            try sys.join(s, &.{ output, "disk.qcow2" }),
            raw,
        },
        .{},
    );
    try sys.run(
        s,
        &.{ "zstd", "-q", "-T1", "-19", raw, "-o", try sys.join(s, &.{ output, "disk.img.zst" }) },
        .{},
    );
    try candidates.archiveInputs(s, snapshot, try sys.join(s, &.{ output, "inputs.tar.gz" }));
    try sys.writeJson(
        s,
        try sys.join(s, &.{ output, "packages.json" }),
        try notes.inventory(
            s,
            snapshot,
            name,
            arch,
            try candidates.localPackages(s, tree, snapshot, arch),
        ),
    );
    var records: json.Map = .empty;
    for (files) |f| try records.put(
        s.gpa,
        f,
        try (try sys.record(s, try sys.join(s, &.{ output, f }))).toJson(s.gpa),
    );
    const raw_size = (try std.Io.Dir.cwd().statFile(s.io, raw, .{})).size;
    const manifest = try json.from(s.gpa, .{
        .format = format,
        .form = name,
        .variants = try s.variantNames(),
        .arch = arch,
        .boot_profile = "legacy-boot",
        .disabled = try disabledJson(s),
        .serial = try json.field(target, "serial"),
        .inputs = try json.field(target, "inputs"),
        .commit = try json.field(target, "commit"),
        .raw_size = raw_size,
        .files = records,
    });
    _ = try validate(s, t, manifest, output);
    try sys.writeJson(s, try sys.join(s, &.{ output, "manifest.json" }), manifest);
    sys.remove(s, work);
}

fn skipped(target: Json) ?[]const u8 {
    const status = json.text(target, "status") catch "";
    if (mem.eql(u8, status, "unsupported architecture")) return status;
    if (mem.eql(u8, json.text(target, "legacy_status") catch "", "unchanged")) return "unchanged";
    return null;
}

/// build builds a plan's legacy targets; it says whether any failed.
pub fn build(
    s: *Sys,
    t: images.Images,
    tree: plan.Tree,
    snapshot_dir: []const u8,
    output_dir: []const u8,
) !bool {
    const snapshot = try sys.resolve(s, snapshot_dir);
    const output = try sys.resolve(s, output_dir);
    const p = try sys.readJson(s, try sys.join(s, &.{ snapshot, "plan.json" }), 1 << 20);
    try plan.native(s, tree, try json.text(p, "arch"));
    if (sys.exists(s, output)) return s.refuse("{s} already exists", .{output});
    try sys.mkdirs(s, output);
    var results: std.ArrayList(Json) = .empty;
    const results_path = try sys.join(s, &.{ output, "results.json" });
    for (try json.items(try json.field(p, "targets"))) |target| {
        const name = try json.text(target, "form");
        if (!t.hasForm(name)) return s.refuse("unlisted form in legacy image plan", .{});
        var result = try json.parse(s.gpa, try json.encode(s.gpa, target));
        try result.object.put(s.gpa, "status", .{ .string = "build failed" });
        try results.append(s.gpa, result);
        defer {
            results.items[results.items.len - 1] = result;
            sys.writeJson(
                s,
                results_path,
                .{ .array = .fromOwnedSlice(s.gpa, results.items) },
            ) catch {};
        }
        if (skipped(target)) |why| {
            try result.object.put(s.gpa, "status", .{ .string = why });
            continue;
        }
        // Legacy heads have their own publication history. A settled secure
        // target never implies that this profile has been built or tested.
        const status = try json.text(target, "status");
        if (!mem.eql(u8, status, "build") and !mem.eql(u8, status, "unchanged")) continue;
        buildChecked(s, t, tree, target, snapshot, output) catch |err| {
            s.say("legacy-boot: {s} build failed: {s}", .{ name, s.reason(err) });
            continue;
        };
        try result.object.put(s.gpa, "status", .{ .string = "built" });
    }
    for (results.items) |r| {
        const status = try json.text(r, "status");
        if (!mem.eql(u8, status, "built") and !mem.eql(u8, status, "unchanged") and
            !mem.eql(u8, status, "unsupported architecture")) return true;
    }
    return false;
}

fn buildChecked(
    s: *Sys,
    t: images.Images,
    tree: plan.Tree,
    target: Json,
    snapshot: []const u8,
    output: []const u8,
) !void {
    const name = try json.text(target, "form");
    const own = try sys.join(s, &.{ snapshot, name });
    const chain = try candidates.stringList(
        s,
        try json.field(
            try sys.readJson(s, try sys.join(s, &.{ own, "input.json" }), 1 << 20),
            "chain",
        ),
    );
    if (!mem.eql(
        u8,
        &try plan.resolvedIdentity(s, name, try json.text(target, "arch"), own, chain),
        try json.text(target, "inputs"),
    ) or
        !json.eql(
            try sys.readJson(s, try sys.join(s, &.{ own, "tools.json" }), 1 << 20),
            try plan.toolVersions(s, name),
        ))
        return s.refuse("legacy build inputs or tools changed after resolution", .{});
    const log = try std.Io.Dir.cwd().createFile(
        s.io,
        try sys.join(s, &.{ output, try s.gpa.print("{s}.log", .{name}) }),
        .{},
    );
    defer log.close(s.io);
    s.log = log;
    defer s.log = null;
    try buildOne(s, t, tree, target, own, try sys.join(s, &.{ output, name }));
}

/// check compares a plan's legacy builds, tests them and boots the exact
/// images; it says whether any failed.
pub fn check(
    s: *Sys,
    t: images.Images,
    tree: plan.Tree,
    snapshot_dir: []const u8,
    first_dir: []const u8,
    second_dir: []const u8,
    output_dir: []const u8,
) !bool {
    const snapshot = try sys.resolve(s, snapshot_dir);
    const first = try sys.resolve(s, first_dir);
    const second = try sys.resolve(s, second_dir);
    const output = try sys.resolve(s, output_dir);
    const p = try sys.readJson(s, try sys.join(s, &.{ snapshot, "plan.json" }), 1 << 20);
    try plan.native(s, tree, try json.text(p, "arch"));
    if (sys.exists(s, output)) return s.refuse("{s} already exists", .{output});
    try sys.mkdirs(s, output);
    var failed = false;
    var results: std.ArrayList(Json) = .empty;
    for (try json.items(try json.field(p, "targets"))) |target| {
        const name = try json.text(target, "form");
        if (!t.hasForm(name)) return s.refuse("unlisted form in legacy image plan", .{});
        const arch = try json.text(target, "arch");
        var result = try json.from(
            s.gpa,
            .{ .form = name, .variants = try s.variantNames(), .arch = arch, .status = "failed" },
        );
        if (skipped(target)) |why| {
            try result.object.put(s.gpa, "status", .{ .string = why });
        } else if (checkOne(s, t, tree, target, snapshot, first, second, output)) {
            try result.object.put(s.gpa, "status", .{ .string = "passed" });
        } else |err| {
            s.say("legacy-boot: {s} verification failed: {s}", .{ name, s.reason(err) });
            failed = true;
        }
        try results.append(s.gpa, result);
    }
    try sys.writeJson(
        s,
        try sys.join(s, &.{ output, "results.json" }),
        .{ .array = .fromOwnedSlice(s.gpa, results.items) },
    );
    return failed;
}

fn checkOne(
    s: *Sys,
    t: images.Images,
    tree: plan.Tree,
    target: Json,
    snapshot: []const u8,
    first: []const u8,
    second: []const u8,
    output: []const u8,
) !void {
    const name = try json.text(target, "form");
    const arch = try json.text(target, "arch");
    const left = try sys.join(s, &.{ first, name });
    const right = try sys.join(s, &.{ second, name });
    const manifest = try validate(
        s,
        t,
        try sys.readJson(s, try sys.join(s, &.{ left, "manifest.json" }), 1 << 20),
        left,
    );
    _ = try validate(
        s,
        t,
        try sys.readJson(s, try sys.join(s, &.{ right, "manifest.json" }), 1 << 20),
        right,
    );
    if (!json.eql(
        try candidates.digests(s, left),
        try candidates.digests(s, right),
    )) return s.refuse("independent legacy boot builds differ", .{});
    for ([_][]const u8{ "form", "arch", "serial", "commit", "inputs" }) |k|
        if (!json.eql(
            try json.field(manifest, k),
            try json.field(target, k),
        )) return s.refuse("legacy build differs from resolved inputs", .{});
    {
        const work = try sys.scratch(s, null, "ww-legacy-disk-");
        defer sys.remove(s, work);
        const raw = try sys.join(s, &.{ work, "disk.raw" });
        const size = try json.field(manifest, "raw_size");
        try exporter.unpack(s, try sys.join(s, &.{ left, "disk.img.zst" }), raw, size);
        try exporter.compare(s, raw, try sys.join(s, &.{ left, "disk.qcow2" }), size);
    }
    try plan.installLocks(s, tree, try sys.join(s, &.{ snapshot, name }));
    var coverage: std.ArrayList([]const u8) = .empty;
    try coverage.appendSlice(s.gpa, tree.coverage);
    try coverage.appendSlice(s.gpa, &.{ "--form", name });
    try sys.run(s, coverage.items, .{});
    var env = try s.env.clone(s.gpa);
    try env.put("WEREWOLF_FORM_INPUTS", try sys.join(s, &.{ snapshot, name }));
    try sys.run(
        s,
        &.{ try sys.resolve(s, tree.howl), "test", "--with", name, "--arch", arch },
        .{ .env = &env },
    );
    // The package updater and slot commitment are shared platform code.
    // Test their compatibility path as well as each exact image's boots.
    try sys.run(
        s,
        &.{ "make", try s.gpa.print("ARCH={s}", .{arch}), "check-slot", "check-updater" },
        .{},
    );
    try sys.run(
        s,
        &.{
            try sys.resolve(s, tree.legacy_check),
            left,
            try sys.join(s, &.{ output, try s.gpa.print("{s}-logs", .{name}) }),
        },
        .{},
    );
    const destination = try sys.join(s, &.{ output, name });
    try sys.copyTree(s, left, destination);
    try sys.writeJson(s, try sys.join(s, &.{ destination, "tests.json" }), try json.from(s.gpa, .{
        .boot_profile = "legacy-boot",
        .manifest = try s.gpa.dupe(
            u8,
            &try sys.sha(s, try sys.join(s, &.{ destination, "manifest.json" })),
        ),
        .checks = try checksJson(s),
    }));
}

/// Previous is a target's last signed legacy release and its inventory.
const Previous = struct { release: Json, inventory: Json };

fn previousInventory(
    s: *Sys,
    t: images.Images,
    store: ?Store,
    name: []const u8,
    arch: []const u8,
    certificate: []const u8,
    work: []const u8,
) !?Previous {
    const st = store orelse return null;
    const namespace = try s.gpa.print("legacy-boot/{s}/{s}", .{ try s.variantKey(name), arch });
    const receipt = try sys.join(s, &.{ work, "accepted.json" });
    if (!try st.fetch(
        s,
        try s.gpa.print("{s}/latest/accepted.json", .{namespace}),
        receipt,
    )) return null;
    const envelope = try sys.readJson(s, receipt, 4 << 20);
    const raw = try json.text(envelope, "manifest");
    try catalog.verify(
        s,
        raw,
        try catalog.unhex(s, try json.text(envelope, "signature")),
        certificate,
    );
    const manifest = try json.parse(s.gpa, raw);
    if (!mem.eql(u8, try json.text(manifest, "form"), name) or
        !mem.eql(u8, try json.text(manifest, "arch"), arch) or
        !mem.eql(u8, try json.text(manifest, "boot_profile"), "legacy-boot"))
        return s.refuse("foreign previous legacy release", .{});
    const object = try s.gpa.print("{s}/objects/{s}", .{ namespace, &sys.sha256(raw) });
    const expected = try json.field(try json.field(manifest, "files"), "packages.json");
    const inventory = try sys.join(s, &.{ work, "packages.json" });
    const want = try s.gpa.print("{s}-packages.json", .{try prefix(s, t, name, arch)});
    if (!mem.eql(u8, json.text(expected, "asset") catch "", want) or
        !try st.fetch(s, try s.gpa.print("{s}/{s}", .{ object, want }), inventory) or
        !(try sys.record(s, inventory)).matches(expected))
        return s.refuse("previous legacy package inventory is missing or changed", .{});
    return .{
        .release = try json.from(
            s.gpa,
            .{
                .object = object,
                .serial = try json.field(manifest, "serial"),
                .commit = try json.field(manifest, "commit"),
            },
        ),
        .inventory = try notes.validate(s, try sys.readJson(s, inventory, 4 << 20), name, arch),
    };
}

fn reuseExport(
    s: *Sys,
    t: images.Images,
    store: ?Store,
    manifest: Json,
    report: Json,
    provenance: Json,
    assets: []const u8,
    certificate: []const u8,
) !bool {
    const st = store orelse return false;
    const name = try json.text(manifest, "form");
    const arch = try json.text(manifest, "arch");
    const namespace = try s.gpa.print("legacy-boot/{s}/{s}", .{ try s.variantKey(name), arch });
    const work = try sys.scratch(s, null, "ww-legacy-retry-");
    defer sys.remove(s, work);
    const receipt = try sys.join(s, &.{ work, "accepted.json" });
    if (!try st.fetch(
        s,
        try s.gpa.print("{s}/latest/accepted.json", .{namespace}),
        receipt,
    )) return false;
    const envelope = try sys.readJson(s, receipt, 4 << 20);
    const raw = try json.text(envelope, "manifest");
    const signature = try catalog.unhex(s, try json.text(envelope, "signature"));
    try catalog.verify(s, raw, signature, certificate);
    const previous = try json.parse(s.gpa, raw);
    if (!json.eql(
        try json.field(previous, "serial"),
        try json.field(manifest, "serial"),
    )) return false;
    const was = try json.field(previous, "provenance");
    for ([_][]const u8{ "repository", "commit", "run" }) |k| {
        if (!json.eql(
            try json.field(was, k),
            try json.field(provenance, k),
        )) return s.refuse("existing legacy export is from another workflow build", .{});
    }
    if (!json.eql(
        try json.field(previous, "tests"),
        report,
    )) return s.refuse("existing legacy export is from another workflow build", .{});
    const listed = try json.object(try json.field(previous, "files"));
    for (listed.keys()) |k| if (!isFile(k) and !mem.eql(u8, k, "tests.json") and
        !images.has(&release_notes, k))
        return s.refuse("existing legacy export contains unexpected files", .{});
    const p = try prefix(s, t, name, arch);
    const head = try sys.join(s, &.{ assets, try s.gpa.print("{s}-downloads.json", .{p}) });
    try sys.write(s, head, raw);
    try sys.write(s, try s.gpa.print("{s}.sig", .{head}), signature);
    const object = try s.gpa.print("{s}/objects/{s}", .{ namespace, &sys.sha256(raw) });
    for (listed.keys()) |k| {
        const asset = try assetName(s, p, k);
        if (!try st.fetch(
            s,
            try s.gpa.print("{s}/{s}", .{ object, asset }),
            try sys.join(s, &.{ assets, asset }),
        ))
            return s.refuse("existing legacy export is incomplete", .{});
    }
    _ = try verify(s, t, assets, certificate);
    return true;
}

/// exportVerified signs only fully verified legacy artifacts of this
/// workflow's resolved targets; it never produces a protected head.
pub fn exportVerified(
    s: *Sys,
    t: images.Images,
    verified: []const u8,
    output_dir: []const u8,
    provenance: Json,
    targets: []const Json,
    certificate: []const u8,
    store: ?Store,
) ![]Json {
    const output = try sys.resolve(s, output_dir);
    try sys.mkdirs(s, output);
    var exported: std.ArrayList(Json) = .empty;
    var seen: std.ArrayList([]const u8) = .empty;
    var manifests: std.ArrayList([]const u8) = .empty;
    for (try sys.walk(
        s,
        verified,
    )) |e| if (e.kind == .file and mem.eql(u8, std.fs.path.basename(e.path), "manifest.json"))
        try manifests.append(s.gpa, try sys.join(s, &.{ verified, e.path }));
    for (manifests.items) |path| {
        const directory = std.fs.path.dirname(path).?;
        const raw = try sys.readJson(s, path, 1 << 20);
        if (!s.matchesVariants(raw)) continue;
        const manifest = try validate(s, t, raw, directory);
        const name = try json.text(manifest, "form");
        const arch = try json.text(manifest, "arch");
        const identity = try s.gpa.print("{s}/{s}", .{ try s.variantKey(name), arch });
        const target = for (targets) |x| {
            if (mem.eql(u8, json.text(x, "form") catch "", name) and
                mem.eql(u8, json.text(x, "arch") catch "", arch)) break x;
        } else null;
        const ok = blk: {
            const tg = target orelse break :blk false;
            if (images.has(seen.items, identity)) break :blk false;
            const status = json.text(tg, "status") catch "";
            if (!mem.eql(u8, status, "build") and
                !mem.eql(u8, status, "unchanged")) break :blk false;
            if (!mem.eql(
                u8,
                try json.text(manifest, "commit"),
                s.getenv("GITHUB_SHA") orelse "",
            )) break :blk false;
            for ([_][]const u8{ "serial", "commit", "inputs" }) |k| {
                if (!json.eql(
                    try json.field(manifest, k),
                    json.get(tg, k) orelse .null,
                )) break :blk false;
            }
            break :blk true;
        };
        if (!ok) return s.refuse(
            "legacy artifact differs from this workflow's resolved target",
            .{},
        );
        try seen.append(s.gpa, identity);
        const report = try sys.readJson(
            s,
            try sys.join(s, &.{ directory, "tests.json" }),
            64 << 10,
        );
        const want = try json.from(
            s.gpa,
            .{
                .boot_profile = "legacy-boot",
                .manifest = try s.gpa.dupe(u8, &try sys.sha(s, path)),
                .checks = try checksJson(s),
            },
        );
        if (!json.eql(report, want) or !allTrue(json.get(report, "checks") orelse .null))
            return s.refuse("legacy artifact has incomplete or foreign tests", .{});
        const p = try prefix(s, t, name, arch);
        const assets = try sys.join(s, &.{ output, p });
        try sys.mkdir(s, assets);
        const entry = try json.from(
            s.gpa,
            .{
                .form = name,
                .variants = try s.variantNames(),
                .arch = arch,
                .boot_profile = "legacy-boot",
                .serial = try json.field(manifest, "serial"),
                .assets = assets,
            },
        );
        if (try reuseExport(s, t, store, manifest, report, provenance, assets, certificate)) {
            try exported.append(s.gpa, entry);
            continue;
        }
        var records: json.Map = .empty;
        var names: std.ArrayList([]const u8) = .empty;
        try names.appendSlice(s.gpa, &files);
        try names.append(s.gpa, "tests.json");
        mem.sort([]const u8, names.items, {}, json.less);
        for (names.items) |f| {
            const asset = try assetName(s, p, f);
            try sys.copy(
                s,
                try sys.join(s, &.{ directory, f }),
                try sys.join(s, &.{ assets, asset }),
            );
            try records.put(s.gpa, f, try assetRecord(s, assets, asset));
        }
        {
            const work = try sys.scratch(s, null, "ww-legacy-notes-");
            defer sys.remove(s, work);
            const previous = try previousInventory(s, t, store, name, arch, certificate, work);
            const current = try sys.readJson(
                s,
                try sys.join(s, &.{ directory, "packages.json" }),
                4 << 20,
            );
            const release = try notes.release(s, .{
                .form = name,
                .variants = try s.variantNames(),
                .provider = "legacy-boot",
                .arch = arch,
                .serial = try json.text(manifest, "serial"),
                .commit = try json.text(manifest, "commit"),
            }, current, if (previous) |x|
                x.release
            else
                null, if (previous) |x| x.inventory else null);
            try sys.writeJson(
                s,
                try sys.join(s, &.{ assets, try s.gpa.print("{s}-release-notes.json", .{p}) }),
                release,
            );
            try sys.write(
                s,
                try sys.join(s, &.{ assets, try s.gpa.print("{s}-release-notes.html", .{p}) }),
                try notes.page(s, release, try s.gpa.print("{s}-", .{p})),
            );
        }
        for (release_notes) |f| try records.put(
            s.gpa,
            f,
            try assetRecord(s, assets, try s.gpa.print("{s}-{s}", .{ p, f })),
        );
        var signed = try json.parse(s.gpa, try json.encode(s.gpa, manifest));
        try signed.object.put(s.gpa, "files", .{ .object = records });
        try signed.object.put(s.gpa, "tests", report);
        try signed.object.put(s.gpa, "provenance", provenance);
        const head = try sys.join(s, &.{ assets, try s.gpa.print("{s}-downloads.json", .{p}) });
        try sys.writeJson(s, head, signed);
        const key = s.getenv("WEREWOLF_PROTECTED_IMAGE_KEY") orelse return s.refuse(
            "WEREWOLF_PROTECTED_IMAGE_KEY is required",
            .{},
        );
        try sys.write(
            s,
            try s.gpa.print("{s}.sig", .{head}),
            try catalog.sign(s, try sys.read(s, head, 4 << 20), key),
        );
        _ = try verify(s, t, assets, certificate);
        try exported.append(s.gpa, entry);
    }
    return exported.items;
}

fn assetRecord(s: *Sys, assets: []const u8, asset: []const u8) !Json {
    const r = try sys.record(s, try sys.join(s, &.{ assets, asset }));
    return json.from(
        s.gpa,
        .{ .asset = asset, .sha256 = try s.gpa.dupe(u8, &r.sha256), .size = r.size },
    );
}

/// verify checks a legacy release's assets against their signed manifest:
/// the profile, every file's bytes, nothing more, and tests that describe
/// this exact candidate. It returns the manifest.
pub fn verify(s: *Sys, t: images.Images, assets: []const u8, certificate: []const u8) !Json {
    var heads: std.ArrayList([]const u8) = .empty;
    for (try sys.list(
        s,
        assets,
    )) |n| if (mem.endsWith(u8, n, "-legacy-boot-downloads.json")) try heads.append(s.gpa, n);
    if (heads.items.len != 1) return s.refuse(
        "missing or ambiguous legacy downloads manifest",
        .{},
    );
    const head_name = heads.items[0];
    const head = try sys.join(s, &.{ assets, head_name });
    const bytes = try sys.read(s, head, 1 << 20);
    try catalog.verify(
        s,
        bytes,
        try sys.read(s, try s.gpa.print("{s}.sig", .{head}), 512),
        certificate,
    );
    const manifest = try json.parse(s.gpa, bytes);
    const p = try prefix(s, t, try json.text(manifest, "form"), try json.text(manifest, "arch"));
    if (!t.identity(
        try json.text(manifest, "form"),
        try json.text(manifest, "arch"),
        try json.text(manifest, "boot_profile"),
    ))
        return s.refuse("unsupported published image identity", .{});
    const listed = json.object(try json.field(
        manifest,
        "files",
    )) catch return s.refuse("invalid signed legacy profile", .{});
    var with_notes: usize = 0;
    for (release_notes) |n| with_notes += @intFromBool(listed.get(n) != null);
    var valid = mem.eql(u8, json.text(manifest, "format") catch "", format) and
        mem.eql(u8, json.text(manifest, "boot_profile") catch "", "legacy-boot") and
        json.eql(json.get(manifest, "disabled") orelse .null, try disabledJson(s)) and
        listed.get("tests.json") != null and
        (with_notes == 0 or with_notes == release_notes.len);
    for (files) |f| valid = valid and listed.get(f) != null;
    for (listed.keys()) |k| valid = valid and (isFile(k) or mem.eql(u8, k, "tests.json") or
        images.has(&release_notes, k));
    if (!valid) return s.refuse("invalid signed legacy profile", .{});
    var expected: std.ArrayList([]const u8) = .empty;
    try expected.appendSlice(s.gpa, &.{ head_name, try s.gpa.print("{s}.sig", .{head_name}) });
    var it = listed.iterator();
    while (it.next()) |e| {
        const asset = try assetName(s, p, e.key_ptr.*);
        if (!json.eql(
            e.value_ptr.*,
            try assetRecord(s, assets, asset),
        )) return s.refuse("legacy download differs from signed bytes", .{});
        try expected.append(s.gpa, asset);
    }
    const present = try sys.list(s, assets);
    if (present.len != expected.items.len) return s.refuse("unexpected legacy release assets", .{});
    for (present) |n| if (!images.has(
        expected.items,
        n,
    )) return s.refuse("unexpected legacy release assets", .{});
    const report = try json.field(manifest, "tests");
    const report_asset = try sys.join(
        s,
        &.{ assets, try json.text(listed.get("tests.json").?, "asset") },
    );
    if (!json.eql(try sys.readJson(s, report_asset, 64 << 10), report) or
        !allTrue(json.get(report, "checks") orelse .null))
        return s.refuse("legacy release tests are incomplete", .{});
    var candidate = try json.parse(s.gpa, try json.encode(s.gpa, manifest));
    _ = candidate.object.orderedRemove("tests");
    _ = candidate.object.orderedRemove("provenance");
    var records: json.Map = .empty;
    var rit = listed.iterator();
    while (rit.next()) |e| if (isFile(
        e.key_ptr.*,
    )) try records.put(s.gpa, e.key_ptr.*, try json.from(s.gpa, .{
        .sha256 = try json.field(e.value_ptr.*, "sha256"),
        .size = try json.field(e.value_ptr.*, "size"),
    }));
    try candidate.object.put(s.gpa, "files", .{ .object = records });
    if (!mem.eql(u8, json.text(report, "boot_profile") catch "", "legacy-boot") or
        !mem.eql(
            u8,
            json.text(report, "manifest") catch "",
            &sys.sha256(try json.encode(s.gpa, candidate)),
        ))
        return s.refuse("legacy tests describe another candidate", .{});
    return manifest;
}

/// publish uploads each exported legacy release, objects before its heads,
/// keeping its signed receipt as the profile's release floor, and returns
/// the legacy rows of the boot profile catalog.
pub fn publish(
    s: *Sys,
    t: images.Images,
    exported: []const Json,
    store: Store,
    certificate: []const u8,
) ![]Json {
    var rows: std.ArrayList(Json) = .empty;
    {
        const work = try sys.scratch(s, null, "ww-legacy-index-");
        defer sys.remove(s, work);
        const previous = try sys.join(s, &.{ work, "index.json" });
        if (try store.fetch(s, "boot-profiles.json", previous)) {
            const signed = try catalog.opened(s, try sys.read(s, previous, 4 << 20), certificate);
            if (!mem.eql(
                u8,
                json.text(signed, "format") catch "",
                "werewolf-boot-profiles/1",
            )) return s.refuse("invalid prior boot profile catalog", .{});
            for (try json.items(try json.field(signed, "legacy_boot"))) |row| {
                const name = try json.text(row, "form");
                if (!t.hasForm(name)) {
                    if (images.has(t.catalog_forms, name)) try putRow(s, &rows, row);
                    continue;
                }
                if (!t.identity(
                    name,
                    try json.text(row, "arch"),
                    try json.text(row, "boot_profile"),
                )) return s.refuse("unsupported published image identity", .{});
                try putRow(s, &rows, row);
            }
        }
    }
    const public = try catalog.public(s);
    for (exported) |target| {
        const directory = try json.text(target, "assets");
        const manifest = try verify(s, t, directory, certificate);
        const name = try json.text(manifest, "form");
        const arch = try json.text(manifest, "arch");
        const namespace = try s.gpa.print("legacy-boot/{s}/{s}", .{ try s.variantKey(name), arch });
        const head = try sys.join(
            s,
            &.{ directory, try s.gpa.print("{s}-downloads.json", .{try prefix(s, t, name, arch)}) },
        );
        const head_bytes = try sys.read(s, head, 1 << 20);
        const descriptor = sys.sha256(head_bytes);
        const receipt_key = try s.gpa.print("{s}/latest/accepted.json", .{namespace});
        {
            const work = try sys.scratch(s, null, "ww-legacy-floor-");
            defer sys.remove(s, work);
            const receipt = try sys.join(s, &.{ work, "accepted.json" });
            if (try store.fetch(s, receipt_key, receipt)) {
                const previous = try sys.readJson(s, receipt, 4 << 20);
                const raw = try json.text(previous, "manifest");
                try catalog.verify(
                    s,
                    raw,
                    try catalog.unhex(s, try json.text(previous, "signature")),
                    certificate,
                );
                const old = try json.parse(s.gpa, raw);
                const old_serial = try json.text(old, "serial");
                const serial = try json.text(manifest, "serial");
                if (!mem.eql(u8, try json.text(old, "form"), name) or
                    !mem.eql(u8, try json.text(old, "arch"), arch) or
                    !mem.eql(u8, try json.text(old, "boot_profile"), "legacy-boot") or
                    mem.order(u8, old_serial, serial) == .gt or
                    (mem.eql(u8, old_serial, serial) and !mem.eql(u8, raw, head_bytes)))
                    return s.refuse(
                        "legacy release would lower or reuse its signed release floor",
                        .{},
                    );
            }
        }
        for (try sys.list(s, directory)) |file| {
            const path = try sys.join(s, &.{ directory, file });
            const key = try s.gpa.print("{s}/objects/{s}/{s}", .{ namespace, &descriptor, file });
            const work = try sys.scratch(s, null, "ww-legacy-object-");
            defer sys.remove(s, work);
            const existing = try sys.join(s, &.{ work, "object" });
            const mine = try sys.record(s, path);
            if (try store.fetch(s, key, existing)) {
                if (!(try sys.record(
                    s,
                    existing,
                )).eql(mine)) return s.refuse("immutable legacy object collision", .{});
            } else {
                try store.upload(s, key, path, true);
            }
            if (!try store.fetch(s, key, existing) or !(try sys.record(s, existing)).eql(mine))
                return s.refuse("public legacy object differs from GitHub asset", .{});
            if (store.remote()) try sys.download(
                s,
                try s.gpa.print("{s}/{s}", .{ public, key }),
                try sys.join(s, &.{ work, "public" }),
                mine.size,
                mine,
            );
        }
        {
            const work = try sys.scratch(s, null, "ww-legacy-receipt-");
            defer sys.remove(s, work);
            const receipt = try sys.join(s, &.{ work, "accepted.json" });
            try sys.writeJson(s, receipt, try json.from(s.gpa, .{
                .manifest = head_bytes,
                .signature = try sys.hexAlloc(
                    s.gpa,
                    try sys.read(s, try s.gpa.print("{s}.sig", .{head}), 512),
                ),
            }));
            try store.upload(s, receipt_key, receipt, false);
        }
        for ([_][]const u8{ try s.gpa.print("{s}.sig", .{head}), head }) |path|
            try store.upload(
                s,
                try s.gpa.print("{s}/latest/{s}", .{ namespace, std.fs.path.basename(path) }),
                path,
                false,
            );
        try putRow(s, &rows, try json.from(s.gpa, .{
            .form = name,
            .variants = try s.variantNames(),
            .arch = arch,
            .boot_profile = "legacy-boot",
            .serial = try json.field(manifest, "serial"),
            .object = try s.gpa.print("{s}/objects/{s}", .{ namespace, &descriptor }),
            .files = try json.field(manifest, "files"),
        }));
    }
    mem.sort(Json, rows.items, {}, byFormArch);
    return rows.items;
}

/// putRow replaces the row of row's form and arch, or adds it.
fn putRow(s: *Sys, rows: *std.ArrayList(Json), row: Json) !void {
    const selection = try sys.selection(s, row);
    for (rows.items) |*r| {
        if (!sys.selectionMatches(r.*, selection)) continue;
        if (mem.eql(u8, try json.text(r.*, "form"), try json.text(row, "form")) and
            mem.eql(u8, try json.text(r.*, "arch"), try json.text(row, "arch")))
        {
            r.* = row;
            return;
        }
    }
    try rows.append(s.gpa, row);
}

fn byFormArch(_: void, a: Json, b: Json) bool {
    return switch (mem.order(u8, json.text(a, "form") catch "", json.text(b, "form") catch "")) {
        .lt => true,
        .gt => false,
        .eq => mem.order(u8, json.text(a, "arch") catch "", json.text(b, "arch") catch "") == .lt,
    };
}

const testing = std.testing;
const fixture = @import("fixture.zig");

/// Legacy is a store and verified legacy candidates, signed with a test
/// key: the release flow of the legacy-boot profile without its builds.
pub const Legacy = struct {
    f: fixture.Fixture,
    t: images.Images,
    keys: fixture.Keys,
    provenance: Json,
    store: Store,

    pub fn init(l: *Legacy) !void {
        try l.f.init();
        const s = &l.f.s;
        l.t = try images.load(s);
        l.keys = try fixture.keys(&l.f, "legacy");
        try l.f.env.put("WEREWOLF_PROTECTED_IMAGE_KEY", l.keys.key);
        try l.f.env.put("GITHUB_SHA", fixture.rep('a', 40));
        l.provenance = try json.from(s.gpa, .{
            .repository = "werewolf-linux/werewolf",
            .commit = fixture.rep('a', 40),
            .run = "https://github.com/werewolf-linux/werewolf/actions/runs/123",
            .attempt = "1",
        });
        l.store = Store.init(l.f.path("store"));
    }

    pub fn deinit(l: *Legacy) void {
        l.f.deinit();
    }

    pub fn candidate(
        l: *Legacy,
        name: []const u8,
        serial: []const u8,
        version: []const u8,
    ) ![]const u8 {
        return testCandidate(&l.f, name, serial, version);
    }

    fn manifest(l: *Legacy, dir: []const u8, name: []const u8, serial: []const u8) !void {
        return testManifest(&l.f.s, dir, name, serial);
    }

    fn targets(l: *Legacy, dir: []const u8, status: []const u8) ![]const Json {
        return testTargets(&l.f.s, dir, status);
    }

    /// exported is the export of a candidate, without a store.
    pub fn exported(l: *Legacy, dir: []const u8) !Json {
        const s = &l.f.s;
        const parent = std.fs.path.dirname(dir).?;
        const out = try exportVerified(
            s,
            l.t,
            parent,
            l.f.path(try s.gpa.print("assets-{s}", .{std.fs.path.basename(parent)})),
            l.provenance,
            try l.targets(dir, "build"),
            l.keys.crt,
            null,
        );
        try testing.expectEqual(@as(usize, 1), out.len);
        return out[0];
    }

    fn publishOne(l: *Legacy, e: Json) ![]Json {
        return publish(&l.f.s, l.t, &.{e}, l.store, l.keys.crt);
    }
};

/// testCandidate is a verified legacy build of form at serial under f's
/// root, whose one package is at version.
pub fn testCandidate(
    f: *fixture.Fixture,
    name: []const u8,
    serial: []const u8,
    version: []const u8,
) ![]const u8 {
    const s = &f.s;
    const gpa = s.gpa;
    const dir = f.path(try gpa.print("verified-{s}/{s}", .{ serial, name }));
    for (files) |file| try sys.write(
        s,
        try sys.join(s, &.{ dir, file }),
        try gpa.print("{s}{s}", .{ file, serial }),
    );
    try sys.writeJson(s, try sys.join(s, &.{ dir, "packages.json" }), try json.from(gpa, .{
        .format = notes.format,
        .form = name,
        .variants = try s.variantNames(),
        .arch = "x86_64",
        .packages = &[_]Json{try json.from(
            gpa,
            .{
                .scope = "runtime",
                .name = "example",
                .version = version,
                .checksum = try gpa.dupe(u8, &sys.sha256(version)),
            },
        )},
        .images = &[_]Json{},
    }));
    try sys.write(
        s,
        try sys.join(s, &.{ dir, "cmdline" }),
        "werewolf.disable=secureboot,tpm,ipe\n",
    );
    try testManifest(s, dir, name, serial);
    return dir;
}

/// testTargets are the resolved targets a candidate in dir was built for.
pub fn testTargets(s: *Sys, dir: []const u8, status: []const u8) ![]const Json {
    var target = try sys.readJson(s, try sys.join(s, &.{ dir, "manifest.json" }), 1 << 20);
    try target.object.put(s.gpa, "status", .{ .string = status });
    return s.gpa.dupe(Json, &.{target});
}

/// testManifest writes dir's manifest and its passing tests.
fn testManifest(s: *Sys, dir: []const u8, name: []const u8, serial: []const u8) !void {
    var records: json.Map = .empty;
    for (files) |file| try records.put(
        s.gpa,
        file,
        try (try sys.record(s, try sys.join(s, &.{ dir, file }))).toJson(s.gpa),
    );
    try sys.writeJson(s, try sys.join(s, &.{ dir, "manifest.json" }), try json.from(s.gpa, .{
        .format = format,
        .form = name,
        .variants = try s.variantNames(),
        .arch = "x86_64",
        .boot_profile = "legacy-boot",
        .disabled = try disabledJson(s),
        .serial = serial,
        .commit = fixture.rep(
            'a',
            40,
        ),
        .inputs = fixture.rep('b', 64),
        .raw_size = 8 << 30,
        .files = records,
    }));
    try sys.writeJson(s, try sys.join(s, &.{ dir, "tests.json" }), try json.from(s.gpa, .{
        .boot_profile = "legacy-boot",
        .manifest = try s.gpa.dupe(
            u8,
            &try sys.sha(s, try sys.join(s, &.{ dir, "manifest.json" })),
        ),
        .checks = try checksJson(s),
    }));
}

test "a retry reuses the signed legacy release without lowering its floor" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    const dir = try l.candidate("minimal", "20261017T010000Z", "1");
    const first = try l.exported(dir);
    _ = try l.publishOne(first);
    var provenance = try json.parse(s.gpa, try json.encode(s.gpa, l.provenance));
    try provenance.object.put(s.gpa, "attempt", .{ .string = "2" });
    const again = try exportVerified(
        s,
        l.t,
        std.fs.path.dirname(dir).?,
        l.f.path("retry-assets"),
        provenance,
        try l.targets(dir, "build"),
        l.keys.crt,
        l.store,
    );
    try testing.expectEqual(@as(usize, 1), again.len);
    const a = try json.text(first, "assets");
    const b = try json.text(again[0], "assets");
    const names = try sys.list(s, a);
    try testing.expectEqual(names.len, (try sys.list(s, b)).len);
    for (names) |n| try testing.expectEqualStrings(
        try sys.read(s, try sys.join(s, &.{ a, n }), 1 << 20),
        try sys.read(s, try sys.join(s, &.{ b, n }), 1 << 20),
    );
    _ = try l.publishOne(again[0]);
}

test "a retry refuses a damaged published legacy asset" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    const dir = try l.candidate("minimal", "20261017T010000Z", "1");
    const rows = try l.publishOne(try l.exported(dir));
    const asset = l.f.path(try s.gpa.print(
        "store/{s}/{s}",
        .{
            try json.text(rows[0], "object"),
            try json.text(json.get(json.get(rows[0], "files").?, "disk.qcow2").?, "asset"),
        },
    ));
    try sys.write(s, asset, "corrupted");
    try testing.expectError(
        error.Refused,
        exportVerified(
            s,
            l.t,
            std.fs.path.dirname(dir).?,
            l.f.path("retry-assets"),
            l.provenance,
            try l.targets(dir, "build"),
            l.keys.crt,
            l.store,
        ),
    );
    try testing.expectEqualStrings("legacy download differs from signed bytes", s.why.text);
}

test "a legacy artifact must match the trusted resolved plan" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    const dir = try l.candidate("minimal", "20261017T010000Z", "1");
    for ([_][2][]const u8{
        .{ "inputs", fixture.rep('c', 64) },
        .{ "serial", "20261017T030000Z" },
        .{ "status", "resolution failed" },
    }, 0..) |change, i| {
        const targets = try l.targets(dir, "build");
        var target = targets[0];
        try target.object.put(s.gpa, change[0], .{ .string = change[1] });
        try testing.expectError(
            error.Refused,
            exportVerified(
                s,
                l.t,
                std.fs.path.dirname(dir).?,
                l.f.path(try s.gpa.print("foreign-{d}", .{i})),
                l.provenance,
                &.{target},
                l.keys.crt,
                null,
            ),
        );
        try testing.expectEqualStrings(
            "legacy artifact differs from this workflow's resolved target",
            s.why.text,
        );
    }
}

test "signed legacy assets name their profile and keep their own namespace" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    for (l.t.forms, 0..) |name, i| {
        const dir = try l.candidate(name, try s.gpa.print("20261017T01000{d}Z", .{i}), "1");
        const e = try l.exported(dir);
        const assets = try json.text(e, "assets");
        try testing.expectEqualStrings(
            "legacy-boot",
            try json.text(try verify(s, l.t, assets, l.keys.crt), "boot_profile"),
        );
        try testing.expect(sys.isFile(
            s,
            try sys.join(s, &.{ assets, try s.gpa.print("{s}-x86_64-legacy-boot.qcow2", .{name}) }),
        ));
        const rows = try l.publishOne(e);
        try testing.expectStringStartsWith(
            try json.text(rows[rows.len - 1], "object"),
            "legacy-boot/",
        );
        try testing.expect(!sys.exists(
            s,
            l.f.path(try s.gpa.print("store/{s}/qemu/x86_64/latest/boot.json", .{name})),
        ));
    }
}

test "legacy variant publications keep their siblings and accepted release floors" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    const base_rows = try l.publishOne(try l.exported(try l.candidate(
        "minimal",
        "20261017T010000Z",
        "1",
    )));
    try sys.write(s, l.f.path(
        "store/boot-profiles.json",
    ), try catalog.envelope(s, try json.from(s.gpa, .{
        .format = "werewolf-boot-profiles/" ++
            "1",
        .secure_boot = &[_]Json{},
        .legacy_boot = base_rows,
    }), l.keys.key));
    s.variants = "ssh";
    const ssh = try l.exported(try l.candidate("minimal", "20261017T010001Z", "1"));
    const rows = try l.publishOne(ssh);
    try testing.expectEqual(@as(usize, 2), rows.len);
    var ordinary: ?Json = null;
    var selected: ?Json = null;
    for (rows) |row| {
        if (sys.selectionMatches(row, "ssh")) selected = row;
        if (sys.selectionMatches(row, "")) ordinary = row;
    }
    try testing.expect(ordinary != null and selected != null);
    try testing.expect(!mem.eql(
        u8,
        try json.text(ordinary.?, "object"),
        try json.text(selected.?, "object"),
    ));
    try testing.expect(sys.isFile(
        s,
        l.f.path("store/legacy-boot/minimal/x86_64/latest/accepted.json"),
    ));
    try testing.expect(sys.isFile(
        s,
        l.f.path("store/legacy-boot/minimal-variants-ssh/x86_64/latest/accepted.json"),
    ));
}

test "the prior catalog keeps selected forms and retires excluded ones" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    const rows = try l.publishOne(try l.exported(try l.candidate(
        "minimal",
        "20261017T010000Z",
        "1",
    )));
    var all: std.ArrayList(Json) = .empty;
    try all.appendSlice(s.gpa, rows);
    for ([_][]const u8{ "retired-form", "removed-form" }) |name| {
        var retired = try json.parse(s.gpa, try json.encode(s.gpa, rows[0]));
        try retired.object.put(s.gpa, "form", .{ .string = name });
        try all.append(s.gpa, retired);
    }
    try sys.write(s, l.f.path(
        "store/boot-profiles.json",
    ), try catalog.envelope(s, try json.from(s.gpa, .{
        .format = "werewolf-boot-profiles/1",
        .secure_boot = &[_]Json{},
        .legacy_boot = all.items,
    }), l.keys.key));
    const kept = try publish(s, l.t, &.{}, l.store, l.keys.crt);
    try testing.expectEqual(rows.len, kept.len);
    for (rows, kept) |a, b| try testing.expect(json.eql(a, b));
}

test "a changed candidate or a nonboolean check is never signed" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    const dir = try l.candidate("minimal", "20261017T010000Z", "1");
    try sys.write(s, try sys.join(s, &.{ dir, "disk.qcow2" }), "tampered");
    try testing.expectError(
        error.Refused,
        exportVerified(
            s,
            l.t,
            std.fs.path.dirname(dir).?,
            l.f.path("tampered"),
            l.provenance,
            try l.targets(dir, "build"),
            l.keys.crt,
            null,
        ),
    );
    try testing.expectStringStartsWith(s.why.text, "legacy image differs from its manifest");
    const other = try l.candidate("prod-ssh", "20261017T010001Z", "1");
    const tests_path = try sys.join(s, &.{ other, "tests.json" });
    var report = try sys.readJson(s, tests_path, 4096);
    try report.object.getPtr("checks").?.object.put(s.gpa, "uefi_boot", .{ .integer = 1 });
    try sys.writeJson(s, tests_path, report);
    try testing.expectError(
        error.Refused,
        exportVerified(
            s,
            l.t,
            std.fs.path.dirname(other).?,
            l.f.path("nonboolean"),
            l.provenance,
            try l.targets(other, "build"),
            l.keys.crt,
            null,
        ),
    );
    try testing.expectEqualStrings("legacy artifact has incomplete or foreign tests", s.why.text);
}

fn mirror(
    f: *fixture.Fixture,
    s: *Sys,
    url: []const u8,
    to: []const u8,
    limit: u64,
    expected: ?sys.Record,
) anyerror!void {
    const key = url[(try catalog.public(s)).len + 1 ..];
    const data = try sys.read(s, try sys.join(s, &.{ f.text, key }), 1 << 20);
    try testing.expect(data.len <= limit);
    try testing.expect(expected.?.eql(.{ .sha256 = sys.sha256(data), .size = data.len }));
    const out = try std.Io.Dir.cwd().createFile(s.io, to, .{ .exclusive = true });
    defer out.close(s.io);
    try out.writeStreamingAll(s.io, data);
    f.state += 1;
}

test "public verification uses a fresh file and allows retries" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    const e = try l.exported(try l.candidate("minimal", "20261017T010000Z", "1"));
    var bucket: fixture.FakeBucket = .{ .root = l.f.path("bucket") };
    l.f.bucket = &bucket;
    l.f.text = bucket.root;
    l.f.fetch_answer = mirror;
    const remote = Store.init("s3://legacy-tests");
    const first = try publish(s, l.t, &.{e}, remote, l.keys.crt);
    const again = try publish(s, l.t, &.{e}, remote, l.keys.crt);
    try testing.expectEqual(first.len, again.len);
    for (first, again) |a, b| try testing.expect(json.eql(a, b));
    try testing.expect(l.f.state > 0);
}

test "a secure identity cannot be labeled legacy" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    const dir = try l.candidate("minimal", "20261017T010000Z", "1");
    var manifest = try sys.readJson(s, try sys.join(s, &.{ dir, "manifest.json" }), 1 << 20);
    try sys.write(s, try sys.join(s, &.{ dir, "cmdline" }), "werewolf.secure=1 werewolf.tpm=1\n");
    try manifest.object.getPtr("files").?.object.put(
        s.gpa,
        "cmdline",
        try (try sys.record(s, try sys.join(s, &.{ dir, "cmdline" }))).toJson(s.gpa),
    );
    try testing.expectError(error.Refused, validate(s, l.t, manifest, dir));
    try testing.expectEqualStrings("legacy image has an incompatible boot identity", s.why.text);
    try manifest.object.put(s.gpa, "boot_profile", .{ .string = "secure-boot" });
    try testing.expectError(error.Refused, validate(s, l.t, manifest, dir));
    try testing.expectEqualStrings("invalid legacy boot manifest", s.why.text);
}

test "signed asset tampering is refused" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    const assets = try json.text(
        try l.exported(try l.candidate("minimal", "20261017T010000Z", "1")),
        "assets",
    );
    try sys.write(s, try sys.join(s, &.{ assets, "minimal-x86_64-legacy-boot.qcow2" }), "tampered");
    try testing.expectError(error.Refused, verify(s, l.t, assets, l.keys.crt));
    try testing.expectEqualStrings("legacy download differs from signed bytes", s.why.text);
}

test "the release floor survives a torn head and refuses rollback" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    const old = try l.exported(try l.candidate("minimal", "20261017T010000Z", "1"));
    const newer = try l.exported(try l.candidate("minimal", "20261017T020000Z", "1"));
    _ = try l.publishOne(newer);
    try testing.expectError(error.Refused, l.publishOne(old));
    try testing.expectEqualStrings(
        "legacy release would lower or reuse its signed release floor",
        s.why.text,
    );
    // The accepted receipt keeps the floor even if the JSON and signature heads tear.
    try sys.write(
        s,
        l.f.path(
            "store/legacy-boot/minimal/x86_64/latest/minimal-x86_64-legacy-boot-downloads.json",
        ),
        "interrupted write",
    );
    try testing.expectError(error.Refused, l.publishOne(old));
    try testing.expectEqualStrings(
        "legacy release would lower or reuse its signed release floor",
        s.why.text,
    );
}

test "a serial cannot authorize different bytes, and an identical retry is idempotent" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    const dir = try l.candidate("minimal", "20261017T010000Z", "1");
    const e = try l.exported(dir);
    _ = try l.publishOne(e);
    _ = try l.publishOne(e);
    try sys.write(
        s,
        try sys.join(s, &.{ dir, "disk.qcow2" }),
        "a different disk under the same serial",
    );
    try l.manifest(dir, "minimal", "20261017T010000Z");
    const conflicting = try exportVerified(
        s,
        l.t,
        std.fs.path.dirname(dir).?,
        l.f.path("conflicting-assets"),
        l.provenance,
        try l.targets(dir, "build"),
        l.keys.crt,
        null,
    );
    try testing.expectError(error.Refused, l.publishOne(conflicting[0]));
    try testing.expectEqualStrings(
        "legacy release would lower or reuse its signed release floor",
        s.why.text,
    );
}

test "package changes compare with the signed previous legacy release" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    _ = try l.publishOne(try l.exported(try l.candidate("minimal", "20261017T010000Z", "1")));
    const dir = try l.candidate("minimal", "20261017T010001Z", "2");
    const second = try exportVerified(
        s,
        l.t,
        std.fs.path.dirname(dir).?,
        l.f.path("second"),
        l.provenance,
        try l.targets(dir, "build"),
        l.keys.crt,
        l.store,
    );
    const assets = try json.text(second[0], "assets");
    const signed = try verify(s, l.t, assets, l.keys.crt);
    const path = try sys.join(
        s,
        &.{
            assets,
            try json.text(json.get(json.get(signed, "files").?, "release-notes.json").?, "asset"),
        },
    );
    const release = try sys.readJson(s, path, 1 << 20);
    try testing.expectEqualStrings(
        "20261017T010000Z",
        try json.text(json.get(release, "previous").?, "serial"),
    );
    const changes = try json.items(json.get(release, "packages").?);
    try testing.expectEqual(@as(usize, 1), changes.len);
    try testing.expectEqualStrings("updated", try json.text(changes[0], "kind"));
    try testing.expectEqualStrings("1", try json.text(json.get(changes[0], "before").?, "version"));
    try testing.expectEqualStrings("2", try json.text(json.get(changes[0], "after").?, "version"));
    try sys.write(s, path, "{}");
    try testing.expectError(error.Refused, verify(s, l.t, assets, l.keys.crt));
    try testing.expectEqualStrings("legacy download differs from signed bytes", s.why.text);
}

test "the previous package inventory must match its signed digest" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    const rows = try l.publishOne(try l.exported(try l.candidate(
        "minimal",
        "20261017T010000Z",
        "1",
    )));
    try sys.write(
        s,
        l.f.path(try s.gpa.print(
            "store/{s}/minimal-x86_64-legacy-boot-packages.json",
            .{try json.text(rows[0], "object")},
        )),
        "{}",
    );
    const dir = try l.candidate("minimal", "20261017T010001Z", "1");
    try testing.expectError(
        error.Refused,
        exportVerified(
            s,
            l.t,
            std.fs.path.dirname(dir).?,
            l.f.path("second"),
            l.provenance,
            try l.targets(dir, "build"),
            l.keys.crt,
            l.store,
        ),
    );
    try testing.expectEqualStrings(
        "previous legacy package inventory is missing or changed",
        s.why.text,
    );
}

fn answerReceipt(f: *fixture.Fixture, url: []const u8, limit: usize) anyerror!?sys.Got {
    _ = limit;
    try testing.expect(mem.endsWith(u8, url, "/latest/accepted.json"));
    return .{ .body = f.text };
}

test "only a signed matching legacy receipt can skip an unchanged build" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    _ = try l.publishOne(try l.exported(try l.candidate("minimal", "20261017T010000Z", "1")));
    const raw = try sys.read(
        s,
        l.f.path("store/legacy-boot/minimal/x86_64/latest/accepted.json"),
        1 << 20,
    );
    l.f.text = raw;
    l.f.get_answer = answerReceipt;
    try testing.expect(try settled(s, l.t, "minimal", "x86_64", fixture.rep('b', 64), l.keys.crt));
    try testing.expect(!try settled(s, l.t, "minimal", "x86_64", fixture.rep('c', 64), l.keys.crt));
    try testing.expectError(
        error.Refused,
        settled(s, l.t, "prod-ssh", "x86_64", fixture.rep('b', 64), l.keys.crt),
    );
    try testing.expectEqualStrings("foreign legacy publication receipt", s.why.text);
    var tampered = try json.parse(s.gpa, raw);
    try tampered.object.put(
        s.gpa,
        "manifest",
        .{ .string = try mem.replaceOwned(
            u8,
            s.gpa,
            try json.text(tampered, "manifest"),
            fixture.rep('b', 64),
            fixture.rep('c', 64),
        ) },
    );
    l.f.text = try json.encode(s.gpa, tampered);
    try testing.expectError(
        error.Refused,
        settled(s, l.t, "minimal", "x86_64", fixture.rep('c', 64), l.keys.crt),
    );
    try testing.expectStringStartsWith(s.why.text, "signature does not verify");
}

test "unchanged profiles and unsupported architectures neither build nor boot" {
    var l: Legacy = undefined;
    try l.init();
    defer l.deinit();
    const s = &l.f.s;
    try sys.writeJson(s, l.f.path("snapshot/plan.json"), try json.parse(s.gpa,
        \\{"arch":"aarch64","targets":[{"form":"minimal","arch":"aarch64","status":"unsupported architecture"},
        \\{"form":"prod-ssh","arch":"aarch64","status":"unchanged","legacy_status":"unchanged"}]}
    ));
    l.f.answer = struct {
        fn refuse(_: *fixture.Fixture, argv: []const []const u8) anyerror!?sys.Result {
            _ = argv;
            return error.TestRanACommand;
        }
    }.refuse;
    const tree: plan.Tree = .{ .native = false, .howl = "howl" };
    try testing.expect(!try build(s, l.t, tree, l.f.path("snapshot"), l.f.path("built")));
    try testing.expect(!try check(
        s,
        l.t,
        tree,
        l.f.path("snapshot"),
        l.f.path("first"),
        l.f.path("second"),
        l.f.path("checked"),
    ));
    const results = try json.items(try sys.readJson(s, l.f.path("checked/results.json"), 4096));
    try testing.expectEqualStrings("unsupported architecture", try json.text(results[0], "status"));
    try testing.expectEqualStrings("unchanged", try json.text(results[1], "status"));
}
