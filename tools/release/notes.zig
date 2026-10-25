//! notes are the deterministic package inventory of a form image and its
//! release notes: what changed since the target's last publication.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const catalog = @import("catalog.zig");

pub const format = "werewolf-form-packages/1";

const scopes = [_][2][]const u8{
    .{ "runtime", "Image packages" },
    .{ "local", "Packages built from form recipes" },
    .{ "kernel", "Kernel configuration inputs" },
    .{ "test", "Additional integration test packages" },
    .{ "build:kernel", "Kernel build environment" },
    .{ "build:stub", "EFI build environment" },
    .{ "boot", "Boot package inputs" },
};

/// Local is a package built from a form's recipe, as its APK names it.
pub const Local = struct { name: []const u8, version: []const u8, checksum: []const u8 };

/// inventory normalizes a snapshot's resolved inputs for one target:
/// other architectures, mirror URLs and resolver order drop out, and a
/// test package identical to the runtime one is listed once.
pub fn inventory(
    s: *Sys,
    snapshot: []const u8,
    name: []const u8,
    arch: []const u8,
    local: []const Local,
) !Json {
    const gpa = s.gpa;
    const mapping = try json.object(try sys.readJson(
        s,
        try sys.join(s, &.{ snapshot, "melange.json" }),
        1 << 20,
    ));
    var locks: std.ArrayList([]const u8) = .empty;
    const parent = std.fs.path.dirname(snapshot) orelse ".";
    for ([_][]const u8{ parent, snapshot }) |dir| for (try sys.list(s, dir)) |file| {
        if (mem.endsWith(
            u8,
            file,
            ".lock.json",
        )) try locks.append(gpa, try sys.join(s, &.{ dir, file }));
    };
    mem.sort([]const u8, locks.items, {}, sys.pathLess);
    var packages: std.ArrayList(Json) = .empty;
    var runtime: std.ArrayList(Json) = .empty;
    for (locks.items) |path| {
        const file = std.fs.path.basename(path);
        const scope = if (mem.eql(u8, file, try gpa.print("{s}.lock.json", .{name})))
            "runtime"
        else if (mem.eql(u8, file, try gpa.print("{s}-dev.lock.json", .{name})))
            "test"
        else if (mem.eql(u8, file, "kernel.lock.json") or mem.eql(u8, file, "boot.lock.json"))
            file[0 .. file.len - ".lock.json".len]
        else if (mem.eql(u8, file, "stub-builder.lock.json"))
            "build:stub"
        else blk: {
            // The last recipe naming a lock wins, as Python's inverted dict.
            var recipe: ?[]const u8 = null;
            var it = mapping.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.* == .string and
                    mem.eql(u8, e.value_ptr.string, file)) recipe = e.key_ptr.*;
            }
            break :blk try gpa.print("build:{s}", .{recipe orelse
                return s.refuse("unknown form image package lock: {s}", .{file})});
        };
        const lock = try sys.readJson(s, path, 64 << 20);
        for (try json.items(try json.field(try json.field(lock, "contents"), "packages"))) |p| {
            if (!mem.eql(u8, try json.text(p, "architecture"), arch)) continue;
            // Mirror URLs and resolver ordering are not package content changes.
            var content: json.Map = .empty;
            if (json.get(p, "checksum")) |c| try content.put(gpa, "checksum", c);
            for ([_][]const u8{ "control", "data" }) |k| if (json.get(p, k)) |part|
                try content.put(gpa, k, try json.field(part, "checksum"));
            if (content.count() == 0) return s.refuse("package has no content identity", .{});
            const item = try json.from(gpa, .{
                .scope = scope,
                .name = try json.text(p, "name"),
                .version = try json.text(p, "version"),
                .checksum = try gpa.dupe(
                    u8,
                    &sys.sha256(try json.encode(gpa, .{ .object = content })),
                ),
            });
            try packages.append(gpa, item);
            if (mem.eql(u8, scope, "runtime")) try runtime.append(gpa, item);
        }
    }
    var kept: std.ArrayList(Json) = .empty;
    for (packages.items) |p| {
        if (mem.eql(u8, try json.text(p, "scope"), "test") and
            duplicate(runtime.items, p)) continue;
        try kept.append(gpa, p);
    }
    for (local) |l| try kept.append(gpa, try json.from(gpa, .{
        .scope = "local",
        .name = l.name,
        .version = l.version,
        .checksum = l.checksum,
    }));
    mem.sort(Json, kept.items, PairOrder{ .a = "scope", .b = "name" }, PairOrder.less);
    const lock = try sys.readJson(
        s,
        try sys.join(s, &.{ snapshot, try gpa.print("{s}.lock.json", .{name}) }),
        64 << 20,
    );
    var oci: std.ArrayList(Json) = .empty;
    for (try json.items(try json.field(
        try json.field(lock, "werewolf"),
        "images",
    ))) |p| try oci.append(gpa, try json.from(gpa, .{
        .form = try json.field(p, "form"),
        .service = try json.field(p, "service"),
        .ref = try json.field(p, "ref"),
        .digest = try json.field(p, "digest"),
    }));
    mem.sort(Json, oci.items, PairOrder{ .a = "form", .b = "service" }, PairOrder.less);
    const result = try json.from(gpa, .{
        .format = format,
        .form = name,
        .arch = arch,
        .packages = kept.items,
        .images = oci.items,
    });
    return validate(s, result, name, arch);
}

/// duplicate says whether runtime has p's name, version and checksum: the
/// test variant's copy of an image package.
fn duplicate(runtime: []const Json, p: Json) bool {
    const name = json.text(p, "name") catch return false;
    // The last runtime entry of a name wins, as a dict keeps it.
    var last: ?Json = null;
    for (runtime) |r| {
        if (mem.eql(u8, json.text(r, "name") catch "", name)) last = r;
    }
    const r = last orelse return false;
    return mem.eql(u8, json.text(r, "version") catch "", json.text(p, "version") catch "") and
        mem.eql(u8, json.text(r, "checksum") catch "", json.text(p, "checksum") catch "");
}

/// PairOrder sorts records by two string members, as Python sorts tuples.
const PairOrder = struct {
    a: []const u8,
    b: []const u8,

    fn less(o: PairOrder, x: Json, y: Json) bool {
        const xa = json.text(x, o.a) catch "";
        const ya = json.text(y, o.a) catch "";
        return switch (mem.order(u8, xa, ya)) {
            .lt => true,
            .gt => false,
            .eq => mem.order(u8, json.text(x, o.b) catch "", json.text(y, o.b) catch "") == .lt,
        };
    }
};

/// text is a name or version an inventory may hold: printable, one to
/// 4096 characters.
fn text(v: Json) bool {
    if (v != .string) return false;
    const n = std.unicode.utf8CountCodepoints(v.string) catch return false;
    return n > 0 and n <= 4096 and catalog.isPrintable(v.string);
}

/// validate refuses an inventory of another target, or with malformed or
/// repeated entries.
pub fn validate(s: *Sys, v: Json, name: []const u8, arch: []const u8) !Json {
    if (!json.hasKeys(v, &.{ "format", "form", "arch", "packages", "images" }) or
        !mem.eql(u8, json.text(v, "format") catch "", format) or
        !mem.eql(u8, json.text(v, "form") catch "", name) or
        !mem.eql(u8, json.text(v, "arch") catch "", arch))
        return s.refuse("wrong package inventory identity", .{});
    const packages = json.items(json.get(
        v,
        "packages",
    ).?) catch return s.refuse("invalid package inventory entry", .{});
    for (packages, 0..) |p, i| {
        if (!json.hasKeys(p, &.{ "scope", "name", "version", "checksum" }) or
            !text(json.get(p, "scope").?) or !text(json.get(p, "name").?) or
            !text(json.get(p, "version").?) or
            !catalog.isHex(json.text(p, "checksum") catch "", 64))
            return s.refuse("invalid package inventory entry", .{});
        for (packages[0..i]) |q| if (samePair(
            p,
            q,
            "scope",
            "name",
        )) return s.refuse("duplicate package inventory entry", .{});
    }
    const oci = json.items(json.get(
        v,
        "images",
    ).?) catch return s.refuse("invalid OCI inventory entry", .{});
    for (oci, 0..) |p, i| {
        if (!json.hasKeys(
            p,
            &.{ "form", "service", "ref", "digest" },
        )) return s.refuse("invalid OCI inventory entry", .{});
        for ([_][]const u8{
            "form",
            "service",
            "ref",
            "digest",
        }) |k| if (!text(json.get(p, k).?)) return s.refuse("invalid OCI inventory entry", .{});
        // An OCI reference pinned by digest: ...@sha256:HEX.
        const digest = json.get(p, "digest").?.string;
        const tail = "@sha256:".len + 64;
        if (digest.len <= tail or !mem.startsWith(u8, digest[digest.len - tail ..], "@sha256:") or
            !catalog.isHex(digest[digest.len - 64 ..], 64))
            return s.refuse("invalid OCI inventory entry", .{});
        for (oci[0..i]) |q| if (samePair(
            p,
            q,
            "form",
            "service",
        )) return s.refuse("duplicate OCI inventory entry", .{});
    }
    return v;
}

fn samePair(p: Json, q: Json, a: []const u8, b: []const u8) bool {
    return mem.eql(u8, json.text(p, a) catch "", json.text(q, a) catch "") and
        mem.eql(u8, json.text(p, b) catch "", json.text(q, b) catch "");
}

/// changes lists what differs between two inventories' entries, keyed by
/// two members: added, removed, updated, or rebuilt at the same version.
fn changes(
    gpa: Allocator,
    before: []const Json,
    after: []const Json,
    a: []const u8,
    b: []const u8,
) ![]Json {
    var keys: std.ArrayList(Json) = .empty;
    for ([_][]const Json{ before, after }) |side| for (side) |p| {
        for (keys.items) |k| {
            if (samePair(k, p, a, b)) break;
        } else try keys.append(gpa, p);
    };
    mem.sort(Json, keys.items, PairOrder{ .a = a, .b = b }, PairOrder.less);
    var out: std.ArrayList(Json) = .empty;
    for (keys.items) |k| {
        const left = lastWith(before, k, a, b);
        const right = lastWith(after, k, a, b);
        if (left != null and right != null and json.eql(left.?, right.?)) continue;
        var kind: []const u8 = if (left == null)
            "added"
        else if (right == null)
            "removed"
        else
            "updated";
        if (left != null and right != null) if (json.get(left.?, "version")) |v| {
            if (json.eql(v, json.get(right.?, "version") orelse .null)) kind = "rebuilt";
        };
        var change: json.Map = .empty;
        try change.put(gpa, a, json.get(k, a).?);
        try change.put(gpa, b, json.get(k, b).?);
        try change.put(gpa, "kind", .{ .string = kind });
        try change.put(gpa, "before", left orelse .null);
        try change.put(gpa, "after", right orelse .null);
        try out.append(gpa, .{ .object = change });
    }
    return out.items;
}

/// lastWith is the entry of side under k's key, the last if repeated, as
/// a dict built from the list keeps it.
fn lastWith(side: []const Json, k: Json, a: []const u8, b: []const u8) ?Json {
    var found: ?Json = null;
    for (side) |p| if (samePair(p, k, a, b)) {
        found = p;
    };
    return found;
}

pub const Candidate = struct {
    form: []const u8,
    provider: []const u8,
    arch: []const u8,
    serial: []const u8,
    commit: []const u8,
};

/// release is a candidate's notes against its target's previous
/// publication, whose inventory must be that release's own.
pub fn release(s: *Sys, c: Candidate, current: Json, previous: ?Json, old_inventory: ?Json) !Json {
    const gpa = s.gpa;
    _ = try validate(s, current, c.form, c.arch);
    if (previous) |p| {
        const prefix = if (mem.eql(u8, c.provider, "legacy-boot"))
            try gpa.print("legacy-boot/{s}/{s}/objects/", .{ c.form, c.arch })
        else
            try gpa.print("{s}/{s}/{s}/objects/", .{ c.form, c.provider, c.arch });
        if (!mem.startsWith(u8, json.text(p, "object") catch "", prefix) or old_inventory == null)
            return s.refuse("release notes need the matching previous package inventory", .{});
        _ = try validate(s, old_inventory.?, c.form, c.arch);
    } else if (old_inventory != null) {
        return s.refuse("initial release notes cannot have a previous inventory", .{});
    }
    const old_packages = if (old_inventory) |o|
        try json.items(json.get(o, "packages").?)
    else
        &[_]Json{};
    const old_images = if (old_inventory) |o|
        try json.items(json.get(o, "images").?)
    else
        &[_]Json{};
    const prior: Json = if (previous) |p| try json.from(gpa, .{
        .serial = try json.field(p, "serial"),
        .commit = try json.field(p, "commit"),
        .object = try json.field(p, "object"),
    }) else .null;
    return json.from(gpa, .{
        .format = "werewolf-form-release-notes/1",
        .form = c.form,
        .provider = c.provider,
        .arch = c.arch,
        .serial = c.serial,
        .commit = c.commit,
        .previous = prior,
        .packages = try changes(
            gpa,
            old_packages,
            try json.items(json.get(current, "packages").?),
            "scope",
            "name",
        ),
        .images = try changes(
            gpa,
            old_images,
            try json.items(json.get(current, "images").?),
            "form",
            "service",
        ),
    });
}

/// page is the release notes as HTML; asset_prefix names their sibling
/// files, as legacy releases prefix them.
pub fn page(s: *Sys, notes: Json, asset_prefix: []const u8) ![]const u8 {
    const gpa = s.gpa;
    const e = catalog.escape;
    const provider = try json.text(notes, "provider");
    const commit = try json.text(notes, "commit");
    const title = try gpa.print("{s} / {s} / {s} — {s}", .{
        try json.text(
            notes,
            "form",
        ),
        provider,
        try json.text(notes, "arch"),
        try json.text(notes, "serial"),
    });
    var body: std.ArrayList([]const u8) = .empty;
    try body.appendSlice(gpa, &.{
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        try gpa.print("<title>{s}</title>", .{try e(gpa, title)}),
        "<style>body{font:16px system-ui;max-width:80rem;margin:2rem auto;padding:0 1rem}" ++
            "table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.6rem;borde" ++
            "r-bottom:1px solid #bbb}" ++
            "code{overflow-wrap:anywhere}a{color:#1265ac}</style>",
        try gpa.print("<h1>{s}</h1>", .{try e(gpa, title)}),
        try gpa.print("<p><a href=\"../../../../../index.html\">Form images</a> · " ++
            "<a href=\"{0s}release-notes.json\">JSON changes</a> · " ++
            "<a href=\"{0s}packages.json\">Package inventory</a> · " ++
            "<a href=\"{0s}downloads.json\">Signed manifest</a></p>", .{asset_prefix}),
    });
    const previous = json.get(notes, "previous") orelse .null;
    if (previous != .null) {
        const previous_file = if (mem.eql(u8, provider, "legacy-boot"))
            try gpa.print("{s}downloads.json", .{asset_prefix})
        else
            "release-notes.html";
        const object = try json.text(previous, "object");
        var parts = mem.splitSequence(u8, object, "/objects/");
        _ = parts.next();
        const descriptor = parts.next() orelse return s.refuse(
            "invalid previous release object",
            .{},
        );
        try body.append(gpa, try gpa.print("<p>Changes since {s}. <a href=\"../{s}/{s}\">Previou" ++
            "s release</a>.</p>", .{
            try e(gpa, try json.text(previous, "serial")), try e(gpa, descriptor), previous_file,
        }));
        const previous_commit = try json.text(previous, "commit");
        if (!mem.eql(u8, previous_commit, commit)) try body.append(gpa, try gpa.print(
            "<p><a href=\"{s}/compare/{s}...{s}\">Source comparison</a>.</p>",
            .{ catalog.repository, previous_commit, commit },
        ));
    } else {
        try body.append(
            gpa,
            "<p>Initial published image. Packages and OCI images below establish the baseline.</p>",
        );
    }
    try body.append(gpa, "<p>Resolved package inputs are grouped by use. Build and test " ++
        "packages are not a list of " ++
        "software installed in the VM. OCI images are compared by digest; their internal " ++
        "packages " ++
        "are not enumerated. “Rebuilt” means package contents changed at the same " ++
        "version.</p>");
    const packages = try json.items(try json.field(notes, "packages"));
    const oci = try json.items(try json.field(notes, "images"));
    if (packages.len == 0 and
        oci.len == 0) try body.append(gpa, "<p>No resolved package or OCI image changes. " ++
        "This release was rebuilt from source, build tools or other input changes, or a forced " ++
        "build.</p>");
    var seen: std.ArrayList([]const u8) = .empty;
    for (packages) |p| {
        const scope = try json.text(p, "scope");
        for (seen.items) |x| {
            if (mem.eql(u8, x, scope)) break;
        } else try seen.append(gpa, scope);
    }
    mem.sort([]const u8, seen.items, {}, runtimeFirst);
    for (seen.items) |scope| {
        const heading = for (scopes) |pair| {
            if (mem.eql(u8, pair[0], scope)) break pair[1];
        } else try gpa.print(
            "{s} build environment",
            .{if (mem.startsWith(u8, scope, "build:")) scope[6..] else scope},
        );
        try body.append(gpa, try gpa.print("<h2>{s}</h2>", .{try e(gpa, heading)}));
        try body.append(
            gpa,
            "<table><thead><tr><th>Package</th><th>Change</th><th>Previous</th><th>Current</th><" ++
                "/tr></thead><tbody>",
        );
        for (packages) |p| {
            if (!mem.eql(u8, try json.text(p, "scope"), scope)) continue;
            var versions: [2][]const u8 = undefined;
            for ([_][]const u8{ "before", "after" }, &versions) |side, *v| {
                const record = json.get(p, side) orelse .null;
                v.* = if (record == .null) "—" else try e(gpa, try json.text(record, "version"));
            }
            try body.append(gpa, try gpa.print("<tr><td>{s}</td><td>{s}</td><td>{s}</td><td>{s}<" ++
                "/td></tr>", .{
                try e(
                    gpa,
                    try json.text(p, "name"),
                ),
                try json.text(p, "kind"),
                versions[0],
                versions[1],
            }));
        }
        try body.append(gpa, "</tbody></table>");
    }
    if (oci.len > 0) {
        try body.append(gpa, "<h2>OCI images</h2>");
        for (oci) |image| {
            try body.append(gpa, try gpa.print("<h3>{s} — {s}</h3>", .{
                try e(
                    gpa,
                    try gpa.print(
                        "{s}/{s}",
                        .{ try json.text(image, "form"), try json.text(image, "service") },
                    ),
                ),
                try json.text(image, "kind"),
            }));
            for ([_][2][]const u8{ .{ "Previous", "before" }, .{ "Current", "after" } }) |pair| {
                const record = json.get(image, pair[1]) orelse .null;
                if (record == .null) continue;
                try body.append(gpa, try gpa.print("<p>{s}: <code>{s}</code></p>", .{
                    pair[0], try e(gpa, try json.text(record, "digest")),
                }));
            }
        }
    }
    try body.append(gpa, "</html>");
    return gpa.print("{s}\n", .{try mem.join(gpa, "\n", body.items)});
}

/// runtimeFirst orders scopes as sorted(key=(scope != 'runtime', scope)).
fn runtimeFirst(_: void, a: []const u8, b: []const u8) bool {
    const ra = mem.eql(u8, a, "runtime");
    const rb = mem.eql(u8, b, "runtime");
    if (ra != rb) return ra;
    return mem.order(u8, a, b) == .lt;
}

const testing = std.testing;
const fixture = @import("fixture.zig");

fn testInventory(f: *fixture.Fixture) !Json {
    return json.parse(f.gpa(),
        \\{"format":"werewolf-form-packages/1","form":"playground","arch":"x86_64","images":[],"packages":[
        \\{"scope":"runtime","name":"busybox","version":"1.37-r0","checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        \\{"scope":"runtime","name":"removed","version":"1-r0","checksum":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        \\{"scope":"build:kernel","name":"gcc","version":"15-r0","checksum":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}]}
    );
}

test "release notes escape package and image text and refuse foreign inventories" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const gpa = f.gpa();
    const serial = sys.serial(s.now());
    const candidate: Candidate = .{
        .form = "playground",
        .provider = "qemu",
        .arch = "x86_64",
        .serial = &serial,
        .commit = fixture.rep('b', 40),
    };
    var hostile = try testInventory(&f);
    const first = &hostile.object.get("packages").?.array.items[0].object;
    try first.put(gpa, "name", .{ .string = "<script>" });
    try first.put(gpa, "version", .{ .string = "<img>" });
    const html = try page(s, try release(s, candidate, hostile, null, null), "");
    try testing.expect(mem.find(u8, html, "<script>") == null);
    try testing.expect(mem.find(u8, html, "<img>") == null);
    try testing.expect(mem.find(u8, html, "&lt;script&gt;") != null);
    for ([_][2][]const u8{ .{ "form", "prod-ssh" }, .{ "arch", "aarch64" } }) |change| {
        var other = try testInventory(&f);
        try other.object.put(gpa, change[0], .{ .string = change[1] });
        try testing.expectError(error.Refused, release(s, candidate, other, null, null));
    }
    var doubled = try testInventory(&f);
    const packages = &doubled.object.getPtr("packages").?.array;
    try packages.appendSlice(try gpa.dupe(Json, packages.items));
    try testing.expectError(error.Refused, release(s, candidate, doubled, null, null));
    const foreign = try json.from(
        gpa,
        .{
            .serial = &serial,
            .commit = fixture.rep('b', 40),
            .object = "playground/lima/aarch64/objects/" ++ fixture.rep('d', 64),
        },
    );
    try testing.expectError(
        error.Refused,
        release(s, candidate, try testInventory(&f), foreign, try testInventory(&f)),
    );
}

test "release notes compare with the previous inventory" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const gpa = f.gpa();
    const candidate: Candidate = .{
        .form = "playground",
        .provider = "qemu",
        .arch = "x86_64",
        .serial = "20261015T120005Z",
        .commit = fixture.rep('c', 40),
    };
    const old = try testInventory(&f);
    var current = try testInventory(&f);
    const packages = &current.object.getPtr("packages").?.array;
    try packages.items[0].object.put(gpa, "version", .{ .string = "1.38-r0" });
    try packages.items[0].object.put(gpa, "checksum", .{ .string = fixture.rep('1', 64) });
    try packages.items[2].object.put(gpa, "checksum", .{ .string = fixture.rep('2', 64) });
    _ = packages.orderedRemove(1);
    const previous = try json.from(
        gpa,
        .{
            .serial = "20261015T120000Z",
            .commit = fixture.rep('b', 40),
            .descriptor = fixture.rep('d', 64),
            .object = "playground/qemu/x86_64/objects/" ++ fixture.rep('d', 64),
        },
    );
    const notes = try release(s, candidate, current, previous, old);
    var kinds: [3][]const u8 = undefined;
    for (try json.items(json.get(
        notes,
        "packages",
    ).?), &kinds) |c, *k| k.* = try json.text(c, "kind");
    try testing.expectEqualStrings("updated", kinds[1]);
    try testing.expectEqualStrings("removed", kinds[2]);
    try testing.expectEqualStrings("rebuilt", kinds[0]);
    const html = try page(s, notes, "");
    try testing.expect(mem.find(
        u8,
        html,
        "href=\"../" ++ fixture.rep('d', 64) ++ "/release-notes.html\"",
    ) != null);
    try testing.expect(mem.find(
        u8,
        html,
        "/compare/" ++ fixture.rep('b', 40) ++ "..." ++ fixture.rep('c', 40),
    ) != null);
    try testing.expectError(error.Refused, release(s, candidate, current, null, old));
}

test "an inventory holds only the target's packages, identified by content" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const gpa = f.gpa();
    const snapshot = f.path("snapshot/caddy");
    try sys.mkdirs(s, snapshot);
    const Pkg = struct {
        fn make(a: Allocator, name: []const u8, arch: []const u8) !Json {
            return json.from(a, .{
                .name = name,
                .architecture = arch,
                .version = "1-r0",
                .checksum = "Q1test",
                .data = .{ .range = "bytes=1-100", .checksum = "sha256-test" },
                .url = try a.print("https://example.test/{s}", .{name}),
            });
        }
    };
    const caddy = try Pkg.make(gpa, "caddy", "x86_64");
    const other = try Pkg.make(gpa, "other-architecture", "aarch64");
    const runtime = [_]Json{ caddy, other };
    try sys.writeJson(
        s,
        f.path("snapshot/caddy/caddy.lock.json"),
        try json.from(
            gpa,
            .{ .contents = .{ .packages = &runtime }, .werewolf = .{ .images = &[_]Json{} } },
        ),
    );
    try sys.writeJson(
        s,
        f.path("snapshot/caddy/caddy-dev.lock.json"),
        try json.from(
            gpa,
            .{ .contents = .{ .packages = &[_]Json{
                caddy,
                other,
                try Pkg.make(gpa, "busybox", "x86_64"),
            } } },
        ),
    );
    try sys.writeJson(
        s,
        f.path("snapshot/kernel.lock.json"),
        try json.from(
            gpa,
            .{ .contents = .{ .packages = &[_]Json{try Pkg.make(
                gpa,
                "linux-werewolf",
                "x86_64",
            )} } },
        ),
    );
    try sys.writeJson(
        s,
        f.path("snapshot/stub-builder.lock.json"),
        try json.from(
            gpa,
            .{ .contents = .{ .packages = &[_]Json{try Pkg.make(gpa, "gcc", "x86_64")} } },
        ),
    );
    try sys.writeJson(
        s,
        f.path("snapshot/caddy/melange-local.lock.json"),
        try json.from(
            gpa,
            .{ .contents = .{ .packages = &[_]Json{try Pkg.make(gpa, "cargo", "x86_64")} } },
        ),
    );
    try sys.writeJson(
        s,
        f.path("snapshot/caddy/melange.json"),
        try json.parse(gpa, "{\"forms/caddy/melange/local.yaml\":\"melange-local.lock.json\"}"),
    );
    const local = [_]Local{.{
        .name = "local",
        .version = "2-r0",
        .checksum = fixture.rep('c', 64),
    }};
    const first = try inventory(s, snapshot, "caddy", "x86_64", &local);
    const want = [_][2][]const u8{
        .{ "build:forms/caddy/melange/local.yaml", "cargo" }, .{ "build:stub", "gcc" },
        .{ "kernel", "linux-werewolf" },                      .{ "local", "local" },
        .{ "runtime", "caddy" },                              .{ "test", "busybox" },
    };
    const got = try json.items(json.get(first, "packages").?);
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| {
        try testing.expectEqualStrings(w[0], try json.text(g, "scope"));
        try testing.expectEqualStrings(w[1], try json.text(g, "name"));
    }
    // Resolver order, mirror URLs and byte ranges are not content.
    for (try sys.walk(s, f.path("snapshot"))) |e| {
        if (!mem.endsWith(u8, e.path, ".lock.json")) continue;
        const p = f.path(try sys.join(s, &.{ "snapshot", e.path }));
        var lock = try sys.readJson(s, p, 1 << 20);
        const list = &lock.object.getPtr("contents").?.object.getPtr("packages").?.array;
        mem.reverse(Json, list.items);
        for (list.items) |*item| {
            try item.object.put(
                gpa,
                "url",
                .{ .string = try gpa.print(
                    "https://mirror.test/{s}",
                    .{try json.text(item.*, "name")},
                ) },
            );
            try item.object.getPtr("data").?.object.put(
                gpa,
                "range",
                .{ .string = "bytes=10-200" },
            );
        }
        try sys.writeJson(s, p, lock);
    }
    try testing.expect(json.eql(first, try inventory(s, snapshot, "caddy", "x86_64", &local)));
}
