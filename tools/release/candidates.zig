//! candidates are form-images' builds: two independent copies of each
//! changed form's bundles, compared byte for byte and tested, and the
//! lifecycle gates that authorize the bundles of forms that pass.

const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const images = @import("images.zig");
const notes = @import("notes.zig");
const plan = @import("plan.zig");
const Tree = plan.Tree;
const protected = @import("protected.zig");
const admission = @import("admission.zig");

/// archiveInputs keeps a target's resolved inputs, the apko declaration
/// locks with their OCI digests, so the build can be reproduced: a tar of
/// the shared and the form's JSON, every member 0644 at time zero.
pub fn archiveInputs(s: *Sys, snapshot: []const u8, output: []const u8) !void {
    var members: std.ArrayList([2][]const u8) = .empty;
    const parent = std.fs.path.dirname(snapshot).?;
    for (try sys.list(s, parent)) |name| {
        if (mem.endsWith(u8, name, ".json") and !mem.eql(u8, name, "plan.json"))
            try members.append(s.gpa, .{ name, try sys.join(s, &.{ parent, name }) });
    }
    for (try sys.list(s, snapshot)) |name| {
        if (mem.endsWith(u8, name, ".json"))
            try members.append(
                s.gpa,
                .{
                    try s.gpa.print("{s}/{s}", .{ std.fs.path.basename(snapshot), name }),
                    try sys.join(s, &.{ snapshot, name }),
                },
            );
    }
    var tar: std.ArrayList(u8) = .empty;
    for (members.items) |m| {
        const data = try sys.read(s, m[1], 64 << 20);
        try tar.appendSlice(s.gpa, &try ustar(m[0], data.len));
        try tar.appendSlice(s.gpa, data);
        try tar.appendNTimes(s.gpa, 0, (512 - data.len % 512) % 512);
    }
    try tar.appendNTimes(s.gpa, 0, 1024);
    try tar.appendNTimes(s.gpa, 0, (10240 - tar.items.len % 10240) % 10240);
    const file = try Io.Dir.cwd().createFile(s.io, output, .{});
    defer file.close(s.io);
    var buf: [64 << 10]u8 = undefined;
    var w = file.writer(s.io, &buf);
    const window = try s.gpa.alloc(u8, std.compress.flate.max_window_len);
    var c = try std.compress.flate.Compress.init(&w.interface, window, .gzip, .level_9);
    try c.writer.writeAll(tar.items);
    try c.finish();
    try w.interface.flush();
}

/// ustar is a regular file's header as Python's tarfile writes one.
fn ustar(name: []const u8, size: usize) ![512]u8 {
    if (name.len > 100) return error.NameTooLong;
    var h: [512]u8 = @splat(0);
    @memcpy(h[0..name.len], name);
    _ = try std.mem.print(h[100..108], "{o:0>7}\x00", .{@as(u32, 0o644)});
    _ = try std.mem.print(h[108..116], "{o:0>7}\x00", .{@as(u32, 0)});
    _ = try std.mem.print(h[116..124], "{o:0>7}\x00", .{@as(u32, 0)});
    _ = try std.mem.print(h[124..136], "{o:0>11}\x00", .{size});
    _ = try std.mem.print(h[136..148], "{o:0>11}\x00", .{@as(u32, 0)});
    @memset(h[148..156], ' ');
    h[156] = '0';
    // A regular file has no device numbers: Python leaves them NUL.
    @memcpy(h[257..265], "ustar\x0000");
    var sum: u32 = 0;
    for (h) |b| sum += b;
    _ = try std.mem.print(h[148..155], "{o:0>6}\x00", .{sum});
    return h;
}

/// localPackages are what a form's recipes built, as their APKs' own
/// metadata says, so a payload rebuilt at the same version shows.
pub fn localPackages(
    s: *Sys,
    tree: Tree,
    snapshot: []const u8,
    arch: []const u8,
) ![]const notes.Local {
    const template = "{{.Package.Name}}-{{.Package.Version}}-r{{.Package.Epoch}}" ++
        "{{$v := print \"-\" .Package.Version \"-r\" .Package.Epoch}}" ++
        "{{range .Subpackages}} {{.Name}}{{$v}}{{end}}";
    var out: std.ArrayList(notes.Local) = .empty;
    const mapping = try sys.readJson(s, try sys.join(s, &.{ snapshot, "melange.json" }), 1 << 20);
    for (try json.keys(s.gpa, mapping)) |recipe| {
        var names = mem.tokenizeAny(
            u8,
            try sys.output(s, &.{ "melange", "query", recipe, template }),
            " \t\r\n\x0b\x0c",
        );
        var any = false;
        while (names.next()) |name| {
            any = true;
            const apk = try sys.join(
                s,
                &.{ tree.packages, arch, try s.gpa.print("{s}.apk", .{name}) },
            );
            const metadata = try sys.output(s, &.{ "bsdtar", "-xzOf", apk, ".PKGINFO" });
            var fields: std.array_hash_map.String([]const u8) = .empty;
            for (try sys.lines(s, metadata)) |line| {
                const at = mem.find(u8, line, " = ") orelse continue;
                try fields.put(s.gpa, line[0..at], line[at + 3 ..]);
            }
            if (!mem.eql(
                u8,
                fields.get("arch") orelse "",
                arch,
            )) return s.refuse("built package has the wrong architecture", .{});
            try out.append(s.gpa, .{
                .name = fields.get("pkgname") orelse return s.refuse("{s}: no pkgname", .{apk}),
                .version = fields.get("pkgver") orelse return s.refuse("{s}: no pkgver", .{apk}),
                .checksum = fields.get("datahash") orelse return s.refuse(
                    "{s}: no datahash",
                    .{apk},
                ),
            });
        }
        if (!any) return s.refuse("empty built package inventory: {s}", .{recipe});
    }
    return out.items;
}

/// digests record every file of a build by digest and size; a link is
/// refused, since the copies compare bytes, not where links point.
pub fn digests(s: *Sys, root: []const u8) !Json {
    var files: json.Map = .empty;
    for (try sys.walk(s, root)) |e| switch (e.kind) {
        .sym_link => return s.refuse("form image builds must not hold links", .{}),
        .file => try files.put(
            s.gpa,
            e.path,
            try (try sys.record(s, try sys.join(s, &.{ root, e.path }))).toJson(s.gpa),
        ),
        else => {},
    };
    return .{ .object = files };
}

/// keep records a build's files, which the copies compare. Only gated
/// forms can publish, so the others keep just their descriptors: their
/// gigabytes never leave the runner.
pub fn keep(s: *Sys, t: images.Images, target: Json, output: []const u8) !void {
    const name = try json.text(target, "form");
    try sys.writeJson(
        s,
        try sys.join(
            s,
            &.{ std.fs.path.dirname(output).?, try s.gpa.print("{s}.files.json", .{name}) },
        ),
        try digests(s, output),
    );
    if (t.gated(name)) return;
    for (try plan.bundles(s, t, target)) |b| {
        const dir = try sys.join(s, &.{ output, b.provider });
        const descriptor = try sys.read(s, try sys.join(s, &.{ dir, "boot.json" }), 1 << 20);
        sys.remove(s, dir);
        try sys.mkdir(s, dir);
        try sys.write(s, try sys.join(s, &.{ dir, "boot.json" }), descriptor);
    }
}

/// buildOne builds a target's bundles from its resolved inputs, refusing
/// inputs or tools that changed since resolution and development images.
fn buildOne(
    s: *Sys,
    t: images.Images,
    tree: Tree,
    target: Json,
    snapshot: []const u8,
    output: []const u8,
) !void {
    const name = try json.text(target, "form");
    const arch = try json.text(target, "arch");
    const chain = try stringList(
        s,
        try json.field(
            try sys.readJson(s, try sys.join(s, &.{ snapshot, "input.json" }), 1 << 20),
            "chain",
        ),
    );
    if (!mem.eql(
        u8,
        &try plan.resolvedIdentity(s, name, arch, snapshot, chain),
        try json.text(target, "inputs"),
    ))
        return s.refuse("source, package or OCI inputs changed after resolution", .{});
    if (!json.eql(
        try sys.readJson(s, try sys.join(s, &.{ snapshot, "tools.json" }), 1 << 20),
        try plan.toolVersions(s, name),
    ))
        return s.refuse("build tools changed after input resolution", .{});
    try plan.installLocks(s, tree, snapshot);
    try s.env.put("WEREWOLF_FORM_INPUTS", snapshot);
    try sys.mkdirs(s, output);
    for (try plan.bundles(s, t, target)) |b| {
        const work = try sys.join(
            s,
            &.{ tree.protected_work, try s.gpa.print("{s}-{s}", .{ arch, b.provider }), name },
        );
        // Disposable outputs: keep a shard within the runner's disk.
        defer sys.remove(s, work);
        try protected.build(
            s,
            tree,
            name,
            b.provider,
            arch,
            &b.serial,
            b.index,
            try sys.join(s, &.{ output, b.provider }),
        );
        if (sys.exists(
            s,
            try sys.join(
                s,
                &.{ work, try s.gpa.print("{s}-ipe", .{name}), "meta/usr/share/werewolf/dev" },
            ),
        ))
            return s.refuse("development images cannot be published", .{});
    }
    try archiveInputs(s, snapshot, try sys.join(s, &.{ output, "inputs.tar.gz" }));
    try sys.writeJson(
        s,
        try sys.join(s, &.{ output, "packages.json" }),
        try notes.inventory(s, snapshot, name, arch, try localPackages(s, tree, snapshot, arch)),
    );
    try keep(s, t, target, output);
}

pub fn stringList(s: *Sys, v: Json) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (try json.items(v)) |item| try out.append(
        s.gpa,
        if (item == .string) item.string else return error.Record,
    );
    return out.items;
}

/// logged runs step with children's output in output/FORM.log.
fn logged(
    s: *Sys,
    output: []const u8,
    name: []const u8,
    comptime step: anytype,
    args: anytype,
) !void {
    const log = try Io.Dir.cwd().createFile(
        s.io,
        try sys.join(s, &.{ output, try s.gpa.print("{s}.log", .{name}) }),
        .{},
    );
    defer log.close(s.io);
    const saved = s.log;
    s.log = log;
    defer s.log = saved;
    return @call(.auto, step, args);
}

/// build builds a plan's changed targets; it says whether any failed.
pub fn build(
    s: *Sys,
    t: images.Images,
    tree: Tree,
    snapshot_dir: []const u8,
    output_dir: []const u8,
) !bool {
    const snapshot = try sys.resolve(s, snapshot_dir);
    const output = try sys.resolve(s, output_dir);
    const p = try sys.readJson(s, try sys.join(s, &.{ snapshot, "plan.json" }), 1 << 20);
    try plan.native(s, tree, try json.text(p, "arch"));
    // As build-protected runs: work trees hold signing inputs.
    _ = std.c.umask(0o077);
    try s.env.put("SOURCE_DATE_EPOCH", "0");
    try s.env.put("WEREWOLF_PROTECTED_INPUTS", snapshot);
    if (sys.exists(s, output)) return s.refuse("{s} already exists", .{output});
    try sys.mkdirs(s, output);
    var results: std.ArrayList(Json) = .empty;
    const results_path = try sys.join(s, &.{ output, "results.json" });
    defer sys.writeJson(
        s,
        results_path,
        .{ .array = .fromOwnedSlice(s.gpa, results.items) },
    ) catch {};
    if (!json.eql(
        try sys.readJson(s, try sys.join(s, &.{ snapshot, "tools.json" }), 1 << 20),
        try plan.toolVersions(s, null),
    ))
        return s.refuse("security build tools changed after input resolution", .{});
    for (try json.items(try json.field(p, "targets"))) |target| {
        var result = try json.parse(s.gpa, try json.encode(s.gpa, target));
        try results.append(s.gpa, result);
        if (!mem.eql(u8, try json.text(target, "status"), "build")) continue;
        const name = try json.text(target, "form");
        if (logged(
            s,
            output,
            name,
            buildOne,
            .{
                s,
                t,
                tree,
                target,
                try sys.join(s, &.{ snapshot, name }),
                try sys.join(s, &.{ output, name }),
            },
        )) {
            try result.object.put(s.gpa, "status", .{ .string = "built" });
        } else |err| {
            try result.object.put(s.gpa, "status", .{ .string = "build failed" });
            s.say("form-images: {s} build failed: {s}", .{ name, s.reason(err) });
            sys.remove(s, try sys.join(s, &.{ output, name }));
        }
        results.items[results.items.len - 1] = result;
        try sys.writeJson(s, results_path, .{ .array = .fromOwnedSlice(s.gpa, results.items) });
    }
    for (results.items) |r| {
        const status = try json.text(r, "status");
        if (mem.eql(u8, status, "build failed") or
            mem.eql(u8, status, "resolution failed")) return true;
    }
    return false;
}

/// same refuses copies whose build records differ, or a first copy that
/// no longer holds what it recorded: the bytes later jobs read.
pub fn same(
    s: *Sys,
    t: images.Images,
    name: []const u8,
    first: []const u8,
    second: []const u8,
) !void {
    var records: [2]Json = undefined;
    for ([_][]const u8{ first, second }, &records) |root, *r|
        r.* = try sys.readJson(
            s,
            try sys.join(
                s,
                &.{ std.fs.path.dirname(root).?, try s.gpa.print("{s}.files.json", .{name}) },
            ),
            1 << 20,
        );
    if (!json.eql(
        records[0],
        records[1],
    )) return s.refuse("independent form image builds differ", .{});
    const held = try digests(s, first);
    var it = held.object.iterator();
    while (it.next()) |e| {
        const recorded = json.get(
            records[0],
            e.key_ptr.*,
        ) orelse return s.refuse("form image copy differs from its build record", .{});
        if (!json.eql(
            recorded,
            e.value_ptr.*,
        )) return s.refuse("form image copy differs from its build record", .{});
    }
    if (t.gated(name) and
        !json.eql(
            held,
            records[0],
        )) return s.refuse("form image copy differs from its build record", .{});
}

/// checkOne compares a target's copies, checks each bundle is the one
/// resolved, runs the form's coverage and integration tests, and writes
/// the evidence binding them to the exact bundles gated later.
pub fn checkOne(
    s: *Sys,
    t: images.Images,
    tree: Tree,
    target: Json,
    snapshot: []const u8,
    first: []const u8,
    second: []const u8,
    output: []const u8,
    lifecycle: []const u8,
) !void {
    const name = try json.text(target, "form");
    const arch = try json.text(target, "arch");
    try same(s, t, name, first, second);
    var descriptors: json.Map = .empty;
    const bundles = try plan.bundles(s, t, target);
    for (bundles) |b| {
        const head_path = try sys.join(s, &.{ first, b.provider, "boot.json" });
        const manifest = try sys.readJson(s, head_path, 1 << 20);
        const image = try json.field(manifest, "image");
        if (!mem.eql(u8, try json.text(manifest, "form"), name) or
            !mem.eql(u8, try json.text(image, "arch"), arch) or
            !mem.eql(u8, try json.text(image, "serial"), &b.serial) or
            try json.int(image, "index") != b.index)
            return s.refuse("bundle differs from its resolved target: {s}", .{b.provider});
        try descriptors.put(
            s.gpa,
            b.provider,
            .{ .string = try s.gpa.dupe(u8, &try sys.sha(s, head_path)) },
        );
    }
    try plan.installLocks(s, tree, snapshot);
    var env = try s.env.clone(s.gpa);
    try env.put("WEREWOLF_FORM_INPUTS", snapshot);
    var coverage: std.ArrayList([]const u8) = .empty;
    try coverage.appendSlice(s.gpa, tree.coverage);
    try coverage.appendSlice(s.gpa, &.{ "--form", name });
    try sys.run(s, coverage.items, .{ .env = &env });
    try sys.run(
        s,
        &.{ try sys.resolve(s, tree.howl), "test", "--with", name, "--arch", arch },
        .{ .env = &env },
    );
    try sys.mkdirs(s, output);
    for ([_][]const u8{ "inputs.tar.gz", "packages.json" }) |file|
        try sys.copy(s, try sys.join(s, &.{ first, file }), try sys.join(s, &.{ output, file }));
    // The bundle descriptors bind this evidence to the exact bytes gated later.
    var checks: json.Map = .empty;
    for (t.checks) |c| try checks.put(s.gpa, c, .{ .bool = true });
    try sys.writeJson(s, try sys.join(s, &.{ output, "tests.json" }), try json.from(s.gpa, .{
        .format = "werewolf-form-tests/1",
        .bundles = descriptors,
        .checks = checks,
        .form = name,
        .variants = try s.variantNames(),
        .arch = arch,
        .inputs = try json.field(target, "inputs"),
    }));
    if (t.gated(name)) for (bundles) |b|
        try sys.copyTree(
            s,
            try sys.join(s, &.{ first, b.provider }),
            try sys.join(s, &.{ lifecycle, name, b.provider }),
        );
}

/// check verifies a plan's built targets; it says whether any failed.
pub fn check(
    s: *Sys,
    t: images.Images,
    tree: Tree,
    snapshot_dir: []const u8,
    first_dir: []const u8,
    second_dir: []const u8,
    output_dir: []const u8,
    lifecycle_dir: []const u8,
) !bool {
    const snapshot = try sys.resolve(s, snapshot_dir);
    const first = try sys.resolve(s, first_dir);
    const second = try sys.resolve(s, second_dir);
    const output = try sys.resolve(s, output_dir);
    const lifecycle = try sys.resolve(s, lifecycle_dir);
    const p = try sys.readJson(s, try sys.join(s, &.{ snapshot, "plan.json" }), 1 << 20);
    try plan.native(s, tree, try json.text(p, "arch"));
    if (sys.exists(s, output)) return s.refuse("{s} already exists", .{output});
    try sys.mkdirs(s, output);
    var results: std.ArrayList(Json) = .empty;
    var failed = false;
    for (try json.items(try json.field(p, "targets"))) |target| {
        var result = try json.parse(s.gpa, try json.encode(s.gpa, target));
        const status = try json.text(target, "status");
        if (mem.eql(u8, status, "build")) {
            const name = try json.text(target, "form");
            var dirs: [4][]const u8 = undefined;
            for ([_][]const u8{ snapshot, first, second, output }, &dirs) |root, *d|
                d.* = try sys.join(s, &.{ root, name });
            const args = .{ s, t, tree, target, dirs[0], dirs[1], dirs[2], dirs[3], lifecycle };
            if (logged(s, output, name, checkOne, args)) {
                try result.object.put(s.gpa, "status", .{ .string = "passed" });
            } else |err| {
                try result.object.put(
                    s.gpa,
                    "status",
                    .{ .string = "tests or reproducibility failed" },
                );
                s.say("form-images: {s} verification failed: {s}", .{ name, s.reason(err) });
                sys.remove(s, try sys.join(s, &.{ output, name }));
                sys.remove(s, try sys.join(s, &.{ lifecycle, name }));
                failed = true;
            }
        } else if (mem.eql(u8, status, "resolution failed")) failed = true;
        try results.append(s.gpa, result);
        try sys.writeJson(
            s,
            try sys.join(s, &.{ output, "results.json" }),
            .{ .array = .fromOwnedSlice(s.gpa, results.items) },
        );
    }
    return failed;
}

/// gate authorizes and lifecycle-tests each form's candidate where it
/// boots; one that passes moves to output with its evidence. updates holds
/// check-independent-updates' evidence, made once on disposable keys: a
/// candidate's own updates follow the public mirror, so they cannot run
/// before publication. A form whose build was unchanged or failed has no
/// candidate and is skipped. It says whether any gate failed.
pub fn gate(
    s: *Sys,
    t: images.Images,
    tree: Tree,
    lifecycle: []const u8,
    updates: []const u8,
    output: []const u8,
    provider: []const u8,
    arch: []const u8,
    selected: []const []const u8,
) !bool {
    if (mem.eql(u8, provider, "qemu")) try plan.native(s, tree, arch);
    if (selected.len == 0) return s.refuse("invalid lifecycle gate forms", .{});
    for (selected, 0..) |name, i| {
        if (images.has(selected[0..i], name) or
            !t.supportsGate(name, provider)) return s.refuse("invalid lifecycle gate forms", .{});
    }
    if (!sys.isFile(s, try sys.join(s, &.{ updates, "result.json" })))
        return s.refuse("{s} holds no update evidence", .{updates});
    const evidence = try sys.resolve(s, updates);
    if (sys.exists(s, output)) return s.refuse("{s} already exists", .{output});
    try sys.mkdirs(s, output);
    const howl = try sys.resolve(s, tree.howl);
    var failed = false;
    for (selected) |name| {
        const initial = try sys.join(s, &.{ lifecycle, name, provider });
        if (!sys.exists(s, initial)) continue;
        const own_evidence = try sys.join(s, &.{ evidence, name });
        const source = if (sys.isFile(s, try sys.join(s, &.{ own_evidence, "result.json" })))
            own_evidence
        else
            evidence;
        gateOne(s, tree, howl, initial, source, name, provider, output) catch |err| {
            s.say(
                "form-images: {s}/{s}/{s} lifecycle failed: {s}",
                .{ name, provider, arch, s.reason(err) },
            );
            sys.remove(s, try sys.join(s, &.{ output, name }));
            failed = true;
        };
    }
    return failed;
}

fn gateOne(
    s: *Sys,
    tree: Tree,
    howl: []const u8,
    initial: []const u8,
    updates: []const u8,
    name: []const u8,
    provider: []const u8,
    output: []const u8,
) !void {
    const logs = try sys.join(s, &.{ tree.lifecycle, name });
    try admission.authorize(s, tree, howl, provider, initial);
    try sys.run(
        s,
        &.{ try sys.resolve(s, tree.lifecycle_check), howl, provider, initial, updates, logs },
        .{},
    );
    const destination = try sys.join(s, &.{ output, name });
    try sys.mkdir(s, destination);
    try sys.rename(s, initial, try sys.join(s, &.{ destination, "bundle" }));
    try sys.copy(
        s,
        try sys.join(s, &.{ logs, "gates.json" }),
        try sys.join(s, &.{ destination, "gates.json" }),
    );
}

const testing = std.testing;
const fixture = @import("fixture.zig");

fn gateAnswer(f: *fixture.Fixture, argv: []const []const u8) anyerror!?sys.Result {
    if (mem.endsWith(u8, argv[0], "check-published-lifecycle")) {
        try sys.writeJson(
            &f.s,
            try sys.join(&f.s, &.{ argv[argv.len - 1], "gates.json" }),
            try json.parse(f.gpa(), "{\"passed\":true}"),
        );
        return sys.Result.passed;
    }
    if (argv.len < 8 or !mem.eql(u8, argv[1], "_boot-image")) return null;
    if (mem.find(
        u8,
        argv[3],
        "minimal",
    ) != null) return .{ .term = .{ .exited = 1 }, .stderr = "refused for the test" };
    if (mem.eql(u8, argv[2], "verify")) return .{ .term = .{ .exited = 0 }, .stdout = "{}" };
    return .{
        .term = .{ .exited = 0 },
        .stdout = try sys.read(&f.s, try sys.join(&f.s, &.{ argv[3], "boot.json" }), 4096),
    };
}

test "a gate failure keeps other forms, and unchanged targets need no authorization" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const gpa = f.gpa();
    const t = try images.load(s);
    const k = try fixture.keys(&f, "image");
    try f.env.put("WEREWOLF_PROTECTED_IMAGE_KEY", k.key);
    try sys.mkdirs(s, f.path("trust"));
    try sys.copy(s, "release/protected/trust.json", f.path("trust/trust.json"));
    const tree: Tree = .{
        .trust = f.path("trust"),
        .howl = "howl",
        .lifecycle = f.path("build/lifecycle"),
        .lifecycle_check = f.path("check-published-lifecycle"),
        .native = false,
    };
    const lifecycle = f.path("lifecycle");
    const serial = sys.serial(s.now());
    for ([_][]const u8{
        "minimal",
        "prod-ssh",
    }) |name| {
        const dir = try sys.join(s, &.{ lifecycle, name, "qemu" });
        try sys.write(s, try sys.join(s, &.{ dir, "production" }), name);
        try sys.write(s, try sys.join(
            s,
            &.{ dir, "boot.json" },
        ), try json.dumps(gpa, try json.from(gpa, .{
            .form = name,
            .variants = try s.variantNames(),
            .image = .{ .arch = "x86_64", .serial = &serial, .build = fixture.rep('a', 64) },
        })));
    }
    f.answer = gateAnswer;
    const updates = f.path("updates");
    // No evidence of the updates, no gate.
    try testing.expectError(
        error.Refused,
        gate(s, t, tree, lifecycle, updates, f.path("none"), "qemu", "x86_64", &.{"prod-ssh"}),
    );
    try sys.write(s, try sys.join(s, &.{ updates, "result.json" }), "{}");
    const output = f.path("gated");
    try testing.expect(try gate(
        s,
        t,
        tree,
        lifecycle,
        updates,
        output,
        "qemu",
        "x86_64",
        &.{ "minimal", "prod-ssh", "playground" },
    ));
    try testing.expectEqual(@as(usize, 1), f.called(&.{tree.lifecycle_check}));
    try testing.expectEqual(@as(usize, 1), (try sys.list(s, output)).len);
    try testing.expectEqualStrings(
        "prod-ssh",
        try sys.read(s, f.path("gated/prod-ssh/bundle/production"), 64),
    );
    try testing.expect(sys.isFile(s, f.path("gated/prod-ssh/gates.json")));
    try testing.expect(sys.isFile(s, f.path("gated/prod-ssh/bundle/boot.json.sig")));
    try testing.expect(sys.isFile(s, f.path("lifecycle/minimal/qemu/production")));
    // A refused candidate keeps no signature.
    try testing.expect(!sys.exists(s, f.path("lifecycle/minimal/qemu/boot.json.sig")));
    f.calls.clearRetainingCapacity();
    try testing.expect(!try gate(
        s,
        t,
        tree,
        lifecycle,
        updates,
        f.path("unchanged"),
        "qemu",
        "x86_64",
        &.{"playground"},
    ));
    try testing.expectEqual(@as(usize, 0), f.calls.items.len);
    for ([_][]const []const u8{
        &.{},
        &.{ "playground", "playground" },
        &.{"other"},
    }, 0..) |bad, i| {
        try testing.expectError(
            error.Refused,
            gate(
                s,
                t,
                tree,
                lifecycle,
                updates,
                f.path(try gpa.print("bad-{d}", .{i})),
                "lima",
                "aarch64",
                bad,
            ),
        );
        try testing.expectEqualStrings("invalid lifecycle gate forms", s.why.text);
    }
}

fn testBundle(s: *Sys, dir: []const u8, name: []const u8, serial: []const u8, index: i64) !void {
    for (@import("boot.zig").files) |file| try sys.write(
        s,
        try sys.join(s, &.{ dir, "slot", file }),
        try s.gpa.print("{s}{s}", .{ file, serial }),
    );
    try sys.write(s, try sys.join(
        s,
        &.{ dir, "boot.json" },
    ), try json.dumps(s.gpa, try json.from(s.gpa, .{
        .form = name,
        .variants = try s.variantNames(),
        .image = .{
            .arch = "x86_64",
            .build = try s.gpa.dupe(u8, &sys.sha256(serial)),
            .serial = serial,
            .index = index,
        },
        .raw_size = 512 << 20,
    })));
}

test "copies that differ fail before any test runs or evidence is written" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const t = try images.load(s);
    const serial = sys.serial(s.now());
    const target = try json.from(
        s.gpa,
        .{
            .form = "minimal",
            .arch = "x86_64",
            .serial = &serial,
            .index = 1,
            .inputs = try s.gpa.dupe(u8, &sys.sha256("minimal")),
        },
    );
    const first = f.path("one/minimal");
    const second = f.path("two/minimal");
    for ([_][]const u8{
        first,
        second,
    }) |copy| try testBundle(s, try sys.join(s, &.{ copy, "qemu" }), "minimal", &serial, 1);
    try sys.write(s, f.path("two/minimal/qemu/slot/root.erofs"), "different output");
    for ([_][]const u8{ first, second }) |copy| try keep(s, t, target, copy);
    const tree: Tree = .{ .howl = "howl", .lock = f.path("lock") };
    f.answer = struct {
        fn refuse(_: *fixture.Fixture, argv: []const []const u8) anyerror!?sys.Result {
            _ = argv;
            return error.TestRanACommand;
        }
    }.refuse;
    try testing.expectError(
        error.Refused,
        checkOne(
            s,
            t,
            tree,
            target,
            f.path("snapshot"),
            first,
            second,
            f.path("verified"),
            f.path("lifecycle"),
        ),
    );
    try testing.expectEqualStrings("independent form image builds differ", s.why.text);
    try sys.copy(s, f.path("one/minimal.files.json"), f.path("two/minimal.files.json"));
    try sys.write(s, f.path("one/minimal/qemu/boot.json"), "{\"changed\": \"after the build\"}");
    try testing.expectError(
        error.Refused,
        checkOne(
            s,
            t,
            tree,
            target,
            f.path("snapshot"),
            first,
            second,
            f.path("verified"),
            f.path("lifecycle"),
        ),
    );
    try testing.expectEqualStrings("form image copy differs from its build record", s.why.text);
    try testing.expect(!sys.exists(s, f.path("verified")));
}

test "builds keep what later jobs read, and record all of it" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const t = try images.load(s);
    const serial = sys.serial(s.now());
    for ([_][]const u8{ "minimal", "playground" }) |name| {
        const output = f.path(try s.gpa.print("candidates/{s}", .{name}));
        const target = try json.from(
            s.gpa,
            .{ .form = name, .arch = "x86_64", .serial = &serial, .index = 1 },
        );
        for (try plan.bundles(
            s,
            t,
            target,
        )) |b| try testBundle(
            s,
            try sys.join(s, &.{ output, b.provider }),
            name,
            &b.serial,
            b.index,
        );
        for ([_][]const u8{
            "inputs.tar.gz",
            "packages.json",
        }) |file| try sys.write(s, try sys.join(s, &.{ output, file }), file);
        const whole = try digests(s, output);
        try keep(s, t, target, output);
        const recorded = try sys.readJson(
            s,
            f.path(try s.gpa.print("candidates/{s}.files.json", .{name})),
            1 << 20,
        );
        try testing.expect(json.eql(whole, recorded));
        // A gated form keeps every byte it recorded.
        try testing.expect(json.eql(recorded, try digests(s, output)));
    }
    try std.Io.Dir.cwd().symLink(s.io, "boot.json", f.path("candidates/minimal/qemu/link"), .{});
    try testing.expectError(error.Refused, digests(s, f.path("candidates/minimal")));
}

fn melangeQuery(f: *fixture.Fixture, argv: []const []const u8) anyerror!?sys.Result {
    _ = f;
    if (!mem.eql(u8, argv[0], "melange")) return null;
    return .{ .term = .{ .exited = 0 }, .stdout = "example-2-r1 example-web-2-r1\n" };
}

test "local inventories read main and subpackage payload identities" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    const snapshot = f.path("snapshot");
    try sys.writeJson(
        s,
        f.path("snapshot/melange.json"),
        try json.parse(s.gpa, "{\"forms/example/melange/package.yaml\":\"example.lock.json\"}"),
    );
    const tree: Tree = .{ .packages = f.path("packages") };
    const Apk = struct {
        fn make(
            fx: *fixture.Fixture,
            name: []const u8,
            digest: []const u8,
            arch: []const u8,
        ) !void {
            const sx = &fx.s;
            const work = fx.path(try sx.gpa.print("apk-{s}", .{name}));
            sys.remove(sx, work);
            try sys.write(
                sx,
                try sys.join(sx, &.{ work, ".PKGINFO" }),
                try sx.gpa.print(
                    "pkgname = {s}\npkgver = 2-r1\narch = {s}\ndatahash = {s}\n",
                    .{ name, arch, digest },
                ),
            );
            try sys.mkdirs(sx, fx.path("packages/x86_64"));
            try sys.run(
                sx,
                &.{
                    "tar",
                    "-czf",
                    fx.path(try sx.gpa.print("packages/x86_64/{s}-2-r1.apk", .{name})),
                    "-C",
                    work,
                    ".PKGINFO",
                },
                .{},
            );
        }
    };
    try Apk.make(&f, "example", fixture.rep('a', 64), "x86_64");
    try Apk.make(&f, "example-web", fixture.rep('b', 64), "x86_64");
    f.answer = melangeQuery;
    const got = try localPackages(s, tree, snapshot, "x86_64");
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqualStrings("example", got[0].name);
    try testing.expectEqualStrings("2-r1", got[0].version);
    try testing.expectEqualStrings(fixture.rep('a', 64), got[0].checksum);
    try testing.expectEqualStrings("example-web", got[1].name);
    try testing.expectEqualStrings(fixture.rep('b', 64), got[1].checksum);
    try Apk.make(&f, "example-web", fixture.rep('c', 64), "aarch64");
    try testing.expectError(error.Refused, localPackages(s, tree, snapshot, "x86_64"));
    try testing.expectEqualStrings("built package has the wrong architecture", s.why.text);
}

test "archived inputs are a tar of the shared and the form's JSON" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const s = &f.s;
    try sys.write(s, f.path("snap/kernel.lock.json"), "{\"k\":1}\n");
    try sys.write(s, f.path("snap/plan.json"), "{}\n");
    try sys.write(s, f.path("snap/caddy/caddy.lock.json"), "{\"c\":1}\n");
    try sys.write(s, f.path("snap/caddy/notes.txt"), "not JSON");
    try archiveInputs(s, f.path("snap/caddy"), f.path("inputs.tar.gz"));
    const listed = try sys.output(s, &.{ "tar", "-tzf", f.path("inputs.tar.gz") });
    try testing.expectEqualStrings("kernel.lock.json\ncaddy/caddy.lock.json\n", listed);
    try sys.mkdirs(s, f.path("out"));
    try sys.run(s, &.{ "tar", "-xzf", f.path("inputs.tar.gz"), "-C", f.path("out") }, .{});
    try testing.expectEqualStrings(
        "{\"c\":1}\n",
        try sys.read(s, f.path("out/caddy/caddy.lock.json"), 64),
    );
    // The same inputs archive to the same bytes.
    try archiveInputs(s, f.path("snap/caddy"), f.path("again.tar.gz"));
    try testing.expectEqualStrings(
        &try sys.sha(s, f.path("inputs.tar.gz")),
        &try sys.sha(s, f.path("again.tar.gz")),
    );
}
