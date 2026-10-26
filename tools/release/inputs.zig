//! inputs resolves one public package snapshot for independent protected
//! image builds, and the identities that decide whether a target changed:
//! of its source tree, its packages' bytes and their repository trust.

const std = @import("std");
const mem = std.mem;
const json = @import("json.zig");
const Json = json.Json;
const sys = @import("sys.zig");
const Sys = sys.Sys;
const images = @import("images.zig");

/// resolve locks an apko config, retrying a flaky mirror three times.
pub fn resolve(
    s: *Sys,
    config: []const u8,
    output: []const u8,
    arch: []const u8,
    workdir: []const u8,
) !void {
    const absolute = try sys.resolve(s, output);
    var attempt: u32 = 0;
    while (true) : (attempt += 1) {
        sys.run(
            s,
            &.{
                "apko",
                "--workdir",
                workdir,
                "lock",
                "--arch",
                arch,
                "--output",
                absolute,
                config,
            },
            .{},
        ) catch |err| {
            if (err != error.Refused or attempt == 3) return err;
            s.say(
                "protected-inputs: apko lock {s} failed; retrying in {d}s",
                .{ config, 15 * (attempt + 1) },
            );
            try s.io.sleep(.fromSeconds(15 * (attempt + 1)), .awake);
            continue;
        };
        return;
    }
}

/// bootConfigs lays boot/'s apko configs out in directory as a build lays
/// them out, werewolf's repository key in ../keys; it returns their place.
pub fn bootConfigs(s: *Sys, directory: []const u8) ![]const u8 {
    const configs = try sys.join(s, &.{ directory, "apko" });
    const keys = try sys.join(s, &.{ directory, "keys" });
    try sys.mkdir(s, configs);
    try sys.mkdir(s, keys);
    for ([_][]const u8{ "kernel.yaml", "boot.yaml" }) |name|
        try sys.copy(s, try sys.join(s, &.{ "boot", name }), try sys.join(s, &.{ configs, name }));
    try sys.copy(
        s,
        "release/packages.pub",
        try sys.join(s, &.{ keys, "werewolf-packages.rsa.pub" }),
    );
    return configs;
}

pub const Lock = struct { name: []const u8, lock: Json };

/// identity ignores resolver paths and order, but binds authenticated
/// package bytes, versions, architecture, repository trust and the whole
/// source identity.
pub fn identity(s: *Sys, source: []const u8, arch: []const u8, locks: []const Lock) ![64]u8 {
    const sorted = try s.gpa.dupe(Lock, locks);
    mem.sort(Lock, sorted, {}, struct {
        fn less(_: void, a: Lock, b: Lock) bool {
            return json.less({}, a.name, b.name);
        }
    }.less);
    var records: json.Map = .empty;
    for (sorted) |l| {
        const contents = try json.field(l.lock, "contents");
        var packages: std.ArrayList(Json) = .empty;
        for (try json.items(try json.field(contents, "packages"))) |p| {
            if (mem.eql(u8, try json.text(p, "architecture"), arch)) try packages.append(s.gpa, p);
        }
        if (packages.items.len == 0) return s.refuse("empty package snapshot: {s}", .{l.name});
        mem.sort(Json, packages.items, {}, byNameUrl);
        try records.put(
            s.gpa,
            l.name,
            try json.from(
                s.gpa,
                .{ .packages = packages.items, .keyring = try json.field(contents, "keyring") },
            ),
        );
    }
    const data = try json.from(
        s.gpa,
        .{
            .format = "werewolf-protected-inputs/1",
            .source = source,
            .arch = arch,
            .locks = records,
        },
    );
    const encoded = try json.encode(s.gpa, data);
    return sys.sha256(encoded[0 .. encoded.len - 1]);
}

fn byNameUrl(_: void, a: Json, b: Json) bool {
    return switch (mem.order(u8, json.text(a, "name") catch "", json.text(b, "name") catch "")) {
        .lt => true,
        .gt => false,
        .eq => mem.order(u8, json.text(a, "url") catch "", json.text(b, "url") catch "") == .lt,
    };
}

/// sourceIdentity hashes `git ls-tree -rz` rows, less documentation that
/// no image ships and Python caches.
pub fn sourceIdentity(tree: []const u8) [64]u8 {
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    var first = true;
    var it = mem.splitScalar(u8, tree, 0);
    while (it.next()) |row| {
        if (row.len == 0) continue;
        const tab = mem.findScalar(u8, row, '\t') orelse continue;
        const path = row[tab + 1 ..];
        const manual = path.len >= 5 and path[path.len - 5] == '.' and
            path[path.len - 4] >= '1' and path[path.len - 4] <= '9';
        if ((mem.endsWith(u8, path, ".md") and !manual and
            mem.find(u8, path, "/rootfs/") == null) or
            mem.find(u8, path, "__pycache__/") != null) continue;
        if (!first) h.update("\x00");
        h.update(row);
        first = false;
    }
    return sys.hex(h.finalResult());
}

/// melangeContents asks Melange for a recipe's own parsed environment,
/// which apko resolves like any config.
pub fn melangeContents(s: *Sys, recipe: []const u8) !Json {
    var contents: json.Map = .empty;
    for ([_][]const u8{ "Repositories", "Keyring", "Packages" }) |field| {
        const template = try s.gpa.print(
            "{{{{ range .Environment.Contents.{s} }}}}{{{{ println . }}}}{{{{ end }}}}",
            .{field},
        );
        const found = try sys.lines(
            s,
            try sys.output(s, &.{ "melange", "query", recipe, template }),
        );
        if (found.len == 0) return s.refuse("empty Melange environment: {s}", .{recipe});
        for (found) |line| if (mem.trim(
            u8,
            line,
            " \t\r\n\x0b\x0c",
        ).len == 0) return s.refuse("incomplete Melange environment: {s}", .{recipe});
        var list: json.List = .init(s.gpa);
        for (found) |line| try list.append(.{ .string = line });
        const name = try std.ascii.allocLowerString(s.gpa, field);
        try contents.put(s.gpa, name, .{ .array = list });
    }
    return .{ .object = contents };
}

/// prepare resolves the published forms' locks, the boot locks and the
/// stub builder's into output, and writes their combined identity.
pub fn prepare(
    s: *Sys,
    t: images.Images,
    howl_path: []const u8,
    arch: []const u8,
    output_dir: []const u8,
) ![64]u8 {
    if (!mem.eql(u8, arch, "x86_64") and
        !mem.eql(u8, arch, "aarch64")) return s.refuse("unsupported protected architecture", .{});
    const howl = try sys.resolve(s, howl_path);
    const output = try sys.resolve(s, output_dir);
    if (sys.exists(s, output)) return s.refuse("{s} already exists", .{output});
    try sys.mkdirs(s, output);
    const lockdir = "build/lock";
    try sys.mkdirs(s, lockdir);
    for (t.forms) |name| {
        std.Io.Dir.cwd().deleteFile(
            s.io,
            try s.gpa.print("{s}/{s}.lock.json", .{ lockdir, name }),
        ) catch {};
        try sys.run(s, &.{ howl, "_build", "--with", name, "--arch", arch, "lock" }, .{});
    }
    {
        const work = try sys.scratch(s, null, "ww-protected-inputs-");
        defer sys.remove(s, work);
        const configs = try bootConfigs(s, work);
        for ([_][]const u8{ "kernel", "boot" }) |name|
            try resolve(
                s,
                try s.gpa.print("{s}.yaml", .{name}),
                try s.gpa.print("{s}/{s}.lock.json", .{ lockdir, name }),
                "aarch64,x86_64",
                configs,
            );
    }
    const config = try sys.join(s, &.{ output, "stub-builder.json" });
    const contents = try melangeContents(s, "boot/tpm-stub.melange.yaml");
    const stub_config = try json.from(
        s.gpa,
        .{ .contents = contents, .archs = &[_][]const u8{arch} },
    );
    try sys.write(s, config, try s.gpa.print("{s}\n", .{try json.dumps(s.gpa, stub_config)}));
    try resolve(
        s,
        "stub-builder.json",
        try sys.join(s, &.{ output, "stub-builder.lock.json" }),
        arch,
        output,
    );
    var locks: std.ArrayList(Lock) = .empty;
    var paths: std.ArrayList([]const u8) = .empty;
    for (t.forms) |name| try paths.append(
        s.gpa,
        try s.gpa.print("{s}/{s}.lock.json", .{ lockdir, name }),
    );
    for ([_][]const u8{
        "kernel",
        "boot",
    }) |name| try paths.append(s.gpa, try s.gpa.print("{s}/{s}.lock.json", .{ lockdir, name }));
    for (try sys.list(
        s,
        output,
    )) |name| if (mem.endsWith(
        u8,
        name,
        "-builder.lock.json",
    )) try paths.append(s.gpa, try sys.join(s, &.{ output, name }));
    for (paths.items) |path| {
        const name = std.fs.path.basename(path);
        const bytes = try sys.read(s, path, 64 << 20);
        try locks.append(s.gpa, .{ .name = name, .lock = try json.parse(s.gpa, bytes) });
        if (!mem.eql(
            u8,
            std.fs.path.dirname(path).?,
            output,
        )) try sys.write(s, try sys.join(s, &.{ output, name }), bytes);
    }
    const tree = try sys.output(
        s,
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
            "forms",
            "lib",
            "tools",
            "release",
            "test",
            ".github",
        },
    );
    const source = sourceIdentity(tree);
    const digest = try identity(s, &source, arch, locks.items);
    try sys.write(s, try sys.join(s, &.{ output, "inputs" }), try s.gpa.print("{s}\n", .{&digest}));
    try std.Io.File.stdout().writeStreamingAll(
        s.io,
        try s.gpa.print("protected inputs: {s}\n", .{&digest}),
    );
    return digest;
}

const testing = std.testing;
const fixture = @import("fixture.zig");

fn testLock(f: *fixture.Fixture) !Json {
    return json.parse(f.gpa(),
        \\{"config":{"name":"/runner/one/config.yaml"},"contents":{"keyring":[{"content":"trusted public key"}],"packages":[
        \\{"name":"libc","version":"1-r0","architecture":"x86_64","url":"https://repo/libc.apk","checksum":"first"},
        \\{"name":"shell","version":"2-r0","architecture":"x86_64","url":"https://repo/shell.apk","checksum":"second"}]}}
    );
}

fn digestOf(f: *fixture.Fixture, lock: Json, source: []const u8) ![64]u8 {
    return identity(&f.s, source, "x86_64", &.{.{ .name = "form.lock.json", .lock = lock }});
}

test "resolver paths and package order do not make a release" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    var other = try testLock(&f);
    try other.object.getPtr("config").?.object.put(
        f.gpa(),
        "name",
        .{ .string = "/runner/two/config.yaml" },
    );
    mem.reverse(Json, other.object.getPtr("contents").?.object.getPtr("packages").?.array.items);
    try testing.expectEqualStrings(
        &try digestOf(&f, try testLock(&f), "source"),
        &try digestOf(&f, other, "source"),
    );
}

test "changed source, package bytes, versions and trust make a release" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    const gpa = f.gpa();
    const base = try digestOf(&f, try testLock(&f), "source");
    try testing.expect(!mem.eql(u8, &base, &try digestOf(&f, try testLock(&f), "updated source")));
    for ([_][]const u8{ "version", "checksum", "url" }) |field| {
        var other = try testLock(&f);
        const p = &other.object.getPtr(
            "contents",
        ).?.object.getPtr("packages").?.array.items[0].object;
        try p.put(
            gpa,
            field,
            .{ .string = try gpa.print("{s}-changed", .{p.get(field).?.string}) },
        );
        try testing.expect(!mem.eql(u8, &base, &try digestOf(&f, other, "source")));
    }
    var other = try testLock(&f);
    try other.object.getPtr("contents").?.object.getPtr("keyring").?.array.items[0].object.put(
        gpa,
        "content",
        .{ .string = "new public key" },
    );
    try testing.expect(!mem.eql(u8, &base, &try digestOf(&f, other, "source")));
}

test "a foreign architecture is no empty successful snapshot" {
    var f: fixture.Fixture = undefined;
    try f.init();
    defer f.deinit();
    try testing.expectError(
        error.Refused,
        identity(&f.s, "source", "aarch64", &.{.{ .name = "form", .lock = try testLock(&f) }}),
    );
    try testing.expectEqualStrings("empty package snapshot: form", f.s.why.text);
}

test "only documentation shipped in images invalidates published image inputs" {
    const code = "100644 blob code\tcmd/init/init.zig\x00";
    const docs = "100644 blob docs\tcmd/howl/README.md\x00";
    const changed = "100644 blob edited\tcmd/howl/README.md\x00";
    try testing.expectEqualStrings(&sourceIdentity(code), &sourceIdentity(code ++ docs));
    try testing.expectEqualStrings(&sourceIdentity(code ++ docs), &sourceIdentity(code ++ changed));
    const manual = "100644 blob manual\tcmd/init/init.8.md\x00";
    const edited_manual = "100644 blob edited\tcmd/init/init.8.md\x00";
    try testing.expect(!mem.eql(u8, &sourceIdentity(code), &sourceIdentity(code ++ manual)));
    try testing.expect(!mem.eql(
        u8,
        &sourceIdentity(code ++ manual),
        &sourceIdentity(code ++ edited_manual),
    ));
    try testing.expect(!mem.eql(
        u8,
        &sourceIdentity(code),
        &sourceIdentity("100644 blob updated\tcmd/init/init.zig\x00"),
    ));
    const shipped = "100644 blob shipped\tforms/demo/rootfs/usr/share/help.md\x00";
    try testing.expect(!mem.eql(u8, &sourceIdentity(code), &sourceIdentity(code ++ shipped)));
    try testing.expect(mem.eql(
        u8,
        &sourceIdentity(code),
        &sourceIdentity(code ++ "100644 blob c\tx/__pycache__/y.pyc\x00"),
    ));
}
