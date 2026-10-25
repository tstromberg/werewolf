//! ci-forms checks forms one at a time, as CI's check jobs do, so that a
//! runner's disk need hold only one form's images.
//!
//!     [ARCH=aarch64|x86_64] [SHARD=K/N] ci-forms forms|shellfree|all
//!
//! For each form of the shard, in name order, it runs make check-FORM
//! (forms), check-shellfree-FORM (shellfree) or both (all), and records
//! each result as it comes in build/ARCH/check/ci-forms-GROUP.json, which
//! CI uploads. A passing form's generated images are discarded before the
//! next is built; the first failure stops the run, keeping that form's
//! images, disks and logs. make _test/ci-forms runs the tests below.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Environ = std.process.Environ;
const mem = std.mem;

const Group = enum { forms, shellfree, all };
const Arch = enum { aarch64, x86_64 };

/// Shard is SHARD=K/N: the Kth form in name order, and every Nth after it.
const Shard = struct { k: usize, n: usize };

/// scrubbed is what an outer make, or the job, leaves in the environment
/// that must not steer the makes run here: flags such as -n, overrides,
/// the jobserver, and SHARD, by which the Makefile shards its own groups.
const scrubbed = [_][]const u8{
    "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "GNUMAKEFLAGS", "MAKEFILES", "SHARD",
};

const lstat: Dir.StatFileOptions = .{ .follow_symlinks = false };
const lchmod: Dir.SetFilePermissionsOptions = .{ .follow_symlinks = false };

/// Report is build/ARCH/check/ci-forms-GROUP.json: inventory is the forms
/// the run is to check, and complete says whether it has checked them all.
const Report = struct {
    arch: Arch,
    group: Group,
    shard: []const u8,
    inventory: []const []const u8,
    results: []const Result = &.{},
    complete: bool = false,
};

const Result = struct {
    form: []const u8,
    command: []const []const u8,
    /// exit is make's exit status, or minus the signal that ended it.
    exit: i32,
    seconds: f64,
};

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = init.minimal.args.toSlice(gpa) catch fatal("out of memory", .{});
    const group = (if (args.len == 2) std.meta.stringToEnum(Group, args[1]) else null) orelse
        fatal("usage: ci-forms forms|shellfree|all", .{});
    const host = init.environ_map.get("ARCH") orelse @tagName(builtin.cpu.arch);
    const arch: Arch = if (mem.eql(u8, host, "arm64"))
        .aarch64
    else if (mem.eql(u8, host, "amd64"))
        .x86_64
    else
        std.meta.stringToEnum(Arch, host) orelse
            fatal("ARCH={s}: unsupported architecture", .{host});
    const shard = init.environ_map.get("SHARD") orelse "";
    const share = shardOf(shard) catch
        fatal("SHARD={s}: SHARD must be K/N, with 1 <= K <= N", .{shard});
    var env = init.environ_map.clone(gpa) catch fatal("out of memory", .{});
    for (scrubbed) |key| _ = env.swapRemove(key);
    const make: Make = .{ .io = io };

    const tool = command(gpa, arch, &.{"build/host/form"}) catch fatal("out of memory", .{});
    const built = make.run(tool, &env) catch |err| fatal("make build/host/form: {t}", .{err});
    if (built != 0) fatal("make build/host/form: exit {d}", .{built});
    const listed = std.process.run(gpa, io, .{
        .argv = &.{ "build/host/form", "for-arch", @tagName(arch) },
        .environ_map = &env,
    }) catch |err| fatal("build/host/form for-arch {t}: {t}", .{ arch, err });
    std.debug.print("{s}", .{listed.stderr});
    if (!listed.term.success()) fatal("build/host/form for-arch {t}: {f}", .{ arch, listed.term });
    const names = selected(gpa, listed.stdout, share) catch |err|
        fatal("build/host/form for-arch {t}: invalid form inventory: {t}", .{ arch, err });
    log("arch={t} group={t} shard={s} forms={d}", .{ arch, group, shard, names.len });

    const plan: Report = .{ .arch = arch, .group = group, .shard = shard, .inventory = names };
    const exit = checkForms(io, gpa, Dir.cwd(), plan, &env, make) catch |err|
        fatal("stopped: {t}", .{err});
    std.process.exit(if (exit >= 0 and exit < 256) @intCast(exit) else 1);
}

fn log(comptime format: []const u8, args: anytype) void {
    std.debug.print("ci-forms: " ++ format ++ "\n", args);
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    log(format, args);
    std.process.exit(1);
}

/// Make runs one make command, its output the job's, and returns its status.
const Make = struct {
    io: Io,

    fn run(m: Make, argv: []const []const u8, env: *const Environ.Map) !i32 {
        var child = try std.process.spawn(m.io, .{ .argv = argv, .environ_map = env });
        return switch (try child.wait(m.io)) {
            .exited => |code| code,
            .signal, .stopped => |sig| -@as(i32, @intCast(@backingInt(sig))),
            .unknown => -1,
        };
    }
};

/// shardOf reads SHARD: empty for every form, else K/N with 1 <= K <= N,
/// each a decimal number without leading zeros.
fn shardOf(text: []const u8) error{InvalidShard}!?Shard {
    if (text.len == 0) return null;
    var parts: [2]usize = undefined;
    var it = mem.splitScalar(u8, text, '/');
    for (&parts) |*part| {
        const digits = it.next() orelse return error.InvalidShard;
        if (digits.len == 0 or digits[0] == '0') return error.InvalidShard;
        for (digits) |d| if (!std.ascii.isDigit(d)) return error.InvalidShard;
        part.* = std.fmt.parseInt(usize, digits, 10) catch return error.InvalidShard;
    }
    if (it.next() != null or parts[0] > parts[1]) return error.InvalidShard;
    return .{ .k = parts[0], .n = parts[1] };
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return mem.lessThan(u8, a, b);
}

/// selected is shard's share, in name order, of inventory: the lines
/// build/host/form for-arch printed. An inventory that is empty, repeats a
/// form or misnames one is refused, as it would not check what it says.
fn selected(gpa: Allocator, inventory: []const u8, shard: ?Shard) ![]const []const u8 {
    const body = mem.cutSuffix(u8, inventory, "\n") orelse inventory;
    if (body.len == 0) return error.InvalidInventory;
    var names: std.ArrayList([]const u8) = .empty;
    var lines = mem.splitScalar(u8, body, '\n');
    while (lines.next()) |name| {
        if (name.len == 0 or !std.ascii.isLower(name[0])) return error.InvalidInventory;
        for (name) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '-')
            return error.InvalidInventory;
        try names.append(gpa, name);
    }
    const all = names.items;
    mem.sort([]const u8, all, {}, lessThan);
    for (all[1..], all[0 .. all.len - 1]) |a, b|
        if (mem.eql(u8, a, b)) return error.InvalidInventory;
    const s = shard orelse return all;
    var share: std.ArrayList([]const u8) = .empty;
    var i = s.k - 1;
    while (i < all.len) : (i += s.n) try share.append(gpa, all[i]);
    return share.items;
}

/// command is make, for arch and one job at a time, with targets.
fn command(gpa: Allocator, arch: Arch, targets: []const []const u8) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, &.{
        "make",
        "--no-print-directory",
        "-j1",
        try gpa.print("ARCH={t}", .{arch}),
        try gpa.print("BUILD=build/{t}", .{arch}),
    });
    try argv.appendSlice(gpa, targets);
    return argv.items;
}

/// targetsOf are the make targets that check name for group.
fn targetsOf(gpa: Allocator, group: Group, name: []const u8) ![]const []const u8 {
    const integration = try gpa.print("check-{s}", .{name});
    const shellfree = try gpa.print("check-shellfree-{s}", .{name});
    return switch (group) {
        .forms => gpa.dupe([]const u8, &.{integration}),
        .shellfree => gpa.dupe([]const u8, &.{shellfree}),
        .all => gpa.dupe([]const u8, &.{ integration, shellfree }),
    };
}

/// checkForms checks plan's forms in turn under root, each with make.run,
/// which runs one make command and returns its exit status. It returns the
/// first failing form's status, or 0 once every form has passed.
fn checkForms(
    io: Io,
    gpa: Allocator,
    root: Dir,
    plan: Report,
    env: *Environ.Map,
    make: anytype,
) !i32 {
    if (try redirect(io, gpa, root, plan.arch)) |path| {
        log("{s} is a symbolic link; refusing to build, check or clean through it", .{path});
        return error.Redirected;
    }
    const build = try gpa.print("build/{t}", .{plan.arch});
    try root.createDirPath(io, try gpa.print("{s}/check", .{build}));
    try root.createDirPath(io, try gpa.print("{s}/tmp", .{build}));
    const stem = try gpa.print("{s}/check/ci-forms-{t}", .{ build, plan.group });
    var report = plan;
    var results: std.ArrayList(Result) = .empty;
    try record(io, gpa, root, stem, report);
    if (plan.group != .shellfree and
        try make.run(try command(gpa, plan.arch, &.{"_test/form-coverage"}), env) != 0)
        return error.FormCoverage;
    for (plan.inventory, 1..) |name, n| {
        // Each form gets a TMPDIR of its own, empty and private.
        const scratch = try gpa.print("{s}/tmp/{s}", .{ build, name });
        try discard(io, gpa, root, scratch);
        try root.createDir(io, scratch, .fromMode(0o700));
        try env.put("TMPDIR", try root.realPathFileAlloc(io, scratch, gpa));
        const targets = try targetsOf(gpa, plan.group, name);
        const argv = try command(gpa, plan.arch, targets);
        log("form={s} ({d}/{d}): {s}", .{
            name, n, plan.inventory.len, try mem.join(gpa, " ", targets),
        });
        const started = Io.Clock.awake.now(io);
        const exit = try make.run(argv, env);
        const ms = started.durationTo(Io.Clock.awake.now(io)).toMilliseconds();
        const seconds = @as(f64, @floatFromInt(@divFloor(ms + 5, 10))) / 100;
        try results.append(
            gpa,
            .{ .form = name, .command = argv, .exit = exit, .seconds = seconds },
        );
        report.results = results.items;
        try record(io, gpa, root, stem, report);
        if (exit != 0) {
            // Keep the failed image and disk, and leave space for uploading logs.
            log("form={s} exit={d} seconds={d:.2}: stopping; its images stay", .{
                name, exit, seconds,
            });
            return exit;
        }
        log("form={s} exit=0 seconds={d:.2}", .{ name, seconds });
        try clean(io, gpa, root, plan.arch, name);
    }
    report.complete = true;
    try record(io, gpa, root, stem, report);
    log("arch={t} group={t} complete: {d} forms passed", .{
        plan.arch, plan.group, plan.inventory.len,
    });
    return 0;
}

/// redirect returns the first of the build tree's directories that is a
/// symbolic link, or null. Through one, cleaning would remove what the link
/// names, and TMPDIR and the report would land there.
fn redirect(io: Io, gpa: Allocator, root: Dir, arch: Arch) !?[]const u8 {
    const build = try gpa.print("build/{t}", .{arch});
    for ([_][]const u8{
        "build",
        build,
        try gpa.print("{s}/tmp", .{build}),
        try gpa.print("{s}/check", .{build}),
    }) |path| {
        const stat = root.statFile(io, path, lstat) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        if (stat.kind == .sym_link) return path;
    }
    return null;
}

/// record writes report to stem.json whole, by renaming, so that an upload
/// never finds it half written.
fn record(io: Io, gpa: Allocator, root: Dir, stem: []const u8, report: Report) !void {
    const json = try std.json.Stringify.valueAlloc(gpa, report, .{ .whitespace = .indent_2 });
    const temporary = try gpa.print("{s}.tmp", .{stem});
    try root.writeFile(io, .{ .sub_path = temporary, .data = try gpa.print("{s}\n", .{json}) });
    try root.rename(temporary, root, try gpa.print("{s}.json", .{stem}), io);
}

/// clean discards what name's checks made that no later check needs: its
/// images, its disks and native test inputs, and the layers and scratch
/// that any form can fetch or make again. Logs and results stay for upload.
fn clean(io: Io, gpa: Allocator, root: Dir, arch: Arch, name: []const u8) !void {
    const build = try gpa.print("build/{t}", .{arch});
    var paths: std.ArrayList([]const u8) = .empty;
    // Platform checks reuse these small images after the form checks.
    const reused = for ([_][]const u8{ "minimal", "prod", "prod-ssh" }) |kept| {
        if (mem.eql(u8, name, kept)) break true;
    } else false;
    if (!reused) {
        for ([_][]const u8{ "", "-dev", "-app", "-dev-app" }) |suffix|
            try paths.append(gpa, try gpa.print("{s}/{s}{s}", .{ build, name, suffix }));
        try paths.append(gpa, try gpa.print("{s}/native-test-{s}", .{ build, name }));
    }
    // Every repeat and native verification boot has finished before cleanup.
    for ([_][]const u8{ ".img", "-shellfree.img" }) |suffix|
        try paths.append(gpa, try gpa.print("{s}/check/{s}{s}", .{ build, name, suffix }));
    for ([_][]const u8{ "data.img", "config", "seed.tar", "verify.tar" }) |part|
        try paths.append(gpa, try gpa.print("{s}/check/{s}-native/{s}", .{ build, name, part }));
    try paths.append(gpa, try gpa.print("build/native-tests/{t}/{s}", .{ arch, name }));
    // No other form is building; its pinned layers can be fetched again.
    try paths.append(gpa, try gpa.print("{s}/oci", .{build}));
    try paths.append(gpa, try gpa.print("{s}/tmp/{s}", .{ build, name }));
    for (paths.items) |path| discard(io, gpa, root, path) catch |err| {
        log("form={s}: cannot discard {s}: {t}", .{ name, path, err });
        return err;
    };
}

/// discard removes path, relative to root, and all beneath it, never
/// following a symbolic link: a link is removed, not what it names, and a
/// path through one is refused.
fn discard(io: Io, gpa: Allocator, root: Dir, path: []const u8) !void {
    var dir = root;
    defer if (dir.handle != root.handle) dir.close(io);
    var parts = mem.splitScalar(u8, path, '/');
    var name = parts.first();
    const kind = while (true) {
        const kind = (dir.statFile(io, name, lstat) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        }).kind;
        const next = parts.next() orelse break kind;
        // Nothing lies beneath a file, and nothing of ours beneath a link.
        if (kind == .sym_link) return error.Redirected;
        if (kind != .directory) return;
        const sub = try dir.openDir(io, name, .{ .follow_symlinks = false });
        if (dir.handle != root.handle) dir.close(io);
        dir = sub;
        name = next;
    };
    if (kind != .directory) return dir.deleteFile(io, name);
    // OCI layers may hold read-only directories, owned by this runner.
    const owner: Dir.Permissions = .fromMode(0o700);
    try dir.setFilePermissions(io, name, owner, lchmod);
    {
        var top = try dir.openDir(io, name, .{ .iterate = true, .follow_symlinks = false });
        defer top.close(io);
        var walker = try top.walkSelectively(gpa);
        defer walker.deinit();
        while (try walker.next(io)) |found| {
            var entry = found;
            if (entry.kind == .unknown)
                entry.kind = (try entry.dir.statFile(io, entry.basename, lstat)).kind;
            if (entry.kind != .directory) continue;
            try entry.dir.setFilePermissions(io, entry.basename, owner, lchmod);
            try walker.enter(io, entry);
        }
    }
    try dir.deleteTree(io, name);
}

const testing = std.testing;

/// Fake stands in for make. For a form's check it fills the form's TMPDIR,
/// image, layers and disk as a build would, and it fails the form named fail.
const Fake = struct {
    root: Dir,
    gpa: Allocator,
    fail: []const u8 = "",
    commands: std.ArrayList([]const []const u8) = .empty,

    fn run(f: *Fake, argv: []const []const u8, env: *const Environ.Map) !i32 {
        const io = testing.io;
        try f.commands.append(f.gpa, argv);
        const target = for (argv) |a| {
            if (mem.cutPrefix(u8, a, "check-")) |t| break t;
        } else return 0;
        const name = mem.cutPrefix(u8, target, "shellfree-") orelse target;
        const scratch = try f.gpa.print("build/aarch64/tmp/{s}", .{name});
        const readonly = try f.gpa.print("{s}/apko-root/readonly", .{scratch});
        try testing.expectEqualStrings(
            try f.root.realPathFileAlloc(io, scratch, f.gpa),
            env.get("TMPDIR").?,
        );
        try write(f.root, try f.gpa.print("{s}/payload", .{readonly}));
        try f.root.setFilePermissions(io, readonly, .fromMode(0o555), .{});
        try write(f.root, try f.gpa.print("build/aarch64/{s}/slot/root.erofs", .{name}));
        try write(f.root, "build/aarch64/oci/layer");
        try write(f.root, try f.gpa.print("build/aarch64/check/{s}.img", .{name}));
        return if (mem.eql(u8, name, f.fail)) 7 else 0;
    }
};

fn write(dir: Dir, path: []const u8) !void {
    try dir.createDirPath(testing.io, std.fs.path.dirname(path).?);
    try dir.writeFile(testing.io, .{ .sub_path = path, .data = "retained" });
}

/// exists says whether path is there, a link or not.
fn exists(dir: Dir, path: []const u8) bool {
    _ = dir.statFile(testing.io, path, lstat) catch return false;
    return true;
}

/// scrub removes a test's directory, read-only parts and all.
fn scrub(tmp: *testing.TmpDir) void {
    discard(testing.io, testing.allocator, tmp.dir, "build") catch {};
    tmp.cleanup();
}

fn threeForms(gpa: Allocator, group: Group) !Report {
    const names = try selected(gpa, "alpha\nbeta\ngamma\n", null);
    return .{ .arch = .aarch64, .group = group, .shard = "", .inventory = names };
}

/// Recorded is the report's exact shape, as CI's upload carries it.
const Recorded = struct {
    arch: []const u8,
    group: []const u8,
    shard: []const u8,
    inventory: []const []const u8,
    results: []const struct {
        form: []const u8,
        command: []const []const u8,
        exit: i32,
        seconds: f64,
    },
    complete: bool,
};

fn recorded(gpa: Allocator, dir: Dir, path: []const u8) !Recorded {
    const text = try dir.readFileAlloc(testing.io, path, gpa, .limited(1 << 20));
    return std.json.parseFromSliceLeaky(Recorded, gpa, text, .{});
}

test "shards are disjoint and cover every form" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const inventory = "gamma\nalpha\nbeta\ndelta\nepsilon\n";
    const sorted = [_][]const u8{ "alpha", "beta", "delta", "epsilon", "gamma" };
    for ([_]usize{ 3, 4 }) |count| {
        const first = try selected(gpa, inventory, .{ .k = 1, .n = count });
        try testing.expectEqual((sorted.len + count - 1) / count, first.len);
        for (first, 0..) |name, i| try testing.expectEqualStrings(sorted[i * count], name);
        var every: std.ArrayList([]const u8) = .empty;
        for (1..count + 1) |k|
            try every.appendSlice(gpa, try selected(gpa, inventory, .{ .k = k, .n = count }));
        mem.sort([]const u8, every.items, {}, lessThan);
        try testing.expectEqual(sorted.len, every.items.len);
        for (sorted, every.items) |want, got| try testing.expectEqualStrings(want, got);
    }
    try testing.expectEqual(sorted.len, (try selected(gpa, inventory, null)).len);
}

test "an invalid inventory or shard is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    for ([_][]const u8{
        "",        "\n",       "alpha\nalpha\n", "../outside\n", "alpha\n\nbeta\n",
        "Alpha\n", "1alpha\n", "-alpha\n",       "al pha\n",     "al_pha\n",
    }) |inventory|
        try testing.expectError(error.InvalidInventory, selected(gpa, inventory, null));
    try testing.expectEqual(2, (try selected(gpa, "a-1\nb2", null)).len);
    for ([_][]const u8{
        "2/1", "0/3", "1/0", "01/3", "1/03", "/3", "1/", "3", "1/3/5", "a/3", "+1/3", "1_0/20",
    }) |shard| try testing.expectError(error.InvalidShard, shardOf(shard));
    try testing.expectEqual(Shard{ .k = 2, .n = 4 }, (try shardOf("2/4")).?);
    try testing.expectEqual(Shard{ .k = 12, .n = 12 }, (try shardOf("12/12")).?);
    try testing.expectEqual(null, try shardOf(""));
}

test "each group checks its targets, with make for the architecture" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const base = [_][]const u8{
        "make", "--no-print-directory", "-j1", "ARCH=x86_64", "BUILD=build/x86_64",
    };
    const want = [_][]const []const u8{
        &.{"check-alpha"},
        &.{"check-shellfree-alpha"},
        &.{ "check-alpha", "check-shellfree-alpha" },
    };
    for ([_]Group{ .forms, .shellfree, .all }, want) |group, targets| {
        const argv = try command(gpa, .x86_64, try targetsOf(gpa, group, "alpha"));
        try testing.expectEqual(base.len + targets.len, argv.len);
        for (base, argv[0..base.len]) |w, g| try testing.expectEqualStrings(w, g);
        for (targets, argv[base.len..]) |w, g| try testing.expectEqualStrings(w, g);
    }
}

test "all runs both targets, cleans each form and records the complete inventory" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer scrub(&tmp);
    var fake: Fake = .{ .root = tmp.dir, .gpa = gpa };
    var env: Environ.Map = .init(gpa);
    const exit = try checkForms(io, gpa, tmp.dir, try threeForms(gpa, .all), &env, &fake);
    try testing.expectEqual(0, exit);
    const first = fake.commands.items[0];
    try testing.expectEqualStrings("_test/form-coverage", first[first.len - 1]);
    for ([_][]const u8{ "alpha", "beta", "gamma" }) |name| {
        const integration = try gpa.print("check-{s}", .{name});
        const shellfree = try gpa.print("check-shellfree-{s}", .{name});
        const both = for (fake.commands.items) |c| {
            if (c.len >= 2 and mem.eql(u8, c[c.len - 2], integration) and
                mem.eql(u8, c[c.len - 1], shellfree)) break true;
        } else false;
        try testing.expect(both);
        try testing.expect(!exists(tmp.dir, try gpa.print("build/aarch64/{s}", .{name})));
        try testing.expect(!exists(tmp.dir, try gpa.print("build/aarch64/tmp/{s}", .{name})));
        try testing.expect(!exists(tmp.dir, try gpa.print("build/aarch64/check/{s}.img", .{name})));
    }
    const report = try recorded(gpa, tmp.dir, "build/aarch64/check/ci-forms-all.json");
    try testing.expect(report.complete);
    try testing.expectEqualStrings("aarch64", report.arch);
    try testing.expectEqualStrings("all", report.group);
    try testing.expectEqual(report.inventory.len, report.results.len);
    for (report.inventory, report.results) |name, r| {
        try testing.expectEqualStrings(name, r.form);
        try testing.expectEqual(0, r.exit);
        try testing.expectEqualStrings("make", r.command[0]);
    }
}

test "a failure keeps its images and stops before the next form" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer scrub(&tmp);
    var fake: Fake = .{ .root = tmp.dir, .gpa = gpa, .fail = "beta" };
    var env: Environ.Map = .init(gpa);
    const exit = try checkForms(io, gpa, tmp.dir, try threeForms(gpa, .forms), &env, &fake);
    try testing.expectEqual(7, exit);
    try testing.expect(!exists(tmp.dir, "build/aarch64/alpha"));
    try testing.expect(exists(tmp.dir, "build/aarch64/beta/slot/root.erofs"));
    try testing.expect(exists(tmp.dir, "build/aarch64/oci/layer"));
    try testing.expect(exists(tmp.dir, "build/aarch64/tmp/beta/apko-root/readonly/payload"));
    for (fake.commands.items) |c| for (c) |arg|
        try testing.expect(!mem.eql(u8, arg, "check-gamma"));
    const report = try recorded(gpa, tmp.dir, "build/aarch64/check/ci-forms-forms.json");
    try testing.expect(!report.complete);
    try testing.expectEqual(3, report.inventory.len);
    try testing.expectEqual(2, report.results.len);
    try testing.expectEqual(7, report.results[report.results.len - 1].exit);
}

test "cleanup keeps transcripts, results and shared inputs" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer scrub(&tmp);
    const native = "build/aarch64/check/alpha-native/";
    for ([_][]const u8{
        native ++ "data.img",                    native ++ "config/data.key",
        native ++ "seed.tar",                    native ++ "verify.tar",
        native ++ "results.json",                native ++ "seed.log",
        "build/aarch64/kernel/rootfs.tar",       "build/aarch64/programs/init/init",
        "build/aarch64/minimal/slot/root.erofs", "build/aarch64/check/minimal.img",
    }) |path| try write(tmp.dir, path);
    try clean(io, gpa, tmp.dir, .aarch64, "alpha");
    for ([_][]const u8{
        native ++ "results.json",
        native ++ "seed.log",
        "build/aarch64/kernel/rootfs.tar",
        "build/aarch64/programs/init/init",
        "build/aarch64/minimal/slot/root.erofs",
    }) |path| try testing.expect(exists(tmp.dir, path));
    for ([_][]const u8{ "data.img", "config", "seed.tar", "verify.tar" }) |part|
        try testing.expect(!exists(tmp.dir, try gpa.print(native ++ "{s}", .{part})));
    // A form that platform checks boot again keeps its image, not its disk.
    try clean(io, gpa, tmp.dir, .aarch64, "minimal");
    try testing.expect(exists(tmp.dir, "build/aarch64/minimal/slot/root.erofs"));
    try testing.expect(!exists(tmp.dir, "build/aarch64/check/minimal.img"));
}

test "cleanup removes read-only generated directories" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer scrub(&tmp);
    try write(tmp.dir, "build/aarch64/alpha/rootfs/readonly/payload");
    try write(tmp.dir, "build/aarch64/alpha/rootfs/closed/payload");
    for ([_]struct { []const u8, std.posix.mode_t }{
        .{ "build/aarch64/alpha/rootfs/readonly", 0o555 },
        .{ "build/aarch64/alpha/rootfs/closed", 0 },
        .{ "build/aarch64/alpha/rootfs", 0o555 },
    }) |d| try tmp.dir.setFilePermissions(io, d[0], .fromMode(d[1]), .{});
    try clean(io, gpa, tmp.dir, .aarch64, "alpha");
    try testing.expect(!exists(tmp.dir, "build/aarch64/alpha"));
}

test "a redirected build tree is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer scrub(&tmp);
    try write(tmp.dir, "outside/evidence");
    const outside = try tmp.dir.realPathFileAlloc(io, "outside", gpa);
    try tmp.dir.createDirPath(io, "build/aarch64");
    try tmp.dir.symLink(io, outside, "build/aarch64/tmp", .{ .is_directory = true });
    var fake: Fake = .{ .root = tmp.dir, .gpa = gpa };
    var env: Environ.Map = .init(gpa);
    try testing.expectError(
        error.Redirected,
        checkForms(io, gpa, tmp.dir, try threeForms(gpa, .all), &env, &fake),
    );
    const evidence = try tmp.dir.readFileAlloc(io, "outside/evidence", gpa, .limited(64));
    try testing.expectEqualStrings("retained", evidence);
    try testing.expectEqual(0, fake.commands.items.len);
    const links = [_][]const u8{
        "build", "build/aarch64", "build/aarch64/tmp", "build/aarch64/check",
    };
    for (links, 0..) |link, i| {
        var root = try tmp.dir.createDirPathOpen(io, try gpa.print("case{d}", .{i}), .{});
        defer root.close(io);
        if (std.fs.path.dirname(link)) |parent| try root.createDirPath(io, parent);
        try root.symLink(io, outside, link, .{ .is_directory = true });
        try testing.expectEqualStrings(link, (try redirect(io, gpa, root, .aarch64)).?);
    }
    try testing.expectEqual(null, try redirect(io, gpa, tmp.dir, .x86_64));
}

test "cleanup unlinks a redirect without following it, and refuses a path through one" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer scrub(&tmp);
    try write(tmp.dir, "outside/evidence");
    try write(tmp.dir, "outside/data.img");
    const outside = try tmp.dir.realPathFileAlloc(io, "outside", gpa);
    try tmp.dir.createDirPath(io, "build/aarch64/check");
    try tmp.dir.symLink(io, outside, "build/aarch64/alpha", .{ .is_directory = true });
    try clean(io, gpa, tmp.dir, .aarch64, "alpha");
    try testing.expect(exists(tmp.dir, "outside/evidence"));
    try testing.expect(!exists(tmp.dir, "build/aarch64/alpha"));
    try tmp.dir.symLink(io, outside, "build/aarch64/check/alpha-native", .{ .is_directory = true });
    try testing.expectError(error.Redirected, clean(io, gpa, tmp.dir, .aarch64, "alpha"));
    try testing.expect(exists(tmp.dir, "outside/data.img"));
}

/// environ is the test's environment without what an outer make passes,
/// so that a make run here reads only its own command line.
fn environ(gpa: Allocator) !Environ.Map {
    var env = try testing.environ.createMap(gpa);
    for (scrubbed) |key| _ = env.swapRemove(key);
    return env;
}

/// mustRun runs argv to its end, within a minute, and fails unless it exits 0.
fn mustRun(
    gpa: Allocator,
    argv: []const []const u8,
    env: *const Environ.Map,
    cwd: std.process.Child.Cwd,
) !std.process.RunResult {
    const io = testing.io;
    const r = try std.process.run(gpa, io, .{
        .argv = argv,
        .environ_map = env,
        .cwd = cwd,
        .timeout = .{ .deadline = .fromNow(io, .{ .raw = .fromSeconds(60), .clock = .awake }) },
    });
    if (!r.term.success()) {
        std.debug.print("{s}: {f}\n{s}{s}", .{ argv[0], r.term, r.stdout, r.stderr });
        return error.TestUnexpectedResult;
    }
    return r;
}

fn expectHas(text: []const u8, want: []const u8, has: bool) !void {
    if ((mem.find(u8, text, want) != null) == has) return;
    std.debug.print("{s} {s}:\n{s}\n", .{ if (has) "missing" else "unwanted", want, text });
    return error.TestUnexpectedResult;
}

test "generated forms do not also run their unconfigured base form" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var env = try environ(gpa);
    for ([_][]const u8{ "bastion", "people" }) |name| {
        // Recursive recipes run even with -n; their build-log redirects
        // must not overwrite those of an integration run at the same time.
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const build = try tmp.dir.realPathFileAlloc(testing.io, ".", gpa);
        const r = try mustRun(gpa, &.{
            "make",
            "-n",
            "MAKE=echo",
            try gpa.print("BUILD={s}", .{build}),
            try gpa.print("check-{s}", .{name}),
        }, &env, .inherit);
        try expectHas(r.stdout, try gpa.print("test/{s}-form ", .{name}), true);
        try expectHas(r.stdout, try gpa.print("FORM={s}/check/{s}-check ", .{ build, name }), true);
        try expectHas(r.stdout, try gpa.print("FORM={s} ", .{name}), false);
    }
}

test "nodata reuses the native prod disk without its key" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "check/prod-native");
    try tmp.dir.createDirPath(io, "test");
    try tmp.dir.writeFile(io, .{
        .sub_path = "check/prod-native/data.img",
        .data = "LUKS-test-ciphertext",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "check/prod-native/data.key",
        .data = "must-not-be-passed",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "test/boot",
        .data = "#!/bin/sh\nprintf '%s\\n' \"$@\" > boot-args\n",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    var env = try environ(gpa);
    try env.put("CHECK", try tmp.dir.realPathFileAlloc(io, "check", gpa));
    try env.put("OUT", "/image");
    try env.put("KERNEL", "/kernel");
    try env.put("CMDLINE", "console=ttyS0");
    const script = try Dir.cwd().realPathFileAlloc(io, "test/check-nodata", gpa);
    _ = try mustRun(gpa, &.{ "sh", script, "qemu" }, &env, .{ .dir = tmp.dir });
    try testing.expectEqualStrings(
        "LUKS-test-ciphertext",
        try tmp.dir.readFileAlloc(io, "check/nodata.img", gpa, .limited(64)),
    );
    const args = try tmp.dir.readFileAlloc(io, "boot-args", gpa, .limited(64 << 10));
    try expectHas(args, "nodata.img,format=raw,if=virtio", true);
    try testing.expectEqual(1, mem.count(u8, args, "-drive"));
    try expectHas(args, "data.key", false);
    try expectHas(args, "prod-native", false);
}

test "selected release forms dispatch to their intended checks" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "checks.mk",
        .data = "_check-legacy-prod-ssh:\n\t@echo dispatched-legacy-prod-ssh\n" ++
            "_check-legacy-playground:\n\t@echo dispatched-legacy-playground\n" ++
            "check-native-tests-minimal:\n\t@echo dispatched-native-minimal\n" ++
            "_check-legacy-minimal:\n\t@echo unexpected-legacy-minimal; exit 99\n",
    });
    // howl, which every check needs, must be neither built nor run.
    try tmp.dir.writeFile(io, .{
        .sub_path = "howl",
        .data = "#!/bin/sh\nexit 99\n",
        .flags = .{ .permissions = .fromMode(0o700) },
    });
    const overrides = try tmp.dir.realPathFileAlloc(io, "checks.mk", gpa);
    const howl = try tmp.dir.realPathFileAlloc(io, "howl", gpa);
    var env = try environ(gpa);
    const r = try mustRun(gpa, &.{
        "make",
        "-s",
        "-f",
        "Makefile",
        "-f",
        overrides,
        "-o",
        howl,
        "FORMS_FOR_ARCH=minimal prod-ssh playground",
        try gpa.print("HOWL={s}", .{howl}),
        "check-prod-ssh",
        "check-playground",
        "check-minimal",
    }, &env, .inherit);
    try testing.expectEqualStrings(
        "dispatched-legacy-prod-ssh\ndispatched-legacy-playground\ndispatched-native-minimal\n",
        r.stdout,
    );
}
