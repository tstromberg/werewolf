//! runtime builds a private ARM64 bhyve and its U-Boot firmware from pinned
//! commits, patches and packages on native FreeBSD. It never installs or
//! elevates. See README.md.
//!
//!     zig run tools/bhyve-arm64/runtime.zig -- OUTPUT --packages DIR
//!         [--freebsd-cache REPO] [--uboot-cache REPO] [--jobs N]
const std = @import("std");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Environ = std.process.Environ;
const Sha256 = std.crypto.hash.sha2.Sha256;

const freebsd = "893c7c99b60dd500a1ad30de667713e2400de15a";
const uboot = "e37de002fac3895e8d0b60ae2015e17bb33e2b5b";
const ports = "3a7a1297a515552d4aef02f06cd5ee1a92ed4583";
const release = "15.1-RELEASE-p5";
const usage = "usage: zig run tools/bhyve-arm64/runtime.zig -- OUTPUT --packages DIR " ++
    "[--freebsd-cache REPO] [--uboot-cache REPO] [--jobs N]";

const Patch = struct { name: []const u8, data: []const u8 };
const rtc: Patch = .{ .name = "rtc.patch", .data = @embedFile("rtc.patch") };
const board: Patch = .{ .name = "u-boot.patch", .data = @embedFile("u-boot.patch") };

const Options = struct {
    output: []const u8,
    packages: []const u8,
    freebsd_cache: ?[]const u8 = null,
    uboot_cache: ?[]const u8 = null,
    jobs: i64 = 4,
};

const Host = struct { system: []const u8, machine: []const u8, release: []const u8 };
const Pin = struct { sha256: []const u8, name: []const u8 };
const Found = struct { path: []const u8, sha256: [64]u8 };
const Plan = struct { options: Options, packages: []const []const u8 };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    const u = std.posix.uname();
    const host: Host = .{
        .system = std.mem.sliceTo(&u.sysname, 0),
        .machine = std.mem.sliceTo(&u.machine, 0),
        .release = std.mem.sliceTo(&u.release, 0),
    };
    var why: []const u8 = "";
    const plan = prepare(io, gpa, host, args[1..], &why) catch |err| {
        std.debug.print(
            "bhyve-arm64: {s}\n",
            .{if (err == error.Refused) why else @errorName(err)},
        );
        std.process.exit(2);
    };
    var buf: [4096]u8 = undefined;
    var log = Io.File.stderr().writerStreaming(io, &buf);
    var r: Recipe = try .init(io, gpa, init.environ_map, &log.interface);
    build(&r, plan, u) catch |err| {
        log.interface.flush() catch {};
        std.debug.print("bhyve-arm64: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn refuse(why: *[]const u8, text: []const u8) error{Refused} {
    why.* = text;
    return error.Refused;
}

/// admit reads the command line and refuses a host whose ABI the pinned
/// source does not match.
fn admit(host: Host, args: []const []const u8, why: *[]const u8) !Options {
    var o: Options = .{ .output = "", .packages = "" };
    var output: ?[]const u8 = null;
    var packages: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const flag = args[i];
        if (!std.mem.startsWith(u8, flag, "--")) {
            if (output != null) return refuse(why, usage);
            output = flag;
            continue;
        }
        i += 1;
        if (i == args.len) return refuse(why, usage);
        const value = args[i];
        if (std.mem.eql(u8, flag, "--packages")) {
            packages = value;
        } else if (std.mem.eql(u8, flag, "--freebsd-cache")) {
            o.freebsd_cache = value;
        } else if (std.mem.eql(u8, flag, "--uboot-cache")) {
            o.uboot_cache = value;
        } else if (std.mem.eql(u8, flag, "--jobs")) {
            o.jobs = std.fmt.parseInt(i64, value, 10) catch return refuse(why, usage);
        } else return refuse(why, usage);
    }
    o.output = output orelse return refuse(why, usage);
    o.packages = packages orelse return refuse(why, usage);
    if (!std.mem.eql(u8, host.system, "FreeBSD") or !std.mem.eql(u8, host.release, release) or
        !(std.mem.eql(u8, host.machine, "arm64") or std.mem.eql(u8, host.machine, "aarch64")))
        return refuse(why, "requires native FreeBSD " ++ release ++
            " arm64 (source must match the host ABI)");
    if (o.jobs < 1) return refuse(why, "--jobs must be positive");
    return o;
}

/// pins are packages.sha256's packages, in digest order.
fn pins(gpa: Allocator) ![]Pin {
    var out: std.ArrayList(Pin) = .empty;
    var lines = std.mem.tokenizeScalar(u8, @embedFile("packages.sha256"), '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const sha = fields.next() orelse return error.BadPins;
        const name = fields.next() orelse return error.BadPins;
        if (sha.len != 64 or fields.next() != null) return error.BadPins;
        try out.append(gpa, .{ .sha256 = sha, .name = name });
    }
    std.mem.sort(Pin, out.items, {}, struct {
        fn less(_: void, a: Pin, b: Pin) bool {
            return std.mem.lessThan(u8, a.sha256, b.sha256);
        }
    }.less);
    return out.items;
}

/// select takes, for each pin, a found package with its digest: a name
/// proves nothing. It names the pins nothing found.
fn select(
    gpa: Allocator,
    pinned: []const Pin,
    found: []const Found,
    why: *[]const u8,
) ![]const []const u8 {
    var paths: std.ArrayList([]const u8) = .empty;
    var missing: std.ArrayList(u8) = .empty;
    next: for (pinned) |pin| {
        for (found) |f| if (std.mem.eql(u8, &f.sha256, pin.sha256)) {
            try paths.append(gpa, f.path);
            continue :next;
        };
        if (missing.items.len > 0) try missing.appendSlice(gpa, ", ");
        try missing.appendSlice(gpa, pin.name);
    }
    if (missing.items.len > 0)
        return refuse(why, try gpa.print("missing pinned packages: {s}", .{missing.items}));
    return paths.items;
}

/// prepare refuses what the recipe cannot build before it makes anything.
fn prepare(io: Io, gpa: Allocator, host: Host, args: []const []const u8, why: *[]const u8) !Plan {
    const o = try admit(host, args, why);
    var found: std.ArrayList(Found) = .empty;
    var dir = try Dir.cwd().openDir(io, o.packages, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind == .directory or !std.mem.endsWith(u8, entry.basename, ".pkg")) continue;
        const path = try std.fs.path.join(gpa, &.{ o.packages, entry.path });
        try found.append(gpa, .{ .path = path, .sha256 = try digest(io, path) });
    }
    return .{ .options = o, .packages = try select(gpa, try pins(gpa), found.items, why) };
}

fn digest(io: Io, path: []const u8) ![64]u8 {
    const file = try Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var buf: [1 << 16]u8 = undefined;
    var reader = file.reader(io, &buf);
    var hash = Sha256.init(.{});
    while (true) {
        const n = try reader.interface.readSliceShort(&buf);
        if (n == 0) break;
        hash.update(buf[0..n]);
    }
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

/// Recipe runs the build's commands, saying each first.
const Recipe = struct {
    io: Io,
    gpa: Allocator,
    env: *const Environ.Map,
    /// git is env without the user's git configuration or prompts.
    git: Environ.Map,
    log: *Io.Writer,

    fn init(io: Io, gpa: Allocator, env: *const Environ.Map, log: *Io.Writer) !Recipe {
        var git = try env.clone(gpa);
        try git.put("GIT_CONFIG_GLOBAL", "/dev/null");
        try git.put("GIT_CONFIG_NOSYSTEM", "1");
        try git.put("GIT_TERMINAL_PROMPT", "0");
        return .{ .io = io, .gpa = gpa, .env = env, .git = git, .log = log };
    }

    const Run = struct {
        cwd: ?[]const u8 = null,
        env: ?*const Environ.Map = null,
        /// stdout names the file the command's standard output goes to.
        stdout: ?[]const u8 = null,
    };

    /// run runs argv to success. git always runs with r.git.
    fn run(r: *Recipe, argv: []const []const u8, o: Run) !void {
        try r.log.print("bhyve-arm64: {s}\n", .{try join(r.gpa, argv)});
        try r.log.flush();
        const out = if (o.stdout) |path|
            try Dir.cwd().createFile(r.io, path, .{ .exclusive = true })
        else
            null;
        defer if (out) |f| f.close(r.io);
        var child = try std.process.spawn(r.io, .{
            .argv = argv,
            .cwd = if (o.cwd) |d| .{ .path = d } else .inherit,
            .environ_map = r.environment(argv, o.env),
            .stdin = .ignore,
            .stdout = if (out) |f| .{ .file = f } else .inherit,
        });
        const term = try child.wait(r.io);
        if (term != .exited or term.exited != 0) return error.CommandFailed;
    }

    /// first is the first line argv prints, which must succeed.
    fn first(r: *Recipe, argv: []const []const u8) ![]const u8 {
        const result = try std.process.run(r.gpa, r.io, .{
            .argv = argv,
            .environ_map = r.environment(argv, null),
            .stdout_limit = .limited(1 << 20),
        });
        if (result.term != .exited or result.term.exited != 0) return error.CommandFailed;
        var lines = std.mem.splitScalar(u8, result.stdout, '\n');
        return lines.first();
    }

    fn environment(
        r: *Recipe,
        argv: []const []const u8,
        env: ?*const Environ.Map,
    ) *const Environ.Map {
        if (std.mem.eql(u8, argv[0], "git")) return &r.git;
        return env orelse r.env;
    }
};

const Step = struct { argv: []const []const u8, stdout: ?[]const u8 = null };

/// sparse are the FreeBSD source paths bhyve and libfdt build from.
const sparse = [_][]const u8{
    "Makefile",       "Makefile.inc1",    "Makefile.sys.inc", "usr.sbin/Makefile.inc",
    "usr.sbin/bhyve", "lib/Makefile.inc", "lib/libfdt",       "sys",
    "share/mk",       "contrib/lib9p",
};

/// checkoutSteps put name's revision in dest: exported from cache's
/// committed tree, never its possibly patched worktree, or fetched.
fn checkoutSteps(
    gpa: Allocator,
    dest: []const u8,
    name: []const u8,
    revision: []const u8,
    cache: ?[]const u8,
) ![]const Step {
    const paths: []const []const u8 = if (std.mem.eql(u8, name, "freebsd/freebsd-src"))
        &sparse
    else
        &.{};
    var out: std.ArrayList(Step) = .empty;
    // A repository of its own keeps git apply from a parent checkout.
    try out.append(gpa, .{ .argv = try gpa.dupe([]const u8, &.{ "git", "init", "-q", dest }) });
    if (cache) |c| {
        const archive = try std.fs.path.join(gpa, &.{ dest, "source.tar" });
        try out.append(gpa, .{
            .argv = try std.mem.concat(gpa, []const u8, &.{
                &.{ "git", "-C", c, "archive", revision }, paths,
            }),
            .stdout = archive,
        });
        try out.append(gpa, .{ .argv = try gpa.dupe([]const u8, &.{
            "tar", "-xf", archive, "-C", dest,
        }) });
        return out.items;
    }
    const upstream = try gpa.print("https://github.com/{s}.git", .{name});
    try out.append(gpa, .{ .argv = try gpa.dupe([]const u8, &.{
        "git", "-C", dest, "remote", "add", "origin", upstream,
    }) });
    try out.append(gpa, .{ .argv = try gpa.dupe([]const u8, &.{
        "git", "-C", dest, "fetch", "--depth=1", "--filter=blob:none", "origin", revision,
    }) });
    if (paths.len > 0) try out.append(gpa, .{ .argv = try std.mem.concat(gpa, []const u8, &.{
        &.{ "git", "-C", dest, "sparse-checkout", "set", "--skip-checks" }, paths,
    }) });
    try out.append(gpa, .{ .argv = try gpa.dupe([]const u8, &.{
        "git", "-C", dest, "checkout", "--detach", revision,
    }) });
    return out.items;
}

fn checkout(
    r: *Recipe,
    root: []const u8,
    name: []const u8,
    revision: []const u8,
    cache: ?[]const u8,
) ![]const u8 {
    const dest = try std.fs.path.join(r.gpa, &.{ root, name });
    try Dir.cwd().createDirPath(r.io, dest);
    for (try checkoutSteps(r.gpa, dest, name, revision, cache)) |step|
        try r.run(step.argv, .{ .stdout = step.stdout });
    if (cache != null) try Dir.cwd().deleteFile(
        r.io,
        try std.fs.path.join(r.gpa, &.{ dest, "source.tar" }),
    );
    const actual = try r.first(&.{ "git", "-C", cache orelse dest, "rev-parse", revision });
    if (!std.mem.eql(u8, actual, revision)) return error.SourceRevisionMismatch;
    return dest;
}

fn build(r: *Recipe, plan: Plan, host: std.posix.utsname) !void {
    const io = r.io;
    const gpa = r.gpa;
    const o = plan.options;
    const jobs = try gpa.print("-j{d}", .{o.jobs});
    // Refuse reuse, including an existing empty directory.
    try Dir.cwd().createDir(io, o.output, .fromMode(0o700));
    const root = try Dir.cwd().realPathFileAlloc(io, o.output, gpa);
    const deps = try std.fs.path.join(gpa, &.{ root, "deps" });
    const bins = try std.fs.path.join(gpa, &.{ root, "bin" });
    try Dir.cwd().createDir(io, deps, .default_dir);
    try Dir.cwd().createDir(io, bins, .default_dir);
    for (plan.packages) |package| try r.run(&.{ "tar", "-xf", package, "-C", deps }, .{});
    const prefix = try std.fs.path.join(gpa, &.{ deps, "usr/local" });
    for ([_][2][]const u8{ .{ "sed", "gsed" }, .{ "date", "gdate" }, .{ "touch", "gtouch" } }) |a|
        try Dir.cwd().symLink(
            io,
            try gpa.print("{s}/bin/{s}", .{ prefix, a[1] }),
            try gpa.print("{s}/{s}", .{ bins, a[0] }),
            .{},
        );
    const src = try checkout(r, root, "freebsd/freebsd-src", freebsd, o.freebsd_cache);
    const firmware = try checkout(r, root, "u-boot/u-boot", uboot, o.uboot_cache);
    for ([_]struct { []const u8, Patch }{ .{ src, rtc }, .{ firmware, board } }) |p| {
        const patch = try std.fs.path.join(gpa, &.{ root, p[1].name });
        try Dir.cwd().writeFile(io, .{ .sub_path = patch, .data = p[1].data });
        try r.run(&.{ "git", "-C", p[0], "apply", "--check", patch }, .{});
        try r.run(&.{ "git", "-C", p[0], "apply", patch }, .{});
    }
    try r.run(&.{ "make", "-C", try gpa.print("{s}/lib/libfdt", .{src}), jobs, "all" }, .{});
    try r.run(&.{
        "make",                       "-C",  try gpa.print("{s}/usr.sbin/bhyve", .{src}), jobs,
        "WITHOUT_BHYVE_SNAPSHOT=yes", "all",
    }, .{});
    var env = try r.env.clone(gpa);
    try env.put(
        "PATH",
        try gpa.print("{s}:{s}/bin:/usr/bin:/bin:/usr/local/bin", .{ bins, prefix }),
    );
    try env.put("LD_LIBRARY_PATH", try gpa.print("{s}/lib", .{prefix}));
    try env.put("BISON_PKGDATADIR", try gpa.print("{s}/share/bison", .{prefix}));
    try env.put("M4", try gpa.print("{s}/bin/gm4", .{prefix}));
    try env.put("SHELL", try gpa.print("{s}/bin/bash", .{prefix}));
    try env.put("CONFIG_SHELL", try gpa.print("{s}/bin/bash", .{prefix}));
    try env.put("CROSS_COMPILE", "aarch64-none-elf-");
    // U-Boot's own build runs Python.
    try env.put("PYTHON", "python3");
    try env.put("SOURCE_DATE_EPOCH", "1751846400");
    // Match the patched pinned checkout's version even when building an
    // archive; otherwise setlocalversion embeds different strings for
    // identical sources.
    const version = "UBOOTRELEASE=2025.07-g" ++ uboot[0..12] ++ "-dirty";
    try r.run(&.{ "gmake", "HOSTCC=cc", version, "bhyve_arm64_defconfig" }, .{
        .cwd = firmware,
        .env = &env,
    });
    try r.run(&.{ "gmake", jobs, "HOSTCC=cc", version, "u-boot.bin" }, .{
        .cwd = firmware,
        .env = &env,
    });
    const artifacts = [_][2][]const u8{
        .{ "bhyve", try gpa.print("{s}/usr.sbin/bhyve/bhyve", .{src}) },
        .{ "u-boot.bin", try gpa.print("{s}/u-boot.bin", .{firmware}) },
    };
    var digests: [artifacts.len][64]u8 = undefined;
    for (artifacts, &digests) |a, *d| {
        const to = try std.fs.path.join(gpa, &.{ root, a[0] });
        try Dir.cwd().copyFile(a[1], Dir.cwd(), to, io, .{});
        d.* = try digest(io, to);
    }
    try Dir.cwd().copyFile(
        try gpa.print("{s}/.config", .{firmware}),
        Dir.cwd(),
        try std.fs.path.join(gpa, &.{ root, "u-boot.config" }),
        io,
        .{},
    );

    var manifest: Io.Writer.Allocating = .init(gpa);
    var s: std.json.Stringify = .{ .writer = &manifest.writer, .options = .{
        .whitespace = .indent_2,
    } };
    try s.beginObject();
    try s.objectField("host");
    try s.write(.{
        .system = std.mem.sliceTo(&host.sysname, 0),
        .node = std.mem.sliceTo(&host.nodename, 0),
        .release = std.mem.sliceTo(&host.release, 0),
        .version = std.mem.sliceTo(&host.version, 0),
        .machine = std.mem.sliceTo(&host.machine, 0),
    });
    try s.objectField("freebsd_commit");
    try s.write(freebsd);
    try s.objectField("uboot_commit");
    try s.write(uboot);
    try s.objectField("ports_commit");
    try s.write(ports);
    try s.objectField("patches");
    try s.beginObject();
    for ([_]Patch{ rtc, board }) |p| {
        var d: [32]u8 = undefined;
        Sha256.hash(p.data, &d, .{});
        try s.objectField(p.name);
        try s.write(&std.fmt.bytesToHex(d, .lower));
    }
    try s.endObject();
    try s.objectField("packages");
    try s.beginObject();
    for (try pins(gpa)) |pin| {
        try s.objectField(pin.sha256);
        try s.write(pin.name);
    }
    try s.endObject();
    try s.objectField("artifacts");
    try s.beginObject();
    for (artifacts, digests) |a, d| {
        try s.objectField(a[0]);
        try s.write(&d);
    }
    try s.endObject();
    try s.objectField("host_tools");
    try s.beginObject();
    for ([_][]const u8{ "cc", "gmake", "python3", "git" }) |tool| {
        try s.objectField(tool);
        try s.write(try r.first(&.{ tool, "--version" }));
    }
    try s.objectField("zig");
    try s.write(@import("builtin").zig_version_string);
    try s.endObject();
    try s.objectField("installed");
    try s.write(false);
    try s.objectField("secure_boot");
    try s.write(false);
    try s.endObject();
    try manifest.writer.writeByte('\n');
    try Dir.cwd().writeFile(io, .{
        .sub_path = try std.fs.path.join(gpa, &.{ root, "manifest.json" }),
        .data = manifest.written(),
    });
    const runtime = try std.fs.path.join(gpa, &.{ root, "runtime.env" });
    try Dir.cwd().writeFile(io, .{ .sub_path = runtime, .data = try gpa.print(
        "export BHYVE_BINARY={s}\nexport BHYVE_ARM64_FIRMWARE={s}\n",
        .{
            try quote(gpa, try std.fs.path.join(gpa, &.{ root, "bhyve" })),
            try quote(gpa, try std.fs.path.join(gpa, &.{ root, "u-boot.bin" })),
        },
    ) });
    try r.log.print("bhyve-arm64: built the private runtime: {s}\n", .{runtime});
    try r.log.flush();
}

/// quote is word as a POSIX shell reads it back.
fn quote(gpa: Allocator, word: []const u8) ![]const u8 {
    const plain = word.len > 0 and for (word) |b| {
        if (!std.ascii.isAlphanumeric(b) and std.mem.findScalar(u8, "@%+=:,./-_", b) == null)
            break false;
    } else true;
    if (plain) return word;
    var out: std.ArrayList(u8) = .empty;
    try out.append(gpa, '\'');
    for (word) |b| if (b == '\'') try out.appendSlice(gpa, "'\"'\"'") else try out.append(gpa, b);
    try out.append(gpa, '\'');
    return out.items;
}

fn join(gpa: Allocator, argv: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (argv, 0..) |a, i| {
        if (i > 0) try out.append(gpa, ' ');
        try out.appendSlice(gpa, try quote(gpa, a));
    }
    return out.items;
}

const testing = std.testing;
const native: Host = .{ .system = "FreeBSD", .machine = "arm64", .release = release };

test "refusals come before the output exists" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const output = try std.fs.path.join(gpa, &.{ root, "output" });
    const packages = try std.fs.path.join(gpa, &.{ root, "packages" });
    try tmp.dir.createDir(io, "packages", .default_dir);
    const args = [_][]const u8{ output, "--packages", packages };
    var why: []const u8 = "";
    const cases = [_]struct { Host, []const []const u8, []const u8 }{
        .{ .{ .system = "Linux", .machine = "aarch64", .release = release }, &args, "requires" },
        .{ .{ .system = "FreeBSD", .machine = "amd64", .release = release }, &args, "requires" },
        .{
            .{ .system = "FreeBSD", .machine = "arm64", .release = "15.0-RELEASE" },
            &args,
            "requires",
        },
        .{ native, &(args ++ .{ "--jobs", "0" }), "--jobs must be positive" },
        .{ native, &.{ output, "--packages" }, "usage" },
        .{ native, &.{ "--packages", packages }, "usage" },
        .{ native, &args, "missing pinned packages: " },
    };
    for (cases) |c| {
        try testing.expectError(error.Refused, prepare(io, gpa, c[0], c[1], &why));
        try testing.expect(std.mem.startsWith(u8, why, c[2]));
        try testing.expectError(error.FileNotFound, tmp.dir.access(io, "output", .{}));
    }
    // A matching name is insufficient: only the locked digest is accepted.
    try tmp.dir.writeFile(io, .{
        .sub_path = "packages/bison-3.8.2_2,1.pkg",
        .data = "not the pinned package",
    });
    try testing.expectError(error.Refused, prepare(io, gpa, native, &args, &why));
    try testing.expect(std.mem.find(u8, why, "bison-3.8.2_2,1") != null);
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, "output", .{}));
}

test "packages are chosen by digest alone, in digest order" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const pinned = try pins(gpa);
    try testing.expectEqual(15, pinned.len);
    for (pinned[1..], pinned[0 .. pinned.len - 1]) |b, a|
        try testing.expect(std.mem.lessThan(u8, a.sha256, b.sha256));
    var found: std.ArrayList(Found) = .empty;
    for (pinned, 0..) |p, i| try found.append(gpa, .{
        .path = try gpa.print("cache/{d}.pkg", .{pinned.len - i}),
        .sha256 = p.sha256[0..64].*,
    });
    var why: []const u8 = "";
    const paths = try select(gpa, pinned, found.items, &why);
    try testing.expectEqualStrings("cache/15.pkg", paths[0]);
    found.items[3].sha256[0] ^= 1;
    try testing.expectError(error.Refused, select(gpa, pinned, found.items, &why));
    try testing.expectEqualStrings(
        try gpa.print("missing pinned packages: {s}", .{pinned[3].name}),
        why,
    );
}

test "a cached checkout exports the committed tree into its own repository" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    const steps = try checkoutSteps(
        gpa,
        "/build/freebsd/freebsd-src",
        "freebsd/freebsd-src",
        freebsd,
        "/cached/repository",
    );
    try testing.expectEqualDeep(
        @as([]const []const u8, &.{ "git", "init", "-q", "/build/freebsd/freebsd-src" }),
        steps[0].argv,
    );
    try testing.expectEqualDeep(
        @as([]const []const u8, &.{ "git", "-C", "/cached/repository", "archive", freebsd }),
        steps[1].argv[0..5],
    );

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    var env = try testing.environ.createMap(gpa);
    var discard: Io.Writer.Discarding = .init(&.{});
    var r: Recipe = try .init(io, gpa, &env, &discard.writer);
    const cache = try std.fs.path.join(gpa, &.{ root, "cache" });
    for ([_][]const u8{
        "Makefile",               "Makefile.inc1",           "Makefile.sys.inc",
        "usr.sbin/Makefile.inc",  "usr.sbin/bhyve/Makefile", "lib/Makefile.inc",
        "lib/libfdt/Makefile",    "sys/Makefile",            "share/mk/sys.mk",
        "contrib/lib9p/Makefile", "bin/ls/Makefile",
    }) |file| {
        const path = try std.fs.path.join(gpa, &.{ cache, file });
        try Dir.cwd().createDirPath(io, std.fs.path.dirname(path).?);
        try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "committed\n" });
    }
    try r.run(&.{ "git", "init", "-q", cache }, .{});
    try r.run(&.{ "git", "-C", cache, "add", "." }, .{});
    try r.run(&.{
        "git",                     "-C",     cache, "-c", "user.name=test", "-c",
        "user.email=test@invalid", "commit", "-q",  "-m", "pin",
    }, .{});
    const head = try r.first(&.{ "git", "-C", cache, "rev-parse", "HEAD" });
    try Dir.cwd().writeFile(io, .{
        .sub_path = try std.fs.path.join(gpa, &.{ cache, "Makefile" }),
        .data = "patched worktree\n",
    });
    const dest = try checkout(&r, root, "freebsd/freebsd-src", head, cache);
    try testing.expectEqualStrings(
        try std.fs.path.join(gpa, &.{ root, "freebsd/freebsd-src" }),
        dest,
    );
    var tree = try Dir.cwd().openDir(io, dest, .{});
    defer tree.close(io);
    try testing.expectEqualStrings(
        "committed\n",
        try tree.readFileAlloc(io, "Makefile", gpa, .limited(64)),
    );
    try testing.expectEqualStrings(
        "committed\n",
        try tree.readFileAlloc(io, "sys/Makefile", gpa, .limited(64)),
    );
    try tree.access(io, ".git", .{});
    try testing.expectError(error.FileNotFound, tree.access(io, "bin", .{}));
    try testing.expectError(error.FileNotFound, tree.access(io, "source.tar", .{}));
    try testing.expectError(
        error.SourceRevisionMismatch,
        checkout(
            &r,
            try std.fs.path.join(gpa, &.{ root, "again" }),
            "u-boot/u-boot",
            "HEAD",
            cache,
        ),
    );
}

test quote {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    try testing.expectEqualStrings("/a/b-c_1.bin", try quote(gpa, "/a/b-c_1.bin"));
    try testing.expectEqualStrings("'/a b/it'\"'\"'s'", try quote(gpa, "/a b/it's"));
    try testing.expectEqualStrings("''", try quote(gpa, ""));
}
