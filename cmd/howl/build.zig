//! build makes a form's image as the Makefile's image targets do, step by
//! step: the same tools with the same arguments, writing the same files at
//! the same paths, so the bytes match. make still compiles the programs.
//! The steps are in packages.zig and slot.zig. See README.md and
//! docs/design/howl-build.md.

const std = @import("std");
const forms = @import("form");
const compose = @import("compose");
const image = @import("image");
const howl = @import("howl.zig");
const adhoc = @import("adhoc.zig");
const progress = @import("progress.zig");
const packages = @import("packages.zig");
const slot = @import("slot.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;

/// Goals are the make targets a build stands in for.
pub const Goals = struct {
    /// image is BUILD/vmlinuz and OUT/initramfs.zst, for a direct boot.
    image: bool = false,
    /// slot is OUT/slot: vmlinuz, both stage0s, root.erofs and cmdline.
    slot: bool = false,
    /// disk is OUT/disk.img, a UEFI boot disk of the slot.
    disk: bool = false,
    /// qcow2 is OUT/disk.qcow2, the disk a release publishes.
    qcow2: bool = false,
    /// vmlinux is BUILD/vmlinux, x86_64's kernel for Firecracker.
    vmlinux: bool = false,
};

/// Spec is what to build: a form, for an arch, with or without a shell
/// and an application.
pub const Spec = struct {
    /// form is a form's name, or the directory of one outside forms/.
    form: []const u8,
    arch: howl.Arch,
    /// dev adds a shell, as DEV=1 does.
    dev: bool = false,
    /// app is the staged application's root (howl.appBuild), or null.
    app: ?[]const u8 = null,
    /// freeze pins every package to its lock, as FREEZE=1 does.
    freeze: bool = false,
};

/// Paths are where a build writes, as the Makefile names them.
pub const Paths = struct {
    /// build is BUILD, build/ARCH: the kernel and stage0, shared by forms.
    build: []const u8,
    /// out is OUT, build/ARCH/FORM[-dev][-app].
    out: []const u8,
    /// programs is PROGRAMS, where make compiles them.
    programs: []const u8,
};

pub fn paths(gpa: Allocator, s: Spec) !Paths {
    const name = std.fs.path.basename(mem.trimEnd(u8, s.form, "/"));
    return .{
        .build = try gpa.print("build/{t}", .{s.arch}),
        .out = try gpa.print("build/{t}/{s}{s}{s}", .{
            s.arch, name, if (s.dev) "-dev" else "", if (s.app != null) "-app" else "",
        }),
        .programs = try gpa.print("build/{t}/programs", .{s.arch}),
    };
}

const DiskFormat = enum { qcow2, raw, vhd, vmdk };

const BuildOptions = struct {
    form: []const u8,
    app: ?[]const u8 = null,
    dir: []const u8 = "dist",
    arch: howl.Arch,
    format: DiskFormat = .qcow2,
};

/// buildOptions parses build's command line: FORM, and -o, --arch,
/// --format and --app, each with a value. host is this machine's arch, or
/// null if werewolf does not build for it.
fn buildOptions(args: []const []const u8, host: ?howl.Arch, why: *howl.Why) !BuildOptions {
    var form: ?[]const u8 = null;
    var arch = host;
    var o: BuildOptions = .{ .form = "", .arch = undefined };
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (args[i].len == 0 or args[i][0] != '-') {
            if (form != null) return why.refuse("{s}: one form at a time", .{args[i]});
            form = args[i];
            continue;
        }
        const a, const v = try howl.flagValue(args, &i, why);
        if (std.mem.eql(u8, a, "-o")) {
            o.dir = v;
        } else if (std.mem.eql(u8, a, "--arch")) {
            arch = howl.archName(v) orelse return why.refuse(howl.arch_refusal, .{v});
        } else if (std.mem.eql(u8, a, "--app")) {
            o.app = v;
        } else if (std.mem.eql(u8, a, "--format")) {
            o.format = std.meta.stringToEnum(DiskFormat, v) orelse
                return why.refuse("--format {s}: qcow2 raw vhd vmdk", .{v});
        } else return why.refuse(
            "{s}: build takes -o, --arch, --format and --app\n{s}",
            .{ a, howl.usage },
        );
    }
    o.form = form orelse return why.refuse("no form\n{s}", .{howl.usage});
    o.arch = arch orelse return why.refuse("{s}: --arch", .{howl.not_built_here});
    return o;
}

/// build makes a form's release files in -o DIR, as make's _dist-form
/// does: the image's files under their release names, and the manifest,
/// unsigned (release/manifest).
pub fn build(io: Io, gpa: Allocator, given: []const []const u8, why: *howl.Why) !void {
    const all = (try adhoc.take(io, gpa, .build, given, why)) orelse return;
    const verbose, const args = try howl.verboseFlag(gpa, all);
    const o = try buildOptions(args, howl.hostArch(), why);
    // ref is the form as given, a name or a directory; f is its name.
    const ref = o.form;
    const f = std.fs.path.basename(std.mem.trimEnd(u8, ref, "/"));
    const a = @tagName(o.arch);
    const dir = o.dir;
    const format = o.format;
    _ = try howl.chain(io, gpa, ref, why);
    const ab = try howl.appBuild(io, gpa, ref, o.arch, o.app, why);
    const command = try gpa.print("howl build {s}", .{std.mem.join(gpa, " ", args) catch ref});
    var steps: progress.Steps = try .init(io, gpa, why, .{
        .verbose = verbose,
        .command = command,
        .log = try gpa.print("build/log/{s}-{s}-build.log", .{ f, a }),
        .first = howl.start_phase,
        .make = false,
    });

    // minimal is released whole, for direct boot; the rest as the slot
    // the updater follows, and as a disk to boot a VM from.
    const direct = std.mem.eql(u8, f, "minimal");
    const spec: Spec = .{ .form = ref, .arch = o.arch, .app = ab.root, .freeze = frozen() };
    try make(
        io,
        gpa,
        &steps,
        spec,
        if (direct) .{ .image = true } else .{ .slot = true, .qcow2 = true },
    );
    const p = try paths(gpa, spec);
    // A DEV=1 build has a root shell on its console (cmd/debug-shell): never one to publish.
    if (Dir.cwd().access(io, try gpa.print("{s}/meta/usr/share/werewolf/dev", .{p.out}), .{})) |_|
        return steps.fail(try gpa.print(
            "refused: {s} is a DEV=1 build, with a root shell on its console",
            .{f},
        ))
    else |_| {}
    try steps.enter(progress.phaseOf("_dist-form").?);
    var manifest: std.ArrayList([]const u8) = .empty;
    try manifest.appendSlice(gpa, &.{
        "release/manifest",
        f,
        a,
        try gpa.print("{s}/rootfs.tar", .{p.out}),
        try gpa.print("{s}/meta/usr/share/werewolf/kernel", .{p.out}),
        dir,
    });
    const released: []const [2][]const u8 = if (direct) &.{
        .{ "vmlinuz", try gpa.print("{s}/vmlinuz", .{p.build}) },
        .{ "initramfs.zst", try gpa.print("{s}/initramfs.zst", .{p.out}) },
        .{ "cmdline", try gpa.print("{s}/slot/cmdline", .{p.out}) },
    } else &.{
        .{ "vmlinuz", try gpa.print("{s}/slot/vmlinuz", .{p.out}) },
        .{ "stage0.zst", try gpa.print("{s}/slot/stage0.zst", .{p.out}) },
        .{ "stage0-bitten.zst", try gpa.print("{s}/slot/stage0-bitten.zst", .{p.out}) },
        .{ "root.erofs", try gpa.print("{s}/slot/root.erofs", .{p.out}) },
        .{ "cmdline", try gpa.print("{s}/slot/cmdline", .{p.out}) },
        .{ "disk.qcow2", try gpa.print("{s}/disk.qcow2", .{p.out}) },
    };
    for (released) |r| try manifest.append(gpa, try gpa.print("{s}={s}", .{ r[0], r[1] }));
    const made = try steps.exec(&.{.{ .argv = manifest.items }}, .{});
    if (!made.ok) return steps.fail("release/manifest failed");

    const name = try gpa.print("{s}/{s}-{s}.json", .{ dir, f, a });
    const text = Dir.cwd().readFileAlloc(io, name, gpa, .limited(1 << 20)) catch |err|
        return steps.fail(try gpa.print("{s}: {s}", .{ name, @errorName(err) }));
    // Parse only the manifest's file list. The updater reads the rest
    // (cmd/slot-update/release.zig).
    const m = json.parseFromSliceLeaky(
        struct { files: json.ArrayHashMap(struct { sha256: []const u8, size: u64 }) },
        gpa,
        text,
        .{ .ignore_unknown_fields = true },
    ) catch return steps.fail(try gpa.print("{s}: not a manifest", .{name}));
    const files = m.files.map;

    // boot is what a machine boots: the disk, or the initramfs of a form
    // released for direct boot. Another --format replaces it below.
    var boot = try gpa.print("{s}/{s}-{s}-{s}", .{
        dir, f, a, if (files.contains("disk.qcow2")) "disk.qcow2" else "initramfs.zst",
    });
    if (format != .qcow2) {
        if (!files.contains("disk.qcow2")) return steps.fail(
            try gpa.print("{s} is released for direct boot, without a disk to convert", .{f}),
        );
        const dst = try gpa.print("{s}/{s}-{s}-disk.{t}", .{ dir, f, a, format });
        // Azure takes a fixed VHD; force_size keeps its size the disk's exactly.
        const convert: []const []const u8 = switch (format) {
            .raw => &.{ "qemu-img", "convert", "-f", "qcow2", "-O", "raw", boot, dst },
            .vhd => &.{
                "qemu-img",
                "convert",
                "-f",
                "qcow2",
                "-O",
                "vpc",
                "-o",
                "subformat=fixed,force_size=on",
                boot,
                dst,
            },
            .vmdk => &.{ "qemu-img", "convert", "-f", "qcow2", "-O", "vmdk", boot, dst },
            .qcow2 => unreachable,
        };
        try steps.enter(.{
            .name = try gpa.print("Converting the disk to {t}", .{format}),
            .short = "convert",
        });
        const converted = try steps.exec(&.{.{ .argv = convert }}, .{});
        if (!converted.ok) return steps.fail("qemu-img failed");
        boot = dst;
    }
    const done = try steps.finish();

    // Say what was made, where, and what to do next.
    const look: progress.Look = .of(io, Io.File.stderr());
    var err_out: Io.Writer.Allocating = .init(gpa);
    const e = &err_out.writer;
    try e.print(
        "{s} Built {s} for {s} in {f}\n",
        .{ look.check(), f, a, progress.Clock{ .seconds = done.seconds } },
    );
    if (!verbose) try e.print("  {f}\n", .{look.dim(try gpa.print("{f}", .{done}))});
    Io.File.stderr().writeStreamingAll(io, err_out.written()) catch {};
    var out = Io.File.stdout().writerStreaming(io, &.{});
    const w = &out.interface;
    const size = if (Dir.cwd().statFile(io, boot, .{})) |st| st.size else |_| 0;
    try w.print(
        "  {s}  {f}\n",
        .{
            boot,
            look.dim(try gpa.print("{f}, every file in {s}", .{ Size{ .bytes = size }, name })),
        },
    );
    if (verbose) {
        for (files.keys()) |file| try w.print("  {s}/{s}-{s}-{s}\n", .{ dir, f, a, file });
    }
    err_out.clearRetainingCapacity();
    if (o.arch == howl.hostArch()) {
        try e.print(
            "  Next: howl create NAME --with {s}   {f}\n",
            .{
                ref,
                look.dim(try gpa.print("a machine on {t}, kept", .{howl.engine(io, gpa, null).on})),
            },
        );
        try e.print(
            "        howl run --with {s}           {f}\n",
            .{ ref, look.dim("boot it here, its console in this terminal") },
        );
    } else {
        try e.print(
            "  Next: howl upload {s} --on {s}\n",
            .{ boot, howl.Platform.list(.cloud, "|") },
        );
    }
    Io.File.stderr().writeStreamingAll(io, err_out.written()) catch {};
}

/// buildTargets builds make's targets of one form natively: image, slot,
/// disk, qcow2 and vmlinux, as `make TARGET` would, at the same paths. It
/// is how the gate compares the two, until run and create use build.zig.
///
///   howl _build --with FORM [--arch ARCH] [--dev] [--app DIR] [--verbose] GOAL...
pub fn buildTargets(io: Io, gpa: Allocator, given: []const []const u8, why: *howl.Why) !void {
    const verbose, const args = try howl.verboseFlag(gpa, given);
    const syntax = "_build --with FORM [--arch ARCH] [--dev] [--app DIR] [--verbose] " ++
        "image|slot|disk|qcow2|vmlinux...";
    var form: ?[]const u8 = null;
    var arch = howl.hostArch();
    var dev = false;
    var app_dir: ?[]const u8 = null;
    var goals: Goals = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--dev")) {
            dev = true;
        } else if (std.mem.startsWith(u8, args[i], "-")) {
            const flag, const v = try howl.flagValue(args, &i, why);
            if (std.mem.eql(u8, flag, "--with")) {
                form = v;
            } else if (std.mem.eql(u8, flag, "--arch")) {
                arch = howl.archName(v) orelse return why.refuse(howl.arch_refusal, .{v});
            } else if (std.mem.eql(u8, flag, "--app")) {
                app_dir = v;
            } else return why.refuse("{s}: {s}", .{ flag, syntax });
        } else {
            const goal = std.meta.stringToEnum(std.meta.FieldEnum(Goals), args[i]) orelse
                return why.refuse("{s}: {s}", .{ args[i], syntax });
            switch (goal) {
                inline else => |g| @field(goals, @tagName(g)) = true,
            }
        }
    }
    const ref = form orelse return why.refuse("{s}", .{syntax});
    const for_arch = arch orelse return why.refuse("{s}: --arch", .{howl.not_built_here});
    if (goals.vmlinux and for_arch != .x86_64)
        return why.refuse("vmlinux is x86_64's, for Firecracker", .{});
    _ = try howl.chain(io, gpa, ref, why);
    const ab = try howl.appBuild(io, gpa, ref, for_arch, app_dir, why);
    const f = std.fs.path.basename(std.mem.trimEnd(u8, ref, "/"));
    var steps: progress.Steps = try .init(io, gpa, why, .{
        .verbose = verbose,
        .command = try gpa.print("howl _build {s}", .{try std.mem.join(gpa, " ", given)}),
        .log = try gpa.print("build/log/{s}-{t}-build.log", .{ f, for_arch }),
        .first = howl.start_phase,
        .make = false,
    });
    try make(io, gpa, &steps, .{
        .form = ref,
        .arch = for_arch,
        .dev = dev,
        .app = ab.root,
        .freeze = frozen(),
    }, goals);
    const done = try steps.finish();
    const look: progress.Look = .of(io, Io.File.stderr());
    howl.say(io, "{s} built {s} for {t} in {f}  {f}", .{
        look.check(),
        f,
        for_arch,
        progress.Clock{ .seconds = done.seconds },
        look.dim(try gpa.print("{f}", .{done})),
    });
}

/// frozen reports whether FREEZE is set, as make's FREEZE=1: every package
/// pinned to its lock, for a reproducible build.
fn frozen() bool {
    const v = howl.environ.get("FREEZE") orelse return false;
    return v.len > 0;
}

/// Size formats a byte count for people: 812 KiB, 44 MiB, 1.2 GiB.
const Size = struct {
    bytes: u64,

    pub fn format(s: Size, w: *Io.Writer) Io.Writer.Error!void {
        const k: u64 = 1 << 10;
        if (s.bytes < k << 10) return w.print("{d} KiB", .{(s.bytes + k - 1) / k});
        if (s.bytes < k << 20) return w.print("{d} MiB", .{(s.bytes + (k << 10) - 1) / (k << 10)});
        return w.print("{d}.{d} GiB", .{ s.bytes >> 30, ((s.bytes >> 20) & 1023) * 10 / 1024 });
    }
};

/// B is one build: what it was asked, what it derives from the form
/// before any step runs, and the helpers its steps share.
pub const B = struct {
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    spec: Spec,
    p: Paths,
    /// arch is spec's, as compose names it.
    arch: compose.Arch,
    chain: []const forms.Form,
    /// name is the form's name, the last of its chain's.
    name: []const u8,
    /// self is howl's executable, which holds the steps' code: what the
    /// Makefile and build/host/form were to make's targets.
    self: []const u8,
    /// form_files are the chain's apko.yaml and form.yaml files.
    form_files: []const []const u8,
    /// rootfs are the chain's rootfs files and etc/sv directories, whose
    /// removal changes nothing else a step could see.
    rootfs: []const []const u8,
    /// bins are the programs the overlay lays in; stage0's are apart.
    bins: []const []const u8,
    stage0_bin: []const u8,
    loader_bin: []const u8,
    /// overlay are the directories laid over the packages, OUT/ro first.
    overlay: []const []const u8,
    /// made are what make still builds for the overlay: melange's packages
    /// and a tutorial's compiled application.
    made: []const []const u8,
    /// app are --app's directories and files.
    app: []const []const u8,
    modules: compose.Modules,
    params: []const image.Param,
    /// env is howl's environment with COPYFILE_DISABLE=1, so macOS's tar
    /// adds no AppleDouble files.
    env: *const std.process.Environ.Map,

    /// path formats a path the build names.
    pub fn path(b: *B, comptime fmt: []const u8, args: anytype) ![]const u8 {
        return b.gpa.print(fmt, args);
    }

    /// fail ends the build for a reason (progress.Steps.fail).
    pub fn fail(b: *B, comptime fmt: []const u8, args: anytype) error{ Refused, OutOfMemory } {
        return b.steps.fail(try b.gpa.print(fmt, args));
    }

    /// begin reports whether target must be made, as make decides: it is
    /// missing, or an input is newer. If so, it enters target's phase and
    /// returns the time it began. A missing input fails the build.
    pub fn begin(b: *B, target: []const u8, inputs: []const []const u8) !?Io.Timestamp {
        if (Dir.cwd().statFile(b.io, target, .{})) |made| {
            const newer = for (inputs) |in| {
                const st = Dir.cwd().statFile(b.io, in, .{}) catch |err|
                    return b.fail("{s}: {t}, needed for {s}", .{ in, err, target });
                if (st.mtime.nanoseconds > made.mtime.nanoseconds) break true;
            } else false;
            if (!newer) return null;
        } else |_| {}
        if (progress.phaseOf(target)) |ph| try b.steps.enter(ph);
        return Io.Clock.awake.now(b.io);
    }

    /// done logs target and the time since it began.
    pub fn done(b: *B, target: []const u8, began: Io.Timestamp) !void {
        const ms: u64 = @intCast(@max(began.untilNow(b.io, .awake).toMilliseconds(), 0));
        try b.steps.note("{s} {d}.{d}s", .{ target, ms / 1000, ms % 1000 / 100 });
    }

    /// run runs one command, and fails the build if it fails.
    pub fn run(b: *B, argv: []const []const u8, o: struct {
        cwd: ?[]const u8 = null,
        stdin: ?Io.File = null,
        stdout: ?Io.File = null,
    }) !void {
        const ran = try b.steps.exec(&.{.{ .argv = argv, .cwd = o.cwd, .env = b.env }}, .{
            .stdin = o.stdin,
            .stdout = o.stdout,
        });
        if (!ran.ok) return b.fail("{s} failed", .{argv[0]});
    }

    /// tmp is the name a step writes target under, then renames: an
    /// interrupted build leaves nothing half written that looks made.
    pub fn tmp(b: *B, target: []const u8) ![]const u8 {
        return b.gpa.print("{s}.tmp", .{target});
    }

    /// rename moves from over target, the last act of a step.
    pub fn rename(b: *B, from: []const u8, target: []const u8) !void {
        Dir.rename(Dir.cwd(), from, Dir.cwd(), target, b.io) catch |err|
            return b.fail("{s}: {t}", .{ target, err });
    }

    /// write writes data to target through a temporary name.
    pub fn write(b: *B, target: []const u8, data: []const u8) !void {
        const t = try b.tmp(target);
        try Dir.cwd().writeFile(b.io, .{ .sub_path = t, .data = data });
        try b.rename(t, target);
    }

    /// put writes dir/name, a file of a tree a step makes whole.
    pub fn put(b: *B, dir: []const u8, name: []const u8, data: []const u8) !void {
        try Dir.cwd().writeFile(
            b.io,
            .{ .sub_path = try b.path("{s}/{s}", .{ dir, name }), .data = data },
        );
    }

    /// copy copies a file with its mode, as cp does.
    pub fn copy(b: *B, from: []const u8, to: []const u8) !void {
        Dir.copyFile(Dir.cwd(), from, Dir.cwd(), to, b.io, .{}) catch |err|
            return b.fail("{s}: {t}", .{ from, err });
    }

    /// read returns the file at p, of at most limit bytes.
    pub fn read(b: *B, p: []const u8, limit: usize) ![]u8 {
        return Dir.cwd().readFileAlloc(b.io, p, b.gpa, .limited(limit)) catch |err|
            b.fail("{s}: {t}", .{ p, err });
    }

    /// absolute returns p from the current directory, for a tool that runs
    /// in another.
    pub fn absolute(b: *B, p: []const u8) ![]const u8 {
        const cwd = std.process.currentPathAlloc(b.io, b.gpa) catch |err|
            return b.fail("the current directory: {t}", .{err});
        return std.fs.path.join(b.gpa, &.{ cwd, p });
    }

    /// capture returns what argv writes to standard output, which goes to
    /// a file beside target rather than to the log.
    pub fn capture(b: *B, target: []const u8, argv: []const []const u8) ![]u8 {
        const out = try b.path("{s}.out", .{target});
        {
            const f = try Dir.cwd().createFile(b.io, out, .{});
            defer f.close(b.io);
            try b.run(argv, .{ .stdout = f });
        }
        const text = try b.read(out, 64 << 20);
        try Dir.cwd().deleteFile(b.io, out);
        return text;
    }
};

/// make builds goals of s, logging each step and its time to steps.
pub fn make(io: Io, gpa: Allocator, steps: *progress.Steps, s: Spec, goals: Goals) !void {
    pipeline(io, gpa, steps, s, goals) catch |err| switch (err) {
        error.Refused => return err,
        else => return steps.fail(@errorName(err)),
    };
}

fn pipeline(io: Io, gpa: Allocator, steps: *progress.Steps, s: Spec, goals: Goals) !void {
    const p = try paths(gpa, s);
    // make compiles werewolf's programs, in a checkout: each compile is
    // mostly one thread, so as many at once as there are CPUs.
    if (exists(io, "Makefile")) {
        try steps.enter(progress.phaseOf(try gpa.print("{s}/", .{p.programs})).?);
        const ran = try steps.exec(&.{.{ .argv = &.{
            howl.make_cmd,
            "-s",
            try gpa.print("-j{d}", .{std.Thread.getCpuCount() catch 1}),
            "--no-print-directory",
            try gpa.print("FORM={s}", .{s.form}),
            try gpa.print("ARCH={t}", .{s.arch}),
            "programs",
        } }}, .{});
        if (!ran.ok) return steps.fail("make programs failed");
    }
    var b = try plan(io, gpa, steps, s, p);
    try packages.kernel(&b);
    if (goals.vmlinux) try packages.vmlinux(&b);
    if (!goals.image and !goals.slot and !goals.disk and !goals.qcow2) return;

    const suffix = if (s.dev) "-dev" else "";
    const config = try b.path("{s}/form/{s}{s}.yaml", .{ p.build, b.name, suffix });
    const lock = try b.path("build/lock/{s}{s}.lock.json", .{ b.name, suffix });
    try packages.apkoConfig(&b, config);
    try packages.relock(&b, lock, config, b.form_files);
    const rootfs = try b.path("{s}/rootfs.tar", .{p.out});
    try packages.apkoBuild(&b, rootfs, config, lock, &.{ lock, config });
    try packages.madeByMake(&b);
    try slot.meta(&b, rootfs);
    try slot.make(&b, rootfs, goals);
}

/// every_program are the programs in every form but init and bite-cleanup,
/// each in PROGRAMS/NAME/usr/lib/werewolf/NAME, in the Makefile's overlay
/// order: the module loader, the network's setup and policy, the mounts,
/// posture, the seal's two, and those that replace shell scripts
/// (docs/design/shell-free.md).
const every_program = [_][]const u8{
    "modload",     "iface-up",   "fence",        "mount",       "mount-broker",
    "posture",     "seal-watch", "seal",         "runit-stage", "reboot",
    "grub-setenv", "slot-keep",  "power-button", "debug-shell", "ssh-host-key",
    "leash",       "leash-reap",
};

/// plan reads the form's chain and works out everything the steps need.
fn plan(io: Io, gpa: Allocator, steps: *progress.Steps, s: Spec, p: Paths) !B {
    var f: forms.Failure = .{};
    const chain = forms.chain(io, gpa, Dir.cwd(), s.form, &f) catch |err| switch (err) {
        error.Form => return steps.fail(f.text),
        else => |e| return e,
    };
    const name = chain[chain.len - 1].name;

    // The overlay's directories, in the Makefile's order (OVERLAY_DIRS),
    // and the programs in them.
    var bins: std.ArrayList([]const u8) = .empty;
    var overlay: std.ArrayList([]const u8) = .empty;
    try overlay.append(gpa, try gpa.print("{s}/ro", .{p.out}));
    try bins.append(gpa, try gpa.print("{s}/init/init", .{p.programs}));
    try overlay.append(gpa, try gpa.print("{s}/init", .{p.programs}));
    for (every_program) |prog| {
        try bins.append(
            gpa,
            try gpa.print("{s}/{s}/usr/lib/werewolf/{s}", .{ p.programs, prog, prog }),
        );
        try overlay.append(gpa, try gpa.print("{s}/{s}", .{ p.programs, prog }));
    }
    try bins.append(gpa, try gpa.print("{s}/bite-cleanup/usr/bin/bite-cleanup", .{p.programs}));
    try overlay.append(gpa, try gpa.print("{s}/bite-cleanup", .{p.programs}));

    var form_files: std.ArrayList([]const u8) = .empty;
    var rootfs: std.ArrayList([]const u8) = .empty;
    // The form's programs' directories: form.yaml's programs, each in
    // PROGRAMS/NAME (popen-shim.so in PROGRAMS/popen-shim, as make's
    // basename names it), and a form's own, F/cmd/P, in PROGRAMS/forms/F.
    var dirs: std.array_hash_map.String(void) = .empty;
    for (chain) |c| {
        for ([_][]const u8{ "apko.yaml", "form.yaml" }) |file| {
            const at = try gpa.print("{s}/{s}", .{ c.dir, file });
            if (exists(io, at)) try form_files.append(gpa, at);
        }
        try rootfsInputs(io, gpa, try gpa.print("{s}/rootfs", .{c.dir}), &rootfs);
        for (try c.items(gpa, "programs")) |item| {
            var it = mem.tokenizeAny(u8, item, " \t");
            while (it.next()) |prog| {
                const stem = prog[0 .. mem.findScalarLast(u8, prog, '.') orelse prog.len];
                const dir = try gpa.print("{s}/{s}", .{ p.programs, stem });
                try bins.append(gpa, try gpa.print("{s}/usr/lib/werewolf/{s}", .{ dir, prog }));
                try dirs.put(gpa, dir, {});
            }
        }
        var cmd = Dir.cwd().openDir(
            io,
            try gpa.print("{s}/cmd", .{c.dir}),
            .{ .iterate = true },
        ) catch
            continue;
        defer cmd.close(io);
        const dir = try gpa.print("{s}/forms/{s}", .{ p.programs, std.fs.path.basename(c.dir) });
        var it = cmd.iterate();
        while (try it.next(io)) |e| if (e.kind == .directory) {
            try bins.append(gpa, try gpa.print("{s}/usr/lib/werewolf/{s}", .{ dir, e.name }));
            try dirs.put(gpa, dir, {});
        };
    }
    const sorted = dirs.keys();
    mem.sortUnstable([]const u8, sorted, {}, lessThan);
    try overlay.appendSlice(gpa, sorted);

    // Then what make builds for the overlay (examples/build.mk, then
    // melange.mk), then --app.
    var made: std.ArrayList([]const u8) = .empty;
    if (isExample(name)) {
        try overlay.append(gpa, try gpa.print("{s}/application", .{p.out}));
        try made.append(gpa, if (mem.eql(u8, name, "example-aspnet"))
            try gpa.print("{s}/application.stamp", .{p.out})
        else
            try gpa.print("{s}/application/usr/lib/app/server", .{p.out}));
    }
    if (try hasRecipes(io, gpa, chain)) {
        try overlay.append(gpa, try gpa.print("{s}/melange", .{p.out}));
        try made.append(gpa, try gpa.print("{s}/melange.stamp", .{p.out}));
    }
    var app: std.ArrayList([]const u8) = .empty;
    if (s.app) |root| {
        try overlay.append(gpa, root);
        try app.append(gpa, root);
        try tree(io, gpa, root, &app);
    }

    const arch: compose.Arch = switch (s.arch) {
        .aarch64 => .aarch64,
        .x86_64 => .x86_64,
    };
    const allowed = compose.allowances(gpa, chain, &f) catch |err| switch (err) {
        error.Form => return steps.fail(f.text),
        else => |e| return e,
    };
    var params: std.ArrayList(image.Param) = .empty;
    for (compose.moduleParams(allowed, arch)) |mp|
        try params.append(gpa, .{ .module = mp.module, .value = mp.value });

    const env = try gpa.create(std.process.Environ.Map);
    env.* = try howl.environ.clone(gpa);
    try env.put("COPYFILE_DISABLE", "1");
    return .{
        .io = io,
        .gpa = gpa,
        .steps = steps,
        .spec = s,
        .p = p,
        .arch = arch,
        .chain = chain,
        .name = name,
        .self = try std.process.executablePathAlloc(io, gpa),
        .form_files = form_files.items,
        .rootfs = rootfs.items,
        .bins = bins.items,
        .stage0_bin = try gpa.print("{s}/stage0/init", .{p.programs}),
        .loader_bin = try gpa.print("{s}/modload/usr/lib/werewolf/modload", .{p.programs}),
        .overlay = overlay.items,
        .made = made.items,
        .app = app.items,
        .modules = try compose.modules(gpa, chain, arch),
        .params = params.items,
        .env = env,
    };
}

pub fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return mem.lessThan(u8, a, b);
}

fn exists(io: Io, p: []const u8) bool {
    Dir.cwd().access(io, p, .{}) catch return false;
    return true;
}

/// rootfsInputs adds a rootfs directory's files, and its etc/sv
/// directories: a service removed or renamed changes nothing else a step
/// could see, and its supervise link would stay.
fn rootfsInputs(io: Io, gpa: Allocator, dir: []const u8, out: *std.ArrayList([]const u8)) !void {
    var d = Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch return;
    defer d.close(io);
    var w = try d.walk(gpa);
    defer w.deinit();
    while (try w.next(io)) |e| {
        const full = try gpa.print("{s}/{s}", .{ dir, e.path });
        const sv = mem.endsWith(u8, full, "/etc/sv") or mem.find(u8, full, "/etc/sv/") != null;
        if (e.kind == .file or (e.kind == .directory and sv)) try out.append(gpa, full);
    }
}

/// tree adds every file and directory under dir.
fn tree(io: Io, gpa: Allocator, dir: []const u8, out: *std.ArrayList([]const u8)) !void {
    var d = try Dir.cwd().openDir(io, dir, .{ .iterate = true });
    defer d.close(io);
    var w = try d.walk(gpa);
    defer w.deinit();
    while (try w.next(io)) |e| if (e.kind == .file or e.kind == .directory)
        try out.append(gpa, try gpa.print("{s}/{s}", .{ dir, e.path }));
}

/// isExample reports whether name is a tutorial form whose application
/// make compiles (examples/build.mk).
fn isExample(name: []const u8) bool {
    for ([_][]const u8{ "example-go", "example-rust", "example-aspnet" }) |e|
        if (mem.eql(u8, name, e)) return true;
    return false;
}

/// hasRecipes reports whether the chain has melange recipes (melange.mk).
fn hasRecipes(io: Io, gpa: Allocator, chain: []const forms.Form) !bool {
    for (chain) |c| {
        var d = Dir.cwd().openDir(
            io,
            try gpa.print("{s}/melange", .{c.dir}),
            .{ .iterate = true },
        ) catch
            continue;
        defer d.close(io);
        var it = d.iterate();
        while (try it.next(io)) |e| if (mem.endsWith(u8, e.name, ".yaml")) return true;
    }
    return false;
}

const testing = std.testing;

test buildOptions {
    var why: howl.Why = .{};
    const o = try buildOptions(&.{ "bastion", "--format", "vhd", "-o", "out" }, .aarch64, &why);
    try testing.expectEqualStrings("bastion", o.form);
    try testing.expectEqualStrings("out", o.dir);
    try testing.expectEqual(.aarch64, o.arch);
    try testing.expectEqual(DiskFormat.vhd, o.format);
    try testing.expectEqual(
        .x86_64,
        (try buildOptions(&.{ "--arch", "x86_64", "prod" }, null, &why)).arch,
    );
    for ([_][]const []const u8{
        &.{},
        &.{ "a", "b" },
        &.{ "a", "--arch", "riscv64" },
        &.{ "a", "--format", "zip" },
        &.{ "a", "--on", "gcp" },
        &.{ "a", "-o" },
    }) |args| try testing.expectError(error.Refused, buildOptions(args, .aarch64, &why));
    try testing.expectError(error.Refused, buildOptions(&.{"a"}, null, &why));
    try testing.expectEqual(
        .aarch64,
        (try buildOptions(&.{ "--arch=arm64", "prod" }, null, &why)).arch,
    );
}

test {
    _ = packages;
    _ = slot;
}
