//! build makes a form's image step by step, with the tools and arguments
//! the Makefile's image recipes used, at their paths, so the bytes match.
//! make still compiles the programs. The steps are in packages.zig,
//! melange.zig, app.zig and slot.zig. See README.md and
//! docs/design/howl-build.md.

const std = @import("std");
const forms = @import("form");
const compose = @import("compose");
const image = @import("image");
const howl = @import("howl.zig");
const adhoc = @import("adhoc.zig");
const app = @import("app.zig");
const melange = @import("melange.zig");
const progress = @import("progress.zig");
const packages = @import("packages.zig");
const slot = @import("slot.zig");
const manifest = @import("manifest.zig");
const disk = @import("disk.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;

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
    /// build and programs replace BUILD and PROGRAMS, as make's BUILD= and
    /// PROGRAMS= do, to keep a build apart from build/ARCH.
    build: ?[]const u8 = null,
    programs: ?[]const u8 = null,
    /// disk is the disk goal's size and kernel arguments, as make's
    /// DISK_MIB and DISK_ARGS; the qcow2 goal takes the size only.
    disk: disk.Options = .{},
    /// published takes werewolf's programs from its apk repository, as make's
    /// PUBLISHED=1 does, not from PROGRAMS: a machine built so updates them
    /// with apk (docs/design/custom-updates.md). stage0's and a form's own
    /// programs, which are not packaged, still come from PROGRAMS.
    published: bool = false,
    /// disk_path is where the disk goal writes, as make's DISK; null is
    /// OUT/disk.img. A machine's disk has its own: the disk is rebuilt by
    /// file times alone, so a path reused with other arguments would not be.
    disk_path: ?[]const u8 = null,
};

/// Paths are where a build writes, as the Makefile names them.
pub const Paths = struct {
    /// build is BUILD, build/ARCH: the kernel and stage0, shared by forms.
    build: []const u8,
    /// out is OUT, build/ARCH/FORM[-dev][-app][-published].
    out: []const u8,
    /// programs is PROGRAMS, where make compiles them.
    programs: []const u8,
};

pub fn paths(gpa: Allocator, s: Spec) !Paths {
    const name = std.fs.path.basename(mem.trimEnd(u8, s.form, "/"));
    const dir = s.build orelse try gpa.print("build/{t}", .{s.arch});
    return .{
        .build = dir,
        .out = try gpa.print("{s}/{s}{s}{s}{s}", .{
            dir,
            name,
            if (s.dev) "-dev" else "",
            if (s.app != null) "-app" else "",
            if (s.published) "-published" else "",
        }),
        .programs = s.programs orelse try gpa.print("build/{t}/programs", .{s.arch}),
    };
}

const DiskFormat = enum { qcow2, raw, vhd, vmdk };

const BuildOptions = struct {
    form: []const u8,
    app: ?[]const u8 = null,
    /// local takes werewolf's programs from this checkout (--build), not
    /// from its repository.
    local: bool = false,
    dir: []const u8 = "dist",
    arch: howl.Arch,
    format: DiskFormat = .qcow2,
};

/// buildOptions parses build's command line: FORM, --build, and -o, --arch,
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
        if (std.mem.eql(u8, args[i], "--build")) {
            o.local = true;
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
            "{s}: build takes --build, -o, --arch, --format and --app\n{s}",
            .{ a, howl.usage },
        );
    }
    o.form = form orelse return why.refuse("no form\n{s}", .{howl.usage});
    o.arch = arch orelse return why.refuse("{s}: --arch", .{howl.not_built_here});
    return o;
}

/// build makes a form's release files in -o DIR, as make's _dist-form
/// does: the image's files under their release names, and the manifest,
/// unsigned (manifest.zig).
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
    });

    // minimal is released whole, for direct boot; the rest as the slot
    // the updater follows, and as a disk to boot a VM from.
    const direct = std.mem.eql(u8, f, "minimal");
    const spec: Spec = .{
        .form = ref,
        .arch = o.arch,
        .app = ab.root,
        .freeze = frozen(),
        .published = !o.local,
    };
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
    const released: []const manifest.File = if (direct) &.{
        .{ .name = "vmlinuz", .path = try gpa.print("{s}/vmlinuz", .{p.build}) },
        .{ .name = "initramfs.zst", .path = try gpa.print("{s}/initramfs.zst", .{p.out}) },
        .{ .name = "cmdline", .path = try gpa.print("{s}/slot/cmdline", .{p.out}) },
    } else &.{
        .{ .name = "vmlinuz", .path = try gpa.print("{s}/slot/vmlinuz", .{p.out}) },
        .{ .name = "stage0.zst", .path = try gpa.print("{s}/slot/stage0.zst", .{p.out}) },
        .{
            .name = "stage0-bitten.zst",
            .path = try gpa.print("{s}/slot/stage0-bitten.zst", .{p.out}),
        },
        .{ .name = "root.erofs", .path = try gpa.print("{s}/slot/root.erofs", .{p.out}) },
        .{ .name = "cmdline", .path = try gpa.print("{s}/slot/cmdline", .{p.out}) },
        .{ .name = "disk.qcow2", .path = try gpa.print("{s}/disk.qcow2", .{p.out}) },
    };
    const id = manifest.write(io, gpa, &steps, dir, .{
        .form = f,
        .arch = a,
        .rootfs = try gpa.print("{s}/rootfs.tar", .{p.out}),
        .kernel = try gpa.print("{s}/meta/usr/share/werewolf/kernel", .{p.out}),
        .files = released,
    }) catch |err| switch (err) {
        error.Refused => return err,
        else => return steps.fail(try gpa.print("{s}: {t}", .{ dir, err })),
    };
    try steps.note("{s} {s}: build {s}", .{ f, a, &id });
    const name = try gpa.print("{s}/{s}-{s}.json", .{ dir, f, a });

    // boot is what a machine boots: the disk, or the initramfs of a form
    // released for direct boot. Another --format replaces it below.
    var boot = try gpa.print("{s}/{s}-{s}-{s}", .{
        dir, f, a, if (direct) "initramfs.zst" else "disk.qcow2",
    });
    if (format != .qcow2) {
        if (direct) return steps.fail(
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
        for (released) |file| try w.print("  {s}/{s}-{s}-{s}\n", .{ dir, f, a, file.name });
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

/// buildTargets builds make's targets of one form: the Makefile's image,
/// slot, disk and OUT/disk.qcow2 targets run it. --app stages an
/// application as run and create do; --app-root takes one staged already,
/// as make's APP. --disk, --disk-mib and --disk-args are make disk's DISK,
/// DISK_MIB and DISK_ARGS; the qcow2 goal takes --disk-mib too.
pub fn buildTargets(io: Io, gpa: Allocator, given: []const []const u8, why: *howl.Why) !void {
    const verbose, const args = try howl.verboseFlag(gpa, given);
    const syntax = "_build --with FORM [--arch ARCH] [--dev] [--published] " ++
        "[--app DIR | --app-root DIR] " ++
        "[--build DIR] [--programs DIR] [--disk FILE] [--disk-mib N] [--disk-args ARGS] " ++
        "[--verbose] image|slot|disk|qcow2|vmlinux...";
    var spec: Spec = .{ .form = "", .arch = undefined, .freeze = frozen() };
    var form: ?[]const u8 = null;
    var arch = howl.hostArch();
    var app_dir: ?[]const u8 = null;
    var app_root: ?[]const u8 = null;
    var goals: Goals = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--dev")) {
            spec.dev = true;
        } else if (std.mem.eql(u8, args[i], "--published")) {
            spec.published = true;
        } else if (std.mem.startsWith(u8, args[i], "-")) {
            const flag, const v = try howl.flagValue(args, &i, why);
            if (std.mem.eql(u8, flag, "--with")) {
                form = v;
            } else if (std.mem.eql(u8, flag, "--arch")) {
                arch = howl.archName(v) orelse return why.refuse(howl.arch_refusal, .{v});
            } else if (std.mem.eql(u8, flag, "--app")) {
                app_dir = v;
            } else if (std.mem.eql(u8, flag, "--app-root")) {
                app_root = v;
            } else if (std.mem.eql(u8, flag, "--build")) {
                spec.build = v;
            } else if (std.mem.eql(u8, flag, "--programs")) {
                spec.programs = v;
            } else if (std.mem.eql(u8, flag, "--disk")) {
                spec.disk_path = v;
            } else if (std.mem.eql(u8, flag, "--disk-mib")) {
                spec.disk.size_mib = std.fmt.parseInt(u32, v, 10) catch 0;
                if (spec.disk.size_mib == 0)
                    return why.refuse("--disk-mib {s}: a size in MiB", .{v});
            } else if (std.mem.eql(u8, flag, "--disk-args")) {
                // Split as make's $(DISK_ARGS) was, by the shell.
                var words: std.ArrayList([]const u8) = .empty;
                var it = mem.tokenizeAny(u8, v, " \t\n");
                while (it.next()) |w| try words.append(gpa, w);
                spec.disk.args = words.items;
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
    spec.form = ref;
    spec.arch = arch orelse return why.refuse("{s}: --arch", .{howl.not_built_here});
    if (goals.vmlinux and spec.arch != .x86_64)
        return why.refuse("vmlinux is x86_64's, for Firecracker", .{});
    if (app_dir != null and app_root != null)
        return why.refuse("--app or --app-root: one application", .{});
    if (!goals.disk and (spec.disk_path != null or spec.disk.args.len > 0))
        return why.refuse("--disk and --disk-args are the disk goal's", .{});
    if (!goals.disk and !goals.qcow2 and spec.disk.size_mib != disk.default_mib)
        return why.refuse("--disk-mib is the disk and qcow2 goals'", .{});
    _ = try howl.chain(io, gpa, ref, why);
    spec.app = app_root orelse (try howl.appBuild(io, gpa, ref, spec.arch, app_dir, why)).root;
    const f = std.fs.path.basename(std.mem.trimEnd(u8, ref, "/"));
    var steps: progress.Steps = try .init(io, gpa, why, .{
        .verbose = verbose,
        .command = try gpa.print("howl _build {s}", .{try std.mem.join(gpa, " ", given)}),
        .log = try gpa.print("build/log/{s}-{t}-build.log", .{ f, spec.arch }),
        .first = howl.start_phase,
    });
    try make(io, gpa, &steps, spec, goals);
    const done = try steps.finish();
    const look: progress.Look = .of(io, Io.File.stderr());
    howl.say(io, "{s} built {s} for {t} in {f}  {f}", .{
        look.check(),
        f,
        spec.arch,
        progress.Clock{ .seconds = done.seconds },
        look.dim(try gpa.print("{f}", .{done})),
    });
}

/// frozen reports whether FREEZE is set, as make's FREEZE=1: every package
/// pinned to its lock, for a reproducible build.
pub fn frozen() bool {
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
    /// bins are the programs the overlay lays in.
    bins: []const []const u8,
    /// stage0_bin and loader_bin are stage0's init and module loader in
    /// PROGRAMS, which stage0 takes when the overlay lays them.
    stage0_bin: []const u8,
    loader_bin: []const u8,
    /// overlay are the directories laid over the packages, OUT/ro first.
    overlay: []const []const u8,
    /// made are the targets of the overlay's compiled parts: a tutorial's
    /// application (app.zig) and melange's packages (melange.zig).
    made: []const []const u8,
    /// recipes are the chain's melange recipes.
    recipes: []const []const u8,
    /// app are --app's directories and files.
    app: []const []const u8,
    modules: compose.Modules,
    params: []const image.Param,
    /// env is the tools' environment (pipeline).
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

    /// run runs one command, in env or the build's, and fails the build if
    /// it fails.
    pub fn run(b: *B, argv: []const []const u8, o: struct {
        cwd: ?[]const u8 = null,
        stdin: ?Io.File = null,
        stdout: ?Io.File = null,
        env: ?*const std.process.Environ.Map = null,
    }) !void {
        const ran = try b.steps.exec(&.{.{
            .argv = argv,
            .cwd = o.cwd,
            .env = o.env orelse b.env,
        }}, .{
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

    /// absolute returns p from the current directory, cleaned as make's
    /// abspath cleans it, for a tool that runs in another or records it.
    pub fn absolute(b: *B, p: []const u8) ![]const u8 {
        const cwd = std.process.currentPathAlloc(b.io, b.gpa) catch |err|
            return b.fail("the current directory: {t}", .{err});
        return std.fs.path.resolveAlloc(b.gpa, &.{ cwd, p });
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

/// prepare plans a build of s and runs no step: build-apk's, whose melange
/// VM boots the kernel any form's build fetches.
pub fn prepare(io: Io, gpa: Allocator, steps: *progress.Steps, s: Spec) !B {
    return plan(io, gpa, steps, s, try paths(gpa, s), try toolEnv(gpa));
}

/// toolEnv returns the tools' environment: COPYFILE_DISABLE=1, so macOS's
/// tar adds no AppleDouble files, and no make variables, so a make that
/// runs howl passes the make howl runs nothing but what howl says.
fn toolEnv(gpa: Allocator) !*std.process.Environ.Map {
    const env = try gpa.create(std.process.Environ.Map);
    env.* = try howl.environ.clone(gpa);
    try env.put("COPYFILE_DISABLE", "1");
    for ([_][]const u8{ "MAKEFLAGS", "MFLAGS", "MAKELEVEL" }) |k| _ = env.swapRemove(k);
    return env;
}

fn pipeline(io: Io, gpa: Allocator, steps: *progress.Steps, s: Spec, goals: Goals) !void {
    const p = try paths(gpa, s);
    const env = try toolEnv(gpa);
    // make compiles werewolf's programs, in a checkout: each compile is
    // mostly one thread, so as many at once as there are CPUs.
    if (exists(io, "Makefile")) {
        if (progress.phaseOf(try gpa.print("{s}/", .{p.programs}))) |ph| try steps.enter(ph);
        const ran = try steps.exec(&.{.{ .argv = &.{
            howl.make_cmd,
            "-s",
            try gpa.print("-j{d}", .{std.Thread.getCpuCount() catch 1}),
            "--no-print-directory",
            try gpa.print("FORM={s}", .{s.form}),
            try gpa.print("ARCH={t}", .{s.arch}),
            try gpa.print("BUILD={s}", .{p.build}),
            try gpa.print("PROGRAMS={s}", .{p.programs}),
            "programs",
        }, .env = env }}, .{});
        if (!ran.ok) return steps.fail("make programs failed");
    }
    var b = try plan(io, gpa, steps, s, p, env);
    try packages.kernel(&b);
    if (goals.vmlinux) try packages.vmlinux(&b);
    if (!goals.image and !goals.slot and !goals.disk and !goals.qcow2) return;

    const suffix = try gpa.print("{s}{s}", .{
        if (s.dev) "-dev" else "",
        if (s.published) "-published" else "",
    });
    const config = try b.path("{s}/form/{s}{s}.yaml", .{ p.build, b.name, suffix });
    const lock = try b.path("build/lock/{s}{s}.lock.json", .{ b.name, suffix });
    try packages.apkoConfig(&b, config);
    try packages.relock(&b, lock, config, b.form_files);
    const rootfs = try b.path("{s}/rootfs.tar", .{p.out});
    try packages.apkoBuild(&b, rootfs, config, lock, &.{ lock, config });
    try app.compile(&b);
    try melange.lay(&b, rootfs);
    try slot.meta(&b, rootfs);
    try slot.make(&b, rootfs, goals);
}

/// every_program are the programs in every form but init and bite-cleanup,
/// each in PROGRAMS/NAME/usr/lib/werewolf/NAME, in overlay order: stage0's
/// init, the module loader, the network's setup and policy, the mounts,
/// posture, the seal's two, and those that replace shell scripts
/// (docs/design/shell-free.md).
const every_program = [_][]const u8{
    "stage0",       "modload",     "iface-up",   "fence",        "mount",
    "mount-broker", "posture",     "seal-watch", "seal",         "runit-stage",
    "reboot",       "grub-setenv", "slot-keep",  "power-button", "debug-shell",
    "ssh-host-key", "leash",       "leash-reap",
};

/// plan reads the form's chain and works out everything the steps need.
fn plan(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    s: Spec,
    p: Paths,
    env: *const std.process.Environ.Map,
) !B {
    var f: forms.Failure = .{};
    const chain = forms.chain(io, gpa, Dir.cwd(), s.form, &f) catch |err| switch (err) {
        error.Form => return steps.fail(f.text),
        else => |e| return e,
    };
    const name = chain[chain.len - 1].name;

    // The overlay's directories, in the Makefile's order (OVERLAY_DIRS),
    // and the programs in them. Published, werewolf's packaged programs
    // come from its repository instead (compose.published).
    var bins: std.ArrayList([]const u8) = .empty;
    var overlay: std.ArrayList([]const u8) = .empty;
    try overlay.append(gpa, try gpa.print("{s}/ro", .{p.out}));
    if (!s.published) {
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
    }

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
                if (s.published) continue;
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

    // Then the compiled parts, a tutorial's application and melange's
    // packages, then --app.
    var made: std.ArrayList([]const u8) = .empty;
    if (app.example(name)) |e| {
        try overlay.append(gpa, try gpa.print("{s}/application", .{p.out}));
        try made.append(gpa, try app.compiled(gpa, p.out, e));
    }
    const recipes = try melange.recipes(io, gpa, chain);
    if (recipes.len > 0) {
        try overlay.append(gpa, try gpa.print("{s}/melange", .{p.out}));
        try made.append(gpa, try gpa.print("{s}/melange.stamp", .{p.out}));
    }
    var staged: std.ArrayList([]const u8) = .empty;
    if (s.app) |root| {
        try overlay.append(gpa, root);
        try staged.append(gpa, root);
        try tree(io, gpa, root, &staged);
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
        .stage0_bin = try gpa.print("{s}/stage0/usr/lib/werewolf/stage0", .{p.programs}),
        .loader_bin = try gpa.print("{s}/modload/usr/lib/werewolf/modload", .{p.programs}),
        .overlay = overlay.items,
        .made = made.items,
        .recipes = recipes,
        .app = staged.items,
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
    _ = melange;
    _ = slot;
    _ = manifest;
    _ = disk;
}
