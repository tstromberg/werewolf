//! build makes a form's image step by step, with the tools and arguments
//! the Makefile's image recipes used, at their paths, so the bytes match.
//! make still compiles the programs. The steps are in packages.zig,
//! melange.zig, app.zig and slot.zig. See README.md and
//! docs/design/implemented/howl-build.md.

const std = @import("std");
const forms = @import("form");
const compose = @import("compose");
const image = @import("image");
const howl = @import("howl.zig");
const cmdline = @import("cmdline");
const adhoc = @import("adhoc.zig");
const app = @import("app.zig");
const melange = @import("melange.zig");
const oci = @import("oci.zig");
const progress = @import("progress.zig");
const packages = @import("packages.zig");
const slot = @import("slot.zig");
const manifest = @import("manifest.zig");
const disk = @import("disk.zig");
const published = @import("published.zig");
const locks = @import("lock.zig");
const deployment = @import("deployment.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const mem = std.mem;

/// Goals are the make targets a build stands in for.
pub const Goals = struct {
    /// Private networkless storage appliance, never an application boot disk.
    transfer_helper: bool = false,
    prebuilt: bool = false,
    /// image is BUILD/vmlinuz and OUT/initramfs.zst, for a direct boot.
    image: bool = false,
    /// slot is OUT/slot: vmlinuz, both stage0s, root.erofs and cmdline.
    slot: bool = false,
    /// disk is OUT/disk.img, a UEFI boot disk of the slot.
    disk: bool = false,
    /// qcow2 is OUT/disk.qcow2, the disk a release publishes.
    qcow2: bool = false,
    /// Internal named-machine builds are private deployments, not releases.
    private_machine: bool = false,
    /// lock is the form's apko config and lock, for make's release-inputs.
    lock: bool = false,
};

/// Spec is what to build: a form, for an arch, with or without a shell
/// and an application.
pub const Spec = struct {
    /// form is a form's name, or the directory of one outside forms/.
    form: []const u8,
    variants: []const []const u8 = &.{},
    arch: howl.Arch,
    /// dev adds developer SSH for test iteration (--dev=ssh): sh-shim and the
    /// native clients, with no shell.
    dev: bool = false,
    /// disabled is what --disable gave up of werewolf's protections. An
    /// image may lack only these (unnamed), and its command line says which.
    disabled: cmdline.Protections = .empty,
    /// app is the staged application's root (howl.appBuild), or null.
    app: ?[]const u8 = null,
    /// build and programs replace BUILD and PROGRAMS, as make's BUILD= and
    /// PROGRAMS= do, to keep a build apart from build/ARCH.
    build: ?[]const u8 = null,
    programs: ?[]const u8 = null,
    /// disk is the disk goal's size and kernel arguments, as make's
    /// DISK_MIB and DISK_ARGS; the qcow2 goal takes the size only.
    disk: disk.Options = .{},
    /// published takes werewolf's programs from its apk repository, as make's
    /// PUBLISHED=1 does, not from PROGRAMS: a machine built so updates them
    /// with apk (docs/design/implemented/custom-updates.md). stage0's and a form's own
    /// programs, which are not packaged, still come from PROGRAMS.
    published: bool = false,
    /// disk_path is where the disk goal writes, as make's DISK; null is
    /// OUT/disk.img. A machine's disk has its own: the disk is rebuilt by
    /// file times alone, so a path reused with other arguments would not be.
    disk_path: ?[]const u8 = null,
    qcow2_path: ?[]const u8 = null,
    /// kernel_rootfs tests an unpublished kernel without enabling IPE.
    /// The caller must explicitly disable IPE; signed builds use ipe_kernel.
    kernel_rootfs: ?[]const u8 = null,
    /// IPE builds use an external kernel archive and a host-only policy signer.
    ipe_kernel: ?[]const u8 = null,
    ipe_key: ?[]const u8 = null,
    ipe_cert: ?[]const u8 = null,
    ipe_updates: ?[]const u8 = null,
    image_serial: ?[]const u8 = null,
    boot_key: ?[]const u8 = null,
    boot_cert: ?[]const u8 = null,
    boot_native: bool = false,
    /// tpm makes a root whose boot requires its channel's TPM floor: the
    /// signed UKI names werewolf.channel and werewolf.index, and stage0
    /// enrolls or checks the TPM (docs/design/implemented/independent-updates.md).
    tpm: bool = false,
    /// image_index is the release's place in its channel: 1, 2, 3, ...
    image_index: u64 = 1,
    update_ca: ?[]const u8 = null,
    update_port: ?u16 = null,

    /// lacks returns the protections s's image is made without: Secure Boot
    /// with no boot key, the TPM unless asked for, IPE with no kernel. A provider may give one
    /// --disable named, as QEMU signs for
    /// Secure Boot regardless.
    pub fn lacks(s: Spec) cmdline.Protections {
        var d: cmdline.Protections = .empty;
        if (s.boot_key == null) d.insert(.secureboot);
        if (!s.tpm) d.insert(.tpm);
        if (s.ipe_kernel == null) d.insert(.ipe);
        return d;
    }

    /// channelId is the release channel's identity: its update URL's, or,
    /// for an image that follows none, its form's alone, so a TPM that
    /// knows one form's counter refuses another's image.
    pub fn channelId(s: Spec) [32]u8 {
        if (s.ipe_updates) |url| return @import("prebuilt").channelId(url);
        var id: [32]u8 = undefined;
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("werewolf-local:");
        h.update(std.fs.path.basename(std.mem.trimEnd(u8, s.form, "/")));
        for (s.selected()) |variant| {
            h.update("/variant:");
            h.update(variant);
        }
        h.final(&id);
        return id;
    }

    pub fn selected(s: Spec) []const []const u8 {
        return s.variants;
    }

    pub fn variantSuffix(s: Spec, gpa: Allocator) ![]const u8 {
        if (s.selected().len == 0) return "";
        return gpa.print("-variants-{s}", .{try mem.join(gpa, ",", s.selected())});
    }

    pub fn devSuffix(s: Spec) []const u8 {
        return if (s.dev) "-dev-ssh" else "";
    }
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
    const dir = s.build orelse try gpa.print(
        "build/{t}{s}",
        .{ s.arch, if (s.ipe_kernel != null) "/ipe" else "" },
    );
    return .{
        .build = dir,
        .out = try gpa.print("{s}/{s}{s}{s}{s}{s}{s}", .{
            dir,
            name,
            try s.variantSuffix(gpa),
            s.devSuffix(),
            if (s.app != null) "-app" else "",
            if (s.published) "-published" else "",
            if (s.ipe_kernel != null) "-ipe" else "",
        }),
        .programs = s.programs orelse try gpa.print("build/{t}/programs", .{s.arch}),
    };
}

test "developer images build apart from production ones" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var spec: Spec = .{ .form = "minimal", .arch = .aarch64 };
    const production = try paths(gpa, spec);
    spec.dev = true;
    const ssh = try paths(gpa, spec);
    try std.testing.expect(!mem.eql(u8, production.out, ssh.out));
    try std.testing.expect(mem.endsWith(u8, ssh.out, "-dev-ssh"));
}

const DiskFormat = enum { qcow2, raw, vhd, vmdk };

const BuildOptions = struct {
    form: []const u8,
    app: ?[]const u8 = null,
    /// local takes werewolf's programs from this checkout (--build), not
    /// from its repository.
    local: bool = false,
    disabled: cmdline.Protections = .empty,
    /// on is the provider a protected build's bundle is for: lima or qemu.
    on: ?howl.Platform = null,
    dir: []const u8 = "dist",
    arch: howl.Arch,
    format: DiskFormat = .qcow2,
    ipe_kernel: ?[]const u8 = null,
    ipe_key: ?[]const u8 = null,
    ipe_cert: ?[]const u8 = null,
    ipe_updates: ?[]const u8 = null,
    image_serial: ?[]const u8 = null,
    boot_key: ?[]const u8 = null,
    boot_cert: ?[]const u8 = null,
    boot_native: bool = false,
    tpm: bool = false,
    image_index: u64 = 1,
};

/// buildOptions parses build's command line: FORM, --build, and -o, --arch,
/// --format, --app and the three --ipe-* flags, each with a value. host is this machine's arch, or
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
        if (std.mem.eql(u8, args[i], "--boot-native")) {
            o.boot_native = true;
            continue;
        }
        if (std.mem.eql(u8, args[i], "--tpm")) {
            o.tpm = true;
            continue;
        }
        const a, const v = try howl.flagValue(args, &i, why);
        if (std.mem.eql(u8, a, "-o")) {
            o.dir = v;
        } else if (std.mem.eql(u8, a, "--disable")) {
            o.disabled = try howl.disableValue(v, why);
        } else if (std.mem.eql(u8, a, "--on")) {
            o.on = std.meta.stringToEnum(howl.Platform, v) orelse
                return why.refuse("--on {s}: lima or qemu", .{v});
        } else if (std.mem.eql(u8, a, "--arch")) {
            arch = howl.archName(v) orelse return why.refuse(howl.arch_refusal, .{v});
        } else if (std.mem.eql(u8, a, "--app")) {
            o.app = v;
        } else if (std.mem.eql(u8, a, "--ipe-kernel")) {
            o.ipe_kernel = v;
        } else if (std.mem.eql(u8, a, "--ipe-key")) {
            o.ipe_key = v;
        } else if (std.mem.eql(u8, a, "--ipe-cert")) {
            o.ipe_cert = v;
        } else if (std.mem.eql(u8, a, "--ipe-updates")) {
            o.ipe_updates = v;
        } else if (std.mem.eql(u8, a, "--image-serial")) {
            o.image_serial = v;
        } else if (std.mem.eql(u8, a, "--boot-key")) {
            o.boot_key = v;
        } else if (std.mem.eql(u8, a, "--boot-cert")) {
            o.boot_cert = v;
        } else if (std.mem.eql(u8, a, "--image-index")) {
            o.image_index = cmdline.releaseIndex(v) orelse
                return why.refuse("--image-index {s}: a release index, 1 or more", .{v});
        } else if (std.mem.eql(u8, a, "--format")) {
            o.format = std.meta.stringToEnum(DiskFormat, v) orelse
                return why.refuse("--format {s}: qcow2 raw vhd vmdk", .{v});
        } else return why.refuse(
            "{s}: build takes --build, --disable, --on, -o, --arch, --format, --app, " ++
                "--ipe-kernel, " ++
                "--ipe-key, --ipe-cert, --ipe-updates, --image-serial, --image-index, " ++
                "--boot-key, --boot-cert, --boot-native and --tpm\n{s}",
            .{ a, howl.usage },
        );
    }
    if ((o.disabled.contains(.ipe) and (o.ipe_kernel != null or o.ipe_key != null or
        o.ipe_cert != null or o.ipe_updates != null or o.image_serial != null)) or
        (o.disabled.contains(.secureboot) and
            (o.boot_key != null or o.boot_cert != null or o.boot_native)) or
        (o.disabled.contains(.tpm) and o.tpm))
        return why.refuse("--disable names a protection the other flags give", .{});
    if (o.on) |on| if ((on != .lima and on != .qemu) or !o.disabled.eql(.empty)) return why.refuse(
        "--on {t}: a protected build's bundle is for lima or qemu; a disk without --on is for " ++
            "the rest",
        .{on},
    );
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
    const command = try gpa.print("howl build {s}", .{std.mem.join(gpa, " ", args) catch ref});
    var steps: progress.Steps = try .init(io, gpa, why, .{
        .verbose = verbose,
        .command = command,
        .log = try gpa.print("build/log/{s}-{s}-build.log", .{ f, a }),
        .first = howl.start_phase,
    });
    if (o.disabled.eql(.empty)) {
        // Every protection, as create deploys it: a bundle any machine on
        // the provider enrolls, signed with the user's own keys, following
        // the channel its builder serves.
        const provider = o.on orelse if (@import("builtin").os.tag == .macos) .lima else .qemu;
        const channel = o.ipe_updates orelse return why.refuse(
            "a protected bundle follows an update channel: --ipe-updates URL, where you " ++
                "serve it; or give up what it needs: --disable=" ++ howl.every_protection,
            .{},
        );
        const out = try gpa.print("{s}/{s}-{t}-{s}", .{ dir, f, provider, a });
        try Dir.cwd().createDirPath(io, dir);
        Dir.cwd().deleteTree(io, out) catch {};
        try @import("local-secure.zig").localBundle(
            io,
            gpa,
            &steps,
            .{ .form = ref, .app = o.app, .local = o.local },
            provider,
            o.arch,
            channel,
            o.image_index,
            out,
            why,
        );
        _ = try steps.finish();
        howl.say(io, "{s}: Secure Boot, the TPM and IPE, for {t}; signed with your keys", .{
            out,
            provider,
        });
        return;
    }
    const ab = try howl.appBuild(io, gpa, ref, o.arch, o.app, why);
    const ipe_inputs: ?@import("prerequisites.zig").Inputs = if (!o.disabled.contains(.ipe) and
        o.ipe_kernel == null)
        try @import("prerequisites.zig").resolve(io, gpa, &steps, o.arch, why)
    else
        null;

    // minimal is released whole, for direct boot; the rest as the slot
    // the updater follows, and as a disk to boot a VM from.
    const direct = std.mem.eql(u8, f, "minimal");
    const spec: Spec = .{
        .form = ref,
        .variants = howl.variants,
        .arch = o.arch,
        .disabled = o.disabled,
        .app = ab.root,
        .published = !o.local,
        .ipe_kernel = o.ipe_kernel orelse if (ipe_inputs) |inp| inp.kernel else null,
        .ipe_key = o.ipe_key orelse if (ipe_inputs) |inp| inp.key else null,
        .ipe_cert = o.ipe_cert orelse if (ipe_inputs) |inp| inp.cert else null,
        .ipe_updates = o.ipe_updates,
        .update_port = if (o.ipe_updates) |url| (try std.Uri.parse(url)).port orelse 443 else null,
        .image_serial = o.image_serial,
        .boot_key = o.boot_key orelse howl.environ.get("WEREWOLF_BOOT_KEY"),
        .tpm = o.tpm,
        .image_index = o.image_index,
        .boot_cert = o.boot_cert orelse if (o.boot_key != null or
            howl.environ.get("WEREWOLF_BOOT_KEY") != null)
            howl.environ.get("WEREWOLF_BOOT_CRT") orelse "release/boot.crt"
        else
            null,
        .boot_native = o.boot_native or (!direct and (o.boot_key != null or
            howl.environ.get("WEREWOLF_BOOT_KEY") != null)),
    };
    try make(
        io,
        gpa,
        &steps,
        spec,
        if (direct)
            .{ .image = true, .slot = o.ipe_updates != null, .prebuilt = o.ipe_updates != null }
        else
            .{ .slot = true, .qcow2 = true, .prebuilt = o.ipe_updates != null },
    );
    const p = try paths(gpa, spec);
    // A developer image takes SSH logins with howl's local key: never one to publish.
    if (Dir.cwd().access(io, try gpa.print("{s}/meta/usr/share/werewolf/dev", .{p.out}), .{})) |_|
        return steps.fail(try gpa.print(
            "refused: {s} is a developer image, with SSH for test iteration",
            .{f},
        ))
    else |_| {}
    try steps.enter(progress.phaseOf("_dist-form").?);
    const released: []const manifest.File = if (direct) &.{
        .{ .name = "vmlinuz", .path = try gpa.print("{s}/vmlinuz", .{p.build}) },
        .{ .name = "initramfs.zst", .path = try gpa.print("{s}/initramfs.zst", .{p.out}) },
        .{ .name = "cmdline", .path = try gpa.print("{s}/slot/cmdline", .{p.out}) },
    } else blk: {
        // The signed UKI the boot key made (Makefile), listed when it is
        // there, so a release carries it exactly when it was signed.
        var out: std.ArrayList(manifest.File) = .empty;
        try out.appendSlice(gpa, &.{
            .{ .name = "vmlinuz", .path = try gpa.print("{s}/slot/vmlinuz", .{p.out}) },
            .{ .name = "stage0.zst", .path = try gpa.print("{s}/slot/stage0.zst", .{p.out}) },
            .{ .name = "root.erofs", .path = try gpa.print("{s}/slot/root.erofs", .{p.out}) },
            .{ .name = "cmdline", .path = try gpa.print("{s}/slot/cmdline", .{p.out}) },
            .{ .name = "disk.qcow2", .path = try gpa.print("{s}/disk.qcow2", .{p.out}) },
        });
        const uki = try gpa.print("{s}/slot/uki.efi", .{p.out});
        if (spec.boot_key != null)
            try out.append(gpa, .{ .name = "uki", .path = uki })
        else
            try steps.note("no signed UKI in the release: WEREWOLF_BOOT_KEY was not set", .{});
        if (spec.boot_cert) |cert| try out.append(gpa, .{ .name = "boot.crt", .path = cert });
        break :blk out.items;
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
    } else if (o.disabled.eql(.empty)) {
        try e.print(
            "  Next: howl upload {s} --on {s}\n",
            .{ boot, howl.Platform.list(.cloud, "|") },
        );
    } else {
        try e.print(
            "  Next: howl upload {s} --on {s} --disable={s}\n",
            .{ boot, howl.Platform.list(.cloud, "|"), howl.every_protection },
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
    const syntax = "_build --with FORM [--arch ARCH] [--dev=ssh] [--disable=LIST] " ++
        "[--published] " ++
        "[--app DIR | --app-root DIR] " ++
        "[--build DIR] [--programs DIR] [--disk FILE] [--disk-mib N] [--disk-args ARGS] " ++
        "[--kernel-rootfs TAR | --ipe-kernel TAR --ipe-key KEY --ipe-cert CERT] " ++
        "[--ipe-updates URL --image-serial UTC [--image-index N]] [--boot-key KEY " ++
        "--boot-cert CERT [--boot-native [--tpm]]] [--update-ca PEM] [--verbose] " ++
        "image|slot|disk|qcow2|prebuilt...";
    var spec: Spec = .{ .form = "", .arch = undefined, .variants = howl.variants };
    var form: ?[]const u8 = null;
    var arch = howl.hostArch();
    var app_dir: ?[]const u8 = null;
    var app_root: ?[]const u8 = null;
    var goals: Goals = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--dev=ssh")) {
            spec.dev = true;
        } else if (std.mem.eql(u8, args[i], "--boot-native")) {
            spec.boot_native = true;
        } else if (std.mem.eql(u8, args[i], "--tpm")) {
            spec.tpm = true;
        } else if (std.mem.eql(u8, args[i], "--published")) {
            spec.published = true;
        } else if (std.mem.startsWith(u8, args[i], "-")) {
            const flag, const v = try howl.flagValue(args, &i, why);
            if (std.mem.eql(u8, flag, "--with")) {
                form = v;
            } else if (std.mem.eql(u8, flag, "--disable")) {
                spec.disabled = try howl.disableValue(v, why);
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
            } else if (std.mem.eql(u8, flag, "--kernel-rootfs")) {
                spec.kernel_rootfs = v;
            } else if (std.mem.eql(u8, flag, "--ipe-kernel")) {
                spec.ipe_kernel = v;
            } else if (std.mem.eql(u8, flag, "--ipe-key")) {
                spec.ipe_key = v;
            } else if (std.mem.eql(u8, flag, "--ipe-cert")) {
                spec.ipe_cert = v;
            } else if (std.mem.eql(u8, flag, "--ipe-updates")) {
                spec.ipe_updates = v;
            } else if (std.mem.eql(u8, flag, "--image-serial")) {
                spec.image_serial = v;
            } else if (std.mem.eql(u8, flag, "--boot-key")) {
                spec.boot_key = v;
            } else if (std.mem.eql(u8, flag, "--boot-cert")) {
                spec.boot_cert = v;
            } else if (std.mem.eql(u8, flag, "--image-index")) {
                spec.image_index = cmdline.releaseIndex(v) orelse
                    return why.refuse("--image-index {s}: a release index, 1 or more", .{v});
            } else if (std.mem.eql(u8, flag, "--update-ca")) {
                spec.update_ca = v;
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
                .private_machine => return why.refuse(
                    "private_machine is an internal deployment goal",
                    .{},
                ),
                inline else => |g| @field(goals, @tagName(g)) = true,
            }
        }
    }
    const ref = form orelse return why.refuse("{s}", .{syntax});
    spec.form = ref;
    spec.arch = arch orelse return why.refuse("{s}: --arch", .{howl.not_built_here});
    if (spec.ipe_updates) |url| spec.update_port = (try std.Uri.parse(url)).port orelse 443;
    if (goals.prebuilt) goals.slot = true;
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
    /// from_repo are the chain's forms that came from werewolf's repository
    /// (published.zig), each NAME-form in the image's world.
    from_repo: []const []const u8,
    locked_images: []const locks.Image = &.{},
    locked_packages: []const []const u8 = &.{},
    resolved_images: std.ArrayList(locks.Image) = .empty,
    deployment: ?deployment.Prepared = null,
    /// name is the form's name, the last of its chain's.
    name: []const u8,
    /// self is howl's executable, which holds the steps' code: what the
    /// Makefile and build/host/form were to make's targets.
    self: []const u8,
    /// form_files are the chain's form.yaml files.
    form_files: []const []const u8,
    /// rootfs are the chain's rootfs files and etc/sv directories, whose
    /// removal changes nothing else a step could see.
    rootfs: []const []const u8,
    /// bins are the programs the overlay lays in.
    bins: []const []const u8,
    /// stage0_bin is stage0's init in PROGRAMS, which stage0 takes when the
    /// overlay lays it.
    stage0_bin: []const u8,
    /// overlay are the directories laid over the packages, OUT/ro first.
    overlay: []const []const u8,
    /// made are the targets of the overlay's compiled parts: a tutorial's
    /// application (app.zig) and melange's packages (melange.zig).
    made: []const []const u8,
    /// recipes are the chain's melange recipes.
    recipes: []const []const u8,
    /// app are --app's directories and files.
    app: []const []const u8,
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
            return b.fail("copy {s} to {s}: {t}", .{ from, to, err });
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
        error.Refused, error.OlderDeclaration => return err,
        else => return steps.fail(@errorName(err)),
    };
}

/// prepare plans a build of s and runs no step: build-apk's, whose melange
/// VM boots the kernel any form's build fetches.
pub fn prepare(io: Io, gpa: Allocator, steps: *progress.Steps, s: Spec) !B {
    return plan(io, gpa, steps, s, try paths(gpa, s), try toolEnv(gpa), "forms");
}

/// toolEnv returns the tools' environment: COPYFILE_DISABLE=1, so macOS's
/// tar adds no AppleDouble files, and no make variables, so a make that
/// runs howl passes the make howl runs nothing but what howl says. Make
/// exports DISABLE from its command line; the make howl runs refuses it
/// from the environment, and howl has already taken it as --disable.
fn toolEnv(gpa: Allocator) !*std.process.Environ.Map {
    const env = try gpa.create(std.process.Environ.Map);
    env.* = try howl.environ.clone(gpa);
    try env.put("COPYFILE_DISABLE", "1");
    for ([_][]const u8{ "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES", "DISABLE" }) |k|
        _ = env.swapRemove(k);
    return env;
}

test "build tools do not inherit the caller's Make protection opt-outs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var caller = std.process.Environ.Map.init(gpa);
    for ([_][]const u8{ "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES", "DISABLE" }) |key|
        try caller.put(key, "inherited");
    try caller.put("PATH", "/tools");
    const saved = howl.environ;
    defer howl.environ = saved;
    howl.environ = &caller;
    const env = try toolEnv(gpa);
    for ([_][]const u8{ "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES", "DISABLE" }) |key| {
        try std.testing.expect(env.get(key) == null);
        try std.testing.expectEqualStrings("inherited", caller.get(key).?);
    }
    try std.testing.expectEqualStrings("/tools", env.get("PATH").?);
}

fn pipeline(io: Io, gpa: Allocator, steps: *progress.Steps, s: Spec, goals: Goals) !void {
    if (goals.image or goals.slot or goals.disk or goals.qcow2 or goals.prebuilt)
        if (try unnamed(gpa, s)) |why| return steps.fail(why);
    try validateIpe(s);
    const p = try paths(gpa, s);
    try Dir.cwd().createDirPath(io, p.programs);
    const guard = try Dir.cwd().createFile(io, try gpa.print("{s}.build.lock", .{p.programs}), .{
        .truncate = false,
    });
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    const env = try toolEnv(gpa);
    const fingerprint = try locks.inputs(io, gpa, s);
    const previous = try locks.matching(io, gpa, s);
    // Published, the forms a name reaches come from werewolf's repository,
    // at the versions the matching input lock names.
    const names = try published.names(
        io,
        gpa,
        if (s.published) s.arch else null,
        s.form,
        if (previous) |rec| try locks.formPins(gpa, rec) else &.{},
        steps.why,
    );
    var b = try plan(io, gpa, steps, s, p, env, names);
    // Native test roots are instrumentation, never distributable releases.
    if ((goals.qcow2 and !goals.private_machine) or goals.prebuilt) for (b.chain) |fm| {
        const marker = try gpa.print("{s}/rootfs/usr/share/werewolf/test-image", .{fm.dir});
        if (Dir.cwd().access(io, marker, .{})) |_| {
            return steps.fail("native test images cannot be exported as release artifacts");
        } else |err| if (err != error.FileNotFound) return err;
    };
    if (previous) |rec| b.locked_images = rec.images;
    const image_goals = goals.image or goals.slot or goals.disk or goals.qcow2 or goals.prebuilt or
        goals.transfer_helper;
    // A lock needs image digests, but no downloaded or unpacked layers.
    try oci.lay(&b, goals.lock and !image_goals);
    const suffix = try gpa.print("{s}{s}{s}", .{
        try s.variantSuffix(gpa),
        s.devSuffix(),
        if (s.published) "-published" else "",
    });
    const config = try b.path("{s}/form/{s}{s}.yaml", .{ p.build, b.name, suffix });
    const lock = try b.path("build/lock/{s}{s}.lock.json", .{ b.name, suffix });
    if (previous != null) b.locked_packages = try packages.pins(
        gpa,
        try b.read(lock, 64 << 20),
        @tagName(s.arch),
    );
    if (goals.lock and !image_goals) {
        try packages.apkoConfig(&b, config);
        return packages.boundLock(&b, lock, config, &fingerprint, previous != null);
    }
    // make compiles the programs the overlay lays, in a checkout: each
    // compile is mostly one thread, so as many at once as there are CPUs.
    if (b.bins.len > 0 and exists(io, "Makefile")) {
        if (progress.phaseOf(try gpa.print("{s}/", .{p.programs}))) |ph| try steps.enter(ph);
        const ran = try steps.exec(&.{.{ .argv = &.{
            howl.make_cmd,
            "-s",
            try gpa.print("-j{d}", .{std.Thread.getCpuCount() catch 1}),
            "--no-print-directory",
            try gpa.print("FORM={s}", .{s.form}),
            try gpa.print("VARIANTS={s}", .{try mem.join(gpa, ",", s.selected())}),
            try gpa.print("ARCH={t}", .{s.arch}),
            try gpa.print("BUILD={s}", .{p.build}),
            try gpa.print("PROGRAMS={s}", .{p.programs}),
            "programs",
        }, .env = env }}, .{});
        if (!ran.ok) return steps.fail("make programs failed");
    }
    // Manuals are installed beside binaries by make programs. Track their
    // contents too, so a documentation-only edit invalidates the overlay.
    var manuals: std.ArrayList([]const u8) = .empty;
    for (b.overlay) |dir|
        try rootfsInputs(io, gpa, try b.path("{s}/usr/share/man", .{dir}), &manuals);
    b.bins = try mem.concat(gpa, []const u8, &.{ b.bins, manuals.items });
    try packages.kernel(&b);
    if (!image_goals and !goals.lock) return;
    try packages.apkoConfig(&b, config);
    try packages.boundLock(&b, lock, config, &fingerprint, previous != null);
    if (!image_goals) return;
    const rootfs = try b.path("{s}/rootfs.tar", .{p.out});
    try packages.apkoBuild(&b, rootfs, config, lock, &.{ lock, config });
    try app.compile(&b);
    try melange.lay(&b, rootfs);
    try slot.meta(&b, rootfs);
    try slot.make(&b, rootfs, goals);
}

/// unnamed returns why s's image may not be made, if it would lack a
/// protection --disable does not name, and how to give it; or null.
/// Nothing is given up by default.
fn unnamed(gpa: Allocator, s: Spec) !?[]const u8 {
    const lacks = s.lacks();
    var missing: cmdline.Protections = .empty;
    var named = s.disabled;
    for (std.enums.values(cmdline.Protection)) |p| if (lacks.contains(p) and !named.contains(p)) {
        missing.insert(p);
        named.insert(p);
    };
    if (missing.count() == 0) return null;
    var w: Io.Writer.Allocating = .init(gpa);
    try w.writer.writeAll("the image would be made without ");
    try cmdline.writeProtections(&w.writer, missing, ", ");
    try w.writer.writeAll(", which --disable does not name. Give");
    var first = true;
    for (std.enums.values(cmdline.Protection)) |p| if (missing.contains(p)) {
        try w.writer.writeAll(if (first) " " else "; ");
        try w.writer.writeAll(switch (p) {
            .secureboot => "a boot key (--boot-key, or WEREWOLF_BOOT_KEY)",
            .tpm => "the TPM (--tpm, with a boot key, native boot and IPE)",
            .ipe => "IPE (--ipe-kernel, --ipe-key and --ipe-cert)",
        });
        first = false;
    };
    try w.writer.writeAll(", or give them up: --disable=");
    try cmdline.writeProtections(&w.writer, named, ",");
    return w.written();
}

test unnamed {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var s: Spec = .{ .form = "prod", .arch = .aarch64 };
    try testing.expect(s.lacks().eql(.full));
    try testing.expectEqualStrings(
        "the image would be made without secureboot, tpm, ipe, which --disable does not " ++
            "name. Give a boot key (--boot-key, or WEREWOLF_BOOT_KEY); the TPM (--tpm, with " ++
            "a boot key, native boot and IPE); IPE (--ipe-kernel, --ipe-key and --ipe-cert), or " ++
            "give them up: --disable=secureboot,tpm,ipe",
        (try unnamed(gpa, s)).?,
    );
    // QEMU signs a machine --disable gave all three up for: it lacks two.
    s.disabled = .full;
    s.boot_key = "boot.key";
    try testing.expectEqual(null, try unnamed(gpa, s));
    try testing.expect(s.lacks().eql(.initMany(&.{ .tpm, .ipe })));
    // A key and IPE given, the TPM neither given nor named.
    s.disabled = .empty;
    s.ipe_kernel = "k.tar";
    try testing.expectEqualStrings(
        "the image would be made without tpm, which --disable does not name. Give the TPM " ++
            "(--tpm, with a boot key, native boot and IPE), or give them up: --disable=tpm",
        (try unnamed(gpa, s)).?,
    );
    s.tpm = true;
    try testing.expectEqual(null, try unnamed(gpa, s));
    try testing.expect(s.lacks().eql(.empty));
}

fn validateIpe(s: Spec) !void {
    if (s.kernel_rootfs) |kernel| {
        if (kernel.len == 0 or !s.disabled.contains(.ipe) or s.ipe_kernel != null)
            return error.TestKernelNeedsIpeDisabled;
    }
    if (s.disabled.contains(.ipe) and (s.ipe_kernel != null or s.ipe_key != null or
        s.ipe_cert != null or s.ipe_updates != null or s.image_serial != null))
        return error.DisabledIpeGiven;
    if (s.disabled.contains(.tpm) and s.tpm) return error.DisabledTpmGiven;
    if (s.tpm and (!s.boot_native or s.boot_key == null or s.ipe_kernel == null))
        return error.TpmNeedsSignedNativeIpe;
    if (s.image_index == 0) return error.BadReleaseIndex;
    if ((s.boot_key == null) != (s.boot_cert == null)) return error.BootKeyAndCertificateRequired;
    if (s.boot_native and s.boot_key == null) return error.NativeBootNeedsSigner;
    const fields = [_]?[]const u8{ s.ipe_kernel, s.ipe_key, s.ipe_cert };
    var count: usize = 0;
    for (fields) |f| if (f) |v| {
        if (v.len == 0) return error.IpeNeedsKernelKeyAndCertificate;
        count += 1;
    };
    if (count != 0 and count != fields.len) return error.IpeNeedsKernelKeyAndCertificate;
    if (s.ipe_updates != null or s.image_serial != null) {
        if (count != fields.len or s.ipe_updates == null or s.image_serial == null)
            return error.ImageUpdatesNeedIpeChannelAndSerial;
        try @import("prebuilt").channel(s.ipe_updates.?);
        const uri = try std.Uri.parse(s.ipe_updates.?);
        if ((uri.port orelse 443) != (s.update_port orelse 443)) return error.BadImageChannel;
        _ = @import(
            "update-policy",
        ).parseSerial(s.image_serial.?) catch return error.BadImageSerial;
    }
}

test "unpublished kernels cannot silently replace the signed IPE profile" {
    const t = std.testing;
    var s: Spec = .{ .form = "minimal", .arch = .aarch64, .kernel_rootfs = "kernel.tar" };
    try t.expectError(error.TestKernelNeedsIpeDisabled, validateIpe(s));
    s.disabled.insert(.ipe);
    try validateIpe(s);
    try t.expect(s.lacks().contains(.ipe));
    s.ipe_kernel = "signed-kernel.tar";
    try t.expectError(error.TestKernelNeedsIpeDisabled, validateIpe(s));
    s.ipe_kernel = null;
    s.kernel_rootfs = "";
    try t.expectError(error.TestKernelNeedsIpeDisabled, validateIpe(s));
}

test "the TPM floor requires the complete protected profile" {
    const t = std.testing;
    var s: Spec = .{ .form = "minimal", .arch = .aarch64, .tpm = true };
    try t.expectError(error.TpmNeedsSignedNativeIpe, validateIpe(s));
    s.boot_native = true;
    s.boot_key = "vendor.key";
    s.boot_cert = "vendor.crt";
    s.ipe_kernel = "kernel.tar";
    s.ipe_key = "policy.key";
    s.ipe_cert = "policy.crt";
    try validateIpe(s);
    s.ipe_updates = "https://images.example/secure";
    s.image_serial = "20261013T120000Z";
    try validateIpe(s);
    s.image_index = 0;
    try t.expectError(error.BadReleaseIndex, validateIpe(s));
    s.image_index = 1;
    s.boot_native = false;
    try t.expectError(error.TpmNeedsSignedNativeIpe, validateIpe(s));
    // A channel's identity is its URL's; an image without one is its form's.
    const followed = s.channelId();
    s.ipe_updates = null;
    try t.expect(!std.mem.eql(u8, &followed, &s.channelId()));
    s.form = "forms/minimal/";
    try t.expectEqualSlices(
        u8,
        &(Spec{ .form = "minimal", .arch = .x86_64 }).channelId(),
        &s.channelId(),
    );
}

test "IPE builds require all signing inputs and have separate output paths" {
    const t = std.testing;
    var s: Spec = .{ .form = "minimal", .arch = .aarch64 };
    try validateIpe(s);
    s.ipe_kernel = "kernel.tar";
    try t.expectError(error.IpeNeedsKernelKeyAndCertificate, validateIpe(s));
    s.ipe_key = "key.pem";
    try t.expectError(error.IpeNeedsKernelKeyAndCertificate, validateIpe(s));
    s.ipe_cert = "cert.pem";
    try validateIpe(s);
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const p = try paths(arena.allocator(), s);
    try t.expectEqualStrings("build/aarch64/ipe/minimal-ipe", p.out);
}

test "image enrollment requires IPE, a safe channel and a release serial" {
    const t = std.testing;
    var s: Spec = .{
        .form = "minimal",
        .arch = .aarch64,
        .ipe_updates = "https://example.test/app",
    };
    try t.expectError(error.ImageUpdatesNeedIpeChannelAndSerial, validateIpe(s));
    s.ipe_kernel = "kernel.tar";
    s.ipe_key = "key.pem";
    s.ipe_cert = "cert.pem";
    try t.expectError(error.ImageUpdatesNeedIpeChannelAndSerial, validateIpe(s));
    s.image_serial = "20261011T180000Z";
    try validateIpe(s);
    s.ipe_updates = "http://example.test/app";
    try t.expectError(error.BadImageChannel, validateIpe(s));
    s.ipe_updates = "https://example.test/app";
    s.image_serial = "invalid";
    try t.expectError(error.BadImageSerial, validateIpe(s));
}

/// every_program are the programs in every form but init,
/// each in PROGRAMS/NAME/usr/lib/werewolf/NAME, in overlay order: stage0's
/// init, the network's setup and policy, the mounts,
/// posture, the seal's two, and those that replace shell scripts
/// (docs/design/implemented/shell-free.md).
pub const every_program = [_][]const u8{
    "stage0",    "iface-up",     "fence",        "mount",       "mount-broker",
    "posture",   "seal-watch",   "seal",         "runit-stage", "reboot",
    "slot-keep", "power-button", "ssh-host-key", "leash",       "leash-reap",
    "syslogd",   "unwound",      "unwound-age",
};

/// plan reads the form's chain and works out everything the steps need.
fn plan(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    s: Spec,
    p: Paths,
    env: *const std.process.Environ.Map,
    names: []const u8,
) !B {
    var f: forms.Failure = .{};
    var chain = forms.chainSelectedIn(
        io,
        gpa,
        Dir.cwd(),
        names,
        s.form,
        s.selected(),
        &f,
    ) catch |err| switch (err) {
        error.Form => return steps.fail(f.text),
        else => |e| return e,
    };
    if (s.dev) {
        var dev_why: howl.Why = .{};
        chain = howl.addDevSsh(io, gpa, chain, &dev_why) catch |err| switch (err) {
            error.Refused => return steps.fail(dev_why.text),
            else => |e| return e,
        };
    }
    const name = chain[chain.len - 1].name;
    var from_repo: std.ArrayList([]const u8) = .empty;
    if (s.published) for (chain) |c| {
        const under = mem.cutPrefix(u8, c.dir, names) orelse continue;
        if (under.len > 0 and under[0] == '/' and published.fetched(io, gpa, names, c.name))
            try from_repo.append(gpa, c.name);
    };

    // The overlay's directories, in the Makefile's order (OVERLAY_DIRS),
    // and the programs in them. Published, werewolf's packaged programs
    // come from its repository instead (compose.published).
    var bins: std.ArrayList([]const u8) = .empty;
    var overlay: std.ArrayList([]const u8) = .empty;
    // Local APKs are packages just like apko's: the form must be able to
    // replace one of their files with a confined helper or configuration.
    // Lay them before the form, retaining slot.lay's refusal to follow links.
    const recipes = try melange.recipes(io, gpa, chain);
    if (recipes.len > 0)
        try overlay.append(gpa, try gpa.print("{s}/melange", .{p.out}));
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
    }

    var form_files: std.ArrayList([]const u8) = .empty;
    var rootfs: std.ArrayList([]const u8) = .empty;
    // The form's programs' directories: form.yaml's programs, each in
    // PROGRAMS/NAME (samba-passwd.so in PROGRAMS/samba-passwd, as make's
    // basename names it), and a form's own, F/cmd/P, in PROGRAMS/forms/F.
    var dirs: std.array_hash_map.String(void) = .empty;
    for (chain) |c| {
        try form_files.append(gpa, try gpa.print("{s}/form.yaml", .{c.dir}));
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

    // Then the compiled parts, a tutorial's application, then --app.
    var made: std.ArrayList([]const u8) = .empty;
    if (app.example(name)) |e| {
        try overlay.append(gpa, try gpa.print("{s}/application", .{p.out}));
        try made.append(gpa, try app.compiled(gpa, p.out, e));
    }
    if (recipes.len > 0) {
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
    // Refuse a chain whose allowances do not hold together before any step runs.
    _ = compose.allowances(gpa, chain, &f) catch |err| switch (err) {
        error.Form => return steps.fail(f.text),
        else => |e| return e,
    };

    return .{
        .io = io,
        .gpa = gpa,
        .steps = steps,
        .spec = s,
        .p = p,
        .arch = arch,
        .chain = chain,
        .from_repo = from_repo.items,
        .name = name,
        .self = try std.process.executablePathAlloc(io, gpa),
        .form_files = form_files.items,
        .rootfs = rootfs.items,
        .bins = bins.items,
        .stage0_bin = try gpa.print("{s}/stage0/usr/lib/werewolf/stage0", .{p.programs}),
        .overlay = overlay.items,
        .made = made.items,
        .recipes = recipes,
        .app = staged.items,
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

test "command-line build goals cannot select private deployment exemptions" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var why: howl.Why = .{};
    try testing.expectError(
        error.Refused,
        buildTargets(testing.io, arena.allocator(), &.{"private_machine"}, &why),
    );
}

test buildOptions {
    var why: howl.Why = .{};
    const o = try buildOptions(&.{ "bastion", "--format", "vhd", "-o", "out" }, .aarch64, &why);
    try testing.expectEqualStrings("bastion", o.form);
    try testing.expectEqualStrings("out", o.dir);
    try testing.expectEqual(.aarch64, o.arch);
    try testing.expectEqual(DiskFormat.vhd, o.format);
    const signed = try buildOptions(&.{
        "prod", "--boot-key", "host.key", "--boot-cert", "public.crt", "--boot-native",
    }, .aarch64, &why);
    try testing.expectEqualStrings("host.key", signed.boot_key.?);
    try testing.expectEqualStrings("public.crt", signed.boot_cert.?);
    try testing.expect(signed.boot_native);
    try testing.expectEqual(
        .x86_64,
        (try buildOptions(&.{ "--arch", "x86_64", "prod" }, null, &why)).arch,
    );
    try testing.expect((try buildOptions(
        &.{ "prod", "--disable=secureboot,tpm,ipe" },
        .aarch64,
        &why,
    )).disabled.eql(.full));
    try testing.expectEqual(
        .qemu,
        (try buildOptions(&.{ "prod", "--on", "qemu" }, .aarch64, &why)).on.?,
    );
    // A build gives each protection itself, so it takes any list.
    try testing.expect((try buildOptions(
        &.{ "prod", "--disable=secureboot,tpm" },
        .aarch64,
        &why,
    )).disabled.eql(.initMany(&.{ .secureboot, .tpm })));
    for ([_][]const []const u8{
        &.{},
        &.{ "a", "b" },
        &.{ "a", "--arch", "riscv64" },
        &.{ "a", "--format", "zip" },
        &.{ "a", "--on", "gcp" },
        &.{ "a", "-o" },
        &.{ "a", "--disable=secureboot,tpm,ipe", "--ipe-kernel", "k.tar" },
        &.{ "a", "--disable=secureboot,tpm,ipe", "--boot-key", "k.pem" },
        &.{ "a", "--disable=secureboot" },
        &.{ "a", "--disable=secureboot,tpm,ipe", "--on", "qemu" },
        &.{ "a", "--disable=ipe", "--ipe-cert", "c.pem" },
        &.{ "a", "--disable=tpm", "--tpm-firmware" },
    }) |args| try testing.expectError(error.Refused, buildOptions(args, .aarch64, &why));
    try testing.expectError(error.Refused, buildOptions(&.{"a"}, null, &why));
    try testing.expectEqual(
        .aarch64,
        (try buildOptions(&.{ "--arch=arm64", "prod" }, null, &why)).arch,
    );
}

test {
    _ = locks;
    _ = deployment;
    _ = packages;
    _ = melange;
    _ = slot;
    _ = manifest;
    _ = disk;
}
