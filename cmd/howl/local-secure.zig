//! Protected local machines: Lima on macOS, QEMU on Linux, bhyve on FreeBSD.
//! A machine enrolls its image's boot certificate as PK, KEK and db, and
//! boots with a fresh TPM that its first boot makes its own. It follows its
//! image's update channel by itself: a download follows werewolf's public
//! mirror; a --build follows the channel its builder names, if any, and
//! otherwise takes changes by reinstalling (docs/design/implemented/independent-updates.md).
const std = @import("std");
const howl = @import("howl.zig");
const lima = @import("lima.zig");
const native = @import("build.zig");
const secureboot = @import("secureboot.zig");
const progress = @import("progress.zig");
const qemu = @import("qemu.zig");
const bhyve = @import("bhyve.zig");
const swtpm = @import("swtpm.zig");
const booting = @import("boot.zig");
const bundle = @import("boot-image.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub const Profile = struct {
    spec: native.Spec,
    managed: bool,
    provider: howl.Platform = .lima,
    /// imported is the build of the downloaded bundle the machine was made from.
    imported: ?[]const u8 = null,
    /// bundle is that download: werewolf's signed bundle and its pins.
    bundle: ?bundle.Request = null,
    configuration: ?@import("boot-config.zig").Definition = null,
    /// local is the build of the machine's image when howl built it here
    /// with the user's own keys, which later --build runs compare with;
    /// null for werewolf's downloads.
    local: ?native.Spec = null,
    /// The approved immutable image cache, independent of later source builds.
    data_image: ?[]const u8 = null,
    cloud: ?@import("data-cloud.zig").Provider = null,
    /// Restored storage remains local and unbooted until explicit activation.
    cloud_staged: bool = false,
    cloud_size: ?[]const u8 = null,
    // Older protected bhyve profiles used SLIRP exclusively. Preserve that
    // choice on resume; new profiles explicitly select the normal TAP default.
    bhyve_network: bhyve.Mode = .slirp,
    bhyve_bridge: ?[]const u8 = null,
};

fn inheritBhyveNetwork(o: *howl.Options, profile: Profile) void {
    if (profile.provider != .bhyve) return;
    if (o.network == null) o.network = if (o.bridge != null) .tap else profile.bhyve_network;
    if (o.network == .tap and o.bridge == null) o.bridge = profile.bhyve_bridge;
}

test "protected bhyve preserves its bridge and legacy SLIRP unless explicitly changed" {
    const t = std.testing;
    var profile: Profile = .{
        .spec = .{ .form = "playground", .arch = .x86_64 },
        .managed = false,
        .provider = .bhyve,
    };
    var legacy: howl.Options = .{};
    inheritBhyveNetwork(&legacy, profile);
    try t.expectEqual(bhyve.Mode.slirp, legacy.network.?);
    profile.bhyve_network = .tap;
    profile.bhyve_bridge = "bridge7";
    var resumed: howl.Options = .{};
    inheritBhyveNetwork(&resumed, profile);
    try t.expectEqual(bhyve.Mode.tap, resumed.network.?);
    try t.expectEqualStrings("bridge7", resumed.bridge.?);
    var explicit: howl.Options = .{ .network = .slirp };
    inheritBhyveNetwork(&explicit, profile);
    try t.expectEqual(bhyve.Mode.slirp, explicit.network.?);
    try t.expect(explicit.bridge == null);
    profile.bhyve_network = .slirp;
    var bridge: howl.Options = .{ .bridge = "bridge9" };
    inheritBhyveNetwork(&bridge, profile);
    try t.expectEqual(bhyve.Mode.tap, bridge.network.?);
    try t.expectEqualStrings("bridge9", bridge.bridge.?);
}

/// Restore networking before the config tar is made, including SLIRP's
/// static defaults for forms without DHCP. Explicit flags still take precedence.
pub fn restoreBhyveNetwork(io: Io, gpa: Allocator, o: *howl.Options, name: []const u8) !void {
    const file = try gpa.print("{s}/authority/profile.json", .{try howl.machineDir(gpa, name)});
    const text = Dir.cwd().readFileAlloc(
        io,
        file,
        gpa,
        .limited(64 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    inheritBhyveNetwork(o, try parseProfile(gpa, text));
}

/// parseProfile reads a machine's profile.json. A profile is howl's own
/// record, and an older howl wrote fields since dropped (spec.insecure,
/// always false in a protected machine's), so unknown fields are ignored.
fn requireVariants(old: []const []const u8, wanted: []const []const u8) !void {
    if (old.len != wanted.len) return error.VariantChangeRequiresNewMachine;
    for (old, wanted) |a, b| if (!std.mem.eql(
        u8,
        a,
        b,
    )) return error.VariantChangeRequiresNewMachine;
}

pub fn parseProfile(gpa: Allocator, text: []const u8) !Profile {
    return std.json.parseFromSliceLeaky(Profile, gpa, text, .{ .ignore_unknown_fields = true });
}

test parseProfile {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const old = try parseProfile(
        gpa,
        "{\"spec\":{\"form\":\"playground\",\"arch\":\"aarch64\",\"insecure\":false}," ++
            "\"managed\":true}",
    );
    try std.testing.expectEqualStrings("playground", old.spec.form);
    try std.testing.expect(old.spec.disabled.eql(.empty));
    var made = old;
    made.spec.disabled = .full;
    const text = try std.json.Stringify.valueAlloc(gpa, made, .{});
    try std.testing.expect((try parseProfile(gpa, text)).spec.disabled.eql(.full));
}

pub const Reuse = enum { miss, running, configure };

pub fn reconcileLima(io: Io, gpa: Allocator, name: []const u8, why: *howl.Why) !void {
    if (howl.madeOn(io, gpa, name) != .lima) return;
    const dir = try howl.machineDir(gpa, name);
    const guard = try Dir.cwd().createFile(io, try gpa.print("{s}/secure.lock", .{dir}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    const present = lima.exists(io, gpa, name) catch |err| return why.refuse(
        "cannot query Lima for {s}: {s}; retained enrollment is unchanged",
        .{ name, @errorName(err) },
    );
    try clearAbsentLima(io, gpa, name, present);
}

fn clearAbsentLima(io: Io, gpa: Allocator, name: []const u8, present: bool) !void {
    if (present) return;
    try Dir.cwd().deleteTree(io, try howl.machineDir(gpa, name));
}

test "absent Lima instances clear stale host enrollment; extant instances retain it" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var nonce: [8]u8 = undefined;
    try t.io.randomSecure(&nonce);
    const name = try gpa.print("ww-orphan-{x}", .{&nonce});
    const dir = try howl.machineDir(gpa, name);
    defer Dir.cwd().deleteTree(t.io, dir) catch {};
    const authority = try gpa.print("{s}/authority", .{dir});
    try Dir.cwd().createDirPath(t.io, authority);
    const profile = try gpa.print("{s}/profile.json", .{authority});
    try Dir.cwd().writeFile(t.io, .{ .sub_path = profile, .data = "original enrollment" });
    try clearAbsentLima(t.io, gpa, name, true);
    try t.expectEqualStrings(
        "original enrollment",
        try Dir.cwd().readFileAlloc(t.io, profile, gpa, .limited(4096)),
    );
    try clearAbsentLima(t.io, gpa, name, false);
    try t.expectError(error.FileNotFound, Dir.cwd().access(t.io, profile, .{}));
}

/// resumeDownload keeps an existing downloaded machine on the bundle it was
/// made from: the machine updates itself from its channel, and a newer
/// download never replaces its enrollment.
pub fn resumeDownload(
    io: Io,
    gpa: Allocator,
    o: *howl.Options,
    name: []const u8,
    why: *howl.Why,
) !void {
    const incoming = o.boot_image orelse return error.MissingBootImage;
    const authority = try gpa.print("{s}/authority", .{try howl.machineDir(gpa, name)});
    const saved = Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/profile.json", .{authority}),
        gpa,
        .limited(64 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    const profile = try parseProfile(gpa, saved);
    try requireVariants(profile.spec.variants, howl.variants);
    inheritBhyveNetwork(o, profile);
    if (profile.local != null or profile.imported == null) return why.refuse(
        "{s} was created with local signing keys; this command requests production-signed " ++
            "images.\n" ++
            "Its firmware trusts only your boot key, and its TPM floor your releases. " ++
            "Its disks and keys are unchanged.\n" ++
            "Keep this VM: {s}\n" ++
            "Create a separate production VM: howl create werewolf-production --with {s} --on {t}",
        .{
            name,
            if (std.mem.eql(u8, name, howl.run_name) and
                std.mem.eql(u8, profile.spec.form, "playground"))
                "howl run --build"
            else
                "repeat your original command with --build",
            o.form,
            o.on orelse profile.provider,
        },
    );
    if (profile.provider != o.on.? or !std.mem.eql(u8, profile.spec.form, o.form))
        return why.refuse(
            "{s}: provider or form changes require a new machine name; enrollment is retained",
            .{name},
        );
    const made = profile.bundle orelse return error.ImportedImageNeedsAuthenticatedResume;
    if (!try sameArtifact(io, gpa, incoming.boot_certificate, profile.spec.boot_cert.?) or
        !try sameArtifact(io, gpa, incoming.image_certificate, profile.spec.ipe_cert.?) or
        !std.mem.eql(u8, incoming.channel, made.channel))
        return error.ExistingImageAuthorityMismatch;
    o.boot_image = made;
}

/// Built is the image a --build made for its machine, and the stub it took.
pub const Built = struct { spec: native.Spec, stub: []const u8 };

/// Recorded profiles retain public build metadata and signer certificates,
/// never host private-key paths.
pub fn scrubLocalSpec(spec: native.Spec) native.Spec {
    var s = spec;
    s.boot_key = null;
    s.ipe_key = null;
    return s;
}

/// Prepare an independently enrolled target; no application boot takes place.
/// The caller holds its lifecycle lock and has validated the entire archive.
pub fn transferTarget(
    io: Io,
    a: Allocator,
    name: []const u8,
    on: howl.Platform,
    r: @import("data-image.zig").Record,
    tar: []const u8,
    why: *howl.Why,
) !Profile {
    if (r.profile.spec.boot_cert == null) return why.refuse(
        "create an empty destination with the approved image before importing",
        .{},
    );
    _ = try admit(io, a, on, false, why);
    const at = try std.fs.path.resolveAlloc(
        a,
        &.{ try std.process.currentPathAlloc(io, a), try howl.machineDir(a, name) },
    );
    const authority = try a.print("{s}/authority", .{at});
    if (!try emptyAuthority(io, authority)) return error.TransferTargetExists;
    const fallback = std.fmt.bytesToHex(r.verity.root, .lower);
    const cache = try @import("data-image.zig").directory(
        io,
        a,
        r.profile.data_image orelse &fallback,
    );
    var steps = try progress.Steps.init(io, a, why, .{
        .command = "howl import",
        .log = try a.print("{s}/create.log", .{at}),
        .first = .{ .name = "Preparing stopped import destination", .short = "prepare" },
    });
    const disk = try a.print("{s}/disk.img", .{at});
    if (r.disk_sha256) |expected| {
        const base = try a.print("{s}/disk.raw", .{cache});
        if (!std.mem.eql(u8, expected, (try @import("prebuilt").hashFile(io, a, base)).sha256))
            return error.TransferImageCache;
        try howl.run(io, why, &.{ "qemu-img", "convert", "-f", "raw", "-O", "raw", base, disk });
    } else if (r.profile.bundle) |request| {
        try bundle.materialize(
            io,
            a,
            &steps,
            request,
            try bundle.verify(io, a, request, r.profile.spec.arch),
            disk,
        );
    } else return why.refuse(
        "matching pristine image is unavailable; create an empty destination with the same " ++
            "image first",
        .{},
    );
    try Dir.cwd().setFilePermissions(io, disk, .fromMode(0o600), .{});
    var profile = r.profile;
    profile.provider = on;
    profile.spec.disk_path = disk;
    profile.spec.boot_cert = try a.print("{s}/boot.crt", .{at});
    try Dir.cwd().createDir(io, authority, .fromMode(0o700));
    try enroll(
        io,
        a,
        &steps,
        name,
        at,
        authority,
        try a.print("{s}/boot.crt", .{cache}),
        profile,
        null,
        tar,
        why,
    );
    try bundle.durable(io, try a.print("{s}/engine", .{at}), @tagName(on));
    _ = try steps.finish();
    return profile;
}

/// localBundle builds o's form into a protected bundle in out, as
/// `release build-protected` builds werewolf's: Secure Boot, the TPM floor and
/// IPE, for provider, following channel at index, signed with the user's own
/// keys (howl.dataDir). It carries no key of a machine, so a machine enrolls
/// it as it would a download.
pub fn localBundle(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    o: howl.Options,
    provider: howl.Platform,
    arch: howl.Arch,
    channel: []const u8,
    index: u64,
    out: []const u8,
    why: *howl.Why,
) !void {
    const form = std.fs.path.basename(std.mem.trimEnd(u8, o.form, "/"));
    if (!@import("form").isName(form)) return why.refuse(
        "{s}: a protected image's form is named a-z, 0-9 and -",
        .{o.form},
    );
    try @import("prebuilt").channel(channel);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const work = try gpa.print("{s}/build/bundles/{t}-{t}/{s}", .{ cwd, provider, arch, form });
    const built = try localSpec(io, gpa, steps, o, provider, arch, work, .{
        .channel = channel,
        .index = index,
        .disk = try gpa.print("{s}/disk.raw", .{work}),
    }, why);
    const paths = try build(io, gpa, steps, built.spec, built.stub, .{ .disk = true });
    try bundle.seal(io, gpa, .{
        .form = form,
        .configuration_form = o.form,
        .arch = @tagName(arch),
        .disk = built.spec.disk_path.?,
        .slot = try gpa.print("{s}/slot", .{paths.out}),
        .head = try gpa.print("{s}/prebuilt/{t}", .{ paths.out, arch }),
        .output = out,
        .image_key = built.spec.ipe_key.?,
        .image_certificate = built.spec.ipe_cert.?,
        .boot_certificate = built.spec.boot_cert.?,
        .channel = channel,
    }, why);
    // The bundle holds the disk compressed.
    Dir.cwd().deleteFile(io, built.spec.disk_path.?) catch {};
}

const Release = struct { channel: ?[]const u8, index: u64, disk: []const u8 };

/// localSpec is the protected build of o's form for provider with the
/// user's own keys, writing its disk to r.disk; it follows r.channel, if
/// any, as release r.index.
fn localSpec(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    o: howl.Options,
    provider: howl.Platform,
    arch: howl.Arch,
    work: []const u8,
    r: Release,
    why: *howl.Why,
) !Built {
    const prerequisites = try @import("prerequisites.zig").resolve(io, gpa, steps, arch, why);
    const boot = try secureboot.signer(io, gpa, steps, try howl.keysDir(
        io,
        gpa,
        try gpa.print("boot/{t}", .{arch}),
        try gpa.print("build/boot/{t}", .{arch}),
    ), false);
    return .{
        .spec = .{
            .form = o.form,
            .variants = howl.variants,
            .arch = arch,
            .published = !o.local,
            .app = (try howl.appBuild(io, gpa, o.form, arch, o.app, why)).root,
            .build = work,
            .disk_path = r.disk,
            .disk = .{ .args = bundleArgs(provider, arch) },
            .boot_key = boot.key,
            .boot_cert = boot.cert,
            .boot_native = true,
            .tpm = true,
            .image_index = r.index,
            .ipe_kernel = prerequisites.kernel.?,
            .ipe_key = prerequisites.key.?,
            .ipe_cert = prerequisites.cert.?,
            .ipe_updates = r.channel,
            .update_port = if (r.channel) |url| (try std.Uri.parse(url)).port orelse 443 else null,
            .image_serial = if (r.channel != null) try serial(io, gpa) else null,
            // A channel its builder serves under a private CA: the root trusts it too.
            .update_ca = if (r.channel != null) howl.environ.get("IPE_UPDATES_CA") else null,
        },
        .stub = prerequisites.stub,
    };
}

/// admit refuses a protected machine its provider cannot run here, before
/// anything is built for it, and returns the arch it runs.
pub fn admit(
    io: Io,
    gpa: Allocator,
    provider: howl.Platform,
    dev: bool,
    why: *howl.Why,
) !howl.Arch {
    if (dev) return why.refuse("the secured local profile refuses --dev", .{});
    if (provider == .bhyve) {
        if (!bhyve.installed(io) or @import("builtin").cpu.arch != .x86_64) return why.refuse(
            "protected bhyve requires FreeBSD x86_64 with vmm loaded",
            .{},
        );
        _ = bhyve.Runtime.fromEnvironment(howl.environ) catch return why.refuse(
            "protected bhyve: BHYVE_BINARY must be an absolute path without commas " ++
                "or control characters",
            .{},
        );
    } else if (provider != .lima and @import("builtin").os.tag != .linux)
        return why.refuse("secured QEMU currently requires Linux", .{});
    if (provider == .lima and !lima.installed(io, gpa))
        return why.refuse("protected deployment requires Lima on macOS", .{});
    const arch = try howl.localArch(why);
    if (provider == .lima and arch != .aarch64)
        return why.refuse("the secured Lima profile currently requires arm64", .{});
    return arch;
}

/// bundleArgs are a protected image's kernel arguments on provider, as
/// `release build-protected` gives werewolf's: Lima's guest has a fixed
/// address on its host network; QEMU's asks DHCP.
fn bundleArgs(provider: howl.Platform, arch: howl.Arch) []const []const u8 {
    if (provider == .lima) return &.{
        "console=ttyAMA0",              "werewolf.ip=" ++ lima.user_ip,
        "werewolf.gw=" ++ lima.user_gw, "werewolf.dns=192.168.5.3",
    };
    return switch (arch) {
        .aarch64 => &.{"console=ttyAMA0"},
        .x86_64 => &.{"console=ttyS0"},
    };
}

/// resumeLocal builds a --build machine's image with the user's own keys:
/// for a new machine, or `howl run`'s, which a changed input reinstalls. A
/// privately signed image takes no changes in place unless it follows a
/// channel its builder serves (IPE_UPDATES), so another named machine keeps
/// the image it was made with, and starts on it, whatever changed.
pub fn resumeLocal(
    io: Io,
    gpa: Allocator,
    o: *howl.Options,
    name: []const u8,
    tell: howl.Tell,
    why: *howl.Why,
) !void {
    const provider = o.on.?;
    const arch = try admit(io, gpa, provider, tell.dev, why);
    const dir = try howl.machineDir(gpa, name);
    const authority = try gpa.print("{s}/authority", .{dir});
    const saved = Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/profile.json", .{authority}),
        gpa,
        .limited(64 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (saved) |text| {
        const p = try parseProfile(gpa, text);
        try requireVariants(p.spec.variants, howl.variants);
        inheritBhyveNetwork(o, p);
        const built = p.local orelse return why.refuse(
            "{s} was not built here with your keys: it runs werewolf's downloads, or an " ++
                "older howl made it. Name another machine, or howl delete {s} first",
            .{ name, name },
        );
        if (p.provider != provider or !std.mem.eql(u8, built.form, o.form)) return why.refuse(
            "{s}: provider or form changes require a new machine name; enrollment is retained",
            .{name},
        );
        if (o.app == null and try unchanged(io, gpa, authority, built)) return;
        if (!std.mem.eql(u8, name, howl.run_name)) return howl.say(
            io,
            "{s}: keeps the image it was made with; an image signed with your keys takes " ++
                "changes by reinstalling: howl delete {s}, then create it again",
            .{ name, name },
        );
        try @import("verbs.zig").remove(io, gpa, name, provider, why);
    }
    var options = try tell.step(gpa, dir);
    options.log = try gpa.print("{s}/build.log", .{dir});
    options.first = .{ .name = "Building the protected image", .short = "image" };
    var steps: progress.Steps = try .init(io, gpa, why, options);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    try Dir.cwd().createDirPath(io, dir);
    try Dir.cwd().setFilePermissions(io, dir, .fromMode(0o700), .{});
    const form = std.fs.path.basename(std.mem.trimEnd(u8, o.form, "/"));
    const index = if (howl.environ.get("IMAGE_INDEX")) |text|
        @import("cmdline").releaseIndex(text) orelse
            return why.refuse("IMAGE_INDEX={s}: a release index, 1 or more", .{text})
    else
        1;
    const built = try localSpec(io, gpa, &steps, o.*, provider, arch, try gpa.print(
        "{s}/build/bundles/{t}-{t}/{s}",
        .{ cwd, provider, arch, form },
    ), .{
        .channel = howl.environ.get("IPE_UPDATES"),
        .index = index,
        .disk = try gpa.print("{s}/{s}/disk.img", .{ cwd, dir }),
    }, why);
    _ = try build(io, gpa, &steps, built.spec, built.stub, .{ .disk = true });
    _ = try steps.finish();
    o.built = built;
}

/// recordBuild keeps what a local machine's next --build run compares its
/// inputs with: the stub its image took, and their fingerprint.
fn recordBuild(io: Io, gpa: Allocator, authority: []const u8, b: Built) !void {
    const stub = try gpa.print("{s}/linux.efi.stub", .{authority});
    try Dir.cwd().copyFile(b.stub, Dir.cwd(), stub, io, .{});
    const file = try gpa.print("{s}/image-inputs", .{authority});
    const temporary = try gpa.print("{s}.new", .{file});
    Dir.cwd().deleteFile(io, temporary) catch {};
    try bundle.durable(io, temporary, &try inputs(io, gpa, b.spec, stub));
    try Dir.cwd().rename(temporary, Dir.cwd(), file, io);
}

/// unchanged reports whether a local machine's build has the inputs its
/// image was made from. One gone, as make clean takes the IPE kernel, is
/// a change.
fn unchanged(io: Io, gpa: Allocator, authority: []const u8, built: native.Spec) !bool {
    const previous = Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/image-inputs", .{authority}),
        gpa,
        .limited(65),
    ) catch return false;
    const now = inputs(
        io,
        gpa,
        built,
        try gpa.print("{s}/linux.efi.stub", .{authority}),
    ) catch |err|
        switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
    return std.mem.eql(u8, &now, previous);
}

/// importImage readies a download's machine: it verifies werewolf's bundle
/// against howl's pins and unpacks its disk.
fn importImage(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    o: howl.Options,
    at: []const u8,
    authority: []const u8,
    request: bundle.Request,
) !Profile {
    const arch = howl.hostArch() orelse return error.UnsupportedHostArch;
    const verified = try bundle.verify(io, gpa, request, arch);
    const m = verified.manifest;
    const disk = try gpa.print("{s}/disk.img", .{at});
    try bundle.materialize(io, gpa, steps, request, verified, disk);
    try Dir.cwd().createDir(io, authority, .fromMode(0o700));
    const image_cert = try gpa.print("{s}/image.crt", .{authority});
    try Dir.cwd().copyFile(request.image_certificate, Dir.cwd(), image_cert, io, .{});
    const code = try gpa.print("{s}/boot.crt", .{at});
    return .{
        .provider = o.on.?,
        .bhyve_network = o.network orelse .tap,
        .bhyve_bridge = o.bridge,
        .managed = if (m.configuration) |definition| definition.lima_managed else false,
        .imported = m.image.build,
        .bundle = .{
            .directory = request.directory,
            .boot_certificate = code,
            .image_certificate = image_cert,
            .channel = request.channel,
        },
        .configuration = m.configuration,
        .spec = .{
            .form = m.form,
            .variants = m.variants,
            .arch = arch,
            .published = true,
            .disk_path = disk,
            .boot_cert = code,
            .boot_native = true,
            .tpm = true,
            .image_index = m.image.index,
            .ipe_cert = image_cert,
            .ipe_updates = m.image.channel,
            .image_serial = m.image.serial,
            .update_port = (try std.Uri.parse(m.image.channel)).port,
        },
    };
}

/// enroll gives a new machine its firmware, trusting the image's boot
/// certificate as PK, KEK and db alone, records its profile, and makes
/// its VM, with a TPM nothing has touched: its first boot makes it its own.
fn enroll(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    name: []const u8,
    at: []const u8,
    authority: []const u8,
    certificate: []const u8,
    profile: Profile,
    built: ?Built,
    tar: []const u8,
    why: *howl.Why,
) !void {
    const code = try gpa.print("{s}/boot.crt", .{at});
    if (!std.mem.eql(u8, certificate, code))
        try Dir.cwd().copyFile(certificate, Dir.cwd(), code, io, .{});
    try secureboot.enroll(io, gpa, steps, at, profile.spec.arch, code, code);
    try bundle.durable(
        io,
        try gpa.print("{s}/profile.json", .{authority}),
        try std.json.Stringify.valueAlloc(gpa, profile, .{}),
    );
    if (built) |b| try recordBuild(io, gpa, authority, b);
    try provisionInstance(io, gpa, steps, profile, name, at, tar, why);
}

/// An explicit stop preserves the protected machine's image and enrollment.
pub fn stop(
    io: Io,
    gpa: Allocator,
    name: []const u8,
    provider: howl.Platform,
    why: *howl.Why,
) !bool {
    const dir = try howl.machineDir(gpa, name);
    const authority = try gpa.print("{s}/authority", .{dir});
    const saved = Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/profile.json", .{authority}),
        gpa,
        .limited(64 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    const guard = try Dir.cwd().openFile(
        io,
        try gpa.print("{s}/secure.lock", .{dir}),
        .{ .mode = .read_write },
    );
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    const profile = try parseProfile(gpa, saved);
    if (profile.provider != provider) return why.refuse("the secured provider cannot change", .{});
    switch (provider) {
        .lima => {
            const instance = try lima.dir(io, gpa, name) orelse return error.MissingLimaInstance;
            const yaml = try Dir.cwd().readFileAlloc(
                io,
                try gpa.print("{s}/lima.yaml", .{instance}),
                gpa,
                .limited(1 << 20),
            );
            const form = lima.formOf(yaml) orelse return error.ForeignLimaInstance;
            if (!std.mem.eql(u8, form, profile.spec.form)) return error.ForeignLimaInstance;
            if (try lima.running(io, gpa, name)) try howl.run(io, why, &.{
                "limactl", "stop", "-f", name,
            });
        },
        .qemu => {
            _ = try qemu.stop(io, gpa, dir);
            try stopTpm(io, gpa, dir);
        },
        .bhyve => try bhyve.stopProtected(io, gpa, name, dir),
        else => return error.BadSecuredProvider,
    }
    return true;
}

/// Matching inputs keep the image and TPM; matching live guests need no work.
pub fn reuse(io: Io, gpa: Allocator, o: howl.Options, name: []const u8, tar: []const u8) !Reuse {
    if (!o.protected() or o.app != null) return .miss;
    const dir = try howl.machineDir(gpa, name);
    const authority = try gpa.print("{s}/authority", .{dir});
    const saved = Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/profile.json", .{authority}),
        gpa,
        .limited(64 << 10),
    ) catch |err| switch (err) {
        error.FileNotFound => return .miss,
        else => return err,
    };
    const guard = try Dir.cwd().openFile(
        io,
        try gpa.print("{s}/secure.lock", .{dir}),
        .{ .mode = .read_write },
    );
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    const profile = try parseProfile(gpa, saved);
    try requireVariants(profile.spec.variants, howl.variants);
    if (profile.provider != o.on.?) return .miss;
    if (profile.local) |built| {
        if (!o.local or o.app != null or !std.mem.eql(u8, built.form, o.form)) return .miss;
        if (!try unchanged(io, gpa, authority, built)) return .miss;
    } else if (profile.imported != null) {
        if (!std.mem.eql(u8, profile.spec.form, o.form)) return .miss;
        if (o.local or o.boot_image == null) return error.ImportedImageCannotSourceBuild;
    } else return .miss;
    Dir.cwd().access(io, try gpa.print("{s}/ready", .{authority}), .{}) catch return .miss;
    const current = try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/config.tar", .{dir}),
        gpa,
        .limited(64 << 20),
    );
    if (!std.mem.eql(u8, tar, current)) return .configure;
    if (profile.provider == .lima) {
        return if (try lima.running(io, gpa, name)) .running else .configure;
    } else if (profile.provider == .qemu) {
        if (qemu.running(io, gpa, dir) == null) return .configure;
        const monitor = try Io.net.UnixAddress.init(try gpa.print("{s}/monitor.sock", .{dir}));
        const connection = monitor.connect(io) catch return .configure;
        connection.close(io);
        return .running;
    } else if (profile.provider == .bhyve) {
        if (profile.bhyve_network != (o.network orelse .tap) or
            !std.mem.eql(u8, profile.bhyve_bridge orelse "", o.bridge orelse "")) return .configure;
        return if (try bhyve.supervised(io, gpa, dir) and try bhyve.exists(io, gpa, name))
            .running
        else
            .configure;
    }
    return .miss;
}

fn sameArtifact(io: Io, gpa: Allocator, given: []const u8, held: []const u8) !bool {
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const a_path = try std.fs.path.resolveAlloc(gpa, &.{ cwd, given });
    const b_path = try std.fs.path.resolveAlloc(gpa, &.{ cwd, held });
    // inputs checks held's bytes; do not hash that same file twice.
    if (std.mem.eql(u8, a_path, b_path)) return true;
    const a = try @import("prebuilt").hashFile(io, gpa, given);
    const b = try @import("prebuilt").hashFile(io, gpa, held);
    return a.size == b.size and std.mem.eql(u8, a.sha256, b.sha256);
}

/// testMachine makes a fake running QEMU machine for reuse's tests: its
/// profile, config tar, live pid and monitor socket.
fn testMachine(io: Io, gpa: Allocator, profile: Profile, tar: []const u8) !struct {
    name: []const u8,
    dir: []const u8,
    server: Io.net.Server,
} {
    var nonce: [6]u8 = undefined;
    try io.randomSecure(&nonce);
    const name = try gpa.print("ww-cache-{x}", .{&nonce});
    const dir = try howl.machineDir(gpa, name);
    const authority = try gpa.print("{s}/authority", .{dir});
    try Dir.cwd().createDirPath(io, authority);
    try Dir.cwd().writeFile(io, .{
        .sub_path = try gpa.print("{s}/profile.json", .{authority}),
        .data = try std.json.Stringify.valueAlloc(gpa, profile, .{}),
    });
    try Dir.cwd().writeFile(
        io,
        .{ .sub_path = try gpa.print("{s}/secure.lock", .{dir}), .data = "" },
    );
    try Dir.cwd().writeFile(
        io,
        .{ .sub_path = try gpa.print("{s}/ready", .{authority}), .data = "" },
    );
    try Dir.cwd().writeFile(
        io,
        .{ .sub_path = try gpa.print("{s}/config.tar", .{dir}), .data = tar },
    );
    try Dir.cwd().writeFile(io, .{
        .sub_path = try gpa.print("{s}/qemu.pid", .{dir}),
        .data = try gpa.print("{d}\n", .{if (@import("builtin").os.tag == .linux)
            std.os.linux.getpid()
        else
            std.c.getpid()}),
    });
    const monitor = try Io.net.UnixAddress.init(try gpa.print("{s}/monitor.sock", .{dir}));
    return .{ .name = name, .dir = dir, .server = try monitor.listen(io, .{}) };
}

test "unchanged live runs preserve state; changed inputs and config refuse reuse" {
    const t = std.testing;
    const io = t.io;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var env: std.process.Environ.Map = .init(gpa);
    howl.environ = &env;
    defer howl.environ = undefined;
    var scratch = t.tmpDir(.{});
    defer scratch.cleanup();
    const root = try scratch.dir.realPathFileAlloc(io, ".", gpa);
    const form = try gpa.print("{s}/form", .{root});
    try Dir.cwd().createDirPath(io, form);
    try Dir.cwd().writeFile(io, .{
        .sub_path = try gpa.print("{s}/form.yaml", .{form}),
        .data = "base: playground\n",
    });
    const source_dir = try gpa.print("{s}/cmd/cache", .{form});
    try Dir.cwd().createDirPath(io, source_dir);
    const source_file = try gpa.print("{s}/cache.zig", .{source_dir});
    try Dir.cwd().writeFile(io, .{ .sub_path = source_file, .data = "original source" });
    for ([_][]const u8{ "kernel", "ipe.key", "ipe.crt", "boot.key", "boot.crt" }) |file|
        try Dir.cwd().writeFile(
            io,
            .{ .sub_path = try gpa.print("{s}/{s}", .{ root, file }), .data = file },
        );
    const spec: native.Spec = .{
        .variants = howl.variants,
        .form = form,
        .arch = .aarch64,
        .ipe_kernel = try gpa.print("{s}/kernel", .{root}),
        .ipe_key = try gpa.print("{s}/ipe.key", .{root}),
        .ipe_cert = try gpa.print("{s}/ipe.crt", .{root}),
        .boot_key = try gpa.print("{s}/boot.key", .{root}),
        .boot_cert = try gpa.print("{s}/boot.crt", .{root}),
    };
    const tar = try howl.writeTar(
        gpa,
        &.{.{ .path = "hostname", .data = "cached", .from = "test" }},
    );
    const profile: Profile = .{
        .spec = .{ .form = "form", .arch = .aarch64 },
        .managed = false,
        .provider = .qemu,
        .local = scrubLocalSpec(spec),
    };
    var m = testMachine(io, gpa, profile, tar) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer Dir.cwd().deleteTree(io, m.dir) catch {};
    defer m.server.deinit(io);
    const authority = try gpa.print("{s}/authority", .{m.dir});
    const stub = try gpa.print("{s}/linux.efi.stub", .{authority});
    try Dir.cwd().writeFile(io, .{ .sub_path = stub, .data = "stub" });
    try Dir.cwd().writeFile(io, .{
        .sub_path = try gpa.print("{s}/image-inputs", .{authority}),
        .data = &try inputs(io, gpa, scrubLocalSpec(spec), stub),
    });
    const saved_json = try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/profile.json", .{authority}),
        gpa,
        .limited(64 << 10),
    );
    try t.expect(std.mem.find(u8, saved_json, "boot.key") == null);
    try t.expect(std.mem.find(u8, saved_json, "ipe.key") == null);
    const o: howl.Options = .{ .form = form, .on = .qemu, .local = true };
    try t.expectEqual(Reuse.running, try reuse(io, gpa, o, m.name, tar));
    var downloaded = o;
    downloaded.local = false;
    downloaded.form = "playground";
    downloaded.boot_image = .{
        .directory = "unused-vendor-bundle",
        .boot_certificate = "unused-boot-certificate",
        .image_certificate = "unused-image-certificate",
        .channel = "https://dist.example/boot/v1/playground/qemu",
    };
    var why: howl.Why = .{};
    try t.expectError(error.Refused, resumeDownload(io, gpa, &downloaded, m.name, &why));
    try t.expect(std.mem.indexOf(u8, why.text, "trusts only your boot key") != null);
    try t.expect(std.mem.indexOf(u8, why.text, "--with playground --on qemu") != null);
    try Dir.cwd().writeFile(io, .{ .sub_path = source_file, .data = "edited guest source" });
    try t.expectEqual(Reuse.miss, try reuse(io, gpa, o, m.name, tar));
    try Dir.cwd().writeFile(io, .{ .sub_path = source_file, .data = "original source" });
    try Dir.cwd().writeFile(io, .{
        .sub_path = try gpa.print("{s}/README.md", .{source_dir}),
        .data = "documentation edit",
    });
    try t.expectEqual(Reuse.running, try reuse(io, gpa, o, m.name, tar));
    try t.expectEqual(Reuse.configure, try reuse(
        io,
        gpa,
        o,
        m.name,
        try howl.writeTar(gpa, &.{.{ .path = "hostname", .data = "changed", .from = "test" }}),
    ));
    try Dir.cwd().writeFile(io, .{ .sub_path = spec.ipe_cert.?, .data = "changed signer" });
    try t.expectEqual(Reuse.miss, try reuse(io, gpa, o, m.name, tar));
    try Dir.cwd().writeFile(io, .{ .sub_path = spec.ipe_cert.?, .data = "ipe.crt" });
    try Dir.cwd().writeFile(io, .{ .sub_path = spec.boot_cert.?, .data = "changed boot signer" });
    try t.expectEqual(Reuse.miss, try reuse(io, gpa, o, m.name, tar));
    try Dir.cwd().writeFile(io, .{ .sub_path = spec.boot_cert.?, .data = "boot.crt" });
    try Dir.cwd().deleteFile(io, try gpa.print("{s}/ready", .{authority}));
    try t.expectEqual(Reuse.miss, try reuse(io, gpa, o, m.name, tar));
}

test "scrubLocalSpec and replaceRecord persist 0600 profiles without private-key paths" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(t.io, ".", gpa);
    const raw: native.Spec = .{
        .form = "playground",
        .arch = .aarch64,
        .boot_key = "/secret/host/boot.key",
        .boot_cert = "/public/host/boot.crt",
        .ipe_key = "/secret/host/ipe.key",
        .ipe_cert = "/public/host/ipe.crt",
    };
    const scrubbed = scrubLocalSpec(raw);
    const profile: Profile = .{
        .spec = scrubbed,
        .local = scrubbed,
        .managed = false,
        .provider = .qemu,
    };
    const profile_path = try gpa.print("{s}/profile.json", .{root});
    try @import("data-image.zig").replaceRecord(
        t.io,
        gpa,
        profile_path,
        try std.json.Stringify.valueAlloc(gpa, profile, .{}),
    );
    const st = try tmp.dir.statFile(t.io, "profile.json", .{ .follow_symlinks = false });
    try t.expectEqual(@as(u32, 0o600), st.permissions.toMode() & 0o777);
    const text = try tmp.dir.readFileAlloc(t.io, "profile.json", gpa, .limited(64 << 10));
    try t.expect(std.mem.find(u8, text, "boot.key") == null);
    try t.expect(std.mem.find(u8, text, "ipe.key") == null);
    const loaded = try parseProfile(gpa, text);
    try t.expectEqual(null, loaded.spec.boot_key);
    try t.expectEqual(null, loaded.spec.ipe_key);
    try t.expectEqual(null, loaded.local.?.boot_key);
    try t.expectEqual(null, loaded.local.?.ipe_key);
}

test "downloaded live reuse has no vendor keys and keeps the bundle it was made from" {
    const t = std.testing;
    const io = t.io;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const made: bundle.Request = .{
        .directory = "immutable-A",
        .boot_certificate = "public-boot.crt",
        .image_certificate = "public-image.crt",
        .channel = "https://dist.example/boot/v1/playground/qemu",
    };
    const profile: Profile = .{
        .spec = .{ .form = "playground", .arch = .x86_64, .published = true },
        .managed = false,
        .provider = .qemu,
        .imported = "A",
        .bundle = made,
    };
    const tar = try howl.writeTar(gpa, &.{.{ .path = "hostname", .data = "a", .from = "test" }});
    var m = testMachine(io, gpa, profile, tar) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer Dir.cwd().deleteTree(io, m.dir) catch {};
    defer m.server.deinit(io);
    var o: howl.Options = .{ .form = "playground", .on = .qemu, .boot_image = made };
    try t.expectEqual(Reuse.running, try reuse(io, gpa, o, m.name, tar));
    try t.expectEqual(Reuse.configure, try reuse(
        io,
        gpa,
        o,
        m.name,
        try howl.writeTar(gpa, &.{.{ .path = "hostname", .data = "changed", .from = "test" }}),
    ));
    o.local = true;
    try t.expectError(error.ImportedImageCannotSourceBuild, reuse(io, gpa, o, m.name, tar));
    const kept = try parseProfile(gpa, try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/authority/profile.json", .{m.dir}),
        gpa,
        .limited(64 << 10),
    ));
    try t.expectEqualStrings("immutable-A", kept.bundle.?.directory);
    try t.expectEqual(null, kept.spec.ipe_key);
    try t.expectEqual(null, kept.spec.boot_key);
}

pub fn create(
    io: Io,
    gpa: Allocator,
    o: howl.Options,
    name: []const u8,
    tar: []const u8,
    tell: howl.Tell,
    w: *Io.Writer,
    why: *howl.Why,
) !void {
    const provider = howl.engine(io, gpa, o.on).on;
    const on_lima = provider == .lima;
    _ = try admit(io, gpa, provider, tell.dev, why);
    const dir = try howl.machineDir(gpa, name);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const at = try gpa.print("{s}/{s}", .{ cwd, dir });
    const authority = try gpa.print("{s}/authority", .{at});
    const profile_file = try gpa.print("{s}/profile.json", .{authority});
    try Dir.cwd().createDirPath(io, at);
    try Dir.cwd().setFilePermissions(io, at, .fromMode(0o700), .{});
    const guard = try Dir.cwd().createFile(io, try gpa.print("{s}/secure.lock", .{at}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    const kept = if (Dir.cwd().access(io, profile_file, .{})) |_| true else |err| switch (err) {
        error.FileNotFound => false,
        else => return err,
    };
    if (!kept) {
        // An empty directory left by failed firmware preparation contains
        // no enrollment to replace. All nonempty authority remains guarded.
        if (!try emptyAuthority(io, authority)) return why.refuse(
            "{s}: enrollment already exists; inspect the partial creation before recreating",
            .{name},
        );
        Dir.cwd().deleteDir(io, authority) catch |err| if (err != error.FileNotFound) return err;
    }
    var steps: progress.Steps = try .init(io, gpa, why, try tell.step(gpa, dir));
    Dir.cwd().deleteFile(io, try gpa.print("{s}/ready", .{authority})) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    var profile: Profile = undefined;
    if (kept) {
        profile = try parseProfile(gpa, try Dir.cwd().readFileAlloc(
            io,
            profile_file,
            gpa,
            .limited(64 << 10),
        ));
        if (profile.imported != null) {
            const requested = o.boot_image orelse
                return error.ImportedImageNeedsAuthenticatedResume;
            const verified = try bundle.verify(io, gpa, requested, profile.spec.arch);
            if (!std.mem.eql(u8, profile.imported.?, verified.manifest.image.build))
                return error.ImportedImageCannotReplaceEnrollment;
        } else if (profile.local == null) return why.refuse(
            "{s} was made by an older howl: howl delete {s}, then create it again",
            .{ name, name },
        );
        if (profile.provider != provider) return why.refuse(
            "the secured provider cannot change",
            .{},
        );
        try howl.reconfigurable(o, name, profile.spec.form, provider, why);
        const current = try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/config.tar", .{at}),
            gpa,
            .limited(64 << 20),
        );
        const network_changed = provider == .bhyve and
            (profile.bhyve_network != (o.network orelse .tap) or
                !std.mem.eql(u8, profile.bhyve_bridge orelse "", o.bridge orelse ""));
        if (!std.mem.eql(u8, current, tar) or network_changed) {
            if (on_lima) {
                _ = try @import("local.zig").reconfigure(io, gpa, name, o.form, dir, tar, why);
            } else {
                if (provider == .bhyve) {
                    try bhyve.stopProtected(io, gpa, name, at);
                } else {
                    _ = try qemu.stop(io, gpa, dir);
                    try swtpm.stop(io, gpa, try tpm(io, gpa, at));
                }
                try howl.writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{at}), tar, why);
            }
            if (network_changed) {
                profile.bhyve_network = o.network orelse .tap;
                profile.bhyve_bridge = o.bridge;
                try @import("data-image.zig").replaceRecord(
                    io,
                    gpa,
                    profile_file,
                    try std.json.Stringify.valueAlloc(gpa, profile, .{}),
                );
            }
        }
    } else if (o.built) |b| {
        try Dir.cwd().createDir(io, authority, .fromMode(0o700));
        const form = std.fs.path.basename(std.mem.trimEnd(u8, o.form, "/"));
        const definition = try @import("boot-config.zig").derive(io, gpa, o.form, form, why);
        const spec = scrubLocalSpec(b.spec);
        profile = .{
            .spec = spec,
            .provider = provider,
            .managed = definition.lima_managed,
            .configuration = definition,
            .local = spec,
            .bhyve_network = o.network orelse .tap,
            .bhyve_bridge = o.bridge,
        };
        try enroll(io, gpa, &steps, name, at, authority, b.spec.boot_cert.?, profile, b, tar, why);
    } else if (o.boot_image) |request| {
        profile = try importImage(io, gpa, &steps, o, at, authority, request);
        try enroll(
            io,
            gpa,
            &steps,
            name,
            at,
            authority,
            request.boot_certificate,
            profile,
            null,
            tar,
            why,
        );
    } else return error.MissingBootImage;
    if (!kept) {
        const approved = try @import("data-image.zig").approve(io, gpa, profile, true, why);
        profile.data_image = approved.profile.data_image;
        try @import("data-image.zig").replaceRecord(
            io,
            gpa,
            profile_file,
            try std.json.Stringify.valueAlloc(gpa, profile, .{}),
        );
    }
    try startEnrolled(io, gpa, profile, name, at, tell, &steps, w, why);
}

/// Start the enrolled image with its saved deployment configuration. No form
/// source, new configuration, image selection or application startup precedes it.
pub fn start(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    if (args.len != 1 or !howl.isMachineName(args[0])) return why.refuse("howl start NAME", .{});
    const name = args[0];
    const at = try std.fs.path.resolveAlloc(
        gpa,
        &.{ try std.process.currentPathAlloc(io, gpa), try howl.machineDir(gpa, name) },
    );
    const guard = try Dir.cwd().openFile(
        io,
        try gpa.print("{s}/secure.lock", .{at}),
        .{ .mode = .read_write },
    );
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    var profile = try parseProfile(
        gpa,
        try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/authority/profile.json", .{at}),
            gpa,
            .limited(256 << 10),
        ),
    );
    if (profile.cloud_staged) return @import("data-cloud-target.zig").start(
        io,
        gpa,
        name,
        at,
        profile,
        why,
    );
    if (cloud.supported(profile.provider)) {
        const context = try @import("data-cloud.zig").load(io, gpa, at, profile.provider);
        if ((try @import("data-cloud.zig").state(
            io,
            gpa,
            name,
            context,
        )).running) return why.refuse("{s}: already running", .{name});
        const argv: []const []const u8 = switch (context) {
            .aws => |p| &.{
                "aws",
                "--region",
                p.region,
                "ec2",
                "start-instances",
                "--instance-ids",
                p.id,
            },
            .gcp => |p| &.{
                "gcloud",
                "--quiet",
                "--project",
                p.project,
                "compute",
                "instances",
                "start",
                name,
                "--zone",
                p.zone,
            },
            .azure => |p| &.{ "az", "vm", "start", "-g", p.group, "-n", name, "-o", "none" },
        };
        return howl.run(io, why, argv);
    }
    if (profile.provider == .firecracker) {
        if (@import("builtin").os.tag != .linux or
            profile.spec.arch != howl.hostArch()) return error.TransferArchitecture;
        if (try @import("firecracker.zig").supervised(
            io,
            gpa,
            at,
        )) return why.refuse("{s}: already running", .{name});
        const spec = profile.local orelse return error.MissingBootImage;
        const definition = profile.configuration orelse return error.MissingBootConfiguration;
        const saved_definition = @import("boot-config.zig").current;
        @import("boot-config.zig").current = definition;
        defer @import("boot-config.zig").current = saved_definition;
        const tar = try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/config.tar", .{at}),
            gpa,
            .limited(64 << 20),
        );
        const tell: howl.Tell = .{
            .verbose = false,
            .command = try gpa.print("howl start {s}", .{name}),
            .began = Io.Clock.awake.now(io),
        };
        return @import("local.zig").createFirecrackerLocked(
            io,
            gpa,
            .{
                .form = definition.form,
                .local = true,
                .on = .firecracker,
                .disabled = spec.disabled,
            },
            name,
            tar,
            null,
            tell,
            guard,
            why,
        );
    }
    profile.spec.form = (profile.configuration orelse return error.MissingBootConfiguration).form;
    if (profile.spec.arch != try admit(
        io,
        gpa,
        profile.provider,
        false,
        why,
    )) return error.TransferArchitecture;
    if (profile.bundle) |request| {
        const approved = try bundle.verify(io, gpa, request, profile.spec.arch);
        if (!std.mem.eql(
            u8,
            approved.manifest.image.build,
            profile.imported orelse return error.MissingBootImage,
        )) return error.ExistingImageAuthorityMismatch;
    } else if (profile.local == null) return error.MissingBootImage;
    const previous = @import("boot-config.zig").current;
    @import("boot-config.zig").current = profile.configuration;
    defer @import("boot-config.zig").current = previous;
    const tell: howl.Tell = .{
        .verbose = false,
        .command = try gpa.print("howl start {s}", .{name}),
        .began = Io.Clock.awake.now(io),
    };
    var steps = try progress.Steps.init(io, gpa, why, try tell.step(gpa, at));
    var out = Io.File.stdout().writerStreaming(io, &.{});
    try startEnrolled(io, gpa, profile, name, at, tell, &steps, &out.interface, why);
}

fn startEnrolled(
    io: Io,
    gpa: Allocator,
    profile: Profile,
    name: []const u8,
    at: []const u8,
    tell: howl.Tell,
    steps: *progress.Steps,
    w: *Io.Writer,
    why: *howl.Why,
) !void {
    const provider = profile.provider;
    const on_lima = provider == .lima;
    const authority = try gpa.print("{s}/authority", .{at});

    try steps.enter(.{
        .name = if (on_lima)
            "Starting Lima VM and waiting for guest init"
        else if (provider == .bhyve)
            "Starting bhyve and waiting for guest init"
        else
            "Starting QEMU and waiting for guest init",
        .short = "launch",
    });
    if (!on_lima) {
        if (provider == .bhyve) {
            if (!try bhyve.supervised(io, gpa, at))
                try startBhyve(io, gpa, profile, name, at, steps, why);
        } else if (qemu.running(io, gpa, at) == null)
            try startQemu(io, gpa, profile, name, at, steps, why);
    } else if (!try lima.running(io, gpa, name)) {
        const instance = try lima.dir(io, gpa, name) orelse return error.MissingLimaInstance;
        const console = try gpa.print("{s}/serial.log", .{instance});
        const seen = if (Dir.cwd().statFile(io, console, .{})) |stat| stat.size else |_| 0;
        const log = try Dir.cwd().createFile(io, try gpa.print("{s}/start.log", .{at}), .{});
        defer log.close(io);
        var env = try howl.environ.clone(gpa);
        try env.put("QEMU_SYSTEM_AARCH64", try qemuWrapper(io, gpa, at));
        // Howl checks verified init over the console. Lima's shell readiness
        // probes cannot succeed on these images and can penalize the same NAT
        // address used by the owner. Keep those probes local and unsuccessful;
        // Howl's explicit, pinned SSH connections use a separate process.
        const probes = try gpa.print("{s}/lima-probes", .{at});
        try Dir.cwd().createDirPath(io, probes);
        const no_connect = try Dir.cwd().createFile(
            io,
            try gpa.print("{s}/ssh", .{probes}),
            .{ .permissions = .fromMode(0o700) },
        );
        defer no_connect.close(io);
        try no_connect.writeStreamingAll(
            io,
            "#!/bin/sh\nexec /usr/bin/ssh -o ProxyCommand=/usr/bin/false \"$@\"\n",
        );
        try env.put(
            "PATH",
            try gpa.print("{s}:{s}", .{ probes, howl.environ.get("PATH") orelse "/usr/bin:/bin" }),
        );
        var starter = try std.process.spawn(io, .{
            .argv = &.{ "limactl", "start", "--tty=false", name },
            .environ_map = &env,
            .stdin = .ignore,
            .stdout = .{ .file = log },
            .stderr = .{ .file = log },
        });
        defer starter.kill(io);
        var spin: progress.Spinner = .init(io);
        spin.phase = steps.said.phase.name;
        spin.start = steps.said.since;
        const boot = try booting.watch(io, gpa, console, seen, null, 0, &spin);
        spin.clear();
        if (!boot.up) return why.refuse(
            "{s}: protected boot did not finish; see {s}",
            .{ name, console },
        );
    }
    try @import("data-image.zig").replaceRecord(
        io,
        gpa,
        try gpa.print("{s}/ready", .{authority}),
        "verified\n",
    );
    _ = try steps.finish();
    if (tell.milestones) |m| m.done(.{
        .name = try gpa.print("{s} running; total", .{name}),
        .short = "ready",
    });
    try @import("local.zig").protectedReady(
        io,
        gpa,
        name,
        profile.spec.form,
        provider,
        false,
        w,
        why,
    );
}

fn emptyAuthority(io: Io, path: []const u8) !bool {
    var dir = Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return true,
        else => return err,
    };
    defer dir.close(io);
    var iterator = dir.iterate();
    return try iterator.next(io) == null;
}

test "early firmware failure can retry but any enrollment material refuses replacement" {
    const t = std.testing;
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realPathFileAlloc(t.io, ".", t.allocator);
    defer t.allocator.free(path);
    try t.expect(try emptyAuthority(t.io, path));
    try tmp.dir.writeFile(t.io, .{ .sub_path = "owner.auth", .data = "original authority" });
    try t.expect(!try emptyAuthority(t.io, path));
    const bytes = try tmp.dir.readFileAlloc(t.io, "owner.auth", t.allocator, .limited(64));
    defer t.allocator.free(bytes);
    try t.expectEqualStrings("original authority", bytes);
}

fn inputs(io: Io, gpa: Allocator, spec: native.Spec, stub: []const u8) ![64]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&try @import("lock.zig").inputs(io, gpa, spec));
    hash.update(&try programInputs(io, gpa, spec));
    for ([5][]const u8{
        spec.ipe_kernel.?,                            spec.ipe_cert.?,
        spec.boot_cert.?,                             stub,
        try std.process.executablePathAlloc(io, gpa),
    }) |file| hash.update((try @import("prebuilt").hashFile(io, gpa, file)).sha256);
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

/// Bind checkout sources used by the image, even when howl itself was not rebuilt.
fn programInputs(io: Io, gpa: Allocator, spec: native.Spec) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for ([_][]const u8{ "Makefile", "files.zig" }) |file| {
        hash.update(file);
        const bytes = @import("prebuilt").hashFile(io, gpa, file) catch |err| switch (err) {
            error.FileNotFound => {
                hash.update("absent");
                continue;
            },
            else => return err,
        };
        hash.update(bytes.sha256);
    }
    try sourceTree(io, gpa, &hash, "lib");
    for ([_][]const u8{"init"} ++ native.every_program) |name|
        try sourceTree(io, gpa, &hash, try gpa.print("cmd/{s}", .{name}));
    var bad: @import("form").Failure = .{};
    const chain = try @import("form").chainSelectedIn(
        io,
        gpa,
        Dir.cwd(),
        "forms",
        spec.form,
        spec.selected(),
        &bad,
    );
    for (chain) |part| {
        for (try part.items(gpa, "programs")) |item| {
            var names = std.mem.tokenizeAny(u8, item, " \t");
            while (names.next()) |name| {
                const stem = name[0 .. std.mem.findScalarLast(u8, name, '.') orelse name.len];
                try sourceTree(io, gpa, &hash, try gpa.print("cmd/{s}", .{stem}));
            }
        }
        try sourceTree(io, gpa, &hash, try gpa.print("{s}/cmd", .{part.dir}));
        for (try part.recipes(io, gpa, Dir.cwd())) |recipe| {
            hash.update(recipe);
            hash.update(&try @import("lock.zig").tree(
                io,
                gpa,
                Dir.cwd(),
                std.fs.path.dirname(recipe) orelse ".",
            ));
        }
    }
    if (@import("app.zig").example(chain[chain.len - 1].name)) |example| {
        const sources: []const []const u8 = switch (example) {
            .go => &.{"examples/go/main.go"},
            .rust => &.{"examples/rust/main.rs"},
            .aspnet => &.{ "examples/aspnet/Program.cs", "examples/aspnet/App.csproj" },
        };
        for (sources) |file| hash.update((try @import("prebuilt").hashFile(io, gpa, file)).sha256);
    }
    return hash.finalResult();
}

fn sourceTree(io: Io, gpa: Allocator, hash: *std.crypto.hash.sha2.Sha256, path: []const u8) !void {
    hash.update(path);
    hash.update(&.{0});
    var dir = Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => {
            hash.update("absent");
            return;
        },
        else => return err,
    };
    defer dir.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var walker = try dir.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (!std.mem.endsWith(u8, entry.path, ".zig") and
            !std.mem.endsWith(u8, entry.path, ".mtree")) continue;
        try names.append(gpa, try gpa.dupe(u8, entry.path));
    }
    std.mem.sort([]const u8, names.items, {}, native.lessThan);
    for (names.items) |name| {
        hash.update(name);
        hash.update(&.{0});
        hash.update((try @import("prebuilt").hashFile(io, gpa, try gpa.print(
            "{s}/{s}",
            .{ path, name },
        ))).sha256);
    }
}

fn build(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    spec: native.Spec,
    stub: []const u8,
    goals: native.Goals,
) !native.Paths {
    var env = try howl.environ.clone(gpa);
    try env.put("UKI_STUB", stub);
    const previous = howl.environ;
    howl.environ = &env;
    defer howl.environ = previous;
    return howl.buildHere(io, gpa, steps, spec, goals);
}

fn serial(io: Io, gpa: Allocator) ![]const u8 {
    const seconds = @divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s);
    return gpa.print("{f}", .{@import("update-policy").Serial{ .secs = @intCast(seconds) }});
}

/// tpm is the TPM supervisor of the machine at at. Its socket directory is
/// named by the machine's path, short enough for QEMU's and bhyve's sockets.
fn tpm(io: Io, gpa: Allocator, at: []const u8) !swtpm.Service {
    const absolute = if (std.fs.path.isAbsolute(at))
        at
    else
        try gpa.print("{s}/{s}", .{ try std.process.currentPathAlloc(io, gpa), at });
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(absolute, &hash, .{});
    const backend: swtpm.Backend = if (Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/authority/profile.json", .{absolute}),
        gpa,
        .limited(64 << 10),
    )) |data| switch ((try parseProfile(gpa, data)).provider) {
        .qemu => .qemu,
        .bhyve => .bhyve,
        else => return error.BadTpmBackend,
    } else |err| if (err == error.FileNotFound) .qemu else return err;
    return .{
        .authority = try gpa.print("{s}/authority", .{absolute}),
        .sockets = try gpa.print("/tmp/ww-tpm-{x}", .{hash[0..12]}),
        .backend = backend,
    };
}

pub fn stopTpm(io: Io, gpa: Allocator, dir: []const u8) !void {
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const at = try gpa.print("{s}/{s}", .{ cwd, dir });
    return stopTpmAt(io, gpa, at);
}

pub fn stopTpmAt(io: Io, gpa: Allocator, at: []const u8) !void {
    // A TPM that never ran has no supervisor lock; Lima keeps its own TPM.
    Dir.cwd().access(
        io,
        try gpa.print("{s}/authority/tpm-service.lock", .{at}),
        .{},
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    try swtpm.stop(io, gpa, try tpm(io, gpa, at));
}

pub fn restartTpmAt(io: Io, gpa: Allocator, at: []const u8) !void {
    const service = try tpm(io, gpa, at);
    try swtpm.stop(io, gpa, service);
    try swtpm.start(io, gpa, service);
}

fn startBhyve(
    io: Io,
    gpa: Allocator,
    profile: Profile,
    name: []const u8,
    at: []const u8,
    steps: *progress.Steps,
    why: *howl.Why,
) !void {
    if (try bhyve.exists(
        io,
        gpa,
        name,
    )) return why.refuse("{s}: bhyve exists without its protected supervisor", .{name});
    try bhyve.prepareSupervisor(io, gpa, at);
    const definition = profile.configuration orelse return error.MissingBootConfiguration;
    const config = try gpa.print("{s}/config.tar", .{at});
    const configured = try Dir.cwd().readFileAlloc(io, config, gpa, .limited(64 << 20));
    const static_address = try bhyve.staticAddress(gpa, configured);
    const mode = profile.bhyve_network;
    if (mode == .tap and !definition.dhcp and static_address == null) return why.refuse(
        "{s} has no DHCP client; TAP needs --ip CIDR --gw ADDR --dns ADDR (or --config " ++
            "DIR/network)",
        .{profile.spec.form},
    );
    const network = try bhyve.prepareNetwork(io, gpa, at, mode, profile.bhyve_bridge, why);
    errdefer bhyve.stopProtected(io, gpa, name, at) catch {};
    const fwds = try bhyve.forwards(gpa, name, definition.ports);
    var ssh: u16 = 0;
    for (fwds) |f| if (f.guest == 22) {
        ssh = if (mode == .slirp) f.host else 22;
    };
    try howl.writePrivate(
        io,
        gpa,
        try gpa.print("{s}/machine", .{at}),
        try gpa.print("form {s}\nssh {d}\n", .{ profile.spec.form, ssh }),
        why,
    );
    const log = try gpa.print("{s}/console.log", .{at});
    const file = try Dir.cwd().createFile(io, log, .{ .permissions = .fromMode(0o600) });
    file.close(io);
    Dir.cwd().deleteFile(
        io,
        try gpa.print("{s}/bhyve.stop", .{at}),
    ) catch |err| if (err != error.FileNotFound) return err;
    const args = try bhyve.commandWith(gpa, name, try gpa.print(
        "{s}/disk.img",
        .{at},
    ), config, network.backend(fwds), null, .{
        .code = try gpa.print("{s}/code.fd", .{at}),
        .vars = try gpa.print("{s}/vars.fd", .{at}),
        .tpm_socket = try gpa.print("{s}/data.sock", .{(try tpm(io, gpa, at)).sockets}),
    }, try bhyve.Runtime.fromEnvironment(howl.environ));
    const launch = try std.mem.concat(
        gpa,
        []const u8,
        &.{
            &.{
                "daemon",
                "-f",
                "-o",
                log,
                try std.process.executablePathAlloc(io, gpa),
                "_bhyve-secure",
                name,
                at,
            },
            try bhyve.asRoot(io),
            args,
        },
    );
    if (!(try steps.exec(
        &.{.{ .argv = launch }},
        .{},
    )).ok) return steps.fail("protected bhyve did not start");
    var spin: progress.Spinner = .init(io);
    defer spin.clear();
    const boot = try booting.watch(io, gpa, log, 0, null, 0, &spin);
    if (!boot.up) return why.refuse(
        "{s}: protected bhyve boot did not finish; see {s}",
        .{ name, log },
    );
    const address = if (mode == .slirp) "127.0.0.1" else static_address orelse
        (try bhyve.awaitAddress(io, gpa, log, 0)) orelse return why.refuse(
        "{s}: protected TAP guest reported no DHCP address; see {s}",
        .{ name, log },
    );
    try howl.writePrivate(io, gpa, try gpa.print("{s}/machine", .{at}), try gpa.print(
        "form {s}\nhost {s}\nssh {d}\nnetwork {t}\n",
        .{ profile.spec.form, address, ssh, mode },
    ), why);
    if (ssh != 0 and !booting.awaitSsh(io, address, ssh, &spin))
        return why.refuse("{s}: protected bhyve SSH did not become ready", .{name});
}

fn startQemu(
    io: Io,
    gpa: Allocator,
    profile: Profile,
    name: []const u8,
    at: []const u8,
    steps: *progress.Steps,
    why: *howl.Why,
) !void {
    const spec = profile.spec;
    // A new QEMU must not inherit an old emulator's in-flight connections.
    // Its enrolled NV state survives the supervisor restart.
    const service = try tpm(io, gpa, at);
    try swtpm.stop(io, gpa, service);
    try swtpm.start(io, gpa, service);
    errdefer swtpm.stop(io, gpa, service) catch {};
    const ssh = try qemu.freePort(io, 2222);
    const web = try qemu.freePort(io, 8080);
    try howl.writePrivate(
        io,
        gpa,
        try gpa.print("{s}/machine", .{at}),
        try gpa.print("form {s}\nssh {d}\nweb {d}\n", .{ spec.form, ssh, web }),
        why,
    );
    const guest_web = try qemuWebPort(profile);
    for ([_][]const u8{ "console.log", "console.sock", "monitor.sock", "owner.sock" }) |file|
        Dir.cwd().deleteFile(io, try gpa.print("{s}/{s}", .{ at, file })) catch {};
    const args = try qemu.argv(gpa, .{
        .arch = spec.arch,
        .dir = at,
        .firmware = .{
            .code = try gpa.print(
                "{s}/code.fd",
                .{at},
            ),
            .vars = try gpa.print("{s}/vars.fd", .{at}),
            .secure = true,
        },
        .ssh_port = ssh,
        .web_port = web,
        .guest_web = guest_web,
        .tpm_socket = try gpa.print("{s}/tpm.sock", .{service.sockets}),
        .owner = true,
    }, qemu.accel(io));
    if (!(try steps.exec(&.{.{ .argv = args }}, .{})).ok)
        return steps.fail("secured QEMU did not start");
    errdefer {
        _ = qemu.stop(io, gpa, at) catch false;
    }
    var spin: progress.Spinner = .init(io);
    spin.phase = steps.said.phase.name;
    spin.start = steps.said.since;
    const boot = try booting.watch(
        io,
        gpa,
        try gpa.print("{s}/console.log", .{at}),
        0,
        null,
        0,
        &spin,
    );
    spin.clear();
    if (!boot.up) return why.refuse("{s}: protected QEMU boot did not finish", .{name});
    if (std.mem.findScalar(u16, profile.configuration.?.ports, 22) != null) {
        defer spin.clear();
        if (!booting.awaitSsh(io, "127.0.0.1", ssh, &spin)) return why.refuse(
            "{s}: protected QEMU SSH did not become ready; howl console {s}",
            .{ name, name },
        );
    }
}

/// A downloaded form need not exist in this checkout. Its signed deployment
/// definition supplies the ports, including for locally built ad-hoc forms.
fn qemuWebPort(profile: Profile) !u16 {
    const definition = profile.configuration orelse return error.MissingBootConfiguration;
    var port: u16 = 80;
    for (definition.ports) |candidate| if (candidate != 22) {
        port = candidate;
    };
    return port;
}

test "protected QEMU uses authenticated ports without a local form tree" {
    const t = std.testing;
    var profile: Profile = .{
        .spec = .{ .form = "unavailable-custom-form", .arch = .x86_64 },
        .managed = false,
        .configuration = .{
            .form = "unavailable-custom-form",
            .interface = .{ .files = &.{}, .settings = &.{} },
            .ports = &.{ 22, 8081 },
            .dhcp = true,
            .ssh = .files,
            .lima_managed = false,
        },
    };
    try t.expectEqual(8081, try qemuWebPort(profile));
    profile.configuration.?.ports = &.{22};
    try t.expectEqual(80, try qemuWebPort(profile));
    profile.configuration = null;
    try t.expectError(error.MissingBootConfiguration, qemuWebPort(profile));
}

pub fn qemuCommand(gpa: Allocator, vars: []const u8) ![]const u8 {
    const escaped = try std.mem.replaceOwned(u8, gpa, vars, ",", ",,");
    const argument = try gpa.print("if=pflash,format=raw,unit=1,readonly=on,file={s}", .{escaped});
    const quoted = try std.mem.replaceOwned(u8, gpa, argument, "'", "'\\''");
    return gpa.print("qemu-system-aarch64 -drive '{s}'", .{quoted});
}

/// qemuWrapper writes the QEMU Lima runs for a protected machine: its
/// enrolled firmware variables, read-only, and any import disk.
fn qemuWrapper(io: Io, gpa: Allocator, at: []const u8) ![]const u8 {
    const vars = try std.mem.replaceOwned(u8, gpa, try gpa.print("{s}/vars.fd", .{at}), ",", ",,");
    const args: []const []const u8 = &.{
        "qemu-system-aarch64",                                                      "-drive",
        try gpa.print("if=pflash,format=raw,unit=1,readonly=on,file={s}", .{vars}),
    };
    var command: std.ArrayList(u8) = .empty;
    for (args, 0..) |arg, i| {
        if (i > 0) try command.append(gpa, ' ');
        try command.append(gpa, '\'');
        try command.appendSlice(gpa, try std.mem.replaceOwned(u8, gpa, arg, "'", "'\\''"));
        try command.append(gpa, '\'');
    }
    // Lima probes accelerators using only the executable in QEMU_SYSTEM_*.
    // Keep the fixed arguments inside an executable wrapper for those probes.
    const wrapper = try gpa.print("{s}/qemu-private", .{at});
    const file = try Dir.cwd().createFile(io, wrapper, .{ .permissions = .fromMode(0o700) });
    defer file.close(io);
    try file.writeStreamingAll(
        io,
        try gpa.print("#!/bin/sh\nexec {s} \"$@\"\n", .{command.items}),
    );
    return gpa.print("'{s}'", .{try std.mem.replaceOwned(u8, gpa, wrapper, "'", "'\\''")});
}

fn template(
    gpa: Allocator,
    form: []const u8,
    disk: []const u8,
    at: []const u8,
    config_disk: []const u8,
    managed: bool,
) ![]const u8 {
    return gpa.print(
        "# " ++ howl.form_tag ++ ": {s}\n# werewolf lima: secure\n{s}" ++
            "vmType: qemu\narch: aarch64\nplain: true\ntpm: true\ncpus: 4\nmemory: {d}MiB\n" ++
            "images:\n  - location: {s}\n    arch: aarch64\nfirmware:\n  images:\n" ++
            "    - location: {s}\n      arch: aarch64\nmounts: []\n" ++
            "additionalDisks:\n  - name: {s}\n    format: false\n",
        .{
            form,
            if (managed) "# werewolf lima: managed\n" else "",
            howl.local_mib,
            try std.json.Stringify.valueAlloc(gpa, disk, .{}),
            try std.json.Stringify.valueAlloc(gpa, try gpa.print("{s}/code.fd", .{at}), .{}),
            try std.json.Stringify.valueAlloc(gpa, config_disk, .{}),
        },
    );
}

test "secured Lima uses measured QEMU and has no host mounts" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const yaml = try template(gpa, "prod", "/tmp/a b/disk.img", "/tmp/a b", "vm-config", false);
    try std.testing.expect(std.mem.find(u8, yaml, "vmType: qemu\n") != null);
    try std.testing.expect(std.mem.find(u8, yaml, "tpm: true\n") != null);
    try std.testing.expect(std.mem.find(u8, yaml, "mounts: []\n") != null);
    try std.testing.expect(std.mem.find(u8, yaml, "location: \"/tmp/a b/disk.img\"") != null);
    try std.testing.expectEqualStrings("qemu-system-aarch64 -drive 'if=pflash,format=raw,unit=1," ++
        "readonly=on,file=/tmp/a,,b c.fd'", try qemuCommand(gpa, "/tmp/a,b c.fd"));
}

/// provisionInstance makes a new machine's VM: for Lima, an instance with
/// its config disk and a TPM Lima keeps; for QEMU, the helper that keeps
/// its TPM. Neither TPM is touched before the guest's first boot.
fn provisionInstance(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    profile: Profile,
    name: []const u8,
    at: []const u8,
    configured: []const u8,
    why: *howl.Why,
) !void {
    const tar_path = try gpa.print("{s}/config.tar", .{at});
    try howl.writePrivate(io, gpa, tar_path, configured, why);
    if (profile.provider != .lima) return;
    const config_disk = try gpa.print("{s}-config", .{name});
    // Match the unprotected path: limactl delete leaves detached config disks.
    _ = try steps.exec(&.{.{ .argv = &.{ "limactl", "disk", "delete", config_disk } }}, .{});
    if (!(try steps.exec(&.{.{ .argv = &.{
        "limactl", "disk", "import", config_disk, tar_path,
    } }}, .{})).ok) return steps.fail("importing the config disk failed");
    const yaml = try gpa.print("{s}/lima.yaml", .{at});
    try howl.writePrivate(io, gpa, yaml, try template(
        gpa,
        profile.spec.form,
        profile.spec.disk_path.?,
        at,
        config_disk,
        profile.managed,
    ), why);
    if (!(try steps.exec(&.{.{ .argv = &.{
        "limactl", "create", "--name", name, "--tty=false", yaml,
    } }}, .{})).ok) return steps.fail("creating the secured Lima instance failed");
    // Lima's swtpm keeps its state here; a new machine's starts empty.
    const instance = try lima.dir(io, gpa, name) orelse return error.MissingLimaInstance;
    try Dir.cwd().createDir(io, try gpa.print("{s}/swtpm", .{instance}), .fromMode(0o700));
}
