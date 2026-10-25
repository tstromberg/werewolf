//! Protected local profiles, enrolled once and updated by their host publisher.
const std = @import("std");
const howl = @import("howl.zig");
const lima = @import("lima.zig");
const native = @import("build.zig");
const enrollment = @import("enrollment.zig");
const secureboot = @import("secureboot.zig");
const progress = @import("progress.zig");
const qemu = @import("qemu.zig");
const bhyve = @import("bhyve.zig");
const booting = @import("boot.zig");
const import_disk = @import("import.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const Profile = struct {
    spec: native.Spec,
    managed: bool,
    provider: howl.Platform = .lima,
    imported: ?[]const u8 = null,
    bootstrap: ?@import("boot-image.zig").Request = null,
    configuration: ?@import("boot-config.zig").Definition = null,
    candidate: ?@import("boot-image.zig").Request = null,
    /// local is the build of the machine's bundle when howl built it here with
    /// the user's own keys (localBundle), which later --build runs repeat;
    /// null for werewolf's downloads.
    local: ?native.Spec = null,
};

/// parseProfile reads a machine's profile.json. A profile is howl's own
/// record, and an older howl wrote fields since dropped (spec.insecure,
/// always false in a protected machine's), so unknown fields are ignored.
fn parseProfile(gpa: Allocator, text: []const u8) !Profile {
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

const Publisher = struct {
    authority: []const u8,
    public: []const u8,
    howl: []const u8,
    arch: []const u8,
    channel: []const u8,
    port: u16,
    certificate: []const u8,
    key: []const u8,
    image_certificate: []const u8,
    token: []const u8,
    refresh_seconds: u32 = 3600,
    service: ?[]const u8 = null,
};

pub const Reuse = enum { miss, running, configure };

fn requireImport(
    definition: @import("boot-config.zig").Definition,
    mode: import_disk.Mode,
    why: *howl.Why,
) !void {
    for (definition.imports) |allowed| {
        if (std.mem.eql(u8, allowed, @tagName(mode))) return;
    }
    return why.refuse("{s} does not support {s} imports", .{ definition.form, @tagName(mode) });
}

test "sync and retained retry require the signed form's explicit support" {
    const t = std.testing;
    const io = t.io;
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var nonce: [8]u8 = undefined;
    try io.randomSecure(&nonce);
    const name = try a.print("ww-import-mode-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
    const dir = try howl.machineDir(a, name);
    defer Dir.cwd().deleteTree(io, dir) catch {};
    try Dir.cwd().createDirPath(io, try a.print("{s}/authority", .{dir}));
    const profile: Profile = .{
        .spec = .{ .form = "database", .arch = .aarch64 },
        .managed = false,
        .configuration = .{
            .form = "database",
            .interface = .{ .files = &.{}, .settings = &.{} },
            .ports = &.{},
            .dhcp = false,
            .ssh = .disabled,
            .lima_managed = false,
            .imports = &.{"init"},
        },
    };
    try Dir.cwd().writeFile(
        io,
        .{
            .sub_path = try a.print("{s}/authority/profile.json", .{dir}),
            .data = try std.json.Stringify.valueAlloc(a, profile, .{}),
        },
    );
    var why: howl.Why = .{};
    var closed = profile.configuration.?;
    closed.imports = &.{};
    try t.expectError(error.Refused, requireImport(closed, .init, &why));
    try t.expectError(error.Refused, requireImport(closed, .sync, &why));
    try t.expectError(
        error.Refused,
        importData(io, a, &.{ name, "nonexistent-source" }, .sync, &why),
    );
    const id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const record: import_disk.Record = .{
        .id = id,
        .digest = id,
        .mode = .sync,
        .sha256 = id,
        .bytes = 1,
    };
    const history = try a.print("{s}/imports/{s}", .{ dir, id });
    try Dir.cwd().createDirPath(io, history);
    try Dir.cwd().writeFile(
        io,
        .{
            .sub_path = try a.print("{s}/record.json", .{history}),
            .data = try std.json.Stringify.valueAlloc(a, record, .{}),
        },
    );
    try t.expectError(error.Refused, importData(io, a, &.{ name, "--retry", id }, .init, &why));
    try t.expectError(
        error.Refused,
        importData(io, a, &.{ name, "--retry", "../../escape" }, .init, &why),
    );
    try t.expectError(
        error.FileNotFound,
        Dir.cwd().access(io, try a.print("{s}/import.json", .{dir}), .{}),
    );
}

/// Stage immutable data for the next cold start. A running VM retains its
/// already-open disk; no guest disk, enrollment, or live service is modified.
pub fn importData(
    io: Io,
    gpa: Allocator,
    args: []const []const u8,
    mode: import_disk.Mode,
    why: *howl.Why,
) !void {
    const retry = args.len == 3 and std.mem.eql(u8, args[1], "--retry") and
        @import("import-data").validId(args[2]);
    if ((args.len != 2 and !retry) or !howl.isMachineName(args[0]))
        return why.refuse(
            "howl {s} NAME DIR; or howl import NAME --retry SNAPSHOT-ID",
            .{if (mode == .sync) "sync" else "import"},
        );
    const name = args[0];
    const dir = try howl.machineDir(gpa, name);
    Dir.cwd().access(io, try gpa.print("{s}/authority/profile.json", .{dir}), .{}) catch
        return why.refuse("{s} is not a protected local machine created by howl", .{name});
    const lock = try Dir.cwd().createFile(
        io,
        try gpa.print("{s}/secure.lock", .{dir}),
        .{ .truncate = false, .permissions = .fromMode(0o600) },
    );
    defer lock.close(io);
    try lock.lock(io, .exclusive);
    const profile = try parseProfile(
        gpa,
        try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/authority/profile.json", .{dir}),
            gpa,
            .limited(64 << 10),
        ),
    );
    const definition = profile.configuration orelse return error.MissingBootConfiguration;
    try @import("boot-config.zig").check(definition, profile.spec.form);
    const retained = if (retry)
        try import_disk.recordAt(
            io,
            gpa,
            try gpa.print("{s}/imports/{s}", .{ dir, args[2] }),
            "record.json",
        )
    else
        null;
    if (retained) |record| if (!std.mem.eql(u8, record.id, args[2])) return error.ImportRecord;
    const operation = if (retained) |record| record.mode else mode;
    try requireImport(definition, operation, why);
    const wanted = @tagName(operation);
    if (profile.provider != .lima and profile.provider != .qemu)
        return why.refuse("imports currently support protected Lima and QEMU machines", .{});
    const record = retained orelse try import_disk.prepare(io, gpa, args[1], dir, mode, why);
    try import_disk.activate(io, gpa, dir, record, true);
    howl.say(
        io,
        "{s}: {s} staged ({s}); selected for the next full stop/start; previous snapshots are " ++
            "retained",
        .{ name, wanted, record.id },
    );
}

/// Host enrollment files cannot establish whether a Lima instance still exists.
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
    const dir = try howl.machineDir(gpa, name);
    stopPublisher(io, gpa, dir);
    try Dir.cwd().deleteTree(io, dir);
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

/// A latest vendor head can authorize updates, never replace an existing enrollment.
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
    if (profile.local != null or profile.imported == null) return why.refuse(
        "{s} was created with local signing keys; this command requests production-signed " ++
            "images.\n" ++
            "Changing signing keys would invalidate its retained A/B rollback slot. " ++
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
    if (!try sameArtifact(io, gpa, incoming.boot_certificate, profile.spec.boot_cert.?) or
        !try sameArtifact(io, gpa, incoming.image_certificate, profile.spec.ipe_cert.?) or
        !std.mem.eql(
            u8,
            incoming.channel,
            profile.spec.ipe_updates.?,
        )) return error.ExistingImageAuthorityMismatch;
    const bootstrap = profile.bootstrap orelse return error.ImportedImageNeedsAuthenticatedResume;
    if (profile.candidate == null or
        !std.mem.eql(u8, profile.candidate.?.directory, incoming.directory))
        try acceptImage(io, gpa, &.{ name, incoming.directory }, why);
    o.boot_image = bootstrap;
}

/// Built is a bundle localBundle built: the request that enrolls or updates
/// a machine with it, as a download's does, and the build that made it.
pub const Built = struct {
    request: @import("boot-image.zig").Request,
    spec: native.Spec,
    stub: []const u8,
};

/// Locally signed update channels belong to a checkout, including when two
/// checkouts use the same machine or form name on the shared host listener.
pub fn localChannel(
    gpa: Allocator,
    directory: []const u8,
    kind: []const u8,
    name: []const u8,
) ![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(directory, &digest, .{});
    return gpa.print("{s}/{x}/{s}", .{ kind, digest, name });
}

test "local update channels isolate like-named machines in separate checkouts" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const first = try localChannel(gpa, "/one", "_local", "werewolf-run");
    const again = try localChannel(gpa, "/one", "_local", "werewolf-run");
    const other = try localChannel(gpa, "/two", "_local", "werewolf-run");
    try std.testing.expectEqualStrings(first, again);
    try std.testing.expect(!std.mem.eql(u8, first, other));
}

/// localBundle builds o's form into a protected bundle as
/// release/build-protected builds werewolf's: Secure Boot, the TPM's
/// firmware authority and IPE, on provider's permit endpoint, but signed
/// with the user's own keys (howl.dataDir). It carries no key of a machine,
/// so a machine on provider enrolls it as it would a download, and follows
/// channel, a path on the host's one publisher: werewolf's channels are its
/// forms' names, so one built here starts with _ (resumeLocal, build). The
/// bundle goes to out, or beside its build in build/bundles.
pub fn localBundle(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    o: howl.Options,
    provider: howl.Platform,
    arch: howl.Arch,
    channel_path: []const u8,
    out: ?[]const u8,
    why: *howl.Why,
) !Built {
    // The form's name is its update channel's path; a form outside forms/
    // is named by its directory.
    const form = std.fs.path.basename(std.mem.trimEnd(u8, o.form, "/"));
    if (!@import("form").isName(form)) return why.refuse(
        "{s}: a protected image's form is named a-z, 0-9 and -, as its update channel is",
        .{o.form},
    );
    const port = try @import("download.zig").permitPort(gpa);
    // Resolve the host socket before a cold kernel build. Every checkout and
    // provider shares its transport identity, independently of VM authorities.
    _ = try sharedTls(io, gpa, steps, port, provider != .bhyve);
    const prerequisites = try @import("prerequisites.zig").resolve(io, gpa, steps, arch, why);
    const boot = try secureboot.signer(io, gpa, steps, try howl.keysDir(
        io,
        gpa,
        try gpa.print("boot/{t}", .{arch}),
        try gpa.print("build/boot/{t}", .{arch}),
    ), false);
    const host = gateway(provider);
    const channel = try gpa.print("https://{s}:{d}/{s}", .{ host, port, channel_path });
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const work = try gpa.print("{s}/build/bundles/{t}-{t}/{s}", .{ cwd, provider, arch, form });
    const image_serial = try serial(io, gpa);
    const spec: native.Spec = .{
        .form = o.form,
        .arch = arch,
        .published = !o.local,
        .app = (try howl.appBuild(io, gpa, o.form, arch, o.app, why)).root,
        .build = work,
        .disk_path = try gpa.print("{s}/disk.raw", .{work}),
        .disk = .{ .args = bundleArgs(provider, arch) },
        .boot_key = boot.key,
        .boot_cert = boot.cert,
        .boot_native = true,
        .tpm_firmware = true,
        .ipe_kernel = prerequisites.kernel.?,
        .ipe_key = prerequisites.key.?,
        .ipe_cert = prerequisites.cert.?,
        .ipe_updates = channel,
        .update_port = port,
        .image_serial = image_serial,
        .permit_host = host,
        .permit_port = port,
    };
    const paths = try build(io, gpa, steps, spec, prerequisites.stub, .{ .disk = true });
    const output = out orelse try gpa.print("{s}/{s}", .{ work, image_serial });
    try @import("boot-image.zig").seal(io, gpa, .{
        .form = form,
        .configuration_form = o.form,
        .arch = @tagName(arch),
        .disk = spec.disk_path.?,
        .slot = try gpa.print("{s}/slot", .{paths.out}),
        .head = try gpa.print("{s}/prebuilt/{t}", .{ paths.out, arch }),
        .output = output,
        .image_key = prerequisites.key.?,
        .image_certificate = prerequisites.cert.?,
        .boot_certificate = boot.cert,
        .channel = channel,
        .permit_host = host,
        .permit_port = port,
    }, why);
    // The bundle holds the disk compressed.
    Dir.cwd().deleteFile(io, spec.disk_path.?) catch {};
    var recorded = spec;
    recorded.image_serial = null;
    return .{
        .request = .{
            .directory = output,
            .boot_certificate = boot.cert,
            .image_certificate = prerequisites.cert.?,
            .channel = channel,
        },
        .spec = recorded,
        .stub = prerequisites.stub,
    };
}

/// admit refuses a protected machine its provider cannot run here, before
/// anything is built for it, and returns the arch it runs.
fn admit(
    io: Io,
    gpa: Allocator,
    o: howl.Options,
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
        if (o.network != .slirp) return why.refuse(
            "protected bhyve TAP update transport is not ready; experimental enrollment " ++
                "requires explicit SLIRP",
            .{},
        );
    } else if (provider != .lima and @import("builtin").os.tag != .linux)
        return why.refuse("secured QEMU currently requires Linux", .{});
    if (provider == .lima and !lima.installed(io, gpa))
        return why.refuse("protected deployment requires Lima on macOS", .{});
    const arch = try howl.localArch(why);
    if (provider == .lima and arch != .aarch64)
        return why.refuse("the secured Lima profile currently requires arm64", .{});
    if (o.import_dir != null and provider == .bhyve)
        return why.refuse("protected bhyve import attachment is not supported", .{});
    return arch;
}

/// gateway is the address a guest on provider reaches its host at, where
/// the host serves its updates and permits.
fn gateway(provider: howl.Platform) []const u8 {
    return if (provider == .lima) "192.168.5.2" else "10.0.2.2";
}

/// bundleArgs are a protected image's kernel arguments on provider, as
/// release/build-protected gives werewolf's: Lima's guest has a fixed
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

/// resumeLocal readies a --build machine's bundle, as resumeDownload does a
/// download's: built here with the user's own keys when the machine is new
/// or its inputs changed, and offered to an existing machine as its next
/// update. o.boot_image is then the bundle the machine enrolls from.
pub fn resumeLocal(
    io: Io,
    gpa: Allocator,
    o: *howl.Options,
    name: []const u8,
    tell: howl.Tell,
    why: *howl.Why,
) !void {
    const arch = try admit(io, gpa, o.*, o.on.?, tell.dev, why);
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
    const existing: ?Profile = if (saved) |text| try parseProfile(gpa, text) else null;
    if (existing) |p| {
        const built = p.local orelse return why.refuse(
            "{s} was not built here with your keys: it runs werewolf's downloads, or an " ++
                "older howl made it. Name another machine, or howl delete {s} first",
            .{ name, name },
        );
        if (p.provider != o.on.? or !std.mem.eql(u8, built.form, o.form)) return why.refuse(
            "{s}: provider or form changes require a new machine name; enrollment is retained",
            .{name},
        );
        if (o.app == null and try unchanged(io, gpa, authority, built)) {
            o.boot_image = p.bootstrap;
            return;
        }
    }
    var options = try tell.step(gpa, dir);
    options.log = try gpa.print("{s}/build.log", .{dir});
    options.first = .{ .name = "Building the protected image", .short = "image" };
    var steps: progress.Steps = try .init(io, gpa, why, options);
    // Each machine follows its own builds, never another's of a like-named form.
    const channel = if (existing) |p| retained: {
        const uri = try std.Uri.parse(
            p.local.?.ipe_updates orelse return error.ExistingImageAuthorityMismatch,
        );
        break :retained std.mem.trimStart(u8, try uri.path.toRawMaybeAlloc(gpa), "/");
    } else try localChannel(gpa, try std.process.currentPathAlloc(io, gpa), "_local", name);
    const b = try localBundle(io, gpa, &steps, o.*, o.on.?, arch, channel, null, why);
    _ = try steps.finish();
    const p = existing orelse {
        o.boot_image = b.request;
        o.built = b;
        return;
    };
    // The machine verifies and installs it as it would werewolf's update.
    try acceptImage(io, gpa, &.{ name, b.request.directory }, why);
    const profile_path = try gpa.print("{s}/profile.json", .{authority});
    var updated = try parseProfile(gpa, try Dir.cwd().readFileAlloc(
        io,
        profile_path,
        gpa,
        .limited(64 << 10),
    ));
    updated.local = b.spec;
    try writeProfile(io, gpa, profile_path, updated);
    try recordBuild(io, gpa, authority, b);
    o.boot_image = p.bootstrap;
}

/// recordBuild keeps what a local machine's next --build run compares its
/// inputs with: the measured stub its bundle took, and their fingerprint.
fn recordBuild(io: Io, gpa: Allocator, authority: []const u8, b: Built) !void {
    const stub = try gpa.print("{s}/linux.efi.stub", .{authority});
    try Dir.cwd().copyFile(b.stub, Dir.cwd(), stub, io, .{});
    const file = try gpa.print("{s}/image-inputs", .{authority});
    const temporary = try gpa.print("{s}.new", .{file});
    Dir.cwd().deleteFile(io, temporary) catch {};
    try enrollment.durable(io, temporary, &try inputs(io, gpa, b.spec, stub));
    try Dir.cwd().rename(temporary, Dir.cwd(), file, io);
}

/// unchanged reports whether a local machine's build has the inputs its
/// bundle was made from. One gone, as make clean takes the IPE kernel, is
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

/// writeProfile replaces a machine's profile whole.
fn writeProfile(io: Io, gpa: Allocator, path: []const u8, profile: Profile) !void {
    const temporary = try gpa.print("{s}.new", .{path});
    Dir.cwd().deleteFile(io, temporary) catch |err| if (err != error.FileNotFound) return err;
    try enrollment.durable(io, temporary, try std.json.Stringify.valueAlloc(gpa, profile, .{}));
    try Dir.cwd().rename(temporary, Dir.cwd(), path, io);
}

/// Explicit pins are supplied by the future download consumer, never by the image itself.
pub fn enrollImage(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    if ((args.len != 7 and args.len != 8) or
        !howl.isMachineName(args[0])) return error.BadArguments;
    const provider = std.meta.stringToEnum(howl.Platform, args[6]) orelse return error.BadArguments;
    if (provider != .lima and provider != .qemu and
        provider != .bhyve) return error.BadSecuredProvider;
    const request: @import("boot-image.zig").Request = .{
        .directory = args[1],
        .boot_certificate = args[2],
        .image_certificate = args[3],
        .channel = args[4],
    };
    const verified = try @import("boot-image.zig").verify(
        io,
        gpa,
        request,
        (howl.hostArch() orelse return error.UnsupportedHostArch),
    );
    @import("boot-config.zig").current = verified.manifest.configuration;
    const directory = try howl.machineDir(gpa, args[0]);
    const existed = if (Dir.cwd().access(io, directory, .{})) |_| true else |_| false;
    if (!existed) {
        try Dir.cwd().createDirPath(io, directory);
        try howl.writePrivate(
            io,
            gpa,
            try gpa.print("{s}/engine", .{directory}),
            @tagName(provider),
            why,
        );
    }
    var out = Io.File.stdout().writerStreaming(io, &.{});
    try create(
        io,
        gpa,
        .{
            .form = verified.manifest.form,
            .on = provider,
            .local = true,
            .boot_image = request,
            .network = if (args.len == 8)
                std.meta.stringToEnum(bhyve.Mode, args[7]) orelse return error.BadArguments
            else
                null,
        },
        args[0],
        try Dir.cwd().readFileAlloc(io, args[5], gpa, .limited(16 << 20)),
        .{
            .verbose = false,
            .command = "howl enroll authenticated image",
            .began = Io.Clock.awake.now(io),
        },
        &out.interface,
        why,
    );
}

const SharedTls = struct { directory: []const u8, key: []const u8, certificate: []const u8 };

/// Approve a vendor-authenticated candidate without rebuilding or changing machine authority.
pub fn acceptImage(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    if (args.len != 2 or !howl.isMachineName(args[0])) return error.BadArguments;
    const machine = try howl.machineDir(gpa, args[0]);
    const guard = try Dir.cwd().openFile(
        io,
        try gpa.print("{s}/secure.lock", .{machine}),
        .{ .mode = .read_write },
    );
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    const authority = try gpa.print("{s}/authority", .{machine});
    var profile = try parseProfile(gpa, try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/profile.json", .{authority}),
        gpa,
        .limited(64 << 10),
    ));
    if (profile.imported == null) return error.ImageIsNotImported;
    const verified = try @import("boot-image.zig").verify(io, gpa, .{
        .directory = args[1],
        .boot_certificate = profile.spec.boot_cert.?,
        .image_certificate = profile.spec.ipe_cert.?,
        .channel = profile.spec.ipe_updates.?,
    }, profile.spec.arch);
    if (!std.mem.eql(u8, verified.manifest.form, profile.spec.form) or
        !std.mem.eql(u8, verified.manifest.permit_host, profile.spec.permit_host.?) or
        verified.manifest.permit_port != profile.spec.permit_port.?)
        return error.WrongPermitProvider;
    for ([_]struct { []const u8, [32]u8 }{
        .{ "release.id", verified.release }, .{ "pcr11", verified.pcr },
    }) |v| {
        const raw = try enrollment.digestFile(
            io,
            gpa,
            try gpa.print("{s}/slot/{s}", .{ args[1], v[0] }),
        );
        if (!std.mem.eql(u8, &raw, &v[1])) return error.WrongBootMeasurement;
    }
    var steps: progress.Steps = try .init(io, gpa, why, .{
        .command = "howl accept authenticated image",
        .log = try gpa.print(
            "{s}/accept.log",
            .{authority},
        ),
        .first = .{ .name = "Accepting vendor-signed image", .short = "image" },
    });
    try publish(
        &steps,
        try gpa.print("{s}/local-publisher", .{authority}),
        try gpa.print("{s}/publisher.json", .{authority}),
        args[1],
    );
    profile.candidate = .{
        .directory = args[1],
        .boot_certificate = profile.spec.boot_cert.?,
        .image_certificate = profile.spec.ipe_cert.?,
        .channel = profile.spec.ipe_updates.?,
    };
    profile.configuration = verified.manifest.configuration;
    try writeProfile(io, gpa, try gpa.print("{s}/profile.json", .{authority}), profile);
    _ = try steps.finish();
}

fn sharedTls(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    port: u16,
    private: bool,
) !SharedTls {
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const root = try gpa.print("{s}/permit-service{s}", .{
        try howl.dataDir(io, gpa), if (private) "/private" else "",
    });
    try Dir.cwd().createDirPath(io, root);
    const helper = @import("files").local_publisher;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(helper, &digest, .{});
    const program = try gpa.print("{s}/publisher-{x}.py", .{ root, digest });
    {
        const helper_guard = try Dir.cwd().createFile(io, try gpa.print(
            "{s}/helper.lock",
            .{root},
        ), .{
            .truncate = false,
            .permissions = .fromMode(0o600),
        });
        defer helper_guard.close(io);
        try helper_guard.lock(io, .exclusive);
        defer helper_guard.unlock(io);
        if (Dir.cwd().readFileAlloc(io, program, gpa, .limited(128 << 10))) |held| {
            if (!std.mem.eql(u8, helper, held)) return error.WrongPublisherHelper;
        } else |err| {
            if (err != error.FileNotFound) return err;
            try enrollment.durable(io, program, helper);
        }
    }
    const dir = try gpa.print("{s}/{d}", .{ root, port });
    const prepare = try std.mem.concat(gpa, []const u8, &.{
        &.{ "python3", program, "prepare-service", dir, cwd },
        if (private) &.{"--private"} else &.{},
    });
    if (!(try steps.exec(&.{.{ .argv = prepare }}, .{})).ok) return error.PermitServiceStateFailed;
    try Dir.cwd().setFilePermissions(io, dir, .fromMode(0o700), .{});
    const guard = try Dir.cwd().createFile(
        io,
        try gpa.print("{s}/service.lock", .{dir}),
        .{ .truncate = false, .permissions = .fromMode(0o600) },
    );
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    const key = try gpa.print("{s}/tls.key", .{dir});
    const cert = try gpa.print("{s}/tls.crt", .{dir});
    const config = try gpa.print("{s}/publisher.json", .{dir});
    const registry = try gpa.print("{s}/registry", .{dir});
    if (Dir.cwd().access(io, config, .{})) |_| {
        for ([_][]const u8{ key, cert, registry }) |file| try Dir.cwd().access(io, file, .{});
    } else |err| {
        if (err != error.FileNotFound) return err;
        for ([_][]const u8{ key, cert }) |file| {
            if (Dir.cwd().access(io, file, .{})) |_|
                return error.PartialPermitServiceIdentity
            else |missing| if (missing != error.FileNotFound) return missing;
        }
        try enrollment.durable(io, key, "");
        if (!(try steps.exec(
            &.{.{ .argv = &.{
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-x509",
                "-sha256",
                "-days",
                "3650",
                "-subj",
                "/CN=werewolf-permits",
                "-addext",
                "subjectAltName=IP:192.168.5.2,IP:10.0.2.2,IP:127.0.0.1",
                "-keyout",
                key,
                "-out",
                cert,
            } }},
            .{},
        )).ok) return error.PermitServiceIdentityFailed;
        try Dir.cwd().createDir(io, registry, .fromMode(0o700));
        var token: [32]u8 = undefined;
        try io.randomSecure(&token);
        try enrollment.durable(io, config, try std.json.Stringify.valueAlloc(gpa, .{
            .authority = dir,
            .registry = registry,
            .port = port,
            .certificate = cert,
            .key = key,
            .program = program,
            .token = &std.fmt.bytesToHex(token, .lower),
            .refresh_seconds = 0,
            .private = private,
        }, .{}));
    }
    return .{ .directory = dir, .key = key, .certificate = cert };
}

const ImportedSetup = struct { profile: Profile, tar: []const u8 };

fn importImage(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    o: howl.Options,
    name: []const u8,
    at: []const u8,
    authority: []const u8,
    request: @import("boot-image.zig").Request,
    tar: []const u8,
    why: *howl.Why,
) !ImportedSetup {
    const verified = try @import("boot-image.zig").verify(
        io,
        gpa,
        request,
        (howl.hostArch() orelse return error.UnsupportedHostArch),
    );
    const m = verified.manifest;
    const expected_host = if (o.on.? == .lima) "192.168.5.2" else "10.0.2.2";
    if (!std.mem.eql(u8, m.permit_host, expected_host)) return error.WrongPermitProvider;
    try Dir.cwd().createDir(io, authority, .fromMode(0o700));
    const code = try gpa.print("{s}/boot.crt", .{at});
    const image_cert = try gpa.print("{s}/image.crt", .{authority});
    try Dir.cwd().copyFile(request.boot_certificate, Dir.cwd(), code, io, .{});
    try Dir.cwd().copyFile(request.image_certificate, Dir.cwd(), image_cert, io, .{});
    const signer = try enrollment.signer(io, gpa, steps, authority, false);
    const owner = try enrollment.certificate(io, gpa, steps, signer, authority);
    try secureboot.enroll(
        io,
        gpa,
        steps,
        at,
        (howl.hostArch() orelse return error.UnsupportedHostArch),
        code,
        owner,
    );
    const tls = try sharedTls(io, gpa, steps, m.permit_port, o.on.? != .bhyve);
    const slot = try gpa.print("{s}/initial-slot", .{authority});
    try Dir.cwd().createDir(io, slot, .fromMode(0o700));
    try enrollment.durable(io, try gpa.print("{s}/release.id", .{slot}), &verified.release);
    try enrollment.durable(io, try gpa.print("{s}/pcr11", .{slot}), &verified.pcr);
    const factory = try enrollment.factory(io, gpa, steps, signer, authority, slot);
    const configured = try withTransport(
        gpa,
        tar,
        try enrollment.transport(
            io,
            gpa,
            steps,
            signer,
            authority,
            tls.certificate,
            if (o.on.? == .lima) .{ 192, 168, 5, 2 } else .{ 10, 0, 2, 2 },
            m.permit_port,
        ),
    );
    const disk = try gpa.print("{s}/disk.img", .{at});
    try @import("boot-image.zig").materialize(io, gpa, steps, request, verified, disk, factory);
    const profile: Profile = .{
        .provider = o.on.?,
        .managed = if (m.configuration) |definition| definition.lima_managed else false,
        .imported = m.image.build,
        .local = if (o.built) |b| b.spec else null,
        .bootstrap = .{
            .directory = request.directory,
            .boot_certificate = code,
            .image_certificate = image_cert,
            .channel = request.channel,
        },
        .configuration = m.configuration,
        .candidate = .{
            .directory = request.directory,
            .boot_certificate = code,
            .image_certificate = image_cert,
            .channel = request.channel,
        },
        .spec = .{
            .form = m.form,
            .arch = (howl.hostArch() orelse return error.UnsupportedHostArch),
            .published = true,
            .disk_path = disk,
            .boot_cert = code,
            .boot_native = true,
            .tpm_firmware = true,
            .tpm_pub = signer.public,
            .boot_state = factory,
            .ipe_cert = image_cert,
            .ipe_updates = m.image.channel,
            .image_serial = m.image.serial,
            .update_ca = tls.certificate,
            .update_port = (try std.Uri.parse(m.image.channel)).port,
            .permit_host = m.permit_host,
            .permit_port = m.permit_port,
        },
    };
    const config = try gpa.print("{s}/publisher.json", .{authority});
    const script = try gpa.print("{s}/local-publisher", .{authority});
    var channel_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(m.image.channel, &channel_digest, .{});
    const channel_hash = std.fmt.bytesToHex(channel_digest, .lower);
    const pubconfig: Publisher = .{
        .authority = authority,
        .public = try gpa.print("{s}/public/{s}", .{ tls.directory, &channel_hash }),
        .howl = try std.process.executablePathAlloc(io, gpa),
        .arch = m.image.arch,
        .channel = m.image.channel,
        .port = m.permit_port,
        .certificate = tls.certificate,
        .key = tls.key,
        .image_certificate = image_cert,
        .token = "unused-registration",
        .refresh_seconds = if (o.production_download) 300 else 0,
        .service = tls.directory,
    };
    try enrollment.durable(io, script, @import("files").local_publisher);
    try enrollment.durable(io, config, try std.json.Stringify.valueAlloc(gpa, pubconfig, .{}));
    // Recheck auxiliary measurements before the existing publisher registers them.
    for ([_]struct {
        []const u8,
        [32]u8,
    }{ .{ "release.id", verified.release }, .{ "pcr11", verified.pcr } }) |v| {
        const bytes = try enrollment.digestFile(
            io,
            gpa,
            try gpa.print("{s}/slot/{s}", .{ request.directory, v[0] }),
        );
        if (!std.mem.eql(u8, &bytes, &v[1])) return error.WrongBootMeasurement;
    }
    try publish(steps, script, config, request.directory);
    try enrollment.durable(
        io,
        try gpa.print("{s}/profile.json", .{authority}),
        try std.json.Stringify.valueAlloc(gpa, profile, .{}),
    );
    if (o.built) |b| try recordBuild(io, gpa, authority, b);
    try provisionInstance(io, gpa, steps, profile, name, at, authority, configured, signer, why);
    return .{ .profile = profile, .tar = configured };
}

/// Health-check the retained publisher, restarting it only when absent.
pub fn startPublisher(io: Io, gpa: Allocator, name: []const u8, why: *howl.Why) !void {
    const authority = try gpa.print("{s}/authority", .{try howl.machineDir(gpa, name)});
    try howl.run(io, why, &.{
        "python3",
        try gpa.print("{s}/local-publisher", .{authority}),
        "start",
        try gpa.print("{s}/publisher.json", .{authority}),
    });
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
            try Dir.cwd().access(io, try gpa.print("{s}/swtpm", .{instance}), .{});
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
    stopPublisher(io, gpa, dir);
    return true;
}

/// Matching inputs keep the image and authority; matching live guests need no work.
pub fn reuse(io: Io, gpa: Allocator, o: howl.Options, name: []const u8, tar: []const u8) !Reuse {
    if (!o.protected() or o.app != null or o.import_dir != null) return .miss;
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
    if (profile.provider != o.on.?) return .miss;
    if (profile.local) |built| {
        if (!o.local or o.app != null or !std.mem.eql(u8, built.form, o.form)) return .miss;
        if (!try unchanged(io, gpa, authority, built)) return .miss;
    } else if (profile.imported != null) {
        if (!std.mem.eql(u8, profile.spec.form, o.form)) return .miss;
        if (o.local or o.boot_image == null) return error.ImportedImageCannotSourceBuild;
    } else return .miss;
    for ([_][]const u8{ "enrolled", "credentials/owner.auth", "credentials/lockout.auth" }) |file|
        try Dir.cwd().access(io, try gpa.print("{s}/{s}", .{ authority, file }), .{});
    Dir.cwd().access(io, try gpa.print("{s}/ready", .{authority}), .{}) catch return .miss;
    const requested = if (profile.spec.permit_host != null)
        try withTransport(
            gpa,
            tar,
            try Dir.cwd().readFileAlloc(
                io,
                try gpa.print("{s}/transport.bundle", .{authority}),
                gpa,
                .limited(@import("tpm").transport.max_bundle),
            ),
        )
    else
        tar;
    const current = try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/config.tar", .{dir}),
        gpa,
        .limited(64 << 20),
    );
    if (!std.mem.eql(u8, requested, current)) return .configure;
    if (profile.provider == .lima) {
        const instance = try lima.dir(io, gpa, name) orelse return .configure;
        try Dir.cwd().access(io, try gpa.print("{s}/swtpm", .{instance}), .{});
        return if (try lima.running(io, gpa, name)) .running else .configure;
    } else if (profile.provider == .qemu) {
        if (qemu.running(io, gpa, dir) == null) return .configure;
        const monitor = try Io.net.UnixAddress.init(try gpa.print("{s}/monitor.sock", .{dir}));
        const connection = monitor.connect(io) catch return .configure;
        connection.close(io);
        return .running;
    } else if (profile.provider == .bhyve) {
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

test "unchanged live runs preserve state; changed inputs, config and lost authority refuse reuse" {
    const t = std.testing;
    const io = t.io;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var env: std.process.Environ.Map = .init(gpa);
    howl.environ = &env;
    defer howl.environ = undefined;
    var nonce: [6]u8 = undefined;
    try io.randomSecure(&nonce);
    const name = try gpa.print("ww-cache-{x}", .{&nonce});
    const dir = try howl.machineDir(gpa, name);
    defer Dir.cwd().deleteTree(io, dir) catch {};
    const authority = try gpa.print("{s}/authority", .{dir});
    try Dir.cwd().createDirPath(io, authority);
    const form = try gpa.print("{s}/form", .{dir});
    try Dir.cwd().createDirPath(io, form);
    try Dir.cwd().writeFile(io, .{
        .sub_path = try gpa.print("{s}/form.yaml", .{form}),
        .data = "base: playground\n",
    });
    const source_dir = try gpa.print("{s}/cmd/cache", .{form});
    try Dir.cwd().createDirPath(io, source_dir);
    const source_file = try gpa.print("{s}/cache.zig", .{source_dir});
    try Dir.cwd().writeFile(io, .{ .sub_path = source_file, .data = "original source" });
    for ([_][]const u8{
        "kernel",
        "ipe.key",
        "ipe.crt",
        "boot.key",
        "boot.crt",
        "authority/linux.efi.stub",
    }) |file|
        try Dir.cwd().writeFile(
            io,
            .{ .sub_path = try gpa.print("{s}/{s}", .{ dir, file }), .data = file },
        );
    const spec: native.Spec = .{
        .form = form,
        .arch = .aarch64,
        .ipe_kernel = try gpa.print("{s}/kernel", .{dir}),
        .ipe_key = try gpa.print("{s}/ipe.key", .{dir}),
        .ipe_cert = try gpa.print("{s}/ipe.crt", .{dir}),
        .boot_key = try gpa.print("{s}/boot.key", .{dir}),
        .boot_cert = try gpa.print("{s}/boot.crt", .{dir}),
    };
    try Dir.cwd().writeFile(io, .{ .sub_path = try gpa.print(
        "{s}/profile.json",
        .{authority},
    ), .data = try std.json.Stringify.valueAlloc(
        gpa,
        Profile{
            .spec = .{ .form = "form", .arch = .aarch64 },
            .managed = false,
            .provider = .qemu,
            .imported = "built-here",
            .local = spec,
        },
        .{},
    ) });
    try Dir.cwd().writeFile(
        io,
        .{ .sub_path = try gpa.print("{s}/secure.lock", .{dir}), .data = "" },
    );
    try Dir.cwd().createDirPath(io, try gpa.print("{s}/credentials", .{authority}));
    for ([_][]const u8{
        "ready",
        "enrolled",
        "credentials/owner.auth",
        "credentials/lockout.auth",
    }) |file|
        try Dir.cwd().writeFile(
            io,
            .{ .sub_path = try gpa.print("{s}/{s}", .{ authority, file }), .data = "original" },
        );
    const stub = try gpa.print("{s}/linux.efi.stub", .{authority});
    try Dir.cwd().writeFile(
        io,
        .{
            .sub_path = try gpa.print("{s}/image-inputs", .{authority}),
            .data = &try inputs(io, gpa, spec, stub),
        },
    );
    const tar = try howl.writeTar(
        gpa,
        &.{.{ .path = "hostname", .data = "cached", .from = "test" }},
    );
    try Dir.cwd().writeFile(
        io,
        .{ .sub_path = try gpa.print("{s}/config.tar", .{dir}), .data = tar },
    );
    try Dir.cwd().writeFile(
        io,
        .{
            .sub_path = try gpa.print("{s}/qemu.pid", .{dir}),
            .data = try gpa.print("{d}\n", .{if (@import("builtin").os.tag == .linux)
                std.os.linux.getpid()
            else
                std.c.getpid()}),
        },
    );
    const monitor = try Io.net.UnixAddress.init(try gpa.print("{s}/monitor.sock", .{dir}));
    var server = monitor.listen(io, .{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit(io);
    const o: howl.Options = .{ .form = form, .on = .qemu, .local = true };
    try t.expectEqual(Reuse.running, try reuse(io, gpa, o, name, tar));
    const saved_profile = try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/profile.json", .{authority}),
        gpa,
        .limited(64 << 10),
    );
    var downloaded = o;
    downloaded.local = false;
    downloaded.form = "playground";
    downloaded.boot_image = .{
        .directory = "unused-vendor-bundle",
        .boot_certificate = "unused-boot-certificate",
        .image_certificate = "unused-image-certificate",
        .channel = "https://10.0.2.2:9443/playground",
    };
    var why: howl.Why = .{};
    try t.expectError(error.Refused, resumeDownload(io, gpa, &downloaded, name, &why));
    try t.expect(std.mem.indexOf(u8, why.text, "retained A/B rollback slot") != null);
    try t.expect(std.mem.indexOf(u8, why.text, "--with playground --on qemu") != null);
    try t.expectEqualStrings(saved_profile, try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/profile.json", .{authority}),
        gpa,
        .limited(64 << 10),
    ));
    try t.expectEqual(Reuse.running, try reuse(io, gpa, o, name, tar));
    try Dir.cwd().writeFile(io, .{ .sub_path = source_file, .data = "edited guest source" });
    try t.expectEqual(Reuse.miss, try reuse(io, gpa, o, name, tar));
    try Dir.cwd().writeFile(io, .{ .sub_path = source_file, .data = "original source" });
    try Dir.cwd().writeFile(io, .{
        .sub_path = try gpa.print("{s}/README.md", .{source_dir}),
        .data = "documentation edit",
    });
    try t.expectEqual(Reuse.running, try reuse(io, gpa, o, name, tar));
    try t.expectEqual(Reuse.configure, try reuse(
        io,
        gpa,
        o,
        name,
        try howl.writeTar(gpa, &.{.{ .path = "hostname", .data = "changed", .from = "test" }}),
    ));
    try Dir.cwd().writeFile(io, .{ .sub_path = spec.ipe_key.?, .data = "changed signer" });
    try t.expectEqual(Reuse.miss, try reuse(io, gpa, o, name, tar));
    try Dir.cwd().writeFile(io, .{ .sub_path = spec.ipe_key.?, .data = "ipe.key" });
    try Dir.cwd().deleteFile(io, try gpa.print("{s}/qemu.pid", .{dir}));
    try t.expectEqual(Reuse.configure, try reuse(io, gpa, o, name, tar));
    // A machine an older howl made from source, its keys in its image, is
    // never reused.
    const profile_path = try gpa.print("{s}/profile.json", .{authority});
    try Dir.cwd().writeFile(io, .{
        .sub_path = profile_path,
        .data = try std.json.Stringify.valueAlloc(
            gpa,
            Profile{ .spec = spec, .managed = false, .provider = .qemu },
            .{},
        ),
    });
    try t.expectEqual(Reuse.miss, try reuse(io, gpa, o, name, tar));
    try Dir.cwd().writeFile(io, .{ .sub_path = profile_path, .data = saved_profile });
    const credential = try gpa.print("{s}/credentials/owner.auth", .{authority});
    try Dir.cwd().deleteFile(io, credential);
    try t.expectError(error.FileNotFound, reuse(io, gpa, o, name, tar));
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
    const arch = try admit(io, gpa, o, provider, tell.dev, why);
    const dir = try howl.machineDir(gpa, name);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const at = try gpa.print("{s}/{s}", .{ cwd, dir });
    const authority = try gpa.print("{s}/authority", .{at});
    const profile_file = try gpa.print("{s}/profile.json", .{authority});
    const config = try gpa.print("{s}/publisher.json", .{authority});
    const script = try gpa.print("{s}/local-publisher", .{authority});
    const kept = if (on_lima) try lima.exists(io, gpa, name) else if (Dir.cwd().access(
        io,
        try gpa.print("{s}/disk.img", .{at}),
        .{},
    )) |_| true else |_| false;
    try Dir.cwd().createDirPath(io, at);
    try Dir.cwd().setFilePermissions(io, at, .fromMode(0o700), .{});
    const guard = try Dir.cwd().createFile(io, try gpa.print("{s}/secure.lock", .{at}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    if (!kept) {
        // An empty directory left by failed firmware preparation contains
        // no enrollment to replace. All nonempty authority remains guarded.
        if (!try emptyAuthority(io, authority)) return why.refuse(
            "{s}: enrollment already exists; inspect the partial creation before recreating",
            .{name},
        );
        Dir.cwd().deleteDir(io, authority) catch |err| if (err != error.FileNotFound) return err;
    }
    if (o.import_dir) |source| {
        const request = o.boot_image orelse return error.MissingBootImage;
        const manifest = try @import("boot-image.zig").admitHead(io, gpa, request, arch);
        try requireImport(
            manifest.configuration orelse return error.MissingBootConfiguration,
            .init,
            why,
        );
        // Validate and snapshot before enrolling a new guest. A repeat may
        // reuse the same input, but never replace an existing import implicitly.
        try import_disk.write(io, gpa, source, at, why);
    }
    _ = try import_disk.existing(io, gpa, at);
    var steps: progress.Steps = try .init(io, gpa, why, try tell.step(gpa, dir));
    Dir.cwd().deleteFile(io, try gpa.print("{s}/ready", .{authority})) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    var profile: Profile = undefined;
    var configured = tar;
    if (kept) {
        const data = Dir.cwd().readFileAlloc(
            io,
            profile_file,
            gpa,
            .limited(64 << 10),
        ) catch return why.refuse(
            "{s} has no secured enrollment: howl delete {s}, then create it again",
            .{ name, name },
        );
        profile = try parseProfile(gpa, data);
        if (profile.imported != null) {
            const requested = o.boot_image orelse
                return error.ImportedImageNeedsAuthenticatedResume;
            const verified = try @import("boot-image.zig").verify(io, gpa, requested, arch);
            if (!std.mem.eql(u8, profile.imported.?, verified.manifest.image.build))
                return error.ImportedImageCannotReplaceEnrollment;
        } else return why.refuse(
            "{s} was made by an older howl, which kept its keys in its image: " ++
                "howl delete {s}, then create it again",
            .{ name, name },
        );

        if (profile.spec.permit_host != null) configured = try withTransport(
            gpa,
            tar,
            try Dir.cwd().readFileAlloc(
                io,
                try gpa.print("{s}/transport.bundle", .{authority}),
                gpa,
                .limited(@import("tpm").transport.max_bundle),
            ),
        );
        if (profile.provider != provider) return why.refuse(
            "the secured provider cannot change",
            .{},
        );
        var changes = o;
        changes.import_dir = null; // The immutable import was checked above.
        try howl.reconfigurable(changes, name, profile.spec.form, provider, why);
        for ([3][]const u8{
            "enrolled",
            "credentials/owner.auth",
            "credentials/lockout.auth",
        }) |file|
            try Dir.cwd().access(io, try gpa.print("{s}/{s}", .{ authority, file }), .{});
        const current = try Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/config.tar", .{at}),
            gpa,
            .limited(64 << 20),
        );
        const changed = !std.mem.eql(u8, current, configured);
        if (on_lima) {
            const existing = try lima.dir(io, gpa, name) orelse return error.MissingLimaInstance;
            try Dir.cwd().access(io, try gpa.print("{s}/swtpm", .{existing}), .{});
            if (changed) _ = try @import("local.zig").reconfigure(
                io,
                gpa,
                name,
                o.form,
                dir,
                configured,
                why,
            );
        } else if (changed) {
            if (provider == .bhyve) {
                try bhyve.stopProtected(io, gpa, name, at);
            } else {
                _ = try qemu.stop(io, gpa, dir);
                try tpmService(io, gpa, at, "stop");
            }
            try howl.writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{at}), configured, why);
        }
    } else if (o.boot_image) |request| {
        const setup = try importImage(io, gpa, &steps, o, name, at, authority, request, tar, why);
        profile = setup.profile;
        configured = setup.tar;
    } else return error.MissingBootImage;
    const helper = @import("files").local_publisher;
    const previous_helper = try Dir.cwd().readFileAlloc(io, script, gpa, .limited(128 << 10));
    if (!std.mem.eql(u8, helper, previous_helper)) {
        const replacement = try gpa.print("{s}.new", .{script});
        Dir.cwd().deleteFile(io, replacement) catch {};
        try enrollment.durable(io, replacement, helper);
        if (!(try steps.exec(
            &.{.{ .argv = &.{ "python3", replacement, "stop", config } }},
            .{},
        )).ok)
            return steps.fail("the previous host publisher did not stop");
        try Dir.cwd().rename(replacement, Dir.cwd(), script, io);
        try publish(
            &steps,
            script,
            config,
            if (profile.candidate) |candidate|
                candidate.directory
            else
                (try native.paths(gpa, profile.spec)).out,
        );
    }
    // Publisher convergence and VM-state checks belong to the launch phase.
    try steps.enter(.{
        .name = if (on_lima)
            "Starting Lima VM and waiting for guest init"
        else if (provider == .bhyve)
            "Starting bhyve and waiting for guest init"
        else
            "Starting QEMU and waiting for guest init",
        .short = "launch",
    });
    if (!(try steps.exec(&.{.{ .argv = &.{ "python3", script, "start", config } }}, .{})).ok)
        return steps.fail("the host image publisher did not start");
    if (!on_lima) {
        if (provider == .bhyve) {
            if (!try bhyve.supervised(io, gpa, at))
                try startBhyve(io, gpa, profile, name, at, &steps, why);
        } else if (qemu.running(io, gpa, at) == null)
            try startQemu(io, gpa, profile, name, at, &steps, why);
        try enrollment.durable(io, try gpa.print("{s}/ready", .{authority}), "verified\n");
        _ = try steps.finish();
        if (tell.milestones) |m| m.done(.{
            .name = try gpa.print("{s} running; total", .{name}),
            .short = "ready",
        });
        try @import("local.zig").protectedReady(io, gpa, name, o.form, provider, false, w, why);
        return;
    }
    if (!try lima.running(io, gpa, name)) {
        const instance = try lima.dir(io, gpa, name) orelse return error.MissingLimaInstance;
        const console = try gpa.print("{s}/serial.log", .{instance});
        const seen = if (Dir.cwd().statFile(io, console, .{})) |stat| stat.size else |_| 0;
        const log = try Dir.cwd().createFile(io, try gpa.print("{s}/start.log", .{at}), .{});
        defer log.close(io);
        var env = try howl.environ.clone(gpa);
        try env.put(
            "QEMU_SYSTEM_AARCH64",
            try permitQemuCommand(io, gpa, profile, at),
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
    try enrollment.durable(io, try gpa.print("{s}/ready", .{authority}), "verified\n");
    _ = try steps.finish();
    if (tell.milestones) |m| m.done(.{
        .name = try gpa.print("{s} running; total", .{name}),
        .short = "ready",
    });
    try @import("local.zig").protectedReady(io, gpa, name, o.form, provider, false, w, why);
}

/// Rebuild with the existing authorities; publishing never changes protected TPM state.
pub fn refresh(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    if (args.len != 1) return error.BadArguments;
    const dir = args[0];
    const authority = try gpa.print("{s}/authority", .{dir});
    const profile_file = try gpa.print("{s}/profile.json", .{authority});
    const profile = try parseProfile(gpa, try Dir.cwd().readFileAlloc(
        io,
        profile_file,
        gpa,
        .limited(64 << 10),
    ));
    // A machine built here takes new builds from howl run or create --build.
    if (profile.local != null or profile.imported == null) return;
    var options: howl.Options = .{ .form = profile.spec.form, .on = profile.provider };
    options.boot_image = try @import("download.zig").latest(
        io,
        gpa,
        profile.spec.form,
        profile.provider,
        profile.spec.arch,
        why,
    );
    try resumeDownload(io, gpa, &options, std.fs.path.basename(dir), why);
}

fn withTransport(gpa: Allocator, tar: []const u8, bundle: []const u8) ![]const u8 {
    if (tar.len > 64 << 20 or bundle.len > @import("tpm").transport.max_bundle)
        return error.ConfigTooBig;
    var entries: std.ArrayList(howl.Entry) = .empty;
    var reader: Io.Reader = .fixed(tar);
    var names: [Dir.max_path_bytes]u8 = undefined;
    var links: [Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&reader, .{
        .file_name_buffer = &names,
        .link_name_buffer = &links,
    });
    while (try it.next()) |entry| {
        if (entry.kind != .file or entry.name.len > 100 or
            reader.seek > tar.len or entry.size > tar.len - reader.seek)
            return error.BadMachineConfig;
        if (std.mem.eql(u8, entry.name, "machine-transport")) continue;
        try entries.append(gpa, .{
            .path = try gpa.dupe(u8, entry.name),
            .data = tar[reader.seek..][0..@intCast(entry.size)],
            .from = "existing config",
        });
    }
    try entries.append(
        gpa,
        .{ .path = "machine-transport", .data = bundle, .from = "host authority" },
    );
    const result = try howl.writeTar(gpa, entries.items);
    if (result.len > 64 << 20) return error.ConfigTooBig;
    return result;
}

test "downloaded live reuse has no vendor keys and retains bootstrap and TPM authority" {
    const t = std.testing;
    const io = t.io;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var nonce: [8]u8 = undefined;
    try io.randomSecure(&nonce);
    const name = try gpa.print("ww-import-{s}", .{std.fmt.bytesToHex(nonce, .lower)});
    const dir = try howl.machineDir(gpa, name);
    defer Dir.cwd().deleteTree(io, dir) catch {};
    const authority = try gpa.print("{s}/authority", .{dir});
    try Dir.cwd().createDirPath(io, try gpa.print("{s}/credentials", .{authority}));
    try Dir.cwd().writeFile(
        io,
        .{ .sub_path = try gpa.print("{s}/secure.lock", .{dir}), .data = "" },
    );
    for ([_][]const u8{
        "ready",
        "enrolled",
        "credentials/owner.auth",
        "credentials/lockout.auth",
    }) |file|
        try Dir.cwd().writeFile(
            io,
            .{ .sub_path = try gpa.print("{s}/{s}", .{ authority, file }), .data = "retained" },
        );
    const bootstrap: @import("boot-image.zig").Request = .{
        .directory = "immutable-" ++
            "A",
        .boot_certificate = "public-boot.crt",
        .image_certificate = "public-image.crt",
        .channel = "https://10.0.2.2:9443/playground",
    };
    const profile: Profile = .{
        .spec = .{
            .form = "playground",
            .arch = .x86_64,
            .published = true,
        },
        .managed = false,
        .provider = .qemu,
        .imported = "A",
        .bootstrap = bootstrap,
        .candidate = bootstrap,
    };
    try Dir.cwd().writeFile(
        io,
        .{
            .sub_path = try gpa.print("{s}/profile.json", .{authority}),
            .data = try std.json.Stringify.valueAlloc(gpa, profile, .{}),
        },
    );
    const tar = try howl.writeTar(gpa, &.{.{ .path = "hostname", .data = name, .from = "test" }});
    try Dir.cwd().writeFile(
        io,
        .{ .sub_path = try gpa.print("{s}/config.tar", .{dir}), .data = tar },
    );
    try Dir.cwd().writeFile(
        io,
        .{
            .sub_path = try gpa.print("{s}/qemu.pid", .{dir}),
            .data = try gpa.print(
                "{d}\n",
                .{
                    if (@import("builtin").os.tag == .linux)
                        std.os.linux.getpid()
                    else
                        std.c.getpid(),
                },
            ),
        },
    );
    const address = try Io.net.UnixAddress.init(try gpa.print("{s}/monitor.sock", .{dir}));
    var listener = address.listen(io, .{}) catch |err| switch (err) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer listener.deinit(io);
    var o: howl.Options = .{
        .form = "playground",
        .on = .qemu,
        .boot_image = bootstrap,
    };
    try t.expectEqual(Reuse.running, try reuse(io, gpa, o, name, tar));
    try t.expectEqual(
        Reuse.configure,
        try reuse(
            io,
            gpa,
            o,
            name,
            try howl.writeTar(gpa, &.{.{ .path = "hostname", .data = "changed", .from = "test" }}),
        ),
    );
    o.local = true;
    try t.expectError(error.ImportedImageCannotSourceBuild, reuse(io, gpa, o, name, tar));
    o.local = false;
    try Dir.cwd().deleteFile(io, try gpa.print("{s}/credentials/owner.auth", .{authority}));
    try t.expectError(error.FileNotFound, reuse(io, gpa, o, name, tar));
    const saved = try Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/profile.json", .{authority}),
        gpa,
        .limited(64 << 10),
    );
    const kept = try parseProfile(gpa, saved);
    try t.expectEqualStrings("immutable-A", kept.bootstrap.?.directory);
    try t.expectEqual(null, kept.spec.ipe_key);
    try t.expectEqual(null, kept.spec.boot_key);
}

test "machine transport config replaces only its reserved public declaration" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const old = try howl.writeTar(gpa, &.{
        .{ .path = "authorized_keys", .data = "retained SSH keys", .from = "test" },
        .{ .path = "machine-transport", .data = "untrusted old declaration", .from = "test" },
    });
    const result = try withTransport(gpa, old, "host-signed declaration");
    var reader: Io.Reader = .fixed(result);
    var names: [Dir.max_path_bytes]u8 = undefined;
    var links: [Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&reader, .{
        .file_name_buffer = &names,
        .link_name_buffer = &links,
    });
    var count: usize = 0;
    while (try it.next()) |entry| {
        const expected = if (count == 0) "retained SSH keys" else "host-signed declaration";
        try t.expectEqualStrings(expected, result[reader.seek..][0..@intCast(entry.size)]);
        count += 1;
    }
    try t.expectEqual(@as(usize, 2), count);
    try t.expectError(error.UnexpectedEndOfStream, withTransport(gpa, old[0..20], "signed"));
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
    hash.update(&try programInputs(io, gpa, spec.form));
    for ([7][]const u8{
        spec.ipe_kernel.?,                            spec.ipe_cert.?,
        spec.ipe_key.?,                               spec.boot_cert.?,
        spec.boot_key.?,                              stub,
        try std.process.executablePathAlloc(io, gpa),
    }) |file| hash.update((try @import("prebuilt").hashFile(io, gpa, file)).sha256);
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

/// Bind checkout sources used by the image, even when howl itself was not rebuilt.
fn programInputs(io: Io, gpa: Allocator, form: []const u8) ![32]u8 {
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
    const chain = try @import("form").chain(io, gpa, Dir.cwd(), form, &bad);
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

fn publish(steps: *progress.Steps, script: []const u8, config: []const u8, out: []const u8) !void {
    if (!(try steps.exec(&.{.{ .argv = &.{ "python3", script, "publish", config, out } }}, .{})).ok)
        return steps.fail("publishing the local signed image failed");
}

fn serial(io: Io, gpa: Allocator) ![]const u8 {
    const seconds = @divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s);
    return gpa.print("{f}", .{@import("update-policy").Serial{ .secs = @intCast(seconds) }});
}

pub fn stopPublisher(io: Io, gpa: Allocator, dir: []const u8) void {
    const script = gpa.print("{s}/authority/local-publisher", .{dir}) catch return;
    const config = gpa.print("{s}/authority/publisher.json", .{dir}) catch return;
    _ = std.process.run(gpa, io, .{ .argv = &.{ "python3", script, "stop", config } }) catch {};
}

fn sockets(gpa: Allocator, at: []const u8) ![]const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(at, &hash, .{});
    return gpa.print("/tmp/ww-tpm-{x}", .{hash[0..12]});
}

fn tpmService(io: Io, gpa: Allocator, at: []const u8, operation: []const u8) !void {
    const script = try gpa.print("{s}/authority/local-tpm", .{at});
    const helper = @import("files").local_tpm;
    const previous = try Dir.cwd().readFileAlloc(io, script, gpa, .limited(128 << 10));
    if (!std.mem.eql(u8, helper, previous)) {
        var why: howl.Why = .{};
        try howl.writePrivate(io, gpa, script, helper, &why);
    }
    const result = try std.process.run(gpa, io, .{ .argv = &.{
        "python3",
        script,
        operation,
        try gpa.print("{s}/authority", .{at}),
        try sockets(gpa, at),
        if (Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/authority/profile.json", .{at}),
            gpa,
            .limited(64 << 10),
        )) |data|
            @tagName((try parseProfile(gpa, data)).provider)
        else |err| if (err == error.FileNotFound) "qemu" else return err,
    } });
    if (result.term != .exited or result.term.exited != 0) return error.TpmServiceFailed;
}

test "TPM service upgrades an existing helper without creating enrolled state" {
    const t = std.testing;
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(t.io, "authority", .default_dir);
    try tmp.dir.writeFile(t.io, .{
        .sub_path = "authority/local-tpm",
        .data = "raise RuntimeError('obsolete helper')\n",
    });
    const path = try tmp.dir.realPathFileAlloc(t.io, ".", gpa);
    try tpmService(t.io, gpa, path, "stop");
    try t.expectEqualStrings(
        @import("files").local_tpm,
        try tmp.dir.readFileAlloc(t.io, "authority/local-tpm", gpa, .limited(128 << 10)),
    );
    try t.expectError(error.FileNotFound, tmp.dir.access(t.io, "authority/swtpm", .{}));
}

pub fn stopTpm(io: Io, gpa: Allocator, dir: []const u8) !void {
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const at = try gpa.print("{s}/{s}", .{ cwd, dir });
    return stopTpmAt(io, gpa, at);
}

pub fn stopTpmAt(io: Io, gpa: Allocator, at: []const u8) !void {
    Dir.cwd().access(
        io,
        try gpa.print("{s}/authority/local-tpm", .{at}),
        .{},
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    const absolute = if (std.fs.path.isAbsolute(at))
        at
    else
        try gpa.print("{s}/{s}", .{ try std.process.currentPathAlloc(io, gpa), at });
    try tpmService(io, gpa, absolute, "stop");
}

pub fn restartTpmAt(io: Io, gpa: Allocator, at: []const u8) !void {
    try tpmService(io, gpa, at, "stop");
    try tpmService(io, gpa, at, "start");
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
    const fwds = try bhyve.forwards(gpa, name, definition.ports);
    var ssh: u16 = 0;
    for (fwds) |f| if (f.guest == 22) {
        ssh = f.host;
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
    const args = try bhyve.command(gpa, name, try gpa.print(
        "{s}/disk.img",
        .{at},
    ), try gpa.print("{s}/config.tar", .{at}), .{ .slirp = fwds }, null, .{
        .code = try gpa.print("{s}/code.fd", .{at}),
        .vars = try gpa.print("{s}/vars.fd", .{at}),
        .tpm_socket = try gpa.print("{s}/data.sock", .{try sockets(gpa, at)}),
    });
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
    errdefer bhyve.stopProtected(io, gpa, name, at) catch {};
    var spin: progress.Spinner = .init(io);
    defer spin.clear();
    const boot = try booting.watch(io, gpa, log, 0, null, 0, &spin);
    if (!boot.up) return why.refuse(
        "{s}: protected bhyve boot did not finish; see {s}",
        .{ name, log },
    );
    if (ssh != 0 and !booting.awaitSsh(io, "127.0.0.1", ssh, &spin))
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
    try tpmService(io, gpa, at, "stop");
    try tpmService(io, gpa, at, "start");
    errdefer tpmService(io, gpa, at, "stop") catch {};
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
        .tpm_socket = try gpa.print("{s}/tpm.sock", .{try sockets(gpa, at)}),
        .owner = true,
        .import_disk = try import_disk.existing(io, gpa, at),
    }, qemu.accel(io));
    if (!(try steps.exec(
        &.{.{ .argv = try permitForwarding(gpa, profile, at, args) }},
        .{},
    )).ok) return steps.fail("secured QEMU did not start");
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

fn permitForwarding(
    gpa: Allocator,
    profile: Profile,
    at: []const u8,
    command: []const []const u8,
) ![]const []const u8 {
    const host = profile.spec.permit_host orelse return command;
    return std.mem.concat(gpa, []const u8, &.{ &.{
        "python3",
        try gpa.print("{s}/authority/local-publisher", .{at}),
        "qemu",
        try gpa.print("{s}/authority/publisher.json", .{at}),
        host,
        try gpa.print("{d}", .{profile.spec.permit_port.?}),
    }, command });
}

fn permitQemuCommand(io: Io, gpa: Allocator, profile: Profile, at: []const u8) ![]const u8 {
    const vars = try std.mem.replaceOwned(u8, gpa, try gpa.print("{s}/vars.fd", .{at}), ",", ",,");
    const base: []const []const u8 = &.{
        "qemu-system-aarch64",                                                      "-drive",
        try gpa.print("if=pflash,format=raw,unit=1,readonly=on,file={s}", .{vars}),
    };
    const args = try permitForwarding(gpa, profile, at, base);
    // Append after Lima's own disks so imports never renumber its boot disk.
    const trailing = if (try import_disk.existing(io, gpa, at)) |disk| blk: {
        const drive = try gpa.print(
            "file={s},format=raw,if=virtio,readonly=on",
            .{try std.mem.replaceOwned(u8, gpa, disk, ",", ",,")},
        );
        break :blk try gpa.print(
            " -drive '{s}'",
            .{try std.mem.replaceOwned(u8, gpa, drive, "'", "'\\''")},
        );
    } else "";
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
        try gpa.print("#!/bin/sh\nexec {s} \"$@\"{s}\n", .{ command.items, trailing }),
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

fn provisionInstance(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    profile: Profile,
    name: []const u8,
    at: []const u8,
    authority: []const u8,
    configured: []const u8,
    permit_signer: enrollment.Signer,
    why: *howl.Why,
) !void {
    const tar_path = try gpa.print("{s}/config.tar", .{at});
    try howl.writePrivate(io, gpa, tar_path, configured, why);
    if (profile.provider == .lima) {
        const config_disk = try gpa.print("{s}-config", .{name});
        // Match the unprotected path: limactl delete leaves detached config disks.
        _ = try steps.exec(&.{.{ .argv = &.{ "limactl", "disk", "delete", config_disk } }}, .{});
        if (!(try steps.exec(&.{.{ .argv = &.{
            "limactl", "disk", "import", config_disk, tar_path,
        } }}, .{})).ok) return steps.fail("importing the config disk failed");
        const yaml = try gpa.print("{s}/lima.yaml", .{at});
        try howl.writePrivate(
            io,
            gpa,
            yaml,
            try template(
                gpa,
                profile.spec.form,
                profile.spec.disk_path.?,
                at,
                config_disk,
                profile.managed,
            ),
            why,
        );
        if (!(try steps.exec(&.{.{ .argv = &.{
            "limactl", "create", "--name", name, "--tty=false", yaml,
        } }}, .{})).ok) return steps.fail("creating the secured Lima instance failed");
        const instance = try lima.dir(io, gpa, name) orelse return error.MissingLimaInstance;
        try enrollment.provision(
            io,
            gpa,
            permit_signer,
            authority,
            try gpa.print("{s}/swtpm", .{instance}),
        );
    } else {
        try enrollment.durable(
            io,
            try gpa.print("{s}/local-tpm", .{authority}),
            @import("files").local_tpm,
        );
        try enrollment.provision(
            io,
            gpa,
            permit_signer,
            authority,
            try gpa.print("{s}/swtpm", .{authority}),
        );
    }
}
