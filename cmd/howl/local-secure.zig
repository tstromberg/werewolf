//! Protected local profiles, enrolled once and updated by their host publisher.
const std = @import("std");
const howl = @import("howl.zig");
const lima = @import("lima.zig");
const native = @import("build.zig");
const enrollment = @import("enrollment.zig");
const secureboot = @import("secureboot.zig");
const progress = @import("progress.zig");
const qemu = @import("qemu.zig");
const booting = @import("boot.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const Profile = struct { spec: native.Spec, managed: bool, provider: howl.Platform = .lima };
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
};

pub const Reuse = enum { miss, running, configure };

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
    const profile = try std.json.parseFromSliceLeaky(Profile, gpa, saved, .{});
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
        else => return error.BadSecuredProvider,
    }
    stopPublisher(io, gpa, dir);
    return true;
}

/// Matching inputs keep the image and authority; matching live guests need no work.
pub fn reuse(io: Io, gpa: Allocator, o: howl.Options, name: []const u8, tar: []const u8) !Reuse {
    if (!o.secure or !o.local or o.app != null or o.import_dir != null) return .miss;
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
    const profile = try std.json.parseFromSliceLeaky(Profile, gpa, saved, .{});
    if (profile.provider != o.on.? or profile.spec.published or
        !std.mem.eql(u8, profile.spec.form, o.form)) return .miss;
    for ([_][]const u8{ "enrolled", "credentials/owner.auth", "credentials/lockout.auth" }) |file|
        try Dir.cwd().access(io, try gpa.print("{s}/{s}", .{ authority, file }), .{});
    Dir.cwd().access(io, try gpa.print("{s}/ready", .{authority}), .{}) catch return .miss;
    if (!try callerMatches(io, gpa, profile.spec)) return .miss;
    const expected = try inputs(
        io,
        gpa,
        profile.spec,
        try gpa.print("{s}/linux.efi.stub", .{authority}),
    );
    const previous = try Dir.cwd().readFileAlloc(io, try gpa.print(
        "{s}/image-inputs",
        .{authority},
    ), gpa, .limited(65));
    if (!std.mem.eql(u8, &expected, previous)) return .miss;
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
    }
    return .miss;
}

fn callerMatches(io: Io, gpa: Allocator, spec: native.Spec) !bool {
    if (howl.environ.get("WEREWOLF_BOOT_CRT") != null and
        howl.environ.get("WEREWOLF_BOOT_KEY") == null) return false;
    if (howl.environ.get("WEREWOLF_BOOT_KEY")) |key| {
        if (!try sameCredential(io, gpa, key, spec.boot_key.?)) return false;
        if (!try sameCredential(io, gpa, howl.environ.get(
            "WEREWOLF_BOOT_CRT",
        ) orelse "release/boot.crt", spec.boot_cert.?)) return false;
    }
    const fields = [_][]const u8{ "WEREWOLF_IPE_KERNEL", "WEREWOLF_IPE_KEY", "WEREWOLF_IPE_CRT" };
    const previous = [_][]const u8{ spec.ipe_kernel.?, spec.ipe_key.?, spec.ipe_cert.? };
    const supplied = try @import("prerequisites.zig").supplied(
        howl.environ.get(fields[0]),
        howl.environ.get(fields[1]),
        howl.environ.get(fields[2]),
    );
    if (supplied) for (fields, previous) |field, file| {
        if (!try sameArtifact(io, gpa, howl.environ.get(field).?, file)) return false;
    };
    if (howl.environ.get("UKI_STUB")) |stub| {
        const a = try @import("prebuilt").hashFile(io, gpa, stub);
        const machine = std.fs.path.dirname(spec.boot_key.?).?;
        const b = try @import("prebuilt").hashFile(
            io,
            gpa,
            try gpa.print("{s}/authority/linux.efi.stub", .{machine}),
        );
        if (!std.mem.eql(u8, a.sha256, b.sha256)) return false;
    }
    return true;
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

fn sameCredential(io: Io, gpa: Allocator, given: []const u8, held: []const u8) !bool {
    const a = try Dir.cwd().readFileAlloc(io, given, gpa, .limited(32 << 10));
    defer std.crypto.secureZero(u8, a);
    const b = try Dir.cwd().readFileAlloc(io, held, gpa, .limited(32 << 10));
    defer std.crypto.secureZero(u8, b);
    return std.mem.eql(u8, a, b);
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
        Profile{ .spec = spec, .managed = false, .provider = .qemu },
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
    var server = try monitor.listen(io, .{});
    defer server.deinit(io);
    const o: howl.Options = .{ .form = form, .on = .qemu, .local = true, .secure = true };
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
    if (tell.dev) return why.refuse("the secured local profile refuses --dev", .{});
    if (!on_lima and @import("builtin").os.tag != .linux)
        return why.refuse("secured QEMU currently requires Linux", .{});
    if (on_lima and
        !lima.installed(io, gpa)) return why.refuse("--secure requires Lima on macOS", .{});
    const arch = try howl.localArch(why);
    if (on_lima and arch != .aarch64) return why.refuse(
        "the secured Lima profile currently requires arm64",
        .{},
    );
    if (o.import_dir != null) return why.refuse("--secure does not yet support --import", .{});
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
            "{s} has no secured enrollment; recreate it explicitly before using --secure",
            .{name},
        );
        profile = try std.json.parseFromSliceLeaky(Profile, gpa, data, .{});
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
        try howl.reconfigurable(o, name, profile.spec.form, provider, why);
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
            _ = try qemu.stop(io, gpa, dir);
            try tpmService(io, gpa, at, "stop");
            try howl.writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{at}), configured, why);
        }
    } else {
        const prerequisites = try @import("prerequisites.zig").resolve(io, gpa, &steps, arch, why);
        const boot = try ownedBoot(io, gpa, &steps, at, arch, o.local);
        try Dir.cwd().createDir(io, authority, .fromMode(0o700));
        const permit_signer = try enrollment.signer(io, gpa, &steps, authority, false);
        const owner_cert = try enrollment.certificate(io, gpa, &steps, permit_signer, authority);
        try secureboot.enroll(io, gpa, &steps, at, arch, boot.cert, owner_cert);
        const port = try qemu.freePort(io, 8443);
        const tls_key = try gpa.print("{s}/tls.key", .{authority});
        const tls_cert = try gpa.print("{s}/tls.crt", .{authority});
        try enrollment.durable(io, tls_key, "");
        if (!(try steps.exec(&.{.{ .argv = &.{
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
            "/CN=werewolf-local-images",
            "-addext",
            if (on_lima)
                "subjectAltName=IP:192.168.5.2,IP:127.0.0.1"
            else
                "subjectAltName=IP:10.0.2.2,IP:127.0.0.1",
            "-keyout",
            tls_key,
            "-out",
            tls_cert,
        } }}, .{})).ok) return steps.fail("creating the local HTTPS authority failed");
        const app = try howl.appBuild(io, gpa, o.form, arch, o.app, why);
        profile = .{ .provider = provider, .managed = on_lima and
            try @import("local.zig").limaManages(
                io,
                gpa,
                o.form,
                why,
            ), .spec = .{
            .form = o.form,
            .arch = arch,
            .published = !o.local,
            .app = app.root,
            .build = try gpa.print("{s}/images", .{at}),
            .disk_path = try gpa.print("{s}/disk.img", .{at}),
            .boot_key = boot.key,
            .boot_cert = boot.cert,
            .boot_native = true,
            .tpm_pub = permit_signer.public,
            .tpm_firmware = true,
            .ipe_kernel = prerequisites.kernel.?,
            .ipe_key = prerequisites.key.?,
            .ipe_cert = prerequisites.cert.?,
            .ipe_updates = try gpa.print(
                "https://{s}:{d}",
                .{ if (on_lima) "192.168.5.2" else "10.0.2.2", port },
            ),
            .image_serial = try serial(io, gpa),
            .update_ca = tls_cert,
            .update_port = port,
            .permit_host = if (on_lima) "192.168.5.2" else "10.0.2.2",
            .permit_port = port,
            .disk = .{ .args = if (on_lima) &.{
                "console=ttyAMA0",              "werewolf.ip=" ++ lima.user_ip,
                "werewolf.gw=" ++ lima.user_gw, "werewolf.dns=192.168.5.3",
            } else secureArgs(arch) },
        } };
        const stub = try gpa.print("{s}/linux.efi.stub", .{authority});
        try Dir.cwd().copyFile(prerequisites.stub, Dir.cwd(), stub, io, .{});
        // Every refresh uses the same measured stub, even after the caller's environment changes.
        const pubconfig: Publisher = .{
            .authority = authority,
            .public = try gpa.print("{s}/public", .{authority}),
            .howl = try std.process.executablePathAlloc(io, gpa),
            .arch = @tagName(arch),
            .channel = profile.spec.ipe_updates.?,
            .port = port,
            .certificate = tls_cert,
            .key = tls_key,
            .image_certificate = profile.spec.ipe_cert.?,
            .token = blk: {
                var token: [32]u8 = undefined;
                try io.randomSecure(&token);
                break :blk try gpa.dupe(u8, &std.fmt.bytesToHex(token, .lower));
            },
        };
        try enrollment.durable(io, script, @import("files").local_publisher);
        try enrollment.durable(io, config, try std.json.Stringify.valueAlloc(gpa, pubconfig, .{}));
        const paths = try build(io, gpa, &steps, profile.spec, stub, .{ .prebuilt = true });
        profile.spec.boot_state = try enrollment.factory(
            io,
            gpa,
            &steps,
            permit_signer,
            authority,
            try gpa.print("{s}/slot", .{paths.out}),
        );
        configured = try withTransport(gpa, tar, try enrollment.transport(
            io,
            gpa,
            &steps,
            permit_signer,
            authority,
            tls_cert,
            if (on_lima) .{ 192, 168, 5, 2 } else .{ 10, 0, 2, 2 },
            port,
        ));
        _ = try build(io, gpa, &steps, profile.spec, stub, .{ .disk = true });
        try enrollment.durable(
            io,
            profile_file,
            try std.json.Stringify.valueAlloc(gpa, profile, .{}),
        );
        try publish(&steps, script, config, paths.out);
        try enrollment.durable(
            io,
            try gpa.print("{s}/image-inputs", .{authority}),
            &try inputs(io, gpa, profile.spec, stub),
        );
        const tar_path = try gpa.print("{s}/config.tar", .{at});
        try howl.writePrivate(io, gpa, tar_path, configured, why);
        if (on_lima) {
            const config_disk = try gpa.print("{s}-config", .{name});
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
                    o.form,
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
        try publish(&steps, script, config, (try native.paths(gpa, profile.spec)).out);
    }
    if (!(try steps.exec(&.{.{ .argv = &.{ "python3", script, "start", config } }}, .{})).ok)
        return steps.fail("the host image publisher did not start");
    if (!on_lima) {
        try startQemu(io, gpa, profile.spec, name, at, &steps, why);
        try enrollment.durable(io, try gpa.print("{s}/ready", .{authority}), "verified\n");
        _ = try steps.finish();
        try w.print("{s}\t127.0.0.1:{s}\t{s}\tSecure Boot, IPE, TPM A/B\n", .{
            name, qemu.record(io, gpa, dir, "ssh") orelse "0", o.form,
        });
        return;
    }
    _ = try steps.finish();
    if (!try lima.running(io, gpa, name)) {
        const instance = try lima.dir(io, gpa, name) orelse return error.MissingLimaInstance;
        const console = try gpa.print("{s}/serial.log", .{instance});
        const seen = if (Dir.cwd().statFile(io, console, .{})) |stat| stat.size else |_| 0;
        const log = try Dir.cwd().createFile(io, try gpa.print("{s}/start.log", .{at}), .{});
        defer log.close(io);
        var env = try howl.environ.clone(gpa);
        try env.put(
            "QEMU_SYSTEM_AARCH64",
            try qemuCommand(gpa, try gpa.print("{s}/vars.fd", .{at})),
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
        const boot = try booting.watch(io, gpa, console, seen, null, 0, &spin);
        spin.clear();
        if (!boot.up) return why.refuse(
            "{s}: protected boot did not finish; see {s}",
            .{ name, console },
        );
    }
    try enrollment.durable(io, try gpa.print("{s}/ready", .{authority}), "verified\n");
    try w.print("{s}\t127.0.0.1:{s}\t{s}\tSecure Boot, IPE, TPM A/B\n", .{
        name, lima.sshPort(io, gpa, name) orelse "0", o.form,
    });
}

/// Rebuild with the existing authorities; publishing never changes protected TPM state.
pub fn refresh(io: Io, gpa: Allocator, args: []const []const u8, why: *howl.Why) !void {
    if (args.len != 1) return error.BadArguments;
    const dir = args[0];
    const authority = try gpa.print("{s}/authority", .{dir});
    const profile_file = try gpa.print("{s}/profile.json", .{authority});
    var profile = try std.json.parseFromSliceLeaky(Profile, gpa, try Dir.cwd().readFileAlloc(
        io,
        profile_file,
        gpa,
        .limited(64 << 10),
    ), .{});
    const guard = try Dir.cwd().openFile(
        io,
        try gpa.print("{s}/secure.lock", .{dir}),
        .{ .mode = .read_write },
    );
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    var steps: progress.Steps = try .init(io, gpa, why, .{
        .command = "howl local image refresh",
        .log = try gpa.print(
            "{s}/refresh.log",
            .{authority},
        ),
        .first = .{ .name = "Refreshing signed local images", .short = "images" },
    });
    const stub = try gpa.print("{s}/linux.efi.stub", .{authority});
    const fingerprint = try inputs(io, gpa, profile.spec, stub);
    const input_file = try gpa.print("{s}/image-inputs", .{authority});
    const previous = Dir.cwd().readFileAlloc(io, input_file, gpa, .limited(65)) catch "";
    if (std.mem.eql(u8, &fingerprint, previous)) {
        _ = try steps.finish();
        return;
    }
    profile.spec.image_serial = try serial(io, gpa);
    profile.spec.boot_state = null;
    const paths = try build(io, gpa, &steps, profile.spec, stub, .{ .prebuilt = true });
    try publish(
        &steps,
        try gpa.print("{s}/local-publisher", .{authority}),
        try gpa.print("{s}/publisher.json", .{authority}),
        paths.out,
    );
    const temporary = try gpa.print("{s}.new", .{input_file});
    Dir.cwd().deleteFile(io, temporary) catch {};
    try enrollment.durable(io, temporary, &fingerprint);
    try Dir.cwd().rename(temporary, Dir.cwd(), input_file, io);
    _ = try steps.finish();
}

fn ownedBoot(
    io: Io,
    gpa: Allocator,
    steps: *progress.Steps,
    at: []const u8,
    arch: howl.Arch,
    local: bool,
) !secureboot.Keys {
    try steps.enter(.{ .name = "Preparing enrolled Secure Boot firmware", .short = "firmware" });
    // A source build belongs to the caller's signing authority. Published
    // deployments must not silently substitute an unrelated local signer.
    if (local) return secureboot.prepare(io, gpa, steps, at, arch, false);
    var env = try howl.environ.clone(gpa);
    _ = env.swapRemove("WEREWOLF_BOOT_KEY");
    _ = env.swapRemove("WEREWOLF_BOOT_CRT");
    const previous = howl.environ;
    howl.environ = &env;
    defer howl.environ = previous;
    return secureboot.prepare(io, gpa, steps, at, arch, false);
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
    for ([_][]const u8{ "init", "bite-cleanup" } ++ native.every_program) |name|
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
        hash.update(&try @import("lock.zig").tree(
            io,
            gpa,
            Dir.cwd(),
            try gpa.print("{s}/melange", .{part.dir}),
        ));
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

fn secureArgs(arch: howl.Arch) []const []const u8 {
    const network = [_][]const u8{
        "werewolf.ip=10.0.2.15/24", "werewolf.gw=10.0.2.2", "werewolf.dns=10.0.2.3",
    };
    return switch (arch) {
        .aarch64 => &([_][]const u8{"console=ttyAMA0"} ++ network),
        .x86_64 => &([_][]const u8{"console=ttyS0"} ++ network),
    };
}

fn sockets(gpa: Allocator, at: []const u8) ![]const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(at, &hash, .{});
    return gpa.print("/tmp/ww-tpm-{x}", .{hash[0..12]});
}

fn tpmService(io: Io, gpa: Allocator, at: []const u8, operation: []const u8) !void {
    const result = try std.process.run(gpa, io, .{ .argv = &.{
        "python3",
        try gpa.print(
            "{s}/authority/local-tpm",
            .{at},
        ),
        operation,
        try gpa.print("{s}/authority", .{at}),
        try sockets(gpa, at),
    } });
    if (result.term != .exited or result.term.exited != 0) return error.TpmServiceFailed;
}

pub fn stopTpm(io: Io, gpa: Allocator, dir: []const u8) !void {
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const at = try gpa.print("{s}/{s}", .{ cwd, dir });
    Dir.cwd().access(
        io,
        try gpa.print("{s}/authority/local-tpm", .{at}),
        .{},
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    try tpmService(io, gpa, at, "stop");
}

fn startQemu(
    io: Io,
    gpa: Allocator,
    spec: native.Spec,
    name: []const u8,
    at: []const u8,
    steps: *progress.Steps,
    why: *howl.Why,
) !void {
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
    var guest_web: u16 = 80;
    for (try howl.listens(io, gpa, spec.form, why)) |port| if (port != 22) {
        guest_web = port;
    };
    for ([_][]const u8{ "console.log", "console.sock", "monitor.sock" }) |file|
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
    }, qemu.accel(io));
    if (!(try steps.exec(
        &.{.{ .argv = args }},
        .{},
    )).ok) return steps.fail("secured QEMU did not start");
    errdefer {
        _ = qemu.stop(io, gpa, at) catch false;
    }
    var spin: progress.Spinner = .init(io);
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
}

pub fn qemuCommand(gpa: Allocator, vars: []const u8) ![]const u8 {
    const escaped = try std.mem.replaceOwned(u8, gpa, vars, ",", ",,");
    const argument = try gpa.print("if=pflash,format=raw,unit=1,readonly=on,file={s}", .{escaped});
    const quoted = try std.mem.replaceOwned(u8, gpa, argument, "'", "'\\''");
    return gpa.print("qemu-system-aarch64 -drive '{s}'", .{quoted});
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
