//! Lima's protected local profile, enrolled once and updated by its host publisher.
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

const Profile = struct { spec: native.Spec, managed: bool };
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
    if (tell.dev) return why.refuse("the secured Lima profile refuses --dev", .{});
    if (!lima.installed(io, gpa)) return why.refuse("--secure requires Lima on macOS", .{});
    const arch = try howl.localArch(why);
    if (arch != .aarch64) return why.refuse(
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
    const kept = try lima.exists(io, gpa, name);
    if (!kept) {
        // Never re-enroll a partial creation or an instance deleted outside howl.
        if (Dir.cwd().access(io, authority, .{})) |_| return why.refuse(
            "{s}: enrollment already exists; inspect the partial creation before recreating",
            .{
                name,
            },
        ) else |err| if (err != error.FileNotFound) return err;
        for ([4][]const u8{
            "WEREWOLF_IPE_KERNEL", "WEREWOLF_IPE_KEY", "WEREWOLF_IPE_CRT", "UKI_STUB",
        }) |variable| if (howl.environ.get(variable) == null) return why.refuse(
            "--secure requires {s}; use the pinned IPE kernel and TPM-enabled EFI stub",
            .{
                variable,
            },
        );
    }
    try Dir.cwd().createDirPath(io, at);
    try Dir.cwd().setFilePermissions(io, at, .fromMode(0o700), .{});
    const guard = try Dir.cwd().createFile(io, try gpa.print("{s}/secure.lock", .{at}), .{
        .truncate = false,
        .permissions = .fromMode(0o600),
    });
    defer guard.close(io);
    try guard.lock(io, .exclusive);
    defer guard.unlock(io);
    var steps: progress.Steps = try .init(io, gpa, why, try tell.step(gpa, dir));
    var profile: Profile = undefined;
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
        try howl.reconfigurable(o, name, profile.spec.form, .lima, why);
        for ([3][]const u8{
            "enrolled",
            "credentials/owner.auth",
            "credentials/lockout.auth",
        }) |file|
            try Dir.cwd().access(io, try gpa.print("{s}/{s}", .{ authority, file }), .{});
        const existing = try lima.dir(io, gpa, name) orelse return error.MissingLimaInstance;
        try Dir.cwd().access(io, try gpa.print("{s}/swtpm", .{existing}), .{});
        _ = try @import("local.zig").reconfigure(io, gpa, name, o.form, dir, tar, why);
    } else {
        try Dir.cwd().createDir(io, authority, .fromMode(0o700));
        const boot = try ownedBoot(io, gpa, &steps, at, arch);
        const permit_signer = try enrollment.signer(io, gpa, &steps, authority, false);
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
            "subjectAltName=IP:192.168.5.2,IP:127.0.0.1",
            "-keyout",
            tls_key,
            "-out",
            tls_cert,
        } }}, .{})).ok) return steps.fail("creating the local HTTPS authority failed");
        const app = try howl.appBuild(io, gpa, o.form, arch, o.app, why);
        profile = .{ .managed = try @import("local.zig").limaManages(
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
            .ipe_kernel = try absolute(gpa, cwd, howl.environ.get("WEREWOLF_IPE_KERNEL").?),
            .ipe_key = try absolute(gpa, cwd, howl.environ.get("WEREWOLF_IPE_KEY").?),
            .ipe_cert = try absolute(gpa, cwd, howl.environ.get("WEREWOLF_IPE_CRT").?),
            .ipe_updates = try gpa.print("https://192.168.5.2:{d}", .{port}),
            .image_serial = try serial(io, gpa),
            .update_ca = tls_cert,
            .update_port = port,
            .disk = .{ .args = &.{
                "console=ttyAMA0",              "werewolf.ip=" ++ lima.user_ip,
                "werewolf.gw=" ++ lima.user_gw, "werewolf.dns=192.168.5.3",
            } },
        } };
        const stub = try gpa.print("{s}/linux.efi.stub", .{authority});
        try Dir.cwd().copyFile(howl.environ.get("UKI_STUB").?, Dir.cwd(), stub, io, .{});
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
        try howl.writePrivate(io, gpa, tar_path, tar, why);
        const config_disk = try gpa.print("{s}-config", .{name});
        if (!(try steps.exec(&.{.{ .argv = &.{
            "limactl", "disk", "import", config_disk, tar_path,
        } }}, .{})).ok) return steps.fail("importing the config disk failed");
        const yaml = try gpa.print("{s}/lima.yaml", .{at});
        try howl.writePrivate(
            io,
            gpa,
            yaml,
            try template(gpa, o.form, profile.spec.disk_path.?, at, config_disk, profile.managed),
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
) !secureboot.Keys {
    var env = try howl.environ.clone(gpa);
    _ = env.swapRemove("WEREWOLF_BOOT_KEY");
    _ = env.swapRemove("WEREWOLF_BOOT_CRT");
    const previous = howl.environ;
    howl.environ = &env;
    defer howl.environ = previous;
    return secureboot.prepare(io, gpa, steps, at, arch, false);
}

fn inputs(io: Io, gpa: Allocator, spec: native.Spec, stub: []const u8) ![64]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&try @import("lock.zig").inputs(io, gpa, spec));
    for ([5][]const u8{
        spec.ipe_kernel.?,                            spec.ipe_cert.?, spec.boot_cert.?, stub,
        try std.process.executablePathAlloc(io, gpa),
    }) |file| hash.update((try @import("prebuilt").hashFile(io, gpa, file)).sha256);
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
}

fn absolute(gpa: Allocator, cwd: []const u8, file: []const u8) ![]const u8 {
    return if (std.fs.path.isAbsolute(file)) file else gpa.print("{s}/{s}", .{ cwd, file });
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
