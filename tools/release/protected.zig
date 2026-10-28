//! protected builds one vendor bundle of a form for a provider: the
//! published IPE kernel and the measured stub from public inputs only,
//! cached by their inputs, then howl's build and seal on this host, the
//! only place the signing keys are. The boot descriptor's signature is
//! withheld: candidates are public until a lifecycle job authorizes them.

const std = @import("std");
const mem = std.mem;
const json = @import("json.zig");
const sys = @import("sys.zig");
const Sys = sys.Sys;
const images = @import("images.zig");
const inputs = @import("inputs.zig");
const plan = @import("plan.zig");
const si = @import("security-inputs");

/// build builds form's bundle for provider and arch, release serial and
/// channel index, into output, which must not exist. It is called with
/// the protected keys (with-protected-keys) on a native Linux runner.
pub fn build(
    s: *Sys,
    tree: plan.Tree,
    form: []const u8,
    provider: []const u8,
    arch: []const u8,
    serial: []const u8,
    index: i64,
    output_dir: []const u8,
) !void {
    if (!images.isName(form) or (!mem.eql(u8, provider, "lima") and !mem.eql(u8, provider, "qemu")))
        return s.refuse("invalid protected form or provider", .{});
    if (!mem.eql(u8, arch, "aarch64") and !mem.eql(u8, arch, "x86_64"))
        return s.refuse(
            "CI builds require a native Linux runner for the requested architecture",
            .{},
        );
    plan.native(
        s,
        tree,
        arch,
    ) catch return s.refuse(
        "CI builds require a native Linux runner for the requested architecture",
        .{},
    );
    if (mem.eql(u8, provider, "lima") and
        !mem.eql(
            u8,
            arch,
            "aarch64",
        )) return s.refuse("protected Lima currently requires arm64", .{});
    if (index < 1) return s.refuse("a release index is 1 or more", .{});
    const output = try sys.resolve(s, output_dir);
    if (sys.exists(s, output)) return s.refuse("protected output already exists", .{});
    try sys.mkdirs(s, std.fs.path.dirname(output).?);
    try s.env.put("SOURCE_DATE_EPOCH", "0");
    const here = try std.process.currentPathAlloc(s.io, s.gpa);
    const cache = try sys.resolve(s, "build/protected-cache");
    try sys.mkdirs(s, cache);
    // Key files stay on this host; the stub's builder sees only public inputs.
    var keys: [4][]const u8 = undefined;
    for ([_][]const u8{
        "WEREWOLF_PROTECTED_IMAGE_KEY",
        "WEREWOLF_PROTECTED_IMAGE_CRT",
        "WEREWOLF_PROTECTED_BOOT_KEY",
        "WEREWOLF_PROTECTED_BOOT_CRT",
    }, &keys) |name, *k|
        k.* = try sys.resolve(
            s,
            s.getenv(name) orelse return s.refuse(
                "{s} is required: run under with-protected-keys",
                .{name},
            ),
        );
    var kernel_inputs: std.ArrayList(si.Input) = .empty;
    for ([_][]const u8{ "boot/kernel.yaml", "release/packages.pub" }) |name|
        try kernel_inputs.append(
            s.gpa,
            .{ .name = name, .path = try sys.join(s, &.{ here, name }) },
        );
    var pins: std.ArrayList([]const u8) = .empty;
    if (s.getenv("WEREWOLF_PROTECTED_INPUTS")) |snapshot| {
        const lock = try sys.join(s, &.{ snapshot, "kernel.lock.json" });
        try kernel_inputs.append(s.gpa, .{ .name = "package-lock", .path = lock });
        for (try si.packagePins(
            s.io,
            s.gpa,
            lock,
            arch,
        )) |p| try pins.appendSlice(s.gpa, &.{ "-p", p });
    }
    var adapter: Adapter = .{ .s = s };
    const host: si.Host = .{ .io = s.io, .env = s.env, .runner = adapter.runner() };
    var kernel: []const u8 = undefined;
    var stub: []const u8 = undefined;
    {
        const guard = try std.Io.Dir.cwd().createFile(
            s.io,
            try sys.join(s, &.{ cache, "build.lock" }),
            .{ .truncate = false, .lock = .exclusive },
        );
        defer guard.close(s.io);
        // The published kernel's IPE trusts the protected image certificate.
        // check-protected-qemu's disposable certificate needs a test kernel
        // (tools/test-kernel); howl refuses any whose IPE trusts another.
        if (s.getenv("WEREWOLF_PROTECTED_TEST_KERNEL")) |test_kernel| {
            kernel = try sys.resolve(s, test_kernel);
        } else {
            const pin = try si.fingerprint(s.io, s.gpa, arch, kernel_inputs.items);
            var make: KernelMake = .{ .s = s, .arch = arch, .pins = pins.items };
            kernel = try si.cached(
                s.io,
                s.gpa,
                try sys.join(s, &.{ cache, arch, try s.gpa.print("kernel-{s}", .{&pin}) }),
                &pin,
                "rootfs.tar",
                make.make(),
            );
        }
        const stub_pin = try si.fingerprint(
            s.io,
            s.gpa,
            arch,
            try si.stubInputs(s.gpa, s.env, here),
        );
        var make: StubMake = .{ .host = host, .tree = here, .cache = cache, .arch = arch };
        stub = try si.cached(
            s.io,
            s.gpa,
            try sys.join(s, &.{ cache, arch, try s.gpa.print("stub-{s}", .{&stub_pin}) }),
            &stub_pin,
            "linux.efi.stub",
            make.make(),
        );
    }
    var env = try s.env.clone(s.gpa);
    try env.put("UKI_STUB", stub);
    // Machines follow the public mirror themselves
    // (docs/design/implemented/independent-updates.md).
    const trust = try sys.readJson(s, try sys.join(s, &.{ tree.trust, "trust.json" }), 4096);
    const channel = try s.gpa.print(
        "{s}/{s}/{s}",
        .{ try json.text(trust, "source"), form, provider },
    );
    const work = try sys.join(
        s,
        &.{
            try sys.resolve(s, tree.protected_work),
            try s.gpa.print("{s}-{s}", .{ arch, provider }),
            form,
        },
    );
    try std.Io.Dir.cwd().createDirPath(s.io, work);
    try std.Io.Dir.cwd().setFilePermissions(s.io, work, .fromMode(0o700), .{});
    const disk = try sys.join(s, &.{ work, "disk.raw" });
    var disk_args: []const u8 = if (mem.eql(u8, arch, "aarch64"))
        "console=ttyAMA0"
    else
        "console=ttyS0";
    if (mem.eql(
        u8,
        provider,
        "qemu",
    )) disk_args = try s.gpa.print(
        "{s} werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3",
        .{disk_args},
    );
    if (mem.eql(
        u8,
        provider,
        "lima",
    )) disk_args = try s.gpa.print(
        "{s} werewolf.ip=192.168.5.15/24 werewolf.gw=192.168.5.2 werewolf.dns=192.168.5.3",
        .{disk_args},
    );
    const howl = try sys.resolve(s, tree.howl);
    try sys.run(s, &.{
        howl,            "_build", "--with",        form,      "--arch",         arch,
        "--build",       work,     "--ipe-kernel",  kernel,    "--ipe-key",      keys[0],
        "--ipe-cert",    keys[1],  "--ipe-updates", channel,   "--image-serial", serial,
        "--image-index",
        try s.gpa.print(
            "{d}",
            .{index},
        ),
        "--boot-key",    keys[2],  "--boot-cert",   keys[3],   "--boot-native",  "--tpm",
        "--disk",        disk,     "--disk-args",   disk_args, "disk",
    }, .{ .env = &env });
    const slot = try sys.join(s, &.{ work, try s.gpa.print("{s}-ipe", .{try s.variantKey(form)}) });
    const config = try sys.join(s, &.{ work, "seal.json" });
    try sys.write(s, config, try json.dumps(s.gpa, try json.from(s.gpa, .{
        .form = form,
        .arch = arch,
        .disk = disk,
        .slot = try sys.join(s, &.{ slot, "slot" }),
        .head = try sys.join(s, &.{ slot, "prebuilt", arch }),
        .output = output,
        .image_key = keys[0],
        .image_certificate = keys[1],
        .boot_certificate = keys[3],
        .channel = channel,
    })));
    {
        defer std.Io.Dir.cwd().deleteFile(s.io, config) catch {};
        try sys.run(s, &.{ howl, "_boot-image", "seal", config }, .{ .env = &env });
    }
    // Candidate artifacts may be publicly readable. Withhold the signature that
    // admits a boot bundle until the trusted lifecycle/publication job passes.
    // Signed image heads and PE code alone cannot authorize the boot descriptor.
    try std.Io.Dir.cwd().deleteFile(s.io, try sys.join(s, &.{ output, "boot.json.sig" }));
    try std.Io.Dir.cwd().deleteFile(s.io, disk);
}

/// Adapter runs security-inputs' commands through Sys, so their output
/// lands in the form's log.
const Adapter = struct {
    s: *Sys,

    fn runner(a: *Adapter) si.Runner {
        return .{ .context = a, .run = run, .capture = capture, .phase = phase };
    }

    fn run(context: *anyopaque, gpa: std.mem.Allocator, command: si.Command) anyerror!void {
        _ = gpa;
        const a: *Adapter = @ptrCast(@alignCast(context));
        if (command.stdin != null) return error.StdinUnsupported;
        try sys.run(a.s, command.argv, .{ .env = command.env });
    }

    fn capture(
        context: *anyopaque,
        gpa: std.mem.Allocator,
        argv: []const []const u8,
    ) anyerror![]const u8 {
        _ = gpa;
        const a: *Adapter = @ptrCast(@alignCast(context));
        return sys.output(a.s, argv);
    }

    fn phase(context: *anyopaque, short: []const u8, name: []const u8) void {
        const a: *Adapter = @ptrCast(@alignCast(context));
        a.s.say("howl: phase {s}: {s}", .{ short, name });
    }
};

/// KernelMake makes linux-werewolf from werewolf's kernel repository, as
/// apko installs it.
const KernelMake = struct {
    s: *Sys,
    arch: []const u8,
    pins: []const []const u8,

    fn make(k: *KernelMake) si.Make {
        return .{ .context = k, .make = run };
    }

    fn run(context: *anyopaque, gpa: std.mem.Allocator, output: []const u8) anyerror!void {
        _ = gpa;
        const k: *KernelMake = @ptrCast(@alignCast(context));
        const s = k.s;
        const work = try sys.scratch(s, std.fs.path.dirname(output).?, "tmp");
        defer sys.remove(s, work);
        const configs = try inputs.bootConfigs(s, work);
        const incoming = try sys.join(s, &.{ work, "rootfs.tar" });
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(
            s.gpa,
            &.{ "apko", "--workdir", configs, "build-minirootfs", "--build-arch", k.arch },
        );
        try argv.appendSlice(s.gpa, k.pins);
        try argv.appendSlice(s.gpa, &.{ "kernel.yaml", incoming });
        try sys.run(s, argv.items, .{});
        try sys.rename(s, incoming, output);
    }
};

const StubMake = struct {
    host: si.Host,
    tree: []const u8,
    cache: []const u8,
    arch: []const u8,

    fn make(m: *StubMake) si.Make {
        return .{ .context = m, .make = run };
    }

    fn run(context: *anyopaque, gpa: std.mem.Allocator, output: []const u8) anyerror!void {
        const m: *StubMake = @ptrCast(@alignCast(context));
        try si.stub(gpa, m.host, m.tree, m.cache, m.arch, output);
    }
};
