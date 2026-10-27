//! provider runs one disposable machine of a provider A/B fixture
//! (docs/design/provider-ab-tests.md) on a VM backend: QEMU here, Lima, a
//! cloud through howl create, bhyve or Firecracker on a remote host, or
//! Proxmox. It gives the machine's SSH and console, and removes only what
//! it made. buildArgv and exportRelease make and keep the fixture's
//! releases.

const std = @import("std");
const builtin = @import("builtin");
const check = @import("check.zig");
const qemu = @import("qemu.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;
const Environ = std.process.Environ;
const Result = check.Result;
const join = check.join;
const quote = check.quote;

pub const Kind = enum {
    qemu,
    @"lima-qemu",
    @"lima-vz",
    aws,
    gcp,
    azure,
    bhyve,
    firecracker,
    proxmox,
};

/// Fixture is a fixture.json: its signed releases and how to boot them.
pub const Fixture = struct {
    arch: []const u8,
    mode: []const u8,
    tpm: bool = false,
    ssh_key: []const u8,
    form: []const u8 = "",
    channel: []const u8 = "",
    kernel: []const u8 = "",
    key: []const u8 = "",
    cert: []const u8 = "",
    boot_key: ?[]const u8 = null,
    boot_cert: ?[]const u8 = null,
    initial_serial: []const u8 = "",
    disk: []const u8 = "",
    releases: json.Value = .null,
    tpm_socket: ?[]const u8 = null,
    firmware: ?[]const u8 = null,

    pub fn secure(f: Fixture) bool {
        return mem.eql(u8, f.mode, "secure");
    }

    pub fn bootCert(f: Fixture) []const u8 {
        return f.boot_cert orelse f.cert;
    }
};

/// Runner runs a provider's commands. The tests give one that records them.
pub const Runner = struct {
    context: ?*anyopaque = null,
    run: *const fn (
        context: ?*anyopaque,
        io: Io,
        gpa: Allocator,
        argv: []const []const u8,
        o: check.Options,
    ) anyerror!Result = real,

    fn real(
        _: ?*anyopaque,
        io: Io,
        gpa: Allocator,
        argv: []const []const u8,
        o: check.Options,
    ) !Result {
        return check.command(io, gpa, argv, o);
    }
};

pub const Run = struct {
    /// must fails unless the command exits 0.
    must: bool = true,
    /// timeout is in seconds: 900, or 120 for ssh.
    timeout: ?i64 = null,
    input: ?[]const u8 = null,
    environ_map: ?*const Environ.Map = null,
};

const default_arm64_firmware = "/usr/local/share/u-boot/u-boot-bhyve-arm64/u-boot.bin";
const user_network = "werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3\n";

pub const Provider = struct {
    io: Io,
    gpa: Allocator,
    kind: Kind,
    fixture: Fixture,
    /// work is the absolute directory of the run's logs and disks.
    work: []const u8,
    howl: []const u8,
    name: []const u8,
    env: Environ.Map,
    /// lima_home is the caller's own, which enrollment must use.
    lima_home: ?[]const u8,
    runner: Runner = .{},
    why: []const u8 = "",
    machine: ?*qemu.Machine = null,
    remote: ?[]const u8 = null,
    remote_dir: ?[]const u8 = null,
    remote_pid: ?[]const u8 = null,
    cloud_created: bool = false,
    lima_created: bool = false,
    proxmox_created: bool = false,
    tap_created: bool = false,
    own_group: bool = false,
    proxy: ?[]const u8 = null,
    image: ?[]const u8 = null,
    vmid: ?[]const u8 = null,
    tap: ?[]const u8 = null,
    bhyve_machine: ?[]const u8 = null,
    address: []const u8 = "127.0.0.1",
    ssh_port: u16 = 22,
    log: []const u8,
    config: []const u8,
    qemu_args: []const []const u8 = &.{},
    vars_path: ?[]const u8 = null,
    vars_digest: [32]u8 = undefined,
    bhyve_howl: bool = false,
    bhyve_binary: []const u8 = "bhyve",
    bhyve_arm64_firmware: []const u8 = default_arm64_firmware,
    bhyve_tap: ?[]const u8 = null,

    /// init readies a machine of kind for fixture in work, which exists:
    /// its config tar, its environment, its bhyve settings. env is the
    /// caller's. It refuses a bhyve override it cannot trust.
    pub fn init(
        p: *Provider,
        io: Io,
        gpa: Allocator,
        kind: Kind,
        fixture: Fixture,
        work: []const u8,
        howl: []const u8,
        env: *const Environ.Map,
    ) !void {
        var id: [6]u8 = undefined;
        io.random(&id);
        p.* = .{
            .io = io,
            .gpa = gpa,
            .kind = kind,
            .fixture = fixture,
            .work = work,
            .howl = howl,
            .name = try gpa.print("wwab-{s}", .{&std.fmt.bytesToHex(id, .lower)}),
            .env = try env.clone(gpa),
            .lima_home = env.get("LIMA_HOME"),
            .log = try std.fs.path.join(gpa, &.{ work, "console.raw.log" }),
            .config = try std.fs.path.join(gpa, &.{ work, "config" }),
        };
        try Io.Dir.cwd().createDir(io, p.config, .default_dir);
        try p.put("hostname", try gpa.print("{s}\n", .{p.name}));
        const public = try gpa.print("{s}.pub", .{fixture.ssh_key});
        const keys = try Io.Dir.cwd().readFileAlloc(io, public, gpa, .limited(64 << 10));
        try p.put("authorized_keys", keys);
        if (kind == .bhyve) try p.bhyveSettings();
        try p.writeConfig();
        try p.env.put("WEREWOLF_IPE_KERNEL", fixture.kernel);
        try p.env.put("WEREWOLF_IPE_KEY", fixture.key);
        try p.env.put("WEREWOLF_IPE_CRT", fixture.cert);
        try p.env.put("IPE_UPDATES", fixture.channel);
        try p.env.put("IMAGE_SERIAL", fixture.initial_serial);
        if (fixture.secure()) {
            try p.env.put("WEREWOLF_BOOT_KEY", fixture.boot_key orelse fixture.key);
            try p.env.put("WEREWOLF_BOOT_CRT", fixture.bootCert());
        } else {
            _ = p.env.swapRemove("WEREWOLF_BOOT_KEY");
            _ = p.env.swapRemove("WEREWOLF_BOOT_CRT");
        }
    }

    fn bhyveSettings(p: *Provider) !void {
        const launch = p.env.get("BHYVE_LAUNCH") orelse "direct";
        if (!mem.eql(u8, launch, "direct") and !mem.eql(u8, launch, "howl"))
            return p.refuse("BHYVE_LAUNCH must be direct or howl", .{});
        p.bhyve_howl = mem.eql(u8, launch, "howl");
        if (p.bhyve_howl and (p.fixture.secure() or p.env.get("BHYVE_BRIDGE") == null))
            return p.refuse("BHYVE_LAUNCH=howl requires plain mode and BHYVE_BRIDGE", .{});
        p.bhyve_binary = p.env.get("BHYVE_BINARY") orelse "bhyve";
        if (!mem.eql(u8, p.bhyve_binary, "bhyve") and !mem.startsWith(u8, p.bhyve_binary, "/"))
            return p.refuse("BHYVE_BINARY must be an absolute remote path", .{});
        const firmware = p.env.get("BHYVE_ARM64_FIRMWARE") orelse default_arm64_firmware;
        if (!mem.startsWith(u8, firmware, "/") or mem.findAny(u8, firmware, ",\n\r") != null)
            return p.refuse("BHYVE_ARM64_FIRMWARE must be an absolute remote path " ++
                "without commas or newlines", .{});
        p.bhyve_arm64_firmware = firmware;
        p.bhyve_tap = p.env.get("BHYVE_TAP");
        if (p.bhyve_tap == null and !p.bhyve_howl) return p.put("network", user_network);
        if (p.bhyve_howl and p.bhyve_tap != null)
            return p.refuse("howl owns its TAP; omit BHYVE_TAP with BHYVE_LAUNCH=howl", .{});
        if (p.bhyve_tap) |tap| if (!isTap(tap))
            return p.refuse("BHYVE_TAP must name an existing tap interface", .{});
        const ip = p.env.get("BHYVE_TEST_IP") orelse return p.refuse("BHYVE_TEST_IP is unset", .{});
        const gw = p.env.get("BHYVE_TEST_GW") orelse return p.refuse("BHYVE_TEST_GW is unset", .{});
        const slash = mem.findScalar(u8, ip, '/') orelse ip.len;
        const bits = if (slash < ip.len)
            std.fmt.parseInt(u8, ip[slash + 1 ..], 10) catch 99
        else
            32;
        _ = Io.net.Ip4Address.parse(ip[0..slash], 0) catch
            return p.refuse("BHYVE_TEST_IP is not an IPv4 interface", .{});
        if (bits > 32) return p.refuse("BHYVE_TEST_IP is not an IPv4 interface", .{});
        _ = Io.net.Ip4Address.parse(gw, 0) catch
            return p.refuse("BHYVE_TEST_GW is not an IPv4 address", .{});
        p.address = ip[0..slash];
        try p.put("network", try p.gpa.print(
            "werewolf.ip={s}/{d} werewolf.gw={s} werewolf.dns={s}\n",
            .{ p.address, bits, gw, gw },
        ));
    }

    fn put(p: *Provider, file: []const u8, data: []const u8) !void {
        const at = try std.fs.path.join(p.gpa, &.{ p.config, file });
        try Io.Dir.cwd().writeFile(p.io, .{ .sub_path = at, .data = data });
    }

    /// writeConfig packs the config directory as work/config.tar.
    fn writeConfig(p: *Provider) !void {
        var dir = try Io.Dir.cwd().openDir(p.io, p.config, .{ .iterate = true });
        defer dir.close(p.io);
        var names: std.ArrayList([]const u8) = .empty;
        var it = dir.iterate();
        while (try it.next(p.io)) |e| try names.append(p.gpa, try p.gpa.dupe(u8, e.name));
        mem.sortUnstable([]const u8, names.items, {}, lessThan);
        var out: Io.Writer.Allocating = .init(p.gpa);
        var tar: std.tar.Writer = .{ .underlying_writer = &out.writer };
        for (names.items) |n| {
            const data = try dir.readFileAlloc(p.io, n, p.gpa, .limited(1 << 20));
            try tar.writeFileBytes(n, data, .{ .mode = 0o644 });
        }
        try tar.finishPedantically();
        const at = try p.path("config.tar");
        try Io.Dir.cwd().writeFile(p.io, .{ .sub_path = at, .data = out.written() });
    }

    fn refuse(p: *Provider, comptime fmt: []const u8, args: anytype) error{ProviderFailed} {
        p.why = p.gpa.print(fmt, args) catch "(out of memory saying why)";
        return error.ProviderFailed;
    }

    fn path(p: *Provider, name: []const u8) ![]const u8 {
        return std.fs.path.join(p.gpa, &.{ p.work, name });
    }

    /// run runs argv in the provider's environment and keeps its command
    /// line and errors in host.log. It refuses a failure unless told not to.
    pub fn run(p: *Provider, argv: []const []const u8, o: Run) !Result {
        const head = try join(p.gpa, argv[0..@min(4, argv.len)]);
        const log = try p.path("host.log");
        const r = p.runner.run(p.runner.context, p.io, p.gpa, argv, .{
            .environ_map = o.environ_map orelse &p.env,
            .input = o.input,
            .timeout = .fromSeconds(o.timeout orelse 900),
        }) catch |err| {
            const line = try p.gpa.print("{s}\n({t})\n", .{ try join(p.gpa, argv), err });
            check.append(p.io, log, line) catch {};
            if (err == error.Timeout) return err;
            return p.refuse("{s}: {t}", .{ head, err });
        };
        const line = try p.gpa.print("{s}\n{s}\n", .{ try join(p.gpa, argv), r.stderr });
        check.append(p.io, log, line) catch {};
        if (o.must and !r.ok()) return p.refuse("{s}: {s}{s}", .{
            head,
            check.tail(r.stderr, 3000),
            check.tail(r.stdout, 3000 -| r.stderr.len),
        });
        return r;
    }

    /// remoteCommand runs argv on the remote host, through its shell.
    pub fn remoteCommand(p: *Provider, argv: []const []const u8, o: Run) !Result {
        var options = o;
        options.input = try p.gpa.print("{s}\n", .{try join(p.gpa, argv)});
        return p.run(&.{ "ssh", "-o", "BatchMode=yes", p.remote.?, "sh", "-s" }, options);
    }

    /// remote is name in the remote private directory.
    fn remotePath(p: *Provider, name: []const u8) ![]const u8 {
        return p.gpa.print("{s}/{s}", .{ p.remote_dir.?, name });
    }

    /// copyOut copies local files into the remote private directory.
    fn copyOut(p: *Provider, files: []const []const u8) !void {
        const to = try p.gpa.print("{s}:{s}/", .{ p.remote.?, p.remote_dir.? });
        _ = try p.run(
            try mem.concat(p.gpa, []const u8, &.{ &.{ "scp", "-q" }, files, &.{to} }),
            .{},
        );
    }

    /// jump is the ProxyCommand that reaches target through the remote host.
    fn jump(p: *Provider, target: []const u8) ![]const u8 {
        return join(p.gpa, &.{ "ssh", "-o", "BatchMode=yes", "-W", target, p.remote.? });
    }

    /// makeRemoteDir makes the run's private directory on the remote host,
    /// the only remote path cleanup may remove.
    fn makeRemoteDir(p: *Provider, why: []const u8) !void {
        const made = try p.remoteCommand(&.{ "mktemp", "-d", "/tmp/ww-ab.XXXXXXXX" }, .{});
        const dir = mem.trim(u8, made.stdout, " \t\r\n");
        if (!isPrivateDir(dir, "/tmp/ww-ab.")) return p.refuse("{s}", .{why});
        p.remote_dir = dir;
    }

    fn enroll(p: *Provider, directory: []const u8) !void {
        if (p.fixture.firmware) |firmware| return check.copyTree(p.io, p.gpa, firmware, directory);
        // tools/enroll-boot may need the caller's Lima, not this run's.
        var env = try p.env.clone(p.gpa);
        if (p.lima_home) |home| try env.put("LIMA_HOME", home) else _ = env.swapRemove("LIMA_HOME");
        const argv = [_][]const u8{
            "sh",
            "tools/enroll-boot",
            p.fixture.arch,
            p.fixture.bootCert(),
            directory,
        };
        _ = try p.run(&argv, .{ .environ_map = &env });
    }

    pub fn start(p: *Provider) !void {
        switch (p.kind) {
            .qemu => try p.startQemu(),
            .@"lima-qemu", .@"lima-vz" => try p.startLima(),
            .aws, .gcp, .azure => try p.startCloud(),
            .bhyve, .firecracker => try p.startRemote(),
            .proxmox => try p.startProxmox(),
        }
    }

    fn startQemu(p: *Provider) !void {
        const arch = p.fixture.arch;
        p.ssh_port = try check.freePort(p.io);
        const disk = try p.path("disk.qcow2");
        try Io.Dir.cwd().copyFile(p.fixture.disk, .cwd(), disk, p.io, .{});
        const firmware = try p.path("enrolled");
        if (!p.fixture.secure()) try p.env.put("ENROLL_TEST_SETUP", "1");
        try p.enroll(firmware);
        const vars = try std.fs.path.join(p.gpa, &.{ firmware, "vars.fd" });
        if (!p.fixture.secure()) {
            const setup = try std.fs.path.join(p.gpa, &.{ firmware, "setup.fd" });
            try Io.Dir.cwd().copyFile(setup, .cwd(), vars, p.io, .{});
        }
        p.qemu_args = try qemuArgv(p.gpa, .{
            .arch = arch,
            .accel = accel(p.io, arch),
            .disk = disk,
            .config_tar = try p.path("config.tar"),
            .ssh_port = p.ssh_port,
            .firmware = firmware,
            .tpm_socket = p.fixture.tpm_socket,
        });
        p.vars_path = vars;
        p.vars_digest = try check.digest(p.io, vars);
        const m = try p.gpa.create(qemu.Machine);
        try m.start(p.io, p.gpa, p.qemu_args, .{ .log = p.log, .environ_map = &p.env });
        p.machine = m;
    }

    fn startLima(p: *Provider) !void {
        const gpa = p.gpa;
        if (builtin.os.tag != .macos) return p.refuse("Lima provider tests require macOS", .{});
        if (!mem.eql(u8, p.fixture.arch, "aarch64") or builtin.cpu.arch != .aarch64)
            return p.refuse("this Lima adapter currently requires an arm64 Mac", .{});
        try p.env.put("LIMA_HOME", try p.path("lima"));
        const backend = @tagName(p.kind)["lima-".len..];
        const config_disk = try gpa.print("{s}-config", .{p.name});
        const config_tar = try p.path("config.tar");
        _ = try p.run(&.{ "limactl", "disk", "import", config_disk, config_tar }, .{});
        p.lima_created = true;
        const Image = struct { location: []const u8, arch: []const u8, vmType: ?[]const u8 = null };
        const Firmware = struct { images: []const Image };
        var firmware: ?Firmware = null;
        if (mem.eql(u8, backend, "qemu") and p.fixture.secure()) {
            const enrolled = try p.path("enrolled");
            try p.enroll(enrolled);
            const code = try std.fs.path.join(gpa, &.{ enrolled, "code.fd" });
            const image: Image = .{ .location = code, .arch = p.fixture.arch, .vmType = "qemu" };
            firmware = .{ .images = try gpa.dupe(Image, &.{image}) };
            const vars = try std.fs.path.join(gpa, &.{ enrolled, "vars.fd" });
            const drive = try gpa.print(
                "if=pflash,format=raw,unit=1,readonly=on,file={s}",
                .{vars},
            );
            const command = try gpa.print(
                "qemu-system-aarch64 -drive {s}",
                .{try quote(gpa, drive)},
            );
            try p.env.put("QEMU_SYSTEM_AARCH64", command);
            p.vars_path = vars;
            p.vars_digest = try check.digest(p.io, vars);
        }
        const Disk = struct { name: []const u8, readOnly: bool };
        const config = try json.Stringify.valueAlloc(gpa, .{
            .vmType = backend,
            .plain = true,
            .arch = p.fixture.arch,
            .cpus = 2,
            .memory = "3GiB",
            .mounts = [_][]const u8{},
            .containerd = .{ .system = false, .user = false },
            .images = [_]Image{.{ .location = p.fixture.disk, .arch = p.fixture.arch }},
            .additionalDisks = [_]Disk{.{ .name = config_disk, .readOnly = true }},
            .firmware = firmware,
        }, .{ .emit_null_optional_fields = false });
        const template = try p.path("lima.yaml");
        try Io.Dir.cwd().writeFile(p.io, .{ .sub_path = template, .data = config });
        const named = try gpa.print("--name={s}", .{p.name});
        _ = try p.run(&.{ "limactl", "create", "--tty=false", named, template }, .{});
        const m = try gpa.create(qemu.Machine);
        try m.start(p.io, gpa, &.{ "limactl", "start", "--tty=false", p.name }, .{
            .log = try p.path("lima-start.log"),
            .environ_map = &p.env,
        });
        p.machine = m;
        const deadline = qemu.after(p.io, 45);
        while (Io.Clock.Timestamp.now(p.io, .awake).compare(.lt, deadline)) {
            const listed = try p.run(&.{ "limactl", "list", p.name, "--json" }, .{});
            const info = json.parseFromSliceLeaky(json.Value, gpa, listed.stdout, .{}) catch .null;
            const port = field(info, "sshLocalPort") orelse .null;
            if (port == .integer and port.integer > 0 and port.integer < 65536) {
                p.ssh_port = @intCast(port.integer);
                return;
            }
            try p.io.sleep(.fromSeconds(1), .awake);
        }
        return p.refuse("Lima did not assign its SSH forwarding port", .{});
    }

    fn startCloud(p: *Provider) !void {
        if (p.kind == .gcp) {
            try p.env.put("CLOUDSDK_COMPUTE_ZONE", p.env.get("GCP_ZONE") orelse "us-central1-b");
            if (p.env.get("GCP_PROJECT")) |project| try p.env.put("CLOUDSDK_CORE_PROJECT", project);
        }
        if (p.kind == .azure and p.env.get("AZURE_DEFAULTS_GROUP") == null) {
            try p.env.put("AZURE_DEFAULTS_GROUP", p.name);
            p.own_group = true;
            const argv = [_][]const u8{ "az", "group", "create", "-n", p.name, "-l", "westus2" };
            _ = try p.run(&argv ++ [_][]const u8{ "-o", "none" }, .{});
        }
        // The legacy cloud slot path, without local exact-pair TPM
        // enrollment; protected-default CLI tests are separate.
        var args: std.ArrayList([]const u8) = .empty;
        try args.appendSlice(p.gpa, &.{ p.howl, "create", p.name, "--disable=secureboot,tpm,ipe" });
        try args.appendSlice(p.gpa, &.{ "--with", p.fixture.form, "--on", @tagName(p.kind) });
        try args.appendSlice(p.gpa, &.{ "--arch", p.fixture.arch, "--build" });
        try args.appendSlice(p.gpa, &.{ "--config", p.config, "--allow-from", "me" });
        const x86 = mem.eql(u8, p.fixture.arch, "x86_64");
        const size: ?[]const u8 = p.env.get("CLOUD_SIZE") orelse switch (p.kind) {
            .aws => if (x86) "t3.medium" else "t4g.medium",
            .azure => if (x86) "Standard_D2s_v5" else null,
            else => null,
        };
        if (size) |s| try args.appendSlice(p.gpa, &.{ "--size", s });
        p.cloud_created = true;
        const r = try p.run(args.items, .{ .must = false, .timeout = 2400 });
        p.image = madeImage(r.stderr);
        if (!r.ok()) return p.refuse(
            "provider create failed; see host.log and console.raw.log",
            .{},
        );
        var fields = mem.splitScalar(u8, mem.trim(u8, r.stdout, " \t\r\n"), '\t');
        _ = fields.next();
        p.address = fields.next() orelse return p.refuse("howl create named no address", .{});
    }

    fn startProxmox(p: *Provider) !void {
        const gpa = p.gpa;
        if (p.fixture.secure())
            return p.refuse("Proxmox enrollment is not implemented; select AB_MODE=plain", .{});
        p.remote = p.env.get("PROXMOX_HOST");
        const storage = p.env.get("PROXMOX_STORAGE") orelse "local-lvm";
        const bridge = p.env.get("PROXMOX_BRIDGE") orelse "vmbr0";
        if (p.remote == null or !isHost(p.remote.?))
            return p.refuse("PROXMOX_HOST must name an SSH node with qm privileges", .{});
        for ([_][]const u8{ storage, bridge }) |setting| if (!isName(setting))
            return p.refuse("invalid Proxmox storage or bridge", .{});
        try p.makeRemoteDir("invalid remote test directory");
        try p.copyOut(&.{ p.fixture.disk, try p.path("config.tar") });
        // scp keeps the local names; the import names the disk.
        const next = try p.remoteCommand(&.{ "pvesh", "get", "/cluster/nextid" }, .{});
        const vmid = mem.trim(u8, mem.trim(u8, next.stdout, " \t\r\n"), "\"");
        if (vmid.len == 0 or !allDigits(vmid)) return p.refuse("invalid Proxmox VMID", .{});
        p.vmid = vmid;
        const disk = try p.remotePath(std.fs.path.basename(p.fixture.disk));
        const config = try p.remotePath("config.tar");
        const console_log = try p.remotePath("console.log");
        var create: std.ArrayList([]const u8) = .empty;
        try create.appendSlice(gpa, &.{ "qm", "create", vmid, "--name", p.name });
        try create.appendSlice(gpa, &.{
            "--description", try gpa.print("werewolf-ab: {s}", .{p.name}),
            "--tags",        "werewolf-ab",
            "--machine",     "q35",
            "--bios",        "ovmf",
            "--efidisk0",    try gpa.print("{s}:1,efitype=4m,pre-enrolled-keys=0", .{storage}),
            "--cpu",         "host",
            "--cores",       "2",
            "--memory",      "3072",
            "--ostype",      "l26",
            "--virtio0",     try gpa.print("{s}:0,import-from={s}", .{ storage, disk }),
            "--virtio1",
            try gpa.print(
                "{s}:0,import-from={s},format=raw,ro=1",
                .{ storage, config },
            ),
            "--boot",        "order=virtio0",
            "--net0",        try gpa.print("virtio,bridge={s}", .{bridge}),
            "--rng0",        "source=/dev/urandom",
            "--args",
            try gpa.print(
                "-chardev file,id=werewolf,path={s} -device isa-serial,chardev=werewolf",
                .{console_log},
            ),
        });
        _ = try p.remoteCommand(create.items, .{});
        p.proxmox_created = true;
        _ = try p.remoteCommand(&.{ "qm", "start", vmid }, .{});
        const deadline = qemu.after(p.io, 180);
        while (Io.Clock.Timestamp.now(p.io, .awake).compare(.lt, deadline)) {
            const text = try p.remoteCommand(&.{ "cat", console_log }, .{ .must = false });
            if (boundAddress(text.stdout)) |address| {
                p.address = address;
                p.proxy = try p.jump(try gpa.print("{s}:22", .{address}));
                return;
            }
            try p.io.sleep(.fromSeconds(3), .awake);
        }
        return p.refuse("Proxmox guest did not report its DHCP address", .{});
    }

    fn startRemote(p: *Provider) !void {
        const gpa = p.gpa;
        const bhyve = p.kind == .bhyve;
        const arm = mem.eql(u8, p.fixture.arch, "aarch64");
        if (bhyve and arm and p.fixture.secure())
            return p.refuse("arm64 bhyve Secure Boot enrollment is unsupported", .{});
        if (bhyve and p.fixture.secure() and p.env.get("SECUREBOOT_DIR") == null) return p.refuse(
            "signed bhyve tests require SECUREBOOT_DIR with bhyve code.fd and vars.fd",
            .{},
        );
        const remote = if (bhyve)
            p.env.get("BHYVE_HOST") orelse "bilbo"
        else
            p.env.get("FIRECRACKER_HOST") orelse "galadriel";
        if (!isHost(remote)) return p.refuse("invalid remote test host", .{});
        p.remote = remote;
        try p.makeRemoteDir("invalid remote private directory");
        const disk = try p.remotePath("disk.img");
        if (bhyve) {
            // Convert on the builder: the FreeBSD host needs only base zstd,
            // not a QEMU installation to test another hypervisor.
            const raw = try p.path("disk.img");
            const packed_disk = try p.path("disk.img.zst");
            const convert = [_][]const u8{ "qemu-img", "convert", "-f", "qcow2", "-O", "raw" };
            _ = try p.run(&convert ++ [_][]const u8{ p.fixture.disk, raw }, .{});
            _ = try p.run(&.{ "zstd", "-q", raw, "-o", packed_disk }, .{});
            try p.copyOut(&.{packed_disk});
            const unpack = [_][]const u8{ "zstd", "-d", "-q", try p.remotePath("disk.img.zst") };
            _ = try p.remoteCommand(&unpack ++ [_][]const u8{ "-o", disk }, .{});
        } else {
            try p.copyOut(&.{p.fixture.disk});
            const qcow2 = try p.remotePath(std.fs.path.basename(p.fixture.disk));
            const convert = [_][]const u8{ "qemu-img", "convert", "-f", "qcow2", "-O", "raw" };
            _ = try p.remoteCommand(&convert ++ [_][]const u8{ qcow2, disk }, .{});
        }
        const launch = if (bhyve)
            try p.bhyveLaunch() orelse return
        else
            try p.firecrackerLaunch();
        const output = try quote(gpa, try p.remotePath("console.log"));
        const script = try gpa.print(
            "nohup {s} >{s} 2>&1 </dev/null &\necho $!\n",
            .{ try join(gpa, launch), output },
        );
        const started = try p.run(&.{ "ssh", "-o", "BatchMode=yes", remote, "sh", "-s" }, .{
            .input = script,
        });
        p.remote_pid = mem.trim(u8, started.stdout, " \t\r\n");
    }

    /// bhyveLaunch readies the remote howl and returns the command that
    /// runs bhyve under its supervisor, or null after a normal howl launch.
    fn bhyveLaunch(p: *Provider) !?[]const []const u8 {
        const gpa = p.gpa;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(p.name, &digest, .{});
        const hashed: u32 = mem.readInt(u16, digest[0..2], .big);
        const forwarded: u16 = @intCast(20000 + hashed % 400 * 100);
        const binary = try gpa.print("build/{s}/tools/howl-freebsd", .{p.fixture.arch});
        _ = try p.run(&.{ "make", binary }, .{});
        try p.copyOut(&.{ try p.path("config.tar"), try check.absolutePath(p.io, gpa, binary) });
        if (p.bhyve_howl) {
            try p.startBhyveHowl();
            return null;
        }
        var firmware: ?[]const u8 = null;
        var tpm_socket: ?[]const u8 = null;
        if (p.fixture.secure()) {
            const enrolled = try p.path("enrolled");
            try p.enroll(enrolled);
            const code = try std.fs.path.join(gpa, &.{ enrolled, "code.fd" });
            const vars = try std.fs.path.join(gpa, &.{ enrolled, "vars.fd" });
            try p.copyOut(&.{ code, vars });
            const dir = p.remote_dir.?;
            firmware = try gpa.print("bootrom,{s}/code.fd,{s}/vars.fd", .{ dir, dir });
        }
        if (p.fixture.tpm) {
            if (!p.fixture.secure()) return p.refuse("TPM fixture requires Secure Boot", .{});
            const profile = try p.path("profile.json");
            const profile_data = try json.Stringify.valueAlloc(gpa, .{
                .spec = .{ .form = "provider-ab", .arch = p.fixture.arch },
                .managed = false,
                .provider = "bhyve",
            }, .{});
            try Io.Dir.cwd().writeFile(p.io, .{ .sub_path = profile, .data = profile_data });
            try p.copyOut(&.{profile});
            const authority = try p.remotePath("authority");
            _ = try p.remoteCommand(&.{ "mkdir", "-m", "700", authority }, .{});
            _ = try p.remoteCommand(
                &.{
                    "mv",
                    try p.remotePath("profile.json"),
                    try gpa.print("{s}/profile.json", .{authority}),
                },
                .{},
            );
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(p.remote_dir.?, &hash, .{});
            tpm_socket = try gpa.print("/tmp/ww-tpm-{x}/data.sock", .{hash[0..12]});
        }
        const args = try bhyveArgv(gpa, .{
            .binary = p.bhyve_binary,
            .arch = p.fixture.arch,
            .dir = p.remote_dir.?,
            .name = p.name,
            .tap = p.bhyve_tap,
            .ssh_port = forwarded,
            .arm64_firmware = p.bhyve_arm64_firmware,
            .enrolled = firmware,
            .tpm_socket = tpm_socket,
        });
        const supervisor: []const []const u8 = if (p.fixture.tpm) &.{
            try p.remotePath("howl-freebsd"), "_bhyve-secure", p.name, p.remote_dir.?, "doas", "-n",
        } else &.{
            "doas",
            "-n",
            try p.remotePath("howl-freebsd"),
            "_bhyve",
            p.name,
            try p.remotePath("config.tar"),
        };
        p.proxy = try p.jump(if (p.bhyve_tap != null)
            try gpa.print("{s}:22", .{p.address})
        else
            try gpa.print("127.0.0.1:{d}", .{forwarded}));
        p.ssh_port = 22;
        return try mem.concat(gpa, []const u8, &.{ supervisor, args });
    }

    /// firecrackerLaunch gives the machine a TAP of its own and a boot
    /// entry Firecracker can restart, and returns howl's supervisor.
    fn firecrackerLaunch(p: *Provider) ![]const []const u8 {
        const gpa = p.gpa;
        const dir = p.remote_dir.?;
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(std.fs.path.basename(dir), &h, .{});
        const subnet = (h[1] & 0x3f) << 2;
        p.tap = try gpa.print("fc{s}", .{&std.fmt.bytesToHex(h[2..6].*, .lower)});
        p.address = try gpa.print("172.16.{d}.{d}", .{ h[0], subnet + 2 });
        const host_ip = try gpa.print("172.16.{d}.{d}", .{ h[0], subnet + 1 });
        try p.put("network", try gpa.print(
            "werewolf.ip={s}/30 werewolf.gw={s} werewolf.dns=1.1.1.1\n",
            .{ p.address, host_ip },
        ));
        try p.writeConfig();
        const image = try p.remotePath("disk.img@@1048576");
        const entry_path = "::/loader/entries/werewolf-a.conf";
        const entry = try p.remoteCommand(&.{ "mtype", "-i", image, entry_path }, .{});
        if (efiEntry(entry.stdout)) return p.refuse("Firecracker cannot boot an EFI release", .{});
        const patched = try p.path("entry.conf");
        const rebooting = try rebootByKeyboard(gpa, entry.stdout);
        try Io.Dir.cwd().writeFile(p.io, .{ .sub_path = patched, .data = rebooting });
        try p.copyOut(&.{patched});
        const copied = try p.remotePath("entry.conf");
        _ = try p.remoteCommand(&.{ "mcopy", "-o", "-i", image, copied, entry_path }, .{});
        if (mem.eql(u8, p.env.get("AB_FIRECRACKER_PINNED") orelse "0", "1")) {
            // The fixture is fresh and host-built. Pin it before first boot,
            // exactly as the production create path pins its initial image.
            var hashes: [2][64]u8 = undefined;
            for ([_][]const u8{ "vmlinuz", "stage0.zst" }, 0..) |file, i| {
                const target = try p.remotePath(try gpa.print("pin-{s}", .{file}));
                _ = try p.remoteCommand(
                    &.{ "mcopy", "-i", image, try gpa.print("::/werewolf/a/{s}", .{file}), target },
                    .{},
                );
                const digest = try p.remoteCommand(&.{ "sha256sum", target }, .{});
                if (digest.stdout.len < 64) return error.BadPinDigest;
                hashes[i] = digest.stdout[0..64].*;
            }
            const trust = try p.path("firecracker-boot.json");
            const trust_data = try json.Stringify.valueAlloc(gpa, .{
                .version = 1,
                .entry = rebooting,
                .kernel = hashes[0],
                .initrd = hashes[1],
            }, .{});
            try Io.Dir.cwd().writeFile(p.io, .{ .sub_path = trust, .data = trust_data });
            try p.copyOut(&.{trust});
        }
        const binary = "build/x86_64/tools/howl-linux";
        _ = try p.run(&.{ "make", binary }, .{});
        try p.copyOut(&.{ try p.path("config.tar"), try check.absolutePath(p.io, gpa, binary) });
        const tap = p.tap.?;
        const identity = try p.remoteCommand(&.{ "id", "-u" }, .{});
        const uid = mem.trim(u8, identity.stdout, " \t\r\n");
        _ = try std.fmt.parseUnsigned(u32, uid, 10);
        _ = try p.remoteCommand(
            &.{ "doas", "-n", "ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", uid },
            .{},
        );
        p.tap_created = true;
        const net = try gpa.print("{s}/30", .{host_ip});
        _ = try p.remoteCommand(&.{ "doas", "-n", "ip", "addr", "add", net, "dev", tap }, .{});
        _ = try p.remoteCommand(&.{ "doas", "-n", "ip", "link", "set", tap, "up" }, .{});
        p.proxy = try p.jump(try gpa.print("{s}:22", .{p.address}));
        const supervisor = try p.remotePath("howl-linux");
        // Match howl: the directory owner runs the sandbox and opens its own
        // TAP. Root in a user namespace cannot traverse another user's 0700 directory.
        if (p.env.get("FIRECRACKER_REMOTE_PATH")) |remote_path|
            return gpa.dupe(
                []const u8,
                &.{
                    "env",
                    try gpa.print("PATH={s}", .{remote_path}),
                    supervisor,
                    "_firecracker",
                    dir,
                },
            );
        return gpa.dupe([]const u8, &.{ supervisor, "_firecracker", dir });
    }

    fn remoteHowl(p: *Provider, args: []const []const u8) !Result {
        const gpa = p.gpa;
        var command: std.ArrayList([]const u8) = .empty;
        try command.append(gpa, "env");
        if (!mem.eql(u8, p.bhyve_binary, "bhyve"))
            try command.append(gpa, try gpa.print("BHYVE_BINARY={s}", .{p.bhyve_binary}));
        try command.append(
            gpa,
            try gpa.print("BHYVE_ARM64_FIRMWARE={s}", .{p.bhyve_arm64_firmware}),
        );
        try command.append(gpa, "./howl-freebsd");
        try command.appendSlice(gpa, args);
        const line = try gpa.print("cd {s} && {s}", .{
            try quote(gpa, p.remote_dir.?),
            try join(gpa, command.items),
        });
        return p.remoteCommand(&.{ "sh", "-c", line }, .{});
    }

    /// startBhyveHowl seeds the machine's record so normal create boots the
    /// immutable signed fixture, without rebuilding it on the FreeBSD host.
    fn startBhyveHowl(p: *Provider) !void {
        const gpa = p.gpa;
        const machine = try gpa.print("build/machines/{s}", .{p.name});
        var out: Io.Writer.Allocating = .init(gpa);
        var tar: std.tar.Writer = .{ .underlying_writer = &out.writer };
        try packTree(p.io, gpa, &tar, "forms", "forms");
        try packTree(p.io, gpa, &tar, p.config, "test-config");
        const form = try gpa.print("{s}/form", .{machine});
        try tar.writeFileBytes(form, "playground\n", .{ .mode = 0o600 });
        const engine = try gpa.print("{s}/engine", .{machine});
        try tar.writeFileBytes(engine, "bhyve\n", .{ .mode = 0o600 });
        try tar.finishPedantically();
        const assets = try p.path("launch.tar");
        try Io.Dir.cwd().writeFile(p.io, .{ .sub_path = assets, .data = out.written() });
        try p.copyOut(&.{assets});
        const dir = p.remote_dir.?;
        _ = try p.remoteCommand(&.{ "tar", "-xf", try p.remotePath("launch.tar"), "-C", dir }, .{});
        p.bhyve_machine = try p.remotePath(machine);
        const disk = try gpa.print("{s}/disk.img", .{p.bhyve_machine.?});
        _ = try p.remoteCommand(&.{ "mv", try p.remotePath("disk.img"), disk }, .{});
        _ = try p.remoteHowl(&.{
            "create",    p.name,
            "--with",    "playground",
            "--build",   "--on",
            "bhyve",     "--disable=secureboot,tpm,ipe",
            "--network", "tap",
            "--bridge",  p.env.get("BHYVE_BRIDGE").?,
            "--config",  "test-config",
        });
        p.proxy = try p.jump(try gpa.print("{s}:22", .{p.address}));
        p.ssh_port = 22;
    }

    /// sshArgv is ssh running command as root on the machine with the
    /// fixture's key, its host key kept in work/known_hosts.
    pub fn sshArgv(p: *Provider, command: []const u8) ![]const []const u8 {
        const gpa = p.gpa;
        const known = try gpa.print("UserKnownHostsFile={s}", .{try p.path("known_hosts")});
        var args: std.ArrayList([]const u8) = .empty;
        try args.appendSlice(gpa, &.{
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            known,
            "-i",
            p.fixture.ssh_key,
            "-p",
            try gpa.print("{d}", .{p.ssh_port}),
        });
        if (p.proxy) |proxy|
            try args.appendSlice(gpa, &.{ "-o", try gpa.print("ProxyCommand={s}", .{proxy}) });
        try args.appendSlice(gpa, &.{ try gpa.print("root@{s}", .{p.address}), command });
        return args.items;
    }

    pub fn ssh(p: *Provider, command: []const u8, o: Run) !Result {
        var options = o;
        options.timeout = o.timeout orelse 120;
        return p.run(try p.sshArgv(command), options);
    }

    /// reboot asks the machine to restart. A Lima forwarder may hold the
    /// connection after the guest exits; the caller must still prove a
    /// fresh, authenticated boot afterward.
    pub fn reboot(p: *Provider, command: []const u8) !void {
        _ = p.ssh(command, .{ .must = false, .timeout = 15 }) catch |err| switch (err) {
            error.Timeout => try check.append(
                p.io,
                try p.path("host.log"),
                "SSH restart connection remained open; awaiting fresh boot evidence\n",
            ),
            else => return err,
        };
    }

    /// console refreshes console.raw.log from wherever the machine's console
    /// is, and returns it.
    pub fn console(p: *Provider) ![]const u8 {
        switch (p.kind) {
            .aws, .gcp, .azure => if (p.cloud_created) {
                const argv = [_][]const u8{ p.howl, "console", p.name, "--on", @tagName(p.kind) };
                const r = try p.run(&argv, .{ .must = false });
                try Io.Dir.cwd().writeFile(p.io, .{ .sub_path = p.log, .data = r.stdout });
            },
            .@"lima-qemu", .@"lima-vz" => if (p.lima_created) {
                const dir = try std.fs.path.join(p.gpa, &.{ p.env.get("LIMA_HOME").?, p.name });
                const text = try serialLogs(p.io, p.gpa, dir);
                try Io.Dir.cwd().writeFile(p.io, .{ .sub_path = p.log, .data = text });
            },
            else => if (p.remote_dir) |dir| {
                const file = try p.gpa.print("{s}/console.log", .{p.bhyve_machine orelse dir});
                const r = if (p.kind == .proxmox)
                    try p.remoteCommand(&.{ "cat", file }, .{ .must = false })
                else
                    try p.remoteCommand(&.{ "doas", "-n", "cat", file }, .{ .must = false });
                try Io.Dir.cwd().writeFile(p.io, .{ .sub_path = p.log, .data = r.stdout });
            },
        }
        return Io.Dir.cwd().readFileAlloc(p.io, p.log, p.gpa, .unlimited) catch "";
    }

    /// stop removes what this run made, and only that, trying every step
    /// however others fail; then it refuses if any failed.
    pub fn stop(p: *Provider) !void {
        const gpa = p.gpa;
        var errors: std.ArrayList([]const u8) = .empty;
        p.note(&errors, if (p.console()) |_| {} else |err| err);
        if (p.machine) |m| if (p.kind == .qemu) m.stop(.fromSeconds(30));
        if (p.lima_created) {
            p.note(&errors, p.quietly(&.{ "limactl", "delete", "--force", p.name }));
            const disk = try gpa.print("{s}-config", .{p.name});
            p.note(&errors, p.quietly(&.{ "limactl", "disk", "delete", disk }));
            if (p.machine) |m| m.stop(.fromSeconds(30));
        }
        if (p.cloud_created)
            p.note(&errors, p.quietly(&.{ p.howl, "delete", p.name, "--on", @tagName(p.kind) }));
        if (p.own_group) {
            const argv = [_][]const u8{
                "az",
                "group",
                "delete",
                "-n",
                p.name,
                "--yes",
                "--no-wait",
            };
            p.note(&errors, p.quietly(&argv));
        } else if (p.cloud_created and p.image != null) p.note(&errors, p.deleteImage());
        if (p.remote_dir) |dir| {
            if (p.kind == .proxmox and p.proxmox_created) p.note(&errors, p.deleteProxmox());
            if (p.kind == .firecracker) {
                const config = try p.remotePath("config.tar");
                p.note(&errors, p.remoteQuietly(&.{ "doas", "-n", "rm", "-f", config }, true));
                p.note(&errors, p.killChild());
            }
            if (p.kind == .bhyve and p.bhyve_machine != null) {
                p.note(&errors, p.remoteHowlQuietly(&.{ "delete", p.name, "--on", "bhyve" }));
                if (errors.items.len > 0) {
                    const all = try mem.join(gpa, "; ", errors.items);
                    return p.refuse("howl cleanup failed; retained {s}: {s}", .{ dir, all });
                }
            } else if (p.kind == .bhyve) {
                if (p.fixture.tpm) p.note(&errors, p.remoteQuietly(&.{
                    "touch", try p.remotePath("bhyve.stop"),
                }, true));
                const vm = try gpa.print("--vm={s}", .{p.name});
                p.note(
                    &errors,
                    p.remoteQuietly(&.{ "doas", "-n", "bhyvectl", vm, "--destroy" }, false),
                );
                if (p.fixture.tpm) if (p.remote_pid) |pid| {
                    p.note(&errors, p.remoteQuietly(&.{
                        "sh",
                        "-c",
                        "n=0; while kill -0 \"$1\" 2>/dev/null; do " ++
                            "n=$((n+1)); [ \"$n\" -lt 15 ] || exit 1; sleep 1; done",
                        "wait-bhyve",
                        pid,
                    }, true));
                    if (errors.items.len > 0) return p.refuse(
                        "protected supervisor did not stop; retained {s}",
                        .{dir},
                    );
                };
            }
            if (p.remote_pid) |pid| if (pid.len > 0 and allDigits(pid))
                p.note(&errors, p.remoteQuietly(&.{ "doas", "-n", "kill", pid }, false));
            if (p.kind == .firecracker and p.tap_created) {
                const argv = [_][]const u8{ "doas", "-n", "ip", "link", "delete", p.tap.? };
                p.note(&errors, p.remoteQuietly(&argv, true));
            }
            const delete: []const []const u8 = if (p.kind == .proxmox)
                &.{ "rm", "-rf", dir }
            else
                &.{ "doas", "-n", "rm", "-rf", dir };
            p.note(&errors, p.remoteQuietly(delete, true));
        }
        if (p.vars_path) |vars| if (mem.eql(u8, p.fixture.arch, "aarch64") and p.kind != .bhyve) {
            const now = check.digest(p.io, vars) catch @as([32]u8, @splat(0));
            if (!mem.eql(u8, &now, &p.vars_digest))
                try errors.append(gpa, "immutable firmware enrollment changed");
        };
        if (errors.items.len == 0) return;
        const all = try mem.join(gpa, "; ", errors.items);
        const log = try p.path("cleanup-errors.log");
        Io.Dir.cwd().writeFile(p.io, .{ .sub_path = log, .data = all }) catch {};
        return p.refuse("cleanup failed: {s}", .{all});
    }

    fn note(p: *Provider, errors: *std.ArrayList([]const u8), result: anyerror!void) void {
        const err = if (result) return else |e| e;
        const why = if (err == error.ProviderFailed) p.why else @errorName(err);
        errors.append(p.gpa, why) catch {};
    }

    fn quietly(p: *Provider, argv: []const []const u8) !void {
        _ = try p.run(argv, .{});
    }

    fn remoteQuietly(p: *Provider, argv: []const []const u8, must: bool) !void {
        _ = try p.remoteCommand(argv, .{ .must = must });
    }

    fn remoteHowlQuietly(p: *Provider, args: []const []const u8) !void {
        _ = try p.remoteHowl(args);
    }

    fn killChild(p: *Provider) !void {
        const pid_file = try p.remotePath("firecracker.pid");
        const r = try p.remoteCommand(&.{ "doas", "-n", "cat", pid_file }, .{ .must = false });
        const child = mem.trim(u8, r.stdout, " \t\r\n");
        if (child.len > 0 and allDigits(child))
            _ = try p.remoteCommand(&.{ "doas", "-n", "kill", child }, .{ .must = false });
    }

    /// deleteProxmox destroys the VM it made, after checking it is that one.
    pub fn deleteProxmox(p: *Provider) !void {
        const vmid = p.vmid.?;
        const config = try p.remoteCommand(&.{ "qm", "config", vmid }, .{});
        const owner = try p.gpa.print("name: {s}\n", .{p.name});
        if (mem.find(u8, config.stdout, owner) == null)
            return p.refuse("refusing to remove a Proxmox VM with a different owner/name", .{});
        _ = try p.remoteCommand(&.{ "qm", "stop", vmid }, .{ .must = false });
        const destroy = [_][]const u8{ "qm", "destroy", vmid, "--purge", "1" };
        _ = try p.remoteCommand(
            &destroy ++ [_][]const u8{ "--destroy-unreferenced-disks", "1" },
            .{},
        );
    }

    fn deleteImage(p: *Provider) !void {
        const gpa = p.gpa;
        const image = p.image.?;
        switch (p.kind) {
            .gcp => _ = try p.run(
                &.{ "gcloud", "--quiet", "compute", "images", "delete", image },
                .{},
            ),
            .aws => {
                const filter = try gpa.print("Name=name,Values={s}", .{image});
                const listed = try p.run(&.{
                    "aws",             "ec2",
                    "describe-images", "--owners",
                    "self",            "--filters",
                    filter,            "--output",
                    "json",
                }, .{});
                const records = try json.parseFromSliceLeaky(json.Value, gpa, listed.stdout, .{});
                const images = field(records, "Images") orelse .null;
                if (images != .array) return p.refuse("aws describe-images said no Images", .{});
                for (images.array.items) |record| {
                    const id = field(record, "ImageId") orelse continue;
                    if (id != .string) continue;
                    const deregister = [_][]const u8{ "aws", "ec2", "deregister-image" };
                    _ = try p.run(&deregister ++ [_][]const u8{ "--image-id", id.string }, .{});
                    const mappings = field(record, "BlockDeviceMappings") orelse continue;
                    if (mappings != .array) continue;
                    for (mappings.array.items) |mapping| {
                        const ebs = field(mapping, "Ebs") orelse continue;
                        const snapshot = field(ebs, "SnapshotId") orelse continue;
                        if (snapshot != .string) continue;
                        const delete = [_][]const u8{ "aws", "ec2", "delete-snapshot" };
                        _ = try p.run(
                            &delete ++ [_][]const u8{ "--snapshot-id", snapshot.string },
                            .{},
                        );
                    }
                }
            },
            .azure => {
                const group = p.env.get("AZURE_DEFAULTS_GROUP").?;
                const gallery = try mem.replaceOwned(u8, gpa, image, "-", "_");
                const sig = [_][]const u8{ "-g", group, "--gallery-name", gallery };
                const boot = [_][]const u8{ "--gallery-image-definition", "boot" };
                const none = [_][]const u8{ "-o", "none" };
                const version = [_][]const u8{ "--gallery-image-version", "1.0.0" };
                const versions = [_][]const u8{ "az", "sig", "image-version", "delete" };
                _ = try p.run(&(versions ++ sig ++ boot ++ version ++ none), .{});
                const definitions = [_][]const u8{ "az", "sig", "image-definition", "delete" };
                _ = try p.run(&(definitions ++ sig ++ boot ++ none), .{});
                _ = try p.run(&([_][]const u8{ "az", "sig", "delete" } ++ sig ++ none), .{});
                const disk = [_][]const u8{ "az", "disk", "delete", "-g", group, "-n", image };
                _ = try p.run(&(disk ++ [_][]const u8{"--yes"} ++ none), .{});
            },
            else => {},
        }
    }
};

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return mem.lessThan(u8, a, b);
}

/// field is v's member key, if v is an object with one.
fn field(v: json.Value, key: []const u8) ?json.Value {
    return if (v == .object) v.object.get(key) else null;
}

fn allDigits(s: []const u8) bool {
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

fn isTap(s: []const u8) bool {
    return s.len > 3 and mem.startsWith(u8, s, "tap") and allDigits(s[3..]);
}

/// isHost is whether s is a plain SSH destination: [a-zA-Z0-9_.@:-]+.
fn isHost(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and mem.findScalar(u8, "_.@:-", c) == null)
        return false;
    return true;
}

/// isName is whether s is [a-zA-Z0-9_.-]+.
fn isName(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and mem.findScalar(u8, "_.-", c) == null)
        return false;
    return true;
}

/// isPrivateDir is whether s is mktemp's directory under prefix.
fn isPrivateDir(s: []const u8, prefix: []const u8) bool {
    if (!mem.startsWith(u8, s, prefix) or s.len == prefix.len) return false;
    for (s[prefix.len..]) |c| if (!std.ascii.isAlphanumeric(c)) return false;
    return true;
}

/// madeImage is the image howl create said it made, if it said so.
fn madeImage(stderr: []const u8) ?[]const u8 {
    for ([_][]const u8{ "howl: image ", "werewolf: image " }) |lead| {
        var from: usize = 0;
        while (mem.findPos(u8, stderr, from, lead)) |at| : (from = at + 1) {
            const start = at + lead.len;
            var end = start;
            while (end < stderr.len and (std.ascii.isLower(stderr[end]) or
                std.ascii.isDigit(stderr[end]) or stderr[end] == '-')) end += 1;
            if (end > start and mem.startsWith(u8, stderr[end..], ": making it "))
                return stderr[start..end];
        }
    }
    return null;
}

/// boundAddress is the address a guest's DHCP client reported binding.
fn boundAddress(console: []const u8) ?[]const u8 {
    var lines = mem.splitScalar(u8, console, '\n');
    while (lines.next()) |line| {
        const at = mem.find(u8, line, "\"event\":\"bound\"") orelse continue;
        const key = "\"addr\":\"";
        const start = (mem.findPos(u8, line, at, key) orelse continue) + key.len;
        var end = start;
        while (end < line.len and (std.ascii.isDigit(line[end]) or line[end] == '.')) end += 1;
        if (end == start or end + 1 >= line.len or line[end] != '/') continue;
        var bits = end + 1;
        while (bits < line.len and std.ascii.isDigit(line[bits])) bits += 1;
        if (bits == end + 1 or bits >= line.len or line[bits] != '"') continue;
        return line[start..end];
    }
    return null;
}

/// efiEntry is whether a BLS entry boots through EFI, which Firecracker
/// cannot.
fn efiEntry(entry: []const u8) bool {
    var lines = mem.splitScalar(u8, entry, '\n');
    while (lines.next()) |line| for ([_][]const u8{ "efi", "uki", "uki-url" }) |key| {
        if (!mem.startsWith(u8, line, key)) continue;
        if (line.len == key.len or std.ascii.isWhitespace(line[key.len])) return true;
    };
    return false;
}

/// rebootByKeyboard asks the kernel to reboot through the keyboard
/// controller, which is how Firecracker sees a guest restart.
fn rebootByKeyboard(gpa: Allocator, entry: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = mem.splitScalar(u8, entry, '\n');
    var first = true;
    while (lines.next()) |line| {
        if (!first) try out.append(gpa, '\n');
        first = false;
        try out.appendSlice(gpa, line);
        if (mem.startsWith(u8, line, "options ")) try out.appendSlice(gpa, " reboot=k");
    }
    return out.items;
}

/// serialLogs is Lima's serial logs of a machine, in name order.
fn serialLogs(io: Io, gpa: Allocator, dir: []const u8) ![]const u8 {
    var d = Io.Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch return "";
    defer d.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = d.iterate();
    while (try it.next(io)) |e| {
        if (!mem.startsWith(u8, e.name, "serial") or !mem.endsWith(u8, e.name, ".log")) continue;
        try names.append(gpa, try gpa.dupe(u8, e.name));
    }
    mem.sortUnstable([]const u8, names.items, {}, lessThan);
    var out: std.ArrayList(u8) = .empty;
    for (names.items) |n| try out.appendSlice(gpa, try d.readFileAlloc(io, n, gpa, .unlimited));
    return out.items;
}

/// packTree adds the tree at path to tar under name: directories, files
/// with their modes, symbolic links as links.
pub fn packTree(
    io: Io,
    gpa: Allocator,
    tar: *std.tar.Writer,
    path: []const u8,
    name: []const u8,
) !void {
    var dir = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer dir.close(io);
    try tar.writeDir(name, .{ .mode = 0o755 });
    var walker = try dir.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |e| {
        const inside = try gpa.print("{s}/{s}", .{ name, e.path });
        switch (e.kind) {
            .directory => try tar.writeDir(inside, .{ .mode = 0o755 }),
            .sym_link => {
                var buf: [std.fs.max_path_bytes]u8 = undefined;
                try tar.writeLink(inside, buf[0..try dir.readLink(io, e.path, &buf)], .{});
            },
            .file => {
                const st = try dir.statFile(io, e.path, .{});
                const data = try dir.readFileAlloc(io, e.path, gpa, .unlimited);
                const mode: u32 = @intCast(st.permissions.toMode() & 0o7777);
                try tar.writeFileBytes(inside, data, .{ .mode = mode });
            },
            else => {},
        }
    }
}

/// accel is QEMU's accelerator here for a guest of arch.
pub fn accel(io: Io, arch: []const u8) []const u8 {
    const host = if (builtin.cpu.arch == .aarch64) "aarch64" else "x86_64";
    if (!mem.eql(u8, arch, host)) return "tcg";
    if (builtin.os.tag == .macos) return "hvf";
    Io.Dir.cwd().access(io, "/dev/kvm", .{ .read = true, .write = true }) catch return "tcg";
    return "kvm";
}

pub const QemuSetup = struct {
    arch: []const u8,
    accel: []const u8,
    disk: []const u8,
    config_tar: []const u8,
    ssh_port: u16,
    /// firmware holds enrolled code.fd and vars.fd.
    firmware: []const u8,
    tpm_socket: ?[]const u8 = null,
};

/// qemuArgv is the QEMU command that boots a fixture's disk on enrolled
/// firmware, ssh forwarded from loopback.
pub fn qemuArgv(gpa: Allocator, s: QemuSetup) ![]const []const u8 {
    const arm = mem.eql(u8, s.arch, "aarch64");
    const tcg = mem.eql(u8, s.accel, "tcg");
    const frozen = if (arm) "readonly=on," else "";
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(gpa, &.{
        try gpa.print("qemu-system-{s}", .{s.arch}),
        "-M",
        if (arm) "virt" else "q35,smm=on",
        "-accel",
        s.accel,
        "-cpu",
        if (tcg) "max" else "host",
        "-smp",
        "2",
        "-m",
        "3072",
        "-nographic",
        "-drive",
        try gpa.print("file={s},format=qcow2,if=virtio", .{s.disk}),
        "-drive",
        try gpa.print("file={s},format=raw,if=virtio,readonly=on", .{s.config_tar}),
        "-netdev",
        try gpa.print("user,id=n0,hostfwd=tcp:127.0.0.1:{d}-:22", .{s.ssh_port}),
        "-device",
        "virtio-net-pci,netdev=n0,romfile=",
        "-device",
        "virtio-rng-pci",
        "-drive",
        try gpa.print("if=pflash,format=raw,unit=0,readonly=on,file={s}/code.fd", .{s.firmware}),
        "-drive",
        try gpa.print("if=pflash,format=raw,unit=1,{s}file={s}/vars.fd", .{ frozen, s.firmware }),
    });
    if (!arm) try args.appendSlice(
        gpa,
        &.{ "-global", "driver=cfi.pflash01,property=secure,value=on" },
    );
    if (s.tpm_socket) |socket| try args.appendSlice(gpa, &.{
        "-chardev",
        try gpa.print("socket,id=tpmsock,path={s}", .{socket}),
        "-tpmdev",
        "emulator,id=tpm0,chardev=tpmsock",
        "-device",
        try gpa.print("{s},tpmdev=tpm0{s}", .{
            if (arm) "tpm-tis-device" else "tpm-tis",
            if (mem.eql(u8, s.accel, "hvf")) ",ppi=off" else "",
        }),
    });
    return args.items;
}

pub const BhyveSetup = struct {
    binary: []const u8,
    arch: []const u8,
    /// dir is the remote directory holding disk.img and config.tar.
    dir: []const u8,
    name: []const u8,
    /// tap is the caller's TAP; without it, slirp forwards ssh_port.
    tap: ?[]const u8,
    ssh_port: u16,
    arm64_firmware: []const u8,
    /// enrolled is bhyve's -l bootrom argument for enrolled firmware.
    enrolled: ?[]const u8 = null,
    tpm_socket: ?[]const u8 = null,
};

/// bhyveArgv is bhyve booting the fixture's disk.
pub fn bhyveArgv(gpa: Allocator, s: BhyveSetup) ![]const []const u8 {
    const x86 = mem.eql(u8, s.arch, "x86_64");
    const network = if (s.tap) |tap|
        try gpa.print("2,virtio-net,{s}", .{tap})
    else
        try gpa.print("2,virtio-net,slirp,open,hostfwd=tcp:127.0.0.1:{d}-:22", .{s.ssh_port});
    var args: std.ArrayList([]const u8) = .empty;
    try args.append(gpa, s.binary);
    if (x86) try args.appendSlice(gpa, &.{ "-H", "-w", "-u" });
    try args.appendSlice(gpa, &.{ "-c", "2", "-m", "3072M", "-s", "0,hostbridge" });
    if (x86) try args.appendSlice(gpa, &.{ "-s", "1,lpc" });
    try args.appendSlice(gpa, &.{
        "-s", network,
        "-s", try gpa.print("3,virtio-blk,{s}/disk.img", .{s.dir}),
        "-s", try gpa.print("4,virtio-blk,{s}/config.tar,ro", .{s.dir}),
        "-s", "5,virtio-rnd",
    });
    if (x86) {
        const bootrom = s.enrolled orelse "bootrom,/usr/local/share/uefi-firmware/BHYVE_UEFI.fd";
        try args.appendSlice(gpa, &.{ "-l", "com1,stdio", "-l", bootrom });
        if (s.tpm_socket) |socket| try args.appendSlice(gpa, &.{
            "-o", "lpc.fwcfg=qemu", "-l", try gpa.print("tpm,swtpm,{s}", .{socket}),
        });
    } else {
        if (s.enrolled != null) return error.Arm64SecureBootUnsupported;
        const bootrom = try gpa.print("bootrom={s}", .{s.arm64_firmware});
        try args.appendSlice(gpa, &.{ "-o", "console=stdio", "-o", bootrom });
    }
    try args.append(gpa, s.name);
    return args.items;
}

/// Build is what one fixture release is built from (howl _build).
pub const Build = struct {
    howl: []const u8,
    form: []const u8,
    arch: []const u8,
    kernel: []const u8,
    key: []const u8,
    cert: []const u8,
    build: []const u8,
    channel: []const u8,
    serial: []const u8,
    boot_key: ?[]const u8 = null,
    boot_cert: ?[]const u8 = null,
    tpm: bool = false,
    app: ?[]const u8 = null,
    goals: []const []const u8 = &.{ "prebuilt", "qcow2" },
    disk_args: ?[]const u8 = null,
    index: u32 = 1,
};

pub const Built = struct { argv: []const []const u8, output: []const u8 };

/// buildArgv is howl _build making b's release privately, without the
/// public managed-bundle export, and the directory it leaves it in. A
/// boot key makes it natively signed; without one, or without --tpm, the
/// protection is disabled by name.
pub fn buildArgv(gpa: Allocator, b: Build) !Built {
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(gpa, &.{
        b.howl,           "_build",
        "--with",         b.form,
        "--arch",         b.arch,
        "--build",        b.build,
        "--ipe-kernel",   b.kernel,
        "--ipe-key",      b.key,
        "--ipe-cert",     b.cert,
        "--ipe-updates",  b.channel,
        "--image-serial", b.serial,
        "--image-index",  try gpa.print("{d}", .{b.index}),
    });
    var disabled: std.ArrayList([]const u8) = .empty;
    if (b.boot_key) |key| {
        const cert = b.boot_cert orelse return error.BootKeyWithoutCertificate;
        try args.appendSlice(gpa, &.{ "--boot-key", key, "--boot-cert", cert, "--boot-native" });
    } else try disabled.append(gpa, "secureboot");
    if (b.tpm) try args.append(gpa, "--tpm") else try disabled.append(gpa, "tpm");
    if (disabled.items.len > 0) {
        const off = try mem.join(gpa, ",", disabled.items);
        try args.append(gpa, try gpa.print("--disable={s}", .{off}));
    }
    if (b.app) |app| try args.appendSlice(gpa, &.{ "--app-root", app });
    if (b.disk_args) |d| try args.appendSlice(gpa, &.{ "--disk-args", d });
    try args.appendSlice(gpa, b.goals);
    const app = if (b.app != null) "-app" else "";
    const output = try gpa.print("{s}/{s}{s}-ipe", .{ b.build, std.fs.path.basename(b.form), app });
    return .{ .argv = args.items, .output = output };
}

/// exportRelease keeps only the public artifacts the providers boot:
/// FORM-ARCH-{vmlinuz,stage0.zst,root.erofs,cmdline,disk.qcow2}, and the
/// UKI when there is one.
pub fn exportRelease(
    io: Io,
    gpa: Allocator,
    output: []const u8,
    form: []const u8,
    arch: []const u8,
    destination: []const u8,
) !void {
    try Io.Dir.cwd().createDirPath(io, destination);
    const prefix = try gpa.print("{s}-{s}-", .{ std.fs.path.basename(form), arch });
    for ([_][2][]const u8{
        .{ "slot/vmlinuz", "vmlinuz" },
        .{ "slot/stage0.zst", "stage0.zst" },
        .{ "slot/root.erofs", "root.erofs" },
        .{ "slot/cmdline", "cmdline" },
        .{ "disk.qcow2", "disk.qcow2" },
        .{ "slot/uki.efi", "uki" },
    }) |c| {
        const from = try std.fs.path.join(gpa, &.{ output, c[0] });
        if (mem.eql(u8, c[1], "uki")) Io.Dir.cwd().access(io, from, .{}) catch continue;
        const to = try gpa.print("{s}/{s}{s}", .{ destination, prefix, c[1] });
        try Io.Dir.cwd().copyFile(from, .cwd(), to, io, .{});
    }
}

const testing = std.testing;

/// Fake records each command and answers as a remote host might.
const Fake = struct {
    gpa: Allocator,
    calls: std.ArrayList([]const u8) = .empty,
    /// dir is what mktemp answers.
    dir: []const u8 = "/tmp/ww-ab.unit\n",
    /// reply answers every other command.
    reply: []const u8 = "123\n",
    /// fail fails every command whose line holds it.
    fail: ?[]const u8 = null,

    fn runner(f: *Fake) Runner {
        return .{ .context = f, .run = record };
    }

    fn record(
        context: ?*anyopaque,
        _: Io,
        _: Allocator,
        argv: []const []const u8,
        o: check.Options,
    ) !Result {
        const f: *Fake = @ptrCast(@alignCast(context.?));
        const input = o.input orelse "";
        const fed = if (o.input != null) " <<< " else "";
        const line = try f.gpa.print("{s}{s}{s}", .{ try join(f.gpa, argv), fed, input });
        try f.calls.append(f.gpa, line);
        if (f.fail) |text| if (mem.find(u8, line, text) != null)
            return .{ .term = .{ .exited = 1 }, .stdout = "", .stderr = "injected failure" };
        const made = o.input != null and mem.find(u8, input, "nohup") == null and
            mem.find(u8, input, "mktemp") != null;
        return .{ .term = .{ .exited = 0 }, .stdout = if (made) f.dir else f.reply, .stderr = "" };
    }

    fn launch(f: *Fake) []const u8 {
        for (f.calls.items) |c| if (mem.find(u8, c, "nohup") != null) return c;
        return "";
    }

    fn any(f: *Fake, text: []const u8) bool {
        for (f.calls.items) |c| if (mem.find(u8, c, text) != null) return true;
        return false;
    }
};

const Bench = struct {
    gpa: Allocator,
    io: Io,
    dir: []const u8,
    fixture: Fixture,
    n: usize = 0,

    fn machine(b: *Bench, kind: Kind, fixture: Fixture, env: *const Environ.Map) !*Provider {
        b.n += 1;
        const work = try b.gpa.print("{s}/run-{d}", .{ b.dir, b.n });
        try Io.Dir.cwd().createDir(b.io, work, .default_dir);
        const p = try b.gpa.create(Provider);
        try p.init(b.io, b.gpa, kind, fixture, work, "howl", env);
        return p;
    }
};

fn bench(gpa: Allocator, io: Io, tmp: *testing.TmpDir) !Bench {
    const dir = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const key = "ssh-ed25519 disposable-fixture\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "ssh.pub", .data = key });
    return .{ .gpa = gpa, .io = io, .dir = dir, .fixture = .{
        .ssh_key = try gpa.print("{s}/ssh", .{dir}),
        .kernel = "kernel",
        .key = "signer",
        .cert = "public",
        .channel = "https://127.0.0.1/image",
        .initial_serial = "20261012T000000Z",
        .mode = "plain",
        .arch = "x86_64",
    } };
}

fn has(args: []const []const u8, want: []const u8) bool {
    for (args) |a| if (mem.eql(u8, a, want)) return true;
    return false;
}

fn after(args: []const []const u8, flag: []const u8) []const u8 {
    for (args, 0..) |a, i| if (mem.eql(u8, a, flag) and i + 1 < args.len) return args[i + 1];
    return "";
}

fn holds(text: []const u8, part: []const u8) bool {
    return mem.find(u8, text, part) != null;
}

test "buildArgv disables by name what a release lacks; exportRelease keeps public files" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    const base: Build = .{
        .howl = "howl",
        .form = try gpa.print("{s}/form", .{root}),
        .arch = "x86_64",
        .kernel = "kernel",
        .key = "ipe.key",
        .cert = "ipe.crt",
        .build = try gpa.print("{s}/fixture-build", .{root}),
        .channel = "https://127.0.0.1/image",
        .serial = "20261012T000000Z",
    };
    var protected = base;
    protected.boot_key = "boot.key";
    protected.boot_cert = "boot.crt";
    protected.tpm = true;
    protected.index = 3;
    const made = try buildArgv(gpa, protected);
    const args = made.argv;
    try testing.expectEqualStrings("_build", args[1]);
    try testing.expectEqualStrings("prebuilt", args[args.len - 2]);
    try testing.expectEqualStrings("qcow2", args[args.len - 1]);
    try testing.expect(has(args, "--boot-native") and has(args, "--tpm"));
    try testing.expectEqualStrings("3", after(args, "--image-index"));
    for (args) |a| try testing.expect(!mem.startsWith(u8, a, "--disable"));
    var secure = base;
    secure.boot_key = "boot.key";
    secure.boot_cert = "boot.crt";
    try testing.expect(has((try buildArgv(gpa, secure)).argv, "--disable=tpm"));
    try testing.expect(has((try buildArgv(gpa, base)).argv, "--disable=secureboot,tpm"));
    var native = secure;
    native.app = try gpa.print("{s}/app", .{root});
    native.goals = &.{ "prebuilt", "disk" };
    native.disk_args = "werewolf.ip=10.0.2.15/24";
    const n = try buildArgv(gpa, native);
    try testing.expect(has(n.argv, "--disable=tpm") and has(n.argv, "--boot-native"));
    try testing.expectEqualStrings("disk", n.argv[n.argv.len - 1]);
    try testing.expectEqualStrings("form-app-ipe", std.fs.path.basename(n.output));
    try testing.expectEqualStrings("werewolf.ip=10.0.2.15/24", after(n.argv, "--disk-args"));
    var keyless = base;
    keyless.boot_key = "boot.key";
    try testing.expectError(error.BootKeyWithoutCertificate, buildArgv(gpa, keyless));

    try tmp.dir.createDirPath(io, "fixture-build/form-ipe/slot");
    for ([_][]const u8{ "vmlinuz", "stage0.zst", "root.erofs", "cmdline", "uki.efi" }) |name| {
        const at = try gpa.print("fixture-build/form-ipe/slot/{s}", .{name});
        try tmp.dir.writeFile(io, .{ .sub_path = at, .data = "public artifact" });
    }
    const disk = "fixture-build/form-ipe/disk.qcow2";
    try tmp.dir.writeFile(io, .{ .sub_path = disk, .data = "public disk" });
    const key = "fixture-build/form-ipe/boot.key";
    try tmp.dir.writeFile(io, .{ .sub_path = key, .data = "private signing key" });
    const destination = try gpa.print("{s}/export", .{root});
    try exportRelease(io, gpa, made.output, base.form, "x86_64", destination);
    var exported = try tmp.dir.openDir(io, "export", .{ .iterate = true });
    defer exported.close(io);
    var it = exported.iterate();
    var count: usize = 0;
    while (try it.next(io)) |e| {
        count += 1;
        const data = try exported.readFileAlloc(io, e.name, gpa, .unlimited);
        try testing.expect(!holds(data, "private signing key"));
    }
    try testing.expectEqual(6, count);
}

test "bhyve launches by architecture and refuses arm64 Secure Boot" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var b = try bench(gpa, testing.io, &tmp);
    var env: Environ.Map = .init(gpa);
    for ([_][]const u8{ "x86_64", "aarch64" }) |arch| {
        var fixture = b.fixture;
        fixture.arch = arch;
        fixture.disk = "fixture.qcow2";
        const vm = try b.machine(.bhyve, fixture, &env);
        var fake: Fake = .{ .gpa = gpa };
        vm.runner = fake.runner();
        try vm.start();
        const launch = fake.launch();
        try testing.expect(holds(launch, "3,virtio-blk,/tmp/ww-ab.unit/disk.img"));
        try testing.expect(holds(launch, "4,virtio-blk,/tmp/ww-ab.unit/config.tar,ro"));
        if (mem.eql(u8, arch, "aarch64")) {
            try testing.expect(holds(launch, "-o console=stdio"));
            try testing.expect(holds(launch, "u-boot-bhyve-arm64/u-boot.bin"));
            for ([_][]const u8{
                "1,lpc",
                " -H ",
                "-l com1",
            }) |no| try testing.expect(!holds(launch, no));
        } else for ([_][]const u8{ "-H -w -u", "1,lpc", "-l com1,stdio" }) |yes|
            try testing.expect(holds(launch, yes));
        vm.fixture.mode = "secure";
        vm.fixture.arch = "aarch64";
        try testing.expectError(error.ProviderFailed, vm.start());
        try testing.expect(holds(vm.why, "arm64 bhyve Secure Boot"));
    }
}

test "a QEMU machine has its entropy device" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    for ([_][]const u8{ "x86_64", "aarch64" }) |arch| {
        const args = try qemuArgv(arena.allocator(), .{
            .arch = arch,
            .accel = "tcg",
            .disk = "disk.qcow2",
            .config_tar = "config.tar",
            .ssh_port = 23456,
            .firmware = "enrolled",
        });
        const rng = for (args, 0..) |a, i| {
            if (mem.eql(u8, a, "virtio-rng-pci")) break i;
        } else return error.NoEntropyDevice;
        try testing.expectEqualStrings("-device", args[rng - 1]);
    }
}

test "protected bhyve uses the persistent TPM supervisor and waits for cleanup" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var b = try bench(gpa, testing.io, &tmp);
    var env: Environ.Map = .init(gpa);
    try env.put("SECUREBOOT_DIR", "firmware-templates");
    var fixture = b.fixture;
    fixture.mode = "secure";
    fixture.tpm = true;
    fixture.disk = "fixture.qcow2";
    const vm = try b.machine(.bhyve, fixture, &env);
    var fake: Fake = .{ .gpa = gpa };
    vm.runner = fake.runner();
    try vm.start();
    const launch = fake.launch();
    try testing.expect(holds(launch, "nohup /tmp/ww-ab.unit/howl-freebsd _bhyve-secure"));
    try testing.expect(holds(launch, "doas -n bhyve"));
    try testing.expect(holds(launch, "lpc.fwcfg=qemu"));
    try testing.expect(holds(launch, "tpm,swtpm,/tmp/ww-tpm-"));
    try testing.expect(holds(launch, "bootrom,/tmp/ww-ab.unit/code.fd,/tmp/ww-ab.unit/vars.fd"));
    fake.calls.clearRetainingCapacity();
    fake.fail = "wait-bhyve";
    try testing.expectError(error.ProviderFailed, vm.stop());
    try testing.expect(fake.any("touch /tmp/ww-ab.unit/bhyve.stop"));
    try testing.expect(fake.any("bhyvectl"));
    try testing.expect(!fake.any("rm -rf"));
    fake.fail = null;
    try vm.stop();
    try testing.expect(fake.any("rm -rf /tmp/ww-ab.unit"));
}

test "bhyve takes the caller's TAP and overrides, and leaves the TAP to its owner" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var b = try bench(gpa, io, &tmp);
    var env: Environ.Map = .init(gpa);
    try env.put("BHYVE_BINARY", "/var/tmp/rtc-test/bhyve");
    try env.put("BHYVE_ARM64_FIRMWARE", "/var/tmp/firmware-test/u-boot.bin");
    try env.put("BHYVE_TAP", "tap7");
    try env.put("BHYVE_TEST_IP", "192.0.2.2/30");
    try env.put("BHYVE_TEST_GW", "192.0.2.1");
    var fixture = b.fixture;
    fixture.disk = "fixture.qcow2";
    fixture.arch = "aarch64";
    const tap = try b.machine(.bhyve, fixture, &env);
    var fake: Fake = .{ .gpa = gpa };
    tap.runner = fake.runner();
    try tap.start();
    const launch = fake.launch();
    try testing.expect(holds(launch, "/var/tmp/rtc-test/bhyve"));
    try testing.expect(holds(launch, "bootrom=/var/tmp/firmware-test/u-boot.bin"));
    try testing.expect(holds(launch, "2,virtio-net,tap7"));
    try testing.expect(!holds(launch, "hostfwd="));
    try testing.expect(holds(tap.proxy.?, "192.0.2.2:22"));
    const network = try std.fs.path.join(gpa, &.{ tap.config, "network" });
    try testing.expectEqualStrings(
        "werewolf.ip=192.0.2.2/30 werewolf.gw=192.0.2.1 werewolf.dns=192.0.2.1\n",
        try Io.Dir.cwd().readFileAlloc(io, network, gpa, .unlimited),
    );
    fake.calls.clearRetainingCapacity();
    try tap.stop();
    try testing.expect(!fake.any("ifconfig"));

    for ([_][2][]const u8{
        .{ "BHYVE_TAP", "tap7,slirp" },
        .{ "BHYVE_BINARY", "relative/bhyve" },
        .{ "BHYVE_ARM64_FIRMWARE", "relative/u-boot.bin" },
        .{ "BHYVE_ARM64_FIRMWARE", "/firmware,extra" },
        .{ "BHYVE_ARM64_FIRMWARE", "/firmware\nextra" },
    }) |bad| {
        var wrong = try env.clone(gpa);
        try wrong.put(bad[0], bad[1]);
        try testing.expectError(error.ProviderFailed, b.machine(.bhyve, b.fixture, &wrong));
    }
}

test "a normal howl bhyve launch is cleaned up by howl, or kept when that fails" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var b = try bench(gpa, testing.io, &tmp);
    var env: Environ.Map = .init(gpa);
    try env.put("BHYVE_LAUNCH", "howl");
    try env.put("BHYVE_BRIDGE", "bridge7");
    try env.put("BHYVE_TEST_IP", "192.0.2.2/30");
    try env.put("BHYVE_TEST_GW", "192.0.2.1");
    const normal = try b.machine(.bhyve, b.fixture, &env);
    normal.remote = "test-host";
    normal.remote_dir = "/tmp/ww-ab.normal";
    var fake: Fake = .{ .gpa = gpa, .reply = "" };
    normal.runner = fake.runner();
    try normal.startBhyveHowl();
    const record = try gpa.print("/build/machines/{s}", .{normal.name});
    try testing.expect(mem.endsWith(u8, normal.bhyve_machine.?, record));
    const launch = fake.calls.items[fake.calls.items.len - 1];
    try testing.expect(holds(launch, "./howl-freebsd create ") and
        holds(launch, "--bridge bridge7"));
    try testing.expect(!holds(launch, "_bhyve") and !holds(launch, "BHYVE_BINARY=bhyve"));
    try testing.expect(holds(normal.proxy.?, "192.0.2.2:22"));
    try normal.stop();
    try testing.expect(fake.any("./howl-freebsd delete "));
    try testing.expect(!fake.any("bhyvectl"));

    fake.calls.clearRetainingCapacity();
    fake.fail = "./howl-freebsd delete";
    try testing.expectError(error.ProviderFailed, normal.stop());
    try testing.expect(holds(normal.why, "retained /tmp/ww-ab.normal"));
    try testing.expect(!fake.any(" rm "));
}

test "cleanup tries every owned resource, refuses unowned paths and other owners' VMs" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var b = try bench(gpa, testing.io, &tmp);
    var env: Environ.Map = .init(gpa);

    // A failed instance deletion still deletes the image it made, and fails.
    const cloud = try b.machine(.gcp, b.fixture, &env);
    cloud.cloud_created = true;
    cloud.image = "owned-image";
    var failing: Fake = .{ .gpa = gpa, .fail = "" };
    cloud.runner = failing.runner();
    try testing.expectError(error.ProviderFailed, cloud.stop());
    try testing.expect(holds(cloud.why, "injected failure"));
    var deletions: std.ArrayList([]const u8) = .empty;
    for (failing.calls.items) |c| if (!holds(c, " console ")) try deletions.append(gpa, c);
    try testing.expectEqual(2, deletions.items.len);
    const delete = try gpa.print("howl delete {s} --on gcp", .{cloud.name});
    try testing.expectEqualStrings(delete, deletions.items[0]);
    try testing.expectEqualStrings(
        "gcloud --quiet compute images delete owned-image",
        deletions.items[1],
    );

    // A directory mktemp did not make is never taken for cleanup.
    const remote = try b.machine(.firecracker, b.fixture, &env);
    var other: Fake = .{ .gpa = gpa, .dir = "/tmp/other-owner\n" };
    remote.runner = other.runner();
    try testing.expectError(error.ProviderFailed, remote.start());
    try testing.expect(holds(remote.why, "invalid remote private directory"));
    try testing.expectEqual(null, remote.remote_dir);
    try remote.stop();

    // A TAP this run did not make stays; the directory it made goes.
    const collision = try b.machine(.firecracker, b.fixture, &env);
    collision.remote = "test-host";
    collision.remote_dir = "/tmp/ww-ab.unit";
    collision.tap = "existing-tap";
    var owned: Fake = .{ .gpa = gpa, .reply = "" };
    collision.runner = owned.runner();
    try collision.stop();
    try testing.expect(!owned.any("ip link delete"));
    const last = owned.calls.items[owned.calls.items.len - 1];
    try testing.expect(mem.endsWith(u8, last, "<<< doas -n rm -rf /tmp/ww-ab.unit\n"));

    // Another owner's Proxmox VM is never destroyed.
    const proxmox = try b.machine(.proxmox, b.fixture, &env);
    proxmox.remote = "test-host";
    proxmox.vmid = "100";
    var stranger: Fake = .{ .gpa = gpa, .reply = "name: another-owner\n" };
    proxmox.runner = stranger.runner();
    try testing.expectError(error.ProviderFailed, proxmox.deleteProxmox());
    try testing.expect(holds(proxmox.why, "different owner/name"));
    try testing.expectEqual(1, stranger.calls.items.len);
    try testing.expect(mem.endsWith(u8, stranger.calls.items[0], "<<< qm config 100\n"));
}

test "helpers read what hosts and guests say" {
    try testing.expectEqualStrings(
        "wwab-1-x",
        madeImage("howl: image wwab-1-x: making it from\n").?,
    );
    try testing.expectEqual(null, madeImage("howl: image Bad: making it "));
    const bound = "x\n{\"event\":\"bound\",\"addr\":\"10.1.2.3/24\"}\n";
    try testing.expectEqualStrings("10.1.2.3", boundAddress(bound).?);
    try testing.expectEqual(null, boundAddress("{\"event\":\"lease\",\"addr\":\"10.1.2.3/24\"}"));
    try testing.expect(efiEntry("title a\nuki /werewolf/a/uki.efi\n"));
    try testing.expect(!efiEntry("title a\nlinux /werewolf/a/vmlinuz\noptions x\n"));
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const patched = try rebootByKeyboard(arena.allocator(), "linux v\noptions a b\n");
    try testing.expectEqualStrings("linux v\noptions a b reboot=k\n", patched);
    try testing.expect(isPrivateDir("/tmp/ww-ab.Ab12", "/tmp/ww-ab."));
    try testing.expect(!isPrivateDir("/tmp/ww-ab.", "/tmp/ww-ab."));
    try testing.expect(!isPrivateDir("/tmp/ww-ab.a/b", "/tmp/ww-ab."));
}
