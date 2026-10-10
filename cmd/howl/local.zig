//! local creates machines here, under QEMU, Lima, bhyve or Firecracker, or
//! on a Proxmox node, and says when each is up and how to reach it. See
//! README.md.

const std = @import("std");
const howl = @import("howl.zig");
const lima = @import("lima.zig");
const bhyve = @import("bhyve.zig");
const firecracker = @import("firecracker.zig");
const proxmox = @import("proxmox.zig");
const qemu = @import("qemu.zig");
const booting = @import("boot.zig");
const progress = @import("progress.zig");
const native = @import("build.zig");
const forms = @import("form");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Why = howl.Why;
const say = howl.say;
const run = howl.run;
const writePrivate = howl.writePrivate;
const Options = howl.Options;
const Platform = howl.Platform;
const Tell = howl.Tell;
const localArch = howl.localArch;
const machineDir = howl.machineDir;
const appBuild = howl.appBuild;
const listens = howl.listens;
const chain = howl.chain;
const reconfigurable = howl.reconfigurable;
const releaseDisk = howl.releaseDisk;
const run_name = howl.run_name;
const testing = std.testing;

/// createQemu builds the form's boot disk and boots it in the background
/// under QEMU (qemu.zig), with its config tar: from its slots, so it
/// updates in place. ssh and the form's last port are forwarded from free
/// loopback ports. A machine of the same name is stopped and keeps its
/// disk, taking the new config. QEMU is the fallback engine.
pub fn createQemu(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    tell: Tell,
    why: *Why,
) !void {
    const arch = try localArch(why);
    const dir = try machineDir(gpa, name);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const at = try gpa.print("{s}/{s}", .{ cwd, dir });
    const fw = qemu.firmware(io, arch) orelse return why.refuse(
        "--on qemu: no UEFI firmware for {t} (edk2, which QEMU's packages bring)",
        .{arch},
    );
    const replaced = try qemu.stop(io, gpa, dir);
    // The machine is its disk, booted from slots and updated in place, so a
    // machine of this name keeps it and takes the new config; howl run
    // removed its last machine first.
    const disk = try gpa.print("{s}/disk.img", .{at});
    const kept = if (Dir.cwd().access(io, disk, .{})) |_| true else |_| false;
    if (kept) try howl.reconfigurable(
        o,
        name,
        qemu.record(io, gpa, dir, "form") orelse "",
        .qemu,
        why,
    );
    var steps: progress.Steps = try .init(io, gpa, why, try tell.step(gpa, dir));
    var built: ?i64 = null;
    if (!kept) {
        const ab = try appBuild(io, gpa, o.form, arch, o.app, why);
        var spec: native.Spec = .{
            .form = o.form,
            .arch = arch,
            .dev = tell.dev,
            .published = !o.local,
            .app = ab.root,
            .disk_path = disk,
        };
        spec.disk.args = qemu.bootArgs(arch);
        _ = try howl.buildHere(io, gpa, &steps, spec, .{ .disk = true });
        built = steps.start.untilNow(io, .awake).toSeconds();
        if (fw.vars) |v| try Dir.copyFile(
            Dir.cwd(),
            v,
            Dir.cwd(),
            try gpa.print("{s}/vars.fd", .{dir}),
            io,
            .{},
        );
    }
    try writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{dir}), tar, why);
    const ssh_port = try qemu.freePort(io, 2222);
    const web_port = try qemu.freePort(io, 8080);
    try writePrivate(io, gpa, try gpa.print("{s}/machine", .{dir}), try gpa.print(
        "form {s}\nssh {d}\nweb {d}\n",
        .{ o.form, ssh_port, web_port },
    ), why);
    const ports = try listens(io, gpa, o.form, why);
    // The machine's port this host's web port reaches: its last but ssh's,
    // or 80.
    var guest_web: u16 = 80;
    for (ports) |port| if (port != 22) {
        guest_web = port;
    };
    try steps.enter(.{ .name = "Starting the VM under QEMU", .short = "start" });
    // A console log and sockets left by the last machine of this name
    // would be taken for this one's.
    for ([_][]const u8{ "console.log", "console.sock", "monitor.sock" }) |f|
        Dir.cwd().deleteFile(io, try gpa.print("{s}/{s}", .{ dir, f })) catch {};
    const accel = qemu.accel(io);
    const argv = try qemu.argv(gpa, .{
        .arch = arch,
        .dir = at,
        .firmware = fw,
        .ssh_port = ssh_port,
        .web_port = web_port,
        .guest_web = guest_web,
    }, accel);
    const launched = Io.Clock.awake.now(io);
    if (!(try steps.exec(&.{.{ .argv = argv }}, .{})).ok) return steps.fail("QEMU did not start");
    _ = try steps.finish();
    var spin: progress.Spinner = .init(io);
    const watch = Io.Clock.awake.now(io);
    var boot = try booting.watch(
        io,
        gpa,
        try gpa.print("{s}/console.log", .{dir}),
        0,
        null,
        0,
        &spin,
    );
    spin.clear();
    // Count the VM's start from QEMU's launch to its first console output.
    if (boot.power_ns) |ns| boot.power_ns = ns + launched.durationTo(watch).toNanoseconds();
    const look: progress.Look = .of(io, Io.File.stderr());
    if (!boot.up) {
        try Io.File.stderr().writeStreamingAll(io, try gpa.print(
            "{s} {s} did not say it was up within 3 minutes\n  {s} · {s}\n",
            .{ look.cross(), name, try consoleCommand(gpa, name), try stopCommand(gpa, name) },
        ));
        why.text = "";
        return error.Refused;
    }
    if (!(Io.File.stdout().isTty(io) catch false)) {
        var out = Io.File.stdout().writerStreaming(io, &.{});
        try out.interface.print("{s}\t127.0.0.1:{d}\t{s}\n", .{ name, ssh_port, o.form });
    }
    const ssh = std.mem.findScalar(u16, ports, 22) != null;
    const late = sshReady(io, ports, "127.0.0.1", ssh_port);
    return sayUp(io, gpa, tell.began, try gpa.print("{s} is up here, under QEMU{s}{s}", .{
        name,
        if (kept)
            ", its disk kept, with the new config"
        else if (replaced)
            ", in place of the last"
        else
            "",
        late,
    }), built, boot, try gpa.print("{s}{s}{s}{s} · {s}", .{
        if (ssh) try sshCommand(gpa, name) else "",
        if (ssh) " · " else "",
        try reach(gpa, ports, web_port),
        try consoleCommand(gpa, name),
        try stopCommand(gpa, name),
    }), tell.note);
}

/// sshCommand returns the command a summary gives to reach name. The run
/// machine's commands need no name.
fn sshCommand(gpa: Allocator, name: []const u8) ![]const u8 {
    return if (std.mem.eql(u8, name, run_name))
        "howl ssh"
    else
        gpa.print("howl ssh {s}", .{name});
}

fn consoleCommand(gpa: Allocator, name: []const u8) ![]const u8 {
    return if (std.mem.eql(u8, name, run_name))
        "howl console"
    else
        gpa.print("howl console {s}", .{name});
}

fn stopCommand(gpa: Allocator, name: []const u8) ![]const u8 {
    return if (std.mem.eql(u8, name, run_name))
        "howl stop"
    else
        gpa.print("howl delete {s}", .{name});
}

/// reach says how this host reaches a machine under QEMU: web_port
/// reaches its last port other than ssh, shown as a URL if that port
/// speaks the web. A non-empty result ends in " · ".
fn reach(gpa: Allocator, ports: []const u16, web_port: u16) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var web: ?u16 = null;
    for (ports) |p| if (p != 22) {
        web = p;
    };
    if (web) |p| {
        const scheme: ?[]const u8 = switch (p) {
            443, 8443 => "https://",
            80, 3000, 8000, 8080, 8081, 9000, 11434 => "http://",
            else => null,
        };
        if (scheme) |sc| {
            try out.print(gpa, "{s}127.0.0.1:{d} · ", .{ sc, web_port });
        } else try out.print(gpa, "127.0.0.1:{d} reaches its :{d} · ", .{ web_port, p });
    }
    return out.items;
}

/// createLima builds the form's disk and makes a Lima machine of it, or
/// gives one of the same form a new config (reconfigure). Lima manages a
/// form with sshd and bash (limaManages); any other it boots on vzNAT and
/// watches through its DHCP lease, or its console without DHCP.
pub fn createLima(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    dhcp: bool,
    tell: Tell,
    w: *Io.Writer,
    why: *Why,
) !void {
    const dir = try machineDir(gpa, name);
    const began = tell.began;
    if (!lima.installed(
        io,
        gpa,
    )) return why.refuse("--on lima: no limactl here, or not macOS (brew install lima)", .{});
    const arch = try localArch(why);
    const m = lima.mac(name);
    var managed = try limaManages(io, gpa, o.form, why);
    // Each step prints one line naming it and logs its output.
    const step = try tell.step(gpa, dir);
    var built: ?i64 = null;
    if (try lima.exists(io, gpa, name)) {
        if (o.app != null) return why.refuse(
            "{s} exists, and an application is in the image: howl delete {s}, then create",
            .{ name, name },
        );
        managed = try reconfigure(io, gpa, name, o.form, dir, tar, why);
    } else {
        const ab = try appBuild(io, gpa, o.form, arch, o.app, why);
        const tar_path = try gpa.print("{s}/config.tar", .{dir});
        const config_disk = try gpa.print("{s}-config", .{name});
        try writePrivate(io, gpa, tar_path, tar, why);
        const cwd = try std.process.currentPathAlloc(io, gpa);
        const spec: native.Spec = .{
            .form = o.form,
            .arch = arch,
            .dev = tell.dev,
            .published = !o.local,
            .app = ab.root,
        };
        var steps: progress.Steps = try .init(io, gpa, why, step);
        var template: []const u8 = undefined;
        // The machine's own boot disk, booted from its slots, so it updates
        // in place: under Lima's management on Lima's network, with Lima's
        // user and ssh, or on vzNAT, whose console is the virtio one and,
        // with DHCP, whose MAC this host finds its lease by.
        const disk = try gpa.print("{s}/{s}/disk.img", .{ cwd, dir });
        var with = spec;
        with.disk_path = disk;
        if (managed) {
            with.disk.args = &lima.managed_args;
            _ = try howl.buildHere(io, gpa, &steps, with, .{ .disk = true });
            template = try lima.managedTemplate(gpa, o.form, @tagName(arch), disk, config_disk);
        } else {
            with.disk.args = if (dhcp)
                try gpa.dupe(
                    []const u8,
                    &.{ try gpa.print("werewolf.mac={s}", .{m}), "console=hvc0" },
                )
            else
                &.{"console=hvc0"};
            _ = try howl.buildHere(io, gpa, &steps, with, .{ .disk = true });
            template = try lima.template(
                gpa,
                o.form,
                @tagName(arch),
                disk,
                if (dhcp) &m else null,
                config_disk,
            );
        }
        built = (try steps.finish()).seconds;
        // Remove a config disk left by a machine deleted with limactl alone.
        _ = std.process.run(
            gpa,
            io,
            .{ .argv = &.{ "limactl", "disk", "delete", config_disk } },
        ) catch {};
        var lima_step = step;
        lima_step.first = .{ .name = "Creating the VM", .short = "create" };
        _ = try progress.run(
            io,
            gpa,
            why,
            &.{ "limactl", "disk", "import", config_disk, tar_path },
            lima_step,
        );
        const yaml = try gpa.print("{s}/lima.yaml", .{dir});
        try writePrivate(io, gpa, yaml, template, why);
        _ = try progress.run(
            io,
            gpa,
            why,
            &.{ "limactl", "create", "--name", name, "--tty=false", yaml },
            lima_step,
        );
    }
    const tty = Io.File.stdout().isTty(io) catch false;

    if (managed) {
        // limactl start returns once Lima's ssh and boot scripts are done.
        // The machine is reached through Lima's ssh forward.
        var start_step = step;
        start_step.first = .{ .name = "Starting the VM, and Lima's ssh", .short = "start" };
        const started = try progress.run(
            io,
            gpa,
            why,
            &.{ "limactl", "start", "--tty=false", name },
            start_step,
        );
        const r = try std.process.run(gpa, io, .{
            .argv = &.{ "limactl", "list", name, "--format", "{{.SSHLocalPort}}" },
        });
        const port = std.mem.trim(u8, r.stdout, " \n");
        if (!tty) try w.print("{s}\t127.0.0.1:{s}\t{s}\n", .{ name, port, o.form });
        try sayUp(io, gpa, began, try gpa.print(
            "{s} is up on Lima, which manages it",
            .{name},
        ), built, .{
            .power_ns = @as(i96, started.seconds) * std.time.ns_per_s,
        }, try gpa.print(
            "{s} · {s}",
            .{ try sshCommand(gpa, name), try stopCommand(gpa, name) },
        ), tell.note);
        return;
    }

    // limactl start waits for an ssh that never answers. Watch the DHCP
    // lease instead, or the console without DHCP, then kill limactl start;
    // the VM keeps running.
    const before = lima.previous(io, gpa, &m);
    const console_log = try gpa.print("{s}/serialv.log", .{
        try lima.dir(io, gpa, name) orelse return why.refuse("no machine {s}", .{name}),
    });
    const seen = if (Dir.cwd().statFile(io, console_log, .{})) |st| st.size else |_| 0;
    const log = try Dir.cwd().createFile(io, try gpa.print("{s}/start.log", .{dir}), .{});
    defer log.close(io);
    var starter = std.process.spawn(io, .{
        .argv = &.{ "limactl", "start", "--tty=false", name },
        .stdin = .ignore,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
    }) catch |err| return why.refuse("limactl start: {s}", .{@errorName(err)});
    var spin: progress.Spinner = .init(io);
    const boot = try booting.watch(
        io,
        gpa,
        console_log,
        seen,
        if (dhcp) &m else null,
        before,
        &spin,
    );
    spin.clear();
    starter.kill(io);
    if (!dhcp) {
        if (!boot.up) return why.refuse(
            "{s} is not up after 3 minutes: howl console {s}",
            .{ name, name },
        );
        if (!tty) try w.print("{s}\t-\t{s}\n", .{ name, o.form });
        return sayUp(io, gpa, began, try gpa.print(
            "{s} is up on Lima, on its own network, which this Mac does not reach " ++
                "({s} has no DHCP client)",
            .{ name, o.form },
        ), built, boot, try gpa.print(
            "{s} · {s}",
            .{ try consoleCommand(gpa, name), try stopCommand(gpa, name) },
        ), tell.note);
    }
    const addr = boot.address orelse
        return why.refuse(
            "{s} has no address after 3 minutes: howl console {s}",
            .{ name, name },
        );
    if (!tty) try w.print("{s}\t{s}\t{s}\n", .{ name, addr, o.form });
    const ports = try listens(io, gpa, o.form, why);
    const late = sshReady(io, ports, addr, 22);
    try sayUp(io, gpa, began, try gpa.print(
        "{s} is up on Lima, at {s}{s}",
        .{ name, addr, late },
    ), built, boot, try gpa.print(
        "{s}{s} · {s}",
        .{
            try reachAt(gpa, addr, ports, name),
            try consoleCommand(gpa, name),
            try stopCommand(gpa, name),
        },
    ), tell.note);
}

/// sshReady waits for sshd at host:port if ports holds 22, so that "up"
/// means reachable. It returns what to add to the up line if ssh never
/// answered.
fn sshReady(io: Io, ports: []const u16, host: []const u8, port: u16) []const u8 {
    if (std.mem.findScalar(u16, ports, 22) == null) return "";
    var spin: progress.Spinner = .init(io);
    defer spin.clear();
    return if (booting.awaitSsh(io, host, port, &spin)) "" else ", but its ssh does not answer yet";
}

/// sayUp prints that a machine is up and how long each step took, as
/// minikube does (build, VM start, kernel, userland, address), then how to
/// reach it.
fn sayUp(
    io: Io,
    gpa: Allocator,
    began: Io.Timestamp,
    what: []const u8,
    built: ?i64,
    boot: booting.Boot,
    next: []const u8,
    note: ?[]const u8,
) !void {
    const look: progress.Look = .of(io, Io.File.stderr());
    var steps: std.ArrayList(u8) = .empty;
    if (built) |b| try steps.print(gpa, "build {f}", .{progress.Clock{ .seconds = b }});
    if (boot.power_ns) |ns| try steps.print(
        gpa,
        "{s}VM start {f}",
        .{ sep(steps.items), Tenths{ .ns = ns } },
    );
    if (boot.kernel.len > 0)
        try steps.print(
            gpa,
            "{s}kernel {s} · userland {s}",
            .{ sep(steps.items), boot.kernel, boot.userland },
        );
    // An address that came with the boot is not a step of its own.
    if (boot.address_ns) |ns| if (ns >= std.time.ns_per_s / 10) {
        try steps.print(gpa, "{s}address {f}", .{ sep(steps.items), Tenths{ .ns = ns } });
    };
    var out: Io.Writer.Allocating = .init(gpa);
    const ow = &out.writer;
    try ow.print(
        "{s} {s}, in {f}\n",
        .{
            look.check(),
            what,
            progress.Clock{ .seconds = began.untilNow(io, .awake).toSeconds() },
        },
    );
    if (steps.items.len > 0) try ow.print("  {f}\n", .{look.dim(steps.items)});
    if (note) |n| try ow.print("  {f}\n", .{look.dim(n)});
    try ow.print("  {s}\n", .{next});
    Io.File.stderr().writeStreamingAll(io, out.written()) catch {};
}

fn sep(so_far: []const u8) []const u8 {
    return if (so_far.len > 0) " · " else "";
}

/// Tenths formats a duration to a tenth of a second: 2.1s.
const Tenths = struct {
    ns: i96,

    pub fn format(t: Tenths, w: *Io.Writer) Io.Writer.Error!void {
        const ns: u64 = @intCast(@max(t.ns, 0));
        // Under a second, print milliseconds: 42ms, not 0.0s.
        if (ns < std.time.ns_per_s) return w.print("{d}ms", .{ns / std.time.ns_per_ms});
        const d = ns / (std.time.ns_per_s / 10);
        try w.print("{d}.{d}s", .{ d / 10, d % 10 });
    }
};

/// reachAt says how this host reaches a machine at addr: ssh if it serves
/// ssh, and its last other port, as a URL if it speaks the web. Each part
/// ends in " · ".
fn reachAt(gpa: Allocator, addr: []const u8, ports: []const u16, name: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var web: ?u16 = null;
    var ssh = false;
    for (ports) |p| if (p == 22) {
        ssh = true;
    } else {
        web = p;
    };
    if (ssh) try out.print(gpa, "{s} · ", .{try sshCommand(gpa, name)});
    if (web) |p| switch (p) {
        80 => try out.print(gpa, "http://{s} · ", .{addr}),
        443 => try out.print(gpa, "https://{s} · ", .{addr}),
        3000,
        8000,
        8080,
        8081,
        9000,
        11434,
        => try out.print(gpa, "http://{s}:{d} · ", .{ addr, p }),
        else => try out.print(gpa, "{s}:{d} · ", .{ addr, p }),
    };
    return out.items;
}

/// up_ms is how long create waits for a machine here to come up, and
/// up_poll_ms how often it looks. A machine is up about a second after it
/// starts, so a coarser poll would make create slower than the boot.
const up_ms = 180_000;
const up_poll_ms = 50;

/// awaitUp waits for init's up line, or a panic, in the console log past
/// its first seen bytes. It serves machines with no address this host can
/// watch. Each poll reads into one 1 MiB buffer, so frequent polls cost no
/// memory; a boot says it is up well within its first MiB.
fn awaitUp(io: Io, gpa: Allocator, log: []const u8, seen: u64) !booting.Outcome {
    const buf = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(buf);
    var waited: u32 = 0;
    while (waited < up_ms) : (waited += up_poll_ms) {
        if (Dir.cwd().openFile(io, log, .{})) |f| {
            defer f.close(io);
            // A log shorter than seen was started again: read from its start.
            const len = f.length(io) catch 0;
            const from = if (seen <= len) seen else 0;
            const n = f.readPositionalAll(io, buf, from) catch 0;
            if (booting.outcome(buf[0..n])) |o| return o;
        } else |_| {}
        try io.sleep(.fromMilliseconds(up_poll_ms), .awake);
    }
    return .late;
}

/// createBhyve builds the machine's disk and writes its config tar and
/// form name beside it, then starts bhyve (bhyve.zig) as root under howl's
/// supervisor, detached by daemon(8), with the console in console.log. It
/// waits for the console to say up and prints the port forwards. A machine
/// of the same form gets a new config with a hard stop, since nothing can
/// ask a werewolf machine to shut down; its boot disk and /data stay.
pub fn createBhyve(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    tell: Tell,
    w: *Io.Writer,
    why: *Why,
) !void {
    if (!bhyve.installed(io))
        return why.refuse("--on bhyve: FreeBSD on x86_64, with vmm loaded (kldload vmm)", .{});
    Dir.cwd().access(io, bhyve.firmware, .{}) catch
        return why.refuse("no {s}: pkg install bhyve-firmware", .{bhyve.firmware});
    const root = bhyve.asRoot(io) catch
        return why.refuse("bhyve needs root, and there is no doas or sudo: pkg install doas", .{});
    const arch = try localArch(why);
    const dir = try machineDir(gpa, name);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const disk = try gpa.print("{s}/{s}/disk.img", .{ cwd, dir });
    const config = try gpa.print("{s}/{s}/config.tar", .{ cwd, dir });
    const log = try gpa.print("{s}/{s}/console.log", .{ cwd, dir });
    const form_file = try gpa.print("{s}/form", .{dir});
    const was = std.mem.trim(
        u8,
        Dir.cwd().readFileAlloc(io, form_file, gpa, .limited(256)) catch "",
        " \n",
    );
    if (was.len > 0) try reconfigurable(o, name, was, .bhyve, why);
    if (try bhyve.exists(io, gpa, name)) {
        say(
            io,
            "{s}: replacing its config, with a hard stop: bhyve cannot ask it to shut down",
            .{name},
        );
        try run(
            io,
            why,
            try std.mem.concat(gpa, []const u8, &.{ root, try bhyve.destroy(gpa, name) }),
        );
    }
    if (was.len == 0) {
        const ab = try appBuild(io, gpa, o.form, arch, o.app, why);
        var steps: progress.Steps = try .init(io, gpa, why, try tell.step(gpa, dir));
        _ = try howl.buildHere(io, gpa, &steps, .{
            .form = o.form,
            .arch = arch,
            .dev = tell.dev,
            .published = !o.local,
            .app = ab.root,
            .disk_path = disk,
        }, .{ .disk = true });
        _ = try steps.finish();
        try writePrivate(io, gpa, form_file, o.form, why);
    }
    try writePrivate(io, gpa, config, tar, why);
    const fwds = try bhyve.forwards(gpa, name, try listens(io, gpa, o.form, why));
    // Create the log as this user, so daemon appends to it as root and
    // delete can still remove it.
    const f = Dir.cwd().createFile(
        io,
        log,
        .{ .truncate = false, .permissions = .fromMode(0o600) },
    ) catch |err| return why.refuse("{s}: {s}", .{ log, @errorName(err) });
    f.close(io);
    const seen = if (Dir.cwd().statFile(io, log, .{})) |st| st.size else |_| 0;
    const self = try std.process.executablePathAlloc(io, gpa);
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, root);
    try argv.appendSlice(gpa, &.{ "daemon", "-f", "-o", log, self, "_bhyve", name, config });
    try argv.appendSlice(gpa, try bhyve.argv(gpa, name, disk, config, fwds));
    try run(io, why, argv.items);
    say(io, "{s}: waiting for it to boot", .{name});
    switch (try awaitUp(io, gpa, log, seen)) {
        .up => {},
        .panic => return why.refuse("{s} panicked: howl console {s} --on bhyve", .{ name, name }),
        .late => return why.refuse(
            "{s} is not up after 3 minutes: howl console {s} --on bhyve",
            .{ name, name },
        ),
    }
    for (fwds) |fw| say(
        io,
        "{s}: 127.0.0.1:{d} reaches its port {d}",
        .{ name, fw.host, fw.guest },
    );
    if (fwds.len == 0) say(
        io,
        "{s} listens on no port, so nothing reaches it; its console: howl console {s} --on " ++
            "bhyve",
        .{ name, name },
    );
    try w.print("{s}\t{s}\t{s}\n", .{
        name,
        if (fwds.len > 0) try gpa.print("127.0.0.1:{d}", .{fwds[0].host}) else "-",
        o.form,
    });
}

/// createFirecracker builds the form's slot and kernel, writes
/// its data disk, config tar and Firecracker config, sets up its network as
/// root, and starts Firecracker (firecracker.zig) under howl's supervisor,
/// detached by setsid, with the console in console.log. A machine of the
/// same form gets a new config with a hard stop; its data disk and
/// Firecracker config stay, so only the first create reads --dns.
pub fn createFirecracker(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    dns_given: ?[]const u8,
    tell: Tell,
    why: *Why,
) !void {
    if (!firecracker.installed(io, gpa)) return why.refuse(
        "--on firecracker: Linux with /dev/kvm, and firecracker on the PATH (tools/install-deps)",
        .{},
    );
    const root = firecracker.asRoot(io, gpa) catch
        return why.refuse("the machine's tap device needs root, and there is no sudo or doas", .{});
    const user = howl.environ.get("USER") orelse
        return why.refuse("no USER in the environment, whose tap device the machine's is", .{});
    const arch = try localArch(why);
    const dir = try machineDir(gpa, name);
    const cwd = try std.process.currentPathAlloc(io, gpa);
    const form_file = try gpa.print("{s}/form", .{dir});
    const was = std.mem.trim(
        u8,
        Dir.cwd().readFileAlloc(io, form_file, gpa, .limited(256)) catch "",
        " \n",
    );
    if (was.len > 0) try reconfigurable(o, name, was, .firecracker, why);
    if (firecracker.running(io, gpa, dir)) |pid| {
        say(io, "{s}: replacing its config, with a hard stop", .{name});
        try firecracker.stop(io, gpa, dir, pid, why);
    }
    const n = try firecracker.net(gpa, name);
    var built: ?i64 = null;
    if (was.len == 0) {
        const ab = try appBuild(io, gpa, o.form, arch, o.app, why);
        var steps: progress.Steps = try .init(io, gpa, why, try tell.step(gpa, dir));
        const p = try howl.buildHere(io, gpa, &steps, .{
            .form = o.form,
            .arch = arch,
            .dev = tell.dev,
            .published = !o.local,
            .app = ab.root,
        }, .{ .slot = true, .vmlinux = arch == .x86_64 });
        built = (try steps.finish()).seconds;
        const dns = dns_given orelse firecracker.hostDns(io, gpa) orelse return why.refuse(
            "--dns ADDR: this host's resolvers are all on loopback, which the machine cannot reach",
            .{},
        );
        const image_args = std.mem.trim(u8, Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/slot/cmdline", .{p.out}),
            gpa,
            .limited(4096),
        ) catch |err| return why.refuse(
            "{s}: no cmdline in its image: {s}",
            .{ o.form, @errorName(err) },
        ), " \n");
        const data = try gpa.print("{s}/{s}/data.img", .{ cwd, dir });
        // The guest's /data is sparse and mode 0600: it holds the machine's
        // state, secrets included.
        const data_file = Dir.cwd().createFile(
            io,
            data,
            .{ .truncate = false, .permissions = .fromMode(0o600) },
        ) catch |err| return why.refuse("{s}: {s}", .{ data, @errorName(err) });
        defer data_file.close(io);
        data_file.setLength(io, 8192 << 20) catch |err|
            return why.refuse("{s}: {s}", .{ data, @errorName(err) });
        try writePrivate(io, gpa, try gpa.print("{s}/vm.json", .{dir}), try firecracker.config(
            gpa,
            try gpa.print("{s}/{s}", .{ cwd, try firecracker.kernelPath(gpa, arch) }),
            try gpa.print("{s}/{s}/slot/stage0.zst", .{ cwd, p.out }),
            try firecracker.bootArgs(gpa, image_args, n, dns),
            data,
            try gpa.print("{s}/{s}/config.tar", .{ cwd, dir }),
            try gpa.print("{s}/{s}/slot/root.erofs", .{ cwd, p.out }),
            try gpa.print("{s}/{s}/firecracker.log", .{ cwd, dir }),
            n,
        ), why);
        try writePrivate(io, gpa, form_file, o.form, why);
    }
    try writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{dir}), tar, why);
    const log = try gpa.print("{s}/{s}/console.log", .{ cwd, dir });
    const seen = if (Dir.cwd().statFile(io, log, .{})) |st| st.size else |_| 0;
    try firecracker.networkUp(io, gpa, root, n, user, why);
    const self = try std.process.executablePathAlloc(io, gpa);
    // The supervisor writes the console to console.log and has nothing
    // else to say, so its own output is discarded.
    const launched = Io.Clock.awake.now(io);
    var starter = std.process.spawn(io, .{
        .argv = &.{ "setsid", "-f", self, "_firecracker", try gpa.print("{s}/{s}", .{ cwd, dir }) },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch |err| return why.refuse("setsid: {s}", .{@errorName(err)});
    _ = starter.wait(io) catch {};
    var spin: progress.Spinner = .init(io);
    const watched = Io.Clock.awake.now(io);
    var boot = try booting.watch(io, gpa, log, seen, null, 0, &spin);
    spin.clear();
    // Count the VM's start from Firecracker's launch to its first console
    // output.
    if (boot.power_ns) |ns| boot.power_ns = ns + launched.durationTo(watched).toNanoseconds();
    if (boot.ended) return why.refuse(
        "{s}: Firecracker exited before it was up: {s}",
        .{ name, try consoleCommand(gpa, name) },
    );
    if (!boot.up) return why.refuse(
        "{s} is not up after 3 minutes: {s}",
        .{ name, try consoleCommand(gpa, name) },
    );
    if (!(Io.File.stdout().isTty(io) catch false)) {
        var out = Io.File.stdout().writerStreaming(io, &.{});
        try out.interface.print("{s}\t{s}\t{s}\n", .{ name, n.guest, o.form });
    }
    const ports = try listens(io, gpa, o.form, why);
    const late = sshReady(io, ports, n.guest, 22);
    return sayUp(io, gpa, tell.began, try gpa.print(
        "{s} is up here, under Firecracker, at {s}{s}",
        .{ name, n.guest, late },
    ), built, boot, try gpa.print(
        "{s}{s} · {s}",
        .{
            try reachAt(gpa, n.guest, ports, name),
            try consoleCommand(gpa, name),
            try stopCommand(gpa, name),
        },
    ), tell.note);
}

/// createProxmox uploads the release disk to the node once (proxmox.zig)
/// and makes a VM of it, with the config tar imported as its second disk.
/// A VM of the same form gets a new config after a hard stop. The console,
/// a file on the node, says when it is up and what address DHCP gave it.
pub fn createProxmox(
    io: Io,
    gpa: Allocator,
    o: Options,
    name: []const u8,
    tar: []const u8,
    w: *Io.Writer,
    why: *Why,
) !void {
    const p = try proxmox.place(howl.environ, why);
    const arch = o.arch orelse .x86_64;
    if (arch != .x86_64)
        return why.refuse("--on proxmox: x86_64 machines only; its nodes are", .{});
    if (o.size != null) return why.refuse("--size is for --on {s}", .{Platform.list(.cloud, ", ")});
    const dir = try machineDir(gpa, name);
    const tar_path = try gpa.print("{s}/config.tar", .{dir});
    try writePrivate(io, gpa, tar_path, tar, why);
    var vmid: []const u8 = undefined;
    if (try proxmox.find(io, gpa, p, name, why)) |m| {
        try reconfigurable(o, name, m.form, .proxmox, why);
        say(io, "{s}: replacing the config of VM {s} on {s}, with a hard stop", .{
            name,
            m.vmid,
            p.host,
        });
        try proxmox.upload(io, gpa, p, tar_path, name, why);
        try proxmox.reconfigure(io, gpa, p, m, name, why);
        vmid = m.vmid;
    } else {
        const disk = try releaseDisk(io, gpa, o, arch, why);
        const image = try proxmox.ensureImage(io, gpa, p, o.form, arch, disk, why);
        vmid = proxmox.nextId(io, gpa, p) orelse
            return why.refuse("{s}: pvesh gave no next VMID", .{p.host});
        try proxmox.upload(io, gpa, p, tar_path, name, why);
        say(io, "{s}: making VM {s} on {s}", .{ name, vmid, p.host });
        try proxmox.create(io, gpa, p, vmid, name, o.form, image, why);
    }
    const seen = proxmox.logSize(io, gpa, p, name);
    try proxmox.start(io, gpa, p, vmid, why);
    say(io, "{s}: waiting for it to boot", .{name});
    switch (try proxmox.awaitUp(io, gpa, p, name, seen)) {
        .up => {},
        .panic => return why.refuse(
            "{s} panicked: howl console {s} --on proxmox",
            .{ name, name },
        ),
        .late => return why.refuse(
            "{s} not up after 3 minutes: howl console {s} --on proxmox",
            .{ name, name },
        ),
    }
    const addr = proxmox.address(proxmox.console(io, gpa, p, name, seen) orelse "") orelse "-";
    if (std.mem.eql(u8, addr, "-")) say(
        io,
        "{s}: its console reports no DHCP lease: its address is the static one in its tar, if any",
        .{name},
    );
    try w.print("{s}\t{s}\t{s}\n", .{ name, addr, o.form });
}

/// limaManages reports whether Lima can manage a machine of form. Lima's
/// ssh and readiness probes need openssh-server and bash among the packages
/// its chain's apko configs install (lib/form.zig). Any other form starts
/// on vzNAT, unmanaged, and is stopped hard.
fn limaManages(io: Io, gpa: Allocator, form: []const u8, why: *Why) !bool {
    const c = try chain(io, gpa, form, why);
    const config = try forms.apko(gpa, c, &.{});
    var sshd = false;
    var bash = false;
    const packages = (config.get("contents") orelse return false).get("packages") orelse
        return false;
    if (packages != .list) return false;
    for (packages.list) |p| if (p == .scalar) {
        if (std.mem.eql(u8, p.scalar.text, "openssh-server")) sshd = true;
        if (std.mem.eql(u8, p.scalar.text, "bash")) bash = true;
    };
    return sshd and bash;
}

/// reconfigure gives an existing Lima machine of the same form a new
/// config and returns whether Lima manages it. The config disk Lima
/// attached holds the tar's bytes, so they are replaced while the machine
/// is stopped; its boot disk and /data stay. Lima's stop request reaches
/// no unmanaged machine, so that stop is a hard one.
fn reconfigure(
    io: Io,
    gpa: Allocator,
    name: []const u8,
    form: []const u8,
    dir: []const u8,
    tar: []const u8,
    why: *Why,
) !bool {
    const d = try lima.dir(io, gpa, name) orelse return why.refuse("no machine {s}", .{name});
    const yaml = Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/lima.yaml", .{d}),
        gpa,
        .limited(1 << 20),
    ) catch |err|
        return why.refuse("{s}/lima.yaml: {s}", .{ d, @errorName(err) });
    const managed = lima.isManaged(yaml);
    const was = lima.formOf(yaml) orelse
        return why.refuse("{s} was not made by howl create; it is Lima's alone", .{name});
    if (!std.mem.eql(u8, was, form)) return why.refuse(
        "{s} runs {s}, not {s}: another form is another disk; howl delete {s}, then create",
        .{ name, was, form, name },
    );
    if (!try lima.running(io, gpa, name)) {
        say(io, "{s}: replacing its config", .{name});
    } else if (managed) {
        say(io, "{s}: replacing its config; stopping it", .{name});
        try run(io, why, &.{ "limactl", "stop", name });
    } else {
        say(
            io,
            "{s}: replacing its config, with a hard stop: Lima cannot ask it to shut down",
            .{name},
        );
        try run(io, why, &.{ "limactl", "stop", "-f", name });
    }
    const parent = std.fs.path.dirname(d) orelse return why.refuse("{s}: no Lima home", .{d});
    try writePrivate(
        io,
        gpa,
        try gpa.print("{s}/_disks/{s}-config/datadisk", .{ parent, name }),
        tar,
        why,
    );
    try writePrivate(io, gpa, try gpa.print("{s}/config.tar", .{dir}), tar, why);
    return managed;
}

// --- tests -------------------------------------------------------------------------------

test awaitUp {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const old = "werewolf: up in 0.7s\n";
    try tmp.dir.writeFile(
        io,
        .{ .sub_path = "console.log", .data = old ++ "boot two\nwerewolf: up in 0.8s\n" },
    );
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const log = try tmp.dir.realPathFileAlloc(io, "console.log", arena.allocator());
    // Past the first boot's line, it finds the second's.
    try testing.expectEqual(.up, try awaitUp(io, testing.allocator, log, old.len));
    // A log shorter than what was seen was started again: read from its start.
    try testing.expectEqual(.up, try awaitUp(io, testing.allocator, log, 1 << 30));
}
