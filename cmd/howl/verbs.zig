//! verbs reaches, stops, deletes and shows the console of the machines
//! create made, here or in a cloud. See README.md.

const std = @import("std");
const howl = @import("howl.zig");
const lima = @import("lima.zig");
const bhyve = @import("bhyve.zig");
const firecracker = @import("firecracker.zig");
const proxmox = @import("proxmox.zig");
const qemu = @import("qemu.zig");
const gcp = @import("gcp.zig");
const aws = @import("aws.zig");
const azure = @import("azure.zig");
const progress = @import("progress.zig");
const keys = @import("keys.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const Why = howl.Why;
const say = howl.say;
const run = howl.run;
const Platform = howl.Platform;
const machineDir = howl.machineDir;
const notMade = howl.notMade;
const run_name = howl.run_name;
const madeOn = howl.madeOn;
const engine = howl.engine;
const isMachineName = howl.isMachineName;
const flagValue = howl.flagValue;
const testing = std.testing;

/// sshTo is howl ssh [[USER@]NAME] [-- COMMAND...]. It execs ssh as the local user into a
/// machine here, run's without a name: under QEMU on its forwarded port,
/// under Firecracker at its tap address, on Lima at the lease or forwarded
/// port, or on GCP at its external address. Dev Lima runs use the address
/// recorded for their current boot.
pub fn sshTo(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    const line = try sshLine(gpa, args, why);
    var identities: std.ArrayList([]const u8) = .empty;
    for (line.identities) |value| try identities.append(
        gpa,
        Dir.cwd().realPathFileAlloc(io, value, gpa) catch
            return why.refuse("{s}: cannot read identity path", .{value}),
    );
    const explicit_identities = identities.items.len > 0;
    // One word that names no machine is most likely a command: say how.
    if (line.command.len == 0 and line.machine.len == 1 and
        !std.mem.startsWith(u8, line.machine[0], "-"))
    {
        if (Dir.cwd().access(
            io,
            try machineDir(gpa, line.machine[0]),
            .{},
        )) |_| {} else |_| return why.refuse(
            "no machine {s}; a command goes after --: howl ssh -- {s}",
            .{ line.machine[0], line.machine[0] },
        );
    }
    const name, const on = try machineArgs(io, gpa, line.machine, why);
    const user = line.user orelse blk: {
        const local = try keys.currentUserName(io, gpa, why);
        if (!sshUser(local))
            return why.refuse("cannot determine local user; specify USER@NAME", .{});
        break :blk local;
    };
    const dir = try machineDir(gpa, name);
    const dev_marker = Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/dev", .{dir}),
        gpa,
        .limited(32),
    ) catch null;
    const dev_access = dev_marker != null;
    // Lima provisions its own NoCloud identity for the configured user, and
    // developer machines have a howl-managed key. Prefer those credentials
    // over forwarding local FIDO keys when they are available.
    const lima_identity = if (on == .lima and !dev_access and !explicit_identities)
        try lima.sshIdentity(io, gpa, name, user)
    else
        null;
    if (!line.no_agent and !explicit_identities and lima_identity == null and !dev_access)
        if (howl.environ.get("HOME")) |home| try identities.appendSlice(
            gpa,
            try keys.securityIdentities(io, gpa, try std.fs.path.join(gpa, &.{ home, ".ssh" })),
        );
    var login: Login = .{
        .user = user,
        .host = "127.0.0.1",
        .alias = try sshAlias(gpa, name, dev_access),
        .known_hosts = try gpa.print("{s}/known_hosts", .{dir}),
        .agent = identities.items.len > 0,
        .command = line.command,
    };
    if (!explicit_identities and dev_marker != null and !std.mem.eql(u8, dev_marker.?, "custom\n"))
        login.dev_key = try keys.devPrivatePath(io, gpa);
    if (on == .qemu) {
        if (qemu.running(
            io,
            gpa,
            dir,
        ) == null) return why.refuse("no machine {s} running under QEMU", .{name});
        login.port = qemu.record(
            io,
            gpa,
            dir,
            "ssh",
        ) orelse return why.refuse("{s}: no ssh port on record", .{name});
    } else if (on == .bhyve) {
        if (!try bhyve.exists(
            io,
            gpa,
            name,
        )) return why.refuse("no machine {s} running under bhyve", .{name});
        login.host = qemu.record(io, gpa, dir, "host") orelse "127.0.0.1";
        if (!howl.isIp4(login.host))
            return why.refuse("{s}: invalid bhyve address on record", .{name});
        const port = qemu.record(io, gpa, dir, "ssh") orelse
            return why.refuse("{s}: no SSH address on record; recreate it with this howl", .{name});
        const number = std.fmt.parseInt(u16, port, 10) catch 0;
        if (number == 0) return why.refuse("{s}: no SSH listener on record", .{name});
        login.port = port;
    } else if (on == .firecracker) {
        if (dev_access) login.port = "2222";
        login.host = (try firecracker.net(gpa, name)).guest;
    } else if (on == .lima) {
        if (!try lima.exists(io, gpa, name)) return why.refuse("no machine {s} on Lima", .{name});
        // A machine Lima manages has no vzNAT lease of its own: one under its
        // name is an earlier machine's, gone.
        const yaml = Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/lima.yaml", .{dir}),
            gpa,
            .limited(64 << 10),
        ) catch "";
        const managed = lima.isManaged(yaml);
        // Developer SSH has its own listener. Use the address the current
        // boot reported, rather than a lease left by an earlier instance.
        const current = if (dev_access) Dir.cwd().readFileAlloc(
            io,
            try gpa.print("{s}/dev-address", .{dir}),
            gpa,
            .limited(64),
        ) catch null else null;
        const addr = if (dev_access)
            try devAddress(current, why)
        else
            limaAddress(managed, lima.addressOf(io, gpa, name));
        // Lima's NoCloud account accepts its own key, not necessarily ~/.ssh's.
        login.lima_key = lima_identity;
        if (addr) |a| {
            if (dev_access) login.port = "2222";
            login.host = a;
        } else {
            login.port = lima.sshPort(io, gpa, name) orelse
                return why.refuse("{s}: no SSH address available", .{name});
        }
    } else if (on == .gcp) {
        const place = try gcp.place(io, gpa, why);
        if (try gcp.formOf(io, gpa, place, name, why) == null)
            return why.refuse("no machine {s} in GCP zone {s}", .{ name, place.zone });
        try gcp.ensureSshReachable(io, gpa, place, name, why);
        login.host = gcp.address(io, gpa, place, name) orelse
            return why.refuse("{s}: no external SSH address in GCP", .{name});
    } else return why.refuse(
        "ssh reaches machines here (qemu, firecracker, lima, bhyve, gcp); {t}'s address is in " ++
            "create's summary",
        .{on},
    );
    const argv = try sshArgv(gpa, login);
    if (login.agent) return @import("ssh-agent.zig").start(
        io,
        gpa,
        login.known_hosts,
        login.alias,
        user,
        identities.items,
        argv,
        line.command.len,
        why,
    );
    const err = std.process.replace(io, .{ .argv = argv });
    return why.refuse("{s}: {s}", .{ argv[0], @errorName(err) });
}

/// SshLine is howl ssh's line: what names the machine, the account, the
/// identities given, and the command after --.
const SshLine = struct {
    machine: []const []const u8,
    user: ?[]const u8 = null,
    identities: []const []const u8 = &.{},
    no_agent: bool = false,
    command: []const []const u8 = &.{},
};

/// sshLine separates USER@NAME before machineArgs resolves NAME's engine and
/// directory. Words after -- are the command, never a target.
fn sshLine(gpa: Allocator, args: []const []const u8, why: *Why) !SshLine {
    var line: SshLine = .{ .machine = &.{} };
    var rest = args;
    for (args, 0..) |a, i| if (std.mem.eql(u8, a, "--")) {
        rest = args[0..i];
        line.command = args[i + 1 ..];
        break;
    };
    var identities: std.ArrayList([]const u8) = .empty;
    var machine: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        const a = rest[i];
        if (std.mem.eql(u8, a, "--no-agent")) {
            line.no_agent = true;
        } else if (std.mem.eql(u8, a, "--identity") or std.mem.startsWith(u8, a, "--identity=")) {
            _, const value = try flagValue(rest, &i, why);
            try identities.append(gpa, value);
        } else if (std.mem.eql(u8, a, "--on") and i + 1 < rest.len) {
            try machine.appendSlice(gpa, rest[i .. i + 2]);
            i += 1;
        } else if (a.len > 0 and a[0] != '-' and std.mem.findScalar(u8, a, '@') != null) {
            const at = std.mem.findScalar(u8, a, '@').?;
            if (line.user != null or !sshUser(a[0..at]) or !isMachineName(a[at + 1 ..]))
                return why.refuse("{s}: expected USER@NAME", .{a});
            line.user = a[0..at];
            try machine.append(gpa, a[at + 1 ..]);
        } else try machine.append(gpa, a);
    }
    if (line.no_agent and identities.items.len > 0)
        return why.refuse("--no-agent cannot be combined with --identity", .{});
    line.machine = machine.items;
    line.identities = identities.items;
    return line;
}

/// Login is where and how ssh logs in, once sshTo has found the machine.
const Login = struct {
    user: []const u8,
    host: []const u8,
    port: ?[]const u8 = null,
    /// alias names the host key pinned in known_hosts. Developer and
    /// ordinary sshd keep distinct host keys, so their aliases differ too.
    alias: []const u8,
    known_hosts: []const u8,
    /// agent: a dedicated agent offers the selected identities, and nothing
    /// else does.
    agent: bool = false,
    /// dev_key is howl's developer key; lima_key, Lima's NoCloud identity.
    dev_key: ?[]const u8 = null,
    lima_key: ?[]const u8 = null,
    command: []const []const u8 = &.{},
};

/// sshArgv is ssh's argv for l. The guest keeps its host key in /data, so
/// first use trusts it and pins it by name in the machine's directory, not
/// by an address another machine may get later; delete removes both pins.
/// A dedicated agent requires the pin, and ignores every other config and key.
fn sshArgv(gpa: Allocator, l: Login) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(gpa, "ssh");
    if (l.port) |p| try argv.appendSlice(gpa, &.{ "-p", p });
    try argv.appendSlice(gpa, &.{
        "-o",
        if (l.agent) "StrictHostKeyChecking=yes" else "StrictHostKeyChecking=accept-new",
        "-o",
        try gpa.print("UserKnownHostsFile={s}", .{l.known_hosts}),
        "-o",
        try gpa.print("HostKeyAlias={s}", .{l.alias}),
        "-o",
        "LogLevel=ERROR",
    });
    if (l.agent) try argv.appendSlice(gpa, &.{
        "-F",                             "/dev/null",
        "-S",                             "none",
        "-A",                             "-o",
        "IdentityAgent=SSH_AUTH_SOCK",    "-o",
        "IdentityFile=none",              "-o",
        "GlobalKnownHostsFile=/dev/null",
    }) else try argv.append(gpa, "-a");
    if (l.dev_key) |key| try argv.appendSlice(gpa, &.{ "-i", key, "-o", "IdentitiesOnly=yes" });
    if (l.lima_key) |key| try argv.appendSlice(gpa, &.{ "-i", key });
    try argv.append(gpa, try gpa.print("{s}@{s}", .{ l.user, l.host }));
    try argv.appendSlice(gpa, l.command);
    return argv.items;
}

fn sshAlias(gpa: Allocator, name: []const u8, developer: bool) ![]const u8 {
    return gpa.print("{s}{s}", .{ name, if (developer) "-dev" else "" });
}

/// A developer VM's address comes from its current boot, not an older
/// instance's DHCP lease. Host keys remain pinned in the machine directory.
fn devAddress(current: ?[]const u8, why: *Why) ![]const u8 {
    const addr = current orelse return why.refuse(
        "no developer VM address; run howl run again",
        .{},
    );
    _ = std.Io.net.Ip4Address.parse(addr, 0) catch
        return why.refuse("invalid developer VM address", .{});
    return addr;
}

/// Managed Lima VMs use their forwarded SSH port rather than a vzNAT lease.
fn limaAddress(managed: bool, address: ?[]const u8) ?[]const u8 {
    return if (managed) null else address;
}

test "Lima SSH uses a current developer address and ignores managed leases" {
    const stale = "192.168.64.36";
    try testing.expectEqual(@as(?[]const u8, null), limaAddress(true, stale));
    try testing.expectEqualStrings(stale, limaAddress(false, stale).?);
    var why: Why = .{};
    try testing.expectEqualStrings("192.168.64.40", try devAddress("192.168.64.40", &why));
    try testing.expectError(error.Refused, devAddress(null, &why));
    try testing.expectError(error.Refused, devAddress("-oProxyCommand=bad", &why));
}

fn sshUser(user: []const u8) bool {
    if (user.len == 0 or user[0] == '-') return false;
    for (user) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and
        c != '.') return false;
    return true;
}

/// Stop keeps a named QEMU disk and every protected machine's authority. The
/// unnamed legacy `howl run` machine retains its historical remove-on-stop.
pub fn stopHere(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    var named = false;
    var option_value = false;
    for (args) |arg| {
        if (option_value) {
            option_value = false;
            continue;
        }
        if (std.mem.eql(u8, arg, "--on")) {
            option_value = true;
            continue;
        }
        if (arg.len > 0 and arg[0] != '-') named = true;
    }
    const name, const on = if (args.len == 0)
        .{
            run_name,
            madeOn(io, gpa, run_name) orelse return why.refuse("no machine from howl run", .{}),
        }
    else
        try machineArgs(io, gpa, args, why);
    if (on == .firecracker) {
        if (madeOn(io, gpa, name) != .firecracker) return notMade(name, on, why);
        const dir = try machineDir(gpa, name);
        if (firecracker.running(io, gpa, dir)) |pid|
            try firecracker.stop(io, gpa, dir, pid, why);
        const pinned = if (Dir.cwd().access(
            io,
            try gpa.print("{s}/{s}", .{ dir, firecracker.trust_file }),
            .{},
        )) |_|
            true
        else |err| switch (err) {
            error.FileNotFound => false,
            else => return err,
        };
        if (!named and !pinned) {
            try remove(io, gpa, name, on, why);
            say(io, "{s}: stopped and removed", .{name});
        } else say(io, "{s}: stopped; its disk and boot trust stay", .{name});
        return;
    }
    const secured = try @import("local-secure.zig").stop(io, gpa, name, on, why);
    if (named) {
        if (!secured) {
            if (on == .bhyve) {
                try bhyve.stop(io, gpa, name, try machineDir(gpa, name));
            } else if (on != .qemu) return why.refuse(
                "stop NAME currently supports a local QEMU or bhyve machine",
                .{},
            ) else if (!try qemu.stop(io, gpa, try machineDir(gpa, name)))
                return why.refuse("no machine {s} running under QEMU", .{name});
        }
        say(io, "{s}: stopped; its disk stays", .{name});
        return;
    }
    if (!secured) try remove(io, gpa, name, on, why);
    const look: progress.Look = .of(io, Io.File.stderr());
    try Io.File.stderr().writeStreamingAll(
        io,
        try gpa.print(
            "{s} Stopped {s}, the machine howl run kept\n",
            .{ look.check(), name },
        ),
    );
}

/// machineArgs parses NAME and --on for delete, console and ssh.
fn machineArgs(
    io: Io,
    gpa: Allocator,
    args: []const []const u8,
    why: *Why,
) !struct { []const u8, Platform } {
    const syntax = "[NAME] [--on " ++ comptime Platform.list(.made, "|") ++ "]";
    var name: ?[]const u8 = null;
    var on: ?Platform = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (args[i].len > 0 and args[i][0] == '-') {
            const flag, const value = try flagValue(args, &i, why);
            if (!std.mem.eql(u8, flag, "--on") or on != null)
                return why.refuse("{s}: {s}", .{ flag, syntax });
            const p = std.meta.stringToEnum(Platform, value) orelse .disk;
            if (!p.is(.made)) return why.refuse("--on {s}: {s}", .{ value, syntax });
            on = p;
        } else if (name == null) {
            name = args[i];
        } else return why.refuse("{s}: {s}", .{ args[i], syntax });
    }
    // No name means the machine howl run keeps.
    const n = name orelse run_name;
    if (!isMachineName(n)) return why.refuse("{s}: not a machine's name", .{n});
    // Without --on, use the platform create recorded, else the default.
    return .{ n, on orelse madeOn(io, gpa, n) orelse engine(io, gpa, null).on };
}

pub fn delete(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    const name, const on = try machineArgs(io, gpa, args, why);
    try remove(io, gpa, name, on, why);
    say(io, "{s}: deleted, with its /data", .{name});
}

/// remove deletes machine name on platform on, with its disks and its
/// files here; the caller reports it. It refuses a machine whose form label
/// or tag is missing: howl create did not make it, so it is not howl's.
pub fn remove(io: Io, gpa: Allocator, name: []const u8, on: Platform, why: *Why) !void {
    const dir = try machineDir(gpa, name);
    switch (on) {
        .qemu => {
            _ = try qemu.stop(io, gpa, dir);
            try @import("local-secure.zig").stopTpm(io, gpa, dir);
        },
        .gcp => {
            // Delete the VM and its disk, not the image, which others may share.
            const p = try gcp.place(io, gpa, why);
            if (try gcp.formOf(io, gpa, p, name, why)) |was| {
                if (was.len == 0) return notMade(name, .gcp, why);
                try gcp.delete(io, gpa, p, name, why);
            }
        },
        .aws => {
            // Delete the instance, its volume and security group, not the AMI.
            const p = try aws.place(io, gpa, why);
            const i = try aws.find(io, gpa, p, name, why);
            if (i) |m| if (m.form.len == 0) return notMade(name, .aws, why);
            try aws.delete(io, gpa, p, name, i, why);
        },
        .azure => {
            // Delete the VM, its disk, NIC and network, not the image.
            const p = try azure.place(io, gpa, why);
            const vm = try azure.find(io, gpa, p, name, why);
            if (vm) |v| if (v.form.len == 0) return notMade(name, .azure, why);
            try azure.delete(io, gpa, p, name, vm, why);
        },
        .proxmox => {
            // Delete the VM and disks, not the image, which others may share.
            const p = try proxmox.place(howl.environ, why);
            const vm = try proxmox.find(io, gpa, p, name, why);
            if (vm) |m| try proxmox.delete(io, gpa, p, m, name, why);
        },
        .firecracker => {
            // Remove the tar first, so the supervisor does not boot it
            // again; then kill Firecracker; then remove its network as root.
            Dir.cwd().deleteFile(io, try gpa.print("{s}/config.tar", .{dir})) catch {};
            if (firecracker.running(
                io,
                gpa,
                dir,
            )) |pid| try firecracker.stop(io, gpa, dir, pid, why);
            if (firecracker.asRoot(io, gpa)) |root|
                firecracker.networkDown(io, gpa, root, try firecracker.net(gpa, name))
            else |_|
                say(io, "{s}: no sudo or doas, so its tap device and rules stay", .{name});
        },
        .bhyve => {
            // Wait for the supervisor and remove only this VM's owned TAP.
            if (!try @import("local-secure.zig").stop(io, gpa, name, on, why))
                try bhyve.stop(io, gpa, name, dir);
        },
        .lima => {
            if (try lima.exists(io, gpa, name)) {
                const d = try lima.dir(io, gpa, name) orelse
                    return why.refuse("no machine {s}", .{name});
                const yaml = Dir.cwd().readFileAlloc(
                    io,
                    try gpa.print("{s}/lima.yaml", .{d}),
                    gpa,
                    .limited(1 << 20),
                ) catch |err| return why.refuse("{s}/lima.yaml: {s}", .{ d, @errorName(err) });
                if (lima.formOf(yaml) == null) return notMade(name, .lima, why);
                // Run quietly; on failure, report limactl's last output.
                const r = std.process.run(gpa, io, .{
                    .argv = &.{ "limactl", "delete", "-f", name },
                }) catch |err| return why.refuse("limactl: {s}", .{@errorName(err)});
                if (r.term != .exited or r.term.exited != 0) {
                    const said = std.mem.trim(
                        u8,
                        if (r.stderr.len > 0) r.stderr else r.stdout,
                        " \n",
                    );
                    return why.refuse("limactl failed: {s}", .{said[said.len -| 400..]});
                }
            }
            _ = std.process.run(gpa, io, .{
                .argv = &.{ "limactl", "disk", "delete", try gpa.print("{s}-config", .{name}) },
            }) catch {};
            _ = std.process.run(gpa, io, .{
                .argv = &.{ "limactl", "disk", "delete", try gpa.print("{s}-import", .{name}) },
            }) catch {};
        },
        .disk => unreachable,
    }
    // Remove what create kept: the disks, and the config tar, which holds
    // secrets.
    Dir.cwd().deleteTree(io, dir) catch {};
}

pub fn console(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    const name, const on = try machineArgs(io, gpa, args, why);
    const d = try machineDir(gpa, name);
    if (on == .qemu) {
        if (qemu.running(io, gpa, d) == null) return why.refuse(
            "no machine {s} running under QEMU{s}",
            .{ name, if (std.mem.eql(u8, name, run_name)) ": howl run --with FORM" else "" },
        );
        return qemu.attach(io, gpa, d);
    }
    if (on == .gcp) {
        const p = try gcp.place(io, gpa, why);
        const text = gcp.console(
            io,
            gpa,
            p,
            name,
        ) orelse return why.refuse("no machine {s} in {s}", .{ name, p.zone });
        return show(io, gpa, text[text.len -| (64 << 10)..]);
    }
    if (on == .aws) {
        const p = try aws.place(io, gpa, why);
        const i = try aws.find(io, gpa, p, name, why) orelse
            return why.refuse("no machine {s} in {s}", .{ name, p.region });
        const text = aws.console(io, gpa, p, i.id) orelse
            return why.refuse("{s}: no console yet; AWS keeps it from shortly after boot", .{name});
        return show(io, gpa, text);
    }
    if (on == .azure) {
        const p = try azure.place(io, gpa, why);
        const text = azure.console(io, gpa, p, name) orelse
            return why.refuse("no machine {s} in {s}, or no boot diagnostics", .{ name, p.group });
        return show(io, gpa, text[text.len -| (64 << 10)..]);
    }
    if (on == .proxmox) {
        const p = try proxmox.place(howl.environ, why);
        const text = proxmox.console(io, gpa, p, name, 0) orelse
            return why.refuse("no console for {s} on {s}", .{ name, p.host });
        return show(io, gpa, text[text.len -| (64 << 10)..]);
    }
    const path = if (on == .bhyve or on == .firecracker)
        try gpa.print("{s}/console.log", .{d})
    else
        try gpa.print("{s}/{s}", .{
            try lima.dir(io, gpa, name) orelse return why.refuse("no machine {s}", .{name}),
            if (Dir.cwd().access(io, try gpa.print("{s}/authority/enrolled", .{d}), .{})) |_|
                "serial.log"
            else |_|
                "serialv.log",
        });
    const text = Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 << 20)) catch |err|
        return why.refuse("{s}: {s}", .{ path, @errorName(err) });
    // Show the last 64 KiB: the boot and what followed.
    try show(io, gpa, text[text.len -| (64 << 10)..]);
}

/// show writes a guest's console text to stdout. To a terminal it drops
/// control characters (inert), since the guest wrote them and could
/// otherwise drive the terminal; to a pipe or file it writes text as is.
pub fn show(io: Io, gpa: Allocator, text: []const u8) !void {
    const out = Io.File.stdout();
    try out.writeStreamingAll(io, if (out.isTty(io) catch false) try inert(gpa, text) else text);
}

/// inert returns a copy of text that is safe to print to a terminal
/// (howl.inert), so a machine's output cannot send it an escape sequence.
fn inert(gpa: Allocator, text: []const u8) ![]const u8 {
    const out = try gpa.dupe(u8, text);
    return gpa.realloc(out, howl.inert(out).len);
}

test inert {
    const a = testing.allocator;
    const got = try inert(a, "ok\x1b]0;title\x07 \x1b[2Jdone\r\n\xc2\x9b31m\xc3\xa9\ttab\x7f");
    defer a.free(got);
    try testing.expectEqualStrings("ok]0;title [2Jdone\n31m\xc3\xa9\ttab", got);
    // Raw C1 (CSI), a stray continuation byte, a bad lead byte and a
    // truncated sequence go; a three-byte character stays whole.
    const raw = try inert(a, "a\x9b2Jb\x88c\xffd\xe2\x88\x91e\xe2\x88");
    defer a.free(raw);
    try testing.expectEqualStrings("a2Jbcd\xe2\x88\x91e", raw);
}

test "developer and ordinary SSH host keys have distinct aliases" {
    const a = testing.allocator;
    const ordinary = try sshAlias(a, "edge", false);
    defer a.free(ordinary);
    const developer = try sshAlias(a, "edge", true);
    defer a.free(developer);
    try testing.expectEqualStrings("edge", ordinary);
    try testing.expectEqualStrings("edge-dev", developer);
}

test "ssh lines separate the account, the identities and the command" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var why: Why = .{};
    const root = try sshLine(gpa, &.{ "root@werewolf-run", "--", "id", "-u" }, &why);
    try testing.expectEqualStrings("root", root.user.?);
    try testing.expectEqualStrings("werewolf-run", try std.mem.join(gpa, " ", root.machine));
    try testing.expectEqualStrings("id -u", try std.mem.join(gpa, " ", root.command));
    // A command's own USER@HOST is the command's, not a second target.
    const alice = try sshLine(
        gpa,
        &.{ "--on=lima", "alice@werewolf-run", "--", "echo", "root@other" },
        &why,
    );
    try testing.expectEqualStrings("alice", alice.user.?);
    try testing.expectEqualStrings(
        "--on=lima werewolf-run",
        try std.mem.join(gpa, " ", alice.machine),
    );
    try testing.expectEqualStrings("echo root@other", try std.mem.join(gpa, " ", alice.command));
    const on = try sshLine(gpa, &.{ "--on", "gcp", "root@werewolf-run" }, &why);
    try testing.expectEqualStrings("--on gcp werewolf-run", try std.mem.join(gpa, " ", on.machine));
    const named = try sshLine(
        gpa,
        &.{ "alice@werewolf-run", "--identity", "admin key", "--identity=second;key" },
        &why,
    );
    try testing.expectEqualStrings(
        "admin key|second;key",
        try std.mem.join(gpa, "|", named.identities),
    );
    try testing.expectEqualStrings("werewolf-run", try std.mem.join(gpa, " ", named.machine));
    const plain = try sshLine(gpa, &.{"--no-agent"}, &why);
    try testing.expect(plain.no_agent and plain.user == null and plain.machine.len == 0);
    for ([_][]const []const u8{
        &.{"@werewolf-run"},
        &.{"root@"},
        &.{"root@@werewolf-run"},
        &.{"root@../werewolf-run"},
        &.{ "root@werewolf-run", "alice@werewolf-run" },
        &.{"--identity"},
        &.{ "--no-agent", "--identity", "key" },
    }) |line| try testing.expectError(error.Refused, sshLine(gpa, line, &why));
}

test "ssh pins the host key by name and offers only the identities chosen" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const pin = "-o UserKnownHostsFile=build/machines/werewolf-run/known_hosts " ++
        "-o HostKeyAlias=werewolf-run";
    const run_login: Login = .{
        .user = "alice",
        .host = "127.0.0.1",
        .port = "60022",
        .alias = "werewolf-run",
        .known_hosts = "build/machines/werewolf-run/known_hosts",
    };
    // Lima's forwarded port, with its NoCloud identity.
    var lima_login = run_login;
    lima_login.lima_key = "/test/lima-key";
    try testing.expectEqualStrings(
        "ssh -p 60022 -o StrictHostKeyChecking=accept-new " ++ pin ++
            " -o LogLevel=ERROR -a -i /test/lima-key alice@127.0.0.1",
        try std.mem.join(gpa, " ", try sshArgv(gpa, lima_login)),
    );
    // Root, with a command and no identity of howl's choosing.
    var root = run_login;
    root.user = "root";
    root.command = &.{ "id", "-u" };
    try testing.expectEqualStrings(
        "ssh -p 60022 -o StrictHostKeyChecking=accept-new " ++ pin ++
            " -o LogLevel=ERROR -a root@127.0.0.1 id -u",
        try std.mem.join(gpa, " ", try sshArgv(gpa, root)),
    );
    // Developer SSH: its own listener, host key and howl's key.
    try testing.expectEqualStrings(
        "ssh -p 2222 -o StrictHostKeyChecking=accept-new " ++
            "-o UserKnownHostsFile=build/machines/werewolf-run/known_hosts " ++
            "-o HostKeyAlias=werewolf-run-dev -o LogLevel=ERROR -a " ++
            "-i /keys/dev/ssh-ed25519 -o IdentitiesOnly=yes alice@192.168.64.40",
        try std.mem.join(gpa, " ", try sshArgv(gpa, .{
            .user = "alice",
            .host = "192.168.64.40",
            .port = "2222",
            .alias = try sshAlias(gpa, "werewolf-run", true),
            .known_hosts = "build/machines/werewolf-run/known_hosts",
            .dev_key = "/keys/dev/ssh-ed25519",
        })),
    );
    // A dedicated agent: the pin must exist, and no config, file or other
    // agent offers a key.
    try testing.expectEqualStrings(
        "ssh -o StrictHostKeyChecking=yes " ++ pin ++ " -o LogLevel=ERROR -F /dev/null " ++
            "-S none -A -o IdentityAgent=SSH_AUTH_SOCK -o IdentityFile=none " ++
            "-o GlobalKnownHostsFile=/dev/null alice@203.0.113.20 printf literal;command",
        try std.mem.join(gpa, " ", try sshArgv(gpa, .{
            .user = "alice",
            .host = "203.0.113.20",
            .alias = "werewolf-run",
            .known_hosts = "build/machines/werewolf-run/known_hosts",
            .agent = true,
            .command = &.{ "printf", "literal;command" },
        })),
    );
}

test {
    _ = @import("ssh-agent.zig");
}
