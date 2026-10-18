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

/// sshTo is howl ssh [NAME] [-- COMMAND...]. It execs ssh as root into a
/// machine here, run's without a name: under QEMU on its forwarded port,
/// under Firecracker at its tap address, and on Lima at the lease or forwarded
/// port. Dev Lima runs use the address recorded for their current boot.
pub fn sshTo(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    var rest: []const []const u8 = args;
    var command: []const []const u8 = &.{};
    for (args, 0..) |a, i| if (std.mem.eql(u8, a, "--")) {
        rest = args[0..i];
        command = args[i + 1 ..];
        break;
    };
    // One word that names no machine is most likely a command: say how.
    if (command.len == 0 and rest.len == 1 and !std.mem.startsWith(u8, rest[0], "-")) {
        if (Dir.cwd().access(
            io,
            try machineDir(gpa, rest[0]),
            .{},
        )) |_| {} else |_| return why.refuse(
            "no machine {s}; a command goes after --: howl ssh -- {s}",
            .{ rest[0], rest[0] },
        );
    }
    const name, const on = try machineArgs(io, gpa, rest, why);
    const dir = try machineDir(gpa, name);
    const dev_marker = Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/dev", .{dir}),
        gpa,
        .limited(32),
    ) catch null;
    const dev_access = dev_marker != null;
    // The guest keeps its host key in /data, so trust it on first use and
    // pin it by name in the machine's directory, not by an address another
    // machine may get later. Developer and ordinary sshd use distinct host
    // keys, so their aliases are distinct too. delete removes both.
    var pinned: std.ArrayList([]const u8) = .empty;
    try pinned.appendSlice(gpa, &.{
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", try gpa.print("UserKnownHostsFile={s}/known_hosts", .{dir}),
        "-o", try gpa.print("HostKeyAlias={s}", .{try sshAlias(gpa, name, dev_access)}),
        "-o", "LogLevel=ERROR",
    });
    if (dev_marker != null and !std.mem.eql(u8, dev_marker.?, "custom\n")) {
        try pinned.appendSlice(gpa, &.{
            "-i", try @import("keys.zig").devPrivatePath(io, gpa),
            "-o", "IdentitiesOnly=yes",
        });
    }
    var argv: std.ArrayList([]const u8) = .empty;
    if (on == .qemu) {
        if (qemu.running(
            io,
            gpa,
            dir,
        ) == null) return why.refuse("no machine {s} running under QEMU", .{name});
        const port = qemu.record(
            io,
            gpa,
            dir,
            "ssh",
        ) orelse return why.refuse("{s}: no ssh port on record", .{name});
        try argv.appendSlice(gpa, &.{ "ssh", "-p", port });
        try argv.appendSlice(gpa, pinned.items);
        try argv.append(gpa, "root@127.0.0.1");
    } else if (on == .bhyve) {
        if (!try bhyve.exists(
            io,
            gpa,
            name,
        )) return why.refuse("no machine {s} running under bhyve", .{name});
        const host = qemu.record(io, gpa, dir, "host") orelse "127.0.0.1";
        if (!howl.isIp4(host)) return why.refuse("{s}: invalid bhyve address on record", .{name});
        const port = qemu.record(io, gpa, dir, "ssh") orelse
            return why.refuse("{s}: no SSH address on record; recreate it with this howl", .{name});
        const number = std.fmt.parseInt(u16, port, 10) catch 0;
        if (number == 0) return why.refuse("{s}: no SSH listener on record", .{name});
        try argv.appendSlice(gpa, &.{ "ssh", "-p", port });
        try argv.appendSlice(gpa, pinned.items);
        try argv.append(gpa, try gpa.print("root@{s}", .{host}));
    } else if (on == .firecracker) {
        try argv.append(gpa, "ssh");
        if (dev_access) try argv.appendSlice(gpa, &.{ "-p", "2222" });
        try argv.appendSlice(gpa, pinned.items);
        try argv.append(gpa, try gpa.print("root@{s}", .{(try firecracker.net(gpa, name)).guest}));
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
        // Root, by Lima's forwarded port, when its config tar gave root keys.
        const secured = std.mem.find(u8, yaml, "# werewolf lima: secure\n") != null;
        const port = if (dev_access or ((managed or secured) and try rootKeyed(io, gpa, dir)))
            lima.sshPort(io, gpa, name)
        else
            null;
        if (addr) |a| {
            try argv.append(gpa, "ssh");
            if (dev_access) try argv.appendSlice(gpa, &.{ "-p", "2222" });
            try argv.appendSlice(gpa, pinned.items);
            try argv.append(gpa, try gpa.print("root@{s}", .{a}));
        } else if (port) |p| {
            try argv.appendSlice(gpa, &.{ "ssh", "-p", p });
            try argv.appendSlice(gpa, pinned.items);
            try argv.append(gpa, "root@127.0.0.1");
        } else {
            try argv.appendSlice(gpa, &.{ "limactl", "shell", name });
            // ssh hands the guest's shell the command's words joined; so
            // does this, where limactl would run them as one program.
            if (command.len > 0) try argv.appendSlice(gpa, &.{
                "sh",
                "-c",
                try std.mem.join(gpa, " ", command),
            });
            command = &.{};
        }
    } else return why.refuse(
        "ssh reaches machines here (qemu, firecracker, lima, bhyve); {t}'s address is in " ++
            "create's summary",
        .{on},
    );
    try argv.appendSlice(gpa, command);
    const err = std.process.replace(io, .{ .argv = argv.items });
    return why.refuse("{s}: {s}", .{ argv.items[0], @errorName(err) });
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

/// rootKeyed reports whether the config tar in dir gives root keys.
fn rootKeyed(io: Io, gpa: Allocator, dir: []const u8) !bool {
    const tar = Dir.cwd().readFileAlloc(
        io,
        try gpa.print("{s}/config.tar", .{dir}),
        gpa,
        .limited(64 << 20),
    ) catch return false;
    var r: Io.Reader = .fixed(tar);
    var name_buf: [Dir.max_path_bytes]u8 = undefined;
    var link_buf: [Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(
        &r,
        .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
    );
    while (it.next() catch return false) |e| {
        if (std.mem.eql(u8, e.name, "authorized_keys")) return true;
    }
    return false;
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
    if (on == .lima or on == .qemu or
        on == .bhyve) @import("local-secure.zig").stopPublisher(io, gpa, dir);
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
