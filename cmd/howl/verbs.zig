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
/// under Firecracker at its tap address, on Lima at its DHCP lease address,
/// or through limactl shell when Lima gives no address.
pub fn sshTo(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    var rest: []const []const u8 = args;
    var command: []const []const u8 = &.{};
    for (args, 0..) |a, i| if (std.mem.eql(u8, a, "--")) {
        rest = args[0..i];
        command = args[i + 1 ..];
        break;
    };
    const name, const on = try machineArgs(io, gpa, rest, why);
    const dir = try machineDir(gpa, name);
    // The guest keeps its host key in /data, so trust it on first use and
    // pin it by name in the machine's directory, not by an address another
    // machine may get later. delete removes it with the machine.
    const pinned = [_][]const u8{
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", try gpa.print("UserKnownHostsFile={s}/known_hosts", .{dir}),
        "-o", try gpa.print("HostKeyAlias={s}", .{name}),
        "-o", "LogLevel=ERROR",
    };
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
        try argv.appendSlice(gpa, &pinned);
        try argv.append(gpa, "root@127.0.0.1");
    } else if (on == .firecracker) {
        try argv.append(gpa, "ssh");
        try argv.appendSlice(gpa, &pinned);
        try argv.append(gpa, try gpa.print("root@{s}", .{(try firecracker.net(gpa, name)).guest}));
    } else if (on == .lima) {
        if (!try lima.exists(io, gpa, name)) return why.refuse("no machine {s} on Lima", .{name});
        if (lima.addressOf(io, gpa, name)) |addr| {
            try argv.append(gpa, "ssh");
            try argv.appendSlice(gpa, &pinned);
            try argv.append(gpa, try gpa.print("root@{s}", .{addr}));
        } else try argv.appendSlice(gpa, &.{ "limactl", "shell", name });
    } else return why.refuse(
        "ssh reaches machines here (qemu, firecracker, lima); {t}'s address is in create's summary",
        .{on},
    );
    try argv.appendSlice(gpa, command);
    const err = std.process.replace(io, .{ .argv = argv.items });
    return why.refuse("{s}: {s}", .{ argv.items[0], @errorName(err) });
}

/// stopHere is howl stop. It removes the machine howl run keeps, wherever
/// it runs.
pub fn stopHere(io: Io, gpa: Allocator, args: []const []const u8, why: *Why) !void {
    if (args.len > 0) return why.refuse(
        "stop takes nothing: it ends howl run's machine; delete NAME ends another",
        .{},
    );
    const on = madeOn(
        io,
        gpa,
        run_name,
    ) orelse return why.refuse("no machine from howl run", .{});
    try remove(io, gpa, run_name, on, why);
    const look: progress.Look = .of(io, Io.File.stderr());
    try Io.File.stderr().writeStreamingAll(
        io,
        try gpa.print(
            "{s} Stopped {s}, the machine howl run kept\n",
            .{ look.check(), run_name },
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
        .qemu => _ = try qemu.stop(io, gpa, dir),
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
            // Destroying the VM makes bhyve exit, and its supervisor with it.
            if (try bhyve.exists(io, gpa, name)) {
                const root = bhyve.asRoot(io) catch
                    return why.refuse("bhyve needs root, and there is no doas or sudo", .{});
                try run(
                    io,
                    why,
                    try std.mem.concat(gpa, []const u8, &.{ root, try bhyve.destroy(gpa, name) }),
                );
            }
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
        try gpa.print("{s}/serialv.log", .{
            try lima.dir(io, gpa, name) orelse return why.refuse("no machine {s}", .{name}),
        });
    const text = Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 << 20)) catch |err|
        return why.refuse("{s}: {s}", .{ path, @errorName(err) });
    // Show the last 64 KiB: the boot and what followed.
    try show(io, gpa, text[text.len -| (64 << 10)..]);
}

/// show writes a guest's console text to stdout. To a terminal it drops
/// control characters (inert), since the guest wrote them and could
/// otherwise drive the terminal; to a pipe or file it writes text as is.
fn show(io: Io, gpa: Allocator, text: []const u8) !void {
    const out = Io.File.stdout();
    try out.writeStreamingAll(io, if (out.isTty(io) catch false) try inert(gpa, text) else text);
}

/// inert returns text that is safe to print to a terminal: valid UTF-8 with
/// no control characters but newline and tab (no C0, DEL or C1), so a
/// machine's output cannot send the terminal an escape sequence. Bytes that
/// are not valid UTF-8 are dropped too: a lone 0x9b is CSI to a terminal
/// that reads 8-bit controls.
fn inert(gpa: Allocator, text: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = try .initCapacity(gpa, text.len);
    var i: usize = 0;
    while (i < text.len) {
        const n = std.unicode.utf8ByteSequenceLength(text[i]) catch {
            i += 1;
            continue;
        };
        if (n > text.len - i) break;
        const seq = text[i..][0..n];
        if (!std.unicode.utf8ValidateSlice(seq)) {
            i += 1;
            continue;
        }
        i += n;
        const c = seq[0];
        // C1 controls, U+0080 to U+009F, are 0xc2 0x80 to 0xc2 0x9f.
        const control = switch (n) {
            1 => (c < 0x20 and c != '\n' and c != '\t') or c == 0x7f,
            2 => c == 0xc2 and seq[1] <= 0x9f,
            else => false,
        };
        if (!control) out.appendSliceAssumeCapacity(seq);
    }
    return out.toOwnedSlice(gpa);
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
