//! bhyve: a werewolf machine as a bhyve VM on FreeBSD, experimental, from
//! the same two files every target takes: a boot disk, which bhyve's UEFI
//! firmware boots, and the config tar, attached as a second, read-only
//! virtio disk, where init finds it.
//!
//! bhyve is a process, not a service: it runs until the guest halts, and
//! exits 0 when the guest asks to reboot, to be run again. So create
//! starts it under daemon(8), detached, with its console on the machine's
//! console.log, through werewolf's own supervisor (`werewolf _bhyve`),
//! which runs bhyve again on a reboot and destroys the VM when it stops.
//! bhyve needs root, so what runs it goes through doas or sudo. The
//! machine is on slirp's network, as QEMU's user network is: the host
//! reaches it only through the ports slirp forwards, one host port per
//! port the form listens on, from a base the name's sha256 picks. bhyve
//! is the state: /dev/vmm/NAME exists while the VM does, and nothing here
//! remembers more than the form, in the machine's directory.
//!
//! x86_64 alone: bhyve on arm64 is new in FreeBSD 15, with other firmware
//! and flags, and is not built here yet.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// bhyve's UEFI firmware, from the bhyve-firmware package.
pub const firmware = "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd";
/// slirp's network, as every machine has it: the address slirp gives
/// the guest, its gateway, and its DNS, for a form with no DHCP client.
pub const user_ip = "10.0.2.15/24";
pub const user_gw = "10.0.2.2";
pub const user_dns = "10.0.2.3";

/// Whether this machine runs bhyve: FreeBSD on x86_64, with vmm loaded
/// (/dev/vmmctl; kldload vmm).
pub fn installed(io: Io) bool {
    if (builtin.os.tag != .freebsd or builtin.cpu.arch != .x86_64) return false;
    Dir.cwd().access(io, "/dev/vmmctl", .{}) catch return false;
    return true;
}

/// Whether bhyve has a VM named name: it exists from its first run until
/// bhyvectl --destroy.
pub fn exists(io: Io, gpa: Allocator, name: []const u8) !bool {
    Dir.cwd().access(io, try gpa.print("/dev/vmm/{s}", .{name}), .{}) catch return false;
    return true;
}

/// What runs bhyve, which needs root: nothing as root, else doas, or
/// sudo, from the ports, where FreeBSD keeps them.
pub fn asRoot(io: Io) error{NoRoot}![]const []const u8 {
    if (isRoot()) return &.{};
    inline for (.{ "doas", "sudo" }) |tool| {
        if (Dir.cwd().access(io, "/usr/local/bin/" ++ tool, .{})) |_| return &.{tool} else |_| {}
    }
    return error.NoRoot;
}

fn isRoot() bool {
    return switch (builtin.os.tag) {
        .linux => std.os.linux.geteuid() == 0,
        else => std.c.geteuid() == 0,
    };
}

/// A port slirp forwards: this host's 127.0.0.1:host to the machine's guest.
pub const Forward = struct { host: u16, guest: u16 };

/// The forwards for a machine named name, one per port it listens on: the
/// ports from a base the name's sha256 picks, 20000 to 59900 by hundreds,
/// so two machines rarely collide and a name always gets the same ports.
pub fn forwards(gpa: Allocator, name: []const u8, ports: []const u16) ![]const Forward {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(name, &h, .{});
    const base: u16 = 20000 + (std.mem.readInt(u16, h[0..2], .big) % 400) * 100;
    const out = try gpa.alloc(Forward, @min(ports.len, 100));
    for (out, ports[0..out.len], 0..) |*f, p, i| f.* = .{
        .host = base + @as(u16, @intCast(i)),
        .guest = p,
    };
    return out;
}

/// bhyve's arguments for the machine: two CPUs and 2 GiB, as Lima's
/// machines have; the disk and the config tar on virtio, the tar read-only;
/// slirp with the forwards, open, so the machine reaches out, as updates
/// need, and so that slirp's helper, which bhyve runs apart since 15.1,
/// skips capability mode: in it, as root, its getpwnam(nobody) fails and
/// it dies, and bhyve with it at the first packet, of SIGPIPE; a random
/// number device; the serial console on bhyve's standard output, which the
/// supervisor's log keeps; and the UEFI firmware, which boots the disk.
/// Linux wants -w, since it reads MSRs bhyve does not have; -H yields the
/// host's CPU when the guest idles; -u keeps the clock in UTC. No -A:
/// FreeBSD 15 always makes ACPI tables and dropped the flag.
pub fn argv(
    gpa: Allocator,
    name: []const u8,
    disk: []const u8,
    config: []const u8,
    fwds: []const Forward,
) ![]const []const u8 {
    var net: std.ArrayList(u8) = .empty;
    try net.appendSlice(gpa, "virtio-net,slirp,open");
    for (fwds, 0..) |f, i| try net.print(
        gpa,
        "{s}tcp:127.0.0.1:{d}-:{d}",
        .{ if (i == 0) ",hostfwd=" else ";", f.host, f.guest },
    );
    return try gpa.dupe([]const u8, &.{
        "bhyve",
        "-H",
        "-w",
        "-u",
        "-c",
        "2",
        "-m",
        "2048M",
        "-s",
        "0,hostbridge",
        "-s",
        "1,lpc",
        "-s",
        try gpa.print("2,{s}", .{net.items}),
        "-s",
        try gpa.print("3,virtio-blk,{s}", .{disk}),
        "-s",
        try gpa.print("4,virtio-blk,{s},ro", .{config}),
        "-s",
        "5,virtio-rnd",
        "-l",
        "com1,stdio",
        "-l",
        "bootrom," ++ firmware,
        name,
    });
}

/// bhyvectl's arguments to destroy the VM named name, which ends its
/// bhyve, and so its supervisor.
pub fn destroy(gpa: Allocator, name: []const u8) ![]const []const u8 {
    return try gpa.dupe(
        []const u8,
        &.{ "bhyvectl", try gpa.print("--vm={s}", .{name}), "--destroy" },
    );
}

/// The supervisor, `werewolf _bhyve NAME CONFIG BHYVE...`, under daemon(8)
/// as root: runs bhyve, whose console is this process's standard output,
/// with its standard input a pipe held open and never written, so the
/// console reads nothing. bhyve exits 0 when the guest asks to reboot, and
/// is run again once the VM is destroyed, as bhyve wants, so long as the
/// machine's config tar is still there: delete removes it. A halt ends the
/// machine, and the VM is destroyed with it. An error, 4, is also what
/// bhyve exits with when delete or another create destroys the VM under
/// it, so that one leaves the VM alone: the next bhyve of the name may
/// already be it.
pub fn keep(
    io: Io,
    gpa: Allocator,
    name: []const u8,
    config: []const u8,
    bhyve: []const []const u8,
) !void {
    while (true) {
        var child = try std.process.spawn(io, .{
            .argv = bhyve,
            .stdin = .pipe,
            .stdout = .inherit,
            .stderr = .inherit,
        });
        const term = try child.wait(io);
        const code: u32 = if (term == .exited) term.exited else 4;
        say(io, "{s}: bhyve exited {d}: {s}", .{ name, code, switch (code) {
            0 => "the guest asked to reboot",
            1 => "the guest powered off",
            2 => "the guest halted",
            3 => "triple fault",
            else => "an error, or the VM was destroyed",
        } });
        if (code == 4) return;
        _ = std.process.run(gpa, io, .{ .argv = try destroy(gpa, name) }) catch {};
        if (code != 0) return;
        Dir.cwd().access(io, config, .{}) catch return;
    }
}

fn say(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const line = std.mem.print(&buf, "werewolf: " ++ fmt ++ "\n", args) catch return;
    Io.File.stderr().writeStreamingAll(io, line) catch {};
}

const testing = std.testing;

test forwards {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const f = try forwards(gpa, "edge", &.{ 22, 443 });
    try testing.expectEqual(@as(usize, 2), f.len);
    try testing.expect(f[0].host >= 20000 and f[0].host <= 59900 and f[0].host % 100 == 0);
    try testing.expectEqual(f[0].host + 1, f[1].host);
    try testing.expectEqual(@as(u16, 443), f[1].guest);
    try testing.expectEqual(f[0].host, (try forwards(gpa, "edge", &.{22}))[0].host);
    try testing.expectEqual(@as(usize, 0), (try forwards(gpa, "edge", &.{})).len);
}

test argv {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const a = try argv(gpa, "edge", "/m/disk.img", "/m/config.tar", &.{
        .{ .host = 23400, .guest = 22 },
        .{ .host = 23401, .guest = 443 },
    });
    try testing.expectEqualStrings("bhyve", a[0]);
    try testing.expectEqualStrings("edge", a[a.len - 1]);
    try testing.expectEqualStrings(
        "2,virtio-net,slirp,open,hostfwd=tcp:127.0.0.1:23400-:22;tcp:127.0.0.1:23401-:443",
        a[13],
    );
    try testing.expectEqualStrings("4,virtio-blk,/m/config.tar,ro", a[17]);
    const none = try argv(gpa, "m", "/d", "/c", &.{});
    try testing.expectEqualStrings("2,virtio-net,slirp,open", none[13]);
    const d = try destroy(gpa, "edge");
    try testing.expectEqualStrings("--vm=edge", d[1]);
}
