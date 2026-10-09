//! bhyve runs a machine as a bhyve VM on FreeBSD x86_64 (experimental),
//! under a supervisor that restarts bhyve on reboot. See README.md.

const std = @import("std");
const builtin = @import("builtin");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

/// firmware is bhyve's UEFI firmware, from the bhyve-firmware package.
pub const firmware = "/usr/local/share/uefi-firmware/BHYVE_UEFI.fd";
/// user_ip, user_gw and user_dns are slirp's fixed guest network, written
/// into the config tar for a form with no DHCP client.
pub const user_ip = "10.0.2.15/24";
pub const user_gw = "10.0.2.2";
pub const user_dns = "10.0.2.3";

/// installed reports whether this is FreeBSD on x86_64 with vmm loaded
/// (/dev/vmmctl exists; kldload vmm). bhyve on arm64 needs other firmware
/// and flags, which howl does not support yet.
pub fn installed(io: Io) bool {
    if (builtin.os.tag != .freebsd or builtin.cpu.arch != .x86_64) return false;
    Dir.cwd().access(io, "/dev/vmmctl", .{}) catch return false;
    return true;
}

/// exists reports whether bhyve has a VM named name. A VM exists from its
/// first run until bhyvectl --destroy.
pub fn exists(io: Io, gpa: Allocator, name: []const u8) !bool {
    Dir.cwd().access(io, try gpa.print("/dev/vmm/{s}", .{name}), .{}) catch return false;
    return true;
}

/// asRoot returns the command prefix that runs bhyve as root: none when
/// already root, else doas or sudo from /usr/local/bin. It fails with
/// error.NoRoot if neither is installed.
pub fn asRoot(io: Io) error{NoRoot}![]const []const u8 {
    if (howl.isRoot()) return &.{};
    inline for (.{ "doas", "sudo" }) |tool| {
        if (Dir.cwd().access(io, "/usr/local/bin/" ++ tool, .{})) |_| return &.{tool} else |_| {}
    }
    return error.NoRoot;
}

/// Forward is a port slirp forwards from 127.0.0.1:host to guest.
pub const Forward = struct { host: u16, guest: u16 };

/// forwards maps up to 100 guest ports to consecutive host ports from a
/// base that name's sha256 picks (20000 to 59900, by hundreds). A name
/// always gets the same ports, and two names rarely collide.
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

/// argv returns bhyve's command line: the disk and a read-only config tar
/// on virtio, slirp with fwds, an RNG, the serial console on stdout, and
/// UEFI firmware. slirp is "open" so updates can reach out, and so that
/// FreeBSD 15.1's slirp helper skips capability mode, where, as root,
/// getpwnam(nobody) fails and the helper dies, killing bhyve with SIGPIPE.
/// -w: Linux reads MSRs bhyve lacks. -H: yield the CPU when idle. -u: UTC
/// clock. No -A: FreeBSD 15 always builds ACPI tables and dropped the flag.
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
        std.fmt.comptimePrint("{d}", .{howl.local_cpus}),
        "-m",
        std.fmt.comptimePrint("{d}M", .{howl.local_mib}),
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

/// destroy returns the bhyvectl command that destroys the VM name, which
/// also ends its bhyve and supervisor.
pub fn destroy(gpa: Allocator, name: []const u8) ![]const []const u8 {
    return try gpa.dupe(
        []const u8,
        &.{ "bhyvectl", try gpa.print("--vm={s}", .{name}), "--destroy" },
    );
}

/// keep is the supervisor, `howl _bhyve NAME CONFIG BHYVE...`, run as root
/// under daemon(8). bhyve's stdin is a pipe never written, so the console
/// reads nothing. On exit 0 (reboot) keep destroys the VM and runs bhyve
/// again while config exists; delete removes config to stop the loop. On
/// any other exit it destroys the VM and returns, except on 4: bhyve also
/// exits 4 when delete or another create destroyed the VM, and the VM of
/// that name may already be a new one.
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
        howl.say(io, "{s}: bhyve exited {d}: {s}", .{ name, code, switch (code) {
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
