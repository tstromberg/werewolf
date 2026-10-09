//! lima runs a machine as a Lima VM under macOS's Virtualization framework
//! (vz). Lima keeps all the state; howl records nothing. See README.md.

const std = @import("std");
const builtin = @import("builtin");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub const leases = "/var/db/dhcpd_leases";
/// user_ip and user_gw are the guest address and gateway of Lima's user
/// network in every VM. The gateway also answers DNS.
pub const user_ip = "192.168.5.15/24";
pub const user_gw = "192.168.5.2";

/// installed reports whether this is macOS with limactl on the PATH.
pub fn installed(io: Io, gpa: Allocator) bool {
    if (builtin.os.tag != .macos) return false;
    const r = std.process.run(
        gpa,
        io,
        .{ .argv = &.{ "limactl", "--version" } },
    ) catch return false;
    return r.term == .exited and r.term.exited == 0;
}

/// mac derives a locally administered vzNAT MAC from name's sha256, so
/// nothing needs to record it. Every octet is at least 0x10 because macOS's
/// lease file drops leading zeros.
pub fn mac(name: []const u8) [17]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(name, &h, .{});
    var out: [17]u8 = undefined;
    _ = std.mem.print(
        &out,
        "52:55:55:{x:0>2}:{x:0>2}:{x:0>2}",
        .{ h[0] | 0x10, h[1] | 0x10, h[2] | 0x10 },
    ) catch unreachable;
    return out;
}

/// exists reports whether Lima has an instance named name.
pub fn exists(io: Io, gpa: Allocator, name: []const u8) !bool {
    const r = try std.process.run(
        gpa,
        io,
        .{ .argv = &.{ "limactl", "list", "--format", "{{.Name}}" } },
    );
    var lines = std.mem.tokenizeScalar(u8, r.stdout, '\n');
    while (lines.next()) |l| if (std.mem.eql(u8, l, name)) return true;
    return false;
}

/// running reports whether Lima says the instance is running.
pub fn running(io: Io, gpa: Allocator, name: []const u8) !bool {
    const r = try std.process.run(
        gpa,
        io,
        .{ .argv = &.{ "limactl", "list", name, "--format", "{{.Status}}" } },
    );
    return std.mem.eql(u8, std.mem.trim(u8, r.stdout, " \n"), "Running");
}

/// dir returns the instance's directory, which holds its console log, or
/// null if Lima has no such instance.
pub fn dir(io: Io, gpa: Allocator, name: []const u8) !?[]const u8 {
    const r = try std.process.run(
        gpa,
        io,
        .{ .argv = &.{ "limactl", "list", name, "--format", "{{.Dir}}" } },
    );
    const d = std.mem.trim(u8, r.stdout, " \n");
    return if (r.term == .exited and r.term.exited == 0 and d.len > 0) d else null;
}

/// template returns a Lima template that boots disk with config_disk as a
/// second, unformatted disk, and no mounts, ssh or provisioning. A null m
/// omits the vzNAT network, for forms without a DHCP client.
pub fn template(
    gpa: Allocator,
    form: []const u8,
    arch: []const u8,
    disk: []const u8,
    m: ?[]const u8,
    config_disk: []const u8,
) ![]const u8 {
    const net = if (m) |a|
        try gpa.print("networks:\n  - vzNAT: true\n    macAddress: \"{s}\"\n", .{a})
    else
        "";
    return gpa.print(
        \\# Written by howl create. A disk that boots itself, and its config
        \\# tar as a second, unformatted disk; no cloud-init, no ssh.
        \\# {s}: {s}
        \\vmType: vz
        \\arch: {s}
        \\plain: true
        \\cpus: {d}
        \\memory: {d}MiB
        \\images:
        \\  - location: "{s}"
        \\    arch: {s}
        \\{s}mounts: []
        \\additionalDisks:
        \\  - name: "{s}"
        \\    format: false
        \\
    , .{
        howl.form_tag,
        form,
        arch,
        howl.local_cpus,
        howl.local_mib,
        disk,
        arch,
        net,
        config_disk,
    });
}

/// Managed is what a machine Lima manages boots: build's kernel and blank
/// disk, out's initramfs, both directories absolute, and the image's
/// kernel arguments.
pub const Managed = struct {
    form: []const u8,
    arch: []const u8,
    build: []const u8,
    out: []const u8,
    cmdline: []const u8,
    config_disk: []const u8,
};

/// managedTemplate returns the template of a machine Lima manages, in plain
/// mode: Lima boots it and forwards ssh, nothing else. There is no
/// cloud-init in the guest; init reads the ssh key Lima puts in its cidata
/// volume and makes that user itself. The blank disk is the instance's,
/// which Lima grows and keeps until limactl delete and the form formats as
/// /data; the config tar is a second disk.
pub fn managedTemplate(gpa: Allocator, m: Managed) ![]const u8 {
    return gpa.print(
        \\# Written by howl create: Lima manages it.
        \\# {s}: {s}
        \\# werewolf lima: managed
        \\vmType: vz
        \\plain: true
        \\arch: {s}
        \\cpus: 4
        \\memory: 2GiB
        \\images:
        \\  - location: "{s}/disk.img"
        \\    arch: {s}
        \\    kernel:
        \\      location: "{s}/vmlinuz"
        \\      # Lima's user network; its gateway answers DNS. vz has no
        \\      # serial port, so the console is hvc0.
        \\      cmdline: "console=hvc0 {s} werewolf.ip={s} werewolf.gw={s} werewolf.dns={s} werewolf.data=vda"
        \\    initrd:
        \\      location: "{s}/initramfs.zst"
        \\mounts: []
        \\additionalDisks:
        \\  - name: "{s}"
        \\    format: false
        \\
    , .{
        howl.form_tag, m.form,        m.arch,  m.build, m.arch,
        m.build,       m.cmdline,     user_ip, user_gw, user_gw,
        m.out,         m.config_disk,
    });
}

/// isManaged reports whether yaml came from managedTemplate.
pub fn isManaged(yaml: []const u8) bool {
    var lines = std.mem.splitScalar(u8, yaml, '\n');
    while (lines.next()) |l|
        if (std.mem.eql(u8, std.mem.trimEnd(u8, l, " \r"), "# werewolf lima: managed")) return true;
    return false;
}

/// formOf returns the form named in the template's comment. Lima keeps the
/// template, so the form needs no other record.
pub fn formOf(yaml: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, yaml, '\n');
    const prefix = "# " ++ howl.form_tag ++ ": ";
    while (lines.next()) |l| if (std.mem.startsWith(u8, l, prefix)) {
        const f = std.mem.trim(u8, l[prefix.len..], " \r");
        return if (f.len > 0) f else null;
    };
    return null;
}

/// Lease is a DHCP lease: an address and its expiry in Unix seconds.
pub const Lease = struct { ip: []const u8, expiry: u64 };

/// lease returns the latest-expiring lease for m in the text of macOS's
/// lease file, or null.
pub fn lease(text: []const u8, m: []const u8) ?Lease {
    var best: ?Lease = null;
    var blocks = std.mem.splitScalar(u8, text, '}');
    while (blocks.next()) |b| {
        var ip: ?[]const u8 = null;
        var hw = false;
        var expiry: u64 = 0;
        var lines = std.mem.tokenizeAny(u8, b, "\n\t {");
        while (lines.next()) |l| {
            if (std.mem.startsWith(u8, l, "ip_address=")) ip = l["ip_address=".len..];
            if (std.mem.startsWith(
                u8,
                l,
                "hw_address=1,",
            )) hw = std.mem.eql(u8, l["hw_address=1,".len..], m);
            if (std.mem.startsWith(u8, l, "lease=0x"))
                expiry = std.fmt.parseInt(u64, l["lease=0x".len..], 16) catch 0;
        }
        if (hw and ip != null and (best == null or expiry >= best.?.expiry))
            best = .{ .ip = ip.?, .expiry = expiry };
    }
    return best;
}

/// previous returns the expiry of m's current lease, or 0. create calls it
/// before boot so a lease left by a deleted machine of the same name is not
/// taken for the new one's.
pub fn previous(io: Io, gpa: Allocator, m: []const u8) u64 {
    const text = Dir.cwd().readFileAlloc(io, leases, gpa, .limited(4 << 20)) catch return 0;
    return if (lease(text, m)) |l| l.expiry else 0;
}

/// addressOf returns the leased vzNAT address of the machine name, or null.
pub fn addressOf(io: Io, gpa: Allocator, name: []const u8) ?[]const u8 {
    const m = mac(name);
    const text = Dir.cwd().readFileAlloc(io, leases, gpa, .limited(4 << 20)) catch return null;
    const l = lease(text, &m) orelse return null;
    return gpa.dupe(u8, l.ip) catch null;
}

const testing = std.testing;

test mac {
    const a = mac("edge");
    try testing.expectEqualStrings("52:55:55:", a[0..9]);
    try testing.expectEqualSlices(u8, &a, &mac("edge"));
    try testing.expect(!std.mem.eql(u8, &a, &mac("router")));
    var octets = std.mem.splitScalar(u8, &a, ':');
    while (octets.next()) |o| try testing.expect(std.fmt.parseInt(u8, o, 16) catch 0 >= 0x10);
}

test lease {
    const text = "{\n\tname=werewolf\n\tip_address=192.168.105.4\n" ++
        "\thw_address=1,52:55:55:57:e1:f0\n\tidentifier=1,52:55:55:57:e1:f0\n\tlease=0x6700a000" ++
        "\n}\n" ++
        "{\n\tname=werewolf\n\tip_address=192.168.105.9\n" ++
        "\thw_address=1,52:55:55:57:e1:f0\n\tlease=0x6700b000\n}\n" ++
        "{\n\tip_address=192.168.105.2\n\thw_address=1,52:55:55:aa:bb:cc\n\tlease=0x6800b000\n}\n";
    const l = lease(text, "52:55:55:57:e1:f0").?;
    try testing.expectEqualStrings("192.168.105.9", l.ip);
    try testing.expectEqual(@as(u64, 0x6700b000), l.expiry);
    try testing.expectEqual(null, lease(text, "52:55:55:57:e1:f1"));
}

test template {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const t = try template(
        arena.allocator(),
        "bastion",
        "aarch64",
        "/x/disk.img",
        "52:55:55:11:22:33",
        "edge-config",
    );
    try testing.expect(std.mem.find(u8, t, "macAddress: \"52:55:55:11:22:33\"") != null);
    try testing.expect(std.mem.find(
        u8,
        t,
        "  - name: \"edge-config\"\n    format: false",
    ) != null);
    try testing.expectEqualStrings("bastion", formOf(t).?);
    try testing.expect(!isManaged(t));
    const plain = try template(
        arena.allocator(),
        "minimal",
        "aarch64",
        "/x/disk.img",
        null,
        "m-config",
    );
    try testing.expect(std.mem.find(u8, plain, "networks:") == null);
    try testing.expect(std.mem.find(u8, plain, "    arch: aarch64\nmounts: []") != null);
    const mt = try managedTemplate(arena.allocator(), .{
        .form = "lima",
        .arch = "aarch64",
        .build = "/w/build/aarch64",
        .out = "/w/build/aarch64/lima",
        .cmdline = "debugfs=off",
        .config_disk = "x-config",
    });
    try testing.expect(isManaged(mt));
    try testing.expectEqualStrings("lima", formOf(mt).?);
    for ([_][]const u8{
        "  - location: \"/w/build/aarch64/disk.img\"\n    arch: aarch64\n",
        "cmdline: \"console=hvc0 debugfs=off werewolf.ip=192.168.5.15/24 werewolf.gw=192.168.5.2",
        "location: \"/w/build/aarch64/lima/initramfs.zst\"\nmounts: []\nadditionalDisks:\n" ++
            "  - name: \"x-config\"",
    }) |want| try testing.expect(std.mem.find(u8, mt, want) != null);
    try testing.expectEqual(null, formOf("vmType: vz\n"));
}
