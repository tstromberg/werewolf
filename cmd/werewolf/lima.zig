//! Lima: a werewolf machine as a Lima VM under macOS's Virtualization
//! framework (vz), from the same two files every target takes: a boot disk
//! and the config tar, which Lima attaches as a second disk, unformatted,
//! where init finds it.
//!
//! Lima reaches a guest through ssh or its agent, and a werewolf machine
//! runs neither, so the VM has a second network, vzNAT, whose address this
//! Mac reaches directly. Its MAC is the name's, hashed, so nothing records
//! it; the disk's command line names it (werewolf.mac), so DHCP runs there,
//! and macOS's DHCP server records the address it gave. A form with no
//! DHCP client has no vzNAT: it takes Lima's own network from its config
//! tar's network file, and its console says it is up. Lima is the state:
//! `limactl list` says what exists, and nothing here remembers more.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

const leases = "/var/db/dhcpd_leases";
/// Lima's own network, as every VM has it: the address it expects its
/// guest at, and its gateway, which answers DNS too.
pub const user_ip = "192.168.5.15/24";
pub const user_gw = "192.168.5.2";
/// How long create waits for the machine's address.
const wait_seconds = 180;

/// Whether this machine runs Lima with vz: macOS, and limactl on the PATH.
pub fn installed(io: Io, gpa: Allocator) bool {
    if (builtin.os.tag != .macos) return false;
    const r = std.process.run(
        gpa,
        io,
        .{ .argv = &.{ "limactl", "--version" } },
    ) catch return false;
    return r.term == .exited and r.term.exited == 0;
}

/// The vzNAT MAC for a machine named name: locally administered, and the
/// rest the name's sha256. No octet is below 0x10, since macOS's lease file
/// writes them without the leading zero.
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

/// Whether Lima has an instance named name.
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

/// Whether Lima says the instance is running.
pub fn running(io: Io, gpa: Allocator, name: []const u8) !bool {
    const r = try std.process.run(
        gpa,
        io,
        .{ .argv = &.{ "limactl", "list", name, "--format", "{{.Status}}" } },
    );
    return std.mem.eql(u8, std.mem.trim(u8, r.stdout, " \n"), "Running");
}

/// The instance's directory, where Lima keeps its console log.
pub fn dir(io: Io, gpa: Allocator, name: []const u8) !?[]const u8 {
    const r = try std.process.run(
        gpa,
        io,
        .{ .argv = &.{ "limactl", "list", name, "--format", "{{.Dir}}" } },
    );
    const d = std.mem.trim(u8, r.stdout, " \n");
    return if (r.term == .exited and r.term.exited == 0 and d.len > 0) d else null;
}

/// The Lima template: the disk, the vzNAT network with MAC m, unless the
/// form has no DHCP client to take an address there, the config tar's
/// disk, and nothing of Lima's own: no mounts, no ssh, no provisioning.
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
        \\# Written by werewolf create. A disk that boots itself, and its config
        \\# tar as a second, unformatted disk; no cloud-init, no ssh.
        \\# werewolf form: {s}
        \\vmType: vz
        \\arch: {s}
        \\plain: true
        \\cpus: 2
        \\memory: 2GiB
        \\images:
        \\  - location: "{s}"
        \\    arch: {s}
        \\{s}mounts: []
        \\additionalDisks:
        \\  - name: "{s}"
        \\    format: false
        \\
    , .{ form, arch, disk, arch, net, config_disk });
}

/// The template for a machine Lima manages: make's, from boot/lima.yaml.in,
/// as make lima uses it, with the config tar's disk and what werewolf
/// recalls of it later added.
pub fn managedTemplate(
    gpa: Allocator,
    base: []const u8,
    form: []const u8,
    config_disk: []const u8,
) ![]const u8 {
    return gpa.print(
        \\# Written by werewolf create, from make's template: Lima manages it.
        \\# werewolf form: {s}
        \\# werewolf lima: managed
        \\{s}
        \\additionalDisks:
        \\  - name: "{s}"
        \\    format: false
        \\
    , .{ form, std.mem.trimEnd(u8, base, "\n"), config_disk });
}

/// Whether a machine's template is one Lima manages.
pub fn isManaged(yaml: []const u8) bool {
    var lines = std.mem.splitScalar(u8, yaml, '\n');
    while (lines.next()) |l|
        if (std.mem.eql(u8, std.mem.trimEnd(u8, l, " \r"), "# werewolf lima: managed")) return true;
    return false;
}

/// The form a machine was made from, as its template's comment says: Lima
/// keeps the template, so Lima is where it is recorded.
pub fn formOf(yaml: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, yaml, '\n');
    while (lines.next()) |l| if (std.mem.startsWith(u8, l, "# werewolf form: ")) {
        const f = std.mem.trim(u8, l["# werewolf form: ".len..], " \r");
        return if (f.len > 0) f else null;
    };
    return null;
}

/// A DHCP lease: the address, and when it expires, in seconds since 1970.
pub const Lease = struct { ip: []const u8, expiry: u64 };

/// The lease macOS's DHCP server gave m, from its lease file: the one that
/// expires last, if any.
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

/// m's lease now, before the machine starts: one a deleted machine of the
/// same name left, which create must not mistake for the new one's.
pub fn previous(io: Io, gpa: Allocator, m: []const u8) u64 {
    const text = Dir.cwd().readFileAlloc(io, leases, gpa, .limited(4 << 20)) catch return 0;
    return if (lease(text, m)) |l| l.expiry else 0;
}

/// Wait for a lease for m newer than before: limactl start waits for ssh,
/// which a werewolf machine never answers, so the lease says it is up.
pub fn awaitAddress(io: Io, gpa: Allocator, m: []const u8, before: u64) !?[]const u8 {
    var waited: u32 = 0;
    while (waited < wait_seconds) : (waited += 2) {
        if (Dir.cwd().readFileAlloc(io, leases, gpa, .limited(4 << 20))) |text| {
            if (lease(text, m)) |l| if (l.expiry > before) return l.ip;
        } else |_| {}
        try io.sleep(.fromSeconds(2), .awake);
    }
    return null;
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
    const mt = try managedTemplate(
        arena.allocator(),
        "vmType: vz\nplain: true\n",
        "lima",
        "x-config",
    );
    try testing.expect(isManaged(mt));
    try testing.expectEqualStrings("lima", formOf(mt).?);
    try testing.expect(std.mem.find(
        u8,
        mt,
        "plain: true\nadditionalDisks:\n  - name: \"x-config\"",
    ) != null);
    try testing.expectEqual(null, formOf("vmType: vz\n"));
}
