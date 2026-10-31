//! lima runs a machine as a Lima VM under macOS's Virtualization framework
//! (vz). Lima owns VM existence and runtime state; howl retains build and
//! enrollment inputs separately. See README.md.

const std = @import("std");
const builtin = @import("builtin");
const howl = @import("howl.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;

pub const leases = "/var/db/dhcpd_leases";
/// user_ip and user_gw are the guest address and gateway of Lima's user
/// network in every VM. The gateway also answers DNS.
const user_address = "192.168.5.15";
pub const user_ip = user_address ++ "/24";
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
    return listed(r.term == .exited and r.term.exited == 0, r.stdout, name);
}

fn listed(ok: bool, text: []const u8, name: []const u8) !bool {
    // A failed listing is not evidence that an enrolled VM was deleted.
    if (!ok) return error.LimaListFailed;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |l| if (std.mem.eql(u8, std.mem.trim(u8, l, " \r"), name)) return true;
    return false;
}

test "instance absence requires a successful Lima listing" {
    try std.testing.expect(try listed(true, "stopped-vm\nrunning-vm\n", "stopped-vm"));
    try std.testing.expect(!try listed(true, "another-vm\n", "deleted-vm"));
    try std.testing.expect(!try listed(true, "", "deleted-vm"));
    try std.testing.expectError(error.LimaListFailed, listed(false, "", "deleted-vm"));
}

/// running reports whether Lima says the instance is running.
pub fn running(io: Io, gpa: Allocator, name: []const u8) !bool {
    const r = try std.process.run(
        gpa,
        io,
        .{ .argv = &.{ "limactl", "list", name, "--format", "{{.Status}}" } },
    );
    if (!r.term.success()) return error.LimaListFailed;
    return runningStatus(std.mem.trim(u8, r.stdout, " \r\n"));
}

fn runningStatus(status: []const u8) !bool {
    if (std.mem.eql(u8, status, "Running")) return true;
    if (std.mem.eql(u8, status, "Stopped")) return false;
    return error.LimaUnknownState;
}

test "unknown Lima state never authorizes detached storage access" {
    try std.testing.expect(try runningStatus("Running"));
    try std.testing.expect(!try runningStatus("Stopped"));
    try std.testing.expectError(error.LimaUnknownState, runningStatus(""));
    try std.testing.expectError(error.LimaUnknownState, runningStatus("Broken"));
}

/// sshPort returns the port Lima forwards to a machine it manages's sshd,
/// or null.
pub fn sshPort(io: Io, gpa: Allocator, name: []const u8) ?[]const u8 {
    const r = std.process.run(
        gpa,
        io,
        .{ .argv = &.{ "limactl", "list", name, "--format", "{{.SSHLocalPort}}" } },
    ) catch return null;
    const p = std.mem.trim(u8, r.stdout, " \n");
    const n = std.fmt.parseInt(u16, p, 10) catch return null;
    return if (n == 0) null else p;
}

/// Approved provider configuration for a new data identity ledger. The archive
/// never chooses this account, its numeric identity or its credentials.
pub fn dataIdentity(io: Io, gpa: Allocator, name: []const u8) !@import("people").NoCloud {
    const r = try std.process.run(gpa, io, .{
        .argv = &.{
            "limactl",
            "list",
            name,
            "--format",
            "{{.Config.User.Name}}|{{.Config.User.UID}}",
        },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    if (!r.term.success()) return error.LimaListFailed;
    const line = std.mem.trim(u8, r.stdout, " \r\n");
    var fields = std.mem.splitScalar(u8, line, '|');
    const user = fields.next() orelse return error.LimaUnknownUser;
    const id = try std.fmt.parseUnsigned(
        u32,
        fields.next() orelse return error.LimaUnknownUser,
        10,
    );
    if (!@import("people").validNoCloudName(user) or fields.next() != null or id < 500 or
        id > 60000)
        return error.LimaUnknownUser;
    return .{ .name = try gpa.dupe(u8, user), .id = id, .keys = "" };
}

/// sshIdentity is the key Lima puts in its NoCloud user's authorized_keys.
pub fn sshIdentity(io: Io, gpa: Allocator, name: []const u8, user: []const u8) !?[]const u8 {
    const r = try std.process.run(gpa, io, .{
        .argv = &.{
            "limactl",
            "list",
            name,
            "--format",
            "{{.Config.User.Name}}|{{.IdentityFile}}",
        },
    });
    if (r.term != .exited or r.term.exited != 0) return null;
    const text = std.mem.trim(u8, r.stdout, " \r\n");
    const separator = std.mem.findScalar(u8, text, '|') orelse return null;
    if (!std.mem.eql(u8, text[0..separator], user)) return null;
    const path = text[separator + 1 ..];
    return if (std.fs.path.isAbsolute(path)) path else null;
}

pub const Forward = struct { guest: u16, host: u16 };

/// Forward declared TCP services in QEMU itself. Plain Lima has neither a
/// guest agent nor SSH tunnels. Its monitor also preserves live mappings
/// across repeated howl commands, without restarting the guest.
pub fn forward(io: Io, gpa: Allocator, name: []const u8, ports: []const u16) ![]const Forward {
    if (ports.len == 0) return &.{};
    const instance = try dir(io, gpa, name) orelse return error.MissingLimaInstance;
    const address = try Io.net.UnixAddress.init(try gpa.print("{s}/qmp.sock", .{instance}));
    const stream = try address.connect(io);
    defer stream.close(io);
    var buffer: [64 << 10]u8 = undefined;
    var reader = stream.reader(io, &buffer);
    _ = try qmpReply(gpa, &reader.interface);
    try qmpSend(io, gpa, stream, .{ .execute = "qmp_capabilities" });
    _ = try qmpReply(gpa, &reader.interface);
    try qmpSend(io, gpa, stream, .{
        .execute = "human-monitor-command",
        .arguments = .{ .@"command-line" = "info usernet" },
    });
    const table = try qmpReply(gpa, &reader.interface);
    if (table != .string) return error.BadQemuReply;
    const held = try forwarded(gpa, table.string);
    var result: std.ArrayList(Forward) = .empty;
    for (ports) |guest| {
        for (held) |mapping| {
            if (mapping.guest == guest) {
                try result.append(gpa, mapping);
                break;
            }
        } else {
            const host = try @import("qemu.zig").freePort(
                io,
                if (guest == 443) 8443 else if (guest < 1024) 8080 else guest,
            );
            const command = try gpa.print("hostfwd_add net0 tcp:127.0.0.1:{d}-{s}:{d}", .{
                host, user_address, guest,
            });
            try qmpSend(io, gpa, stream, .{
                .execute = "human-monitor-command",
                .arguments = .{ .@"command-line" = command },
            });
            const reply = try qmpReply(gpa, &reader.interface);
            if (reply != .string or reply.string.len != 0) return error.PortForwardFailed;
            try result.append(gpa, .{ .guest = guest, .host = host });
        }
    }
    return result.toOwnedSlice(gpa);
}

fn qmpSend(io: Io, gpa: Allocator, stream: Io.net.Stream, command: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(gpa, command, .{});
    var writer = stream.writer(io, &.{});
    try writer.interface.writeAll(json);
    try writer.interface.writeByte('\n');
}

fn qmpReply(gpa: Allocator, reader: *Io.Reader) !std.json.Value {
    while (true) {
        const line = try reader.takeDelimiterInclusive('\n');
        const reply = try std.json.parseFromSliceLeaky(std.json.Value, gpa, line, .{});
        if (reply != .object or reply.object.contains("error")) return error.BadQemuReply;
        if (reply.object.get("return")) |value| return value;
        if (reply.object.contains("QMP")) return .null;
        // Lifecycle events can arrive between command replies.
        if (!reply.object.contains("event")) return error.BadQemuReply;
    }
}

test "QMP skips lifecycle events and refuses command errors" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var good: Io.Reader = .fixed("{\"event\":\"RESET\"}\n{\"return\":\"ready\"}\n");
    try std.testing.expectEqualStrings("ready", (try qmpReply(gpa, &good)).string);
    var bad: Io.Reader = .fixed("{\"error\":{\"class\":\"GenericError\"}}\n");
    try std.testing.expectError(error.BadQemuReply, qmpReply(gpa, &bad));
}

fn forwarded(gpa: Allocator, table: []const u8) ![]const Forward {
    var result: std.ArrayList(Forward) = .empty;
    var lines = std.mem.splitScalar(u8, table, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        if (!std.mem.eql(u8, words.next() orelse continue, "TCP[HOST_FORWARD]")) continue;
        _ = words.next() orelse continue; // QEMU's file descriptor.
        if (!std.mem.eql(u8, words.next() orelse continue, "127.0.0.1")) continue;
        const host = std.fmt.parseInt(u16, words.next() orelse continue, 10) catch continue;
        if (!std.mem.eql(u8, words.next() orelse continue, user_address)) continue;
        const guest = std.fmt.parseInt(u16, words.next() orelse continue, 10) catch continue;
        if (host != 0 and guest != 0) try result.append(gpa, .{ .guest = guest, .host = host });
    }
    return result.toOwnedSlice(gpa);
}

test "QEMU forwarding table admits only loopback TCP mappings to this guest" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const mappings = try forwarded(arena.allocator(), "Hub -1 (net0):\r\n" ++
        " TCP[HOST_FORWARD] 27 127.0.0.1 53129 192.168.5.15 22 0 0\r\n" ++
        " TCP[ESTABLISHED] 28 127.0.0.1 8443 192.168.5.15 443 0 0\r\n" ++
        " UDP[HOST_FORWARD] 29 127.0.0.1 5353 192.168.5.15 53 0 0\r\n" ++
        " TCP[HOST_FORWARD] 30 0.0.0.0 8080 192.168.5.15 80 0 0\r\n" ++
        " TCP[HOST_FORWARD] 31 127.0.0.1 8081 192.168.5.16 80 0 0\r\n" ++
        " TCP[HOST_FORWARD] 32 127.0.0.1 8443 192.168.5.15 443 0 0\r\n");
    try std.testing.expectEqualDeep(
        &[_]Forward{ .{ .guest = 22, .host = 53129 }, .{ .guest = 443, .host = 8443 } },
        mappings,
    );
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

/// storageDisk resolves the raw GPT root disk inside a Lima instance directory.
/// Lima 2.x writes `disk`; Lima 1.x wrote `diffdisk` (raw under vz, qcow2 under
/// qemu). Symlinks, hardlinks, ambiguous dual-disk directories, and legacy
/// qcow2 overlays are refused without interpreting qcow2 backing paths.
pub fn storageDisk(io: Io, gpa: Allocator, instance: []const u8) ![]const u8 {
    var inst = Dir.cwd().openDir(io, instance, .{ .follow_symlinks = false }) catch |err|
        switch (err) {
            error.FileNotFound => return error.MissingLimaInstance,
            else => return err,
        };
    defer inst.close(io);
    const has_disk = try probeRawCandidate(io, inst, "disk");
    const has_diffdisk = try probeRawCandidate(io, inst, "diffdisk");
    if (has_disk and has_diffdisk) return error.AmbiguousLimaDisk;
    if (!has_disk and !has_diffdisk) return error.MissingLimaInstance;
    const chosen = if (has_disk) "disk" else "diffdisk";
    const file = try inst.openFile(io, chosen, .{ .follow_symlinks = false });
    defer file.close(io);
    const st = try file.stat(io);
    if (st.kind != .file or st.nlink != 1) return error.UnsafeLimaDisk;
    var head: [520]u8 = undefined;
    const n = try file.readPositionalAll(io, &head, 0);
    if (n >= 4 and std.mem.eql(u8, head[0..4], "QFI\xfb")) return error.LimaLegacyQcow2Disk;
    if (n != head.len or !std.mem.eql(u8, head[512..520], "EFI PART"))
        return error.UnsafeLimaDisk;
    return gpa.print("{s}/{s}", .{ instance, chosen });
}

fn probeRawCandidate(io: Io, inst: Dir, name: []const u8) !bool {
    const st = inst.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    if (st.kind != .file or st.nlink != 1) return error.UnsafeLimaDisk;
    return true;
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

/// managedArgs are the kernel arguments a managed machine's disk boots
/// with: Lima's user network, whose gateway answers DNS. vz has no serial
/// port, so the console is hvc0.
pub const managed_args = [_][]const u8{
    "console=hvc0",
    "werewolf.ip=" ++ user_ip,
    "werewolf.gw=" ++ user_gw,
    "werewolf.dns=" ++ user_gw,
};

/// managedTemplate returns the template of a machine Lima manages, in plain
/// mode: Lima boots its disk, from the slots on it, and forwards ssh,
/// nothing else. There is no cloud-init in the guest; init reads the ssh
/// key Lima puts in its cidata volume and makes that user itself. The
/// config tar is a second disk.
pub fn managedTemplate(
    gpa: Allocator,
    form: []const u8,
    arch: []const u8,
    disk: []const u8,
    config_disk: []const u8,
) ![]const u8 {
    return gpa.print(
        \\# Written by howl create: Lima manages it.
        \\# {s}: {s}
        \\# werewolf lima: managed
        \\vmType: vz
        \\plain: true
        \\arch: {s}
        \\cpus: 4
        \\memory: {d}MiB
        \\images:
        \\  - location: "{s}"
        \\    arch: {s}
        \\mounts: []
        \\additionalDisks:
        \\  - name: "{s}"
        \\    format: false
        \\
    , .{ howl.form_tag, form, arch, howl.local_mib, disk, arch, config_disk });
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
            // The guest asked for this address; take it only as an address.
            if (std.mem.startsWith(u8, l, "ip_address=") and howl.isIp4(l["ip_address=".len..]))
                ip = l["ip_address=".len..];
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
        "{\n\tip_address=192.168.105.2\n\thw_address=1,52:55:55:aa:bb:cc\n\tlease=0x6800b000\n}" ++
        "\n" ++
        "{\n\tip_address=-oProxyCommand=x\n\thw_address=1,52:55:55:57:e1:f1\n\tlease=0x6900b000" ++
        "\n}\n";
    const l = lease(text, "52:55:55:57:e1:f0").?;
    try testing.expectEqualStrings("192.168.105.9", l.ip);
    try testing.expectEqual(@as(u64, 0x6700b000), l.expiry);
    try testing.expectEqual(null, lease(text, "52:55:55:57:e1:f1"));
    try testing.expectEqual(null, lease(text, "52:55:55:57:e1:f2"));
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
        "playground",
        "aarch64",
        "/m/disk.img",
        "x-config",
    );
    try testing.expect(isManaged(mt));
    try testing.expectEqualStrings("playground", formOf(mt).?);
    try testing.expect(std.mem.find(u8, mt, "kernel:") == null);
    try testing.expect(std.mem.find(
        u8,
        mt,
        "  - location: \"/m/disk.img\"\n    arch: aarch64\nmounts: []\nadditionalDisks:\n" ++
            "  - name: \"x-config\"",
    ) != null);
    try testing.expectEqualStrings("werewolf.ip=192.168.5.15/24", managed_args[1]);
    try testing.expectEqual(null, formOf("vmType: vz\n"));
}

test "storageDisk selects raw GPT disk or diffdisk and refuses qcow2, links and ambiguity" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(testing.io, ".", gpa);
    try testing.expectError(
        error.MissingLimaInstance,
        storageDisk(testing.io, gpa, try gpa.print("{s}/absent", .{root})),
    );
    const inst = try gpa.print("{s}/inst", .{root});
    try tmp.dir.createDir(testing.io, "inst", .fromMode(0o700));
    try testing.expectError(error.MissingLimaInstance, storageDisk(testing.io, gpa, inst));

    var gpt: [1024]u8 = @splat(0);
    @memcpy(gpt[512..520], "EFI PART");
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "inst/disk", .data = &gpt });
    try testing.expectEqualStrings(
        try gpa.print("{s}/disk", .{inst}),
        try storageDisk(testing.io, gpa, inst),
    );

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "inst/diffdisk", .data = &gpt });
    try testing.expectError(error.AmbiguousLimaDisk, storageDisk(testing.io, gpa, inst));

    try tmp.dir.deleteFile(testing.io, "inst/disk");
    try testing.expectEqualStrings(
        try gpa.print("{s}/diffdisk", .{inst}),
        try storageDisk(testing.io, gpa, inst),
    );

    var qcow2 = gpt;
    @memcpy(qcow2[0..4], "QFI\xfb");
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "inst/diffdisk", .data = &qcow2 });
    try testing.expectError(error.LimaLegacyQcow2Disk, storageDisk(testing.io, gpa, inst));

    var plain: [1024]u8 = @splat(0);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "inst/diffdisk", .data = &plain });
    try testing.expectError(error.UnsafeLimaDisk, storageDisk(testing.io, gpa, inst));

    try tmp.dir.deleteFile(testing.io, "inst/diffdisk");
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "outside.raw", .data = &gpt });
    try tmp.dir.symLink(testing.io, "../outside.raw", "inst/disk", .{});
    try testing.expectError(error.UnsafeLimaDisk, storageDisk(testing.io, gpa, inst));

    try tmp.dir.deleteFile(testing.io, "inst/disk");
    try tmp.dir.hardLink("outside.raw", tmp.dir, "inst/disk", testing.io, .{});
    try testing.expectError(error.UnsafeLimaDisk, storageDisk(testing.io, gpa, inst));
}
