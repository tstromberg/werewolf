//! Host-side containment and posture checks for disposable hypervisor guests.
const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const Io = std.Io;
const mem = std.mem;
const Json = std.json.Value;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "hypervisor-isolation") catch std.process.exit(1);
    c.finish(run(&c));
}

fn run(c: *host.Check) !void {
    const args = c.args;
    if (args.len == 4 and mem.eql(u8, args[1], "posture")) {
        if (!mem.eql(u8, args[2], "firecracker") and !mem.eql(u8, args[2], "bhyve"))
            return error.UnknownProvider;
        const report = try std.json.parseFromSliceLeaky(Json, c.gpa, try read(c, args[3]), .{});
        try posture(report, mem.eql(u8, args[2], "firecracker"));
    } else if (args.len == 3 and mem.eql(u8, args[1], "bhyve")) {
        const processes = try root(c, &.{ "ps", "-axo", "pid,args" });
        const suffix = try c.gpa.print("bhyve: {s} (bhyve)", .{args[2]});
        var pid: ?[]const u8 = null;
        var lines = mem.tokenizeScalar(u8, processes.stdout, '\n');
        while (lines.next()) |line| {
            if (!mem.endsWith(u8, line, suffix)) continue;
            if (pid != null) return error.MultipleBhyveProcesses;
            var words = mem.tokenizeAny(u8, line, " \t");
            pid = words.next();
        }
        const credentials = try root(c, &.{ "procstat", "-s", pid orelse
            return error.BhyveProcessMissing });
        c.say("{s}", .{credentials.stdout});
        try capsicum(credentials.stdout);
    } else if ((args.len == 4 and mem.eql(u8, args[1], "inspect")) or
        (args.len == 3 and mem.eql(u8, args[1], "tap-probe")))
    {
        const uid = try command(c, &.{ "id", "-u" }, true);
        if (!mem.eql(u8, mem.trim(u8, uid.stdout, " \n"), "0")) {
            var elevated: std.ArrayList([]const u8) = .empty;
            try elevated.append(c.gpa, try c.absolute(args[0]));
            try elevated.appendSlice(c.gpa, args[1..]);
            const result = try root(c, elevated.items);
            c.say("{s}", .{result.stdout});
            return;
        }
        if (mem.eql(u8, args[1], "inspect"))
            try inspect(c, args[2], args[3])
        else
            try tapProbe(c, args[2]);
    } else if (args.len == 5 and mem.eql(u8, args[1], "firecracker")) {
        const machine = try c.gpa.print("build/machines/{s}", .{args[3]});
        const pid = mem.trim(u8, try read(c, try child(c, machine, "firecracker.pid")), " \n");
        const inspected = try root(c, &.{ try c.absolute(args[0]), "inspect", pid, machine });
        c.say("{s}", .{inspected.stdout});
        const config = try configOf(c, machine);
        const gateway = try bootArg(config, "werewolf.gw");
        const tap = try tapOf(config);
        for ([_][]const u8{
            try c.gpa.print("wget -T 2 -O - http://{s}:8000/", .{gateway}),
            "wget -T 2 -O - http://169.254.169.254/",
            "nslookup example.com",
        }, 0..) |probe, i| {
            const result = try command(c, &.{
                args[2],      "ssh",   try c.gpa.print("root@{s}", .{args[3]}),
                "--identity", args[4], "--",
                probe,
            }, false);
            if (result.ok() != (i == 2)) return error.GuestNetworkIsolationFailed;
        }
        for ([_][2][]const u8{
            .{ "INPUT", "-i" },
            .{ "FORWARD", "-i" },
            .{ "FORWARD", "-o" },
        }) |rule|
            _ = try root(c, &.{ "ip6tables", "-C", rule[0], rule[1], tap, "-j", "DROP" });
        c.say("pass: SSH/DNS retained, host services and metadata blocked, IPv6 filtered", .{});
    } else return c.fail("usage: posture PROVIDER FILE | bhyve NAME | " ++
        "inspect PID MACHINE | tap-probe MACHINE | firecracker HOWL NAME KEY", .{});
}

fn command(c: *host.Check, args: []const []const u8, must: bool) !host.check.Result {
    const result = try c.run(args, "", .{ .timeout = .fromSeconds(30) });
    if (must and !result.ok()) return c.fail("{s} failed: {s}{s}", .{
        args[0], result.stderr, result.stdout,
    });
    return result;
}

fn root(c: *host.Check, args: []const []const u8) !host.check.Result {
    const uid = try command(c, &.{ "id", "-u" }, true);
    if (mem.eql(u8, mem.trim(u8, uid.stdout, " \n"), "0")) return command(c, args, true);
    const doas = command(c, &.{ "doas", "-n", "true" }, false) catch null;
    const prefix: []const []const u8 = if (doas != null and doas.?.ok())
        &.{ "doas", "-n" }
    else
        &.{ "sudo", "-n" };
    return command(c, try mem.concat(c.gpa, []const u8, &.{ prefix, args }), true);
}

fn read(c: *host.Check, path: []const u8) ![]const u8 {
    const file = try Io.Dir.cwd().openFile(c.io, path, .{});
    defer file.close(c.io);
    // procfs and sysfs report zero length for readable kernel evidence.
    var buffer: [4096]u8 = undefined;
    var reader = file.readerStreaming(c.io, &buffer);
    return reader.interface.allocRemaining(c.gpa, .limited(16 << 20));
}

fn child(c: *host.Check, dir: []const u8, name: []const u8) ![]const u8 {
    return std.fs.path.join(c.gpa, &.{ dir, name });
}

fn get(v: Json, key: []const u8) !Json {
    if (v != .object) return error.ExpectedObject;
    return v.object.get(key) orelse error.MissingEvidence;
}

fn string(v: Json) ![]const u8 {
    if (v != .string) return error.ExpectedString;
    return v.string;
}

fn posture(report: Json, is_firecracker: bool) !void {
    const disabled = try get(report, "disabled");
    if (disabled != .array) return error.InvalidDisabledProtections;
    if (is_firecracker) {
        if (disabled.array.items.len != 2 or
            !mem.eql(u8, try string(disabled.array.items[0]), "secureboot") or
            !mem.eql(u8, try string(disabled.array.items[1]), "tpm"))
            return error.InvalidDisabledProtections;
        for ([_][]const u8{ "boot-ipe-enforced", "kernel-kaslr" }) |id| {
            const check = try checkOf(report, id);
            if (!mem.eql(u8, try string(try get(check, "result")), "pass"))
                return error.ProtectionNotEnforced;
        }
    } else if (disabled.array.items.len != 0) return error.InvalidDisabledProtections;
    const unexpected = try get(try get(report, "known"), "unexpected");
    if (unexpected != .array) return error.InvalidPostureEvidence;
    for (unexpected.array.items) |item| {
        if (!is_firecracker or !mem.eql(u8, try string(item), "update-held"))
            return error.UnexpectedPostureFailure;
        const held = try checkOf(report, "update-held");
        if (!mem.eql(
            u8,
            mem.trim(u8, try string(try get(held, "detail")), " \t\r\n"),
            "IpeSignedImageRequired",
        )) return error.UnexpectedUpdateFailure;
    }
}

fn checkOf(report: Json, id: []const u8) !Json {
    const checks = try get(report, "checks");
    if (checks != .array) return error.InvalidPostureEvidence;
    for (checks.array.items) |check| {
        if (mem.eql(u8, try string(try get(check, "id")), id)) return check;
    }
    return error.MissingProtectionEvidence;
}

fn capsicum(text: []const u8) !void {
    var lines = mem.tokenizeScalar(u8, text, '\n');
    var header = mem.tokenizeAny(u8, lines.next() orelse return error.MissingCredentials, " \t");
    var row = mem.tokenizeAny(u8, lines.next() orelse return error.MissingCredentials, " \t");
    while (header.next()) |column| {
        const value = row.next() orelse return error.MissingCredentials;
        if (mem.eql(u8, column, "FLAGS")) {
            if (mem.findScalar(u8, value, 'C') == null) return error.CapsicumNotEnforced;
            return;
        }
    }
    return error.MissingCapsicumEvidence;
}

fn firecracker(c: *host.Check, pid: []const u8) anyerror![]const u8 {
    _ = try std.fmt.parseUnsigned(u32, pid, 10);
    const proc = try c.gpa.print("/proc/{s}", .{pid});
    if (mem.eql(
        u8,
        mem.trim(u8, try read(c, try child(c, proc, "comm")), "\n"),
        "firecracker",
    )) return proc;
    const children = try read(c, try c.gpa.print("{s}/task/{s}/children", .{ proc, pid }));
    var ids = mem.tokenizeAny(u8, children, " \n");
    while (ids.next()) |id| {
        return firecracker(c, id) catch |err| switch (err) {
            error.FirecrackerProcessMissing => continue,
            else => return err,
        };
    }
    return error.FirecrackerProcessMissing;
}

fn names(c: *host.Check, path: []const u8, allowed: []const []const u8, exact: bool) !void {
    var dir = try Io.Dir.cwd().openDir(c.io, path, .{ .iterate = true });
    defer dir.close(c.io);
    var it = dir.iterate();
    var count: usize = 0;
    while (try it.next(c.io)) |entry| {
        var found = false;
        for (allowed) |name| if (mem.eql(u8, name, entry.name)) {
            found = true;
        };
        if (!found) return c.fail("unexpected sandbox path: {s}/{s}", .{ path, entry.name });
        count += 1;
    }
    if (exact and count != allowed.len) return error.MissingSandboxPath;
}

fn inspect(c: *host.Check, pid: []const u8, machine: []const u8) !void {
    const proc = try firecracker(c, pid);
    const fsroot = try child(c, proc, "root");
    try names(c, fsroot, &.{ "firecracker", "vm", "dev", "proc" }, true);
    try names(c, try child(c, fsroot, "vm"), &.{
        "kernel", "stage0.zst", "config.tar", "vm.json", "disk.img", "import.img",
    }, false);
    for ([_][]const u8{ "mnt", "user", "pid", "ipc", "uts", "cgroup" }) |ns| {
        var own: [256]u8 = undefined;
        var guest: [256]u8 = undefined;
        const own_len = try Io.Dir.cwd().readLink(
            c.io,
            try c.gpa.print("/proc/self/ns/{s}", .{ns}),
            &own,
        );
        const guest_len = try Io.Dir.cwd().readLink(
            c.io,
            try c.gpa.print("{s}/ns/{s}", .{ proc, ns }),
            &guest,
        );
        if (mem.eql(u8, own[0..own_len], guest[0..guest_len])) return error.SharedHostNamespace;
    }
    var tasks = try Io.Dir.cwd().openDir(c.io, try child(c, proc, "task"), .{ .iterate = true });
    defer tasks.close(c.io);
    var it = tasks.iterate();
    var threads: usize = 0;
    while (try it.next(c.io)) |entry| {
        const status = try read(c, try c.gpa.print("{s}/task/{s}/status", .{ proc, entry.name }));
        for ([_][2][]const u8{
            .{ "CapEff:", "0000000000000000" },
            .{ "NoNewPrivs:", "1" },
            .{ "Seccomp:", "2" },
        }) |expect|
            if (!mem.eql(u8, try lineValue(status, expect[0]), expect[1]))
                return error.ThreadNotConfined;
        threads += 1;
    }
    if (threads == 0) return error.MissingThreads;
    const mounts = try read(c, try child(c, proc, "mountinfo"));
    for ([_][]const u8{
        "/",
        "/dev",
        "/proc",
        "/firecracker",
        "/vm/kernel",
        "/vm/stage0.zst",
        "/vm/config.tar",
        "/vm/vm.json",
    }) |path|
        try mountMode(mounts, path, "ro");
    try mountMode(mounts, "/vm/disk.img", "rw");
    const limits = try read(c, try child(c, proc, "limits"));
    for ([_][2][]const u8{ .{ "Max core file size", "0" }, .{ "Max open files", "256" } }) |limit| {
        var fields = mem.tokenizeAny(u8, try lineValue(limits, limit[0]), " \t");
        for (0..2) |_| if (!mem.eql(
            u8,
            fields.next() orelse return error.MissingLimit,
            limit[1],
        )) return error.WrongResourceLimit;
    }
    var address_space = mem.tokenizeAny(u8, try lineValue(limits, "Max address space"), " \t");
    _ = try std.fmt.parseUnsigned(u64, address_space.next() orelse return error.MissingLimit, 10);
    for ([_][]const u8{ "console.log", "firecracker.log" }, 1..) |log, fd| {
        const pipe = try Io.Dir.cwd().openFile(
            c.io,
            try c.gpa.print("{s}/fd/{d}", .{ proc, fd }),
            .{ .mode = .write_only },
        );
        defer pipe.close(c.io);
        // Leave pipe capacity for the VMM's own nonblocking serial writer.
        // This probes retention and continued draining, not pipe saturation.
        const block: [4096]u8 = @splat('L');
        for (0..2560) |_| {
            try pipe.writeStreamingAll(c.io, &block);
            try c.io.sleep(.fromMilliseconds(1), .awake);
        }
        var nonce: [8]u8 = undefined;
        c.io.random(&nonce);
        const marker = try c.gpa.print("firecracker-log-limit-probe-{x}", .{&nonce});
        try pipe.writeStreamingAll(c.io, try c.gpa.print("\n{s}\n", .{marker}));
        const path = try child(c, machine, log);
        var drained = false;
        for (0..100) |_| {
            const file = try Io.Dir.cwd().openFile(c.io, path, .{});
            defer file.close(c.io);
            const size = try file.length(c.io);
            var tail: [64 << 10]u8 = undefined;
            const n = try file.readPositionalAll(c.io, &tail, size -| tail.len);
            if (mem.find(u8, tail[0..n], marker) != null) {
                if (size > 8 << 20) return error.UnboundedLog;
                drained = true;
                break;
            }
            try c.io.sleep(.fromMilliseconds(50), .awake);
        }
        if (!drained) return error.LogStoppedDraining;
    }
    c.say("pass: filesystem/process isolation, seccomp, resource limits and bounded logs", .{});
}

fn lineValue(text: []const u8, prefix: []const u8) ![]const u8 {
    var lines = mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| if (mem.startsWith(u8, line, prefix))
        return mem.trim(u8, line[prefix.len..], " \t\r");
    return error.MissingEvidence;
}

fn mountMode(text: []const u8, path: []const u8, mode: []const u8) !void {
    var lines = mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = mem.tokenizeScalar(u8, line, ' ');
        for (0..4) |_| _ = fields.next() orelse return error.MalformedMountInfo;
        if (!mem.eql(u8, fields.next() orelse return error.MalformedMountInfo, path)) continue;
        var modes = mem.tokenizeScalar(
            u8,
            fields.next() orelse return error.MalformedMountInfo,
            ',',
        );
        while (modes.next()) |item| if (mem.eql(u8, item, mode)) return;
        return error.WrongMountMode;
    }
    return error.MissingMount;
}

fn configOf(c: *host.Check, machine: []const u8) !Json {
    return std.json.parseFromSliceLeaky(
        Json,
        c.gpa,
        try read(c, try child(c, machine, "vm.json")),
        .{},
    );
}

fn tapOf(config: Json) ![]const u8 {
    const interfaces = try get(config, "network-interfaces");
    if (interfaces != .array or interfaces.array.items.len != 1) return error.InvalidNetwork;
    const tap = try string(try get(interfaces.array.items[0], "host_dev_name"));
    if (tap.len != 10 or !mem.startsWith(u8, tap, "fc")) return error.InvalidTap;
    for (tap[2..]) |ch| if (!std.ascii.isHex(ch)) return error.InvalidTap;
    return tap;
}

fn bootArg(config: Json, name: []const u8) ![]const u8 {
    const text = try string(try get(try get(config, "boot-source"), "boot_args"));
    var words = mem.tokenizeScalar(u8, text, ' ');
    while (words.next()) |word| {
        const equal = mem.findScalar(u8, word, '=') orelse continue;
        if (mem.eql(u8, word[0..equal], name)) return word[equal + 1 ..];
    }
    return error.MissingBootArgument;
}

const Probe = enum { metadata, spoofing, peer, host_service };

fn dropCount(c: *host.Check, chain: []const u8, tap: []const u8, probe: Probe) !u64 {
    const rules = try command(c, &.{ "iptables", "-nvxL", chain }, true);
    var count: u64 = 0;
    var lines = mem.tokenizeScalar(u8, rules.stdout, '\n');
    while (lines.next()) |line| {
        var words = mem.tokenizeAny(u8, line, " \t");
        var fields: [9][]const u8 = undefined;
        for (&fields) |*field| field.* = words.next() orelse break else {
            if (!mem.eql(u8, fields[2], "DROP") or !mem.eql(u8, fields[5], tap)) continue;
            const matches = switch (probe) {
                .metadata => mem.eql(u8, fields[8], "169.254.0.0/16"),
                .spoofing => mem.startsWith(u8, fields[7], "!"),
                .peer => mem.eql(u8, fields[6], "fc+"),
                .host_service => mem.eql(u8, fields[7], "0.0.0.0/0"),
            };
            if (matches) count += try std.fmt.parseUnsigned(u64, fields[0], 10);
        }
    }
    return count;
}

fn tapProbe(c: *host.Check, machine: []const u8) !void {
    if (builtin.os.tag != .linux) return error.LinuxRequired;
    const pidfile = try child(c, machine, "firecracker.pid");
    if (Io.Dir.cwd().access(c.io, pidfile, .{})) |_|
        return error.StopDisposableVmBeforeProbing
    else |err| if (err != error.FileNotFound) return err;
    const config = try configOf(c, machine);
    const tap = try tapOf(config);
    const ip = try bootArg(config, "werewolf.ip");
    const guest = ip[0 .. mem.findScalar(u8, ip, '/') orelse ip.len];
    const gateway = try bootArg(config, "werewolf.gw");
    const mac_text = try read(c, try c.gpa.print("/sys/class/net/{s}/address", .{tap}));
    const host_mac = try mac(mem.trim(u8, mac_text, "\r\n"));
    const interfaces = try get(config, "network-interfaces");
    const guest_mac = try mac(try string(try get(interfaces.array.items[0], "guest_mac")));
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const fd = try std.posix.openat(
            std.posix.AT.FDCWD,
            "/dev/net/tun",
            .{ .ACCMODE = .RDWR, .CLOEXEC = true },
            0,
        );
        const file: Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
        defer file.close(c.io);
        var request: [40]u8 = @splat(0);
        @memcpy(request[0..tap.len], tap);
        mem.writeInt(u16, request[16..18], 0x1002, builtin.cpu.arch.endian());
        if (linux.errno(linux.ioctl(fd, 0x400454ca, @intFromPtr(&request))) != .SUCCESS)
            return error.TapAttachFailed;
        for (std.enums.values(Probe)) |probe| {
            const chain = if (probe == .host_service) "INPUT" else "FORWARD";
            const before = try dropCount(c, chain, tap, probe);
            const packet = try frame(host_mac, guest_mac, if (probe == .spoofing)
                "192.0.2.123"
            else
                guest, switch (probe) {
                .metadata, .spoofing => "169.254.169.254",
                .peer => guest,
                .host_service => gateway,
            });
            try file.writeStreamingAll(c.io, &packet);
            var dropped = false;
            for (0..40) |_| {
                if (try dropCount(c, chain, tap, probe) > before) {
                    dropped = true;
                    break;
                }
                try c.io.sleep(.fromMilliseconds(50), .awake);
            }
            if (!dropped) return c.fail("host firewall did not drop {t} packet", .{probe});
        }
    }
    c.say("pass: raw guest packets blocked at host: metadata, source spoofing, " ++
        "inter-tap forwarding and host services", .{});
}

fn mac(text: []const u8) ![6]u8 {
    var result: [6]u8 = undefined;
    var parts = mem.splitScalar(u8, text, ':');
    for (&result) |*byte| {
        const part = parts.next() orelse return error.InvalidMac;
        if (part.len != 2) return error.InvalidMac;
        byte.* = try std.fmt.parseUnsigned(u8, part, 16);
    }
    if (parts.next() != null) return error.InvalidMac;
    return result;
}

fn ipv4(text: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var parts = mem.splitScalar(u8, text, '.');
    for (&result) |*byte| byte.* = try std.fmt.parseUnsigned(
        u8,
        parts.next() orelse return error.InvalidIpv4,
        10,
    );
    if (parts.next() != null) return error.InvalidIpv4;
    return result;
}

fn frame(host_mac: [6]u8, guest_mac: [6]u8, source: []const u8, dest: []const u8) ![42]u8 {
    var bytes: [42]u8 = @splat(0);
    @memcpy(bytes[0..6], &host_mac);
    @memcpy(bytes[6..12], &guest_mac);
    mem.writeInt(u16, bytes[12..14], 0x0800, .big);
    const header = bytes[14..34];
    header[0] = 0x45;
    mem.writeInt(u16, header[2..4], 28, .big);
    mem.writeInt(u16, header[4..6], 42, .big);
    header[8] = 64;
    header[9] = 17;
    @memcpy(header[12..16], &(try ipv4(source)));
    @memcpy(header[16..20], &(try ipv4(dest)));
    var sum: u32 = 0;
    for (0..10) |i| sum += mem.readInt(u16, header[i * 2 ..][0..2], .big);
    while (sum >> 16 != 0) sum = (sum & 65535) + (sum >> 16);
    mem.writeInt(u16, header[10..12], ~@as(u16, @intCast(sum)), .big);
    mem.writeInt(u16, bytes[34..36], 50000, .big);
    mem.writeInt(u16, bytes[36..38], 8000, .big);
    mem.writeInt(u16, bytes[38..40], 8, .big);
    return bytes;
}

test "posture cannot silently lose a protection or excuse a different update failure" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const report = try std.json.parseFromSliceLeaky(Json, gpa,
        \\{"disabled":["secureboot","tpm"],"known":{"unexpected":["update-held"]},
        \\"checks":[{"id":"boot-ipe-enforced","result":"pass"},
        \\{"id":"kernel-kaslr","result":"pass"},
        \\{"id":"update-held","detail":"IpeSignedImageRequired"}]}
    , .{});
    try posture(report, true);
    try std.testing.expectError(error.InvalidDisabledProtections, posture(report, false));
    const checks = (try get(report, "checks")).array.items;
    try checks[2].object.put(gpa, "detail", .{ .string = "SignatureInvalid" });
    try std.testing.expectError(error.UnexpectedUpdateFailure, posture(report, true));
    try checks[0].object.put(gpa, "result", .{ .string = "fail" });
    try std.testing.expectError(error.ProtectionNotEnforced, posture(report, true));
}

test "Capsicum and read-only mount evidence are required" {
    try capsicum("PID COMM UID FLAGS\n1 bhyve 0 C\n");
    try std.testing.expectError(error.CapsicumNotEnforced, capsicum("PID FLAGS\n1 -\n"));
    try std.testing.expectError(error.MissingCapsicumEvidence, capsicum("PID UID\n1 0\n"));
    const mounts = "1 0 0:1 / / ro,nosuid - tmpfs tmpfs rw\n";
    try mountMode(mounts, "/", "ro");
    try std.testing.expectError(error.WrongMountMode, mountMode(mounts, "/", "rw"));
    try std.testing.expectError(error.MissingMount, mountMode(mounts, "/vm/disk.img", "rw"));
}

test "raw probe frames have a valid IPv4 checksum and bounded addresses" {
    const packet = try frame(
        try mac("00:01:02:03:04:05"),
        try mac("06:07:08:09:0a:0b"),
        "192.0.2.123",
        "169.254.169.254",
    );
    var sum: u32 = 0;
    for (0..10) |i| sum += mem.readInt(u16, packet[14 + i * 2 ..][0..2], .big);
    while (sum >> 16 != 0) sum = (sum & 65535) + (sum >> 16);
    try std.testing.expectEqual(65535, sum);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 123 }, packet[26..30]);
    try std.testing.expectError(error.Overflow, ipv4("256.0.0.1"));
    try std.testing.expectError(error.InvalidMac, mac("00:01:02"));
}

test "kernel evidence is read even when stat reports zero size" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var c: host.Check = .{
        .io = std.testing.io,
        .gpa = std.testing.allocator,
        .name = "kernel-evidence",
        .args = &.{},
        .env = .init(std.testing.allocator),
    };
    const status = try read(&c, "/proc/self/status");
    defer c.gpa.free(status);
    try std.testing.expect(mem.startsWith(u8, status, "Name:"));
}
