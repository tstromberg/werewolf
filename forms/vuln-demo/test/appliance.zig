//! appliance --build DIR boots the shipping vuln-demo image from DIR under
//! QEMU and probes it over host-forwarded HTTP and SSH with its Go test,
//! adding no guest programs or permissions (forms/vuln-demo/README.md).
//! make check-vuln-demo-appliance runs it.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const join = std.fs.path.join;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "vuln-demo appliance") catch |err| {
        std.log.err("vuln-demo appliance: {t}", .{err});
        std.process.exit(1);
    };
    c.finish(run(&c));
}

/// Port is a guest port and the loopback port forwarded to it.
const Port = struct { guest: u16, host: u16 };

const guest_ports = [_]u16{ 22, 8080, 8983, 5678, 7860 };

fn run(c: *host.Check) !void {
    const gpa = c.gpa;
    const io = c.io;
    const given = buildArgument(c.args[1..]) orelse
        return c.fail("usage: appliance --build DIR, the BUILD holding the shipping image", .{});
    const build = try c.absolute(given);
    const out = try join(gpa, &.{ build, "vuln-demo" });
    const kernel = try join(gpa, &.{ build, "vmlinuz" });
    const initramfs = try join(gpa, &.{ out, "initramfs.zst" });
    const cmdline_file = try join(gpa, &.{ out, "slot/cmdline" });
    for ([_][]const u8{ kernel, initramfs, cmdline_file }) |p|
        Io.Dir.cwd().access(io, p, .{}) catch
            return c.fail("Build the shipping image first: missing {s}", .{p});
    try c.setWork(try join(gpa, &.{ build, "check/vuln-demo-appliance" }));
    const config = try c.path("config");
    try Io.Dir.cwd().createDirPath(io, config);
    var key: [64]u8 = undefined;
    io.random(&key);
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = try join(gpa, &.{ config, "data.key" }),
        .data = &key,
        .flags = .{ .permissions = .fromMode(0o600) },
    });
    _ = try c.must(&.{ "forms/vuln-demo/test/config", config }, "config", .{});
    const tar = try c.path("config.tar");
    const pack = [_][]const u8{ "build/host/howl", "pack", "--build", "--with", "vuln-demo" };
    _ = try c.must(&(pack ++ .{ "-o", tar, "--config", config }), "pack", .{});
    const data = try c.path("data.img");
    {
        const f = try Io.Dir.cwd().createFile(io, data, .{ .permissions = .fromMode(0o600) });
        defer f.close(io);
        try f.setLength(io, 4 << 30);
    }
    var ports: [guest_ports.len]Port = undefined;
    for (&ports, guest_ports) |*p, guest|
        p.* = .{ .guest = guest, .host = try host.check.freePort(io) };
    const qmp = try c.path("qmp.sock");
    Io.Dir.cwd().deleteFile(io, qmp) catch {};
    const arm = builtin.cpu.arch == .aarch64;
    const slot_cmdline = try Io.Dir.cwd().readFileAlloc(io, cmdline_file, gpa, .limited(64 << 10));
    const append = try gpa.print("{s} werewolf.check=1 werewolf.ip=10.0.2.15/24 " ++
        "werewolf.gw=10.0.2.2 werewolf.dns=10.0.2.3 werewolf.data=vda", .{
        mem.trim(u8, slot_cmdline, " \t\r\n"),
    });
    const argv: []const []const u8 = &.{
        if (arm) "qemu-system-aarch64" else "qemu-system-x86_64",
        "-M",
        if (arm) "virt,virtualization=on" else "q35",
        "-accel",
        if (builtin.os.tag == .macos) "hvf" else "kvm",
        "-cpu",
        "host",
        "-nographic",
        "-smp",
        "4",
        "-m",
        "12288",
        "-no-reboot",
        "-device",
        "virtio-rng-pci",
        "-netdev",
        try network(gpa, &ports),
        "-device",
        "virtio-net-pci,netdev=n0,romfile=",
        "-kernel",
        kernel,
        "-initrd",
        initramfs,
        "-append",
        append,
        "-drive",
        try gpa.print("file={s},format=raw,if=virtio", .{data}),
        "-drive",
        try gpa.print("file={s},format=raw,if=virtio,readonly=on", .{tar}),
        "-qmp",
        try gpa.print("unix:{s},server=on,wait=off", .{qmp}),
    };
    var env = try c.env.clone(gpa);
    const root = try c.absolute(".");
    if (env.get("GOCACHE") == null)
        try env.put("GOCACHE", try join(gpa, &.{ root, "build/go-cache" }));
    if (env.get("GOMODCACHE") == null)
        try env.put("GOMODCACHE", try join(gpa, &.{ root, "build/go-mod-cache" }));
    const services = [_]struct { []const u8, u16 }{
        .{ "URL", 8080 }, .{ "SOLR", 8983 }, .{ "N8N", 5678 }, .{ "LANGFLOW", 7860 },
    };
    for (services) |s| {
        const url = try gpa.print("http://127.0.0.1:{d}", .{forwarded(&ports, s[1])});
        try env.put(try gpa.print("VULN_DEMO_TEST_{s}", .{s[0]}), url);
    }
    try env.put("VULN_DEMO_TEST_SSH", try gpa.print("127.0.0.1:{d}", .{forwarded(&ports, 22)}));
    const log = try c.path("console.log");
    var m: host.qemu.Machine = undefined;
    try m.start(io, gpa, argv, .{ .log = log, .environ_map = &env });
    defer powerOff(c, &m, qmp);
    const go_test = [_][]const u8{ "go", "test", "-count=1", "-tags", "integration" };
    const appliance = [_][]const u8{ "-run", "^TestAppliance$", "-v", "-timeout", "15m", "./..." };
    var probe = try std.process.spawn(io, .{
        .argv = &(go_test ++ appliance),
        .cwd = .{ .path = "forms/vuln-demo/melange" },
        .environ_map = &env,
        .stdin = .ignore,
    });
    const term = try probe.wait(io);
    if (!term.success()) return c.fail("go test {f}", .{term});
    c.say("vuln-demo appliance: passed; console: {s}", .{log});
}

/// buildArgument is DIR of --build DIR or --build=DIR, the only argument.
fn buildArgument(args: []const [:0]const u8) ?[]const u8 {
    if (args.len == 2 and mem.eql(u8, args[0], "--build")) return args[1];
    if (args.len != 1 or !mem.startsWith(u8, args[0], "--build=")) return null;
    const dir = args[0]["--build=".len..];
    return if (dir.len > 0) dir else null;
}

/// network is QEMU's user network forwarding each loopback port to its guest port.
fn network(gpa: Allocator, ports: []const Port) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "user,id=n0");
    for (ports) |p| try out.print(gpa, ",hostfwd=tcp:127.0.0.1:{d}-:{d}", .{ p.host, p.guest });
    return out.items;
}

fn forwarded(ports: []const Port, guest: u16) u16 {
    for (ports) |p| if (p.guest == guest) return p.host;
    unreachable;
}

/// powerOff asks the guest to shut down through QEMU's monitor, gives it
/// 45 seconds, and stops QEMU if it has not ended by then.
fn powerOff(c: *host.Check, m: *host.qemu.Machine, qmp: []const u8) void {
    const Never = struct {
        pub fn done(_: @This(), _: []const u8) !bool {
            return false;
        }
    };
    if (!m.exited()) if (host.qmp.command(c.io, c.gpa, qmp, "system_powerdown", null)) |_| {
        m.until(host.qemu.after(c.io, 45), Never{}) catch {};
    } else |_| {};
    m.stop(.fromSeconds(5));
}

test "the build directory is the one argument" {
    try std.testing.expectEqualStrings("b", buildArgument(&.{ "--build", "b" }).?);
    try std.testing.expectEqualStrings("b", buildArgument(&.{"--build=b"}).?);
    try std.testing.expectEqual(null, buildArgument(&.{}));
    try std.testing.expectEqual(null, buildArgument(&.{"--build="}));
    try std.testing.expectEqual(null, buildArgument(&.{ "--build", "b", "x" }));
}

test "each guest port is forwarded from its own loopback port" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const ports = [_]Port{ .{ .guest = 22, .host = 4022 }, .{ .guest = 8080, .host = 4080 } };
    try std.testing.expectEqualStrings(
        "user,id=n0,hostfwd=tcp:127.0.0.1:4022-:22,hostfwd=tcp:127.0.0.1:4080-:8080",
        try network(arena.allocator(), &ports),
    );
    try std.testing.expectEqual(4080, forwarded(&ports, 8080));
}
