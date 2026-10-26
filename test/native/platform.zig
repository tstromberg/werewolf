//! Shared clean-boot checks. Production services and their policies stay intact.
const std = @import("std");
const driver = @import("test-driver");
const system = driver.system;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Json = std.json.Value;
const linux = std.os.linux;
const mark = "/data/.werewolf-platform-check";
const Plan = struct { seed: []const []const u8, verify: []const []const u8 };
const Check = enum {
    network,
    @"services-up",
    @"boot-quiet",
    listeners,
    answering,
    @"http-answering",
    @"data-usable",
    @"data-encrypted",
    @"slot-commits",
    @"root-unlinked",
    @"root-verified",
    @"age-cache-protected",
    cgrouped,
    reaped,
    sealed,
    @"power-separated",
    @"data-mark",
    @"data-kept",
};
const Port = struct { protocol: []const u8, port: u16, loopback: bool };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len == 2 and std.mem.eql(u8, args[1], "hold")) {
        try io.sleep(.fromSeconds(120), .awake);
        std.process.exit(1);
    }
    if (args.len != 4 or (!std.mem.eql(u8, args[1], "test-platform") and
        !std.mem.eql(u8, args[1], "test-lifecycle"))) return error.Usage;
    const suite = args[1];
    const ctx = try driver.Run.load(io, a, args[3]);
    const plan = try std.json.parseFromSliceLeaky(Plan, a, @embedFile("platform.json"), .{});
    // The old console checks ran after posture. Its attacks and initial service
    // setup must finish before inspecting the kernel log or restarting a service.
    const ready = try waitFile(io, "/run/werewolf/posture.json", 240);
    var passed = true;
    const cases = if (std.mem.eql(u8, ctx.phase, "seed")) plan.seed else plan.verify;
    for (cases) |name| {
        var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer arena.deinit();
        var reason: []const u8 = "";
        if (!ready) reason = "PostureUnavailable" else {
            const check = std.meta.stringToEnum(Check, name) orelse return error.UnknownCheck;
            run(io, arena.allocator(), ctx, check) catch |err| {
                reason = @errorName(err);
            };
        }
        try driver.emit(io, .{
            .event = "case",
            .run = ctx.run,
            .phase = ctx.phase,
            .suite = suite,
            .case = name,
            .status = if (reason.len == 0) "pass" else "fail",
            .reason = reason,
        });
        passed = passed and reason.len == 0;
    }
    if (!passed) std.process.exit(1);
}

fn run(io: Io, a: Allocator, ctx: driver.Run, check: Check) !void {
    switch (check) {
        .network => {
            if (std.mem.find(
                u8,
                try system.read(io, a, "/proc/net/fib_trie"),
                "10.0.2.15",
            ) == null or
                !defaultRoute(try system.read(
                    io,
                    a,
                    "/proc/net/route",
                ))) return error.NetworkUnavailable;
        },
        .@"services-up" => try servicesUp(io, a),
        .@"boot-quiet" => try bootQuiet(a),
        .listeners => {
            const ports = try policyPorts(a, try system.read(io, a, "/usr/share/werewolf/net"));
            const sockets = try system.listeners(io, a, "all");
            for (sockets.array.items) |socket| {
                const protocol = socket.object.get("protocol").?.string;
                const address = socket.object.get("address").?.string;
                const port: u16 = @intCast(socket.object.get("port").?.integer);
                if (!allowedListener(ports, protocol, address, port)) {
                    std.debug.print(
                        "test-platform: undeclared {s}/{d} on {s}\n",
                        .{ protocol, port, address },
                    );
                    if (std.mem.eql(u8, protocol, "udp")) {
                        // Keep the kernel UID and inode in the diagnostic:
                        // unconnected UDP clients also appear in this table.
                        std.debug.print(
                            "test-platform: UDP sockets:\n{s}\n",
                            .{try system.read(io, a, "/proc/net/udp")},
                        );
                    }
                    return error.UndeclaredListener;
                }
            }
        },
        .answering, .@"http-answering" => try answering(io, a, check == .@"http-answering"),
        .@"data-usable" => if (try exists(
            io,
            "/run/werewolf/nodata",
        )) {
            return error.DataUnavailable;
        },
        .@"data-encrypted" => {
            if (try exists(io, "/usr/bin/cryptsetup")) {
                const data = try system.mount(io, a, "/data");
                if (!std.mem.eql(
                    u8,
                    data.object.get("source").?.string,
                    "/dev/mapper/data",
                )) return error.DataUnencrypted;
            }
        },
        .@"slot-commits" => {
            if (std.mem.find(
                u8,
                try system.read(io, a, "/proc/cmdline"),
                "werewolf.slot=",
            ) != null and
                !try waitFile(io, "/run/werewolf/committed", 120)) return error.SlotNotCommitted;
        },
        .@"root-unlinked" => {
            if (linux.errno(linux.unlink("/init")) != .ROFS or
                !try exists(io, "/init")) return error.RootUnlink;
            if (!hasFlag(try system.mount(io, a, "/"), "ro")) return error.RootWritable;
        },
        .@"root-verified" => {
            const root = try system.mount(io, a, "/");
            if (!std.mem.eql(u8, root.object.get("source").?.string, "/dev/mapper/root") or
                !std.mem.eql(u8, root.object.get("type").?.string, "erofs") or
                !hasFlag(root, "ro") or
                !std.mem.eql(
                    u8,
                    trim(try system.read(io, a, "/sys/block/dm-0/dm/name")),
                    "root",
                )) return error.RootNotVerified;
            try directory(io, "/sys/module/dm_verity");
            var loop = false;
            for (try names(
                io,
                a,
                "/sys/block/dm-0/slaves",
            )) |name| loop = loop or std.mem.startsWith(u8, name, "loop");
            if (!loop) return error.RootBackingDevice;
        },
        .@"age-cache-protected" => try ageCacheProtected(io, a),
        .cgrouped => {
            if (!try exists(io, "/run/cgroup/svc")) return;
            for (try leashed(io, a)) |name| {
                const status = try system.service(io, a, name);
                if (!std.mem.eql(
                    u8,
                    status.object.get("pids_max").?.string,
                    "4096",
                )) return error.UnboundedService;
            }
        },
        .reaped => try reaped(io, a),
        .sealed => try sealed(io, a),
        .@"power-separated" => try powerSeparated(io, a),
        .@"data-mark", .@"data-kept" => {
            const data = try system.mount(io, a, "/data");
            if (std.mem.eql(u8, data.object.get("type").?.string, "tmpfs")) return;
            if (check == .@"data-kept") {
                if (!std.mem.eql(
                    u8,
                    try system.read(io, a, mark),
                    ctx.run,
                )) return error.DataNotKept;
            } else {
                var file = try Io.Dir.cwd().createFile(
                    io,
                    mark,
                    .{ .permissions = .fromMode(0o600) },
                );
                defer file.close(io);
                try file.writeStreamingAll(io, ctx.run);
                try file.sync(io);
            }
        },
    }
}

fn ageCacheProtected(io: Io, a: Allocator) !void {
    if (!try exists(io, "/usr/share/werewolf/age-enforce")) return error.AgeMarkerMissing;
    const directory_path: [:0]const u8 = if (try exists(io, "/run/werewolf/nodata"))
        "/run/werewolf-age-cache"
    else
        "/data/svc/unwound-age";
    for ([_][:0]const u8{ directory_path, "/run/werewolf-age" }) |path| {
        const mounted = try system.mount(io, a, path);
        for ([_][]const u8{ "ro", "nosuid", "nodev", "noexec", "nosymfollow" }) |flag|
            if (!hasFlag(mounted, flag)) return error.AgeMountFlags;
        const rc = linux.mount(null, path, null, linux.MS.BIND | linux.MS.REMOUNT, 0);
        if (linux.errno(rc) == .SUCCESS) return error.AgeRemounted;
    }
    // Nor may root make a second, writable view of the cache somewhere else.
    const alias = "/run/age-alias-check";
    try Io.Dir.cwd().createDirPath(io, alias);
    defer Io.Dir.cwd().deleteDir(io, alias) catch {};
    if (linux.errno(linux.mount(directory_path, alias, null, linux.MS.BIND, 0)) == .SUCCESS) {
        _ = linux.umount2(alias, linux.MNT.DETACH);
        return error.AgeAliasMounted;
    }
    const db_path: [:0]const u8 = if (std.mem.eql(u8, directory_path, "/data/svc/unwound-age"))
        "/data/svc/unwound-age/age.db"
    else
        "/run/werewolf-age-cache/age.db";
    if (linux.errno(linux.open(db_path, .{ .ACCMODE = .WRONLY }, 0)) != .ROFS)
        return error.AgeCacheWritable;
    if (linux.errno(linux.unlink("/run/werewolf-age/age.sock")) != .ROFS)
        return error.AgeSocketReplaceable;
    const mounts = try system.read(io, a, "/proc/self/mountinfo");
    var lines = std.mem.splitScalar(u8, mounts, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "unwound-age") == null) continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        for (0..4) |_| _ = fields.next() orelse return error.BadMountInfo;
        const target = fields.next() orelse return error.BadMountInfo;
        if (!std.mem.eql(u8, target, directory_path) and
            !std.mem.eql(u8, target, "/run/werewolf-age")) return error.AgeMountAlias;
    }
}

fn trim(raw: []const u8) []const u8 {
    return std.mem.trim(u8, raw, " \t\r\n");
}
fn exists(io: Io, path: []const u8) !bool {
    Io.Dir.cwd().access(io, path, .{}) catch |err| {
        if (err == error.FileNotFound) return false;
        return err;
    };
    return true;
}
fn directory(io: Io, path: []const u8) !void {
    var dir = try Io.Dir.cwd().openDir(io, path, .{});
    dir.close(io);
}
fn waitFile(io: Io, path: []const u8, seconds: u32) !bool {
    for (0..seconds * 10) |_| {
        if (try exists(io, path)) return true;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    return false;
}
fn names(io: Io, a: Allocator, path: []const u8) ![]const []const u8 {
    var dir = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    var result: std.ArrayList([]const u8) = .empty;
    while (try it.next(io)) |entry| {
        if (result.items.len == 8192) return error.TooManyEntries;
        try result.append(a, try a.dupe(u8, entry.name));
    }
    std.mem.sort([]const u8, result.items, {}, struct {
        fn less(
            _: void,
            x: []const u8,
            y: []const u8,
        ) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.less);
    return result.toOwnedSlice(a);
}
fn leashed(io: Io, a: Allocator) ![]const []const u8 {
    var result: std.ArrayList([]const u8) = .empty;
    for (try names(io, a, "/etc/sv")) |name| {
        if (try exists(io, try a.print("/etc/sv/{s}/service", .{name}))) try result.append(a, name);
    }
    return result.toOwnedSlice(a);
}
fn defaultRoute(raw: []const u8) bool {
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        _ = fields.next() orelse continue;
        const dest = fields.next() orelse continue;
        const gateway = fields.next() orelse continue;
        if (std.mem.eql(u8, dest, "00000000") and std.mem.eql(u8, gateway, "0202000A")) return true;
    }
    return false;
}
fn settled(raw: []const u8, now: u64) bool {
    if (raw.len != 20) return false;
    const since = std.mem.readInt(u64, raw[0..8], .big) -| ((1 << 62) + 10);
    return switch (raw[19]) {
        0 => raw[17] == 'd',
        1 => raw[17] == 'u' and now -| since >= 2,
        else => false,
    };
}
fn servicesUp(io: Io, a: Allocator) !void {
    const services = try names(io, a, "/etc/sv");
    for (0..1200) |_| {
        var arena: std.heap.ArenaAllocator = .init(a);
        defer arena.deinit();
        var ok = true;
        for (services) |name| {
            const raw = system.read(
                io,
                arena.allocator(),
                try a.print("/etc/sv/{s}/supervise/status", .{name}),
            ) catch |err| {
                if (err != error.FileNotFound) return err;
                ok = false;
                continue;
            };
            if (!settled(
                raw,
                @intCast(@max(0, Io.Timestamp.now(io, .real).toSeconds())),
            )) ok = false;
        }
        if (ok) return;
        try io.sleep(.fromMilliseconds(100), .awake);
    }
    return error.ServicesUnsettled;
}
fn quiet(raw: []const u8) bool {
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        if (std.mem.find(u8, line, "Lockdown:") == null and
            std.mem.find(u8, line, "ptrace attach") == null) continue;
        if (std.mem.find(u8, line, "Lockdown: run: /dev/mem") != null or
            std.mem.find(
                u8,
                line,
                "ptrace attach of \"runit\"[1] was attempted by \"./run\"",
            ) != null) continue;
        return false;
    }
    return true;
}
fn bootQuiet(a: Allocator) !void {
    const size = linux.syscall3(.syslog, 10, 0, 0);
    if (linux.errno(size) != .SUCCESS or size > 8 << 20) return error.KernelLogSize;
    const buffer = try a.alloc(u8, size);
    const length = linux.syscall3(.syslog, 3, @intFromPtr(buffer.ptr), buffer.len);
    if (linux.errno(length) != .SUCCESS) return error.KernelLogRead;
    if (!quiet(buffer[0..length])) return error.KernelViolation;
}
fn policyPorts(a: Allocator, raw: []const u8) ![]const Port {
    var ports: std.ArrayList(Port) = .empty;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t");
        if (!std.mem.eql(u8, words.next() orelse continue, "listen")) continue;
        var protocol = words.next() orelse return error.NetworkPolicy;
        if (!std.mem.eql(u8, protocol, "tcp")) {
            _ = try std.fmt.parseInt(u32, protocol, 10);
            protocol = words.next() orelse return error.NetworkPolicy;
            if (!std.mem.eql(u8, protocol, "udp")) return error.NetworkPolicy;
        }
        const port = try std.fmt.parseInt(u16, words.next() orelse return error.NetworkPolicy, 10);
        if (port == 0) return error.NetworkPolicy;
        const scope = words.next();
        const tcp = std.mem.eql(u8, protocol, "tcp");
        if (scope != null and !std.mem.eql(u8, scope.?, "lan") and
            !(tcp and std.mem.eql(u8, scope.?, "loopback")))
            return error.NetworkPolicy;
        if (words.next() != null) return error.NetworkPolicy;
        try ports.append(
            a,
            .{ .protocol = protocol, .port = port, .loopback = tcp and scope != null and
                std.mem.eql(u8, scope.?, "loopback") },
        );
    }
    return ports.toOwnedSlice(a);
}
fn loopback(address: []const u8) bool {
    return std.mem.startsWith(u8, address, "127.") or std.mem.eql(u8, address, "0:0:0:0:0:0:0:1") or
        std.mem.eql(u8, address, "::1");
}
fn allowedListener(ports: []const Port, protocol: []const u8, address: []const u8, port: u16) bool {
    if (loopback(address)) return true;
    for (ports) |allow| {
        if (!allow.loopback and allow.port == port and
            std.mem.eql(u8, allow.protocol, protocol)) return true;
    }
    return false;
}
fn answering(io: Io, a: Allocator, http: bool) !void {
    if (http) for ([_][]const u8{
        "/usr/bin/bao",
        "/usr/sbin/mosquitto",
        "/usr/bin/mosquitto",
        "/usr/bin/nats-server",
    }) |path| {
        if (try exists(io, path)) return;
    };
    const ports = try policyPorts(a, try system.read(io, a, "/usr/share/werewolf/net"));
    var client = if (http) try driver.fetch.Client.init(a) else null;
    defer if (client) |*c| c.deinit();
    for (ports) |port| {
        // Public ports only, as a client would reach them: a loopback listener
        // may open only while it has work, as n8n's task runner does.
        if (!std.mem.eql(u8, port.protocol, "tcp") or port.port == 22 or port.loopback) continue;
        if (http and port.port == 443) continue;
        // Cold application setup may finish after its supervisor reports up.
        const until = Io.Clock.awake.now(io).addDuration(.fromSeconds(120));
        while (true) {
            var arena: std.heap.ArenaAllocator = .init(a);
            defer arena.deinit();
            const alloc = arena.allocator();
            var ok = false;
            if (http) {
                var request = system.object(alloc);
                try request.object.put(
                    alloc,
                    "url",
                    system.text(try alloc.print("http://127.0.0.1:{d}/", .{port.port})),
                );
                const response = client.?.request(request, 5000, alloc) catch |err| switch (err) {
                    error.ConnectionRefused, error.Timeout => null,
                    else => return err,
                };
                if (response) |got| {
                    const status = got.object.get("status").?.integer;
                    ok = status >= 100 and status <= 599;
                }
            } else {
                const sockets = try system.listeners(io, alloc, "tcp");
                for (sockets.array.items) |socket| ok = ok or
                    socket.object.get("port").?.integer == port.port;
            }
            if (ok) break;
            if (Io.Clock.awake.now(io).compare(.gte, until)) {
                std.debug.print(
                    "test-platform: readiness timed out for tcp/{d} (HTTP: {})\n",
                    .{ port.port, http },
                );
                return error.PortNotAnswering;
            }
            try io.sleep(.fromMilliseconds(100), .awake);
        }
    }
}
fn hasFlag(mount: Json, flag: []const u8) bool {
    for (mount.object.get("flags").?.array.items) |value| if (std.mem.eql(
        u8,
        value.string,
        flag,
    )) return true;
    return false;
}
fn command(io: Io, a: Allocator, argv: []const []const u8) !std.process.RunResult {
    return std.process.run(a, io, .{ .argv = argv, .stdout_limit = .limited(
        64 << 10,
    ), .stderr_limit = .limited(16 << 10), .timeout = driver.deadline(
        io,
        60,
    ) });
}
fn reaped(io: Io, a: Allocator) !void {
    if (!try exists(io, "/run/cgroup/svc")) return;
    const services = try leashed(io, a);
    if (services.len == 0) return;
    const name = services[0];
    var child = try std.process.spawn(
        io,
        .{ .argv = &.{ "/usr/lib/werewolf/test-platform", "hold" }, .stdin = .ignore },
    );
    defer child.kill(io);
    var group = try Io.Dir.cwd().openFile(
        io,
        try a.print("/run/cgroup/svc/{s}/cgroup.procs", .{name}),
        .{ .mode = .write_only },
    );
    defer group.close(io);
    try group.writeStreamingAll(io, try a.print("{d}\n", .{child.id.?}));
    const restart = try command(
        io,
        a,
        &.{ "/usr/bin/sv", "-w", "60", "restart", try a.print("/etc/sv/{s}", .{name}) },
    );
    if (restart.term != .exited or restart.term.exited != 0) return error.ServiceRestart;
    const term = try child.wait(io);
    if (term != .signal or term.signal != .KILL) return error.ServiceChildSurvived;
    try servicesUp(io, a);
}
fn identity(raw: []const u8, uid: u32) !bool {
    var fields = std.mem.tokenizeAny(u8, try system.field(raw, "Uid"), " \t");
    var n: usize = 0;
    while (fields.next()) |id| : (n += 1) if (try std.fmt.parseInt(
        u32,
        id,
        10,
    ) != uid) return false;
    return n == 4;
}
fn powerless(raw: []const u8, sandboxed: bool) !bool {
    for ([_][]const u8{
        "CapEff",
        "CapBnd",
    }) |key| if (try std.fmt.parseInt(u64, try system.field(raw, key), 16) != 0) return false;
    if (sandboxed and (!std.mem.eql(u8, try system.field(raw, "NoNewPrivs"), "1") or
        !std.mem.eql(u8, try system.field(raw, "Seccomp"), "2"))) return false;
    return true;
}
fn sealed(io: Io, a: Allocator) !void {
    if (std.mem.find(
        u8,
        try system.read(io, a, "/proc/cmdline"),
        "werewolf.seal=learn",
    ) != null) return;
    const report = try command(io, a, &.{"/usr/lib/werewolf/seal"});
    if (report.term != .exited or report.term.exited != 0 or
        !std.mem.startsWith(u8, report.stdout, "seal: enforcing;")) return error.SealNotEnforcing;
    var count: usize = 0;
    for (try names(io, a, "/proc")) |pid| {
        _ = std.fmt.parseInt(u32, pid, 10) catch continue;
        const comm = system.read(io, a, try a.print("/proc/{s}/comm", .{pid})) catch |err| {
            if (err == error.FileNotFound) continue;
            return err;
        };
        if (!std.mem.eql(u8, trim(comm), "seal-watch")) continue;
        const raw = try system.read(io, a, try a.print("/proc/{s}/status", .{pid}));
        if (!try identity(raw, 66) or !try powerless(raw, false)) return error.SealWatchPrivileged;
        count += 1;
    }
    if (count != 1) return error.SealWatchMissing;
}
fn powerSeparated(io: Io, a: Allocator) !void {
    const parent = try std.fmt.parseInt(
        u32,
        trim(try system.read(io, a, "/etc/sv/power-button/supervise/pid")),
        10,
    );
    if (parent <= 1) return error.PowerMonitorMissing;
    const status = try system.read(io, a, try a.print("/proc/{d}/status", .{parent}));
    if (!try powerless(status, true)) return error.PowerMonitorPrivileged;
    var children: usize = 0;
    for (try names(io, a, "/proc")) |pid| {
        _ = std.fmt.parseInt(u32, pid, 10) catch continue;
        const raw = system.read(io, a, try a.print("/proc/{s}/status", .{pid})) catch |err| {
            if (err == error.FileNotFound) continue;
            return err;
        };
        if (try std.fmt.parseInt(u32, try system.field(raw, "PPid"), 10) != parent) continue;
        if (!try identity(raw, 71) or !try powerless(raw, true)) return error.PowerReaderPrivileged;
        children += 1;
    }
    if (children == 0) return error.PowerReaderMissing;
}

test "listener policy keeps protocols and loopback scopes distinct" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const ports = try policyPorts(
        arena.allocator(),
        "listen tcp 443\nlisten tcp 53 lan\nlisten 65536 udp 53\nlisten tcp 5432 " ++
            "loopback\nlisten 65537 udp 5353 " ++
            "lan\n",
    );
    try std.testing.expect(allowedListener(ports, "tcp", "0.0.0.0", 443));
    try std.testing.expect(!allowedListener(ports, "udp", "0.0.0.0", 443));
    try std.testing.expect(allowedListener(ports, "udp", "0:0:0:0:0:0:0:0", 53));
    try std.testing.expect(allowedListener(ports, "udp", "0.0.0.0", 5353));
    try std.testing.expect(allowedListener(ports, "tcp", "10.0.2.15", 53));
    try std.testing.expect(!allowedListener(ports, "tcp", "0.0.0.0", 5432));
    try std.testing.expect(allowedListener(ports, "tcp", "127.0.0.2", 5432));
    try std.testing.expect(!allowedListener(ports, "tcp", "0.0.0.0", 1111));
    for ([_][]const u8{
        "listen tcp 80 public junk",
        "listen tcp 80 lan junk",
        "listen 65536 udp 53 loopback",
    }) |bad| try std.testing.expectError(
        error.NetworkPolicy,
        policyPorts(arena.allocator(), bad),
    );
}
test "supervision rejects restart loops and a service still finishing" {
    var status: [20]u8 = @splat(0);
    std.mem.writeInt(u64, status[0..8], (1 << 62) + 10 + 100, .big);
    status[17] = 'u';
    status[19] = 1;
    try std.testing.expect(!settled(&status, 101));
    try std.testing.expect(settled(&status, 102));
    status[19] = 0;
    try std.testing.expect(!settled(&status, 102));
    status[17] = 'd';
    try std.testing.expect(settled(&status, 102));
    status[19] = 2;
    try std.testing.expect(!settled(&status, 102));
    try std.testing.expect(!settled(status[0..19], 102));
}
test "kernel exceptions do not hide unrelated lockdown or ptrace violations" {
    try std.testing.expect(quiet("Lockdown: run: /dev/mem, access is restricted\n"));
    try std.testing.expect(
        !quiet("Lockdown: run: /dev/mem, access is restricted\nLockdown: attacker: kexec\n"),
    );
    try std.testing.expect(!quiet("ptrace attach of victim was attempted by attacker\n"));
    try std.testing.expect(defaultRoute("eth0\t00000000\t0202000A\t0003\n"));
    try std.testing.expect(!defaultRoute("eth0\t00000000\t0102000A\t0003\n"));
}
test "privilege checks include saved identity and bounding capabilities" {
    const zero = "CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:" ++
        "\t2\n";
    try std.testing.expect(try powerless(zero, true));
    try std.testing.expect(!try powerless("CapEff:\t0\nCapBnd:\t1\n", false));
    try std.testing.expect(try identity("Uid:\t71 71 71 71\n", 71));
    try std.testing.expect(!try identity("Uid:\t71 71 0 71\n", 71));
}
