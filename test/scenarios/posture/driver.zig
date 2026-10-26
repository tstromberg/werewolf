//! posture's attacks under strain, and the platform programs' own
//! refusals, as root on minimal: four scans at once, a scan over a probe
//! left behind, and one after a quiet interval must each pass their
//! attacks; leash must fail closed on a bad directory and refuse every
//! system identity; and power-button's reader and monitor must restart.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const linux = std.os.linux;

const posture = "/usr/lib/werewolf/posture";
const leash = "/usr/lib/werewolf/leash";
const supervise = "/etc/sv/power-button/supervise/pid";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !mem.eql(u8, args[2], "attacks")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const suite = args[1];
    try ctx.result(io, suite, "posture-concurrent-attacks", try concurrent(io, a));
    try ctx.result(io, suite, "posture-stale-probe", try stale(io, a));
    // A quiet interval refills printk's audit burst, which the scans spent.
    try io.sleep(.fromSeconds(6), .awake);
    try ctx.result(
        io,
        suite,
        "posture-fresh-audit",
        try passes(a, try scan(io, a), &.{"kernel-exec-log"}),
    );
    try ctx.result(io, suite, "leash-directory-error", try badDirectory(io, a));
    try ctx.result(io, suite, "system-identities-reserved", try reserved(io, a));
    try ctx.result(io, suite, "power-worker-restarts", try restarts(io, a, .worker));
    try ctx.result(io, suite, "power-monitor-restarts", try restarts(io, a, .monitor));
}

/// passes is whether report, posture's JSON, says each of ids passed. When
/// one did not, it says why on stderr, as the console shows it.
fn passes(a: Allocator, report: []const u8, ids: []const []const u8) !bool {
    const v = std.json.parseFromSliceLeaky(std.json.Value, a, report, .{}) catch |err| {
        std.debug.print("posture: report is not JSON ({t}): {s}\n", .{
            err,
            report[0..@min(report.len, 300)],
        });
        return false;
    };
    const checks = if (v == .object) v.object.get("checks") else null;
    if (checks == null or checks.? != .array) {
        std.debug.print("posture: report has no checks\n", .{});
        return false;
    }
    for (ids) |id| {
        const check = for (checks.?.array.items) |c| {
            if (c != .object) continue;
            const got = c.object.get("id") orelse continue;
            if (got == .string and mem.eql(u8, got.string, id)) break c.object;
        } else {
            std.debug.print("posture: {s} is not in the report\n", .{id});
            return false;
        };
        const result = check.get("result") orelse .null;
        if (result == .string and mem.eql(u8, result.string, "pass")) continue;
        const detail = check.get("detail") orelse .null;
        std.debug.print("posture: {s} is {f}: {f}\n", .{
            id,
            std.json.fmt(result, .{}),
            std.json.fmt(detail, .{}),
        });
        return false;
    }
    return true;
}

fn scan(io: Io, a: Allocator) ![]const u8 {
    const r = try std.process.run(a, io, .{
        .argv = &.{ posture, "--json" },
        .stdout_limit = .limited(4 << 20),
        .stderr_limit = .limited(64 << 10),
        .timeout = driver.deadline(io, 120),
    });
    return r.stdout;
}

/// concurrent runs four scans at once: each must pass its attacks.
fn concurrent(io: Io, a: Allocator) !bool {
    var out: [4]Io.File = undefined;
    var children: [4]std.process.Child = undefined;
    for (&out, &children, 0..) |*file, *child, i| {
        file.* = try Io.Dir.cwd().createFile(io, try a.print(
            "/run/posture-concurrent.{d}",
            .{i},
        ), .{
            .read = true,
        });
        child.* = try std.process.spawn(io, .{
            .argv = &.{ posture, "--json" },
            .stdin = .ignore,
            .stdout = .{ .file = file.* },
            .stderr = .ignore,
        });
    }
    var all = true;
    for (&out, &children, 0..) |file, *child, i| {
        const term = try child.wait(io);
        file.close(io);
        if (term != .exited) std.debug.print("posture: scan {d} ended {any}\n", .{ i, term });
        const report = try driver.system.read(
            io,
            a,
            try a.print("/run/posture-concurrent.{d}", .{i}),
        );
        all = try passes(a, report, &.{ "processes-leash-attack", "files-links-attack" }) and all;
    }
    return all;
}

/// stale leaves a probe's files behind, as nobody's: a scan must still pass
/// its leash attack, and clear them.
fn stale(io: Io, a: Allocator) !bool {
    const cwd = Io.Dir.cwd();
    for ([_][2][]const u8{
        .{ "/run/svc/posture-probe", "result" },
        .{ "/data/svc/posture-probe", "leftover" },
    }) |left| {
        try cwd.createDirPath(io, left[0]);
        const file = try a.print("{s}/{s}", .{ left[0], left[1] });
        try cwd.writeFile(io, .{ .sub_path = file, .data = "stale\n" });
        for ([_][]const u8{ left[0], file }) |path| {
            const z = try a.dupeSentinel(u8, path, 0);
            if (linux.errno(linux.chown(z, 65534, 65534)) != .SUCCESS) return error.Chown;
        }
    }
    const ok = try passes(a, try scan(io, a), &.{"processes-leash-attack"});
    for ([_][]const u8{ "/run/svc/posture-probe", "/data/svc/posture-probe" }) |dir| {
        cwd.access(io, dir, .{}) catch continue;
        std.debug.print("posture: {s} left behind\n", .{dir});
        return false;
    }
    return ok;
}

/// leashIn runs leash on the service file in dir, as runit would, and is
/// its exit status and what it said.
fn leashIn(io: Io, a: Allocator, dir: []const u8) !struct { code: ?u8, said: []const u8 } {
    const r = try std.process.run(a, io, .{
        .argv = &.{leash},
        .cwd = .{ .path = dir },
        .stdout_limit = .limited(64 << 10),
        .stderr_limit = .limited(64 << 10),
        .timeout = driver.deadline(io, 30),
    });
    return .{
        .code = if (r.term == .exited) r.term.exited else null,
        .said = try mem.concat(a, u8, &.{ r.stdout, r.stderr }),
    };
}

/// badDirectory gives a service a data directory that is a file: leash must
/// refuse it, naming the operation and errno, and leave the file alone.
fn badDirectory(io: Io, a: Allocator) !bool {
    const cwd = Io.Dir.cwd();
    const dir = "/run/werewolf/posture-bad-dir";
    const data = "/data/svc/posture-bad-dir";
    try cwd.createDirPath(io, dir);
    defer for ([_][]const u8{ dir, "/run/svc/posture-bad-dir", data }) |path|
        cwd.deleteTree(io, path) catch {};
    try cwd.writeFile(io, .{
        .sub_path = dir ++ "/service",
        .data = "exec " ++ posture ++ " --noop\nuser nobody\npledge stdio\n",
    });
    try cwd.writeFile(io, .{ .sub_path = data, .data = "kept\n" });
    const r = try leashIn(io, a, dir);
    if (r.code == 0 or mem.find(u8, r.said, "open directory " ++ data ++ ": NOTDIR") == null) {
        std.debug.print("leash: {s}\n", .{r.said});
        return false;
    }
    return mem.eql(u8, try driver.system.read(io, a, data), "kept\n");
}

/// reserved asks leash to run as each of the machine's system identities,
/// its _NAME accounts: it must refuse every one.
fn reserved(io: Io, a: Allocator) !bool {
    const cwd = Io.Dir.cwd();
    const dir = "/tmp/identity-probe";
    try cwd.createDirPath(io, dir);
    defer cwd.deleteTree(io, dir) catch {};
    const users = try systemUsers(a, try driver.system.read(io, a, "/etc/passwd"));
    if (users.len == 0) {
        std.debug.print("leash: /etc/passwd has no system identities\n", .{});
        return false;
    }
    for (users) |user| {
        try cwd.writeFile(io, .{
            .sub_path = dir ++ "/service",
            .data = try a.print("exec " ++ posture ++ " --noop\nuser {s}\npledge stdio\n", .{user}),
        });
        const r = try leashIn(io, a, dir);
        if (r.code == 0 or mem.find(u8, r.said, "is a system") == null) {
            std.debug.print("leash as {s}: {s}\n", .{ user, r.said });
            return false;
        }
    }
    return true;
}

/// systemUsers is the _NAME accounts of passwd, werewolf's system identities.
fn systemUsers(a: Allocator, passwd: []const u8) ![]const []const u8 {
    var users: std.ArrayList([]const u8) = .empty;
    var lines = mem.splitScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        const name = line[0 .. mem.findScalar(u8, line, ':') orelse continue];
        if (name.len > 1 and name[0] == '_') try users.append(a, name);
    }
    return users.items;
}

const Victim = enum { worker, monitor };

/// restarts kills power-button's reader or its monitor: runit must start
/// a new monitor, and the old reader must be gone with it.
fn restarts(io: Io, a: Allocator, victim: Victim) !bool {
    const parent = try pidIn(io, a, supervise);
    const worker = try childOf(io, a, parent) orelse return error.NoPowerWorker;
    const target = if (victim == .worker) worker else parent;
    if (linux.errno(linux.kill(@intCast(target), .KILL)) != .SUCCESS) return error.Kill;
    for (0..30) |_| {
        const next = pidIn(io, a, supervise) catch 0;
        if (next > 1 and next != parent) break;
        try io.sleep(.fromSeconds(1), .awake);
    } else return false;
    const path = try a.print("/proc/{d}", .{worker});
    for (0..30) |_| {
        Io.Dir.cwd().access(io, path, .{}) catch return true;
        try io.sleep(.fromSeconds(1), .awake);
    }
    return false;
}

fn pidIn(io: Io, a: Allocator, path: []const u8) !u32 {
    return std.fmt.parseInt(u32, mem.trim(u8, try driver.system.read(io, a, path), " \n"), 10);
}

fn childOf(io: Io, a: Allocator, parent: u32) !?u32 {
    var proc = try Io.Dir.cwd().openDir(io, "/proc", .{ .iterate = true });
    defer proc.close(io);
    var it = proc.iterate();
    const want = try a.print("{d}", .{parent});
    while (try it.next(io)) |e| {
        const pid = std.fmt.parseInt(u32, e.name, 10) catch continue;
        const s = driver.readKernel(io, a, try a.print("/proc/{d}/status", .{pid})) catch continue;
        var lines = mem.splitScalar(u8, s, '\n');
        while (lines.next()) |line| if (mem.startsWith(u8, line, "PPid:")) {
            if (mem.eql(u8, mem.trim(u8, line["PPid:".len..], " \t"), want)) return pid;
            break;
        };
    }
    return null;
}

test "a report passes only the checks it shows passing" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const report =
        \\{"checks": [{"id": "kernel-exec-log", "result": "pass"},
        \\            {"id": "files-links-attack", "result": "fail"}]}
    ;
    try std.testing.expect(try passes(a, report, &.{"kernel-exec-log"}));
    try std.testing.expect(!try passes(a, report, &.{"files-links-attack"}));
    try std.testing.expect(!try passes(a, report, &.{"processes-leash-attack"}));
    try std.testing.expect(!try passes(a, "not json", &.{"kernel-exec-log"}));
}

test "system identities are the _NAME accounts" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const passwd =
        \\root:x:0:0:root:/root:/sbin/nologin
        \\nobody:x:65534:65534::/var/empty:/sbin/nologin
        \\_power:x:71:71:Account created by apko:/var/empty:/sbin/nologin
        \\_slotkeep:x:72:72:Account created by apko:/var/empty:/sbin/nologin
        \\_:x:9:9::/:/sbin/nologin
        \\
    ;
    const users = try systemUsers(arena.allocator(), passwd);
    try std.testing.expectEqual(2, users.len);
    try std.testing.expectEqualStrings("_power", users[0]);
    try std.testing.expectEqualStrings("_slotkeep", users[1]);
}
