//! check-privilege-boundaries [HOWL] builds a disposable protected Lima
//! machine of test/privilege-probes and probes real SSH sessions: root's
//! and two users', with and without a PTY; home isolation, the network a
//! user is granted, refused forwarding, concurrent sessions, SFTP, and a
//! daemon restart. Logs and the build's profile stay in
//! build/security-probes/NAME; the machine is deleted however it ends.

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const mem = std.mem;
const Result = host.check.Result;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "privilege-boundaries") catch std.process.exit(1);
    c.finish(run(&c));
}

const users = [_][]const u8{ "root", "auditone", "audittwo" };

const Probe = struct {
    c: *host.Check,
    common: []const []const u8 = &.{},
    keys: [users.len][]const u8 = undefined,

    fn key(p: *Probe, user: []const u8) []const u8 {
        for (users, 0..) |u, i| if (mem.eql(u8, u, user)) return p.keys[i];
        unreachable;
    }

    fn ssh(
        p: *Probe,
        user: []const u8,
        command: []const u8,
        tty: bool,
        extra: []const []const u8,
    ) !Result {
        const gpa = p.c.gpa;
        const login = try gpa.print("{s}@127.0.0.1", .{user});
        const argv = try mem.concat(gpa, []const u8, &.{
            &.{"ssh"},
            p.common,
            &.{ "-i", p.key(user), if (tty) "-tt" else "-T" },
            extra,
            &.{ login, command },
        });
        const options: host.check.Options = .{
            .environ_map = &p.c.env,
            .timeout = .fromSeconds(60),
        };
        return host.check.command(p.c.io, gpa, argv, options);
    }

    /// require keeps a probe's output as label.log and requires its
    /// outcome and, when given, a line of its output.
    fn require(
        p: *Probe,
        label: []const u8,
        result: Result,
        success: bool,
        contains: ?[]const u8,
    ) ![]const u8 {
        const c = p.c;
        const output = try mem.concat(c.gpa, u8, &.{ result.stdout, result.stderr });
        const log = try c.path(try c.gpa.print("{s}.log", .{label}));
        try Io.Dir.cwd().writeFile(c.io, .{ .sub_path = log, .data = output });
        const missing = if (contains) |want| mem.find(u8, output, want) == null else false;
        if (result.ok() != success or missing)
            return c.fail("{s}: {f}; see {s}", .{ label, result.term, log });
        c.say("PASS {s}", .{label});
        return output;
    }
};

const baseline = "uname -a; cat /proc/cmdline; " ++
    "stat -c '%u:%g:%a %n' /data/.werewolf/identities; " ++
    "cat /etc/sv/sshd/service; cat /run/werewolf/posture.json";

const setup = "umask 077; printf private > ~/private; " ++
    "mkdir -p ~/.ssh; printf 'id -u > ~/rc.uid\\n' > ~/.ssh/rc";

// sshd runs no ~/.ssh/rc (PermitUserRC no, docs/design/ssh-hardening.md).
const isolation = "test ! -e ~/rc.uid && " ++
    "! cat /data/home/{s}/private 2>~/denied && " ++
    "grep -q 'Permission denied' ~/denied";

// playground grants people names through unwound and a few ports: 443 is
// routed, so TEST-NET times out, and 25 is refused at once.
const network = "nslookup example.com >/dev/null && " ++
    "wget -q -T 2 -O /dev/null http://192.0.2.1:25/ 2>&1 | grep -q 'Permission denied' && " ++
    "! wget -q -T 2 -O /dev/null http://192.0.2.1:443/ 2>&1 | grep -q 'Permission denied'";

const probe_program = "/usr/lib/werewolf/privilege-probe";

fn run(c: *host.Check) !void {
    const io = c.io;
    const gpa = c.gpa;
    const cwd = Io.Dir.cwd();
    const howl = try c.absolute(if (c.args.len > 1) c.args[1] else "build/host/howl");
    var id: [4]u8 = undefined;
    io.random(&id);
    const name = try gpa.print("ww-security-{s}", .{&std.fmt.bytesToHex(id, .lower)});
    const work = try gpa.print("build/security-probes/{s}", .{name});
    try cwd.createDirPath(io, "build/security-probes");
    try cwd.createDir(io, work, .default_dir);
    try c.setWork(work);
    const config = try c.path("config");
    try cwd.createDir(io, config, .default_dir);
    var p: Probe = .{ .c = c };
    for (users, 0..) |user, i| {
        p.keys[i] = try c.path(user);
        const key = p.keys[i];
        _ = try c.must(&.{ "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key }, "", .{});
    }
    var people: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "auditone", "audittwo" }) |user| {
        const pub_path = try gpa.print("{s}.pub", .{p.key(user)});
        const public = try cwd.readFileAlloc(io, pub_path, gpa, .limited(64 << 10));
        try people.print(gpa, "{s} {s}", .{ user, public });
    }
    const users_file = try std.fs.path.join(gpa, &.{ config, "users" });
    try cwd.writeFile(io, .{ .sub_path = users_file, .data = people.items });
    const hostname = try std.fs.path.join(gpa, &.{ config, "hostname" });
    try cwd.writeFile(io, .{ .sub_path = hostname, .data = "privilege-probe\n" });
    defer cleanup(c, howl, name);
    try probe(c, &p, howl, name, config);
}

fn probe(c: *host.Check, p: *Probe, howl: []const u8, name: []const u8, config: []const u8) !void {
    const io = c.io;
    const gpa = c.gpa;
    const cwd = Io.Dir.cwd();
    const build_log = try c.path("build.log");
    c.say("Building protected fixture {s}; log: {s}", .{ name, build_log });
    {
        const log = try cwd.createFile(io, build_log, .{});
        defer log.close(io);
        // The lengthy build goes to its log, never through memory.
        const root_key = try gpa.print("{s}.pub", .{p.key("root")});
        var child = try std.process.spawn(io, .{
            .argv = &.{
                howl,
                "create",
                name,
                "--on",
                "lima",
                "--with",
                "test/privilege-probes",
                "--build",
                "--yes",
                "--config",
                config,
                "--root-keys",
                root_key,
            },
            .environ_map = &c.env,
            .stdin = .ignore,
            .stdout = .{ .file = log },
            .stderr = .{ .file = log },
        });
        const term = try child.wait(io);
        if (!term.success())
            return c.fail("howl create {s}: {f}; see {s}", .{ name, term, build_log });
    }
    const list = [_][]const u8{ "limactl", "list", name, "--format", "{{.SSHLocalPort}}" };
    const options: host.check.Options = .{ .environ_map = &c.env, .timeout = .fromSeconds(60) };
    const listed = try host.check.command(io, gpa, &list, options);
    const port = mem.trim(u8, listed.stdout, " \t\r\n");
    if (!listed.ok()) return c.fail("no Lima SSH port", .{});
    _ = std.fmt.parseInt(u16, port, 10) catch return c.fail("no Lima SSH port", .{});
    const known = try gpa.print("UserKnownHostsFile={s}", .{try c.path("known_hosts")});
    p.common = try gpa.dupe([]const u8, &.{
        "-F", "/dev/null",
        "-S", "none",
        "-p", port,
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", known,
    });
    const deadline = host.qemu.after(io, 60);
    while (true) {
        const ready = try p.ssh("root", "test -s /run/werewolf/posture.json", false, &.{});
        if (ready.ok()) break;
        if (!before(io, deadline)) _ = try p.require("ssh-ready", ready, true, null);
        try io.sleep(.fromMilliseconds(500), .awake);
    }
    _ = try p.require("baseline", try p.ssh("root", baseline, false, &.{}), true, null);
    // Root's session holds sshd's login capabilities, pledge and write layer.
    for ([_]bool{ false, true }) |tty| {
        const label = try gpa.print("root-probe-{s}", .{if (tty) "pty" else "pipe"});
        const result = try p.ssh("root", probe_program ++ " root", tty, &.{});
        _ = try p.require(label, result, true, "PASS root-no-dac-override");
    }
    for ([_][]const u8{ "auditone", "audittwo" }) |user| {
        const made = try p.ssh(user, setup, false, &.{});
        _ = try p.require(try gpa.print("{s}-setup", .{user}), made, true, null);
        for ([_]bool{ false, true }) |tty| {
            const label = try gpa.print("{s}-probe-{s}", .{ user, if (tty) "pty" else "pipe" });
            const result = try p.ssh(user, probe_program, tty, &.{});
            _ = try p.require(label, result, true, "PASS cannot-regain-root");
        }
        const peer = if (mem.eql(u8, user, "auditone")) "audittwo" else "auditone";
        const isolated = try p.ssh(user, try gpa.print(isolation, .{peer}), false, &.{});
        _ = try p.require(try gpa.print("{s}-home-isolation", .{user}), isolated, true, null);
        const reached = try p.ssh(user, network, false, &.{});
        _ = try p.require(try gpa.print("{s}-network", .{user}), reached, true, null);
        const forward = [_][]const u8{ "-o", "ExitOnForwardFailure=yes", "-R", "0:127.0.0.1:22" };
        const forwarded = try p.ssh(user, "true", false, &forward);
        const label = try gpa.print("{s}-no-remote-forward", .{user});
        _ = try p.require(label, forwarded, false, "remote port forwarding failed");
    }
    try concurrent(c, p);
    try sftp(c, p);
    const pid = "cat /etc/sv/sshd/supervise/pid";
    const before_restart = try p.ssh("root", pid, false, &.{});
    const said = try p.require("sshd-before-restart", before_restart, true, null);
    const old_pid = mem.trim(u8, said, " \t\r\n");
    const restart = try p.ssh("root", "sv restart /etc/sv/sshd", false, &.{});
    const restart_log = try mem.concat(gpa, u8, &.{ restart.stdout, restart.stderr });
    try cwd.writeFile(io, .{ .sub_path = try c.path("restart-sshd.log"), .data = restart_log });
    // Restart may end the session that asked for it. Require a new daemon
    // and a working unprivileged session, not merely a disconnect.
    const restarted = host.qemu.after(io, 60);
    while (true) {
        const current = try p.ssh("root", pid, false, &.{});
        const now = mem.trim(u8, current.stdout, " \t\r\n");
        if (current.ok() and !mem.eql(u8, now, old_pid)) break;
        if (!before(io, restarted)) return c.fail("sshd did not restart", .{});
        try io.sleep(.fromMilliseconds(500), .awake);
    }
    const after = try p.ssh("auditone", probe_program, false, &.{});
    _ = try p.require("after-restart", after, true, null);
    keepProfile(c, name);
    c.say("PASS privilege boundaries; evidence: {s}", .{c.work});
}

/// sftp puts a file and gets it back under the same login policy.
fn sftp(c: *host.Check, p: *Probe) !void {
    const io = c.io;
    const gpa = c.gpa;
    const payload = try c.path("payload");
    const text = "SFTP remains usable under the same login policy.\n";
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = payload, .data = text });
    const downloaded = try c.path("downloaded");
    // sftp's -S selects the SSH executable, unlike ssh's control socket
    // flag, and -P is its port.
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(gpa, "sftp");
    for (p.common, 0..) |arg, i| {
        if (i == 2 or i == 3) continue;
        try argv.append(gpa, if (mem.eql(u8, arg, "-p")) "-P" else arg);
    }
    try argv.appendSlice(gpa, &.{ "-o", "ControlPath=none", "-i", p.key("auditone") });
    try argv.appendSlice(gpa, &.{ "-b", "-", "auditone@127.0.0.1" });
    const batch = try gpa.print(
        "put {s} transferred\nget transferred {s}\n",
        .{ payload, downloaded },
    );
    const result = try host.check.command(io, gpa, argv.items, .{
        .environ_map = &c.env,
        .timeout = .fromSeconds(60),
        .input = batch,
    });
    _ = try p.require("sftp", result, true, null);
    const got = Io.Dir.cwd().readFileAlloc(io, downloaded, gpa, .unlimited) catch "";
    if (!mem.eql(u8, text, got)) return c.fail("SFTP content mismatch", .{});
}

/// concurrent runs four probe sessions at once: none may inherit another's
/// authority descriptors.
fn concurrent(c: *host.Check, p: *Probe) !void {
    const io = c.io;
    const who = [_][]const u8{ "auditone", "audittwo", "auditone", "audittwo" };
    var futures: [who.len]Io.Future(anyerror!Result) = undefined;
    for (who, 0..) |user, i| futures[i] = try io.concurrent(session, .{ p, user });
    var results: [who.len]anyerror!Result = undefined;
    for (&futures, 0..) |*f, i| results[i] = f.await(io);
    for (results, 0..) |result, i| {
        const label = try c.gpa.print("concurrent-{d}", .{i});
        _ = try p.require(label, try result, true, "PASS no-inherited-authority-descriptors");
    }
}

fn session(p: *Probe, user: []const u8) anyerror!Result {
    return p.ssh(user, probe_program, false, &.{});
}

/// before is whether deadline is still ahead.
fn before(io: Io, deadline: Io.Clock.Timestamp) bool {
    return Io.Clock.Timestamp.now(io, .awake).compare(.lt, deadline);
}

/// keepProfile keeps the runtime facts and the exact source-built profile.
fn keepProfile(c: *host.Check, name: []const u8) void {
    const cwd = Io.Dir.cwd();
    const profile = c.gpa.print("build/machines/{s}/authority/profile.json", .{name}) catch return;
    const data = cwd.readFileAlloc(c.io, profile, c.gpa, .limited(16 << 20)) catch return;
    const kept = c.path("profile.json") catch return;
    cwd.writeFile(c.io, .{ .sub_path = kept, .data = data }) catch {};
}

fn cleanup(c: *host.Check, howl: []const u8, name: []const u8) void {
    const io = c.io;
    const gpa = c.gpa;
    const cwd = Io.Dir.cwd();
    if (c.env.get("HOME")) |home| serial: {
        const serial = std.fs.path.join(gpa, &.{ home, ".lima", name, "serial.log" }) catch
            break :serial;
        const data = cwd.readFileAlloc(io, serial, gpa, .unlimited) catch break :serial;
        const kept = c.path("serial.log") catch break :serial;
        cwd.writeFile(io, .{ .sub_path = kept, .data = data }) catch {};
    }
    keepProfile(c, name);
    const delete = [_][]const u8{ howl, "delete", name, "--on", "lima" };
    const options: host.check.Options = .{ .environ_map = &c.env, .timeout = .fromSeconds(120) };
    const result = host.check.command(io, gpa, &delete, options);
    const log = c.path("cleanup.log") catch return;
    if (result) |r| {
        const output = mem.concat(gpa, u8, &.{ r.stdout, r.stderr }) catch "";
        cwd.writeFile(io, .{ .sub_path = log, .data = output }) catch {};
        if (r.ok()) return;
    } else |_| {}
    std.log.err("Cleanup failed: see {s}", .{log});
}
