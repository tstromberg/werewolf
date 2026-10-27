//! check-provider-ab HOWL PROVIDER ARCH drives a real signed update on one
//! VM backend (docs/design/provider-ab-tests.md): A boots and commits; the
//! updater installs B from the fixture's loopback HTTPS channel, which
//! commits; operator rollback returns to A, which survives another reboot;
//! an unhealthy signed candidate never commits, the deadman restores A, and
//! the updater then refuses that candidate again. Every boot must be
//! fresh, of the exact signed root, with dm-verity and IPE on, and Secure
//! Boot when signed. Only what the run made is removed.

const std = @import("std");
const host = @import("host");
const form = @import("form");
const fixtures = @import("ab-fixture.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;
const Provider = host.provider.Provider;
const Kind = host.provider.Kind;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "provider-ab") catch std.process.exit(1);
    c.finish(run(&c));
}

/// Mode is how a provider's test is signed, and whether it may be.
pub fn defaultMode(kind: Kind) []const u8 {
    return switch (kind) {
        .@"lima-vz", .bhyve, .firecracker, .proxmox => "plain",
        else => "secure",
    };
}

/// refusal says why kind cannot be tested as asked, or null.
pub fn refusal(kind: Kind, arch: []const u8, mode: []const u8, proxmox_host: bool) ?[]const u8 {
    const secure = mem.eql(u8, mode, "secure");
    if ((kind == .@"lima-vz" or kind == .firecracker) and secure)
        return "this backend has no Secure Boot enrollment; run its explicit refusal test";
    if ((kind == .firecracker or kind == .proxmox) and !mem.eql(u8, arch, "x86_64"))
        return "this remote backend currently requires x86_64";
    if (kind == .bhyve and mem.eql(u8, arch, "aarch64") and secure)
        return "arm64 bhyve has no validated Secure Boot enrollment; use AB_MODE=plain";
    if (kind == .proxmox and !proxmox_host)
        return "Proxmox is untested: set PROXMOX_HOST when a test node is available";
    return null;
}

const Run = struct {
    c: *host.Check,
    table: host.evidence.Table,
    fixture: host.provider.Fixture,
    machine: *Provider,
    logs: []const u8,
    provider: []const u8,
    secure: bool,
    phases: std.ArrayList(json.Value) = .empty,

    fn fail(r: *Run, err: anyerror) anyerror {
        if (err == error.ProviderFailed) return r.c.fail("{s}", .{r.machine.why});
        return err;
    }

    /// report records a phase and its evidence, with the console as it was.
    fn report(r: *Run, label: []const u8, status: json.Value) !void {
        const gpa = r.c.gpa;
        var phase: json.ObjectMap = .empty;
        try phase.put(gpa, "phase", .{ .string = label });
        try phase.put(gpa, "status", status);
        try r.phases.append(gpa, .{ .object = phase });
        const options: json.Stringify.Options = .{ .whitespace = .indent_2 };
        const text = try json.Stringify.valueAlloc(gpa, r.phases.items, options);
        try write(r.c, try path(gpa, r.logs, "phases.json"), try gpa.print("{s}\n", .{text}));
        const id = status.object.get("boot_id").?.string;
        const console = r.machine.console() catch |err| return r.fail(err);
        const log = try path(gpa, r.machine.work, "console-evidence.log");
        const entry = try gpa.print("\n{s} {s}\n{s}", .{ label, id, console });
        try host.check.append(r.c.io, log, entry);
        r.c.say("pass   {s}: {s}", .{ r.provider, label });
    }

    /// evidence is ab-status's record of the running boot, or null while
    /// the machine cannot answer.
    fn evidence(r: *Run) !?json.Value {
        const gpa = r.c.gpa;
        const options: host.provider.Run = .{ .must = false, .timeout = 15 };
        const result = r.machine.ssh("/usr/bin/ab-status", options) catch |err| switch (err) {
            error.Timeout => return null,
            else => return r.fail(err),
        };
        if (!result.ok()) return null;
        const value = json.parseFromSliceLeaky(json.Value, gpa, result.stdout, .{}) catch
            return r.c.fail("invalid guest evidence: {s}", .{host.check.tail(result.stdout, 1000)});
        const log = try path(gpa, r.machine.work, "evidence.log");
        try host.check.append(r.c.io, log, try gpa.print("{f}\n", .{json.fmt(value, .{})}));
        return value;
    }

    /// waitBoot waits for release in slot, a boot other than previous with
    /// the updater paused, at the commit state asked, and requires its
    /// evidence.
    fn waitBoot(
        r: *Run,
        release: []const u8,
        slot: []const u8,
        previous: ?[]const u8,
        committed: bool,
        seconds: i64,
    ) !json.Value {
        const io = r.c.io;
        const deadline = host.qemu.after(io, seconds);
        var last: ?json.Value = null;
        var paused: ?[]const u8 = null;
        while (before(io, deadline)) : (try io.sleep(.fromSeconds(3), .awake)) {
            last = try r.evidence();
            const seen = last orelse continue;
            if (!holds(seen, "release", release)) continue;
            const id = field(seen, "boot_id") orelse continue;
            if (id != .string) continue;
            if (previous) |p| if (mem.eql(u8, id.string, p)) continue;
            if (paused == null or !mem.eql(u8, paused.?, id.string)) {
                const pause = r.machine.ssh(pause_updater, .{
                    .must = false,
                    .timeout = 15,
                }) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => return r.fail(err),
                };
                if (pause.code() == 255) continue;
                if (!pause.ok())
                    return r.c.fail("cannot pause fixture updater: {s}{s}", .{
                        pause.stderr,
                        pause.stdout,
                    });
                paused = id.string;
            }
            last = try r.evidence();
            const now = last orelse continue;
            const state = field(now, "committed") orelse continue;
            if (state != .bool or state.bool != committed) continue;
            const root_hash = rootHash(r.fixture, release) orelse
                return r.c.fail("fixture has no root hash for {s}", .{release});
            var why: host.check.Why = .{};
            _ = host.evidence.boot(r.table, now, .{
                .release = release,
                .slot = slot,
                .root_hash = root_hash,
                .previous = previous,
                .secure = r.secure,
                .committed = committed,
            }, &why) catch return r.c.fail("{s}", .{why.text});
            if (r.fixture.tpm) {
                const expected: i64 = if (mem.eql(u8, release, "A"))
                    1
                else if (mem.eql(u8, release, "B"))
                    2
                else
                    3;
                const index = field(now, "index") orelse return error.MissingTpmEvidence;
                const floor = field(now, "floor") orelse return error.MissingTpmEvidence;
                if (!isTrue(field(now, "rollback_protected")) or index != .integer or
                    index.integer != expected or floor != .integer or floor.integer < 1 or
                    floor.integer > expected)
                    return r.c.fail(
                        "invalid TPM evidence for {s}: {f}",
                        .{ release, json.fmt(now, .{}) },
                    );
            }
            return now;
        }
        const shown = last orelse json.Value{ .null = {} };
        return r.c.fail("missing boot/commit {s}: {f}", .{ release, json.fmt(shown, .{}) });
    }

    /// select makes release the channel's head, as a publisher would: the
    /// signature first, then what it signs.
    fn select(r: *Run, release: []const u8) !void {
        const gpa = r.c.gpa;
        const target = try gpa.print("/data/svc/ab-https/head/image/{s}", .{r.fixture.arch});
        const source = try gpa.print("/usr/share/ab/seed/heads/{s}", .{release});
        const copy = try gpa.print(
            "mkdir -p {s} && cp {s}/latest.json.sig {s}/latest.json.sig && cp {s}/latest.json " ++
                "{s}/latest.json",
            .{ target, source, target, source, target },
        );
        const result = try r.ssh(copy, 120);
        if (!result.ok()) return r.c.fail("selecting {s}: {s}", .{
            release, host.check.tail(result.stderr, 2000),
        });
    }

    fn ssh(r: *Run, command: []const u8, timeout: i64) !host.check.Result {
        return r.machine.ssh(command, .{ .timeout = timeout }) catch |err| r.fail(err);
    }

    fn reboot(r: *Run, command: []const u8) !void {
        r.machine.reboot(command) catch |err| return r.fail(err);
    }
};

/// pause_updater keeps the fixture's updater from acting on its own
/// between the test's steps, once it is ready.
const pause_updater = "while [ ! -e /run/werewolf/updater-ready ]; do sleep 1; done; " ++
    "/usr/bin/sv down /etc/sv/autoupdate";

fn run(c: *host.Check) !void {
    const io = c.io;
    const gpa = c.gpa;
    const cwd = Io.Dir.cwd();
    if (c.args.len != 4) return c.fail("usage: check-provider-ab HOWL PROVIDER ARCH", .{});
    const howl = try c.absolute(c.args[1]);
    const name = c.args[2];
    const arch = c.args[3];
    const kind = std.meta.stringToEnum(Kind, name) orelse
        return c.fail("unknown provider: {s}", .{name});
    const mode = c.env.get("AB_MODE") orelse defaultMode(kind);
    const tpm = mem.eql(u8, c.env.get("AB_TPM") orelse "0", "1");
    if (c.env.get("AB_FIRECRACKER_PINNED") != null and kind != .firecracker)
        return c.fail("AB_FIRECRACKER_PINNED is for Firecracker only", .{});
    if (tpm and (kind != .bhyve or !mem.eql(u8, mode, "secure")))
        return c.fail("AB_TPM=1 currently requires x86_64 bhyve in secure mode", .{});
    const proxmox = c.env.get("PROXMOX_HOST") != null;
    if (refusal(kind, arch, mode, proxmox)) |why| return c.fail("{s}", .{why});
    const check_dir = c.env.get("CHECK") orelse try gpa.print("build/{s}/check", .{arch});
    try c.setWork(try path(gpa, check_dir, try gpa.print("provider-ab-{s}", .{name})));
    const logs = c.work;
    for ([_][]const u8{ "failure.log", "cleanup-failure.log", "phases.json" }) |f|
        cwd.deleteFile(io, try c.path(f)) catch {};
    var fixture_path: []const u8 = undefined;
    if (c.env.get("AB_FIXTURE")) |given| {
        fixture_path = try c.absolute(given);
        const st = cwd.statFile(io, fixture_path, .{}) catch null;
        if (st != null and st.?.kind == .directory)
            fixture_path = try path(gpa, fixture_path, "fixture.json");
    } else {
        var id: [6]u8 = undefined;
        io.random(&id);
        const root = try gpa.print("fixture-{s}", .{&std.fmt.bytesToHex(id, .lower)});
        fixture_path = try fixtures.build(c, .{
            .howl = howl,
            .arch = arch,
            .kernel = try c.absolute(try required(c, "IPE_KERNEL")),
            .key = try c.absolute(try required(c, "IPE_KEY")),
            .cert = try c.absolute(try required(c, "IPE_CERT")),
            .root = try c.path(root),
            .mode = mode,
            .tpm = tpm,
        });
    }
    if (mem.eql(u8, c.env.get("AB_FIXTURE_ONLY") orelse "0", "1")) {
        c.say("fixture: {s}", .{fixture_path});
        return;
    }
    const text = try cwd.readFileAlloc(io, fixture_path, gpa, .limited(16 << 20));
    const Fixture = host.provider.Fixture;
    const options: json.ParseOptions = .{ .ignore_unknown_fields = true };
    const fixture = try json.parseFromSliceLeaky(Fixture, gpa, text, options);
    if (!mem.eql(u8, fixture.arch, arch) or !mem.eql(u8, fixture.mode, mode) or fixture.tpm != tpm)
        return c.fail("fixture architecture or boot mode differs from the requested " ++
            "provider test", .{});

    // Lima's sockets live under the run's directory: keep it short.
    var id: [6]u8 = undefined;
    io.random(&id);
    const temporary = try gpa.print("/tmp/ww-ab-{s}", .{&std.fmt.bytesToHex(id, .lower)});
    try cwd.createDir(io, temporary, .fromMode(0o700));
    defer cwd.deleteTree(io, temporary) catch {};
    const machine = try gpa.create(Provider);
    machine.init(io, gpa, kind, fixture, temporary, howl, &c.env) catch |err| {
        if (err == error.ProviderFailed) return c.fail("{s}", .{machine.why});
        return err;
    };
    var r: Run = .{
        .c = c,
        .table = try host.evidence.load(gpa, form),
        .fixture = fixture,
        .machine = machine,
        .logs = logs,
        .provider = name,
        .secure = mem.eql(u8, mode, "secure"),
    };
    const failed = lifecycle(&r);
    if (failed) |_| {} else |err| try write(c, try c.path("failure.log"), try failureText(c, err));
    const cleaned = machine.stop();
    if (cleaned) |_| {} else |err| {
        const why = if (err == error.ProviderFailed) machine.why else @errorName(err);
        try write(c, try c.path("cleanup-failure.log"), why);
    }
    try copyLogs(io, gpa, temporary, logs);
    failed catch |err| {
        if (err == error.CheckFailed) return c.fail("{s}; see {s}", .{ c.why, logs });
        return c.fail("{t}; see {s}", .{ err, logs });
    };
    cleaned catch return c.fail("{s}; see {s}", .{ machine.why, logs });
    if (mem.eql(u8, c.env.get("AB_FIRECRACKER_PINNED") orelse "0", "1"))
        c.say(
            "pass   Firecracker default-mode limitation: signed B stages but host pins retain " ++
                "A; automatic upgrades unsupported; resources removed",
            .{},
        )
    else
        c.say("pass   {s}: signed A/B upgrade, post-commit rollback, persistent rollback and " ++
            "automatic unhealthy recovery; resources removed", .{name});
}

fn failureText(c: *host.Check, err: anyerror) ![]const u8 {
    if (err == error.CheckFailed) return c.gpa.print("{s}\n", .{c.why});
    return c.gpa.print("{t}\n", .{err});
}

fn lifecycle(r: *Run) !void {
    const c = r.c;
    const io = c.io;
    const gpa = c.gpa;
    r.machine.start() catch |err| return r.fail(err);
    const initial = try r.waitBoot("A", "a", null, true, 400);
    try r.report("initial A verified and committed", initial);
    const clock = mem.trim(u8, (try r.ssh("date +%s", 120)).stdout, " \t\r\n");
    try write(c, try path(gpa, r.machine.work, "clock.log"), try gpa.print("{s}\n", .{clock}));
    const guest = std.fmt.parseInt(i64, clock, 10) catch
        return c.fail("guest clock unreadable: {s}", .{clock});
    if (@abs(guest - Io.Clock.real.now(io).toSeconds()) > 300)
        return c.fail("guest clock differs from host by over five minutes; " ++
            "fix timekeeping before testing HTTPS signed updates", .{});
    try r.select("B");
    _ = try r.ssh("/usr/lib/werewolf/slot-update check", 600);
    const pinned = mem.eql(u8, c.env.get("AB_FIRECRACKER_PINNED") orelse "0", "1");
    if (pinned) {
        const staged = (try r.ssh("/bin/cat /data/svc/autoupdate/log", 120)).stdout;
        try write(c, try c.path("pinned-staging.log"), staged);
        const build = r.fixture.releases.object.get("B").?.object.get("build").?.string;
        if (mem.find(u8, staged, build) == null or
            mem.find(u8, staged, "\"event\":\"stage\"") == null)
            return c.fail("pinned-mode negative test did not stage signed B", .{});
    }
    try r.reboot("/usr/bin/reboot");
    if (pinned) {
        const retained = try r.waitBoot("A", "a", bootId(initial), true, 400);
        try r.report(
            "host pins retain A after signed B stages; automatic upgrade unsupported",
            retained,
        );
        return;
    }
    const upgraded = try r.waitBoot("B", "b", bootId(initial), true, 400);
    try r.report("authenticated upgrade B verified and committed", upgraded);
    try r.reboot("/usr/lib/werewolf/slot-update try");
    const rolled_back = try r.waitBoot("A", "a", bootId(upgraded), true, 400);
    try r.report("post-commit rollback to retained A", rolled_back);
    try r.reboot("/usr/bin/reboot");
    const persisted = try r.waitBoot("A", "a", bootId(rolled_back), true, 400);
    try r.report("rollback A survives another reboot", persisted);
    try r.select("bad");
    _ = try r.ssh("/usr/lib/werewolf/slot-update check", 600);
    try r.reboot("/usr/bin/reboot");
    const unhealthy = try r.waitBoot("bad", "b", bootId(persisted), false, 400);
    try r.report("unhealthy signed candidate remains uncommitted", unhealthy);
    const deadline = host.qemu.after(io, 750);
    const poll: Io.Duration = .fromSeconds(30);
    const recovered: json.Value = while (before(io, deadline)) : (try io.sleep(poll, .awake)) {
        const current = try r.evidence() orelse continue;
        const same = holds(current, "boot_id", bootId(unhealthy));
        if (same and isTrue(field(current, "committed")))
            return c.fail("unhealthy candidate committed", .{});
        if (holds(current, "release", "A") and !same) {
            const back = try r.waitBoot("A", "a", bootId(unhealthy), true, 400);
            try r.report("deadman automatically restored verified A", back);
            break back;
        }
    } else return c.fail("unhealthy candidate did not automatically return to A", .{});
    const console = r.machine.console() catch |err| return r.fail(err);
    const evidence_log = try path(gpa, r.machine.work, "console-evidence.log");
    const kept = Io.Dir.cwd().readFileAlloc(io, evidence_log, gpa, .unlimited) catch "";
    const all = try mem.concat(gpa, u8, &.{ console, kept });
    if (mem.find(u8, all, "slot b did not commit in 600s") == null)
        return c.fail("missing deadman evidence from the provider console", .{});
    if (r.secure and mem.count(u8, all, "Secure Boot enforced outside setup mode") < 2)
        return c.fail("provider console did not independently confirm enforced boots", .{});
    _ = try r.ssh("/usr/lib/werewolf/slot-update outcome", 120);
    const before_log = (try r.ssh("/bin/cat /data/svc/autoupdate/log", 120)).stdout;
    try write(c, try c.path("retry-before.jsonl"), before_log);
    const check: host.provider.Run = .{ .must = false, .timeout = 600 };
    const retry = r.machine.ssh("/usr/lib/werewolf/slot-update check", check) catch |err|
        return r.fail(err);
    const record = json.fmt(.{
        .exit = retry.code(),
        .stdout = retry.stdout,
        .stderr = retry.stderr,
    }, .{ .whitespace = .indent_2 });
    try write(c, try c.path("retry-command.json"), try gpa.print("{f}\n", .{record}));
    // The updater fsyncs its audit record before replying. Provider consoles
    // may concatenate several UARTs and cannot be sliced as an append log.
    const after_log = (try r.ssh("/bin/cat /data/svc/autoupdate/log", 120)).stdout;
    try write(c, try c.path("retry-after.jsonl"), after_log);
    var why: host.check.Why = .{};
    const code = retry.code();
    _ = host.evidence.refusedRetry(gpa, code, before_log, after_log, &why) catch |err|
        return if (err == error.Refused) c.fail("{s}", .{why.text}) else err;
    try r.report("failed candidate is refused on retry", recovered);
}

/// before is whether deadline is still ahead.
fn before(io: Io, deadline: Io.Clock.Timestamp) bool {
    return Io.Clock.Timestamp.now(io, .awake).compare(.lt, deadline);
}

fn bootId(v: json.Value) []const u8 {
    return v.object.get("boot_id").?.string;
}

/// rootHash is the signed root the fixture's release must boot.
fn rootHash(f: host.provider.Fixture, release: []const u8) ?[]const u8 {
    const manifest = field(f.releases, release) orelse return null;
    const hash = field(manifest, "root_hash") orelse return null;
    return if (hash == .string) hash.string else null;
}

fn field(v: json.Value, key: []const u8) ?json.Value {
    return if (v == .object) v.object.get(key) else null;
}

fn holds(v: json.Value, key: []const u8, want: []const u8) bool {
    const got = field(v, key) orelse return false;
    return got == .string and mem.eql(u8, got.string, want);
}

fn isTrue(v: ?json.Value) bool {
    const x = v orelse return false;
    return x == .bool and x.bool;
}

fn path(gpa: Allocator, dir: []const u8, name: []const u8) ![]const u8 {
    return std.fs.path.join(gpa, &.{ dir, name });
}

fn write(c: *host.Check, file: []const u8, data: []const u8) !void {
    try Io.Dir.cwd().writeFile(c.io, .{ .sub_path = file, .data = data });
}

/// copyLogs keeps the run's logs once its directory goes.
fn copyLogs(io: Io, gpa: Allocator, from: []const u8, to: []const u8) !void {
    var dir = Io.Dir.cwd().openDir(io, from, .{ .iterate = true }) catch return;
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| if (e.kind == .file and mem.endsWith(u8, e.name, ".log"))
        try dir.copyFile(e.name, .cwd(), try path(gpa, to, e.name), io, .{});
}

test "providers default to the signing they can enforce, and refuse what they cannot" {
    try std.testing.expectEqualStrings("plain", defaultMode(.@"lima-vz"));
    try std.testing.expectEqualStrings("plain", defaultMode(.bhyve));
    try std.testing.expectEqualStrings("secure", defaultMode(.qemu));
    try std.testing.expectEqualStrings("secure", defaultMode(.gcp));
    try std.testing.expect(refusal(.@"lima-vz", "aarch64", "secure", false) != null);
    try std.testing.expect(refusal(.firecracker, "x86_64", "secure", false) != null);
    try std.testing.expect(refusal(.firecracker, "aarch64", "plain", false) != null);
    try std.testing.expect(refusal(.proxmox, "x86_64", "plain", false) != null);
    try std.testing.expectEqual(null, refusal(.proxmox, "x86_64", "plain", true));
    try std.testing.expect(refusal(.bhyve, "aarch64", "secure", false) != null);
    try std.testing.expectEqual(null, refusal(.bhyve, "x86_64", "secure", false));
    try std.testing.expectEqual(null, refusal(.qemu, "aarch64", "secure", false));
}

test "the fixture names each release's signed root" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const f = try json.parseFromSliceLeaky(host.provider.Fixture, gpa,
        \\{"arch": "x86_64", "mode": "plain", "ssh_key": "/k", "extra": 1,
        \\ "releases": {"A": {"root_hash": "aa"}, "B": {"build": "x"}}}
    , .{ .ignore_unknown_fields = true });
    try std.testing.expectEqualStrings("aa", rootHash(f, "A").?);
    try std.testing.expectEqual(null, rootHash(f, "B"));
    try std.testing.expectEqual(null, rootHash(f, "bad"));
}

/// required is an input file the environment must name: make passes an
/// unset one as empty.
fn required(c: *host.Check, name: []const u8) ![]const u8 {
    const value = c.env.get(name) orelse "";
    if (value.len == 0) return c.fail("{s} is not set", .{name});
    return value;
}
