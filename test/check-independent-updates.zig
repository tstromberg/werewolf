//! check-independent-updates HOWL OUTPUT [lima|qemu] [playground|postdoc-server]: a protected
//! machine
//! takes its own TPM and updates from a static channel alone.
//!
//! howl create --build makes release A (index 1) of a channel this check
//! serves as static HTTPS files, signed with the caller's keys, and boots
//! it under Secure Boot, IPE and a fresh TPM, which its first boot makes its
//! own. Releases B and C are published to the channel; the machine's own
//! updater installs each, and the mount broker raises the TPM floor before
//! overwriting a slot. Operator rollback, a power cut at the floor's
//! increment, a restored older disk (refused by stage0), a failed trial and
//! a service reaching for the TPM are each checked
//! (docs/design/implemented/independent-updates.md). No host service but the static
//! file server takes part. The check runs itself as QEMU, from the PATH it
//! gives howl and Lima, to put its TPM proxy between QEMU and swtpm.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const form = @import("form");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;
const join = std.fs.path.join;
const Machine = host.qemu.Machine;

pub fn main(init: std.process.Init) void {
    const gpa = init.arena.allocator();
    const args = init.minimal.args.toSlice(gpa) catch std.process.exit(1);
    host.swtpm.interpose(init.io, gpa, args, init.environ_map);
    var c = host.Check.init(init, "independent-updates") catch |err| {
        std.log.err("check-independent-updates: {t}", .{err});
        std.process.exit(1);
    };
    var t: Test = .{ .c = &c };
    const result = t.run();
    t.cleanup();
    c.finish(result);
}

/// Status is ab-status's report of the running boot.
const Status = struct {
    value: json.Value,

    fn str(s: Status, key: []const u8) []const u8 {
        const v = s.value.object.get(key) orelse return "";
        return if (v == .string) v.string else "";
    }

    fn int(s: Status, key: []const u8) i64 {
        const v = s.value.object.get(key) orelse return -1;
        return if (v == .integer) v.integer else -1;
    }

    fn flag(s: Status, key: []const u8) ?bool {
        const v = s.value.object.get(key) orelse return null;
        return if (v == .bool) v.bool else null;
    }
};

/// Never is an until condition that only QEMU's end or the deadline meets.
const Never = struct {
    pub fn done(_: Never, _: []const u8) !bool {
        return false;
    }
};

const Test = struct {
    c: *host.Check,
    howl: []const u8 = "",
    provider: []const u8 = "",
    arch: []const u8 = "",
    name: []const u8 = "",
    machine: []const u8 = "",
    proxy_dir: []const u8 = "",
    proxy: ?*host.swtpm.Proxy = null,
    server: ?*host.http.Server = null,
    files: ?*host.http.Files = null,
    channel: []const u8 = "",
    form: []const u8 = "",
    www: []const u8 = "",
    private_ssh: []const u8 = "",
    source_form: []const u8 = "playground",
    postdoc_seeded: bool = false,
    postgres_seeded: bool = false,
    variants: []const []const u8 = &.{},
    create: []const []const u8 = &.{},
    passed: usize = 0,
    started: bool = false,

    fn run(t: *Test) !void {
        const c = t.c;
        const gpa = c.gpa;
        const io = c.io;
        if (c.args.len < 3 or c.args.len > 5)
            return c.fail(
                "usage: check-independent-updates HOWL OUTPUT [lima|qemu] " ++
                    "[playground|postdoc-server|postgresql]",
                .{},
            );
        if (c.args.len == 5) t.source_form = c.args[4];
        if (!mem.eql(u8, t.source_form, "playground") and
            !mem.eql(u8, t.source_form, "postdoc-server") and
            !mem.eql(u8, t.source_form, "postgresql"))
            return c.fail("the update workload is playground, postdoc-server or postgresql", .{});
        const selection = c.env.get("FORM_IMAGES_VARIANTS") orelse c.env.get("VARIANTS") orelse "";
        var failure: form.Failure = .{};
        t.variants = try form.variantNames(
            gpa,
            if (selection.len == 0) &.{} else &.{selection},
            &failure,
        );
        t.provider = if (c.args.len > 3 and c.args[3].len > 0) c.args[3] else "lima";
        if (!mem.eql(u8, t.provider, "lima") and !mem.eql(u8, t.provider, "qemu"))
            return c.fail("provider must be lima or qemu", .{});
        const lima = mem.eql(u8, t.provider, "lima");
        t.arch = if (builtin.cpu.arch == .aarch64) "aarch64" else "x86_64";
        t.howl = try c.absolute(c.args[1]);
        const revision = try c.must(&.{ "git", "rev-parse", "HEAD" }, "", .{});
        const source_commit = mem.trim(u8, revision.stdout, " \t\r\n");
        const work = try c.absolute(c.args[2]);
        if (Io.Dir.cwd().access(io, work, .{})) |_| {
            return c.fail("{s} exists already", .{work});
        } else |_| {}
        if (std.fs.path.dirname(work)) |parent| try Io.Dir.cwd().createDirPath(io, parent);
        try Io.Dir.cwd().createDir(io, work, .fromMode(0o700));
        try c.setWork(work);
        var id: [4]u8 = undefined;
        io.random(&id);
        t.name = try gpa.print("ww-floor-{s}", .{&std.fmt.bytesToHex(id, .lower)});
        t.machine = try join(gpa, &.{ "build/machines", t.name });
        t.started = true;
        const gateway = if (lima) "192.168.5.2" else "10.0.2.2";

        // QEMU, wherever howl or Lima starts it, reaches its TPM through the proxy.
        t.proxy_dir = try temporary(c, "ww-floor-proxy-");
        const wrappers = try c.path("wrapper");
        try Io.Dir.cwd().createDir(io, wrappers, .default_dir);
        const qemu_name = try gpa.print("qemu-system-{s}", .{t.arch});
        const real_qemu = host.consumer.which(io, gpa, &c.env, qemu_name) orelse
            return c.fail("no {s} on PATH", .{qemu_name});
        const self = try std.process.executablePathAlloc(io, gpa);
        try Io.Dir.cwd().symLink(io, self, try join(gpa, &.{ wrappers, qemu_name }), .{});
        const real_ssh = host.consumer.which(io, gpa, &c.env, "ssh") orelse
            return c.fail("no ssh on PATH", .{});
        t.private_ssh = try c.path("ssh.key");
        const provider = if (t.variants.len > 0 or !mem.eql(u8, t.source_form, "playground"))
            try c.absolute("build/host/test-sk.so")
        else
            null;
        try host.consumer.sshWithProvider(io, gpa, wrappers, real_ssh, t.private_ssh, provider);

        t.form = try c.path("form");
        const overlay = try join(gpa, &.{ t.form, "rootfs" });
        try Io.Dir.cwd().createDirPath(io, try join(gpa, &.{ overlay, "usr/share/werewolf" }));
        const original = try Io.Dir.cwd().readFileAlloc(
            io,
            try gpa.print("forms/{s}/form.yaml", .{t.source_form}),
            gpa,
            .limited(1 << 20),
        );
        try write(
            io,
            try join(gpa, &.{ t.form, "form.yaml" }),
            try formYamlFor(gpa, t.source_form, original),
        );
        if (mem.eql(u8, t.source_form, "postgresql")) {
            const sql = try join(gpa, &.{ overlay, "usr/share/werewolf-postgres" });
            try Io.Dir.cwd().createDirPath(io, sql);
            try write(io, try join(
                gpa,
                &.{ sql, "99-update-test.sql" },
            ), "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='root') " ++
                "THEN CREATE ROLE root LOGIN SUPERUSER; END IF; END $$;\n");
        }
        t.www = try c.path("www");
        try Io.Dir.cwd().createDirPath(io, try join(gpa, &.{ t.www, "image", t.arch }));
        const port = try host.check.freePort(io);
        t.channel = try gpa.print("https://{s}:{d}/image", .{ gateway, port });
        const ca_pem = try c.path("ca.crt");
        const path = try gpa.print("{s}:{s}", .{ wrappers, c.env.get("PATH") orelse "" });
        try c.env.put("IPE_UPDATES", t.channel);
        try c.env.put("IPE_UPDATES_CA", ca_pem);
        try c.env.put("IMAGE_INDEX", "1");
        try c.env.put("PATH", path);
        try c.env.put(host.swtpm.env_qemu, real_qemu);
        try c.env.put(host.swtpm.env_dir, t.proxy_dir);

        // A channel on a private authority, which the images trust (IPE_UPDATES_CA).
        const ca = try host.tls.Authority.init(io, gpa, "floor-test-ca");
        try write(io, ca_pem, try ca.pem(gpa));
        const identity = try gpa.create(host.tls.Identity);
        identity.* = try ca.issue(io, gpa, &.{gateway});
        const files = try gpa.create(host.http.Files);
        files.* = .{ .io = io, .gpa = gpa, .root = try Io.Dir.cwd().openDir(io, t.www, .{}) };
        const server = try gpa.create(host.http.Server);
        try server.start(io, gpa, .{
            .address = .{ .ip4 = .loopback(port) },
            .identity = identity,
            .handler = files.handler(),
        });
        t.server = server;
        t.files = files;

        if (provider) |p| {
            _ = try c.must(
                &.{
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519-sk",
                    "-O",
                    "verify-required",
                    "-w",
                    p,
                    "-N",
                    "",
                    "-f",
                    t.private_ssh,
                },
                "ssh-key",
                .{},
            );
        } else {
            const keygen = [_][]const u8{ "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f" };
            _ = try c.must(&(keygen ++ .{t.private_ssh}), "ssh-key", .{});
        }
        const probe = try join(gpa, &.{ overlay, "usr/bin/ab-status" });
        try Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(probe).?);
        const target = try gpa.print("{s}-linux-musl", .{t.arch});
        const emit = try gpa.print("-femit-bin={s}", .{probe});
        _ = try c.must(&.{
            "zig",               "build-exe",                 "-O",
            "ReleaseSafe",       "-fPIE",                     "-target",
            target,              "--dep",                     "cmdline",
            "--dep",             "ipe",                       "--dep",
            "tpm",               "-Mroot=test/ab-status.zig", "--dep",
            "network",           "-Mcmdline=lib/cmdline.zig", "-Mnetwork=lib/network.zig",
            "-Mipe=lib/ipe.zig", "--dep",                     "apk",
            "-Mtpm=lib/tpm.zig", "--dep",                     "package",
            "-Mapk=lib/apk.zig", "-Mpackage=lib/package.zig", emit,
        }, "probe", .{ .timeout = .fromSeconds(1800) });
        try write(io, try join(gpa, &.{ overlay, "usr/share/werewolf/ab-release" }), "A\n");
        try modes(io, gpa, overlay, probe);

        var create: std.ArrayList([]const u8) = .empty;
        const keys = try gpa.print("{s}.pub", .{t.private_ssh});
        try create.appendSlice(gpa, &.{ t.howl, "create", t.name, "--with", t.form });
        try create.appendSlice(gpa, &.{ "--build", "--yes", "--root-keys", keys });
        if (t.variants.len > 0) try create.appendSlice(
            gpa,
            &.{ "--variant", try mem.join(gpa, ",", t.variants) },
        );
        if (mem.eql(u8, t.source_form, "postdoc-server")) {
            const config = try c.path("config");
            _ = try c.must(&.{ "forms/postdoc-server/test/config", config }, "config", .{});
            try create.appendSlice(gpa, &.{ "--config", config, "--add-current-user", "no" });
        }
        if (!lima) try create.appendSlice(gpa, &.{ "--on", "qemu" });
        t.create = create.items;
        try t.launch("create", 3600);
        const release_a = try c.path("release-a.img");
        try copy(io, try join(gpa, &.{ t.machine, "disk.img" }), release_a);
        const a = try t.waitBoot("A", 1, 1, null, true);
        const enrolled = "TPM floor 1: release 1 admitted; reset authority sealed";
        if (mem.find(u8, try t.console(), enrolled) == null)
            return c.fail("stage0 did not enroll the fresh TPM at release 1", .{});
        t.ok("A enrolled its own TPM at floor 1 under Secure Boot and IPE", .{});
        if ((try t.ssh("exec 3<>/dev/tpmrm0", "tpm-denied", 1800)).ok())
            return c.fail("a root session opened the TPM", .{});
        t.ok("a root session cannot open the TPM", .{});
        const unsigned = "cp /usr/bin/true /data/unsigned && /data/unsigned";
        if ((try t.ssh(unsigned, "unsigned", 1800)).ok())
            return c.fail("unsigned writable code ran", .{});
        t.ok("IPE refuses code outside the verified root", .{});

        const try_slot = "/usr/lib/werewolf/slot-update try";
        try t.publish("B", 2, null);
        var b = try t.install("B", 2, 1, a, true);
        t.ok("B installed from the static channel; floor stays at the retained release, 1", .{});
        _ = try t.ssh(try_slot, "rollback-A", 60);
        const a2 = try t.waitBoot("A", 1, 1, b.str("boot_id"), true);
        t.ok("operator rollback to A, the retained release, boots", .{});
        _ = try t.ssh(try_slot, "forward-B", 60);
        b = try t.waitBoot("B", 2, 1, a2.str("boot_id"), true);

        // Installing C overwrites A: the broker raises the floor to B first.
        // Cut the power at that increment, before and after the TPM executes it.
        try t.publish("C", 3, null);
        var current = b;
        for ([_]struct { host.swtpm.Cut, i64 }{ .{ .before, 1 }, .{ .after, 2 } }) |cut| {
            const label = try gpa.print("cut-{t}", .{cut[0]});
            current = try t.cutPower(label, cut[0], cut[1], current);
            t.ok("power cut {t} the floor increment: B boots at floor {d}", .{ cut[0], cut[1] });
        }
        var cc = try t.install("C", 3, 2, current, true);
        t.ok("C installed; A is retired, floor 2", .{});

        // A restored disk with A on it, the TPM kept: stage0 refuses it before handover.
        const saved = try c.path("current.img");
        const stop: []const []const u8 = if (lima)
            &.{ "limactl", "stop", "--force", t.name }
        else
            &.{ t.howl, "stop", t.name };
        _ = try c.run(stop, "stop-restore", .{});
        const disk = if (lima)
            try join(gpa, &.{ try t.limaHome(), t.name, "disk" })
        else
            try join(gpa, &.{ t.machine, "disk.img" });
        const info = try c.must(&.{ "qemu-img", "info", "--output=json", disk }, "disk-info", .{});
        const Info = struct { format: []const u8 };
        const format = try json.parseFromSliceLeaky(Info, gpa, info.stdout, .{
            .ignore_unknown_fields = true,
        });
        try Io.Dir.cwd().rename(disk, .cwd(), saved, io);
        const restore = [_][]const u8{ "qemu-img", "convert", "-O", format.format };
        _ = try c.must(&(restore ++ .{ release_a, disk }), "restore-a", .{});
        try t.refusedRestore();
        t.ok("a restored disk holding retired A is refused by stage0", .{});
        try t.powerOff(true);
        try Io.Dir.cwd().rename(saved, .cwd(), disk, io);
        try t.restart("restored");
        cc = try t.waitBoot("C", 3, 2, null, true);

        // A trial that never becomes healthy falls back to C, and the floor stays.
        try t.publish("E", 4, unhealthy);
        // Installing E overwrote B: the floor rose to C, the running release, first.
        const trial = try t.install("E", 4, 3, cc, false);
        _ = try t.ssh("/usr/bin/reboot", "failed-trial-reboot", 60);
        _ = try t.waitBoot("C", 3, 3, trial.str("boot_id"), true);
        t.ok("a failed trial of E falls back to C at floor 3", .{});
        // The evidence the publication gate reads (test/check-published-lifecycle.zig),
        // written only once every check above has passed.
        const evidence = try json.Stringify.valueAlloc(gpa, .{
            .format = "werewolf-update-evidence/1",
            .provider = t.provider,
            .arch = t.arch,
            .commit = source_commit,
            .form = t.source_form,
            .variants = t.variants,
            .passed = true,
            .checks = .{
                .ab_upgrade = true,
                .operator_rollback = true,
                .unhealthy_fallback = true,
                .retirement_cuts = true,
            },
        }, .{ .whitespace = .indent_2 });
        try write(io, try c.path("result.json"), try gpa.print("{s}\n", .{evidence}));
        c.say("pass   independent-updates: {d} checks on {s}", .{ t.passed, t.provider });
    }

    fn ok(t: *Test, comptime what: []const u8, args: anytype) void {
        t.passed += 1;
        t.c.say("pass   independent-updates: " ++ what, args);
    }

    /// launch runs howl create, which boots the machine, and puts the proxy
    /// between its QEMU and swtpm as soon as QEMU names swtpm's socket.
    fn launch(t: *Test, label: []const u8, seconds: i64) !void {
        const c = t.c;
        const io = c.io;
        const gpa = c.gpa;
        const log = try c.path(try gpa.print("{s}.log", .{label}));
        var creating: Machine = undefined;
        try creating.start(io, gpa, t.create, .{ .log = log, .environ_map = &c.env });
        defer creating.stop(.fromSeconds(30));
        const until = host.qemu.after(io, seconds);
        const backend_json = try join(gpa, &.{ t.proxy_dir, "backend.json" });
        while (true) {
            if (Io.Dir.cwd().access(io, backend_json, .{})) |_| break else |_| {}
            if (creating.exited()) {
                if (!creating.term.?.success()) return t.failed(label, &creating);
                return c.fail("QEMU did not attach its TPM through the test proxy", .{});
            }
            if (Io.Clock.Timestamp.now(io, .awake).compare(.gt, until))
                return c.fail("QEMU did not start", .{});
            try io.sleep(.fromMilliseconds(200), .awake);
        }
        try t.restartProxy();
        try write(io, try join(gpa, &.{ t.proxy_dir, "ready" }), "");
        creating.until(until, Never{}) catch |err| switch (err) {
            error.MachineExited => {},
            else => return c.fail("{s}: {t}", .{ label, err }),
        };
        if (!creating.term.?.success()) return t.failed(label, &creating);
    }

    fn failed(t: *Test, label: []const u8, m: *Machine) error{ CheckFailed, OutOfMemory } {
        const said = host.check.tail(try m.console(t.c.gpa), 3000);
        return t.c.fail("{s}: {f}: {s}", .{ label, m.term.?, said });
    }

    /// restartProxy listens afresh for QEMU, forwarding to swtpm's socket as
    /// the QEMU that started last named it.
    fn restartProxy(t: *Test) !void {
        const c = t.c;
        if (t.proxy) |p| p.close();
        const recorded = try Io.Dir.cwd().readFileAlloc(
            c.io,
            try join(c.gpa, &.{ t.proxy_dir, "backend.json" }),
            c.gpa,
            .limited(4096),
        );
        const backend = try json.parseFromSliceLeaky([]const u8, c.gpa, recorded, .{});
        const p = try c.gpa.create(host.swtpm.Proxy);
        const listen = try join(c.gpa, &.{ t.proxy_dir, "proxy.sock" });
        try p.start(c.io, c.gpa, listen, backend, null);
        t.proxy = p;
    }

    /// cutPower holds the floor increment of installing C at cut, cuts the
    /// power there, and requires B to boot again at floor.
    fn cutPower(t: *Test, label: []const u8, cut: host.swtpm.Cut, floor: i64, was: Status) !Status {
        const c = t.c;
        const proxy = t.proxy.?;
        proxy.arm(cut);
        var checking: Machine = undefined;
        try checking.start(c.io, c.gpa, try t.sshArgv("/usr/lib/werewolf/slot-update check"), .{
            .log = try c.path(try c.gpa.print("{s}.log", .{label})),
            .environ_map = &c.env,
        });
        const hit = proxy.waitHit(.fromSeconds(900));
        const failure = proxy.failed();
        const powered_off = if (hit and failure == null)
            t.powerOff(false)
        else
            @as(anyerror!void, {});
        proxy.cancel();
        checking.stop(.fromSeconds(60));
        try powered_off;
        if (!hit or failure != null)
            return c.fail("the floor increment was not reached: {s}", .{failure orelse "timeout"});
        try t.restartProxy();
        try t.restart(label);
        return t.waitBoot("B", 2, floor, was.str("boot_id"), true);
    }

    /// refusedRestore boots the restored disk, and needs stage0 to refuse it
    /// once more than before. Lima starts a new serial log on each start,
    /// so refusals are counted, not found by offset.
    fn refusedRestore(t: *Test) !void {
        const c = t.c;
        const io = c.io;
        const refused = "TPM floor: release 1 is below its channel's floor, 2; not handing over";
        const before = mem.count(u8, try t.console(), refused);
        var restoring: Machine = undefined;
        try restoring.start(io, c.gpa, t.create, .{
            .log = try c.path("restore-boot.log"),
            .environ_map = &c.env,
        });
        defer restoring.stop(.fromSeconds(30));
        const created = host.qemu.after(io, 600);
        const until = host.qemu.after(io, 420);
        while (mem.count(u8, try t.console(), refused) <= before) {
            if (Io.Clock.Timestamp.now(io, .awake).compare(.gt, until))
                return c.fail("stage0 did not refuse the restored release A", .{});
            try io.sleep(.fromSeconds(2), .awake);
        }
        restoring.until(created, Never{}) catch |err| switch (err) {
            error.MachineExited => {},
            else => return c.fail("restore-boot: create did not end: {t}", .{err}),
        };
    }

    fn sshArgv(t: *Test, command: []const u8) ![]const []const u8 {
        const gpa = t.c.gpa;
        const root = try gpa.print("root@{s}", .{t.name});
        return gpa.dupe([]const u8, &.{ t.howl, "ssh", root, "--no-agent", "--", command });
    }

    /// ssh runs command as root on the machine; its exit is the caller's to judge.
    fn ssh(t: *Test, command: []const u8, label: []const u8, seconds: i64) !host.check.Result {
        return t.c.run(try t.sshArgv(command), label, .{ .timeout = .fromSeconds(seconds) });
    }

    fn status(t: *Test) ?Status {
        const r = t.ssh("/usr/bin/ab-status", "status", 15) catch return null;
        if (!r.ok()) return null;
        const v = json.parseFromSliceLeaky(json.Value, t.c.gpa, r.stdout, .{}) catch return null;
        return if (v == .object) .{ .value = v } else null;
    }

    /// waitBoot waits for a fresh boot of label at index and floor, all its
    /// protections enforced, committed or not as asked, and pauses its
    /// updater, which must not act on its own between steps.
    fn waitBoot(
        t: *Test,
        label: []const u8,
        index: i64,
        floor: i64,
        previous: ?[]const u8,
        committed: bool,
    ) !Status {
        const c = t.c;
        const until = host.qemu.after(c.io, 420);
        const pause = "test -e /run/werewolf/updater-ready && sv pause /etc/sv/autoupdate";
        var paused: []const u8 = "";
        while (Io.Clock.Timestamp.now(c.io, .awake).compare(.lt, until)) {
            const s = t.status() orelse {
                try c.io.sleep(.fromSeconds(3), .awake);
                continue;
            };
            const fresh = previous == null or !mem.eql(u8, s.str("boot_id"), previous.?);
            if (!mem.eql(u8, s.str("release"), label) or !fresh) {
                try c.io.sleep(.fromSeconds(3), .awake);
                continue;
            }
            const shown = json.fmt(s.value, .{});
            for ([_][]const u8{ "secure_boot", "ipe", "verified_root", "rollback_protected" }) |f|
                if (s.flag(f) != true)
                    return c.fail("missing guest enforcement {s}: {f}", .{ f, shown });
            if (s.int("index") != index or s.int("floor") != floor) return c.fail(
                "{s}: want index {d} floor {d}, have {f}",
                .{ label, index, floor, shown },
            );
            if (s.flag("committed") == committed) {
                if (!mem.eql(u8, paused, s.str("boot_id"))) {
                    if (!(try t.ssh(pause, "pause", 15)).ok()) {
                        try c.io.sleep(.fromSeconds(2), .awake);
                        continue;
                    }
                    paused = s.str("boot_id");
                }
                const record = try c.gpa.print("{f}\n", .{shown});
                try host.check.append(c.io, try c.path("evidence.jsonl"), record);
                if (committed and mem.eql(u8, t.source_form, "postdoc-server")) {
                    const workload = @import("postdoc.zig");
                    if (!(try t.ssh(workload.health, "postdoc-health", 960)).ok() or
                        !(try t.ssh(
                            try workload.command(c.gpa, t.postdoc_seeded),
                            "postdoc-api",
                            360,
                        )).ok() or
                        !(try t.ssh(workload.tunnel, "postdoc-tunnel", 30)).ok())
                        return c.fail(
                            "postdoc failed on {s}: JIT API, persisted verdict or tunnel metrics",
                            .{label},
                        );
                    t.postdoc_seeded = true;
                    t.ok("postdoc API and persistent verdict healthy on {s}", .{label});
                }
                if (committed and mem.eql(u8, t.source_form, "postgresql")) {
                    const result = try t.ssh(
                        try postgresCommand(c.gpa, t.variants, t.postgres_seeded),
                        "postgres-health",
                        90,
                    );
                    if (!result.ok() or
                        !mem.eql(u8, mem.trim(u8, result.stdout, " \r\n"), "variant-data-kept"))
                        return c.fail(
                            "PostgreSQL data or selected extensions failed on {s}",
                            .{label},
                        );
                    t.postgres_seeded = true;
                    t.ok("PostgreSQL data and selected extensions healthy on {s}", .{label});
                }
                return s;
            }
            try c.io.sleep(.fromSeconds(3), .awake);
        }
        return c.fail("{s} did not boot {s} (index {d}, floor {d})", .{
            t.name, label, index, floor,
        });
    }

    /// publish builds release label at index with the machine's own keys and
    /// inputs, from its own copy of the form, and makes it the channel's
    /// head, as a publisher uploads objects before the head.
    fn publish(t: *Test, label: []const u8, index: i64, extra: ?*const Extra) !void {
        const c = t.c;
        const io = c.io;
        const gpa = c.gpa;
        const releases = try c.path(try gpa.print("releases/{s}", .{label}));
        try Io.Dir.cwd().createDirPath(io, releases);
        const source = try join(gpa, &.{ releases, "form" });
        try host.check.copyTree(io, gpa, t.form, source);
        const rootfs = try join(gpa, &.{ source, "rootfs" });
        const release = try gpa.print("{s}\n", .{label});
        try write(io, try join(gpa, &.{ rootfs, "usr/share/werewolf/ab-release" }), release);
        if (extra) |f| try f(io, gpa, rootfs);
        const profile = try Io.Dir.cwd().readFileAlloc(
            io,
            try join(gpa, &.{ t.machine, "authority/profile.json" }),
            gpa,
            .limited(1 << 20),
        );
        const parsed = try json.parseFromSliceLeaky(json.Value, gpa, profile, .{});
        const spec = field(parsed, "local") orelse
            return c.fail("the machine's profile has no local spec", .{});
        const build = try c.path(try gpa.print("build-{s}", .{label}));
        var env = try c.env.clone(gpa);
        const stub = try join(gpa, &.{ try c.absolute(t.machine), "authority/linux.efi.stub" });
        try env.put("UKI_STUB", stub);
        const now = @divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s);
        const stamp = serial(@intCast(now));
        var disk_args: std.ArrayList([]const u8) = .empty;
        const listed = field(field(spec, "disk") orelse .null, "args") orelse .null;
        if (listed == .array) for (listed.array.items) |a|
            if (a == .string) try disk_args.append(gpa, a.string);
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(gpa, &.{ t.howl, "_build", "--with", source, "--arch", t.arch });
        if (t.variants.len > 0) try argv.appendSlice(
            gpa,
            &.{ "--variant", try mem.join(gpa, ",", t.variants) },
        );
        try argv.appendSlice(gpa, &.{ "--build", build });
        try argv.appendSlice(gpa, &.{ "--ipe-kernel", try str(spec, "ipe_kernel") });
        try argv.appendSlice(gpa, &.{ "--ipe-key", try str(spec, "ipe_key") });
        try argv.appendSlice(gpa, &.{ "--ipe-cert", try str(spec, "ipe_cert") });
        try argv.appendSlice(gpa, &.{ "--boot-key", try str(spec, "boot_key") });
        try argv.appendSlice(gpa, &.{ "--boot-cert", try str(spec, "boot_cert") });
        try argv.appendSlice(gpa, &.{ "--boot-native", "--tpm", "--ipe-updates", t.channel });
        try argv.appendSlice(gpa, &.{ "--image-serial", &stamp });
        try argv.appendSlice(gpa, &.{ "--image-index", try gpa.print("{d}", .{index}) });
        try argv.appendSlice(gpa, &.{ "--update-ca", try c.path("ca.crt") });
        try argv.appendSlice(gpa, &.{ "--disk", try join(gpa, &.{ build, "disk.img" }) });
        try argv.appendSlice(gpa, &.{ "--disk-args", try mem.join(gpa, " ", disk_args.items) });
        try argv.appendSlice(gpa, &.{ "disk", "prebuilt" });
        const r = try c.run(argv.items, try gpa.print("build-{s}", .{label}), .{
            .environ_map = &env,
            .timeout = .fromSeconds(3600),
        });
        if (!r.ok()) return c.fail("build {s}: {s}", .{ label, host.check.tail(r.stderr, 3000) });
        const head = try prebuiltHead(io, gpa, build, t.arch) orelse
            return c.fail("build {s} made no prebuilt head", .{label});
        const head_text = try Io.Dir.cwd().readFileAlloc(
            io,
            try join(gpa, &.{ head, "latest.json" }),
            gpa,
            .limited(1 << 20),
        );
        const manifest = try json.parseFromSliceLeaky(json.Value, gpa, head_text, .{});
        const built = field(manifest, "index") orelse .null;
        if (built != .integer or built.integer != index)
            return c.fail("built {s} at index {f}", .{ label, json.fmt(built, .{}) });
        const id = try str(manifest, "build");
        const channel_dir = try join(gpa, &.{ t.www, "image", t.arch });
        try merge(io, gpa, try join(gpa, &.{ head, id }), try join(gpa, &.{ channel_dir, id }));
        // Objects before the head, and the signature before what it signs.
        const heads = [_][]const u8{ "latest.json.sig", "latest.json" };
        for (heads) |f| {
            const incoming = try join(gpa, &.{ channel_dir, try gpa.print("{s}.new", .{f}) });
            try copy(io, try join(gpa, &.{ head, f }), incoming);
        }
        for (heads) |f| {
            const incoming = try join(gpa, &.{ channel_dir, try gpa.print("{s}.new", .{f}) });
            try Io.Dir.cwd().rename(incoming, .cwd(), try join(gpa, &.{ channel_dir, f }), io);
        }
    }

    fn install(
        t: *Test,
        label: []const u8,
        index: i64,
        floor: i64,
        previous: Status,
        committed: bool,
    ) !Status {
        const c = t.c;
        const check = "/usr/lib/werewolf/slot-update check";
        // SSH can drop a connection before the idempotent check reaches
        // the guest. Retry transport failures, never an updater rejection.
        var checked = try t.ssh(check, try c.gpa.print("check-{s}", .{label}), 900);
        var retries: u8 = 0;
        while (checked.code() == 255 and retries < 3) : (retries += 1) {
            try c.io.sleep(.fromSeconds(5), .awake);
            checked = try t.ssh(
                check,
                try c.gpa.print("check-{s}-retry-{d}", .{ label, retries + 1 }),
                900,
            );
        }
        if (!checked.ok())
            return c.fail(
                "check-{s}: {f}: {s}",
                .{ label, checked.term, host.check.tail(checked.stderr, 3000) },
            );
        const try_slot = "/usr/lib/werewolf/slot-update try";
        _ = try t.ssh(try_slot, try c.gpa.print("try-{s}", .{label}), 60);
        return t.waitBoot(label, index, floor, previous.str("boot_id"), committed);
    }

    fn limaHome(t: *Test) ![]const u8 {
        if (t.c.env.get("LIMA_HOME")) |h| return h;
        return join(t.c.gpa, &.{ t.c.env.get("HOME") orelse "", ".lima" });
    }

    /// powerOff cuts the machine's power, as a host crash would: the VM and
    /// its TPM die at once, and the TPM's NV keeps what it last committed.
    fn powerOff(t: *Test, stopped: bool) !void {
        const pids = try t.powered();
        // Retired-image refusal may already have removed QEMU's pidfile.
        // A real power-cut proof requires both owned processes.
        try powerCutPids(pids, stopped);
        for (pids) |pid| std.posix.kill(pid, .KILL) catch {};
        // SIGKILL is asynchronous. Until both processes have exited, create
        // can mistake the dying QEMU for the restarted machine and return.
        const until = host.qemu.after(t.c.io, 30);
        for (pids) |pid| while (true) {
            std.posix.kill(pid, @fromBackingInt(@intCast(0))) catch |err| switch (err) {
                error.ProcessNotFound => break,
                else => return err,
            };
            if (Io.Clock.Timestamp.now(t.c.io, .awake).compare(.gt, until))
                return t.c.fail("power-cut process {d} did not exit", .{pid});
            try t.c.io.sleep(.fromMilliseconds(50), .awake);
        };
    }

    /// powered is the machine's QEMU and swtpm.
    fn powered(t: *Test) ![]const std.posix.pid_t {
        const c = t.c;
        const gpa = c.gpa;
        var pids: std.ArrayList(std.posix.pid_t) = .empty;
        if (!mem.eql(u8, t.provider, "lima")) {
            for ([_][]const u8{ "qemu.pid", "authority/tpm.pid" }) |f|
                if (pidFile(c.io, gpa, try join(gpa, &.{ t.machine, f }))) |pid|
                    try pids.append(gpa, pid);
            return pids.items;
        }
        const home = try join(gpa, &.{ try t.limaHome(), t.name });
        const qemu_pid = try join(gpa, &.{ home, "qemu.pid" });
        if (pidFile(c.io, gpa, qemu_pid)) |pid| try pids.append(gpa, pid);
        const listed = try c.run(&.{ "ps", "-axo", "pid=,command=" }, "", .{});
        const pattern = try gpa.print("--tpmstate dir={s}/swtpm", .{home});
        try pids.appendSlice(gpa, try matching(gpa, listed.stdout, pattern));
        return pids.items;
    }

    fn restart(t: *Test, label: []const u8) !void {
        const c = t.c;
        if (mem.eql(u8, t.provider, "lima")) {
            const stop = [_][]const u8{ "limactl", "stop", "--force", t.name };
            _ = try c.run(&stop, try c.gpa.print("stop-{s}", .{label}), .{});
        }
        const restarted = try c.gpa.print("restart-{s}", .{label});
        _ = try c.must(t.create, restarted, .{ .timeout = .fromSeconds(1800) });
    }

    fn console(t: *Test) ![]const u8 {
        const c = t.c;
        const path = if (mem.eql(u8, t.provider, "lima"))
            try join(c.gpa, &.{ try t.limaHome(), t.name, "serial.log" })
        else
            try join(c.gpa, &.{ t.machine, "console.log" });
        return Io.Dir.cwd().readFileAlloc(c.io, path, c.gpa, .unlimited) catch "";
    }

    /// cleanup keeps the console and build logs, deletes the machine unless
    /// FLOOR_KEEP=1, and stops the channel and the proxy.
    fn cleanup(t: *Test) void {
        if (!t.started) return;
        const c = t.c;
        const gpa = c.gpa;
        if (t.server) |s| s.stop();
        if (t.files) |f| if (f.asked(gpa)) |asked| {
            var log: std.ArrayList(u8) = .empty;
            for (asked) |p| log.print(gpa, "GET {s}\n", .{p}) catch {};
            if (c.path("channel.log")) |p| write(c.io, p, log.items) catch {} else |_| {}
        } else |_| {};
        if (t.console()) |text| {
            if (c.path("console.log")) |p| write(c.io, p, text) catch {} else |_| {}
        } else |_| {}
        for ([_][]const u8{ "create.log", "build.log" }) |f| {
            const from = join(gpa, &.{ t.machine, f }) catch continue;
            const to = c.path(gpa.print("native-{s}", .{f}) catch continue) catch continue;
            copy(c.io, from, to) catch {};
        }
        const keep = mem.eql(u8, c.env.get("FLOOR_KEEP") orelse "", "1");
        const made = if (Io.Dir.cwd().access(c.io, t.machine, .{})) |_| true else |_| false;
        if (!keep and made) {
            const delete = [_][]const u8{ t.howl, "delete", t.name, "--on", t.provider };
            _ = c.run(&delete, "cleanup", .{}) catch {};
        }
        if (t.proxy) |p| p.close();
        if (t.private_ssh.len > 0) Io.Dir.cwd().deleteFile(c.io, t.private_ssh) catch {};
        if (t.proxy_dir.len > 0) Io.Dir.cwd().deleteTree(c.io, t.proxy_dir) catch {};
    }
};

/// Extra changes a release's rootfs before it is built.
const Extra = fn (Io, Allocator, []const u8) anyerror!void;

fn write(io: Io, path: []const u8, data: []const u8) !void {
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
}

fn copy(io: Io, from: []const u8, to: []const u8) !void {
    try Io.Dir.cwd().copyFile(from, .cwd(), to, io, .{});
}

/// formYaml is the test's form: playground, and only playground's
/// weaknesses, so the release differs from it only in its files.
fn formYaml(gpa: Allocator, playground: []const u8) ![]const u8 {
    return formYamlFor(gpa, "playground", playground);
}

fn formYamlFor(gpa: Allocator, name: []const u8, original: []const u8) ![]const u8 {
    const weaknesses = section(original, "weaknesses:\n") orelse return error.NoWeaknesses;
    return gpa.print("base: {s}\n{s}{s}{s}{s}", .{
        name,
        if (mem.eql(u8, name, "postgresql"))
            "with: [ssh-su]\npackages: [postgresql-client]\n"
        else
            "",
        weaknesses,
        if (mem.eql(u8, name, "postgresql"))
            "  network-no-login: SSH controls the update test fixture\n" ++
                "  programs-no-shell: The update test fixture uses a shell\n"
        else
            "",
        section(original, "variants:\n") orelse "",
    });
}

fn section(original: []const u8, key: []const u8) ?[]const u8 {
    const at = mem.find(u8, original, key) orelse return null;
    var end = at + key.len;
    while (end < original.len) {
        const next = if (mem.findScalarPos(u8, original, end, '\n')) |n| n + 1 else original.len;
        if (original[end] != ' ' and original[end] != '\n' and original[end] != '#') break;
        end = next;
    }
    return original[at..end];
}

fn postgresCommand(gpa: Allocator, variants: []const []const u8, seeded: bool) ![]const u8 {
    var vector = false;
    for (variants) |name| if (mem.eql(u8, name, "vector")) {
        vector = true;
    };
    return gpa.print("/usr/bin/psql -X -w -A -t -q -v ON_ERROR_STOP=1 " ++
        "-h /run/svc/postgres -U root -d postgres <<'SQL'\n{s}{s}" ++
        "SELECT value FROM update_variant_test;\nSQL\n", .{
        if (seeded) "" else "CREATE TABLE update_variant_test(value text);\n" ++
            "INSERT INTO update_variant_test VALUES ('variant-data-kept');\n",
        if (vector) "CREATE EXTENSION IF NOT EXISTS vector;\n" ++
            "DO $$ BEGIN IF ('[1,2,3]'::vector <-> '[1,2,3]'::vector) <> 0 " ++
            "THEN RAISE EXCEPTION 'vector distance failed'; END IF; END $$;\n" else "",
    });
}

/// modes gives the overlay the modes a release's files have: directories
/// and the probe 0755, everything else 0644.
fn modes(io: Io, gpa: Allocator, overlay: []const u8, probe: []const u8) !void {
    var dir = try Io.Dir.cwd().openDir(io, overlay, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(gpa);
    defer walker.deinit();
    const probe_inside = probe[overlay.len + 1 ..];
    while (try walker.next(io)) |e| {
        if (e.kind == .sym_link) continue;
        const exec = e.kind == .directory or mem.eql(u8, e.path, probe_inside);
        try dir.setFilePermissions(io, e.path, .fromMode(if (exec) 0o755 else 0o644), .{});
    }
}

/// unhealthy adds a service that never runs, so the release never commits.
fn unhealthy(io: Io, gpa: Allocator, root: []const u8) !void {
    const service = try join(gpa, &.{ root, "etc/sv/ab-unhealthy" });
    try Io.Dir.cwd().createDirPath(io, service);
    for ([_][]const u8{ "etc", "etc/sv", "etc/sv/ab-unhealthy" }) |d| {
        const dir = try join(gpa, &.{ root, d });
        try Io.Dir.cwd().setFilePermissions(io, dir, .fromMode(0o755), .{});
    }
    try Io.Dir.cwd().symLink(io, "/usr/bin/false", try join(gpa, &.{ service, "run" }), .{});
}

/// prebuiltHead is the one BUILD/*/prebuilt/ARCH a build made, or null.
fn prebuiltHead(io: Io, gpa: Allocator, build: []const u8, arch: []const u8) !?[]const u8 {
    var dir = try Io.Dir.cwd().openDir(io, build, .{ .iterate = true });
    defer dir.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |e|
        if (e.kind == .directory) try names.append(gpa, try gpa.dupe(u8, e.name));
    mem.sortUnstable([]const u8, names.items, {}, lessThan);
    for (names.items) |n| {
        const head = try join(gpa, &.{ build, n, "prebuilt", arch });
        if (Io.Dir.cwd().access(io, try join(gpa, &.{ head, "latest.json" }), .{})) |_| {
            return head;
        } else |_| {}
    }
    return null;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return mem.lessThan(u8, a, b);
}

/// merge copies the tree from into to, keeping what to already holds.
fn merge(io: Io, gpa: Allocator, from: []const u8, to: []const u8) !void {
    try Io.Dir.cwd().createDirPath(io, to);
    var source = try Io.Dir.cwd().openDir(io, from, .{ .iterate = true });
    defer source.close(io);
    var target = try Io.Dir.cwd().openDir(io, to, .{});
    defer target.close(io);
    var walker = try source.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |e| switch (e.kind) {
        .directory => try target.createDirPath(io, e.path),
        .file => try source.copyFile(e.path, target, e.path, io, .{}),
        else => return error.UnsupportedFileKind,
    };
}

fn field(v: json.Value, key: []const u8) ?json.Value {
    return if (v == .object) v.object.get(key) else null;
}

fn str(v: json.Value, key: []const u8) ![]const u8 {
    const got = field(v, key) orelse return error.MissingField;
    return if (got == .string) got.string else error.MissingField;
}

fn pidFile(io: Io, gpa: Allocator, path: []const u8) ?std.posix.pid_t {
    const text = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64)) catch return null;
    return std.fmt.parseInt(std.posix.pid_t, mem.trim(u8, text, " \t\r\n"), 10) catch null;
}

fn powerCutPids(pids: []const std.posix.pid_t, stopped: bool) !void {
    if (!stopped and pids.len != 2) return error.MissingPowerCutProcesses;
    for (pids) |pid| if (pid <= 1) return error.InvalidOwnedProcess;
}

test "power cuts require owned processes but retired-image refusal may have stopped them" {
    try powerCutPids(&.{ 100, 101 }, false);
    try std.testing.expectError(error.MissingPowerCutProcesses, powerCutPids(&.{100}, false));
    try std.testing.expectError(error.MissingPowerCutProcesses, powerCutPids(&.{}, false));
    try powerCutPids(&.{100}, true);
    try powerCutPids(&.{}, true);
    for ([_]std.posix.pid_t{ -1, 0, 1 }) |pid|
        try std.testing.expectError(error.InvalidOwnedProcess, powerCutPids(&.{pid}, true));
}

/// matching is the pids of ps's "pid command" lines containing pattern.
fn matching(gpa: Allocator, ps: []const u8, pattern: []const u8) ![]const std.posix.pid_t {
    var out: std.ArrayList(std.posix.pid_t) = .empty;
    var lines = mem.tokenizeScalar(u8, ps, '\n');
    while (lines.next()) |line| {
        if (mem.find(u8, line, pattern) == null) continue;
        var words = mem.tokenizeAny(u8, line, " \t");
        const pid = std.fmt.parseInt(std.posix.pid_t, words.next() orelse continue, 10) catch
            continue;
        try out.append(gpa, pid);
    }
    return out.items;
}

/// temporary makes a fresh private directory, its name starting prefix,
/// under TMPDIR: short enough for the proxy's sockets.
fn temporary(c: *host.Check, prefix: []const u8) ![]const u8 {
    var id: [6]u8 = undefined;
    c.io.random(&id);
    const base = mem.trimEnd(u8, c.env.get("TMPDIR") orelse "/tmp", "/");
    const hex = std.fmt.bytesToHex(id, .lower);
    const dir = try c.gpa.print("{s}/{s}{s}", .{ base, prefix, &hex });
    try Io.Dir.cwd().createDir(c.io, dir, .fromMode(0o700));
    return dir;
}

/// serial is a release serial, YYYYMMDDTHHMMSSZ, for seconds since 1970.
fn serial(seconds: u64) [16]u8 {
    const at: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year = at.getEpochDay().calculateYearDay();
    const month = year.calculateMonthDay();
    const day = at.getDaySeconds();
    var out: [16]u8 = undefined;
    _ = std.mem.print(&out, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        year.year,             month.month.numeric(),    month.day_index + 1,
        day.getHoursIntoDay(), day.getMinutesIntoHour(), day.getSecondsIntoMinute(),
    }) catch unreachable;
    return out;
}

test "the form is playground with only playground's weaknesses" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "base: playground\nweaknesses:\n  a: b\n",
        try formYaml(arena.allocator(), "base: x\nwith: [y]\nweaknesses:\n  a: b\n"),
    );
    try std.testing.expectError(error.NoWeaknesses, formYaml(arena.allocator(), "base: x\n"));
}

test "matching finds the TPM of this machine only" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const ps =
        \\  101 /usr/bin/swtpm socket --tpmstate dir=/l/ww-floor-1/swtpm --ctrl x
        \\  102 /usr/bin/swtpm socket --tpmstate dir=/l/other/swtpm
        \\ 103 qemu
    ;
    const pids = try matching(arena.allocator(), ps, "--tpmstate dir=/l/ww-floor-1/swtpm");
    try std.testing.expectEqualSlices(std.posix.pid_t, &.{101}, pids);
}

test "serial is the release serial of a moment" {
    try std.testing.expectEqualStrings("20261024T235959Z", &serial(1792886399));
}

test "postdoc trials keep the form's weaknesses without copying its service declarations" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    try std.testing.expectEqualStrings(
        "base: postdoc-server\nweaknesses:\n  kernel-write-xor-execute: JIT\n\n",
        try formYamlFor(gpa, "postdoc-server", "base: prod\nwith: [sshd]\n" ++
            "weaknesses:\n  kernel-write-xor-execute: JIT\n\ncheck:\n  memory: " ++
            "4096\nservices:\n  app: {}\n"),
    );
    const lookup = try @import("postdoc.zig").command(gpa, true);
    try std.testing.expect(mem.find(
        u8,
        lookup,
        "cf48981276a20c3ed7a5e878416c98179ff43a5ee7fd309738bf72a3bea8df17",
    ) != null);
}
