//! check-published-lifecycle HOWL PROVIDER BUNDLE UPDATES OUTPUT holds one
//! candidate bundle, signed for publication, to the twelve lifecycle gates
//! `release prepare-protected` requires (tools/release/prepare.zig), and
//! writes them to OUTPUT/gates.json.
//!
//! The candidate itself goes through a consumer's own download from a
//! private HTTPS mirror laid out as the public one: a default `howl run`,
//! with no source tree, build tools or vendor key, boots it under Secure
//! Boot and IPE from its verified root, and its first boot takes the TPM at
//! the candidate's index; unsigned and tampered code is refused; a repeat
//! run neither reboots nor downloads; a resume keeps the enrollment. QEMU
//! drives QEMU through the owner channel, Lima over SSH. Postdoc's API and
//! persistent verdict are also checked over security-key SSH on both providers.
//!
//! A candidate's updater follows the public mirror its signed image names,
//! so its own A/B updates cannot run before it is published. UPDATES is
//! check-independent-updates' evidence instead, which the gate made once:
//! the same tree's updates, operator rollback, power cuts at the floor's
//! increment, a refused retired release and a failed trial's fallback, on
//! disposable keys (docs/design/implemented/independent-updates.md).

const std = @import("std");
const host = @import("host");
const form = @import("form");
const published = @import("published.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;

const machine_name = "werewolf-run";

/// candidate_gates are what the candidate proves itself here.
const candidate_gates = [_][]const u8{
    "secure_boot",    "ipe",                "verified_root",          "rollback_protected",
    "tamper_refused", "no_consumer_builds", "no_vendor_private_keys", "fresh_download",
};
/// update_gates are what check-independent-updates' evidence proves.
const update_gates = [_][]const u8{
    "ab_upgrade", "operator_rollback", "unhealthy_fallback", "retirement_cuts",
};

pub fn main(init: std.process.Init) !void {
    var c = try host.Check.init(init, "published lifecycle");
    if (c.args.len != 6) {
        var buf: [256]u8 = undefined;
        var out = Io.File.stderr().writerStreaming(c.io, &buf);
        const usage = "usage: check-published-lifecycle HOWL PROVIDER BUNDLE UPDATES OUTPUT\n";
        out.interface.writeAll(usage) catch {};
        out.interface.flush() catch {};
        std.process.exit(1);
    }
    var l: Lifecycle = .{ .c = &c };
    const result = l.check();
    l.cleanup();
    c.finish(result);
}

/// Boot is a committed, protected boot of the candidate.
const Boot = struct { boot_id: []const u8 };

const Lifecycle = struct {
    c: *host.Check,
    howl: []const u8 = "",
    provider: []const u8 = "",
    form: []const u8 = "",
    variants: []const []const u8 = &.{},
    login: bool = false,
    arch: []const u8 = "",
    channel: []const u8 = "",
    index: u64 = 0,
    /// shellfree targets, QEMU's, are driven through howl's owner channel,
    /// with no SSH into the guest.
    shellfree: bool = false,
    consumer: []const u8 = "",
    machine: []const u8 = "",
    identity: []const u8 = "",
    security_key_provider: ?[]const u8 = null,
    lima_home: []const u8 = "",
    env: std.process.Environ.Map = undefined,
    mirror: published.Mirror = undefined,
    serving: bool = false,
    required: []const []const u8 = &.{},
    run_argv: []const []const u8 = &.{},

    fn check(l: *Lifecycle) !void {
        const c = l.c;
        const gpa = c.gpa;
        const io = c.io;
        published.private();
        l.howl = try c.absolute(c.args[1]);
        l.provider = c.args[2];
        const bundle = try c.absolute(c.args[3]);
        const updates = try c.absolute(c.args[4]);
        const work = try c.absolute(c.args[5]);
        if (exists(io, work)) return c.fail("{s} exists already", .{work});
        try Io.Dir.cwd().createDirPath(io, work);
        try c.setWork(work);
        const descriptor = try l.describe(bundle);
        const evidence = try l.readJson(updates, "result.json");
        var why: host.check.Why = .{};
        const revision = try c.must(&.{ "git", "rev-parse", "HEAD" }, "", .{});
        const source_commit = mem.trim(u8, revision.stdout, " \t\r\n");
        updated(
            evidence,
            l.provider,
            l.arch,
            l.form,
            source_commit,
            &why,
        ) catch return c.fail("{s}", .{why.text});
        if (!published.sameVariants(evidence, l.variants))
            return c.fail("the update evidence describes another variant selection", .{});

        // QEMU's sockets are Unix paths under a 108-byte limit; a fresh
        // consumer stays independent of the checkout's possibly deep path.
        l.consumer = try published.temporary(io, gpa, "ww-consumer-");
        const mirror = try c.path("mirror");
        const base = try std.fs.path.join(
            gpa,
            &.{ mirror, try form.variantPath(gpa, l.form, l.variants), l.provider, l.arch },
        );
        _ = try published.stock(io, gpa, bundle, base, l.arch);
        const latest = try std.fs.path.join(gpa, &.{ base, "latest" });
        try Io.Dir.cwd().createDirPath(io, latest);
        try published.promote(io, gpa, bundle, latest);
        l.identity = try c.path("ssh.key");
        if (l.login or mem.eql(u8, l.form, "postdoc-server")) {
            l.security_key_provider = try c.absolute("build/host/test-sk.so");
            _ = try c.must(&.{
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519-sk",
                "-w",
                l.security_key_provider.?,
                "-O",
                "verify-required",
                "-N",
                "",
                "-f",
                l.identity,
            }, "ssh-key", .{});
        } else {
            const keygen = [_][]const u8{ "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f" };
            _ = try c.must(&(keygen ++ .{l.identity}), "ssh-key", .{});
        }
        try l.serve(mirror);
        l.machine = try std.fs.path.join(gpa, &.{ l.consumer, "build/machines", machine_name });
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(
            gpa,
            &.{ l.howl, "run", "--with", l.form, "--on", l.provider, "--add-current-user", "no" },
        );
        if (l.variants.len > 0) try argv.appendSlice(
            gpa,
            &.{ "--variant", try mem.join(gpa, ",", l.variants) },
        );
        if (!l.shellfree or l.security_key_provider != null)
            try argv.appendSlice(gpa, &.{ "--root-keys", try gpa.print("{s}.pub", .{l.identity}) });
        if (mem.eql(u8, l.form, "postdoc-server")) {
            const config = try c.path("config");
            _ = try c.must(&.{ "forms/postdoc-server/test/config", config }, "config", .{});
            try argv.appendSlice(gpa, &.{ "--config", config });
        }
        if (mem.eql(u8, l.form, "bastion")) {
            const config = try c.path("config");
            try Io.Dir.cwd().createDirPath(io, config);
            const key = try Io.Dir.cwd().readFileAlloc(
                io,
                try gpa.print("{s}.pub", .{l.identity}),
                gpa,
                .limited(64 << 10),
            );
            try l.write(
                try std.fs.path.join(gpa, &.{ config, "users" }),
                try gpa.print("operator admin {s}", .{key}),
            );
            try argv.appendSlice(gpa, &.{ "--config", config });
        }
        l.run_argv = argv.items;

        // The first run downloads, builds nothing (its PATH refuses build
        // tools) and boots the candidate with every protection.
        _ = try c.must(l.run_argv, "first-run", l.options(600));
        const first = try l.committed(null);
        try l.checkLogin();
        if (mem.eql(u8, l.form, "postdoc-server")) try l.postdoc(false);
        try l.enrolled();
        if (try l.mirror.requests(gpa) == 0)
            return c.fail("the first run downloaded nothing from the mirror", .{});
        // A shell-free image's own native probes already ran: its owner
        // status needs them passed. Over SSH, they run here.
        if (!l.shellfree) for ([_][2][]const u8{
            .{ "cp /usr/bin/true /data/unsigned-probe && /data/unsigned-probe", "unsigned" },
            .{ "echo tamper >> /usr/bin/true", "root-write" },
        }) |probe| {
            if ((try l.ssh(probe[0], probe[1], 300)).ok())
                return c.fail("{s} was accepted", .{probe[1]});
        };

        // An unchanged run neither reboots, downloads nor rechecks the mirror.
        const before = try l.authority();
        const downloaded = try l.mirror.requests(gpa);
        const checked = try l.freshness();
        const began = Io.Clock.Timestamp.now(io, .awake);
        _ = try c.must(l.run_argv, "repeat-run", l.options(300));
        const elapsed = began.untilNow(io).raw.toMilliseconds();
        const now = try l.status();
        if (now == null or !mem.eql(u8, now.?.boot_id, first.boot_id) or
            try l.mirror.requests(gpa) != downloaded)
            return c.fail("unchanged run rebooted or downloaded again", .{});
        if (!mem.eql(u8, &checked, &try l.freshness()))
            return c.fail("unchanged run repeated mirror freshness checks", .{});
        if (!mem.eql(u8, &before, &try l.authority()))
            return c.fail("unchanged run replaced machine authority", .{});

        // The consumer holds the exact candidate and no vendor key.
        const profile = try l.readJson(l.machine, "authority/profile.json");
        const head = try std.fs.path.join(
            gpa,
            &.{ published.bundleDirectory(profile) orelse "", "boot.json" },
        );
        const got = host.check.hexDigest(io, head) catch @as([64]u8, @splat('-'));
        if (!mem.eql(u8, &got, &descriptor))
            return c.fail("the download differs from the candidate", .{});
        if (!published.vendorFree(profile)) return c.fail(
            "consumer owns a vendor signing key",
            .{},
        );

        // A stop and resume boots again on the same enrollment.
        _ = try c.must(&.{ l.howl, "stop" }, "stop", l.options(300));
        _ = try c.must(l.run_argv, "resume", l.options(600));
        _ = try l.committed(first.boot_id);
        try l.checkLogin();
        if (mem.eql(u8, l.form, "postdoc-server")) try l.postdoc(true);
        if (!mem.eql(u8, &before, &try l.authority()))
            return c.fail("resume replaced the enrollment", .{});

        try l.write(try c.path("gates.json"), try gates(gpa, &descriptor, l.arch, l.provider));
        const result = try json.Stringify.valueAlloc(gpa, .{
            .descriptor = &descriptor,
            .index = l.index,
            .unchanged_run_seconds = @as(f64, @floatFromInt(elapsed)) / 1000,
            .updates = "check-independent-updates on disposable keys",
        }, .{ .whitespace = .indent_2 });
        try l.write(try c.path("result.json"), try gpa.print("{s}\n", .{result}));
        c.say("pass: the exact candidate downloads, boots protected, takes the TPM at index " ++
            "{d} and keeps it; updates from this tree's disposable-key evidence", .{l.index});
    }

    /// describe reads the candidate's boot.json: its form, architecture,
    /// channel and index, which must be a published target of provider.
    /// It returns the descriptor, boot.json's digest.
    fn describe(l: *Lifecycle, bundle: []const u8) ![64]u8 {
        const c = l.c;
        const manifest = try l.readJson(bundle, "boot.json");
        const image = published.field(manifest, "image") orelse json.Value{ .null = {} };
        l.form = published.text(manifest, "form") orelse "";
        l.variants = try published.variants(c.gpa, manifest);
        for (l.variants) |name| if (mem.eql(u8, name, "ssh")) {
            l.login = true;
        };
        l.arch = published.text(image, "arch") orelse "";
        l.channel = published.text(image, "channel_id") orelse "";
        const index = published.field(image, "index") orelse json.Value{ .null = {} };
        if (index != .integer or index.integer < 1 or l.channel.len != 64)
            return c.fail("the candidate names no release of a channel", .{});
        l.index = @intCast(index.integer);
        const images = try published.Images.load(c.io, c.gpa);
        const qemu = mem.eql(u8, l.provider, "qemu");
        if (!qemu and !mem.eql(u8, l.provider, "lima"))
            return c.fail("provider is qemu or lima", .{});
        if (!images.isTarget(l.form, l.provider, l.arch))
            return c.fail("{s} is not published for {s} on {s}", .{ l.form, l.provider, l.arch });
        // Lima has no owner channel here; its gated forms have SSH.
        if (!qemu and !l.login and !mem.eql(u8, l.form, "playground") and
            !mem.eql(u8, l.form, "postdoc-server"))
            return c.fail("Lima tests playground and postdoc-server over SSH", .{});
        l.shellfree = qemu;
        l.required = if (qemu)
            (try host.evidence.load(c.gpa, form)).published
        else
            (try host.evidence.load(c.gpa, form)).ssh;
        return host.check.hexDigest(c.io, try std.fs.path.join(c.gpa, &.{ bundle, "boot.json" }));
    }

    fn checkLogin(l: *Lifecycle) !void {
        if (l.login and !(try l.ssh("id -u", "variant-login", 30)).ok())
            return l.c.fail("the SSH variant did not authenticate an operator login", .{});
    }

    /// serve starts the private HTTPS mirror and the consumer's env: no
    /// vendor key, a PATH of build-refusing wrappers, the mirror's CA and
    /// the mirror in place of the public one.
    fn serve(l: *Lifecycle, mirror: []const u8) !void {
        const c = l.c;
        const gpa = c.gpa;
        const io = c.io;
        try l.mirror.start(io, gpa, mirror, "werewolf-lifecycle-mirror");
        l.serving = true;
        l.env = try c.env.clone(gpa);
        try host.consumer.scrub(gpa, &l.env);
        const bin = try c.path("bin");
        try Io.Dir.cwd().createDir(io, bin, .default_dir);
        try host.consumer.refuseBuilds(io, gpa, bin);
        const ssh_binary = host.consumer.which(io, gpa, &c.env, "ssh") orelse
            return c.fail("no ssh on PATH", .{});
        try host.consumer.sshWithProvider(
            io,
            gpa,
            bin,
            ssh_binary,
            l.identity,
            l.security_key_provider,
        );
        l.lima_home = try published.temporary(io, gpa, "ww-published-lifecycle-");
        const roots = try c.path("mirror-roots.pem");
        const system = &host.consumer.system_bundles;
        const pem = host.consumer.mirrorRoots(io, gpa, &c.env, system, l.mirror.authority) catch
            return c.fail("public TLS roots are missing; install ca-certificates", .{});
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = roots, .data = pem });
        try l.env.put("LIMA_HOME", l.lima_home);
        try l.env.put("SSL_CERT_FILE", roots);
        try l.env.put("XDG_DATA_HOME", try std.fs.path.join(gpa, &.{ l.consumer, "data" }));
        try l.env.put("WEREWOLF_BOOT_MIRROR", try l.mirror.url(gpa));
        try l.env.put("PATH", try gpa.print("{s}:{s}", .{ bin, c.env.get("PATH") orelse "" }));
    }

    /// status is the running boot once it is committed, with every
    /// protection and the candidate's channel and index on its signed
    /// command line, else null; a missing protection fails. It pauses the
    /// updater, which follows the public mirror, so nothing changes
    /// between steps.
    fn status(l: *Lifecycle) !?Boot {
        const c = l.c;
        var why: host.check.Why = .{};
        if (l.shellfree) {
            const reply = try c.run(
                &.{ l.howl, "owner", machine_name, "status" },
                "status",
                l.options(20),
            );
            if (!reply.ok()) return null;
            const value = json.parseFromSliceLeaky(json.Value, c.gpa, reply.stdout, .{}) catch
                return null;
            const boot = ownerBoot(c.gpa, value, l.required, l.channel, l.index, &why) catch |err|
                return if (err == error.Refused) c.fail("{s}", .{why.text}) else err;
            if (boot != null and !published.isTrue(published.field(value, "paused")))
                _ = try c.must(
                    &.{ l.howl, "owner", machine_name, "pause" },
                    "pause",
                    l.options(300),
                );
            return boot;
        }
        const command = "/usr/lib/werewolf/posture --json; printf \"\\nBOOT-ID \"; " ++
            "cat /proc/sys/kernel/random/boot_id; printf \"CMDLINE \"; cat /proc/cmdline; " ++
            "printf \"COMMITTED \"; test -e /run/werewolf/committed && echo yes";
        const reply = try l.ssh(command, "status", 15);
        if (!reply.ok()) return null;
        const boot = sshBoot(c.gpa, reply.stdout, l.required, l.channel, l.index, &why) catch |err|
            return if (err == error.Refused) c.fail("{s}", .{why.text}) else err;
        if (boot != null) {
            const pause = "test -e /run/werewolf/updater-ready && sv pause /etc/sv/autoupdate";
            if (!(try l.ssh(pause, "pause-updater", 15)).ok()) return null;
        }
        return boot;
    }

    /// committed waits up to four minutes for a committed boot other than
    /// previous.
    fn committed(l: *Lifecycle, previous: ?[]const u8) !Boot {
        const c = l.c;
        const deadline = host.qemu.after(c.io, 240);
        while (Io.Clock.Timestamp.now(c.io, .awake).compare(.lt, deadline)) {
            if (try l.status()) |boot| {
                if (previous == null or !mem.eql(u8, previous.?, boot.boot_id)) return boot;
            }
            try c.io.sleep(.fromSeconds(2), .awake);
        }
        return c.fail("the candidate did not report a committed protected boot", .{});
    }

    /// enrolled requires stage0's own account of the first boot on the
    /// console: firmware enforcing the image's signer alone, the verified
    /// root, IPE, and the TPM taken at the candidate's index.
    fn enrolled(l: *Lifecycle) !void {
        const c = l.c;
        const console = Io.Dir.cwd().readFileAlloc(
            c.io,
            try l.consolePath(),
            c.gpa,
            .limited(64 << 20),
        ) catch
            return c.fail("the machine kept no console", .{});
        const floor = try c.gpa.print(
            "stage0: TPM floor {d}: release {d} admitted; reset authority sealed",
            .{ l.index, l.index },
        );
        for ([_][]const u8{
            "stage0: Secure Boot enforced outside setup mode",
            "stage0: Secure Boot admits only this image's signer",
            "stage0: slot a: /boot/slot/a/root.erofs, read-only, verified",
            "stage0: IPE: only this root image may execute; policy administration removed",
            floor,
        }) |line| if (mem.find(u8, console, line) == null)
            return c.fail("the console lacks \"{s}\"", .{line});
    }

    fn consolePath(l: *Lifecycle) ![]const u8 {
        if (l.shellfree) return std.fs.path.join(l.c.gpa, &.{ l.machine, "console.log" });
        return std.fs.path.join(l.c.gpa, &.{ l.lima_home, machine_name, "serial.log" });
    }

    fn ssh(l: *Lifecycle, command: []const u8, label: []const u8, seconds: i64) !host.check.Result {
        const argv = [_][]const u8{
            l.howl,
            "ssh",
            if (mem.eql(u8, l.form, "bastion"))
                "operator@" ++ machine_name
            else
                "root@" ++ machine_name,
            "--no-agent",
            "--",
            command,
        };
        return l.c.run(&argv, label, l.options(seconds));
    }

    /// Exercise the real JIT server with config supplied by the consumer,
    /// then require its verdict to survive a cold stop/resume.
    fn postdoc(l: *Lifecycle, resumed: bool) !void {
        const workload = @import("postdoc.zig");
        if (!(try l.ssh(workload.health, "postdoc-health", 960)).ok())
            return l.c.fail("postdoc did not become healthy under IPE", .{});
        if (!(try l.ssh(
            try workload.command(l.c.gpa, resumed),
            if (resumed) "postdoc-persisted" else "postdoc-analyze",
            360,
        )).ok())
            return l.c.fail("postdoc analysis or persistent verdict failed", .{});
        if (!(try l.ssh(workload.tunnel, "postdoc-tunnel", 30)).ok())
            return l.c.fail("cloudflared did not start with the supplied tunnel token", .{});
    }

    /// options runs a command in the consumer, with its environment, for at
    /// most seconds.
    fn options(l: *Lifecycle, seconds: i64) host.check.Options {
        return .{ .environ_map = &l.env, .cwd = l.consumer, .timeout = .fromSeconds(seconds) };
    }

    /// authority is the digest of what the host keeps of the machine's
    /// authority: its enrolled boot certificate and profile, no TPM secret.
    fn authority(l: *Lifecycle) ![64]u8 {
        var h: std.crypto.hash.sha2.Sha256 = .init(.{});
        for ([_][]const u8{ "boot.crt", "authority/profile.json" }) |name| {
            const path = try std.fs.path.join(l.c.gpa, &.{ l.machine, name });
            h.update(&try host.check.digest(l.c.io, path));
        }
        return std.fmt.bytesToHex(h.finalResult(), .lower);
    }

    /// freshness is the digest of every mirror freshness record howl keeps.
    fn freshness(l: *Lifecycle) ![64]u8 {
        const io = l.c.io;
        const gpa = l.c.gpa;
        var h: std.crypto.hash.sha2.Sha256 = .init(.{});
        const cache = try std.fs.path.join(gpa, &.{ l.consumer, "build/boot-cache" });
        var dir = Io.Dir.cwd().openDir(io, cache, .{ .iterate = true }) catch
            return std.fmt.bytesToHex(h.finalResult(), .lower);
        defer dir.close(io);
        var names: std.ArrayList([]const u8) = .empty;
        var walker = try dir.walk(gpa);
        defer walker.deinit();
        while (try walker.next(io)) |e| {
            if (e.kind == .file and mem.eql(u8, e.basename, "current.json"))
                try names.append(gpa, try gpa.dupe(u8, e.path));
        }
        mem.sortUnstable([]const u8, names.items, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return mem.lessThan(u8, a, b);
            }
        }.less);
        for (names.items) |name| {
            h.update(name);
            h.update(&try host.check.digest(io, try std.fs.path.join(gpa, &.{ cache, name })));
        }
        return std.fmt.bytesToHex(h.finalResult(), .lower);
    }

    fn readJson(l: *Lifecycle, dir: []const u8, name: []const u8) !json.Value {
        const path = try std.fs.path.join(l.c.gpa, &.{ dir, name });
        const text = Io.Dir.cwd().readFileAlloc(l.c.io, path, l.c.gpa, .limited(1 << 20)) catch
            return l.c.fail("{s}: unreadable", .{path});
        return json.parseFromSliceLeaky(json.Value, l.c.gpa, text, .{}) catch
            return l.c.fail("{s}: not JSON", .{path});
    }

    fn write(l: *Lifecycle, path: []const u8, data: []const u8) !void {
        try Io.Dir.cwd().writeFile(l.c.io, .{ .sub_path = path, .data = data });
    }

    /// cleanup keeps the machine's console and logs, deletes it, stops the
    /// mirror, and removes the consumer and its key, however far the run got.
    fn cleanup(l: *Lifecycle) void {
        const c = l.c;
        if (l.serving) {
            keep: {
                const from = l.consolePath() catch break :keep;
                const to = c.path("console.log") catch break :keep;
                Io.Dir.cwd().copyFile(from, .cwd(), to, c.io, .{}) catch {};
            }
            if (!l.shellfree) l.keepLimaLogs();
            const delete = [_][]const u8{ l.howl, "delete", machine_name, "--on", l.provider };
            _ = c.run(&delete, "cleanup", l.options(180)) catch {};
            l.mirror.stop();
        }
        if (l.lima_home.len > 0) Io.Dir.cwd().deleteTree(c.io, l.lima_home) catch {};
        if (l.consumer.len > 0) Io.Dir.cwd().deleteTree(c.io, l.consumer) catch {};
        if (l.identity.len > 0) Io.Dir.cwd().deleteFile(c.io, l.identity) catch {};
    }

    /// keepLimaLogs copies each log Lima kept for the machine into the output.
    fn keepLimaLogs(l: *Lifecycle) void {
        const c = l.c;
        const home = std.fs.path.join(c.gpa, &.{ l.lima_home, machine_name }) catch return;
        var dir = Io.Dir.cwd().openDir(c.io, home, .{ .iterate = true }) catch return;
        defer dir.close(c.io);
        var it = dir.iterate();
        while (it.next(c.io) catch return) |e| {
            if (e.kind != .file or !mem.endsWith(u8, e.name, ".log")) continue;
            const to = c.path(c.gpa.print("lima-{s}", .{e.name}) catch return) catch return;
            dir.copyFile(e.name, .cwd(), to, c.io, .{}) catch {};
        }
    }
};

/// updated judges check-independent-updates' evidence: a pass on this
/// provider, architecture and source revision, attesting every update gate.
fn updated(
    evidence: json.Value,
    provider: []const u8,
    arch: []const u8,
    workload: []const u8,
    commit: []const u8,
    why: *host.check.Why,
) !void {
    const format = published.text(evidence, "format") orelse "";
    if (!mem.eql(u8, format, "werewolf-update-evidence/1") or
        !published.isTrue(published.field(evidence, "passed")))
        return why.refuse("the update evidence records no pass", .{});
    if (!mem.eql(u8, published.text(evidence, "provider") orelse "", provider) or
        !mem.eql(u8, published.text(evidence, "arch") orelse "", arch) or
        !mem.eql(u8, published.text(evidence, "commit") orelse "", commit))
        return why.refuse("the update evidence is of another target or source revision", .{});
    if ((mem.eql(u8, workload, "postdoc-server") or mem.eql(u8, workload, "postgresql")) and
        !mem.eql(u8, published.text(evidence, "form") orelse "", workload))
        return why.refuse(
            "{s} publication requires its own signed A/B workload evidence",
            .{workload},
        );
    const checks = published.field(evidence, "checks") orelse json.Value{ .null = {} };
    for (update_gates) |gate| if (!published.isTrue(published.field(checks, gate)))
        return why.refuse("the update evidence lacks {s}", .{gate});
}

/// ownerBoot judges an owner status: null until it is ready and committed;
/// then the boot, which must run the candidate with every protection.
fn ownerBoot(
    gpa: Allocator,
    value: json.Value,
    required: []const []const u8,
    channel: []const u8,
    index: u64,
    why: *host.check.Why,
) !?Boot {
    if (!published.isTrue(published.field(value, "ready")) or
        !published.isTrue(published.field(value, "committed"))) return null;
    const boot_id = published.text(value, "boot_id") orelse return null;
    try candidate(published.text(value, "cmdline") orelse "", channel, index, why);
    try protected(gpa, value, required, why);
    return .{ .boot_id = boot_id };
}

/// sshBoot judges an SSH status reply, the posture report then BOOT-ID,
/// CMDLINE and COMMITTED lines, as ownerBoot does.
fn sshBoot(
    gpa: Allocator,
    reply: []const u8,
    required: []const []const u8,
    channel: []const u8,
    index: u64,
    why: *host.check.Why,
) !?Boot {
    const marker = "\nBOOT-ID ";
    const end = mem.find(u8, reply, marker) orelse return null;
    const report = json.parseFromSliceLeaky(json.Value, gpa, reply[0..end], .{}) catch return null;
    var boot_id: ?[]const u8 = null;
    var cmdline: []const u8 = "";
    var committed = false;
    var lines = mem.splitScalar(u8, reply[end + 1 ..], '\n');
    while (lines.next()) |line| {
        if (mem.cutPrefix(u8, line, "BOOT-ID ")) |v| boot_id = v;
        if (mem.cutPrefix(u8, line, "CMDLINE ")) |v| cmdline = v;
        if (mem.eql(u8, line, "COMMITTED yes")) committed = true;
    }
    if (!committed) return null;
    try candidate(cmdline, channel, index, why);
    try protected(gpa, report, required, why);
    return .{ .boot_id = boot_id orelse return null };
}

/// candidate refuses a signed command line of another channel or release.
fn candidate(cmdline: []const u8, channel: []const u8, index: u64, why: *host.check.Why) !void {
    var buf: [24]u8 = undefined;
    const want = std.mem.print(&buf, "{d}", .{index}) catch unreachable;
    if (!mem.eql(u8, word(cmdline, "werewolf.channel=") orelse "", channel) or
        !mem.eql(u8, word(cmdline, "werewolf.index=") orelse "", want))
        return why.refuse("the running boot is not the candidate: {s}", .{cmdline});
}

fn protected(
    gpa: Allocator,
    report: json.Value,
    required: []const []const u8,
    why: *host.check.Why,
) !void {
    const checks = try host.evidence.results(gpa, report);
    if (host.evidence.passes(checks, required)) return;
    return why.refuse(
        "guest protection missing: {s}",
        .{try published.missing(gpa, checks, required)},
    );
}

/// word is the value of the command line word that starts with key.
fn word(cmdline: []const u8, key: []const u8) ?[]const u8 {
    var words = mem.tokenizeAny(u8, cmdline, " \n");
    while (words.next()) |w| if (mem.cutPrefix(u8, w, key)) |v| return v;
    return null;
}

/// gates is the evidence `release export-protected` reads, for the
/// candidate boot.json's descriptor: every gate, passed.
fn gates(
    gpa: Allocator,
    descriptor: []const u8,
    arch: []const u8,
    provider: []const u8,
) ![]const u8 {
    var checks: std.ArrayList(u8) = .empty;
    for (candidate_gates ++ update_gates, 0..) |name, i|
        try checks.print(gpa, "{s}\n    \"{s}\": true", .{ if (i > 0) "," else "", name });
    return gpa.print(
        "{{\n  \"format\": \"werewolf-boot-gates/1\",\n  \"descriptor\": \"{s}\",\n" ++
            "  \"arch\": \"{s}\",\n  \"provider\": \"{s}\",\n  \"checks\": {{{s}\n  }}\n}}\n",
        .{ descriptor, arch, provider, checks.items },
    );
}

fn exists(io: Io, path: []const u8) bool {
    Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

const testing = std.testing;
const source_revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const channel_id = "abababababababababababababababababababababababababababababababab";

test "the update evidence must pass for this target and source revision" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const good =
        \\{"format":"werewolf-update-evidence/1","provider":"qemu","arch":"x86_64","passed":true,"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\ "checks":{"ab_upgrade":true,"operator_rollback":true,"unhealthy_fallback":true,"retirement_cuts":true}}
    ;
    var why: host.check.Why = .{};
    const value = try json.parseFromSliceLeaky(json.Value, gpa, good, .{});
    try updated(value, "qemu", "x86_64", "playground", source_revision, &why);
    try testing.expectError(
        error.Refused,
        updated(value, "qemu", "x86_64", "postdoc-server", source_revision, &why),
    );
    var app = try json.parseFromSliceLeaky(json.Value, gpa, good, .{});
    try app.object.put(gpa, "form", .{ .string = "postdoc-server" });
    try updated(app, "qemu", "x86_64", "postdoc-server", source_revision, &why);
    try testing.expectError(
        error.Refused,
        updated(value, "lima", "x86_64", "playground", source_revision, &why),
    );
    for ([_][2][]const u8{
        .{ "\"passed\":true", "\"passed\":false" },
        .{ "\"retirement_cuts\":true", "\"retirement_cuts\":false" },
        .{ "update-evidence/1", "update-evidence/0" },
        .{ "\"commit\":\"" ++ source_revision ++ "\"", "\"commit\":\"wrong-revision\"" },
        .{
            "\"commit\":\"" ++ source_revision ++ "\"",
            "\"missing_commit\":\"" ++ source_revision ++ "\"",
        },
    }) |change| {
        const bad = try mem.replaceOwned(u8, gpa, good, change[0], change[1]);
        try testing.expectError(
            error.Refused,
            updated(
                try json.parseFromSliceLeaky(json.Value, gpa, bad, .{}),
                "qemu",
                "x86_64",
                "playground",
                source_revision,
                &why,
            ),
        );
    }
}

test "a boot counts once committed, protected, and the candidate's own" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const required = (try host.evidence.load(gpa, form)).ssh;
    var checks: std.ArrayList(u8) = .empty;
    for (required, 0..) |id, i|
        try checks.print(
            gpa,
            "{s}{{\"id\":\"{s}\",\"result\":\"pass\"}}",
            .{ if (i > 0) "," else "", id },
        );
    const report = try gpa.print("{{\"checks\":[{s}]}}", .{checks.items});
    const boot = "12345678-1234-1234-1234-123456789abc";
    const cmdline = "console=ttyS0 werewolf.channel=" ++ channel_id ++ " werewolf.index=7 ro";
    var why: host.check.Why = .{};
    const good = try gpa.print(
        "{s}\nBOOT-ID {s}\nCMDLINE {s}\nCOMMITTED yes\n",
        .{ report, boot, cmdline },
    );
    try testing.expectEqualStrings(
        boot,
        (try sshBoot(gpa, good, required, channel_id, 7, &why)).?.boot_id,
    );
    const trial = try gpa.print(
        "{s}\nBOOT-ID {s}\nCMDLINE {s}\nCOMMITTED \n",
        .{ report, boot, cmdline },
    );
    try testing.expectEqual(null, try sshBoot(gpa, trial, required, channel_id, 7, &why));
    try testing.expectError(error.Refused, sshBoot(gpa, good, required, channel_id, 8, &why));
    try testing.expectError(
        error.Refused,
        sshBoot(gpa, good, required, "cd" ++ channel_id[2..], 7, &why),
    );
    const passed = try gpa.print("\"{s}\",\"result\":\"pass\"", .{required[0]});
    const skipped = try gpa.print("\"{s}\",\"result\":\"skip\"", .{required[0]});
    const weak = try mem.replaceOwned(u8, gpa, good, passed, skipped);
    try testing.expectError(error.Refused, sshBoot(gpa, weak, required, channel_id, 7, &why));
    try testing.expectEqualStrings("7", word(cmdline, "werewolf.index=").?);
    try testing.expectEqual(null, word(cmdline, "werewolf.release="));
}

test "the gates are the twelve tools/release/prepare.zig requires" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const text = try gates(arena.allocator(), &@as([64]u8, @splat('d')), "aarch64", "lima");
    const value = try json.parseFromSliceLeaky(json.Value, arena.allocator(), text, .{});
    const checks = published.field(value, "checks").?;
    try testing.expectEqual(@as(usize, 12), checks.object.count());
    for (candidate_gates ++
        update_gates) |name| try testing.expect(published.isTrue(published.field(checks, name)));
}
