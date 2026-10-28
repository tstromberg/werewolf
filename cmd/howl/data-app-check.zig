//! Real CLI, SSH and PostgreSQL restore gate. Owns only randomly named
//! disposable machines and public fixture data. The fixture has no shell.
const std = @import("std");
const host = @import("host");
const howl = @import("howl.zig");
const lima = @import("lima.zig");
const Io = std.Io;
const Dir = Io.Dir;
const mem = std.mem;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "data-transfer") catch std.process.exit(1);
    howl.environ = &c.env;
    var t: Test = .{ .c = &c };
    const result = t.run();
    t.cleanup();
    c.finish(result);
}

const Test = struct {
    c: *host.Check,
    binary: []const u8 = "",
    form: []const u8 = "",
    key: []const u8 = "",
    names: std.ArrayList([]const u8) = .empty,
    on: howl.Platform = if (@import("builtin").os.tag == .macos) .lima else .qemu,

    fn run(t: *Test) !void {
        const c = t.c;
        if (c.args.len != 3) return c.fail("usage: check-data-transfer HOWL CONTROLLER", .{});
        t.binary = try c.absolute(c.args[1]);
        var nonce: [6]u8 = undefined;
        try c.io.randomSecure(&nonce);
        const suffix = std.fmt.bytesToHex(nonce, .lower);
        try c.setWork(try c.gpa.print("build/check/data-transfer/{s}", .{suffix}));
        try Dir.cwd().setFilePermissions(c.io, c.work, .fromMode(0o700), .{});
        try c.env.put("XDG_DATA_HOME", try c.path("credentials"));
        try c.env.put("SSH_AUTH_SOCK", "");
        t.key = try c.path("owner.key");
        _ = try c.must(
            &.{
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "data-transfer-fixture",
                "-f",
                t.key,
            },
            "identity",
            .{},
        );
        t.form = try c.path(try c.gpa.print("transfer-fixture-{s}", .{suffix}));
        try Dir.cwd().createDirPath(
            c.io,
            try c.gpa.print("{s}/rootfs/usr/lib/werewolf", .{t.form}),
        );
        try Dir.cwd().createDirPath(
            c.io,
            try c.gpa.print("{s}/rootfs/usr/share/werewolf", .{t.form}),
        );
        try Dir.cwd().createDirPath(c.io, try c.gpa.print("{s}/rootfs/etc/sv/posture", .{t.form}));
        try Dir.cwd().copyFile(
            c.args[2],
            .cwd(),
            try c.gpa.print("{s}/rootfs/usr/lib/werewolf/transfer-control", .{t.form}),
            c.io,
            .{},
        );
        try Dir.cwd().symLink(
            c.io,
            "/usr/lib/werewolf/transfer-control",
            try c.gpa.print("{s}/rootfs/etc/sv/posture/run", .{t.form}),
            .{},
        );
        try Dir.cwd().writeFile(
            c.io,
            .{
                .sub_path = try c.gpa.print("{s}/rootfs/usr/share/werewolf/test-image", .{t.form}),
                .data = "private data-transfer fixture\n",
            },
        );
        try Dir.cwd().writeFile(c.io, .{
            .sub_path = try c.gpa.print("{s}/form.yaml", .{t.form}),
            .data = "base: postgresql\nwith: [data-export]\nupdates: off\npackages: " ++
                "[postgresql-client~18]\n" ++
                "sshd:\n  pubkey-accepted-algorithms: ssh-ed25519\n" ++
                "weaknesses:\n  network-no-login: fixed native export in a disposable VM\n" ++
                "  kernel-write-xor-execute: the PostgreSQL form permits JIT\n" ++
                "  network-ssh-security-keys: disposable fixture identity; real hardware is a " ++
                "separate gate\n" ++
                "services:\n  postgres:\n" ++
                "    exec: /usr/bin/postgres -D /data/svc/postgres/data -c listen_addresses= -c " ++
                "unix_socket_directories=/run/svc/postgres\n" ++
                "    before: /usr/lib/werewolf/pg-init\n    user: postgres\n" ++
                "    pledge: stdio rpath wpath proc shm unix listen connect\n" ++
                "    run: [/usr/bin/initdb, /usr/lib/werewolf/sh-shim, /usr/bin/locale]\n" ++
                "    share: shared\n    config: transfer-role /run/config/transfer-role\n",
        });
        const source_config = try t.configuration("source");
        const target_config = try t.configuration("target");
        // Keep Unix socket paths below the limit in long runner checkouts.
        const source = try t.own(try c.gpa.print("dts{s}", .{suffix}));
        try t.create(source, source_config, "source-create");
        try t.pin(source);
        const denied_key = try c.path("unauthorized.key");
        _ = try c.must(
            &.{ "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", denied_key },
            "unauthorized-identity",
            .{},
        );
        defer Dir.cwd().deleteFile(c.io, denied_key) catch {};
        {
            const owner_key = t.key;
            t.key = denied_key;
            defer t.key = owner_key;
            try t.ssh(source, &.{"export-v1"}, "unauthorized-key-refused", false);
        }
        try t.ssh(source, &.{"id"}, "shell-command-refused", false);
        try t.sshRequest(source, .pty, &.{"id"}, "pty-refused", false);
        try t.sshRequest(source, .forward, &.{}, "forwarding-refused", false);
        try t.sshRequest(source, .subsystem, &.{"sftp"}, "sftp-refused", false);
        try t.ssh(source, &.{ "service-down-v1", "sshd" }, "system-control-refused", false);
        try t.ssh(source, &.{ "export-v1", "../postgres" }, "scope-path-refused", false);
        const pin_path = try c.gpa.print("{s}/known_hosts", .{try howl.machineDir(c.gpa, source)});
        const original_pin = try Dir.cwd().readFileAlloc(c.io, pin_path, c.gpa, .limited(4096));
        const wrong_key = try Dir.cwd().readFileAlloc(
            c.io,
            try c.gpa.print("{s}.pub", .{t.key}),
            c.gpa,
            .limited(4096),
        );
        try Dir.cwd().writeFile(
            c.io,
            .{ .sub_path = pin_path, .data = try c.gpa.print("{s} {s}", .{ source, wrong_key }) },
        );
        try t.exportData(source, try c.path("wrong-pin.tar.zst"), null, false, "wrong-pin-refused");
        try Dir.cwd().writeFile(c.io, .{ .sub_path = pin_path, .data = original_pin });
        const refused = try c.path("live-refused.tar.zst");
        try t.exportData(source, refused, null, false, "live-refused");
        if (Dir.cwd().access(c.io, refused, .{})) |_|
            return error.PublishedLiveCapture
        else |err| if (err != error.FileNotFound)
            return err;
        try t.ssh(source, &.{ "service-down-v1", "postgres" }, "manual-down", true);
        for ([_]bool{ true, false }) |online| {
            if (!online) try t.poweroff(source);
            const prefix = if (online) "online" else "offline";
            const full = try c.path(try c.gpa.print("{s}-full.tar.zst", .{prefix}));
            const selected = try c.path(try c.gpa.print("{s}-postgres.tar.zst", .{prefix}));
            try t.exportData(
                source,
                full,
                null,
                true,
                try c.gpa.print("{s}-full-export", .{prefix}),
            );
            try t.exportData(
                source,
                selected,
                "postgres",
                true,
                try c.gpa.print("{s}-service-export", .{prefix}),
            );
            for (0..3) |which| {
                const name = try t.own(try c.gpa.print(
                    "dt{s}{d}{s}",
                    .{ if (online) "n" else "f", which, suffix },
                ));
                var args: std.ArrayList([]const u8) = .empty;
                try args.appendSlice(
                    c.gpa,
                    &.{
                        t.binary,
                        "import",
                        name,
                        if (which == 1) selected else full,
                        "--on",
                        @tagName(t.on),
                        "--config",
                        target_config,
                    },
                );
                if (which == 2) try args.appendSlice(c.gpa, &.{ "--service", "postgres" });
                _ = try c.must(
                    args.items,
                    try c.gpa.print("{s}-{d}-import", .{ prefix, which }),
                    .{},
                );
                if (try t.running(name)) return error.ImportStartedTarget;
                const before_start = try c.path(try c.gpa.print(
                    "{s}-{d}-before-start.tar.zst",
                    .{ prefix, which },
                ));
                try t.exportData(
                    name,
                    before_start,
                    if (which == 0) null else "postgres",
                    true,
                    try c.gpa.print("{s}-{d}-verify-bytes", .{ prefix, which }),
                );
                if (!mem.eql(
                    u8,
                    &try t.plainHash(if (which == 0) full else selected),
                    &try t.plainHash(before_start),
                )) return error.RestoredBytes;
                _ = try c.must(
                    &.{ t.binary, "start", name },
                    try c.gpa.print("{s}-{d}-start", .{ prefix, which }),
                    .{},
                );
                _ = try t.consoleUntil(name, "transfer-fixture: ready", 180);
                try t.pin(name);
                try t.ssh(
                    name,
                    &.{ "service-down-v1", "postgres" },
                    try c.gpa.print("{s}-{d}-down", .{ prefix, which }),
                    true,
                );
                try t.poweroff(name);
                c.say(
                    "pass: {s} case {d}, pre-start bytes and restored PostgreSQL queries",
                    .{ prefix, which },
                );
            }
            if (online) {
                try t.ssh(source, &.{ "service-up-v1", "postgres" }, "manual-up", true);
                try t.exportData(
                    source,
                    try c.path("restarted-refused.tar.zst"),
                    null,
                    false,
                    "restarted-writer-refused",
                );
                try t.ssh(source, &.{ "service-down-v1", "postgres" }, "manual-down-again", true);
            }
        }
        c.say(
            "pass: real PostgreSQL full/service imports, both source states, shell-free SSH and " ++
                "stopped destinations",
            .{},
        );
    }

    fn configuration(t: *Test, role: []const u8) ![]const u8 {
        const c = t.c;
        const path = try c.path(try c.gpa.print("config-{s}", .{role}));
        try Dir.cwd().createDir(c.io, path, .fromMode(0o700));
        try Dir.cwd().copyFile(
            try c.gpa.print("{s}.pub", .{t.key}),
            .cwd(),
            try c.gpa.print("{s}/authorized_keys", .{path}),
            c.io,
            .{},
        );
        try Dir.cwd().writeFile(
            c.io,
            .{ .sub_path = try c.gpa.print("{s}/transfer-role", .{path}), .data = role },
        );
        return path;
    }

    fn own(t: *Test, name: []const u8) ![]const u8 {
        const c = t.c;
        if (t.on == .lima and try lima.exists(c.io, c.gpa, name)) return error.ExistingFixtureName;
        try Dir.cwd().createDir(c.io, try howl.machineDir(c.gpa, name), .fromMode(0o700));
        try t.names.append(c.gpa, name);
        return name;
    }

    fn create(t: *Test, name: []const u8, config: []const u8, label: []const u8) !void {
        const c = t.c;
        _ = try c.must(
            &.{
                t.binary,
                "create",
                name,
                "--with",
                t.form,
                "--on",
                @tagName(t.on),
                "--build",
                "--config",
                config,
                "--add-current-user",
                "no",
                "--yes",
            },
            label,
            .{ .timeout = .fromSeconds(1800) },
        );
        // A successful startup must also preserve the real database invariants.
        _ = try t.consoleUntil(name, "transfer-fixture: ready", 180);
        const console = try t.consoleUntil(name, "posture: fail=", 90);
        if (mem.find(u8, console, "invalid user") != null) return error.LimaShellProbe;
    }

    fn instance(t: *Test, name: []const u8) ![]const u8 {
        return if (t.on == .lima)
            try lima.dir(t.c.io, t.c.gpa, name) orelse error.MissingLimaInstance
        else
            try howl.machineDir(t.c.gpa, name);
    }

    fn consoleUntil(t: *Test, name: []const u8, needle: []const u8, seconds: usize) ![]const u8 {
        const c = t.c;
        const file = try c.gpa.print(
            "{s}/{s}",
            .{ try t.instance(name), if (t.on == .lima) "serial.log" else "console.log" },
        );
        for (0..seconds) |_| {
            const raw = Dir.cwd().readFileAlloc(c.io, file, c.gpa, .limited(4 << 20)) catch "";
            const text = try host.qemu.clean(c.gpa, raw);
            // A serial read can end halfway through a marker or host key.
            if (mem.find(u8, text, needle)) |start| {
                if (mem.findScalarPos(u8, text, start + needle.len, '\n') != null) return text;
            }
            if (mem.find(u8, text, "transfer-fixture: Sql") != null or
                mem.find(u8, text, "transfer-fixture: Rows") != null)
                return c.fail("database fixture failed; see {s}", .{file});
            try c.io.sleep(.fromSeconds(1), .awake);
        }
        const text = Dir.cwd().readFileAlloc(c.io, file, c.gpa, .limited(4 << 20)) catch "";
        return c.fail("missing {s}; see {s}\n{s}", .{
            needle, file, text[text.len -| (16 << 10)..],
        });
    }

    fn pin(t: *Test, name: []const u8) !void {
        const c = t.c;
        const text = try t.consoleUntil(name, "transfer-host-key: ", 60);
        const start = mem.find(u8, text, "transfer-host-key: ").? + "transfer-host-key: ".len;
        const end = mem.findScalarPos(u8, text, start, '\n') orelse return error.MissingHostKey;
        const key = mem.trim(u8, text[start..end], "\r");
        if (!mem.startsWith(u8, key, "ssh-ed25519 ")) return error.HostKey;
        try Dir.cwd().writeFile(
            c.io,
            .{
                .sub_path = try c.gpa.print("{s}/known_hosts", .{try howl.machineDir(c.gpa, name)}),
                .data = try c.gpa.print("{s} {s}\n", .{ name, key }),
                .flags = .{ .permissions = .fromMode(0o600) },
            },
        );
    }

    fn ssh(
        t: *Test,
        name: []const u8,
        command: []const []const u8,
        label: []const u8,
        success: bool,
    ) !void {
        return t.sshRequest(name, .command, command, label, success);
    }

    fn sshRequest(
        t: *Test,
        name: []const u8,
        kind: enum { command, pty, forward, subsystem },
        command: []const []const u8,
        label: []const u8,
        success: bool,
    ) !void {
        const c = t.c;
        const at = try howl.machineDir(c.gpa, name);
        const port = if (t.on == .lima)
            lima.sshPort(c.io, c.gpa, name) orelse return error.SshPort
        else
            @import("qemu.zig").record(c.io, c.gpa, at, "ssh") orelse return error.SshPort;
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(
            c.gpa,
            &.{
                "ssh",
                "-F",
                "/dev/null",
                "-S",
                "none",
                "-T",
                "-a",
                "-p",
                port,
                "-i",
                t.key,
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                try c.gpa.print("HostKeyAlias={s}", .{name}),
                "-o",
                try c.gpa.print("UserKnownHostsFile={s}/known_hosts", .{at}),
            },
        );
        switch (kind) {
            .command => {},
            .pty => try argv.append(c.gpa, "-tt"),
            .forward => try argv.appendSlice(c.gpa, &.{ "-W", "127.0.0.1:22" }),
            .subsystem => try argv.append(c.gpa, "-s"),
        }
        try argv.append(c.gpa, "root@127.0.0.1");
        try argv.appendSlice(c.gpa, command);
        const r = try c.run(argv.items, label, .{ .timeout = .fromSeconds(100) });
        if (r.ok() != success) return c.fail(
            "{s}: unexpected SSH result: {s}",
            .{ label, r.stderr },
        );
        if (mem.eql(u8, label, "shell-command-refused") and
            mem.find(u8, r.stderr, "TransferInvocation") == null) return error.CommandNotRefused;
        if ((mem.eql(u8, label, "system-control-refused") or
            mem.eql(u8, label, "scope-path-refused")) and
            mem.find(u8, r.stderr, "TransferService") == null) return error.ScopeNotRefused;
        if (mem.eql(u8, label, "unauthorized-key-refused") and
            mem.find(
                u8,
                r.stderr,
                "Permission denied",
            ) == null) return error.AuthenticationNotRefused;
        if (kind == .pty and
            mem.find(
                u8,
                r.stderr,
                "PTY allocation request failed",
            ) == null) return error.TerminalNotRefused;
        if (kind == .forward and
            mem.find(
                u8,
                r.stderr,
                "administratively prohibited",
            ) == null) return error.ForwardingNotRefused;
        if (kind == .subsystem and mem.find(u8, r.stderr, "subsystem request failed") == null and
            mem.find(u8, r.stderr, "TransferInvocation") == null) return error.SubsystemNotRefused;
    }

    fn exportData(
        t: *Test,
        name: []const u8,
        archive: []const u8,
        service: ?[]const u8,
        success: bool,
        label: []const u8,
    ) !void {
        const c = t.c;
        var args: std.ArrayList([]const u8) = .empty;
        try args.appendSlice(
            c.gpa,
            &.{ t.binary, "export", name, "--identity", t.key, "--output", archive },
        );
        if (service) |s| try args.appendSlice(c.gpa, &.{ "--service", s });
        if (mem.eql(u8, label, "online-service-export")) {
            const port = if (t.on == .lima)
                lima.sshPort(c.io, c.gpa, name) orelse return error.SshPort
            else
                @import("qemu.zig").record(
                    c.io,
                    c.gpa,
                    try howl.machineDir(c.gpa, name),
                    "ssh",
                ) orelse return error.SshPort;
            try args.appendSlice(c.gpa, &.{ "--host", "127.0.0.1", "--port", port });
        }
        const r = try c.run(args.items, label, .{ .timeout = .fromSeconds(900) });
        if (r.ok() != success) return c.fail("{s}: export result: {s}", .{ label, r.stderr });
        if ((mem.eql(u8, label, "live-refused") or
            mem.eql(u8, label, "restarted-writer-refused")) and
            mem.find(
                u8,
                r.stderr,
                "TransferWritersRunning",
            ) == null) return c.fail("{s}: writers were not checked: {s}", .{ label, r.stderr });
        if (mem.eql(u8, label, "wrong-pin-refused") and
            mem.find(u8, r.stderr, "Host key verification failed") == null)
            return error.HostIdentityNotRefused;
        if (!success) {
            if (Dir.cwd().access(c.io, archive, .{})) |_|
                return error.PublishedFailedCapture
            else |err| if (err != error.FileNotFound)
                return err;
        }
    }

    fn running(t: *Test, name: []const u8) !bool {
        return if (t.on == .lima)
            lima.running(t.c.io, t.c.gpa, name)
        else
            @import("qemu.zig").running(
                t.c.io,
                t.c.gpa,
                try howl.machineDir(t.c.gpa, name),
            ) != null;
    }

    fn plainHash(t: *Test, path: []const u8) ![32]u8 {
        const io = t.c.io;
        var child = try std.process.spawn(
            io,
            .{
                .argv = &.{ "zstd", "-d", "-q", "-c", "--", path },
                .stdin = .ignore,
                .stdout = .pipe,
                .stderr = .ignore,
            },
        );
        defer child.kill(io);
        const pipe = child.stdout.?;
        child.stdout = null;
        defer pipe.close(io);
        var hash: std.crypto.hash.sha2.Sha256 = .init(.{});
        var buffer: [64 << 10]u8 = undefined;
        var total: u64 = 0;
        while (true) {
            const n = pipe.readStreaming(io, &.{&buffer}) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
            total += n;
            if (total > 1 << 30) return error.FixtureLimit;
            hash.update(buffer[0..n]);
        }
        if (!(try child.wait(io)).success()) return error.FixtureCompression;
        return hash.finalResult();
    }

    fn poweroff(t: *Test, name: []const u8) !void {
        const c = t.c;
        const at = try t.instance(name);
        if (t.on == .lima)
            _ = try host.qmp.command(
                c.io,
                c.gpa,
                try c.gpa.print("{s}/qmp.sock", .{at}),
                "system_powerdown",
                null,
            )
        else {
            const address = try Io.net.UnixAddress.init(try c.gpa.print("{s}/monitor.sock", .{at}));
            const stream = try address.connect(c.io);
            defer stream.close(c.io);
            const f: Io.File = .{
                .handle = stream.socket.handle,
                .flags = .{ .nonblocking = false },
            };
            try f.writeStreamingAll(c.io, "system_powerdown\n");
        }
        for (0..120) |_| {
            // Lima can briefly lose its runtime PID before its hostagent has
            // recorded Stopped. Uncertain state is still busy, never permission
            // for detached storage access.
            const busy = t.running(name) catch |err| switch (err) {
                error.LimaUnknownState => true,
                else => return err,
            };
            if (!busy) return;
            try c.io.sleep(.fromSeconds(1), .awake);
        }
        return error.PoweroffTimeout;
    }

    fn cleanup(t: *Test) void {
        const c = t.c;
        for (t.names.items) |name| {
            if (t.instance(name)) |at| {
                const file = c.gpa.print(
                    "{s}/{s}",
                    .{ at, if (t.on == .lima) "serial.log" else "console.log" },
                ) catch continue;
                const kept = c.path(c.gpa.print(
                    "{s}-console.log",
                    .{name},
                ) catch continue) catch continue;
                Dir.cwd().copyFile(file, .cwd(), kept, c.io, .{}) catch {};
                // The catalog uploader collects architecture-specific check
                // logs; keep the console before delete removes the machine.
                const catalog = c.gpa.print("build/{s}/check/data-transfer-{s}.log", .{
                    @tagName(@import("builtin").cpu.arch), name,
                }) catch continue;
                Dir.cwd().createDirPath(c.io, std.fs.path.dirname(catalog).?) catch {};
                Dir.cwd().copyFile(file, .cwd(), catalog, c.io, .{}) catch {};
            } else |_| {}
            _ = c.run(
                &.{ t.binary, "delete", name, "--on", @tagName(t.on) },
                "cleanup",
                .{ .timeout = .fromSeconds(120) },
            ) catch {};
        }
        if (t.key.len != 0) Dir.cwd().deleteFile(c.io, t.key) catch {};
        if (c.work.len > 1) Dir.cwd().deleteTree(c.io, c.path("credentials") catch return) catch {};
    }
};
