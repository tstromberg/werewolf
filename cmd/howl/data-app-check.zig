//! Real CLI, SSH and PostgreSQL restore gate. Owns only randomly named
//! disposable machines and public fixture data. The fixture has no shell.
const std = @import("std");
const host = @import("host");
const howl = @import("howl.zig");
const cloud = @import("data-cloud.zig");
const lima = @import("lima.zig");
const data = @import("data-transfer");
const Io = std.Io;
const Dir = Io.Dir;
const mem = std.mem;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "data-transfer") catch std.process.exit(1);
    howl.environ = &c.env;
    var t: Test = .{ .c = &c };
    var result: anyerror!void = if (c.env.get("DATA_TRANSFER_RESUME")) |nonce| t.resumeCloud(nonce) else t.run();
    const retain = if (result) |_| false else |_| mem.eql(u8, c.env.get("DATA_TRANSFER_KEEP_FAILED") orelse "", "1");
    if (retain) c.say("retained disposable fixtures for diagnosis; credentials: {s}; delete these VMs and keys after recovery", .{c.work}) else t.cleanup() catch |err| {
        c.say("fixture cleanup failed; retained private credentials in {s}", .{c.work});
        if (result) |_| {
            result = err;
        } else |_| {}
    };
    c.finish(result);
}

const Test = struct {
    c: *host.Check,
    binary: []const u8 = "",
    form: []const u8 = "",
    key: []const u8 = "",
    names: std.ArrayList([]const u8) = .empty,
    boot_markers: std.StringHashMapUnmanaged([]const u8) = .empty,
    disks: std.ArrayList(struct { context: @import("data-cloud.zig").Context, id: []const u8 }) = .empty,
    ssh_only: bool = false,
    on: howl.Platform = switch (@import("builtin").os.tag) {
        .macos => .lima,
        .freebsd => .bhyve,
        else => .qemu,
    },

    fn run(t: *Test) !void {
        const c = t.c;
        if (c.args.len != 3) return c.fail("usage: check-data-transfer HOWL CONTROLLER", .{});
        if (c.env.get("DATA_TRANSFER_PROVIDER")) |provider|
            t.on = std.meta.stringToEnum(howl.Platform, provider) orelse return error.TransferTestProvider;
        if (t.on != .qemu and t.on != .lima and t.on != .bhyve and t.on != .firecracker and !cloud.supported(t.on))
            return error.TransferTestProvider;
        if (c.env.get("DATA_TRANSFER_PATH")) |path| {
            if (!mem.eql(u8, path, "ssh") and !mem.eql(u8, path, "all")) return error.TransferTestPath;
            t.ssh_only = mem.eql(u8, path, "ssh");
        }
        t.binary = try c.absolute(c.args[1]);
        var nonce: [6]u8 = undefined;
        try c.io.randomSecure(&nonce);
        const suffix = std.fmt.bytesToHex(nonce, .lower);
        try c.setWork(try c.gpa.print("build/check/data-transfer/{s}", .{suffix}));
        try Dir.cwd().setFilePermissions(c.io, c.work, .fromMode(0o700), .{});
        try c.env.put("XDG_DATA_HOME", try c.path("credentials"));
        try c.env.put("SSH_AUTH_SOCK", "");
        t.key = try c.path("owner.key");
        _ = try c.must(&.{ "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "data-transfer-fixture", "-f", t.key }, "identity", .{});
        t.form = try c.path(try c.gpa.print("transfer-fixture-{s}", .{suffix}));
        try Dir.cwd().createDirPath(c.io, try c.gpa.print("{s}/rootfs/usr/lib/werewolf", .{t.form}));
        try Dir.cwd().createDirPath(c.io, try c.gpa.print("{s}/rootfs/usr/share/werewolf", .{t.form}));
        try Dir.cwd().createDirPath(c.io, try c.gpa.print("{s}/rootfs/etc/sv/posture", .{t.form}));
        try Dir.cwd().copyFile(c.args[2], .cwd(), try c.gpa.print("{s}/rootfs/usr/lib/werewolf/transfer-control", .{t.form}), c.io, .{});
        try Dir.cwd().symLink(c.io, "/usr/lib/werewolf/transfer-control", try c.gpa.print("{s}/rootfs/etc/sv/posture/run", .{t.form}), .{});
        try Dir.cwd().writeFile(c.io, .{ .sub_path = try c.gpa.print("{s}/rootfs/usr/share/werewolf/test-image", .{t.form}), .data = "private data-transfer fixture\n" });
        try Dir.cwd().writeFile(c.io, .{
            .sub_path = try c.gpa.print("{s}/form.yaml", .{t.form}),
            .data = "base: postgresql\nwith: [data-export]\nupdates: off\npackages: [postgresql-client~18]\n" ++
                "sshd:\n  pubkey-accepted-algorithms: ssh-ed25519\n" ++
                "weaknesses:\n  network-no-login: fixed native export in a disposable VM\n" ++
                "  kernel-write-xor-execute: the PostgreSQL form permits JIT\n" ++
                "  network-ssh-security-keys: disposable fixture identity; real hardware is a separate gate\n" ++
                "services:\n  postgres:\n" ++
                "    exec: /usr/bin/postgres -D /data/svc/postgres/data -c listen_addresses= -c unix_socket_directories=/run/svc/postgres\n" ++
                "    before: /usr/lib/werewolf/transfer-control prepare-postgres\n    user: postgres\n" ++
                "    pledge: stdio rpath wpath proc shm unix listen connect\n" ++
                "    run: [/usr/lib/werewolf/pg-init, /usr/bin/initdb, /usr/lib/werewolf/sh-shim, /usr/bin/locale]\n" ++
                "    share: shared\n    config: transfer-role /run/config/transfer-role\n",
        });
        const source_config = try t.configuration("source");
        if (t.on == .firecracker) {
            try Dir.cwd().writeFile(c.io, .{ .sub_path = try c.gpa.print("{s}/rootfs/usr/share/werewolf/transfer-stop-fixture", .{t.form}), .data = "private shutdown fixture\n" });
            const fixture = try Dir.cwd().openFile(c.io, try c.gpa.print("{s}/form.yaml", .{t.form}), .{ .mode = .read_write });
            defer fixture.close(c.io);
            try fixture.writePositionalAll(c.io, "  transfer-stop:\n    exec: /usr/lib/werewolf/transfer-control park\n    user: transfer-stop\n    pledge: stdio\n", try fixture.length(c.io));
        }
        const target_config = try t.configuration("target");
        const source = try t.own(try c.gpa.print("transfer-src-{s}", .{suffix}));
        try t.create(source, source_config, "source-create");
        try t.pin(source);
        const denied_key = try c.path("unauthorized.key");
        _ = try c.must(&.{ "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", denied_key }, "unauthorized-identity", .{});
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
        const wrong_key = try Dir.cwd().readFileAlloc(c.io, try c.gpa.print("{s}.pub", .{t.key}), c.gpa, .limited(4096));
        try Dir.cwd().writeFile(c.io, .{ .sub_path = pin_path, .data = try c.gpa.print("{s} {s}", .{ source, wrong_key }) });
        try t.exportData(source, try c.path("wrong-pin.tar.zst"), null, false, "wrong-pin-refused");
        try Dir.cwd().writeFile(c.io, .{ .sub_path = pin_path, .data = original_pin });
        const refused = try c.path("live-refused.tar.zst");
        try t.exportData(source, refused, null, false, "live-refused");
        if (Dir.cwd().access(c.io, refused, .{})) |_| return error.PublishedLiveCapture else |err| if (err != error.FileNotFound) return err;
        try t.stopApplications(source, "manual-down");
        const cloud_provider = cloud.supported(t.on);
        for ([_]bool{ true, false }) |online| {
            if (!online and !cloud_provider) try t.poweroff(source);
            const prefix = if (online) "online" else "offline";
            const full = try c.path(try c.gpa.print("{s}-full.tar.zst", .{prefix}));
            const selected = try c.path(try c.gpa.print("{s}-postgres.tar.zst", .{prefix}));
            if (online or !cloud_provider) {
                try t.exportData(source, full, null, true, try c.gpa.print("{s}-full-export", .{prefix}));
                try t.exportData(source, selected, "postgres", true, try c.gpa.print("{s}-service-export", .{prefix}));
            }
            if (online) {
                // SSH-only runs no longer need the captured cloud source.
                // Deallocated Azure VMs still consume regional core quota.
                if (cloud_provider) {
                    try t.poweroff(source);
                    if (!t.ssh_only) {
                        try t.exportData(source, try c.path("offline-full.tar.zst"), null, true, "offline-full-export");
                        try t.exportData(source, try c.path("offline-postgres.tar.zst"), "postgres", true, "offline-service-export");
                    }
                    try t.removeCompleted(source, "captured-source-delete");
                }
                try t.onlineImports(full, selected, &suffix);
            }
            if (t.ssh_only) {
                c.say("pass: {t} SSH full/service import and export; disk path was not requested", .{t.on});
                return;
            }
            try t.diskImports(full, selected, &suffix, online, target_config);
            if (online and !cloud_provider) {
                try t.ssh(source, &.{ "service-up-v1", "postgres" }, "manual-up", true);
                try t.exportData(source, try c.path("restarted-refused.tar.zst"), null, false, "restarted-writer-refused");
                try t.stopApplications(source, "manual-down-again");
            }
        }
        c.say("pass: real PostgreSQL full/service imports, both source states, online SSH and offline disk destinations", .{});
    }

    fn diskImports(t: *Test, full: []const u8, selected: []const u8, suffix: []const u8, online: bool, target_config: []const u8) !void {
        const c = t.c;
        if (c.env.get("DATA_TRANSFER_CASE")) |one| {
            var valid = false;
            for ([_][]const u8{ "online-0", "online-1", "online-2", "offline-0", "offline-1", "offline-2" }) |name|
                if (mem.eql(u8, one, name)) {
                    valid = true;
                };
            if (!valid) return error.TransferTestArguments;
        }
        const cloud_provider = cloud.supported(t.on);
        const prefix = if (online) "online" else "offline";
        for (0..3) |which| {
            if (c.env.get("DATA_TRANSFER_CASE")) |selected_case|
                if (!mem.eql(u8, selected_case, try c.gpa.print("{s}-{d}", .{ prefix, which }))) continue;
            const name = try t.own(try c.gpa.print("transfer-{s}-{d}-{s}", .{ prefix, which, suffix[0..8] }));
            var args: std.ArrayList([]const u8) = .empty;
            const existing = t.on == .firecracker;
            if (existing) {
                try t.create(name, try t.configuration("empty"), try c.gpa.print("{s}-{d}-empty", .{ prefix, which }));
                try t.pin(name);
                try t.stopApplications(name, try c.gpa.print("{s}-{d}-empty-down", .{ prefix, which }));
                try t.poweroff(name);
            }
            try args.appendSlice(c.gpa, &.{ t.binary, "import", name, if (which == 1) selected else full, "--on", @tagName(t.on) });
            if (!existing) try args.appendSlice(c.gpa, &.{ "--config", target_config });
            if (cloud_provider) if (c.env.get("DATA_TRANSFER_SIZE")) |size| try args.appendSlice(c.gpa, &.{ "--size", size });
            if (which == 2) try args.appendSlice(c.gpa, &.{ "--service", "postgres" });
            _ = try c.must(args.items, try c.gpa.print("{s}-{d}-import", .{ prefix, which }), .{});
            try t.rememberDisk(name);
            if (try t.running(name)) return error.ImportStartedTarget;
            const before_start = try c.path(try c.gpa.print("{s}-{d}-before-start.tar.zst", .{ prefix, which }));
            try t.exportData(name, before_start, if (which == 0) null else "postgres", true, try c.gpa.print("{s}-{d}-verify-bytes", .{ prefix, which }));
            if (!mem.eql(u8, &try t.plainHash(if (which == 0) full else selected), &try t.plainHash(before_start))) return error.RestoredBytes;
            try t.startMachine(name, try c.gpa.print("{s}-{d}-start", .{ prefix, which }));
            _ = try t.consoleUntil(name, "transfer-fixture: ready", 180);
            if (!cloud_provider) {
                try t.pin(name);
                try t.stopApplications(name, try c.gpa.print("{s}-{d}-down", .{ prefix, which }));
            }
            try t.poweroff(name);
            if (cloud_provider and online and which == 0) {
                const before = try t.cloudContext(name);
                var pending = try t.profile(name);
                pending.cloud_staged = true;
                try @import("data-image.zig").replaceRecord(c.io, c.gpa, try c.gpa.print("{s}/authority/profile.json", .{try howl.machineDir(c.gpa, name)}), try std.json.Stringify.valueAlloc(c.gpa, pending, .{}));
                try t.boot_markers.put(c.gpa, name, @import("azure.zig").mark(try t.cloudConsole(name)));
                try t.startMachine(name, "resume-recorded-vm-start");
                _ = try t.consoleUntil(name, "transfer-fixture: ready", 180);
                const after = try t.cloudContext(name);
                if (!mem.eql(u8, try std.json.Stringify.valueAlloc(c.gpa, before, .{}), try std.json.Stringify.valueAlloc(c.gpa, after, .{}))) return error.TransferTestIdentity;
                try t.poweroff(name);
            }
            if (cloud_provider and online and which == 0) try t.rejectHostBacking(name);
            if (cloud.supported(t.on)) try t.removeCompleted(name, try c.gpa.print("{s}-{d}-delete", .{ prefix, which }));
            c.say("pass: {s} case {d}, pre-start bytes and restored PostgreSQL queries", .{ prefix, which });
        }
    }

    // Explicitly resume this run's private disposable fixtures after diagnosing
    // a provider failure. Never discover or adopt unrelated machine names.
    fn resumeCloud(t: *Test, nonce: []const u8) !void {
        const c = t.c;
        if (nonce.len != 12 or c.args.len != 3) return error.TransferTestArguments;
        for (nonce) |ch| if (!std.ascii.isHex(ch)) return error.TransferTestArguments;
        t.on = std.meta.stringToEnum(howl.Platform, c.env.get("DATA_TRANSFER_PROVIDER") orelse "") orelse return error.TransferTestProvider;
        if (!cloud.supported(t.on)) return error.TransferTestProvider;
        t.binary = try c.absolute(c.args[1]);
        try c.setWork(try c.gpa.print("build/check/data-transfer/{s}", .{nonce}));
        try c.env.put("XDG_DATA_HOME", try c.path("credentials"));
        try c.env.put("SSH_AUTH_SOCK", "");
        t.key = try c.path("owner.key");
        try Dir.cwd().access(c.io, t.key, .{});
        t.form = try c.path(try c.gpa.print("transfer-fixture-{s}", .{nonce}));
        const source = try c.gpa.print("transfer-src-{s}", .{nonce});
        const source_file = try c.gpa.print("{s}/authority/profile.json", .{try howl.machineDir(c.gpa, source)});
        if (Dir.cwd().access(c.io, source_file, .{})) |_| {
            try t.names.append(c.gpa, source);
            if (try t.running(source)) return error.TransferStorageInUse;
            for ([_][]const u8{ "full", "postgres" }) |scope| {
                const archive = try c.path(try c.gpa.print("offline-{s}.tar.zst", .{scope}));
                if (Dir.cwd().access(c.io, archive, .{})) |_| {} else |err| {
                    if (err != error.FileNotFound) return err;
                    try t.exportData(source, archive, if (mem.eql(u8, scope, "full")) null else "postgres", true, try c.gpa.print("resume-{s}-export", .{scope}));
                }
            }
            try t.removeCompleted(source, "resume-source-delete");
        } else |err| if (err != error.FileNotFound) return err;
        const full = try c.path("online-full.tar.zst");
        const selected = try c.path("online-postgres.tar.zst");
        if (!mem.eql(u8, c.env.get("DATA_TRANSFER_RESUME_DISK_ONLY") orelse "", "1")) try t.onlineImports(full, selected, nonce);
        const config = try t.configuration("target");
        try t.diskImports(full, selected, nonce, true, config);
        try t.diskImports(try c.path("offline-full.tar.zst"), try c.path("offline-postgres.tar.zst"), nonce, false, config);
        c.say("pass: resumed cloud disk full/service imports, pre-start bytes, PostgreSQL queries and host-backing refusal", .{});
    }

    fn onlineImports(t: *Test, full: []const u8, selected: []const u8, suffix: []const u8) !void {
        const c = t.c;
        const config = try t.configuration("empty");
        const corrupt = try c.path("truncated.tar.zst");
        try Dir.cwd().writeFile(c.io, .{ .sub_path = corrupt, .data = "\x28\xb5\x2f\xfd" });
        const first = std.fmt.parseUnsigned(usize, c.env.get("DATA_TRANSFER_SSH_FROM") orelse "0", 10) catch return error.TransferTestArguments;
        if (first > 3) return error.TransferTestArguments;
        for (first..3) |which| {
            const name = try t.own(try c.gpa.print("transfer-ssh-{d}-{s}", .{ which, suffix }));
            try t.create(name, config, try c.gpa.print("ssh-{d}-create", .{which}));
            try t.pin(name);
            const scope: ?[]const u8 = if (which == 2) "postgres" else null;
            const archive = if (which == 1) selected else full;
            try t.importOnline(name, archive, scope, false, try c.gpa.print("ssh-{d}-wanted-up-refused", .{which}));
            try t.stopApplications(name, try c.gpa.print("ssh-{d}-down", .{which}));
            try t.importOnline(name, corrupt, scope, false, try c.gpa.print("ssh-{d}-truncated-refused", .{which}));
            try t.importOnline(name, archive, scope, true, try c.gpa.print("ssh-{d}-import", .{which}));
            if (!try t.running(name)) return error.ImportStoppedTarget;
            const captured = try c.path(try c.gpa.print("ssh-{d}-restored.tar.zst", .{which}));
            try t.exportData(name, captured, if (which == 0) null else "postgres", true, try c.gpa.print("ssh-{d}-verify", .{which}));
            if (!mem.eql(u8, &try t.plainHash(if (which == 0) full else selected), &try t.plainHash(captured))) return error.RestoredBytes;
            try t.importOnline(name, archive, scope, false, try c.gpa.print("ssh-{d}-overwrite-refused", .{which}));
            try t.poweroff(name);
            try t.startMachine(name, try c.gpa.print("ssh-{d}-restart", .{which}));
            // The same image's fixture verifies all restored PostgreSQL invariants.
            _ = try t.consoleUntil(name, "transfer-fixture: database verified", 180);
            const console = try t.consoleUntil(name, "transfer-host-key: ", 60);
            if (mem.find(u8, console, "transfer-fixture: Rows") != null) return error.RestoredDatabase;
            try t.poweroff(name);
            if (cloud.supported(t.on)) try t.removeCompleted(name, try c.gpa.print("ssh-{d}-delete", .{which}));
            c.say("pass: SSH import case {d}, truncated-input retry, occupied-root refusal and restored bytes", .{which});
        }
    }

    fn importOnline(t: *Test, name: []const u8, archive: []const u8, service: ?[]const u8, success: bool, label: []const u8) !void {
        const c = t.c;
        var args: std.ArrayList([]const u8) = .empty;
        try args.appendSlice(c.gpa, &.{ t.binary, "import", name, archive, "--identity", t.key });
        if (service) |s| try args.appendSlice(c.gpa, &.{ "--service", s });
        const result = try c.run(args.items, label, .{ .timeout = .fromSeconds(900) });
        if (result.ok() != success) return c.fail("{s}: SSH import: {s}", .{ label, result.stderr });
        if (mem.endsWith(u8, label, "wanted-up-refused") and mem.find(u8, result.stderr, "TransferWritersRunning") == null)
            return error.ImportWriterCheckMissing;
        if (mem.endsWith(u8, label, "overwrite-refused") and mem.find(u8, result.stderr, "TransferConflict") == null)
            return error.ImportConflictCheckMissing;
    }

    fn configuration(t: *Test, role: []const u8) ![]const u8 {
        const c = t.c;
        const path = try c.path(try c.gpa.print("config-{s}", .{role}));
        try Dir.cwd().createDirPath(c.io, path);
        try Dir.cwd().setFilePermissions(c.io, path, .fromMode(0o700), .{});
        try Dir.cwd().copyFile(try c.gpa.print("{s}.pub", .{t.key}), .cwd(), try c.gpa.print("{s}/authorized_keys", .{path}), c.io, .{});
        try Dir.cwd().writeFile(c.io, .{ .sub_path = try c.gpa.print("{s}/transfer-role", .{path}), .data = role });
        return path;
    }

    fn own(t: *Test, name: []const u8) ![]const u8 {
        const c = t.c;
        if (t.on == .lima and try lima.exists(c.io, c.gpa, name)) return error.ExistingFixtureName;
        const at = try howl.machineDir(c.gpa, name);
        try Dir.cwd().createDirPath(c.io, std.fs.path.dirname(at).?);
        try Dir.cwd().createDir(c.io, at, .fromMode(0o700));
        try t.names.append(c.gpa, name);
        return name;
    }

    fn create(t: *Test, name: []const u8, config: []const u8, label: []const u8) !void {
        const c = t.c;
        var args: std.ArrayList([]const u8) = .empty;
        try args.appendSlice(c.gpa, &.{ t.binary, "create", name, "--with", t.form, "--on", @tagName(t.on), "--build", "--config", config, "--add-current-user", "no", "--yes" });
        if (t.on == .bhyve) try args.appendSlice(c.gpa, &.{ "--network", "slirp" });
        if (cloud.supported(t.on)) {
            try args.appendSlice(c.gpa, &.{ "--allow-from", "me" });
            if (c.env.get("DATA_TRANSFER_SIZE")) |size| try args.appendSlice(c.gpa, &.{ "--size", size });
        }
        _ = try c.must(args.items, label, .{ .timeout = .fromSeconds(1800) });
        try t.rememberDisk(name);
        // A successful startup must also preserve the real database invariants.
        _ = try t.consoleUntil(name, "transfer-fixture: ready", 180);
        const console = try t.consoleUntil(name, "posture: fail=", 90);
        if (mem.find(u8, console, "invalid user") != null) return error.LimaShellProbe;
    }

    fn instance(t: *Test, name: []const u8) ![]const u8 {
        return if (t.on == .lima) try lima.dir(t.c.io, t.c.gpa, name) orelse error.MissingLimaInstance else try howl.machineDir(t.c.gpa, name);
    }

    fn consoleUntil(t: *Test, name: []const u8, needle: []const u8, seconds: usize) ![]const u8 {
        const c = t.c;
        const file = try c.gpa.print("{s}/{s}", .{ try t.instance(name), if (t.on == .lima) "serial.log" else "console.log" });
        for (0..seconds) |_| {
            const raw = if (cloud.supported(t.on)) try t.cloudConsole(name) else Dir.cwd().readFileAlloc(c.io, file, c.gpa, .limited(4 << 20)) catch "";
            if (cloud.supported(t.on)) try Dir.cwd().writeFile(c.io, .{ .sub_path = file, .data = raw });
            const fresh = if (t.boot_markers.get(name)) |marker| @import("azure.zig").since(raw, marker) else raw;
            const text = try host.qemu.clean(c.gpa, fresh);
            if (mem.find(u8, text, needle) != null) return text;
            if (mem.find(u8, text, "transfer-fixture: Sql") != null or mem.find(u8, text, "transfer-fixture: Rows") != null)
                return c.fail("database fixture failed; see {s}", .{file});
            try c.io.sleep(.fromSeconds(1), .awake);
        }
        return c.fail("missing {s}; see {s}", .{ needle, file });
    }

    fn pin(t: *Test, name: []const u8) !void {
        const c = t.c;
        const text = try t.consoleUntil(name, "transfer-host-key: ", 60);
        const start = mem.find(u8, text, "transfer-host-key: ").? + "transfer-host-key: ".len;
        const end = mem.findScalarPos(u8, text, start, '\n') orelse return error.MissingHostKey;
        const key = mem.trim(u8, text[start..end], "\r");
        if (!mem.startsWith(u8, key, "ssh-ed25519 ")) return error.HostKey;
        try Dir.cwd().writeFile(c.io, .{ .sub_path = try c.gpa.print("{s}/known_hosts", .{try howl.machineDir(c.gpa, name)}), .data = try c.gpa.print("{s} {s}\n", .{ name, key }), .flags = .{ .permissions = .fromMode(0o600) } });
    }

    fn ssh(t: *Test, name: []const u8, command: []const []const u8, label: []const u8, success: bool) !void {
        return t.sshRequest(name, .command, command, label, success);
    }

    fn sshRequest(t: *Test, name: []const u8, kind: enum { command, pty, forward, subsystem, shutdown }, command: []const []const u8, label: []const u8, success: bool) !void {
        const c = t.c;
        const at = try howl.machineDir(c.gpa, name);
        const port = try t.sshPort(name);
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(c.gpa, &.{ "ssh", "-F", "/dev/null", "-S", "none", "-T", "-a", "-p", port, "-i", t.key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", try c.gpa.print("HostKeyAlias={s}", .{name}), "-o", try c.gpa.print("UserKnownHostsFile={s}/known_hosts", .{at}) });
        switch (kind) {
            .command, .shutdown => {},
            .pty => try argv.append(c.gpa, "-tt"),
            .forward => try argv.appendSlice(c.gpa, &.{ "-W", "127.0.0.1:22" }),
            .subsystem => try argv.append(c.gpa, "-s"),
        }
        try argv.append(c.gpa, try c.gpa.print("root@{s}", .{try t.sshHost(name)}));
        try argv.appendSlice(c.gpa, command);
        const r = try c.run(argv.items, label, .{ .timeout = .fromSeconds(100) });
        if (kind != .shutdown and r.ok() != success) return c.fail("{s}: unexpected SSH result: {s}", .{ label, r.stderr });
        if (mem.eql(u8, label, "shell-command-refused") and mem.find(u8, r.stderr, "TransferInvocation") == null) return error.CommandNotRefused;
        if ((mem.eql(u8, label, "system-control-refused") or mem.eql(u8, label, "scope-path-refused")) and
            mem.find(u8, r.stderr, "TransferService") == null) return error.ScopeNotRefused;
        if (mem.eql(u8, label, "unauthorized-key-refused") and mem.find(u8, r.stderr, "Permission denied") == null) return error.AuthenticationNotRefused;
        if (kind == .pty and mem.find(u8, r.stderr, "PTY allocation request failed") == null) return error.TerminalNotRefused;
        if (kind == .forward and mem.find(u8, r.stderr, "administratively prohibited") == null) return error.ForwardingNotRefused;
        if (kind == .subsystem and mem.find(u8, r.stderr, "subsystem request failed") == null and mem.find(u8, r.stderr, "TransferInvocation") == null) return error.SubsystemNotRefused;
    }

    fn exportData(t: *Test, name: []const u8, archive: []const u8, service: ?[]const u8, success: bool, label: []const u8) !void {
        const c = t.c;
        // Resume rechecks current bytes; never mistake a previous successful
        // fixture capture for the output of this invocation.
        if (success) Dir.cwd().deleteFile(c.io, archive) catch |err| {
            if (err != error.FileNotFound) return err;
        };
        var args: std.ArrayList([]const u8) = .empty;
        try args.appendSlice(c.gpa, &.{ t.binary, "export", name, "--identity", t.key, "--output", archive });
        if (service) |s| try args.appendSlice(c.gpa, &.{ "--service", s });
        if (mem.eql(u8, label, "online-service-export")) {
            const port = try t.sshPort(name);
            try args.appendSlice(c.gpa, &.{ "--host", try t.sshHost(name), "--port", port });
        }
        const r = try c.run(args.items, label, .{ .timeout = .fromSeconds(if (cloud.supported(t.on)) 7200 else 900) });
        if (r.ok() != success) return c.fail("{s}: export result: {s}", .{ label, r.stderr });
        if ((mem.eql(u8, label, "live-refused") or mem.eql(u8, label, "restarted-writer-refused")) and
            mem.find(u8, r.stderr, "TransferWritersRunning") == null) return c.fail("{s}: writers were not checked: {s}", .{ label, r.stderr });
        if (mem.eql(u8, label, "wrong-pin-refused") and mem.find(u8, r.stderr, "Host key verification failed") == null)
            return error.HostIdentityNotRefused;
        if (!success) {
            if (Dir.cwd().access(c.io, archive, .{})) |_| return error.PublishedFailedCapture else |err| if (err != error.FileNotFound) return err;
        }
    }

    fn running(t: *Test, name: []const u8) !bool {
        if (t.on == .firecracker) return try @import("firecracker.zig").supervised(t.c.io, t.c.gpa, try t.instance(name)) or
            @import("firecracker.zig").running(t.c.io, t.c.gpa, try t.instance(name)) != null;
        if (cloud.supported(t.on)) {
            if ((try t.profile(name)).cloud_staged) return false;
            return (try @import("data-cloud.zig").state(t.c.io, t.c.gpa, name, try t.cloudContext(name))).running;
        }
        if (t.on == .bhyve) return try @import("bhyve.zig").supervised(t.c.io, t.c.gpa, try howl.machineDir(t.c.gpa, name)) or
            try @import("bhyve.zig").exists(t.c.io, t.c.gpa, name);
        return if (t.on == .lima) lima.running(t.c.io, t.c.gpa, name) else @import("qemu.zig").running(t.c.io, t.c.gpa, try howl.machineDir(t.c.gpa, name)) != null;
    }

    fn sshHost(t: *Test, name: []const u8) ![]const u8 {
        if (t.on == .firecracker) return (try @import("firecracker.zig").net(t.c.gpa, name)).guest;
        if (cloud.supported(t.on)) return @import("data-cloud.zig").address(t.c.io, t.c.gpa, name, try t.cloudContext(name));
        const host_name = if (t.on == .bhyve)
            @import("qemu.zig").record(t.c.io, t.c.gpa, try howl.machineDir(t.c.gpa, name), "host") orelse return error.SshAddress
        else
            "127.0.0.1";
        if (!howl.isIp4(host_name)) return error.SshAddress;
        return host_name;
    }

    fn sshPort(t: *Test, name: []const u8) ![]const u8 {
        if (cloud.supported(t.on) or t.on == .firecracker) return "22";
        return if (t.on == .lima) lima.sshPort(t.c.io, t.c.gpa, name) orelse error.SshPort else @import("qemu.zig").record(t.c.io, t.c.gpa, try howl.machineDir(t.c.gpa, name), "ssh") orelse error.SshPort;
    }

    fn cloudContext(t: *Test, name: []const u8) !@import("data-cloud.zig").Context {
        return @import("data-cloud.zig").load(t.c.io, t.c.gpa, try howl.machineDir(t.c.gpa, name), t.on);
    }

    fn profile(t: *Test, name: []const u8) !@import("local-secure.zig").Profile {
        const c = t.c;
        return @import("local-secure.zig").parseProfile(c.gpa, try Dir.cwd().readFileAlloc(c.io, try c.gpa.print("{s}/authority/profile.json", .{try howl.machineDir(c.gpa, name)}), c.gpa, .limited(256 << 10)));
    }

    fn rejectHostBacking(t: *Test, name: []const u8) !void {
        const c = t.c;
        const raw = (try t.profile(name)).spec.disk_path orelse return error.TransferStorageState;
        const allowed = try c.path("manual-raw.tar.zst");
        _ = try c.must(&.{ t.binary, "export", name, "--disk", raw, "--output", allowed }, "manual-raw-export", .{});
        const forged = try c.path("host-pointer.qcow2");
        _ = try c.must(&.{ "qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", raw, forged }, "host-pointer-image", .{});
        const output = try c.path("host-pointer-must-not-export.tar.zst");
        const result = try c.run(&.{ t.binary, "export", name, "--disk", forged, "--output", output }, "host-pointer-refused", .{});
        if (result.ok()) return error.TransferHostBackingRead;
        if (Dir.cwd().access(c.io, output, .{})) |_| return error.TransferHostBackingRead else |err| if (err != error.FileNotFound) return err;
    }

    fn rememberDisk(t: *Test, name: []const u8) !void {
        if (!cloud.supported(t.on)) return;
        if ((try t.profile(name)).cloud_staged) return;
        const context = try t.cloudContext(name);
        const machine = try @import("data-cloud.zig").state(t.c.io, t.c.gpa, name, context);
        for (t.disks.items) |disk| if (mem.eql(u8, disk.id, machine.disk)) return;
        try t.disks.append(t.c.gpa, .{ .context = context, .id = machine.disk });
    }

    fn cleanupDisks(t: *Test) !void {
        const c = t.c;
        const disk_api = @import("data-cloud-disk.zig");
        // Only exact disk IDs observed on this run's randomly named fixtures.
        // A VM must be deleted successfully before any retained disk is removed.
        for (t.disks.items) |disk| switch (disk.context) {
            .gcp => |p| {
                const found = try disk_api.gcp(c.io, c.gpa, p.project, &.{ "compute", "disks", "list", "--zones", p.zone, "--filter", try c.gpa.print("name={s}", .{std.fs.path.basename(disk.id)}), "--format=value(selfLink)" });
                if (found.len == 0) continue;
                if (!mem.eql(u8, found, disk.id)) return error.TransferTestCleanup;
                _ = try disk_api.gcp(c.io, c.gpa, p.project, &.{ "compute", "disks", "delete", disk.id, "--zone", p.zone });
            },
            .azure => |p| {
                const found = try disk_api.azure(c.io, c.gpa, p.group, &.{ "disk", "list", "--query", try c.gpa.print("[?id=='{s}'].id", .{disk.id}), "-o", "tsv" });
                if (found.len == 0) continue;
                if (!mem.eql(u8, found, disk.id)) return error.TransferTestCleanup;
                _ = try disk_api.azure(c.io, c.gpa, p.group, &.{ "disk", "delete", "--ids", disk.id, "--yes", "-o", "none" });
            },
        };
    }

    fn cloudConsole(t: *Test, name: []const u8) ![]const u8 {
        return switch (try t.cloudContext(name)) {
            .gcp => |p| @import("gcp.zig").console(t.c.io, t.c.gpa, .{ .project = p.project, .zone = p.zone }, name),
            .azure => |p| @import("azure.zig").console(t.c.io, t.c.gpa, .{ .group = p.group, .location = p.location }, name),
        } orelse "";
    }

    fn cloudPower(t: *Test, name: []const u8, up: bool, label: []const u8) !void {
        const c = t.c;
        const context = try t.cloudContext(name);
        _ = try @import("data-cloud.zig").state(c.io, c.gpa, name, context);
        if (up) try t.boot_markers.put(c.gpa, name, @import("azure.zig").mark(try t.cloudConsole(name)));
        const args: []const []const u8 = switch (context) {
            .gcp => |p| &.{ "gcloud", "--quiet", "--project", p.project, "compute", "instances", if (up) "start" else "stop", name, "--zone", p.zone },
            .azure => |p| &.{ "az", "vm", if (up) "start" else "deallocate", "-g", p.group, "-n", name, "-o", "none" },
        };
        _ = try c.must(args, label, .{ .timeout = .fromSeconds(600) });
    }

    fn startMachine(t: *Test, name: []const u8, label: []const u8) !void {
        if (cloud.supported(t.on)) {
            if (!(try t.profile(name)).cloud_staged) return t.cloudPower(name, true, label);
            _ = try t.c.must(&.{ t.binary, "start", name }, label, .{ .timeout = .fromSeconds(1800) });
            try t.rememberDisk(name);
            return;
        }
        if (t.on == .firecracker) {
            // Its supervisor appends serial logs across boots. A readiness
            // marker from the previous boot cannot qualify this restart.
            const console = try Dir.cwd().createFile(t.c.io, try t.c.gpa.print("{s}/console.log", .{try t.instance(name)}), .{});
            console.close(t.c.io);
        }
        _ = try t.c.must(&.{ t.binary, "start", name }, label, .{});
    }

    fn removeCompleted(t: *Test, name: []const u8, label: []const u8) !void {
        const c = t.c;
        try Dir.cwd().copyFile(try c.gpa.print("{s}/console.log", .{try t.instance(name)}), .cwd(), try c.path(try c.gpa.print("{s}-console.log", .{name})), c.io, .{});
        _ = try c.must(&.{ t.binary, "delete", name, "--on", @tagName(t.on) }, label, .{ .timeout = .fromSeconds(600) });
        for (t.names.items) |*owned| if (mem.eql(u8, owned.*, name)) {
            owned.* = "";
            break;
        };
    }

    fn plainHash(t: *Test, path: []const u8) ![32]u8 {
        const io = t.c.io;
        const a = t.c.gpa;
        const file = try Dir.cwd().openFile(io, path, .{});
        defer file.close(io);
        var buffer: [64 << 10]u8 = undefined;
        var reader = file.reader(io, &buffer);
        const manifest = try data.zstd.manifest(a, &reader.interface);
        var users: std.ArrayList(data.Identity) = .empty;
        var groups: std.ArrayList(data.Identity) = .empty;
        var services: std.ArrayList([]const u8) = .empty;
        for (manifest.entries) |entry| {
            try users.append(a, .{ .name = entry.owner, .id = 0 });
            try groups.append(a, .{ .name = entry.group, .id = 0 });
            if (mem.cutPrefix(u8, entry.path, "svc/")) |suffix| {
                const end = mem.findScalar(u8, suffix, '/') orelse suffix.len;
                try services.append(a, suffix[0..end]);
            }
        }
        // Test-only policy checks the fixture's whole archive. The sink hashes
        // selected application metadata and bytes, excluding archived logs.
        const policy: data.Policy = .{ .image = manifest.image, .arch = manifest.arch, .services = services.items, .users = users.items, .groups = groups.items };
        const Hash = struct {
            hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
            allocator: mem.Allocator,
            fn begin(ctx: *anyopaque, entry: data.Entry) !void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                const json = try std.json.Stringify.valueAlloc(self.allocator, entry, .{});
                defer self.allocator.free(json);
                var size: [8]u8 = undefined;
                mem.writeInt(u64, &size, json.len, .little);
                self.hash.update(&size);
                self.hash.update(json);
            }
            fn write(ctx: *anyopaque, bytes: []const u8) !void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                self.hash.update(bytes);
            }
            fn end(_: *anyopaque, _: data.Entry) !void {}
        };
        var hash: Hash = .{ .allocator = a };
        var again = file.reader(io, &buffer);
        _ = try data.zstd.validate(a, &again.interface, policy, null, .{ .context = &hash, .begin = Hash.begin, .write = Hash.write, .end = Hash.end });
        return hash.hash.finalResult();
    }

    fn poweroff(t: *Test, name: []const u8) !void {
        const c = t.c;
        const at = try t.instance(name);
        if (t.on == .firecracker) {
            try Dir.cwd().writeFile(c.io, .{ .sub_path = try c.gpa.print("{s}/stop-request", .{at}), .data = "", .flags = .{ .permissions = .fromMode(0o600) } });
            try t.ssh(name, &.{ "service-down-v1", "transfer-stop" }, "fixture-stop-arm", true);
            try c.io.sleep(.fromMilliseconds(300), .awake);
            try t.sshRequest(name, .shutdown, &.{ "service-up-v1", "transfer-stop" }, "fixture-stop", true);
        } else if (cloud.supported(t.on)) {
            try t.cloudPower(name, false, "cloud-poweroff");
        } else if (t.on == .bhyve) {
            const root = try @import("bhyve.zig").asRoot(c.io);
            const found = try c.must(try mem.concat(c.gpa, []const u8, &.{ root, &.{ "/bin/pgrep", "-u", "0", "-f", "-x", try c.gpa.print("bhyve: {s}", .{name}) } }), "bhyve-poweroff-pid", .{});
            const pid_text = mem.trim(u8, found.stdout, " \r\n");
            const pid = try std.fmt.parseUnsigned(u32, pid_text, 10);
            if (pid <= 1) return error.PoweroffPid;
            _ = try c.must(try mem.concat(c.gpa, []const u8, &.{ root, &.{ "/bin/kill", "-TERM", pid_text } }), "bhyve-poweroff", .{});
        } else if (t.on == .lima) _ = try host.qmp.command(c.io, c.gpa, try c.gpa.print("{s}/qmp.sock", .{at}), "system_powerdown", null) else {
            const address = try Io.net.UnixAddress.init(try c.gpa.print("{s}/monitor.sock", .{at}));
            const stream = try address.connect(c.io);
            defer stream.close(c.io);
            const f: Io.File = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = false } };
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

    fn stopApplications(t: *Test, name: []const u8, label: []const u8) !void {
        try t.ssh(name, &.{ "service-down-v1", "postgres" }, label, true);
        if (t.on == .firecracker) try t.ssh(name, &.{ "service-down-v1", "transfer-stop" }, try t.c.gpa.print("{s}-stop", .{label}), true);
    }

    fn cleanup(t: *Test) !void {
        const c = t.c;
        var failed = false;
        for (t.names.items) |name| {
            if (name.len == 0) continue;
            if (t.instance(name)) |at| {
                const file = c.gpa.print("{s}/{s}", .{ at, if (t.on == .lima) "serial.log" else "console.log" }) catch continue;
                const kept = c.path(c.gpa.print("{s}-console.log", .{name}) catch continue) catch continue;
                Dir.cwd().copyFile(file, .cwd(), kept, c.io, .{}) catch {};
            } else |_| {}
            const removed = c.run(&.{ t.binary, "delete", name, "--on", @tagName(t.on) }, "cleanup", .{ .timeout = .fromSeconds(600) }) catch {
                failed = true;
                continue;
            };
            if (!removed.ok()) {
                c.say("cleanup failed for owned fixture {s}", .{name});
                failed = true;
            }
        }
        if (failed) return error.TransferTestCleanup;
        try t.cleanupDisks();
        if (t.key.len != 0) Dir.cwd().deleteFile(c.io, t.key) catch {};
        if (c.work.len > 1) Dir.cwd().deleteTree(c.io, c.path("credentials") catch return) catch {};
    }
};
