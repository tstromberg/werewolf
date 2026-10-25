//! gcp-metadata HOWL SK_PROVIDER ARCH is make check-gcp-metadata: it builds
//! this checkout's prod-ssh with metadata people, creates its own GCP VM,
//! and changes its metadata as an operator would: user-data at boot,
//! instance and project keys, declared-user precedence, refused root
//! access, expired and malformed key records, expiry without an edit,
//! project-key blocking, account removal, root-key rotation, invalid and
//! absent user-data, all without a reboot. It appends a test key to the
//! project's ssh-keys and restores that attribute alone afterwards. Logs
//! stay in build/check/gcp-metadata-*; CLOUD_KEEP=1 keeps the VM and its
//! test keys. It needs gcloud logged in with create, delete and project
//! metadata permissions.

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;
const Result = host.check.Result;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "gcp-metadata") catch std.process.exit(1);
    c.finish(run(&c));
}

const keys = [_][]const u8{ "root", "declared", "instance", "project" };

const Gcp = struct {
    c: *host.Check,
    project: []const u8,
    zone: []const u8,
    name: []const u8,
    provider: []const u8,
    dir: []const u8,
    ip: []const u8 = "",

    /// g runs gcloud on the project, and refuses its failure.
    fn g(t: *Gcp, args: []const []const u8) ![]const u8 {
        const c = t.c;
        const base = [_][]const u8{ "gcloud", "--quiet", "--project", t.project };
        const argv = try mem.concat(c.gpa, []const u8, &.{ &base, args });
        const r = try host.check.command(c.io, c.gpa, argv, .{ .environ_map = &c.env });
        if (!r.ok()) return c.fail("{s}", .{r.stderr});
        return mem.trim(u8, r.stdout, " \t\r\n");
    }

    fn ssh(t: *Gcp, key: []const u8, user: []const u8, command: []const u8) !Result {
        const c = t.c;
        const gpa = c.gpa;
        const known = try gpa.print("UserKnownHostsFile={s}", .{try t.at("known_hosts")});
        const provider = try gpa.print("SecurityKeyProvider={s}", .{t.provider});
        const argv = [_][]const u8{
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            known,
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            provider,
            "-i",
            try t.at(key),
            try gpa.print("{s}@{s}", .{ user, t.ip }),
            command,
        };
        const options: host.check.Options = .{ .environ_map = &c.env, .timeout = .fromSeconds(15) };
        return host.check.command(c.io, gpa, &argv, options);
    }

    /// ok requires command to run as user with key, retrying only a
    /// dropped connection, which proves nothing about the key.
    fn ok(t: *Gcp, key: []const u8, user: []const u8, command: []const u8) ![]const u8 {
        const io = t.c.io;
        const deadline = host.qemu.after(io, 90);
        while (true) {
            const r = try t.ssh(key, user, command);
            const settled = r.ok() or !transient(r.stderr) or !before(io, deadline);
            if (!settled) {
                try io.sleep(.fromSeconds(5), .awake);
                continue;
            }
            if (!r.ok()) return t.c.fail("{s} as {s} failed: {s}", .{ key, user, r.stderr });
            return mem.trim(u8, r.stdout, " \t\r\n");
        }
    }

    /// root is whether key logs user in as root.
    fn root(t: *Gcp, key: []const u8, user: []const u8) !bool {
        return mem.eql(u8, try t.ok(key, user, "id -u"), "0");
    }

    /// refused requires sshd to refuse key for user.
    fn refused(t: *Gcp, key: []const u8, user: []const u8) !void {
        const io = t.c.io;
        const deadline = host.qemu.after(io, 90);
        while (true) {
            const r = try t.ssh(key, user, "id -u");
            const denied = mem.find(u8, r.stderr, "Permission denied") != null;
            const settled = denied or !transient(r.stderr) or !before(io, deadline);
            if (!settled) {
                try io.sleep(.fromSeconds(5), .awake);
                continue;
            }
            if (r.code() != 255 or !denied) {
                const said = .{ key, user, r.term, r.stderr };
                return t.c.fail("{s} as {s} was not refused: {f}: {s}", said);
            }
            return;
        }
    }

    /// wait polls command, as user with key, until it says expected.
    fn wait(
        t: *Gcp,
        command: []const u8,
        expected: []const u8,
        key: []const u8,
        user: []const u8,
    ) !void {
        const io = t.c.io;
        const deadline = host.qemu.after(io, 160);
        var last: ?Result = null;
        while (before(io, deadline)) : (try io.sleep(.fromSeconds(3), .awake)) {
            const r = try t.ssh(key, user, command);
            last = r;
            if (r.ok() and mem.eql(u8, mem.trim(u8, r.stdout, " \t\r\n"), expected)) return;
        }
        const out = if (last) |r| r.stdout else "";
        const err = if (last) |r| r.stderr else "";
        return t.c.fail("poll timeout: {s}: {s} {s}", .{ command, out, err });
    }

    /// metadata adds instance metadata, from a file, values, or both.
    fn metadata(t: *Gcp, file: ?[]const u8, values: ?[]const u8) !void {
        var args: std.ArrayList([]const u8) = .empty;
        const gpa = t.c.gpa;
        try args.appendSlice(gpa, &.{ "compute", "instances", "add-metadata", t.name });
        try args.appendSlice(gpa, &.{ "--zone", t.zone });
        if (file) |f| try args.appendSlice(gpa, &.{ "--metadata-from-file", f });
        if (values) |v| try args.appendSlice(gpa, &.{ "--metadata", v });
        _ = try t.g(args.items);
    }

    /// projectInfo is the project's metadata item key, if it has one.
    fn projectInfo(t: *Gcp, key: []const u8) !?[]const u8 {
        const describe = [_][]const u8{
            "compute",
            "project-info",
            "describe",
            "--format=json(commonInstanceMetadata)",
        };
        return itemValue(t.c.gpa, try t.g(&describe), key);
    }

    /// projectKeysFrom makes file the project's ssh-keys.
    fn projectKeysFrom(t: *Gcp, file: []const u8) !void {
        const from = try t.c.gpa.print("ssh-keys={s}", .{try t.at(file)});
        _ = try t.g(&.{ "compute", "project-info", "add-metadata", "--metadata-from-file", from });
    }

    fn publicKey(t: *Gcp, which: []const u8) ![]const u8 {
        const path = try t.c.gpa.print("{s}.pub", .{try t.at(which)});
        const text = try Io.Dir.cwd().readFileAlloc(t.c.io, path, t.c.gpa, .limited(64 << 10));
        return mem.trim(u8, text, " \t\r\n");
    }

    fn at(t: *Gcp, name: []const u8) ![]const u8 {
        return std.fs.path.join(t.c.gpa, &.{ t.dir, name });
    }

    fn put(t: *Gcp, name: []const u8, data: []const u8) !void {
        try Io.Dir.cwd().writeFile(t.c.io, .{ .sub_path = try t.at(name), .data = data });
    }

    fn log(t: *Gcp, text: []const u8) !void {
        t.c.say("PASS {s}", .{text});
        const line = try t.c.gpa.print("PASS {s}\n", .{text});
        try host.check.append(t.c.io, try t.at("checks.log"), line);
    }
};

/// before is whether deadline is still ahead.
fn before(io: Io, deadline: Io.Clock.Timestamp) bool {
    return Io.Clock.Timestamp.now(io, .awake).compare(.lt, deadline);
}

/// transient is whether ssh lost its connection, not its key: production
/// sshd penalizes repeated failed logins from one source.
pub fn transient(stderr: []const u8) bool {
    for ([_][]const u8{
        "Connection reset",
        "Connection closed",
        "kex_exchange_identification",
    }) |sign|
        if (mem.find(u8, stderr, sign) != null) return true;
    return false;
}

/// stamp is t as GCP's key expiry format: YYYY-MM-DDTHH:MM:SS+0000.
pub fn stamp(gpa: Allocator, t: i64) ![]const u8 {
    const at: std.time.epoch.EpochSeconds = .{ .secs = @intCast(t) };
    const year = at.getEpochDay().calculateYearDay();
    const month = year.calculateMonthDay();
    const day = at.getDaySeconds();
    return gpa.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}+0000", .{
        year.year,
        month.month.numeric(),
        month.day_index + 1,
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
        day.getSecondsIntoMinute(),
    });
}

/// googleKey is a key row Google's guest agent writes: user, key, and
/// the user and expiry it binds the key to.
pub fn googleKey(
    gpa: Allocator,
    row_user: []const u8,
    public: []const u8,
    user: []const u8,
    expire: []const u8,
) ![]const u8 {
    return gpa.print(
        "{s}:{s} google-ssh {{\"userName\": \"{s}\", \"expireOn\": \"{s}\"}}",
        .{ row_user, public, user, expire },
    );
}

/// restoredKeys is the project's ssh-keys once this run's line is gone:
/// what it was if nobody else changed it, else the current value without
/// that line. null means there was no attribute to restore.
pub fn restoredKeys(
    gpa: Allocator,
    old: ?[]const u8,
    written: []const u8,
    current: []const u8,
    line: []const u8,
) !?[]const u8 {
    if (mem.eql(u8, current, written)) return old;
    var out: std.ArrayList(u8) = .empty;
    var rest = current;
    while (rest.len > 0) {
        const end = if (mem.findScalar(u8, rest, '\n')) |i| i + 1 else rest.len;
        if (!mem.eql(u8, rest[0..end], line)) try out.appendSlice(gpa, rest[0..end]);
        rest = rest[end..];
    }
    return out.items;
}

/// containsLine is whether text holds line, newline and all, as a line.
pub fn containsLine(text: []const u8, line: []const u8) bool {
    var rest = text;
    while (rest.len > 0) {
        const end = if (mem.findScalar(u8, rest, '\n')) |i| i + 1 else rest.len;
        if (mem.eql(u8, rest[0..end], line)) return true;
        rest = rest[end..];
    }
    return false;
}

/// rotate is a config tar with root's authorized_keys replaced by keys.
pub fn rotate(gpa: Allocator, tar: []const u8, authorized: []const u8) ![]const u8 {
    var in: Io.Reader = .fixed(tar);
    var name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(
        &in,
        .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
    );
    var out: Io.Writer.Allocating = .init(gpa);
    var w: std.tar.Writer = .{ .underlying_writer = &out.writer };
    while (try it.next()) |entry| switch (entry.kind) {
        .file => {
            var data: Io.Writer.Allocating = .init(gpa);
            try it.streamRemaining(entry, &data.writer);
            const replaced = mem.eql(u8, mem.trim(u8, entry.name, "./"), "authorized_keys");
            try w.writeFileBytes(
                entry.name,
                if (replaced) authorized else data.written(),
                .{ .mode = entry.mode },
            );
        },
        .directory => try w.writeDir(entry.name, .{ .mode = entry.mode }),
        .sym_link => try w.writeLink(entry.name, entry.link_name, .{ .mode = entry.mode }),
    };
    try w.finishPedantically();
    return out.written();
}

const form_yaml =
    \\base: prod-ssh
    \\updates: off
    \\machine:
    \\  metadata-users: true
    \\users:
    \\  declared:
    \\    admin: true
    \\    keys:
    \\      - {s}
    \\
;

fn run(c: *host.Check) !void {
    const io = c.io;
    const gpa = c.gpa;
    const cwd = Io.Dir.cwd();
    if (c.args.len != 4) return c.fail("usage: gcp-metadata HOWL SK_PROVIDER ARCH", .{});
    const howl = try c.absolute(c.args[1]);
    const provider = try c.absolute(c.args[2]);
    const arch = c.args[3];
    const project = if (c.env.get("GCP_PROJECT")) |p| p else blk: {
        const r = try c.must(&.{ "gcloud", "config", "get-value", "project" }, "", .{});
        break :blk mem.trim(u8, r.stdout, " \t\r\n");
    };
    if (project.len == 0 or mem.eql(u8, project, "(unset)"))
        return c.fail("set GCP_PROJECT or gcloud's project", .{});
    const zone = c.env.get("GCP_ZONE") orelse "us-central1-a";
    try c.env.put("CLOUDSDK_CORE_PROJECT", project);
    try c.env.put("CLOUDSDK_COMPUTE_ZONE", zone);
    try cwd.createDirPath(io, "build/check");
    var suffix: [6]u8 = undefined;
    var random: [6]u8 = undefined;
    io.random(&random);
    for (&suffix, random) |*s, r| s.* = "abcdefghijklmnopqrstuvwxyz0123456789"[r % 36];
    try c.setWork(try gpa.print("build/check/gcp-metadata-{s}", .{&suffix}));
    const when = try stamp(gpa, Io.Clock.real.now(io).toSeconds());
    // YYMMDDHHMMSS, as the machine's name shows when it was made.
    const date = [_][]const u8{ when[2..4], when[5..7], when[8..10] };
    const time = [_][]const u8{ when[11..13], when[14..16], when[17..19] };
    const parts = date ++ time;
    const made = try mem.concat(gpa, u8, &parts);
    var t: Gcp = .{
        .c = c,
        .project = project,
        .zone = zone,
        .name = try gpa.print("ww-metadata-{s}-{s}", .{ made, &suffix }),
        .provider = provider,
        .dir = c.work,
    };
    try t.put("name", t.name);
    c.say("GCP metadata logs: {s}", .{c.work});
    try cwd.createDir(io, try t.at("config"), .default_dir);
    for (keys) |which| {
        const keygen = [_][]const u8{
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519-sk",
            "-O",
            "verify-required",
            "-w",
            provider,
            "-N",
            "",
            "-C",
            try gpa.print("gcp-metadata-{s}", .{which}),
            "-f",
            try t.at(which),
        };
        _ = try c.must(&keygen, "", .{});
    }
    const root_key = try cwd.readFileAlloc(io, try t.at("root.pub"), gpa, .limited(64 << 10));
    try t.put("config/authorized_keys", root_key);
    try t.put("config/hostname", "gcp-metadata-check\n");
    try t.put("form.yaml", try gpa.print(form_yaml, .{try t.publicKey("declared")}));
    const outcome = createAndCheck(&t, howl, arch);
    if (outcome) |_| {} else |err| {
        const why = if (err == error.CheckFailed) c.why else @errorName(err);
        try t.put("failure.log", why);
    }
    const why = c.why;
    cwd.access(io, try t.at("serial.log"), .{}) catch {
        const serial = [_][]const u8{
            "gcloud",
            "--quiet",
            "--project",
            project,
            "compute",
            "instances",
            "get-serial-port-output",
            t.name,
            "--zone",
            zone,
        };
        const r = host.check.command(io, gpa, &serial, .{ .environ_map = &c.env }) catch null;
        if (r) |said| {
            try t.put("serial.log", said.stdout);
            if (!said.ok()) try t.put("serial-error.log", said.stderr);
        }
    };
    if (mem.eql(u8, c.env.get("CLOUD_KEEP") orelse "", "1")) {
        c.say("KEPT {s}; keys and logs: {s}", .{ t.name, c.work });
        return outcome;
    }
    const cleaned = cleanup(&t, howl);
    outcome catch |err| {
        cleaned catch std.log.err("cleanup failed too: {s}", .{c.why});
        c.why = why;
        return err;
    };
    try cleaned;
}

fn createAndCheck(t: *Gcp, howl: []const u8, arch: []const u8) !void {
    const c = t.c;
    const io = c.io;
    const create_log = try t.at("create.log");
    {
        const log = try Io.Dir.cwd().createFile(io, create_log, .{});
        defer log.close(io);
        var child = try std.process.spawn(io, .{
            .argv = &.{
                howl,
                "create",
                t.name,
                "--build",
                "-f",
                try t.at("form.yaml"),
                "--on",
                "gcp",
                "--arch",
                arch,
                "--config",
                try t.at("config"),
                "--allow-from",
                "me",
            },
            .environ_map = &c.env,
            .stdin = .ignore,
            .stdout = .{ .file = log },
            .stderr = .{ .file = log },
        });
        const term = try child.wait(io);
        if (!term.success()) {
            const text = try Io.Dir.cwd().readFileAlloc(io, create_log, c.gpa, .unlimited);
            return c.fail("{s}", .{host.check.tail(text, 5000)});
        }
    }
    try checks(t);
}

/// present is a guest command that says yes once user has an account.
fn present(gpa: Allocator, user: []const u8) ![]const u8 {
    return gpa.print("grep '^{s}:' /etc/passwd >/dev/null && echo yes", .{user});
}

/// absent is a guest command that says absent once user has no account.
fn absent(gpa: Allocator, user: []const u8) ![]const u8 {
    return gpa.print("grep '^{s}:' /etc/passwd >/dev/null || echo absent", .{user});
}

const boot_id = "cat /proc/sys/kernel/random/boot_id";

fn checks(t: *Gcp) !void {
    const c = t.c;
    const io = c.io;
    const gpa = c.gpa;
    const nat = "--format=value(networkInterfaces[0].accessConfigs[0].natIP)";
    t.ip = try t.g(&.{ "compute", "instances", "describe", t.name, "--zone", t.zone, nat });
    try t.put("ip", t.ip);
    try t.wait("hostname", "gcp-metadata-check", "root", "root");
    const boot = try t.ok("root", "root", boot_id);
    if (try t.root("declared", "declared")) return c.fail("declared user is root", .{});
    if (!try t.root("declared", "root")) return c.fail("declared admin key is not root's", .{});
    try t.log("user-data boot config and declared admin key");

    const now = Io.Clock.real.now(io).toSeconds();
    const future = try stamp(gpa, now + 3600);
    const fleeting = try stamp(gpa, now + 180);
    const instance = try t.publicKey("instance");
    const expired = "2020-01-01T00:00:00+0000";
    const rows = [_][]const u8{
        try gpa.print("alice:{s}", .{instance}),
        try gpa.print("declared:{s}", .{instance}),
        try gpa.print("root:{s}", .{instance}),
        try googleKey(gpa, "expired", instance, "expired", expired),
        try gpa.print("malformed:{s} google-ssh {{}}", .{instance}),
        try googleKey(gpa, "mismatch", instance, "other", future),
        try googleKey(gpa, "fresh", instance, "fresh", future),
        try googleKey(gpa, "fleeting", instance, "fleeting", fleeting),
    };
    try t.put("instance.keys", try gpa.print("{s}\n", .{try mem.join(gpa, "\n", &rows)}));
    const instance_keys = try gpa.print("ssh-keys={s}", .{try t.at("instance.keys")});
    try t.metadata(instance_keys, null);
    try t.wait(try present(gpa, "alice"), "yes", "root", "root");
    for ([_][]const u8{ "alice", "fresh", "fleeting" }) |user|
        if (try t.root("instance", user)) return c.fail("{s} is root", .{user});
    for ([_][]const u8{ "root", "declared", "expired", "malformed", "mismatch" }) |user|
        try t.refused("instance", user);
    if (try t.root("declared", "declared")) return c.fail("declared user is root", .{});
    const stale = "grep -E '^(expired|malformed|mismatch):' /etc/passwd || true";
    if (!mem.eql(u8, try t.ok("root", "root", stale), ""))
        return c.fail("expired, malformed or mismatched keys made accounts", .{});
    try t.log("instance SSH keys, declared precedence, no root/admin, " ++
        "expiry and malformed records");

    try projectKeys(t);

    try t.wait(try absent(gpa, "fleeting"), "absent", "root", "root");
    try t.refused("instance", "fleeting");
    try t.log("an initially valid key expires and is revoked without a metadata edit");
    try t.put("instance.keys", try gpa.print("bob:{s}\n", .{try t.publicKey("project")}));
    try t.metadata(instance_keys, null);
    try t.wait(try present(gpa, "bob"), "yes", "root", "root");
    if (try t.root("project", "bob")) return c.fail("bob is root", .{});
    try t.refused("instance", "alice");
    try t.refused("instance", "fresh");
    const replaced = "grep -E '^(alice|fresh):' /etc/passwd || true";
    if (!mem.eql(u8, try t.ok("root", "root", replaced), ""))
        return c.fail("replaced accounts remain", .{});
    try t.log("live replacement revokes old accounts and admits new keys");

    const config = try gpa.print("build/machines/{s}/config.tar", .{t.name});
    const original = try Io.Dir.cwd().readFileAlloc(io, config, gpa, .limited(1 << 20));
    const project_key = try gpa.print("{s}\n", .{try t.publicKey("project")});
    const rotated = try rotate(gpa, original, project_key);
    const encoder = std.base64.standard.Encoder;
    const encoded = try gpa.alloc(u8, encoder.calcSize(rotated.len));
    try t.put("rotated.b64", encoder.encode(encoded, rotated));
    const rotated_data = try gpa.print("user-data={s}", .{try t.at("rotated.b64")});
    try t.metadata(rotated_data, null);
    try t.wait("id -u", "0", "project", "root");
    try t.refused("root", "root");
    if (!try t.root("declared", "root")) return c.fail("declared admin lost root", .{});
    try t.log("user-data root-key rotation revokes old key and retains declared admin");

    try t.put("bad.b64", "not-a-config");
    try t.metadata(try gpa.print("user-data={s}", .{try t.at("bad.b64")}), null);
    try io.sleep(.fromSeconds(70), .awake);
    if (!try t.root("project", "root")) return c.fail("invalid user-data dropped root's key", .{});
    if (try t.root("project", "bob")) return c.fail("bob is root", .{});
    if (!try t.root("declared", "root"))
        return c.fail("invalid user-data dropped the declared admin", .{});
    try t.log("invalid user-data retains the last accepted people and root keys");
    const remove = [_][]const u8{
        "compute",
        "instances",
        "remove-metadata",
        t.name,
        "--zone",
        t.zone,
        "--keys",
        "user-data",
    };
    _ = try t.g(&remove);
    try t.wait(try absent(gpa, "declared"), "absent", "project", "bob");
    if (try t.root("project", "bob")) return c.fail("bob is root", .{});
    try t.refused("declared", "root");
    try t.refused("project", "root");
    try t.log("absent user-data keeps metadata people and removes declared people/root keys");
    try t.metadata(rotated_data, null);
    try t.wait("id -u", "0", "project", "root");
    if (!try t.root("declared", "root")) return c.fail("declared admin lost root", .{});
    if (!mem.eql(u8, try t.ok("project", "root", boot_id), boot))
        return c.fail("a metadata change rebooted the machine", .{});
    try t.log("all metadata changes applied without reboot");
    const serial = [_][]const u8{
        "compute",
        "instances",
        "get-serial-port-output",
        t.name,
        "--zone",
        t.zone,
    };
    try t.put("serial.log", try t.g(&serial));
    c.say("ALL LIVE GCP METADATA CHECKS PASSED", .{});
}

/// projectKeys adds a test key to the project's ssh-keys, checks it and
/// blocking, then restores that attribute alone, even if others changed
/// project metadata meanwhile.
fn projectKeys(t: *Gcp) !void {
    const gpa = t.c.gpa;
    const old = try t.projectInfo("ssh-keys");
    const user = try gpa.print("gcpcheck{s}", .{t.dir[t.dir.len - 6 ..]});
    const line = try gpa.print("{s}:{s}\n", .{ user, try t.publicKey("project") });
    const kept = if (old) |o| try gpa.print("{s}\n", .{o}) else "";
    const written = try gpa.print("{s}{s}", .{ kept, line });
    try t.put("project.keys", written);
    const outcome = projectChecks(t, user);
    const restore = restoreProject(t, old, written, line);
    try outcome;
    try restore;
}

fn projectChecks(t: *Gcp, user: []const u8) !void {
    const c = t.c;
    const gpa = c.gpa;
    try t.projectKeysFrom("project.keys");
    try t.wait(try present(gpa, user), "yes", "root", "root");
    if (try t.root("project", user)) return c.fail("{s} is root", .{user});
    try t.refused("project", "root");
    try t.log("project SSH keys grant an ordinary account");
    try t.metadata(null, "block-project-ssh-keys=TRUE");
    try t.wait(try absent(gpa, user), "absent", "root", "root");
    try t.refused("project", user);
    if (try t.root("instance", "alice")) return c.fail("alice is root", .{});
    try t.log("block-project-ssh-keys revokes project access and preserves instance access");
    try t.metadata(null, "block-project-ssh-keys=FALSE");
    try t.wait(try present(gpa, user), "yes", "root", "root");
    if (try t.root("project", user)) return c.fail("{s} is root", .{user});
    try t.log("unblocking project keys restores access live");
}

fn restoreProject(t: *Gcp, old: ?[]const u8, written: []const u8, line: []const u8) !void {
    const current = try t.projectInfo("ssh-keys") orelse "";
    // Remove only this run's unique key, also when somebody has appended
    // their own since.
    if (containsLine(current, line)) {
        if (try restoredKeys(t.c.gpa, old, written, current, line)) |restored| {
            try t.put("project.restore", restored);
            try t.projectKeysFrom("project.restore");
        } else {
            _ = try t.g(&.{ "compute", "project-info", "remove-metadata", "--keys", "ssh-keys" });
        }
    }
    t.c.say("RESTORED project ssh-keys", .{});
}

/// itemValue is a project's metadata item key, from project-info's JSON.
pub fn itemValue(gpa: Allocator, text: []const u8, key: []const u8) ?[]const u8 {
    const v = json.parseFromSliceLeaky(json.Value, gpa, text, .{}) catch return null;
    if (v != .object) return null;
    const metadata = v.object.get("commonInstanceMetadata") orelse return null;
    if (metadata != .object) return null;
    const items = metadata.object.get("items") orelse return null;
    if (items != .array) return null;
    for (items.array.items) |item| {
        if (item != .object) continue;
        const k = item.object.get("key") orelse continue;
        const value = item.object.get("value") orelse continue;
        if (k == .string and value == .string and mem.eql(u8, k.string, key)) return value.string;
    }
    return null;
}

/// cleanup removes only this run's machine, disk, firewall rule and the
/// images its create made, and refuses if any is left.
fn cleanup(t: *Gcp, howl: []const u8) !void {
    const c = t.c;
    const io = c.io;
    const gpa = c.gpa;
    const env: host.check.Options = .{ .environ_map = &c.env };
    var errors: std.ArrayList([]const u8) = .empty;
    const describe = [_][]const u8{
        "gcloud",
        "--quiet",
        "--project",
        t.project,
        "compute",
        "instances",
        "describe",
        t.name,
        "--zone",
        t.zone,
        "--format=value(name)",
    };
    var r = try host.check.command(io, gpa, &describe, env);
    // howl delete removes only this unique machine, its disk and its firewall.
    const delete = [_][]const u8{ howl, "delete", t.name, "--on", "gcp" };
    if (r.ok()) r = try host.check.command(io, gpa, &delete, env);
    if (!r.ok() and mem.find(u8, r.stderr, "was not found") == null)
        try errors.append(gpa, r.stderr);
    const log = Io.Dir.cwd().readFileAlloc(io, try t.at("create.log"), gpa, .unlimited) catch "";
    var made: Images = .{ .log = log };
    while (made.next()) |image| {
        const remove = [_][]const u8{
            "gcloud",
            "--quiet",
            "--project",
            t.project,
            "compute",
            "images",
            "delete",
            image,
        };
        const d = try host.check.command(io, gpa, &remove, env);
        if (!d.ok() and mem.find(u8, d.stderr, "was not found") == null)
            try errors.append(gpa, d.stderr);
    }
    const resources = [_][2][]const u8{
        .{ "instances", try gpa.print("name={s}", .{t.name}) },
        .{ "disks", try gpa.print("name={s}", .{t.name}) },
        .{ "firewall-rules", try gpa.print("name={s}-allow", .{t.name}) },
    };
    for (resources) |resource| {
        const kind = resource[0];
        const filter = resource[1];
        const names = "--format=value(name)";
        const remaining = try t.g(&.{ "compute", kind, "list", "--filter", filter, names });
        if (remaining.len > 0)
            try errors.append(gpa, try gpa.print("{s} left behind: {s}", .{ kind, remaining }));
    }
    if (errors.items.len > 0)
        return c.fail("cleanup failed: {s}", .{try mem.join(gpa, "\n", errors.items)});
    for (keys) |which| Io.Dir.cwd().deleteFile(io, try t.at(which)) catch {};
    c.say("CLEANED {s} and its image/firewall", .{t.name});
}

/// Images are the images howl create said it made, from its log.
const Images = struct {
    log: []const u8,
    from: usize = 0,

    fn next(it: *Images) ?[]const u8 {
        const lead = "howl: image ";
        while (mem.findPos(u8, it.log, it.from, lead)) |at| {
            it.from = at + 1;
            const start = at + lead.len;
            var end = start;
            while (end < it.log.len and isImageByte(it.log[end])) end += 1;
            if (end > start and mem.startsWith(u8, it.log[end..], ": making it"))
                return it.log[start..end];
        }
        return null;
    }
};

fn isImageByte(b: u8) bool {
    return std.ascii.isLower(b) or std.ascii.isDigit(b) or b == '-';
}

test "key rows, stamps and restoring only this run's project key" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    try std.testing.expectEqualStrings("2026-10-12T00:00:00+0000", try stamp(gpa, 1791763200));
    const key = "sk-ssh-ed25519@openssh.com AAAA";
    const row =
        \\fresh:sk-ssh-ed25519@openssh.com AAAA google-ssh {"userName": "fresh", "expireOn": "x"}
    ;
    try std.testing.expectEqualStrings(row, try googleKey(gpa, "fresh", key, "fresh", "x"));
    const line = "gcpcheckabc123:sk-ssh-ed25519 KEY\n";
    // Untouched: back to what it was, or to nothing.
    const alice = "alice:K\n" ++ line;
    const untouched = (try restoredKeys(gpa, "alice:K", alice, alice, line)).?;
    try std.testing.expectEqualStrings("alice:K", untouched);
    try std.testing.expectEqual(null, try restoredKeys(gpa, null, line, line, line));
    // Changed by someone else: only this run's line goes.
    const both = alice ++ "bob:K\n";
    const restored = (try restoredKeys(gpa, "alice:K", alice, both, line)).?;
    try std.testing.expectEqualStrings("alice:K\nbob:K\n", restored);
    try std.testing.expect(containsLine("a\n" ++ line, line));
    try std.testing.expect(!containsLine("a\ngcpcheckabc123:sk-ssh-ed25519 KEY extra\n", line));
    const reset = "kex_exchange_identification: read: Connection reset by peer";
    try std.testing.expect(transient(reset));
    try std.testing.expect(!transient("root@192.0.2.1: Permission denied (publickey)."));
    const info =
        \\{"commonInstanceMetadata": {"items": [{"key": "ssh-keys", "value": "a:b"}]}}
    ;
    try std.testing.expectEqualStrings("a:b", itemValue(gpa, info, "ssh-keys").?);
    const empty = "{\"commonInstanceMetadata\": {}}";
    try std.testing.expectEqual(null, itemValue(gpa, empty, "ssh-keys"));
    const said = "howl: image ww-1-a: making it from the disk\nhowl: image Bad: making it\n";
    var made: Images = .{ .log = said };
    try std.testing.expectEqualStrings("ww-1-a", made.next().?);
    try std.testing.expectEqual(null, made.next());
}

test "rotate replaces root's keys and keeps every other entry" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var out: Io.Writer.Allocating = .init(gpa);
    var w: std.tar.Writer = .{ .underlying_writer = &out.writer };
    try w.writeFileBytes("hostname", "gcp-metadata-check\n", .{ .mode = 0o600 });
    try w.writeFileBytes("./authorized_keys", "old key\n", .{ .mode = 0o600 });
    try w.finishPedantically();
    const rotated = try rotate(gpa, out.written(), "new key\n");
    var in: Io.Reader = .fixed(rotated);
    var name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const buffers: std.tar.Iterator.Options = .{
        .file_name_buffer = &name_buf,
        .link_name_buffer = &link_buf,
    };
    var it: std.tar.Iterator = .init(&in, buffers);
    const first = (try it.next()).?;
    try std.testing.expectEqualStrings("hostname", first.name);
    try std.testing.expectEqual(0o600, first.mode);
    const second = (try it.next()).?;
    var data: Io.Writer.Allocating = .init(gpa);
    try it.streamRemaining(second, &data.writer);
    try std.testing.expectEqualStrings("new key\n", data.written());
    try std.testing.expectEqual(null, try it.next());
}
