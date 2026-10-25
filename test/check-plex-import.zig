//! check-plex-import [HOWL] exercises protected Plex import and sync in a
//! disposable Lima machine: the initial import's content, ownership and
//! mount protections, code refused from it, real decoding of imported
//! media, replay across cold restarts without reenrollment, live staging
//! that leaves media alone, a refused source link, drift repair, a refused
//! conflicting init, retry of a retained snapshot, and media surviving a
//! verified A/B update. The fixture adds operator SSH and two immutable
//! probes to Plex's form; no Plex account is needed. Host logs stay in
//! build/import-tests/NAME; only this test's machine is removed.

const std = @import("std");
const builtin = @import("builtin");
const host = @import("host");
const Io = std.Io;
const mem = std.mem;
const json = std.json;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "plex-import") catch std.process.exit(1);
    c.finish(run(&c));
}

const form_yaml =
    \\base: plex
    \\with: [sshd]
    \\sshd:
    \\  pubkey-accepted-algorithms: ssh-ed25519
    \\weaknesses:
    \\  network-no-login: operator SSH in the disposable import fixture
    \\  network-ssh-security-keys: disposable file key for automated operator SSH
    \\  programs-no-downloaders: SSH test shell tools
    \\  programs-no-interpreters: SSH test shell tools
    \\  programs-no-shell: SSH test shell
    \\
;

const Import = struct {
    c: *host.Check,
    name: []const u8,
    key: []const u8,
    form: []const u8,
    create: []const []const u8 = &.{},

    /// step runs argv, its output in label.log, and requires its outcome
    /// unless success is null.
    fn step(
        t: *Import,
        argv: []const []const u8,
        label: []const u8,
        success: ?bool,
        timeout: i64,
    ) ![]const u8 {
        const c = t.c;
        const cwd = Io.Dir.cwd();
        const log = try c.path(try c.gpa.print("{s}.log", .{label}));
        const options: host.check.Options = .{
            .environ_map = &c.env,
            .timeout = .fromSeconds(timeout),
        };
        const r = host.check.command(c.io, c.gpa, argv, options) catch |err| {
            try cwd.writeFile(c.io, .{ .sub_path = log, .data = @errorName(err) });
            return c.fail("{s}: {t}; see {s}", .{ label, err, log });
        };
        const output = try mem.concat(c.gpa, u8, &.{ r.stdout, r.stderr });
        try cwd.writeFile(c.io, .{ .sub_path = log, .data = output });
        if (success) |want| if (r.ok() != want)
            return c.fail("{s}: {f}; see {s}", .{ label, r.term, log });
        return output;
    }

    fn ssh(
        t: *Import,
        command: []const u8,
        label: []const u8,
        success: ?bool,
        timeout: i64,
    ) ![]const u8 {
        const c = t.c;
        const gpa = c.gpa;
        const list = [_][]const u8{ "limactl", "list", t.name, "--format", "{{.SSHLocalPort}}" };
        const listed = try host.check.command(c.io, gpa, &list, .{ .environ_map = &c.env });
        const port = mem.trim(u8, listed.stdout, " \t\r\n");
        if (!listed.ok()) return c.fail("limactl list {s}: {s}", .{ t.name, listed.stderr });
        _ = std.fmt.parseInt(u16, port, 10) catch return c.fail("no test VM SSH port", .{});
        const known = try gpa.print("UserKnownHostsFile={s}", .{try c.path("known_hosts")});
        return t.step(&.{
            "ssh",
            "-F",
            "/dev/null",
            "-S",
            "none",
            "-p",
            port,
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            known,
            "-i",
            t.key,
            "root@127.0.0.1",
            command,
        }, label, success, timeout);
    }

    /// ready waits for Plex and the probes, and returns their evidence
    /// once committed, of release when given.
    fn ready(t: *Import, label: []const u8, release: ?[]const u8) !json.Value {
        const io = t.c.io;
        const deadline = host.qemu.after(io, 180);
        const status_command = "test -f /run/svc/plex-media/ready && /usr/bin/import-status";
        while (before(io, deadline)) : (try io.sleep(.fromSeconds(1), .awake)) {
            const text = t.ssh(status_command, label, true, 10) catch continue;
            const status = json.parseFromSliceLeaky(json.Value, t.c.gpa, text, .{}) catch continue;
            if (!enforced(status))
                return t.c.fail("missing protected enforcement: {f}", .{json.fmt(status, .{})});
            if (!isTrue(field(status, "committed"))) continue;
            if (release) |want| if (!holds(status, "release", want)) continue;
            return status;
        }
        return t.c.fail("protected Plex/import fixture did not become ready", .{});
    }

    fn waitSsh(t: *Import, label: []const u8) !void {
        const io = t.c.io;
        const deadline = host.qemu.after(io, 60);
        while (before(io, deadline)) : (try io.sleep(.fromSeconds(1), .awake)) {
            _ = t.ssh("true", label, true, 10) catch continue;
            return;
        }
        return t.c.fail("operator SSH did not become ready", .{});
    }

    fn coldStart(t: *Import, label: []const u8) !json.Value {
        const gpa = t.c.gpa;
        const stop = [_][]const u8{ t.c.args[1], "stop", t.name };
        _ = try t.step(&stop, try gpa.print("{s}-stop", .{label}), true, 120);
        _ = try t.step(t.create, try gpa.print("{s}-create", .{label}), true, 1800);
        return t.ready(try gpa.print("{s}-ready", .{label}), null);
    }

    fn report(t: *Import, label: []const u8) void {
        t.c.say("pass   plex-import: {s}", .{label});
    }
};

/// enforced is whether import-status (test/ab-status.zig) reports every
/// boot protection on.
pub fn enforced(status: json.Value) bool {
    for ([_][]const u8{ "secure_boot", "ipe", "verified_root", "rollback_protected" }) |flag|
        if (!isTrue(field(status, flag))) return false;
    return true;
}

/// protectedImport is whether /proc/mounts mounts the import read-only,
/// without devices, setuid, execution or symlinks, exactly once.
pub fn protectedImport(mounts: []const u8) bool {
    var found: ?[]const u8 = null;
    var lines = mem.splitScalar(u8, mounts, '\n');
    while (lines.next()) |line| {
        var fields = mem.tokenizeAny(u8, line, " \t");
        _ = fields.next() orelse continue;
        const point = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const options = fields.next() orelse continue;
        if (!mem.eql(u8, point, "/run/werewolf/import")) continue;
        if (found != null) return false;
        found = options;
    }
    const options = found orelse return false;
    for ([_][]const u8{ "ro", "nosuid", "nodev", "noexec", "nosymfollow" }) |want| {
        var it = mem.splitScalar(u8, options, ',');
        while (it.next()) |o| {
            if (mem.eql(u8, o, want)) break;
        } else return false;
    }
    return true;
}

fn field(v: json.Value, key: []const u8) ?json.Value {
    return if (v == .object) v.object.get(key) else null;
}

fn isTrue(v: ?json.Value) bool {
    const x = v orelse return false;
    return x == .bool and x.bool;
}

fn holds(v: json.Value, key: []const u8, want: []const u8) bool {
    const got = field(v, key) orelse return false;
    return got == .string and mem.eql(u8, got.string, want);
}

fn write(c: *host.Check, path: []const u8, data: []const u8) !void {
    try Io.Dir.cwd().writeFile(c.io, .{ .sub_path = path, .data = data });
}

fn at(gpa: mem.Allocator, a: []const u8, b: []const u8) ![]const u8 {
    return std.fs.path.join(gpa, &.{ a, b });
}

/// before is whether deadline is still ahead.
fn before(io: Io, deadline: Io.Clock.Timestamp) bool {
    return Io.Clock.Timestamp.now(io, .awake).compare(.lt, deadline);
}

fn run(c: *host.Check) !void {
    const io = c.io;
    const gpa = c.gpa;
    const cwd = Io.Dir.cwd();
    const root = try std.process.currentPathAlloc(io, gpa);
    const howl = try c.absolute(if (c.args.len > 1) c.args[1] else "build/host/howl");
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64)
        return c.fail("check-plex-import currently uses protected Lima on macOS arm64", .{});
    var id: [5]u8 = undefined;
    io.random(&id);
    const name = try gpa.print("ww-plex-import-{s}", .{&std.fmt.bytesToHex(id, .lower)});
    try cwd.createDirPath(io, "build/import-tests");
    const work = try gpa.print("build/import-tests/{s}", .{name});
    try cwd.createDir(io, work, .fromMode(0o700));
    try c.setWork(work);
    const source = try c.path("source");
    try cwd.createDirPath(io, try at(gpa, source, "Movies"));
    try write(c, try at(gpa, source, "Movies/title.srt"), "original subtitle\n");
    try write(c, try at(gpa, source, "keep.txt"), "keep when absent from sync\n");
    const sample = try findSample(c, root);
    try cwd.copyFile(sample, cwd, try at(gpa, source, "Movies/sample.ts"), io, .{});
    const form = try c.path("plex-import-fixture");
    const overlay = try at(gpa, form, "rootfs");
    try cwd.createDirPath(io, try at(gpa, overlay, "usr/bin"));
    try cwd.createDirPath(io, try at(gpa, overlay, "usr/share/werewolf"));
    try write(c, try at(gpa, overlay, "usr/share/werewolf/ab-release"), "A\n");
    const config = try c.path("config");
    for ([_][]const u8{ "plex", "caddy" }) |service| {
        try cwd.createDirPath(io, try at(gpa, config, service));
        const settings = try at(gpa, config, try gpa.print("{s}/settings.json", .{service}));
        try write(c, settings, "{\"domain\":\"localhost\"}\n");
    }
    try write(c, try at(gpa, config, "plex/token"), "werewolf-test-owner-token-invalid\n");
    var t: Import = .{ .c = c, .name = name, .key = try c.path("ssh.key"), .form = form };
    const outcome = prepare(&t, root, howl, source, config);
    const cleaned = cleanup(c, howl, name);
    try outcome;
    if (!cleaned) return c.fail("test VM cleanup failed; see {s}", .{try c.path("cleanup.log")});
}

/// status_build is zig building test/ab-status.zig for the guest, its
/// modules as the Makefile would give them, but for -femit-bin.
const status_build = "zig build-exe -O ReleaseSafe -fstrip -fPIE -target aarch64-linux-musl " ++
    "--dep cmdline --dep ipe --dep tpm -Mroot=test/ab-status.zig " ++
    "--dep network -Mcmdline=lib/cmdline.zig -Mnetwork=lib/network.zig -Mipe=lib/ipe.zig " ++
    "--dep apk -Mtpm=lib/tpm.zig --dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig";

const probe_build = "zig build-exe -O ReleaseSafe -fstrip -fPIE -target aarch64-linux-musl " ++
    "test/plex-import-probe.zig";

/// prepare builds the fixture's probes and private runtime repository,
/// then runs the import lifecycle.
fn prepare(
    t: *Import,
    root: []const u8,
    howl: []const u8,
    source: []const u8,
    config: []const u8,
) !void {
    const c = t.c;
    const io = c.io;
    const gpa = c.gpa;
    const cwd = Io.Dir.cwd();
    const overlay = try at(gpa, t.form, "rootfs");
    const keygen = [_][]const u8{ "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", t.key };
    _ = try t.step(&keygen, "key", true, 120);
    const status = try at(gpa, overlay, "usr/bin/import-status");
    const status_line = try gpa.print("{s} -femit-bin={s}", .{ status_build, status });
    _ = try t.step(try words(gpa, status_line), "status-build", true, 600);
    const probe = try at(gpa, overlay, "usr/bin/import-probe");
    const probe_line = try gpa.print("{s} -femit-bin={s}", .{ probe_build, probe });
    _ = try t.step(try words(gpa, probe_line), "probe-build", true, 600);
    try cwd.copyFile(probe, cwd, try at(gpa, source, "untrusted-elf"), io, .{});
    try publicModes(c, overlay);
    t.create = try gpa.dupe([]const u8, &.{
        howl,
        "create",
        t.name,
        "--on",
        "lima",
        "--with",
        t.form,
        "--build",
        "--yes",
        "--config",
        config,
        "--root-keys",
        try gpa.print("{s}.pub", .{t.key}),
    });
    c.say("Building protected Plex fixture; logs: {s}", .{c.work});
    // The private musl runtime is not yet in the public feed. This
    // repository is local to the fixture, signed with a disposable key,
    // and never published.
    const repo = try c.path("runtime-repository");
    try cwd.createDir(io, repo, .default_dir);
    const signing = try at(gpa, repo, "import-test.rsa");
    const public = try at(gpa, repo, "import-test.rsa.pub");
    _ = try t.step(&.{ "openssl", "genrsa", "-out", signing, "2048" }, "repo-key", true, 120);
    const pubout = [_][]const u8{ "openssl", "rsa", "-in", signing, "-pubout", "-out", public };
    _ = try t.step(&pubout, "repo-public", true, 120);
    const parent = std.fs.path.dirname(root) orelse root;
    const recipes = [_][]const u8{
        try at(gpa, parent, "packages/devel/musl/musl.yaml"),
        try at(gpa, parent, "packages/multimedia/plex/plex.yaml"),
    };
    const pin = "{{.Package.Name}}={{.Package.Version}}-r{{.Package.Epoch}}";
    const file = "{{.Package.Name}}-{{.Package.Version}}-r{{.Package.Epoch}}";
    var pins: std.ArrayList([]const u8) = .empty;
    for (recipes) |recipe| try pins.append(gpa, try melangeQuery(c, recipe, pin));
    for ([_][]const u8{ "aarch64", "x86_64" }) |target| {
        const folder = try at(gpa, repo, target);
        try cwd.createDir(io, folder, .default_dir);
        var packages: std.ArrayList([]const u8) = .empty;
        for (recipes) |recipe| {
            const filename = try gpa.print("{s}.apk", .{try melangeQuery(c, recipe, file)});
            const runtime = try builtPackage(c, root, target, filename);
            const package = try at(gpa, folder, filename);
            try cwd.copyFile(runtime, cwd, package, io, .{});
            try packages.append(gpa, package);
            const recipe_name = std.fs.path.basename(std.fs.path.dirname(recipe).?);
            const label = try gpa.print("repo-sign-{s}-{s}", .{ target, recipe_name });
            const sign = [_][]const u8{ "melange", "sign", "--signing-key", signing, package };
            _ = try t.step(&sign, label, true, 600);
        }
        const index = try at(gpa, folder, "APKINDEX.tar.gz");
        const argv = try mem.concat(gpa, []const u8, &.{
            &.{ "melange", "index", "--signing-key", signing, "-o", index },
            packages.items,
        });
        _ = try t.step(argv, try gpa.print("repo-index-{s}", .{target}), true, 600);
    }
    // Ordinary file keys are explicit in this disposable operator-access fixture.
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(gpa, form_yaml);
    try text.print(gpa, "repositories:\n  - {f}\n", .{json.fmt(repo, .{})});
    try text.print(gpa, "keyring:\n  - {f}\npackages:\n", .{json.fmt(public, .{})});
    for (pins.items) |p| try text.print(gpa, "  - {f}\n", .{json.fmt(p, .{})});
    try write(c, try at(gpa, t.form, "form.yaml"), text.items);
    try lifecycle(t, source);
}

/// builtPackage is where a local build left a runtime package filename for target.
fn builtPackage(
    c: *host.Check,
    root: []const u8,
    target: []const u8,
    filename: []const u8,
) ![]const u8 {
    const gpa = c.gpa;
    const dirs = [_][]const u8{
        "build/vendor/packages",
        "build/plex-x86-src/build/vendor/packages",
    };
    for (dirs) |dir| {
        const candidate = try std.fs.path.join(gpa, &.{ root, dir, target, filename });
        if (Io.Dir.cwd().access(c.io, candidate, .{})) return candidate else |_| {}
    }
    return c.fail("build {s} for {s} before running this fixture", .{ filename, target });
}

/// words splits a command line written with single spaces into its words.
fn words(gpa: mem.Allocator, line: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = mem.tokenizeScalar(u8, line, ' ');
    while (it.next()) |w| try out.append(gpa, w);
    return out.items;
}

const media = "/data/svc/plex-media";
const title = "\"$(cat " ++ media ++ "/Movies/title.srt)\"";

const initial_content = "test " ++ title ++ " = 'original subtitle' && " ++
    "test \"$(stat -c %u " ++ media ++ "/Movies/sample.ts)\" = \"$(id -u plex-media)\" && " ++
    "test \"$(stat -c %a " ++ media ++ "/Movies/sample.ts)\" = 644";

const synced_content = "test " ++ title ++ " = 'updated subtitle' && " ++
    "test \"$(cat " ++ media ++ "/new.txt)\" = 'new file' && " ++
    "test \"$(cat " ++ media ++ "/keep.txt)\" = 'keep when absent from sync'";

const conflict_content = "test ! -e /run/svc/plex-media/ready && " ++
    "test " ++ title ++ " = 'updated subtitle' && " ++
    "test -f " ++ media ++ "/keep.txt";

const updated_content = "test " ++ title ++ " = 'updated subtitle' && " ++
    "test -f " ++ media ++ "/keep.txt && " ++
    "test -f " ++ media ++ "/new.txt";

fn lifecycle(t: *Import, source: []const u8) !void {
    const c = t.c;
    const io = c.io;
    const gpa = c.gpa;
    const cwd = Io.Dir.cwd();
    const howl = t.create[0];
    const first = try mem.concat(gpa, []const u8, &.{ t.create, &.{ "--import", source } });
    _ = try t.step(first, "initial-create", true, 1800);
    const initial = try t.ready("initial-ready", null);
    _ = try t.ssh(initial_content, "initial-content", true, 120);
    if (!protectedImport(try t.ssh("cat /proc/mounts", "mounts", true, 120)))
        return c.fail("import mount lost protections", .{});
    const map = "/usr/bin/import-probe map /run/werewolf/import/untrusted-elf";
    _ = try t.ssh(map, "mapping-denied", true, 120);
    const decode = "/usr/bin/import-probe decode " ++ media ++ "/Movies/sample.ts";
    const decoded = try t.ssh(decode, "decode-imported-media", true, 120);
    if (mem.find(u8, decoded, "#format: frame checksums") == null)
        return c.fail("imported media did not decode through the Plex worker", .{});
    t.report("protected init, ownership, mount flags, code refusal and real Plex decode");
    const again = try t.coldStart("replay");
    if (!sameAnchor(initial, again)) return c.fail("import replay changed TPM authority", .{});
    t.report("completed import survives cold restart without reenrollment");
    try write(c, try at(gpa, source, "Movies/title.srt"), "updated subtitle\n");
    try write(c, try at(gpa, source, "new.txt"), "new file\n");
    try cwd.deleteFile(io, try at(gpa, source, "keep.txt"));
    const sync = [_][]const u8{ howl, "sync", t.name, source };
    _ = try t.step(&sync, "stage-live-sync", true, 600);
    const machine = try gpa.print("build/machines/{s}", .{t.name});
    const import_json = try at(gpa, machine, "import.json");
    const selected = try cwd.readFileAlloc(io, import_json, gpa, .limited(1 << 20));
    var sync_id = try importId(c, selected);
    const unchanged = "test " ++ title ++ " = 'original subtitle'";
    _ = try t.ssh(unchanged, "live-media-unchanged", true, 120);
    t.report("staging while running leaves live media unchanged");
    try cwd.symLink(io, "/etc/passwd", try at(gpa, source, "escape"), .{});
    _ = try t.step(&sync, "reject-source-link", false, 600);
    const kept = try cwd.readFileAlloc(io, import_json, gpa, .limited(1 << 20));
    if (!mem.eql(u8, kept, selected))
        return c.fail("failed staging replaced the selected import", .{});
    try cwd.deleteFile(io, try at(gpa, source, "escape"));
    const synced = try t.coldStart("sync");
    _ = try t.ssh(synced_content, "synced-content", true, 120);
    if (!sameAnchor(initial, synced)) return c.fail("sync changed TPM authority", .{});
    t.report("sync updates files, keeps destination-only data and retains enrollment");
    const drift = "printf 'destination drift' > " ++ media ++ "/Movies/title.srt";
    _ = try t.ssh(drift, "introduce-destination-drift", true, 120);
    _ = try t.step(&sync, "stage-identical-source-again", true, 600);
    const next = try cwd.readFileAlloc(io, import_json, gpa, .limited(1 << 20));
    const next_id = try importId(c, next);
    if (mem.eql(u8, next_id, sync_id))
        return c.fail("an explicit sync reused a completed batch ID", .{});
    sync_id = next_id;
    _ = try t.coldStart("resync");
    const repaired = "test " ++ title ++ " = 'updated subtitle'";
    _ = try t.ssh(repaired, "resync-repairs-drift", true, 120);
    t.report("a new sync with identical source repairs destination drift");
    // A new init must refuse existing data: restart on the rejected batch,
    // then find the old data and no media readiness.
    const init_again = [_][]const u8{ howl, "import", t.name, source };
    _ = try t.step(&init_again, "stage-conflicting-init", true, 600);
    _ = try t.step(&.{ howl, "stop", t.name }, "conflict-stop", true, 120);
    _ = try t.step(t.create, "conflict-create", true, 1800);
    try t.waitSsh("conflict-ssh-ready");
    _ = try t.ssh(conflict_content, "init-conflict-preserves-data", true, 120);
    t.report("init refuses a populated destination without destroying data");
    const retry = [_][]const u8{ howl, "import", t.name, "--retry", sync_id };
    _ = try t.step(&retry, "restore-completed-sync", true, 600);
    const restored = try t.coldStart("restore");
    if (!sameAnchor(restored, initial)) return c.fail("import recovery changed TPM authority", .{});
    t.report("reselecting the retained completed snapshot recovers normal startup");
    const credentials = try at(gpa, machine, "authority/credentials/owner.auth");
    const owner = try host.check.digest(io, credentials);
    const overlay = try at(gpa, t.form, "rootfs");
    try write(c, try at(gpa, overlay, "usr/share/werewolf/ab-release"), "B\n");
    _ = try t.step(t.create, "publish-update", true, 1800);
    _ = try t.ssh("/usr/lib/werewolf/slot-update check", "update-check", true, 120);
    _ = try t.ssh("/usr/lib/werewolf/slot-update try", "update-try", null, 120);
    const updated = try t.ready("updated-ready", "B");
    _ = try t.ssh(updated_content, "updated-content", true, 120);
    if (sameField(updated, restored, "boot_id") or sameField(updated, restored, "root_hash"))
        return c.fail("A/B update did not boot its new verified root", .{});
    if (!mem.eql(u8, &try host.check.digest(io, credentials), &owner))
        return c.fail("image update replaced VM enrollment credentials", .{});
    t.report("imported and synced media survive a verified A/B image update");
}

fn sameField(a: json.Value, b: json.Value, key: []const u8) bool {
    const x = field(a, key) orelse return false;
    const y = field(b, key) orelse return false;
    return x == .string and y == .string and mem.eql(u8, x.string, y.string);
}

/// sameAnchor is whether two boots report one TPM authority.
fn sameAnchor(a: json.Value, b: json.Value) bool {
    const x = field(a, "tpm_anchor") orelse json.Value{ .null = {} };
    const y = field(b, "tpm_anchor") orelse json.Value{ .null = {} };
    if (x == .string and y == .string) return mem.eql(u8, x.string, y.string);
    if (x == .integer and y == .integer) return x.integer == y.integer;
    return x == .null and y == .null;
}

fn importId(c: *host.Check, text: []const u8) ![]const u8 {
    const v = json.parseFromSliceLeaky(json.Value, c.gpa, text, .{}) catch
        return c.fail("import.json is not JSON", .{});
    const id = field(v, "id") orelse return c.fail("import.json names no batch", .{});
    return switch (id) {
        .string => |s| s,
        .integer => |i| try c.gpa.print("{d}", .{i}),
        else => c.fail("import.json names no batch", .{}),
    };
}

fn melangeQuery(c: *host.Check, recipe: []const u8, template: []const u8) ![]const u8 {
    const r = try c.must(&.{ "melange", "query", recipe, template }, "", .{});
    return mem.trim(u8, r.stdout, " \t\r\n");
}

const sample_ts = "/usr/lib/plexmediaserver/Resources/black-h264.ts";
const no_sample = "build the Plex form first; its pinned sample TS is the media fixture";

/// findSample is Plex's own pinned sample transport stream, the media fixture.
fn findSample(c: *host.Check, root: []const u8) ![]const u8 {
    const io = c.io;
    const gpa = c.gpa;
    const pinned = try std.fs.path.join(gpa, &.{ root, "build/plex-inspect" ++ sample_ts });
    if (Io.Dir.cwd().access(io, pinned, .{})) return pinned else |_| {}
    var build = Io.Dir.cwd().openDir(io, "build", .{ .iterate = true }) catch
        return c.fail(no_sample, .{});
    defer build.close(io);
    var walker = try build.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |e| {
        if (e.kind != .file) continue;
        if (!mem.endsWith(u8, try gpa.print("/{s}", .{e.path}), "/melange" ++ sample_ts)) continue;
        return std.fs.path.join(gpa, &.{ root, "build", e.path });
    }
    return c.fail(no_sample, .{});
}

/// publicModes gives the overlay public directory modes and executable
/// probes, as the other protected fixtures have.
fn publicModes(c: *host.Check, overlay: []const u8) !void {
    var dir = try Io.Dir.cwd().openDir(c.io, overlay, .{ .iterate = true });
    defer dir.close(c.io);
    var walker = try dir.walk(c.gpa);
    defer walker.deinit();
    while (try walker.next(c.io)) |e| {
        const in_bin = mem.eql(u8, std.fs.path.dirname(e.path) orelse "", "usr/bin");
        const program = e.kind == .file and in_bin;
        const mode: std.posix.mode_t = if (e.kind == .directory or program) 0o755 else 0o644;
        try dir.setFilePermissions(c.io, e.path, .fromMode(mode), .{});
    }
}

/// cleanup keeps the machine's console and deletes it, and reports
/// whether the deletion worked.
fn cleanup(c: *host.Check, howl: []const u8, name: []const u8) bool {
    const io = c.io;
    const gpa = c.gpa;
    keepConsole(c, name);
    const log = c.path("cleanup.log") catch return false;
    const delete = [_][]const u8{ howl, "delete", name, "--on", "lima" };
    const options: host.check.Options = .{ .environ_map = &c.env, .timeout = .fromSeconds(180) };
    const r = host.check.command(io, gpa, &delete, options) catch return false;
    write(c, log, mem.concat(gpa, u8, &.{ r.stdout, r.stderr }) catch "") catch {};
    return r.ok();
}

fn keepConsole(c: *host.Check, name: []const u8) void {
    const io = c.io;
    const gpa = c.gpa;
    const list = [_][]const u8{ "limactl", "list", name, "--json" };
    const r = host.check.command(io, gpa, &list, .{ .environ_map = &c.env }) catch return;
    if (!r.ok()) return;
    const info = json.parseFromSliceLeaky(json.Value, gpa, r.stdout, .{}) catch return;
    const dir = field(info, "dir") orelse return;
    if (dir != .string) return;
    const serial = std.fs.path.join(gpa, &.{ dir.string, "serial.log" }) catch return;
    const data = Io.Dir.cwd().readFileAlloc(io, serial, gpa, .unlimited) catch return;
    write(c, c.path("console.log") catch return, data) catch {};
}

test "the import mount keeps every protection, once" {
    const line = "/dev/vdc /run/werewolf/import ext4 ";
    const relatime = line ++ "ro,nosuid,nodev,noexec,nosymfollow,relatime 0 0\n";
    try std.testing.expect(protectedImport(relatime));
    try std.testing.expect(!protectedImport(line ++ "ro,nosuid,nodev,noexec 0 0\n"));
    try std.testing.expect(!protectedImport(line ++ "rw,nosuid,nodev,noexec,nosymfollow 0 0\n"));
    try std.testing.expect(!protectedImport("/dev/vda /data ext4 rw 0 0\n"));
    const once = line ++ "ro,nosuid,nodev,noexec,nosymfollow 0 0\n";
    try std.testing.expect(protectedImport(once));
    try std.testing.expect(!protectedImport(once ++ once));
}

test "enforcement needs every boot protection" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const flags = [_][]const u8{ "secure_boot", "ipe", "verified_root", "rollback_protected" };
    const good =
        \\{"secure_boot":true,"ipe":true,"verified_root":true,"rollback_protected":true}
    ;
    try std.testing.expect(enforced(try json.parseFromSliceLeaky(json.Value, gpa, good, .{})));
    for (flags) |flag| {
        const on = try gpa.print("\"{s}\":true", .{flag});
        const off = try gpa.print("\"{s}\":false", .{flag});
        const bad = try mem.replaceOwned(u8, gpa, good, on, off);
        try std.testing.expect(!enforced(try json.parseFromSliceLeaky(json.Value, gpa, bad, .{})));
    }
}

test "the guest's checks name the media they expect" {
    try std.testing.expect(mem.find(u8, synced_content, "'keep when absent from sync'") != null);
    try std.testing.expect(mem.endsWith(u8, updated_content, "/data/svc/plex-media/new.txt"));
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const argv = try words(arena.allocator(), status_build);
    try std.testing.expectEqualStrings("-Mpackage=lib/package.zig", argv[argv.len - 1]);
}
