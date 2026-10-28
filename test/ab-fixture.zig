//! ab-fixture builds the private, self-contained signed releases a provider
//! A/B test boots (test/check-provider-ab.zig): A, which carries B and an
//! unhealthy candidate as signed update objects, and a disposable TLS
//! identity for the loopback channel that serves them. Only public boot
//! enrollment and that identity enter the guests; the host's signing keys
//! never do.

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;
const provider = host.provider;

pub const Inputs = struct {
    howl: []const u8,
    arch: []const u8,
    kernel: []const u8,
    key: []const u8,
    cert: []const u8,
    /// root is the empty directory the fixture is built in.
    root: []const u8,
    mode: []const u8,
    tpm: bool = false,
};

const channel = "https://127.0.0.1/image";

const form_yaml =
    \\base: prod-ssh
    \\packages: [openssl, caddy-werewolf]
    \\sshd:
    \\  pubkey-accepted-algorithms: ssh-ed25519
    \\  allow-agent-forwarding: "no"
    \\services:
    \\  ab-https:
    \\    exec: /usr/bin/caddy run --config /usr/share/ab/Caddyfile --adapter caddyfile
    \\    before: /usr/bin/mkdir -p -m 1777 /data/svc/ab-https/head
    \\    user: ab-https
    \\    pledge: stdio rpath wpath inet unix listen proc
    \\    listen: [tcp/443 loopback]
    \\    read: /usr/share/ab
    \\    share: shared
    \\    memory: 256
    \\weaknesses:
    \\  network-ssh-security-keys: disposable provider fixture accepts a test key file
    \\  network-no-login: the provider fixture is controlled through SSH
    \\  programs-no-downloaders: prod-ssh supplies busybox tools for the fixture operator
    \\  programs-no-interpreters: prod-ssh supplies busybox awk for the fixture operator
    \\  programs-no-shell: prod-ssh supplies the shell used by the fixture driver
    \\
;

// Caddy serves the releases from the image, and the channel's head from
// /data/svc/ab-https/head, where the test puts the release it chooses: an SSH
// session never writes a service's data (docs/design/implemented/ssh-hardening.md), so
// the service opens that one directory to it as it starts, and lets it
// through its own (share: shared).
const caddyfile =
    \\{
    \\    admin off
    \\    auto_https off
    \\    servers {
    \\        protocols h1
    \\    }
    \\}
    \\https://127.0.0.1 {
    \\    bind 127.0.0.1
    \\    tls /usr/share/ab/tls.crt /usr/share/ab/tls.key
    \\    @head path */latest.json */latest.json.sig
    \\    handle @head {
    \\        root * /data/svc/ab-https/head
    \\        file_server
    \\    }
    \\    handle {
    \\        root * /usr/share/ab/seed
    \\        file_server
    \\    }
    \\}
    \\
;

/// Release is one of the fixture's builds: its label, written into the
/// image as /usr/share/werewolf/ab-release, and how many minutes before
/// now its serial is. A is the newest, so B and bad are updates only in
/// order of selection, not of serial.
const Release = struct { label: []const u8, minutes: i64 };
const releases = [_]Release{
    .{ .label = "B", .minutes = 8 },
    .{ .label = "bad", .minutes = 6 },
    .{ .label = "A", .minutes = 10 },
};

/// probe_build is zig building test/ab-status.zig for the guest's ARCH, its
/// modules as the Makefile would give them. -target applies only to modules
/// declared after it, so it precedes the root: after, a Mac would build the
/// probe for itself.
const probe_build = "zig build-exe -O ReleaseSafe -fPIE -target {s}-linux-musl " ++
    "--dep cmdline --dep ipe --dep verity --dep tpm -Mroot=test/ab-status.zig " ++
    "--dep network -Mcmdline=lib/cmdline.zig -Mnetwork=lib/network.zig " ++
    "-Mipe=lib/ipe.zig -Mverity=lib/verity.zig --dep apk -Mtpm=lib/tpm.zig " ++
    "--dep package -Mapk=lib/apk.zig -Mpackage=lib/package.zig";

/// build makes the fixture in in.root and returns its fixture.json path.
pub fn build(c: *host.Check, in: Inputs) ![]const u8 {
    const io = c.io;
    const gpa = c.gpa;
    const cwd = Io.Dir.cwd();
    if (!mem.eql(u8, in.mode, "secure") and !mem.eql(u8, in.mode, "plain"))
        return c.fail("ab-fixture: mode must be secure or plain", .{});
    if (in.tpm and !mem.eql(u8, in.mode, "secure"))
        return c.fail("ab-fixture: TPM requires secure mode", .{});
    try cwd.createDirPath(io, in.root);
    var root = try cwd.openDir(io, in.root, .{ .iterate = true });
    defer root.close(io);
    var it = root.iterate();
    if (try it.next(io) != null) return c.fail("ab-fixture: destination must be empty", .{});
    try cwd.setFilePermissions(io, in.root, .fromMode(0o700), .{});
    var env = try c.env.clone(gpa);
    try env.put("COPYFILE_DISABLE", "1");
    for ([_][]const u8{ "WEREWOLF_BOOT_KEY", "WEREWOLF_BOOT_CRT", "UKI_ARGS", "UKI_NATIVE" }) |name|
        _ = env.swapRemove(name);

    const ca = try host.tls.Authority.init(io, gpa, "werewolf-ab-tls authority");
    const identity = try ca.issue(io, gpa, &.{"127.0.0.1"});
    const authority = try ca.pem(gpa);
    try root.writeFile(io, .{ .sub_path = "ca.crt", .data = authority });
    try root.writeFile(io, .{ .sub_path = "tls.crt", .data = try host.pem.chain(gpa, identity) });
    try root.writeFile(io, .{
        .sub_path = "tls.key",
        .data = try host.pem.key(gpa, identity),
        .flags = .{ .permissions = .fromMode(0o600) },
    });
    const ssh_key = try at(gpa, in.root, "ssh.key");
    const keygen = [_][]const u8{ "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", ssh_key };
    try step(c, in.root, &env, &keygen, "ssh-key");
    const probe = try at(gpa, in.root, "ab-status");
    try step(c, in.root, &env, try words(gpa, try gpa.print(
        probe_build ++ " -femit-bin={s}",
        .{ in.arch, probe },
    )), "probe");

    const dashed = try mem.replaceOwned(u8, gpa, in.arch, "_", "-");
    const name = try gpa.print("provider-ab-{s}-{s}", .{ in.mode, dashed });
    const form = try at(gpa, in.root, name);
    try cwd.createDir(io, form, .default_dir);
    try put(io, try at(gpa, form, "form.yaml"), form_yaml);
    const overlay = try at(gpa, form, "rootfs");
    for ([_][]const u8{ "usr/share/werewolf", "usr/share/ab", "usr/bin", "etc/ssl/certs" }) |d|
        try cwd.createDirPath(io, try at(gpa, overlay, d));
    try cwd.copyFile(probe, cwd, try at(gpa, overlay, "usr/bin/ab-status"), io, .{});
    // Caddy runs as ab-https; the key is the fixture's alone, disposable.
    for ([_][]const u8{ "tls.crt", "tls.key" }) |file| try cwd.copyFile(
        try at(gpa, in.root, file),
        cwd,
        try at(gpa, overlay, try gpa.print("usr/share/ab/{s}", .{file})),
        io,
        .{},
    );
    try put(io, try at(gpa, overlay, "usr/share/ab/Caddyfile"), caddyfile);
    try put(io, try at(gpa, overlay, "etc/ssl/certs/ca-certificates.crt"), authority);

    const secure = mem.eql(u8, in.mode, "secure");
    const boot_key = env.get("AB_BOOT_KEY") orelse in.key;
    const boot_cert = env.get("AB_BOOT_CRT") orelse in.cert;
    const now = Io.Clock.real.now(io).toSeconds();
    var manifests: json.ObjectMap = .empty;
    const seed = try at(gpa, in.root, "seed");
    try cwd.createDir(io, seed, .default_dir);
    var initial_serial: []const u8 = "";
    for (releases) |r| {
        const version = try serial(gpa, now - r.minutes * 60);
        const label = try gpa.print("{s}\n", .{r.label});
        try put(io, try at(gpa, overlay, "usr/share/werewolf/ab-release"), label);
        const health = try at(gpa, overlay, "etc/sv/ab-unhealthy");
        try cwd.deleteTree(io, health);
        if (mem.eql(u8, r.label, "bad")) {
            try cwd.createDirPath(io, health);
            try cwd.symLink(io, "/usr/bin/false", try at(gpa, health, "run"), .{});
        }
        if (mem.eql(u8, r.label, "A"))
            try host.check.copyTree(io, gpa, seed, try at(gpa, overlay, "usr/share/ab/seed"));
        try publicModes(io, gpa, overlay);
        const release = try at(gpa, in.root, try gpa.print("release-{s}", .{r.label}));
        const made = try provider.buildArgv(gpa, .{
            .howl = in.howl,
            .form = form,
            .arch = in.arch,
            .kernel = in.kernel,
            .key = in.key,
            .cert = in.cert,
            .build = try at(gpa, in.root, "build"),
            .channel = channel,
            .serial = version,
            .boot_key = if (secure) boot_key else null,
            .boot_cert = if (secure) boot_cert else null,
            .tpm = in.tpm,
            .index = if (!in.tpm or mem.eql(u8, r.label, "A"))
                1
            else if (mem.eql(u8, r.label, "B"))
                2
            else
                3,
        });
        try step(c, in.root, &env, made.argv, try gpa.print("build-{s}", .{r.label}));
        try provider.exportRelease(io, gpa, made.output, form, in.arch, release);
        if (secure) {
            const prefix = try gpa.print("{s}/{s}-{s}-", .{ release, name, in.arch });
            const uki_path = try gpa.print("{s}uki", .{prefix});
            const stage0_path = try gpa.print("{s}stage0.zst", .{prefix});
            const uki = try cwd.readFileAlloc(io, uki_path, gpa, .unlimited);
            const stage0 = try cwd.readFileAlloc(io, stage0_path, gpa, .unlimited);
            var why: host.check.Why = .{};
            host.evidence.nativeInitrd(uki, stage0, &why) catch
                return c.fail("ab-fixture: {s}", .{why.text});
        }
        const bundle = try at(gpa, made.output, try gpa.print("prebuilt/{s}", .{in.arch}));
        const latest_path = try at(gpa, bundle, "latest.json");
        const latest = try cwd.readFileAlloc(io, latest_path, gpa, .limited(4 << 20));
        const manifest = try json.parseFromSliceLeaky(json.Value, gpa, latest, .{});
        try manifests.put(gpa, r.label, manifest);
        if (mem.eql(u8, r.label, "A")) {
            initial_serial = version;
            continue;
        }
        const id = (if (manifest == .object) manifest.object.get("build") else null) orelse
            return c.fail("ab-fixture: release {s} names no build", .{r.label});
        if (id != .string or !plainName(id.string))
            return c.fail("ab-fixture: release {s} has a bad build name", .{r.label});
        const objects = try at(gpa, seed, try gpa.print("image/{s}", .{in.arch}));
        try cwd.createDirPath(io, objects);
        const from = try at(gpa, bundle, id.string);
        try host.check.copyTree(io, gpa, from, try at(gpa, objects, id.string));
        const heads = try at(gpa, seed, try gpa.print("heads/{s}", .{r.label}));
        try cwd.createDirPath(io, heads);
        for ([_][]const u8{ "latest.json", "latest.json.sig" }) |file|
            try cwd.copyFile(try at(gpa, bundle, file), cwd, try at(gpa, heads, file), io, .{});
    }
    const disk = try gpa.print("release-A/{s}-{s}-disk.qcow2", .{ name, in.arch });
    const result = try json.Stringify.valueAlloc(gpa, .{
        .arch = in.arch,
        .mode = in.mode,
        .tpm = in.tpm,
        .form = form,
        .channel = channel,
        .boot_key = boot_key,
        .boot_cert = boot_cert,
        .kernel = in.kernel,
        .key = in.key,
        .cert = in.cert,
        .initial_serial = initial_serial,
        .disk = try at(gpa, in.root, disk),
        .ssh_key = ssh_key,
        .releases = json.Value{ .object = manifests },
    }, .{ .whitespace = .indent_2 });
    const fixture = try at(gpa, in.root, "fixture.json");
    try put(io, fixture, try gpa.print("{s}\n", .{result}));
    c.say("pass   ab-fixture: signed A, B and unhealthy candidate; " ++
        "host signing keys excluded from guests", .{});
    return fixture;
}

/// step runs argv, its output in root/label.log, and fails with its tail.
fn step(
    c: *host.Check,
    root: []const u8,
    env: *const std.process.Environ.Map,
    argv: []const []const u8,
    label: []const u8,
) !void {
    const gpa = c.gpa;
    const log = try at(gpa, root, try gpa.print("{s}.log", .{label}));
    const options: host.check.Options = .{ .environ_map = env, .timeout = .fromSeconds(7200) };
    const r = host.check.command(c.io, gpa, argv, options) catch |err|
        return c.fail("ab-fixture: {s} failed: {t}", .{ label, err });
    const output = try mem.concat(gpa, u8, &.{ r.stdout, r.stderr });
    try put(c.io, log, output);
    if (!r.ok()) return c.fail("ab-fixture: {s} failed; log: {s}\n{s}", .{
        label, log, host.check.tail(output, 16000),
    });
}

/// words splits a command line written with single spaces into its words.
pub fn words(gpa: Allocator, line: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = mem.tokenizeScalar(u8, line, ' ');
    while (it.next()) |w| try out.append(gpa, w);
    return out.items;
}

fn at(gpa: Allocator, dir: []const u8, name: []const u8) ![]const u8 {
    return std.fs.path.join(gpa, &.{ dir, name });
}

fn put(io: Io, path: []const u8, data: []const u8) !void {
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
}

/// publicModes gives the overlay the modes an image wants: directories
/// and ab-status 0755, everything else 0644, links untouched.
fn publicModes(io: Io, gpa: Allocator, overlay: []const u8) !void {
    var dir = try Io.Dir.cwd().openDir(io, overlay, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |e| {
        if (e.kind == .sym_link) continue;
        const program = mem.eql(u8, e.basename, "ab-status");
        const mode: std.posix.mode_t = if (e.kind == .directory or program) 0o755 else 0o644;
        try dir.setFilePermissions(io, e.path, .fromMode(mode), .{ .follow_symlinks = false });
    }
}

/// serial is seconds since the epoch as an image serial, UTC:
/// YYYYMMDDTHHMMSSZ.
pub fn serial(gpa: Allocator, seconds: i64) ![]const u8 {
    const t: std.time.epoch.EpochSeconds = .{ .secs = @intCast(seconds) };
    const year = t.getEpochDay().calculateYearDay();
    const month = year.calculateMonthDay();
    const day = t.getDaySeconds();
    return gpa.print("{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        year.year,
        month.month.numeric(),
        month.day_index + 1,
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
        day.getSecondsIntoMinute(),
    });
}

/// plainName is whether a manifest's build ID can name a directory of its
/// own: no separators, not "." or "..".
fn plainName(s: []const u8) bool {
    return s.len > 0 and mem.findAny(u8, s, "/\\\x00") == null and
        !mem.eql(u8, s, ".") and !mem.eql(u8, s, "..");
}

test "serial is the UTC time an image's channel orders by" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    try std.testing.expectEqualStrings("20261012T000000Z", try serial(gpa, 1791763200));
    try std.testing.expectEqualStrings("19700101T000001Z", try serial(gpa, 1));
}

test "probe_build is the words of a zig command, and build IDs are plain names" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const argv = try words(arena.allocator(), probe_build);
    try std.testing.expectEqualStrings("zig", argv[0]);
    try std.testing.expectEqualStrings("-Mpackage=lib/package.zig", argv[argv.len - 1]);
    for (argv) |w| try std.testing.expect(w.len > 0);
    try std.testing.expect(plainName("20261012T000000Z-ab"));
    const bad = [_][]const u8{ "", ".", "..", "a/b", "a\\b" };
    for (bad) |name| try std.testing.expect(!plainName(name));
}
