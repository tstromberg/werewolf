//! check-bhyve-lifecycle HOST ARCH DISK.zst KEY [tap|slirp] [SECONDS] runs
//! a private copy of a prebuilt playground disk through howl's bhyve
//! create, supervisor, stop, restart and delete on HOST, with KEY a
//! disposable SSH identity. It checks the source disk offline, sustained
//! 64 MiB SSH transfers, three guest reboots, persistent checksums, and the
//! data partition's ext4 after stop. It needs passwordless doas, firmware,
//! and a bridge for TAP; it makes no bridge, address, route or firewall
//! rule. Logs and disk evidence stay in build/bhyve-validation/NAME; a failed
//! run keeps its remote directory. A seeded machine record keeps the FreeBSD
//! host from rebuilding the supplied image.

const std = @import("std");
const host = @import("host");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const json = std.json;
const join = host.check.join;

pub fn main(init: std.process.Init) void {
    var c = host.Check.init(init, "bhyve-lifecycle") catch std.process.exit(1);
    c.finish(run(&c));
}

const Result = host.check.Result;

const Life = struct {
    c: *host.Check,
    host: []const u8,
    mode: []const u8,
    name: []const u8,
    key: []const u8,
    remote_dir: ?[]const u8 = null,
    machine: []const u8 = "",
    address: []const u8 = "",
    port: []const u8 = "",
    phases: std.ArrayList(json.Value) = .empty,

    /// cmd runs argv here, logging it and its errors to host.log.
    fn cmd(l: *Life, argv: []const []const u8, must: bool, timeout: i64) !Result {
        const c = l.c;
        const gpa = c.gpa;
        const line = try join(gpa, argv);
        const short = try join(gpa, argv[0..@min(5, argv.len)]);
        const log = try c.path("host.log");
        const options: host.check.Options = .{
            .environ_map = &c.env,
            .timeout = .fromSeconds(timeout),
        };
        const r = host.check.command(c.io, gpa, argv, options) catch |err| {
            try host.check.append(c.io, log, try gpa.print("{s}\n({t})\n", .{ line, err }));
            return c.fail("{s}: {t}", .{ short, err });
        };
        try host.check.append(c.io, log, try gpa.print("{s}\n{s}", .{ line, r.stderr }));
        if (must and !r.ok())
            return c.fail("{s}: {s}", .{ short, host.check.tail(r.stderr, 4000) });
        return r;
    }

    fn remote(l: *Life, argv: []const []const u8, must: bool) !Result {
        const command = try join(l.c.gpa, argv);
        return l.cmd(&.{ "ssh", "-o", "BatchMode=yes", l.host, command }, must, 240);
    }

    fn howl(l: *Life, args: []const []const u8) !Result {
        const gpa = l.c.gpa;
        var command: std.ArrayList([]const u8) = .empty;
        try command.append(gpa, "env");
        for ([_][]const u8{ "BHYVE_BINARY", "BHYVE_ARM64_FIRMWARE" }) |name| {
            const value = l.c.env.get(name) orelse continue;
            try command.append(gpa, try gpa.print("{s}={s}", .{ name, value }));
        }
        try command.append(gpa, "./howl-freebsd");
        try command.appendSlice(gpa, args);
        const dir = try host.check.quote(gpa, l.remote_dir.?);
        const script = try gpa.print("cd {s} && {s}", .{ dir, try join(gpa, command.items) });
        return l.remote(&.{ "sh", "-c", script }, true);
    }

    fn report(l: *Life, phase: []const u8, facts: anytype) !void {
        const gpa = l.c.gpa;
        const given = try json.Stringify.valueAlloc(gpa, facts, .{});
        var record = try json.parseFromSliceLeaky(json.Value, gpa, given, .{});
        try record.object.put(gpa, "phase", .{ .string = phase });
        try l.phases.append(gpa, record);
        const options: json.Stringify.Options = .{ .whitespace = .indent_2 };
        const text = try json.Stringify.valueAlloc(gpa, l.phases.items, options);
        try write(l.c, try l.c.path("phases.json"), try gpa.print("{s}\n", .{text}));
        l.c.say("{s} {s}: {s}", .{ l.host, l.mode, phase });
    }

    /// console keeps the guest's console and refuses any storage, kernel
    /// or updater error on it.
    fn console(l: *Life) !void {
        const log = try l.c.gpa.print("{s}/console.log", .{l.machine});
        const data = (try l.remote(&.{ "cat", log }, false)).stdout;
        try write(l.c, try l.c.path("console.log"), data);
        if (fault(data))
            return l.c.fail("guest storage, kernel or updater error; see console.log", .{});
    }

    fn guest(l: *Life, command: []const u8, must: bool, timeout: i64) !Result {
        const gpa = l.c.gpa;
        const target = try gpa.print("{s}:{s}", .{ l.address, l.port });
        const proxy = try join(gpa, &.{ "ssh", "-o", "BatchMode=yes", l.host, "-W", target });
        const known = try gpa.print("UserKnownHostsFile={s}", .{try l.c.path("known_hosts")});
        return l.cmd(&.{
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            known,
            "-o",
            try gpa.print("HostKeyAlias={s}", .{l.name}),
            "-o",
            "ConnectTimeout=5",
            "-o",
            try gpa.print("ProxyCommand={s}", .{proxy}),
            "-i",
            l.key,
            "root@127.0.0.1",
            command,
        }, must, timeout);
    }

    /// ready waits for the guest to answer SSH with a boot ID not previous.
    fn ready(l: *Life, previous: ?[]const u8) ![]const u8 {
        const io = l.c.io;
        const deadline = host.qemu.after(io, 120);
        while (before(io, deadline)) : (try io.sleep(.fromSeconds(2), .awake)) {
            try l.console();
            const r = try l.guest("cat /proc/sys/kernel/random/boot_id", false, 15);
            const boot = mem.trim(u8, r.stdout, " \t\r\n");
            if (!r.ok() or boot.len == 0) continue;
            if (previous) |p| if (mem.eql(u8, boot, p)) continue;
            return boot;
        }
        return l.c.fail("guest did not become ready with a fresh boot ID", .{});
    }

    /// settings reads howl's record of the machine's SSH address and port.
    fn settings(l: *Life) !void {
        const path = try l.c.gpa.print("{s}/machine", .{l.machine});
        const record = (try l.remote(&.{ "cat", path }, true)).stdout;
        l.address = recordValue(record, "host") orelse
            return l.c.fail("machine record names no host", .{});
        l.port = recordValue(record, "ssh") orelse
            return l.c.fail("machine record names no ssh port", .{});
    }

    fn checksum(l: *Life) ![]const u8 {
        const out = (try l.guest("sha256sum /data/lifecycle.bin", true, 240)).stdout;
        var words = mem.tokenizeAny(u8, out, " \t\r\n");
        return words.next() orelse l.c.fail("sha256sum said nothing", .{});
    }

    /// filesystem checks the data partition of raw from a private copy,
    /// never a mounted disk: journal recovery alone must make it clean.
    fn filesystem(l: *Life, raw: []const u8, label: []const u8) !void {
        const c = l.c;
        const io = c.io;
        const gpa = c.gpa;
        const target = try c.path(try gpa.print("{s}-data.ext4", .{label}));
        try extract(c, raw, target);
        const homebrew = "/opt/homebrew/opt/e2fsprogs/sbin/e2fsck";
        const fsck = host.consumer.which(io, gpa, &c.env, "e2fsck") orelse homebrew;
        if (!mem.eql(u8, label, "before")) {
            // A full preen also refreshes superblock free counts from the
            // recovered group descriptors; journal_only leaves them stale.
            const replay = try l.cmd(&.{ fsck, "-p", target }, false, 600);
            const log = try c.path(try gpa.print("{s}-journal.log", .{label}));
            try write(c, log, try mem.concat(gpa, u8, &.{ replay.stdout, replay.stderr }));
            if (!replay.ok())
                return c.fail("filesystem needs repairs beyond normal journal recovery", .{});
        }
        const result = try l.cmd(&.{ fsck, "-fn", target }, false, 600);
        const log = try c.path(try gpa.print("{s}-fsck.log", .{label}));
        try write(c, log, try mem.concat(gpa, u8, &.{ result.stdout, result.stderr }));
        if (!result.ok() or mem.find(u8, result.stdout, "Fix? no") != null)
            return c.fail("{s}: offline filesystem check failed", .{label});
        try Io.Dir.cwd().deleteFile(io, target);
        try l.report(try gpa.print("{s}: offline ext4 check clean", .{label}), .{});
    }
};

/// extract copies raw's data partition, werewolf's second, to target.
fn extract(c: *host.Check, raw: []const u8, target: []const u8) !void {
    const io = c.io;
    const disk = try Io.Dir.cwd().openFile(io, raw, .{});
    defer disk.close(io);
    var header: [512]u8 = undefined;
    if (try disk.readPositionalAll(io, &header, 512) != 512) return c.fail("disk is not GPT", .{});
    var why: host.check.Why = .{};
    const table = gptTable(&header, &why) catch return c.fail("{s}", .{why.text});
    var entry_buf: [4096]u8 = undefined;
    if (table.entry_size > entry_buf.len) return c.fail("disk is not GPT", .{});
    const entry = entry_buf[0..table.entry_size];
    const second = table.lba * 512 + table.entry_size;
    if (try disk.readPositionalAll(io, entry, second) != entry.len)
        return c.fail("truncated partition table", .{});
    const extent = dataExtent(entry, &why) catch return c.fail("{s}", .{why.text});
    const out = try Io.Dir.cwd().createFile(io, target, .{});
    defer out.close(io);
    var buf: [1 << 20]u8 = undefined;
    var at: u64 = 0;
    while (at < extent.len) {
        const want: usize = @intCast(@min(buf.len, extent.len - at));
        const n = try disk.readPositionalAll(io, buf[0..want], extent.start + at);
        if (n == 0) return c.fail("truncated data partition", .{});
        try out.writePositionalAll(io, buf[0..n], at);
        at += n;
    }
}

/// before is whether deadline is still ahead.
fn before(io: Io, deadline: Io.Clock.Timestamp) bool {
    return Io.Clock.Timestamp.now(io, .awake).compare(.lt, deadline);
}

/// fault is whether a console shows a storage, kernel or updater error.
pub fn fault(console: []const u8) bool {
    for ([_][]const u8{
        "EXT4-fs error",
        "Corrupt filesystem",
        "Kernel panic",
        "worker setup:",
        "failed CRC",
    }) |sign|
        if (mem.find(u8, console, sign) != null) return true;
    return false;
}

/// recordValue is the value of a "KEY VALUE" line of howl's machine record.
pub fn recordValue(record: []const u8, key: []const u8) ?[]const u8 {
    var lines = mem.splitScalar(u8, record, '\n');
    while (lines.next()) |line| {
        const space = mem.findScalar(u8, line, ' ') orelse continue;
        if (mem.eql(u8, line[0..space], key)) return line[space + 1 ..];
    }
    return null;
}

pub const Table = struct { lba: u64, entry_size: u32 };

/// gptTable reads a GPT header's partition table location.
pub fn gptTable(header: *const [512]u8, why: *host.check.Why) !Table {
    if (!mem.eql(u8, header[0..8], "EFI PART")) return why.refuse("disk is not GPT", .{});
    const size = mem.readInt(u32, header[84..88], .little);
    if (size < 128) return why.refuse("disk is not GPT", .{});
    return .{ .lba = mem.readInt(u64, header[72..80], .little), .entry_size = size };
}

pub const Extent = struct { start: u64, len: u64 };

/// dataExtent is where a GPT entry's partition lies, in bytes.
pub fn dataExtent(entry: []const u8, why: *host.check.Why) !Extent {
    const first = mem.readInt(u64, entry[32..40], .little);
    const last = mem.readInt(u64, entry[40..48], .little);
    if (last < first) return why.refuse("invalid data partition", .{});
    return .{ .start = first * 512, .len = (last - first + 1) * 512 };
}

fn write(c: *host.Check, file: []const u8, data: []const u8) !void {
    try Io.Dir.cwd().writeFile(c.io, .{ .sub_path = file, .data = data });
}

const usage = "usage: check-bhyve-lifecycle HOST ARCH DISK.zst KEY [tap|slirp] [SECONDS]";

fn run(c: *host.Check) !void {
    const io = c.io;
    const gpa = c.gpa;
    const cwd = Io.Dir.cwd();
    if (c.args.len < 5 or c.args.len > 7) return c.fail("{s}", .{usage});
    const host_name = c.args[1];
    const arch = c.args[2];
    const image = c.args[3];
    const mode = if (c.args.len > 5) c.args[5] else "tap";
    const seconds = if (c.args.len > 6)
        std.fmt.parseInt(i64, c.args[6], 10) catch return c.fail("SECONDS must be a number", .{})
    else
        180;
    const known_arch = mem.eql(u8, arch, "x86_64") or mem.eql(u8, arch, "aarch64");
    const known_mode = mem.eql(u8, mode, "tap") or mem.eql(u8, mode, "slirp");
    if (!known_arch or !known_mode) return c.fail("invalid architecture or network backend", .{});
    if (!validHost(host_name)) return c.fail("invalid host", .{});
    var id: [5]u8 = undefined;
    io.random(&id);
    const name = try gpa.print("wwlife-{s}", .{&std.fmt.bytesToHex(id, .lower)});
    const work = try gpa.print("build/bhyve-validation/{s}", .{name});
    try cwd.createDirPath(io, "build/bhyve-validation");
    try cwd.createDir(io, work, .fromMode(0o700));
    try c.setWork(work);
    var l: Life = .{
        .c = c,
        .host = host_name,
        .mode = mode,
        .name = name,
        .key = try c.absolute(c.args[4]),
    };
    var loaded_vmm = false;
    var started = false;
    var passed = false;
    defer {
        if (started) {
            // Stop through the root supervisor, not kill -0 from an unprivileged shell.
            _ = l.howl(&.{ "stop", name, "--on", "bhyve" }) catch {};
            const log = gpa.print("{s}/console.log", .{l.machine}) catch "";
            if (l.remote(&.{ "cat", log }, false)) |r|
                write(c, c.path("console.log") catch "", r.stdout) catch {}
            else |_| {}
        }
        if (loaded_vmm) _ = l.remote(&.{ "doas", "-n", "kldunload", "vmm" }, false) catch {};
        if (passed) {
            _ = l.remote(&.{ "doas", "-n", "rm", "-rf", l.remote_dir.? }, true) catch {};
        } else if (l.remote_dir) |dir| {
            std.log.err("Retained failed test evidence on {s}:{s}", .{ host_name, dir });
        }
        c.say("Evidence: {s}", .{c.work});
    }

    const binary = try gpa.print("build/{s}/tools/howl-freebsd", .{arch});
    _ = try l.cmd(&.{ "make", binary }, true, 600);
    const raw = try c.path("before.img");
    _ = try l.cmd(&.{ "zstd", "-d", "-q", image, "-o", raw }, true, 240);
    try l.filesystem(raw, "before");
    try cwd.deleteFile(io, raw);
    const mktemp = [_][]const u8{ "mktemp", "-d", "/var/tmp/ww-lifecycle.XXXXXXXX" };
    const made = mem.trim(u8, (try l.remote(&mktemp, true)).stdout, " \t\r\n");
    if (!privateDir(made)) return c.fail("invalid temporary directory", .{});
    l.remote_dir = made;
    const where = .{ .host = host_name, .directory = made, .name = name };
    try write(c, try c.path("remote.json"), try json.Stringify.valueAlloc(gpa, where, .{}));
    l.machine = try gpa.print("{s}/build/machines/{s}", .{ made, name });
    const assets = try c.path("assets.tar");
    try write(c, assets, try seed(c, name, l.key));
    const to = try gpa.print("{s}:{s}/", .{ host_name, made });
    _ = try l.cmd(&.{ "scp", "-q", try c.absolute(binary), assets, image, to }, true, 600);
    const unpack = try gpa.print("{s}/assets.tar", .{made});
    _ = try l.remote(&.{ "tar", "-xf", unpack, "-C", made }, true);
    const shipped = try gpa.print("{s}/{s}", .{ made, std.fs.path.basename(image) });
    const disk = try gpa.print("{s}/disk.img", .{l.machine});
    _ = try l.remote(&.{ "zstd", "-d", "-q", shipped, "-o", disk }, true);
    if (!(try l.remote(&.{ "kldstat", "-q", "-m", "vmm" }, false)).ok()) {
        _ = try l.remote(&.{ "doas", "-n", "kldload", "vmm" }, true);
        loaded_vmm = true;
    }
    var create: std.ArrayList([]const u8) = .empty;
    try create.appendSlice(gpa, &.{ "create", name, "--with", "playground", "--build" });
    try create.appendSlice(gpa, &.{ "--on", "bhyve", "--disable=secureboot,tpm,ipe" });
    try create.appendSlice(gpa, &.{ "--network", mode, "--config", "test-config" });
    if (c.env.get("BHYVE_BRIDGE")) |bridge| try create.appendSlice(gpa, &.{ "--bridge", bridge });
    if (c.env.get("BHYVE_TEST_IP")) |ip| {
        const gw = c.env.get("BHYVE_TEST_GW") orelse
            return c.fail("BHYVE_TEST_IP needs BHYVE_TEST_GW", .{});
        try create.appendSlice(gpa, &.{ "--ip", ip, "--gw", gw, "--dns", gw });
    }
    started = true;
    _ = try l.howl(create.items);
    try l.settings();
    var boot = try l.ready(null);
    const said = mem.trim(u8, (try l.guest("date +%s", true, 240)).stdout, " \t\r\n");
    const guest_time = std.fmt.parseInt(i64, said, 10) catch
        return c.fail("guest clock unreadable", .{});
    if (@abs(guest_time - Io.Clock.real.now(io).toSeconds()) > 300)
        return c.fail("guest clock differs by more than 300 seconds", .{});
    try l.report("guest clock verified", .{ .unix_time = guest_time });
    const ready = .{ .boot_id = boot, .address = l.address, .port = l.port };
    try l.report("howl create and SSH ready", ready);
    const fill = "dd if=/dev/urandom of=/data/lifecycle.bin bs=1048576 count=64";
    _ = try l.guest(fill, true, 120);
    _ = try l.guest("sync", true, 240);
    const expected = try l.checksum();
    const until = host.qemu.after(io, seconds);
    var transfers: u64 = 0;
    while (before(io, until)) : (try io.sleep(.fromSeconds(1), .awake)) {
        const data = (try l.guest("cat /data/lifecycle.bin", true, 120)).stdout;
        var sum: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &sum, .{});
        if (!mem.eql(u8, &std.fmt.bytesToHex(sum, .lower), expected))
            return c.fail("SSH transfer checksum differs", .{});
        transfers += 1;
        const progress = .{ .completed = transfers, .bytes = transfers * (64 << 20) };
        const record = try json.Stringify.valueAlloc(gpa, progress, .{});
        try write(c, try c.path("transfers.json"), record);
        try l.console();
    }
    try l.report("sustained network and storage checks passed", .{
        .seconds = seconds,
        .transfers = transfers,
        .bytes = transfers * (64 << 20),
        .sha256 = expected,
    });
    for (1..4) |iteration| {
        _ = try l.guest("sync", true, 240);
        _ = try l.guest("reboot", false, 20);
        boot = try l.ready(boot);
        if (!mem.eql(u8, try l.checksum(), expected))
            return c.fail("persistent file changed across reboot", .{});
        const done = .{ .iteration = iteration, .boot_id = boot };
        try l.report("guest reboot and persistent checksum passed", done);
    }
    _ = try l.guest("sync", true, 240);
    _ = try l.howl(&.{ "stop", name, "--on", "bhyve" });
    const vmm = try gpa.print("/dev/vmm/{s}", .{name});
    const survived = (try l.remote(&.{ "test", "-e", vmm }, false)).ok();
    if (survived) return c.fail("VM survived howl stop", .{});
    try l.report("howl stop removed VM", .{});
    const packed_after = try gpa.print("{s}/after.img.zst", .{made});
    _ = try l.remote(&.{ "zstd", "-q", disk, "-o", packed_after }, true);
    const fetched = try gpa.print("{s}:{s}", .{ host_name, packed_after });
    _ = try l.cmd(&.{ "scp", "-q", fetched, c.work }, true, 600);
    const after = try c.path("after.img");
    _ = try l.cmd(&.{ "zstd", "-d", "-q", try c.path("after.img.zst"), "-o", after }, true, 240);
    try l.filesystem(after, "after");
    try cwd.deleteFile(io, after);
    _ = try l.howl(create.items);
    try l.settings();
    boot = try l.ready(boot);
    if (!mem.eql(u8, try l.checksum(), expected))
        return c.fail("persistent file changed across stop/start", .{});
    try l.report("howl restart preserves data", .{ .boot_id = boot });
    try l.console();
    _ = try l.howl(&.{ "delete", name, "--on", "bhyve" });
    started = false;
    try l.report("howl delete completed", .{});
    passed = true;
}

/// seed is the tar a remote run unpacks: the forms, and the machine record
/// that keeps howl from rebuilding the supplied image.
fn seed(c: *host.Check, name: []const u8, key: []const u8) ![]const u8 {
    const io = c.io;
    const gpa = c.gpa;
    var out: Io.Writer.Allocating = .init(gpa);
    var tar: std.tar.Writer = .{ .underlying_writer = &out.writer };
    try host.provider.packTree(io, gpa, &tar, "forms", "forms");
    const pub_path = try gpa.print("{s}.pub", .{key});
    const public = try Io.Dir.cwd().readFileAlloc(io, pub_path, gpa, .limited(64 << 10));
    const record = try gpa.print("build/machines/{s}", .{name});
    const private: std.tar.Writer.Options = .{ .mode = 0o600 };
    try tar.writeFileBytes(try gpa.print("{s}/form", .{record}), "playground\n", private);
    try tar.writeFileBytes(try gpa.print("{s}/engine", .{record}), "bhyve\n", private);
    try tar.writeFileBytes("test-config/authorized_keys", public, private);
    try tar.finishPedantically();
    return out.written();
}

/// validHost is whether h is a plain host name ssh will not read as an option.
pub fn validHost(h: []const u8) bool {
    if (h.len == 0 or h[0] == '-') return false;
    for (h) |b| if (!std.ascii.isAlphanumeric(b) and
        mem.findScalar(u8, "_.-", b) == null) return false;
    return true;
}

/// privateDir is whether d is mktemp's directory, the only one removed.
pub fn privateDir(d: []const u8) bool {
    const prefix = "/var/tmp/ww-lifecycle.";
    if (!mem.startsWith(u8, d, prefix) or d.len == prefix.len) return false;
    for (d[prefix.len..]) |b| if (!std.ascii.isAlphanumeric(b)) return false;
    return true;
}

test "the lifecycle refuses hosts and directories it cannot trust" {
    try std.testing.expect(validHost("smaug"));
    try std.testing.expect(validHost("bilbo.lan"));
    for ([_][]const u8{ "", "-oProxyCommand=x", "a b", "user@host", "h;x" }) |bad|
        try std.testing.expect(!validHost(bad));
    try std.testing.expect(privateDir("/var/tmp/ww-lifecycle.Ab12cD34"));
    for ([_][]const u8{
        "/var/tmp/ww-lifecycle.",
        "/tmp/ww-lifecycle.a",
        "/var/tmp/ww-lifecycle.a/b",
    }) |bad|
        try std.testing.expect(!privateDir(bad));
}

test "console faults, machine records and GPT extents" {
    try std.testing.expect(fault("[ 3.1] EXT4-fs error (device vda2)\n"));
    try std.testing.expect(fault("autoupdate: worker setup: denied\n"));
    try std.testing.expect(!fault("werewolf: up in 1s, handing over to runit\n"));
    const record = "host 192.0.2.2\nssh 22\nform playground\n";
    try std.testing.expectEqualStrings("192.0.2.2", recordValue(record, "host").?);
    try std.testing.expectEqualStrings("22", recordValue(record, "ssh").?);
    try std.testing.expectEqual(null, recordValue(record, "web"));
    var why: host.check.Why = .{};
    var header: [512]u8 = @splat(0);
    try std.testing.expectError(error.Refused, gptTable(&header, &why));
    @memcpy(header[0..8], "EFI PART");
    mem.writeInt(u64, header[72..80], 2, .little);
    mem.writeInt(u32, header[84..88], 128, .little);
    const t = try gptTable(&header, &why);
    try std.testing.expectEqual(2, t.lba);
    try std.testing.expectEqual(128, t.entry_size);
    var entry: [128]u8 = @splat(0);
    mem.writeInt(u64, entry[32..40], 4096, .little);
    mem.writeInt(u64, entry[40..48], 4096 + 2047, .little);
    const e = try dataExtent(&entry, &why);
    try std.testing.expectEqual(4096 * 512, e.start);
    try std.testing.expectEqual(2048 * 512, e.len);
}
