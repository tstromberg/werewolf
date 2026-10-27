//! The cloud boots' assertions inside the machine (test/cloud-boot): prod
//! took its config from a stand-in metadata server (test/metadata.zig),
//! which names the boot in the hostname it serves. cloud-check took a good
//! config; cloud-poll a good one, then one naming tom; cloud-reapply tom,
//! then tom with a new key; cloud-retired tom, then a config without him.
//! cloud-metadata polls every minute, so a change can take two.
const std = @import("std");
const driver = @import("test-driver");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const mem = std.mem;

const Variant = enum { check, poll, reapply, retired };

const config_tar = "/run/werewolf/cloud/config.tar";
const root_keys = "/run/werewolf/keys/root";
const tom_keys = "/run/werewolf/keys/tom";
const tom_home = "/data/home/tom";
/// tom is the identity the people mapping gives tom.
const tom = 654612137;
const tom_entry = std.fmt.comptimePrint("tom:x:{d}:{d}::/data/home/tom:", .{ tom, tom });
const tom_reserved = std.fmt.comptimePrint("p tom {d} {d}", .{ tom, tom });
/// parser and fetcher are cloud-metadata's workers' uids, fixed by lib/baselayout.zig.
const parser = 74;
const fetcher = 68;
/// poll is how long a change at the server may take to reach the machine.
const poll = 150;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len != 4 or !mem.eql(u8, args[2], "cloud")) return error.Usage;
    const ctx = try driver.Run.load(io, a, args[3]);
    const suite = args[1];
    const hostname = mem.trimEnd(
        u8,
        try driver.readKernel(io, a, "/proc/sys/kernel/hostname"),
        "\n",
    );
    // The served hostname names the boot: one that is not taken took nothing.
    const variant = if (mem.startsWith(u8, hostname, "cloud-"))
        std.meta.stringToEnum(Variant, hostname["cloud-".len..])
    else
        null;
    try ctx.result(io, suite, "config-taken", variant != null and try taken(io, a));
    try ctx.result(io, suite, "people", switch (variant.?) {
        .check => try nobody(io, a),
        .poll => try arrives(io, a),
        .reapply => try reapplied(io, a),
        .retired => try retired(io, a),
    });
    try ctx.result(io, suite, "poller", try poller(io, a, variant.? == .poll));
}

/// Verdict is a case's: it holds while each check does, and says on the
/// console, which the stage keeps, why each that fails does not.
const Verdict = struct {
    ok: bool = true,

    fn check(v: *Verdict, condition: bool, comptime fmt: []const u8, args: anytype) void {
        if (condition) return;
        std.debug.print("metadata: " ++ fmt ++ "\n", args);
        v.ok = false;
    }

    /// has checks that path's text holds want, or, unless present, does not.
    fn has(
        v: *Verdict,
        io: Io,
        a: Allocator,
        path: []const u8,
        want: []const u8,
        present: bool,
    ) !void {
        const found = mem.find(u8, try read(io, a, path), want) != null;
        v.check(found == present, "{s}: {s} {s}", .{ path, if (present) "lacks" else "has", want });
    }

    /// home checks tom's home: his, and his alone.
    fn home(v: *Verdict, a: Allocator) !void {
        const m = try meta(a, tom_home) orelse return v.check(false, "{s}: missing", .{tom_home});
        v.check(m.uid == tom and m.gid == tom and m.mode == 0o700, "{s}: {d}:{d}:{o}", .{
            tom_home, m.uid, m.gid, m.mode,
        });
    }
};

const Meta = struct { uid: u32, gid: u32, mode: u32, dir: bool };

/// meta is path's, or null if it does not exist.
fn meta(a: Allocator, path: []const u8) !?Meta {
    var info: linux.Statx = undefined;
    const rc = linux.statx(
        linux.AT.FDCWD,
        try a.dupeSentinel(u8, path, 0),
        linux.AT.SYMLINK_NOFOLLOW,
        .{ .TYPE = true, .MODE = true, .UID = true, .GID = true },
        &info,
    );
    return switch (linux.errno(rc)) {
        .SUCCESS => .{
            .uid = info.uid,
            .gid = info.gid,
            .mode = info.mode & 0o7777,
            .dir = info.mode & linux.S.IFMT == linux.S.IFDIR,
        },
        .NOENT => null,
        else => error.FileMetadata,
    };
}

/// read is path's text, or nothing if there is no such file.
fn read(io: Io, a: Allocator, path: []const u8) ![]const u8 {
    return driver.system.read(io, a, path) catch |err| switch (err) {
        error.FileNotFound => "",
        else => err,
    };
}

/// line is whether text has a line that is want or, unless whole, begins with it.
fn line(text: []const u8, want: []const u8, whole: bool) bool {
    var lines = mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| if (if (whole) mem.eql(u8, l, want) else mem.startsWith(u8, l, want))
        return true;
    return false;
}

/// until waits up to poll seconds for done(io, a, arg), checking each second.
fn until(io: Io, a: Allocator, comptime done: anytype, arg: anytype) !bool {
    for (0..poll) |_| {
        if (try done(io, a, arg)) return true;
        try io.sleep(.fromSeconds(1), .awake);
    }
    return false;
}

fn named(io: Io, a: Allocator, prefix: []const u8) !bool {
    return line(try read(io, a, "/etc/passwd"), prefix, false);
}

fn locked(io: Io, a: Allocator, _: void) !bool {
    return line(try read(io, a, "/etc/shadow"), "tom:!:", false);
}

fn changed(io: Io, a: Allocator, before: []const u8) !bool {
    return !mem.eql(u8, try read(io, a, config_tar), before);
}

/// taken is the config as cloud-metadata leaves it for init: root's key
/// taken, and its tar rewritten, every entry a file root owns, mode 0600.
fn taken(io: Io, a: Allocator) !bool {
    var v: Verdict = .{};
    try v.has(io, a, root_keys, "werewolf-check-key", true);
    v.check(try rewritten(try read(io, a, config_tar)), "{s}: not rewritten", .{config_tar});
    return v.ok;
}

/// rewritten is whether every ustar header in tar is a regular file's,
/// owned by root, mode 0600, and the archive ends as one should.
fn rewritten(tar: []const u8) !bool {
    var at: usize = 0;
    var entries: usize = 0;
    while (at + 512 <= tar.len) {
        const h = tar[at..][0..512];
        if (mem.allEqual(u8, h, 0)) return entries > 0;
        const mode = try octal(h[100..108]);
        const uid = try octal(h[108..116]);
        const gid = try octal(h[116..124]);
        const size = try octal(h[124..136]);
        if (h[156] != '0' and h[156] != 0) return false;
        if (mode & 0o7777 != 0o600 or uid != 0 or gid != 0) return false;
        entries += 1;
        at += 512 + (size + 511) / 512 * 512;
    }
    return false;
}

fn octal(text: []const u8) !u64 {
    const digits = mem.trim(u8, text, " \x00");
    return if (digits.len == 0) 0 else std.fmt.parseInt(u64, digits, 8);
}

/// nobody is a good config's: it names no one, so there is no tom.
fn nobody(io: Io, a: Allocator) !bool {
    var v: Verdict = .{};
    v.check(!try named(io, a, "tom:"), "passwd: tom, whom no config named", .{});
    v.check((try read(io, a, "/run/werewolf/people")).len == 0, "people: not empty", .{});
    return v.ok;
}

/// arrives is tom, named only by the server's second config: polling makes
/// his account, reserved, with his key his and root's beside the config's.
fn arrives(io: Io, a: Allocator) !bool {
    var v: Verdict = .{};
    if (!try until(io, a, named, @as([]const u8, "tom:x:")))
        return holds(false, "no tom after {d} s", .{poll});
    v.check(try named(io, a, tom_entry), "passwd: no {s}", .{tom_entry});
    try v.has(io, a, tom_keys, "tom@yubikey", true);
    try v.has(io, a, root_keys, "tom@yubikey", true);
    try v.has(io, a, root_keys, "werewolf-check-key", true);
    v.check(line(try read(io, a, "/run/werewolf/people"), "tom", true), "people: no tom", .{});
    v.check(line(try read(io, a, "/data/.werewolf/identities"), tom_reserved, true), "no {s}", .{
        tom_reserved,
    });
    try v.home(a);
    return v.ok;
}

/// reapplied is tom's changed key at the cloud: his account, home and
/// reservation reused, the ledger untouched, which a stray directory where
/// it would be rewritten proves.
fn reapplied(io: Io, a: Allocator) !bool {
    var v: Verdict = .{};
    const before = try read(io, a, config_tar);
    try Io.Dir.cwd().createDirPath(io, "/data/.werewolf/identities.new");
    try v.has(io, a, tom_keys, "tom@yubikey", true);
    try v.home(a);
    if (!try until(io, a, changed, before))
        return holds(false, "the new key did not arrive in {d} s", .{poll});
    for ([_][]const u8{ tom_keys, root_keys }) |keys| {
        try v.has(io, a, keys, "tom@spare", true);
        try v.has(io, a, keys, "tom@yubikey", false);
    }
    v.check((try meta(a, "/data/.werewolf/identities.new") orelse Meta{
        .uid = 0,
        .gid = 0,
        .mode = 0,
        .dir = false,
    }).dir, "the ledger was rewritten", .{});
    const active = try a.print("{s}{s}", .{ tom_entry, try shell(a) });
    v.check(line(try read(io, a, "/etc/passwd"), active, true), "passwd: no {s}", .{active});
    v.check(line(try read(io, a, "/etc/shadow"), "tom:*:", false), "shadow: tom not active", .{});
    v.check(line(try read(io, a, "/data/.werewolf/identities"), tom_reserved, true), "no {s}", .{
        tom_reserved,
    });
    try v.home(a);
    return v.ok;
}

/// shell is the one init gives the active: a shell if the image has one.
fn shell(a: Allocator) ![]const u8 {
    return if (try meta(a, "/bin/mksh") != null) "/bin/mksh" else "/sbin/nologin";
}

/// retired is tom, gone from the server's second config. While his key
/// cannot be removed, he is locked and the config is not published; once it
/// can, he is retired: his identity and home kept, his access gone.
fn retired(io: Io, a: Allocator) !bool {
    var v: Verdict = .{};
    v.check(line(try read(io, a, "/etc/shadow"), "tom:*:", false), "shadow: tom not active", .{});
    try v.has(io, a, tom_keys, "tom@yubikey", true);
    const before = try read(io, a, config_tar);
    // A directory in place of his key file is one cloud-metadata cannot remove.
    const key = try read(io, a, tom_keys);
    try Io.Dir.cwd().deleteFile(io, tom_keys);
    try Io.Dir.cwd().createDir(io, tom_keys, .fromMode(0o700));
    if (!try until(io, a, locked, {})) return holds(false, "tom not locked in {d} s", .{poll});
    try io.sleep(.fromSeconds(2), .awake);
    v.check((try meta(a, tom_keys)).?.dir, "{s}: the blocking directory went", .{tom_keys});
    v.check(!try changed(io, a, before), "a removal that failed was published", .{});
    try Io.Dir.cwd().deleteDir(io, tom_keys);
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = tom_keys,
        .data = key,
        .flags = .{ .permissions = .fromMode(0o640) },
    });
    const path = try a.dupeSentinel(u8, tom_keys, 0);
    if (linux.errno(linux.chown(path, 0, tom)) != .SUCCESS) return error.Chown;
    if (!try until(io, a, changed, before))
        return holds(false, "tom not retired in {d} s", .{poll});
    const entry = tom_entry ++ "/sbin/nologin";
    v.check(line(try read(io, a, "/etc/passwd"), entry, true), "passwd: no {s}", .{entry});
    const member = std.fmt.comptimePrint("tom:x:{d}:", .{tom});
    v.check(line(try read(io, a, "/etc/group"), member, true), "group: no {s}", .{member});
    v.check(!line(try read(io, a, "/run/werewolf/people"), "tom", true), "people: tom", .{});
    v.check(try meta(a, tom_keys) == null, "{s}: a retired account's keys", .{tom_keys});
    try v.has(io, a, root_keys, "tom@yubikey", false);
    try v.has(io, a, root_keys, "werewolf-check-key", true);
    v.check(line(try read(io, a, "/data/.werewolf/identities"), tom_reserved, true), "no {s}", .{
        tom_reserved,
    });
    try v.home(a);
    return v.ok;
}

fn holds(ok: bool, comptime fmt: []const u8, args: anytype) bool {
    if (!ok) std.debug.print("metadata: " ++ fmt ++ "\n", args);
    return ok;
}

/// Status is what the poller's processes must show of themselves.
const Status = struct {
    ppid: u32,
    uid: u32,
    eff: []const u8,
    bnd: []const u8,
    nnp: []const u8,
    seccomp: []const u8,
};

fn status(io: Io, a: Allocator, pid: u32) !?Status {
    const text = driver.readKernel(io, a, try a.print("/proc/{d}/status", .{pid})) catch |err|
        return if (err == error.FileNotFound) null else err;
    return .{
        .ppid = try std.fmt.parseInt(u32, field(text, "PPid:"), 10),
        .uid = try std.fmt.parseInt(u32, field(text, "Uid:"), 10),
        .eff = field(text, "CapEff:"),
        .bnd = field(text, "CapBnd:"),
        .nnp = field(text, "NoNewPrivs:"),
        .seccomp = field(text, "Seccomp:"),
    };
}

/// field is the first word after key in a /proc/PID/status text.
fn field(text: []const u8, key: []const u8) []const u8 {
    var lines = mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| if (mem.startsWith(u8, l, key)) {
        var words = mem.tokenizeAny(u8, l[key.len..], " \t");
        return words.next() orelse "";
    };
    return "";
}

/// supervised is the poller's pid, as runit supervises it.
fn supervised(io: Io, a: Allocator) !u32 {
    const text = mem.trim(u8, try read(io, a, "/etc/sv/cloud-metadata/supervise/pid"), " \n");
    return std.fmt.parseInt(u32, text, 10) catch 0;
}

/// children are pid's.
fn children(io: Io, a: Allocator, pid: u32) ![]const u32 {
    var out: std.ArrayList(u32) = .empty;
    var proc = try Io.Dir.cwd().openDir(io, "/proc", .{ .iterate = true });
    defer proc.close(io);
    var it = proc.iterate();
    while (try it.next(io)) |e| {
        const child = std.fmt.parseInt(u32, e.name, 10) catch continue;
        const s = try status(io, a, child) orelse continue;
        if (s.ppid == pid) try out.append(a, child);
    }
    return out.items;
}

/// poller is cloud-metadata as it polls: the publisher root's, holding
/// CAP_CHOWN alone; the parser and fetcher, its workers, holding nothing;
/// all three unable to gain more, under seccomp. With restart, the
/// publisher killed must take both workers with it, and the new one keep
/// tom's account.
fn poller(io: Io, a: Allocator, restart: bool) !bool {
    var v: Verdict = .{};
    const parent = try supervised(io, a);
    const p = try status(io, a, parent) orelse return holds(false, "the poller is not up", .{});
    v.check(
        p.uid == 0 and mem.eql(u8, p.eff, "0000000000000001") and mem.eql(u8, p.bnd, p.eff) and
            mem.eql(u8, p.nnp, "1") and mem.eql(u8, p.seccomp, "2"),
        "the publisher: uid {d}, CapEff {s}, CapBnd {s}, NoNewPrivs {s}, Seccomp {s}",
        .{ p.uid, p.eff, p.bnd, p.nnp, p.seccomp },
    );
    const workers = try children(io, a, parent);
    var seen = [2]bool{ false, false };
    for (workers) |pid| {
        const w = try status(io, a, pid) orelse continue;
        v.check(w.uid == parser or w.uid == fetcher, "a worker as uid {d}", .{w.uid});
        if (w.uid == parser) seen[0] = true;
        if (w.uid == fetcher) seen[1] = true;
        v.check(
            mem.eql(u8, w.eff, "0000000000000000") and mem.eql(u8, w.bnd, w.eff) and
                mem.eql(u8, w.nnp, "1") and mem.eql(u8, w.seccomp, "2"),
            "worker {d}: CapEff {s}, CapBnd {s}, NoNewPrivs {s}, Seccomp {s}",
            .{ w.uid, w.eff, w.bnd, w.nnp, w.seccomp },
        );
    }
    v.check(seen[0] and seen[1], "workers: parser {}, fetcher {}", .{ seen[0], seen[1] });
    if (!restart) return v.ok;
    if (linux.errno(linux.kill(@intCast(parent), linux.SIG.KILL)) != .SUCCESS) return error.Kill;
    var next: u32 = parent;
    for (0..30) |_| {
        next = try supervised(io, a);
        if (next > 1 and next != parent) break;
        try io.sleep(.fromSeconds(1), .awake);
    }
    v.check(next > 1 and next != parent, "no new publisher in 30 s", .{});
    for (workers) |pid| {
        var gone = false;
        for (0..30) |_| {
            gone = try status(io, a, pid) == null;
            if (gone) break;
            try io.sleep(.fromSeconds(1), .awake);
        }
        v.check(gone, "worker {d} outlived its publisher", .{pid});
    }
    v.check(try named(io, a, "tom:x:"), "passwd: tom gone after the restart", .{});
    try v.has(io, a, root_keys, "tom@yubikey", true);
    return v.ok;
}

test "a rewritten config tar is root's files, mode 0600" {
    var buf: [2048]u8 = @splat(0);
    const h = buf[0..512];
    @memcpy(h[0..8], "hostname");
    @memcpy(h[100..107], "0000600");
    @memcpy(h[108..115], "0000000");
    @memcpy(h[116..123], "0000000");
    @memcpy(h[124..135], "00000000014");
    h[156] = '0';
    try std.testing.expect(try rewritten(&buf));
    @memcpy(h[100..107], "0000644");
    try std.testing.expect(!try rewritten(&buf));
    @memcpy(h[100..107], "0000600");
    @memcpy(h[108..115], "0001750");
    try std.testing.expect(!try rewritten(&buf));
    @memcpy(h[108..115], "0000000");
    h[156] = '2';
    try std.testing.expect(!try rewritten(&buf));
    try std.testing.expect(!try rewritten(buf[512..]));
}
