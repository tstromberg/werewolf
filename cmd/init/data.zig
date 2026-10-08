//! init's /data: a werewolf.data disk made once, encrypted when it has a
//! key, checked and mounted; or RAM, said as such.

const std = @import("std");
const linux = std.os.linux;
const init = @import("init.zig");
const Machine = init.Machine;
const phase_config = @import("config.zig");
const exists = init.exists;
const isBlockDevice = init.isBlockDevice;
const mkdir = init.mkdir;
const mount_bin = init.mount_bin;
const say = init.say;
const hasUstar = phase_config.hasUstar;
const lookupIds = phase_config.lookupIds;

const label = "werewolf-data";

/// The least data.key LUKS is made with: the key derivation is quick, as a
/// random key needs no slow one, so the key itself must be strong.
const min_data_key = 32;

/// /data is the machine's one writable home, and what is on it may be
/// the only copy: a database, someone's files. So init formats a disk
/// once, when werewolf.data names it and blkid finds nothing on it at
/// all, and never again. A disk that carries our label but is not what
/// the form wants (plain where it wants LUKS, no key or a key that does
/// not open it, damage that e2fsck -p will not repair) is left as it is,
/// for a person to look at.
///
/// /data is then unavailable: an empty, read-only tmpfs, so a service
/// that needs it fails where it can be seen, rather than writing to RAM
/// what it believes is kept. /run/werewolf/nodata says why, and stops a
/// slot on probation from committing, so an update that broke /data
/// falls back.
///
/// /data follows links, the one writable place that does (symfollow):
/// the updater builds each new root there, and apk and the updater
/// resolve the links its packages lay (lib to usr/lib) inside it. So a
/// service could plant a link in its own directory for a root program
/// walking it to follow. None does today: leash, which makes each
/// service's directory as root, takes it only as a directory, never
/// through a link, and walks no further. Accepted for now, and listed in
/// docs/security.md, "Not yet".
///
/// The command line and the config decide what /data is, never which
/// form this is; the form only has the tools or not:
///
///     no werewolf.data, or no mke2fs   tmpfs, capped at a quarter of RAM: nothing is kept
///     werewolf.data                    ext4 on the disk labelled werewolf-data
///     + data.key in the config         the same inside LUKS2, keyed by it
///
/// So a disk is used only where the command line says one is wanted,
/// and a disk that is slow to appear, or gone, is not quietly replaced
/// by RAM. The disk is found by its label, so its device name may
/// differ from boot to boot; werewolf.data names the device to format
/// when there is none yet.
pub fn data(m: *Machine) void {
    mkdir("/data", 0o755);
    if (m.victim_dir.len > 0) {
        // On a machine with slots /data is a directory beside them, on a
        // filesystem the kernel repairs as it mounts it: nothing to
        // format, check or label. It takes precedence over any disk.
        const dir = m.fmtZ("{s}/data", .{m.victim_dir});
        mkdir(dir, 0o755);
        if (m.run(&.{ mount_bin, "--bind", "-o", "symfollow", dir, "/data" }) and
            m.run(&.{ mount_bin, "-o", "remount,bind,noatime,nosuid,nodev,noexec", "/data" }))
        {
            say("/data is {s}", .{dir});
        } else {
            nodata(m, m.fmt("cannot bind {s}", .{dir}));
        }
        // From here /victim is for looking at. Read-only is a property of
        // the mount, not the filesystem, so /data, bound from it, stays
        // writable. What must write there (slot-keep; slot-update) mounts
        // it again, apart.
        if (m.run(&.{
            mount_bin,
            "-o",
            "remount,bind,ro,nosuid,nodev,noexec,nosymfollow",
            "/victim",
        }))
            say("/victim is read-only", .{})
        else
            say("/victim stays writable: remounting it read-only failed", .{});
    } else if (m.cmd.data.len == 0 or m.which("mke2fs") == null) {
        m.mount(&.{
            "-t",
            "tmpfs",
            "-o",
            "size=25%,nosuid,nodev,noexec,symfollow,mode=0755",
            "tmpfs",
            "/data",
        });
        say("/data is RAM, capped at 25%", .{});
    } else {
        var why: []const u8 = "";
        if (dataHome(m, &why)) |what| {
            _ = linux.fchmodat(linux.AT.FDCWD, "/data", 0o755);
            say("/data is {s}", .{what});
        } else nodata(m, why);
    }
    // /data holds /data/svc/<service>, which each service makes for
    // itself, and /data/home/<user> for people. The only person init
    // creates is the NoCloud user (Lima's).
    if (m.nocloud_user.len > 0 and !exists("/run/werewolf/nodata")) {
        const home = m.fmtZ("/data/home/{s}", .{m.nocloud_user});
        m.mkdirAll(home);
        if (lookupIds(m.read("/run/werewolf/passwd"), m.nocloud_user)) |ids|
            _ = linux.fchownat(linux.AT.FDCWD, home, ids.uid, ids.gid, 0);
        _ = linux.fchmodat(linux.AT.FDCWD, home, 0o700);
    }
    // The key now lives in the kernel's dm table. No service needs it,
    // and the config directory is the one place a service would look.
    _ = linux.unlink("/run/config/data.key");
}

/// The form's disk on /data; what it is and where, as said on the
/// console, or null with why set.
fn dataHome(m: *Machine, why: *[]const u8) ?[]const u8 {
    const key = "/run/config/data.key";
    const key_len = m.read(key).len;
    const crypt = if (key_len == 0) null else m.which("cryptsetup") orelse {
        why.* = "data.key is in the config, and there is no cryptsetup to use it";
        return null;
    };
    const want: []const u8 = if (crypt != null) "crypto_LUKS" else "ext4";
    var fresh = false;

    // The disk labelled so, found by reading each disk's first 2 KiB, as
    // config's search does, not by blkid, which probes every superblock
    // of every disk: 19 ms of a boot under Firecracker. Two disks with the
    // label leave no telling which is /data: an attached one could take
    // its place.
    var labelled: std.ArrayList([]const u8) = .empty;
    var have: []const u8 = "";
    for (m.list("/sys/class/block")) |name| {
        const dev = m.fmtZ("/dev/{s}", .{name});
        if (!isBlockDevice(dev)) continue;
        var head: Head = undefined;
        if (!readHead(dev, &head)) continue;
        const d = identify(&head);
        if (d.kind == .other or !std.mem.eql(u8, d.label, label)) continue;
        labelled.append(m.gpa, dev) catch {};
        have = if (d.kind == .luks) "crypto_LUKS" else "ext4";
    }
    if (labelled.items.len > 1) {
        why.* = m.fmt(
            "more than one disk is labelled {s}: {s}",
            .{ label, std.mem.join(m.gpa, " ", labelled.items) catch "" },
        );
        return null;
    }
    var src: []const u8 = if (labelled.items.len == 1) labelled.items[0] else "";
    if (src.len > 0) {
        if (!std.mem.eql(u8, have, want)) {
            why.* = m.fmt(
                "{s} is {s}; {s} data.key in the config, this machine wants {s}",
                .{ src, have, if (crypt != null) "with" else "without", want },
            );
            return null;
        }
    } else {
        const d = m.cmd.data;
        src = m.fmt(
            "/dev/{s}",
            .{if (std.mem.startsWith(u8, d, "/dev/")) d["/dev/".len..] else d},
        );
        if (!isBlockDevice(m.z(src))) {
            why.* = m.fmt("werewolf.data: no device {s}", .{src});
            return null;
        }
        if (hasUstar(m.z(src))) {
            why.* = m.fmt("werewolf.data: {s} holds a config tar", .{src});
            return null;
        }
        // Blank as blkid sees it, every signature it knows probed: the
        // one judgement before a format, so it stays blkid's. Only its
        // exit 2, nothing found, is blank: 0 found something, 8 found
        // more than one thing, and 4, or blkid not running at all, said
        // nothing, and a disk not known blank is never formatted.
        const blkid_bin = m.which("blkid") orelse {
            why.* = "no blkid, so no telling a blank disk from one in use";
            return null;
        };
        const blank = m.spawn(&.{ blkid_bin, "-c", "/dev/null", "-p", src }, true);
        if (blank != 2) {
            why.* = m.fmt("werewolf.data: {s} is not blank (blkid exit {d})", .{ src, blank });
            return null;
        }
        fresh = true;
    }

    var fs = src;
    if (crypt) |cryptsetup| {
        // No udev here: libdevmapper must make /dev/mapper nodes itself,
        // here and in /etc/runit/3, which closes the volume and inherits
        // this environment through fence and runit.
        m.env.put("DM_DISABLE_UDEV", "1") catch {};
        mkdir("/run/cryptsetup", 0o700);
        // The key is random, so a slow KDF adds nothing; argon2id's
        // default would spend up to 1 GiB and two seconds every boot.
        const open = [_][]const u8{
            cryptsetup,
            "open",
            "--key-file",
            key,
            "--perf-no_read_workqueue",
            "--perf-no_write_workqueue",
            src,
            "data",
        };
        if (key_len < min_data_key) {
            if (fresh) {
                why.* = m.fmt(
                    "data.key is {d} bytes; LUKS2 is made only with {d} or more random bytes",
                    .{ key_len, min_data_key },
                );
                return null;
            }
            say(
                "data.key is only {d} bytes: a disk copied from this one could be opened by " ++
                    "guessing it; make a new disk with {d} random bytes or more",
                .{ key_len, min_data_key },
            );
        }
        if (fresh) {
            say("making LUKS2 on {s}", .{src});
            if (!m.run(&.{
                cryptsetup,
                "luksFormat",
                "-q",
                "--type",
                "luks2",
                "--label",
                label,
                "--pbkdf",
                "pbkdf2",
                "--pbkdf-force-iterations",
                "1000",
                "--key-file",
                key,
                src,
            }) or
                !m.run(&open))
            {
                why.* = m.fmt("cannot make LUKS2 on {s}", .{src});
                return null;
            }
        } else if (!m.runQuiet(&open)) {
            why.* = m.fmt("data.key does not open {s}", .{src});
            return null;
        }
        fs = "/dev/mapper/data";
    }

    // Inside LUKS the filesystem goes unlabelled: the label belongs to
    // the disk, and two devices answering to it would make the search
    // ambiguous. -F: the device is blank as far as blkid can tell, or a
    // LUKS volume made a moment ago, so a stale signature deeper in is no
    // reason to stop. ^orphan_file: e2fsprogs 1.47 turns it on, and ext4
    // then reads all of it, a block at a time, at every mount (0.2s a
    // boot on GCP's disks); without it, orphans go on the list ext4
    // always kept.
    if (fresh) {
        say("formatting {s}", .{fs});
        const mke2fs = m.which("mke2fs").?;
        const ok = if (crypt != null)
            m.run(&.{ mke2fs, "-q", "-F", "-t", "ext4", "-m", "0", "-O", "^orphan_file", fs })
        else
            m.run(&.{
                mke2fs, "-q",           "-F", "-t",  "ext4", "-m", "0",
                "-O",   "^orphan_file", "-L", label, fs,
            });
        if (!ok) {
            why.* = m.fmt("mke2fs failed on {s}", .{fs});
            return null;
        }
    } else {
        // -p repairs only what is safe without a person. Anything more
        // is theirs to decide, with the disk attached where there are
        // tools. Run when the superblock says it has work, as e2fsck -p
        // itself decides: on a clean disk it changes nothing, and cost 13
        // ms of a boot; the kernel replays the journal as it mounts.
        var head: Head = undefined;
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.REALTIME, &ts);
        const reason = if (readHead(m.z(fs), &head))
            checkDue(head[1024..], ts.sec)
        else
            "its superblock cannot be read";
        if (reason) |r| {
            say("e2fsck -p {s}: {s}", .{ fs, r });
            const rc = m.spawn(&.{ m.which("e2fsck") orelse "e2fsck", "-p", fs }, true);
            if (rc >= 4) {
                why.* = m.fmt("e2fsck -p will not repair {s} (exit {d})", .{ fs, rc });
                return null;
            }
        }
    }
    if (!m.run(&.{
        mount_bin,
        "-t",
        "ext4",
        "-o",
        "noatime,nosuid,nodev,noexec,symfollow",
        fs,
        "/data",
    })) {
        why.* = m.fmt("cannot mount {s}", .{fs});
        return null;
    }
    return m.fmt("{s} on {s}", .{ want, src });
}

/// A disk's first 2 KiB: LUKS's header at 0, ext4's superblock at 1024.
const Head = [2048]u8;

fn readHead(dev: [:0]const u8, head: *Head) bool {
    const fd = linux.open(dev, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    const n = linux.pread(@intCast(fd), head, head.len, 0);
    return linux.errno(n) == .SUCCESS and n == head.len;
}

/// What a disk holds, as far as /data asks: LUKS (its magic at 0, and
/// LUKS2's label at 24), or ext4 (its magic at 1080, its label at 1144),
/// as mke2fs -t ext4 made it; ext2 and ext3 share the magic, and ext4
/// mounts them too. The label is a slice of head.
const Disk = struct { kind: enum { ext4, luks, other }, label: []const u8 = "" };

fn identify(head: *const Head) Disk {
    if (std.mem.eql(u8, head[0..6], "LUKS\xba\xbe")) {
        const v2 = std.mem.readInt(u16, head[6..8], .big) == 2;
        return .{ .kind = .luks, .label = if (v2) std.mem.sliceTo(head[24..72], 0) else "" };
    }
    if (std.mem.readInt(u16, head[1080..1082], .little) == 0xEF53)
        return .{ .kind = .ext4, .label = std.mem.sliceTo(head[1144..1160], 0) };
    return .{ .kind = .other };
}

/// Why e2fsck -p has work on ext4's superblock sb, at now (seconds since
/// the epoch), or null where it would only find it clean: not marked
/// clean (s_state), errors recorded (s_state, s_error_count), or a check
/// due by mounts (s_mnt_count of s_max_mnt_count) or by time
/// (s_lastcheck and s_checkinterval), as e2fsck -p decides.
fn checkDue(sb: []const u8, now: i64) ?[]const u8 {
    const state = std.mem.readInt(u16, sb[0x3a..0x3c], .little);
    if (state & 1 == 0) return "not marked clean";
    if (state & 2 != 0 or std.mem.readInt(u32, sb[0x194..0x198], .little) != 0)
        return "errors recorded";
    const mounts = std.mem.readInt(u16, sb[0x34..0x36], .little);
    const max_mounts = std.mem.readInt(i16, sb[0x36..0x38], .little);
    if (max_mounts > 0 and mounts >= max_mounts) return "its mounts between checks are up";
    const last = std.mem.readInt(u32, sb[0x40..0x44], .little);
    const interval = std.mem.readInt(u32, sb[0x44..0x48], .little);
    if (interval != 0 and now >= @as(i64, last) + interval) return "its check interval has passed";
    return null;
}

fn nodata(m: *Machine, why: []const u8) void {
    say("{s}; /data is unavailable", .{why});
    m.write("/run/werewolf/nodata", m.fmt("{s}\n", .{why}), 0o644);
    m.mount(&.{ "-t", "tmpfs", "-o", "ro,nosuid,nodev,noexec,mode=0755", "tmpfs", "/data" });
}

const testing = std.testing;

test identify {
    var head: Head = @splat(0);
    try testing.expectEqual(.other, identify(&head).kind);

    std.mem.writeInt(u16, head[1080..1082], 0xEF53, .little);
    @memcpy(head[1144..][0..label.len], label);
    const ext4 = identify(&head);
    try testing.expectEqual(.ext4, ext4.kind);
    try testing.expectEqualStrings(label, ext4.label);

    head = @splat(0);
    @memcpy(head[0..6], "LUKS\xba\xbe");
    std.mem.writeInt(u16, head[6..8], 2, .big);
    @memcpy(head[24..][0..label.len], label);
    const luks2 = identify(&head);
    try testing.expectEqual(.luks, luks2.kind);
    try testing.expectEqualStrings(label, luks2.label);
    std.mem.writeInt(u16, head[6..8], 1, .big);
    try testing.expectEqualStrings("", identify(&head).label);
}

test checkDue {
    var sb: [1024]u8 = @splat(0);
    try testing.expectEqualStrings("not marked clean", checkDue(&sb, 0).?);
    std.mem.writeInt(u16, sb[0x3a..0x3c], 1, .little);
    try testing.expectEqual(null, checkDue(&sb, 1 << 30));
    std.mem.writeInt(u32, sb[0x194..0x198], 3, .little);
    try testing.expectEqualStrings("errors recorded", checkDue(&sb, 0).?);
    std.mem.writeInt(u32, sb[0x194..0x198], 0, .little);
    std.mem.writeInt(u16, sb[0x3a..0x3c], 3, .little);
    try testing.expectEqualStrings("errors recorded", checkDue(&sb, 0).?);
    std.mem.writeInt(u16, sb[0x3a..0x3c], 1, .little);
    // mke2fs's default, -1: no check by mounts.
    std.mem.writeInt(i16, sb[0x36..0x38], -1, .little);
    std.mem.writeInt(u16, sb[0x34..0x36], 500, .little);
    try testing.expectEqual(null, checkDue(&sb, 0));
    std.mem.writeInt(i16, sb[0x36..0x38], 20, .little);
    try testing.expect(checkDue(&sb, 0) != null);
    std.mem.writeInt(i16, sb[0x36..0x38], -1, .little);
    std.mem.writeInt(u32, sb[0x40..0x44], 1000, .little);
    std.mem.writeInt(u32, sb[0x44..0x48], 100, .little);
    try testing.expectEqual(null, checkDue(&sb, 1099));
    try testing.expect(checkDue(&sb, 1100) != null);
}
