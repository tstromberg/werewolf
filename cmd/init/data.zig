//! init's /data phase: a directory on the victim, RAM, or the disk named by
//! werewolf.data, formatted only while blank and encrypted when there is a key.

const std = @import("std");
const settings = @import("settings");
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

/// min_data_key is the shortest data.key LUKS2 is made with; howl pack
/// checks keys against it too.
const min_data_key = settings.min_data_key;

/// data mounts /data: the victim's data/ directory on a machine with slots,
/// else RAM without werewolf.data or mke2fs, else the disk labelled
/// werewolf-data, in LUKS2 when the config has a data.key. A disk is
/// formatted only while blkid finds it blank, since /data may hold the
/// only copy of something. When it cannot use a disk, /data is an empty
/// read-only tmpfs and /run/werewolf/nodata says why (see README.md).
pub fn data(m: *Machine) void {
    mkdir("/data", 0o755);
    if (m.victim_dir.len > 0) {
        // The victim's filesystem is repaired by the kernel as it mounts,
        // so there is nothing to format, check or label. It wins over any
        // disk.
        const dir = m.fmtZ("{s}/data", .{m.victim_dir});
        mkdir(dir, 0o755);
        if (m.run(&.{ mount_bin, "--bind", "-o", "symfollow", dir, "/data" }) and
            m.run(&.{ mount_bin, "-o", "remount,bind,noatime,nosuid,nodev,noexec", "/data" }))
        {
            say("/data is {s}", .{dir});
        } else {
            nodata(m, m.fmt("cannot bind {s}", .{dir}));
        }
        // Make /victim read-only. That is a property of the mount, so /data,
        // bound from it, stays writable; slot-keep and slot-update mount the
        // victim again to write it.
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
    // Services make their own /data/svc/NAME. init makes a home only for
    // the NoCloud user (Lima's).
    if (m.nocloud_user.len > 0 and !exists("/run/werewolf/nodata")) {
        const home = m.fmtZ("/data/home/{s}", .{m.nocloud_user});
        m.mkdirAll(home);
        if (lookupIds(m.read("/run/werewolf/passwd"), m.nocloud_user)) |ids|
            _ = linux.fchownat(linux.AT.FDCWD, home, ids.uid, ids.gid, 0);
        _ = linux.fchmodat(linux.AT.FDCWD, home, 0o700);
    }
    // The key now lives in the kernel's dm table. No service needs it, and
    // /run/config is where a service would look.
    _ = linux.unlink("/run/config/data.key");
}

/// dataHome mounts the werewolf-data disk on /data and describes it, or
/// returns null with why set.
fn dataHome(m: *Machine, why: *[]const u8) ?[]const u8 {
    const key = "/run/config/data.key";
    const key_len = m.read(key).len;
    const crypt = if (key_len == 0) null else m.which("cryptsetup") orelse {
        why.* = "data.key is in the config, and there is no cryptsetup to use it";
        return null;
    };
    const want: []const u8 = if (crypt != null) "crypto_LUKS" else "ext4";
    var fresh = false;

    // Find the label by reading each disk's first 2 KiB, not with blkid,
    // which probes every superblock (19 ms under Firecracker). Two disks
    // with the label are refused, since an attached one could take /data.
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
        src = m.fmt("/dev/{s}", .{m.cmd.data});
        if (!isBlockDevice(m.z(src))) {
            why.* = m.fmt("werewolf.data: no device {s}", .{src});
            return null;
        }
        if (hasUstar(m.z(src))) {
            why.* = m.fmt("werewolf.data: {s} holds a config tar", .{src});
            return null;
        }
        // Formatting needs blkid's full probe of every signature it knows.
        // Only exit 2 (nothing found) is blank: 0 found something, 8 found
        // several, 4 or 255 is an error. A disk not known blank is never
        // formatted.
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
        // With no udev, libdevmapper must make /dev/mapper nodes itself.
        // /etc/runit/3 closes the volume and inherits this environment.
        m.env.put("DM_DISABLE_UDEV", "1") catch {};
        mkdir("/run/cryptsetup", 0o700);
        // The key is random, so a slow KDF adds nothing; argon2id's
        // default would cost up to 1 GiB and two seconds every boot.
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

    // Inside LUKS the filesystem has no label: the disk has it, and two
    // devices with it would make the search ambiguous. -F because blkid
    // found the device blank (or it is a new LUKS volume), so a stale
    // signature deeper in does not matter. ^orphan_file: e2fsprogs 1.47
    // enables it, and ext4 then reads it block by block at every mount
    // (0.2 s a boot on GCP); without it ext4 uses the classic orphan list.
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
        // -p repairs only what is safe without a person. Run it only when
        // the superblock says it has work, as e2fsck -p would decide: on a
        // clean disk it did nothing and cost 13 ms. The kernel replays the
        // journal as it mounts.
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

/// Head is a disk's first 2 KiB: the LUKS header at 0, the ext4 superblock
/// at 1024.
const Head = [2048]u8;

fn readHead(dev: [:0]const u8, head: *Head) bool {
    const fd = linux.open(dev, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    const n = linux.pread(@intCast(fd), head, head.len, 0);
    return linux.errno(n) == .SUCCESS and n == head.len;
}

/// Disk is what identify finds: LUKS (magic at 0, LUKS2 label at 24) or
/// ext4 (magic at 1080, label at 1144). ext2 and ext3 share the magic, and
/// ext4 mounts them too. label is a slice of the head.
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

/// checkDue returns why e2fsck -p has work on ext4 superblock sb at now
/// (Unix seconds), or null if it would find it clean. It checks s_state,
/// s_error_count, s_mnt_count against s_max_mnt_count, and s_lastcheck
/// plus s_checkinterval, as e2fsck -p does.
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
