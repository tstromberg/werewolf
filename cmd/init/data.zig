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
        if (m.run(&.{ mount_bin, "--bind", dir, "/data" }) and
            m.run(&.{ mount_bin, "-o", "remount,bind,noatime,nosuid,nodev,noexec", "/data" }))
        {
            say("/data is {s}", .{dir});
        } else {
            m.nodata(m.fmt("cannot bind {s}", .{dir}));
        }
        // From here /victim is for looking at. Read-only is a property of
        // the mount, not the filesystem, so /data, bound from it, stays
        // writable. What must write there (slot-keep; slot-update) mounts
        // it again, apart.
        if (m.run(&.{
            mount_bin,
            "-o",
            "remount,bind,ro,nosuid,nodev,noexec",
            "/victim",
        })) say("/victim is read-only", .{});
    } else if (m.cmd.data.len == 0 or m.which("mke2fs") == null) {
        m.mount(&.{
            "-t",
            "tmpfs",
            "-o",
            "size=25%,nosuid,nodev,noexec,mode=0755",
            "tmpfs",
            "/data",
        });
        say("/data is RAM, capped at 25%", .{});
    } else {
        var why: []const u8 = "";
        if (m.dataHome(&why)) |what| {
            _ = linux.fchmodat(linux.AT.FDCWD, "/data", 0o755);
            say("/data is {s}", .{what});
        } else m.nodata(why);
    }
    // /data holds /data/svc/<service>, which each service makes for
    // itself, and /data/home/<user> for people. The only person init
    // creates is the NoCloud user (Lima's).
    if (m.nocloud_user.len > 0 and !exists("/run/werewolf/nodata")) {
        const home = m.fmtZ("/data/home/{s}", .{m.nocloud_user});
        m.mkdirAll(home);
        if (lookupIds(
            m.read("/run/werewolf/passwd"),
            m.nocloud_user,
        )) |ids| _ = linux.fchownat(linux.AT.FDCWD, home, ids.uid, ids.gid, 0);
        _ = linux.fchmodat(linux.AT.FDCWD, home, 0o700);
    }
    // The key now lives in the kernel's dm table. No service needs it,
    // and the config directory is the one place a service would look.
    _ = linux.unlink("/run/config/data.key");
}

/// The form's disk on /data; what it is and where, as said on the
/// console, or null with why set.
pub fn dataHome(m: *Machine, why: *[]const u8) ?[]const u8 {
    const blkid_bin = m.which("blkid") orelse {
        why.* = "no blkid, so no telling a blank disk from one in use";
        return null;
    };
    const key = "/run/config/data.key";
    const key_len = m.read(key).len;
    const crypt = if (key_len == 0) null else m.which("cryptsetup") orelse {
        why.* = "data.key is in the config, and there is no cryptsetup to use it";
        return null;
    };
    const want: []const u8 = if (crypt != null) "crypto_LUKS" else "ext4";
    var fresh = false;

    // Two disks with the label leave no telling which is /data: an
    // attached one could take its place.
    const labelled = m.blkidAll(&.{ "-o", "device", "-t", "LABEL=" ++ label });
    if (std.mem.findScalar(u8, labelled, '\n') != null) {
        why.* = m.fmt(
            "more than one disk is labelled {s}: {s}",
            .{ label, std.mem.replaceOwned(u8, m.gpa, labelled, "\n", " ") catch labelled },
        );
        return null;
    }
    var src = labelled;
    if (src.len > 0) {
        const have = m.blkid(&.{ "-p", "-o", "value", "-s", "TYPE", src });
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
        if (m.runQuiet(&.{ blkid_bin, "-c", "/dev/null", "-p", src })) {
            why.* = m.fmt("werewolf.data: {s} is not blank", .{src});
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
        if (fresh and key_len < min_data_key) {
            why.* = m.fmt(
                "data.key is {d} bytes; LUKS2 is made only with {d} or more random bytes",
                .{ key_len, min_data_key },
            );
            return null;
        }
        if (!fresh and key_len < min_data_key) say(
            "data.key is only {d} bytes: a disk copied from this one could be opened by " ++
                "guessing it; make a new disk with {d} random bytes or more",
            .{ key_len, min_data_key },
        );
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
        // tools.
        const rc = m.exitCode(&.{ m.which("e2fsck") orelse "e2fsck", "-p", fs });
        if (rc >= 4) {
            why.* = m.fmt("e2fsck -p will not repair {s} (exit {d})", .{ fs, rc });
            return null;
        }
    }
    if (!m.run(&.{
        mount_bin,
        "-t",
        "ext4",
        "-o",
        "noatime,nosuid,nodev,noexec",
        fs,
        "/data",
    })) {
        why.* = m.fmt("cannot mount {s}", .{fs});
        return null;
    }
    return m.fmt("{s} on {s}", .{ want, src });
}

pub fn nodata(m: *Machine, why: []const u8) void {
    say("{s}; /data is unavailable", .{why});
    m.write("/run/werewolf/nodata", m.fmt("{s}\n", .{why}), 0o644);
    m.mount(&.{ "-t", "tmpfs", "-o", "ro,nosuid,nodev,noexec,mode=0755", "tmpfs", "/data" });
}
