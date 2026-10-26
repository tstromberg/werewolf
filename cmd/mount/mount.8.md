# mount(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

mount — attach filesystems without relaxing mount restrictions

## SYNOPSIS

**mount** **-t** *type* [**-o** *options*] *source target*

**mount** **--bind** *source target*

**mount** **-o** *remount*[,options] *target*

## DESCRIPTION

The Werewolf **mount** utility mounts, binds and remounts the filesystems used during
boot. It is normally called by init(8). It does not read fstab, probe filesystem
types, resolve labels or configure loop devices.

Supported types are proc, sysfs, securityfs, cgroup2, devtmpfs, devpts, tmpfs, ext4 and
iso9660. Targets are restricted to the boot filesystem locations beneath `/proc`,
`/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`, `/data`, `/boot`, `/mnt` and `/oci`. Mounts
over the root, /etc or /usr are refused. Paths must be absolute, without dot components,
and are resolved without symlinks.

New mounts are nosuid and noexec, with nodev except for device filesystems and
nosymfollow except for proc, sysfs and devtmpfs. The symfollow option withholds
nosymfollow from a new mount or bind. Binds retain the source's restrictions. Remounts
only add restrictions; rw and symfollow are refused on remount. The suid, dev, exec
and strictatime options are refused.

Mounts are built and restricted while detached, then attached. The utility keeps
CAP_SYS_ADMIN alone and installs a system call filter before performing mount
operations. After fence(8), ordinary processes cannot mount even through this utility.

## EXIT STATUS

The **mount** utility exits 0 on success, and >0 if an error occurs. Successful
operations produce no output. Failures include the kernel's reason when available.

## SEE ALSO

fence(8), init(8), mount-broker(8)
