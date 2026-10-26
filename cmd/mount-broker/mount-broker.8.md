# mount-broker(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

mount-broker — perform privileged slot and shutdown filesystem operations

## SYNOPSIS

**mount-broker**

## DESCRIPTION

The **mount-broker** daemon is started by init(8) before the filesystem restrictions
imposed by fence(8). It serves fixed operations over three inherited socketpairs
assigned to the updater, slot keeper and shutdown stage. It has no public pathname
socket or operator command interface.

The broker derives devices, paths and mount options from boot state. It installs
digest-checked slot files, maintains EFI boot entries, raises the running release's
TPM floor when authorized, commits slots, and unmounts data and boot filesystems at
shutdown. EFI and slot writes use detached mounts; callers never receive a writable
mount of the EFI partition or /boot.

Only CAP_SYS_ADMIN is retained, under a restricted system call filter. The daemon
executes no programs. Starting another copy from a login shell does not recreate its
inherited authority or the privileges removed at boot.

## SEE ALSO

fence(8), init(8), runit-stage(8), slot-keep(8), slot-update(8)
