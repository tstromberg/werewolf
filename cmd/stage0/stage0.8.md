# stage0(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

stage0 — open the verified root and hand over to system initialization

## SYNOPSIS

**/init**

## DESCRIPTION

The **stage0** program is the initramfs's /init and the kernel's first process. It
establishes confidentiality lockdown, validates the kernel command line, opens the
root through dm-verity, mounts it read-only, and executes the root's init(8). It uses
kernel interfaces directly and executes no shell or mount helper.

The kernel arguments select the root:

- `werewolf.slots=UUID` `werewolf.slot=a|b`

  Read /slot/SLOT/root.erofs from the identified slot filesystem.

- `werewolf.root=DEV`

  Use the root block device /dev/DEV.

- Neither

  Use /root.erofs appended to the initramfs.

TPM-enrolled images verify enrollment and reject a release below the channel's
rollback floor. On a slot boot, a deadman reboots after ten minutes unless the
running system has committed the slot. The boot loader then falls back to the last
good slot.

## FILES

- `/verity`

  Root dm-verity parameters in the initramfs.

- `/proc/cmdline`

  Boot selection and protection arguments.

- `/run/werewolf/committed`

  Commit marker in the running system's root, checked by the deadman.

## DIAGNOSTICS

A failure is reported to the kernel log and ends boot. The program cannot continue
with an unverified root.

## SEE ALSO

init(8), slot-keep(8), slot-update(8)
