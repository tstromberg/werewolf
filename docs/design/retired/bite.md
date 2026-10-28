# Bite: existing-distro takeover

**Status:** Retired as of 2026-10-27

**Retired, 2026-10-13.** The installer and its runtime support have been
removed. This document records the former design. Current machines use
[native boot](../implemented/native-boot.md) and its EFI update path.

## Purpose

`bite` converted an existing Debian, Ubuntu, Fedora or Rocky VM into
werewolf using the distro's GRUB tools. It served providers that could not
boot a custom disk image. Installation initially kept the distro as a
fallback; a separate `bite-cleanup` program deleted it after a healthy boot.

## Installation and boot

The POSIX shell installer ran as root inside the existing distro. It took
a locally built slot or downloaded a release, verifying the release
manifest and each artifact before installation. It carried the hostname,
SSH keys and live network configuration into werewolf's config tar.

Installation added files without repartitioning:

| Location | Contents |
| --- | --- |
| `/boot/werewolf/{a,b}/` | Kernel and stage0 archives |
| `/var/lib/werewolf/{a,b}/` | Verified root images |
| `/var/lib/werewolf/` | Configuration and persistent data |
| GRUB environment block | Default slot, next attempt and each slot's kernel arguments |

GRUB entries read `werewolf_args_a` or `werewolf_args_b` from the environment
block at boot. `werewolf.victim=UUID:PATH` identified the slot filesystem,
`werewolf.slot` selected the root, and `werewolf.grubenv=UUID:PATH` identified
the environment block. The root image was mounted through dm-verity.

The first boot was a single GRUB attempt. `slot-keep` committed it only
after services had stayed healthy for a minute, data was available and the
updater was ready. Before commit, a reset returned to the distro. Later
updates wrote the other slot, set `next_entry` and relied on the same
health check and deadman watchdog to keep or reject it.

## Additional runtime support

The build exported `stage0-bitten.zst` beside the native stage0 archive.
Its `modules-bitten` record included XFS and Btrfs modules for the existing
distro's filesystem. Stage0 identified those filesystems and told modload
which tagged modules to load. The GRUB path also needed an unpacked arm64
kernel Image because GRUB could not load Alpine's EFI zboot image.

The mount broker lent writable `grub` and `victim` mounts to the updater,
slot keeper and cleanup program. `grub-setenv` rewrote GRUB's environment
block for trial boots and commits. This was a second installation,
verification and commit path alongside native EFI operations.

## Cleanup and fallback

After commit, `bite-cleanup` removed the distro while retaining werewolf's
directory and the bootloader files. It checked the running root and kernel
before deleting, refused links in retained paths, and confined deletion to
the old filesystem. Files it could not remove were reported and left in
place. Freed blocks and earlier snapshots were not erased. Cleanup ended
the option to undo the conversion and return to the distro.

## Retirement

The existing bootloader, kernel arguments and boot files added a mutable
trust path that complicated posture and authenticated boot. Supporting
multiple distro filesystems, borrowed writable mounts and destructive
cleanup also burdened every image and the updater.

The replacement uses one stage0 artifact and the native EFI slot workflow.
The takeover installer, cleanup program, GRUB helper, environment selector,
distro filesystem detection and alternate stage0 contract are removed.
The slot filesystem and its read-only view remain part of native boot.
