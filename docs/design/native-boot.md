# Native boot

Proposed, 2026-10-06. Built (cmd/howl/disk.zig, boot/gpt.zig, `make disk`;
`installEsp` in cmd/slot-update; cmd/slot-keep).

## Summary

A werewolf disk that boots on its own (UEFI firmware, systemd-boot, a slot)
and updates itself as a bitten machine does, wherever a VM boots a disk.

## Background

Booted directly (`howl run --on qemu`), a machine takes its kernel from the
host and has nothing to update; bite lends it a distro's disk and GRUB
([bite.md](../bite.md)). Debian updates itself under Lima because its image
is a disk with its own bootloader, as each werewolf release now is
([releases.md](../releases.md)).

## Goals

- One disk that boots wherever UEFI firmware finds it, built on a Mac or
  on Linux, and the same bytes from the same slot.
- A new slot gets one try and falls back on its own, as on bitten machines.

## Non-Goals

- Replacing bite: bitten machines keep the distro's GRUB and `grubenv`.
- Secure Boot (verified-boot.md phase 5), and growing the disk.

## Detailed design

GPT, two partitions; every GUID, UUID, serial number and time is fixed.

| Partition | Holds |
| --- | --- |
| EFI system, FAT32, 256 MiB | systemd-boot at the removable-media path (`EFI/BOOT/BOOTAA64.EFI` or `BOOTX64.EFI`), `loader/loader.conf`, `loader/entries/werewolf-*.conf`, `werewolf/{a,b}/vmlinuz` and `stage0.zst` |
| ext4, the rest | `werewolf/{a,b}/root.erofs`; init adds `werewolf/data`, which is `/data` |

The removable-media path needs no NVRAM entry, so the disk boots wherever
it is attached. The ext4 partition is laid out as bite lays out a distro's:
stage0 finds it by `werewolf.victim=UUID:/werewolf`. systemd-boot sorts
entries by `sort-key`, then newest `version`, with any entry out of tries
last. No default is set, so the newest slot not known bad wins; slot a's
version is 1980, older than any update's. `make disk` needs no Linux: it
uses `boot/gpt.zig` (no `sfdisk`), mtools and `mke2fs -d`.

The updater knows the disk by `werewolf.esp`. It builds the other slot as
always, borrows the EFI partition from the mount broker, and:

1. Removes the other slot's entries, writes its kernel and stage0 to the
   EFI partition and `root.erofs` to ext4, each whole, and syncs.
2. Writes `werewolf-<other>+1.conf`, with one try, dated now or a second
   past the newest entry. Its options are this boot's, with `werewolf.slot`
   and the new image's arguments swapped in.
3. Reboots. systemd-boot renames the entry `+0-1` and boots it.

| Then | Happens |
| --- | --- |
| it commits | slot-keep renames it `werewolf-<slot>.conf`, with no counter: good for good |
| it panics | the reset finds it out of tries; the old slot boots, and the updater logs `rollback` |
| it hangs | stage0's deadman reboots it after ten minutes; as above |

The old slot stays a good, older entry: the fallback, and the next target.

### Open questions

- **Growing the data partition.** A larger disk leaves the partition at its
  built size. Growing it means rewriting the GPT's end and `resize2fs` at
  boot, or `/data` on a second disk, as `werewolf.data=` already allows.
- **Lima's networks.** Under vz, DHCP takes Lima's own NIC, not vzNAT's, so
  `howl create` pins vzNAT's MAC and builds the disk with `werewolf.mac=`.

## Drawbacks

- The updater and slot-keep each keep two paths, GRUB's and systemd-boot's.
- The build needs mtools and e2fsprogs.

## Alternatives Considered

- **GRUB, as bite uses.** `grub-mkimage` needs Linux, its configuration is
  a script plus `grubenv`, and one try takes `next_entry`, the deadman and
  slot-keep. systemd-boot is one EFI file from Wolfi, a text file per
  entry, counts tries itself, and its editor can be turned off.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A console user adds `init=/bin/sh` | `timeout 0` and `editor no`: no menu, no editor. |
| A file on ext4 owned by the builder's uid, so by whoever has it on the machine (Lima makes the host user's), who could swap a slot | `debugfs` makes every file root's; `werewolf/` is 0700. |
| The EFI partition | Mounted by the mount broker only to write a slot or commit, `nosuid,nodev,noexec,nosymfollow`. root can still rewrite it, as it can a bitten machine's GRUB, until Secure Boot. |
| Kernel arguments that start a new entry line | `disk.zig` takes only letters, digits and `_.,= -` from the image, and no control character from `DISK_ARGS`. |

## Reliability Considerations

- **Whole files**, copied under a temporary name; vfat has no journal, so
  deletes are synced before any file changes.
- **Tested:** `make check-persist` and `make check-dist` boot this disk
  under UEFI; unit tests cover the updater's entries (cmd/slot-update).
