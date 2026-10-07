# Native boot

Proposed, 2026-10-06.

A werewolf disk that boots on its own: UEFI firmware, then systemd-boot,
then a slot. Today a machine updates itself only after bite borrows a
distro's disk and GRUB; booted directly (`make run`, `make lima`), it gets
its kernel and image from the host every time and has nothing to update.
Debian and Fedora update themselves under Lima because their image is a disk
with its own bootloader. This gives werewolf the same, for Lima, QEMU and
providers that boot a custom image.

## Not goals

- **Replacing bite.** Bitten machines keep the distro's GRUB, and the updater
  keeps writing `grubenv` for them.
- **Secure Boot.** Signing systemd-boot and the kernel is verified-boot.md
  phase 5; this disk is where it will apply.
- **Growing the disk.** The data partition is the size the image was built
  at (see *Open questions*).

## Why systemd-boot

| | systemd-boot | GRUB |
| --- | --- | --- |
| What we ship | one file, `systemd-bootaa64.efi` (263 KB), from Wolfi's `systemd-boot` | `grub-mkimage`'s output, which needs Linux to make |
| Its configuration | a text file per entry on the EFI partition | a script, `grub.cfg`, and `grubenv` |
| Trying a new slot once | built in: an entry named `werewolf-b+1.conf` has one try; systemd-boot counts it down before booting it, and skips an entry with none left | `next_entry` in `grubenv`, plus our deadman and `slot-keep` |
| Editing the command line at boot | off (`editor no`) | on unless locked with a password |

The disk builds on a Mac without a Linux step, and the try-once-then-fall-back
that bitten machines assemble from `grubenv` comes with the bootloader.

## The disk

GPT, two partitions:

| Partition | Filesystem | Holds |
| --- | --- | --- |
| EFI system, 256 MiB | FAT32 | `EFI/BOOT/BOOTAA64.EFI` (systemd-boot; `BOOTX64.EFI` on x86_64), `loader/loader.conf`, `loader/entries/werewolf-*.conf`, `werewolf/{a,b}/vmlinuz`, `werewolf/{a,b}/initramfs.zst` |
| werewolf, the rest | ext4 | `werewolf/{a,b}/root.erofs`, `werewolf/data/`, `werewolf/config.tar` |

The firmware finds systemd-boot at the removable-media path, so no NVRAM
entry is needed and the disk boots wherever it is attached. The ext4
partition is laid out as bite lays out a distro's: stage0 and init find it
by `werewolf.victim=UUID:/werewolf` and treat it exactly as they treat a
bitten machine's filesystem. `/data` is `werewolf/data` on it.

`loader/loader.conf`:

```
timeout 0
editor no
auto-entries no
auto-firmware no
```

`loader/entries/werewolf-a.conf`, as the build writes it:

```
title werewolf
sort-key werewolf
version 20261006T120000Z
linux /werewolf/a/vmlinuz
initrd /werewolf/a/initramfs.zst
options console=... init=/init panic=10 softlockup_panic=1 werewolf.slot=a werewolf.victim=UUID:/werewolf werewolf.esp=UUID
```

systemd-boot sorts entries by `sort-key`, then newest `version` first, with
any entry out of tries last, and boots the first. No default is configured,
so the newest slot that is not known bad always wins.

## An update

The updater recognises the disk by `werewolf.esp=` on the command line, as
it recognises a bitten machine by `werewolf.grubenv=`. It builds the other
slot as now, then:

1. Mounts the EFI partition by UUID, `nosuid,nodev,noexec`.
2. Writes the other slot's `vmlinuz` and `initramfs.zst`, each to a
   temporary name and renamed into place, and `root.erofs` to the ext4
   partition as now.
3. Removes any entry for the other slot, and writes
   `werewolf-<other>+1.conf`: version now, or a second past the running
   entry's if the clock is behind it, so it is always the newest; options
   this boot's command line with `werewolf.slot` changed. Anything the machine was booted with
   (`werewolf.mac`, `console`) carries over.
4. Reboots.

systemd-boot boots the new entry, the newest, renaming it `+0-1` first.

| Then | Happens |
| --- | --- |
| it commits | `slot-keep` renames the entry to `werewolf-<slot>.conf`, which has no counter: good for good |
| it panics | the reset finds the entry at `+0-1`, out of tries; the old slot boots, and `update outcome` logs `rollback` as now |
| it hangs | stage0's deadman reboots it after ten minutes; as above |

The slot it replaced stays as it was, a good entry with an older version: the
fallback, and the next update's target.

## What changes

| Piece | Change |
| --- | --- |
| Makefile | `make disk`: the slot, systemd-boot from a pinned Wolfi package (`boot/boot.yaml`), and `boot/mkdisk`, which writes the GPT with a small Zig program (`boot/gpt.zig`, so no `sfdisk`), the EFI partition with mtools, and the ext4 partition with `mke2fs -d`, then makes every file root's with `debugfs`. On a Mac: `brew install mtools e2fsprogs` |
| updater | a second install path for `werewolf.esp=`; GRUB's stays |
| `slot-keep` | for `werewolf.esp=`, rename the entry instead of setting `saved_entry` |
| `minimal.modules` | `fat vfat nls_cp437 nls_utf8`, for the EFI partition |
| stage0, init | nothing: the ext4 partition is a victim filesystem |
| `make demo` | boots the demo's disk in Lima like a distro's, with no Debian and no bite |

Every GUID, UUID, serial number and timestamp is fixed, so the same slot
gives the same disk. The fixed identities, `E2FSPROGS_FAKE_TIME` and the
`debugfs` pass come from an earlier GRUB disk built the same way.

## Security

- **No boot menu, no editor.** `timeout 0` and `editor no`: the console
  cannot add `init=/bin/sh`.
- **The EFI partition is mounted only to write a slot or commit**, then
  unmounted, and `nosuid,nodev,noexec` while it is.
- **Every file on the ext4 partition is root's.** `mke2fs -d` copies the
  builder's uid; left so, a file would belong to whoever has that uid on
  the machine (Lima creates the host user's), who could replace a slot's
  image while the updater has the partition mounted.
- **The same exposure as bitten machines.** root can rewrite the EFI
  partition and the entries, as root on a bitten machine can rewrite GRUB's
  files; Secure Boot (verified-boot.md phase 5) is what closes it.

## Open questions

- **Growing the data partition.** Lima and providers make the disk larger
  than the image; the partition stays the size it was built. Growing it at
  boot means rewriting the GPT's end and running `resize2fs`, or putting
  `/data` on a second disk, as `werewolf.data=` already does.
- **Lima's networks.** Under vz, Lima's own network is the first NIC and
  vzNAT the second, and a DHCP client takes the first. `make demo` pins
  vzNAT's MAC in its Lima config and builds the disk with `werewolf.mac=`,
  which updates carry over.
