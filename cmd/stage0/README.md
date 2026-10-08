# stage0

## Summary

The kernel's first process on every werewolf machine: it raises lockdown,
loads the form's modules, finds the slot's disk, opens the root image
through dm-verity, mounts it read-only as the root, and hands over to the
root's `/init`. If anything fails, it panics, and the loader boots the slot
that last worked.

## Background

werewolf's root is one image, `root.erofs`, the same byte for byte on every
boot. On a machine with slots it is a file on a filesystem the kernel
command line names (`werewolf.victim=UUID:/DIR`, `werewolf.slot=a|b`): the
replaced distro's, after bite, or werewolf's own disk. Booted directly,
it is in the initramfs (`make run`), or on a disk of its own that
`werewolf.root=DEV` names (Firecracker's `vdc`): read as it is used,
where the kernel unpacks an appended image into RAM that nothing frees,
20 MB for the machine's life and 26 ms of every boot on Firecracker. The initramfs carries the root
hash the image must match (`/verity`, `lib/verity.zig`). Nothing else runs
before stage0, so it uses the kernel alone: no shell, no blkid, no mount.

## Goals

- A root that is the image the build made, or no boot at all.
- No unsigned kernel code, ever: lockdown before any module.
- A failing slot ends in the last good one, never in a hung machine.
- Fast: the disk looked for while drivers load; the image read ahead.

## Non-Goals

- Choosing slots: the loader (GRUB or systemd-boot) does.
- Verifying the initramfs or kernel: secure boot's job
  (docs/design/verified-boot.md).

## Detailed design

1. **Mounts** `/proc`, `/sys`, `/dev`; parses `werewolf.victim` and
   `werewolf.slot`, both or neither, each once, the UUID 36 hex digits and
   dashes, the directory plain names only.
2. **Lockdown** to integrity, read first since it only rises.
3. **Modules**: modload, alongside the search for the slot's disk, then
   told its filesystem's kind for those modules alone; then the
   initramfs's 14 MB of modules freed, as nothing frees the initramfs.
4. **The disk**: each block device's superblock read for the UUID (ext4,
   xfs, btrfs), every 10 ms for up to 10 s. Two devices with it, as a clone
   or snapshot attached beside the disk would be, and it fails: `/data`
   and the config tar come from that filesystem too.
5. **The root**: the slot's `root.erofs` (or the initramfs's) on a
   read-only, autoclearing loop device, read ahead in the background, mapped
   by dm-verity from `/verity`, mounted erofs read-only.
6. **The deadman**, on a slot: a child with its own `/proc` and a kernel
   log descriptor opened now, which after ten minutes reboots (sysrq `b`)
   unless `/run/werewolf/committed` exists in PID 1's root, and says so,
   waiting a second for the console first, since the reset waits for
   nothing. A DEV build's root may shorten the wait (`werewolf.deadman`).
7. **Hands over**: moves `/dev`, `/proc`, `/sys`, `/victim` in, makes the
   root `/` (as switch_root), and execs `/init` with `WEREWOLF_BOOT`, how
   long each phase took.
8. **Fails** through `/dev/kmsg` at KERN_CRIT, which a panic flushes, then
   exits; the kernel panics, `panic=10` reboots.

## Drawbacks

- A second disk with the victim's UUID stops both slots booting until it is
  detached: refusal over a guess.
- A victim on an md RAID1 with its metadata at the end shows its superblock
  on each member, so it is refused, as the mount broker refuses it.

## Alternatives Considered

### An initramfs with a shell, busybox and blkid
Many tools, each a way in, for six steps the kernel does directly.

### The first device with the UUID
How it first was; a clone attached beside the disk could have supplied
`/data` and root's keys.

### Waiting for udev
There is none; the superblock is read directly every 10 ms.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A changed root image | dm-verity against the initramfs's root hash: a changed block fails to read. |
| Unsigned modules | Lockdown at integrity before modload; then the loader closes. |
| A disk standing in for the victim | Two matching UUIDs refused. |
| A crafted command line | Checked: UUID, plain directory, slot a or b. |
| A slot that boots but cannot serve | The deadman reboots it after ten minutes. |

## Reliability Considerations

- **Fails to the last good slot**: every failure panics, and the reason
  reaches the console first.
- **Says why the deadman acts**: its line reaches the kernel's log.
- **Tested**: every `make check` boots through it; `check-slot` and
  `check-updater` from a slot; `check-verity` with a changed image, which
  must not boot; `check-deadman`, a slot that never commits, rebooted with
  its reason on the console (its wait shortened by `werewolf.deadman`,
  which only a DEV build's root may ask for).
