# stage0

## Summary

stage0 is the kernel's first process. It raises lockdown, loads modules,
finds the slot's disk, opens the root image through dm-verity, mounts it
read-only as `/`, and execs the root's `/init`. If anything fails, it
panics, and the loader boots the slot that last worked.

## Background

werewolf's root is one image, `root.erofs`, the same byte for byte on every
boot; what the system writes goes to `/run`, `/tmp`, `/var/tmp` or `/data`.
The image comes from one of three places, named on the kernel command line:

| Words | Image |
| --- | --- |
| `werewolf.victim=UUID:DIR`, `werewolf.slot=a\|b` | `DIR/SLOT/root.erofs` on that filesystem (bite's victim, or werewolf's own disk) |
| `werewolf.root=DEV` | the disk `/dev/DEV` (Firecracker's `vdc`) |
| neither | `/root.erofs` appended to the initramfs (`make run`) |

A disk is read as it is used; an appended image is unpacked into RAM that
nothing frees (20 MB and 26 ms a boot on Firecracker). The initramfs holds
the image's dm-verity parameters, `/verity` (`lib/verity.zig`). Nothing runs
before stage0, so it uses the kernel directly: no shell, blkid or mount.

## Goals

- A root that is the image the build made, or no boot at all.
- No unsigned kernel code: lockdown before any module.
- A failing slot ends in the last good one, never in a hung machine.
- Fast: the disk is searched while drivers load, and the image read ahead.

## Non-Goals

- Choosing slots: the loader (GRUB or systemd-boot) does.
- Verifying the initramfs or kernel: secure boot's job
  ([verified-boot.md](../../docs/design/verified-boot.md)).

## Detailed design

1. **Mounts** `/proc`, `/sys`, `/dev`, and checks every `werewolf.*` word
   with `lib/cmdline.zig`, which every later program uses. A refused line
   ends the boot here.
2. **Lockdown** to integrity, read first: writing the current level fails.
3. **Modules**: modload runs while stage0 searches for the slot's disk,
   reading tags on stdin (`hyperv`, `esp`, then the filesystem kind). Then
   the initramfs's 14 MB of modules are deleted, since nothing frees it.
4. **The disk**: every block device's superblock is read for the UUID
   (ext4, xfs, btrfs), every 10 ms for up to 10 s. If two devices have it,
   stage0 fails: `/data` and the config tar come from that filesystem too.
5. **The root**: dm-verity maps the disk, or a file on a read-only,
   autoclearing loop device read ahead in the background, with `/verity`;
   erofs mounts it read-only.
6. **The deadman**, on a slot: a child sleeps ten minutes, then reboots
   (sysrq `b`) unless `/run/werewolf/committed` exists in PID 1's root,
   logging why a second before. Only a DEV build's root may shorten the
   wait (`werewolf.deadman`, for `make check-deadman`).
7. **Hands over**: moves `/dev`, `/proc`, `/sys`, `/victim` into the root,
   makes it `/` (as switch_root does), and execs `/init` with only
   `WEREWOLF_BOOT` (phase timings), so the kernel's leftover words stop here.
8. **Fails** by writing the reason to `/dev/kmsg` at KERN_CRIT, which the
   kernel flushes on panic, and exiting; `panic=10` reboots.

## Drawbacks

- A second disk with the victim's UUID stops both slots booting until it is
  detached: refusal over a guess.
- A victim on md RAID1 with metadata at the end shows its superblock on
  each member, so it is refused, as the mount broker refuses it.

## Alternatives Considered

### An initramfs with a shell, busybox and blkid
Many tools, each a way in, for six steps the kernel does directly.

### The first device with the UUID
A clone attached beside the disk could then supply `/data` and root's keys.

### Waiting for udev
There is none; the superblock is read directly every 10 ms.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A changed root image | dm-verity against the initramfs's root hash: a changed block fails to read. |
| Unsigned modules | Lockdown at integrity before modload; then the loader closes. |
| A disk standing in for the victim | Two matching UUIDs refused. |
| A FIFO or link as the image | Opened `O_NOFOLLOW`; only a regular file is used, so PID 1 cannot block. |
| A crafted command line | Every `werewolf.*` word checked by `lib/cmdline.zig`; a refusal panics. |
| A slot that boots but cannot serve | The deadman reboots it after ten minutes. |

## Reliability Considerations

- **Fails to the last good slot**: every failure panics, and the reason
  reaches the console first.
- **Tested**: every `make check` boots through it; `check-slot` and
  `check-updater` from a slot; `check-verity`, a changed image that must not
  boot; `check-deadman`, a slot that never commits.
