# bite

`bite`, a POSIX shell script, takes over a Debian, Ubuntu, Fedora or Rocky
VM using the distro's own GRUB tools. It is for providers that will not
boot a custom image.

```sh
make FORM=autoupdate slot               # build/<arch>/autoupdate/slot/
sudo ./bite -n DIR                      # check, and show the plan
sudo ./bite --reboot [--config X] DIR   # take over, and reboot into werewolf
sudo ./bite --undo                      # from the distro: remove werewolf
bite [-n] --cleanup                     # in werewolf, after commit: delete the distro
```

DIR holds a slot (*Slots*, below) of a form built on `bitten`.

**Nothing is removed or repartitioned.** The slot's kernel and stage0 go in
`/boot/werewolf/<slot>`; `root.erofs`, `config.tar` and `data/` go in
`/var/lib/werewolf`.

**werewolf boots once, then must prove itself.** bite adds GRUB entries
`werewolf-a` and `werewolf-b` and boots `werewolf-a` once (`grub-reboot`).
When every service has stayed up for a minute, the `commit` service makes
that slot GRUB's default; until then, a reset returns to the distro.

**It refuses rather than strand a machine**: the wrong architecture, Secure
Boot on (shim will not load Alpine's unsigned kernel), a NIC or disk that is
not virtio, LVM or LUKS, or a filesystem other than ext4, xfs or btrfs.

**It carries over the live network** as a static address: cloud
addresses come from DHCP but do not change, and a provider without DHCP
works the same. The config tar gets the
hostname and the ssh keys of root and of the sudo user.

**The victim stays visible, not writable.** werewolf mounts the distro's
filesystem read-only at `/victim`; `/data`, bound from it, stays writable.
Root can still remount it; this guards against mistakes and non-root code.

**`--cleanup` ends the fallback.** Once werewolf commits, the distro is
stale and still holds its secrets, cloud-init's user-data among them. Run in
werewolf, `bite --cleanup` deletes everything but `/boot` and
`/var/lib/werewolf`, remounting with `discard` first. It refuses before
commit. Freed blocks are not erased, and earlier snapshots still hold the
distro.

## Tested

In Lima (aarch64, UEFI and GRUB), with the RAM-root image; slots so far on
Debian 13 only:

| Distro | Filesystem | `/boot` | Committed, survives a power cycle |
| --- | --- | --- | --- |
| Debian 13 | ext4 | on root | yes |
| Ubuntu 26.04 | ext4 | ext4 partition | yes |
| Fedora 44 | btrfs | btrfs subvolume | yes |
| Rocky 10 | xfs | xfs partition | yes |

A reset before commit returned to the distro. `bite --undo` left nothing
behind. `--cleanup` took Debian from 1.6 GB to 105 MB and Fedora from 1.1 GB
to 117 MB, and both rebooted into werewolf with `/data` intact.

To test in Lima: until the instance restarts, Lima's ssh runs over vsock,
which werewolf does not provide; after `limactl stop` and `start`, use
`ssh -F ~/.lima/NAME/ssh.config`. `limactl start` never reports a bitten
instance READY, since it waits for Lima's guest agent, and `limactl stop`
forces the VM off.

## Slots

A bitten machine boots a *slot*: the rootfs kept on disk, read-only.
`make slot` builds one in `build/<arch>/<form>/slot/`:

| File | Installed in | Contents |
| --- | --- | --- |
| `vmlinuz` | `/boot/werewolf/<slot>/` | Alpine's kernel |
| `initramfs.zst` | `/boot/werewolf/<slot>/` | stage0: busybox, blkid, mount, werewolf's module loader, the form's modules |
| `root.erofs` | `/var/lib/werewolf/<slot>/` | the rootfs |

stage0 mounts `root.erofs` read-only, directly at `/`, as on every form; a
direct boot carries the same image in its initramfs. Pages load on demand
and can be reclaimed.

**Two slots, one try each.** The committed slot is GRUB's default. A new
slot gets one boot (`next_entry`) and stays only if `commit` finds it
healthy. Every failure ends on the previous slot:

| Failure | Recovery | Tested |
| --- | --- | --- |
| GRUB cannot load the kernel | GRUB's `fallback` | |
| stage0 cannot mount the root | stage0 exits, the kernel panics, `panic=10` reboots | yes |
| `/init` will not run | `init=/init` makes it a panic | |
| the kernel locks up | `softlockup_panic=1` makes it a panic | |
| it boots but never gets healthy | stage0's deadman reboots it at ten minutes | yes |

The `autoupdate` form builds new slots on the machine itself; see the
README's *Autoupdate* and [updater.md](updater.md).
