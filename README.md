# werewolf

<img src="media/logo-small.png" alt="werewolf logo" width="160" align="right">

A minimal, secure, fast Linux for virtual machines: Wolfi's userland on
Alpine's kernel.

We wanted Chainguard's VMs without paying for them:

- **Secure**: little to attack.
- **Fast**: glibc and its malloc, for heavy compute.
- **Low maintenance**: few CVEs to chase; it updates and reboots itself.
- **Auditable**: every update is logged.
- **Reliable**: A/B slots; a failed update rolls itself back.

Images are built from *forms*, so each holds only what it needs. Where a
provider will not boot a custom image, `bite` takes over an existing Debian,
Ubuntu, Fedora or Rocky VM.

## Quick start

On a Mac, with [Homebrew](https://brew.sh):

```sh
brew install apko lima qemu zstd erofs-utils
git clone https://github.com/tstromberg/werewolf.git
cd werewolf
```

On Linux, install the same plus `bsdtar` (`libarchive-tools` on Debian and
Ubuntu).

### In Lima

```sh
make lima                  # build the lima form and boot it
limactl shell werewolf     # log in as yourself, with your ssh key
make lima-stop             # stop and delete the VM
```

The first build downloads Alpine's kernel and Wolfi's packages. Lima runs
the VM under Apple's Virtualization framework on a Mac and QEMU elsewhere,
with a 100 GiB `/data` disk that lasts until `make lima-stop`. Inside there
is no sudo, and not much else:

```sh
cat /usr/share/werewolf/release   # form, build time, kernel
ls /etc/sv                        # every service there is
free -m                           # about 60 MB in use
```

Lima copies the kernel and initramfs only at creation, so boot a change with
`make lima-stop lima`.

### In QEMU

```sh
make run                   # the sshd form: a root shell on the console
make ssh                   # from another terminal
```

`poweroff`, or Ctrl-A X, ends it. ssh logs in as root with the keys in
`config/authorized_keys` (*Configuration*):

```sh
mkdir -p config && cp ~/.ssh/id_ed25519.pub config/authorized_keys
```

`make run` needs port 2222 free; `pkill -f 'qemu-system.*initramfs'` frees
it.

### Other forms and architectures

```sh
make forms                 # each form and its include chain
make run FORM=minimal      # 5.7 MB, nothing listening
make run FORM=crypt        # /data encrypted with LUKS2
make run ARCH=x86_64       # from arm64: cross-built, emulated, slow
```

## Forms

A form is `forms/<name>.yaml`, an apko config, with an optional
`forms/<name>/` of files laid over the rootfs and an optional
`forms/<name>.modules` list of kernel modules.

| Form | Includes | Adds | /data | Listens | RAM image | root.erofs | Packages |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `minimal` | | busybox, kmod, net-tools, runit; init, shutdown, services; virtio, power button | RAM | nothing | 5.7 MB | | 20 |
| `disk` | minimal | e2fsprogs, util-linux mount, blkid; ext4 | ext4 | nothing | 7.8 MB | | 31 |
| `crypt` | disk | cryptsetup; dm-crypt, hardware AES | ext4 in LUKS2 | nothing | 9.0 MB | | 36 |
| `bitten` | minimal | util-linux mount, blkid; ext4, xfs, btrfs, erofs, overlay, loop | a directory on the victim | nothing | 9.6 MB | 12.8 MB | 27 |
| `autoupdate` | bitten | apk-tools, erofs-utils, zstd, jq, wget; Alpine's keys; the updater | a directory on the victim | nothing | 11.5 MB | 16.4 MB | 36 |
| `sshd` | minimal | openssh-server, sftp-server | RAM | :22 | 7.9 MB | | 28 |
| `sshd-cloudflared` | sshd | cloudflared, CA certificates | RAM | :22, tunnel | 15.0 MB | | 29 |
| `lima` | autoupdate | sshd, bash, e2fsprogs: a test vehicle for Lima | ext4, or a directory on the victim | :22 | 14.4 MB | 23.2 MB | 47 |

1. **Forms build on each other with apko's `include:`.** The Makefile
   follows the chain, laying on each form's files and modules, base first.
   A `.modules` line may start with an arch: `aarch64: aes-ce-blk`.
2. **Every form includes `minimal`, which carries `/init`.** init does not
   know which form it is in. Each service prepares itself in its run script
   and parks itself (`sv down .`) when it lacks what it needs: sshd without
   `sshd`, cloudflared without a token.
3. **Storage forms carry only packages and modules.** init builds `/data`
   from whichever tools are present (*Data*).

No form ships a setuid or setgid file; apko `paths:` entries clear them
from util-linux `mount` and PAM's `unix_chkpwd`. openssl appears only where
it is needed: sshd, cryptsetup and apk-tools use it, and kmod links
`libcrypto` to check module signatures. Networking uses net-tools, which
needs only libc; Wolfi's iproute2 would pull in about thirty packages, PAM
and iptables among them. runit, not systemd: the heaviest form is 87 MB, and
the same packages with systemd measured 189 MB.

## Build

To build without booting:

```sh
make                 # build/<arch>/vmlinuz, build/<arch>/<form>/initramfs.zst
make slot            # vmlinuz, stage0 and root.erofs, for bite
```

Images need `apko`, `zstd` and `bsdtar`; slots also need `mkfs.erofs`.

bsdtar writes the cpio straight from apko's tar, so ownership arrives as apko
set it. The kernel is pinned by digest. On aarch64, Alpine ships an EFI zboot
image; the Makefile unwraps the raw `Image`, which Apple's Virtualization
framework requires.

On an M-series Mac, init hands over to runit 0.17 s after the kernel starts
(1.3 s under VZ). The booted machine runs seven processes in 51 MB.

## Configuration

**The kernel command line** sets the network (`werewolf.ip=CIDR`,
`werewolf.gw=`, `werewolf.dns=`, `werewolf.mac=`), the disk `/data` may
format (`werewolf.data=DEV`), and `werewolf.debug=1`, a root shell on the
console, which `make run` sets.

**The config tar** carries secrets. It is written raw to any block device,
where init finds it by its ustar magic, or on a bitten machine is
`/var/lib/werewolf/config.tar`. Keep a `config/` directory (gitignored);
`make config` packs it.

```
config/
  authorized_keys      root's ssh keys
  hostname
  data.key             crypt's /data key: `head -c 64 /dev/urandom`, one per host
  cloudflared/token    sshd-cloudflared's tunnel; it stays down without one
```

init applies the first two and leaves the rest in `/run/config` (tmpfs,
0700) for services. cloudflared gets its token through the environment, not
argv.

**NoCloud** is read for Lima only: init creates the first user in
`user-data` with its ssh keys, and writes `/run/lima-boot-done` for Lima's
readiness probe. This is not cloud-init.

## Data

The root is never written. `/data` is the one writable place, and
everything on it is cache: losing it costs a cold start, never a broken
machine. That is why every failure below ends in reformatting.

| Present | /data |
| --- | --- |
| no storage tools | tmpfs capped at 25% of RAM, so a runaway cache fills up rather than exhausting memory |
| `mke2fs` | ext4 on the disk labelled `werewolf-data` |
| `mke2fs`, `cryptsetup` | the same in LUKS2, keyed by `data.key` |
| `werewolf.victim=` | a directory on the victim's filesystem (*Bite*) |

`/data` holds `/data/svc/<service>` and `/data/home/<user>`, and is mounted
`noatime,nosuid,nodev,noexec`.

**The disk** is found by its label. It is formatted only when
`werewolf.data=DEV` names it, it is not the config disk, and `blkid` finds
nothing on it; anything else is refused and the machine runs from RAM. A
disk with our label that the form cannot use (the wrong type, a key that
does not open it, damage `e2fsck -p` cannot repair) is reformatted, with a
console line saying why.

**Encryption** protects snapshots, backups and recycled volumes, so the key
must not be stored beside them: on a single-disk provider, deliver the
config as user-data. init deletes the key from `/run/config` once the volume
is open. Without a key, `crypt` uses a throwaway one, and `/data` does not
survive a reboot.

LUKS2 tells a wrong key from a corrupt disk. pbkdf2 runs at 1000 iterations
because the key is random; argon2id would cost up to 1 GiB and two seconds
per boot. The hardware AES modules are loaded explicitly, since once the
loader closes, dm-crypt would silently fall back to generic AES.
Under QEMU a 1 GiB synced write took 0.48 s encrypted and 0.50 s plain. XTS
does not detect tampering; dm-integrity would, at a cost in write speed.

`make run` attaches a sparse 8 GiB `build/<arch>/data.img`; delete it for a
blank disk.

## Boot and shutdown

init mounts the pseudo-filesystems, loads the form's modules in dependency
order (from Alpine's `modules.dep`, no kmod index needed), and sets
`kernel.modules_disabled=1`: no kernel code can be added after boot. It
brings up one interface, reads the config, builds `/data` and execs runit.
Its stdin is `/dev/null`, so no tool can stall a boot waiting for input.

runit's stage 3 stops the services (30 s each), unmounts `/data`, closes
LUKS, and remounts the victim's filesystem read-only (*Slots*). `poweroff`
and `reboot` call `runit-init`. The `powerbtn` service reads ACPI
power-button events from `/dev/input` with `dd` and `od`, so a provider's
shutdown button shuts the machine down cleanly; under QEMU x86_64, a write
never synced survived it.

Alpine's arm64 kernel lacks `gpio_keys`, so on device-tree arm64 hypervisors
(QEMU `virt`, Apple's VZ booting a kernel directly) the power button never
arrives and an external stop is a power cut. `poweroff` from inside works
everywhere.

Wolfi's busybox `mount` cannot set `nosuid` or `noexec`, so the
pseudo-filesystems get kernel defaults; forms with storage carry util-linux
`mount`.

## Bite

`bite`, a POSIX shell script, takes over a Debian, Ubuntu, Fedora or Rocky
VM using the distro's own GRUB tools.

```sh
make FORM=autoupdate slot               # build/<arch>/autoupdate/slot/
sudo ./bite -n DIR                      # check, and show the plan
sudo ./bite --reboot [--config X] DIR   # take over, and reboot into werewolf
sudo ./bite --undo                      # from the distro: remove werewolf
bite [-n] --cleanup                     # in werewolf, after commit: delete the distro
```

DIR holds a slot (*Slots*) of a form built on `bitten`.

**Nothing is removed or repartitioned.** The slot's kernel and stage0 go in
`/boot/werewolf/<slot>`; `root.erofs`, `config.tar` and `data/` go in
`/var/lib/werewolf`.

**werewolf boots once, then must prove itself.** bite adds GRUB entries
`werewolf-a` and `werewolf-b` and boots `werewolf-a` once (`grub-reboot`).
When every service has stayed up for a minute, the `commit` service makes
that slot GRUB's default; until then, a reset returns to the distro. bite
also sets GRUB's `fallback` to the saved default.

**It refuses rather than strand a machine**: the wrong architecture, Secure
Boot on (shim will not load Alpine's unsigned kernel), a NIC or disk that is
not virtio, LVM or LUKS, or a filesystem other than ext4, xfs or btrfs.

**It records what werewolf cannot discover** on the kernel command line:

| Parameter | |
| --- | --- |
| `werewolf.ip`, `.gw`, `.dns`, `.mac` | the live network; cloud addresses come from DHCP but do not change |
| `werewolf.victim=UUID:DIR` | the distro's filesystem and werewolf's directory on it |
| `werewolf.grubenv=UUID:PATH` | GRUB's environment block |
| `werewolf.slot=a\|b` | which slot this entry boots |
| `console=` | the distro's consoles that exist, then `hvc0`, where hypervisors keep logs |
| `init=/init panic=10 softlockup_panic=1` | failures reboot into the last good slot (*Slots*) |

bite verifies each path by mounting the filesystem as werewolf will. The
config tar gets the hostname and the ssh keys of root and of the sudo user.
bite finishes with `fsfreeze`, because GRUB reads ext4 and xfs without
replaying their journals.

**The victim stays visible, not writable.** werewolf mounts the distro's
filesystem read-only at `/victim`; `/data`, bound from it, stays writable.
Writers (`commit`, the updater, `--cleanup`) mount it separately. Root can
still remount it; this guards against mistakes and non-root code.

**`--cleanup` ends the fallback.** Once werewolf commits, the distro is
stale and still holds its secrets, cloud-init's user-data among them. Run in
werewolf, `bite --cleanup` deletes everything but `/boot` and
`/var/lib/werewolf`, remounting with `discard` first. It refuses before
commit. Freed blocks are not erased, and earlier snapshots still hold the
distro.

**Tested in Lima** (aarch64, UEFI and GRUB), with the RAM-root image; slots
so far on Debian 13 only:

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
| `initramfs.zst` | `/boot/werewolf/<slot>/` | stage0: busybox, kmod, blkid, mount, the form's modules |
| `root.erofs` | `/var/lib/werewolf/<slot>/` | the rootfs |

stage0 loads the modules, closes the loader, mounts `root.erofs` read-only
under a tmpfs overlay, and hands over to its `/init` with `mount --move` and
`chroot` (Wolfi's `switch_root` comes in a 22 MB package). Writes go to RAM
and vanish at reboot. Unlike a RAM root, pages load on demand and can be
reclaimed: 79 MB in use on a 4 GB VM.

`root.erofs` is built straight from apko's tar, with LZ4HC for fast random
reads and `-b 4096`: on Apple silicon, mkfs.erofs would default to 16 KiB
blocks, which a 4 KiB-page kernel cannot mount.

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

The deadman is a subshell stage0 leaves running. After ten minutes it looks
for `/run/werewolf/committed` through `/proc/1/root`, and if it is missing,
reboots through sysrq. Alpine's kernels lack `softdog`, so the deadman is
the watchdog.

`init=/init` matters for another reason: without it, a kernel whose `/init`
will not run falls back to `/bin/sh`, an unauthenticated root shell on the
console.

GRUB reads ext4 and xfs without their journals, and the loop device under
`/` keeps the victim's filesystem mounted. So shutdown remounts that
filesystem read-only, which writes the journal into place before GRUB looks
for a new slot's files.

## Autoupdate

The `autoupdate` form updates a bitten machine from Wolfi and Alpine
directly: no build server, no signing key of ours, nothing apk has not
verified against keys in the image. At boot, once committed, and every 20
hours, `/usr/lib/werewolf/update`:

1. **Fetches.** apk builds a userland from the image's own `/etc/apk`
   (apko's `world`, repository and Wolfi key), and fetches Alpine's
   `linux-virt`, verified against the Alpine keys in
   `/etc/werewolf/alpine-keys`. Those keys matched byte for byte at
   alpinelinux.org and in Alpine's git.
2. **Compares** them with the running image. If nothing changed, it logs
   `check` and stops.
3. **Builds** the other slot as `make slot` would, from the build record in
   `/usr/share/werewolf`. It also does the two things apko does that apk
   does not: busybox's links, and clearing setuid and setgid bits.
4. **Installs** the slot, sets GRUB's `next_entry`, logs `update`, and
   reboots.
5. **After the reboot**, logs `commit` or `rollback`. A build that rolled
   back is not retried until its contents change.

Each event is a JSON line in `/data/svc/autoupdate/log` and on the console.
From a test in Lima, with an image claiming an older kernel:

```
{"time":"2026-10-06T12:42:29Z","host":"lima-bite-erofs","event":"update","from":"a","to":"b","build":"ad5c83649ab367c6","kernel":"linux-virt-6.18.54-r0 -> linux-virt-6.18.55-r0","packages":""}
{"time":"2026-10-06T12:43:42Z","host":"lima-bite-erofs","event":"commit","slot":"b","release":"lima 20261006T124216Z linux-virt-6.18.55-r0 updated-on-lima-bite-erofs"}
{"time":"2026-10-06T12:43:50Z","host":"lima-bite-erofs","event":"check","slot":"b","release":"lima 20261006T124216Z linux-virt-6.18.55-r0 updated-on-lima-bite-erofs","result":"current"}
```

`packages` lists changes as `old -> new`, `+added` and `-removed`. `cves`
lists, per source package, the CVEs the update fixes, from Wolfi's
`security.json`: those fixed in a version newer than the old one and no
newer than the new one. A versioned stream such as `openssl-4.0` is also
looked up under its base name. The file is not signed, so it informs the
log and nothing else; if it cannot be fetched, `cves` reads `unavailable`
and the update goes ahead. Alpine's security database does not track the
kernel, so kernel updates are logged by version only.

```
"cves":"busybox: CVE-2023-39810 CVE-2024-58251 ...; glibc-2.44: CVE-2026-18374 ...; zlib: CVE-2026-85091"
```

Updates never touch werewolf's own files (`init`, the run scripts, `bite`,
the updater). Those are copied forward and change only with a new image.

## Limits

- **No DHCP.** Wolfi has no client outside systemd-networkd, and the
  kernel's `ip=dhcp` runs before virtio-net loads. Addresses come from the
  command line.
- **No NTP.** The clock comes from the hypervisor at boot.
- **No service sandboxing.** runit has none of systemd's; services must
  sandbox themselves, with Landlock and seccomp.
- **No external clean stop** on arm64 device-tree hypervisors (*Boot and
  shutdown*).
- **No log shipping.** Services log to the console.

## Next

1. werewolf's own files as apks, so autoupdate can update werewolf itself.
2. DHCP: busybox with udhcpc, or a systemd form.
3. dm-verity under `root.erofs`, with the root hash on the command line.
4. Lockdown: `lockdown=integrity`, no sshd in production, nftables
   default-deny inbound.
5. A static `finit_module(2)` helper in place of kmod, removing libcrypto
   from forms that do no cryptography.
6. Shipping the update log off the machine.
7. bite on x86, and drivers beyond virtio (NVMe, ENA, Hyper-V).
