# werewolf

**Wolfi's userland on Alpine's kernel, booted from RAM.**

An experiment in the smallest machine that can run a Wolfi-packaged service:
Alpine supplies only the kernel, Wolfi supplies everything above it through
apko, and the whole root filesystem is the initramfs. There is no disk to
find, no package manager on the box, and nothing on it that was not named in
a form under `forms/`.

> Status: four forms boot, network, and take ssh; the tunnel form runs a
> Cloudflare tunnel. No postdoc yet, no updates, no DHCP. See *Next*.

## Why these two

Wolfi has no kernel. It is a container distro: glibc, continuous rebuilds,
near-zero open CVEs, and the apko/melange tooling that makes an image a
declaration rather than a procedure. Alpine's `linux-virt` is the opposite
half: a maintained KVM guest kernel, 6.18 LTS within days of upstream, with
Landlock, seccomp and lockdown compiled in and the whole VM driver set as
modules. A kernel does not care which libc runs on it, so the two fit with no
glue beyond an initramfs.

Alpine's own userland is musl, which is the thing this avoids. scan and
postdoc already carry jemalloc to escape musl's allocator; the string and
memory routines in tree-sitter would still be musl's. FreeBSD was considered
and rejected: no glibc, and postdoc's DEPLOY.md records what its jemalloc
costs to tune.

## Forms

A form is one flavour of the machine: `forms/<name>.yaml`, an apko config,
plus an optional `forms/<name>/` folder of files laid over the rootfs and an
optional `forms/<name>.modules` list of the kernel modules it needs.

| Form | Includes | Adds | /data | Listens | initramfs | packages |
| --- | --- | --- | --- | --- | --- | --- |
| `minimal` | | busybox-full, kmod, net-tools, runit; `/init`, shutdown, console; virtio, power button | RAM | nothing | 5.7 MB | 20 |
| `disk` | minimal | e2fsprogs, util-linux mount, blkid; ext4 | ext4 | nothing | 7.8 MB | 31 |
| `crypt` | disk | cryptsetup; dm-crypt, hardware AES | ext4 in LUKS2 | nothing | 9.0 MB | 36 |
| `bitten` | minimal | util-linux mount, blkid; ext4, xfs, btrfs | a directory on the victim | nothing | 9.4 MB | 27 |
| `sshd` | minimal | openssh-server, sftp-server; sshd service and policy | RAM | :22 | 7.9 MB | 28 |
| `sshd-cloudflared` | sshd | cloudflared, ca-certificates-bundle; tunnel service | RAM | :22, tunnel | 15.6 MB | 29 |
| `lima` | sshd | bash, for Lima's readiness probes; disk's packages, bitten's modules | ext4, or a directory on the victim | :22 | 12.3 MB | 39 |

```sh
make forms                    # each form and its include chain
make run FORM=minimal         # default FORM is sshd; `make lima` builds lima
```

Three rules keep it this small:

1. **A form builds on another with apko's own `include:`.** There is no form
   system. apko merges the package lists; `sshd.yaml` is `include:
   minimal.yaml` and two packages.
2. **A form's files and modules follow its packages.** The Makefile reads
   the `include:` chain out of the yaml, lays on the folder of each form
   along it, base first, and loads the modules each one lists. A form's
   parents are written in one place. A `.modules` line may begin with an
   arch and a colon (`aarch64: aes-ce-blk`) to apply to that arch alone.
3. **Every form includes `minimal`, which carries `/init`.** init therefore
   knows nothing about the form it is in: it prepares the machine and starts
   runit. A form's services prepare themselves in their `run` scripts. sshd
   generates its host keys; cloudflared parks itself with `sv down .` when
   there is no token rather than being restarted every second. The Makefile
   refuses a form whose chain does not start at `minimal`.

Forms are a chain, not a matrix. A service is written once, for runit.
When the folders become melange packages (*Next*), a form is a single apko
file.

Storage is the one exception the chain would otherwise force into a matrix,
and it does not need to be: `disk`, `crypt` and `bitten` carry no files,
only packages and modules, and init builds `/data` from whichever tools are
present (see *Data*). So a form that wants a disk without including `disk`
lists its packages and modules, which is what `lima` does.

No form ships a setuid or setgid file. Wolfi installs util-linux `mount`
setuid root, and PAM's `unix_chkpwd` setgid (PAM arrives with
openssh-server); `disk.yaml` and `sshd.yaml` clear both with apko's own
`paths:` permissions entries, which merge through `include:`.

**Where openssl is.** `minimal` and `disk` link it in exactly one place:
kmod links `libcrypto` to check module signatures, and Wolfi has no other
`insmod`. sshd and cryptsetup link it because they do cryptography. Nothing
else does. The network is configured by net-tools' `ifconfig` and `route`,
which need only libc; Wolfi's iproute2 would have pulled about thirty
packages into every form for one `ip` command, among them libcap and with
it PAM, iptables, krb5, libtirpc, libbpf and openssl's libssl.

The kernel is shared, in `build/<arch>/`; each form, with its modules, is
in `build/<arch>/<form>/`.

The heaviest form unpacks to 87 MB, 28 MB of it cloudflared. The same
packages with Wolfi's systemd instead of runit measured 189 MB, the
difference being cryptsetup, curl, dbus, libarchive, PAM and quota-tools that
nothing here calls. That is why runit; see *Next* for what systemd would buy
back.

## Build and run

Needs `apko`, `zstd`, `bsdtar` (macOS `tar` is one; `libarchive-tools` on
Debian) and either `qemu-system-*` or `limactl`.

```sh
make                 # fetch + verify the kernel, apko the rootfs, pack the initramfs
make run             # QEMU: serial console with a root shell, ssh forwarded to :2222
make lima            # the lima form under Lima, vz on Apple silicon; then `limactl shell werewolf`
make ARCH=x86_64     # the cloud arch; boots under TCG on an arm64 host
```

`make run` needs port 2222 free. If a previous QEMU is still holding it, the
new one exits with "Could not set up host forwarding rule";
`pkill -f 'qemu-system.*initramfs'` clears it.

`make` does not extract the rootfs on the host. bsdtar reads apko's tar and
writes the cpio directly (`@rootfs.tar`), so ownership and modes arrive as
apko set them, and the host's uid never leaks into the image.

The kernel package is pinned by digest. Bumping it is editing two lines.

On aarch64 Alpine ships the kernel as an EFI zboot image: a PE whose payload
is the gzipped `Image`, unpacked by its own EFI stub. QEMU boots that as is;
Apple's Virtualization framework needs the raw `Image`, so the Makefile reads
the payload offset from the zboot header and unwraps it. Both hypervisors get
the raw one.

Measured on an M-series host: init hands over to runit 0.17 s after the
kernel starts under QEMU/hvf and 1.3 s under vz; sshd answers 2.5 s after
power-on. The booted machine is seven userland processes in 51 MB.

## Configuration

`init` takes the machine's identity from two places and nothing else.

**Kernel command line** carries the network, because every hypervisor here
hands out a fixed address: `werewolf.ip=CIDR werewolf.gw=ADDR
werewolf.dns=ADDR`. `werewolf.debug=1` starts a root shell on the console;
`make run` sets it, `make lima` does not.

**A config tar** carries secrets. Keep a `config/` directory (gitignored):

```
config/
  authorized_keys      root's ssh keys (applied by init)
  hostname             (applied by init)
  data.key             the crypt form's /data key; `head -c 64 /dev/urandom`, one per host
  cloudflared/token    read by the sshd-cloudflared form's tunnel; it stays down without one
```

init applies the first two because every form has a hostname and a root
account. Anything else in the tar is for a form's services to read from
`/run/config`.

`make config` packs it; `make run` attaches it as a raw virtio disk. init
probes every block device for a ustar magic at byte 257 and extracts the
first match into `/run/config` (tmpfs, 0700). A tar needs no filesystem, no
kernel module and no tool to write, so the same mechanism works on any
provider that can attach a disk. The tunnel token reaches cloudflared through
`TUNNEL_TOKEN` in its environment, not argv.

**NoCloud** is also read, only far enough for Lima: if a block device is an
ISO 9660 volume with `user-data`, init creates the first user it names,
installs the ssh keys found in the file, and writes the `instance-id` from
`meta-data` to `/run/lima-boot-done`, which is what Lima's readiness probe
reads back. Lima refuses to log in as root, so this is what makes
`limactl shell` work. It is not cloud-init and will not become one; a
provider's user-data will be fed to the same tar reader.

Two details cost a boot each. busybox `adduser -D` leaves `!` in the shadow
field and sshd reads that as a locked account, refusing even a key; init
rewrites it to `*`. And Lima's user-mode network answers DNS on the gateway,
192.168.5.2, under vz; 192.168.5.3 is slirp's resolver and exists only under
QEMU.

## Data

The root stays in RAM. `/data` is the one writable home, and everything on
it is cache: losing it costs a cold start, never a broken machine. That rule
is what lets every failure below end in "format it again".

What `/data` is depends on the form's packages, so init never asks which
form it is in:

| Tools present | /data |
| --- | --- |
| none (`minimal`, `sshd`, `sshd-cloudflared`) | tmpfs, capped at 25% of RAM, so a runaway cache fills up instead of running the machine out of memory |
| `mke2fs` (`disk`, `lima`) | ext4 on the disk labelled `werewolf-data` |
| `mke2fs` + `cryptsetup` (`crypt`) | the same inside LUKS2, keyed by `data.key` |
| `werewolf.victim` on the command line (`bitten`, and `lima` when bitten) | a directory on the victim's filesystem, bound; see *Bite* |

It holds two trees: `/data/svc/<service>`, which each service's run script
makes for itself, and `/data/home/<user>`, for people. It is mounted
`noatime,nosuid,nodev,noexec`, which is why `disk` brings util-linux `mount`:
busybox's cannot pass those flags.

**Finding the disk.** By label, so the device name may change from boot to
boot. **Formatting it** happens only when `werewolf.data=DEV` on the command
line names a device, that device does not hold the config tar, and `blkid`
finds nothing on it at all. A disk with anything else on it is refused and
left untouched; the machine runs with RAM.

**Repairing it.** A disk carrying our label is ours, so init formats it again
when it is not what the form wants (plain under `crypt`, LUKS under `disk`),
when the key does not open it, or when `e2fsck -p` cannot repair it. Each is
logged on the console.

**The key.** `data.key` travels in the config tar like every other secret.
Delivering it through cloud-init would not make it safer: anything a
provider delivers, the provider can read. What encryption buys is that disk
snapshots, backups and recycled volumes are useless without the key, so the
key must never be stored on a disk beside them. On a single-disk provider
that means the config arrives as user-data, not as a partition. init deletes
the key from `/run/config` once the volume is open; it lives on only in the
kernel's dm table. With no key, `crypt` uses a throwaway one: still
encrypted, but `/data` does not survive a reboot.

LUKS2 rather than plain dm-crypt, so a wrong key is told apart from a corrupt
disk. pbkdf2 at 1000 iterations, because the key is random and argon2id's
default would spend up to 1 GiB and two seconds of every boot for nothing.
Opened with `no_read_workqueue,no_write_workqueue`. The hardware AES drivers
(`aes-ce-blk`, `aesni-intel`) are modules, and with the loader closed nothing
would pull them in on demand; dm-crypt would silently fall back to generic
AES. They are in the module list. Under QEMU/hvf a 1 GiB fsync write took
0.48 s encrypted and 0.50 s plain: the host disk, not the cipher, is the
limit. AF_ALG stays out: cryptsetup does not need it, and it is a socket
interface to the kernel's crypto code that every process could reach.

XTS hides data; it does not detect tampering by someone who can write to the
disk. dm-integrity would, at a cost in write speed. Not done.

`make run` attaches `build/<arch>/data.img`, a sparse 8 GiB disk shared by
every form of an arch, as `vda`, with `werewolf.data=vda`. Delete it to start
from a blank disk. `make lima` uses Lima's own instance disk, grown to
100 GiB, which lives until `limactl delete`.

Measured on that disk, each boot powered off hard: a blank disk becomes LUKS
or ext4 in 0.3 s of boot time and reopens with its contents; a new key, no
key, or a form switch reformats it, with a console line saying why; a disk
holding an ISO is refused and left byte-identical.

## What init does

Mount the pseudo-filesystems. `insmod` the modules in the order the Makefile
wrote (it reads each leaf's transitive dependencies from Alpine's
`modules.dep` back to front, which is what modprobe would do, so no kmod index
files travel), then set `kernel.modules_disabled=1` so no kernel code can be
added for the life of the machine. Bring up one interface. Read config.
Build `/data`. Mark the console down unless `werewolf.debug=1`.
`exec runit`.

## Shutdown

runit is PID 1, in its own three stages. init is stage 1, already done when
runit starts, so `/etc/runit/1` is empty. Stage 2 is `runsvdir`. Stage 3
stops every service (30 s each before KILL), syncs, unmounts `/data` (or
remounts it read-only if something still holds it) and closes LUKS; then
runit kills what is left and powers off, or restarts.

Three things ask for it. `poweroff` and `reboot` in `/usr/bin` are one line
each, `runit-init 0` and `runit-init 6`. And the `powerbtn` service turns
the hypervisor's power button into `poweroff`: `button` and `evdev` deliver
the ACPI button as an input event, and the run script reads the 24-byte
`struct input_event` records off each `/dev/input/event*` with `dd` and
`od`, waiting for `KEY_POWER` pressed. No acpid, no new package.

Where that event exists, it works: x86 and arm64 cloud servers boot with
ACPI, and a provider's shut-down button is that press. Measured under QEMU
x86_64, `system_powerdown` from the monitor stopped the services, unmounted
`/data` and powered off, and a file written without `sync` was there on the
next boot. Under QEMU aarch64 `poweroff` did the same, with `crypt` closing
LUKS too, and `reboot` came back up with the volume reopened.

Where it does not: an arm64 machine described by a device tree (QEMU's
`virt` with `-kernel`, Apple's VZ under Lima) wires its power button to
`gpio-keys`, and Alpine's arm64 `linux-virt` does not build that driver. No
input device appears, `powerbtn` parks itself, and `limactl stop` remains a
power cut that can lose the last few seconds of writes. `poweroff` from
inside works there as everywhere.

The debug console is an interactive `ash`, which ignores the TERM runsv
stops a service with, so stage 3 used to wait out its whole timeout on it.
`console/control/t` sends HUP instead.

init's stdin is `/dev/null`. mke2fs once asked "Proceed anyway?" on the
console over an old signature, waited a minute for nobody, said no, and left
the machine on RAM; nothing init runs may wait on a person.

One limitation worth knowing: Wolfi's busybox `mount` has no flag parsing,
so `nosuid`/`noexec` cannot be set from it; the pseudo-filesystems are
mounted with kernel defaults. Forms with a disk carry util-linux `mount`,
which is how `/data` gets its flags.

## Bite

Where a provider will not boot our image, `bite` turns a Debian, Ubuntu,
Fedora or Rocky machine into werewolf from inside. It is a POSIX shell
script; the host's own GRUB tools do the rest.

```sh
make FORM=bitten                         # vmlinuz + initramfs.zst for this arch
sudo ./bite -n DIR                       # check, and show the plan; changes nothing
sudo ./bite --reboot [--config X] DIR    # take over, and reboot into werewolf
sudo ./bite --undo                       # from the distro: as if it never happened
bite [-n] --cleanup                      # in werewolf, after commit: delete the distro
```

DIR holds `vmlinuz` and `initramfs.zst` of a form that can live on a bitten
machine: `bitten`, or any form with util-linux `mount`, `blkid` and
`bitten.modules`.

**Nothing of the distro is removed, and the disk is not repartitioned.**
werewolf's kernel goes in `/boot/werewolf`, beside the distro's, where GRUB
can read it. `/var/lib/werewolf` holds `config.tar` and `data/`, which
becomes `/data`. The root stays in RAM. On the victim's disk, the distro's
filesystem already exists and repairs itself as it mounts, so a directory
on it is the direct route: no image file, no loop device, no second
filesystem to check.

**It boots werewolf once, and keeps it only if it is healthy.** bite adds a
GRUB entry after the distro's and runs `grub-reboot`, so werewolf is chosen
for one boot only. In werewolf, the `commit` service waits until every
running service has stayed up for a minute, then makes it GRUB's default by
rewriting `saved_entry` in GRUB's environment block in place. Until then,
any reset comes back to the distro. Debian and Ubuntu get a
`/etc/grub.d/42_werewolf` that uses the distro's own `grub-mkconfig_lib`, and
`GRUB_DEFAULT=saved` in `/etc/default/grub.d/99-werewolf.cfg`; Fedora and
Rocky get a Boot Loader Spec entry.

**The victim stays visible, not writable.** In werewolf the distro's root
filesystem is mounted at `/victim`, read-only: you can look at everything
the machine was, and nothing can change it, or werewolf's own kernel beside
it, through that path. Read-only is a property of the mount, not the
filesystem, so `/data`, bound from the same filesystem, stays writable.
`commit` and `bite --cleanup` mount it again, apart, for as long as they
write. Root could still remount it or write the disk; this is a guardrail
for everything that is not root, and for mistakes.

**`bite --cleanup` ends the fallback.** The distro is a stale fallback once
werewolf is GRUB's default: nothing updates it, and it still holds whatever
it held, cloud-init's copy of the user-data among it. `bite` ships in the
`bitten` image, and `bite --cleanup` in werewolf deletes the distro, keeping
werewolf's directory and, if it is on the same filesystem, `/boot`, which
holds GRUB and werewolf's kernel. It refuses until werewolf is GRUB's saved
default, since before that a reset still needs the distro. `-n` lists what
would go. It remounts the filesystem with `discard` first, so a thin cloud
volume gets the freed blocks back; `rm` does not erase them, and snapshots
taken earlier still hold the distro, which it says. Afterwards `--undo` is
impossible and GRUB's menu still lists the distro, which no longer boots.
Measured: Debian went from 1.6 GB used to 105 MB, Fedora from 1.1 GB to
117 MB with its `root` and `home` subvolumes gone; both power-cycled
straight back into werewolf with `/data` intact.

**It refuses rather than strand a machine.** Before changing anything it
checks the kernel is for this arch, that Secure Boot is off (shim will not
load Alpine's unsigned kernel), that the NIC and disk are virtio (all
werewolf drives), that neither is behind LVM or LUKS, and that the host
filesystem is ext4, xfs or btrfs.

**It writes down what werewolf cannot discover.** On the command line in the
GRUB entry:

| Parameter | |
| --- | --- |
| `werewolf.ip`, `.gw`, `.dns`, `.mac` | the live address, gateway, resolver (past systemd-resolved's stub) and NIC; cloud addresses come from DHCP but do not change |
| `werewolf.victim=UUID:DIR` | the victim's filesystem holding `/var/lib/werewolf`, and its path as werewolf will see it |
| `werewolf.grubenv=UUID:PATH` | GRUB's environment block, often on a separate `/boot` |
| `console=` | the distro's consoles that exist here, then `hvc0` if there is one, last, so werewolf logs where the hypervisor keeps logs |

Each path is proved before it is written: bite mounts the filesystem by UUID
exactly as werewolf will, and checks it finds the same inode. On btrfs that
is what turns Fedora's `/var/lib/werewolf` into the path below its subvolume.
The config tar carries the hostname and the `authorized_keys` of root and of
whoever ran bite through sudo, so the same keys let you in as root.

**Measured in Lima (aarch64, VZ, booting through UEFI and GRUB):**

| Distro | Host filesystem | `/boot` | werewolf up | commit | after a power cycle |
| --- | --- | --- | --- | --- | --- |
| Debian 13 | ext4 | on root | 0.41 s | yes | werewolf |
| Ubuntu 26.04 | ext4 | own ext4 | 0.41 s | yes | werewolf |
| Fedora 44 | btrfs, subvolumes | btrfs subvolume | 0.41 s | yes | werewolf |
| Rocky 10 | xfs | own xfs | 0.42 s | yes | werewolf |

A hard reset before commit came back to the distro on Debian and on Fedora,
whose `/boot` is btrfs. On Ubuntu, handing `saved_entry` back from inside
werewolf, rebooting to Ubuntu and running `bite --undo` left no file, GRUB
script, `grub.cfg` entry or saved default behind, and Ubuntu booted as
before.

Five things it took to get there. GRUB reads ext4 and xfs without replaying
their journals, so a reset moments after bite booted the distro as it had
been, though Linux, replaying the journal, saw every change: bite now ends by
freezing and thawing each filesystem GRUB reads (`fsfreeze`), which writes
everything in place, and a power cut straight after bite then booted
werewolf. btrfs asks the crypto API for `crc32c`
when it mounts, after the module loader is closed, so `crc32c-cryptoapi` is
in `bitten.modules`; util-linux will not mount a filesystem already mounted
read-write a second time read-only, so bite's proof mounts it read-write
and only looks; cloud images name consoles for hypervisors they are not on
(`ttyAMA0` under VZ), so only those that exist are kept; and `-n` must not
create `/var/lib/werewolf`, so preflight checks parent directories.

**Lima specifics.** A Lima instance started on the distro talks ssh over
vsock, which systemd provides and werewolf does not, so until the instance
is restarted Lima's forward resets; after `limactl stop`/`start` it falls
back to its user-mode network and `ssh -F ~/.lima/NAME/ssh.config` works.
`limactl start` on a bitten instance never reports READY, since it waits
for Lima's guest agent. Under EFI, VZ does expose an ACPI power button and
`powerbtn` listens on it, but `limactl stop` did not press it; it waited,
then forced the VM off.

## What is deliberately not here

- **No DHCP client.** Wolfi ships none outside systemd-networkd, and the
  kernel's own `ip=dhcp` runs before a modular virtio-net exists. Static is
  right for QEMU and Lima; it is the first real problem for the cloud step.
- **No NTP.** The guest trusts the hypervisor's clock at boot. chrony is in
  Wolfi; it is one service and one `pool` line when a long-lived VM needs it.
- **No sandbox around services.** postdoc's systemd unit carries twenty
  `Protect*`/`Restrict*` directives and a seccomp filter. runit has none of
  that. Either systemd comes back for it, or postdoc sandboxes itself with
  Landlock and seccomp, which would protect every platform it runs on.
- **No clean stop from outside on arm64 device-tree hypervisors** (Lima/VZ,
  QEMU `virt`); see *Shutdown*. A kernel with `gpio_keys` would fix it.
- **No logs.** Services write to the console. Metrics go to OTel as before.

## Next

1. **postdoc as a Wolfi apk.** melange needs a Linux host; uruk-hai (arm64)
   and galadriel (x86-64) are available. scan's deleted melange/apko files
   (`scan` repo, `648332c^:packaging/wolfi/`) are the starting point. Then
   a `postdoc` form: `include: minimal.yaml` (or `sshd-cloudflared.yaml`
   while it is being debugged), one package, one `run` script.
2. **Form folders into apks.** `werewolf-init`, `werewolf-sshd` and
   `werewolf-cloudflared` built by melange make each form a single apko file,
   and the overlay step disappears.
3. **DHCP**, by the cheapest honest route: a Wolfi busybox rebuilt with
   udhcpc, or a `systemd` form. Wolfi has the parts for one (`systemd-init`,
   `systemd-default-network` for networkd DHCP, `openssh-service` for an
   enabled `sshd.service`); it would be the one form that does not include
   `minimal`, and init's last line would have to become a per-form hook.
   Deferred until something needs it.
4. **A real root.** erofs (apko can emit it) under dm-verity, with the
   initramfs shrunk to busybox + kmod. Then an A/B pair of images and a
   signed manifest on R2, which is the update story: hosts reboot into the
   new slot, with `systemd-boot`'s boot counting or a hand-rolled equivalent
   to fall back.
5. **Lockdown** once nothing needs it open: `lockdown=integrity` on the
   command line, sshd gone from production images, nftables default-deny
   inbound.
6. **A helper, in Go.** `update` needs a signed manifest fetched over
   validated TLS (busybox `wget` does not validate, Wolfi's `wget` and
   `curl` pull openssl, and Wolfi has no minisign or signify) and GRUB's
   environment block written. One static, standard-library binary would do
   both, take `commit`'s block rewrite from shell, and replace kmod's
   `insmod` with `finit_module(2)`, taking openssl's libcrypto out of every
   form that does no cryptography.
7. **`update`.** Hourly, with jitter: a signed manifest from R2 with a
   serial that only rises, the new kernel and initramfs into the other of
   two slots in `/boot/werewolf`, `grub-reboot` into it, and `commit` once
   it is healthy. The slots and the commit are what bite already installs.
8. **bite on x86** against a throwaway cloud VM, and drivers beyond virtio
   (NVMe, ENA, Hyper-V) when a provider needs them.
