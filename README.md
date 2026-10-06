# werewolf

<img src="media/logo-small.png" alt="werewolf logo" width="160" align="right">

Quite possibly the world's most secure Linux distribution, with no way to execute malware out of the box.

Werewolf Linux is a minimal, secure, fast Linux for virtual machines, combining [Wolfi](https://wolfi.dev/)'s userland with 
[Alpine](https://www.alpinelinux.org/)'s kernel. It enforces a strict secure-by-default philosophy, inspired by [Chainguard VMs](https://www.chainguard.dev/vms) and [OpenBSD](https://openbsd.org/).

- **Secure**: tiny attack surface, with heavy use of Landlock and privilege separation.
- **Fast**: glibc and its malloc, for heavy compute.
- **Low maintenance**: few moving parts, few CVEs to chase - updates and reboots itself.
- **Auditable**: every update is logged, along with which CVE it addresses.
- **Reliable**: A/B slots; a failed update rolls itself back.
- **Injectable**: Able to take over an existing Linux VM using `bite`, for providers without custom image support.

## Security

The philosophy: carry as little as possible, lock what can be locked at
boot so that not even root can unlock it, keep the system itself off any
writable disk, and prove every claim with a test.

- **Tiny**: `minimal` is 10 packages, 3 MB, and listens on nothing. No
  systemd, no package manager outside `autoupdate`, no setuid or setgid
  binaries. Modules load, and the network comes up, through werewolf's own
  small static programs.
- **Locked at boot, for good**: the module loader closes, kernel lockdown
  refuses `kexec`, `/dev/mem` and unsigned modules, and ptrace is off, for
  root too.
- **Nothing written runs**: `/data`, `/tmp`, `/run` and `/dev/shm` are
  `noexec`, user namespaces are off so no one can mount around that, the
  kernel refuses the symlink and hardlink tricks of shared directories, and
  each user sees only its own processes.
- **One-way mounts**: werewolf mounts with its own tool,
  [mount/mount.zig](mount/mount.zig), which can add `ro`, `nosuid`, `nodev`
  and `noexec` but never lift them, mounts only werewolf's filesystems in
  werewolf's places, refuses symlinks in a path, and sandboxes itself
  before it acts.
- **Declared listeners**: each form lists the ports it listens on, and the
  tests fail on anything else listening.
- **A read-only root**: the system is an erofs image mounted read-only,
  so nothing can change its programs, and a reboot restores it. `/data` is
  the one writable disk; in `crypt` it is encrypted, with a key kept apart
  from the disk.
- **ssh**: keys only, no PAM, no forwarding.
- **Updates**: verified against keys in the image, logged with the CVEs
  they fix, and rolled back automatically if the new image is unhealthy.
- **Tested**: `make check` boots every form on every push, tries the
  attacks, and fails if one gets through.

Next: machines that install only our signed releases, and Linux's IPE, so
the kernel runs only code we signed
([design/verified-boot.md](design/verified-boot.md)). What is not yet
covered, and how to check a machine: [docs/security.md](docs/security.md).

## Quick start

First install our dependencies, for example, on macOS:

```sh
brew install apko lima qemu zstd erofs-utils zig
```

Then build and connect to a local VM:

```sh
make lima
```

Now you can login and poke around:

```sh
limactl shell werewolf
```

### QEMU-based execution

Don't care for Lima? You can rawdog it with QEMU:

```sh
make run                   # the sshd form: a root shell on the console
make ssh                   # from another terminal
```

### Taking over an existing VM

Where a provider will not boot a custom image, `bite` turns a running
Debian, Ubuntu, Fedora or Rocky VM into werewolf, without repartitioning
anything. Build a slot, copy it and `bite` to the VM, then:

```sh
make FORM=autoupdate slot               # build/<arch>/autoupdate/slot/
sudo ./bite -n DIR                      # on the VM: check, and show the plan
sudo ./bite --reboot DIR                # take over, and reboot into werewolf
```

werewolf boots once and makes itself the default only after its services
have stayed up for a minute; until then, a reset returns to the distro. See
[docs/bite.md](docs/bite.md) for what it refuses, `--undo`, `bite-cleanup`,
and how slots recover from a bad boot.

### Other Options

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
| `minimal` | | runit; init, shutdown, services, werewolf's module loader, network setup and one-way mount; virtio, power button, erofs | RAM | nothing | 3.0 MB | | 7 |
| `dhcp` | minimal | werewolf's DHCP client, split into a jailed engine and a parent with one capability; packet sockets | RAM | nothing | 3.1 MB | | 7 |
| `disk` | minimal | e2fsprogs, blkid; ext4 | ext4 | nothing | 4.2 MB | | 13 |
| `crypt` | disk | cryptsetup; dm-crypt, hardware AES | ext4 in LUKS2 | nothing | 8.0 MB | | 27 |
| `cloud` | dhcp | werewolf's metadata fetcher: the config from GCP's, AWS's or Hetzner's user data ([docs/cloud.md](docs/cloud.md)); GCP's SCSI, NVMe and gVNIC | RAM | nothing | 3.3 MB | | 7 |
| `bitten` | cloud | blkid; ext4, xfs, btrfs | a directory on the victim | nothing | 5.9 MB | 2.9 MB | 9 |
| `autoupdate` | bitten | apk-tools, erofs-utils, zstd; Alpine's keys; the updater | a directory on the victim | nothing | 9.8 MB | 6.8 MB | 22 |
| `prod` | autoupdate | nothing: the production base, published by CI ([docs/releases.md](docs/releases.md)) | a directory on the victim | nothing | 9.8 MB | 6.8 MB | 22 |
| `sshd` | minimal | openssh-server, sftp-server, busybox (a shell to log in to) | RAM | :22 | 7.8 MB | | 24 |
| `prod-ssh` | prod | sshd: published by CI ([docs/releases.md](docs/releases.md)) | a directory on the victim | :22 | 12.4 MB | 9.5 MB | 33 |
| `lima` | autoupdate | sshd, bash, e2fsprogs: a test vehicle for Lima | ext4, or a directory on the victim | :22 | 13.8 MB | 10.9 MB | 39 |
| `demo` | prod | nginx, grype, a status page; updates hourly ([docs/demo.md](docs/demo.md)) | a directory on the victim | :80 | 30.5 MB | 27.5 MB | 32 |

1. **Forms build on each other with apko's `include:`.** The Makefile
   follows the chain, laying on each form's files and modules, base first.
   A `.modules` line may start with an arch: `aarch64: aes-ce-blk`.
   Modules load at boot and the loader then closes, so a module not listed
   cannot be loaded later.
2. **Every form includes `minimal`, which carries `/init`.** A service that
   lacks what it needs stays down: sshd without `sshd`. init takes the
   address the kernel command line gives, or, in forms built on `dhcp`,
   asks the network's DHCP server.
3. **Storage forms carry only packages and modules.** init builds `/data`
   from whichever tools are present ([docs/data.md](docs/data.md)).

No form ships a setuid or setgid file.

## Build

To build without booting:

```sh
make                 # build/<arch>/vmlinuz, build/<arch>/<form>/initramfs.zst
make slot            # vmlinuz, stage0 and root.erofs, for bite
```

Images need `apko`, `zstd` and `bsdtar`; slots also need `mkfs.erofs`.
Every form needs Zig 0.17 for werewolf's own programs, and the Makefile
checks the version: Zig is pre-1.0 and changes between releases.
`make test` runs their unit tests; `make check` boots every form
and checks its protections ([docs/testing.md](docs/testing.md)).

Builds are reproducible. The first build pins every package, Wolfi's and
the kernel's, in `build/lock/`; later builds install exactly those and
write the same bytes. `make lock` takes the newest again. CI publishes
`minimal` and `prod-ssh` as signed releases whenever an image would change
([docs/releases.md](docs/releases.md)).

On an M-series Mac, init hands over to runit 0.17 s after the kernel starts
(1.3 s under VZ). The booted machine runs seven processes in 51 MB.

## Configuration

**The kernel command line** sets the network (`werewolf.ip=CIDR`,
`werewolf.gw=`, `werewolf.dns=`, `werewolf.mac=`; without `werewolf.ip`,
werewolf's own DHCP client asks the network), the disk `/data` may
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
```

init applies the first two and leaves the rest in `/run/config` (tmpfs,
0700) for services.

**On GCP, AWS and Hetzner Cloud** the config tar can instead be the
instance's user data, in base64; forms from `cloud` up fetch it when no
config disk is found ([docs/cloud.md](docs/cloud.md)).

**NoCloud** is read for Lima only: init creates the first user in
`user-data` with its ssh keys. This is not cloud-init.

## Data

The root is never written. `/data` is the one writable place, and it can
hold real data: init formats a disk only while it is blank, and never one
it has used. The form decides what it is: tmpfs, an ext4 disk, the same
encrypted with LUKS2, or a directory on a bitten machine's old disk. See
[docs/data.md](docs/data.md).

## Autoupdate

The `autoupdate` form keeps a bitten machine current from Wolfi and Alpine
directly: no build server, and nothing installed that apk has not verified
against keys in the image. At boot and every 20 hours, if anything is
newer, it builds the other slot, boots it once, and keeps it only if it
stays healthy.

Every update is logged with the CVEs it fixes, in packages and the kernel
alike, and writes a report an auditor can reproduce:

```
{"time":"2026-10-06T13:42:36Z","host":"lima-bite-zig","event":"update","from":"a","to":"b","build":"450cf1f484b24f41","kernel":"linux-virt-6.18.54-r0 -> linux-virt-6.18.55-r0","packages":0,"cves":1,"report":"/data/svc/autoupdate/reports/2026-10-06T13:42:36Z-450cf1f484b24f41.json"}
```

See [docs/updater.md](docs/updater.md).

## Limits

- **IPv4 only.** DHCP or a static address; no IPv6.
- **No NTP.** The clock comes from the hypervisor at boot.
- **No service sandboxing.** runit has none of systemd's; services must
  sandbox themselves, with Landlock and seccomp.
- **No log shipping.** Services log to the console.
- **No debuggers.** ptrace is off for everyone, root included, until the
  machine reboots.

## Documentation

- [docs/bite.md](docs/bite.md): taking over a VM, and slots
- [docs/data.md](docs/data.md): `/data`, disks and encryption
- [docs/updater.md](docs/updater.md): updates, the log and CVE reports
- [docs/testing.md](docs/testing.md): `make check`, and CI
- [docs/releases.md](docs/releases.md): signed, reproducible releases
- [docs/cloud.md](docs/cloud.md): the config from a cloud's metadata server
- [docs/programs.md](docs/programs.md): how werewolf's own programs separate
  privileges and confine themselves
- [docs/security.md](docs/security.md): what is locked down, what is not
  yet, and how to check
- [docs/demo.md](docs/demo.md): the demo, a self-patching page about itself
- [docs/posture.md](docs/posture.md): `posture`, which measures a machine's security
- [docs/roadmap.md](docs/roadmap.md): what comes next
- [design/fence.md](design/fence.md): only declared ports served, and the
  metadata server only for whom it is meant
- [design/verified-boot.md](design/verified-boot.md): running only code we
  signed (proposed)
