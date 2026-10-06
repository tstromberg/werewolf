# werewolf

<img src="media/logo-small.png" alt="werewolf logo" width="160" align="right">

A minimal, secure, fast Linux for virtual machines: Wolfi's userland on
Alpine's kernel. Inspired by [Chainguard VMs](https://www.chainguard.dev/vms), but even more paranoid:

- **Secure**: an OpenBSD-like security philosophy: tiny attack surface, extreme security defaults.
- **Fast**: glibc and its malloc, for heavy compute.
- **Low maintenance**: few moving parts, few CVEs to chase - updates and reboots itself.
- **Auditable**: every update is logged, along with which CVE it addresses.
- **Reliable**: A/B slots; a failed update rolls itself back.
- **Injectable**: Able to take over an existing Linux VM using `bite`, for providers without custom image support.

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
[docs/bite.md](docs/bite.md) for what it refuses, `--undo`, `--cleanup`,
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
| `minimal` | | busybox, kmod, net-tools, runit; init, shutdown, services; virtio, power button | RAM | nothing | 5.7 MB | | 20 |
| `disk` | minimal | e2fsprogs, util-linux mount, blkid; ext4 | ext4 | nothing | 7.8 MB | | 31 |
| `crypt` | disk | cryptsetup; dm-crypt, hardware AES | ext4 in LUKS2 | nothing | 9.0 MB | | 36 |
| `bitten` | minimal | util-linux mount, blkid; ext4, xfs, btrfs, erofs, overlay, loop | a directory on the victim | nothing | 9.6 MB | 12.8 MB | 27 |
| `autoupdate` | bitten | apk-tools, erofs-utils, zstd; Alpine's keys; the updater | a directory on the victim | nothing | 11.4 MB | 16.0 MB | 33 |
| `sshd` | minimal | openssh-server, sftp-server | RAM | :22 | 7.9 MB | | 28 |
| `sshd-cloudflared` | sshd | cloudflared, CA certificates | RAM | :22, tunnel | 15.0 MB | | 29 |
| `lima` | autoupdate | sshd, bash, e2fsprogs: a test vehicle for Lima | ext4, or a directory on the victim | :22 | 14.3 MB | 22.8 MB | 44 |

1. **Forms build on each other with apko's `include:`.** The Makefile
   follows the chain, laying on each form's files and modules, base first.
   A `.modules` line may start with an arch: `aarch64: aes-ce-blk`.
   Modules load at boot and the loader then closes, so a module not listed
   cannot be loaded later.
2. **Every form includes `minimal`, which carries `/init`.** A service that
   lacks what it needs stays down: sshd without `sshd`, cloudflared without
   a token.
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
Forms with autoupdate need Zig 0.16 for the updater, and the Makefile
checks the version: Zig is pre-1.0 and changes between releases.
`make test` runs the updater's unit tests.

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
0700) for services.

**NoCloud** is read for Lima only: init creates the first user in
`user-data` with its ssh keys. This is not cloud-init.

## Data

The root is never written. `/data` is the one writable place, and
everything on it is cache. The form decides what it is: tmpfs, an ext4 disk,
the same encrypted with LUKS2, or a directory on a bitten machine's old
disk. See [docs/data.md](docs/data.md).

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

- **No DHCP.** Wolfi has no client outside systemd-networkd, and the
  kernel's `ip=dhcp` runs before virtio-net loads. Addresses come from the
  command line.
- **No NTP.** The clock comes from the hypervisor at boot.
- **No service sandboxing.** runit has none of systemd's; services must
  sandbox themselves, with Landlock and seccomp.
- **No external clean stop** on arm64 device-tree hypervisors (QEMU
  `virt`, Apple's VZ booting a kernel directly): Alpine's arm64 kernel
  lacks `gpio_keys`, so an external stop is a power cut. `poweroff` from
  inside works.
- **No log shipping.** Services log to the console.

## Documentation

- [docs/bite.md](docs/bite.md): taking over a VM, and slots
- [docs/data.md](docs/data.md): `/data`, disks and encryption
- [docs/updater.md](docs/updater.md): updates, the log and CVE reports
- [docs/roadmap.md](docs/roadmap.md): what comes next
