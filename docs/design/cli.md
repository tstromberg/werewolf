# howl: the werewolf command

**Note for reviewers**:
While reviewing this proposal, focus on answering for yourself:

* Does this proposal fit with our engineering principles?
* Are there unexplored concerns with this design, such as reliability or usability issues?
* Could the proposed implementation be made simpler?
* Are there other alternatives to consider?

Proposed, 2026-10-07. Built (cmd/howl, `make howl`): `build`,
`pack`, `run`; `create`, `delete` and `console` on Lima, GCP and AWS; and
`upload` to GCP and AWS. On AWS (2026-10-07), prod on a t3.small and on
a t4g.small (Graviton) runs end to end: imported, booted, its config from
IMDSv2, `up in` in 1.2 to 1.5 s, posture clean, restarted with a new
config, deleted. Graviton's 16550 is a console only when named, so the
arm64 disk names `console=ttyS0,115200` before `hvc0` (boot/mkdisk). `build` makes a form as `make dist` makes a release,
through make's `_dist-form`; `--app DIR` works with `build`, `run` and
`create`. `pack` reads FORM's
declarations from `./forms`; `--image` is not built. `pack` makes no
host keys: the bastion makes its own on first boot and keeps it in
`/data`. bhyve, Firecracker, Proxmox and Azure are built, experimental.
`make check-gcp`, `make demo` and the GCP demos run through `howl
create`; `test/gcp` keeps only its judging, and `test/lima-demo` its wait
for the page.

## Summary

One static Zig binary, `howl`, with eight verbs: build an image, pack
a config, and put the two on a machine, locally or in a cloud; and build
a form's own package from a melange recipe. `make`
stays the build system and the contributor's interface; `howl` is the
user's. A bastion or a Tailscale router becomes one command, with its
keys and destinations given as flags, and every deploy path CI tests is
the path users type.

## Background

A werewolf machine is made from three things. The *form*
([forms.md](forms.md)) says what runs: packages, services, network
policy. The *config tar* ([cloud.md](../cloud.md)) carries what is
specific to one machine: its hostname, `data.key`, ssh keys. init finds
the tar raw on any block device or in the cloud's user data, and leaves
it in `/run/config`, readable by root alone. Leash copies the files a
service file names (`config users /run/config/nats/users.conf`) into
the service's private directory, and `service-config` renders the
service's `settings.json` (routes) into the daemon's format,
inside the leash.

Getting those three things onto a machine is where the project is least
finished:

- **Make is a build graph, not a user interface.** It ignores a variable
  it does not know, so `make run FROM=prod` boots the `sshd` form without
  a word. `FORM`'s default depends on which goal was named. `DEV=` and
  `DEV=1` decide whether a shell ships, and nothing checks either.
- **The secrets path is the least tested path.** Packing the tar is seven
  shell blocks in a tutorial: `umask 077`, `COPYFILE_DISABLE=1`,
  `--format=ustar`, a heredoc for Lima. Every user runs it by hand; CI
  never does. A missing `authorized_keys` is discovered on a serial
  console, after boot, as "sshd is down".
- **Deploying is shell.** 330 lines of it under `test/`, run against real
  clouds, against the rule that werewolf's own programs are Zig
  ([shell-free.md](shell-free.md)).
- **Settings were in the wrong place.** Until `service-config`, setting a
  router's routes meant forking the form. A route is per machine, not per
  fleet. (A bastion's users and destinations are the other way, by
  choice: who reaches what is the image's, reviewed with it.)

## Goals

- A bastion or Tailscale router from a clean checkout to a running
  machine in one command, on Lima or GCP. The tutorials shrink to that
  command and a paragraph.
- Every config error that can be found on the host is found on the host:
  a missing file, a bad route, a key in the wrong format, a tar over the
  target's limit. Each names the file.
- `make check` boots machines through `howl`, so no deploy path
  exists that CI does not run. `test/gcp`, `test/lima-demo` and the
  shell blocks in `service-vms.md` are deleted.
- A built image carries a manifest, and the same inputs give the same
  bytes, whether CI built it or a user did.
- Any hypervisor that can attach two disks runs werewolf with no code in
  this tool: Proxmox, VMware, Hyper-V, a USB stick.

## Non-Goals

- A daemon, a state file, a plugin system, or a config file for the tool.
- Building without `make`, or `make` deploying without `howl`.
- `start`/`stop` apart from `create`/`delete`. A declarative machine is
  recreated, not paused.
- Provider flags beyond `--on`. Region, project, zone and machine type
  come from `gcloud config`, `aws configure` and `az configure`.
- `bite` as a verb. It runs on a machine that has no werewolf yet;
  `/bin/sh` is the honest dependency there.
- Packaging applications with melange, or any build of the application
  itself. Compiling is the user's toolchain's job.
- A text UI, prompts, or wizards. Flags and files, so every invocation
  is a line in a script or a shell history.

## Detailed design

### The three inputs

| | Is | Lives in | Changes when |
| --- | --- | --- | --- |
| **Form** | what runs: packages, services, policy | git, `forms/` | the software or the fleet's policy changes; rebuild |
| **Settings** | who this machine serves: destinations, routes, hostname | the config tar, `settings.json` | per machine; re-read at every boot, no rebuild |
| **Secrets** | `authorized_keys`, `auth-key`, `data.key` | the config tar | on rotation |

The form says what; the config says for whom. A changed destination is
another `create`, not a new image.

### The verbs

```
howl build   --with FORM,... [-o DIR] [--arch ARCH] [--format qcow2|raw|vhd|vmdk] [--app DIR]
howl pack    --with FORM [-o FILE] [-n] [--on TARGET] CONFIG...
howl run     [--with FORM,...] [--on TARGET] [--dev] [CONFIG...]   create's machine werewolf-run; prod, or lima on Lima, with no --with
howl ssh     [NAME] [-- COMMAND...]
howl stop
howl create  NAME --with FORM,... [--on TARGET] [--dev] [--arch ARCH] [--size TYPE] [--allow-from me|CIDR] [CONFIG...]
howl delete  NAME [--on TARGET]
howl console [NAME] [--on TARGET]
howl upload  FILE --on gcp|aws|azure
howl build-apk RECIPE [--arch ARCH]                 a form's own melange package
howl form    --with FORM,... --package PKG,... --oci NAME=REF --NAME.DIRECTIVE 'LINE' --KEY LINE --KEY.SUB VALUE -o DIR
```

A form is a reference, `--with`, never a positional: one alone is run as
it is; more, or anything added, is a form `howl` generates and builds,
kept with `form -o` ([adhoc.md](adhoc.md)).

`--arch` takes each world's spelling: `aarch64` or `arm64`, and `x86_64`,
`x86-64` or `amd64`, in any case. werewolf makes it `aarch64` or `x86_64`,
which make and release names use, and each cloud names it as it does:
GCP `ARM64`/`X86_64`, AWS `arm64`/`x86_64`, Azure `Arm64`/`x64`. An
image's name writes it `aarch64` or `x86-64`, as GCP's names take no
underscore. `--arch` and `--size` are for the clouds; an engine here runs
this machine's arch, and Proxmox takes `x86_64` alone.

Two rules, stated once:

- **`build` and `pack` never touch the network or a credential.** They
  are functions of their inputs: the same inputs give the same bytes.
- **`create`, `delete`, `console` and `upload` never compile anything.**
  They move files the first two made, and run the provider's own CLI
  with an explicit argument list: `limactl`, `gcloud`, `aws`, `az`. No
  `sh -c`, no SDK, no state file: the provider's list command is the
  state.

`build-apk` builds one melange recipe in Wolfi's style, as a form's
build builds the recipes in `forms/NAME/melange/` (melange.mk): for a
package Wolfi does not ship, tried before a form keeps it.
It is `build`'s kind of verb, a file from inputs, and runs make's
`_build-apk` as `build` runs `_dist-form`, so the form's build and the
author's are one path. On macOS it boots melange's QEMU runner from
werewolf's own Alpine kernel; that, and melange's modules bug the
Makefile works around, are why it is a verb rather than "run melange".

`build` is named for what it does and `image` for what it makes; the verb
wins because `image` here also names a kernel and an OCI artifact.
`build` makes a *file* from a form; `create` makes a *machine* from a
file. `run` and `create` are two verbs because they return different
things: `run` returns when the machine exits, `create` when it is up and
has a name.

### CONFIG: the config tar from flags

`CONFIG...` is the set of flags that fill the config tar. They are the
same for `pack`, `run` and `create`; `pack` writes the tar out, the
others hand it to a machine.

```
--config DIR               files, as today: DIR/hostname, DIR/nats/users.conf, ...
--hostname NAME            the hostname file
--ip CIDR --gw ADDR --dns ADDR   the network file: a static address
--data-key FILE            data.key: /data goes in LUKS2
--NAME FILE                a file a service declared: --users, --auth-key
--KEY VALUE[,VALUE...]     a setting a service declared: --routes
```

The flags are not written into the tool. The form's service files
declare them, and the CLI reads the form's chain to learn which flags
this form takes and where each lands:

```
config   users   /run/config/nats/users.conf → --users FILE
setting  routes  cidr...                     → --routes CIDR,...
```

`setting` is one new line in a service file: a key in `settings.json`
and its type, which is also what `service-config` validates with
([settings.md](settings.md)). The types are a closed set of ten in
`lib/`: `ip`, `cidr`, `addrport`, `hostport`, `hostname`, `port`, `url`,
`int`, `bool`, `string`. A form that needs anything else takes a file,
which its service validates. Flags are the common case and files the
long tail, and neither has to grow.

A flag the form does not declare is an error that lists the flags it
does. A file given both by `--config DIR` and by a flag is an error, not
a precedence rule. The flags that do not come from a form are werewolf's
own files: `--config`, `--hostname`, `--ip`/`--gw`/`--dns`,
`--data-key`, `--root-keys` and `--update-policy`, and grow only with
werewolf's own programs.

The `network` file is the kernel command line's own words, `werewolf.ip=
werewolf.gw= werewolf.dns=`, each at most once and nothing else, for a
machine no DHCP server gives an address: a hypervisor of your own, bare
metal, or a form with no DHCP client. init reads it before the network
comes up, and only when the command line has no `werewolf.ip`, which
wins; `pack` checks it with init's own parser (`lib/network.zig`). On
Lima, `create` gives a form with no DHCP client Lima's own network,
`192.168.5.15/24` by `192.168.5.2`, which the Mac does not reach: its
console does. On bhyve it gives slirp's, `10.0.2.15/24` by `10.0.2.2`.

The names are part of the form's interface, as the tar paths already
are. A chain that declares the same name twice (a form that takes two
services, each with a `tls-cert`) fails to build, and the form author
renames one. Qualifying flags only when they collide would rename
a flag when a service is added, and break every script that used it.

The declarations are already in the image: they are its service files,
in `root.erofs`, whose sha256 the release's signed manifest names. So
`--image root.erofs` reads them there, with erofs-utils' `dump.erofs
--ls` and `--cat`, which the build already needs, and takes the flags of
the image being booted with no form checked out; the flags then describe
the bytes that boot, not a source that may have moved on. The manifest
carries no copy. A copy is a second source of truth, which could
disagree with the image leash reads, and would make the release format
promise a shape. `--image` waits for someone deploying without a
checkout; until then `pack --with FORM` reads the same files from `./forms`.

A `--NAME FILE` flag reads a file. It never takes the value itself, so no
secret is in `ps` or a shell history; `-` reads standard input, for a
key that comes out of a password manager. Settings are not secret and go
on the line.

The tar is deterministic: ustar, regular files only, mode 0600, fixed
mtime and owner, entries sorted. The same flags give the same tar. The
tar is already a raw disk image; nothing else is needed to attach it.

`pack` validates everything before it writes anything, with the same Zig
functions the guest's `service-config` runs in the leash, moved to
`lib/`: a route or destination that passes here passes there. It reads
the form's `config` lines, so a nats with no `users.conf` fails naming
the file. `-n` checks and writes nothing, Venema's `postfix check`.
`--on` sets the size ceiling the target enforces (AWS 16 KB, Azure 64
KB, a disk none) and `pack` reports the size either way, because a tar
of five small files is 6 KB of ustar headers and people will be
surprised.

`pack` makes no keys. A host key is the machine's identity, and its
private half is best never leaving the machine: not on the laptop that
packed the tar, not in a cloud's metadata. So the bastion makes its own
on first boot, as a distribution does: its `before` step,
`ssh-host-key`, runs `ssh-keygen` once into `/data/svc/sshd` and logs the
fingerprint and public half on the console at every boot, for
`howl console` to show and an operator to pin. Without `/data` it
stays down, rather than take a new identity each boot. To keep an
identity across machines, keep `/data`.

### build

A form becomes a disk, through `make`, which keeps the build graph. The
output is a release's files, named as a release names them
(`FORM-ARCH-disk.qcow2`, the slot's `vmlinuz`, `stage0.zst` and
`root.erofs`), and its manifest beside them, `FORM-ARCH.json`
(`werewolf-release/1`, [releases.md](../releases.md)): the kernel, every
package's version, and every file's sha256, with a build id over them.
Every build gets one, not only CI's releases, so a bastion on Proxmox has
the provenance `prod` on GitHub has. It is built as it ships, never with
`DEV`, and only a release form is given the releases URL its updater
follows. `--format` is `qemu-img convert`, nothing more: `vhd` is fixed
and exactly the disk's size, as Azure takes it. A converted disk is not
in the manifest, which names the qcow2 it came from; qemu-img stamps a
VHD with the time, so it would not be the same twice.

`--app DIR` is the one way an application goes in: the directory lands
at the runtime form's app path (`/usr/lib/app`, or nginx's html root),
after a check that nothing in it is setuid or escapes that path. Its
content digest in the manifest is what makes the image reproducible.

### run

`run` is `create`, of the one machine it keeps for trying a form:
`werewolf-run`, on the engine `create` would pick, with `create`'s flags,
in place of the last one. With no name, `howl ssh` logs into it,
`howl console` shows its console (and, under QEMU, joins it until
Ctrl-] leaves it running), and `howl stop` ends it.

The engine, for both, when `--on` does not say: Lima on macOS, bhyve on
FreeBSD, Firecracker on Linux with KVM where its network can be set up
without a password (root, or a sudo or doas that asks none), otherwise
QEMU. The summary names it, and says why when a likelier one was passed
over ("not Firecracker: its network needs root, and sudo asks a
password"). Under QEMU the machine runs in the background with user-mode
networking, so it needs no root: ssh and the form's last port are
forwarded from this host's loopback, 2222 and 8080 or free ones when
those are taken, and it keeps a data disk of its own. `--dev` builds a
machine here with the debug shell. A form that serves ssh is up when its
sshd answers, not only when init hands over, so `howl ssh` right after
works.

Whatever it runs on, `create` keeps a machine's files in
`build/machines/NAME`, with `engine` there naming the platform, so
`delete`, `console` and `ssh` find a machine without `--on`. On every
platform the form it was made from is recorded under one name,
`werewolf-form`: a cloud's label or tag, Proxmox's description, a
comment in Lima's template.

### What the verbs say

`build`, `run` and `create` say little: one line that names the phase
they are in (make names its own: run with `--debug=b`, it says which
target it remakes, and the target's path says what it is), how long it
has run, and, faint, the last thing the commands said, so a long phase is
seen to move. Everything they said goes to a log. Done, a verb says what
it made in at most five lines: what, how long each step took (as
minikube does: the build's phases, or the VM's start, the kernel,
userland and the address, from init's own "up in" line), where it is, and
the command to reach or run it next. A failure says which phase failed,
its last lines, without repeats, where the whole log is, and the same
command with `--verbose`, which shows everything as it runs, as make
does. Off a terminal there is no line to redraw, and `create` prints its
machine line on standard output for scripts; `NO_COLOR` turns color off.

### create, delete, console

`create` builds if stale, packs the config, uploads the image if the
target has an image store and lacks this digest, attaches the tar or
sets it as user data, starts the machine, and prints what the user needs
next and nothing else. Another `create` with the same name and changed
flags replaces the tar and reboots; the image is untouched. `delete`
removes the machine; the image stays. `console` is the serial log
wherever the target keeps it (Lima's `serialv.log`,
`gcloud ... get-serial-port-output`, `aws ec2 get-console-output`,
Azure's boot diagnostics): on a shell-free machine it is the only way to
learn why it did not come up.

Without `--on`, a machine goes where this host keeps machines itself:
Lima, where it is installed on macOS, bhyve on FreeBSD with vmm loaded,
or Firecracker on Linux with KVM and `firecracker` installed, else QEMU
here, in the foreground, as `run` boots it, and not kept. `delete` and
`console` take the same default.

On Lima, built: the machine's disk is built for it, since its command
line names the MAC of its vzNAT network (`werewolf.mac`), which is the
name's sha256, so nothing records it. The tar goes in as a Lima disk,
`NAME-config`, attached unformatted, where init finds it: binary files
survive, as they would not in YAML, and Lima's instance file holds no
copy of a secret. `limactl start` waits for ssh, which never answers, so
`create` waits for the MAC's DHCP lease, newer than any a deleted
machine of the same name left, and prints `NAME ADDRESS FORM` on
standard output and nothing else there. What it built is in
`build/machines/NAME`, which `delete` removes with the instance and
its config disk. Another `create` of a name that exists, with the same
form, replaces its config: Lima keeps the template, which names the form
in a comment, and the config disk is the tar's bytes, so werewolf stops
the VM, writes the new tar over them and starts it, with its boot disk
and `/data` kept. A different form is refused: it is another disk.

Lima manages a machine only once it answers Lima's ssh, as Lima's user,
and runs Lima's readiness probes, which need a shell (bash). A form with
sshd and bash (`lima` today) is created as `make lima` creates one, from
the template make writes (`boot/lima.yaml.in`): on Lima's own network,
with its user, booted directly from the image. Lima then manages it
whole: `limactl shell`, and `limactl stop`, which presses VZ's power
button, the PL061 GPIO line power-button reads, for a clean shutdown in
about two seconds; `create` prints its ssh forward as its address. Every
other form, shell-free, never answers Lima, so its host agent never asks
VZ to press the button; it goes on vzNAT, as above, and its stop is a
hard one. Answering Lima would mean a login and a shell for whoever
holds Lima's key, which is what those forms remove. `sshd` and
`prod-ssh` have sshd and a busybox shell but not bash, and stay so: Lima
needs bash only to wrap its own probes, which are POSIX `sh`, in
`#!/bin/bash -c` on every Linux guest, and a second shell in a released
image is too high a price for that. They go on vzNAT, like the shell-free
forms, and since they run sshd with a shell, `ssh root@ADDR poweroff`
stops one cleanly. If Lima wraps its probes in `/bin/sh` one day, they
are managed with no change here.

On bhyve, built, and experimental: FreeBSD on x86_64, with no CI run
yet (`cmd/howl/bhyve.zig`). The machine's disk is built as for Lima,
and bhyve's UEFI firmware (the `bhyve-firmware` package) boots it; the
tar is a second virtio disk, read-only. bhyve is a process that needs
root and exits when the guest halts, or with 0 when it asks to reboot,
so `create` starts it through `doas` or `sudo` under `daemon(8)`,
detached, running werewolf's own supervisor (`howl _bhyve`), which
runs bhyve again after a reboot and destroys the VM when it stops; the
console is bhyve's standard output, which `daemon` appends to
`console.log` in `build/machines/NAME`, where `console` reads it
and `create` waits for the `up in` line. The network is slirp's (the
`libslirp` package), as `run`'s is under QEMU, in its `open` mode, so
the machine reaches out, as its updater must; `open` also keeps slirp's
helper process out of capability mode, where, run as root, FreeBSD
15.1's dies on `getpwnam`, and bhyve with it at the first packet. A
form with no DHCP client gets `10.0.2.15/24` by `10.0.2.2` in its tar,
and this host
reaches the machine only through the ports slirp forwards, one host port
on `127.0.0.1` per `listen tcp/PORT` in its chain's form.yaml `net`, from a
base the name's sha256 picks between 20000 and 59900; `create` says
which, and prints the first as the address. bhyve is the state:
`/dev/vmm/NAME` exists while the VM does, and the machine's directory
holds its form. A second `create` of the name replaces the tar after a
hard stop, `bhyvectl --destroy`, since nothing asks a werewolf machine
to shut down; `delete` destroys the VM the same way, which ends its
bhyve and supervisor, and removes the directory. bhyve on arm64, new in
FreeBSD 15 with other firmware, is not built.

On Firecracker, built, and experimental: Linux with KVM
(`cmd/howl/firecracker.zig`; `tools/install-deps` installs the
pinned release, which no distribution packages). The machine boots
directly: the kernel and the slot's initramfs, no bootloader and no
slots, so no updater; a data disk of its own; the tar as a second
virtio drive, read-only; and the slot's `root.erofs` as a third,
read-only, which stage0 opens through dm-verity (`werewolf.root=vdc`).
`run` appends the root to the initramfs instead, which the kernel
unpacks into RAM and never frees: on Firecracker that held 20 MB for
the machine's life and cost 26 ms of kernel time a boot, where reading
the root from the disk as it is used cost userland 10 ms, so the
machine is up 10 to 15 ms sooner with 20 MB more to spare. A rebuild
does not change the root under a running machine: the build writes a
new `root.erofs` rather than over the old, which Firecracker holds
open until it next boots. Firecracker has
no PCI, so minimal's form.yaml `modules` carries `virtio_mmio`, its bus. Firecracker
runs as the user and exits when the guest stops, for a reboot as for a
halt, so `create` starts it detached, under `setsid`, through
werewolf's own supervisor (`howl _firecracker DIR`), which keeps
the console on `console.log` in `build/machines/NAME`, tells a
reboot from a halt by the kernel's last line there, runs Firecracker
again after a reboot, and leaves its pid in a pidfile, which is the
state. Only the network needs root, through `sudo` or `doas`:
Firecracker has no user-mode network and no DHCP, so each machine gets
a tap device of the user's and a /30 of `172.16.0.0/16`, both from the
name's sha256, with this host at `.1` and the machine at `.2`, NAT out
and forwarding by three `iptables` rules, each added only if absent and
removed by `delete`. The address goes on the kernel command line, as
init takes it, with this host's resolver, the first not on loopback
(systemd-resolved's own file, then `/etc/resolv.conf`), or `--dns`;
`--ip` and `--gw` are refused. `create` waits for the `up in` line and
prints the machine's `.2`. A second `create` of the name kills its
Firecracker, a hard stop, and starts it with the new tar, keeping its
data disk and its configuration, so `--dns` counts at the first
`create` alone.

On Proxmox VE, built, experimental, and never yet run against a node
(`cmd/howl/proxmox.zig`). Proxmox's own command, `qm`, runs on the
node, so `create` runs it there over ssh, with an explicit argument
list, as it runs `limactl` and `gcloud` here: `PROXMOX_HOST=root@NODE`
names the node, `PROXMOX_STORAGE` (`local-lvm`) its disks' storage and
`PROXMOX_BRIDGE` (`vmbr0`) its network. The REST API with a token is
how Terraform and Ansible drive Proxmox, and would spare the root login;
it was not chosen because it keeps no serial log and learns no address
without the guest agent werewolf does not ship, so `create` could say
neither that the machine is up nor where it is. The node keeps
werewolf's files in `/var/lib/vz/werewolf`: the release's `disk.qcow2`,
named `werewolf-FORM-ARCH-DIGEST.qcow2` and copied with `scp` only if
not there; each machine's config tar; and each machine's console. `qm
create` makes a q35 VM with OVMF and no vendor keys, two host CPUs and
2 GiB, the image and the tar imported onto the storage (`import-from`),
the tar raw and read-only, virtio network on the bridge, a virtio random
number device, and the console on the file through QEMU's own `-chardev
file`, passed in `args`, which Proxmox allows root alone, since Proxmox
keeps a serial port on a socket and no log; the form is in the
description and the tag `werewolf` marks it ours, and `qm list` is the
state. `create` waits for the `up in` line in the console file and
prints the DHCP lease the console reported, or `-` for a static one. A
second `create` of the name stops the VM hard (`qm shutdown` presses
the ACPI power button, which no werewolf machine answers on x86_64
yet), imports the new tar over the old disk and removes the old one;
`delete` destroys the VM and its disks and removes its files on the
node, keeping the image. x86_64 only, as Proxmox nodes are.

On GCP, built: `create` builds the release's `disk.qcow2` and makes it an
image named `werewolf-FORM-ARCH-DIGEST`, the first 16 hex digits of the
disk's sha256, uploading it only if no such image exists, and storing it
in the zone's region rather than GCP's multi-region default (making one
took 1 min 30 s so, against 1 min 58 s before). The VM gets
the config tar in base64 as `user-data`, no service account, no scopes
and no Secure Boot, a label naming its form, and the default network.
On GCP, AWS and Azure alike a new machine lets nothing in, and `create`
ends by printing, to paste as they are, the lines that open the TCP ports
its form's `net` listens on to this host's address alone (`$ME`, from
`checkip.amazonaws.com`): a firewall rule `NAME-allow` for the VM's tag,
rules in its own security group, or one in its NSG; `delete` removes
them with the machine. `--allow-from me|CIDR` has `create` run them
itself, for that source; it is off unless given, and refused for a
machine that exists, whose rules stay as its owner left them: what the
Internet may reach is its owner's to say, on the command line.
Its boot disk is `pd-balanced`, SSD, not GCP's HDD default: on a
t2a-standard-1, a reboot to ssh took 3.8 s on it against 5.3 s on an
8 GB `pd-standard` disk (about 10 MB/s), for $0.80 a month against $0.32.
`create` waits for init's `up in` line on the serial port. A second
`create` of the same name and form replaces the user-data and stops and
starts the VM, which GCP stops with its power button; the stop releases
an ephemeral address, so the VM's address changes unless it is static,
and GCP keeps the console of the current run alone. Project and zone are
gcloud's (`gcloud config`, or `CLOUDSDK_COMPUTE_ZONE`), the zone
`us-central1-a` if gcloud has none; where a zone has no Arm machines
free, GCP says so and another zone serves.

On AWS, built, and run on both arches: `create` builds the same
`disk.qcow2`, writes it into an EBS snapshot through EBS's direct API,
its 512 KiB blocks that hold data alone, eight at a time, each with its
sha256, and registers the AMI under the same digest name, for UEFI, the
ENA and IMDSv2 alone. It began with VM Import, from a VHD in S3, which
took 6 to 10 minutes and wanted a bucket and a `vmimport` service role
made once by hand; a hundred-odd blocks written directly take well under
a minute and want nothing made. The
instance gets the tar in base64 as user data, no instance profile, IMDSv2
with one hop, `Name` and `werewolf-form` tags, and a security group of
its own, `werewolf-NAME`, with no rule in; `delete` waits for the
instance to go, then deletes the group. AWS begins a console afresh at
each start but may answer with the last run's for a while, so `create`
takes a console as this run's only if AWS last wrote it no earlier than
the instance's `LaunchTime`: by its text it cannot tell, since a werewolf
boot prints the same lines every time. A second `create` stops the
instance, replaces its user data (in base64 once more, which
`modify-instance-attribute` wants and `run-instances` does itself) and
starts it.

On Azure, built, experimental, and run on both arches (2026-10-08): prod
on `Standard_D2as_v4` in eastus and on `Standard_B2pls_v2` in westus2,
each up in 2 to 3 s with posture clean, its root found through
`hv_storvsc`, a second `create` with a new config, and `delete`
(`cmd/howl/azure.zig`). A subscription may offer Arm sizes only in
some regions: `az vm list-skus -l LOCATION` says which. The subscription is `az`'s own and the
resource group its default (`az configure --defaults group=RG`), which
`create` names when it is missing and does not make. The release's
`disk.qcow2` becomes a fixed VHD and goes straight into a managed disk
made for upload, named `werewolf-FORM-ARCH-DIGEST` and made only if
absent (or remade, if a failed `create` left it mid-upload), so no
storage account is needed. The upload is `azcopy`'s: a disk's upload URL
takes page writes alone, which `az storage blob upload` does not begin
with, and `azcopy` writes only the pages that hold data. Azure
provisions a VM from an image only through an agent in it, which
werewolf does not carry, so each machine gets its own copy of that disk,
`werewolf-NAME`, attached as its OS disk: a specialized VM, which Azure
boots as it is. It is Gen2, with Standard security, since werewolf's
boot loader is signed by no one Azure trusts; `Standard_D2as_v4`, or
`Standard_B2pls_v2` on arm64, or `--size`. Not the B-series on x86_64:
a new subscription is often refused them, as this one was in eastus.
The tar is its `userData`. `az vm create` reads that file as text and
encodes it in base64 itself, so a carriage return or a byte past ASCII
would change on the way; `create` refuses such a file, naming it,
rather than send it changed. Keys, settings and JSON are text. `az vm
create` makes it a network of its own with a security group that lets
nothing in and a public address, and its OS disk and NIC go when it
goes. Boot diagnostics hold the serial console; `az vm create` can turn
them on only with a storage account, and Azure keeps only what the
console says after they are on, so `create` turns them on from beside
`az vm create`, retrying each second until Azure knows the VM. That is
mostly early enough to keep its first boot whole (measured, a VM up in
84 s from the start of the create, against 2 to 3 minutes when every
new VM was restarted once to be watched); where the first minute shows
no `up in`, it restarts the VM once, as before, and waits. Then it
prints the public address. Azure keeps only
the console's last 64 KiB, across restarts, so a wait after a restart
looks past the old end it saw: from its last line a clock stamped to its
end, since a werewolf boot prints its other lines the same every time,
to the pids, and those recur after the next run's `up in`. A second `create` of the name
sets the VM's `userData` to the tar in base64 werewolf makes, from a
file (`az vm update --set @FILE`), since `--user-data` there encodes
its argument, the path, and restarts it. `delete` removes the VM, its
disk and NIC, the network `az` made for it, and any disk copy a failed
`create` left, which that `create` names; the image stays.

### upload

A disk file becomes a provider image, named by its content digest, so
uploading twice is a no-op and two people building the same form get the
same image name. It exists on its own because CI publishes images nobody
builds locally, one image serves many machines, and people who deploy
with Terraform want werewolf only as far as an image id. `create` calls
it.

### Targets

| Target | Image | Config | Notes |
| --- | --- | --- | --- |
| qemu | the file | second virtio drive | `run` only |
| firecracker | kernel, slot initramfs and root disk, no bootloader | second virtio drive | Linux with KVM; no ACPI, so no `power-button`; address on the command line; experimental |
| lima | the file | `limactl disk import` | `test/lima-demo` today |
| gcp | image from tar.gz | metadata `user-data` | `test/gcp` today |
| aws | AMI from an EBS snapshot written directly | user data, 16 KB | needs EBS direct API permissions; nothing to set up first |
| azure | fixed VHD uploaded to a managed disk, copied per VM | userData, 64 KB | no reusable image without a ready agent; specialized VMs; experimental |
| proxmox | the file, by scp and `import-from` | second virtio drive, imported raw | `qm` over ssh to the node; experimental, untested |
| VMware, Hyper-V, a stick | the file | the tar | manual |

Each automated target is one Zig file with five functions: upload,
create, address, console, delete. If a target cannot be done that thinly
it stays manual. Manual is not the lesser path: it is the same two files,
and `make check` boots them under QEMU with the tar as a second drive,
which tests the core of every other target.

### End to end

A bastion, forwarding to one host. Its users, their keys and their
destinations are its image's, from the form built on it
([bastion](../../forms/bastion/README.md)); it makes its host key on its
first boot, on /data (`ssh-host-key`), and says the fingerprint on its
console:

```sh
howl create edge --with edge --on gcp   # forms/edge/form.yaml: base: bastion, bastion: users: ...
```
```
edge  34.1.2.3  bastion  SHA256:k2w...  (verify before connecting)
ssh -J bastion@34.1.2.3 you@10.20.0.10
```

A Tailscale subnet router. The auth key cannot be generated: it comes
from the admin console, tagged and preauthorized, and is read from a
file or standard input, never the line. Node identity lives in `/data`,
so another `create` with new routes does not re-enroll:

```sh
op read op://infra/tailscale/auth-key |
    howl create router --with tailscale --on gcp --auth-key - --routes 10.20.0.0/24
```
```
router  34.1.2.4  tailscale
approve 10.20.0.0/24 for router at https://login.tailscale.com/admin/machines
```

The same two, for a hypervisor this tool does not know:

```sh
howl build --with edge -o edge.qcow2          # the bastion: no config tar, its users are its image's
howl build --with tailscale -o router.qcow2
howl pack --with tailscale -o router.tar --auth-key - --routes 10.20.0.0/24
qm importdisk 100 edge.qcow2 local-lvm
qm importdisk 101 router.qcow2 local-lvm
qm importdisk 101 router.tar local-lvm --format raw
```

### Checked against three services

**OpenBao.** Two files (`tls-cert`, `tls-key`), two settings
(`api-addr url`, `cluster-addr url`), raft under `/data/svc/openbao`,
8200 and 8201 in its `net`. All inputs fit, for a single node; a
cluster's `retry_join` is a list of objects, which no format in
[settings.md](settings.md) renders. Auto-unseal with a cloud KMS needs the
service to reach the metadata server, which fence allows no one, and the
`net`, being by port, cannot name. Auto-unseal is not optional
here: with Shamir, bao comes up sealed after every reboot, and werewolf
reboots itself on every update. Its first boot also *produces* secrets,
the unseal keys and root token. The tool never fetches them; `create`
ends with `bao operator init -address=https://ADDR:8200`.

**A PHP or Java application.** Code is `--app DIR` at build. The user's
own service file declares the flags, `setting database-url url` and
`config db-password`, so the list grows with the app, not the tool.
Applications read the environment, Java's frameworks included, so
settings render as `env` ([settings.md](settings.md)), which leash loads
before `exec`; secrets stay files in `/run/svc/app/`, with the
`_FILE` convention most frameworks accept. Twenty secrets is what
`--config DIR` is for, and a Java keystore can exceed a cloud metadata
entry, which `pack --on` reports. The database's port is in the form and
its host in the settings. An application that installs its own code at
runtime is not a werewolf application.

**A new image for an existing name** recreates the machine; only changed
flags replace the tar and reboot. Whether an application update should
instead ride the A/B updater is the updater's question.

### Order

1. `pack`, with `destination()` and `route()` moved from `service-config`
   to `lib/`, and the `setting` line in service files. Deletes the tar
   blocks from `service-vms.md`.
2. `build`, with the manifest and `--format`. A paragraph each for the
   manual targets.
3. `run`, replacing `make run`'s QEMU recipe.
4. `create`, `delete`, `console`, `upload` for lima and gcp, deleting
   `test/lima-demo` and `test/gcp`. `make demo`, `make webshell-gcp` and
   the checks call `howl`, so CI runs what users type.
5. firecracker, aws, azure.

Each step removes a block of shell or prose; that is the measure.

## Drawbacks

- **Two interfaces.** Contributors use `make`, users use `howl`, and
  `howl build` calls `make`. The rule that one never does the other's
  job has to be kept by hand.
- **Flags read from service files are indirect.** `howl create
  bastion --help` must build its flag list from the form chain, and a
  typo in a service file surfaces as a missing flag. The service file is
  already the schema the guest enforces, so this is one schema rather
  than two, but it is a less obvious place to look.
- **Four provider CLIs to track.** `gcloud`, `aws`, `az` and `limactl`
  change their output and flags; each target is a few argv arrays and a
  parser for one list command, and each breaks on its own schedule.
- **Azure stays awkward.** Without a ready agent there is no reusable
  image, so `create` copies a disk per machine. The alternative is an
  agent in the image, which is a daemon talking to the wire server as
  root, and this project will not carry one.
- **Another binary in the tree**, built for the host rather than the
  guest, with its own tests.
- **The guest's `service-config` has per-form code.** It has a `bastion`
  case and a `tailscale` case: the thing this design removes from the
  host. With many forms it has to become a few declared *formats* (an
  sshd `PermitOpen` line, a JSON merge), perhaps five in all. That is
  the guest's half of this design, and is not designed here.

## Alternatives Considered

### Keep Make and improve the docs

Cheapest, and where the project is. Make cannot validate a variable,
cannot read a service file, and cannot produce a deterministic tar
without the shell it is wrapping. The secrets path would remain prose.

### One verb, `boot --on TARGET`, for `run` and `create`

Fewer verbs. It hides that one returns when the machine exits and the
other when it is up and named; the user learns the difference from
behaviour instead of from the name.

### `up`/`down`, `deploy`/`destroy`

Compose and Vagrant vocabulary; symmetric and short, and vague about
what is created. `create`/`delete` is every cloud CLI's pair and says
what happens.

### `config` or `check` instead of `pack`

`config` reads as *configure*, which it does not do. `check` collides
with `make check` and is served by `pack -n`. `pack` names what happens
to the directory.

### Named flags in the tool, per form

`--destinations` as code in the CLI, with a `bastion` case and a
`tailscale` case, as `service-config` has today. Every new form means a
change to the tool, and the host's idea of a form drifts from the
guest's. Reading the service file makes the form the one source.

### A generic `--file NAME=PATH` and `--set KEY=VALUE`

One mechanism, no per-form knowledge, and Pike would like that it is one
mechanism. It is also `--file bastion/authorized_keys=~/.ssh/id.pub` on
every invocation, with the user spelling a guest path. Declared flags
give the same generality, since the declaration is in the form, with
`--authorized-keys FILE` on the line.

### A directory only, no flags

Where the first draft of this document was. Right for a fleet, where the
directory is checked in beside the form; wrong for the first machine,
where the user is told to create three files with the right modes
before anything runs. Both remain; a file from both is an error.

### The declarations copied into the manifest

A `services` field in `FORM-ARCH.json`, each service's `config`,
`setting` and `render` lines, for `pack --image` to read. It would not
change a release's `build`, which hashes the files, and the updater
ignores fields it does not know. But it is a copy of what `root.erofs`
already holds, which the manifest already names by sha256: two sources of
truth, the second one not the one leash reads, and a shape the release
format would then promise. Reading the image itself has neither cost.

### melange for applications

Packages the application as an apk, signed and locked. It is three new
things to learn, needs a Linux kernel for its sandbox, so a VM on macOS,
and solves a problem this project does not have: a catalogue consumed by
strangers. A digested directory gives the same reproducibility claim.
Revisit if the updater should ever update an application apart from its
base image; the apk is the natural unit for that.

### A provider SDK, or Terraform underneath

An SDK per cloud is a dependency per cloud, in Go or Python, for a tool
whose whole job is a few API calls. Terraform is a daemon's worth of
state. The provider CLIs are already installed, authenticated and
documented, and an argv array is auditable in a way a client library is
not.

### Generating the host key always, keeping it in `~/.werewolf`

Convenient, and hidden state: the thing the Non-Goals forbid. The
config directory is the key's home; without one, the user is told how to
make a key and where to put it.

## Security Considerations

The tool handles secrets on the host; the guest's protections
([lockdown.md](lockdown.md), [fence.md](fence.md)) begin after boot.

- **Secrets never cross argv or the environment.** Files or standard
  input. `ps`, shell history and crash reports see paths.
- **The host validates with the guest's code.** `destination()` and
  `route()` live in `lib/` and are linked into `pack` and
  `service-config` alike. What the host accepts the leash accepts; what
  the leash would refuse never leaves the host.
- **The tar rejects what init rejects, earlier.** Symlinks, hard links,
  devices, AppleDouble files, paths with `..`, more than 32 entries or
  32 KiB each. init still enforces all of it: the host check is for the
  user, not the guest.
- **`create` sees a tar, not its contents.** The provider half uploads
  bytes `pack` produced and reads nothing in them. A bug in the `gcloud`
  argv cannot leak a key it never parsed.
- **No `sh -c`, anywhere.** Every provider invocation is an argument
  list. A hostname or route that reaches `gcloud` cannot become a shell
  word, and what `howl` runs can be printed with `-v` exactly as
  run.
- **Settings cannot widen policy.** `settings.json` carries routes and
  destinations only; the kernel's egress ports, the service's
  capabilities and the image's seal are in the form, which the user
  built and signed. `service-config` refuses default routes, host bits
  and anything but a literal address and port.
- **The config tar is root on the machine.** It always was: whoever can
  set user data holds root's keys ([cloud.md](../cloud.md)). The tool
  changes nothing there, but the one-line deploy makes it easier to
  forget, so `create` prints the account that set the metadata.
- **Theo's objection** would be that a host-side validator duplicates a
  guest-side one and the two drift. That is why they are one function in
  `lib/`, and why the guest's check remains the one that counts.

## Reliability Considerations

- **The deploy path is the tested path.** `make check` runs `werewolf
  run` and `howl create --on lima`; `check-gcp` runs `create --on
  gcp`. There is no path users take that CI does not.
- **No state to lose.** `delete` and `console` ask the provider which
  machines exist. A laptop that dies mid-`create` leaves a machine the
  provider lists and `delete` removes; nothing on the laptop records it.
- **Idempotent uploads.** Images are named by content digest, so a
  retried `upload` or `create` after a dropped connection finds the
  image already there.
- **Errors say the next step.** Azure's missing resource group is
  named, with the command that makes it; the tool does not create it,
  nor any IAM role, because a tool that creates those on a retry is the
  kind an SRE would rather not have. AWS needs neither: its images are
  written as snapshots directly.
- **A dead machine is diagnosable.** `console` works whether or not the
  machine came up, and is the first thing an error from `create` tells
  the user to run.
- **Provider CLI drift is the main failure.** Each target parses one
  list command, and `check-gcp` runs weekly against the real thing, so a
  changed field fails in CI before it fails for a user.
- **Partial failure in `create`** leaves what was made (an uploaded
  image, a disk) and says so; it does not roll back, because a rollback
  that deletes the wrong thing is worse than a leftover with a name.
