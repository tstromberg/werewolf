# The werewolf command

**Note for reviewers**:
While reviewing this proposal, focus on answering for yourself:

* Does this proposal fit with our engineering principles?
* Are there unexplored concerns with this design, such as reliability or usability issues?
* Could the proposed implementation be made simpler?
* Are there other alternatives to consider?

Proposed, 2026-10-07. Built (cmd/werewolf, `make werewolf`): `build`,
`pack`, `run`; `create`, `delete` and `console` on Lima and GCP; and
`upload` to GCP. `build` makes a form as `make dist` makes a release,
through make's `_dist-form`; `--app DIR` works with `build`, `run` and
`create`. `pack` reads FORM's
declarations from `./forms`; `--image` is not built. `pack` makes no
host keys: the bastion makes its own on first boot and keeps it in
`/data`. Firecracker, AWS and Azure are not built.
`make check-gcp`, `make demo` and the GCP demos run through `werewolf
create`; `test/gcp` keeps only its judging, and `test/lima-demo` its wait
for the page.

## Summary

One static Zig binary, `werewolf`, with seven verbs: build an image, pack
a config, and put the two on a machine, locally or in a cloud. `make`
stays the build system and the contributor's interface; `werewolf` is the
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
service file names (`config host-key /run/config/bastion/host_key`) into
the service's private directory, and `service-config` renders the
service's `settings.json` (destinations, routes) into the daemon's format,
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
  bastion destination meant forking the form. A destination is per
  machine, not per fleet.

## Goals

- A bastion or Tailscale router from a clean checkout to a running
  machine in one command, on Lima or GCP. The tutorials shrink to that
  command and a paragraph.
- Every config error that can be found on the host is found on the host:
  a missing file, a bad route, a key in the wrong format, a tar over the
  target's limit. Each names the file.
- `make check` boots machines through `werewolf`, so no deploy path
  exists that CI does not run. `test/gcp`, `test/lima-demo` and the
  shell blocks in `service-vms.md` are deleted.
- A built image carries a manifest, and the same inputs give the same
  bytes, whether CI built it or a user did.
- Any hypervisor that can attach two disks runs werewolf with no code in
  this tool: Proxmox, VMware, Hyper-V, a USB stick.

## Non-Goals

- A daemon, a state file, a plugin system, or a config file for the tool.
- Building without `make`, or `make` deploying without `werewolf`.
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
| **Secrets** | host key, `authorized_keys`, `auth_key`, `data.key` | the config tar | on rotation |

The form says what; the config says for whom. A changed destination is
another `create`, not a new image.

### The verbs

```
werewolf build   FORM [-o DIR] [--arch ARCH] [--format qcow2|raw|vhd|vmdk] [--app DIR]
werewolf pack    FORM|--image IMAGE [-o FILE] [-n] [--on TARGET] CONFIG...
werewolf run     FORM [--dev] [CONFIG...]                QEMU, in the foreground
werewolf create  FORM|--image IMAGE NAME [--on TARGET] [CONFIG...]
werewolf delete  NAME [--on TARGET]
werewolf console NAME [--on TARGET]
werewolf upload  FILE --on gcp|aws|azure
```

Two rules, stated once:

- **`build` and `pack` never touch the network or a credential.** They
  are functions of their inputs: the same inputs give the same bytes.
- **`create`, `delete`, `console` and `upload` never compile anything.**
  They move files the first two made, and run the provider's own CLI
  with an explicit argument list: `limactl`, `gcloud`, `aws`, `az`. No
  `sh -c`, no SDK, no state file: the provider's list command is the
  state.

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
--config DIR               files, as today: DIR/hostname, DIR/bastion/host_key, ...
--hostname NAME            the hostname file
--ip CIDR --gw ADDR --dns ADDR   the network file: a static address
--data-key FILE            data.key: /data goes in LUKS2
--NAME FILE                a file a service declared: --host-key, --authorized-keys, --auth-key
--KEY VALUE[,VALUE...]     a setting a service declared: --destinations, --routes
```

The flags are not written into the tool. The form's service files
declare them, and the CLI reads the form's chain to learn which flags
this form takes and where each lands:

```
config   host-key         /run/config/bastion/host_key       → --host-key FILE
config   authorized-keys  /run/config/bastion/authorized_keys → --authorized-keys FILE
setting  destinations     addrport...                        → --destinations ADDR:PORT,...
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
console does.

The names are part of the form's interface, as the tar paths already
are. A chain that declares the same name twice (a form on `prod-ssh`
that adds a bastion: two `authorized-keys`) fails to build, and the form
author renames one. Qualifying flags only when they collide would rename
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
checkout; until then `pack FORM` reads the same files from `./forms`.

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
the form's `config` lines, so a bastion with no `authorized_keys` fails
naming the file. `-n` checks and writes nothing, Venema's `postfix check`.
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
`werewolf console` to show and an operator to pin. Without `/data` it
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

The form under QEMU on this machine, console on the terminal, Ctrl-a x
ends it. It has no name and no `delete`, because nothing outlives the
process. werewolf packs the config tar from the flags, checked as `pack`
checks it, into `build/werewolf-run.tar`, then becomes `make run` with
that tar attached, so QEMU's arguments stay in one place. The config is
the flags' alone, not `./config`. `--dev` builds with the debug shell.
The data disk, `build/ARCH/data.img`, outlives runs, as `make run`'s
does: one that a `data.key` once put in LUKS2 stays unavailable, never
reformatted, until a run gives the same key with `--data-key`.

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
Lima, where it is installed on macOS, else QEMU here, in the foreground,
as `run` boots it, and not kept (Firecracker, on Linux with KVM, is where
that fallback goes next). `delete` and `console` take the same default.

On Lima, built: the machine's disk is built for it, since its command
line names the MAC of its vzNAT network (`werewolf.mac`), which is the
name's sha256, so nothing records it. The tar goes in as a Lima disk,
`NAME-config`, attached unformatted, where init finds it: binary files
survive, as they would not in YAML, and Lima's instance file holds no
copy of a secret. `limactl start` waits for ssh, which never answers, so
`create` waits for the MAC's DHCP lease, newer than any a deleted
machine of the same name left, and prints `NAME ADDRESS FORM` on
standard output and nothing else there. What it built is in
`build/ARCH/machines/NAME`, which `delete` removes with the instance and
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

On GCP, built: `create` builds the release's `disk.qcow2` and makes it an
image named `werewolf-FORM-ARCH-DIGEST`, the first 16 hex digits of the
disk's sha256, uploading it only if no such image exists. The VM gets
the config tar in base64 as `user-data`, no service account, no scopes
and no Secure Boot, a label naming its form, and the default network.
`create` waits for init's `up in` line on the serial port. A second
`create` of the same name and form replaces the user-data and stops and
starts the VM, which GCP stops with its power button; the stop releases
an ephemeral address, so the VM's address changes unless it is static,
and GCP keeps the console of the current run alone. Project and zone are
gcloud's (`gcloud config`, or `CLOUDSDK_COMPUTE_ZONE`), the zone
`us-central1-a` if gcloud has none; where a zone has no Arm machines
free, GCP says so and another zone serves.

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
| firecracker | slot files, no bootloader | second virtio-blk drive | Linux only; no ACPI, so no `power-button`; address on the command line |
| lima | the file | `limactl disk import` | `test/lima-demo` today |
| gcp | image from tar.gz | metadata `user-data` | `test/gcp` today |
| aws | AMI via S3 and `vmimport` | user data, 16 KB | `create` names the missing bucket or role rather than making it |
| azure | fixed VHD, specialized disk | userData, 64 KB | no reusable image without a ready agent; `upload` keeps the source disk, `create` copies it |
| proxmox, VMware, Hyper-V, a stick | the file | the tar | manual |

Each automated target is one Zig file with five functions: upload,
create, address, console, delete. If a target cannot be done that thinly
it stays manual. Manual is not the lesser path: it is the same two files,
and `make check` boots them under QEMU with the tar as a second drive,
which tests the core of every other target.

### End to end

A bastion, forwarding to one host, with the config directory keeping the
host key for next time:

```sh
werewolf create bastion edge --on gcp --config edge \
    --authorized-keys ~/.ssh/id_ed25519.pub --destinations 10.20.0.10:22
```
```
edge/bastion/host_key: generated, SHA256:k2w...
edge  34.1.2.3  bastion  SHA256:k2w...  (verify before connecting)
ssh -J bastion@34.1.2.3 you@10.20.0.10
```

A Tailscale subnet router. The auth key cannot be generated: it comes
from the admin console, tagged and preauthorized, and is read from a
file or standard input, never the line. Node identity lives in `/data`,
so another `create` with new routes does not re-enroll:

```sh
op read op://infra/tailscale/auth-key |
    werewolf create tailscale router --on gcp --auth-key - --routes 10.20.0.0/24
```
```
router  34.1.2.4  tailscale
approve 10.20.0.0/24 for router at https://login.tailscale.com/admin/machines
```

The same two, for a hypervisor this tool does not know:

```sh
werewolf build bastion -o edge.qcow2
werewolf pack bastion -o edge.tar --config edge --authorized-keys ~/.ssh/id_ed25519.pub \
    --destinations 10.20.0.10:22
qm importdisk 100 edge.qcow2 local-lvm
qm importdisk 100 edge.tar local-lvm --format raw
```

### Checked against three services

**OpenBao.** Two files (`tls-cert`, `tls-key`), two settings
(`api-addr url`, `cluster-addr url`), raft under `/data/svc/openbao`,
8200 and 8201 in the `.net`. All inputs fit, for a single node; a
cluster's `retry_join` is a list of objects, which no format in
[settings.md](settings.md) renders. Auto-unseal with a cloud KMS needs the
service to reach the metadata server, which fence allows no one, and the
`.net`, being by port, cannot name. Auto-unseal is not optional
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
   the checks call `werewolf`, so CI runs what users type.
5. firecracker, aws, azure.

Each step removes a block of shell or prose; that is the measure.

## Drawbacks

- **Two interfaces.** Contributors use `make`, users use `werewolf`, and
  `werewolf build` calls `make`. The rule that one never does the other's
  job has to be kept by hand.
- **Flags read from service files are indirect.** `werewolf create
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
  word, and what `werewolf` runs can be printed with `-v` exactly as
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
  run` and `werewolf create --on lima`; `check-gcp` runs `create --on
  gcp`. There is no path users take that CI does not.
- **No state to lose.** `delete` and `console` ask the provider which
  machines exist. A laptop that dies mid-`create` leaves a machine the
  provider lists and `delete` removes; nothing on the laptop records it.
- **Idempotent uploads.** Images are named by content digest, so a
  retried `upload` or `create` after a dropped connection finds the
  image already there.
- **Errors say the next step.** AWS's missing `vmimport` role is named,
  with the policy it needs; Azure's missing resource group likewise. The
  tool does not create either, because a tool that creates IAM roles on
  a retry is the kind an SRE would rather not have.
- **A dead machine is diagnosable.** `console` works whether or not the
  machine came up, and is the first thing an error from `create` tells
  the user to run.
- **Provider CLI drift is the main failure.** Each target parses one
  list command, and `check-gcp` runs weekly against the real thing, so a
  changed field fails in CI before it fails for a user.
- **Partial failure in `create`** leaves what was made (an uploaded
  image, a disk) and says so; it does not roll back, because a rollback
  that deletes the wrong thing is worse than a leftover with a name.
