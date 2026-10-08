# Testing

```sh
make test           # the updater's unit tests
make check          # boot every form, and a slot, and check each one
make -j check       # the same, side by side
make ci             # the CI job, in an Ubuntu VM under Lima
make check-updater  # a whole update, over the network
make check-updater-release  # the same, to CI's latest signed release
make check-gcp      # prod-ssh's disk on a Google Compute Engine VM
make check-aws      # the same on an EC2 instance
make check-azure    # the same on an Azure VM
```

`make check` needs, beyond the build's tools, QEMU, `expect` and `mke2fs`
(e2fsprogs). On a Mac: `brew install qemu e2fsprogs`; `expect` ships with
macOS.

The tutorial forms also need Go, rustup and the .NET 10 SDK on the build host. Install Rust's
Linux musl target for the architecture being tested, for example
`rustup toolchain install stable --profile minimal --target aarch64-unknown-linux-musl`.
Use `x86_64-unknown-linux-musl` for `ARCH=x86_64`. CI and `make ci` install
these compilers before checking the forms. None ships in a VM.

## What `make check` does

It builds every form and boots each under QEMU, then boots a slot the way
bite leaves one. On each machine it runs [test/checks](../test/checks) as
root on the serial console, then powers it off. A machine passes when it
boots, every check comes out as expected, and it shuts down cleanly.

On aarch64 each machine is given EL2 wherever the host can lend it (TCG
always, HVF on Apple M3 and later, KVM where the host nests), as a cloud
that offers nested virtualization would: the kernel's built-in KVM would
start there, so posture's `kernel-no-hypervisor` proves that
`kvm-arm.mode=none` stops it, and `qemu-host` that its allowance does not.

Those checks need a shell, which most forms do not have, so each form is
built for them with `DEV=1`: busybox-full on top of its packages, in
`build/<arch>/<form>-dev`, and nothing else changed. Every form is also
built as it ships and booted once more (`check-shellfree-<form>`), where
test/boot runs nothing on the machine and judges it by its posture line,
no failure but the weaknesses its form.yaml excuses, and by what
`forms/<form>/test/console` says its console must and must not show.

The checks try what an attacker would and expect to be refused: lower
lockdown, read `/dev/mem` or another process's memory, undo a one-way
sysctl, find a setuid file, listen on a port the form has not declared in
its network policy (ssh's 22 is declared by sshd being installed), run a
program from `/tmp`. And a socket must listen on every port it has
declared, and answer HTTP where the port speaks it, so a runtime form's
application runs, leashed, and serves; a daemon that speaks another
protocol (Valkey, OpenBao, step-ca, Caddy's HTTPS) is asked in its own,
by its form's `forms/FORM/test/checks`, which `make check` appends. A socket
bound to loopback alone (OpenBao's cluster port) is the machine's own,
not a listener the network can reach, to this check and to posture
alike. What a form's services need from the config, `forms/FORM/test/config`
writes into the check's config tar: OpenBao's unseal key
and certificate, a CA for step-ca, WordPress's admin.
Where the attacker would be an ordinary user, the check acts as one, with
runit's `chpst -u nobody`: write to `/run`, see another user's processes,
plant a symlink or hardlink in `/tmp` for root to follow. Where a refusal
and an ordinary error look alike, a check also asks for the kernel's own
line saying it refused. A check confirms the address and default route the command line gave. One check runs first, before any attack: that
nothing was refused during boot, which catches a protection breaking a
service.

Every form then boots a second time, on the disks its first boot left
([test/checks-again](../test/checks-again)). `/data` may hold real data, so
a disk init formatted once must come back as it was: opened, checked,
mounted, still holding the mark the first boot wrote, and with no line on
the console saying it formatted anything. And `prod` boots once more on
the LUKS2 disk its own boots left, with no key
([test/checks-nodata](../test/checks-nodata)): it must refuse the disk,
leaving `/data` an empty read-only tmpfs, the reason in
`/run/werewolf/nodata`, and the disk as it was, rather than format it again. And two boots offer an
unsigned module, `minimal`'s init on a RAM root and stage0 on a slot
([test/checks-unsigned](../test/checks-unsigned)): [test/unsign](../test/unsign)
cuts the signature off `evdev` and appends it to the initramfs, where it
replaces the signed one. The kernel must refuse it, say so, stay
untainted, and still load every signed module. And `minimal` boots once
with one byte of its root image's superblock changed (`make check-verity`):
dm-verity must name the block, and stage0 must stop before the root is
mounted. Every other boot checks that its root is mounted through dm-verity
(`root-verified` in [test/checks](../test/checks)). And a slot that boots
but never commits must be taken back (`make check-deadman`): a DEV build of
`minimal`, whose root alone lets `werewolf.deadman` shorten stage0's ten
minutes to twenty seconds, boots with no loader to commit to; the deadman
must say why on the console and reset the machine.

Seven boots put `prod` behind a stand-in metadata server
([test/metadata](../test/metadata), driven by
[test/cloud-boot](../test/cloud-boot)), with the firmware's strings set as
each cloud's: on GCP, AWS, Hetzner Cloud and Azure a good config must be
taken (the hostname and root's key applied, the tar rewritten root's and
0600), and on AWS only through a session token; a tar with a symlink and a
`../` entry must be refused whole; and a machine on no cloud, or on a
desktop's Hyper-V, which names itself as Azure does but for Azure's asset
tag, must not ask the metadata server at all, which the server's own log
shows. arm64 guests get SMBIOS only under UEFI firmware, which the boots
load.

`make check-dist`, after `make dist`, boots each release disk in `dist/`
as published: UEFI firmware, systemd-boot, slot a, with `-snapshot` so the
file is not changed and a network with no way out, so the updater cannot
install the latest release over it. Its posture line must show exactly
what the form fails as it ships (its form.yaml's `weaknesses`).
The release workflow runs it on every release.

Every boot so far gives its address on the kernel command line. One more
boots `prod` without one ([test/checks-lease](../test/checks-lease)),
so init asks QEMU's DHCP server: the address, gateway and DNS server must
be applied, the console must show the client's `bound` event, and the
client must be split as it says it is, an engine running as `_dhcp`,
chrooted, with no capabilities, under seccomp, and a parent keeping
`CAP_NET_ADMIN` alone. Another, `check-static`, boots `minimal`, which has no DHCP client,
without one too, and with a config tar from `howl pack --ip --gw --dns`
([test/checks-static](../test/checks-static)): init must take the address,
route and DNS server from the tar's `network` file, and say so.

The slot boot covers what direct boot cannot: stage0 finding `root.erofs`
by filesystem UUID, `/victim` read-only, the `slot-keep`
service making the slot GRUB's default once it has stayed healthy for a
minute, and then `bite-cleanup` deleting a stand-in distro around it,
traps included, while keeping werewolf's directory and `/boot`. Among the
traps, `debugfs` makes `/etc/resolv.conf` immutable: bite-cleanup must
delete the rest of `/etc`, name the file, and exit 1. The victim is a 128 MiB ext4 that `mke2fs -d` fills with what bite
leaves: the root image in slot a, its kernel, and GRUB's environment block. The slot
uses `minimal`, which has no updater to reach the network once
committed.

```
ok     sshd               posture
ok     sshd               services-up
ok     sshd               root-unlinked
pass   sshd               all checks
pass   sshd-again         all checks
```

Each machine gets a blank disk and a config disk of its own, holding only a
fixed test `data.key` so `prod` and the forms on it put `/data` in LUKS2, and forwards no
ports, so machines never share state and `make -j` runs them together.
A few forms boot a second time from the disk the first left, to show what
it kept (`AGAIN_FORMS`, Makefile): the code is every form's, so those stand
for all, chosen for what they keep; `AGAIN_FORMS=all` boots every form twice.
Nothing waits a
fixed time: [test/boot](../test/boot) waits for each thing it needs to see,
up to a limit, so a fast machine finishes fast and a slow one, emulated in
CI, still passes. On an M4, `make -j8 check` takes about 25 s for the forms
and a further minute for the slot to commit.

Logs are in `build/<arch>/check/`: `<form>-build.log` for each build, and
`<form>.log` for each console, kernel messages and all; a shell-free boot's
are `<form>-shellfree-build.log` and `<form>-shellfree.log`.

## What `make check-updater` does

A whole update, as a machine does one: `prod`, built with `DEV=1` so it
follows no releases and builds its own slot, boots from slot a of a disk, with its build record claiming the kernel
release before its own (`linux-virt-6.18.55-r0` claims `6.18.54-r0`). The
claim is one file laid over the slot's root as a later tar entry; nothing
in `build/` is changed. The machine commits, finds Alpine's kernel newer,
fetches Wolfi's and Alpine's packages and the CVE sources as `_update`,
builds slot b, installs it and reboots.

[test/update](../test/update) then reads the disk, with `debugfs`: the
report names both CVE sources with a sha256 and no error; each apk cache
kept its packages; slot b's root is root's, mode 0755; GRUB boots b next.
It boots slot b, which must commit and the updater record that the update
held; no seccomp filter may have killed anything in either boot. The
consoles are in `build/<arch>/check/update-autoupdate/`.

`make check-updater-release` does the same with `prod-ssh`, a form CI
publishes: its updater installs the latest signed release instead of
building (docs/updater.md, Releases), and there are no apk caches to
check. It tests the release as much as the updater: slot b is what CI
published, so it passes only once CI has published from a tree whose
slot boots and updates as this one does, and whose packages are no older
than this tree's: the updater takes nothing backwards.

It needs the network, so it is not part of `make check`. About 4 minutes
with KVM or HVF; under TCG, much longer. CI runs it nightly on x86_64.

## What `make check-gcp`, `check-aws` and `check-azure` do

[test/cloud](../test/cloud) runs `prod-ssh`'s disk, as a release makes
it, on a real cloud, as a user would: `howl create --on CLOUD` makes
it that cloud's image (a GCP image, an AMI from an EBS snapshot written
directly, an Azure managed disk) and boots a fresh machine of it, the
arch's smallest (`ARCH=aarch64` or `x86_64`), with a config in its user
data: a hostname, and an ssh key made for this run. It is judged from the
cloud's record of the machine's serial port:

| Check | Passes when |
| --- | --- |
| `root-verified` | stage0 opened slot a's root through dm-verity |
| `metadata-config` | `cloud-metadata` took the config from that cloud's metadata server |
| `hostname` | posture names the host as the config did |
| `posture` | what fails is exactly what `prod-ssh`'s weaknesses say it fails |
| `ssh-login` | root logs in, over the Internet, with the run's key, through the port `create --allow-from me` opened |
| `reconfigure` | a second `create` of the name, with a new hostname, restarts the machine on it |
| `delete` | `howl delete` leaves nothing of the machine: instance, disk, network, security group, firewall rule |

The machine is made with `--allow-from me`, so werewolf itself opens the
form's ports, to this host's address alone, as a user's `create` would. Everything the run made, the image included, is deleted
however it ends; `CLOUD_KEEP=1` keeps the machine, to look around. The
serial port is kept in `build/<arch>/prod-ssh/check/CLOUD-serial.log`.

Each needs that cloud's CLI logged in, and costs a few cents:

- **GCP:** gcloud with a project (`GCP_PROJECT`, or gcloud's own); the zone
  is `us-central1-a` (`GCP_ZONE`).
- **AWS:** the aws CLI's region and credentials (`aws login` or `aws
  configure`, or `AWS_REGION` and `AWS_PROFILE`); nothing to set up first.
- **Azure:** az's default resource group (`az configure --defaults
  group=RG`, or `AZURE_DEFAULTS_GROUP`), whose location must offer the
  arch's size: some subscriptions offer Arm sizes in few regions
  (`az vm list-skus -l LOCATION`).

A few minutes each, most of it the cloud making the image and the
machine. Not part of `make check`, nor of CI, which holds no cloud
credentials.

## Writing a check

A machine's settings, and the attacks on them, are
[posture](posture.md)'s to judge, so each is checked once, the way a
machine's owner checks it. Every machine's posture service prints one line
on the console once its services settle; with `werewolf.check=1`, which
only `make check` sets, posture also makes the attacks that write to the
kernel log, and proves each refusal by the kernel's own line.
[test/boot](../test/boot) waits for that line before anything else and
fails the machine unless the checks that fail are exactly the weaknesses
its form.yaml excuses, and those [test/posture-known](../test/posture-known)
gives every DEV=1 build or the architecture: a new failure fails, and so
does a known one that starts passing, until it leaves the list and the
docs say so. A new protection belongs in cmd/posture, in the file for its area.

A form that serves ssh is also logged into from the host, as an operator
would, through a forwarded port: root's key from the config gets in, a
session cannot forward a port past fence, and only keys are offered.

`test/checks` holds the rest, the boot's own behaviour: the network, the
services, `/data`, the slot's commit. A check is one line: a kind, a name
and one line of sh, run as root in a subshell, exiting 0 when the property
holds. A machine with no shell is judged by its posture line alone
(`test/boot NAME - LOG QEMU...`).

```
ok  data-usable      [ ! -e /run/werewolf/nodata ]
ok  root-unlinked    ! rm -f /init && [ -e /init ] && awk '$2 == "/" { o = $4 } END { exit o !~ /^ro(,|$)/ }' /proc/mounts
```

- **ok** must hold on every machine. A check that applies to some machines
  only decides for itself: `slot-commits` passes at once unless the machine
  booted from a slot.
- **gap** is a known weakness from [security.md](security.md), "Not yet",
  and must not hold. When work closes one, its check starts holding, and
  `make check` fails until the line becomes `ok` and the docs say so. So
  the docs cannot claim a protection the machines lack, or miss one they
  have.

Test the attack, not the setting: `ptrace_scope` reading 3 proves less than
`cat /proc/1/mem` being refused, which is why posture asks the kernel to
undo a setting and expects a refusal. And make a check fail before trusting it
to pass: point it at a machine without the protection, or invert it.

## Debugging a failure

A FAIL says what the machine last reported doing (its last progress line),
the first thing its kernel said was wrong (an RCU stall, a blocked task, a
lockup, a panic), and the host: its kernel, QEMU, accelerator, CPUs and
load. The same host line heads every console log. Check boots panic on a
CPU stalled 20 s or a task blocked two minutes, so a hang fails in
seconds, with the kernel's reason, rather than at a timeout. A machine that
stops answering has every virtual CPU's state (`info cpus`, `info registers
-a`) dumped into its log first: a CPU parked and never woken is the
hypervisor's, not the guest's.

```sh
make check-one FORM=lima REPEAT=20          # how often does it fail?
make check-one FORM=lima REPEAT=20 ACCEL=tcg   # without the hypervisor
BOOT_TIMEOUT=20 make check-minimal          # see a hang sooner
```

`check-one` keeps each failing boot's console as `FORM-one-N.log`.

## Where a boot's time goes

Every boot says it on the console, and every machine keeps it in
`/run/werewolf/boot` as `kernel_ms`, `userland_ms` and `phases`, each a
`name` and its `ms`:

```
werewolf: phases: kernel 0.225s, modules 0.386s, slot 0.227s, root 0.013s, mounts 0.012s, ...
werewolf: up in 1.470s (the kernel 0.225s, userland 1.245s), handing over to runit
```

| Phase | Until |
|---|---|
| `kernel` | stage0 starts |
| `modules` | stage0's modload closes the loader, after the scan for the slot's disk it runs alongside |
| `slot` | the slot's filesystem is mounted (a slot's boot only) |
| `root` | `root.erofs` is mounted through dm-verity |
| `mounts`, `sysctls`, `network`, `victim`, `config`, `data` | init's steps of those names end |
| `seal` | init has sealed itself and started the mount broker and the DHCP renewal |

A reboot's other half is on the console too: stage 3 ends with `werewolf:
down in Xs (services Ys, filesystems Zs)`, after `werewolf: SERVICE not
down in 30s; killed` for any it had to kill. On a machine with slots, the update's
`commit` or `rollback` event carries `down`: the seconds from its `reboot`
event to the new kernel's start, which are the stop, the firmware and the
loader. The console shows only the kernel's warnings and worse
(`loglevel=5`); `dmesg` keeps every line with its time, so a gap between two
of them is where to look next.

## CI

[.github/workflows/check.yml](../.github/workflows/check.yml) runs `make
test` on GitHub's x86_64 and arm64 Ubuntu runners, `make lint` on one, and
`make check` split into jobs that run in parallel, so a failure names the
area it is in: `forms`, `shellfree`, `integrity`, `cloud`, `persist` and, on
arm64, `native`; `forms`, `shellfree` and `native` are split again over
runners (`SHARD=K/N`), 19 jobs in all, under the 20 the account runs at
once. Each job boots four machines at a time on its four CPUs, and keeps
Zig's and apko's caches from one run to the next, a week at a time, so a
program or a package unchanged since is not built or fetched again.
[test/ci-setup](../test/ci-setup) installs the tools with
[tools/install-deps](../tools/install-deps), as `make install-deps` does
anywhere: Ubuntu's packages, and apko and Zig pinned by version and
sha256; `ci-setup apko zig` installs those two alone, for the release job
that only resolves packages. Each job keeps its logs when it fails.

The x86_64 runner has KVM, so it emulates fast and runs every group. The
arm64 runner has none: a full boot there emulates under TCG, slowly. So arm64
runs the `native` group instead of `forms` and `shellfree`:
[test/cage](../test/cage) boots each form's root under `systemd-nspawn` on
the runner's own kernel -- no virtual machine -- and judges its posture.
cage runs nothing on the machine, so each form is built as it ships,
without `DEV=1`, and arm64 checks the shipped images too. werewolf's runtime protections (the seal, Landlock, fence's policy routing,
the leash, hidepid, W^X) are the host kernel's own features and hold in a
container, so cage asserts them directly, and `WEREWOLF_CHECK=1` has the
in-container posture service attack them too, as `werewolf.check=1` does on a
booted machine. What a container cannot own -- the kernel's sysctls and boot
line, dm-verity, a few mount options -- `POSTURE_KNOWN_NATIVE` allows to
fail, as the form's own weaknesses allow what the form carries by
design. The host sysctls behind `files-links`, `files-links-attack` and
`files-memfd-exec` cage raises to werewolf's levels first where it may change
the host (`CAGE_HARDEN_HOST=1`, which CI sets on its throwaway runners), so
those attacks run for real; elsewhere a host below werewolf's levels makes
them expected to fail, and cage says so; arm64 still emulates `minimal` and `prod` (the `integrity` and `cloud`
groups) to assert those, and the attacks a container cannot carry. `persist`
is skipped on emulated arm64 (Makefile).

[.github/workflows/update.yml](../.github/workflows/update.yml) runs `make
check-updater` nightly, and on demand, on x86_64 alone: `prod`
updates itself over the network, and the slot it builds must boot and
commit. A workflow of its own, so a network flake fails it and nothing
else; no push, pull request or release waits on it.

`make ci` runs the same job here, in an Ubuntu VM, `werewolf-ci-24.04`,
with nested virtualization for KVM. The tree is copied in fresh each run,
without `config/` or `.git`; the VM, its tools and its build cache stay
between runs. `limactl delete -f werewolf-ci-24.04` starts over.
`LIMA_TEMPLATE=ubuntu-26.04 make ci` runs it on 26.04, as GitHub's runners
are, in a VM of its own; there, nested guests lose a CPU's timer early in
boot and stall, so 24.04 is the default. Its old erofs-utils is replaced
by [tools/install-deps](../tools/install-deps), which builds 1.9.4.
