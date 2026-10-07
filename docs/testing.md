# Testing

```sh
make test           # the updater's unit tests
make check          # boot every form, and a slot, and check each one
make -j check       # the same, side by side
make ci             # the CI job, in an Ubuntu VM under Lima
make check-updater  # a whole update, over the network
make check-updater-release  # the same, to CI's latest signed release
make check-gcp      # prod-ssh's disk on a Google Compute Engine VM
```

`make check` needs, beyond the build's tools, QEMU, `expect` and `mke2fs`
(e2fsprogs). On a Mac: `brew install qemu e2fsprogs`; `expect` ships with
macOS.

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
`build/<arch>/<form>-dev`, and nothing else changed. The forms released
without a shell, `minimal`, `prod` and `demo`, are also built as they ship
and booted once more (`check-shellfree-<form>`), where test/boot runs
nothing on the machine and judges it by its posture line alone: no shell,
and no failure at all.

The checks try what an attacker would and expect to be refused: lower
lockdown, read `/dev/mem` or another process's memory, undo a one-way
sysctl, find a setuid file, listen on a port the form has not declared in
`/etc/werewolf/listen` (ssh's 22 is declared by sshd being installed), run
a program from `/tmp`.
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
(`root-verified` in [test/checks](../test/checks)).

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
what the form fails as it ships ([test/posture-known](../test/posture-known)).
The release workflow runs it on every release.

Every boot so far gives its address on the kernel command line. One more
boots `prod` without one ([test/checks-lease](../test/checks-lease)),
so init asks QEMU's DHCP server: the address, gateway and DNS server must
be applied, the console must show the client's `bound` event, and the
client must be split as it says it is, an engine running as `_dhcp`,
chrooted, with no capabilities, under seccomp, and a parent keeping
`CAP_NET_ADMIN` alone.

The slot boot covers what direct boot cannot: stage0 finding `root.erofs`
by filesystem UUID, `/victim` read-only, the `slot-keep`
service making the slot GRUB's default once it has stayed healthy for a
minute, and then `bite-cleanup` deleting a stand-in distro around it,
traps included, while keeping werewolf's directory and `/boot`. The victim is a 128 MiB ext4 that `mke2fs -d` fills with what bite
leaves: the root image in slot a and GRUB's environment block. The slot
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
slot boots and updates as this one does.

It needs the network, so it is not part of `make check`. About 4 minutes
with KVM or HVF; under TCG, much longer. CI runs it nightly on x86_64.

## What `make check-gcp` does

[test/gcp](../test/gcp) runs `prod-ssh`'s disk, as a release makes it, on
Google Compute Engine, as a user would: converted to the raw disk GCP
imports, made an image (UEFI, gVNIC), and booted on a fresh VM (an
`e2-small`, or a `t2a-standard-1` for `ARCH=aarch64`) with a config in its
user-data: a hostname, and an ssh key made for this run. It is judged from
GCP's record of the VM's serial port:

| Check | Passes when |
| --- | --- |
| `root-verified` | stage0 opened slot a's root through dm-verity |
| `metadata-config` | `cloud-metadata` took the config from GCP's metadata server |
| `hostname` | posture names the host as the config did |
| `posture` | what fails is exactly what `test/posture-known` says `prod-ssh` fails |
| `ssh-login` | root logs in, over the Internet, with the run's key |

For the login, a firewall rule opens port 22 to this VM alone, while the
check runs. The VM, the rule, the image and the upload are deleted however
the check ends; `GCP_KEEP=1` keeps the VM and the rule, to look around.
The serial port is kept in `build/<arch>/prod-ssh/check/gcp-serial.log`.

It needs gcloud, logged in, with a project (`GCP_PROJECT`, or gcloud's
own), and costs a few cents. The zone is `us-central1-a` (`GCP_ZONE`), and
the image goes up through a bucket it makes, `PROJECT-werewolf-images`
(`GCP_BUCKET`). About 5 minutes, most of it GCP making the image. Not part
of `make check`, nor of CI, which holds no GCP credentials.

## Writing a check

A machine's settings, and the attacks on them, are
[posture](posture.md)'s to judge, so each is checked once, the way a
machine's owner checks it. Every machine's posture service prints one line
on the console once its services settle; with `werewolf.check=1`, which
only `make check` sets, posture also makes the attacks that write to the
kernel log, and proves each refusal by the kernel's own line.
[test/boot](../test/boot) waits for that line before anything else and
fails the machine unless the checks that fail are exactly those
[test/posture-known](../test/posture-known) gives the form and the
architecture: a new failure fails, and so
does a known one that starts passing, until it leaves the list and the
docs say so. A new protection belongs in cmd/posture/posture.zig.

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

## CI

[.github/workflows/check.yml](../.github/workflows/check.yml) runs `make
test`, `make lint` and `make check` on GitHub's x86_64 and arm64 Ubuntu
runners. [test/ci-setup](../test/ci-setup) installs the tools: Ubuntu's
packages, and apko and Zig pinned by version and sha256; `ci-setup apko`
installs apko alone, for jobs that only resolve packages. Each job keeps its
logs when it fails. The x86_64 runner has KVM; the arm64 runner has none, so
QEMU emulates there, and the job still takes under five minutes.

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
by [test/ci-setup](../test/ci-setup), which builds 1.9.4.
