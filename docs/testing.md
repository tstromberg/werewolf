# Testing

Opt-in IPE builds have a separate `make IPE=1 check-ipe` suite. It boots
the real image, tests global execution and executable mappings without
Landlock, seccomp or noexec, and refuses missing, tampered, wrong-signer and wrong-root
policies before handover. Build the custom kernel with `make ipe-kernel`
on Linux and supply `WEREWOLF_IPE_KEY` and `WEREWOLF_IPE_CRT`; see
[design/ipe.md](design/ipe.md). CI runs it on both architectures with
disposable signing keys. `make IPE=1 check-image-updater` also exercises
signed HTTPS slot updates, rejection before writes and reboot/commit with
IPE enforced ([design/prebuilt-images.md](design/prebuilt-images.md)).
On accelerated arm64, `make IPE=1 check-updater-uki` keeps one disk
through firmware boot, signed UKI delivery, verified slot b and commit.

```sh
make test           # every program's and library's unit tests
make check          # boot every form, and a slot, and check each one
make -j check       # the same, side by side
make ci             # the CI job, in an Ubuntu VM under Lima
make check-updater  # a whole update, over the network
make check-updater-published  # the same, on forms from werewolf's repository
make check-gcp      # prod-ssh's disk on a Google Compute Engine VM
make check-gcp-metadata # live GCP people, key expiry, precedence and rotation
make check-aws      # the same on an EC2 instance
make check-azure    # the same on an Azure VM
```

Besides the build's tools, `make check` needs QEMU, `expect` and `mke2fs`
(from e2fsprogs). On a Mac, run `brew install qemu e2fsprogs`; `expect`
ships with macOS.

The tutorial forms also need Go, rustup and the .NET 10 SDK on the build
host. Install Rust's Linux musl target for the architecture you test, for
example
`rustup toolchain install stable --profile minimal --target aarch64-unknown-linux-musl`.
Use `x86_64-unknown-linux-musl` for `ARCH=x86_64`. CI and `make ci` install
these compilers before they check the forms. None of them ships in a VM.

## What `make check` does

It builds every form and boots each one under QEMU. Then it boots a slot
the way bite leaves one. On each machine it runs
[test/checks](../test/checks) as root on the serial console, then powers
the machine off. A machine passes when it boots, every check comes out as
expected, and it shuts down cleanly.

On aarch64, each machine gets EL2 wherever the host can lend it: always
under TCG, under HVF on Apple M3 and later, and under KVM where the host
nests. A cloud that offers nested virtualization does the same. The
kernel's built-in KVM would start there, so posture's
`kernel-no-hypervisor` check proves that `kvm-arm.mode=none` stops it, and
`qemu-host` proves that its allowance does not.

These checks need a shell, and most forms have none. So `make check`
builds each form for them with `DEV=1`, which adds busybox-full on top of
its packages in `build/<arch>/<form>-dev` and changes nothing else. Every
form is also built as it ships and booted once more
(`check-shellfree-<form>`). There, test/boot runs nothing on the machine.
It judges the machine by its posture line, which may show no failure but
the weaknesses its form.yaml excuses. It also checks what
`forms/<form>/test/console` says the console must and must not show.

The checks try what an attacker would, and expect to be refused. They try
to lower lockdown, read `/dev/mem` or another process's memory, undo a
one-way sysctl, find a setuid file, listen on a port the form has not
declared in its network policy, and run a program from `/tmp`. (Installing
sshd declares ssh's port 22.) A socket must also listen on every port the
form declared, and answer HTTP where the port speaks it, so a runtime
form's application runs, leashed, and serves. A daemon that speaks another
protocol (Valkey, OpenBao, step-ca, Caddy's HTTPS) is tested in that
protocol by its form's `forms/FORM/test/checks`, which `make check`
appends. A socket bound only to loopback (OpenBao's cluster port) belongs
to the machine itself. Neither this check nor posture counts it as a
listener the network can reach. `forms/FORM/test/config` writes what a
form's services need from the config into the check's config tar:
OpenBao's unseal key and certificate, a CA for step-ca, WordPress's admin.

Where the attacker would be an ordinary user, the check acts as one, with
runit's `chpst -u nobody`. It tries to write to `/run`, see another user's
processes, and plant a symlink or hardlink in `/tmp` for root to follow.
Where a refusal and an ordinary error look alike, a check also looks for
the kernel's line saying it refused. One check confirms the address and
default route that the command line gave. One check runs first, before any
attack: it confirms that nothing was refused during boot, which catches a
protection that breaks a service.

Every form then boots a second time, on the disks its first boot left
([test/checks-again](../test/checks-again)). `/data` may hold real data, so
a disk that init formatted once must come back as it was. It must be
opened, checked and mounted, and still hold the mark the first boot wrote.
No line on the console may say that init formatted anything.

`prod` boots once more on the LUKS2 disk its own boots left, with no key
([test/checks-nodata](../test/checks-nodata)). It must refuse the disk
rather than format it again. `/data` must be an empty read-only tmpfs, the
reason must be in `/run/werewolf/nodata`, and the disk must be unchanged.

Two boots offer an unsigned module: `minimal`'s init on a RAM root, and
stage0 on a slot ([test/checks-unsigned](../test/checks-unsigned)).
[test/unsign](../test/unsign) cuts the signature off `evdev` and appends
the module to the initramfs, where it replaces the signed one. The kernel
must refuse it, say so, stay untainted, and still load every signed
module.

`minimal` boots once with one byte of its root image's superblock changed
(`make check-verity`). dm-verity must name the block, and stage0 must stop
before the root is mounted. Every other boot checks that its root is
mounted through dm-verity (`root-verified` in [test/checks](../test/checks)).

A slot that boots but never commits must be taken back
(`make check-deadman`). A DEV build of `minimal` boots with no loader to
commit to. Only its root lets `werewolf.deadman` shorten stage0's ten
minutes to twenty seconds. The deadman must say why on the console and
reset the machine.

Seven boots put `prod` behind a stand-in metadata server
([test/metadata](../test/metadata), driven by
[test/cloud-boot](../test/cloud-boot)), with the firmware's strings set to
each cloud's:

- On GCP, AWS, Hetzner Cloud and Azure, the machine must take a good
  config: it applies the hostname and root's key, and rewrites the tar as
  root's with mode 0600. On AWS it must take it only through a session
  token.
- A tar with a symlink and a `../` entry must be refused whole.
- A machine on no cloud, or on a desktop's Hyper-V, must not ask the
  metadata server at all, as the server's log shows. Hyper-V names itself
  as Azure does, except for Azure's asset tag.

arm64 guests get SMBIOS only under UEFI firmware, so these boots load it.

`make check-dist`, run after `make dist`, boots each release disk in
`dist/` as published: UEFI firmware, systemd-boot, slot a. It uses
`-snapshot`, so the file does not change, and a network with no way out,
so the updater cannot install the latest release over it. The posture line
must show exactly what the form fails as it ships (its form.yaml's
`weaknesses`). The release workflow runs it on every release.

Every boot so far gives its address on the kernel command line. One more
boots `prod` without one ([test/checks-lease](../test/checks-lease)), so
init asks QEMU's DHCP server. The machine must apply the address, gateway
and DNS server, and the console must show the client's `bound` event. The
client must also be split as it claims: an engine runs as `_dhcp`,
chrooted, with no capabilities, under seccomp, and only a parent keeps
`CAP_NET_ADMIN`. Another boot, `check-static`, boots `minimal`, which has
no DHCP client, also without an address. Its config tar comes from
`howl pack --ip --gw --dns` ([test/checks-static](../test/checks-static)).
init must take the address, route and DNS server from the tar's `network`
file, and say so.

The slot boot covers what direct boot cannot:

- stage0 finds `root.erofs` by filesystem UUID;
- `/victim` is read-only;
- the `slot-keep` service makes the slot GRUB's default once it has stayed
  healthy for a minute;
- `bite-cleanup` then deletes a stand-in distro around it, traps included,
  while it keeps werewolf's directory and `/boot`.

Among the traps, `debugfs` makes `/etc/resolv.conf` immutable.
bite-cleanup must delete the rest of `/etc`, name the file, and exit 1. The
victim is a 128 MiB ext4 that `mke2fs -d` fills with what bite leaves: the
root image in slot a, its kernel, and GRUB's environment block. The slot
uses `minimal`, which has no updater to reach the network once it commits.

```
ok     sshd               posture
ok     sshd               services-up
ok     sshd               root-unlinked
pass   sshd               all checks
pass   sshd-again         all checks
```

Each machine gets its own blank disk and config disk. The config disk
holds only a fixed test `data.key`, so `prod` and the forms on it put
`/data` in LUKS2. A form that serves ssh forwards it from 127.0.0.1, on
port 22200 plus the form's place among the forms, and its check's web port
from 23200 plus that place. So machines never share state or ports, and
`make -j` runs them together. A few forms boot a second time from the disk
the first boot left, to show what it kept (`AGAIN_FORMS`, Makefile):
`minimal` keeps nothing, `sshd` a host key, `prod-ssh` a host key under an
updater, `gitea` and `vaultwarden` an application's data, `demo`
PostgreSQL's, and `samba` its files while adding and revoking users.
Every form runs the same code, so these few stand for all.
`AGAIN_FORMS=all` boots every form twice.

A form's `test/config-again` may change its config before that second
boot, and `test/checks-again` adds checks to the common persistence checks.
A form's `test/config-shellfree` supplies configuration for its production
boot when its service needs secrets to start.

Nothing waits a fixed time. [test/boot](../test/boot) waits for each thing
it needs to see, up to a limit, so a fast machine finishes fast and a slow
one, emulated in CI, still passes. On an M4, `make -j8 check` takes about
25 s for the forms, and a further minute for the slot to commit.

Logs are in `build/<arch>/check/`. Each build, howl's `_build` run by
make, writes `<form>-build.log`, and each console, kernel messages and all,
goes to `<form>.log`. A shell-free boot writes `<form>-shellfree-build.log`
and `<form>-shellfree.log`. `shared-build.log` is what every check shares,
built once first: howl, the programs, the kernel and minimal's DEV=1 image.

## What `make check-updater` does

It runs a whole update, as a machine does one. `prod` is built with
`DEV=1`, so it follows no releases and builds its own slot. It boots from
slot a of a disk that [test/check-updater](../test/check-updater) makes,
and its build record claims the kernel release before its own (`linux-virt-6.18.55-r0` claims `6.18.54-r0`). The claim is one file,
laid over the slot's root as a later tar entry; nothing in `build/`
changes. The machine commits and finds Alpine's kernel newer. As
`_update`, it fetches Wolfi's and Alpine's packages and the CVE sources,
builds slot b, installs it and reboots.

[test/update](../test/update) then reads the disk with `debugfs`. The
report must list each CVE source with a sha256 and no error, each apk cache
must have kept its packages, slot b's root must be owned by root with mode
0755, and GRUB must boot b next. Then test/update boots slot b, which must
commit, and the updater must record that the update held. No seccomp
filter may have killed anything in either boot. The consoles are in
`build/<arch>/check/update-prod/`.

`make check-updater-published` builds `test/published-form`, a form given by
path on the published `prod`, from werewolf's repository, and gives slot a
an older-looking staged `prod`. Slot b must install `minimal-form` and
`prod-form`, compose `prod` from the package, not slot a's copy, and keep
the local form's files, carried from slot a (docs/design/custom-updates.md).
It takes the published packages, so it passes once CI has published this
tree's format and forms.

`make check-updater-staged` cuts the power the moment slot b is staged, as
a crash or an operator's reboot would. Slot b must boot all the same,
because a staged slot is armed (docs/design/update-policy.md).

It needs the network, so it is not part of `make check`. It takes about 4
minutes with KVM or HVF, and much longer under TCG. CI runs it nightly on
x86_64.

## What `make check-gcp`, `check-aws` and `check-azure` do

[test/cloud](../test/cloud) runs `prod-ssh`'s disk, as a release makes it,
on a real cloud, as a user would. `howl create --on CLOUD` turns the disk
into that cloud's image: a GCP image, an AMI from an EBS snapshot written
directly, or an Azure managed disk. It then boots a fresh machine from it,
the smallest for the arch (`ARCH=aarch64` or `x86_64`). The machine's user
data holds a config with a hostname and an ssh key made for this run. The
test judges the machine from the cloud's record of its serial port:

| Check | Passes when |
| --- | --- |
| `root-verified` | stage0 opened slot a's root through dm-verity |
| `metadata-config` | `cloud-metadata` took the config from that cloud's metadata server |
| `hostname` | posture names the host as the config did |
| `posture` | what fails is exactly what `prod-ssh`'s weaknesses say it fails |
| `ssh-login` | root logs in, over the Internet, with the run's key, through the port `create --allow-from me` opened |
| `reconfigure` | a second `create` of the name, with a new hostname, restarts the machine on it |
| `delete` | `howl delete` leaves nothing of the machine: instance, disk, network, security group, firewall rule |

The machine is made with `--allow-from me`, as a user's `create` would be,
so werewolf itself opens the form's ports to this host's address only.
However the run ends, it deletes everything it made, the image included.
`CLOUD_KEEP=1` keeps the machine, so you can look around. The serial port
log is kept in `build/<arch>/prod-ssh/check/CLOUD-serial.log`.

Each check needs that cloud's CLI logged in, and costs a few cents:

- **GCP:** gcloud with a project (`GCP_PROJECT`, or gcloud's own). The zone
  is `us-central1-a` (`GCP_ZONE`).
- **AWS:** the aws CLI's region and credentials (`aws login` or `aws
  configure`, or `AWS_REGION` and `AWS_PROFILE`). Nothing needs setting up
  first.
- **Azure:** az's default resource group (`az configure --defaults
  group=RG`, or `AZURE_DEFAULTS_GROUP`). Its location must offer the
  arch's size. Some subscriptions offer Arm sizes in few regions
  (`az vm list-skus -l LOCATION`).

Each takes a few minutes, most of it the cloud making the image and the
machine. They are not part of `make check`, nor of CI, which holds no cloud
credentials.

## What `make check-gcp-metadata` does

[test/gcp-metadata](../test/gcp-metadata) builds this checkout's `prod-ssh`
with `machine.metadata-users: true` and creates a fresh GCP VM. It uses
the software security-key provider from [test/keys](../test/keys), so SSH
keeps its production key policy. It checks user-data at boot, instance
and project keys, declared-user precedence, refusal of root access,
expired and malformed Google key records, expiry without a metadata
edit, project-key blocking and unblocking, account removal, root-key
rotation, and retention of the last accepted people after invalid user-data.
Removing user-data must leave only metadata people; restoring it must
restore the declared people and root keys. The boot ID must stay the same
through every change.

Use `GCP_PROJECT`, `GCP_ZONE` and `ARCH` as for `check-gcp`. The test
temporarily appends its public test key to the project's `ssh-keys`, then
removes that key even if a check fails. Use a test project where temporary
project SSH keys are appropriate; the account needs project-metadata write
permission as well as permission to create and delete the test resources.
The test deletes its VM, disk, firewall rule and newly created image.
`CLOUD_KEEP=1` keeps those resources and their test private keys. Logs stay
in `build/check/gcp-metadata-*`. This live test is outside `make check` and
CI.

## Writing a check

[posture](posture.md) judges a machine's settings and the attacks on them,
so each is checked once, the way a machine's owner checks it. Every
machine's posture service prints one line on the console once its services
settle. With `werewolf.check=1`, which only `make check` sets, posture also
makes the attacks that write to the kernel log, and proves each refusal by
the kernel's own line.

[test/boot](../test/boot) waits for that line before anything else. It
fails the machine unless the failing checks are exactly the weaknesses its
form.yaml excuses, plus those that [test/posture-known](../test/posture-known)
gives every DEV=1 build or the architecture. A new failure fails the
machine. So does a known failure that starts passing, until it leaves the
list and the docs say so. A new protection belongs in cmd/posture, in the
file for its area.

For a form that serves ssh, the host also logs in, as an operator would,
through a forwarded port. Root's key from the config must get in, a session
must not forward a port past fence, and only keys may be offered.

`test/checks` holds the rest, which is the boot's own behaviour: the
network, the services, `/data`, the slot's commit. A check is one line: a
kind, a name, and one line of sh. It runs as root in a subshell and exits 0
when the property holds. A machine with no shell is judged by its posture
line alone (`test/boot NAME - LOG QEMU...`).

```
ok  data-usable      [ ! -e /run/werewolf/nodata ]
ok  root-unlinked    ! rm -f /init && [ -e /init ] && awk '$2 == "/" { o = $4 } END { exit o !~ /^ro(,|$)/ }' /proc/mounts
```

- **ok** must hold on every machine. A check that applies to only some
  machines decides for itself: `slot-commits` passes at once unless the
  machine booted from a slot.
- **gap** is a known weakness from [security.md](security.md), "Not yet",
  and must not hold. When work closes one, its check starts to hold, and
  `make check` fails until the line becomes `ok` and the docs say so. So
  the docs cannot claim a protection the machines lack, or miss one they
  have.

A check that needs more than a boot and these lines is a script,
`test/check-NAME`, which `make check-NAME` runs once it has built what the
script boots. The script takes the machine, `QEMU...`, as its arguments,
and the form's values in its environment (the Makefile's `CHECK_ENV`):
`CHECK`, the log directory; `FORM` and `OUT`, the form and its build;
`KERNEL`, with its command line without an address (`BOOT`) and with one
(`CMDLINE`); `VICTIM`, the UUID stage0 finds a slot's disk by; and the
tools `HOWL`, `TAR` and `DEBUGFS`. It says `pass` or `FAIL` in test/boot's
columns.

Test the attack, not the setting. `ptrace_scope` reading 3 proves less than
a refused `cat /proc/1/mem`, which is why posture asks the kernel to undo a
setting and expects a refusal. And make a check fail before you trust it to
pass: point it at a machine without the protection, or invert it.

## Debugging a failure

A FAIL reports three things. It gives what the machine last reported doing
(its last progress line), and the first thing its kernel said was wrong (an
RCU stall, a blocked task, a lockup, a panic). It also describes the host:
its kernel, QEMU, accelerator, CPUs and load. The same host line heads
every console log. Check boots panic on a CPU stalled for 20 s or a task
blocked for two minutes, so a hang fails in seconds, with the kernel's
reason, rather than at a timeout. When a machine stops answering, test/boot
first dumps every virtual CPU's state (`info cpus`, `info registers -a`)
into its log. A CPU parked and never woken is the hypervisor's fault, not
the guest's.

```sh
make check-one FORM=playground REPEAT=20          # how often does it fail?
make check-one FORM=playground REPEAT=20 ACCEL=tcg   # without the hypervisor
BOOT_TIMEOUT=20 make check-minimal          # see a hang sooner
```

`check-one` keeps each failing boot's console as `FORM-one-N.log`.

## Where a boot's time goes

Every boot prints its timing on the console. Every machine also keeps it in
`/run/werewolf/boot` as `kernel_ms`, `userland_ms` and `phases`, each phase
a `name` and its `ms`:

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

The console also shows the other half of a reboot. Stage 3 ends with
`werewolf: down in Xs (services Ys, filesystems Zs)`. Before that, it
prints `werewolf: SERVICE not down in 30s; killed` for any service it had
to kill. On a machine with slots, the update's `commit` or `rollback` event
carries `down`: the seconds from its `reboot` event to the new kernel's
start, which covers the stop, the firmware and the loader. The console
shows only the kernel's warnings and worse (`loglevel=5`). `dmesg` keeps
every line with its time, so a gap between two lines is where to look next.

## CI

[.github/workflows/check.yml](../.github/workflows/check.yml) runs `make
test` on GitHub's x86_64 and arm64 Ubuntu runners, and `make lint` on one.
It splits `make check` into jobs that run in parallel, so a failure names
its area: `forms`, `shellfree`, `integrity`, `cloud`, `persist` and, on
arm64, `native`. `forms`, `shellfree` and `native` are split again over
runners: `SHARD=K/N` takes every Nth form from the Kth, in name order. The
forms jobs check `demo`, so the `persist` job passes `PERSIST_AFTER=` to
skip it. That makes 19 jobs in all, under the 20 the account
runs at once. Each job boots four machines at a time on its four CPUs. It
keeps Zig's and apko's caches from one run to the next, a week at a time,
so a program or package that has not changed is not built or fetched again.
[test/ci-setup](../test/ci-setup) installs the tools with
[tools/install-deps](../tools/install-deps), as `make install-deps` does
anywhere: Ubuntu's packages, and apko and Zig pinned by version and sha256.
`ci-setup apko zig` installs only those two, for the release job that only
resolves packages. Each job keeps its logs when it fails.

The x86_64 runner has KVM, so its emulation is fast and it runs every
group. The arm64 runner has none, so a full boot there is emulated slowly
under TCG. So arm64 runs the `native` group instead of `forms` and
`shellfree`. [test/cage](../test/cage) boots each form's root under
`systemd-nspawn` on the runner's own kernel, with no virtual machine, and
judges its posture. cage runs nothing on the machine, so each form is built
as it ships, without `DEV=1`, and arm64 checks the shipped images too.

werewolf's runtime protections (the seal, Landlock, fence's policy routing,
the leash, hidepid, W^X) are features of the host kernel and hold in a
container. So cage checks them directly, and `WEREWOLF_CHECK=1` makes the
posture service in the container attack them too, as `werewolf.check=1`
does on a booted machine. A container cannot own the kernel's sysctls and
boot line, dm-verity, or a few mount options. test/cage's
`POSTURE_KNOWN_NATIVE` allows those checks to fail, as the form's weaknesses allow what the form carries
by design.

Where cage may change the host (`CAGE_HARDEN_HOST=1`, which CI sets on its
throwaway runners), it first raises the host sysctls behind `files-links`,
`files-links-attack` and `files-memfd-exec` to werewolf's levels, so those
attacks run for real. Elsewhere, a host below werewolf's levels makes those
checks expected to fail, and cage says so. arm64 still emulates `minimal`
and `prod` (the `integrity` and `cloud` groups) to check those, and the
attacks a container cannot carry. `persist` is skipped on emulated arm64
(Makefile).

[.github/workflows/update.yml](../.github/workflows/update.yml) runs `make
check-updater` nightly, and on demand, on x86_64 only. `prod` updates
itself over the network, and the slot it builds must boot and commit. It is
a separate workflow, so a network flake fails only it. No push, pull
request or release waits on it.

`make ci` runs the same job here, in an Ubuntu VM, `werewolf-ci-24.04`,
with nested virtualization for KVM. Each run copies the tree in fresh,
without `config/` or `.git`. The VM, its tools and its build cache stay
between runs, and `limactl delete -f werewolf-ci-24.04` starts over.
`LIMA_TEMPLATE=ubuntu-26.04 make ci` runs it on 26.04, as GitHub's runners
are, in a separate VM. There, nested guests lose a CPU's timer early in
boot and stall, so 24.04 is the default. Its old erofs-utils is replaced by
[tools/install-deps](../tools/install-deps), which builds 1.9.4.

## Provider A/B upgrades and rollbacks

`make IPE=1 check-ab-PROVIDER` builds three disposable signed releases and
uses the real updater over confined loopback HTTPS. Each boot must have a fresh
boot ID, the expected signed root hash, read-only dm-verity and enforcing IPE.
Supported firmware tests additionally require SecureBoot=1 and SetupMode=0.
The runner checks upgrade A→B, health commit, operator rollback B→A, another
reboot of A, and automatic recovery from an unhealthy signed candidate after
600 seconds. After recovery the updater must refuse that failed build again.
Host/console logs and `phases.json` remain under `CHECK/provider-ab-PROVIDER`;
only resources created by the test are removed, including on failure.

Build an IPE kernel with a disposable signing identity first, as described above.
Set `WEREWOLF_IPE_KEY`, `WEREWOLF_IPE_CRT` and, for an existing kernel archive,
`IPE_KERNEL`. A saved `AB_FIXTURE=/absolute/path/fixture.json` reuses an existing
fixture of the same architecture and mode. Private signers stay on the host.

| Target | Mode | Requirements |
|---|---|---|
| `check-ab-qemu` | Secure Boot | QEMU and enrollment tools; CI runs both architectures |
| `check-ab-lima-qemu` | Secure Boot | arm64 Mac; explicit debug firmware arguments |
| `check-ab-lima-vz` | Signed updates | arm64 Mac; `AB_MODE=plain` |
| `check-ab-aws`, `check-ab-gcp` | Secure Boot | Authenticated cloud CLI; optional `CLOUD_SIZE`, `GCP_PROJECT`, `GCP_ZONE` |
| `check-ab-azure` | Secure Boot | Authenticated Azure CLI; owned temporary group in West US 2 by default |
| `check-ab-bhyve` | Signed updates | x86_64; `BHYVE_HOST=bilbo`, passwordless `doas`, bhyve firmware and mtools |
| `check-ab-firecracker` | Signed updates | x86_64; `FIRECRACKER_HOST=galadriel`, KVM and passwordless `doas` |
| `check-ab-proxmox` | Signed updates | Untested; `PROXMOX_HOST`, optional `PROXMOX_STORAGE` and `PROXMOX_BRIDGE` |

Lima VZ, Firecracker, bhyve and Proxmox default to `AB_MODE=plain`; their signed
updates do not imply firmware enforcement. Bilbo also accepts `AB_MODE=secure`
with `SECUREBOOT_DIR` holding its public `code.fd` and `vars.fd` templates.
`make check-bhyve-secureboot AB_FIXTURE=...` checks tampered-UKI rejection with
those templates. `howl` does not yet configure bhyve enrollment itself.
Smaug runs arm64 FreeBSD; Werewolf's bhyve backend currently supports x86_64 only.
Proxmox has no available test node. Azure's setup-mode inconsistency remains a
failing Secure Boot deployment, not a passing recovery test.

Observed on 2026-10-12 (full lifecycle includes automatic unhealthy recovery):

| Provider / architecture | A/B result | Firmware enforcement |
|---|---|---|
| QEMU arm64 | Passed | Secure Boot with immutable variables |
| Lima QEMU arm64 | Passed | Secure Boot with explicit debug firmware arguments |
| AWS and GCP arm64 | Passed | Custom enrolled keys; SecureBoot=1, SetupMode=0 |
| bhyve x86_64 on Bilbo | Passed in both modes | Manual Secure Boot enrollment also passed changed-UKI refusal |
| Lima VZ arm64 | Passed | Signed updates, without Secure Boot |
| Firecracker x86_64 on Galadriel | Passed | Signed updates; no UEFI |
| Azure arm64, West US 2 | Blocked before handover | Firmware again reported SecureBoot=1, SetupMode=1 |
| Proxmox | Unverified | No node available |
| bhyve arm64 on Smaug | Unsupported backend | Werewolf integration unfinished |

Stock QEMU firmware boot and tampered-UKI rejection also passed on x86_64;
full QEMU A/B CI covers both IPE architectures. See the
[audit](audit/astra-2026-10-11.md#provider-ab-follow-up-2026-10-12) for findings.

These opt-in live tests need no public mirror. Cloud tests create billable
resources and must use test credentials. Ordinary PR CI requires no cloud or
remote-host credentials. Protected TPM retirement remains unfinished and must
preserve the previous good slot after commit ([design](design/provider-ab-tests.md)).

## Secure Boot

`make check-secureboot` builds a stock-Alpine signed release disk and verifies
its UKI and certificate against the release manifest and actual ESP. Enrolled
firmware must boot the native slot, verify the root and pass expected posture;
a changed UKI must be refused. It runs on arm64 and x86_64, including emulation.

`make IPE=1 check-updater-uki` additionally proves continuous signed A/B delivery
under Secure Boot. It rejects unsigned, altered and wrong-key loaders and UKIs,
an unexpected UKI path, and setup-mode boot before handover. Malicious unsigned
loader options cannot change slot identity or disable IPE. The valid HTTPS
update must boot verified slot b and commit it with IPE still enforcing.
Arm A/B boots keep enrollment flash read-only and verify its digest; disposable
writable clones capture AAVMF's explicit rejection diagnostics.

On an arm64 Mac, `make check-lima-secureboot` proves the signed release under
Lima's QEMU backend and checks that VZ refuses its Secure Boot requirement.
The test supplies enrolled firmware through Lima's debug QEMU arguments; the
normal `howl --on lima` VZ engine does not support firmware-key enrollment.
Firecracker has no UEFI firmware and refuses EFI entries, including entries
with appended unsigned `linux` and `initrd` lines. Use QEMU for firmware enforcement.

Install `python3-virt-firmware`, OVMF and `qemu-efi-aarch64` on Linux. On macOS,
`tools/enroll-boot` uses the existing `werewolf-ci-24.04` Lima build VM for firmware
and public-key enrollment. `SECUREBOOT_DIR` optionally supplies `code.fd` and
`vars.fd`; pinned systemd stubs come from `out/tools/stubs/ARCH/linux.efi.stub`.
Enrollment never copies a private signer into that helper's VM scratch directory.

`test/check-tpm-policy` runs on Linux with swtpm and tpm2-tools. It tests signed
monotonic NV writes, replay, altered data, undefine and hierarchy-reset refusal.
Set `TPM_POLICY_PROBE` to `build/host/tpm-policy` to exercise Werewolf's actual
TPM command implementation as well. These serial-floor commands are host test
probes; their former guest commit hook is removed because it invalidated A/B fallback.

With that same probe, `python3 test/check-tpm-ab` tests the
[replacement exact-pair protocol](design/tpm-ab-retirement.md) using actual
TPM commands and independently generated trial policies. It covers both members,
operator rollback, wrong/zero/changed PCRs, replayed state, altered signatures,
direct writes, index removal, hierarchy resets and weaker provisioning.
Eleven durable-boundary models use on-disk records, slot fixtures and simulator
restarts. A TCP proxy drops a successful NV_Extend reply to exercise uncertain
completion; recovery reads the anchor and refuses a blind retry.
These protocol/model checks do not prove physical TPM atomicity.
CI runs both TPM suites and both firmware architectures. Normal unit tests compare
the new policy digests with checked-in public TPM fixtures; no private keys are retained.

`make IPE=1 check-tpm-guest` builds disposable TPM-gated releases and boots QEMU
with persistent swtpm state. Install `swtpm`, `tpm2-tools` and `systemd-boot-efi`.
The harness selects the host's TPM-enabled stub; `UKI_STUB` can supply another.
Alpine's [stub build](https://github.com/alpinelinux/aports/blob/master/main/systemd-boot/APKBUILD)
disables TPM measurement; mandatory boot refuses zero PCR 11.
The runner checks signed identity, exact root, actual PCR prediction and posture;
then commit, operator rollback, failed trials and cuts around the NV extension.
It kills both VM and simulator and retains their existing disk, variables and NV.
It also restores retired A, installs a signed unmeasured UKI and removes the TPM,
requiring explicit stage0 refusal. The full guest suite passed on Galadriel x86_64;
IPE CI runs it on x86_64. Both architectures run the protocol/model suites.
Retain only logs and `evidence.jsonl`; fixture signers and reset credentials are private.

The opt-in build takes `--tpm-pub` (or `WEREWOLF_TPM_PUB`) and a TPM-enabled
`UKI_STUB`, alongside signed native IPE image updates. `WEREWOLF_BOOT_STATE` supplies
the signed factory pair; `tools/tpm-enroll` initializes a fresh host-controlled TPM.
Reset credentials and the permit signer stay outside guests. Firmware must trust
only UKIs that enforce this check. The updater fetches machine-specific public
permits at `CHANNEL/ARCH/permits/MACHINE_NONCE/CANDIDATE_ID.permit`.
See [TPM retirement](design/tpm-ab-retirement.md) for issuer and custody requirements.

`howl run --on lima --secure` uses an arm64 QEMU guest with host-managed enrollment,
HTTPS image publication and contextual permits. Supply `WEREWOLF_IPE_KERNEL`,
`WEREWOLF_IPE_KEY`, `WEREWOLF_IPE_CRT` and a TPM-enabled `UKI_STUB`.
The [local deployment design](design/secure-local-deployment.md) defines the host trust boundary.
`tools/build-tpm-stub OUT` builds the pinned measured stub on Linux; copy its public
`linux.efi.stub` back to the Mac. No signing key is needed to build the stub.

`make check-secure-lima` uses those inputs and exercises creation, multiple signed
updates, operator rollback, restart with the same NV authorization, updates after
rollback and an unhealthy counted trial recovering its predecessor. It compares
actual PCR 11 with registered predictions and rejects writable-code execution,
verified-root writes and requests to reauthorize retired history.
The test removes its own instance, signers and reset credentials, retaining public logs.
`make test` runs the bounded publisher's signature, context, concurrency and restart
regressions. `python3 test/check-tpm-enrollment` tests native enrollment against
swtpm on macOS or Linux, including private file modes, repeat refusal and restart.
Only the VM's TPM device is exposed; no signing keys or host directories are mounted.

PR CI checks the IPE source version against both Alpine architecture locks.
Nightly CI resolves fresh signed indexes and compares their full package versions
with `boot/kernel-source`, including Alpine's revision. `test/kernel-version`
checks version drift, revision drift and missing architectures without network access.

## Firecracker

`make check-firecracker` boots the `sshd` form as a real Firecracker
microVM on `FIRECRACKER_HOST` (default `galadriel`), a Linux host with
KVM, Firecracker, mtools, erofs-utils and passwordless `doas`. The tree,
built for x86_64 here, is copied with a howl, a form tool and a verity
tool cross-compiled for it, so the host needs no toolchain; the form is
sshd relaxed to take a key file, which the host holds, and the adhoc
generator then declares the `network-ssh-security-keys` weakness it
costs. The machine must hand over to runit with its root verified through
dm-verity, posture must fail exactly what the form and test/posture-known
allow, ssh must reach it through its tap with the host's key, and delete
must remove the machine. `FIRECRACKER_KEEP=1` leaves it for a look.

The host resolves any lock the copy does not match with `go install`'s
apko, at the version tools/install-deps pins.
