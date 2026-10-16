# Testing

To test one form from the checkout root:

```sh
howl test --with caddy
howl test --with caddy --arch x86_64
```

For most forms this runs `make -k check-FORM check-shellfree-FORM`: the integration
checks in a development VM, then posture and console checks of the form as it ships. A
form with `test/native.json`, such as `postgresql`, runs its native suite instead:
compiled Zig drivers under leash use the service as its clients would, with no shell or
ssh added, on a generated test form compared with the plain build before boot
([design](design/image-release-testing.md)). Publishing a form's image asks more of it
([form-images.md](form-images.md)). While developing a suite, use the [local iteration
loop](design/local-test-iteration.md) to keep the VM running between client changes.

PostgreSQL tests SQL, shim redirects, no TCP and encrypted-disk persistence.
[Greenbone](../forms/greenbone/README.md#testing-status) tests GMP/OSP, database roles,
Valkey ACLs, shared mounts and persistence; `legacy: true` retains its DEV checks.
Logs: `build/ARCH/check/FORM-native/`. These local QEMU runs are separate from
protected lifecycle evidence.

```sh
make test           # every program's and library's unit tests, in seconds
make -j check       # boot every form, and a slot, side by side, and check each
make check-FORM     # one form; check-shellfree-FORM boots it as it ships
make check-apps     # application-carrier forms with supplied code
make check-posture  # concurrent scans, stale probes and fresh audit evidence
make check-dns      # Linux: resolver, DHCP and TLS fixtures in private namespaces
python3 test/form-coverage --list   # each form's integration cases
```

Tests that need the network, a cloud or another host are in
[testing-live.md](testing-live.md); Secure Boot, TPM and signed updates in
[testing-secure-boot.md](testing-secure-boot.md).

Besides the build's tools, `make check` needs QEMU, `expect` and `mke2fs`
(`brew install qemu e2fsprogs` on a Mac); the tutorial forms also need Go,
rustup with the architecture's Linux musl target, the .NET 10 SDK and a JDK.
`make check-dns` runs as root, or as a user with subordinate ids.

## What `make check` does

It builds every form and boots each one under QEMU, then boots a slot with a
native EFI partition. On each machine it runs [test/checks](../test/checks)
as root on the serial console, then powers the machine off. A machine passes
when it boots, every check comes out as expected, and it shuts down cleanly.

The checks need a shell, and most forms have none. So each form is built
with `DEV=1`, which adds busybox-full and changes nothing else, and once
more as it ships (`check-shellfree-<form>`), where [test/boot](../test/boot)
runs nothing on the machine and judges it by its posture line and by what
`forms/<form>/test/console` says the console must and must not show.

The checks try what an attacker would, and expect to be refused: lower
lockdown, read `/dev/mem` or another process's memory, undo a one-way
sysctl, find a setuid file, listen on an undeclared port, run a program from
`/tmp`; and as `nobody`, write to `/run`, see another user's processes, plant
a link in `/tmp` for root to follow. A socket must listen on every declared
port and answer HTTP where the port speaks it; another protocol is tested in
`forms/FORM/test/checks`, with `forms/FORM/test/config` giving the services
what they need. The first check: nothing was refused during boot.

Other boots cover what one boot cannot:

| Boot | Must | Where |
| --- | --- | --- |
| again (the Makefile's `AGAIN_FORMS`; `all` for every form) | come back on the disk the first boot left: `/data` opened, not formatted, its mark kept | [test/checks-again](../test/checks-again); a form's `test/checks-again` and `test/config-again` |
| `prod` with no key | refuse its LUKS2 disk, mount an empty read-only tmpfs, say why in `/run/werewolf/nodata` | [test/checks-nodata](../test/checks-nodata) |
| `minimal` with one root byte changed (`check-verity`) | dm-verity names the block; stage0 stops before the root is mounted | `root-verified` in test/checks, for every other boot |
| a slot that never commits (`check-deadman`) | the deadman says why and resets the machine | `werewolf.deadman`, honoured by DEV builds only |
| `prod` behind a stand-in metadata server, as each cloud | take a good config on GCP, AWS (by session token only), Hetzner and Azure; refuse a tar with a link or `../`; ask nothing on no cloud or on Hyper-V | [test/metadata](../test/metadata), [test/cloud-boot](../test/cloud-boot) |
| `prod` with no address; `minimal` with a packed one (`check-static`) | take it from DHCP, the client split as it claims; or from `howl pack --ip --gw --dns` | [test/checks-lease](../test/checks-lease), [test/checks-static](../test/checks-static) |
| the slot | find `root.erofs` by UUID, keep `/boot` read-only, commit its EFI entry once healthy for a minute | a 128 MiB ext4 and a FAT EFI partition with one counted entry |
| each release disk in `dist/` (`check-dist`, after `make dist`) | boot under UEFI firmware, with `-snapshot` and no way out, failing exactly its form.yaml's `weaknesses` | [test/check-dist](../test/check-dist); the release workflow |

Each machine gets its own blank disk, a config disk with a fixed test
`data.key` (so `/data` is LUKS2) and forwarded ports (22200 and 23200 plus
its place among the forms), so `make -j` runs them together. Nothing waits
a fixed time: test/boot waits for each thing it needs to see, up to a
limit. On an M4, `make -j8 check` takes about 25 s for the forms and a
minute more for the slot to commit. `build/<arch>/check/` keeps the logs.

## Form integration coverage

A service or application form needs at least five distinct integration
cases through the running service: write and read data, authenticate,
reject a wrong password, refuse an unsupported operation, serve the
configured content, keep state across a reboot. Several assertions about
one operation are one case; name each for the behaviour it tests. Shared
boot and posture checks do not count. `python3 test/form-coverage` checks
the minimum in `make test`; `--list` shows where each form's cases come
from, and the [exceptions](../test/form-coverage-exceptions) say why the
foundations and runtime-only forms use the shared suites. The count guards
against missing coverage; review still judges the cases. `make check-apps`
builds the `-app` forms and `php` with the applications in
[test/app-fixtures](../test/app-fixtures) and tests their HTTP behaviour.

## Porting a form to native tests

See the [native-test porting guide](testing-native.md) for drivers and persistence.

## Writing a check

[posture](posture.md) judges a machine's settings and the attacks on them,
once, the way its owner would; with `werewolf.check=1`, which only `make
check` sets, it also makes the attacks that write to the kernel log.
test/boot waits for its line and fails the machine unless the failing checks
are exactly the weaknesses its form.yaml excuses, plus what
[test/posture-known](../test/posture-known) gives every DEV=1 build or the
architecture. A known failure that starts passing fails too, until the list
and the docs change. A new protection belongs in cmd/posture.

`test/checks` holds the rest, the boot's own behaviour: the network, the
services, `/data`, the slot's commit. A check is one line, a kind, a name
and sh, run as root in a subshell, exiting 0 when it holds.

```
ok  data-usable      [ ! -e /run/werewolf/nodata ]
ok  root-unlinked    ! rm -f /init && [ -e /init ] && awk '$2 == "/" { o = $4 } END { exit o !~ /^ro(,|$)/ }' /proc/mounts
```

- **ok** must hold on every machine. A check that applies to some decides
  for itself: `slot-commits` passes at once off a slot.
- **gap** is a known weakness from [security.md](security.md) and must not
  hold. When work closes one, `make check` fails until the line becomes
  `ok` and the docs say so: the docs can neither claim a protection the
  machines lack nor miss one they have.

A check that needs more than a boot is a script, `test/check-NAME`, run by
`make check-NAME` with the machine's QEMU command as its arguments and the
form's values in its environment (the Makefile's `CHECK_ENV`). Test the
attack, not the setting: a refused `cat /proc/1/mem` proves more than
`ptrace_scope` reading 3. And make a check fail before you trust it to pass.

## Debugging a failure

A FAIL reports the machine's last progress line, the first thing its kernel
said was wrong (a stall, a blocked task, a panic), and the host: kernel,
QEMU, accelerator, CPUs and load. Check boots panic on a CPU stalled for
20 s or a task blocked for two minutes, so a hang fails in seconds with the
kernel's reason; a machine that stops answering gets every virtual CPU's
state dumped into its log first.

```sh
make check-one FORM=playground REPEAT=20             # how often does it fail?
make check-one FORM=playground REPEAT=20 ACCEL=tcg   # without the hypervisor
BOOT_TIMEOUT=20 make check-minimal                   # see a hang sooner
```

`check-one` keeps each failing boot's console as `FORM-one-N.log`. Every
boot prints where its time went, `werewolf: up in 1.470s (the kernel
0.225s, userland 1.245s)`, phase by phase (kernel, disk, slot, root,
init's steps, seal), and keeps it in `/run/werewolf/boot`. The console
shows only warnings and worse (`loglevel=5`); `dmesg` keeps every line.

## CI

[check.yml](../.github/workflows/check.yml) runs `make test` on x86_64 and
arm64 runners and `make lint` on one, and splits x86_64's `make check` into
jobs that name their area (`forms`, `shellfree`, `integrity`, `cloud`,
`persist`), the first two sharded again (`SHARD=K/N`): 10 jobs, each booting
four machines at a time, with Zig's and apko's caches kept a week.
[test/ci-setup](../test/ci-setup) installs the tools, pinned.

Hosted arm64 runners have no KVM, so `vm-arm64` runs every group under KVM on a
self-hosted Ampere runner, for pushes and maintainers' pull requests.
`make check-native` still checks each form's root under `systemd-nspawn`
([test/cage](../test/cage)), attacking what holds in a container.

`make ci` runs the same job here, in the `werewolf-ci-24.04` Lima VM with
nested KVM, copying the tree in fresh without `config/` or `.git`; the VM
and its caches stay (`limactl delete -f werewolf-ci-24.04` starts over).
