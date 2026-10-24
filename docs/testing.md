# Testing

To test one form from the checkout root:

```sh
howl test --with caddy
howl test --with caddy --arch x86_64
```

`make -k check-FORM check-shellfree-FORM` runs integration tests, then shipping-form
posture and console checks. Forms with native plans run compiled service clients under
leash without shell or SSH ([driver guide](testing-native.md)). Their generated test
form pins and is compared with the production package closure before boot
([design](design/image-release-testing.md)). Publishing adds [image
gates](form-images.md). [Local iteration](design/local-test-iteration.md) keeps the VM
running between changes.

PostgreSQL tests SQL, redirects, no TCP and encrypted persistence;
[Greenbone](../forms/greenbone/README.md#testing-status) tests GMP/OSP, roles, Valkey
ACLs, mounts and persistence. `legacy: true` retains DEV checks. Logs are in
`build/ARCH/check/FORM-native/`; local QEMU tests are separate from protected evidence.

For a native driver edit, keep one disposable VM running and replace only that driver:

```sh
howl test --with postgresql --iterate
howl test --with postgresql --iterate --driver test-postgres
howl test --with postgresql --iterate --driver test-postgres --phase verify
howl test --with postgresql --iterate --reset   # discard guest state
howl test --with postgresql --iterate --stop
```

Drivers use 128 MiB by default; `memory` accepts 16–8192 MiB. Their `allow` list may
include `python:native`, `node:native` or `java:native`, scoped to the driver only.
Payload comparison rejects blanket grants and undeclared files. Iteration uses
SSH/sh-shim without BusyBox, disables IPE and is not release evidence. Rerun normally
after edits. `KERNEL_ROOTFS=/path/rootfs.tar` tests kernels; byte changes reset the VM.

```sh
make test           # every program's and library's unit tests, in seconds
make -j check       # boot every form, and a slot, side by side, and check each
make check-FORM     # one form; check-shellfree-FORM boots it as it ships
make check-apps     # application-carrier forms with supplied code
make check-posture  # concurrent scans, stale probes and fresh audit evidence
make check-dns      # Linux: resolver, DHCP and TLS fixtures in private namespaces
python3 test/form-coverage --list   # each form's integration cases
```

[Live tests](testing-live.md) cover network, cloud and remote hosts; see
[secure boot tests](testing-secure-boot.md) for Secure Boot, TPM and signed updates.

`make check` also needs QEMU, `expect` and `mke2fs` (`brew install qemu e2fsprogs` on
macOS); tutorials need Go, rustup with Linux musl targets, .NET 10 and a JDK.
`make check-dns` needs root or subordinate ids.

## What `make check` does

It builds and boots every form under QEMU, then a slot with a native EFI partition.
Each runs [test/checks](../test/checks) as root on the serial console, then powers off.
Passing requires a successful boot, all expected check results and a clean shutdown.

Forms run twice: `DEV=1` adds BusyBox/developer SSH for shell checks;
`check-shellfree-<form>` boots the shipping form. [test/boot](../test/boot) judges its
posture and expected console patterns in `forms/<form>/test/console`.

The checks try what an attacker would, and expect to be refused: lower lockdown, read
`/dev/mem` or another process's memory, undo a one-way sysctl, find a setuid file,
listen on an undeclared port, run a program from `/tmp`; and as `nobody`, write to
`/run`, see another user's processes, plant a link in `/tmp` for root to follow. A
socket must listen on every declared port and answer HTTP where the port speaks it;
another protocol is tested in `forms/FORM/test/checks`, with `forms/FORM/test/config`
giving the services what they need. The first check: nothing was refused during boot.

`make check-people-persist` (`check-cloud`) tests enrollment, retirement, conflicts,
NoCloud and reactivation on one data volume, including private-file access and refusal
of missing/corrupt identity tables before service handover. Logs are in
`build/ARCH/check/people-persist/`. Seeds need Linux `xorriso` or macOS `hdiutil`.

`make check-privilege-boundaries` uses a disposable protected Lima image to test real
SSH credentials, descriptors, cross-user files, PTYs, forwarding refusal, concurrent
sessions, SFTP, daemon restart and kernel restrictions. Secure Boot, TPM and IPE stay
enabled. Logs/profile remain in `build/security-probes/`; `werewolf-run` is untouched.

`make check-mount-broker LINUX_TEST_RUNNER=sudo` tests the confined broker's roles,
malformed requests, stalled readers and staged-file integrity in a private mount
namespace. CI runs it with updater construction tests. macOS can use a disposable
Linux VM via `LINUX_TEST_RUNNER='limactl shell VM sudo -n'`. `make fuzz-broker` tests
the wire parser without privileged operations.

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
| each legacy release disk and direct image | boot without Secure Boot or a TPM, judging the exact form's posture | [test/check-legacy-image](../test/check-legacy-image); the shared image workflow |

Each machine gets blank/config disks, a fixed test LUKS2 key and distinct forwarded
ports (22200 and 23200 plus its form index), so `make -j` can run them together.
test/boot waits for bounded events; logs stay in `build/<arch>/check/`.

## Form integration coverage

A service/application form needs five distinct cases through its running service:
read/write, authentication, refusals, configured content or reboot persistence. Name
each behaviour; assertions about one operation count once, and shared boot/posture
checks do not count. `python3 test/form-coverage` enforces this in `make test`;
`--list` shows cases and [exceptions](../test/form-coverage-exceptions) explain shared
suites. Review judges quality. `make check-apps` tests HTTP for `-app` forms and `php`
using [test/app-fixtures](../test/app-fixtures).

## Writing a check

[posture](posture.md) judges a machine's settings and the attacks on them, once, the way
its owner would; with `werewolf.check=1`, which only `make check` sets, it also makes
the attacks that write to the kernel log. test/boot waits for its line and fails the
machine unless the failing checks are exactly the weaknesses its form.yaml excuses, plus
what [test/posture-known](../test/posture-known) gives every DEV=1 build or the
architecture. A known failure that starts passing fails too, until the list and the docs
change. A new protection belongs in cmd/posture.

`test/checks` covers boot behaviour: network, services, `/data` and slot commit. Each
line has a kind, name and sh, run as root in a subshell and exiting 0 when it holds.

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

A check needing more than a boot is a `test/check-NAME` script, run by `make check-NAME`
with the QEMU command as arguments and form values in the environment (`CHECK_ENV` in
the Makefile). Test attacks: a refused `cat /proc/1/mem` proves more than reading
`ptrace_scope=3`. Make a check fail before trusting it to pass.

## Debugging a failure

A FAIL includes the last progress line, kernel error and host kernel/QEMU/CPU/load.
Boots panic on 20-second CPU stalls or two-minute blocked tasks; unresponsive VMs
dump every virtual CPU's state before failing.

```sh
make check-one FORM=playground REPEAT=20             # how often does it fail?
make check-one FORM=playground REPEAT=20 ACCEL=tcg   # without the hypervisor
BOOT_TIMEOUT=20 make check-minimal                   # see a hang sooner
```

`check-one` keeps failures as `FORM-one-N.log`. Boot timings cover kernel, disk, slot,
root, init and seal and stay in `/run/werewolf/boot`. The console shows warnings and
worse (`loglevel=5`); `dmesg` keeps every line.

## CI

[check.yml](../.github/workflows/check.yml) runs both host architectures, four `forms`
shards, three `shellfree` shards and four platform groups.
[test/ci-forms](../test/ci-forms) tests one form at a time, discards successful images,
and keeps logs, locks, native results and failed images. Platform boots share CPUs
within their memory budget; [test/ci-setup](../test/ci-setup) installs pinned tools.

Hosted arm64 lacks KVM: `vm-arm64` uses Ampere for all forms, then
`make check-platform` (the rest of `make check`), on pushes/maintainers' PRs.
`make check-native` attacks roots in `systemd-nspawn` ([test/cage](../test/cage)).

`make ci` uses a persistent 16 GiB KVM Lima VM; delete `werewolf-ci-24.04` to reset.
