# Testing

To test one form from the checkout root:

```sh
howl test --with caddy
howl test --with caddy --arch x86_64
```

Most forms run `make -k check-FORM check-shellfree-FORM`: integration tests in a DEV VM,
then posture and console checks of the shipping form. Forms with `test/tests.yaml`,
such as `postgresql`, instead run compiled Zig drivers under leash as service clients,
without shell or SSH ([driver guide](testing-native.md)). A generated form pins the
production package closure and is
compared with production before boot ([design](design/image-release-testing.md)).
Image publishing requires further checks ([form-images.md](form-images.md)).
[Local iteration](design/local-test-iteration.md) keeps the VM running between changes.
Checks boot their kernels directly, so they build without Secure Boot, the TPM and,
unless `IPE=1`, IPE, and name them in `--disable` (the Makefile's `CHECK_DISABLE`);
`check-secureboot`, `check-tpm-floor`, `check-ipe` and the release gates test those.

PostgreSQL tests SQL, shim redirects, no TCP and encrypted-disk persistence.
[Greenbone](../forms/greenbone/README.md#testing-status) covers GMP/OSP, database roles,
Valkey ACLs, mounts and persistence; `legacy: true` retains DEV checks.
Logs: `build/ARCH/check/FORM-native/`. Protected lifecycle evidence is separate.

For driver edits, [iteration](design/local-test-iteration.md) keeps a disposable VM
running and replaces only the selected driver. Native drivers default to 128 MiB;
`memory` (16–8192 MiB) sizes their test cgroup.
An optional driver `allow` list permits `python:native`, `node:native` or
`java:native` in that driver's runtime namespace. Production grants stay unchanged;
the payload comparison rejects blanket grants and undeclared files.
Iteration uses SSH with `sh-shim`, without BusyBox. It is not release evidence.
Run the plain command after editing. `KERNEL_ROOTFS=/path/rootfs.tar` tests a candidate
kernel; changing its bytes resets the VM. This profile explicitly disables IPE.

```sh
make test           # every program's and library's unit tests, in seconds
make -j check       # boot every form, and a slot, side by side, and check each
make check-FORM     # one form; check-shellfree-FORM boots it as it ships
make check-posture  # concurrent scans, stale probes and fresh audit evidence
make check-dns      # Linux: resolver, DHCP and TLS fixtures in private namespaces
make form-coverage  # each form's integration cases
```

[Live tests](testing-live.md) cover network, cloud and remote hosts; see
[secure boot tests](testing-secure-boot.md) for Secure Boot, TPM and signed updates.

`make check` also needs QEMU, `expect` and `mke2fs` (`brew install qemu e2fsprogs` on
macOS); tutorials need Go, rustup with Linux musl targets, .NET 10 and a JDK.
`make check-dns` needs root or subordinate ids.

## What `make check` does

It boots every form and a slot with native EFI under QEMU. Passing requires a successful
boot, expected [checks](../test/checks) as root, and a clean shutdown.

Legacy checks add mksh, BusyBox tools and developer SSH with `DEV=1`. Shipping-image
checks (`check-shellfree-<form>`) use [test/boot](../test/boot) to judge posture and
expected console output (`forms/<form>/test/console`) without running guest commands.

Checks attack lockdown, memory access, one-way sysctls, setuid, undeclared listeners,
execution from `/tmp`, and `nobody` writing `/run`, seeing others' processes or planting
links. Declared ports must listen and answer their protocol; form-specific checks and
configuration live in `forms/FORM/test/`. Boot must have no unexpected refusals.

`make check-people-persist` (also in `check-cloud`) tests enrollment, retirement,
conflicting people/NoCloud requests and reactivation on one persistent volume. It checks
private files and refuses corrupt or missing reservation tables before services start.
Logs: `build/ARCH/check/people-persist/`. Seeds need `xorriso` (Linux) or `hdiutil`
(Mac).

`make check-privilege-boundaries` tests real SSH credentials, inherited descriptors,
cross-user files, PTYs, forwarding refusal, concurrent sessions, SFTP, daemon restart
and kernel restrictions in a disposable protected `playground` Lima VM. Secure Boot,
TPM and IPE stay enabled. Logs/profile: `build/security-probes/`; `werewolf-run` stays.

`make check-mount-broker LINUX_TEST_RUNNER=sudo` tests the confined broker's roles,
malformed requests, stalled readers and staged-file integrity in a Linux mount
namespace. CI runs it beside updater construction tests; macOS can use
`LINUX_TEST_RUNNER='limactl shell VM sudo -n'` with a VM that mounts the checkout.
`make fuzz-broker` fuzzes its wire parser.

Other boots cover what one boot cannot:

| Boot | Must | Where |
| --- | --- | --- |
| again (the Makefile's `AGAIN_FORMS`; `all` for every form) | come back on the disk the first boot left: `/data` opened, not formatted, its mark kept | [test/checks-again](../test/checks-again); a form's `test/checks-again` and `test/config-again` |
| `prod` with no key | refuse its LUKS2 disk, mount an empty read-only tmpfs, say why in `/run/werewolf/nodata` | [test/checks-nodata](../test/checks-nodata) |
| `minimal` with one root byte changed (`check-verity`) | dm-verity names the block; stage0 stops before the root is mounted | `root-verified` in test/checks, for every other boot |
| a slot that never commits (`check-deadman`) | the deadman says why and resets the machine | `werewolf.deadman`, honoured by DEV builds only |
| `prod` behind a stand-in metadata server, as each cloud | take a good config on GCP, AWS (by session token only), Hetzner and Azure; refuse a tar with a link or `../`; ask nothing on no cloud or on Hyper-V | [test/metadata.zig](../test/metadata.zig), [test/cloud-boot](../test/cloud-boot) |
| `prod` with no address; `minimal` with a packed one (`check-static`) | take it from DHCP, the client split as it claims; or from `howl pack --ip --gw --dns` | [test/checks-lease](../test/checks-lease), [test/checks-static](../test/checks-static) |
| the slot | find `root.erofs` by UUID, keep `/boot` read-only, commit its EFI entry once healthy for a minute | a 128 MiB ext4 and a FAT EFI partition with one counted entry |
| each legacy release disk and direct image | boot without Secure Boot or a TPM, judging the exact form's posture | [test/check-legacy-image.zig](../test/check-legacy-image.zig); the shared image workflow |

Each machine gets blank/config disks, a fixed test LUKS2 key and distinct forwarded
ports (22200 and 23200 plus its form index), so `make -j` can run them together.
test/boot waits for bounded events; logs stay in `build/<arch>/check/`.

## Form integration coverage

A service/application form needs five distinct cases through its running service:
read/write, authentication, refusals, configured content or reboot persistence. Name
each behaviour; assertions about one operation count once, and shared boot/posture
checks do not count. `make test` enforces this
([form-coverage](../tools/form-coverage.zig)); `make form-coverage` lists cases, and
[exceptions](../test/form-coverage-exceptions) explain shared suites. Review judges
quality. `make check-apps` tests HTTP for `-app` forms and `php` using
[test/app-fixtures](../test/app-fixtures).

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

A FAIL reports the last progress line, the first kernel error (stall, blocked task,
panic) and host details: kernel, QEMU, accelerator, CPUs and load. Check boots panic on
a CPU stalled for 20 s or a task blocked for two minutes, reporting the kernel's reason.
An unresponsive machine dumps every virtual CPU's state into its log before failing.

```sh
make check-one FORM=playground REPEAT=20             # how often does it fail?
make check-one FORM=playground REPEAT=20 ACCEL=tcg   # without the hypervisor
BOOT_TIMEOUT=20 make check-minimal                   # see a hang sooner
```

`check-one` keeps each failing boot's console as `FORM-one-N.log`. Every boot prints
where its time went, `werewolf: up in 1.470s (the kernel 0.225s, userland 1.245s)`,
phase by phase (kernel, disk, slot, root, init's steps, seal), and keeps it in
`/run/werewolf/boot`. The console shows only warnings and worse (`loglevel=5`); `dmesg`
keeps every line.

## CI

[check.yml](../.github/workflows/check.yml) runs host tests on both architectures, four
`forms` shards, three `shellfree` shards and four platform groups.
[ci-forms](../test/ci-forms.zig) checks forms serially, cleaning successful images
and retaining failures, logs, locks and native results. Platform boots share CPUs within
a memory budget; [ci-setup](../test/ci-setup) installs pinned tools.

Hosted arm64 lacks KVM: `vm-arm64` uses Ampere for all forms, then
`make check-platform` (the rest of `make check`), on pushes/maintainers' PRs.
`make check-native` attacks roots in `systemd-nspawn` ([test/cage](../test/cage)).

`make ci` copies fresh source (no `config/` or `.git`) into a 16 GiB Lima VM with KVM.
VM and caches persist; `limactl delete -f werewolf-ci-24.04` starts over.
