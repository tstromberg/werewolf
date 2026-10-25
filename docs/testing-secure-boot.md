# Secure Boot, TPM and signed-update tests

These suites prove the protections that reach across reboots: Secure Boot
on the boot files, a TPM that records which releases may boot, and IPE,
which runs only native code from the verified root
([security.md](security.md)). Most take `IPE=1`, which needs a test kernel
whose IPE trusts a disposable certificate: `make ipe-kernel` builds one with
`tools/test-kernel`, from kernel-build at the commit `boot/kernel-build` pins,
howl makes and caches one where none is given, and `WEREWOLF_IPE_KEY` and
`WEREWOLF_IPE_CRT` name its signer
([design/ipe.md](design/ipe.md), [macos-builds.md](macos-builds.md)). CI
runs them with disposable keys on both architectures. Private signers stay
on the host and never enter a guest or a build VM.

## IPE

`make IPE=1 check-ipe` boots the real image and tests global execution and
executable mappings with Landlock, seccomp and noexec out of the way, and
refuses missing, tampered, wrong-signer and wrong-root policies before
handover. `make IPE=1 check-image-updater` runs signed HTTPS slot updates
under IPE: rejection before any write, then reboot and commit
([design/prebuilt-images.md](design/prebuilt-images.md)). On accelerated
arm64, `make IPE=1 check-updater-uki` keeps one disk through firmware boot,
signed UKI delivery, a verified slot b and its commit, with IPE still
enforcing; it rejects unsigned, altered and wrong-key loaders and UKIs, an
unexpected UKI path and a setup-mode boot, and unsigned loader options
cannot change the slot or disable IPE.

## Secure Boot

`make check-secureboot` builds a signed release disk, checks
its UKI and certificate against the manifest and the ESP, and boots it under
enrolled firmware: the native slot must boot, the root verify and posture
pass, and a changed UKI must be refused. It runs on both architectures,
emulated too. On an arm64 Mac, `make check-lima-secureboot` proves the
signed release under Lima's QEMU backend, through Lima's debug QEMU
arguments, and checks that the VZ engine refuses the Secure Boot
requirement it cannot meet. Firecracker has no UEFI firmware at all.

Linux needs `python3-virt-firmware`, OVMF and `qemu-efi-aarch64`; on macOS
[tools/enroll-boot](../tools/enroll-boot) uses hash-pinned firmware and the
Mac's own Python. `SECUREBOOT_DIR` may supply `code.fd` and `vars.fd`; the
pinned systemd stubs are `out/tools/stubs/ARCH/linux.efi.stub`, and
`tools/build-tpm-stub OUT` builds the one protected images use, on Linux, with no
key.

## Provider A/B upgrades and rollbacks

`make IPE=1 check-ab-PROVIDER` builds three disposable signed releases and drives the
real updater over confined loopback HTTPS: upgrade A→B, a health commit, operator
rollback B→A, another boot of A, then automatic recovery from an unhealthy signed
candidate after 600 seconds, after which the updater must refuse that build again. Every
boot must have a fresh boot id, the expected signed root hash, read-only dm-verity and
enforcing IPE; where the firmware enforces, SecureBoot=1 and SetupMode=0. Logs and
`phases.json` are under `CHECK/provider-ab-PROVIDER`, and only what the test made is
removed. `AB_FIXTURE` reuses a fixture of the same architecture and mode, `IPE_KERNEL`
an existing kernel archive ([test/check-provider-ab.zig](../test/check-provider-ab.zig),
[design/provider-ab-tests.md](design/provider-ab-tests.md)).

| Target | Mode | Needs |
|---|---|---|
| `check-ab-qemu` | Secure Boot | QEMU and enrollment tools; CI runs both architectures |
| `check-ab-lima-qemu` | Secure Boot | arm64 Mac; explicit debug firmware arguments |
| `check-ab-lima-vz` | signed updates | arm64 Mac; `AB_MODE=plain` |
| `check-ab-aws`, `check-ab-gcp` | Secure Boot | a logged-in cloud CLI; optional `CLOUD_SIZE`, `GCP_PROJECT`, `GCP_ZONE` |
| `check-ab-azure` | Secure Boot | a logged-in az; a temporary group in West US 2 by default |
| `check-ab-bhyve` | signed updates | `BHYVE_HOST=bilbo` (x86_64) or `smaug` (aarch64); passwordless `doas`, loaded vmm, firmware; libslirp only for SLIRP, or [TAP setup](testing-live.md#bhyve) |
| `check-ab-firecracker` | signed updates | x86_64; `FIRECRACKER_HOST=galadriel`, KVM and passwordless `doas` |
| `check-ab-proxmox` | signed updates | untested; `PROXMOX_HOST`, optional `PROXMOX_STORAGE` and `PROXMOX_BRIDGE` |

Lima VZ, Firecracker, bhyve and Proxmox default to `AB_MODE=plain`: signed
updates without Secure Boot enforcement. bhyve also takes `AB_MODE=secure`
with `SECUREBOOT_DIR` holding its `code.fd` and `vars.fd`, and `make
check-bhyve-secureboot AB_FIXTURE=...` checks that it refuses a tampered
UKI; bhyve Secure Boot testing remains x86_64-only. ARM64 uses U-Boot and plain
mode; passing it requires the same IPE, signed-update and rollback assertions.
On 2026-10-18 smaug passed with the private RTC/firmware fixes through normal howl
launches, but a longer TAP soak panicked in virtio TX. Secure Boot and TPM were off;
see [current limits and evidence](testing-live.md#bhyve), not a reliability guarantee.
On 2026-10-12 every target (bhyve: x86_64 only) passed but two: Azure reported
SecureBoot=1 with SetupMode=1 and was blocked before handover, a failing
deployment rather than a passing recovery, and Proxmox has no node
([audit](audit/astra-2026-10-11.md#provider-ab-follow-up-2026-10-12)). The
cloud targets make billable resources: use test credentials.

## TPM

Each release channel has one TPM counter, its floor, and a release boots only if its
index reaches it ([design/independent-updates.md](design/independent-updates.md)). `make
check-tpm-floor`, also part of `make test` as `_test/tpm-floor`, runs
[test/check-tpm-floor.zig](../test/check-tpm-floor.zig) against swtpm with
`build/host/tpm-floor`, which drives lib/tpm.zig's code as stage0 and the mount broker
do. A fresh TPM must enroll at the release's index, and an enrollment cut after each
step must complete on the next boot. Then raw commands play guest root: undefining,
redefining, writing, locking or re-passwording the counter, clearing the TPM or
re-enabling clear, reopening the platform hierarchy and emptying the owner or lockout
password must all fail, and incrementing must work. A release below the floor, another
channel's release, a TPM someone else owns, an owner policy and a different counter at
the handle must be refused.

## Local deployment and publication

`howl run --build` is the protected path: an arm64 Lima QEMU guest on macOS, protected
QEMU on Linux ([design/secure-local-deployment.md](design/secure-local-deployment.md)).
`make check-independent-updates` (Lima on macOS, `PROVIDER=qemu` on Linux) runs
[test/check-independent-updates.zig](../test/check-independent-updates.zig): `howl
create --build` makes release A (index 1) of a channel the test serves as static
HTTPS files under a private CA, and boots it under Secure Boot, IPE and a fresh TPM,
which it must enroll at floor 1. A root session must not open the TPM, and IPE must
refuse code outside the verified root. The machine's own updater then installs B and
C from the channel; operator rollback to the retained release, a power cut before and
after the floor's increment, a restored disk holding retired A (stage0 must refuse
it, the TPM kept) and a failed trial that falls back with the floor unchanged follow.
No host service but the file server takes part.
[test/check-published-lifecycle](../test/check-published-lifecycle.zig) runs one
production-signed candidate through a consumer's own download, with no source tree or
vendor keys, and emits publication gates only when every check passes and so did this
check's evidence, made on disposable keys from the same tree.

The host-side pieces have suites of their own, run by `make test` and
[protected-images.yml](../.github/workflows/protected-images.yml):
lib/security-inputs.zig's tests (cache tampering, incomplete publication, signer
custody, kernel and stub invalidation, interrupted builds), the tests of
cmd/howl/boot-image.zig, cmd/howl/download.zig and lib/boot-download.zig (admission:
foreign and altered signatures, weak profiles, unknown fields, release identity, size
bounds, HTTPS bounds and redirects, torn heads, replay, equivocation), and
tools/release's tests (`make _test/tools/release/release.zig`: signing custody, ordered
uploads, interruption recovery, immutable collisions, release floors, an index that
does not advance). Candidate CI has no publication permission
([design/protected-downloads.md](design/protected-downloads.md)).

To test an unpublished kernel, set `KERNEL_ROOTFS=/path/to/rootfs.tar` on `make`
with a separate `BUILD` directory. This accepts the archive from `tools/test-kernel`,
checks its configuration, and requires IPE explicitly disabled. For strict IPE testing,
use `IPE=1` and its three signing inputs instead. JIT forms can thus exercise the same
candidate kernel through their normal profile without changing strict IPE policy.
