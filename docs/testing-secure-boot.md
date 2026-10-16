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
`tools/build-tpm-stub OUT` builds the measured one on Linux, with no key.
[test/check-boot-authority](../test/check-boot-authority) boots a signed
probe against real EFI variables: valid enrollment, a foreign PK, KEK or db,
extra db trust and setup mode, for `--tpm-firmware` builds, whose machine
authority is the firmware's PK.

## Provider A/B upgrades and rollbacks

`make IPE=1 check-ab-PROVIDER` builds three disposable signed releases and drives the
real updater over confined loopback HTTPS: upgrade A→B, a health commit, operator
rollback B→A, another boot of A, then automatic recovery from an unhealthy signed
candidate after 600 seconds, after which the updater must refuse that build again. Every
boot must have a fresh boot id, the expected signed root hash, read-only dm-verity and
enforcing IPE; where the firmware enforces, SecureBoot=1 and SetupMode=0. Logs and
`phases.json` are under `CHECK/provider-ab-PROVIDER`, and only what the test made is
removed. `AB_FIXTURE` reuses a fixture of the same architecture and mode, `IPE_KERNEL`
an existing kernel archive ([test/check-provider-ab](../test/check-provider-ab),
[design/provider-ab-tests.md](design/provider-ab-tests.md)).

| Target | Mode | Needs |
|---|---|---|
| `check-ab-qemu` | Secure Boot | QEMU and enrollment tools; CI runs both architectures |
| `check-ab-lima-qemu` | Secure Boot | arm64 Mac; explicit debug firmware arguments |
| `check-ab-lima-vz` | signed updates | arm64 Mac; `AB_MODE=plain` |
| `check-ab-aws`, `check-ab-gcp` | Secure Boot | a logged-in cloud CLI; optional `CLOUD_SIZE`, `GCP_PROJECT`, `GCP_ZONE` |
| `check-ab-azure` | Secure Boot | a logged-in az; a temporary group in West US 2 by default |
| `check-ab-bhyve` | signed updates | x86_64; `BHYVE_HOST=bilbo`, passwordless `doas`, bhyve firmware and mtools |
| `check-ab-firecracker` | signed updates | x86_64; `FIRECRACKER_HOST=galadriel`, KVM and passwordless `doas` |
| `check-ab-proxmox` | signed updates | untested; `PROXMOX_HOST`, optional `PROXMOX_STORAGE` and `PROXMOX_BRIDGE` |

Lima VZ, Firecracker, bhyve and Proxmox default to `AB_MODE=plain`: signed
updates, with no firmware to enforce them. bhyve also takes `AB_MODE=secure`
with `SECUREBOOT_DIR` holding its `code.fd` and `vars.fd`, and `make
check-bhyve-secureboot AB_FIXTURE=...` checks that it refuses a tampered
UKI; howl does not enroll bhyve itself yet, and supports it on x86_64 only.
On 2026-10-12 every target passed but two: Azure's firmware reported
SecureBoot=1 with SetupMode=1 and was blocked before handover, a failing
deployment rather than a passing recovery, and Proxmox has no node
([audit](audit/astra-2026-10-11.md#provider-ab-follow-up-2026-10-12)). The
cloud targets make billable resources: use test credentials.

## TPM

A TPM records which releases may boot, so an older signed release cannot be
booted again ([design/tpm-ab-retirement.md](design/tpm-ab-retirement.md)).
The protocol is tested on the host, against swtpm, before any guest is:

- [test/check-tpm-policy](../test/check-tpm-policy) (Linux, swtpm and
  tpm2-tools) tests signed monotonic NV writes, replay, altered data,
  undefine and hierarchy-reset refusal; `TPM_POLICY_PROBE=build/host/tpm-policy`
  runs werewolf's own TPM commands through it.
- `python3 test/check-tpm-ab` tests the exact-pair replacement protocol
  with real TPM commands: both members, operator rollback, wrong, zero and
  changed PCRs, replayed state, altered signatures, direct writes, index
  removal, hierarchy resets, weaker provisioning, and eleven boundary models
  with simulator restarts, one a dropped `NV_Extend` reply, after which
  recovery reads the anchor and refuses a blind retry.
- `python3 test/check-tpm-enrollment` tests native enrollment against swtpm
  on macOS or Linux: private file modes, repeat refusal, restart, supervisor
  crash recovery and cleanup.

`make IPE=1 check-tpm-guest` builds disposable TPM-gated releases and boots
QEMU with persistent swtpm state (`swtpm`, `tpm2-tools`, `systemd-boot-efi`,
and a TPM-enabled `UKI_STUB`: Alpine's stub does not measure, and a
mandatory boot refuses a zero PCR 11). It checks the signed identity, exact
root, predicted PCRs and posture, then commit, operator rollback, failed
trials and power cuts around the NV extension, killing VM and simulator
while keeping disk, variables and NV; then it restores retired A, installs a
signed but unmeasured UKI and removes the TPM, each of which stage0 must
refuse. Only logs and `evidence.jsonl` are kept. The build takes
`--tpm-pub` (or `WEREWOLF_TPM_PUB`) and `WEREWOLF_BOOT_STATE`, the signed
factory pair, and `tools/tpm-enroll` initialises a host-controlled TPM.

Enrollment from a cloud is tested without deploying one. `test/cloud-enrollment`
checks SDK replies and the immutable AWS and GCP TPM identity pins, and
`python3 test/check-cloud-tpm-activation`, with `build/host/tpm-bootstrap`
and `tpm-policy` built, checks quotes, publisher-signed encrypted capsules,
provisioning, tamper and replay against fresh simulators
([design/cloud-tpm-enrollment.md](design/cloud-tpm-enrollment.md),
[design/tpm-bootstrap-protocol.md](design/tpm-bootstrap-protocol.md)).
`make IPE=1 check-tpm-bootstrap-guest` boots the separate signed enrollment
UKI, whose agent runs alone as PID 1 over a bounded virtio channel: PCR and
EK binding, encrypted provisioning, protected readback and reboot must
hold; wrong machines or PCRs, foreign signatures, invalid AEAD, unsigned or
oversized capsules, replay, unmeasured images, absent TPMs, tampered UKIs
and setup mode must refuse. It also cuts the power at the owner-auth,
NV-definition and NV-extension boundaries and boots a measured recovery
image; `make check-tpm-recovery` tests all twelve provisioning boundaries
on macOS or Linux, keeping only public manifests, quotes and logs.

## Local deployment and publication

`howl run --build` is the protected path: an arm64 Lima QEMU guest on macOS, protected
QEMU on Linux, with host-managed enrollment, HTTPS image publication and permits
([design/secure-local-deployment.md](design/secure-local-deployment.md)). `make
check-secure-lima` and, on Linux, `make check-secure-qemu` drive it: creation, several
signed updates, operator rollback, restart with the same NV authorization, kills of VM
and simulator around NV extension, resume of a completed update, and an unhealthy
counted trial recovering its predecessor; PCR 11 must match the booted release's
prediction, and writable-code execution, verified-root writes and reauthorizing retired
history must be refused. `make check-run-cache` (macOS, an isolated checkout) measures
repeat runs and resume, refusing repeated builders, changed boot ids and replaced
authority; `make check-shared-boot` (arm64 Lima) seals one vendor artifact, withholds
the vendor keys and enrolls two machines, which must share code and PCRs with distinct
owner keys, nonces and anchors ([design/boot-images.md](design/boot-images.md)).
[test/check-published-lifecycle](../test/check-published-lifecycle) runs the
production-signed playground bundles under isolated Lima enrollments with no source tree
or vendor keys, and emits publication gates only when every check passes.

The host-side pieces have suites of their own, run by `make test`,
`_test/local-publisher` and
[protected-images.yml](../.github/workflows/protected-images.yml):
`test/local-prerequisites` (cache tampering, incomplete publication, signer custody,
kernel and stub invalidation, interrupted builds), `test/boot-images` and
`test/boot-download` (admission: foreign and altered signatures, weak profiles,
unknown fields, size bounds, torn heads, replay, equivocation),
`test/protected-release` and `test/protected-publication` (signing custody, ordered
uploads, interruption recovery, immutable collisions, release floors), and the
[machine-transport](design/machine-transport.md) tests, which reject foreign machines,
endpoints, signers and every single-byte mutation. Candidate CI has no publication
permission ([design/protected-downloads.md](design/protected-downloads.md)).

To test an unpublished kernel, set `KERNEL_ROOTFS=/path/to/rootfs.tar` on `make`
with a separate `BUILD` directory. This accepts the archive from `tools/test-kernel`,
checks its configuration, and requires IPE explicitly disabled. For strict IPE testing,
use `IPE=1` and its three signing inputs instead. JIT forms can thus exercise the same
candidate kernel through their normal profile without changing strict IPE policy.
