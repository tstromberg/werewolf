# Builds on macOS

`howl run --build` builds a protected image and deploys it through Lima QEMU
on an arm64 Mac. Signing and TPM authority remain on the Mac. Builds honor
caller boot credentials; howl manages local credentials when none are supplied.
Published protected downloads remain gated while the
[publication design](design/published-secure-boot.md) is implemented.

## Why a Linux guest is needed

The IPE kernel and measured EFI stub use native Linux build tools and headers.
Melange runs those tools in a temporary Linux guest under QEMU on the Mac,
using a stock Alpine kernel and matching initramfs modules. This build guest
is separate from the protected Werewolf guest that Lima deploys.
Ubuntu is not required for the default build path.

Only explicitly staged public sources, base archives and the public IPE
certificate enter the builder. Private policy, boot, permit and reset
credentials stay on the Mac. A separate temporary module signer is generated
inside the builder and deleted after compilation.

The recipes are [ipe-kernel.melange.yaml](../boot/ipe-kernel.melange.yaml) and
[tpm-stub.melange.yaml](../boot/tpm-stub.melange.yaml).
[local-prerequisites](../tools/local-prerequisites) stages their inputs and
caches the resulting artifacts. Cache identities bind the architecture,
Alpine base, public signer, sources and builder bytes; completion hashes
reject altered or incomplete artifacts.

Kernel and stub caches are independent. Changing the stub recipe reuses the
kernel; changing the public IPE certificate reuses the stub. Completed older
combined caches are adopted without recompilation. A failed stub build keeps
the completed kernel. Builder sources are written only when their bytes change.

An unchanged `howl run --build` reuses the running protected machine without
building, signing or rebooting. It checks image inputs, caller credentials,
configuration, guest source bytes and provider, and preserves signing keys and TPM state.
A stopped machine resumes its existing image; changed configuration updates
only its config disk. `howl stop` keeps protected disks and authority;
`howl delete` explicitly removes a machine for a fresh run.
Application builds currently use the existing replacement path.

GCC 15.2 is pinned to match the Alpine kernel configuration. A rolling GCC 16
build crashed on Alpine's latent-entropy plugin; retain the plugin and use
the compatible compiler rather than disabling kernel hardening.

## Firmware enrollment on the Mac

[native-firmware](../tools/native-firmware) verifies the firmware package and
extracted code/template hashes, then installs native enrollment tools in a
private Python environment. [firmware-requirements.txt](../boot/firmware-requirements.txt)
pins dependency versions and hashes; installation requires binary wheels.
The unused Linux cloud-password dependency is excluded.

Enrollment uses a machine owner certificate in PK/KEK and the caller's code
certificate in db. Bundled default certificates
and sample private keys are not extracted. The tested maintained firmware
package is selected independently of the compiler guest's distribution.
Ubuntu 26.04 firmware enrolled successfully but failed the protected boot
probe; it is not a validated replacement. Missing or invalid protected
firmware refuses startup.

## Optional persistent Lima builder

`WEREWOLF_BUILD_VM` explicitly selects an isolated native arm64 Linux Lima
builder instead of Melange's temporary QEMU guest.
[build-helper](../tools/build-helper) creates it from
[build-helper.yaml](../boot/build-helper.yaml) when absent and starts it when
stopped, then verifies that it is running before executing build commands.
The helper rejects host mounts and SSH forwarding. No pre-existing Ubuntu
VM is required. Its Ubuntu version does not select the enrolled firmware.

## Validation

[local-prerequisites tests](../test/local-prerequisites) cover public staging,
private-input exclusion and cache integrity. [builder tests](../test/build-helper)
cover creation, restart and unsafe configuration rejection.
[firmware tests](../test/native-firmware) cover package authentication,
component corruption, symlinks and unsupported architectures.
The opt-in [run-cache test](../test/check-run-cache) requires an isolated checkout
and measures actual Lima repeat runs and resume. It rejects repeated builders,
guest restarts on unchanged runs and changes to signing or TPM authority.
It also checks host publisher recovery without rebuilding or restarting the guest.

Kernel/stub compilation through Melange QEMU and native firmware enrollment
have passed on this arm64 Mac; enrollment was exercised with Python 3.9 and
3.14. Complete deployment and A/B validation are separate gates: see
[testing](testing.md) and the [local deployment design](design/secure-local-deployment.md).
Compiler success alone does not establish a protected guest lifecycle.

The arm64 Lima run-cache test passed live reuse, host publisher recovery and
retained-authority resume. Warm repeats measured 0.93–1.30 seconds; the first
repeat took 6.16 seconds. Resume took 17.15 seconds, including VM boot.
No repeat or resume invoked builders; live reuse preserved the boot ID.
Timings vary with host load and filesystem caches, so the test checks repeated
work and authority preservation rather than a fragile wall-clock threshold.
Public evidence: `build/ipe-check/secure-lima/run-cache-verified/`.
