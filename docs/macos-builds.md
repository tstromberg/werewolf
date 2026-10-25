# Builds on macOS

`howl run --build` builds a protected image and deploys it through Lima QEMU on an arm64
Mac. Signing keys remain on the Mac. Builds honor caller boot credentials; howl manages
local credentials when none are supplied. Plain `howl run` downloads a protected image
with embedded production trust. Targets remain unavailable until their signed artifacts
pass the [publication gates](design/protected-downloads.md); there is no implicit source
build. The downloader identifies Werewolf to the mirror. Stock macOS Python uses system
curl for modern TLS, with certificate verification and bounded, authenticated downloads.

## Why a Linux guest is needed

The EFI stub, and the test kernels IPE tests boot, use native Linux build tools and
headers. Melange runs those tools in a temporary Linux guest under QEMU on the Mac. Its
kernel is Alpine's `linux-virt`, as melange's initramfs loads 9p and overlayfs as
modules, which werewolf's kernel lacks: howl makes it from
[melange-guest.yaml](../boot/melange-guest.yaml) as
`build/vendor/melange-guest-ARCH.{vmlinuz,cpio}` (`guest()` in cmd/howl/melange.zig). It
only builds; no Werewolf image boots it, and it is separate from the protected Werewolf
guest that Lima deploys. Ubuntu is not required for the default build path.

Only explicitly staged public sources and the public IPE certificate enter the builder.
Private policy and boot keys stay on the Mac. Protected builds use the published
`linux-werewolf`, whose IPE trusts the protected image certificate, installed by apko
from [kernel.yaml](../boot/kernel.yaml); they build only the stub. The kernel has no
modules, so nothing is signed for it.

The stub's recipe is [tpm-stub.melange.yaml](../boot/tpm-stub.melange.yaml).
[local-prerequisites](../tools/local-prerequisites) stages its inputs, builds a test
kernel with [test-kernel](../tools/test-kernel) for a disposable certificate, and
caches both. Cache identities bind the architecture, the certificate, sources and
builder bytes; completion hashes reject altered or incomplete artifacts.

Kernel and stub caches are independent. Changing the stub recipe reuses the
kernel; changing the certificate or the kernel-build commit
[kernel-build](../boot/kernel-build) pins reuses the stub. A failed stub build keeps
the completed kernel. Builder sources are written only when their bytes change.

An unchanged `howl run --build` reuses the running protected machine without building,
signing or rebooting. It checks image inputs, caller credentials, configuration, guest
source bytes and provider, and preserves signing keys and TPM state. Changed inputs
reinstall `howl run`'s machine; a named machine keeps the image it was made with, since
an image signed with your keys takes changes by reinstalling unless its builder serves
a channel ([local deployment](design/secure-local-deployment.md)). A stopped machine
resumes its existing image; changed configuration updates only its config disk. `howl
stop` keeps protected disks and TPM state; `howl delete` explicitly removes a machine
for a fresh run.

kernel-build compiles the kernel with Wolfi's pinned Clang 22. On macOS,
`make ipe-kernel` (with `WEREWOLF_IPE_CRT`) needs `QEMU_KERNEL_IMAGE` and
`QEMU_BASE_INITRAMFS` naming the guest above. Linux managed builds use the same
Melange recipes under bubblewrap.

## Firmware enrollment on the Mac

[native-firmware](../tools/native-firmware) verifies the firmware package and extracted
code/template hashes, then installs native enrollment tools in a private Python
environment. [firmware-requirements.txt](../boot/firmware-requirements.txt) pins
dependency versions and hashes; installation requires binary wheels. The unused Linux
cloud-password dependency is excluded.
The pinned tools use Python 3.10-3.14 (`make install-deps` installs Python 3.14).
Enrollment selects a compatible installed interpreter when the host default is
outside that range.

Enrollment puts the image's boot certificate in PK, KEK and db, and nothing else.
Bundled default certificates and sample private keys are not extracted. The tested
maintained firmware package is selected independently of the compiler guest's
distribution. Ubuntu 26.04 firmware enrolled successfully but failed the protected boot
probe; it is not a validated replacement. Missing or invalid protected firmware refuses
startup.

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
private-input exclusion and cache integrity. [builder tests](../test/build-helper) cover
creation, restart and unsafe configuration rejection. [firmware
tests](../test/native-firmware) cover package authentication, component corruption,
symlinks and unsupported architectures. `make check-independent-updates` deploys and
updates a protected Lima machine ([live tests](testing-live.md)). kernel-build's CI
boots each kernel with its probe before publishing it.

Stub compilation through Melange QEMU and native firmware enrollment have passed
on this arm64 Mac; the current enrollment dependencies require Python 3.10+. Complete
deployment and A/B validation are separate gates: see [testing](testing.md) and the
[local deployment design](design/secure-local-deployment.md). Compiler success alone
does not establish a protected guest lifecycle.
