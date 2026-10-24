# Live tests

These tests need the network, a cloud account or another host, so none is part of `make
check`, and CI holds no cloud credentials. Each takes a few minutes, and the cloud ones
cost a few cents.

## `make check-updater`

It runs a whole update ([updater.md](updater.md)). `prod` uses `DEV=1` to build its own
slot. [test/check-updater](../test/check-updater) boots slot a with a build record
claiming the preceding kernel release, without changing `build/`. After committing, it
finds the newer published kernel, fetches packages and CVE sources as `_update`, builds
slot b, installs it and reboots.

[test/update](../test/update) then reads the disk with `debugfs`: each CVE source listed
with a sha256 and no error, each apk cache intact, slot b's root owned by root with mode
0755, and the EFI entry allowing one try of b. It boots slot b, which must commit, and
the updater must record that the update held. No seccomp filter may have killed anything
in either boot. The consoles are in `build/<arch>/check/update-prod/`.

- `make check-updater-published` builds `test/published-form`, a form given
  by path on the published `prod`, and gives slot a an older-looking staged
  `prod`. Slot b must install `minimal-form` and `prod-form`, compose `prod`
  from the package rather than slot a's copy, and carry the local form's
  files forward ([design/custom-updates.md](design/custom-updates.md)). It
  passes once CI has published this tree's format and forms.
- `make check-updater-staged` cuts the power the moment slot b is staged.
  Slot b must boot all the same: a staged slot is armed
  ([design/update-policy.md](design/update-policy.md)).

It takes about 4 minutes with KVM or HVF, much longer under TCG.
[update.yml](../.github/workflows/update.yml) runs it nightly on x86_64, as a workflow
of its own, so a network flake fails only it.

## `make check-gcp`, `check-aws` and `check-azure`

Protected cloud deployment is currently blocked: AWS and GCP lack the completed provider
TPM bootstrap and permit transport, and Azure also lacks reliable firmware enforcement.
These checks must fail until those paths are implemented and validated; they never add
`--disable`. See [cloud TPM enrollment](design/cloud-tpm-enrollment.md) and [signed boot
status](cloud.md#signed-boot).

`make check-prod-ssh-clouds` runs all three providers with `--build` and then with
published downloads. A single provider defaults to `CLOUD_MODE=build`; use
`CLOUD_MODE=download` for its non-build path. Each case must pass independently.

[test/cloud](../test/cloud) runs `prod-ssh`'s disk, as a release makes it, on a real
cloud, as a user would. `howl create --on CLOUD` turns the disk into that cloud's image
(a GCP image, an AMI from an EBS snapshot written directly, an Azure managed disk) and
boots the smallest machine for the arch (`ARCH=aarch64` or `x86_64`) from it, with a
config holding a hostname and a software security key made for the run, and
`--allow-from me`, so werewolf opens the form's ports to this host alone. The test
judges the machine from the cloud's record of its serial port:

| Check | Passes when |
| --- | --- |
| `root-verified` | stage0 opened slot a's root through dm-verity |
| `secure-boot` | stage0 verified firmware enforcement outside setup mode |
| `tpm-authorization` | stage0 checked release authorization and protected reset authority |
| `ipe-enforced` | stage0 restricted execution to the verified root and removed policy administration |
| `metadata-config` | `cloud-metadata` took the config from that cloud's metadata server |
| `hostname` | posture names the host as the config did |
| `posture` | what fails is exactly what `prod-ssh`'s weaknesses say it fails |
| `ssh-login-t`, `ssh-login-root` | both accounts log in with the run's security key and report their own identities; `t` has a nonzero UID |
| `ssh-security-keys-only` | a plain key file is refused while the security-key logins still succeed |
| `reconfigure` | a second `create` of the name, with a new hostname, restarts the machine on it |
| `delete` | `howl delete` leaves nothing of the machine: instance, disk, network, security group, firewall rule |

However the run ends, it deletes everything it made, the image included; `CLOUD_KEEP=1`
keeps the machine. The serial log is kept in
`build/<arch>/prod-ssh/check/CLOUD-MODE-serial.log`; failed launches also retain
`CLOUD-MODE-create.log`. Each needs that cloud's CLI logged in:

- **GCP:** gcloud with a project (`GCP_PROJECT`, or gcloud's own); the zone
  is `us-central1-a` (`GCP_ZONE`).
- **AWS:** the aws CLI's region and credentials (`aws login` or `aws
  configure`, or `AWS_REGION` and `AWS_PROFILE`). Nothing needs setting up.
- **Azure:** az's default resource group (`az configure --defaults
  group=RG`, or `AZURE_DEFAULTS_GROUP`), in a location that offers the arch's
  size (`az vm list-skus -l LOCATION`; Arm sizes are in few regions).

## `make check-gcp-metadata`

[test/gcp-metadata](../test/gcp-metadata) builds this checkout's `prod-ssh` with
`machine.metadata-users: true`, creates a fresh GCP VM with the software security-key
provider from [test/keys](../test/keys), and changes its metadata as an operator would:
user-data at boot, instance and project keys, declared-user precedence, refusal of root
access, expired and malformed Google key records, expiry without a metadata edit,
project-key blocking and unblocking, account removal, root-key rotation, and keeping the
last accepted people after invalid user-data. Removing user-data must leave only
metadata people; restoring it must restore the declared people and root keys. The boot
id must not change.

It takes `GCP_PROJECT`, `GCP_ZONE` and `ARCH` as `check-gcp` does, and temporarily adds
its public test key to the project's `ssh-keys`, so use a test project; the account
needs project-metadata write permission as well. It deletes its VM, disk, firewall rule
and image (`CLOUD_KEEP=1` keeps them, with their test private keys). Logs are in
`build/check/gcp-metadata-*`.

## Firecracker

`make check-firecracker` boots the `sshd` form as a Firecracker microVM on
`FIRECRACKER_HOST` (default `galadriel`), a Linux host with KVM, Firecracker, mtools,
erofs-utils and passwordless `doas`. The tree, built for x86_64 here, is copied over
with a howl, a form tool and a verity tool cross-compiled for the host, so it needs no
toolchain; the host resolves a lock the copy does not match with `go install`'s apko, at
the version tools/install-deps pins. The form is sshd relaxed to take a key file the
host holds, and the ad-hoc generator declares the `network-ssh-security-keys` weakness
that costs. The machine must hand over to runit with its root verified, posture must
fail exactly what the form and test/posture-known allow, ssh must reach it through its
tap with the host's key, and delete must remove the machine. `FIRECRACKER_KEEP=1` leaves
it for a look.

## bhyve

Status, 2026-10-18: ARM64 on smaug is experimental, not qualified for unattended
deployment. Normal howl launches pass signed A/B recovery with the private runtime, but
a sustained TAP transfer test panicked in virtio TX. Secure Boot and TPM were off.
Earlier bilbo x86_64 results do not qualify ARM64, or vice versa.

`test/check-bhyve-lifecycle HOST ARCH DISK.zst KEY [tap|slirp] [SECONDS]` tests a fresh
copy of a prebuilt playground disk through howl's create/reconfigure, supervisor, stop
and delete paths. KEY and KEY.pub are a disposable SSH identity. The host needs
passwordless doas, firmware, zstd, and Python 3 for TAP; the builder needs Zig, zstd and
e2fsck. ARM64 needs legacy virtio PCI (kernel 7.2.11-r6 or later). TAP requires an
existing bridge; `BHYVE_BRIDGE` selects it. `BHYVE_TEST_IP` and `BHYVE_TEST_GW` select a
static test subnet instead of DHCP. The test does not create a bridge or change host
addressing, routes or firewall rules. Defaults are TAP and 180 seconds; SLIRP remains an
explicit option.

It checks the source disk, repeated 64 MiB SSH transfers, three guest reboots,
persistent checksums, stop/start and offline ext4 integrity after journal recovery.
Successful runs delete their remote directory; failed runs stop the VM and retain their
disk. Logs, phase records and snapshots are in `build/bhyve-validation/wwlife-*`. Never
share a writable disk between test VMs. A successful lifecycle run does not certify
Secure Boot, updates or long-term timekeeping; the initial guest clock must be within
300 seconds of the builder's clock.

Use `make check-ab-bhyve ARCH=aarch64 BHYVE_HOST=smaug AB_MODE=plain` for signed
updates, rollback and unhealthy-slot recovery (see [secure
tests](testing-secure-boot.md)). This test requires IPE and a correct guest clock; it
does not bypass TLS validation. The direct A/B harness defaults to SLIRP, unlike normal
howl. To test direct TAP, supply an existing `BHYVE_TAP=tapN`,
`BHYVE_TEST_IP=192.0.2.2/30` and `BHYVE_TEST_GW=192.0.2.1`; the caller owns its TAP,
bridge and cleanup. The fixture serves signed updates on guest loopback, so an isolated
bridge suffices. `BHYVE_BINARY=/absolute/remote/path/bhyve` tests a separate host
executable without replacing system bhyve. `BHYVE_ARM64_FIRMWARE` selects an absolute
remote path to a separate ARM64 firmware image. These overrides also work with normal
unprotected `howl create` launches on the FreeBSD host; they do not change the ARM64
Secure Boot refusal. FreeBSD 15.1's ARM RTC identification bug can leave the guest in
1970; upstream [corrected the ID register
offsets](https://github.com/freebsd/freebsd-src/commit/a554906ea44c26925730a25263e64890d48d2b36).
That fix restores the clock, but does not establish automatic update recovery. ARM64
U-Boot 2024.07's EFI file protocol refuses renames: the loader cannot consume the `+1`
boot attempt, so the deadman can reboot into the unhealthy slot again. Signed upgrades
and explicit rollback passing are not sufficient; require the unhealthy-slot recovery
phase to pass before relying on unattended updates. On smaug, a separate U-Boot 2025.07
build with the FreeBSD bhyve board support and `CONFIG_FAT_RENAME=y`, paired with the
RTC-fixed bhyve and TAP, passed the full plain A/B test through both direct and normal
howl launches: signed upgrade, explicit and persistent rollback, automatic 600-second
unhealthy-slot recovery, and failed-image retry refusal. This validates the workaround,
not the installed firmware or Secure Boot. System binaries were unchanged. Build
provenance and the latest A/B/soak evidence are in
`build/bhyve-validation/results-smaug-normal-runtime-20261018.json` (local artifacts,
not checked in).

For repeatable private builds and normal-launch testing, see the [pinned ARM64 runtime
recipe](../tools/bhyve-arm64/README.md). The longer normal-launch soak on smaug found a
separate blocker: after 286 verified 64 MiB transfers, virtio TX reported `id 255 is not
a head!`, followed by a soft-lockup panic around 12 minutes into the requested half-hour
test. It did not reach the planned reboot, stop/start or post-soak filesystem checks.
The failed VM was stopped, its disk retained, and test TAPs/bridge removed. Firmware
recovery success does not establish sustained network reliability. No root cause or
workaround for this TX failure has been established.
