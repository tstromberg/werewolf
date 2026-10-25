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

- `make check-updater-published` builds `test/published-form`, a form given by path on
  the published `prod`, and gives slot a an older-looking staged `prod`. Slot b must
  install `minimal-form` and `prod-form`, compose `prod` from the package rather than
  slot a's copy, and carry the local form's files forward
  ([design/custom-updates.md](design/custom-updates.md)). It passes once CI has
  published this tree's format and forms.
- `make check-updater-staged` cuts the power the moment slot b is staged. Slot b must
  boot all the same: a staged slot is armed
  ([design/update-policy.md](design/update-policy.md)).

It takes about 4 minutes with KVM or HVF, much longer under TCG.
[update.yml](../.github/workflows/update.yml) runs it nightly on x86_64, as a workflow
of its own, so a network flake fails only it.

## `make check-gcp`, `check-aws` and `check-azure`

[test/cloud](../test/cloud) deploys `prod-ssh` with every protection, as a user would:
`howl create --on CLOUD --build` builds it with your keys, makes the disk that cloud's
image (GCP image, AMI from an EBS snapshot, Azure specialized gallery image) with its
boot certificate as PK, KEK and db, and boots the smallest `ARCH` machine under Secure
Boot with a vTPM its first boot takes. `IMAGE_INDEX`, `IPE_UPDATES` and
`WEREWOLF_DISK_ARGS` (kernel arguments, for diagnosis) apply; `check-prod-ssh-clouds`
runs all three. The config holds a hostname and a security key made for the run;
`--allow-from me` opens the form's ports to this host alone. The checks:

| Check | Passes when |
| --- | --- |
| `root-verified` | stage0 opened slot a's root through dm-verity |
| `secure-boot` | stage0 verified firmware enforcement outside setup mode |
| `firmware-trust` | stage0 found the image's signer alone in the EFI db less dbx |
| `tpm-floor` | stage0 took the TPM and admitted this release at its channel's floor (`TPM floor M: release N admitted; reset authority sealed`) |
| `ipe-enforced` | stage0 restricted execution to the verified root and removed policy administration |
| `metadata-config`, `hostname` | `cloud-metadata` took the config from that cloud's metadata server; posture names the host as the config did |
| `shielded`, `nitro-tpm`, `trusted-launch`, `specialized-image` | GCP reports Secure Boot, vTPM and integrity monitoring on; the AMI gives a TPM 2.0; Azure reports Trusted Launch on a specialized image |
| `posture`, `runtime-protections` | what fails is exactly what `prod-ssh`'s weaknesses say it fails; root's runtime posture passes every required protection |
| `ssh-login-t`, `ssh-login-root`, `ssh-security-keys-only` | both accounts log in with the run's security key and report their own identities, `t` with a nonzero UID; a plain key file is refused |
| `reconfigure`, `delete` | a second `create` of the name, with a new hostname, restarts the machine on it; `howl delete` leaves nothing of it: instance, disk, network, security group, firewall rule |

However the run ends, it deletes what it made, the image included (`CLOUD_KEEP=1` keeps
the machine), and keeps `build/<arch>/prod-ssh/check/CLOUD-MODE-serial.log` and, for a
failed launch, `CLOUD-MODE-create.log`. Each needs that cloud's CLI logged in:

- **GCP:** gcloud with a project (`GCP_PROJECT`, or gcloud's own) and `GCP_ZONE`, by
  default `us-central1-a`. C4, C4A and N4 machines boot from `hyperdisk-balanced`.
  Passed 2026-10-24 in `us-west1-a` on `c4a-standard-1`, all fourteen checks.
- **AWS:** the aws CLI's region and credentials (`aws login` or `aws configure`, or
  `AWS_REGION` and `AWS_PROFILE`), and a default VPC. Passed 2026-10-25 in `us-west-2`
  on Graviton, all checks. Its console needs `CONFIG_SERIAL_8250_PCI` for Graviton's PCI
  16550 UART (`1d0f:8250`), which kernel-build sets and `lib/image.zig` requires.
- **Azure:** az's default resource group (`az configure --defaults group=RG`, or
  `AZURE_DEFAULTS_GROUP`), where Cobalt `Standard_D2ps_v6`, the one Arm size with
  Trusted Launch, is offered. Passed 2026-10-25 in `westus`, all checks. A custom PK
  leaves firmware in setup mode, so the version keeps Microsoft's PK via its UEFI CA
  template and revokes in dbx the CAs it trusts, leaving the image's signer db's only.

## `make check-independent-updates`

[test/check-independent-updates](../test/check-independent-updates), on Lima (macOS) or
`PROVIDER=qemu` (Linux, swtpm), proves a machine takes its own TPM and updates from a
static HTTPS channel alone ([design](design/independent-updates.md)). A, made by `howl
create --build`, enrolls at floor 1; its updater installs B; rollback returns to A;
power cuts around the floor's increment while installing C keep B booting; stage0
refuses a restored disk holding retired A; unhealthy E falls back to C at floor 3; a
root session cannot open the TPM. Output goes to `BUILD/check/independent-updates`,
which must not exist yet. Passed on Lima 2026-10-24, all ten checks, against swtpm.

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
not the installed firmware or Secure Boot. Provenance and A/B/soak evidence are in
`build/bhyve-validation/results-smaug-normal-runtime-20261018.json` (local, not checked
in).

For repeatable private builds and normal-launch testing, see the [pinned ARM64 runtime
recipe](../tools/bhyve-arm64/README.md). The longer normal-launch soak on smaug found a
separate blocker: after 286 verified 64 MiB transfers, virtio TX reported `id 255 is not
a head!`, then a soft-lockup panic about 12 minutes into the half-hour test, before its
reboot, stop/start and filesystem checks. No root cause or workaround is known.
