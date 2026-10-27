# Live tests

These tests need the network, a cloud account or another host, so none is part of
`make check`, and CI holds no cloud credentials. Each takes a few minutes, and the
cloud ones cost a few cents.

## `make check-updater`

It runs a whole update ([updater.md](updater.md)) of `prod` as it ships, which builds
its own slot. [test/check-updater](../test/check-updater) boots slot a with a build
record claiming the preceding kernel release, without changing `build/`. After
committing, it finds the newer published kernel, fetches packages and CVE sources as
`_update`, builds slot b, installs it and reboots.

[test/update](../test/update) then reads the disk with `debugfs`: each CVE source
listed with a sha256 and no error, each apk cache intact, slot b's root owned by root
with mode 0755, and the EFI entry allowing one try of b. It boots slot b, which must
commit, and the updater must record that the update held. No seccomp filter may have
killed anything in either boot. The consoles are in
`build/<arch>/check/update-prod/`.

- `make check-updater-published` builds `test/published-form`, a form given by path
  on the published `prod`, and gives slot a an older-looking staged `prod`. Slot b
  must install `minimal-form` and `prod-form`, compose `prod` from the package rather
  than slot a's copy, and carry the local form's files forward
  ([design/custom-updates.md](design/custom-updates.md)). It passes once CI has
  published this tree's format and forms.
- `make check-updater-staged` cuts the power the moment slot b is staged. Slot b must
  boot all the same: a staged slot is armed
  ([design/update-policy.md](design/update-policy.md)).

It takes about 4 minutes with KVM or HVF, much longer under TCG.
[update.yml](../.github/workflows/update.yml) runs it nightly on x86_64, as a
workflow of its own, so a network flake fails only it.

## `make check-gcp`, `check-aws` and `check-azure`

[test/cloud](../test/cloud) deploys `prod-ssh` with every protection, as a user
would: `howl create --on CLOUD --build` builds it with your keys, makes the disk that
cloud's image (GCP image, AMI from an EBS snapshot, Azure specialized gallery image)
with its boot certificate as PK, KEK and db, and boots the smallest `ARCH` machine
under Secure Boot with a vTPM its first boot takes. `IMAGE_INDEX`, `IPE_UPDATES` and
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

However the run ends, it deletes what it made, the image included (`CLOUD_KEEP=1`
keeps the machine), and keeps `build/<arch>/prod-ssh/check/CLOUD-MODE-serial.log`
and, for a failed launch, `CLOUD-MODE-create.log`. Each needs that cloud's CLI logged
in:

- **GCP:** gcloud with a project (`GCP_PROJECT`, or gcloud's own) and `GCP_ZONE`, by
  default `us-central1-a`. C4, C4A and N4 machines boot from `hyperdisk-balanced`.
  Passed 2026-10-25 in `us-west1-a` on `c4a-standard-1`, all fifteen checks.
- **AWS:** the aws CLI's region and credentials (`aws login` or `aws configure`, or
  `AWS_REGION` and `AWS_PROFILE`), and a default VPC. Passed 2026-10-25 in
  `us-west-2` on Graviton, all checks. Its console needs `CONFIG_SERIAL_8250_PCI` for
  Graviton's PCI 16550 UART (`1d0f:8250`), which kernel-build sets and
  `lib/image.zig` requires.
- **Azure:** az's default resource group (`az configure --defaults group=RG`, or
  `AZURE_DEFAULTS_GROUP`), where Cobalt `Standard_D2ps_v6`, the one Arm size with
  Trusted Launch, is offered. Passed 2026-10-25 in `westus`, all checks. A custom PK
  leaves firmware in setup mode, so the version keeps Microsoft's PK via its UEFI CA
  template and revokes in dbx the CAs it trusts, leaving the image's signer db's
  only.

## `make check-independent-updates`

[test/check-independent-updates.zig](../test/check-independent-updates.zig), on Lima
(macOS) or `PROVIDER=qemu` (Linux, swtpm), proves a machine takes its own TPM and
updates from a static HTTPS channel alone ([design](design/independent-updates.md)).
A, made by `howl create --build`, enrolls at floor 1; its updater installs B;
rollback returns to A; power cuts around the floor's increment while installing C
keep B booting; stage0 refuses a restored disk holding retired A; unhealthy E falls
back to C at floor 3; a root session cannot open the TPM. Passed on Lima 2026-10-24,
all ten checks, against swtpm. Output goes to `BUILD/check/independent-updates`; it
must be new.

## `make check-gcp-metadata`

[test/gcp-metadata.zig](../test/gcp-metadata.zig) builds this checkout's `prod-ssh`
with `machine.metadata-users: true`, creates a fresh GCP VM with the software
security-key provider from [test/keys](../test/keys), and changes its metadata as an
operator would: user-data at boot, instance and project keys, declared-user
precedence, refusal of root access, expired and malformed Google key records, expiry
without a metadata edit, project-key blocking and unblocking, account removal,
root-key rotation, and keeping the last accepted people after invalid user-data.
Removing user-data must leave only metadata people; restoring it must restore the
declared people and root keys. The boot id must not change.

It takes `GCP_PROJECT`, `GCP_ZONE` and `ARCH` as `check-gcp` does, and temporarily
adds its public test key to the project's `ssh-keys`, so use a test project; the
account needs project-metadata write permission as well. It deletes its VM, disk,
firewall rule and image (`CLOUD_KEEP=1` keeps them, with their test private keys).
Logs are in `build/check/gcp-metadata-*`.

## Firecracker

[Protected Firecracker checks](testing-secure-boot.md#firecracker) exercise the
host-pinned IPE mode on Linux/KVM.

`make check-firecracker` boots `sshd` on `FIRECRACKER_HOST` (default `galadriel`).
The host needs Linux/KVM, Firecracker, mtools, erofs-utils and passwordless `doas`.
The x86_64 tree, howl, form and verity tools are copied there; no Zig toolchain is
needed. A mismatched lock is resolved with `go install`'s apko, pinned in
`tools/install-deps`. The form accepts the host's key file and declares the
`network-ssh-security-keys` weakness. It must hand over to runit with a verified root,
match the form's and `test/posture-known`'s expected posture, and accept SSH through
the tap with that key. Delete must remove the VM; `FIRECRACKER_KEEP=1` retains it.

## bhyve

See [bhyve live tests](testing-hypervisors.md#bhyve) for protected x86_64 lifecycle
and A/B coverage, ARM64 limits, and the separate-host test commands.
