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

Normal protected cloud deployment is currently blocked: AWS and GCP lack the completed
provider lifecycle and reachable permit transport, and Azure also lacks reliable
firmware enforcement. These checks must fail until those paths are implemented and
validated; they never add `--disable`. See [cloud TPM
enrollment](design/cloud-tpm-enrollment.md) and [signed boot
status](cloud.md#signed-boot).

On 2026-10-24, the internal GCP path passed provider-pinned EK verification, measured
attestation, encrypted enrollment with host-held reset credentials, reboot replay
refusal, and factory disk handover on the same instance and TPM. The source-built
`prod-ssh` then accepted both `t` (nonzero UID) and `root` (UID 0) with a
verification-required security key. Root posture passed Secure Boot, TPM rollback
protection, IPE, lockdown, seal, verity and fence, with no disabled protections or
unexpected/stale weaknesses. Evidence is retained locally in
`build/check/gcp-bootstrap-261024183249/`; the VM, disks and images were deleted. This
does not qualify normal create, non-build downloads or cloud updates.

`test/check-gcp-bootstrap --workload BUNDLE` exercises that internal path. It takes
explicit measured kernel, bootstrap agent, stub and signing-key/certificate paths; its
`--help` lists them. `--provider aws` selects AWS; `--workload` also attempts its
same-instance factory handover and both SSH accounts. The AWS test refuses
disabled account Serial Console access unless the operator explicitly supplies
`--enable-aws-serial-console`, and restores disabled access even after test failures.
These test switches never relax Secure Boot, TPM or IPE checks.

`make check-prod-ssh-clouds` runs GCP, AWS, then Azure, with both `--build` and
published downloads for each. A single provider defaults to `CLOUD_MODE=build`; use
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

See [live bhyve tests](testing-bhyve.md) for runtime status, prerequisites,
lifecycle commands, firmware workarounds and retained test evidence.
