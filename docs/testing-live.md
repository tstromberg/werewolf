# Live tests

These tests need the network, a cloud account or another host, so none is
part of `make check`, and CI holds no cloud credentials. Each takes a few
minutes, and the cloud ones cost a few cents.

## `make check-updater`

It runs a whole update, as a machine does one ([updater.md](updater.md)).
`prod` is built with `DEV=1`, so it follows no releases and builds its own
slot, and boots from slot a of a disk that
[test/check-updater](../test/check-updater) makes, whose build record claims
the kernel release before its own: one file laid over the slot's root, so
nothing in `build/` changes. The machine commits, finds the published
kernel newer, fetches Wolfi's and werewolf's packages and the CVE sources as
`_update`, builds slot b, installs it and reboots.

[test/update](../test/update) then reads the disk with `debugfs`: each CVE
source listed with a sha256 and no error, each apk cache intact, slot b's
root owned by root with mode 0755, and the EFI entry allowing one try of b.
It boots slot b, which must commit, and the updater must record that the
update held. No seccomp filter may have killed anything in either boot. The
consoles are in `build/<arch>/check/update-prod/`.

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
[update.yml](../.github/workflows/update.yml) runs it nightly on x86_64, as
a workflow of its own, so a network flake fails only it.

## `make check-gcp`, `check-aws` and `check-azure`

[test/cloud](../test/cloud) runs `prod-ssh`'s disk, as a release makes it,
on a real cloud, as a user would. `howl create --on CLOUD` turns the disk
into that cloud's image (a GCP image, an AMI from an EBS snapshot written
directly, an Azure managed disk) and boots the smallest machine for the arch
(`ARCH=aarch64` or `x86_64`) from it, with a config holding a hostname and
an ssh key made for the run, and `--allow-from me`, so werewolf opens the
form's ports to this host alone. The test judges the machine from the
cloud's record of its serial port:

| Check | Passes when |
| --- | --- |
| `root-verified` | stage0 opened slot a's root through dm-verity |
| `metadata-config` | `cloud-metadata` took the config from that cloud's metadata server |
| `hostname` | posture names the host as the config did |
| `posture` | what fails is exactly what `prod-ssh`'s weaknesses say it fails |
| `ssh-login` | root logs in, over the Internet, with the run's key, through the port `--allow-from me` opened |
| `reconfigure` | a second `create` of the name, with a new hostname, restarts the machine on it |
| `delete` | `howl delete` leaves nothing of the machine: instance, disk, network, security group, firewall rule |

However the run ends, it deletes everything it made, the image included;
`CLOUD_KEEP=1` keeps the machine. The serial log is kept in
`build/<arch>/prod-ssh/check/CLOUD-serial.log`. Each needs that cloud's CLI
logged in:

- **GCP:** gcloud with a project (`GCP_PROJECT`, or gcloud's own); the zone
  is `us-central1-a` (`GCP_ZONE`).
- **AWS:** the aws CLI's region and credentials (`aws login` or `aws
  configure`, or `AWS_REGION` and `AWS_PROFILE`). Nothing needs setting up.
- **Azure:** az's default resource group (`az configure --defaults
  group=RG`, or `AZURE_DEFAULTS_GROUP`), in a location that offers the arch's
  size (`az vm list-skus -l LOCATION`; Arm sizes are in few regions).

## `make check-gcp-metadata`

[test/gcp-metadata](../test/gcp-metadata) builds this checkout's `prod-ssh`
with `machine.metadata-users: true`, creates a fresh GCP VM with the
software security-key provider from [test/keys](../test/keys), and changes
its metadata as an operator would: user-data at boot, instance and project
keys, declared-user precedence, refusal of root access, expired and
malformed Google key records, expiry without a metadata edit, project-key
blocking and unblocking, account removal, root-key rotation, and keeping the
last accepted people after invalid user-data. Removing user-data must leave
only metadata people; restoring it must restore the declared people and
root keys. The boot id must not change.

It takes `GCP_PROJECT`, `GCP_ZONE` and `ARCH` as `check-gcp` does, and
temporarily adds its public test key to the project's `ssh-keys`, so use a
test project; the account needs project-metadata write permission as well.
It deletes its VM, disk, firewall rule and image (`CLOUD_KEEP=1` keeps them,
with their test private keys). Logs are in `build/check/gcp-metadata-*`.

## Firecracker

`make check-firecracker` boots the `sshd` form as a Firecracker microVM on
`FIRECRACKER_HOST` (default `galadriel`), a Linux host with KVM,
Firecracker, mtools, erofs-utils and passwordless `doas`. The tree, built
for x86_64 here, is copied over with a howl, a form tool and a verity tool
cross-compiled for the host, so it needs no toolchain; the host resolves a
lock the copy does not match with `go install`'s apko, at the version
tools/install-deps pins. The form is sshd relaxed to take a key file the
host holds, and the ad-hoc generator declares the
`network-ssh-security-keys` weakness that costs. The machine must hand over
to runit with its root verified, posture must fail exactly what the form
and test/posture-known allow, ssh must reach it through its tap with the
host's key, and delete must remove the machine. `FIRECRACKER_KEEP=1` leaves
it for a look.
