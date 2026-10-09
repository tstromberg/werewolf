# Releases

CI publishes three forms, `minimal`, `prod` and `prod-ssh`, for aarch64 and x86_64,
as GitHub releases. It makes a release only when an image would change,
usually within the hour of a fix reaching Wolfi or Alpine, and anyone
can rebuild a release byte for byte from what it carries.

`prod` is the production base: a machine that takes its address by DHCP,
keeps itself current, and listens on nothing. `prod-ssh` is `prod` with
sshd, for an operator to reach by security key (`ed25519-sk` or
`ecdsa-sk`, touched); a key file is refused.

## What a release holds

| File | |
| --- | --- |
| `prod-ARCH-disk.qcow2`, `prod-ssh-ARCH-disk.qcow2` | a UEFI boot disk of 8 GiB holding the slot: what a VM boots from ([Deploying](#deploying)) |
| `FORM-ARCH-vmlinuz` | the kernel |
| `prod-ARCH-stage0.zst`, `prod-ARCH-stage0-bitten.zst`, `prod-ARCH-root.erofs`, `prod-ARCH-cmdline`, and the same for `prod-ssh` | the slot the updater installs, and the kernel arguments it boots with ([updater.md](updater.md#releases)): stage0 for werewolf's own disk, and for a distro's after bite, which adds the modules of the distro's filesystem (xfs, btrfs) |
| `minimal-ARCH-initramfs.zst`, `minimal-ARCH-cmdline` | the whole image, and the kernel arguments its host passes, for direct boot |
| `FORM-ARCH.json`, `FORM-ARCH.json.sig` | the manifest, signed |
| `minimal.lock.json`, `prod.lock.json`, `prod-ssh.lock.json`, `kernel.lock.json`, `boot.lock.json` | every package, pinned: apko's locks |
| `inputs` | what the release was built from |

The tag is the manifests' serial, the time CI signed them.

```json
{
  "format": "werewolf-release/1",
  "form": "prod-ssh",
  "arch": "aarch64",
  "serial": "20261006T144722Z",
  "expires": "9999-12-31T23:59:59Z",
  "build": "ccdf6e096eb6f15d",
  "kernel": "linux-virt-6.18.55-r0",
  "files": {
    "vmlinuz": {"sha256": "27e0c04b…", "size": 36306944},
    "stage0.zst": {"sha256": "47bb1201…", "size": 9799501},
    "stage0-bitten.zst": {"sha256": "…", "size": …},
    "root.erofs": {"sha256": "779f06fb…", "size": 20717568},
    "disk.qcow2": {"sha256": "7d383112…", "size": 26214400}
  },
  "packages": [
    {"name": "busybox-full", "version": "1.38.0-r2", "origin": "busybox"}
  ]
}
```

`build` is the first 16 hex digits of the sha256 of the files' `sha256sum`
lines, in manifest order: two releases with the same `build` have the same
images. `packages` is the root image's, for CVE reports. `advisories` is
[release/advisories](../release/advisories), werewolf's own security fixes,
which no CVE names: a machine boots a release that carries one its own
image lacks as soon as that advisory's tier says
([docs/design/update-policy.md](design/update-policy.md#werewolfs-own-fixes)).

## When CI releases

[.github/workflows/release.yml](../.github/workflows/release.yml) runs
every 15 minutes, for what Wolfi and Alpine change, and whenever the `check`
workflow passes on `main`, for what werewolf changes, building the commit
that passed. GitHub runs a schedule this frequent late, or skips it, under
load, most often on the hour and its quarters, so release.yml's minutes are
7, 22, 37 and 52; a push does not wait on one.

1. **Inputs.** `make release-inputs` resolves fresh locks for the forms, stage0,
   the kernel and systemd-boot: the newest packages in Wolfi, and in Alpine's
   v3.24 for the kernel. It writes `inputs`: a digest of the files that build the
   images, and every package's URL. The locks resolve all at once, and CI
   keeps the form tool built, so this takes seconds. CI keeps a cache entry
   per digest; if these inputs were built before, the run stops.
2. **Build, twice.** Each architecture is built on two runners from those
   locks, and the two must match byte for byte.
3. **Boot.** Each form boots under QEMU and passes `make check`
   ([testing.md](testing.md)), and so does the slot path. `make check-dist`
   boots each published disk, the very file, under UEFI firmware, and
   judges its posture as the form ships.
4. **Compare.** If every image's `build` matches the latest release's, as
   after a change to a comment, nothing is published.
5. **Publish.** The manifests are signed, the release is made as a draft,
   its files are attested with Sigstore, and the draft is published.

A fixed CVE arrives as a new package or kernel, so the next run releases
it. A release is published only when its images change, and stays as
published: GitHub keeps releases immutable, and a manifest does not
expire, since the next release supersedes it and its serial forbids going
back. Its `expires` is the end of 9999, there only for updaters from
before 2026-10-08, which require the field. How fresh a machine's view is
comes from the CVE tiers feed, which expires in three days (below).

CI's cache drops entries unused for a week. A run that loses its entry
builds again, finds the same images, and publishes nothing.

## Reproducing a release

```sh
git checkout COMMIT                  # from the release notes
mkdir -p build/lock
gh release download TAG --dir build/lock --pattern '*.lock.json'
make dist                            # and ARCH=x86_64 make dist on arm64
grep '"build"' dist/*.json           # compare with the release's manifests
```

Fetch the locks after the checkout: a lock older than its config is
resolved again.

What makes the bytes repeat:

- **Pinned packages.** apko installs exactly what the locks name, and
  writes the same rootfs from the same packages.
- **werewolf's files as a normalized tar.** Sorted, owned by root, modes
  644 or 755, dated 1970, without extended attributes.
- **Images made from tars alone.** The cpio carries no inode numbers;
  `mkfs.erofs -T0` dates everything 1970 and the UUID is fixed.
- **Disks with fixed identities.** Every GUID, UUID, serial number and time
  on the disk is fixed (`cmd/howl/disk.zig`), and the qcow2 names its
  compression.
- **Nothing records the build.** No time, host or path reaches an image.

The toolchain must match too: a different zstd, mkfs.erofs or qemu-img can
write other bytes from the same input. CI uses Ubuntu 26.04's zstd, bsdtar,
erofs-utils (or, if Ubuntu's has no zstd, the 1.9.4 it builds), mtools,
e2fsprogs and qemu-img, and the apko and Zig that
[tools/install-deps](../tools/install-deps) pins. A Mac gets that same erofs-utils 1.9.4 from it, built
with zstd, which Homebrew's lacks; it writes the same root as Wolfi's. In practice the first release rebuilt on a Mac with Homebrew's
tools came out the same, but for the updater: Homebrew's Zig names its own
linker in the binary, so use Zig's release tarball. `inputs` leaves the
toolchain out, so a new runner image alone does not make a release.

## Checking a release

```sh
openssl dgst -sha256 -verify release/image.pub \
    -signature prod-ssh-x86_64.json.sig prod-ssh-x86_64.json
shasum -a 256 prod-ssh-x86_64-disk.qcow2        # against the manifest
gh attestation verify prod-ssh-x86_64-disk.qcow2 --repo werewolf-linux/werewolf
```

The signature is RSA PKCS#1 v1.5 over the manifest's sha256. The
attestation ties each file to the workflow run and commit that built it.

## Deploying

A VM boots the disk under UEFI firmware, on slot a, and from then on keeps
itself current from these releases ([updater.md](updater.md#releases)).
Its config comes from a config disk, NoCloud, or the cloud's metadata
server ([cloud.md](cloud.md)). Secure Boot must be off: systemd-boot is
not signed yet ([verified-boot.md](design/verified-boot.md)).

```sh
gh release download --repo werewolf-linux/werewolf --pattern 'prod-ssh-x86_64*'
```

Check it, as above. QEMU, Lima, Proxmox and OpenStack take the qcow2 as
it is. The clouds each want their own format; on aarch64, tell each the
architecture too (`--architecture ARM64` on GCP, `arm64` on AWS, `Arm64`
on Azure).

**GCP**: a raw disk named `disk.raw`, in a gzipped tar.

```sh
qemu-img convert -O raw prod-ssh-x86_64-disk.qcow2 disk.raw
tar --format=oldgnu -Sczf werewolf.tar.gz disk.raw
gcloud storage cp werewolf.tar.gz gs://BUCKET/
gcloud compute images create werewolf --source-uri gs://BUCKET/werewolf.tar.gz \
    --guest-os-features UEFI_COMPATIBLE,GVNIC
```

`make check-gcp` does this with a disk built from the tree, boots it and
checks it there, then deletes it ([testing.md](testing.md)).

**AWS**: `howl upload prod-ssh-x86_64-disk.qcow2 --on aws` writes
the disk straight into an EBS snapshot, only its blocks that hold data,
registers it as a UEFI image with ENA and IMDSv2 alone, and prints the
AMI's id; nothing needs setting up first. By hand, without werewolf, VM
Import does the same from S3, more slowly, and needs the `vmimport` role:

```sh
qemu-img convert -O raw prod-ssh-x86_64-disk.qcow2 disk.raw
aws s3 cp disk.raw s3://BUCKET/werewolf.raw
aws ec2 import-snapshot --disk-container 'Format=RAW,UserBucket={S3Bucket=BUCKET,S3Key=werewolf.raw}'
# once aws ec2 describe-import-snapshot-tasks names the snapshot:
aws ec2 register-image --name werewolf --architecture x86_64 --boot-mode uefi \
    --ena-support --virtualization-type hvm --root-device-name /dev/xvda \
    --block-device-mappings 'DeviceName=/dev/xvda,Ebs={SnapshotId=SNAPSHOT}'
```

**Azure**: a fixed-size VHD, made a Gen2 managed disk and attached as a
VM's OS disk. That makes the VM *specialized*: Azure provisions nothing
and waits for no agent to report ready, which a generalized image needs
and werewolf has not. One disk serves one VM.

```sh
qemu-img convert -O vpc -o subformat=fixed,force_size prod-ssh-x86_64-disk.qcow2 disk.vhd
az storage blob upload --account-name ACCOUNT -c disks -n werewolf.vhd -f disk.vhd --type page
az disk create -g RG -n web-1 --os-type Linux --hyper-v-generation V2 --security-type Standard \
    --source https://ACCOUNT.blob.core.windows.net/disks/werewolf.vhd
az vm create -g RG -n web-1 --attach-os-disk web-1 --os-type Linux --security-type Standard \
    --user-data config.tar
```

`prod` carries each cloud's devices (`forms/prod/form.yaml`): virtio, GCP's
virtio-scsi, NVMe and gVNIC, AWS's ENA and NVMe, and Azure's Hyper-V disks
and synthetic NIC. Each is tested where it is absent, and the metadata
fetch against stand-ins for each cloud ([cloud.md](cloud.md)). Each
cloud's steps also run for real, in `make check-gcp`, `make check-aws`
and `make check-azure` ([testing.md](testing.md)).

The disk is 8 GiB, and stays so: a provider's larger disk leaves the rest
unused ([native-boot.md](design/native-boot.md#open-questions)).

## The key

The image key is RSA-4096 because it will also sign IPE policies, which
the kernel checks ([docs/design/verified-boot.md](design/verified-boot.md)).
Its private half is the secret `WEREWOLF_IMAGE_KEY` in the GitHub
environment `release`, which only the release workflow on `main` uses; its
public half is `release/image.pub`. To set it up:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out image.key
openssl pkey -in image.key -pubout -out release/image.pub
gh api -X PUT repos/werewolf-linux/werewolf/environments/release
gh secret set WEREWOLF_IMAGE_KEY --env release <image.key
```

Then limit the environment to `main` (Settings, Environments), commit
`release/image.pub`, and keep `image.key` offline. Until both exist, the
workflow builds and checks, then fails at signing and publishes nothing.

## Packages

werewolf's programs and forms are also apk packages, at
`https://dist.werewolf-linux.org/apk/ARCH/` in the R2 bucket `werewolf`
([custom-updates.md](design/custom-updates.md)): `werewolf-PROGRAM` for each
program, and `NAME-form` for each form but those with melange recipes, its
files as an image stages them, depending on its base's, the forms it takes,
its packages and its programs. When check passes on main, the packages
workflow packs both arches twice, requires the copies to match, and publishes
(release/packages) only the packages whose files changed, with the index
signed again. Published packages are never replaced or removed.

Each package depends on `werewolf-format`, the version of the files compose
writes (`format` in lib/compose.zig); bump it on an incompatible change, and
machines on the old one keep the last packages for it. The index is signed
by `release/packages.pub`'s key, the secret `WEREWOLF_PACKAGES_KEY` in the
environment `release`; R2 takes uploads with `R2_ACCESS_KEY_ID` and
`R2_SECRET_ACCESS_KEY`, a token for that bucket alone. Nothing is published
until the repository variable `PUBLISH_PACKAGES` is `true`. A release's forms
are the published ones, so howl writes its configs and locks (`make
release-inputs`), from the forms the repository holds then.

## The tiers feed

`cve-tiers.json` tells a machine how soon to boot an update: within 15
minutes for a fix to an exploited or critical CVE, and up to four weeks,
in its maintenance window, for a minor one
([docs/design/update-policy.md](design/update-policy.md)). It gives every
CVE Wolfi's `security.json` names, and every kernel CVE fixed on the branch
of the kernel Alpine ships, a tier, with the evidence for it:

| Tier | A CVE is in it when |
| --- | --- |
| `urgent` | it is in CISA's [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog, or its CVSS score is 9.0 or more with network attack vector (`AV:N`) |
| `high` | its score is 7.0 or more |
| `medium` | its score is 4.0 or more, or it has no score yet |
| `low` | its score is below 4.0 |

```json
{
  "format": "werewolf-cve-tiers/1",
  "serial": "20261007T140000Z",
  "expires": "2026-10-10T14:00:00Z",
  "kernel": "6.18",
  "urgent": [
    {"cve": "CVE-2026-1234", "origin": "openssl", "fixed": "3.5.4-r0", "score": 9.8, "vector": "CVSS:3.1/AV:N/...", "source": "nvd", "kev": "2026-10-01"},
    {"cve": "CVE-2026-5678", "fixed": "6.18.55", "score": 9.1, "vector": "CVSS:3.1/AV:N/...", "source": "cna"}
  ],
  "high": [...],
  "medium": [
    {"cve": "CVE-2025-0001", "score": 5.5, "vector": "CVSS:3.1/AV:L/...", "source": "cisa-adp"},
    {"cve": "CVE-2025-0002"}
  ],
  "low": [...]
}
```

Urgent and high CVEs are listed with each package version that fixed
them, its package's `origin` with it, or kernel release, on the `kernel`
branch, without one, so a machine finds them from the signed feed alone;
medium and low once each. Every entry carries what its tier rests
on, for the machine's log: `score`, `vector` and `source` when the CVE has
a score, and `kev`, the date CISA listed it, when it is in KEV; each is
left out otherwise. A score is NVD's own, or, until NVD has one, that of
the CNA that assigned the CVE, then CISA's: CVSS 3.1, then 4.0, then 3.0.
Anyone else's is passed over.

[tools/cve-tiers.zig](../tools/cve-tiers.zig) builds it, fetching each
source with curl and keeping NVD's scores between runs, so a run asks NVD
only for what changed since the last. It covers only what werewolf
installs: [release/origins](../release/origins) locks every form, stage0
and the boot disk, and names each package's source package, its origin, as
Wolfi's index gives it, about 120 of them. A CVE in a package werewolf
never installs tells no machine anything; a machine running a form built
elsewhere, with packages of its own, counts their CVEs as medium. With the
kernel's, about 7,000 CVEs: 780 KB, nearly all of it the kernel's.
[release/sign-tiers](../release/sign-tiers) stamps it with a serial and an
expiry three days out, and signs it. [release/tiers](../release/tiers)
does all three, hourly, run by the feed repository's own workflow
([werewolf-linux/cve-feed](https://github.com/werewolf-linux/cve-feed)):
hourly, because a CVE CISA adds to KEV should become urgent within the
hour, not the day. A feed that stops coming expires within three days,
and a machine then counts every fix as high. `make cve-tiers` builds one
here, unsigned, in `build/tiers/`.

### Where it is published

In a repository of its own,
[werewolf-linux/cve-feed](https://github.com/werewolf-linux/cve-feed), as
`cve-tiers.json` and `cve-tiers.json.sig`; machines fetch
`https://raw.githubusercontent.com/werewolf-linux/cve-feed/main/cve-tiers.json`. A run commits only when a tier changed, or when the
published feed is a day old, to renew its expiry, so the repository's
history is the feed's: each change a diff anyone can read. Machines fetch
both files from GitHub's raw file server, gzipped (37 KB) and only when the
`ETag` changed; it caches each for five minutes, so just after a commit a machine may get one file's new copy and
the other's old. The signature then fails, and the machine keeps the last
feed it checked until its next check, as it does whenever the feed cannot
be had.

The workflow runs in that repository, not in werewolf: it checks out
werewolf's `main`, read only, for the tools, and pushes with the feed
repository's own token, which can write nowhere else. The tiers and NVD
keys are in that repository's `release` environment, apart from the image
key. Whoever can push there can change or remove the files, never sign
them: the worst it does is no feed, and then every fix counts as high.

The feed has its own key, not the image key: it decides when a machine
reboots, never what it runs, so a leak of a key that signs daily costs
timing, not code. It is RSA-4096 like the image key, so a machine checks
both the same way. Its private half is the secret `WEREWOLF_TIERS_KEY` in
cve-feed's `release` environment, beside `NVD_API_KEY`, an
[NVD API key](https://nvd.nist.gov/developers/request-an-api-key); its
public half is `release/tiers.pub`. To set them up:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out tiers.key
openssl pkey -in tiers.key -pubout -out release/tiers.pub
gh api -X PUT repos/werewolf-linux/cve-feed/environments/release   # then limit it to main
gh secret set WEREWOLF_TIERS_KEY -R werewolf-linux/cve-feed --env release <tiers.key
gh secret set NVD_API_KEY -R werewolf-linux/cve-feed --env release   # paste the key NVD sent
```

Commit `release/tiers.pub` and keep `tiers.key` offline. Without the key,
the `tiers` job builds the feed, then fails at signing and publishes
nothing. To check a feed:

```sh
git clone https://github.com/werewolf-linux/cve-feed && cd cve-feed
openssl dgst -sha256 -verify ../release/tiers.pub -signature cve-tiers.json.sig cve-tiers.json
git log -p cve-tiers.json   # every change, as a diff
```

## Limits

- The published disks boot in CI under QEMU alone: not on a cloud, and
  not with a cloud's devices.
- Releases are kept; nothing prunes old ones.
