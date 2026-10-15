# Releases

For all forms, browse the [R2 image catalog](https://dist.werewolf-linux.org/images/v1/index.html)
or run `howl forms --published`. See [catalog verification and deployment](#form-image-catalog).
For current form coverage, see [image availability](forms-catalog.md#images-and-downloads).
Protected qcow2 downloads and their verification instructions are [below](#downloading-a-protected-qcow2).

The legacy CI workflow publishes three forms, `minimal`, `prod` and `prod-ssh`, for aarch64 and x86_64,
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
| `prod-ARCH-stage0.zst`, `prod-ARCH-root.erofs`, `prod-ARCH-cmdline`, and the same for `prod-ssh` | the slot and the kernel arguments for werewolf's native disk |
| `minimal-ARCH-initramfs.zst`, `minimal-ARCH-cmdline` | the whole image, and the kernel arguments its host passes, for direct boot |
| `FORM-ARCH-uki` | the whole slot as one signed PE — kernel, stage0, root and command line (tools/uki) — that firmware with Secure Boot on and the boot key enrolled boots whole; listed when the release was signed with one ([design/verified-boot.md](design/verified-boot.md)) |
| `FORM-ARCH.json`, `FORM-ARCH.json.sig` | the manifest, signed |
| `minimal.lock.json`, `prod.lock.json`, `prod-ssh.lock.json`, `kernel.lock.json`, `boot.lock.json` | every package, pinned: apko's locks |
| `inputs` | what the release was built from |

The tag is the manifests' serial, the time CI signed them.

CI uses `release/with-boot-key` to materialize its PEM secret as a private key file,
verify it against the boot certificate, and remove it after the build. Missing keys refuse.
Boot PE signatures use a fixed signing time so independent release builds can match.
`check-dist` verifies signed artifacts and enrolls their certificate before booting the actual disk.
These existing releases do not yet provide the complete IPE/TPM default deployment profile;
see [published protected images](design/published-secure-boot.md).
The separate [protected candidate workflow](../.github/workflows/protected-images.yml) uses
dedicated public trust and compares independent signed bundles for Lima and Linux QEMU.
Its [download/publication gates](design/protected-downloads.md) remain separate from these releases.

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

Formatting and documentation checks run in the independent `lint` workflow;
they do not gate package or image publication. Builds, signatures, reproducibility
and runtime checks remain publication requirements.

[.github/workflows/release.yml](../.github/workflows/release.yml) runs
every 15 minutes, for what Wolfi and Alpine change, and whenever the
`packages` workflow has run after `check` passes on `main`, for what werewolf
changes, so the packages a change brings are published first. GitHub runs a schedule this frequent late, or skips it, under
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
itself current through apk, from werewolf's repository and Wolfi's
([updater.md](updater.md)): releases are for installs.
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

The boot key is the same arrangement for Secure Boot: RSA-2048, its
public half committed as `release/boot.crt` and its private held as
`WEREWOLF_BOOT_KEY` in the same environment; systemd's stub comes with
tools/install-deps. Each release
then carries its `uki`, and firmware holding the certificate's public
half boots only what that key signed
([design/verified-boot.md](design/verified-boot.md)). Without the secret,
a release ships as before, with no UKI.

## Packages

werewolf's programs and forms are also apk packages, at
`https://dist.werewolf-linux.org/apk/ARCH/` in the R2 bucket `werewolf`
([custom-updates.md](design/custom-updates.md)): `werewolf-PROGRAM` for each
program, `werewolf-advisories` (release/advisories, which tiers a machine's
update by werewolf's own fixes), and `NAME-form` for each form but those
with melange recipes, its
files as an image stages them, depending on its base's, the forms it takes,
its packages and its programs. When check passes on main, the packages
workflow packs both arches twice, requires the copies to match, and publishes
(release/packages) only the packages whose files changed, with the index
signed again. Published packages are never replaced or removed.

Each package depends on `werewolf-formatN`, N numbering the files compose
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

## Form image catalog

[form-images.yml](../.github/workflows/form-images.yml) discovers every directory
under `forms/` and considers aarch64 and x86_64 independently. A form's declared
architecture limits are honored and shown in the catalog. Relevant main pushes,
an hourly schedule and manual dispatch resolve fresh inputs. Each form's digest
binds its source chain, shared code and tests, trust, exact package versions and
checksums, OCI digests, Melange build environments and host tool versions.
Documentation and unrelated forms do not trigger image rebuilds.

An authenticated `current.json` with the same digest skips a completed target.
Changed targets build on two independent native Linux runners without restored
compiled output. Forms within a job share pinned kernel and EFI prerequisites.
The complete qcow2, slot files, signatures and rebuild locks must match byte for
byte. Each matching target must meet its form integration coverage minimum,
then runs `howl test --with FORM --arch ARCH` and boots
the actual release disk under enrolled Secure Boot firmware. Failed tests,
missing evidence or different build bytes prevent that target's publication.
Passing targets can publish while another form fails; the workflow reports failure
and the catalog keeps the last passing release alongside the failed attempt.

The catalog uses the existing R2 bucket and dedicated `images/v1/` prefix:

```text
images/v1/index.html                         browse every form
images/v1/index.json                         signed catalog envelope
images/v1/FORM/index.html                    architectures, downloads and test status
images/v1/FORM/ARCH/current.json             atomic signed download head
images/v1/FORM/ARCH/objects/HASH/disk.qcow2   immutable disk
images/v1/FORM/ARCH/objects/HASH/downloads.json[.sig]
images/v1/FORM/ARCH/objects/HASH/tests.json   artifact-bound test evidence
images/v1/FORM/ARCH/objects/HASH/inputs.tar.gz
images/v1/FORM/ARCH/objects/HASH/packages.json
images/v1/FORM/ARCH/objects/HASH/release-notes.{html,json}
images/v1/FORM/ARCH/BUILD/{vmlinuz,root.erofs,stage0.zst,cmdline,uki.efi}
images/v1/FORM/ARCH/latest.json[.sig]         signed slot update head
```

Objects are uploaded and checked through public HTTPS before any head advances.
An atomic signed receipt retains the publication floor across interrupted update
head writes. A retry repairs that pair; an incomplete pair never counts as an
unchanged successful publication. Immutable objects are never overwritten with
different bytes. The publishing health workflow reports failures and recovery.

### Package release notes

Each passing release includes HTML release notes and JSON changes, linked from
the image pages, `howl forms FORM --published` and the publishing job summary.
The comparison uses the previous passing image of the same form and architecture;
failed attempts never become a baseline. The first release lists its initial
inventory. Later notes show additions, removals, version updates and packages
rebuilt with different content at the same version. They also show changes to
the digests of baked OCI images, with a source comparison when the commit changes.
A source-only or forced rebuild explicitly reports when no packages changed.

`packages.json` records architecture-specific resolved packages, plus locally
built form packages read from their APK metadata. Image packages, local recipes,
kernel configuration inputs, and build/test dependencies are grouped separately.
Identical runtime dependencies are omitted from the additional test-package list.
Build/test groups describe inputs, not software installed in the VM. OCI internals
are not enumerated; their exact image digests are recorded instead.

The inventory is part of both independent builds. The publisher checks the
previous inventory against its signed manifest before generating notes. The
signed download manifest binds the inventory and both release-note files, which
are uploaded and verified before the image head advances. Notes link to the
previous release, preserving the history even when a later attempt fails.

### Download and verify a catalog disk

Choose a form and architecture on its image page. Download `disk.qcow2`,
`downloads.json` and `downloads.json.sig` from the same immutable release.
From a trusted checkout, extract the committed legacy boot certificate's public
key and verify the manifest before checking the disk:

```sh
openssl x509 -in release/boot.crt -pubkey -noout > image.pub
openssl dgst -sha256 -verify image.pub -signature downloads.json.sig downloads.json
jq -r '.files["disk.qcow2"] | "\(.sha256)  disk.qcow2"' downloads.json | shasum -a 256 -c -
```

Stop on verification failure. `downloads.json` also binds the source commit,
GitHub Actions run, rebuild inputs and passing form tests. `current.json` and
the catalog embed their exact signed JSON bytes as `manifest` and a hex-encoded
RSA/SHA-256 `signature`; the standalone download uses a detached binary signature.

Catalog images use the legacy boot identity in `release/boot.crt` for UEFI and
IPE signing, separate from protected-download trust. Enroll that certificate
using [the signed boot instructions](cloud.md#signed-boot), attach configuration
packed with `howl pack --build --with FORM`, and follow the form's setup guide.
The updater fetches complete signed slots from that form's catalog channel;
forms declaring `updates: off` retain that choice. Configuration and
application credentials are supplied per machine, never baked into public disks.

These catalog disks do not include TPM release-retirement enrollment. Secure
`howl run`/`create` downloads retain their separate exact-bundle lifecycle gates;
use `--build` for a protected source deployment when that form has no protected
download. The catalog does not cause howl to downgrade to another profile.

## Protected production downloads

`howl run` uses production-signed downloads by default; playground is published for
x86_64 QEMU and arm64 Lima.
`--build` retains local signing and cached builds. Existing locally signed machines retain
their original trust; use a new machine name when adopting production downloads.
The protected trust and layout are described in [protected-downloads](design/protected-downloads.md).

The [protected workflow](../.github/workflows/protected-images.yml) runs after relevant pushes
to main, hourly for upstream updates, and on manual dispatch. It compares two independent
x86_64 builds, privately authorizes test candidates, and runs the exact-artifact playground
lifecycle under QEMU/KVM, OVMF and swtpm on a hosted Linux runner. All fourteen gates must
pass before publication. `prod` and `prod-ssh` remain candidates; arm64 QEMU and Lima need
their own runtime evidence before this workflow can publish them. Existing arm64 Lima
downloads are separate from this GHA publication path.

`release/export-protected HOWL BUNDLE GATES_JSON PROVIDER OUTPUT` admits the gated bundle
and produces one set of GitHub assets. Original boot/image manifests and signatures are
copied exactly. A standalone compressed qcow2 is derived from the authenticated raw disk;
`qemu-img check` and `qemu-img compare` verify its structure and disk contents. A separately
signed `werewolf-downloads/1` manifest binds every asset's size and SHA-256, the original boot
descriptor, lifecycle evidence, source commit and GHA run. Conversion does not enroll a VM;
the protected profile still needs its matching Secure Boot certificate, TPM and permit service.

GitHub releases use tags `protected-SERIAL` and asset names `FORM-PROVIDER-ARCH-FILE`.
They carry the qcow2, compressed raw disk, slot files, both original signature pairs,
public certificates, lifecycle gates and signed download manifest. Every asset also receives
a GitHub build provenance attestation. The legacy release workflow compares only legacy tags.

`release/publish-protected HOWL BUNDLE GATES_JSON PROVIDER RELEASE_ASSETS` rechecks committed trust and
artifact-bound gates, uploads immutable objects before signed heads, and retains an authenticated
floor across interrupted uploads. The same qcow2 and signed download assets accompany the
original bundle under its immutable R2 descriptor. CI uses the existing R2 release credentials.
`release/check-protected-download HOWL BUNDLE PROVIDER RELEASE_ASSETS` downloads from the public
endpoint, performs full native admission and compares every R2 object with its GitHub asset.
The workflow creates a GitHub draft first and makes it public only after attestation, R2 upload
and this parity check succeed. A failure leaves the draft unpublished; it never bypasses a gate.
PRs and manual dispatch with `build: false` run the full QEMU lifecycle and export using
temporary test keys on a disposable hosted runner. They receive no production secrets and upload no images.
Private boot/image keys remain on signing hosts; consumers and compile guests receive public inputs.

### Downloading a protected qcow2

Open [GitHub Releases](https://github.com/werewolf-linux/werewolf/releases) and choose
a `protected-SERIAL` release with assets for your form, provider and architecture.
The x86_64 QEMU playground disk is `playground-qemu-x86_64-disk.qcow2`.
For deployment on a matching Linux host, `howl run --on qemu` downloads and
authenticates the bundle, enrolls firmware and TPM, and starts the host permit service.

To inspect or archive the standalone disk, set `TAG` to the chosen protected release
tag and run these commands from a trusted checkout. Use the committed image
certificate as the trust anchor:

```sh
TAG=protected-20261014T232908Z
mkdir -p downloads
gh release download "$TAG" --repo werewolf-linux/werewolf --dir downloads \
  --pattern 'playground-qemu-x86_64-*'
openssl x509 -in release/protected/image.crt -pubkey -noout > downloads/image.pub
openssl dgst -sha256 -verify downloads/image.pub \
  -signature downloads/playground-qemu-x86_64-downloads.json.sig \
  downloads/playground-qemu-x86_64-downloads.json
(cd downloads && jq -r '.files["disk.qcow2"] | "\(.sha256)  \(.asset)"' \
  playground-qemu-x86_64-downloads.json | shasum -a 256 -c -)
gh attestation verify downloads/playground-qemu-x86_64-disk.qcow2 \
  --repo werewolf-linux/werewolf
```

Stop if signature or digest verification fails. The signed download manifest covers
the qcow2, and the signed boot/image manifests cover the original bundle.
The qcow2 contains the same protected system, but importing it into a hypervisor
does not create the machine's owner keys, firmware enrollment, TPM state or host
update/permit service. Use howl for the supported protected deployment path.
Its host service polls for authenticated vendor bundles every five minutes;
the guest applies them under its [update policy](updater.md#when-an-update-boots).
A/B recovery and retirement protection depend on retaining that machine's
enrollment and host service. Legacy release disks use the package updater and
do not acquire the protected profile by being converted or imported.

## Limits

Opt-in IPE application channels use complete signed slot bundles rather
than on-machine package composition. `make prebuilt` exports a pinned
channel; `WEREWOLF_BOOT_KEY` adds its freshly signed UKI. See
[design/prebuilt-images.md](design/prebuilt-images.md) for enrollment,
artifact layout, publication order and rollback limits.

- The published disks boot in CI under QEMU alone: not on a cloud, and
  not with a cloud's devices.
- Releases are kept; nothing prunes old ones.
