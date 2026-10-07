# Releases

CI publishes three forms, `minimal`, `prod` and `prod-ssh`, for aarch64 and x86_64,
as GitHub releases. It makes a release only when an image would change,
usually within the hour of a fix reaching Wolfi or Alpine, and anyone
can rebuild a release byte for byte from what it carries.

`prod` is the production base: a machine that takes its address by DHCP,
keeps itself current, and listens on nothing. `prod-ssh` is `prod` with
sshd, for an operator to reach by key.

## What a release holds

| File | |
| --- | --- |
| `prod-ARCH-disk.qcow2`, `prod-ssh-ARCH-disk.qcow2` | a UEFI boot disk of 8 GiB holding the slot: what a VM boots from ([Deploying](#deploying)) |
| `FORM-ARCH-vmlinuz` | the kernel |
| `prod-ARCH-stage0.zst`, `prod-ARCH-root.erofs`, and the same for `prod-ssh` | the slot the updater installs ([updater.md](updater.md#releases)) |
| `minimal-ARCH-initramfs.zst`, `minimal-ARCH-cmdline` | the whole image, and the kernel arguments its host passes, for direct boot |
| `FORM-ARCH.json`, `FORM-ARCH.json.sig` | the manifest, signed |
| `minimal.lock.json`, `prod.lock.json`, `prod-ssh.lock.json`, `stage0.lock.json`, `kernel.lock.json`, `boot.lock.json` | every package, pinned: apko's locks |
| `inputs` | what the release was built from |

The tag is the manifests' serial, the time CI signed them.

```json
{
  "format": "werewolf-release/1",
  "form": "prod-ssh",
  "arch": "aarch64",
  "serial": "20261006T144722Z",
  "expires": "2026-10-13T14:47:23Z",
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
images. `packages` is the root image's, for CVE reports.

## When CI releases

[.github/workflows/release.yml](../.github/workflows/release.yml) runs
every 15 minutes, for what Wolfi and Alpine change, and whenever the `check`
workflow passes on `main`, for what werewolf changes, building the commit
that passed. GitHub runs a schedule this frequent late, or skips it, under
load; a push does not wait on one.

1. **Inputs.** `make release-inputs` resolves fresh locks for the forms, stage0,
   the kernel and systemd-boot: the newest packages in Wolfi, and in Alpine's
   v3.24 for the kernel. It writes `inputs`: a digest of the files that build the
   images, and every package's URL. CI keeps a cache entry per digest; if
   these inputs were built before, the run stops.
2. **Build, twice.** Each architecture is built on two runners from those
   locks, and the two must match byte for byte.
3. **Boot.** Each form boots under QEMU and passes `make check`
   ([testing.md](testing.md)), and so does the slot path.
4. **Compare.** If every image's `build` matches the latest release's, as
   after a change to a comment, nothing is published.
5. **Publish.** The manifests are signed, the release is made as a draft,
   its files are attested with Sigstore, and the draft is published.

A fixed CVE arrives as a new package or kernel, so the next run releases
it. Each day CI signs the latest release's manifests again with a new
expiry, a week out: a current release never expires, and a mirror that
stops updating is noticed within a week.

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
  on the disk is fixed (`boot/mkdisk`), and the qcow2 names its compression.
- **Nothing records the build.** No time, host or path reaches an image.

The toolchain must match too: a different zstd, mkfs.erofs or qemu-img can
write other bytes from the same input. CI uses Ubuntu 26.04's zstd, bsdtar,
erofs-utils, mtools, e2fsprogs and qemu-img, and the apko and Zig that
[test/ci-setup](../test/ci-setup) pins. In practice the first release rebuilt on a Mac with Homebrew's
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
server ([cloud.md](cloud.md)).

```sh
gh release download --repo werewolf-linux/werewolf --pattern 'prod-ssh-x86_64*'
# check it, as above; then QEMU, Lima, Proxmox and OpenStack take the qcow2 as it is.

# GCP wants a raw disk named disk.raw, in a gzipped tar:
qemu-img convert -O raw prod-ssh-x86_64-disk.qcow2 disk.raw
tar --format=oldgnu -Sczf werewolf.tar.gz disk.raw
gcloud storage cp werewolf.tar.gz gs://BUCKET/
gcloud compute images create werewolf --source-uri gs://BUCKET/werewolf.tar.gz \
    --guest-os-features UEFI_COMPATIBLE,GVNIC
```

The disk is 8 GiB, and stays so: a provider's larger disk leaves the rest
unused ([native-boot.md](design/native-boot.md#open-questions)). Beyond
virtio, `prod` carries GCP's devices (`forms/prod.modules`); AWS's ENA
and Azure's Hyper-V devices are not among them yet.

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

## Limits

- No release is booted from its published disk: CI boots each form directly
  and the slot path, and `make check` boots the demo's disk, which
  `boot/mkdisk` makes the same way.
- A release's `build` hashes its files; the updater's own build hash, in
  its log and reports, hashes the package list and kernel.
- Releases are kept; nothing prunes old ones.
