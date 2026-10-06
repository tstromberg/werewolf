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
| `FORM-ARCH-vmlinuz` | the kernel |
| `minimal-ARCH-initramfs.zst` | the whole image, for direct boot |
| `prod-ARCH-stage0.zst`, `prod-ARCH-root.erofs`, and the same for `prod-ssh` | the slot bite installs |
| `FORM-ARCH.json`, `FORM-ARCH.json.sig` | the manifest, signed |
| `minimal.lock.json`, `prod.lock.json`, `prod-ssh.lock.json`, `stage0.lock.json`, `kernel.lock.json` | every package, pinned: apko's locks |
| `inputs` | what the release was built from |

The tag is the manifests' serial, the time CI signed them. A release is
about 170 MB.

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
    "root.erofs": {"sha256": "779f06fb…", "size": 20717568}
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
every 15 minutes:

1. **Inputs.** `make inputs` resolves fresh locks for both forms, stage0
   and the kernel: the newest packages in Wolfi, and in Alpine's v3.24 for
   the kernel. It writes `inputs`: a digest of the files that build the
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
- **Nothing records the build.** No time, host or path reaches an image.

The toolchain must match too: a different zstd or mkfs.erofs can write
other bytes from the same input. CI uses Ubuntu 24.04's zstd, bsdtar and
erofs-utils, and the apko and Zig that [test/ci-setup](../test/ci-setup)
pins. In practice the first release rebuilt on a Mac with Homebrew's
tools came out the same, but for the updater: Homebrew's Zig names its own
linker in the binary, so use Zig's release tarball. `inputs` leaves the
toolchain out, so a new runner image alone does not make a release.

## Checking a release

```sh
openssl dgst -sha256 -verify keys/image.pub \
    -signature prod-ssh-x86_64.json.sig prod-ssh-x86_64.json
shasum -a 256 prod-ssh-x86_64-root.erofs        # against the manifest
gh attestation verify prod-ssh-x86_64-root.erofs --repo werewolf-linux/werewolf
```

The signature is RSA PKCS#1 v1.5 over the manifest's sha256. The
attestation ties each file to the workflow run and commit that built it.

## The key

The image key is RSA-4096 because it will also sign IPE policies, which
the kernel checks ([design/verified-boot.md](../design/verified-boot.md)).
Its private half is the secret `WEREWOLF_IMAGE_KEY` in the GitHub
environment `release`, which only the release workflow on `main` uses; its
public half is `keys/image.pub`. To set it up:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out image.key
openssl pkey -in image.key -pubout -out keys/image.pub
gh api -X PUT repos/werewolf-linux/werewolf/environments/release
gh secret set WEREWOLF_IMAGE_KEY --env release <image.key
```

Then limit the environment to `main` (Settings, Environments), commit
`keys/image.pub`, and keep `image.key` offline. Until both exist, the
workflow builds and checks, then fails at signing and publishes nothing.

## Limits

- Machines do not install releases yet: autoupdate builds each slot on the
  machine ([updater.md](updater.md)). Installing signed releases is phase 3
  of [design/verified-boot.md](../design/verified-boot.md).
- A release's `build` hashes its files; the updater's own build hash, in
  its log and reports, hashes the package list and kernel.
- Releases are kept; nothing prunes old ones.
