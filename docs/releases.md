# Releases

CI publishes three forms, `minimal`, `prod` and `prod-ssh`, for aarch64
and x86_64, as GitHub releases. It makes a release only when an image
would change, usually within the hour of a fix reaching Wolfi or
werewolf's kernel, and anyone can rebuild a release byte for byte from
what it carries.

`prod` is the production base: a machine that takes its address by DHCP, keeps itself
current, and listens on nothing. `prod-ssh` is `prod` with sshd, for an operator to
reach by security key (`ed25519-sk` or `ecdsa-sk`, touched); a key file is refused.
Every form is also built, with every protection, by the [image
pipeline](form-images.md), which publishes the protected downloads `howl run` takes by
default. How soon a machine boots a fix comes from [the CVE tiers feed](cve-feed.md).

## What a release holds

| File | |
| --- | --- |
| `FORM-ARCH-disk.qcow2` | a UEFI boot disk of 8 GiB holding the slot: what a VM boots from ([Deploying](#deploying)) |
| `FORM-ARCH-vmlinuz` | the kernel |
| `FORM-ARCH-stage0.zst`, `FORM-ARCH-root.erofs`, `FORM-ARCH-cmdline` | the slot and the kernel arguments for werewolf's native disk |
| `minimal-ARCH-initramfs.zst`, `minimal-ARCH-cmdline` | the whole image, and the kernel arguments its host passes, for direct boot |
| `FORM-ARCH-uki` | the whole slot as one signed PE (tools/uki) for firmware with Secure Boot on and the boot key enrolled; listed when the release was signed with one ([design/verified-boot.md](design/verified-boot.md)) |
| `FORM-ARCH.json`, `FORM-ARCH.json.sig` | the manifest, signed |
| `FORM.lock.json`, `kernel.lock.json`, `boot.lock.json` | every package, pinned: apko's locks |
| `inputs` | what the release was built from |

The manifest (`"format": "werewolf-release/1"`) names the form, arch,
`serial` (the tag: the time CI signed it), `kernel`, each file's sha256
and size, and the root image's `packages`, for CVE reports. `build` is the
first 16 hex digits of the sha256 of the files' `sha256sum` lines, in
manifest order: two releases with the same `build` have the same images.
`advisories` is [release/advisories](../release/advisories), werewolf's
own security fixes, which no CVE names; a machine boots a release that
carries one its own image lacks as soon as that advisory's tier says
([design/update-policy.md](design/update-policy.md#werewolfs-own-fixes)).

## When CI releases

[release.yml](../.github/workflows/release.yml) runs every 15 minutes (at
7, 22, 37 and 52, since GitHub runs schedules on the hour late), for what
Wolfi and werewolf's kernel repository change, and after the `packages`
workflow has run on `main`, for what werewolf changes, so the packages a
change brings are published first.

1. **Inputs.** `make release-inputs` resolves fresh locks for the forms,
   stage0, the kernel and systemd-boot, and writes `inputs`: a digest of
   the files that build the images, and every package's URL. CI keeps a
   cache entry per digest; if these inputs were built before, the run stops.
2. **Build, twice.** Each architecture is built on two runners from those
   locks, and the two must match byte for byte.
3. **Boot.** Each form boots under QEMU and passes `make check`
   ([testing.md](testing.md)), and `make check-dist` boots each published
   disk, the very file, under UEFI firmware, judging its posture as the
   form ships.
4. **Compare.** If every image's `build` matches the latest release's, as
   after a change to a comment, nothing is published.
5. **Publish.** The manifests are signed (`release/with-boot-key` holds the
   key as a file only for the build), the release is made as a draft, its
   files are attested with Sigstore, and the draft is published.

A fixed CVE arrives as a new package or kernel, so the next run releases
it. GitHub keeps releases immutable, and a manifest does not expire: the
next release supersedes it, and its serial forbids going back. `expires`
is the end of 9999, there only for updaters from before 2026-10-08.

## Reproducing a release

```sh
git checkout COMMIT                  # from the release notes
mkdir -p build/lock
gh release download TAG --dir build/lock --pattern '*.lock.json'
make dist                            # and ARCH=x86_64 make dist on arm64
grep '"build"' dist/*.json           # compare with the release's manifests
```

Fetch the locks after the checkout: a lock older than its config is
resolved again. The bytes repeat because apko installs exactly what the
locks name; werewolf's files go in as a normalized tar (sorted, root's,
modes 644 or 755, dated 1970); the cpio, erofs and disk carry no inode
numbers, times or random identities (`cmd/howl/disk.zig`); and no time,
host or path reaches an image. The toolchain must match too: Ubuntu
26.04's zstd, bsdtar, mtools, e2fsprogs and qemu-img, and the erofs-utils,
apko and Zig that [tools/install-deps](../tools/install-deps) pins (on a
Mac too; Homebrew's Zig names its linker in the binary). `inputs` leaves
the toolchain out, so a new runner image alone does not make a release.

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
itself current through apk ([updater.md](updater.md)): releases are for
installs. Its config comes from a config disk, NoCloud, or the cloud's
metadata server ([cloud.md](cloud.md)). Secure Boot must be off unless the
boot key is enrolled ([cloud.md](cloud.md#signed-boot)).

```sh
gh release download --repo werewolf-linux/werewolf --pattern 'prod-ssh-x86_64*'
```

Check it, as above. QEMU, Lima, Proxmox and OpenStack take the qcow2 as it is; `howl
create NAME --on gcp|aws|azure` makes a cloud machine of a form
([service-vms.md](service-vms.md)). By hand, each cloud wants its own format, and on
aarch64 must be told the architecture: GCP a raw `disk.raw` in a gzipped tar, made an
image with `UEFI_COMPATIBLE,GVNIC` ([service-vms.md](service-vms.md#gcp-vm)); AWS an EBS
snapshot, which `howl upload DISK.qcow2 --on aws` writes directly and registers as a
UEFI AMI, with nothing to set up first; Azure a fixed-size VHD (`qemu-img convert -O vpc
-o subformat=fixed,force_size`) made a Gen2 managed disk and attached as one VM's OS
disk. `prod` carries each cloud's devices (`forms/prod/form.yaml`), tested for real in
`make check-gcp`, `check-aws` and `check-azure` ([testing-live.md](testing-live.md)).
The disk is 8 GiB; a larger one leaves the rest unused
([native-boot.md](design/native-boot.md#open-questions)).

## The key

The image key is RSA-4096 because it will also sign IPE policies, which
the kernel checks. Its private half is the secret `WEREWOLF_IMAGE_KEY` in
the GitHub environment `release`, which only the release workflow on
`main` uses; its public half is `release/image.pub`:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out image.key
openssl pkey -in image.key -pubout -out release/image.pub
gh api -X PUT repos/werewolf-linux/werewolf/environments/release
gh secret set WEREWOLF_IMAGE_KEY --env release <image.key
```

Then limit the environment to `main`, commit `release/image.pub`, and keep
`image.key` offline. Until both exist, the workflow builds and checks, then
fails at signing and publishes nothing. The boot key is the same
arrangement for Secure Boot: RSA-2048, `release/boot.crt` and
`WEREWOLF_BOOT_KEY`. Each release then carries its `uki`, signed at a
fixed time so independent builds match, and firmware holding the
certificate boots only what that key signed; without the secret, a
release ships with no UKI. These releases lack the IPE and TPM profile of
the protected downloads ([form-images.md](form-images.md)).

## Packages

werewolf's programs and forms are also apk packages, at
`https://dist.werewolf-linux.org/apk/ARCH/` in the R2 bucket `werewolf`
([custom-updates.md](design/custom-updates.md)): `werewolf-PROGRAM` for
each program, `werewolf-advisories`, and `NAME-form` for each form but
those with melange recipes. When check passes on main, the packages
workflow packs both arches twice, requires the copies to match, and
publishes (`release/packages`) only the packages whose files changed, with
the index signed again by `release/packages.pub`'s key,
`WEREWOLF_PACKAGES_KEY`. Published packages are never replaced or removed,
and nothing is published until the repository variable `PUBLISH_PACKAGES`
is `true`. Each package depends on `werewolf-formatN`, N numbering the
files compose writes (`format` in lib/compose.zig); bump it on an
incompatible change, and machines on the old one keep the last packages
for it.

## Limits

The published disks boot in CI under QEMU alone, not on a cloud. Releases
are kept; nothing prunes old ones. Opt-in IPE channels take complete
signed slots rather than packages: `make prebuilt`
([design/prebuilt-images.md](design/prebuilt-images.md)).
