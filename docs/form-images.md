# Form images

One workflow publishes only `minimal`, `prod-ssh` and `playground`, on aarch64
and x86_64. Each has two explicit boot profiles: `secure-boot` requires
Secure Boot, IPE and an enrolled TPM; `legacy-boot` runs without those three
requirements, retaining sandboxing and the verified root. Download signatures
and attestations authenticate both profiles. Browse the
[image catalog](https://dist.werewolf-linux.org/boot/v1/index.html) or run
`howl forms --published` for protected targets. `howl run` continues to require
the secure profile; it never falls back to a compatibility disk. Legacy assets
are explicit downloads from the same GitHub release ([releases.md](releases.md)).

## The pipeline

[form-images.yml](../.github/workflows/form-images.yml) runs on pushes to
main that touch a form, hourly, and on demand. Each target's digest covers its
form chain, shared code and tests, trust, exact packages and checksums, OCI
digests, melange environments and host tools. An authenticated catalog row with
matching inputs and a passing attempt skips the build; failures retry every run.
`force` rebuilds the selected targets.

Manual dispatch defaults to `target=all`, selecting the three published forms.
`target=playground/qemu/x86_64` keeps a focused recovery lane. Focused builds
run alongside full builds. A shared publication lock protects the catalog;
other targets keep their status, inputs and previous release.

A changed form is built by `release/build-protected` for each provider of
its architecture, with the dedicated boot and image keys: signed UEFI
boot, IPE, a verified root and TPM-anchored A/B updates, nothing given up.
A provider's gateway is baked into the verified root, so each form,
provider and architecture is its own image. Two independent native Linux
runners build it, with no restored compiled output, and the bundles must
match byte for byte: each runner records every file's SHA-256, and only a
form with gates ships its bundles on to later jobs. The form must then meet its
[form integration coverage](testing.md#form-integration-coverage) and pass
`howl test --with FORM --arch ARCH`; `tests.json` records both, with the
descriptor of each bundle they cover. None of these jobs holds the
signature that admits a bundle.

The gate job authorizes three candidates of a target with the image key,
on the runner that boots them, and runs all fourteen
[lifecycle gates](design/protected-downloads.md) on the exact files
(`test/check-published-lifecycle`). That harness drives a shell over ssh,
so only `playground` has gates today; other forms are built and tested
but read `not published: no lifecycle gates for this form`.

`legacy-build` uses the same resolved form/package snapshots on independent
runners, without code-signing or TPM credentials. `legacy-check` compares the
bytes, runs coverage, integration and package-updater checks, checks raw/qcow2
parity, and boots the exact qcow2 under ordinary UEFI and the exact kernel/initramfs
directly, without a TPM. Publication
signs a separate `werewolf-legacy-downloads/1` manifest with
`boot_profile: legacy-boot`; it cannot be admitted as a protected boot descriptor.
Its immutable objects and release floor live under `legacy-boot/FORM/ARCH`.

Both profiles enter one `base-images-SERIAL` GitHub release, with attested assets
and R2 parity checks before the draft becomes public. The old scheduled
image publisher is retired. `boot-profiles.json` is the signed inventory of both
profiles; `index.json` preserves the protected catalog used by existing clients.
The HTML catalog labels the profiles separately.

| Target | Gate runner |
| --- | --- |
| qemu/x86_64 | GitHub-hosted `ubuntu-26.04`, with KVM |
| qemu/aarch64 | self-hosted Linux arm64 with KVM, named by the `WEREWOLF_ARM64_KVM_RUNNER` variable |
| lima/aarch64 | self-hosted macOS arm64 with Lima, named by the `WEREWOLF_LIMA_RUNNER` variable |

Each repository variable is a JSON list of runner labels, such as
`["self-hosted", "macOS", "ARM64", "werewolf-lima"]`; the dedicated label
keeps the gate off unrelated machines. A target with no runner is built
and tested but not published. A self-hosted gate runner holds the image
key during the job, so it serves this repository alone (the workflow never
runs for pull requests). It keeps what `test/ci-setup` installs, and Lima
on macOS; nothing else on it may listen on port 9443.

A target that fails its profile's checks is not published; the others are, and
the catalog keeps the last published release beside the failed attempt.
[publishing-health.yml](../.github/workflows/publishing-health.yml)
reports failures and recovery. The scripts are `release/form-images`,
`release/image_catalog.py` and `release/image_notes.py`. Pull requests run
the QEMU lifecycle with disposable keys instead
([protected-images.yml](../.github/workflows/protected-images.yml)), with
no production secrets and no upload.

```text
boot/v1/index.html                                 browse every form
boot/v1/index.json                                 catalog, signed by the image key
boot/v1/FORM/index.html                            targets, downloads and status
boot/v1/FORM/PROVIDER/ARCH/latest/boot.json[.sig]  signed boot head
boot/v1/FORM/PROVIDER/ARCH/objects/DESCRIPTOR/     immutable bundle: slot, disk.img.zst,
    disk.qcow2, heads, gates.json, tests.json, inputs.tar.gz, packages.json,
    release-notes.{html,json}, downloads.json[.sig]
```

`howl forms --published` verifies `index.json` against the committed
`release/protected/image.crt`; it embeds its signed JSON as `manifest`
with a hex RSA `signature`.

### Release notes

Each published release carries HTML and JSON release notes, linked from
the image pages, `howl forms FORM --published` and the job summary. They
compare with the previous published image of the same form, provider and
architecture, never with a failed attempt: packages added, removed,
updated, or rebuilt at the same version with different content, and
changed OCI image digests, with a source comparison when the commit
changed. `packages.json` lists the resolved packages by group: image
packages, local recipes, kernel inputs, and build or test dependencies,
which are inputs, not software in the VM. The previous inventory is
checked against its signed download manifest, and the new manifest binds
the inventory and both notes.

## Protected production downloads

`howl run` takes a production-signed download by default for a published
target; `--build` makes the image here, signed with your own keys. A
machine signed locally keeps its trust; adopt a download under a new
name. The trust and layout are in
[design/protected-downloads.md](design/protected-downloads.md).

The release is made by `release/export-protected`, which admits the gated
bundle and derives a compressed qcow2 from the authenticated raw disk,
checked with `qemu-img check` and `compare`, under a separately signed
`werewolf-downloads/1` manifest that binds every asset's size and
SHA-256, the boot descriptor, the lifecycle evidence, the commit and the
run; the pipeline adds the test evidence, rebuild inputs, inventory and
notes. `release/publish-protected` rechecks the trust and gates, uploads
immutable objects to R2 before the signed heads, and keeps a floor across
an interrupted upload; `release/check-protected-download` then fetches
from the public endpoint, admits it as a machine would, and compares
every R2 object with its GitHub asset. A run's one draft release goes
public only after attestation, the upload and that comparison succeed
for every target it carries.

GitHub releases are tagged `base-images-SERIAL`, with assets named
`FORM-PROVIDER-ARCH-FILE`: the qcow2, the compressed raw disk, the slot
files, both signature pairs, the public certificates, the gates and the
download manifest, each with a build provenance attestation.

### Downloading images

A `base-images-SERIAL` release carries `FORM-PROVIDER-ARCH-secure-boot.qcow2`
(and its canonical `disk.qcow2` name) for secure targets, and
`FORM-ARCH-legacy-boot.qcow2` for compatibility targets. Each target has a signed
`downloads.json` mapping every filename to its size and SHA-256. Verify that
signature against `release/protected/image.crt`, then verify the file hashes and
GitHub build attestations before importing a disk.

Importing a secure disk creates no firmware enrollment, TPM state or host permit
service: use `howl` for protected deployment. Its host service polls every five
minutes, and the guest follows its [update policy](updater.md#when-an-update-boots).
Legacy boot uses the package updater and carries no protected enrollment.

### Installing a particular version

List versions with a complete bundle for your target, then start a new machine:

```sh
howl versions --with playground --on qemu --arch x86_64
howl create upgrade-test --with playground --on qemu --version 20261014T232908Z
```

`howl run` also takes `--version`. A timestamp, full `base-images-SERIAL` tag,
or older `protected-SERIAL` tag selects the initial image from GitHub releases.
Discovery supports `--json`; its defaults are playground and the host's provider and
architecture. Every install still verifies the embedded vendor keys and signed
artifacts. An explicit version has a separate cache floor, so it can install an old
image without lowering the latest channel's floor. It requires the download path;
`--build` and `--disable` cannot be combined with it. Use a new machine name to test
upgrades: existing enrollments retain their rollback protection. The version selects
the initial image; the host service still polls the latest channel for image updates.
