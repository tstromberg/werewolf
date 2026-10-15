# Form images

Every form is built, with every protection, for each target it can run
on: QEMU on aarch64 and x86_64, and Lima on aarch64, where the form allows
the architecture. A target is published, and is what `howl run --with
FORM` downloads by default, only when its exact bundle has passed the
protected lifecycle gates. Browse the
[image catalog](https://dist.werewolf-linux.org/boot/v1/index.html) or run
`howl forms --published`. `minimal`, `prod` and `prod-ssh` are also GitHub
releases of an older kind ([releases.md](releases.md)).

## The pipeline

[form-images.yml](../.github/workflows/form-images.yml) runs on pushes to
main that touch a form, hourly, and on demand. Each form and architecture
has a digest over everything that reaches its image: its form chain,
shared code and tests, trust, exact package versions and checksums, OCI
digests, melange environments and host tool versions. A target whose
signed catalog row carries the same digest and a passing attempt is
skipped; a doc change or another form rebuilds nothing, and a failure is
retried every run. Dispatching with `force` rebuilds everything, as after
adding a gate runner.

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

A target that fails any of this is not published; the others are, and
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

GitHub releases are tagged `protected-SERIAL`, with assets named
`FORM-PROVIDER-ARCH-FILE`: the qcow2, the compressed raw disk, the slot
files, both signature pairs, the public certificates, the gates and the
download manifest, each with a build provenance attestation.

### Downloading a protected qcow2

Choose a `protected-SERIAL` release with assets for your form, provider
and architecture; the x86_64 QEMU playground disk is
`playground-qemu-x86_64-disk.qcow2`. On a matching Linux host,
`howl run --on qemu` downloads and authenticates the bundle, enrolls
firmware and TPM, and starts the host permit service. To inspect or
archive the disk itself, from a trusted checkout:

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

Stop if a signature or digest fails. The qcow2 holds the same protected
system, but importing it into a hypervisor makes no owner keys, firmware
enrollment, TPM state or host permit service: use howl for a protected
deployment. Its host service polls for authenticated vendor bundles every
five minutes, and the guest applies them under its
[update policy](updater.md#when-an-update-boots). A/B recovery and
retirement protection depend on keeping that machine's enrollment and
host service. A GitHub release disk uses the package updater and gains
no protected profile by being imported.
