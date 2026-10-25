# Form images

One workflow publishes `minimal`, `prod-ssh`, `playground` and `postdoc-server` for
aarch64 and x86_64. `secure-boot` requires Secure Boot, IPE and an enrolled TPM;
`legacy-boot` keeps sandboxing and verified root without those requirements.
Signatures and attestations authenticate both. Browse the [image
catalog](https://dist.werewolf-linux.org/boot/v1/index.html) or run
`howl forms --published` for protected targets. `howl run` requires the secure profile.
Legacy assets download from R2; all forms ship in [GitHub releases](releases.md).

## The pipeline

[form-images.yml](../.github/workflows/form-images.yml) runs hourly, on demand and on
pushes to main that touch a form. Each target's digest covers its form chain, shared
code and tests, trust, exact packages and checksums, OCI digests, melange environments
and host tools. A passing authenticated catalog row with matching inputs skips the
build; failures retry every run.
`force` rebuilds the selected targets.

Pushes and manual dispatch default to `target=base`; the hourly run uses `target=all`.
Both scopes select exactly the same forms from `release/images.yaml`. Other forms remain
available for source builds and are excluded from image publication.
`target=playground/qemu/x86_64` keeps a focused recovery lane. Focused builds run
alongside full builds. A shared publication lock protects the catalog; other targets
keep their status, inputs and previous release.

A changed form is built by `build/host/release build-protected` for each provider of its
architecture, with the dedicated boot and image keys: signed UEFI boot, IPE, a verified
root and the TPM floor, nothing given up, at its channel's next release index, one past
the last published. A provider's gateway is baked into the verified root, so each form,
provider and architecture is its own image. Two independent native Linux runners build
it, with no restored compiled output, and the bundles must match byte for byte: each
runner records every file's SHA-256, and only a form with gates ships its bundles on to
later jobs. The form must then meet its [form integration
coverage](testing.md#form-integration-coverage) and pass `howl test --with FORM --arch
ARCH`; `tests.json` records both, with the descriptor of each bundle they cover. None of
these jobs holds the signature that admits a bundle.

Each gate job downloads one shard and judges its forms independently; a failed form
retains its evidence while other forms can publish. Unchanged forms need no
authorization or boot. A candidate's updater follows the public mirror its signature
names, so the job first proves this tree's updates, rollback, floor power cuts, refusal
of a retired release and failed-trial fallback on keys made for that step alone
(`test/check-independent-updates.zig`). For each changed target it then authorizes the
candidate with the image key and holds the exact files to the other [lifecycle
gates](design/protected-downloads.md) (`test/check-published-lifecycle.zig`). QEMU
drives published forms through the host-private owner channel; Lima uses SSH for
`playground` and `postdoc-server`. Postdoc also receives disposable API and tunnel
tokens and a host-only software security key on both providers. The gate checks its real
JIT server, analysis API, tunnel metrics and a persisted verdict after stop/resume; it
does not require a live Cloudflare tunnel or weaken the guest's security-key-only SSH
policy. Postdoc publication additionally requires update evidence from the
`postdoc-server` workload: its API and saved verdict are checked after every committed
upgrade and rollback in the signed A/B sequence, including recovery after power cuts and
a failed trial.

`legacy-build` uses the same resolved form/package snapshots on independent
runners, without code-signing or TPM credentials. `legacy-check` compares the
bytes, runs coverage, integration and package-updater checks, checks raw/qcow2
parity, and boots the exact qcow2 under ordinary UEFI and the exact kernel/initramfs
directly, without a TPM. Publication
signs a separate `werewolf-legacy-downloads/1` manifest with
`boot_profile: legacy-boot`; it cannot be admitted as a protected boot descriptor.
Its immutable objects and release floor live under `legacy-boot/FORM/ARCH`.

Both profiles enter one `base-images-SERIAL` GitHub release. Changed images (`minimal`,
`prod-ssh`, `playground`, `postdoc-server`) are attached and listed in R2. All assets
receive attestations and R2 parity checks before the draft becomes public. Signed
package changes compare each target with its own last published inventory, and GitHub
generates the included PR and contributor notes. The old scheduled image publisher is
retired. `boot-profiles.json` is the signed inventory of both profiles; `index.json`
preserves the protected catalog used by existing clients. After publication, native QEMU
runners use a fresh source-free consumer to discover each new image in the signed public
catalog, download it from R2, verify its protected boot, repeat the command, check its
authenticated update channel, and stop and resume it. This adds no guest shell or test
code; the full two-update A/B and power-cut sequence runs before publication. The HTML
catalog labels the profiles separately.

| Target | Gate runner |
| --- | --- |
| qemu/x86_64 | GitHub-hosted `ubuntu-26.04`, with KVM |
| qemu/aarch64 | self-hosted Linux arm64 with KVM, named by the `WEREWOLF_ARM64_KVM_RUNNER` variable |
| lima/aarch64 | self-hosted macOS arm64 with Lima, named by the `WEREWOLF_LIMA_RUNNER` variable |

Each repository variable is a JSON list of runner labels, such as `["self-hosted",
"macOS", "ARM64", "werewolf-lima"]`; the dedicated label keeps the gate off unrelated
machines. A target with no runner is built and tested but not published. A self-hosted
gate runner holds the image key during the job, so it serves this repository alone (the
workflow never runs for pull requests). It keeps what `test/ci-setup` installs, and Lima
on macOS. Separate consumer state can run concurrently.

A target that fails its profile's checks is not published; the others are, and the
catalog keeps the last published release beside the failed attempt.
[publishing-health.yml](../.github/workflows/publishing-health.yml) reports failures and
recovery. The pipeline is `build/host/release form-images`
([tools/release](../tools/release/README.md)); the published forms, profiles,
architectures and gates are [release/images.yaml](../release/images.yaml). Pull requests
run the QEMU lifecycle with disposable keys instead
([protected-images.yml](../.github/workflows/protected-images.yml)), with no production
secrets and no upload.

```text
boot/v1/index.html                                 browse every form
boot/v1/index.json                                 catalog, signed by the image key
boot/v1/FORM/index.html                            targets, downloads and status
boot/v1/FORM/PROVIDER/ARCH/latest.json[.sig]       the channel machines update from
boot/v1/FORM/PROVIDER/ARCH/BUILD/                  each release's slot files
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

`howl run` downloads production-signed images for published targets; `--build` uses your
own keys. Locally signed machines keep their trust; adopt downloads under a new name.
See [design/protected-downloads.md](design/protected-downloads.md) for trust and layout.

`release export-protected` admits the gated bundle and derives a qcow2 from its
authenticated raw disk. Its signed `werewolf-downloads/1` manifest binds every
asset's size and SHA-256, descriptor, lifecycle evidence, source commit and run.
`release publish-protected` uploads immutable objects before signed heads and keeps
an upload recovery floor. `release check-protected-download` fetches from public R2,
performs native admission, and compares every object with its release asset. The
GitHub draft becomes public after attestation and parity checks for every target.

### Downloading images

A `base-images-SERIAL` release carries `FORM-PROVIDER-ARCH-secure-boot.qcow2`
(and its canonical `disk.qcow2` name) for secure targets, and
`FORM-ARCH-legacy-boot.qcow2` for compatibility targets. Each target has a signed
`downloads.json` mapping every filename to its size and SHA-256. Verify that
signature against `release/protected/image.crt`, then verify the file hashes and
GitHub build attestations before importing a disk.

Importing a secure disk does not enroll its firmware: use `howl` for protected
deployment. The machine's own updater then follows its channel, and its [update
policy](updater.md#when-an-update-boots) decides when a release boots.
Legacy boot uses the package updater and carries no protected enrollment.

### Installing a particular version

List versions with a complete bundle for your target, then start a new machine:

```sh
howl versions --with playground --on qemu --arch x86_64
howl create upgrade-test --with playground --on qemu --version 20261014T232908Z
```

`howl run` also takes `--version`: a timestamp, `base-images-SERIAL` tag or older
`protected-SERIAL` tag selects the initial GitHub image. Discovery supports `--json`
and defaults to playground on the host's provider and architecture. Every install
verifies vendor keys and signatures. Explicit versions have a separate cache floor;
older images cannot lower the latest channel's floor. They require downloads and
cannot use `--build` or `--disable`. Test upgrades under a new machine name: existing
enrollments retain rollback protection. Updates still follow the channel to the latest.
