# Releases

[form-images.yml](../.github/workflows/form-images.yml) is the single image
publisher. It builds only `minimal`, `prod-ssh` and `playground` for aarch64 and x86_64
from pinned package snapshots on independent runners. GitHub and the R2 catalog
carry the passing images from this same three-form set.

## Boot profiles

| Profile | Boot requirements | Artifact |
| --- | --- | --- |
| `secure-boot` | Enrolled UEFI Secure Boot, IPE and a TPM release floor; updates itself from its channel | `FORM-PROVIDER-ARCH-secure-boot.qcow2` |
| `legacy-boot` | Ordinary UEFI or direct kernel/initramfs boot; no Secure Boot or TPM | `FORM-ARCH-legacy-boot.qcow2` |

Both profiles retain sandboxing and verified roots. Legacy boot also disables
IPE enforcement; its manifest explicitly records all three disabled protections.
A signed download authenticates its files, not the platform's boot environment.
`howl run` defaults to secure boot and never substitutes a legacy image.

Secure targets publish only after their exact bundles pass all twelve protected
lifecycle gates. QEMU covers all three published forms through a host-private owner
channel; Lima currently covers `playground` through SSH. Each target requires a
configured gate runner and passing evidence. Legacy targets require reproducibility,
coverage, integration, package-updater tests, raw/qcow2 parity and boots of the exact
qcow2 and direct
image without Secure Boot or a TPM.

## Publication

Relevant pushes publish `target=base`; the hourly run uses `target=all`.
Both select only the three published forms; manual dispatch retains both names for
compatibility. One
`base-images-SERIAL` GitHub release holds the verified assets for both profiles: disk
images, kernel/initramfs or signed slot files, package inputs, test evidence and signed
download manifests. Unpassed targets are omitted. The draft becomes public only after
attestation and authenticated R2 parity checks. Each target includes signed package
changes against its last published inventory. GitHub release notes also list included
PRs and contributors. A focused `playground/qemu/x86_64` dispatch remains available for
recovery.

Retries use a fresh publication timestamp in the GitHub tag, because published
releases are immutable. The signed image serials and source provenance stay intact.
Already published bundles reuse their verified signed exports, including the original
release notes, rather than regenerating files under an immutable object identity.

Protected R2 heads keep their namespace, `boot/v1/FORM/PROVIDER/ARCH`, which also holds
what installed machines' updaters fetch: each release, at its channel's next index,
replaces `latest.json` and adds `BUILD/` ([independent
updates](design/independent-updates.md)). Legacy objects and signed release floors live
under `legacy-boot/FORM/ARCH`; they never write protected heads. `boot-profiles.json` is
the signed inventory of both profiles; `index.json` remains the protected-only catalog.
See [form images](form-images.md) for enrollment, provider runners, release notes and
reproduction inputs.

Both download-manifest signatures use the committed `release/protected/image.crt`
identity. Secure Boot code uses the separate `release/protected/boot.crt` authority;
compatibility builds receive no code-signing or TPM credentials. The main-only
`release` environment supplies signing credentials to trusted export/publication jobs.

The previous independent image-release workflow is retired. Package publication
remains separate because installed package-updating systems still consume it.

Mac QEMU runners need a working IPv4 DNS server in their host network configuration.
Libslirp forwards guest IPv4 DNS to an IPv4 upstream; an IPv6-only host resolver
leaves guest lookups failing even when host downloads work. Add the network's IPv4
resolver alongside existing DNS servers, then verify DNS from a guest. The workflow
installs missing Mac runtime packages.

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
