# Releases

[form-images.yml](../.github/workflows/form-images.yml) is the single image
publisher. It builds only `minimal`, `prod-ssh` and `playground`, for aarch64
and x86_64, from pinned package snapshots on independent runners.

## Boot profiles

| Profile | Boot requirements | Artifact |
| --- | --- | --- |
| `secure-boot` | Enrolled UEFI Secure Boot, IPE, persistent TPM and host permit service | `FORM-PROVIDER-ARCH-secure-boot.qcow2` |
| `legacy-boot` | Ordinary UEFI or direct kernel/initramfs boot; no Secure Boot or TPM | `FORM-ARCH-legacy-boot.qcow2` |

Both profiles retain sandboxing and verified roots. Legacy boot also disables
IPE enforcement; its manifest explicitly records all three disabled protections.
A signed download authenticates its files, not the platform's boot environment.
`howl run` defaults to secure boot and never substitutes a legacy image.

Secure targets publish only after their exact bundles pass all fourteen protected
lifecycle gates. Today that harness supports only `playground`; `minimal` and
`prod-ssh` secure targets remain unpublished until their lifecycle control is
implemented. Legacy targets require reproducibility, coverage, integration,
package-updater tests, raw/qcow2 parity and boots of the exact qcow2 and direct
image without Secure Boot or a TPM.

## Publication

The workflow runs hourly, after relevant pushes, or by manual dispatch with
`target=all`. One `base-images-SERIAL` GitHub release holds the verified assets
for both profiles: disk images, kernel/initramfs or signed slot files, package
inputs, test evidence and signed download manifests. Unpassed targets are omitted.
The draft becomes public only after attestation and authenticated R2 parity checks.
A focused `playground/qemu/x86_64` dispatch remains available for recovery.

Protected R2 heads keep their existing namespace for installed clients. Legacy
objects and signed release floors live under `legacy-boot/FORM/ARCH`; they never
write protected heads. `boot-profiles.json` is the signed inventory of both profiles;
`index.json` remains the protected-only catalog. See [form images](form-images.md)
for enrollment, provider runners, release notes and reproduction inputs.

Both download-manifest signatures use the committed `release/protected/image.crt`
identity. Secure Boot code uses the separate `release/protected/boot.crt` authority;
compatibility builds receive no code-signing or TPM credentials. The main-only
`release` environment supplies signing credentials to trusted export/publication jobs.

The previous independent image-release workflow is retired. Package publication
remains separate because installed package-updating systems still consume it.

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
