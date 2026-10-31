# Microsoft's third-party UEFI CAs

Azure's firmware keeps Microsoft's PK: a gallery image that brings its own PK boots
in setup mode. So `howl` takes Azure's `MicrosoftUefiCertificateAuthorityTemplate`,
adds the image's boot certificate to db, and revokes in dbx the certificates that
template trusts, which sign every other vendor's loader. Firmware then admits the
image's signer alone, as on GCP and AWS, and stage0 checks that it does.

The first three certificates are Microsoft's published Secure Boot objects,
[microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects)
`PreSignedObjects/DB/Certificates`, taken 2026-10-24; the fourth is Azure's own
UEFI db authority captured from a Trusted Launch VM's `db` efivar:

| File | Subject | SHA-256 |
|------|---------|---------|
| `microsoft-corporation-uefi-ca-2011.der` | Microsoft Corporation UEFI CA 2011 | `48e99b991f57fc52f76149599bff0a58c47154229b9f8d603ac40d3500248507` |
| `microsoft-uefi-ca-2023.der` | Microsoft UEFI CA 2023 | `f6124e34125bee3fe6d79a574eaa7b91c0e7bd9d929c1a321178efd611dad901` |
| `microsoft-option-rom-uefi-ca-2023.der` | Microsoft Option ROM UEFI CA 2023 | `e5be3e64c6e66a281457ecdece0d6d0787577aad2a3a0144262c10c14ba8d8f1` |
| `azure-services-linux-kmod-pca.der` | Azure Services Linux Kmod PCA | `ca400f913ac6a55a5cc8629ce8d2b847bfa0fccad20a4d133c1f76dab2b36925` |

`shasum -a 256 boot/microsoft/*.der` reproduces the table. A new Microsoft CA in the
template shows up as a stage0 refusal naming the extra signer; add it here.
