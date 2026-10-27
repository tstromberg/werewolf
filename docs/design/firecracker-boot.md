# Firecracker boot files

Firecracker cannot expose UEFI Secure Boot or the TPM used for the release floor.
Its default mode retains IPE, dm-verity, the seal and fence. Before the first boot,
howl records the freshly built kernel, stage0 (including its root hash and signed IPE
policy) and boot entry in `firecracker-boot.json` outside the guest. Each boot checks
them against that record and ignores other guest-written boot entries. Missing or
malformed records and changed boot files fail closed. Existing unprotected disks are
never enrolled automatically. Image changes require a host rebuild; `IPE_UPDATES` and
protected UEFI downloads selected with `--version` are refused in this mode.

This host check does not supply firmware Secure Boot or a TPM: the trusted host can
replace the record, and restoring older host state can restore an older vulnerable
release. Keep that state outside guest access. The warning and guest command line
name both missing protections. `--disable=secureboot,tpm` explicitly selects the same
mode. `--disable=secureboot,tpm,ipe` selects the legacy Firecracker path, including
its guest-controlled A/B updates, and does not pin its boot files.
