# TPM retirement with A/B recovery

## Summary

Authorize an exact TPM release pair; commit preserves both and replacement retires one.
Status: opt-in guest enforcement; QEMU x86_64 lifecycle and power cuts verified.

## Background

The serial prototype broke A/B recovery; signatures alone permit old-image replay.

## Goals

- Boot either authorized slot after commit, operator rollback or a failed trial.
- Reject replayed state, changed transitions and unauthorized TPM reset commands.
- Preserve the running release across every durable installation boundary.
- Verify actual TPM commands independently against tpm2-tools trial sessions.

## Non-Goals

- Defend against a host administrator who replaces the TPM or firmware state.
- Prevent guest root from deleting disks or falsifying service health.
- Treat TPM presence or an unmeasured UKI as protected rollback.

## Detailed design

### Exact authorization

A 176-byte state record has a 16-byte tag and five SHA-256 fields: machine nonce,
previous anchor, retained release ID, candidate release ID and retained PCR 11.
Release IDs bind architecture, root, kernel, stage0, EFI stub and signed boot arguments;
compute them before adding the ID to the UKI command line to avoid self-hashing.
The signer verifies this mapping; the initial pair repeats the factory release.

Index `0x01500021` is SHA-256 NV-extend storage with public reads and signed
policy writes. Its value is `H(previous-anchor || H(record))`.
Host initializes from zero; a unique nonce and signed policy bind each exact extension.
Host-only owner and lockout credentials protect provisioning and deletion;
clear is disabled; platform authority is disabled or locked by trusted firmware.
Empty platform auth and any hierarchy-policy override fail closed.

The writer policy combines `PolicyNV(old-anchor == NV)`, `PolicyPCR(PCR 11)`,
`PolicyCpHash(exact NV_Extend)` and `PolicyAuthorize` with `werewolf.boot/2`. The
external signer checks that the retained release belongs to the old pair. PCR binding
prevents root from replaying a preissued later transition while still running the
release that transition would retire. The [NV-extend
command](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_nvextend.1.md)
hashes the old value with the input. Select a TPM-enabled `UKI_STUB`; Alpine disables
measurement. Boot refuses zero PCR 11; predictions follow the [stub
rules](https://github.com/systemd/systemd/blob/main/docs/TPM2_PCR_MEASUREMENTS.md).

Boot verifies the record's signature, matches its resulting anchor to the TPM,
and requires the sealed release ID to equal either authorized member.
Disk flags and serials grant no authority. Commit and rollback never mutate NV.
For `{A,B}` with B running, installing C changes authorization to `{B,C}`.
After an operator rollback to A, installing D retains A instead. Replayed permits
cannot restore an earlier anchor; deliberate reauthorization requires the signer.

### Durable installation

1. Authenticate and stage the candidate without changing either boot entry.
2. Persist the new signed record and permit in a two-record journal; sync.
3. Remove the inactive slot's entry; sync, leaving the running entry intact.
4. Extend the TPM and read back its anchor before replacing inactive files.
5. Install and verify the candidate files; sync. Arm its counted entry last; sync.
6. A healthy boot commits only the counted entry. Both releases remain authorized.

Keep both journal records outside slots until readback confirms the new anchor.
Serialize host permit issuance and hold the updater lock through journal writes, TPM
readback and entry arming;
[PolicyNV](https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/command/EA/PolicyNV.c)
is not an atomic compare-and-swap operation. After an uncertain command response, read
the TPM and select the matching record; never retry an extension blindly or trust a
disk-side completion flag. The retained slot works even with an incomplete candidate;
unknown anchors stop boot.

## Drawbacks

- Machine-specific permits require a host signer and durable enrollment custody.
- Retirement consumes NV writes and removes the replaced fallback permanently.
- PCR predictions must track the exact stub and UKI section contents.

## Alternatives Considered

- Commit-time serial floors break A/B recovery; two independent floors can tear.
- Retirement-only floors authorize extra releases and mishandle rollback ordering.
- Disk-only pairs permit replay; policies without PCR binding permit early retirement.

## Security Considerations

Firmware must trust only UKIs that require the new check. An older signed UKI
without mandatory enforcement bypasses it even with a correctly protected TPM.
The serial commit hook is removed; its enrollment fails closed. TPM presence
grants no protection. Signing, TPM reset and recovery credentials stay outside guests.

## Reliability Considerations

`test/check-tpm-ab` verifies actual policies, reset refusal and 11 modeled boundaries.
`test/check-tpm-guest` verifies QEMU x86_64 commit and operator rollback,
cuts before and after NV_Extend, lost replies and failed-trial recovery.
Retired releases, unmeasured UKIs and missing TPM devices stop before handover.
Tests keep disk and NV state through process kills; physical TPM atomicity is unproven.
Lima arm64 integration and AWS/GCP TPM enrollment remain open; the host is trusted.
