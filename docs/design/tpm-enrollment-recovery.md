# TPM enrollment recovery

## Summary

Finish interrupted enrollment using the original publisher-held credentials and a separate signed bootstrap.
Never clear a TPM, replace its reset authority or write a factory pair over existing authorization history.

## Background

Enrollment changes owner auth, lockout auth, clear protection, NV definition and the factory anchor.
A power cut can leave a TPM partially initialized; ordinary bootstrap must continue to refuse that state.
The [bootstrap protocol](tpm-bootstrap-protocol.md) supplies attested, publisher-authenticated encrypted delivery.

## Goals

- Recover every durable boundary before the first NV extension using the same credentials.
- Authenticate existing owner and lockout authority before completing missing steps.
- Refuse completed, retired, foreign-policy and legacy indices before activating credentials.
- Keep exact-pair A/B upgrades and rollback unchanged.

## Non-Goals

- Reset or force enrollment, rotate credentials or bypass missing publisher custody.
- Recover arbitrary TPM configurations or prove physical-device power-loss atomicity.
- Enable cloud deployment before transport and provider lifecycle validation.

## Detailed design

### Admission

Build with `tools/build-tpm-bootstrap --recovery`; the signed command line carries `werewolf.recovery=1`.
Only secure native bootstrap permits that flag; normal workload boots reject it.
Its measured PCR differs from ordinary enrollment, binding quotes and encrypted capsules to this mode.
Ordinary enrollment still requires a fresh TPM; it never infers recovery from guest state.

Read hierarchy policies, permanent flags, owner enablement and Werewolf NV public areas.
Recovery requires owner auth already set, no hierarchy policy overrides and no legacy index.
If the pair index exists, require both reset credentials, disable-clear and its exact expected public area.
Reject any written index, regardless of whether its anchor resembles the factory state.
Read-only admission runs before readiness, key creation and capsule activation.
The immutable factory signature, machine/digest, actual PCR and publisher capsule signature still apply.

### Authority and completion

Publisher custody must retain the original two random credentials before the first enrollment mutation.
Load that durable custody; do not generate substitutes because a TPM reports partial state.
Authenticate owner with a hierarchy-control no-op that retains its enabled state and auth value.
If lockout auth exists, authenticate it by retaining the exact same credential.
Recheck admission after authentication; refuse unexpected progress rather than guessing which steps ran.
Set lockout auth only when absent; disable clear if needed; define only an absent pair index.
Never undefine, rewrite or clear an existing index, and never change owner auth during recovery.
Protect the platform hierarchy before the first NV extension in both fresh enrollment and recovery.
Then extend the factory digest once, verify the full protected anchor and wipe secrets before reboot.

### Uncertain replies

Every step before NV extension is recoverable by inspection and authentication with the original credentials.
The first extension is terminal: all reset guards already hold when its TPM command executes.
If execution succeeded but its reply was lost, recovery refuses the written index before releasing secrets.
The controller must attempt normal factory boot and require its mandatory protected-state/readiness checks.
A network acknowledgement alone cannot authorize workload startup.

## Drawbacks

Adds an explicit boot mode and requires retained publisher custody; recovery cannot manufacture lost secrets.

## Alternatives Considered

- Automatic partial-state completion weakens the normal enrollment replay guard.
- Clearing or replacing an index destroys authorized rollback history.
- Sending reset credentials to ordinary workload code exposes authority to guest root.

## Security Considerations

Attestation binds the separate recovery image and provider-pinned EK; encryption alone is insufficient.
Wrong owner or existing lockout credentials must refuse before effective authority or NV changes.
Wrong-credential attempts may affect TPM dictionary-attack accounting; recovery never resets that accounting.
Completed and retired pairs cannot enter recovery, even with a valid old factory permit.

## Reliability Considerations

Test before/after each command and after execution with the reply dropped, preserving persistent TPM state.
Repeat cuts during recovery; verify exact readback and unchanged credentials independently.
Signed VM tests must cover normal-bootstrap partial refusal and recovery-mode measurement binding.
Existing reset-refusal and A/B retirement tests remain required; provider and physical TPM tests remain separate.
