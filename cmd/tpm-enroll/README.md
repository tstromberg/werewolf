# tpm-enroll

## Summary

PID 1 of an isolated signed TPM bootstrap; enrolls or explicitly recovers, then reboots.

## Background

Cloud TPMs require attested encrypted delivery of reset credentials held by the publisher.
This program is packed separately by `tools/build-tpm-bootstrap`, never into a workload root.
See [the protocol](../../docs/design/tpm-bootstrap-protocol.md) and
[recovery](../../docs/design/tpm-enrollment-recovery.md).

## Goals

- Require secure firmware, measured identity and immutable publisher/factory trust.
- Protect the factory pair without exposing reset authority to workload code.
- Refuse replay and finish partial enrollment only in the separately signed recovery mode.

## Non-Goals

No shell, workload handover, TPM reset/clear or public administration service.
Cloud deployment and its provider transport remain gated.

## Detailed design

Mount only procfs, sysfs, devtmpfs, read-only firmware variables and securityfs.
Require SecureBoot=1, SetupMode=0, confidentiality lockdown and exact boot IPE enforcement.
Close module loading and drop policy administration; use built-in drivers only.
Check the immutable public factory signature and discover the named `werewolf.enroll` virtio port.
Bound file/device discovery and all framing; read kernel pseudo-files in streaming mode.
Require freshness or explicit read-only recovery admission before readiness and key creation.
Bind the peer's challenge to baked machine/factory identity and actual nonzero PCR 11.
Verify the publisher signature before activating encrypted credentials under the measured AK policy.
Verify protected readback and wipe credentials before acknowledging the public anchor and rebooting.
On refusal, halt instead of creating an automatic retry loop.

## Drawbacks

Needs a separate signed image, built-in TPM/virtio drivers and publisher custody.

## Alternatives Considered

Ordinary guest enrollment and plaintext metadata expose reset authority.
Implicit recovery weakens replay refusal; clearing a TPM destroys A/B authorization history.

## Security Considerations

Every factory/workload boot still requires the existing mandatory TPM authorization checks.
Recovery refuses written, foreign-policy and legacy indices; it retains existing reset credentials.
Only public trust/context enters the image; private signers remain on the publisher.

## Reliability Considerations

`make IPE=1 check-tpm-bootstrap-guest` tests firmware, measurement and encrypted enrollment refusals.
Recovery tests must preserve the TPM across every provisioning cut and repeated recovery interruption.
Provider transport, one-shot factory selection and provider lifecycle proof remain open.
