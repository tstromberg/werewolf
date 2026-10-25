# Cloud TPM enrollment

## Summary

Extend exact-pair authorization to provider TPMs without publishing reset secrets. Pins,
native exchange and signed local enrollment/recovery are tested; deployment awaits live
tests.

AWS/GCP expose TPMs inside VMs, unlike host-provisioned swtpm. Secure Boot and signed
A/B updates work there; authenticate TPMs and protect reset paths before workloads
start.

## Goals

- Bind enrollment to the requested provider resource and its authenticated EK.
- Keep signing keys on the publisher and reset credentials in private host custody.
- Deliver reset credentials only to verified bootstrap code, never in plaintext.
- Keep both authorized A/B releases: retain the running one before replacing its peer.
- Refuse replay, partial enrollment, missing TPMs and unauthenticated measurements.

Enrollment refuses guest-supplied EKs, firmware failures (including Azure setup mode)
and deployment before bootstrap/live validation. Whole-VM/TPM restoration is out of
scope.

## Detailed design

### Provider identity

[AWS](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetInstanceTpmEkPub.html)
supplies an instance RSA-2048 DER NitroTPM key;
[GCP](https://docs.cloud.google.com/compute/shielded-vm/docs/retrieving-endorsement-key)
supplies a VM encryption EK. `howl _cloud-ek aws|gcp INSTANCE OUTPUT.json` reads it
through the host SDK, validating shape, algorithm and size. AWS must return the
requested instance ID; pin and check GCP's immutable numeric ID before and after
retrieval. Pin provider, region/project/zone, resource and normalized key together;
refuse changed pins. These reads neither initialize TPMs nor authorize workloads.

### Trusted bootstrap

A separate measured, signed bootstrap UKI holds only the enrollment agent and
networking, with the factory machine nonce, signed factory-record digest and bootstrap
mode sealed in its identity (`cmd/tpm-enroll`, `tools/build-tpm-bootstrap`); workload
UKIs keep the mandatory v2 checks. Nothing else runs in bootstrap mode, which refuses to
start where protected enrollment exists, with no guest reset or force option. The
internal GCP test uses a dedicated second serial port, selected only by the signed
initramfs. It verifies the provider EK before sending an encrypted capsule, then swaps
the stopped instance's boot disk for the authenticated factory disk without replacing
the instance or its TPM. This passed with both `prod-ssh` SSH accounts on 2026-10-24;
normal launch, download and update qualification remain open.

GCP firmware leaves a volatile empty-password platform reset path enabled. Both the
bootstrap and workload close it before handling enrollment credentials or exposing the
workload. GCP omits the platform handle from its authorization-policy capability; that
omission is accepted only after independently verifying that the platform hierarchy is
disabled. Owner, lockout and endorsement policy entries remain mandatory.

The bootstrap creates a TPM attestation key with fixed TPM and parent attributes,
adminWithPolicy set and userWithAuth clear, so empty-password activation fails. Its
policy is PolicyPCR at the expected nonzero bootstrap PCR 11, then command-specific
Quote and ActivateCredential branches under PolicyOR; the activation branch must set
PolicyCommandCode, as PCR policy alone is insufficient. The host verifies a fresh nonce,
the complete public template and the expected quote and PCR selection, and proves
association with the provider-pinned endorsement key by credential activation.
`test/check-cloud-tpm-activation` and the [wire protocol](tpm-bootstrap-protocol.md)'s
tests check this with independent TPM tools. An endorsement-key match alone does not
attest which software is running.

### Reset credentials

Persist random owner and lockout credentials at mode 0600 before authority changes.
After attestation, credential activation conveys a random 32-byte key, sealing a capsule
bound to the enrollment context and TPM policy. The factory publisher must sign it
before activation: public EK encryption alone lacks sender trust. Credentials stay
transient in verified bootstrap memory: never logged, persisted, returned or exposed
after handover; wipe every buffer. Enrollment replay refuses before activation.

The bootstrap installs disable-clear, owner and lockout authentication and the v2 NV
policy and anchor, reads the protected state back, and reboots into the normal signed
factory image, whose identity, measurement and protected-pair evidence make the host
ready. Partial provisioning refuses ordinary boot and preserves host recovery material.
The [signed recovery mode](tpm-enrollment-recovery.md) proves the original authority and
rejects written NV; it cannot clear the TPM, replace credentials or restore factory
state over retirement history.

### Publication and updates

The verified root declares a reachable, authenticated image and permit channel; the
local loopback publisher is no cloud transport, though its validation and issuance rules
are reused. Only the current published candidate receives new retirement authorization,
and a completed transition resumes with its permit even if the head advances. The signed
journal is persisted before the inactive root is retired, files are replaced only after
protected readback, and commit and operator rollback never raise a floor or change NV
authorization.

## Drawbacks and alternatives

Bootstrap, attestation, encrypted delivery and recovery need provider endorsement
support and a reachable publisher, without simulator control or writable TPM backing
files.

Metadata/image secrets expose reset keys to root and disk readers. A guest-only
installer proves neither publisher custody nor provider identity; commit floors destroy
A/B recovery.

## Security Considerations

Key retrieval, attestation, activation and readback are separate gates. Missing TPMs,
unmeasured boots and setup mode must refuse. Test signed bootstrap/capsule enrollment
replay.

## Reliability Considerations

Test every provisioning interruption and require explicit recovery, never automatic
re-enrollment. AWS/GCP must pass upgrades, rollback, failed trials and retirement power
cuts; refuse retired images, wrong keys, machines/PCRs and missing TPMs. Simulators
cannot prove provider behavior or physical TPM power-loss atomicity. References:
tpm2-tools
[activatecredential](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_activatecredential.1/)
and [checkquote](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_checkquote.1/).
