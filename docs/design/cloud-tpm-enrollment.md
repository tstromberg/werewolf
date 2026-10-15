# Cloud TPM enrollment

## Summary

Extend the exact-pair protocol to provider TPMs without publishing reset secrets.
Provider pins and the native exchange are tested and signed enrollment and recovery
work in a local VM; protected deployment stays refused until the live tests pass.

## Background

Local hosts provision swtpm before exposing its device to a guest; AWS and GCP expose
their TPM through the VM, so that method cannot be reused. Secure Boot and signed A/B
updates already work there, but a vTPM flag alone adds no retirement guard: the TPM
must be authenticated and reset protection installed before the workload starts.

## Goals

- Bind enrollment to the requested provider resource and its authenticated EK.
- Keep signing keys on the publisher and reset credentials in private host custody.
- Deliver reset credentials only to verified bootstrap code, never in plaintext.
- Keep both authorized A/B releases: retain the running one before replacing its peer.
- Refuse replay, partial enrollment, missing TPMs and unauthenticated measurements.

## Non-Goals

- Protect against the provider or an administrator restoring the whole VM and TPM.
- Accept a guest-supplied endorsement key as proof of provider identity.
- Treat firmware enrollment failures, Azure setup mode included, as success.
- Enable cloud enrollment before its bootstrap and live tests are complete.

## Detailed design

### Provider identity

[AWS](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetInstanceTpmEkPub.html)
returns an instance's public NitroTPM key (request RSA-2048 in DER), and
[GCP](https://docs.cloud.google.com/compute/shielded-vm/docs/retrieving-endorsement-key)
a named VM's encryption endorsement key. `howl _cloud-ek aws|gcp INSTANCE OUTPUT.json`
records that identity through the host SDK, validating shape, algorithm and size; AWS's
returned instance ID must match the request, and GCP's immutable numeric ID is pinned
and checked before and after the read. Provider, region/project/zone, resource and
normalized key are pinned together, and changed pins refuse overwrite. These reads
initialize no TPM and authorize no workload boot.

### Trusted bootstrap

A separate measured, signed bootstrap UKI holds only the enrollment agent and
networking, with the factory machine nonce, signed factory-record digest and bootstrap
mode sealed in its identity (`cmd/tpm-enroll`, `tools/build-tpm-bootstrap`); workload
UKIs keep the mandatory v2 checks. Nothing else runs in bootstrap mode, which refuses
to start where protected enrollment exists, with no guest reset or force option.
Provider transport and factory boot selection remain open.

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

Random owner and lockout credentials are persisted at mode 0600 before any authority
changes. After attestation succeeds, they are encrypted for that TPM and policy-bound
key: credential activation conveys a random 32-byte key, which seals an authenticated
capsule bound to the full enrollment context, and the factory publisher's signature is
required before activation, since public EK encryption alone lacks sender trust. The
credentials exist transiently in verified bootstrap memory and are never logged,
persisted, returned over the network or exposed after handover; every buffer that held
them is wiped. Replaying bootstrap after enrollment refuses before capsule activation.

The bootstrap installs disable-clear, owner and lockout authentication and the v2 NV
policy and anchor, reads the protected state back, and reboots into the normal signed
factory image, whose identity, measurement and protected-pair evidence make the host
ready. Partial provisioning refuses ordinary boot and preserves host recovery material.
The [signed recovery mode](tpm-enrollment-recovery.md) proves the original authority
and rejects written NV; it cannot clear the TPM, replace credentials or restore factory
state over retirement history.

### Publication and updates

The verified root declares a reachable, authenticated image and permit channel; the
local loopback publisher is no cloud transport, though its validation and issuance
rules are reused. Only the current published candidate receives new retirement
authorization, and a completed transition resumes with its permit even if the head
advances. The signed journal is persisted before the inactive root is retired, files
are replaced only after protected readback, and commit and operator rollback never
raise a floor or change NV authorization.

## Drawbacks

Measured bootstrap, attestation, encrypted credential delivery and host recovery state
are all new; the design needs a provider-supported endorsement hierarchy and a
reachable publisher, with no local simulator control or writable TPM backing files.

## Alternatives Considered

Plaintext metadata or image credentials expose reset authority to guest root or disk
readers. A guest-only installer can neither establish independent publisher custody nor
prove provider identity. A commit-time minimum version destroys A/B recovery.

## Security Considerations

Public-key retrieval, attestation, capsule activation and protected readback are
separate gates; missing-TPM, unmeasured-boot and setup-mode refusals are not relaxed for
convenience. Replay tests include the signed bootstrap and its capsule after enrollment.

## Reliability Considerations

Every provisioning interruption is tested and needs explicit recovery, never implicit
re-enrollment. AWS and GCP must pass healthy upgrades, operator rollback, failed trials
and retirement power cuts, and refuse retired images, wrong keys, machines or PCRs, and
missing TPMs. Simulator success proves neither provider behavior nor physical TPM
power-loss atomicity. References: tpm2-tools'
[activatecredential](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_activatecredential.1/)
and [checkquote](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_checkquote.1/).
