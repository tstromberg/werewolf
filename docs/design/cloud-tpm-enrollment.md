# Cloud TPM enrollment

## Summary

Extend the local exact-pair protocol to provider-controlled TPMs without publishing reset secrets.
Status: provider pins/native exchange are tested; signed enrollment and recovery work in a local VM.
Cloud `--secure` remains refused until enrollment and provider recovery tests pass.

## Background

Local hosts provision swtpm before exposing its device to a guest.
AWS and GCP expose their TPM through the VM, so that provisioning method cannot be reused.
Secure Boot and signed A/B updates already work there; a vTPM flag alone adds no retirement guard.
The missing step is authenticating the TPM and installing reset protection before workload startup.

## Goals

- Bind enrollment to the requested provider resource and its authenticated endorsement key.
- Keep signing keys on the publisher and reset credentials in private host custody.
- Deliver reset credentials only to verified bootstrap code, never as plaintext disk or metadata data.
- Preserve both authorized A/B releases; retain the running release before replacing its peer.
- Refuse replay, partial enrollment, missing TPMs and unauthenticated bootstrap measurements.

## Non-Goals

- Protect against the provider or an administrator restoring the entire VM and TPM.
- Accept a guest-supplied endorsement key as proof of provider identity.
- Treat firmware enrollment failures, including Azure setup mode, as successful deployment.
- Enable cloud enrollment before its bootstrap implementation and live tests are complete.

## Detailed design

### Provider identity

AWS's [GetInstanceTpmEkPub](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetInstanceTpmEkPub.html)
returns the public NitroTPM key for an instance; request RSA-2048 in DER form.
GCP's [Shielded identity API](https://docs.cloud.google.com/compute/shielded-vm/docs/retrieving-endorsement-key)
returns the encryption endorsement key for a named VM.
`howl _cloud-ek aws|gcp INSTANCE OUTPUT.json` records that public identity through the host SDK.
Validate response shape, algorithm and size; AWS's returned instance ID must match the request.
Pin provider, region/project/zone, resource and normalized key together; changed pins refuse overwrite.
These reads prepare enrollment and do not initialize a TPM or authorize a workload boot.
GCP also pins its immutable numeric ID, checked before and after reading the key.

### Trusted bootstrap

Build a separate measured, signed bootstrap UKI containing only the enrollment agent and networking.
Seal the factory machine nonce, signed factory-record digest and bootstrap mode in its identity.
Regular workload UKIs continue to require the existing mandatory v2 checks.
No root filesystem handover, application or ordinary administration service runs in bootstrap mode.
`cmd/tpm-enroll` and `tools/build-tpm-bootstrap` implement that isolated image with a bounded VM channel.
Provider transport and normal-factory boot selection remain open; this does not enable cloud deployment.
Refuse bootstrap when protected enrollment already exists; there is no guest reset or force option.

The bootstrap creates a TPM attestation key with fixed TPM/parent attributes.
Its policy permits activation only at the expected nonzero bootstrap PCR 11.
Require adminWithPolicy and clear userWithAuth; empty-password activation must fail.
Use PolicyPCR followed by command-specific Quote/ActivateCredential branches and PolicyOR.
The activation branch must set PolicyCommandCode; PCR policy alone is insufficient.
The host must verify a fresh nonce, the complete public template and the expected quote/PCR selection.
Prove association with the provider-pinned endorsement key using credential activation.
`test/check-cloud-tpm-activation` verifies these policies with independent TPM tools.
The [native wire protocol](tpm-bootstrap-protocol.md) passes independent-tool interoperability tests.
An endorsement-key match alone does not attest which software is running.

### Reset credentials

Persist random owner and lockout credentials at mode 0600 before any authority changes.
After bootstrap attestation succeeds, encrypt credentials for that TPM and policy-bound key.
Credential activation conveys a random 32-byte key, not the reset credentials themselves.
Use that key for an authenticated encrypted capsule bound to the full enrollment context.
Require the factory publisher's signature before activation; public EK encryption alone lacks sender trust.
Credentials may exist transiently in verified bootstrap memory while provisioning.
They must never be logged, persisted, returned over the network or exposed after workload handover.
Explicitly wipe credentials and every TPM-command buffer that contained them.
Replaying bootstrap after enrollment must refuse before capsule activation.

Install disable-clear, owner/lockout authentication and the existing v2 NV policy/anchor.
Read back the full protected state, then reboot into the normal signed factory image.
Host readiness requires the normal boot's identity, measurement and protected-pair evidence.
Partial provisioning refuses ordinary boot and preserves host recovery material.
The [signed recovery mode](tpm-enrollment-recovery.md) proves the original authority and rejects written NV.
It cannot clear the TPM, replace credentials or restore factory state over retirement history.

### Publication and updates

Use a reachable authenticated image/permit channel declared inside the verified root.
The local loopback publisher is not a cloud transport; its validation and issuance rules are reusable.
Only the current published candidate receives new retirement authorization.
Completed transitions resume with their existing permit even if the head advances.
Persist the signed journal before retiring the inactive root; replace files only after protected readback.
Commit and operator rollback never raise a floor or change NV authorization.

## Drawbacks

- Adds measured bootstrap, attestation, encrypted credential delivery and host recovery state.
- Requires a provider-supported endorsement hierarchy/template and an accessible publisher.
- Cloud enrollment cannot reuse local simulator control or assume writable TPM backing files.

## Alternatives Considered

- Plaintext metadata or image credentials expose reset authority to guest root or disk readers.
- A guest-only installer cannot establish independent publisher custody or prove provider identity.
- A commit-time minimum version destroys the authorized predecessor and A/B recovery.

## Security Considerations

Treat public-key retrieval, attestation, capsule activation and protected readback as separate gates.
Do not relax missing-TPM, unmeasured-boot or firmware setup-mode refusal for bootstrap convenience.
Replay tests must include the signed bootstrap itself and its encrypted capsule after enrollment.

## Reliability Considerations

Test each provisioning interruption and require explicit recovery rather than implicit re-enrollment.
AWS/GCP must pass healthy upgrades, operator rollback, failed trials and retirement power cuts.
Also require retired-image, wrong-key, wrong-machine, wrong-PCR and missing-TPM refusals.
Simulator success does not establish provider behavior or physical TPM power-loss atomicity.

References: [credential activation](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_activatecredential.1/),
[quote checks](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_checkquote.1/).
