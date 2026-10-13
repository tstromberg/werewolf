# TPM bootstrap protocol

## Summary

`lib/tpm-bootstrap.zig` implements native attestation, credential wrapping and authenticated capsules.
The integration probe completes provisioning on swtpm; signed cloud deployment remains gated.

## Background

The [cloud enrollment design](cloud-tpm-enrollment.md) requires authenticated TPM identity and code.
`tools/tpm-bootstrap.zig` is a host codec and test probe, excluded from ordinary workload images.
It does not establish Secure Boot, expose a cloud endpoint or implement recovery by itself.

## Goals

- Check native bytes against independent TPM tools.
- Release credentials only to the pinned TPM, expected bootstrap PCR and signed factory context.
- Authenticate the publisher before activating a capsule; refuse enrollment replay.
- Preserve existing exact-pair A/B authorization.

## Non-Goals

- Enable cloud `--secure` before signed-bootstrap and provider lifecycle tests.
- Send private signing keys, persist guest reset secrets or silently clear a partial enrollment.

## Detailed design

### Challenge and attestation

The challenge is four fixed 32-byte values: machine nonce, signed factory digest, PCR 11 and fresh nonce.
Its quote qualification is SHA-256 of `werewolf.enroll/1\0` followed by those values.
All four values must be nonzero; the guest checks machine/factory against the signed factory permit.
Host identity pins supply the EK public key independently of the guest.
Accept the standard RSA-2048/SHA-256/AES-128-CFB endorsement template and matching pinned modulus.
The AK must be RSA-2048/SHA-256 restricted signing, fixed TPM/parent and sensitive-data origin.
Require adminWithPolicy, forbid userWithAuth and accept only the expected policy digest.
PolicyPCR covers SHA-256 PCR 11; PolicyCommandCode branches for Quote/ActivateCredential join with PolicyOR.
Verify complete public areas and names, qualified parent, quote type, challenge and exact PCR selection/digest.
Quotes require RSASSA/SHA-256 signatures; truncated, extra or unsupported fields refuse.

### Credential and capsule

Native MakeCredential wraps a random 32-byte capsule key for the EK and AK name.
It uses RSA-OAEP/SHA-256 with `IDENTITY\0`, TPM KDFa and AES-128-CFB with an integrity HMAC.
AES-256-GCM encrypts the 64-byte owner/lockout credentials under the capsule key.
Associated data binds the protocol domain, challenge digest, AK name and pinned EK modulus digest.
The unsigned body is 438 bytes: domain, sized 68-byte credential, sized 256-byte seed,
12-byte GCM nonce, 64-byte ciphertext and 16-byte tag.
Append a big-endian 16-bit signature length and the factory publisher's RSA signature.
Its signed message is `werewolf.enroll.capsule/1\0`, challenge digest and the complete unsigned body.
The guest verifies the signature using immutable factory trust before TPM activation.
Anyone can wrap a chosen key using a public EK; GCM alone cannot authenticate the publisher.

### Provisioning

`Boot.receive` combines publisher verification, template checks, activation and capsule authentication.
The activation primitive stays private so callers cannot omit the signature gate accidentally.
Freshness checks reject owner/lockout auth, either Werewolf NV index and hierarchy policy overrides.
Check freshness both before key creation and immediately before activation.
Provision the existing signed factory pair, protect reset paths and verify the resulting NV anchor.
Only the public anchor is returned; plaintext credentials and command/response buffers are wiped.
The deployment agent must reboot before ordinary workload startup.
Partial provisioning requires authenticated recovery; replay does not reset or finish it implicitly.

### Probe and tests

Build with `make build/host/tpm-bootstrap build/host/tpm-policy`.
The probe's policy/challenge/verify/wrap commands exercise the host codec.
`guest-probe` keeps ephemeral keys alive over a private TPM connection and framed standard I/O.
Its output contains public templates, a quote/signature and the final public anchor.
The probe input carries only a signed encrypted capsule; it is not a cloud administration service.
`python3 test/check-cloud-tpm-activation` checks both native directions with independent TPM tools.
Tests include attacker-signed/unsigned capsules, damaged AEAD, truncation, oversized input and replay.
Wrong factory/PCR and partial enrollment refuse before any proof is emitted.
Offline tests retain public templates/quotes and check every truncated representation and context binding.

## Drawbacks

Requires strict TPM templates, publisher signatures and a separate signed-bootstrap integration.

## Alternatives Considered

- TPM encryption alone permits an attacker to choose reset credentials.
- Password-enabled AKs permit bypassing the measured activation policy.
- Metadata plaintext and guest-persisted credentials expose reset authority.

## Security Considerations

Signing keys and durable reset custody stay with the publisher.
The actual deployment must bake factory trust/context into a measured signed bootstrap UKI.
An offline probe using caller-provided files cannot establish that boot trust.
Never expose the probe as a workload service or enable deployment from simulator success alone.

## Reliability Considerations

Preserve recovery material before provisioning and refuse uncertain partial enrollment.
Existing retirement tests remain mandatory; commit and operator rollback do not change the authorized pair.
Provider boot/recovery and physical TPM power-loss behavior remain separate validation requirements.
