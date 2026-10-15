# TPM bootstrap protocol

## Summary

`lib/tpm-bootstrap.zig` implements native attestation, credential wrapping and
authenticated capsules; the signed VM agent completes enrollment and explicit recovery.
Provider deployment remains gated.

## Background

The [cloud enrollment design](cloud-tpm-enrollment.md) requires authenticated TPM
identity and code. `tools/tpm-bootstrap.zig` is a host codec and test probe, kept out
of workload images, with no Secure Boot, cloud endpoint or recovery of its own.

## Goals

- Check native bytes against independent TPM tools; keep exact-pair A/B authorization.
- Release credentials only to the pinned TPM, bootstrap PCR and signed factory context.
- Authenticate the publisher before activating a capsule; refuse enrollment replay.

## Non-Goals

- Enable protected cloud deployment before signed-bootstrap and provider lifecycle
  tests, send signing keys, keep guest reset secrets or silently clear an enrollment.

## Detailed design

### Challenge and attestation

The challenge is four 32-byte values, all nonzero: machine nonce, signed factory digest,
PCR 11 and a fresh nonce; its quote qualification is SHA-256 of `werewolf.enroll/1\0`
and those values, and the guest checks machine and factory against the signed factory
permit. Host identity pins supply the EK public key apart from the guest: the standard
RSA-2048/SHA-256/AES-128-CFB endorsement template with the pinned modulus. The AK must
be RSA-2048/SHA-256 restricted signing, fixed TPM and parent, sensitive-data origin,
adminWithPolicy without userWithAuth, and carry the expected policy digest: PolicyPCR
over SHA-256 PCR 11, with PolicyCommandCode branches for Quote and ActivateCredential
joined by PolicyOR. Verify public areas, names, parent, quote type, challenge and PCR
selection and digest; a quote needs an RSASSA/SHA-256 signature, and truncated, extra or
unsupported fields refuse.

### Credential and capsule

Native MakeCredential wraps a random 32-byte capsule key for the EK and AK name, with
RSA-OAEP/SHA-256 under `IDENTITY\0`, TPM KDFa and AES-128-CFB with an integrity HMAC;
AES-256-GCM encrypts the 64-byte owner and lockout credentials under that key, its
associated data binding the protocol domain, challenge digest, AK name and pinned EK
modulus digest. The unsigned body is 438 bytes (domain, sized 68-byte credential, sized
256-byte seed, 12-byte nonce, 64-byte ciphertext, 16-byte tag), followed by a big-endian
16-bit length and the factory publisher's RSA signature over
`werewolf.enroll.capsule/1\0`, the challenge digest and the body. The guest verifies it
with immutable factory trust before activation: anyone can wrap a chosen key for a
public EK, so GCM alone cannot authenticate the publisher.

### Provisioning

`Boot.receive` combines publisher verification, template checks, activation and capsule
authentication; the activation primitive is private, so no caller can skip the
signature gate. Freshness checks, before key creation and again before activation,
reject owner/lockout auth, Werewolf NV indices and hierarchy policy overrides. Provision
the signed factory pair, protect reset paths and verify the NV anchor; return only the
public anchor and wipe plaintext credentials and buffers. The agent reboots before any
workload starts. Partial provisioning needs [recovery](tpm-enrollment-recovery.md),
which authenticates the original reset credentials and rejects written indices.

### Signed image and channel

`tools/build-tpm-bootstrap` signs a separate UKI with `cmd/tpm-enroll` as its only
executable; its deterministic initramfs holds PID 1, the console node and public factory
trust, verified before the build and recorded with its digest and machine. The signed
command line selects secure native bootstrap and permits no workload options; recovery
adds signed `werewolf.recovery=1`, a measured identity of its own; ordinary stage0
refuses the mode before module loading or root handover. The agent requires
SecureBoot=1, SetupMode=0, confidentiality lockdown and the exact boot IPE policy,
closes module loading, drops policy administration and uses built-in drivers only. Over
the kernel-named `werewolf.enroll` virtio port, found with strict bounds, it emits
`WWREADY1` after freshness and nonzero-PCR checks; the host sends `WWCHAL01` and
context, whose machine and factory must match immutable trust and whose PCR the
measurement; the agent answers with its proof frame, takes `WWCAPS01` (a big-endian u16
length, at most 952 bytes), wipes secrets, reads the anchor back, sends `WWDONE01` with
the public anchor and reboots. There is no shell, filesystem handover, network daemon
or guest reset. `make IPE=1 check-tpm-bootstrap-guest` exercises the signed image and
firmware refusal gates; provider transport, normal-factory selection and provider
lifecycle validation remain open.

### Probe and tests

`make build/host/tpm-bootstrap build/host/tpm-policy` builds the probe, whose
policy/challenge/verify/wrap commands exercise the host codec; `guest-probe` keeps
ephemeral keys alive over a private TPM connection and framed standard I/O, emits public
templates, a quote and signature and the public anchor, and takes only a signed
encrypted capsule: it is no administration service. `python3
test/check-cloud-tpm-activation` checks both directions with independent TPM tools
(attacker-signed and unsigned capsules, damaged AEAD, truncation, oversized input,
replay; a wrong factory or PCR and partial enrollment refuse before any proof), and
offline tests check every truncated representation and context binding.

## Drawbacks

Strict TPM templates, publisher signatures and a separate signed-bootstrap integration.

## Alternatives Considered

TPM encryption alone lets an attacker choose reset credentials; password-enabled AKs
bypass the measured activation policy; plaintext metadata and guest-persisted
credentials expose reset authority.

## Security Considerations

Signing keys and durable reset custody stay with the publisher. Provider deployment must
select the verified normal factory image after bootstrap, which an offline probe on
caller-provided files cannot establish: never expose the probe as a workload service or
deploy on simulator success alone.

## Reliability Considerations

Preserve recovery material before provisioning and refuse uncertain partial enrollment.
Retirement tests remain mandatory; commit and operator rollback do not change the
authorized pair. Provider boot, recovery and TPM power loss are validated apart.
