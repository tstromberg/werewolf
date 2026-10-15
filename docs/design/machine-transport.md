# Signed machine transport

## Summary

Machine-specific HTTPS trust lives in host-signed config, outside the verified root. The
firmware PK authenticates that declaration; the root fixes its permitted host and port.
Vendor signatures still authenticate code. TPM permits still authorize the exact A/B
pair. Status: implemented for new local profiles; full arm64 Lima lifecycle passed.

## Background

Baking each machine's TLS CA and permit public key into its root prevents sharing a
published image. Firmware-derived machine authority removes the permit key from the
root. This declaration also removes its TLS CA while preserving explicit network
restrictions. Published-image production and consumption remain separate unfinished
work.

## Goals

- Authenticate a host permit service without granting it vendor code-signing authority.
- Bind transport trust to the actual TPM machine nonce, rather than mutable
  configuration.
- Preserve bounded parsing, explicit endpoints and existing A/B retirement semantics.
- Keep machine private keys and reset credentials outside guests and build helpers.

## Non-Goals

- Let configuration change vendor trust, arbitrary network access or authorized
  releases.
- Replace authenticated manifests, permits, measured boot or TPM authorization.
- Protect against an administrator restoring the complete VM and TPM together.

## Detailed design

### Immutable declaration

New local roots record TPM protocol `2-firmware`, the vendor db certificate hash, and
`tpm/permit-host` plus `tpm/permit-port`. Supported hosts are Lima's `192.168.5.2` and
QEMU's `10.0.2.2`; ports must be nonzero. The image build adds that TCP port to the
updater's explicit network policy. The vendor image channel remains a separate immutable
declaration. Legacy protocol `2` roots retain their embedded permit key and previous
transport behavior.

### Signed mutable declaration

Howl injects the public bundle at `/run/config/machine-transport` in the config tar. The
machine owner signs the following body with RSA/SHA-256, using the permit signing key.
The signature follows the body; its size is the authenticated PK's RSA modulus size.

| Field | Size | Encoding |
| --- | --- | --- |
| Domain | 21 bytes | `werewolf.transport/1` followed by NUL |
| Machine nonce | 32 bytes | Nonzero factory/TPM journal nonce |
| IPv4 host | 4 bytes | Network-order address bytes |
| Port | 2 bytes | Unsigned big-endian |
| CA length | 2 bytes | Unsigned big-endian |
| Public TLS CA | 1–4096 bytes | One bounded DER X.509 certificate |
| Signature | 256, 384 or 512 bytes | RSA PKCS#1 v1.5, SHA-256 |

The guest verifies the signature before interpreting the certificate. It obtains the
nonce from the authenticated current journal and actual TPM anchor. It then requires an
exact nonce, host and port match, and validates bounded DER structure. Missing,
oversized, truncated, foreign or altered declarations fail closed.

### Fetching and authorization

Permit requests use the declared HTTPS endpoint and contextual predecessor/retained-PCR
parameters. Only requests under that exact endpoint use the declared CA as their TLS
trust anchor. Vendor-channel requests retain normal certificate verification and signed
manifest verification. A signed transport declaration cannot mint a release, retire a
slot or reset the hierarchy. The existing issuer validates candidate identity and
retained membership before signing a permit. Commit, operator rollback, failed trials
and interrupted retirement retain their existing pair rules.

### Host lifecycle

The private machine owner, TLS signer and hierarchy credentials persist on the host. The
root contains neither the machine permit key nor its TLS CA. Config injection preserves
other config files and replaces only the reserved transport entry. Restart requires the
existing signed declaration and original TPM backing state. No missing credential or
partial enrollment is repaired by silently generating a new authority.

## Drawbacks

- Host permit service availability remains necessary for newly authorized transitions.
- Published profiles need a fixed declared listener or shared host service for multiple
  guests.

## Alternatives Considered

- Embedding every machine's CA in its root prevents sharing identical published roots.
- Unsigned config trust allows guest-controlled endpoint and TLS authority substitution.
- Giving the host vendor signing keys couples machine enrollment to published code
  authority.

## Security Considerations

Endpoint and machine binding precede TLS CA use; mutable config cannot widen network
policy. Separate vendor db trust and machine PK trust remain mandatory. The signed
declaration is public; no private signing or reset material enters the config disk.

## Reliability Considerations

Unit tests cover independent signed fixtures, malformed signed bodies and every byte
mutation. Real Lima tests passed updates, rollback, restart, unhealthy fallback and
VM/TPM retirement cuts. Evidence:
`build/ipe-check/secure-lima/machine-transport-lifecycle/`. CI and published-download
lifecycle execution remain separate gates.
