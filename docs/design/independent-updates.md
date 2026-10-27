# Independent updates from public signed images

Built 2026-10-24 (lib/tpm.zig, cmd/stage0, cmd/mount-broker, cmd/slot-update,
cmd/howl); Lima/QEMU, GCP, AWS and Azure validation in
[testing-live.md](../testing-live.md).
## Summary

A VM installs from a public signed image, enrolls its own TPM on first boot, and from
then on updates itself from static public files. One TPM counter retires old releases
and keeps the A/B fallback. Nothing signs per machine; the operator need never
return.
## Background

Protocol v2 binds each transition to a machine nonce and predecessor, so the
operator's `howl` signs for every VM on every update and delivers owner credentials
in capsules: a laptop driving one VM, not thousands of unrelated users on GCP, AWS
and Azure.
## Goals

- Identical public artifacts update unrelated VMs without registration or device IDs.
- No installer, cloud API, operator machine or per-machine signing takes part.
- Guest root cannot boot any release older than the VM's current fallback.
- Keep Secure Boot, IPE, verified roots, failed-trial fallback and operator rollback.
## Non-Goals
- Firmware, hypervisor or provider-API attackers, who can restore disk and TPM
  together; availability against guest root, which can already erase the disk.
- Rotating the boot certificate on running VMs; Azure's unreliable setup mode;
  updating privately signed images, which have no channel unless their builder
  publishes one.
## Detailed design

**Release index.** Each channel (`FORM/PROVIDER`; one per custom application) numbers
each architecture's releases 1, 2, 3, …, each the signed head's plus one, fixing no
less. The UKI's signed command line and the manifest carry `werewolf.channel=SHA256`
and `werewolf.index=N`.

**TPM state.** One NV counter in the owner hierarchy, the floor, at handle `0x0150`
plus the channel digest's first two bytes (the publisher refuses a colliding
channel): empty authorization, public read, no policy (so no `NV_ChangeAuth`), no
dictionary attack accounting, no lock, orderly or global-lock attribute. A release
boots only if its index is at least the floor, which rises and never falls. Raising
needs no authority: nothing below the floor boots again, so its only misuse is a
denial of service. Lowering needs Clear or the owner or platform hierarchy, which
enrollment closes. Another channel's UKI finds no counter at its handle on an owned
TPM: refused.

**First boot.** Before any workload, stage0 enrolls a TPM that has no owner or
lockout authorization and no Werewolf counter: define the counter at this channel's
handle and raise it to this release's index; disable clear; last, set lockout and
owner authorization to random values and forget them. Each step is checked before it
is taken and authorization comes last, so a cut leaves a state the next boot
completes; any other TPM state refuses boot. No credentials, custody, recovery mode,
attestation or bootstrap image exist.

**Every boot.** stage0 requires Secure Boot on, setup mode off and a TPM; disables
the platform hierarchy; verifies owner and lockout authorization set, clear disabled
and the counter at its channel's handle with exactly the expected public area;
requires its index ≥ floor; and hands over, passing init what it found for posture.
It reads the floor and never raises it: the broker raised it before the fallback's
predecessor was overwritten, so after any install nothing older than the fallback
boots again.

**Updates.** The updater service fetches the channel head as `_update` (TCP 443 and
53 only) and verifies it offline with the pinned image key: same channel, index above
the running one, every file's size and hash
([prebuilt-images.md](prebuilt-images.md)). It then disarms the inactive slot; has
the mount broker raise the floor to the running release's index, a zero-argument
operation, and read it back (after a lost reply, read and raise again); writes the
candidate's files; arms one try. The retained release stays bootable throughout; the
replaced one is retired before a byte of it is overwritten. Commit, failed-trial
fallback and operator rollback touch no TPM state.

**Publication and keys.** Published cloud images carry the vendor PK, KEK and db, so
a user launches the public image with Secure Boot on and nothing else; local `howl
run` enrolls the same public certificates into fresh firmware variables. The image
key is pinned in the root; a rotation ships the new key in a release and signs heads
with both keys for a year, each signature filed under its key's digest. Manifests do
not expire; the updater logs the head's serial and age at every check, so a withheld
update shows.
## Drawbacks
- The owner hierarchy is sealed forever; later sealing must use the endorsement one.
  Releases between the fallback and the running one stay bootable; none is older.
- A compromised broker or stage0 can brick by raising the floor, as it could erase
  the disk. An index costs as many increments; 16-bit handles allow 65,536 channels.
## Alternatives Considered

- Exact pairs (v2): per-machine signatures need a signer at every update;
  operator-held credentials keep the owner hierarchy usable at the cost of
  attestation, capsules and recovery. v3 keeps the TPM command plumbing, hierarchy
  checks, firmware enrollment and swtpm fixtures, and deletes policies, journals,
  permits, capsules and their tests.
- A maintenance UKI that alone writes the TPM, vendor-signed `PolicyAuthorize`
  policies or a PCR capped after boot: each bounds only a denial of service the
  device grant already bounds, for a second signed image and a reboot.
- TUF: four roles for one head under one pinned key; its expiry needs a clock we do
  not trust, and the counter replaces its version check. A floor raised at commit
  retires the fallback; a floor on disk is root's to lower.
## Security Considerations

Firmware must trust only UKIs that enforce this check, so the boot certificate may
have signed no UKI that boots without one: v2 UKIs refuse a TPM without their pair
index and legacy images carry no protected signature. Verify that against the catalog
before publishing v3, or publish under a new certificate. A service account that can
create instances from snapshots gets a fresh TPM: a provider-API attacker. Only
stage0 and the mount broker open `/dev/tpmrm0`: the updater loses its grant, fence
gives it to no service domain, the seal drops `CAP_MKNOD` and writable mounts are
`nodev`, so uid 0 in a service cannot reach it; whoever does can increment, never
define, undefine, lock, clear or lower. Test each, redefinition, another channel's
and retired UKIs, forged and stale other-slot manifests, foreign and partly enrolled
TPMs, and a service's reach.
## Reliability Considerations

Release promotion requires the CI test `test/check-independent-updates.zig` on each
target: it builds A, B and C with disposable keys, boots a guest from A's public
image with only a static file server reachable, and watches the guest's own updater
install B, then C, on schedule, asserting running index, floor and channel after each
boot. It exercises skipped releases, key rotation, offline boot, wrong signatures and
channels, failed trials, operator rollback, retired replay and a power cut at every
durable step, keeping disk and TPM; on QEMU/swtpm, then GCP, AWS and Azure.
