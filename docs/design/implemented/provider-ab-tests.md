# Provider A/B update tests

**Status:** Implemented
[2026-10-12](https://github.com/werewolf-linux/werewolf/commit/933bdd4f)

## Summary

Run the same signed upgrade and recovery scenarios on each VM backend.
Report Secure Boot support separately from A/B test coverage.

## Background

Cloud smoke tests prove first boot and reconfiguration, not slot recovery.
Native UKI entries omit unsigned options; retained factory slots also need
their signed manifests before the operator can authenticate a rollback.

## Goals

- Prove an actual authenticated update, boot and health commit.
- Roll back to the previous good release after commit, then reboot it again.
- Prove an unhealthy signed candidate automatically returns to the good slot.
- Require fresh boot IDs, exact release identity and dm-verity on every boot.
- Require Secure Boot and IPE throughout supported signed-provider runs.
- Preserve logs and remove only resources created by the test.

## Non-Goals

- Treating unsupported firmware as a passing Secure Boot test.
- Publishing test images or private signers to a public update service.
- Advancing and resetting the TPM floor, which `test/check-independent-updates.zig`
  tests. The bhyve protected run checks rollback admission throughout recovery.

## Detailed design

A private fixture builds good releases A and B, plus an unhealthy release.
Every release is signed by a disposable host key; only public boot enrollment
and a disposable TLS server identity enter guest artifacts.
The initial root carries the signed update objects. A confined loopback HTTPS
server serves them from persistent test data, requiring no public mirror.
SSH uses a disposable test key through the fixture's explicit SSH policy.
The host selects signed channel heads and invokes the real updater.

The runner boots A, updates to B and waits for durable health commit.
It invokes the normal operator rollback and proves A remains bootable after
another restart. An unhealthy candidate must consume its try without committing,
then automatically return to A. BLS entries and authenticated factory-slot
proofs must survive the normal lifecycle; the runner does not synthesize success.
UKIs use the pinned systemd-boot's `uki` directive, which spends the entry's
boot attempt. Generic `efi` entries do not, so a deadman reboot can repeatedly
select the unhealthy candidate instead of restoring the previous good release.

QEMU, Lima, cloud and remote hypervisor adapters provide lifecycle operations,
SSH and raw consoles. Azure's known setup-mode conflict is a failing test,
not a skip or an excuse to weaken stage0. Unsupported Secure Boot backends
can test ordinary A/B separately; signed EFI refusal remains a negative test.
Live cloud and remote-host tests are opt-in. Local firmware tests run in CI.

### Firecracker and bhyve

For x86_64 bhyve, use `AB_MODE=secure AB_TPM=1`. The fixture signs A, B and the
unhealthy candidate at indexes 1, 2 and 3. The adapter uses howl's protected
supervisor, persistent swtpm state and enrolled bhyve firmware. Each boot must
report TPM rollback protection and an admissible floor, alongside Secure Boot,
IPE and dm-verity. Cleanup waits for the supervisor to stop its TPM before
removing the disposable machine directory.

```sh
make check-ab-bhyve ARCH=x86_64 BHYVE_HOST=bilbo \
  AB_MODE=secure AB_TPM=1 SECUREBOOT_DIR=/path/to/bhyve-firmware
make check-ab-firecracker ARCH=x86_64 FIRECRACKER_HOST=galadriel AB_MODE=plain
make check-ab-firecracker ARCH=x86_64 FIRECRACKER_HOST=galadriel \
  AB_MODE=plain AB_FIRECRACKER_PINNED=1
```

`SECUREBOOT_DIR` contains matching bhyve `code.fd` and `vars.fd` templates.
Fixture creation needs the local test IPE kernel and signer; TPM fixtures also
need a measured EFI stub. `AB_FIXTURE_ONLY=1` builds without launching a VM.
`AB_FIXTURE=/path/to/fixture.json` reuses an image whose architecture, boot mode
and TPM mode match the requested run. Only the disk, disposable SSH key and
public enrollment material need to reach the controller or hypervisor; the
signing keys stay on the build host.

Firecracker runs as the owner of its private directory and TAP, with the
production bubblewrap sandbox. Set `FIRECRACKER_REMOTE_PATH` when its binaries
are outside the remote SSH session's PATH. The ordinary A/B test exercises the
legacy guest-selected boot entries with signed updates, IPE and dm-verity;
it does not establish authenticated boot or TPM protection. The separate
`AB_FIRECRACKER_PINNED=1` check exercises the default host pins: signed B must
stage, then a fresh reboot must retain A. This is a passing limitation check,
not an A/B upgrade pass. Default Firecracker deployments still need host
rebuilds to receive image updates.

## Drawbacks

- Three signed releases increase fixture build time and image size.
- The production deadman interval makes the unhealthy-slot test slower.
- Live cloud runs cost money and require credentials outside ordinary PR CI.

## Alternatives Considered

- Restarting on new metadata does not test installation or A/B rollback.
- Installing slots by hand skips updater authentication and arming checks.
- A public test mirror adds credentials, networking and cleanup dependencies.

## Security Considerations

Boot and policy private keys stay on the build host. Test SSH allowances and
loopback TLS service are confined to disposable fixtures. A production signer
is never used for intentionally unhealthy releases. A/B recovery must remain
available after commit, which is why the TPM floor rises only when the inactive slot
is replaced ([independent-updates.md](independent-updates.md)).

## Reliability Considerations

Each phase checks a new boot ID and expected release, preventing stale console
records from passing the test. Cleanup runs after failures too. Provider results
distinguish observed passes, failures and unavailable hosts.
