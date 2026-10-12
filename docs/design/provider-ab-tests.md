# Provider A/B update tests

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
- Implementing the unfinished TPM retirement protocol.

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

QEMU, Lima, cloud and remote hypervisor adapters provide lifecycle operations,
SSH and raw consoles. Azure's known setup-mode conflict is a failing test,
not a skip or an excuse to weaken stage0. Unsupported Secure Boot backends
can test ordinary A/B separately; signed EFI refusal remains a negative test.
Live cloud and remote-host tests are opt-in. Local firmware tests run in CI.

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
available after commit; the per-release TPM floor cannot be enabled unchanged.

## Reliability Considerations

Each phase checks a new boot ID and expected release, preventing stale console
records from passing the test. Cleanup runs after failures too. Provider results
distinguish observed passes, failures and unavailable hosts.
