# slot-keep(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

slot-keep — commit a trial system slot after health checks

## SYNOPSIS

**slot-keep**

## DESCRIPTION

The **slot-keep** service commits the running slot only after it has proved healthy.
It runs as _slotkeep without capabilities in a read-only Landlock domain. The
inherited keeper channel permits a commit request to mount-broker(8).

Every other supervised service must have run for at least a minute, or be down because
it was requested to stay down. Finishing, crash loops and missing supervisor state do
not count as healthy. Persistent data must be usable, the updater must be ready when
present, and the boot posture report must contain no unexcused failure.

The broker keeps the EFI entry and only then publishes the root-owned commit marker.
The service logs the result and takes itself down. Machines without a committable slot
have nothing to do. Failure leaves the slot uncommitted, allowing the deadman and boot
loader to return to the previous slot. Committing does not raise the TPM floor.

## FILES

- `/etc/sv/*/supervise/status`

  Service health records.

- `/run/werewolf/posture.json`

  Boot protection report.

- `/run/werewolf/updater-ready`

  Updater readiness marker.

- `/run/werewolf/nodata`

  Persistent-data failure marker, which prevents commitment.

- `/run/werewolf/committed`

  Successful commit marker.

## SEE ALSO

mount-broker(8), posture(8), slot-update(8), stage0(8)

## CAVEATS

A minute of uptime cannot prove that an application will remain healthy.
