# slot-update(8)

<!-- date: October 25, 2026 -->
<!-- os: Werewolf -->

## NAME

slot-update — prepare and boot updates in the inactive system slot

## SYNOPSIS

**slot-update** [**check** | **outcome** | **daemon**]

**slot-update** **try** [*declaration-hash*]

## DESCRIPTION

The **slot-update** utility builds or downloads an updated root in the inactive slot
and boots it once when update policy permits. The previous slot remains available
until slot-keep(8) commits the new boot. An unhealthy boot rolls back.

Operator commands require root and submit requests to the supervised autoupdate
service. They do not perform mounts in the caller's process. The commands are as
follows:

- **check**

  Check for updates and apply the configured update policy. This is the default when
  invoked by an operator without arguments.

- **outcome**

  Record the outcome of an earlier update attempt. An attempt armed during the current
  boot has not yet been tried.

- **daemon**

  Run the supervised updater. Invocation as `/etc/sv/autoupdate/run` selects this mode
  automatically. It requires the private channels supplied at boot.

- **try** [*declaration-hash*]

  Select the parked slot for a trial boot, optionally requiring its declaration to
  match the given hash.

The service checks after boot and at the configured interval, normally an hour.
Enrolled IPE machines fetch authenticated prebuilt slots. Unenrolled IPE machines hold
updates. Other machines construct roots from signed packages. Package versions, signed
feed serials and boot floors may not go backwards.

Network fetching and parsing run in confined workers. Installation uses verified
inputs offline; fixed filesystem operations go through mount-broker(8). Reports
identify changed packages, CVEs and source digests. JSON log records are chained to
their predecessors.

## FILES

- `/etc/werewolf/update-policy.json`

  Image update policy.

- `/run/config/update-policy.json`

  Operator policy, constrained by the image policy.

- `/data/svc/autoupdate`

  Persistent state, cache, work files, log and reports.

- `/run/werewolf/updater-ready`

  Service readiness marker used by the slot keeper.

- `/run/werewolf/committed`

  Marker required before updating the inactive slot.

## SEE ALSO

mount-broker(8), reboot(8), slot-keep(8), stage0(8)

## CAVEATS

A check may stage an update and reboot the machine. Failed updates are recorded to
prevent repeated attempts at the same bad build.
