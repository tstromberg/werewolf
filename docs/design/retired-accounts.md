# Retired accounts

## Summary

Keep an account's name and numeric IDs reserved after access is revoked.
Publish a locked account in `/run`, and keep its reservation on `/data` so a
later account cannot acquire its files.

## Background

Werewolf hashes names in the `users` file, including cloud metadata imports,
to make UIDs and GIDs. At boot, init also reads the first user in a NoCloud
`#cloud-config` seed with a supplied UID of 500–60000; it does not run cloud-init.

Previously, account updates removed old accounts before checking new IDs.
`alice` and `audit-2ola31` received the same UID under the old mapping.
Removing `alice` leaves her files; the next account gets her UID and can
open them. A NoCloud seed can reuse an old name with a new UID; init then
changes ownership of that name's old home.

## Goals

- Revocation stops new logins without making the name, UID, or GID reusable.
- The same source and name may return with the same IDs and home.
- Boot and polling tests reject hash and NoCloud conflicts before account changes.

## Non-Goals

- Killing old processes, reusing IDs, or automatically repairing upgrade conflicts.

## Detailed design

### Reservation table

Keep bounded, versioned source/name/UID/GID rows at `/data/.werewolf/identities`.
Directory root:root 0700; file root:root 0600. PID 1 writes at boot; the root
publisher writes through a pinned FD and narrow Landlock. Workers get no FD.
`/data` itself must be root-owned and not writable by group or others.

For `people`, use `65536 + floor(FNV1a32(name) * (2^30-65536) / 2^32)`.
This spans `[65536,2^30)`, above NoCloud and below service defaults.
Before accepting an account, check system and reserved names, UIDs, and GIDs.
A row may become active again only for the same source, name, UID, and GID.
A different name with the same hash is refused. A NoCloud seed that changes
an existing name's UID is refused. For a home already on disk, require its
owner UID and GID to match the reservation before using it.

Commit a reservation before publishing an account or creating a home: write
a new file, sync it, rename it, then sync the directory. Check type, owner,
mode, version, length, and rows; refuse links, duplicates, and malformed data.
A crash after the commit may waste an ID, but cannot assign it twice.

### Revocation and boot

When an identity disappears, remove its SSH key file and any admin key from
root's file. Retain its passwd and group entries with the same IDs. Give it
shadow `!` and `/sbin/nologin`. Only active `people` names go in
`/run/werewolf/people`; retired entries must survive the next update.
A failed key removal fails publication rather than acknowledging revocation.
Every retry removes keys for all retired reservations, even if an earlier
attempt already replaced the active-name list. When rows are unchanged,
repeat the directory sync without rewriting the table: visible rows do not
prove a prior sync succeeded, and revocation must not need a new table file.
Polling changes `people` accounts but still checks NoCloud reservations.
A missing NoCloud seed retires that identity at the next boot.

Init must stage account requests while reading disk, metadata, and NoCloud.
After mounting `/data`, it loads the table, reserves accepted identities,
derives `/run` account files from the table and active requests, and makes
homes. Services start afterward. With volatile `/data`, both homes and the
table are volatile. If persistent `/data` is unreadable or unwritable, do
not publish non-system accounts.

### Existing installations

An empty data volume starts a new table. The new mapping changes existing IDs.
Do not relabel an old home merely because its name matches. A nonempty
persistent volume with no table blocks publication until its owner migrates
old UID ownership and enrolls the table, or starts with a fresh volume.
Files outside `/data/home` make automatic migration unsafe.

## Drawbacks

Existing data needs migration or replacement. Reservations and locked entries
grow; boot account publication moves after the data mount, and the publisher
gains one narrow write destination.

## Alternatives Considered

Keeping the old 29-bit interval avoids an ID change but roughly doubles the chance
of an accidental collision. Home scans miss deleted homes; deleting homes
destroys data and misses files elsewhere.

## Security Considerations

Treat the seed as hostile input and the table as privileged state. Validate
both before use; refuse a home whose recorded owner does not match. Root
ownership excludes unprivileged live writers but does not protect an offline
writable volume. Lockout does not stop processes already running under the UID.

## Reliability Considerations

A corrupt table or failed durable write blocks new account publication; it
must never silently reset the history. Test return of the same identity,
source and ID conflicts, range endpoints, old-data refusal, NoCloud UID
changes, failed key removal, reboot, and crashes at each commit step.

## Implementation

`lib/people.zig` owns the mapping, table validation, account derivation, and home
checks. Init publishes after mounting `/data`; the metadata publisher uses a pinned
table FD. It checks retained homes through `O_PATH` without reading a user's private
directory. `test/generated/people/tests.yaml` and the metadata poll tests cover boot
and revocation; `test/people-ledger.zig` probes Linux file and owner rules. `make
check-people-persist` reboots one data volume through retirement, hash and NoCloud
conflicts, and reactivation, checking private-file ownership and access. Separate
boots with corrupt or missing tables must stop before service handover.
