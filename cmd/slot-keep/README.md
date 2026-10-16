# slot-keep

## Summary

slot-keep commits a new slot once it has proved itself: it makes this slot
the boot loader's default and tells stage0's deadman to stand down. Until
then the slot is on probation, and a reset goes back to the last good slot.

## Background

An update writes the other slot and boots it once (docs/updater.md). If the
slot cannot boot, the loader falls back by itself. If it boots but does not
work, stage0's deadman reboots after ten minutes unless
`/run/werewolf/committed` exists, and the loader goes back.
systemd-boot on werewolf's own disk (docs/design/native-boot.md) counts tries
in the entry name
(`werewolf-a+1.conf`) until it is renamed `werewolf-a.conf`.

## Goals

- Commit a slot only when it works: every other service up for a minute,
  `/data` usable, if the form has an updater, the updater ready, and
  posture failing nothing the image does not excuse. A broken updater is
  the one failure no later update could undo; a lost protection would be
  measured as normal by every later boot.
- Never commit on a guess. A slot not shown to work is left for the deadman.
- Change the loader only through the mount broker, and only for as long as
  the write takes.

## Non-Goals

- Judging a service beyond runsv's word. Up for a minute is the test.
- Rolling back. The deadman and the loader do that.

## Detailed design

runsv starts it as `/etc/sv/slot-keep/run`, with no arguments. It opens its
control pipe, becomes `_slotkeep` (uid 72) without capabilities, and enters
a read-only Landlock domain before judging service health.

1. **Which slot.** It parses the kernel command line as stage0 does
   (`lib/cmdline.zig`). `werewolf.esp` with `werewolf.slot` identifies
   a systemd-boot slot; anything else means nothing to commit, and it parks.
   The parser allows only slot `a` or `b`. A refused command line is logged,
   and it parks.
2. **Wait** every 15 s until healthy. Each `/etc/sv/*/supervise/status`
   (20 bytes: last change, want, state) must show the service running for
   60 s, or down because it wants to be. Down while wanted up (between
   crashes), finishing (leash-reap clearing a crash), or no status yet is not
   healthy. After two minutes it logs the blocking service each time it
   changes, so a crash loop is visible before the deadman acts. Then, if
   `/etc/sv/autoupdate` exists, it waits for `/run/werewolf/updater-ready`,
   which slot-update writes once its setup succeeds, logging this once.
   Then it reads posture's report, `/run/werewolf/posture.json`: a check
   that fails without an excuse in the image's weaknesses, or a report it
   cannot read, means the slot is never committed, and it parks saying so.
   posture parks itself after writing, so its health says nothing.
3. **Not with `/data` gone.** If `/run/werewolf/nodata` exists, it logs its
   reason and commits nothing.
4. **systemd-boot**: the broker renames the counting entry to
   `werewolf-SLOT.conf` on a detached EFI mount and syncs it. If the loader already
   points at this slot, it skips the write.
5. **Commit**: the broker creates `/run/werewolf/committed`, root-owned,
   only after keeping the EFI entry. The keeper logs one line and
   parks (`sv down .`). Commit never retires the retained A/B release in the TPM;
   retirement belongs to replacing the inactive slot (docs/design/tpm-ab-retirement.md).

## Drawbacks

- A minute is a heuristic: a service that fails after an hour is kept.
- A form whose updater never gets ready is never committed, so it reboots
  every ten minutes back to the old slot. That is intended, but loud.

## Alternatives Considered

### `sv status`, as it first did
It ran a process per service every 15 s and parsed text. It counted a
service finishing after a crash as healthy, so a crash loop could be kept.

### Commit as soon as the slot boots
A slot that boots but cannot serve, or cannot update, would be kept for good.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A broken update committed | Only after every service has run a minute, /data works, the updater is ready, and posture fails nothing unexcused. |
| A path from the command line | Slot a or b; the broker derives entry paths itself. |
| Writing the loader | Through the mount broker, mounted detached for one write. |
| Its own privilege | Non-root, no capabilities, read-only file access; only its keeper channel can request the commit. |

## Reliability Considerations

- **Fails safe**: anything it cannot do leaves the slot uncommitted, and the
  deadman takes the machine back.
- **Logs each step**: why it waits, why it did not commit, what it committed.
- **Tested**: unit tests for `serviceHealthy` and the broker's loader operations;
  `check-slot` and `check-updater` (native EFI), each with a boot
  that must be committed. `check-persist` and `check-dist` boot werewolf's own disk;
  `check-ab-qemu` covers signed upgrade, commit and both rollback paths.
