# slot-keep

## Summary

Keeps a new slot once it has proved itself: it makes the boot loader's
default this slot, and tells stage0's deadman to let the machine be.
Until then the slot is on probation, and a reset goes back to the last one
that worked.

## Background

An update writes the other slot and boots it once (docs/updater.md). If it
cannot boot, the loader falls back by itself; if it boots but cannot run,
stage0's deadman reboots it after ten minutes, unless
`/run/werewolf/committed` says otherwise, and the loader goes back. Two
loaders choose slots: a distro's GRUB after bite (`saved_entry` in its
environment block), and systemd-boot on werewolf's own disk (an entry
whose name counts its tries, `werewolf-a+1.conf`, kept as `werewolf-a.conf`).

## Goals

- Keep a slot only when it works: every other service up for a minute,
  `/data` usable, and, where the form has an updater, the updater able to
  update, the one failure no later update could undo.
- Keep nothing on a guess: a slot that is not shown to work is left for the
  deadman.
- Change the loader only through the mount broker, for only as long as the
  write takes.

## Non-Goals

- Judging a service beyond runsv's word: up a minute is the test.
- Rolling back: the deadman and the loader do.

## Detailed design

1. **Which loader**: `/run/werewolf/grubenv` (init writes it from
   `werewolf.grubenv=UUID:PATH`) means GRUB; else `werewolf.esp` and
   `werewolf.slot` mean systemd-boot; else nothing to keep, and it parks.
   The slot must be `a` or `b`, and GRUB's PATH absolute with no `.` or `..`
   parts, as both go into paths written as root.
2. **Wait**, every 15 s, until healthy: each `/etc/sv/*/supervise/status`
   (20 bytes: state, want, time of the last change) says running for 60 s,
   or down because it asked to be. Down while wanted up (between crashes),
   finishing (a crash, while leash-reap clears it), or no status yet is not
   healthy. Then, if `/etc/sv/autoupdate` exists, wait for
   `/run/werewolf/updater-ready`, said once.
3. **GRUB**: the broker mounts the block's filesystem apart, writable;
   `grub-setenv` sets `saved_entry=werewolf-SLOT` in place.
   **systemd-boot**: the broker mounts the EFI partition; the counting
   entry is renamed to `werewolf-SLOT.conf`, then `sync`.
4. **Not with `/data` gone**: if `/run/werewolf/nodata` says why, nothing is
   kept.
5. **Commit**: `/run/werewolf/committed`, one line on the console, park.

## Drawbacks

- A minute is a heuristic: a service that fails after an hour is kept.
- A form whose updater never gets ready is never kept, and so reboots every
  ten minutes, back to the old slot: by design, but loud.

## Alternatives Considered

### `sv status`, as it first did
A process per service every 15 s, and text to parse; it counted a service
finishing after a crash as healthy, so a crash loop could be kept.

### Keep at once, as soon as the slot boots
A slot that boots but cannot serve, or cannot update, would be kept for good.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A broken update kept | Kept only after every service has run a minute, /data works, and the updater is ready. |
| A path from the command line | Slot a or b; GRUB's path absolute with no `.` or `..`. |
| Writing the loader | Through the mount broker, mounted apart for one write; GRUB's block rewritten in place by `grub-setenv`. |
| Its own privilege | Root, in fence's domain and under the seal; it asks the broker, which alone can mount. |

## Reliability Considerations

- **Fails safe**: anything it cannot do leaves the slot uncommitted, and the
  deadman takes the machine back.
- **Says each step**: why it waits on the updater, why it did not keep, what
  it kept.
- **Tested**: `check-slot` (GRUB after bite) and `check-updater`
  (systemd-boot), each with a boot that must be kept.
