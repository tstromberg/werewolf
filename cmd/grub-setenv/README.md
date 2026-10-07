# grub-setenv

## Summary

Sets one variable in GRUB's environment block, in place, as GRUB itself
would: `grub-setenv FILE NAME VALUE`.

## Background

On a machine bite took over, the distro's GRUB still boots it, and GRUB's
environment block says which slot: `saved_entry` (the committed default),
`next_entry` (one try of a new slot) and `werewolf_args_a`/`_b` (each
slot's kernel arguments). slot-keep sets `saved_entry` when a slot commits;
slot-update sets a new slot's arguments and `next_entry`, and clears
`next_entry` when it gives up on one.

## Goals

- GRUB reads exactly what was set, on its next boot, even after a reset.
- Nothing else in the block changes.
- No path, name or value that GRUB would misread.

## Non-Goals

- Creating a block: bite does, with the distro's `grub-editenv`.
- Escaping values: werewolf's values need no newline or backslash.

## Detailed design

- **In place.** The block is exactly 1024 bytes: a header line,
  `name=value` lines, then `#` to the end. GRUB reads it from where it lies,
  without the filesystem's journal, so the new bytes go over the old.
- **Read as GRUB reads it.** A backslash escapes the next character, so a
  value GRUB stored with a newline stays one variable. A variable is set
  where it was, as GRUB's `save_env` sets one, or added last.
- **Synced for GRUB.** fsync, then syncfs: btrfs answers a file's fsync
  from a log GRUB never replays, and only a commit puts the block where
  GRUB looks.
- **One writer.** Each caller holds GRUB's filesystem from the mount broker,
  which lends it to one program at a time.

## Drawbacks

- A reset mid-write can leave one 512-byte half new, as with GRUB's own
  writes.
- It writes the whole block even when nothing changes.

## Alternatives Considered

### Write a new file and rename it
GRUB would read the old blocks until the journal is written back, which a
reset prevents.

### Run `grub-editenv`
It is the distro's, not in the image, and writes a new file the same way.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A link at FILE writes the block elsewhere | No link is followed at the last component; anything but a regular file is refused. |
| A file that is not a block | Anything but 1024 bytes under GRUB's header is refused, unchanged. |
| A value GRUB would misread | Names are letters, digits and `_`; values have no newline or backslash, whose trailing one would swallow the next variable. |
| A value too long | It would overflow the block, so it is refused, unchanged. |

## Reliability Considerations

- **A torn write cannot reach other variables** on a commit: a variable keeps
  its place, so `werewolf-a` to `werewolf-b` changes only its own byte.
- **A reset just after** finds the block in place on ext4 and xfs, and
  committed on btrfs.
- **Tested:** `check-slot` reads the committed default off the disk;
  `check-updater` boots the slot `next_entry` names.
