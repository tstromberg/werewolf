# grub-setenv

## Summary

grub-setenv sets one variable in GRUB's environment block, in place, the way
GRUB itself would: `grub-setenv FILE NAME VALUE`.

## Background

On a machine bite took over, the distro's GRUB still boots it, and GRUB's
environment block says which slot to boot: `saved_entry` (the committed
default), `next_entry` (one try of a new slot) and `werewolf_args_a`/`_b`
(each slot's kernel arguments). slot-keep sets `saved_entry` when a slot
commits. slot-update sets a new slot's arguments and `next_entry`, and clears
`next_entry` when it gives up on a slot.

## Goals

- GRUB reads exactly what was set on its next boot, even after a reset.
- Nothing else in the block changes.
- Refuse any path, name or value that GRUB would misread.

## Non-Goals

- Creating a block. bite does that with the distro's `grub-editenv`.
- Escaping values. werewolf's values need no newline or backslash.

## Detailed design

- **In place.** The block is exactly 1024 bytes: a header line,
  `name=value` lines, then `#` to the end. GRUB reads its sectors directly,
  without the filesystem's journal, so the new bytes overwrite the old.
- **Parsed as GRUB parses it.** A backslash escapes the next character, so a
  value GRUB stored with an escaped newline stays one variable. A variable is
  set where it was, as GRUB's `save_env` does, or appended. A duplicate entry
  is dropped. Comments are dropped and the rest is padded with `#`.
- **Synced for GRUB.** fsync, then syncfs. btrfs answers a file's fsync from
  a log GRUB never replays; only a commit puts the block where GRUB looks.
- **One writer.** Each caller holds GRUB's filesystem from the mount broker,
  which lends it to one program at a time.
- **Errors** print one line, `grub-setenv: ...`, and exit 1. A refused
  block, name or value leaves the file unchanged.

## Drawbacks

- A reset mid-write can leave one 512-byte sector new and one old, as with
  GRUB's own writes.
- It writes the whole block even when nothing changes.

## Alternatives Considered

### Write a new file and rename it
GRUB would read the old sectors until the journal is written back, which a
reset prevents.

### Run `grub-editenv`
It is the distro's, not in the image, and writes a new file the same way.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A link at FILE redirects the write | No link is followed at the last component; anything but a regular file is refused. |
| A file that is not a block | Anything but 1024 bytes starting with GRUB's header is refused, unchanged. |
| A value GRUB would misread | Names are letters, digits and `_`; values have no newline or backslash (a trailing one would swallow the next variable). |
| A value too long | It would overflow the block, so it is refused, unchanged. |

## Reliability Considerations

- **A torn write cannot reach other variables** on a commit: a variable keeps
  its place, so `werewolf-a` to `werewolf-b` changes only one byte.
- **A reset just after** finds the block in place on ext4 and xfs, and
  committed on btrfs.
- **Tested:** unit tests for `edit` and `nextEntry`; `check-slot` reads the
  committed default off the disk; `check-updater` boots the slot `next_entry`
  names.
