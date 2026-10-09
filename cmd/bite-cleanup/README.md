# bite-cleanup

## Summary

bite-cleanup deletes the distro that [bite](../../docs/bite.md) took over,
once werewolf is GRUB's default. It keeps werewolf's directory and `/boot`,
deletes everything else on the victim's filesystem, and trims the freed
blocks. `bite-cleanup -n` shows what would go and changes nothing.

## Background

bite installs werewolf beside a Debian, Ubuntu, Fedora or Rocky VM: the
slots, `config.tar` and `data/` in `/var/lib/werewolf`, and the slots'
kernels in `/boot/werewolf`. Until werewolf commits, the distro is GRUB's
fallback. After that it is stale: nothing updates it, and it still holds
its secrets, cloud-init's user-data among them. bite-cleanup ends it. It is
in every form and runs as root under runit, where nothing may mount, so it
asks the mount broker (`lib/broker.zig`) for GRUB's filesystem and the
victim's, mounted writable at `/run/werewolf/mnt/`.

## Goals

- Delete the distro only on a machine that has committed to werewolf.
- Never delete werewolf: a layout it misreads must leave the distro whole.
- Delete all it may, and name what it may not.
- Hand the freed blocks back to a thin cloud volume.

## Non-Goals

- Erasing data: `rm` frees blocks, and earlier snapshots still hold the
  distro.
- Editing GRUB's menu: the distro's entries stay, and no longer boot.
- Undo: after it runs, `bite --undo` is no longer possible.

## Detailed design

1. **Read** `werewolf.victim`, `werewolf.grubenv` and `werewolf.slot` from
   `/proc/cmdline` with `lib/cmdline.zig`. Without them the machine was not
   bitten, and it stops.
2. **Plan** what to keep: werewolf's directory, which must hold
   `SLOT/root.erofs`; and, if GRUB's environment is on the same filesystem
   (UUIDs compared as bytes), the directory above GRUB's (`/boot`, or
   `/@/boot` in a btrfs subvolume), which must hold `werewolf/SLOT/vmlinuz`.
   If GRUB's directory is at the top of the filesystem, it refuses.
3. **Check commit**: it mounts GRUB's filesystem through the broker and
   reads the environment block (non-blocking, through no link, at most
   4 KiB). Unless `saved_entry` is `werewolf-a` or `werewolf-b`, it stops.
   If slot-keep holds the mount, it retries once a second later.
4. **Fork a child** on the victim's mount. The child opens each needed
   file with `openat2` (`RESOLVE_BENEATH`, no symlinks) and deletes nothing
   if one is missing. Then it confines itself (`lib/sandbox.zig`):
   `no_new_privs`, only CAP_DAC_OVERRIDE and CAP_FOWNER, Landlock allowing
   only reading directories and removing beneath the mount (no network,
   scoped signals), and a seccomp filter of the calls walking takes.
5. **Walk**: an entry that is kept stays; one above something kept is
   descended; anything else is deleted whole. Symlinks are deleted, never
   followed. When `deleteTree` meets an entry it may not delete (`chattr +i`
   or `+a`, as some cloud agents leave `/etc/resolv.conf`), it deletes
   everything around it, at most 256 levels deep, and names what stays.
6. **Finish**: the parent syncs, trims the filesystem (`FITRIM`), and
   releases the mount. It exits 1 if anything stays.

Each log line goes to the console. Names come from the distro's disk, so
control bytes are printed as `?`.

## Drawbacks

- The distro's GRUB entries remain and fail to boot.
- Deleted files stay readable in snapshots and unerased blocks.

## Alternatives Considered

### Delete from bite, at install
The distro is the fallback until werewolf commits; deleting it then would
leave a failed first boot nothing to fall back on.

### Delete in PID 1 with every capability
A misread layout or a hostile name would then reach the whole machine. The
confined child can only remove entries beneath one mount.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| Deleting werewolf | It must find the slot's `root.erofs` and kernel beneath the kept paths, through no link, before deleting. |
| A link leading out of the victim | Never followed: Landlock and `openat2` keep the child beneath the mount. |
| A FIFO as GRUB's environment | Opened non-blocking. |
| Escape sequences in the distro's names | Control bytes become `?`. |
| The deleter turned | Two capabilities, Landlock, and a seccomp allowlist. |

## Reliability Considerations

- **Fails closed**: any doubt about what to keep deletes nothing.
- **Partial deletes** are named, and the rest still goes.
- **Tested**: `make check-slot` boots a slot on a stand-in distro with an
  immutable `/etc/resolv.conf` and links that lead out, and checks what
  stays (`test/checks`, `cleanup`).
