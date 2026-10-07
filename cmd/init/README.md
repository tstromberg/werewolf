# init

## Summary

PID 1 from stage0's handover until runit: it makes the machine reachable
(filesystems, the kernel's settings, one address, the operator's keys,
`/data`), seals it, and hands over to fence, which becomes runit. It is in
every image, and never needs to know which form it is in.

## Background

stage0 mounts the verified, read-only root and hands over. Nothing after can
write the root, so what changes lives in `/run`, `/tmp`, `/var/tmp` and
`/data`. init decides from what the image carries (a DHCP client, mke2fs,
cryptsetup) and what it is told: the kernel command line (`werewolf.ip`,
`.gw`, `.dns`, `.mac`, `.data`, `.victim`, `.grubenv`), and one config.
It runs no shell: what it cannot do itself it asks of werewolf's programs
and the form's filesystem tools, each by its full path.

## Goals

- On the network, with its keys and `/data`, in under a second of userland.
- Every protection in place before any service starts: lockdown, sysctls,
  the seal, fence.
- Fail closed on what protects the machine; boot on, and say so, on the rest.
- Never destroy data: a disk is formatted once, while blank, and never again.

## Non-Goals

- Running services: runit does, under fence and leash.
- cloud-init: a NoCloud seed gives a user and keys, never scripts.
- Knowing the form: it only has the tools or not.

## Detailed design

1. **Filesystems**: `/proc` (`hidepid=invisible`), `/sys`, `/dev`, and RAM
   filesystems, all `nosuid` and `noexec`; a cgroup2 tree for leash's
   services; accounts seeded into `/run` from the image's copies.
2. **The kernel**: lockdown raised to integrity, modules loaded and closed,
   then the protective sysctls. One the kernel refuses ends the boot, but
   for a container's read-only `/proc/sys`.
3. **The config** on the machine's disks, one tar: the victim's `config.tar`, or else the first
   block device holding one; any other is said and ignored. A confined
   child extracts it to `/run/config`: root's uid without capabilities,
   Landlock on `/run/config` alone, seccomp of file calls; at most 256
   entries and 16 MiB, checked before anything is written. Beside it, a
   NoCloud volume, only if labelled `cidata`, adds a user, keys and Lima's
   data files, never replacing the tar's. A seed's `network-config` is
   not read.
4. **The network**: `iface-up` with the command line's address, or else
   the config tar's `network` file's (`lib/network.zig`, checked as
   `werewolf pack` checks it), or else `dhcp-client up`. Then, where no
   disk held a config, `cloud-metadata`; a `network` file it brings comes
   too late, and is said and not read. Then the hostname and root's keys.
5. **`/data`**: a directory beside the slots, RAM, or the disk labelled
   `werewolf-data`, in LUKS2 when the config has a `data.key` of 32 bytes
   or more. Anything it cannot use is left as it is, and `/data` is an
   empty read-only tmpfs, with the reason in `/run/werewolf/nodata`.
6. **The seal**, then the two programs that must stay outside fence's
   domain (the mount broker; DHCP's renewal), then `exec fence runit`.

## Drawbacks

- Before the seal it runs as root with every capability, and the kernel
  still parses whatever filesystem a config or seed disk carries.
- A single-slot machine that fails closed reboots into the same image.
- Its own steps say what failed, but only the seal, fence and the sysctls
  stop the boot; a missing hostname or key is said and passed.

## Alternatives Considered

### A shell script, as most distributions' initramfs
A shell is what werewolf ships without; a program parses its inputs strictly
and can run with no interpreter in the image.

### Merging every config found
A disk attached by anyone would then add to or replace root's keys. One
source, said, leaves no doubt which config the machine runs.

### Probing every disk for a NoCloud seed
That mounts every disk through the kernel's ISO 9660 parser. A label read
by blkid, in its own process, picks the one disk that claims to be a seed.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A hostile config tar on a disk | Extracted by a confined child; plain relative names, files and directories only, no links; 1 MiB a file, 16 MiB and 256 entries in all. |
| A second config disk, attached later | Ignored, and said: one source only. |
| A hostile disk mounted to look for a seed | Only a device labelled `cidata` is mounted, read-only, `nosuid`, `noexec`. |
| A weak `data.key` with a quick KDF | LUKS2 is not made with one under 32 bytes; an existing disk opened with one is warned of. |
| A disk that claims to be `/data` | Two with the label are refused, as is a device holding a config tar. |
| A security sysctl not applied | The boot ends, and the machine returns on the slot that last worked. |
| Helpers the kernel starts outside the seal | Their capabilities are cut to CAP_SYS_BOOT before the seal. |

## Reliability Considerations

- **Fails closed** on the sysctls, the seal and fence: PID 1 ends, the
  kernel panics (`panic=10`), and GRUB's one-try entry falls back.
- **Never formats twice**: a disk with the label is checked with `e2fsck -p`
  and mounted, or left alone for a person.
- **Never waits on a person**: stdin is `/dev/null`, so no tool can prompt.
- **Tested**: every `make check` boot runs it, with a static address, DHCP,
  a config disk, LUKS, slots, metadata servers and Lima.
