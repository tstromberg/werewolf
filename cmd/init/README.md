# init

## Summary

init is PID 1 from stage0's handover until runit. It mounts filesystems,
sets the kernel's protections, reads the config, brings up the network and
`/data`, seals the machine, and execs fence, which becomes runit.

## Background

stage0 mounts the verified, read-only root, so all that changes lives in
`/run`, `/tmp`, `/var/tmp` and `/data`. init is in every form and must not
know which: it decides from the tools the image carries (DHCP client,
mke2fs, cryptsetup), the command line's `werewolf.*` words
(`lib/cmdline.zig`) and one config tar. It runs no shell.

## Goals

- Reach the network, with keys and `/data`, in under a second of userland.
- Set every protection (lockdown, sysctls, MDWE, seal, fence) first.
- Fail closed on what protects the machine; log and boot on for the rest.
- Never destroy data: format a disk only while it is blank.

## Non-Goals

- Running services (runit does), or scripts from a cloud-init seed.

## Detailed design

`init.zig` runs the phases in order, each in its own file:

1. **Filesystems** (`kernel.zig`): `/proc` (`hidepid=invisible`), `/sys`,
   `/dev`, RAM filesystems (`nosymfollow`), all `nosuid,noexec`; devpts only
   if the form allows `pty`; cgroup2 for leash; accounts copied to `/run`.
2. **Kernel** (`kernel.zig`): lockdown to integrity, modules loaded and the
   loader closed (`cmd/modload`), sysctls, audit of refused execs, then MDWE
   on PID 1 unless the form allows `jit`. A refused sysctl or MDWE ends the
   boot, except in a container, where they are the host's.
3. **Config** (`config.zig`): one tar, the victim's `config.tar` or else
   the first block device holding one; others are logged and ignored. A
   confined child (no capabilities, Landlock, seccomp) extracts it to
   `/run/config`. A NoCloud volume labelled `cidata` adds a user, keys and
   Lima's data files, never replacing the tar's.
4. **Network** (`network.zig`): `iface-up` with the command line's or the
   tar's address (`lib/network.zig`), else `dhcp-client up`. Router
   advertisements count on that NIC only. Without a disk config,
   `cloud-metadata` fetches one. Then the hostname and root's keys.
5. **`/data`** (`data.zig`): a directory beside the slots, RAM, or the disk
   labelled `werewolf-data`, in LUKS2 when the config has a `data.key`.
   Otherwise `/data` is an empty read-only tmpfs and `/run/werewolf/nodata`
   says why, which also stops a slot on probation from committing.
6. **Image roots** (`oci.zig`), if the build listed any: binds for each,
   made before fence forbids mounting ([adhoc.md](../../docs/design/adhoc.md)).
7. **Seal** (`seal.zig`): core dumps off, helpers cut to CAP_SYS_BOOT,
   seal-watch started, bounding set cut, seccomp filter installed. The mount
   broker and DHCP renewal start outside fence; then `exec fence runit`.

## Drawbacks

- Until the seal it runs as root with every capability, and the kernel
  parses whatever filesystem a config or seed disk carries.
- A single-slot machine that fails closed reboots into the same image.
- `/data` follows links (`symfollow`), since the updater and apk build
  roots there, so a service could plant a link for a root program walking
  its directory. None does today. Open; listed in docs/security.md.

## Alternatives Considered

### A shell script, as most initramfs use
werewolf ships no shell, and a program parses its inputs strictly.

### Merging every config found
Any attached disk could then add to or replace root's keys. One source,
logged, leaves no doubt which config the machine runs.

### Probing every disk for a NoCloud seed
That mounts every disk through the kernel's ISO 9660 parser, and blkid
costs 85 ms on GCP. Reading each disk's volume descriptor finds the seed.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A hostile config tar | Confined child; plain relative names, files and directories only; size limits checked on both passes. |
| A hostile seed disk | Only a device labelled `cidata` is mounted, read-only, `nosuid`, `noexec`. |
| A FIFO or link on a victim or seed | Opened `O_NOFOLLOW`; only a regular file (or a disk, for a tar) is read, so PID 1 cannot block. |
| A weak `data.key` | LUKS2 is not made with one under 32 bytes; an existing disk opened with one is warned of. |
| A disk that claims to be `/data` | Two with the label are refused, as is a device holding a config tar. |
| A security sysctl not applied | The boot ends, and the machine returns on the slot that last worked. |
| Usermode helpers outside the seal | Cut to CAP_SYS_BOOT; `kernel.modprobe` and `kernel.hotplug` emptied. |

## Reliability Considerations

- **Fails closed** on the command line, the sysctls, MDWE, the seal and
  fence: PID 1 exits, the kernel panics (`panic=10`), and GRUB's one-try
  entry falls back. Other steps, such as a hostname or a key, log and pass.
- **Never formats twice**: a labelled disk is checked (`e2fsck -p`) and
  mounted, or left alone. stdin is `/dev/null`, so no tool can prompt.
- **Tested**: every `make check` boot runs it, with a static address, DHCP,
  a config disk, LUKS, slots, metadata servers and Lima.
