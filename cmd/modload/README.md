# modload

## Summary

Loads the form's kernel modules, in the order the build listed them, then
closes the kernel's module loader for the life of the machine.

## Background

werewolf runs Alpine's kernel, whose drivers (virtio, NVMe, filesystems,
dm-verity, a cloud's NIC) are modules. Each form names the ones it needs;
the build resolves their dependencies, decompresses them (Alpine's kernel
cannot), and lists them in `/usr/lib/modules/RELEASE/werewolf.modules`, on
the verified, read-only root. stage0 runs it; init's run finds the loader
closed already and says so. What only one filesystem needs (Rocky's xfs,
Fedora's btrfs, which bite leaves) is listed `@xfs PATH`, and loads only
on a slot that is on it: btrfs's raid6 alone timed itself for 0.17 s of
every boot.

## Goals

- Every module the form needs loaded before anything uses the hardware.
- No module loaded that the kernel did not verify as signed by its builder.
- After it, no module loaded by anyone, root included, until reboot.
- Each refusal said, with the kernel's own reason.

## Non-Goals

- Choosing modules at run time (udev, modprobe): the form decides at build,
  and the boot only which filesystem's lines it needs.
- Judging a module: the kernel does, by its signature.

## Detailed design

1. **Refuse unless the kernel will check**: lockdown at integrity or above,
   or `module.sig_enforce`. Otherwise nothing loads, and the loader closes.
2. **The list, strictly**: paths under `kernel/`, ending `.ko`, of plain
   characters, no `.`, `..` or empty parts, at most 256, each with
   `KEY=VALUE` parameters of plain characters, and for a filesystem's own,
   `@` and a name of 1 to 15 letters and digits first. One bad line, and
   none.
3. **Open everything first**, beneath the module directory with symlinks
   refused (`openat2`, `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`), and the two
   descriptors that close the loader and read it back.
4. **Pledge** (`lib/sandbox.zig`): every capability but CAP_SYS_MODULE
   gone, from the bounding set too, securebits locked; a seccomp filter of
   `finit_module`, `read`, `write`, `close` and exit, killing anything else.
5. **Load** each by `finit_module` on its open file, so the kernel reads and
   checks what is on disk, not a copy. A module already built in counts as
   loaded; one whose hardware is absent (ENODEV, EOPNOTSUPP) as absent.
   Untagged lines first; then one line from stdin, the filesystem stage0
   found the slot on while these loaded (`none` without a slot), picks the
   tagged lines to load. stdin ending unnamed loads them all, as before.
6. **Close** the loader (`kernel.modules_disabled=1`) whatever happened,
   and read it back: the kernel's answer, not the write's, is reported.

## Drawbacks

- A module refused at boot cannot be loaded later without a reboot: the
  loader is closed by design.
- init cannot tell a loader left open from a driver refused (both exit 1),
  so it boots on in either case.

## Alternatives Considered

### modprobe with modules.dep
A larger tool resolving dependencies on the machine, from files a person
could edit; the build resolves them once, into a list the image verifies.

### Building every driver into the kernel
werewolf uses Alpine's signed kernel and its modules unchanged, so its
fixes arrive as Alpine ships them.

### Loading from a copy in memory (init_module)
The kernel would check bytes this program read. `finit_module` hands it the
file itself.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| An unsigned module | Refused by the kernel under lockdown; modload loads nothing without it. |
| A list or path that leads elsewhere | Clean paths only, opened beneath the module directory with symlinks refused. |
| A module loaded later | `kernel.modules_disabled=1`, which only rises; then the seal drops CAP_SYS_MODULE from every process and refuses `init_module` and `finit_module` to all. |
| modload itself turned | It holds CAP_SYS_MODULE alone, already-open files, and six system calls. |

## Reliability Considerations

- **Fails closed**: without signature enforcement, or with a bad list, no
  module loads, and the loader closes anyway.
- **Hardware that is not there** is not an error: one CPU vendor's KVM on
  the other's, or a cloud's NIC driver elsewhere.
- **Checked each boot**: posture's `kernel-modules-closed` and
  `kernel-modules-signed`.
