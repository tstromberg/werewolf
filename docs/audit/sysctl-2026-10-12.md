# Sysctl boundary review

Tested on 2026-10-12: aarch64 playground VMs under Lima, built from this
checkout with howl, Linux 6.18.56-0-virt. The attacker was a root SSH
session under the machine seal and fence. No service-specific filter was
added to the probes.

## Finding and fix

The `/proc/sys` write restriction held, but it did not cover every way to
change the underlying settings. Before the fix, `dmesg -n 5` succeeded as
root and changed the first value of `kernel.printk` from 6 to 5. Kernel
notices would then stop reaching the console. The test restored 6.

This used `syslog(SYSLOG_ACTION_CONSOLE_LEVEL)`. The `syslog` promise
allowed the entire syscall, and root retained `CAP_SYSLOG` for reading
logs. Landlock was never consulted because no sysctl file was opened.

The machine seal now allows only syslog actions 0, 1, 2, 3, 9 and 10.
Actions that clear the log or change console settings, and unknown actions,
are refused. The listener returns `EPERM`; it also refuses them in learn
mode. Reading the kernel log remains available.

`files-system-writes` now probes eight settings across `kernel`, `vm`,
`user`, `fs` and `net`, using both `O_WRONLY` and `O_RDWR`. It writes nothing
and requires `EACCES`; missing `kernel.printk` fails instead of passing.
The new `kernel-log-control` check tries the console-setting action with
the current valid level. An unprotected kernel accepts it without changing
that level, which makes the check fail safely.

## Patched VM results

| Attempt | Result |
| --- | --- |
| Write opens on eight sysctls, with both access modes | `EACCES` |
| Paths through `/proc/1/root`, `/proc/self/root`, `/proc/thread-self/root` | `EACCES` |
| `openat` through an `O_PATH` directory; `openat2` | `EACCES` |
| Reopen a read-only sysctl through `/proc/self/fd` for writing | `EACCES` |
| Write through the original read-only descriptor | `EBADF` |
| Hard link into `/run`; follow a symlink from `/run` | `EXDEV`; `ELOOP` |
| New proc mount; bind `/proc/sys` into `/run`; `fsopen("proc")` | `EPERM` |
| Create user/mount namespaces; join PID 1's mount namespace | `ENOSYS` |
| Steal PID 1's descriptor with `pidfd_getfd` | `ENOSYS` |
| Syslog actions 4 through 8; action 8 with high argument bits set | `EPERM` |
| Read kernel log buffer size through syslog | Success |
| `TIOCLINUX` console control | `ENOTTY`: this VM's console does not implement it |

Both posture checks passed, as did `kernel-console-log`. The VM still had
the playground's shell/login weaknesses and boot integrity gaps; this was
not an all-green posture report. Seal unit tests passed on aarch64 and
x86_64, including every syslog action, missing promises and argument width.

## Limits and remaining attack paths

- **Descriptors opened before confinement retain their rights.** Init's
  sysctl writer closes each descriptor and marks it close-on-exec. New boot
  code must preserve this. No visible descriptor referred to `/proc/sys`
  in the post-boot scan. The probes covered reopening a read-only
  descriptor, not revoking a deliberately inherited writable descriptor.
- **Helpers outside fence remain trusted.** The mount broker has
  `CAP_SYS_ADMIN` and is outside Landlock. Its protocol accepts fixed words
  and filesystem identities, not arbitrary paths or filesystems. This
  source review found no request that opens or writes a sysctl. Code
  execution inside the broker would cross the tested boundary. DHCP has
  its own Landlock domain; seal-watch cannot open files after confinement.
- **Network allowances matter.** A form retaining `CAP_NET_ADMIN` can
  reconfigure networking through other interfaces. The playground tests
  do not establish equivalent restrictions for those forms.
- **Reboot is a separate boundary.** Mutable boot files can change the
  next kernel or init. Firmware enforcement and authenticated boot inputs
  are required to extend these guarantees across reboot.
- **Kernel exploitation was not tested.** These probes test supported
  interfaces under the existing kernel, not resistance to a kernel bug.

No additional working bypass was found in these probes. That is a bounded
test result, not proof that every route to every kernel setting is closed.
