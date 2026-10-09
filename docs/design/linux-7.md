# Linux 7.2

Proposed, 2026-10-09. Declined the same day: werewolf stays on Alpine's
`linux-virt` 6.18 LTS until its next LTS. Built anyway, for any kernel:
lockdown `confidentiality`, `dev.tty.legacy_tiocsti=0`, and leash's UNIX
socket rule, which waits for Landlock ABI 9.

## Summary

Boot Alpine edge's `linux-stable` 7.2.9 instead of `linux-virt` 6.18.55,
for Landlock rules 6.18 lacks: which UNIX sockets a service may reach
(ABI 9, 7.1) and UDP (ABI 10, 7.2).

## Background

leash holds each service to its files, TCP ports and system calls
([cmd/leash](../../cmd/leash/README.md)). A socket file is the gap:
Landlock does not check `connect()` to one, so only the directory's mode
(`share`) stands between services. Linux 7.1 added
[`LANDLOCK_ACCESS_FS_RESOLVE_UNIX`](https://docs.kernel.org/userspace-api/landlock.html):
a socket outside the domain is reached only beneath a rule granting it,
and a refusal is `EACCES`. Alpine ships 7.x only as `community/linux-stable`.

## Goals

- nginx reaches php-fpm's socket, and an undeclared socket is refused:
  posture's leash attack, on every boot.
- Every form passes `make check`, and prod-ssh passes on GCP, AWS and Azure.
- No check posture or the build makes is weakened.

## Non-Goals

- Building werewolf's own kernel ([verified-boot.md](verified-boot.md), phase 4).
- Landlock's UDP rules: fence already holds UDP to each user's ports.

## Detailed design

- `boot/kernel.yaml`: edge's main and community, `linux-stable` and
  `linux-firmware-none`. `howl` takes the kernel's file from its config's
  name (`vmlinuz-stable`); the updater passes each repository to apk.
- Module lists: `virtio_pci` and `virtio_mmio` everywhere, and
  `@hyperv hv_vmbus hv_storvsc hv_netvsc`, since `linux-stable` makes
  modules of what `linux-virt` builds in. stage0 knows Hyper-V by DMI's
  vendor, as VMBus no longer exists before modload. `crc32c-cryptoapi` is
  gone: 7.x btrfs uses the kernel's library.
- `sandbox.Ruleset.init(.{ .sockets = true })` handles the new right for
  leash alone; fence and werewolf's own programs, which reach the mount
  broker's socket, keep `fsAll`. A service's `connect PATH` grants the
  right beneath the socket's directory, and `write_tree` carries it, so a
  socket its last run made is reachable. The build refuses a `connect`
  into a strict service's directory.

Tried on 7.2.9: php, wordpress, demo and minimal under QEMU; prod-ssh's
UEFI disk; prod-ssh on GCP arm64 (pass), AWS arm64 (pass but for a posture
line an audit record split) and Firecracker on galadriel (kernel 0.10 s,
userland 0.27 s). The kernel audited `blockers=fs.resolve_unix` for the
undeclared socket, and nginx served php through its declared one.

## Drawbacks

- **Patch lag.** `linux-stable` went 70 days without an update (07-28 to
  10-06, missing 7.1.6–7.1.13 past 7.1's end of life, and 7.2.0–7.2.8),
  and 48 days before that. `linux-lts` takes each 6.18 point release within
  a day. Neither tracks secfixes, so the CVE tiers learn nothing from Alpine.
- **Churn.** 7.2 reaches end of life about two weeks after 7.3 ships (mid
  November 2026): a new series every 9–10 weeks, where 6.18's support is projected to run to 2028.
- **Weight.** No virt flavor: 2,705 options built in against 1,590 (arm64),
  a 42 MB kernel against 36 MB, and Hyper-V's modules on every boot until
  stage0 learned DMI.
- **Config.** AF_ALG's core and hash sockets built in (for iwd), leaving the
  seal as AF_ALG's only barrier; `LEGACY_TIOCSTI`, hibernation (x86), CAN
  and DRM built in; USB audio and video as modules.

## Alternatives Considered

### Stay on 6.18 and prepare (chosen)
Everything kernel-independent lands now; the socket rule switches on when
`linux-virt` reaches the next LTS, likely 7.4 in 2027: bump the kernel,
recheck the module lists and `lib/image.zig`'s config rules.

### Our own kernel
kernel.org stable with werewolf's config: prompt fixes, 7.x's Landlock, and
what Alpine leaves off (`SLAB_FREELIST_HARDENED`, `INIT_ON_FREE`,
`MSEAL_SYSTEM_MAPPINGS`, which needs `CHECKPOINT_RESTORE` off). The most
work, and a kernel to keep patched forever.

### `confidentiality` and UDP rules alone
Lockdown needs no new kernel, and was built. UDP rules repeat fence.

## Security Considerations

Theo would take the kernel that is patched over the one with a new knob.
A two-month-old kernel is a worse hole than a socket that `0711` and the
socket's own mode already guard. What 7.2 opened anyway (TIOCSTI, AF_ALG)
now has a sysctl or the seal, and posture checks both at every boot.

## Reliability Considerations

The updater replaces the kernel only from a signed release built on it, so
a series change cannot reach a machine untested. But a series every 9–10
weeks means a new driver set as often, and `linux-stable` changes its config
freely (30 or more commits on 2026-10-06 alone). An LTS changes neither.
