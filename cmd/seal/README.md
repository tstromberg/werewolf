# seal

## Summary

A machine-wide system call allowlist: a seccomp filter on PID 1, built from
pledge-style promises, which every process inherits and none, root's
included, can remove before a reboot. `seal`, this program, reports it.

## Background

Most kernel escapes go through calls an application never needs: bpf,
userfaultfd, io_uring, keyrings. A werewolf image runs a fixed set of
programs, so their calls are known at build. Parts: `lib/seal.zig`,
`cmd/init`, `cmd/seal-watch`, leash, and `seal`, which anyone may run.

## Goals

- Every process under one filter, from before runit starts until reboot.
- Calls outside every promise fail with ENOSYS, as on an older kernel.
- Each refusal by werewolf's own programs said once, and counted.
- What a form needs, learned on a DEV=1 build (`make seal-learn`).

## Non-Goals

- Reading arguments beyond the few that exploits use: a service's own
  filter narrows the rest.
- Recording a leashed service's refusals: its own filter answers first.
- Binding root within the calls it allows: fence's Landlock and leash do.

## Detailed design

- **Promises** (`lib/seal.zig`) are words such as `stdio`, `rpath`, `inet`,
  each a list of calls for both architectures. `never` calls (bpf, kexec,
  io_uring, keyctl, ...) belong to no promise. `splice` (splice, tee) and
  `sendfile` are promises of their own, out of `stdio`; the machine makes
  `sendfile`, which Zig copies files with.
- **By argument**, machine-wide, whatever a pledge says: a socket family no
  promise names (AF_ALG, RDS, TIPC, VSOCK, ...), `TCP_ULP` (kernel TLS),
  `O_NOTIFICATION_PIPE` (watch queues), and timers on a CPU-time clock,
  each the way into a known exploited bug. Each is refused as a kernel
  without the feature would refuse it.
- **init** allows werewolf's own promises and every service's pledge. It
  kills another architecture's call, refers the rest to a listener, and
  installs the filter with TSYNC, on every thread.
- **seal-watch** answers ENOSYS, says each call once and counts it, past 512
  as `other`; it runs as `_seal` (uid 66), without capabilities, under its
  own filter. Learning (DEV=1, `werewolf.seal=learn`), it allows and
  records each call, with its program and service.
- **leash** gives each service a filter answering ENOSYS. The kernel takes
  the strictest answer, so no pledge exceeds the machine's filter.
- **`seal`** says "enforcing" only when init's policy says `mode enforce`;
  any other mode, or none, is said as unknown, and it exits 1.

## Drawbacks

- Promises are coarse: `mount`, `exec`, `setuid` are allowed machine-wide.
- A leashed service probing `never` calls leaves no record.
- One listener answers every referred call in turn.

## Alternatives Considered

### Per-service filters alone
They leave werewolf's own programs, root's shells and anything unleashed
with every call.

### Kill the caller, as pledge does
A machine-wide KILL outranks each service's ENOSYS, and would kill runtimes
that probe, as libuv does for io_uring.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| seal-watch dies or is killed | The kernel refuses referred calls itself. No service shares `_seal`'s uid to signal it. |
| seal-watch is compromised | It reads only numbers from the kernel; no capabilities; a filter that kills it for any other call or architecture, ioctl only on the listener. |
| Kernel-started helpers | Limited to CAP_SYS_BOOT, and `/proc` is unwritable after fence, so none can be named. |
| Learn mode in production | Needs the DEV=1 marker on the verified root; `make dist` refuses DEV=1. |

## Reliability Considerations

- **Fails closed:** init ends if it cannot install the filter; the kernel
  panics, and the machine returns on the last slot that worked.
- **No flood holds the console:** each call is said once.
- **Checked each boot:** `make check`'s `sealed` wants enforcing, and
  seal-watch as uid 66 with no capabilities; posture's probes try AF_ALG,
  kernel TLS and a watch queue.
