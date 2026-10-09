# seal

## Summary

The seal is a machine-wide system call allowlist: a seccomp filter on PID 1,
built from pledge-style promises, that every process inherits and none, not
even root, can remove. `seal`, this program, reports it.

## Background

Most kernel escapes go through calls an application never needs: bpf,
userfaultfd, io_uring, keyrings. A werewolf image runs a fixed set of
programs, so their calls are known at build time. The parts are
`lib/seal.zig`, `cmd/init`, `cmd/seal-watch`, leash, and `seal`, which
anyone may run:

    $ seal
    seal: enforcing; the machine promises stdio rpath wpath inet unix ...
    services:
      app          stdio rpath inet listen
      slot-keep    (werewolf's own: the machine's promises alone)
    refused this boot:
      keyctl           never     1 time, last by pid 97, first at 2026-10-07 01:14:03 UTC
    never allowed: bpf perf_event_open init_module ...
    never allowed for what they ask: socket and socketpair (a family no promise names); ...

## Goals

- One filter covers every process, from before runit starts until reboot.
- Calls outside every promise fail with ENOSYS, as on an older kernel.
- Each refusal by werewolf's own programs is logged once and counted.
- A DEV=1 build learns what a form needs (`make seal-learn`).

## Non-Goals

- Checking arguments beyond the few that exploits use. A service's own
  filter narrows the rest.
- Recording a leashed service's refusals. Its own filter answers first.
- Limiting root within the calls it allows. fence's Landlock and leash do.

## Detailed design

- **Promises** (`lib/seal.zig`) are words such as `stdio`, `rpath`, `inet`.
  Each is a list of calls for both architectures. `never` calls (bpf,
  kexec, io_uring, keyctl, ...) belong to no promise. `splice` (splice,
  tee) and `sendfile` are separate from `stdio`. The machine promises
  `sendfile`, which Zig uses to copy files.
- **Refused by argument**, machine-wide, whatever a pledge says: a socket
  family no promise names (AF_ALG, RDS, TIPC, VSOCK, ...), `TCP_ULP`
  (kernel TLS), `O_NOTIFICATION_PIPE` (watch queues), and timers on a
  CPU-time clock. Each is the way into a known exploited bug. Each fails
  as it would on a kernel without the feature.
- **init** allows werewolf's own promises and every service's pledge. It
  kills calls from another architecture, refers the rest to seal-watch,
  and installs the filter with TSYNC, on every thread.
- **seal-watch** answers ENOSYS and logs each call once (see its README).
  When learning (DEV=1, `werewolf.seal=learn`), it allows and records each
  call with its program and service.
- **leash** gives each service a filter that returns ENOSYS. The kernel
  takes the strictest answer, so no pledge can exceed the machine's filter.
- **`seal`** reads init's policy (`seal.policy_path`), seal-watch's refused
  table, and each `/etc/sv/NAME/service` file, parsed as leash parses it.
  A service with no service file is werewolf's own. A file leash refuses
  is shown with the reason, since that service will not run. `seal` says
  "enforcing" only for `mode enforce`, and "learning" for `mode learn`.
  It exits 1 for any other mode, no mode, or no policy file.

## Drawbacks

- Promises are coarse: `mount`, `exec` and `setuid` are allowed machine-wide.
- A leashed service's refusals reach only the kernel's audit log, not seal-watch's.
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
| seal-watch dies or is killed | The kernel refuses referred calls itself. No service shares `_seal`'s uid, so none can signal it. |
| seal-watch is compromised | It reads only numbers from the kernel, has no capabilities, and its own filter kills it for any other call or architecture. ioctl works only on the listener. |
| Kernel-started helpers | Limited to CAP_SYS_BOOT, and `/proc` is unwritable after fence, so none can be named. |
| Learn mode in production | Needs the DEV=1 marker on the verified root; `make dist` refuses DEV=1. |

## Reliability Considerations

- **Fails closed:** init exits if it cannot install the filter. The kernel
  panics, and the machine falls back to the last slot that worked.
- **No flood holds the console:** each call is logged once.
- **Checked each boot:** `make check`'s `sealed` wants enforcing, and
  seal-watch as uid 66 with no capabilities. posture's probes try AF_ALG,
  kernel TLS and a watch queue.
