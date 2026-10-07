# seal-watch

## Summary

The machine seal's listener: it answers every system call the seal refers
to it, refusing it as a kernel without that call would, says each one once
on the console, and counts them for `seal` to show.

## Background

init installs the seal (cmd/seal, `lib/seal.zig`), a seccomp filter on PID 1
that every process inherits. Calls of the machine's promises pass; calls
outside them are referred to a listener (SECCOMP_RET_USER_NOTIF) rather
than killed, so a program that probes a call carries on, and an operator
hears what was asked. Leashed services refuse their own calls first, with
their own filters, so what arrives here is what werewolf's own programs,
or a root shell, made outside the promises.

## Goals

- Every referred call answered, so no caller waits.
- Each refusal said once, with the promise that would allow it.
- A count of this boot's refusals, for `seal`.
- Nothing it holds worth taking.

## Non-Goals

- Deciding policy: the seal decides; it answers.
- Recording leashed services' refusals: their filters answer first.

## Detailed design

- **Started by init** before the seal, so not under it. init passes the
  listener over a socket on stdin, with one byte: `l` to learn, anything
  else to enforce.
- **Confines itself**, enforcing: becomes `_seal` (uid 66), which no
  service shares and so none may signal; no capabilities, bounding set
  empty; under no_new_privs, a filter of seven calls and the listener's
  two ioctls, killing anything else or another architecture.
- **Answers** each notification: ENOSYS, or for a refusal by argument
  (a socket family no promise names, `TCP_ULP`, `O_NOTIFICATION_PIPE`, a
  CPU-time timer) the error a kernel without the feature gives.
- **Says** the first of each call:
  `seal-watch: {"event":"refused","call":"keyctl","promise":"never","pid":97}`,
  and keeps `/run/werewolf/seal/refused` (call, count, last pid, first
  time, promise). Past 512 calls, the rest are counted together as `other`.
- **Learning** (DEV=1, `werewolf.seal=learn`): allows each call and says it
  once with its program and service, for `make seal-learn`. It stays root
  to read `/proc/PID/exe`.
- **Ignores** stage 3's TERM: refusals come until the machine is down.

## Drawbacks

- One process answers every referred call in turn; a flood of refused calls
  slows each caller.
- Enforcing, it names only a pid: as `_seal` it cannot read other users'
  `/proc` entries.

## Alternatives Considered

### Kill the caller (SECCOMP_RET_KILL)
A machine-wide kill outranks each service's ENOSYS and kills runtimes that
probe, as libuv does for io_uring.

### ENOSYS in the filter, no listener
Nothing would be said, and a needed call would fail unseen.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| It dies or is killed | The kernel refuses referred calls itself; no service shares its uid. |
| It is taken over | It reads only numbers from the kernel; no capabilities; seven calls. |
| A flood holds the console | Each call said once; past 512, counted together. |
| Learning in production | Only on a DEV=1 build, which `make dist` refuses. |

## Reliability Considerations

- **Fails closed**: without it, referred calls are still refused.
- **Checked each boot**: `make check`'s `sealed` wants it as uid 66 with
  no capabilities; `seal` reads its table.
