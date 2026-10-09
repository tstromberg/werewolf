# seal-watch

## Summary

seal-watch is the machine seal's seccomp listener. It answers every system
call the seal refers to it, refusing it as a kernel without that call
would. It logs each call once on the console and counts refusals for
`seal` to show.

## Background

init installs the seal (cmd/seal, `lib/seal.zig`), a seccomp filter on PID 1
that every process inherits. Calls in the machine's promises pass. Calls
outside them go to a listener (SECCOMP_RET_USER_NOTIF) instead of killing
the caller, so a program that probes for a call keeps running, and an
operator sees what was asked. Each leashed service has its own filter that
returns ENOSYS, and the kernel prefers ENOSYS over the listener. So only
calls from werewolf's own programs, or a root shell, reach seal-watch.

## Goals

- Answer every referred call, so no caller hangs.
- Log each refused call once, with the promise that would allow it.
- Keep a count of this boot's refusals for `seal`.
- Hold nothing worth stealing.

## Non-Goals

- Deciding policy. The seal decides; seal-watch answers.
- Recording leashed services' refusals. Their filters answer first.

## Detailed design

- **Start:** init starts it before installing the seal, so it is not under
  the seal. init sends the listener over a socket on stdin, with one mode
  byte: `l` to learn, anything else to enforce.
- **Confinement**, when enforcing: it becomes `_seal` (uid 66), which no
  service shares, so no service can signal it. It has no capabilities and
  an empty bounding set. It runs under no_new_privs and a filter
  (`lib/sandbox.zig`) that allows seven calls and the listener's two
  ioctls, and kills it on anything else or another architecture.
- **Answers:** ENOSYS for most calls. For calls the seal refuses by
  argument (a socket family no promise names, `TCP_ULP`,
  `O_NOTIFICATION_PIPE`, a CPU-time timer) it returns the error a kernel
  without the feature gives.
- **Logging:** the first refusal of each call is logged:
  `seal-watch: {"event":"refused","call":"keyctl","promise":"never","pid":97}`.
  Refusals by argument also carry `why` and `arg`. It rewrites
  `/run/werewolf/seal/refused` (call, count, last pid, first time,
  promise) after each refusal. After 512 distinct calls, the rest are
  counted together as `other`, logged once.
- **Learning** (DEV=1 build booted with `werewolf.seal=learn`): it allows
  each call outside `never` and the argument refusals, and logs each new
  call, program and service once, for `make seal-learn`:
  `{"event":"learned","call":"memfd_create","promise":"memfd","service":"app","exe":"/usr/bin/node"}`.
  A learning machine installs no per-service filters, so every call
  arrives here. After 4096 entries it logs `learning-full` and allows the
  rest silently. It stays root, to read `/proc/PID/exe`.
- **Shutdown:** it ignores TERM, HUP, INT and PIPE, because refused calls
  keep coming until the machine is down. Stage 3's KILL ends it.

## Drawbacks

- One process answers every referred call in turn, so a flood of refused
  calls slows every caller.
- When enforcing, it logs only a pid: as `_seal` it cannot read other
  users' `/proc` entries.

## Alternatives Considered

### Kill the caller (SECCOMP_RET_KILL)
A machine-wide kill outranks each service's ENOSYS, and it kills runtimes
that probe, as libuv does for io_uring.

### ENOSYS in the filter, no listener
Nothing would be logged, and a needed call would fail unseen.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| It dies or is killed | The kernel refuses referred calls itself. No service shares its uid. |
| It is taken over | It reads only numbers from the kernel, has no capabilities, and may make seven calls. |
| A caller forges log fields | Program and service names are reduced to printable ASCII without `"` or `\`. |
| A flood holds the console | Each call is logged once; past 512, calls are counted together. |
| Learning in production | Only on a DEV=1 build, which `make dist` refuses. |

## Reliability Considerations

- **Fails closed:** without seal-watch, the kernel still refuses referred
  calls.
- **Checked each boot:** `make check`'s `sealed` wants it running as uid
  66 with no capabilities; `seal` reads its table.
