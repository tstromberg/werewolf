# posture

## Summary

posture measures how a Linux machine protects itself: about a hundred
checks, each passed, failed or skipped, with why it matters and how it was
checked. On werewolf it runs once a boot as a service; on any Linux, by hand.

## Background

werewolf's protections live in many places: the kernel command line,
sysctls, fence's Landlock domain and rules, the seal, leash, the mounts, and
what the image leaves out. posture reports whether each is in force on the
running machine. It assumes nothing of werewolf, so a report from another
distribution is a comparison; werewolf-only checks skip where their subject
is absent. `docs/posture.md` lists the checks.

`posture [--extended] [--attack] [--json | --line]` prints text, or JSON
with why and how, or `posture: fail=ID,ID pass=N skip=N {JSON of failures}`,
and exits 1 if any check fails. `--extended` adds what werewolf skips by
choice (wiping freed memory, forced CPU mitigations, strict reverse-path
filtering, ignoring IPv6 router advertisements; docs/security.md).

## Goals

- Check every protection on the running machine, not its configuration.
- Test rather than read where that is safe: ask for a refusal.
- Never weaken the machine it measures.
- Produce a report no one on the machine can falsify by planting files.

## Non-Goals

- Fixing failures, or serving as a compliance benchmark.

## Detailed design

- **Areas**, one file each: `kernel.zig` (lockdown, modules, sysctls, CPU,
  memory, features exploits reach for), `processes.zig` (hidden processes,
  leashed services, intruder tools), `files.zig` (mounts, where programs
  run, shared directories, accounts), `network.zig` (ports, fence's rules,
  IPv6, sshd), `attacks.zig`. `posture.zig` holds the report and service.
- **One-way settings** (lockdown, `modules_disabled`, `ptrace_scope=3`,
  `unprivileged_bpf_disabled=1`): only if one reads locked is the unlocked
  value written back, which must be refused, so no check lowers anything.
- **Proofs:** a copy of itself, under a random name, in each writable
  place and in a memfd, must not start. Opening a sysctl, a sysfs file and
  the first disk for writing must be refused. Running `/` as a program
  must leave an audit record, and stopping audit must be refused.
- **Walks** (setuid files, anything anyone may write) go from each
  directory's descriptor, not following links, on one filesystem.
- **Attacks**, only with `werewolf.check=1`, `--attack` or `WEREWOLF_CHECK=1`
  (containers): `/proc/1/mem` and `/dev/mem` must be refused and logged
  (`/dev/mem` silently without `CAP_SYS_RAWIO`); as `nobody`, `/proc/1`
  must be hidden, `/run` closed, and link tricks in `/tmp` refused; and
  posture leashed as `nobody` (`--probe`) tries what it was not granted.
- **Service** (`/etc/sv/posture/run`): it waits up to 60 s for each other
  service to run 5 s or be down on request, writes `/run/werewolf/posture.json`,
  prints the line, and parks itself with `sv down`. Nothing waits for it.
- **Expected failures:** a werewolf image lists the failures it expects,
  with excuses, in `/usr/share/werewolf/weaknesses` (the form's
  `weaknesses`, plus test/posture-known's line; `?ID` when the host
  decides). A listed failure carries its excuse in the JSON. Any other is
  unexpected, and the service prints `posture: WARNING: unexpected: ID,...`
  and names excuses no longer needed. Elsewhere, a failure is a failure.

## Drawbacks

- Run as another user, some checks read less, and some skip.
- Each run opens one TCP connection to `169.254.169.254`, and leaves
  refused execs and Landlock refusals in the kernel log and on the console.
- About a hundred checks must be kept true as kernels change.

## Alternatives Considered

### Lynis, OpenSCAP and other scanners
They read configuration, need a shell and interpreters, and judge a
general-purpose server. posture is one static binary that tests what the
kernel refuses.

### Checks in test scripts only
The machine itself would not know its posture; the service reports it on
every machine.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A check that weakens the machine | Only one-way settings are written, and only when they read locked. |
| A file name that attacks the admin's terminal | Control characters, C1 and invalid UTF-8 shown as `?` in text; JSON escaped. |
| A planted file making a check pass | Random names for its copies; attack files made with `O_EXCL`. |
| A directory swapped for a link mid-walk | Walks by descriptor, without following links, on one filesystem. |
| Attacks harming a real machine | Off unless asked; each expects refusal; run as `nobody` where possible. |
| Its own privilege | Root, in fence's domain and under the seal; it runs only itself, `leash` and `sv`. |

## Reliability Considerations

- **Bounded:** walks stop at depth 40; the service waits 60 s at most.
- **Degrades:** a check it cannot make is skipped with the reason.
- **Tested:** unit tests in each area but attacks (the walk on Linux
  only); every `make check` boot judges the line against `test/posture-known`.
