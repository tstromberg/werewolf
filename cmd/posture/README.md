# posture

## Summary

posture tests a Linux machine's protections and reports passes, failures
and skips, with reasons. It runs each boot on werewolf, or by hand on Linux.

## Background

werewolf's protections live in the kernel command line, sysctls, fence's
Landlock domain and rules, the seal, leash, the mounts, and what the image
leaves out. posture reports whether each is in force on the running machine.
It detects werewolf by `/usr/share/werewolf`; other distributions run generic
checks (`docs/posture.md`).

`posture [--extended] [--attack] [--no-cache] [--verbose] [--json | --line | --summary]`
prints text, JSON with why and how, `posture: fail=ID,ID pass=N skip=N {JSON}`, or the
login summary playground shows (`/etc/profile.d/posture.sh`): form, release and kernel;
state (`nominal`, `expected gaps`, `degraded`) and counts; a red `✗` row for each
unexcused failure; one line of declared gaps. It exits 1 if any check fails.
`--extended` adds what werewolf skips by choice (wiping freed memory, forced CPU
mitigations, strict reverse-path filtering; docs/security.md). Text shows `source =
value, want expectation` for a failure, at most two rows an item; `--json` keeps all of
`source`, `expected`, `observed` and `comparison`. `--verbose` streams phases, timings
and walk progress to stderr. A check citing a file this run may not read, one a root SSH
session cannot make (netlink, leashing, the attacks' lock), or one a run
without root skips takes boot's result from `/run/werewolf/posture.json`, named
`(cached)`; `--no-cache` leaves it skipped. Boot's holds stage0's TPM floor record.

## Goals

- Check every protection on the running machine, not its configuration.
- Test rather than read where that is safe: ask for a refusal.
- Never weaken the machine it measures, or let planted files falsify the report.

## Non-Goals

- Fixing failures, or serving as a compliance benchmark.

## Detailed design

- **Areas**, one file each: `kernel.zig` (lockdown, modules, sysctls, CPU,
  memory, features exploits reach for), `processes.zig` (hidden processes,
  root consoles, leashed services, intruder tools), `files.zig` (mounts, where programs
  run, shared directories, accounts), `network.zig` (ports, fence's rules,
  IPv6, sshd), `attacks.zig`. `posture.zig` holds the report and service.
- **One-way settings** (lockdown, `modules_disabled`, `ptrace_scope=3`,
  `unprivileged_bpf_disabled=1`): only if one reads locked is the unlocked
  value written back, which must be refused, so no check lowers anything. A
  switch the kernel lacks (modules, BPF, io_uring, SysRq, perf) passes, built without.
- **Proofs:** a copy of itself, under a random name, in each writable place and in a
  memfd, must not start. Opening sysctls across five subtrees, a sysfs file and the
  first disk with O_WRONLY or O_RDWR must be refused, as must setting the console
  loglevel through syslog. Running `/` must leave an audit record; stopping audit fail.
- **Walks** (setuid files, anything anyone may write) go from each directory's
  descriptor, not following links, on one filesystem.
- **Attacks**, only with `werewolf.check=1`, `--attack` or `WEREWOLF_CHECK=1`
  (containers): `/proc/1/mem` and `/dev/mem` must be refused and logged; as `nobody`,
  `/proc/1` must be hidden, `/run` closed, and link tricks in `/tmp` refused; a leashed
  `--probe` tests its grants. A lock isolates concurrent attacks on werewolf.
- **Service** (`/etc/sv/posture/run`): it waits up to 60 s for each other service to run
  5 s, writes `/run/werewolf/posture.json` and the login message `/run/werewolf/motd`
  (`/etc/werewolf/motd`, then dev mode, a root console, `werewolf.disable`). It drops
  capabilities, writes `d` to its own supervisor's control pipe and exits.
- **Expected failures:** a werewolf image lists them, excused, in
  `/usr/share/werewolf/weaknesses`; any other prints `posture: WARNING: unexpected:
  ID,...`, and excuses no longer needed are named.

## Drawbacks

- Run as another user, some checks read less, and some skip.
- Each run opens one TCP connection to `169.254.169.254`, and leaves refused execs and
  Landlock refusals in the kernel log and on the console.
- About a hundred checks must be kept true as kernels change.

## Alternatives Considered

### Lynis, OpenSCAP and other scanners
They judge general server configuration; posture tests what the kernel refuses.

### Checks in test scripts only
The machine itself would not know its posture; the service reports it on every boot.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A check that weakens the machine | Only one-way settings are written, and only when they read locked. |
| A file name that attacks the admin's terminal | Control characters, C1 and invalid UTF-8 shown as `?` in text; JSON escaped. |
| A planted file making a check pass | Random names for its copies; attack files made with `O_EXCL`. |
| A directory swapped for a link mid-walk | Walks by descriptor, without following links, on one filesystem. |
| Attacks harming a real machine | Off unless asked; each expects refusal; run as `nobody` where possible. |
| Its own privilege | One-shot root inspection under fence and the seal; [audit](../../docs/design/posture-inspection.md). |

## Reliability Considerations

- **Bounded:** walks stop at depth 40; settling waits 60 s. Evidence reads accept
  regular files only, up to 16 MiB; kernel-log reads also stop after 65,536 attempts.
- **Degrades:** a check it cannot make takes boot's result, or skips with the reason.
- **Tested:** unit tests and every `make check` boot against `test/posture-known`.
