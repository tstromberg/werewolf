# posture

## Summary

posture tests a Linux machine's protections and reports passes, failures
and skips, with reasons. It runs each boot on werewolf, or by hand on Linux.

## Background

werewolf's protections live in many places: the kernel command line,
sysctls, fence's Landlock domain and rules, the seal, leash, the mounts, and
what the image leaves out. posture reports whether each is in force on the
running machine. It detects werewolf by the `/usr/share/werewolf`
directory. Other distributions run generic checks; image
policy, TPM release authorization, updater, generated service and leash
checks are omitted. `docs/posture.md` lists the checks.

`posture [--extended] [--attack] [--verbose] [--json | --line | --summary]` prints text, or JSON
with why and how, or `posture: fail=ID,ID pass=N skip=N {JSON of failures}`,
and exits 1 if any check fails. `--extended` adds what werewolf skips by
choice (wiping freed memory, forced CPU mitigations, strict reverse-path
filtering, ignoring IPv6 router advertisements; docs/security.md).

`--summary` prints a state and counts on one line, followed by only failures.
The scan is live, so the summary omits its timestamp.
NOMINAL means no failed checks; EXPECTED GAPS means
every failure has an image excuse; DEGRADED means an unexcused failure;
Skipped checks and limited privileges describe coverage separately.
A terminal uses green passes and red X marks for all failures; the
EXPECTED GAPS state is amber. `NO_COLOR` or `TERM=dumb` disables color. Failures still exit 1,
including expected ones. Playground's interactive terminal logins run a
fresh summary through `/etc/profile.d/posture.sh`, covering ash and bash.

Text uses two columns: a short label and `source = value, want expectation`
for failures; passes omit `want`. Each item takes at most two rows, with
long values shortened. `--json` retains the complete `source`, `expected`,
`observed` and `comparison`, including syscall arguments and numeric errno.
Unavailable reads do not claim a particular cause. Expected weaknesses
do not replace measured evidence.

`--verbose` streams phase starts, each check's result and elapsed
milliseconds, expensive operation starts, walk progress, phase totals and
the total scan time to stderr. Per-check times measure work since the
preceding result in the same phase, including shared setup; they are not
independent microbenchmarks. The output combines with every report format.

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
  place and in a memfd, must not start. Opening sysctls across five subtrees,
  a sysfs file and the first disk with O_WRONLY or O_RDWR must be refused.
  Setting the current console loglevel through syslog must be refused.
  Running `/` must leave an audit record; stopping audit must be refused.
  The audit proof follows new `/dev/kmsg` records with `poll`, allowing
  100 ms for kauditd, and matches the probe child's pid and exec syscall.
  Missing or rate-limited evidence fails, rather than passing silently.
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
