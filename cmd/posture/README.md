# posture

## Summary

Measures how a Linux machine protects itself, about a hundred checks, each
passed, failed or skipped, with why it matters and how it was checked. It
runs on werewolf once a boot, as a service, and on any Linux by hand.

## Background

werewolf's protections live in many places: the kernel command line,
sysctls, fence's Landlock and rules, the seal, leash, the mounts, what the
image leaves out. posture says in one report whether each is in force on
the running machine. It assumes nothing of werewolf, so the same report on
another distribution is a comparison. `docs/posture.md` lists the checks.

## Goals

- Every protection checked on the machine as it runs, not as configured.
- Tested rather than read where that is safe: a refusal asked for, not
  inferred.
- Never weaken the machine it measures.
- A report no one on the machine can falsify by planting files.

## Non-Goals

- Fixing what fails: it measures, and the form or the kernel fixes.
- A compliance benchmark. The checks are werewolf's threat model.

## Detailed design

- **Areas**, a file each: `kernel.zig` (lockdown, modules, sysctls, CPU
  mitigations, memory, features exploits reach for), `processes.zig`
  (hidden processes, leashed services, the tools an intruder would want),
  `files.zig` (mounts, what runs from where, shared places, accounts),
  `network.zig` (ports, fence's rules, IPv6, ssh), `attacks.zig`.
  `posture.zig` holds the report, the output and the service.
- **One-way settings** (lockdown, `modules_disabled`, `ptrace_scope=3`,
  `unprivileged_bpf_disabled=1`): read, then, only if they read locked,
  written back to unlocked, which must be refused. A check that fails never
  lowers anything.
- **Proofs**: a copy of itself, under a random name, in each writable place
  and in a memfd, must not start; opening a sysctl, a sysfs file and the
  first disk for writing must be refused; running `/` as a program, refused
  everywhere, must leave the kernel's audit record in the kernel log, and
  asking the kernel to stop auditing must be refused.
- **Walks** (setuid files on the root, anything anyone may write) go from
  each directory's descriptor, links not followed, within one filesystem.
- **Attacks**, only with `werewolf.check=1`, `--attack` or
  `WEREWOLF_CHECK=1`: `/proc/1/mem` and `/dev/mem` refused and logged; as
  `nobody`, in a child making only system calls, `/proc/1` hidden, `/run`
  closed, link and file tricks in `/tmp` refused; and a copy of posture,
  leashed as `nobody`, tries what its service file does not grant.
- **Output**: text for people, with every control character shown as `?`;
  `--json`; `--line`, one line for the console. As werewolf's service it
  waits for the others to settle (60 s at most), keeps the JSON in
  `/run/werewolf/posture.json`, prints the line, and stops itself. It runs
  beside the services, after them; nothing waits for it.
- **Expected failures**: a werewolf image lists the failures it expects,
  each with its excuse, in `/usr/share/werewolf/weaknesses` (its form's
  `weaknesses`, and test/posture-known's line for its kind). A failed
  check there carries its excuse in the JSON; any other is unexpected, and
  the service says so on the console, `posture: WARNING: unexpected: ID,...`,
  as it says which excuses are no longer needed. Without the file, on
  another Linux, a failure is a failure.

## Drawbacks

- Root sees the whole picture; another user gets some checks skipped.
- Network probes are quiet, but the metadata probe opens one TCP connection
  to `169.254.169.254`, and the exec proofs leave eight refused execs, two
  audit lines each, in the kernel log and on the console every run.
- About a hundred checks is a lot to keep true as kernels change; `test/posture-known`
  lists the expected failures per form and architecture.

## Alternatives Considered

### Lynis, OpenSCAP and other scanners
They read configuration files and package lists, need a shell and
interpreters, and judge a general-purpose server. posture is one static
binary, and tests what the kernel actually refuses.

### Checks in test scripts only
The machine itself would not know its posture. The boot service puts it on
the console and in `/run` for the status page, on every machine.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A check that weakens the machine | Only one-way settings are written, and only when they read locked. |
| A file name that attacks the admin's terminal | Control characters and C1 shown as `?` in text; JSON escaped. |
| A planted file making a check pass | Random names for its copies; attack files made with `O_EXCL`. |
| A directory swapped for a link mid-walk | Walks by descriptor, `O_NOFOLLOW`, one filesystem. |
| Attacks harming a real machine | Off unless asked; each expects refusal; run as `nobody` where they can be. |
| Its own privilege | Root, in fence's domain and under the seal; it runs only itself, `leash` and `sv`. |

## Reliability Considerations

- **Bounded**: walks stop at depth 40; the service checks after at most 60 s
  whatever the others are doing.
- **Degrades**: a check it cannot make is skipped with the reason, never
  passed.
- **Tested**: unit tests per area (29, the walk on Linux); every `make check`
  boot judges the posture line against `test/posture-known`.
