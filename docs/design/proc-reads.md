# Declared proc reads

Proposed, 2026-10-13. No implementation. Prototype AppArmor before committing to it.

## Summary

Declare procfs reads, including root's. AppArmor handles PID paths; Landlock and the
seal still hold.

## Background

Fence refuses writes to procfs but grants reads; leash's floors include `/proc`.
`hidepid=invisible` hides processes, with a default GID-0 exemption; file checks still
apply. [Landlock](https://docs.kernel.org/6.18/userspace-api/landlock.html) grants
existing objects and directory trees: it cannot express `/proc/<any future
PID>/cmdline`. Opening `/proc/self` at launch selects that process, not its future
children.

## Goals

- An undeclared `cmdline` read fails, including from a root shell and a future child.
- A form grants an exception to its named service or program without widening others.
- No process monitor, PID scan, read broker, policy daemon or custom kernel code.

## Non-Goals

Kernel exploits, hiding all process evidence, or stopping readers sharing output. No
write exceptions.

## Detailed design

**One declaration.** Add `proc-read` to service and `narrow` declarations:

```yaml
proc-read:
  - meminfo
  - pid/cmdline
```

Accept literal global files and `pid/LEAF`, with reviewed entries only. `meminfo`
grants `/proc/meminfo`; `pid/cmdline` grants current and future process/thread cmdlines
visible to the caller. Other leaves stay denied; existing kernel checks still apply.
UID ownership is not "self". Reject unknown entries, traversal, arbitrary globs,
directory grants, `all`, and implicit exceptions through ordinary `read` declarations.

**Exceptions belong to their reader.** Defaults are empty; the owning form or program
declares needs. A form's exception names an existing reader and explains its need.
Combining forms preserves grants by reader; conflicting definitions fail rather than
merge. A narrowed program's grant must be within its service's. Form settings,
environment, command line and writable configuration cannot change grants. New entries
stay denied.

**Compile once.** Generate small AppArmor allowlist profiles from these declarations
and the image's mount manifest; compile with the upstream parser during the build.
Each profile allows ordinary non-proc filesystem operations already constrained by
Landlock, and only declared proc reads. Generate non-proc rules from the mount layout;
no recursive read grant may cover a proc mount, including beneath `/oci`. Blanket
proc denies override exceptions. Pin the feature ABI; put policy on the verified root.

**Load, lock, launch.** Enable AppArmor alongside the existing LSMs in our kernel.
Init loads policy before dropping `CAP_MAC_ADMIN`, verifies enforcement, then locks
policy changes. No parser or reload service runs afterward.
Trusted supervision needs a ceiling profile with the union of launch requirements;
its execute rules name only trusted supervisors and launch entrypoints. Those
entrypoints stack the selected reader profile before accepting untrusted input or
executing application code. Leash selects from its verified file; root shells and
helpers, including those outside fence, get explicit roles. Supervision is trusted.

**Stack, never replace.** Children inherit the reader profile. Ordinary exec retains
it; narrowing stacks another profile and cannot restore an earlier one. No transition
to an unconfined profile, reversible hat, or broader reader is allowed. An approved
diagnostic needing more than a root shell runs as its own supervised role; invoking
its executable from that shell does not acquire its grant. Test inherited
`no_new_privs`: Linux checks profile labels, not permission-list subsets. Proc grants
authorize a process tree; distinct privileges need roles or `narrow` wrappers.
Permit only the necessary stack targets. argv and cmdline are never identity.

## Drawbacks

Another LSM, a build dependency and launch integration are substantial costs;
supervision retains broader reads. Path aliases and descriptors complicate review.

## Alternatives Considered

- **Landlock alone:** good for fixed files, insufficient for future PID leaf rules.
- **Grant `/proc` to exceptional services:** simplest fallback, but grants every leaf.
- **seccomp path checks or PID scans:** pointer races or incomplete coverage over time.
- **Read broker, BPF or a new LSM:** application changes or more enforcement code to
  own.

## Security Considerations

Close unintended inherited descriptors; preserve stdio deliberately. Proc magic links
must obey their target authority: a write to an allowed log is not a procfs write.
Keep memory/namespace checks. Prove alternate roots, chroot, bind paths, fd reopening,
`openat2`, mmap, fd-based exec and caller-controlled environments cannot widen reads.

## Reliability Considerations

Gate rollout on root/unprivileged denial probes, an allowed reader, unrelated-form
isolation, future forks/threads, narrowed exec, OCI paths and retained write denials.
Test the actual launch order with `no_new_privs`, restart and A/B recovery on both
architectures. Missing policy or enforcement stops launch; no automatic broadening. If
alias or launch coverage requires an intricate workaround, reject this approach.
References: [AppArmor policy](https://www.apparmor.net/man/4.0/apparmor.d/), [transition
checks](https://github.com/torvalds/linux/blob/v6.18/security/apparmor/domain.c).
