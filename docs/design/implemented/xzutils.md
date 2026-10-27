# Protections against the xzutils attack

**Status:** Implemented
[2026-10-20](https://github.com/werewolf-linux/packages/commit/f483ea0)

## Summary

Remove glibc audit callbacks, constrain native loading and keep compression outside
authentication processes. Implement and test loader policy in `../packages`.

## Background

The [xz backdoor][xz] reached liblzma through release scripts and some sshd packages
through libsystemd. An indirect function (IFUNC) resolver, used for CPU dispatch,
forged audit state during relocation and intercepted a cryptographic function
before relocation tables became read-only. No environment injection was necessary.

Our glibc rejects audit registration, preload and loader search overrides.
Registration denial leaves callback dispatch reachable through forged state.

## Goals

- No production loader audit callback runs, even with forged registration state.
- Services grant optional loading and additional IFUNCs; core CPU dispatch remains.
- Package checks identify new IFUNCs and unexpected SSH native dependencies.
- Native probes fail independently of the upstream suite's failure allowance.

## Non-Goals

- Isolating malicious libraries inside one native address space.
- Removing libc's optimized functions or adding an audit compatibility allowance.
- Timed grants, clock selection, restart budgets or automatic permission learning.

## Detailed design

**First: audit dispatch.** Extend glibc's fixed loader policy. Remove callback
dispatch bodies, retaining neutral internal entry points and ordinary binding.
Do not trust a mutable enable bit or zero callback count. Reject explicit audit
requests; no symbol lookup, object lifecycle, PLT or bookkeeping path may call
pointers supplied by audit state.

Test every entry point with forged state using glibc's internal types; no callback
may run or change a binding. Use unmodified dispatch as a positive control. Keep
IFUNC and loading probes, the full upstream suite and its existing failure ceiling.

**Next: service allowances.** Add `glibc:dlopen` and `glibc:ifunc` to
`services.NAME.allow`, using existing root-held regular-file grants under
`/etc/runtime-hardening/allow/<ns>/glibc/`. The supervisor assigns the service's
cgroup namespace. Grants authorize the service and its descendants across restarts;
fork and exec neither add nor remove them. Missing grants deny the capability;
malformed policy fails closed. No durations, symlink grants or deadline state.

`glibc:dlopen` permits runtime loading through dlopen, dlmopen and libc's internal
loading paths. Initial linked dependencies remain supported. Allowed operations
retain upstream semantics. Keep shell execution under the existing exec allowlist.

`glibc:ifunc` permits resolvers beyond a small reviewed core baseline, bound to
verified object identity rather than SONAME or self-declared metadata. Inventory
IFUNC symbols and IRELATIVE relocations. Enforcement must precede resolver execution
at startup, loading and dlsym/dlvsym on both architectures; constructors are too
late. Reject forbidden resolvers; never substitute an implementation. Static
executable IFUNC admission remains separate work; runtime-loaded DSOs in static
programs are gated.

Remove foreign stdio vtable compatibility exceptions without an allowance. Preserve
upstream supported stream behavior; do not rewrite logging or general stdio dispatch.

**Dependencies and permissions.** Check SSH's native dependency closure at build:
no liblzma or unnecessary libsystemd; inspect binaries without executing them.
Compression workers need bounded resources, explicit I/O, no secrets, network or
child execution. Review `narrow` before claiming descriptor-only isolation.

**Delivery.** Bump the glibc policy revision for changed package bytes. Validate
patch application at the locked source, then native probes, upstream results and
ABI on x86_64 and aarch64. Publish only validated packages. Advance Werewolf's pins
after publishing the reviewed package commit, as CONTRIBUTING.md requires.

## Drawbacks

Audit removal adds maintenance and prevents loader profilers from working. Loading
and IFUNC gates require service declarations. Early policy reads enlarge loader code.

## Alternatives Considered

- Disable LD_AUDIT alone: the backdoor fabricated registration in memory.
- Add an audit allowance: retains unused callbacks in every production loader.
- Disable every IFUNC: breaks CPU dispatch without isolating ordinary native code.
- Timed grants: defer until a concrete threat justifies clock and restart semantics.
- Earlier RELRO or reproducibility does not establish trust in loaded native code.

## Security Considerations

Native code inherits its process's authority. Constructors and ordinary functions
remain execution routes; a loader check is admission policy, not a library sandbox.
RELRO and W^X do not stop data corruption by native code already in the process.
Preserve kernel confinement before exec, including loader initialization.

## Reliability Considerations

Land audit removal separately. Failed validation retains the previous release.
Check denials and useful behavior on both architectures; patch application and
host tests alone do not establish runtime protection.

[xz]: https://www.openwall.com/lists/oss-security/2024/03/29/4
