# Protections against the xzutils attack

## Summary

Remove glibc's audit callback machinery and require review of early-executing
native dependencies. Keep compression code outside authentication processes.
Implement loader changes in `../hardened-packages`, with native regression tests.

## Background

The [xz backdoor][xz] entered liblzma through release build scripts. Some sshd
packages loaded it through libsystemd. An indirect function (IFUNC) resolver,
normally used to select CPU-specific code, ran during relocation. It forged
loader audit state and intercepted a cryptographic function before relocation
tables became read-only. No environment-controlled injection was necessary.

Our glibc rejects audit registration, preload and loader search overrides.
Registration denial leaves callback dispatch reachable through forged state.

## Goals

- No production loader audit callback runs, even with forged registration state.
- Existing libc CPU dispatch and ordinary library loading continue to work.
- Package checks identify new IFUNCs and unexpected SSH native dependencies.
- Native probes fail independently of the upstream suite's failure allowance.

## Non-Goals

- Isolating malicious libraries inside one native address space.
- Removing libc's optimized functions or adding an audit compatibility allowance.

## Detailed design

**First: audit dispatch.** Extend glibc's fixed loader policy. Remove callback
dispatch bodies, retaining neutral internal entry points where callers need them.
Do not consult a mutable enable bit or trust a zero callback count. Preserve
ordinary symbol binding and reject explicit audit requests as before. Check all
audit entry points, including symbol lookup, object lifecycle and PLT callbacks.
Any remaining audit bookkeeping must not invoke pointers supplied by audit state.

Add a native test using glibc's own internal types. Supply forged callback state
and exercise the dispatch entry points; no callback may run or change a binding.
Run a positive control against unmodified dispatch to prove the fixture works.
Exercise normal IFUNC dispatch, startup and later library loading separately.
Keep the full upstream suite and its existing failure ceiling.

**Next: IFUNC admission.** Inventory ELF dynamic symbols and architecture-specific
IRELATIVE relocations in the built image. Approve a small core baseline and
explicit additional objects. New resolver use fails image review; a library's
SONAME or self-declared metadata cannot authorize itself. Approval comes from
reviewed policy, bound to the image's verified files. Packages cannot silently
expand it during refresh.

Runtime enforcement is later work. Check the defining object before invoking a
resolver, including startup, dlopen, dlmopen, dlsym and dlvsym on both architectures.
Policy must be available before non-core relocation code runs. Constructors are
too late. Reject forbidden resolvers; never guess an implementation to substitute.
Static executables need separate build checks because they can bypass ld.so.

**Dependencies and permissions.** Check the SSH dependency closure at image build:
no liblzma or unnecessary libsystemd. Inspect binaries without executing them.
For services needing compression, prefer a separate worker with bounded resources,
explicit inputs and outputs, no secrets, network or child execution. The current
`narrow` floor is broader than a descriptor-only worker and needs separate review.

**Delivery.** Bump the glibc policy revision for changed package bytes. Validate
patch application at the locked source, then native probes, upstream results and
ABI on x86_64 and aarch64. Publish only validated packages. Update Werewolf's source
pins after the reviewed package commit is published, as CONTRIBUTING.md requires.

## Drawbacks

Removing audit dispatch adds downstream maintenance and prevents loader profilers
from working. IFUNC admission needs an inventory and explicit exceptions. Loader
startup has few safe APIs; runtime policy parsing would enlarge trusted code.

## Alternatives Considered

- Disable LD_AUDIT alone: the backdoor fabricated registration in memory.
- Add an audit allowance: retains unused callbacks in every production loader.
- Disable every IFUNC: breaks CPU dispatch without isolating ordinary native code.
- Move RELRO earlier: initialization still needs writes; ordering changes are
  larger and do not establish a boundary against malicious code in the process.
- Trust reproducible builds: compromised inputs can reproduce a compromised output.

## Security Considerations

Native code inherits its process's authority. Constructors and ordinary functions
remain execution routes; a loader check is admission policy, not a library sandbox.
RELRO and W^X do not make arbitrary data immutable against an already compromised
process. Preserve kernel confinement before exec, including loader initialization.

## Reliability Considerations

Land audit removal separately from IFUNC restrictions. Failed validation retains
the previous release. Check denials and useful behavior on both architectures;
patch application and host unit tests alone do not establish runtime protection.

[xz]: https://www.openwall.com/lists/oss-security/2024/03/29/4
