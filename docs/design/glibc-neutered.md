# glibc with fewer implicit inputs

## Summary

Build a Wolfi-derived glibc with five fixed protections: deny environment
configuration, disable loader injection and search overrides, allow only built-in
NSS and converters, and disable nscd. Keep the optimized implementations and the
public environment API; adapt applications before weakening a protection. Native-code
integrity in production also needs Werewolf's kernel enforcement ([IPE](ipe.md)).

## Background

The [vulnerability
audit](https://github.com/werewolf-linux/glibc-build/blob/main/docs/glibc-vuln-audit.md)
records ten years of glibc flaws reached through startup parsing (Looney Tunables),
converter settings restored after startup (PwnKit) and NSS without loader variables
(sudo); sanitizing the environment at launch covers only some of these paths. Adopted
2026-10-15 by forms/minimal; each package names its Wolfi build (`wolfi-origin:`).

## Goals

Exactly five mechanisms, as the smallest reviewable diff against Wolfi's source. A
disabled input causes no tuning, injection, module load or file write, ever; untrusted
libraries cannot run through retained dependencies or explicit loading. Public
`getenv`, `secure_getenv`, environment mutation, symbol versions and the optimized CPU
and allocator defaults stay. Upstream tests pass with each policy change explained;
form checks and comparative performance gates precede rollout.

## Non-Goals

Rewriting allocation, DNS, formatting, sorting, vector routines or `dlopen`; runtime
switches, permissive builds or exceptions; claiming to repair memory corruption.

## Detailed design

1. **Deny implicit environment configuration.** In the private build headers, redirect
   the internal environment getters to a typed helper returning `NULL` (if that proves
   smaller and reliable than editing each caller), exempting the public getters and
   `AT_SECURE` sanitation and covering `__libc_secure_getenv` and its aliases; an
   interposition wrapper is not enough. Review each caller: HOME expansion and other
   environment-dependent APIs change, and every fallback fails closed (bare-name
   `execvp` fails rather than search a broader PATH, temporary names need an explicit
   directory, binding is eager, executable stacks are refused). Skip environment
   interpretation in `elf/rtld.c`, `elf/dl-tunables.c` and static `elf/dl-support.c`,
   keeping compiled tunable defaults and hardware detection; locale, timezone,
   resolver, temp-directory, profiling and tracing overrides are ignored, and
   `setlocale(cat, "")` selects `C`.
2. **Disable loader injection and search overrides.** Ignore every `LD_*` loader
   variable and `/etc/ld.so.preload` without parsing them; reject the loader's
   `--preload`, `--audit`, `--library-path`, `--inhibit-rpath`, `--inhibit-cache` and
   hwcaps overrides and ELF `DT_AUDIT`/`DT_DEPAUDIT` before activation. Gate the
   activation points; keep normal dependencies and `dlopen`.
3. **Built-in NSS only.** In `nss/nss_module.c`, keep the `files` and `dns` branches
   and fail an external request before a name is built or a DSO loaded, through the
   existing state and locking, with the established unavailable status rather than
   different identity data. Another source is the application's to adapt.
4. **Built-in converters only.** Skip external gconv discovery in `iconv/gconv_conf.c`,
   deny DSO loading in `iconv/gconv_dl.c` as a backstop, ship no converter files.
   Built-ins are UTF-8, ASCII and the internal UCS forms, not UTF-16.
5. **Disable nscd.** `--disable-build-nscd` and `--disable-nscd`; measure files/DNS
   lookup cost before deciding on caching elsewhere.

[werewolf-linux/glibc-build](https://github.com/werewolf-linux/glibc-build)
holds the patches and releases: Wolfi's complete recipe and files, pinned by hash,
with Wolfi's hardening and backports kept; a scheduled Action proposes updates, applies
the patches without fuzz, builds matching loader and libc packages for both
architectures, and publishes only validated, signed and indexed artifacts; patch drift
blocks the update and keeps the last validated package. PostgreSQL setup, its bootstrap
children and locale enumeration now use static sh-shim in place of the popen preload
([postgresql-sh-shim.md](postgresql-sh-shim.md)), with no glibc loading exception.

Retained loading is bounded by [IPE](ipe.md): every native mapping, dependencies,
`dlopen`/`dlmopen` and static loading included, comes from the verified root. That is
an existing requirement, not a sixth patch: audit RPATH/RUNPATH, `$ORIGIN`, cache
entries and symlinks in the image, and authorize no writable directory or alternate
loader. Non-IPE images miss the claim; JIT forms need design work, not an exception.

## Drawbacks

Environment-dependent APIs change behaviour though public `getenv` works; the C locale
is not C.UTF-8; external NSS, legacy encodings, profiling injection and nscd consumers
need application work; private-header macros can reach tools and tests (build guards,
or consumer edits where easier). No patch-size or performance claim is measured yet.

## Alternatives Considered

Launcher sanitation: a later `setenv` or memory corruption restores settings, and CLI,
ELF, NSS and converter inputs bypass it. Overriding public `getenv`, or forcing secure
mode: breaks application configuration and privilege semantics. Variable allowlists or
removing subsystems: policy code and patch churn; one denial helper plus a few gates
is validated first. Opt-outs: widen every process; the application is fixed instead.
Replacing glibc: other libcs fail the same ways, and a new ABI adds migration work.

## Security Considerations

`ld-linux --library-path /writable/lib /usr/bin/app` is the CLI equivalent of
`LD_LIBRARY_PATH`: with a compatible dependency there and control of the loader's
arguments, the substituted library's constructors run first. A loader feature, not an
escalation (a setuid target gains nothing), it matters only where the attacker controls
the invocation; reject it, and adapt the test harness without an exception. IPE
rejects the mapping independently, so CLI denial is defense in depth. Reject before
parsing, allocating or loading; denial must survive OOM, duplicate or mutated
environment entries, reloads, alternate roots and static loading. Upstream fixes for
retained APIs remain separate risks; IPE constrains provenance, not memory corruption.

## Reliability Considerations

Test public getters and mutation, ordinary and secure execution, static and shared
linking, direct loader execution, malformed inputs and post-startup changes; assert the
C locale under every LANG/LC variant; exercise every injection route, NSS reload and
unavailable results, converter aliases and short buffers, and the absent nscd socket.
Explain each policy-related upstream failure; never suppress a suite. Release probes
attempt constructors from attacker DSOs through every disabled source, the loader CLI,
alternate roots, reloads, dependencies, `dlopen`/`dlmopen`, static loading, bad RPATH
elements and symlinks into writable storage under IPE, failing before any constructor
runs, with IPE's exec, mmap, mprotect and tampered-policy checks on both architectures.
Before release, compare the same Wolfi revision with and without the patches (startup,
allocator, vector operations, DNS and identity latency, service and database traffic):
no correctness failure, no repeatable regression over 5%, variance and caching
investigated before the policy is weakened; keep the prior packages for rollback.
