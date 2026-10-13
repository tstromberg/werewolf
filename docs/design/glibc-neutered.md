# glibc with fewer implicit inputs

## Summary

Build a Wolfi-derived glibc with five fixed protections: deny environment configuration, disable loader injection/search overrides, allow only built-in NSS and converters, and disable nscd. Preserve optimized implementations and public application environment access; adapt applications before weakening these protections. Production native-code integrity also requires Werewolf's existing kernel enforcement.

## Background

The [vulnerability audit](../../../glibc-neutered/docs/glibc-vuln-audit.md) records ten years of glibc flaws and analogous libc failures. Looney Tunables attacked startup parsing; PwnKit restored converter settings after startup; sudo exploits used NSS without loader variables. Removing environment variables at launch covers only some of these paths.

Follow [CONTRIBUTING.md](../../CONTRIBUTING.md): small changes, deny by default, fail closed. This is a proposal; patches and application compatibility have not been validated.

## Goals

- Implement exactly five protection mechanisms with the smallest reviewable diff against Wolfi's pinned source.
- Disabled inputs cause no tuning, injection, module loading, or configured file writes, including after startup.
- Untrusted libraries cannot execute through retained dependencies or explicit loading on the production Werewolf image.
- Preserve public `getenv`, `secure_getenv`, environment mutation, symbol versions, and optimized CPU/allocator defaults on x86_64 and aarch64.
- Pass upstream tests with narrowly explained policy changes, Werewolf form checks, and comparative performance gates before rollout.

## Non-Goals

- Rewrite memory allocation, DNS, formatting, sorting, vector routines, or general `dlopen`.
- Add runtime switches, permissive builds, or application-specific exceptions to disabled features.
- Claim these reductions repair application memory corruption or every libc vulnerability.

## Detailed design

1. **Deny implicit environment configuration.** In glibc's private build headers, redirect internal environment getters to a typed helper returning `NULL`, if build validation confirms this is smaller and reliable. Exempt the public getter implementations and required secure-execution sanitation. Cover `__libc_secure_getenv` and aliases; a public interposition wrapper is insufficient. Review each caller: denying lookups also changes HOME expansion and other environment-dependent APIs. Bare-name `execvp`/`posix_spawnp` must fail closed; explicit executable paths remain available. Use explicit paths or application workarounds first; retain a real internal lookup only for a demonstrated API requirement, never as a generic variable allowlist.
   Freeze security-sensitive fallbacks: fail implicit executable lookup instead of searching a broader PATH; retain strict option/pattern defaults; fail environment-selected temporary-name lookup without an explicit valid directory; require eager binding and reject executable-stack requests. These are part of environment/tuning policy, not additional protection mechanisms.
   Separately skip direct environment interpretation in `elf/rtld.c`, `elf/dl-tunables.c`, and static `elf/dl-support.c`. Preserve kernel `AT_SECURE` sanitation and startup bookkeeping. Retain compiled tunable defaults and hardware detection. Ignore `LANG`, `LANGUAGE`, `LC_ALL`, every `LC_*`, locale paths, timezone, resolver, temp-directory, profiling, and tracing overrides. `setlocale(category, "")` selects `C`; an empty locale argument does not mean an unset current locale. Explicit application locale requests are separate APIs and require compatibility review.
2. **Disable loader injection and search overrides.** Explicitly ignore `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_PROFILE`, and all other loader environment controls. Cover `/etc/ld.so.preload`, loader `--preload`/`--audit`/`--library-path`, and ELF `DT_AUDIT`/`DT_DEPAUDIT`. Reject other CLI search overrides (`--inhibit-rpath`, `--inhibit-cache`, and hwcaps directory overrides) rather than leave alternative knobs. Ignore disabled environment/file sources without parsing their values; reject explicit CLI/ELF requests clearly before activation. Preserve normal dependencies and `dlopen`. Gate existing activation points rather than removing the loader's dependency machinery.
3. **Built-in NSS only.** In `nss/nss_module.c`, retain the existing `files` and `dns` branches and fail external requests before constructing names or loading DSOs. Record failure using existing state/locking conventions so retries and concurrent lookups remain correct. Unsupported configuration must return the established unavailable status, not silently change identity data. Applications needing another identity source must adapt separately.
4. **Built-in converters only.** Skip external gconv cache/configuration discovery in `iconv/gconv_conf.c`; retain its existing built-in module and alias registration. Deny DSO loading in `iconv/gconv_dl.c` as a backstop, and omit external converter files/registries from runtime packages. Built-ins include UTF-8, ASCII, and internal UCS conversions; UTF-16 is not a built-in in the inspected source. Keep existing lookup/error semantics. Applications needing additional conversion use an explicit, tested application library.
5. **Disable nscd.** Use existing `--disable-build-nscd` and `--disable-nscd` options to omit the daemon and libc clients. Keep direct files/DNS resolution; measure lookup costs before deciding whether application or resolver caching is needed.

Host patches and releases in [werewolf-linux/glibc-neutered](https://github.com/werewolf-linux/glibc-neutered). Track the complete Wolfi recipe and supporting files rather than maintaining a hand-copied recipe or assuming Melange supports inheritance. Pin recipe/source hashes; retain Wolfi's hardening and security backports. A scheduled GitHub Action proposes updates, applies patches without fuzz, and builds matching loader/libc packages for both architectures. Publish only validated, signed/indexed artifacts with source and patch provenance. Patch drift blocks the update; the last validated package remains available. Runtime package dependencies must keep the custom loader and libc together through updates.

PostgreSQL migration blocks its rollout: replace the `popen-shim.so` preload in `forms/postgresql/cmd/pg-init` with direct argument-vector execution and explicit locale handling in PostgreSQL setup. Cover `initdb`, bootstrap/server children, and locale enumeration. Linking a shim only into `initdb` does not cover children. No preload exception, added shell, or permissive libc.

Retained loading is bounded by Werewolf's [IPE policy](ipe.md): native executable mappings must come from the selected verified root, including dependencies, explicit `dlopen`/`dlmopen`, and static-linked loading. This is an existing Werewolf integration requirement, not a sixth libc patch. Audit ELF RPATH/RUNPATH, `$ORIGIN`, dependencies, cache entries, and symlinks in the built image; do not authorize writable directories or an untrusted alternate loader. Non-IPE images do not meet the native-code integrity claim. The current strict policy rejects anonymous executable memory, so JIT-dependent forms cannot meet this profile without separate design work; do not silently add an exception.

## Drawbacks

Environment-dependent libc APIs change behavior even though public `getenv` works. C locale affects collation and multibyte conversion; it is not C.UTF-8. External NSS, legacy encodings, profiling injection, and nscd consumers need application work. Private-header macros can affect tools/tests or function definitions; use build guards and explicit exemptions, or choose explicit consumer edits if those are easier to maintain. No patch-size or performance claim is measured yet.

## Alternatives Considered

- Launcher sanitation: useful defense, but later `setenv` or memory corruption can restore settings; CLI, ELF, NSS, and converter inputs bypass it.
- Override public `getenv`, or force secure mode: breaks application configuration and changes unrelated privilege semantics; direct startup scans still remain.
- Maintain many variable allowlists or remove entire subsystems: adds policy/parser code and patch churn. One private denial helper plus a few activation gates is the first approach to validate.
- Restore features for PostgreSQL or offer opt-outs: expands every process's surface. Fix setup and conversion requirements in the application.
- Replace glibc: other libc implementations have analogous parser and memory-safety failures; changing ABI adds migration work without preserving our current performance assumptions.

## Security Considerations

Direct loader invocation can bypass an environment-only policy:

```sh
/lib/ld-linux-aarch64.so.1 --library-path /writable/lib /usr/bin/trusted-app
```

If an attacker can place a compatible dependency in that directory and control loader invocation and arguments, the loader can select the substituted library and run its constructors before application startup. A command allowlist that trusts the loader but accepts arbitrary arguments can expose this route. This is an intentional loader feature, not itself a vulnerability or an automatic privilege escalation; invoking a setuid target through the loader does not grant the target's setuid privileges. Without control of loader invocation, denying this option adds little protection. Reject it to close the CLI equivalent of `LD_LIBRARY_PATH`; adapt the test harness without a runtime exception.

Production IPE must independently reject executable mappings of the substituted library. With comprehensive IPE enforcement, CLI denial is defense in depth. Normal dependency loading, RPATH/RUNPATH, and explicit `dlopen` remain subject to that boundary; CLI denial alone cannot prevent arbitrary native-code execution.

Reject before parsing, allocating, or loading. Denial must survive OOM, duplicate environment entries, environment mutation, configuration reload, alternate filesystem roots, and static-linked loading. Keep upstream fixes for retained APIs: syslog sizing, resolver bounds, `$ORIGIN`, qsort failures, signals, and allocation arithmetic remain separate risks. IPE constrains native-code provenance; it does not prevent reuse of trusted code, malicious interpreted input, or arbitrary application memory corruption. This proposal removes identified injection mechanisms rather than claiming to prevent every possible RCE.

## Reliability Considerations

Test public getters and mutation, ordinary and secure execution, static/shared linking, direct loader execution, malformed inputs, and post-startup changes. Assert C locale despite all LANG/LC variants. Exercise every injection route, NSS reload/unavailable results, converter aliases and short output buffers, and absence of nscd socket access. Explain policy-related upstream failures individually; never suppress a whole suite.

Release injection probes must attempt constructors from attacker DSOs via every disabled source, direct loader CLI, alternate roots, and reloads. Also try dependencies, `dlopen`/`dlmopen`, static loading, relative/empty RPATH elements, and symlinks into writable storage under production IPE; untrusted native code must fail before any constructor executes. Run IPE's exec/mmap/mprotect and tampered-policy checks on both architectures.

Before release, run supported form checks on both architectures and compare the same Wolfi revision with/without patches: startup, allocator throughput/RSS, vector operations, DNS/identity latency, and service/database traffic. Initial gate: no correctness failures or repeatable regression over 5% in required workloads; investigate variance and caching effects rather than weakening the policy. Retain the prior validated packages for rollback and run Werewolf's required integration checks before changing production forms.
