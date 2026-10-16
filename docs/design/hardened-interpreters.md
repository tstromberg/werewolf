# Hardened interpreters by default

## Summary

Rebuild Wolfi's Java, Python and PHP in three repositories modelled on glibc-build, with
werewolf's protections compiled in, so a compromised application cannot turn its runtime
into an engine for code that is not on the verified root. Each runtime has one build;
what a form needs back it names as an allowance, which the runtime reads from the root.

## Background

leash turns code execution in a compiled service into a refused `execve`; in an
interpreter the attacker needs none. A JVM running attacker bytecode makes the same
calls as one running its own, so a feature that loads bytes as code suffices
(deserialization, `defineClass`, a jar in `/data`), as in the PaperCut chain
(CVE-2026-82077). [IPE](ipe.md) names interpreted code a non-goal, and
[script-argv.md](script-argv.md) closes only re-exec.

Launch flags in a service file do not hold: argv and the environment are what an
attacker controls when they re-exec the runtime from inside it. A protection must be in
the runtime's own build, as [glibc-neutered](glibc-neutered.md) puts libc's in libc.

## Goals

- Code a runtime loads from a file comes from the verified root, from process start.
- No runtime reads its configuration from the environment, loads agents or debuggers,
  or deserializes arbitrary classes, unless an allowance on the root says so; each
  protection has a probe that fails the build when it stops holding.
- A Wolfi runtime release is signed in werewolf's repository within four hours, both
  architectures, the default for a `high` fix ([update-policy.md](update-policy.md)).
- Every form uses these builds; posture lists each runtime allowance a machine holds.

## Non-Goals

- Code that already-verified code runs on attacker data: an expression language (SpEL,
  OGNL), pickle calling stdlib functions, a Jinja template. The leash contains it.
- Ruby and Node until phase 3; gadget design; memory corruption (W^X and IPE).

## Detailed design

**Repositories.** `openjdk-build`, `python-build` and `php-build` copy glibc-build's
pipeline. `refresh` captures Wolfi's recipe, unchanged, for each stream `policy.json`
names (OpenJDK 21 and 27, Python 3.13 and 3.14, PHP 8.5). `derive` keeps Wolfi's names
with epoch 1000 × revision + Wolfi's, above Wolfi's rebuilds, adds `wolfi-origin:` for
CVE matching (lib/prebuilt.zig), and stops on drift; patches apply without fuzz.
CI signs into `apk/RUNTIME` on R2 and files what stops a Wolfi build as an issue.

**Phase 1, compiled-in defaults.** What Wolfi builds, less these:
- OpenJDK: ignore `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS` and `_JAVA_OPTIONS`; jlink
  the JRE without `jdk.attach`, `jdk.jdwp.agent`, `jdk.management.agent`,
  `jdk.hotspot.agent`, `jdk.jshell`; `DisableAttachMechanism` on; `jdk.serialFilter`
  `!*`, the system property ignored; `Unsafe` memory access denied, and native access
  unless a jar's manifest on the root grants `Enable-Native-Access`.
- CPython: isolated by default in `PyConfig` (no `PYTHON*` variables, user site or
  unsafe path); no `--enable-loadable-sqlite-extensions`; `_ctypes` refused unless
  allowed, since a process that can write its memory can remove any check.
- PHP: ignore `PHPRC` and `PHP_INI_SCAN_DIR`; a `disable_functions` floor (`exec`,
  `system`, `passthru`, `shell_exec`, `proc_open`, `popen`, `pcntl_exec`, `dl`) that
  `php.ini` cannot lift; `unserialize` makes objects only of classes it is given;
  `allow_url_include`, `phar://` and the OPcache file cache off; no phpdbg or PEAR.

**Allowances.** A form takes a protection back in `allow:`, as it takes `jit` today:
`allow: [jit, php:proc_open, java:deserialize]`, in the runtime's own names; the build
refuses one the runtime does not define. compose writes an empty file per allowance on
the read-only root, beside the machine's own: `/etc/werewolf/allow/php/proc_open`. The
runtime checks it with `faccessat(AT_SYMLINK_NOFOLLOW)`, never argv or the environment.
1. Later, per service: the same files in `/etc/sv/NAME/allow/`, beside its pledge. The
   runtime finds NAME in `/proc/self/cgroup`, which leash joined as root and the
   service cannot leave.
2. Then lock times: an allowance may be a link whose target, read with `readlinkat`
   and never followed, says when it locks: `/+3s` after leash starts the service, or a
   named point such as `/init`. leash records the start as root, in boot-clock time, so
   a re-run from inside the service keeps the clock and a runsv restart resets it.

**Phase 2, the code seal.** Compiled into each runtime, judged by provenance:
1. Code from a file must be on the dm-verity root, from process start: a class path or
   module path entry, an import, an `include`. A jar, script or upload in `/data` is
   refused, and re-executing the runtime gains nothing.
2. Code from argv or stdin (`python -c`, `php -r`, a piped script) is always refused.
3. Code from bytes is refused unless the runtime's own generators make it (what
   `java.base` makes for lambdas and proxies, CPython's `namedtuple` and `dataclasses`)
   or an allowance grants it, which a lock time can limit to a framework's start. An
   AppCDS archive dumped at build time holds the lambda proxies an application warms.

The checks sit where code is defined: OpenJDK's class definition path in HotSpot, not
an agent, which would be argv; a C audit hook added during CPython's initialization;
`zend_compile_file` and `zend_compile_string` wrapped by a built-in PHP extension.

**Phase 3, the default.** `jre`, `jre21`, `python`, `php` and their `-app` and
`-example` forms install these builds. A form that holds a runtime allowance declares it
among its weaknesses with an excuse, as `jit` is today. Ruby and Node follow.

## Drawbacks

- Breaks code defined at run time: lazy Spring and Hibernate proxies, PHP templates
  compiled to a writable cache (Twig, Blade, Smarty), Nextcloud's apps in `/data`. Each
  precompiles at build or takes an allowance.
- Until per-service allowances land, one service's allowance is every service's.
- Three repositories to keep current forever. OpenJDK and CPython take about an hour
  per architecture, and a drifted recipe holds every later fix until someone follows.

## Alternatives Considered

- **Two flavors, hardened and `-insecure`**: two builds, two CVE streams, two sets of
  forms, and all or nothing where an allowance takes back one thing.
- **Allowances in a home directory or the environment**: the confined process can write
  both, so it could grant itself what it lacks.
- **Launch flags, a JVMTI agent, or the kernel alone**: argv and the environment do not
  survive a re-exec, and the kernel sees no bytecode.

## Security Considerations

Deny by default; every allowance is named, on the verified root and declared, as `jit`
and `sh` are. Phase 2 closes the in-process route argv enforcement cannot, while a
process cannot write its own memory: hence phase 1 refuses ctypes, FFM and `Unsafe`.

## Reliability Considerations

Each phase ships alone; a protection fails closed and logs, a refused class parks the
service, and slot-keep then keeps the old slot. `make check` runs each app form first.
