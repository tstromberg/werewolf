# Hardened interpreters by default
## Summary

Rebuild Wolfi's Java, Python, PHP and Node.js beside glibc in packages. Each has one
build, with root-held allowances for loading code outside the verified root.
## Background

An interpreter can run attacker code without `execve`: deserialization, `defineClass`
or a jar in `/data`, as in the PaperCut chain (CVE-2026-82077). [IPE](ipe.md)
excludes interpreted code; [script-argv.md](script-argv.md) closes only re-exec.
Launch flags and environment settings do not survive attacker-controlled re-exec. The
protection belongs in the runtime, as [glibc-neutered](glibc-neutered.md) puts libc's
in libc.
## Goals

- Code a runtime loads from a file comes from the verified root, from process start.
- Environment configuration, inline or writable-source code and object reconstruction
  require root-held allowances; probes fail the build when a protection stops
  working.
- A Wolfi runtime release is signed in werewolf's repository within four hours, both
  architectures, the default for a `high` fix ([update-policy.md](update-policy.md)).
- Every form uses these builds; posture lists each runtime allowance a machine holds.
## Non-Goals

- Verified code interpreting attacker data (SpEL, OGNL, Jinja); leash contains it.
- Unsafe third-party library APIs, such as PyYAML's `UnsafeLoader`; fix their
  defaults.
- Ruby until phase 3; gadget design; memory corruption (W^X and IPE).
## Detailed design

**Repository.** werewolf-linux/packages builds glibc and runtimes together. `refresh`
captures Wolfi's unchanged recipe for the newest stable stream (OpenJDK 27, Python
3.15, PHP 8.5, Node.js 26). `derive` keeps names, uses epoch 1000 × revision +
Wolfi's, adds `wolfi-origin:` for CVE matching (lib/prebuilt.zig), and stops on
drift. Patches allow fuzz 2, as Wolfi's do; stopped or fuzzed builds produce issues.
CI signs the combined `apk/hardened` feed on R2, inherited once through `minimal`.
Snapshots and release notes remain under `apk/RUNTIME/builds/BUILD-ID`.

**No fallback.** New Wolfi versions can outrank hardened epochs. Before resolution,
howl authenticates the feed and pins covered requested runtimes. Original constraints
still apply: incompatible minimums fail; exact production/native-test pins stay
fixed. After resolution, howl and the updater require covered names, versions and
control checksums in the signed index. Bad or unavailable feeds and replacements fail
before image or slot commit. Explicit older streams and OCI runtimes need separate
migrations.

**Allowances.** Capability groups cover classes of functions: `exec` spawns programs;
`native` permits native code or memory; `deserialize` rebuilds objects; `phar` its
wrapper; `inline` argv/stdin code; `writable-source` scripts on writable mounts.

A service grants `[java:native]` in `services.NAME.allow`; top-level `allow` is
image-wide. Forms validate `PACKAGE:NAME`: both parts nonempty, using only `a-z`,
`0-9` and `-`. Packages define supported names; unrecognized names have no effect.
The builder writes an empty regular file:
`/etc/runtime-hardening/allow/<ns>/PACKAGE/NAME`, read with `lstat`, fail closed.

`<ns>` is the service's `/proc/self/cgroup` leaf: leash joins it as root; the service
cannot leave or forge it. Runtimes check that namespace, then `all`. Service grants
follow whole-service replacement, so replacing a service drops its old grants. Grants
require the machine's root; `all` is reserved. A lock-time link (`/+3s` or `/init`)
is deferred. Distros without service cgroups use `all`, writable by root.

**Effective root.** Runtime initialization (including embedding) rejects effective
UID 0 regardless of real UID; real UID 0 may run with non-root effective UID.
Services and PHP-FPM masters drop privileges first. Build/test guests alone create
`/etc/runtime-hardening/build-root`, root-owned and without group/other writes. It is
never a form allowance; runtime APKs may contain no `/etc/runtime-hardening` files.

**Phase 1, compiled-in defaults and group gates.** Wolfi's builds with these changes:
- OpenJDK: ignore `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS` and
  `JDK_ALTERNATE_VM`; `DisableAttachMechanism` on; `deserialize` refuses every class
  but primitive arrays; `native` denies `Unsafe` and native access a jar manifest
  does not.
- CPython: no `PYTHON*` variables or user site; no working directory on `sys.path`
  for `-m`, `-c` or stdin; no loadable SQLite extensions; `native` denies `_ctypes`;
  `deserialize` denies `pickle` loading a global.
- PHP: ignore `PHPRC` and `PHP_INI_SCAN_DIR`; `exec` gates the whole
  `disable_functions` floor; `native` denies `dl`; `deserialize` makes `unserialize`
  yield only named classes; `phar` the wrapper; `allow_url_include` and the OPcache
  file cache off.
- Node.js: omit npm/npx, inspector and SEA; ignore runtime environment options and
  user module paths. `exec` gates child processes and `--run` package scripts;
  `native` gates addons, FFI, WASI, OpenSSL native-loading configuration and SQLite
  extensions. `inline` gates argv/stdin, worker eval and data-URL code imports;
  `writable-source` gates ordinary main/dependency modules and disk compilation
  caches on writable storage. Custom startup snapshots and security reverts refuse.
  Normal worker threads and data access remain. V8 serialization has no object gadget
  behavior like Java serialization or pickle, so there is no deserialize gate.
- Python: `inline` gates argv/stdin; `writable-source` gates the main script. PHP
  checks all compiled files by descriptor, outside OPcache and during preloads;
  `writable-source` permits writable files, `inline` evaluated and generated code.
  Metadata failures refuse. Java's `defineClass` seal remains deferred.

**Phase 2.** `defineClass`, `marshal`, Python `eval`, Node `vm` and custom loaders
still need provenance; PHP gates string compilation with `inline`. **Form coverage.**
Native forms still request PHP 8.4; hardened PHP follows 8.5. Migrate writable
configuration to data and precompile templates before switching; blanket grants
restore webshell risk. Older Node and OCI runtimes also need migration. Declare
allowances as weaknesses with excuses, like `jit`.
## Drawbacks

- Generated code needs root-held precompilation or `writable-source`.
- Image-wide grants affect every service; build guests grant every group for testing.
- Runtime upkeep is permanent; JDK/Python builds take ~1h/arch; drift delays fixes.
## Alternatives Considered

- **Hardened and insecure flavors:** duplicate builds/CVE streams and coarse
  exceptions.
- **Per-function knobs:** drift as APIs change; groups retain their meaning.
- **Flags, JVMTI or kernel alone:** re-exec controls argv/environment, not bytecode.

## Security Considerations

Root-held capability grants like `jit`/`sh` deny by default and survive refactors.
Deny `native` first: ctypes, FFM or `Unsafe` memory access can remove later checks.

## Reliability Considerations

Phases ship separately. Refusals park services; slot-keep retains the old slot. `make
check` exercises each app form before release.
