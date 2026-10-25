# PostgreSQL without a preload

## Summary

Replace PostgreSQL setup's popen preload with the existing static sh-shim. Support its
required trailing /dev/null redirections and declare every setup executable in the
PostgreSQL service.

## Background

pg-init preloaded popen-shim.so into initdb and its setup backends; hardened glibc
disables preloads, so that no longer works. PostgreSQL 17 uses system/popen for backend
version checks, configuration probes, bootstrap and single-user setup, and the setup
backend runs locale -a. sh-shim already runs one command without a shell but refuses
every redirection; the preload accepted /dev/null redirections, with fork, stream and
wait bookkeeping of its own. The static executable can reuse glibc's popen machinery.

## Goals

- Fresh UTF-8/C clusters initialize without LD_PRELOAD under stock and hardened glibc.
- Existing clusters, SQL imports and crash-safe data.new promotion retain their
  behavior.
- No shell, arbitrary redirection target, command chaining or new glibc exception.
- PostgreSQL alone declares the shim and locale executable in its Landlock run list.

## Non-Goals

- Replacing PostgreSQL, changing database locale or upgrading an existing cluster.
- General shell syntax, arbitrary file redirections or a service-wide shell allowance.
- Migrating other applications' preloads in this change.

## Detailed design

pg-init keeps its absolute initdb invocation, UTF8 encoding, --no-locale and peer/reject
authentication flags. Its child environment keeps the fixed /usr/bin PATH and drops
LD_PRELOAD.

The PostgreSQL form includes the static sh-shim program and lays /usr/bin/sh as a link
to it; merged /bin reaches the same file. The alias is explicit for this form, so adding
a debugging shell does not make PostgreSQL depend on it (the console debugger starts
/bin/mksh directly). The service's run list names initdb, sh-shim and /usr/bin/locale,
which Wolfi's posix-libc-utils-bin supplies, so the backend's locale -a succeeds without
a pretend response or a patch. No global allow: sh is added; Landlock still decides
which binaries can execute, regardless of the alias or PATH search.

sh-shim's existing word parser stays unchanged. An outer parser separates a trailing
unquoted redirection suffix from those words. The first operator must follow whitespace.
It accepts stdin/stdout redirection to the exact literal /dev/null, optionally quoted,
once each; 2>&1 is accepted only after stdout has been redirected to /dev/null and only
once. No words follow the suffix. Append, heredoc, other descriptors, targets,
pipelines, substitutions and chains fail before any descriptor changes or execution.

The shim opens /dev/null and duplicates it only onto requested standard descriptors,
checking errors and handling an already-closed descriptor. It then execs the same one
program with the original environment. There is no child bookkeeping, writable-file
creation or extra interpreter. Set-ID invocation remains refused.

Remove the unused popen-shim implementation and its build/test registration once the
executable path is covered. Other preloads remain separate migrations.

## Drawbacks

The PostgreSQL form owns its sh alias, including combinations with other forms. Human
shell users should select an actual interactive shell explicitly. The locale utility
enumerates installed trusted locales; --no-locale still chooses C for the database. This
migration alone does not certify the rest of PostgreSQL's behavior under hardened glibc.

## Alternatives Considered

- Restore LD_PRELOAD: weakens every application and defeats the fixed libc policy.
- Extend sh-shim with unrestricted redirection: introduces file creation/truncation and
  grammar we do not need.
- Put a locale stub inside sh-shim: mixes a PostgreSQL-specific response with a general
  command adapter.
- Patch PostgreSQL to use argv spawning: removes its shell-shaped interface but needs a
  maintained package/source delta across releases.
- Keep the preload as a linked replacement: misses setup children unless PostgreSQL is
  rebuilt too.

## Security Considerations

This is an adapter, not an executable allowlist. PostgreSQL's Landlock and seccomp
policy remain the boundary. Adding only the three explicit run paths avoids granting the
shim to unrelated services. No parser expansion, arbitrary native loading or glibc
environment exception is introduced.

The old preload already discarded these descriptors; the new suffix offers the same
operation without opening other files. Refusal happens before redirection, and
diagnostics continue to sanitize control characters.

## Reliability Considerations

Test PostgreSQL's command shapes, rejection of other targets, descriptors and suffix
argument injection, and descriptor behavior with closed standard streams. Boot
PostgreSQL without a shell; initialize UTF-8/C data, run SQL, retain it across restart
and verify failed setup leaves no promoted cluster. Repeat against the signed
hardened-glibc packages before adoption. The DEV form adds only the PostgreSQL client
and checks the sh alias, the removed library and explicit run paths, refused file
redirection, UTF8/C/C database settings, Unicode SQL and denial of another user's peer
login; the production console checks require cluster creation and a ready server, with
no shim refusal or service retry. The sh-shim form keeps its package-shell precedence
and allowance; its runtime checks passed, and its full gate keeps the same
kernel-exec-log failure.

On aarch64, PostgreSQL 17.10 initialized with stock glibc and the locally validated
glibc-neutered 2.44-r13 libc and loader, passing peer login, Unicode SQL, clean
shutdown, persistence across restart and the closed-descriptor tests. This chroot
evidence does not replace the appliance confinement checks or x86_64 validation. The
stock-libc appliance passed its startup, no-shell, DEV SQL/peer and service-restart
checks; its kernel-exec-log gate fails as in the unchanged minimal appliance.

Sources: PostgreSQL 17
[initdb](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/bin/initdb/initdb.c),
[backend version
checks](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/common/exec.c),
[collation
import](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/backend/commands/collationcmds.c).
