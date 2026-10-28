# Forms without loader preloads

**Status:** Implemented
[2026-10-14](https://github.com/werewolf-linux/werewolf/commit/337308f6)

## Summary

Use real UNIX accounts for Samba, PostgreSQL for Paperless, and no crash
preload for Suricata. Zeek keeps the loader and libc inside its OCI image.

## Background

glibc-neutered refuses loader environment overrides. Three native forms
used preloads for account lookup, SQLite permissions or crash diagnostics.

## Goals

- Keep applications unprivileged, confined and preserve existing data.
- Add UNIX users through declarations or cloud metadata without reinstalling.
- Make Paperless use the upstream-recommended PostgreSQL backend.

## Non-Goals

- Deploy the base glibc change or replace vendor OCI libraries.
- Give smbd root or identity-switching capabilities.
- Automatically convert an existing SQLite archive.

## Detailed design

Samba passwords still come from its private config. samba-init requires
each name in the real passwd database and records its actual nonzero UID.
It creates no synthetic accounts or lookup library. smbd remains the
unprivileged samba user; its shares force that file owner. UNIX accounts
come from existing account declarations, NoCloud or metadata. A keyless
person can be declared as `users: {alice: {}}` or a bare name in the config's
users file. Admins still need keys. Metadata reconciles accounts each
minute; changing Samba passwords/shares requires the next boot or an
explicit local config update and service restart. No image reinstall is
needed, and stable account IDs preserve identity across config changes.

Paperless takes the existing PostgreSQL form and its local peer-authenticated
socket. The components share the paperless UNIX identity and login role. Each
declares shared-user: true; undeclared sharing and root sharing are refused.
They use one private upload scratch directory, as upstream expects; service
rules and process limits remain separate. The web process runs migrations. The
locked upstream postgres extra supplies psycopg, linked to Wolfi's libpq.
The form format is bumped so old launchers cannot accept the new service
syntax. Each component creates its scratch directory; the scheduler has a
bounded 256 MiB limit, validated against document processing.
Startup waits for both local sockets. Readiness lives in /run, so an old
boot cannot start workers before migrations. An existing db.sqlite3 stops
every component before database access and requires upstream export/import.
Neither database listens on TCP; PostgreSQL runs with jit=off, while the
inherited form's kernel JIT allowance remains declared.

Suricata drops the diagnostic constructor and keeps its normal logs.
Unused preload libraries and their build rules are removed.

## Drawbacks

- PostgreSQL adds memory and storage overhead and a database to maintain.
- Samba file ownership remains service-owned; UNIX ownership per share
  needs a separate design for switching identities safely.

## Alternatives Considered

- SQLite: smaller, but PostgreSQL is the selected production default.
- Restore loader variables: conflicts with the fixed libc policy.

## Security Considerations

Missing or root Samba accounts fail before configuration is rewritten.
Keyless accounts grant neither SSH keys nor root access. PostgreSQL peer
authentication refuses another application impersonating Paperless.
The Paperless components are one UNIX trust identity. No database password is added.

## Reliability Considerations

Test stable account IDs, revoked users and preserved shares across config
changes. Boot Paperless and verify migrations, component database access,
peer refusals, shared-user declarations and persistent document operations. Test
that SQLite migration refusal leaves the database intact. Native form
checks remain required before adopting glibc-neutered in the base image.

Sources: Paperless [setup](https://docs.paperless-ngx.com/setup/) and
[export/import](https://docs.paperless-ngx.com/administration/#exporter-importer).
