# opensearch-setup

## Summary

opensearch-setup writes OpenSearch's configuration directory before each
start: the image's files, and `internal_users.yml` with one user, `admin`,
by a bcrypt hash of the config's password. Then it removes the password.

## Background

OpenSearch reads its configuration from one directory, `path.conf`, and
writes it too: it makes its keystore there at every start. Its security
plugin reads its own files beneath it (`opensearch-security/`), and the
certificates by paths relative to it. So the directory is the service's
own, `/run/svc/opensearch`, where leash also copies the config's files
(`admin-password`, `tls-cert`, `tls-key`, `tls-ca`). The security plugin
wants a password only as a bcrypt hash; upstream's `hash.sh` is a shell
script.

## Goals

- OpenSearch starts from the image's configuration and the config's
  secrets alone, never a demo file.
- The password is never where OpenSearch could read it.

## Non-Goals

- Changing the password of a running node: the security index on `/data`
  holds it after the first start ([README](../../README.md#drawbacks)).
- Checking certificates: the security plugin refuses a bad or demo one,
  and says why.

## Detailed design

leash runs it as the `opensearch` user, in the service's Landlock rules,
after copying the config's files:

1. Read `/run/svc/opensearch/admin-password`, without its trailing
   newline; refuse fewer than 12 bytes or more than 72, which bcrypt
   would cut.
2. Hash it, bcrypt, cost 12, as the plugin's own tool does.
3. Copy each file of `/etc/opensearch` (`opensearch.yml`,
   `log4j2.properties`, the security plugin's files) into
   `/run/svc/opensearch`, 0600, each by a temporary file and a rename.
4. Write `opensearch-security/internal_users.yml`: `admin` alone,
   reserved.
5. Remove the password's copy, and say whether the security index on
   `/data` already exists, so whose password counts.

A failure prints its name and exits 1, which parks the service.

## Drawbacks

- The hash is made at every start, for a file the plugin reads only at
  its first: about a quarter of a second.

## Alternatives Considered

- **securityadmin at every start**: a second certificate, an admin's,
  and a Java tool run as `run:`; it would let the config's password win
  at every start, at the cost of a key that can rewrite the security
  index.
- **Configuration in `/etc/opensearch` alone**: OpenSearch must write
  its keystore beside it.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| The password read from the JVM's directory | Removed once hashed. |
| A demo user | Only `admin` is written; the image has no other users' file. |
| A half-written file | Each is renamed into place whole. |

## Reliability Considerations

- No state of its own: everything is written again at every start.
- Tested by its unit tests and by `make check-opensearch`.
