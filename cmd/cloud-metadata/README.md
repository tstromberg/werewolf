# cloud-metadata

## Summary

cloud-metadata fetches a base64-encoded config tar from cloud instance user data.
`once` rewrites it for init at `/run/werewolf/cloud/config.tar`. It exits 0 without
writing on unknown clouds or non-werewolf data, and 1 on errors. With no argument,
the service refetches cloud config each minute and updates accounts on changes
(`lib/people.zig`); it stays down on machines without cloud config.

## Background

A cloud image has no config disk, but every cloud carries user data. This is how a
machine on GCP, AWS, Hetzner or Azure gets its hostname and root's ssh keys without
cloud-init: GCP's `user-data` attribute, AWS's user data, Hetzner's user_data, or
Azure's userData. init runs cloud-metadata once at boot, after the network is up and
before fence sets the network policy, when no config tar was found on a disk or seed.

## Goals

- Read the config from the four clouds' user data, and ask nothing elsewhere.
- Hand init only what werewolf wrote: plain files owned by root.
- Confine the process that reads the network so it can do nothing else.

## Non-Goals

- cloud-init. `#cloud-config` users, packages and scripts are not applied.
- Clouds werewolf does not know. Adding one is a row in the provider table.

## Detailed design

- **The firmware names the cloud** before any packet is sent: DMI vendor,
  product, and Azure's asset tag, which desktop Hyper-V lacks. So nothing
  asks 169.254.169.254 on a network where a neighbour might answer for it.
- **The fetcher**, a forked child, runs as `_cloud` (uid 68), chrooted to
  `/var/empty`, with no capabilities. Landlock allows no file and only TCP
  to port 80. seccomp allows a TCP socket and little else, so no UDP, which
  Landlock cannot hold to a port. These hold it because fence has not set
  the network policy yet. It speaks HTTP/1.1 to 169.254.169.254 with AWS's
  IMDSv2 token or GCP's and Azure's headers: 5 seconds an exchange, 4
  tries, 128 KiB at most. It refuses a GCP answer without
  `Metadata-Flavor: Google`, and hands the parent a tag byte and the body.
- **The parent** keeps root's uid but no capabilities, and never touches the
  network. Landlock lets it write only in `/run/werewolf/cloud`; seccomp
  lets it read only the pipe. It checks the tar entry by entry: regular
  files and directories, names of `A-Za-z0-9._-/`, relative, no `.` or
  `..`, none twice or beneath a file, 32 entries, 32 KiB each, 48 KiB in
  all, numbers of digits alone. It then writes a new tar: every entry owned
  by root, 0600 or 0700, pax headers ignored.
- **Logging**: the parent writes every event as one JSON line on stdout.
- **The service** forks a persistent `_cloud` fetcher and `_usrmgr` parser before
  dropping setup privileges. `_usrmgr` (uid 74) has no capabilities or network,
  checks the metadata, and writes only its private cloud scratch directory.
  Once a minute it requests a fetch; unchanged or refused input sends a heartbeat.
  The root publisher receives bounded users/key records, derives IDs and paths
  through `people.applyReserved`, and keeps CHOWN alone under Landlock and seccomp.
  A root-owned table on `/data` keeps old names and IDs reserved. Removed people
  retain locked account entries, while their keys and admin grants disappear.
  Neither worker can write accounts or keys. Publication is acknowledged before
  advancing the last-applied config; failures are retried on the next poll.
  Both workers watch a publisher-only lifetime pipe, including during HTTP waits.
  GCP `machine.metadata-users: true` retains expiry, declared-user precedence
  and the prohibition on admin/root from provider keys
  ([manifest.md](../../docs/design/manifest.md)).

## Drawbacks

- Plain HTTP to a link-local, unauthenticated server, as on every cloud.
- User data stays readable at the server for the instance's life.

## Alternatives Considered

### cloud-init
cloud-init is a large Python agent that runs scripts as root: the opposite
of a machine with no shell and no interpreter.

### Pass the tar to init as fetched
init would extract what the network sent. Rewriting it from plain fields
means a pax header, a link, or an owner never reaches init.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A neighbour answers for 169.254.169.254 | It asks only on a cloud the firmware names; there the address is the hypervisor's. |
| A hostile HTTP response | Only the fetcher parses it, and it holds nothing but its socket. |
| A hostile tar: links, devices, `..`, pax tricks | Refused or skipped, rewritten from plain fields, checked by init again. |
| A compromised fetcher sends the user data away | **Open, in part:** before fence, its sandbox holds it to TCP port 80, but cannot pin the address. |
| Secrets in user data | After boot, fence refuses the metadata server to every account. On AWS, require IMDSv2 with a hop limit of 1. |
| Whoever sets user data | Owns the machine, by design: it carries root's keys. |

## Reliability Considerations

- **Bounded:** at most 27 seconds, or 47 on AWS, when the server is down.
- **Fails safe:** no config means no keys, not a broken config; init boots on.
- **Says why:** a failure is logged with its cause (refused, timed out, an
  HTTP status, a token refused, an answer not GCP's). The fetcher passes it
  as a byte and a number, never text, and the parent puts it in words.
- **Tested:** `make check-cloud`: all four clouds, a hostile one, and none.
