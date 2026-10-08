# cloud-metadata

## Summary

Fetches werewolf's config tar from a cloud's metadata server, as the
instance's base64 user data, and leaves a rewritten copy for init. It exits
0 with nothing written where there is nothing of werewolf's, 1 on an error.

## Background

A cloud image has no disk for a config tar, but every cloud carries user
data: this is how a machine on GCP, AWS, Hetzner or Azure gets its hostname
and root's ssh keys without cloud-init. init runs it once at boot, after the
network is up, before fence, when no config tar was on a disk or seed.

## Goals

- The config from the four clouds' user data, and nothing asked elsewhere.
- What reaches init is only what werewolf wrote: plain files, root's.
- The process that reads the network can do nothing else.

## Non-Goals

- cloud-init: `#cloud-config` users, packages and scripts are not applied.
- Clouds werewolf does not know; each is a row in its provider table.

## Detailed design

- **The cloud from the firmware**, before a packet is sent: DMI vendor,
  product, and Azure's asset tag, which a desktop Hyper-V lacks.
- **The fetcher**, a forked child, runs as `_cloud` (uid 68), chrooted to
  `/var/empty`, with no capabilities. Landlock allows no file and TCP to
  port 80 alone; seccomp a TCP socket and little else, so no UDP. It speaks
  HTTP/1.1 to 169.254.169.254: AWS's IMDSv2 token, GCP's and Azure's
  headers, 5 seconds an exchange, 4 tries, 128 KiB at most. It refuses a
  GCP answer without `Metadata-Flavor: Google`, and hands the parent a tag
  byte and the body.
- **The parent**, root's uid without capabilities, never touches the network:
  Landlock lets it write only in `/run/werewolf/cloud`, seccomp read only
  the pipe. It checks the tar entry by entry (regular files and directories,
  names of `A-Za-z0-9._-/`, relative, no `.` or `..`, none twice or beneath
  a file, 32 entries, 32 KiB each, 48 KiB in all; numbers digits alone),
  and writes a new one: every entry root's, 0600 or 0700, pax ignored.

## Drawbacks

- Plain HTTP to a link-local, unauthenticated server, as on every cloud.
- User data stays readable at the server for the instance's life.

## Alternatives Considered

### cloud-init
A large Python agent that runs scripts as root: the opposite of a machine
with no shell and no interpreter.

### Pass the tar to init as fetched
init would extract what the network sent. Rewriting it from plain fields
means a pax header, a link or an owner never reaches init.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A neighbour answers for 169.254.169.254 | It asks only on a cloud the firmware names; there the address is the hypervisor's. |
| A hostile HTTP response | Parsed by the fetcher alone, which holds nothing but its socket. |
| A hostile tar: links, devices, `..`, pax tricks | Refused or skipped, rewritten from plain fields, checked by init again. |
| A compromised fetcher sends the user data away | **Open, in part:** before fence, its sandbox holds it to TCP port 80, but cannot pin the address. |
| Secrets in user data | After boot, fence refuses the metadata server to every account. On AWS, require IMDSv2 with a hop limit of 1. |
| Whoever sets user data | Owns the machine, by design: it carries root's keys. |

## Reliability Considerations

- **Bounded:** at most 27 seconds, or 47 on AWS, when the server is down.
- **Fails safe:** no config means no keys, not a broken config; init boots on.
- **Says why:** a failure is logged with its cause (refused, timed out, an
  HTTP status, a token refused, an answer not GCP's), which the fetcher
  passes as a byte and a number, never text, and the parent puts in words.
- **Tested:** `make check-cloud`: all four clouds, a hostile one, and none.
