# unbound-setup

## Summary

unbound-setup is Unbound's `before` step. It seeds the root's trust anchor
on the first start, and writes the include that names the addresses
Unbound listens on and the forward zones the machine's settings name.

## Background

The `unbound` form ([README](../../README.md)) validates DNSSEC from the
root's keys, in a file Unbound rewrites as the root rolls them (RFC 5011,
`auto-trust-anchor-file`). Distros make that file with `unbound-anchor`,
which fetches the keys over the network that Unbound is meant to provide;
the image brings them instead, in Wolfi's `dnssec-root`. Unbound's
configuration cannot read settings, and werewolf has no shell to template
it, so a small program writes the part that differs per machine. leash
runs it as the unbound user, under the service's Landlock rules, after
service-config has checked the settings, and parks the service if it fails.

## Goals

- The anchor is seeded once, whole or not at all, and never replaced:
  after the first start it is Unbound's, which follows the root's keys.
- A forward zone resolves through its servers even though the root
  cannot vouch for it, and even where Unbound serves a default local zone.
- Unbound listens on IPv6 only where the kernel has it.

## Non-Goals

- Unbound's policy: access control, hardening and caches are the image's
  `/etc/unbound/unbound.conf`, which the reviewer reads.
- Servers of their own for each zone, or ports other than 53.

## Detailed design

1. **The anchor.** If `/data/svc/unbound/root.key` is missing,
   `/usr/share/dnssec-root/trusted-key.key` is copied there: a temporary
   file, synced, renamed over it, 0600. Otherwise it is kept.
2. **The settings.** `UNBOUND_FORWARD_ZONES` and `UNBOUND_FORWARD_TO`,
   lists service-config joined by commas, from the `forward-zones`
   (hostname) and `forward-to` (ip) settings. Each value is checked again:
   a zone is letters, digits, dashes and dots; a server a literal address,
   with no port or scope. One without the other is refused.
3. **The include**, `/run/svc/unbound/unbound-setup.conf`, written as the
   anchor is: `interface: 0.0.0.0`, and `::0` with `do-ip6: yes` while
   `/proc/net/if_inet6` exists; for each zone `domain-insecure` and
   `local-zone ... nodefault`, then a `forward-zone` to every server.
4. **Logging**: one console line for the anchor, seeded or kept, and one
   for the include, naming the zones and servers, or why it failed.

## Drawbacks

- A lost `/data` reseeds the anchor from the image, which is only as
  current as the image: an image older than a completed root key
  rollover would fail to validate until updated.
- Every zone shares one set of servers.

## Alternatives Considered

### unbound-anchor before each start
It needs a resolver and the network before Unbound runs to give them,
and trusts what it fetches by a certificate; the image already carries
the keys, verified with the rest of it.

### A static `trust-anchor-file`
Unbound would never follow a rollover; the image would have to.

### A list of zone@address strings
A `string` list cannot be rendered as `env`, and the program would parse
what service-config's typed lists already check.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A setting that adds a directive | Only typed hostnames and addresses, checked again for characters Unbound's syntax uses. |
| An anchor an attacker planted | Only the unbound user writes `/data/svc/unbound`; the image's copy is verified with the root. |
| A half-written file | Temporary file, synced, renamed. |

## Reliability Considerations

- **No state** but the anchor; the include is rewritten at every start.
- **Tested** by its unit tests, and by `make check-unbound`, which boots
  with two forward zones and reads what it wrote.
