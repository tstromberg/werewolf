# squid-setup

## Summary

squid-setup writes the two lists the squid form's Squid reads, from the
machine's settings, before each start: the client networks and the
destination domains, one to a line.

## Background

Squid reads an ACL's values from a file named in quotes, one value to a
line (`acl clients src "/run/svc/squid/networks"`). service-config renders
settings as `env`, `json` or `conf` lines, none of which is that, and its
`conf` format cannot hold a string, which a domain with a leading dot is.
So the policy stays in the image's `/etc/squid.conf`, and this program
turns the settings into the two files it names.

## Goals

- Squid's configuration is the image's; the settings fill only two lists.
- Nothing reaches Squid but a network or a domain name.

## Non-Goals

- Checking the whole configuration: Squid does that at start, and says why.
- Ports, methods or the cache manager, which are the image's policy.

## Detailed design

leash runs it as the squid user, after service-config has written
`/run/svc/squid/site.json` from settings.json: `networks`, a list of
`cidr`, and `domains`, a list of `string`, both required. It writes
`/run/svc/squid/networks` and `/run/svc/squid/domains`, each through a
temporary file, synced and renamed, mode 0600.

A domain is a hostname (lib/settings.zig's `isHostname`), which matches
that host alone, or a dot and a hostname, which matches the domain and
its subdomains, as Squid's `dstdomain` reads it. A dot and one label
(`.com`) is refused: it would let clients reach a whole top-level domain.
A network may hold only a CIDR's characters, which service-config already
checked. Either refusal names the value and exits 1, which parks Squid.

It logs two lines: the client networks, and the domains Squid CONNECTs to.

## Drawbacks

- 32 values a list, settings' limit: a wider allowlist wants subdomains.

## Alternatives Considered

### A conf include
service-config's `conf` writes `KEY VALUE...`, a line Squid cannot take as
an ACL, and refuses strings.

### Two hostname lists, exact and with subdomains
Typed by lib/settings.zig alone, but not Squid's own notation.

## Security Considerations

| Risk | Mitigation |
| --- | --- |
| A setting that adds a directive | The files are ACL values, read by `acl ... "file"`, one to a line; a value is checked first. |
| A whole TLD allowed by mistake | A dot and one label is refused. |
| A forged console line | Control bytes print as `?`. |

## Reliability Considerations

- No state: both files are written again at every start, into a tmpfs.
- Tested by its unit tests, and by `make check-squid`, which boots the
  form with its test config.
