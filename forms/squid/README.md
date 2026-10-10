# Squid

The `squid` form is an egress proxy: Squid 7 on :3128, on one leash,
taking clients from the networks you name and tunnelling them to port 443
of the domains you name, and nothing else: no plain HTTP, no cache, no
cache manager, no helpers ([design/corporate.md](../../docs/design/corporate.md)).

## Run your own

```sh
howl create egress --with squid --on gcp --allow-from 10.128.0.0/9 \
	--networks 10.128.0.0/9 \
	--domains .github.com --domains .githubusercontent.com --domains pypi.org
```

Clients set `HTTPS_PROXY=http://ADDRESS:3128`. Squid answers a CONNECT to
a listed name's port 443 with `200 Connection established` and passes the
TLS through unread; anything else gets its 403.

| Flag | |
| --- | --- |
| `--networks CIDR,...` | required. Up to 32: the clients Squid serves, besides the machine itself |
| `--domains NAME` | required, once a name, up to 32. `pypi.org` is that host alone; `.github.com` is github.com and every name beneath it. A whole top-level domain (`.com`) is refused |

To change a running machine's lists, run its create line again: howl
replaces its config and restarts it.

## How it is held

- **squid-setup first.** [cmd/squid-setup](cmd/squid-setup/README.md)
  writes `/run/svc/squid/networks` and `/run/svc/squid/domains` from the
  settings; [/etc/squid.conf](rootfs/etc/squid.conf), in the image, is
  the policy, and names them.
- **CONNECT to 443 alone.** Plain HTTP, other methods and other ports are
  refused: no mail out on 25, no FTP, no gopher.
- **Names, not addresses.** `dstdomain -n`: a CONNECT to an address is
  never matched by its reverse DNS, which whoever holds it writes.
- **Public addresses alone.** fence lets Squid reach port 443 only at
  public addresses (`tcp/443 public`), so a listed name that resolves
  inward (DNS rebinding, a cloud's metadata name) reaches nothing.
- **No cache manager**, from anywhere, this machine included; no ICP,
  HTCP or SNMP port; no cache in memory or on disk.
- **Nothing told of the client**: `via off`, `forwarded_for delete`, and
  error pages without Squid's version.
- **One process.** `-N`, no workers, no helpers (Squid's perl and sh
  helpers are pruned), no IPC sockets; no `exec` in its pledge. It runs
  as the squid user from the start, so it never switches users. Squid 7
  keeps one shared-memory queue even so, in `/dev/shm`.

## Drawbacks

- **No access log.** Squid opens its log by path; `/dev/stdout` is
  runsv's pipe, root's, which the squid user cannot open again, and the
  console would not carry every request anyway. Errors reach the console
  (`-d 1`); requests do not.
- **A name, not what flows.** Squid reads the CONNECT's name, not the TLS
  inside it: a client can tunnel to a listed host and name another in
  its SNI (domain fronting), where a CDN serves both.
- **32 networks and 32 domains**, settings' limit: list domains with a
  leading dot rather than hosts one by one.
- **Clients unauthenticated**: a listed network is trusted whole.
- Squid logs at each start that IPv6 is off, as werewolf leaves it.

## Checked

`make check-squid` boots it with its test config ([test/config](test/config)):
`.example.com`, `pypi.org` and `localhost` listed, and 127.0.0.2 standing
in for a client network. A CONNECT to a listed name, from the machine and
from that network, is Squid's to make (200 online, 503 offline, never
403); one to `localhost` is allowed and then refused by fence; Squid's
only UDP socket is its resolver's. Refused with 403: an unlisted name, a
listed host's subdomain, port 25, an address whose reverse DNS is listed,
plain HTTP, a client from 127.0.0.3, and the cache manager.
`make check-shellfree-squid` boots it as it ships, with no config: its
settings are refused for want of networks, and Squid stays down,
binding nothing.
