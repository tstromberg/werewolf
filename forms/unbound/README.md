# Unbound

The `unbound` form resolves names for the private networks around it:
Unbound 1.25, recursive and validating, on one leash, answering loopback,
RFC 1918, 100.64/10, link-local and IPv6's unique local addresses, and
refusing everyone else ([design/service-forms.md](../../docs/design/service-forms.md)).

## Run your own

```sh
howl create dns --with unbound --on gcp --allow-from 10.128.0.0/9
```

Point the machines on your network at its address. Your own private
zones go to the servers that hold them, the rest is resolved from the
root:

```sh
howl create dns --with unbound --on aws --allow-from 10.0.0.0/8 \
	--forward-zones corp.example,10.in-addr.arpa --forward-to 10.0.0.2
```

| Flag | |
| --- | --- |
| `--forward-zones ZONE,...` | up to 32 zones, such as a cloud's private zones or your directory's, answered by the servers below and not from the root; each is taken as unsigned |
| `--forward-to ADDRESS,...` | up to 32 literal addresses of the servers that answer for every one of those zones, on port 53; needed with `--forward-zones` |

A cloud's resolver for its private zones is AWS's VPC network plus two
(10.0.0.2 above), GCP's 169.254.169.254 and Azure's 168.63.129.16. To
change a running machine's zones, run its create line again: howl
replaces its config and restarts it.

## How it is held

- **No open resolver.** `access-control` refuses every address but the
  private ranges, with a REFUSED answer, so the machine amplifies no
  attack even where `--allow-from` lets the world reach :53. Answers stay
  within 1232 bytes, and `ANY` is not answered in full.
- **Internal names in public DNS resolve.** No `private-address`: a name
  in a public zone may point at a private address, as split-horizon
  setups and clouds' load balancers do.
- **Validating from the first start.** unbound-setup
  ([cmd/unbound-setup](cmd/unbound-setup/README.md)) seeds
  `/data/svc/unbound/root.key` from the image's root keys (Wolfi's
  `dnssec-root`, KSK-2017 and KSK-2024), and Unbound follows the root's
  rollovers in it from then on (RFC 5011). `unbound-anchor` would need the
  network before Unbound had it.
- **Nothing to control it by.** `control-enable: no`, and the control
  client and its key maker pruned: a new configuration is a restart.
- **leash does the rest.** No chroot or user change of its own: leash
  starts it as `unbound`, binding :53 with the one capability a low port
  needs, in a pledge without `exec`, writing only `/data/svc/unbound`.
  fence lets it reach port 53 alone.
- **Its scripts pruned.** Unbound depends on bash for
  `unbound-control-setup`, a shell script; the image leaves out both,
  `unbound-anchor`, `unbound-host` and `unbound-checkconf`.
- **Its own limits.** One thread, 96 MiB of caches, under leash's 256.

## Drawbacks

- One set of servers answers for every forward zone: a zone with servers
  of its own needs a form on `base: unbound`.
- A forward zone under one of Unbound's default local zones (a part of
  `10.in-addr.arpa`) needs that whole zone forwarded instead.
- IPv6 only where the form allows it (`allow: [ipv6]`); unbound-setup
  listens on `::0` when the kernel has it.
- fence holds UDP :53 by its routing rules alone
  ([listen-udp.md](../../docs/design/listen-udp.md)): while Unbound
  restarts, another low-port service could take the port, and hear but
  not answer queries.
- No DNS over TLS or HTTPS, and no cache shared between machines.

## Checked

`make check-unbound` boots it with its test config ([test/config](test/config)),
offline, with two forward zones. `localhost` resolves by UDP and TCP, on
loopback and on the machine's own address; unbound-setup wrote the zones,
each insecure and its default local zone dropped; the trust anchor holds
the root's two keys, 0600, Unbound's own; there is no control socket, and
no shell. The attack, a query from a public address, cannot be sent
there: every address the check machine has is private, and root holds no
`CAP_NET_ADMIN` or `CAP_NET_RAW` to add or forge another. So the check
reads the policy Unbound runs with: every address refused, the private
ranges alone allowed, and nothing else setting `access-control`.
`make check-shellfree-unbound` boots it as it ships, with no config:
unbound-setup seeds the anchor, and Unbound loads its validator and serves.
