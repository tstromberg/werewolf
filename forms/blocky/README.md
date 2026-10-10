# blocky

The `blocky` form is `prod` with Blocky 0.35, a DNS resolver that blocks
ads and trackers for a home or office network: point the network's DHCP
at the machine for DNS, and every device on it is covered.

| | |
| --- | --- |
| Listens | udp/53 and tcp/53 |
| Sends | DNS-over-TLS to Quad9 and Cloudflare (tcp/853), and its blocklist over HTTPS (tcp/443), to public addresses alone |
| Runs as | `_oci-blocky` in Blocky's own image, leashed |
| Keeps | nothing: lists and cache are in memory, fetched again at boot |
| Config | none needed; settings `upstreams` and `blocklists` (lists, each optional) replace the configuration's ([rootfs/oci/blocky/app/blocky.json](rootfs/oci/blocky/app/blocky.json)) |

## Run your own

```sh
howl create dns --with blocky --on proxmox
```

Give the address howl prints to your router's DHCP server as the DNS
server, or set it on one device first to try it. On a cloud, put the
machine on the private network your devices reach it by (a tailnet, a
VPN); never give it a public address in place of that, as below.

## Defaults

- **Upstreams over TLS alone**: Quad9 and Cloudflare, the fastest
  answering, whose own names Blocky resolves over TLS from addresses in
  its configuration. fence lets Blocky send nothing in plain DNS.
- **One blocklist**: Steven Black's hosts list (about 75,000 names),
  fetched at start and every day after. DNS answers at once; blocking
  begins when the list is in. A blocked name answers 0.0.0.0.
- **Not an open resolver.** Blocky has no access list, so its
  configuration gives every client outside the private networks
  (10/8, 172.16/12, 192.168/16, 100.64/10, link-local, loopback, ULA) a
  group that blocks every name, before any upstream is asked, and holds
  it to 5 queries a second. A stranger gets 0.0.0.0, never an answer.
- **No query log**, and its own log hides client addresses and names.
- **No HTTP API**, metrics or DNS-over-HTTPS server: nothing but DNS
  listens.
- **Blocky's own image**, `latest`, pinned by digest at each build, so
  a new image follows each Blocky release, in a tree of its own
  ([oci.md](../../docs/design/oci.md)). It holds one program and no
  shell. Its configuration is rendered at each start, into the service's
  own directory, from the image's and the settings.

## Changing it

```sh
howl create dns --with blocky --on proxmox \
	--upstreams tcp-tls:dns.mullvad.net \
	--blocklists https://example.org/list.txt \
	--blocklists https://example.org/other.txt
```

A list is a repeated flag. Each replaces the configuration's list
whole, at the next start; an upstream is in [Blocky's
syntax](https://0xerr0r.github.io/blocky/), over TLS (`tcp-tls:` or
`https:`), as fence lets Blocky send nothing else. For more, a form of your own, on `blocky`, lays its own
`blocky.json` at `rootfs/oci/blocky/app/blocky.json`, keeping the
`clientGroupsBlock` that refuses strangers.

## Drawbacks

- The lists come again at every boot: until they do, nothing is
  blocked.
- `fence` cannot yet take a listen from private addresses alone, so a
  machine with a public address on :53 answers strangers, blocked and
  slowly; prefer a private network.

## Checked

`make check-blocky` boots it: Blocky runs as its own user with only the
low port's capability; `example.org` resolves through the upstreams;
`ad.doubleclick.net`, on the list, answers 0.0.0.0; fence has no plain
DNS line for Blocky's user; the configuration it runs has the test
config's upstream and blocklist in place of its own, and blocks every name
for strangers; and root, holding :53 after Blocky stops, as a
broken-into service could, cannot answer a client from it (fence lets
only Blocky's user send from the port). `make check-shellfree-blocky`
boots it as it ships.
