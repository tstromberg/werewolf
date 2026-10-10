# adguard-home

The `adguard-home` form is `prod` with AdGuard Home 0.107, a DNS
resolver that blocks ads and trackers for a home or office network, and
its web UI behind Caddy, which serves it over HTTPS for your domain to
the one user you name.

| | |
| --- | --- |
| Listens | udp/53 and tcp/53; tcp/80 and tcp/443, Caddy's; the UI on loopback alone |
| Sends | DNS-over-TLS to Quad9 and Cloudflare (tcp/853), plain DNS to find them (udp/53), its lists over HTTPS (tcp/443), all to public addresses alone; Caddy's ACME requests |
| Runs as | `_oci-adguard-home` in AdGuard Home's own image, and `caddy`, each leashed |
| Keeps | its configuration, lists and counts in `/data/svc/adguard-home` |
| Config | `caddy/admin-hash`, a bcrypt hash (`htpasswd -nbBC 10 '' PASSWORD`, without the colon); settings `domain` and `admin` (both required), `upstreams` and `blocklists` (lists, each optional) |

## Run your own

```sh
htpasswd -nbBC 10 '' 'a long password' | tr -d ':\n' >admin-hash
howl create dns --with adguard-home --on proxmox \
	--domain dns.example.com --admin me --admin-hash admin-hash
```

Point `dns.example.com` at the machine, open it, and sign in. Give its
address to your router's DHCP server as the DNS server.

## Defaults

- **No setup wizard.** Before its first start, `adguard-home-setup`
  copies a working configuration to `/data`, so AdGuard Home never asks
  a first visitor to set it up. From then on it is AdGuard Home's: its
  UI changes it, and a new image keeps it.
- **Upstreams and blocklists are settings**, where you give them:
  `--upstreams tls://dns.quad9.net --blocklists URL`, each repeated for
  more, replace the configuration's at every start, and the UI's
  changes to those two until the next. What no setting names is the
  UI's alone.
- **The UI behind a login.** Caddy lets through the one user the config
  names; AdGuard Home serves the UI on loopback alone.
- **Upstreams over TLS**: Quad9 and Cloudflare, load-balanced, with
  DNSSEC checked; plain DNS only to learn their addresses.
- **Not an open resolver.** Clients outside the private networks (10/8,
  172.16/12, 192.168/16, 100.64/10, link-local, loopback, ULA) are
  refused; the rest are held to 20 queries a second each.
- **No query log**; counts alone. No WHOIS or reverse lookups of
  clients, no DHCP server, no update checks.
- **AdGuard Home's own image**, `latest`, pinned by digest at each
  build, in a tree of its own ([oci.md](../../docs/design/oci.md)).
  Nothing in it runs but AdGuard Home, and its pledge has no `exec`.

## Drawbacks

- An upstream or list on another port than 853, 53 or 443 is refused
  by fence: a form of your own adds its port to the service's `connect`.
- AdGuard Home's own login is unused: a session is Caddy's basic auth,
  sent with each request.
- Settings in the UI that open ports (DHCP, encrypted DNS, the UI on
  another address) fail: fence and the leash allow only the ports above.

## Checked

`make check-adguard-home` boots it with its test config: AdGuard Home
runs as its own user with only the low port's capability; nothing but
the form's helper runs before it; the configuration on `/data` is the
one AdGuard Home wrote back, with the settings' upstream and blocklist; `example.org`
resolves; `ad.doubleclick.net` is blocked; Caddy refuses a stranger and
a wrong password and lets the admin in; there is no setup wizard to
finish; strangers are refused; and root, holding :53 after AdGuard Home
stops, cannot answer a client from it. `make check-shellfree-adguard-home`
boots it as it ships: the helper copies the first configuration,
AdGuard Home serves DNS, and Caddy parks for its missing password.
