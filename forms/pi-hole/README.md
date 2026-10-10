# pi-hole

The `pi-hole` form is `prod` with Pi-hole, network-wide ad blocking: the
DNS server for your network, which answers ad and tracker names with
`0.0.0.0`. Its web interface is behind Caddy, which serves it over HTTPS
for your domain.

| | |
| --- | --- |
| Listens | tcp/53 and udp/53, Pi-hole's; tcp/80 and tcp/443, Caddy's; the web interface on loopback alone |
| Sends | DNS to its upstreams; blocklists over HTTPS from public addresses; Caddy's ACME requests |
| Runs as | `_oci-pi-hole` in Pi-hole's own image, and `caddy`, each leashed |
| Keeps | its settings, lists and query history in `/data/svc/pi-hole` |
| Config | `pi-hole/password`, the web interface's password; setting `domain` (required) |

## Run your own

```sh
printf %s 'a long password' >password
howl create dns --with pi-hole --on lima --password password \
	--domain dns.home.example
```

Point your router's DHCP at the machine's address as the network's DNS
server, and open `https://dns.home.example/admin/`. Upstreams, lists,
local names and clients are set there and kept on `/data`.

## Defaults

- **Local networks only.** Pi-hole answers clients on the machine's own
  networks and refuses the rest (`dns.listeningMode LOCAL`), so it is
  never an open resolver, whatever the firewall in front says. The web
  interface cannot change this.
- **The password is the config's**, so no visitor sets it first, and the
  web interface cannot change it either.
- **Quad9 upstream** (9.9.9.9, 149.112.112.112), set once on the first
  start: no logs of who asked, and it refuses known malware domains.
- **StevenBlack's hosts list**, added on the first start.
- **No DHCP or NTP server**, and no clock sync: each would take more of
  the machine than DNS does.
- **Lists refreshed weekly, at a start.** Pi-hole's gravity script, under
  bash from the image, fetches them before pihole-FTL starts, when they
  are missing or older than a week; a failed fetch keeps the old lists,
  and Pi-hole starts anyway. werewolf reboots into each update.
- **No update checks.** werewolf updates the machine: each build pins
  Pi-hole's `latest` image by digest, so a new image follows each release.

## Drawbacks

- **bash.** Gravity is a bash script, so this form lets pihole-FTL's
  service run bash, curl and busybox's and coreutils' tools from the
  image, and pledge `exec`. pihole-FTL itself is one static program.
- The web interface's *Update Gravity* button fails: pihole-FTL runs the
  `pihole` script for it, and leash runs only ELF programs. Restart the
  service instead (`sv restart pi-hole`), or wait for the week.
- No refresh while the machine stays up for weeks: nothing in an image
  service runs on a timer yet.
- Shared memory is on `/data` (`/dev/shm`, bound from it), as image
  services get no tmpfs of their own.

## Checked

`make check-pi-hole` boots it with its test config ([test/config](test/config)),
domain `localhost`, for which Caddy's own CA signs: pihole-FTL answers
DNS as `_oci-pi-hole` with the one capability its port needs; the web
interface is served; the API refuses a stranger and a wrong password and
takes the config's; listening mode is LOCAL; a name on the deny list
answers `0.0.0.0`; and, with pihole-FTL stopped, a program that takes
udp/53 cannot answer from it. `make check-shellfree-pi-hole` boots it as
it ships, with no config: pihole-FTL and Caddy park, each saying why.
