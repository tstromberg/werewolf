# Pi-hole

DNS for a home network that answers ad and tracker names with `0.0.0.0`: [Pi-hole](https://pi-hole.net), from its own image, the web interface behind Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
printf %s 'a long password' >password
howl create dns --with pi-hole --on lima --password password \
	--domain dns.home.arpa
```

Open `https://dns.home.arpa/admin/` and sign in with that password. Point one device at the machine for DNS before you point the whole house at it.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
printf %s 'a long password' >password
howl create dns --with pi-hole --on proxmox --password password \
	--domain dns.home.example
```

Give the machine's address to the router's DHCP as the DNS server. Keep it on the home network or a tailnet. Do not publish port 53 on the internet: Pi-hole answers only the machine's own networks, but the port is still reachable.

Upstreams, lists and local names are changed in the web interface and kept on `/data`. The password and the local-only mode are not: those come from the config.

### Known Quirks

- Quad9 (9.9.9.9 and 149.112.112.112) and Steven Black's list are set on the first start.
- Lists refresh when the machine starts, if they are missing or older than a week. A failed fetch keeps the old lists.
- The web interface's Update Gravity button does not work: that button runs a script, and this service runs programs from a fixed list. Restart with `sv restart pi-hole`, or wait for the next boot.
- DHCP and NTP are off.
- Shared memory lives on `/data`, because an image service has no tmpfs of its own.

### Network Exposure

- udp/53 and tcp/53, Pi-hole. tcp/80 and tcp/443, Caddy. The web interface is on loopback.

### Security Weaknesses

- Refreshing the lists runs bash, curl and coreutils from the image, as the Pi-hole user. pihole-FTL itself is one program. The host image has no shell.
