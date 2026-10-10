# AdGuard Home

DNS for a home network, with a web interface: [AdGuard Home](https://adguard.com/adguard-home.html) 0.107, from its own image, the interface behind Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
htpasswd -nbBC 10 '' 'a long password' | tr -d ':\n' >admin-hash
howl create dns --with adguard-home --on lima \
	--domain dns.home.arpa --admin me --admin-hash admin-hash
```

Open `https://dns.home.arpa` and sign in as `me`. Point one device at the machine for DNS first.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
htpasswd -nbBC 10 '' 'a long password' | tr -d ':\n' >admin-hash
howl create dns --with adguard-home --on proxmox \
	--domain dns.example.com --admin me --admin-hash admin-hash
```

Point the name at the machine and give its address to the router's DHCP. Keep port 53 on the home network. Replace the upstreams or the lists with `--upstreams tls://dns.quad9.net` and `--blocklists URL`, each repeated. Those two are reset from the flags at every start. Everything else you change in the UI stays.

### Known Quirks

- There is no setup wizard. The configuration is written before the first start.
- Defaults are Quad9 and Cloudflare over TLS, and one block list.
- Clients outside the private ranges are refused, so it is not an open resolver.
- DHCP is off.

### Network Exposure

- udp/53 and tcp/53, AdGuard Home. tcp/80 and tcp/443, Caddy, for the one user you named. The UI is on loopback.
