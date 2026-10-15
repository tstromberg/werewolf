# AdGuard Home - Hardened VM

DNS for a home network, with a web interface: [AdGuard
Home](https://adguard.com/adguard-home.html) 0.107, from its own image, behind Caddy.
The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/adguard-home/index.html).

## Security Posture

- The service runs as its own user, held to the files and ports its manifest names. The
  root is read-only. `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
htpasswd -nbBC 10 '' "$(cat admin-password)" | tr -d ':\n' >admin-hash
howl create adguard-home --with adguard-home \
	--domain dns.home.arpa --admin me --admin-hash admin-hash
```

Open `https://dns.home.arpa` and sign in as `me`. The password is the line in
`admin-password`. Point that name at the address howl prints, then point one device at
the machine for DNS. Caddy's own CA signs names under `.home.arpa`. Filters and clients
are in [AdGuard Home's getting
started](https://github.com/AdguardTeam/AdGuardHome/wiki/Getting-Started).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
htpasswd -nbBC 10 '' "$(cat admin-password)" | tr -d ':\n' >admin-hash
howl create adguard-home --with adguard-home --on gcp --allow-from me \
	--domain dns.example.com --admin me --admin-hash admin-hash
```

Sign in at `https://dns.example.com` as `me`. The password is the line in
`admin-password`. Point that name at the address howl prints. `--allow-from me` opens
the ports to the address you run this from. A house more often runs on Proxmox, on the
LAN the devices already use:

```text
howl create adguard-home --with adguard-home --on proxmox \
	--allow-from 192.168.0.0/16 --domain dns.home.arpa \
	--admin me --admin-hash admin-hash
```

Keep port 53 on that network. `--upstreams tls://dns.quad9.net` and `--blocklists URL`,
each repeated, replace the defaults, and a later start resets those two. Everything else
you change in the UI stays.

### Importing data

This machine starts empty. What it must remember is in the create command or `--config`.
There is no database to import.

### Known Quirks

- There is no setup wizard. The configuration is written before the first start.
- Defaults are Quad9 and Cloudflare over TLS, and one block list.
- Clients outside the private ranges are refused, so it is not an open resolver.
- DHCP is off.

### Network Exposure

- listen: udp/53 *
- listen: tcp/53 *
- listen: tcp/80 *
- listen: tcp/443 *
