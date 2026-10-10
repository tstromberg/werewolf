# Caddy - Hardened VM

A web server that gets its own certificates: [Caddy](https://caddyserver.com) 2.11. The form's manifest is [form.yaml](form.yaml). A form of your own includes this one and lays its site and Caddyfile over the image's.

## Security Posture

Caddy runs as its own user. There is no shell. Landlock and seccomp hold it to ports 80 and 443 and to `/data/svc/caddy`. The root is read-only.

- The admin API is off. The configuration is in the image, so there is nothing to reload.
- The placeholder site sends `X-Content-Type-Options: nosniff` and a strict referrer policy, and no `Server`.
- On-demand TLS needs an `ask` endpoint, so a stranger cannot make Caddy request certificates without limit.
- Protocols are HTTP/1 and HTTP/2. HTTP/3 waits until the firewall can serve UDP.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
howl create caddy --with caddy --domain www.home.arpa
```

Open `https://www.home.arpa`. A name under `.home.arpa`, `.local`, `.internal` or `.localhost` gets a certificate from Caddy's own CA. Without `--domain` the site is plain HTTP on port 80. The site is in [Caddy's documentation](https://caddyserver.com/docs/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
howl create caddy --with caddy --on gcp --allow-from me --domain www.example.com
```

Point the name at the address howl prints. Caddy gets a certificate from Let's Encrypt once the name resolves, and renews it. Certificates live in `/data/svc/caddy`.

### Migrating data in

This machine starts empty. The site and the Caddyfile are in the image. What differs per machine is `--domain`. There is no database to import.

### Known Quirks

- Timeouts are 10 seconds to read a header and 2 minutes idle. There is no body timeout, which would cut off an upload.
- HSTS is the site's to choose. It locks a name to HTTPS for months.
- Wolfi's Caddy is the standard build, with no plugins.

### Network Exposure

tcp/80 tcp/443
