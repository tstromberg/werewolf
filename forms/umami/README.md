# Umami

Web analytics without cookies: [Umami](https://umami.is) 3.4, with PostgreSQL and Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 32 >app-secret
htpasswd -nBC 10 admin | cut -d: -f2 >admin-hash
howl create stats --with umami --on lima \
	--domain stats.home.arpa --app-secret app-secret --admin-hash admin-hash
```

`htpasswd` asks for the password. Sign in at `https://stats.home.arpa` as `admin`.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 32 >app-secret
htpasswd -nBC 10 admin | cut -d: -f2 >admin-hash
howl create stats --with umami --on gcp --allow-from 0.0.0.0/0 \
	--domain stats.example.com --app-secret app-secret --admin-hash admin-hash
```

Point the name at the machine, add a site, and put the script Umami shows you on its pages. The tracker and the collector are public. Statistics are not.

### Known Quirks

- Umami's first migration would create `admin` / `umami`. This form replaces that password with your hash before anything is served, and again on every start.
- Change the password by replacing `admin-hash` and running create again.
- Keep `app-secret`. It signs logins.
- The tables are in the schema `umami` of PostgreSQL, on `/data`.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Umami and PostgreSQL are on loopback. Nothing else leaves the machine.

### Security Weaknesses

- Node and PostgreSQL may compile as they run. Named in `form.yaml`.
