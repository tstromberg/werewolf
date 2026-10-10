# Nextcloud

Files, calendars and contacts for a household: [Nextcloud](https://nextcloud.com) 35, with PostgreSQL, Valkey and Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >admin-password
howl create cloud --with nextcloud --on lima \
	--base-url https://cloud.home.arpa --admin alice \
	--admin-password admin-password
```

Sign in as `alice`. The first start installs Nextcloud before the site answers. Phone and desktop apps use the same URL; calendars and contacts are at `/.well-known`.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
howl create cloud --with nextcloud --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://cloud.example.com --admin alice \
	--admin-password admin-password --admin-email alice@example.com
```

Point the name at the machine. Nobody else can sign up: add people under Accounts. `--phone-region` is an ISO country code, for numbers written without one. Change the password in Nextcloud; a later start does not reset it.

### Known Quirks

- The web installer is not in the image, and the web updater is off. A new Nextcloud arrives with the machine's next image.
- Apps from the app store install into `/data`. One that brings its own program does not run, because `/data` cannot execute files.
- Background jobs run every five minutes. You do not start them.
- Files live in `/data/svc/nextcloud`. The code does not.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Nextcloud may fetch from public ports 80, 443, 465 and 587. PostgreSQL and Valkey are not on the network.

### Security Weaknesses

- PHP runs Nextcloud, and PostgreSQL may compile a query. Both are named in `form.yaml`.
