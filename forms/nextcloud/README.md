# Nextcloud

Files, calendars and contacts for a household: [Nextcloud](https://nextcloud.com) 35, with PostgreSQL, Valkey and Caddy. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- PHP runs Nextcloud, and PostgreSQL may compile a query. Both are named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
howl create nextcloud --with nextcloud \
	--base-url https://cloud.home.arpa --admin alice \
	--admin-password admin-password
```

Open `https://cloud.home.arpa` and sign in as `alice`. The password is in `admin-password`. The first start installs Nextcloud before the site answers. Phone and desktop apps use the same URL. Clients are in [Nextcloud's documentation](https://docs.nextcloud.com/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
howl create nextcloud --with nextcloud --on gcp --allow-from me \
	--base-url https://cloud.example.com --admin alice \
	--admin-password admin-password --admin-email alice@example.com
```

Sign in at `https://cloud.example.com`. Nobody else can sign up: add people under Accounts. `--phone-region` is an ISO country code, for numbers written without one. Change the password in Nextcloud; a later start does not reset it.

### Migrating data in

PostgreSQL has no TCP port. `--import` attaches a directory of SQL. It is applied once, in the `postgres` database, while the cluster is first made. See [postgresql](../postgresql/README.md). `CREATE DATABASE` is not available there. The same directory may hold `dump.rdb` for Valkey. A cloud cannot attach the disk.

```sh
howl create nextcloud --with nextcloud --import ./dump
```

Files the application stores itself are not on that disk. Bring those through the service after it is up.

### Known Quirks

- The web installer is not in the image, and the web updater is off. A new Nextcloud arrives with the machine's next image.
- Apps from the app store install into `/data`. One that brings its own program does not run, because `/data` cannot execute files.
- Background jobs run every five minutes. You do not start them.
- Files live in `/data/svc/nextcloud`. The code does not.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Nextcloud may fetch from public ports 80, 443, 465 and 587. PostgreSQL and Valkey are not on the network.
