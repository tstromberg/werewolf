# Mattermost

Team chat: [Mattermost](https://mattermost.com) Team Edition 11.7, the extended-support release, with PostgreSQL and Caddy. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- PostgreSQL may compile a query. Named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
howl create mattermost --with mattermost \
	--base-url https://chat.home.arpa --admin alice \
	--admin-email alice@example.com --admin-password admin-password
```

Open `https://chat.home.arpa` and sign in as `alice`. The password is in `admin-password`. The first start migrates the database, so give it a few minutes. Teams and channels are in [Mattermost's documentation](https://docs.mattermost.com/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
howl create mattermost --with mattermost --on gcp --allow-from me \
	--base-url https://chat.example.com --admin alice \
	--admin-email alice@example.com --admin-password admin-password
```

Sign in at `https://chat.example.com`. Point the name at the machine with an A record. Invite people with the team's link. Mail is off until you set SMTP in System Console. `--admin` is 3 to 22 characters. The password is 12 to 72 bytes.

### Migrating data in

PostgreSQL has no TCP port. `--import` attaches a directory of SQL. It is applied once, in the `postgres` database, while the cluster is first made. See [postgresql](../postgresql/README.md). `CREATE DATABASE` is not available there. A cloud cannot attach the disk.

```sh
howl create mattermost --with mattermost --import ./dump
```

Files the application stores itself are not on that disk. Bring those through the service after it is up.

### Known Quirks

- Open sign-up is off. A stranger needs an invitation.
- Plugin uploads are off. A plugin is code.
- The admin is created before Caddy opens the port. A later start does not reset the password.
- Wolfi's Mattermost package lags upstream. This form runs the image's 11.7 line.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Mattermost and PostgreSQL are on loopback. Mattermost may call public addresses on 443.
