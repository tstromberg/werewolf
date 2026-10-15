# Miniflux - Hardened VM

[Miniflux](https://miniflux.app) reads feeds, with PostgreSQL and Caddy. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download instructions](https://dist.werewolf-linux.org/images/v1/miniflux/index.html).

## Security Posture

- Miniflux, Caddy, and PostgreSQL run as their own users. The root is read-only.
- PostgreSQL is on a UNIX socket. The host cannot reach it.
- The admin is created once, when the database is new.

### Weaknesses

- PostgreSQL compiles costly queries to machine code with LLVM.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >admin-password
howl create miniflux --with miniflux \
	--base-url https://feeds.home.arpa --admin alice --admin-password admin-password
```

Open `https://feeds.home.arpa` and sign in as that admin. Adding a feed is in [Miniflux's documentation](https://miniflux.app/docs/user.html).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
howl create miniflux --with miniflux --on gcp --allow-from me \
	--base-url https://feeds.example.com --admin alice --admin-password admin-password
```

`--allow-from me` admits your address to ports 80 and 443. Point the name at the machine.

### Importing data

`--import` streams `*.sql` into the `postgres` database once, while data is first made. `CREATE DATABASE` is not available. A cloud cannot attach the disk.

```sh
openssl rand -base64 24 >admin-password
howl create miniflux --with miniflux --import ./dump \
	--base-url https://feeds.home.arpa --admin alice --admin-password admin-password
```

### Known Quirks

- The base URL is stored. Changing it later is a setting in the database, not a new flag.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
