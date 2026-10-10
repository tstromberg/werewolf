# Immich

A photo and video library, with the phone apps: [Immich](https://immich.app) 3, from the image the project publishes, with PostgreSQL, Valkey and Caddy. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- Node and PostgreSQL may compile as they run. Named in `form.yaml`. The image's shell is not started.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
howl create immich --with immich \
	--base-url https://photos.home.arpa --admin-email me@example.com \
	--admin-password admin-password
```

Open `https://photos.home.arpa` and sign in as `me@example.com`. The password is in `admin-password`, 12 to 72 characters. The first start builds tables and loads place names before Caddy opens. The phone app uses the same URL. Libraries and albums are in [Immich's documentation](https://docs.immich.app/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
howl create immich --with immich --on gcp --allow-from me \
	--base-url https://photos.example.com --admin-email me@example.com \
	--admin-name 'Your Name' --admin-password admin-password
```

Sign in at `https://photos.example.com`. The library, thumbnails and nightly database dumps are in `/data/svc/immich`.

### Migrating data in

PostgreSQL has no TCP port. `--import` attaches a directory of SQL. It is applied once, in the `postgres` database, while the cluster is first made. See [postgresql](../postgresql/README.md). `CREATE DATABASE` is not available there. The same directory may hold `dump.rdb` for Valkey. A cloud cannot attach the disk.

```sh
howl create immich --with immich --import ./dump
```

Files the application stores itself are not on that disk. Bring those through the service after it is up.

### Known Quirks

- There is no sign-up page. The administrator is made from the config, and adds everyone else.
- Version checks, telemetry and machine learning are off. Face recognition is not in this form.
- Search uses pgvector, which Immich accepts in place of VectorChord.
- Immich 4 would be a change to this form. A 3.x release follows the next image.
- The image is large. Give the machine several gigabytes.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Immich, PostgreSQL and Valkey are on loopback. Nothing is fetched for a user.
