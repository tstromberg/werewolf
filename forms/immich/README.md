# Immich

A photo and video library, with the phone apps: [Immich](https://immich.app) 3, from the image the project publishes, with PostgreSQL, Valkey and Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >admin-password
howl create photos --with immich --on lima \
	--base-url https://photos.home.arpa --admin-email me@example.com \
	--admin-password admin-password
```

The first start takes a few minutes: Immich builds its tables and loads place names before Caddy opens. Then sign in on the site or in the app. The password is 12 to 72 characters.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
howl create photos --with immich --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://photos.example.com --admin-email me@example.com \
	--admin-name 'Your Name' --admin-password admin-password
```

Point the name at the machine. Give the phone app that URL. The library, thumbnails and nightly database dumps are in `/data/svc/immich`.

### Known Quirks

- There is no sign-up page. The administrator is made from the config, and adds everyone else.
- Version checks, telemetry and machine learning are off. Face recognition is not in this form.
- Search uses pgvector, which Immich accepts in place of VectorChord.
- Immich 4 would be a change to this form. A 3.x release follows the next image.
- The image is large. Give the machine several gigabytes.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Immich, PostgreSQL and Valkey are on loopback. Nothing is fetched for a user.

### Security Weaknesses

- Node and PostgreSQL may compile as they run. Named in `form.yaml`. The image's shell is not started.
