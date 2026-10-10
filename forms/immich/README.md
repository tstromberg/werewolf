# Immich

The `immich` form is `prod` with Immich 3.3, a photo and video library
with apps for phones, from the image its project publishes, and with
PostgreSQL, Valkey and Caddy beside it.

| | |
| --- | --- |
| Listens | tcp/443 and tcp/80, Caddy's; Immich on loopback behind it |
| Sends | nothing: no version check, no machine learning, no telemetry |
| Runs as | `_oci-immich` in its image, leashed; `postgres`, `valkey` and `caddy` beside it |
| Keeps | the library, thumbnails, video encodings and nightly database dumps in `/data/svc/immich`; its tables in PostgreSQL |
| Config | `caddy/admin-password` (12 to 72 characters); settings `admin-email` (required), `admin-name`, `base-url` (the site's https URL) |

```sh
openssl rand -base64 24 >admin-password      # you sign in with it; keep it
howl create photos --with immich --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://photos.example.com --admin-email me@example.com \
	--admin-password admin-password
```

Point `photos.example.com` at the address howl prints, and sign in at
`https://photos.example.com`, or in Immich's app, as `me@example.com`.
The first start takes a few minutes: Immich makes its tables and loads
its place names before Caddy opens.

## The image

`ghcr.io/immich-app/immich-server:v3`, as Immich builds it, pinned by
digest when the image is built and baked into the verified root at
`/oci/immich` ([docs/design/oci.md](../../docs/design/oci.md)): the
machine pulls nothing. A new Immich 3 release reaches the machine with
the next image; Immich 4 is a change to [form.yaml](form.yaml).
Its entrypoint is a bash script, so the service runs `node` itself; the
image's shell and the rest of its userland never run. The leash lets it
run `node` (its API and workers), `ffmpeg` and `ffprobe`, and `pg_dump`
and `gzip` for its backups, and nothing else.

PostgreSQL is Wolfi's 17 with `pgvector`, which Immich takes in place of
VectorChord (`DB_VECTOR_EXTENSION=pgvector`). As the image cannot reach
UNIX sockets outside it, PostgreSQL and Valkey also listen on loopback,
where only Immich's leash may connect: PostgreSQL lets the role `immich`
in there without a password ([pg_hba.conf](rootfs/usr/share/werewolf-immich/pg_hba.conf)),
the port standing in for the peer check a socket would make. Immich owns
the `postgres` database, as its migrations set the database's
`search_path`; a form beside it keeps its tables in a schema of its own.

## Defaults

- **Nobody claims it.** Before Caddy opens, `immich-setup`
  ([cmd/immich-setup](cmd/immich-setup/immich-setup.zig)) waits for
  Immich on loopback, makes the admin from the config, sets the defaults
  below and records that it is done, once. Caddy refuses Immich's admin
  sign-up for good. Without the config, Caddy stays down. The admin adds
  each user; there is no public sign-up in Immich.
- **Nothing leaves the machine.** No version check (the machine's
  updater brings new Immich), no machine learning (this form runs no
  model), and fence lets Immich reach PostgreSQL and Valkey and nothing
  else, so smart search, faces, mail and OAuth wait for a form of your
  own.
  Places come from the geodata in the image. The map's tiles are fetched
  by the viewer's browser from Immich's tile server; the admin may turn
  the map off.
- **Settings stay the admin's.** The defaults are set once through
  Immich's API, not locked in a file: the admin may change them.
- A nightly `pg_dump` into `/data/svc/immich/backups`, as Immich ships it.

## Checked

`make check-immich` runs [test/checks](test/checks): Caddy answers once
setup is done; Immich runs as `_oci-immich` with no capabilities; the
admin is the config's and the defaults are set; a photo uploads, its
EXIF is read and its thumbnail made; the library is Immich's; fence
lets it reach its database and queue alone; and a stranger's admin
sign-up is refused through Caddy and on loopback, leaving one user. `make
check-shellfree-immich` boots it as it ships, without a config, and
finds Caddy down, waiting for one.
