# Umami - Hardened VM

Web analytics without cookies: [Umami](https://umami.is) 3.4, with PostgreSQL and Caddy.
The form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/umami/index.html).

## Security Posture

- The service runs as its own user, held to the files and ports its manifest names. The
  root is read-only. `/data` is what survives.

### Weaknesses

- Node and PostgreSQL may compile as they run. Named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 32 >app-secret
openssl rand -base64 18 >admin-password
htpasswd -nbBC 10 admin "$(cat admin-password)" | cut -d: -f2 >admin-hash
howl create umami --with umami \
	--domain stats.home.arpa --app-secret app-secret --admin-hash admin-hash
```

Open `https://stats.home.arpa` and sign in as `admin`. The password is in
`admin-password`. Sites and the tracking script are in [Umami's
documentation](https://umami.is/docs).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 32 >app-secret
openssl rand -base64 18 >admin-password
htpasswd -nbBC 10 admin "$(cat admin-password)" | cut -d: -f2 >admin-hash
howl create umami --with umami --on gcp --allow-from me \
	--domain stats.example.com --app-secret app-secret --admin-hash admin-hash
```

Sign in at `https://stats.example.com`, add a site, and put the script Umami shows you
on its pages. The tracker and the collector are public. Statistics are not.

### Importing data

PostgreSQL has no TCP port. `--import` attaches a directory of SQL. It is applied once,
in the `postgres` database, while the cluster is first made. See
[postgresql](../postgresql/README.md). `CREATE DATABASE` is not available there. A cloud
cannot attach the disk.

```sh
howl create umami --with umami --import ./dump
```

Files the application stores itself are not on that disk. Bring those through the
service after it is up.

### Known Quirks

- Umami's first migration would create `admin` / `umami`. This form replaces that
  password with your hash before anything is served, and again on every start.
- Change the password by replacing `admin-hash` and running create again.
- Keep `app-secret`. It signs logins.
- The tables are in the schema `umami` of PostgreSQL, on `/data`.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
