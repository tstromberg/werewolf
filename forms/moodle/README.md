# Moodle

Courses for a school or a university: [Moodle](https://moodle.org) 5.3, the long-term release, with PostgreSQL and Caddy. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- PHP runs Moodle, and PostgreSQL may compile a query. Both are named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
howl create moodle --with moodle \
	--base-url https://courses.home.arpa --admin alice \
	--admin-email alice@example.edu --admin-password admin-password
```

Open `https://courses.home.arpa` and sign in as `alice`. The password is in `admin-password`. The first start builds about 500 tables, so the site is quiet for a few minutes. Caddy's own CA signs names under `.home.arpa`. Courses are in [Moodle's documentation](https://docs.moodle.org/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
howl create moodle --with moodle --on gcp --allow-from me \
	--base-url https://courses.example.edu --admin alice \
	--admin-email alice@example.edu --admin-password admin-password
```

Sign in at `https://courses.example.edu`. Add `--smtp HOST:PORT`, `--smtp-user`, `--smtp-password` and `--mail-from` when you want mail. `--site-name` defaults to Moodle. Change the password in Moodle afterwards; a later start does not reset it.

### Migrating data in

PostgreSQL has no TCP port. `--import` attaches a directory of SQL. It is applied once, in the `postgres` database, while the cluster is first made. See [postgresql](../postgresql/README.md). `CREATE DATABASE` is not available there. A cloud cannot attach the disk.

```sh
howl create moodle --with moodle --import ./dump
```

Files the application stores itself are not on that disk. Bring those through the service after it is up.

### Known Quirks

- Nobody can sign up, and there is no guest. The web installer is refused.
- Plugins and themes come with the image. The web cannot install one.
- No path to a program can be set from the web, so no LaTeX filter and no antivirus scan until a form of your own adds one.
- There is no LDAP or SAML package in the image. Use Keycloak in front, or add `php-8.4-ldap` in a form of your own.
- Wolfi does not ship Moodle, so a new release is this form's recipe to bump.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Moodle and PostgreSQL are not on the network.
