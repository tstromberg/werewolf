# Moodle

Courses for a school or a university: [Moodle](https://moodle.org) 5.3, the long-term release, with PostgreSQL and Caddy.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 24 >admin-password
howl create courses --with moodle --on lima \
	--base-url https://courses.home.arpa --admin alice \
	--admin-email alice@example.edu --admin-password admin-password
```

Open `https://courses.home.arpa` once the name points at the machine, and sign in as `alice`. The first start builds about 500 tables, so the site is quiet for a few minutes. Caddy's own CA signs names under `.home.arpa`.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 24 >admin-password
howl create courses --with moodle --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://courses.example.edu --admin alice \
	--admin-email alice@example.edu --admin-password admin-password
```

Point `courses.example.edu` at the address howl prints. Add `--smtp HOST:PORT`, `--smtp-user`, `--smtp-password` and `--mail-from` when you want mail. `--site-name` defaults to Moodle. Change the password in Moodle afterwards; a later start does not reset it.

### Known Quirks

- Nobody can sign up, and there is no guest. The web installer is refused.
- Plugins and themes come with the image. The web cannot install one.
- No path to a program can be set from the web, so no LaTeX filter and no antivirus scan until a form of your own adds one.
- There is no LDAP or SAML package in the image. Use Keycloak in front, or add `php-8.4-ldap` in a form of your own.
- Wolfi does not ship Moodle, so a new release is this form's recipe to bump.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Moodle and PostgreSQL are not on the network.

### Security Weaknesses

- PHP runs Moodle, and PostgreSQL may compile a query. Both are named in `form.yaml`.
