# Moodle

The `moodle` form is courses for a school or a university:
[Moodle](https://moodle.org) 5.3, the long-term release, with PostgreSQL
and its cron beside it and Caddy in front, serving HTTPS at your URL with
a certificate from Let's Encrypt, each part on a leash of its own
([design/academic.md](../../docs/design/academic.md)).

## Run your own

You need a domain name you can point at the machine.

```sh
openssl rand -base64 24 >admin-password      # you sign in with it; keep it
howl create courses --with moodle --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://courses.example.edu --admin alice \
	--admin-email alice@example.edu --admin-password admin-password
```

Point `courses.example.edu` at the address howl prints and sign in at
`https://courses.example.edu` as `alice`. Caddy gets the certificate once
the name resolves to the machine. The first start installs Moodle, some
500 tables: a few minutes before the site answers.

| Flag | |
| --- | --- |
| `--base-url URL` | required. Where Moodle is served: Caddy's site and Moodle's `wwwroot` |
| `--admin NAME` | the administrator, made on the first start; `admin` if not given |
| `--admin-password FILE` | required. Its password, never printed or logged |
| `--admin-email ADDRESS` | required. The administrator's address, and the site's support address |
| `--site-name NAME` | the site's name; `Moodle` if not given |
| `--smtp HOST:PORT`, `--smtp-user NAME`, `--smtp-password FILE`, `--mail-from ADDRESS` | the mail relay, over TLS (465 implicit, else STARTTLS); without it Moodle sends no mail |

Moodle is installed before it serves anything, so no visitor claims a
fresh machine, and its web installer is refused. A later start keeps the
administrator as it is: change its password in Moodle.

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; php-fpm's socket; the ACME CA |
| Moodle (php-fpm) | `moodle` | PostgreSQL's socket; public addresses on 80, 443, 465 and 587 |
| Cron (supercronic) | `moodle-cron` | the same |
| PostgreSQL | `postgres` | nothing |

- **Code from the image.** Moodle is in `/usr/share/moodle`, which nothing
  on the machine can write, with the form's `config.php`; Caddy serves its
  `public` directory and refuses what Moodle's own advice refuses, its
  dotfiles and the installer. A new Moodle comes with the image: the first
  start after an update runs Moodle's `upgrade.php`.
- **Forced settings** ([config.php](rootfs/usr/share/moodle/config.php)),
  which no administrator can change from the web: no plugin installed or
  updated from the web, and no update checks; no path to a program set
  from the web (`preventexecpath`), a way to run any program; nobody
  signs up and there is no guest; HTTPS-only cookies.
- **Everything else on `/data`.** `/data/svc/moodle/data` holds course
  files, sessions, caches and locks; `setup.php` writes `site.json` beside
  it at every start from the flags above, which `config.php` reads.
- **Its own schema.** Its tables are in the schema `moodle` of the
  `postgres` database, owned by the role of its name, which logs in by
  peer authentication; cron's role acts as it
  ([rootfs/usr/share/werewolf-postgres/moodle.sql](rootfs/usr/share/werewolf-postgres/moodle.sql)).
- **Cron every minute.** supercronic runs `admin/cli/cron.php` as
  `moodle-cron`, of moodle's group, at a quarter share of contended CPUs.
- **What it fetches**, from public addresses alone: what a teacher links
  to, and mail by your provider. Moodle refuses private addresses itself,
  and fence beneath it.
- PHP hands its shell functions none of its work (`disable_functions`),
  and php-fpm's pledge has no `exec`. PostgreSQL's `allow: [jit]` turns
  MDWE off for the whole machine, a weakness this form names.

## Drawbacks

- Plugins (a theme, an activity, an authentication method) come only with
  the image: a form of your own lays them in `/usr/share/moodle/public`.
- No program paths: no Ghostscript for PDF annotation, no antivirus scan
  of uploads, no LaTeX filter, until a form brings one and names it.
- Built here: Wolfi does not ship Moodle, so every minor release is
  werewolf's to bump ([melange/moodle.yaml](melange/moodle.yaml)).
- No LDAP or SAML sign-in as shipped: `php-8.4-ldap` is not in the image.

## Checked

`make check-moodle` boots it with its test config ([test/config](test/config)),
base URL `https://localhost`, for which Caddy's own CA signs: it is
installed under the site's name; plain HTTP is sent to HTTPS; the
administrator signs in and a wrong password is refused; the sign-up page
refuses; as the administrator, a path to a program cannot be set and no
plugin can be installed, and `moodle` cannot write the code; the
installer and Moodle's insides are 404; fence lets it reach public
addresses alone; the secrets are its own; and the first cron run is
recorded. `make check-shellfree-moodle` boots it as it ships, with no
config: no posture failure but those named, PostgreSQL, Caddy and cron
up, and Moodle parked, saying it has no administrator's password, before
it installs or serves anything.
