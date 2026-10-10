# Nextcloud

The `nextcloud` form is files, calendars and contacts for a household:
[Nextcloud](https://nextcloud.com) 35, with PostgreSQL, Valkey and its
background jobs beside it and Caddy in front, serving HTTPS at your URL
with a certificate from Let's Encrypt, each part on a leash of its own
([design/self-hosting.md](../../docs/design/self-hosting.md)).

## Run your own

You need a domain name you can point at the machine.

```sh
openssl rand -base64 24 >admin-password      # you sign in with it; keep it
howl create cloud --with nextcloud --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://cloud.example.com --admin alice \
	--admin-password admin-password
```

Point `cloud.example.com` at the address howl prints and sign in at
`https://cloud.example.com` as `alice`. Caddy gets the certificate once
the name resolves to the machine. The phones' and desktops' apps take
the same URL; calendars and contacts are found at `/.well-known`.

| Flag | |
| --- | --- |
| `--base-url URL` | required. Where Nextcloud is served: Caddy's site, its trusted domain and its own links |
| `--admin NAME` | the administrator, made on the first start; `admin` if not given |
| `--admin-password FILE` | required. Its password, never printed or logged |
| `--admin-email ADDRESS` | the administrator's address, for its notices |
| `--phone-region CODE` | ISO 3166 country, for phone numbers without one |

Nextcloud is installed before it serves anything, so no visitor claims a
fresh machine: its installer is not even in the image. Nobody signs up;
the administrator adds people under Accounts. A later start keeps the
administrator as it is: change its password in Nextcloud.

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; php-fpm's socket; the ACME CA |
| Nextcloud (php-fpm) | `nextcloud` | PostgreSQL's and Valkey's sockets; public addresses on 80, 443, 465 and 587 |
| Background jobs (supercronic) | `nextcloud-cron` | the same |
| PostgreSQL, Valkey | `postgres`, `valkey` | nothing |

- **Code from the image.** Nextcloud is in `/usr/share/nextcloud`, which
  nothing on the machine can write; Caddy serves its files and hands only
  Nextcloud's entry points to PHP, and refuses its insides, its dotfiles
  and the web updater. A new Nextcloud comes with the image: the first
  start after an update runs `occ upgrade`, then adds the indices a
  release wants. The web cannot upgrade it (`upgrade.disable-web`).
- **Everything else on `/data`.** `/data/svc/nextcloud` holds its config,
  the apps from the app store, and everyone's files. `setup.php` writes
  `werewolf.config.php` there at every start from the flags above, with
  the policy beside them (Valkey for locking and the shared cache, logs on
  the console); Nextcloud reads it after its own `config.php`, so it wins.
- **Apps from the app store** install as Nextcloud has them, into `/data`.
  One that brings a program of its own does not run: `/data` is
  `noexec`. Nextcloud checks the store's signatures.
- **Background jobs by cron.** supercronic runs `cron.php` every five
  minutes as `nextcloud-cron`, of nextcloud's group. Nextcloud runs jobs
  only as its config's owner, so the job runs on a copy of the config in
  its own directory, and its database role acts as `nextcloud`'s.
- **Its own database**, `nextcloud`, made by its installer, owned by the
  role of its name, which logs in by peer authentication
  ([rootfs/usr/share/werewolf-postgres/nextcloud.sql](rootfs/usr/share/werewolf-postgres/nextcloud.sql)).
- **What it fetches**, from public addresses alone: the app store, other
  servers' shares, link previews, mail by your provider, and the
  password policy's breach lookup. No update checks or announcements.
- PHP hands its shell functions none of its work (`disable_functions`),
  and php-fpm's pledge has no `exec`. PostgreSQL's `allow: [jit]` turns
  MDWE off for the whole machine, a weakness this form names.

## Drawbacks

- Built here: Wolfi's Nextcloud is a container's, a major release behind,
  so every release is werewolf's to bump
  ([melange/nextcloud.yaml](melange/nextcloud.yaml)).
- No `occ` at a prompt: there is no shell. What the web cannot do waits
  for a form of your own.
- No Office or Talk's media server: each is a program of its own.
- Previews by GD alone: no `imagick`, whose ImageMagick is large; the
  theming app's favicons are plain.

## Checked

`make check-nextcloud` boots it with its test config ([test/config](test/config)),
base URL `https://localhost`, for which Caddy's own CA signs: it is
installed and current; plain HTTP is sent to HTTPS; the login page is no
installer; the administrator signs in and a file goes up and comes back
over WebDAV onto `/data`; the code's insides, its scripts by path and
the web updater are 404, and `nextcloud` cannot write the code; there is
no sign-up; fence lets it reach public addresses alone; the password and
config are its own; a wrong password is refused; and the first
background job runs. `make check-shellfree-nextcloud` boots it as it
ships, with no config: no posture failure but those named, PostgreSQL,
Valkey, Caddy and cron up, and Nextcloud parked, saying it has no
administrator's password, before it installs or serves anything.
