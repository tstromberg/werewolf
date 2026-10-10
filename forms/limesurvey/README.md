# LimeSurvey

The `limesurvey` form is surveys and research data collection:
[LimeSurvey](https://www.limesurvey.org) 7.5, its tables in MariaDB beside
it, installed from the config before it serves, its code read-only and
plugins from the image alone
([design/academic.md](../../docs/design/academic.md)).

| | |
| --- | --- |
| Listens | tcp/80, nginx. TLS is in front of it: a `caddy` machine or the cloud's load balancer, which says so in `X-Forwarded-Proto` |
| Sends | mail, by SMTP submission to the relay the settings name (tcp/587), LDAPS to a directory (tcp/636), and DNS; nothing else |
| Runs as | nginx as `nginx`; php-fpm as `php`; MariaDB as `mariadb`, on its socket alone |
| Keeps | the tables (MariaDB's `limesurvey`), uploads and published assets (`/data/svc/php-fpm/upload`, `tmp`, which the image's `upload` and `tmp` link to) and the encryption keys (`security.json`, made once) |
| Flags | `--admin-password-hash FILE` (bcrypt, required); `--smtp-password FILE`; `--url` and `--admin-email` (required), `--title`, `--admin-user`, `--admin-name`, `--smtp HOST:PORT`, `--smtp-user`, `--mail-from` |

```sh
htpasswd -nbB x 'a long admin password' | cut -d: -f2 >admin-password-hash
howl create surveys --with limesurvey --on gcp --allow-from 0.0.0.0/0 \
	--url https://surveys.example.edu --title 'Department surveys' \
	--admin-email it@example.edu --admin-password-hash admin-password-hash
```

## Installed before it serves

A fresh LimeSurvey's web installer makes whoever finds it first the
administrator. Here `application/config/config.php` is in the image, which
turns that installer off, and `usr/share/werewolf-limesurvey/install.php`
runs before php-fpm, as `php`, inside its leash: it makes the directories
on `/data` and the encryption keys (once, 0600), waits for MariaDB, and
installs LimeSurvey's tables with the settings' admin, whose password is
the hash the config gave; never a plaintext password on a command line.
A later release brings the tables up to its own (`db_upgrade_all`), and
empties the assets and cache the old one published. A missing hash parks
the service with a line naming the file; tables newer than the release (a
rolled-back slot) park it too, rather than being written to.

## Defaults

- **No code from `/data`.** Plugin upload is off (`disablePluginUpload`),
  and plugins load from the image alone: the upload directory is not one
  of the plugin manager's, so a PHP file someone managed to write there
  never runs. Custom Twig extensions are off. Themes may still be
  uploaded, as institutions brand their surveys, but LimeSurvey unpacks no
  `.php` from them, and nginx runs none beneath `upload/`. A plugin of
  your own is a form on this one that lays it into `plugins/`.
- **nginx** runs `index.php` and the HTML editor's file browser and no
  other `.php`; refuses dotfiles, `application/`, `vendor/`, `docs/`,
  `installer/`, `locale/`, the cache in `tmp/` and the files participants
  upload with their answers, which LimeSurvey hands out itself; sandboxes
  uploaded SVG, HTML and XML; and rate limits sign-in to ten a minute an
  address, beside LimeSurvey's own lockout.
- **PHP** (`etc/php/php-fpm.conf`): `open_basedir` to LimeSurvey and its
  own directories, URL fopen and include off, the shell functions
  disabled, `max_input_vars` 10000 for large surveys.
- **No phoning home**: update checks off, and fence lets php-fpm reach
  MariaDB's socket, the relay and a directory alone. Links in mail are
  built from `url`, and a request for another host is refused, so a forged
  `Host` cannot aim a password reset elsewhere.
- With an `https` address, cookies are secure. The JSON-RPC API stays off
  until the administrator turns it on.

## MariaDB

LimeSurvey's first database. The role `php` logs in by `unix_socket` and
holds `limesurvey.*` alone: no `FILE`, so no SQL reads the machine's files
([rootfs/usr/share/werewolf-mariadb/limesurvey.sql](rootfs/usr/share/werewolf-mariadb/limesurvey.sql)).

## Drawbacks

- LDAP sign-in reaches a directory on tcp/636 (LDAPS) only; plain LDAP on
  389 needs a form that adds it.
- Releases ship about monthly; each is werewolf's to pin until Wolfi
  takes the recipe ([melange/limesurvey.yaml](melange/limesurvey.yaml)).
- No ComfortUpdate: an update is a new image.

## Checked

`make check-limesurvey` gives it `http://localhost` and the hash of
`werewolf-check` ([test/config](test/config)) and runs
[test/checks](test/checks). `make check-shellfree-limesurvey` boots it as
it ships: MariaDB up, php-fpm parked for want of the hash, nothing
installed.
