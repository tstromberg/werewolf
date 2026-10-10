# WordPress

The `wordpress` form is `php` with WordPress 7.1 in the image, on SQLite:
one machine, no second server. It is the worked example of an application
baked into a form ([forms.md](../../docs/forms.md#your-application)).

| | |
| --- | --- |
| Listens | tcp/80, nginx. TLS is in front of it: a `caddy` machine or the cloud's load balancer, which says so in `X-Forwarded-Proto` |
| Sends | mail, by SMTP submission to the relay the settings name (`connect php tcp/587`), and DNS to find it; nothing else (`WP_HTTP_BLOCK_EXTERNAL`) |
| Runs as | nginx as `nginx`; php-fpm as `php`, leashed to the site, `/run/svc/php-fpm` and `/data/svc/php-fpm` |
| Keeps | the database (`/data/svc/php-fpm/database/wordpress.sqlite`), uploads (`/data/svc/php-fpm/uploads`, which `wp-content/uploads` links to) and the salts, made once |
| Config | `wordpress/admin-password-hash` (bcrypt, required); `wordpress/salts.php` and `wordpress/smtp-password`, optional; settings `url` and `admin-email` (required), `title`, `admin-user`, `smtp` (host:port), `smtp-user`, `mail-from` |

```sh
umask 077; mkdir -p config/wordpress
htpasswd -nbB x 'the admin password' | cut -d: -f2 >config/wordpress/admin-password-hash
build/host/howl pack --with wordpress -o config.tar --config config \
	--url https://blog.example.com --title 'A blog' --admin-email me@example.com \
	--smtp smtp.example.com:587 --smtp-user me@example.com --mail-from blog@example.com
```

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- php-fpm runs WordPress
- PCRE2 compiles PHP's patterns to machine code (allow jit, from php)

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
umask 077
mkdir -p config/wordpress
htpasswd -nbB x 'a long admin password' | cut -d: -f2 >config/wordpress/admin-password-hash
howl create wordpress --with wordpress --config config \
	--url https://blog.home.arpa --admin-email me@example.com
```

Open the URL. Sign in as `admin` with the password you hashed. TLS is in front: Caddy, or the cloud's load balancer, which sets `X-Forwarded-Proto`.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
umask 077
mkdir -p config/wordpress
htpasswd -nbB x 'a long admin password' | cut -d: -f2 >config/wordpress/admin-password-hash
howl create wordpress --with wordpress --on gcp --allow-from me --config config \
	--url https://blog.example.com --admin-email me@example.com
```

`--allow-from me` admits your address to port 80. Mail is `--smtp`, `--smtp-user` and `config/wordpress/smtp-password`.

### Migrating data in

The database is SQLite in `/data`, and the host cannot write that directory. Export the old site as a WordPress XML file and import it under Tools after this one is up.

### Network Exposure

tcp/80


## Installed before it serves

A fresh WordPress belongs to whoever finds it first. Here
`usr/share/werewolf-wordpress/install.php` runs before php-fpm, as `php`,
inside its leash: it makes the data directories and the salts (once, 0600,
unless the config brought `salts.php`), and if the site is not installed,
installs it with the settings' title, admin and email and sets the admin's
password to the hash the config gave. nginx never serves `install.php` or
`setup-config.php`. A missing hash parks the service with a line naming
the file.

## Defaults

- **Code in the image.** `DISALLOW_FILE_MODS`, `DISALLOW_FILE_EDIT`,
  `AUTOMATIC_UPDATER_DISABLED`: plugins, themes and updates come with the
  image, by a form of your own that lays them into
  `usr/src/wordpress/wp-content`.
- **nginx** refuses `wp-config.php`, `readme.html`, `license.txt`, every
  dotfile (Wolfi's package carries the site's `.git`) and any `.php` under
  uploads; sends `nosniff` everywhere and `Content-Security-Policy:
  sandbox` on uploaded SVG, HTML and XML, so a script in one runs for no
  one; and rate limits `wp-login.php` and `xmlrpc.php` to ten a minute an
  address.
- **PHP** (`etc/php/php-fpm.conf`): `open_basedir` to the site and its
  own directories, `expose_php`, `allow_url_fopen` and `allow_url_include`
  off, the shell functions disabled, uploads to 64 MB,
  `opcache.validate_timestamps` off since the code cannot change.
- **The must-use plugin** (`wp-content/mu-plugins/werewolf.php`): mail by
  SMTP with STARTTLS, or off with a line on the console when no relay is
  set; pingbacks off, XML-RPC kept for the mobile apps and Jetpack; users
  listed over REST only to those logged in, and `?author=N` a 404; and
  logins, failures, role changes and password resets on the console.
- With an `https` address, `FORCE_SSL_ADMIN` and secure cookies follow.
  Application passwords stay, over HTTPS only, as WordPress has them.
- **Plugins that call an API** need a form of your own that adds
  `connect php tcp/443 public` to its `net` and the hosts to
  `WP_ACCESSIBLE_HOSTS` in `wp-config.php`.

## SQLite

The database is WordPress's own SQLite plugin (the Performance team's
`sqlite-database-integration`, 3.0, GPL-2.0), carried in the form under
`wp-content/plugins`, chosen by the drop-in `wp-content/db.php`. A
WordPress that needs MySQL (`wordpress-mariadb`) waits on Wolfi's
`mariadb` package losing its shell scripts
([design/service-forms.md](../../docs/design/service-forms.md)).

## Checked

`make check-wordpress` gives it `http://localhost` and the hash of
`werewolf-check` ([forms/wordpress/test/config](test/config)) and
runs [forms/wordpress/test/checks](test/checks): the site answers
with its name; the installer, configuration, version page and `.git` are
404; the admin logs in and a wrong password does not; thirty requests to
`wp-login.php` meet a 503; users are hidden; no pingbacks; a `.php` and
an SVG planted under uploads are refused and sandboxed; `php` cannot write
the code; and the hash, salts and database are `php`'s alone.
