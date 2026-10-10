# WordPress on MariaDB

The `wordpress-mariadb` form is the [wordpress](../wordpress/README.md)
form with its tables in MariaDB, beside it ([mariadb](../mariadb/README.md)),
instead of SQLite: for a site whose plugins want MySQL, or that outgrows
one file ([design/service-forms.md](../../docs/design/service-forms.md)).
Everything else, its settings, config, defenses and checks, is the
wordpress form's; read that README first.

## Run your own

```sh
htpasswd -nbB x 'a long admin password' | cut -d: -f2 >admin-password-hash
howl create site --with wordpress-mariadb --on gcp --allow-from 0.0.0.0/0 \
	--url https://www.example.com --admin-email you@example.com \
	--admin-password-hash admin-password-hash
```

The flags are the wordpress form's. TLS is in front of it, as there: a
caddy machine or the cloud's load balancer.

## How it differs

- **The database is MariaDB's `wordpress`**, made with its role before
  MariaDB first serves
  ([rootfs/usr/share/werewolf-mariadb/wordpress.sql](rootfs/usr/share/werewolf-mariadb/wordpress.sql)).
- **No password exists.** php-fpm's system user, `php`, is the role `php`
  by unix_socket on MariaDB's socket: nothing in `wp-config.php` or on
  `/data` would log in from anywhere else.
- **The role holds its database alone**: all privileges on `wordpress`,
  none on the server; no FILE, so not even a SQL injection reads the
  machine's files through MariaDB.
- **The installer waits for MariaDB.** On the first start MariaDB makes
  its data while php-fpm's installer starts; `wp-config.php` makes the
  installer wait up to two minutes, then fail. WordPress's own error page
  would exit 0, and php-fpm would serve a site not installed, to be
  claimed by its first visitor.
- **Its `db.php` does nothing**, laid over the wordpress form's, which
  chose SQLite: a form cannot remove a file, and WordPress loads any
  `wp-content/db.php`. The SQLite plugin stays in the image, unused.

## Drawbacks

- A second server on the machine: MariaDB's 1 GiB beside php-fpm and
  nginx.
- Backups are MariaDB's to make: `/data` holds its files, not one
  database file to copy.

## Checked

`make check-wordpress-mariadb` boots it with the wordpress form's test
config: WordPress is installed into MariaDB once MariaDB answers, the
site answers with its name, the admin logs in with the configured
password, `wp_users` is MariaDB's and no SQLite file was made, the role
`php` holds its database alone, by unix_socket, and MariaDB reads no file
asked as `php`. `make check-shellfree-wordpress-mariadb` boots it as it
ships: MariaDB serves its socket, and php-fpm parks, saying it has no
admin password hash, before WordPress is installed.
