# WordPress and MariaDB - Hardened VM

[WordPress](https://wordpress.org) with MariaDB on a UNIX socket, behind nginx. The
form's manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/wordpress-mariadb/index.html).

## Security Posture

- nginx, php-fpm, and MariaDB run as their own users. The root is read-only.
- The admin password is a bcrypt hash in a file. The plaintext is not on the machine.
- MariaDB has no TCP listener. The host cannot reach it.

### Weaknesses

- php-fpm runs WordPress.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
umask 077
htpasswd -nbB x 'a long admin password' | cut -d: -f2 >admin-password-hash
howl create wordpress-mariadb --with wordpress-mariadb \
	--url https://blog.home.arpa --admin-email me@example.com \
	--admin-password-hash admin-password-hash
```

Open `https://blog.home.arpa` and sign in as `admin`. Posts and users are in
[WordPress's documentation](https://wordpress.org/documentation/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
umask 077
htpasswd -nbB x 'a long admin password' | cut -d: -f2 >admin-password-hash
howl create wordpress-mariadb --with wordpress-mariadb --on gcp --allow-from me \
	--url https://blog.example.com --admin-email me@example.com \
	--admin-password-hash admin-password-hash
```

`--allow-from me` admits your address to port 80. Point the name at the machine.

### Importing data

`--import` streams `*.sql` into MariaDB once, while data is first made. Uploads and the
WordPress tree are not on that disk. A cloud cannot attach it.

```sh
umask 077
htpasswd -nbB x 'a long admin password' | cut -d: -f2 >admin-password-hash
howl create wordpress-mariadb --with wordpress-mariadb --import ./dump \
	--url https://blog.home.arpa --admin-email me@example.com \
	--admin-password-hash admin-password-hash
```

### Known Quirks

- The hash file is the bcrypt string only. `--admin-password-hash` names that file.
- The URL is stored at first install.

### Network Exposure

- listen: tcp/80 *
