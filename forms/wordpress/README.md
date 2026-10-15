# WordPress - Hardened VM

[WordPress](https://wordpress.org) on SQLite, behind nginx. The form's manifest is [form.yaml](form.yaml).

[Images, test status and download instructions](https://dist.werewolf-linux.org/images/v1/wordpress/index.html).

## Security Posture

- nginx and php-fpm run as their own users. The root is read-only.
- The admin password is a bcrypt hash in a file. The plaintext is not on the machine.
- The database is SQLite in `/data`. The host cannot write that directory.

### Weaknesses

- php-fpm runs WordPress.
- PCRE2 compiles PHP's patterns to machine code.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
umask 077
mkdir -p config/wordpress
htpasswd -nbB x 'a long admin password' | cut -d: -f2 >config/wordpress/admin-password-hash
howl create wordpress --with wordpress --config config \
	--url https://blog.home.arpa --admin-email me@example.com
```

Open `https://blog.home.arpa` and sign in as `admin`. Posts and users are in [WordPress's documentation](https://wordpress.org/documentation/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
umask 077
mkdir -p config/wordpress
htpasswd -nbB x 'a long admin password' | cut -d: -f2 >config/wordpress/admin-password-hash
howl create wordpress --with wordpress --on gcp --allow-from me --config config \
	--url https://blog.example.com --admin-email me@example.com
```

`--allow-from me` admits your address to port 80. Point the name at the machine. The URL is stored at first install.

### Importing data

Export the old site as WXR and import it under Tools, once the site answers. The host cannot write the SQLite file.

### Known Quirks

- The hash file is the bcrypt string only, the part after `:` in `htpasswd -nbB`.
- There is no MySQL. Uploads live beside the SQLite file on `/data`.

### Network Exposure

- listen: tcp/80 *
