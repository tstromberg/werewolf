# MediaWiki

A wiki for a lab or a department: [MediaWiki](https://www.mediawiki.org) 1.43, the long-term release, on SQLite. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- PHP runs the wiki, and PCRE may compile a pattern. Both are named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
umask 077; mkdir -p config/mediawiki
openssl rand -base64 24 >config/mediawiki/admin-password
howl create mediawiki --with mediawiki --config config \
	--url https://wiki.home.arpa --name 'Lab notes' --admin Alice
```

Open the address howl prints, port 80, and sign in as `Alice`. The password is in `config/mediawiki/admin-password`. This form serves plain HTTP and trusts `X-Forwarded-Proto`. Pages and accounts are in [MediaWiki's manual](https://www.mediawiki.org/wiki/Help:Contents).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
umask 077; mkdir -p config/mediawiki
openssl rand -base64 24 >config/mediawiki/admin-password
howl create mediawiki --with mediawiki --on gcp --allow-from me \
	--config config --url https://wiki.lab.example.edu --name 'Lab notes'
```

Open `https://wiki.lab.example.edu` once Caddy or the load balancer is in front and sends `X-Forwarded-Proto`. Reading is closed until you set `public-read` true. Only an administrator makes accounts. There is no mail, so there is no password reset by email.

### Migrating data in

The database is SQLite in `/data`, and the host cannot write that directory. Export pages as XML from the old wiki and import them with Special:Import after this one is up.

### Known Quirks

- The wiki installs itself before it serves. A later image runs `update.php` only when the code has changed.
- Uploads are images and PDF. SVG and HTML are refused.
- Extensions that run programs are not installed: Scribunto, SyntaxHighlight, Math, PdfHandler.
- The database, uploads and secret key live in `/data/svc/php-fpm`.

### Network Exposure

- tcp/80, nginx. Nothing leaves the machine.
