# MediaWiki

A wiki for a lab or a department: [MediaWiki](https://www.mediawiki.org) 1.43, the long-term release, on SQLite.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
umask 077; mkdir -p config/mediawiki
openssl rand -base64 24 >config/mediawiki/admin-password
howl create wiki --with mediawiki --on lima --config config \
	--url https://wiki.home.arpa --name 'Lab notes' --admin Alice
```

Sign in as `Alice`. TLS in front is Caddy or the host's balancer; this form serves plain HTTP and trusts `X-Forwarded-Proto`.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
umask 077; mkdir -p config/mediawiki
openssl rand -base64 24 >config/mediawiki/admin-password
howl create wiki --with mediawiki --on gcp --allow-from 0.0.0.0/0 \
	--config config --url https://wiki.lab.example.edu --name 'Lab notes'
```

Put Caddy or the cloud load balancer in front and send `X-Forwarded-Proto`. Reading is closed until you set `public-read` true. Only an administrator makes accounts. There is no mail, so there is no password reset by email: keep the admin password.

### Known Quirks

- The wiki installs itself before it serves. A later image runs `update.php` only when the code has changed.
- Uploads are images and PDF. SVG and HTML are refused.
- Extensions that run programs are not installed: Scribunto, SyntaxHighlight, Math, PdfHandler.
- The database, uploads and secret key live in `/data/svc/php-fpm`.

### Network Exposure

- tcp/80, nginx. Nothing leaves the machine.

### Security Weaknesses

- PHP runs the wiki, and PCRE may compile a pattern. Both are named in `form.yaml`.
