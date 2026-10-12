# Paperless-ngx - Hardened VM

A document archive with OCR and search: [Paperless-ngx](https://docs.paperless-ngx.com/) 3.3, with Caddy in front and Valkey as its queue. The form's manifest is [form.yaml](form.yaml).

## Security Posture

- The web server, the consumer, the worker and the scheduler each run as their own user. They share the library, which the web server's user owns. The root is read-only. `/data` is what survives.
- Sign-up is closed. The administrator is created from the config before the site answers.
- The web server listens on loopback. Caddy is the public port.
- The queue is Valkey's socket. There is no Redis port.

### Weaknesses

- Python runs Paperless. Named in `form.yaml`.
- The four services share one library, so the files they make stay writable by that group. Named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/paperless
umask 077
openssl rand -hex 32 >config/paperless/secret-key
openssl rand -base64 18 >config/paperless/admin-password
howl create paperless --with paperless --config config \
	--admin admin --domain paper.home.arpa
```

Open `https://paper.home.arpa` and sign in as `admin`. The password is `config/paperless/admin-password`. Keep `secret-key`: it signs sessions. Tags, correspondents and the consume folder are in [Paperless's documentation](https://docs.paperless-ngx.com/usage/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/paperless
umask 077
openssl rand -hex 32 >config/paperless/secret-key
openssl rand -base64 18 >config/paperless/admin-password
howl create paperless --with paperless --on gcp --allow-from me \
	--config config --admin admin --domain paper.example.com
```

Sign in at `https://paper.example.com`. The library is in `/data/svc/paperless`.

### Importing data

The database is SQLite in `/data`, and the documents are files beside it. The host cannot write that directory. Add documents in the web interface after the site answers.

### Known Quirks

- Tesseract, Ghostscript, ImageMagick, poppler and qpdf are the system's packages.
- Page cleaning is off. Wolfi does not package unpaper.
- Office documents and email are not converted.
- The assistant is not installed.
- Keep `secret-key`. Creating again with a new one signs everyone out.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
