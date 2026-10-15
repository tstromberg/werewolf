# Paperless-ngx - Hardened VM

A document archive with OCR and search: [Paperless-ngx](https://docs.paperless-ngx.com/)
3.3, with Caddy in front and Valkey as its queue. The form's manifest is
[form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/paperless/index.html).

## Security Posture

- The web server, consumer, worker and scheduler share the unprivileged paperless user
  and private upload files. Each retains separate service rules and process limits. The
  root is read-only. `/data` is what survives.
- Sign-up is closed. The administrator is created from the config before the site
  answers.
- The web server listens on loopback. Caddy is the public port.
- The queue and PostgreSQL database use local UNIX sockets. Paperless authenticates to
  PostgreSQL as its UNIX user; neither has a TCP listener.

### Weaknesses

- Python runs Paperless. Named in `form.yaml`.

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

Open `https://paper.home.arpa` and sign in as `admin`. The password is
`config/paperless/admin-password`. Keep `secret-key`: it signs sessions. Tags,
correspondents and the consume folder are in [Paperless's
documentation](https://docs.paperless-ngx.com/usage/).

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

PostgreSQL stores the database in `/data/svc/postgres`; documents remain in
`/data/svc/paperless`. Add documents in the web interface after the site answers.

An existing SQLite library stops startup. Export it with the previous image using
Paperless's `document_exporter`, keep a backup, and follow the upstream [export/import
procedure](https://docs.paperless-ngx.com/administration/#exporter-importer) into
PostgreSQL. Move the old `db.sqlite3` and its journal files out of the live library only
after the export succeeds; retain them with the backup. The form never converts or
deletes an existing database automatically.

### Known Quirks

- Tesseract, Ghostscript, ImageMagick, poppler and qpdf are the system's packages.
- Page cleaning is off. Wolfi does not package unpaper.
- Office documents and email are not converted.
- The assistant is not installed.
- PostgreSQL JIT is disabled for this form; the inherited PostgreSQL form still declares
  the kernel JIT allowance.
- Keep `secret-key`. Creating again with a new one signs everyone out.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
