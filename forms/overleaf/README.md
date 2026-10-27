# Overleaf - Hardened VM

Collaborative LaTeX: [Overleaf Community
Edition](https://github.com/overleaf/overleaf) 6.3, from Overleaf's own image, with
MongoDB, Valkey and Caddy. The image is published for x86_64 only. The form's
manifest is [form.yaml](form.yaml).

[Images, test status and download
instructions](https://dist.werewolf-linux.org/boot/v1/overleaf/index.html).

## Security Posture

- The service runs as its own user, held to the files and ports its manifest names.
  The root is read-only. `/data` is what survives.

- `\write18` can run only TeX Live's restricted helpers, not a command a document
  names.

- Each compile reads only its own project, TeX's files and a TeX cache of its own,
  and connects nowhere ([clsi-confine](cmd/clsi-confine/README.md)).

### Weaknesses

- Node compiles as it runs. That is named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/overleaf
openssl rand -base64 24 >config/overleaf/admin-password
howl create overleaf --with overleaf \
	--config config --base-url https://latex.home.arpa \
	--admin-email you@example.com
```

The host must be x86_64: Overleaf publishes no Arm image, so this command is skipped
on any other machine. Give it 8 GB. Open `https://latex.home.arpa` and sign in with
your email. The password is in `config/overleaf/admin-password`. Projects are in
[Overleaf's documentation](https://www.overleaf.com/learn).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/overleaf
openssl rand -base64 24 >config/overleaf/admin-password
howl create overleaf --with overleaf --on gcp --arch x86_64 --allow-from me \
	--config config --base-url https://latex.example.com \
	--admin-email you@example.com
```

Sign in at `https://latex.example.com`. Make other accounts under Admin, Manage
users. Add `--email-from`, `--smtp-host`, `--smtp-port`, `--smtp-user` and
`config/overleaf/smtp-password` and Overleaf mails each a link; without them it shows
you the link.

### Importing data

Projects live in MongoDB. This form does not import a MongoDB dump. `--import` can
carry Valkey's `dump.rdb`, which is a cache, not the projects. Bring a project in
through the site after this machine is up.

### Known Quirks

- The compiler is a second copy of the image, as its own user, and cannot see the
  database or the session secret.
- TeX Live is `scheme-basic`, with no `tlmgr`. A document that needs another package
  fails to compile.
- Compiles share one user, as upstream's Community Edition does, each held to its own
  project; word counts and SyncTeX are not. Give accounts to people you would trust
  with each other's drafts.
- A document that inputs a file outside its project and TeX Live fails to compile:
  TeX finds the file but may not open it.
- Deleted projects are kept. Upstream's deletion cron stays off.
- The image is about 3 GB, twice, plus MongoDB. The first boot is slow.

### Network Exposure

- listen: tcp/80 *
- listen: tcp/443 *
