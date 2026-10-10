# Overleaf

Collaborative LaTeX: [Overleaf Community Edition](https://github.com/overleaf/overleaf) 6.3, from Overleaf's own image, with MongoDB, Valkey and Caddy. The image is published for x86_64 only. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- Node compiles as it runs. That is named in `form.yaml`.
- `\write18` can run only TeX Live's restricted helpers, not a command a document names.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/overleaf
openssl rand -base64 24 >config/overleaf/admin-password
howl create overleaf --with overleaf \
	--config config --base-url https://latex.home.arpa \
	--admin-email you@example.com
```

The host must be x86_64: Overleaf publishes no Arm image, so this command is skipped on any other machine. Give it 8 GB. Open `https://latex.home.arpa` and sign in with your email. The password is in `config/overleaf/admin-password`. Projects are in [Overleaf's documentation](https://www.overleaf.com/learn).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/overleaf
openssl rand -base64 24 >config/overleaf/admin-password
howl create overleaf --with overleaf --on gcp --arch x86_64 --allow-from me \
	--config config --base-url https://latex.example.com \
	--admin-email you@example.com
```

Sign in at `https://latex.example.com`. Make other accounts under Admin, Manage users. Add `--email-from`, `--smtp-host`, `--smtp-port`, `--smtp-user` and `config/overleaf/smtp-password` and Overleaf mails each a link; without them it shows you the link.

### Migrating data in

Projects live in MongoDB. This form does not import a MongoDB dump. `--import` can carry Valkey's `dump.rdb`, which is a cache, not the projects. Bring a project in through the site after this machine is up.

### Known Quirks

- The compiler is a second copy of the image, as its own user, and cannot see the database or the session secret.
- TeX Live is `scheme-basic`, with no `tlmgr`. A document that needs another package fails to compile.
- Compiles share one user, as upstream's Community Edition does. Give accounts to people you would trust with each other's drafts.
- Deleted projects are kept. Upstream's deletion cron stays off.
- The image is about 3 GB, twice, plus MongoDB. The first boot is slow.

### Network Exposure

- tcp/80 and tcp/443, Caddy. MongoDB, Valkey and the compiler listen on loopback.
