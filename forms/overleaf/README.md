# Overleaf

Collaborative LaTeX: [Overleaf Community Edition](https://github.com/overleaf/overleaf) 6.3, from Overleaf's own image, with MongoDB, Valkey and Caddy. The image is published for x86_64 only.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/overleaf
openssl rand -base64 24 >config/overleaf/admin-password
howl create latex --with overleaf --on qemu \
	--config config --base-url https://latex.home.arpa \
	--admin-email you@example.com
```

The host must be x86_64: Overleaf publishes no Arm image. Give the machine 8 GB. Sign in with your email.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/overleaf
openssl rand -base64 24 >config/overleaf/admin-password
howl create latex --with overleaf --on gcp --arch x86_64 --allow-from 0.0.0.0/0 \
	--config config --base-url https://latex.example.com \
	--admin-email you@example.com
```

Point the name at the machine. Make other accounts under Admin, Manage users. Add `--email-from`, `--smtp-host`, `--smtp-port`, `--smtp-user` and `config/overleaf/smtp-password` and Overleaf mails each a link; without them it shows you the link.

### Known Quirks

- The compiler is a second copy of the image, as its own user, and cannot see the database or the session secret.
- TeX Live is `scheme-basic`, with no `tlmgr`. A document that needs another package fails to compile.
- Compiles share one user, as upstream's Community Edition does. Give accounts to people you would trust with each other's drafts.
- Deleted projects are kept. Upstream's deletion cron stays off.
- The image is about 3 GB, twice, plus MongoDB. The first boot is slow.

### Network Exposure

- tcp/80 and tcp/443, Caddy. MongoDB, Valkey and the compiler listen on loopback.

### Security Weaknesses

- Node compiles as it runs. That is named in `form.yaml`.
- `\write18` can run only TeX Live's restricted helpers, not a command a document names.
