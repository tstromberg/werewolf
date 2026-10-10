# LimeSurvey

Surveys and research data: [LimeSurvey](https://www.limesurvey.org) 7.5, its tables in MariaDB. The 6.x line is no longer supported.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
htpasswd -nbB x 'a long admin password' | cut -d: -f2 >admin-password-hash
howl create surveys --with limesurvey --on lima \
	--url https://surveys.home.arpa --title 'Department surveys' \
	--admin-email it@example.edu --admin-password-hash admin-password-hash
```

Sign in with the password you hashed. The form stores the hash, never the password.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
htpasswd -nbB x 'a long admin password' | cut -d: -f2 >admin-password-hash
howl create surveys --with limesurvey --on gcp --allow-from 0.0.0.0/0 \
	--url https://surveys.example.edu --title 'Department surveys' \
	--admin-email it@example.edu --admin-password-hash admin-password-hash
```

Put TLS in front; the form serves plain HTTP and trusts `X-Forwarded-Proto`. Mail and a directory are optional: `--smtp HOST:PORT`, `--smtp-user`, `--smtp-password`, `--mail-from`.

### Known Quirks

- It installs itself before it serves, and refuses tables newer than the image, so a rolled-back slot cannot open them.
- Plugin upload is off. Plugins load only from the image.
- Theme uploads stay on, for a department's branding. LimeSurvey unpacks no PHP from them.
- A forged Host header is refused.

### Network Exposure

- tcp/80, nginx. Mail may leave on tcp/587 and a directory on tcp/636, when you name them.

### Security Weaknesses

- PHP runs LimeSurvey. That is named in `form.yaml`.
