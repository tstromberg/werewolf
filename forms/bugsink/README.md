# Bugsink

Error tracking that takes the events Sentry's SDKs send: [Bugsink](https://www.bugsink.com) 2, from its own image, with Caddy in front.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/bugsink
openssl rand -hex 32 >config/bugsink/secret-key
printf '%s' you@example.com:"$(openssl rand -base64 18)" >config/bugsink/admin
printf '%s' https://errors.home.arpa >config/bugsink/base-url
howl create errors --with bugsink --on lima --config config \
	--domain errors.home.arpa
```

Sign in as the address in `admin`. The domain is given twice, as Caddy's site and as Bugsink's `base-url`, because an image service takes files rather than settings.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/bugsink
openssl rand -hex 32 >config/bugsink/secret-key
printf '%s' alice@example.com:"$(openssl rand -base64 18)" >config/bugsink/admin
printf '%s' https://errors.example.com >config/bugsink/base-url
howl create errors --with bugsink --on gcp --allow-from 0.0.0.0/0 \
	--config config --domain errors.example.com
```

Point the name at the machine, sign in, make a team and a project, and give its DSN to your application's Sentry SDK. There is no sign-up page.

### Known Quirks

- Keep `secret-key`. It signs sessions.
- The web server and the background worker are one service, so they share a queue.
- Events are stored in SQLite on `/data/svc/bugsink`.
- Alert webhooks may call public addresses on port 443.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Bugsink is on loopback.

### Security Weaknesses

- Python runs Bugsink once the config is present. The machine without a config never starts it. Named in `form.yaml`.
