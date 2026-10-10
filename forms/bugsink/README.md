# Bugsink

Error tracking that takes the events Sentry's SDKs send: [Bugsink](https://www.bugsink.com) 2, from its own image, with Caddy in front. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

- Python runs Bugsink once the config is present. The machine without a config never starts it. Named in `form.yaml`.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/bugsink
openssl rand -hex 32 >config/bugsink/secret-key
printf '%s' you@example.com:"$(openssl rand -base64 18)" >config/bugsink/admin
printf '%s' https://errors.home.arpa >config/bugsink/base-url
howl create bugsink --with bugsink --config config \
	--domain errors.home.arpa
```

Open `https://errors.home.arpa` and sign in as `you@example.com`. The password is the text after the colon in `config/bugsink/admin`. The domain is given twice, as Caddy's site and as Bugsink's `base-url`, because an image service takes files rather than settings. Projects and DSNs are in [Bugsink's documentation](https://www.bugsink.com/docs/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/bugsink
openssl rand -hex 32 >config/bugsink/secret-key
printf '%s' alice@example.com:"$(openssl rand -base64 18)" >config/bugsink/admin
printf '%s' https://errors.example.com >config/bugsink/base-url
howl create bugsink --with bugsink --on gcp --allow-from me \
	--config config --domain errors.example.com
```

Sign in at `https://errors.example.com`, make a team and a project, and give its DSN to your application's Sentry SDK. There is no sign-up page.

### Migrating data in

The database is SQLite in `/data`, and the host cannot write that directory. Point the SDK at this machine. Events from here on are the data.

### Known Quirks

- Keep `secret-key`. It signs sessions.
- The web server and the background worker are one service, so they share a queue.
- Events are stored in SQLite on `/data/svc/bugsink`.
- Alert webhooks may call public addresses on port 443.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Bugsink is on loopback.
