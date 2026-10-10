# Authelia

One sign-in for every site under your domain: [Authelia](https://www.authelia.com) 4.39, a password plus a TOTP app or a security key, with Caddy in front. The form's manifest is [form.yaml](form.yaml).

## Security Posture

The service runs as its own user. Landlock and seccomp hold it to the files and ports its manifest names. The root is read-only. An update replaces the image, and `/data` is what survives.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
openssl rand -base64 18 >admin-password
openssl rand -hex 32 >session-secret
openssl rand -hex 32 >storage-key
node forms/authelia/example/users.js admin-password >users.yml
howl create authelia --with authelia \
	--domain home.arpa --sso-users users.yml \
	--session-secret session-secret --storage-key storage-key
```

Open `https://auth.home.arpa` and sign in as `alice`. The password is in `admin-password`. The script needs Node 24 or newer: it writes an Argon2id hash, which is the only password Authelia's file backend stores. Without SMTP, registering a second factor has no mail channel. Rules and the file format are in [Authelia's documentation](https://www.authelia.com/configuration/first-factor/file/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -base64 18 >admin-password
openssl rand -hex 32 >session-secret
openssl rand -hex 32 >storage-key
node forms/authelia/example/users.js admin-password >users.yml
howl create authelia --with authelia --on gcp --allow-from me \
	--domain example.com --sso-users users.yml \
	--session-secret session-secret --storage-key storage-key
```

Sign in at `https://auth.example.com`. Point `example.com` and `*.example.com` at the machine. Add `--smtp-server`, `--smtp-sender`, `--smtp-username` and `--smtp-password` so a person can receive a one-time code and register a second factor. Keep `storage-key`: it encrypts the database.

### Migrating data in

Users and policy are in the create command or `--config`. There is no database to import.

### Known Quirks

- Default policy is deny. A site is reachable only after a sign-in Authelia accepts.
- Repeated failures are banned.
- No secret is generated on the machine. A missing file parks the service and says which one.
- Users live in the file you passed, not in a directory. A password reset would be overwritten at the next start.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Authelia is on loopback. Mail leaves on the SMTP port you name.
