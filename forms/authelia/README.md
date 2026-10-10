# Authelia

One sign-in for every site under your domain: [Authelia](https://www.authelia.com) 4.39, a password plus a TOTP app or a security key, with Caddy in front.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

Hash each password with `authelia crypto hash generate argon2` (Argon2id, m=65536, t=3, p=4) into `users.yml`:

```yaml
users:
  alice:
    displayname: 'Alice'
    email: 'alice@example.com'
    password: '$argon2id$v=19$m=65536,t=3,p=4$...'
    groups: ['admins']
```

```sh
openssl rand -hex 32 >session-secret
openssl rand -hex 32 >storage-key
howl create sso --with authelia --on lima \
	--domain home.arpa --sso-users users.yml \
	--session-secret session-secret --storage-key storage-key
```

Open `https://auth.home.arpa`. Without SMTP, registering a second factor has no mail channel: use the cloud command once you have a relay.

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
openssl rand -hex 32 >session-secret
openssl rand -hex 32 >storage-key
howl create sso --with authelia --on gcp --allow-from 0.0.0.0/0 \
	--domain example.com --sso-users users.yml \
	--session-secret session-secret --storage-key storage-key \
	--smtp-server smtp.example.com:587 --smtp-sender auth@example.com \
	--smtp-username auth@example.com --smtp-password smtp-password
```

Point `example.com` and `*.example.com` at the machine. Each person signs in at `https://auth.example.com`, receives a one-time code by mail, and registers a TOTP app or a security key. Keep `storage-key`: it encrypts the database.

### Known Quirks

- Default policy is deny. A site is reachable only after a sign-in Authelia accepts.
- Repeated failures are banned.
- No secret is generated on the machine. A missing file parks the service and says which one.
- Users live in the file you passed, not in a directory.

### Network Exposure

- tcp/80 and tcp/443, Caddy. Authelia is on loopback. Mail leaves on the SMTP port you name.

### Security Weaknesses

None the form does not already refuse: a password alone does not sign in.
