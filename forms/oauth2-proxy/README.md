# oauth2-proxy - Hardened VM

A login in front of another service: [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) 7. It sends visitors to an OIDC provider and lets those the settings allow through. The form's manifest is [form.yaml](form.yaml).

## Security Posture

oauth2-proxy runs as its own user. There is no shell. Landlock and seccomp hold it to port 4180, to the provider, and to the upstream. The root is read-only.

- Cookies are secure, HttpOnly, and `SameSite=Lax`. They refresh hourly and expire in eight.
- The upstream sees the visitor's identity as headers, never the token.
- This image's upstream is `static://200`, a wall with nothing behind it.

## Getting Started

### Local test deployment (lima, qemu, firecracker)

```sh
mkdir -p config/oauth2-proxy
openssl rand -base64 24 | tr -d '\n' >config/oauth2-proxy/cookie_secret
printf '%s' 'the client secret' >config/oauth2-proxy/client_secret
howl create oauth2-proxy --with oauth2-proxy --config config \
	--provider-url https://accounts.google.com \
	--client-id 1234.apps.googleusercontent.com \
	--redirect-url https://app.home.arpa/oauth2/callback \
	--email-domains example.com
```

Put TLS in front of port 4180. The secure cookie requires it. Providers are in [oauth2-proxy's documentation](https://oauth2-proxy.github.io/oauth2-proxy/configuration/providers/).

### Cloud production deployment (aws, gcp, azure, proxmox)

```sh
mkdir -p config/oauth2-proxy
openssl rand -base64 24 | tr -d '\n' >config/oauth2-proxy/cookie_secret
printf '%s' 'the client secret' >config/oauth2-proxy/client_secret
howl create oauth2-proxy --with oauth2-proxy --on gcp --allow-from me --config config \
	--provider-url https://accounts.google.com \
	--client-id 1234.apps.googleusercontent.com \
	--redirect-url https://app.example.com/oauth2/callback \
	--email-domains example.com
```

`--allow-from me` admits your address to port 4180. A form of your own points `upstreams` at the application on this machine.

### Migrating data in

This machine starts empty. What it must remember is in the create command. There is no database to import.

### Known Quirks

- The cookie secret is 24 random bytes, base64, with no newline.
- A provider without discovery takes `--skip-discovery` and the login, redeem and JWKS URLs.

### Network Exposure

tcp/4180
