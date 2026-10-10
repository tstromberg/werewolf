# Authelia

The `authelia` form is single sign-on with a second factor:
[Authelia](https://www.authelia.com) 4.39, with Caddy in front, guarding
every site under your domain. One sign-in, with a password and a TOTP
app or a security key, reaches them all; nothing is reachable without it
([design/forms-catalog.md](../../docs/design/forms-catalog.md)).

## Run your own

You need a domain, with `example.com` and `*.example.com` pointing at the
machine. Hash each user's password with `authelia crypto hash generate
argon2` (or `argon2`, Argon2id, m=65536, t=3, p=4), into `users.yml`:

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
openssl rand -hex 32 >storage-key      # encrypts the database; keep it
howl create sso --with authelia --on gcp --allow-from 0.0.0.0/0 \
	--domain example.com --sso-users users.yml \
	--session-secret session-secret --storage-key storage-key \
	--smtp-server smtp.example.com:587 --smtp-sender auth@example.com \
	--smtp-username auth@example.com --smtp-password smtp-password
```

Each user signs in at `https://auth.example.com`, receives a one-time
code by mail, and registers a TOTP app or a security key.

| Flag | |
| --- | --- |
| `--domain NAME` | required. The cookie's domain: the portal is `auth.NAME`, and NAME and every name under it need both factors |
| `--sso-users FILE`, `--session-secret FILE`, `--storage-key FILE` | required. Users, and the two secrets, never printed or logged |
| `--smtp-server HOST:PORT` | the mail server for one-time codes: 587 STARTTLS, 465 TLS; TLS 1.2 at least, verified |
| `--smtp-sender`, `--smtp-username`, `--smtp-password FILE` | its sender, and its login |

Without a mail server, codes go to `/data/svc/authelia/notification.txt`,
which only root reads: a machine with no shell then has no way to
register a second factor. Give it one.

## Your sites behind it

A form of your own takes `with: [authelia]`, and adds a file per site
in `rootfs/etc/caddy/sites/NAME.caddy`, which Caddy reads after the
domain's own:

```text
grafana.{$DOMAIN} {
	import authelia
	reverse_proxy 127.0.0.1:3000
}
```

`import authelia` asks Authelia about every request; one that passes
carries `Remote-User`, `Remote-Groups`, `Remote-Email` and `Remote-Name`,
set by Caddy from Authelia's answer, never the client's. Add the site's
port to Caddy's `connect` in your form's `caddy` service.

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; Authelia on loopback; the ACME CA |
| Authelia | `authelia` | a mail server on 587 or 465 |

- **Deny by default.** No rule, no access; every name under the domain
  needs two factors.
- **Users from the config.** No sign-up; password reset and change are
  off, since the next start copies the file again. Change the file.
- **Brute force is banned.** Three wrong passwords in two minutes ban
  the user for ten.
- **Nothing phoned home.** No NTP check, no telemetry.
- **Built here.** melange builds the portal with Wolfi's Node and the
  server with Wolfi's Go, linked to Wolfi's SQLite
  ([melange/authelia.yaml](melange/authelia.yaml)).

## Drawbacks

- No OpenID Connect provider yet: apps that sign in by OIDC (Gitea,
  Grafana) use it only behind `forward_auth`, by header.
- Users in a file: a directory (LDAP) is not wired.

## Checked

`make check-authelia` boots it with its test config ([test/config](test/config)),
domain `werewolf.internal`, for which Caddy's own CA signs: the portal
answers its health check; a visitor without a session is sent to the
portal, as is one forging `Remote-User`; alice's right password alone
leaves her at one factor, sent back to the portal; and three wrong
passwords ban bob, whose right one is then refused.
`make check-shellfree-authelia` boots it as it ships, with no config:
no posture failure but those named, Authelia parked for want of its
users, Caddy for want of its domain.
