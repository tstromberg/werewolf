# Keycloak

The `keycloak` form is single sign-on: [Keycloak](https://www.keycloak.org)
26.8, an identity provider speaking OpenID Connect and SAML, with
PostgreSQL beside it and Caddy in front, serving HTTPS at your URL with a
certificate from Let's Encrypt, each part on a leash of its own. It is
what a university runs to sign its people in to everything else, and to
join a federation such as eduGAIN or InCommon by SAML.

## Run your own

You need a domain name you can point at the machine.

```sh
openssl rand -base64 24 >admin-password      # you sign in with it; keep it
howl create sso --with keycloak --on gcp --allow-from 0.0.0.0/0 \
	--base-url https://sso.example.edu --admin alice \
	--admin-password admin-password
```

Point `sso.example.edu` at the address howl prints, with an `A` record,
and sign in at `https://sso.example.edu/admin` as `alice`. Caddy gets the
certificate once the name resolves to the machine, and retries until it
does.

| Flag | |
| --- | --- |
| `--base-url URL` | required. Where Keycloak is served, `https://NAME`: Caddy's site, and every link and token issuer Keycloak makes |
| `--admin NAME` | required. The first administrator, of the master realm, made on the first start |
| `--admin-password FILE` | required. Its password, never printed or logged |

The administrator is made before Keycloak serves anything, so no visitor
claims a fresh machine. Keycloak calls it temporary: make your own
administrators, or bring them from your directory, then remove it. Realms,
clients, your LDAP directory and federations are set up in the admin
console, and kept in PostgreSQL.

## How the parts are held

| Part | Runs as | Reaches |
| --- | --- | --- |
| Caddy | `caddy` | :80 and :443; Keycloak on loopback; the ACME CA |
| Keycloak | `keycloak` | PostgreSQL's socket; LDAP (389, 636), mail submission (587, 465) and HTTPS anywhere |
| PostgreSQL | `postgres` | nothing |

- **Links for the base URL alone.** Keycloak's hostname is the base
  URL, strictly: a request with a forged `Host` or `X-Forwarded-Host`
  still gets issuers, redirects and password-reset links for it, so no
  mail sends a user to someone else's host. It takes the client's address
  and scheme from Caddy, on loopback, and no one else.
- **No first visitor.** The administrator comes from the config; nobody
  signs up to a realm unless an administrator turns that on.
- **Health and metrics on loopback.** `/health` and `/metrics` answer
  on their own port, 9180, which Caddy does not pass on.
- **Its own schema, by the socket.** Its tables are in the schema
  `keycloak` of the `postgres` database, owned by the role of its name,
  which logs in by peer authentication: no password, no TCP. pgjdbc has
  no UNIX socket of its own, so the package carries a socket factory of a
  page, on the JDK's own AF_UNIX channels ([melange/keycloak.yaml](melange/keycloak.yaml)).
- **Built here, for this form.** melange takes upstream's release and
  builds its server once, for PostgreSQL, a single node's caches and its
  health checks; the image starts it `--optimized`, read-only, with java
  alone. Wolfi's Keycloak was 26.3 and brought bash; `kc.sh`, `kcadm.sh`
  and the rest of `bin/` stay out, being shell.
- Its network reaches anywhere on those ports, as a campus directory is
  on the campus's own network. An identity provider's metadata, or a
  client's keys, are URLs an administrator gives it.
- The JVM, and PostgreSQL's `jit`, turn MDWE off for the whole machine, a
  weakness this form names.

## Drawbacks

- One node: caches are local, so a second machine is not a cluster.
- Themes and providers of your own need a form of your own on this one,
  as `providers/` is in the read-only image and the server is built.
- Kerberos and SSSD federation are not built in: there is no `sssd`.
- Until Wolfi takes a current release, every one is werewolf's to rebuild.

## Checked

`make check-keycloak` boots it with its test config ([test/config](test/config)),
base URL `https://localhost`, for which Caddy's own CA signs: the OpenID
discovery document answers through Caddy over HTTPS with the base URL as
its issuer, plain HTTP is sent to HTTPS, the administrator gets a token
and reads a realm that lets nobody sign up, a wrong password gets none, a
forged `Host` or `X-Forwarded-Host`, through Caddy or straight to
Keycloak, gets links for the base URL alone, and health answers on its own
loopback port and not through Caddy. `make check-shellfree-keycloak`
boots it as it ships, with no config: no posture failure but those named,
PostgreSQL and Caddy up, and Keycloak parked, saying it has no
administrator's password, before it makes a table or serves anything.
