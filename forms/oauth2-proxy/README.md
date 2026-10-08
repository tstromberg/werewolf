# oauth2-proxy

The `oauth2-proxy` form is `prod` with oauth2-proxy 7, a login in front
of anything: it sends visitors to an OIDC provider and lets those the
settings allow through to the upstream.

| | |
| --- | --- |
| Listens | tcp/4180, behind `caddy` or the cloud's balancer, which its secure cookies require |
| Sends | HTTPS and DNS to the provider; HTTP to the upstream |
| Runs as | `oauth2-proxy` (uid 214), leashed |
| Config | `oauth2-proxy/client_secret`, `oauth2-proxy/cookie_secret` (32 characters: 24 random bytes, base64); settings `provider-url`, `client-id`, `redirect-url` (required), `email-domains`, `allowed-groups`, and `skip-discovery` with `login-url`, `redeem-url`, `jwks-url` for a provider without discovery |

```sh
openssl rand -base64 24 | tr -d '\n' >config/oauth2-proxy/cookie_secret
printf '%s' 'the client secret' >config/oauth2-proxy/client_secret
build/host/howl pack oauth2-proxy -o config.tar --config config \
	--provider-url https://accounts.google.com --client-id 1234.apps.googleusercontent.com \
	--redirect-url https://app.example.com/oauth2/callback --email-domains example.com
```

The upstream is `static://200` here, a wall with nothing behind it. A
form of your own lays its `etc/oauth2-proxy/oauth2-proxy.cfg` over this
one's with `upstreams = ["http://127.0.0.1:8080"]`, an application on the
same machine, or one on the network.

## Defaults

Secure, HttpOnly, `SameSite=Lax` cookies refreshed hourly and expiring
in eight; the visitor's identity passed to the upstream as headers, never
the token; the provider's button skipped; the balancer's pings not logged,
everything else logged.

## Checked

`make check-oauth2-proxy` gives it a provider the machine never reaches,
by hand ([forms/oauth2-proxy/test/config](test/config)), and
runs [forms/oauth2-proxy/test/checks](test/checks): `/ping`
answers; a visitor is sent to the provider; `/oauth2/auth` is 401; a
forged cookie is thrown out; the secrets are root's files, in no file
the service writes.
