# Caddy

The `caddy` form is `prod` with Caddy 2.11, a web server that gets its own
certificates. The site is in the image, `/usr/share/caddy`, with the
form's Caddyfile over it (`forms/caddy/rootfs/etc/caddy/Caddyfile`); a form of
your own includes `caddy` and lays its site and Caddyfile over those.

| | |
| --- | --- |
| Listens | tcp/80 and tcp/443; HTTP/3 (UDP) waits on fence serving UDP |
| Sends | HTTPS to the ACME CA and DNS to find it (`connect caddy tcp/443 tcp/53 udp/53`); the upstreams a form of your own adds |
| Runs as | `caddy` (uid 207), leashed: it binds its two ports, reads the image and writes `/run/svc/caddy` and `/data/svc/caddy` |
| Keeps | certificates, keys and the ACME account in `/data/svc/caddy`; on a RAM `/data` every boot asks the CA again, whose rate limits will notice |
| Settings | `domain` (a hostname): the site's name. Without one the site is `:80`, plain HTTP, with no certificate |

```sh
build/host/howl pack caddy -o config.tar --domain www.example.com
```

With a public name, Caddy does what it ships doing: a certificate from
Let's Encrypt (ZeroSSL behind it), renewed in time, and `:80` redirected
to HTTPS. `localhost`, and names under `.localhost`, `.local`, `.internal`
and `.home.arpa`, get a certificate from Caddy's own CA instead, which is
how `make check-caddy` checks HTTPS with no CA on the network.

## Defaults

- **`admin off`.** The admin API on `:2019` lets any local process rewrite
  the configuration. werewolf's configuration is in the image, so there is
  nothing to reload.
- **Headers.** The placeholder site sends `X-Content-Type-Options:
  nosniff` and `Referrer-Policy: strict-origin-when-cross-origin`, and no
  `Server`. HSTS is the site's to choose: it locks a name to HTTPS for
  months.
- **Timeouts.** `read_header 10s`, `idle 2m`, against slowloris. No body
  or write timeout, which would cut off uploads and streams.
- **On-demand TLS** only with an `ask` endpoint (a comment in the
  Caddyfile shows where), so a stranger cannot make Caddy ask for
  certificates without limit.
- **Protocols `h1 h2`**, until fence serves UDP. Wolfi's caddy is the
  standard build, with no plugins.
- **No shell, no interpreter.** Caddy is one Go binary; posture passes
  every check on this form.

## Checked

`make check-caddy` boots it with `domain localhost` ([forms/caddy/test/config](test/config))
and, beyond every form's checks, [forms/caddy/test/checks](test/checks):
HTTPS answers with the site and its headers and no `Server`; `:80`
redirects to HTTPS; nothing listens on `:2019` and the admin API does not
answer; and the certificate it made is kept on `/data`.
