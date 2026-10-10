# grafana

The `grafana` form is `prod` with Grafana 13.2, dashboards and alerts
over Prometheus, Loki and the other data sources it ships, behind Caddy,
which serves it over HTTPS at your base URL. Its administrator comes
from the config before it serves, its secret key is its own, nobody signs
up, and it sends nothing home.

| | |
| --- | --- |
| Listens | tcp/80 and tcp/443, Caddy's; Grafana on loopback alone |
| Sends | to data sources on 443, 80, 9090 (Prometheus) and 3100 (Loki), DNS, and grafana.com's plugin catalog when its administrator asks; Caddy's ACME requests |
| Runs as | `_oci-grafana` in Grafana's own image, and `caddy`, each leashed |
| Keeps | its SQLite database (WAL), its secret key, and the plugins its administrator installs, in `/data/svc/grafana` |
| Config | `grafana/admin-password` (required); `grafana/secret-key` (optional); setting `base-url`, Caddy's site and the URL Grafana's links use |

## Run your own

You need a domain name you can point at the machine.

```sh
mkdir -p config/grafana
openssl rand -base64 24 >config/grafana/admin-password   # admin's; keep it
howl create dash --with grafana --on gcp --allow-from 0.0.0.0/0 \
	--config config --base-url https://grafana.example.com
```

Point `grafana.example.com` at the address howl prints and sign in as
`admin`. Add data sources and users from Grafana's own pages. With
`--with grafana,prometheus` on one machine, Prometheus is at
`127.0.0.1:9090`, with the user its config names.

The password makes the administrator once, when the database is new;
change it later in Grafana.

The secret key encrypts the credentials Grafana stores for data
sources. `grafana-setup` ([cmd/grafana-setup](cmd/grafana-setup/grafana-setup.zig))
makes one before the first start, 256 random bits, and keeps it in
`/data/svc/grafana/secret-key`, 0600. To keep it across a new disk,
give it in the config as `grafana/secret-key`, which then wins; a new
key leaves what the old one encrypted unreadable.

## Defaults

- **No one gets in unasked.** Sign-up, organisations made by users and
  anonymous viewing are off; the administrator invites. Grafana's own
  login limits hold.
- **No public default key.** Grafana ships a secret key everyone knows;
  this one never runs with it.
- **Nothing sent home or fetched unasked:** no usage reports, update
  checks, news feed, feedback links, public snapshots or plugins
  installed at start. Gravatar is off.
- **Behind Caddy's TLS:** secure cookies, and Grafana's content security
  policy.
- **Grafana's own image**, the 13.2 line, pinned by digest at each build
  ([oci.md](../../docs/design/oci.md)): its entrypoint is a shell
  script, so leash runs `grafana server` itself. It may also run the
  data sources' backends, each a program beneath
  `data/plugins-bundled/` of the image (`run DIR/`), and nothing else.

## Plugins

The administrator may install plugins from the catalog, into `/data`.
One with a backend of its own (a program) will not run: `/data` is
`noexec`, so only the image's programs run. Panels and apps written in
JavaScript alone work.

## Drawbacks

- A new Grafana line (13.3, 14) is a new tag in form.yaml. Grafana
  migrates its database forward on start; a slot rolled back to an older
  Grafana may not read it.

## Checked

`make check-grafana` boots it with its test config
([test/config](test/config)), base URL `https://localhost`, for which
Caddy's own CA signs: Grafana is healthy behind HTTPS and plain HTTP is
redirected; it runs as `_oci-grafana` with no capability; the config's
administrator signs in; its secret key is its own, 0600; its links use
the base URL; the settings in effect send nothing home; a
Prometheus data source's backend starts and answers its health check;
the database is on `/data`; and a stranger gets 401 for the dashboards
and a wrong password, and cannot sign up. `make check-shellfree-grafana`
boots it as it ships, with no config: Grafana parks, naming the file;
Caddy runs.
